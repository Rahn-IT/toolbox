use super::*;
use crate::mailbox_scanner::core::{config, message};
use std::num::NonZeroU32;
use std::path::PathBuf;
use std::sync::{
    Arc,
    atomic::{AtomicU64, Ordering},
};

static NEXT: AtomicU64 = AtomicU64::new(0);

fn parent() -> PathBuf {
    let stamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let path = std::env::temp_dir().join(format!(
        "toolbox-directory-test-{}-{stamp}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    std::fs::create_dir(&path).unwrap();
    path
}

async fn prepared(parent: &std::path::Path, count: u32) -> batch::Batch {
    let settings = config::Settings::try_from(config::Draft {
        host: "example.invalid".into(),
        username: "test".into(),
        password: "test".into(),
        scan_dir: parent.into(),
        ..Default::default()
    })
    .unwrap();
    let mut builder = batch::Builder::create(parent, 1024 * 1024 * 1024).unwrap();
    let (_sender, receiver) = watch::channel(false);
    for uid in 1..=count {
        let identity = message::Identity::new(
            message::Account::from_settings(&settings),
            message::Folder::new("INBOX".into(), "INBOX".into()).unwrap(),
            NonZeroU32::new(1).unwrap(),
            NonZeroU32::new(uid).unwrap(),
        );
        builder
            .add(
                identity,
                b"From: harmless@example.invalid\r\nSubject: harmless\r\n\r\nbody".to_vec(),
                &receiver,
            )
            .await
            .unwrap();
    }
    builder.seal().unwrap().unwrap()
}

fn settings() -> scanner::Settings {
    scanner::Settings::Custom(scanner::custom::Settings {
        executable: std::env::current_exe().unwrap(),
        arguments: vec!["{directory}".into()],
        clean_code: 0,
        detected_code: 1,
    })
}

fn line(inspection: &mut Inspection<'_>, path: &str, status: &str, detail: &str) {
    let record = format!("{path}\t{status}\t{detail}");
    inspection.line(
        &settings(),
        transport::Stream::Stdout,
        transport::Record::Line(record.into_bytes()),
    );
}

#[tokio::test]
async fn missing_and_unknown_outcomes_cannot_establish_clean_coverage() {
    let parent = parent();
    let batch = prepared(&parent, 2).await;
    let updates = Updates::default();
    let mut inspection = Inspection::new(&batch, scanner::Backend::Custom, &updates);
    for file in batch.files().iter().filter(|file| file.owner() == 0) {
        line(
            &mut inspection,
            file.path().file_name().unwrap().to_str().unwrap(),
            "CLEAN",
            "",
        );
    }
    line(
        &mut inspection,
        "foreign.eml",
        "DETECTED",
        "not attributable",
    );
    let outcome = inspection.finish(
        &settings(),
        &transport::Outcome {
            code: Some(0),
            exit_confirmed: true,
            ..Default::default()
        },
    );
    assert!(outcome.cleanup_safe);
    assert!(outcome.reports.iter().all(|report| !report.complete()));
    assert!(outcome.reports.iter().all(|report| !report.detected()));
    assert!(updates.take().is_empty());
    assert!(batch.cleanup().await.is_empty());
    std::fs::remove_dir(parent).unwrap();
}

#[tokio::test]
async fn conflicting_clean_record_preserves_positive_without_duplicate_evidence() {
    let parent = parent();
    let batch = prepared(&parent, 1).await;
    let updates = Updates::default();
    let mut inspection = Inspection::new(&batch, scanner::Backend::Custom, &updates);
    let first = batch.files()[0]
        .path()
        .file_name()
        .unwrap()
        .to_str()
        .unwrap();
    line(&mut inspection, first, "DETECTED", "Fixture");
    line(&mut inspection, first, "DETECTED", "Fixture");
    line(&mut inspection, first, "CLEAN", "");
    for file in &batch.files()[1..] {
        line(
            &mut inspection,
            file.path().file_name().unwrap().to_str().unwrap(),
            "CLEAN",
            "",
        );
    }
    let outcome = inspection.finish(
        &settings(),
        &transport::Outcome {
            code: Some(1),
            exit_confirmed: true,
            ..Default::default()
        },
    );
    assert!(outcome.reports[0].detected());
    assert!(!outcome.reports[0].complete());
    assert_eq!(outcome.reports[0].evidence().len(), 1);
    let snapshots = updates.take();
    assert_eq!(snapshots.len(), 1);
    assert!(snapshots[0].2.detected());
    assert!(batch.cleanup().await.is_empty());
    std::fs::remove_dir(parent).unwrap();
}

#[tokio::test]
async fn process_failure_keeps_live_positive_and_forbids_uncertain_cleanup() {
    let parent = parent();
    let batch = prepared(&parent, 1).await;
    let updates = Updates::default();
    let mut inspection = Inspection::new(&batch, scanner::Backend::Custom, &updates);
    let first = batch.files()[0]
        .path()
        .file_name()
        .unwrap()
        .to_str()
        .unwrap();
    line(&mut inspection, first, "DETECTED", "");
    let outcome = inspection.finish(
        &settings(),
        &transport::Outcome {
            code: Some(1),
            timed_out: true,
            termination_requested: true,
            exit_confirmed: false,
            ..Default::default()
        },
    );
    assert!(!outcome.cleanup_safe);
    assert!(outcome.reports[0].detected());
    assert!(!outcome.reports[0].complete());
    // No child was started in this accumulator-only test.
    assert!(batch.cleanup().await.is_empty());
    std::fs::remove_dir(parent).unwrap();
}

#[tokio::test]
async fn custom_utf16_records_are_rejected_even_when_the_transport_can_frame_them() {
    let parent = parent();
    let batch = prepared(&parent, 1).await;
    let updates = Updates::default();
    let mut inspection = Inspection::new(&batch, scanner::Backend::Custom, &updates);
    let mut bytes = vec![0xff, 0xfe];
    bytes.extend(
        "m000000.eml\tDETECTED\tFixture"
            .encode_utf16()
            .flat_map(u16::to_le_bytes),
    );
    inspection.line(
        &settings(),
        transport::Stream::Stdout,
        transport::Record::Line(bytes),
    );
    let outcome = inspection.finish(
        &settings(),
        &transport::Outcome {
            code: Some(1),
            exit_confirmed: true,
            ..Default::default()
        },
    );
    assert!(!outcome.reports[0].detected());
    assert!(!outcome.reports[0].complete());
    assert!(batch.cleanup().await.is_empty());
    std::fs::remove_dir(parent).unwrap();
}

#[tokio::test]
async fn directory_child_starts_once_and_publishes_before_it_exits() {
    let parent = parent();
    let batch = Arc::new(prepared(&parent, 2).await);
    assert!(batch.files().len() >= 4);
    let source = parent.join("fixture.rs");
    let executable = parent.join(if cfg!(windows) {
        "fixture.exe"
    } else {
        "fixture"
    });
    std::fs::write(&source, r#"
use std::io::Write;
fn main() {
    let mut args = std::env::args_os().skip(1);
    let directory = std::path::PathBuf::from(args.next().unwrap());
    let started = std::path::PathBuf::from(args.next().unwrap());
    let release = std::path::PathBuf::from(args.next().unwrap());
    let mut log = std::fs::OpenOptions::new().create(true).append(true).open(started).unwrap();
    writeln!(log, "started").unwrap();
    let mut paths: Vec<_> = std::fs::read_dir(directory).unwrap().map(|entry| entry.unwrap().path()).collect();
    paths.sort();
    for path in paths {
        let name = path.file_name().unwrap().to_str().unwrap();
        if name == "m000000.eml" {
            println!("{name}\tDETECTED\tFixture");
        } else {
            println!("{name}\tCLEAN");
        }
    }
    std::io::stdout().flush().unwrap();
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(15);
    while !release.exists() && std::time::Instant::now() < deadline {
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
    std::process::exit(1);
}
"#).unwrap();
    let compiler = std::process::Command::new("rustc")
        .arg("--edition=2024")
        .arg(&source)
        .arg("-o")
        .arg(&executable)
        .output()
        .unwrap();
    assert!(
        compiler.status.success(),
        "Fixture compiler: {}",
        String::from_utf8_lossy(&compiler.stderr)
    );
    let started = parent.join("started");
    let release = parent.join("release");
    let engine = Engine {
        executable: executable.clone(),
        settings: scanner::Settings::Custom(scanner::custom::Settings {
            executable,
            arguments: vec![
                "{directory}".into(),
                started.to_str().unwrap().into(),
                release.to_str().unwrap().into(),
            ],
            clean_code: 0,
            detected_code: 1,
        }),
    };
    let updates = Arc::new(Updates::default());
    let worker_batch = Arc::clone(&batch);
    let worker_updates = Arc::clone(&updates);
    let (_sender, receiver) = watch::channel(false);
    let task = tokio::spawn(async move {
        scan(
            &engine,
            &worker_batch,
            Duration::from_secs(20),
            receiver,
            &worker_updates,
        )
        .await
    });
    let snapshot = tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            if let Some(snapshot) = updates
                .take()
                .into_iter()
                .find(|(_, _, report)| report.detected())
            {
                break snapshot;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
    assert_eq!(snapshot.0, 0);
    assert!(
        !task.is_finished(),
        "Finding must arrive before the child is released"
    );
    std::fs::write(&release, b"finish").unwrap();
    let outcome = task.await.unwrap();
    assert!(outcome.cleanup_safe);
    assert!(outcome.reports.iter().all(detection::Report::complete));
    assert!(outcome.reports[0].detected());
    assert!(!outcome.reports[1].detected());
    assert_eq!(std::fs::read_to_string(started).unwrap().lines().count(), 1);
    assert!(batch.cleanup().await.is_empty());
    // Everything left is a known fixture artifact below this unique test directory.
    for entry in std::fs::read_dir(&parent).unwrap() {
        std::fs::remove_file(entry.unwrap().path()).unwrap();
    }
    std::fs::remove_dir(parent).unwrap();
}

#[tokio::test]
async fn avast_nested_detection_then_outer_ok_establishes_complete_positive() {
    let parent = parent();
    let batch = prepared(&parent, 1).await;
    let updates = Updates::default();
    let settings = scanner::Settings::Avast(scanner::avast::Settings::default());
    let mut inspection = Inspection::new(&batch, scanner::Backend::Avast, &updates);
    let original = batch.files()[0].path().to_str().unwrap();
    inspection.line(
        &settings,
        transport::Stream::Stdout,
        transport::Record::Line(
            format!("{original}|>standard-test.txt#943030176\tEICAR Test-NOT virus!!!")
                .into_bytes(),
        ),
    );
    assert!(inspection.reports[0].detected());
    assert!(inspection.states[0].is_none());
    assert!(updates.take()[0].2.detected());
    for file in batch.files() {
        inspection.line(
            &settings,
            transport::Stream::Stdout,
            transport::Record::Line(format!("{}\tOK", file.path().display()).into_bytes()),
        );
    }
    let outcome = inspection.finish(
        &settings,
        &transport::Outcome {
            code: Some(1),
            exit_confirmed: true,
            ..Default::default()
        },
    );
    assert!(outcome.reports[0].detected());
    assert!(outcome.reports[0].complete());
    assert_eq!(outcome.reports[0].evidence().len(), 1);
    assert!(batch.cleanup().await.is_empty());
    std::fs::remove_dir(parent).unwrap();
}

#[tokio::test]
async fn avast_nested_clean_record_does_not_finish_the_outer_input() {
    let parent = parent();
    let batch = prepared(&parent, 1).await;
    let updates = Updates::default();
    let settings = scanner::Settings::Avast(scanner::avast::Settings::default());
    let mut inspection = Inspection::new(&batch, scanner::Backend::Avast, &updates);
    for file in batch.files() {
        inspection.line(
            &settings,
            transport::Stream::Stdout,
            transport::Record::Line(
                format!("{}|>PartNo_0#925606545\tOK", file.path().display()).into_bytes(),
            ),
        );
    }
    let outcome = inspection.finish(
        &settings,
        &transport::Outcome {
            code: Some(0),
            exit_confirmed: true,
            ..Default::default()
        },
    );
    assert!(!outcome.reports[0].detected());
    assert!(!outcome.reports[0].complete());
    assert!(batch.cleanup().await.is_empty());
    std::fs::remove_dir(parent).unwrap();
}

fn avast_engine() -> Engine {
    let executable = avast::executable();
    assert!(executable.is_file(), "Installed Avast is required");
    Engine {
        executable,
        settings: scanner::Settings::Avast(scanner::avast::Settings {
            entire_files: false,
            archives: true,
            heuristics: 0,
        }),
    }
}

#[tokio::test]
#[ignore = "Runs installed Avast on a task-owned harmless directory"]
async fn installed_avast_scans_prepared_directory_without_modifying_inputs() {
    let parent = parent();
    let batch = prepared(&parent, 2).await;
    let originals: Vec<_> = batch
        .files()
        .iter()
        .map(|file| (file.path().to_owned(), std::fs::read(file.path()).unwrap()))
        .collect();
    let (_sender, receiver) = watch::channel(false);
    let outcome = scan(
        &avast_engine(),
        &batch,
        Duration::from_secs(300),
        receiver,
        &Updates::default(),
    )
    .await;
    assert!(
        outcome.cleanup_safe,
        "Retained unconfirmed batch: {}",
        batch.directory().display()
    );
    for report in &outcome.reports {
        assert!(!report.detected());
        assert!(report.complete(), "{:?}", report.issues());
    }
    for (path, expected) in originals {
        assert_eq!(std::fs::read(path).unwrap(), expected);
    }
    println!(
        "Installed Avast completed one directory scan of {} prepared files",
        batch.files().len()
    );
    assert!(batch.cleanup().await.is_empty());
    std::fs::remove_dir(parent).unwrap();
}

#[tokio::test]
#[ignore = "Runs installed Avast on task-owned standard harmless EICAR MIME fixtures"]
async fn installed_avast_mime_batch_preserves_attribution_or_rejects_resident_interference() {
    let parent = parent();
    let settings = config::Settings::try_from(config::Draft {
        host: "example.invalid".into(),
        username: "test".into(),
        password: "test".into(),
        scan_dir: parent.clone(),
        ..Default::default()
    })
    .unwrap();
    let mut builder = batch::Builder::create(&parent, 1024 * 1024 * 1024).unwrap();
    let mut test = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$".to_vec();
    test.extend_from_slice(b"EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*");
    let encoded = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, test);
    let positive = format!("From: fixture@example.invalid\r\nSubject: harmless antivirus test\r\nMIME-Version: 1.0\r\nContent-Type: multipart/mixed; boundary=probe\r\n\r\n--probe\r\nContent-Type: text/plain\r\n\r\nStandard test.\r\n--probe\r\nContent-Type: application/octet-stream\r\nContent-Disposition: attachment; filename=standard-test.txt\r\nContent-Transfer-Encoding: base64\r\n\r\n{encoded}\r\n--probe--\r\n").into_bytes();
    let messages = [
        positive.clone(),
        positive,
        b"From: sentinel@example.invalid\r\n\r\nHarmless end sentinel.\r\n".to_vec(),
    ];
    let (_sender, receiver) = watch::channel(false);
    for (index, bytes) in messages.iter().enumerate() {
        let identity = message::Identity::new(
            message::Account::from_settings(&settings),
            message::Folder::new("INBOX".into(), "INBOX".into()).unwrap(),
            NonZeroU32::new(1).unwrap(),
            NonZeroU32::new(index as u32 + 1).unwrap(),
        );
        builder
            .add(identity, bytes.clone(), &receiver)
            .await
            .unwrap();
    }
    let batch = match builder.seal() {
        Ok(Some(batch)) => batch,
        Ok(None) => panic!("Nonempty fixture disappeared"),
        Err(rejected) => {
            let batch = rejected.into_batch();
            assert!(
                batch.files().iter().any(|file| !file.path().is_file()),
                "Unexpected sealing failure"
            );
            println!(
                "Resident antivirus removed a decoded test file before sealing; batch correctly rejected and no scanner launched"
            );
            assert!(batch.cleanup().await.is_empty());
            std::fs::remove_dir(parent).unwrap();
            return;
        }
    };
    let updates = Updates::default();
    let outcome = scan(
        &avast_engine(),
        &batch,
        Duration::from_secs(300),
        receiver,
        &updates,
    )
    .await;
    assert!(
        outcome.cleanup_safe,
        "Retained unconfirmed batch: {}",
        batch.directory().display()
    );
    assert_eq!(outcome.reports.len(), 3);
    assert!(
        outcome.reports[0].detected(),
        "First MIME detection missing: {:?}",
        outcome.reports[0].issues()
    );
    assert!(
        outcome.reports[1].detected(),
        "Second MIME detection missing: {:?}",
        outcome.reports[1].issues()
    );
    assert!(!outcome.reports[2].detected());
    for (index, expected) in messages.iter().enumerate() {
        assert_eq!(
            std::fs::read(batch.directory().join(format!("m{index:06}.eml"))).unwrap(),
            *expected
        );
    }
    for file in batch.files().iter().filter(|file| !file.path().is_file()) {
        assert!(
            !outcome.reports[file.owner()].complete(),
            "Missing decoded input must prevent complete coverage"
        );
    }
    println!(
        "Installed Avast attributed both MIME detections; coverage complete: {:?}",
        outcome
            .reports
            .iter()
            .map(detection::Report::complete)
            .collect::<Vec<_>>()
    );
    for (index, report) in outcome.reports.iter().enumerate() {
        println!("Message {index} coverage issues: {:?}", report.issues());
    }
    let leftovers = batch.cleanup().await;
    if leftovers.is_empty() {
        std::fs::remove_dir(parent).unwrap();
    } else {
        assert!(
            leftovers
                .iter()
                .all(|path| path == batch.directory() || batch.owned_paths().contains(path))
        );
        println!(
            "Cleanup retained task-owned paths for review; no unowned file was deleted: {leftovers:?}"
        );
    }
}
