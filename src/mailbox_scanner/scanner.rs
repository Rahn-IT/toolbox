//! Direct, bounded execution of installed antivirus command-line scanners.

mod avast;
pub(crate) mod batch;
mod classify;
mod custom;
mod defender;
pub(super) mod mime;
pub(super) mod transport;

use std::io;
use std::path::{Path, PathBuf};

use std::time::Duration;

use tokio::io::AsyncReadExt;
use tokio::process::Command;
use tokio::sync::watch;
use tokio::time::Instant;

use crate::mailbox_scanner::core::{config, detection, scanner};

const OUTPUT_LIMIT: usize = 64 * 1024;
const COMMAND_TIMEOUT: Duration = Duration::from_secs(120);
const MESSAGE_TIMEOUT: Duration = Duration::from_secs(300);

/// A selected installed command-line engine. The backend set is deliberately closed.
#[derive(Clone)]
pub struct Engine {
    settings: scanner::Settings,
    executable: PathBuf,
}

/// Failures before a scan report can be established.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error(transparent)]
    Settings(#[from] scanner::Error),
    #[error("Selected scanner is unavailable on this platform")]
    Platform,
    #[error("Scanner executable not found: {0}")]
    Executable(PathBuf),
    #[error("Scanner I/O failed: {0}")]
    Io(#[from] io::Error),
    #[error("Scanner termination was not confirmed; scan files must be retained")]
    TerminationUnconfirmed,
}

impl Engine {
    /// Resolve the standard installation or a validated Custom executable.
    pub fn resolve(settings: &config::Settings) -> Result<Self, Error> {
        if !cfg!(windows) {
            return Err(Error::Platform);
        }
        let executable = match settings.scanner() {
            scanner::Settings::Avast(_) => avast::executable(),
            scanner::Settings::Defender => defender::executable(),
            scanner::Settings::Custom(settings) => custom::executable(settings)?,
        };
        if !executable.is_file() {
            return Err(Error::Executable(executable));
        }
        Ok(Self {
            settings: settings.scanner().clone(),
            executable: executable.canonicalize()?,
        })
    }

    /// The selected closed backend.
    pub fn backend(&self) -> scanner::Backend {
        self.settings.backend()
    }

    /// The resolved executable path.
    pub fn executable(&self) -> &Path {
        &self.executable
    }

    /// Scan an original EML and prefixed decoded parts, tracking files created for cleanup.
    pub async fn scan(
        &self,
        eml: &Path,
        files: &mut Vec<PathBuf>,
        cancel: watch::Receiver<bool>,
    ) -> Result<detection::Report, Error> {
        let mut report = detection::Report::new();
        if *cancel.borrow() || cancel.has_changed().is_err() {
            report.warn(detection::Issue::Cancelled);
            return Ok(report);
        }
        let eml = tokio::fs::canonicalize(eml).await?;
        let metadata = tokio::fs::metadata(&eml).await?;
        if !metadata.is_file() || metadata.len() > mime::MAX_ORIGINAL as u64 {
            report.warn(detection::Issue::Limit(
                "Original message exceeds 200 MiB or is not a regular file",
            ));
            return Ok(report);
        }
        let file = tokio::fs::File::open(&eml).await?;
        let mut raw = Vec::with_capacity(metadata.len() as usize);
        file.take(mime::MAX_ORIGINAL as u64 + 1)
            .read_to_end(&mut raw)
            .await?;
        if raw.len() > mime::MAX_ORIGINAL || raw.len() as u64 != metadata.len() {
            report.warn(detection::Issue::Input(
                "Message changed while reading for scanning".into(),
            ));
            return Ok(report);
        }
        let deadline = Instant::now() + MESSAGE_TIMEOUT;
        report.merge(self.file(&eml, cancel.clone(), deadline).await?);
        if stopped(&cancel, deadline) {
            report.warn(detection::Issue::Cancelled);
            return Ok(report);
        }
        let mut parsed = match mime::Parsed::parse(raw).await {
            Ok(parsed) => parsed,
            Err(error) => {
                report.warn(detection::Issue::Decode(error.to_string()));
                return Ok(report);
            }
        };
        let mut index = 0_u32;
        loop {
            if stopped(&cancel, deadline) {
                report.warn(detection::Issue::Scanner(
                    "MIME scan stopped or reached its orchestration deadline".into(),
                ));
                break;
            }
            let leaf = match parsed.next().await {
                Ok(Some(leaf)) => leaf,
                Ok(None) => break,
                Err(error) => {
                    report.warn(detection::Issue::Decode(error.to_string()));
                    break;
                }
            };
            for issue in leaf.issues {
                report.warn(issue);
            }
            if stopped(&cancel, deadline) {
                report.warn(detection::Issue::Cancelled);
                break;
            }
            let Some(bytes) = leaf.bytes else { continue };
            index += 1;
            let path = eml.with_extension(format!("{index}.bin"));
            let mut file = match tokio::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&path)
                .await
            {
                Ok(file) => file,
                Err(error) => {
                    report.warn(detection::Issue::Input(format!(
                        "Cannot create MIME scan file {}: {error}",
                        path.display()
                    )));
                    break;
                }
            };
            files.push(path.clone());
            let write = async {
                use tokio::io::AsyncWriteExt;
                file.write_all(&bytes).await?;
                file.flush().await
            }
            .await;
            drop(file);
            match write {
                Ok(()) => report.merge(self.file(&path, cancel.clone(), deadline).await?),
                Err(error) => report.warn(detection::Issue::Input(format!(
                    "Cannot prepare MIME scan file {}: {error}",
                    path.display()
                ))),
            }
            match tokio::fs::remove_file(&path).await {
                Ok(()) => {}
                Err(error) if error.kind() == io::ErrorKind::NotFound => {
                    report.warn(detection::Issue::Input(format!(
                        "MIME scan file disappeared: {}",
                        path.display()
                    )));
                }
                Err(error) => {
                    report.warn(detection::Issue::Input(format!(
                        "Temporary file could not be removed: {}: {error}",
                        path.display()
                    )));
                    break;
                }
            }
        }
        Ok(report)
    }

    async fn file(
        &self,
        path: &Path,
        cancel: watch::Receiver<bool>,
        deadline: Instant,
    ) -> Result<detection::Report, Error> {
        let before = tokio::fs::metadata(path)
            .await
            .map(|metadata| metadata.len());
        let mut report = match capture(
            self.command(path),
            cancel,
            deadline.min(Instant::now() + COMMAND_TIMEOUT),
        )
        .await
        {
            Ok((capture, true)) => classify::report(&self.settings, path, capture),
            Ok((_, false)) => return Err(Error::TerminationUnconfirmed),
            Err(error) => {
                let mut report = detection::Report::new();
                report.warn(detection::Issue::Scanner(format!(
                    "Cannot start scanner: {error}"
                )));
                report
            }
        };
        let after = tokio::fs::metadata(path)
            .await
            .map(|metadata| metadata.len());
        match (before, after) {
            (Ok(before), Ok(after)) if before == after => {}
            _ => report.warn(detection::Issue::Input(format!(
                "Scanner input disappeared, became inaccessible or changed length: {}",
                path.display()
            ))),
        }
        Ok(report)
    }

    fn command(&self, path: &Path) -> Command {
        let mut command = match &self.settings {
            scanner::Settings::Avast(settings) => avast::command(&self.executable, path, settings),
            scanner::Settings::Defender => defender::command(&self.executable, path),
            scanner::Settings::Custom(settings) => {
                custom::command(&self.executable, path, settings)
            }
        };
        #[cfg(windows)]
        command.creation_flags(0x0800_0000);
        command
    }
}

fn program_files() -> PathBuf {
    std::env::var_os("ProgramFiles")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(r"C:\Program Files"))
}

fn stopped(cancel: &watch::Receiver<bool>, deadline: Instant) -> bool {
    *cancel.borrow() || cancel.has_changed().is_err() || Instant::now() >= deadline
}

async fn cancelled(cancel: &mut watch::Receiver<bool>) {
    loop {
        if *cancel.borrow_and_update() {
            return;
        }
        if cancel.changed().await.is_err() {
            return;
        }
    }
}

#[cfg(test)]
async fn supervise(
    command: Command,
    cancel: watch::Receiver<bool>,
    deadline: Instant,
) -> io::Result<classify::Capture> {
    let (capture, _) = capture(command, cancel, deadline).await?;
    Ok(capture)
}

async fn capture(
    command: Command,
    cancel: watch::Receiver<bool>,
    deadline: Instant,
) -> io::Result<(classify::Capture, bool)> {
    let mut capture = classify::Capture::default();
    let outcome = transport::run(command, cancel, deadline, |stream, bytes| {
        let target = match stream {
            transport::Stream::Stdout => &mut capture.stdout,
            transport::Stream::Stderr => &mut capture.stderr,
        };
        capture.truncated |= append(target, bytes);
    })
    .await?;
    capture.code = outcome.code;
    capture.termination_requested = outcome.termination_requested;
    capture.timed_out = outcome.timed_out;
    capture.cancelled = outcome.cancelled;
    capture.truncated |= outcome.drain_incomplete;
    capture.failure = outcome.failure;
    Ok((capture, outcome.exit_confirmed))
}
fn append(target: &mut Vec<u8>, bytes: &[u8]) -> bool {
    let available = OUTPUT_LIMIT.saturating_sub(target.len());
    target.extend_from_slice(&bytes[..bytes.len().min(available)]);
    bytes.len() > available
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn versions_are_sorted_numerically() {
        assert!(defender::version("4.18.10.0-0") > defender::version("4.18.9.0-0"));
        assert_eq!(defender::version("CurrentVersion"), None);
    }

    #[test]
    fn commands_keep_the_input_path_as_one_argument() {
        let path = Path::new("C:/scan folder/mail & example.eml");
        for settings in [
            scanner::Settings::Avast(scanner::avast::Settings::default()),
            scanner::Settings::Defender,
        ] {
            let backend = settings.backend();
            let engine = Engine {
                settings,
                executable: PathBuf::from("scanner.exe"),
            };
            let command = engine.command(path);
            let args = command.as_std().get_args().collect::<Vec<_>>();
            assert_eq!(
                args.iter().filter(|arg| **arg == path.as_os_str()).count(),
                1
            );
            if backend == scanner::Backend::Defender {
                assert!(args.contains(&std::ffi::OsStr::new("-DisableRemediation")));
            } else {
                assert!(args.contains(&std::ffi::OsStr::new("/p=4")));
            }
        }
    }

    #[test]
    fn avast_arguments_follow_the_selected_inspection_scope() {
        for (entire_files, archives, heuristics) in
            [(true, true, 50), (false, false, 0), (false, true, 100)]
        {
            let engine = Engine {
                settings: scanner::Settings::Avast(scanner::avast::Settings {
                    entire_files,
                    archives,
                    heuristics,
                }),
                executable: "scanner.exe".into(),
            };
            let command = engine.command(Path::new("mail.eml"));
            let args = command
                .as_std()
                .get_args()
                .map(|arg| arg.to_string_lossy().into_owned())
                .collect::<Vec<_>>();
            assert!(args.contains(&"/a".into()));
            assert!(args.contains(&"/p=4".into()));
            assert!(args.contains(&format!("/e={heuristics}")));
            assert_eq!(args.contains(&"/c".into()), entire_files);
            assert!(args.contains(&if archives {
                "/t=A".into()
            } else {
                "/t=N".into()
            }));
        }
    }

    #[cfg(windows)]
    #[test]
    fn custom_resolves_the_selected_native_executable() {
        let settings = config::Settings::try_from(config::Draft {
            host: "imap.example.org".into(),
            username: "user".into(),
            password: "password".into(),
            scan_dir: "scan".into(),
            scanner: scanner::Settings::Custom(scanner::custom::Settings {
                executable: std::env::current_exe().unwrap(),
                arguments: vec!["{directory}".into()],
                clean_code: 0,
                detected_code: 1,
            }),
            ..Default::default()
        })
        .unwrap();
        let engine = Engine::resolve(&settings).unwrap();
        assert_eq!(engine.backend(), scanner::Backend::Custom);
        assert_eq!(
            engine.executable(),
            std::env::current_exe().unwrap().canonicalize().unwrap()
        );
    }

    #[test]
    fn child_fixture() {
        match std::env::var("MAILBOX_SCANNER_FIXTURE").as_deref() {
            Ok("output") => {
                use std::io::Write;
                let bytes = vec![b'x'; OUTPUT_LIMIT * 2];
                let thread = std::thread::spawn(move || {
                    let _ = io::stderr().write_all(&bytes);
                });
                let _ = io::stdout().write_all(&vec![b'y'; OUTPUT_LIMIT * 2]);
                let _ = thread.join();
            }
            Ok("sleep") => std::thread::sleep(Duration::from_secs(30)),
            Ok("stream") => {
                use std::io::Write;
                println!("\nmail.eml\tDETECTED\tfixture");
                io::stdout().flush().unwrap();
                std::thread::sleep(Duration::from_secs(30));
            }
            Ok("exit") => {
                let code = std::env::var("MAILBOX_SCANNER_EXIT")
                    .unwrap()
                    .parse()
                    .unwrap();
                std::process::exit(code);
            }
            Ok("argv") => {
                let expected = std::env::var_os("MAILBOX_SCANNER_PATH").unwrap();
                let arguments = std::env::args_os().collect::<Vec<_>>();
                assert_eq!(arguments.last(), Some(&expected));
                println!("literal path verified");
            }
            _ => {}
        }
    }

    fn fixture(mode: &str) -> Command {
        let mut command = Command::new(std::env::current_exe().unwrap());
        command
            .args([
                "--exact",
                "mailbox_scanner::scanner::tests::child_fixture",
                "--nocapture",
            ])
            .env("MAILBOX_SCANNER_FIXTURE", mode);
        command
    }

    #[tokio::test]
    async fn output_on_both_pipes_is_bounded_without_deadlock() {
        let (_sender, receiver) = watch::channel(false);
        let capture = supervise(
            fixture("output"),
            receiver,
            Instant::now() + Duration::from_secs(10),
        )
        .await
        .unwrap();
        assert!(capture.truncated);
        assert!(capture.stdout.len() <= OUTPUT_LIMIT);
        assert!(capture.stderr.len() <= OUTPUT_LIMIT);
        assert_eq!(capture.code, Some(0));
        assert!(!capture.termination_requested);
    }

    #[tokio::test]
    async fn transport_delivers_all_output_without_capture_volume_termination() {
        let (_sender, receiver) = watch::channel(false);
        let mut lengths = [0usize; 2];
        let outcome = transport::run(
            fixture("output"),
            receiver,
            Instant::now() + Duration::from_secs(10),
            |stream, bytes| {
                lengths[usize::from(stream == transport::Stream::Stderr)] += bytes.len()
            },
        )
        .await
        .unwrap();
        assert!(lengths.into_iter().all(|length| length >= OUTPUT_LIMIT * 2));
        assert_eq!(outcome.code, Some(0));
        assert!(outcome.exit_confirmed);
        assert!(!outcome.termination_requested);
        assert!(!outcome.drain_incomplete);
    }

    #[tokio::test]
    async fn streamed_record_arrives_while_the_child_is_running() {
        let (cancel, receiver) = watch::channel(false);
        let (notice, received) = tokio::sync::oneshot::channel();
        let mut notice = Some(notice);
        let mut lines = transport::Lines::default();
        let task = tokio::spawn(transport::run(
            fixture("stream"),
            receiver,
            Instant::now() + Duration::from_secs(10),
            move |stream, bytes| {
                if stream == transport::Stream::Stdout {
                    lines.push(bytes, |record| {
                        if let transport::Record::Line(line) = record
                            && line == b"mail.eml\tDETECTED\tfixture"
                            && let Some(notice) = notice.take()
                        {
                            let _ = notice.send(());
                        }
                    });
                }
            },
        ));
        tokio::time::timeout(Duration::from_secs(5), received)
            .await
            .unwrap()
            .unwrap();
        assert!(!task.is_finished());
        cancel.send(true).unwrap();
        let outcome = task.await.unwrap().unwrap();
        assert!(outcome.cancelled);
        assert!(outcome.exit_confirmed);
    }

    #[tokio::test]
    async fn cancellation_stops_the_owned_wrapper() {
        let (sender, receiver) = watch::channel(false);
        let task = tokio::spawn(supervise(
            fixture("sleep"),
            receiver,
            Instant::now() + Duration::from_secs(20),
        ));
        tokio::time::sleep(Duration::from_millis(50)).await;
        sender.send(true).unwrap();
        let capture = tokio::time::timeout(Duration::from_secs(8), task)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        assert!(capture.cancelled);
        assert!(capture.termination_requested);
        assert_no_forced_detection(capture);
    }

    #[tokio::test]
    async fn a_process_deadline_is_reported_as_incomplete() {
        let (_sender, receiver) = watch::channel(false);
        let capture = supervise(
            fixture("sleep"),
            receiver,
            Instant::now() + Duration::from_millis(50),
        )
        .await
        .unwrap();
        assert!(capture.timed_out);
        assert!(capture.termination_requested);
        assert_no_forced_detection(capture);
    }

    fn assert_no_forced_detection(capture: classify::Capture) {
        for settings in [
            scanner::Settings::Custom(custom_settings(vec!["{directory}".into()])),
            scanner::Settings::Avast(scanner::avast::Settings::default()),
        ] {
            let result = classify::report(
                &settings,
                Path::new("mail.eml"),
                classify::Capture {
                    code: capture.code,
                    termination_requested: capture.termination_requested,
                    timed_out: capture.timed_out,
                    cancelled: capture.cancelled,
                    ..Default::default()
                },
            );
            assert!(!result.detected());
            assert!(!result.complete());
        }
    }

    fn custom_settings(arguments: Vec<String>) -> scanner::custom::Settings {
        scanner::custom::Settings {
            executable: std::env::current_exe().unwrap(),
            arguments,
            clean_code: 0,
            detected_code: 1,
        }
    }

    #[test]
    fn custom_arguments_are_literal_and_preserve_empty_values() {
        let settings = custom_settings(vec![
            "".into(),
            "a & b | c".into(),
            "\"quoted\"".into(),
            "{directory}".into(),
        ]);
        let path = Path::new("C:/scan folder/mail & example.eml");
        let command = custom::directory_command(&settings.executable, path, &settings);
        assert_eq!(
            command.as_std().get_args().collect::<Vec<_>>(),
            vec![
                std::ffi::OsStr::new(""),
                std::ffi::OsStr::new("a & b | c"),
                std::ffi::OsStr::new("\"quoted\""),
                path.as_os_str(),
            ]
        );
    }

    #[cfg(windows)]
    #[test]
    fn custom_placeholder_keeps_non_unicode_path_units() {
        use std::os::windows::ffi::OsStringExt;
        let mut units = "C:\\scan\\".encode_utf16().collect::<Vec<_>>();
        units.push(0xd800);
        units.extend(".eml".encode_utf16());
        let path = PathBuf::from(std::ffi::OsString::from_wide(&units));
        let settings = custom_settings(vec!["{directory}".into()]);
        let command = custom::directory_command(&settings.executable, &path, &settings);
        assert_eq!(
            command.as_std().get_args().collect::<Vec<_>>(),
            vec![path.as_os_str()]
        );
    }

    #[tokio::test]
    async fn custom_command_round_trips_a_literal_path_to_the_child() {
        let settings = custom_settings(vec![
            "--exact".into(),
            "mailbox_scanner::scanner::tests::child_fixture".into(),
            "--nocapture".into(),
            "--skip".into(),
            "{directory}".into(),
        ]);
        let path = Path::new("C:/scan folder/mail & literal.eml");
        let mut command = custom::directory_command(&settings.executable, path, &settings);
        command
            .env("MAILBOX_SCANNER_FIXTURE", "argv")
            .env("MAILBOX_SCANNER_PATH", path);
        let (_sender, receiver) = watch::channel(false);
        let capture = supervise(command, receiver, Instant::now() + Duration::from_secs(10))
            .await
            .unwrap();
        assert!(String::from_utf8_lossy(&capture.stdout).contains("literal path verified"));
        let report = classify::report(&scanner::Settings::Custom(settings), path, capture);
        assert!(!report.detected());
        assert!(report.complete());
    }

    #[cfg(windows)]
    #[test]
    #[ignore = "Exit-code fixture invoked only in an isolated scanner subprocess"]
    fn child_fixture_exit_one() {
        std::process::exit(1);
    }

    #[cfg(windows)]
    #[tokio::test]
    #[ignore = "Runs installed Defender on harmless EICAR MIME and may trigger real-time quarantine"]
    async fn defender_eicar_mime_integration() {
        let stamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let work = std::env::current_dir()
            .unwrap()
            .join("target")
            .join(format!("scanner-eicar-{}-{stamp}", std::process::id()));
        std::fs::create_dir(&work).unwrap();
        let cleanup = LiveDirectory(work.clone());
        let settings = config::Settings::try_from(config::Draft {
            host: "unused.invalid".into(),
            username: "unused".into(),
            password: "unused".into(),
            scan_dir: work.clone(),
            scanner: scanner::Settings::Defender,
            ..config::Draft::default()
        })
        .unwrap();
        let engine = Engine::resolve(&settings).unwrap();
        // Assemble the standardized harmless signature only when this ignored test runs.
        let signature = [
            &b"X5O!P%@AP[4"[..],
            &b"\\PZX54(P^)7CC)7}$"[..],
            &b"EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"[..],
        ]
        .concat();
        assert_eq!(signature.len(), 68);
        let encoded = test_base64(&signature);
        let path = work.join("message.eml");
        let mail = format!(
            "From: Scanner test <scanner@example.test>\r\nTo: Scanner test <scanner@example.test>\r\nSubject: Harmless EICAR scanner integration\r\nMIME-Version: 1.0\r\nContent-Type: multipart/mixed; boundary=mailbox-eicar-test\r\n\r\n--mailbox-eicar-test\r\nContent-Type: text/plain\r\n\r\nHarmless antivirus integration test.\r\n--mailbox-eicar-test\r\nContent-Type: application/octet-stream; name=eicar.txt\r\nContent-Disposition: attachment; filename=eicar.txt\r\nContent-Transfer-Encoding: base64\r\n\r\n{encoded}\r\n--mailbox-eicar-test--\r\n"
        );
        eprintln!("Engine: {}", engine.executable().display());
        match std::fs::write(&path, mail) {
            Ok(()) => {
                let (_sender, cancel) = watch::channel(false);
                match std::fs::canonicalize(&path) {
                    Ok(path) => {
                        let capture = supervise(
                            engine.command(&path),
                            cancel.clone(),
                            Instant::now() + COMMAND_TIMEOUT,
                        )
                        .await
                        .unwrap();
                        eprintln!("Original EML CLI exit: {:?}", capture.code);
                        eprintln!("stdout:\n{}", String::from_utf8_lossy(&capture.stdout));
                        eprintln!("stderr:\n{}", String::from_utf8_lossy(&capture.stderr));
                        let direct = classify::report(&scanner::Settings::Defender, &path, capture);
                        eprintln!(
                            "Original EML detected={}, complete={}, issues={:?}",
                            direct.detected(),
                            direct.complete(),
                            direct.issues()
                        );
                        let positive = work.join("positive.bin");
                        match std::fs::write(&positive, &signature) {
                            Ok(()) => {
                                let positive = std::fs::canonicalize(&positive).unwrap();
                                let capture = supervise(
                                    engine.command(&positive),
                                    cancel.clone(),
                                    Instant::now() + COMMAND_TIMEOUT,
                                )
                                .await
                                .unwrap();
                                eprintln!(
                                    "Decoded test leaf exit: {:?}\nstdout:\n{}\nstderr:\n{}",
                                    capture.code,
                                    String::from_utf8_lossy(&capture.stdout),
                                    String::from_utf8_lossy(&capture.stderr)
                                );
                                let report = classify::report(
                                    &scanner::Settings::Defender,
                                    &positive,
                                    capture,
                                );
                                eprintln!(
                                    "Decoded test leaf detected={}, complete={}, evidence={:?}, issues={:?}",
                                    report.detected(),
                                    report.complete(),
                                    report.evidence(),
                                    report.issues()
                                );
                                assert!(
                                    report.detected() || !report.complete(),
                                    "Known test material must not be reported as a complete no-detection scan"
                                );
                                if let Err(error) = std::fs::remove_file(&positive) {
                                    eprintln!(
                                        "Decoded test leaf cleanup {}: {error}",
                                        positive.display()
                                    );
                                }
                            }
                            Err(error) => eprintln!(
                                "Decoded test leaf write blocked: {error}; direct positive integration remains unverified"
                            ),
                        }
                        match engine.scan(&path, &mut Vec::new(), cancel).await {
                            Ok(report) => {
                                eprintln!(
                                    "Full MIME pipeline detected={}, complete={}, evidence={:?}, issues={:?}",
                                    report.detected(),
                                    report.complete(),
                                    report.evidence(),
                                    report.issues()
                                );
                                assert!(
                                    report.detected() || !report.complete(),
                                    "Known test material must not be reported as a complete no-detection scan"
                                );
                            }
                            Err(error) => eprintln!(
                                "Full MIME pipeline blocked before a report: {error}; positive integration remains unverified"
                            ),
                        }
                    }
                    Err(error) => eprintln!(
                        "EML intercepted before CLI access: {error}; positive integration remains unverified"
                    ),
                }
            }
            Err(error) => {
                eprintln!("EML write blocked: {error}; positive integration remains unverified")
            }
        }
        drop(cleanup);
    }

    #[cfg(windows)]
    struct LiveDirectory(PathBuf);

    #[cfg(windows)]
    impl Drop for LiveDirectory {
        fn drop(&mut self) {
            if let Ok(entries) = std::fs::read_dir(&self.0) {
                for entry in entries.flatten() {
                    if let Err(error) = std::fs::remove_file(entry.path()) {
                        eprintln!("Test leftover {}: {error}", entry.path().display());
                    }
                }
            }
            if let Err(error) = std::fs::remove_dir(&self.0) {
                eprintln!("Test directory leftover {}: {error}", self.0.display());
            }
        }
    }

    #[cfg(windows)]
    fn test_base64(bytes: &[u8]) -> String {
        const ALPHABET: &[u8; 64] =
            b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let mut encoded = String::new();
        for chunk in bytes.chunks(3) {
            let value = ((chunk[0] as u32) << 16)
                | ((chunk.get(1).copied().unwrap_or(0) as u32) << 8)
                | chunk.get(2).copied().unwrap_or(0) as u32;
            for index in 0..4 {
                encoded.push(if index > chunk.len() {
                    '='
                } else {
                    ALPHABET[((value >> (18 - index * 6)) & 63) as usize] as char
                });
            }
        }
        encoded
            .as_bytes()
            .chunks(76)
            .map(|line| std::str::from_utf8(line).expect("base64 alphabet is ASCII"))
            .collect::<Vec<_>>()
            .join("\r\n")
    }
}
