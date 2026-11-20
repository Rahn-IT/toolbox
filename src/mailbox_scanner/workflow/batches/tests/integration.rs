use super::*;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

async fn command(peer: &mut BufReader<tokio::io::DuplexStream>, expected: &str) -> String {
    let mut line = String::new();
    peer.read_line(&mut line).await.unwrap();
    let (tag, actual) = line.trim_end().split_once(' ').unwrap();
    assert_eq!(actual, expected);
    tag.to_owned()
}

#[tokio::test]
async fn coordinator_services_active_batch_and_flushes_outage_remainder_once() {
    let root = unique_directory(&std::env::temp_dir(), "batch-network-integration").unwrap();
    let executable = root.join("fixture.exe");
    let source = root.join("fixture.rs");
    let starts = root.join("starts.txt");
    std::fs::write(
        &source,
        r#"
use std::{env,fs,io::Write,path::PathBuf};
fn main() {
    let args: Vec<_> = env::args_os().collect();
    let mut marker = fs::OpenOptions::new().create(true).append(true).open(&args[2]).unwrap();
    writeln!(marker,"started").unwrap();
    for entry in fs::read_dir(PathBuf::from(&args[1])).unwrap() {
        let path = entry.unwrap().path();
        if path.is_file() {
            println!("{}\tCLEAN", path.file_name().unwrap().to_str().unwrap());
        }
    }
}
"#,
    )
    .unwrap();
    let output = std::process::Command::new("rustc")
        .arg("--edition=2024")
        .arg(&source)
        .arg("-o")
        .arg(&executable)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    for full in [false, true] {
        let scan_dir = unique_directory(&root, "scan").unwrap();
        let settings = config::Settings::try_from(config::Draft {
            host: "imap.example.test".into(),
            username: "user".into(),
            password: "password".into(),
            scan_dir: scan_dir.clone(),
            batch_mib: "1".into(),
            parallel: "1".into(),
            scanner: crate::mailbox_scanner::core::scanner::Settings::Custom(
                crate::mailbox_scanner::core::scanner::custom::Settings {
                    executable: executable.clone(),
                    arguments: vec!["{directory}".into(), starts.to_str().unwrap().into()],
                    clean_code: 0,
                    detected_code: 1,
                },
            ),
            ..Default::default()
        })
        .unwrap();
        let mut body = b"Subject: fixture\r\n\r\nharmless".to_vec();
        if full {
            body.resize(1024 * 1024, b'x');
        }
        let size = body.len();
        let (stream, peer) = tokio::io::duplex(4096);
        let (release, fail) = tokio::sync::oneshot::channel();
        let server = tokio::spawn(async move {
            let mut peer = BufReader::new(peer);
            peer.write_all(b"* OK ready\r\n").await.unwrap();
            for (expected, response) in [
                ("LOGIN \"user\" \"password\"", "{tag} OK login\r\n"),
                (
                    "LIST \"\" \"*\"",
                    "* LIST () \"/\" \"INBOX\"\r\n{tag} OK list\r\n",
                ),
                (
                    "EXAMINE \"INBOX\"",
                    "* OK [UIDVALIDITY 7] stable\r\n{tag} OK open\r\n",
                ),
                ("UID SEARCH ALL", "* SEARCH 1 2 3\r\n{tag} OK search\r\n"),
                (
                    "EXAMINE \"INBOX\"",
                    "* OK [UIDVALIDITY 7] stable\r\n{tag} OK open\r\n",
                ),
            ] {
                let tag = command(&mut peer, expected).await;
                peer.write_all(response.replace("{tag}", &tag).as_bytes())
                    .await
                    .unwrap();
            }
            let tag = command(&mut peer, "UID FETCH 1,2,3 (UID RFC822.SIZE)").await;
            peer.write_all(format!("* 1 FETCH (UID 1 RFC822.SIZE {size})\r\n* 2 FETCH (UID 2 RFC822.SIZE 1)\r\n* 3 FETCH (UID 3 RFC822.SIZE 1)\r\n{tag} OK sizes\r\n").as_bytes()).await.unwrap();
            let first = command(
                &mut peer,
                &format!("UID FETCH 1 (UID BODY.PEEK[]<0.{size}>)"),
            )
            .await;
            let second = command(&mut peer, "UID FETCH 2 (UID BODY.PEEK[]<0.1>)").await;
            command(&mut peer, "UID FETCH 3 (UID BODY.PEEK[]<0.1>)").await;
            peer.write_all(format!("* 1 FETCH (UID 1 BODY[]<0> {{{size}}}\r\n").as_bytes())
                .await
                .unwrap();
            peer.write_all(&body).await.unwrap();
            peer.write_all(format!(")\r\n{first} OK body\r\n").as_bytes())
                .await
                .unwrap();
            fail.await.unwrap();
            peer.write_all(format!("{second} BAD terminal\r\n").as_bytes())
                .await
                .unwrap();
        });
        let client =
            mailbox::Client::scripted(stream, message::Account::from_settings(&settings), false)
                .await
                .unwrap();
        let engine = scanner::Engine::resolve(&settings).unwrap();
        let (events, mut receiver) = mpsc::channel(64);
        let (_cancel, cancelled) = watch::channel(false);
        let run = tokio::spawn(async move {
            let mut counts = event::Counts::default();
            let mut client = Some(client);
            let finish = execute_with(
                &settings,
                &events,
                &mut counts,
                cancelled,
                engine,
                &mut || std::future::ready(Ok(client.take().unwrap())),
            )
            .await;
            (finish, counts)
        });
        if full {
            tokio::time::timeout(Duration::from_secs(5), async {
                loop {
                    if let Some(event::Event::Progress { counts, .. }) = receiver.recv().await
                        && counts.processed == 1
                    {
                        break;
                    }
                }
            })
            .await
            .expect("batch completion must publish while next IMAP body is pending");
        }
        release.send(()).unwrap();
        let (finish, counts) = tokio::time::timeout(Duration::from_secs(5), run)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(finish.unwrap(), event::Finish::Partial);
        assert_eq!(
            (
                counts.total,
                counts.processed,
                counts.incomplete,
                counts.cancelled
            ),
            (3, 2, 1, 1)
        );
        assert_eq!(
            std::fs::read_to_string(&starts).unwrap().lines().count(),
            if full { 2 } else { 1 }
        );
        server.await.unwrap();
        std::fs::remove_dir(scan_dir.join("quarantine")).unwrap();
        assert_eq!(std::fs::read_dir(&scan_dir).unwrap().count(), 0);
        std::fs::remove_dir(scan_dir).unwrap();
    }
    for path in [source, executable.with_extension("pdb"), executable, starts] {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
        loop {
            match std::fs::remove_file(&path) {
                Ok(()) => break,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => break,
                Err(error)
                    if matches!(error.raw_os_error(), Some(32 | 33))
                        && tokio::time::Instant::now() < deadline =>
                {
                    tokio::time::sleep(Duration::from_millis(25)).await;
                }
                Err(error) => panic!("Fixture artifact retained at {}: {error}", path.display()),
            }
        }
    }
    std::fs::remove_dir(&root).unwrap_or_else(|error| {
        panic!("Fixture directory retained at {}: {error}", root.display())
    });
}
