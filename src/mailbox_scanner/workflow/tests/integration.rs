use super::*;
use tokio::io::AsyncReadExt;

fn settings(root: &Path) -> config::Settings {
    config::Settings::try_from(config::Draft {
        host: "imap.example.test".into(),
        username: "user".into(),
        password: "password".into(),
        scan_dir: root.into(),
        quarantine_dir: root.into(),
        parallel: "1".into(),
        ..Default::default()
    })
    .unwrap()
}

async fn command(peer: &mut BufReader<tokio::io::DuplexStream>, expected: &str) -> String {
    let mut line = String::new();
    peer.read_line(&mut line).await.unwrap();
    let (tag, actual) = line.trim_end().split_once(' ').unwrap();
    assert_eq!(actual, expected);
    tag.to_owned()
}

async fn pending_peer(
    settings: &config::Settings,
    disconnect: bool,
) -> (
    mailbox::Client<tokio::io::DuplexStream>,
    tokio::sync::oneshot::Receiver<()>,
    tokio::task::JoinHandle<()>,
) {
    let (stream, peer) = tokio::io::duplex(4096);
    let (pending, ready) = tokio::sync::oneshot::channel();
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
            ("UID SEARCH ALL", "* SEARCH 1 2\r\n{tag} OK search\r\n"),
            (
                "EXAMINE \"INBOX\"",
                "* OK [UIDVALIDITY 7] stable\r\n{tag} OK open\r\n",
            ),
            (
                "UID FETCH 1,2 (UID RFC822.SIZE)",
                "* 1 FETCH (UID 1 RFC822.SIZE 4)\r\n* 2 FETCH (UID 2 RFC822.SIZE 4)\r\n{tag} OK sizes\r\n",
            ),
        ] {
            let tag = command(&mut peer, expected).await;
            peer.write_all(response.replace("{tag}", &tag).as_bytes())
                .await
                .unwrap();
        }
        let first = command(&mut peer, "UID FETCH 1 (UID BODY.PEEK[]<0.4>)").await;
        command(&mut peer, "UID FETCH 2 (UID BODY.PEEK[]<0.4>)").await;
        peer.write_all(
            format!("* 1 FETCH (UID 1 BODY[]<0> {{4}}\r\n\r\nxx)\r\n{first} OK body\r\n")
                .as_bytes(),
        )
        .await
        .unwrap();
        pending.send(()).unwrap();
        if disconnect {
            return;
        }
        let mut byte = [0];
        assert_eq!(
            peer.read(&mut byte).await.unwrap(),
            0,
            "cancel must close connection before scanner settlement"
        );
    });
    let client =
        mailbox::Client::scripted(stream, message::Account::from_settings(settings), false)
            .await
            .unwrap();
    (client, ready, server)
}

async fn scenario(hold_scanner: bool, close_receiver: bool, disconnect: bool, full_receiver: bool) {
    let root = unique_directory(&std::env::temp_dir(), "coordinator-integration").unwrap();
    let settings = settings(&root);
    let (client, pending, server) = pending_peer(&settings, disconnect).await;
    let (events, mut receiver) = mpsc::channel(32);
    let fill = events.clone();
    let (cancel, cancelled) = watch::channel(false);
    let gate = Arc::new(tokio::sync::Semaphore::new(0));
    let scan_gate = gate.clone();
    let (started, mut starts) = mpsc::channel(1);
    let run = tokio::spawn(async move {
        let mut client = Some(client);
        let mut counts = event::Counts::default();
        let result = execute_with(
            &settings,
            &events,
            &mut counts,
            cancelled,
            &mut || {
                let client = client.take();
                async move {
                    match client {
                        Some(client) => Ok(client),
                        None => std::future::pending().await,
                    }
                }
            },
            move |pending: Pending, _| {
                let gate = scan_gate.clone();
                let started = started.clone();
                async move {
                    started.send(()).await.unwrap();
                    if hold_scanner {
                        gate.acquire().await.unwrap().forget();
                    }
                    let leftovers = cleanup(&pending.files).await;
                    Job {
                        identity: pending.identity,
                        subject: pending.subject,
                        sender: pending.sender,
                        report: detection::Report::new(),
                        leftovers,
                    }
                }
            },
        )
        .await;
        (result, counts)
    });
    pending.await.unwrap();
    starts.recv().await.unwrap();
    if full_receiver {
        while fill
            .try_send(event::Event::Progress {
                counts: event::Counts::default(),
                folder: None,
            })
            .is_ok()
        {}
        gate.add_permits(1);
        tokio::time::sleep(Duration::from_millis(30)).await;
    }
    if !hold_scanner {
        tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                if let Some(event::Event::Progress { counts, .. }) = receiver.recv().await
                    && counts.processed == 1
                {
                    break;
                }
            }
        })
        .await
        .expect("scanner completion must be serviced while IMAP remains pending");
    }
    if close_receiver {
        receiver.close();
    } else {
        cancel.send(true).unwrap();
    }
    tokio::time::timeout(Duration::from_secs(2), server)
        .await
        .unwrap()
        .unwrap();
    if hold_scanner {
        assert!(
            !run.is_finished(),
            "local scanner still owns its staged files"
        );
        if !full_receiver {
            gate.add_permits(1);
        }
    }
    let mut publications = 0;
    if full_receiver {
        tokio::time::timeout(Duration::from_secs(2), async {
            while !run.is_finished() {
                tokio::select! {
                    event = receiver.recv() => if matches!(event, Some(event::Event::MessageFinished { .. })) { publications += 1; },
                    _ = tokio::time::sleep(Duration::from_millis(5)) => {},
                }
            }
        }).await.unwrap();
        while let Ok(event) = receiver.try_recv() {
            if matches!(event, event::Event::MessageFinished { .. }) {
                publications += 1;
            }
        }
        assert_eq!(
            publications, 1,
            "terminal scanner result must remain retained through cancellation"
        );
    }
    let (finish, counts) = tokio::time::timeout(Duration::from_secs(2), run)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(finish.unwrap(), event::Finish::Cancelled);
    assert_eq!(
        (counts.total, counts.processed, counts.cancelled),
        (2, 1, 1)
    );
    assert_eq!(std::fs::read_dir(&root).unwrap().count(), 0);
    std::fs::remove_dir(root).unwrap();
}

#[tokio::test]
async fn services_scanner_completion_while_body_read_waits() {
    scenario(false, false, false, false).await;
}

#[tokio::test]
async fn cancellation_closes_imap_before_waiting_for_scanner() {
    scenario(true, false, false, false).await;
}

#[tokio::test]
async fn receiver_closure_closes_imap_before_waiting_for_scanner() {
    scenario(true, true, false, false).await;
}

#[tokio::test]
async fn services_scanner_completion_during_network_retry() {
    scenario(false, false, true, false).await;
}

#[tokio::test]
async fn full_gui_channel_does_not_delay_network_cancellation_or_lose_result() {
    scenario(true, false, false, true).await;
}

#[tokio::test]
async fn full_gui_channel_retains_download_diagnostic_but_closes_connection_on_cancel() {
    let root = unique_directory(&std::env::temp_dir(), "diagnostic-cancel").unwrap();
    let settings = settings(&root);
    let (stream, peer) = tokio::io::duplex(4096);
    let (ready, metadata) = tokio::sync::oneshot::channel();
    let (release, released) = tokio::sync::oneshot::channel();
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
            ("UID SEARCH ALL", "* SEARCH 1 2\r\n{tag} OK search\r\n"),
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
        let tag = command(&mut peer, "UID FETCH 1,2 (UID RFC822.SIZE)").await;
        ready.send(()).unwrap();
        released.await.unwrap();
        peer.write_all(format!("* 1 FETCH (UID 1 RFC822.SIZE 209715201)\r\n* 2 FETCH (UID 2 RFC822.SIZE 1)\r\n{tag} OK sizes\r\n").as_bytes()).await.unwrap();
        assert_eq!(peer.read(&mut [0]).await.unwrap(), 0);
    });
    let client =
        mailbox::Client::scripted(stream, message::Account::from_settings(&settings), false)
            .await
            .unwrap();
    let (events, mut receiver) = mpsc::channel(32);
    let fill = events.clone();
    let (cancel, cancelled) = watch::channel(false);
    let mut run = tokio::spawn(async move {
        let mut client = Some(client);
        let mut counts = event::Counts::default();
        let result = execute_with(
            &settings,
            &events,
            &mut counts,
            cancelled,
            &mut || std::future::ready(Ok(client.take().unwrap())),
            |_, _| async { panic!("no message may reach scanner") },
        )
        .await;
        (result, counts)
    });
    metadata.await.unwrap();
    while fill
        .try_send(event::Event::Progress {
            counts: event::Counts::default(),
            folder: None,
        })
        .is_ok()
    {}
    release.send(()).unwrap();
    tokio::time::sleep(Duration::from_millis(30)).await;
    cancel.send(true).unwrap();
    tokio::time::timeout(Duration::from_secs(2), server)
        .await
        .unwrap()
        .unwrap();
    assert!(!run.is_finished());
    let mut diagnostics = 0;
    let (result, counts) = tokio::time::timeout(Duration::from_secs(2), async {
        loop { tokio::select! {
            result = &mut run => break result.unwrap(),
            event = receiver.recv() => if matches!(event, Some(event::Event::Diagnostic { .. })) { diagnostics += 1; },
        } }
    }).await.unwrap();
    while let Ok(event) = receiver.try_recv() {
        if matches!(event, event::Event::Diagnostic { .. }) {
            diagnostics += 1;
        }
    }
    assert_eq!(diagnostics, 1);
    assert_eq!(result.unwrap(), event::Finish::Cancelled);
    assert_eq!(
        (counts.processed, counts.incomplete, counts.cancelled),
        (1, 1, 1)
    );
    assert_eq!(std::fs::read_dir(&root).unwrap().count(), 0);
    std::fs::remove_dir(root).unwrap();
}
