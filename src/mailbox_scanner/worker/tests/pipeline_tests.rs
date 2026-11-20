use super::*;
use std::num::NonZeroU32;

pub(super) fn snapshot(count: u32) -> mailbox::Snapshot {
    mailbox::Snapshot {
        folder: message::Folder::new("INBOX".into(), "INBOX".into()).unwrap(),
        uidvalidity: NonZeroU32::new(7).unwrap(),
        uids: (1..=count)
            .map(|uid| NonZeroU32::new(uid).unwrap())
            .collect(),
    }
}

async fn command(peer: &mut BufReader<tokio::io::DuplexStream>, expected: &str) -> String {
    let mut line = String::new();
    peer.read_line(&mut line).await.unwrap();
    let (tag, actual) = line.trim_end().split_once(' ').unwrap();
    assert_eq!(actual, expected);
    tag.to_owned()
}

async fn reply(peer: &mut BufReader<tokio::io::DuplexStream>, uid: u32, tag: &str) {
    peer.write_all(
        format!("* {uid} FETCH (UID {uid} BODY[]<0> {{1}}\r\nx)\r\n{tag} OK body\r\n").as_bytes(),
    )
    .await
    .unwrap();
}

#[tokio::test]
async fn configured_depth_bounds_requests_and_refills_before_other_completions() {
    for depth in [1, 2, 4, 8] {
        overlaps_requests_and_refills(depth).await;
    }
}

async fn overlaps_requests_and_refills(depth: u32) {
    let settings = config::Settings::try_from(config::Draft {
        host: "mail.example.com".into(),
        username: "user".into(),
        password: "password".into(),
        scan_dir: "scan".into(),
        download_chunks: depth.to_string(),
        ..Default::default()
    })
    .unwrap();
    let (stream, peer) = tokio::io::duplex(4096);
    let server = tokio::spawn(async move {
        let mut peer = BufReader::new(peer);
        peer.write_all(b"* OK ready\r\n").await.unwrap();
        let tag = command(&mut peer, "LOGIN \"user\" \"password\"").await;
        peer.write_all(format!("{tag} OK login\r\n").as_bytes())
            .await
            .unwrap();
        let tag = command(&mut peer, OPEN.0).await;
        peer.write_all(OPEN.1.replace("{tag}", &tag).as_bytes())
            .await
            .unwrap();
        let uids = (1..=depth + 1)
            .map(|uid| uid.to_string())
            .collect::<Vec<_>>()
            .join(",");
        let tag = command(&mut peer, &format!("UID FETCH {uids} (UID RFC822.SIZE)")).await;
        for uid in 1..=depth + 1 {
            peer.write_all(format!("* {uid} FETCH (UID {uid} RFC822.SIZE 1)\r\n").as_bytes())
                .await
                .unwrap();
        }
        peer.write_all(format!("{tag} OK sizes\r\n").as_bytes())
            .await
            .unwrap();
        let mut tags = Vec::new();
        for uid in 1..=depth {
            tags.push(
                command(
                    &mut peer,
                    &format!("UID FETCH {uid} (UID BODY.PEEK[]<0.1>)"),
                )
                .await,
            );
        }
        // Admission must stop at the configured depth until one response arrives.
        let mut extra = String::new();
        assert!(
            tokio::time::timeout(Duration::from_millis(30), peer.read_line(&mut extra))
                .await
                .is_err()
        );
        reply(&mut peer, depth, tags.last().unwrap()).await;
        let next = command(
            &mut peer,
            &format!("UID FETCH {} (UID BODY.PEEK[]<0.1>)", depth + 1),
        )
        .await;
        for uid in 1..depth {
            reply(&mut peer, uid, &tags[uid as usize - 1]).await;
        }
        reply(&mut peer, depth + 1, &next).await;
    });
    let client =
        mailbox::Client::scripted(stream, message::Account::from_settings(&settings), false)
            .await
            .unwrap();
    let mut client = Some(client);
    let mut worker = Worker {
        settings: &settings,
        client: None,
        pipeline: pipeline::Pipeline::default(),
    };
    worker.begin(snapshot(depth + 1));
    let mut connector = || std::future::ready(Ok(client.take().expect("one connection")));
    let mut seen = Vec::new();
    for _ in 0..depth + 1 {
        let (identity, result) =
            tokio::time::timeout(Duration::from_secs(3), worker.next_with(&mut connector))
                .await
                .unwrap()
                .unwrap();
        assert_eq!(result.unwrap(), b"x");
        seen.push(identity.uid());
    }
    let expected: Vec<_> = std::iter::once(depth)
        .chain(1..depth)
        .chain(std::iter::once(depth + 1))
        .collect();
    assert_eq!(seen, expected);
    assert_eq!(worker.remaining(), 0);
    server.await.unwrap();
}

#[tokio::test]
async fn completed_message_survives_disconnect_and_only_pending_uid_restarts() {
    let settings = settings();
    let (first, a) = peer(vec![OPEN,
        ("UID FETCH 1,2 (UID RFC822.SIZE)", "* 1 FETCH (UID 1 RFC822.SIZE 1)\r\n* 2 FETCH (UID 2 RFC822.SIZE 1)\r\n{tag} OK sizes\r\n"),
        ("UID FETCH 1 (UID BODY.PEEK[]<0.1>)", "* 1 FETCH (UID 1 BODY[]<0> {1}\r\na)\r\n{tag} OK body\r\n"),
        ("UID FETCH 2 (UID BODY.PEEK[]<0.1>)", "* 2 FETCH (UID 2 BODY[]<0> {1}\r\nb)\r\n"),
    ]).await;
    let (second, b) = peer(vec![
        OPEN,
        (
            "UID FETCH 2 (UID BODY.PEEK[]<0.1>)",
            "* 2 FETCH (UID 2 BODY[]<0> {1}\r\nc)\r\n{tag} OK body\r\n",
        ),
    ])
    .await;
    let mut connections = std::collections::VecDeque::from([first, second]);
    let mut connector = || std::future::ready(Ok(connections.pop_front().unwrap()));
    let mut worker = Worker {
        settings: &settings,
        client: None,
        pipeline: pipeline::Pipeline::default(),
    };
    worker.begin(snapshot(2));
    let (identity, result) = worker.next_with(&mut connector).await.unwrap();
    assert_eq!((identity.uid(), result.unwrap()), (1, b"a".to_vec()));
    let (identity, result) = worker.next_with(&mut connector).await.unwrap();
    assert_eq!((identity.uid(), result.unwrap()), (2, b"c".to_vec()));
    a.await.unwrap();
    b.await.unwrap();
}

#[tokio::test]
async fn changed_validity_never_commits_provisional_body() {
    for response in [
        "* 1 FETCH (UID 1 BODY[]<0> {1}\r\nx)\r\n* OK [UIDVALIDITY 8] changed\r\n{tag} OK done\r\n",
        "* 1 FETCH (UID 1 BODY[]<0> {1}\r\nx)\r\n{tag} OK [UIDVALIDITY 8] changed\r\n",
    ] {
        let settings = settings();
        let (client, server) = peer(vec![
            OPEN,
            (
                "UID FETCH 1 (UID RFC822.SIZE)",
                "* 1 FETCH (UID 1 RFC822.SIZE 1)\r\n{tag} OK size\r\n",
            ),
            ("UID FETCH 1 (UID BODY.PEEK[]<0.1>)", response),
        ])
        .await;
        let mut client = Some(client);
        let mut worker = Worker {
            settings: &settings,
            client: None,
            pipeline: pipeline::Pipeline::default(),
        };
        worker.begin(snapshot(1));
        let (_, result) = worker
            .next_with(&mut || std::future::ready(Ok(client.take().unwrap())))
            .await
            .unwrap();
        assert!(matches!(result, Err(mailbox::Error::Stale)));
        server.await.unwrap();
    }
}

#[tokio::test]
async fn cancelled_fragmented_read_resumes_without_losing_parser_bytes() {
    let settings = settings();
    let (stream, peer) = tokio::io::duplex(4096);
    let (release, resume) = tokio::sync::oneshot::channel();
    let server = tokio::spawn(async move {
        let mut peer = BufReader::new(peer);
        peer.write_all(b"* OK ready\r\n").await.unwrap();
        let tag = command(&mut peer, "LOGIN \"user\" \"password\"").await;
        peer.write_all(format!("{tag} OK login\r\n").as_bytes())
            .await
            .unwrap();
        let tag = command(&mut peer, "UID FETCH 1 (UID BODY.PEEK[]<0.4>)").await;
        peer.write_all(b"* 1 FETCH (UID 1 BODY[]<0> {4}\r\nab")
            .await
            .unwrap();
        resume.await.unwrap();
        peer.write_all(format!("cd)\r\n{tag} OK done\r\n").as_bytes())
            .await
            .unwrap();
    });
    let mut client =
        mailbox::Client::scripted(stream, message::Account::from_settings(&settings), false)
            .await
            .unwrap();
    client
        .send("UID FETCH 1 (UID BODY.PEEK[]<0.4>)")
        .await
        .unwrap();
    let limit = tokio::time::Instant::now() + Duration::from_secs(3);
    assert!(
        tokio::time::timeout(
            Duration::from_millis(20),
            client.response(limit, |_| Ok(()))
        )
        .await
        .is_err()
    );
    release.send(()).unwrap();
    let body = client
        .response(limit, |response| {
            if let async_imap::imap_proto::Response::Fetch(_, attributes) = response {
                for attribute in attributes {
                    if let async_imap::imap_proto::AttributeValue::BodySection {
                        data: Some(data),
                        ..
                    } = attribute
                    {
                        return Ok(data.to_vec());
                    }
                }
            }
            panic!("expected complete body");
        })
        .await
        .unwrap();
    assert_eq!(body, b"abcd");
    client.response(limit, |_| Ok(())).await.unwrap();
    server.await.unwrap();
}

#[tokio::test]
async fn cancelling_a_blocked_write_invalidates_the_session() {
    let settings = settings();
    let (stream, peer) = tokio::io::duplex(128);
    let (release, done) = tokio::sync::oneshot::channel();
    let server = tokio::spawn(async move {
        let mut peer = BufReader::new(peer);
        peer.write_all(b"* OK ready\r\n").await.unwrap();
        let tag = command(&mut peer, "LOGIN \"user\" \"password\"").await;
        peer.write_all(format!("{tag} OK login\r\n").as_bytes())
            .await
            .unwrap();
        done.await.unwrap();
    });
    let mut client =
        mailbox::Client::scripted(stream, message::Account::from_settings(&settings), false)
            .await
            .unwrap();
    assert!(
        tokio::time::timeout(Duration::from_millis(20), client.send(&"X".repeat(4096)))
            .await
            .is_err()
    );
    assert!(matches!(
        client.send("NOOP").await,
        Err(mailbox::Error::Disconnected)
    ));
    release.send(()).unwrap();
    server.await.unwrap();
}

#[tokio::test]
async fn reconciliation_failure_stops_before_later_metadata_uids() {
    let settings = settings();
    let (client, server) = peer(vec![
        OPEN,
        ("UID FETCH 1,2,3 (UID RFC822.SIZE)", "{tag} OK empty\r\n"),
    ])
    .await;
    let mut client = Some(client);
    let mut attempts = 0;
    let mut connector = || {
        attempts += 1;
        std::future::ready(
            client
                .take()
                .ok_or(mailbox::Error::Unexpected("authentication refused")),
        )
    };
    let mut worker = Worker {
        settings: &settings,
        client: None,
        pipeline: pipeline::Pipeline::default(),
    };
    worker.begin(snapshot(3));
    let (identity, result) = worker.next_with(&mut connector).await.unwrap();
    assert_eq!(identity.uid(), 1);
    assert!(matches!(result, Err(mailbox::Error::Unexpected(_))));
    assert_eq!(attempts, 2);
    assert_eq!(worker.remaining(), 2);
    server.await.unwrap();
}

#[test]
fn full_body_reservations_prevent_four_sixty_mib_admissions() {
    let settings = settings();
    let account = message::Account::from_settings(&settings);
    let snapshot = snapshot(4);
    let mut pipeline = pipeline::Pipeline::default();
    for (index, uid) in snapshot.uids.into_iter().enumerate() {
        pipeline.entries.push(pipeline::Entry {
            identity: message::Identity::new(
                account.clone(),
                snapshot.folder.clone(),
                snapshot.uidvalidity,
                uid,
            ),
            size: 60 * 1024 * 1024,
            bytes: (index < 3).then(Vec::new),
            request: None,
            result: None,
            retired: false,
            retries: Retry::default(),
            attempted: index < 3,
        });
    }
    // Occupied requests are not eligible for another chunk.
    for index in 0..3 {
        pipeline.sent(index, format!("A{index}"));
    }
    assert!(pipeline.candidate(4).is_none());
    assert!(pipeline.entries[3].bytes.is_none());
    pipeline.entries[0].retired = true;
    pipeline.held = 60 * 1024 * 1024;
    assert!(pipeline.candidate(4).is_none());
    pipeline.resume();
    assert_eq!(pipeline.candidate(4), Some(3));
}

#[tokio::test]
async fn parser_rejects_over_limit_literal_declaration_before_body_allocation() {
    let (mut client, server) = peer(vec![(
        "UID FETCH 1 (UID BODY.PEEK[]<0.1>)",
        "* 1 FETCH (UID 1 BODY[]<0> {536870913}\r\n",
    )])
    .await;
    client
        .send("UID FETCH 1 (UID BODY.PEEK[]<0.1>)")
        .await
        .unwrap();
    let error = client
        .response(tokio::time::Instant::now() + Duration::from_secs(2), |_| {
            Ok(())
        })
        .await
        .unwrap_err();
    assert!(!error.retryable(), "{error:?}");
    server.await.unwrap();
}
