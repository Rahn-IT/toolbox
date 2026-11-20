use super::pipeline_tests::snapshot;
use super::*;

#[tokio::test]
async fn four_rejected_peers_do_not_exhaust_healthy_multichunk_message() {
    let settings = settings();
    let mut connections = std::collections::VecDeque::new();
    let mut servers = Vec::new();
    for (round, uids) in [
        vec![1, 2, 3, 4],
        vec![1, 2, 3, 5],
        vec![1, 2, 3],
        vec![1, 2],
    ]
    .into_iter()
    .enumerate()
    {
        let mut steps = vec![(OPEN.0.to_owned(), OPEN.1.to_owned())];
        if round == 0 {
            steps.push(("UID FETCH 1,2,3,4,5 (UID RFC822.SIZE)".into(), "* 1 FETCH (UID 1 RFC822.SIZE 1048577)\r\n* 2 FETCH (UID 2 RFC822.SIZE 1)\r\n* 3 FETCH (UID 3 RFC822.SIZE 1)\r\n* 4 FETCH (UID 4 RFC822.SIZE 1)\r\n* 5 FETCH (UID 5 RFC822.SIZE 1)\r\n{tag} OK sizes\r\n".into()));
        }
        for (index, uid) in uids.iter().enumerate() {
            steps.push((
                format!(
                    "UID FETCH {uid} (UID BODY.PEEK[]<0.{}>)",
                    if *uid == 1 { 1048576 } else { 1 }
                ),
                if index + 1 == uids.len() {
                    "{tag} NO gone\r\n"
                } else {
                    ""
                }
                .into(),
            ));
        }
        let (client, server) = peer(
            steps
                .iter()
                .map(|(a, b)| (a.as_str(), b.as_str()))
                .collect(),
        )
        .await;
        connections.push_back(client);
        servers.push(server);
    }
    let body = format!(
        "* 1 FETCH (UID 1 BODY[]<0> {{1048576}}\r\n{})\r\n{{tag}} OK chunk\r\n",
        "x".repeat(1048576)
    );
    let (client, server) = peer(vec![
        OPEN,
        ("UID FETCH 1 (UID BODY.PEEK[]<0.1048576>)", &body),
        (
            "UID FETCH 1 (UID BODY.PEEK[]<1048576.1>)",
            "* 1 FETCH (UID 1 BODY[]<1048576> {1}\r\ny)\r\n{tag} OK done\r\n",
        ),
    ])
    .await;
    connections.push_back(client);
    servers.push(server);
    let mut worker = Worker::new(&settings);
    worker.begin(snapshot(5));
    let mut connect = || std::future::ready(Ok(connections.pop_front().unwrap()));
    for uid in [4, 5, 3, 2] {
        let (identity, result) = worker.next_with(&mut connect).await.unwrap();
        assert_eq!(identity.uid(), uid);
        assert!(matches!(
            result,
            Err(mailbox::Error::Rejected { status: "NO", .. })
        ));
        assert_eq!(worker.pipeline.entries[0].retries.failures, 0);
    }
    let (identity, result) = worker.next_with(&mut connect).await.unwrap();
    assert_eq!(identity.uid(), 1);
    let body = result.unwrap();
    assert_eq!(body.len(), 1048577);
    assert_eq!(body.last(), Some(&b'y'));
    for server in servers {
        server.await.unwrap();
    }
}

#[tokio::test]
async fn reconnect_failures_use_the_interrupted_messages_existing_budget() {
    let settings = settings();
    let (client, server) = peer(vec![
        OPEN,
        (
            "UID FETCH 1 (UID RFC822.SIZE)",
            "* 1 FETCH (UID 1 RFC822.SIZE 1)\r\n{tag} OK size\r\n",
        ),
        ("UID FETCH 1 (UID BODY.PEEK[]<0.1>)", ""),
    ])
    .await;
    let mut client = Some(client);
    let mut attempts = 0;
    let mut connect = || {
        attempts += 1;
        std::future::ready(client.take().ok_or_else(|| {
            mailbox::Error::Io(std::io::Error::from(std::io::ErrorKind::ConnectionReset))
        }))
    };
    let mut worker = Worker::new(&settings);
    worker.begin(snapshot(1));
    let (_, result) = tokio::time::timeout(Duration::from_secs(10), worker.next_with(&mut connect))
        .await
        .unwrap()
        .unwrap();
    assert!(result.is_err());
    assert_eq!(attempts, 4);
    assert_eq!(worker.pipeline.entries[0].retries.failures, 3);
    server.await.unwrap();
}

#[tokio::test]
async fn local_pause_stops_admission_and_excludes_paused_time_from_deadlines() {
    let settings = settings();
    let (client, server) = peer(vec![OPEN,
        ("UID FETCH 1,2 (UID RFC822.SIZE)", "* 1 FETCH (UID 1 RFC822.SIZE 1)\r\n* 2 FETCH (UID 2 RFC822.SIZE 1)\r\n{tag} OK sizes\r\n"),
        ("UID FETCH 1 (UID BODY.PEEK[]<0.1>)", "* 1 FETCH (UID 1 BODY[]<0> {1}\r\nx)\r\n{tag} OK body\r\n"),
        ("UID FETCH 2 (UID BODY.PEEK[]<0.1>)", "* 2 FETCH (UID 2 BODY[]<0> {1}\r\ny)\r\n{tag} OK body\r\n")]).await;
    let mut client = Some(client);
    let mut connect = || std::future::ready(Ok(client.take().unwrap()));
    let mut worker = Worker::new(&settings);
    worker.begin(snapshot(2));
    worker.next_with(&mut connect).await.unwrap().1.unwrap();
    assert_eq!(worker.pipeline.held, 1);
    let deadline = worker.pipeline.entries[1]
        .request
        .as_ref()
        .unwrap()
        .deadline;
    worker.pipeline.paused = Some(tokio::time::Instant::now() - Duration::from_secs(180));
    tokio::time::sleep(Duration::from_millis(15)).await;
    assert!(
        worker.pipeline.entries[1].result.is_none(),
        "no polling while staging owns handoff"
    );
    worker.pipeline.resume();
    assert!(
        worker.pipeline.entries[1]
            .request
            .as_ref()
            .unwrap()
            .deadline
            >= deadline + Duration::from_secs(180)
    );
    assert_eq!(worker.pipeline.held, 0);
    assert_eq!(
        worker.next_with(&mut connect).await.unwrap().1.unwrap(),
        b"y"
    );
    server.await.unwrap();
}

#[tokio::test]
async fn literal_bytes_refresh_idle_budget_but_silence_expires() {
    for active in [true, false] {
        let settings = settings();
        let (stream, peer) = tokio::io::duplex(4096);
        let server = tokio::spawn(async move {
            let mut peer = BufReader::new(peer);
            peer.write_all(b"* OK ready\r\n").await.unwrap();
            let mut login = String::new();
            peer.read_line(&mut login).await.unwrap();
            let tag = login.split_once(' ').unwrap().0;
            peer.write_all(format!("{tag} OK login\r\n").as_bytes())
                .await
                .unwrap();
            peer.write_all(b"* 1 FETCH (UID 1 BODY[]<0> {8}\r\n")
                .await
                .unwrap();
            if active {
                for byte in b"abcdefgh" {
                    tokio::time::sleep(Duration::from_millis(30)).await;
                    peer.write_all(&[*byte]).await.unwrap();
                }
                peer.write_all(b")\r\n").await.unwrap();
            } else {
                tokio::time::sleep(Duration::from_millis(300)).await;
            }
        });
        let mut client =
            mailbox::Client::scripted(stream, message::Account::from_settings(&settings), false)
                .await
                .unwrap();
        let result = client
            .response_with_idle(
                tokio::time::Instant::now() + Duration::from_secs(2),
                Duration::from_millis(100),
                |_| Ok(()),
            )
            .await;
        if active {
            result.unwrap();
        } else {
            assert!(matches!(
                result,
                Err(mailbox::Error::Timeout("body inactivity"))
            ));
        }
        server.await.unwrap();
    }
}

#[tokio::test]
async fn unrelated_chatter_cannot_extend_request_completion_deadline() {
    let settings = settings();
    let (stream, peer) = tokio::io::duplex(4096);
    let server = tokio::spawn(async move {
        let mut peer = BufReader::new(peer);
        peer.write_all(b"* OK ready\r\n").await.unwrap();
        let mut login = String::new();
        peer.read_line(&mut login).await.unwrap();
        let tag = login.split_once(' ').unwrap().0;
        peer.write_all(format!("{tag} OK login\r\n").as_bytes())
            .await
            .unwrap();
        loop {
            tokio::time::sleep(Duration::from_millis(10)).await;
            if peer.write_all(b"* 1 EXISTS\r\n").await.is_err() {
                break;
            }
        }
    });
    let mut client =
        mailbox::Client::scripted(stream, message::Account::from_settings(&settings), false)
            .await
            .unwrap();
    let limit = tokio::time::Instant::now() + Duration::from_millis(120);
    let mut responses = 0;
    loop {
        match client
            .response_with_idle(limit, Duration::from_millis(100), |_| Ok(()))
            .await
        {
            Ok(()) => responses += 1,
            Err(error) => {
                assert!(matches!(
                    error,
                    mailbox::Error::Timeout("request completion")
                ));
                break;
            }
        }
    }
    assert!(responses > 1);
    drop(client);
    server.await.unwrap();
}
