//! Connection-independent scan discovery and bounded retry of read-only operations.

use std::time::Duration;

mod pipeline;

use super::{
    core::{config, message},
    mailbox,
};

const MAX_UIDS: usize = 1_000_000;

/// Shared read-only worker; callers retain completed downloads while staging them.
pub struct Worker<'a, T = tokio_rustls::client::TlsStream<tokio::net::TcpStream>>
where
    T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + std::fmt::Debug + Send,
{
    settings: &'a config::Settings,
    client: Option<mailbox::Client<T>>,
    pipeline: pipeline::Pipeline,
}

/// A discovery result remains usable even if later discovery could not finish.
pub struct Discovery {
    pub snapshots: Vec<mailbox::Snapshot>,
    pub error: Option<mailbox::Error>,
}

#[derive(Default)]
struct Retry {
    failures: u8,
}

impl Retry {
    fn delay(&mut self, error: &mailbox::Error) -> Option<Duration> {
        if !error.retryable() || self.failures == 3 {
            return None;
        }
        let delay = Duration::from_secs(1 << self.failures);
        self.failures += 1;
        Some(delay)
    }
}

impl<'a, T> Worker<'a, T>
where
    T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + std::fmt::Debug + Send,
{
    pub fn new(settings: &'a config::Settings) -> Self {
        Self {
            settings,
            client: None,
            pipeline: pipeline::Pipeline::default(),
        }
    }
    pub fn begin(&mut self, snapshot: mailbox::Snapshot) {
        let account = message::Account::from_settings(self.settings);
        self.pipeline = pipeline::Pipeline::default();
        self.pipeline.pending = snapshot
            .uids
            .into_iter()
            .map(|uid| {
                message::Identity::new(
                    account.clone(),
                    snapshot.folder.clone(),
                    snapshot.uidvalidity,
                    uid,
                )
            })
            .collect();
    }

    pub fn remaining(&self) -> usize {
        self.pipeline.remaining()
    }

    /// Release network and unconsumed buffers before waiting for local scanners.
    pub fn stop(&mut self) {
        self.client = None;
        self.pipeline = pipeline::Pipeline::default();
    }

    pub(super) async fn next_with<C, F>(
        &mut self,
        connect: &mut C,
    ) -> Option<(message::Identity, Result<Vec<u8>, mailbox::Error>)>
    where
        C: FnMut() -> F,
        F: Future<Output = Result<mailbox::Client<T>, mailbox::Error>>,
    {
        self.pipeline.resume();
        let mut connection_retries = Retry::default();
        loop {
            if let Some(entry) = self
                .pipeline
                .entries
                .iter_mut()
                .find(|entry| !entry.retired && entry.result.is_some())
            {
                entry.retired = true;
                self.pipeline.held = entry.size;
                self.pipeline.paused = Some(tokio::time::Instant::now());
                return Some((
                    entry.identity.clone(),
                    entry.result.take().expect("completed result"),
                ));
            }
            if let Some(error) = self.pipeline.fatal.take() {
                let identity = if let Some(entry) = self
                    .pipeline
                    .entries
                    .iter_mut()
                    .find(|entry| !entry.retired)
                {
                    entry.retired = true;
                    entry.identity.clone()
                } else {
                    self.pipeline.pending.pop_front()?
                };
                return Some((identity, Err(error)));
            }
            if self.pipeline.entries.iter().all(|entry| entry.retired) {
                self.pipeline.entries.clear();
                let identities: Vec<_> = self.pipeline.pending.iter().take(32).cloned().collect();
                let identity = identities.first()?;
                let mut retries = Retry::default();
                let mut rejected = false;
                let sizes = loop {
                    let result = async {
                        let client = self.connection(connect).await?;
                        client.open(identity, false).await?;
                        client.sizes(&identities).await
                    }
                    .await;
                    match result {
                        Ok(sizes) => break sizes,
                        Err(mailbox::Error::Rejected {
                            operation: "message size",
                            status: "NO",
                        }) => {
                            self.client = None;
                            rejected = true;
                            break vec![None; identities.len()];
                        }
                        Err(error) => {
                            if let Err(error) = self.retry(&mut retries, error).await {
                                self.pipeline.fatal = Some(error);
                                break Vec::new();
                            }
                        }
                    }
                };
                if self.pipeline.fatal.is_some() {
                    continue;
                }
                self.pipeline.selected = !rejected;
                for (identity, size) in identities.into_iter().zip(sizes) {
                    if self.pipeline.fatal.is_some() {
                        break;
                    }
                    self.pipeline.pending.pop_front();
                    let result = match size {
                        _ if rejected => Some(Err(mailbox::Error::Rejected {
                            operation: "message size",
                            status: "NO",
                        })),
                        Some(size) if size > mailbox::MAX_MESSAGE => {
                            Some(Err(mailbox::Error::Oversize(size as u64)))
                        }
                        None => {
                            self.client = None;
                            self.pipeline.selected = false;
                            match self.exists(&identity, connect).await {
                                Ok(false) => Some(Err(mailbox::Error::Missing)),
                                Ok(true) => Some(Err(mailbox::Error::Size)),
                                Err(error) => {
                                    self.pipeline.fatal = Some(error);
                                    None
                                }
                            }
                        }
                        _ => None,
                    };
                    self.pipeline.entries.push(pipeline::Entry {
                        identity,
                        size: if result.is_some() {
                            0
                        } else {
                            size.unwrap_or(0)
                        },
                        bytes: None,
                        request: None,
                        result,
                        retired: false,
                        retries: Retry::default(),
                        attempted: false,
                    });
                }
                continue;
            }
            if !self.pipeline.selected {
                let identity = self
                    .pipeline
                    .entries
                    .iter()
                    .find(|entry| !entry.retired)
                    .expect("unfinished message")
                    .identity
                    .clone();
                let result =
                    async { self.connection(connect).await?.open(&identity, false).await }.await;
                if let Err(error) = result {
                    self.client = None;
                    if self
                        .pipeline
                        .entries
                        .iter()
                        .any(|entry| entry.attempted && !entry.retired && entry.result.is_none())
                    {
                        match self.pipeline.reset(Some(&error)) {
                            Ok(delay) if error.retryable() => tokio::time::sleep(delay).await,
                            _ => self.pipeline.fatal = Some(error),
                        }
                    } else if let Err(error) = self.retry(&mut connection_retries, error).await {
                        self.pipeline.fatal = Some(error);
                    }
                    continue;
                }
                self.pipeline.selected = true;
            }
            let result = async {
                while let Some(index) = self.pipeline.candidate() {
                    let command = self.pipeline.command(index);
                    let tag = self
                        .client
                        .as_mut()
                        .expect("selected connection")
                        .send(&command)
                        .await?;
                    self.pipeline.sent(index, tag);
                }
                if self
                    .pipeline
                    .entries
                    .iter()
                    .any(|entry| entry.result.is_some())
                {
                    return Ok(pipeline::Change::None);
                }
                let deadline = self
                    .pipeline
                    .entries
                    .iter()
                    .filter_map(|entry| entry.request.as_ref().map(|request| request.deadline))
                    .min()
                    .expect("active request");
                let pipeline = &mut self.pipeline;
                self.client
                    .as_mut()
                    .expect("selected connection")
                    .response(deadline, |response| pipeline.receive(response))
                    .await
            }
            .await;
            match result {
                Ok(pipeline::Change::None) => {}
                Ok(change) => {
                    let index = match change {
                        pipeline::Change::Reconcile(index) | pipeline::Change::Reject(index) => {
                            index
                        }
                        _ => unreachable!(),
                    };
                    self.client = None;
                    let _ = self.pipeline.reset(None);
                    let error = match change {
                        pipeline::Change::Reject(_) => mailbox::Error::Rejected {
                            operation: "message body",
                            status: "NO",
                        },
                        _ => {
                            let identity = self.pipeline.entries[index].identity.clone();
                            match self.exists(&identity, connect).await {
                                Ok(false) => mailbox::Error::Missing,
                                Ok(true) => mailbox::Error::Size,
                                Err(error) => {
                                    self.pipeline.fatal = Some(error);
                                    continue;
                                }
                            }
                        }
                    };
                    self.pipeline.entries[index].result = Some(Err(error));
                }
                Err(error) => {
                    self.client = None;
                    match self.pipeline.reset(Some(&error)) {
                        Ok(delay) if error.retryable() => tokio::time::sleep(delay).await,
                        _ => self.pipeline.fatal = Some(error),
                    }
                }
            }
        }
    }

    async fn connection<C, F>(
        &mut self,
        connect: &mut C,
    ) -> Result<&mut mailbox::Client<T>, mailbox::Error>
    where
        C: FnMut() -> F,
        F: Future<Output = Result<mailbox::Client<T>, mailbox::Error>>,
    {
        if self.client.is_none() {
            self.client = Some(connect().await?);
        }
        Ok(self.client.as_mut().expect("connection established"))
    }

    async fn retry(
        &mut self,
        retries: &mut Retry,
        error: mailbox::Error,
    ) -> Result<(), mailbox::Error> {
        self.client = None;
        let Some(delay) = retries.delay(&error) else {
            return Err(error);
        };
        tokio::time::sleep(delay).await;
        Ok(())
    }

    pub(super) async fn discover_with<C, F>(&mut self, connect: &mut C) -> Discovery
    where
        C: FnMut() -> F,
        F: Future<Output = Result<mailbox::Client<T>, mailbox::Error>>,
    {
        let mut snapshots = Vec::new();
        let result = self.discovery(&mut snapshots, connect).await;
        Discovery {
            snapshots,
            error: result.err(),
        }
    }

    async fn discovery<C, F>(
        &mut self,
        snapshots: &mut Vec<mailbox::Snapshot>,
        connect: &mut C,
    ) -> Result<(), mailbox::Error>
    where
        C: FnMut() -> F,
        F: Future<Output = Result<mailbox::Client<T>, mailbox::Error>>,
    {
        let mut retries = Retry::default();
        let folders = loop {
            let result = async { self.connection(connect).await?.folders().await }.await;
            match result {
                Ok(folders) => break folders,
                Err(error) => self.retry(&mut retries, error).await?,
            }
        };
        let mut total = 0;
        for folder in folders {
            // EXAMINE and SEARCH are one item: successful selection cannot reset retries.
            let mut retries = Retry::default();
            let snapshot = loop {
                let result =
                    async { self.connection(connect).await?.snapshot(&folder).await }.await;
                match result {
                    Ok(snapshot) => break snapshot,
                    Err(error) => self.retry(&mut retries, error).await?,
                }
            };
            if total + snapshot.uids.len() > MAX_UIDS {
                return Err(mailbox::Error::Limit("more than 1000000 UIDs in the run"));
            }
            total += snapshot.uids.len();
            snapshots.push(snapshot);
        }
        Ok(())
    }

    #[cfg(test)]
    async fn fetch_with<C, F>(
        &mut self,
        identity: &message::Identity,
        connect: &mut C,
    ) -> Result<Vec<u8>, mailbox::Error>
    where
        C: FnMut() -> F,
        F: Future<Output = Result<mailbox::Client<T>, mailbox::Error>>,
    {
        let mut retries = Retry::default();
        loop {
            let result = async {
                let client = self.connection(connect).await?;
                client.open(identity, false).await?;
                client.fetch(identity).await
            }
            .await;
            match result {
                Ok(bytes) => return Ok(bytes),
                Err(mailbox::Error::MissingBody) => {
                    self.client = None;
                    return match self.exists(identity, connect).await? {
                        true => Err(mailbox::Error::Size),
                        false => Err(mailbox::Error::Missing),
                    };
                }
                Err(error) => self.retry(&mut retries, error).await?,
            }
        }
    }

    async fn exists<C, F>(
        &mut self,
        identity: &message::Identity,
        connect: &mut C,
    ) -> Result<bool, mailbox::Error>
    where
        C: FnMut() -> F,
        F: Future<Output = Result<mailbox::Client<T>, mailbox::Error>>,
    {
        let mut retries = Retry::default();
        loop {
            let result = async {
                let client = self.connection(connect).await?;
                client.open(identity, false).await?;
                Ok(client.flags(identity).await?.is_some())
            }
            .await;
            match result {
                Ok(exists) => return Ok(exists),
                Err(error) => self.retry(&mut retries, error).await?,
            }
        }
    }

    /// Close the remaining session after scanner work settles.
    pub async fn logout(&mut self) {
        if let Some(mut client) = self.client.take() {
            let _ = client.logout().await;
        }
    }
}

/// Only message-local failures permit advancing to another UID.
pub fn terminal_message(error: &mailbox::Error) -> bool {
    matches!(
        error,
        mailbox::Error::Missing
            | mailbox::Error::Oversize(_)
            | mailbox::Error::Size
            | mailbox::Error::Rejected {
                operation: "message body" | "message size",
                status: "NO"
            }
    )
}

#[cfg(test)]
mod tests {
    mod faults;
    mod pipeline_tests;
    use super::*;
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

    fn settings() -> config::Settings {
        config::Settings::try_from(config::Draft {
            host: "mail.example.com".into(),
            username: "user".into(),
            password: "password".into(),
            scan_dir: "scan".into(),
            quarantine_dir: "quarantine".into(),
            ..Default::default()
        })
        .unwrap()
    }

    pub(super) async fn peer(
        steps: Vec<(&str, &str)>,
    ) -> (
        mailbox::Client<tokio::io::DuplexStream>,
        tokio::task::JoinHandle<()>,
    ) {
        let steps: Vec<_> = steps
            .into_iter()
            .map(|(command, reply)| (command.to_owned(), reply.to_owned()))
            .collect();
        let (stream, peer) = tokio::io::duplex(4096);
        let task = tokio::spawn(async move {
            let mut peer = BufReader::new(peer);
            peer.write_all(b"* OK ready\r\n").await.unwrap();
            let mut commands = vec![(
                "LOGIN \"user\" \"password\"".to_owned(),
                "{tag} OK login\r\n".to_owned(),
            )];
            commands.extend(steps);
            for (expected, reply) in commands {
                let mut line = String::new();
                peer.read_line(&mut line).await.unwrap();
                let (tag, actual) = line.trim_end().split_once(' ').unwrap();
                assert_eq!(actual, expected);
                peer.write_all(reply.replace("{tag}", tag).as_bytes())
                    .await
                    .unwrap();
            }
        });
        (
            mailbox::Client::scripted(stream, message::Account::from_settings(&settings()), false)
                .await
                .unwrap(),
            task,
        )
    }

    const OPEN: (&str, &str) = (
        "EXAMINE \"INBOX\"",
        "* OK [UIDVALIDITY 7] stable\r\n{tag} OK open\r\n",
    );
    const LIST: (&str, &str) = (
        "LIST \"\" \"*\"",
        "* LIST () \"/\" \"INBOX\"\r\n{tag} OK list\r\n",
    );

    #[tokio::test]
    async fn search_disconnect_retries_same_folder_without_relisting() {
        let settings = settings();
        let (first, a) = peer(vec![LIST, OPEN, ("UID SEARCH ALL", "* SEARCH 1 2\r\n")]).await;
        let (second, b) = peer(vec![
            OPEN,
            ("UID SEARCH ALL", "* SEARCH 9\r\n{tag} OK search\r\n"),
        ])
        .await;
        let mut connections = std::collections::VecDeque::from([first, second]);
        let mut worker = Worker {
            settings: &settings,
            client: None,
            pipeline: pipeline::Pipeline::default(),
        };
        let result = worker
            .discover_with(&mut || std::future::ready(Ok(connections.pop_front().unwrap())))
            .await;
        assert!(result.error.is_none());
        assert_eq!(result.snapshots.len(), 1);
        assert_eq!(
            result.snapshots[0]
                .uids
                .iter()
                .map(|uid| uid.get())
                .collect::<Vec<_>>(),
            vec![9]
        );
        assert!(connections.is_empty());
        a.await.unwrap();
        b.await.unwrap();
    }

    #[tokio::test]
    async fn unacknowledged_body_is_redownloaded_before_returning() {
        let settings = settings();
        let size = (
            "UID FETCH 9 (UID RFC822.SIZE)",
            "* 1 FETCH (UID 9 RFC822.SIZE 4)\r\n{tag} OK size\r\n",
        );
        let body = "UID FETCH 9 (UID BODY.PEEK[]<0.4>)";
        let (first, a) = peer(vec![
            OPEN,
            size,
            (body, "* 1 FETCH (UID 9 BODY[]<0> {4}\r\nold!)\r\n"),
        ])
        .await;
        let (second, b) = peer(vec![
            OPEN,
            size,
            (
                body,
                "* 1 FETCH (UID 9 BODY[]<0> {4}\r\nnew!)\r\n{tag} OK body\r\n",
            ),
        ])
        .await;
        let mut connections = std::collections::VecDeque::from([first, second]);
        let mut worker = Worker {
            settings: &settings,
            client: None,
            pipeline: pipeline::Pipeline::default(),
        };
        let identity = message::Identity::new(
            message::Account::from_settings(&settings),
            message::Folder::new("INBOX".into(), "INBOX".into()).unwrap(),
            std::num::NonZeroU32::new(7).unwrap(),
            std::num::NonZeroU32::new(9).unwrap(),
        );
        let bytes = worker
            .fetch_with(&identity, &mut || {
                std::future::ready(Ok(connections.pop_front().unwrap()))
            })
            .await
            .unwrap();
        assert_eq!(bytes, b"new!");
        assert!(connections.is_empty());
        a.await.unwrap();
        b.await.unwrap();
    }

    #[test]
    fn login_network_failure_differs_from_bad_credentials_and_parser_errors() {
        assert!(
            mailbox::Error::Authentication(async_imap::error::Error::Io(
                std::io::ErrorKind::UnexpectedEof.into()
            ))
            .retryable()
        );
        assert!(
            !mailbox::Error::Authentication(async_imap::error::Error::No("credentials".into()))
                .retryable()
        );
        assert!(!mailbox::Error::Io(std::io::Error::other("malformed reply")).retryable());
    }

    #[test]
    fn retry_budget_is_finite_and_backoff_increases() {
        let mut retry = Retry::default();
        for seconds in [1, 2, 4] {
            assert_eq!(
                retry.delay(&mailbox::Error::Disconnected),
                Some(Duration::from_secs(seconds))
            );
        }
        assert_eq!(retry.delay(&mailbox::Error::Disconnected), None);
    }

    #[test]
    fn permanent_failure_does_not_consume_a_retry() {
        let mut retry = Retry::default();
        assert_eq!(retry.delay(&mailbox::Error::Stale), None);
        assert_eq!(retry.failures, 0);
        assert!(!terminal_message(&mailbox::Error::Disconnected));
        assert!(terminal_message(&mailbox::Error::Missing));
    }
}
