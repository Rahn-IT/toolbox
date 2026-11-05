//! Bounded mailbox work and explicit save-before-purge actions.

use std::{
    collections::VecDeque,
    fs::OpenOptions,
    io::Write,
    path::{Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use tokio::{
    sync::{mpsc, watch},
    task::JoinSet,
};

use crate::mailbox_scanner::{
    core::{config, detection, event, message},
    mailbox, quarantine, scanner,
};

const MAX_UIDS: usize = 1_000_000;
const MAX_DETECTIONS: u64 = 100_000;
static NEXT: AtomicU64 = AtomicU64::new(0);

/// A workflow failure. Post-mutation uncertainty is returned as a purge outcome.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("Mailbox: {0}")]
    Mailbox(#[from] mailbox::Error),
    #[error("Scanner: {0}")]
    Scanner(#[from] scanner::Error),
    #[error("Quarantine: {0}")]
    Quarantine(#[from] quarantine::Error),
    #[error("File operation failed at {path}: {source}")]
    Io {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("Background operation failed: {0}")]
    Task(#[from] tokio::task::JoinError),
    #[error("Operation cancelled")]
    Cancelled,
    #[error("Message identity does not match this account")]
    Account,
}

struct Job {
    identity: message::Identity,
    subject: String,
    sender: String,
    report: detection::Report,
    leftovers: Vec<PathBuf>,
}

struct Pending {
    identity: message::Identity,
    subject: String,
    sender: String,
    work: PathBuf,
    report: detection::Report,
}

/// Discover folders and scan a bounded snapshot; no upstream mutation is performed.
pub async fn run(
    settings: Arc<config::Settings>,
    events: mpsc::Sender<event::Event>,
    cancel: watch::Receiver<bool>,
) -> Result<(), Error> {
    let mut counts = event::Counts::default();
    let result = execute(&settings, &events, &mut counts, cancel).await;
    let finish = match &result {
        Ok(finish) => *finish,
        Err(Error::Cancelled) => event::Finish::Cancelled,
        Err(error) => {
            let _ = events
                .send(event::Event::Diagnostic {
                    context: "Scan stopped".into(),
                    detail: error.to_string(),
                })
                .await;
            if matches!(error, Error::Mailbox(mailbox::Error::Limit(_))) {
                event::Finish::Partial
            } else {
                event::Finish::Failed
            }
        }
    };
    let _ = events.send(event::Event::Finished { finish, counts }).await;
    result.map(|_| ())
}

async fn execute(
    settings: &config::Settings,
    events: &mpsc::Sender<event::Event>,
    counts: &mut event::Counts,
    mut cancel: watch::Receiver<bool>,
) -> Result<event::Finish, Error> {
    let engine = scanner::Engine::resolve(settings)?;
    let scan_root = prepare(settings.scan_dir())?;
    prepare(settings.quarantine_dir())?;
    if events.send(event::Event::Discovering).await.is_err() {
        return Err(Error::Cancelled);
    }
    let mut client = tokio::select! { _ = cancelled(&mut cancel) => return Err(Error::Cancelled), result = mailbox::Client::connect(settings) => result? };
    let folders = tokio::select! { _ = cancelled(&mut cancel) => return Err(Error::Cancelled), result = client.folders() => result? };
    let mut snapshots = Vec::new();
    let mut total = 0;
    let mut partial = false;
    for folder in folders {
        if *cancel.borrow() {
            return Err(Error::Cancelled);
        }
        let _ = events
            .send(event::Event::Progress {
                counts: *counts,
                folder: Some(format!("Discovering {}", folder.display())),
            })
            .await;
        let result = tokio::select! { _ = cancelled(&mut cancel) => return Err(Error::Cancelled), result = client.snapshot(&folder) => result };
        match result {
            Ok(snapshot) => {
                if total + snapshot.uids.len() > MAX_UIDS {
                    partial = true;
                    let _ = events
                        .send(event::Event::Diagnostic {
                            context: "Discovery limit".into(),
                            detail: "The run exceeds 1,000,000 messages. Scan is partial.".into(),
                        })
                        .await;
                    break;
                }
                total += snapshot.uids.len();
                snapshots.push(snapshot);
            }
            Err(error) => {
                partial = true;
                let _ = events
                    .send(event::Event::Diagnostic {
                        context: folder.display().into(),
                        detail: error.to_string(),
                    })
                    .await;
                client = tokio::select! { _ = cancelled(&mut cancel) => return Err(Error::Cancelled), result = mailbox::Client::connect(settings) => result? };
            }
        }
    }
    counts.total = total as u64;
    let session = unique_directory(&scan_root, "mailbox-scan")?;
    let account = message::Account::from_settings(settings);
    let (stop, stopped) = watch::channel(false);
    let mut jobs = JoinSet::new();
    let parallel = settings.parallel() as usize;
    let capacity = parallel * 2;
    let mut queue = VecDeque::with_capacity(capacity);
    let mut aborted = false;
    let mut limit = false;
    'folders: for snapshot in snapshots {
        for uid in snapshot.uids {
            if *cancel.borrow() || events.is_closed() {
                aborted = true;
                break 'folders;
            }
            dispatch(&mut queue, &mut jobs, parallel, counts, |pending| {
                scan_job(pending, engine.clone(), stopped.clone())
            });
            while queue.len() >= capacity {
                tokio::select! {
                    _ = cancelled(&mut cancel) => { aborted = true; break 'folders; }
                    joined = jobs.join_next() => {
                        if let Some(joined) = joined { partial |= publish(joined, events, counts).await; }
                        dispatch(&mut queue, &mut jobs, parallel, counts, |pending| scan_job(pending, engine.clone(), stopped.clone()));
                        progress(events, counts);
                    }
                }
                if counts.detected >= MAX_DETECTIONS {
                    limit = true;
                    break 'folders;
                }
            }
            if counts.detected >= MAX_DETECTIONS {
                limit = true;
                break 'folders;
            }
            let identity = message::Identity::new(
                account.clone(),
                snapshot.folder.clone(),
                snapshot.uidvalidity,
                uid,
            );
            let fetched = {
                let fetch = async {
                    client.open(&identity, false).await?;
                    client.fetch(&identity).await
                };
                tokio::pin!(fetch);
                loop {
                    tokio::select! {
                        _ = cancelled(&mut cancel) => { aborted = true; break 'folders; }
                        result = &mut fetch => break result,
                        joined = jobs.join_next(), if !jobs.is_empty() => {
                            if let Some(joined) = joined { partial |= publish(joined, events, counts).await; }
                            dispatch(&mut queue, &mut jobs, parallel, counts, |pending| scan_job(pending, engine.clone(), stopped.clone()));
                            progress(events, counts);
                            if counts.detected >= MAX_DETECTIONS { limit = true; break 'folders; }
                        }
                    }
                }
            };
            match fetched {
                Ok(bytes) => {
                    let work = match unique_directory(&session, "job") {
                        Ok(work) => work,
                        Err(error) => {
                            partial = true;
                            counts.processed += 1;
                            counts.incomplete += 1;
                            let _ = events
                                .send(event::Event::Diagnostic {
                                    context: snapshot.folder.display().into(),
                                    detail: error.to_string(),
                                })
                                .await;
                            continue;
                        }
                    };
                    let pending = {
                        let write = stage(identity, bytes, work);
                        tokio::pin!(write);
                        loop {
                            tokio::select! {
                                pending = &mut write => break pending,
                                _ = cancelled(&mut cancel), if !aborted => {
                                    aborted = true;
                                    let _ = stop.send(true);
                                }
                                joined = jobs.join_next(), if !jobs.is_empty() => {
                                    if let Some(joined) = joined { partial |= publish(joined, events, counts).await; }
                                    if counts.detected >= MAX_DETECTIONS { limit = true; }
                                    if !aborted && !limit {
                                        dispatch(&mut queue, &mut jobs, parallel, counts, |pending| scan_job(pending, engine.clone(), stopped.clone()));
                                        progress(events, counts);
                                    }
                                }
                            }
                        }
                    };
                    queue.push_back(pending);
                    counts.queued = queue.len() as u8;
                    if aborted || limit {
                        break 'folders;
                    }
                    dispatch(&mut queue, &mut jobs, parallel, counts, |pending| {
                        scan_job(pending, engine.clone(), stopped.clone())
                    });
                }
                Err(error) => {
                    counts.processed += 1;
                    let skip_folder = matches!(
                        &error,
                        mailbox::Error::Stale
                            | mailbox::Error::ReadOnly
                            | mailbox::Error::Rejected {
                                operation: "folder selection",
                                ..
                            }
                    );
                    match error {
                        mailbox::Error::Missing => {
                            counts.vanished += 1;
                            let _ = events.send(event::Event::Vanished(identity)).await;
                        }
                        _ => {
                            partial = true;
                            counts.incomplete += 1;
                            let _ = events
                                .send(event::Event::Diagnostic {
                                    context: snapshot.folder.display().into(),
                                    detail: error.to_string(),
                                })
                                .await;
                        }
                    }
                    match tokio::select! { _ = cancelled(&mut cancel) => { aborted = true; break 'folders; }, result = mailbox::Client::connect(settings) => result }
                    {
                        Ok(connection) => client = connection,
                        Err(error) => {
                            partial = true;
                            let _ = events
                                .send(event::Event::Diagnostic {
                                    context: "Reconnect".into(),
                                    detail: error.to_string(),
                                })
                                .await;
                            break 'folders;
                        }
                    }
                    if skip_folder {
                        continue 'folders;
                    }
                }
            }
            let _ = events
                .send(event::Event::Progress {
                    counts: *counts,
                    folder: Some(snapshot.folder.display().into()),
                })
                .await;
        }
    }
    if aborted {
        let _ = stop.send(true);
    }
    while !jobs.is_empty() || (!queue.is_empty() && !aborted && !limit) {
        if !aborted && !limit {
            dispatch(&mut queue, &mut jobs, parallel, counts, |pending| {
                scan_job(pending, engine.clone(), stopped.clone())
            });
            progress(events, counts);
        }
        tokio::select! {
            _ = cancelled(&mut cancel), if !aborted => { aborted = true; let _ = stop.send(true); }
            joined = jobs.join_next() => {
                if let Some(joined) = joined { partial |= publish(joined, events, counts).await; }
                if counts.detected >= MAX_DETECTIONS { limit = true; }
            }
        }
    }
    // Buffered mail is not scanned after cancellation or the detection cap.
    // Its files still belong to this session and must be removed before Finished.
    while let Some(pending) = queue.pop_front() {
        for path in cleanup(&pending.work).await {
            partial = true;
            let _ = events.send(event::Event::Leftover(path)).await;
        }
    }
    counts.queued = 0;
    counts.active = 0;
    counts.cancelled = counts.total.saturating_sub(counts.processed);
    if let Err(error) = std::fs::remove_dir(&session) {
        partial = true;
        let _ = events.send(event::Event::Leftover(session)).await;
        let _ = events
            .send(event::Event::Diagnostic {
                context: "Temporary cleanup".into(),
                detail: error.to_string(),
            })
            .await;
    }
    if !aborted {
        let _ = client.logout().await;
    }
    Ok(if aborted {
        event::Finish::Cancelled
    } else if partial || limit || counts.incomplete > 0 || counts.cancelled > 0 {
        event::Finish::Partial
    } else {
        event::Finish::Completed
    })
}

fn dispatch<F, Fut>(
    queue: &mut VecDeque<Pending>,
    jobs: &mut JoinSet<Job>,
    parallel: usize,
    counts: &mut event::Counts,
    mut scan: F,
) where
    F: FnMut(Pending) -> Fut,
    Fut: std::future::Future<Output = Job> + Send + 'static,
{
    if counts.detected < MAX_DETECTIONS {
        while jobs.len() < parallel {
            let Some(pending) = queue.pop_front() else {
                break;
            };
            jobs.spawn(scan(pending));
        }
    }
    counts.active = jobs.len() as u8;
    counts.queued = queue.len() as u8;
}

fn progress(events: &mpsc::Sender<event::Event>, counts: &event::Counts) {
    // This snapshot may be coalesced when the GUI is busy; findings and Finished
    // still use awaited sends and cannot be discarded by a full progress queue.
    let _ = events.try_send(event::Event::Progress {
        counts: *counts,
        folder: None,
    });
}

async fn stage(identity: message::Identity, bytes: Vec<u8>, work: PathBuf) -> Pending {
    let (subject, sender) = metadata(&bytes);
    let path = work.join("message.eml");
    let mut report = detection::Report::new();
    match tokio::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&path)
        .await
    {
        Ok(mut file) => {
            use tokio::io::AsyncWriteExt;
            let written = async {
                file.write_all(&bytes).await?;
                file.flush().await
            }
            .await;
            match written {
                Ok(()) => {
                    drop(file);
                }
                Err(error) => report.warn(detection::Issue::Input(error.to_string())),
            }
        }
        Err(error) => report.warn(detection::Issue::Input(error.to_string())),
    }
    drop(bytes);
    Pending {
        identity,
        subject,
        sender,
        work,
        report,
    }
}

async fn scan_job(pending: Pending, engine: scanner::Engine, cancel: watch::Receiver<bool>) -> Job {
    let Pending {
        identity,
        subject,
        sender,
        work,
        mut report,
    } = pending;
    if report.complete() {
        match engine.scan(&work.join("message.eml"), &work, cancel).await {
            Ok(found) => report.merge(found),
            Err(error) => report.warn(detection::Issue::Scanner(error.to_string())),
        }
    }
    let leftovers = cleanup(&work).await;
    if !leftovers.is_empty() {
        report.warn(detection::Issue::Input(
            "Some temporary files could not be removed".into(),
        ));
    }
    Job {
        identity,
        subject,
        sender,
        report,
        leftovers,
    }
}

async fn cleanup(work: &Path) -> Vec<PathBuf> {
    let mut leftovers = Vec::new();
    match tokio::fs::read_dir(&work).await {
        Ok(mut entries) => {
            while let Ok(Some(entry)) = entries.next_entry().await {
                if tokio::fs::remove_file(entry.path()).await.is_err() {
                    leftovers.push(entry.path());
                }
            }
        }
        Err(_) => leftovers.push(work.to_path_buf()),
    }
    if tokio::fs::remove_dir(&work).await.is_err() && leftovers.is_empty() {
        leftovers.push(work.to_path_buf());
    }
    leftovers
}

async fn publish(
    joined: Result<Job, tokio::task::JoinError>,
    events: &mpsc::Sender<event::Event>,
    counts: &mut event::Counts,
) -> bool {
    counts.processed += 1;
    counts.active = counts.active.saturating_sub(1);
    match joined {
        Ok(job) => {
            let incomplete = !job.report.complete();
            counts.detected += u64::from(job.report.detected());
            counts.incomplete += u64::from(incomplete);
            for path in job.leftovers {
                let _ = events.send(event::Event::Leftover(path)).await;
            }
            let _ = events
                .send(event::Event::MessageFinished {
                    identity: job.identity,
                    subject: job.subject,
                    sender: job.sender,
                    report: job.report,
                })
                .await;
            let _ = events
                .send(event::Event::Progress {
                    counts: *counts,
                    folder: None,
                })
                .await;
            incomplete
        }
        Err(error) => {
            counts.incomplete += 1;
            let _ = events
                .send(event::Event::Diagnostic {
                    context: "Scan worker".into(),
                    detail: error.to_string(),
                })
                .await;
            true
        }
    }
}

fn metadata(bytes: &[u8]) -> (String, String) {
    match mail_parser::MessageParser::new().parse_headers(bytes) {
        Some(mail) => {
            let subject = mail
                .subject()
                .unwrap_or("(no subject)")
                .chars()
                .take(512)
                .collect();
            let sender = mail
                .from()
                .and_then(|from| from.first())
                .map(|address| match (address.name(), address.address()) {
                    (Some(name), Some(address)) => format!("{name} <{address}>"),
                    (_, Some(address)) => address.to_string(),
                    (Some(name), _) => name.to_string(),
                    _ => "(unknown sender)".into(),
                })
                .unwrap_or_else(|| "(unknown sender)".into());
            (subject, sender.chars().take(512).collect())
        }
        None => ("(unreadable subject)".into(), "(unknown sender)".into()),
    }
}

/// Download and verify one message without any upstream flag changes.
pub async fn download(
    settings: Arc<config::Settings>,
    identity: message::Identity,
    mut cancel: watch::Receiver<bool>,
) -> Result<detection::Saved, Error> {
    check_account(&settings, &identity)?;
    let bytes = tokio::select! {
        _ = cancelled(&mut cancel) => return Err(Error::Cancelled),
        result = async {
            let mut client = mailbox::Client::connect(&settings).await?;
            client.open(&identity, false).await?;
            let bytes = client.fetch(&identity).await?;
            let _ = client.logout().await;
            Ok::<_, mailbox::Error>(bytes)
        } => result?,
    };
    if *cancel.borrow() {
        return Err(Error::Cancelled);
    }
    let directory = settings.quarantine_dir().to_path_buf();
    let verified =
        tokio::task::spawn_blocking(move || quarantine::Store::open(&directory)?.save(bytes))
            .await??;
    Ok(verified.saved().clone())
}

/// Preserve a fresh copy before attempting only the explicitly selected UID's removal.
pub async fn purge(
    settings: Arc<config::Settings>,
    identity: message::Identity,
    mut cancel: watch::Receiver<bool>,
) -> Result<detection::Purge, Error> {
    check_account(&settings, &identity)?;
    let (mut client, flags, bytes) = tokio::select! {
        _ = cancelled(&mut cancel) => return Err(Error::Cancelled),
        result = async {
            let mut client = mailbox::Client::connect(&settings).await?;
            if !client.supports_purge() { return Err(mailbox::Error::UnsupportedPurge); }
            client.open(&identity, true).await?;
            let flags = client.flags(&identity).await?.ok_or(mailbox::Error::Missing)?;
            let bytes = client.fetch(&identity).await?;
            Ok::<_, mailbox::Error>((client, flags, bytes))
        } => result?,
    };
    let directory = settings.quarantine_dir().to_path_buf();
    let verified =
        tokio::task::spawn_blocking(move || quarantine::Store::open(&directory)?.save(bytes))
            .await??;
    let saved = verified.saved().clone();
    if *cancel.borrow() {
        return Ok(detection::Purge::Saved {
            saved,
            detail: "Cancelled before marking the message".into(),
        });
    }
    let mutation = commit(&mut client, &identity, verified, &cancel).await;
    match mutation {
        Ok(()) => Ok(detection::Purge::Purged(saved)),
        Err(Error::Mailbox(error)) => {
            let reason = compact(&error.to_string());
            let state = tokio::time::timeout(Duration::from_secs(120), async {
                let mut client = mailbox::Client::connect(&settings).await?;
                client.open(&identity, false).await?;
                client.flags(&identity).await
            })
            .await;
            Ok(match state {
                Ok(Ok(Some(current))) if current.deleted => detection::Purge::MarkedDeleted {
                    saved,
                    preexisting_deleted: flags.deleted,
                },
                Ok(Ok(Some(_))) => detection::Purge::Saved {
                    saved,
                    detail: format!("{reason}; message still present without Deleted flag"),
                },
                Ok(Ok(None)) => detection::Purge::OutcomeUnknown {
                    saved,
                    detail: format!(
                        "{reason}; message is now absent; cause of deletion is unconfirmed"
                    ),
                },
                Ok(Err(error)) => detection::Purge::OutcomeUnknown {
                    saved,
                    detail: format!(
                        "{reason}; reconciliation failed: {}",
                        compact(&error.to_string())
                    ),
                },
                Err(_) => detection::Purge::OutcomeUnknown {
                    saved,
                    detail: format!("{reason}; reconciliation timed out"),
                },
            })
        }
        Err(error) => Ok(detection::Purge::Saved {
            saved,
            detail: compact(&error.to_string()),
        }),
    }
}

fn check_account(settings: &config::Settings, identity: &message::Identity) -> Result<(), Error> {
    if identity.account() == &message::Account::from_settings(settings) {
        Ok(())
    } else {
        Err(Error::Account)
    }
}

fn prepare(directory: &Path) -> Result<PathBuf, Error> {
    std::fs::create_dir_all(directory).map_err(|source| Error::Io {
        path: directory.into(),
        source,
    })?;
    let directory = std::fs::canonicalize(directory).map_err(|source| Error::Io {
        path: directory.into(),
        source,
    })?;
    let probe = unique_directory(&directory, "mailbox-write-check")?;
    let path = probe.join("probe");
    let result = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&path)
        .and_then(|mut file| file.write_all(b"write check"));
    result.map_err(|source| Error::Io { path, source })?;
    let path = probe.join("probe");
    std::fs::remove_file(&path).map_err(|source| Error::Io { path, source })?;
    std::fs::remove_dir(&probe).map_err(|source| Error::Io {
        path: probe,
        source,
    })?;
    Ok(directory)
}

fn unique_directory(parent: &Path, prefix: &str) -> Result<PathBuf, Error> {
    let time = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    loop {
        let path = parent.join(format!(
            "{prefix}-{}-{time}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        match std::fs::create_dir(&path) {
            Ok(()) => return Ok(path),
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(source) => return Err(Error::Io { path, source }),
        }
    }
}

async fn cancelled(cancel: &mut watch::Receiver<bool>) {
    loop {
        if *cancel.borrow() {
            return;
        }
        if cancel.changed().await.is_err() {
            return;
        }
    }
}

fn compact(value: &str) -> String {
    value.chars().take(512).collect()
}

async fn commit<T>(
    client: &mut mailbox::Client<T>,
    identity: &message::Identity,
    verified: quarantine::Verified,
    cancel: &watch::Receiver<bool>,
) -> Result<(), Error>
where
    T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + std::fmt::Debug + Send,
{
    let verified =
        tokio::task::spawn_blocking(move || verified.recheck().map(|()| verified)).await??;
    if *cancel.borrow() || cancel.has_changed().is_err() {
        return Err(Error::Cancelled);
    }
    // Holding this freshly verified copy until mutation settles keeps preservation
    // distinct from an old UI Saved record. External antivirus can still remove it.
    client.mark_deleted(identity).await?;
    client.expunge(identity).await?;
    if client.flags(identity).await?.is_some() {
        return Err(mailbox::Error::Unexpected("UID still present after targeted expunge").into());
    }
    drop(verified);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

    fn pending(uid: u32, work: PathBuf) -> Pending {
        let settings = config::Settings::try_from(config::Draft {
            host: "imap.example.org".into(),
            username: "user".into(),
            password: "password".into(),
            scan_dir: std::env::temp_dir(),
            quarantine_dir: std::env::temp_dir(),
            ..Default::default()
        })
        .unwrap();
        Pending {
            identity: message::Identity::new(
                message::Account::from_settings(&settings),
                message::Folder::new("INBOX".into(), "INBOX".into()).unwrap(),
                std::num::NonZeroU32::new(7).unwrap(),
                std::num::NonZeroU32::new(uid).unwrap(),
            ),
            subject: String::new(),
            sender: String::new(),
            work,
            report: detection::Report::new(),
        }
    }

    #[tokio::test]
    async fn buffered_downloads_do_not_consume_scan_slots_and_refill_them() {
        let parallel = 2;
        let gate = Arc::new(tokio::sync::Semaphore::new(0));
        let (started, mut starts) = mpsc::channel(8);
        let mut queue: VecDeque<_> = (1..=4).map(|uid| pending(uid, PathBuf::new())).collect();
        let mut jobs = JoinSet::new();
        let mut counts = event::Counts::default();
        let scan = |pending: Pending| {
            let gate = Arc::clone(&gate);
            let started = started.clone();
            async move {
                started.send(pending.identity.uid()).await.unwrap();
                gate.acquire().await.unwrap().forget();
                Job {
                    identity: pending.identity,
                    subject: pending.subject,
                    sender: pending.sender,
                    report: pending.report,
                    leftovers: Vec::new(),
                }
            }
        };
        dispatch(&mut queue, &mut jobs, parallel, &mut counts, scan);
        assert_eq!(starts.recv().await, Some(1));
        assert_eq!(starts.recv().await, Some(2));
        // Downloading can fill a separate 2*N queue while N scans remain active.
        queue.extend([pending(5, PathBuf::new()), pending(6, PathBuf::new())]);
        dispatch(&mut queue, &mut jobs, parallel, &mut counts, scan);
        assert_eq!((counts.active, counts.queued), (2, 4));
        assert!(starts.try_recv().is_err());
        gate.add_permits(1);
        jobs.join_next().await.unwrap().unwrap();
        dispatch(&mut queue, &mut jobs, parallel, &mut counts, scan);
        assert_eq!(starts.recv().await, Some(3));
        assert_eq!((counts.active, counts.queued), (2, 3));
        queue.clear();
        gate.add_permits(2);
        while let Some(job) = jobs.join_next().await {
            job.unwrap();
        }
    }

    #[tokio::test]
    async fn queued_mail_is_flushed_to_disk_and_removed_without_scanning() {
        let directory = unique_directory(&std::env::temp_dir(), "mailbox-buffer-test").unwrap();
        let mut queue = VecDeque::new();
        for uid in 1..=3 {
            let work = unique_directory(&directory, "job").unwrap();
            let identity = pending(uid, work.clone()).identity;
            let raw =
                b"From: test@example.invalid\r\nSubject: buffered mail\r\n\r\nharmless".to_vec();
            queue.push_back(stage(identity, raw.clone(), work.clone()).await);
            assert_eq!(
                tokio::fs::read(work.join("message.eml")).await.unwrap(),
                raw
            );
        }
        while let Some(pending) = queue.pop_front() {
            assert!(cleanup(&pending.work).await.is_empty());
            assert!(!pending.work.exists());
        }
        std::fs::remove_dir(directory).unwrap();
    }

    async fn connection(
        path: PathBuf,
        mutate: bool,
    ) -> (
        mailbox::Client<tokio::io::DuplexStream>,
        message::Identity,
        tokio::task::JoinHandle<()>,
    ) {
        let settings = config::Settings::try_from(config::Draft {
            host: "imap.example.org".into(),
            username: "user".into(),
            password: "password".into(),
            scan_dir: std::env::temp_dir(),
            quarantine_dir: std::env::temp_dir(),
            ..config::Draft::default()
        })
        .unwrap();
        let account = message::Account::from_settings(&settings);
        let identity = message::Identity::new(
            account.clone(),
            message::Folder::new("INBOX".into(), "INBOX".into()).unwrap(),
            std::num::NonZeroU32::new(7).unwrap(),
            std::num::NonZeroU32::new(9).unwrap(),
        );
        let (stream, peer) = tokio::io::duplex(8192);
        let server = tokio::spawn(async move {
            let mut peer = BufReader::new(peer);
            peer.get_mut()
                .write_all(b"* OK test server\r\n")
                .await
                .unwrap();
            let mut line = String::new();
            peer.read_line(&mut line).await.unwrap();
            let tag = line.split_once(' ').unwrap().0;
            peer.get_mut()
                .write_all(format!("{tag} OK logged in\r\n").as_bytes())
                .await
                .unwrap();
            line.clear();
            peer.read_line(&mut line).await.unwrap();
            let (tag, command) = line.trim_end().split_once(' ').unwrap();
            assert_eq!(command, "SELECT \"INBOX\"");
            peer.get_mut()
                .write_all(
                    format!("* OK [UIDVALIDITY 7] stable\r\n{tag} OK [READ-WRITE] selected\r\n")
                        .as_bytes(),
                )
                .await
                .unwrap();
            if mutate {
                for expected in [
                    "UID STORE 9 +FLAGS.SILENT (\\Deleted)",
                    "UID EXPUNGE 9",
                    "UID FETCH 9 (UID FLAGS)",
                ] {
                    line.clear();
                    peer.read_line(&mut line).await.unwrap();
                    let (tag, command) = line.trim_end().split_once(' ').unwrap();
                    assert_eq!(command, expected);
                    assert_eq!(std::fs::read(&path).unwrap(), b"preserved message");
                    peer.get_mut()
                        .write_all(format!("{tag} OK completed\r\n").as_bytes())
                        .await
                        .unwrap();
                }
            } else {
                line.clear();
                assert_eq!(
                    peer.read_line(&mut line).await.unwrap(),
                    0,
                    "A failed preservation check must not send STORE"
                );
            }
        });
        let mut client = mailbox::Client::scripted(stream, account, true)
            .await
            .unwrap();
        client.open(&identity, true).await.unwrap();
        (client, identity, server)
    }

    #[tokio::test]
    async fn purge_preserves_a_copy_before_targeted_mutation() {
        let directory = unique_directory(&std::env::temp_dir(), "mailbox-workflow-test").unwrap();
        let verified = quarantine::Store::open(&directory)
            .unwrap()
            .save(b"preserved message".to_vec())
            .unwrap();
        let saved = verified.saved().clone();
        let (mut client, identity, server) = connection(saved.path().into(), true).await;
        let (_stop, cancel) = watch::channel(false);
        commit(&mut client, &identity, verified, &cancel)
            .await
            .unwrap();
        server.await.unwrap();
        assert!(saved.path().is_file());
        std::fs::remove_file(saved.path()).unwrap();
        std::fs::remove_dir(directory).unwrap();
    }

    #[tokio::test]
    async fn a_disappearing_quarantine_copy_prevents_any_store() {
        let directory = unique_directory(&std::env::temp_dir(), "mailbox-workflow-test").unwrap();
        let verified = quarantine::Store::open(&directory)
            .unwrap()
            .save(b"preserved message".to_vec())
            .unwrap();
        let path = verified.saved().path().to_path_buf();
        let (mut client, identity, server) = connection(path.clone(), false).await;
        std::fs::remove_file(path).unwrap();
        let (_stop, cancel) = watch::channel(false);
        assert!(matches!(
            commit(&mut client, &identity, verified, &cancel).await,
            Err(Error::Quarantine(_))
        ));
        drop(client);
        server.await.unwrap();
        std::fs::remove_dir(directory).unwrap();
    }

    #[tokio::test]
    async fn cancellation_after_saving_does_not_start_upstream_deletion() {
        let directory = unique_directory(&std::env::temp_dir(), "mailbox-workflow-test").unwrap();
        let verified = quarantine::Store::open(&directory)
            .unwrap()
            .save(b"preserved message".to_vec())
            .unwrap();
        let path = verified.saved().path().to_path_buf();
        let (mut client, identity, server) = connection(path.clone(), false).await;
        let (_stop, cancel) = watch::channel(true);
        assert!(matches!(
            commit(&mut client, &identity, verified, &cancel).await,
            Err(Error::Cancelled)
        ));
        drop(client);
        server.await.unwrap();
        std::fs::remove_file(path).unwrap();
        std::fs::remove_dir(directory).unwrap();
    }
}
