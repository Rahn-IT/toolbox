//! Directory batches retain admission slots until their final UI results are delivered.

use std::collections::{BTreeMap, HashSet, VecDeque};
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::{mpsc, watch};
use tokio::task::JoinHandle;

use crate::mailbox_scanner::core::{config, detection, event, message};
use crate::mailbox_scanner::{batch, mailbox, scanner};

use super::{Error, MAX_DETECTIONS, MAX_UIDS, cancelled, prepare, unique_directory};

struct Active {
    batch: Arc<batch::Batch>,
    updates: Arc<scanner::batch::Updates>,
    task: Option<JoinHandle<(scanner::batch::Outcome, Vec<std::path::PathBuf>)>>,
    latest: BTreeMap<usize, detection::Report>,
    detected: HashSet<usize>,
    pending: BTreeMap<usize, event::Event>,
    extra: VecDeque<event::Event>,
    settled: bool,
}

impl Active {
    fn collect(&mut self, counts: &mut event::Counts) {
        if self.settled {
            return;
        }
        for (index, revision, report) in self.updates.take() {
            let Some(message) = self.batch.messages().get(index) else {
                continue;
            };
            if report.detected() && self.detected.insert(index) {
                counts.detected += 1;
            }
            self.latest.insert(index, report.clone());
            self.pending.insert(
                index,
                event::Event::MessageUpdated {
                    identity: message.identity().clone(),
                    subject: message.subject().into(),
                    sender: message.sender().into(),
                    report,
                    revision,
                    terminal: false,
                },
            );
        }
    }
}
struct Run<'a> {
    events: &'a mpsc::Sender<event::Event>,
    counts: &'a mut event::Counts,
    engine: scanner::Engine,
    timeout: Duration,
    stop: watch::Sender<bool>,
    stopped: watch::Receiver<bool>,
    active: Vec<Active>,
    partial: bool,
    halted: bool,
    aborted: bool,
}

impl Run<'_> {
    fn stop(&mut self) {
        self.aborted = true;
        let _ = self.stop.send(true);
    }

    fn diagnostic(&mut self, context: &str, detail: String) {
        self.partial = true;
        let _ = self.events.try_send(event::Event::Diagnostic {
            context: context.into(),
            detail,
        });
    }

    fn launch(&mut self, batch: batch::Batch) {
        let batch = Arc::new(batch);
        let updates = Arc::new(scanner::batch::Updates::default());
        let worker_batch = Arc::clone(&batch);
        let worker_updates = Arc::clone(&updates);
        let engine = self.engine.clone();
        let cancel = self.stopped.clone();
        let timeout = self.timeout;
        let task = tokio::spawn(async move {
            let outcome =
                scanner::batch::scan(&engine, &worker_batch, timeout, cancel, &worker_updates)
                    .await;
            let leftovers = if outcome.cleanup_safe {
                worker_batch.cleanup().await
            } else {
                vec![worker_batch.directory().to_path_buf()]
            };
            (outcome, leftovers)
        });
        self.active.push(Active {
            batch,
            updates,
            task: Some(task),
            latest: BTreeMap::new(),
            detected: HashSet::new(),
            pending: BTreeMap::new(),
            extra: VecDeque::new(),
            settled: false,
        });
    }

    fn retain(&mut self, batch: batch::Batch, reason: String) {
        self.halted = true;
        self.partial = true;
        let reports = batch
            .messages()
            .iter()
            .map(|message| {
                let mut report = message.report().clone();
                report.warn(detection::Issue::Input(reason.clone()));
                report
            })
            .collect();
        let leftovers = vec![batch.directory().to_path_buf()];
        let task = tokio::spawn(async move {
            (
                scanner::batch::Outcome {
                    reports,
                    cleanup_safe: false,
                },
                leftovers,
            )
        });
        self.active.push(Active {
            batch: Arc::new(batch),
            updates: Arc::new(scanner::batch::Updates::default()),
            task: Some(task),
            latest: BTreeMap::new(),
            detected: HashSet::new(),
            pending: BTreeMap::new(),
            extra: VecDeque::new(),
            settled: false,
        });
    }

    async fn flush(
        &mut self,
        builder: batch::Builder,
        parallel: usize,
        cancel: &mut watch::Receiver<bool>,
    ) {
        let mut tick = tokio::time::interval(Duration::from_millis(100));
        if *cancel.borrow() || cancel.has_changed().is_err() || self.events.is_closed() {
            self.stop();
        }
        while self.active.len() >= parallel && !self.aborted && !self.halted {
            tokio::select! {
                _ = cancelled(cancel) => self.stop(),
                _ = tick.tick() => self.service().await,
            }
        }
        if *cancel.borrow() || cancel.has_changed().is_err() || self.events.is_closed() {
            self.stop();
        }
        match builder.seal() {
            Ok(Some(batch)) if self.aborted || self.halted => {
                for path in batch.cleanup().await {
                    self.partial = true;
                    let _ = self.events.send(event::Event::Leftover(path)).await;
                }
            }
            Ok(Some(batch)) => self.launch(batch),
            Ok(None) => {}
            Err(rejected) => {
                let reason = rejected.error().to_string();
                self.retain(rejected.into_batch(), reason);
            }
        }
    }
    async fn service(&mut self) {
        if self.events.is_closed() {
            self.stop();
        }
        for active in &mut self.active {
            active.collect(self.counts);
            if active.task.as_ref().is_some_and(JoinHandle::is_finished) {
                // Completion closes the publication race before a panic fallback is built.
                active.collect(self.counts);
                let task = active
                    .task
                    .take()
                    .expect("completed task remains owned until joined");
                let (outcome, leftovers) = match task.await {
                    Ok(result) => result,
                    Err(error) => (
                        scanner::batch::Outcome {
                            reports: active
                                .batch
                                .messages()
                                .iter()
                                .enumerate()
                                .map(|(index, message)| {
                                    let mut report = active
                                        .latest
                                        .get(&index)
                                        .cloned()
                                        .unwrap_or_else(|| message.report().clone());
                                    report.warn(detection::Issue::Scanner(format!(
                                        "Batch worker failed: {error}"
                                    )));
                                    report
                                })
                                .collect(),
                            cleanup_safe: false,
                        },
                        vec![active.batch.directory().to_path_buf()],
                    ),
                };
                // A nonempty directory may contain scanner-created files we do not own.
                // Only retained inputs or an unsettled scanner must block admission.
                let cleanup_failed = !outcome.cleanup_safe
                    || leftovers
                        .iter()
                        .any(|path| path != active.batch.directory());
                self.halted |= cleanup_failed;
                if !leftovers.is_empty() {
                    self.partial = true;
                    for path in leftovers {
                        active.extra.push_back(event::Event::Leftover(path));
                    }
                }
                for (index, message) in active.batch.messages().iter().enumerate() {
                    let mut report = outcome.reports.get(index).cloned().unwrap_or_else(|| {
                        let mut report = active
                            .latest
                            .get(&index)
                            .cloned()
                            .unwrap_or_else(|| message.report().clone());
                        report.warn(detection::Issue::Scanner(
                            "Batch worker omitted a message result".into(),
                        ));
                        report
                    });
                    if cleanup_failed {
                        report.warn(detection::Issue::Input(
                            "Batch files remain or scanner termination is uncertain".into(),
                        ));
                    }
                    if report.detected() && active.detected.insert(index) {
                        self.counts.detected += 1;
                    }
                    self.counts.processed += 1;
                    if !report.complete() {
                        self.counts.incomplete += 1;
                        self.partial = true;
                    }
                    active.pending.insert(
                        index,
                        event::Event::MessageUpdated {
                            identity: message.identity().clone(),
                            subject: message.subject().into(),
                            sender: message.sender().into(),
                            report,
                            revision: u64::MAX,
                            terminal: true,
                        },
                    );
                }
                active.settled = true;
            }
            while let Some((index, event)) = active.pending.pop_first() {
                match self.events.try_send(event) {
                    Ok(()) => {}
                    Err(mpsc::error::TrySendError::Full(event)) => {
                        active.pending.insert(index, event);
                        break;
                    }
                    Err(mpsc::error::TrySendError::Closed(_)) => {
                        active.pending.clear();
                        break;
                    }
                }
            }
            while let Some(event) = active.extra.pop_front() {
                match self.events.try_send(event) {
                    Ok(()) => {}
                    Err(mpsc::error::TrySendError::Full(event)) => {
                        active.extra.push_front(event);
                        break;
                    }
                    Err(mpsc::error::TrySendError::Closed(_)) => {
                        active.extra.clear();
                        break;
                    }
                }
            }
        }
        self.active.retain(|active| {
            !active.settled || !active.pending.is_empty() || !active.extra.is_empty()
        });
        if self.counts.detected >= MAX_DETECTIONS {
            self.halted = true;
            self.partial = true;
            let _ = self.stop.send(true);
        }
        self.counts.batches_active = self.active.len() as u64;
        self.counts.active = self
            .active
            .iter()
            .filter(|active| !active.settled)
            .map(|active| active.batch.messages().len() as u64)
            .sum();
        super::progress(self.events, self.counts);
    }
}

pub(super) async fn execute(
    settings: &config::Settings,
    events: &mpsc::Sender<event::Event>,
    counts: &mut event::Counts,
    mut cancel: watch::Receiver<bool>,
) -> Result<event::Finish, Error> {
    let engine = scanner::Engine::resolve(settings)?;
    let root = prepare(settings.scan_dir())?;
    prepare(settings.quarantine_dir())?;
    if events.send(event::Event::Discovering).await.is_err() {
        return Err(Error::Cancelled);
    }
    let mut client = tokio::select! {
        _ = cancelled(&mut cancel) => return Err(Error::Cancelled),
        result = mailbox::Client::connect(settings) => result?,
    };
    let folders = tokio::select! {
        _ = cancelled(&mut cancel) => return Err(Error::Cancelled),
        result = client.folders() => result?,
    };
    let mut snapshots = Vec::new();
    let mut total = 0;
    let mut partial = false;
    for folder in folders {
        let result = tokio::select! {
            _ = cancelled(&mut cancel) => return Err(Error::Cancelled),
            result = client.snapshot(&folder) => result,
        };
        match result {
            Ok(snapshot) => {
                if total + snapshot.uids.len() > MAX_UIDS {
                    partial = true;
                    break;
                }
                total += snapshot.uids.len();
                snapshots.push(snapshot);
            }
            Err(error) => {
                partial = true;
                let _ = events.try_send(event::Event::Diagnostic {
                    context: folder.display().into(),
                    detail: error.to_string(),
                });
                client = tokio::select! {
                    _ = cancelled(&mut cancel) => return Err(Error::Cancelled),
                    result = mailbox::Client::connect(settings) => result?,
                };
            }
        }
    }
    counts.total = total as u64;
    let session = unique_directory(&root, "mailbox-scan")?;
    let account = message::Account::from_settings(settings);
    let (stop, stopped) = watch::channel(false);
    let mut run = Run {
        events,
        counts,
        engine,
        timeout: settings.batch_timeout(),
        stop,
        stopped,
        active: Vec::new(),
        partial,
        halted: false,
        aborted: false,
    };
    let mut filling = match batch::Builder::create(&session, settings.batch_bytes()) {
        Ok(builder) => Some(builder),
        Err(error) => {
            if tokio::fs::remove_dir(&session).await.is_err() {
                let _ = events.send(event::Event::Leftover(session)).await;
            }
            return Err(error.into());
        }
    };
    let parallel = settings.parallel() as usize;
    let mut tick = tokio::time::interval(Duration::from_millis(100));
    'folders: for snapshot in snapshots {
        for uid in snapshot.uids {
            run.service().await;
            if *cancel.borrow() || cancel.has_changed().is_err() || events.is_closed() {
                run.stop();
            }
            if run.aborted || run.halted {
                break 'folders;
            }
            if filling.as_ref().is_some_and(batch::Builder::full) {
                run.counts.batches_queued = 1;
                while run.active.len() >= parallel && !run.aborted && !run.halted {
                    tokio::select! {
                        _ = cancelled(&mut cancel) => run.stop(),
                        _ = tick.tick() => run.service().await,
                    }
                }
                if run.aborted || run.halted {
                    break 'folders;
                }
                match filling
                    .take()
                    .expect("producer owns its current batch")
                    .seal()
                {
                    Ok(Some(batch)) => run.launch(batch),
                    Ok(None) => {}
                    Err(rejected) => {
                        let reason = rejected.error().to_string();
                        run.retain(rejected.into_batch(), reason);
                        break 'folders;
                    }
                }
                run.counts.batches_queued = 0;
                filling = match batch::Builder::create(&session, settings.batch_bytes()) {
                    Ok(builder) => Some(builder),
                    Err(error) => {
                        run.diagnostic("Batch preparation", error.to_string());
                        break 'folders;
                    }
                };
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
                        _ = cancelled(&mut cancel) => { run.stop(); break 'folders; }
                        result = &mut fetch => break result,
                        _ = tick.tick() => { run.service().await; if run.aborted || run.halted { break 'folders; } }
                    }
                }
            };
            match fetched {
                Ok(bytes) => {
                    let builder = filling.as_mut().expect("admission has a filling batch");
                    let stopped = run.stopped.clone();
                    let add = builder.add(identity, bytes, &stopped);
                    tokio::pin!(add);
                    let result = loop {
                        tokio::select! {
                            result = &mut add => break result,
                            _ = cancelled(&mut cancel), if !run.aborted => { run.aborted = true; let _ = run.stop.send(true); }
                            _ = tick.tick() => {
                                run.service().await;
                                if events.is_closed() { run.aborted = true; let _ = run.stop.send(true); }
                            }
                        }
                    };
                    if let Err(error) = result {
                        run.diagnostic("Batch preparation", error.to_string());
                        run.halted = true;
                    }
                }
                Err(error) => {
                    run.counts.processed += 1;
                    let skip_folder = matches!(
                        &error,
                        mailbox::Error::Stale
                            | mailbox::Error::ReadOnly
                            | mailbox::Error::Rejected {
                                operation: "folder selection",
                                ..
                            }
                    );
                    if matches!(error, mailbox::Error::Missing) {
                        run.counts.vanished += 1;
                    } else {
                        run.counts.incomplete += 1;
                        run.diagnostic(snapshot.folder.display(), error.to_string());
                    }
                    let reconnect = {
                        let connect = mailbox::Client::connect(settings);
                        tokio::pin!(connect);
                        loop {
                            tokio::select! {
                                _ = cancelled(&mut cancel) => { run.stop(); break 'folders; }
                                result = &mut connect => break result,
                                _ = tick.tick() => { run.service().await; if run.aborted || run.halted { break 'folders; } }
                            }
                        }
                    };
                    match reconnect {
                        Ok(connection) => client = connection,
                        Err(error) => {
                            run.diagnostic("Reconnect", error.to_string());
                            break 'folders;
                        }
                    }
                    if skip_folder {
                        continue 'folders;
                    }
                }
            }
            run.counts.queued = filling
                .as_ref()
                .map_or(0, |builder| builder.retained().messages().len() as u64);
            let _ = events.try_send(event::Event::Progress {
                counts: *run.counts,
                folder: Some(snapshot.folder.display().into()),
            });
        }
    }
    if *cancel.borrow() || cancel.has_changed().is_err() || events.is_closed() {
        run.stop();
    }
    // EOF and download failure flush a nonempty remainder; cancellation never launches it.
    if let Some(builder) = filling.take() {
        run.flush(builder, parallel, &mut cancel).await;
    }
    run.counts.queued = 0;
    run.counts.batches_queued = 0;
    while !run.active.is_empty() {
        tokio::select! {
            _ = cancelled(&mut cancel), if !run.aborted => run.stop(),
            _ = tick.tick() => run.service().await,
        }
    }
    run.counts.active = 0;
    run.counts.batches_active = 0;
    run.counts.cancelled = run.counts.total.saturating_sub(run.counts.processed);
    if let Err(error) = tokio::fs::remove_dir(&session).await {
        run.diagnostic("Temporary cleanup", error.to_string());
        let _ = events.send(event::Event::Leftover(session)).await;
    }
    if !run.aborted {
        let _ = client.logout().await;
    }
    Ok(if run.aborted {
        event::Finish::Cancelled
    } else if run.partial || run.halted || run.counts.incomplete > 0 || run.counts.cancelled > 0 {
        event::Finish::Partial
    } else {
        event::Finish::Completed
    })
}

#[cfg(all(test, windows))]
mod tests {
    use super::*;
    use std::num::NonZeroU32;

    fn settings() -> config::Settings {
        config::Settings::try_from(config::Draft {
            host: "imap.example.test".into(),
            username: "user".into(),
            password: "unused".into(),
            scan_dir: "unused".into(),
            quarantine_dir: "unused".into(),
            scanner: crate::mailbox_scanner::core::scanner::Settings::Custom(
                crate::mailbox_scanner::core::scanner::custom::Settings {
                    executable: std::env::current_exe().unwrap(),
                    arguments: vec!["{directory}".into()],
                    clean_code: 0,
                    detected_code: 1,
                },
            ),
            ..Default::default()
        })
        .unwrap()
    }

    async fn batch(settings: &config::Settings) -> (std::path::PathBuf, batch::Batch) {
        let parent =
            super::super::unique_directory(&std::env::temp_dir(), "mailbox-batch-outbox-test")
                .unwrap();
        let mut builder = batch::Builder::create(&parent, 1024 * 1024).unwrap();
        let (_stop, cancel) = watch::channel(false);
        builder
            .add(
                message::Identity::new(
                    message::Account::from_settings(settings),
                    message::Folder::new("INBOX".into(), "INBOX".into()).unwrap(),
                    NonZeroU32::new(1).unwrap(),
                    NonZeroU32::new(1).unwrap(),
                ),
                b"Subject: fixture\r\n\r\nharmless body".to_vec(),
                &cancel,
            )
            .await
            .unwrap();
        assert!(!builder.full());
        (parent, builder.seal().unwrap().unwrap())
    }

    fn active(batch: batch::Batch, cleanup_safe: bool) -> Active {
        let reports = batch
            .messages()
            .iter()
            .map(|message| message.report().clone())
            .collect();
        let batch = Arc::new(batch);
        let worker_batch = Arc::clone(&batch);
        let task = tokio::spawn(async move {
            let leftovers = if cleanup_safe {
                worker_batch.cleanup().await
            } else {
                vec![worker_batch.directory().to_path_buf()]
            };
            (
                scanner::batch::Outcome {
                    reports,
                    cleanup_safe,
                },
                leftovers,
            )
        });
        Active {
            batch,
            updates: Arc::new(scanner::batch::Updates::default()),
            task: Some(task),
            latest: BTreeMap::new(),
            detected: HashSet::new(),
            pending: BTreeMap::new(),
            extra: VecDeque::new(),
            settled: false,
        }
    }
    #[tokio::test]
    async fn completed_batch_keeps_its_slot_until_terminal_delivery() {
        let settings = settings();
        let (parent, batch) = batch(&settings).await;
        let (events, mut receiver) = mpsc::channel(1);
        events.send(event::Event::Discovering).await.unwrap();
        let mut counts = event::Counts::default();
        let (stop, stopped) = watch::channel(false);
        let mut run = Run {
            events: &events,
            counts: &mut counts,
            engine: scanner::Engine::resolve(&settings).unwrap(),
            timeout: Duration::from_secs(10),
            stop,
            stopped,
            active: vec![active(batch, true)],
            partial: false,
            halted: false,
            aborted: false,
        };
        while !run.active[0].task.as_ref().unwrap().is_finished() {
            tokio::task::yield_now().await;
        }
        run.service().await;
        assert!(run.active[0].settled);
        assert_eq!(run.active.len(), 1);
        assert_eq!(run.active[0].pending.len(), 1);
        assert_eq!(run.counts.processed, 1);
        assert!(matches!(
            receiver.recv().await,
            Some(event::Event::Discovering)
        ));
        run.service().await;
        assert!(run.active.is_empty());
        assert!(matches!(
            receiver.recv().await,
            Some(event::Event::MessageUpdated {
                terminal: true,
                revision: u64::MAX,
                ..
            })
        ));
        assert_eq!(run.counts.processed, 1);
        std::fs::remove_dir(parent).unwrap();
    }

    #[tokio::test]
    async fn uncertain_termination_retains_files_and_stops_admission() {
        let settings = settings();
        let (parent, batch) = batch(&settings).await;
        let retained = Arc::new(batch);
        let task_batch = Arc::clone(&retained);
        let reports = retained
            .messages()
            .iter()
            .map(|message| message.report().clone())
            .collect();
        let leftovers = vec![retained.directory().to_path_buf()];
        let task = tokio::spawn(async move {
            (
                scanner::batch::Outcome {
                    reports,
                    cleanup_safe: false,
                },
                leftovers,
            )
        });
        let (events, mut receiver) = mpsc::channel(16);
        let mut counts = event::Counts::default();
        let (stop, stopped) = watch::channel(false);
        let mut run = Run {
            events: &events,
            counts: &mut counts,
            engine: scanner::Engine::resolve(&settings).unwrap(),
            timeout: Duration::from_secs(10),
            stop,
            stopped,
            active: vec![Active {
                batch: task_batch,
                updates: Arc::new(scanner::batch::Updates::default()),
                task: Some(task),
                latest: BTreeMap::new(),
                detected: HashSet::new(),
                pending: BTreeMap::new(),
                extra: VecDeque::new(),
                settled: false,
            }],
            partial: false,
            halted: false,
            aborted: false,
        };
        while !run.active[0].task.as_ref().unwrap().is_finished() {
            tokio::task::yield_now().await;
        }
        run.service().await;
        assert!(run.halted && run.partial);
        assert!(retained.directory().is_dir());
        assert!(retained.files().iter().all(|file| file.path().is_file()));
        let mut leftover = false;
        while let Ok(event) = receiver.try_recv() {
            leftover |= matches!(event, event::Event::Leftover(_));
        }
        assert!(leftover);
        // This synthetic task never launched a scanner, so test teardown may remove its inputs.
        assert!(retained.cleanup().await.is_empty());
        std::fs::remove_dir(parent).unwrap();
    }

    #[tokio::test]
    async fn retained_owned_input_still_stops_admission() {
        let settings = settings();
        let (parent, batch) = batch(&settings).await;
        let directory = batch.directory().to_owned();
        let blocked = batch.files()[0].path().to_owned();
        std::fs::remove_file(&blocked).unwrap();
        std::fs::create_dir(&blocked).unwrap();
        let (events, mut receiver) = mpsc::channel(16);
        let mut counts = event::Counts::default();
        let (stop, stopped) = watch::channel(false);
        let mut run = Run {
            events: &events,
            counts: &mut counts,
            engine: scanner::Engine::resolve(&settings).unwrap(),
            timeout: Duration::from_secs(10),
            stop,
            stopped,
            active: vec![active(batch, true)],
            partial: false,
            halted: false,
            aborted: false,
        };
        while !run.active[0].task.as_ref().unwrap().is_finished() {
            tokio::task::yield_now().await;
        }
        run.service().await;
        assert!(run.halted && run.partial);
        assert_eq!(run.counts.incomplete, 1);
        assert!(blocked.is_dir());
        let mut reported = false;
        while let Ok(event) = receiver.try_recv() {
            reported |= matches!(event, event::Event::Leftover(path) if path == blocked);
        }
        assert!(reported);
        std::fs::remove_dir(blocked).unwrap();
        std::fs::remove_dir(directory).unwrap();
        std::fs::remove_dir(parent).unwrap();
    }

    #[tokio::test]
    async fn pipeline_dispatches_full_and_small_final_batches_but_not_empty_or_cancelled() {
        pipeline(false).await;
    }

    #[tokio::test]
    async fn scanner_created_files_remain_without_blocking_the_next_batch() {
        pipeline(true).await;
    }

    async fn pipeline(leave_temporary_file: bool) {
        let parent =
            super::super::unique_directory(&std::env::temp_dir(), "mailbox-flush-pipeline-test")
                .unwrap();
        let source = parent.join("fixture.rs");
        let executable = parent.join("fixture.exe");
        let starts = parent.join("starts");
        std::fs::write(&source, r#"
use std::{fs, io::Write, path::PathBuf};
fn main() {
    let mut args = std::env::args_os().skip(1);
    let directory = PathBuf::from(args.next().unwrap());
    let marker = PathBuf::from(args.next().unwrap());
    let mut marker = fs::OpenOptions::new().create(true).append(true).open(marker).unwrap();
    writeln!(marker, "batch").unwrap();
    for entry in fs::read_dir(&directory).unwrap() {
        let entry = entry.unwrap();
        if entry.file_type().unwrap().is_file() { println!("{}\tCLEAN\t", entry.file_name().to_str().unwrap()); }
    }
    if args.next().as_deref() == Some(std::ffi::OsStr::new("leave-temp")) {
        fs::write(directory.join("unp-fixture.tmp"), b"scanner-owned contents").unwrap();
    }
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
            "{}",
            String::from_utf8_lossy(&compiler.stderr)
        );
        let settings = config::Settings::try_from(config::Draft {
            host: "imap.example.test".into(),
            username: "user".into(),
            password: "unused".into(),
            scan_dir: parent.clone(),
            quarantine_dir: parent.clone(),
            scanner: crate::mailbox_scanner::core::scanner::Settings::Custom(
                crate::mailbox_scanner::core::scanner::custom::Settings {
                    executable,
                    arguments: vec![
                        "{directory}".into(),
                        starts.to_str().unwrap().into(),
                        if leave_temporary_file {
                            "leave-temp"
                        } else {
                            "no-temp"
                        }
                        .into(),
                    ],
                    clean_code: 0,
                    detected_code: 1,
                },
            ),
            ..Default::default()
        })
        .unwrap();
        let (source_stop, mut cancel) = watch::channel(false);
        let mut full = batch::Builder::create(&parent, 1).unwrap();
        let mut remainder = batch::Builder::create(&parent, 1024 * 1024 * 1024).unwrap();
        let mut cancelled = batch::Builder::create(&parent, 1024 * 1024 * 1024).unwrap();
        for (index, builder) in [&mut full, &mut remainder, &mut cancelled]
            .into_iter()
            .enumerate()
        {
            builder
                .add(
                    message::Identity::new(
                        message::Account::from_settings(&settings),
                        message::Folder::new("INBOX".into(), "INBOX".into()).unwrap(),
                        NonZeroU32::new(1).unwrap(),
                        NonZeroU32::new(index as u32 + 1).unwrap(),
                    ),
                    b"Subject: fixture\r\n\r\nharmless".to_vec(),
                    &cancel,
                )
                .await
                .unwrap();
        }
        assert!(full.full());
        assert!(!remainder.full());
        let cancelled_path = cancelled.retained().directory().to_path_buf();
        let (events, mut receiver) = mpsc::channel(64);
        let mut counts = event::Counts::default();
        let (stop, stopped) = watch::channel(false);
        let mut run = Run {
            events: &events,
            counts: &mut counts,
            engine: scanner::Engine::resolve(&settings).unwrap(),
            timeout: Duration::from_secs(15),
            stop,
            stopped,
            active: Vec::new(),
            partial: false,
            halted: false,
            aborted: false,
        };
        let full_path = full.retained().directory().to_path_buf();
        let remainder_path = remainder.retained().directory().to_path_buf();
        let parallel = if leave_temporary_file { 1 } else { 2 };
        run.flush(full, parallel, &mut cancel).await;
        run.flush(remainder, parallel, &mut cancel).await;
        assert_eq!(
            run.active.len(),
            parallel,
            "The final small batch must actually be dispatched"
        );
        tokio::time::timeout(Duration::from_secs(20), async {
            while !run.active.is_empty() {
                run.service().await;
                while receiver.try_recv().is_ok() {}
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap();
        assert_eq!(run.counts.processed, 2);
        assert_eq!(run.counts.incomplete, 0);
        assert!(!run.halted);
        assert_eq!(run.partial, leave_temporary_file);
        for directory in [full_path, remainder_path] {
            if leave_temporary_file {
                let temporary = directory.join("unp-fixture.tmp");
                assert_eq!(
                    std::fs::read(&temporary).unwrap(),
                    b"scanner-owned contents"
                );
                assert_eq!(std::fs::read_dir(&directory).unwrap().count(), 1);
                // The fixture owns this file; application cleanup must have left it intact.
                std::fs::remove_file(temporary).unwrap();
                std::fs::remove_dir(directory).unwrap();
            } else {
                assert!(!directory.exists());
            }
        }
        let empty = batch::Builder::create(&parent, 1024).unwrap();
        run.flush(empty, 2, &mut cancel).await;
        assert!(run.active.is_empty());
        source_stop.send(true).unwrap();
        run.flush(cancelled, 2, &mut cancel).await;
        assert!(run.active.is_empty());
        assert!(run.aborted);
        assert!(!cancelled_path.exists());
        assert_eq!(std::fs::read_to_string(&starts).unwrap().lines().count(), 2);
        // Remaining entries are only the known source, executable, marker and compiler artifacts.
        let mut retained = false;
        for entry in std::fs::read_dir(&parent).unwrap() {
            let path = entry.unwrap().path();
            match std::fs::remove_file(&path) {
                Ok(()) => {}
                Err(error) if error.raw_os_error() == Some(32) => {
                    // Resident scanners can retain compiler artifacts after the child exits.
                    retained = true;
                    eprintln!("Retained locked test helper: {}", path.display());
                }
                Err(error) => panic!("Cannot remove test helper {}: {error}", path.display()),
            }
        }
        if !retained {
            std::fs::remove_dir(parent).unwrap();
        }
    }
}
