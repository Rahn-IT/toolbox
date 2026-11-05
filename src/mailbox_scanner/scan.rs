//! Progress and deliberate download/purge actions for one mailbox run.

use std::collections::{HashMap, VecDeque};
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use futures_util::stream;
use iced::widget::{
    button, checkbox, column, container, progress_bar, row, scrollable, space, text,
};
use iced::{Element, Length, Task};
use tokio::sync::{mpsc, watch};

use crate::mailbox_scanner::action::Action;
use crate::mailbox_scanner::core::{config, detection, event, message};
use crate::mailbox_scanner::{quarantine, workflow};

const PAGE_SIZE: usize = 100;
const MAX_DIAGNOSTICS: usize = 1_000;
static NEXT_RUN: AtomicU64 = AtomicU64::new(1);

pub struct State {
    settings: Arc<config::Settings>,
    run: u64,
    cancel: watch::Sender<bool>,
    runner_done: bool,
    stream_closed: bool,
    runner_error: Option<String>,
    discovering: bool,
    stopping: bool,
    finish: Option<event::Finish>,
    counts: event::Counts,
    folder: Option<String>,
    rows: Vec<Finding>,
    index: HashMap<message::Identity, usize>,
    page: usize,
    diagnostics: Vec<String>,
    omitted_diagnostics: u64,
    leftovers: Vec<PathBuf>,
    omitted_leftovers: u64,
    show_details: bool,
    active: Option<Active>,
    queue: VecDeque<message::Identity>,
    closing: bool,
    close_review: bool,
}

struct Finding {
    identity: message::Identity,
    subject: String,
    sender: String,
    report: detection::Report,
    selected: bool,
    expanded: bool,
    upstream: Upstream,
    saved: Option<detection::Saved>,
    availability: Option<detection::Availability>,
    detail: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Upstream {
    NotPurged,
    MarkedDeleted,
    Unknown,
    Purged,
}

struct Active {
    identity: message::Identity,
    kind: Kind,
    cancel: watch::Sender<bool>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Download,
    Purge,
    Check,
}

#[derive(Debug, Clone)]
pub enum Response {
    Downloaded(detection::Saved),
    Purged(detection::Purge),
    Checked(detection::Availability),
    Failed { detail: String, uncertain: bool },
}

#[derive(Debug, Clone)]
pub enum Message {
    Worker {
        run: u64,
        event: event::Event,
    },
    RunnerDone {
        run: u64,
        error: Option<String>,
    },
    StreamClosed(u64),
    Select(message::Identity, bool),
    SelectPage(bool),
    Page(usize),
    Details(message::Identity),
    ToggleDiagnostics,
    Start(message::Identity, Kind),
    PurgeSelected,
    ActionDone {
        run: u64,
        identity: message::Identity,
        response: Response,
    },
    StopScan,
    StopActions,
    Back,
    CloseRequested,
    ConfirmClose,
    Stay,
}

pub enum Instruction {
    Back,
    Close,
}

impl State {
    pub fn new(settings: Arc<config::Settings>) -> (Self, Task<Message>) {
        let run = NEXT_RUN.fetch_add(1, Ordering::Relaxed);
        let (cancel, cancelled) = watch::channel(false);
        let (events, receiver) = mpsc::channel(256);
        let worker_settings = Arc::clone(&settings);
        let worker = Task::perform(
            async move {
                match tokio::spawn(workflow::run(worker_settings, events, cancelled)).await {
                    Ok(Ok(())) => None,
                    Ok(Err(error)) => Some(error.to_string()),
                    Err(error) => Some(format!("Scan worker stopped unexpectedly: {error}")),
                }
            },
            move |error| Message::RunnerDone { run, error },
        );
        let updates = stream::unfold(
            (receiver, false),
            move |(mut receiver, closed)| async move {
                if closed {
                    return None;
                }
                let (message, closed) = match receiver.recv().await {
                    Some(event) => (Message::Worker { run, event }, false),
                    None => (Message::StreamClosed(run), true),
                };
                Some((message, (receiver, closed)))
            },
        );
        let state = Self {
            settings,
            run,
            cancel,
            runner_done: false,
            stream_closed: false,
            runner_error: None,
            discovering: true,
            stopping: false,
            finish: None,
            counts: event::Counts::default(),
            folder: None,
            rows: Vec::new(),
            index: HashMap::new(),
            page: 0,
            diagnostics: Vec::new(),
            omitted_diagnostics: 0,
            leftovers: Vec::new(),
            omitted_leftovers: 0,
            show_details: false,
            active: None,
            queue: VecDeque::new(),
            closing: false,
            close_review: false,
        };
        (
            state,
            Task::batch([worker, Task::run(updates, |message| message)]),
        )
    }

    pub fn update(&mut self, message: Message) -> Action<Instruction, Message> {
        match message {
            Message::Worker { run, event } if run == self.run => self.receive(event),
            Message::RunnerDone { run, error } if run == self.run => {
                self.runner_done = true;
                self.runner_error = error;
            }
            Message::StreamClosed(run) if run == self.run => self.stream_closed = true,
            Message::Select(identity, selected) if self.active.is_none() => {
                if let Some(finding) = self.find(&identity) {
                    finding.selected = selected && finding.upstream != Upstream::Purged;
                }
            }
            Message::SelectPage(selected) if self.active.is_none() => {
                let start = self.page * PAGE_SIZE;
                for finding in self.rows.iter_mut().skip(start).take(PAGE_SIZE) {
                    finding.selected = selected && finding.upstream != Upstream::Purged;
                }
            }
            Message::Page(page) => self.page = page.min(self.pages() - 1),
            Message::Details(identity) => {
                if let Some(finding) = self.find(&identity) {
                    finding.expanded = !finding.expanded;
                }
            }
            Message::ToggleDiagnostics => self.show_details = !self.show_details,
            Message::Start(identity, kind) if !self.busy() && !self.closing => {
                return self.start(identity, kind);
            }
            Message::PurgeSelected if !self.busy() && !self.closing => {
                self.queue = self
                    .rows
                    .iter()
                    .filter(|finding| finding.selected && finding.upstream != Upstream::Purged)
                    .map(|finding| finding.identity.clone())
                    .collect();
                return self.next();
            }
            Message::ActionDone {
                run,
                identity,
                response,
            } if run == self.run => {
                if self
                    .active
                    .as_ref()
                    .is_some_and(|active| active.identity == identity)
                {
                    self.active = None;
                    self.action_done(&identity, response);
                    if !self.closing {
                        return self.next();
                    }
                }
            }
            Message::StopScan => {
                self.stopping = true;
                let _ = self.cancel.send(true);
            }
            Message::StopActions => self.queue.clear(),
            Message::Back if !self.busy() && !self.closing => {
                return Action::instruction(Instruction::Back);
            }
            Message::CloseRequested => {
                self.closing = true;
                self.queue.clear();
                self.stopping = true;
                let _ = self.cancel.send(true);
                if let Some(active) = &self.active {
                    let _ = active.cancel.send(true);
                }
            }
            Message::ConfirmClose if !self.busy() => {
                return Action::instruction(Instruction::Close);
            }
            Message::Stay => {
                self.closing = false;
                self.close_review = false;
            }
            Message::Worker { .. }
            | Message::RunnerDone { .. }
            | Message::StreamClosed(_)
            | Message::Select(_, _)
            | Message::SelectPage(_)
            | Message::Start(_, _)
            | Message::PurgeSelected
            | Message::ActionDone { .. }
            | Message::Back
            | Message::ConfirmClose => {}
        }
        if self.runner_done && self.stream_closed && self.finish.is_none() {
            self.finish = Some(event::Finish::Failed);
            let detail = self
                .runner_error
                .take()
                .unwrap_or_else(|| "Scan worker ended without a final result".into());
            self.diagnostic(detail);
        }
        if self.closing && !self.busy() {
            if self.needs_close_review() {
                self.close_review = true;
            } else {
                return Action::instruction(Instruction::Close);
            }
        }
        Action::none()
    }

    pub fn busy(&self) -> bool {
        !self.runner_done || !self.stream_closed || self.active.is_some() || !self.queue.is_empty()
    }

    pub fn is_closing(&self) -> bool {
        self.closing
    }

    #[cfg(test)]
    pub fn preview() -> Self {
        let settings = config::Settings::try_from(config::Draft {
            host: "preview.example.invalid".into(),
            username: "Synthetic preview".into(),
            password: "unused".into(),
            scan_dir: "preview-scan".into(),
            quarantine_dir: "preview-quarantine".into(),
            ..config::Draft::default()
        })
        .expect("synthetic preview settings are valid");
        let (mut state, task) = Self::new(Arc::new(settings));
        drop(task);
        for uid in 1..=3 {
            let identity = message::Identity::new(
                message::Account::from_settings(&state.settings),
                message::Folder::new("INBOX.Archive".into(), "INBOX.Archive".into())
                    .expect("valid synthetic folder"),
                std::num::NonZeroU32::new(10).expect("nonzero synthetic generation"),
                std::num::NonZeroU32::new(uid).expect("nonzero synthetic UID"),
            );
            let mut report = detection::Report::new();
            report.record(detection::Evidence {
                backend: state.settings.backend(),
                threat: "Synthetic detection — no malware".into(),
            });
            if uid == 2 {
                report.warn(detection::Issue::Scanner(
                    "Synthetic partial inspection warning".into(),
                ));
            }
            state.receive(event::Event::MessageFinished {
                identity: identity.clone(),
                subject: format!("SYNTHETIC PREVIEW {uid}: Monthly invoice and archived attachment — a deliberately long subject to inspect wrapping"),
                sender: "Synthetic Sender <sender@example.invalid>".into(),
                report,
            });
            if uid == 1 {
                state.action_done(
                    &identity,
                    Response::Downloaded(detection::Saved::new(
                        "D:/Preview/Quarantine/synthetic-message.eml".into(),
                        4096,
                    )),
                );
                if let Some(finding) = state.find(&identity) {
                    finding.selected = true;
                    finding.detail =
                        "SYNTHETIC PREVIEW: no message downloaded and no local file written."
                            .into();
                }
            }
        }
        state.runner_done = true;
        state.stream_closed = true;
        state.discovering = false;
        state.finish = Some(event::Finish::Partial);
        state.counts = event::Counts {
            total: 1280,
            processed: 1280,
            detected: 3,
            incomplete: 1,
            ..event::Counts::default()
        };
        state.diagnostic(
            "SYNTHETIC PREVIEW: sample messages only; no mailbox or scanner was contacted.".into(),
        );
        state
    }

    fn receive(&mut self, event: event::Event) {
        match event {
            event::Event::Discovering => self.discovering = true,
            event::Event::Progress { counts, folder } => {
                if counts.total > 0 {
                    self.discovering = false;
                }
                self.counts = counts;
                self.folder = folder;
            }
            event::Event::MessageFinished {
                identity,
                subject,
                sender,
                report,
            } => {
                if report.detected() {
                    if let Some(finding) = self.find(&identity) {
                        finding.report.merge(report);
                    } else {
                        let index = self.rows.len();
                        self.index.insert(identity.clone(), index);
                        self.rows.push(Finding {
                            identity,
                            subject,
                            sender,
                            report,
                            selected: false,
                            expanded: false,
                            upstream: Upstream::NotPurged,
                            saved: None,
                            availability: None,
                            detail: String::new(),
                        });
                    }
                } else if !report.complete() {
                    let mut detail = report
                        .issues()
                        .iter()
                        .map(ToString::to_string)
                        .collect::<Vec<_>>()
                        .join("; ");
                    if report.omitted_issues() > 0 {
                        detail.push_str(&format!(
                            "; {} further issues omitted",
                            report.omitted_issues()
                        ));
                    }
                    self.diagnostic(format!(
                        "{} · UID {} · {}: {}",
                        identity.folder().display(),
                        identity.uid(),
                        subject,
                        detail
                    ));
                }
            }
            event::Event::Diagnostic { context, detail } => {
                self.diagnostic(format!("{context}: {detail}"))
            }
            event::Event::Leftover(path) => {
                if self.leftovers.len() < MAX_DIAGNOSTICS {
                    self.leftovers.push(path);
                } else {
                    self.omitted_leftovers = self.omitted_leftovers.saturating_add(1);
                }
                self.show_details = true;
            }
            event::Event::Finished { finish, counts } => {
                self.finish = Some(finish);
                self.counts = counts;
                self.discovering = false;
            }
            event::Event::Downloaded { identity, saved } => {
                self.action_done(&identity, Response::Downloaded(saved))
            }
            event::Event::Checked {
                identity,
                availability,
            } => self.action_done(&identity, Response::Checked(availability)),
            event::Event::Purged { identity, outcome } => {
                self.action_done(&identity, Response::Purged(outcome))
            }
            event::Event::ActionFailed { identity, detail } => self.action_done(
                &identity,
                Response::Failed {
                    detail,
                    uncertain: false,
                },
            ),
            event::Event::Vanished(_) => {}
        }
    }

    fn start(&mut self, identity: message::Identity, kind: Kind) -> Action<Instruction, Message> {
        let Some(index) = self.index.get(&identity).copied() else {
            return Action::none();
        };
        let finding = &self.rows[index];
        if kind != Kind::Check && finding.upstream == Upstream::Purged {
            return Action::none();
        }
        let saved = finding.saved.clone();
        if kind == Kind::Check && saved.is_none() {
            return Action::none();
        }
        let (cancel, cancelled) = watch::channel(false);
        self.active = Some(Active {
            identity: identity.clone(),
            kind,
            cancel,
        });
        let settings = Arc::clone(&self.settings);
        let run = self.run;
        let work_identity = identity.clone();
        let task = Task::perform(
            async move {
                let operation = tokio::spawn(async move {
                    match kind {
                        Kind::Download => {
                            match workflow::download(settings, work_identity, cancelled).await {
                                Ok(saved) => Response::Downloaded(saved),
                                Err(error) => Response::Failed {
                                    detail: error.to_string(),
                                    uncertain: false,
                                },
                            }
                        }
                        Kind::Purge => {
                            match workflow::purge(settings, work_identity, cancelled).await {
                                Ok(outcome) => Response::Purged(outcome),
                                Err(error) => Response::Failed {
                                    detail: error.to_string(),
                                    uncertain: false,
                                },
                            }
                        }
                        Kind::Check => {
                            let Some(saved) = saved else {
                                return Response::Failed {
                                    detail: "No local copy is recorded".into(),
                                    uncertain: false,
                                };
                            };
                            match tokio::task::spawn_blocking(move || quarantine::check(&saved))
                                .await
                            {
                                Ok(availability) => Response::Checked(availability),
                                Err(error) => Response::Failed {
                                    detail: error.to_string(),
                                    uncertain: false,
                                },
                            }
                        }
                    }
                });
                match operation.await {
                    Ok(response) => response,
                    Err(error) => Response::Failed {
                        detail: format!("Background action stopped unexpectedly: {error}"),
                        uncertain: kind == Kind::Purge,
                    },
                }
            },
            move |response| Message::ActionDone {
                run,
                identity: identity.clone(),
                response,
            },
        );
        Action {
            instruction: None,
            task,
        }
    }

    fn next(&mut self) -> Action<Instruction, Message> {
        while let Some(identity) = self.queue.pop_front() {
            if self
                .index
                .get(&identity)
                .is_some_and(|index| self.rows[*index].upstream != Upstream::Purged)
            {
                return self.start(identity, Kind::Purge);
            }
        }
        Action::none()
    }

    fn action_done(&mut self, identity: &message::Identity, response: Response) {
        let Some(finding) = self.find(identity) else {
            return;
        };
        match response {
            Response::Downloaded(saved) => {
                finding.saved = Some(saved);
                finding.availability = Some(detection::Availability::Available);
                finding.detail =
                    "Downloaded and byte-verified. Upstream message was left untouched.".into();
            }
            Response::Checked(availability) => finding.availability = Some(availability),
            Response::Purged(outcome) => {
                let (saved, upstream, detail) = match outcome {
                    detection::Purge::Saved { saved, detail } => (saved, finding.upstream, detail),
                    detection::Purge::MarkedDeleted { saved, preexisting_deleted } => (
                        saved,
                        Upstream::MarkedDeleted,
                        if preexisting_deleted {
                            "Message remains upstream; Deleted was already set before this operation."
                        } else {
                            "Message remains upstream with Deleted set; targeted purge did not complete."
                        }.into(),
                    ),
                    detection::Purge::Purged(saved) => (saved, Upstream::Purged, "Quarantine verified; targeted purge confirmed.".into()),
                    detection::Purge::OutcomeUnknown { saved, detail } => (saved, Upstream::Unknown, detail),
                };
                finding.saved = Some(saved);
                finding.availability = None;
                finding.upstream = upstream;
                finding.detail = detail;
                if upstream == Upstream::Purged {
                    finding.selected = false;
                }
            }
            Response::Failed { detail, uncertain } => {
                finding.detail = detail;
                if uncertain {
                    finding.upstream = Upstream::Unknown;
                    if finding.saved.is_none() {
                        finding.detail.push_str(
                            " No local copy path could be confirmed by the interrupted task.",
                        );
                    }
                }
            }
        }
        clip(&mut finding.detail, 2048);
        if let Some(detection::Availability::Unreadable(detail)) = &mut finding.availability {
            clip(detail, 512);
        }
    }

    fn find(&mut self, identity: &message::Identity) -> Option<&mut Finding> {
        let index = self.index.get(identity).copied()?;
        self.rows.get_mut(index)
    }

    fn diagnostic(&mut self, mut detail: String) {
        if self.diagnostics.len() < MAX_DIAGNOSTICS {
            clip(&mut detail, 2048);
            self.diagnostics.push(detail);
        } else {
            self.omitted_diagnostics = self.omitted_diagnostics.saturating_add(1);
        }
    }

    fn pages(&self) -> usize {
        self.rows.len().div_ceil(PAGE_SIZE).max(1)
    }

    fn needs_close_review(&self) -> bool {
        !self.leftovers.is_empty()
            || self.omitted_leftovers != 0
            || self.rows.iter().any(|finding| {
                matches!(
                    finding.upstream,
                    Upstream::MarkedDeleted | Upstream::Unknown
                )
            })
    }

    pub fn view(&self) -> Element<'_, Message> {
        let scanning = !self.runner_done || !self.stream_closed;
        let actions_enabled = !self.busy() && !self.closing;
        let selected = self
            .rows
            .iter()
            .filter(|finding| finding.selected && finding.upstream != Upstream::Purged)
            .count();
        let title = row![
            column![
                text("Mailbox Scanner").size(27),
                row![
                    text(format!(
                        "{} @ {}",
                        self.settings.username(),
                        self.settings.host()
                    ))
                    .size(13)
                    .width(Length::Fill),
                    text(format!("Scanner: {}", self.settings.backend()))
                        .size(13)
                        .width(Length::Fill),
                    text(format!("Parallel scans: {}", self.settings.parallel()))
                        .size(13)
                        .width(Length::Fill),
                ]
                .spacing(16)
            ]
            .spacing(4)
            .width(Length::Fill),
            button("Back to setup")
                .on_press_maybe((!self.busy() && !self.closing).then_some(Message::Back)),
        ]
        .spacing(16)
        .align_y(iced::Alignment::Center);
        let status = if self.stopping && scanning {
            "Stopping scan and cleaning up…"
        } else if scanning && self.discovering {
            "Discovering folders and messages…"
        } else if scanning {
            "Scanning mailbox…"
        } else {
            match self.finish {
                Some(event::Finish::Completed) => "Scan completed",
                Some(event::Finish::Partial) => "Scan finished with incomplete coverage",
                Some(event::Finish::Cancelled) => "Scan cancelled",
                Some(event::Finish::Failed) => "Scan failed",
                None => "Finishing scan…",
            }
        };
        let progress = if self.counts.total == 0 {
            0.0
        } else {
            self.counts.processed as f32 / self.counts.total as f32
        };
        let stop = button(if self.stopping {
            "Stopping…"
        } else {
            "Stop scan"
        })
        .on_press_maybe((scanning && !self.stopping).then_some(Message::StopScan));
        let summary = column![
            row![text(status).size(18), space().width(Length::Fill), stop]
                .align_y(iced::Alignment::Center),
            text(
                self.folder
                    .as_deref()
                    .unwrap_or("All selectable IMAP folders")
            )
            .size(13),
            progress_bar(0.0..=1.0, progress),
            row![
                text(format!("Processed: {}", self.counts.processed))
                    .size(13)
                    .width(Length::Fill),
                text(format!("Total: {}", self.counts.total))
                    .size(13)
                    .width(Length::Fill),
                text(format!("Active scans: {}", self.counts.active))
                    .size(13)
                    .width(Length::Fill),
                text(format!("Buffered: {}", self.counts.queued))
                    .size(13)
                    .width(Length::Fill),
            ]
            .spacing(16),
            row![
                text(format!("Detected: {}", self.counts.detected))
                    .size(13)
                    .width(Length::Fill),
                text(format!("Incomplete: {}", self.counts.incomplete))
                    .size(13)
                    .width(Length::Fill),
                text(format!("Vanished: {}", self.counts.vanished))
                    .size(13)
                    .width(Length::Fill),
                text(format!("Unprocessed/cancelled: {}", self.counts.cancelled))
                    .size(13)
                    .width(Length::Fill),
            ]
            .spacing(16),
        ]
        .spacing(8);

        let mut table = column![
            row![
                text("").width(30),
                text("Subject").width(240),
                text("Sender").width(165),
                text("Folder").width(125),
                text("Detection / status").width(225),
                text("Actions").width(190)
            ]
            .spacing(10)
        ]
        .spacing(10)
        .width(Length::Fixed(1090.0));
        if self.rows.is_empty() {
            table = table.push(
                container(text(if scanning {
                    "No detections yet."
                } else {
                    "No detections."
                }))
                .padding(24),
            );
        }
        for finding in self.rows.iter().skip(self.page * PAGE_SIZE).take(PAGE_SIZE) {
            table = table.push(self.finding_view(finding, actions_enabled));
        }
        let list = scrollable(table)
            .direction(scrollable::Direction::Both {
                vertical: scrollable::Scrollbar::default(),
                horizontal: scrollable::Scrollbar::default(),
            })
            .height(Length::Fill)
            .width(Length::Fill);
        let navigation = row![
            button("Previous")
                .on_press_maybe((self.page > 0).then(|| Message::Page(self.page - 1))),
            text(format!(
                "Page {} of {} · {} detections",
                self.page + 1,
                self.pages(),
                self.rows.len()
            ))
            .size(13),
            button("Next").on_press_maybe(
                (self.page + 1 < self.pages()).then_some(Message::Page(self.page + 1))
            ),
            space().width(Length::Fill),
            button("Select page")
                .on_press_maybe(self.active.is_none().then_some(Message::SelectPage(true))),
            button("Clear page")
                .on_press_maybe(self.active.is_none().then_some(Message::SelectPage(false))),
        ]
        .spacing(10)
        .align_y(iced::Alignment::Center);
        let mut batch = row![
            text(format!("{selected} selected")).size(14),
            space().width(Length::Fill)
        ];
        if let Some(active) = &self.active {
            let label = match active.kind {
                Kind::Download => "Downloading…",
                Kind::Purge => "Preserving and purging…",
                Kind::Check => "Checking local file…",
            };
            batch = batch
                .push(text(format!("{label} {} queued", self.queue.len())).size(13))
                .push(button("Stop after current").on_press(Message::StopActions));
        }
        batch = batch
            .push(
                button(text(format!("Download & purge selected ({selected})")))
                    .style(button::danger)
                    .on_press_maybe(
                        (actions_enabled && selected > 0).then_some(Message::PurgeSelected),
                    ),
            )
            .spacing(12)
            .align_y(iced::Alignment::Center);
        let mut content = column![title, summary, list, navigation, batch]
            .spacing(14)
            .height(Length::Fill);
        let diagnostic_count = self.diagnostics.len() as u64 + self.omitted_diagnostics;
        let leftover_count = self.leftovers.len() as u64 + self.omitted_leftovers;
        if diagnostic_count > 0 || leftover_count > 0 {
            content = content.push(
                button(text(format!(
                    "{} diagnostics · {} temporary leftovers {}",
                    diagnostic_count,
                    leftover_count,
                    if self.show_details { "▴" } else { "▾" }
                )))
                .style(button::secondary)
                .on_press(Message::ToggleDiagnostics),
            );
            if self.show_details {
                let mut details = column![].spacing(5);
                for path in &self.leftovers {
                    details = details.push(
                        text(format!(
                            "Temporary file could not be removed: {}",
                            path.display()
                        ))
                        .size(12),
                    );
                }
                for detail in &self.diagnostics {
                    details = details.push(text(detail).size(12));
                }
                if self.omitted_diagnostics != 0 || self.omitted_leftovers != 0 {
                    details = details.push(
                        text(format!(
                            "Additional details omitted: {} diagnostics, {} leftover paths",
                            self.omitted_diagnostics, self.omitted_leftovers
                        ))
                        .size(12),
                    );
                }
                content = content.push(scrollable(details).height(130));
            }
        }
        if self.closing {
            if self.close_review {
                content = content.push(container(column![
                    text("Review before closing: temporary files remain or an upstream deletion is incomplete/uncertain.").size(15),
                    row![button("Keep window open").on_press(Message::Stay), button("Close anyway").style(button::danger).on_press_maybe((!self.busy()).then_some(Message::ConfirmClose))].spacing(12),
                ].spacing(8)).padding(12).style(container::bordered_box));
            } else {
                content =
                    content.push(text("Closing after active work and cleanup settle…").size(14));
            }
        }
        container(content)
            .padding(24)
            .height(Length::Fill)
            .width(Length::Fill)
            .into()
    }

    fn finding_view<'a>(&self, finding: &'a Finding, enabled: bool) -> Element<'a, Message> {
        let identity = &finding.identity;
        let pending = self
            .active
            .as_ref()
            .is_some_and(|active| &active.identity == identity);
        let actionable = enabled && finding.upstream != Upstream::Purged;
        let mut selected = checkbox(finding.selected);
        if self.active.is_none() && finding.upstream != Upstream::Purged {
            let identity = identity.clone();
            selected = selected.on_toggle(move |value| Message::Select(identity.clone(), value));
        }
        let threat = finding
            .report
            .evidence()
            .iter()
            .take(2)
            .map(|item| item.threat.as_str())
            .collect::<Vec<_>>()
            .join("; ");
        let upstream = match finding.upstream {
            Upstream::NotPurged => "Not purged",
            Upstream::MarkedDeleted => "Still upstream · marked Deleted",
            Upstream::Unknown => "Upstream outcome unknown",
            Upstream::Purged => "Purged upstream",
        };
        let mut status = column![
            text(threat).size(13),
            text(if pending {
                "Action in progress…"
            } else {
                upstream
            })
            .size(12)
        ]
        .spacing(5)
        .width(225);
        if !finding.report.complete() {
            status = status.push(text("Incomplete scan coverage").size(12));
        }
        let actions = column![
            button("Download to quarantine")
                .on_press_maybe(
                    actionable.then(|| Message::Start(identity.clone(), Kind::Download))
                )
                .width(190),
            button("Download & purge")
                .style(button::danger)
                .on_press_maybe(actionable.then(|| Message::Start(identity.clone(), Kind::Purge)))
                .width(190),
            row![
                button("Check file").on_press_maybe(
                    (enabled && finding.saved.is_some())
                        .then(|| Message::Start(identity.clone(), Kind::Check))
                ),
                button(if finding.expanded { "Less" } else { "Details" })
                    .style(button::secondary)
                    .on_press(Message::Details(identity.clone()))
            ]
            .spacing(6),
        ]
        .spacing(6)
        .width(190);
        let top = row![
            selected.width(30),
            text(&finding.subject).size(14).width(240).height(42),
            text(&finding.sender).size(13).width(165).height(42),
            text(identity.folder().display())
                .size(13)
                .width(125)
                .height(42),
            status,
            actions
        ]
        .spacing(10);
        let mut body = column![top].spacing(6);
        if let Some(saved) = &finding.saved {
            body = body.push(text(format!("Saved: {}", saved.path().display())).size(12));
            if let Some(availability) = &finding.availability {
                let detail = match availability {
                    detection::Availability::Available => {
                        "Last observation: local file was readable at the expected size (availability only)."
                            .into()
                    }
                    detection::Availability::Missing => {
                        "Local file is missing. Its cause has not been determined.".into()
                    }
                    detection::Availability::Unreadable(detail) => {
                        format!("Local file is unreadable: {detail}")
                    }
                    detection::Availability::SizeChanged { actual } => format!(
                        "Local file size changed: expected {}, observed {actual} bytes",
                        saved.expected_len()
                    ),
                };
                body = body.push(text(detail).size(12));
            }
        }
        if !finding.detail.is_empty() {
            body = body.push(text(&finding.detail).size(12));
        }
        if finding.expanded {
            body = body.push(
                text(format!(
                    "Subject: {}\nSender: {}\nFolder: {}",
                    finding.subject,
                    finding.sender,
                    identity.folder().display()
                ))
                .size(12),
            );
            body = body.push(
                text(format!(
                    "UID {} · UIDVALIDITY {}",
                    identity.uid(),
                    identity.uidvalidity()
                ))
                .size(12),
            );
            for evidence in finding.report.evidence() {
                body =
                    body.push(text(format!("{}: {}", evidence.backend, evidence.threat)).size(12));
            }
            for issue in finding.report.issues() {
                body = body.push(text(issue.to_string()).size(12));
            }
            if finding.report.omitted_evidence() > 0 || finding.report.omitted_issues() > 0 {
                body = body.push(
                    text(format!(
                        "Additional findings omitted: {} detections, {} issues",
                        finding.report.omitted_evidence(),
                        finding.report.omitted_issues()
                    ))
                    .size(12),
                );
            }
        }
        container(body)
            .padding(10)
            .style(container::bordered_box)
            .into()
    }
}

fn clip(value: &mut String, maximum: usize) {
    let mut boundary = value.len().min(maximum);
    while !value.is_char_boundary(boundary) {
        boundary -= 1;
    }
    value.truncate(boundary);
}

#[cfg(test)]
mod tests {
    use std::num::NonZeroU32;
    use std::sync::Arc;

    use super::{Instruction, Kind, Message, Response, State, Upstream};
    use crate::mailbox_scanner::core::{config, detection, event, message, scanner};

    fn state() -> State {
        let settings = config::Settings::try_from(config::Draft {
            host: "imap.example.org".into(),
            username: "user".into(),
            password: "private".into(),
            scan_dir: "unused-scan-path".into(),
            quarantine_dir: "unused-quarantine-path".into(),
            ..config::Draft::default()
        })
        .unwrap();
        let (mut state, task) = State::new(Arc::new(settings));
        // Dropping the unpolled iced tasks keeps these transition tests free of IO.
        drop(task);
        state.runner_done = true;
        state.stream_closed = true;
        state.finish = Some(event::Finish::Completed);
        state
    }

    fn detected(state: &mut State, uid: u32) -> message::Identity {
        let identity = message::Identity::new(
            message::Account::from_settings(&state.settings),
            message::Folder::new("INBOX".into(), "INBOX".into()).unwrap(),
            NonZeroU32::new(1).unwrap(),
            NonZeroU32::new(uid).unwrap(),
        );
        let mut report = detection::Report::new();
        report.record(detection::Evidence {
            backend: scanner::Backend::Defender,
            threat: "Example detection".into(),
        });
        state.receive(event::Event::MessageFinished {
            identity: identity.clone(),
            subject: "Subject".into(),
            sender: "sender@example.org".into(),
            report,
        });
        identity
    }

    #[test]
    fn final_progress_does_not_unlock_actions_before_workers_settle() {
        let mut state = state();
        state.runner_done = false;
        state.stream_closed = false;
        state.receive(event::Event::Finished {
            finish: event::Finish::Completed,
            counts: event::Counts::default(),
        });
        assert!(state.busy());
        let _ = state.update(Message::RunnerDone {
            run: state.run,
            error: None,
        });
        assert!(state.busy());
        let _ = state.update(Message::StreamClosed(state.run));
        assert!(!state.busy());
    }

    #[test]
    fn download_only_keeps_the_row_and_prior_upstream_status() {
        let mut state = state();
        let identity = detected(&mut state, 1);
        state.action_done(
            &identity,
            Response::Purged(detection::Purge::MarkedDeleted {
                saved: detection::Saved::new("first.eml".into(), 5),
                preexisting_deleted: false,
            }),
        );
        state.action_done(
            &identity,
            Response::Downloaded(detection::Saved::new("second.eml".into(), 5)),
        );
        assert_eq!(state.rows.len(), 1);
        assert_eq!(state.rows[0].upstream, Upstream::MarkedDeleted);
        assert_eq!(
            state.rows[0].saved.as_ref().unwrap().path(),
            std::path::Path::new("second.eml")
        );
        assert!(state.needs_close_review());
    }

    #[test]
    fn a_saved_only_retry_does_not_erase_prior_uncertainty() {
        let mut state = state();
        let identity = detected(&mut state, 1);
        state.action_done(
            &identity,
            Response::Failed {
                detail: "Worker interrupted".into(),
                uncertain: true,
            },
        );
        state.action_done(
            &identity,
            Response::Purged(detection::Purge::Saved {
                saved: detection::Saved::new("copy.eml".into(), 5),
                detail: "Stopped before marking".into(),
            }),
        );
        assert_eq!(state.rows[0].upstream, Upstream::Unknown);
        assert!(state.needs_close_review());
    }

    #[test]
    fn events_from_an_old_run_cannot_change_the_screen() {
        let mut state = state();
        let _ = state.update(Message::Worker {
            run: state.run + 1,
            event: event::Event::Diagnostic {
                context: "Old run".into(),
                detail: "stale".into(),
            },
        });
        assert!(state.diagnostics.is_empty());
    }

    #[test]
    fn page_selection_preserves_other_pages() {
        let mut state = state();
        for uid in 1..=105 {
            detected(&mut state, uid);
        }
        let _ = state.update(Message::SelectPage(true));
        assert_eq!(
            state.rows.iter().filter(|finding| finding.selected).count(),
            100
        );
        let _ = state.update(Message::Page(1));
        let _ = state.update(Message::SelectPage(true));
        let _ = state.update(Message::Page(0));
        let _ = state.update(Message::SelectPage(false));
        assert_eq!(
            state.rows.iter().filter(|finding| finding.selected).count(),
            5
        );
    }

    #[test]
    fn close_waits_for_settlement_and_then_displays_uncertainty() {
        let mut state = state();
        let _cancellation_receiver = state.cancel.subscribe();
        let identity = detected(&mut state, 1);
        state.action_done(
            &identity,
            Response::Failed {
                detail: "Uncertain outcome".into(),
                uncertain: true,
            },
        );
        state.runner_done = false;
        state.stream_closed = false;
        let action = state.update(Message::CloseRequested);
        assert!(action.instruction.is_none());
        assert!(*state.cancel.borrow());
        let _ = state.update(Message::RunnerDone {
            run: state.run,
            error: None,
        });
        let action = state.update(Message::StreamClosed(state.run));
        assert!(action.instruction.is_none());
        assert!(state.close_review);
        let action = state.update(Message::ConfirmClose);
        assert!(matches!(action.instruction, Some(Instruction::Close)));
    }

    #[test]
    fn stopping_a_batch_leaves_the_current_purge_running() {
        let mut state = state();
        let first = detected(&mut state, 1);
        let second = detected(&mut state, 2);
        state.queue.push_back(second);
        let action = state.start(first.clone(), Kind::Purge);
        drop(action);
        let _ = state.update(Message::StopActions);
        assert!(state.queue.is_empty());
        assert!(!*state.active.as_ref().unwrap().cancel.borrow());
        let _ = state.update(Message::ActionDone {
            run: state.run,
            identity: first,
            response: Response::Purged(detection::Purge::Saved {
                saved: detection::Saved::new("copy.eml".into(), 5),
                detail: "No mutation".into(),
            }),
        });
        assert!(!state.busy());
    }

    #[test]
    fn mailbox_actions_are_ignored_while_scan_workers_are_active() {
        let mut state = state();
        let identity = detected(&mut state, 1);
        state.runner_done = false;
        let action = state.update(Message::Start(identity, Kind::Purge));
        assert!(action.instruction.is_none());
        assert!(state.active.is_none());
    }

    #[test]
    fn incomplete_messages_without_detections_have_visible_diagnostics() {
        let mut state = state();
        let identity = detected(&mut state, 1);
        state.rows.clear();
        state.index.clear();
        let mut report = detection::Report::new();
        report.warn(detection::Issue::Scanner("Engine unavailable".into()));
        state.receive(event::Event::MessageFinished {
            identity,
            subject: "Needs inspection".into(),
            sender: "sender@example.org".into(),
            report,
        });
        assert!(state.rows.is_empty());
        assert_eq!(state.diagnostics.len(), 1);
        assert!(state.diagnostics[0].contains("Engine unavailable"));
        assert_eq!(state.counts.processed, 0);
    }
}
