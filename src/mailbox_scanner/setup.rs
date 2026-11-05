//! Account and scan configuration screen.

use std::{path::PathBuf, sync::Arc};

use iced::{
    Element, Length,
    widget::{button, column, container, pick_list, row, scrollable, text, text_input},
};

use crate::mailbox_scanner::{
    action::Action,
    core::{config, scanner},
};

pub struct State {
    host: String,
    port: String,
    username: String,
    password: String,
    scan_dir: String,
    quarantine_dir: String,
    executable: String,
    parallel: String,
    backend: scanner::Backend,
    tls: config::Tls,
    error: Option<String>,
}

#[derive(Clone)]
pub enum Message {
    Host(String),
    Port(String),
    Username(String),
    Password(String),
    ScanDir(String),
    QuarantineDir(String),
    Executable(String),
    Parallel(String),
    Backend(scanner::Backend),
    Tls(config::Tls),
    Start,
    Browse(Browse),
    Picked(Browse, Option<PathBuf>),
}

#[derive(Debug, Clone, Copy)]
pub enum Browse {
    Scan,
    Quarantine,
    Executable,
}

impl std::fmt::Debug for Message {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Password(_) => "Password([redacted])",
            _ => "Setup event",
        })
    }
}

pub enum Instruction {
    Begin(Arc<config::Settings>),
}

impl Default for State {
    fn default() -> Self {
        Self {
            host: String::new(),
            port: "993".into(),
            username: String::new(),
            password: String::new(),
            scan_dir: String::new(),
            quarantine_dir: String::new(),
            executable: String::new(),
            parallel: "4".into(),
            backend: scanner::Backend::Defender,
            tls: config::Tls::Implicit,
            error: None,
        }
    }
}

impl State {
    pub fn update(&mut self, message: Message) -> Action<Instruction, Message> {
        match message {
            Message::Browse(kind) => {
                return Action {
                    instruction: None,
                    task: iced::Task::perform(pick(kind), move |path| Message::Picked(kind, path)),
                };
            }
            Message::Picked(kind, Some(path)) => {
                let path = path.to_string_lossy().into_owned();
                match kind {
                    Browse::Scan => self.scan_dir = path,
                    Browse::Quarantine => self.quarantine_dir = path,
                    Browse::Executable => self.executable = path,
                }
            }
            Message::Picked(_, None) => {}
            Message::Host(value) => self.host = value,
            Message::Port(value) => self.port = value,
            Message::Username(value) => self.username = value,
            Message::Password(value) => self.password = value,
            Message::ScanDir(value) => self.scan_dir = value,
            Message::QuarantineDir(value) => self.quarantine_dir = value,
            Message::Executable(value) => self.executable = value,
            Message::Parallel(value) => self.parallel = value,
            Message::Backend(value) => self.backend = value,
            Message::Tls(value) => {
                if self.port == "993" || self.port == "143" {
                    self.port = match value {
                        config::Tls::Implicit => "993",
                        config::Tls::StartTls => "143",
                    }
                    .into();
                }
                self.tls = value;
            }
            Message::Start => {
                let draft = config::Draft {
                    host: self.host.clone(),
                    port: self.port.clone(),
                    username: self.username.clone(),
                    password: self.password.clone(),
                    scan_dir: PathBuf::from(&self.scan_dir),
                    quarantine_dir: PathBuf::from(&self.quarantine_dir),
                    executable: (!self.executable.trim().is_empty())
                        .then(|| PathBuf::from(&self.executable)),
                    parallel: self.parallel.clone(),
                    backend: self.backend,
                    tls: self.tls,
                };
                match config::Settings::try_from(draft) {
                    Ok(settings) => {
                        return Action::instruction(Instruction::Begin(Arc::new(settings)));
                    }
                    Err(error) => self.error = Some(error.to_string()),
                }
            }
        }
        Action::none()
    }

    pub fn view(&self) -> Element<'_, Message> {
        let folders = column![
            text("1  Working folders").size(21),
            path_field(
                "Scan folder",
                &self.scan_dir,
                Message::ScanDir,
                Browse::Scan
            ),
            path_field(
                "Quarantine folder",
                &self.quarantine_dir,
                Message::QuarantineDir,
                Browse::Quarantine
            ),
        ]
        .spacing(12);
        let account = column![
            text("2  IMAP account").size(21),
            row![
                field("Server hostname", &self.host, Message::Host),
                field("Port", &self.port, Message::Port).width(120)
            ]
            .spacing(16),
            pick_list(
                [config::Tls::Implicit, config::Tls::StartTls],
                Some(self.tls),
                Message::Tls
            ),
            field("Username", &self.username, Message::Username),
            column![
                text("Password / app password"),
                text_input("", &self.password)
                    .secure(true)
                    .on_input(Message::Password)
                    .padding(10)
            ]
            .spacing(5),
        ]
        .spacing(12);
        let scanner = column![
            text("3  Scanner").size(21),
            row![
                pick_list(
                    [scanner::Backend::Defender, scanner::Backend::Avast],
                    Some(self.backend),
                    Message::Backend
                ),
                field("Parallel scans (1–16)", &self.parallel, Message::Parallel).width(180)
            ]
            .spacing(16),
            path_field(
                "Scanner executable (auto-detect if empty)",
                &self.executable,
                Message::Executable,
                Browse::Executable
            ),
        ]
        .spacing(12);
        let body =
            column![text("Mailbox Scanner").size(32), folders, account, scanner,].spacing(26);
        let mut footer = column![
            button("Start scan")
                .on_press(Message::Start)
                .padding([12, 24])
        ]
        .spacing(8);
        if let Some(error) = &self.error {
            footer = footer.push(text(error).color(iced::Color::from_rgb8(240, 100, 100)));
        }
        column![
            scrollable(
                container(container(body).max_width(850).padding(28)).center_x(Length::Fill)
            )
            .height(Length::Fill),
            container(
                container(footer)
                    .width(Length::Fill)
                    .max_width(850)
                    .padding([12, 28])
            )
            .center_x(Length::Fill),
        ]
        .height(Length::Fill)
        .into()
    }
}

fn field<'a>(
    label: &'a str,
    value: &'a str,
    message: fn(String) -> Message,
) -> iced::widget::Column<'a, Message> {
    column![
        text(label),
        text_input("", value).on_input(message).padding(10)
    ]
    .spacing(5)
    .width(Length::Fill)
}

fn path_field<'a>(
    label: &'a str,
    value: &'a str,
    message: fn(String) -> Message,
    kind: Browse,
) -> iced::widget::Column<'a, Message> {
    let controls = row![
        text_input("", value).on_input(message).padding(10),
        button("Browse…")
            .on_press(Message::Browse(kind))
            .padding(10)
    ]
    .spacing(8);
    column![text(label), controls]
        .spacing(5)
        .width(Length::Fill)
}

async fn pick(kind: Browse) -> Option<PathBuf> {
    #[cfg(windows)]
    {
        let dialog = rfd::AsyncFileDialog::new();
        let selected = match kind {
            Browse::Scan | Browse::Quarantine => dialog.pick_folder().await,
            Browse::Executable => dialog.add_filter("Executable", &["exe"]).pick_file().await,
        };
        selected.map(|file| file.path().to_path_buf())
    }
    #[cfg(not(windows))]
    {
        let _ = kind;
        None
    }
}
