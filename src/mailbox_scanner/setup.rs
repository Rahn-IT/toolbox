//! Account and scan configuration screen.

use std::{path::PathBuf, sync::Arc};

use iced::{
    Element, Length,
    widget::{
        button, checkbox, column, container, pick_list, row, scrollable, slider, text, text_input,
    },
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
    parallel: String,
    scanner: Draft,
    picker_token: u64,
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
    EntireFiles(bool),
    Archives(bool),
    Heuristics(u8),
    Executable(String),
    Argument(usize, String),
    AddArgument,
    RemoveArgument(usize),
    CleanCode(String),
    DetectedCode(String),
    PickExecutable,
    ExecutablePicked(u64, Option<PathBuf>),
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

#[derive(Default)]
enum Draft {
    #[default]
    Defender,
    Avast(scanner::avast::Settings),
    Custom(Custom),
}

struct Custom {
    executable: String,
    picked: Option<PathBuf>,
    arguments: Vec<String>,
    clean_code: String,
    detected_code: String,
}

#[derive(Debug, thiserror::Error)]
enum Error {
    #[error("Enter a clean exit code between -2147483648 and 2147483647")]
    CleanCode,
    #[error("Enter a detected exit code between -2147483648 and 2147483647")]
    DetectedCode,
}

impl Default for Custom {
    fn default() -> Self {
        Self {
            executable: String::new(),
            picked: None,
            arguments: vec!["{file}".into()],
            clean_code: "0".into(),
            detected_code: "1".into(),
        }
    }
}

impl Draft {
    fn backend(&self) -> scanner::Backend {
        match self {
            Self::Defender => scanner::Backend::Defender,
            Self::Avast(_) => scanner::Backend::Avast,
            Self::Custom(_) => scanner::Backend::Custom,
        }
    }

    fn settings(&self) -> Result<scanner::Settings, Error> {
        Ok(match self {
            Self::Defender => scanner::Settings::Defender,
            Self::Avast(settings) => scanner::Settings::Avast(*settings),
            Self::Custom(draft) => scanner::Settings::Custom(scanner::custom::Settings {
                executable: draft
                    .picked
                    .clone()
                    .unwrap_or_else(|| PathBuf::from(&draft.executable)),
                arguments: draft.arguments.clone(),
                clean_code: draft
                    .clean_code
                    .trim()
                    .parse()
                    .map_err(|_| Error::CleanCode)?,
                detected_code: draft
                    .detected_code
                    .trim()
                    .parse()
                    .map_err(|_| Error::DetectedCode)?,
            }),
        })
    }
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
            parallel: "4".into(),
            scanner: Draft::default(),
            picker_token: 0,
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
                }
            }
            Message::Picked(_, None) => {}
            Message::Host(value) => self.host = value,
            Message::Port(value) => self.port = value,
            Message::Username(value) => self.username = value,
            Message::Password(value) => self.password = value,
            Message::ScanDir(value) => self.scan_dir = value,
            Message::QuarantineDir(value) => self.quarantine_dir = value,
            Message::EntireFiles(value) => {
                if let Draft::Avast(settings) = &mut self.scanner {
                    settings.entire_files = value;
                }
            }
            Message::Archives(value) => {
                if let Draft::Avast(settings) = &mut self.scanner {
                    settings.archives = value;
                }
            }
            Message::Heuristics(value) => {
                if let Draft::Avast(settings) = &mut self.scanner {
                    settings.heuristics = value;
                }
            }
            Message::Parallel(value) => self.parallel = value,
            Message::Executable(value) => {
                if let Draft::Custom(draft) = &mut self.scanner {
                    self.picker_token += 1;
                    draft.executable = value;
                    draft.picked = None;
                }
            }
            Message::Argument(index, value) => {
                if let Draft::Custom(draft) = &mut self.scanner
                    && let Some(argument) = draft.arguments.get_mut(index)
                {
                    *argument = value;
                }
            }
            Message::AddArgument => {
                if let Draft::Custom(draft) = &mut self.scanner {
                    draft.arguments.push(String::new());
                }
            }
            Message::RemoveArgument(index) => {
                if let Draft::Custom(draft) = &mut self.scanner
                    && index < draft.arguments.len()
                {
                    draft.arguments.remove(index);
                }
            }
            Message::CleanCode(value) => {
                if let Draft::Custom(draft) = &mut self.scanner {
                    draft.clean_code = value;
                }
            }
            Message::DetectedCode(value) => {
                if let Draft::Custom(draft) = &mut self.scanner {
                    draft.detected_code = value;
                }
            }
            Message::PickExecutable => {
                if matches!(self.scanner, Draft::Custom(_)) {
                    self.picker_token += 1;
                    let token = self.picker_token;
                    return Action {
                        instruction: None,
                        task: iced::Task::perform(
                            async {
                                #[cfg(windows)]
                                {
                                    rfd::AsyncFileDialog::new()
                                        .add_filter("Executable", &["exe"])
                                        .pick_file()
                                        .await
                                        .map(|file| file.path().to_path_buf())
                                }
                                #[cfg(not(windows))]
                                {
                                    None
                                }
                            },
                            move |path| Message::ExecutablePicked(token, path),
                        ),
                    };
                }
            }
            Message::ExecutablePicked(token, path) => {
                if token == self.picker_token
                    && let Draft::Custom(draft) = &mut self.scanner
                {
                    self.picker_token += 1;
                    if let Some(path) = path {
                        draft.executable = path.to_string_lossy().into_owned();
                        draft.picked = Some(path);
                    }
                }
            }
            Message::Backend(value) => {
                self.picker_token += 1;
                self.scanner = match value {
                    scanner::Backend::Defender => Draft::Defender,
                    scanner::Backend::Avast => Draft::Avast(scanner::avast::Settings::default()),
                    scanner::Backend::Custom => Draft::Custom(Custom::default()),
                };
                self.error = None;
            }
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
                let scanner = match self.scanner.settings() {
                    Ok(settings) => settings,
                    Err(error) => {
                        self.error = Some(error.to_string());
                        return Action::none();
                    }
                };
                let draft = config::Draft {
                    host: self.host.clone(),
                    port: self.port.clone(),
                    username: self.username.clone(),
                    password: self.password.clone(),
                    scan_dir: PathBuf::from(&self.scan_dir),
                    quarantine_dir: PathBuf::from(&self.quarantine_dir),
                    parallel: self.parallel.clone(),
                    scanner,
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
                    [
                        scanner::Backend::Defender,
                        scanner::Backend::Avast,
                        scanner::Backend::Custom
                    ],
                    Some(self.scanner.backend()),
                    Message::Backend
                ),
                field("Parallel scans (1–16)", &self.parallel, Message::Parallel).width(180)
            ]
            .spacing(16),
            self.scanner_view(),
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

    fn scanner_view(&self) -> Element<'_, Message> {
        match &self.scanner {
            Draft::Defender => text("Windows Defender is detected automatically. Files are scanned without remediation.").into(),
            Draft::Avast(settings) => column![
                text("Avast is detected automatically. All file types are scanned."),
                checkbox(settings.entire_files).label("Scan entire files").on_toggle(Message::EntireFiles),
                checkbox(settings.archives).label("Scan archives").on_toggle(Message::Archives),
                text(format!("Heuristic sensitivity: {}", settings.heuristics)),
                slider(0..=100, settings.heuristics, Message::Heuristics),
                text("Turning off entire-file or archive scanning reduces inspection coverage."),
            ].spacing(10).into(),
            Draft::Custom(draft) => {
                let arguments = column(draft.arguments.iter().enumerate().map(|(index, argument)| {
                    row![
                        text_input("Literal argument", argument).on_input(move |value| Message::Argument(index, value)).padding(10),
                        button("Remove").on_press(Message::RemoveArgument(index)).padding(10),
                    ].spacing(8).into()
                })).spacing(8);
                column![
                    text("Scanner executable (.exe)"),
                    row![
                        text_input("Absolute path to the scanner", &draft.executable).on_input(Message::Executable).padding(10),
                        button("Browse scanner...").on_press(Message::PickExecutable).padding(10),
                    ].spacing(8),
                    text("Arguments (one row per argument)"),
                    text("Use a separate {file} row for the input path. Do not add quotes around it; other rows are passed literally."),
                    arguments,
                    button("Add argument").on_press(Message::AddArgument).padding(10),
                    row![
                        field("Clean exit code", &draft.clean_code, Message::CleanCode),
                        field("Detected exit code", &draft.detected_code, Message::DetectedCode),
                    ].spacing(16),
                    text("Other exit codes or interrupted scans are reported as incomplete."),
                    text("Use a foreground CLI that stays open until scanning finishes. Configure it to scan all file types: it receives the original .eml and extracted .bin files."),
                    text("Choose non-remediating arguments. Toolbox cannot prevent a custom scanner from changing files or guarantee termination of processes it launches."),
                ].spacing(10).into()
            },
        }
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
        };
        selected.map(|file| file.path().to_path_buf())
    }
    #[cfg(not(windows))]
    {
        let _ = kind;
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn selecting_a_builtin_resets_its_settings_and_hides_other_controls() {
        let mut state = State::default();
        let _ = state.update(Message::Backend(scanner::Backend::Avast));
        let mut ui = iced_test::Simulator::with_size(
            iced::Settings::default(),
            (1180.0, 1000.0),
            state.view(),
        );
        assert!(ui.find("Heuristic sensitivity: 50").is_ok());
        assert!(
            ui.find("Scanner executable (auto-detect if empty)")
                .is_err()
        );
        ui.click("Scan archives").unwrap();
        let messages: Vec<_> = ui.into_messages().collect();
        for message in messages {
            let _ = state.update(message);
        }
        assert!(matches!(&state.scanner, Draft::Avast(settings) if !settings.archives));
        let _ = state.update(Message::Heuristics(100));
        let _ = state.update(Message::Backend(scanner::Backend::Defender));
        let _ = state.update(Message::Heuristics(0));
        assert!(matches!(state.scanner, Draft::Defender));
        let mut ui = iced_test::Simulator::with_size(
            iced::Settings::default(),
            (1180.0, 1000.0),
            state.view(),
        );
        assert!(ui.find("Scan archives").is_err());
        assert!(
            ui.find("Scanner executable (auto-detect if empty)")
                .is_err()
        );
        drop(ui);
        let _ = state.update(Message::Backend(scanner::Backend::Avast));
        assert!(
            matches!(&state.scanner, Draft::Avast(settings) if settings.heuristics == 50 && settings.archives && settings.entire_files)
        );
    }

    fn custom_state() -> State {
        let mut state = State {
            host: "imap.example.test".into(),
            username: "user".into(),
            password: "secret".into(),
            scan_dir: "scan".into(),
            quarantine_dir: "quarantine".into(),
            ..State::default()
        };
        let _ = state.update(Message::Backend(scanner::Backend::Custom));
        let _ = state.update(Message::Executable(
            std::env::current_exe()
                .unwrap()
                .to_string_lossy()
                .into_owned(),
        ));
        state
    }

    #[test]
    fn custom_controls_edit_argument_rows_and_reset_on_selection() {
        let mut state = State::default();
        let _ = state.update(Message::Backend(scanner::Backend::Custom));
        assert!(
            matches!(&state.scanner, Draft::Custom(draft) if draft.arguments == ["{file}"] && draft.clean_code == "0" && draft.detected_code == "1")
        );
        let mut ui = iced_test::Simulator::with_size(
            iced::Settings::default(),
            (1180.0, 1400.0),
            state.view(),
        );
        assert!(ui.find("Scanner executable (.exe)").is_ok());
        assert!(ui.find("Heuristic sensitivity: 50").is_err());
        ui.click("Add argument").unwrap();
        for message in ui.into_messages() {
            let _ = state.update(message);
        }
        let _ = state.update(Message::Argument(1, "  --literal=&\"value\"  ".into()));
        let _ = state.update(Message::Argument(99, "ignored".into()));
        let _ = state.update(Message::RemoveArgument(99));
        let _ = state.update(Message::CleanCode("5".into()));
        assert!(
            matches!(&state.scanner, Draft::Custom(draft) if draft.arguments[1] == "  --literal=&\"value\"  ")
        );
        let _ = state.update(Message::Backend(scanner::Backend::Defender));
        let _ = state.update(Message::Argument(0, "ignored".into()));
        let _ = state.update(Message::Backend(scanner::Backend::Custom));
        assert!(
            matches!(&state.scanner, Draft::Custom(draft) if draft.arguments == ["{file}"] && draft.clean_code == "0" && draft.executable.is_empty())
        );
    }

    #[test]
    fn invalid_custom_fields_prevent_start_and_valid_settings_are_snapshotted() {
        let mut state = custom_state();
        for message in [
            Message::CleanCode("".into()),
            Message::CleanCode("2147483648".into()),
        ] {
            let _ = state.update(message);
            assert!(state.update(Message::Start).instruction.is_none());
        }
        let _ = state.update(Message::CleanCode("0".into()));
        let _ = state.update(Message::DetectedCode("invalid".into()));
        assert!(state.update(Message::Start).instruction.is_none());
        let _ = state.update(Message::DetectedCode("0".into()));
        assert!(state.update(Message::Start).instruction.is_none());
        assert!(state.error.as_ref().unwrap().contains("different"));
        let _ = state.update(Message::DetectedCode(" 1 ".into()));
        for argument in ["", "--file={file}"] {
            let _ = state.update(Message::Argument(0, argument.into()));
            assert!(state.update(Message::Start).instruction.is_none());
        }
        let _ = state.update(Message::Argument(0, "{file}".into()));
        let _ = state.update(Message::AddArgument);
        let Instruction::Begin(settings) = state.update(Message::Start).instruction.unwrap();
        let _ = state.update(Message::Argument(1, "later edit".into()));
        assert!(
            matches!(settings.scanner(), scanner::Settings::Custom(custom) if custom.arguments == ["{file}", ""] && custom.clean_code == 0 && custom.detected_code == 1)
        );
        for executable in [
            "relative.exe".to_string(),
            std::env::current_dir()
                .unwrap()
                .join("scanner.cmd")
                .display()
                .to_string(),
        ] {
            let _ = state.update(Message::Executable(executable));
            assert!(state.update(Message::Start).instruction.is_none());
        }
    }

    #[test]
    fn stale_executable_picker_results_do_not_overwrite_newer_edits() {
        let mut state = custom_state();
        let _ = state.update(Message::PickExecutable);
        let first = state.picker_token;
        let _ = state.update(Message::Backend(scanner::Backend::Defender));
        let _ = state.update(Message::Backend(scanner::Backend::Custom));
        let _ = state.update(Message::ExecutablePicked(first, Some("old.exe".into())));
        assert!(matches!(&state.scanner, Draft::Custom(draft) if draft.executable.is_empty()));
        let _ = state.update(Message::PickExecutable);
        let first = state.picker_token;
        let _ = state.update(Message::PickExecutable);
        let second = state.picker_token;
        let _ = state.update(Message::ExecutablePicked(first, Some("old.exe".into())));
        let _ = state.update(Message::ExecutablePicked(second, Some("new.exe".into())));
        assert!(matches!(&state.scanner, Draft::Custom(draft) if draft.executable == "new.exe"));
        let _ = state.update(Message::PickExecutable);
        let old = state.picker_token;
        let _ = state.update(Message::Executable("manual.exe".into()));
        let _ = state.update(Message::ExecutablePicked(old, Some("old.exe".into())));
        let _ = state.update(Message::PickExecutable);
        let current = state.picker_token;
        let _ = state.update(Message::ExecutablePicked(current, None));
        assert!(
            matches!(&state.scanner, Draft::Custom(draft) if draft.executable == "manual.exe" && draft.picked.is_none())
        );
    }

    #[cfg(windows)]
    #[test]
    fn picked_executable_retains_native_path_until_manually_edited() {
        use std::{
            ffi::OsString,
            os::windows::ffi::{OsStrExt, OsStringExt},
        };
        let mut state = custom_state();
        let mut units: Vec<u16> = std::env::current_dir()
            .unwrap()
            .join("scanner-")
            .as_os_str()
            .encode_wide()
            .collect();
        units.push(0xd800);
        units.extend(".exe".encode_utf16());
        let path = PathBuf::from(OsString::from_wide(&units));
        let _ = state.update(Message::PickExecutable);
        let token = state.picker_token;
        let _ = state.update(Message::ExecutablePicked(token, Some(path.clone())));
        assert!(
            matches!(state.scanner.settings().unwrap(), scanner::Settings::Custom(settings) if settings.executable == path)
        );
        let _ = state.update(Message::Executable("manual.exe".into()));
        assert!(
            matches!(state.scanner.settings().unwrap(), scanner::Settings::Custom(settings) if settings.executable == std::path::Path::new("manual.exe"))
        );
    }

    #[test]
    #[ignore = "Renders synthetic setup variants for human layout review; no scanners run"]
    fn scanner_settings_layout_snapshots() {
        let directory = std::env::current_dir()
            .unwrap()
            .join("target/ui-snapshots/scanner-settings");
        for (name, backend) in [
            ("defender", scanner::Backend::Defender),
            ("avast", scanner::Backend::Avast),
            ("custom", scanner::Backend::Custom),
        ] {
            let mut state = State::default();
            let _ = state.update(Message::Backend(backend));
            let mut ui = iced_test::Simulator::with_size(
                iced::Settings::default(),
                (1150.0, 700.0),
                state.view(),
            );
            assert!(
                ui.snapshot(&iced::Theme::Dark)
                    .unwrap()
                    .matches_image(directory.join(format!("{name}-top.png")))
                    .unwrap()
            );
            ui.point_at((600.0, 350.0));
            let _ = ui.simulate([iced::Event::Mouse(iced::mouse::Event::WheelScrolled {
                delta: iced::mouse::ScrollDelta::Lines { x: 0.0, y: -100.0 },
            })]);
            assert!(
                ui.snapshot(&iced::Theme::Dark)
                    .unwrap()
                    .matches_image(directory.join(format!("{name}-settings.png")))
                    .unwrap()
            );
        }
        println!("Scanner settings snapshots: {}", directory.display());
    }
}
