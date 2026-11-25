//! Mailbox scanning desktop application.
#![forbid(unsafe_code)]

pub mod batch;
pub mod core;
pub mod mailbox;
pub mod quarantine;
pub mod scanner;
mod worker;
pub mod workflow;

mod action;
mod scan;
mod setup;

use iced::{Element, Task};

use crate::action::Action;

/// Application state and screen ownership.
#[derive(Default)]
pub struct App {
    setup: setup::State,
    scan: Option<Box<scan::State>>,
    confirm_abort: bool,
}

/// Messages are routed to their owning screen.
#[derive(Debug, Clone)]
pub enum Message {
    Setup(setup::Message),
    Scan(scan::Message),
    CloseRequested,
    ConfirmAbort,
    KeepScanning,
}

impl App {
    pub const TITLE: &'static str = "Mailbox Scanner";

    pub fn new() -> crate::OpenedModule {
        (crate::Module::MailboxScanner(Self::default()), Task::none())
    }

    pub fn is_closing(&self) -> bool {
        self.scan.as_ref().is_some_and(|state| state.is_closing())
    }

    pub(crate) fn has_scan(&self) -> bool {
        self.scan.is_some()
    }

    pub(crate) fn close_status(&self) -> Option<&'static str> {
        if self.confirm_abort
            || self
                .scan
                .as_ref()
                .is_some_and(|state| state.is_reviewing_close())
        {
            Some("Review to close")
        } else if self.is_closing() {
            Some("Closing…")
        } else {
            None
        }
    }

    pub fn close(&mut self) -> Action<Message> {
        if self.is_closing() {
            return if self
                .scan
                .as_ref()
                .is_some_and(|state| state.is_reviewing_close())
            {
                Action::Focus
            } else {
                Action::None
            };
        }
        if self.scan.as_ref().is_some_and(|state| state.busy()) {
            self.confirm_abort = true;
            Action::Focus
        } else {
            self.update(Message::CloseRequested)
        }
    }

    pub(crate) fn clear_close_request(&mut self) {
        if let Some(state) = &mut self.scan {
            state.clear_close_request();
        }
    }

    /// Development-only synthetic scan view for visual verification.
    #[cfg(test)]
    pub fn preview_scan() -> Self {
        Self {
            setup: setup::State::default(),
            scan: Some(Box::new(scan::State::preview())),
            confirm_abort: false,
        }
    }
    /// Apply an event and forward screen tasks.
    pub fn update(&mut self, message: Message) -> Action<Message> {
        match message {
            Message::Setup(message) if self.scan.is_none() => {
                let action = self.setup.update(message);
                if let Some(setup::Instruction::Begin(settings)) = action.instruction {
                    let (state, task) = scan::State::new(settings);
                    self.scan = Some(Box::new(state));
                    return Action::Task(Task::batch([
                        action.task.map(Message::Setup),
                        task.map(Message::Scan),
                    ]));
                }
                Action::Task(action.task.map(Message::Setup))
            }
            Message::Scan(message) => {
                let Some(state) = &mut self.scan else {
                    return Action::None;
                };
                let was_reviewing = state.is_reviewing_close();
                let action = state.update(message);
                match action.instruction {
                    Some(scan::Instruction::Back) => self.scan = None,
                    Some(scan::Instruction::Close) => return Action::Close,
                    None if !was_reviewing && state.is_reviewing_close() => return Action::Focus,
                    None => {}
                }
                Action::Task(action.task.map(Message::Scan))
            }
            Message::CloseRequested | Message::ConfirmAbort
                if matches!(message, Message::CloseRequested) || self.confirm_abort =>
            {
                self.confirm_abort = false;
                if self.scan.is_some() {
                    self.update(Message::Scan(scan::Message::CloseRequested))
                } else {
                    Action::Close
                }
            }
            Message::KeepScanning => {
                self.confirm_abort = false;
                Action::None
            }
            _ => Action::None,
        }
    }

    /// Render the active screen.
    pub fn view(&self) -> Element<'_, Message> {
        if self.confirm_abort {
            use iced::{
                Length,
                widget::{button, column, container, row, text},
            };

            let dialog = container(column![
                text("Abort the current scan?").size(22),
                text("Mailbox Scanner will stop its current work and finish cleanup before closing."),
                row![
                    button("Keep tab open").on_press(Message::KeepScanning),
                    button("Abort and close").style(button::danger).on_press(Message::ConfirmAbort),
                ].spacing(10),
            ].spacing(12))
            .padding(20)
            .max_width(460)
            .style(container::bordered_box);
            return container(dialog).center(Length::Fill).into();
        }
        match &self.scan {
            Some(state) => state.view().map(Message::Scan),
            None => self.setup.view().map(Message::Setup),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn headless_start_validation_stays_on_setup() {
        let mut app = App::default();
        let mut ui =
            iced_test::Simulator::with_size(iced::Settings::default(), (1180.0, 800.0), app.view());
        ui.click("Start scan").unwrap();
        let messages: Vec<_> = ui.into_messages().collect();
        assert!(!messages.is_empty());
        for message in messages {
            let _ = app.update(message);
        }
        assert!(app.scan.is_none());
        let mut ui =
            iced_test::Simulator::with_size(iced::Settings::default(), (1180.0, 800.0), app.view());
        assert!(
            ui.find(core::config::Error::Host.to_string().as_str())
                .is_ok()
        );
    }

    #[test]
    fn headless_purge_all_uses_the_rendered_control() {
        let mut app = App::preview_scan();
        let mut ui =
            iced_test::Simulator::with_size(iced::Settings::default(), (1180.0, 800.0), app.view());
        assert!(ui.find("Select page").is_err());
        ui.click("Download & purge all (3)").unwrap();
        let messages: Vec<_> = ui.into_messages().collect();
        assert!(!messages.is_empty());
        for message in messages {
            let _ = app.update(message);
        }
        let mut ui =
            iced_test::Simulator::with_size(iced::Settings::default(), (1180.0, 800.0), app.view());
        assert!(ui.find("Preserving and purging… 2 queued").is_ok());
    }

    #[test]
    #[ignore = "Renders offscreen PNGs for human layout review"]
    fn headless_layout_snapshots() {
        let stamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let directory = std::path::PathBuf::from("target/ui-snapshots").join(stamp.to_string());
        let setup = App::default();
        let scan = App::preview_scan();
        for (name, app, size) in [
            ("setup", &setup, (1180.0, 800.0)),
            ("scan", &scan, (1180.0, 800.0)),
            ("scan-compact", &scan, (900.0, 600.0)),
        ] {
            let mut ui =
                iced_test::Simulator::with_size(iced::Settings::default(), size, app.view());
            let snapshot = ui.snapshot(&iced::Theme::Dark).unwrap();
            assert!(
                snapshot
                    .matches_image(directory.join(format!("{name}.png")))
                    .unwrap()
            );
        }
        println!("Headless snapshots: {}", directory.display());
    }
}
