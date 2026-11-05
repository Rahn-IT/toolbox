//! Mailbox scanning desktop application.
#![forbid(unsafe_code)]

pub mod core;
pub mod mailbox;
pub mod quarantine;
pub mod scanner;
pub mod workflow;

mod action;
mod scan;
mod setup;

use iced::{Element, Subscription, Task};

/// Application state and screen ownership.
#[derive(Default)]
pub struct App {
    setup: setup::State,
    scan: Option<Box<scan::State>>,
}

/// Messages are routed to their owning screen.
#[derive(Debug, Clone)]
pub enum Message {
    Setup(setup::Message),
    Scan(scan::Message),
    CloseRequested,
}

impl App {
    pub fn is_closing(&self) -> bool {
        self.scan.as_ref().is_some_and(|state| state.is_closing())
    }

    /// Development-only synthetic scan view for visual verification.
    #[cfg(test)]
    pub fn preview_scan() -> Self {
        Self {
            setup: setup::State::default(),
            scan: Some(Box::new(scan::State::preview())),
        }
    }
    /// Apply an event and forward screen tasks.
    pub fn update(&mut self, message: Message) -> Task<Message> {
        match message {
            Message::Setup(message) if self.scan.is_none() => {
                let action = self.setup.update(message);
                if let Some(setup::Instruction::Begin(settings)) = action.instruction {
                    let (state, task) = scan::State::new(settings);
                    self.scan = Some(Box::new(state));
                    return Task::batch([action.task.map(Message::Setup), task.map(Message::Scan)]);
                }
                action.task.map(Message::Setup)
            }
            Message::Scan(message) => {
                let Some(state) = &mut self.scan else {
                    return Task::none();
                };
                let action = state.update(message);
                match action.instruction {
                    Some(scan::Instruction::Back) => self.scan = None,
                    Some(scan::Instruction::Close) => return iced::exit(),
                    None => {}
                }
                action.task.map(Message::Scan)
            }
            Message::CloseRequested => {
                if self.scan.is_some() {
                    self.update(Message::Scan(scan::Message::CloseRequested))
                } else {
                    iced::exit()
                }
            }
            _ => Task::none(),
        }
    }

    /// Render the active screen.
    pub fn view(&self) -> Element<'_, Message> {
        match &self.scan {
            Some(state) => state.view().map(Message::Scan),
            None => self.setup.view().map(Message::Setup),
        }
    }

    /// Window close participates in cancellation and cleanup.
    pub fn subscription(&self) -> Subscription<Message> {
        iced::event::listen_with(|event, _, _| match event {
            iced::Event::Window(iced::window::Event::CloseRequested) => {
                Some(Message::CloseRequested)
            }
            _ => None,
        })
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
    fn headless_page_selection_uses_the_rendered_controls() {
        let mut app = App::preview_scan();
        let mut ui =
            iced_test::Simulator::with_size(iced::Settings::default(), (1180.0, 800.0), app.view());
        ui.click("Select page").unwrap();
        let messages: Vec<_> = ui.into_messages().collect();
        assert!(!messages.is_empty());
        for message in messages {
            let _ = app.update(message);
        }
        let mut ui =
            iced_test::Simulator::with_size(iced::Settings::default(), (1180.0, 800.0), app.view());
        assert!(ui.find("Download & purge selected (3)").is_ok());
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
