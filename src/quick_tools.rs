//! Single-run Windows maintenance modules.

pub mod adwcleaner;
pub mod clear_default_extensions;
pub mod disable_hibernation;
pub mod set_power_config;
pub mod temp_files;

pub(crate) mod system;

use iced::{
    Element, Length, Task, Theme,
    widget::{column, container, scrollable, text},
};

use crate::{Module, OpenedModule, action::Action, tab_manager::TabMessage};

pub struct State {
    title: &'static str,
    status: Status,
}

enum Status {
    Running { closing: bool },
    Finished(Result<String, String>),
}

#[derive(Clone)]
pub enum Message {
    Finished(Result<String, String>),
}

fn start(title: &'static str, run: fn() -> Result<String, String>) -> OpenedModule {
    let state = State {
        title,
        status: Status::Running { closing: false },
    };
    let task = Task::perform(
        async move {
            tokio::task::spawn_blocking(run)
                .await
                .unwrap_or_else(|error| Err(format!("Tool execution failed: {error}")))
        },
        |result| TabMessage::QuickTool(Message::Finished(result)),
    );
    (Module::QuickTool(state), task)
}

impl State {
    pub fn title(&self) -> &'static str {
        self.title
    }

    pub fn is_closing(&self) -> bool {
        matches!(self.status, Status::Running { closing: true })
    }

    pub fn close(&mut self) -> Action<Message> {
        match &mut self.status {
            Status::Running { closing } => {
                *closing = true;
                Action::None
            }
            Status::Finished(_) => Action::Close,
        }
    }

    pub fn update(&mut self, message: Message) -> Action<Message> {
        match message {
            Message::Finished(result) if self.is_closing() => {
                self.status = Status::Finished(result);
                Action::Close
            }
            Message::Finished(result) => {
                self.status = Status::Finished(result);
                Action::None
            }
        }
    }

    pub fn view(&self) -> Element<'_, Message> {
        match &self.status {
            Status::Running { closing } => crate::loading::screen(
                Some(self.title),
                if *closing {
                    "Closing when the operation finishes…"
                } else {
                    "Running…"
                },
            ),
            Status::Finished(result) => {
                let (status, details) = match result {
                    Ok(details) => ("Completed", details),
                    Err(details) => ("Operation failed", details),
                };
                container(
                    column![
                        text(self.title).size(24),
                        text(status).style(move |theme: &Theme| {
                            let palette = theme.extended_palette();
                            text::Style {
                                color: Some(if result.is_ok() {
                                    palette.success.base.color
                                } else {
                                    palette.danger.base.color
                                }),
                            }
                        }),
                        scrollable(text(details)).height(Length::Fill),
                    ]
                    .spacing(12),
                )
                .width(Length::Fill)
                .padding(16)
                .into()
            }
        }
    }
}
