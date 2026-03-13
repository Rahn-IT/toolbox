mod common;
mod chrome;
mod firefox;
mod seven_zip;

use iced::{
    Length, Task,
    widget::{button, checkbox, column, text},
};

#[derive(Clone, Debug)]
pub enum Message {
    Selection(SelectionMessage),
    InstallSelected,
    InstallFinished(InstallOutcome),
}

#[derive(Clone, Debug)]
pub enum SelectionMessage {
    FirefoxToggled(bool),
    ChromeToggled(bool),
    SevenZipToggled(bool),
}

#[derive(Clone, Debug)]
pub struct InstallOutcome {
    succeeded: Vec<&'static str>,
    failed: Vec<(&'static str, String)>,
}

#[derive(Clone, Debug, Default)]
struct InstallSelection {
    firefox: bool,
    chrome: bool,
    seven_zip: bool,
}

pub enum QuickInstall {
    Selection(Selection),
    Installing(Installing),
}

pub struct Selection {
    install_selection: InstallSelection,
    status_message: Option<String>,
    install_success: bool,
}

pub struct Installing {
    install_selection: InstallSelection,
    status_message: String,
}

impl QuickInstall {
    pub fn new() -> Self {
        Self::Selection(Selection {
            install_selection: InstallSelection::default(),
            status_message: None,
            install_success: false,
        })
    }

    pub fn update(&mut self, message: Message) -> Task<Message> {
        match message {
            Message::Selection(message) => match self {
                QuickInstall::Selection(selection) => {
                    selection.update(message).map(Message::Selection)
                }
                QuickInstall::Installing(_) => Task::none(),
            },
            Message::InstallSelected => self.install_selected(),
            Message::InstallFinished(outcome) => match self {
                QuickInstall::Selection(selection) => {
                    selection.finish_install(outcome);
                    Task::none()
                }
                QuickInstall::Installing(_) => {
                    let previous = std::mem::replace(
                        self,
                        QuickInstall::Selection(Selection {
                            install_selection: InstallSelection::default(),
                            status_message: None,
                            install_success: false,
                        }),
                    );

                    if let QuickInstall::Installing(installing) = previous {
                        *self = QuickInstall::Selection(installing.finish_install(outcome));
                    }

                    Task::none()
                }
            },
        }
    }

    pub fn view(&self) -> iced::Element<'_, Message> {
        match self {
            QuickInstall::Selection(selection) => selection.view(),
            QuickInstall::Installing(installing) => installing.view(),
        }
    }

    fn install_selected(&mut self) -> Task<Message> {
        let QuickInstall::Selection(selection) = self else {
            return Task::none();
        };

        let selected = selection.selected_installers();

        if selected.is_empty() {
            selection.install_success = false;
            selection.status_message = Some("Select at least one application.".to_string());
            return Task::none();
        }

        let install_selection = selection.install_selection.clone();
        let status_message = format!("Installing {}...", selected.join(", "));

        *self = QuickInstall::Installing(Installing {
            install_selection: install_selection.clone(),
            status_message,
        });

        Task::perform(run_installers(install_selection), Message::InstallFinished)
    }
}

impl Selection {
    pub fn update(&mut self, message: SelectionMessage) -> Task<SelectionMessage> {
        match message {
            SelectionMessage::FirefoxToggled(value) => self.install_selection.firefox = value,
            SelectionMessage::ChromeToggled(value) => self.install_selection.chrome = value,
            SelectionMessage::SevenZipToggled(value) => self.install_selection.seven_zip = value,
        }

        Task::none()
    }

    fn finish_install(&mut self, outcome: InstallOutcome) {
        if outcome.failed.is_empty() {
            self.install_success = true;
            self.status_message = Some(format!("Installed: {}", outcome.succeeded.join(", ")));
            return;
        }

        self.install_success = false;

        let mut lines = Vec::new();
        if !outcome.succeeded.is_empty() {
            lines.push(format!("Installed: {}", outcome.succeeded.join(", ")));
        }

        let failures = outcome
            .failed
            .into_iter()
            .map(|(name, error)| format!("{name}: {error}"))
            .collect::<Vec<_>>()
            .join(" | ");
        lines.push(format!("Failed: {failures}"));
        self.status_message = Some(lines.join("\n"));
    }

    fn selected_installers(&self) -> Vec<&'static str> {
        let mut selected = Vec::new();

        if self.install_selection.firefox {
            selected.push("Firefox");
        }
        if self.install_selection.chrome {
            selected.push("Chrome");
        }
        if self.install_selection.seven_zip {
            selected.push("7-Zip");
        }

        selected
    }

    pub fn view(&self) -> iced::Element<'_, Message> {
        let status = self
            .status_message
            .clone()
            .unwrap_or_else(|| "Select the applications to install.".to_string());

        column![
            text("Quick Install").size(24),
            text("Selection").size(18),
            checkbox(self.install_selection.firefox)
                .label("Firefox")
                .on_toggle(|value| Message::Selection(SelectionMessage::FirefoxToggled(value))),
            checkbox(self.install_selection.chrome)
                .label("Chrome")
                .on_toggle(|value| Message::Selection(SelectionMessage::ChromeToggled(value))),
            checkbox(self.install_selection.seven_zip)
                .label("7-Zip")
                .on_toggle(|value| Message::Selection(SelectionMessage::SevenZipToggled(value))),
            button("Install selected").on_press(Message::InstallSelected),
            if self.install_success {
                text(status).style(text::success)
            } else {
                text(status)
            },
        ]
        .spacing(12)
        .padding(20)
        .width(Length::Fill)
        .into()
    }
}

impl Installing {
    fn finish_install(self, outcome: InstallOutcome) -> Selection {
        let mut selection = Selection {
            install_selection: self.install_selection,
            status_message: None,
            install_success: false,
        };
        selection.finish_install(outcome);
        selection
    }

    fn view(&self) -> iced::Element<'_, Message> {
        column![
            text("Quick Install").size(24),
            text("Installing").size(18),
            text(&self.status_message),
        ]
        .spacing(12)
        .padding(20)
        .width(Length::Fill)
        .into()
    }
}

async fn run_installers(selection: InstallSelection) -> InstallOutcome {
    let mut outcome = InstallOutcome {
        succeeded: Vec::new(),
        failed: Vec::new(),
    };

    if selection.firefox {
        match firefox::install().await {
            Ok(()) => outcome.succeeded.push("Firefox"),
            Err(error) => outcome.failed.push(("Firefox", error)),
        }
    }

    if selection.chrome {
        match chrome::install().await {
            Ok(()) => outcome.succeeded.push("Chrome"),
            Err(error) => outcome.failed.push(("Chrome", error)),
        }
    }

    if selection.seven_zip {
        match seven_zip::install().await {
            Ok(()) => outcome.succeeded.push("7-Zip"),
            Err(error) => outcome.failed.push(("7-Zip", error)),
        }
    }

    outcome
}
