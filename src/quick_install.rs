mod chrome;
mod common;
mod firefox;
mod seven_zip;
mod windirstat;

use std::{collections::BTreeSet, future::Future, pin::Pin};

use iced::{
    Element, Length, Task,
    widget::{Column, button, checkbox, column, row, scrollable, text, text_input},
};

const INSTALLERS: &[&dyn Installer] = &[
    &firefox::INSTALLER,
    &chrome::INSTALLER,
    &seven_zip::INSTALLER,
    &windirstat::INSTALLER,
];

type InstallFuture<'a> = Pin<Box<dyn Future<Output = Result<(), String>> + Send + 'a>>;

pub trait Installer: Sync {
    fn id(&self) -> &'static str;
    fn name(&self) -> &'static str;
    fn install(&self) -> InstallFuture<'_>;
}

#[derive(Clone, Debug)]
pub enum Message {
    Toggled(&'static str, bool),
    FilterChanged(String),
    DeselectAll,
    InstallSelected,
    InstallFinished(InstallOutcome),
}

#[derive(Clone, Debug)]
pub struct InstallOutcome {
    succeeded: Vec<&'static str>,
    failed: Vec<(&'static str, String)>,
}

#[derive(Clone, Debug, Default)]
struct InstallSelection {
    selected: BTreeSet<&'static str>,
}

pub enum QuickInstall {
    Selection(Selection),
    Installing(Installing),
}

pub struct Selection {
    install_selection: InstallSelection,
    filter: String,
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
            filter: String::new(),
            status_message: None,
            install_success: false,
        })
    }

    pub fn update(&mut self, message: Message) -> Task<Message> {
        match message {
            Message::Toggled(installer_id, value) => match self {
                QuickInstall::Selection(selection) => {
                    selection.update(Message::Toggled(installer_id, value))
                }
                QuickInstall::Installing(_) => Task::none(),
            },
            Message::FilterChanged(filter) => match self {
                QuickInstall::Selection(selection) => selection.update(Message::FilterChanged(filter)),
                QuickInstall::Installing(_) => Task::none(),
            },
            Message::DeselectAll => match self {
                QuickInstall::Selection(selection) => {
                    selection.clear_selection();
                    Task::none()
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
                            filter: String::new(),
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
    pub fn update(&mut self, message: Message) -> Task<Message> {
        match message {
            Message::Toggled(installer_id, value) => {
                self.install_selection.set(installer_id, value);
            }
            Message::FilterChanged(filter) => {
                self.filter = filter;
            }
            Message::DeselectAll | Message::InstallSelected | Message::InstallFinished(_) => {}
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
        INSTALLERS
            .iter()
            .filter(|installer| self.install_selection.contains(installer.id()))
            .map(|installer| installer.name())
            .collect()
    }

    fn clear_selection(&mut self) {
        self.install_selection.clear();
    }

    pub fn view(&self) -> iced::Element<'_, Message> {
        let status = self
            .status_message
            .clone()
            .unwrap_or_else(|| "Select the applications to install.".to_string());

        let normalized_filter = self.filter.trim().to_ascii_lowercase();
        let installers: Vec<_> = if normalized_filter.is_empty() {
            INSTALLERS.to_vec()
        } else {
            INSTALLERS
                .into_iter()
                .filter(|installer| {
                    installer.name().contains(&normalized_filter)
                        || installer.id().contains(&normalized_filter)
                })
                .cloned()
                .collect()
        };

        let filter_empty = installers.is_empty();

        let installer_list = column(
            installers
                .into_iter()
                .map(|installer| {
                    let id = installer.id();
                    Element::from(
                        checkbox(self.install_selection.contains(id))
                            .label(installer.name())
                            .on_toggle(move |value| Message::Toggled(id, value)),
                    )
                })
                .collect::<Vec<Element<'_, Message>>>(),
        )
        .spacing(12);

        column![
            text("Quick Install").size(24),
            text("Selection").size(18),
            text_input("Filter applications...", &self.filter).on_input(Message::FilterChanged),
            if filter_empty {
                Element::from(text("No applications match the current filter."))
            } else {
                scrollable(installer_list).height(Length::Fill).into()
            },
            row![
                button("Deselect all").on_press_maybe(if self.install_selection.is_empty() {
                    None
                } else {
                    Some(Message::DeselectAll)
                }),
                button("Install selected").on_press_maybe(if self.install_selection.is_empty() {
                    None
                } else {
                    Some(Message::InstallSelected)
                })
            ]
            .spacing(12),
            if self.install_success {
                text(status).style(text::success)
            } else {
                text(status)
            }
        ]
        .spacing(12)
        .padding(20)
        .width(Length::Fill)
        .height(Length::Fill)
        .into()
    }
}

impl Installing {
    fn finish_install(self, outcome: InstallOutcome) -> Selection {
        let mut selection = Selection {
            install_selection: self.install_selection,
            filter: String::new(),
            status_message: None,
            install_success: false,
        };
        selection.finish_install(outcome);
        selection
    }

    fn view(&self) -> iced::Element<'_, Message> {
        Column::new()
            .spacing(12)
            .padding(20)
            .width(Length::Fill)
            .push(text("Quick Install").size(24))
            .push(text("Installing").size(18))
            .push(text(&self.status_message))
            .into()
    }
}

impl InstallSelection {
    fn contains(&self, installer_id: &'static str) -> bool {
        self.selected.contains(&installer_id)
    }

    fn clear(&mut self) {
        self.selected.clear();
    }

    fn set(&mut self, installer_id: &'static str, selected: bool) {
        if selected {
            self.selected.insert(installer_id);
        } else {
            self.selected.remove(&installer_id);
        }
    }

    fn is_empty(&self) -> bool {
        self.selected.is_empty()
    }
}

async fn run_installers(selection: InstallSelection) -> InstallOutcome {
    let mut outcome = InstallOutcome {
        succeeded: Vec::new(),
        failed: Vec::new(),
    };

    for installer in INSTALLERS {
        if !selection.contains(installer.id()) {
            continue;
        }

        match installer.install().await {
            Ok(()) => outcome.succeeded.push(installer.name()),
            Err(error) => outcome.failed.push((installer.name(), error)),
        }
    }

    outcome
}
