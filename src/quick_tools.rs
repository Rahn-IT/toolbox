//! Select and run built-in Windows maintenance tools.

mod adwcleaner;
mod clear_chrome_default_extensions;
mod disable_hibernation;
mod set_power_config;
mod system;
mod temp_files;

use std::collections::BTreeSet;

use iced::{
    Element, Length, Task,
    widget::{button, checkbox, column, row, scrollable, text, text_input},
};

struct Tool {
    id: &'static str,
    name: &'static str,
    description: &'static str,
    run: fn() -> Result<String, String>,
}

const TOOLS: &[Tool] = &[
    Tool {
        id: "adwcleaner",
        name: "Run AdwCleaner",
        description: "Download AdwCleaner from Malwarebytes, launch it with administrator approval, and wait for it to close. The temporary download is removed afterward. Choose scanning and cleaning actions in AdwCleaner itself.",
        run: adwcleaner::run,
    },
    Tool {
        id: "clear-chrome-default-extensions",
        name: "Clear Chrome Default Extensions",
        description: "Permanently remove all three Chrome external-extension registry key trees and both Chrome policy key trees (HKLM and HKCU), including every value and subkey. This clears all Chrome policies, not just extension policies. Machine-wide keys may require running Toolbox as administrator. Each location is attempted even if another fails.",
        run: clear_chrome_default_extensions::run,
    },
    Tool {
        id: "disable-hibernation",
        name: "Disable hibernation",
        description: "Run powercfg -h off to disable Windows hibernation and Fast Startup and remove the hibernation file. Requires running Toolbox as administrator.",
        run: disable_hibernation::run,
    },
    Tool {
        id: "set-power-config",
        name: "Set Power Config",
        description: "Update the active power plan: on battery, turn off the display after 5 minutes and sleep after 15 minutes; when plugged in, turn off the display after 15 minutes and never sleep. Each setting is attempted even if another fails.",
        run: set_power_config::run,
    },
    Tool {
        id: "temp-files",
        name: "Delete old temporary files",
        description: "Permanently delete files older than 7 days directly in your temporary folder. Subfolders and links are left untouched. Locked or inaccessible files are skipped.",
        run: temp_files::run,
    },
];

/// Persistent selection and execution state for Quick Tools.
#[derive(Default)]
pub struct State {
    selected: BTreeSet<&'static str>,
    filter: String,
    phase: Phase,
    status: String,
}

#[derive(Default, PartialEq)]
enum Phase {
    #[default]
    Selection,
    Review,
    Running,
}

/// UI events and background execution results.
#[derive(Debug, Clone)]
pub enum Message {
    Toggle(&'static str, bool),
    Filter(String),
    Clear,
    Review,
    Cancel,
    Run,
    Finished(String),
}

impl State {
    /// Handle selection, review, and execution without blocking the UI.
    pub fn update(&mut self, message: Message) -> Task<Message> {
        if self.phase == Phase::Running {
            if let Message::Finished(status) = message {
                self.status = status;
                self.phase = Phase::Selection;
            }
            return Task::none();
        }
        match message {
            Message::Toggle(id, value) if self.phase == Phase::Selection => {
                if TOOLS.iter().any(|tool| tool.id == id) {
                    if value {
                        self.selected.insert(id);
                    } else {
                        self.selected.remove(id);
                    }
                }
            }
            Message::Filter(value) if self.phase == Phase::Selection => self.filter = value,
            Message::Clear if self.phase == Phase::Selection => self.selected.clear(),
            Message::Review if !self.selected.is_empty() => self.phase = Phase::Review,
            Message::Cancel => self.phase = Phase::Selection,
            Message::Run if self.phase == Phase::Review => {
                self.phase = Phase::Running;
                self.status = "Running selected tools...".into();
                let selected = self.selected.clone();
                return Task::perform(
                    async move {
                        tokio::task::spawn_blocking(move || {
                            TOOLS
                                .iter()
                                .filter(|tool| selected.contains(tool.id))
                                .map(|tool| match (tool.run)() {
                                    Ok(report) => format!("{}: {report}", tool.name),
                                    Err(error) => format!("{} failed: {error}", tool.name),
                                })
                                .collect::<Vec<_>>()
                                .join("\n")
                        })
                        .await
                        .unwrap_or_else(|error| format!("Tool execution failed: {error}"))
                    },
                    Message::Finished,
                );
            }
            _ => {}
        }
        Task::none()
    }

    /// Display the tool catalog or the selected actions awaiting confirmation.
    pub fn view(&self) -> Element<'_, Message> {
        if self.phase == Phase::Running {
            return column![text("Quick Tools").size(24), text(&self.status)]
                .spacing(12)
                .into();
        }
        if self.phase == Phase::Review {
            let tools = column(
                TOOLS
                    .iter()
                    .filter(|tool| self.selected.contains(tool.id))
                    .map(|tool| {
                        column![text(tool.name).size(18), text(tool.description)]
                            .spacing(6)
                            .into()
                    }),
            )
            .spacing(16);
            return column![
                text("Review selected tools").size(24),
                scrollable(tools).height(Length::Fill),
                text(format!(
                    "Temporary folder: {}",
                    std::env::temp_dir().display()
                )),
                row![
                    button("Run selected tools").on_press(Message::Run),
                    button("Cancel").on_press(Message::Cancel)
                ]
                .spacing(12),
            ]
            .spacing(12)
            .into();
        }
        let filter = self.filter.trim().to_ascii_lowercase();
        let tools: Vec<Element<'_, Message>> = TOOLS
            .iter()
            .filter(|tool| {
                format!("{} {}", tool.name, tool.description)
                    .to_ascii_lowercase()
                    .contains(&filter)
            })
            .map(|tool| {
                column![
                    checkbox(self.selected.contains(tool.id))
                        .label(tool.name)
                        .on_toggle(move |value| Message::Toggle(tool.id, value)),
                    text(tool.description)
                ]
                .spacing(6)
                .into()
            })
            .collect();
        let empty = tools.is_empty();
        column![
            text("Quick Tools").size(24),
            text("Select maintenance tools to run."),
            text_input("Filter tools...", &self.filter).on_input(Message::Filter),
            if empty {
                Element::from(text("No tools match the current filter."))
            } else {
                Element::from(scrollable(column(tools).spacing(16)).height(Length::Fill))
            },
            row![
                button(text(format!("Review selected ({})", self.selected.len())))
                    .on_press_maybe((!self.selected.is_empty()).then_some(Message::Review)),
                button("Deselect all").on_press(Message::Clear)
            ]
            .spacing(12),
            scrollable(text(&self.status)).height(120),
        ]
        .spacing(12)
        .into()
    }
}
