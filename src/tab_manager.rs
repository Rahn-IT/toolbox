use std::collections::BTreeMap;

#[cfg(test)]
mod tests;

use iced::{
    Alignment, Border, Element, Length, Subscription, Task, Theme,
    keyboard::{self, Key, key::Named},
    widget::{button, column, container, row, rule, scrollable, text},
};

use crate::action::Action;
use crate::{
    Module, device_scan, encoder, mailbox_scanner, network_scanner, nut, path_length_checker,
    search, spelling_alphabet, wake_on_lan,
};
#[cfg(windows)]
use crate::{quick_install, quick_tools};

#[derive(Clone)]
pub enum Message {
    OpenSearch,
    SelectTab(usize),
    CloseTab(usize),
    Tab(usize, TabMessage),
    CloseRequested,
    LinkPressed(crate::Link),
}

#[derive(Clone)]
pub enum TabMessage {
    Search(search::Message),
    Encoder(encoder::Message),
    SpellingAlphabet(spelling_alphabet::Message),
    PathLengthChecker(path_length_checker::Message),
    Nut(nut::Message),
    WakeOnLan(wake_on_lan::Message),
    NetworkDevices(network_scanner::Message),
    DeviceScan(device_scan::Message),
    MailboxScanner(mailbox_scanner::Message),
    #[cfg(windows)]
    QuickInstall(quick_install::Message),
    #[cfg(windows)]
    QuickTool(quick_tools::Message),
}

/// Owns the open modules and tracks the selected tab.
pub struct TabManager {
    tabs: BTreeMap<usize, Module>,
    selected_tab: usize,
    next_tab: usize,
    selected_result: Option<usize>,
    window_close_tab: Option<usize>,
}

impl TabManager {
    pub fn update(&mut self, message: Message) -> Task<Message> {
        match message {
            Message::OpenSearch => {
                self.open_tab(Module::Search(String::new()));
                iced::widget::operation::focus(search::INPUT_ID)
            }
            Message::SelectTab(index) => {
                self.select_tab(index);
                Task::none()
            }
            Message::CloseTab(index) => {
                let Some(module) = self.tabs.get_mut(&index) else {
                    return Task::none();
                };
                let action = match module {
                    Module::MailboxScanner(state) => state.close().map(TabMessage::MailboxScanner),
                    Module::PathLengthChecker(state) => {
                        state.close().map(TabMessage::PathLengthChecker)
                    }
                    #[cfg(windows)]
                    Module::QuickInstall(state) => state.close().map(TabMessage::QuickInstall),
                    #[cfg(windows)]
                    Module::QuickTool(state) => state.close().map(TabMessage::QuickTool),
                    _ => Action::Close,
                };
                self.apply_action(index, action)
            }
            Message::Tab(index, message) => self.update_tab(index, message),
            Message::CloseRequested => {
                if self.window_close_tab.is_some() {
                    Task::none()
                } else {
                    self.close_window_from(0)
                }
            }
            Message::LinkPressed(link) => {
                link.open();
                Task::none()
            }
        }
    }

    pub fn view(&self) -> Element<'_, Message> {
        let tabs = row(self.tabs.iter().map(|(&index, module)| {
            let selected = index == self.selected_tab;
            let title = module.title();
            let label = module
                .close_status()
                .map_or_else(|| title.to_owned(), |status| format!("{title} · {status}"));
            let close = button(text("×").size(16).center())
                .width(28)
                .height(28)
                .padding(0)
                .style(close_button_style)
                .on_press(Message::CloseTab(index));
            button(
                row![text(label).size(14), close]
                    .spacing(8)
                    .align_y(Alignment::Center),
            )
            .padding(iced::Padding {
                top: 3.0,
                right: 4.0,
                bottom: 3.0,
                left: 12.0,
            })
            .style(move |theme, status| tab_style(theme, status, selected))
            .on_press(Message::SelectTab(index))
            .into()
        }))
        .spacing(6)
        .align_y(Alignment::Center)
        .push(
            button(text("+").size(19).center())
                .width(34)
                .height(34)
                .padding(0)
                .style(tab_button_style)
                .on_press(Message::OpenSearch),
        );
        let tab_bar = container(
            scrollable(tabs)
                .direction(scrollable::Direction::Horizontal(
                    scrollable::Scrollbar::new(),
                ))
                .width(Length::Fill),
        )
        .padding([8, 12])
        .style(|theme: &Theme| {
            let palette = theme.extended_palette();
            container::Style::default()
                .background(palette.background.weak.color)
                .color(palette.background.weak.text)
        });

        let selected_tab = self.selected_tab;
        let content = self.tabs[&selected_tab]
            .tab_view(self.selected_result)
            .map(move |message| Message::Tab(selected_tab, message));

        column![
            tab_bar,
            container(content)
                .width(Length::Fill)
                .height(Length::Fill)
                .padding(12),
            rule::horizontal(1),
            container(crate::footer().map(Message::LinkPressed))
                .width(Length::Fill)
                .padding([8, 12]),
        ]
        .into()
    }

    pub fn subscription(&self) -> Subscription<Message> {
        let close = iced::window::close_requests().map(|_| Message::CloseRequested);
        if matches!(&self.tabs[&self.selected_tab], Module::Search(_)) {
            let navigation = iced::event::listen_with(|event, _, _| {
                let iced::Event::Keyboard(keyboard::Event::KeyPressed { key, modifiers, .. }) =
                    event
                else {
                    return None;
                };
                if !modifiers.is_empty() {
                    return None;
                }
                match key {
                    Key::Named(Named::ArrowUp) => Some(search::Message::PreviousResult),
                    Key::Named(Named::ArrowDown) => Some(search::Message::NextResult),
                    Key::Named(Named::Enter) => Some(search::Message::Submit),
                    _ => None,
                }
            })
            .with(self.selected_tab)
            .map(|(index, message)| Message::Tab(index, TabMessage::Search(message)));
            Subscription::batch([close, navigation])
        } else {
            close
        }
    }

    fn select_tab(&mut self, index: usize) {
        if index == self.selected_tab || !self.tabs.contains_key(&index) {
            return;
        }
        if self.window_close_tab.is_some() {
            return;
        }
        if let Some(Module::PathLengthChecker(state)) = self.tabs.get_mut(&self.selected_tab) {
            state.cancel_scan();
        }
        self.selected_tab = index;
        self.selected_result = None;
    }

    fn open_tab(&mut self, module: Module) -> usize {
        let index = self.next_tab;
        self.next_tab += 1;
        self.tabs.insert(index, module);
        self.select_tab(index);
        index
    }

    fn close_tab(&mut self, index: usize) {
        self.tabs.remove(&index);
        if self.tabs.is_empty() {
            self.selected_result = None;
            self.selected_tab = self.next_tab;
            self.open_tab(Module::Search(String::new()));
        } else if index == self.selected_tab {
            self.selected_result = None;
            self.selected_tab = *self
                .tabs
                .range(index..)
                .next()
                .or_else(|| self.tabs.last_key_value())
                .expect("at least one tab remains")
                .0;
        }
    }

    fn mailbox_is_closing(&self, index: usize) -> bool {
        matches!(self.tabs.get(&index), Some(Module::MailboxScanner(state)) if state.is_closing())
    }

    fn close_window_from(&mut self, first_tab: usize) -> Task<Message> {
        let next = self.tabs.range(first_tab..).find_map(|(&index, module)| {
            matches!(module, Module::MailboxScanner(state) if state.has_scan()).then_some(index)
        });
        let Some(index) = next else {
            return iced::exit();
        };
        self.select_tab(index);
        self.window_close_tab = Some(index);
        self.update_tab(
            index,
            TabMessage::MailboxScanner(mailbox_scanner::Message::CloseRequested),
        )
    }

    fn update_tab(&mut self, index: usize, message: TabMessage) -> Task<Message> {
        let Some(module) = self.tabs.get_mut(&index) else {
            return Task::none();
        };
        let action = match (module, message) {
            (module, TabMessage::Search(message)) if index == self.selected_tab => {
                if let Module::Search(query) = module
                    && let Some((opened, task)) =
                        search::State::update_query(query, &mut self.selected_result, message)
                {
                    *module = opened;
                    self.selected_result = None;
                    return self.apply_action(index, Action::Task(task));
                }
                Action::None
            }
            (Module::Encoder(state), TabMessage::Encoder(message)) => {
                state.update(message).map(TabMessage::Encoder)
            }
            (Module::SpellingAlphabet(state), TabMessage::SpellingAlphabet(message)) => {
                state.update(message);
                Action::None
            }
            (Module::PathLengthChecker(state), TabMessage::PathLengthChecker(message)) => {
                state.update(message).map(TabMessage::PathLengthChecker)
            }
            (Module::Nut(state), TabMessage::Nut(message)) => {
                state.update(message).map(TabMessage::Nut)
            }
            (Module::WakeOnLan(state), TabMessage::WakeOnLan(message)) => {
                state.update(message).map(TabMessage::WakeOnLan)
            }
            (Module::NetworkDevices(state), TabMessage::NetworkDevices(message)) => {
                state.update(message).map(TabMessage::NetworkDevices)
            }
            (Module::DeviceScan(state), TabMessage::DeviceScan(message)) => {
                state.update(message).map(TabMessage::DeviceScan)
            }
            (Module::MailboxScanner(state), TabMessage::MailboxScanner(message)) => {
                state.update(message).map(TabMessage::MailboxScanner)
            }
            #[cfg(windows)]
            (Module::QuickInstall(state), TabMessage::QuickInstall(message)) => {
                state.update(message).map(TabMessage::QuickInstall)
            }
            #[cfg(windows)]
            (Module::QuickTool(state), TabMessage::QuickTool(message)) => {
                state.update(message).map(TabMessage::QuickTool)
            }
            _ => Action::None,
        };
        if self.window_close_tab == Some(index)
            && !matches!(&action, Action::Close)
            && !self.mailbox_is_closing(index)
        {
            self.window_close_tab = None;
        }
        self.apply_action(index, action)
    }

    fn apply_action(&mut self, index: usize, action: Action<TabMessage>) -> Task<Message> {
        match action {
            Action::None => Task::none(),
            Action::Focus => {
                self.select_tab(index);
                Task::none()
            }
            Action::Task(task) => task.map(move |message| Message::Tab(index, message)),
            Action::OpenModule((module, task)) => {
                let new_tab = self.open_tab(module);
                task.map(move |message| Message::Tab(new_tab, message))
            }
            Action::Close if self.window_close_tab == Some(index) => {
                self.window_close_tab = None;
                if let Some(Module::MailboxScanner(state)) = self.tabs.get_mut(&index) {
                    state.clear_close_request();
                }
                self.close_window_from(index + 1)
            }
            Action::Close => {
                let was_selected = index == self.selected_tab;
                self.close_tab(index);
                if was_selected && matches!(&self.tabs[&self.selected_tab], Module::Search(_)) {
                    iced::widget::operation::focus(search::INPUT_ID)
                } else {
                    Task::none()
                }
            }
        }
    }
}

fn tab_style(theme: &Theme, status: button::Status, selected: bool) -> button::Style {
    let palette = theme.extended_palette();
    let mut style = tab_button_style(theme, status);
    if selected && status == button::Status::Active {
        style.background = Some(palette.background.base.color.into());
    }
    style.border = Border {
        radius: 8.0.into(),
        width: if selected { 1.0 } else { 0.0 },
        color: palette.primary.base.color,
    };
    style
}

fn close_button_style(theme: &Theme, status: button::Status) -> button::Style {
    let mut style = tab_button_style(theme, status);
    if matches!(status, button::Status::Hovered | button::Status::Pressed) {
        let danger = theme.extended_palette().danger.base;
        style.background = Some(danger.color.into());
        style.text_color = danger.text;
    }
    style
}

fn tab_button_style(theme: &Theme, status: button::Status) -> button::Style {
    let mut style = button::text(theme, status);
    let palette = theme.extended_palette();
    style.text_color = palette.background.base.text;
    style.border.radius = 6.0.into();
    if matches!(status, button::Status::Hovered | button::Status::Pressed) {
        style.background = Some(palette.background.strong.color.into());
        style.text_color = palette.background.strong.text;
    }
    style
}

impl Module {
    fn close_status(&self) -> Option<&'static str> {
        match self {
            Self::MailboxScanner(state) => state.close_status(),
            Self::PathLengthChecker(state) if state.is_closing() => Some("Closing…"),
            #[cfg(windows)]
            Self::QuickInstall(state) if state.is_closing() => Some("Closing…"),
            #[cfg(windows)]
            Self::QuickTool(state) if state.is_closing() => Some("Closing…"),
            _ => None,
        }
    }

    pub fn title(&self) -> &str {
        match self {
            Self::Search(_) => search::State::TITLE,
            Self::Encoder(state) => state.title(),
            Self::SpellingAlphabet(_) => spelling_alphabet::State::TITLE,
            Self::PathLengthChecker(_) => path_length_checker::PathLengthChecker::TITLE,
            Self::Nut(_) => nut::Nut::TITLE,
            Self::WakeOnLan(_) => wake_on_lan::State::TITLE,
            Self::NetworkDevices(_) => network_scanner::State::TITLE,
            Self::DeviceScan(state) => state.title(),
            Self::MailboxScanner(_) => mailbox_scanner::App::TITLE,
            #[cfg(windows)]
            Self::QuickInstall(_) => quick_install::QuickInstall::TITLE,
            #[cfg(windows)]
            Self::QuickTool(state) => state.title(),
        }
    }

    fn tab_view(&self, selected_result: Option<usize>) -> Element<'_, TabMessage> {
        match self {
            Self::Search(query) => {
                search::State::view_query(query, selected_result).map(TabMessage::Search)
            }
            Self::Encoder(state) => state.view().map(TabMessage::Encoder),
            Self::SpellingAlphabet(state) => state.view().map(TabMessage::SpellingAlphabet),
            Self::PathLengthChecker(state) => state.view().map(TabMessage::PathLengthChecker),
            Self::Nut(state) => state.view().map(TabMessage::Nut),
            Self::WakeOnLan(state) => state.view().map(TabMessage::WakeOnLan),
            Self::NetworkDevices(state) => state.view().map(TabMessage::NetworkDevices),
            Self::DeviceScan(state) => state.view().map(TabMessage::DeviceScan),
            Self::MailboxScanner(state) => state.view().map(TabMessage::MailboxScanner),
            #[cfg(windows)]
            Self::QuickInstall(state) => state.view().map(TabMessage::QuickInstall),
            #[cfg(windows)]
            Self::QuickTool(state) => state.view().map(TabMessage::QuickTool),
        }
    }
}

impl Default for TabManager {
    fn default() -> Self {
        Self {
            tabs: BTreeMap::from([(0, Module::Search(String::new()))]),
            selected_tab: 0,
            next_tab: 1,
            selected_result: None,
            window_close_tab: None,
        }
    }
}
