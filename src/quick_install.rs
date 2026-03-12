use iced::{
    Length, Task,
    widget::{checkbox, column, text},
};

#[derive(Clone, Debug)]
pub enum Message {
    Selection(SelectionMessage),
}

#[derive(Clone, Debug)]
pub enum SelectionMessage {
    FirefoxToggled(bool),
    ChromeToggled(bool),
    SevenZipToggled(bool),
}

pub enum QuickInstall {
    Selection(Selection),
}

pub struct Selection {
    firefox: bool,
    chrome: bool,
    seven_zip: bool,
}

impl QuickInstall {
    pub fn new() -> Self {
        Self::Selection(Selection {
            firefox: false,
            chrome: false,
            seven_zip: false,
        })
    }

    pub fn update(&mut self, message: Message) -> Task<Message> {
        match message {
            Message::Selection(message) => match self {
                QuickInstall::Selection(selection) => {
                    selection.update(message).map(Message::Selection)
                }
            },
        }
    }

    pub fn view(&self) -> iced::Element<'_, Message> {
        match self {
            QuickInstall::Selection(selection) => selection.view().map(Message::Selection),
        }
    }
}

impl Selection {
    pub fn update(&mut self, message: SelectionMessage) -> Task<SelectionMessage> {
        match message {
            SelectionMessage::FirefoxToggled(value) => self.firefox = value,
            SelectionMessage::ChromeToggled(value) => self.chrome = value,
            SelectionMessage::SevenZipToggled(value) => self.seven_zip = value,
        }

        Task::none()
    }

    pub fn view(&self) -> iced::Element<'_, SelectionMessage> {
        column![
            text("Quick Install").size(24),
            text("Selection").size(18),
            checkbox(self.firefox)
                .label("Firefox")
                .on_toggle(SelectionMessage::FirefoxToggled),
            checkbox(self.chrome)
                .label("Chrome")
                .on_toggle(SelectionMessage::ChromeToggled),
            checkbox(self.seven_zip)
                .label("7-Zip")
                .on_toggle(SelectionMessage::SevenZipToggled),
        ]
        .spacing(12)
        .padding(20)
        .width(Length::Fill)
        .into()
    }
}
