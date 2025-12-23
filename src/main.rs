use base64::{Engine, prelude::BASE64_STANDARD};
use std::fmt::Write;

use iced::{
    Length, Task,
    widget::{button, column, row, rule},
};

fn main() -> Result<(), iced::Error> {
    iced::application(UI::boot, UI::update, UI::view).run()
}

pub mod eml;
pub mod encoder;

struct UI {
    site: Site,
    encoder: encoder::Encoder,
}

pub enum Site {
    Home,
    Eml,
    Base64,
    Unicode,
}

#[derive(Clone)]
pub enum Message {
    SwitchToEml,
    SwitchToBase64,
    SwitchToUnicode,
    Encoder(encoder::Message),
}

impl UI {
    pub fn boot() -> Self {
        Self {
            site: Site::Home,
            encoder: encoder::Encoder::new(|str| str.to_string(), |str| str.to_string()),
        }
    }

    pub fn update(&mut self, message: Message) -> Task<Message> {
        match message {
            Message::SwitchToEml => {
                self.site = Site::Eml;
                self.encoder.set_encoding(eml::qp_encode, eml::qp_decode);
                Task::none()
            }
            Message::SwitchToBase64 => {
                self.site = Site::Base64;
                self.encoder.set_encoding(
                    |raw| BASE64_STANDARD.encode(raw),
                    |encoded| {
                        BASE64_STANDARD
                            .decode(encoded)
                            .map(|decoded| String::from_utf8_lossy(&decoded).to_string())
                            .unwrap_or_else(|err| err.to_string())
                    },
                );
                Task::none()
            }
            Message::SwitchToUnicode => {
                self.site = Site::Unicode;
                self.encoder.set_encoding(
                    |encoded| {
                        encoded.chars().fold(String::new(), |mut acc, c| {
                            if !acc.is_empty() {
                                acc.push(' ');
                            }
                            write!(acc, "{}", c as u32)
                                .expect("Writing to a string shouldn't fail");
                            acc
                        })
                    },
                    |decoded| {
                        decoded
                            .split_ascii_whitespace()
                            .filter_map(|number| {
                                let number = u32::from_str_radix(number, 10).ok()?;
                                char::from_u32(number)
                            })
                            .collect::<String>()
                    },
                );
                Task::none()
            }
            Message::Encoder(message) => self.encoder.update(message).map(Message::Encoder),
        }
    }

    pub fn view(&self) -> iced::Element<'_, Message> {
        row![
            iced::Element::from(
                column![
                    button("EML Encode").on_press(Message::SwitchToEml),
                    button("Base64 Encode").on_press(Message::SwitchToBase64),
                    button("Unicode Encode").on_press(Message::SwitchToUnicode)
                ]
                .spacing(10)
                .height(Length::Fill)
            ),
            rule::vertical(2),
            match self.site {
                Site::Home => "Toolbox".into(),
                Site::Eml => self
                    .encoder
                    .view("Encoder for qouted printable encoding in EML files")
                    .map(Message::Encoder),
                Site::Base64 => self.encoder.view("Base 64 Encoder").map(Message::Encoder),
                Site::Unicode => self.encoder.view("Unicode Encoder").map(Message::Encoder),
            }
        ]
        .spacing(20)
        .padding(20)
        .height(Length::Fill)
        .width(Length::Fill)
        .into()
    }
}
