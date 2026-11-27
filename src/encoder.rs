use std::fmt;

use base64::{Engine, prelude::BASE64_STANDARD};
use iced::{
    Alignment, Length,
    widget::{button, column, pick_list, row, space, text, text_editor},
};

use crate::{action::Action, eml};

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Encoding {
    Eml,
    Base64,
    Unicode,
}

impl Encoding {
    const ALL: [Self; 3] = [Self::Eml, Self::Base64, Self::Unicode];

    pub const fn title(self) -> &'static str {
        match self {
            Self::Eml => "EML Encoder",
            Self::Base64 => "Base64 Encoder",
            Self::Unicode => "Unicode Encoder",
        }
    }

    fn description(self) -> &'static str {
        match self {
            Self::Eml => "Quoted-printable encoding for EML files",
            Self::Base64 => "Base64 encoding",
            Self::Unicode => "Unicode code points in decimal",
        }
    }

    fn encode(self, raw: &str) -> String {
        match self {
            Self::Eml => eml::qp_encode(raw),
            Self::Base64 => BASE64_STANDARD.encode(raw),
            Self::Unicode => raw
                .chars()
                .map(|character| (character as u32).to_string())
                .collect::<Vec<_>>()
                .join(" "),
        }
    }

    fn decode(self, encoded: &str) -> String {
        match self {
            Self::Eml => eml::qp_decode(encoded),
            Self::Base64 => BASE64_STANDARD
                .decode(encoded)
                .map(|decoded| String::from_utf8_lossy(&decoded).into_owned())
                .unwrap_or_else(|err| err.to_string()),
            Self::Unicode => encoded
                .split_ascii_whitespace()
                .filter_map(|number| char::from_u32(number.parse().ok()?))
                .collect(),
        }
    }
}

impl fmt::Display for Encoding {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Eml => "EML (quoted-printable)",
            Self::Base64 => "Base64",
            Self::Unicode => "Unicode",
        })
    }
}

#[derive(Clone)]
pub enum Message {
    EncodingChanged(Encoding),
    EncodedChanged(text_editor::Action),
    DecodedChanged(text_editor::Action),
    Encode,
    Decode,
}

pub struct Encoder {
    encoded: text_editor::Content,
    decoded: text_editor::Content,
    encoding: Encoding,
}

impl Encoder {
    pub fn new(encoding: Encoding) -> crate::OpenedModule {
        let state = Self {
            encoded: text_editor::Content::new(),
            decoded: text_editor::Content::new(),
            encoding,
        };
        (crate::Module::Encoder(state), iced::Task::none())
    }

    pub fn title(&self) -> &'static str {
        self.encoding.title()
    }

    pub fn update(&mut self, message: Message) -> Action<Message> {
        match message {
            Message::EncodingChanged(encoding) => {
                self.encoding = encoding;
                Action::None
            }
            Message::EncodedChanged(action) => {
                self.encoded.perform(action);
                Action::None
            }
            Message::DecodedChanged(action) => {
                self.decoded.perform(action);
                Action::None
            }
            Message::Encode => {
                let decoded = self.decoded.text();
                let encoded = self.encoding.encode(&decoded);
                self.encoded = text_editor::Content::with_text(&encoded);
                Action::None
            }
            Message::Decode => {
                let encoded = self.encoded.text();
                let decoded = self.encoding.decode(&encoded);
                self.decoded = text_editor::Content::with_text(&decoded);
                Action::None
            }
        }
    }

    pub fn view(&self) -> iced::Element<'_, Message> {
        column![
            row![
                text(self.encoding.description()),
                space::horizontal(),
                pick_list(Encoding::ALL, Some(self.encoding), Message::EncodingChanged).width(200),
            ]
            .spacing(12)
            .align_y(Alignment::Center),
            text_editor(&self.encoded)
                .font(iced::Font::MONOSPACE)
                .placeholder("Encoded")
                .on_action(Message::EncodedChanged)
                .height(Length::Fill),
            row![
                button("Encode ↑").on_press(Message::Encode),
                space::horizontal(),
                button("Decode ↓").on_press(Message::Decode),
            ],
            text_editor(&self.decoded)
                .font(iced::Font::MONOSPACE)
                .placeholder("Decoded")
                .on_action(Message::DecodedChanged)
                .height(Length::Fill)
        ]
        .spacing(10)
        .into()
    }
}
