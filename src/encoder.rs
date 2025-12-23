use iced::{
    Length, Task,
    widget::{button, column, row, space, text_editor},
};

#[derive(Clone)]
pub enum Message {
    EncodedChanged(text_editor::Action),
    DecodedChanged(text_editor::Action),
    Encode,
    Decode,
}

pub struct Encoder {
    encoded: text_editor::Content,
    decoded: text_editor::Content,
    encode: fn(&str) -> String,
    decode: fn(&str) -> String,
}

impl Encoder {
    pub fn new(encode: fn(&str) -> String, decode: fn(&str) -> String) -> Self {
        Encoder {
            encoded: text_editor::Content::new(),
            decoded: text_editor::Content::new(),
            encode,
            decode,
        }
    }

    pub fn update(&mut self, message: Message) -> Task<Message> {
        match message {
            Message::EncodedChanged(action) => {
                self.encoded.perform(action);
                Task::none()
            }
            Message::DecodedChanged(action) => {
                self.decoded.perform(action);
                Task::none()
            }
            Message::Encode => {
                let decoded = self.decoded.text();
                let encoded = (self.encode)(&decoded);
                self.encoded = text_editor::Content::with_text(&encoded);
                Task::none()
            }
            Message::Decode => {
                let encoded = self.encoded.text();
                let decoded = (self.decode)(&encoded);
                self.decoded = text_editor::Content::with_text(&decoded);
                Task::none()
            }
        }
    }

    pub fn view<'a>(
        &'a self,
        description: impl Into<iced::Element<'a, Message>>,
    ) -> iced::Element<'a, Message> {
        column![
            description.into(),
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

    pub fn set_encoding(&mut self, encode: fn(&str) -> String, decode: fn(&str) -> String) {
        self.encode = encode;
        self.decode = decode;
    }
}
