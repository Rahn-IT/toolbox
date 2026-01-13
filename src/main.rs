#![windows_subsystem = "windows"]

use base64::{Engine, prelude::BASE64_STANDARD};
use std::fmt::Write;

use iced::{
    Font, Length, Task,
    alignment::Vertical,
    widget::{button, column, row, rule},
};

fn main() -> Result<(), iced::Error> {
    iced::application(UI::boot, UI::update, UI::view).run()
}

pub mod eml;
pub mod encoder;
pub mod path_length_checker;

struct UI {
    site: Site,
    encoder: encoder::Encoder,
    path_length_checker: path_length_checker::PathLengthChecker,
}

#[derive(Clone)]
pub enum Site {
    Home,
    Eml,
    Base64,
    Unicode,
    PathLengthChecker,
}

#[derive(Clone)]
pub enum Message {
    LinkPressed(Link),
    SwitchSite(Site),
    Encoder(encoder::Message),
    PathLengthChecker(path_length_checker::Message),
}

impl UI {
    pub fn boot() -> Self {
        Self {
            site: Site::Home,
            encoder: encoder::Encoder::new(|str| str.to_string(), |str| str.to_string()),
            path_length_checker: path_length_checker::PathLengthChecker::new(),
        }
    }

    pub fn update(&mut self, message: Message) -> Task<Message> {
        match message {
            Message::LinkPressed(link) => {
                let _ = open::that_in_background(match link {
                    Link::Rust => "https://rust-lang.org",
                    Link::Iced => "https://iced.rs",
                    Link::RahnIT => "https://it-rahn.de",
                });

                Task::none()
            }
            Message::SwitchSite(site) => {
                self.site = site.clone();

                self.path_length_checker.cancel_scan();
                match site {
                    Site::Eml => {
                        self.site = Site::Eml;
                        self.encoder.set_encoding(eml::qp_encode, eml::qp_decode);
                        Task::none()
                    }
                    Site::Base64 => {
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
                    Site::Unicode => {
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
                    Site::Home | Site::PathLengthChecker => Task::none(),
                }
            }
            Message::Encoder(message) => self.encoder.update(message).map(Message::Encoder),
            Message::PathLengthChecker(message) => self
                .path_length_checker
                .update(message)
                .map(Message::PathLengthChecker),
        }
    }

    pub fn view(&self) -> iced::Element<'_, Message> {
        column![
            row![
                iced::Element::from(
                    column![
                        button("EML Encode").on_press(Site::Eml),
                        button("Base64 Encode").on_press(Site::Base64),
                        button("Unicode Encode").on_press(Site::Unicode),
                        button("Path Length Checker").on_press(Site::PathLengthChecker)
                    ]
                    .spacing(10)
                    .height(Length::Fill)
                )
                .map(Message::SwitchSite),
                rule::vertical(2),
                match self.site {
                    Site::Home => "Toolbox".into(),
                    Site::Eml => self
                        .encoder
                        .view("Encoder for qouted printable encoding in EML files")
                        .map(Message::Encoder),
                    Site::Base64 => self.encoder.view("Base 64 Encoder").map(Message::Encoder),
                    Site::Unicode => self.encoder.view("Unicode Encoder").map(Message::Encoder),
                    Site::PathLengthChecker => self
                        .path_length_checker
                        .view()
                        .map(Message::PathLengthChecker),
                }
            ]
            .spacing(20)
            .padding(10)
            .height(Length::Fill)
            .width(Length::Fill),
            rule::horizontal(2),
            footer().map(Message::LinkPressed)
        ]
        .padding(10)
        .spacing(10)
        .into()
    }
}

#[derive(Clone, Debug)]
pub enum Link {
    Rust,
    Iced,
    RahnIT,
}

const FONT_SIZE: f32 = 14.0;
fn footer<'a>() -> iced::Element<'a, Link> {
    use iced::widget::*;
    let text = |content| text(content).font(Font::MONOSPACE).size(FONT_SIZE);

    let link = |button: button::Button<'static, Link>, link| {
        button.on_press(link).padding(0).style(button::text)
    };

    let rust = link(
        button(text("🦀 Rust").shaping(text::Shaping::Advanced)),
        Link::Rust,
    );

    let iced = link(button(iced(FONT_SIZE)), Link::Iced);

    let rahn_it = link(button(text("Rahn-IT")), Link::RahnIT);

    row![
        text("Made with"),
        rust,
        text("and"),
        iced,
        space::horizontal(),
        text("Created by"),
        rahn_it,
    ]
    .height(15)
    .spacing(7)
    .align_y(Vertical::Center)
    .into()
}
