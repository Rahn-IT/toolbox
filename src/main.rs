#![windows_subsystem = "windows"]

use base64::{Engine, prelude::BASE64_STANDARD};
use std::fmt::Write;

use iced::{
    Font, Length, Task,
    alignment::Vertical,
    widget::{button, column, row, rule},
};

fn main() -> Result<(), iced::Error> {
    iced::application(UI::boot, UI::update, UI::view)
        .window(iced::window::Settings {
            size: (1400.0, 850.0).into(),
            min_size: Some((1150.0, 700.0).into()),
            exit_on_close_request: false,
            ..Default::default()
        })
        .subscription(UI::subscription)
        .run()
}

pub mod eml;
pub mod encoder;
pub mod mailbox_scanner;
pub mod nut;
pub mod path_length_checker;
#[cfg(windows)]
pub mod quick_install;
#[cfg(windows)]
pub mod quick_tools;

struct UI {
    site: Site,
    encoder: encoder::Encoder,
    path_length_checker: path_length_checker::PathLengthChecker,
    #[cfg(windows)]
    quick_install: quick_install::QuickInstall,
    #[cfg(windows)]
    quick_tools: quick_tools::State,
    nut: nut::Nut,
    mailbox_scanner: mailbox_scanner::App,
}

#[derive(Clone)]
pub enum Site {
    Home,
    #[cfg(windows)]
    QuickInstall,
    #[cfg(windows)]
    QuickTools,
    Eml,
    Base64,
    Unicode,
    PathLengthChecker,
    Nut,
    MailboxScanner,
}

#[derive(Clone)]
pub enum Message {
    LinkPressed(Link),
    SwitchSite(Site),
    Encoder(encoder::Message),
    PathLengthChecker(path_length_checker::Message),
    #[cfg(windows)]
    QuickInstall(quick_install::Message),
    #[cfg(windows)]
    QuickTools(quick_tools::Message),
    Nut(nut::Message),
    MailboxScanner(mailbox_scanner::Message),
}

impl UI {
    pub fn boot() -> Self {
        Self {
            site: Site::Home,
            encoder: encoder::Encoder::new(|str| str.to_string(), |str| str.to_string()),
            path_length_checker: path_length_checker::PathLengthChecker::new(),
            #[cfg(windows)]
            quick_install: quick_install::QuickInstall::new(),
            #[cfg(windows)]
            quick_tools: quick_tools::State::default(),
            nut: nut::Nut::new(),
            mailbox_scanner: mailbox_scanner::App::default(),
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
                if self.mailbox_scanner.is_closing() {
                    return Task::none();
                }
                self.site = site.clone();

                self.path_length_checker.cancel_scan();
                match site {
                    Site::QuickInstall => Task::none(),
                    #[cfg(windows)]
                    Site::QuickTools => Task::none(),
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
                    Site::Home | Site::PathLengthChecker | Site::Nut | Site::MailboxScanner => {
                        Task::none()
                    }
                }
            }
            Message::Encoder(message) => self.encoder.update(message).map(Message::Encoder),
            Message::PathLengthChecker(message) => self
                .path_length_checker
                .update(message)
                .map(Message::PathLengthChecker),
            #[cfg(windows)]
            Message::QuickInstall(message) => self
                .quick_install
                .update(message)
                .map(Message::QuickInstall),
            Message::Nut(message) => self.nut.update(message).map(Message::Nut),
            #[cfg(windows)]
            Message::QuickTools(message) => {
                self.quick_tools.update(message).map(Message::QuickTools)
            }
            Message::MailboxScanner(message) => {
                if matches!(message, mailbox_scanner::Message::CloseRequested) {
                    self.site = Site::MailboxScanner;
                    self.path_length_checker.cancel_scan();
                }
                self.mailbox_scanner
                    .update(message)
                    .map(Message::MailboxScanner)
            }
        }
    }

    fn subscription(&self) -> iced::Subscription<Message> {
        self.mailbox_scanner
            .subscription()
            .map(Message::MailboxScanner)
    }

    pub fn view(&self) -> iced::Element<'_, Message> {
        column![
            row![
                iced::Element::from(
                    column![
                        #[cfg(windows)]
                        button("Quick Install").on_press(Site::QuickInstall),
                        #[cfg(windows)]
                        button("Quick Tools").on_press(Site::QuickTools),
                        button("EML Encode").on_press(Site::Eml),
                        button("Base64 Encode").on_press(Site::Base64),
                        button("Unicode Encode").on_press(Site::Unicode),
                        button("Path Length Checker").on_press(Site::PathLengthChecker),
                        button("NUT Client").on_press(Site::Nut),
                        button("Mailbox scanner").on_press(Site::MailboxScanner)
                    ]
                    .spacing(10)
                    .height(Length::Fill)
                )
                .map(Message::SwitchSite),
                rule::vertical(2),
                match self.site {
                    Site::Home => "Toolbox".into(),
                    #[cfg(windows)]
                    Site::QuickInstall => self.quick_install.view().map(Message::QuickInstall),
                    #[cfg(windows)]
                    Site::QuickTools => self.quick_tools.view().map(Message::QuickTools),
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
                    Site::Nut => self.nut.view().map(Message::Nut),
                    Site::MailboxScanner =>
                        self.mailbox_scanner.view().map(Message::MailboxScanner),
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mailbox_results_survive_navigation_to_another_tool() {
        let mut app = UI::boot();
        app.mailbox_scanner = mailbox_scanner::App::preview_scan();
        app.site = Site::MailboxScanner;
        let mut ui =
            iced_test::Simulator::with_size(iced::Settings::default(), (1400.0, 850.0), app.view());
        ui.click("Select page").unwrap();
        let messages: Vec<_> = ui.into_messages().collect();
        let _ = app.update(Message::SwitchSite(Site::Base64));
        for message in messages {
            let _ = app.update(message);
        }
        assert!(matches!(app.site, Site::Base64));
        let _ = app.update(Message::SwitchSite(Site::MailboxScanner));
        let mut ui =
            iced_test::Simulator::with_size(iced::Settings::default(), (1400.0, 850.0), app.view());
        assert!(ui.find("Download & purge selected (3)").is_ok());
    }

    #[test]
    fn closing_from_another_tool_routes_to_mailbox_cleanup() {
        let mut app = UI::boot();
        app.mailbox_scanner = mailbox_scanner::App::preview_scan();
        app.site = Site::Base64;
        let _ = app.update(Message::MailboxScanner(
            mailbox_scanner::Message::CloseRequested,
        ));
        assert!(matches!(app.site, Site::MailboxScanner));
        assert!(app.mailbox_scanner.is_closing());
        let _ = app.update(Message::SwitchSite(Site::Nut));
        assert!(matches!(app.site, Site::MailboxScanner));
    }
}
