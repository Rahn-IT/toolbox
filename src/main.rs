#![windows_subsystem = "windows"]

use iced::{Font, alignment::Vertical};

fn main() -> Result<(), iced::Error> {
    use tab_manager::TabManager;

    iced::application(TabManager::default, TabManager::update, TabManager::view)
        .title("Rahn-IT Toolbox")
        .window(iced::window::Settings {
            size: (1400.0, 850.0).into(),
            min_size: Some((1150.0, 700.0).into()),
            exit_on_close_request: false,
            ..Default::default()
        })
        .subscription(TabManager::subscription)
        .run()
}

pub mod action;
pub mod eml;
pub mod encoder;
pub mod mailbox_scanner;
pub mod nut;
pub mod path_length_checker;
#[cfg(windows)]
pub mod quick_install;
#[cfg(windows)]
pub mod quick_tools;
pub mod search;
pub mod tab_manager;

/// State for a module in the redesigned interface.
pub enum Module {
    Search(String),
    #[cfg(windows)]
    QuickInstall(quick_install::QuickInstall),
    #[cfg(windows)]
    QuickTools(quick_tools::State),
    Eml(encoder::Encoder),
    Base64(encoder::Encoder),
    Unicode(encoder::Encoder),
    PathLengthChecker(path_length_checker::PathLengthChecker),
    Nut(nut::Nut),
    MailboxScanner(mailbox_scanner::App),
}

#[derive(Clone, Debug)]
pub enum Link {
    Rust,
    Iced,
    RahnIT,
}

impl Link {
    fn open(self) {
        let _ = open::that_in_background(match self {
            Self::Rust => "https://rust-lang.org",
            Self::Iced => "https://iced.rs",
            Self::RahnIT => "https://it-rahn.de",
        });
    }
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
