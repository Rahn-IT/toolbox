use iced::{
    Border, Color, Element, Length, Padding, Rectangle, Size, Theme,
    advanced::{Layout, Widget, layout, mouse, renderer, widget::Tree},
    widget::{button, column, container, row, scrollable, space, stack, text, text_input},
};

use crate::{
    OpenedModule, device_scan,
    encoder::{Encoder, Encoding},
    mailbox_scanner, network_scanner, nut, path_length_checker, spelling_alphabet, wake_on_lan,
};
#[cfg(windows)]
use crate::{
    quick_install::QuickInstall,
    quick_tools::{
        adwcleaner, clear_default_extensions, restart_print_spooler, run_windows_command,
        set_power_config, temp_files,
    },
};

pub(crate) const INPUT_ID: &str = "tool-search";

struct Tool {
    title: &'static str,
    keywords: &'static [&'static str],
    open: fn() -> OpenedModule,
    requires_admin: bool,
}

impl Tool {
    const fn new(title: &'static str, open: fn() -> OpenedModule) -> Self {
        Self {
            title,
            keywords: &[],
            open,
            requires_admin: false,
        }
    }

    const fn keywords(mut self, keywords: &'static [&'static str]) -> Self {
        self.keywords = keywords;
        self
    }

    #[cfg(windows)]
    const fn admin_only(mut self) -> Self {
        self.requires_admin = true;
        self
    }

    fn is_available(&self) -> bool {
        if self.requires_admin {
            #[cfg(windows)]
            return crate::windows_admin::is_elevated();
            #[cfg(not(windows))]
            return false;
        }
        true
    }
}

const TOOLS: &[Tool] = &[
    #[cfg(windows)]
    Tool::new(QuickInstall::TITLE, QuickInstall::new).keywords(&["software", "applications"]),
    Tool::new(Encoding::Eml.title(), || Encoder::new(Encoding::Eml))
        .keywords(&["quoted-printable", "decode"]),
    Tool::new(Encoding::Base64.title(), || Encoder::new(Encoding::Base64)).keywords(&["decode"]),
    Tool::new(Encoding::Unicode.title(), || {
        Encoder::new(Encoding::Unicode)
    })
    .keywords(&["code points", "decode"]),
    Tool::new(
        spelling_alphabet::State::TITLE,
        spelling_alphabet::State::new,
    )
    .keywords(&["phonetic", "nato", "buchstabieralphabet"]),
    Tool::new(
        path_length_checker::PathLengthChecker::TITLE,
        path_length_checker::PathLengthChecker::new,
    )
    .keywords(&["long paths", "max_path"]),
    Tool::new(nut::Nut::TITLE, nut::Nut::new).keywords(&["ups", "network ups tools"]),
    Tool::new(wake_on_lan::State::TITLE, wake_on_lan::State::new)
        .keywords(&["wol", "magic packet"]),
    Tool::new(network_scanner::State::TITLE, network_scanner::State::new).keywords(&[
        "lan scanner",
        "device discovery",
        "ping sweep",
    ]),
    Tool::new(mailbox_scanner::App::TITLE, mailbox_scanner::App::new)
        .keywords(&["imap", "email scanner"]),
    #[cfg(windows)]
    Tool::new(adwcleaner::TITLE, adwcleaner::new).keywords(&["adware", "malwarebytes"]),
    #[cfg(windows)]
    Tool::new(
        clear_default_extensions::TITLE,
        clear_default_extensions::new,
    )
    .keywords(&["file associations", "default apps"])
    .admin_only(),
    #[cfg(windows)]
    Tool::new("Disable Hibernation", || {
        run_windows_command::new(
            "Disable Hibernation",
            "powercfg.exe",
            &["-h", "off"],
            "Hibernation disabled (powercfg -h off).",
        )
    })
    .keywords(&["hibernate", "hiberfil"])
    .admin_only(),
    #[cfg(windows)]
    Tool::new(restart_print_spooler::TITLE, restart_print_spooler::new)
        .keywords(&["printer", "print queue"])
        .admin_only(),
    #[cfg(windows)]
    Tool::new("Flush DNS Cache", || {
        run_windows_command::new(
            "Flush DNS Cache",
            "ipconfig.exe",
            &["/flushdns"],
            "DNS resolver cache flushed.",
        )
    })
    .keywords(&["ipconfig", "flushdns"]),
    #[cfg(windows)]
    Tool::new(set_power_config::TITLE, set_power_config::new).keywords(&["power plan", "powercfg"]),
    #[cfg(windows)]
    Tool::new(temp_files::TITLE, temp_files::new).keywords(&["temporary files", "disk cleanup"]),
];

#[derive(Clone)]
pub enum Message {
    QueryChanged(String),
    PreviousResult,
    NextResult,
    Submit,
    Open(usize),
    OpenDevice(Ipv4Addr),
}

#[derive(Default)]
pub struct State {
    query: String,
    selected_result: Option<usize>,
}

impl State {
    pub const TITLE: &'static str = "Search";

    pub fn new(query: String) -> Self {
        Self {
            query,
            selected_result: None,
        }
    }

    pub fn update(&mut self, message: Message) -> Option<OpenedModule> {
        Self::update_query(&mut self.query, &mut self.selected_result, message)
    }

    pub(crate) fn update_query(
        query: &mut String,
        selected_result: &mut Option<usize>,
        message: Message,
    ) -> Option<OpenedModule> {
        match message {
            Message::QueryChanged(value) => {
                *query = value;
                *selected_result = None;
                None
            }
            Message::PreviousResult => {
                *selected_result = match *selected_result {
                    Some(index) => Some(index.saturating_sub(1)),
                    None => available_results(query).count().checked_sub(1),
                };
                None
            }
            Message::NextResult => {
                if let Some(last) = available_results(query).count().checked_sub(1) {
                    *selected_result =
                        Some(selected_result.map_or(0, |index| (index + 1).min(last)));
                }
                None
            }
            Message::Submit => {
                let result = available_results(query).nth(selected_result.unwrap_or(0))?;
                Self::update_query(query, selected_result, result)
            }
            Message::Open(index) => TOOLS
                .get(index)
                .filter(|tool| tool.is_available())
                .map(|tool| (tool.open)()),
            Message::OpenDevice(ip) if device_address(query) == Some(ip) => {
                Some(device_scan::State::new(ip))
            }
            Message::OpenDevice(_) => None,
        }
    }

    pub fn view(&self) -> Element<'_, Message> {
        Self::view_query(&self.query, self.selected_result)
    }

    pub(crate) fn view_query(value: &str, selected_result: Option<usize>) -> Element<'_, Message> {
        let mut results = column![].spacing(2).width(Length::Fill);
        let mut has_results = false;
        let mut position = 0;
        if let Some(ip) = device_address(value) {
            let selected = selected_result == Some(0);
            results = results.push(
                button(text(format!("Scan device {ip}")).size(16))
                    .width(Length::Fill)
                    .padding([8, 16])
                    .style(move |theme, status| result_style(theme, status, selected))
                    .on_press(Message::OpenDevice(ip)),
            );
            has_results = true;
            position = 1;
        }
        for (index, tool) in matching_tools(value) {
            let available = tool.is_available();
            let selected = available && selected_result == Some(position);
            let mut label = row![text(tool.title).size(16)].spacing(12);
            if available {
                position += 1;
            } else {
                label =
                    label
                        .push(space::horizontal())
                        .push(
                            text("Admin Required")
                                .size(13)
                                .style(|theme: &Theme| text::Style {
                                    color: Some(theme.extended_palette().danger.base.color),
                                }),
                        );
            }
            results = results.push(
                button(label.align_y(iced::Alignment::Center))
                    .width(Length::Fill)
                    .padding([8, 16])
                    .style(move |theme, status| result_style(theme, status, selected))
                    .on_press_maybe(available.then_some(Message::Open(index))),
            );
            has_results = true;
        }
        if !has_results {
            results = results.push(container(text("No matching tools")).padding([12, 16]));
        }

        let input = text_input("Search tools", value)
            .id(INPUT_ID)
            .on_input(Message::QueryChanged)
            .size(18)
            .padding(Padding {
                top: 16.0,
                right: 16.0,
                bottom: 16.0,
                left: 46.0,
            })
            .style(crate::rounded_input_style);
        let search_field = stack![
            input,
            container(Element::new(SearchIcon))
                .padding(Padding::default().left(16))
                .center_y(Length::Fill),
        ];

        container(
            container(
                column![search_field, scrollable(results).height(Length::Fill)]
                    .width(Length::Fill)
                    .spacing(16),
            )
            .max_width(680),
        )
        .padding([24, 12])
        .center_x(Length::Fill)
        .into()
    }
}

fn device_address(query: &str) -> Option<Ipv4Addr> {
    query.trim().parse().ok()
}

fn available_results(query: &str) -> impl Iterator<Item = Message> {
    device_address(query)
        .map(Message::OpenDevice)
        .into_iter()
        .chain(
            matching_tools(query)
                .filter(|(_, tool)| tool.is_available())
                .map(|(index, _)| Message::Open(index)),
        )
}

fn matching_tools(query: &str) -> impl Iterator<Item = (usize, &'static Tool)> {
    let query = query.trim().to_ascii_lowercase();
    TOOLS.iter().enumerate().filter(move |(_, tool)| {
        tool.title.to_ascii_lowercase().contains(&query)
            || tool.keywords.iter().any(|keyword| keyword.contains(&query))
    })
}

fn result_style(theme: &Theme, status: button::Status, selected: bool) -> button::Style {
    let mut style = if selected {
        button::primary(theme, status)
    } else {
        button::secondary(theme, status)
    };
    style.border.radius = 6.0.into();
    style
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn searching_a_keyword_opens_the_matching_tool() {
        let mut search = State::new("  NATO  ".into());
        assert!(matches!(
            search.update(Message::Submit),
            Some((crate::Module::SpellingAlphabet(_), _))
        ));
    }

    #[test]
    fn entering_an_ipv4_address_opens_a_device_scan_as_the_first_result() {
        let mut search = State::new("192.0.2.".into());
        assert!(search.update(Message::Submit).is_none());
        assert!(
            search
                .update(Message::QueryChanged("192.0.2.10".into()))
                .is_none()
        );
        let Some((crate::Module::DeviceScan(device), _)) = search.update(Message::Submit) else {
            panic!("expected Device Scan as the first result");
        };
        assert_eq!(device.title(), "192.0.2.10");
    }
}

struct SearchIcon;

impl Widget<Message, Theme, iced::Renderer> for SearchIcon {
    fn size(&self) -> Size<Length> {
        Size::new(Length::Fixed(20.0), Length::Fixed(20.0))
    }

    fn layout(
        &mut self,
        _tree: &mut Tree,
        _renderer: &iced::Renderer,
        limits: &layout::Limits,
    ) -> layout::Node {
        layout::atomic(limits, Length::Fixed(20.0), Length::Fixed(20.0))
    }

    fn draw(
        &self,
        _tree: &Tree,
        renderer: &mut iced::Renderer,
        theme: &Theme,
        _style: &renderer::Style,
        layout: Layout<'_>,
        _cursor: mouse::Cursor,
        _viewport: &Rectangle,
    ) {
        use iced::advanced::Renderer as _;

        let bounds = layout.bounds();
        let color = theme.extended_palette().background.weak.text;
        renderer.fill_quad(
            renderer::Quad {
                bounds: Rectangle::new(
                    [bounds.x + 1.0, bounds.y + 1.0].into(),
                    Size::new(14.0, 14.0),
                ),
                border: Border {
                    radius: 7.0.into(),
                    width: 1.7,
                    color,
                },
                snap: false,
                ..renderer::Quad::default()
            },
            Color::TRANSPARENT,
        );

        // Stroke the diagonal handle with overlapping rounded caps.
        for step in 0..=20 {
            let offset = step as f32 * 0.25;
            renderer.fill_quad(
                renderer::Quad {
                    bounds: Rectangle::new(
                        [bounds.x + 12.1 + offset, bounds.y + 12.1 + offset].into(),
                        Size::new(1.75, 1.75),
                    ),
                    border: Border::default().rounded(0.875),
                    snap: false,
                    ..renderer::Quad::default()
                },
                color,
            );
        }
    }
}
use std::net::Ipv4Addr;
