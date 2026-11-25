use base64::{Engine, prelude::BASE64_STANDARD};
use iced::{
    Border, Color, Element, Length, Padding, Rectangle, Size, Theme,
    advanced::{Layout, Widget, layout, mouse, renderer, widget::Tree},
    widget::{button, column, container, scrollable, stack, text, text_input},
};

use crate::{Module, eml, encoder, mailbox_scanner, nut, path_length_checker};

pub(crate) const INPUT_ID: &str = "tool-search";

const TOOLS: &[(&str, fn() -> Module)] = &[
    #[cfg(windows)]
    ("Quick Install", || {
        Module::QuickInstall(crate::quick_install::QuickInstall::new())
    }),
    #[cfg(windows)]
    ("Quick Tools", || {
        Module::QuickTools(crate::quick_tools::State::default())
    }),
    ("EML Encode", || {
        Module::Eml(encoder::Encoder::new(eml::qp_encode, eml::qp_decode))
    }),
    ("Base64 Encode", || {
        Module::Base64(encoder::Encoder::new(
            |raw| BASE64_STANDARD.encode(raw),
            |encoded| {
                BASE64_STANDARD
                    .decode(encoded)
                    .map(|decoded| String::from_utf8_lossy(&decoded).into_owned())
                    .unwrap_or_else(|err| err.to_string())
            },
        ))
    }),
    ("Unicode Encode", || {
        Module::Unicode(encoder::Encoder::new(
            |raw| {
                raw.chars()
                    .map(|character| (character as u32).to_string())
                    .collect::<Vec<_>>()
                    .join(" ")
            },
            |encoded| {
                encoded
                    .split_ascii_whitespace()
                    .filter_map(|number| char::from_u32(number.parse().ok()?))
                    .collect()
            },
        ))
    }),
    ("Path Length Checker", || {
        Module::PathLengthChecker(path_length_checker::PathLengthChecker::new())
    }),
    ("NUT Client", || Module::Nut(nut::Nut::new())),
    ("Mailbox Scanner", || {
        Module::MailboxScanner(mailbox_scanner::App::default())
    }),
];

#[derive(Clone)]
pub enum Message {
    QueryChanged(String),
    PreviousResult,
    NextResult,
    Submit,
    Open(usize),
}

#[derive(Default)]
pub struct State {
    query: String,
    selected_result: Option<usize>,
}

impl State {
    pub fn new(query: String) -> Self {
        Self {
            query,
            selected_result: None,
        }
    }

    pub fn update(&mut self, message: Message) -> Option<Module> {
        Self::update_query(&mut self.query, &mut self.selected_result, message)
    }

    pub(crate) fn update_query(
        query: &mut String,
        selected_result: &mut Option<usize>,
        message: Message,
    ) -> Option<Module> {
        match message {
            Message::QueryChanged(value) => {
                *query = value;
                *selected_result = None;
                None
            }
            Message::PreviousResult => {
                *selected_result = match *selected_result {
                    Some(index) => Some(index.saturating_sub(1)),
                    None => matching_tools(query).count().checked_sub(1),
                };
                None
            }
            Message::NextResult => {
                if let Some(last) = matching_tools(query).count().checked_sub(1) {
                    *selected_result =
                        Some(selected_result.map_or(0, |index| (index + 1).min(last)));
                }
                None
            }
            Message::Submit => matching_tools(query)
                .nth(selected_result.unwrap_or(0))
                .map(|(index, _)| (TOOLS[index].1)()),
            Message::Open(index) => TOOLS.get(index).map(|(_, open)| open()),
        }
    }

    pub fn view(&self) -> Element<'_, Message> {
        Self::view_query(&self.query, self.selected_result)
    }

    pub(crate) fn view_query(value: &str, selected_result: Option<usize>) -> Element<'_, Message> {
        let mut results = column![].spacing(2).width(Length::Fill);
        let mut has_results = false;
        for (position, (index, name)) in matching_tools(value).enumerate() {
            let selected = selected_result == Some(position);
            results = results.push(
                button(text(name).size(16))
                    .width(Length::Fill)
                    .padding([12, 16])
                    .style(move |theme, status| result_style(theme, status, selected))
                    .on_press(Message::Open(index)),
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
            .style(|theme, status| {
                let mut style = text_input::default(theme, status);
                style.background = theme.extended_palette().background.weak.color.into();
                style.border.radius = 14.0.into();
                style
            });
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

fn matching_tools(query: &str) -> impl Iterator<Item = (usize, &'static str)> {
    let query = query.trim().to_ascii_lowercase();
    TOOLS
        .iter()
        .enumerate()
        .filter_map(move |(index, (name, _))| {
            name.to_ascii_lowercase()
                .contains(&query)
                .then_some((index, *name))
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
