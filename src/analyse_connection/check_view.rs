use iced::{
    Alignment, Border, Color, Element, Length, color,
    widget::{column, container, row, rule, text, tooltip},
};

pub(super) fn badge<'a, Message: 'a>(
    label: impl text::IntoFragment<'a>,
    positive: bool,
) -> Element<'a, Message> {
    let background = if positive {
        color!(0x167344)
    } else {
        color!(0xB32539)
    };
    colored_badge(label, background, Color::WHITE)
}

pub(super) fn warning_badge<'a, Message: 'a>(
    label: impl text::IntoFragment<'a>,
) -> Element<'a, Message> {
    colored_badge(label, color!(0xF2C94C), color!(0x241A00))
}

fn colored_badge<'a, Message: 'a>(
    label: impl text::IntoFragment<'a>,
    background: Color,
    foreground: Color,
) -> Element<'a, Message> {
    container(text(label).size(14).color(foreground))
        .padding([3, 8])
        .style(move |_| container::background(background).border(Border::default().rounded(5.0)))
        .into()
}

pub(super) fn error_badge<'a, Message: 'a>(label: &'a str, error: &'a str) -> Element<'a, Message> {
    tooltip(
        badge(label, false),
        container(text(error))
            .padding(8)
            .style(container::rounded_box),
        tooltip::Position::Bottom,
    )
    .into()
}

pub(super) fn checking<'a, Message: 'a>() -> Element<'a, Message> {
    row![crate::loading::spinner(), text("Checking")]
        .align_y(Alignment::Center)
        .spacing(8)
        .into()
}

pub(super) fn table<'a, Message: 'a>(
    title: &'static str,
    target: Option<String>,
    checks: impl IntoIterator<Item = (&'static str, Option<Element<'a, Message>>)>,
) -> Option<Element<'a, Message>> {
    const CHECK_WIDTH: f32 = 160.0;
    let mut rows = checks
        .into_iter()
        .filter_map(|(label, result)| {
            Some(
                container(
                    row![
                        text(label).width(CHECK_WIDTH),
                        container(result?).width(Length::Fill)
                    ]
                    .spacing(12),
                )
                .width(Length::Fill)
                .padding([10, 12])
                .style(container::rounded_box)
                .into(),
            )
        })
        .peekable();
    rows.peek()?;
    Some(
        column![
            text(title).size(24),
            target.map(|target| text(target).size(14)),
            container(row![text("Check").width(CHECK_WIDTH), text("Result")].spacing(12))
                .padding([0, 12]),
            rule::horizontal(1),
            column(rows).spacing(6),
        ]
        .spacing(8)
        .into(),
    )
}
