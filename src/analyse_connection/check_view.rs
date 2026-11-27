use iced::{
    Alignment, Border, Color, Element, Length, color,
    widget::{column, container, row, rule, text, tooltip},
};

pub(super) fn badge<'a, Message: 'a>(label: &'a str, positive: bool) -> Element<'a, Message> {
    let background = if positive {
        color!(0x167344)
    } else {
        color!(0xB32539)
    };
    container(text(label).size(14).color(Color::WHITE))
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

pub(super) fn section<'a, Message: 'a>(
    title: String,
    label: &'static str,
    result: Element<'a, Message>,
) -> Element<'a, Message> {
    column![
        text(title).size(24),
        container(row![text("Check").width(160), text("Result")].spacing(12)).padding([0, 12]),
        rule::horizontal(1),
        container(
            row![
                text(label).width(160),
                container(result).width(Length::Fill)
            ]
            .spacing(12)
        )
        .width(Length::Fill)
        .padding([10, 12])
        .style(container::rounded_box),
    ]
    .spacing(8)
    .into()
}
