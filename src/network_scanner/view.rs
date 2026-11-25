use iced::{
    Alignment, Element, Font, Length,
    widget::{button, column, container, pick_list, progress_bar, row, rule, scrollable, text},
};
use std::net::Ipv4Addr;

use super::{
    Message, State,
    scan::{Observation, Progress},
};
use crate::loading;

pub(super) fn render(state: &State) -> Element<'_, Message> {
    let interfaces = match &state.interfaces {
        Err(error) => return screen(text(format!("Could not read interfaces: {error}"))),
        Ok(_) if state.loading_interfaces.is_some() => {
            return loading::screen(None, "Reading interfaces…");
        }
        Ok(interfaces) if interfaces.is_empty() => {
            return screen(text("No eligible IPv4 interfaces found."));
        }
        Ok(interfaces) => interfaces,
    };
    let controls = row![
        pick_list(
            interfaces.as_slice(),
            state.interface.clone(),
            Message::SelectInterface
        )
        .placeholder("Select a network interface")
        .width(Length::Fill),
        if state.loading_scan.is_some() {
            button("Cancel").on_press(Message::Cancel)
        } else {
            button("Rescan").on_press_maybe(state.interface.is_some().then_some(Message::Rescan))
        },
    ]
    .spacing(12)
    .align_y(Alignment::Center);

    let status = if state.canceled {
        Some(text("Discovery canceled."))
    } else if state.interface.is_none() {
        Some(text("Select an interface to discover devices."))
    } else {
        None
    };

    let mut content = column![controls, status].spacing(14);
    if state.loading_scan.is_some() {
        content = content.push(scan_loading(state.progress));
    }
    if let Some(report) = &state.results {
        for notice in &report.notices {
            content = content.push(text(notice));
        }
        if report.devices.is_empty() {
            content = content.push(text("No devices found."));
        } else {
            content = content.push(table(&report.devices, state.device));
        }
    }
    screen(content)
}

fn scan_loading(progress: Progress) -> Element<'static, Message> {
    let (label, count) = match progress {
        Progress::Preparing => ("Preparing network scan…", None),
        Progress::Ping { done, total } => ("Sending ping requests…", Some((done, total))),
        Progress::Arp => ("Reading ARP cache…", None),
        Progress::NetBios { done, total } => ("Looking up NetBIOS names…", Some((done, total))),
    };
    let mut indicator = loading::content(None, label);
    if let Some((done, total)) = count {
        indicator = indicator
            .push(progress_bar(0.0..=total as f32, done as f32).length(Length::Fill))
            .push(text(format!("{done} of {total}")).size(14));
    }
    container(container(indicator).width(Length::Fill).max_width(420))
        .center_x(Length::Fill)
        .padding([12, 0])
        .into()
}

fn screen<'a>(content: impl Into<Element<'a, Message>>) -> Element<'a, Message> {
    container(content).width(Length::Fill).padding(24).into()
}

fn table(devices: &[Observation], selected: Option<Ipv4Addr>) -> Element<'_, Message> {
    let rows = column(devices.iter().map(|device| {
        let style = if selected == Some(device.ip) {
            button::primary
        } else {
            button::secondary
        };
        button(
            row![
                text(device.ip.to_string()).width(125),
                text(
                    device
                        .addresses
                        .first()
                        .map(|entry| entry.mac_address())
                        .unwrap_or_else(|| "—".into())
                )
                .font(Font::MONOSPACE)
                .width(165),
                text(device.names.first().map_or("—", |name| name.name.as_str()))
                    .width(Length::Fill),
                ping_label(device.ping_reply).width(90),
            ]
            .spacing(12),
        )
        .width(Length::Fill)
        .padding([10, 12])
        .style(style)
        .on_press(Message::SelectDevice(device.ip))
        .into()
    }))
    .spacing(6);

    let table = column![
        container(
            row![
                text("IPv4 address").width(125),
                text("MAC address").width(165),
                text("NetBIOS").width(Length::Fill),
                text("Ping reply").width(90),
            ]
            .spacing(12)
        )
        .padding([0, 12]),
        rule::horizontal(1),
        scrollable(rows).height(Length::Fill),
    ]
    .width(Length::Fill)
    .spacing(8);

    let mut detail = column![text("Device details").size(20)].spacing(10);
    if let Some(device) = devices.iter().find(|device| selected == Some(device.ip)) {
        detail = detail
            .push(text(device.ip.to_string()))
            .push(text(match device.ping_reply {
                Some(true) => "Ping reply received",
                Some(false) => "Found in ARP cache without a ping reply",
                None => "Found in ARP cache",
            }));
        for address in &device.addresses {
            detail = detail.push(text(address.mac_address()).font(Font::MONOSPACE));
        }
        for name in &device.names {
            detail = detail.push(text(format!("{} <{:02X}>", name.name, name.suffix)));
        }
    } else {
        detail = detail.push(text("Select a device."));
    }

    row![
        table,
        container(scrollable(detail))
            .padding(16)
            .width(260)
            .style(container::bordered_box),
    ]
    .spacing(20)
    .into()
}

fn ping_label(reply: Option<bool>) -> iced::widget::Text<'static> {
    match reply {
        Some(replied) => {
            text(if replied { "Yes" } else { "No" }).style(move |theme: &iced::Theme| {
                let palette = theme.extended_palette();
                let color = if replied {
                    palette.success.base.color
                } else {
                    palette.danger.base.color
                };
                text::Style { color: Some(color) }
            })
        }
        None => text("—"),
    }
}
