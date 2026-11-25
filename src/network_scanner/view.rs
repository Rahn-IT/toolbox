use iced::{
    Alignment, Border, Color, Element, Font, Length, Padding, Theme, color,
    widget::{
        button, column, container, pick_list, progress_bar, row, rule, scrollable, text, text_input,
    },
};

use super::{
    Message, State,
    ports::{Outcome, PORTS},
    scan::{Observation, Progress},
};
use crate::loading;

const TABLE_RIGHT_INSET: f32 = 8.0;
const TABLE_SCROLLBAR_WIDTH: f32 = 10.0;

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

    let mut content = column![
        controls,
        text_input("Filter by IP, MAC address, or name", &state.filter)
            .on_input(Message::FilterChanged)
            .padding([8, 12]),
        status,
    ]
    .spacing(14);
    if state.port_task.is_some()
        && let Some(report) = &state.results
    {
        content = content.push(scan_loading(Progress::Ports {
            done: state.port_completed,
            total: report.devices.len() * PORTS.len(),
        }));
    }
    if let Some(notice) = &state.port_notice {
        content = content.push(text(notice));
    }
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
            content = content.push(table(&report.devices, state));
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
        Progress::ReverseDns { done, total } => ("Looking up hostnames…", Some((done, total))),
        Progress::Ports { done, total } => ("Checking TCP ports…", Some((done, total))),
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

fn table<'a>(devices: &'a [Observation], state: &'a State) -> Element<'a, Message> {
    let filter = state.filter.trim().to_lowercase();
    let mut devices = devices
        .iter()
        .filter(|device| matches_filter(device, &filter))
        .peekable();
    if devices.peek().is_none() {
        return text("No devices match the filter.").into();
    }
    let rows = column(devices.map(|device| {
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
                text(device.hostname.as_deref().unwrap_or("—")).width(Length::Fill),
                text(device.names.first().map_or("—", |name| name.name.as_str())).width(145),
                ping_label(device.ping_reply),
                text(open_ports(state, device)).width(150),
            ]
            .spacing(12)
            .align_y(Alignment::Center),
        )
        .width(Length::Fill)
        .padding([10, 12])
        .style(device_row_style)
        .on_press(Message::OpenDevice(device.ip))
        .into()
    }))
    .spacing(6);

    column![
        container(
            row![
                text("IPv4 address").width(125),
                text("MAC address").width(165),
                text("Hostname").width(Length::Fill),
                text("NetBIOS").width(145),
                text("Ping reply").width(90),
                text("Open ports").width(150),
            ]
            .spacing(12)
        )
        .padding(
            Padding::default()
                .left(12)
                .right(12.0 + TABLE_RIGHT_INSET + TABLE_SCROLLBAR_WIDTH)
        ),
        rule::horizontal(1),
        scrollable(rows)
            .direction(scrollable::Direction::Vertical(
                scrollable::Scrollbar::new()
                    .width(TABLE_SCROLLBAR_WIDTH)
                    .scroller_width(TABLE_SCROLLBAR_WIDTH)
                    .spacing(TABLE_RIGHT_INSET)
            ))
            .height(Length::Fill),
    ]
    .width(Length::Fill)
    .spacing(8)
    .into()
}

fn matches_filter(device: &Observation, filter: &str) -> bool {
    filter.is_empty()
        || device.ip.to_string().contains(filter)
        || device
            .addresses
            .iter()
            .any(|entry| entry.mac_address().to_ascii_lowercase().contains(filter))
        || device
            .hostname
            .as_ref()
            .is_some_and(|name| name.to_lowercase().contains(filter))
        || device
            .names
            .iter()
            .any(|entry| entry.name.to_lowercase().contains(filter))
}

fn device_row_style(theme: &Theme, status: button::Status) -> button::Style {
    let background = theme.extended_palette().background;
    let surface = match status {
        button::Status::Hovered => background.weak,
        button::Status::Pressed => background.strong,
        _ => background.base,
    };
    button::Style {
        background: Some(surface.color.into()),
        text_color: surface.text,
        border: Border {
            color: background.weak.color,
            width: 1.0,
            radius: 6.0.into(),
        },
        ..button::Style::default()
    }
}

fn open_ports(state: &State, device: &Observation) -> String {
    let Some(results) = state.port_results.get(&device.ip) else {
        return "—".into();
    };
    let ports = results
        .iter()
        .filter(|(_, outcome)| **outcome == Outcome::Open)
        .map(|(port, _)| port.to_string())
        .collect::<Vec<_>>();
    if ports.is_empty() {
        "—".into()
    } else {
        ports.join(", ")
    }
}

fn ping_label(reply: Option<bool>) -> Element<'static, Message> {
    let Some(replied) = reply else {
        return container(text("—")).width(90).into();
    };
    let (label, background) = if replied {
        ("Yes", color!(0x167344))
    } else {
        ("No", color!(0xB32539))
    };
    let badge = container(text(label).size(14).color(Color::WHITE))
        .center_x(48)
        .padding([3, 8])
        .style(move |_| container::background(background).border(Border::default().rounded(5.0)));
    container(badge).width(90).into()
}
