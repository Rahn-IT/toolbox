use std::{io, net::Ipv4Addr};

use iced::{
    Alignment, Element, Length, Task,
    task::Handle,
    widget::{button, column, container, row, scrollable, space, text, text_input},
};
use tokio::net::UdpSocket;

use crate::tab_manager::TabMessage;
use crate::{Module, OpenedModule, action::Action};

pub use crate::arp::Device;
use crate::arp::{self, parse_mac};

#[derive(Clone)]
pub enum Message {
    MacChanged(String),
    Wake,
    Sent(Result<(), String>),
    RefreshDevices,
    DevicesLoaded(Result<Vec<Device>, String>),
}

#[derive(Default)]
pub struct State {
    mac: String,
    sending: Option<Handle>,
    result: Option<Result<(), String>>,
    devices: Vec<Device>,
    loading_devices: Option<Handle>,
    device_error: Option<String>,
}

impl State {
    pub const TITLE: &str = "Wake on LAN";

    pub fn new() -> OpenedModule {
        let mut state = Self::default();
        let task = state.load_devices().map(TabMessage::WakeOnLan);
        (Module::WakeOnLan(state), task)
    }

    pub fn update(&mut self, message: Message) -> Action<Message> {
        match message {
            Message::MacChanged(value) => {
                self.mac = value
                    .chars()
                    .filter_map(|character| match character {
                        '-' | ':' => Some(':'),
                        digit if digit.is_ascii_hexdigit() => Some(digit.to_ascii_uppercase()),
                        _ => None,
                    })
                    .collect();
                self.result = None;
            }
            Message::Wake if self.sending.is_none() => {
                let Some(mac) = parse_mac(&self.mac) else {
                    return Action::None;
                };
                self.result = None;
                let (task, handle) = Task::perform(send_magic_packet(mac), |result| {
                    Message::Sent(result.map_err(|error| error.to_string()))
                })
                .abortable();
                self.sending = Some(handle.abort_on_drop());
                return Action::Task(task);
            }
            Message::Wake => {}
            Message::Sent(result) => {
                self.sending = None;
                self.result = Some(result);
            }
            Message::RefreshDevices if self.loading_devices.is_none() => {
                return Action::Task(self.load_devices());
            }
            Message::RefreshDevices => {}
            Message::DevicesLoaded(result) => {
                self.loading_devices = None;
                match result {
                    Ok(devices) => self.devices = devices,
                    Err(error) => self.device_error = Some(error),
                }
            }
        }
        Action::None
    }

    pub fn view(&self) -> Element<'_, Message> {
        let ready = self.sending.is_none() && parse_mac(&self.mac).is_some();
        let status = if self.sending.is_some() {
            Some(text("Sending…"))
        } else {
            self.result.as_ref().map(|result| match result {
                Ok(()) => text("Magic packet sent."),
                Err(error) => text(format!("Could not send magic packet: {error}")),
            })
        };

        let wake_controls = column![
            container(
                text_input("MAC address", &self.mac)
                    .font(iced::Font::MONOSPACE)
                    .size(18)
                    .padding([16, 20])
                    .align_x(Alignment::Center)
                    .width(Length::Fill)
                    .style(crate::rounded_input_style)
                    .on_input(Message::MacChanged)
                    .on_submit(Message::Wake),
            )
            .max_width(420),
            button("Wake")
                .padding([9, 24])
                .on_press_maybe(ready.then_some(Message::Wake)),
            status,
        ]
        .width(Length::Fill)
        .align_x(Alignment::Center)
        .spacing(12);

        let devices = column![
            row![
                text("ARP devices").size(20),
                space::horizontal(),
                button("Refresh").padding([8, 14]).on_press_maybe(
                    self.loading_devices
                        .is_none()
                        .then_some(Message::RefreshDevices)
                ),
            ]
            .spacing(8)
            .align_y(Alignment::Center),
            self.device_list(),
        ]
        .spacing(12);

        container(
            container(
                column![wake_controls, devices]
                    .spacing(28)
                    .width(Length::Fill),
            )
            .max_width(680),
        )
        .padding([24, 16])
        .center_x(Length::Fill)
        .into()
    }

    fn load_devices(&mut self) -> Task<Message> {
        self.device_error = None;
        let (task, handle) =
            Task::perform(arp::read(arp::Scope::All), Message::DevicesLoaded).abortable();
        self.loading_devices = Some(handle.abort_on_drop());
        task
    }

    fn device_list(&self) -> Element<'_, Message> {
        let status = if self.loading_devices.is_some() {
            Some(text("Reading ARP cache…"))
        } else if let Some(error) = &self.device_error {
            Some(text(format!("Could not read ARP cache: {error}")))
        } else if self.devices.is_empty() {
            Some(text("No devices in the ARP cache."))
        } else {
            None
        };

        let mut devices = column![status].spacing(8);
        for device in &self.devices {
            let mac = device.mac_address();
            devices = devices.push(
                button(
                    row![
                        text(device.ip.to_string()).width(145),
                        text(mac.clone()).font(iced::Font::MONOSPACE),
                    ]
                    .spacing(12),
                )
                .width(Length::Fill)
                .padding([12, 16])
                .style(|theme, status| {
                    let mut style = button::secondary(theme, status);
                    style.border.radius = 8.0.into();
                    style
                })
                .on_press(Message::MacChanged(mac)),
            );
        }
        scrollable(container(devices).padding(6).width(Length::Fill))
            .height(Length::Fill)
            .into()
    }
}

async fn send_magic_packet(mac: [u8; 6]) -> io::Result<()> {
    let mut packet = [0xff; 102];
    for address in packet[6..].chunks_exact_mut(mac.len()) {
        address.copy_from_slice(&mac);
    }
    let socket = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0)).await?;
    socket.set_broadcast(true)?;
    socket.send_to(&packet, (Ipv4Addr::BROADCAST, 9)).await?;
    Ok(())
}
