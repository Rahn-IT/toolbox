mod check_view;
mod local_link;
mod name_resolution;
mod port_connectivity;

use std::{fmt, net::IpAddr, num::NonZeroU16};

use iced::{
    Element, Length, Subscription, Task,
    keyboard::{self, Key, key::Named},
    widget::{button, column, container, pick_list, scrollable, text, text_input},
};

const HOST_INPUT_ID: &str = "analyse-connection-host";

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Protocol {
    Http,
    Https,
    Tls,
    Unknown,
    Autodetect,
}

impl Protocol {
    const ALL: [Self; 5] = [
        Self::Http,
        Self::Https,
        Self::Tls,
        Self::Unknown,
        Self::Autodetect,
    ];

    fn for_port(port: NonZeroU16) -> Self {
        match crate::network_scanner::ports::web_protocol(port.get()) {
            Some("http") => Self::Http,
            Some("https") => Self::Https,
            _ if port.get() == 8007 => Self::Https,
            _ if matches!(port.get(), 465 | 636 | 853 | 993 | 995) => Self::Tls,
            _ => Self::Autodetect,
        }
    }
}

impl fmt::Display for Protocol {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Http => "HTTP",
            Self::Https => "HTTPS",
            Self::Tls => "TLS",
            Self::Unknown => "Unknown",
            Self::Autodetect => "Autodetect",
        })
    }
}

#[derive(Clone)]
pub enum Message {
    HostEdited(String),
    PortEdited(String),
    ProtocolSelected(Protocol),
    Analyse,
    Resolution(name_resolution::Message),
    LocalLink(local_link::Message),
    PortConnectivity(port_connectivity::Message),
}

#[derive(Default)]
pub struct State {
    host: String,
    port: String,
    protocol: Option<Protocol>,
    target_ip: Option<IpAddr>,
    resolver: name_resolution::Resolver,
    local_link: local_link::State,
    port_connectivity: port_connectivity::State,
}

impl State {
    pub const TITLE: &'static str = "Analyse Connection Problems";

    pub fn new() -> crate::OpenedModule {
        (
            crate::Module::AnalyseConnection(Self::default()),
            iced::widget::operation::focus(HOST_INPUT_ID),
        )
    }

    pub fn update(&mut self, message: Message) -> Task<Message> {
        match message {
            Message::HostEdited(host) if !self.is_running() => {
                let host = host
                    .chars()
                    .filter(|character| {
                        if character.is_ascii() {
                            character.is_ascii_alphanumeric()
                                || matches!(character, '-' | '.' | ':' | '[' | ']')
                        } else {
                            !character.is_whitespace() && !character.is_control()
                        }
                    })
                    .collect();
                if self.host != host {
                    self.host = host;
                    self.target_ip = None;
                    self.resolver = name_resolution::Resolver::default();
                    self.local_link = local_link::State::default();
                    self.port_connectivity = port_connectivity::State::default();
                }
                return Task::none();
            }
            Message::PortEdited(port) if !self.is_running() => {
                let port = port.chars().filter(char::is_ascii_digit).collect();
                if self.port != port {
                    let previous = self.port_number();
                    self.port = port;
                    let current = self.port_number();
                    if previous != current {
                        self.protocol = current.map(Protocol::for_port);
                    }
                    self.port_connectivity = port_connectivity::State::default();
                }
                return Task::none();
            }
            Message::ProtocolSelected(protocol) => {
                self.protocol = Some(protocol);
                return Task::none();
            }
            Message::Analyse if self.can_analyse() => {
                self.target_ip = None;
                self.resolver = name_resolution::Resolver::default();
                self.local_link = local_link::State::default();
                self.port_connectivity = self.port_number().map_or(
                    port_connectivity::State::Disabled,
                    port_connectivity::State::Waiting,
                );
                self.resolver
                    .update(name_resolution::Message::Start(self.host.trim().into()));
            }
            Message::Resolution(message) => self.resolver.update(message),
            Message::LocalLink(message) => self.local_link.update(message),
            Message::PortConnectivity(message) => self.port_connectivity.update(message),
            Message::Analyse | Message::HostEdited(_) | Message::PortEdited(_) => {
                return Task::none();
            }
        }
        self.next_checks()
    }

    fn next_checks(&mut self) -> Task<Message> {
        if self.target_ip.is_none()
            && let Some(target) = self.resolver.target()
        {
            self.target_ip = Some(target);
            self.local_link.start(target);
            self.port_connectivity.start(target);
        }
        let resolution = self.resolver.next_checks().map(Message::Resolution);
        let link = self.local_link.next_checks().map(Message::LocalLink);
        let port = self
            .port_connectivity
            .next_checks()
            .map(Message::PortConnectivity);

        // Claim ready checks before returning to iced, where other checks may finish.
        self.resolver
            .update(name_resolution::Message::ChecksStarted);
        self.local_link.update(local_link::Message::ChecksStarted);
        self.port_connectivity
            .update(port_connectivity::Message::CheckStarted);
        Task::batch([resolution, link, port])
    }

    fn is_running(&self) -> bool {
        self.resolver.is_running()
            || self.local_link.is_running()
            || self.port_connectivity.is_running()
    }

    fn can_analyse(&self) -> bool {
        !self.host.trim().is_empty() && !self.is_running() && self.valid_port()
    }

    fn port_number(&self) -> Option<NonZeroU16> {
        self.port.parse().ok()
    }

    fn valid_port(&self) -> bool {
        self.port.is_empty() || self.port_number().is_some()
    }

    pub fn subscription(&self) -> Subscription<Message> {
        if !self.can_analyse() {
            return Subscription::none();
        }
        keyboard::listen().filter_map(|event| match event {
            keyboard::Event::KeyPressed {
                key: Key::Named(Named::Enter),
                modifiers,
                repeat: false,
                ..
            } if modifiers.is_empty() => Some(Message::Analyse),
            _ => None,
        })
    }

    pub fn view(&self) -> Element<'_, Message> {
        let submit = self.can_analyse().then_some(Message::Analyse);
        let form = column![
            column![
                text("Hostname or IP"),
                text_input("example.com", &self.host)
                    .id(HOST_INPUT_ID)
                    .on_input_maybe((!self.is_running()).then_some(Message::HostEdited))
                    .on_submit_maybe(submit.clone())
                    .padding([12, 16])
                    .style(crate::rounded_input_style),
            ]
            .spacing(6),
            column![
                text("Port (optional)"),
                text_input("", &self.port)
                    .on_input_maybe((!self.is_running()).then_some(Message::PortEdited))
                    .on_submit_maybe(submit.clone())
                    .padding([12, 16])
                    .style(crate::rounded_input_style),
                (!self.valid_port()).then(|| text("Enter a port from 1 to 65535.")),
            ]
            .spacing(6),
            (!self.port.trim().is_empty()).then(|| {
                column![
                    text("Protocol"),
                    pick_list(Protocol::ALL, self.protocol, Message::ProtocolSelected)
                        .placeholder("Select a protocol")
                        .padding([12, 16])
                        .width(Length::Fill),
                ]
                .spacing(6)
            }),
            button("Analyse").on_press_maybe(submit),
            matches!(self.resolver, name_resolution::Resolver::Invalid)
                .then(|| text("Enter a valid hostname or IP address.")),
        ]
        .spacing(16);

        let content = column![
            container(container(form).width(Length::Fill).max_width(680)).center_x(Length::Fill),
            self.resolver
                .view()
                .map(|view| view.map(Message::Resolution)),
            self.local_link
                .view()
                .map(|view| view.map(Message::LocalLink)),
            self.port_connectivity
                .view()
                .map(|view| view.map(Message::PortConnectivity)),
        ]
        .spacing(24);
        scrollable(container(content).width(Length::Fill).padding(24))
            .height(Length::Fill)
            .into()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_new_port_suggests_a_protocol_and_allows_a_manual_override() {
        let mut state = State::default();
        let _ = state.update(Message::PortEdited("443".into()));
        assert!(state.protocol == Some(Protocol::Https));
        let _ = state.update(Message::ProtocolSelected(Protocol::Unknown));
        let _ = state.update(Message::PortEdited("0443".into()));
        assert!(state.protocol == Some(Protocol::Unknown));
        for (port, protocol) in [
            ("8080", Some(Protocol::Http)),
            ("8006", Some(Protocol::Https)),
            ("8007", Some(Protocol::Https)),
            ("993", Some(Protocol::Tls)),
            ("12345", Some(Protocol::Autodetect)),
            ("", None),
        ] {
            let _ = state.update(Message::PortEdited(port.into()));
            assert!(state.protocol == protocol);
        }
    }

    #[test]
    fn host_input_filters_spaces_and_symbols_without_breaking_ipv6_or_idns() {
        let mut state = State::default();
        for (input, expected) in [
            (" bu\u{308}cher .example/@ ", "bu\u{308}cher.example"),
            ("[ 2001:db8::1 ]", "[2001:db8::1]"),
        ] {
            let _ = state.update(Message::HostEdited(input.into()));
            assert_eq!(state.host, expected);
        }
    }

    #[test]
    fn ip_literals_skip_name_resolution() {
        for host in ["192.0.2.1", "2001:db8::1", "[2001:db8::1]"] {
            let mut state = State::default();
            let _ = state.update(Message::HostEdited(host.into()));
            let ping = state.update(Message::Analyse);
            assert!(matches!(state.resolver, name_resolution::Resolver::Ip(_)));
            assert!(state.resolver.view().is_none());
            assert_eq!(state.target_ip, state.resolver.target());
            assert_eq!(ping.units(), 1);
        }
    }

    #[test]
    fn ping_and_tcp_start_as_soon_as_the_system_resolver_returns_an_ip() {
        let mut state = State::default();
        let _ = state.update(Message::HostEdited("example.com".into()));
        let _ = state.update(Message::PortEdited("443".into()));
        let _ = state.update(Message::Analyse);
        let _ = state.update(Message::Resolution(
            name_resolution::Message::CacheFinished(Ok(None)),
        ));
        assert!(!state.port_connectivity.is_running());

        let ip = "192.0.2.1".parse().unwrap();
        let tasks = state.update(Message::Resolution(
            name_resolution::Message::SystemFinished(Ok(vec![ip])),
        ));
        assert_eq!(state.target_ip, Some(ip));
        assert_eq!(state.host, "example.com");
        assert!(state.resolver.is_running());
        assert!(state.local_link.is_running());
        assert!(
            matches!(state.port_connectivity, port_connectivity::State::Checking(endpoint)
            if endpoint.ip() == ip && endpoint.port() == 443)
        );
        assert_eq!(tasks.units(), 2);
    }
}
