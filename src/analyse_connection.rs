mod certificate_overlay;
mod check_view;
mod local_link;
mod name_resolution;
mod port_connectivity;
mod tls;

use std::{fmt, net::IpAddr, num::NonZeroU16};

use iced::{
    Alignment, Element, Length, Subscription, Task,
    keyboard::{self, Key, key::Named},
    widget::{
        button, column, container, pick_list, row, scrollable, space, stack, text, text_input,
    },
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
    ShowCertificates,
    CloseCertificates,
}

#[derive(Default)]
pub struct State {
    host: String,
    port: String,
    protocol: Option<Protocol>,
    #[allow(dead_code, reason = "Reserved for protocol detection.")]
    detected_protocol: Option<Protocol>,
    target_ip: Option<IpAddr>,
    resolver: name_resolution::Resolver,
    local_link: local_link::State,
    port_connectivity: port_connectivity::State,
    tls: tls::State,
    certificate_overlay: certificate_overlay::ViewState,
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
            Message::ShowCertificates => {
                self.certificate_overlay.open = self.tls.certificates().is_some();
                return Task::none();
            }
            Message::CloseCertificates => {
                self.certificate_overlay.open = false;
                return Task::none();
            }
            Message::HostEdited(host) if self.can_edit() => {
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
                    self.tls = tls::State::default();
                }
                return Task::none();
            }
            Message::PortEdited(port) if self.can_edit() => {
                let port = port.chars().filter(char::is_ascii_digit).collect();
                if self.port != port {
                    let previous = self.port_number();
                    self.port = port;
                    let current = self.port_number();
                    if previous != current {
                        self.protocol = current.map(Protocol::for_port);
                    }
                    self.port_connectivity = port_connectivity::State::default();
                    self.tls = tls::State::default();
                }
                return Task::none();
            }
            Message::ProtocolSelected(protocol) if !self.certificate_overlay.open => {
                if self.protocol != Some(protocol) && !self.is_running() {
                    self.tls = tls::State::default();
                }
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
                self.tls = tls::State::new(self.host.trim(), self.protocol);
                self.resolver
                    .update(name_resolution::Message::Start(self.host.trim().into()));
            }
            Message::Resolution(message) => self.resolver.update(message),
            Message::LocalLink(message) => self.local_link.update(message),
            Message::PortConnectivity(port_connectivity::Message::TlsFinished(report)) => {
                self.tls.finish(report);
            }
            Message::PortConnectivity(message) => {
                self.port_connectivity.update(message);
                if self.port_connectivity.connected() {
                    self.tls.start();
                }
            }
            Message::Analyse
            | Message::HostEdited(_)
            | Message::PortEdited(_)
            | Message::ProtocolSelected(_) => {
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
            .next_checks(self.tls.request())
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
            || self.tls.is_running()
    }

    fn can_analyse(&self) -> bool {
        !self.host.trim().is_empty() && self.can_edit() && self.valid_port()
    }

    fn can_edit(&self) -> bool {
        !self.is_running() && !self.certificate_overlay.open
    }

    fn port_number(&self) -> Option<NonZeroU16> {
        self.port.parse().ok()
    }

    fn valid_port(&self) -> bool {
        self.port.is_empty() || self.port_number().is_some()
    }

    pub fn subscription(&self) -> Subscription<Message> {
        if self.certificate_overlay.open {
            return keyboard::listen().filter_map(|event| match event {
                keyboard::Event::KeyPressed {
                    key: Key::Named(Named::Escape),
                    ..
                } => Some(Message::CloseCertificates),
                _ => None,
            });
        }
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
                    .on_input_maybe(self.can_edit().then_some(Message::HostEdited))
                    .on_submit_maybe(submit.clone())
                    .padding([12, 16])
                    .style(crate::rounded_input_style),
            ]
            .spacing(6),
            column![
                text("Port (optional)"),
                text_input("", &self.port)
                    .on_input_maybe(self.can_edit().then_some(Message::PortEdited))
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
            self.connectivity_view(),
        ]
        .spacing(24);
        let screen =
            scrollable(container(content).width(Length::Fill).padding(24)).height(Length::Fill);
        if self.certificate_overlay.open
            && let Some(chain) = self.tls.certificates()
        {
            stack![screen, certificate_overlay::view(chain)].into()
        } else {
            screen.into()
        }
    }

    fn connectivity_view(&self) -> Option<Element<'_, Message>> {
        let target = self.target_ip?;
        let target = self
            .port_connectivity
            .visible_endpoint()
            .map_or_else(|| target.to_string(), |endpoint| endpoint.to_string());
        check_view::connectivity(
            target,
            [
                (
                    "ARP-Table",
                    self.local_link
                        .arp_view()
                        .map(|view| view.map(Message::LocalLink)),
                ),
                (
                    "ICMP echo",
                    self.local_link
                        .ping_view()
                        .map(|view| view.map(Message::LocalLink)),
                ),
                (
                    "TCP connection",
                    self.port_connectivity
                        .view()
                        .map(|view| view.map(Message::PortConnectivity)),
                ),
                (
                    "TLS Handshake",
                    self.tls.view().map(|view| {
                        row![
                            view.map(Message::PortConnectivity),
                            space::horizontal(),
                            self.tls.certificates().map(|_| {
                                button("Show Certificates").on_press(Message::ShowCertificates)
                            }),
                        ]
                        .spacing(12)
                        .align_y(Alignment::Center)
                        .into()
                    }),
                ),
            ],
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tls_becomes_visible_only_after_tcp_succeeds_for_an_explicit_tls_protocol() {
        for (protocol, should_check_tls) in [
            (Protocol::Tls, true),
            (Protocol::Https, true),
            (Protocol::Http, false),
            (Protocol::Autodetect, false),
            (Protocol::Unknown, false),
        ] {
            let mut state = State::default();
            let _ = state.update(Message::HostEdited("192.0.2.1".into()));
            let _ = state.update(Message::PortEdited("443".into()));
            let _ = state.update(Message::ProtocolSelected(protocol));
            let _ = state.update(Message::Analyse);
            assert!(state.tls.view().is_none());
            let _ = state.update(Message::PortConnectivity(
                port_connectivity::Message::Finished(port_connectivity::Outcome::Connected),
            ));
            assert_eq!(state.tls.view().is_some(), should_check_tls);
        }
    }

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
