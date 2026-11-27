mod certificate_overlay;
mod check_view;
mod http;
mod local_link;
mod name_resolution;
mod port_connectivity;
mod protocol_detection;
#[cfg(test)]
mod screenshot;
mod tls;

use std::{fmt, net::IpAddr, num::NonZeroU16};

use crate::network_scanner::interfaces;
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
    Autodetect,
}

impl Protocol {
    const ALL: [Self; 4] = [Self::Autodetect, Self::Http, Self::Https, Self::Tls];

    fn for_port(port: NonZeroU16) -> Option<Self> {
        match crate::network_scanner::ports::web_protocol(port.get()) {
            Some("http") => Some(Self::Http),
            Some("https") => Some(Self::Https),
            _ if port.get() == 8007 => Some(Self::Https),
            _ if matches!(port.get(), 465 | 636 | 853 | 993 | 995) => Some(Self::Tls),
            _ => None,
        }
    }
}

impl fmt::Display for Protocol {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Http => "HTTP",
            Self::Https => "HTTPS",
            Self::Tls => "TLS",
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
    RouteFinished(Result<interfaces::RouteDetails, interfaces::Error>),
    PortConnectivity(port_connectivity::Message),
    HttpFinished(Result<http::Report, String>),
    ShowCertificates,
    CloseCertificates,
}

#[derive(Default)]
pub struct State {
    host: String,
    port: String,
    protocol: Option<Protocol>,
    passive_result: protocol_detection::Check,
    active_result: protocol_detection::Check,
    target_ip: Option<IpAddr>,
    resolver: name_resolution::Resolver,
    local_link: local_link::State,
    route: Option<Result<interfaces::RouteDetails, interfaces::Error>>,
    port_connectivity: port_connectivity::State,
    tls: tls::State,
    http: http::State,
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
                    self.route = None;
                    self.resolver = name_resolution::Resolver::default();
                    self.local_link = local_link::State::default();
                    self.port_connectivity = port_connectivity::State::default();
                    self.reset_protocol_checks();
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
                        self.protocol = current.and_then(Protocol::for_port);
                    }
                    self.port_connectivity = port_connectivity::State::default();
                    self.reset_protocol_checks();
                }
                return Task::none();
            }
            Message::ProtocolSelected(protocol) if self.can_edit() => {
                self.protocol = (protocol != Protocol::Autodetect).then_some(protocol);
                return Task::none();
            }
            Message::Analyse if self.can_analyse() => {
                self.target_ip = None;
                self.route = None;
                self.resolver = name_resolution::Resolver::default();
                self.local_link = local_link::State::default();
                self.port_connectivity = self.port_number().map_or(
                    port_connectivity::State::Disabled,
                    port_connectivity::State::Waiting,
                );
                self.reset_protocol_checks();
                self.resolver
                    .update(name_resolution::Message::Start(self.host.trim().into()));
            }
            Message::Resolution(message) => self.resolver.update(message),
            Message::LocalLink(message) => self.local_link.update(message),
            Message::RouteFinished(result) => self.route = Some(result),
            Message::HttpFinished(report) => self.http = http::State::Complete(report),
            Message::PortConnectivity(message) => {
                use port_connectivity::Message as CheckMessage;
                use protocol_detection::Check;
                match message {
                    CheckMessage::Finished(port_connectivity::Outcome::Connected) => {
                        self.port_connectivity.update(message);
                        if self.port_connectivity.connected() {
                            self.passive_result = Check::Checking;
                        }
                    }
                    CheckMessage::PassiveFinished(detected) => {
                        self.passive_result = Check::Complete(detected);
                        if detected.is_none() {
                            self.active_result = Check::Checking;
                        }
                    }
                    CheckMessage::TlsStarted => self.tls.start(),
                    CheckMessage::TlsFinished(report) => self.tls.finish(report),
                    CheckMessage::ActiveFinished(detected) => {
                        self.active_result = Check::Complete(detected);
                    }
                    _ => self.port_connectivity.update(message),
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

    fn reset_protocol_checks(&mut self) {
        self.passive_result = protocol_detection::Check::Skipped;
        self.active_result = protocol_detection::Check::Skipped;
        self.tls = tls::State::default();
        self.http = http::State::default();
    }

    fn next_checks(&mut self) -> Task<Message> {
        let route = if self.target_ip.is_none()
            && let Some(target) = self.resolver.target()
        {
            self.target_ip = Some(target);
            self.local_link.start(target);
            self.port_connectivity.start(target);
            Task::perform(interfaces::route_details(target), Message::RouteFinished)
        } else {
            Task::none()
        };
        let resolution = self.resolver.next_checks().map(Message::Resolution);
        let link = self.local_link.next_checks().map(Message::LocalLink);
        let port = self
            .port_connectivity
            .next_checks(self.host.trim())
            .map(Message::PortConnectivity);
        let http = match (
            self.http_scheme(),
            self.port_connectivity.visible_endpoint(),
        ) {
            (Some(https), Some(endpoint)) if self.port_connectivity.connected() => {
                self.http.start(self.host.trim(), endpoint, https)
            }
            _ => Task::none(),
        };

        // Claim ready checks before returning to iced, where other checks may finish.
        self.resolver
            .update(name_resolution::Message::ChecksStarted);
        self.local_link.update(local_link::Message::ChecksStarted);
        self.port_connectivity
            .update(port_connectivity::Message::CheckStarted);
        Task::batch([resolution, link, port, http, route])
    }

    fn is_running(&self) -> bool {
        self.resolver.is_running()
            || self.local_link.is_running()
            || self.port_connectivity.is_running()
            || self.protocol_check_running()
            || self.http.is_running()
            || (self.target_ip.is_some() && self.route.is_none())
    }

    fn protocol_check_running(&self) -> bool {
        use protocol_detection::Check;
        matches!(self.passive_result, Check::Checking)
            || matches!(self.active_result, Check::Checking)
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
            self.http.view(self.can_edit()),
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

    fn protocol_view(&self) -> Option<Element<'_, Message>> {
        use protocol_detection::Check;
        if self.protocol_check_running() {
            return Some(check_view::checking());
        }
        if matches!(self.passive_result, Check::Skipped) {
            return None;
        }
        let Some(detected) = self.observed_protocol() else {
            return Some(text("Inconclusive").into());
        };
        let label = detected.to_string();
        let protocol = match self
            .protocol
            .and_then(|selected| detected.comparison(selected))
        {
            Some(matches) => check_view::badge(label, matches),
            None => text(label).into(),
        };
        Some(
            row![
                protocol,
                space::horizontal(),
                self.protocol_for_follow_up()
                    .is_some_and(|expected| detected.conflicts_with(expected))
                    .then(|| { check_view::badge("Protocol mismatch", false) }),
            ]
            .spacing(8)
            .align_y(Alignment::Center)
            .into(),
        )
    }

    fn observed_protocol(&self) -> Option<protocol_detection::Detected> {
        self.passive_result
            .detected()
            .or_else(|| self.active_result.detected())
    }

    fn protocol_for_follow_up(&self) -> Option<protocol_detection::Detected> {
        self.protocol
            .and_then(protocol_detection::Detected::from_selection)
            .or_else(|| self.observed_protocol())
    }

    fn uses_tls(&self) -> bool {
        matches!(
            self.protocol_for_follow_up(),
            Some(protocol_detection::Detected::Tls(_))
        )
    }

    fn http_scheme(&self) -> Option<bool> {
        use protocol_detection::{Application, Detected};
        match self.protocol {
            Some(Protocol::Http) => Some(false),
            Some(Protocol::Https) => Some(true),
            _ => match self.observed_protocol() {
                Some(Detected::Plain(Application::Http)) => Some(false),
                Some(Detected::Tls(Some(Application::Http))) => Some(true),
                _ => None,
            },
        }
    }

    fn connectivity_view(&self) -> Option<Element<'_, Message>> {
        let target = self.target_ip?;
        let target = self
            .port_connectivity
            .visible_endpoint()
            .map_or_else(|| target.to_string(), |endpoint| endpoint.to_string());
        let (interface, first_hop) = self.route_views();
        check_view::table(
            "Connectivity",
            Some(target),
            [
                ("Used Interface", Some(interface)),
                ("First Hop", first_hop),
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
                ("Detected Protocol", self.protocol_view()),
                (
                    "TLS Handshake",
                    self.uses_tls()
                        .then(|| self.tls.view())
                        .flatten()
                        .map(|view| {
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

    fn route_views(&self) -> (Element<'_, Message>, Option<Element<'_, Message>>) {
        match &self.route {
            None => (check_view::checking(), None),
            Some(Ok(route)) => (
                column![
                    route.interface.as_deref().map(text),
                    text(format!("Source {}", route.source)),
                ]
                .spacing(4)
                .into(),
                Some(
                    text(
                        route
                            .gateway
                            .map_or_else(|| "On-link".into(), |gateway| gateway.to_string()),
                    )
                    .into(),
                ),
            ),
            Some(Err(error)) => (
                check_view::error_badge("Route unavailable", error.to_string()),
                None,
            ),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn preference_keeps_explicit_selection_and_observation_independent() {
        use protocol_detection::{Application, Check, Detected};

        let ssh = Detected::Plain(Application::Ssh);
        let https = Detected::Tls(Some(Application::Http));
        let tls = Detected::Tls(None);
        let mut state = State {
            protocol: Some(Protocol::Https),
            passive_result: Check::Complete(Some(ssh)),
            ..State::default()
        };
        assert_eq!(state.observed_protocol(), Some(ssh));
        assert_eq!(state.protocol_for_follow_up(), Some(https));
        assert!(state.uses_tls());
        assert!(ssh.conflicts_with(https));
        assert!(!tls.conflicts_with(https));
        assert!(!https.conflicts_with(tls));
        state.protocol = None;
        assert_eq!(state.protocol_for_follow_up(), Some(ssh));
        assert!(!state.uses_tls());
        state.passive_result = Check::Complete(None);
        state.active_result = Check::Complete(Some(tls));
        assert!(state.uses_tls());
    }

    #[test]
    fn protocol_discovery_runs_after_tcp_for_every_selection() {
        for protocol in Protocol::ALL {
            let mut state = State::default();
            let _ = state.update(Message::HostEdited("192.0.2.1".into()));
            let _ = state.update(Message::PortEdited("443".into()));
            let _ = state.update(Message::ProtocolSelected(protocol));
            let _ = state.update(Message::Analyse);
            assert!(state.tls.view().is_none());
            assert!(state.protocol_view().is_none());
            let _ = state.update(Message::PortConnectivity(
                port_connectivity::Message::Finished(port_connectivity::Outcome::Connected),
            ));
            assert!(state.protocol_check_running());
            assert!(state.protocol_view().is_some());
            assert!(state.tls.view().is_none());
            let _ = state.update(Message::PortConnectivity(
                port_connectivity::Message::PassiveFinished(None),
            ));
            let _ = state.update(Message::PortConnectivity(
                port_connectivity::Message::TlsStarted,
            ));
            assert!(state.tls.view().is_some());
            assert!(state.protocol_check_running());
            let _ = state.update(Message::PortConnectivity(
                port_connectivity::Message::ActiveFinished(None),
            ));
            assert!(!state.protocol_check_running());
        }
    }

    #[test]
    fn a_new_port_suggests_a_protocol_and_allows_a_manual_override() {
        let mut state = State::default();
        let _ = state.update(Message::PortEdited("443".into()));
        assert!(state.protocol == Some(Protocol::Https));
        let _ = state.update(Message::ProtocolSelected(Protocol::Autodetect));
        let _ = state.update(Message::PortEdited("0443".into()));
        assert!(state.protocol.is_none());
        for (port, protocol) in [
            ("8080", Some(Protocol::Http)),
            ("8006", Some(Protocol::Https)),
            ("8007", Some(Protocol::Https)),
            ("993", Some(Protocol::Tls)),
            ("12345", None),
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
            assert_eq!(ping.units(), 2);
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
        assert_eq!(tasks.units(), 3);
    }
}
