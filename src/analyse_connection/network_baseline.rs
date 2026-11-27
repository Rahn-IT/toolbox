use super::{
    check_view,
    local_link::{self, ArpResult},
    name_resolution::lookup,
    ping_check::PingResult,
    port_connectivity::{self, Outcome},
};
use crate::network_scanner::{interfaces, ping};
use iced::{Element, Task};
use std::net::IpAddr;

const CONTROL_HOST: &str = "example.com";

const PROBES: [(&str, [u8; 4]); 2] = [
    ("Google (8.8.8.8)", [8, 8, 8, 8]),
    ("Cloudflare (1.1.1.1)", [1, 1, 1, 1]),
];

#[derive(Clone)]
pub enum Message {
    PingFinished(usize, PingResult),
    RoutesFinished(RouteReport),
    GatewayFinished(usize, GatewayResult),
    LocalPingFinished(IpAddr, PingResult),
    TcpFinished(usize, Outcome),
    DnsFinished(Resolver, Result<Vec<IpAddr>, String>),
}

struct Gateway {
    ip: IpAddr,
    source: IpAddr,
    interface: Option<String>,
    result: Option<GatewayResult>,
}

#[derive(Clone)]
pub enum GatewayResult {
    Outside,
    Unavailable(String),
    Checked(PingResult, ArpResult),
}

impl Gateway {
    async fn check(ip: IpAddr, source: IpAddr, device: Option<String>) -> GatewayResult {
        let (IpAddr::V4(ip), IpAddr::V4(source)) = (ip, source) else {
            return GatewayResult::Unavailable("IPv4 subnet information unavailable".into());
        };
        let interfaces = match interfaces::list().await {
            Ok(interfaces) => interfaces,
            Err(error) => return GatewayResult::Unavailable(error.to_string()),
        };
        let mut matches = interfaces
            .iter()
            .filter(|i| i.ip == source && device.as_ref().is_none_or(|d| *d == i.name));
        let Some(interface) = matches.next() else {
            return GatewayResult::Unavailable("Source interface prefix unavailable".into());
        };
        if matches.any(|i| i.name != interface.name) {
            return GatewayResult::Unavailable("Ambiguous source interface".into());
        }
        if !interfaces
            .iter()
            .any(|i| i.name == interface.name && i.is_neighbor(ip))
        {
            return GatewayResult::Outside;
        }
        let ping = PingResult(match ping::prepare().await {
            Ok(runner) => runner.echo(Some(&interface.name), ip.into()).await,
            Err(error) => ping::Outcome::Failed(error),
        });
        let arp = local_link::read_arp(ip, source, interface.name.clone()).await;
        GatewayResult::Checked(ping, arp)
    }

    fn view(&self) -> Element<'_, Message> {
        use iced::widget::{row, space, text};
        let label = self.interface.as_ref().map_or_else(
            || self.ip.to_string(),
            |name| format!("{} · {name}", self.ip),
        );
        let line = row![text(label), space::horizontal()]
            .align_y(iced::Alignment::Center)
            .spacing(8);
        match &self.result {
            None => line.push(check_view::checking()),
            Some(GatewayResult::Outside) => {
                line.push(check_view::badge("Outside local network", false))
            }
            Some(GatewayResult::Unavailable(error)) => {
                line.push(check_view::error_badge("Gateway check unavailable", error))
            }
            Some(GatewayResult::Checked(ping, arp)) => {
                let icmp = match &ping.0 {
                    ping::Outcome::Reply(time) => check_view::badge(
                        time.as_ref().map_or_else(
                            || "ICMP reply".to_owned(),
                            |t| format!("ICMP reply · {t}"),
                        ),
                        true,
                    ),
                    ping::Outcome::Failed(error) => check_view::error_badge("ICMP failed", error),
                    _ => check_view::badge("ICMP no reply", false),
                };
                let arp = match arp {
                    ArpResult::Mac(mac) => check_view::badge(format!("ARP · {mac}"), true),
                    ArpResult::Failed(error) => check_view::error_badge("ARP unavailable", error),
                    _ => check_view::badge("No ARP entry", false),
                };
                line.push(icmp).push(arp)
            }
        }
        .into()
    }
}
#[derive(Clone)]
pub struct RouteReport {
    origins: interfaces::AddressOrigins,
    routes: [Result<interfaces::RouteDetails, interfaces::Error>; PROBES.len()],
    links: Result<interfaces::AdapterLinks, String>,
}

impl RouteReport {
    async fn read() -> Self {
        let (google, cloudflare, origins, links) = tokio::join!(
            interfaces::route_details(PROBES[0].1.into()),
            interfaces::route_details(PROBES[1].1.into()),
            interfaces::address_origins(),
            interfaces::adapter_links(),
        );
        let routes = [google, cloudflare];
        Self {
            routes,
            links,
            origins: origins.unwrap_or_default(),
        }
    }

    fn address_view(
        &self,
        interface: Option<&str>,
        source: IpAddr,
        show_name: bool,
    ) -> Element<'_, Message> {
        use iced::widget::{row, text};
        let name = interface.unwrap_or("Unknown interface");
        let mut result = row![text(if show_name {
            format!("{name} · {source}")
        } else {
            source.to_string()
        })]
        .spacing(8);
        if !show_name {
            result = result.push(iced::widget::space::horizontal());
        }
        if let IpAddr::V4(ip) = source {
            if ip.is_link_local() {
                result = result.push(check_view::warning_badge("Emergency address (link local)"));
            } else {
                if let Some(origin) = self.origins.get(&(name.to_owned(), ip)) {
                    result = result.push(check_view::badge(*origin, true));
                }
                if !ip.is_private() {
                    result = result.push(check_view::warning_badge("Outside private range"));
                }
            }
        }
        result.into()
    }

    fn no_routes(&self) -> bool {
        self.routes
            .iter()
            .all(|r| matches!(r, Err(interfaces::Error::NoRoute(_))))
    }

    fn adapter_rows(&self) -> Vec<(&str, Option<Element<'_, Message>>)> {
        use iced::widget::{column, row, text};
        let links = match &self.links {
            Ok(links) => links,
            Err(error) => {
                return vec![(
                    "Adapters",
                    Some(check_view::error_badge("Status unavailable", error)),
                )];
            }
        };
        links
            .iter()
            .filter(|(name, _)| {
                self.no_routes()
                    || self
                        .routes
                        .iter()
                        .flatten()
                        .any(|route| route.interface.as_deref() == Some(name.as_str()))
            })
            .map(|(name, link)| {
                let mut addresses = column![].spacing(4).width(iced::Length::Fill);
                if link.ips.is_empty() {
                    addresses = addresses.push(text("-"));
                }
                for ip in &link.ips {
                    addresses = addresses.push(self.address_view(Some(name), (*ip).into(), false));
                }
                let status = match link.status {
                    "Link up" => check_view::badge(link.status, true),
                    "Cable disconnected" => check_view::badge(link.status, false),
                    _ => check_view::neutral_badge(link.status),
                };
                let kind = link.physical.map(|physical| {
                    check_view::neutral_badge(if physical { "Physical" } else { "Virtual" })
                });
                (
                    name.as_str(),
                    Some(row![addresses, kind, status].spacing(8).into()),
                )
            })
            .collect()
    }
    fn view(&self) -> Element<'_, Message> {
        use iced::widget::{column, row, text};
        let mut findings = column![].spacing(6);
        if let [Ok(first), Ok(second)] = &self.routes
            && first.interface == second.interface
            && first.source == second.source
        {
            return self.address_view(first.interface.as_deref(), first.source, true);
        }
        if self.no_routes() {
            return findings.push(check_view::badge("No route", false)).into();
        }
        for ((label, _), result) in PROBES.iter().zip(&self.routes) {
            let detail: Element<'_, Message> = match result {
                Ok(route) => self.address_view(route.interface.as_deref(), route.source, true),
                Err(interfaces::Error::NoRoute(_)) => check_view::badge("No IPv4 route", false),
                Err(error) => check_view::error_badge("Route unavailable", error.to_string()),
            };
            findings = findings.push(row![text(*label), detail].spacing(8));
        }
        findings.into()
    }
}

#[derive(Clone, Copy)]
pub enum Resolver {
    System,
    Fresh,
    Configured,
    Cloudflare,
    Google,
}

impl Resolver {
    const ALL: [Self; 5] = [
        Self::System,
        Self::Fresh,
        Self::Configured,
        Self::Cloudflare,
        Self::Google,
    ];

    fn label(self) -> &'static str {
        match self {
            Self::System => "System DNS",
            Self::Fresh => "Fresh hostname",
            Self::Configured => "Configured DNS",
            Self::Cloudflare => "Cloudflare DNS (HTTPS)",
            Self::Google => "Google DNS (HTTPS)",
        }
    }

    async fn lookup(self, host: String) -> Result<Vec<IpAddr>, String> {
        if matches!(self, Self::System | Self::Fresh) {
            return crate::dns::system_lookup(host).await;
        }
        let name =
            hickory_client::proto::rr::Name::from_ascii(host).map_err(|error| error.to_string())?;
        let report = match self {
            Self::Configured => lookup::configured(name).await.1,
            Self::Cloudflare => lookup::public(lookup::CLOUDFLARE, name).await,
            Self::Google => lookup::public(lookup::GOOGLE, name).await,
            Self::System | Self::Fresh => unreachable!(),
        }?;
        let addresses: Vec<_> = report.addresses.into_iter().flatten().flatten().collect();
        if addresses.is_empty() && !report.details.is_empty() {
            return Err(report.details);
        }
        Ok(addresses)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gateway_arp_controls_tcp_per_route_and_tcp_success_starts_dns_once() {
        let mut state = State::default();
        let routes = [1, 2].map(|n| {
            Ok(interfaces::RouteDetails {
                interface: Some(format!("Adapter {n}")),
                source: [10, n, 0, 2].into(),
                gateway: Some([10, n, 0, 1].into()),
            })
        });
        let _ = state.update(Message::RoutesFinished(RouteReport {
            routes,
            origins: Default::default(),
            links: Ok(Default::default()),
        }));
        let arp = |mac| GatewayResult::Checked(PingResult(ping::Outcome::NoReply), mac);
        assert_eq!(
            state
                .update(Message::GatewayFinished(0, arp(ArpResult::Missing)))
                .units(),
            2
        );
        assert!(
            state
                .local_pings
                .contains_key(&IpAddr::from([127, 0, 0, 1]))
        );
        assert!(state.local_pings.contains_key(&IpAddr::from([10, 1, 0, 2])));
        assert_eq!(
            state
                .update(Message::GatewayFinished(
                    1,
                    arp(ArpResult::Mac("00:11:22:33:44:55".into()))
                ))
                .units(),
            1
        );
        assert!(matches!(state.tcp, [Check::Idle, Check::Checking]));
        assert_eq!(
            state
                .update(Message::TcpFinished(1, Outcome::Connected))
                .units(),
            1
        );
        assert!(matches!(
            state.dns[Resolver::System as usize],
            Check::Checking
        ));
    }

    #[test]
    fn gatewayless_route_starts_tcp_while_other_route_checks_gateway() {
        let mut state = State::default();
        let routes = [None, Some([10, 0, 0, 1].into())].map(|gateway| {
            Ok(interfaces::RouteDetails {
                interface: None,
                source: [10, 0, 0, 2].into(),
                gateway,
            })
        });
        let tasks = state.update(Message::RoutesFinished(RouteReport {
            routes,
            origins: Default::default(),
            links: Ok(Default::default()),
        }));
        assert_eq!(tasks.units(), 2);
        assert_eq!(state.gateways.len(), 1);
        assert!(matches!(state.tcp, [Check::Checking, Check::Idle]));
        assert_eq!(
            state
                .update(Message::TcpFinished(0, Outcome::Connected))
                .units(),
            1
        );
    }

    #[test]
    fn adapters_are_filtered_by_the_routes_to_the_probes() {
        let mut report = RouteReport {
            origins: Default::default(),
            routes: PROBES.map(|(_, ip)| Err(interfaces::Error::NoRoute(ip.into()))),
            links: Ok(["Ethernet", "VPN", "vEthernet"]
                .map(|name| (name.into(), interfaces::AdapterLink::default()))
                .into()),
        };
        let names = |report: &RouteReport| {
            report
                .adapter_rows()
                .into_iter()
                .map(|(name, _)| name.to_owned())
                .collect::<Vec<_>>()
        };
        assert_eq!(names(&report), ["Ethernet", "VPN", "vEthernet"]);
        let route = |name: &str| {
            Ok(interfaces::RouteDetails {
                interface: Some(name.into()),
                source: [192, 0, 2, 1].into(),
                gateway: None,
            })
        };
        report.routes[0] = route("Ethernet");
        assert_eq!(names(&report), ["Ethernet"]);
        report.routes[1] = route("Ethernet");
        assert_eq!(names(&report), ["Ethernet"]);
        report.routes[1] = route("VPN");
        assert_eq!(names(&report), ["Ethernet", "VPN"]);
    }

    #[test]
    fn both_public_pings_must_finish_without_a_reply_to_check_routes() {
        let mut state = State::default();
        let _ = state.start();
        assert_eq!(
            state
                .update(Message::PingFinished(
                    1,
                    PingResult(ping::Outcome::TimedOut)
                ))
                .units(),
            0
        );
        assert_eq!(
            state
                .update(Message::PingFinished(0, PingResult(ping::Outcome::NoReply)))
                .units(),
            1
        );
        assert!(state.is_running());
        assert!(matches!(
            state.dns[Resolver::System as usize],
            DnsCheck::Idle
        ));
        let _ = state.update(Message::RoutesFinished(RouteReport {
            origins: Default::default(),
            routes: PROBES.map(|(_, ip)| Err(interfaces::Error::NoRoute(ip.into()))),
            links: Ok(Default::default()),
        }));
        assert!(!state.is_running());
    }

    #[test]
    fn public_fallback_only_runs_after_configured_dns_fails() {
        for configured in [
            Ok(vec![[192, 0, 2, 1].into()]),
            Err("Server failure".into()),
        ] {
            let mut state = State::default();
            let _ = state.start_dns(Resolver::System);
            assert_eq!(
                state
                    .update(Message::DnsFinished(Resolver::System, Ok(vec![])))
                    .units(),
                1
            );
            let failed = configured.is_err();
            assert_eq!(
                state
                    .update(Message::DnsFinished(Resolver::Configured, configured))
                    .units(),
                if failed { 2 } else { 0 }
            );
            assert_eq!(state.is_running(), failed);
            if failed {
                let _ = state.update(Message::DnsFinished(
                    Resolver::Google,
                    Err("Timed out".into()),
                ));
                assert!(state.is_running());
                let _ = state.update(Message::DnsFinished(
                    Resolver::Cloudflare,
                    Ok(vec![[192, 0, 2, 1].into()]),
                ));
                assert!(!state.is_running());
            }
        }
    }

    #[test]
    fn first_reply_starts_one_lookup_per_run() {
        let mut state = State::default();
        for first in [ping::Outcome::Reply(None), ping::Outcome::TimedOut] {
            let _ = state.start();
            let replied = matches!(first, ping::Outcome::Reply(_));
            assert_eq!(
                state
                    .update(Message::PingFinished(0, PingResult(first)))
                    .units(),
                usize::from(replied)
            );
            assert_eq!(
                state
                    .update(Message::PingFinished(
                        1,
                        PingResult(ping::Outcome::Reply(None))
                    ))
                    .units(),
                usize::from(!replied)
            );
            assert!(state.is_running());
            let _ = state.update(Message::DnsFinished(
                Resolver::System,
                Ok(vec![[192, 0, 2, 1].into()]),
            ));
            assert!(state.is_running());
            let _ = state.update(Message::DnsFinished(
                Resolver::Fresh,
                Ok(vec![[192, 0, 2, 2].into()]),
            ));
            assert!(!state.is_running());
        }
    }
}

#[cfg(test)]
#[test]
fn fresh_failures_compare_the_same_name_and_end_inconclusively() {
    let mut state = State::default();
    let _ = state.start_dns(Resolver::System);
    let _ = state.update(Message::DnsFinished(
        Resolver::System,
        Ok(vec![[192, 0, 2, 1].into()]),
    ));
    let fresh = state.dns_host(Resolver::Fresh).to_owned();
    assert!(fresh.ends_with(".translate.goog."));
    assert_eq!(state.dns_host(Resolver::System), CONTROL_HOST);
    for resolver in [
        Resolver::Fresh,
        Resolver::Configured,
        Resolver::Google,
        Resolver::Cloudflare,
    ] {
        assert_eq!(state.dns_host(resolver), fresh);
        assert!(!state.fresh_inconclusive());
        let _ = state.update(Message::DnsFinished(resolver, Err("Lookup failed".into())));
    }
    assert!(state.fresh_inconclusive());
}

#[derive(Default)]
enum Check<T> {
    #[default]
    Idle,
    Checking,
    Complete(T),
}

type DnsCheck = Check<Result<Vec<IpAddr>, String>>;

#[derive(Default)]
pub struct State {
    fresh_host: Option<String>,
    results: Option<[Option<PingResult>; PROBES.len()]>,
    dns: [DnsCheck; Resolver::ALL.len()],
    routes: Option<RouteReport>,
    checking_routes: bool,
    gateways: Vec<Gateway>,
    local_pings: std::collections::BTreeMap<IpAddr, Option<PingResult>>,
    tcp: [Check<Outcome>; PROBES.len()],
}

impl State {
    pub fn start(&mut self) -> Task<Message> {
        self.fresh_host = None;
        self.results = Some([None, None]);
        self.dns = Default::default();
        self.routes = None;
        self.checking_routes = false;
        self.gateways.clear();
        self.local_pings.clear();
        self.tcp = Default::default();
        Task::batch(PROBES.into_iter().enumerate().map(|(index, (_, ip))| {
            Task::perform(PingResult::check(ip.into()), move |result| {
                Message::PingFinished(index, result)
            })
        }))
    }

    pub fn update(&mut self, message: Message) -> Task<Message> {
        match message {
            Message::PingFinished(index, result) => {
                let Some(results) = &mut self.results else {
                    return Task::none();
                };
                let replied = matches!(result.0, ping::Outcome::Reply(_));
                if results[index].is_some() {
                    return Task::none();
                }
                results[index] = Some(result);
                if replied && matches!(self.dns[Resolver::System as usize], DnsCheck::Idle) {
                    return self.start_dns(Resolver::System);
                }
                if results.iter().all(|r| {
                    r.as_ref()
                        .is_some_and(|p| !matches!(p.0, ping::Outcome::Reply(_)))
                }) {
                    self.checking_routes = true;
                    return Task::perform(RouteReport::read(), Message::RoutesFinished);
                }
            }
            Message::RoutesFinished(report) => {
                self.checking_routes = false;
                let mut tasks = Vec::new();
                for (probe, route) in report.routes.iter().enumerate() {
                    let Ok(route) = route else { continue };
                    let Some(ip) = route.gateway else {
                        tasks.push(Self::start_tcp(probe, &mut self.tcp[probe]));
                        continue;
                    };
                    if self.gateways.iter().any(|g| {
                        g.ip == ip && g.source == route.source && g.interface == route.interface
                    }) {
                        continue;
                    }
                    let index = self.gateways.len();
                    let device = route.interface.clone();
                    tasks.push(Task::perform(
                        Gateway::check(ip, route.source, device),
                        move |result| Message::GatewayFinished(index, result),
                    ));
                    self.gateways.push(Gateway {
                        ip,
                        source: route.source,
                        interface: route.interface.clone(),
                        result: None,
                    });
                }
                self.routes = Some(report);
                return Task::batch(tasks);
            }
            Message::GatewayFinished(index, result) => {
                let gateway = &mut self.gateways[index];
                let arp_found = matches!(result, GatewayResult::Checked(_, ArpResult::Mac(_)));
                let check_local = matches!(&result, GatewayResult::Checked(ping, ArpResult::Missing)
                    if !matches!(ping.0, ping::Outcome::Reply(_)));
                gateway.result = Some(result);
                if check_local {
                    let mut tasks = Vec::new();
                    for ip in [IpAddr::V4(std::net::Ipv4Addr::LOCALHOST), gateway.source] {
                        if let std::collections::btree_map::Entry::Vacant(entry) =
                            self.local_pings.entry(ip)
                        {
                            entry.insert(None);
                            tasks.push(Task::perform(PingResult::check(ip), move |result| {
                                Message::LocalPingFinished(ip, result)
                            }));
                        }
                    }
                    return Task::batch(tasks);
                }
                if arp_found && let Some(report) = &self.routes {
                    let mut tasks = Vec::new();
                    for (probe, route) in report.routes.iter().enumerate() {
                        if let Ok(route) = route
                            && route.gateway == Some(gateway.ip)
                            && route.source == gateway.source
                            && route.interface == gateway.interface
                        {
                            tasks.push(Self::start_tcp(probe, &mut self.tcp[probe]));
                        }
                    }
                    return Task::batch(tasks);
                }
            }
            Message::TcpFinished(probe, outcome) => {
                let connected = outcome == Outcome::Connected;
                self.tcp[probe] = Check::Complete(outcome);
                if connected && matches!(self.dns[Resolver::System as usize], Check::Idle) {
                    return self.start_dns(Resolver::System);
                }
            }
            Message::LocalPingFinished(ip, result) => {
                self.local_pings.insert(ip, Some(result));
            }
            Message::DnsFinished(resolver, result) => {
                let state = &mut self.dns[resolver as usize];
                if !matches!(state, DnsCheck::Checking) {
                    return Task::none();
                }
                let resolved = result.as_ref().is_ok_and(|ips| !ips.is_empty());
                *state = DnsCheck::Complete(result);
                if resolved && matches!(resolver, Resolver::System) {
                    use std::hash::{BuildHasher, RandomState};
                    let nonce = RandomState::new().hash_one(());
                    self.fresh_host = Some(format!("probe-{nonce:016x}.translate.goog."));
                    return self.start_dns(Resolver::Fresh);
                }
                if !resolved {
                    return match resolver {
                        Resolver::System | Resolver::Fresh => self.start_dns(Resolver::Configured),
                        Resolver::Configured => Task::batch([
                            self.start_dns(Resolver::Cloudflare),
                            self.start_dns(Resolver::Google),
                        ]),
                        _ => Task::none(),
                    };
                }
            }
        }
        Task::none()
    }

    fn start_tcp(probe: usize, state: &mut Check<Outcome>) -> Task<Message> {
        if !matches!(state, Check::Idle) {
            return Task::none();
        }
        *state = Check::Checking;
        let endpoint = (PROBES[probe].1, 443).into();
        Task::perform(
            async move {
                match port_connectivity::connect(endpoint).await {
                    Ok(_) => Outcome::Connected,
                    Err(outcome) => outcome,
                }
            },
            move |outcome| Message::TcpFinished(probe, outcome),
        )
    }

    fn dns_host(&self, resolver: Resolver) -> &str {
        if matches!(resolver, Resolver::System) {
            CONTROL_HOST
        } else {
            self.fresh_host.as_deref().unwrap_or(CONTROL_HOST)
        }
    }

    fn fresh_inconclusive(&self) -> bool {
        self.fresh_host.is_some()
            && [
                Resolver::Fresh,
                Resolver::Configured,
                Resolver::Cloudflare,
                Resolver::Google,
            ]
            .iter()
            .all(|r| match &self.dns[*r as usize] {
                Check::Complete(result) => !result.as_ref().is_ok_and(|ips| !ips.is_empty()),
                _ => false,
            })
    }

    fn start_dns(&mut self, resolver: Resolver) -> Task<Message> {
        self.dns[resolver as usize] = DnsCheck::Checking;
        Task::perform(
            resolver.lookup(self.dns_host(resolver).to_owned()),
            move |result| Message::DnsFinished(resolver, result),
        )
    }

    pub fn is_running(&self) -> bool {
        self.checking_routes
            || self
                .tcp
                .iter()
                .any(|check| matches!(check, Check::Checking))
            || self.gateways.iter().any(|g| g.result.is_none())
            || self.local_pings.values().any(Option::is_none)
            || self
                .dns
                .iter()
                .any(|state| matches!(state, DnsCheck::Checking))
            || self
                .results
                .as_ref()
                .is_some_and(|results| results.iter().any(Option::is_none))
    }

    pub fn view(&self) -> Option<Element<'_, Message>> {
        let results = self.results.as_ref()?;
        let dns = Resolver::ALL.into_iter().map(|resolver| {
            let result = match &self.dns[resolver as usize] {
                DnsCheck::Idle => None,
                DnsCheck::Checking => Some(check_view::checking()),
                DnsCheck::Complete(_)
                    if matches!(resolver, Resolver::Fresh) && self.fresh_inconclusive() =>
                {
                    Some(check_view::neutral_badge("Probe inconclusive"))
                }
                DnsCheck::Complete(Ok(ips)) if !ips.is_empty() => {
                    Some(check_view::badge("Resolved", true))
                }
                DnsCheck::Complete(Ok(_)) => {
                    Some(check_view::badge("No addresses returned", false))
                }
                DnsCheck::Complete(Err(error)) => {
                    Some(check_view::error_badge("Lookup failed", error))
                }
            };
            (
                resolver.label(),
                result.map(|result| {
                    iced::widget::row![result, iced::widget::text(self.dns_host(resolver))]
                        .spacing(8)
                        .align_y(iced::Alignment::Center)
                        .into()
                }),
            )
        });
        check_view::table(
            "Network baseline",
            None,
            PROBES
                .iter()
                .zip(results)
                .map(|((label, _), result)| {
                    (
                        *label,
                        Some(
                            result
                                .as_ref()
                                .map_or_else(check_view::checking, PingResult::view),
                        ),
                    )
                })
                .chain([(
                    "IP route",
                    if self.checking_routes {
                        Some(check_view::checking())
                    } else {
                        self.routes.as_ref().map(RouteReport::view)
                    },
                )])
                .chain(self.routes.iter().flat_map(RouteReport::adapter_rows))
                .chain(self.gateways.iter().map(|g| ("Gateway", Some(g.view()))))
                .chain(self.local_pings.iter().map(|(ip, result)| {
                    let label = if ip == &IpAddr::V4(std::net::Ipv4Addr::LOCALHOST) {
                        "Loopback ICMP"
                    } else {
                        "Local address ICMP"
                    };
                    let status = result
                        .as_ref()
                        .map_or_else(check_view::checking, PingResult::view);
                    (
                        label,
                        Some(
                            iced::widget::row![
                                iced::widget::text(ip.to_string()),
                                iced::widget::space::horizontal(),
                                status
                            ]
                            .spacing(8)
                            .into(),
                        ),
                    )
                }))
                .chain(self.tcp.iter().zip(PROBES).map(|(check, (_, ip))| {
                    let result = match check {
                        Check::Idle => None,
                        Check::Checking => Some(check_view::checking()),
                        Check::Complete(outcome) => Some(outcome.view()),
                    };
                    (
                        "Public TCP",
                        result.map(|result| {
                            iced::widget::row![
                                iced::widget::text(format!("{}:443", IpAddr::from(ip))),
                                iced::widget::space::horizontal(),
                                result
                            ]
                            .spacing(8)
                            .into()
                        }),
                    )
                }))
                .chain(dns),
        )
    }
}
