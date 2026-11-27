mod lookup;

use std::{
    collections::BTreeSet,
    net::{IpAddr, Ipv6Addr, SocketAddr},
};

use hickory_client::proto::rr::Name;
use iced::{
    Alignment, Border, Color, Element, Length, Task, color,
    widget::{column, container, row, rule, text},
};
use lookup::{DnsReport, DnssecWarning};

#[derive(Default)]
enum Check<T> {
    #[default]
    Pending,
    Checking,
    Complete(T),
    Failed(String),
    Skipped,
}

impl<T> Check<T> {
    fn outstanding(&self) -> bool {
        matches!(self, Self::Pending | Self::Checking)
    }

    fn view<'a>(
        &'a self,
        complete: impl FnOnce(&'a T) -> Element<'a, Message>,
    ) -> Option<Element<'a, Message>> {
        Some(match self {
            Self::Pending | Self::Checking => row![crate::loading::spinner(), text("Checking")]
                .spacing(8)
                .align_y(Alignment::Center)
                .into(),
            Self::Complete(result) => complete(result),
            Self::Failed(error) => text(error).into(),
            Self::Skipped => return None,
        })
    }
}

impl<T> From<Result<T, String>> for Check<T> {
    fn from(result: Result<T, String>) -> Self {
        match result {
            Ok(value) => Self::Complete(value),
            Err(error) => Self::Failed(error),
        }
    }
}

#[derive(Clone)]
pub enum Message {
    Start(String),
    ChecksStarted,
    CacheFinished(Result<Option<String>, String>),
    SystemFinished(Result<Vec<IpAddr>, String>),
    NetBiosFinished(Result<Option<String>, String>),
    ConfiguredFinished(Option<SocketAddr>, Result<DnsReport, String>),
    DnsFinished(DnsCheck, Result<DnsReport, String>),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DnsCheck {
    Configured,
    Google,
    Cloudflare,
    Authoritative,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ReadyCheck {
    Cache,
    System,
    NetBios,
    Dns(DnsCheck),
}

#[derive(Default)]
pub enum Resolver {
    #[default]
    Empty,
    Invalid,
    Ip(IpAddr),
    Hostname(Box<HostnameChecks>),
}

impl Resolver {
    pub fn is_running(&self) -> bool {
        matches!(self, Self::Hostname(_)) && !self.done()
    }

    pub fn done(&self) -> bool {
        match self {
            Self::Empty => false,
            Self::Invalid | Self::Ip(_) => true,
            Self::Hostname(checks) => !checks.outstanding(),
        }
    }

    pub fn target(&self) -> Option<IpAddr> {
        match self {
            Self::Ip(ip) => Some(*ip),
            Self::Hostname(checks) => match &checks.system {
                Check::Complete(addresses) => addresses.first().copied(),
                _ => None,
            },
            _ => None,
        }
    }

    pub fn update(&mut self, message: Message) {
        match message {
            Message::Start(host) if matches!(self, Self::Empty) => {
                if let Some(ip) = parse_ip(&host) {
                    *self = Self::Ip(ip);
                    return;
                }
                let Ok(mut name) = Name::from_utf8(&host) else {
                    *self = Self::Invalid;
                    return;
                };
                if name.is_root() {
                    *self = Self::Invalid;
                    return;
                }
                name.set_fqdn(true);
                let ascii = name.to_ascii().to_ascii_lowercase();
                let local = name.num_labels() < 2
                    || ascii.ends_with(".local.")
                    || ascii.ends_with(".home.arpa.");
                let public = || {
                    if local {
                        Check::Skipped
                    } else {
                        Check::Pending
                    }
                };
                let netbios = if host.contains('.') {
                    Check::Skipped
                } else {
                    Check::Pending
                };
                *self = Self::Hostname(Box::new(HostnameChecks {
                    host,
                    name,
                    cache: Check::Pending,
                    system: Check::Pending,
                    netbios,
                    configured: Check::Pending,
                    configured_server: None,
                    google: public(),
                    cloudflare: public(),
                    authoritative: public(),
                }));
            }
            message => match self {
                Self::Hostname(checks) => checks.update(message),
                _ => {}
            },
        }
    }

    pub fn next_checks(&self) -> Task<Message> {
        match self {
            Self::Hostname(checks) => Task::batch(
                checks
                    .ready_checks()
                    .into_iter()
                    .map(|check| checks.task(check)),
            ),
            _ => Task::none(),
        }
    }

    pub fn view(&self) -> Option<Element<'_, Message>> {
        let content: Element<'_, Message> = match self {
            Self::Hostname(checks) if !matches!(checks.cache, Check::Pending) => checks.view(),
            _ => return None,
        };
        Some(
            column![text("Name Resolution").size(24), content]
                .spacing(12)
                .into(),
        )
    }
}

fn parse_ip(host: &str) -> Option<IpAddr> {
    host.parse().ok().or_else(|| {
        host.strip_prefix('[')?
            .strip_suffix(']')?
            .parse::<Ipv6Addr>()
            .ok()
            .map(IpAddr::V6)
    })
}

pub struct HostnameChecks {
    host: String,
    name: Name,
    cache: Check<Option<String>>,
    system: Check<Vec<IpAddr>>,
    netbios: Check<Option<String>>,
    configured: Check<DnsReport>,
    configured_server: Option<SocketAddr>,
    google: Check<DnsReport>,
    cloudflare: Check<DnsReport>,
    authoritative: Check<DnsReport>,
}

impl HostnameChecks {
    fn dns_checks(&self) -> [(DnsCheck, &Check<DnsReport>); 4] {
        [
            (DnsCheck::Configured, &self.configured),
            (DnsCheck::Google, &self.google),
            (DnsCheck::Cloudflare, &self.cloudflare),
            (DnsCheck::Authoritative, &self.authoritative),
        ]
    }

    fn dns_check_mut(&mut self, check: DnsCheck) -> &mut Check<DnsReport> {
        match check {
            DnsCheck::Configured => &mut self.configured,
            DnsCheck::Google => &mut self.google,
            DnsCheck::Cloudflare => &mut self.cloudflare,
            DnsCheck::Authoritative => &mut self.authoritative,
        }
    }

    fn outstanding(&self) -> bool {
        self.cache.outstanding()
            || self.system.outstanding()
            || self.netbios.outstanding()
            || self
                .dns_checks()
                .into_iter()
                .any(|(_, check)| check.outstanding())
    }

    fn update(&mut self, message: Message) {
        match message {
            Message::ChecksStarted => {
                for check in self.ready_checks() {
                    match check {
                        ReadyCheck::Cache => self.cache = Check::Checking,
                        ReadyCheck::System => self.system = Check::Checking,
                        ReadyCheck::NetBios => self.netbios = Check::Checking,
                        ReadyCheck::Dns(check) => *self.dns_check_mut(check) = Check::Checking,
                    }
                }
            }
            Message::CacheFinished(result) if matches!(self.cache, Check::Checking) => {
                self.cache = result.into();
            }
            Message::SystemFinished(result) if matches!(self.system, Check::Checking) => {
                if !result
                    .as_ref()
                    .is_ok_and(|addresses| addresses.iter().any(IpAddr::is_ipv4))
                {
                    self.netbios = Check::Skipped;
                }
                self.system = result.into();
            }
            Message::NetBiosFinished(result) if matches!(self.netbios, Check::Checking) => {
                self.netbios = result.into();
            }
            Message::ConfiguredFinished(server, result)
                if matches!(self.configured, Check::Checking) =>
            {
                self.configured_server = server;
                self.configured = result.into();
            }
            Message::DnsFinished(check, result) => {
                let state = self.dns_check_mut(check);
                if matches!(state, Check::Checking) {
                    *state = result.into();
                }
            }
            _ => {}
        }
    }

    fn ready_checks(&self) -> Vec<ReadyCheck> {
        match self.cache {
            Check::Pending => return vec![ReadyCheck::Cache],
            Check::Checking => return Vec::new(),
            _ => {}
        }

        let mut ready = Vec::new();
        if matches!(self.system, Check::Pending) {
            ready.push(ReadyCheck::System);
        }
        if matches!(self.netbios, Check::Pending) && matches!(self.system, Check::Complete(_)) {
            ready.push(ReadyCheck::NetBios);
        }
        ready.extend(self.dns_checks().into_iter().filter_map(|(check, state)| {
            matches!(state, Check::Pending).then_some(ReadyCheck::Dns(check))
        }));
        ready
    }

    fn task(&self, check: ReadyCheck) -> Task<Message> {
        match check {
            ReadyCheck::Cache => {
                let name = self.name.to_ascii();
                Task::perform(
                    async move { crate::dns_cache::lookup(&name).await },
                    Message::CacheFinished,
                )
            }
            ReadyCheck::System => {
                Task::perform(lookup::system(self.host.clone()), Message::SystemFinished)
            }
            ReadyCheck::NetBios => {
                let Check::Complete(addresses) = &self.system else {
                    return Task::none();
                };
                let ipv4 = addresses
                    .iter()
                    .filter_map(|address| match address {
                        IpAddr::V4(address) => Some(*address),
                        IpAddr::V6(_) => None,
                    })
                    .collect();
                Task::perform(lookup::netbios(ipv4), Message::NetBiosFinished)
            }
            ReadyCheck::Dns(check) => {
                let name = self.name.clone();
                Task::perform(
                    async move {
                        let result = match check {
                            DnsCheck::Configured => {
                                let (server, result) = lookup::configured(name).await;
                                return Message::ConfiguredFinished(server, result);
                            }
                            DnsCheck::Google => lookup::public(lookup::GOOGLE, name).await,
                            DnsCheck::Cloudflare => lookup::public(lookup::CLOUDFLARE, name).await,
                            DnsCheck::Authoritative => lookup::authoritative(name).await,
                        };
                        Message::DnsFinished(check, result)
                    },
                    std::convert::identity,
                )
            }
        }
    }

    fn view(&self) -> Element<'_, Message> {
        const CHECK_WIDTH: f32 = 160.0;
        let (local_override, system_override) = self.dns_overrides();
        let check = |label| column![text(label)].spacing(4).width(CHECK_WIDTH);
        let mut configured = check("Configured DNS");
        if let Some(server) = self.configured_server {
            configured = configured.push(
                text(server.to_string())
                    .size(13)
                    .wrapping(text::Wrapping::WordOrGlyph),
            );
        }
        let mut authority = check("Authoritative DNS");
        if let Check::Complete(report) = &self.authoritative {
            authority = authority.extend(report.nameservers.iter().map(|server| {
                text(server.to_ascii())
                    .size(13)
                    .wrapping(text::Wrapping::WordOrGlyph)
                    .into()
            }));
        }
        let entries = [
            (
                check("NetBIOS"),
                self.netbios
                    .view(|result| text(result.as_deref().unwrap_or("-")).into()),
            ),
            (
                check("DNS cache"),
                self.cache.view(|result| match result {
                    Some(records) => text(cache_addresses(records)).into(),
                    None => text("-").into(),
                }),
            ),
            (
                check("Local lookup"),
                self.system.view(|addresses| {
                    let summary = if addresses.is_empty() {
                        "No addresses returned".into()
                    } else {
                        addresses
                            .iter()
                            .map(ToString::to_string)
                            .collect::<Vec<_>>()
                            .join(", ")
                    };
                    row![
                        text(summary).width(Length::Fill),
                        system_override.then(|| override_badge("System DNS Override")),
                    ]
                    .spacing(12)
                    .into()
                }),
            ),
            (
                configured,
                self.configured.view(|report| {
                    row![
                        container(dns_result(report)).width(Length::Fill),
                        local_override.then(|| override_badge("Local DNS Override")),
                    ]
                    .spacing(12)
                    .into()
                }),
            ),
            (check("Google (DoH)"), self.google.view(dns_result)),
            (check("Cloudflare (DoH)"), self.cloudflare.view(dns_result)),
            (authority, self.authoritative.view(dns_result)),
        ];
        let rows = column(entries.into_iter().filter_map(|(check, value)| {
            Some(
                container(row![check, container(value?).width(Length::Fill)].spacing(12))
                    .width(Length::Fill)
                    .padding([10, 12])
                    .style(container::rounded_box)
                    .into(),
            )
        }))
        .spacing(6);

        column![
            container(row![text("Check").width(CHECK_WIDTH), text("Result")].spacing(12))
                .padding([0, 12]),
            rule::horizontal(1),
            rows,
        ]
        .spacing(8)
        .into()
    }

    fn dns_overrides(&self) -> (bool, bool) {
        let Check::Complete(configured) = &self.configured else {
            return (false, false);
        };
        let references = [&self.authoritative, &self.cloudflare, &self.google];
        let local_override = references.iter().all(|check| !check.outstanding())
            && configured
                .addresses
                .iter()
                .enumerate()
                .any(|(family, local)| {
                    let Some(local) = local else { return false };
                    let answers: Vec<_> = references
                        .iter()
                        .filter_map(|reference| match reference {
                            Check::Complete(report) => report.addresses[family].as_ref(),
                            _ => None,
                        })
                        .collect();
                    differs_from_consensus(local, &answers)
                });
        let system_override = match &self.system {
            Check::Complete(addresses) => {
                let system = [true, false].map(|ipv4| {
                    Some(
                        addresses
                            .iter()
                            .copied()
                            .filter(|ip| ip.is_ipv4() == ipv4)
                            .collect(),
                    )
                });
                different_addresses(&configured.addresses, &system)
            }
            _ => false,
        };
        (local_override, system_override)
    }
}

fn differs_from_consensus(local: &BTreeSet<IpAddr>, references: &[&BTreeSet<IpAddr>]) -> bool {
    let [first, _, ..] = references else {
        return false;
    };
    if references
        .iter()
        .any(|reference| *reference == local || !reference.is_disjoint(local))
    {
        return false;
    }

    if first.is_empty() {
        references.iter().all(|reference| reference.is_empty())
    } else {
        first
            .iter()
            .any(|ip| references.iter().all(|reference| reference.contains(ip)))
    }
}

fn different_addresses(
    left: &[Option<BTreeSet<IpAddr>>; 2],
    right: &[Option<BTreeSet<IpAddr>>; 2],
) -> bool {
    left.iter()
        .zip(right)
        .any(|(left, right)| match (left, right) {
            (Some(left), Some(right)) => left != right,
            _ => false,
        })
}

fn override_badge(label: &'static str) -> Element<'static, Message> {
    container(text(label).size(14).color(color!(0x241A00)))
        .padding([3, 8])
        .style(|_| container::background(color!(0xF2C94C)).border(Border::default().rounded(5.0)))
        .into()
}

impl From<String> for DnsReport {
    fn from(details: String) -> Self {
        Self {
            details,
            dnssec: None,
            nameservers: Vec::new(),
            addresses: [None, None],
        }
    }
}

fn dns_result(report: &DnsReport) -> Element<'_, Message> {
    let badge = report.dnssec.map(|warning| {
        let label = match warning {
            DnssecWarning::Unverified => "DNSSEC unverified",
            DnssecWarning::Unsupported => "DNSSEC not supported",
            DnssecWarning::ValidationFailed => "DNSSEC validation failed",
        };
        container(text(label).size(14).color(Color::WHITE))
            .padding([3, 8])
            .style(|_| {
                container::background(color!(0xB32539)).border(Border::default().rounded(5.0))
            })
    });
    let details = column(report.details.lines().map(|line| {
        if let Some(alias) = line.strip_prefix("CNAME ") {
            let tag =
                container(text("CNAME").size(14))
                    .padding([3, 8])
                    .style(|theme: &iced::Theme| {
                        let accent = theme.extended_palette().primary.weak;
                        container::background(accent.color)
                            .color(accent.text)
                            .border(Border::default().rounded(5.0))
                    });
            row![tag, text(alias).width(Length::Fill)]
                .align_y(Alignment::Center)
                .spacing(8)
                .into()
        } else {
            text(line).into()
        }
    }))
    .width(Length::Fill)
    .spacing(4);
    row![details, badge].spacing(12).into()
}

fn cache_addresses(records: &str) -> String {
    records
        .lines()
        .map(|line| {
            let payload = line.strip_prefix("IN ").unwrap_or(line);
            payload
                .strip_prefix("A ")
                .or_else(|| payload.strip_prefix("AAAA "))
                .unwrap_or(line)
        })
        .collect::<Vec<_>>()
        .join("\n")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn override_badges_compare_available_address_sets_independently() {
        let mut resolver = Resolver::default();
        resolver.update(Message::Start("example.com".into()));
        let Resolver::Hostname(checks) = &mut resolver else {
            panic!("expected hostname checks");
        };
        let first = IpAddr::from([192, 0, 2, 1]);
        let second = IpAddr::from([192, 0, 2, 2]);
        let third = IpAddr::from([192, 0, 2, 3]);
        let unrelated_v6 = "2001:db8::1".parse().unwrap();
        let answer = |ips: &[IpAddr]| {
            Check::Complete(DnsReport {
                addresses: [Some(ips.iter().copied().collect()), None],
                ..String::new().into()
            })
        };

        checks.configured = answer(&[first, second]);
        checks.system = Check::Complete(vec![second, first, unrelated_v6]);
        checks.authoritative = answer(&[first]);
        checks.cloudflare = answer(&[first]);
        checks.google = answer(&[third]);
        assert_eq!(checks.dns_overrides(), (false, false));

        checks.configured = answer(&[third]);
        checks.system = Check::Complete(vec![third]);
        checks.google = Check::Checking;
        assert_eq!(checks.dns_overrides(), (false, false));
        checks.google = Check::Failed("Timed out".into());
        assert_eq!(checks.dns_overrides(), (true, false));

        checks.system = Check::Complete(vec![second]);
        assert_eq!(checks.dns_overrides(), (true, true));

        checks.cloudflare = answer(&[second]);
        assert_eq!(checks.dns_overrides(), (false, true));
    }

    #[test]
    fn cache_completion_starts_dns_checks_and_dotted_hosts_skip_netbios() {
        let mut resolver = Resolver::default();
        assert!(!resolver.done());
        assert_eq!(resolver.next_checks().units(), 0);
        resolver.update(Message::Start("example.com".into()));
        assert_eq!(resolver.next_checks().units(), 1);
        resolver.update(Message::ChecksStarted);
        assert_eq!(resolver.next_checks().units(), 0);

        resolver.update(Message::CacheFinished(Err("Unavailable".into())));
        assert_eq!(resolver.next_checks().units(), 5);
        resolver.update(Message::ChecksStarted);
        let Resolver::Hostname(checks) = &resolver else {
            panic!("expected hostname checks")
        };
        assert!(matches!(checks.cache, Check::Failed(_)));
        assert!(matches!(checks.system, Check::Checking));
        assert!(matches!(checks.google, Check::Checking));
        assert!(matches!(checks.netbios, Check::Skipped));
        resolver.update(Message::DnsFinished(
            DnsCheck::Google,
            Ok("Answer".to_owned().into()),
        ));
        assert!(!resolver.done());
        assert_eq!(resolver.next_checks().units(), 0);

        let preferred = "2001:db8::1".parse().unwrap();
        resolver.update(Message::SystemFinished(Ok(vec![
            preferred,
            "192.0.2.1".parse().unwrap(),
        ])));
        assert_eq!(resolver.target(), Some(preferred));
        assert_eq!(resolver.next_checks().units(), 0);
        resolver.update(Message::ConfiguredFinished(
            Some("192.0.2.53:53".parse().unwrap()),
            Err("Timed out".into()),
        ));
        let Resolver::Hostname(checks) = &resolver else {
            panic!("expected hostname checks");
        };
        assert_eq!(
            checks.configured_server,
            Some("192.0.2.53:53".parse().unwrap())
        );
        assert!(matches!(checks.configured, Check::Failed(_)));
        for check in [DnsCheck::Cloudflare, DnsCheck::Authoritative] {
            resolver.update(Message::DnsFinished(check, Ok("Answer".to_owned().into())));
        }
        assert!(resolver.done());
    }

    #[test]
    fn a_single_label_host_checks_netbios_after_the_system_lookup() {
        let mut resolver = Resolver::default();
        resolver.update(Message::Start("fileserver".into()));
        resolver.update(Message::ChecksStarted);
        resolver.update(Message::CacheFinished(Ok(None)));
        assert_eq!(resolver.next_checks().units(), 2);
        resolver.update(Message::ChecksStarted);
        let Resolver::Hostname(checks) = &resolver else {
            panic!("expected hostname checks");
        };
        assert!(matches!(checks.netbios, Check::Pending));
        assert!(matches!(checks.google, Check::Skipped));
        let addresses = vec!["192.0.2.1".parse().unwrap()];
        resolver.update(Message::SystemFinished(Ok(addresses)));
        assert_eq!(resolver.next_checks().units(), 1);
        resolver.update(Message::ChecksStarted);
        assert_eq!(resolver.next_checks().units(), 0);
    }
}
