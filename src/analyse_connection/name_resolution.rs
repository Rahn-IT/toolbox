mod lookup;

use std::{
    collections::BTreeSet,
    net::{IpAddr, Ipv6Addr, SocketAddr},
};

use crate::dns::dnssec;
use hickory_client::proto::rr::Name;
use iced::{
    Alignment, Border, Element, Length, Task, color,
    widget::{column, container, row, rule, text},
};
use lookup::DnsReport;

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
            Self::Failed(error) => dns_details(error),
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
    DnssecFinished(PublicProvider, dnssec::Report),
    ConfiguredSignaturesFinished(dnssec::ConfiguredReport),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PublicProvider {
    Google,
    Cloudflare,
}

impl PublicProvider {
    const ALL: [Self; 2] = [Self::Google, Self::Cloudflare];

    fn name(self) -> &'static str {
        match self {
            Self::Google => "Google",
            Self::Cloudflare => "Cloudflare",
        }
    }

    fn server(self) -> crate::dns::Server {
        match self {
            Self::Google => lookup::GOOGLE,
            Self::Cloudflare => lookup::CLOUDFLARE,
        }
    }
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
    Dnssec(PublicProvider),
    ConfiguredSignatures(SocketAddr),
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
    #[cfg(test)]
    pub(super) fn screenshot_fixture(target: IpAddr) -> Self {
        let mut resolver = Self::Empty;
        resolver.update(Message::Start("portal.example".into()));
        let Self::Hostname(checks) = &mut resolver else {
            unreachable!("fixture uses a hostname");
        };
        let report = |details: String, address| DnsReport {
            details,
            addresses: [Some(BTreeSet::from([address])), None],
            nameservers: Vec::new(),
        };
        let public = || {
            report(
                "CNAME portal.example. → edge.example.\n198.51.100.24".into(),
                [198, 51, 100, 24].into(),
            )
        };
        let mut authority = public();
        authority
            .nameservers
            .push(Name::from_ascii("ns1.example.").unwrap());
        checks.cache = Check::Complete(Some(format!("IN A {target}")));
        checks.system = Check::Complete(vec![target]);
        checks.configured_server = Some(([192, 0, 2, 1], 53).into());
        checks.configured = Check::Complete(report("192.0.2.30".into(), [192, 0, 2, 30].into()));
        checks.google = Check::Complete(public());
        checks.cloudflare = Check::Complete(public());
        checks.authoritative = Check::Complete(authority);
        checks.dnssec = [Check::Skipped, Check::Skipped];
        checks.configured_signatures = Check::Skipped;
        resolver
    }

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
                    dnssec: [public_dnssec(local), public_dnssec(local)],
                    configured_signatures: Check::Pending,
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

    pub fn dnssec_view(&self) -> Option<Element<'_, Message>> {
        let Self::Hostname(checks) = self else {
            return None;
        };
        if matches!(checks.cache, Check::Pending | Check::Checking) {
            return None;
        }
        use dnssec::FindingKind::*;
        let configured = match &checks.configured_signatures {
            Check::Complete(report) => Some(report),
            _ => None,
        };
        let reports = PublicProvider::ALL
            .into_iter()
            .filter_map(|provider| {
                let Check::Complete(report) = &checks.dnssec[provider as usize] else {
                    return None;
                };
                Some((provider.name(), report))
            })
            .chain(configured.map(|report| ("Configured DNS", &report.validation)))
            .collect::<Vec<_>>();

        let mut findings: Vec<(&dnssec::Finding, Vec<&str>)> = Vec::new();
        for (source, report) in &reports {
            for finding in &report.details {
                if let Some((_, sources)) = findings.iter_mut().find(|(item, _)| *item == finding) {
                    sources.push(source);
                } else {
                    findings.push((finding, vec![source]));
                }
            }
        }

        let groups: &[(&str, &[dnssec::FindingKind])] = &[
            ("Root key", &[RootTrusted]),
            (
                "Delegations",
                &[
                    DelegationVerified,
                    KeysPublished,
                    UnsignedDelegation,
                    KeyLinkUnavailable,
                    DelegationUnavailable,
                ],
            ),
            (
                "Record signatures",
                &[
                    RecordVerified,
                    DenialVerified,
                    MissingSignature,
                    InvalidSignature,
                ],
            ),
            ("Unavailable", &[ProofUnavailable]),
        ];
        let mut rows = Vec::new();
        for &(label, kinds) in groups {
            let mut entries = findings
                .iter()
                .filter(|(finding, _)| kinds.contains(&finding.kind))
                .peekable();
            if entries.peek().is_some() {
                let results = column(entries.map(|(finding, sources)| {
                    let source = (sources.len() < reports.len()).then(|| sources.join(", "));
                    dnssec_finding(finding, source)
                }))
                .spacing(6);
                rows.push((label, Some(results.into())));
            }
        }
        if let Some(report) = configured
            && !report.observed.is_empty()
        {
            let result = column![dnssec_badge(report.validation.verdict)].extend(
                report
                    .observed
                    .iter()
                    .filter(|finding| finding.kind != SignaturesReturned)
                    .map(|finding| {
                        if finding.kind == NoSignaturesReturned && finding.answer.is_some() {
                            let sources = PublicProvider::ALL.into_iter().filter(|provider| {
                                matches!(&checks.dnssec[*provider as usize], Check::Complete(report)
                                    if report.details.iter().any(|public| public.kind == RecordVerified && public.answer == finding.answer))
                            }).map(|provider| provider.name()).collect::<Vec<_>>();
                            if !sources.is_empty() {
                                return row![
                                    super::check_view::warning_badge("Signature available but not returned"),
                                    text(format!("{} (validated by {})", finding.subject, sources.join(", "))),
                                ].align_y(Alignment::Center).spacing(8).into();
                            }
                        }
                        dnssec_finding(finding, None)
                    }),
            )
            .spacing(6);
            rows.push(("Configured DNS", Some(result.into())));
        }
        if checks.dnssec.iter().any(Check::outstanding)
            || checks.configured_signatures.outstanding()
        {
            rows.push(("Validation", Some(super::check_view::checking())));
        }
        super::check_view::table("DNSSEC", None, rows)
    }
}

fn public_dnssec(local: bool) -> Check<dnssec::Report> {
    if local {
        Check::Skipped
    } else {
        Check::Pending
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
    dnssec: [Check<dnssec::Report>; 2],
    configured_signatures: Check<dnssec::ConfiguredReport>,
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
            || self.dnssec.iter().any(Check::outstanding)
            || self.configured_signatures.outstanding()
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
                        ReadyCheck::Dnssec(provider) => {
                            self.dnssec[provider as usize] = Check::Checking
                        }
                        ReadyCheck::ConfiguredSignatures(_) => {
                            self.configured_signatures = Check::Checking
                        }
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
                if server.is_none() {
                    self.configured_signatures =
                        Check::Complete(dnssec::ConfiguredReport::unavailable());
                }
            }
            Message::DnsFinished(check, result) => {
                let state = self.dns_check_mut(check);
                if matches!(state, Check::Checking) {
                    *state = result.into();
                }
            }
            Message::DnssecFinished(provider, report)
                if matches!(self.dnssec[provider as usize], Check::Checking) =>
            {
                self.dnssec[provider as usize] = Check::Complete(report);
            }
            Message::ConfiguredSignaturesFinished(details)
                if matches!(self.configured_signatures, Check::Checking) =>
            {
                self.configured_signatures = Check::Complete(details);
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
        ready.extend(PublicProvider::ALL.into_iter().filter_map(|provider| {
            matches!(self.dnssec[provider as usize], Check::Pending)
                .then_some(ReadyCheck::Dnssec(provider))
        }));
        if matches!(self.configured_signatures, Check::Pending)
            && let Some(server) = self.configured_server
        {
            ready.push(ReadyCheck::ConfiguredSignatures(server));
        }
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
            ReadyCheck::Dnssec(provider) => Task::perform(
                dnssec::inspect(provider.server(), self.name.to_ascii()),
                move |report| Message::DnssecFinished(provider, report),
            ),
            ReadyCheck::ConfiguredSignatures(server) => Task::perform(
                dnssec::inspect_configured(server, self.name.to_ascii()),
                Message::ConfiguredSignaturesFinished,
            ),
        }
    }

    fn view(&self) -> Element<'_, Message> {
        const CHECK_WIDTH: f32 = 160.0;
        let (local_override, system_override) = self.dns_overrides();
        let check = |label| column![text(label)].spacing(4).width(CHECK_WIDTH);
        let encrypted_check = |provider: PublicProvider, result: &Check<DnsReport>| {
            let mut name = check(provider.name());
            if matches!(result, Check::Complete(_)) {
                name = name.push(super::check_view::badge("Encrypted", true));
            }
            name
        };
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
                dns_result_with_badges(
                    &self.configured,
                    match &self.configured_signatures {
                        Check::Complete(report) => Some(report.validation.verdict),
                        _ => None,
                    },
                    local_override,
                ),
            ),
            (
                encrypted_check(PublicProvider::Google, &self.google),
                self.public_dns_result(PublicProvider::Google, &self.google),
            ),
            (
                encrypted_check(PublicProvider::Cloudflare, &self.cloudflare),
                self.public_dns_result(PublicProvider::Cloudflare, &self.cloudflare),
            ),
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

    fn public_dns_result<'a>(
        &'a self,
        provider: PublicProvider,
        result: &'a Check<DnsReport>,
    ) -> Option<Element<'a, Message>> {
        let verdict = match &self.dnssec[provider as usize] {
            Check::Complete(report) => Some(report.verdict),
            _ => None,
        };
        dns_result_with_badges(result, verdict, false)
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

fn dns_result_with_badges(
    result: &Check<DnsReport>,
    verdict: Option<dnssec::Verdict>,
    local_override: bool,
) -> Option<Element<'_, Message>> {
    Some(
        row![
            container(result.view(dns_result)?).width(Length::Fill),
            local_override.then(|| override_badge("Local DNS Override")),
            verdict.map(dnssec_badge),
        ]
        .spacing(12)
        .into(),
    )
}

fn dnssec_badge(verdict: dnssec::Verdict) -> Element<'static, Message> {
    use super::check_view::{badge, neutral_badge, warning_badge};
    match verdict {
        dnssec::Verdict::Validated => badge("DNSSEC validated", true),
        dnssec::Verdict::Unsigned => warning_badge("Unsigned"),
        dnssec::Verdict::MissingSignature => badge("Missing DNSSEC signature", false),
        dnssec::Verdict::Failed => badge("Validation failed", false),
        dnssec::Verdict::Unavailable => neutral_badge("DnsSec not available"),
    }
}

fn dnssec_finding(finding: &dnssec::Finding, source: Option<String>) -> Element<'_, Message> {
    use super::check_view::{badge, neutral_badge, warning_badge};
    use dnssec::FindingKind::*;
    let status = match finding.kind {
        RootTrusted => badge("Root key trusted locally", true),
        DelegationVerified => badge("DS link verified", true),
        KeysPublished => neutral_badge("DNSKEY published"),
        UnsignedDelegation => warning_badge("Unsigned"),
        RecordVerified => badge("Signature verified", true),
        DenialVerified => badge("Negative answer verified", true),
        MissingSignature => badge("Missing DNSSEC signature", false),
        InvalidSignature => badge("Signature invalid", false),
        KeyLinkUnavailable => neutral_badge("Key link unavailable"),
        DelegationUnavailable => neutral_badge("DS proof unavailable"),
        ProofUnavailable => neutral_badge("DnsSec not available"),
        SignaturesReturned => neutral_badge("Signatures returned"),
        NoSignaturesReturned => neutral_badge("No signatures returned"),
        NoRecordsReturned => neutral_badge("No records returned"),
        SignedDenialReturned => neutral_badge("Signed denial returned"),
    };
    row![
        status,
        (!finding.subject.is_empty())
            .then(|| { text(&finding.subject).wrapping(text::Wrapping::WordOrGlyph) }),
        source.map(|source| text(format!("({source})")).size(13)),
    ]
    .align_y(Alignment::Center)
    .spacing(8)
    .into()
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
            nameservers: Vec::new(),
            addresses: [None, None],
        }
    }
}

fn dns_result(report: &DnsReport) -> Element<'_, Message> {
    dns_details(&report.details)
}

fn dns_details(details: &str) -> Element<'_, Message> {
    column(details.lines().map(|line| {
        if line == "Server Failure" {
            super::check_view::badge(line, false)
        } else if let Some(alias) = line.strip_prefix("CNAME ") {
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
    .spacing(4)
    .into()
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
    fn dnssec_groups_shared_evidence_and_names_the_source_of_a_different_finding() {
        use dnssec::{Finding, FindingKind, Report, Verdict};

        let mut resolver = Resolver::screenshot_fixture([192, 0, 2, 20].into());
        let Resolver::Hostname(checks) = &mut resolver else {
            unreachable!("fixture uses a hostname");
        };
        let root = Finding {
            answer: None,
            kind: FindingKind::RootTrusted,
            subject: String::new(),
        };
        checks.dnssec = [
            Check::Complete(Report {
                verdict: Verdict::Validated,
                details: vec![root.clone()],
            }),
            Check::Complete(Report {
                verdict: Verdict::Unavailable,
                details: vec![
                    root,
                    Finding {
                        answer: None,
                        kind: FindingKind::KeyLinkUnavailable,
                        subject: "example. → portal.example.".into(),
                    },
                ],
            }),
        ];
        let mut ui = iced_test::Simulator::with_size(
            iced::Settings::default(),
            (1150.0, 650.0),
            resolver.dnssec_view().unwrap(),
        );
        assert!(ui.find("Root key trusted locally").is_ok());
        assert!(ui.find("Delegations").is_ok());
        assert!(ui.find("Key link unavailable").is_ok());
        assert!(ui.find("(Cloudflare)").is_ok());
        assert!(ui.find("(Google)").is_err());
    }

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
        assert_eq!(resolver.next_checks().units(), 7);
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
        assert!(!resolver.done());
        assert_eq!(resolver.next_checks().units(), 1);
        resolver.update(Message::ChecksStarted);
        resolver.update(Message::ConfiguredSignaturesFinished(
            dnssec::ConfiguredReport::unavailable(),
        ));
        for provider in PublicProvider::ALL {
            resolver.update(Message::DnssecFinished(
                provider,
                dnssec::Report {
                    verdict: dnssec::Verdict::Unavailable,
                    details: Vec::new(),
                },
            ));
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
