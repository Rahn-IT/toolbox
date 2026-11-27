use std::{
    collections::BTreeSet,
    net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4},
    time::Duration,
};

use futures_util::future::join_all;
use hickory_client::proto::{
    op::ResponseCode,
    rr::{
        Name, RData, RecordType,
        rdata::opt::{EdnsCode, EdnsOption},
    },
    xfer::DnsResponse,
};

use crate::{
    dns::{self, Server},
    network_scanner::netbios,
};

pub(super) const CLOUDFLARE: Server = Server::Https(
    SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(1, 1, 1, 1), 443)),
    "cloudflare-dns.com",
);
pub(super) const GOOGLE: Server = Server::Https(
    SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(8, 8, 8, 8), 443)),
    "dns.google",
);

pub(super) async fn system(host: String) -> Result<Vec<IpAddr>, String> {
    let lookup = tokio::time::timeout(
        Duration::from_secs(3),
        tokio::net::lookup_host((host.as_str(), 0)),
    )
    .await;
    match lookup {
        Ok(Ok(addresses)) => {
            let mut seen = BTreeSet::new();
            Ok(addresses
                .map(|address| address.ip())
                .filter(|ip| seen.insert(*ip))
                .collect())
        }
        Ok(Err(error)) => Err(error.to_string()),
        Err(_) => Err("Timed out".into()),
    }
}

pub(super) async fn netbios(ipv4: Vec<Ipv4Addr>) -> Result<Option<String>, String> {
    let runner =
        netbios::prepare()?.ok_or_else(|| "NetBIOS lookup utility unavailable".to_owned())?;
    let runner = &runner;
    let outcomes = join_all(ipv4.into_iter().map(|ip| async move {
        match runner.lookup(ip).await {
            netbios::Outcome::Found(names) => {
                let names = names
                    .into_iter()
                    .map(|name| name.name)
                    .collect::<BTreeSet<_>>()
                    .into_iter()
                    .collect::<Vec<_>>()
                    .join(", ");
                Ok(Some(format!("{names} (reply from {ip})")))
            }
            netbios::Outcome::NoReply => Ok(None),
            netbios::Outcome::Failed(error) => Err(format!("Query to {ip} failed · {error}")),
        }
    }))
    .await;
    let mut replied = false;
    let lines: Vec<_> = outcomes
        .into_iter()
        .filter_map(|outcome| match outcome {
            Ok(reply) => {
                replied |= reply.is_some();
                reply
            }
            Err(error) => Some(error),
        })
        .collect();
    if lines.is_empty() {
        Ok(None)
    } else if replied {
        Ok(Some(lines.join("\n")))
    } else {
        Err(lines.join("\n"))
    }
}

pub(super) async fn configured(name: Name) -> (Option<SocketAddr>, Result<DnsReport, String>) {
    match dns::configured_server().await {
        Ok(Some(address)) => (
            Some(address),
            resolver_lookup(Server::Plain(address), &name, false).await,
        ),
        Ok(None) => (None, Err("No DNS server configured".into())),
        Err(error) => (None, Err(error)),
    }
}

pub(super) async fn public(server: Server, name: Name) -> Result<DnsReport, String> {
    resolver_lookup(server, &name, true).await
}

pub(super) async fn authoritative(name: Name) -> Result<DnsReport, String> {
    tokio::time::timeout(Duration::from_secs(15), authoritative_lookup(&name))
        .await
        .map_err(|_| "Authoritative lookup timed out".to_owned())?
}

type AddressResponses = [Result<DnsResponse, String>; 2];

#[derive(Clone)]
pub struct DnsReport {
    pub(super) details: String,
    pub(super) dnssec: Option<DnssecWarning>,
    pub(super) nameservers: Vec<Name>,
    pub(super) addresses: [Option<BTreeSet<IpAddr>>; 2],
}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(super) enum DnssecWarning {
    Unverified,
    Unsupported,
    ValidationFailed,
}

struct Authority {
    zone: Name,
    server: Name,
    address: IpAddr,
}

type DnsReply = Result<(DnsResponse, Option<Authority>), String>;

#[derive(Default)]
struct AddressChain {
    aliases: Vec<String>,
    addresses: Vec<IpAddr>,
    notes: Vec<String>,
    nameservers: Vec<Name>,
    answered: bool,
    complete: bool,
    dnssec: Option<DnssecWarning>,
}

async fn address_queries(server: Server, name: &Name, recursive: bool) -> AddressResponses {
    let (ipv4, ipv6) = tokio::join!(
        server.query(name.clone(), RecordType::A, recursive),
        server.query(name.clone(), RecordType::AAAA, recursive),
    );
    [ipv4, ipv6]
}

async fn resolver_lookup(server: Server, name: &Name, dnssec: bool) -> Result<DnsReport, String> {
    tokio::time::timeout(Duration::from_secs(12), async {
        let replies = address_queries(server, name, true).await;
        follow_addresses(name, replies, dnssec, |name, kind| async move {
            server
                .query(name, kind, true)
                .await
                .map(|response| (response, None))
        })
        .await
    })
    .await
    .map_err(|_| "DNS lookup timed out while following aliases".to_owned())?
}

async fn follow_addresses<F, Fut>(
    name: &Name,
    [ipv4, ipv6]: AddressResponses,
    dnssec: bool,
    query: F,
) -> Result<DnsReport, String>
where
    F: Fn(Name, RecordType) -> Fut + Sync,
    Fut: Future<Output = DnsReply> + Send,
{
    let (ipv4, ipv6) = tokio::join!(
        follow_family(name.clone(), RecordType::A, ipv4, dnssec, &query),
        follow_family(name.clone(), RecordType::AAAA, ipv6, dnssec, &query),
    );
    let answered = ipv4.answered || ipv6.answered;
    let dnssec = ipv4.dnssec.max(ipv6.dnssec);
    let no_addresses = ipv4.addresses.is_empty() && ipv6.addresses.is_empty();
    let no_notes = ipv4.notes.is_empty() && ipv6.notes.is_empty();
    let addresses = [&ipv4, &ipv6].map(|chain| {
        chain
            .complete
            .then(|| chain.addresses.iter().copied().collect())
    });
    let mut lines = Vec::new();
    for line in ipv4
        .aliases
        .into_iter()
        .chain(ipv6.aliases)
        .chain(
            [ipv4.addresses, ipv6.addresses]
                .into_iter()
                .filter(|addresses| !addresses.is_empty())
                .map(|addresses| {
                    addresses
                        .iter()
                        .map(ToString::to_string)
                        .collect::<Vec<_>>()
                        .join(", ")
                }),
        )
        .chain(ipv4.notes)
        .chain(ipv6.notes)
    {
        if !lines.contains(&line) {
            lines.push(line);
        }
    }
    if no_addresses && no_notes {
        lines.push("No address records".into());
    }
    let details = lines.join("\n");
    let mut nameservers = ipv4.nameservers;
    for server in ipv6.nameservers {
        if !nameservers.contains(&server) {
            nameservers.push(server);
        }
    }
    if answered || dnssec.is_some() {
        Ok(DnsReport {
            details,
            dnssec,
            nameservers,
            addresses,
        })
    } else {
        Err(details)
    }
}

async fn follow_family<F, Fut>(
    mut name: Name,
    kind: RecordType,
    first_reply: Result<DnsResponse, String>,
    dnssec: bool,
    query: &F,
) -> AddressChain
where
    F: Fn(Name, RecordType) -> Fut + Sync,
    Fut: Future<Output = DnsReply> + Send,
{
    const MAX_ALIASES: usize = 8;
    let mut chain = AddressChain::default();
    let mut seen = BTreeSet::from([name.clone()]);
    let mut reply: DnsReply = first_reply.map(|response| (response, None));

    loop {
        let (response, authority) = match reply {
            Ok(reply) => reply,
            Err(error) => {
                chain.notes.push(error);
                return chain;
            }
        };
        if let Some(authority) = authority {
            if !chain.nameservers.contains(&authority.server) {
                chain.nameservers.push(authority.server);
            }
            chain.notes.push(format!(
                "{name} · Zone {} · {}",
                authority.zone, authority.address
            ));
        }
        let status = response.response_code();
        let answered = matches!(status, ResponseCode::NoError | ResponseCode::NXDomain);
        chain.answered |= answered;
        chain.notes.extend(extended_errors(&response));
        if dnssec {
            chain.dnssec = chain.dnssec.max(dnssec_warning(&response));
        }
        if !answered {
            chain.notes.push(status.to_string());
            return chain;
        }

        let queried = name.clone();
        loop {
            let mut target = None;
            for record in response
                .answers()
                .iter()
                .filter(|record| record.name() == &name)
            {
                match record.data() {
                    RData::A(address) if kind == RecordType::A => {
                        chain.addresses.push(IpAddr::V4(address.0))
                    }
                    RData::AAAA(address) if kind == RecordType::AAAA => {
                        chain.addresses.push(IpAddr::V6(address.0))
                    }
                    RData::CNAME(alias) => target = Some(alias.0.clone()),
                    _ => {}
                }
            }
            let Some(target) = target.filter(|_| chain.addresses.is_empty()) else {
                break;
            };
            chain.aliases.push(format!("CNAME {name} → {target}"));
            if !seen.insert(target.clone()) {
                chain.notes.push("CNAME loop detected".into());
                return chain;
            }
            if chain.aliases.len() > MAX_ALIASES {
                chain.notes.push("CNAME lookup limit reached".into());
                return chain;
            }
            name = target;
        }

        if status == ResponseCode::NXDomain {
            chain.notes.push(status.to_string());
            chain.complete = true;
            return chain;
        }
        if !chain.addresses.is_empty() || name == queried {
            chain.complete = true;
            return chain;
        }
        reply = query(name.clone(), kind).await;
    }
}

fn dnssec_warning(response: &DnsResponse) -> Option<DnssecWarning> {
    let extended = extended_error_data(response)
        .filter_map(|(code, _)| match code {
            1 | 2 => Some(DnssecWarning::Unsupported),
            6..=12 => Some(DnssecWarning::ValidationFailed),
            _ => None,
        })
        .max();
    extended.or_else(|| {
        (!response.authentic_data()
            && matches!(
                response.response_code(),
                ResponseCode::NoError | ResponseCode::NXDomain
            ))
        .then_some(DnssecWarning::Unverified)
    })
}

fn extended_error_data(response: &DnsResponse) -> impl Iterator<Item = (u16, &[u8])> + '_ {
    const EXTENDED_DNS_ERROR: u16 = 15;
    response
        .extensions()
        .iter()
        .flat_map(|edns| {
            edns.options()
                .get_all(EdnsCode::Unknown(EXTENDED_DNS_ERROR))
        })
        .filter_map(|option| {
            let EdnsOption::Unknown(EXTENDED_DNS_ERROR, data) = option else {
                return None;
            };
            let (&[first, second], detail) = data.split_first_chunk::<2>()?;
            Some((u16::from_be_bytes([first, second]), detail))
        })
}

fn extended_errors(response: &DnsResponse) -> impl Iterator<Item = String> + '_ {
    extended_error_data(response).map(|(code, detail)| {
        let detail = String::from_utf8_lossy(detail);
        let detail = detail.trim();
        let label = if code == 6 { " (DNSSEC bogus)" } else { "" };
        if detail.is_empty() {
            format!("Extended DNS error {code}{label}")
        } else {
            format!("Extended DNS error {code}{label} · {detail}")
        }
    })
}

async fn discover_authority(name: &Name, resolver: Server) -> Result<(Name, Vec<Name>), String> {
    let mut candidate = name.clone();
    let zone = loop {
        if candidate.is_root() {
            return Err("No authoritative zone found".into());
        }
        let response = resolver
            .query(candidate.clone(), RecordType::SOA, true)
            .await?;
        check_discovery_status(&response)?;
        if let Some(record) = response
            .answers()
            .iter()
            .chain(response.name_servers())
            .find(|record| {
                matches!(record.data(), RData::SOA(_)) && record.name().zone_of(&candidate)
            })
        {
            break record.name().clone();
        }
        candidate = candidate.base_name();
    };
    let response = resolver.query(zone.clone(), RecordType::NS, true).await?;
    check_discovery_status(&response)?;
    let servers: Vec<_> = response
        .answers()
        .iter()
        .filter_map(|record| match record.data() {
            RData::NS(server) if *record.name() == zone => Some(server.0.clone()),
            _ => None,
        })
        .collect();
    if servers.is_empty() {
        return Err(format!("No NS records returned for {zone}"));
    }
    Ok((zone, servers))
}

fn check_discovery_status(response: &DnsResponse) -> Result<(), String> {
    match response.response_code() {
        ResponseCode::NoError | ResponseCode::NXDomain => Ok(()),
        code => Err(code.to_string()),
    }
}

async fn authoritative_lookup(name: &Name) -> Result<DnsReport, String> {
    let (authority, responses) =
        authoritative_answers(name, [RecordType::A, RecordType::AAAA]).await?;
    let mut result = follow_addresses(name, responses, false, |target, kind| async move {
        let (authority, [answer]) = authoritative_answers(&target, [kind]).await?;
        answer.map(|response| (response, Some(authority)))
    })
    .await?;
    result
        .nameservers
        .retain(|server| *server != authority.server);
    result.nameservers.insert(0, authority.server);
    result.details = format!(
        "Zone {} · {}\n{}",
        authority.zone, authority.address, result.details
    );
    Ok(result)
}

async fn authoritative_answers<const N: usize>(
    name: &Name,
    kinds: [RecordType; N],
) -> Result<(Authority, [Result<DnsResponse, String>; N]), String> {
    let (zone, servers, resolver) = match discover_authority(name, CLOUDFLARE).await {
        Ok((zone, servers)) => (zone, servers, CLOUDFLARE),
        Err(cloudflare) => {
            let (zone, servers) = discover_authority(name, GOOGLE).await.map_err(|google| {
                format!("Zone discovery failed · Cloudflare: {cloudflare} · Google: {google}")
            })?;
            (zone, servers, GOOGLE)
        }
    };

    // Try the zone's nameservers until one answers authoritatively for the input name.
    let mut last_attempt = None;
    for server in servers {
        let addresses = address_queries(resolver, &server, true).await;
        for address in addresses
            .iter()
            .filter_map(|result| result.as_ref().ok())
            .flat_map(|result| result.answers())
            .filter_map(|record| match record.data() {
                RData::A(address) => Some(IpAddr::V4(address.0)),
                RData::AAAA(address) => Some(IpAddr::V6(address.0)),
                _ => None,
            })
        {
            let endpoint = Server::Plain(SocketAddr::new(address, 53));
            let responses = join_all(kinds.map(|kind| async move {
                let response = endpoint.query(name.clone(), kind, false).await?;
                if response.authoritative() {
                    Ok(response)
                } else {
                    Err(format!(
                        "Non-authoritative reply ({})",
                        response.response_code()
                    ))
                }
            }))
            .await;
            if responses.iter().any(Result::is_ok) {
                let responses = responses
                    .try_into()
                    .ok()
                    .expect("one response per record type");
                return Ok((
                    Authority {
                        zone,
                        server,
                        address,
                    },
                    responses,
                ));
            }
            let errors: BTreeSet<_> = responses.into_iter().filter_map(Result::err).collect();
            last_attempt = Some(format!(
                "{address}\n{}",
                errors.into_iter().collect::<Vec<_>>().join("\n")
            ));
        }
    }
    match last_attempt {
        Some(attempt) => Err(format!("{zone} · No authoritative reply\n{attempt}")),
        None => Err(format!("{zone} · No nameserver addresses found")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hickory_client::proto::{
        op::{Edns, Message},
        rr::{
            Record,
            rdata::{A, CNAME},
        },
    };

    #[tokio::test]
    async fn follows_an_alias_when_the_first_reply_has_no_address() {
        let origin = Name::from_ascii("alias.example.").unwrap();
        let target = Name::from_ascii("target.example.").unwrap();
        let mut alias = Message::new();
        alias.add_answer(Record::from_rdata(
            origin.clone(),
            60,
            RData::CNAME(CNAME(target.clone())),
        ));
        let mut address = Message::new();
        address.add_answer(Record::from_rdata(
            target.clone(),
            60,
            RData::A(A::new(192, 0, 2, 1)),
        ));
        let result = follow_addresses(
            &origin,
            [
                DnsResponse::from_message(alias).map_err(|error| error.to_string()),
                DnsResponse::from_message(Message::new()).map_err(|error| error.to_string()),
            ],
            false,
            |name, kind| {
                assert_eq!(name, target);
                assert_eq!(kind, RecordType::A);
                let address = address.clone();
                async move { Ok((DnsResponse::from_message(address).unwrap(), None)) }
            },
        )
        .await
        .unwrap();
        assert_eq!(
            result.details,
            "CNAME alias.example. → target.example.\n192.0.2.1"
        );
    }

    #[test]
    fn reports_explicit_dnssec_errors_from_the_resolver() {
        let mut message = Message::new();
        let mut edns = Edns::new();
        edns.options_mut()
            .insert(EdnsOption::Unknown(15, vec![0, 6]));
        message.set_edns(edns);
        let response = DnsResponse::from_message(message).unwrap();
        assert_eq!(
            extended_errors(&response).collect::<Vec<_>>(),
            ["Extended DNS error 6 (DNSSEC bogus)"]
        );
        assert!(dnssec_warning(&response) == Some(DnssecWarning::ValidationFailed));
    }

    #[tokio::test]
    #[ignore = "requires network access to Cloudflare and Google on TCP port 443"]
    async fn public_resolvers_authenticate_a_signed_domain_over_https() {
        let name = Name::from_ascii("cloudflare.com.").unwrap();
        let (cloudflare, google) = tokio::join!(
            CLOUDFLARE.query(name.clone(), RecordType::A, true),
            GOOGLE.query(name, RecordType::A, true),
        );
        assert!(cloudflare.expect("Cloudflare DoH").authentic_data());
        assert!(google.expect("Google DoH").authentic_data());
    }

    #[tokio::test]
    #[ignore = "requires network access to public resolvers and authoritative DNS on port 53"]
    async fn discovers_and_queries_the_authority_for_a_subdomain() {
        let name = Name::from_ascii("www.cloudflare.com.").unwrap();
        let report = authoritative_lookup(&name).await.unwrap();
        let (zone, _) = report
            .details
            .strip_prefix("Zone ")
            .unwrap()
            .split_once(" · ")
            .unwrap();
        assert!(
            Name::from_ascii(zone).unwrap().zone_of(&name),
            "{}",
            report.details
        );
        assert!(!report.nameservers.is_empty());
        for server in &report.nameservers {
            assert!(!report.details.contains(&server.to_ascii()));
        }
        assert!(
            report.details.lines().any(|line| line
                .split(", ")
                .any(|record| record.parse::<Ipv4Addr>().is_ok())),
            "{}",
            report.details
        );
    }
}
