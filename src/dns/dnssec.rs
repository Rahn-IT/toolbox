use std::{
    collections::{BTreeSet, HashMap},
    net::SocketAddr,
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};

use futures_util::{Stream, StreamExt, stream};
use hickory_resolver::{
    net::{
        DnsHandle, NetError, client::Client, dnssec::DnssecDnsHandle, h2::HttpsClientStream,
        runtime::TokioRuntimeProvider, tcp::TcpClientStream, udp::UdpClientStream,
    },
    proto::{
        dnssec::{
            Proof, Verifier,
            rdata::{DNSKEY, DS, NSEC, RRSIG},
        },
        op::{DnsRequest, DnsRequestOptions, DnsResponse, Message, Query, ResponseCode},
        rr::{DNSClass, Name, RData, Record, RecordType},
    },
};
use tokio::time::{Instant, timeout_at};
use tokio_rustls::rustls;
use tokio_util::task::AbortOnDropHandle;

use super::Server;

const MAX_STEPS: usize = 8;
const MAX_WIRE_QUERIES: usize = 96;

#[cfg(test)]
mod fixture;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Verdict {
    Validated,
    Unsigned,
    MissingSignature,
    Failed,
    Unavailable,
}

#[derive(Clone)]
pub struct Report {
    pub(crate) verdict: Verdict,
    pub(crate) details: Vec<Finding>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum FindingKind {
    RootTrusted,
    DelegationVerified,
    KeysPublished,
    UnsignedDelegation,
    RecordVerified,
    DenialVerified,
    MissingSignature,
    InvalidSignature,
    KeyLinkUnavailable,
    DelegationUnavailable,
    ProofUnavailable,
    SignaturesReturned,
    NoSignaturesReturned,
    NoRecordsReturned,
    SignedDenialReturned,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Finding {
    pub(crate) kind: FindingKind,
    pub(crate) subject: String,
    pub(crate) answer: Option<(Name, BTreeSet<RData>)>,
}

#[derive(Clone)]
pub struct ConfiguredReport {
    pub(crate) observed: Vec<Finding>,
    pub(crate) validation: Report,
}

impl ConfiguredReport {
    pub(crate) fn unavailable() -> Self {
        Self {
            observed: Vec::new(),
            validation: unavailable("No configured DNS server"),
        }
    }
}

#[derive(Clone)]
struct Bounded {
    client: Client<TokioRuntimeProvider>,
    tcp_fallback: Option<SocketAddr>,
    deadline: Instant,
    queries: Arc<AtomicUsize>,
}

impl Bounded {
    fn admit_query(&self) -> Result<(), NetError> {
        if Instant::now() >= self.deadline
            || self
                .queries
                .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |used| {
                    (used < MAX_WIRE_QUERIES).then_some(used + 1)
                })
                .is_err()
        {
            return Err(NetError::from("DNSSEC diagnostic budget exhausted"));
        }
        Ok(())
    }

    async fn exchange(&self, request: DnsRequest) -> Result<DnsResponse, NetError> {
        self.admit_query()?;
        let questions = request.queries.clone();
        let mut response = self
            .client
            .send(request.clone())
            .next()
            .await
            .ok_or_else(|| NetError::from("No DNSSEC response"))??;
        if response.queries != questions {
            return Err(NetError::from("Mismatched DNSSEC response"));
        }
        if response.metadata.truncation
            && let Some(address) = self.tcp_fallback
        {
            self.admit_query()?;
            let (stream, handle) = TcpClientStream::new(
                address,
                None,
                Some(Duration::from_secs(3)),
                TokioRuntimeProvider::default(),
            );
            let (client, driver) = Client::<TokioRuntimeProvider>::with_timeout(
                stream.await?,
                handle,
                Duration::from_secs(3),
            );
            let _driver = AbortOnDropHandle::new(tokio::spawn(driver));
            response = client
                .send(request)
                .next()
                .await
                .ok_or_else(|| NetError::from("No DNSSEC response over TCP"))??;
        }
        if response.metadata.truncation || response.queries != questions {
            return Err(NetError::from("Incomplete or mismatched DNSSEC response"));
        }
        Ok(response)
    }
}

impl DnsHandle for Bounded {
    type Response = Pin<Box<dyn Stream<Item = Result<DnsResponse, NetError>> + Send>>;
    type Runtime = TokioRuntimeProvider;

    fn send(&self, mut request: DnsRequest) -> Self::Response {
        request.metadata.checking_disabled = true;
        request
            .edns
            .get_or_insert_with(Default::default)
            .enable_dnssec();
        let session = self.clone();
        Box::pin(stream::once(async move {
            timeout_at(session.deadline, session.exchange(request))
                .await
                .map_err(|_| NetError::from("DNSSEC query timed out"))?
        }))
    }
}

struct Session {
    validator: DnssecDnsHandle<Bounded>,
    deadline: Instant,
    replies: HashMap<(Name, RecordType), Result<DnsResponse, String>>,
    zones: HashMap<Name, Zone>,
    _driver: AbortOnDropHandle<()>,
}

#[derive(Clone, Copy, Default)]
struct Zone {
    linked: bool,
    signed_delegation: bool,
    unsigned: bool,
}

impl Session {
    async fn connect(server: Server) -> Result<Self, String> {
        let deadline = Instant::now() + Duration::from_secs(12);
        match server {
            Server::Plain(address) => {
                let stream = UdpClientStream::builder(address, TokioRuntimeProvider::default())
                    .with_timeout(Some(Duration::from_secs(3)))
                    .build();
                let (client, driver) = Client::from_sender(stream);
                Ok(Self::new(
                    client,
                    tokio::spawn(driver),
                    deadline,
                    Some(address),
                ))
            }
            Server::Https(address, hostname) => {
                Self::connect_https(address, hostname, deadline).await
            }
        }
    }

    async fn connect_https(
        address: SocketAddr,
        hostname: &'static str,
        deadline: Instant,
    ) -> Result<Self, String> {
        let roots =
            rustls::RootCertStore::from_iter(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        let tls = rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        let mut builder =
            HttpsClientStream::builder(Arc::new(tls), TokioRuntimeProvider::default());
        builder.request_timeout(Duration::from_secs(3));
        let stream = timeout_at(
            deadline,
            builder.build(address, hostname.into(), "/dns-query".into()),
        )
        .await
        .map_err(|_| "DNSSEC connection timed out".to_owned())?
        .map_err(|error| error.to_string())?;
        let (client, driver) = Client::from_sender(stream);
        Ok(Self::new(client, tokio::spawn(driver), deadline, None))
    }

    fn new(
        client: Client<TokioRuntimeProvider>,
        driver: tokio::task::JoinHandle<()>,
        deadline: Instant,
        tcp_fallback: Option<SocketAddr>,
    ) -> Self {
        let validator = DnssecDnsHandle::new(Bounded {
            client,
            tcp_fallback,
            deadline,
            queries: Arc::new(AtomicUsize::new(0)),
        });
        Self {
            validator,
            deadline,
            replies: HashMap::new(),
            zones: HashMap::new(),
            _driver: AbortOnDropHandle::new(driver),
        }
    }

    async fn query(&mut self, name: &Name, kind: RecordType) -> Result<DnsResponse, String> {
        let key = (name.clone(), kind);
        if let Some(response) = self.replies.get(&key) {
            return response.clone();
        }
        let question = Query::query(name.clone(), kind);
        let result = match timeout_at(
            self.deadline,
            self.validator
                .lookup(question.clone(), DnsRequestOptions::default())
                .next(),
        )
        .await
        {
            Ok(Some(Ok(response)))
                if !response.metadata.truncation
                    && response.queries.as_slice() == std::slice::from_ref(&question) =>
            {
                Ok(response)
            }
            Ok(Some(Ok(_))) => Err("Incomplete or mismatched DNSSEC response".into()),
            Ok(Some(Err(error))) => Err(error.to_string()),
            Ok(None) => Err("No DNSSEC response".into()),
            Err(_) => Err("DNSSEC query timed out".into()),
        };
        self.replies.insert(key, result.clone());
        result
    }

    async fn zone(&mut self, zone: &Name, details: &mut Vec<Finding>) -> Zone {
        use FindingKind::*;
        if let Some(evidence) = self.zones.get(zone) {
            return *evidence;
        }
        let mut current = zone.clone();
        let mut result = Zone::default();
        let mut chain = Vec::new();
        for step in 0..MAX_STEPS {
            let details = &mut chain;
            let keys = self.query(&current, RecordType::DNSKEY).await;
            let published: Vec<_> = keys
                .as_ref()
                .ok()
                .into_iter()
                .flat_map(|response| response.answers.iter())
                .filter(|record| record.name == current && record.dns_class == DNSClass::IN)
                .filter_map(|record| {
                    let key = record.try_borrow::<DNSKEY>()?;
                    Some((key.data().calculate_key_tag().ok()?, record.proof))
                })
                .collect();
            if current.is_root() {
                if published.iter().any(|(_, proof)| *proof == Proof::Secure) {
                    push(details, RootTrusted, String::new());
                }
                break;
            }
            let published_keys = |details: &mut Vec<Finding>| {
                if !published.is_empty() {
                    let tags = published
                        .iter()
                        .map(|(tag, _)| tag.to_string())
                        .collect::<BTreeSet<_>>()
                        .into_iter()
                        .collect::<Vec<_>>()
                        .join(", ");
                    push(details, KeysPublished, format!("{current} · key {tags}"));
                }
            };
            let Ok(ds) = self.query(&current, RecordType::DS).await else {
                published_keys(details);
                push(details, DelegationUnavailable, current.to_string());
                break;
            };
            let records: Vec<_> = ds
                .answers
                .iter()
                .filter(|record| {
                    record.name == current
                        && record.dns_class == DNSClass::IN
                        && record.proof == Proof::Secure
                })
                .filter_map(|record| record.try_borrow::<DS>())
                .filter(|record| {
                    record.data().algorithm().is_supported()
                        && record.data().digest_type().is_supported()
                })
                .collect();
            if records.is_empty() {
                published_keys(details);
                if unsigned_delegation(&ds, &current) {
                    push(details, UnsignedDelegation, current.to_string());
                    result.unsigned = true;
                } else {
                    push(details, DelegationUnavailable, current.to_string());
                }
                break;
            }
            let Some(signature) = verified_signature(&ds.answers, &current, RecordType::DS) else {
                break;
            };
            let parent = &signature.input().signer_name;
            if parent == &current || !parent.zone_of(&current) {
                break;
            }
            if step == 0 {
                result.signed_delegation = true;
            }
            let matches = records
                .iter()
                .filter_map(|ds| {
                    let keys = keys.as_ref().ok()?;
                    let found = keys
                        .answers
                        .iter()
                        .filter(|record| {
                            record.name == current
                                && record.dns_class == DNSClass::IN
                                && record.proof == Proof::Secure
                        })
                        .filter_map(|record| record.try_borrow::<DNSKEY>())
                        .any(|key| matches_ds(&current, ds.data(), key.data()));
                    found.then_some(ds.data().key_tag())
                })
                .collect::<BTreeSet<_>>();
            if matches.is_empty() {
                published_keys(details);
                push(details, KeyLinkUnavailable, format!("{parent} → {current}"));
                current = parent.clone();
                continue;
            }
            if step == 0 {
                result.linked = true;
            }
            let tags = matches
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join(", ");
            push(
                details,
                DelegationVerified,
                format!("{parent} → {current} · key {tags}"),
            );
            current = parent.clone();
        }
        for finding in chain.into_iter().rev() {
            push(details, finding.kind, finding.subject);
        }
        self.zones.insert(zone.clone(), result);
        result
    }

    async fn family(
        &mut self,
        mut name: Name,
        kind: RecordType,
        details: &mut Vec<Finding>,
    ) -> Verdict {
        let mut chain = Verdict::Validated;
        let mut seen = BTreeSet::new();
        for _ in 0..MAX_STEPS {
            if !seen.insert(name.clone()) {
                break;
            }
            let response = match self.query(&name, kind).await {
                Ok(response) => response,
                Err(_) => {
                    push(
                        details,
                        FindingKind::ProofUnavailable,
                        format!("{name} {kind}"),
                    );
                    break;
                }
            };
            // Hickory annotates and may filter records in the parsed message. Its
            // buffer still represents the very same exchange before validation.
            let Ok(raw) = Message::from_vec(response.as_buffer()) else {
                break;
            };
            if raw.metadata.truncation {
                break;
            }
            if !matches!(
                raw.metadata.response_code,
                ResponseCode::NoError | ResponseCode::NXDomain
            ) {
                push(
                    details,
                    FindingKind::ProofUnavailable,
                    format!("{name} {kind} · {}", raw.metadata.response_code),
                );
                break;
            }
            let mut alias = None;
            loop {
                let record_type = if raw
                    .answers
                    .iter()
                    .any(|record| relevant(record, &name, kind))
                {
                    kind
                } else {
                    RecordType::CNAME
                };
                let records: Vec<_> = raw
                    .answers
                    .iter()
                    .filter(|record| relevant(record, &name, record_type))
                    .collect();
                if records.is_empty() {
                    if alias.is_some() {
                        break;
                    }
                    let zone = response.soa().map(|soa| soa.name().clone());
                    if let Some(zone) = zone.filter(|zone| zone.zone_of(&name))
                        && self.zone(&zone, details).await.unsigned
                    {
                        return combine(chain, Verdict::Unsigned);
                    }
                    let denial = response.authorities.iter().any(|record| {
                        record.proof == Proof::Secure
                            && matches!(record.record_type(), RecordType::NSEC | RecordType::NSEC3)
                    });
                    if denial {
                        push(
                            details,
                            FindingKind::DenialVerified,
                            format!("{name} {kind}"),
                        );
                        return chain;
                    }
                    push(
                        details,
                        FindingKind::ProofUnavailable,
                        format!("{name} {kind}"),
                    );
                    return Verdict::Unavailable;
                }
                if record_type == kind && raw.metadata.response_code != ResponseCode::NoError {
                    return Verdict::Unavailable;
                }
                let verdict = self
                    .record(&response, &raw, &name, record_type, &records, details)
                    .await;
                chain = combine(chain, verdict);
                if record_type == kind
                    || matches!(chain, Verdict::MissingSignature | Verdict::Failed)
                {
                    return chain;
                }
                let Some(RData::CNAME(target)) = records.first().map(|record| &record.data) else {
                    break;
                };
                if seen.contains(&target.0) || seen.len() >= MAX_STEPS {
                    return Verdict::Unavailable;
                }
                name = target.0.clone();
                alias = Some(());
                if raw.answers.iter().any(|record| {
                    relevant(record, &name, kind) || relevant(record, &name, RecordType::CNAME)
                }) {
                    seen.insert(name.clone());
                }
            }
        }
        Verdict::Unavailable
    }

    async fn record(
        &mut self,
        response: &DnsResponse,
        raw: &Message,
        name: &Name,
        kind: RecordType,
        records: &[&Record],
        details: &mut Vec<Finding>,
    ) -> Verdict {
        if let Some(signature) = verified_signature(&response.answers, name, kind)
            && records.iter().all(|raw_record| {
                response.answers.iter().any(|record| {
                    relevant(record, name, kind)
                        && record.proof == Proof::Secure
                        && record.data == raw_record.data
                })
            })
        {
            let input = signature.input();
            push_finding(
                details,
                Finding {
                    kind: FindingKind::RecordVerified,
                    answer: Some((
                        name.clone(),
                        records.iter().map(|r| r.data.clone()).collect(),
                    )),
                    subject: format!(
                        "{name} {kind} · {} key {}",
                        input.signer_name, input.key_tag
                    ),
                },
            );
            self.zone(&input.signer_name, details).await;
            return Verdict::Validated;
        }

        let signatures: Vec<_> = raw
            .answers
            .iter()
            .filter_map(|record| covering(record, name, kind))
            .collect();
        if signatures.is_empty()
            && matches!(kind, RecordType::A | RecordType::AAAA)
            && raw.metadata.response_code == ResponseCode::NoError
        {
            let mut apex_details = Vec::new();
            let apex = self.zone(name, &mut apex_details).await;
            for finding in apex_details {
                if apex.signed_delegation
                    || apex.unsigned
                    || finding.kind == FindingKind::KeysPublished
                {
                    push(details, finding.kind, finding.subject);
                }
            }
            if apex.signed_delegation {
                push(
                    details,
                    FindingKind::MissingSignature,
                    format!("{name} {kind}"),
                );
                return Verdict::MissingSignature;
            }
            if apex.unsigned {
                return Verdict::Unsigned;
            }
        }
        if !signatures.is_empty() {
            let mut all_invalid = true;
            for signature in signatures {
                let input = signature.input();
                if !input.signer_name.zone_of(name)
                    || !self.zone(&input.signer_name, details).await.linked
                {
                    all_invalid = false;
                    break;
                }
                let Ok(keys) = self.query(&input.signer_name, RecordType::DNSKEY).await else {
                    all_invalid = false;
                    break;
                };
                let mut candidates = keys
                    .answers
                    .iter()
                    .filter(|record| {
                        record.proof == Proof::Secure
                            && relevant(record, &input.signer_name, RecordType::DNSKEY)
                    })
                    .filter_map(|record| record.try_borrow::<DNSKEY>())
                    .filter(|key| {
                        key.data().algorithm() == input.algorithm
                            && key.data().calculate_key_tag().ok() == Some(input.key_tag)
                    })
                    .peekable();
                if candidates.peek().is_none()
                    || candidates.any(|key| {
                        key.data()
                            .verify_rrsig(name, DNSClass::IN, signature, records.iter().copied())
                            .is_ok()
                    })
                {
                    all_invalid = false;
                    break;
                }
            }
            if all_invalid {
                push(
                    details,
                    FindingKind::InvalidSignature,
                    format!("{name} {kind}"),
                );
                return Verdict::Failed;
            }
        }
        let zone = self
            .query(name, RecordType::SOA)
            .await
            .ok()
            .and_then(|response| {
                response.soa().map(|soa| soa.name().clone()).or_else(|| {
                    response
                        .answers
                        .iter()
                        .find(|record| record.record_type() == RecordType::SOA)
                        .map(|record| record.name.clone())
                })
            });
        if let Some(zone) = zone.filter(|zone| zone.zone_of(name))
            && self.zone(&zone, details).await.unsigned
        {
            return Verdict::Unsigned;
        }
        push(
            details,
            FindingKind::ProofUnavailable,
            format!("{name} {kind}"),
        );
        Verdict::Unavailable
    }
}

pub(crate) async fn inspect(server: Server, name: String) -> Report {
    let Ok(name) = Name::from_ascii(name) else {
        return unavailable("Invalid DNS name");
    };
    let mut session = match Session::connect(server).await {
        Ok(session) => session,
        Err(error) => return unavailable(&error),
    };
    let mut details = Vec::new();
    let ipv4 = session
        .family(name.clone(), RecordType::A, &mut details)
        .await;
    let ipv6 = session
        .family(name.clone(), RecordType::AAAA, &mut details)
        .await;
    if details.is_empty() {
        push(
            &mut details,
            FindingKind::ProofUnavailable,
            name.to_string(),
        );
    }
    Report {
        verdict: combine(ipv4, ipv6),
        details,
    }
}

pub(crate) async fn inspect_configured(address: SocketAddr, name: String) -> ConfiguredReport {
    let (observed, validation) = tokio::join!(
        observe(address, name.clone()),
        inspect(Server::Plain(address), name),
    );
    ConfiguredReport {
        observed,
        validation,
    }
}

async fn observe(address: SocketAddr, name: String) -> Vec<Finding> {
    let Ok(name) = Name::from_ascii(name) else {
        return unavailable("Invalid DNS name").details;
    };
    let (ipv4, ipv6) = tokio::join!(
        observe_family(address, name.clone(), RecordType::A),
        observe_family(address, name, RecordType::AAAA),
    );
    let mut details = ipv4;
    for line in ipv6 {
        push_finding(&mut details, line);
    }
    details
}

async fn observe_family(address: SocketAddr, mut name: Name, kind: RecordType) -> Vec<Finding> {
    let mut details = Vec::new();
    let mut seen = BTreeSet::new();
    let deadline = Instant::now() + Duration::from_secs(6);
    for _ in 0..MAX_STEPS {
        if !seen.insert(name.clone()) {
            break;
        }
        let old_name = hickory_client::proto::rr::Name::from_ascii(name.to_ascii());
        let Ok(old_name) = old_name else { break };
        let old_kind = if kind == RecordType::A {
            hickory_client::proto::rr::RecordType::A
        } else {
            hickory_client::proto::rr::RecordType::AAAA
        };
        let Ok(Ok(response)) = timeout_at(
            deadline,
            Server::Plain(address).signed_material(old_name, old_kind),
        )
        .await
        else {
            break;
        };
        let Ok(raw) = Message::from_vec(response.as_buffer()) else {
            break;
        };
        if raw.metadata.truncation
            || !matches!(
                raw.metadata.response_code,
                ResponseCode::NoError | ResponseCode::NXDomain
            )
        {
            break;
        }
        let mut next = None;
        loop {
            let record = raw
                .answers
                .iter()
                .find(|record| relevant(record, &name, kind))
                .or_else(|| {
                    raw.answers
                        .iter()
                        .find(|record| relevant(record, &name, RecordType::CNAME))
                });
            let Some(record) = record else {
                if next.is_some() {
                    break;
                }
                let signed_denial = raw.authorities.iter().any(|denial| {
                    matches!(denial.record_type(), RecordType::NSEC | RecordType::NSEC3)
                        && raw.authorities.iter().any(|record| {
                            covering(record, &denial.name, denial.record_type()).is_some()
                        })
                });
                let status = if signed_denial {
                    FindingKind::SignedDenialReturned
                } else {
                    FindingKind::NoRecordsReturned
                };
                push(&mut details, status, format!("{name} {kind}"));
                return details;
            };
            let rr_type = record.record_type();
            let synthesized = rr_type == RecordType::CNAME
                && raw.answers.iter().any(|candidate| {
                    candidate.record_type() == RecordType::DNAME
                        && candidate.name != name
                        && candidate.name.zone_of(&name)
                });
            if !synthesized {
                let signed = raw
                    .answers
                    .iter()
                    .any(|record| covering(record, &name, rr_type).is_some());
                let status = if signed {
                    FindingKind::SignaturesReturned
                } else {
                    FindingKind::NoSignaturesReturned
                };
                let answer = (!signed).then(|| {
                    (
                        name.clone(),
                        raw.answers
                            .iter()
                            .filter(|r| relevant(r, &name, rr_type))
                            .map(|r| r.data.clone())
                            .collect(),
                    )
                });
                push_finding(
                    &mut details,
                    Finding {
                        kind: status,
                        subject: format!("{name} {rr_type}"),
                        answer,
                    },
                );
            }
            let RData::CNAME(alias) = &record.data else {
                return details;
            };
            if seen.contains(&alias.0) || seen.len() >= MAX_STEPS {
                push(
                    &mut details,
                    FindingKind::ProofUnavailable,
                    format!("{name} {kind}"),
                );
                return details;
            }
            name = alias.0.clone();
            next = Some(());
            if raw.answers.iter().any(|record| {
                relevant(record, &name, kind) || relevant(record, &name, RecordType::CNAME)
            }) {
                seen.insert(name.clone());
            }
        }
    }
    push(
        &mut details,
        FindingKind::ProofUnavailable,
        format!("{name} {kind}"),
    );
    details
}

fn unavailable(reason: &str) -> Report {
    Report {
        verdict: Verdict::Unavailable,
        details: vec![Finding {
            kind: FindingKind::ProofUnavailable,
            subject: reason.into(),
            answer: None,
        }],
    }
}

fn combine(left: Verdict, right: Verdict) -> Verdict {
    use Verdict::*;
    match (left, right) {
        (MissingSignature, _) | (_, MissingSignature) => MissingSignature,
        (Failed, _) | (_, Failed) => Failed,
        (Unavailable, _) | (_, Unavailable) => Unavailable,
        (Unsigned, _) | (_, Unsigned) => Unsigned,
        (Validated, Validated) => Validated,
    }
}

fn push(details: &mut Vec<Finding>, kind: FindingKind, subject: String) {
    push_finding(
        details,
        Finding {
            kind,
            subject,
            answer: None,
        },
    );
}

fn push_finding(details: &mut Vec<Finding>, finding: Finding) {
    if !details.contains(&finding) {
        details.push(finding);
    }
}

fn relevant(record: &Record, name: &Name, kind: RecordType) -> bool {
    &record.name == name && record.dns_class == DNSClass::IN && record.record_type() == kind
}

fn covering<'a>(record: &'a Record, name: &Name, kind: RecordType) -> Option<&'a RRSIG> {
    if !relevant(record, name, RecordType::RRSIG) {
        return None;
    }
    let RData::DNSSEC(hickory_resolver::proto::dnssec::rdata::DNSSECRData::RRSIG(signature)) =
        &record.data
    else {
        return None;
    };
    (signature.input().type_covered == kind).then_some(signature)
}

fn verified_signature<'a>(
    records: &'a [Record],
    name: &Name,
    kind: RecordType,
) -> Option<&'a RRSIG> {
    records
        .iter()
        .filter(|record| record.proof == Proof::Secure)
        .find_map(|record| covering(record, name, kind))
}

fn matches_ds(name: &Name, ds: &DS, key: &DNSKEY) -> bool {
    key.algorithm() == ds.algorithm()
        && key.calculate_key_tag().ok() == Some(ds.key_tag())
        && ds.covers(name, key).unwrap_or(false)
}

fn unsigned_delegation(response: &DnsResponse, zone: &Name) -> bool {
    response
        .authorities
        .iter()
        .filter(|record| record.proof == Proof::Secure && relevant(record, zone, RecordType::NSEC))
        .filter_map(|record| record.try_borrow::<NSEC>())
        .any(|record| {
            let types = record.data().type_bit_maps().collect::<BTreeSet<_>>();
            types.contains(&RecordType::NS)
                && !types.contains(&RecordType::DS)
                && !types.contains(&RecordType::SOA)
                && verified_signature(&response.authorities, zone, RecordType::NSEC).is_some_and(
                    |sig| sig.input().signer_name != *zone && sig.input().signer_name.zone_of(zone),
                )
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use hickory_resolver::proto::dnssec::{Algorithm, DigestType, PublicKeyBuf};

    #[test]
    fn a_ds_matches_the_zone_and_key_digest() {
        let zone = Name::from_ascii("example.net.").unwrap();
        let other = Name::from_ascii("example.org.").unwrap();
        let key = DNSKEY::new(
            true,
            true,
            false,
            PublicKeyBuf::new(vec![1; 32], Algorithm::ED25519),
        );
        let wrong_key = DNSKEY::new(
            true,
            true,
            false,
            PublicKeyBuf::new(vec![2; 32], Algorithm::ED25519),
        );
        let ds = DS::from_key(
            &PublicKeyBuf::new(vec![1; 32], Algorithm::ED25519),
            &zone,
            DigestType::SHA256,
        )
        .unwrap();
        assert!(matches_ds(&zone, &ds, &key));
        assert!(!matches_ds(&zone, &ds, &wrong_key));
        assert!(!matches_ds(&other, &ds, &key));
    }

    #[test]
    fn missing_evidence_cannot_turn_a_partial_result_green() {
        assert_eq!(
            combine(Verdict::Validated, Verdict::Unavailable),
            Verdict::Unavailable
        );
        assert_eq!(
            combine(Verdict::Unsigned, Verdict::MissingSignature),
            Verdict::MissingSignature
        );
        assert_eq!(
            combine(Verdict::Validated, Verdict::Unsigned),
            Verdict::Unsigned
        );
    }

    #[tokio::test]
    #[ignore = "queries Cloudflare and Google through DNS over HTTPS"]
    async fn public_doh_exposes_the_verified_dnssec_chain() {
        let cloudflare = Server::Https("1.1.1.1:443".parse().unwrap(), "cloudflare-dns.com");
        let google = Server::Https("8.8.8.8:443".parse().unwrap(), "dns.google");
        let (cloudflare, google) = tokio::join!(
            inspect(cloudflare, "cloudflare.com.".into()),
            inspect(google, "cloudflare.com.".into()),
        );
        for report in [cloudflare, google] {
            assert_eq!(report.verdict, Verdict::Validated, "{:?}", report.details);
            assert!(
                report
                    .details
                    .iter()
                    .any(|finding| finding.kind == FindingKind::DelegationVerified),
                "{:?}",
                report.details
            );
            assert!(
                report
                    .details
                    .iter()
                    .any(|finding| finding.kind == FindingKind::RecordVerified),
                "{:?}",
                report.details
            );
        }
    }
}
