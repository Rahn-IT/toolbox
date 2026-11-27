use std::{
    collections::{BTreeMap, BTreeSet},
    net::Ipv4Addr,
    time::Duration,
};

use futures_util::{StreamExt, stream};
use iced::task::{Sipper, sipper};
use tokio::sync::Semaphore;

use super::{interfaces, name_lookup, netbios, ping};
use crate::arp::{self, Device, Scope};

pub(super) const MAX_HOSTS: u32 = 4094;
const PING_CONCURRENCY: usize = 32;
const NAME_CONCURRENCY: usize = 32;
const PROGRESS_BATCH: usize = 8;
pub(super) static PROBES: Semaphore = Semaphore::const_new(PING_CONCURRENCY);

#[derive(Clone, Copy)]
pub enum Progress {
    Preparing,
    Ping { done: usize, total: usize },
    Arp,
    NetBios { done: usize, total: usize },
    ReverseDns { done: usize, total: usize },
    Ports { done: usize, total: usize },
}

#[derive(Clone)]
pub enum Update {
    Progress(Progress),
    Rows(Vec<Observation>),
}

#[derive(Clone, Default)]
pub struct Report {
    pub(super) devices: Vec<Observation>,
    pub(super) notices: Vec<String>,
}

#[derive(Clone)]
pub struct Observation {
    pub(super) ip: Ipv4Addr,
    pub(super) ping_reply: Option<bool>,
    pub(super) addresses: Vec<Device>,
    pub(super) names: Vec<netbios::Name>,
    pub(super) hostname: Option<String>,
}

impl Observation {
    fn new(ip: Ipv4Addr) -> Self {
        Self {
            ip,
            ping_reply: None,
            addresses: Vec::new(),
            names: Vec::new(),
            hostname: None,
        }
    }
}

pub(super) fn discover(interface: interfaces::Interface) -> impl Sipper<Report, Update> + Send {
    sipper(move |mut sender| async move {
        let mut report = Report::default();
        let mut devices = BTreeMap::new();
        let mut unanswered = BTreeSet::new();
        let targets = eligible(&interface);
        let can_probe = match &targets {
            Err(error) => {
                report.notices.push(error.clone());
                false
            }
            Ok(_) => match interfaces::verify_route(&interface).await {
                Ok(()) => true,
                Err(error) => {
                    report.notices.push(error.to_string());
                    false
                }
            },
        };

        if can_probe && let Ok(targets) = targets {
            match ping::prepare().await {
                Ok(runner) => {
                    let (first, last) = host_bounds(&interface);
                    let total = (last - first) as usize;
                    if total > 0 {
                        sender
                            .send(Update::Progress(Progress::Ping { done: 0, total }))
                            .await;
                    }
                    let runner = &runner;
                    let device = interface.name.as_str();
                    let mut replies = stream::iter(targets.map(|ip| async move {
                        let _permit = PROBES
                            .acquire()
                            .await
                            .expect("the probe semaphore stays open");
                        (ip, runner.echo(device, ip).await)
                    }))
                    .buffer_unordered(PING_CONCURRENCY);
                    let mut first_error = None;
                    let mut done = 0;
                    let mut rows = Vec::new();
                    while let Some((ip, outcome)) = replies.next().await {
                        match outcome {
                            ping::Outcome::Reply => {
                                let observation = Observation {
                                    ping_reply: Some(true),
                                    ..Observation::new(ip)
                                };
                                rows.push(observation.clone());
                                devices.insert(ip, observation);
                            }
                            ping::Outcome::Failed(error) => {
                                first_error.get_or_insert(error);
                            }
                            ping::Outcome::NoReply | ping::Outcome::TimedOut => {
                                unanswered.insert(ip);
                            }
                        }
                        done += 1;
                        if done % PROGRESS_BATCH == 0 || done == total {
                            if !rows.is_empty() {
                                sender.send(Update::Rows(std::mem::take(&mut rows))).await;
                            }
                            sender
                                .send(Update::Progress(Progress::Ping { done, total }))
                                .await;
                        }
                    }
                    if let Some(error) = first_error {
                        report
                            .notices
                            .push(format!("Some ping requests failed: {error}"));
                    }
                }
                Err(error) => report.notices.push(format!("Ping unavailable: {error}")),
            }
        }

        sender.send(Update::Progress(Progress::Arp)).await;
        match tokio::time::timeout(
            Duration::from_secs(5),
            arp::read(Scope::Interface {
                local_ip: interface.ip,
                device: &interface.name,
            }),
        )
        .await
        {
            Ok(Ok(entries)) => {
                for entry in entries
                    .into_iter()
                    .filter(|entry| in_subnet(&interface, entry.ip))
                {
                    devices
                        .entry(entry.ip)
                        .or_insert_with(|| Observation {
                            ping_reply: unanswered.contains(&entry.ip).then_some(false),
                            ..Observation::new(entry.ip)
                        })
                        .addresses
                        .push(entry);
                }
            }
            Ok(Err(error)) => report
                .notices
                .push(format!("Could not read ARP cache: {error}")),
            Err(_) => report
                .notices
                .push("Reading the ARP cache timed out.".into()),
        }

        report.devices = devices.into_values().collect();
        if !report.devices.is_empty() {
            sender.send(Update::Rows(report.devices.clone())).await;
        }
        if can_probe && !report.devices.is_empty() {
            match interfaces::verify_route(&interface).await {
                Ok(()) => match netbios::prepare() {
                    Ok(Some(runner)) => {
                        report = read_names(report, NameLookup::NetBios(runner))
                            .run(sender.clone())
                            .await;
                    }
                    Ok(None) => report.notices.push(
                        "NetBIOS lookup skipped because the system lookup utility is unavailable."
                            .into(),
                    ),
                    Err(error) => report
                        .notices
                        .push(format!("NetBIOS lookup unavailable: {error}")),
                },
                Err(error) => report
                    .notices
                    .push(format!("NetBIOS lookup skipped: {error}")),
            }
            match name_lookup::prepare() {
                Ok(resolver) => {
                    return read_names(report, NameLookup::ReverseDns(resolver))
                        .run(sender)
                        .await;
                }
                Err(error) => report
                    .notices
                    .push(format!("Reverse lookup unavailable: {error}")),
            }
        }
        report
    })
}

enum NameLookup {
    NetBios(netbios::Runner),
    ReverseDns(name_lookup::Resolver),
}

enum Names {
    NetBios(Vec<netbios::Name>),
    Hostname(String),
}

impl NameLookup {
    fn progress(&self, done: usize, total: usize) -> Progress {
        match self {
            Self::NetBios(_) => Progress::NetBios { done, total },
            Self::ReverseDns(_) => Progress::ReverseDns { done, total },
        }
    }

    fn label(&self) -> &'static str {
        match self {
            Self::NetBios(_) => "NetBIOS",
            Self::ReverseDns(_) => "reverse",
        }
    }

    async fn lookup(&self, ip: Ipv4Addr) -> Result<Option<Names>, String> {
        match self {
            Self::NetBios(runner) => match runner.lookup(ip).await {
                netbios::Outcome::Found(names) => Ok(Some(Names::NetBios(names))),
                netbios::Outcome::NoReply => Ok(None),
                netbios::Outcome::Failed(error) => Err(error),
            },
            Self::ReverseDns(resolver) => Ok(resolver.reverse(ip).await?.map(Names::Hostname)),
        }
    }
}

fn read_names(mut report: Report, lookup: NameLookup) -> impl Sipper<Report, Update> + Send {
    sipper(move |mut sender| async move {
        let lookup = &lookup;
        let addresses = report
            .devices
            .iter()
            .map(|device| device.ip)
            .collect::<Vec<_>>();
        let total = addresses.len();
        sender
            .send(Update::Progress(lookup.progress(0, total)))
            .await;
        let mut names = stream::iter(addresses.into_iter().enumerate().map(
            |(index, ip)| async move {
                let _permit = PROBES
                    .acquire()
                    .await
                    .expect("the probe semaphore stays open");
                (index, lookup.lookup(ip).await)
            },
        ))
        .buffer_unordered(NAME_CONCURRENCY);
        let mut first_error = None;
        let mut done = 0;
        let mut rows = Vec::new();
        while let Some((index, outcome)) = names.next().await {
            match outcome {
                Ok(Some(Names::NetBios(names))) => {
                    report.devices[index].names = names;
                    rows.push(report.devices[index].clone());
                }
                Ok(Some(Names::Hostname(hostname))) => {
                    report.devices[index].hostname = Some(hostname);
                    rows.push(report.devices[index].clone());
                }
                Ok(None) => {}
                Err(error) => {
                    first_error.get_or_insert(error);
                }
            }
            done += 1;
            if done % PROGRESS_BATCH == 0 || done == total {
                if !rows.is_empty() {
                    sender.send(Update::Rows(std::mem::take(&mut rows))).await;
                }
                sender
                    .send(Update::Progress(lookup.progress(done, total)))
                    .await;
            }
        }
        if let Some(error) = first_error {
            report
                .notices
                .push(format!("Some {} lookups failed: {error}", lookup.label()));
        }
        report
    })
}

fn eligible(interface: &interfaces::Interface) -> Result<impl Iterator<Item = Ipv4Addr>, String> {
    let (first, last) = host_bounds(interface);
    if last - first + 1 > MAX_HOSTS + 1 {
        return Err(format!(
            "This subnet exceeds the {MAX_HOSTS}-address discovery limit. Showing its ARP cache."
        ));
    }
    let local = u32::from(interface.ip);
    Ok((first..=last)
        .filter(move |ip| *ip != local)
        .map(Ipv4Addr::from))
}

pub(super) fn in_subnet(interface: &interfaces::Interface, address: Ipv4Addr) -> bool {
    let (first, last) = host_bounds(interface);
    address != interface.ip && (first..=last).contains(&u32::from(address))
}

fn host_bounds(interface: &interfaces::Interface) -> (u32, u32) {
    let mask = u32::MAX
        .checked_shl(32 - u32::from(interface.prefix))
        .unwrap_or(0);
    let network = u32::from(interface.ip) & mask;
    let broadcast = network | !mask;
    if interface.prefix <= 30 {
        (network + 1, broadcast - 1)
    } else {
        (network, broadcast)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn discovery_stays_within_the_interface_and_skips_its_own_address() {
        let mut interface = interfaces::Interface {
            name: "test".into(),
            ip: Ipv4Addr::new(192, 0, 2, 1),
            prefix: 30,
        };
        assert_eq!(
            eligible(&interface).unwrap().collect::<Vec<_>>(),
            [Ipv4Addr::new(192, 0, 2, 2)],
        );
        interface.prefix = 31;
        assert_eq!(
            eligible(&interface).unwrap().collect::<Vec<_>>(),
            [Ipv4Addr::new(192, 0, 2, 0)],
        );
        interface.prefix = 32;
        assert_eq!(eligible(&interface).unwrap().count(), 0);
        interface.prefix = 16;
        assert!(eligible(&interface).is_err());
    }
}
