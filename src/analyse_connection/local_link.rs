use std::{
    net::{IpAddr, Ipv4Addr},
    time::Duration,
};

use iced::{
    Alignment, Element, Task,
    widget::{row, text},
};

use super::check_view::{badge, checking, error_badge};

use crate::{
    arp,
    network_scanner::{interfaces, ping},
};

#[derive(Clone)]
pub enum Message {
    ChecksStarted,
    PingFinished(PingResult),
    RouteFinished(Option<interfaces::Interface>),
    ArpFinished(ArpResult),
}

#[derive(Clone)]
pub struct PingResult(ping::Outcome);

#[derive(Clone)]
pub enum ArpResult {
    Skipped,
    Mac(String),
    Missing,
    Failed(String),
}

#[derive(Default)]
pub struct State {
    run: Option<Run>,
}

struct Run {
    target: IpAddr,
    phase: Phase,
}

enum Phase {
    PingPending,
    Pinging,
    RoutePending(PingResult, Ipv4Addr),
    CheckingRoute(PingResult, Ipv4Addr),
    ArpPending(PingResult, Ipv4Addr, interfaces::Interface),
    ReadingArp(PingResult),
    Done(PingResult, ArpResult),
}

impl State {
    #[cfg(test)]
    pub(super) fn screenshot_fixture(target: IpAddr, on_link: bool) -> Self {
        Self {
            run: Some(Run {
                target,
                phase: Phase::Done(
                    PingResult(ping::Outcome::Reply(Some(
                        if on_link { "1 ms" } else { "18 ms" }.into(),
                    ))),
                    if on_link {
                        ArpResult::Mac("02:00:00:00:00:14".into())
                    } else {
                        ArpResult::Skipped
                    },
                ),
            }),
        }
    }

    pub fn start(&mut self, target: IpAddr) {
        self.run.get_or_insert(Run {
            target,
            phase: Phase::PingPending,
        });
    }

    pub fn is_running(&self) -> bool {
        self.run
            .as_ref()
            .is_some_and(|run| !matches!(run.phase, Phase::Done(..)))
    }

    pub fn update(&mut self, message: Message) {
        let Some(run) = &mut self.run else { return };
        run.phase = match (
            std::mem::replace(&mut run.phase, Phase::PingPending),
            message,
        ) {
            (Phase::PingPending, Message::ChecksStarted) => Phase::Pinging,
            (Phase::Pinging, Message::PingFinished(ping)) => match arp_target(run.target) {
                Some(ip) => Phase::RoutePending(ping, ip),
                None => Phase::Done(ping, ArpResult::Skipped),
            },
            (Phase::RoutePending(ping, ip), Message::ChecksStarted) => {
                Phase::CheckingRoute(ping, ip)
            }
            (Phase::CheckingRoute(ping, ip), Message::RouteFinished(Some(interface))) => {
                Phase::ArpPending(ping, ip, interface)
            }
            (Phase::CheckingRoute(ping, _), Message::RouteFinished(None)) => {
                Phase::Done(ping, ArpResult::Skipped)
            }
            (Phase::ArpPending(ping, ..), Message::ChecksStarted) => Phase::ReadingArp(ping),
            (Phase::ReadingArp(ping), Message::ArpFinished(arp)) => Phase::Done(ping, arp),
            (phase, _) => phase,
        };
    }

    pub fn next_checks(&self) -> Task<Message> {
        let Some(run) = &self.run else {
            return Task::none();
        };
        match &run.phase {
            Phase::PingPending => Task::perform(ping_target(run.target), Message::PingFinished),
            Phase::RoutePending(_, ip) => {
                let ip = *ip;
                Task::perform(
                    async move { interfaces::on_link(ip).await.ok().flatten() },
                    Message::RouteFinished,
                )
            }
            Phase::ArpPending(_, ip, interface) => {
                Task::perform(read_arp(*ip, interface.clone()), Message::ArpFinished)
            }
            _ => Task::none(),
        }
    }

    pub fn ping_view(&self) -> Option<Element<'_, Message>> {
        Some(match &self.run.as_ref()?.phase {
            Phase::PingPending => return None,
            Phase::Pinging => checking(),
            Phase::RoutePending(ping, _)
            | Phase::CheckingRoute(ping, _)
            | Phase::ArpPending(ping, ..)
            | Phase::ReadingArp(ping)
            | Phase::Done(ping, _) => ping.view(),
        })
    }

    pub fn arp_view(&self) -> Option<Element<'_, Message>> {
        self.run.as_ref()?.phase.arp_view()
    }
}

impl Phase {
    fn arp_view(&self) -> Option<Element<'_, Message>> {
        match self {
            Self::ReadingArp(_) => Some(checking()),
            Self::Done(_, arp) => arp.view(),
            _ => None,
        }
    }
}

impl PingResult {
    fn view(&self) -> Element<'_, Message> {
        match &self.0 {
            ping::Outcome::Reply(timing) => {
                row![badge("Reply", true), timing.as_deref().map(text),]
                    .align_y(Alignment::Center)
                    .spacing(8)
                    .into()
            }
            ping::Outcome::NoReply | ping::Outcome::TimedOut => badge("No reply", false),
            ping::Outcome::Failed(error) => error_badge("No reply", error),
        }
    }
}

impl ArpResult {
    fn view(&self) -> Option<Element<'_, Message>> {
        Some(match self {
            Self::Skipped => return None,
            Self::Mac(mac) => badge(mac, true),
            Self::Missing => badge("No ARP entry", false),
            Self::Failed(error) => error_badge("ARP unavailable", error),
        })
    }
}

fn arp_target(target: IpAddr) -> Option<Ipv4Addr> {
    match target {
        IpAddr::V4(ip)
            if !ip.is_loopback()
                && !ip.is_unspecified()
                && !ip.is_multicast()
                && !ip.is_broadcast() =>
        {
            Some(ip)
        }
        _ => None,
    }
}

async fn ping_target(target: IpAddr) -> PingResult {
    PingResult(match ping::prepare().await {
        Ok(runner) => runner.echo(None, target).await,
        Err(error) => ping::Outcome::Failed(error),
    })
}

async fn read_arp(ip: Ipv4Addr, interface: interfaces::Interface) -> ArpResult {
    let scope = arp::Scope::Interface {
        local_ip: interface.ip,
        device: &interface.name,
    };
    match tokio::time::timeout(Duration::from_secs(3), arp::read(scope)).await {
        Ok(Ok(entries)) => entries
            .iter()
            .find(|entry| entry.ip == ip)
            .map_or(ArpResult::Missing, |entry| {
                ArpResult::Mac(entry.mac_address())
            }),
        Ok(Err(error)) => ArpResult::Failed(error),
        Err(_) => ArpResult::Failed("Reading the ARP table timed out".into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn arp_waits_for_ping_and_uses_the_same_address() {
        let ip = Ipv4Addr::new(192, 0, 2, 10);
        let mut state = State::default();
        state.start(ip.into());
        assert_eq!(state.next_checks().units(), 1);
        state.update(Message::ChecksStarted);
        assert_eq!(state.next_checks().units(), 0);
        state.update(Message::PingFinished(PingResult(ping::Outcome::NoReply)));
        assert!(matches!(
            state.run.as_ref().unwrap().phase,
            Phase::RoutePending(_, target) if target == ip
        ));
        assert_eq!(state.next_checks().units(), 1);
        state.update(Message::ChecksStarted);
        assert!(state.run.as_ref().unwrap().phase.arp_view().is_none());
        state.update(Message::RouteFinished(Some(interfaces::Interface {
            name: "test".into(),
            ip: Ipv4Addr::new(192, 0, 2, 1),
            prefix: 24,
        })));
        assert_eq!(state.next_checks().units(), 1);
        state.update(Message::ChecksStarted);
        assert!(state.run.as_ref().unwrap().phase.arp_view().is_some());
        state.update(Message::ArpFinished(ArpResult::Missing));
        assert!(!state.is_running());
    }

    #[test]
    fn an_off_link_route_never_shows_an_arp_result() {
        let mut state = State::default();
        state.start(IpAddr::from([192, 0, 2, 10]));
        state.update(Message::ChecksStarted);
        state.update(Message::PingFinished(PingResult(ping::Outcome::Reply(
            None,
        ))));
        state.update(Message::ChecksStarted);
        assert!(state.run.as_ref().unwrap().phase.arp_view().is_none());
        state.update(Message::RouteFinished(None));
        assert!(state.run.as_ref().unwrap().phase.arp_view().is_none());
        assert!(!state.is_running());
    }

    #[test]
    fn ipv6_finishes_after_ping_without_an_arp_check() {
        let ip = "2001:db8::1".parse().unwrap();
        let mut state = State::default();
        state.start(ip);
        state.update(Message::ChecksStarted);
        state.update(Message::PingFinished(PingResult(ping::Outcome::Reply(
            None,
        ))));
        assert!(!state.is_running());
        assert_eq!(state.next_checks().units(), 0);
    }
}
