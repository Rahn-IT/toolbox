use super::{
    check_view,
    local_link::{self, ArpResult},
    ping_check::PingResult,
};
use crate::network_scanner::{interfaces, ping};
use iced::Element;
use std::net::IpAddr;

pub(super) struct Gateway {
    pub(super) ip: IpAddr,
    pub(super) source: IpAddr,
    pub(super) interface: Option<String>,
    pub(super) result: Option<GatewayResult>,
}

#[derive(Clone)]
pub enum GatewayResult {
    Outside,
    Unavailable(String),
    Checked(PingResult, ArpResult),
}

impl Gateway {
    pub(super) async fn check(ip: IpAddr, source: IpAddr, device: Option<String>) -> GatewayResult {
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

    pub(super) fn view<M: 'static>(&self, label: String) -> Element<'_, M> {
        use iced::widget::{row, space, text};
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
                            || "Ping reply".to_owned(),
                            |t| format!("Ping reply · {t}"),
                        ),
                        true,
                    ),
                    ping::Outcome::Failed(error) => check_view::error_badge("Ping failed", error),
                    _ => check_view::badge("Ping no reply", false),
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
