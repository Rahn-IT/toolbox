use std::net::IpAddr;

use super::{
    Protocol, State, http, interfaces, local_link, name_resolution, port_connectivity,
    protocol_detection::{Application, Check, Detected},
    tls,
};

impl State {
    pub(crate) fn screenshot_dns_fixture() -> Self {
        let target = [192, 0, 2, 20].into();
        Self {
            host: "portal.example".into(),
            port: "443".into(),
            protocol: Some(Protocol::Https),
            target_ip: Some(target),
            resolver: name_resolution::Resolver::screenshot_fixture(target),
            local_link: local_link::State::screenshot_fixture(target, true),
            route: Some(Ok(interfaces::RouteDetails {
                interface: Some("Office Ethernet".into()),
                source: [192, 0, 2, 10].into(),
                gateway: None,
            })),
            port_connectivity: port_connectivity::State::Complete(
                (target, 443).into(),
                port_connectivity::Outcome::Refused,
            ),
            ..Self::default()
        }
    }

    pub(crate) fn screenshot_https_fixture() -> Self {
        let target = IpAddr::from([198, 51, 100, 24]);
        Self {
            host: target.to_string(),
            port: "443".into(),
            protocol: Some(Protocol::Https),
            target_ip: Some(target),
            resolver: name_resolution::Resolver::Ip(target),
            local_link: local_link::State::screenshot_fixture(target, false),
            route: Some(Ok(interfaces::RouteDetails {
                interface: Some("Office Ethernet".into()),
                source: [192, 0, 2, 10].into(),
                gateway: Some([192, 0, 2, 1].into()),
            })),
            port_connectivity: port_connectivity::State::Complete(
                (target, 443).into(),
                port_connectivity::Outcome::Connected,
            ),
            passive_result: Check::Complete(None),
            active_result: Check::Complete(Some(Detected::Tls(Some(Application::Http)))),
            tls: tls::State::screenshot_fixture(),
            http: http::State::screenshot_fixture(),
            ..Self::default()
        }
    }
}
