use std::{
    io::ErrorKind,
    net::{Ipv4Addr, SocketAddr, SocketAddrV4},
    time::Duration,
};

use futures_util::{Stream, StreamExt, stream};
use iced::task::{Sipper, sipper};
use tokio::net::TcpSocket;

use super::{
    interfaces::{self, Interface},
    scan::PROBES,
};

pub(super) struct Port {
    pub(super) number: u16,
    pub(super) label: &'static str,
    pub(super) web_protocol: Option<&'static str>,
}

impl Port {
    const fn new(number: u16, label: &'static str, web_protocol: Option<&'static str>) -> Self {
        Self {
            number,
            label,
            web_protocol,
        }
    }
}

pub(super) const PORTS: &[Port] = &[
    Port::new(21, "FTP", None),
    Port::new(22, "SSH", None),
    Port::new(25, "SMTP", None),
    Port::new(80, "HTTP", Some("http")),
    Port::new(110, "POP3", None),
    Port::new(143, "IMAP", None),
    Port::new(443, "HTTPS", Some("https")),
    Port::new(445, "SMB", None),
    Port::new(465, "SMTP submission over TLS", None),
    Port::new(587, "SMTP submission", None),
    Port::new(631, "IPP printing", None),
    Port::new(993, "IMAP over TLS", None),
    Port::new(995, "POP3 over TLS", None),
    Port::new(3389, "Remote Desktop (RDP)", None),
    Port::new(3493, "Network UPS Tools", None),
    Port::new(4040, "ngrok / Spark web UI", None),
    Port::new(8006, "Proxmox VE", Some("https")),
    Port::new(8080, "HTTP (alternate)", Some("http")),
    Port::new(8443, "HTTPS (alternate)", Some("https")),
    Port::new(9100, "Raw printing", None),
    Port::new(51821, "wg-easy web UI", None),
];

pub(super) const EXTRA_PORTS: &[Port] = &[Port::new(9443, "Portainer", Some("https"))];

pub(super) fn definition(number: u16) -> Option<&'static Port> {
    PORTS
        .iter()
        .chain(EXTRA_PORTS)
        .find(|port| port.number == number)
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    Open,
    Refused,
    TimedOut,
    Failed,
}

pub(super) fn check(
    interface: Interface,
    addresses: Vec<Ipv4Addr>,
) -> impl Sipper<Result<(), String>, (Ipv4Addr, u16, Outcome)> + Send {
    sipper(move |mut sender| async move {
        interfaces::verify_route(&interface)
            .await
            .map_err(|error| error.to_string())?;
        let mut results = check_addresses(interface.ip, addresses, &[]);
        while let Some(result) = results.next().await {
            sender.send(result).await;
        }
        Ok(())
    })
}

pub(super) fn check_addresses(
    local: Ipv4Addr,
    addresses: impl IntoIterator<Item = Ipv4Addr, IntoIter: Send + Unpin>,
    extra_ports: &'static [Port],
) -> impl Stream<Item = (Ipv4Addr, u16, Outcome)> + Send + Unpin {
    let pairs = addresses.into_iter().flat_map(move |address| {
        PORTS
            .iter()
            .chain(extra_ports)
            .map(move |port| (address, port.number))
    });
    stream::iter(pairs.map(move |(address, port)| async move {
        let _permit = PROBES
            .acquire()
            .await
            .expect("the probe semaphore stays open");
        (
            address,
            port,
            connect(local, SocketAddrV4::new(address, port)).await,
        )
    }))
    .buffer_unordered(32)
}

async fn connect(local: Ipv4Addr, remote: SocketAddrV4) -> Outcome {
    let Ok(socket) = TcpSocket::new_v4() else {
        return Outcome::Failed;
    };
    if socket.bind(SocketAddr::from((local, 0))).is_err() {
        return Outcome::Failed;
    }
    match tokio::time::timeout(Duration::from_secs(1), socket.connect(remote.into())).await {
        Ok(Ok(_)) => Outcome::Open,
        Ok(Err(error)) if error.kind() == ErrorKind::ConnectionRefused => Outcome::Refused,
        Ok(Err(error)) if error.kind() == ErrorKind::TimedOut => Outcome::TimedOut,
        Ok(Err(_)) => Outcome::Failed,
        Err(_) => Outcome::TimedOut,
    }
}

pub(super) async fn check_single(
    interface: Interface,
    address: Ipv4Addr,
    port: u16,
) -> Result<Outcome, String> {
    let _permit = PROBES
        .acquire()
        .await
        .expect("the probe semaphore stays open");
    interfaces::verify_route(&interface)
        .await
        .map_err(|error| error.to_string())?;
    Ok(connect(interface.ip, SocketAddrV4::new(address, port)).await)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fixed_ports_include_smb_and_requested_mail_ports() {
        for port in [25, 110, 143, 445, 465, 587, 993, 995, 51821] {
            assert!(definition(port).is_some());
        }
    }

    #[test]
    fn portainer_is_a_device_only_https_port() {
        assert!(!PORTS.iter().any(|port| port.number == 9443));
        let port = definition(9443).unwrap();
        assert_eq!(
            (port.label, port.web_protocol),
            ("Portainer", Some("https"))
        );
    }

    #[tokio::test]
    async fn checks_a_loopback_listener() {
        let listener = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .unwrap();
        let port = listener.local_addr().unwrap().port();
        assert!(matches!(
            connect(
                Ipv4Addr::LOCALHOST,
                SocketAddrV4::new(Ipv4Addr::LOCALHOST, port)
            )
            .await,
            Outcome::Open
        ));
    }
}
