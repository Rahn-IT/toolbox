use std::{fmt, net::Ipv4Addr};

#[cfg(any(windows, target_os = "linux"))]
use std::{io, time::Duration};
#[cfg(any(windows, target_os = "linux"))]
use tokio::process::Command;

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Interface {
    pub name: String,
    pub ip: Ipv4Addr,
    pub prefix: u8,
}

impl fmt::Display for Interface {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{} · {}/{}", self.name, self.ip, self.prefix)
    }
}

#[derive(Clone, Debug, thiserror::Error)]
pub enum Error {
    #[cfg(any(windows, target_os = "linux"))]
    #[error("{tool} is unavailable: {details}")]
    Unavailable { tool: &'static str, details: String },
    #[cfg(any(windows, target_os = "linux"))]
    #[error("{tool} failed: {details}")]
    Command { tool: &'static str, details: String },
    #[cfg(any(windows, target_os = "linux"))]
    #[error("{tool} did not respond in time.")]
    Timeout { tool: &'static str },
    #[cfg(any(windows, target_os = "linux", test))]
    #[error("Could not read IPv4 data from {tool} output.")]
    Unrecognized { tool: &'static str },
    #[cfg(any(windows, test))]
    #[error("The IPv4 address {ip} is assigned to more than one interface.")]
    Ambiguous { ip: Ipv4Addr },
    #[cfg(any(windows, test))]
    #[error("No directly connected IPv4 route covers {ip}/{prefix}.")]
    MissingRoute { ip: Ipv4Addr, prefix: u8 },
    #[cfg(any(windows, test))]
    #[error(
        "The competing route {network}/{prefix} can redirect traffic from the selected subnet."
    )]
    ConflictingRoute { network: Ipv4Addr, prefix: u8 },
    #[cfg(not(any(windows, target_os = "linux")))]
    #[error("Reading network interfaces is supported on Windows and Linux.")]
    Unsupported,
}

#[cfg(windows)]
pub(super) async fn list() -> Result<Vec<Interface>, Error> {
    const TOOL: &str = "netsh.exe";
    let path =
        crate::quick_tools::system::executable(TOOL).map_err(|details| Error::Unavailable {
            tool: TOOL,
            details,
        })?;
    let mut command = Command::new(path);
    command
        .args(["interface", "ipv4", "show", "addresses"])
        .creation_flags(0x0800_0000); // CREATE_NO_WINDOW
    parse_windows(&read_output(command, TOOL).await?)
}

#[cfg(windows)]
pub(super) async fn verify_route(interface: &Interface) -> Result<(), Error> {
    check_routes(interface, &windows_routes().await?)
}

#[cfg(windows)]
async fn windows_routes() -> Result<String, Error> {
    const TOOL: &str = "route.exe";
    let path =
        crate::quick_tools::system::executable(TOOL).map_err(|details| Error::Unavailable {
            tool: TOOL,
            details,
        })?;
    let mut command = Command::new(path);
    command.args(["print", "-4"]).creation_flags(0x0800_0000);
    read_output(command, TOOL).await
}

#[cfg(windows)]
pub(crate) async fn on_link(target: Ipv4Addr) -> Result<Option<Interface>, Error> {
    let output = windows_routes().await?;
    let routes = parse_routes(&output)?;
    let Some(route) = best_route(&routes, target).filter(|route| route.on_link) else {
        return Ok(None);
    };
    Ok(list()
        .await?
        .into_iter()
        .find(|interface| interface.ip == route.source && interface.is_neighbor(target)))
}

#[cfg(target_os = "linux")]
pub(crate) async fn on_link(target: Ipv4Addr) -> Result<Option<Interface>, Error> {
    const TOOL: &str = "ip";
    let mut command = Command::new(TOOL);
    command
        .args(["-4", "-o", "route", "get", &target.to_string()])
        .env("LC_ALL", "C");
    let output = read_output(command, TOOL).await?;
    let Some((device, source)) = linux_on_link_route(&output)? else {
        return Ok(None);
    };
    Ok(list().await?.into_iter().find(|interface| {
        interface.name == device && interface.ip == source && interface.is_neighbor(target)
    }))
}

#[cfg(not(any(windows, target_os = "linux")))]
pub(crate) async fn on_link(_target: Ipv4Addr) -> Result<Option<Interface>, Error> {
    Err(Error::Unsupported)
}

#[cfg(any(windows, target_os = "linux"))]
impl Interface {
    fn is_neighbor(&self, target: Ipv4Addr) -> bool {
        let mask = prefix_mask(self.prefix);
        target != self.ip && (u32::from(target) & mask) == (u32::from(self.ip) & mask)
    }
}

#[cfg(any(target_os = "linux", test))]
fn linux_on_link_route(output: &str) -> Result<Option<(&str, Ipv4Addr)>, Error> {
    const ERROR: Error = Error::Unrecognized { tool: "ip" };
    let fields: Vec<_> = output.split_ascii_whitespace().collect();
    if fields
        .first()
        .is_some_and(|field| matches!(*field, "local" | "broadcast" | "multicast"))
        || fields.contains(&"via")
    {
        return Ok(None);
    }
    let value = |key| {
        fields
            .windows(2)
            .find(|pair| pair[0] == key)
            .map(|pair| pair[1])
    };
    let dev = value("dev").ok_or(ERROR)?;
    let source = value("src")
        .and_then(|value| value.parse().ok())
        .ok_or(ERROR)?;
    Ok(Some((dev, source)))
}

#[cfg(target_os = "linux")]
pub(super) async fn verify_route(_interface: &Interface) -> Result<(), Error> {
    Ok(())
}

#[cfg(not(any(windows, target_os = "linux")))]
pub(super) async fn verify_route(_interface: &Interface) -> Result<(), Error> {
    Err(Error::Unsupported)
}

#[cfg(target_os = "linux")]
pub(super) async fn list() -> Result<Vec<Interface>, Error> {
    let mut command = Command::new("ip");
    command
        .args(["-o", "-4", "address", "show", "up"])
        .env("LC_ALL", "C");
    parse_linux(&read_output(command, "ip").await?)
}

#[cfg(not(any(windows, target_os = "linux")))]
pub(super) async fn list() -> Result<Vec<Interface>, Error> {
    Err(Error::Unsupported)
}

#[cfg(any(windows, target_os = "linux"))]
async fn read_output(mut command: Command, tool: &'static str) -> Result<String, Error> {
    let output = tokio::time::timeout(Duration::from_secs(5), command.kill_on_drop(true).output())
        .await
        .map_err(|_| Error::Timeout { tool })?
        .map_err(|error| {
            let details = error.to_string();
            if error.kind() == io::ErrorKind::NotFound {
                Error::Unavailable { tool, details }
            } else {
                Error::Command { tool, details }
            }
        })?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let stdout = String::from_utf8_lossy(&output.stdout);
        let details = [stderr.trim(), stdout.trim()]
            .into_iter()
            .find(|text| !text.is_empty())
            .map_or_else(|| output.status.to_string(), str::to_owned);
        return Err(Error::Command { tool, details });
    }
    Ok(String::from_utf8_lossy(&output.stdout).into_owned())
}

#[cfg(any(windows, test))]
fn parse_windows(output: &str) -> Result<Vec<Interface>, Error> {
    const ERROR: Error = Error::Unrecognized { tool: "netsh.exe" };
    let mut interfaces = Vec::new();
    let mut adapter = None;
    let mut ip = None;
    let mut recognized = false;

    for line in output
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
    {
        // The heading's quoted adapter name and the address/prefix values
        // have the same shape across the supported output languages.
        if let Some((_, name)) = line.split_once('"')
            && let Some(name) = name.strip_suffix('"').filter(|name| !name.is_empty())
        {
            adapter = Some(name);
            ip = None;
            recognized = true;
            continue;
        }

        let Some(name) = adapter else { continue };
        let Some((_, value)) = line.split_once(':') else {
            continue;
        };
        let value = value.trim();
        if let Some(cidr) = value.split_ascii_whitespace().next()
            && cidr.contains('/')
        {
            let (network, prefix) = parse_cidr(cidr).ok_or(ERROR)?;
            let address: Ipv4Addr = ip.take().ok_or(ERROR)?;
            let mask = u32::MAX.checked_shl(32 - u32::from(prefix)).unwrap_or(0);
            if u32::from(address) & mask != u32::from(network) & mask {
                return Err(ERROR);
            }
            push_interface(&mut interfaces, name, address, prefix);
        } else {
            ip = value.parse().ok();
        }
    }

    if !recognized && !output.trim().is_empty() {
        return Err(ERROR);
    }
    let mut names_by_ip = std::collections::BTreeMap::new();
    for interface in &interfaces {
        if let Some(previous) = names_by_ip.insert(interface.ip, &interface.name)
            && previous != &interface.name
        {
            return Err(Error::Ambiguous { ip: interface.ip });
        }
    }
    Ok(sorted(interfaces))
}

#[cfg(any(windows, test))]
struct Route {
    network: u32,
    last: u32,
    prefix: u8,
    source: Ipv4Addr,
    on_link: bool,
    metric: u32,
}

#[cfg(any(windows, test))]
fn best_route(routes: &[Route], target: Ipv4Addr) -> Option<&Route> {
    let target = u32::from(target);
    routes
        .iter()
        .filter(|route| (route.network..=route.last).contains(&target))
        .min_by_key(|route| (std::cmp::Reverse(route.prefix), route.metric))
}

#[cfg(any(windows, test))]
fn check_routes(interface: &Interface, output: &str) -> Result<(), Error> {
    let missing_route = Error::MissingRoute {
        ip: interface.ip,
        prefix: interface.prefix,
    };
    if interface.prefix > 32 {
        return Err(missing_route);
    }

    let routes = parse_routes(output)?;
    let local = u32::from(interface.ip);
    let mask = prefix_mask(interface.prefix);
    let first = local & mask;
    let last = first | !mask;
    let direct_prefix = routes
        .iter()
        .filter(|route| {
            route.on_link
                && route.source == interface.ip
                && route.network <= first
                && last <= route.last
        })
        .map(|route| route.prefix)
        .max()
        .ok_or(missing_route)?;

    let omit_endpoints = u32::from(interface.prefix < 31);
    for route in &routes {
        let overlap_start = route.network.max(first + omit_endpoints);
        let overlap_end = route.last.min(last - omit_endpoints);
        let has_candidate =
            overlap_start <= overlap_end && (overlap_start != local || overlap_end != local);
        if route.prefix >= direct_prefix
            && (!route.on_link || route.source != interface.ip)
            && has_candidate
        {
            return Err(Error::ConflictingRoute {
                network: route.network.into(),
                prefix: route.prefix,
            });
        }
    }
    Ok(())
}

#[cfg(any(windows, test))]
fn parse_routes(output: &str) -> Result<Vec<Route>, Error> {
    const ERROR: Error = Error::Unrecognized { tool: "route.exe" };
    let mut lines = output
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty());
    lines
        .find(|line| matches!(*line, "Active Routes:" | "Aktive Routen:"))
        .ok_or(ERROR)?;
    let header = lines.next().ok_or(ERROR)?;
    if !header.starts_with("Network Destination") && !header.starts_with("Netzwerkziel") {
        return Err(ERROR);
    }

    let mut routes = Vec::new();
    for line in lines {
        if line.len() >= 8 && line.bytes().all(|byte| byte == b'=') {
            return Ok(routes);
        }

        let fields: Vec<_> = line.split_ascii_whitespace().collect();
        let [destination, netmask, gateway @ .., source, metric] = fields.as_slice() else {
            return Err(ERROR);
        };
        let network = u32::from(destination.parse::<Ipv4Addr>().map_err(|_| ERROR)?);
        let mask = u32::from(netmask.parse::<Ipv4Addr>().map_err(|_| ERROR)?);
        let prefix = mask.leading_ones() as u8;
        if mask != prefix_mask(prefix) || network & mask != network {
            return Err(ERROR);
        }
        let source = source.parse().map_err(|_| ERROR)?;
        let metric = metric.parse::<u32>().map_err(|_| ERROR)?;
        let on_link = match gateway {
            ["On-link"] | ["Auf", "Verbindung"] => true,
            [ip] if ip.parse::<Ipv4Addr>().is_ok() => false,
            _ => return Err(ERROR),
        };
        routes.push(Route {
            network,
            last: network | !mask,
            prefix,
            source,
            on_link,
            metric,
        });
    }
    Err(ERROR)
}

#[cfg(any(windows, target_os = "linux", test))]
fn prefix_mask(prefix: u8) -> u32 {
    u32::MAX.checked_shl(32 - u32::from(prefix)).unwrap_or(0)
}

#[cfg(any(target_os = "linux", test))]
fn parse_linux(output: &str) -> Result<Vec<Interface>, Error> {
    const ERROR: Error = Error::Unrecognized { tool: "ip" };
    let mut interfaces = Vec::new();
    for line in output.lines().filter(|line| !line.trim().is_empty()) {
        let mut fields = line.split_ascii_whitespace();
        let _index = fields
            .next()
            .and_then(|index| index.strip_suffix(':'))
            .and_then(|index| index.parse::<u32>().ok())
            .ok_or(ERROR)?;
        let name = fields.next().ok_or(ERROR)?;
        let name = name.split_once('@').map_or(name, |(device, _)| device);
        if fields.next() != Some("inet") {
            return Err(ERROR);
        }
        let (ip, prefix) = fields.next().and_then(parse_cidr).ok_or(ERROR)?;
        push_interface(&mut interfaces, name, ip, prefix);
    }
    Ok(sorted(interfaces))
}

#[cfg(any(windows, target_os = "linux", test))]
fn parse_cidr(value: &str) -> Option<(Ipv4Addr, u8)> {
    let (ip, prefix) = value.split_once('/')?;
    let prefix = prefix.parse().ok()?;
    (prefix <= 32).then_some((ip.parse().ok()?, prefix))
}

#[cfg(any(windows, target_os = "linux", test))]
fn push_interface(interfaces: &mut Vec<Interface>, name: &str, ip: Ipv4Addr, prefix: u8) {
    if !name.is_empty()
        && !ip.is_loopback()
        && !ip.is_unspecified()
        && !ip.is_multicast()
        && ip != Ipv4Addr::BROADCAST
    {
        interfaces.push(Interface {
            name: name.to_owned(),
            ip,
            prefix,
        });
    }
}

#[cfg(any(windows, target_os = "linux", test))]
fn sorted(mut interfaces: Vec<Interface>) -> Vec<Interface> {
    interfaces.sort_unstable();
    interfaces.dedup();
    interfaces
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn selects_the_most_specific_windows_route_for_arp() {
        let routes = parse_routes(
            "Active Routes:\nNetwork Destination Netmask Gateway Interface Metric\n\
            192.0.2.0 255.255.255.0 On-link 192.0.2.1 10\n\
            192.0.2.42 255.255.255.255 192.0.2.254 192.0.2.1 20\n\
            192.0.2.42 255.255.255.255 On-link 192.0.2.1 30\n\
            ====================\n",
        )
        .unwrap();
        assert!(
            best_route(&routes, Ipv4Addr::new(192, 0, 2, 41))
                .unwrap()
                .on_link
        );
        assert!(
            !best_route(&routes, Ipv4Addr::new(192, 0, 2, 42))
                .unwrap()
                .on_link
        );
    }

    #[test]
    fn linux_arp_route_must_be_direct_and_remote_to_the_interface() {
        let address = Ipv4Addr::new(192, 0, 2, 1);
        assert_eq!(
            linux_on_link_route("192.0.2.2 dev eth0 src 192.0.2.1 uid 1000").unwrap(),
            Some(("eth0", address))
        );
        assert_eq!(
            linux_on_link_route("198.51.100.2 via 192.0.2.254 dev eth0 src 192.0.2.1").unwrap(),
            None
        );
        assert_eq!(
            linux_on_link_route("local 192.0.2.1 dev lo src 192.0.2.1").unwrap(),
            None
        );
    }

    fn route_check(rows: &str) -> Result<(), Error> {
        let interface = Interface {
            name: "Ethernet".into(),
            ip: Ipv4Addr::new(192, 168, 1, 20),
            prefix: 24,
        };
        let output = format!(
            "IPv4-Routentabelle\nAktive Routen:\n\
            Netzwerkziel Netzwerkmaske Gateway Schnittstelle Metrik\n\
            {rows}\n====================================\n\
            Ständige Routen:\n192.168.1.99 255.255.255.255 192.168.1.1 1"
        );
        check_routes(&interface, &output)
    }

    #[test]
    fn accepts_localized_on_link_and_ignores_excluded_addresses() {
        assert!(
            route_check(concat!(
                "0.0.0.0 0.0.0.0 192.168.1.1 192.168.1.20 15\n",
                "192.168.1.0 255.255.255.0 Auf Verbindung 192.168.1.20 281\n",
                "192.168.1.20 255.255.255.255 On-link 10.0.0.1 1\n",
                "192.168.1.255 255.255.255.255 On-link 10.0.0.1 1"
            ))
            .is_ok()
        );
    }

    #[test]
    fn rejects_a_vpn_host_route_and_a_gateway_on_the_same_adapter() {
        for conflicting in [
            "192.168.1.99 255.255.255.255 On-link 10.0.0.1 1",
            "192.168.1.99 255.255.255.255 192.168.1.1 192.168.1.20 1",
        ] {
            let rows =
                format!("192.168.1.0 255.255.255.0 Auf Verbindung 192.168.1.20 281\n{conflicting}");
            assert!(matches!(
                route_check(&rows),
                Err(Error::ConflictingRoute { .. })
            ));
        }
    }

    #[test]
    fn requires_the_selected_address_and_a_readable_active_table() {
        assert!(matches!(
            route_check("192.168.1.0 255.255.255.0 On-link 192.168.1.21 281"),
            Err(Error::MissingRoute { .. })
        ));
        assert!(matches!(
            route_check("192.168.1.0 255.255.255.0 invalid gateway text 192.168.1.20 281"),
            Err(Error::Unrecognized { .. })
        ));
    }

    #[test]
    fn parses_localized_windows_adapters_and_multiple_addresses() {
        let output = r#"
Konfiguration der Schnittstelle "Ethernet"
    DHCP aktiviert: Ja
    IP-Adresse: 192.168.1.20
    Subnetzpräfix: 192.168.1.0/24 (Maske 255.255.255.0)
    IP-Adresse: 10.0.0.20
    Subnetzpräfix: 10.0.0.0/16 (Maske 255.255.0.0)
Configuration for interface "Loopback"
    IP Address: 127.0.0.1
    Subnet Prefix: 127.0.0.0/8 (mask 255.0.0.0)
"#;
        let interfaces = parse_windows(output).unwrap();
        assert_eq!(interfaces.len(), 2);
        assert_eq!(interfaces[0].to_string(), "Ethernet · 10.0.0.20/16");
        assert_eq!(interfaces[1].to_string(), "Ethernet · 192.168.1.20/24");
    }

    #[test]
    fn rejects_duplicate_windows_addresses_on_distinct_adapters() {
        let output = r#"
Configuration for interface "Ethernet"
    IP Address: 192.168.1.20
    Subnet Prefix: 192.168.1.0/24 (mask 255.255.255.0)
Configuration for interface "VPN"
    IP Address: 192.168.1.20
    Subnet Prefix: 192.168.1.20/32 (mask 255.255.255.255)
"#;
        assert!(matches!(
            parse_windows(output),
            Err(Error::Ambiguous { .. })
        ));
    }

    #[test]
    fn linux_normalizes_peer_suffix_and_retains_prefix() {
        let output = "1: lo inet 127.0.0.1/8 scope host lo\n\
            3: veth0@if5 inet 192.168.1.20/24 scope global veth0\n";
        let interfaces = parse_linux(output).unwrap();
        assert_eq!(interfaces.len(), 1);
        assert_eq!(interfaces[0].to_string(), "veth0 · 192.168.1.20/24");
        assert!(matches!(
            parse_linux("3: veth0 inet 192.168.1.20/33"),
            Err(Error::Unrecognized { .. })
        ));
    }
}
