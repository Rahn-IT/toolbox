#[cfg(any(windows, test))]
use std::net::Ipv6Addr;
use std::{
    fmt,
    net::{IpAddr, Ipv4Addr},
};

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
    #[error("No route was found for {0}.")]
    NoRoute(IpAddr),
    #[cfg(windows)]
    #[error("Could not determine the route source: {0}")]
    RouteSource(String),
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
pub(crate) async fn list() -> Result<Vec<Interface>, Error> {
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
    check_routes(interface, &windows_routes("-4").await?)
}

#[cfg(windows)]
async fn windows_routes(family: &str) -> Result<String, Error> {
    const TOOL: &str = "route.exe";
    let path =
        crate::quick_tools::system::executable(TOOL).map_err(|details| Error::Unavailable {
            tool: TOOL,
            details,
        })?;
    let mut command = Command::new(path);
    command.args(["print", family]).creation_flags(0x0800_0000);
    read_output(command, TOOL).await
}

#[cfg(windows)]
pub(crate) async fn on_link(target: Ipv4Addr) -> Result<Option<Interface>, Error> {
    let output = windows_routes("-4").await?;
    let routes = parse_routes(&output)?;
    let Some(route) = best_route(&routes, target).filter(|route| route.on_link) else {
        return Ok(None);
    };
    Ok(list()
        .await?
        .into_iter()
        .find(|interface| interface.ip == route.source && interface.is_neighbor(target)))
}

#[derive(Clone)]
pub struct RouteDetails {
    pub interface: Option<String>,
    pub source: IpAddr,
    pub gateway: Option<IpAddr>,
}

#[cfg(windows)]
pub(crate) async fn route_details(target: IpAddr) -> Result<RouteDetails, Error> {
    use std::net::SocketAddr;
    use tokio::net::UdpSocket;

    let bind = if target.is_ipv4() {
        "0.0.0.0:0"
    } else {
        "[::]:0"
    };
    // Connecting a UDP socket selects a local address without sending a packet.
    let source = async {
        let socket = UdpSocket::bind(bind).await?;
        socket.connect(SocketAddr::new(target, 9)).await?;
        Ok::<_, io::Error>(socket.local_addr()?.ip())
    }
    .await
    .map_err(|error| match error.kind() {
        io::ErrorKind::NetworkUnreachable | io::ErrorKind::HostUnreachable => {
            Error::NoRoute(target)
        }
        _ => Error::RouteSource(error.to_string()),
    })?;
    let adapters = tokio::task::spawn_blocking(crate::windows_network::adapters)
        .await
        .ok()
        .and_then(Result::ok)
        .unwrap_or_default();
    let source_adapter = adapters
        .iter()
        .find(|adapter| adapter.ip_addresses().contains(&source));
    let (interface, gateway) = match target {
        IpAddr::V4(target) => {
            let output = windows_routes("-4").await?;
            let routes = parse_routes(&output)?;
            let route = best_route(&routes, target).ok_or(Error::NoRoute(target.into()))?;
            let adapter = adapters
                .iter()
                .find(|adapter| adapter.ip_addresses().contains(&route.source.into()));
            (
                adapter
                    .or(source_adapter)
                    .map(|adapter| adapter.friendly_name().to_owned()),
                route.gateway.map(IpAddr::from),
            )
        }
        IpAddr::V6(target) => {
            let output = windows_routes("-6").await?;
            let (index, gateway) = best_ipv6_route(
                &output,
                target,
                source_adapter.map(|adapter| adapter.ipv6_if_index()),
            )
            .ok_or(Error::NoRoute(target.into()))?;
            let interface = adapters
                .iter()
                .find(|adapter| adapter.ipv6_if_index() == index)
                .map_or_else(
                    || format!("#{index}"),
                    |adapter| adapter.friendly_name().to_owned(),
                );
            (Some(interface), gateway.map(IpAddr::from))
        }
    };
    Ok(RouteDetails {
        interface,
        source,
        gateway,
    })
}

#[cfg(any(windows, test))]
fn best_ipv6_route(
    output: &str,
    target: Ipv6Addr,
    interface: Option<u32>,
) -> Option<(u32, Option<Ipv6Addr>)> {
    let mut lines = output.lines().map(str::trim);
    lines.find(|line| matches!(*line, "Active Routes:" | "Aktive Routen:"))?;
    let mut best = None;
    while let Some(line) = lines.next() {
        if line.starts_with("====") {
            break;
        }
        let mut fields = line.split_ascii_whitespace();
        let (Some(index), Some(metric), Some(cidr)) = (fields.next(), fields.next(), fields.next())
        else {
            continue;
        };
        let (Ok(index), Ok(metric)) = (index.parse::<u32>(), metric.parse::<u32>()) else {
            continue;
        };
        let gateway = match fields.next() {
            Some(gateway) => gateway,
            None => lines
                .next()
                .unwrap_or_default()
                .split_ascii_whitespace()
                .next()
                .unwrap_or_default(),
        };
        let gateway = match gateway {
            "On-link" | "Auf" => None,
            value => match value.split('%').next().and_then(|value| value.parse().ok()) {
                Some(gateway) => Some(gateway),
                None => continue,
            },
        };
        let Some((network, prefix)) = cidr.split_once('/').and_then(|(network, prefix)| {
            Some((
                network.parse::<Ipv6Addr>().ok()?,
                prefix.parse::<u8>().ok()?,
            ))
        }) else {
            continue;
        };
        if prefix > 128 || interface.is_some_and(|selected| index != selected) {
            continue;
        }
        let mask = u128::MAX.checked_shl(128 - u32::from(prefix)).unwrap_or(0);
        let priority = (std::cmp::Reverse(prefix), metric);
        if u128::from(target) & mask == u128::from(network) & mask
            && best
                .as_ref()
                .is_none_or(|(previous, _)| priority < *previous)
        {
            best = Some((priority, (index, gateway)));
        }
    }
    best.map(|(_, route)| route)
}

#[cfg(target_os = "linux")]
pub(crate) async fn route_details(target: IpAddr) -> Result<RouteDetails, Error> {
    let family = if target.is_ipv4() { "-4" } else { "-6" };
    let mut command = Command::new("ip");
    command
        .args([family, "-o", "route", "get", &target.to_string()])
        .env("LC_ALL", "C");
    let output = match read_output(command, "ip").await {
        Err(Error::Command { details, .. })
            if details.ends_with("Network is unreachable")
                || details.ends_with("No route to host") =>
        {
            return Err(Error::NoRoute(target));
        }
        result => result?,
    };
    parse_linux_route(&output).ok_or(Error::Unrecognized { tool: "ip" })
}

#[derive(Clone, Default)]
pub(crate) struct AdapterLink {
    pub status: &'static str,
    pub physical: Option<bool>,
    pub ips: Vec<Ipv4Addr>,
}
pub(crate) type AdapterLinks = std::collections::BTreeMap<String, AdapterLink>;

pub(crate) type AddressOrigins = std::collections::BTreeMap<(String, Ipv4Addr), &'static str>;

#[cfg(windows)]
pub(crate) async fn address_origins() -> Option<AddressOrigins> {
    let mut command = Command::new(crate::quick_tools::system::executable("netsh.exe").ok()?);
    command
        .args(["interface", "ipv4", "show", "ipaddresses", "level=verbose"])
        .creation_flags(0x0800_0000);
    Some(windows_address_origins(
        &read_output(command, "netsh.exe").await.ok()?,
    ))
}

#[cfg(any(windows, test))]
fn windows_address_origins(output: &str) -> AddressOrigins {
    let mut origins = AddressOrigins::new();
    let mut current = None;
    let mut interface = None;
    for line in output.lines().map(str::trim) {
        if let Some((key, value)) = line.split_once(':') {
            match key.trim() {
                "Interface Luid" | "Interface LUID" | "Schnittstellen-LUID" => {
                    interface = Some(value.trim())
                }
                "Address Type" | "Adresstyp" => {
                    let origin = match value.trim() {
                        "DHCP" | "Dhcp" => "DHCP",
                        "Manual" | "Manuell" => "Static",
                        _ => continue,
                    };
                    if let (Some(ip), Some(name)) = (current, interface) {
                        origins.insert((name.to_owned(), ip), origin);
                    }
                }
                _ => {}
            }
        } else if let Some(ip) = line
            .split_whitespace()
            .find_map(|word| word.parse::<Ipv4Addr>().ok())
        {
            current = Some(ip);
            interface = None;
        }
    }
    origins
}

#[cfg(target_os = "linux")]
pub(crate) async fn address_origins() -> Option<AddressOrigins> {
    let mut command = Command::new("ip");
    command
        .args(["-o", "-4", "address", "show"])
        .env("LC_ALL", "C");
    let output = read_output(command, "ip").await.ok()?;
    let mut origins = AddressOrigins::new();
    for line in output.lines() {
        let fields: Vec<_> = line.split_whitespace().collect();
        let [_, device, "inet", cidr, tail @ ..] = fields.as_slice() else {
            continue;
        };
        let Some((ip, _)) = parse_cidr(cidr) else {
            continue;
        };
        let Some(origin) = tail.windows(2).find_map(|pair| match pair {
            ["proto", "dhcp"] => Some("DHCP"),
            ["proto", "static"] => Some("Static"),
            _ => None,
        }) else {
            continue;
        };
        origins.insert((device.split('@').next()?.to_owned(), ip), origin);
    }
    // NetworkManager can identify the leased address even without a kernel address protocol.
    let mut nm = Command::new("nmcli");
    nm.args([
        "-t",
        "-e",
        "no",
        "-f",
        "GENERAL.DEVICE,DHCP4.OPTION",
        "device",
        "show",
    ])
    .env("LC_ALL", "C");
    if let Ok(output) = read_output(nm, "nmcli").await {
        let mut device = None;
        for line in output.lines() {
            if let Some(name) = line.strip_prefix("GENERAL.DEVICE:") {
                device = Some(name);
            } else if line.starts_with("DHCP4.OPTION")
                && let Some((_, value)) = line.split_once(':')
                && let Some(ip) = value
                    .trim()
                    .strip_prefix("ip_address = ")
                    .and_then(|ip| ip.parse().ok())
                && let Some(name) = device
            {
                origins.insert((name.to_owned(), ip), "DHCP");
            }
        }
    }
    Some(origins)
}

#[cfg(not(any(windows, target_os = "linux")))]
pub(crate) async fn address_origins() -> Option<AddressOrigins> {
    None
}

#[cfg(windows)]
pub(crate) async fn adapter_links() -> Result<AdapterLinks, String> {
    let adapters = tokio::task::spawn_blocking(crate::windows_network::adapters)
        .await
        .map_err(|e| e.to_string())?
        .map_err(|e| e.to_string())?;
    let mut links: AdapterLinks = adapters
        .into_iter()
        .filter(|a| a.if_type() != ipconfig::IfType::SoftwareLoopback)
        .map(|a| {
            (
                a.friendly_name().to_owned(),
                AdapterLink {
                    status: if a.oper_status() == ipconfig::OperStatus::IfOperStatusUp {
                        "Link up"
                    } else {
                        "Link unavailable"
                    },
                    physical: None,
                    ips: a
                        .ip_addresses()
                        .iter()
                        .filter_map(|ip| match ip {
                            IpAddr::V4(ip) => Some(*ip),
                            _ => None,
                        })
                        .collect(),
                },
            )
        })
        .collect();
    // ipconfig lacks administrative and physical media state, and may omit disabled adapters.
    let path = crate::quick_tools::system::executable(r"WindowsPowerShell\v1.0\powershell.exe")
        .map_err(|e| e.to_string())?;
    let mut command = Command::new(path);
    command.creation_flags(0x0800_0000).args(["-NoProfile", "-NonInteractive", "-Command",
        r#"[Console]::OutputEncoding = [Text.UTF8Encoding]::new($false); Get-NetAdapter -ErrorAction Stop | ForEach-Object { "{0}`t{1}`t{2}`t{3}`t{4}`t{5}" -f $_.AdminStatus,$_.Status,$_.MediaConnectionState,$_.HardwareInterface,$_.InterfaceType,$_.Name }"#]);
    if let Ok(output) = read_output(command, "Get-NetAdapter").await {
        for line in output.lines() {
            let fields: Vec<_> = line.splitn(6, '\t').collect();
            let [admin, status, media, hardware, kind, name] = fields.as_slice() else {
                continue;
            };
            let link = links.entry((*name).to_owned()).or_default();
            link.physical = match *hardware {
                "True" => Some(true),
                "False" => Some(false),
                _ => None,
            };
            link.status = match (*admin, *status, *media, *hardware, *kind) {
                ("Down", ..) | (_, "Disabled", ..) => "Disabled",
                (_, "Up", ..) => "Link up",
                (_, _, "Disconnected", "True", "6") => "Cable disconnected",
                (_, _, "Disconnected", ..) => "Disconnected",
                _ => "Link unavailable",
            };
        }
    }
    Ok(links)
}

#[cfg(target_os = "linux")]
pub(crate) async fn adapter_links() -> Result<AdapterLinks, String> {
    let mut command = Command::new("ip");
    command.args(["-o", "link", "show"]).env("LC_ALL", "C");
    let output = read_output(command, "ip")
        .await
        .map_err(|e| e.to_string())?;
    let mut links = AdapterLinks::new();
    for line in output.lines() {
        let (_, rest) = line.split_once(": ").ok_or("Invalid ip link output")?;
        let (name, rest) = rest.split_once(": <").ok_or("Invalid ip link flags")?;
        let (flags, details) = rest.split_once('>').ok_or("Invalid ip link flags")?;
        let has = |flag| flags.split(',').any(|f| f == flag);
        if has("LOOPBACK") {
            continue;
        }
        let name = name.split('@').next().unwrap_or(name);
        let sys = std::path::Path::new("/sys/class/net").join(name);
        let status = if !has("UP") {
            "Disabled"
        } else if has("LOWER_UP") {
            "Link up"
        } else if has("NO-CARRIER")
            && details.contains("link/ether ")
            && sys.join("device").exists()
            && !sys.join("wireless").exists()
            && !sys.join("phy80211").exists()
        {
            "Cable disconnected"
        } else {
            "Link unavailable"
        };
        links.insert(
            name.into(),
            AdapterLink {
                status,
                physical: if sys.join("device").exists() {
                    Some(true)
                } else {
                    sys.canonicalize()
                        .ok()
                        .and_then(|p| p.starts_with("/sys/devices/virtual/net").then_some(false))
                },
                ips: Vec::new(),
            },
        );
    }
    let mut command = Command::new("ip");
    command
        .args(["-o", "-4", "address", "show"])
        .env("LC_ALL", "C");
    for interface in parse_linux(
        &read_output(command, "ip")
            .await
            .map_err(|e| e.to_string())?,
    )
    .map_err(|e| e.to_string())?
    {
        if let Some(link) = links.get_mut(&interface.name) {
            link.ips.push(interface.ip);
        }
    }
    Ok(links)
}

#[cfg(not(any(windows, target_os = "linux")))]
pub(crate) async fn adapter_links() -> Result<AdapterLinks, String> {
    Err(Error::Unsupported.to_string())
}
#[cfg(any(target_os = "linux", test))]
fn parse_linux_route(output: &str) -> Option<RouteDetails> {
    let fields: Vec<_> = output.split_ascii_whitespace().collect();
    let after = |key| {
        fields
            .iter()
            .position(|field| *field == key)
            .map(|index| &fields[index + 1..])
    };
    let source = after("src")?.first()?.parse().ok()?;
    let interface = Some(after("dev")?.first()?.to_string());
    let gateway = match after("via") {
        Some(["inet" | "inet6", address, ..]) | Some([address, ..]) => Some(address.parse().ok()?),
        Some([]) => return None,
        None => None,
    };
    Some(RouteDetails {
        interface,
        source,
        gateway,
    })
}

#[cfg(not(any(windows, target_os = "linux")))]
pub(crate) async fn route_details(_target: IpAddr) -> Result<RouteDetails, Error> {
    Err(Error::Unsupported)
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

impl Interface {
    pub(crate) fn is_neighbor(&self, target: Ipv4Addr) -> bool {
        let mask = u32::MAX
            .checked_shl(32 - u32::from(self.prefix))
            .unwrap_or(0);
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
pub(crate) async fn list() -> Result<Vec<Interface>, Error> {
    let mut command = Command::new("ip");
    command
        .args(["-o", "-4", "address", "show", "up"])
        .env("LC_ALL", "C");
    parse_linux(&read_output(command, "ip").await?)
}

#[cfg(not(any(windows, target_os = "linux")))]
pub(crate) async fn list() -> Result<Vec<Interface>, Error> {
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
    #[cfg(windows)]
    gateway: Option<Ipv4Addr>,
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
            #[cfg(windows)]
            gateway: gateway.first().and_then(|gateway| gateway.parse().ok()),
            metric,
        });
    }
    Err(ERROR)
}

#[cfg(any(windows, test))]
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
    fn windows_address_origin_belongs_to_the_specific_interface_and_address() {
        let origins = windows_address_origins(
            "Adresse 10.0.0.2 Parameter\nSchnittstellen-LUID : Ethernet\nAdresstyp : DHCP\nAddress 10.0.0.3 Parameters\nInterface Luid : Ethernet\nAddress Type : Manual\nAddress 10.0.0.4 Parameters\nInterface Luid : Ethernet\nAddress Type : Other",
        );
        assert_eq!(origins.len(), 2);
        assert_eq!(origins[&("Ethernet".into(), [10, 0, 0, 2].into())], "DHCP");
        assert_eq!(
            origins[&("Ethernet".into(), [10, 0, 0, 3].into())],
            "Static"
        );
    }

    #[test]
    fn reads_the_most_specific_ipv6_route_on_the_selected_interface() {
        let output = "Aktive Routen:\n If Metrik Netzwerkziel Gateway\n\
            8 5 ::/0 fe80::1\n\
            13 20 ::/0 fe80::2\n\
            13 25 2001:db8:1::2/128\n Auf Verbindung\n\
            ============\n13 1 ::/0 fe80::3";
        assert_eq!(
            best_ipv6_route(output, "2001:db8:1::2".parse().unwrap(), Some(13)),
            Some((13, None))
        );
        assert_eq!(
            best_ipv6_route(output, "2001:db8:2::2".parse().unwrap(), Some(13)),
            Some((13, Some("fe80::2".parse().unwrap())))
        );
    }

    #[test]
    fn reads_linux_route_source_device_and_next_hop() {
        let direct = parse_linux_route("192.0.2.2 dev eth0 src 192.0.2.1 uid 1000").unwrap();
        assert_eq!(direct.interface.as_deref(), Some("eth0"));
        assert_eq!(direct.source, "192.0.2.1".parse::<IpAddr>().unwrap());
        assert_eq!(direct.gateway, None);
        let routed =
            parse_linux_route("2001:db8:2::2 via fe80::1 dev eth1 src 2001:db8::2 metric 100")
                .unwrap();
        assert_eq!(routed.interface.as_deref(), Some("eth1"));
        assert_eq!(routed.gateway, Some("fe80::1".parse().unwrap()));
    }

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
