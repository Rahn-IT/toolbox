use std::net::Ipv4Addr;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Device {
    pub ip: Ipv4Addr,
    pub mac: [u8; 6],
}

impl Device {
    pub fn mac_address(&self) -> String {
        let [a, b, c, d, e, f] = self.mac;
        format!("{a:02X}:{b:02X}:{c:02X}:{d:02X}:{e:02X}:{f:02X}")
    }
}

#[cfg(windows)]
pub(super) async fn read() -> Result<Vec<Device>, String> {
    let executable = crate::quick_tools::system::executable("arp.exe")?;
    let output = tokio::process::Command::new(executable)
        .arg("-a")
        .creation_flags(0x0800_0000) // CREATE_NO_WINDOW
        .kill_on_drop(true)
        .output()
        .await
        .map_err(|error| error.to_string())?;
    if !output.status.success() {
        let error = String::from_utf8_lossy(&output.stderr);
        let details = error.trim();
        return Err(if details.is_empty() {
            format!("arp.exe exited with {}", output.status)
        } else {
            details.to_owned()
        });
    }
    Ok(parse_windows(&String::from_utf8_lossy(&output.stdout)))
}

#[cfg(target_os = "linux")]
pub(super) async fn read() -> Result<Vec<Device>, String> {
    let table = tokio::fs::read_to_string("/proc/net/arp")
        .await
        .map_err(|error| error.to_string())?;
    Ok(parse_linux(&table))
}

#[cfg(not(any(windows, target_os = "linux")))]
pub(super) async fn read() -> Result<Vec<Device>, String> {
    Err("Reading the ARP cache is supported on Windows and Linux.".into())
}

#[cfg(any(windows, test))]
fn parse_windows(table: &str) -> Vec<Device> {
    collect_devices(table.lines().filter_map(|line| {
        let mut fields = line.split_ascii_whitespace();
        device(fields.next()?, fields.next()?)
    }))
}

#[cfg(any(target_os = "linux", test))]
fn parse_linux(table: &str) -> Vec<Device> {
    const ATF_COM: u32 = 0x02;
    collect_devices(table.lines().skip(1).filter_map(|line| {
        let mut fields = line.split_ascii_whitespace();
        let ip = fields.next()?;
        let _hardware_type = fields.next()?;
        let flags = u32::from_str_radix(fields.next()?.strip_prefix("0x")?, 16).ok()?;
        if flags & ATF_COM == 0 {
            return None;
        }
        device(ip, fields.next()?)
    }))
}

#[cfg(any(windows, target_os = "linux", test))]
fn device(ip: &str, mac: &str) -> Option<Device> {
    let ip: Ipv4Addr = ip.parse().ok()?;
    let mac = super::parse_mac(mac)?;
    // Broadcast, multicast and incomplete mappings cannot identify a wake target.
    if ip.is_unspecified()
        || ip.is_multicast()
        || ip == Ipv4Addr::BROADCAST
        || mac == [0; 6]
        || mac[0] & 1 != 0
    {
        return None;
    }
    Some(Device { ip, mac })
}

#[cfg(any(windows, target_os = "linux", test))]
fn collect_devices(entries: impl Iterator<Item = Device>) -> Vec<Device> {
    let mut devices: Vec<_> = entries.collect();
    devices.sort_unstable();
    devices.dedup();
    devices
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn windows_rows_ignore_headers_and_group_addresses() {
        let table = "Schnittstelle: 192.168.1.10 --- 0xc\n\
            Internetadresse Physische Adresse Typ\n\
            192.168.1.2 02-aa-bb-cc-dd-ee dynamisch\n\
            192.168.1.2 02-aa-bb-cc-dd-ee dynamisch\n\
            192.168.1.255 ff-ff-ff-ff-ff-ff statisch\n\
            224.0.0.22 01-00-5e-00-00-16 statisch";
        let devices = parse_windows(table);
        assert_eq!(devices.len(), 1);
        assert_eq!(devices[0].ip, Ipv4Addr::new(192, 168, 1, 2));
        assert_eq!(devices[0].mac_address(), "02:AA:BB:CC:DD:EE");
    }

    #[test]
    fn linux_rows_require_completed_arp_mappings() {
        let table = "IP address HW type Flags HW address Mask Device\n\
            192.168.1.2 0x1 0x2 02:aa:bb:cc:dd:ee * eth0\n\
            192.168.1.3 0x1 0x0 00:00:00:00:00:00 * eth0\n\
            192.168.1.4 0x1 0x0 02:aa:bb:cc:dd:ff * eth0";
        let devices = parse_linux(table);
        assert_eq!(devices.len(), 1);
        assert_eq!(devices[0].ip, Ipv4Addr::new(192, 168, 1, 2));
        assert_eq!(devices[0].mac_address(), "02:AA:BB:CC:DD:EE");
    }
}
