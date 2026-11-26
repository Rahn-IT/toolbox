use std::net::Ipv4Addr;

#[cfg(any(windows, target_os = "linux"))]
use std::{path::PathBuf, time::Duration};

pub(super) struct Resolver {
    #[cfg(any(windows, target_os = "linux"))]
    program: PathBuf,
}

#[cfg(windows)]
pub(super) fn prepare() -> Result<Resolver, String> {
    let program = crate::quick_tools::system::executable("nslookup.exe")?;
    if !program.try_exists().map_err(|error| error.to_string())? {
        return Err("nslookup.exe is unavailable.".into());
    }
    Ok(Resolver { program })
}

#[cfg(target_os = "linux")]
pub(super) fn prepare() -> Result<Resolver, String> {
    super::ping::find_program("getent")
        .map(|program| Resolver { program })
        .ok_or_else(|| "getent is unavailable.".into())
}

#[cfg(not(any(windows, target_os = "linux")))]
pub(super) fn prepare() -> Result<Resolver, String> {
    Err("Reverse lookup is supported on Windows and Linux.".into())
}

impl Resolver {
    #[cfg(any(windows, target_os = "linux"))]
    pub(super) async fn lookup(&self, ip: Ipv4Addr) -> Result<Option<String>, String> {
        let mut command = tokio::process::Command::new(&self.program);
        command.kill_on_drop(true);
        #[cfg(windows)]
        let target = reverse_name(ip);
        #[cfg(windows)]
        command
            .arg("-type=PTR")
            .arg(&target)
            .creation_flags(0x0800_0000);
        #[cfg(target_os = "linux")]
        command.args(["hosts", &ip.to_string()]);

        let Ok(output) = tokio::time::timeout(Duration::from_secs(2), command.output()).await
        else {
            return Ok(None);
        };
        let output = output.map_err(|error| error.to_string())?;
        let text = String::from_utf8_lossy(&output.stdout);
        #[cfg(windows)]
        let hostname = parse_ptr(&text, &target);
        #[cfg(target_os = "linux")]
        let hostname = parse_hosts(&text, ip);
        Ok(hostname.map(str::to_owned))
    }

    #[cfg(not(any(windows, target_os = "linux")))]
    pub(super) async fn lookup(&self, _ip: Ipv4Addr) -> Result<Option<String>, String> {
        Ok(None)
    }
}

#[cfg(any(windows, test))]
fn reverse_name(ip: Ipv4Addr) -> String {
    let [a, b, c, d] = ip.octets();
    format!("{d}.{c}.{b}.{a}.in-addr.arpa.")
}

#[cfg(any(windows, test))]
fn parse_ptr<'a>(output: &'a str, target: &str) -> Option<&'a str> {
    output.lines().find_map(|line| {
        let (record, value) = line.split_once('=')?;
        let owner = record.split_ascii_whitespace().next()?;
        if !owner
            .trim_end_matches('.')
            .eq_ignore_ascii_case(target.trim_end_matches('.'))
        {
            return None;
        }
        hostname(value.trim())
    })
}

#[cfg(any(target_os = "linux", test))]
fn parse_hosts(output: &str, ip: Ipv4Addr) -> Option<&str> {
    output.lines().find_map(|line| {
        let mut fields = line.split_ascii_whitespace();
        let address: Ipv4Addr = fields.next()?.parse().ok()?;
        if address != ip {
            return None;
        }
        hostname(fields.next()?)
    })
}

#[cfg(any(windows, target_os = "linux", test))]
fn hostname(value: &str) -> Option<&str> {
    let name = value.trim_end_matches('.');
    (!name.is_empty()
        && name.parse::<Ipv4Addr>().is_err()
        && name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.')))
    .then_some(name)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn windows_uses_the_ptr_owner_and_ignores_the_dns_server_name() {
        let target = reverse_name(Ipv4Addr::new(192, 0, 2, 7));
        assert_eq!(target, "7.2.0.192.in-addr.arpa.");
        let output = "Server: dns.example\nAddress: 192.0.2.1\n7.2.0.192.in-addr.arpa name = printer.example.\n";
        assert_eq!(parse_ptr(output, &target), Some("printer.example"));
        assert_eq!(
            parse_ptr("Server: dns.example\nAddress: 192.0.2.1", &target),
            None
        );
    }

    #[test]
    fn linux_uses_the_primary_name_for_the_requested_address() {
        let ip = Ipv4Addr::new(192, 0, 2, 7);
        assert_eq!(
            parse_hosts(
                "192.0.2.8 other.example\n192.0.2.7 printer.example printer",
                ip
            ),
            Some("printer.example")
        );
        assert_eq!(parse_hosts("192.0.2.7 192.0.2.7", ip), None);
    }
}
