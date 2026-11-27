use std::net::IpAddr;

#[cfg(any(windows, target_os = "linux"))]
use std::{path::PathBuf, time::Duration};
#[cfg(any(windows, target_os = "linux"))]
use tokio::process::Command;

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Outcome {
    Reply(Option<String>),
    NoReply,
    TimedOut,
    Failed(String),
}

pub(crate) struct Runner {
    #[cfg(any(windows, target_os = "linux"))]
    program: PathBuf,
}

#[cfg(windows)]
pub(crate) async fn prepare() -> Result<Runner, String> {
    let program = crate::quick_tools::system::executable("ping.exe")?;
    tokio::fs::metadata(&program)
        .await
        .map_err(|error| format!("ping.exe is unavailable: {error}"))?;
    Ok(Runner { program })
}

#[cfg(target_os = "linux")]
pub(crate) async fn prepare() -> Result<Runner, String> {
    let program = find_program("ping").ok_or_else(|| "ping was not found on PATH.".to_owned())?;
    Ok(Runner { program })
}

#[cfg(not(any(windows, target_os = "linux")))]
pub(crate) async fn prepare() -> Result<Runner, String> {
    Err("Echo requests are supported on Windows and Linux.".into())
}

#[cfg(target_os = "linux")]
pub(super) fn find_program(name: &str) -> Option<PathBuf> {
    use std::os::unix::fs::PermissionsExt;

    let path = std::env::var_os("PATH")?;
    std::env::split_paths(&path)
        .filter(|directory| directory.is_absolute())
        .map(|directory| directory.join(name))
        .find(|program| {
            program.metadata().is_ok_and(|metadata| {
                metadata.is_file() && metadata.permissions().mode() & 0o111 != 0
            })
        })
}

impl Runner {
    #[cfg(any(windows, target_os = "linux"))]
    pub(crate) async fn echo(&self, device: Option<&str>, target: IpAddr) -> Outcome {
        let mut command = Command::new(&self.program);
        let family = if target.is_ipv4() { "-4" } else { "-6" };
        command.kill_on_drop(true).arg(family);
        #[cfg(windows)]
        command
            .args(["-n", "1", "-w", "1000"])
            .creation_flags(0x0800_0000);
        #[cfg(target_os = "linux")]
        {
            command.args(["-n", "-c", "1", "-W", "1"]);
            if let Some(device) = device {
                command.args(["-I", device]);
            }
        }
        #[cfg(windows)]
        let _ = device;
        let result = tokio::time::timeout(
            Duration::from_secs(2),
            command.env("LC_ALL", "C").arg(target.to_string()).output(),
        )
        .await;
        match result {
            Err(_) => Outcome::TimedOut,
            Ok(Err(error)) => Outcome::Failed(error.to_string()),
            Ok(Ok(output)) => classify(output, target),
        }
    }

    #[cfg(not(any(windows, target_os = "linux")))]
    pub(crate) async fn echo(&self, _device: Option<&str>, _target: IpAddr) -> Outcome {
        Outcome::Failed("Echo requests are supported on Windows and Linux.".into())
    }
}

#[cfg(windows)]
fn classify(output: std::process::Output, target: IpAddr) -> Outcome {
    let stdout = String::from_utf8_lossy(&output.stdout);
    if let Some(reply) = windows_reply(&stdout, target) {
        reply
    } else if output.status.success() || output.status.code() == Some(1) {
        Outcome::NoReply
    } else {
        Outcome::Failed(command_error(&output))
    }
}

#[cfg(target_os = "linux")]
fn classify(output: std::process::Output, _target: IpAddr) -> Outcome {
    match output.status.code() {
        Some(0) => Outcome::Reply(
            String::from_utf8_lossy(&output.stdout)
                .lines()
                .find_map(round_trip),
        ),
        Some(1) => Outcome::NoReply,
        _ => Outcome::Failed(command_error(&output)),
    }
}

#[cfg(any(windows, target_os = "linux"))]
pub(super) fn command_error(output: &std::process::Output) -> String {
    let stderr = String::from_utf8_lossy(&output.stderr);
    let stdout = String::from_utf8_lossy(&output.stdout);
    [stderr.trim(), stdout.trim()]
        .into_iter()
        .find(|line| !line.is_empty())
        .map_or_else(|| output.status.to_string(), str::to_owned)
}

#[cfg(any(windows, test))]
fn windows_reply(output: &str, target: IpAddr) -> Option<Outcome> {
    output.lines().find_map(|line| {
        let mut fields = line.split_ascii_whitespace();
        if !fields.any(|field| {
            field.strip_suffix(':').is_some_and(|address| {
                let address = address
                    .split_once('%')
                    .map_or(address, |(address, _)| address);
                address.parse::<IpAddr>().ok() == Some(target)
            })
        }) {
            return None;
        }
        if target.is_ipv4() {
            let confirmed = fields.any(|field| {
                field
                    .strip_prefix("TTL=")
                    .is_some_and(|ttl| ttl.parse::<u8>().is_ok())
            });
            confirmed.then(|| Outcome::Reply(round_trip(line)))
        } else {
            // Windows omits TTL for IPv6 echoes, but includes the round-trip time.
            round_trip(line).map(|time| Outcome::Reply(Some(time)))
        }
    })
}

#[cfg(any(windows, target_os = "linux", test))]
fn round_trip(line: &str) -> Option<String> {
    line.match_indices(['=', '<'])
        .find_map(|(offset, separator)| {
            let (value, _) = line[offset + 1..].split_once("ms")?;
            let value = value.trim();
            let milliseconds: f64 = value.parse().ok()?;
            let qualifier = if separator == "<" { "<" } else { "" };
            (milliseconds.is_finite() && milliseconds >= 0.0)
                .then(|| format!("{qualifier}{value} ms"))
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn windows_echo_matches_a_numeric_reply_to_the_requested_address() {
        let target = IpAddr::from([192, 168, 1, 2]);
        assert_eq!(
            windows_reply("Antwort von 192.168.1.2: Bytes=32 Zeit<1ms TTL=64", target),
            Some(Outcome::Reply(Some("<1 ms".into()))),
        );
        assert!(
            windows_reply(
                "Reply from 192.168.1.2: Destination host unreachable.",
                target,
            )
            .is_none()
        );
        assert!(
            windows_reply("Reply from 192.168.1.3: bytes=32 time<1ms TTL=64", target,).is_none()
        );
    }

    #[test]
    fn windows_ipv6_echo_requires_a_reply_from_the_target_with_a_round_trip_time() {
        let target = "fe80::12".parse().unwrap();
        assert_eq!(
            windows_reply("Antwort von fe80::12%5: Zeit=2ms", target),
            Some(Outcome::Reply(Some("2 ms".into())))
        );
        assert!(
            windows_reply(
                "Reply from fe80::12%5: Destination host unreachable.",
                target
            )
            .is_none()
        );
    }

    #[test]
    fn linux_echo_preserves_fractional_round_trip_time() {
        assert_eq!(
            round_trip("64 bytes from ::1: icmp_seq=1 ttl=64 time=0.034 ms").as_deref(),
            Some("0.034 ms")
        );
        assert!(round_trip("rtt min/avg/max/mdev = 0.034/0.034/0.034/0.000 ms").is_none());
    }
}
