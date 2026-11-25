use std::net::Ipv4Addr;

#[cfg(any(windows, target_os = "linux"))]
use std::{path::PathBuf, time::Duration};
#[cfg(any(windows, target_os = "linux"))]
use tokio::process::Command;

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) enum Outcome {
    Reply,
    NoReply,
    TimedOut,
    Failed(String),
}

pub(super) struct Runner {
    #[cfg(any(windows, target_os = "linux"))]
    program: PathBuf,
}

#[cfg(windows)]
pub(super) async fn prepare() -> Result<Runner, String> {
    let program = crate::quick_tools::system::executable("ping.exe")?;
    tokio::fs::metadata(&program)
        .await
        .map_err(|error| format!("ping.exe is unavailable: {error}"))?;
    Ok(Runner { program })
}

#[cfg(target_os = "linux")]
pub(super) async fn prepare() -> Result<Runner, String> {
    let program = find_program("ping").ok_or_else(|| "ping was not found on PATH.".to_owned())?;
    Ok(Runner { program })
}

#[cfg(not(any(windows, target_os = "linux")))]
pub(super) async fn prepare() -> Result<Runner, String> {
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
    pub(super) async fn echo(&self, device: &str, target: Ipv4Addr) -> Outcome {
        let mut command = Command::new(&self.program);
        command.kill_on_drop(true);
        #[cfg(windows)]
        command
            .args(["-4", "-n", "1", "-w", "1000"])
            .creation_flags(0x0800_0000);
        #[cfg(target_os = "linux")]
        command.args(["-4", "-n", "-c", "1", "-W", "1", "-I", device]);
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
    pub(super) async fn echo(&self, _device: &str, _target: Ipv4Addr) -> Outcome {
        Outcome::Failed("Echo requests are supported on Windows and Linux.".into())
    }
}

#[cfg(windows)]
fn classify(output: std::process::Output, target: Ipv4Addr) -> Outcome {
    let stdout = String::from_utf8_lossy(&output.stdout);
    if confirms_echo(&stdout, target) {
        Outcome::Reply
    } else if output.status.success() || output.status.code() == Some(1) {
        Outcome::NoReply
    } else {
        Outcome::Failed(command_error(&output))
    }
}

#[cfg(target_os = "linux")]
fn classify(output: std::process::Output, _target: Ipv4Addr) -> Outcome {
    match output.status.code() {
        Some(0) => Outcome::Reply,
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
fn confirms_echo(output: &str, target: Ipv4Addr) -> bool {
    let address = format!("{target}:");
    output.lines().any(|line| {
        let mut fields = line.split_ascii_whitespace();
        fields.any(|field| field == address)
            && fields.any(|field| {
                field
                    .strip_prefix("TTL=")
                    .is_some_and(|ttl| ttl.parse::<u8>().is_ok())
            })
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn windows_echo_matches_a_numeric_reply_to_the_requested_address() {
        let target = Ipv4Addr::new(192, 168, 1, 2);
        assert!(confirms_echo(
            "Antwort von 192.168.1.2: Bytes=32 Zeit<1ms TTL=64",
            target,
        ));
        assert!(!confirms_echo(
            "Reply from 192.168.1.2: Destination host unreachable.",
            target,
        ));
        assert!(!confirms_echo(
            "Reply from 192.168.1.3: bytes=32 time<1ms TTL=64",
            target,
        ));
    }
}
