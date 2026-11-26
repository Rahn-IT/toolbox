use std::net::Ipv4Addr;

#[cfg(any(windows, target_os = "linux"))]
use std::{path::PathBuf, time::Duration};
#[cfg(any(windows, target_os = "linux"))]
use tokio::process::Command;

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(super) struct Name {
    pub name: String,
    pub suffix: u8,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) enum Outcome {
    Found(Vec<Name>),
    NoReply,
    Failed(String),
}

pub(super) struct Runner {
    #[cfg(any(windows, target_os = "linux"))]
    program: PathBuf,
}

#[cfg(windows)]
pub(super) fn prepare() -> Result<Option<Runner>, String> {
    let program = crate::quick_tools::system::executable("nbtstat.exe")?;
    if !program.try_exists().map_err(|error| error.to_string())? {
        return Ok(None);
    }
    Ok(Some(Runner { program }))
}

#[cfg(target_os = "linux")]
pub(super) fn prepare() -> Result<Option<Runner>, String> {
    Ok(super::ping::find_program("nmblookup").map(|program| Runner { program }))
}

#[cfg(not(any(windows, target_os = "linux")))]
pub(super) fn prepare() -> Result<Option<Runner>, String> {
    Ok(None)
}

impl Runner {
    #[cfg(any(windows, target_os = "linux"))]
    pub(super) async fn lookup(&self, target: Ipv4Addr) -> Outcome {
        let mut command = Command::new(&self.program);
        command.kill_on_drop(true).env("LC_ALL", "C").arg("-A");
        #[cfg(windows)]
        command.creation_flags(0x0800_0000);
        let result = tokio::time::timeout(
            Duration::from_secs(3),
            command.arg(target.to_string()).output(),
        )
        .await;
        match result {
            Err(_) => Outcome::NoReply,
            Ok(Err(error)) => Outcome::Failed(error.to_string()),
            Ok(Ok(output)) => classify(output),
        }
    }

    #[cfg(not(any(windows, target_os = "linux")))]
    pub(super) async fn lookup(&self, _target: Ipv4Addr) -> Outcome {
        Outcome::Failed("NetBIOS lookups are supported on Windows and Linux.".into())
    }
}

#[cfg(any(windows, target_os = "linux"))]
fn classify(output: std::process::Output) -> Outcome {
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let names = parse_names(&stdout);
    if !names.is_empty() {
        return Outcome::Found(names);
    }

    if [&*stdout, &*stderr].iter().any(|text| {
        let text = text.to_ascii_lowercase();
        text.contains("no reply")
            || text.contains("host not found")
            || text.contains("keine antwort")
            || text.contains("host nicht gefunden")
    }) {
        Outcome::NoReply
    } else if output.status.success() {
        Outcome::Failed("NetBIOS output did not contain a recognizable name table.".into())
    } else {
        Outcome::Failed(super::ping::command_error(&output))
    }
}

#[cfg(any(windows, target_os = "linux", test))]
fn parse_names(output: &str) -> Vec<Name> {
    let mut names: Vec<_> = output
        .lines()
        .filter_map(|line| {
            let (name, suffix_and_flags) = line.split_once('<')?;
            let (suffix, _) = suffix_and_flags.split_once('>')?;
            let name = name.trim();
            if name.is_empty() || suffix.len() != 2 {
                return None;
            }
            Some(Name {
                name: name.to_owned(),
                suffix: u8::from_str_radix(suffix, 16).ok()?,
            })
        })
        .collect();
    names.sort_unstable();
    names.dedup();
    names
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_name_tables_from_both_tools() {
        let windows = "Host name table\n  WORKSTATION     <00>  UNIQUE  Registered\n  WORKSTATION     <20>  UNIQUE  Registered\n MAC Address = 12-34-56-78-90-AB";
        let samba = "Looking up status of 192.168.1.2\n  WORKSTATION <00> -         B <ACTIVE>\n  WORKSTATION <20> -         B <ACTIVE>\n MAC Address = 12-34-56-78-90-AB";
        let names = parse_names(windows);
        assert_eq!(names, parse_names(samba));
        assert_eq!(names.len(), 2);
        assert_eq!(names[0].name, "WORKSTATION");
        assert_eq!(names[1].suffix, 0x20);
    }
}
