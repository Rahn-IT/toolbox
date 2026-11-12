//! Apply the requested display and sleep timeouts to the active Windows power plan.

use std::{os::windows::process::CommandExt, process::Command};

const SETTINGS: &[(&str, &str)] = &[
    ("-monitor-timeout-dc", "5"),
    ("-standby-timeout-dc", "15"),
    ("-monitor-timeout-ac", "15"),
    ("-standby-timeout-ac", "0"),
];

pub(super) fn run() -> Result<String, String> {
    apply_with(|setting, minutes| {
        let output = Command::new(super::system::executable("powercfg.exe")?)
            .args(["-Change", setting, minutes])
            .creation_flags(0x08000000) // CREATE_NO_WINDOW
            .output()
            .map_err(|error| format!("Could not start powercfg.exe: {error}"))?;
        if output.status.success() {
            return Ok(());
        }
        let stderr = String::from_utf8_lossy(&output.stderr);
        let stdout = String::from_utf8_lossy(&output.stdout);
        let details = if stderr.trim().is_empty() {
            stdout.trim()
        } else {
            stderr.trim()
        };
        Err(format!(
            "powercfg.exe exited with {}: {details}",
            output.status
        ))
    })
}

fn apply_with(mut apply: impl FnMut(&str, &str) -> Result<(), String>) -> Result<String, String> {
    let mut failed = false;
    let mut lines = Vec::new();
    for &(setting, minutes) in SETTINGS {
        match apply(setting, minutes) {
            Ok(()) => lines.push(format!("{setting} {minutes}: applied.")),
            Err(error) => {
                failed = true;
                lines.push(format!("{setting} {minutes}: failed: {error}"));
            }
        }
    }
    let report = lines.join("\n");
    if failed { Err(report) } else { Ok(report) }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn applies_all_requested_settings_even_after_an_error() {
        let mut attempted = Vec::new();
        let report = apply_with(|setting, minutes| {
            attempted.push((setting.to_string(), minutes.to_string()));
            if setting == "-monitor-timeout-dc" {
                Err("access denied".into())
            } else {
                Ok(())
            }
        })
        .unwrap_err();
        assert_eq!(
            attempted,
            SETTINGS
                .iter()
                .map(|&(setting, minutes)| (setting.to_string(), minutes.to_string()))
                .collect::<Vec<_>>()
        );
        assert!(report.contains("-monitor-timeout-dc 5: failed: access denied"));
        assert!(report.contains("-standby-timeout-ac 0: applied."));
    }

    #[test]
    fn reports_success_when_all_settings_apply() {
        assert!(apply_with(|_, _| Ok(())).is_ok());
    }
}
