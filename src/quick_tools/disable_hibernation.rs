//! Disable Windows hibernation using the built-in powercfg command.

use std::{os::windows::process::CommandExt, process::Command};

pub(super) fn run() -> Result<String, String> {
    let output = Command::new(super::system::executable("powercfg.exe")?)
        .args(["-h", "off"])
        .creation_flags(0x08000000) // CREATE_NO_WINDOW
        .output()
        .map_err(|error| format!("Could not start powercfg.exe: {error}"))?;

    if output.status.success() {
        return Ok("Hibernation disabled (powercfg -h off).".into());
    }

    let stderr = String::from_utf8_lossy(&output.stderr);
    let stdout = String::from_utf8_lossy(&output.stdout);
    let details = if stderr.trim().is_empty() {
        stdout.trim()
    } else {
        stderr.trim()
    };
    Err(format!(
        "powercfg.exe exited with {}. Run Toolbox as administrator. {details}",
        output.status
    ))
}
