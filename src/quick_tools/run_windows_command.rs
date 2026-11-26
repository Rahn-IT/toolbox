//! Run built-in Windows commands through the shared quick-tool interface.

use std::{
    os::windows::process::CommandExt,
    process::{Command, Stdio},
};

pub fn new(
    title: &'static str,
    executable: &'static str,
    args: &'static [&'static str],
    success: &'static str,
) -> crate::OpenedModule {
    super::start(title, move || {
        run(executable, args)?;
        Ok(success.into())
    })
}

pub(super) fn run(executable: &str, args: &[&str]) -> Result<(), String> {
    let command = format!("{executable} {}", args.join(" "));
    let output = Command::new(super::system::executable(executable)?)
        .args(args)
        // Do not leave invisible commands waiting for interactive confirmation.
        .stdin(Stdio::null())
        .creation_flags(0x08000000) // CREATE_NO_WINDOW
        .output()
        .map_err(|error| format!("Could not run {command}: {error}"))?;

    if output.status.success() {
        return Ok(());
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    Err(format!(
        "{command} exited with {}.\n{}\n{}\nIf Windows requires elevation, run Toolbox as administrator.",
        output.status,
        stdout.trim(),
        stderr.trim(),
    ))
}
