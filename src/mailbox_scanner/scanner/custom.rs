//! Literal arguments and user-defined normal-exit codes for native scanners.

use std::path::{Path, PathBuf};

use tokio::process::Command;

use super::{
    Error,
    classify::{Capture, diagnostic},
};
use crate::mailbox_scanner::core::{detection, scanner};

pub(super) fn executable(settings: &scanner::custom::Settings) -> Result<PathBuf, Error> {
    settings.validate()?;
    if !settings.executable.is_file() {
        return Err(Error::Executable(settings.executable.clone()));
    }
    let path = settings.executable.canonicalize()?;
    if !scanner::custom::native_executable(&path) {
        return Err(Error::Settings(scanner::Error::Executable));
    }
    Ok(path)
}

pub(super) fn command(
    executable: &Path,
    path: &Path,
    settings: &scanner::custom::Settings,
) -> Command {
    let mut command = Command::new(executable);
    for argument in &settings.arguments {
        if argument == "{file}" {
            command.arg(path);
        } else {
            command.arg(argument);
        }
    }
    command
}

pub(super) fn report(
    settings: &scanner::custom::Settings,
    capture: &Capture,
    result: &mut detection::Report,
) {
    if !capture.termination_requested {
        if capture.code == Some(settings.detected_code) {
            result.record(detection::Evidence {
                backend: scanner::Backend::Custom,
                threat: "Custom scanner detected a threat".into(),
            });
        } else if capture.code != Some(settings.clean_code) {
            result.warn(detection::Issue::Scanner(format!(
                "Custom scanner returned an unexpected exit code {:?}",
                capture.code
            )));
        }
    }
    if !capture.stderr.is_empty() {
        result.warn(detection::Issue::Scanner(diagnostic(&capture.stderr)));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolution_rejects_script_and_missing_executable_paths() {
        let mut settings = scanner::custom::Settings {
            executable: std::env::current_exe().unwrap().with_extension("cmd"),
            arguments: vec!["{file}".into()],
            clean_code: 0,
            detected_code: 1,
        };
        assert!(matches!(
            executable(&settings),
            Err(Error::Settings(scanner::Error::Executable))
        ));
        settings.executable = std::env::current_exe().unwrap().join("missing.exe");
        assert!(matches!(executable(&settings), Err(Error::Executable(_))));
    }
}
