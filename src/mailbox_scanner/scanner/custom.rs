//! Literal arguments and user-defined normal-exit codes for native scanners.

use std::path::{Path, PathBuf};

use tokio::process::Command;

use super::{
    Error,
    classify::{Capture, diagnostic},
};
use crate::mailbox_scanner::core::{detection, scanner};

/// A file's terminal status in the Custom directory protocol.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Status {
    Clean,
    Detected,
    Error,
}

/// A syntactically valid record; manifest membership is checked by the caller.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Record<'a> {
    path: &'a str,
    status: Status,
    detail: &'a str,
}

/// A directory result line that cannot be safely attributed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub(super) enum Invalid {
    #[error("Custom result must contain a path and status separated by a tab")]
    Fields,
    #[error("Custom result contains a control character")]
    Control,
    #[error("Custom result path must be a relative path without traversal")]
    Path,
    #[error("Custom result status must be CLEAN, DETECTED or ERROR")]
    Status,
}

impl<'a> Record<'a> {
    pub(super) fn path(&self) -> &'a str {
        self.path
    }

    pub(super) fn status(&self) -> Status {
        self.status
    }

    pub(super) fn detail(&self) -> &'a str {
        self.detail
    }
}

/// Parse one decoded record without its line terminator.
pub(super) fn parse_line(line: &str) -> Result<Record<'_>, Invalid> {
    if line
        .chars()
        .any(|character| character.is_control() && character != '\t')
    {
        return Err(Invalid::Control);
    }
    let mut fields = line.splitn(3, '\t');
    let path = fields.next().ok_or(Invalid::Fields)?;
    let status = fields.next().ok_or(Invalid::Fields)?;
    let detail = fields.next().unwrap_or_default();
    // Check both separators on every host; Windows drive/ADS syntax must never
    // become an apparently relative path when tests run on another platform.
    if path.is_empty()
        || path.contains(':')
        || path.split(['/', '\\']).any(|part| {
            part.is_empty() || part == "." || part == ".." || part.ends_with([' ', '.'])
        })
    {
        return Err(Invalid::Path);
    }
    let status = match status {
        "CLEAN" => Status::Clean,
        "DETECTED" => Status::Detected,
        "ERROR" => Status::Error,
        _ => return Err(Invalid::Status),
    };
    Ok(Record {
        path,
        status,
        detail,
    })
}

/// Construct a directory invocation without shell interpolation.
pub(super) fn directory_command(
    executable: &Path,
    directory: &Path,
    settings: &scanner::custom::Settings,
) -> Command {
    let mut command = Command::new(executable);
    for argument in &settings.arguments {
        if argument == "{directory}" {
            command.arg(directory);
        } else {
            command.arg(argument);
        }
    }
    command
}

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
    fn directory_records_preserve_details_and_optional_empty_values() {
        let clean = parse_line("m000001.eml\tCLEAN").unwrap();
        assert_eq!(clean.path(), "m000001.eml");
        assert_eq!(clean.status(), Status::Clean);
        assert_eq!(clean.detail(), "");
        let detected = parse_line("m000002-p0001.bin\tDETECTED\tExample:Threat\tmore").unwrap();
        assert_eq!(detected.status(), Status::Detected);
        assert_eq!(detected.detail(), "Example:Threat\tmore");
        assert_eq!(parse_line("mail.eml\tDETECTED\t").unwrap().detail(), "");
        assert_eq!(
            parse_line("mail.eml\tERROR\taccess denied")
                .unwrap()
                .status(),
            Status::Error
        );
        assert_eq!(
            parse_line("part/mail.eml\tCLEAN").unwrap().path(),
            "part/mail.eml"
        );
    }

    #[test]
    fn directory_records_reject_paths_that_could_alias_or_escape_inputs() {
        for path in [
            "",
            ".",
            "..",
            "../mail.eml",
            "part/../mail.eml",
            "part/./mail.eml",
            "/mail.eml",
            "\\mail.eml",
            "C:mail.eml",
            "C:\\mail.eml",
            "\\\\server\\mail.eml",
            "mail.eml:stream",
            "part//mail.eml",
            "mail.eml/",
            "part\\..\\mail.eml",
            "mail.eml.",
            "part /mail.eml",
        ] {
            assert_eq!(
                parse_line(&format!("{path}\tCLEAN")),
                Err(Invalid::Path),
                "{path}"
            );
        }
    }

    #[test]
    fn directory_records_reject_controls_and_unknown_statuses() {
        for line in [
            "mail.eml\tclean",
            "mail.eml\tOK",
            "mail.eml\t CLEAN",
            "mail.eml\t",
        ] {
            assert_eq!(parse_line(line), Err(Invalid::Status));
        }
        for line in [
            "mail\0.eml\tCLEAN",
            "mail.eml\tERROR\tbad\rline",
            "mail.eml\tCLEAN\n",
        ] {
            assert_eq!(parse_line(line), Err(Invalid::Control));
        }
        assert_eq!(parse_line("mail.eml CLEAN"), Err(Invalid::Fields));
    }

    #[test]
    fn directory_arguments_are_literal_and_preserve_the_native_path() {
        let settings = scanner::custom::Settings {
            executable: PathBuf::from("scanner.exe"),
            arguments: vec![
                "--literal=$value".into(),
                "{directory}".into(),
                String::new(),
            ],
            clean_code: 0,
            detected_code: 1,
        };
        let directory = Path::new("C:\\scan folder\\Grüße");
        let command = directory_command(&settings.executable, directory, &settings);
        let arguments: Vec<_> = command.as_std().get_args().collect();
        assert_eq!(
            arguments,
            [
                std::ffi::OsStr::new("--literal=$value"),
                directory.as_os_str(),
                std::ffi::OsStr::new("")
            ]
        );
    }

    #[test]
    fn resolution_rejects_script_and_missing_executable_paths() {
        let mut settings = scanner::custom::Settings {
            executable: std::env::current_exe().unwrap().with_extension("cmd"),
            arguments: vec!["{directory}".into()],
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
