//! Avast command construction and exit-code interpretation.

use std::path::{Path, PathBuf};

use tokio::process::Command;

use super::classify::{Capture, diagnostic};
use crate::mailbox_scanner::core::{detection, scanner};

pub(super) fn executable() -> PathBuf {
    super::program_files()
        .join("AVAST Software")
        .join("Avast")
        .join("ashCmd.exe")
}

pub(super) fn command(
    executable: &Path,
    path: &Path,
    settings: &scanner::avast::Settings,
) -> Command {
    let mut command = Command::new(executable);
    command
        .arg(path)
        .args(["/_", "/a", "/p=4", "/s"])
        .arg(format!("/e={}", settings.heuristics))
        .arg(if settings.archives { "/t=A" } else { "/t=N" });
    if settings.entire_files {
        command.arg("/c");
    }
    command
}

pub(super) fn report(capture: &Capture, result: &mut detection::Report) {
    if !capture.termination_requested {
        if capture.code == Some(1) {
            result.record(detection::Evidence {
                backend: scanner::Backend::Avast,
                threat: "Avast detected a threat".into(),
            });
        } else if capture.code != Some(0) {
            result.warn(detection::Issue::Scanner(format!(
                "Avast did not complete successfully (exit {:?})",
                capture.code
            )));
        }
    }
    if !capture.stderr.is_empty() {
        result.warn(detection::Issue::Scanner(diagnostic(&capture.stderr)));
    }
}
