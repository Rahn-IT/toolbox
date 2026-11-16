//! Microsoft Defender command construction, discovery, and result interpretation.

use std::path::{Path, PathBuf};

use tokio::process::Command;

use super::classify::{Capture, decode, valid_prefix};
use crate::mailbox_scanner::core::{detection, scanner};

pub(super) fn command(executable: &Path, path: &Path) -> Command {
    let mut command = Command::new(executable);
    command
        .args(["-Scan", "-ScanType", "3", "-File"])
        .arg(path)
        .arg("-DisableRemediation");
    command
}
pub(super) fn executable() -> PathBuf {
    let base = std::env::var_os("ProgramData")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(r"C:\ProgramData"))
        .join("Microsoft")
        .join("Windows Defender")
        .join("Platform");
    let mut candidates = Vec::new();
    if let Ok(entries) = std::fs::read_dir(base) {
        for entry in entries.flatten() {
            let path = entry.path().join("MpCmdRun.exe");
            if !path.is_file() {
                continue;
            }
            let name = entry.file_name();
            if let Some(version) = name.to_str().and_then(version) {
                candidates.push((version, path));
            }
        }
    }
    candidates.sort_by(|left, right| left.0.cmp(&right.0));
    candidates.pop().map(|(_, path)| path).unwrap_or_else(|| {
        super::program_files()
            .join("Windows Defender")
            .join("MpCmdRun.exe")
    })
}

pub(super) fn version(name: &str) -> Option<Vec<u32>> {
    name.split(['.', '-'])
        .map(str::parse)
        .collect::<Result<Vec<_>, _>>()
        .ok()
}

pub(super) fn report(path: &Path, capture: &Capture, result: &mut detection::Report) {
    let stdout = match decode(&capture.stdout) {
        Ok(text) => text,
        Err(()) => {
            result.warn(detection::Issue::Scanner(
                "Unsupported Defender output encoding; scan result could not be established".into(),
            ));
            // Preserve complete positive lines preceding a damaged/truncated tail.
            // A decode problem always leaves coverage incomplete, never a clean result.
            valid_prefix(&capture.stdout)
        }
    };
    let stderr = match decode(&capture.stderr) {
        Ok(text) => text,
        Err(()) => {
            result.warn(detection::Issue::Scanner(
                "Unsupported Defender diagnostic encoding".into(),
            ));
            String::new()
        }
    };
    let path = path.to_string_lossy();
    let prefix = format!("Scanning {path} found ");
    let mut summaries = Vec::new();
    let mut in_threat_list = false;
    let mut threats = Vec::new();
    let mut finished = false;
    let mut errors = !stderr.trim().is_empty();
    for raw in stdout.lines() {
        let line = raw.trim();
        if line == "Scan finished." {
            finished = true;
        }
        if let Some(summary) = line.strip_prefix(&prefix) {
            let count = if summary == "no threats." {
                Some(0)
            } else {
                summary
                    .strip_suffix(" threats.")
                    .or_else(|| summary.strip_suffix(" threat."))
                    .and_then(|count| count.parse::<u32>().ok())
            };
            if let Some(count) = count {
                summaries.push(count);
            }
        }
        if line == "LIST OF DETECTED THREATS"
            || line
                .strip_prefix('<')
                .and_then(|line| line.strip_suffix('>'))
                .is_some_and(|line| line.trim_matches('=').trim() == "LIST OF DETECTED THREATS")
        {
            in_threat_list = true;
        }
        if in_threat_list
            && let Some((field, value)) = line.split_once(':')
            && field.trim() == "Threat"
            && !value.trim().is_empty()
        {
            threats.push(value.trim().to_owned());
        }
        if line.starts_with("ERROR:") || line.starts_with("CmdTool: Failed") {
            errors = true;
        }
    }
    let positive = summaries.iter().any(|count| *count > 0) && !threats.is_empty();
    if positive {
        for threat in threats {
            result.record(detection::Evidence {
                backend: scanner::Backend::Defender,
                threat,
            });
        }
        if capture.code != Some(2)
            || errors
            || !finished
            || summaries.len() != 1
            || summaries[0] == 0
        {
            result.warn(detection::Issue::Scanner(
                "Defender reported a detection but scan completion or coverage is uncertain".into(),
            ));
        }
    } else if capture.code != Some(0)
        || !finished
        || errors
        || summaries != [0]
        || !threats.is_empty()
    {
        let excerpt = if stderr.trim().is_empty() {
            &stdout
        } else {
            &stderr
        };
        result.warn(detection::Issue::Scanner(format!(
            "Defender result is unrecognized or unsuccessful (exit {:?}): {}",
            capture.code,
            excerpt.chars().take(400).collect::<String>()
        )));
    }
}
