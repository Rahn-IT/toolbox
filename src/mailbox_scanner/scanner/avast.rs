//! Avast command construction and exit-code interpretation.

use std::path::{Path, PathBuf};

use tokio::process::Command;

use super::batch::{Record, Status};
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

/// `/p=4` stops after a detection even with `/d`; directory scans must continue.
/// Verified with Avast 26.8.11125.0, two MIME EICAR messages and unchanged originals.
pub(super) fn batch_command(
    executable: &Path,
    directory: &Path,
    settings: &scanner::avast::Settings,
) -> Command {
    let mut command = Command::new(executable);
    command
        .arg(directory)
        .args(["/_", "/a", "/d", "/s"])
        .arg(format!("/e={}", settings.heuristics))
        .arg(if settings.archives { "/t=A" } else { "/t=N" });
    if settings.entire_files {
        command.arg("/c");
    }
    command
}

/// Decode the captured Windows-1252 Avast console profile, without lossy paths.
pub(super) fn batch_record(bytes: &[u8]) -> Result<Option<Record>, String> {
    let line = console_text(bytes)?;
    let line = line.trim_end_matches(['\r', '\n']);
    if line.is_empty() || line.starts_with('#') {
        return Ok(None);
    }
    if line.chars().any(|ch| ch.is_control() && ch != '\t') {
        return Err("Avast record contains unsupported control characters".into());
    }
    let mut fields = line.splitn(3, '\t');
    let resource = fields.next().unwrap_or_default();
    let status = fields
        .next()
        .ok_or_else(|| "Avast record has no file status".to_string())?;
    let detail = fields.next();
    let (path, terminal) = match resource.split_once("|>") {
        Some((path, member)) if !member.is_empty() => (path, false),
        Some(_) => return Err("Avast archive resource has no member".into()),
        None => (resource, true),
    };
    if path.is_empty() || status.is_empty() || status.trim() != status {
        return Err("Avast record has an empty file path or status".into());
    }
    let (status, detail) = match (status, detail) {
        ("OK", None) => (Status::Clean, String::new()),
        ("ERR", Some(detail)) if !detail.is_empty() => (Status::Error, detail.to_owned()),
        ("ERR" | "OK" | "SKIPPED" | "ERROR" | "WARNING", _) => {
            return Err("Avast record has an unsupported or malformed status".into());
        }
        (threat, None) => (Status::Detected, threat.to_owned()),
        _ => return Err("Avast record has unexpected status fields".into()),
    };
    Ok(Some(Record {
        path: path.to_owned(),
        status,
        detail,
        terminal,
    }))
}

fn console_text(bytes: &[u8]) -> Result<String, String> {
    let mut text = String::with_capacity(bytes.len());
    for &byte in bytes {
        let ch = match byte {
            0x80 => '\u{20ac}',
            0x82 => '\u{201a}',
            0x83 => '\u{0192}',
            0x84 => '\u{201e}',
            0x85 => '\u{2026}',
            0x86 => '\u{2020}',
            0x87 => '\u{2021}',
            0x88 => '\u{02c6}',
            0x89 => '\u{2030}',
            0x8a => '\u{0160}',
            0x8b => '\u{2039}',
            0x8c => '\u{0152}',
            0x8e => '\u{017d}',
            0x91 => '\u{2018}',
            0x92 => '\u{2019}',
            0x93 => '\u{201c}',
            0x94 => '\u{201d}',
            0x95 => '\u{2022}',
            0x96 => '\u{2013}',
            0x97 => '\u{2014}',
            0x98 => '\u{02dc}',
            0x99 => '\u{2122}',
            0x9a => '\u{0161}',
            0x9b => '\u{203a}',
            0x9c => '\u{0153}',
            0x9e => '\u{017e}',
            0x9f => '\u{0178}',
            0x81 | 0x8d | 0x8f | 0x90 | 0x9d => {
                return Err("Avast output is not supported Windows-1252 text".into());
            }
            byte => char::from(byte),
        };
        text.push(ch);
    }
    Ok(text)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn captured_clean_and_empty_file_records_are_terminal() {
        for name in ["000-clean.eml", "999-empty.eml"] {
            let record = batch_record(format!("D:\\probe\\{name}\tOK").as_bytes())
                .unwrap()
                .unwrap();
            assert_eq!(record.status, Status::Clean);
            assert!(record.terminal);
            assert_eq!(record.path, format!("D:\\probe\\{name}"));
        }
    }

    #[test]
    fn captured_archive_detection_and_outer_completion_are_separate() {
        // Captured Avast 26.8.11125.0 /d output; only the probe directory is shortened.
        let nested = batch_record(
            b"D:\\probe\\100-test.eml|>standard-test.txt#943030176\tEICAR Test-NOT virus!!!",
        )
        .unwrap()
        .unwrap();
        assert_eq!(nested.path, "D:\\probe\\100-test.eml");
        assert_eq!(nested.status, Status::Detected);
        assert_eq!(nested.detail, "EICAR Test-NOT virus!!!");
        assert!(!nested.terminal);
        let outer = batch_record(b"D:\\probe\\100-test.eml\tOK")
            .unwrap()
            .unwrap();
        assert_eq!(outer.status, Status::Clean);
        assert!(outer.terminal);
    }

    #[test]
    fn captured_outer_error_is_incomplete_not_a_threat() {
        let record = batch_record(b"D:\\probe\\100-test.eml\tERR\tError 0x0000A41B")
            .unwrap()
            .unwrap();
        assert_eq!(record.status, Status::Error);
        assert_eq!(record.detail, "Error 0x0000A41B");
        assert!(record.terminal);
    }

    #[test]
    fn captured_windows_1252_paths_are_not_lossily_decoded() {
        let record = batch_record(b"D:\\scan Gr\xfc\xdfe\\000-clean.eml\tOK")
            .unwrap()
            .unwrap();
        assert_eq!(record.path, "D:\\scan Grüße\\000-clean.eml");
        assert!(batch_record(b"D:\\invalid\x81.eml\tOK").is_err());
    }

    #[test]
    fn aggregate_summaries_and_nested_clean_results_are_not_outer_completion() {
        assert!(
            batch_record(b"# Anzahl infizierter Dateien: 2")
                .unwrap()
                .is_none()
        );
        let record = batch_record(b"D:\\probe\\100-test.eml|>PartNo_0#925606545\tOK")
            .unwrap()
            .unwrap();
        assert_eq!(record.status, Status::Clean);
        assert!(!record.terminal);
    }

    #[test]
    fn malformed_or_reserved_statuses_are_not_positive_evidence() {
        for record in [
            "no tab",
            "\tOK",
            "file\t",
            "file\t ",
            "file\tOK ",
            "file\tERR",
            "file\tOK\textra",
            "file\tSKIPPED",
            "file|>\tOK",
            "file\tname\textra",
            "file\0\tOK",
        ] {
            assert!(batch_record(record.as_bytes()).is_err(), "{record:?}");
        }
    }

    #[test]
    fn directory_command_continues_without_remediation_flags() {
        let command = batch_command(
            Path::new("ashCmd.exe"),
            Path::new("batch"),
            &scanner::avast::Settings::default(),
        );
        let args: Vec<_> = command.as_std().get_args().collect();
        assert!(args.contains(&std::ffi::OsStr::new("/d")));
        assert!(
            !args
                .iter()
                .any(|arg| arg.to_string_lossy().starts_with("/p"))
        );
        assert_eq!(args[0], "batch");
    }
}
