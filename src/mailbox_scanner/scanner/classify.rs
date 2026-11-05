//! Conservative interpretation of the two scanner command-line interfaces.

use std::path::Path;

use crate::mailbox_scanner::core::{detection, scanner};

#[derive(Default)]
pub(super) struct Capture {
    pub code: Option<i32>,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
    pub truncated: bool,
    pub timed_out: bool,
    pub cancelled: bool,
    pub failure: Option<String>,
}

pub(super) fn report(
    backend: scanner::Backend,
    path: &Path,
    capture: Capture,
) -> detection::Report {
    let mut result = detection::Report::new();
    match backend {
        scanner::Backend::Avast => {
            if capture.code == Some(1) {
                result.record(detection::Evidence {
                    backend,
                    threat: "Avast detected a threat".into(),
                });
            } else if capture.code != Some(0) {
                result.warn(detection::Issue::Scanner(format!(
                    "Avast did not complete successfully (exit {:?})",
                    capture.code
                )));
            }
            if !capture.stderr.is_empty() {
                result.warn(detection::Issue::Scanner(diagnostic(&capture.stderr)));
            }
        }
        scanner::Backend::Defender => defender(path, &capture, &mut result),
    }
    if capture.truncated {
        result.warn(detection::Issue::Limit(
            "Scanner output exceeded its capture limit",
        ));
    }
    if capture.timed_out {
        result.warn(detection::Issue::Scanner("Scanner timed out".into()));
    }
    if capture.cancelled {
        result.warn(detection::Issue::Cancelled);
    }
    if let Some(failure) = capture.failure {
        result.warn(detection::Issue::Scanner(failure));
    }
    result
}

fn defender(path: &Path, capture: &Capture, result: &mut detection::Report) {
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

fn decode(bytes: &[u8]) -> Result<String, ()> {
    if let Some(bytes) = bytes.strip_prefix(&[0xff, 0xfe]) {
        if bytes.len() % 2 != 0 {
            return Err(());
        }
        let units = bytes
            .as_chunks::<2>()
            .0
            .iter()
            .map(|pair| u16::from_le_bytes([pair[0], pair[1]]));
        std::char::decode_utf16(units)
            .collect::<Result<String, _>>()
            .map_err(|_| ())
    } else {
        std::str::from_utf8(bytes.strip_prefix(&[0xef, 0xbb, 0xbf]).unwrap_or(bytes))
            .map(str::to_owned)
            .map_err(|_| ())
    }
}

fn valid_prefix(bytes: &[u8]) -> String {
    if let Some(bytes) = bytes.strip_prefix(&[0xff, 0xfe]) {
        let units = bytes
            .as_chunks::<2>()
            .0
            .iter()
            .map(|pair| u16::from_le_bytes([pair[0], pair[1]]));
        std::char::decode_utf16(units)
            .map_while(Result::ok)
            .collect()
    } else {
        let bytes = bytes.strip_prefix(&[0xef, 0xbb, 0xbf]).unwrap_or(bytes);
        let end = std::str::from_utf8(bytes)
            .err()
            .map_or(bytes.len(), |error| error.valid_up_to());
        std::str::from_utf8(&bytes[..end])
            .unwrap_or_default()
            .to_owned()
    }
}

fn diagnostic(bytes: &[u8]) -> String {
    match decode(bytes) {
        Ok(text) => text.chars().take(400).collect(),
        Err(()) => "Scanner wrote unsupported diagnostic output".into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // These fixtures exercise the parser grammar; they are not captured engine evidence.
    fn defender_capture(code: i32, text: &str) -> Capture {
        Capture {
            code: Some(code),
            stdout: text.as_bytes().into(),
            ..Capture::default()
        }
    }

    #[test]
    fn defender_exit_two_without_positive_evidence_is_incomplete() {
        let report = report(
            scanner::Backend::Defender,
            Path::new("test.eml"),
            defender_capture(2, "CmdTool: Failed with hr = 0x80070005"),
        );
        assert!(!report.detected());
        assert!(!report.complete());
    }

    #[test]
    fn matching_positive_survives_a_timeout() {
        let mut capture = defender_capture(
            2,
            "Scan finished.\nScanning test.eml found 1 threats.\nLIST OF DETECTED THREATS\nThreat : Test:Example\n",
        );
        capture.timed_out = true;
        let report = report(scanner::Backend::Defender, Path::new("test.eml"), capture);
        assert!(report.detected());
        assert!(!report.complete());
    }

    #[test]
    fn a_foreign_path_and_threat_words_are_not_evidence() {
        let capture = defender_capture(
            2,
            "Scanning another.eml found 1 threats.\nLIST OF DETECTED THREATS\nThreat : Test:Example\n",
        );
        let report = report(scanner::Backend::Defender, Path::new("test.eml"), capture);
        assert!(!report.detected());
        assert!(!report.complete());
    }

    #[test]
    fn success_requires_a_matching_zero_threat_summary() {
        let report = report(
            scanner::Backend::Defender,
            Path::new("test.eml"),
            defender_capture(0, "Scan finished.\nScanning test.eml found no threats.\n"),
        );
        assert!(!report.detected());
        assert!(report.complete());
    }

    #[test]
    fn captured_benign_defender_output_is_recognized() {
        // Captured from Defender 4.18.26100.4-0 with harmless plain-text mail.
        let path = Path::new(r"\\?\D:\mailbox-scanner\target\scanner-benign.eml");
        let capture = defender_capture(
            0,
            "Scan starting...\r\nScan finished.\r\nScanning \\\\?\\D:\\mailbox-scanner\\target\\scanner-benign.eml found no threats.\r\n",
        );
        let result = report(scanner::Backend::Defender, path, capture);
        assert!(!result.detected());
        assert!(result.complete());
    }

    #[test]
    fn captured_positive_defender_output_is_recognized() {
        // Captured with Defender 4.18.26100.4-0; payload was the harmless EICAR test.
        let path = Path::new(
            r"\\?\D:\mailbox-scanner\target\scanner-eicar-5968-1793884702066229900\positive.bin",
        );
        let output = concat!(
            "Scan starting...\r\nScan finished.\r\nScanning ",
            r"\\?\D:\mailbox-scanner\target\scanner-eicar-5968-1793884702066229900\positive.bin",
            " found 1 threats.\r\n\r\n",
            "<===========================LIST OF DETECTED THREATS==========================>\r\n",
            "----------------------------- Threat information ------------------------------\r\n",
            "Threat                  : Virus:DOS/EICAR_Test_File\r\n",
            "Resources               : 1 total\r\n    file                : ",
            r"D:\mailbox-scanner\target\scanner-eicar-5968-1793884702066229900\positive.bin",
            "\r\n-------------------------------------------------------------------------------\r\n",
        );
        let result = report(
            scanner::Backend::Defender,
            path,
            defender_capture(2, output),
        );
        assert!(result.detected());
        assert!(result.complete());
        assert_eq!(result.evidence()[0].threat, "Virus:DOS/EICAR_Test_File");
    }

    #[test]
    fn utf16le_is_strict_and_unknown_encodings_fail() {
        let mut bytes = vec![0xff, 0xfe];
        bytes.extend("Grüße".encode_utf16().flat_map(u16::to_le_bytes));
        assert_eq!(decode(&bytes).unwrap(), "Grüße");
        assert!(decode(&[0xff, 0xfe, 0]).is_err());
        assert!(decode(&[0xff]).is_err());
    }

    #[test]
    fn avast_errors_are_not_detections() {
        let report = report(
            scanner::Backend::Avast,
            Path::new("test.eml"),
            Capture {
                code: Some(5),
                ..Capture::default()
            },
        );
        assert!(!report.detected());
        assert!(!report.complete());
    }

    #[test]
    fn contradictory_zero_summary_does_not_hide_a_threat_field() {
        let report = report(
            scanner::Backend::Defender,
            Path::new("test.eml"),
            defender_capture(
                0,
                "Scan finished.\nScanning test.eml found no threats.\nLIST OF DETECTED THREATS\nThreat : Test:Example\n",
            ),
        );
        assert!(!report.detected());
        assert!(!report.complete());
    }

    #[test]
    fn avast_detection_survives_an_output_problem() {
        let report = report(
            scanner::Backend::Avast,
            Path::new("test.eml"),
            Capture {
                code: Some(1),
                truncated: true,
                ..Capture::default()
            },
        );
        assert!(report.detected());
        assert!(!report.complete());
    }

    #[test]
    fn a_damaged_output_tail_keeps_preceding_positive_evidence() {
        let mut capture = defender_capture(
            2,
            "Scan finished.\nScanning test.eml found 1 threats.\nLIST OF DETECTED THREATS\nThreat : Test:Example\n",
        );
        capture.stdout.push(0xff);
        capture.truncated = true;
        let result = report(scanner::Backend::Defender, Path::new("test.eml"), capture);
        assert!(result.detected());
        assert!(!result.complete());
    }
}
