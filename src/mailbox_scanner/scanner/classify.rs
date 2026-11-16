//! Shared scanner capture finalization and bounded diagnostics.

use std::path::Path;

use super::{avast, custom, defender};
use crate::mailbox_scanner::core::{detection, scanner};

#[derive(Default)]
pub(super) struct Capture {
    pub code: Option<i32>,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
    pub truncated: bool,
    pub timed_out: bool,
    pub cancelled: bool,
    pub termination_requested: bool,
    pub failure: Option<String>,
}

pub(super) fn report(
    settings: &scanner::Settings,
    path: &Path,
    capture: Capture,
) -> detection::Report {
    let mut result = detection::Report::new();
    match settings {
        scanner::Settings::Avast(_) => avast::report(&capture, &mut result),
        scanner::Settings::Defender => defender::report(path, &capture, &mut result),
        scanner::Settings::Custom(settings) => custom::report(settings, &capture, &mut result),
    }
    if capture.termination_requested {
        result.warn(detection::Issue::Scanner(
            "Scanner termination was requested; exit code does not establish completion".into(),
        ));
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

pub(super) fn decode(bytes: &[u8]) -> Result<String, ()> {
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

pub(super) fn valid_prefix(bytes: &[u8]) -> String {
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

pub(super) fn diagnostic(bytes: &[u8]) -> String {
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
            &scanner::Settings::Defender,
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
        let report = report(&scanner::Settings::Defender, Path::new("test.eml"), capture);
        assert!(report.detected());
        assert!(!report.complete());
    }

    #[test]
    fn a_foreign_path_and_threat_words_are_not_evidence() {
        let capture = defender_capture(
            2,
            "Scanning another.eml found 1 threats.\nLIST OF DETECTED THREATS\nThreat : Test:Example\n",
        );
        let report = report(&scanner::Settings::Defender, Path::new("test.eml"), capture);
        assert!(!report.detected());
        assert!(!report.complete());
    }

    #[test]
    fn success_requires_a_matching_zero_threat_summary() {
        let report = report(
            &scanner::Settings::Defender,
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
        let result = report(&scanner::Settings::Defender, path, capture);
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
            &scanner::Settings::Defender,
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
            &scanner::Settings::Avast(scanner::avast::Settings::default()),
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
            &scanner::Settings::Defender,
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
            &scanner::Settings::Avast(scanner::avast::Settings::default()),
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
        let result = report(&scanner::Settings::Defender, Path::new("test.eml"), capture);
        assert!(result.detected());
        assert!(!result.complete());
    }

    fn custom_settings() -> scanner::Settings {
        scanner::Settings::Custom(scanner::custom::Settings {
            executable: std::env::current_exe().unwrap(),
            arguments: vec!["{file}".into()],
            clean_code: 0,
            detected_code: 1,
        })
    }

    #[test]
    fn custom_normal_exit_codes_and_stderr_are_interpreted_conservatively() {
        for (code, detected, complete) in [
            (Some(0), false, true),
            (Some(1), true, true),
            (Some(7), false, false),
            (None, false, false),
        ] {
            let result = report(
                &custom_settings(),
                Path::new("mail.eml"),
                Capture {
                    code,
                    ..Default::default()
                },
            );
            assert_eq!(result.detected(), detected);
            assert_eq!(result.complete(), complete);
        }
        let result = report(
            &custom_settings(),
            Path::new("mail.eml"),
            Capture {
                code: Some(0),
                stderr: b"scanner warning".to_vec(),
                ..Default::default()
            },
        );
        assert!(!result.complete());
        assert!(!result.detected());
    }

    #[test]
    fn forced_termination_codes_are_neither_clean_nor_positive() {
        for settings in [
            custom_settings(),
            scanner::Settings::Avast(scanner::avast::Settings::default()),
        ] {
            for code in [0, 1] {
                let result = report(
                    &settings,
                    Path::new("mail.eml"),
                    Capture {
                        code: Some(code),
                        termination_requested: true,
                        ..Default::default()
                    },
                );
                assert!(!result.detected());
                assert!(!result.complete());
            }
        }
    }

    #[test]
    fn normal_custom_detection_survives_later_coverage_issues() {
        for capture in [
            Capture {
                truncated: true,
                ..Default::default()
            },
            Capture {
                timed_out: true,
                ..Default::default()
            },
            Capture {
                cancelled: true,
                ..Default::default()
            },
            Capture {
                failure: Some("pipe failed".into()),
                ..Default::default()
            },
        ] {
            let result = report(
                &custom_settings(),
                Path::new("mail.eml"),
                Capture {
                    code: Some(1),
                    ..capture
                },
            );
            assert!(result.detected());
            assert!(!result.complete());
        }
    }

    #[test]
    fn defender_text_evidence_survives_forced_termination() {
        let mut capture = defender_capture(
            1,
            "Scan finished.\nScanning mail.eml found 1 threats.\nLIST OF DETECTED THREATS\nThreat : Test:Example\n",
        );
        capture.termination_requested = true;
        let result = report(&scanner::Settings::Defender, Path::new("mail.eml"), capture);
        assert!(result.detected());
        assert!(!result.complete());
    }
}
