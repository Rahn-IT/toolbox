//! Remove the five Chrome external-extension and policy registry trees.

use std::{
    os::windows::process::CommandExt,
    process::{Command, Output},
};

const LOCATIONS: &[&str] = &[
    r"HKLM\SOFTWARE\Google\Chrome\Extensions",
    r"HKLM\SOFTWARE\WOW6432Node\Google\Chrome\Extensions",
    r"HKCU\SOFTWARE\Google\Chrome\Extensions",
    r"HKLM\SOFTWARE\Policies\Google\Chrome",
    r"HKCU\SOFTWARE\Policies\Google\Chrome",
];

pub(super) fn run() -> Result<String, String> {
    let executable = super::system::executable("reg.exe")?;
    let report = clear_with(|location| {
        // Windows supplies reg.exe; no shell or additional runtime is needed.
        Command::new(&executable)
            .args(["delete", location, "/f", "/reg:64"])
            .creation_flags(0x08000000) // CREATE_NO_WINDOW
            .output()
            .map_err(|error| error.to_string())
            .and_then(|output| {
                if output.status.success() {
                    Ok("deleted")
                } else if confirmed_absent(location, &mut |parent| {
                    Command::new(&executable)
                        .args(["query", parent, "/reg:64"])
                        .creation_flags(0x08000000)
                        .output()
                        .map_err(|error| error.to_string())
                        .map(|result| {
                            result
                                .status
                                .success()
                                .then(|| String::from_utf8_lossy(&result.stdout).into_owned())
                        })
                })
                .unwrap_or(false)
                {
                    Ok("already clear")
                } else {
                    Err(details(&output))
                }
            })
    });
    if report.failed == 0 {
        Ok(report.text)
    } else {
        Err(report.text)
    }
}

struct Report {
    failed: usize,
    text: String,
}

fn clear_with(mut delete: impl FnMut(&str) -> Result<&'static str, String>) -> Report {
    let mut failed = 0;
    let mut lines = Vec::new();
    for location in LOCATIONS {
        match delete(location) {
            Ok(status) => lines.push(format!("{location}: {status}.")),
            Err(error) => {
                failed += 1;
                lines.push(format!("{location}: not deleted: {error}"));
            }
        }
    }
    Report {
        failed,
        text: format!(
            "Cleared {} of {} locations. Errors may require administrator rights.\n{}",
            LOCATIONS.len() - failed,
            LOCATIONS.len(),
            lines.join("\n")
        ),
    }
}

// reg.exe uses the same exit code for missing keys and access errors. Confirm
// absence through a readable ancestor rather than interpreting localized errors.
fn confirmed_absent(
    location: &str,
    query: &mut impl FnMut(&str) -> Result<Option<String>, String>,
) -> Result<bool, String> {
    let Some((parent, _)) = location.rsplit_once('\\') else {
        return Ok(false);
    };
    match query(parent)? {
        Some(listing) => {
            let expanded = location.replacen("HKLM", "HKEY_LOCAL_MACHINE", 1).replacen(
                "HKCU",
                "HKEY_CURRENT_USER",
                1,
            );
            Ok(!listing
                .lines()
                .any(|line| line.trim().eq_ignore_ascii_case(&expanded)))
        }
        None => confirmed_absent(parent, query),
    }
}

fn details(output: &Output) -> String {
    let stderr = String::from_utf8_lossy(&output.stderr);
    let stdout = String::from_utf8_lossy(&output.stdout);
    let message = if stderr.trim().is_empty() {
        stdout.trim()
    } else {
        stderr.trim()
    };
    if message.is_empty() {
        format!("reg.exe exited with {}", output.status)
    } else {
        message.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn attempts_every_location_despite_deletion_errors() {
        let mut attempted = Vec::new();
        let report = clear_with(|location| {
            attempted.push(location.to_string());
            if location.starts_with("HKLM") {
                Err("access denied or key missing".into())
            } else {
                Ok("deleted")
            }
        });
        assert_eq!(attempted, LOCATIONS);
        assert_eq!(report.failed, 3);
        assert!(report.text.contains("Cleared 2 of 5 locations"));
        assert!(
            report
                .text
                .contains("HKCU\\SOFTWARE\\Policies\\Google\\Chrome: deleted.")
        );
    }

    #[test]
    fn reports_all_successes() {
        let report = clear_with(|_| Ok("deleted"));
        assert_eq!(report.failed, 0);
        assert!(report.text.contains("Cleared 5 of 5 locations"));
    }

    #[test]
    fn missing_keys_are_successful_and_access_errors_are_not_absence() {
        let report = clear_with(|_| Ok("already clear"));
        assert_eq!(report.failed, 0);
        assert!(report.text.contains("already clear"));
        assert!(
            confirmed_absent(LOCATIONS[0], &mut |_| Ok(Some(
                "HKEY_LOCAL_MACHINE\\SOFTWARE\\Google\\Chrome\n".into()
            )))
            .unwrap()
        );
        assert!(
            !confirmed_absent(LOCATIONS[0], &mut |_| Ok(Some(
                "HKEY_LOCAL_MACHINE\\SOFTWARE\\Google\\Chrome\\Extensions\n".into()
            )))
            .unwrap()
        );
        assert!(!confirmed_absent(LOCATIONS[0], &mut |_| Ok(None)).unwrap());
        assert!(confirmed_absent(LOCATIONS[0], &mut |_| Err("access denied".into())).is_err());
    }
}
