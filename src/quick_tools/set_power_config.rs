//! Apply the requested display and sleep timeouts to the active Windows power plan.

const SETTINGS: &[(&str, &str)] = &[
    ("-monitor-timeout-dc", "5"),
    ("-standby-timeout-dc", "15"),
    ("-monitor-timeout-ac", "15"),
    ("-standby-timeout-ac", "0"),
];

pub const TITLE: &str = "Set Power Config";

pub fn new() -> crate::OpenedModule {
    super::start(TITLE, run)
}

fn run() -> Result<String, String> {
    apply_with(|setting, minutes| {
        super::run_windows_command::run("powercfg.exe", &["-Change", setting, minutes])
    })
}

fn apply_with(mut apply: impl FnMut(&str, &str) -> Result<(), String>) -> Result<String, String> {
    let mut failed = false;
    let mut lines = Vec::new();
    for &(setting, minutes) in SETTINGS {
        match apply(setting, minutes) {
            Ok(()) => lines.push(format!("{setting} {minutes}: applied.")),
            Err(error) => {
                failed = true;
                lines.push(format!("{setting} {minutes}: failed: {error}"));
            }
        }
    }
    let report = lines.join("\n");
    if failed { Err(report) } else { Ok(report) }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn applies_all_requested_settings_even_after_an_error() {
        let mut attempted = Vec::new();
        let report = apply_with(|setting, minutes| {
            attempted.push((setting.to_string(), minutes.to_string()));
            if setting == "-monitor-timeout-dc" {
                Err("access denied".into())
            } else {
                Ok(())
            }
        })
        .unwrap_err();
        assert_eq!(
            attempted,
            SETTINGS
                .iter()
                .map(|&(setting, minutes)| (setting.to_string(), minutes.to_string()))
                .collect::<Vec<_>>()
        );
        assert!(report.contains("-monitor-timeout-dc 5: failed: access denied"));
        assert!(report.contains("-standby-timeout-ac 0: applied."));
    }

    #[test]
    fn reports_success_when_all_settings_apply() {
        assert!(apply_with(|_, _| Ok(())).is_ok());
    }
}
