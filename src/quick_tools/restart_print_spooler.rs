//! Restart the Windows Print Spooler without deleting queued print jobs.

pub const TITLE: &str = "Restart Print Spooler (Printer Queue)";

pub fn new() -> crate::OpenedModule {
    super::start(TITLE, run)
}

fn run() -> Result<String, String> {
    for action in ["stop", "start"] {
        // net waits for the service transition before the next command starts.
        if let Err(error) = super::run_windows_command::run("net.exe", &[action, "Spooler"]) {
            let context = if action == "start" {
                "The Print Spooler was stopped, but could not be started again."
            } else {
                "The Print Spooler could not be stopped; restart was not completed."
            };
            return Err(format!("{context}\n{error}"));
        }
    }
    Ok("Print Spooler restarted. Queued print jobs were not deleted.".into())
}
