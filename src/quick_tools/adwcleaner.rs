//! Download, elevate, and remove a temporary copy of AdwCleaner.

use std::{fs, os::windows::process::CommandExt, path::Path, process::Command, time::SystemTime};

const URL: &str = "https://adwcleaner.malwarebytes.com/adwcleaner?channel=release";

pub(super) fn run() -> Result<String, String> {
    let nonce = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map_err(|error| error.to_string())?
        .as_nanos();
    let directory =
        std::env::temp_dir().join(format!("toolbox-adwcleaner-{}-{nonce}", std::process::id()));
    fs::create_dir(&directory)
        .map_err(|error| format!("Could not create temporary folder: {error}"))?;
    let path = directory.join("adwcleaner.exe");
    let result = download_and_run(&path);
    let cleanup = fs::remove_file(&path)
        .or_else(|error| {
            if error.kind() == std::io::ErrorKind::NotFound {
                Ok(())
            } else {
                Err(error)
            }
        })
        .and_then(|()| fs::remove_dir(&directory));
    match (result, cleanup) {
        (Ok(()), Ok(())) => Ok("AdwCleaner closed. Temporary download removed.".into()),
        (Err(error), Ok(())) => Err(error),
        (result, Err(error)) => Err(format!(
            "{} Cleanup failed for {}: {error}",
            result.err().unwrap_or_else(|| "AdwCleaner closed.".into()),
            directory.display()
        )),
    }
}

fn download_and_run(path: &Path) -> Result<(), String> {
    // Quick Tools runs this function on Tokio's blocking pool.
    tokio::runtime::Handle::current().block_on(async {
        let client = reqwest::Client::builder()
            .connect_timeout(std::time::Duration::from_secs(30))
            .timeout(std::time::Duration::from_secs(300))
            .build()
            .map_err(|error| format!("Could not create download client: {error}"))?;
        let response = client
            .get(URL)
            .send()
            .await
            .map_err(|error| format!("Download failed: {error}"))?
            .error_for_status()
            .map_err(|error| format!("Download failed: {error}"))?;
        let bytes = response
            .bytes()
            .await
            .map_err(|error| format!("Download failed: {error}"))?;
        tokio::fs::write(path, bytes)
            .await
            .map_err(|error| format!("Could not save AdwCleaner: {error}"))
    })?;

    // Start-Process supplies UAC elevation without unsafe Windows API calls.
    // Pass the path via the environment so it is never interpreted as script text.
    let output = Command::new(super::system::executable(r"WindowsPowerShell\v1.0\powershell.exe")?)
        .args(["-NoProfile", "-NonInteractive", "-Command",
            "$ErrorActionPreference = 'Stop'; try { $process = Start-Process -FilePath $env:TOOLBOX_ADWCLEANER_PATH -Verb RunAs -Wait -PassThru; exit $process.ExitCode } catch { [Console]::Error.WriteLine($_.Exception.Message); exit 1 }"])
        .env("TOOLBOX_ADWCLEANER_PATH", path)
        .creation_flags(0x08000000) // CREATE_NO_WINDOW
        .output().map_err(|error| format!("Could not launch AdwCleaner: {error}"))?;
    if output.status.success() {
        return Ok(());
    }
    Err(format!(
        "AdwCleaner launch or execution failed ({}): {}",
        output.status,
        String::from_utf8_lossy(&output.stderr).trim()
    ))
}
