use std::path::{Path, PathBuf};

use tokio::{fs, io::AsyncWriteExt};
use tokio::process::Command;

pub async fn download_to_temp(url: &str, file_name: &str) -> Result<PathBuf, String> {
    let response = reqwest::get(url)
        .await
        .map_err(|error| format!("failed to download {url}: {error}"))?
        .error_for_status()
        .map_err(|error| format!("download failed for {url}: {error}"))?;

    let bytes = response
        .bytes()
        .await
        .map_err(|error| format!("failed to read response body for {url}: {error}"))?;

    let path = std::env::temp_dir().join(file_name);
    let mut file = fs::File::create(&path)
        .await
        .map_err(|error| format!("failed to create {}: {error}", path.display()))?;

    file.write_all(&bytes)
        .await
        .map_err(|error| format!("failed to write {}: {error}", path.display()))?;

    file.flush()
        .await
        .map_err(|error| format!("failed to flush {}: {error}", path.display()))?;

    Ok(path)
}

pub async fn fetch_text(url: &str) -> Result<String, String> {
    reqwest::get(url)
        .await
        .map_err(|error| format!("failed to fetch {url}: {error}"))?
        .error_for_status()
        .map_err(|error| format!("request failed for {url}: {error}"))?
        .text()
        .await
        .map_err(|error| format!("failed to read response text for {url}: {error}"))
}

pub async fn run_elevated_installer(path: &Path, parameters: &[&str]) -> Result<(), String> {
    let path = escape_powershell_string(&path.display().to_string());
    let parameters = parameters
        .iter()
        .map(|value| escape_powershell_string(value))
        .collect::<Vec<_>>()
        .join(", ");
    let script = format!(
        "$process = Start-Process -FilePath '{path}' -ArgumentList @('{parameters}') -Verb RunAs -Wait -PassThru; exit $process.ExitCode"
    );

    let output = Command::new("powershell")
        .args([
            "-NoProfile",
            "-ExecutionPolicy",
            "Bypass",
            "-Command",
            &script,
        ])
        .output()
        .await
        .map_err(|error| format!("failed to start PowerShell: {error}"))?;

    if output.status.success() {
        return Ok(());
    }

    let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
    let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
    let details = if !stderr.is_empty() { stderr } else { stdout };

    Err(if details.is_empty() {
        format!("installer {} failed", path)
    } else {
        details
    })
}

pub async fn remove_file_if_exists(path: &Path) {
    let _ = fs::remove_file(path).await;
}

fn escape_powershell_string(value: &str) -> String {
    value.replace('\'', "''")
}
