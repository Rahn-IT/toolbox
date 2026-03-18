use std::path::Path;

use regex::Regex;

use super::{
    InstallFuture, Installer,
    common::{download_to_temp, fetch_text, remove_file_if_exists, run_elevated_installer},
};

pub const INSTALLER: SevenZipInstaller = SevenZipInstaller;

pub struct SevenZipInstaller;

impl Installer for SevenZipInstaller {
    fn id(&self) -> &'static str {
        "7zip"
    }

    fn name(&self) -> &'static str {
        "7-Zip"
    }

    fn install(&self) -> InstallFuture<'_> {
        Box::pin(async move {
            let html = fetch_text("https://7-zip.org/").await?;
            let download_url = find_download_url(&html)?;
            let file_name = installer_file_name(&download_url);
            let path = download_to_temp(&download_url, &file_name).await?;

            let result = run_elevated_installer(&path, &["/S"]).await;
            remove_file_if_exists(&path).await;
            result
        })
    }
}

fn installer_file_name(download_url: &str) -> String {
    Path::new(download_url)
        .file_name()
        .and_then(|value| value.to_str())
        .filter(|value| !value.is_empty())
        .unwrap_or("7zip-installer.exe")
        .to_string()
}

fn find_download_url(html: &str) -> Result<String, String> {
    let regex =
        Regex::new(r#"href="(a/[^"]*-x64\.exe)""#).map_err(|error| format!("invalid regex: {error}"))?;

    let href = regex
        .captures_iter(html)
        .find_map(|capture| capture.get(1).map(|value| value.as_str().to_string()))
        .ok_or_else(|| "failed to find 7-Zip x64 download link".to_string())?;

    Ok(format!("https://7-zip.org/{href}"))
}
