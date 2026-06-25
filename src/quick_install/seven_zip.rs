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
    let download_url = download_url
        .split_once(['?', '#'])
        .map(|(path, _)| path)
        .unwrap_or(download_url);

    Path::new(download_url)
        .file_name()
        .and_then(|value| value.to_str())
        .filter(|value| !value.is_empty())
        .unwrap_or("7zip-installer.exe")
        .to_string()
}

fn find_download_url(html: &str) -> Result<String, String> {
    let regex = Regex::new(r#"(?i)href\s*=\s*["']([^"']*7z[^"']*-x64\.exe(?:\?[^"']*)?)["']"#)
        .map_err(|error| format!("invalid regex: {error}"))?;

    let href = regex
        .captures_iter(html)
        .find_map(|capture| capture.get(1).map(|value| value.as_str().to_string()))
        .ok_or_else(|| "failed to find 7-Zip x64 download link".to_string())?;

    Ok(absolute_download_url(&href))
}

fn absolute_download_url(href: &str) -> String {
    if href.starts_with("https://") || href.starts_with("http://") {
        return href.to_string();
    }

    if href.starts_with('/') {
        return format!("https://7-zip.org{href}");
    }

    format!("https://7-zip.org/{href}")
}

#[cfg(test)]
mod tests {
    use super::{absolute_download_url, find_download_url};

    #[test]
    fn finds_current_github_x64_download_url() {
        let html = r#"
            <tr>
              <td><a href="https://github.com/ip7z/7zip/releases/download/26.01/7z2601-x64.exe">Download</a></td>
              <td>.exe</td><td>64-bit x64</td>
            </tr>
        "#;

        let url = find_download_url(html).expect("download URL");

        assert_eq!(
            url,
            "https://github.com/ip7z/7zip/releases/download/26.01/7z2601-x64.exe"
        );
    }

    #[test]
    fn finds_legacy_relative_x64_download_url() {
        let html = r#"<a href="a/7z2408-x64.exe">Download</a>"#;

        let url = find_download_url(html).expect("download URL");

        assert_eq!(url, "https://7-zip.org/a/7z2408-x64.exe");
    }

    #[test]
    fn normalizes_root_relative_download_url() {
        assert_eq!(
            absolute_download_url("/a/7z2408-x64.exe"),
            "https://7-zip.org/a/7z2408-x64.exe"
        );
    }

    #[test]
    fn strips_query_string_from_installer_file_name() {
        assert_eq!(
            super::installer_file_name("https://example.test/7z2601-x64.exe?download=1"),
            "7z2601-x64.exe"
        );
    }
}
