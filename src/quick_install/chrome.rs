use super::common::{download_to_temp, remove_file_if_exists, run_elevated_installer};

pub async fn install() -> Result<(), String> {
    let path = download_to_temp(
        "https://dl.google.com/chrome/install/latest/chrome_installer.exe",
        "chrome-installer.exe",
    )
    .await?;

    let result = run_elevated_installer(&path, &["/silent", "/install"]).await;
    remove_file_if_exists(&path).await;
    result
}
