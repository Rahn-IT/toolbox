use super::common::{download_to_temp, remove_file_if_exists, run_elevated_installer};

pub async fn install() -> Result<(), String> {
    let path = download_to_temp(
        "https://download.mozilla.org/?product=firefox-latest-ssl&os=win64&lang=de",
        "firefox-installer.exe",
    )
    .await?;

    let result = run_elevated_installer(&path, &["/S"]).await;
    remove_file_if_exists(&path).await;
    result
}
