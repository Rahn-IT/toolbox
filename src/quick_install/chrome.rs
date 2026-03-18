use super::{
    InstallFuture, Installer,
    common::{download_to_temp, remove_file_if_exists, run_elevated_installer},
};

pub const INSTALLER: ChromeInstaller = ChromeInstaller;

pub struct ChromeInstaller;

impl Installer for ChromeInstaller {
    fn id(&self) -> &'static str {
        "chrome"
    }

    fn name(&self) -> &'static str {
        "Chrome"
    }

    fn install(&self) -> InstallFuture<'_> {
        Box::pin(async move {
            let path = download_to_temp(
                "https://dl.google.com/chrome/install/latest/chrome_installer.exe",
                "chrome-installer.exe",
            )
            .await?;

            let result = run_elevated_installer(&path, &["/silent", "/install"]).await;
            remove_file_if_exists(&path).await;
            result
        })
    }
}
