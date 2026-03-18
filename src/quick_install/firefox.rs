use super::{
    InstallFuture, Installer,
    common::{download_to_temp, remove_file_if_exists, run_elevated_installer},
};

pub const INSTALLER: FirefoxInstaller = FirefoxInstaller;

pub struct FirefoxInstaller;

impl Installer for FirefoxInstaller {
    fn id(&self) -> &'static str {
        "firefox"
    }

    fn name(&self) -> &'static str {
        "Firefox"
    }

    fn install(&self) -> InstallFuture<'_> {
        Box::pin(async move {
            let path = download_to_temp(
                "https://download.mozilla.org/?product=firefox-latest-ssl&os=win64&lang=de",
                "firefox-installer.exe",
            )
            .await?;

            let result = run_elevated_installer(&path, &["/S"]).await;
            remove_file_if_exists(&path).await;
            result
        })
    }
}
