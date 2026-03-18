use super::{
    InstallFuture, Installer,
    common::{download_to_temp, remove_file_if_exists, run_elevated_installer},
};

pub const INSTALLER: SteamInstaller = SteamInstaller;

pub struct SteamInstaller;

impl Installer for SteamInstaller {
    fn id(&self) -> &'static str {
        "steam"
    }

    fn name(&self) -> &'static str {
        "Steam"
    }

    fn install(&self) -> InstallFuture<'_> {
        Box::pin(async move {
            let path = download_to_temp(
                "https://cdn.cloudflare.steamstatic.com/client/installer/SteamSetup.exe",
                "SteamSetup.exe",
            )
            .await?;

            let result = run_elevated_installer(&path, &["/S"]).await;
            remove_file_if_exists(&path).await;
            result
        })
    }
}
