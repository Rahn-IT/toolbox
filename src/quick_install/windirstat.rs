use crate::quick_install::common::run_msi_installer;

use super::{
    InstallFuture, Installer,
    common::{download_to_temp, remove_file_if_exists},
};

pub const INSTALLER: WinDirStatInstaller = WinDirStatInstaller;

pub struct WinDirStatInstaller;

impl Installer for WinDirStatInstaller {
    fn id(&self) -> &'static str {
        "windirstat"
    }

    fn name(&self) -> &'static str {
        "WinDirStat"
    }

    fn install(&self) -> InstallFuture<'_> {
        Box::pin(async move {
            let path = download_to_temp(
                "https://github.com/windirstat/windirstat/releases/latest/download/WinDirStat-x64.msi",
                "WinDirStat-x64.msi",
            )
            .await?;

            let result = run_msi_installer(&path).await;
            remove_file_if_exists(&path).await;
            result
        })
    }
}
