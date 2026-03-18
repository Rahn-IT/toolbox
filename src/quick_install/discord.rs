use super::{
    InstallFuture, Installer,
    common::{download_to_temp, remove_file_if_exists, run_elevated_installer},
};

pub const INSTALLER: DiscordInstaller = DiscordInstaller;

pub struct DiscordInstaller;

impl Installer for DiscordInstaller {
    fn id(&self) -> &'static str {
        "discord"
    }

    fn name(&self) -> &'static str {
        "Discord"
    }

    fn install(&self) -> InstallFuture<'_> {
        Box::pin(async move {
            let path =
                download_to_temp("https://discord.com/api/download?platform=win", "discord.exe")
                    .await?;

            let result = run_elevated_installer(&path, &["-S"]).await;
            remove_file_if_exists(&path).await;
            result
        })
    }
}
