use super::{
    InstallFuture, Installer,
    common::{download_to_temp, remove_file_if_exists, run_installer},
};

pub const INSTALLER: SpotifyInstaller = SpotifyInstaller;

pub struct SpotifyInstaller;

impl Installer for SpotifyInstaller {
    fn id(&self) -> &'static str {
        "spotify"
    }

    fn name(&self) -> &'static str {
        "Spotify"
    }

    fn install(&self) -> InstallFuture<'_> {
        Box::pin(async move {
            let path = download_to_temp(
                "https://download.spotify.com/SpotifyFullSetup.exe",
                "SpotifyFullSetup.exe",
            )
            .await?;

            let result = run_installer(&path, &["/S"]).await;
            remove_file_if_exists(&path).await;
            result
        })
    }
}
