//! Stable IMAP identity independent of sequence positions or local filenames.

use std::hash::{Hash, Hasher};
use std::num::NonZeroU32;

use crate::mailbox_scanner::core::config;

/// Account identity, deliberately excluding credentials.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Account {
    host: String,
    port: u16,
    username: String,
}

/// A wire folder identity and its independently decoded display name.
#[derive(Debug, Clone)]
pub struct Folder {
    wire: String,
    display: String,
}

/// One immutable message identity within an account and folder generation.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Identity {
    account: Account,
    folder: Folder,
    uidvalidity: NonZeroU32,
    uid: NonZeroU32,
}

/// Folder names that cannot safely be used as IMAP identities.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum Error {
    /// The wire name is empty, too long, or contains a command delimiter.
    #[error("IMAP folder name is empty, oversized, or contains control characters")]
    Folder,
}

impl PartialEq for Folder {
    fn eq(&self, other: &Self) -> bool {
        self.wire == other.wire
    }
}

impl Eq for Folder {}

impl Hash for Folder {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.wire.hash(state);
    }
}

impl Account {
    /// Bind identity to the original validated run settings.
    pub fn from_settings(settings: &config::Settings) -> Self {
        Self {
            host: settings.host().into(),
            port: settings.port(),
            username: settings.username().into(),
        }
    }

    /// The connected host.
    pub fn host(&self) -> &str {
        &self.host
    }

    /// The connected port.
    pub fn port(&self) -> u16 {
        self.port
    }

    /// The authenticated account login.
    pub fn username(&self) -> &str {
        &self.username
    }
}

impl Folder {
    /// Preserve a bounded wire name without normalization or delimiter splitting.
    pub fn new(wire: String, display: String) -> Result<Self, Error> {
        if wire.is_empty() || wire.len() > 8192 || wire.contains(['\r', '\n', '\0']) {
            return Err(Error::Folder);
        }
        Ok(Self { wire, display })
    }

    /// Exact folder name returned by the server.
    pub fn wire(&self) -> &str {
        &self.wire
    }

    /// Independently decoded folder name for presentation.
    pub fn display(&self) -> &str {
        &self.display
    }
}

impl Identity {
    /// Bind a UID to its account, folder and nonzero UIDVALIDITY generation.
    pub fn new(account: Account, folder: Folder, uidvalidity: NonZeroU32, uid: NonZeroU32) -> Self {
        Self {
            account,
            folder,
            uidvalidity,
            uid,
        }
    }

    /// Account originally scanned.
    pub fn account(&self) -> &Account {
        &self.account
    }

    /// Exact folder originally scanned.
    pub fn folder(&self) -> &Folder {
        &self.folder
    }

    /// Nonzero folder generation to recheck before fetching or mutation.
    pub fn uidvalidity(&self) -> u32 {
        self.uidvalidity.get()
    }

    /// Nonzero UID; never a sequence number.
    pub fn uid(&self) -> u32 {
        self.uid.get()
    }
}

#[cfg(test)]
mod tests {
    use std::num::NonZeroU32;

    use super::{Account, Folder, Identity};
    use crate::mailbox_scanner::core::config;

    #[test]
    fn wire_name_is_not_replaced_by_display_or_normalized() {
        let folder = Folder::new("Mail.&AOQ-".into(), "Mail.ä".into()).unwrap();
        assert_eq!(folder.wire(), "Mail.&AOQ-");
        assert_eq!(folder.display(), "Mail.ä");
        assert_eq!(
            folder,
            Folder::new("Mail.&AOQ-".into(), "raw fallback".into()).unwrap()
        );
    }

    #[test]
    fn invalid_wire_names_are_rejected() {
        for wire in [
            String::new(),
            "a\r\nb".into(),
            "a\0b".into(),
            "x".repeat(8193),
        ] {
            assert!(Folder::new(wire, String::new()).is_err());
        }
    }

    #[test]
    fn the_same_uid_in_another_generation_is_a_different_message() {
        let settings = config::Settings::try_from(config::Draft {
            host: "imap.example.org".into(),
            username: "user".into(),
            password: "private password".into(),
            scan_dir: "scan".into(),
            quarantine_dir: "quarantine".into(),
            ..config::Draft::default()
        })
        .unwrap();
        let account = Account::from_settings(&settings);
        assert!(!format!("{account:?}").contains("private password"));
        let folder = Folder::new("INBOX".into(), "INBOX".into()).unwrap();
        let first = Identity::new(
            account.clone(),
            folder.clone(),
            NonZeroU32::new(1).unwrap(),
            NonZeroU32::new(8).unwrap(),
        );
        let replaced = Identity::new(
            account,
            folder,
            NonZeroU32::new(2).unwrap(),
            NonZeroU32::new(8).unwrap(),
        );
        assert_ne!(first, replaced);
    }
}
