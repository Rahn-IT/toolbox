//! Transformation of editable setup fields into immutable run settings.

use std::fmt;
use std::num::{NonZeroU8, NonZeroU16};
use std::path::{Path, PathBuf};

use crate::mailbox_scanner::core::scanner;

/// The mandatory encrypted IMAP transport.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tls {
    /// TLS begins immediately after TCP connection.
    Implicit,
    /// The plaintext greeting is followed by a required TLS upgrade.
    StartTls,
}

impl fmt::Display for Tls {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Implicit => "TLS",
            Self::StartTls => "STARTTLS",
        })
    }
}

/// Raw setup fields; filesystem availability is checked by the IO layer.
#[derive(Clone)]
pub struct Draft {
    /// IMAP DNS name or IP address.
    pub host: String,
    /// Editable decimal TCP port.
    pub port: String,
    /// IMAP account login.
    pub username: String,
    /// Password kept only in memory.
    pub password: String,
    /// Parent directory for owned temporary scan files.
    pub scan_dir: PathBuf,
    /// Parent directory for deliberately preserved EML output.
    pub quarantine_dir: PathBuf,
    /// Selected installed engine.
    pub backend: scanner::Backend,
    /// Optional installed engine path override.
    pub executable: Option<PathBuf>,
    /// Editable number of concurrent message scans.
    pub parallel: String,
    /// Encrypted transport mode.
    pub tls: Tls,
}

/// Validated immutable configuration for one mailbox run.
#[derive(Clone)]
pub struct Settings {
    host: String,
    port: NonZeroU16,
    username: String,
    password: String,
    scan_dir: PathBuf,
    quarantine_dir: PathBuf,
    backend: scanner::Backend,
    executable: Option<PathBuf>,
    parallel: NonZeroU8,
    tls: Tls,
}

/// A setup field that cannot form valid settings.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum Error {
    /// A host is absent or contains protocol control characters.
    #[error("Enter an IMAP hostname without control characters")]
    Host,
    /// The TCP port is not a nonzero u16.
    #[error("Port must be between 1 and 65535")]
    Port,
    /// Credentials are absent or the login contains control characters.
    #[error("Enter a username and password without login control characters")]
    Credentials,
    /// A required directory path is empty.
    #[error("Select both scan and quarantine folders")]
    Folders,
    /// Concurrency is outside the supported range.
    #[error("Parallel scans must be between 1 and 16")]
    Parallel,
}

impl Default for Draft {
    fn default() -> Self {
        Self {
            host: String::new(),
            port: "993".into(),
            username: String::new(),
            password: String::new(),
            scan_dir: PathBuf::new(),
            quarantine_dir: PathBuf::new(),
            backend: scanner::Backend::Defender,
            executable: None,
            parallel: "4".into(),
            tls: Tls::Implicit,
        }
    }
}

impl fmt::Debug for Draft {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Draft")
            .field("host", &self.host)
            .field("port", &self.port)
            .field("username", &self.username)
            .field("password", &"[redacted]")
            .field("scan_dir", &self.scan_dir)
            .field("quarantine_dir", &self.quarantine_dir)
            .field("backend", &self.backend)
            .field("executable", &self.executable)
            .field("parallel", &self.parallel)
            .field("tls", &self.tls)
            .finish()
    }
}

impl fmt::Debug for Settings {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Settings")
            .field("host", &self.host)
            .field("port", &self.port)
            .field("username", &self.username)
            .field("password", &"[redacted]")
            .field("scan_dir", &self.scan_dir)
            .field("quarantine_dir", &self.quarantine_dir)
            .field("backend", &self.backend)
            .field("executable", &self.executable)
            .field("parallel", &self.parallel)
            .field("tls", &self.tls)
            .finish()
    }
}

impl TryFrom<Draft> for Settings {
    type Error = Error;

    fn try_from(draft: Draft) -> Result<Self, Self::Error> {
        let host = draft.host.trim();
        if host.is_empty() || draft.host.chars().any(char::is_control) {
            return Err(Error::Host);
        }
        let port = draft
            .port
            .trim()
            .parse::<NonZeroU16>()
            .map_err(|_| Error::Port)?;
        let username = draft.username.trim();
        if username.is_empty()
            || draft.username.chars().any(char::is_control)
            || draft.password.is_empty()
        {
            return Err(Error::Credentials);
        }
        if draft.scan_dir.as_os_str().is_empty() || draft.quarantine_dir.as_os_str().is_empty() {
            return Err(Error::Folders);
        }
        let parallel = draft
            .parallel
            .trim()
            .parse::<NonZeroU8>()
            .map_err(|_| Error::Parallel)?;
        if parallel.get() > 16 {
            return Err(Error::Parallel);
        }
        Ok(Self {
            host: host.into(),
            port,
            username: username.into(),
            password: draft.password,
            scan_dir: draft.scan_dir,
            quarantine_dir: draft.quarantine_dir,
            backend: draft.backend,
            executable: draft.executable.filter(|path| !path.as_os_str().is_empty()),
            parallel,
            tls: draft.tls,
        })
    }
}

impl Settings {
    /// The validated IMAP host.
    pub fn host(&self) -> &str {
        &self.host
    }

    /// The nonzero TCP port.
    pub fn port(&self) -> u16 {
        self.port.get()
    }

    /// The account login.
    pub fn username(&self) -> &str {
        &self.username
    }

    /// The exact password, without whitespace normalization.
    pub fn password(&self) -> &str {
        &self.password
    }

    /// Parent for owned temporary scan directories.
    pub fn scan_dir(&self) -> &Path {
        &self.scan_dir
    }

    /// Parent for deliberately preserved EML files.
    pub fn quarantine_dir(&self) -> &Path {
        &self.quarantine_dir
    }

    /// The selected installed scanner engine.
    pub fn backend(&self) -> scanner::Backend {
        self.backend
    }

    /// Optional installed scanner path override.
    pub fn executable(&self) -> Option<&Path> {
        self.executable.as_deref()
    }

    /// Maximum concurrent message scans.
    pub fn parallel(&self) -> u8 {
        self.parallel.get()
    }

    /// Required encrypted transport mode.
    pub fn tls(&self) -> Tls {
        self.tls
    }
}

#[cfg(test)]
mod tests {
    use super::{Draft, Error, Settings};

    fn draft() -> Draft {
        Draft {
            host: " imap.example.org ".into(),
            username: " user@example.org ".into(),
            password: " secret ".into(),
            scan_dir: "scan".into(),
            quarantine_dir: "quarantine".into(),
            ..Draft::default()
        }
    }

    #[test]
    fn settings_normalize_fields_but_preserve_password() {
        let settings = Settings::try_from(draft()).unwrap();
        assert_eq!(settings.host(), "imap.example.org");
        assert_eq!(settings.username(), "user@example.org");
        assert_eq!(settings.password(), " secret ");
        assert_eq!(settings.port(), 993);
    }

    #[test]
    fn concurrency_rejects_zero_and_out_of_range_values() {
        for value in ["0", "17", "-1", "256", "many"] {
            let mut input = draft();
            input.parallel = value.into();
            assert!(matches!(Settings::try_from(input), Err(Error::Parallel)));
        }
        for value in ["1", "8", "16"] {
            let mut input = draft();
            input.parallel = value.into();
            assert!(Settings::try_from(input).is_ok());
        }
    }

    #[test]
    fn protocol_controls_and_invalid_ports_are_rejected() {
        let mut input = draft();
        input.host = "example.org\r\nLOGIN".into();
        assert!(matches!(Settings::try_from(input), Err(Error::Host)));
        let mut input = draft();
        input.host = "example.org\r\n".into();
        assert!(matches!(Settings::try_from(input), Err(Error::Host)));
        let mut input = draft();
        input.username = "user\0other".into();
        assert!(matches!(Settings::try_from(input), Err(Error::Credentials)));
        for value in ["0", "65536", "imap"] {
            let mut input = draft();
            input.port = value.into();
            assert!(matches!(Settings::try_from(input), Err(Error::Port)));
        }
    }

    #[test]
    fn debug_output_redacts_password() {
        let input = draft();
        assert!(!format!("{input:?}").contains(" secret "));
        let settings = Settings::try_from(input).unwrap();
        assert!(!format!("{settings:?}").contains(" secret "));
    }
}
