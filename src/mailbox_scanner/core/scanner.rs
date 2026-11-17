//! The supported installed scanner engines.

use std::fmt;

pub mod avast;
pub mod custom;

/// An installed scanner selected for the run.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Backend {
    /// Avast Business ashCmd.
    Avast,
    /// Microsoft Defender MpCmdRun.
    Defender,
    /// User-selected native command-line scanner.
    Custom,
}

impl fmt::Display for Backend {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Avast => "Avast Business",
            Self::Defender => "Windows Defender",
            Self::Custom => "Custom",
        })
    }
}

/// Immutable scanner-specific configuration for one run.
#[derive(Debug, Clone, Default)]
pub enum Settings {
    /// Auto-detected Microsoft Defender with non-remediating scanning.
    #[default]
    Defender,
    /// Auto-detected Avast with explicit inspection settings.
    Avast(avast::Settings),
    /// User-supplied native scanner command.
    Custom(custom::Settings),
}

/// A scanner setting that cannot form a valid run.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum Error {
    /// Avast accepts sensitivity values from zero through one hundred.
    #[error("Avast heuristic sensitivity must be between 0 and 100")]
    Heuristics,
    /// Custom commands must use an absolute native executable path.
    #[error("Select an absolute path to a native .exe scanner")]
    Executable,
    /// Arguments and executable paths cannot contain NUL characters.
    #[error("Scanner paths and arguments cannot contain NUL characters")]
    Nul,
    /// The directory path must be supplied as a separate argument.
    #[error("Add a separate {{directory}} argument; do not embed it in another argument")]
    Placeholder,
    /// Clean and detected outcomes must be distinguishable.
    #[error("Clean and detected exit codes must be different")]
    ExitCodes,
}

impl Settings {
    /// The display/evidence identity derived from these settings.
    pub fn backend(&self) -> Backend {
        match self {
            Self::Defender => Backend::Defender,
            Self::Avast(_) => Backend::Avast,
            Self::Custom(_) => Backend::Custom,
        }
    }

    /// Validate scanner-specific inputs without filesystem access.
    pub fn validate(&self) -> Result<(), Error> {
        match self {
            Self::Defender => Ok(()),
            Self::Avast(settings) => settings.validate(),
            Self::Custom(settings) => settings.validate(),
        }
    }

    /// Effective inspection scope shown during and after the run.
    pub fn summary(&self) -> String {
        match self {
            Self::Defender => "Windows Defender (auto-detected; no remediation)".into(),
            Self::Avast(settings) => format!(
                "Avast Business: heuristics {}; entire files {}; archives {}",
                settings.heuristics,
                if settings.entire_files { "on" } else { "off" },
                if settings.archives { "on" } else { "off" },
            ),
            Self::Custom(settings) => format!(
                "Custom: clean exit {}; detected exit {}",
                settings.clean_code, settings.detected_code
            ),
        }
    }
}
