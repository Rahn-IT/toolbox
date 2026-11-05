//! The supported installed scanner engines.

use std::fmt;

/// An installed scanner selected for the run.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Backend {
    /// Avast Business ashCmd.
    Avast,
    /// Microsoft Defender MpCmdRun.
    Defender,
}

impl fmt::Display for Backend {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Avast => "Avast Business",
            Self::Defender => "Windows Defender",
        })
    }
}
