//! Credential-free worker events consumed by the GUI.

use std::path::PathBuf;

use crate::mailbox_scanner::core::{detection, message};

/// Snapshot of run counters; detected and incomplete can overlap.
#[derive(Debug, Clone, Copy, Default)]
pub struct Counts {
    /// Downloaded messages waiting on disk for a scan slot.
    pub queued: u8,
    /// Snapshotted message UIDs.
    pub total: u64,
    /// Attempted messages that reached a terminal outcome.
    pub processed: u64,
    /// Messages with positive detection evidence.
    pub detected: u64,
    /// Messages with incomplete inspection coverage.
    pub incomplete: u64,
    /// Snapshotted messages no longer present.
    pub vanished: u64,
    /// Messages cancelled before processing.
    pub cancelled: u64,
    /// Reserved message jobs still active.
    pub active: u8,
}

/// A run's terminal status, independent of progress percentage.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Finish {
    /// Every scheduled folder/message was inspected without reported gaps.
    Completed,
    /// At least one folder, message or cleanup step was incomplete.
    Partial,
    /// The user requested cancellation.
    Cancelled,
    /// The run could not proceed.
    Failed,
}

/// A progress or explicit-action event, containing no login password.
#[derive(Debug, Clone)]
pub enum Event {
    /// Folder/UID discovery is underway; the final denominator is not known.
    Discovering,
    /// Latest authoritative progress snapshot and display folder.
    Progress {
        /// Latest worker counts.
        counts: Counts,
        /// Current display name, when a folder is selected.
        folder: Option<String>,
    },
    /// One message inspection reached a terminal result.
    MessageFinished {
        /// Stable original message identity.
        identity: message::Identity,
        /// Bounded decoded display subject.
        subject: String,
        /// Bounded decoded display sender.
        sender: String,
        /// Positive evidence and independent incomplete-coverage reasons.
        report: detection::Report,
    },
    /// A snapshotted UID disappeared before fetching.
    Vanished(message::Identity),
    /// A bounded operational diagnostic.
    Diagnostic {
        /// Folder/action context, excluding credentials.
        context: String,
        /// Display explanation, not an error-dispatch protocol.
        detail: String,
    },
    /// An explicit download-only operation retained a local EML.
    Downloaded {
        /// Original upstream message, left untouched.
        identity: message::Identity,
        /// Locally verified save metadata.
        saved: detection::Saved,
    },
    /// A local availability-only check completed.
    Checked {
        /// Original message associated with the local record.
        identity: message::Identity,
        /// Current observed availability and length.
        availability: detection::Availability,
    },
    /// A purge operation settled; inspect outcome before claiming deletion.
    Purged {
        /// The exact original upstream identity.
        identity: message::Identity,
        /// Confirmed state or explicit remaining uncertainty.
        outcome: detection::Purge,
    },
    /// An explicit action failed before any upstream mutation.
    ActionFailed {
        /// The message whose action failed.
        identity: message::Identity,
        /// Bounded display explanation.
        detail: String,
    },
    /// An owned temporary path could not be removed.
    Leftover(PathBuf),
    /// All workers and cleanup attempts have settled.
    Finished {
        /// Terminal run status.
        finish: Finish,
        /// Final authoritative counts.
        counts: Counts,
    },
}
