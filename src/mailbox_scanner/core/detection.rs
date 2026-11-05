//! Compact scan evidence and local/upstream action outcomes.

use std::fmt;
use std::path::{Path, PathBuf};

use crate::mailbox_scanner::core::scanner;

const SAMPLES: usize = 8;
const THREAT_BYTES: usize = 256;
const DETAIL_BYTES: usize = 512;

/// Positive scanner evidence; independent of incomplete scan coverage.
#[derive(Debug, Clone)]
pub struct Evidence {
    /// The engine supplying positive evidence.
    pub backend: scanner::Backend,
    /// A scanner-reported name or explicit generic detection label.
    pub threat: String,
}

/// A reason not to describe scan coverage as complete.
#[derive(Debug, Clone)]
pub enum Issue {
    /// An application resource limit was reached.
    Limit(&'static str),
    /// MIME structure or transfer decoding could not be fully inspected.
    Decode(String),
    /// The scanner failed or returned an unsupported output format.
    Scanner(String),
    /// The input was inaccessible or changed unexpectedly.
    Input(String),
    /// The message operation was cancelled.
    Cancelled,
}

/// Bounded retained findings; omitted sample counters never erase a detection.
#[derive(Debug, Clone, Default)]
pub struct Report {
    evidence: Vec<Evidence>,
    issues: Vec<Issue>,
    omitted_evidence: u64,
    omitted_issues: u64,
}

/// Metadata recording an observed save, not proof that a file still exists.
#[derive(Debug, Clone)]
pub struct Saved {
    path: PathBuf,
    expected_len: u64,
}

/// Later local-file availability, deliberately not a byte-integrity assertion.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Availability {
    /// The file can be read and has the expected length.
    Available,
    /// The saved path no longer exists.
    Missing,
    /// Access failed for the displayed reason.
    Unreadable(String),
    /// The current length differs from the verified save.
    SizeChanged {
        /// The current file length.
        actual: u64,
    },
}

/// A purge-operation result; only Purged confirms completed targeted deletion.
#[derive(Debug, Clone)]
pub enum Purge {
    /// A copy was retained but the action stopped before confirmed mutation.
    Saved {
        /// The local copy's observed metadata.
        saved: Saved,
        /// Why purge stopped or what reconciliation established.
        detail: String,
    },
    /// The message remains upstream marked Deleted.
    MarkedDeleted {
        /// The local copy's observed metadata.
        saved: Saved,
        /// Whether Deleted was already set before this operation.
        preexisting_deleted: bool,
    },
    /// Targeted expunge was acknowledged and the UID was confirmed absent.
    Purged(Saved),
    /// A possibly sent mutation could not be conclusively reconciled.
    OutcomeUnknown {
        /// The preserved local copy's observed metadata.
        saved: Saved,
        /// The uncertainty or reconciliation failure.
        detail: String,
    },
}

impl fmt::Display for Issue {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Limit(detail) => write!(formatter, "Limit: {detail}"),
            Self::Decode(detail) => write!(formatter, "MIME: {detail}"),
            Self::Scanner(detail) => write!(formatter, "Scanner: {detail}"),
            Self::Input(detail) => write!(formatter, "Input: {detail}"),
            Self::Cancelled => formatter.write_str("Cancelled"),
        }
    }
}

impl Report {
    /// Start with no findings; callers must still perform every required scan.
    pub fn new() -> Self {
        Self::default()
    }

    /// Retain positive evidence within the sample budget.
    pub fn record(&mut self, mut evidence: Evidence) {
        if self.evidence.len() == SAMPLES {
            self.omitted_evidence = self.omitted_evidence.saturating_add(1);
            return;
        }
        clip(&mut evidence.threat, THREAT_BYTES);
        self.evidence.push(evidence);
    }

    /// Retain an incomplete-coverage reason within the sample budget.
    pub fn warn(&mut self, mut issue: Issue) {
        if self.issues.len() == SAMPLES {
            self.omitted_issues = self.omitted_issues.saturating_add(1);
            return;
        }
        match &mut issue {
            Issue::Decode(detail) | Issue::Scanner(detail) | Issue::Input(detail) => {
                clip(detail, DETAIL_BYTES);
            }
            Issue::Limit(_) | Issue::Cancelled => {}
        }
        self.issues.push(issue);
    }

    /// Combine bounded samples while preserving all detection/coverage facts.
    pub fn merge(&mut self, other: Self) {
        self.omitted_evidence = self.omitted_evidence.saturating_add(other.omitted_evidence);
        self.omitted_issues = self.omitted_issues.saturating_add(other.omitted_issues);
        for evidence in other.evidence {
            self.record(evidence);
        }
        for issue in other.issues {
            self.warn(issue);
        }
    }

    /// Retained positive evidence samples.
    pub fn evidence(&self) -> &[Evidence] {
        &self.evidence
    }

    /// Retained incomplete-coverage samples.
    pub fn issues(&self) -> &[Issue] {
        &self.issues
    }

    /// Additional evidence samples not retained in memory.
    pub fn omitted_evidence(&self) -> u64 {
        self.omitted_evidence
    }

    /// Additional issue samples not retained in memory.
    pub fn omitted_issues(&self) -> u64 {
        self.omitted_issues
    }

    /// Whether at least one required scan supplied positive evidence.
    pub fn detected(&self) -> bool {
        !self.evidence.is_empty() || self.omitted_evidence != 0
    }

    /// Whether there were no reported inspection failures or limits.
    pub fn complete(&self) -> bool {
        self.issues.is_empty() && self.omitted_issues == 0
    }
}

impl Saved {
    /// Record the path and byte length observed by the IO-layer save operation.
    pub fn new(path: PathBuf, expected_len: u64) -> Self {
        Self { path, expected_len }
    }

    /// The path deliberately preserved by a download action.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// The byte length during initial verification.
    pub fn expected_len(&self) -> u64 {
        self.expected_len
    }
}

fn clip(value: &mut String, maximum: usize) {
    if value.len() <= maximum {
        return;
    }
    let mut boundary = maximum;
    while !value.is_char_boundary(boundary) {
        boundary -= 1;
    }
    value.truncate(boundary);
}

#[cfg(test)]
mod tests {
    use super::{Evidence, Issue, Report};
    use crate::mailbox_scanner::core::scanner::Backend;

    #[test]
    fn positive_evidence_survives_a_later_failure() {
        let mut report = Report::new();
        report.record(Evidence {
            backend: Backend::Defender,
            threat: "EICAR test detection".into(),
        });
        report.warn(Issue::Input("Later leaf was removed".into()));
        assert!(report.detected());
        assert!(!report.complete());
        assert_eq!(report.evidence().len(), 1);
    }

    #[test]
    fn retained_samples_are_bounded_without_losing_counts() {
        let mut report = Report::new();
        for _ in 0..12 {
            report.record(Evidence {
                backend: Backend::Avast,
                threat: "🦀".repeat(100),
            });
            report.warn(Issue::Scanner("🦀".repeat(200)));
        }
        assert_eq!(report.evidence().len(), 8);
        assert_eq!(report.issues().len(), 8);
        assert_eq!(report.omitted_evidence(), 4);
        assert_eq!(report.omitted_issues(), 4);
        assert_eq!(report.evidence()[0].threat.len(), 256);
        assert!(report.issues()[0].to_string().len() < 530);
    }

    #[test]
    fn merge_preserves_omitted_findings_and_incomplete_status() {
        let mut report = Report::new();
        let mut incoming = Report::new();
        for _ in 0..10 {
            incoming.record(Evidence {
                backend: Backend::Avast,
                threat: "Example".into(),
            });
            incoming.warn(Issue::Cancelled);
        }
        report.merge(incoming.clone());
        report.merge(incoming);
        assert_eq!(report.evidence().len(), 8);
        assert_eq!(report.issues().len(), 8);
        assert_eq!(report.omitted_evidence(), 12);
        assert_eq!(report.omitted_issues(), 12);
        assert!(report.detected());
        assert!(!report.complete());
    }
}
