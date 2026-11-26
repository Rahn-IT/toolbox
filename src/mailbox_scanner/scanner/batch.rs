//! Per-message aggregation of a directory scanner's streaming file results.

use std::{collections::HashMap, sync::Mutex, time::Duration};

use tokio::{sync::watch, time::Instant};

use super::{Engine, avast, custom, transport};
use crate::mailbox_scanner::{
    batch,
    core::{detection, scanner},
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Status {
    Clean,
    Detected,
    Error,
}

pub(super) struct Record {
    pub path: String,
    pub status: Status,
    pub detail: String,
    pub terminal: bool,
}

/// Coalesced state is bounded by the messages in one admitted batch.
#[derive(Default)]
pub(crate) struct Updates {
    pending: Mutex<HashMap<usize, (u64, detection::Report)>>,
}

impl Updates {
    fn publish(&self, index: usize, revision: u64, report: &detection::Report) {
        let mut pending = self
            .pending
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        pending.insert(index, (revision, report.clone()));
    }

    pub(crate) fn take(&self) -> Vec<(usize, u64, detection::Report)> {
        let mut pending = self
            .pending
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        pending
            .drain()
            .map(|(index, (revision, report))| (index, revision, report))
            .collect()
    }
}

pub(crate) struct Outcome {
    pub reports: Vec<detection::Report>,
    pub cleanup_safe: bool,
}

struct Inspection<'a> {
    batch: &'a batch::Batch,
    backend: scanner::Backend,
    reports: Vec<detection::Report>,
    states: Vec<Option<Status>>,
    revisions: Vec<u64>,
    updates: &'a Updates,
    diagnostics: detection::Report,
}

impl<'a> Inspection<'a> {
    fn new(batch: &'a batch::Batch, backend: scanner::Backend, updates: &'a Updates) -> Self {
        Self {
            batch,
            backend,
            updates,
            reports: batch
                .messages()
                .iter()
                .map(|message| message.report().clone())
                .collect(),
            states: vec![None; batch.files().len()],
            revisions: vec![0; batch.messages().len()],
            diagnostics: detection::Report::new(),
        }
    }

    fn warn(&mut self, detail: impl Into<String>) {
        self.diagnostics
            .warn(detection::Issue::Scanner(detail.into()));
    }

    fn record(&mut self, record: Record) {
        let Some(file) = self.batch.lookup(&record.path) else {
            self.warn("Scanner returned a path outside the batch manifest");
            return;
        };
        let owner = self.batch.files()[file].owner();
        let report = &mut self.reports[owner];
        if record.terminal {
            if let Some(previous) = self.states[file] {
                if previous != record.status {
                    report.warn(detection::Issue::Scanner(
                        "Conflicting results for the same scan file".into(),
                    ));
                } else if record.status != Status::Detected {
                    return;
                }
            }
            self.states[file] = Some(record.status);
        }
        match record.status {
            Status::Clean => {}
            Status::Detected => {
                let threat = if record.detail.is_empty() {
                    format!("{} detected a threat", self.backend)
                } else {
                    record.detail
                };
                if !report
                    .evidence()
                    .iter()
                    .any(|evidence| evidence.threat == threat)
                {
                    report.record(detection::Evidence {
                        backend: self.backend,
                        threat,
                    });
                }
            }
            Status::Error => report.warn(detection::Issue::Scanner(if record.detail.is_empty() {
                "Scanner could not inspect this file".into()
            } else {
                record.detail
            })),
        }
        if report.detected() {
            self.revisions[owner] = self.revisions[owner].saturating_add(1);
            self.updates.publish(owner, self.revisions[owner], report);
        }
    }

    fn line(
        &mut self,
        settings: &scanner::Settings,
        stream: transport::Stream,
        record: transport::Record,
    ) {
        let bytes = match record {
            transport::Record::Line(bytes) => bytes,
            transport::Record::Oversized => {
                self.warn("Scanner record exceeds 64 KiB");
                return;
            }
            transport::Record::InvalidEncoding => {
                self.warn("Scanner record has invalid encoding");
                return;
            }
        };
        if bytes.is_empty() {
            return;
        }
        if stream == transport::Stream::Stderr {
            self.warn(format!(
                "Scanner diagnostic: {}",
                super::classify::diagnostic(&bytes)
            ));
            return;
        }
        let parsed = match settings {
            scanner::Settings::Custom(_) => std::str::from_utf8(&bytes)
                .map_err(|_| "Custom records must use UTF-8".to_string())
                .and_then(|line| custom::parse_line(line).map_err(|error| error.to_string()))
                .map(|record| {
                    Some(Record {
                        path: record.path().into(),
                        status: match record.status() {
                            custom::Status::Clean => Status::Clean,
                            custom::Status::Detected => Status::Detected,
                            custom::Status::Error => Status::Error,
                        },
                        detail: record.detail().into(),
                        terminal: true,
                    })
                }),
            scanner::Settings::Avast(_) => avast::batch_record(&bytes),
            scanner::Settings::Defender => Err("Defender uses individual message scans".into()),
        };
        match parsed {
            Ok(Some(record)) => self.record(record),
            Ok(None) => {}
            Err(detail) => self.warn(detail),
        }
    }

    fn finish(mut self, settings: &scanner::Settings, outcome: &transport::Outcome) -> Outcome {
        let detected = self.reports.iter().any(detection::Report::detected);
        let expected = match settings {
            scanner::Settings::Custom(settings) => {
                if detected {
                    settings.detected_code
                } else {
                    settings.clean_code
                }
            }
            scanner::Settings::Avast(_) => i32::from(detected),
            scanner::Settings::Defender => 0,
        };
        if outcome.code != Some(expected)
            || outcome.termination_requested
            || !outcome.exit_confirmed
        {
            self.warn(format!(
                "Directory scan did not establish normal completion (exit {:?})",
                outcome.code
            ));
        }
        if outcome.cancelled {
            self.diagnostics.warn(detection::Issue::Cancelled);
        }
        if outcome.timed_out {
            self.warn("Directory scan timed out");
        }
        if outcome.drain_incomplete {
            self.warn("Scanner output did not fully drain");
        }
        if let Some(failure) = &outcome.failure {
            self.warn(failure.clone());
        }
        for (index, state) in self.states.iter().enumerate() {
            if state.is_none() {
                self.reports[self.batch.files()[index].owner()].warn(detection::Issue::Scanner(
                    "No verified result was received for a required scan file".into(),
                ));
            }
        }
        for report in &mut self.reports {
            report.merge(self.diagnostics.clone());
        }
        Outcome {
            reports: self.reports,
            cleanup_safe: outcome.exit_confirmed,
        }
    }
}

/// Inspect a sealed directory; the caller retains ownership until cleanup settles.
pub(crate) async fn scan(
    engine: &Engine,
    batch: &batch::Batch,
    timeout: Duration,
    cancel: watch::Receiver<bool>,
    updates: &Updates,
) -> Outcome {
    let mut inspection = Inspection::new(batch, engine.backend(), updates);
    if batch.files().is_empty() {
        return Outcome {
            reports: inspection.reports,
            cleanup_safe: true,
        };
    }
    if *cancel.borrow() || cancel.has_changed().is_err() {
        for report in &mut inspection.reports {
            report.warn(detection::Issue::Cancelled);
        }
        return Outcome {
            reports: inspection.reports,
            cleanup_safe: true,
        };
    }
    let command = match &engine.settings {
        scanner::Settings::Avast(settings) => {
            avast::batch_command(&engine.executable, batch.directory(), settings)
        }
        scanner::Settings::Custom(settings) => {
            custom::directory_command(&engine.executable, batch.directory(), settings)
        }
        scanner::Settings::Defender => {
            inspection.warn("Defender does not support the directory strategy");
            for report in &mut inspection.reports {
                report.merge(inspection.diagnostics.clone());
            }
            return Outcome {
                reports: inspection.reports,
                cleanup_safe: true,
            };
        }
    };
    #[cfg(windows)]
    let command = {
        let mut command = command;
        command.creation_flags(0x0800_0000);
        command
    };
    let mut stdout = transport::Lines::default();
    let mut stderr = transport::Lines::default();
    let outcome = transport::run(
        command,
        cancel,
        Instant::now() + timeout,
        |stream, bytes| {
            let lines = if stream == transport::Stream::Stdout {
                &mut stdout
            } else {
                &mut stderr
            };
            lines.push(bytes, |record| {
                inspection.line(&engine.settings, stream, record)
            });
        },
    )
    .await;
    stdout.finish(|record| inspection.line(&engine.settings, transport::Stream::Stdout, record));
    stderr.finish(|record| inspection.line(&engine.settings, transport::Stream::Stderr, record));
    let outcome = match outcome {
        Ok(outcome) => outcome,
        Err(error) => transport::Outcome {
            exit_confirmed: true, // spawn failed: no scanner owns these files
            failure: Some(format!("Cannot launch directory scanner: {error}")),
            ..Default::default()
        },
    };
    if outcome.exit_confirmed {
        for file in batch.files() {
            match tokio::fs::metadata(file.path()).await {
                Ok(metadata) if metadata.is_file() && metadata.len() == file.len() => {}
                _ => inspection.reports[file.owner()].warn(detection::Issue::Input(
                    "Scanner input disappeared or changed length during inspection".into(),
                )),
            }
        }
    }
    inspection.finish(&engine.settings, &outcome)
}
#[cfg(test)]
mod tests;
