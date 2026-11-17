//! Bounded process transport; backend parsers own the meaning of output.

use std::{io, process::Stdio, time::Duration};

use tokio::{io::AsyncReadExt, process::Command, sync::watch, time::Instant};

const RECORD_LIMIT: usize = 64 * 1024;
const KILL_TIMEOUT: Duration = Duration::from_secs(5);
const DRAIN_TIMEOUT: Duration = Duration::from_secs(2);

/// The pipe which supplied a chunk or record.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Stream {
    Stdout,
    Stderr,
}

/// Process status does not imply that every input was inspected.
#[derive(Debug, Default)]
pub(super) struct Outcome {
    pub code: Option<i32>,
    pub exit_confirmed: bool,
    pub termination_requested: bool,
    pub timed_out: bool,
    pub cancelled: bool,
    pub drain_incomplete: bool,
    pub failure: Option<String>,
}

/// Run a child while servicing both pipes independently of UI delivery.
/// The synchronous callback must only update bounded local parser state.
pub(super) async fn run(
    mut command: Command,
    mut cancel: watch::Receiver<bool>,
    deadline: Instant,
    mut output: impl FnMut(Stream, &[u8]),
) -> io::Result<Outcome> {
    command
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    let mut child = command.spawn()?;
    let mut stdout = child
        .stdout
        .take()
        .expect("stdout was configured as piped before spawning");
    let mut stderr = child
        .stderr
        .take()
        .expect("stderr was configured as piped before spawning");
    let mut out_buffer = [0; 4096];
    let mut err_buffer = [0; 4096];
    let mut out_open = true;
    let mut err_open = true;
    let mut outcome = Outcome::default();
    let mut stopping_until = None;
    let mut draining_until = None;
    loop {
        if outcome.exit_confirmed && !out_open && !err_open {
            break;
        }
        let mut stop = false;
        tokio::select! {
            status = child.wait(), if !outcome.exit_confirmed => {
                match status {
                    Ok(status) => {
                        outcome.code = status.code();
                        outcome.exit_confirmed = true;
                        draining_until = Some(Instant::now() + DRAIN_TIMEOUT);
                    }
                    Err(error) => {
                        outcome.failure = Some(format!("Cannot confirm scanner termination: {error}"));
                        outcome.drain_incomplete = out_open || err_open;
                        break;
                    }
                }
            }
            result = stdout.read(&mut out_buffer), if out_open => {
                match result {
                    Ok(0) => out_open = false,
                    Ok(length) => output(Stream::Stdout, &out_buffer[..length]),
                    Err(error) => {
                        out_open = false;
                        outcome.failure = Some(format!("Scanner stdout: {error}"));
                        stop = true;
                    }
                }
            }
            result = stderr.read(&mut err_buffer), if err_open => {
                match result {
                    Ok(0) => err_open = false,
                    Ok(length) => output(Stream::Stderr, &err_buffer[..length]),
                    Err(error) => {
                        err_open = false;
                        outcome.failure = Some(format!("Scanner stderr: {error}"));
                        stop = true;
                    }
                }
            }
            _ = tokio::time::sleep_until(deadline), if !outcome.exit_confirmed && stopping_until.is_none() => {
                outcome.timed_out = true;
                stop = true;
            }
            _ = super::cancelled(&mut cancel), if !outcome.exit_confirmed && stopping_until.is_none() => {
                outcome.cancelled = true;
                stop = true;
            }
            _ = tokio::time::sleep_until(stopping_until.unwrap_or(deadline)), if !outcome.exit_confirmed && stopping_until.is_some() => {
                outcome.failure = Some("Scanner wrapper did not acknowledge termination".into());
                outcome.drain_incomplete = out_open || err_open;
                break;
            }
            _ = tokio::time::sleep_until(draining_until.unwrap_or(deadline)), if outcome.exit_confirmed => {
                outcome.drain_incomplete = out_open || err_open;
                break;
            }
        }
        if stop && !outcome.exit_confirmed && stopping_until.is_none() {
            outcome.termination_requested = true;
            if let Err(error) = child.start_kill() {
                outcome.failure = Some(format!("Cannot terminate scanner wrapper: {error}"));
            }
            stopping_until = Some(Instant::now() + KILL_TIMEOUT);
        }
    }
    Ok(outcome)
}

/// A complete line, or a record rejected without unbounded allocation.
#[derive(Debug, PartialEq, Eq)]
pub(super) enum Record {
    Line(Vec<u8>),
    Oversized,
    InvalidEncoding,
}

/// Incremental raw-line framing; UTF-16LE lines retain their BOM for decoding.
#[derive(Default)]
pub(super) struct Lines {
    prefix: Vec<u8>,
    encoding: Option<bool>,
    pending: Vec<u8>,
    low: Option<u8>,
    discarding: bool,
}

impl Lines {
    pub fn push(&mut self, bytes: &[u8], mut emit: impl FnMut(Record)) {
        for &byte in bytes {
            if self.encoding.is_none() {
                self.prefix.push(byte);
                if self.prefix == [0xff] || self.prefix == [0xef] || self.prefix == [0xef, 0xbb] {
                    continue;
                }
                if self.prefix == [0xff, 0xfe] {
                    self.encoding = Some(true);
                    self.prefix.clear();
                    continue;
                }
                self.encoding = Some(false);
                let prefix = std::mem::take(&mut self.prefix);
                if prefix != [0xef, 0xbb, 0xbf] {
                    for byte in prefix {
                        self.byte(byte, &mut emit);
                    }
                }
            } else {
                self.byte(byte, &mut emit);
            }
        }
    }

    pub fn finish(&mut self, mut emit: impl FnMut(Record)) {
        if self.encoding.is_none() {
            self.encoding = Some(false);
            for byte in std::mem::take(&mut self.prefix) {
                self.byte(byte, &mut emit);
            }
        }
        if self.low.take().is_some() {
            emit(Record::InvalidEncoding);
            self.pending.clear();
        } else if !self.discarding && !self.pending.is_empty() {
            self.line(&mut emit);
        }
        self.discarding = false;
    }

    fn byte(&mut self, byte: u8, emit: &mut impl FnMut(Record)) {
        if self.encoding == Some(true) {
            let Some(low) = self.low.take() else {
                self.low = Some(byte);
                return;
            };
            if [low, byte] == [b'\n', 0] {
                self.line(emit);
            } else {
                self.append(&[low, byte], emit);
            }
        } else if byte == b'\n' {
            self.line(emit);
        } else {
            self.append(&[byte], emit);
        }
    }

    fn append(&mut self, bytes: &[u8], emit: &mut impl FnMut(Record)) {
        if self.discarding {
            return;
        }
        if self.pending.len() + bytes.len() > RECORD_LIMIT {
            self.pending.clear();
            self.discarding = true;
            emit(Record::Oversized);
        } else {
            self.pending.extend_from_slice(bytes);
        }
    }

    fn line(&mut self, emit: &mut impl FnMut(Record)) {
        if self.discarding {
            self.discarding = false;
            return;
        }
        let mut line = std::mem::take(&mut self.pending);
        if self.encoding == Some(true) {
            if line.ends_with(&[b'\r', 0]) {
                line.truncate(line.len() - 2);
            }
            let mut prefixed = vec![0xff, 0xfe];
            prefixed.extend(line);
            emit(Record::Line(prefixed));
        } else {
            if line.last() == Some(&b'\r') {
                line.pop();
            }
            emit(Record::Line(line));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frames_split_encodings_crlf_and_eof() {
        for encoded in [b"\xef\xbb\xbfhello\r\nworld".to_vec(), {
            let mut bytes = vec![0xff, 0xfe];
            bytes.extend("hello\r\nworld".encode_utf16().flat_map(u16::to_le_bytes));
            bytes
        }] {
            for width in 1..=encoded.len() {
                let mut lines = Lines::default();
                let mut records = Vec::new();
                for chunk in encoded.chunks(width) {
                    lines.push(chunk, |record| records.push(record));
                }
                lines.finish(|record| records.push(record));
                let decoded = records
                    .into_iter()
                    .map(|record| match record {
                        Record::Line(bytes) => super::super::classify::decode(&bytes).unwrap(),
                        _ => panic!("valid record rejected"),
                    })
                    .collect::<Vec<_>>();
                assert_eq!(decoded, ["hello", "world"]);
            }
        }
    }

    #[test]
    fn oversized_line_is_discarded_then_framing_recovers() {
        let mut lines = Lines::default();
        let mut records = Vec::new();
        lines.push(&vec![b'x'; RECORD_LIMIT * 2], |record| records.push(record));
        assert!(lines.pending.is_empty());
        lines.push(b"\nnext\n", |record| records.push(record));
        lines.finish(|record| records.push(record));
        assert_eq!(records, [Record::Oversized, Record::Line(b"next".to_vec())]);
    }

    #[test]
    fn odd_utf16_tail_is_not_a_complete_record() {
        let mut lines = Lines::default();
        let mut records = Vec::new();
        lines.push(&[0xff, 0xfe, b'a'], |record| records.push(record));
        lines.finish(|record| records.push(record));
        assert_eq!(records, [Record::InvalidEncoding]);
    }
}
