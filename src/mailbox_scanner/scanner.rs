//! Direct, bounded execution of the two supported installed antivirus CLIs.

mod classify;
mod mime;

use std::io;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::Duration;

use tokio::io::AsyncReadExt;
use tokio::process::Command;
use tokio::sync::{mpsc, watch};
use tokio::time::Instant;

use crate::mailbox_scanner::core::{config, detection, scanner};

const OUTPUT_LIMIT: usize = 64 * 1024;
const COMMAND_TIMEOUT: Duration = Duration::from_secs(120);
const MESSAGE_TIMEOUT: Duration = Duration::from_secs(300);
const DRAIN_TIMEOUT: Duration = Duration::from_secs(2);

/// A selected installed command-line engine. The backend set is deliberately closed.
#[derive(Clone)]
pub struct Engine {
    backend: scanner::Backend,
    executable: PathBuf,
}

/// Failures before a scan report can be established.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("Selected scanner is unavailable on this platform")]
    Platform,
    #[error("Scanner executable not found: {0}")]
    Executable(PathBuf),
    #[error("Scanner I/O failed: {0}")]
    Io(#[from] io::Error),
}

enum Output {
    Stdout(Vec<u8>),
    Stderr(Vec<u8>),
    Failed(String),
}

impl Engine {
    /// Resolve an explicit executable override or the engine's standard installation.
    pub fn resolve(settings: &config::Settings) -> Result<Self, Error> {
        if !cfg!(windows) {
            return Err(Error::Platform);
        }
        let executable = if let Some(path) = settings.executable() {
            path.to_path_buf()
        } else {
            match settings.backend() {
                scanner::Backend::Avast => program_files()
                    .join("AVAST Software")
                    .join("Avast")
                    .join("ashCmd.exe"),
                scanner::Backend::Defender => defender_executable(),
            }
        };
        if !executable.is_file() {
            return Err(Error::Executable(executable));
        }
        Ok(Self {
            backend: settings.backend(),
            executable: executable.canonicalize()?,
        })
    }

    /// The selected closed backend.
    pub fn backend(&self) -> scanner::Backend {
        self.backend
    }

    /// The resolved executable path.
    pub fn executable(&self) -> &Path {
        &self.executable
    }

    /// Scan an original EML and prefixed decoded parts, tracking files created for cleanup.
    pub async fn scan(
        &self,
        eml: &Path,
        files: &mut Vec<PathBuf>,
        cancel: watch::Receiver<bool>,
    ) -> Result<detection::Report, Error> {
        let mut report = detection::Report::new();
        if *cancel.borrow() || cancel.has_changed().is_err() {
            report.warn(detection::Issue::Cancelled);
            return Ok(report);
        }
        let eml = tokio::fs::canonicalize(eml).await?;
        let metadata = tokio::fs::metadata(&eml).await?;
        if !metadata.is_file() || metadata.len() > mime::MAX_ORIGINAL as u64 {
            report.warn(detection::Issue::Limit(
                "Original message exceeds 200 MiB or is not a regular file",
            ));
            return Ok(report);
        }
        let file = tokio::fs::File::open(&eml).await?;
        let mut raw = Vec::with_capacity(metadata.len() as usize);
        file.take(mime::MAX_ORIGINAL as u64 + 1)
            .read_to_end(&mut raw)
            .await?;
        if raw.len() > mime::MAX_ORIGINAL || raw.len() as u64 != metadata.len() {
            report.warn(detection::Issue::Input(
                "Message changed while reading for scanning".into(),
            ));
            return Ok(report);
        }
        let deadline = Instant::now() + MESSAGE_TIMEOUT;
        report.merge(self.file(&eml, cancel.clone(), deadline).await);
        if stopped(&cancel, deadline) {
            report.warn(detection::Issue::Cancelled);
            return Ok(report);
        }
        let mut parsed = match mime::Parsed::parse(raw).await {
            Ok(parsed) => parsed,
            Err(error) => {
                report.warn(detection::Issue::Decode(error.to_string()));
                return Ok(report);
            }
        };
        let mut index = 0_u32;
        loop {
            if stopped(&cancel, deadline) {
                report.warn(detection::Issue::Scanner(
                    "MIME scan stopped or reached its orchestration deadline".into(),
                ));
                break;
            }
            let leaf = match parsed.next().await {
                Ok(Some(leaf)) => leaf,
                Ok(None) => break,
                Err(error) => {
                    report.warn(detection::Issue::Decode(error.to_string()));
                    break;
                }
            };
            for issue in leaf.issues {
                report.warn(issue);
            }
            if stopped(&cancel, deadline) {
                report.warn(detection::Issue::Cancelled);
                break;
            }
            let Some(bytes) = leaf.bytes else { continue };
            index += 1;
            let path = eml.with_extension(format!("{index}.bin"));
            let mut file = match tokio::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&path)
                .await
            {
                Ok(file) => file,
                Err(error) => {
                    report.warn(detection::Issue::Input(format!(
                        "Cannot create MIME scan file {}: {error}",
                        path.display()
                    )));
                    break;
                }
            };
            files.push(path.clone());
            let write = async {
                use tokio::io::AsyncWriteExt;
                file.write_all(&bytes).await?;
                file.flush().await
            }
            .await;
            drop(file);
            match write {
                Ok(()) => report.merge(self.file(&path, cancel.clone(), deadline).await),
                Err(error) => report.warn(detection::Issue::Input(format!(
                    "Cannot prepare MIME scan file {}: {error}",
                    path.display()
                ))),
            }
            match tokio::fs::remove_file(&path).await {
                Ok(()) => {}
                Err(error) if error.kind() == io::ErrorKind::NotFound => {
                    report.warn(detection::Issue::Input(format!(
                        "MIME scan file disappeared: {}",
                        path.display()
                    )));
                }
                Err(error) => {
                    report.warn(detection::Issue::Input(format!(
                        "Temporary file could not be removed: {}: {error}",
                        path.display()
                    )));
                    break;
                }
            }
        }
        Ok(report)
    }

    async fn file(
        &self,
        path: &Path,
        cancel: watch::Receiver<bool>,
        deadline: Instant,
    ) -> detection::Report {
        let before = tokio::fs::metadata(path)
            .await
            .map(|metadata| metadata.len());
        let mut report = match supervise(
            self.command(path),
            cancel,
            deadline.min(Instant::now() + COMMAND_TIMEOUT),
        )
        .await
        {
            Ok(capture) => classify::report(self.backend, path, capture),
            Err(error) => {
                let mut report = detection::Report::new();
                report.warn(detection::Issue::Scanner(format!(
                    "Cannot start scanner: {error}"
                )));
                report
            }
        };
        let after = tokio::fs::metadata(path)
            .await
            .map(|metadata| metadata.len());
        match (before, after) {
            (Ok(before), Ok(after)) if before == after => {}
            _ => report.warn(detection::Issue::Input(format!(
                "Scanner input disappeared, became inaccessible or changed length: {}",
                path.display()
            ))),
        }
        report
    }

    fn command(&self, path: &Path) -> Command {
        let mut command = Command::new(&self.executable);
        match self.backend {
            scanner::Backend::Avast => {
                command
                    .arg(path)
                    .args(["/_", "/a", "/c", "/t=A", "/p=4", "/s"]);
            }
            scanner::Backend::Defender => {
                command
                    .args(["-Scan", "-ScanType", "3", "-File"])
                    .arg(path)
                    .arg("-DisableRemediation");
            }
        }
        #[cfg(windows)]
        command.creation_flags(0x0800_0000);
        command
    }
}

fn program_files() -> PathBuf {
    std::env::var_os("ProgramFiles")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(r"C:\Program Files"))
}

fn defender_executable() -> PathBuf {
    let base = std::env::var_os("ProgramData")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(r"C:\ProgramData"))
        .join("Microsoft")
        .join("Windows Defender")
        .join("Platform");
    let mut candidates = Vec::new();
    if let Ok(entries) = std::fs::read_dir(base) {
        for entry in entries.flatten() {
            let path = entry.path().join("MpCmdRun.exe");
            if !path.is_file() {
                continue;
            }
            let name = entry.file_name();
            if let Some(version) = name.to_str().and_then(version) {
                candidates.push((version, path));
            }
        }
    }
    candidates.sort_by(|left, right| left.0.cmp(&right.0));
    candidates.pop().map(|(_, path)| path).unwrap_or_else(|| {
        program_files()
            .join("Windows Defender")
            .join("MpCmdRun.exe")
    })
}

fn version(name: &str) -> Option<Vec<u32>> {
    name.split(['.', '-'])
        .map(str::parse)
        .collect::<Result<Vec<_>, _>>()
        .ok()
}

fn stopped(cancel: &watch::Receiver<bool>, deadline: Instant) -> bool {
    *cancel.borrow() || cancel.has_changed().is_err() || Instant::now() >= deadline
}

async fn cancelled(cancel: &mut watch::Receiver<bool>) {
    loop {
        if *cancel.borrow_and_update() {
            return;
        }
        if cancel.changed().await.is_err() {
            return;
        }
    }
}

async fn pipe<R: tokio::io::AsyncRead + Unpin>(
    mut reader: R,
    sender: mpsc::Sender<Output>,
    stdout: bool,
) {
    let mut buffer = [0_u8; 4096];
    loop {
        match reader.read(&mut buffer).await {
            Ok(0) => break,
            Ok(length) => {
                let bytes = buffer[..length].to_vec();
                let output = if stdout {
                    Output::Stdout(bytes)
                } else {
                    Output::Stderr(bytes)
                };
                if sender.send(output).await.is_err() {
                    break;
                }
            }
            Err(error) => {
                let _ = sender.send(Output::Failed(error.to_string())).await;
                break;
            }
        }
    }
}

async fn supervise(
    mut command: Command,
    mut cancel: watch::Receiver<bool>,
    deadline: Instant,
) -> io::Result<classify::Capture> {
    command
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    let mut child = command.spawn()?;
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| io::Error::other("Missing scanner stdout pipe"))?;
    let stderr = child
        .stderr
        .take()
        .ok_or_else(|| io::Error::other("Missing scanner stderr pipe"))?;
    let (sender, mut receiver) = mpsc::channel(16);
    let out = tokio::spawn(pipe(stdout, sender.clone(), true));
    let err = tokio::spawn(pipe(stderr, sender, false));
    let mut capture = classify::Capture::default();
    let mut exited = false;
    let mut pipes_open = true;
    let mut draining_until = deadline;
    loop {
        if exited && !pipes_open {
            break;
        }
        let mut stop = false;
        tokio::select! {
            status = child.wait(), if !exited => {
                match status {
                    Ok(status) => capture.code = status.code(),
                    Err(error) => capture.failure = Some(error.to_string()),
                }
                exited = true;
                draining_until = Instant::now() + DRAIN_TIMEOUT;
            },
            output = receiver.recv(), if pipes_open => match output {
                Some(Output::Stdout(bytes)) => stop = append(&mut capture.stdout, &bytes),
                Some(Output::Stderr(bytes)) => stop = append(&mut capture.stderr, &bytes),
                Some(Output::Failed(error)) => { capture.failure = Some(error); stop = true; },
                None => pipes_open = false,
            },
            _ = tokio::time::sleep_until(deadline), if !exited => {
                capture.timed_out = true;
                stop = true;
            },
            _ = cancelled(&mut cancel), if !exited => {
                capture.cancelled = true;
                stop = true;
            },
            _ = tokio::time::sleep_until(draining_until), if exited => {
                capture.truncated = true;
                break;
            },
        }
        if stop && !exited {
            capture.truncated |=
                capture.stdout.len() == OUTPUT_LIMIT || capture.stderr.len() == OUTPUT_LIMIT;
            if let Err(error) = child.start_kill() {
                capture.failure = Some(format!("Cannot terminate scanner wrapper: {error}"));
            }
            match tokio::time::timeout(Duration::from_secs(5), child.wait()).await {
                Ok(Ok(status)) => capture.code = status.code(),
                Ok(Err(error)) => capture.failure = Some(error.to_string()),
                Err(_) => {
                    capture.failure = Some("Scanner wrapper did not acknowledge termination".into())
                }
            }
            exited = true;
            draining_until = Instant::now() + DRAIN_TIMEOUT;
        } else if stop {
            capture.truncated = true;
        }
    }
    out.abort();
    err.abort();
    let _ = out.await;
    let _ = err.await;
    Ok(capture)
}

fn append(target: &mut Vec<u8>, bytes: &[u8]) -> bool {
    let available = OUTPUT_LIMIT.saturating_sub(target.len());
    target.extend_from_slice(&bytes[..bytes.len().min(available)]);
    bytes.len() > available
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn versions_are_sorted_numerically() {
        assert!(version("4.18.10.0-0") > version("4.18.9.0-0"));
        assert_eq!(version("CurrentVersion"), None);
    }

    #[test]
    fn commands_keep_the_input_path_as_one_argument() {
        let path = Path::new("C:/scan folder/mail & example.eml");
        for backend in [scanner::Backend::Avast, scanner::Backend::Defender] {
            let engine = Engine {
                backend,
                executable: PathBuf::from("scanner.exe"),
            };
            let command = engine.command(path);
            let args = command.as_std().get_args().collect::<Vec<_>>();
            assert_eq!(
                args.iter().filter(|arg| **arg == path.as_os_str()).count(),
                1
            );
            if backend == scanner::Backend::Defender {
                assert!(args.contains(&std::ffi::OsStr::new("-DisableRemediation")));
            } else {
                assert!(args.contains(&std::ffi::OsStr::new("/p=4")));
            }
        }
    }

    #[test]
    fn child_fixture() {
        match std::env::var("MAILBOX_SCANNER_FIXTURE").as_deref() {
            Ok("output") => {
                use std::io::Write;
                let bytes = vec![b'x'; OUTPUT_LIMIT * 2];
                let thread = std::thread::spawn(move || {
                    let _ = io::stderr().write_all(&bytes);
                });
                let _ = io::stdout().write_all(&vec![b'y'; OUTPUT_LIMIT * 2]);
                let _ = thread.join();
            }
            Ok("sleep") => std::thread::sleep(Duration::from_secs(30)),
            _ => {}
        }
    }

    fn fixture(mode: &str) -> Command {
        let mut command = Command::new(std::env::current_exe().unwrap());
        command
            .args([
                "--exact",
                "mailbox_scanner::scanner::tests::child_fixture",
                "--nocapture",
            ])
            .env("MAILBOX_SCANNER_FIXTURE", mode);
        command
    }

    #[tokio::test]
    async fn output_on_both_pipes_is_bounded_without_deadlock() {
        let (_sender, receiver) = watch::channel(false);
        let capture = supervise(
            fixture("output"),
            receiver,
            Instant::now() + Duration::from_secs(10),
        )
        .await
        .unwrap();
        assert!(capture.truncated);
        assert!(capture.stdout.len() <= OUTPUT_LIMIT);
        assert!(capture.stderr.len() <= OUTPUT_LIMIT);
    }

    #[tokio::test]
    async fn cancellation_stops_the_owned_wrapper() {
        let (sender, receiver) = watch::channel(false);
        let task = tokio::spawn(supervise(
            fixture("sleep"),
            receiver,
            Instant::now() + Duration::from_secs(20),
        ));
        tokio::time::sleep(Duration::from_millis(50)).await;
        sender.send(true).unwrap();
        let capture = tokio::time::timeout(Duration::from_secs(8), task)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        assert!(capture.cancelled);
    }

    #[tokio::test]
    async fn a_process_deadline_is_reported_as_incomplete() {
        let (_sender, receiver) = watch::channel(false);
        let capture = supervise(
            fixture("sleep"),
            receiver,
            Instant::now() + Duration::from_millis(50),
        )
        .await
        .unwrap();
        assert!(capture.timed_out);
    }

    #[cfg(windows)]
    #[tokio::test]
    #[ignore = "Runs installed Defender on harmless EICAR MIME and may trigger real-time quarantine"]
    async fn defender_eicar_mime_integration() {
        let stamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let work = std::env::current_dir()
            .unwrap()
            .join("target")
            .join(format!("scanner-eicar-{}-{stamp}", std::process::id()));
        std::fs::create_dir(&work).unwrap();
        let cleanup = LiveDirectory(work.clone());
        let settings = config::Settings::try_from(config::Draft {
            host: "unused.invalid".into(),
            username: "unused".into(),
            password: "unused".into(),
            scan_dir: work.clone(),
            quarantine_dir: work.clone(),
            backend: scanner::Backend::Defender,
            ..config::Draft::default()
        })
        .unwrap();
        let engine = Engine::resolve(&settings).unwrap();
        // Assemble the standardized harmless signature only when this ignored test runs.
        let signature = [
            &b"X5O!P%@AP[4"[..],
            &b"\\PZX54(P^)7CC)7}$"[..],
            &b"EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"[..],
        ]
        .concat();
        assert_eq!(signature.len(), 68);
        let encoded = test_base64(&signature);
        let path = work.join("message.eml");
        let mail = format!(
            "From: Scanner test <scanner@example.test>\r\nTo: Scanner test <scanner@example.test>\r\nSubject: Harmless EICAR scanner integration\r\nMIME-Version: 1.0\r\nContent-Type: multipart/mixed; boundary=mailbox-eicar-test\r\n\r\n--mailbox-eicar-test\r\nContent-Type: text/plain\r\n\r\nHarmless antivirus integration test.\r\n--mailbox-eicar-test\r\nContent-Type: application/octet-stream; name=eicar.txt\r\nContent-Disposition: attachment; filename=eicar.txt\r\nContent-Transfer-Encoding: base64\r\n\r\n{encoded}\r\n--mailbox-eicar-test--\r\n"
        );
        eprintln!("Engine: {}", engine.executable().display());
        match std::fs::write(&path, mail) {
            Ok(()) => {
                let (_sender, cancel) = watch::channel(false);
                match std::fs::canonicalize(&path) {
                    Ok(path) => {
                        let capture = supervise(
                            engine.command(&path),
                            cancel.clone(),
                            Instant::now() + COMMAND_TIMEOUT,
                        )
                        .await
                        .unwrap();
                        eprintln!("Original EML CLI exit: {:?}", capture.code);
                        eprintln!("stdout:\n{}", String::from_utf8_lossy(&capture.stdout));
                        eprintln!("stderr:\n{}", String::from_utf8_lossy(&capture.stderr));
                        let direct = classify::report(scanner::Backend::Defender, &path, capture);
                        eprintln!(
                            "Original EML detected={}, complete={}, issues={:?}",
                            direct.detected(),
                            direct.complete(),
                            direct.issues()
                        );
                        let positive = work.join("positive.bin");
                        match std::fs::write(&positive, &signature) {
                            Ok(()) => {
                                let positive = std::fs::canonicalize(&positive).unwrap();
                                let capture = supervise(
                                    engine.command(&positive),
                                    cancel.clone(),
                                    Instant::now() + COMMAND_TIMEOUT,
                                )
                                .await
                                .unwrap();
                                eprintln!(
                                    "Decoded test leaf exit: {:?}\nstdout:\n{}\nstderr:\n{}",
                                    capture.code,
                                    String::from_utf8_lossy(&capture.stdout),
                                    String::from_utf8_lossy(&capture.stderr)
                                );
                                let report = classify::report(
                                    scanner::Backend::Defender,
                                    &positive,
                                    capture,
                                );
                                eprintln!(
                                    "Decoded test leaf detected={}, complete={}, evidence={:?}, issues={:?}",
                                    report.detected(),
                                    report.complete(),
                                    report.evidence(),
                                    report.issues()
                                );
                                assert!(
                                    report.detected() || !report.complete(),
                                    "Known test material must not be reported as a complete no-detection scan"
                                );
                                if let Err(error) = std::fs::remove_file(&positive) {
                                    eprintln!(
                                        "Decoded test leaf cleanup {}: {error}",
                                        positive.display()
                                    );
                                }
                            }
                            Err(error) => eprintln!(
                                "Decoded test leaf write blocked: {error}; direct positive integration remains unverified"
                            ),
                        }
                        match engine.scan(&path, &mut Vec::new(), cancel).await {
                            Ok(report) => {
                                eprintln!(
                                    "Full MIME pipeline detected={}, complete={}, evidence={:?}, issues={:?}",
                                    report.detected(),
                                    report.complete(),
                                    report.evidence(),
                                    report.issues()
                                );
                                assert!(
                                    report.detected() || !report.complete(),
                                    "Known test material must not be reported as a complete no-detection scan"
                                );
                            }
                            Err(error) => eprintln!(
                                "Full MIME pipeline blocked before a report: {error}; positive integration remains unverified"
                            ),
                        }
                    }
                    Err(error) => eprintln!(
                        "EML intercepted before CLI access: {error}; positive integration remains unverified"
                    ),
                }
            }
            Err(error) => {
                eprintln!("EML write blocked: {error}; positive integration remains unverified")
            }
        }
        drop(cleanup);
    }

    #[cfg(windows)]
    struct LiveDirectory(PathBuf);

    #[cfg(windows)]
    impl Drop for LiveDirectory {
        fn drop(&mut self) {
            if let Ok(entries) = std::fs::read_dir(&self.0) {
                for entry in entries.flatten() {
                    if let Err(error) = std::fs::remove_file(entry.path()) {
                        eprintln!("Test leftover {}: {error}", entry.path().display());
                    }
                }
            }
            if let Err(error) = std::fs::remove_dir(&self.0) {
                eprintln!("Test directory leftover {}: {error}", self.0.display());
            }
        }
    }

    #[cfg(windows)]
    fn test_base64(bytes: &[u8]) -> String {
        const ALPHABET: &[u8; 64] =
            b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let mut encoded = String::new();
        for chunk in bytes.chunks(3) {
            let value = ((chunk[0] as u32) << 16)
                | ((chunk.get(1).copied().unwrap_or(0) as u32) << 8)
                | chunk.get(2).copied().unwrap_or(0) as u32;
            for index in 0..4 {
                encoded.push(if index > chunk.len() {
                    '='
                } else {
                    ALPHABET[((value >> (18 - index * 6)) & 63) as usize] as char
                });
            }
        }
        encoded
            .as_bytes()
            .chunks(76)
            .map(|line| std::str::from_utf8(line).expect("base64 alphabet is ASCII"))
            .collect::<Vec<_>>()
            .join("\r\n")
    }
}
