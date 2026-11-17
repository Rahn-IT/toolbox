//! Owned directory batches and exact file-to-message attribution.

use std::collections::HashMap;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use tokio::io::AsyncWriteExt;
use tokio::sync::watch;

use super::core::{detection, limits, message};
use super::scanner::mime;

const MAX_MESSAGES: usize = 10_000;
const MAX_FILES: usize = 65_536;
const FILES_PER_MESSAGE: usize = 257;
static NEXT: AtomicU64 = AtomicU64::new(0);

/// A message and its preparation result, independent of scanner completion.
#[derive(Debug)]
pub struct Message {
    identity: message::Identity,
    subject: String,
    sender: String,
    report: detection::Report,
}

/// One fully written scanner input and its owning message index.
#[derive(Debug)]
pub struct File {
    path: PathBuf,
    owner: usize,
    len: u64,
}

/// Files owned by one batch; cleanup requires confirmed scanner settlement.
#[derive(Debug)]
pub struct Batch {
    directory: PathBuf,
    messages: Vec<Message>,
    files: Vec<File>,
    owned: Vec<PathBuf>,
    index: HashMap<String, usize>,
    raw_bytes: u64,
    staged_bytes: u64,
}

/// A writable batch that cannot be dispatched until sealed.
#[derive(Debug)]
pub struct Builder {
    batch: Batch,
    target: u64,
    poisoned: bool,
}

/// A staging or sealing failure.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// The batch must be sealed before accepting another message.
    #[error("Batch reached its admission limit")]
    Full,
    /// A failed owned file could not be removed.
    #[error("Batch contains failed or unexpected files and cannot be scanned")]
    Unusable,
    /// A zero or overflowing byte target is invalid.
    #[error("Invalid batch byte target")]
    Target,
    /// Owned filesystem work failed.
    #[error("Batch file operation failed at {path}: {source}")]
    Io { path: PathBuf, source: io::Error },
    /// Two file spellings would ambiguously attribute an outcome.
    #[error("Ambiguous batch file alias: {0}")]
    Alias(String),
}

/// A failed seal retains ownership so the coordinator can report or clean files.
#[derive(Debug)]
pub struct Rejected {
    error: Error,
    batch: Box<Batch>,
}

impl Message {
    /// Stable upstream identity.
    pub fn identity(&self) -> &message::Identity {
        &self.identity
    }
    /// Bounded display subject.
    pub fn subject(&self) -> &str {
        &self.subject
    }
    /// Bounded display sender.
    pub fn sender(&self) -> &str {
        &self.sender
    }
    /// MIME or staging issues established before scanning.
    pub fn report(&self) -> &detection::Report {
        &self.report
    }
}

impl File {
    /// Exact owned input path.
    pub fn path(&self) -> &Path {
        &self.path
    }
    /// Index into the batch's messages.
    pub fn owner(&self) -> usize {
        self.owner
    }
    /// Fully written file length.
    pub fn len(&self) -> u64 {
        self.len
    }
    /// Whether this is an empty original input.
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }
}

impl Rejected {
    /// Why sealing failed.
    pub fn error(&self) -> &Error {
        &self.error
    }
    /// Consume the failure while preserving owned filesystem paths.
    pub fn into_batch(self) -> Batch {
        *self.batch
    }
}

impl Batch {
    /// Directory passed to the scanner.
    pub fn directory(&self) -> &Path {
        &self.directory
    }
    /// Every admitted message, including preparation failures.
    pub fn messages(&self) -> &[Message] {
        &self.messages
    }
    /// Only fully written, manifest-indexed scanner inputs.
    pub fn files(&self) -> &[File] {
        &self.files
    }
    /// Owned paths, including any partial write whose removal failed.
    pub fn owned_paths(&self) -> &[PathBuf] {
        &self.owned
    }
    /// Successfully staged original EML bytes.
    pub fn raw_bytes(&self) -> u64 {
        self.raw_bytes
    }
    /// Total original and decoded bytes written successfully.
    pub fn staged_bytes(&self) -> u64 {
        self.staged_bytes
    }
    /// Find an exact path or explicitly supported separator/prefix alias.
    pub fn lookup(&self, path: &str) -> Option<usize> {
        self.index.get(&key(path)).copied()
    }
    /// Remove only owned files, then the empty directory, after scanner settlement.
    pub async fn cleanup(&self) -> Vec<PathBuf> {
        let mut leftovers = Vec::new();
        for path in &self.owned {
            match tokio::fs::remove_file(path).await {
                Ok(()) => {}
                Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                Err(_) => leftovers.push(path.clone()),
            }
        }
        match tokio::fs::remove_dir(&self.directory).await {
            Ok(()) => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(_) => leftovers.push(self.directory.clone()),
        }
        leftovers
    }
}

impl Builder {
    /// Reserve a fresh directory below the caller's run directory.
    pub fn create(parent: &Path, target: u64) -> Result<Self, Error> {
        if target == 0 || target.checked_mul(2).is_none() {
            return Err(Error::Target);
        }
        let parent = std::fs::canonicalize(parent).map_err(|source| Error::Io {
            path: parent.into(),
            source,
        })?;
        let stamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        for _ in 0..128 {
            let serial = NEXT.fetch_add(1, Ordering::Relaxed);
            let directory = parent.join(format!("batch-{}-{stamp}-{serial}", std::process::id()));
            match std::fs::create_dir(&directory) {
                Ok(()) => {
                    return Ok(Self {
                        batch: Batch {
                            directory,
                            messages: Vec::new(),
                            files: Vec::new(),
                            owned: Vec::new(),
                            index: HashMap::new(),
                            raw_bytes: 0,
                            staged_bytes: 0,
                        },
                        target,
                        poisoned: false,
                    });
                }
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
                Err(source) => {
                    return Err(Error::Io {
                        path: directory,
                        source,
                    });
                }
            }
        }
        Err(Error::Io {
            path: parent,
            source: io::Error::new(
                io::ErrorKind::AlreadyExists,
                "Could not reserve a batch directory",
            ),
        })
    }

    /// No messages have been admitted, regardless of their eventual outcome.
    pub fn is_empty(&self) -> bool {
        self.batch.messages.is_empty()
    }

    /// A threshold was crossed or another whole message cannot be safely reserved.
    pub fn full(&self) -> bool {
        self.poisoned
            || self.batch.raw_bytes >= self.target
            || self.batch.staged_bytes >= self.target * 2
            || self.batch.messages.len() >= MAX_MESSAGES
            || self.batch.files.len().saturating_add(FILES_PER_MESSAGE) > MAX_FILES
    }

    /// Borrow retained ownership for diagnostics while preparation is active.
    pub fn retained(&self) -> &Batch {
        &self.batch
    }

    /// Prepare one entire message; callers must await settlement instead of dropping this future.
    pub async fn add(
        &mut self,
        identity: message::Identity,
        bytes: Vec<u8>,
        cancel: &watch::Receiver<bool>,
    ) -> Result<(), Error> {
        if self.full() {
            return Err(Error::Full);
        }
        let (subject, sender) = metadata(&bytes);
        let owner = self.batch.messages.len();
        self.batch.messages.push(Message {
            identity,
            subject,
            sender,
            report: detection::Report::new(),
        });
        if *cancel.borrow() || cancel.has_changed().is_err() {
            self.batch.messages[owner]
                .report
                .warn(detection::Issue::Cancelled);
            return Ok(());
        }
        if bytes.len() > limits::MESSAGE_BYTES {
            self.batch.messages[owner]
                .report
                .warn(detection::Issue::Limit("Original exceeds 200 MiB"));
            return Ok(());
        }
        let original = format!("m{owner:06}.eml");
        if !self.write(owner, &original, &bytes).await? {
            return Ok(());
        }
        self.batch.raw_bytes += bytes.len() as u64;
        let mut parsed = match mime::Parsed::parse(bytes).await {
            Ok(parsed) => parsed,
            Err(error) => {
                self.batch.messages[owner]
                    .report
                    .warn(detection::Issue::Decode(error.to_string()));
                return Ok(());
            }
        };
        let mut part = 0;
        loop {
            if *cancel.borrow() || cancel.has_changed().is_err() {
                self.batch.messages[owner]
                    .report
                    .warn(detection::Issue::Cancelled);
                break;
            }
            let leaf = match parsed.next().await {
                Ok(Some(leaf)) => leaf,
                Ok(None) => break,
                Err(error) => {
                    self.batch.messages[owner]
                        .report
                        .warn(detection::Issue::Decode(error.to_string()));
                    break;
                }
            };
            for issue in leaf.issues {
                self.batch.messages[owner].report.warn(issue);
            }
            if let Some(bytes) = leaf.bytes {
                let name = format!("m{owner:06}-p{part:04}.bin");
                part += 1;
                if !self.write(owner, &name, &bytes).await? {
                    break;
                }
            }
        }
        Ok(())
    }

    async fn write(&mut self, owner: usize, name: &str, bytes: &[u8]) -> Result<bool, Error> {
        let path = self.batch.directory.join(name);
        let mut file = match tokio::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
            .await
        {
            Ok(file) => file,
            Err(source) => {
                self.batch.messages[owner]
                    .report
                    .warn(detection::Issue::Input(format!(
                        "Cannot create {}: {source}",
                        path.display()
                    )));
                // A colliding entry is not owned and must not be removed.
                if source.kind() == io::ErrorKind::AlreadyExists {
                    self.poisoned = true;
                    return Err(Error::Io { path, source });
                }
                return Ok(false);
            }
        };
        self.batch.owned.push(path.clone());
        let result = async {
            file.write_all(bytes).await?;
            file.flush().await
        }
        .await;
        drop(file);
        if let Err(source) = result {
            self.batch.messages[owner]
                .report
                .warn(detection::Issue::Input(format!(
                    "Cannot stage {}: {source}",
                    path.display()
                )));
            match tokio::fs::remove_file(&path).await {
                Ok(()) => {
                    self.batch.owned.pop();
                }
                Err(error) if error.kind() == io::ErrorKind::NotFound => {
                    self.batch.owned.pop();
                }
                Err(source) => {
                    self.poisoned = true;
                    return Err(Error::Io { path, source });
                }
            }
            return Ok(false);
        }
        let file_index = self.batch.files.len();
        let mut aliases = vec![name.to_owned(), format!("./{name}")];
        if let Some(absolute) = path.to_str() {
            aliases.push(absolute.to_owned());
        }
        for alias in aliases {
            let normalized = key(&alias);
            if self
                .batch
                .index
                .insert(normalized.clone(), file_index)
                .is_some_and(|old| old != file_index)
            {
                self.poisoned = true;
                return Err(Error::Alias(normalized));
            }
        }
        self.batch.files.push(File {
            path,
            owner,
            len: bytes.len() as u64,
        });
        self.batch.staged_bytes += bytes.len() as u64;
        Ok(true)
    }

    /// Close preparation. The last nonempty batch is valid below its target.
    pub fn seal(self) -> Result<Option<Batch>, Rejected> {
        let error = if self.poisoned {
            Some(Error::Unusable)
        } else if self.is_empty() {
            return match std::fs::remove_dir(&self.batch.directory) {
                Ok(()) => Ok(None),
                Err(source) => Err(Rejected {
                    error: Error::Io {
                        path: self.batch.directory.clone(),
                        source,
                    },
                    batch: Box::new(self.batch),
                }),
            };
        } else {
            self.verify().err()
        };
        if let Some(error) = error {
            Err(Rejected {
                error,
                batch: Box::new(self.batch),
            })
        } else {
            Ok(Some(self.batch))
        }
    }

    fn verify(&self) -> Result<(), Error> {
        let entries = std::fs::read_dir(&self.batch.directory).map_err(|source| Error::Io {
            path: self.batch.directory.clone(),
            source,
        })?;
        let mut count = 0;
        for entry in entries {
            let entry = entry.map_err(|source| Error::Io {
                path: self.batch.directory.clone(),
                source,
            })?;
            let path = entry.path();
            let index = path
                .to_str()
                .and_then(|path| self.batch.lookup(path))
                .ok_or(Error::Unusable)?;
            let file = &self.batch.files[index];
            let metadata =
                std::fs::symlink_metadata(&path).map_err(|source| Error::Io { path, source })?;
            if !metadata.file_type().is_file() || metadata.len() != file.len {
                return Err(Error::Unusable);
            }
            count += 1;
        }
        if count != self.batch.files.len() {
            return Err(Error::Unusable);
        }
        Ok(())
    }
}

fn key(path: &str) -> String {
    let mut path = path.replace('\\', "/");
    if let Some(rest) = path.strip_prefix("//?/UNC/") {
        path = format!("//{rest}");
    } else if let Some(rest) = path.strip_prefix("//?/") {
        path = rest.to_owned();
    }
    if cfg!(windows) {
        path.make_ascii_lowercase();
    }
    path
}

fn metadata(bytes: &[u8]) -> (String, String) {
    match mail_parser::MessageParser::new().parse_headers(bytes) {
        Some(mail) => {
            let subject = mail
                .subject()
                .unwrap_or("(no subject)")
                .chars()
                .take(512)
                .collect();
            let sender = mail
                .from()
                .and_then(|from| from.first())
                .map(|address| match (address.name(), address.address()) {
                    (Some(name), Some(address)) => format!("{name} <{address}>"),
                    (_, Some(address)) => address.to_owned(),
                    (Some(name), _) => name.to_owned(),
                    _ => "(unknown sender)".into(),
                })
                .unwrap_or_else(|| "(unknown sender)".into());
            (subject, sender.chars().take(512).collect())
        }
        None => ("(unreadable subject)".into(), "(unknown sender)".into()),
    }
}

#[cfg(test)]
mod tests {
    use super::super::core::config;
    use super::*;
    use std::num::NonZeroU32;

    fn parent() -> PathBuf {
        let serial = NEXT.fetch_add(1, Ordering::Relaxed);
        let stamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let directory = std::env::temp_dir().join(format!(
            "toolbox-batch-test-{}-{stamp}-{serial}",
            std::process::id()
        ));
        std::fs::create_dir(&directory).unwrap();
        directory
    }

    fn identity(uid: u32) -> message::Identity {
        let settings = config::Settings::try_from(config::Draft {
            host: "example.invalid".into(),
            username: "test".into(),
            password: "test".into(),
            scan_dir: "scan".into(),
            quarantine_dir: "quarantine".into(),
            ..Default::default()
        })
        .unwrap();
        message::Identity::new(
            message::Account::from_settings(&settings),
            message::Folder::new("INBOX".into(), "INBOX".into()).unwrap(),
            NonZeroU32::new(1).unwrap(),
            NonZeroU32::new(uid).unwrap(),
        )
    }

    fn mail() -> Vec<u8> {
        b"From: test@example.invalid\r\nSubject: Batch test\r\n\r\nhello".to_vec()
    }

    #[tokio::test]
    async fn final_small_batch_keeps_original_and_decoded_inputs() {
        let parent = parent();
        let mut builder = Builder::create(&parent, 1024 * 1024 * 1024).unwrap();
        let (_sender, cancel) = watch::channel(false);
        let bytes = mail();
        let length = bytes.len();
        builder.add(identity(1), bytes, &cancel).await.unwrap();
        assert!(!builder.full());
        let batch = builder.seal().unwrap().unwrap();
        assert_eq!(batch.messages().len(), 1);
        assert_eq!(batch.raw_bytes(), length as u64);
        assert!(batch.files().len() >= 2);
        for (index, file) in batch.files().iter().enumerate() {
            assert_eq!(file.owner(), 0);
            assert_eq!(batch.lookup(file.path().to_str().unwrap()), Some(index));
            let relative = file.path().file_name().unwrap().to_str().unwrap();
            assert_eq!(batch.lookup(relative), Some(index));
            assert_eq!(batch.lookup(&format!(".\\{relative}")), Some(index));
        }
        assert_eq!(batch.lookup("foreign.eml"), None);
        assert_eq!(batch.lookup("../m000000.eml"), None);
        assert!(batch.cleanup().await.is_empty());
        std::fs::remove_dir(parent).unwrap();
    }

    #[tokio::test]
    async fn exact_and_crossed_targets_include_the_whole_message() {
        for target in [mail().len() as u64, mail().len() as u64 - 1] {
            let parent = parent();
            let mut builder = Builder::create(&parent, target).unwrap();
            let (_sender, cancel) = watch::channel(false);
            builder.add(identity(1), mail(), &cancel).await.unwrap();
            assert!(builder.full());
            assert!(matches!(
                builder.add(identity(2), mail(), &cancel).await,
                Err(Error::Full)
            ));
            let batch = builder.seal().unwrap().unwrap();
            assert_eq!(batch.raw_bytes(), mail().len() as u64);
            assert_eq!(batch.messages().len(), 1);
            assert!(batch.cleanup().await.is_empty());
            std::fs::remove_dir(parent).unwrap();
        }
    }

    #[test]
    fn empty_remainder_removes_its_directory_and_never_seals_work() {
        let parent = parent();
        let builder = Builder::create(&parent, 1024).unwrap();
        let directory = builder.retained().directory().to_owned();
        assert!(builder.seal().unwrap().is_none());
        assert!(!directory.exists());
        std::fs::remove_dir(parent).unwrap();
    }

    #[tokio::test]
    async fn foreign_files_prevent_sealing_and_are_never_cleaned() {
        let parent = parent();
        let mut builder = Builder::create(&parent, 1024 * 1024).unwrap();
        let (_sender, cancel) = watch::channel(false);
        builder.add(identity(1), mail(), &cancel).await.unwrap();
        let foreign = builder.retained().directory().join("foreign");
        std::fs::write(&foreign, b"not owned").unwrap();
        let rejected = builder.seal().unwrap_err();
        assert!(matches!(rejected.error(), Error::Unusable));
        let batch = rejected.into_batch();
        assert_eq!(batch.cleanup().await, vec![batch.directory().to_owned()]);
        assert_eq!(std::fs::read(&foreign).unwrap(), b"not owned");
        std::fs::remove_file(foreign).unwrap();
        std::fs::remove_dir(batch.directory()).unwrap();
        std::fs::remove_dir(parent).unwrap();
    }

    #[tokio::test]
    async fn colliding_original_is_not_owned_or_scanned() {
        let parent = parent();
        let mut builder = Builder::create(&parent, 1024).unwrap();
        let foreign = builder.retained().directory().join("m000000.eml");
        std::fs::write(&foreign, b"not owned").unwrap();
        let (_sender, cancel) = watch::channel(false);
        assert!(builder.add(identity(1), mail(), &cancel).await.is_err());
        assert_eq!(builder.retained().messages().len(), 1);
        assert!(!builder.retained().messages()[0].report().complete());
        let batch = builder.seal().unwrap_err().into_batch();
        assert!(batch.owned_paths().is_empty());
        assert_eq!(batch.cleanup().await, vec![batch.directory().to_owned()]);
        std::fs::remove_file(foreign).unwrap();
        std::fs::remove_dir(batch.directory()).unwrap();
        std::fs::remove_dir(parent).unwrap();
    }

    #[tokio::test]
    async fn cancellation_retains_a_terminal_preparation_issue_without_inputs() {
        let parent = parent();
        let mut builder = Builder::create(&parent, 1024).unwrap();
        let (_sender, cancel) = watch::channel(true);
        builder.add(identity(1), mail(), &cancel).await.unwrap();
        let batch = builder.seal().unwrap().unwrap();
        assert_eq!(batch.messages().len(), 1);
        assert!(!batch.messages()[0].report().complete());
        assert!(batch.files().is_empty());
        assert_eq!(batch.raw_bytes(), 0);
        assert!(batch.cleanup().await.is_empty());
        std::fs::remove_dir(parent).unwrap();
    }

    #[test]
    fn safety_caps_seal_before_another_message_can_exceed_file_budget() {
        let parent = parent();
        let mut builder = Builder::create(&parent, 1024).unwrap();
        builder.batch.staged_bytes = 2048;
        assert!(builder.full());
        builder.batch.staged_bytes = 0;
        for _ in 0..MAX_FILES - FILES_PER_MESSAGE + 1 {
            builder.batch.files.push(File {
                path: PathBuf::new(),
                owner: 0,
                len: 0,
            });
        }
        assert!(builder.full());
        builder.batch.files.clear();
        assert!(builder.seal().unwrap().is_none());
        std::fs::remove_dir(parent).unwrap();
    }

    #[test]
    fn invalid_targets_are_rejected_without_creating_directories() {
        let parent = parent();
        assert!(matches!(Builder::create(&parent, 0), Err(Error::Target)));
        assert!(matches!(
            Builder::create(&parent, u64::MAX),
            Err(Error::Target)
        ));
        assert_eq!(std::fs::read_dir(&parent).unwrap().count(), 0);
        std::fs::remove_dir(parent).unwrap();
    }

    #[tokio::test]
    async fn full_batch_followed_by_smaller_remainder_preserves_every_identity() {
        let parent = parent();
        let target = 2 * mail().len() as u64;
        let mut builder = Builder::create(&parent, target).unwrap();
        let (_sender, cancel) = watch::channel(false);
        let mut batches = Vec::new();
        for uid in 1..=3 {
            builder.add(identity(uid), mail(), &cancel).await.unwrap();
            if builder.full() {
                batches.push(builder.seal().unwrap().unwrap());
                builder = Builder::create(&parent, target).unwrap();
            }
        }
        if let Some(last) = builder.seal().unwrap() {
            batches.push(last);
        }
        assert_eq!(batches.len(), 2);
        assert_eq!(batches[0].raw_bytes(), target);
        assert!(batches[1].raw_bytes() < target);
        assert_eq!(
            batches
                .iter()
                .map(|batch| batch.messages().len())
                .collect::<Vec<_>>(),
            [2, 1]
        );
        let identities: Vec<_> = batches
            .iter()
            .flat_map(|batch| batch.messages())
            .map(|message| message.identity().uid())
            .collect();
        assert_eq!(identities, [1, 2, 3]);
        for batch in batches {
            assert!(batch.cleanup().await.is_empty());
        }
        std::fs::remove_dir(parent).unwrap();
    }

    #[tokio::test]
    async fn missing_or_truncated_original_prevents_dispatch_and_retains_ownership() {
        for remove in [false, true] {
            let parent = parent();
            let mut builder = Builder::create(&parent, 1024 * 1024).unwrap();
            let (_sender, cancel) = watch::channel(false);
            builder.add(identity(1), mail(), &cancel).await.unwrap();
            let path = builder.retained().files()[0].path().to_owned();
            if remove {
                std::fs::remove_file(&path).unwrap();
            } else {
                std::fs::write(&path, b"short").unwrap();
            }
            let retained = builder.seal().unwrap_err().into_batch();
            assert!(retained.owned_paths().contains(&path));
            assert!(retained.cleanup().await.is_empty());
            std::fs::remove_dir(parent).unwrap();
        }
    }

    #[tokio::test]
    async fn empty_original_is_a_real_scan_input_not_an_empty_batch() {
        let parent = parent();
        let mut builder = Builder::create(&parent, 1024).unwrap();
        let (_sender, cancel) = watch::channel(false);
        builder.add(identity(1), Vec::new(), &cancel).await.unwrap();
        assert!(!builder.is_empty());
        let batch = builder.seal().unwrap().unwrap();
        assert_eq!(batch.raw_bytes(), 0);
        assert_eq!(batch.files().len(), 1);
        assert!(batch.files()[0].is_empty());
        assert!(!batch.messages()[0].report().complete());
        assert!(batch.cleanup().await.is_empty());
        std::fs::remove_dir(parent).unwrap();
    }
}
