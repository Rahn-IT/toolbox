//! Durable local message copies, kept independently of upstream deletion.

use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
    time::{SystemTime, UNIX_EPOCH},
};

use crate::mailbox_scanner::core::detection;

const MAX_MESSAGE: usize = crate::mailbox_scanner::core::limits::MESSAGE_BYTES;
static NEXT: AtomicU64 = AtomicU64::new(0);

/// Failures to preserve or verify a local copy.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("Cannot access quarantine file {path}: {source}")]
    Io {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("Quarantine copy is missing or changed: {0}")]
    Changed(PathBuf),
    #[error("Quarantine save did not complete; a partial file may remain at {path}: {source}")]
    Incomplete {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("Quarantine path is not a regular file: {0}")]
    NotFile(PathBuf),
    #[error("Message exceeds the 200 MiB limit")]
    Limit,
    #[error("Could not reserve a unique quarantine filename")]
    Collision,
}

pub(crate) struct Store {
    directory: PathBuf,
}

pub(crate) struct Verified {
    saved: detection::Saved,
    expected: Vec<u8>,
}

impl Store {
    pub(crate) fn open(directory: &Path) -> Result<Self, Error> {
        fs::create_dir_all(directory).map_err(|source| io(directory, source))?;
        let directory = fs::canonicalize(directory).map_err(|source| io(directory, source))?;
        Ok(Self { directory })
    }

    pub(crate) fn save(&self, bytes: Vec<u8>) -> Result<Verified, Error> {
        if bytes.len() > MAX_MESSAGE {
            return Err(Error::Limit);
        }
        let stamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        for _ in 0..128 {
            let number = NEXT.fetch_add(1, Ordering::Relaxed);
            let path = self
                .directory
                .join(format!("{}-{stamp}-{number}.eml", std::process::id()));
            let mut file = match OpenOptions::new().write(true).create_new(true).open(&path) {
                Ok(file) => file,
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(source) => return Err(io(&path, source)),
            };
            file.write_all(&bytes)
                .and_then(|()| file.sync_all())
                .map_err(|source| Error::Incomplete {
                    path: path.clone(),
                    source,
                })?;
            drop(file);
            let verified = Verified {
                saved: detection::Saved::new(path, bytes.len() as u64),
                expected: bytes,
            };
            verified.recheck()?;
            return Ok(verified);
        }
        Err(Error::Collision)
    }
}

impl Verified {
    pub(crate) fn saved(&self) -> &detection::Saved {
        &self.saved
    }

    pub(crate) fn recheck(&self) -> Result<(), Error> {
        let path = self.saved.path();
        let mut file = open_file(path)?;
        if file.metadata().map_err(|source| io(path, source))?.len() != self.expected.len() as u64 {
            return Err(Error::Changed(path.into()));
        }
        let mut block = [0u8; 16 * 1024];
        let mut offset = 0;
        loop {
            let read = match file.read(&mut block) {
                Ok(read) => read,
                Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(source) => return Err(io(path, source)),
            };
            if read == 0 {
                break;
            }
            if self.expected.get(offset..offset + read) != Some(&block[..read]) {
                return Err(Error::Changed(path.into()));
            }
            offset += read;
        }
        if offset != self.expected.len() {
            return Err(Error::Changed(path.into()));
        }
        Ok(())
    }
}

/// Recheck availability and length, without asserting later content integrity.
pub fn check(saved: &detection::Saved) -> detection::Availability {
    if saved.expected_len() > MAX_MESSAGE as u64 {
        return detection::Availability::Unreadable(
            "Saved length exceeds the 200 MiB limit".into(),
        );
    }
    let mut file = match open_file(saved.path()) {
        Ok(file) => file,
        Err(Error::Io { source, .. }) if source.kind() == std::io::ErrorKind::NotFound => {
            return detection::Availability::Missing;
        }
        Err(error) => return detection::Availability::Unreadable(error.to_string()),
    };
    match file.metadata() {
        Ok(metadata) if metadata.len() != saved.expected_len() => {
            return detection::Availability::SizeChanged {
                actual: metadata.len(),
            };
        }
        Err(error) => return detection::Availability::Unreadable(error.to_string()),
        _ => {}
    }
    let mut block = [0u8; 16 * 1024];
    let mut length = 0u64;
    loop {
        match file.read(&mut block) {
            Ok(0) => break,
            Ok(count) => {
                length += count as u64;
                if length > saved.expected_len() {
                    return detection::Availability::SizeChanged { actual: length };
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(error) => return detection::Availability::Unreadable(error.to_string()),
        }
    }
    if length != saved.expected_len() {
        detection::Availability::SizeChanged { actual: length }
    } else {
        detection::Availability::Available
    }
}

fn open_file(path: &Path) -> Result<File, Error> {
    let metadata = fs::symlink_metadata(path).map_err(|source| io(path, source))?;
    if !metadata.file_type().is_file() {
        return Err(Error::NotFile(path.into()));
    }
    File::open(path).map_err(|source| io(path, source))
}

fn io(path: &Path, source: std::io::Error) -> Error {
    Error::Io {
        path: path.into(),
        source,
    }
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::PathBuf;
    use std::sync::atomic::Ordering;

    use super::{Error, MAX_MESSAGE, NEXT, Store, check};
    use crate::mailbox_scanner::core::detection;

    fn directory() -> PathBuf {
        let path = std::env::temp_dir().join(format!(
            "mailbox-quarantine-test-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&path).unwrap();
        path
    }

    #[test]
    fn copy_is_verified_and_later_removal_is_reported() {
        let directory = directory();
        let store = Store::open(&directory).unwrap();
        let copy = store
            .save(b"From: a@example.org\r\n\r\nhello".to_vec())
            .unwrap();
        assert!(matches!(
            check(copy.saved()),
            detection::Availability::Available
        ));
        fs::remove_file(copy.saved().path()).unwrap();
        assert!(copy.recheck().is_err());
        assert!(matches!(
            check(copy.saved()),
            detection::Availability::Missing
        ));
        fs::remove_dir(directory).unwrap();
    }

    #[test]
    fn fresh_verification_detects_same_length_changes() {
        let directory = directory();
        let store = Store::open(&directory).unwrap();
        let copy = store.save(b"original".to_vec()).unwrap();
        fs::write(copy.saved().path(), b"modified").unwrap();
        assert!(copy.recheck().is_err());
        assert!(matches!(
            check(copy.saved()),
            detection::Availability::Available
        ));
        fs::remove_file(copy.saved().path()).unwrap();
        fs::remove_dir(directory).unwrap();
    }

    #[test]
    fn repeated_downloads_never_overwrite_a_previous_copy() {
        let directory = directory();
        let store = Store::open(&directory).unwrap();
        let first = store.save(b"first message".to_vec()).unwrap();
        let second = store.save(b"second message".to_vec()).unwrap();
        assert_ne!(first.saved().path(), second.saved().path());
        assert_eq!(fs::read(first.saved().path()).unwrap(), b"first message");
        assert_eq!(fs::read(second.saved().path()).unwrap(), b"second message");
        fs::remove_file(first.saved().path()).unwrap();
        fs::remove_file(second.saved().path()).unwrap();
        fs::remove_dir(directory).unwrap();
    }

    #[test]
    fn changed_length_is_not_reported_as_available() {
        let directory = directory();
        let store = Store::open(&directory).unwrap();
        let copy = store.save(b"original".to_vec()).unwrap();
        fs::write(copy.saved().path(), b"short").unwrap();
        assert!(matches!(copy.recheck(), Err(Error::Changed(_))));
        assert_eq!(
            check(copy.saved()),
            detection::Availability::SizeChanged { actual: 5 }
        );
        fs::remove_file(copy.saved().path()).unwrap();
        fs::remove_dir(directory).unwrap();
    }

    #[test]
    fn oversized_messages_create_no_partial_output() {
        let directory = directory();
        let store = Store::open(&directory).unwrap();
        assert!(matches!(
            store.save(vec![0; MAX_MESSAGE + 1]),
            Err(Error::Limit)
        ));
        assert_eq!(fs::read_dir(&directory).unwrap().count(), 0);
        fs::remove_dir(directory).unwrap();
    }

    #[test]
    fn a_directory_replacing_the_saved_path_is_not_available() {
        let directory = directory();
        let store = Store::open(&directory).unwrap();
        let copy = store.save(b"message".to_vec()).unwrap();
        fs::remove_file(copy.saved().path()).unwrap();
        fs::create_dir(copy.saved().path()).unwrap();
        assert!(matches!(copy.recheck(), Err(Error::NotFile(_))));
        assert!(matches!(
            check(copy.saved()),
            detection::Availability::Unreadable(_)
        ));
        fs::remove_dir(copy.saved().path()).unwrap();
        fs::remove_dir(directory).unwrap();
    }
}
