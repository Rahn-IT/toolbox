//! Conservative cleanup of regular files directly inside the temporary folder.

use std::{
    fs,
    path::Path,
    time::{Duration, SystemTime},
};

const MIN_AGE: Duration = Duration::from_secs(7 * 24 * 60 * 60);

pub(super) fn run() -> Result<String, String> {
    clean(&std::env::temp_dir(), SystemTime::now()).map_err(|error| error.to_string())
}

fn clean(root: &Path, now: SystemTime) -> Result<String, std::io::Error> {
    let metadata = fs::symlink_metadata(root)?;
    if !root.is_absolute() || root.parent().is_none() || !metadata.is_dir() || is_link(&metadata) {
        return Err(std::io::Error::other(
            "Temporary folder must be an absolute, non-root directory without a link or reparse point.",
        ));
    }
    let mut deleted = 0_u64;
    let mut skipped = 0_u64;
    let mut bytes = 0_u64;
    // Do not recurse: temporary subfolders can contain live application data.
    for entry in fs::read_dir(root)? {
        let result = entry.and_then(|entry| {
            let path = entry.path();
            let metadata = fs::symlink_metadata(&path)?;
            if !metadata.is_file()
                || is_link(&metadata)
                || now.duration_since(metadata.modified()?).unwrap_or_default() < MIN_AGE
            {
                return Ok(None);
            }
            fs::remove_file(path)?;
            Ok(Some(metadata.len()))
        });
        match result {
            Ok(Some(size)) => {
                deleted += 1;
                bytes += size;
            }
            Ok(None) | Err(_) => skipped += 1,
        }
    }
    Ok(format!(
        "Deleted {deleted} files ({bytes} bytes); skipped {skipped} entries. Folder: {}",
        root.display()
    ))
}

fn is_link(metadata: &fs::Metadata) -> bool {
    use std::os::windows::fs::MetadataExt;
    const REPARSE_POINT: u32 = 0x400;
    metadata.file_attributes() & REPARSE_POINT != 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn removes_only_old_files_and_preserves_subfolders() {
        let root = std::env::temp_dir().join(format!(
            "toolbox-cleanup-test-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir(&root).unwrap();
        fs::write(root.join("old"), b"old").unwrap();
        fs::write(root.join("recent"), b"recent").unwrap();
        fs::create_dir(root.join("nested")).unwrap();
        fs::write(root.join("nested/keep"), b"keep").unwrap();
        let now = SystemTime::now();
        fs::File::options()
            .write(true)
            .open(root.join("old"))
            .unwrap()
            .set_modified(now - MIN_AGE - Duration::from_secs(60))
            .unwrap();
        let report = clean(&root, now).unwrap();
        assert!(report.contains("Deleted 1 files (3 bytes)"));
        assert!(!root.join("old").exists());
        assert!(root.join("recent").exists());
        assert!(root.join("nested/keep").exists());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn rejects_relative_paths() {
        assert!(clean(Path::new("."), SystemTime::now()).is_err());
    }
}
