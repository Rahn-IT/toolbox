//! Locate Windows utilities without searching the application folder or PATH.

use std::path::PathBuf;

pub(super) fn executable(relative: &str) -> Result<PathBuf, String> {
    let windows = std::env::var_os("SystemRoot")
        .map(PathBuf::from)
        .filter(|path| path.is_absolute())
        .ok_or_else(|| "SystemRoot must name an absolute Windows directory.".to_string())?;
    Ok(windows.join("System32").join(relative))
}
