//! Literal native scanner command settings.

use std::path::{Path, PathBuf};

use super::Error;

/// A native executable and its argument/exit-code contract.
#[derive(Debug, Clone)]
pub struct Settings {
    /// Absolute path to the native scanner executable.
    pub executable: PathBuf,
    /// Literal arguments, including at least one standalone `{directory}`.
    pub arguments: Vec<String>,
    /// Normal exit code indicating no detection.
    pub clean_code: i32,
    /// Normal exit code indicating a detection.
    pub detected_code: i32,
}

impl Settings {
    /// Validate the command contract without touching the filesystem.
    pub fn validate(&self) -> Result<(), Error> {
        #[cfg(windows)]
        let path_has_nul = {
            use std::os::windows::ffi::OsStrExt;
            self.executable
                .as_os_str()
                .encode_wide()
                .any(|unit| unit == 0)
        };
        #[cfg(not(windows))]
        let path_has_nul = self.executable.as_os_str().as_encoded_bytes().contains(&0);
        if path_has_nul || self.arguments.iter().any(|value| value.contains('\0')) {
            return Err(Error::Nul);
        }
        if !native_executable(&self.executable) {
            return Err(Error::Executable);
        }
        if self.clean_code == self.detected_code {
            return Err(Error::ExitCodes);
        }
        if !self.arguments.iter().any(|value| value == "{directory}")
            || self
                .arguments
                .iter()
                .any(|value| value != "{directory}" && value.contains("{directory}"))
        {
            return Err(Error::Placeholder);
        }
        Ok(())
    }
}

/// Check the native executable path shape; IO resolution rechecks the target.
pub fn native_executable(path: &Path) -> bool {
    path.is_absolute()
        && path
            .extension()
            .is_some_and(|extension| extension.eq_ignore_ascii_case("exe"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn settings() -> Settings {
        Settings {
            executable: std::env::current_dir().unwrap().join("scanner.EXE"),
            arguments: vec!["{directory}".into()],
            clean_code: 0,
            detected_code: 1,
        }
    }

    #[test]
    fn command_contract_rejects_scripts_bad_codes_and_placeholders() {
        let mut input = settings();
        assert!(input.validate().is_ok());
        for name in ["scanner.cmd", "scanner.BAT", "scanner.ps1"] {
            input.executable = std::env::current_dir().unwrap().join(name);
            assert_eq!(input.validate(), Err(Error::Executable));
        }
        input = settings();
        input.clean_code = 1;
        assert_eq!(input.validate(), Err(Error::ExitCodes));
        for arguments in [
            vec![],
            vec!["--file={directory}".into()],
            vec!["{directory}".into(), "\0".into()],
        ] {
            input = settings();
            input.arguments = arguments;
            assert!(input.validate().is_err());
        }
        input = settings();
        input.arguments.push(String::new());
        assert!(input.validate().is_ok());
        input.executable = "relative.exe".into();
        assert_eq!(input.validate(), Err(Error::Executable));
    }
}
