//! Avast inspection settings, independent of execution and UI.

use super::Error;

/// The inspection scope of each Avast invocation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Settings {
    /// Inspect the whole file rather than Avast's default regions.
    pub entire_files: bool,
    /// Inspect all supported archive formats.
    pub archives: bool,
    /// Heuristic sensitivity from zero to one hundred.
    pub heuristics: u8,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            entire_files: true,
            archives: true,
            heuristics: 50,
        }
    }
}

impl Settings {
    /// Reject sensitivity values outside Avast's documented range.
    pub fn validate(&self) -> Result<(), Error> {
        if self.heuristics <= 100 {
            Ok(())
        } else {
            Err(Error::Heuristics)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_and_sensitivity_boundaries_are_validated() {
        let defaults = Settings::default();
        assert_eq!(defaults.heuristics, 50);
        assert!(defaults.entire_files && defaults.archives);
        for (heuristics, valid) in [(0, true), (100, true), (101, false)] {
            assert_eq!(
                Settings {
                    heuristics,
                    ..defaults
                }
                .validate()
                .is_ok(),
                valid
            );
        }
    }
}
