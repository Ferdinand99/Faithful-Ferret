//! The clock of the end-to-end test stack (cargo feature `e2e-clock`).
//!
//! Only the image of the end-to-end stack is built with this feature. A release
//! build does not contain this module, the variable name below or any code that
//! reads it: setting the variable on a release server does nothing
//! (`tests/build_info.rs` checks the binary for it).
//!
//! The file named by `FERRET_E2E_CLOCK_FILE` holds a number of seconds that is
//! added to the system time, so a test can move the server forward (for
//! example by 12 hours, to see an idle session expire) without waiting. The
//! time keeps running between the changes. A missing file adds nothing. A file
//! that is not a plain non-negative number makes the clock fail, which reads as
//! `u64::MAX`: every state counts as expired and sign-in is refused (the same
//! fail-closed reading as a system clock before 1970).

use std::path::{Path, PathBuf};

use ferret_server_auth::{Clock, SystemClock};

/// The environment variable that names the file.
pub const CLOCK_FILE_VAR: &str = "FERRET_E2E_CLOCK_FILE";

/// The system clock plus the offset in a file.
#[derive(Debug, Clone)]
pub struct FileClock {
    path: PathBuf,
}

impl FileClock {
    /// A clock that reads its offset from `path` on every call.
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }

    /// The path of the offset file.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// The offset in seconds, or `None` when the file cannot be read as one.
    fn offset(&self) -> Option<u64> {
        match std::fs::read_to_string(&self.path) {
            Ok(text) => {
                // Digits only: `parse` would also take a leading `+`.
                let text = text.trim();
                if text.is_empty() || !text.bytes().all(|b| b.is_ascii_digit()) {
                    return None;
                }
                text.parse::<u64>().ok()
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Some(0),
            Err(_) => None,
        }
    }
}

impl Clock for FileClock {
    fn now_unix(&self) -> u64 {
        let real = SystemClock.now_unix();
        match self.offset() {
            Some(offset) => real.saturating_add(offset),
            None => u64::MAX,
        }
    }
}

/// The clock named by `FERRET_E2E_CLOCK_FILE`, if the variable is set and not
/// empty.
pub fn from_env() -> Option<FileClock> {
    let path = std::env::var_os(CLOCK_FILE_VAR).filter(|p| !p.is_empty())?;
    Some(FileClock::new(path))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    fn temp(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!("ferret-e2e-clock-{}-{name}", std::process::id()))
    }

    #[test]
    fn a_missing_file_adds_nothing() {
        let clock = FileClock::new(temp("missing"));
        let (before, now) = (SystemClock.now_unix(), clock.now_unix());
        assert!(now >= before && now - before < 5);
    }

    #[test]
    fn the_offset_in_the_file_is_added_and_can_change() {
        let path = temp("offset");
        let clock = FileClock::new(&path);
        std::fs::write(&path, "43200\n").unwrap();
        let day = clock.now_unix() - SystemClock.now_unix();
        assert!((43_200..43_205).contains(&day), "got {day}");
        std::fs::write(&path, "0").unwrap();
        assert!(clock.now_unix() - SystemClock.now_unix() < 5);
        std::fs::remove_file(&path).unwrap();
    }

    #[test]
    fn anything_but_a_plain_number_fails_the_clock() {
        let path = temp("bad");
        let clock = FileClock::new(&path);
        for bad in ["", "-5", "+5", "1.5", "twelve", "99999999999999999999999"] {
            std::fs::write(&path, bad).unwrap();
            assert_eq!(clock.now_unix(), u64::MAX, "{bad:?}");
        }
        std::fs::remove_file(&path).unwrap();
    }

    #[test]
    fn an_offset_that_overflows_fails_the_clock() {
        let path = temp("overflow");
        std::fs::write(&path, u64::MAX.to_string()).unwrap();
        assert_eq!(FileClock::new(&path).now_unix(), u64::MAX);
        std::fs::remove_file(&path).unwrap();
    }

    #[test]
    fn an_unreadable_path_fails_the_clock() {
        // A directory is not a file that can be read.
        assert_eq!(FileClock::new(std::env::temp_dir()).now_unix(), u64::MAX);
    }
}
