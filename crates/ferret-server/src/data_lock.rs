//! One process at a time on a data directory.
//!
//! The server takes an exclusive lock on `ferret.lock` in its data directory
//! before it opens the database, and holds it until it ends. A command that
//! changes the database while the server is stopped (`ferret restore-epoch
//! bump`) takes the same lock, so it cannot run against a live server: the
//! lock is the operating system's, released when the process ends however it
//! ends, so a crash leaves no stale lock behind.

use std::fs::{File, OpenOptions, TryLockError};
use std::path::{Path, PathBuf};

use crate::error::StartError;

/// The lock file in the data directory.
pub const LOCK_FILE: &str = "ferret.lock";

/// The exclusive lock on a data directory. Dropping it releases the lock.
#[derive(Debug)]
pub struct DataDirLock {
    // Held for its lock: the file is never read or written.
    _file: File,
    path: PathBuf,
}

impl DataDirLock {
    /// The lock file.
    pub fn path(&self) -> &Path {
        &self.path
    }
}

/// Takes the lock on `data_dir`, creating the directory and the lock file if
/// they are not there. Fails at once, without waiting, when another process
/// holds it.
pub fn acquire(data_dir: &Path) -> Result<DataDirLock, StartError> {
    std::fs::create_dir_all(data_dir).map_err(|e| {
        format!(
            "can't create the data directory {}: {e}",
            data_dir.display()
        )
    })?;
    acquire_existing(data_dir)
}

/// Takes the lock on a data directory that must already exist.
pub fn acquire_existing(data_dir: &Path) -> Result<DataDirLock, StartError> {
    let path = data_dir.join(LOCK_FILE);
    let file = OpenOptions::new()
        .create(true)
        .truncate(false)
        .write(true)
        .open(&path)
        .map_err(|e| format!("can't open the lock file {}: {e}", path.display()))?;
    match file.try_lock() {
        Ok(()) => Ok(DataDirLock { _file: file, path }),
        Err(TryLockError::WouldBlock) => Err(format!(
            "another ferret process is using the data directory {} (it holds {}); \
             stop it first",
            data_dir.display(),
            path.display()
        )
        .into()),
        Err(TryLockError::Error(e)) => Err(format!("can't lock {}: {e}", path.display()).into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_dir(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("ferret-lock-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        dir
    }

    #[test]
    fn a_second_holder_is_refused_until_the_first_lets_go() {
        let dir = temp_dir("second");
        let first = acquire(&dir).expect("the first lock");
        assert!(first.path().ends_with(LOCK_FILE));
        let refused = acquire(&dir).expect_err("the directory is in use");
        assert!(
            refused.to_string().contains("another ferret process"),
            "{refused}"
        );
        drop(first);
        drop(acquire(&dir).expect("free again"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn two_directories_do_not_share_a_lock() {
        let a = temp_dir("a");
        let b = temp_dir("b");
        let _a = acquire(&a).expect("a");
        let _b = acquire(&b).expect("b");
        let _ = std::fs::remove_dir_all(&a);
        let _ = std::fs::remove_dir_all(&b);
    }

    #[test]
    fn an_existing_directory_is_required_by_acquire_existing() {
        let dir = temp_dir("missing");
        assert!(acquire_existing(&dir).is_err());
        assert!(!dir.exists(), "nothing was created");
    }
}
