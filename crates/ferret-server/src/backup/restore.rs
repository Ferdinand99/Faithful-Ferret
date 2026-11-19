//! Putting a set back, and the marker that stops everything else while a
//! restore is under way.
//!
//! A restore writes [`RESTORE_MARKER`] into the data directory before it moves
//! anything, and removes it as its last step. While the marker is there the
//! server, `ferret restore-epoch bump` and `ferret backup create` refuse to
//! start ([`refuse_if_in_progress`]): a half-restored directory is never served
//! and never backed up. The restore itself is not built yet.

use std::io::ErrorKind;
use std::path::{Path, PathBuf};

use super::{BackupError, RESTORE_MARKER};
use crate::error::StartError;

/// Refuses when the marker is in `data_dir`. Anything but a clear "not there"
/// (an error reading the directory, say) refuses too: the answer must be a yes
/// before anything goes on.
pub fn refuse_if_in_progress(data_dir: &Path) -> Result<(), StartError> {
    let marker = data_dir.join(RESTORE_MARKER);
    match std::fs::symlink_metadata(&marker) {
        Ok(_) => Err(format!(
            "a restore is in progress in {}: {} is there. Run `ferret backup restore --from <set> \
             --yes` again to finish it, or `ferret backup restore --abort --yes` to put the old \
             files back",
            data_dir.display(),
            RESTORE_MARKER
        )
        .into()),
        Err(e) if e.kind() == ErrorKind::NotFound => Ok(()),
        Err(e) => Err(format!(
            "can't tell whether a restore is in progress in {}: {e}",
            data_dir.display()
        )
        .into()),
    }
}

/// What a restore did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RestoreReport {
    /// The restore epoch every vault has now.
    pub restore_epoch: u64,
    /// How many vaults were restored.
    pub vaults: u64,
    /// How many sessions were ended.
    pub sessions_ended: u64,
    /// Where the files that were in the data directory before went.
    pub moved_aside: PathBuf,
}

/// Restores the set in `from` into `data_dir`, with a restore epoch of at least
/// `at_least`, at `now` (Unix seconds).
pub fn restore(
    data_dir: &Path,
    from: &Path,
    at_least: Option<u64>,
    now: i64,
) -> Result<RestoreReport, BackupError> {
    let _ = (data_dir, from, at_least, now);
    Err(BackupError::NotImplemented)
}

/// Undoes a restore that did not finish: puts the files that were moved aside
/// back and removes the marker.
pub fn abort(data_dir: &Path) -> Result<(), BackupError> {
    let _ = data_dir;
    Err(BackupError::NotImplemented)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_dir(name: &str) -> PathBuf {
        let dir =
            std::env::temp_dir().join(format!("ferret-restore-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("a directory");
        dir
    }

    #[test]
    fn the_marker_refuses_and_its_absence_does_not() {
        let dir = temp_dir("marker");
        assert!(refuse_if_in_progress(&dir).is_ok());
        std::fs::write(dir.join(RESTORE_MARKER), "{}").expect("the marker");
        let err = refuse_if_in_progress(&dir).expect_err("a restore is in progress");
        assert!(err.to_string().contains(RESTORE_MARKER), "{err}");
        assert!(err.to_string().contains("--abort"), "{err}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_marker_that_is_a_folder_refuses_too() {
        let dir = temp_dir("folder");
        std::fs::create_dir(dir.join(RESTORE_MARKER)).expect("a folder");
        assert!(refuse_if_in_progress(&dir).is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_directory_that_cannot_be_read_refuses_instead_of_going_on() {
        // A "directory" that is a file: the marker cannot be told apart from
        // missing by a lookup, and the answer must not be yes.
        let dir = temp_dir("file");
        let file = dir.join("not-a-directory");
        std::fs::write(&file, b"x").expect("a file");
        assert!(refuse_if_in_progress(&file).is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
