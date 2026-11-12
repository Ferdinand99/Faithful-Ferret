//! Making, checking, listing and pruning backup sets.
//!
//! A set is a folder in the backup directory with a copy of the database, the
//! three secret files and `MANIFEST.json` (see the module documentation of
//! [`super`]). These functions have their final signatures; until the set is
//! built each returns [`BackupError::NotImplemented`].

use std::path::Path;

use rusqlite::Connection;

use super::{BackupConfig, BackupError, Manifest, SetInfo};

/// Makes a new set from the database behind `conn` and the secret files in
/// `data_dir`, in the folder of `cfg`, stamped `now` (Unix seconds).
pub fn create(
    data_dir: &Path,
    conn: &Connection,
    cfg: &BackupConfig,
    now: i64,
) -> Result<SetInfo, BackupError> {
    let _ = (data_dir, conn, cfg, now);
    Err(BackupError::NotImplemented)
}

/// Checks the set in `set_dir` against its manifest, and its migrations against
/// `build_migrations` (the names this build knows): a set made by a newer build
/// is refused.
pub fn verify(set_dir: &Path, build_migrations: &[&str]) -> Result<Manifest, BackupError> {
    let _ = (set_dir, build_migrations);
    Err(BackupError::NotImplemented)
}

/// The finished sets in the folder of `cfg`, oldest first. A set that is still
/// being written is never listed.
pub fn list(cfg: &BackupConfig) -> Result<Vec<SetInfo>, BackupError> {
    let _ = cfg;
    Err(BackupError::NotImplemented)
}

/// Removes the sets that are older than `cfg.keep_days` at `now` (the newest
/// good sets are always kept) and returns how many were removed.
pub fn prune(cfg: &BackupConfig, now: i64) -> Result<u32, BackupError> {
    let _ = (cfg, now);
    Err(BackupError::NotImplemented)
}
