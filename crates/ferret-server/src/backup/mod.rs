//! Backups of the database and the secret files.
//!
//! The kit makes a copy before a migration and nothing else, so the server builds
//! its own scheduled backup. A set is a folder that holds the database,
//! `opaque_setup`, `prelogin_secret` and `session.key` (without the three
//! secrets a restored database cannot log anybody in) and a manifest that lists
//! the files with their lengths and SHA-256 hashes.
//!
//! * [`set`]: making, checking, listing and pruning sets.
//! * [`schedule`]: the job that makes a set on a timer and when asked.
//! * [`push`]: the message to the monitor after a good set.
//! * [`restore`]: putting a set back, and the marker that stops the server from
//!   starting on a half-restored directory.
//!
//! A set is as sensitive as the database plus `opaque_setup`: folders `0700`,
//! files `0600`, never served over HTTP, never logged with their contents, and
//! out of the machine only encrypted.
//!
//! Most of this module is a signature that returns [`BackupError::NotImplemented`]
//! until it is built; the marker check in [`restore`] and the configuration here
//! are complete.

pub mod push;
pub mod restore;
pub mod schedule;
pub mod set;

use std::fmt;
use std::path::{Path, PathBuf};
use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::error::ConfigError;
use crate::secret::SecretUrl;

/// The `format` of a set's manifest.
pub const SET_FORMAT: &str = "ferret-backup/1";

/// The file in the data directory that exists while a restore is under way.
/// The server and the commands that change the database refuse to start while
/// it is there ([`restore::refuse_if_in_progress`]).
pub const RESTORE_MARKER: &str = "RESTORE_IN_PROGRESS";

/// Where the sets go when `FERRET_BACKUP_DIR` is not set, under the data
/// directory.
pub const DEFAULT_DIR: &str = "backups/auto";
/// Hours between two scheduled backups when `FERRET_BACKUP_EVERY_HOURS` is not
/// set.
pub const DEFAULT_EVERY_HOURS: u32 = 24;
/// The least and the most `FERRET_BACKUP_EVERY_HOURS` takes.
pub const EVERY_HOURS_RANGE: std::ops::RangeInclusive<u32> = 1..=168;
/// Days a set is kept when `FERRET_BACKUP_KEEP_DAYS` is not set.
pub const DEFAULT_KEEP_DAYS: u32 = 30;
/// The least and the most `FERRET_BACKUP_KEEP_DAYS` takes.
pub const KEEP_DAYS_RANGE: std::ops::RangeInclusive<u32> = 1..=365;

/// How the backups run. Built from the settings of `config::Config`, or from
/// the environment for the commands that do not parse the server's flags.
///
/// The push address is a secret: `Debug` shows nothing of it.
#[derive(Debug, Clone)]
pub struct BackupConfig {
    /// The folder that holds the sets.
    pub dir: PathBuf,
    /// The time between two scheduled backups.
    pub every: Duration,
    /// How many days a set is kept (the newest good sets are kept longer).
    pub keep_days: u32,
    /// Where to say that a set was made, if anywhere.
    pub push_url: Option<SecretUrl>,
}

impl BackupConfig {
    /// Checks the values and fills in the defaults: no folder is
    /// `<data_dir>/backups/auto`, hours and days must be inside their ranges,
    /// and an empty push address is none. No message quotes the push address.
    pub fn from_parts(
        data_dir: &Path,
        dir: Option<&Path>,
        every_hours: u32,
        keep_days: u32,
        push_url: Option<&SecretUrl>,
    ) -> Result<Self, ConfigError> {
        if !EVERY_HOURS_RANGE.contains(&every_hours) {
            return Err(ConfigError(format!(
                "FERRET_BACKUP_EVERY_HOURS must be from {} to {}",
                EVERY_HOURS_RANGE.start(),
                EVERY_HOURS_RANGE.end()
            )));
        }
        if !KEEP_DAYS_RANGE.contains(&keep_days) {
            return Err(ConfigError(format!(
                "FERRET_BACKUP_KEEP_DAYS must be from {} to {}",
                KEEP_DAYS_RANGE.start(),
                KEEP_DAYS_RANGE.end()
            )));
        }
        let dir = match dir {
            Some(dir) if dir.as_os_str().is_empty() => {
                return Err(ConfigError("FERRET_BACKUP_DIR must not be empty".into()));
            }
            Some(dir) => dir.to_path_buf(),
            None => data_dir.join(DEFAULT_DIR),
        };
        let push_url = match push_url.filter(|url| !url.is_empty()) {
            Some(url) => {
                url.check()
                    .map_err(|why| ConfigError(format!("FERRET_BACKUP_PUSH_URL: {why}")))?;
                Some(url.clone())
            }
            None => None,
        };
        Ok(Self {
            dir,
            every: Duration::from_secs(u64::from(every_hours).saturating_mul(3600)),
            keep_days,
            push_url,
        })
    }

    /// The settings of the commands that do not parse the server's flags:
    /// `FERRET_BACKUP_DIR`, `FERRET_BACKUP_EVERY_HOURS` and
    /// `FERRET_BACKUP_KEEP_DAYS` from the environment, the same bounds, and no
    /// push address (a command never pushes).
    pub fn from_env(data_dir: &Path) -> Result<Self, ConfigError> {
        let number = |name: &str, default: u32| -> Result<u32, ConfigError> {
            match std::env::var(name) {
                Ok(text) if !text.trim().is_empty() => text
                    .trim()
                    .parse()
                    .map_err(|_| ConfigError(format!("{name} must be a whole number"))),
                _ => Ok(default),
            }
        };
        let dir = std::env::var_os("FERRET_BACKUP_DIR")
            .filter(|dir| !dir.is_empty())
            .map(PathBuf::from);
        Self::from_parts(
            data_dir,
            dir.as_deref(),
            number("FERRET_BACKUP_EVERY_HOURS", DEFAULT_EVERY_HOURS)?,
            number("FERRET_BACKUP_KEEP_DAYS", DEFAULT_KEEP_DAYS)?,
            None,
        )
    }
}

/// One set in the backup folder, as `set::list` reports it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SetInfo {
    /// The folder name.
    pub name: String,
    /// When the set was made (Unix seconds).
    pub created_at: i64,
    /// The size of the files of the set.
    pub bytes: u64,
    /// Whether the set passed the check (files against the manifest).
    pub verified: bool,
}

/// The manifest of a set (`MANIFEST.json`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Manifest {
    /// [`SET_FORMAT`].
    pub format: String,
    /// The version of the server that made the set.
    pub server_version: String,
    /// The names of the migrations of the database in the set: the kit's and
    /// ours.
    pub migrations: Vec<String>,
    /// When the set was made (Unix seconds).
    pub created_at: i64,
    /// Every file of the set with its length and hash.
    pub files: Vec<ManifestFile>,
    /// A fingerprint of the OPAQUE set-up, to check the set against the files
    /// that are loaded.
    pub setup_fingerprint: String,
    /// The position of every vault when the copy was made.
    pub vaults: Vec<ManifestVault>,
}

/// A file in a manifest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ManifestFile {
    /// The file name in the set folder.
    pub name: String,
    /// Its length in bytes.
    pub bytes: u64,
    /// Its SHA-256, in lower-case hex.
    pub sha256: String,
}

/// One vault in a manifest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ManifestVault {
    /// The vault id, in lower-case hex.
    pub vault_id: String,
    /// The `seq` of the vault in the copy.
    pub seq: u64,
    /// The `restore_epoch` of the vault in the copy.
    pub restore_epoch: u64,
}

/// Why a backup or a restore did not go through. A message never holds a path
/// that a client chose or any content of a set.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BackupError {
    /// The part is not built yet.
    NotImplemented,
    /// A file or folder could not be read, written or moved.
    Io(&'static str),
    /// A set did not pass the check.
    Verify(&'static str),
    /// The request was refused before anything changed.
    Refused(&'static str),
    /// There is too little free space to make a set.
    NoSpace,
    /// A restore is under way (the marker is there).
    RestoreInProgress,
}

impl fmt::Display for BackupError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            BackupError::NotImplemented => f.write_str("this backup step is not implemented yet"),
            BackupError::Io(what) => write!(f, "backup: {what}"),
            BackupError::Verify(what) => write!(f, "the backup set did not pass the check: {what}"),
            BackupError::Refused(what) => write!(f, "refused: {what}"),
            BackupError::NoSpace => f.write_str("there is too little free space for a backup"),
            BackupError::RestoreInProgress => f.write_str(
                "a restore is in progress: finish it with `ferret backup restore`, or undo it \
                 with `ferret backup restore --abort --yes`",
            ),
        }
    }
}

impl std::error::Error for BackupError {}

#[cfg(test)]
mod tests {
    use super::*;

    fn secret(text: &str) -> SecretUrl {
        SecretUrl::new(text)
    }

    #[test]
    fn the_defaults_are_a_folder_under_the_data_directory_every_day_for_thirty_days() {
        let cfg = BackupConfig::from_parts(Path::new("/data"), None, 24, 30, None).unwrap();
        assert_eq!(cfg.dir, Path::new("/data/backups/auto"));
        assert_eq!(cfg.every, Duration::from_secs(24 * 3600));
        assert_eq!(cfg.keep_days, 30);
        assert!(cfg.push_url.is_none());
    }

    #[test]
    fn hours_and_days_have_bounds_and_an_empty_push_address_is_none() {
        let build =
            |every, keep| BackupConfig::from_parts(Path::new("/d"), None, every, keep, None);
        assert!(build(1, 1).is_ok());
        assert!(build(168, 365).is_ok());
        for (every, keep) in [(0, 30), (169, 30), (24, 0), (24, 366)] {
            assert!(build(every, keep).is_err(), "{every} {keep}");
        }
        let empty = secret("  ");
        let cfg = BackupConfig::from_parts(Path::new("/d"), None, 24, 30, Some(&empty)).unwrap();
        assert!(cfg.push_url.is_none());
        assert!(
            BackupConfig::from_parts(Path::new("/d"), Some(Path::new("")), 24, 30, None).is_err()
        );
    }

    #[test]
    fn the_push_address_is_checked_and_never_printed() {
        let good = secret("https://monitor.example.test/api/push/tokensecret");
        let cfg = BackupConfig::from_parts(Path::new("/d"), None, 24, 30, Some(&good)).unwrap();
        assert!(!format!("{cfg:?}").contains("tokensecret"));
        assert!(!format!("{cfg:#?}").contains("monitor.example.test"));
        let bad = secret("ftp://monitor.example.test/tokensecret");
        let err = BackupConfig::from_parts(Path::new("/d"), None, 24, 30, Some(&bad))
            .unwrap_err()
            .to_string();
        assert!(
            !err.contains("tokensecret") && !err.contains("monitor"),
            "{err}"
        );
    }

    #[test]
    fn the_manifest_names_the_format_and_round_trips() {
        let manifest = Manifest {
            format: SET_FORMAT.to_string(),
            server_version: "0.0.0".into(),
            migrations: vec!["0001_vault.sql".into()],
            created_at: 5,
            files: vec![ManifestFile {
                name: "ferret.sqlite".into(),
                bytes: 3,
                sha256: "00".repeat(32),
            }],
            setup_fingerprint: "ab".repeat(16),
            vaults: vec![ManifestVault {
                vault_id: "01".repeat(16),
                seq: 7,
                restore_epoch: 2,
            }],
        };
        let json = serde_json::to_string(&manifest).unwrap();
        assert_eq!(serde_json::from_str::<Manifest>(&json).unwrap(), manifest);
        assert_eq!(SET_FORMAT, "ferret-backup/1");
        assert_eq!(RESTORE_MARKER, "RESTORE_IN_PROGRESS");
    }
}
