//! Making, checking, listing and pruning backup sets.
//!
//! A set is a folder in the backup directory with a copy of the database, the
//! three secret files and `MANIFEST.json` (see the module documentation of
//! [`super`]).
//!
//! # How a set is made
//!
//! Spec: Fase 1 § 11. Deviation from the spec text, which names the kit's
//! automatic backup and `opaque_setup`: Ferret makes the set itself, and the set
//! holds `prelogin_secret` and `session.key` besides `opaque_setup` (without
//! them nobody can sign in after a restore).
//!
//! 1. The backup folder must not be, or hold, the data directory.
//! 2. There must be free space for twice the database, or the run is skipped
//!    with [`BackupError::NoSpace`] before anything is touched.
//! 3. Everything is written into `.tmp-<name>/` in the backup folder: the
//!    database with `VACUUM INTO` (one read transaction, so the copy is
//!    consistent while writes go on), the three secret files byte for byte, and
//!    `MANIFEST.json`. Folders are `0700`, files `0600`.
//! 4. `.complete` is written **inside** the temporary folder as the last file.
//! 5. Every file and the temporary folder are synced, the set is checked (see
//!    below), and the folder gets its name with one `rename`; then the backup
//!    folder is synced. A set therefore appears whole or not at all, and a
//!    half-written one is never listed ([`list`]); a leftover `.tmp-` folder is
//!    removed after a day ([`prune`]).
//!
//! # How a set is checked
//!
//! [`verify`] opens the database read-only and `immutable`, so it never creates
//! a `-wal` or `-shm` file beside it; a set that holds any file other than the
//! six expected ones (a stray `-wal` or `-shm` among them) is refused before the
//! database is opened. It then runs `integrity_check`, compares every file with
//! the manifest (length and SHA-256), checks that `opaque_setup` and
//! `prelogin_secret` decode and that the fingerprint of the set-up equals the
//! one in the manifest and the one the database remembers, and refuses a set
//! made by a build that knows more migrations than this one.

use std::collections::BTreeSet;
use std::io::{self, Read as _, Write as _};
use std::path::{Component, Path, PathBuf};
use std::sync::Arc;

use ferret_server_auth::{
    FileKind, OPAQUE_SETUP_FILE, PRELOGIN_SECRET_FILE, ServerKeys, decode_secret_file,
};
use rusqlite::{Connection, OpenFlags};
use sha2::{Digest as _, Sha256};
use zeroize::Zeroizing;

use super::{
    BackupConfig, BackupError, Manifest, ManifestFile, ManifestVault, SET_FORMAT, SetInfo,
};
use crate::db::{CORE_MIGRATIONS, MIGRATION_FILES};
use crate::product::DB_FILE;

/// The manifest inside a set.
pub const MANIFEST_FILE: &str = "MANIFEST.json";

/// The file that is the last thing written inside a set.
pub const COMPLETE_FILE: &str = ".complete";

/// The key file of the kit (the cookie key), a set member.
pub const SESSION_KEY_FILE: &str = "session.key";

/// The three secret files of a set, in manifest order.
pub const SECRET_FILES: [&str; 3] = [OPAQUE_SETUP_FILE, PRELOGIN_SECRET_FILE, SESSION_KEY_FILE];

/// The prefix of a set that is still being written.
pub const TEMP_PREFIX: &str = ".tmp-";

/// Seconds a half-written set is left alone before [`prune`] removes it.
pub const STALE_TEMP_SECS: i64 = 86_400;

/// The sets that are always kept, however old: the newest good ones.
pub const ALWAYS_KEEP_GOOD: usize = 3;

/// The most a manifest is read as.
const MAX_MANIFEST: u64 = 1024 * 1024;

/// The longest a secret file may be (`session.key` is 64 bytes, the others
/// about 150).
const MAX_SECRET_FILE: u64 = 4096;

/// The shortest `session.key` (the cookie crate's master key).
const MIN_SESSION_KEY: usize = 64;

/// How many times the free space must cover the database.
const SPACE_FACTOR: u64 = 2;

const SECS_PER_DAY: i64 = 86_400;

/// The operations of making a set that touch the machine, behind a trait so a
/// test can watch their order or make one fail (the fsync spy, low disk).
pub trait Platform: Send + Sync {
    /// Flushes the file at `path` to disk.
    fn sync_file(&self, path: &Path) -> io::Result<()>;
    /// Flushes the directory at `path` (its entries) to disk.
    fn sync_dir(&self, path: &Path) -> io::Result<()>;
    /// Renames `from` to `to`.
    fn rename(&self, from: &Path, to: &Path) -> io::Result<()>;
    /// The bytes that are free for this user on the file system of `dir`, or
    /// `None` when that is not known (the check is then skipped).
    fn free_bytes(&self, dir: &Path) -> Option<u64>;
}

/// The real machine.
#[derive(Debug, Clone, Copy, Default)]
pub struct RealPlatform;

impl Platform for RealPlatform {
    fn sync_file(&self, path: &Path) -> io::Result<()> {
        std::fs::File::open(path)?.sync_all()
    }

    fn sync_dir(&self, path: &Path) -> io::Result<()> {
        sync_dir_path(path)
    }

    fn rename(&self, from: &Path, to: &Path) -> io::Result<()> {
        std::fs::rename(from, to)
    }

    fn free_bytes(&self, dir: &Path) -> Option<u64> {
        free_bytes_of(dir)
    }
}

#[cfg(unix)]
fn free_bytes_of(dir: &Path) -> Option<u64> {
    let stat = rustix::fs::statvfs(dir).ok()?;
    stat.f_bavail.checked_mul(stat.f_frsize)
}

#[cfg(not(unix))]
fn free_bytes_of(_dir: &Path) -> Option<u64> {
    None
}

/// Flushes a directory. A no-op where a directory cannot be opened for it.
pub(crate) fn sync_dir_path(path: &Path) -> io::Result<()> {
    #[cfg(unix)]
    {
        std::fs::File::open(path)?.sync_all()
    }
    #[cfg(not(unix))]
    {
        let _ = path;
        Ok(())
    }
}

/// Makes `dir` (and its missing parents) with mode `0700`, and takes the group
/// and other bits off a folder that was there with them. A folder that is not
/// ours to change is left as it is: the sets inside are `0700` themselves.
pub(crate) fn ensure_private_dir(dir: &Path) -> io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::{DirBuilderExt as _, PermissionsExt as _};
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(dir)?;
        let meta = std::fs::metadata(dir)?;
        if meta.permissions().mode() & 0o077 != 0 {
            let _ = std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700));
        }
        Ok(())
    }
    #[cfg(not(unix))]
    {
        std::fs::create_dir_all(dir)
    }
}

/// Writes a new file with mode `0600` from the start. Never replaces a file.
fn write_new(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }
    options.open(path)?.write_all(bytes)
}

/// Logs the kind of an I/O error (never the message, which may hold a path) and
/// turns it into [`BackupError::Io`] with a fixed text.
fn io_err(what: &'static str) -> impl Fn(io::Error) -> BackupError {
    move |error| {
        tracing::warn!(step = what, kind = ?error.kind(), "backup step failed");
        BackupError::Io(what)
    }
}

/// The migration names this build knows: the kit's core set and ours.
pub fn build_migrations() -> Vec<&'static str> {
    CORE_MIGRATIONS
        .iter()
        .map(|(name, _)| *name)
        .chain(MIGRATION_FILES.iter().map(|(name, _)| *name))
        .collect()
}

// ---------------------------------------------------------------------------
// Names and time
// ---------------------------------------------------------------------------

/// The folder name of a set made at `secs`: `20261119T201500Z`.
pub fn set_name(secs: i64) -> String {
    let days = secs.div_euclid(SECS_PER_DAY);
    let rest = secs.rem_euclid(SECS_PER_DAY);
    let (y, m, d) = civil_from_days(days);
    format!(
        "{y:04}{m:02}{d:02}T{:02}{:02}{:02}Z",
        rest / 3600,
        rest % 3600 / 60,
        rest % 60
    )
}

/// The time in a set name (`20261119T201500Z` or `20261119T201500Z-2`), or
/// `None` for any other name.
pub fn parse_set_name(name: &str) -> Option<i64> {
    let (stamp, suffix) = match name.split_once('-') {
        Some((stamp, suffix)) => (stamp, Some(suffix)),
        None => (name, None),
    };
    if let Some(suffix) = suffix
        && (suffix.is_empty() || suffix.len() > 6 || !suffix.bytes().all(|b| b.is_ascii_digit()))
    {
        return None;
    }
    let bytes = stamp.as_bytes();
    if bytes.len() != 16 || bytes.get(8) != Some(&b'T') || bytes.get(15) != Some(&b'Z') {
        return None;
    }
    let digits = |range: std::ops::Range<usize>| -> Option<i64> {
        let part = stamp.get(range)?;
        if !part.bytes().all(|c| c.is_ascii_digit()) {
            return None;
        }
        part.parse().ok()
    };
    let (y, m, d) = (digits(0..4)?, digits(4..6)?, digits(6..8)?);
    let (h, mi, s) = (digits(9..11)?, digits(11..13)?, digits(13..15)?);
    if !(1..=12).contains(&m) || !(1..=31).contains(&d) || h > 23 || mi > 59 || s > 59 {
        return None;
    }
    let secs = days_from_civil(y, m, d)
        .checked_mul(SECS_PER_DAY)?
        .checked_add(h * 3600 + mi * 60 + s)?;
    // Only a name that formats back to itself is a real date (not 31 February).
    (set_name(secs) == stamp).then_some(secs)
}

/// Days since 1970-01-01 of a civil date.
fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let mp = if m > 2 { m - 3 } else { m + 9 };
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

/// The civil date of a day count since 1970-01-01.
fn civil_from_days(z: i64) -> (i64, i64, i64) {
    let z = z + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    (if m <= 2 { y + 1 } else { y }, m, d)
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    bytes.iter().fold(String::new(), |mut out, byte| {
        let _ = write!(out, "{byte:02x}");
        out
    })
}

// ---------------------------------------------------------------------------
// The backup folder
// ---------------------------------------------------------------------------

/// Whether `backup` is the same folder as `data`, or holds it, by their
/// spelling alone (no file system access, so it works before either exists).
/// A folder inside the data directory is fine (the default is
/// `<data>/backups/auto`).
pub fn backup_dir_holds_data(data: &Path, backup: &Path) -> bool {
    lexical_abs(data).starts_with(lexical_abs(backup))
}

fn lexical_abs(path: &Path) -> PathBuf {
    let abs = std::path::absolute(path).unwrap_or_else(|_| path.to_path_buf());
    let mut out = PathBuf::new();
    for part in abs.components() {
        match part {
            Component::ParentDir => {
                out.pop();
            }
            Component::CurDir => {}
            other => out.push(other.as_os_str()),
        }
    }
    out
}

/// The backup folder must not be the data directory or hold it: a prune there
/// would walk the data. Checked after links are resolved, with the folder made.
fn check_backup_dir(data_dir: &Path, backup_dir: &Path) -> Result<(), BackupError> {
    const HOLDS: &str = "the backup folder is the data directory or holds it";
    if backup_dir_holds_data(data_dir, backup_dir) {
        return Err(BackupError::Refused(HOLDS));
    }
    ensure_private_dir(backup_dir).map_err(io_err("could not make the backup folder"))?;
    let backup =
        std::fs::canonicalize(backup_dir).map_err(io_err("could not resolve the backup folder"))?;
    let data =
        std::fs::canonicalize(data_dir).map_err(io_err("could not resolve the data directory"))?;
    if data.starts_with(&backup) {
        return Err(BackupError::Refused(HOLDS));
    }
    Ok(())
}

/// A folder name that is free in the backup folder, also as a temporary one.
fn free_name(dir: &Path, now: i64) -> Result<String, BackupError> {
    let base = set_name(now);
    let taken = |path: PathBuf| std::fs::symlink_metadata(path).is_ok();
    for n in 0..1000 {
        let name = if n == 0 {
            base.clone()
        } else {
            format!("{base}-{n}")
        };
        if !taken(dir.join(&name)) && !taken(dir.join(format!("{TEMP_PREFIX}{name}"))) {
            return Ok(name);
        }
    }
    Err(BackupError::Io("no free set name"))
}

// ---------------------------------------------------------------------------
// Making a set
// ---------------------------------------------------------------------------

/// Makes a new set from the database behind `conn` and the secret files in
/// `data_dir`, in the folder of `cfg`, stamped `now` (Unix seconds). The set is
/// checked before it gets its name; one that does not pass is removed and the
/// run fails. Older sets are never touched.
pub fn create(
    data_dir: &Path,
    conn: &Connection,
    cfg: &BackupConfig,
    now: i64,
) -> Result<SetInfo, BackupError> {
    create_with(data_dir, conn, cfg, now, &RealPlatform)
}

/// [`create`] with the machine behind `platform`.
pub fn create_with(
    data_dir: &Path,
    conn: &Connection,
    cfg: &BackupConfig,
    now: i64,
    platform: &dyn Platform,
) -> Result<SetInfo, BackupError> {
    super::restore::refuse_if_in_progress(data_dir).map_err(|_| BackupError::RestoreInProgress)?;
    check_backup_dir(data_dir, &cfg.dir)?;

    // Spec: Fase 1 § 11: too little space (under twice the database) skips the run
    // and touches no set.
    let db_bytes = std::fs::metadata(data_dir.join(DB_FILE))
        .map_err(io_err("could not read the database file"))?
        .len();
    if let Some(free) = platform.free_bytes(&cfg.dir)
        && free < db_bytes.saturating_mul(SPACE_FACTOR)
    {
        return Err(BackupError::NoSpace);
    }

    // The secret files are read first: a missing one ends the run before a
    // folder exists.
    let mut secrets = Vec::with_capacity(SECRET_FILES.len());
    for name in SECRET_FILES {
        secrets.push((name, read_secret_raw(&data_dir.join(name))?));
    }

    // A set that was left half written a day ago is cleaned up now.
    clean_stale_temp(&cfg.dir, now);

    let name = free_name(&cfg.dir, now)?;
    let temp = cfg.dir.join(format!("{TEMP_PREFIX}{name}"));
    let bytes = match write_temp_set(&temp, conn, &secrets, now, platform) {
        Ok(bytes) => bytes,
        Err(error) => {
            let _ = std::fs::remove_dir_all(&temp);
            return Err(error);
        }
    };
    if let Err(error) = platform.rename(&temp, &cfg.dir.join(&name)) {
        let _ = std::fs::remove_dir_all(&temp);
        return Err(io_err("could not move the set into place")(error));
    }
    platform
        .sync_dir(&cfg.dir)
        .map_err(io_err("could not sync the backup folder"))?;
    Ok(SetInfo {
        name,
        created_at: now,
        bytes,
        verified: true,
    })
}

/// Everything inside the temporary folder, up to and including the check.
/// Returns the size of the files.
fn write_temp_set(
    temp: &Path,
    conn: &Connection,
    secrets: &[(&'static str, Zeroizing<Vec<u8>>)],
    now: i64,
    platform: &dyn Platform,
) -> Result<u64, BackupError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt as _;
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(temp)
            .map_err(io_err("could not make the set folder"))?;
    }
    #[cfg(not(unix))]
    std::fs::create_dir(temp).map_err(io_err("could not make the set folder"))?;

    // The database: one read transaction, so the copy is consistent while
    // writes go on (Spec: Fase 1 § 11).
    let db_copy = temp.join(DB_FILE);
    let target = db_copy
        .to_str()
        .ok_or(BackupError::Io("the backup folder name is not UTF-8"))?;
    conn.execute("VACUUM INTO ?1", [target]).map_err(|error| {
        tracing::warn!(code = ?error.sqlite_error_code(), "the database copy failed");
        BackupError::Io("could not copy the database")
    })?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&db_copy, std::fs::Permissions::from_mode(0o600))
            .map_err(io_err("could not set the database copy private"))?;
    }

    // The secret files, byte for byte.
    for (name, bytes) in secrets {
        write_new(&temp.join(name), bytes).map_err(io_err("could not write a secret file"))?;
    }

    // What the copy says: migrations, vaults, the set-up fingerprint.
    let facts = inspect_db(&db_copy)?;
    let setup = secrets
        .iter()
        .find(|(name, _)| *name == OPAQUE_SETUP_FILE)
        .map(|(_, bytes)| bytes)
        .ok_or(BackupError::Io("the set-up file is missing"))?;
    let fingerprint = setup_fingerprint(setup)?;

    let mut files = Vec::with_capacity(1 + secrets.len());
    files.push(describe_file(&db_copy, DB_FILE)?);
    for (name, bytes) in secrets {
        files.push(ManifestFile {
            name: (*name).to_string(),
            bytes: u64::try_from(bytes.len()).unwrap_or(u64::MAX),
            sha256: hex(&Sha256::digest(bytes.as_slice())),
        });
    }
    let total = files
        .iter()
        .map(|f| f.bytes)
        .fold(0u64, u64::saturating_add);
    let manifest = Manifest {
        format: SET_FORMAT.to_string(),
        server_version: crate::VERSION.to_string(),
        migrations: facts.migrations,
        created_at: now,
        files,
        setup_fingerprint: hex(&fingerprint),
        vaults: facts.vaults,
    };
    let json = serde_json::to_vec_pretty(&manifest)
        .map_err(|_| BackupError::Io("could not write the manifest"))?;
    write_new(&temp.join(MANIFEST_FILE), &json).map_err(io_err("could not write the manifest"))?;
    // The last file, inside the temporary folder: the set is whole when this
    // exists and the folder has its name.
    write_new(&temp.join(COMPLETE_FILE), b"complete\n")
        .map_err(io_err("could not write the complete marker"))?;

    for name in [DB_FILE, MANIFEST_FILE, COMPLETE_FILE]
        .into_iter()
        .chain(SECRET_FILES)
    {
        platform
            .sync_file(&temp.join(name))
            .map_err(io_err("could not sync a set file"))?;
    }
    platform
        .sync_dir(temp)
        .map_err(io_err("could not sync the set folder"))?;

    // Spec: Fase 1 § 11: the set is checked after it is written and before it is
    // a set.
    verify_dir(temp, Some(&build_migrations()))?;
    Ok(total)
}

/// A secret file as it is on disk: a regular file, not a link, of a sane size.
fn read_secret_raw(path: &Path) -> Result<Zeroizing<Vec<u8>>, BackupError> {
    let meta = std::fs::symlink_metadata(path).map_err(io_err("a secret file is missing"))?;
    if !meta.is_file() || meta.len() > MAX_SECRET_FILE {
        return Err(BackupError::Refused(
            "a secret file is not a regular file of the right size",
        ));
    }
    let mut buffer = Zeroizing::new(Vec::with_capacity(usize::try_from(meta.len()).unwrap_or(0)));
    std::fs::File::open(path)
        .and_then(|file| file.take(MAX_SECRET_FILE + 1).read_to_end(&mut buffer))
        .map_err(io_err("could not read a secret file"))?;
    Ok(buffer)
}

fn describe_file(path: &Path, name: &str) -> Result<ManifestFile, BackupError> {
    let (bytes, sha256) = hash_file(path).map_err(io_err("could not read a set file"))?;
    Ok(ManifestFile {
        name: name.to_string(),
        bytes,
        sha256,
    })
}

/// The length and SHA-256 (lower-case hex) of a file, read in blocks.
fn hash_file(path: &Path) -> io::Result<(u64, String)> {
    let mut file = std::fs::File::open(path)?;
    let mut hash = Sha256::new();
    let mut buffer = vec![0u8; 64 * 1024];
    let mut total = 0u64;
    loop {
        let n = file.read(&mut buffer)?;
        if n == 0 {
            break;
        }
        hash.update(&buffer[..n]);
        total = total.saturating_add(u64::try_from(n).unwrap_or(0));
    }
    Ok((total, hex(&hash.finalize())))
}

/// The fingerprint of the set-up in an `opaque_setup` file's bytes.
fn setup_fingerprint(file_bytes: &[u8]) -> Result<[u8; 32], BackupError> {
    const BAD: BackupError = BackupError::Verify("the OPAQUE set-up file does not decode");
    let payload = decode_secret_file(FileKind::OpaqueSetup, file_bytes).map_err(|_| BAD)?;
    let keys = ServerKeys::from_payload(&payload).map_err(|_| BAD)?;
    Ok(keys.fingerprint().0)
}

// ---------------------------------------------------------------------------
// Looking inside the database copy
// ---------------------------------------------------------------------------

struct DbFacts {
    migrations: Vec<String>,
    vaults: Vec<ManifestVault>,
    fingerprint: Option<[u8; 32]>,
    has_accounts: bool,
}

/// `file:<path>?immutable=1` with the path percent-encoded.
fn immutable_uri(path: &Path) -> Result<String, BackupError> {
    let abs = std::fs::canonicalize(path).map_err(io_err("could not resolve the database copy"))?;
    let text = abs
        .to_str()
        .ok_or(BackupError::Verify("the set path is not UTF-8"))?;
    let mut out = String::from("file:");
    for byte in text.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~' | b'/') {
            out.push(char::from(byte));
        } else {
            out.push_str(&format!("%{byte:02X}"));
        }
    }
    out.push_str("?immutable=1");
    Ok(out)
}

/// Opens the database copy read-only and `immutable` (no lock, and no `-wal` or
/// `-shm` is made or read), runs `integrity_check` and reads what the manifest
/// and the check need. The caller has seen that the folder holds no stray
/// `-wal` or `-shm`.
fn inspect_db(path: &Path) -> Result<DbFacts, BackupError> {
    let bad = |_: rusqlite::Error| BackupError::Verify("the database copy can not be read");
    let conn = Connection::open_with_flags(
        immutable_uri(path)?,
        OpenFlags::SQLITE_OPEN_READ_ONLY
            | OpenFlags::SQLITE_OPEN_URI
            | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .map_err(bad)?;

    // Spec: Fase 1 § 11 (the check of the set): `integrity_check` says "ok".
    let verdict: Vec<String> = conn
        .prepare("PRAGMA integrity_check")
        .and_then(|mut stmt| stmt.query_map([], |row| row.get(0))?.collect())
        .map_err(bad)?;
    if verdict.as_slice() != ["ok"] {
        return Err(BackupError::Verify("the database copy failed its check"));
    }

    let migrations: Vec<String> = conn
        .prepare("SELECT name FROM schema_migrations ORDER BY name")
        .and_then(|mut stmt| stmt.query_map([], |row| row.get(0))?.collect())
        .map_err(bad)?;
    let vaults: Vec<ManifestVault> = conn
        .prepare("SELECT vault_id, seq, restore_epoch FROM ferret_vaults ORDER BY vault_id")
        .and_then(|mut stmt| {
            stmt.query_map([], |row| {
                let id: Vec<u8> = row.get(0)?;
                let seq: i64 = row.get(1)?;
                let epoch: i64 = row.get(2)?;
                let unsigned = |value: i64| {
                    u64::try_from(value)
                        .map_err(|_| rusqlite::Error::IntegralValueOutOfRange(1, value))
                };
                Ok(ManifestVault {
                    vault_id: hex(&id),
                    seq: unsigned(seq)?,
                    restore_epoch: unsigned(epoch)?,
                })
            })?
            .collect()
        })
        .map_err(bad)?;
    let stored: Option<Vec<u8>> = conn
        .query_row(
            "SELECT value FROM ferret_meta WHERE key = 'setup_fingerprint'",
            [],
            |row| row.get(0),
        )
        .map(Some)
        .or_else(|error| match error {
            rusqlite::Error::QueryReturnedNoRows => Ok(None),
            other => Err(other),
        })
        .map_err(bad)?;
    let fingerprint = match stored {
        None => None,
        Some(bytes) => Some(
            <[u8; 32]>::try_from(bytes.as_slice())
                .map_err(|_| BackupError::Verify("the stored set-up fingerprint is malformed"))?,
        ),
    };
    let accounts: i64 = conn
        .query_row("SELECT EXISTS(SELECT 1 FROM ferret_accounts)", [], |row| {
            row.get(0)
        })
        .map_err(bad)?;
    Ok(DbFacts {
        migrations,
        vaults,
        fingerprint,
        has_accounts: accounts != 0,
    })
}

// ---------------------------------------------------------------------------
// Checking a set
// ---------------------------------------------------------------------------

/// Checks the set in `set_dir` against its manifest, and its migrations against
/// `build_migrations` (the names this build knows): a set made by a newer build
/// is refused.
pub fn verify(set_dir: &Path, build_migrations: &[&str]) -> Result<Manifest, BackupError> {
    verify_dir(set_dir, Some(build_migrations))
}

fn verify_dir(set_dir: &Path, build_migrations: Option<&[&str]>) -> Result<Manifest, BackupError> {
    let manifest = check_structure(set_dir)?;

    // Only now is the database opened: the folder holds exactly the expected
    // files, so no stray -wal or -shm sits beside it.
    let facts = inspect_db(&set_dir.join(DB_FILE))?;

    if facts.migrations != manifest.migrations {
        return Err(BackupError::Verify(
            "the migrations of the database differ from the manifest",
        ));
    }
    if let Some(known) = build_migrations
        && facts
            .migrations
            .iter()
            .any(|name| !known.contains(&name.as_str()))
    {
        return Err(BackupError::Verify(
            "the set was made by a newer build (it has a migration this build does not know)",
        ));
    }
    if facts.vaults != manifest.vaults {
        return Err(BackupError::Verify(
            "the vaults of the database differ from the manifest",
        ));
    }

    // The secret files decode, and the set-up they hold is the one the manifest
    // and the database name.
    let read = |name: &str| -> Result<Zeroizing<Vec<u8>>, BackupError> {
        let mut bytes = Zeroizing::new(Vec::new());
        std::fs::File::open(set_dir.join(name))
            .and_then(|file| file.take(MAX_SECRET_FILE + 1).read_to_end(&mut bytes))
            .map_err(io_err("could not read a set file"))?;
        Ok(bytes)
    };
    let fingerprint = setup_fingerprint(&read(OPAQUE_SETUP_FILE)?)?;
    if hex(&fingerprint) != manifest.setup_fingerprint {
        return Err(BackupError::Verify(
            "the OPAQUE set-up does not match the fingerprint in the manifest",
        ));
    }
    match facts.fingerprint {
        Some(stored) if stored == fingerprint => {}
        None if !facts.has_accounts => {}
        _ => {
            return Err(BackupError::Verify(
                "the OPAQUE set-up does not match the fingerprint in the database",
            ));
        }
    }
    decode_secret_file(FileKind::PreloginSecret, &read(PRELOGIN_SECRET_FILE)?)
        .map_err(|_| BackupError::Verify("the pre-login secret file does not decode"))?;
    if read(SESSION_KEY_FILE)?.len() < MIN_SESSION_KEY {
        return Err(BackupError::Verify("the session key file is too short"));
    }
    Ok(manifest)
}

/// The cheap part of the check, with no database opened: the folder holds
/// exactly the six expected files (all plain files), the manifest parses and
/// names the four data files once, and every length and SHA-256 matches.
fn check_structure(set_dir: &Path) -> Result<Manifest, BackupError> {
    let meta = std::fs::symlink_metadata(set_dir).map_err(io_err("the set is not readable"))?;
    if !meta.is_dir() {
        return Err(BackupError::Verify("the set is not a folder"));
    }

    let expected: BTreeSet<&str> = [DB_FILE, MANIFEST_FILE, COMPLETE_FILE]
        .into_iter()
        .chain(SECRET_FILES)
        .collect();
    let mut seen = BTreeSet::new();
    for entry in std::fs::read_dir(set_dir).map_err(io_err("the set is not readable"))? {
        let entry = entry.map_err(io_err("the set is not readable"))?;
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| BackupError::Verify("the set holds a file with an odd name"))?;
        if !expected.contains(name.as_str()) {
            // A stray -wal, -shm or -journal ends up here: the database of such
            // a set is never opened.
            return Err(BackupError::Verify("the set holds a file it should not"));
        }
        let kind = entry
            .file_type()
            .map_err(io_err("the set is not readable"))?;
        if !kind.is_file() {
            return Err(BackupError::Verify("a set file is not a plain file"));
        }
        seen.insert(name);
    }
    if seen.len() != expected.len() {
        return Err(BackupError::Verify("a file of the set is missing"));
    }

    let manifest_path = set_dir.join(MANIFEST_FILE);
    let mut text = Vec::new();
    std::fs::File::open(&manifest_path)
        .and_then(|file| file.take(MAX_MANIFEST + 1).read_to_end(&mut text))
        .map_err(io_err("the manifest is not readable"))?;
    if u64::try_from(text.len()).unwrap_or(u64::MAX) > MAX_MANIFEST {
        return Err(BackupError::Verify("the manifest is too large"));
    }
    let manifest: Manifest = serde_json::from_slice(&text)
        .map_err(|_| BackupError::Verify("the manifest does not parse"))?;
    if manifest.format != SET_FORMAT {
        return Err(BackupError::Verify("the manifest has another format"));
    }

    let data_files: BTreeSet<&str> = [DB_FILE].into_iter().chain(SECRET_FILES).collect();
    let listed: BTreeSet<&str> = manifest.files.iter().map(|f| f.name.as_str()).collect();
    if manifest.files.len() != data_files.len() || listed != data_files {
        return Err(BackupError::Verify(
            "the manifest does not list the files of a set",
        ));
    }
    for file in &manifest.files {
        let (bytes, sha256) =
            hash_file(&set_dir.join(&file.name)).map_err(io_err("could not read a set file"))?;
        if bytes != file.bytes || sha256 != file.sha256 {
            return Err(BackupError::Verify("a file does not match the manifest"));
        }
    }
    Ok(manifest)
}

// ---------------------------------------------------------------------------
// Listing and pruning
// ---------------------------------------------------------------------------

/// The finished sets in the folder of `cfg`, oldest first. A set that is still
/// being written (a `.tmp-` folder) and anything that is not a folder with a
/// set's name and a `.complete` file is never listed. A listed set that does not
/// pass the cheap check (files against the manifest) shows `verified: false`.
pub fn list(cfg: &BackupConfig) -> Result<Vec<SetInfo>, BackupError> {
    let entries = match std::fs::read_dir(&cfg.dir) {
        Ok(entries) => entries,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => return Err(io_err("could not read the backup folder")(error)),
    };
    let mut sets = Vec::new();
    for entry in entries {
        let entry = entry.map_err(io_err("could not read the backup folder"))?;
        let Ok(name) = entry.file_name().into_string() else {
            continue;
        };
        let Some(named_at) = parse_set_name(&name) else {
            continue;
        };
        let path = entry.path();
        let is_set = std::fs::symlink_metadata(&path).is_ok_and(|m| m.is_dir())
            && std::fs::symlink_metadata(path.join(COMPLETE_FILE)).is_ok_and(|m| m.is_file());
        if !is_set {
            continue;
        }
        sets.push(match check_structure(&path) {
            Ok(manifest) => SetInfo {
                name,
                created_at: manifest.created_at,
                bytes: manifest
                    .files
                    .iter()
                    .map(|f| f.bytes)
                    .fold(0u64, u64::saturating_add),
                verified: true,
            },
            Err(_) => SetInfo {
                name,
                created_at: named_at,
                bytes: 0,
                verified: false,
            },
        });
    }
    sets.sort_by(|a, b| (a.created_at, &a.name).cmp(&(b.created_at, &b.name)));
    Ok(sets)
}

/// Removes the sets that are older than `cfg.keep_days` at `now`, except the
/// [`ALWAYS_KEEP_GOOD`] newest good ones, and the `.tmp-` folders that were
/// left half written more than a day ago. Returns how many sets were removed.
///
/// Spec: Fase 1 § 11: sets are kept for 30 days. The three newest good sets
/// always stay, so a long failure does not empty the folder.
pub fn prune(cfg: &BackupConfig, now: i64) -> Result<u32, BackupError> {
    // A folder that holds the database is the data directory, not a backup
    // folder: nothing is removed there.
    if cfg.dir.join(DB_FILE).exists() {
        return Err(BackupError::Refused(
            "the backup folder holds a database: it looks like the data directory",
        ));
    }
    clean_stale_temp(&cfg.dir, now);

    let sets = list(cfg)?;
    let keep_since = now.saturating_sub(i64::from(cfg.keep_days).saturating_mul(SECS_PER_DAY));
    let mut newest_good: Vec<&SetInfo> = sets.iter().filter(|s| s.verified).collect();
    newest_good.sort_by(|a, b| (b.created_at, &b.name).cmp(&(a.created_at, &a.name)));
    let always: BTreeSet<&str> = newest_good
        .iter()
        .take(ALWAYS_KEEP_GOOD)
        .map(|s| s.name.as_str())
        .collect();

    let mut removed = 0u32;
    for set in &sets {
        if set.created_at >= keep_since || always.contains(set.name.as_str()) {
            continue;
        }
        let path = cfg.dir.join(&set.name);
        // The marker goes first, so a removal that stops half way leaves a
        // folder that is no longer listed as a set.
        let _ = std::fs::remove_file(path.join(COMPLETE_FILE));
        match std::fs::remove_dir_all(&path) {
            Ok(()) => removed = removed.saturating_add(1),
            Err(error) => {
                tracing::warn!(kind = ?error.kind(), "could not remove an old backup set");
            }
        }
    }
    Ok(removed)
}

/// Removes `.tmp-<name>` folders whose name says they are more than a day older
/// than `now`. Best effort; a folder that does not parse is left alone.
fn clean_stale_temp(dir: &Path, now: i64) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let Ok(name) = entry.file_name().into_string() else {
            continue;
        };
        let Some(stamp) = name.strip_prefix(TEMP_PREFIX).and_then(parse_set_name) else {
            continue;
        };
        if now.saturating_sub(stamp) <= STALE_TEMP_SECS {
            continue;
        }
        let path = entry.path();
        if std::fs::symlink_metadata(&path).is_ok_and(|m| m.is_dir()) {
            let _ = std::fs::remove_dir_all(&path);
        }
    }
}

/// A shared handle on the real machine, for the scheduler.
pub fn real_platform() -> Arc<dyn Platform> {
    Arc::new(RealPlatform)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_set_name_is_the_time_and_reads_back() {
        // 2026-11-19T20:15:00Z
        let secs = 1_795_119_300;
        assert_eq!(set_name(secs), "20261119T201500Z");
        assert_eq!(parse_set_name("20261119T201500Z"), Some(secs));
        assert_eq!(parse_set_name("20261119T201500Z-2"), Some(secs));
        assert_eq!(set_name(0), "19700101T000000Z");
        assert_eq!(parse_set_name("19700101T000000Z"), Some(0));
        assert_eq!(set_name(951_782_400), "20000229T000000Z");
        for bad in [
            "",
            "status.json",
            ".tmp-20261119T201500Z",
            "20261119T201500",
            "20261319T201500Z",
            "20260231T201500Z",
            "20261119T251500Z",
            "20261119T201500Z-",
            "20261119T201500Z-x",
            "2026111XT201500Z",
        ] {
            assert_eq!(parse_set_name(bad), None, "{bad}");
        }
    }

    #[test]
    fn a_backup_folder_that_holds_the_data_directory_is_caught_by_its_spelling() {
        let data = Path::new("/srv/data");
        assert!(backup_dir_holds_data(data, Path::new("/srv/data")));
        assert!(backup_dir_holds_data(data, Path::new("/srv")));
        assert!(backup_dir_holds_data(data, Path::new("/srv/data/../data")));
        assert!(backup_dir_holds_data(data, Path::new("/")));
        assert!(!backup_dir_holds_data(
            data,
            Path::new("/srv/data/backups/auto")
        ));
        assert!(!backup_dir_holds_data(data, Path::new("/srv/backups")));
        assert!(!backup_dir_holds_data(data, Path::new("/srv/data2")));
    }

    #[test]
    fn the_uri_of_the_copy_is_encoded_and_immutable() {
        let dir = std::env::temp_dir().join(format!("ferret set uri {}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("a folder");
        let file = dir.join("a?b#c.sqlite");
        std::fs::write(&file, b"x").expect("a file");
        let uri = immutable_uri(&file).expect("a uri");
        assert!(uri.starts_with("file:/"), "{uri}");
        assert!(uri.ends_with("?immutable=1"), "{uri}");
        assert!(!uri.contains(' ') && !uri.contains('#'), "{uri}");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
