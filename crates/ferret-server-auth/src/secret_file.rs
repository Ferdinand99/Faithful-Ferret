//! The server's secret files: the format, and a loader and writer that are
//! strict about what they accept.
//!
//! Two files live in the data directory, apart from `session.key`:
//! `opaque_setup` (the OPAQUE key pair, OPRF seed and dummy key) and
//! `prelogin_secret` (the key behind the made-up pre-login answers). Both use
//! one format, with a version byte like every other Ferret format:
//!
//! | offset | length | field |
//! |---|---|---|
//! | 0 | 4 | magic `FSEC` (`0x46 0x53 0x45 0x43`) |
//! | 4 | 1 | format version, `0x01` |
//! | 5 | 1 | kind: `0x01` `opaque_setup`, `0x02` `prelogin_secret` |
//! | 6 | 1 | suite, `0x01` |
//! | 7 | 2 | payload length, u16 big-endian |
//! | 9 | n | payload: 128 bytes for `opaque_setup`, 32 for `prelogin_secret` |
//! | 9+n | 32 | SHA-256 of everything before it |
//!
//! An `opaque_setup` file is 169 bytes, a `prelogin_secret` file 73. The
//! checksum reveals a truncated or damaged file; it is **not** proof that the
//! file is authentic, because anyone who can write the file can write a
//! matching checksum. Protection against that is the file mode and the
//! directory it lives in.
//!
//! An unknown version, kind or suite is a hard error: the loader never
//! guesses. A damaged server file is the server's problem, not the client's:
//! callers turn a [`SecretFileError`] into
//! [`InternalKind::SecretFile`].
//!
//! Spec: Fase 1 § 11 (the file `opaque_setup`, kept apart and backed up as a
//! separate file).
//!
//! # Loading and writing
//!
//! [`read_secret_file`] looks at the path without following a link, opens the
//! file, and then looks at the open handle (never the path again), so a file
//! swapped in between cannot slip past the checks. It refuses a symbolic link
//! and anything that is not a regular file. On Unix it refuses a file with
//! any group or other permission bit set (`mode & 0o077 != 0`). It reads at
//! most 4 KiB.
//!
//! [`write_new_secret_file`] creates the file with `create_new` and mode 0600
//! from the first byte, syncs the file and then its directory, and removes a
//! half-written file. An existing file is never overwritten, and a symbolic
//! link at the path is never followed.
//!
//! Permissions can only be checked on Unix. On other platforms
//! [`permissions_enforced`] is `false`; a server that runs there is for
//! development only and should say so in its log.

use core::fmt;
use std::fs::{File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::Path;

use ferret_core::opaque::server_suite::SERVER_SETUP_LEN;
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::ct::ct_eq;
use crate::error::{AuthError, InternalKind};

/// Name of the file that holds the OPAQUE set-up, in the data directory.
pub const OPAQUE_SETUP_FILE: &str = "opaque_setup";

/// Name of the file that holds the pre-login secret, in the data directory.
pub const PRELOGIN_SECRET_FILE: &str = "prelogin_secret";

/// The first four bytes of every secret file: `FSEC`.
const MAGIC: [u8; 4] = *b"FSEC";

/// The only format version.
const FORMAT_VERSION: u8 = 0x01;

/// The only suite: ristretto255 with the Ferret OPAQUE cipher suite.
const SUITE_RISTRETTO255: u8 = 0x01;

/// Bytes before the payload: magic 4, version 1, kind 1, suite 1, length 2.
const HEADER_LEN: usize = 9;

/// Length of the SHA-256 checksum at the end.
const CHECKSUM_LEN: usize = 32;

/// Payload of an `opaque_setup` file: OPRF seed 64, private key 32, dummy
/// public key 32.
pub(crate) const OPAQUE_SETUP_PAYLOAD_LEN: usize = SERVER_SETUP_LEN;

/// Payload of a `prelogin_secret` file.
pub(crate) const PRELOGIN_PAYLOAD_LEN: usize = 32;

/// The loader reads at most this many bytes. A valid file is far smaller.
const MAX_FILE_LEN: usize = 4096;

/// The two kinds of secret file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileKind {
    /// `opaque_setup`.
    OpaqueSetup,
    /// `prelogin_secret`.
    PreloginSecret,
}

impl FileKind {
    /// The kind byte in the header.
    const fn code(self) -> u8 {
        match self {
            FileKind::OpaqueSetup => 0x01,
            FileKind::PreloginSecret => 0x02,
        }
    }

    /// The payload length this kind must have.
    pub(crate) const fn payload_len(self) -> usize {
        match self {
            FileKind::OpaqueSetup => OPAQUE_SETUP_PAYLOAD_LEN,
            FileKind::PreloginSecret => PRELOGIN_PAYLOAD_LEN,
        }
    }

    /// The whole file length for this kind.
    pub const fn file_len(self) -> usize {
        HEADER_LEN
            .saturating_add(self.payload_len())
            .saturating_add(CHECKSUM_LEN)
    }
}

/// Why a secret file could not be loaded, written or decoded.
///
/// None of the variants carries file content.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum SecretFileError {
    /// The file does not exist.
    Missing,
    /// The file exists already and was left as it was.
    AlreadyExists,
    /// The path is a directory, a device, a pipe or anything else that is not
    /// a regular file.
    NotARegularFile,
    /// The path is a symbolic link.
    Symlink,
    /// On Unix: the file is accessible to its group or to others.
    PermissionsTooOpen {
        /// The permission bits of the file (`0o640` and so on).
        mode: u32,
    },
    /// On Unix: the file belongs to a user other than the one the server runs
    /// as (and other than root).
    WrongOwner,
    /// The file does not start with `FSEC`.
    BadMagic,
    /// A format version this code does not know.
    UnsupportedVersion(u8),
    /// The file is of another kind than the one asked for, or of an unknown
    /// kind.
    WrongKind,
    /// A suite this code does not know.
    UnsupportedSuite(u8),
    /// The file is shorter than its header says, or the length field is not
    /// the one this kind has.
    BadLength,
    /// The checksum does not match: the file is damaged.
    BadChecksum,
    /// Bytes after the checksum.
    TrailingBytes,
    /// The payload is the right length but is not a valid key.
    PayloadInvalid,
    /// The operating system refused, with this kind of error.
    Io(io::ErrorKind),
}

impl fmt::Display for SecretFileError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let text = match self {
            SecretFileError::Missing => "secret file is missing",
            SecretFileError::AlreadyExists => "secret file exists already",
            SecretFileError::NotARegularFile => "secret file is not a regular file",
            SecretFileError::Symlink => "secret file is a symbolic link",
            SecretFileError::PermissionsTooOpen { .. } => {
                "secret file is accessible to group or others"
            }
            SecretFileError::WrongOwner => "secret file belongs to another user",
            SecretFileError::BadMagic => "secret file has the wrong magic",
            SecretFileError::UnsupportedVersion(_) => "secret file has an unknown version",
            SecretFileError::WrongKind => "secret file is of another kind",
            SecretFileError::UnsupportedSuite(_) => "secret file has an unknown suite",
            SecretFileError::BadLength => "secret file has the wrong length",
            SecretFileError::BadChecksum => "secret file is damaged (checksum)",
            SecretFileError::TrailingBytes => "secret file has bytes after its end",
            SecretFileError::PayloadInvalid => "secret file holds an invalid key",
            SecretFileError::Io(_) => "secret file could not be read or written",
        };
        f.write_str(text)
    }
}

impl std::error::Error for SecretFileError {}

impl From<SecretFileError> for AuthError {
    /// A damaged or missing server file is the server's fault, never the
    /// client's.
    fn from(_: SecretFileError) -> Self {
        AuthError::Internal(InternalKind::SecretFile)
    }
}

fn io_error(error: &io::Error) -> SecretFileError {
    if error.kind() == io::ErrorKind::NotFound {
        SecretFileError::Missing
    } else {
        SecretFileError::Io(error.kind())
    }
}

/// Builds the bytes of a secret file around `payload`.
///
/// The payload must have the length of its kind (128 bytes for
/// [`FileKind::OpaqueSetup`], 32 for [`FileKind::PreloginSecret`]), else
/// [`SecretFileError::BadLength`]. The result holds the secret and is wiped
/// when dropped.
pub fn encode_secret_file(
    kind: FileKind,
    payload: &[u8],
) -> Result<Zeroizing<Vec<u8>>, SecretFileError> {
    if payload.len() != kind.payload_len() {
        return Err(SecretFileError::BadLength);
    }
    let length = u16::try_from(payload.len()).map_err(|_| SecretFileError::BadLength)?;
    // The capacity is the final length, so the vector never moves.
    let mut out = Zeroizing::new(Vec::with_capacity(kind.file_len()));
    out.extend_from_slice(&MAGIC);
    out.push(FORMAT_VERSION);
    out.push(kind.code());
    out.push(SUITE_RISTRETTO255);
    out.extend_from_slice(&length.to_be_bytes());
    out.extend_from_slice(payload);
    let checksum = Sha256::digest(out.as_slice());
    out.extend_from_slice(&checksum);
    Ok(out)
}

/// Checks `bytes` as a secret file of `kind` and returns its payload.
///
/// Every defect has its own error and the order of the checks is fixed: magic,
/// version, kind, suite, length field, truncation, trailing bytes, checksum.
/// No input makes it panic.
pub fn decode_secret_file(
    kind: FileKind,
    bytes: &[u8],
) -> Result<Zeroizing<Vec<u8>>, SecretFileError> {
    // The part of the magic that is there must be right, so a file that is
    // not ours at all is not called "too short".
    let seen = bytes.len().min(MAGIC.len());
    if bytes.get(..seen) != MAGIC.get(..seen) {
        return Err(SecretFileError::BadMagic);
    }
    let Some((header, rest)) = bytes.split_first_chunk::<HEADER_LEN>() else {
        return Err(SecretFileError::BadLength);
    };
    let [_, _, _, _, version, file_kind, suite, len_high, len_low] = *header;
    if version != FORMAT_VERSION {
        return Err(SecretFileError::UnsupportedVersion(version));
    }
    if file_kind != kind.code() {
        return Err(SecretFileError::WrongKind);
    }
    if suite != SUITE_RISTRETTO255 {
        return Err(SecretFileError::UnsupportedSuite(suite));
    }
    let declared = usize::from(u16::from_be_bytes([len_high, len_low]));
    if declared != kind.payload_len() {
        return Err(SecretFileError::BadLength);
    }
    let Some((payload, tail)) = rest.split_at_checked(declared) else {
        return Err(SecretFileError::BadLength);
    };
    let Some((checksum, extra)) = tail.split_at_checked(CHECKSUM_LEN) else {
        return Err(SecretFileError::BadLength);
    };
    if !extra.is_empty() {
        return Err(SecretFileError::TrailingBytes);
    }
    let mut hash = Sha256::new();
    hash.update(header);
    hash.update(payload);
    if !ct_eq(&hash.finalize(), checksum) {
        return Err(SecretFileError::BadChecksum);
    }
    Ok(Zeroizing::new(payload.to_vec()))
}

/// Whether two looks at a path are at the same file (same device and inode).
#[cfg(unix)]
fn same_file(a: &std::fs::Metadata, b: &std::fs::Metadata) -> bool {
    use std::os::unix::fs::MetadataExt;
    (a.dev() == b.dev()) & (a.ino() == b.ino())
}

/// Without device and inode numbers the loader cannot compare; it relies on
/// the look at the open handle alone.
#[cfg(not(unix))]
fn same_file(_a: &std::fs::Metadata, _b: &std::fs::Metadata) -> bool {
    true
}

/// Whether the owner of a secret file is acceptable: the user the server runs
/// as, or root.
#[cfg(unix)]
fn owner_allowed(owner: u32, euid: u32) -> bool {
    (owner == euid) | (owner == 0)
}

/// The effective user id of this process, found without unsafe code and
/// without a new dependency.
///
/// * On Linux it is the owner of `/proc/self`. (A process that is not
///   dumpable has `/proc/self` owned by root, so its own files are then
///   refused unless root owns them: the check fails closed.)
/// * Where that is not available, and everywhere else, the owner of a probe
///   file that is created next to the secret file with `create_new`, looked at
///   with `fstat` and deleted again. That needs a directory the process can
///   write to.
#[cfg(unix)]
fn effective_uid(secret_path: &Path) -> io::Result<u32> {
    #[cfg(target_os = "linux")]
    let from_proc =
        std::fs::metadata("/proc/self").map(|m| std::os::unix::fs::MetadataExt::uid(&m));
    #[cfg(not(target_os = "linux"))]
    let from_proc: io::Result<u32> = Err(io::ErrorKind::Unsupported.into());
    from_proc.or_else(|_| probe_uid(secret_path))
}

/// The owner of a file that this process creates next to `secret_path`.
#[cfg(unix)]
fn probe_uid(secret_path: &Path) -> io::Result<u32> {
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
    use std::time::{SystemTime, UNIX_EPOCH};
    let dir = secret_path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.subsec_nanos());
    let probe = dir.join(format!(
        ".ferret-owner-probe-{}-{nanos}",
        std::process::id()
    ));
    let file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&probe)?;
    let uid = file.metadata().map(|m| m.uid());
    drop(file);
    let removed = std::fs::remove_file(&probe);
    let uid = uid?;
    removed.map(|()| uid)
}

/// Whether this platform lets the loader check and set file permissions.
///
/// `true` on Unix. On other platforms the loader cannot tell who may read a
/// file, so a server there is for development only and should log a warning.
pub const fn permissions_enforced() -> bool {
    cfg!(unix)
}

/// Loads the secret file at `path` and returns its payload.
///
/// The path is looked at once without following a link, the file is opened,
/// and every further check is made on the open handle. A symbolic link and
/// anything that is not a regular file is refused. On Unix a file with a
/// group or other permission bit is refused before a byte of it is read, and
/// so is a file whose owner is neither the user the server runs as nor root
/// (anyone who can write the directory could otherwise put a file of their
/// own in place before the first start). At most 4 KiB is read.
pub fn read_secret_file(
    path: &Path,
    kind: FileKind,
) -> Result<Zeroizing<Vec<u8>>, SecretFileError> {
    let before = std::fs::symlink_metadata(path).map_err(|e| io_error(&e))?;
    if before.file_type().is_symlink() {
        return Err(SecretFileError::Symlink);
    }
    if !before.is_file() {
        return Err(SecretFileError::NotARegularFile);
    }
    let file = File::open(path).map_err(|e| io_error(&e))?;
    let meta = file.metadata().map_err(|e| io_error(&e))?;
    // The handle must be a regular file, and the file the path showed a moment
    // ago. (`&` and not `&&`: one decision, no short cut.)
    if !(meta.is_file() & same_file(&before, &meta)) {
        return Err(SecretFileError::NotARegularFile);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = meta.permissions().mode();
        if mode & 0o077 != 0 {
            return Err(SecretFileError::PermissionsTooOpen {
                mode: mode & 0o7777,
            });
        }
        // The owner of the open file, not of the path.
        let euid = effective_uid(path).map_err(|e| io_error(&e))?;
        if !owner_allowed(std::os::unix::fs::MetadataExt::uid(&meta), euid) {
            return Err(SecretFileError::WrongOwner);
        }
    }
    // One byte more than the largest file, so that a bigger one is seen. The
    // buffer is allocated once, so no copy of the secret is left behind by a
    // growing vector.
    let mut buffer = Zeroizing::new(Vec::with_capacity(MAX_FILE_LEN.saturating_add(1)));
    let limit = u64::try_from(MAX_FILE_LEN.saturating_add(1)).unwrap_or(u64::MAX);
    file.take(limit)
        .read_to_end(&mut buffer)
        .map_err(|e| io_error(&e))?;
    if buffer.len() > MAX_FILE_LEN {
        return Err(SecretFileError::BadLength);
    }
    decode_secret_file(kind, &buffer)
}

/// Creates the secret file at `path` with `payload`, if no file is there.
///
/// The file is made with `create_new` and mode 0600 from the start, then the
/// file and its directory are synced. A file that could not be written in
/// full is removed again. An existing file (or a link at the path) is never
/// touched: the result is [`SecretFileError::AlreadyExists`].
pub fn write_new_secret_file(
    path: &Path,
    kind: FileKind,
    payload: &[u8],
) -> Result<(), SecretFileError> {
    let bytes = encode_secret_file(kind, payload)?;
    create_and_fill(path, &bytes, |file, data| file.write_all(data))
}

/// Creates the file, lets `fill` write it, syncs, and removes the file again
/// if anything after the creation fails. `fill` is a parameter so a test can
/// make the write fail half way.
fn create_and_fill(
    path: &Path,
    bytes: &[u8],
    fill: impl FnOnce(&mut File, &[u8]) -> io::Result<()>,
) -> Result<(), SecretFileError> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(path).map_err(|e| {
        match e.kind() {
            io::ErrorKind::AlreadyExists => SecretFileError::AlreadyExists,
            // A missing directory is not a missing secret file.
            kind => SecretFileError::Io(kind),
        }
    })?;
    let written = fill(&mut file, bytes).and_then(|()| file.sync_all());
    drop(file);
    written
        .and_then(|()| sync_directory(path))
        .map_err(|error| {
            // Best effort: the error to report is the first one.
            let _ = std::fs::remove_file(path);
            SecretFileError::Io(error.kind())
        })
}

/// Syncs the directory that holds `path`, so the new entry survives a crash.
#[cfg(unix)]
fn sync_directory(path: &Path) -> io::Result<()> {
    // A bare file name has the empty path as its parent: that is ".".
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    File::open(parent)?.sync_all()
}

/// A directory cannot be opened and synced here; the file itself was synced.
#[cfg(not(unix))]
fn sync_directory(_path: &Path) -> io::Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_failed_write_removes_the_half_written_file() {
        let dir = std::env::temp_dir().join(format!("ferret-sf-unit-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("half");
        let result = create_and_fill(&path, &[1, 2, 3], |file, data| {
            file.write_all(&data[..1])?;
            Err(io::Error::new(io::ErrorKind::StorageFull, "disk full"))
        });
        assert_eq!(result, Err(SecretFileError::Io(io::ErrorKind::StorageFull)));
        assert!(!path.exists(), "the half-written file was left behind");
        // The same seam leaves a good file alone and reports no error.
        assert_eq!(
            create_and_fill(&path, &[7; 4], |file, data| file.write_all(data)),
            Ok(())
        );
        assert_eq!(std::fs::read(&path).unwrap(), [7; 4]);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn only_the_server_user_and_root_may_own_a_secret_file() {
        // A server that runs as an ordinary user (1000) ...
        assert!(owner_allowed(1000, 1000));
        assert!(owner_allowed(0, 1000));
        assert!(!owner_allowed(1001, 1000));
        assert!(!owner_allowed(65534, 1000));
        // ... and one that runs as root.
        assert!(owner_allowed(0, 0));
        assert!(!owner_allowed(1000, 0));
    }

    #[cfg(unix)]
    #[test]
    fn the_effective_uid_is_the_owner_of_a_file_we_create() {
        use std::os::unix::fs::MetadataExt;
        let dir = std::env::temp_dir().join(format!("ferret-uid-unit-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("opaque_setup");
        let own = std::fs::File::create(dir.join("own")).unwrap();
        let expected = own.metadata().unwrap().uid();
        // The way that is used first (the owner of /proc/self on Linux) ...
        assert_eq!(effective_uid(&path).unwrap(), expected);
        // ... and the probe file, which is the way on other systems.
        assert_eq!(probe_uid(&path).unwrap(), expected);
        // The probe leaves nothing behind.
        let left: Vec<_> = std::fs::read_dir(&dir)
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .collect();
        assert_eq!(left, [std::ffi::OsString::from("own")]);
        // No directory to write to, no answer.
        assert!(probe_uid(&dir.join("none").join("opaque_setup")).is_err());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn same_file_tells_two_files_apart() {
        let dir = std::env::temp_dir().join(format!("ferret-same-unit-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let (a, b) = (dir.join("a"), dir.join("b"));
        std::fs::write(&a, b"x").unwrap();
        std::fs::write(&b, b"x").unwrap();
        let (ma, mb) = (
            std::fs::metadata(&a).unwrap(),
            std::fs::metadata(&b).unwrap(),
        );
        assert!(same_file(&ma, &std::fs::metadata(&a).unwrap()));
        assert!(!same_file(&ma, &mb));
        // A second name for the same inode is the same file.
        let link = dir.join("link");
        std::fs::hard_link(&a, &link).unwrap();
        assert!(same_file(&ma, &std::fs::metadata(&link).unwrap()));
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn io_errors_keep_only_their_kind() {
        assert_eq!(
            io_error(&io::Error::from(io::ErrorKind::NotFound)),
            SecretFileError::Missing
        );
        assert_eq!(
            io_error(&io::Error::new(
                io::ErrorKind::PermissionDenied,
                "/secret/path"
            )),
            SecretFileError::Io(io::ErrorKind::PermissionDenied)
        );
    }

    #[test]
    fn a_secret_file_error_is_an_internal_error() {
        let all = [
            SecretFileError::Missing,
            SecretFileError::AlreadyExists,
            SecretFileError::BadChecksum,
            SecretFileError::PermissionsTooOpen { mode: 0o640 },
            SecretFileError::WrongOwner,
        ];
        for error in all {
            assert_eq!(
                AuthError::from(error),
                AuthError::Internal(InternalKind::SecretFile)
            );
            assert!(!error.to_string().is_empty());
        }
    }
}
