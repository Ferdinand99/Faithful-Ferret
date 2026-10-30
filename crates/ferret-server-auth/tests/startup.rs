//! The secret files, the keys they hold and the decision on start.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::arithmetic_side_effects
)]

use std::path::{Path, PathBuf};
use std::sync::Barrier;
use std::sync::atomic::{AtomicU32, Ordering};

use ferret_core::opaque::server_suite::opaque_ke::ServerSetup;
use ferret_core::opaque::server_suite::{FerretSuite, Rng06};
use ferret_core::{ReplayRng, SecureRng, TestRng};
use ferret_server_auth::{
    CreatePolicy, FileKind, FileOrigin, LoadedSecrets, OPAQUE_SETUP_FILE, PRELOGIN_SECRET_FILE,
    PreloginSecret, SecretFileError, ServerKeys, SetupFingerprint, StartupDecision, StartupRefusal,
    decode_secret_file, encode_secret_file, load_or_create, permissions_enforced, read_secret_file,
    startup_decision, write_new_secret_file,
};
use sha2::{Digest, Sha256};

// ---------------------------------------------------------------- helpers

/// A fresh directory that is removed again at the end of the test.
struct TempDir(PathBuf);

impl TempDir {
    fn new() -> Self {
        static COUNTER: AtomicU32 = AtomicU32::new(0);
        let path = std::env::temp_dir().join(format!(
            "ferret-startup-{}-{}",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&path).unwrap();
        Self(path)
    }

    fn path(&self) -> &Path {
        &self.0
    }

    fn names(&self) -> Vec<String> {
        let mut names: Vec<String> = std::fs::read_dir(&self.0)
            .unwrap()
            .map(|e| e.unwrap().file_name().into_string().unwrap())
            .collect();
        names.sort();
        names
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(&self.0, std::fs::Permissions::from_mode(0o755));
        }
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn rng(seed: &str) -> TestRng {
    TestRng::new(seed.as_bytes())
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    bytes.iter().fold(String::new(), |mut out, b| {
        let _ = write!(out, "{b:02x}");
        out
    })
}

fn setup_file(seed: &str) -> Vec<u8> {
    let keys = ServerKeys::generate(&mut rng(seed)).unwrap();
    encode_secret_file(FileKind::OpaqueSetup, &keys.payload())
        .unwrap()
        .to_vec()
}

fn prelogin_file(seed: &str) -> Vec<u8> {
    let secret = PreloginSecret::generate(&mut rng(seed));
    encode_secret_file(FileKind::PreloginSecret, &secret.payload())
        .unwrap()
        .to_vec()
}

/// Secrets as a first start finds them, with the given origins.
fn secrets(seed: &str, setup: FileOrigin, prelogin: FileOrigin) -> LoadedSecrets {
    let mut r = rng(seed);
    LoadedSecrets {
        keys: ServerKeys::generate(&mut r).unwrap(),
        prelogin: PreloginSecret::generate(&mut r),
        setup_origin: setup,
        prelogin_origin: prelogin,
    }
}

// ----------------------------------------------------------- file format

#[test]
fn file_roundtrip_opaque_setup_is_169_bytes() {
    let keys = ServerKeys::generate(&mut rng("roundtrip")).unwrap();
    let payload = keys.payload();
    assert_eq!(payload.len(), 128);
    let file = encode_secret_file(FileKind::OpaqueSetup, &payload).unwrap();
    assert_eq!(file.len(), 169);
    assert_eq!(FileKind::OpaqueSetup.file_len(), 169);
    // Header: magic, version, kind, suite, length 128.
    assert_eq!(&file[..9], b"FSEC\x01\x01\x01\x00\x80");
    assert_eq!(&file[9..137], &payload[..]);
    assert_eq!(&file[137..], Sha256::digest(&file[..137]).as_slice());
    let back = decode_secret_file(FileKind::OpaqueSetup, &file).unwrap();
    assert_eq!(&back[..], &payload[..]);
}

#[test]
fn file_roundtrip_prelogin_is_73_bytes() {
    let secret = PreloginSecret::generate(&mut rng("roundtrip"));
    let payload = secret.payload();
    assert_eq!(payload.len(), 32);
    let file = encode_secret_file(FileKind::PreloginSecret, &payload).unwrap();
    assert_eq!(file.len(), 73);
    assert_eq!(FileKind::PreloginSecret.file_len(), 73);
    assert_eq!(&file[..9], b"FSEC\x01\x02\x01\x00\x20");
    assert_eq!(&file[9..41], &payload[..]);
    assert_eq!(&file[41..], Sha256::digest(&file[..41]).as_slice());
    let back = decode_secret_file(FileKind::PreloginSecret, &file).unwrap();
    assert_eq!(&back[..], &payload[..]);
}

#[test]
fn encode_refuses_a_payload_of_the_wrong_length() {
    for len in [0usize, 31, 33, 127, 129] {
        let payload = vec![1u8; len];
        let want = if len == 32 {
            Ok(())
        } else {
            Err(SecretFileError::BadLength)
        };
        assert_eq!(
            encode_secret_file(FileKind::PreloginSecret, &payload).map(drop),
            want
        );
    }
    assert_eq!(
        encode_secret_file(FileKind::OpaqueSetup, &[0u8; 32]).map(drop),
        Err(SecretFileError::BadLength)
    );
}

#[test]
fn decode_rejects_bad_magic() {
    let mut file = prelogin_file("magic");
    file[0] = b'X';
    assert_eq!(
        decode_secret_file(FileKind::PreloginSecret, &file).map(drop),
        Err(SecretFileError::BadMagic)
    );
    // A short file that is not ours is not "too short".
    assert_eq!(
        decode_secret_file(FileKind::PreloginSecret, b"PK").map(drop),
        Err(SecretFileError::BadMagic)
    );
    assert_eq!(
        decode_secret_file(FileKind::PreloginSecret, b"FSE").map(drop),
        Err(SecretFileError::BadLength)
    );
}

#[test]
fn decode_rejects_unsupported_version_2() {
    let mut file = prelogin_file("version");
    file[4] = 2;
    assert_eq!(
        decode_secret_file(FileKind::PreloginSecret, &file).map(drop),
        Err(SecretFileError::UnsupportedVersion(2))
    );
    file[4] = 0;
    assert_eq!(
        decode_secret_file(FileKind::PreloginSecret, &file).map(drop),
        Err(SecretFileError::UnsupportedVersion(0))
    );
}

#[test]
fn decode_rejects_wrong_kind() {
    let setup = setup_file("kind");
    let prelogin = prelogin_file("kind");
    assert_eq!(
        decode_secret_file(FileKind::PreloginSecret, &setup).map(drop),
        Err(SecretFileError::WrongKind)
    );
    assert_eq!(
        decode_secret_file(FileKind::OpaqueSetup, &prelogin).map(drop),
        Err(SecretFileError::WrongKind)
    );
    // An unknown kind byte is the same error.
    let mut unknown = prelogin;
    unknown[5] = 0x03;
    assert_eq!(
        decode_secret_file(FileKind::PreloginSecret, &unknown).map(drop),
        Err(SecretFileError::WrongKind)
    );
}

#[test]
fn decode_rejects_unsupported_suite() {
    let mut file = prelogin_file("suite");
    file[6] = 2;
    assert_eq!(
        decode_secret_file(FileKind::PreloginSecret, &file).map(drop),
        Err(SecretFileError::UnsupportedSuite(2))
    );
}

#[test]
fn decode_rejects_flipped_payload_bit() {
    let file = setup_file("flip");
    for byte in 9..137 {
        for bit in 0..8 {
            let mut broken = file.clone();
            broken[byte] ^= 1 << bit;
            assert_eq!(
                decode_secret_file(FileKind::OpaqueSetup, &broken).map(drop),
                Err(SecretFileError::BadChecksum),
                "byte {byte} bit {bit}"
            );
        }
    }
    // A flipped bit in the checksum itself.
    let mut broken = file;
    broken[168] ^= 1;
    assert_eq!(
        decode_secret_file(FileKind::OpaqueSetup, &broken).map(drop),
        Err(SecretFileError::BadChecksum)
    );
}

#[test]
fn decode_rejects_every_flipped_bit_anywhere() {
    let file = setup_file("every-bit");
    for byte in 0..file.len() {
        for bit in 0..8 {
            let mut broken = file.clone();
            broken[byte] ^= 1 << bit;
            assert!(
                decode_secret_file(FileKind::OpaqueSetup, &broken).is_err(),
                "byte {byte} bit {bit} was accepted"
            );
        }
    }
}

#[test]
fn decode_rejects_lying_length_field() {
    for kind_file in [
        (FileKind::OpaqueSetup, setup_file("len")),
        (FileKind::PreloginSecret, prelogin_file("len")),
    ] {
        let (kind, file) = kind_file;
        for lie in [0u16, 1, 31, 33, 127, 129, 0xFFFF] {
            if usize::from(lie) == kind.file_len() - 41 {
                continue;
            }
            let mut broken = file.clone();
            broken[7..9].copy_from_slice(&lie.to_be_bytes());
            assert_eq!(
                decode_secret_file(kind, &broken).map(drop),
                Err(SecretFileError::BadLength),
                "{kind:?} length {lie}"
            );
        }
    }
}

#[test]
fn decode_rejects_trailing_byte() {
    for extra in [1usize, 2, 32, 4000] {
        let mut file = prelogin_file("trailing");
        file.extend(std::iter::repeat_n(0u8, extra));
        assert_eq!(
            decode_secret_file(FileKind::PreloginSecret, &file).map(drop),
            Err(SecretFileError::TrailingBytes),
            "{extra} extra bytes"
        );
    }
}

#[test]
fn decode_rejects_every_truncation() {
    let file = setup_file("truncation");
    assert_eq!(file.len(), 169);
    for len in 0..169 {
        assert!(
            decode_secret_file(FileKind::OpaqueSetup, &file[..len]).is_err(),
            "length {len}"
        );
    }
    assert!(decode_secret_file(FileKind::OpaqueSetup, &file).is_ok());
    // The same for the shorter kind, and for a file cut in front.
    let small = prelogin_file("truncation");
    for len in 0..73 {
        assert!(decode_secret_file(FileKind::PreloginSecret, &small[..len]).is_err());
        assert!(decode_secret_file(FileKind::PreloginSecret, &small[73 - len..]).is_err());
    }
}

// ------------------------------------------------------- reading, writing

#[test]
fn write_then_read_returns_the_payload() {
    let dir = TempDir::new();
    let path = dir.path().join("prelogin_secret");
    write_new_secret_file(&path, FileKind::PreloginSecret, &[9u8; 32]).unwrap();
    let back = read_secret_file(&path, FileKind::PreloginSecret).unwrap();
    assert_eq!(&back[..], &[9u8; 32]);
    assert_eq!(
        read_secret_file(&path, FileKind::OpaqueSetup).map(drop),
        Err(SecretFileError::WrongKind)
    );
    assert_eq!(
        read_secret_file(&dir.path().join("nothing"), FileKind::PreloginSecret).map(drop),
        Err(SecretFileError::Missing)
    );
}

#[test]
fn write_new_never_overwrites() {
    let dir = TempDir::new();
    let path = dir.path().join("opaque_setup");
    let first = ServerKeys::generate(&mut rng("first")).unwrap().payload();
    let second = ServerKeys::generate(&mut rng("second")).unwrap().payload();
    write_new_secret_file(&path, FileKind::OpaqueSetup, &first).unwrap();
    let before = std::fs::read(&path).unwrap();
    assert_eq!(
        write_new_secret_file(&path, FileKind::OpaqueSetup, &second),
        Err(SecretFileError::AlreadyExists)
    );
    assert_eq!(std::fs::read(&path).unwrap(), before);
    assert_eq!(dir.names(), ["opaque_setup"]);
}

#[test]
fn write_new_refuses_a_payload_of_the_wrong_length_and_writes_nothing() {
    let dir = TempDir::new();
    let path = dir.path().join("opaque_setup");
    assert_eq!(
        write_new_secret_file(&path, FileKind::OpaqueSetup, &[0u8; 64]),
        Err(SecretFileError::BadLength)
    );
    assert!(dir.names().is_empty());
}

#[test]
fn an_error_of_the_file_system_keeps_only_its_kind() {
    let dir = TempDir::new();
    let file = dir.path().join("plain");
    std::fs::write(&file, b"x").unwrap();
    // A path below a file: not "missing", an error of the file system.
    assert!(matches!(
        read_secret_file(&file.join("prelogin_secret"), FileKind::PreloginSecret).map(drop),
        Err(SecretFileError::Io(_))
    ));
}

#[test]
fn a_truncated_file_is_waited_for_and_then_refused() {
    let dir = TempDir::new();
    load_or_create(dir.path(), CreatePolicy::CreateIfMissing, &mut rng("short")).unwrap();
    let path = dir.path().join(OPAQUE_SETUP_FILE);
    let mut bytes = std::fs::read(&path).unwrap();
    bytes.truncate(100);
    std::fs::write(&path, &bytes).unwrap();
    // Another start might still be writing it, so the loader looks again for
    // a moment (two seconds) before it gives up.
    let started = std::time::Instant::now();
    assert_eq!(
        load_or_create(dir.path(), CreatePolicy::MustExist, &mut rng("x")).map(drop),
        Err(SecretFileError::BadLength)
    );
    assert!(started.elapsed() >= std::time::Duration::from_secs(1));
    assert_eq!(std::fs::read(&path).unwrap(), bytes);
}

#[test]
fn the_loader_reads_at_most_4_kib() {
    let dir = TempDir::new();
    let path = dir.path().join("prelogin_secret");
    write_new_secret_file(&path, FileKind::PreloginSecret, &[1u8; 32]).unwrap();
    let mut big = std::fs::read(&path).unwrap();
    big.resize(1_000_000, 0);
    std::fs::write(&path, &big).unwrap();
    assert_eq!(
        read_secret_file(&path, FileKind::PreloginSecret).map(drop),
        Err(SecretFileError::BadLength)
    );
    // A file just over the real length is trailing bytes.
    big.truncate(74);
    std::fs::write(&path, &big).unwrap();
    assert_eq!(
        read_secret_file(&path, FileKind::PreloginSecret).map(drop),
        Err(SecretFileError::TrailingBytes)
    );
}

#[test]
fn failed_write_leaves_no_file() {
    let dir = TempDir::new();
    let missing_parent = dir.path().join("no-such-dir").join("opaque_setup");
    let payload = ServerKeys::generate(&mut rng("failed")).unwrap().payload();
    assert!(matches!(
        write_new_secret_file(&missing_parent, FileKind::OpaqueSetup, &payload),
        Err(SecretFileError::Io(_))
    ));
    assert!(dir.names().is_empty());

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let locked = dir.path().join("locked");
        std::fs::create_dir(&locked).unwrap();
        std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o555)).unwrap();
        // The superuser ignores directory permissions, so there is nothing to
        // test as that user (the unit test of the writer covers the clean-up).
        if std::fs::write(locked.join("probe"), b"x").is_ok() {
            eprintln!("skipped: running as a user that ignores directory permissions");
            return;
        }
        let result = write_new_secret_file(
            &locked.join("opaque_setup"),
            FileKind::OpaqueSetup,
            &payload,
        );
        assert_eq!(
            result,
            Err(SecretFileError::Io(std::io::ErrorKind::PermissionDenied))
        );
        assert!(std::fs::read_dir(&locked).unwrap().next().is_none());
    }
}

#[cfg(unix)]
mod unix {
    use super::*;
    use std::os::unix::fs::{PermissionsExt, symlink};

    fn mode_of(path: &Path) -> u32 {
        std::fs::metadata(path).unwrap().permissions().mode() & 0o7777
    }

    #[test]
    fn created_file_is_mode_0600() {
        let dir = TempDir::new();
        let loaded =
            load_or_create(dir.path(), CreatePolicy::CreateIfMissing, &mut rng("mode")).unwrap();
        assert_eq!(loaded.setup_origin, FileOrigin::Created);
        assert_eq!(mode_of(&dir.path().join(OPAQUE_SETUP_FILE)), 0o600);
        assert_eq!(mode_of(&dir.path().join(PRELOGIN_SECRET_FILE)), 0o600);
    }

    #[test]
    fn loader_refuses_0640_and_0604_but_accepts_0400_and_0600() {
        let dir = TempDir::new();
        let path = dir.path().join("prelogin_secret");
        write_new_secret_file(&path, FileKind::PreloginSecret, &[5u8; 32]).unwrap();
        for mode in [0o640u32, 0o604, 0o644, 0o660, 0o666, 0o601, 0o610, 0o677] {
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode)).unwrap();
            assert_eq!(
                read_secret_file(&path, FileKind::PreloginSecret).map(drop),
                Err(SecretFileError::PermissionsTooOpen { mode }),
                "mode {mode:o}"
            );
        }
        for mode in [0o400u32, 0o600, 0o700] {
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode)).unwrap();
            assert!(
                read_secret_file(&path, FileKind::PreloginSecret).is_ok(),
                "mode {mode:o}"
            );
        }
    }

    #[test]
    fn load_or_create_never_replaces_a_file_with_open_permissions() {
        let dir = TempDir::new();
        load_or_create(dir.path(), CreatePolicy::CreateIfMissing, &mut rng("open")).unwrap();
        let path = dir.path().join(OPAQUE_SETUP_FILE);
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        let before = std::fs::read(&path).unwrap();
        for policy in [CreatePolicy::CreateIfMissing, CreatePolicy::MustExist] {
            assert_eq!(
                load_or_create(dir.path(), policy, &mut rng("again")).map(drop),
                Err(SecretFileError::PermissionsTooOpen { mode: 0o644 })
            );
        }
        assert_eq!(std::fs::read(&path).unwrap(), before);
    }

    #[test]
    fn loader_refuses_symlink_and_directory() {
        let dir = TempDir::new();
        let real = dir.path().join("real");
        write_new_secret_file(&real, FileKind::PreloginSecret, &[5u8; 32]).unwrap();
        let link = dir.path().join("link");
        symlink(&real, &link).unwrap();
        assert_eq!(
            read_secret_file(&link, FileKind::PreloginSecret).map(drop),
            Err(SecretFileError::Symlink)
        );
        let dangling = dir.path().join("dangling");
        symlink(dir.path().join("gone"), &dangling).unwrap();
        assert_eq!(
            read_secret_file(&dangling, FileKind::PreloginSecret).map(drop),
            Err(SecretFileError::Symlink)
        );
        let sub = dir.path().join("sub");
        std::fs::create_dir(&sub).unwrap();
        assert_eq!(
            read_secret_file(&sub, FileKind::PreloginSecret).map(drop),
            Err(SecretFileError::NotARegularFile)
        );
        // A link to a directory is a link first.
        let dir_link = dir.path().join("dir_link");
        symlink(&sub, &dir_link).unwrap();
        assert_eq!(
            read_secret_file(&dir_link, FileKind::PreloginSecret).map(drop),
            Err(SecretFileError::Symlink)
        );
    }

    #[test]
    fn the_writer_never_follows_a_link_at_the_path() {
        let dir = TempDir::new();
        let target = dir.path().join("target");
        let link = dir.path().join("opaque_setup");
        symlink(&target, &link).unwrap();
        let payload = ServerKeys::generate(&mut rng("link")).unwrap().payload();
        assert_eq!(
            write_new_secret_file(&link, FileKind::OpaqueSetup, &payload),
            Err(SecretFileError::AlreadyExists)
        );
        assert!(!target.exists());
    }

    /// Gives the file to another user. Only the superuser can; anyone else
    /// has nothing to test.
    fn give_away(path: &Path, uid: u32) -> bool {
        match std::os::unix::fs::chown(path, Some(uid), None) {
            Ok(()) => true,
            Err(_) => {
                eprintln!("skipped: this user cannot give a file to another user");
                false
            }
        }
    }

    #[test]
    fn loader_refuses_a_file_of_another_owner() {
        let dir = TempDir::new();
        let path = dir.path().join("prelogin_secret");
        write_new_secret_file(&path, FileKind::PreloginSecret, &[5u8; 32]).unwrap();
        // The file is ours, mode 0600: fine.
        assert!(read_secret_file(&path, FileKind::PreloginSecret).is_ok());
        if !give_away(&path, 54321) {
            return;
        }
        assert_eq!(mode_of(&path), 0o600);
        assert_eq!(
            read_secret_file(&path, FileKind::PreloginSecret).map(drop),
            Err(SecretFileError::WrongOwner)
        );
        // Root owns it: accepted, whoever the server runs as.
        assert!(give_away(&path, 0));
        assert!(read_secret_file(&path, FileKind::PreloginSecret).is_ok());
    }

    #[test]
    fn a_file_planted_by_another_user_is_never_adopted() {
        // The first start: someone who can write the directory puts valid
        // files of their own in place first.
        let dir = TempDir::new();
        let planted = load_or_create(
            dir.path(),
            CreatePolicy::CreateIfMissing,
            &mut rng("attacker"),
        )
        .unwrap();
        if !give_away(&dir.path().join(OPAQUE_SETUP_FILE), 54321) {
            return;
        }
        assert!(give_away(&dir.path().join(PRELOGIN_SECRET_FILE), 54321));
        let before = std::fs::read(dir.path().join(OPAQUE_SETUP_FILE)).unwrap();
        for policy in [CreatePolicy::CreateIfMissing, CreatePolicy::MustExist] {
            assert_eq!(
                load_or_create(dir.path(), policy, &mut rng("server")).map(drop),
                Err(SecretFileError::WrongOwner)
            );
        }
        assert_eq!(
            std::fs::read(dir.path().join(OPAQUE_SETUP_FILE)).unwrap(),
            before
        );
        assert_eq!(dir.names(), ["opaque_setup", "prelogin_secret"]);
        drop(planted);
    }

    #[test]
    fn permissions_are_enforced_on_unix() {
        assert!(permissions_enforced());
    }
}

#[cfg(not(unix))]
#[test]
fn permissions_are_not_enforced_here() {
    assert!(!permissions_enforced());
}

// ------------------------------------------------------------------- keys

#[test]
fn generate_is_replayable_with_replay_rng() {
    let draws: Vec<Vec<u8>> = {
        let mut source = rng("replay");
        (0..3)
            .map(|_| {
                let mut d = vec![0u8; 64];
                source.fill(&mut d);
                d
            })
            .collect()
    };
    let mut replay = ReplayRng::new(draws.clone());
    let keys = ServerKeys::generate(&mut replay).unwrap();
    replay.finish().unwrap();
    // The draws are the ones `ServerSetup::new` makes, in its order.
    let mut again = ReplayRng::new(draws.clone());
    let library = ServerSetup::<FerretSuite>::new(&mut Rng06(&mut again));
    assert_eq!(&keys.payload()[..], library.serialize().as_slice());
    // And the same draws give the same keys.
    let twin = ServerKeys::generate(&mut ReplayRng::new(draws)).unwrap();
    assert_eq!(&keys.payload()[..], &twin.payload()[..]);
    assert_eq!(keys.fingerprint(), twin.fingerprint());

    // The pre-login secret is one draw of 32 bytes, used as it is.
    let mut one = ReplayRng::new(vec![vec![0xA5; 32]]);
    let secret = PreloginSecret::generate(&mut one);
    one.finish().unwrap();
    assert_eq!(&secret.payload()[..], &[0xA5u8; 32]);
}

#[test]
fn keys_round_trip_through_their_payload() {
    let keys = ServerKeys::generate(&mut rng("payload")).unwrap();
    let payload = keys.payload();
    let back = ServerKeys::from_payload(&payload).unwrap();
    assert_eq!(&back.payload()[..], &payload[..]);
    assert_eq!(back.public_key(), keys.public_key());
    assert_eq!(back.dummy_public_key(), keys.dummy_public_key());
    assert_eq!(back.fingerprint(), keys.fingerprint());
    assert_eq!(&keys.dummy_public_key()[..], &payload[96..128]);
    assert_ne!(keys.public_key(), keys.dummy_public_key());
}

#[test]
fn from_payload_refuses_what_is_not_a_set_up() {
    let payload = ServerKeys::generate(&mut rng("bad-payload"))
        .unwrap()
        .payload();
    // The library's parser would ignore a tail; this must not.
    let mut longer = payload.to_vec();
    longer.push(0);
    for bad in [&[][..], &payload[..127], &longer[..]] {
        assert_eq!(
            ServerKeys::from_payload(bad).map(drop),
            Err(SecretFileError::PayloadInvalid)
        );
    }
    // Private key zero, and not a canonical scalar.
    let mut zero_key = payload.to_vec();
    zero_key[64..96].fill(0);
    assert_eq!(
        ServerKeys::from_payload(&zero_key).map(drop),
        Err(SecretFileError::PayloadInvalid)
    );
    let mut big_key = payload.to_vec();
    big_key[64..96].fill(0xFF);
    assert_eq!(
        ServerKeys::from_payload(&big_key).map(drop),
        Err(SecretFileError::PayloadInvalid)
    );
    // A dummy key that is no point.
    let mut bad_dummy = payload.to_vec();
    bad_dummy[96..128].fill(0xFF);
    assert_eq!(
        ServerKeys::from_payload(&bad_dummy).map(drop),
        Err(SecretFileError::PayloadInvalid)
    );
    for len in [0usize, 31, 33, 64] {
        assert_eq!(
            PreloginSecret::from_payload(&vec![1u8; len]).map(drop),
            Err(SecretFileError::PayloadInvalid)
        );
    }
}

#[test]
fn secrets_never_appear_in_debug_output() {
    let mut r = rng("debug");
    let keys = ServerKeys::generate(&mut r).unwrap();
    let prelogin = PreloginSecret::generate(&mut r);
    let loaded = LoadedSecrets {
        keys: ServerKeys::from_payload(&keys.payload()).unwrap(),
        prelogin: PreloginSecret::from_payload(&prelogin.payload()).unwrap(),
        setup_origin: FileOrigin::Created,
        prelogin_origin: FileOrigin::Existing,
    };
    let shown = [
        format!("{keys:?}"),
        format!("{prelogin:?}"),
        format!("{loaded:?}"),
        format!("{keys:#?}"),
        format!("{loaded:#?}"),
    ];
    for text in &shown {
        assert!(text.contains("[redacted]"), "{text}");
    }
    let mut parts: Vec<Vec<u8>> = Vec::new();
    for payload in [keys.payload().to_vec(), prelogin.payload().to_vec()] {
        // The whole payload, and every 4-byte piece of it, in hex and as a
        // decimal list.
        parts.push(payload.clone());
        parts.extend(payload.windows(4).map(<[u8]>::to_vec));
    }
    for text in &shown {
        for part in &parts {
            assert!(!text.contains(&hex(part)), "hex of a secret in {text}");
            let decimal = part
                .iter()
                .map(u8::to_string)
                .collect::<Vec<_>>()
                .join(", ");
            assert!(!text.contains(&decimal), "bytes of a secret in {text}");
        }
    }
}

/// The keys and the fingerprint of a fixed, synthetic set-up. A change here
/// means the draws of `ServerSetup::new` or the label changed.
#[test]
fn fingerprint_is_a_hash_of_label_and_the_whole_payload() {
    let keys = ServerKeys::generate(&mut rng("fingerprint-vector")).unwrap();
    let payload = keys.payload();
    assert_eq!(payload.len(), 128);
    let mut hash = Sha256::new();
    hash.update(b"ferret/v1/setup-fp");
    hash.update(&payload[..]);
    let expected: [u8; 32] = hash.finalize().into();
    assert_eq!(keys.fingerprint(), SetupFingerprint(expected));

    assert_eq!(
        hex(&keys.public_key()),
        "ba74c53b9638ab6ac03dd7787ddcde71ad7617f3506059038c131bc29a7e1e2f"
    );
    assert_eq!(
        hex(&keys.dummy_public_key()),
        "f4b00f2fcee45af18dec7ba97cf3e55dfe944238e6498c1b28d3e795ecd53e5b"
    );
    assert_eq!(
        hex(&keys.fingerprint().0),
        "10cbcf4d7a9e212ff62562b87f3e73425bd87c1737da445302aec2bdb21448db"
    );
}

#[test]
fn fingerprint_changes_with_the_seed_the_key_or_the_dummy() {
    let keys = ServerKeys::generate(&mut rng("fp-base")).unwrap();
    let base = keys.payload().to_vec();

    // A different OPRF seed, same key pair and dummy key.
    let mut other_seed = base.clone();
    other_seed[..64].fill(0x42);
    let with_seed = ServerKeys::from_payload(&other_seed).unwrap();
    assert_eq!(with_seed.public_key(), keys.public_key());
    assert_eq!(with_seed.dummy_public_key(), keys.dummy_public_key());
    assert_ne!(with_seed.fingerprint(), keys.fingerprint());

    // A different private key (the scalar 2): another public key.
    let mut other_key = base.clone();
    other_key[64..96].fill(0);
    other_key[64] = 2;
    let with_key = ServerKeys::from_payload(&other_key).unwrap();
    assert_ne!(with_key.public_key(), keys.public_key());
    assert_ne!(with_key.fingerprint(), keys.fingerprint());

    // A different dummy key.
    let other_dummy = ServerKeys::generate(&mut rng("fp-other"))
        .unwrap()
        .payload();
    let mut swapped = base.clone();
    swapped[96..].copy_from_slice(&other_dummy[96..]);
    let with_dummy = ServerKeys::from_payload(&swapped).unwrap();
    assert_eq!(with_dummy.public_key(), keys.public_key());
    assert_ne!(with_dummy.fingerprint(), keys.fingerprint());

    // The same payload gives the same fingerprint, and a single bit of the
    // seed already changes it.
    assert_eq!(
        ServerKeys::from_payload(&base).unwrap().fingerprint(),
        keys.fingerprint()
    );
    let mut one_bit = base;
    one_bit[63] ^= 1;
    assert_ne!(
        ServerKeys::from_payload(&one_bit).unwrap().fingerprint(),
        keys.fingerprint()
    );
}

#[test]
fn fingerprints_compare_by_value() {
    let a = SetupFingerprint([7; 32]);
    assert_eq!(a, SetupFingerprint([7; 32]));
    for at in 0..32 {
        let mut other = [7u8; 32];
        other[at] ^= 0x80;
        assert_ne!(a, SetupFingerprint(other));
    }
}

// ------------------------------------------------- loading and creating

#[test]
fn must_exist_never_creates() {
    let dir = TempDir::new();
    assert_eq!(
        load_or_create(dir.path(), CreatePolicy::MustExist, &mut rng("never")).map(drop),
        Err(SecretFileError::Missing)
    );
    assert!(dir.names().is_empty());

    // With one of the two files in place, the other is still not made.
    write_new_secret_file(
        &dir.path().join(OPAQUE_SETUP_FILE),
        FileKind::OpaqueSetup,
        &ServerKeys::generate(&mut rng("one")).unwrap().payload(),
    )
    .unwrap();
    assert_eq!(
        load_or_create(dir.path(), CreatePolicy::MustExist, &mut rng("never")).map(drop),
        Err(SecretFileError::Missing)
    );
    assert_eq!(dir.names(), ["opaque_setup"]);
}

#[test]
fn create_policy_follows_the_database() {
    let remembered = Some(SetupFingerprint([1; 32]));
    // Only a database with no accounts and no fingerprint may create files.
    assert!(matches!(
        CreatePolicy::for_database(false, None),
        CreatePolicy::CreateIfMissing
    ));
    for (accounts, stored) in [(true, None), (false, remembered), (true, remembered)] {
        assert!(
            matches!(
                CreatePolicy::for_database(accounts, stored),
                CreatePolicy::MustExist
            ),
            "accounts {accounts}, stored {stored:?}"
        );
    }
}

#[test]
fn a_refused_start_leaves_no_new_file_behind() {
    let fingerprint = Some(SetupFingerprint([9; 32]));
    // (files that are left, accounts, stored fingerprint)
    let cases: [(&[&str], bool, Option<SetupFingerprint>); 5] = [
        (&[], true, None),
        (&[], false, fingerprint),
        (&[OPAQUE_SETUP_FILE], true, fingerprint),
        (&[PRELOGIN_SECRET_FILE], true, fingerprint),
        (&[PRELOGIN_SECRET_FILE], false, fingerprint),
    ];
    for (keep, accounts, stored) in cases {
        let dir = TempDir::new();
        load_or_create(dir.path(), CreatePolicy::CreateIfMissing, &mut rng("lose")).unwrap();
        for name in [OPAQUE_SETUP_FILE, PRELOGIN_SECRET_FILE] {
            if !keep.contains(&name) {
                std::fs::remove_file(dir.path().join(name)).unwrap();
            }
        }
        let before = dir.names();
        let policy = CreatePolicy::for_database(accounts, stored);
        assert!(matches!(
            load_or_create(dir.path(), policy, &mut rng("new")),
            Err(SecretFileError::Missing)
        ));
        assert_eq!(dir.names(), before, "{keep:?}, accounts {accounts}");
    }
}

#[test]
fn first_start_creates_both_files_and_the_next_start_loads_them() {
    let dir = TempDir::new();
    let first = load_or_create(
        dir.path(),
        CreatePolicy::CreateIfMissing,
        &mut rng("first-start"),
    )
    .unwrap();
    assert_eq!(first.setup_origin, FileOrigin::Created);
    assert_eq!(first.prelogin_origin, FileOrigin::Created);
    assert_eq!(dir.names(), ["opaque_setup", "prelogin_secret"]);
    assert_eq!(
        std::fs::read(dir.path().join("opaque_setup"))
            .unwrap()
            .len(),
        169
    );
    assert_eq!(
        std::fs::read(dir.path().join("prelogin_secret"))
            .unwrap()
            .len(),
        73
    );

    for policy in [CreatePolicy::CreateIfMissing, CreatePolicy::MustExist] {
        // The random source is not used for a file that exists.
        let mut unused = ReplayRng::new(Vec::new());
        let second = load_or_create(dir.path(), policy, &mut unused).unwrap();
        assert_eq!(second.setup_origin, FileOrigin::Existing);
        assert_eq!(second.prelogin_origin, FileOrigin::Existing);
        assert_eq!(&second.keys.payload()[..], &first.keys.payload()[..]);
        assert_eq!(
            &second.prelogin.payload()[..],
            &first.prelogin.payload()[..]
        );
    }
}

#[test]
fn a_missing_prelogin_secret_is_made_while_the_set_up_is_kept() {
    let dir = TempDir::new();
    let first = load_or_create(dir.path(), CreatePolicy::CreateIfMissing, &mut rng("a")).unwrap();
    std::fs::remove_file(dir.path().join(PRELOGIN_SECRET_FILE)).unwrap();
    let second = load_or_create(dir.path(), CreatePolicy::CreateIfMissing, &mut rng("b")).unwrap();
    assert_eq!(second.setup_origin, FileOrigin::Existing);
    assert_eq!(second.prelogin_origin, FileOrigin::Created);
    assert_eq!(second.keys.fingerprint(), first.keys.fingerprint());
    assert_ne!(
        &second.prelogin.payload()[..],
        &first.prelogin.payload()[..]
    );
}

#[test]
fn a_damaged_file_is_an_error_and_is_never_replaced() {
    let dir = TempDir::new();
    load_or_create(
        dir.path(),
        CreatePolicy::CreateIfMissing,
        &mut rng("damage"),
    )
    .unwrap();
    let path = dir.path().join(OPAQUE_SETUP_FILE);
    let mut bytes = std::fs::read(&path).unwrap();
    bytes[20] ^= 0x01;
    std::fs::write(&path, &bytes).unwrap();
    for policy in [CreatePolicy::CreateIfMissing, CreatePolicy::MustExist] {
        assert_eq!(
            load_or_create(dir.path(), policy, &mut rng("other")).map(drop),
            Err(SecretFileError::BadChecksum)
        );
    }
    assert_eq!(std::fs::read(&path).unwrap(), bytes);
}

#[test]
fn a_file_with_a_valid_checksum_and_a_bad_key_is_refused() {
    let dir = TempDir::new();
    let mut payload = ServerKeys::generate(&mut rng("bad-key"))
        .unwrap()
        .payload()
        .to_vec();
    payload[64..96].fill(0);
    let file = encode_secret_file(FileKind::OpaqueSetup, &payload).unwrap();
    let path = dir.path().join(OPAQUE_SETUP_FILE);
    std::fs::write(&path, &file).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    assert_eq!(
        load_or_create(dir.path(), CreatePolicy::CreateIfMissing, &mut rng("x")).map(drop),
        Err(SecretFileError::PayloadInvalid)
    );
}

#[test]
fn concurrent_first_start_yields_one_setup() {
    for round in 0..25 {
        let dir = TempDir::new();
        let barrier = Barrier::new(2);
        let results: Vec<LoadedSecrets> = std::thread::scope(|scope| {
            let handles: Vec<_> = ["thread-a", "thread-b"]
                .into_iter()
                .map(|seed| {
                    let (dir, barrier) = (&dir, &barrier);
                    scope.spawn(move || {
                        barrier.wait();
                        load_or_create(
                            dir.path(),
                            CreatePolicy::CreateIfMissing,
                            &mut rng(&format!("{seed}-{round}")),
                        )
                        .unwrap()
                    })
                })
                .collect();
            handles.into_iter().map(|h| h.join().unwrap()).collect()
        });
        let [a, b] = &results[..] else { panic!() };
        assert_eq!(a.keys.public_key(), b.keys.public_key(), "round {round}");
        assert_eq!(&a.keys.payload()[..], &b.keys.payload()[..]);
        assert_eq!(&a.prelogin.payload()[..], &b.prelogin.payload()[..]);
        assert_eq!(dir.names(), ["opaque_setup", "prelogin_secret"]);
        // Exactly one of the two made each file.
        let created = |f: fn(&LoadedSecrets) -> FileOrigin| {
            results
                .iter()
                .filter(|l| f(l) == FileOrigin::Created)
                .count()
        };
        assert_eq!(created(|l| l.setup_origin), 1, "round {round}");
        assert_eq!(created(|l| l.prelogin_origin), 1, "round {round}");
    }
}

// -------------------------------------------------------- the decision

#[test]
fn startup_decision_table() {
    use FileOrigin::{Created, Existing};
    use StartupDecision::{Proceed, RecordFingerprint, Refuse};
    use StartupRefusal::{
        FingerprintMissingWithAccounts, PreloginSecretLost, SetupLostWhileAccountsExist,
        SetupReplaced,
    };

    let loaded = |setup, prelogin| secrets("table", setup, prelogin);
    let own = loaded(Existing, Existing).keys.fingerprint();
    let other = secrets("another", Existing, Existing).keys.fingerprint();
    assert_ne!(own, other);

    // (setup origin, prelogin origin, stored, accounts) -> decision
    let rows: Vec<(
        FileOrigin,
        FileOrigin,
        Option<SetupFingerprint>,
        bool,
        StartupDecision,
    )> = vec![
        // Everything is new: the first start.
        (Created, Created, None, false, RecordFingerprint(own)),
        // A fingerprint from before there were files, or a database that had
        // none yet, and no accounts.
        (Existing, Existing, None, false, RecordFingerprint(own)),
        (Existing, Created, None, false, RecordFingerprint(own)),
        // All as remembered.
        (Existing, Existing, Some(own), true, Proceed),
        (Existing, Existing, Some(own), false, Proceed),
        // A made-up pre-login secret is harmless while there are no accounts.
        (Existing, Created, Some(own), false, Proceed),
        // The file is not the remembered one.
        (Existing, Existing, Some(other), true, Refuse(SetupReplaced)),
        (
            Existing,
            Existing,
            Some(other),
            false,
            Refuse(SetupReplaced),
        ),
        (Existing, Created, Some(other), true, Refuse(SetupReplaced)),
        // A new set-up where the database remembers one or has accounts.
        (
            Created,
            Created,
            Some(own),
            true,
            Refuse(SetupLostWhileAccountsExist),
        ),
        (
            Created,
            Created,
            Some(own),
            false,
            Refuse(SetupLostWhileAccountsExist),
        ),
        (
            Created,
            Existing,
            Some(own),
            true,
            Refuse(SetupLostWhileAccountsExist),
        ),
        (
            Created,
            Created,
            None,
            true,
            Refuse(SetupLostWhileAccountsExist),
        ),
        (
            Created,
            Existing,
            None,
            true,
            Refuse(SetupLostWhileAccountsExist),
        ),
        // Accounts, but nothing to check the file against.
        (
            Existing,
            Existing,
            None,
            true,
            Refuse(FingerprintMissingWithAccounts),
        ),
        (
            Existing,
            Created,
            None,
            true,
            Refuse(FingerprintMissingWithAccounts),
        ),
        // The pre-login secret is never rotated silently.
        (
            Existing,
            Created,
            Some(own),
            true,
            Refuse(PreloginSecretLost),
        ),
    ];
    for (setup, prelogin, stored, accounts, want) in rows {
        let got = startup_decision(&loaded(setup, prelogin), stored, accounts);
        assert_eq!(
            got, want,
            "setup {setup:?}, prelogin {prelogin:?}, stored {stored:?}, accounts {accounts}"
        );
    }
}

#[test]
fn a_first_start_then_a_restart_end_to_end() {
    let dir = TempDir::new();
    let first = load_or_create(
        dir.path(),
        CreatePolicy::for_database(false, None),
        &mut rng("e2e"),
    )
    .unwrap();
    let StartupDecision::RecordFingerprint(fingerprint) = startup_decision(&first, None, false)
    else {
        panic!("the first start records the fingerprint");
    };
    // Later: accounts exist, the files are still there.
    let again = load_or_create(
        dir.path(),
        CreatePolicy::for_database(true, Some(fingerprint)),
        &mut rng("n/a"),
    )
    .unwrap();
    assert_eq!(
        startup_decision(&again, Some(fingerprint), true),
        StartupDecision::Proceed
    );
    // The set-up file is lost: the policy refuses to make a new one.
    std::fs::remove_file(dir.path().join(OPAQUE_SETUP_FILE)).unwrap();
    assert_eq!(
        load_or_create(
            dir.path(),
            CreatePolicy::for_database(true, Some(fingerprint)),
            &mut rng("n/a")
        )
        .map(drop),
        Err(SecretFileError::Missing)
    );
    // If a server is wrongly started with creation allowed, the decision
    // still refuses.
    let wrong = load_or_create(dir.path(), CreatePolicy::CreateIfMissing, &mut rng("new")).unwrap();
    assert_eq!(
        startup_decision(&wrong, Some(fingerprint), true),
        StartupDecision::Refuse(StartupRefusal::SetupLostWhileAccountsExist)
    );
}
