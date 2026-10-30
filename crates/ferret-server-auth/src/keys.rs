//! The server's long-lived secrets in memory, and how they are loaded or
//! created on start.
//!
//! * [`ServerKeys`] holds the OPAQUE `ServerSetup`: the OPRF seed, the key
//!   pair and the dummy key. It lives in the file `opaque_setup`.
//! * [`PreloginSecret`] is the key behind the made-up pre-login answers. It
//!   lives in the file `prelogin_secret`.
//!
//! Together with `secret_file` this is the only module that touches the file
//! system.
//!
//! # Memory
//!
//! `opaque-ke` derives `Debug` over the secret fields of its set-up, and its
//! `ServerSetup` is not `ZeroizeOnDrop` itself (its seed and private key are,
//! and wipe themselves when the set-up is dropped). [`ServerKeys`] therefore
//! keeps the set-up private, never derives `Debug`, and writes
//! `[redacted]` instead.
//!
//! # First start
//!
//! [`load_or_create`] reads the two files and, when allowed, creates a missing
//! one. [`CreatePolicy::for_database`] forbids creation as soon as the
//! database holds accounts: a lost file then fails the start instead of
//! silently making every stored account unusable. Two servers that start on
//! an empty directory at the same moment end up with the same files: the one
//! that loses the race for a file reads the winner's file.

use core::fmt;
use std::path::Path;
use std::time::Duration;

use ferret_core::SecureRng;
use ferret_core::opaque::server_suite::opaque_ke::ServerSetup;
use ferret_core::opaque::server_suite::{FerretSuite, Rng06, SERVER_SETUP_LEN};
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, Zeroizing};

use crate::ct::ct_eq;
use crate::secret_file::{
    FileKind, OPAQUE_SETUP_FILE, PRELOGIN_PAYLOAD_LEN, PRELOGIN_SECRET_FILE, SecretFileError,
    read_secret_file, write_new_secret_file,
};

/// Label of the fingerprint of the set-up.
///
/// Spec: Fase 1 § 11 (the file `opaque_setup`); the label is this crate's own.
const SETUP_FINGERPRINT_LABEL: &[u8] = b"ferret/v1/setup-fp";

/// The OPAQUE set-up of the server: OPRF seed, key pair and dummy key.
///
/// Created once, on the first start, and then only ever loaded. It is never
/// replaced: every stored record is bound to its key pair and every OPRF
/// answer to its seed.
pub struct ServerKeys {
    setup: ServerSetup<FerretSuite>,
    /// The server's public key and the dummy public key, read once when the
    /// set-up is built, so a layout that did not fit would be an error then
    /// and never a zero key later.
    public_key: [u8; 32],
    dummy_public_key: [u8; 32],
}

impl ServerKeys {
    /// Makes a new set-up. Draws 3 times 64 bytes from `rng`, in the order
    /// key pair, OPRF seed, dummy key pair (`ServerSetup::new`).
    ///
    /// The result is an error only if the serialized set-up does not have the
    /// layout this code expects; that cannot happen with the pinned library,
    /// and is reported rather than papered over.
    pub fn generate<R: SecureRng>(rng: &mut R) -> Result<Self, SecretFileError> {
        Self::from_setup(ServerSetup::<FerretSuite>::new(&mut Rng06(rng)))
    }

    /// Wraps a set-up and reads its two public keys.
    fn from_setup(setup: ServerSetup<FerretSuite>) -> Result<Self, SecretFileError> {
        let mut serialized = setup.keypair().public().serialize();
        let public_key = array32(&serialized);
        serialized.as_mut_slice().zeroize();
        // Seed 64, private key 32, then the dummy key.
        let payload = Self::serialize(&setup);
        let dummy_public_key = payload
            .get(96..)
            .ok_or(SecretFileError::PayloadInvalid)
            .and_then(array32);
        Ok(Self {
            setup,
            public_key: public_key?,
            dummy_public_key: dummy_public_key?,
        })
    }

    fn serialize(setup: &ServerSetup<FerretSuite>) -> Zeroizing<Vec<u8>> {
        let mut serialized = setup.serialize();
        let out = Zeroizing::new(serialized.to_vec());
        serialized.as_mut_slice().zeroize();
        out
    }

    /// Reads the 128-byte payload of an `opaque_setup` file: OPRF seed 64,
    /// private key 32, dummy public key 32.
    ///
    /// Anything but exactly 128 bytes is refused (the library's parser would
    /// ignore trailing bytes). A private key that is not a canonical non-zero
    /// scalar and a dummy key that is not a ristretto255 point are refused.
    pub fn from_payload(payload: &[u8]) -> Result<Self, SecretFileError> {
        if payload.len() != SERVER_SETUP_LEN {
            return Err(SecretFileError::PayloadInvalid);
        }
        let setup = ServerSetup::<FerretSuite>::deserialize(payload)
            .map_err(|_| SecretFileError::PayloadInvalid)?;
        Self::from_setup(setup)
    }

    /// The 128-byte payload for the file. It holds the secrets: it is wiped
    /// when dropped.
    pub fn payload(&self) -> Zeroizing<Vec<u8>> {
        Self::serialize(&self.setup)
    }

    /// The server's public key, which every client pins.
    pub const fn public_key(&self) -> [u8; 32] {
        self.public_key
    }

    /// The public dummy key that stands in for the client key of a made-up
    /// record.
    pub const fn dummy_public_key(&self) -> [u8; 32] {
        self.dummy_public_key
    }

    /// A fingerprint of the whole set-up, for the database to remember.
    ///
    /// `SHA-256("ferret/v1/setup-fp" ‖ payload)` over the 128-byte payload:
    /// the OPRF seed, the private key and the dummy key. A swap of any one of
    /// them changes it. It is a one-way hash of 128 random bytes, so it can be
    /// stored and logged; it is not a public key.
    pub fn fingerprint(&self) -> SetupFingerprint {
        let payload = self.payload();
        let mut hash = Sha256::new();
        hash.update(SETUP_FINGERPRINT_LABEL);
        hash.update(payload.as_slice());
        SetupFingerprint(hash.finalize().into())
    }

    /// The set-up, for the OPAQUE calls of this crate.
    pub(crate) fn setup(&self) -> &ServerSetup<FerretSuite> {
        &self.setup
    }
}

impl fmt::Debug for ServerKeys {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ServerKeys([redacted])")
    }
}

/// Exactly 32 bytes as an array; any other length is an error, never a
/// padded or cut key.
fn array32(bytes: &[u8]) -> Result<[u8; 32], SecretFileError> {
    <[u8; 32]>::try_from(bytes).map_err(|_| SecretFileError::PayloadInvalid)
}

/// The 32-byte secret behind the made-up pre-login answers.
///
/// Created once and then kept for as long as the accounts live: a new value
/// would change the made-up answers and tell an observer which accounts do
/// not exist.
pub struct PreloginSecret(Zeroizing<[u8; PRELOGIN_PAYLOAD_LEN]>);

impl PreloginSecret {
    /// A new secret: one draw of 32 bytes.
    pub fn generate<R: SecureRng>(rng: &mut R) -> Self {
        let mut bytes = Zeroizing::new([0u8; PRELOGIN_PAYLOAD_LEN]);
        rng.fill(bytes.as_mut_slice());
        Self(bytes)
    }

    /// Reads the payload of a `prelogin_secret` file: exactly 32 bytes.
    pub fn from_payload(payload: &[u8]) -> Result<Self, SecretFileError> {
        if payload.len() != PRELOGIN_PAYLOAD_LEN {
            return Err(SecretFileError::PayloadInvalid);
        }
        let mut bytes = Zeroizing::new([0u8; PRELOGIN_PAYLOAD_LEN]);
        for (slot, byte) in bytes.iter_mut().zip(payload) {
            *slot = *byte;
        }
        Ok(Self(bytes))
    }

    /// The payload for the file. It is wiped when dropped.
    pub fn payload(&self) -> Zeroizing<Vec<u8>> {
        Zeroizing::new(self.0.to_vec())
    }

    /// The 32 bytes, for the derivation of made-up answers.
    pub(crate) fn as_bytes(&self) -> &[u8; PRELOGIN_PAYLOAD_LEN] {
        &self.0
    }
}

impl fmt::Debug for PreloginSecret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("PreloginSecret([redacted])")
    }
}

/// A fingerprint of the server's set-up: see [`ServerKeys::fingerprint`]. The
/// next layer keeps it in its database. It is a hash of secrets, so two
/// fingerprints are compared in constant time.
#[derive(Debug, Clone, Copy)]
pub struct SetupFingerprint(pub [u8; 32]);

impl PartialEq for SetupFingerprint {
    fn eq(&self, other: &Self) -> bool {
        ct_eq(&self.0, &other.0)
    }
}

impl Eq for SetupFingerprint {}

/// Whether a missing secret file may be created.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CreatePolicy {
    /// Create a file that is missing. For the very first start.
    CreateIfMissing,
    /// A missing file is an error. For a server that has accounts.
    MustExist,
}

impl CreatePolicy {
    /// `MustExist` as soon as the database shows that this server has run
    /// before (it has accounts, or it remembers a fingerprint), and
    /// `CreateIfMissing` only for a database with neither.
    ///
    /// Call [`startup_decision`](crate::startup_decision) on the result: a
    /// start that is refused then leaves no new file behind, because a
    /// missing file was never created.
    pub const fn for_database(
        accounts_with_records: bool,
        stored: Option<SetupFingerprint>,
    ) -> Self {
        if accounts_with_records | stored.is_some() {
            CreatePolicy::MustExist
        } else {
            CreatePolicy::CreateIfMissing
        }
    }
}

/// Whether a secret was loaded from a file or made by this start.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileOrigin {
    /// The file existed (or another server made it a moment before).
    Existing,
    /// This start made the file.
    Created,
}

/// The two secrets of the server and where each came from.
pub struct LoadedSecrets {
    /// The OPAQUE set-up.
    pub keys: ServerKeys,
    /// The pre-login secret.
    pub prelogin: PreloginSecret,
    /// Whether `opaque_setup` was loaded or created.
    pub setup_origin: FileOrigin,
    /// Whether `prelogin_secret` was loaded or created.
    pub prelogin_origin: FileOrigin,
}

impl fmt::Debug for LoadedSecrets {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("LoadedSecrets([redacted])")
    }
}

/// How often and how long to look again at a file that is still being
/// written by another start: up to two seconds in all.
const SETTLE_ATTEMPTS: u32 = 100;
const SETTLE_PAUSE: Duration = Duration::from_millis(20);

/// Reads a file; a file that is too short is read again for a moment, since
/// another start may be writing it. Any other defect is final.
fn read_settled(path: &Path, kind: FileKind) -> Result<Zeroizing<Vec<u8>>, SecretFileError> {
    let mut attempt = 0u32;
    loop {
        match read_secret_file(path, kind) {
            Err(SecretFileError::BadLength) if attempt < SETTLE_ATTEMPTS => {
                attempt = attempt.saturating_add(1);
                std::thread::sleep(SETTLE_PAUSE);
            }
            other => return other,
        }
    }
}

/// Loads one secret file, or creates it from `make` when it is missing and
/// the policy allows. If another start creates the file first, that file is
/// the one that counts.
fn load_one<T>(
    dir: &Path,
    name: &str,
    kind: FileKind,
    policy: CreatePolicy,
    from_payload: impl Fn(&[u8]) -> Result<T, SecretFileError>,
    make: impl FnOnce() -> Result<(T, Zeroizing<Vec<u8>>), SecretFileError>,
) -> Result<(T, FileOrigin), SecretFileError> {
    let path = dir.join(name);
    match read_settled(&path, kind) {
        Ok(payload) => return Ok((from_payload(&payload)?, FileOrigin::Existing)),
        Err(SecretFileError::Missing) if matches!(policy, CreatePolicy::CreateIfMissing) => {}
        Err(error) => return Err(error),
    }
    let (value, payload) = make()?;
    match write_new_secret_file(&path, kind, &payload) {
        Ok(()) => Ok((value, FileOrigin::Created)),
        Err(SecretFileError::AlreadyExists) => {
            let payload = read_settled(&path, kind)?;
            Ok((from_payload(&payload)?, FileOrigin::Existing))
        }
        Err(error) => Err(error),
    }
}

/// Loads `opaque_setup` and `prelogin_secret` from `dir`, creating a missing
/// one if `policy` allows.
///
/// A file that is there but wrong (bad permissions, damaged, unknown
/// version) is an error under every policy: it is never replaced. With
/// [`CreatePolicy::MustExist`] a missing file is [`SecretFileError::Missing`]
/// and nothing is written. Use [`CreatePolicy::for_database`] to choose the
/// policy, so a server that has run before never makes a new file. The directory must exist.
///
/// Hand the result to [`startup_decision`](crate::startup_decision) before
/// the server accepts a request.
pub fn load_or_create<R: SecureRng>(
    dir: &Path,
    policy: CreatePolicy,
    rng: &mut R,
) -> Result<LoadedSecrets, SecretFileError> {
    let (keys, setup_origin) = load_one(
        dir,
        OPAQUE_SETUP_FILE,
        FileKind::OpaqueSetup,
        policy,
        ServerKeys::from_payload,
        || {
            let keys = ServerKeys::generate(rng)?;
            let payload = keys.payload();
            Ok((keys, payload))
        },
    )?;
    let (prelogin, prelogin_origin) = load_one(
        dir,
        PRELOGIN_SECRET_FILE,
        FileKind::PreloginSecret,
        policy,
        PreloginSecret::from_payload,
        || {
            let secret = PreloginSecret::generate(rng);
            let payload = secret.payload();
            Ok((secret, payload))
        },
    )?;
    Ok(LoadedSecrets {
        keys,
        prelogin,
        setup_origin,
        prelogin_origin,
    })
}

#[cfg(test)]
mod tests {
    use ferret_core::TestRng;
    use ferret_core::opaque::server_suite::opaque_ke::{
        ClientRegistration, RegistrationRequest, ServerRegistration,
    };

    use super::*;

    /// What the server answers to a registration request of a given client
    /// for a given credential id.
    fn answer(keys: &ServerKeys, request: &[u8]) -> Vec<u8> {
        let message = RegistrationRequest::deserialize(request).unwrap();
        ServerRegistration::<FerretSuite>::start(keys.setup(), message, b"0123456789abcdef")
            .unwrap()
            .message
            .serialize()
            .to_vec()
    }

    #[test]
    fn a_first_start_creates_and_the_next_start_loads() {
        let dir = std::env::temp_dir().join(format!("ferret-keys-unit-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let first =
            load_or_create(&dir, CreatePolicy::CreateIfMissing, &mut TestRng::new(b"u")).unwrap();
        assert_eq!(first.setup_origin, FileOrigin::Created);
        assert_eq!(first.prelogin_origin, FileOrigin::Created);
        let second =
            load_or_create(&dir, CreatePolicy::MustExist, &mut TestRng::new(b"v")).unwrap();
        assert_eq!(second.setup_origin, FileOrigin::Existing);
        assert_eq!(second.keys.fingerprint(), first.keys.fingerprint());
        assert_eq!(second.prelogin.as_bytes(), first.prelogin.as_bytes());
        // A missing directory is no missing file.
        assert_eq!(
            load_or_create(
                &dir.join("none"),
                CreatePolicy::MustExist,
                &mut TestRng::new(b"w")
            )
            .map(drop),
            Err(SecretFileError::Missing)
        );
        assert!(matches!(
            load_or_create(
                &dir.join("none"),
                CreatePolicy::CreateIfMissing,
                &mut TestRng::new(b"w")
            )
            .map(drop),
            Err(SecretFileError::Io(_))
        ));
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn restored_keys_answer_like_the_original() {
        let original = ServerKeys::generate(&mut TestRng::new(b"restore")).unwrap();
        let restored = ServerKeys::from_payload(&original.payload()).unwrap();
        let mut client = TestRng::new(b"restore-client");
        let request = ClientRegistration::<FerretSuite>::start(&mut Rng06(&mut client), b"pw")
            .unwrap()
            .message
            .serialize()
            .to_vec();
        // Anything but 128 bytes is no set-up.
        let payload = original.payload();
        assert!(ServerKeys::from_payload(&payload[..127]).is_err());
        let first = answer(&original, &request);
        // The evaluated element (32) and the server public key (32).
        assert_eq!(first.len(), 64);
        assert_eq!(first, answer(&restored, &request));
        assert_eq!(first.get(32..), Some(&original.public_key()[..]));
        // Other keys answer differently.
        let other = ServerKeys::generate(&mut TestRng::new(b"another")).unwrap();
        assert_ne!(first, answer(&other, &request));
    }
}
