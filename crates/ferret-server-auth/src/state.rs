//! The state of a login between `login_start` and `login_finish`: sealed,
//! kept for 60 seconds, used once.
//!
//! OPAQUE needs the server's half of the key exchange again when the third
//! message arrives. That state is the session key and the expected MAC of the
//! client, 128 bytes in all. The server does not keep it in the clear. It is
//! sealed with a key that nothing but the server's secrets can produce, put
//! in a [`LoginStateStore`] under the hash of the login id, and removed by
//! the first `take` of that key.
//!
//! # Sealing
//!
//! XChaCha20-Poly1305 with a fresh 24-byte nonce from the caller's
//! [`SecureRng`]. The key is `HKDF-SHA256(prelogin_secret, info =
//! "ferret/v1/state-seal")`: there is no third secret file. A state lives for
//! a minute, so a leaked key gives nothing that the holder of
//! `prelogin_secret` does not already have. The blob is
//! `version (0x01) ‖ nonce (24) ‖ ciphertext ‖ tag (16)`, 228 bytes. The
//! plaintext is
//!
//! ```text
//! expires_at  u64be            8
//! purpose     u8               1   0 login, 1 re-authentication
//! binding     flag u8 ‖ 32     33  the session of a re-authentication, else zero
//! credential  16               16
//! ksf_profile u8               1
//! ServerLogin                  128
//! ```
//!
//! The associated data is a `Tlv` with the label `ferret/v1/server/login-state`,
//! the version, the suite and the login id. The credential, the purpose and
//! the session binding are inside the sealed bytes, so they are covered by the
//! tag without being in the associated data: the reader of a blob does not
//! know them before it has opened it, and the login id that the blob was
//! sealed for must be the one the reader holds.
//!
//! # Time
//!
//! A state expires when `now >= expires_at`. The expiry of a new state is
//! `now.saturating_add(STATE_TTL_SECS)`. A clock that cannot tell the time
//! reads `u64::MAX`, which makes the expiry equal to `now`: the state is
//! expired the moment it is made, and the login fails closed.
//!
//! # Store
//!
//! [`LoginStateStore`] is synchronous, so the next layer can implement it on
//! the database connection it already holds and take a state in the same
//! transaction as the rest of the request. [`InMemoryLoginStateStore`] is the
//! implementation for tests and for a server that needs no restart
//! safety. The cap on its size and the removal of the oldest state are a
//! second line of defence against memory filled by unauthenticated
//! `login_start` calls; the first is the rate limit.

// The first callers are `login_start` and `login_finish`.
#![cfg_attr(
    not(test),
    expect(dead_code, reason = "no entry point seals or opens a state yet")
)]

use core::fmt;
use std::collections::{BTreeMap, HashMap};
use std::sync::{Mutex, MutexGuard, PoisonError};

use chacha20poly1305::{AeadInOut, Key, KeyInit, XChaCha20Poly1305, XNonce};
use ferret_core::tlv::{SUITE, tag};
use ferret_core::{SecureRng, Tlv};
use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::{Zeroize, Zeroizing};

use crate::STATE_TTL_SECS;
use crate::ct::ct_eq;
use crate::error::{AuthError, DenyReason, InternalKind};
use crate::ids::{CredentialId, LoginId, SessionBinding, StateKey};
use crate::keys::PreloginSecret;

/// Info of the key derivation.
///
/// There is no third secret file: the key comes from `prelogin_secret`.
const STATE_SEAL_INFO: &[u8] = b"ferret/v1/state-seal";

/// Label of the associated data.
const STATE_AAD_LABEL: &str = "ferret/v1/server/login-state";

/// Version of the blob and of the plaintext.
const BLOB_VERSION: u8 = 1;

const NONCE_LEN: usize = 24;
const TAG_LEN: usize = 16;

/// The `ServerLogin` of `opaque-ke` 4.0.1 serialized: the session key (64) and
/// the expected MAC of the client (64).
pub(crate) const SERVER_LOGIN_LEN: usize = 128;

/// `expires_at (8) ‖ purpose (1) ‖ binding (1 + 32) ‖ credential (16) ‖
/// ksf_profile (1) ‖ ServerLogin (128)`.
const PLAIN_LEN: usize = 8 + 1 + 1 + 32 + 16 + 1 + SERVER_LOGIN_LEN;

/// `version ‖ nonce ‖ ciphertext ‖ tag`.
const BLOB_LEN: usize = 1 + NONCE_LEN + PLAIN_LEN + TAG_LEN;

const PURPOSE_LOGIN: u8 = 0;
const PURPOSE_REAUTH: u8 = 1;

/// The key that seals login states.
pub struct StateSealKey(Zeroizing<[u8; 32]>);

impl StateSealKey {
    /// The key for the server's `prelogin_secret`:
    /// `HKDF-SHA256(ikm = prelogin_secret, salt = none, info =
    /// "ferret/v1/state-seal")`, 32 bytes.
    ///
    /// See the module documentation for why there is no separate secret.
    /// Fails only if the derivation itself fails, which it cannot for a
    /// 32-byte output.
    pub fn derive(secret: &PreloginSecret) -> Result<Self, AuthError> {
        // The pseudorandom key is wiped at once; the expander holds its own
        // keyed state, which `hmac` wipes on drop.
        let (mut prk, hkdf) = Hkdf::<Sha256>::extract(None, secret.as_bytes());
        prk.as_mut_slice().zeroize();
        let mut key = Zeroizing::new([0u8; 32]);
        hkdf.expand(STATE_SEAL_INFO, key.as_mut_slice())
            .map_err(|_| sealing_failed())?;
        Ok(Self(key))
    }

    /// A random key, for tests that need keys unrelated to a secret.
    #[cfg(feature = "test-support")]
    pub fn random<R: SecureRng>(rng: &mut R) -> Self {
        let mut key = Zeroizing::new([0u8; 32]);
        rng.fill(key.as_mut_slice());
        Self(key)
    }

    /// The AEAD for this key. The temporary copy of the key is wiped; the
    /// cipher wipes its own copy on drop.
    fn cipher(&self) -> XChaCha20Poly1305 {
        let mut key = Key::from(*self.0);
        let cipher = XChaCha20Poly1305::new(&key);
        key.as_mut_slice().zeroize();
        cipher
    }
}

impl fmt::Debug for StateSealKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("StateSealKey([redacted])")
    }
}

/// A login state as the store keeps it: opaque bytes, sealed under a
/// [`StateSealKey`]. Nothing in a blob can be read without the key.
#[derive(Clone)]
pub struct SealedState(Vec<u8>);

impl SealedState {
    /// Wraps stored bytes. The length and the content are checked when the
    /// state is opened, not here.
    pub const fn from_bytes(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    /// The bytes, for a store to keep.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// The bytes, handed over.
    pub fn into_bytes(self) -> Vec<u8> {
        self.0
    }
}

impl fmt::Debug for SealedState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SealedState([redacted])")
    }
}

/// What a login is for.
///
/// Spec: Fase 1 § 4.6 (a): a re-authentication belongs to one session, and a
/// proof for it is not accepted from any other.
///
/// There is no `PartialEq`: the binding is a value derived from a session id,
/// and two purposes are compared with [`LoginPurpose::same_as`], in constant
/// time.
#[derive(Clone, Copy)]
pub enum LoginPurpose {
    /// An ordinary login.
    Login,
    /// A fresh proof of the password for a session that is already signed in.
    Reauth {
        /// The session the proof is for.
        session: SessionBinding,
    },
}

impl LoginPurpose {
    /// The purpose byte.
    const fn code(&self) -> u8 {
        match self {
            LoginPurpose::Login => PURPOSE_LOGIN,
            LoginPurpose::Reauth { .. } => PURPOSE_REAUTH,
        }
    }

    /// The binding bytes: the session of a re-authentication, zero for a login.
    const fn binding(&self) -> [u8; 32] {
        match self {
            LoginPurpose::Login => [0u8; 32],
            LoginPurpose::Reauth { session } => session.0,
        }
    }

    /// Whether the two purposes are the same, and for a re-authentication
    /// the same session. The comparison of the sessions takes the same time
    /// wherever they differ.
    pub fn same_as(&self, other: &LoginPurpose) -> bool {
        let same_kind = self.code() == other.code();
        let same_binding = ct_eq(&self.binding(), &other.binding());
        same_kind & same_binding
    }
}

impl fmt::Debug for LoginPurpose {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            LoginPurpose::Login => f.write_str("LoginPurpose::Login"),
            LoginPurpose::Reauth { .. } => f.write_str("LoginPurpose::Reauth([redacted])"),
        }
    }
}

/// The content of a sealed login state.
pub(crate) struct StatePlain {
    /// The account the login is for (a made-up one for an unknown name).
    pub credential: CredentialId,
    /// What the login is for.
    pub purpose: LoginPurpose,
    /// The second at which the state stops being valid: valid while `now <
    /// expires_at`.
    pub expires_at: u64,
    /// The key stretching profile the account had at `login_start`.
    pub ksf_profile: u8,
    /// The serialized `ServerLogin`: session key and expected MAC.
    pub server_login: Zeroizing<[u8; SERVER_LOGIN_LEN]>,
}

impl StatePlain {
    /// The expiry of a state made at `now`: `now + STATE_TTL_SECS`, stopping
    /// at the largest value. A clock that failed reads `u64::MAX`, which makes
    /// the expiry equal to `now`, and the state is expired at once.
    pub(crate) const fn expiry_from(now: u64) -> u64 {
        now.saturating_add(STATE_TTL_SECS)
    }

    /// Fails with `StateExpired` when the state is no longer valid at `now`.
    /// The store checks the expiry too; this is the check on the sealed
    /// value itself, which a store cannot tamper with.
    pub(crate) fn check_live(&self, now: u64) -> Result<(), AuthError> {
        if now >= self.expires_at {
            return Err(AuthError::Denied(DenyReason::StateExpired));
        }
        Ok(())
    }

    /// The plaintext bytes, wiped on drop.
    fn encode(&self) -> Zeroizing<Vec<u8>> {
        let mut out = Zeroizing::new(Vec::with_capacity(PLAIN_LEN.saturating_add(TAG_LEN)));
        out.extend_from_slice(&self.expires_at.to_be_bytes());
        out.push(self.purpose.code());
        out.push(u8::from(matches!(
            self.purpose,
            LoginPurpose::Reauth { .. }
        )));
        out.extend_from_slice(&self.purpose.binding());
        out.extend_from_slice(self.credential.as_bytes());
        out.push(self.ksf_profile);
        out.extend_from_slice(self.server_login.as_slice());
        out
    }

    /// Reads the plaintext. Exactly [`PLAIN_LEN`] bytes, a known purpose,
    /// a flag that agrees with the purpose, and a zero binding for a login;
    /// anything else is `StateInvalid`.
    fn parse(bytes: &[u8]) -> Result<Self, AuthError> {
        let invalid = AuthError::Denied(DenyReason::StateInvalid);
        // The length is checked before anything is read.
        let bytes: &[u8; PLAIN_LEN] = bytes.try_into().map_err(|_| invalid)?;
        let mut rest: &[u8] = bytes.as_slice();
        let expires_at = u64::from_be_bytes(*take::<8>(&mut rest).ok_or(invalid)?);
        let [code] = *take::<1>(&mut rest).ok_or(invalid)?;
        let [flag] = *take::<1>(&mut rest).ok_or(invalid)?;
        let binding = *take::<32>(&mut rest).ok_or(invalid)?;
        let credential = CredentialId::from_bytes(*take::<16>(&mut rest).ok_or(invalid)?);
        let [ksf_profile] = *take::<1>(&mut rest).ok_or(invalid)?;
        let login = take::<SERVER_LOGIN_LEN>(&mut rest).ok_or(invalid)?;
        let purpose = match (code, flag) {
            (PURPOSE_LOGIN, 0) if binding == [0u8; 32] => LoginPurpose::Login,
            (PURPOSE_REAUTH, 1) => LoginPurpose::Reauth {
                session: SessionBinding(binding),
            },
            _ => return Err(invalid),
        };
        let mut server_login = Zeroizing::new([0u8; SERVER_LOGIN_LEN]);
        for (slot, byte) in server_login.iter_mut().zip(login) {
            *slot = *byte;
        }
        Ok(Self {
            credential,
            purpose,
            expires_at,
            ksf_profile,
            server_login,
        })
    }
}

impl fmt::Debug for StatePlain {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("StatePlain([redacted])")
    }
}

/// The next `N` bytes of `rest`, which then continues after them.
fn take<'a, const N: usize>(rest: &mut &'a [u8]) -> Option<&'a [u8; N]> {
    let (head, tail) = rest.split_first_chunk::<N>()?;
    *rest = tail;
    Some(head)
}

/// The failure of the sealing itself. It depends on nothing a client sent,
/// and it cannot happen for the sizes used here; it is reported as a storage
/// failure and never reaches a client with its cause.
const fn sealing_failed() -> AuthError {
    AuthError::Internal(InternalKind::Storage)
}

/// The associated data of a blob made for `id`.
fn associated_data(id: &LoginId) -> Result<Vec<u8>, AuthError> {
    Tlv::new()
        .label(STATE_AAD_LABEL)
        .u8(tag::VERSION, BLOB_VERSION)
        .u8(tag::SUITE, SUITE)
        .bytes(tag::NONCE, id.as_bytes())
        .and_then(Tlv::finish)
        .map_err(|_| sealing_failed())
}

/// Seals a state for the login `id`: `version ‖ nonce ‖ ciphertext ‖ tag`.
///
/// One draw of 24 bytes from `rng`, new for every call. Fails only with an
/// internal error, which cannot happen for these sizes.
pub(crate) fn seal_state<R: SecureRng>(
    key: &StateSealKey,
    rng: &mut R,
    id: &LoginId,
    state: &StatePlain,
) -> Result<SealedState, AuthError> {
    let aad = associated_data(id)?;
    let mut nonce = [0u8; NONCE_LEN];
    rng.fill(&mut nonce);
    // The buffer holds the plaintext until it is encrypted in place.
    let mut buf = state.encode();
    key.cipher()
        .encrypt_in_place(&XNonce::from(nonce), &aad, &mut *buf)
        .map_err(|_| sealing_failed())?;
    let mut out = Vec::with_capacity(BLOB_LEN);
    out.push(BLOB_VERSION);
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&buf);
    Ok(SealedState(out))
}

/// Opens a state that was sealed for the login `id`.
///
/// Every failure is `Denied(StateInvalid)`: a blob of the wrong length or
/// version, one made for another id or under another key, one that was
/// changed, and one whose content does not parse. The length is checked
/// before anything else.
///
/// The expiry in the state is not checked here: see
/// [`StatePlain::check_live`].
pub(crate) fn open_state(
    key: &StateSealKey,
    id: &LoginId,
    sealed: &SealedState,
) -> Result<StatePlain, AuthError> {
    let invalid = AuthError::Denied(DenyReason::StateInvalid);
    let blob: &[u8; BLOB_LEN] = sealed.0.as_slice().try_into().map_err(|_| invalid)?;
    let (version, rest) = blob.split_first().ok_or(invalid)?;
    if *version != BLOB_VERSION {
        return Err(invalid);
    }
    let (nonce, ciphertext) = rest.split_first_chunk::<NONCE_LEN>().ok_or(invalid)?;
    let aad = associated_data(id)?;
    let mut buf = Zeroizing::new(ciphertext.to_vec());
    key.cipher()
        .decrypt_in_place(&XNonce::from(*nonce), &aad, &mut *buf)
        .map_err(|_| invalid)?;
    StatePlain::parse(&buf)
}

/// Why a store could not do what it was asked.
#[derive(Debug, PartialEq, Eq)]
pub enum StoreError {
    /// The store cannot hold any state.
    Full,
    /// There is a live state under the key.
    Collision,
    /// The store itself failed.
    Backend,
}

impl From<StoreError> for AuthError {
    fn from(_: StoreError) -> Self {
        AuthError::Internal(InternalKind::Storage)
    }
}

/// Where sealed login states wait for their `login_finish`.
///
/// Rules every implementation keeps, and `testing::conformance` checks:
///
/// * a state is returned at most once: `take` removes and returns it in one
///   atomic step, so two `take` calls for the same key, at the same moment or
///   one after the other, never both succeed;
/// * a state is valid while `now < expires_at`: at `now == expires_at` it is
///   gone, and `take` removes it;
/// * `put` never replaces a live state;
/// * a store with a limit removes the oldest state to make room.
///
/// The store holds sealed bytes under the hash of the login id. It cannot
/// read what it holds and holds no value a client could present.
pub trait LoginStateStore: Send + Sync {
    /// Stores a state until `expires_at`. A live state under the same key is
    /// never overwritten (`Collision`); an expired one counts as absent. When
    /// the store is at its limit, the oldest state is removed first.
    fn put(
        &self,
        key: StateKey,
        sealed: SealedState,
        expires_at: u64,
        now: u64,
    ) -> Result<(), StoreError>;

    /// Removes the state and returns it, in one atomic step. `None` when
    /// there is none, when it was taken before, and when it has expired
    /// (`now >= expires_at`); an expired state is removed too.
    fn take(&self, key: &StateKey, now: u64) -> Result<Option<SealedState>, StoreError>;

    /// Removes every state that has expired and returns how many.
    fn purge_expired(&self, now: u64) -> Result<usize, StoreError>;
}

/// A state in the memory store.
struct Slot {
    sealed: SealedState,
    expires_at: u64,
    /// When the state was stored, counted up: smaller is older.
    order: u64,
}

impl fmt::Debug for Slot {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Slot([redacted])")
    }
}

/// The content of the memory store, under one lock.
#[derive(Default)]
struct StoreBody {
    slots: HashMap<StateKey, Slot>,
    /// Keys by age, oldest first. Always the same keys as `slots`.
    by_age: BTreeMap<u64, StateKey>,
    next_order: u64,
}

impl StoreBody {
    fn remove(&mut self, key: &StateKey) -> Option<Slot> {
        let slot = self.slots.remove(key)?;
        self.by_age.remove(&slot.order);
        Some(slot)
    }

    /// Removes the oldest state. `false` when there is none.
    fn remove_oldest(&mut self) -> bool {
        let Some((_, key)) = self.by_age.pop_first() else {
            return false;
        };
        self.slots.remove(&key);
        true
    }
}

impl fmt::Debug for StoreBody {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("StoreBody([redacted])")
    }
}

/// A login state store in memory.
///
/// It holds at most `capacity` states (20 000 by default). When it is full, a
/// new state removes the oldest one, so a flood of `login_start` calls can
/// push out the logins in progress but cannot fill the memory. The main
/// defence against such a flood is the rate limit of the caller.
///
/// A state does not survive a restart of the process; the next layer's
/// database store does.
pub struct InMemoryLoginStateStore {
    capacity: usize,
    body: Mutex<StoreBody>,
}

impl InMemoryLoginStateStore {
    /// The default limit on the number of states.
    pub const DEFAULT_CAPACITY: usize = 20_000;

    /// A store with the default limit.
    pub fn new() -> Self {
        Self::with_capacity(Self::DEFAULT_CAPACITY)
    }

    /// A store that holds at most `capacity` states. With 0 every `put` is
    /// refused with `Full`.
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            capacity,
            body: Mutex::new(StoreBody::default()),
        }
    }

    /// The number of states held, expired ones that were not yet removed
    /// included.
    pub fn len(&self) -> usize {
        // Reading a count cannot see a half-made change: every change is made
        // under the lock, and none of them can fail half way.
        self.body
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .slots
            .len()
    }

    /// Whether the store holds no state.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// The lock. A store whose lock was poisoned by a panic is not trusted:
    /// every call fails with `Backend`.
    fn lock(&self) -> Result<MutexGuard<'_, StoreBody>, StoreError> {
        self.body.lock().map_err(|_| StoreError::Backend)
    }
}

impl Default for InMemoryLoginStateStore {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Debug for InMemoryLoginStateStore {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("InMemoryLoginStateStore([redacted])")
    }
}

impl LoginStateStore for InMemoryLoginStateStore {
    fn put(
        &self,
        key: StateKey,
        sealed: SealedState,
        expires_at: u64,
        now: u64,
    ) -> Result<(), StoreError> {
        if self.capacity == 0 {
            return Err(StoreError::Full);
        }
        let mut body = self.lock()?;
        if let Some(existing) = body.slots.get(&key) {
            if now < existing.expires_at {
                return Err(StoreError::Collision);
            }
            body.remove(&key);
        }
        while body.slots.len() >= self.capacity {
            if !body.remove_oldest() {
                return Err(StoreError::Backend);
            }
        }
        let order = body.next_order;
        body.next_order = order.wrapping_add(1);
        body.by_age.insert(order, key);
        body.slots.insert(
            key,
            Slot {
                sealed,
                expires_at,
                order,
            },
        );
        Ok(())
    }

    fn take(&self, key: &StateKey, now: u64) -> Result<Option<SealedState>, StoreError> {
        let removed = self.lock()?.remove(key);
        Ok(removed.and_then(|slot| (now < slot.expires_at).then_some(slot.sealed)))
    }

    fn purge_expired(&self, now: u64) -> Result<usize, StoreError> {
        let mut body = self.lock()?;
        let expired: Vec<StateKey> = body
            .slots
            .iter()
            .filter(|(_, slot)| now >= slot.expires_at)
            .map(|(key, _)| *key)
            .collect();
        for key in &expired {
            body.remove(key);
        }
        Ok(expired.len())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ferret_core::testing::{ReplayRng, TestRng};

    const ID_HEX: &str = "000102030405060708090a0b0c0d0e0f";

    fn id() -> LoginId {
        LoginId::parse(ID_HEX.as_bytes()).unwrap()
    }

    fn other_id() -> LoginId {
        LoginId::parse(b"ffffffffffffffffffffffffffffffff").unwrap()
    }

    fn seal_key() -> StateSealKey {
        StateSealKey(Zeroizing::new([0x42; 32]))
    }

    fn login_bytes() -> [u8; SERVER_LOGIN_LEN] {
        let mut out = [0u8; SERVER_LOGIN_LEN];
        for (i, b) in out.iter_mut().enumerate() {
            // Distinct, non-repeating windows.
            *b = (i as u8).wrapping_mul(7).wrapping_add(3);
        }
        out
    }

    fn plain(purpose: LoginPurpose) -> StatePlain {
        StatePlain {
            credential: CredentialId::from_bytes([0x31; 16]),
            purpose,
            expires_at: 1_700_000_060,
            ksf_profile: 2,
            server_login: Zeroizing::new(login_bytes()),
        }
    }

    fn reauth(fill: u8) -> LoginPurpose {
        LoginPurpose::Reauth {
            session: SessionBinding([fill; 32]),
        }
    }

    fn seal(key: &StateSealKey, id: &LoginId, state: &StatePlain) -> SealedState {
        seal_state(key, &mut TestRng::new(b"nonce"), id, state).unwrap()
    }

    fn assert_same(a: &StatePlain, b: &StatePlain) {
        assert_eq!(a.credential, b.credential);
        assert!(a.purpose.same_as(&b.purpose));
        assert_eq!(a.expires_at, b.expires_at);
        assert_eq!(a.ksf_profile, b.ksf_profile);
        assert_eq!(a.server_login.as_slice(), b.server_login.as_slice());
    }

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    fn invalid() -> AuthError {
        AuthError::Denied(DenyReason::StateInvalid)
    }

    #[test]
    fn sizes_add_up() {
        assert_eq!(PLAIN_LEN, 187);
        assert_eq!(BLOB_LEN, 228);
        let state = plain(LoginPurpose::Login);
        assert_eq!(state.encode().len(), PLAIN_LEN);
        assert_eq!(seal(&seal_key(), &id(), &state).as_bytes().len(), BLOB_LEN);
    }

    #[test]
    fn seal_open_roundtrip() {
        for purpose in [LoginPurpose::Login, reauth(0x77)] {
            let state = plain(purpose);
            let sealed = seal(&seal_key(), &id(), &state);
            let opened = open_state(&seal_key(), &id(), &sealed).unwrap();
            assert_same(&opened, &state);
        }
    }

    #[test]
    fn open_with_wrong_key_fails() {
        let sealed = seal(&seal_key(), &id(), &plain(LoginPurpose::Login));
        let other = StateSealKey(Zeroizing::new([0x43; 32]));
        assert_eq!(open_state(&other, &id(), &sealed).err(), Some(invalid()));
    }

    #[test]
    fn open_with_other_login_id_fails() {
        let sealed = seal(&seal_key(), &id(), &plain(LoginPurpose::Login));
        assert_eq!(
            open_state(&seal_key(), &other_id(), &sealed).err(),
            Some(invalid())
        );
    }

    #[test]
    fn every_flipped_bit_is_rejected() {
        for purpose in [LoginPurpose::Login, reauth(0x77)] {
            let sealed = seal(&seal_key(), &id(), &plain(purpose));
            for at in 0..BLOB_LEN {
                for bit in 0..8 {
                    let mut blob = sealed.as_bytes().to_vec();
                    blob[at] ^= 1 << bit;
                    assert_eq!(
                        open_state(&seal_key(), &id(), &SealedState::from_bytes(blob)).err(),
                        Some(invalid()),
                        "byte {at} bit {bit}"
                    );
                }
            }
        }
    }

    #[test]
    fn every_wrong_blob_length_is_rejected() {
        let sealed = seal(&seal_key(), &id(), &plain(LoginPurpose::Login));
        for len in 0..BLOB_LEN + 40 {
            if len == BLOB_LEN {
                continue;
            }
            let mut blob = sealed.as_bytes().to_vec();
            blob.resize(len, 0);
            assert_eq!(
                open_state(&seal_key(), &id(), &SealedState::from_bytes(blob)).err(),
                Some(invalid()),
                "length {len}"
            );
        }
        // Trailing bytes after a valid blob are not ignored.
        let mut longer = sealed.as_bytes().to_vec();
        longer.push(0);
        assert!(open_state(&seal_key(), &id(), &SealedState::from_bytes(longer)).is_err());
    }

    #[test]
    fn a_blob_of_another_version_is_rejected() {
        let sealed = seal(&seal_key(), &id(), &plain(LoginPurpose::Login));
        let mut blob = sealed.as_bytes().to_vec();
        blob[0] = 2;
        assert_eq!(
            open_state(&seal_key(), &id(), &SealedState::from_bytes(blob)).err(),
            Some(invalid())
        );
    }

    /// The credential, the purpose and the session are inside the sealed bytes,
    /// so a blob of one login cannot be made to open as another, and cannot be
    /// changed to name another account or session.
    #[test]
    fn aad_binds_credential_and_purpose() {
        let mut a = plain(LoginPurpose::Login);
        a.credential = CredentialId::from_bytes([0xa1; 16]);
        let b = plain(reauth(0x55));
        let key = seal_key();
        let (id_a, id_b) = (id(), other_id());
        let (sealed_a, sealed_b) = (seal(&key, &id_a, &a), seal(&key, &id_b, &b));
        // Swapped between the ids: neither opens.
        assert!(open_state(&key, &id_a, &sealed_b).is_err());
        assert!(open_state(&key, &id_b, &sealed_a).is_err());
        // Each opens only for its own id, and keeps its own account and purpose.
        let opened_a = open_state(&key, &id_a, &sealed_a).unwrap();
        let opened_b = open_state(&key, &id_b, &sealed_b).unwrap();
        assert_same(&opened_a, &a);
        assert_same(&opened_b, &b);
        assert_ne!(opened_a.credential, opened_b.credential);
        assert!(!opened_a.purpose.same_as(&opened_b.purpose));
    }

    #[test]
    fn nonce_is_fresh_per_seal() {
        let state = plain(LoginPurpose::Login);
        let mut rng = TestRng::new(b"fresh");
        let a = seal_state(&seal_key(), &mut rng, &id(), &state).unwrap();
        let b = seal_state(&seal_key(), &mut rng, &id(), &state).unwrap();
        assert_ne!(a.as_bytes(), b.as_bytes());
        assert_ne!(a.as_bytes().get(1..25), b.as_bytes().get(1..25));
        // Both still open.
        assert!(open_state(&seal_key(), &id(), &a).is_ok());
        assert!(open_state(&seal_key(), &id(), &b).is_ok());
    }

    #[test]
    fn sealing_draws_exactly_one_nonce_of_24_bytes() {
        let nonce: Vec<u8> = (0xa0..0xb8).collect();
        let mut rng = ReplayRng::new(vec![nonce.clone()]);
        let sealed = seal_state(&seal_key(), &mut rng, &id(), &plain(LoginPurpose::Login)).unwrap();
        rng.finish().unwrap();
        assert_eq!(sealed.as_bytes().get(1..25), Some(nonce.as_slice()));
    }

    #[test]
    fn server_login_bytes_do_not_appear_in_blob() {
        let state = plain(reauth(0x77));
        let sealed = seal(&seal_key(), &id(), &state);
        let blob = sealed.as_bytes();
        let login = login_bytes();
        assert!(!blob.windows(SERVER_LOGIN_LEN).any(|w| w == login));
        // Nor any 16-byte piece of it, the credential, or the session.
        for piece in login.chunks(16) {
            assert!(!blob.windows(piece.len()).any(|w| w == piece));
        }
        assert!(!blob.windows(16).any(|w| w == [0x31; 16]));
        assert!(!blob.windows(32).any(|w| w == [0x77; 32]));
        // The plaintext does hold them: the check is not vacuous.
        let plaintext = state.encode();
        assert!(plaintext.windows(SERVER_LOGIN_LEN).any(|w| w == login));
    }

    #[test]
    fn state_plain_parse_rejects_every_wrong_length() {
        let good = plain(reauth(0x77)).encode();
        assert!(StatePlain::parse(&good).is_ok());
        for len in 0..PLAIN_LEN + 64 {
            if len == PLAIN_LEN {
                continue;
            }
            let mut bytes = good.to_vec();
            bytes.resize(len, 0);
            assert_eq!(
                StatePlain::parse(&bytes).err(),
                Some(invalid()),
                "length {len}"
            );
        }
    }

    #[test]
    fn state_plain_parse_rejects_unknown_purpose_and_inconsistent_flag() {
        let login = plain(LoginPurpose::Login).encode().to_vec();
        let reauth = plain(reauth(0x77)).encode().to_vec();
        // Offsets: expires_at 0..8, purpose 8, flag 9, binding 10..42.
        assert!(StatePlain::parse(&login).is_ok());
        assert!(StatePlain::parse(&reauth).is_ok());
        for unknown in [2u8, 3, 0x7f, 0x80, 0xff] {
            for base in [&login, &reauth] {
                let mut bytes = base.clone();
                bytes[8] = unknown;
                assert!(StatePlain::parse(&bytes).is_err(), "purpose {unknown}");
            }
        }
        // The flag must agree with the purpose.
        for base in [&login, &reauth] {
            for flag in [0u8, 1, 2, 0xff] {
                let mut bytes = base.clone();
                bytes[9] = flag;
                assert_eq!(
                    StatePlain::parse(&bytes).is_ok(),
                    flag == base[9],
                    "flag {flag}"
                );
            }
        }
        // A login carries no binding.
        let mut bytes = login.clone();
        bytes[10 + 5] = 1;
        assert!(StatePlain::parse(&bytes).is_err());
        // A re-authentication may carry any binding.
        let mut bytes = reauth.clone();
        bytes[10 + 5] ^= 1;
        assert!(StatePlain::parse(&bytes).is_ok());
    }

    #[test]
    fn plaintext_layout_is_the_documented_one() {
        let state = plain(reauth(0x77));
        let mut expected = Vec::new();
        expected.extend_from_slice(&1_700_000_060u64.to_be_bytes());
        expected.extend_from_slice(&[1, 1]);
        expected.extend_from_slice(&[0x77; 32]);
        expected.extend_from_slice(&[0x31; 16]);
        expected.push(2);
        expected.extend_from_slice(&login_bytes());
        assert_eq!(state.encode().as_slice(), expected.as_slice());
        let login = plain(LoginPurpose::Login).encode();
        assert_eq!(login.get(8..10), Some(&[0u8, 0][..]));
        assert_eq!(login.get(10..42), Some(&[0u8; 32][..]));
    }

    /// Hand-written bytes for the key, the associated data and the blob. The
    /// key is checked against HKDF-SHA256 computed outside this crate; the
    /// blob is opened with the cipher itself and the hand-written data.
    #[test]
    fn key_and_blob_match_hand_written_bytes() {
        let secret = PreloginSecret::from_payload(&[0x11; 32]).unwrap();
        let key = StateSealKey::derive(&secret).unwrap();
        // HMAC-SHA256(HMAC-SHA256(0^32, secret), "ferret/v1/state-seal" ‖ 01)
        assert_eq!(
            hex(key.0.as_slice()),
            "c2b9dcaa1f3ea614af298812b19b34114c6c6a79afa122f736fa126feda8f1f6"
        );

        let nonce: Vec<u8> = (0xa0..0xb8).collect();
        let state = plain(reauth(0x77));
        let mut rng = ReplayRng::new(vec![nonce.clone()]);
        let sealed = seal_state(&key, &mut rng, &id(), &state).unwrap();
        rng.finish().unwrap();
        let blob = sealed.as_bytes();
        assert_eq!(blob.len(), 228);
        assert_eq!(blob.first(), Some(&1));
        assert_eq!(blob.get(1..25), Some(nonce.as_slice()));

        // The associated data, written out: label, version 1, suite 1, login id.
        let mut aad = vec![0x01, 0x00, 0x1c];
        aad.extend_from_slice(b"ferret/v1/server/login-state");
        aad.extend_from_slice(&[
            0x02, 0x00, 0x01, 0x01, 0x03, 0x00, 0x01, 0x01, 0x33, 0x00, 0x10,
        ]);
        aad.extend_from_slice(&(0u8..16).collect::<Vec<u8>>());
        assert_eq!(associated_data(&id()).unwrap(), aad);

        let mut buf = blob.get(25..).unwrap().to_vec();
        let xnonce = XNonce::from(<[u8; 24]>::try_from(nonce).unwrap());
        key.cipher()
            .decrypt_in_place(&xnonce, &aad, &mut buf)
            .unwrap();
        assert_eq!(buf.as_slice(), state.encode().as_slice());

        // The whole blob, pinned.
        assert_eq!(hex(blob), PINNED_BLOB);
    }

    /// The blob of `key_and_blob_match_hand_written_bytes` as the cipher made it:
    /// a change to the layout, the associated data or the key derivation changes
    /// these bytes.
    const PINNED_BLOB: &str = "01a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b76e4601b113792795161aaad60ed40cd956412efbe9df317d45dbcd46565bad7c6f4f4f5a440fc97a713afbdaf047e068875190b27fa1a55452cf3c015223b1e0ddd0dd2d2ed72b595ed20b6d12e75a021a4e4882d4703f673895ebdfa32423abb8b53c225bb592ef6bfdfe83594b3a3c49ae73724afd86e94624425a5a25479c0b3ccc05a72998da8f10b5617de9f37dfd976013b5d3c63533f25744f7395ec4fadece44e1be14f1e6f46a16a9dac4d66f79c74d4ab02bd94e9d61d7734b1e868788cbcb02a671f6de5dd1";

    #[test]
    fn derived_keys_depend_on_the_secret() {
        let a = StateSealKey::derive(&PreloginSecret::from_payload(&[1; 32]).unwrap()).unwrap();
        let b = StateSealKey::derive(&PreloginSecret::from_payload(&[2; 32]).unwrap()).unwrap();
        let a2 = StateSealKey::derive(&PreloginSecret::from_payload(&[1; 32]).unwrap()).unwrap();
        assert_ne!(*a.0, *b.0);
        assert_eq!(*a.0, *a2.0);
    }

    #[cfg(feature = "test-support")]
    #[test]
    fn random_key_takes_32_bytes_from_the_rng() {
        let mut rng = ReplayRng::new(vec![vec![0x09; 32]]);
        let key = StateSealKey::random(&mut rng);
        rng.finish().unwrap();
        assert_eq!(*key.0, [0x09; 32]);
    }

    #[test]
    fn expiry_stops_at_the_largest_value() {
        assert_eq!(StatePlain::expiry_from(1_000), 1_060);
        assert_eq!(StatePlain::expiry_from(0), STATE_TTL_SECS);
        assert_eq!(StatePlain::expiry_from(u64::MAX - 10), u64::MAX);
        assert_eq!(StatePlain::expiry_from(u64::MAX), u64::MAX);
    }

    #[test]
    fn a_state_is_live_until_the_second_before_its_expiry() {
        let mut state = plain(LoginPurpose::Login);
        state.expires_at = StatePlain::expiry_from(1_000);
        assert!(state.check_live(1_000).is_ok());
        assert!(state.check_live(1_059).is_ok());
        assert_eq!(
            state.check_live(1_060).err(),
            Some(AuthError::Denied(DenyReason::StateExpired))
        );
        assert!(state.check_live(1_061).is_err());
        assert!(state.check_live(u64::MAX).is_err());
    }

    #[test]
    fn a_failed_clock_never_gives_a_live_state() {
        // `SystemClock` reads u64::MAX before 1970.
        let now = u64::MAX;
        let mut state = plain(LoginPurpose::Login);
        state.expires_at = StatePlain::expiry_from(now);
        assert!(state.check_live(now).is_err());
        // A sealed state made then is dead on arrival, in the store as well.
        let store = InMemoryLoginStateStore::new();
        let key = id().store_key();
        let sealed = seal(&seal_key(), &id(), &state);
        store.put(key, sealed, state.expires_at, now).unwrap();
        assert!(store.take(&key, now).unwrap().is_none());
    }

    #[test]
    fn purposes_compare_by_kind_and_session() {
        assert!(LoginPurpose::Login.same_as(&LoginPurpose::Login));
        assert!(reauth(1).same_as(&reauth(1)));
        assert!(!reauth(1).same_as(&reauth(2)));
        assert!(!reauth(0).same_as(&LoginPurpose::Login));
        assert!(!LoginPurpose::Login.same_as(&reauth(0)));
        // One differing byte anywhere in the binding counts.
        for at in 0..32 {
            let mut other = [1u8; 32];
            other[at] ^= 0x80;
            let other = LoginPurpose::Reauth {
                session: SessionBinding(other),
            };
            assert!(!reauth(1).same_as(&other), "byte {at}");
        }
    }

    #[test]
    fn debug_shows_no_content() {
        let state = plain(reauth(0x77));
        let sealed = seal(&seal_key(), &id(), &state);
        let shown = format!(
            "{:?} {:?} {:?} {:?} {:?} {:?}",
            seal_key(),
            sealed,
            state,
            reauth(0x77),
            LoginPurpose::Login,
            InMemoryLoginStateStore::new()
        );
        assert_eq!(
            shown,
            "StateSealKey([redacted]) SealedState([redacted]) StatePlain([redacted]) \
             LoginPurpose::Reauth([redacted]) LoginPurpose::Login \
             InMemoryLoginStateStore([redacted])"
        );
        assert_eq!(format!("{:?}", StoreError::Collision), "Collision");
        let body = StoreBody::default();
        assert_eq!(format!("{body:?}"), "StoreBody([redacted])");
        let slot = Slot {
            sealed,
            expires_at: 0,
            order: 0,
        };
        assert_eq!(format!("{slot:?}"), "Slot([redacted])");
    }

    #[test]
    fn a_store_failure_is_an_internal_error() {
        for error in [StoreError::Full, StoreError::Collision, StoreError::Backend] {
            assert_eq!(
                AuthError::from(error),
                AuthError::Internal(InternalKind::Storage)
            );
        }
    }

    fn some_key(n: u8) -> StateKey {
        LoginId::parse(format!("{n:032x}").as_bytes())
            .unwrap()
            .store_key()
    }

    fn small(n: u8) -> SealedState {
        SealedState::from_bytes(vec![n; 4])
    }

    #[test]
    fn a_poisoned_store_fails_every_call_but_still_counts() {
        let store = InMemoryLoginStateStore::new();
        store.put(some_key(1), small(1), 100, 0).unwrap();
        std::thread::scope(|scope| {
            let handle = scope.spawn(|| {
                let _held = store.body.lock().unwrap();
                panic!("poison the lock");
            });
            assert!(handle.join().is_err());
        });
        assert_eq!(
            store.put(some_key(2), small(2), 100, 0),
            Err(StoreError::Backend)
        );
        assert_eq!(store.take(&some_key(1), 0).err(), Some(StoreError::Backend));
        assert_eq!(store.purge_expired(0), Err(StoreError::Backend));
        assert_eq!(store.len(), 1);
    }

    #[test]
    fn a_store_without_room_refuses_with_full() {
        let store = InMemoryLoginStateStore::with_capacity(0);
        assert_eq!(
            store.put(some_key(1), small(1), 100, 0),
            Err(StoreError::Full)
        );
        assert!(store.is_empty());
    }

    #[test]
    fn an_expired_state_does_not_block_its_key() {
        let store = InMemoryLoginStateStore::new();
        store.put(some_key(1), small(1), 100, 0).unwrap();
        assert_eq!(
            store.put(some_key(1), small(2), 200, 50),
            Err(StoreError::Collision)
        );
        // At the expiry second the old state counts as gone.
        store.put(some_key(1), small(3), 300, 100).unwrap();
        assert_eq!(store.len(), 1);
        assert_eq!(
            store.take(&some_key(1), 101).unwrap().unwrap().as_bytes(),
            &[3; 4]
        );
        assert!(store.is_empty());
    }

    #[test]
    fn the_age_index_follows_the_states() {
        let store = InMemoryLoginStateStore::with_capacity(2);
        store.put(some_key(1), small(1), 1000, 0).unwrap();
        store.put(some_key(2), small(2), 1000, 0).unwrap();
        // Taking the older one frees its place without evicting the other.
        assert!(store.take(&some_key(1), 1).unwrap().is_some());
        store.put(some_key(3), small(3), 1000, 1).unwrap();
        assert!(store.take(&some_key(2), 2).unwrap().is_some());
        assert!(store.take(&some_key(3), 2).unwrap().is_some());
        let body = store.body.lock().unwrap();
        assert!(body.slots.is_empty());
        assert!(body.by_age.is_empty());
    }

    #[test]
    fn sealed_state_hands_over_its_bytes() {
        let sealed = SealedState::from_bytes(vec![1, 2, 3]);
        assert_eq!(sealed.clone().into_bytes(), vec![1, 2, 3]);
        assert_eq!(sealed.as_bytes(), &[1, 2, 3]);
    }
}
