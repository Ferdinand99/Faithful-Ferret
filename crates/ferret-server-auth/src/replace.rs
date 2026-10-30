//! Challenges, signed proofs and the replacement of an OPAQUE record.
//!
//! Changing the master password, upgrading the key stretching profile and
//! recovering an account all replace the stored OPAQUE record. A caller that
//! holds nothing but a session must not be able to do that: it could lock the
//! user out. So each of these requests carries a proof signed by the client
//! (Spec: Fase 1 § 4.6), and [`authorize_replacement`] is the one place that
//! checks it. The other signed requests (adding or removing an unlock method,
//! replacing the recovery wrap, a rekey) go through [`authorize_signed`],
//! which is the same check without the record.
//!
//! Nothing outside this module verifies a proof. The functions of
//! `ferret-core` that do (`verify_auth_proof`, `verify_recovery_proof`) are
//! called from here only, after the nonce is used up, and a test keeps it so.
//! An endpoint that calls them itself has no single-use nonce, no binding to
//! the session and no throttle: its proofs can be replayed for the life of the
//! epoch.
//!
//! # The nonce
//!
//! [`issue_challenge`] gives a session a random nonce of 32 bytes. The server
//! keeps only a hash of the session binding and the nonce (a [`ChallengeKey`])
//! in a [`ChallengeStore`], never the nonce itself, and for
//! [`CHALLENGE_TTL_SECS`] seconds. A nonce belongs to the session it was
//! issued to, is used once, and expires: the key is the hash of both values,
//! so the nonce of another session finds nothing, and the store removes a key
//! when it is consumed.
//!
//! The nonce is consumed before the signature is checked. A request with a
//! wrong signature therefore burns its nonce, and a proof cannot be tried
//! twice against one nonce. The operation is not part of the nonce; it is part
//! of what the client signs, so a proof made for one operation (or with the
//! key and label of another) does not verify for a different one.
//!
//! # Order of a replacement
//!
//! 1. The scope of the session must allow the operation (`PasswordPut` or
//!    `Recover`, see [`crate::scope`]) and the clock must be readable.
//! 2. The throttle is asked (`Stage::Replace`) before any other work.
//! 3. The nonce is exactly 32 bytes and the proof exactly 64
//!    ([`Malformed::Nonce`], [`Malformed::Proof`]). These depend on the
//!    client's bytes alone.
//! 4. The nonce is consumed ([`DenyReason::NonceUnknown`] or
//!    [`DenyReason::NonceExpired`]).
//! 5. The proof is verified with the types of `ferret-core`, over the account
//!    id, the `vk_epoch` **the server holds**, the nonce and the exact body
//!    bytes ([`DenyReason::ProofInvalid`]).
//! 6. Only now is the body read. The caller's parser gets the proven bytes and
//!    nothing else, and returns the record, the profile claimed and, for a
//!    recovery, the new `pk_r`.
//! 7. The record is checked ([`ValidatedRecord::parse`]), a recovery must
//!    carry a new `pk_r` that differs from the stored one and a password change
//!    must not carry one ([`Malformed::RecoveryKey`]), and the profile is
//!    checked by the server's [`ProfileRules`](crate::ProfileRules) (never
//!    against anything in the request). A password change or an upgrade is
//!    compared with the profile
//!    **stored for the account**: one that is unknown or lower than the
//!    stored one is [`AuthError::ProfileRejected`]. A recovery is not
//!    compared with the stored profile: it needs the holder of the recovery
//!    key, and it may set any profile the rules accept, a lower one than the
//!    stored profile included. That is how a wrongly claimed higher profile
//!    is undone: a client that claimed a profile it did not use locks its own
//!    account out, and only a recovery can write a lower one.
//!
//! # A missing proof and a wrong proof
//!
//! A proof or a nonce that is missing, empty or of the wrong length is
//! [`Malformed::Proof`] or [`Malformed::Nonce`] (400, step 3). The lengths
//! are checked before the nonce is consumed, so such a request burns nothing
//! and a client can send it again. A proof of exactly 64 bytes that does not
//! verify (zero bytes or a flipped bit included) is
//! [`DenyReason::ProofInvalid`] (401 `denied`) and the nonce is already used
//! up. Both mean "no valid proof"; the difference is whether the nonce
//! survived.
//!
//! A refusal at step 3 or later is reported to the throttle as a failure, and
//! the result is reported as a success only when a permit is given.
//!
//! # Writing the result
//!
//! The library writes nothing. A permit is the right to write, and the
//! endpoint has to write it correctly:
//!
//! * **One transaction.** A [`ReplacePermit`] for a password change is
//!   written together with the new wraps and the manifest. A permit for a
//!   recovery is written together with the new `pk_r` (`new_pk_r`), the new
//!   password wrap, the new recovery wrap and the manifest. A recovery that
//!   leaves the old `pk_r` in place leaves the old recovery key able to
//!   sign.
//! * **Against the snapshot that was checked.** Every check was made against
//!   the [`AccountAuthState`] that the endpoint read before the call, and the
//!   permit carries what that was ([`WriteBasis`], `stored_ksf_profile`). The
//!   endpoint must either read the state and write inside one transaction
//!   that holds the account row (SQLite `BEGIN IMMEDIATE`), or write with a
//!   condition such as `WHERE account_id = ? AND row_version = ? AND vk_epoch
//!   = ? AND ksf_profile = ?` and treat zero changed rows as a refusal, never
//!   as a success. Without that, two requests that were both checked against
//!   profile 1 can both commit, and the second one undoes an upgrade; a
//!   password change signed for epoch *n* can commit after a rekey to
//!   *n + 1*; a recovery and a password change can interleave.
//!   `testing::TestAccountStore` shows the write.
//! * **Other sessions.** After a password change (unless the user opted out),
//!   a recovery and a rekey, the other sessions and the device tokens of the
//!   account are revoked (Spec: Fase 1 § 4.6). `session_effect` says only what
//!   happens to the session that made the request.
//!
//! # Other signed requests
//!
//! [`authorize_signed`] takes the operation (`UnlockMethodAdd`,
//! `UnlockMethodRemove`, `UnlockMethodRecoveryPut` or `Rekey`) and does the
//! scope check, the throttle, the single-use nonce and the proof for exactly
//! that operation. It returns a [`SignedPermit`] that carries the same
//! [`WriteBasis`]. The endpoint parses the body after that call, from the
//! same bytes. The body of `DELETE /api/vault/unlock-methods/{method_id}` is
//! `{method_id, manifest}`; the library does not see the URL, so the endpoint
//! must check that the `method_id` in the proven body is the one in the URL
//! before it removes anything.
//!
//! Two of these requests bring new keys in their bodies. `recovery.put` brings
//! a new `pk_r`, and `rekey` brings a new `pk_a`, a new `vk_epoch` and a new
//! `pk_r`. The endpoint must write those keys and the epoch in the same
//! conditional transaction as the rest of the request, under the
//! [`WriteBasis`] of the permit. A write that leaves the old key in place
//! leaves the old key able to sign.
//!
//! # Calling the core verifiers
//!
//! The test in this crate that keeps proof verification in one module covers
//! this crate only. A server crate built on this library should add a Clippy
//! `disallowed-methods` rule to its `clippy.toml` for the core `verify_*`
//! functions (`ferret_core::verify_auth_proof` and
//! `ferret_core::verify_recovery_proof`), so that it cannot check a proof
//! without the single-use nonce, the session binding and the throttle.
//!
//! Spec: Fase 1 § 4.6 and § 6.3.

use core::fmt;
use std::collections::{BTreeMap, HashMap};
use std::sync::{Mutex, MutexGuard};

use ferret_core::{
    AccountId, AuthPublicKey, MutationOp, RecoveryPublicKey, SecureRng, verify_auth_proof,
    verify_recovery_proof,
};
use sha2::{Digest, Sha256};

use crate::CHALLENGE_TTL_SECS;
use crate::error::{AuthError, DenyReason, InternalKind, Malformed};
use crate::ids::{CredentialId, SessionBinding};
use crate::login::AuthContext;
use crate::prelogin::step;
use crate::record::{RegistrationKind, StoredRecord, ValidatedRecord};
use crate::scope::{Capability, ScopeEffect, SessionScope, authorize};
use crate::state::StoreError;
use crate::throttle::{Admission, Caller, Outcome, Stage, admit};

/// Length of a nonce, in bytes.
const NONCE_LEN: usize = 32;
/// Length of a proof (an Ed25519 signature), in bytes.
const PROOF_LEN: usize = 64;

const fn clock_failed() -> AuthError {
    AuthError::Internal(InternalKind::Clock)
}

// ------------------------------------------------------------------- store

/// The key under which a nonce is stored: `SHA-256(session binding ‖ nonce)`.
///
/// The store never sees the nonce, so a dump of it holds nothing a client
/// could present, and the key of a nonce differs for every session.
///
/// Keys are compared with the derived equality and hashed in a `HashMap`, not
/// compared in constant time: a key is a hash of a nonce that the caller
/// cannot invert, so a timing difference would show a prefix of that hash and
/// nothing a client could use.
///
/// Spec: Fase 1 § 4.6 (the nonce is single-use and bound to the session).
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct ChallengeKey([u8; 32]);

impl ChallengeKey {
    /// The key of `nonce` in the session `session`.
    pub(crate) fn new(session: &SessionBinding, nonce: &[u8; NONCE_LEN]) -> Self {
        let mut hash = Sha256::new();
        hash.update(session.0);
        hash.update(nonce);
        Self(hash.finalize().into())
    }

    /// The 32 bytes, for a store to use as its key.
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Debug for ChallengeKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ChallengeKey([redacted])")
    }
}

/// What [`ChallengeStore::consume`] found.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConsumeOutcome {
    /// The nonce was live. It is gone now.
    Consumed,
    /// There is no such nonce: never issued, already used, or removed.
    Unknown,
    /// The nonce was issued and has expired. It is gone now.
    Expired,
}

/// Where the nonces of signed requests wait to be used.
///
/// Rules every implementation keeps, and `testing::challenge_conformance`
/// checks:
///
/// * a key is consumed at most once: `consume` removes it and reports it in
///   one atomic step, so two calls for the same key, at the same moment or one
///   after the other, never both give `Consumed`;
/// * a nonce is valid while `now < expires_at`: at `now == expires_at` it is
///   `Expired`, and `consume` removes it;
/// * `put` never replaces a live key, and refuses a key that is already
///   expired, or any call at `now == u64::MAX` (`Expired`);
/// * a store with a limit removes the oldest key to make room, for the reason
///   given at [`LoginStateStore`](crate::LoginStateStore): refusing would let
///   a flood of requests keep out every real one.
pub trait ChallengeStore: Send + Sync {
    /// Stores a key until `expires_at`. A live key is never overwritten
    /// (`Collision`); an expired one counts as absent.
    fn put(&self, key: ChallengeKey, expires_at: u64, now: u64) -> Result<(), StoreError>;

    /// Removes the key and says what it was, in one atomic step.
    fn consume(&self, key: &ChallengeKey, now: u64) -> Result<ConsumeOutcome, StoreError>;

    /// Removes every key that has expired and returns how many.
    fn purge_expired(&self, now: u64) -> Result<usize, StoreError>;
}

/// A key in the memory store.
struct KeySlot {
    expires_at: u64,
    /// When the key was stored, counted up: smaller is older.
    order: u64,
}

impl fmt::Debug for KeySlot {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("KeySlot([redacted])")
    }
}

/// The content of the memory store, under one lock.
#[derive(Default)]
struct KeyTable {
    slots: HashMap<ChallengeKey, KeySlot>,
    /// Keys by age, oldest first. Always the same keys as `slots`.
    by_age: BTreeMap<u64, ChallengeKey>,
    next_order: u64,
}

impl KeyTable {
    fn remove(&mut self, key: &ChallengeKey) -> Option<KeySlot> {
        let slot = self.slots.remove(key)?;
        self.by_age.remove(&slot.order);
        Some(slot)
    }

    /// Removes the oldest key. `false` when there is none.
    fn remove_oldest(&mut self) -> bool {
        let Some((_, key)) = self.by_age.pop_first() else {
            return false;
        };
        self.slots.remove(&key);
        true
    }
}

impl fmt::Debug for KeyTable {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("KeyTable([redacted])")
    }
}

/// A challenge store in memory.
///
/// It holds at most `capacity` keys (20 000 by default). When it is full, a
/// new key removes the oldest one. The defence against a flood is the rate
/// limit that runs before a nonce is issued.
///
/// Keys do not survive a restart of the process; the database store of the
/// next layer does.
pub struct InMemoryChallengeStore {
    capacity: usize,
    body: Mutex<KeyTable>,
}

impl InMemoryChallengeStore {
    /// The default limit on the number of keys.
    pub const DEFAULT_CAPACITY: usize = 20_000;

    /// A store with the default limit.
    pub fn new() -> Self {
        Self::with_capacity(Self::DEFAULT_CAPACITY)
    }

    /// A store that holds at most `capacity` keys. With 0 every `put` is
    /// refused with `Full`.
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            capacity,
            body: Mutex::new(KeyTable::default()),
        }
    }

    /// The number of keys held, expired ones that were not yet removed
    /// included.
    pub fn len(&self) -> usize {
        // Every change is made under the lock and none of them can fail half
        // way, so a poisoned lock still holds a consistent body.
        self.body
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .slots
            .len()
    }

    /// Whether the store holds no key.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// The lock. A store whose lock was poisoned by a panic is not trusted:
    /// every call fails with `Backend`.
    fn lock(&self) -> Result<MutexGuard<'_, KeyTable>, StoreError> {
        self.body.lock().map_err(|_| StoreError::Backend)
    }
}

impl Default for InMemoryChallengeStore {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Debug for InMemoryChallengeStore {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("InMemoryChallengeStore([redacted])")
    }
}

impl ChallengeStore for InMemoryChallengeStore {
    fn put(&self, key: ChallengeKey, expires_at: u64, now: u64) -> Result<(), StoreError> {
        // This includes `now == u64::MAX`, whatever the expiry.
        if now >= expires_at {
            return Err(StoreError::Expired);
        }
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
        body.slots.insert(key, KeySlot { expires_at, order });
        Ok(())
    }

    fn consume(&self, key: &ChallengeKey, now: u64) -> Result<ConsumeOutcome, StoreError> {
        Ok(match self.lock()?.remove(key) {
            None => ConsumeOutcome::Unknown,
            Some(slot) if now < slot.expires_at => ConsumeOutcome::Consumed,
            Some(_) => ConsumeOutcome::Expired,
        })
    }

    fn purge_expired(&self, now: u64) -> Result<usize, StoreError> {
        let mut body = self.lock()?;
        let expired: Vec<ChallengeKey> = body
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

// --------------------------------------------------------------- challenge

/// A nonce for one signed request, as the client receives it.
pub struct Challenge {
    /// 32 random bytes. The client signs them into the proof.
    pub nonce: [u8; NONCE_LEN],
    /// How long the nonce is valid, in seconds ([`CHALLENGE_TTL_SECS`]).
    pub expires_in: u64,
}

impl fmt::Debug for Challenge {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Challenge([redacted])")
    }
}

/// Gives the session a nonce for a signed request.
///
/// The scope must allow [`Capability::Challenge`]. The throttle is asked
/// before the nonce is drawn (`Stage::Challenge`, by address and account).
/// The function draws 32 bytes, stores `SHA-256(session ‖ nonce)` until
/// [`CHALLENGE_TTL_SECS`] seconds from now, and answers.
///
/// `session` and `account` are the binding and the account of the session the
/// request came in, taken from the session the endpoint has found and never
/// from the request.
///
/// Errors: [`AuthError::Denied`] with `ScopeForbids`,
/// [`AuthError::Throttled`], and [`AuthError::Internal`] for a clock that
/// failed or a store that could not keep the key.
///
/// Spec: Fase 1 § 4.6 (the signature, step 1).
pub fn issue_challenge<R: SecureRng, S: ChallengeStore>(
    cx: &AuthContext<'_>,
    store: &S,
    rng: &mut R,
    caller: &Caller,
    scope: SessionScope,
    session: &SessionBinding,
    account: &AccountId,
) -> Result<Challenge, AuthError> {
    step("scope");
    authorize(scope, Capability::Challenge)?;
    let now = cx.clock().now_unix();
    // A clock that failed reads `u64::MAX`; a key made then would become
    // valid again once the clock is repaired.
    if now == u64::MAX {
        return Err(clock_failed());
    }
    step("admit");
    let id = CredentialId::from(account);
    let ticket = admit(cx.throttle(), Stage::Challenge, caller, Some(&id), now)?;
    let issued = issue_admitted(store, rng, session, now);
    let outcome = if issued.is_ok() {
        Outcome::Success
    } else {
        Outcome::Failure
    };
    ticket.finish(outcome, now);
    issued
}

fn issue_admitted<R: SecureRng, S: ChallengeStore>(
    store: &S,
    rng: &mut R,
    session: &SessionBinding,
    now: u64,
) -> Result<Challenge, AuthError> {
    let expires_at = now
        .checked_add(CHALLENGE_TTL_SECS)
        .ok_or_else(clock_failed)?;
    step("draw");
    let mut nonce = [0u8; NONCE_LEN];
    rng.fill(&mut nonce);
    step("put");
    store
        .put(ChallengeKey::new(session, &nonce), expires_at, now)
        .map_err(AuthError::from)?;
    Ok(Challenge {
        nonce,
        expires_in: CHALLENGE_TTL_SECS,
    })
}

// ---------------------------------------------------------- signed requests

/// What the server holds for the account that signs a request. Every value
/// comes from the stored row, never from the request.
#[derive(Clone, Copy)]
pub struct SignedAccount {
    /// The account.
    pub account_id: AccountId,
    /// `pk_a`, the key that checks every proof but a recovery.
    pub pk_a: AuthPublicKey,
    /// `pk_r`, the key that checks a recovery.
    pub pk_r: RecoveryPublicKey,
    /// The epoch of the vault key now. The proof must have been made for it.
    pub vk_epoch: u64,
    /// A number the server raises with every write to the keys, wraps and
    /// record of the account. It is carried into the permit
    /// ([`WriteBasis`]), so the write can refuse a permit that was made
    /// against a row that has changed since.
    pub row_version: u64,
}

impl fmt::Debug for SignedAccount {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SignedAccount([redacted])")
    }
}

/// The state of the account that a permit was checked against.
///
/// Every check of the library is made against a snapshot that the endpoint
/// read before the call. The permit says which snapshot, so the write can
/// make sure that it is still the current one (see the module documentation,
/// "Writing the result").
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct WriteBasis {
    /// The account.
    pub account_id: AccountId,
    /// The vault key epoch the proof was checked for.
    pub vk_epoch: u64,
    /// The `pk_a` the proof was checked against, or would have been.
    pub pk_a: AuthPublicKey,
    /// The `pk_r` the proof was checked against, or would have been.
    pub pk_r: RecoveryPublicKey,
    /// The row version of the snapshot.
    pub row_version: u64,
}

impl WriteBasis {
    fn of(account: &SignedAccount) -> Self {
        Self {
            account_id: account.account_id,
            vk_epoch: account.vk_epoch,
            pk_a: account.pk_a,
            pk_r: account.pk_r,
            row_version: account.row_version,
        }
    }
}

impl fmt::Debug for WriteBasis {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("WriteBasis([redacted])")
    }
}

/// What the scope of the session must allow for an operation, or `None` for
/// an operation the library does not know.
const fn capability_of(op: MutationOp) -> Option<Capability> {
    match op {
        MutationOp::UnlockMethodAdd
        | MutationOp::UnlockMethodRemove
        | MutationOp::UnlockMethodRecoveryPut => Some(Capability::UnlockMethodsWrite),
        MutationOp::UnlockMethodPasswordPut => Some(Capability::PasswordPut),
        MutationOp::Recover => Some(Capability::Recover),
        MutationOp::Rekey => Some(Capability::Rekey),
        _ => None,
    }
}

/// The scope, the clock and the throttle: everything that comes before the
/// nonce. Gives the time and the ticket to report the outcome with.
fn begin<'a>(
    cx: &AuthContext<'a>,
    caller: &Caller,
    scope: SessionScope,
    capability: Capability,
    account_id: &AccountId,
) -> Result<(u64, Admission<'a>), AuthError> {
    step("scope");
    authorize(scope, capability)?;
    let now = cx.clock().now_unix();
    if now == u64::MAX {
        return Err(clock_failed());
    }
    // The account is known (the session belongs to it), so the limiter sees
    // it. Nothing but pure computation has happened so far.
    step("admit");
    let id = CredentialId::from(account_id);
    let ticket = admit(cx.throttle(), Stage::Replace, caller, Some(&id), now)?;
    Ok((now, ticket))
}

/// The nonce and the proof: exact lengths, the nonce used up, and the proof
/// verified with the types of `ferret-core`.
///
/// This is the one place in the crate that verifies a proof. It is private
/// on purpose: a proof checked without it has no single-use nonce and no
/// binding to the session.
fn consume_and_verify<S: ChallengeStore>(
    store: &S,
    account: &SignedAccount,
    op: MutationOp,
    session: &SessionBinding,
    (nonce, proof, body): (&[u8], &[u8], &[u8]),
    now: u64,
) -> Result<(), AuthError> {
    // Exact lengths first: they depend on the client's bytes alone.
    step("lengths");
    let nonce: &[u8; NONCE_LEN] = nonce
        .try_into()
        .map_err(|_| AuthError::Malformed(Malformed::Nonce))?;
    let proof: &[u8; PROOF_LEN] = proof
        .try_into()
        .map_err(|_| AuthError::Malformed(Malformed::Proof))?;

    // The nonce is used up before the signature is looked at, so a wrong
    // signature burns it.
    step("consume");
    let key = ChallengeKey::new(session, nonce);
    match store.consume(&key, now).map_err(AuthError::from)? {
        ConsumeOutcome::Consumed => {}
        ConsumeOutcome::Unknown => return Err(AuthError::Denied(DenyReason::NonceUnknown)),
        ConsumeOutcome::Expired => return Err(AuthError::Denied(DenyReason::NonceExpired)),
    }

    // The epoch is the server's own: a client cannot pick the one it signed.
    step("verify");
    let verified = match (op.auth(), op) {
        (Some(auth), _) => verify_auth_proof(
            &account.pk_a,
            auth,
            &account.account_id,
            nonce,
            account.vk_epoch,
            body,
            proof,
        ),
        (None, MutationOp::Recover) => verify_recovery_proof(
            &account.pk_r,
            &account.account_id,
            nonce,
            account.vk_epoch,
            body,
            proof,
        ),
        // An operation the library does not know cannot be verified.
        (None, _) => return Err(AuthError::Denied(DenyReason::ProofInvalid)),
    };
    verified.map_err(|_| AuthError::Denied(DenyReason::ProofInvalid))
}

/// A signed request that changes the keys, wraps or manifest of an account
/// but does not replace the OPAQUE record.
#[derive(Clone, Copy)]
pub struct SignedRequest<'a> {
    /// Who is calling.
    pub caller: Caller,
    /// The operation the proof is for: `UnlockMethodAdd`,
    /// `UnlockMethodRemove`, `UnlockMethodRecoveryPut` or `Rekey`. The
    /// operations that replace the record, `UnlockMethodPasswordPut` and
    /// `Recover`, go through [`authorize_replacement`].
    pub op: MutationOp,
    /// The scope of the session the request came in. The endpoint takes it
    /// from the session, never from the request.
    pub scope: SessionScope,
    /// The binding of that session. The nonce must have been issued to it.
    pub session: SessionBinding,
    /// The nonce of the proof (`Ferret-Nonce`), exactly 32 bytes.
    pub nonce: &'a [u8],
    /// The proof (`Ferret-Proof`), exactly 64 bytes.
    pub proof: &'a [u8],
    /// The body of the request, byte for byte as it was received.
    pub body: &'a [u8],
}

impl fmt::Debug for SignedRequest<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SignedRequest([redacted])")
    }
}

/// The right to carry out a signed request. Nothing has been written.
pub struct SignedPermit {
    /// The account that signed.
    pub account_id: AccountId,
    /// The operation the proof was for.
    pub op: MutationOp,
    /// `SHA-256` of the body the proof covers.
    pub body_sha256: [u8; 32],
    /// What a successful request does to the session that made it.
    pub session_effect: ScopeEffect,
    /// The snapshot of the account that the proof was checked against.
    pub basis: WriteBasis,
}

impl fmt::Debug for SignedPermit {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SignedPermit([redacted])")
    }
}

/// Checks the proof of a request that adds or removes an unlock method,
/// replaces the recovery wrap, or commits a rekey, and gives the permit to
/// carry it out.
///
/// The order is the one of [`authorize_replacement`] without the record:
/// scope, clock, throttle (`Stage::Replace`), exact lengths, the nonce used
/// up, the proof verified for exactly this operation, over the account id,
/// the `vk_epoch` the server holds and the exact body. The library does not
/// read the body. The endpoint parses it after this call, from the same
/// bytes.
///
/// For `unlock-method.remove` the body is `{method_id, manifest}`, and the
/// endpoint must compare the `method_id` in it with the one in the URL before
/// it removes anything; the library does not see the URL.
///
/// An operation that replaces the record (`UnlockMethodPasswordPut`,
/// `Recover`) is refused with `Internal(Policy)`: it would skip the checks of
/// the record and the profile. An operation the library does not know is
/// refused with `ScopeForbids`.
///
/// Errors: as for [`authorize_replacement`], without the errors of the
/// record and the profile.
///
/// Spec: Fase 1 § 4.6.
pub fn authorize_signed<S: ChallengeStore>(
    cx: &AuthContext<'_>,
    store: &S,
    account: &SignedAccount,
    req: &SignedRequest<'_>,
) -> Result<SignedPermit, AuthError> {
    if matches!(
        req.op,
        MutationOp::UnlockMethodPasswordPut | MutationOp::Recover
    ) {
        return Err(AuthError::Internal(InternalKind::Policy));
    }
    let capability = capability_of(req.op).ok_or(AuthError::Denied(DenyReason::ScopeForbids))?;
    let (now, ticket) = begin(cx, &req.caller, req.scope, capability, &account.account_id)?;
    let checked = consume_and_verify(
        store,
        account,
        req.op,
        &req.session,
        (req.nonce, req.proof, req.body),
        now,
    );
    let outcome = if checked.is_ok() {
        Outcome::Success
    } else {
        Outcome::Failure
    };
    ticket.finish(outcome, now);
    checked?;
    Ok(SignedPermit {
        account_id: account.account_id,
        op: req.op,
        body_sha256: Sha256::digest(req.body).into(),
        session_effect: req.scope.effect_of(capability),
        basis: WriteBasis::of(account),
    })
}

// ------------------------------------------------------------ replacement

/// Which request replaces the record.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReplaceKind {
    /// A change of the master password, or an upgrade of the key stretching
    /// profile (the same request with a higher profile). Signed by `sk_a`
    /// for `unlock-method.password.put`.
    PasswordPut,
    /// A recovery. Signed by `sk_r` with the label `ferret/v1/recovery-req`.
    /// It brings a new `pk_r`.
    Recover,
}

impl ReplaceKind {
    /// What the scope of the session must allow for this request.
    const fn capability(self) -> Capability {
        match self {
            ReplaceKind::PasswordPut => Capability::PasswordPut,
            ReplaceKind::Recover => Capability::Recover,
        }
    }

    /// The operation the proof is for.
    const fn op(self) -> MutationOp {
        match self {
            ReplaceKind::PasswordPut => MutationOp::UnlockMethodPasswordPut,
            ReplaceKind::Recover => MutationOp::Recover,
        }
    }
}

/// What the server holds for the account whose record is replaced. Every
/// value comes from the stored row, never from the request.
#[derive(Clone, Copy)]
pub struct AccountAuthState<'a> {
    /// The keys, the epoch and the row version.
    pub account: SignedAccount,
    /// The record stored now, whose profile a new one may not undercut.
    pub current: &'a StoredRecord,
}

impl fmt::Debug for AccountAuthState<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("AccountAuthState([redacted])")
    }
}

/// The record, the profile and, for a recovery, the new `pk_r` that a body
/// carries.
pub struct ReplaceFields<'b> {
    /// The 192 bytes of the new OPAQUE record.
    pub record: &'b [u8],
    /// The profile number the client claims for it.
    pub ksf_profile: u32,
    /// The new `pk_r` of a recovery: present for [`ReplaceKind::Recover`] and
    /// absent for [`ReplaceKind::PasswordPut`]. Anything else is
    /// [`Malformed::RecoveryKey`], and so is a recovery whose key equals the
    /// stored `pk_r`. A recovery that did not bring a new key would leave the
    /// old recovery key valid.
    ///
    /// No curve check is made on the key here. A key that is not a valid
    /// point only breaks the owner's next recovery: `verify_strict` rejects
    /// such a key when it is used to check a proof, so nobody can forge a
    /// proof against it, and the owner can still sign in with the password
    /// and replace the recovery key.
    pub pk_r_new: Option<RecoveryPublicKey>,
}

impl fmt::Debug for ReplaceFields<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ReplaceFields([redacted])")
    }
}

/// A request to replace the record.
#[derive(Clone, Copy)]
pub struct ReplaceRequest<'a> {
    /// Who is calling.
    pub caller: Caller,
    /// Which request it is.
    pub kind: ReplaceKind,
    /// The scope of the session the request came in. The endpoint takes it
    /// from the session, never from the request.
    pub scope: SessionScope,
    /// The binding of that session. The nonce must have been issued to it.
    pub session: SessionBinding,
    /// The nonce of the proof (`Ferret-Nonce`), exactly 32 bytes.
    pub nonce: &'a [u8],
    /// The proof (`Ferret-Proof`), exactly 64 bytes.
    pub proof: &'a [u8],
    /// The body of the request, byte for byte as it was received.
    pub body: &'a [u8],
}

impl fmt::Debug for ReplaceRequest<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ReplaceRequest([redacted])")
    }
}

/// The right to replace a record. Nothing has been written.
///
/// The endpoint writes the record, the wraps, the manifest and, for a
/// recovery, the new `pk_r` in one transaction, and only if the account still
/// is what the permit was checked against. See the module documentation,
/// "Writing the result".
pub struct ReplacePermit {
    /// The account whose record is replaced.
    pub account_id: AccountId,
    /// Which request it was.
    pub kind: ReplaceKind,
    /// The new record, with the profile that was checked.
    pub new: StoredRecord,
    /// The new `pk_r`: `Some` for a recovery, `None` for a password change.
    /// It replaces the stored `pk_r` in the same transaction as the record.
    pub new_pk_r: Option<RecoveryPublicKey>,
    /// `SHA-256` of the body the proof covers.
    pub body_sha256: [u8; 32],
    /// What a successful replacement does to the session that made the
    /// request. A recovery in a session opened after an account reset ends
    /// that session ([`ScopeEffect::EndSession`]).
    pub session_effect: ScopeEffect,
    /// The profile stored for the account when the new one was checked. The
    /// write must still find this one.
    pub stored_ksf_profile: u8,
    /// The snapshot of the account that the proof was checked against.
    pub basis: WriteBasis,
}

impl fmt::Debug for ReplacePermit {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ReplacePermit([redacted])")
    }
}

/// Checks a request that replaces the record of an account and, if it holds,
/// gives the permit to replace it. See the module documentation for the
/// order of the checks.
///
/// `parse` gets the body, which is the exact bytes that the proof covers, and
/// is the only place the new record, the profile and the new `pk_r` can come
/// from. It is called after the proof has verified and not before. The
/// endpoint's parser decides what the body looks like (JSON) and reports a
/// body that does not parse as it sees fit; it must not return fields that
/// are not in the bytes.
///
/// For a password change or an upgrade the profile is compared with
/// `account.current`, the profile stored for the account, with
/// [`RegistrationKind::Existing`]: a profile that is unknown or lower than
/// the stored one is [`AuthError::ProfileRejected`], whoever signed the proof.
/// A recovery is checked by
/// [`ProfileRules::accept_recovery`](crate::ProfileRules::accept_recovery) and
/// may set a lower profile than the stored one.
///
/// Errors: [`AuthError::Denied`] with `ScopeForbids`, `NonceUnknown`,
/// `NonceExpired` or `ProofInvalid`; [`AuthError::Malformed`] for a nonce or a
/// proof of the wrong length, for a record that is not well formed and for a
/// new `pk_r` that is missing or not wanted; [`AuthError::ProfileRejected`];
/// [`AuthError::Throttled`]; [`AuthError::Internal`]; and whatever `parse`
/// returns.
///
/// Spec: Fase 1 § 4.6 and § 6.3 (step 4).
pub fn authorize_replacement<S, P>(
    cx: &AuthContext<'_>,
    store: &S,
    account: &AccountAuthState<'_>,
    req: &ReplaceRequest<'_>,
    parse: P,
) -> Result<ReplacePermit, AuthError>
where
    S: ChallengeStore,
    P: for<'b> FnOnce(&'b [u8]) -> Result<ReplaceFields<'b>, AuthError>,
{
    let (now, ticket) = begin(
        cx,
        &req.caller,
        req.scope,
        req.kind.capability(),
        &account.account.account_id,
    )?;
    let permit = authorize_admitted(cx, store, account, req, parse, now);
    let outcome = if permit.is_ok() {
        Outcome::Success
    } else {
        Outcome::Failure
    };
    ticket.finish(outcome, now);
    permit
}

/// The part of the replacement that runs after the limiter let it through.
fn authorize_admitted<S, P>(
    cx: &AuthContext<'_>,
    store: &S,
    account: &AccountAuthState<'_>,
    req: &ReplaceRequest<'_>,
    parse: P,
    now: u64,
) -> Result<ReplacePermit, AuthError>
where
    S: ChallengeStore,
    P: for<'b> FnOnce(&'b [u8]) -> Result<ReplaceFields<'b>, AuthError>,
{
    consume_and_verify(
        store,
        &account.account,
        req.kind.op(),
        &req.session,
        (req.nonce, req.proof, req.body),
        now,
    )?;

    // Only the bytes the proof covers are read.
    step("parse-body");
    let fields = parse(req.body)?;
    step("validate-record");
    let record = ValidatedRecord::parse(fields.record)?;
    // A recovery brings a new `pk_r` and a password change does not. A
    // recovery must also change the key: one that keeps the stored key leaves
    // the old recovery key able to sign. The proof has been verified over the
    // stored `pk_r`, so naming it here tells the caller nothing new.
    step("new-key");
    let new_pk_r = match (req.kind, fields.pk_r_new) {
        (ReplaceKind::Recover, Some(key)) if key == account.account.pk_r => {
            return Err(AuthError::Malformed(Malformed::RecoveryKey));
        }
        (ReplaceKind::Recover, Some(key)) => Some(key),
        (ReplaceKind::PasswordPut, None) => None,
        (ReplaceKind::Recover, None) | (ReplaceKind::PasswordPut, Some(_)) => {
            return Err(AuthError::Malformed(Malformed::RecoveryKey));
        }
    };
    step("profile");
    let ksf_profile = match req.kind {
        // A recovery needs the holder of the recovery key and may set any
        // profile the rules accept, a lower one than the stored profile
        // included: that is how a wrongly claimed higher profile is undone.
        ReplaceKind::Recover => cx.profiles().accept_recovery(fields.ksf_profile)?,
        // A password change or an upgrade may not lower the profile.
        ReplaceKind::PasswordPut => cx.profiles().accept(
            fields.ksf_profile,
            RegistrationKind::Existing(account.current.ksf_profile),
        )?,
    };

    Ok(ReplacePermit {
        account_id: account.account.account_id,
        kind: req.kind,
        new: StoredRecord {
            record,
            ksf_profile,
        },
        new_pk_r,
        body_sha256: Sha256::digest(req.body).into(),
        session_effect: req.scope.effect_of(req.kind.capability()),
        stored_ksf_profile: account.current.ksf_profile,
        basis: WriteBasis::of(&account.account),
    })
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicBool, Ordering};

    use ferret_core::TestRng;

    use super::*;
    use crate::prelogin::{clear_steps, steps};
    use crate::testing::LoginFixture;
    use crate::throttle::{RetryAfter, Throttle, ThrottleKey};

    const NOW: u64 = LoginFixture::START;

    fn session(fill: u8) -> SessionBinding {
        SessionBinding([fill; 32])
    }

    fn account() -> AccountId {
        AccountId::from_bytes([0x11; 16])
    }

    fn key(n: u8) -> ChallengeKey {
        ChallengeKey::new(&session(n), &[n; 32])
    }

    #[test]
    fn challenge_key_is_the_hash_of_session_and_nonce() {
        // SHA-256 of 32 bytes 0x01 followed by 32 bytes 0x02, computed outside
        // this crate.
        let expected = "f818afd37a6dc3bc92fb44731011277006db4efa6e9023cd7468c02335d22a4d";
        let made = ChallengeKey::new(&SessionBinding([1; 32]), &[2; 32]);
        let hex: String = made.as_bytes().iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(hex, expected);
        // The key holds neither value, and either one changes it.
        assert!(
            !made
                .as_bytes()
                .windows(8)
                .any(|w| w == [1; 8] || w == [2; 8])
        );
        assert_ne!(made, ChallengeKey::new(&SessionBinding([3; 32]), &[2; 32]));
        assert_ne!(made, ChallengeKey::new(&SessionBinding([1; 32]), &[3; 32]));
    }

    #[test]
    fn debug_hides_the_value() {
        let shown = format!(
            "{:?} {:?} {:?}",
            key(1),
            Challenge {
                nonce: [9; 32],
                expires_in: 300
            },
            InMemoryChallengeStore::new(),
        );
        assert_eq!(
            shown,
            "ChallengeKey([redacted]) Challenge([redacted]) InMemoryChallengeStore([redacted])"
        );
    }

    #[test]
    fn a_failed_lock_is_a_backend_error() {
        let store = InMemoryChallengeStore::new();
        std::thread::scope(|scope| {
            let handle = scope.spawn(|| {
                let _guard = store.body.lock().unwrap();
                panic!("poison the lock");
            });
            assert!(handle.join().is_err());
        });
        assert_eq!(store.put(key(1), NOW + 300, NOW), Err(StoreError::Backend));
        assert_eq!(store.consume(&key(1), NOW), Err(StoreError::Backend));
        assert_eq!(store.purge_expired(NOW), Err(StoreError::Backend));
        // Counting is still allowed.
        assert_eq!(store.len(), 0);
    }

    #[test]
    fn the_memory_store_counts_what_it_holds() {
        let store = InMemoryChallengeStore::with_capacity(2);
        assert!(store.is_empty());
        store.put(key(1), NOW + 300, NOW).unwrap();
        assert_eq!(store.len(), 1);
        assert_eq!(
            InMemoryChallengeStore::with_capacity(0).put(key(1), NOW + 300, NOW),
            Err(StoreError::Full)
        );
    }

    /// The order in which the effects of a call happen.
    struct NonceLog(Mutex<Vec<&'static str>>);

    impl fmt::Debug for NonceLog {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_str("NonceLog")
        }
    }

    impl NonceLog {
        fn new() -> Self {
            Self(Mutex::new(Vec::new()))
        }

        fn push(&self, what: &'static str) {
            self.0.lock().unwrap().push(what);
        }

        fn take(&self) -> Vec<&'static str> {
            std::mem::take(&mut *self.0.lock().unwrap())
        }
    }

    struct NonceThrottle<'a> {
        log: &'a NonceLog,
        refuse: AtomicBool,
    }

    impl fmt::Debug for NonceThrottle<'_> {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_str("NonceThrottle")
        }
    }

    impl Throttle for NonceThrottle<'_> {
        fn admit(&self, _: Stage, _: &[ThrottleKey], _: u64) -> Result<(), RetryAfter> {
            self.log.push("admit");
            if self.refuse.load(Ordering::SeqCst) {
                Err(RetryAfter::new(5))
            } else {
                Ok(())
            }
        }

        fn record(&self, _: Stage, _: &[ThrottleKey], _: Outcome, _: u64) {
            self.log.push("record");
        }
    }

    struct NonceStore<'a> {
        log: &'a NonceLog,
        inner: InMemoryChallengeStore,
    }

    impl fmt::Debug for NonceStore<'_> {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_str("NonceStore")
        }
    }

    impl ChallengeStore for NonceStore<'_> {
        fn put(&self, key: ChallengeKey, expires_at: u64, now: u64) -> Result<(), StoreError> {
            self.log.push("put");
            self.inner.put(key, expires_at, now)
        }

        fn consume(&self, key: &ChallengeKey, now: u64) -> Result<ConsumeOutcome, StoreError> {
            self.log.push("consume");
            self.inner.consume(key, now)
        }

        fn purge_expired(&self, now: u64) -> Result<usize, StoreError> {
            self.inner.purge_expired(now)
        }
    }

    struct NonceRng<'a> {
        log: &'a NonceLog,
        inner: TestRng,
    }

    impl fmt::Debug for NonceRng<'_> {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_str("NonceRng")
        }
    }

    impl SecureRng for NonceRng<'_> {
        fn fill(&mut self, dest: &mut [u8]) {
            self.log.push("draw");
            self.inner.fill(dest);
        }
    }

    fn context<'a>(f: &'a LoginFixture, throttle: &'a NonceThrottle<'a>) -> AuthContext<'a> {
        AuthContext::new(
            &f.keys,
            &f.prelogin,
            &f.seal,
            &f.clock,
            throttle,
            &f.policy,
            &f.profiles,
        )
    }

    #[test]
    fn admit_is_the_first_effect_of_issue_challenge() {
        let f = LoginFixture::new();
        let log = NonceLog::new();
        let throttle = NonceThrottle {
            log: &log,
            refuse: AtomicBool::new(false),
        };
        let store = NonceStore {
            log: &log,
            inner: InMemoryChallengeStore::new(),
        };
        let cx = context(&f, &throttle);
        let mut rng = NonceRng {
            log: &log,
            inner: TestRng::new(b"order"),
        };
        clear_steps();
        let caller = LoginFixture::caller();
        let challenge = issue_challenge(
            &cx,
            &store,
            &mut rng,
            &caller,
            SessionScope::Full,
            &session(1),
            &account(),
        )
        .unwrap();
        assert_eq!(challenge.expires_in, 300);
        assert_eq!(log.take(), ["admit", "draw", "put", "record"]);
        assert_eq!(steps(), ["scope", "admit", "draw", "put"]);

        // A refusal ends the call at the limiter: no draw, no write.
        throttle.refuse.store(true, Ordering::SeqCst);
        clear_steps();
        let error = issue_challenge(
            &cx,
            &store,
            &mut rng,
            &caller,
            SessionScope::Full,
            &session(1),
            &account(),
        )
        .unwrap_err();
        assert_eq!(
            error,
            AuthError::Throttled {
                retry_after_secs: 5
            }
        );
        assert_eq!(log.take(), ["admit"]);
        assert_eq!(steps(), ["scope", "admit"]);
    }

    #[test]
    fn issue_challenge_refuses_a_scope_without_touching_anything() {
        let f = LoginFixture::new();
        let log = NonceLog::new();
        let throttle = NonceThrottle {
            log: &log,
            refuse: AtomicBool::new(false),
        };
        let store = NonceStore {
            log: &log,
            inner: InMemoryChallengeStore::new(),
        };
        let cx = context(&f, &throttle);
        let mut rng = NonceRng {
            log: &log,
            inner: TestRng::new(b"order"),
        };
        for scope in [SessionScope::Pending2fa, SessionScope::Unverified] {
            let error = issue_challenge(
                &cx,
                &store,
                &mut rng,
                &LoginFixture::caller(),
                scope,
                &session(1),
                &account(),
            )
            .unwrap_err();
            assert_eq!(error, AuthError::Denied(DenyReason::ScopeForbids));
        }
        assert!(log.take().is_empty());
        // An account reset session may ask for a nonce (it needs one to
        // recover).
        issue_challenge(
            &cx,
            &store,
            &mut rng,
            &LoginFixture::caller(),
            SessionScope::AccountReset,
            &session(1),
            &account(),
        )
        .unwrap();
    }

    #[test]
    fn issue_challenge_fails_closed_on_a_clock_that_failed() {
        let f = LoginFixture::new();
        let log = NonceLog::new();
        let throttle = NonceThrottle {
            log: &log,
            refuse: AtomicBool::new(false),
        };
        let store = InMemoryChallengeStore::new();
        let cx = context(&f, &throttle);
        let mut rng = TestRng::new(b"clock");
        f.clock.set(u64::MAX);
        let error = issue_challenge(
            &cx,
            &store,
            &mut rng,
            &LoginFixture::caller(),
            SessionScope::Full,
            &session(1),
            &account(),
        )
        .unwrap_err();
        assert_eq!(error, AuthError::Internal(InternalKind::Clock));
        assert!(log.take().is_empty());
        assert!(store.is_empty());
        // The last second before the clock overflows is refused too: the key
        // would expire past the end of time.
        f.clock.set(u64::MAX - CHALLENGE_TTL_SECS + 1);
        let error = issue_challenge(
            &cx,
            &store,
            &mut rng,
            &LoginFixture::caller(),
            SessionScope::Full,
            &session(1),
            &account(),
        )
        .unwrap_err();
        assert_eq!(error, AuthError::Internal(InternalKind::Clock));
        assert!(store.is_empty());
        assert_eq!(log.take(), ["admit", "record"]);
    }

    #[test]
    fn a_store_that_fails_is_an_internal_error_and_a_failure() {
        struct Broken;
        impl fmt::Debug for Broken {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("Broken")
            }
        }
        impl ChallengeStore for Broken {
            fn put(&self, _: ChallengeKey, _: u64, _: u64) -> Result<(), StoreError> {
                Err(StoreError::Backend)
            }
            fn consume(&self, _: &ChallengeKey, _: u64) -> Result<ConsumeOutcome, StoreError> {
                Err(StoreError::Backend)
            }
            fn purge_expired(&self, _: u64) -> Result<usize, StoreError> {
                Err(StoreError::Backend)
            }
        }
        let f = LoginFixture::new();
        let error = issue_challenge(
            &f.cx(),
            &Broken,
            &mut TestRng::new(b"broken"),
            &LoginFixture::caller(),
            SessionScope::Full,
            &session(1),
            &account(),
        )
        .unwrap_err();
        assert_eq!(error, AuthError::Internal(InternalKind::Storage));
        let calls = f.throttle.calls();
        assert!(matches!(
            calls.last(),
            Some(crate::ThrottleCall::Record {
                outcome: Outcome::Failure,
                ..
            })
        ));
    }
}
