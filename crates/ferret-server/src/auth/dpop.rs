//! Proof of possession for device tokens: the DPoP proof (RFC 9449) that comes
//! with every request a device client makes with a token, and with its sign-in
//! and every renewal. Spec: Fase 1 § 7.6, § 8.2.
//!
//! The check has two halves:
//!
//! * [`verify`] needs no state. It takes the one `DPoP` header, reads it
//!   strictly ([`proof`]), has the JOSE library check the ES256 signature with
//!   the key the proof carries, and checks the claims against the request.
//!   It records nothing.
//! * [`JtiCache::record`] remembers the proof's `jti` for its key. It is
//!   called only once the proof's key is bound to the token or the sign-in:
//!   inside the write transaction, after that check and before the commit, or,
//!   for a request that writes nothing, before the route runs. So nobody can
//!   fill the cache with proofs of a key that is bound to nothing.
//!
//! The rules:
//!
//! * a compact JWS of at most [`MAX_PROOF_LEN`] bytes, `typ` `dpop+jwt`, `alg`
//!   `ES256` only, a public P-256 `jwk` with `kty`, `crv`, `x` and `y` and
//!   nothing else (RFC 9449 § 4.2, § 4.3);
//! * `htm` is the method and `htu` the configured vault origin and the path,
//!   without query or fragment ([`Expect`]);
//! * `iat` within [`IAT_WINDOW_SECS`] of the server's clock;
//! * a `jti` is used once per key for [`JTI_TTL_SECS`] (RFC 9449 § 11.1), at
//!   most [`JTI_PER_KEY`] per key, [`JTI_PER_USER`] per account and
//!   [`JTI_CAPACITY`] in all; a full cache refuses instead of forgetting;
//! * `ath` is there exactly when a token comes with the proof, and is the hash
//!   of that token ([`crate::ids::TokenSecret::ath`]).
//!
//! Every refusal of a proof is the one answer `401 dpop_invalid`, with no
//! reason (Spec: Fase 1 § 7.6). Proofs and keys never go into a log. There is
//! no server nonce and no `WWW-Authenticate` challenge: the clock window, the
//! `jti` cache and `ath` bound a captured proof instead. A restart empties the
//! cache, so a proof captured just before it could be used again within its
//! clock window.

pub mod proof;

use std::collections::{BTreeMap, HashMap};
use std::fmt;
use std::sync::{Mutex, PoisonError};

use axum::http::{HeaderMap, Method, StatusCode};
use jsonwebtoken::{Algorithm, DecodingKey};

use crate::auth::tokens::Htu;
use crate::error::ApiError;
use crate::ids::TokenSecret;

pub use proof::{IAT_WINDOW_SECS, MAX_PROOF_LEN, ProofError};

/// The name of the header that carries the proof.
///
/// RFC 9449 § 4.1.
pub const DPOP_HEADER: &str = "dpop";

/// How long a used `jti` is remembered, in seconds: longer than a proof's
/// `iat` counts on either side, so a proof is refused for as long as it could
/// pass the clock check.
///
/// RFC 9449 § 11.1.
pub const JTI_TTL_SECS: i64 = 300;

/// The most `jti` values remembered in all. A full cache refuses new proofs
/// (`503 busy`) instead of forgetting one that could then be used again.
pub const JTI_CAPACITY: usize = 65_536;

/// The most `jti` values remembered for one device key (`429 throttled`
/// beyond it).
pub const JTI_PER_KEY: usize = 1_024;

/// The most `jti` values remembered for one account, over all its devices
/// (`429 throttled` beyond it), so a few accounts cannot fill the cache for
/// everyone.
pub const JTI_PER_USER: usize = 4_096;

/// The `Retry-After` of a key or an account with too many proofs, in seconds.
const BUSY_RETRY_SECS: u32 = 60;

/// The `Retry-After` of a full cache, in seconds.
const FULL_RETRY_SECS: u32 = 30;

/// What the proof of one request must say: the method and the URL of the
/// request, and the token that comes with it, if any.
///
/// RFC 9449 § 4.3.
#[derive(Clone, Copy)]
pub struct Expect<'a> {
    /// The method of the request (`htm`).
    pub method: &'a Method,
    /// The configured vault origin and the path, without query or fragment
    /// (`htu`); only `DeviceAuth::htu` makes one.
    pub htu: &'a Htu,
    /// The token of the request: `ath` must be its hash. `None` for a sign-in
    /// and a renewal, whose proof has no `ath`.
    pub access: Option<&'a TokenSecret>,
}

/// A proof that passed every check: the thumbprint of its key, its `jti` and
/// its `iat`. Only [`verify`] makes one.
pub struct VerifiedProof {
    /// The RFC 7638 thumbprint of the `jwk` (SHA-256).
    jkt: [u8; 32],
    /// The `jti` of the proof.
    jti: String,
    /// The `iat` of the proof (Unix seconds).
    iat: i64,
}

impl VerifiedProof {
    /// The RFC 7638 thumbprint of the key that signed the proof.
    pub fn jkt(&self) -> &[u8; 32] {
        &self.jkt
    }

    /// The `jti` of the proof.
    pub fn jti(&self) -> &str {
        &self.jti
    }

    /// The `iat` of the proof (Unix seconds).
    pub fn iat(&self) -> i64 {
        self.iat
    }
}

impl fmt::Debug for VerifiedProof {
    /// The time only: the thumbprint and the `jti` stay out of a log.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("VerifiedProof")
            .field("iat", &self.iat)
            .finish_non_exhaustive()
    }
}

/// Why a proof was refused. The answer does not say which: every refusal of
/// the proof itself is `401 dpop_invalid` (see `From<DpopError> for ApiError`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DpopError {
    /// No `DPoP` header, or more than one.
    Missing,
    /// Not a compact JWS of the one accepted form.
    Malformed,
    /// The signature does not check out.
    Signature,
    /// `htm`, `htu`, `ath` or `jti` is not what the request needs.
    Claims,
    /// `iat` is outside the window.
    Clock,
    /// The `jti` was used before by the same key.
    Replay,
    /// The key has too many proofs in the window.
    KeyBusy,
    /// The account has too many proofs in the window.
    UserBusy,
    /// The cache of used `jti` values is full.
    Full,
}

impl From<ProofError> for DpopError {
    fn from(e: ProofError) -> Self {
        match e {
            ProofError::TooLong
            | ProofError::Segments
            | ProofError::Encoding
            | ProofError::Header
            | ProofError::Key => DpopError::Malformed,
            ProofError::Claims => DpopError::Claims,
            ProofError::Clock => DpopError::Clock,
        }
    }
}

impl From<DpopError> for ApiError {
    /// `KeyBusy` and `UserBusy` are `429 throttled` (`Retry-After: 60`),
    /// `Full` is `503 busy` (`Retry-After: 30`); every other reason is the one
    /// answer `401 dpop_invalid`.
    fn from(e: DpopError) -> Self {
        match e {
            DpopError::KeyBusy | DpopError::UserBusy => ApiError::throttled(BUSY_RETRY_SECS),
            DpopError::Full => ApiError {
                status: StatusCode::SERVICE_UNAVAILABLE,
                code: "busy",
                retry_after: Some(FULL_RETRY_SECS),
            },
            DpopError::Missing
            | DpopError::Malformed
            | DpopError::Signature
            | DpopError::Claims
            | DpopError::Clock
            | DpopError::Replay => ApiError::coded("dpop_invalid"),
        }
    }
}

/// One remembered `jti`.
struct Entry {
    jkt: [u8; 32],
    jti: String,
    user_id: i64,
}

/// The cache behind the lock.
#[derive(Default)]
struct Seen {
    /// `(jkt, jti)` → when it may be forgotten (Unix seconds).
    live: HashMap<([u8; 32], String), i64>,
    /// The same values by the time they may be forgotten (and a number that
    /// keeps equal times apart), so the first is always the next to go, even
    /// when the clock was stepped back between two records.
    order: BTreeMap<(i64, u64), Entry>,
    /// The number of the next record.
    next: u64,
    /// How many values each key has.
    per_key: HashMap<[u8; 32], usize>,
    /// How many values each account has.
    per_user: HashMap<i64, usize>,
}

/// Lowers a count by one, and drops it at zero.
fn release<K: std::hash::Hash + Eq>(counts: &mut HashMap<K, usize>, key: &K) {
    if let Some(count) = counts.get_mut(key) {
        *count = count.saturating_sub(1);
        if *count == 0 {
            counts.remove(key);
        }
    }
}

impl Seen {
    /// Forgets the values whose time is out at `now`. They are ordered by
    /// that time, not by when they were recorded, so a value recorded while
    /// the clock was ahead never holds back the values recorded after the
    /// clock was set back (it stays until its own time, since its proof could
    /// pass the clock check again by then).
    fn forget_expired(&mut self, now: i64) {
        while self
            .order
            .first_key_value()
            .is_some_and(|(&(expires_at, _), _)| expires_at <= now)
        {
            let Some((_, entry)) = self.order.pop_first() else {
                break;
            };
            self.live.remove(&(entry.jkt, entry.jti));
            release(&mut self.per_key, &entry.jkt);
            release(&mut self.per_user, &entry.user_id);
        }
    }
}

/// The `jti` values used in the last [`JTI_TTL_SECS`], keyed by the key's
/// thumbprint and the `jti`, with a limit per key, per account and in all.
/// One cache for the process, shared through an `Arc`.
///
/// RFC 9449 § 11.1.
pub struct JtiCache {
    /// The most values in all.
    capacity: usize,
    /// The most values for one key.
    per_key: usize,
    /// The most values for one account.
    per_user: usize,
    /// The values.
    seen: Mutex<Seen>,
}

impl JtiCache {
    /// An empty cache that holds at most `capacity` values, at most `per_key`
    /// for one key and at most `per_user` for one account.
    pub fn new(capacity: usize, per_key: usize, per_user: usize) -> Self {
        Self {
            capacity,
            per_key,
            per_user,
            seen: Mutex::new(Seen::default()),
        }
    }

    /// Records the `jti` of `proof`, whose key belongs to the account
    /// `user_id`, at `now` (Unix seconds).
    ///
    /// Call it inside the write transaction, after the proof's key was found
    /// to be the one the token or the sign-in is bound to and before the
    /// commit; a refusal rolls the transaction back. For a request that writes
    /// nothing, call it after that check and before the route runs.
    ///
    /// Values whose time is out are forgotten first. Then: a `(jkt, jti)` seen
    /// before is [`DpopError::Replay`]; a key with its limit of live values is
    /// [`DpopError::KeyBusy`]; an account with its limit is
    /// [`DpopError::UserBusy`]; a cache at its capacity is
    /// [`DpopError::Full`]. A live value is never dropped to make room.
    ///
    /// RFC 9449 § 11.1.
    pub fn record(&self, proof: &VerifiedProof, user_id: i64, now: i64) -> Result<(), DpopError> {
        let mut seen = self.seen.lock().unwrap_or_else(PoisonError::into_inner);
        seen.forget_expired(now);

        let key = (proof.jkt, proof.jti.clone());
        if seen.live.contains_key(&key) {
            return Err(DpopError::Replay);
        }
        if seen.per_key.get(&proof.jkt).copied().unwrap_or(0) >= self.per_key {
            return Err(DpopError::KeyBusy);
        }
        if seen.per_user.get(&user_id).copied().unwrap_or(0) >= self.per_user {
            return Err(DpopError::UserBusy);
        }
        if seen.live.len() >= self.capacity {
            return Err(DpopError::Full);
        }

        let expires_at = now.saturating_add(JTI_TTL_SECS);
        seen.live.insert(key, expires_at);
        let number = seen.next;
        seen.next = number.wrapping_add(1);
        seen.order.insert(
            (expires_at, number),
            Entry {
                jkt: proof.jkt,
                jti: proof.jti.clone(),
                user_id,
            },
        );
        let for_key = seen.per_key.entry(proof.jkt).or_default();
        *for_key = for_key.saturating_add(1);
        let for_user = seen.per_user.entry(user_id).or_default();
        *for_user = for_user.saturating_add(1);
        Ok(())
    }

    /// How many values the cache holds now, counting those whose time ran out
    /// since the last [`JtiCache::record`].
    pub fn len(&self) -> usize {
        self.seen
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .live
            .len()
    }

    /// Whether the cache holds no value.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl fmt::Debug for JtiCache {
    /// The size only: the keys and the `jti` values stay out of a log.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("JtiCache")
            .field("len", &self.len())
            .field("capacity", &self.capacity)
            .finish_non_exhaustive()
    }
}

/// Whether `signature_b64` is a valid ES256 signature over `signing_input` by
/// the P-256 key with the coordinates `x` and `y` (base64url). The JOSE library
/// does the work (its aws-lc-rs backend, the one rustls uses); only `Ok(true)`
/// counts, and every error of the library is a `false`.
///
/// This is the signature alone, never a proof check: [`verify`] is that. It is
/// public only so the Wycheproof test runs this exact call; nothing but
/// [`verify`] calls it in the server (`tests/dpop.rs` checks the names).
///
/// RFC 7518 § 3.4.
#[doc(hidden)]
pub fn signature_holds(signature_b64: &str, signing_input: &[u8], x: &str, y: &str) -> bool {
    let Ok(key) = DecodingKey::from_ec_components(x, y) else {
        return false;
    };
    matches!(
        jsonwebtoken::crypto::verify(signature_b64, signing_input, &key, Algorithm::ES256),
        Ok(true)
    )
}

/// Whether the JOSE library has its one crypto backend. Without one, its
/// checks would panic, so the server refuses to start instead (`build_state`).
pub fn backend_ready() -> bool {
    jsonwebtoken::crypto::CryptoProvider::try_get_default().is_some()
}

/// Checks the `DPoP` header of a request against what it must say, at `now`
/// (Unix seconds): exactly one header; read strictly ([`proof::split`]); the
/// ES256 signature over the exact signing input, with the key the header
/// carries ([`signature_holds`]); then the claims ([`proof::claims`],
/// [`proof::check_claims`]). The claims are read only once the signature
/// holds. The library never reads the header or the claims, so there is one
/// reader of a proof.
///
/// It records nothing: the `jti` is recorded by [`JtiCache::record`] once the
/// proof's key is bound to the token or the sign-in.
///
/// RFC 9449 § 4.3.
pub fn verify(
    headers: &HeaderMap,
    expect: &Expect<'_>,
    now: i64,
) -> Result<VerifiedProof, DpopError> {
    let mut values = headers.get_all(DPOP_HEADER).iter();
    let (Some(value), None) = (values.next(), values.next()) else {
        return Err(DpopError::Missing);
    };
    if value.len() > MAX_PROOF_LEN {
        return Err(DpopError::Malformed);
    }
    let text = value.to_str().map_err(|_| DpopError::Malformed)?;
    let parts = proof::split(text)?;

    let jwk = &parts.header.jwk;
    let input = proof::signing_input(&parts);
    if !signature_holds(
        proof::signature_b64(&parts),
        input.as_bytes(),
        &jwk.x,
        &jwk.y,
    ) {
        return Err(DpopError::Signature);
    }

    let claims = proof::claims(&parts)?;
    let ath = expect.access.map(TokenSecret::ath);
    proof::check_claims(
        &claims,
        expect.method.as_str(),
        expect.htu.as_str(),
        ath.as_ref(),
        now,
    )?;
    Ok(VerifiedProof {
        jkt: proof::jkt(jwk),
        jti: claims.jti,
        iat: claims.iat,
    })
}
