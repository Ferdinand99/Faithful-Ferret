//! Proof of possession for device tokens: the DPoP proof (RFC 9449) that comes
//! with every request a device client makes with a token, and with its sign-in
//! and every renewal. Spec: Fase 1 § 7.6, § 8.2.
//!
//! This module holds the types and the limits. The check itself, the strict
//! reading of the proof and the cache of used `jti` values come later; until
//! then [`verify`] refuses every proof with [`DpopError::NotImplemented`],
//! which answers `500 internal` and never looks like a real refusal.
//!
//! The rules, for the check that comes later:
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
//! reason (Spec: Fase 1 § 7.6). Proofs and keys never go into a log.

use std::fmt;

use axum::http::{HeaderMap, Method, StatusCode};

use crate::error::ApiError;
use crate::ids::TokenSecret;

/// How far `iat` may be from the server's clock, either way, in seconds.
///
/// RFC 9449 § 4.3 (`iat` within an acceptable window).
pub const IAT_WINDOW_SECS: i64 = 60;

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

/// The longest `DPoP` header, in bytes.
pub const MAX_PROOF_LEN: usize = 4_096;

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
    /// (`htu`); see `DeviceAuth::htu`.
    pub htu: &'a str,
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
    /// The check is not built yet.
    NotImplemented,
}

impl From<DpopError> for ApiError {
    /// `KeyBusy` and `UserBusy` are `429 throttled` (`Retry-After: 60`),
    /// `Full` is `503 busy` (`Retry-After: 30`), `NotImplemented` is `500
    /// internal` and never a refusal of the proof; every other reason is the
    /// one answer `401 dpop_invalid`.
    fn from(e: DpopError) -> Self {
        match e {
            DpopError::KeyBusy | DpopError::UserBusy => ApiError::throttled(BUSY_RETRY_SECS),
            DpopError::Full => ApiError {
                status: StatusCode::SERVICE_UNAVAILABLE,
                code: "busy",
                retry_after: Some(FULL_RETRY_SECS),
            },
            DpopError::NotImplemented => {
                tracing::error!("the DPoP check was called before it is built");
                ApiError::internal()
            }
            DpopError::Missing
            | DpopError::Malformed
            | DpopError::Signature
            | DpopError::Claims
            | DpopError::Clock
            | DpopError::Replay => ApiError::coded("dpop_invalid"),
        }
    }
}

/// The `jti` values used in the last [`JTI_TTL_SECS`], keyed by the key's
/// thumbprint and the `jti`, with a limit per key, per account and in all.
/// One cache for the process, shared through an `Arc`. Filled in later.
pub struct JtiCache {
    /// The most values in all.
    #[expect(dead_code, reason = "read by the DPoP check, which comes later")]
    capacity: usize,
    /// The most values for one key.
    #[expect(dead_code, reason = "read by the DPoP check, which comes later")]
    per_key: usize,
}

impl JtiCache {
    /// An empty cache that holds at most `capacity` values, and at most
    /// `per_key` for one key.
    pub fn new(capacity: usize, per_key: usize) -> Self {
        Self { capacity, per_key }
    }
}

/// Checks the `DPoP` header of a request against what it must say, at `now`
/// (Unix seconds). It records nothing: the `jti` is recorded only once the
/// proof's key is bound to the token or the sign-in, inside the write
/// transaction and before it commits.
///
/// Not built yet: refuses every proof with [`DpopError::NotImplemented`].
///
/// RFC 9449 § 4.3.
pub fn verify(
    headers: &HeaderMap,
    expect: &Expect<'_>,
    now: i64,
) -> Result<VerifiedProof, DpopError> {
    let _ = (headers, expect, now);
    Err(DpopError::NotImplemented)
}
