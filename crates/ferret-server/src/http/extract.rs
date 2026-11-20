//! The session extractors: the only code that knows the kit's cookie key.
//!
//! A route takes [`VaultSession`] (vault listener) or [`AdminSession`] (admin
//! listener). The extractor needs Ferret's `__Host-ferret_sid` cookie to match
//! a row that is not revoked, belongs to the listener, has the scope `full` and
//! is within its limits (`auth::session::limits`), and the kit's signed cookie
//! to agree with the row's user and `issued_at` and with the kit's
//! `session_version`. The user must still be active. Anything else is the one
//! answer `401 {"error":"unauthorized"}`: the same status, headers and body for
//! every reason, so a caller learns nothing about which part failed.
//!
//! A limit is inclusive: a session that idled exactly 12 hours is still valid,
//! one second more is not. The row's `last_seen` is written at most once a
//! minute.
//!
//! The extractors are generic over the state and ask only for [`SessionAuth`]
//! through `FromRef`: the cookie key, the database and the clock. The vault
//! modules never see the key; they take the extractor.
//!
//! # Sensitive operations
//!
//! Three more extractors guard the operations of Spec: Fase 1 § 4.6. A route
//! takes them in this order, so a request that fails an earlier one never has
//! its body read:
//!
//! 1. [`ScopedSession<C>`]: the same checks as [`VaultSession`], except that
//!    the session may have any scope, and then the scope must allow the
//!    capability `C::CAP` (`ferret_server_auth::authorize`). A session that
//!    does not count is `401 unauthorized`; one whose scope does not allow
//!    the capability is `403 forbidden`. A route that takes a plain
//!    [`VaultSession`] still answers a session that is not `full` with 401.
//! 2. [`FreshReauth`]: a `full` session (`403 forbidden` otherwise), the user
//!    has no second factor (`403
//!    second_factor_required` until the server can ask for one), and this
//!    session proved the master password again within the last 300 seconds
//!    (`403 reauth_required`). The time is in the session's own row, so a
//!    re-authentication in one session makes no other session fresh.
//! 3. [`SignedBody`]: the headers `Ferret-Nonce` (32 bytes) and `Ferret-Proof`
//!    (64 bytes), base64url without padding, and the body as raw bytes of at
//!    most [`MAX_SIGNED_BODY`]. A missing header or a wrong length is `400
//!    malformed_nonce` or `400 malformed_proof`, a larger body is `413
//!    too_large`, a body that breaks off is `400 bad_request`; none of them
//!    touches the nonce, which only the OPAQUE library consumes. The body is
//!    not parsed here: [`SignedBody::parse`] reads it only for a permit of the
//!    library that covers exactly these bytes.
//!
//! Spec: Fase 1 § 4.6 and § 7.6.
//!
//! # Device tokens
//!
//! [`VaultCaller`] is the extractor of the sync routes, the only routes that
//! take a device token besides a session: a full session as [`VaultSession`]
//! reads it, or an access token with a DPoP proof of the device key. Every
//! other route takes one of the session extractors above and so refuses a
//! token (no cookie: `401 unauthorized`). See [`VaultCaller`].
//!
//! Spec: Fase 1 § 7.6, § 8.2; RFC 9449 § 4.3, § 7.

use std::fmt;
use std::marker::PhantomData;
use std::sync::Arc;

use axum::body::{Body, Bytes};
use axum::extract::{FromRef, FromRequest, FromRequestParts, OriginalUri, Request};
use axum::http::header::AUTHORIZATION;
use axum::http::request::Parts;
use axum::http::{HeaderMap, HeaderValue};
use axum::response::{IntoResponse as _, Response};
use axum_extra::extract::cookie::{Key, SignedCookieJar};
use ferret_core::MutationOp;
use ferret_server_auth::{
    Caller, Capability, Clock, ReplaceKind, ReplacePermit, ReplaceRequest, SessionBinding,
    SessionScope, SignedPermit, SignedRequest, authorize,
};
use futures_util::StreamExt as _;
use rusqlite::{OptionalExtension as _, params};
use serde::de::DeserializeOwned;
use sha2::{Digest as _, Sha256};
use vole_kit::auth::session::SessionClaims;

use crate::auth::devices;
use crate::auth::dpop::{self, Expect, VerifiedProof};
use crate::auth::session::{self, Origin, SessionRow, lookup, reauth_fresh, within_limits};
use crate::auth::tokens::{AccessLookup, DeviceAuth, lookup_access, with_server_date};
use crate::error::{ApiError, StoreError};
use crate::http::origin_guard::{TokenHeaders, has_cookie, is_dpop_scheme, token_headers};
use crate::ids::{AccountId, DeviceId, SessionSecret, SidHash, TokenHash, TokenSecret, VaultId};
use crate::product;
use crate::state::VaultDb;
use crate::vault::notify::Revoked;
use crate::wire::{MAX_SIGNED_BODY, NONCE_LEN, PROOF_LEN, b64url, refusal_code};

/// `last_seen` is written when it is at least this many seconds old.
const TOUCH_AFTER_SECS: i64 = 60;

/// The header that carries the nonce of a signed request.
pub const NONCE_HEADER: &str = "ferret-nonce";

/// The header that carries the proof of a signed request.
pub const PROOF_HEADER: &str = "ferret-proof";

/// What the session extractors need and nothing more: the key that opens the
/// kit's cookie, the database and the clock; and the handle of device tokens,
/// which only [`VaultCaller`] reads.
#[derive(Clone)]
pub struct SessionAuth {
    pub key: Key,
    pub db: VaultDb,
    pub clock: Arc<dyn Clock>,
    /// The handle of device tokens, for [`VaultCaller`]: the cache of used
    /// `jti` values and the vault origin that `htu` names.
    pub device: DeviceAuth,
}

/// The clock of the state, handed to a route that must ask the time again
/// later (a stream that holds a session open and checks it from time to time).
/// A route calls [`SessionClock::now`] and names nothing else about it.
#[derive(Clone)]
pub struct SessionClock(Arc<dyn Clock>);

impl SessionClock {
    /// The time in Unix seconds, or `None` when the clock failed (it then
    /// reads as the largest value) or the value does not fit: nothing is valid
    /// then.
    pub fn now(&self) -> Option<i64> {
        i64::try_from(self.0.now_unix()).ok()
    }
}

impl fmt::Debug for SessionClock {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SessionClock")
    }
}

/// A signed-in session on the vault listener, with its account and vault.
///
/// The fields are the facts of the request's `full` session: read them, never
/// rebind or write them. They become private with getters when this file is
/// next opened, as the fields of [`SessionFacts`] are.
#[derive(Debug, Clone)]
pub struct VaultSession {
    pub sid: SidHash,
    pub user_id: i64,
    pub issued_at: i64,
    /// The time the request was checked at (Unix seconds, from the clock of the
    /// state), so a vault route needs no clock of its own for the request.
    pub now: i64,
    /// The same clock, for a route that outlives the request.
    pub clock: SessionClock,
    pub device: DeviceId,
    pub account: AccountId,
    pub vault: VaultId,
    pub vk_epoch: u64,
    /// The kit's `session_version` of the user, which the extractor has found
    /// equal to the one in the kit's cookie. A long-lived stream asks for it
    /// again (`auth::session::still_valid`): a changed value ends the session.
    pub session_version: i64,
}

/// The account of a user with its vault and key epoch, or `None` when the
/// user has no account with a vault (or the row holds what cannot be one).
fn read_account(
    conn: &rusqlite::Connection,
    user_id: i64,
) -> Result<Option<(AccountId, VaultId, u64)>, StoreError> {
    let found: Option<(Vec<u8>, Vec<u8>, i64)> = conn
        .query_row(
            "SELECT a.account_id, v.vault_id, a.vk_epoch
             FROM ferret_accounts a
             JOIN ferret_vaults v ON v.account_id = a.account_id
             WHERE a.user_id = ?1",
            params![user_id],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )
        .optional()?;
    let Some((account, vault, epoch)) = found else {
        return Ok(None);
    };
    let ids = <[u8; 16]>::try_from(account)
        .and_then(|a| <[u8; 16]>::try_from(vault).map(|v| (a, v)))
        .ok()
        .zip(u64::try_from(epoch).ok());
    Ok(ids.map(|((account, vault), epoch)| {
        (
            AccountId::from_bytes(account),
            VaultId::from_bytes(vault),
            epoch,
        )
    }))
}

/// A signed-in session on the admin listener.
#[derive(Debug, Clone)]
pub struct AdminSession {
    pub sid: SidHash,
    pub user_id: i64,
}

/// Which scopes a check lets through.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Scopes {
    /// Only `full`: [`VaultSession`] and [`AdminSession`].
    Full,
    /// Every scope; the caller asks `authorize` itself.
    Any,
}

/// A session that passed every check.
struct Verified {
    /// The session's row, as read for this request.
    row: SessionRow,
    now: i64,
    /// The kit's session version, as checked against the kit's cookie.
    session_version: i64,
    /// Whether the kit has a second factor on for the user.
    second_factor: bool,
    /// The account of the user, read for the vault listener only.
    account: Option<(AccountId, VaultId, u64)>,
}

impl SessionAuth {
    /// Checks the cookies of a request against the database. `Ok(None)` is
    /// every way of not being signed in.
    async fn verify(
        &self,
        parts: &Parts,
        origin: Origin,
        scopes: Scopes,
    ) -> Result<Option<Verified>, StoreError> {
        let jar = SignedCookieJar::from_headers(&parts.headers, self.key.clone());
        let Some(secret) = jar
            .get(product::SID_COOKIE)
            .and_then(|c| SessionSecret::from_cookie(c.value()).ok())
        else {
            return Ok(None);
        };
        let Some(claims) = jar
            .get(product::SESSION_COOKIE)
            .and_then(|c| SessionClaims::decode(c.value()))
        else {
            return Ok(None);
        };
        drop(jar);
        // A clock that failed reads as the largest value; nothing is valid then.
        let Ok(now) = i64::try_from(self.clock.now_unix()) else {
            return Ok(None);
        };
        let sid = secret.hash();
        drop(secret);

        self.db
            .with_conn(move |conn| {
                let Some(row) = lookup(conn, &sid)? else {
                    return Ok(None);
                };
                if row.revoked_at.is_some()
                    || row.origin != origin
                    || (scopes == Scopes::Full && row.scope != SessionScope::Full)
                    || !within_limits(&row, now)
                    || claims.user_id != row.user_id
                    || claims.issued_at != row.issued_at
                {
                    return Ok(None);
                }
                // The kit's side: the user is active and has not bumped the
                // session version (password change, "sign out everywhere").
                // The kit's flag for its second factor comes with it.
                let user: Option<(i64, bool, bool)> = conn
                    .query_row(
                        "SELECT session_version, active, totp_enabled FROM users WHERE id = ?1",
                        params![row.user_id],
                        |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
                    )
                    .optional()?;
                let second_factor = match user {
                    Some((version, true, second_factor)) if version == claims.version => {
                        second_factor
                    }
                    _ => return Ok(None),
                };
                let account = if origin == Origin::Vault {
                    let Some(account) = read_account(conn, row.user_id)? else {
                        return Ok(None);
                    };
                    Some(account)
                } else {
                    None
                };

                // At most once a minute; the condition makes it one statement,
                // so requests that arrive together write once. A failed write
                // only makes the idle limit bite sooner.
                if let Err(e) = conn.execute(
                    "UPDATE ferret_sessions SET last_seen = ?1
                     WHERE sid_hash = ?2 AND revoked_at IS NULL AND ?1 - last_seen >= ?3",
                    params![now, sid.0.as_slice(), TOUCH_AFTER_SECS],
                ) {
                    tracing::warn!(error = %e, "could not record the use of a session");
                }

                Ok(Some(Verified {
                    row,
                    now,
                    session_version: claims.version,
                    second_factor,
                    account,
                }))
            })
            .await
    }

    /// The vault session of a verified request; 401 when it has no account.
    fn vault_session(&self, verified: &Verified) -> Result<VaultSession, ApiError> {
        let (account, vault, vk_epoch) = verified.account.ok_or_else(ApiError::unauthorized)?;
        Ok(VaultSession {
            sid: verified.row.sid,
            now: verified.now,
            clock: SessionClock(self.clock.clone()),
            user_id: verified.row.user_id,
            issued_at: verified.row.issued_at,
            device: verified.row.device,
            account,
            vault,
            vk_epoch,
            session_version: verified.session_version,
        })
    }

    /// A vault session of any scope, or the one 401.
    async fn verify_vault_any(&self, parts: &Parts) -> Result<Verified, ApiError> {
        self.verify(parts, Origin::Vault, Scopes::Any)
            .await?
            .ok_or_else(ApiError::unauthorized)
    }
}

impl<S> FromRequestParts<S> for VaultSession
where
    S: Send + Sync,
    SessionAuth: FromRef<S>,
{
    type Rejection = ApiError;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, ApiError> {
        let auth = SessionAuth::from_ref(state);
        let verified = auth
            .verify(parts, Origin::Vault, Scopes::Full)
            .await?
            .ok_or_else(ApiError::unauthorized)?;
        auth.vault_session(&verified)
    }
}

impl<S> FromRequestParts<S> for AdminSession
where
    S: Send + Sync,
    SessionAuth: FromRef<S>,
{
    type Rejection = ApiError;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, ApiError> {
        let auth = SessionAuth::from_ref(state);
        let verified = auth
            .verify(parts, Origin::Admin, Scopes::Full)
            .await?
            .ok_or_else(ApiError::unauthorized)?;
        Ok(AdminSession {
            sid: verified.row.sid,
            user_id: verified.row.user_id,
        })
    }
}

// ------------------------------------------------------------ vault caller

/// How a [`VaultCaller`] signed in: a full session of the web vault, or an
/// access token of a device.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Credential {
    /// The session cookie: the hash of the session id.
    Cookie {
        /// The key of the session's row.
        sid: SidHash,
    },
    /// An access token with a DPoP proof of the device key.
    Device {
        /// The id the server gave the device.
        device: DeviceId,
        /// The key of the token's row.
        access: TokenHash,
        /// When the token expires (Unix seconds).
        expires_at: i64,
    },
}

impl fmt::Debug for Credential {
    /// The kind and the device only: the row keys stay out of a log.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Credential::Cookie { .. } => f.write_str("Credential::Cookie"),
            Credential::Device {
                device, expires_at, ..
            } => f
                .debug_struct("Credential::Device")
                .field("device", device)
                .field("expires_at", expires_at)
                .finish_non_exhaustive(),
        }
    }
}

/// A request to a sync route: a full session of the web vault, or an access
/// token of a device with a DPoP proof of its key. Only the sync routes take
/// it (`GET /api/sync/changes`, `PUT /api/sync/items/{id}`,
/// `POST /api/sync/batch`, `GET`/`PUT /api/sync/checkpoint`,
/// `GET /api/sync/events` and `GET /api/vault/unlock-methods`); every other
/// route takes a session extractor and refuses a token.
///
/// **Without a token** (no `Authorization` with the scheme `DPoP`): the same
/// checks as [`VaultSession`]. An `Authorization` of another scheme (`Basic`
/// from a proxy) is not looked at.
///
/// **With `Authorization: DPoP <token>`**, in this order:
///
/// 1. a token header next to a cookie, or token headers that read more than
///    one way, are `400 bad_request` (the `Origin` guard refuses them first);
/// 2. exactly one `Authorization` header with exactly one token of 43
///    characters, else `401 unauthorized`;
/// 3. the proof (`dpop::verify`): `htm` the method, `htu` the configured vault
///    origin and the path of the request as the router got it (`OriginalUri`),
///    `ath` the hash of the token; any refusal is `401 dpop_invalid`;
/// 4. the token's row, through its device: none or expired is
///    `401 token_expired`, a revoked device `401 device_revoked`;
/// 5. the proof's key must be the device's (its `jkt`), else
///    `401 dpop_invalid`, and nothing is revoked or recorded: a token seen in
///    a log is no way to throw a device out;
/// 6. the device must still be valid (`devices::still_valid`: not revoked, its
///    user active with the same `session_version`, an account with a vault,
///    younger than the longest life of a sign-in), else `401 device_revoked`;
/// 7. the proof's `jti` is recorded now that its key is bound to the token,
///    before the route runs (a replay is `401 dpop_invalid`, a busy key or
///    account `429 throttled`, a full cache `503 busy`);
/// 8. the device's `last_seen` is noted (at most once a minute).
///
/// Every refusal on that path carries a `Date` of the server's clock, so a
/// device can set its proofs by it.
///
/// The fields are private and only the extractor makes one: a route reads who
/// the caller is and cannot point it at another account, vault or device.
///
/// ```compile_fail
/// fn retarget(c: &mut ferret_server::http::extract::VaultCaller, v: ferret_server::ids::VaultId) {
///     c.vault = v;
/// }
/// ```
///
/// Spec: Fase 1 § 7.6, § 8.2; RFC 9449 § 4.3, § 7.1.
#[derive(Clone)]
pub struct VaultCaller {
    credential: Credential,
    user_id: i64,
    now: i64,
    clock: SessionClock,
    device: DeviceId,
    account: AccountId,
    vault: VaultId,
    vk_epoch: u64,
    session_version: i64,
}

impl fmt::Debug for VaultCaller {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("VaultCaller")
            .field("credential", &self.credential)
            .field("user_id", &self.user_id)
            .field("now", &self.now)
            .field("device", &self.device)
            .field("account", &self.account)
            .field("vault", &self.vault)
            .field("vk_epoch", &self.vk_epoch)
            .finish_non_exhaustive()
    }
}

impl VaultCaller {
    /// The kit user.
    pub fn user_id(&self) -> i64 {
        self.user_id
    }

    /// The time the request was checked at (Unix seconds).
    pub fn now(&self) -> i64 {
        self.now
    }

    /// The clock of the state, for a route that outlives the request.
    pub fn clock(&self) -> &SessionClock {
        &self.clock
    }

    /// The device: the id a browser gave its session, or the id the server
    /// gave a token device. Idempotency, rate limits and stream places count
    /// by it.
    pub fn device(&self) -> DeviceId {
        self.device
    }

    /// The account of the caller's user.
    pub fn account(&self) -> AccountId {
        self.account
    }

    /// The vault of that account.
    pub fn vault(&self) -> VaultId {
        self.vault
    }

    /// The vault key epoch of the account when the request was checked.
    pub fn vk_epoch(&self) -> u64 {
        self.vk_epoch
    }

    /// The kit's `session_version` of the user, as the session cookie or the
    /// device row had it.
    pub fn session_version(&self) -> i64 {
        self.session_version
    }

    /// How the caller signed in.
    pub fn credential(&self) -> &Credential {
        &self.credential
    }

    /// Whether the caller came with a device token rather than a session.
    pub fn is_device(&self) -> bool {
        matches!(self.credential, Credential::Device { .. })
    }

    /// Whether the caller may still be served at `now`, read again from the
    /// database: a session as `auth::session::still_valid` says; a device
    /// whose access token still has its live row and has not expired, and
    /// that `devices::still_valid` accepts. A long-lived stream asks this at
    /// every heartbeat.
    ///
    /// Spec: Fase 1 § 7.6, § 8.2.
    pub fn still_valid(&self, conn: &rusqlite::Connection, now: i64) -> rusqlite::Result<bool> {
        match self.credential {
            Credential::Cookie { sid } => {
                session::still_valid(conn, &sid, Origin::Vault, self.session_version, now)
            }
            Credential::Device { device, access, .. } => {
                let live = matches!(
                    lookup_access(conn, &access, now)?,
                    AccessLookup::Live(row) if row.device == device
                );
                Ok(live && devices::still_valid(conn, &device, now)?)
            }
        }
    }

    /// Whether `revoked` ends this caller: the revocation of its session, or
    /// of its token device. A browser is a session, so a device revocation
    /// never ends a cookie caller, even one whose browser chose the same id.
    ///
    /// Spec: Fase 1 § 7.6 (revocation closes the streams of the device).
    pub fn is_revoked_by(&self, revoked: &Revoked) -> bool {
        match (&self.credential, revoked) {
            (Credential::Cookie { sid }, Revoked::Session(ended)) => sid == ended,
            (Credential::Device { device, .. }, Revoked::Device(ended)) => device == ended,
            _ => false,
        }
    }

    /// When the caller's access token expires (Unix seconds); `None` for a
    /// session, whose limits `still_valid` checks.
    pub fn ends_at(&self) -> Option<i64> {
        match self.credential {
            Credential::Cookie { .. } => None,
            Credential::Device { expires_at, .. } => Some(expires_at),
        }
    }
}

/// The token of an `Authorization: DPoP <token>` value: the scheme `DPoP` in
/// any case, one or more spaces, and exactly one token of 43 characters of
/// base64url. `None` for anything else.
///
/// RFC 9449 § 7.1; RFC 9110 § 11.4.
fn dpop_token(value: &HeaderValue) -> Option<TokenSecret> {
    let text = value.to_str().ok()?;
    let (scheme, rest) = text.split_once(' ')?;
    if !scheme.eq_ignore_ascii_case("dpop") {
        return None;
    }
    TokenSecret::from_wire(rest.trim_start_matches(' ')).ok()
}

/// A refusal of a token request: the error, and the time of the server's
/// clock for its `Date` when it is known.
struct TokenRefusal {
    error: ApiError,
    now: Option<i64>,
}

/// The refusal of a token request with `error`, dated `now` when known.
fn token_refusal(error: ApiError, now: Option<i64>) -> TokenRefusal {
    TokenRefusal { error, now }
}

impl TokenRefusal {
    /// The answer: the error, with a `Date` of the server's clock when the
    /// time is known.
    fn into_response(self) -> Response {
        let response = self.error.into_response();
        match self.now {
            Some(now) => with_server_date(response, now),
            None => response,
        }
    }
}

impl SessionAuth {
    /// The token path of [`VaultCaller`] (steps 2 to 8 there).
    async fn verify_token(&self, parts: &Parts) -> Result<VaultCaller, TokenRefusal> {
        let mut values = parts.headers.get_all(AUTHORIZATION).iter();
        let (Some(value), None) = (values.next(), values.next()) else {
            return Err(token_refusal(ApiError::unauthorized(), None));
        };
        let Some(token) = dpop_token(value) else {
            return Err(token_refusal(ApiError::unauthorized(), None));
        };
        // A clock that failed reads as the largest value; nothing is valid then.
        let Ok(now) = i64::try_from(self.clock.now_unix()) else {
            return Err(token_refusal(ApiError::unauthorized(), None));
        };
        // The path as the router got it: inside a nested router `parts.uri`
        // has lost the prefix, and the proof names the whole URL.
        let path = parts
            .extensions
            .get::<OriginalUri>()
            .map_or_else(|| parts.uri.path(), |original| original.0.path());
        let htu = self.device.htu(path);
        let proof = dpop::verify(
            &parts.headers,
            &Expect {
                method: &parts.method,
                htu: &htu,
                access: Some(&token),
            },
            now,
        )
        .map_err(|error| token_refusal(ApiError::from(error), Some(now)))?;
        let access = token.hash();
        drop(token);

        let device_auth = self.device.clone();
        let clock = SessionClock(self.clock.clone());
        let bound = self
            .db
            .with_conn(move |conn| bind_token(conn, &device_auth, &access, &proof, now))
            .await
            .map_err(|error| token_refusal(ApiError::from(error), Some(now)))?;
        let bound = bound.map_err(|error| token_refusal(error, Some(now)))?;
        Ok(VaultCaller {
            credential: Credential::Device {
                device: bound.device,
                access,
                expires_at: bound.expires_at,
            },
            user_id: bound.user_id,
            now,
            clock,
            device: bound.device,
            account: bound.account,
            vault: bound.vault,
            vk_epoch: bound.vk_epoch,
            session_version: bound.session_version,
        })
    }
}

/// A token found, bound to the proof's key and still valid.
struct BoundToken {
    device: DeviceId,
    expires_at: i64,
    user_id: i64,
    session_version: i64,
    account: AccountId,
    vault: VaultId,
    vk_epoch: u64,
}

/// Steps 4 to 8 of [`VaultCaller`], on one connection: the token's row, the
/// binding of the proof's key, the device, the `jti`, and `last_seen`.
fn bind_token(
    conn: &rusqlite::Connection,
    device_auth: &DeviceAuth,
    access: &TokenHash,
    proof: &VerifiedProof,
    now: i64,
) -> Result<Result<BoundToken, ApiError>, StoreError> {
    let row = match lookup_access(conn, access, now)? {
        AccessLookup::Live(row) => row,
        AccessLookup::Expired => return Ok(Err(ApiError::coded("token_expired"))),
        AccessLookup::DeviceRevoked => return Ok(Err(ApiError::coded("device_revoked"))),
    };
    // A proof of another key: refused, and nothing recorded or revoked.
    if row.jkt != *proof.jkt() {
        return Ok(Err(ApiError::coded("dpop_invalid")));
    }
    if !devices::still_valid(conn, &row.device, now)? {
        return Ok(Err(ApiError::coded("device_revoked")));
    }
    let Some((account, vault, vk_epoch)) = read_account(conn, row.user_id)? else {
        return Ok(Err(ApiError::coded("device_revoked")));
    };
    // The key is bound to the token now, so the proof's `jti` may take a
    // place in the cache; the route has not run yet.
    if let Err(error) = device_auth.replay().record(proof, row.user_id, now) {
        return Ok(Err(ApiError::from(error)));
    }
    // A failed write only makes `last_seen` older.
    if let Err(e) = devices::touch(conn, &row.device, now) {
        tracing::warn!(error = %e, "could not record the use of a device");
    }
    Ok(Ok(BoundToken {
        device: row.device,
        expires_at: row.expires_at,
        user_id: row.user_id,
        session_version: row.session_version,
        account,
        vault,
        vk_epoch,
    }))
}

impl<S> FromRequestParts<S> for VaultCaller
where
    S: Send + Sync,
    SessionAuth: FromRef<S>,
{
    type Rejection = Response;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Response> {
        let auth = SessionAuth::from_ref(state);
        // A request is a session's or a device's, never both, and its token
        // headers read one way only. The `Origin` guard refuses these first;
        // the extractor does not count on it.
        match token_headers(&parts.headers) {
            TokenHeaders::Ambiguous => {
                return Err(ApiError::coded("bad_request").into_response());
            }
            TokenHeaders::Present if has_cookie(&parts.headers) => {
                return Err(ApiError::coded("bad_request").into_response());
            }
            TokenHeaders::Present | TokenHeaders::Absent => {}
        }
        let token = parts
            .headers
            .get_all(AUTHORIZATION)
            .iter()
            .any(is_dpop_scheme);
        if token {
            return auth
                .verify_token(parts)
                .await
                .map_err(TokenRefusal::into_response);
        }
        let verified = auth
            .verify(parts, Origin::Vault, Scopes::Full)
            .await
            .map_err(|e| ApiError::from(e).into_response())?
            .ok_or_else(|| ApiError::unauthorized().into_response())?;
        let session = auth
            .vault_session(&verified)
            .map_err(|e| e.into_response())?;
        Ok(VaultCaller {
            credential: Credential::Cookie { sid: session.sid },
            user_id: session.user_id,
            now: session.now,
            clock: session.clock,
            device: session.device,
            account: session.account,
            vault: session.vault,
            vk_epoch: session.vk_epoch,
            session_version: session.session_version,
        })
    }
}

// ------------------------------------------------------------- capabilities

/// The capability a route needs, named by a type so that a route says it in
/// its signature: `ScopedSession<caps::PasswordPut>`.
pub trait Cap: Send + Sync + 'static {
    /// The capability the scope of the session must allow.
    const CAP: Capability;
}

/// The capabilities of the routes of signed requests and of the recovery.
pub mod caps {
    use super::{Cap, Capability};

    macro_rules! caps {
        ($($(#[$doc:meta])* $name:ident),* $(,)?) => {
            $(
                $(#[$doc])*
                #[derive(Debug, Clone, Copy)]
                pub struct $name;

                impl Cap for $name {
                    const CAP: Capability = Capability::$name;
                }
            )*
        };
    }

    caps! {
        /// Ask for a nonce (`POST /api/auth/challenge`).
        Challenge,
        /// Start a new OPAQUE registration in the session.
        OpaqueRegisterStart,
        /// Read the recovery wrap.
        RecoveryWrapRead,
        /// Replace the account with a recovered one.
        Recover,
        /// Change the master password.
        PasswordPut,
        /// Add, change or remove an unlock method, the recovery wrap included.
        UnlockMethodsWrite,
        /// Write sync data (the import window).
        SyncWrite,
        /// Manage the devices of the account (revoke them all).
        DeviceManage,
    }
}

/// The facts of a vault session of any scope, as a [`ScopedSession`] carries
/// them. Unlike a [`VaultSession`] it is no proof of a `full` session: it has
/// no extractor, and it cannot be passed where a `VaultSession` is expected.
///
/// The fields are private and only the extractor makes one, so a route can
/// read which session, user and account a request belongs to but cannot point
/// it at another one (the library takes the scope, the session binding and
/// the account from here):
///
/// ```
/// use ferret_server::http::extract::{ScopedSession, caps};
/// fn account(s: &ScopedSession<caps::Challenge>) -> ferret_server::ids::AccountId {
///     s.session().account()
/// }
/// ```
///
/// ```compile_fail
/// use ferret_server::http::extract::{ScopedSession, caps};
/// fn retarget(s: &mut ScopedSession<caps::Challenge>, other: ferret_server::ids::AccountId) {
///     s.session.account = other;
/// }
/// ```
///
/// ```compile_fail
/// use ferret_server::http::extract::SessionFacts;
/// fn retarget(f: &mut SessionFacts, other: ferret_server::ids::SidHash) {
///     f.sid = other;
/// }
/// ```
///
/// Nor can it widen the scope, which decides what using a capability does to
/// the session (a reset session's recovery ends it):
///
/// ```
/// use ferret_server::http::extract::{ScopedSession, caps};
/// fn scope(s: &ScopedSession<caps::Recover>) -> ferret_server_auth::SessionScope {
///     s.scope()
/// }
/// ```
///
/// ```compile_fail
/// use ferret_server::http::extract::{ScopedSession, caps};
/// fn widen(s: &mut ScopedSession<caps::Recover>) {
///     s.scope = s.scope();
/// }
/// ```
#[derive(Debug, Clone)]
pub struct SessionFacts {
    sid: SidHash,
    user_id: i64,
    issued_at: i64,
    now: i64,
    device: DeviceId,
    account: AccountId,
    vault: VaultId,
    vk_epoch: u64,
    session_version: i64,
}

impl SessionFacts {
    /// The hash of the session id: the key of the session's row.
    pub fn sid(&self) -> SidHash {
        self.sid
    }

    /// The kit user.
    pub fn user_id(&self) -> i64 {
        self.user_id
    }

    /// The sign-in time of the session.
    pub fn issued_at(&self) -> i64 {
        self.issued_at
    }

    /// The time the request was checked at (Unix seconds).
    pub fn now(&self) -> i64 {
        self.now
    }

    /// The device that signed in.
    pub fn device(&self) -> DeviceId {
        self.device
    }

    /// The account of the session's user.
    pub fn account(&self) -> AccountId {
        self.account
    }

    /// The vault of that account.
    pub fn vault(&self) -> VaultId {
        self.vault
    }

    /// The vault key epoch of the account.
    pub fn vk_epoch(&self) -> u64 {
        self.vk_epoch
    }

    /// The kit's `session_version` of the user, as checked against its cookie.
    pub fn session_version(&self) -> i64 {
        self.session_version
    }

    /// The facts of a verified request; 401 when it has no account.
    fn of(verified: &Verified) -> Result<Self, ApiError> {
        let (account, vault, vk_epoch) = verified.account.ok_or_else(ApiError::unauthorized)?;
        Ok(SessionFacts {
            sid: verified.row.sid,
            user_id: verified.row.user_id,
            issued_at: verified.row.issued_at,
            now: verified.now,
            device: verified.row.device,
            account,
            vault,
            vk_epoch,
            session_version: verified.session_version,
        })
    }
}

/// A vault session whose scope allows the capability `C::CAP`.
///
/// The session is checked as for [`VaultSession`], but any scope passes that
/// check; the scope must then allow the capability. A session that does not
/// count is `401 unauthorized`, one whose scope forbids the capability is
/// `403 forbidden`. An `account_reset` session reaches only the capabilities of
/// its scope (`ferret_server_auth::scope`).
///
/// The facts are a [`SessionFacts`], not a [`VaultSession`]: a `VaultSession`
/// always stands for a `full` session, and this one may be a reset session.
///
/// Spec: Fase 1 § 4.6 (partial session) and § 6.3 (reset account).
pub struct ScopedSession<C: Cap> {
    session: SessionFacts,
    scope: SessionScope,
    _cap: PhantomData<C>,
}

impl<C: Cap> ScopedSession<C> {
    /// The session, its account and its vault. The scope may be other than
    /// `full`.
    pub fn session(&self) -> &SessionFacts {
        &self.session
    }

    /// The scope of the session, read from its row.
    pub fn scope(&self) -> SessionScope {
        self.scope
    }

    /// The binding of this session for the OPAQUE library: the nonces of the
    /// session are bound to it.
    pub fn binding(&self) -> SessionBinding {
        session_binding(&self.session.sid)
    }
}

impl<C: Cap> fmt::Debug for ScopedSession<C> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ScopedSession")
            .field("session", &self.session)
            .field("scope", &self.scope)
            .field("cap", &C::CAP)
            .finish()
    }
}

impl<S, C> FromRequestParts<S> for ScopedSession<C>
where
    S: Send + Sync,
    SessionAuth: FromRef<S>,
    C: Cap,
{
    type Rejection = ApiError;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, ApiError> {
        let auth = SessionAuth::from_ref(state);
        let verified = auth.verify_vault_any(parts).await?;
        let session = SessionFacts::of(&verified)?;
        let scope = verified.row.scope;
        if authorize(scope, C::CAP).is_err() {
            return Err(ApiError::coded("forbidden"));
        }
        Ok(ScopedSession {
            session,
            scope,
            _cap: PhantomData,
        })
    }
}

/// What the library binds a nonce and a re-authentication to: a
/// domain-separated hash of the session's id hash. It cannot be turned back
/// into the session id.
///
/// Spec: Fase 1 § 4.6 (the nonce is bound to the session).
pub fn session_binding(sid: &SidHash) -> SessionBinding {
    let mut hasher = Sha256::new();
    hasher.update(b"ferret/v1/session-binding");
    hasher.update(sid.0);
    SessionBinding(hasher.finalize().into())
}

// ---------------------------------------------------------- fresh re-auth

/// A session that may run a sensitive operation now: the user has no second
/// factor the server would have to ask for, and this session proved the master
/// password again within [`REAUTH_SECS`](crate::auth::session::REAUTH_SECS)
/// seconds.
///
/// * No valid vault session: `401 unauthorized`.
/// * A session whose scope is not `full` (a reset session, one waiting for its
///   second factor): `403 forbidden`. Only a full session can re-authenticate.
/// * The kit has a second factor on for the user: `403
///   second_factor_required`, for every sensitive operation, until the server
///   can ask for a fresh second factor. It fails closed.
/// * The session never re-authenticated, did so more than 300 seconds ago, or
///   the clock reads before the re-authentication: `403 reauth_required`.
///
/// The time is read from the session's own row, so it belongs to the session
/// that proved the password and to no other. Using it does not use it up.
///
/// Where this differs from the spec text, on purpose: § 4.6 (b) asks for a
/// fresh second factor; this server cannot ask for one yet, so an account with
/// a second factor is refused every sensitive operation instead (stricter).
///
/// The second factor checked is the kit's TOTP, whose recovery codes it covers
/// (`users.totp_enabled`). That is the kit's only second factor. The kit's
/// passkey sign-in counts as both factors and its routes are blocked in this
/// server (`admin::guard`). A kit upgrade that adds another second factor must
/// be added to this check.
///
/// Only the extractor makes one: the fields are private, so a route can
/// neither build a `FreshReauth` nor change the time in one it was given. It
/// names the session it was read for, and `Proofs` refuses it for any other
/// session.
///
/// ```
/// fn when(fresh: &ferret_server::http::extract::FreshReauth) -> i64 {
///     fresh.reauth_at()
/// }
/// ```
///
/// ```compile_fail
/// let _ = ferret_server::http::extract::FreshReauth { reauth_at: 0 };
/// ```
///
/// ```compile_fail
/// fn renew(fresh: &mut ferret_server::http::extract::FreshReauth, now: i64) {
///     fresh.reauth_at = now;
/// }
/// ```
///
/// Spec: Fase 1 § 4.6 (a) and (b).
#[derive(Debug, Clone, Copy)]
pub struct FreshReauth {
    sid: SidHash,
    reauth_at: i64,
}

impl FreshReauth {
    /// When the session proved the master password again (Unix seconds).
    pub fn reauth_at(&self) -> i64 {
        self.reauth_at
    }

    /// The session whose row said it was fresh.
    pub(crate) fn sid(&self) -> SidHash {
        self.sid
    }
}

impl<S> FromRequestParts<S> for FreshReauth
where
    S: Send + Sync,
    SessionAuth: FromRef<S>,
{
    type Rejection = ApiError;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, ApiError> {
        let auth = SessionAuth::from_ref(state);
        let verified = auth.verify_vault_any(parts).await?;
        // Only a full session can re-authenticate; any other is never fresh,
        // whatever its row says.
        if verified.row.scope != SessionScope::Full {
            return Err(ApiError::coded("forbidden"));
        }
        if verified.second_factor {
            return Err(ApiError::coded("second_factor_required"));
        }
        match verified.row.reauth_at {
            Some(reauth_at) if reauth_fresh(&verified.row, verified.now) => Ok(FreshReauth {
                sid: verified.row.sid,
                reauth_at,
            }),
            _ => Err(ApiError::coded("reauth_required")),
        }
    }
}

// ------------------------------------------------------------ signed body

/// The nonce, the proof and the raw body of a signed request.
///
/// The body is not parsed: the library checks the proof over these exact
/// bytes first, and [`SignedBody::parse`] reads them only for a permit of the
/// library that covers them. Nothing of the request is printed by `Debug`.
///
/// The fields are private: only the extractor makes one from the request, and
/// nothing changes the nonce, the proof or the bytes after that.
///
/// ```compile_fail
/// fn swap(body: &mut ferret_server::http::extract::SignedBody) {
///     body.bytes = Default::default();
/// }
/// ```
///
/// Spec: Fase 1 § 4.6 (the proof is bound to the exact body).
pub struct SignedBody {
    /// `Ferret-Nonce`: the nonce of `POST /api/auth/challenge`.
    nonce: [u8; NONCE_LEN],
    /// `Ferret-Proof`: the Ed25519 signature.
    proof: [u8; PROOF_LEN],
    /// The body, byte for byte as it was received.
    bytes: Bytes,
}

impl fmt::Debug for SignedBody {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SignedBody([redacted])")
    }
}

/// A permit of the OPAQUE library: the right to act on a body whose SHA-256 the
/// library has checked the proof over.
///
/// The trait is sealed: only the library's two permits implement it, so no
/// other value can make [`SignedBody::parse`] read unproven bytes.
pub trait ProvenBody: sealed::Sealed {
    /// `SHA-256` of the body the proof covers.
    fn body_sha256(&self) -> &[u8; 32];
}

mod sealed {
    /// Implemented for the library's permits and nothing else.
    pub trait Sealed {}

    impl Sealed for ferret_server_auth::SignedPermit {}
    impl Sealed for ferret_server_auth::ReplacePermit {}
}

impl ProvenBody for SignedPermit {
    fn body_sha256(&self) -> &[u8; 32] {
        &self.body_sha256
    }
}

impl ProvenBody for ReplacePermit {
    fn body_sha256(&self) -> &[u8; 32] {
        &self.body_sha256
    }
}

impl SignedBody {
    /// The request for `ferret_server_auth::authorize_signed`. The scope and the
    /// session binding come from the session, never from the request.
    pub fn signed_request<'a, C: Cap>(
        &'a self,
        scoped: &ScopedSession<C>,
        caller: Caller,
        op: MutationOp,
    ) -> SignedRequest<'a> {
        SignedRequest {
            caller,
            op,
            scope: scoped.scope,
            session: scoped.binding(),
            nonce: &self.nonce,
            proof: &self.proof,
            body: &self.bytes,
        }
    }

    /// The request for `ferret_server_auth::authorize_replacement`. The scope
    /// and the session binding come from the session, never from the request.
    pub fn replace_request<'a, C: Cap>(
        &'a self,
        scoped: &ScopedSession<C>,
        caller: Caller,
        kind: ReplaceKind,
    ) -> ReplaceRequest<'a> {
        ReplaceRequest {
            caller,
            kind,
            scope: scoped.scope,
            session: scoped.binding(),
            nonce: &self.nonce,
            proof: &self.proof,
            body: &self.bytes,
        }
    }

    /// Parses the body as JSON, for a permit that covers exactly these bytes.
    ///
    /// A permit for other bytes is a mistake of the route: `500 internal`,
    /// and nothing is parsed. A body that does not parse is `400` with the
    /// code of the field that failed, and nothing of the body in the answer
    /// or the log.
    pub fn parse<T: DeserializeOwned>(&self, permit: &impl ProvenBody) -> Result<T, ApiError> {
        let digest: [u8; 32] = Sha256::digest(&self.bytes).into();
        if &digest != permit.body_sha256() {
            tracing::error!("a signed body was parsed with a permit for other bytes");
            return Err(ApiError::internal());
        }
        serde_json::from_slice(&self.bytes)
            .map_err(|error| ApiError::coded(refusal_code(&error.to_string())))
    }
}

/// The bytes of a proof header: exactly one header line, strict base64url
/// without padding, exactly `N` bytes. `None` for anything else.
fn proof_header<const N: usize>(headers: &HeaderMap, name: &str) -> Option<[u8; N]> {
    let mut lines = headers.get_all(name).iter();
    let value = lines.next()?;
    if lines.next().is_some() {
        return None;
    }
    let bytes = b64url::decode(value.to_str().ok()?).ok()?;
    <[u8; N]>::try_from(bytes).ok()
}

impl<S> FromRequest<S> for SignedBody
where
    S: Send + Sync,
{
    type Rejection = ApiError;

    async fn from_request(request: Request, _state: &S) -> Result<Self, ApiError> {
        // The headers first: they cost nothing to check, and a request that
        // fails them has its body neither read nor kept.
        let nonce = proof_header::<NONCE_LEN>(request.headers(), NONCE_HEADER)
            .ok_or_else(|| ApiError::coded("malformed_nonce"))?;
        let proof = proof_header::<PROOF_LEN>(request.headers(), PROOF_HEADER)
            .ok_or_else(|| ApiError::coded("malformed_proof"))?;
        let bytes = read_limited(request.into_body(), MAX_SIGNED_BODY).await?;
        Ok(SignedBody {
            nonce,
            proof,
            bytes,
        })
    }
}

/// Reads a body of at most `limit` bytes. One byte more is `413 too_large`,
/// and the rest is not read; a body that breaks off or fails to arrive is
/// `400 bad_request`.
async fn read_limited(body: Body, limit: usize) -> Result<Bytes, ApiError> {
    let mut frames = body.into_data_stream();
    let mut out: Vec<u8> = Vec::new();
    while let Some(frame) = frames.next().await {
        let chunk = frame.map_err(|_| ApiError::coded("bad_request"))?;
        if out.len().saturating_add(chunk.len()) > limit {
            return Err(ApiError::coded("too_large"));
        }
        out.extend_from_slice(&chunk);
    }
    Ok(Bytes::from(out))
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderValue;

    fn chunks(parts: Vec<Result<&'static [u8], std::io::Error>>) -> Body {
        Body::from_stream(futures_util::stream::iter(
            parts.into_iter().map(|p| p.map(Bytes::from_static)),
        ))
    }

    #[tokio::test]
    async fn a_body_is_413_only_when_it_passes_the_limit() {
        // In pieces, up to the limit exactly: read whole.
        let body = chunks(vec![Ok(b"abc"), Ok(b"de")]);
        assert_eq!(read_limited(body, 5).await.expect("5 bytes"), "abcde");
        // One byte more: 413.
        let body = chunks(vec![Ok(b"abc"), Ok(b"def")]);
        let refused = read_limited(body, 5).await.expect_err("6 bytes");
        assert_eq!((refused.status.as_u16(), refused.code), (413, "too_large"));
        // A body that breaks off is not "too large".
        let broken = std::io::Error::other("the client went away");
        let body = chunks(vec![Ok(b"ab"), Err(broken)]);
        let refused = read_limited(body, 5).await.expect_err("broken");
        assert_eq!(
            (refused.status.as_u16(), refused.code),
            (400, "bad_request")
        );
        // An empty body is an empty body.
        assert!(
            read_limited(Body::empty(), 5)
                .await
                .expect("empty")
                .is_empty()
        );
    }

    #[test]
    fn every_cap_names_its_own_capability() {
        assert_eq!(caps::Challenge::CAP, Capability::Challenge);
        assert_eq!(
            caps::OpaqueRegisterStart::CAP,
            Capability::OpaqueRegisterStart
        );
        assert_eq!(caps::RecoveryWrapRead::CAP, Capability::RecoveryWrapRead);
        assert_eq!(caps::Recover::CAP, Capability::Recover);
        assert_eq!(caps::PasswordPut::CAP, Capability::PasswordPut);
        assert_eq!(
            caps::UnlockMethodsWrite::CAP,
            Capability::UnlockMethodsWrite
        );
        assert_eq!(caps::SyncWrite::CAP, Capability::SyncWrite);
        assert_eq!(caps::DeviceManage::CAP, Capability::DeviceManage);
    }

    #[test]
    fn a_proof_header_is_one_line_of_exact_base64url() {
        let mut headers = HeaderMap::new();
        assert_eq!(proof_header::<2>(&headers, NONCE_HEADER), None);
        headers.insert(NONCE_HEADER, HeaderValue::from_static("AQI"));
        assert_eq!(proof_header::<2>(&headers, NONCE_HEADER), Some([1, 2]));
        assert_eq!(proof_header::<3>(&headers, NONCE_HEADER), None);
        for bad in ["AQI=", "AQI ", "", "A+I", "A/I"] {
            headers.insert(NONCE_HEADER, HeaderValue::from_static(bad));
            assert_eq!(proof_header::<2>(&headers, NONCE_HEADER), None, "{bad:?}");
        }
        headers.insert(NONCE_HEADER, HeaderValue::from_static("AQI"));
        headers.append(NONCE_HEADER, HeaderValue::from_static("AQI"));
        assert_eq!(proof_header::<2>(&headers, NONCE_HEADER), None);
    }

    #[test]
    fn the_session_binding_is_domain_separated_and_differs_per_session() {
        let a = session_binding(&SidHash([1; 32]));
        let b = session_binding(&SidHash([2; 32]));
        assert_ne!(a.0, b.0);
        assert_ne!(a.0, [1; 32]);
        assert_eq!(a.0, session_binding(&SidHash([1; 32])).0);
    }

    #[test]
    fn parse_takes_only_a_permit_for_exactly_these_bytes() {
        use ferret_core::{AccountId, AuthPublicKey, RecoveryPublicKey};
        use ferret_server_auth::{ScopeEffect, WriteBasis};

        const BODY: &[u8] = br#"{"n":7}"#;
        let signed = SignedBody {
            nonce: [1; NONCE_LEN],
            proof: [2; PROOF_LEN],
            bytes: Bytes::from_static(BODY),
        };
        let permit_for = |body: &[u8]| {
            let account_id = AccountId::from_bytes([3; 16]);
            SignedPermit {
                account_id,
                op: MutationOp::UnlockMethodRecoveryPut,
                body_sha256: Sha256::digest(body).into(),
                session_effect: ScopeEffect::Keep,
                basis: WriteBasis {
                    account_id,
                    vk_epoch: 1,
                    pk_a: AuthPublicKey::new([0; 32]),
                    pk_r: RecoveryPublicKey::new([0; 32]),
                    row_version: 0,
                },
            }
        };
        let other = signed
            .parse::<serde_json::Value>(&permit_for(br#"{"n":8}"#))
            .expect_err("a permit for other bytes");
        assert_eq!(other.status.as_u16(), 500);
        let parsed: serde_json::Value = signed.parse(&permit_for(BODY)).expect("its own permit");
        assert_eq!(parsed["n"], 7);
    }

    #[test]
    fn debug_of_a_signed_body_shows_nothing() {
        let body = SignedBody {
            nonce: [7; NONCE_LEN],
            proof: [8; PROOF_LEN],
            bytes: Bytes::from_static(b"canary-body"),
        };
        assert_eq!(format!("{body:?}"), "SignedBody([redacted])");
    }
}
