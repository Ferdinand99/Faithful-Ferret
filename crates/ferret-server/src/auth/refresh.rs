//! Renewing and revoking a device's tokens: `POST /api/auth/token/refresh` and
//! `POST /api/auth/token/revoke`, the grace period of a refresh token, and the
//! purge of old token rows. Spec: Fase 1 § 7.6; RFC 9449 § 5.
//!
//! A refresh token is used once: a renewal marks it used and issues the next
//! one, in one `BEGIN IMMEDIATE` transaction. For [`GRACE_SECS`] after that,
//! the same token with a proof of the same key gets the same successor again
//! (an answer lost on the way); after that, or with another key, its use
//! revokes the device. A device that renews nothing for [`IDLE_SECS`], or
//! that signed in more than [`ABSOLUTE_SECS`] ago, signs in again.
//!
//! # The renewal
//!
//! The route checks the transport, reads the body (at most
//! [`MAX_BODY_BYTES`]) and then the clock, once; that time is the one the
//! proof and everything after it are checked against, and every answer from
//! there on carries it as its `Date` (`tokens::with_server_date`). Then:
//!
//! 1. The refresh token is read strictly (`400 bad_request` otherwise), and
//!    the DPoP proof is checked without state: `htm` `POST`, `htu` the
//!    configured vault origin and this path, no `ath` (`401 dpop_invalid`
//!    otherwise, before the database is touched).
//! 2. In one `BEGIN IMMEDIATE` transaction the row of the token's hash is read
//!    with its device. No row: `401 token_expired`. A revoked device, or one
//!    `devices::still_valid` refuses (a disabled user, the kit's sign-out
//!    everywhere, an account without a vault): `401 device_revoked`. A device
//!    whose only fault is its age goes on to step 5 instead, so a family that
//!    ran out answers `token_expired` at the second its tokens end.
//! 3. The proof's key is not the device's: the device is revoked (its family
//!    with it) and the answer is `401 token_reused`. A refresh token that
//!    travels with a proof of another key has leaked. The `jti` of that proof
//!    takes no place in the cache.
//! 4. The key is the device's: the proof's `jti` is recorded now, inside the
//!    transaction and before anything is written. A replayed `jti` (`401
//!    dpop_invalid`), a key or an account with too many proofs (`429
//!    throttled`) or a full cache (`503 busy`) rolls everything back.
//! 5. The token is past its idle or its absolute end: the device is revoked
//!    and the answer is `401 token_expired`.
//! 6. The token was not used: it is marked used, its successor is written
//!    (`prev_hash` this token, a new idle end, the absolute end inherited; the
//!    unique index on `prev_hash` allows one successor only), a new access
//!    token is written, and the successor is held in [`RefreshGrace`]. A full
//!    store refuses with `503 busy`, and nothing is rotated.
//! 7. The token was used at most [`GRACE_SECS`] ago and its successor is not
//!    used yet: the answer is the same successor and a new access token, if
//!    [`RefreshGrace`] still holds the successor for this key. After a restart
//!    it does not, and the answer is `401 token_expired` without a revocation.
//! 8. Otherwise (later than the grace period, or the successor was used): the
//!    device is revoked and the answer is `401 token_reused`.
//!
//! A revocation is committed with the transaction and announced after the
//! commit (`SyncEvents::device_revoked`), so the device's streams close at
//! once. `token_reused` and `device_revoked` are final for the device.
//!
//! # Signing out
//!
//! `POST /api/auth/token/revoke` takes the refresh token and a proof for its
//! own path, read and checked as in step 1. A token the server does not know,
//! or one of a device revoked already, changes nothing. A proof of another key
//! revokes the device (the token has leaked). With the device's key, the
//! `jti` is recorded in the transaction as in step 4, and the device is
//! revoked. The answer is `204` in every case but a refused body or proof.
//!
//! # The purge
//!
//! [`purge_expired`] runs every [`PURGE_EVERY`] in one `BEGIN IMMEDIATE`
//! transaction: expired access rows go, used refresh rows go
//! [`USED_KEEP_SECS`] after their use (a reuse of an older token is then
//! `token_expired`), a device with no live refresh token left is revoked (so
//! it leaves the quota), and [`REVOKED_KEEP_SECS`] after a revocation the
//! device's token rows and then its row are deleted.
//!
//! Tokens, proofs and keys never go into a log or an error body.

use std::collections::{BTreeMap, HashMap};
use std::fmt;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use axum::body::Body;
use axum::extract::{ConnectInfo, FromRef, Request, State};
use axum::http::{HeaderMap, Method, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::post;
use axum::{Json, Router};
use ferret_core::OsRng;
use ferret_server_auth::Clock;
use rusqlite::{Connection, OptionalExtension as _, Transaction, TransactionBehavior, params};
use zeroize::Zeroizing;

use crate::auth::devices::{self, REVOKED_KEEP_SECS};
use crate::auth::dpop::{self, DpopError, Expect, VerifiedProof};
use crate::auth::login::{clock_now, no_store, require_transport, to_i64};
use crate::auth::tokens::{DeviceAuth, issue_access, with_server_date};
use crate::error::{ApiError, StoreError};
use crate::ids::{DeviceId, TokenHash, TokenSecret};
use crate::state::{FerretState, VaultDb};
use crate::wire::{
    ACCESS_TOKEN_SECS, TokenJson, TokenRefreshReq, TokenRes, TokenRevokeReq, TokenTypeJson,
};

/// How often the old token rows and devices are purged.
pub const PURGE_EVERY: Duration = Duration::from_secs(10 * 60);

/// How long a used refresh token still gets its successor, with a proof of
/// the same key, in seconds.
pub const GRACE_SECS: i64 = 60;

/// How long a refresh token lives without being used, in seconds.
pub const IDLE_SECS: i64 = 30 * 86_400;

/// How long the tokens of one sign-in live at most, in seconds.
pub const ABSOLUTE_SECS: i64 = 90 * 86_400;

/// How long a used refresh row is kept after its use, in seconds, so a reuse
/// of an old token is still seen as one.
pub const USED_KEEP_SECS: i64 = 30 * 86_400;

/// The most successors held in memory for the grace period. A full store
/// refuses a renewal (`503 busy`) instead of dropping one.
pub const GRACE_CAPACITY: usize = 65_536;

/// The path of the renewal, as the `htu` of its proof names it.
pub const REFRESH_PATH: &str = "/api/auth/token/refresh";

/// The path of a device's sign-out, as the `htu` of its proof names it.
pub const REVOKE_PATH: &str = "/api/auth/token/revoke";

/// The most a renewal or a sign-out body may carry (`413 too_large` beyond):
/// `{"refresh_token":"…"}` is 61 bytes.
pub const MAX_BODY_BYTES: usize = 1024;

// ------------------------------------------------------------ the grace store

/// One successor held for the grace period.
struct Held {
    /// The successor as it travels, zeroed when it is dropped.
    text: Zeroizing<String>,
    /// The RFC 7638 thumbprint of the key the successor is bound to.
    jkt: [u8; 32],
    /// The last second (Unix) the successor may be handed out again.
    until: i64,
    /// Its place in [`Store::order`].
    slot: (i64, u64),
}

/// The store behind the lock.
#[derive(Default)]
struct Store {
    /// The hash of the used token → its successor.
    by_old: HashMap<TokenHash, Held>,
    /// The key → the hash of the used token whose successor is held for it.
    /// A device has one chain of refresh tokens, so only the newest successor
    /// of a key can still be asked for: once that successor is used itself, a
    /// retry of the older token is a reuse, whatever the store holds.
    by_key: HashMap<[u8; 32], TokenHash>,
    /// The entries by the time they go (and a number that keeps equal times
    /// apart), so the first is always the next to go.
    order: BTreeMap<(i64, u64), TokenHash>,
    /// The number of the next entry.
    next: u64,
}

impl Store {
    /// Drops the entry of `old`, if there is one.
    fn remove(&mut self, old: &TokenHash) {
        if let Some(held) = self.by_old.remove(old) {
            self.order.remove(&held.slot);
            if self.by_key.get(&held.jkt) == Some(old) {
                self.by_key.remove(&held.jkt);
            }
        }
    }

    /// Drops the entries whose time is out at `now`.
    fn forget_expired(&mut self, now: i64) {
        while let Some((&(until, _), _)) = self.order.first_key_value() {
            if until >= now {
                break;
            }
            let Some((_, old)) = self.order.pop_first() else {
                break;
            };
            self.remove(&old);
        }
    }
}

/// The successors of the refresh tokens used in the last [`GRACE_SECS`], held
/// in memory only (the database has hashes only), keyed by the hash of the
/// used token and bound to the key of the device. One store for the process,
/// shared through an `Arc`; a restart empties it. An entry is zeroed when it
/// goes.
///
/// It holds at most one successor per key: a new one for the same key takes
/// the place of the last one, which could no longer be handed out (see
/// [`RefreshGrace::put`]). So it holds at most one entry per device that
/// renewed in the last minute, and never more than its capacity.
///
/// Spec: Fase 1 § 7.6 (rotating refresh tokens).
pub struct RefreshGrace {
    /// The most successors held.
    capacity: usize,
    /// The successors.
    store: Mutex<Store>,
}

impl RefreshGrace {
    /// An empty store that holds at most `capacity` successors.
    pub fn new(capacity: usize) -> Self {
        Self {
            capacity,
            store: Mutex::new(Store::default()),
        }
    }

    /// Holds `successor`, the token that took the place of the token with the
    /// hash `old` at `now` (Unix seconds), for the key with the thumbprint
    /// `jkt`, until [`GRACE_SECS`] after `now`.
    ///
    /// The entry held for the same key goes: the token it answers for was the
    /// predecessor of `old`, and `old` is used now, so a retry of that older
    /// token is a reuse. A store at its capacity (the expired entries and that
    /// entry counted out) refuses with [`DpopError::Full`] and changes
    /// nothing: the renewal is refused (`503 busy`) rather than an entry
    /// dropped.
    pub fn put(
        &self,
        old: &TokenHash,
        successor: &TokenSecret,
        jkt: [u8; 32],
        now: i64,
    ) -> Result<(), DpopError> {
        let mut store = self.store.lock().unwrap_or_else(PoisonError::into_inner);
        store.forget_expired(now);
        let replaced = store.by_key.get(&jkt).copied();
        let again = store.by_old.contains_key(old) && replaced != Some(*old);
        let freed = usize::from(replaced.is_some()).saturating_add(usize::from(again));
        if store.by_old.len().saturating_sub(freed) >= self.capacity {
            return Err(DpopError::Full);
        }
        if let Some(replaced) = replaced {
            store.remove(&replaced);
        }
        store.remove(old);

        let until = now.saturating_add(GRACE_SECS);
        let slot = (until, store.next);
        store.next = store.next.wrapping_add(1);
        store.order.insert(slot, *old);
        store.by_key.insert(jkt, *old);
        store.by_old.insert(
            *old,
            Held {
                text: Zeroizing::new(successor.to_wire()),
                jkt,
                until,
                slot,
            },
        );
        Ok(())
    }

    /// The successor of the token with the hash `old`, if one is held, it is
    /// bound to the key `jkt`, and `now` is at most [`GRACE_SECS`] after it
    /// was put.
    pub fn get(&self, old: &TokenHash, jkt: &[u8; 32], now: i64) -> Option<TokenSecret> {
        let mut store = self.store.lock().unwrap_or_else(PoisonError::into_inner);
        store.forget_expired(now);
        let held = store.by_old.get(old)?;
        if held.jkt != *jkt || now > held.until {
            return None;
        }
        TokenSecret::from_wire(&held.text).ok()
    }

    /// How many successors the store holds, counting those whose time ran out
    /// since the last [`RefreshGrace::put`] or [`RefreshGrace::get`].
    pub fn len(&self) -> usize {
        self.store
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .by_old
            .len()
    }

    /// Whether the store holds no successor.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl fmt::Debug for RefreshGrace {
    /// The size only: the successors and the keys stay out of a log.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RefreshGrace")
            .field("len", &self.len())
            .field("capacity", &self.capacity)
            .finish_non_exhaustive()
    }
}

// ------------------------------------------------------------------ the routes

/// The routes of the renewal and the sign-out of a device, on the vault
/// listener only.
pub fn routes<S>() -> Router<S>
where
    S: Clone + Send + Sync + 'static,
    FerretState: FromRef<S>,
{
    Router::new()
        .route(REFRESH_PATH, post(refresh_route))
        .route(REVOKE_PATH, post(revoke_route))
}

/// A refresh token and the proof that came with it, both checked without
/// state.
struct Presented {
    /// The hash of the refresh token.
    old: TokenHash,
    /// The proof.
    proof: VerifiedProof,
}

/// Reads the body, at most [`MAX_BODY_BYTES`] (`413 too_large` beyond).
async fn read_body(body: Body) -> Result<axum::body::Bytes, ApiError> {
    axum::body::to_bytes(body, MAX_BODY_BYTES)
        .await
        .map_err(|_| ApiError::coded("too_large"))
}

/// Reads `token` strictly (`400 bad_request` when it is not a token), and
/// then checks the proof of a `POST` to `path` at `now`, without `ath` and
/// without state (`401 dpop_invalid`).
///
/// RFC 9449 § 4.3, § 5.
fn present(
    auth: &DeviceAuth,
    headers: &HeaderMap,
    token: &TokenJson,
    path: &str,
    now: i64,
) -> Result<Presented, ApiError> {
    let old = TokenSecret::from_wire(&token.0)
        .map_err(|_| ApiError::coded("bad_request"))?
        .hash();
    let htu = auth.htu(path);
    let proof = dpop::verify(
        headers,
        &Expect {
            method: &Method::POST,
            htu: &htu,
            access: None,
        },
        now,
    )?;
    Ok(Presented { old, proof })
}

/// `POST /api/auth/token/refresh`: see the module documentation.
async fn refresh_route(
    State(state): State<FerretState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    request: Request,
) -> Result<Response, ApiError> {
    let (parts, body) = request.into_parts();
    require_transport(&state, &parts.headers, peer)?;
    let bytes = read_body(body).await?;
    // The time of the renewal: the proof and the rows are checked against
    // it, and every answer from here on carries it as its `Date`.
    let now = to_i64(clock_now(&state)?)?;
    let answer = match refresh_at(&state, &parts.headers, &bytes, now).await {
        Ok(response) => response,
        Err(error) => error.into_response(),
    };
    Ok(with_server_date(answer, now))
}

async fn refresh_at(
    state: &FerretState,
    headers: &HeaderMap,
    bytes: &[u8],
    now: i64,
) -> Result<Response, ApiError> {
    let req: TokenRefreshReq =
        serde_json::from_slice(bytes).map_err(|_| ApiError::coded("bad_request"))?;
    let Presented { old, proof } = present(
        &state.device_auth,
        headers,
        &req.refresh_token,
        REFRESH_PATH,
        now,
    )?;
    drop(req);

    let auth = state.device_auth.clone();
    let renewed = state
        .vault_db
        .with_conn(move |conn| renew_tx(conn, &old, &proof, &auth, now))
        .await?;
    match renewed {
        Renewed::Tokens { access, refresh } => Ok(no_store(
            Json(TokenRes {
                access_token: TokenJson(access.to_wire()),
                refresh_token: TokenJson(refresh.to_wire()),
                token_type: TokenTypeJson::DPoP,
                expires_in: ACCESS_TOKEN_SECS,
            })
            .into_response(),
        )),
        Renewed::Refused(code) => Err(ApiError::coded(code)),
        Renewed::Revoked(device, why) => {
            // After the commit: the device's streams close now.
            state.events.device_revoked(device);
            match why {
                Why::OtherKey => tracing::warn!(
                    "a device was revoked: its refresh token came with a proof of another key"
                ),
                Why::Reused => {
                    tracing::warn!("a device was revoked: a used refresh token came again");
                }
                Why::Ended => tracing::info!("a device was revoked: its refresh token ran out"),
            }
            Err(ApiError::coded(why.code()))
        }
        Renewed::Proof(error) => Err(ApiError::from(error)),
    }
}

/// Why a renewal revoked the device.
#[derive(Clone, Copy)]
enum Why {
    /// The proof was of another key (`token_reused`).
    OtherKey,
    /// A used token came after its grace period, or after its successor was
    /// used (`token_reused`).
    Reused,
    /// The token was past its idle or its absolute end (`token_expired`).
    Ended,
}

impl Why {
    /// The code of the answer.
    fn code(self) -> &'static str {
        match self {
            Why::OtherKey | Why::Reused => "token_reused",
            Why::Ended => "token_expired",
        }
    }
}

/// How the transaction of a renewal ended.
enum Renewed {
    /// A new access token and the next refresh token (a new one, or the same
    /// successor again in the grace period); committed.
    Tokens {
        access: TokenSecret,
        refresh: TokenSecret,
    },
    /// Refused with this code; nothing was written.
    Refused(&'static str),
    /// The device was revoked, and the revocation is committed.
    Revoked(DeviceId, Why),
    /// The proof's `jti` was refused when it was recorded, or the grace store
    /// is full; nothing was written.
    Proof(DpopError),
}

/// A refresh row with its device.
struct RefreshRow {
    /// The device.
    device: DeviceId,
    /// The account's user (`users.id`).
    user_id: i64,
    /// The RFC 7638 thumbprint of the device key.
    jkt: [u8; 32],
    /// Whether the device was revoked.
    revoked: bool,
    /// The end of the token without use (Unix seconds).
    idle_expires_at: i64,
    /// The end of every token of the sign-in (Unix seconds).
    abs_expires_at: i64,
    /// When the token was used, if it was.
    used_at: Option<i64>,
}

/// A blob of the wrong length in a token row.
fn bad_blob(index: usize, what: &str) -> rusqlite::Error {
    rusqlite::Error::FromSqlConversionFailure(
        index,
        rusqlite::types::Type::Blob,
        what.to_string().into(),
    )
}

/// The refresh row with the hash `old`, read through its device.
fn find(conn: &Connection, old: &TokenHash) -> rusqlite::Result<Option<RefreshRow>> {
    type Found = (Vec<u8>, i64, Vec<u8>, bool, i64, i64, Option<i64>);
    let found: Option<Found> = conn
        .query_row(
            "SELECT r.device_id, d.user_id, d.jkt, d.revoked_at IS NOT NULL,
                    r.idle_expires_at, r.abs_expires_at, r.used_at
             FROM ferret_refresh r JOIN ferret_devices d ON d.device_id = r.device_id
             WHERE r.token_hash = ?1",
            params![old.0.as_slice()],
            |r| {
                Ok((
                    r.get(0)?,
                    r.get(1)?,
                    r.get(2)?,
                    r.get(3)?,
                    r.get(4)?,
                    r.get(5)?,
                    r.get(6)?,
                ))
            },
        )
        .optional()?;
    let Some((device, user_id, jkt, revoked, idle_expires_at, abs_expires_at, used_at)) = found
    else {
        return Ok(None);
    };
    let device = <[u8; 16]>::try_from(device).map_err(|_| bad_blob(0, "device id"))?;
    let jkt = <[u8; 32]>::try_from(jkt).map_err(|_| bad_blob(2, "jkt"))?;
    Ok(Some(RefreshRow {
        device: DeviceId(device),
        user_id,
        jkt,
        revoked,
        idle_expires_at,
        abs_expires_at,
        used_at,
    }))
}

/// The hash of the successor of the token with the hash `old`, and whether
/// that successor was used.
fn successor_of(conn: &Connection, old: &TokenHash) -> rusqlite::Result<Option<(TokenHash, bool)>> {
    let found: Option<(Vec<u8>, bool)> = conn
        .query_row(
            "SELECT token_hash, used_at IS NOT NULL FROM ferret_refresh WHERE prev_hash = ?1",
            params![old.0.as_slice()],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .optional()?;
    let Some((hash, used)) = found else {
        return Ok(None);
    };
    let hash = <[u8; 32]>::try_from(hash).map_err(|_| bad_blob(0, "token hash"))?;
    Ok(Some((TokenHash(hash), used)))
}

/// Revokes the device of `row` at `now` and commits.
fn revoke_and_commit(
    tx: Transaction<'_>,
    row: &RefreshRow,
    why: Why,
    now: i64,
) -> Result<Renewed, StoreError> {
    devices::revoke(&tx, row.user_id, &row.device, now)?;
    tx.commit()?;
    Ok(Renewed::Revoked(row.device, why))
}

/// The database side of a renewal, in one write transaction: steps 2 to 8 of
/// the module documentation. Every outcome but a revocation and new tokens
/// returns before the commit, so nothing of it is kept.
///
/// Spec: Fase 1 § 7.6; RFC 9449 § 5, § 11.1.
fn renew_tx(
    conn: &mut Connection,
    old: &TokenHash,
    proof: &VerifiedProof,
    auth: &DeviceAuth,
    now: i64,
) -> Result<Renewed, StoreError> {
    let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let Some(row) = find(&tx, old)? else {
        return Ok(Renewed::Refused("token_expired"));
    };
    // A revoked device stays revoked (its rows are kept, so its tokens are
    // still known). A device the account no longer accepts uses no token.
    // `still_valid` also ends a device at its absolute end, which is the
    // absolute end of every token of its chain: that case is step 5's.
    if row.revoked || (now < row.abs_expires_at && !devices::still_valid(&tx, &row.device, now)?) {
        return Ok(Renewed::Refused("device_revoked"));
    }
    // A refresh token with a proof of another key has leaked: the device and
    // its family end. The proof's `jti` takes no place in the cache.
    if *proof.jkt() != row.jkt {
        return revoke_and_commit(tx, &row, Why::OtherKey, now);
    }
    // The key is bound to the token: the `jti` is recorded now, before
    // anything is written; a refusal rolls the transaction back.
    if let Err(error) = auth.replay().record(proof, row.user_id, now) {
        return Ok(Renewed::Proof(error));
    }
    if now >= row.idle_expires_at || now >= row.abs_expires_at {
        return revoke_and_commit(tx, &row, Why::Ended, now);
    }
    let Some(used_at) = row.used_at else {
        return rotate(tx, old, &row, auth, now);
    };
    let in_grace = now.saturating_sub(used_at) <= GRACE_SECS;
    match successor_of(&tx, old)? {
        Some((next, false)) if in_grace => match auth.grace().get(old, &row.jkt, now) {
            Some(successor) if successor.hash() == next => {
                let access = issue_access(&tx, &row.device, now, &mut OsRng)?;
                devices::touch(&tx, &row.device, now)?;
                tx.commit()?;
                Ok(Renewed::Tokens {
                    access,
                    refresh: successor,
                })
            }
            // Not held (the server restarted since): the device signs in
            // again, and nothing is revoked.
            _ => Ok(Renewed::Refused("token_expired")),
        },
        _ => revoke_and_commit(tx, &row, Why::Reused, now),
    }
}

/// Step 6: the token is used now; its successor and a new access token are
/// written, and the successor is held for the grace period. A full grace
/// store returns before the commit.
fn rotate(
    tx: Transaction<'_>,
    old: &TokenHash,
    row: &RefreshRow,
    auth: &DeviceAuth,
    now: i64,
) -> Result<Renewed, StoreError> {
    let marked = tx.execute(
        "UPDATE ferret_refresh SET used_at = ?2 WHERE token_hash = ?1 AND used_at IS NULL",
        params![old.0.as_slice(), now],
    )?;
    if marked != 1 {
        return Err(StoreError::Invalid("a refresh token read unused was used"));
    }
    let next = TokenSecret::random(&mut OsRng);
    tx.execute(
        "INSERT INTO ferret_refresh
            (token_hash, device_id, prev_hash, issued_at, idle_expires_at, abs_expires_at, used_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, NULL)",
        params![
            next.hash().0.as_slice(),
            row.device.0.as_slice(),
            old.0.as_slice(),
            now,
            now.saturating_add(IDLE_SECS),
            row.abs_expires_at,
        ],
    )?;
    let access = issue_access(&tx, &row.device, now, &mut OsRng)?;
    devices::touch(&tx, &row.device, now)?;
    if let Err(error) = auth.grace().put(old, &next, row.jkt, now) {
        return Ok(Renewed::Proof(error));
    }
    tx.commit()?;
    Ok(Renewed::Tokens {
        access,
        refresh: next,
    })
}

/// `POST /api/auth/token/revoke`: see the module documentation.
async fn revoke_route(
    State(state): State<FerretState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    request: Request,
) -> Result<Response, ApiError> {
    let (parts, body) = request.into_parts();
    require_transport(&state, &parts.headers, peer)?;
    let bytes = read_body(body).await?;
    let now = to_i64(clock_now(&state)?)?;
    let answer = match revoke_at(&state, &parts.headers, &bytes, now).await {
        Ok(response) => response,
        Err(error) => error.into_response(),
    };
    Ok(with_server_date(answer, now))
}

async fn revoke_at(
    state: &FerretState,
    headers: &HeaderMap,
    bytes: &[u8],
    now: i64,
) -> Result<Response, ApiError> {
    let req: TokenRevokeReq =
        serde_json::from_slice(bytes).map_err(|_| ApiError::coded("bad_request"))?;
    let Presented { old, proof } = present(
        &state.device_auth,
        headers,
        &req.refresh_token,
        REVOKE_PATH,
        now,
    )?;
    drop(req);

    let auth = state.device_auth.clone();
    let signed_out = state
        .vault_db
        .with_conn(move |conn| sign_out_tx(conn, &old, &proof, &auth, now))
        .await?;
    match signed_out {
        SignedOut::Unchanged => {}
        SignedOut::Revoked { device, other_key } => {
            // After the commit: the device's streams close now.
            state.events.device_revoked(device);
            if other_key {
                tracing::warn!(
                    "a device was revoked: its refresh token came with a proof of another key"
                );
            } else {
                tracing::info!("a device signed out");
            }
        }
        SignedOut::Proof(error) => return Err(ApiError::from(error)),
    }
    Ok(no_store(StatusCode::NO_CONTENT.into_response()))
}

/// How the transaction of a sign-out ended.
enum SignedOut {
    /// No such token, or its device was revoked already: nothing changed.
    Unchanged,
    /// The device was revoked, and the revocation is committed.
    Revoked {
        device: DeviceId,
        /// Whether the proof was of another key than the device's.
        other_key: bool,
    },
    /// The proof's `jti` was refused when it was recorded; nothing changed.
    Proof(DpopError),
}

/// The database side of a sign-out, in one write transaction.
///
/// Spec: Fase 1 § 7.6 (revoking a device); RFC 9449 § 11.1.
fn sign_out_tx(
    conn: &mut Connection,
    old: &TokenHash,
    proof: &VerifiedProof,
    auth: &DeviceAuth,
    now: i64,
) -> Result<SignedOut, StoreError> {
    let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let Some(row) = find(&tx, old)? else {
        return Ok(SignedOut::Unchanged);
    };
    if row.revoked {
        return Ok(SignedOut::Unchanged);
    }
    let other_key = *proof.jkt() != row.jkt;
    // The proof's `jti` takes a place in the cache only when its key is bound
    // to a device the account still accepts. A proof of another key (the
    // token has leaked) and a device that can use nothing any more end the
    // device all the same.
    if !other_key
        && devices::still_valid(&tx, &row.device, now)?
        && let Err(error) = auth.replay().record(proof, row.user_id, now)
    {
        return Ok(SignedOut::Proof(error));
    }
    devices::revoke(&tx, row.user_id, &row.device, now)?;
    tx.commit()?;
    Ok(SignedOut::Revoked {
        device: row.device,
        other_key,
    })
}

// ------------------------------------------------------------------ the purge

/// What one purge removed, row by row.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Purged {
    /// Expired access rows, and the access rows of devices revoked more than
    /// [`REVOKED_KEEP_SECS`] ago.
    pub access: usize,
    /// Refresh rows used more than [`USED_KEEP_SECS`] ago, and the refresh
    /// rows of devices revoked more than [`REVOKED_KEEP_SECS`] ago.
    pub refresh: usize,
    /// Devices with no live refresh token left (revoked), and devices revoked
    /// more than [`REVOKED_KEEP_SECS`] ago (deleted).
    pub devices: usize,
}

/// Purges the old token rows and devices at `now` (Unix seconds), inside the
/// caller's transaction, which the caller opens with `BEGIN IMMEDIATE` and
/// commits:
///
/// 1. access rows that expired (`now` at or past `expires_at`);
/// 2. refresh rows used more than [`USED_KEEP_SECS`] ago (a reuse of one of
///    them is `token_expired` from then on);
/// 3. a device that is not revoked and has no live refresh token (one that
///    was not used and is before its idle and its absolute end) is revoked at
///    `now`, so it leaves the quota;
/// 4. the token rows of devices revoked more than [`REVOKED_KEEP_SECS`] ago,
///    and then those device rows.
///
/// Spec: Fase 1 § 7.6.
pub fn purge_expired(tx: &Transaction<'_>, now: i64) -> rusqlite::Result<Purged> {
    let expired_access = tx.execute(
        "DELETE FROM ferret_access WHERE expires_at <= ?1",
        params![now],
    )?;
    let used_refresh = tx.execute(
        "DELETE FROM ferret_refresh WHERE used_at IS NOT NULL AND used_at < ?1",
        params![now.saturating_sub(USED_KEEP_SECS)],
    )?;
    let revoked = tx.execute(
        "UPDATE ferret_devices SET revoked_at = ?1
         WHERE revoked_at IS NULL
           AND NOT EXISTS (
             SELECT 1 FROM ferret_refresh r
             WHERE r.device_id = ferret_devices.device_id
               AND r.used_at IS NULL
               AND r.idle_expires_at > ?1
               AND r.abs_expires_at > ?1)",
        params![now],
    )?;
    let gone = now.saturating_sub(REVOKED_KEEP_SECS);
    let gone_access = tx.execute(
        "DELETE FROM ferret_access WHERE device_id IN (
           SELECT device_id FROM ferret_devices
           WHERE revoked_at IS NOT NULL AND revoked_at < ?1)",
        params![gone],
    )?;
    let gone_refresh = tx.execute(
        "DELETE FROM ferret_refresh WHERE device_id IN (
           SELECT device_id FROM ferret_devices
           WHERE revoked_at IS NOT NULL AND revoked_at < ?1)",
        params![gone],
    )?;
    let gone_devices = tx.execute(
        "DELETE FROM ferret_devices WHERE revoked_at IS NOT NULL AND revoked_at < ?1",
        params![gone],
    )?;
    Ok(Purged {
        access: expired_access.saturating_add(gone_access),
        refresh: used_refresh.saturating_add(gone_refresh),
        devices: revoked.saturating_add(gone_devices),
    })
}

/// Runs [`purge_expired`] once at the clock's now, in one `BEGIN IMMEDIATE`
/// transaction, and returns what it removed.
pub async fn purge_once(db: &VaultDb, clock: &dyn Clock) -> Result<Purged, StoreError> {
    let now = i64::try_from(clock.now_unix()).map_err(|_| StoreError::Invalid("the clock"))?;
    db.with_conn(move |conn| {
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let purged = purge_expired(&tx, now)?;
        tx.commit()?;
        Ok(purged)
    })
    .await
}

/// Purges the old token rows and devices every [`PURGE_EVERY`]. Call it once,
/// inside the runtime.
pub fn spawn_purge(db: VaultDb, clock: Arc<dyn Clock>) {
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(PURGE_EVERY);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            ticker.tick().await;
            match purge_once(&db, clock.as_ref()).await {
                Ok(purged) if purged == Purged::default() => {}
                Ok(purged) => tracing::debug!(
                    access = purged.access,
                    refresh = purged.refresh,
                    devices = purged.devices,
                    "old device tokens and devices removed"
                ),
                Err(error) => tracing::warn!(%error, "old device tokens were not removed"),
            }
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use ferret_core::TestRng;

    const NOW: i64 = 1_793_491_200;

    fn token(seed: &[u8]) -> TokenSecret {
        TokenSecret::random(&mut TestRng::new(seed))
    }

    fn at(secs: i64) -> i64 {
        NOW.saturating_add(secs)
    }

    #[test]
    fn the_grace_store_hands_the_successor_to_the_same_key_for_sixty_seconds() {
        let grace = RefreshGrace::new(4);
        let old = token(b"old").hash();
        let next = token(b"next");
        grace.put(&old, &next, [1; 32], NOW).expect("room");
        let got = grace.get(&old, &[1; 32], at(GRACE_SECS)).expect("held");
        assert_eq!(got.hash(), next.hash());
        assert!(
            grace.get(&old, &[2; 32], at(GRACE_SECS)).is_none(),
            "another key"
        );
        assert!(
            grace.get(&next.hash(), &[1; 32], NOW).is_none(),
            "not a key"
        );
        assert!(grace.get(&old, &[1; 32], at(GRACE_SECS + 1)).is_none());
        assert!(grace.is_empty(), "gone once its time is out");
    }

    #[test]
    fn a_new_successor_of_a_key_takes_the_place_of_the_last() {
        let grace = RefreshGrace::new(1);
        let (a, b, c) = (token(b"a"), token(b"b"), token(b"c"));
        grace.put(&a.hash(), &b, [1; 32], NOW).expect("room");
        // B is used now: the entry of A goes, so a store of one has room.
        grace.put(&b.hash(), &c, [1; 32], at(1)).expect("room");
        assert_eq!(grace.len(), 1);
        assert!(grace.get(&a.hash(), &[1; 32], at(1)).is_none());
        assert_eq!(
            grace.get(&b.hash(), &[1; 32], at(1)).expect("held").hash(),
            c.hash()
        );
        // Another key finds the store full, and nothing changes.
        let d = token(b"d");
        assert_eq!(
            grace.put(&d.hash(), &a, [2; 32], at(1)),
            Err(DpopError::Full)
        );
        assert_eq!(grace.len(), 1);
        assert!(grace.get(&b.hash(), &[1; 32], at(1)).is_some());
        // Once its time is out there is room again.
        grace
            .put(&d.hash(), &a, [2; 32], at(GRACE_SECS + 2))
            .expect("room");
        assert_eq!(grace.len(), 1);
    }

    #[test]
    fn the_grace_store_prints_no_successor() {
        let grace = RefreshGrace::new(2);
        let next = token(b"next");
        grace
            .put(&token(b"old").hash(), &next, [7; 32], NOW)
            .expect("room");
        let shown = format!("{grace:?}");
        assert!(!shown.contains(&next.to_wire()), "{shown}");
        assert!(shown.contains("len: 1"), "{shown}");
    }
}
