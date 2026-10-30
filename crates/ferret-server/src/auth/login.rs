//! Sign-in and sign-out: `POST /api/auth/opaque/login/{start,finish}` (vault
//! listener only), `POST /api/auth/logout` and `GET /api/auth/session` (both
//! listeners). Spec: Fase 1 § 4.2.
//!
//! # Sign-in
//!
//! `login/start` and `login/finish` are thin: the OPAQUE steps, the single use
//! and the binding of the sealed state, and the order of the throttle are
//! `ferret-server-auth`'s `login_start` and `login_finish`. This module adds
//! the HTTP and the database around them:
//!
//! * Both steps are refused with `insecure_transport` before any other work
//!   when the vault URL is `https` and the request did not arrive over HTTPS
//!   through a trusted proxy.
//! * A clock that failed (`u64::MAX`) refuses both steps.
//! * Every call into the library runs in `spawn_blocking`, because the login
//!   state store is SQLite and its calls block. Every other database call goes
//!   through the pool, which runs on blocking threads too.
//! * A name without an account and a disabled user are `Unknown` and
//!   `Disabled` for the library, which answers both from the made-up record:
//!   same status, same body shape, same effects.
//! * For a re-authentication the account is the one of the session that asks,
//!   never one named in the request body.
//! * `login/finish` names its purpose (`login`, the default, or `reauth`), like
//!   `login/start`. The state is taken and opened once against that purpose; the
//!   purpose sealed inside the state stays the authority, so a state made for
//!   the other purpose, or for another session, is refused (`denied`). A
//!   `reauth` finish needs a live vault session and is bound to it.
//! * A body that does not parse or has the wrong length is refused (400) before
//!   the throttle is asked. Those checks depend on the client's bytes alone and
//!   cost no database access, so they say nothing about any account and are not
//!   worth a throttle entry.
//! * The kit's own second factor is not asked for on the vault origin yet. A
//!   user for whom it is on gets no session after a good proof (403
//!   `forbidden`) instead of a session that skips it.
//!
//! After a proof the account is read again. A user who was disabled during the
//! sixty seconds between the steps gets nothing.
//!
//! # Sessions
//!
//! An ordinary sign-in makes a new session row and its two cookies in one
//! transaction that also ends the vault session the browser presented, whoever
//! it belongs to: its cookies are replaced, so the row would be left behind.
//! Only that one: other devices stay signed in. A re-authentication keeps the
//! session and sets the kit's re-auth grant.
//!
//! Sign-out ends the row named by the presented session cookie and clears the
//! cookies; it answers 204 whether or not there was a valid session.
//!
//! The rows of ended or expired sessions are deleted by [`purge_sessions`] once
//! they are a day past anything that could still read them.

use std::net::SocketAddr;
use std::sync::{Arc, OnceLock, PoisonError, RwLock};
use std::time::Duration;

use axum::Json;
use axum::Router;
use axum::body::Body;
use axum::extract::{ConnectInfo, FromRef, FromRequestParts, Request, State};
use axum::http::header::{CACHE_CONTROL, HeaderValue};
use axum::http::request::Parts;
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum_extra::extract::cookie::SignedCookieJar;
use ferret_core::{KsfProfile, OsRng};
use ferret_server_auth::{
    AccountLookup, AuthContext, AuthError, Caller, Clock, CredentialId, DenyReason,
    LoginFinishRequest, LoginPurpose, LoginStartRequest, LoginVerified, NormalizedLoginName,
    PreloginPolicy, ProfileRules, SessionBinding, SessionScope, StoredRecord, ValidatedRecord,
    login_finish, login_start, normalize_login_name,
};
use rusqlite::{Connection, OptionalExtension as _, params};
use serde::de::DeserializeOwned;
use sha2::{Digest as _, Sha256};
use vole_kit::auth::reauth;
use vole_kit::db::users;

use crate::auth::session::{
    ADMIN_ABSOLUTE_SECS, ADMIN_IDLE_SECS, Origin, VAULT_ABSOLUTE_SECS, VAULT_IDLE_SECS,
    clear_cookies, insert_session, lookup, new_session, revoke, session_cookies,
};
use crate::auth::throttle::caller_from;
use crate::error::{ApiError, StoreError};
use crate::http::extract::{AdminSession, VaultSession};
use crate::http::proxy_guard::request_is_https;
use crate::ids::{AccountId, DeviceId, SessionSecret, SidHash, VaultId};
use crate::product;
use crate::state::{FerretState, VaultDb};
use crate::wire::{
    LoginFinishReq, LoginFinishRes, LoginPurposeJson, LoginStartReq, LoginStartRes, OriginJson,
    SessionRes, hex16, refusal_code,
};

/// The most a sign-in request may carry. The largest is a few hundred bytes.
const MAX_BODY_BYTES: usize = 16 * 1024;

/// The device name when the browser gives none.
const DEFAULT_DEVICE_NAME: &str = "Unnamed device";

/// How often the pre-login policy is renewed and old session rows are removed.
const REFRESH_EVERY: Duration = Duration::from_secs(10 * 60);

/// How long a session row is kept after it can no longer be used, in seconds.
pub const PURGE_MARGIN_SECS: i64 = 24 * 60 * 60;

/// The routes of the vault listener: both OPAQUE steps, sign-out and the
/// session info.
pub fn routes<S>() -> Router<S>
where
    S: Clone + Send + Sync + 'static,
    FerretState: FromRef<S>,
{
    Router::new()
        .route("/api/auth/opaque/login/start", post(login_start_route))
        .route("/api/auth/opaque/login/finish", post(login_finish_route))
        .route("/api/auth/logout", post(logout_vault))
        .route("/api/auth/session", get(session_vault))
}

/// The routes of the admin listener: sign-out and the session info.
pub fn admin_routes<S>() -> Router<S>
where
    S: Clone + Send + Sync + 'static,
    FerretState: FromRef<S>,
{
    Router::new()
        .route("/api/auth/logout", post(logout_admin))
        .route("/api/auth/session", get(session_admin))
}

// ------------------------------------------------------------- the lookup

/// What the database says about a login name, owned, so it can cross into the
/// blocking thread.
pub enum AccountLookupOwned {
    /// A user with an account that may sign in.
    Active {
        /// The credential id of the account (its account id).
        credential: CredentialId,
        /// The OPAQUE record and its key stretching profile.
        record: StoredRecord,
        /// Whether the account has a secret key.
        sk_hint: bool,
    },
    /// A user with an account that may not sign in (`users.active = 0`).
    Disabled,
    /// No user with an account has this name.
    Unknown,
}

impl std::fmt::Debug for AccountLookupOwned {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Which variant it is would say whether the name exists.
        f.write_str("AccountLookupOwned([redacted])")
    }
}

const LOOKUP_SELECT: &str =
    "SELECT a.account_id, a.opaque_record, a.ksf_profile, a.sk_hint, u.active
     FROM users u JOIN ferret_accounts a ON a.user_id = u.id";

/// Looks a normalized login name up: the kit user of that name that has a vault
/// account. A kit user without an account (an administrator who never made a
/// vault) is `Unknown`, like a name nobody has.
pub fn lookup_account(
    conn: &Connection,
    name: &NormalizedLoginName,
) -> rusqlite::Result<AccountLookupOwned> {
    let row = conn
        .query_row(
            &format!("{LOOKUP_SELECT} WHERE u.username = ?1"),
            params![name.as_str()],
            read_lookup_row,
        )
        .optional()?;
    row.map_or(Ok(AccountLookupOwned::Unknown), finish_lookup)
}

/// Like [`lookup_account`], for the user of a session.
fn lookup_account_of_user(conn: &Connection, user_id: i64) -> rusqlite::Result<AccountLookupOwned> {
    let row = conn
        .query_row(
            &format!("{LOOKUP_SELECT} WHERE u.id = ?1"),
            params![user_id],
            read_lookup_row,
        )
        .optional()?;
    row.map_or(Ok(AccountLookupOwned::Unknown), finish_lookup)
}

type LookupRow = (Vec<u8>, Vec<u8>, i64, i64, bool);

fn read_lookup_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<LookupRow> {
    Ok((
        row.get(0)?,
        row.get(1)?,
        row.get(2)?,
        row.get(3)?,
        row.get(4)?,
    ))
}

fn bad_row(index: usize, what: &str) -> rusqlite::Error {
    rusqlite::Error::FromSqlConversionFailure(
        index,
        rusqlite::types::Type::Blob,
        what.to_string().into(),
    )
}

fn finish_lookup(row: LookupRow) -> rusqlite::Result<AccountLookupOwned> {
    let (account, record, profile, hint, active) = row;
    if !active {
        return Ok(AccountLookupOwned::Disabled);
    }
    let account = <[u8; 16]>::try_from(account).map_err(|_| bad_row(0, "account id"))?;
    let record = ValidatedRecord::parse(&record).map_err(|_| bad_row(1, "OPAQUE record"))?;
    let ksf_profile = u8::try_from(profile).map_err(|_| bad_row(2, "profile"))?;
    Ok(AccountLookupOwned::Active {
        credential: CredentialId::from_bytes(account),
        record: StoredRecord {
            record,
            ksf_profile,
        },
        sk_hint: hint != 0,
    })
}

// ------------------------------------------------------ the pre-login policy

/// How the made-up answers of unknown names are spread, from the real accounts:
/// the share of each key stretching profile and the share of accounts with a
/// second factor. The shares are kept in buckets of 100 permille that change
/// only when the real share is more than 50 permille past a bucket's edge, and
/// the current buckets are stored in the database, so a restart keeps them. With
/// no accounts: profile 1 for every answer.
///
/// What this does not hide, kept here so nobody mistakes it for covered:
///
/// * A bucket of 0 or 1000 is used only when the real count is exactly none or
///   all (a minority answer at an extreme would prove that the name exists),
///   and a profile with any account is never below 100. The nearest bucket
///   below 1000 is 900, so with one account in a hundred that differs, about a
///   tenth of the unknown names answer the minority way too: a minority answer
///   is weak evidence that a name exists, never proof.
/// * When the real share leaves a bucket's band the bucket moves once, and the
///   unknown names whose draw falls between the two buckets flip once. A name
///   that flips was not held by anyone, but a watcher who sees the flip learns
///   that the population changed, not which names exist.
/// * With very few accounts every bucket crossing is a large step (one account
///   is a share of 500 or more), so tiny populations leak more than large ones.
/// * A profile whose last account goes disappears from the policy at once and
///   its bucket is dropped without hysteresis. That is deliberate: a held
///   bucket for a profile nobody uses would make every answer of that profile
///   prove that the name does not exist.
pub fn load_prelogin_policy(conn: &Connection) -> PreloginPolicy {
    match try_load_prelogin_policy(conn) {
        Ok(policy) => policy,
        Err(error) => {
            tracing::warn!(%error, "could not read the accounts for the pre-login policy");
            PreloginPolicy::single(KsfProfile::P1)
        }
    }
}

/// The width of a share bucket, in permille.
const BUCKET_STEP: u64 = 100;
/// A stored bucket is kept while the real share is within this distance of
/// it: a bucket reaches 50 permille to each side, so the real share must be
/// more than 50 past an edge before the bucket changes.
const BUCKET_HOLD: u64 = 100;
/// The smallest bucket of a profile that has an account.
const FLOOR: u16 = 100;
/// The `ferret_meta` key that holds the current buckets.
const BUCKETS_KEY: &str = "prelogin_buckets";

/// The buckets the pre-login policy is built from, as they are kept in the
/// database: the bucket of the second-factor hint and one per profile.
#[derive(Default)]
struct Buckets {
    sk: Option<u16>,
    profiles: Vec<(u8, u16)>,
}

impl Buckets {
    fn encode(&self) -> Vec<u8> {
        let mut text = String::new();
        if let Some(sk) = self.sk {
            text.push_str(&format!("sk={sk};"));
        }
        for (profile, bucket) in &self.profiles {
            text.push_str(&format!("p{profile}={bucket};"));
        }
        text.into_bytes()
    }

    /// Reads what `encode` wrote. Anything that does not parse is left out, so
    /// a damaged value only means the bucket is chosen again.
    fn decode(bytes: &[u8]) -> Self {
        let mut buckets = Buckets::default();
        let Ok(text) = std::str::from_utf8(bytes) else {
            return buckets;
        };
        for item in text.split(';') {
            let Some((name, value)) = item.split_once('=') else {
                continue;
            };
            let Some(bucket) = value.parse::<u16>().ok().filter(|b| is_bucket(*b)) else {
                continue;
            };
            if name == "sk" {
                buckets.sk = Some(bucket);
            } else if let Some(profile) = name.strip_prefix('p').and_then(|p| p.parse::<u8>().ok())
            {
                buckets.profiles.push((profile, bucket));
            }
        }
        buckets
    }

    fn profile(&self, profile: u8) -> Option<u16> {
        self.profiles
            .iter()
            .find(|(p, _)| *p == profile)
            .map(|(_, b)| *b)
    }
}

/// Whether `value` is a bucket: a multiple of 100 from 0 to 1000.
fn is_bucket(value: u16) -> bool {
    value <= 1000 && value.checked_rem(100) == Some(0)
}

/// The bucket for a real share: the stored one while the share stays within
/// [`BUCKET_HOLD`] of it, else the multiple of 100 nearest to the share
/// (halves round up). The result still goes through [`pin_extremes`], which
/// knows the exact counts.
///
/// What remains visible: a bucket crossing flips the made-up answer once for
/// the unknown names whose draw lies between the old and the new bucket, and a
/// small population moves in large steps. See `load_prelogin_policy`.
fn settle(stored: Option<u16>, share: u64) -> u16 {
    if let Some(bucket) = stored
        && is_bucket(bucket)
        && share.abs_diff(u64::from(bucket)) <= BUCKET_HOLD
    {
        return bucket;
    }
    let nearest = share
        .checked_add(BUCKET_STEP / 2)
        .and_then(|s| s.checked_div(BUCKET_STEP))
        .and_then(|s| s.checked_mul(BUCKET_STEP))
        .unwrap_or(1000)
        .min(1000);
    u16::try_from(nearest).unwrap_or(1000)
}

/// Keeps the extremes honest, from the exact counts and not from the rounded
/// share: 0 only when none of the accounts has the property, 1000 only when all
/// of them have it, and 100 to 900 otherwise. A minority answer at an extreme
/// would be proof that a name exists, and a profile that has an account must
/// never be left with no share at all.
fn pin_extremes(bucket: u16, part: u64, total: u64) -> u16 {
    if part == 0 {
        0
    } else if part >= total {
        1000
    } else {
        bucket.clamp(100, 900)
    }
}

/// The buckets for the accounts as they are now: `with_hint` of `total`
/// accounts have a secret key, `counts` are the accounts per profile. A profile
/// that has no account is not in `counts`, so its stored bucket is dropped
/// without hysteresis, on purpose: it is the safe direction.
fn next_buckets(
    stored: &Buckets,
    counts: &[(u8, u64)],
    with_hint: u64,
    total: u64,
) -> Option<Buckets> {
    let share_of = |part: u64| share_permille(part.min(total), total);
    let sk = pin_extremes(settle(stored.sk, share_of(with_hint)?), with_hint, total);
    let mut profiles = Vec::with_capacity(counts.len());
    for (profile, count) in counts {
        let bucket = settle(stored.profile(*profile), share_of(*count)?);
        profiles.push((*profile, pin_extremes(bucket, *count, total)));
    }
    Some(Buckets {
        sk: Some(sk),
        profiles,
    })
}

/// Makes the profile buckets add up to exactly 1000, as the policy needs: a
/// missing amount goes to the largest bucket, an excess comes off the largest
/// ones first (ties: the lower profile number), never taking a bucket below 100
/// (a profile with an account keeps a share). `None` when that is not possible.
fn fit_to_whole(buckets: &[(u8, u16)]) -> Option<Vec<(u8, u16)>> {
    let mut out = buckets.to_vec();
    let sum = out
        .iter()
        .try_fold(0u32, |sum, (_, bucket)| sum.checked_add(u32::from(*bucket)))?;
    let mut order: Vec<usize> = (0..out.len()).collect();
    order.sort_by(|a, b| match (out.get(*a), out.get(*b)) {
        (Some(a), Some(b)) => b.1.cmp(&a.1).then(a.0.cmp(&b.0)),
        _ => std::cmp::Ordering::Equal,
    });
    if sum < 1000 {
        let first = out.get_mut(*order.first()?)?;
        let missing = u16::try_from(1000u32.checked_sub(sum)?).ok()?;
        first.1 = first.1.checked_add(missing)?;
    } else {
        let mut excess = sum.checked_sub(1000)?;
        for index in order {
            if excess == 0 {
                break;
            }
            let entry = out.get_mut(index)?;
            let spare = u32::from(entry.1.saturating_sub(FLOOR));
            let take = excess.min(spare);
            entry.1 = entry.1.checked_sub(u16::try_from(take).ok()?)?;
            excess = excess.checked_sub(take)?;
        }
        if excess != 0 {
            return None;
        }
    }
    Some(out)
}

fn read_buckets(conn: &Connection) -> rusqlite::Result<Buckets> {
    let stored: Option<Vec<u8>> = conn
        .query_row(
            "SELECT value FROM ferret_meta WHERE key = ?1",
            params![BUCKETS_KEY],
            |r| r.get(0),
        )
        .optional()?;
    Ok(stored.map_or_else(Buckets::default, |bytes| Buckets::decode(&bytes)))
}

fn try_load_prelogin_policy(conn: &Connection) -> Result<PreloginPolicy, String> {
    let mut statement = conn
        .prepare(
            "SELECT a.ksf_profile, COUNT(*), COALESCE(SUM(a.sk_hint), 0)
             FROM ferret_accounts a JOIN users u ON u.id = a.user_id
             WHERE u.active = 1 GROUP BY a.ksf_profile ORDER BY a.ksf_profile",
        )
        .map_err(|e| e.to_string())?;
    let rows = statement
        .query_map([], |r| {
            Ok((
                r.get::<_, i64>(0)?,
                r.get::<_, i64>(1)?,
                r.get::<_, i64>(2)?,
            ))
        })
        .map_err(|e| e.to_string())?;
    let mut counts: Vec<(u8, u64)> = Vec::new();
    let mut with_hint: u64 = 0;
    for row in rows {
        let (profile, count, hints) = row.map_err(|e| e.to_string())?;
        let profile = u8::try_from(profile).map_err(|_| "a profile out of range".to_string())?;
        let count = u64::try_from(count).map_err(|_| "a negative count".to_string())?;
        let hints = u64::try_from(hints).map_err(|_| "a negative count".to_string())?;
        counts.push((profile, count));
        with_hint = with_hint.saturating_add(hints);
    }
    drop(statement);
    let total: u64 = counts.iter().map(|(_, c)| *c).fold(0, u64::saturating_add);
    if total == 0 {
        return Ok(PreloginPolicy::single(KsfProfile::P1));
    }

    // The shares are coarse and sticky: a made-up answer must not change when
    // the real accounts move a little, or the names whose answer changed would
    // be the ones nobody holds.
    let stored = read_buckets(conn).map_err(|e| e.to_string())?;
    let fresh = next_buckets(&stored, &counts, with_hint, total).ok_or("a share overflows")?;
    if fresh.encode() != stored.encode() {
        // Best effort: a write that fails (a busy or full database) must not
        // change the answers. The policy built here is used either way, and the
        // next round tries to store it again.
        if let Err(error) = conn.execute(
            "INSERT OR REPLACE INTO ferret_meta (key, value) VALUES (?1, ?2)",
            params![BUCKETS_KEY, fresh.encode()],
        ) {
            tracing::warn!(%error, "the pre-login buckets were not stored");
        }
    }
    let sk = fresh.sk.ok_or("no hint bucket")?;
    let shares = fit_to_whole(&fresh.profiles).ok_or("the shares do not add up")?;
    PreloginPolicy::new(&shares, sk).map_err(|e| format!("{e:?}"))
}

/// `part / total` in permille, rounded to the nearest.
fn share_permille(part: u64, total: u64) -> Option<u64> {
    let scaled = part.checked_mul(1000)?.checked_add(total / 2)?;
    scaled.checked_div(total)
}

/// Renews the policy in `policy` from the database every ten minutes, and
/// removes the rows of old sessions at the same pace. Call it once, inside the
/// runtime.
pub fn spawn_prelogin_refresh(
    db: VaultDb,
    policy: Arc<RwLock<PreloginPolicy>>,
    clock: Arc<dyn Clock>,
) {
    spawn_refresh_every(db, policy, clock, REFRESH_EVERY);
}

/// [`spawn_prelogin_refresh`] with another period, for tests.
pub fn spawn_refresh_every(
    db: VaultDb,
    policy: Arc<RwLock<PreloginPolicy>>,
    clock: Arc<dyn Clock>,
    period: Duration,
) {
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(period);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        // The first tick is immediate: the policy was just loaded at start-up.
        ticker.tick().await;
        loop {
            ticker.tick().await;
            refresh_once(&db, &policy, clock.as_ref()).await;
        }
    });
}

/// One round of the background work. A failure keeps the policy as it was.
pub async fn refresh_once(db: &VaultDb, policy: &RwLock<PreloginPolicy>, clock: &dyn Clock) {
    match db
        .with_conn(|conn| Ok(try_load_prelogin_policy(conn)))
        .await
    {
        Ok(Ok(fresh)) => {
            *policy.write().unwrap_or_else(PoisonError::into_inner) = fresh;
        }
        Ok(Err(error)) => tracing::warn!(%error, "the pre-login policy was not renewed"),
        Err(error) => tracing::warn!(%error, "the pre-login policy was not renewed"),
    }
    let Ok(now) = i64::try_from(clock.now_unix()) else {
        return;
    };
    match db
        .with_conn(move |conn| Ok(purge_sessions(conn, now)?))
        .await
    {
        Ok(0) => {}
        Ok(removed) => tracing::debug!(removed, "old session rows removed"),
        Err(error) => tracing::warn!(%error, "old session rows were not removed"),
    }
}

/// Deletes the session rows that can no longer be used and are a day older than
/// that: ended rows, rows idle longer than their origin allows and rows older
/// than the absolute limit. Returns how many it removed.
pub fn purge_sessions(conn: &Connection, now: i64) -> rusqlite::Result<usize> {
    let before = |secs: i64| now.saturating_sub(secs).saturating_sub(PURGE_MARGIN_SECS);
    conn.execute(
        "DELETE FROM ferret_sessions WHERE
            (revoked_at IS NOT NULL AND revoked_at < ?1)
         OR (origin = 'vault' AND (last_seen < ?2 OR issued_at < ?3))
         OR (origin = 'admin' AND (last_seen < ?4 OR issued_at < ?5))",
        params![
            now.saturating_sub(PURGE_MARGIN_SECS),
            before(VAULT_IDLE_SECS),
            before(VAULT_ABSOLUTE_SECS),
            before(ADMIN_IDLE_SECS),
            before(ADMIN_ABSOLUTE_SECS),
        ],
    )
}

// ------------------------------------------------------------- shared pieces

fn profiles() -> &'static ProfileRules {
    static RULES: OnceLock<ProfileRules> = OnceLock::new();
    RULES.get_or_init(ProfileRules::ferret_v1)
}

/// `insecure_transport` when the vault URL is `https` and this request did not
/// come over HTTPS through a trusted proxy.
fn require_transport(
    state: &FerretState,
    headers: &HeaderMap,
    peer: SocketAddr,
) -> Result<(), ApiError> {
    if state.origins.vault_is_https() && !request_is_https(headers, peer.ip(), &state.proxies, true)
    {
        return Err(ApiError::coded("insecure_transport"));
    }
    Ok(())
}

/// The time, or a refusal when the clock failed.
fn clock_now(state: &FerretState) -> Result<u64, ApiError> {
    let now = state.clock.now_unix();
    if now == u64::MAX {
        tracing::error!("the clock failed; sign-in is refused");
        return Err(ApiError::internal());
    }
    Ok(now)
}

fn to_i64(now: u64) -> Result<i64, ApiError> {
    i64::try_from(now).map_err(|_| ApiError::internal())
}

/// Reads a JSON body of at most [`MAX_BODY_BYTES`]. A refusal carries the code
/// of the field that failed (`malformed_ke1`, ...) and nothing of the input.
async fn read_json<T: DeserializeOwned>(body: Body) -> Result<T, ApiError> {
    let bytes = axum::body::to_bytes(body, MAX_BODY_BYTES)
        .await
        .map_err(|_| ApiError::coded("too_large"))?;
    serde_json::from_slice(&bytes)
        .map_err(|error| ApiError::coded(refusal_code(&error.to_string())))
}

fn no_store(mut response: Response) -> Response {
    response
        .headers_mut()
        .insert(CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
}

fn auth_refusal(error: AuthError) -> ApiError {
    // The reason is for this log only; the answer carries the public code.
    tracing::info!(reason = ?error, "sign-in step refused");
    ApiError::from(error)
}

/// What the library binds a re-authentication to: a domain-separated hash of
/// the session's id hash. It cannot be turned back into the session id.
fn session_binding(sid: &SidHash) -> SessionBinding {
    let mut hasher = Sha256::new();
    hasher.update(b"ferret/v1/session-binding");
    hasher.update(sid.0);
    let digest = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    SessionBinding(out)
}

fn read_policy(state: &FerretState) -> PreloginPolicy {
    state
        .prelogin
        .read()
        .unwrap_or_else(PoisonError::into_inner)
        .clone()
}

fn context<'a>(
    state: &'a FerretState,
    policy: &'a PreloginPolicy,
    rules: &'a ProfileRules,
) -> AuthContext<'a> {
    AuthContext::new(
        &state.secrets.keys,
        &state.secrets.prelogin,
        &state.secrets.seal,
        state.clock.as_ref(),
        state.throttle.as_ref(),
        policy,
        rules,
    )
}

// ------------------------------------------------------------- login/start

async fn login_start_route(
    State(state): State<FerretState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    request: Request,
) -> Result<Response, ApiError> {
    let (mut parts, body) = request.into_parts();
    require_transport(&state, &parts.headers, peer)?;
    clock_now(&state)?;
    let req: LoginStartReq = read_json(body).await?;
    let name = normalize_login_name(&req.email).map_err(auth_refusal)?;
    let caller = caller_from(&parts.headers, Some(peer));

    let (purpose, found, scope) = match req.purpose.unwrap_or(LoginPurposeJson::Login) {
        LoginPurposeJson::Login => {
            let by_name = name.clone();
            let found = state
                .vault_db
                .with_conn(move |conn| Ok(lookup_account(conn, &by_name)?))
                .await?;
            (LoginPurpose::Login, found, None)
        }
        LoginPurposeJson::Reauth => {
            // The extractor refuses with the one 401 for every reason a session
            // does not count, a missing one included. The account is the
            // session's own; the name in the request only has to be well formed.
            let session = VaultSession::from_request_parts(&mut parts, &state).await?;
            let user_id = session.user_id;
            let found = state
                .vault_db
                .with_conn(move |conn| Ok(lookup_account_of_user(conn, user_id)?))
                .await?;
            let purpose = LoginPurpose::Reauth {
                session: session_binding(&session.sid),
                account: CredentialId::from(&session.account),
            };
            (purpose, found, Some(SessionScope::Full))
        }
    };

    let ke1 = req.ke1;
    let worker = state.clone();
    let answer = tokio::task::spawn_blocking(move || {
        let policy = read_policy(&worker);
        let cx = context(&worker, &policy, profiles());
        let (credential, lookup) = match &found {
            AccountLookupOwned::Active {
                credential,
                record,
                sk_hint,
            } => (
                *credential,
                AccountLookup::Active {
                    record,
                    sk_hint: *sk_hint,
                },
            ),
            AccountLookupOwned::Disabled => {
                (CredentialId::from_bytes([0; 16]), AccountLookup::Disabled)
            }
            AccountLookupOwned::Unknown => {
                (CredentialId::from_bytes([0; 16]), AccountLookup::Unknown)
            }
        };
        login_start(
            &cx,
            worker.login_states.as_ref(),
            &mut OsRng,
            &LoginStartRequest {
                caller,
                name: &name,
                credential,
                lookup,
                purpose,
                session_scope: scope,
                ke1: &ke1,
            },
        )
    })
    .await
    .map_err(|_| ApiError::internal())?
    .map_err(auth_refusal)?;

    let login_id = hex16::decode(&answer.login_id.to_hex()).map_err(|_| ApiError::internal())?;
    Ok(no_store(
        Json(LoginStartRes {
            login_id,
            ke2: answer.ke2,
            ksf_profile: answer.ksf_profile,
            sk_hint: answer.sk_hint,
        })
        .into_response(),
    ))
}

// ------------------------------------------------------------ login/finish

/// The session id hash in the request's session cookie, if the cookie is one
/// this server signed. Nothing is read from the database.
fn presented_sid(jar: &SignedCookieJar) -> Option<SidHash> {
    jar.get(product::SID_COOKIE)
        .and_then(|c| SessionSecret::from_cookie(c.value()).ok())
        .map(|secret| secret.hash())
}

/// The library's `login_finish`: it takes and opens the sealed state once,
/// against the purpose the request names, and asks the throttle with the
/// account of the state before any OPAQUE work.
fn finish_blocking(
    state: &FerretState,
    caller: Caller,
    login_id: &str,
    ke3: &[u8],
    current_session: Option<(SessionBinding, CredentialId)>,
) -> Result<LoginVerified, AuthError> {
    let policy = read_policy(state);
    let cx = context(state, &policy, profiles());
    login_finish(
        &cx,
        state.login_states.as_ref(),
        &LoginFinishRequest {
            caller,
            login_id: login_id.as_bytes(),
            ke3,
            current_session,
        },
    )
}

/// What a finished ordinary sign-in leaves behind.
struct SignedIn {
    secret: SessionSecret,
    claims: vole_kit::auth::session::SessionClaims,
    account: AccountId,
    vault: VaultId,
    vk_epoch: u64,
}

/// How the database side of an ordinary sign-in ended.
enum Opened {
    /// A new session.
    Session(SignedIn),
    /// The user is gone or was disabled since the first step.
    Refused,
    /// The kit's second factor is on for the user and this server cannot ask
    /// for it yet.
    SecondFactor,
}

async fn login_finish_route(
    State(state): State<FerretState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    request: Request,
) -> Result<Response, ApiError> {
    let (mut parts, body) = request.into_parts();
    require_transport(&state, &parts.headers, peer)?;
    let now = clock_now(&state)?;
    let req: LoginFinishReq = read_json(body).await?;
    let caller = caller_from(&parts.headers, Some(peer));
    let jar = SignedCookieJar::from_headers(&parts.headers, state.core.session_key.clone());

    // The request says what it is for; the purpose sealed in the state stays
    // the authority, and a state made for the other purpose is refused.
    let (current_session, reauth_session) = match req.purpose.unwrap_or(LoginPurposeJson::Login) {
        LoginPurposeJson::Login => (None, None),
        LoginPurposeJson::Reauth => {
            let session = VaultSession::from_request_parts(&mut parts, &state).await?;
            let bound = (
                session_binding(&session.sid),
                CredentialId::from(&session.account),
            );
            (Some(bound), Some(session))
        }
    };

    let login_id = hex16::encode(&req.login_id);
    let ke3 = req.ke3;
    let device = DeviceId(req.device_id);
    let device_name = req
        .device_name
        .filter(|n| !n.is_empty())
        .unwrap_or_else(|| DEFAULT_DEVICE_NAME.to_string());
    let presented = presented_sid(&jar);

    let worker = state.clone();
    let verified = tokio::task::spawn_blocking(move || {
        finish_blocking(&worker, caller, &login_id, &ke3, current_session)
    })
    .await
    .map_err(|_| ApiError::internal())?
    .map_err(auth_refusal)?;

    let secure = state.origins.vault_is_https();
    match verified.purpose {
        LoginPurpose::Reauth { .. } => {
            let session = reauth_session.ok_or_else(ApiError::internal)?;
            let jar = reauth::grant(jar, &state.core.session_key, secure);
            Ok(no_store(
                (
                    jar,
                    Json(LoginFinishRes {
                        account_id: *session.account.as_bytes(),
                        vault_id: *session.vault.as_bytes(),
                        vk_epoch: session.vk_epoch,
                    }),
                )
                    .into_response(),
            ))
        }
        LoginPurpose::Login => {
            let account_bytes = *verified.credential.as_bytes();
            let now = to_i64(now)?;
            let opened = state
                .vault_db
                .with_conn(move |conn| {
                    open_session(conn, account_bytes, now, device, &device_name, presented)
                })
                .await?;
            let signed_in = match opened {
                Opened::Session(signed_in) => signed_in,
                Opened::Refused => {
                    return Err(auth_refusal(AuthError::Denied(DenyReason::StateInvalid)));
                }
                Opened::SecondFactor => {
                    tracing::info!("sign-in refused: the kit's second factor is on");
                    return Err(ApiError::coded("forbidden"));
                }
            };
            let jar = session_cookies(jar, &signed_in.secret, &signed_in.claims, secure);
            Ok(no_store(
                (
                    jar,
                    Json(LoginFinishRes {
                        account_id: *signed_in.account.as_bytes(),
                        vault_id: *signed_in.vault.as_bytes(),
                        vk_epoch: signed_in.vk_epoch,
                    }),
                )
                    .into_response(),
            ))
        }
    }
}

/// The database side of an ordinary sign-in, in one transaction: read the
/// account again (a user disabled since the first step gets `Refused`), refuse
/// a user whose second factor is on, note the sign-in, insert the new session
/// and end the vault session the browser presented, whoever it belongs to.
fn open_session(
    conn: &mut Connection,
    account: [u8; 16],
    now: i64,
    device: DeviceId,
    device_name: &str,
    presented: Option<SidHash>,
) -> Result<Opened, StoreError> {
    let tx = conn.transaction()?;
    let found: Option<(i64, bool, i64, Vec<u8>, i64, bool)> = tx
        .query_row(
            "SELECT u.id, u.active, u.session_version, a.vault_id, a.vk_epoch, u.totp_enabled
             FROM ferret_accounts a JOIN users u ON u.id = a.user_id
             WHERE a.account_id = ?1",
            params![account.as_slice()],
            |r| {
                Ok((
                    r.get(0)?,
                    r.get(1)?,
                    r.get(2)?,
                    r.get(3)?,
                    r.get(4)?,
                    r.get(5)?,
                ))
            },
        )
        .optional()?;
    let Some((user_id, true, version, vault, epoch, totp)) = found else {
        return Ok(Opened::Refused);
    };
    if totp {
        return Ok(Opened::SecondFactor);
    }
    let vault = <[u8; 16]>::try_from(vault).map_err(|_| StoreError::Invalid("vault id"))?;
    let vk_epoch = u64::try_from(epoch).map_err(|_| StoreError::Invalid("vk epoch"))?;

    users::touch_last_login(&tx, user_id)?;
    let (secret, session, claims) = new_session(
        &mut OsRng,
        now,
        user_id,
        version,
        Origin::Vault,
        device,
        device_name,
        SessionScope::Full,
    );
    insert_session(&tx, &session)?;
    // The browser's cookies are replaced by the new ones, so the row they
    // named would be left live and unreachable; it ends here, for any user.
    if let Some(previous) = presented
        && let Some(row) = lookup(&tx, &previous)?
        && row.origin == Origin::Vault
    {
        revoke(&tx, &previous, now)?;
    }
    tx.commit()?;
    Ok(Opened::Session(SignedIn {
        secret,
        claims,
        account: AccountId::from_bytes(account),
        vault: VaultId::from_bytes(vault),
        vk_epoch,
    }))
}

// ------------------------------------------------------------------ logout

/// Ends the session the request names by its session id cookie, if it is a live
/// session of `origin`, and clears the cookies. 204 in every case but a
/// database failure.
async fn logout(
    state: FerretState,
    headers: HeaderMap,
    origin: Origin,
) -> Result<Response, ApiError> {
    let jar = SignedCookieJar::from_headers(&headers, state.core.session_key.clone());
    let sid = jar
        .get(product::SID_COOKIE)
        .and_then(|c| SessionSecret::from_cookie(c.value()).ok())
        .map(|secret| secret.hash());
    if let Some(sid) = sid {
        // A failed clock skips the revoke but never the clearing of cookies.
        match to_i64(state.clock.now_unix()) {
            Ok(now) => {
                state
                    .vault_db
                    .with_conn(move |conn| {
                        if let Some(row) = lookup(conn, &sid)?
                            && row.origin == origin
                        {
                            revoke(conn, &sid, now)?;
                        }
                        Ok(())
                    })
                    .await?;
            }
            Err(_) => tracing::error!("the clock failed; the session row was not ended"),
        }
    }
    Ok(no_store(
        (clear_cookies(jar), StatusCode::NO_CONTENT).into_response(),
    ))
}

async fn logout_vault(
    State(state): State<FerretState>,
    headers: HeaderMap,
) -> Result<Response, ApiError> {
    logout(state, headers, Origin::Vault).await
}

async fn logout_admin(
    State(state): State<FerretState>,
    headers: HeaderMap,
) -> Result<Response, ApiError> {
    logout(state, headers, Origin::Admin).await
}

// ------------------------------------------------------------ session info

async fn user_email(state: &FerretState, user_id: i64) -> Result<String, ApiError> {
    let email = state
        .vault_db
        .with_conn(move |conn| {
            Ok(conn
                .query_row(
                    "SELECT username FROM users WHERE id = ?1",
                    params![user_id],
                    |r| r.get::<_, String>(0),
                )
                .optional()?)
        })
        .await?;
    email.ok_or_else(ApiError::unauthorized)
}

async fn session_vault(
    State(state): State<FerretState>,
    mut parts: Parts,
) -> Result<Response, ApiError> {
    let session = VaultSession::from_request_parts(&mut parts, &state).await?;
    let email = user_email(&state, session.user_id).await?;
    Ok(no_store(
        Json(SessionRes {
            account_id: Some(*session.account.as_bytes()),
            email,
            scope: SessionScope::Full.as_str().to_string(),
            origin: OriginJson::Vault,
        })
        .into_response(),
    ))
}

async fn session_admin(
    State(state): State<FerretState>,
    mut parts: Parts,
) -> Result<Response, ApiError> {
    let session = AdminSession::from_request_parts(&mut parts, &state).await?;
    let user_id = session.user_id;
    let email = user_email(&state, user_id).await?;
    let account = state
        .vault_db
        .with_conn(move |conn| {
            Ok(conn
                .query_row(
                    "SELECT account_id FROM ferret_accounts WHERE user_id = ?1",
                    params![user_id],
                    |r| r.get::<_, Vec<u8>>(0),
                )
                .optional()?)
        })
        .await?
        .and_then(|a| <[u8; 16]>::try_from(a).ok());
    Ok(no_store(
        Json(SessionRes {
            account_id: account,
            email,
            scope: SessionScope::Full.as_str().to_string(),
            origin: OriginJson::Admin,
        })
        .into_response(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_bucket_holds_until_the_share_is_more_than_50_past_its_edge() {
        // Nothing stored: the nearest multiple of 100, halves up.
        assert_eq!(settle(None, 0), 0);
        assert_eq!(settle(None, 49), 0);
        assert_eq!(settle(None, 50), 100);
        assert_eq!(settle(None, 449), 400);
        assert_eq!(settle(None, 1000), 1000);
        // A stored bucket of 500 covers 450..550; it holds up to 100 away.
        for share in [400, 450, 500, 550, 600] {
            assert_eq!(settle(Some(500), share), 500, "{share}");
        }
        assert_eq!(settle(Some(500), 601), 600);
        assert_eq!(settle(Some(500), 650), 700);
        assert_eq!(settle(Some(500), 399), 400);
        assert_eq!(settle(Some(500), 0), 0);
        // A stored value that is not a bucket is ignored.
        assert_eq!(settle(Some(530), 530), 500);
    }

    #[test]
    fn the_extremes_need_an_exact_none_or_all() {
        // 1 of 20 without a key is a share of 950, which rounds to 1000.
        assert_eq!(settle(None, 950), 1000);
        assert_eq!(pin_extremes(1000, 19, 20), 900);
        assert_eq!(pin_extremes(0, 1, 20), 100);
        assert_eq!(pin_extremes(0, 0, 20), 0);
        assert_eq!(pin_extremes(1000, 20, 20), 1000);
        assert_eq!(pin_extremes(500, 10, 20), 500);
        // Even a bucket held from earlier does not keep an extreme alive.
        assert_eq!(pin_extremes(0, 1, 2), 100);
        assert_eq!(pin_extremes(100, 0, 2), 0);
    }

    #[test]
    fn a_profile_with_an_account_keeps_a_share() {
        let stored = Buckets::default();
        let next = next_buckets(&stored, &[(1, 29), (2, 1)], 30, 30).unwrap();
        assert_eq!(next.sk, Some(1000));
        assert_eq!(next.profiles, vec![(1, 900), (2, 100)]);
        let fitted = fit_to_whole(&next.profiles).unwrap();
        assert_eq!(fitted, vec![(1, 900), (2, 100)]);
        // Three profiles, the small ones at their floor: the excess comes off
        // the largest only above the floor.
        let next = next_buckets(&stored, &[(1, 28), (2, 1), (3, 1)], 0, 30).unwrap();
        assert_eq!(next.sk, Some(0));
        assert_eq!(next.profiles, vec![(1, 900), (2, 100), (3, 100)]);
        let fitted = fit_to_whole(&next.profiles).unwrap();
        assert_eq!(fitted, vec![(1, 800), (2, 100), (3, 100)]);
        assert!(fitted.iter().all(|(_, b)| *b >= 100));
        // A dropped profile leaves the buckets at once.
        let stored = Buckets {
            sk: Some(500),
            profiles: vec![(1, 700), (2, 300)],
        };
        let next = next_buckets(&stored, &[(1, 10)], 5, 10).unwrap();
        assert_eq!(next.profiles, vec![(1, 1000)]);
    }

    #[test]
    fn profile_buckets_are_fitted_to_a_thousand() {
        assert_eq!(fit_to_whole(&[(1, 1000)]).unwrap(), vec![(1, 1000)]);
        assert_eq!(
            fit_to_whole(&[(1, 300), (2, 300), (3, 300)]).unwrap(),
            vec![(1, 400), (2, 300), (3, 300)]
        );
        assert_eq!(
            fit_to_whole(&[(1, 600), (2, 600)]).unwrap(),
            vec![(1, 400), (2, 600)]
        );
        assert_eq!(
            fit_to_whole(&[(1, 0), (2, 0)]).unwrap(),
            vec![(1, 1000), (2, 0)]
        );
    }

    #[test]
    fn buckets_round_trip_and_damage_is_ignored() {
        let buckets = Buckets {
            sk: Some(500),
            profiles: vec![(1, 700), (2, 300)],
        };
        let back = Buckets::decode(&buckets.encode());
        assert_eq!(back.sk, Some(500));
        assert_eq!(back.profiles, vec![(1, 700), (2, 300)]);
        let damaged = Buckets::decode(b"sk=530;p1=abc;p2=300;junk;p=1;");
        assert_eq!(damaged.sk, None);
        assert_eq!(damaged.profiles, vec![(2, 300)]);
        assert!(Buckets::decode(&[0xff, 0xfe]).profiles.is_empty());
    }

    #[test]
    fn the_hint_share_rounds_to_the_nearest_permille() {
        assert_eq!(share_permille(1, 3), Some(333));
        assert_eq!(share_permille(2, 3), Some(667));
        assert_eq!(share_permille(0, 5), Some(0));
        assert_eq!(share_permille(5, 5), Some(1000));
    }

    #[test]
    fn debug_of_the_lookup_shows_nothing() {
        let shown = format!("{:?}", AccountLookupOwned::Unknown);
        assert_eq!(shown, format!("{:?}", AccountLookupOwned::Disabled));
    }
}
