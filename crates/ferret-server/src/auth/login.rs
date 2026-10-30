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
//! * `login/finish` does not know from the request whether the sign-in was
//!   started as an ordinary sign-in or as a re-authentication: the request has
//!   no such field, and the purpose is sealed inside the state. When the
//!   request presents a session cookie of this origin, the state is first
//!   opened as a re-authentication of that session and, if the library says
//!   the state is not that, once more as an ordinary sign-in from the same
//!   sealed bytes. The state was taken out of the store once and is never put
//!   back, so it keeps its single use. Only the opening of the state can fail
//!   that way; no OPAQUE work has started when it does.
//!
//! After a proof the account is read again. A user who was disabled during the
//! sixty seconds between the steps gets nothing.
//!
//! # Sessions
//!
//! An ordinary sign-in makes a new session row and its two cookies in one
//! transaction that also ends the session the browser presented, if that one
//! belongs to the same user and origin. Only that one: other devices stay signed
//! in. A re-authentication keeps the session and sets the kit's re-auth grant.
//!
//! Sign-out ends the row named by the presented session cookie and clears the
//! cookies; it answers 204 whether or not there was a valid session.
//!
//! The rows of ended or expired sessions are deleted by [`purge_sessions`] once
//! they are a day past anything that could still read them.

use std::net::SocketAddr;
use std::sync::{Arc, Mutex, OnceLock, PoisonError, RwLock};
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
    LoginFinishRequest, LoginPurpose, LoginStartRequest, LoginStateStore, LoginVerified,
    NormalizedLoginName, PreloginPolicy, ProfileRules, SealedState, SessionBinding, SessionScope,
    StateKey, StoreError as LoginStoreError, StoredRecord, ValidatedRecord, login_finish,
    login_start, normalize_login_name,
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
use crate::auth::state_store::SqliteLoginStateStore;
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
/// second factor, in permille. With no accounts: profile 1 for every answer.
pub fn load_prelogin_policy(conn: &Connection) -> PreloginPolicy {
    match try_load_prelogin_policy(conn) {
        Ok(policy) => policy,
        Err(error) => {
            tracing::warn!(%error, "could not read the accounts for the pre-login policy");
            PreloginPolicy::single(KsfProfile::P1)
        }
    }
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
    let total: u64 = counts.iter().map(|(_, c)| *c).fold(0, u64::saturating_add);
    if total == 0 {
        return Ok(PreloginPolicy::single(KsfProfile::P1));
    }
    let shares = permille_shares(&counts, total).ok_or("the shares do not add up")?;
    let hint_permille = share_permille(with_hint.min(total), total)
        .and_then(|p| u16::try_from(p).ok())
        .ok_or("the hint share does not fit")?;
    PreloginPolicy::new(&shares, hint_permille).map_err(|e| format!("{e:?}"))
}

/// `part / total` in permille, rounded to the nearest.
fn share_permille(part: u64, total: u64) -> Option<u64> {
    let scaled = part.checked_mul(1000)?.checked_add(total / 2)?;
    scaled.checked_div(total)
}

/// Shares in permille that add up to exactly 1000: each profile gets the floor
/// of its share, and the rest goes one by one to the largest remainders (ties:
/// the lower profile number).
fn permille_shares(counts: &[(u8, u64)], total: u64) -> Option<Vec<(u8, u16)>> {
    let mut shares: Vec<(u8, u64, u64)> = Vec::with_capacity(counts.len());
    for (profile, count) in counts {
        let scaled = count.checked_mul(1000)?;
        shares.push((
            *profile,
            scaled.checked_div(total)?,
            scaled.checked_rem(total)?,
        ));
    }
    let given = shares
        .iter()
        .try_fold(0u64, |sum, (_, share, _)| sum.checked_add(*share))?;
    let mut left = 1000u64.checked_sub(given)?;
    let mut order: Vec<usize> = (0..shares.len()).collect();
    order.sort_by(|a, b| match (shares.get(*a), shares.get(*b)) {
        (Some(a), Some(b)) => b.2.cmp(&a.2).then(a.0.cmp(&b.0)),
        _ => std::cmp::Ordering::Equal,
    });
    for index in order {
        if left == 0 {
            break;
        }
        if let Some(share) = shares.get_mut(index) {
            share.1 = share.1.checked_add(1)?;
            left = left.checked_sub(1)?;
        }
    }
    shares
        .into_iter()
        .map(|(profile, share, _)| Some((profile, u16::try_from(share).ok()?)))
        .collect()
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
        return Err(ApiError::bad_request("insecure_transport"));
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
        .map_err(|_| ApiError::new(StatusCode::PAYLOAD_TOO_LARGE, "too_large"))?;
    serde_json::from_slice(&bytes)
        .map_err(|error| ApiError::bad_request(refusal_code(&error.to_string())))
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

/// A store that forwards to the real one and keeps a copy of the sealed state
/// it hands out, so the state can be opened a second time with another
/// expectation. It is never put back anywhere.
struct TeeStore<'a> {
    inner: &'a SqliteLoginStateStore,
    seen: Mutex<Option<SealedState>>,
}

impl std::fmt::Debug for TeeStore<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("TeeStore([redacted])")
    }
}

impl LoginStateStore for TeeStore<'_> {
    fn put(
        &self,
        key: StateKey,
        sealed: SealedState,
        expires_at: u64,
        now: u64,
    ) -> Result<(), LoginStoreError> {
        self.inner.put(key, sealed, expires_at, now)
    }

    fn take(&self, key: &StateKey, now: u64) -> Result<Option<SealedState>, LoginStoreError> {
        let taken = self.inner.take(key, now)?;
        if let Some(sealed) = &taken {
            *self.seen.lock().unwrap_or_else(PoisonError::into_inner) = Some(sealed.clone());
        }
        Ok(taken)
    }

    fn purge_expired(&self, now: u64) -> Result<usize, LoginStoreError> {
        self.inner.purge_expired(now)
    }
}

/// A store with one state in it, the one the first attempt took.
struct OnceStore(Mutex<Option<SealedState>>);

impl std::fmt::Debug for OnceStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("OnceStore([redacted])")
    }
}

impl LoginStateStore for OnceStore {
    fn put(&self, _: StateKey, _: SealedState, _: u64, _: u64) -> Result<(), LoginStoreError> {
        Err(LoginStoreError::Backend)
    }

    fn take(&self, _: &StateKey, _: u64) -> Result<Option<SealedState>, LoginStoreError> {
        Ok(self.0.lock().unwrap_or_else(PoisonError::into_inner).take())
    }

    fn purge_expired(&self, _: u64) -> Result<usize, LoginStoreError> {
        Ok(0)
    }
}

/// The session the request presents by its session id cookie, read without any
/// effect: the row's id hash and the account of its user, if the row is a live
/// vault session. Whether the session counts in full is decided afterwards,
/// and only for a re-authentication.
async fn presented_session(
    state: &FerretState,
    jar: &SignedCookieJar,
) -> Result<Option<(SidHash, CredentialId)>, ApiError> {
    let Some(secret) = jar
        .get(product::SID_COOKIE)
        .and_then(|c| SessionSecret::from_cookie(c.value()).ok())
    else {
        return Ok(None);
    };
    let sid = secret.hash();
    drop(secret);
    let found = state
        .vault_db
        .with_conn(move |conn| {
            let Some(row) = lookup(conn, &sid)? else {
                return Ok(None);
            };
            if row.revoked_at.is_some() || row.origin != Origin::Vault {
                return Ok(None);
            }
            let account: Option<Vec<u8>> = conn
                .query_row(
                    "SELECT account_id FROM ferret_accounts WHERE user_id = ?1",
                    params![row.user_id],
                    |r| r.get(0),
                )
                .optional()?;
            Ok(account
                .and_then(|a| <[u8; 16]>::try_from(a).ok())
                .map(|a| (sid, CredentialId::from_bytes(a))))
        })
        .await?;
    Ok(found)
}

/// The library's `login_finish`, with the second try described in the module
/// documentation.
fn finish_blocking(
    state: &FerretState,
    caller: Caller,
    login_id: &str,
    ke3: &[u8],
    presented: Option<(SessionBinding, CredentialId)>,
) -> Result<LoginVerified, AuthError> {
    let policy = read_policy(state);
    let cx = context(state, &policy, profiles());
    let request = |current_session| LoginFinishRequest {
        caller,
        login_id: login_id.as_bytes(),
        ke3,
        current_session,
    };
    let Some(presented) = presented else {
        return login_finish(&cx, state.login_states.as_ref(), &request(None));
    };
    let tee = TeeStore {
        inner: state.login_states.as_ref(),
        seen: Mutex::new(None),
    };
    match login_finish(&cx, &tee, &request(Some(presented))) {
        Err(AuthError::Denied(DenyReason::StateInvalid)) => {
            let taken = tee
                .seen
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .take();
            match taken {
                Some(sealed) => {
                    login_finish(&cx, &OnceStore(Mutex::new(Some(sealed))), &request(None))
                }
                None => Err(AuthError::Denied(DenyReason::StateInvalid)),
            }
        }
        other => other,
    }
}

/// What a finished ordinary sign-in leaves behind.
struct SignedIn {
    secret: SessionSecret,
    claims: vole_kit::auth::session::SessionClaims,
    account: AccountId,
    vault: VaultId,
    vk_epoch: u64,
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
    let presented = presented_session(&state, &jar).await?;

    let login_id = hex16::encode(&req.login_id);
    let ke3 = req.ke3;
    let device = DeviceId(req.device_id);
    let device_name = req
        .device_name
        .filter(|n| !n.is_empty())
        .unwrap_or_else(|| DEFAULT_DEVICE_NAME.to_string());
    let presented_sid = presented.as_ref().map(|(sid, _)| *sid);
    let offered = presented.map(|(sid, account)| (session_binding(&sid), account));

    let worker = state.clone();
    let verified = tokio::task::spawn_blocking(move || {
        finish_blocking(&worker, caller, &login_id, &ke3, offered)
    })
    .await
    .map_err(|_| ApiError::internal())?
    .map_err(auth_refusal)?;

    let secure = state.origins.vault_is_https();
    match verified.purpose {
        LoginPurpose::Reauth { .. } => {
            // The state belongs to the session the request presented; now the
            // session must also count in full (both cookies, limits, scope).
            let session = VaultSession::from_request_parts(&mut parts, &state).await?;
            let same = presented_sid == Some(session.sid)
                && session.account.as_bytes() == verified.credential.as_bytes();
            if !same {
                return Err(ApiError::unauthorized());
            }
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
            let signed_in = state
                .vault_db
                .with_conn(move |conn| {
                    open_session(
                        conn,
                        account_bytes,
                        now,
                        device,
                        &device_name,
                        presented_sid,
                    )
                })
                .await?
                .ok_or_else(|| auth_refusal(AuthError::Denied(DenyReason::StateInvalid)))?;
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
/// account again (a user disabled since the first step gets `None`), note the
/// sign-in, insert the new session and end the presented one when it is the
/// same user's vault session.
fn open_session(
    conn: &mut Connection,
    account: [u8; 16],
    now: i64,
    device: DeviceId,
    device_name: &str,
    presented: Option<SidHash>,
) -> Result<Option<SignedIn>, StoreError> {
    let tx = conn.transaction()?;
    let found: Option<(i64, bool, i64, Vec<u8>, i64)> = tx
        .query_row(
            "SELECT u.id, u.active, u.session_version, a.vault_id, a.vk_epoch
             FROM ferret_accounts a JOIN users u ON u.id = a.user_id
             WHERE a.account_id = ?1",
            params![account.as_slice()],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?)),
        )
        .optional()?;
    let Some((user_id, true, version, vault, epoch)) = found else {
        return Ok(None);
    };
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
    if let Some(previous) = presented
        && let Some(row) = lookup(&tx, &previous)?
        && row.user_id == user_id
        && row.origin == Origin::Vault
    {
        revoke(&tx, &previous, now)?;
    }
    tx.commit()?;
    Ok(Some(SignedIn {
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
        let now = to_i64(state.clock.now_unix())?;
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
    fn shares_add_up_to_a_thousand_with_the_largest_remainders_rounded_up() {
        let shares = permille_shares(&[(1, 1), (2, 1), (3, 1)], 3).unwrap();
        assert_eq!(shares, vec![(1, 334), (2, 333), (3, 333)]);
        let shares = permille_shares(&[(1, 2), (2, 1)], 3).unwrap();
        assert_eq!(shares, vec![(1, 667), (2, 333)]);
        let shares = permille_shares(&[(1, 5)], 5).unwrap();
        assert_eq!(shares, vec![(1, 1000)]);
        for (counts, total) in [
            (vec![(1u8, 7u64), (2, 11), (3, 13)], 31u64),
            (vec![(1, 1), (2, 999)], 1000),
        ] {
            let sum: u32 = permille_shares(&counts, total)
                .unwrap()
                .iter()
                .map(|(_, s)| u32::from(*s))
                .sum();
            assert_eq!(sum, 1000);
        }
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
