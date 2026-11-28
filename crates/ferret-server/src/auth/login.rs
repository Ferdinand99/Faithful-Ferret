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
//! * Every lookup parses exactly one OPAQUE record (the point decode is the
//!   slow part): the account's own for an active user, a constant stand-in for
//!   a disabled user and for a name without a row. The three kinds therefore
//!   cost the server the same before the library is called. The database read
//!   itself still finds a row or not.
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
//! * A `login/finish` body with the key `client` is a device client's
//!   ([`crate::wire::LoginFinishBody`]); it goes to `auth::device_login`, which
//!   checks its DPoP proof first and answers with tokens instead of cookies.
//!   Every other body is the web vault's and takes the path below, unchanged.
//!
//! After a proof the account is read again. A user who was disabled during the
//! sixty seconds between the steps gets nothing.
//!
//! The login state is bound to the OPAQUE record it was made from. The library
//! reads the account's record when the login finishes (on the request's own
//! connection, after the throttle) and refuses a state made from a record that
//! has since been replaced (a new master password, a recovery, a restore) with
//! the same `denied` and after the same work as a wrong password. The
//! transaction that writes the session, or marks a re-authentication, compares
//! the record once more: a change that commits between the library's read and
//! that transaction is caught there, and a session written before the change
//! commits is one the change ends.
//!
//! # Sessions
//!
//! An ordinary sign-in makes a new session row and its two cookies
//! ([`open_session`], which a redeemed sign-in code uses too) in one
//! transaction that also ends the session of the same origin the browser
//! presented, whoever it belongs to: its cookies are replaced, so the row would
//! be left behind. Only that one: other devices stay signed in.
//!
//! A re-authentication keeps the session. In one transaction it checks the
//! session again (it may have ended while the proof ran) and records the time
//! in the session's own row (`reauth_at`), which makes this session, and no
//! other, fresh for a sensitive operation for five minutes. It also sets the
//! kit's re-auth grant. An ordinary sign-in never makes a session fresh.
//!
//! Every successful sign-in, a re-authentication included, revokes the user's
//! pending sign-in codes in the same transaction: the user knows the password,
//! so a code made because it was forgotten must not stay usable. The kit asks
//! this of every product that signs people in itself.
//!
//! Sign-out ends the row named by the presented session cookie and clears the
//! cookies; it answers 204 whether or not there was a valid session.
//!
//! The session info (`GET /api/auth/session`) answers a `full` session and a
//! session of the scope `account_reset`, with the scope, so the web vault knows
//! it may only recover; `reauth_until` is there while a `full` session is
//! fresh. Any other scope gets the one 401.
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
    AccountLookup, AuthContext, AuthError, Caller, Clock, CredentialId, CurrentRecord, DenyReason,
    InternalKind, LoginFinishRequest, LoginPurpose, LoginStartRequest, LoginVerified,
    NormalizedLoginName, PreloginPolicy, ProfileRules, RecordBinding, SessionBinding, SessionScope,
    StoredRecord, ValidatedRecord, login_finish, login_start, normalize_login_name,
};
use rusqlite::{Connection, OptionalExtension as _, TransactionBehavior, params};
use serde::de::DeserializeOwned;
use vole_kit::auth::reauth;
use vole_kit::db::{sign_in_codes, users};

use crate::accounts::log::{self, Actor, EventKind};
use crate::auth::device_login;
use crate::auth::session::{
    ADMIN_ABSOLUTE_SECS, ADMIN_IDLE_SECS, Origin, REAUTH_SECS, RESET_SESSION_ABSOLUTE_SECS,
    SessionRow, VAULT_ABSOLUTE_SECS, VAULT_IDLE_SECS, clear_cookies, insert_session, lookup,
    mark_reauth, new_session, reauth_fresh, revoke, scoped_session_cookies, still_valid,
};
use crate::auth::state_store::SqliteLoginStateStore;
use crate::auth::throttle::caller_from;
use crate::error::{ApiError, StoreError};
use crate::http::extract::{AdminSession, ScopedSession, VaultSession, caps, session_binding};
use crate::http::proxy_guard::request_is_https;
use crate::ids::{AccountId, DeviceId, SessionSecret, SidHash, VaultId};
use crate::product;
use crate::state::{FerretState, VaultDb};
use crate::wire::{
    LoginFinishBody, LoginFinishRes, LoginPurposeJson, LoginStartReq, LoginStartRes, OriginJson,
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
    finish_lookup(row)
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
    finish_lookup(row)
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

/// The first 32 bytes of the stand-in record: the compressed ristretto255 base
/// point, a valid group element.
const STAND_IN_POINT: [u8; 32] = [
    0xe2, 0xf2, 0xae, 0x0a, 0x6a, 0xbc, 0x4e, 0x71, 0xa8, 0x84, 0xa9, 0x61, 0xc5, 0x00, 0x51, 0x5f,
    0x58, 0xe3, 0x0b, 0x6a, 0xa5, 0x82, 0xdd, 0x8d, 0xb6, 0xa6, 0x59, 0x45, 0xe0, 0x8d, 0x2d, 0x76,
];

/// The length of a stored OPAQUE record.
const RECORD_LEN: usize = 192;

/// A record that belongs to no account and is well formed: a valid public key
/// point followed by zeros. It is never used to answer anything (the library
/// makes up the answer for a name without an account), it only gives the paths
/// that have no usable record the same parse to pay as a real one.
fn stand_in_record() -> &'static [u8] {
    &STAND_IN_RECORD
}

static STAND_IN_RECORD: [u8; RECORD_LEN] = build_stand_in();

const fn build_stand_in() -> [u8; RECORD_LEN] {
    let mut bytes = [0u8; RECORD_LEN];
    let mut index = 0;
    while index < STAND_IN_POINT.len() {
        bytes[index] = STAND_IN_POINT[index];
        index = index.saturating_add(1);
    }
    bytes
}

#[cfg(test)]
thread_local! {
    /// How many times this thread has parsed a record for a lookup.
    static RECORD_PARSES: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

/// The one place where a lookup parses a record. The parse includes a point
/// decode, which takes measurable time, so every lookup must pay it exactly
/// once, whatever the account turns out to be.
fn parse_record(bytes: &[u8]) -> Result<ValidatedRecord, AuthError> {
    #[cfg(test)]
    RECORD_PARSES.with(|n| n.set(n.get().saturating_add(1)));
    ValidatedRecord::parse(bytes)
}

/// Pays the parse of a record for a lookup that has no record to use. The
/// result is thrown away; `black_box` on the input and on the outcome keeps the
/// compiler from folding the parse of a constant or removing it.
fn parse_stand_in() {
    let _ = std::hint::black_box(parse_record(std::hint::black_box(stand_in_record())).is_ok());
}

/// Turns what the database gave (or the absence of a row) into the lookup.
///
/// Every path parses exactly one record: the real one for an account that may
/// sign in, the stand-in for a disabled user and for a name without a row. The
/// work is therefore the same for active, disabled and unknown names, as it is
/// inside the library afterwards.
fn finish_lookup(row: Option<LookupRow>) -> rusqlite::Result<AccountLookupOwned> {
    let (account, record, profile, hint) = match row {
        Some((account, record, profile, hint, true)) => (account, record, profile, hint),
        Some((_, _, _, _, false)) => {
            parse_stand_in();
            return Ok(AccountLookupOwned::Disabled);
        }
        None => {
            parse_stand_in();
            return Ok(AccountLookupOwned::Unknown);
        }
    };
    let account = <[u8; 16]>::try_from(account).map_err(|_| bad_row(0, "account id"))?;
    let record = parse_record(&record).map_err(|_| bad_row(1, "OPAQUE record"))?;
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
/// the share of each key stretching profile and the share of accounts that use
/// a secret key. The shares are kept in buckets of 100 permille that change
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
///   that the population changed, not which names exist. At 0 and 1000 the
///   exact count decides, not the band, so a single account that moves into or
///   out of "none" or "all" moves the bucket at once, and one account that
///   keeps toggling flips it (1000 and 900, or 0 and 100) every time.
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
/// database: the bucket of the secret-key hint and one per profile.
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

/// One renewal at a time, in the whole process: each reads the accounts and
/// the stored buckets and may write the buckets, so two that overlapped could
/// leave an older policy in place after a newer one. Renewals are rare and
/// short, so one lock for every server in the process costs nothing.
static RENEWAL: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

/// Renews the policy in `policy` from the accounts in the database. A failure
/// keeps the policy as it was.
async fn renew_policy(db: &VaultDb, policy: &RwLock<PreloginPolicy>) {
    let _one_at_a_time = RENEWAL.lock().await;
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
}

/// Renews the pre-login policy now, as one round of [`refresh_once`] does but
/// without its clean-up of old sessions. Called after a change to the
/// accounts has committed (a new account, a disable, an enable, a deletion),
/// so the made-up answers follow the accounts at once and not at the next
/// round. A failure keeps the policy as it was and is logged.
///
/// Spec: Fase 1 § 4.2 ("Pre-login with several accounts").
pub async fn refresh_policy_now(state: &FerretState) {
    renew_policy(&state.vault_db, &state.prelogin).await;
}

/// One round of the background work. A failure keeps the policy as it was.
pub async fn refresh_once(db: &VaultDb, policy: &RwLock<PreloginPolicy>, clock: &dyn Clock) {
    renew_policy(db, policy).await;
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
/// that: ended rows, rows idle longer than their origin allows, rows older
/// than the absolute limit, and reset sessions older than their own shorter
/// limit. Returns how many it removed.
pub fn purge_sessions(conn: &Connection, now: i64) -> rusqlite::Result<usize> {
    let before = |secs: i64| now.saturating_sub(secs).saturating_sub(PURGE_MARGIN_SECS);
    conn.execute(
        "DELETE FROM ferret_sessions WHERE
            (revoked_at IS NOT NULL AND revoked_at < ?1)
         OR (origin = 'vault' AND (last_seen < ?2 OR issued_at < ?3))
         OR (origin = 'admin' AND (last_seen < ?4 OR issued_at < ?5))
         OR (scope = 'account_reset' AND issued_at < ?6)",
        params![
            now.saturating_sub(PURGE_MARGIN_SECS),
            before(VAULT_IDLE_SECS),
            before(VAULT_ABSOLUTE_SECS),
            before(ADMIN_IDLE_SECS),
            before(ADMIN_ABSOLUTE_SECS),
            before(RESET_SESSION_ABSOLUTE_SECS),
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
pub(crate) fn require_transport(
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
pub(crate) fn clock_now(state: &FerretState) -> Result<u64, ApiError> {
    let now = state.clock.now_unix();
    if now == u64::MAX {
        tracing::error!("the clock failed; sign-in is refused");
        return Err(ApiError::internal());
    }
    Ok(now)
}

pub(crate) fn to_i64(now: u64) -> Result<i64, ApiError> {
    i64::try_from(now).map_err(|_| ApiError::internal())
}

/// Reads a JSON body of at most [`MAX_BODY_BYTES`]. A refusal carries the code
/// of the field that failed (`malformed_ke1`, ...) and nothing of the input.
async fn read_json<T: DeserializeOwned>(body: Body) -> Result<T, ApiError> {
    let bytes = read_bytes(body).await?;
    serde_json::from_slice(&bytes).map_err(|error| refused_body(&error))
}

/// Reads a body of at most [`MAX_BODY_BYTES`].
async fn read_bytes(body: Body) -> Result<axum::body::Bytes, ApiError> {
    axum::body::to_bytes(body, MAX_BODY_BYTES)
        .await
        .map_err(|_| ApiError::coded("too_large"))
}

/// The refusal of a body that did not parse: the code of the field that
/// failed, and nothing of the input.
fn refused_body(error: &serde_json::Error) -> ApiError {
    ApiError::coded(refusal_code(&error.to_string()))
}

pub(crate) fn no_store(mut response: Response) -> Response {
    response
        .headers_mut()
        .insert(CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
}

pub(crate) fn auth_refusal(error: AuthError) -> ApiError {
    // The reason is for this log only; the answer carries the public code.
    tracing::info!(reason = ?error, "sign-in step refused");
    ApiError::from(error)
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

/// The OPAQUE record each account has now, as the library's `login_finish`
/// reads it, by the credential id of the state (the account id, or the made-up
/// id of a name without an account).
///
/// `login_finish` runs on a blocking thread, outside the vault pool: it waits
/// for the login-state store (its mutex, and the SQLite write lock for
/// `take`). The record is read on that same thread, through the store's own
/// connection ([`SqliteLoginStateStore::account_record`]): a finish takes no
/// pooled connection and no second blocking thread, so a flood of finishes,
/// which need no account, can neither starve the pool nor use up the blocking
/// threads that the pool's own work needs. The read happens only for a state
/// that opened and that the throttle let through.
///
/// A credential with no row hashes the stand-in record, so a real and a
/// made-up account cost the same here apart from the primary-key lookup, which
/// finds a row or not as the lookup of `login/start` does.
struct StoredRecords<'s>(&'s SqliteLoginStateStore);

impl CurrentRecord for StoredRecords<'_> {
    fn current_record(
        &self,
        credential: &CredentialId,
    ) -> Result<Option<RecordBinding>, AuthError> {
        let found = self
            .0
            .account_record(credential.as_bytes())
            .map_err(|_| AuthError::Internal(InternalKind::Storage))?;
        let binding = match &found {
            Some(stored) => RecordBinding::of(stored),
            None => RecordBinding::of(stand_in_record()),
        };
        Ok(found.map(|_| binding))
    }
}

/// Whether `binding` is the record `account` has now, read in the caller's
/// transaction. An account that is gone has no record.
pub(crate) fn record_is_current(
    conn: &Connection,
    account: &AccountId,
    binding: &RecordBinding,
) -> rusqlite::Result<bool> {
    let found: Option<Vec<u8>> = conn
        .query_row(
            "SELECT opaque_record FROM ferret_accounts WHERE account_id = ?1",
            params![account.as_bytes().as_slice()],
            |r| r.get(0),
        )
        .optional()?;
    Ok(found.is_some_and(|stored| binding.same_as(&RecordBinding::of(&stored))))
}

/// The library's `login_finish`, on a blocking thread: it takes and opens the
/// sealed state once, against the purpose the request names, asks the
/// throttle with the account of the state, and then reads the account's
/// record (on the store's connection, see `StoredRecords`) and checks the
/// proof.
///
/// Every caller that writes a credential after it must call
/// [`record_is_current`] with `LoginVerified::record` in that write
/// transaction. Only this module and `auth::device_login` call it (checked by
/// a test).
pub(crate) fn finish_blocking(
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
        &StoredRecords(state.login_states.as_ref()),
        &LoginFinishRequest {
            caller,
            login_id: login_id.as_bytes(),
            ke3,
            current_session,
        },
    )
}

/// The account a proof was for, as read before its session is opened.
pub(crate) struct ProvenAccount {
    /// The kit user (`users.id`).
    pub(crate) user_id: i64,
    /// The user's `session_version` when it was read.
    pub(crate) session_version: i64,
    /// The account.
    pub(crate) account: AccountId,
    /// Its vault.
    pub(crate) vault: VaultId,
    /// The epoch of the vault key.
    pub(crate) vk_epoch: u64,
}

/// The user, account and vault of `account`; `None` when there is no such
/// account (it was removed since the first step).
pub(crate) fn read_proven_account(
    conn: &Connection,
    account: [u8; 16],
) -> Result<Option<ProvenAccount>, StoreError> {
    let found: Option<(i64, i64, Vec<u8>, i64)> = conn
        .query_row(
            "SELECT u.id, u.session_version, a.vault_id, a.vk_epoch
             FROM ferret_accounts a JOIN users u ON u.id = a.user_id
             WHERE a.account_id = ?1",
            params![account.as_slice()],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
        )
        .optional()?;
    let Some((user_id, session_version, vault, epoch)) = found else {
        return Ok(None);
    };
    let vault = <[u8; 16]>::try_from(vault).map_err(|_| StoreError::Invalid("vault id"))?;
    let vk_epoch = u64::try_from(epoch).map_err(|_| StoreError::Invalid("vk epoch"))?;
    Ok(Some(ProvenAccount {
        user_id,
        session_version,
        account: AccountId::from_bytes(account),
        vault: VaultId::from_bytes(vault),
        vk_epoch,
    }))
}

async fn login_finish_route(
    State(state): State<FerretState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    request: Request,
) -> Result<Response, ApiError> {
    let (mut parts, body) = request.into_parts();
    require_transport(&state, &parts.headers, peer)?;
    let now = clock_now(&state)?;
    let bytes = read_bytes(body).await?;
    // The key `client` tells a device's body from the web vault's; each shape
    // is refused with its own field codes. The device sign-in has its own
    // path from here on and never reaches the session code below.
    let req = match LoginFinishBody::from_json(&bytes).map_err(|error| refused_body(&error))? {
        LoginFinishBody::Device(req) => {
            return device_login::finish(&state, &parts, peer, req).await;
        }
        LoginFinishBody::Cookie(req) => req,
    };
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
    let worker = state.clone();
    // On a blocking thread, as the store needs, and outside the pool: see
    // `StoredRecords`.
    let verified = tokio::task::spawn_blocking(move || {
        finish_blocking(&worker, caller, &login_id, &ke3, current_session)
    })
    .await
    .map_err(|_| ApiError::internal())?
    .map_err(auth_refusal)?;
    let now = to_i64(now)?;

    match verified.purpose {
        LoginPurpose::Reauth { .. } => {
            let session = reauth_session.ok_or_else(ApiError::internal)?;
            let (sid, user_id, version) = (session.sid, session.user_id, session.session_version);
            let account = session.account;
            let record = verified.record;
            // The check of the session, of the record and the mark are one
            // write transaction: a session that ended, or whose user was
            // signed out everywhere, while the proof ran is not made fresh,
            // and neither is one whose master password changed meanwhile.
            let marked = state
                .vault_db
                .with_conn(move |conn| {
                    let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
                    if !still_valid(&tx, &sid, Origin::Vault, version, now)? {
                        return Ok(Marked::SessionGone);
                    }
                    if !record_is_current(&tx, &account, &record)? {
                        return Ok(Marked::RecordChanged);
                    }
                    if !mark_reauth(&tx, &sid, now)? {
                        return Ok(Marked::SessionGone);
                    }
                    sign_in_codes::revoke_for_user(&tx, user_id)?;
                    tx.commit()?;
                    Ok(Marked::Fresh)
                })
                .await?;
            match marked {
                Marked::Fresh => {}
                Marked::SessionGone => return Err(ApiError::unauthorized()),
                Marked::RecordChanged => {
                    return Err(auth_refusal(AuthError::Denied(DenyReason::RecordChanged)));
                }
            }
            let jar = reauth::grant(jar, &state.core.session_key, state.origins.vault_is_https());
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
            let proven = state
                .vault_db
                .with_conn(move |conn| read_proven_account(conn, account_bytes))
                .await?
                .ok_or_else(|| auth_refusal(AuthError::Denied(DenyReason::StateInvalid)))?;
            let (jar, _) = open_session_proven(
                &state,
                jar,
                &NewSession {
                    user_id: proven.user_id,
                    origin: Origin::Vault,
                    scope: SessionScope::Full,
                    session_version: proven.session_version,
                    device,
                    device_name: &device_name,
                    now,
                    event: None,
                },
                Some((proven.account, verified.record)),
            )
            .await?;
            Ok(no_store(
                (
                    jar,
                    Json(LoginFinishRes {
                        account_id: *proven.account.as_bytes(),
                        vault_id: *proven.vault.as_bytes(),
                        vk_epoch: proven.vk_epoch,
                    }),
                )
                    .into_response(),
            ))
        }
    }
}

/// How the transaction of a re-authentication ended.
enum Marked {
    /// The session is fresh now.
    Fresh,
    /// The session ended, or its user was signed out everywhere, while the
    /// proof ran.
    SessionGone,
    /// The account's record is not the one the proof was checked against.
    RecordChanged,
}

/// How the database side of opening a session ended.
enum Opened {
    /// A new session, and the session it ended (the one the browser presented
    /// on the same origin), if a live one was ended.
    Session {
        secret: SessionSecret,
        claims: vole_kit::auth::session::SessionClaims,
        sid: SidHash,
        ended: Option<SidHash>,
    },
    /// The user is gone, was disabled, or was signed out everywhere (its
    /// `session_version` moved) since the proof; or, for the vault origin, it
    /// has no account with a vault.
    Refused,
    /// The kit's second factor is on for the user and this server cannot ask
    /// for it yet.
    SecondFactor,
    /// The account's record is not the one the proof was checked against: a
    /// new master password or a recovery committed after the library read it.
    RecordChanged,
    /// The event of the session could not be written to the account log, so
    /// the transaction was rolled back and no session exists.
    NotLogged,
}

/// Opens a session for `user_id` on `origin` with `scope`, after a proof (an
/// OPAQUE sign-in, or a redeemed sign-in code for `account_reset`), and adds
/// its cookies to `jar`. Returns the jar and the new session's id hash.
///
/// One write transaction:
///
/// * the user is read again and must be active with exactly
///   `session_version` (the version the proof was made against; a sign-out
///   everywhere since then refuses with `401 denied`); a user whose kit
///   second factor is on gets `403 forbidden`, since this server cannot ask
///   for it yet; for the vault origin the user must have an account with a
///   vault;
/// * the sign-in is noted, and the user's pending sign-in codes are revoked
///   (the kit's rule for a product that signs people in itself);
/// * the new row is inserted, never fresh (`reauth_at` is empty);
/// * the session of the same origin that the browser presented ends, whoever
///   it belongs to: its cookies are replaced, so the row would be left live
///   and unreachable.
///
/// After the commit, the ended session is announced (`session_revoked`), so
/// its event stream closes at once.
///
/// With `event`, that event is written to the user's account log (actor
/// `account`) in the same transaction; if it cannot be written, the
/// transaction is rolled back and the answer is `401 denied`, with no session.
///
/// This form checks no OPAQUE record: it is only for a session that no
/// OPAQUE proof backs (a redeemed sign-in code). A session issued after
/// `login_finish` must go through `open_session_proven` with the account and
/// `LoginVerified::record`, so the record is checked again in the session's
/// transaction; without that check a new master password that commits between
/// the proof and the session write would not stop the session.
#[allow(
    clippy::too_many_arguments,
    reason = "each argument is a different fact of the sign-in; a struct would only rename them"
)]
pub(crate) async fn open_session(
    state: &FerretState,
    jar: SignedCookieJar,
    user_id: i64,
    origin: Origin,
    scope: SessionScope,
    session_version: i64,
    device: DeviceId,
    device_name: &str,
    now: i64,
    event: Option<EventKind>,
) -> Result<(SignedCookieJar, SidHash), ApiError> {
    let new = NewSession {
        user_id,
        origin,
        scope,
        session_version,
        device,
        device_name,
        now,
        event,
    };
    open_session_proven(state, jar, &new, None).await
}

/// The facts of a session to open, as [`open_session`] takes them.
struct NewSession<'a> {
    user_id: i64,
    origin: Origin,
    scope: SessionScope,
    session_version: i64,
    device: DeviceId,
    device_name: &'a str,
    now: i64,
    /// The event to write to the account log with the session.
    event: Option<EventKind>,
}

/// [`open_session`] after an OPAQUE proof: `proven` is the account and the
/// record the proof was checked against, and the transaction refuses (`401
/// denied`) when the account's record is another one by then.
async fn open_session_proven(
    state: &FerretState,
    jar: SignedCookieJar,
    new: &NewSession<'_>,
    proven: Option<(AccountId, RecordBinding)>,
) -> Result<(SignedCookieJar, SidHash), ApiError> {
    let presented = presented_sid(&jar);
    let device_name = new.device_name.to_string();
    let (user_id, origin, scope, session_version, device, now, event) = (
        new.user_id,
        new.origin,
        new.scope,
        new.session_version,
        new.device,
        new.now,
        new.event,
    );
    let opened = state
        .vault_db
        .with_conn(move |conn| {
            open_session_tx(
                conn,
                &NewRow {
                    user_id,
                    origin,
                    scope,
                    session_version,
                    device,
                    device_name: &device_name,
                    now,
                    proven,
                    event,
                },
                presented,
            )
        })
        .await?;
    let (secret, claims, sid) = match opened {
        Opened::Session {
            secret,
            claims,
            sid,
            ended,
        } => {
            // After the commit: a stream that wakes for this finds the row
            // ended. Only a session that was really ended is announced.
            if let Some(previous) = ended {
                state.events.session_revoked(previous);
            }
            (secret, claims, sid)
        }
        Opened::Refused => {
            return Err(auth_refusal(AuthError::Denied(DenyReason::StateInvalid)));
        }
        Opened::SecondFactor => {
            tracing::info!("sign-in refused: the kit's second factor is on");
            return Err(ApiError::coded("forbidden"));
        }
        Opened::RecordChanged => {
            return Err(auth_refusal(AuthError::Denied(DenyReason::RecordChanged)));
        }
        Opened::NotLogged => {
            return Err(auth_refusal(AuthError::Denied(DenyReason::StateInvalid)));
        }
    };
    let secure = match origin {
        Origin::Vault => state.origins.vault_is_https(),
        Origin::Admin => state.origins.admin_is_https(),
    };
    Ok((
        scoped_session_cookies(jar, &secret, &claims, secure, scope),
        sid,
    ))
}

/// The facts of the row [`open_session_tx`] inserts.
struct NewRow<'a> {
    user_id: i64,
    origin: Origin,
    scope: SessionScope,
    session_version: i64,
    device: DeviceId,
    device_name: &'a str,
    now: i64,
    /// The account and the record of an OPAQUE proof, checked against the
    /// account's record in the transaction.
    proven: Option<(AccountId, RecordBinding)>,
    /// The event to write to the account log in the transaction.
    event: Option<EventKind>,
}

/// The database side of [`open_session`], in one write transaction.
fn open_session_tx(
    conn: &mut Connection,
    new: &NewRow<'_>,
    presented: Option<SidHash>,
) -> Result<Opened, StoreError> {
    let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let user: Option<(bool, i64, bool)> = tx
        .query_row(
            "SELECT active, session_version, totp_enabled FROM users WHERE id = ?1",
            params![new.user_id],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )
        .optional()?;
    let totp = match user {
        Some((true, version, totp)) if version == new.session_version => totp,
        _ => return Ok(Opened::Refused),
    };
    if totp {
        return Ok(Opened::SecondFactor);
    }
    if let Some((account, record)) = &new.proven
        && !record_is_current(&tx, account, record)?
    {
        return Ok(Opened::RecordChanged);
    }
    if new.origin == Origin::Vault {
        let has_vault: Option<i64> = tx
            .query_row(
                "SELECT 1 FROM ferret_accounts a
                 JOIN ferret_vaults v ON v.account_id = a.account_id
                 WHERE a.user_id = ?1",
                params![new.user_id],
                |r| r.get(0),
            )
            .optional()?;
        if has_vault.is_none() {
            return Ok(Opened::Refused);
        }
    }

    users::touch_last_login(&tx, new.user_id)?;
    sign_in_codes::revoke_for_user(&tx, new.user_id)?;
    let (secret, session, claims) = new_session(
        &mut OsRng,
        new.now,
        new.user_id,
        new.session_version,
        new.origin,
        new.device,
        new.device_name,
        new.scope,
    );
    insert_session(&tx, &session)?;
    // The event commits with the session or not at all: on a failure the
    // transaction is dropped (rolled back) and no session exists.
    if let Some(kind) = new.event
        && let Err(error) = log::record(&tx, new.user_id, kind, &Actor::Account, new.now)
    {
        tracing::error!(
            user_id = new.user_id,
            %error,
            "the account log could not be written: no session was opened"
        );
        return Ok(Opened::NotLogged);
    }
    // The browser's cookies are replaced by the new ones, so the row they
    // named would be left live and unreachable; it ends here, for any user.
    let mut ended = None;
    if let Some(previous) = presented
        && previous != session.sid
        && let Some(row) = lookup(&tx, &previous)?
        && row.origin == new.origin
        && revoke(&tx, &previous, new.now)?
    {
        ended = Some(previous);
    }
    tx.commit()?;
    Ok(Opened::Session {
        secret,
        claims,
        sid: session.sid,
        ended,
    })
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
                let ended = state
                    .vault_db
                    .with_conn(move |conn| {
                        if let Some(row) = lookup(conn, &sid)?
                            && row.origin == origin
                        {
                            revoke(conn, &sid, now)?;
                            return Ok(true);
                        }
                        Ok(false)
                    })
                    .await?;
                // After the row is ended: a stream that wakes for this finds
                // it ended as well. A session without a stream is heard by
                // nobody, and the call never fails.
                if ended {
                    state.events.session_revoked(sid);
                }
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

/// The end of the freshness of `row` (the last moment a sensitive operation
/// may run on it), if it is fresh at `now`: `reauth_at + 300`. A session that
/// is not `full` is never fresh.
///
/// Spec: Fase 1 § 4.6 (a).
fn reauth_until(row: &SessionRow, now: i64) -> Option<u64> {
    if row.scope != SessionScope::Full || !reauth_fresh(row, now) {
        return None;
    }
    row.reauth_at
        .and_then(|at| at.checked_add(REAUTH_SECS))
        .and_then(|until| u64::try_from(until).ok())
}

/// `GET /api/auth/session` on the vault listener: a `full` session or a reset
/// session (`account_reset`), with its scope and, while a `full` session is
/// fresh, `reauth_until`. Every other scope gets the one 401, as a session
/// that does not count.
async fn session_vault(
    State(state): State<FerretState>,
    mut parts: Parts,
) -> Result<Response, ApiError> {
    // `Challenge` is a capability of exactly the two scopes that may read
    // this; the match below is the rule itself. A scope that the capability
    // refuses answers like no session at all.
    let scoped = ScopedSession::<caps::Challenge>::from_request_parts(&mut parts, &state)
        .await
        .map_err(|error| {
            if error == ApiError::coded("forbidden") {
                ApiError::unauthorized()
            } else {
                error
            }
        })?;
    let scope = match scoped.scope() {
        SessionScope::Full | SessionScope::AccountReset => scoped.scope(),
        SessionScope::Pending2fa | SessionScope::Unverified => {
            return Err(ApiError::unauthorized());
        }
    };
    let facts = scoped.session();
    let (sid, user_id, now) = (facts.sid(), facts.user_id(), facts.now());
    let found = state
        .vault_db
        .with_conn(move |conn| {
            let row = lookup(conn, &sid)?;
            let user: Option<(String, bool)> = conn
                .query_row(
                    "SELECT username, role = 'admin' AND active = 1 FROM users WHERE id = ?1",
                    params![user_id],
                    |r| Ok((r.get(0)?, r.get(1)?)),
                )
                .optional()?;
            Ok(row.zip(user))
        })
        .await?;
    let Some((row, (email, admin))) = found else {
        return Err(ApiError::unauthorized());
    };
    Ok(no_store(
        Json(SessionRes {
            account_id: Some(*facts.account().as_bytes()),
            email,
            scope: scope.as_str().to_string(),
            origin: OriginJson::Vault,
            reauth_until: reauth_until(&row, now),
            // A reset session (from a one-time code) is told nothing of the role.
            admin: (admin && scope == SessionScope::Full).then_some(true),
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
            reauth_until: None,
            admin: None,
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

    fn parses() -> usize {
        RECORD_PARSES.with(std::cell::Cell::get)
    }

    fn active_row() -> LookupRow {
        (vec![7; 16], stand_in_record().to_vec(), 1, 0, true)
    }

    #[test]
    fn the_stand_in_record_is_a_well_formed_record() {
        assert_eq!(stand_in_record().len(), RECORD_LEN);
        assert!(ValidatedRecord::parse(stand_in_record()).is_ok());
    }

    #[test]
    fn every_kind_of_lookup_parses_exactly_one_record() {
        let before = parses();
        let active = finish_lookup(Some(active_row())).unwrap();
        assert!(matches!(active, AccountLookupOwned::Active { .. }));
        assert_eq!(parses(), before + 1, "an active account");

        let before = parses();
        let mut disabled = active_row();
        disabled.4 = false;
        let disabled = finish_lookup(Some(disabled)).unwrap();
        assert!(matches!(disabled, AccountLookupOwned::Disabled));
        assert_eq!(parses(), before + 1, "a disabled account");

        let before = parses();
        let unknown = finish_lookup(None).unwrap();
        assert!(matches!(unknown, AccountLookupOwned::Unknown));
        assert_eq!(parses(), before + 1, "a name without an account");
    }

    #[test]
    fn a_disabled_account_with_a_damaged_record_is_still_disabled() {
        let mut row = active_row();
        row.1 = vec![1; 5];
        row.4 = false;
        let before = parses();
        assert!(matches!(
            finish_lookup(Some(row)).unwrap(),
            AccountLookupOwned::Disabled
        ));
        assert_eq!(parses(), before + 1);
        // An active account with a damaged record is an error, not a lookup.
        let mut row = active_row();
        row.1 = vec![1; 5];
        assert!(finish_lookup(Some(row)).is_err());
    }

    /// The two lookups that read the database run the parse once per call for
    /// an active, a disabled, a bare and an absent user alike.
    #[test]
    fn both_database_lookups_parse_once_for_every_kind_of_user() {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(
            "CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT NOT NULL, active INTEGER NOT NULL);
             CREATE TABLE ferret_accounts (
                 account_id BLOB NOT NULL, user_id INTEGER NOT NULL, opaque_record BLOB NOT NULL,
                 ksf_profile INTEGER NOT NULL, sk_hint INTEGER NOT NULL);
             INSERT INTO users VALUES (1, 'alice@example.com', 1), (2, 'dora@example.com', 0),
                                      (3, 'root@example.com', 1);",
        )
        .unwrap();
        for user in [1_i64, 2] {
            conn.execute(
                "INSERT INTO ferret_accounts VALUES (?1, ?2, ?3, 1, 0)",
                params![vec![user as u8; 16], user, stand_in_record()],
            )
            .unwrap();
        }
        let kinds = [
            ("alice@example.com", 1_i64, "active"),
            ("dora@example.com", 2, "disabled"),
            ("root@example.com", 3, "unknown"),
            ("nobody@example.com", 99, "unknown"),
        ];
        for (email, user_id, kind) in kinds {
            let name = normalize_login_name(email).unwrap();
            let before = parses();
            let by_name = lookup_account(&conn, &name).unwrap();
            assert_eq!(parses(), before + 1, "{kind} by name");
            let before = parses();
            let by_user = lookup_account_of_user(&conn, user_id).unwrap();
            assert_eq!(parses(), before + 1, "{kind} by user");
            for found in [by_name, by_user] {
                let got = match found {
                    AccountLookupOwned::Active { .. } => "active",
                    AccountLookupOwned::Disabled => "disabled",
                    AccountLookupOwned::Unknown => "unknown",
                };
                assert_eq!(got, kind);
            }
        }
    }

    #[test]
    fn debug_of_the_lookup_shows_nothing() {
        let shown = format!("{:?}", AccountLookupOwned::Unknown);
        assert_eq!(shown, format!("{:?}", AccountLookupOwned::Disabled));
    }
}
