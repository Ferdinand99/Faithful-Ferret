//! The hand-over of a session from the vault origin to the admin origin: the
//! vault origin mints a one-time code (`POST /api/auth/handoff`), the admin
//! origin redeems it (`POST /api/auth/handoff/redeem`). The password is typed
//! on the vault origin only. Spec: Fase 1 § 2.4.
//!
//! # The flow
//!
//! 1. Everything that wants into the admin pages starts at
//!    `GET {admin}/auth/handoff/begin` (see `admin::handoff_page`). It sets the
//!    verifier cookie `__Host-ferret_handoff` (32 random bytes, 120 seconds) and
//!    sends the browser to the vault origin with `challenge = SHA-256(verifier)`.
//! 2. After a sign-in (or a re-authentication) there, the vault page calls
//!    `mint`. The code is 32 random bytes; only its hash is stored, with the
//!    challenge, the user, the purpose, the cleaned `next` and the kit's
//!    session version. It lives 60 seconds.
//! 3. The vault page navigates to `{admin}/auth/handoff#code=<code>`. The
//!    fragment carries the code and nothing else, so it is in no request line,
//!    no `Referer` and no log.
//! 4. The admin page's script calls `redeem`. The row is deleted first and
//!    whatever the checks say, so a failed attempt burns the code. Then:
//!    the verifier cookie must hash to the challenge (this stops an attacker's
//!    code from being used in the victim's browser), the vault session the code
//!    was made from must still be valid in every respect (not ended, within its
//!    limits, scope `full`, user active, session version unchanged), and an
//!    admin session in the request must be for the same user. The admin origin
//!    then gets its own session row (a new id, its own time, the device of the
//!    parent) and its own cookies.
//!
//! A `reauth` hand-over makes no new session: the admin session in the request
//! must be the same user's, and gets the kit's re-auth grant. The vault side
//! uses up its own grant when it mints the code.
//!
//! # Limits that follow from this
//!
//! * Every refusal of `redeem` is the same answer, `handoff_invalid`, whatever
//!   failed, so a caller learns nothing about which check it hit.
//! * The hand-over goes from the vault to the admin origin only: `mint` is a
//!   route of the vault listener and `redeem` one of the admin listener, and
//!   the session extractors refuse a session of the other origin.
//! * Signing out of the vault ends the admin sessions made from it
//!   (`session::revoke`). Signing out of the admin pages ends that session only.
//! * A hand-over code is time-limited with the server's clock; the kit's re-auth
//!   grant keeps the kit's own clock (`vole_kit::auth::session::now_unix`).

use std::sync::Arc;
use std::time::Duration;

use axum::Json;
use axum::Router;
use axum::extract::{FromRef, FromRequest, FromRequestParts, Request, State};
use axum::response::{IntoResponse, Response};
use axum::routing::post;
use axum_extra::extract::CookieJar;
use axum_extra::extract::cookie::{Cookie, SameSite, SignedCookieJar};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use ferret_core::{OsRng, SecureRng as _};
use ferret_server_auth::{Clock, SessionScope};
use rusqlite::{Connection, OptionalExtension as _, params};
use sha2::{Digest as _, Sha256};
use vole_kit::auth::reauth;
use vole_kit::auth::session::{SessionClaims, sanitize_next as kit_sanitize_next};

use crate::auth::login::no_store;
use crate::auth::register::ApiJson;
use crate::auth::session::{
    Origin, insert_session, lookup, new_session, removal, revoke, session_cookies, set_parent,
    within_limits,
};
use crate::error::{ApiError, StoreError};
use crate::http::extract::{AdminSession, VaultSession};
use crate::ids::{SessionSecret, SidHash};
use crate::product;
use crate::state::{FerretState, VaultDb};
use crate::wire::{
    HANDOFF_CODE_BYTES, HandoffPurposeJson, HandoffRedeemRes, HandoffReq, HandoffRes,
    NEXT_MAX_CHARS, RedeemReq, parse_handoff_code,
};

/// Seconds a code lives: 60.
pub const CODE_TTL_SECS: i64 = 60;
/// Seconds the verifier cookie lives: 120.
pub const VERIFIER_TTL_SECS: i64 = 120;
/// How often the expired rows are deleted.
const PURGE_EVERY: Duration = Duration::from_secs(60);
/// The most codes one vault session may have waiting. A newer code pushes the
/// oldest out, so a session cannot fill the table.
const MAX_WAITING_PER_SESSION: i64 = 8;

/// The places on the admin origin that a hand-over never leads to: the vault's
/// own pages and the hand-over itself (a loop), and the machine routes.
const NEXT_BLOCKED: [&str; 3] = ["/vault", "/auth", "/api"];

/// Cleans a `next` before it is stored or followed: the kit's rule (a plain
/// absolute path; no scheme, no `//host`, no backslash, no control character or
/// space; never the kit's sign-in pages), and not the vault's pages, the
/// hand-over or the machine routes either. Anything else is `/`.
pub fn sanitize_next(raw: Option<&str>) -> String {
    let next = kit_sanitize_next(raw);
    let blocked = NEXT_BLOCKED.iter().any(|prefix| {
        next == *prefix
            || next
                .strip_prefix(prefix)
                .is_some_and(|rest| rest.starts_with(['/', '?', '#']))
    });
    if blocked || next.chars().count() > NEXT_MAX_CHARS {
        return "/".to_string();
    }
    next
}

/// The routes of the vault listener: minting a code.
pub fn routes<S>() -> Router<S>
where
    S: Clone + Send + Sync + 'static,
    FerretState: FromRef<S>,
{
    Router::new().route("/api/auth/handoff", post(mint))
}

/// The routes of the admin listener: redeeming a code.
pub fn admin_routes<S>() -> Router<S>
where
    S: Clone + Send + Sync + 'static,
    FerretState: FromRef<S>,
{
    Router::new().route("/api/auth/handoff/redeem", post(redeem))
}

/// SHA-256 of 32 bytes: the hash a code is stored under, and the challenge of a
/// verifier.
fn sha256_32(bytes: &[u8; HANDOFF_CODE_BYTES]) -> [u8; 32] {
    let digest = Sha256::digest(bytes);
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    out
}

/// The challenge of a verifier: its SHA-256.
pub fn challenge_of(verifier: &[u8; HANDOFF_CODE_BYTES]) -> [u8; 32] {
    sha256_32(verifier)
}

/// Equality of two hashes that takes the same time wherever they differ.
fn same_hash(a: &[u8; 32], b: &[u8; 32]) -> bool {
    let mut difference = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        difference |= x ^ y;
    }
    difference == 0
}

// -------------------------------------------------------------------- mint

/// `POST /api/auth/handoff` (vault listener): makes a code for the vault
/// session of the request. The session must be a full one; for a `reauth` code
/// the kit's re-auth grant of this request must be fresh, and it is used up.
async fn mint(State(state): State<FerretState>, request: Request) -> Result<Response, ApiError> {
    let (mut parts, body) = request.into_parts();
    let session = VaultSession::from_request_parts(&mut parts, &state).await?;
    let headers = parts.headers.clone();
    let ApiJson(req) =
        ApiJson::<HandoffReq>::from_request(Request::from_parts(parts, body), &state).await?;

    let jar = SignedCookieJar::from_headers(&headers, state.core.session_key.clone());
    // The version the session was signed in under; the extractor has checked
    // that it is the user's current one.
    let version = jar
        .get(product::SESSION_COOKIE)
        .and_then(|c| SessionClaims::decode(c.value()))
        .map(|claims| claims.version)
        .ok_or_else(ApiError::unauthorized)?;

    let reauth_purpose = req.purpose == HandoffPurposeJson::Reauth;
    if reauth_purpose && !reauth::is_fresh(&jar, &state.core.session_key) {
        // The password was not checked just now: nothing to hand over.
        return Err(ApiError::coded("forbidden"));
    }

    let mut code = [0u8; HANDOFF_CODE_BYTES];
    let mut rng = OsRng;
    rng.fill(&mut code);
    let expires_at = session
        .now
        .checked_add(CODE_TTL_SECS)
        .ok_or_else(ApiError::internal)?;
    let row = NewHandoff {
        code_hash: sha256_32(&code),
        sid: session.sid,
        user_id: session.user_id,
        purpose: if reauth_purpose { "reauth" } else { "login" },
        next: sanitize_next(Some(&req.next)),
        challenge: req.challenge,
        expires_at,
        session_version: version,
    };
    state
        .vault_db
        .with_conn(move |conn| insert_handoff(conn, &row))
        .await?;

    let body = Json(HandoffRes {
        code: URL_SAFE_NO_PAD.encode(code),
        expires_in: u64::try_from(CODE_TTL_SECS).unwrap_or(60),
    });
    // The grant is used up by the code that took its place.
    let response = if reauth_purpose {
        (reauth::clear(jar), body).into_response()
    } else {
        body.into_response()
    };
    Ok(no_store(response))
}

/// A row to insert into `ferret_handoffs`.
struct NewHandoff {
    code_hash: [u8; 32],
    sid: SidHash,
    user_id: i64,
    purpose: &'static str,
    next: String,
    challenge: [u8; 32],
    expires_at: i64,
    session_version: i64,
}

fn insert_handoff(conn: &mut Connection, row: &NewHandoff) -> Result<(), StoreError> {
    let tx = conn.transaction()?;
    tx.execute(
        "INSERT INTO ferret_handoffs
           (code_hash, sid_hash, user_id, purpose, next, challenge, expires_at, session_version)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
        params![
            row.code_hash.as_slice(),
            row.sid.0.as_slice(),
            row.user_id,
            row.purpose,
            row.next,
            row.challenge.as_slice(),
            row.expires_at,
            row.session_version,
        ],
    )?;
    // Keep the newest few codes of the session and drop the rest.
    tx.execute(
        "DELETE FROM ferret_handoffs
         WHERE sid_hash = ?1 AND code_hash NOT IN (
           SELECT code_hash FROM ferret_handoffs WHERE sid_hash = ?1
           ORDER BY expires_at DESC, rowid DESC LIMIT ?2)",
        params![row.sid.0.as_slice(), MAX_WAITING_PER_SESSION],
    )?;
    tx.commit()?;
    Ok(())
}

// ------------------------------------------------------------------ redeem

/// A row of `ferret_handoffs`, as it was when it was deleted.
struct TakenHandoff {
    sid: SidHash,
    user_id: i64,
    reauth: bool,
    next: String,
    challenge: [u8; 32],
    expires_at: i64,
    session_version: i64,
}

fn fixed32(bytes: Vec<u8>, index: usize) -> rusqlite::Result<[u8; 32]> {
    <[u8; 32]>::try_from(bytes).map_err(|_| {
        rusqlite::Error::FromSqlConversionFailure(
            index,
            rusqlite::types::Type::Blob,
            "wrong length".into(),
        )
    })
}

/// Deletes the row of `code_hash` and returns it. The delete is committed
/// before anything is checked: a code is used up by its first attempt.
fn take(conn: &mut Connection, code_hash: &[u8; 32]) -> Result<Option<TakenHandoff>, StoreError> {
    let tx = conn.transaction()?;
    let taken = tx
        .query_row(
            "DELETE FROM ferret_handoffs WHERE code_hash = ?1
             RETURNING sid_hash, user_id, purpose, next, challenge, expires_at, session_version",
            params![code_hash.as_slice()],
            |r| {
                let purpose: String = r.get(2)?;
                Ok(TakenHandoff {
                    sid: SidHash(fixed32(r.get(0)?, 0)?),
                    user_id: r.get(1)?,
                    reauth: purpose == "reauth",
                    next: r.get(3)?,
                    challenge: fixed32(r.get(4)?, 4)?,
                    expires_at: r.get(5)?,
                    session_version: r.get(6)?,
                })
            },
        )
        .optional()?;
    tx.commit()?;
    Ok(taken)
}

/// What a good redeem leaves for the response.
enum Granted {
    /// A new admin session: its secret and the kit's claims for it.
    Session {
        secret: SessionSecret,
        claims: SessionClaims,
        next: String,
    },
    /// The admin session in the request stays and gets the re-auth grant.
    Reauth { next: String },
}

/// Why a redeem was refused. For the log only: the answer is the same for
/// every reason.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Refusal {
    /// No such code: never made, expired and removed, or used already.
    NoSuchCode,
    /// The code is older than its 60 seconds.
    Expired,
    /// The browser holds no verifier, or one that does not match.
    VerifierMismatch,
    /// The vault session the code was made from is gone, ended, past a limit,
    /// not a full one, or the user is no longer active or has a new session
    /// version.
    ParentInvalid,
    /// An admin session of another user is open in this browser.
    OtherAdminSession,
    /// A `reauth` code, and no admin session of the same user is open.
    NoAdminSession,
}

/// The admin session the request presented, if it was a valid one.
struct Presented {
    sid: SidHash,
    user_id: i64,
}

/// The checks that need the database, and the new admin session, in one
/// transaction.
fn open_admin_session(
    conn: &mut Connection,
    taken: TakenHandoff,
    presented: Option<&Presented>,
    now: i64,
) -> Result<Result<Granted, Refusal>, StoreError> {
    let tx = conn.transaction()?;
    // The vault session the code was made from must be valid in every respect.
    let Some(parent) = lookup(&tx, &taken.sid)? else {
        return Ok(Err(Refusal::ParentInvalid));
    };
    if parent.revoked_at.is_some()
        || parent.origin != Origin::Vault
        || parent.scope != SessionScope::Full
        || parent.user_id != taken.user_id
        || !within_limits(&parent, now)
    {
        return Ok(Err(Refusal::ParentInvalid));
    }
    let user: Option<(i64, bool)> = tx
        .query_row(
            "SELECT session_version, active FROM users WHERE id = ?1",
            params![taken.user_id],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .optional()?;
    let version = match user {
        Some((version, true)) if version == taken.session_version => version,
        _ => return Ok(Err(Refusal::ParentInvalid)),
    };
    // An admin session of another user is never replaced by this one.
    if presented.is_some_and(|p| p.user_id != taken.user_id) {
        return Ok(Err(Refusal::OtherAdminSession));
    }

    if taken.reauth {
        // A fresh check of the password, for the admin session that is open.
        if presented.is_none() {
            return Ok(Err(Refusal::NoAdminSession));
        }
        return Ok(Ok(Granted::Reauth { next: taken.next }));
    }

    let (secret, session, claims) = new_session(
        &mut OsRng,
        now,
        taken.user_id,
        version,
        Origin::Admin,
        parent.device,
        &parent.device_name,
        SessionScope::Full,
    );
    insert_session(&tx, &session)?;
    set_parent(&tx, &session.sid, &taken.sid)?;
    // The same user's earlier admin session is replaced, not left behind.
    if let Some(previous) = presented
        && lookup(&tx, &previous.sid)?.is_some_and(|row| row.origin == Origin::Admin)
    {
        revoke(&tx, &previous.sid, now)?;
    }
    tx.commit()?;
    Ok(Ok(Granted::Session {
        secret,
        claims,
        next: taken.next,
    }))
}

/// `POST /api/auth/handoff/redeem` (admin listener): turns a code into an admin
/// session, if every check holds. See the module documentation.
async fn redeem(State(state): State<FerretState>, request: Request) -> Result<Response, ApiError> {
    let (mut parts, body) = request.into_parts();
    let presented = AdminSession::from_request_parts(&mut parts, &state)
        .await
        .ok()
        .map(|session| Presented {
            sid: session.sid,
            user_id: session.user_id,
        });
    let headers = parts.headers.clone();
    let ApiJson(req) =
        ApiJson::<RedeemReq>::from_request(Request::from_parts(parts, body), &state).await?;
    let invalid = || ApiError::coded("handoff_invalid");

    let code = parse_handoff_code(&req.code).map_err(|_| invalid())?;
    // The verifier of the browser, as a hash. A cookie that is not a verifier
    // is no verifier.
    let verifier_hash = CookieJar::from_headers(&headers)
        .get(product::HANDOFF_COOKIE)
        .and_then(|c| parse_handoff_code(c.value()).ok())
        .map(|verifier| challenge_of(&verifier));
    let now = i64::try_from(state.clock.now_unix()).map_err(|_| ApiError::internal())?;
    let hash = sha256_32(&code);

    let granted = state
        .vault_db
        .with_conn(move |conn| {
            let Some(taken) = take(conn, &hash)? else {
                return Ok(Err(Refusal::NoSuchCode));
            };
            if now > taken.expires_at {
                return Ok(Err(Refusal::Expired));
            }
            if !verifier_hash.is_some_and(|v| same_hash(&v, &taken.challenge)) {
                return Ok(Err(Refusal::VerifierMismatch));
            }
            open_admin_session(conn, taken, presented.as_ref(), now)
        })
        .await?
        .map_err(|reason| {
            tracing::info!(?reason, "hand-over refused");
            invalid()
        })?;

    let key = state.core.session_key.clone();
    let secure = state.origins.admin_is_https();
    let jar = SignedCookieJar::from_headers(&headers, key.clone());
    let (jar, next) = match granted {
        Granted::Session {
            secret,
            claims,
            next,
        } => (session_cookies(jar, &secret, &claims, secure), next),
        Granted::Reauth { next } => (reauth::grant(jar, &key, secure), next),
    };
    // The verifier is a plain cookie, so it is removed through a plain jar
    // that holds it (a removal of a cookie the jar does not hold is dropped).
    let verifier = CookieJar::from_headers(&headers).remove(removal(product::HANDOFF_COOKIE));
    Ok(no_store(
        (jar, verifier, Json(HandoffRedeemRes { next })).into_response(),
    ))
}

/// The verifier cookie `begin` sets: `__Host-` prefixed, `HttpOnly`, `Secure`,
/// `SameSite=Strict`, `Path=/`, 120 seconds.
pub fn verifier_cookie(verifier: &[u8; HANDOFF_CODE_BYTES]) -> Cookie<'static> {
    let mut cookie = Cookie::new(product::HANDOFF_COOKIE, URL_SAFE_NO_PAD.encode(verifier));
    cookie.set_path("/");
    cookie.set_http_only(true);
    cookie.set_secure(true);
    cookie.set_same_site(SameSite::Strict);
    cookie.set_max_age(time::Duration::seconds(VERIFIER_TTL_SECS));
    cookie
}

// ------------------------------------------------------------------- purge

/// Deletes the rows whose code has expired. Returns how many it deleted.
pub async fn purge_once(db: &VaultDb, clock: &dyn Clock) -> Result<usize, StoreError> {
    let now = i64::try_from(clock.now_unix()).map_err(|_| StoreError::Invalid("the clock"))?;
    db.with_conn(move |conn| {
        Ok(conn.execute(
            "DELETE FROM ferret_handoffs WHERE expires_at < ?1",
            params![now],
        )?)
    })
    .await
}

/// Deletes expired hand-over rows every minute. Call it once, inside the
/// runtime.
pub fn spawn_purge(db: VaultDb, clock: Arc<dyn Clock>) {
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(PURGE_EVERY);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            ticker.tick().await;
            match purge_once(&db, clock.as_ref()).await {
                Ok(0) => {}
                Ok(removed) => tracing::debug!(removed, "expired hand-over codes removed"),
                Err(error) => tracing::warn!(%error, "expired hand-over codes were not removed"),
            }
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn next_is_cleaned_with_the_kits_rule_and_ours() {
        for (raw, expected) in [
            ("/settings/users", "/settings/users"),
            ("/settings?tab=a", "/settings?tab=a"),
            ("//evil.test", "/"),
            ("/\\evil.test", "/"),
            ("/\t/evil.test", "/"),
            ("/a\nb", "/"),
            ("https://evil.test", "/"),
            ("javascript:alert(1)", "/"),
            ("relative", "/"),
            ("", "/"),
            ("/login", "/"),
            ("/setup?x=1", "/"),
            ("/logout", "/"),
            ("/vault/login", "/"),
            ("/vault", "/"),
            ("/auth/handoff/begin", "/"),
            ("/auth", "/"),
            ("/api/auth/session", "/"),
            ("/apiary", "/apiary"),
            ("/authors", "/authors"),
        ] {
            assert_eq!(sanitize_next(Some(raw)), expected, "{raw:?}");
        }
        assert_eq!(sanitize_next(None), "/");
        assert_eq!(
            sanitize_next(Some(&format!("/{}", "a".repeat(511)))).len(),
            512
        );
        assert_eq!(sanitize_next(Some(&format!("/{}", "a".repeat(512)))), "/");
    }

    #[test]
    fn hashes_compare_by_content() {
        assert!(same_hash(&[7; 32], &[7; 32]));
        let mut other = [7u8; 32];
        other[31] = 8;
        assert!(!same_hash(&[7; 32], &other));
    }

    #[test]
    fn the_verifier_cookie_has_the_promised_attributes() {
        let cookie = verifier_cookie(&[1; HANDOFF_CODE_BYTES]).to_string();
        assert!(cookie.starts_with("__Host-ferret_handoff="), "{cookie}");
        for part in [
            "Max-Age=120",
            "Path=/",
            "HttpOnly",
            "Secure",
            "SameSite=Strict",
        ] {
            assert!(cookie.contains(part), "{part} in {cookie}");
        }
        assert!(!cookie.contains("Domain"), "{cookie}");
    }
}
