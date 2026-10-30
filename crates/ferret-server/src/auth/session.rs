//! Ferret's own sessions: a random session id in `__Host-ferret_sid`, a row in
//! `ferret_sessions` keyed by its hash, and the kit's signed cookie next to it.
//! Both must agree on every request. Spec: Fase 1 § 7.6.
//!
//! * The session id is 32 random bytes ([`SessionSecret`]); only its hash
//!   ([`SidHash`]) is stored, so a copy of the database holds no usable cookie.
//! * The row also holds the `(user_id, issued_at)` that went into the kit's
//!   cookie, and both must match the kit's signed cookie on every request (see
//!   `http::extract`). Two sign-ins in the same second give two rows and two
//!   different session ids.
//! * A row is never reused: signing out sets `revoked_at` and the row stays.
//!
//! Limits ([`limits`]): the vault origin 12 hours idle and 7 days absolute, the
//! admin origin 1 hour idle and 12 hours absolute. They are stricter than the
//! kit's own 30 days and are enforced from the row, not from the cookie.

use axum_extra::extract::cookie::{Cookie, SameSite, SignedCookieJar};
use ferret_core::SecureRng;
use ferret_server_auth::SessionScope;
use rusqlite::types::Type;
use rusqlite::{Connection, OptionalExtension as _, Row, params};
use vole_kit::auth::reauth;
use vole_kit::auth::session::{self as kit_session, SessionClaims};

use crate::ids::{DeviceId, SessionSecret, SidHash};
use crate::product;

/// Seconds without a request after which a vault session ends: 12 hours.
pub const VAULT_IDLE_SECS: i64 = 12 * 60 * 60;
/// Seconds after sign-in after which a vault session ends, however active it
/// is: 7 days.
pub const VAULT_ABSOLUTE_SECS: i64 = 7 * 24 * 60 * 60;
/// Seconds without a request after which an admin session ends: 1 hour.
pub const ADMIN_IDLE_SECS: i64 = 60 * 60;
/// Seconds after sign-in after which an admin session ends: 12 hours.
pub const ADMIN_ABSOLUTE_SECS: i64 = 12 * 60 * 60;

/// The two listeners a session can belong to. A session of one is never valid
/// on the other.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Origin {
    /// The vault listener: the web vault and the vault API.
    Vault,
    /// The admin listener: the kit's admin pages.
    Admin,
}

impl Origin {
    /// The name stored in `ferret_sessions.origin`.
    pub const fn as_str(self) -> &'static str {
        match self {
            Origin::Vault => "vault",
            Origin::Admin => "admin",
        }
    }

    /// The origin for a stored name; anything else is `None`.
    pub fn parse(stored: &str) -> Option<Origin> {
        match stored {
            "vault" => Some(Origin::Vault),
            "admin" => Some(Origin::Admin),
            _ => None,
        }
    }
}

/// How long a session of `origin` may idle and how long it may live in all, in
/// seconds. A session is valid for exactly that long and not a second more.
pub const fn limits(origin: Origin) -> (i64, i64) {
    match origin {
        Origin::Vault => (VAULT_IDLE_SECS, VAULT_ABSOLUTE_SECS),
        Origin::Admin => (ADMIN_IDLE_SECS, ADMIN_ABSOLUTE_SECS),
    }
}

/// A session to insert.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewSession {
    /// The key of the row: the hash of the session id.
    pub sid: SidHash,
    /// The kit user.
    pub user_id: i64,
    /// The sign-in time, the same value as in the kit's claims.
    pub issued_at: i64,
    /// The listener the session is for.
    pub origin: Origin,
    /// The device that signed in.
    pub device: DeviceId,
    /// A name for the device, for the session list.
    pub device_name: String,
    /// What the session may do.
    pub scope: SessionScope,
}

/// A row of `ferret_sessions`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionRow {
    /// The key of the row.
    pub sid: SidHash,
    /// The kit user.
    pub user_id: i64,
    /// The sign-in time.
    pub issued_at: i64,
    /// The listener the session is for.
    pub origin: Origin,
    /// The device that signed in.
    pub device: DeviceId,
    /// The device's name.
    pub device_name: String,
    /// What the session may do; a stored value that is not a known scope reads
    /// as `Unverified`.
    pub scope: SessionScope,
    /// The last time the session was used, to the minute.
    pub last_seen: i64,
    /// When the session was ended, if it was.
    pub revoked_at: Option<i64>,
}

/// Makes a new session: a random session id from `rng`, `issued_at` = `now`,
/// and the kit's claims with exactly the same `issued_at`.
///
/// The secret goes into the cookie ([`session_cookies`]) and nowhere else; the
/// [`NewSession`] goes into the database ([`insert_session`]).
#[allow(
    clippy::too_many_arguments,
    reason = "each argument is a different fact of the sign-in; a struct would only rename them"
)]
pub fn new_session<R: SecureRng>(
    rng: &mut R,
    now: i64,
    user_id: i64,
    session_version: i64,
    origin: Origin,
    device: DeviceId,
    name: &str,
    scope: SessionScope,
) -> (SessionSecret, NewSession, SessionClaims) {
    let secret = SessionSecret::random(rng);
    let claims = SessionClaims::new(user_id, session_version, now);
    let session = NewSession {
        sid: secret.hash(),
        user_id,
        issued_at: claims.issued_at,
        origin,
        device,
        device_name: name.to_string(),
        scope,
    };
    (secret, session, claims)
}

/// Inserts the row. A plain `INSERT`: a session id that exists already is an
/// error, never a silent reuse.
pub fn insert_session(conn: &Connection, s: &NewSession) -> rusqlite::Result<()> {
    conn.execute(
        "INSERT INTO ferret_sessions
           (sid_hash, user_id, issued_at, origin, device_id, device_name, scope, last_seen)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?3)",
        params![
            s.sid.0.as_slice(),
            s.user_id,
            s.issued_at,
            s.origin.as_str(),
            s.device.0.as_slice(),
            s.device_name,
            s.scope.as_str(),
        ],
    )?;
    Ok(())
}

/// The cookies of a new session, added to `jar`:
///
/// * the kit's signed session cookie for `claims`;
/// * `__Host-ferret_sid` with the session id (`HttpOnly`, `Secure`,
///   `SameSite=Strict`, `Path=/`, no `Domain`), signed with the kit's key like
///   the kit's own cookies, so a value that was not issued here never reaches
///   the database lookup;
/// * the kit's pending-second-factor cookie and re-auth grant are removed: a
///   new session starts unconfirmed.
///
/// `secure` is the kit's flag for its own cookies. The session id cookie is
/// always `Secure`: its `__Host-` prefix means a browser drops it otherwise.
pub fn session_cookies(
    jar: SignedCookieJar,
    sid: &SessionSecret,
    claims: &SessionClaims,
    secure: bool,
) -> SignedCookieJar {
    let kit_cookie = kit_session::session_cookie(claims, secure);
    let max_age = kit_cookie.max_age();

    let mut sid_cookie = Cookie::new(product::SID_COOKIE, sid.to_cookie());
    sid_cookie.set_path("/");
    sid_cookie.set_http_only(true);
    sid_cookie.set_secure(true);
    sid_cookie.set_same_site(SameSite::Strict);
    if let Some(max_age) = max_age {
        sid_cookie.set_max_age(max_age);
    }

    let jar = jar
        .add(kit_cookie)
        .remove(removal(product::PENDING_2FA_COOKIE))
        .remove(removal(reauth::cookie_name()));
    jar.add(sid_cookie)
}

/// The cookies that end a session in the browser: the session id, the kit's
/// session cookie, the pending-second-factor cookie and the re-auth grant.
pub fn clear_cookies(jar: SignedCookieJar) -> SignedCookieJar {
    jar.remove(removal(product::SID_COOKIE))
        .remove(removal(product::SESSION_COOKIE))
        .remove(removal(product::PENDING_2FA_COOKIE))
        .remove(removal(reauth::cookie_name()))
}

/// A cookie that, passed to `remove`, deletes `name`. Unlike the kit's, it is
/// `Secure`: a browser ignores a `__Host-` cookie without the flag, deletions
/// included.
fn removal(name: &'static str) -> Cookie<'static> {
    let mut cookie = Cookie::from(name);
    cookie.set_path("/");
    cookie.set_secure(true);
    cookie.set_http_only(true);
    cookie
}

/// Ends the session `sid` at `now`. `true` if a live session was ended, `false`
/// if there is none or it was ended before. The row stays: a session id is not
/// used twice.
pub fn revoke(conn: &Connection, sid: &SidHash, now: i64) -> rusqlite::Result<bool> {
    let changed = conn.execute(
        "UPDATE ferret_sessions SET revoked_at = ?2 WHERE sid_hash = ?1 AND revoked_at IS NULL",
        params![sid.0.as_slice(), now],
    )?;
    Ok(changed > 0)
}

/// Ends every live session of `user_id` at `now`, except `except` if given (the
/// session that asks). Returns how many it ended.
pub fn revoke_all_for_user(
    conn: &Connection,
    user_id: i64,
    now: i64,
    except: Option<&SidHash>,
) -> rusqlite::Result<usize> {
    let keep: Option<&[u8]> = except.map(|sid| sid.0.as_slice());
    conn.execute(
        "UPDATE ferret_sessions SET revoked_at = ?2
         WHERE user_id = ?1 AND revoked_at IS NULL AND (?3 IS NULL OR sid_hash <> ?3)",
        params![user_id, now, keep],
    )
}

/// The row of `sid`, ended or not.
pub fn lookup(conn: &Connection, sid: &SidHash) -> rusqlite::Result<Option<SessionRow>> {
    conn.query_row(
        "SELECT sid_hash, user_id, issued_at, origin, device_id, device_name, scope,
                last_seen, revoked_at
         FROM ferret_sessions WHERE sid_hash = ?1",
        params![sid.0.as_slice()],
        read_row,
    )
    .optional()
}

fn read_row(row: &Row<'_>) -> rusqlite::Result<SessionRow> {
    let origin: String = row.get(3)?;
    let origin = Origin::parse(&origin).ok_or_else(|| {
        rusqlite::Error::FromSqlConversionFailure(3, Type::Text, "unknown origin".into())
    })?;
    let scope: String = row.get(6)?;
    Ok(SessionRow {
        sid: SidHash(fixed(row, 0)?),
        user_id: row.get(1)?,
        issued_at: row.get(2)?,
        origin,
        device: DeviceId(fixed(row, 4)?),
        device_name: row.get(5)?,
        scope: SessionScope::parse_stored(Some(scope.as_str())),
        last_seen: row.get(7)?,
        revoked_at: row.get(8)?,
    })
}

/// A blob column of a fixed length.
fn fixed<const N: usize>(row: &Row<'_>, index: usize) -> rusqlite::Result<[u8; N]> {
    let bytes: Vec<u8> = row.get(index)?;
    <[u8; N]>::try_from(bytes).map_err(|_| {
        rusqlite::Error::FromSqlConversionFailure(index, Type::Blob, "wrong length".into())
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_limits_are_the_stated_ones() {
        assert_eq!(limits(Origin::Vault), (43_200, 604_800));
        assert_eq!(limits(Origin::Admin), (3_600, 43_200));
    }

    #[test]
    fn origin_names_round_trip() {
        for origin in [Origin::Vault, Origin::Admin] {
            assert_eq!(Origin::parse(origin.as_str()), Some(origin));
        }
        assert_eq!(Origin::parse("Vault"), None);
        assert_eq!(Origin::parse(""), None);
    }
}
