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
//! kit's own 30 days and are enforced from the row, not from the cookie. A
//! session of the scope `account_reset` (opened by a sign-in code) lives 30
//! minutes at most ([`RESET_SESSION_ABSOLUTE_SECS`]).
//!
//! Ending sessions in bulk: [`end_all_credentials`] ends every session and
//! every device with tokens of one user (after a change of the master
//! password, a recovery, a redeemed sign-in code or "revoke all devices"),
//! [`end_device_sessions`] ends the sessions of one browser, and
//! [`end_everything_after_restore`] ends every session, every pending sign-in
//! step, every pending invitation and every device token of every user after
//! the database was restored from a backup, and writes `server_restored` to the
//! log of every account. All run in the caller's transaction.

use axum_extra::extract::cookie::{Cookie, SameSite, SignedCookieJar};
use ferret_core::SecureRng;
use ferret_server_auth::SessionScope;
use rusqlite::types::Type;
use rusqlite::{Connection, OptionalExtension as _, Row, Transaction, params};
use vole_kit::auth::reauth;
use vole_kit::auth::session::{self as kit_session, SessionClaims};

use crate::accounts::log;
use crate::auth::{devices, tokens};
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
/// Seconds for which proving the master password again (a sign-in with
/// `purpose: "reauth"`) makes the session fresh for a sensitive operation:
/// 5 minutes. Spec: Fase 1 § 4.6 (a).
pub const REAUTH_SECS: i64 = 300;
/// Seconds after sign-in after which a session of the scope `account_reset`
/// ends, however active it is: 30 minutes. A short window for a session that
/// can replace the account's sign-in.
pub const RESET_SESSION_ABSOLUTE_SECS: i64 = 30 * 60;

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

/// Whether `row` is within the limits of its origin at `now`: not idle for
/// longer than the idle limit and not older than the absolute limit. Both
/// limits are inclusive. A session of the scope `account_reset` is also never
/// older than [`RESET_SESSION_ABSOLUTE_SECS`].
pub fn within_limits(row: &SessionRow, now: i64) -> bool {
    let (idle, origin_absolute) = limits(row.origin);
    let absolute = if row.scope == SessionScope::AccountReset {
        origin_absolute.min(RESET_SESSION_ABSOLUTE_SECS)
    } else {
        origin_absolute
    };
    now.saturating_sub(row.last_seen).max(0) <= idle
        && now.saturating_sub(row.issued_at).max(0) <= absolute
}

/// Whether the session of `row` proved the master password again recently
/// enough for a sensitive operation at `now`: `0 <= now - reauth_at <= 300`.
/// Both ends are inclusive: 300 seconds after the re-authentication the
/// session is still fresh, 301 seconds after it is not. A clock that reads
/// before `reauth_at` is not fresh, and a session that never re-authenticated
/// is never fresh. An operation does not use the freshness up.
///
/// Where this reads more into the spec text than it says: § 4.6 (a) asks for
/// the master password again within 5 minutes. Here only a sign-in with
/// `purpose: "reauth"` in this session counts (an ordinary sign-in does not),
/// and the freshness lasts the whole 5 minutes, for any number of operations.
///
/// Spec: Fase 1 § 4.6 (a).
pub fn reauth_fresh(row: &SessionRow, now: i64) -> bool {
    row.reauth_at
        .and_then(|at| now.checked_sub(at))
        .is_some_and(|age| (0..=REAUTH_SECS).contains(&age))
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
    /// When this session last proved the master password again (a sign-in
    /// with `purpose: "reauth"`), if it ever did. The value lives in this
    /// session's own row, so the freshness belongs to this session and to no
    /// other one of the same user.
    pub reauth_at: Option<i64>,
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
///
/// Both cookies live as long as the kit's session cookie. For a session of
/// another scope than `full` use [`scoped_session_cookies`].
pub fn session_cookies(
    jar: SignedCookieJar,
    sid: &SessionSecret,
    claims: &SessionClaims,
    secure: bool,
) -> SignedCookieJar {
    scoped_session_cookies(jar, sid, claims, secure, SessionScope::Full)
}

/// [`session_cookies`] for a session of `scope`: a session of the scope
/// `account_reset` gets cookies that live [`RESET_SESSION_ABSOLUTE_SECS`] at
/// most, the same as the session itself, so a browser stops sending them when
/// the server stops taking them.
pub fn scoped_session_cookies(
    jar: SignedCookieJar,
    sid: &SessionSecret,
    claims: &SessionClaims,
    secure: bool,
    scope: SessionScope,
) -> SignedCookieJar {
    let mut kit_cookie = kit_session::session_cookie(claims, secure);
    if scope == SessionScope::AccountReset {
        let cap = time::Duration::seconds(RESET_SESSION_ABSOLUTE_SECS);
        let max_age = kit_cookie.max_age().map_or(cap, |kit| kit.min(cap));
        kit_cookie.set_max_age(max_age);
    }
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
pub(crate) fn removal(name: &'static str) -> Cookie<'static> {
    let mut cookie = Cookie::from(name);
    cookie.set_path("/");
    cookie.set_secure(true);
    cookie.set_http_only(true);
    cookie
}

/// Ends the session `sid` at `now`, and every session that was handed over
/// from it (the admin sessions made from a vault session: signing out of the
/// vault signs out of the admin pages that came from it; the other way round
/// ends only the admin session). `true` if a live session `sid` was ended,
/// `false` if there is none or it was ended before. The rows stay: a session id
/// is not used twice.
pub fn revoke(conn: &Connection, sid: &SidHash, now: i64) -> rusqlite::Result<bool> {
    let changed = conn.execute(
        "UPDATE ferret_sessions SET revoked_at = ?2 WHERE sid_hash = ?1 AND revoked_at IS NULL",
        params![sid.0.as_slice(), now],
    )?;
    // Also when `sid` was ended before: the children of a row that an earlier
    // version of the code ended are ended now.
    conn.execute(
        "UPDATE ferret_sessions SET revoked_at = ?2 WHERE parent_sid = ?1 AND revoked_at IS NULL",
        params![sid.0.as_slice(), now],
    )?;
    Ok(changed > 0)
}

/// Records that session `child` was handed over from session `parent`, so that
/// [`revoke`] of the parent ends the child too.
pub fn set_parent(conn: &Connection, child: &SidHash, parent: &SidHash) -> rusqlite::Result<()> {
    conn.execute(
        "UPDATE ferret_sessions SET parent_sid = ?2 WHERE sid_hash = ?1",
        params![child.0.as_slice(), parent.0.as_slice()],
    )?;
    Ok(())
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

/// Records that the session `sid` proved the master password again at `now`
/// (a sign-in with `purpose: "reauth"`), which makes it fresh for a sensitive
/// operation for [`REAUTH_SECS`] seconds ([`reauth_fresh`]). Only a live,
/// `full` session of the vault origin is marked: `false` for any other row and
/// for no row at all, and nothing is written then. The time goes into this
/// session's row only, so no other session of the user becomes fresh.
///
/// The caller checks the session in the same transaction
/// ([`still_valid`]): a session that ended, or whose user was disabled or
/// signed out everywhere, between the proof and this write is not marked.
///
/// Spec: Fase 1 § 4.6 (a).
pub fn mark_reauth(conn: &Connection, sid: &SidHash, now: i64) -> rusqlite::Result<bool> {
    if now < 0 {
        return Ok(false);
    }
    let changed = conn.execute(
        "UPDATE ferret_sessions SET reauth_at = ?2
         WHERE sid_hash = ?1 AND revoked_at IS NULL AND origin = 'vault' AND scope = 'full'",
        params![sid.0.as_slice(), now],
    )?;
    Ok(changed > 0)
}

/// What a bulk end of credentials ended: the sessions (each once) and the
/// devices with tokens. The caller announces each of them after the commit
/// (`SyncEvents::announce_ended`), and not before: a stream that wakes up must
/// find its row ended.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Ended {
    /// The sessions that ended.
    pub sessions: Vec<SidHash>,
    /// The devices with tokens that were revoked.
    pub devices: Vec<DeviceId>,
}

impl Ended {
    /// Whether the session `sid` is among the ended ones.
    pub fn contains(&self, sid: &SidHash) -> bool {
        self.sessions.contains(sid)
    }

    /// How many sessions and devices ended.
    pub fn len(&self) -> usize {
        self.sessions.len().saturating_add(self.devices.len())
    }

    /// Whether nothing ended.
    pub fn is_empty(&self) -> bool {
        self.sessions.is_empty() && self.devices.is_empty()
    }

    /// Sorts both lists and drops repeats, so each credential is announced
    /// once.
    pub fn dedup(&mut self) {
        self.sessions.sort_unstable_by_key(|sid| sid.0);
        self.sessions.dedup();
        self.devices.sort_unstable_by_key(|device| device.0);
        self.devices.dedup();
    }
}

/// Ends every live session of `user_id` at `now`, on both origins, except the
/// session `keep` if given, in the caller's transaction. A session that was
/// handed over from an ended one ends with it, whoever it belongs to (the
/// hand-over only ever makes a session for the same user). In the same
/// transaction every device of the user with tokens is revoked
/// (`devices::revoke_all_for_user`): its tokens are invalid at once, since
/// every token lookup goes through the device row. Returns every session and
/// device it ended, so the caller can announce each one after the commit, and
/// not before: a stream that wakes up must find its row ended.
///
/// The user's pending sign-in codes are revoked too: each caller settles how
/// the user signs in, and the kit's rule is that such a change ends a code
/// made before it.
///
/// Used after a change of the master password, a recovery, a redeemed
/// sign-in code and "revoke all devices". `keep` is a browser session only:
/// no device with tokens is ever kept.
///
/// Spec: Fase 1 § 4.6 (after an MP change, recovery and rekey: all other
/// sessions and device tokens are revoked) and § 7.6.
pub fn end_all_credentials(
    tx: &Transaction<'_>,
    user_id: i64,
    keep: Option<&SidHash>,
    now: i64,
) -> rusqlite::Result<Ended> {
    vole_kit::db::sign_in_codes::revoke_for_user(tx, user_id)?;
    let devices = devices::revoke_all_for_user(tx, user_id, now)?;
    let keep: Option<&[u8]> = keep.map(|sid| sid.0.as_slice());
    let mut ended = returning_sids(
        tx,
        "UPDATE ferret_sessions SET revoked_at = ?2
         WHERE user_id = ?1 AND revoked_at IS NULL AND (?3 IS NULL OR sid_hash <> ?3)
         RETURNING sid_hash",
        params![user_id, now, keep],
    )?;
    // The children of every session of the user other than `keep`, also of a
    // session that had ended before: a child must never outlive its parent.
    let children = returning_sids(
        tx,
        "UPDATE ferret_sessions SET revoked_at = ?2
         WHERE revoked_at IS NULL AND (?3 IS NULL OR sid_hash <> ?3)
           AND parent_sid IN (
               SELECT sid_hash FROM ferret_sessions
               WHERE user_id = ?1 AND (?3 IS NULL OR sid_hash <> ?3))
         RETURNING sid_hash",
        params![user_id, now, keep],
    )?;
    ended.extend(children);
    let mut ended = Ended {
        sessions: ended,
        devices,
    };
    ended.dedup();
    Ok(ended)
}

/// Ends every live session of `user_id` from the browser `device` (on both
/// origins) at `now`, except the session `keep` if given and the sessions
/// handed over from it (its admin sessions, which carry its device id too), and
/// every session handed over from one of the others, in the caller's
/// transaction. Returns the ids of the sessions it ended, each once, for the
/// caller to announce after the commit.
///
/// A browser is a device of the list through its sessions: they all carry the
/// `device_id` the browser chose. Only the sessions of `user_id` are touched,
/// whatever another user's browser calls itself.
///
/// Spec: Fase 1 § 7.6 (revoking a device).
pub fn end_device_sessions(
    tx: &Transaction<'_>,
    user_id: i64,
    device: &DeviceId,
    keep: Option<&SidHash>,
    now: i64,
) -> rusqlite::Result<Vec<SidHash>> {
    let keep: Option<&[u8]> = keep.map(|sid| sid.0.as_slice());
    let mut ended = returning_sids(
        tx,
        "UPDATE ferret_sessions SET revoked_at = ?3
         WHERE user_id = ?1 AND device_id = ?2 AND revoked_at IS NULL
           AND (?4 IS NULL OR sid_hash <> ?4)
           AND (?4 IS NULL OR parent_sid IS NULL OR parent_sid <> ?4)
         RETURNING sid_hash",
        params![user_id, device.0.as_slice(), now, keep],
    )?;
    // The children of every other session of that browser, also of one that
    // had ended before: a child must never outlive its parent.
    let children = returning_sids(
        tx,
        "UPDATE ferret_sessions SET revoked_at = ?3
         WHERE revoked_at IS NULL AND (?4 IS NULL OR sid_hash <> ?4)
           AND parent_sid IN (
               SELECT sid_hash FROM ferret_sessions
               WHERE user_id = ?1 AND device_id = ?2 AND (?4 IS NULL OR sid_hash <> ?4))
         RETURNING sid_hash",
        params![user_id, device.0.as_slice(), now, keep],
    )?;
    ended.extend(children);
    ended.sort_unstable_by_key(|sid| sid.0);
    ended.dedup();
    Ok(ended)
}

/// The live sessions of `user_id` on `origin` at `now`: not revoked and
/// within the limits of their origin ([`within_limits`]), of any scope. For
/// the list of devices, which groups them by browser.
pub fn live_sessions(
    conn: &Connection,
    user_id: i64,
    origin: Origin,
    now: i64,
) -> rusqlite::Result<Vec<SessionRow>> {
    let mut statement = conn.prepare(
        "SELECT sid_hash, user_id, issued_at, origin, device_id, device_name, scope,
                last_seen, revoked_at, reauth_at
         FROM ferret_sessions
         WHERE user_id = ?1 AND origin = ?2 AND revoked_at IS NULL",
    )?;
    let rows = statement.query_map(params![user_id, origin.as_str()], read_row)?;
    let mut live = Vec::new();
    for row in rows {
        let row = row?;
        if within_limits(&row, now) {
            live.push(row);
        }
    }
    Ok(live)
}

/// What [`end_everything_after_restore`] ended or removed, as counts.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct RestoreSweep {
    /// Sessions that were live and are ended now.
    pub sessions: usize,
    /// Hand-over codes (vault to admin) that were removed.
    pub handoffs: usize,
    /// Pending OPAQUE sign-in states that were removed.
    pub login_states: usize,
    /// Pending registrations that were removed.
    pub registrations: usize,
    /// Pending sign-in codes that were revoked.
    pub sign_in_codes: usize,
    /// Pending invitations that were revoked.
    pub invites: usize,
    /// Users whose `session_version` was raised.
    pub users: usize,
    /// Events `server_restored` written to the account log (one per account).
    pub logged: usize,
    /// Devices with tokens that were revoked.
    pub devices: usize,
    /// Token rows (access and refresh) that were deleted.
    pub tokens: usize,
}

/// After the database was restored from a backup, in the caller's
/// transaction: ends every session of every user on both origins, removes
/// every hand-over code, pending sign-in state and pending registration,
/// revokes every sign-in code and every invitation that is neither used nor
/// revoked (an expired one too, whatever the clock says), and raises every
/// user's `session_version`, so a cookie of the kit's (a session or a re-auth
/// grant) made before the restore is no good either. Every device token is
/// deleted and every device with tokens revoked
/// (`tokens::invalidate_all_after_restore`), and every account gets the event
/// `server_restored` (actor `server`) in its log, in the same transaction.
///
/// A backup holds the sessions, codes, invitations and token hashes that were
/// live when it was taken. Without this, a session that was ended, a code
/// that was used, an invitation that was revoked or a token that was renewed
/// or revoked since would come back to life with the restore.
///
/// Spec: Fase 1 § 11 (backups, "Several accounts": backup and restore) and
/// § 7.6.
pub fn end_everything_after_restore(
    tx: &Transaction<'_>,
    now: i64,
) -> rusqlite::Result<RestoreSweep> {
    let sessions = tx.execute(
        "UPDATE ferret_sessions SET revoked_at = ?1 WHERE revoked_at IS NULL",
        params![now],
    )?;
    let handoffs = tx.execute("DELETE FROM ferret_handoffs", [])?;
    let login_states = tx.execute("DELETE FROM ferret_login_states", [])?;
    let registrations = tx.execute("DELETE FROM ferret_registrations", [])?;
    let sign_in_codes = tx.execute(
        "UPDATE sign_in_codes SET revoked_at = datetime('now')
         WHERE used_at IS NULL AND revoked_at IS NULL",
        [],
    )?;
    let invites = tx.execute(
        "UPDATE invites SET revoked_at = datetime('now')
         WHERE used_at IS NULL AND revoked_at IS NULL",
        [],
    )?;
    let users = tx.execute("UPDATE users SET session_version = session_version + 1", [])?;
    let (devices, tokens) = tokens::invalidate_all_after_restore(tx, now)?;
    let logged = log::record_restored_for_all(tx, now)?;
    Ok(RestoreSweep {
        sessions,
        handoffs,
        login_states,
        registrations,
        sign_in_codes,
        invites,
        users,
        logged,
        devices,
        tokens,
    })
}

/// Runs an `UPDATE ... RETURNING sid_hash` and collects the session ids.
fn returning_sids(
    conn: &Connection,
    sql: &str,
    params: impl rusqlite::Params,
) -> rusqlite::Result<Vec<SidHash>> {
    let mut statement = conn.prepare(sql)?;
    let rows = statement.query_map(params, |r| fixed::<32>(r, 0).map(SidHash))?;
    rows.collect()
}

/// The row of `sid`, ended or not.
pub fn lookup(conn: &Connection, sid: &SidHash) -> rusqlite::Result<Option<SessionRow>> {
    conn.query_row(
        "SELECT sid_hash, user_id, issued_at, origin, device_id, device_name, scope,
                last_seen, revoked_at, reauth_at
         FROM ferret_sessions WHERE sid_hash = ?1",
        params![sid.0.as_slice()],
        read_row,
    )
    .optional()
}

/// Whether the session `sid` is still one at `now`: the same rules as the
/// `VaultSession` and `AdminSession` extractors, minus the cookies (a caller
/// that holds a stream open has no cookie to look at, and the kit's cookie
/// is sealed from it). The row exists and is not revoked, belongs to `origin`,
/// has the scope `full` and is within the limits of its origin; its user exists
/// and is active, and the user's `session_version` is `expected_version`; for
/// the vault origin the user has an account with a vault. Reads only: it does
/// not touch `last_seen`.
///
/// A database error is an error here, never `true`.
///
/// Spec: Fase 1 § 7.6.
pub fn still_valid(
    conn: &Connection,
    sid: &SidHash,
    origin: Origin,
    expected_version: i64,
    now: i64,
) -> rusqlite::Result<bool> {
    let Some(row) = lookup(conn, sid)? else {
        return Ok(false);
    };
    if row.revoked_at.is_some()
        || row.origin != origin
        || row.scope != SessionScope::Full
        || !within_limits(&row, now)
    {
        return Ok(false);
    }
    let user: Option<(i64, bool)> = conn
        .query_row(
            "SELECT session_version, active FROM users WHERE id = ?1",
            params![row.user_id],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .optional()?;
    match user {
        Some((version, true)) if version == expected_version => {}
        _ => return Ok(false),
    }
    if origin == Origin::Vault {
        // Only that the user has an account with a vault, as the extractor
        // reads it: a user has one account and so one vault, and the vault of
        // a stream is the one the extractor found with this same join. A caller
        // that needs the vault itself reads it by id (the event stream reads
        // its sequence number from it in the same call).
        let account: Option<i64> = conn
            .query_row(
                "SELECT 1 FROM ferret_accounts a
                 JOIN ferret_vaults v ON v.account_id = a.account_id
                 WHERE a.user_id = ?1",
                params![row.user_id],
                |r| r.get(0),
            )
            .optional()?;
        if account.is_none() {
            return Ok(false);
        }
    }
    Ok(true)
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
        reauth_at: row.get(9)?,
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
