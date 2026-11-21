//! Device access tokens: issuing them and looking them up. Spec: Fase 1
//! § 7.6, § 8.2.
//!
//! A device client signs in with OPAQUE and gets an access token that lives
//! [`crate::wire::ACCESS_TOKEN_SECS`] and a refresh token, both 32 random bytes
//! ([`TokenSecret`]) and both bound to the device key (its RFC 7638 thumbprint,
//! `jkt`). The database holds only their hashes. A lookup goes through the
//! device row, so a token of a revoked device answers `device_revoked`, and a
//! device whose account changed its `session_version` (sign out everywhere, a
//! disabled user, a restore) is stopped as well.
//!
//! A restore from a backup deletes every token row and revokes every device
//! ([`invalidate_all_after_restore`]).
//!
//! Every token request answers with a `Date` header from the server's clock
//! ([`with_server_date`]): a device sets the `iat` of its proofs by it, and
//! syncs to it again after a `401 dpop_invalid`.

use std::fmt;
use std::sync::Arc;

use axum::http::HeaderValue;
use axum::http::header::DATE;
use axum::response::Response;
use ferret_core::SecureRng;
use rusqlite::{Connection, OptionalExtension as _, Transaction, params};

use crate::auth::dpop::{JTI_CAPACITY, JTI_PER_KEY, JTI_PER_USER, JtiCache};
use crate::auth::refresh::{ABSOLUTE_SECS, GRACE_CAPACITY, IDLE_SECS, RefreshGrace};
use crate::ids::{DeviceId, TokenHash, TokenSecret};
use crate::wire::ACCESS_TOKEN_SECS;

/// What the token routes and the extractor of a token request share: the cache
/// of used `jti` values, the successors of the grace period, and the vault
/// origin the proofs name in `htu`. `Clone` shares them (the routes take the
/// database and the clock from the state).
#[derive(Clone)]
pub struct DeviceAuth {
    /// The `jti` values used in the window, for the whole process.
    replay: Arc<JtiCache>,
    /// The successors of the grace period, for the whole process.
    grace: Arc<RefreshGrace>,
    /// The configured public origin of the vault listener, without a trailing
    /// `/`.
    vault_origin: Arc<str>,
}

impl DeviceAuth {
    /// The handle with an empty `jti` cache and an empty store of successors,
    /// for proofs whose `htu` starts with `vault_origin` (the configured
    /// origin; a trailing `/` is dropped).
    pub fn new(vault_origin: &str) -> Self {
        Self {
            replay: Arc::new(JtiCache::new(JTI_CAPACITY, JTI_PER_KEY, JTI_PER_USER)),
            grace: Arc::new(RefreshGrace::new(GRACE_CAPACITY)),
            vault_origin: Arc::from(vault_origin.trim_end_matches('/')),
        }
    }

    /// The same handle with another cache of used `jti` values: the successors
    /// and the origin stay shared.
    ///
    /// Tests only: the server has one cache for the whole process, and a
    /// route with a cache of its own would not see the proofs the others
    /// took. No file under `src/` calls it (checked by a test).
    #[doc(hidden)]
    pub fn with_replay(&self, replay: JtiCache) -> Self {
        Self {
            replay: Arc::new(replay),
            ..self.clone()
        }
    }

    /// The cache of used `jti` values, shared by every clone.
    pub fn replay(&self) -> &JtiCache {
        &self.replay
    }

    /// The successors of the grace period, shared by every clone.
    pub fn grace(&self) -> &RefreshGrace {
        &self.grace
    }

    /// The `htu` a proof for `path` must name: the vault origin and the path
    /// exactly as the request has it, without query or fragment (pass the
    /// path alone).
    ///
    /// RFC 9449 § 4.3 (the `htu` matches the URI of the request, without query
    /// and fragment).
    pub fn htu(&self, path: &str) -> Htu {
        Htu(format!("{}{path}", self.vault_origin))
    }
}

/// The `htu` a proof must name: the configured vault origin and the path of
/// the request. Only [`DeviceAuth::htu`] makes one, so no route can build it
/// from `Host`, a forwarded host or anything else the request says.
///
/// RFC 9449 § 4.3; Spec: Fase 1 § 7.6.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Htu(String);

impl Htu {
    /// The URL as text.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for DeviceAuth {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("DeviceAuth([redacted])")
    }
}

/// The tokens of one sign-in or one renewal, as they go to the device once.
pub struct IssuedTokens {
    /// The access token.
    pub access: TokenSecret,
    /// The refresh token.
    pub refresh: TokenSecret,
    /// Seconds until the access token expires.
    pub expires_in: u32,
}

impl fmt::Debug for IssuedTokens {
    /// The lifetime only: the tokens are secrets.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("IssuedTokens")
            .field("expires_in", &self.expires_in)
            .finish_non_exhaustive()
    }
}

/// What an access token is, looked up through its device.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AccessLookup {
    /// A live token of a live device.
    Live(AccessRow),
    /// No such token, or it expired (`401 token_expired`).
    Expired,
    /// The token's device was revoked (`401 device_revoked`). The hashes of
    /// a revoked device are kept for a while, so its tokens are still known.
    DeviceRevoked,
}

/// A live access token: its device, the account, the key it is bound to, when
/// it expires, and the `session_version` the device signed in under.
#[derive(Clone, PartialEq, Eq)]
pub struct AccessRow {
    /// The device.
    pub device: DeviceId,
    /// The account's user (`users.id`).
    pub user_id: i64,
    /// The RFC 7638 thumbprint of the device key.
    pub jkt: [u8; 32],
    /// When the token expires (Unix seconds).
    pub expires_at: i64,
    /// The account's `session_version` when the device signed in.
    pub session_version: i64,
}

impl fmt::Debug for AccessRow {
    /// Everything but the key's thumbprint.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AccessRow")
            .field("device", &self.device)
            .field("user_id", &self.user_id)
            .field("expires_at", &self.expires_at)
            .field("session_version", &self.session_version)
            .finish_non_exhaustive()
    }
}

/// The tokens of a device that just signed in: an access token that lives
/// [`ACCESS_TOKEN_SECS`] and the first refresh token of its chain, which lives
/// [`IDLE_SECS`] without use and [`ABSOLUTE_SECS`] at most. Only their hashes
/// are written. Call it in the sign-in's transaction, after
/// `devices::insert`.
///
/// Spec: Fase 1 § 7.6.
pub fn issue_for_new_device<R: SecureRng>(
    tx: &Transaction<'_>,
    device: &DeviceId,
    now: i64,
    rng: &mut R,
) -> rusqlite::Result<IssuedTokens> {
    let access = issue_access(tx, device, now, rng)?;
    let refresh = TokenSecret::random(rng);
    tx.execute(
        "INSERT INTO ferret_refresh
            (token_hash, device_id, prev_hash, issued_at, idle_expires_at, abs_expires_at, used_at)
         VALUES (?1, ?2, NULL, ?3, ?4, ?5, NULL)",
        params![
            refresh.hash().0.as_slice(),
            device.0.as_slice(),
            now,
            now.saturating_add(IDLE_SECS),
            now.saturating_add(ABSOLUTE_SECS),
        ],
    )?;
    Ok(IssuedTokens {
        access,
        refresh,
        expires_in: ACCESS_TOKEN_SECS,
    })
}

/// A new access token for `device`, which expires [`ACCESS_TOKEN_SECS`] after
/// `now`. Only its hash is written.
///
/// Spec: Fase 1 § 7.6 (short-lived access tokens).
pub fn issue_access<R: SecureRng>(
    tx: &Transaction<'_>,
    device: &DeviceId,
    now: i64,
    rng: &mut R,
) -> rusqlite::Result<TokenSecret> {
    let access = TokenSecret::random(rng);
    tx.execute(
        "INSERT INTO ferret_access (token_hash, device_id, expires_at) VALUES (?1, ?2, ?3)",
        params![
            access.hash().0.as_slice(),
            device.0.as_slice(),
            now.saturating_add(i64::from(ACCESS_TOKEN_SECS)),
        ],
    )?;
    Ok(access)
}

/// What the access token with `hash` is at `now`, through its device: the
/// device was revoked → [`AccessLookup::DeviceRevoked`] (also for a token that
/// has expired since); no such token, or it expired (`now` is at or past its
/// `expires_at`) → [`AccessLookup::Expired`]; else the live row.
///
/// The row says nothing about the user: the caller checks the device with
/// `devices::still_valid` as well.
///
/// Spec: Fase 1 § 7.6.
pub fn lookup_access(
    conn: &Connection,
    hash: &TokenHash,
    now: i64,
) -> rusqlite::Result<AccessLookup> {
    type Found = (Vec<u8>, i64, i64, Vec<u8>, i64, Option<i64>);
    let found: Option<Found> = conn
        .query_row(
            "SELECT a.device_id, a.expires_at, d.user_id, d.jkt, d.session_version, d.revoked_at
             FROM ferret_access a JOIN ferret_devices d ON d.device_id = a.device_id
             WHERE a.token_hash = ?1",
            params![hash.0.as_slice()],
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
    let Some((device, expires_at, user_id, jkt, session_version, revoked_at)) = found else {
        return Ok(AccessLookup::Expired);
    };
    if revoked_at.is_some() {
        return Ok(AccessLookup::DeviceRevoked);
    }
    if now >= expires_at {
        return Ok(AccessLookup::Expired);
    }
    let bad = |index: usize, what: &str| {
        rusqlite::Error::FromSqlConversionFailure(
            index,
            rusqlite::types::Type::Blob,
            what.to_string().into(),
        )
    };
    let device = <[u8; 16]>::try_from(device).map_err(|_| bad(0, "device id"))?;
    let jkt = <[u8; 32]>::try_from(jkt).map_err(|_| bad(3, "jkt"))?;
    Ok(AccessLookup::Live(AccessRow {
        device: DeviceId(device),
        user_id,
        jkt,
        expires_at,
        session_version,
    }))
}

/// After the database was restored from a backup, in the caller's
/// transaction: deletes every access token and every refresh token of every
/// device, and revokes every device that was not revoked yet (`revoked_at` =
/// `now`). Returns how many devices it revoked and how many token rows it
/// deleted.
///
/// A backup holds the token hashes that were live when it was taken. Unlike a
/// single revocation, which keeps the hashes so a later use of them answers
/// `device_revoked`, a restore removes them all: a token that was used, renewed
/// or revoked since the backup must not come back to life, and the rows of the
/// backup say nothing true about the tokens of now. Every device signs in
/// again with the master password.
///
/// Spec: Fase 1 § 7.6 and § 11 (backups).
pub fn invalidate_all_after_restore(
    tx: &Transaction<'_>,
    now: i64,
) -> rusqlite::Result<(usize, usize)> {
    let access = tx.execute("DELETE FROM ferret_access", [])?;
    let refresh = tx.execute("DELETE FROM ferret_refresh", [])?;
    let devices = tx.execute(
        "UPDATE ferret_devices SET revoked_at = ?1 WHERE revoked_at IS NULL",
        params![now.max(0)],
    )?;
    Ok((devices, access.saturating_add(refresh)))
}

/// `response` with a `Date` header of the server's clock at `now` (Unix
/// seconds), in place of any it had. A device sets the `iat` of its proofs by
/// this clock and syncs to it after a `401 dpop_invalid`, so the header must
/// be the clock the proofs are checked against. Without a date (a time past
/// the year 9999), the response is left as it is.
///
/// RFC 9110 § 6.6.1 (`Date`), § 5.6.7 (IMF-fixdate).
pub fn with_server_date(mut response: Response, now: i64) -> Response {
    if let Some(date) = http_date(now) {
        response.headers_mut().insert(DATE, date);
    }
    response
}

/// `now` (Unix seconds) as an IMF-fixdate: `Sun, 06 Nov 1994 08:49:37 GMT`.
fn http_date(now: i64) -> Option<HeaderValue> {
    const DAYS: [&str; 7] = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"];
    const MONTHS: [&str; 12] = [
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    ];
    let at = time::OffsetDateTime::from_unix_timestamp(now).ok()?;
    if !(0..=9999).contains(&at.year()) {
        return None;
    }
    let day = DAYS.get(usize::from(at.weekday().number_days_from_monday()))?;
    let month = MONTHS.get(usize::from(u8::from(at.month())).checked_sub(1)?)?;
    let text = format!(
        "{day}, {:02} {month} {:04} {:02}:{:02}:{:02} GMT",
        at.day(),
        at.year(),
        at.hour(),
        at.minute(),
        at.second()
    );
    HeaderValue::from_str(&text).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_date_is_an_imf_fixdate() {
        // RFC 9110 § 5.6.7's own example.
        assert_eq!(
            http_date(784_111_777).expect("a date"),
            "Sun, 06 Nov 1994 08:49:37 GMT"
        );
        assert_eq!(
            http_date(0).expect("a date"),
            "Thu, 01 Jan 1970 00:00:00 GMT"
        );
        assert_eq!(
            http_date(1_793_491_200).expect("a date"),
            "Sun, 01 Nov 2026 00:00:00 GMT"
        );
        assert_eq!(http_date(253_402_300_800), None, "the year 10000");
    }
}
