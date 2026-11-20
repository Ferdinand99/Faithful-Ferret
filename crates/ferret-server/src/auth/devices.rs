//! The devices of an account: the device row a device client gets when it
//! signs in, the quota, the list of devices and browsers, and revoking them.
//! Spec: Fase 1 § 7.6, § 8.2.
//!
//! A device with tokens has one row in `ferret_devices`, keyed by an id the
//! server gives it and bound to its key's thumbprint (`jkt`), which no other
//! row may have. An account has at most [`crate::wire::MAX_DEVICES`] live
//! devices with tokens. Revoking a device sets `revoked_at`: its tokens stop
//! at once (every lookup goes through the device row) and their hashes are
//! purged [`REVOKED_KEEP_SECS`] later, the device row after that.
//!
//! This module adds a device, revokes one, and says whether one is still
//! valid. The list and its routes come later; [`routes`] serves nothing yet.

use std::fmt;

use axum::Router;
use axum::extract::FromRef;
use ferret_core::SecureRng;
use rusqlite::{Connection, OptionalExtension as _, Transaction, params};

use crate::auth::refresh::ABSOLUTE_SECS;
use crate::ids::DeviceId;
use crate::state::FerretState;
use crate::wire::{MAX_DEVICES, PlatformJson};

/// "Forget old devices" revokes the devices with tokens that were not seen
/// for this long, in seconds.
pub const FORGET_OLD_SECS: i64 = 7 * 86_400;

/// How long the token hashes and the row of a revoked device are kept after
/// it was revoked, in seconds.
pub const REVOKED_KEEP_SECS: i64 = 30 * 86_400;

/// A device to add when a device client signs in.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct NewDevice<'a> {
    /// The account's user (`users.id`).
    pub user_id: i64,
    /// The RFC 7638 thumbprint of the device key, from the sign-in's proof.
    pub jkt: [u8; 32],
    /// The name the device gave: 1 to 64 characters.
    pub name: &'a str,
    /// The platform the device gave.
    pub platform: PlatformJson,
    /// The account's `session_version` now.
    pub session_version: i64,
    /// Now (Unix seconds).
    pub now: i64,
}

impl fmt::Debug for NewDevice<'_> {
    /// Everything but the key's thumbprint.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NewDevice")
            .field("user_id", &self.user_id)
            .field("name", &self.name)
            .field("platform", &self.platform)
            .field("session_version", &self.session_version)
            .field("now", &self.now)
            .finish_non_exhaustive()
    }
}

/// Why a device could not be added.
#[derive(Debug)]
pub enum DeviceInsertError {
    /// The account has [`crate::wire::MAX_DEVICES`] live devices
    /// (`413 quota_exceeded`).
    Quota,
    /// The key's thumbprint is in a device row already (`400 bad_request`).
    KeyInUse,
    /// The database said no.
    Store(rusqlite::Error),
}

/// How often [`touch`] writes `last_seen` at most, in seconds.
pub const TOUCH_EVERY_SECS: i64 = 60;

/// Adds the device of a sign-in and returns the id the server gave it: 16
/// random bytes from `rng`. Call it inside the sign-in's `BEGIN IMMEDIATE`
/// transaction, after the user was read again, so the quota and the key check
/// below cannot race another sign-in.
///
/// * A key whose thumbprint is in any device row, of any account, live or
///   revoked, is refused ([`DeviceInsertError::KeyInUse`]): a client makes a
///   new key for every sign-in.
/// * An account with [`MAX_DEVICES`] live devices is refused
///   ([`DeviceInsertError::Quota`]). Live means not revoked and signed in
///   under the user's `session_version` of now (`new.session_version`); a
///   device of an older version can never be used again and does not count.
///   Browsers (sessions) do not count either.
///
/// Spec: Fase 1 § 7.6 (the device registry), § 8.2 (20 devices per account).
pub fn insert<R: SecureRng>(
    tx: &Transaction<'_>,
    new: &NewDevice<'_>,
    rng: &mut R,
) -> Result<DeviceId, DeviceInsertError> {
    let known: Option<i64> = tx
        .query_row(
            "SELECT 1 FROM ferret_devices WHERE jkt = ?1",
            params![new.jkt.as_slice()],
            |r| r.get(0),
        )
        .optional()
        .map_err(DeviceInsertError::Store)?;
    if known.is_some() {
        return Err(DeviceInsertError::KeyInUse);
    }
    let live: i64 = tx
        .query_row(
            "SELECT COUNT(*) FROM ferret_devices
             WHERE user_id = ?1 AND revoked_at IS NULL AND session_version = ?2",
            params![new.user_id, new.session_version],
            |r| r.get(0),
        )
        .map_err(DeviceInsertError::Store)?;
    if !usize::try_from(live).is_ok_and(|live| live < MAX_DEVICES) {
        return Err(DeviceInsertError::Quota);
    }
    let mut id = [0u8; 16];
    rng.fill(&mut id);
    tx.execute(
        "INSERT INTO ferret_devices
            (device_id, user_id, jkt, name, platform, session_version, created_at, last_seen)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?7)",
        params![
            id.as_slice(),
            new.user_id,
            new.jkt.as_slice(),
            new.name,
            new.platform.as_str(),
            new.session_version,
            new.now,
        ],
    )
    .map_err(DeviceInsertError::Store)?;
    Ok(DeviceId(id))
}

/// Revokes `device` of `user_id` at `now`. It only sets `revoked_at`: the
/// token rows become invalid at once through the device row, which every
/// lookup joins, and the purge deletes them [`REVOKED_KEEP_SECS`] later. So a
/// token from before the revocation is still known, and answers
/// `device_revoked`.
///
/// `false` when the user has no such device or it was revoked already.
///
/// Spec: Fase 1 § 7.6 (revoking a device).
pub fn revoke(
    tx: &Transaction<'_>,
    user_id: i64,
    device: &DeviceId,
    now: i64,
) -> rusqlite::Result<bool> {
    let changed = tx.execute(
        "UPDATE ferret_devices SET revoked_at = ?3
         WHERE device_id = ?1 AND user_id = ?2 AND revoked_at IS NULL",
        params![device.0.as_slice(), user_id, now],
    )?;
    Ok(changed == 1)
}

/// Whether `device` may still be used at `now`: it was not revoked, its user
/// is active with the `session_version` the device signed in under (the kit's
/// sign-out everywhere, a disabled user and a restore all move or stop it),
/// the account has a vault, and the device signed in less than
/// [`ABSOLUTE_SECS`] ago (no token of one sign-in lives longer).
///
/// Spec: Fase 1 § 7.6.
pub fn still_valid(conn: &Connection, device: &DeviceId, now: i64) -> rusqlite::Result<bool> {
    let found: Option<i64> = conn
        .query_row(
            "SELECT 1 FROM ferret_devices d
             JOIN users u ON u.id = d.user_id
             JOIN ferret_accounts a ON a.user_id = u.id
             JOIN ferret_vaults v ON v.account_id = a.account_id
             WHERE d.device_id = ?1
               AND d.revoked_at IS NULL
               AND u.active = 1
               AND u.session_version = d.session_version
               AND d.created_at > ?2",
            params![device.0.as_slice(), now.saturating_sub(ABSOLUTE_SECS)],
            |r| r.get(0),
        )
        .optional()?;
    Ok(found.is_some())
}

/// Notes that `device` was seen at `now`, at most once every
/// [`TOUCH_EVERY_SECS`]: a request in the same minute writes nothing.
pub fn touch(conn: &Connection, device: &DeviceId, now: i64) -> rusqlite::Result<()> {
    conn.execute(
        "UPDATE ferret_devices SET last_seen = ?2
         WHERE device_id = ?1 AND last_seen <= ?3",
        params![
            device.0.as_slice(),
            now,
            now.saturating_sub(TOUCH_EVERY_SECS)
        ],
    )?;
    Ok(())
}

/// The routes of the list of devices and of revoking them, on the vault
/// listener. None are served yet.
pub fn routes<S>() -> Router<S>
where
    S: Clone + Send + Sync + 'static,
    FerretState: FromRef<S>,
{
    Router::new()
}
