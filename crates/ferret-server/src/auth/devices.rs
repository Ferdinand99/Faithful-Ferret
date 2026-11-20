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
//! This module adds a device, revokes one or all, and says whether one is
//! still valid. Its [`routes`] are the page "Devices" of the web vault: the
//! list of the devices with tokens and of the browsers with a session, the
//! revocation of one, "revoke all" (after the master password again) and
//! "forget old devices". They take the web vault's cookie session only: a
//! device with tokens never reaches them.
//!
//! Revoking takes the server's access away and nothing else: a revoked device
//! keeps what it already holds (the vault key and its cache) until a full
//! rekey (spec § 7.6).

use std::collections::BTreeMap;
use std::fmt;

use axum::Json;
use axum::Router;
use axum::extract::{FromRef, FromRequestParts as _, Path, State};
use axum::http::StatusCode;
use axum::http::request::Parts;
use axum::response::{IntoResponse, Response};
use axum::routing::{delete, get, post};
use ferret_core::SecureRng;
use rusqlite::{Connection, OptionalExtension as _, Transaction, TransactionBehavior, params};

use crate::auth::login::no_store;
use crate::auth::refresh::ABSOLUTE_SECS;
use crate::auth::session::{self, Ended, Origin, SessionRow};
use crate::error::{ApiError, StoreError};
use crate::http::extract::{FreshReauth, ScopedSession, VaultSession, caps};
use crate::ids::{DeviceId, SidHash};
use crate::state::FerretState;
use crate::vault::notify::SyncEvents;
use crate::wire::{
    DeviceJson, DeviceKindJson, DevicesRes, MAX_DEVICE_LIST, MAX_DEVICES, PlatformJson,
    RevokeAllRes, hex16,
};

/// The list of devices: `GET`.
pub const DEVICES_PATH: &str = "/api/auth/devices";
/// Revoke one device or browser: `DELETE`, with the id.
pub const DEVICE_PATH: &str = "/api/auth/devices/{id}";
/// Revoke every device and every other browser: `POST`.
pub const REVOKE_ALL_PATH: &str = "/api/auth/devices/revoke-all";
/// Revoke the devices with tokens not seen for [`FORGET_OLD_SECS`]: `POST`.
pub const FORGET_OLD_PATH: &str = "/api/auth/devices/forget-old";

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
///   ([`DeviceInsertError::Quota`]). Live means what [`still_valid`] accepts:
///   not revoked, signed in under the user's `session_version` of now
///   (`new.session_version`) and less than [`ABSOLUTE_SECS`] ago. A device
///   that can never be used again does not count. Browsers (sessions) do not
///   count either.
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
             WHERE user_id = ?1 AND revoked_at IS NULL AND session_version = ?2
               AND created_at > ?3",
            params![
                new.user_id,
                new.session_version,
                new.now.saturating_sub(ABSOLUTE_SECS)
            ],
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

/// Revokes every device of `user_id` with tokens that is not revoked yet, at
/// `now`, in the caller's transaction, and returns their ids for the caller to
/// announce after the commit. Like [`revoke`] it only sets `revoked_at`: every
/// token of those devices is invalid at once and answers `device_revoked`.
/// A device the account no longer accepts (signed in under an older
/// `session_version`, or too long ago) is revoked too, so it leaves the list
/// and the quota.
///
/// Spec: Fase 1 § 4.6 (all device tokens are revoked after an MP change and
/// a recovery; "revoke all devices") and § 7.6.
pub fn revoke_all_for_user(
    tx: &Transaction<'_>,
    user_id: i64,
    now: i64,
) -> rusqlite::Result<Vec<DeviceId>> {
    returning_devices(
        tx,
        "UPDATE ferret_devices SET revoked_at = ?2
         WHERE user_id = ?1 AND revoked_at IS NULL
         RETURNING device_id",
        params![user_id, now.max(0)],
    )
}

/// "Forget old devices": revokes every device of `user_id` with tokens that
/// is not revoked yet and was last seen [`FORGET_OLD_SECS`] or more before
/// `now`, in the caller's transaction, and returns their ids for the caller
/// to announce after the commit. Browsers are not touched: their sessions end
/// by themselves after 12 hours without use.
///
/// Spec: Fase 1 § 8.2 (20 devices per account: a full account can make room).
pub fn forget_old(tx: &Transaction<'_>, user_id: i64, now: i64) -> rusqlite::Result<Vec<DeviceId>> {
    returning_devices(
        tx,
        "UPDATE ferret_devices SET revoked_at = ?2
         WHERE user_id = ?1 AND revoked_at IS NULL AND last_seen <= ?3
         RETURNING device_id",
        params![user_id, now.max(0), now.saturating_sub(FORGET_OLD_SECS)],
    )
}

/// Runs an `UPDATE ... RETURNING device_id` and collects the ids, each once.
fn returning_devices(
    conn: &Connection,
    sql: &str,
    params: impl rusqlite::Params,
) -> rusqlite::Result<Vec<DeviceId>> {
    let mut statement = conn.prepare(sql)?;
    let rows = statement.query_map(params, |r| {
        let bytes: Vec<u8> = r.get(0)?;
        <[u8; 16]>::try_from(bytes).map(DeviceId).map_err(|_| {
            rusqlite::Error::FromSqlConversionFailure(
                0,
                rusqlite::types::Type::Blob,
                "wrong length".into(),
            )
        })
    })?;
    let mut ids = rows.collect::<rusqlite::Result<Vec<_>>>()?;
    ids.sort_unstable_by_key(|device| device.0);
    ids.dedup();
    Ok(ids)
}

/// One row of the list as it is read, before it is cut and written.
struct Listed {
    id: [u8; 16],
    kind: DeviceKindJson,
    name: String,
    platform: Option<PlatformJson>,
    created_at: i64,
    last_seen: i64,
    current: bool,
}

impl Listed {
    fn json(self) -> DeviceJson {
        DeviceJson {
            id: self.id,
            kind: self.kind,
            name: self.name,
            platform: self.platform,
            created_at: u64::try_from(self.created_at).unwrap_or(0),
            last_seen: u64::try_from(self.last_seen).unwrap_or(0),
            current: self.current,
        }
    }
}

/// The list of devices of `user_id` at `now`, for the session `current`
/// (the session that asks):
///
/// * every device with tokens that the quota counts: not revoked, signed in
///   under the user's `session_version` of now and less than
///   [`ABSOLUTE_SECS`] ago (so the list shows exactly what holds a place of
///   the [`MAX_DEVICES`]);
/// * the session that asks, alone, as "this browser" (`current`);
/// * every other browser with a live session of the vault origin, once per
///   device id, with the name of its newest session, the time of its first
///   live session and the last time any of them was seen. The other sessions
///   that carry the asking session's device id form a row of their own with
///   that id: a browser chooses its device id, so another one may claim this
///   browser's, and it must not hide in "this browser".
///
/// The order is fixed: this browser first, then the devices with tokens,
/// then the other browsers, each newest seen first. At most
/// [`MAX_DEVICE_LIST`] rows; `more` says how many were left out. Nothing of a
/// token or a key is read.
///
/// Spec: Fase 1 § 7.6 (the device registry: name, platform, last seen).
pub fn list(
    conn: &Connection,
    user_id: i64,
    current: &SidHash,
    now: i64,
) -> rusqlite::Result<DevicesRes> {
    let mut statement = conn.prepare(
        "SELECT d.device_id, d.name, d.platform, d.created_at, d.last_seen
         FROM ferret_devices d JOIN users u ON u.id = d.user_id
         WHERE d.user_id = ?1 AND d.revoked_at IS NULL
           AND d.session_version = u.session_version
           AND d.created_at > ?2",
    )?;
    let rows = statement.query_map(params![user_id, now.saturating_sub(ABSOLUTE_SECS)], |r| {
        Ok((
            r.get::<_, Vec<u8>>(0)?,
            r.get::<_, String>(1)?,
            r.get::<_, String>(2)?,
            r.get::<_, i64>(3)?,
            r.get::<_, i64>(4)?,
        ))
    })?;
    let mut devices = Vec::new();
    for row in rows {
        let (id, name, platform, created_at, last_seen) = row?;
        // A row that does not read back is skipped: the list never fails
        // for one, and "revoke all" still reaches it.
        let (Ok(id), Some(platform)) =
            (<[u8; 16]>::try_from(id), PlatformJson::from_word(&platform))
        else {
            tracing::error!("a device row does not read back");
            continue;
        };
        devices.push(Listed {
            id,
            kind: DeviceKindJson::Device,
            name,
            platform: Some(platform),
            created_at,
            last_seen,
            current: false,
        });
    }
    devices.sort_by(|a, b| b.last_seen.cmp(&a.last_seen).then(a.id.cmp(&b.id)));

    let mut browsers = browsers(
        &session::live_sessions(conn, user_id, Origin::Vault, now)?,
        current,
    );
    browsers.sort_by(|a, b| {
        b.current
            .cmp(&a.current)
            .then(b.last_seen.cmp(&a.last_seen))
            .then(a.id.cmp(&b.id))
    });
    let (own, others): (Vec<_>, Vec<_>) = browsers.into_iter().partition(|row| row.current);

    let all: Vec<Listed> = own.into_iter().chain(devices).chain(others).collect();
    let total = all.len();
    let more = total.saturating_sub(MAX_DEVICE_LIST);
    Ok(DevicesRes {
        devices: all
            .into_iter()
            .take(MAX_DEVICE_LIST)
            .map(Listed::json)
            .collect(),
        more: (more > 0).then(|| u32::try_from(more).unwrap_or(u32::MAX)),
    })
}

/// The live sessions as rows: the asking session `current` alone, every
/// other session grouped by browser (device id).
fn browsers(sessions: &[SessionRow], current: &SidHash) -> Vec<Listed> {
    let mut by_device: BTreeMap<([u8; 16], bool), Listed> = BTreeMap::new();
    // The newest session last, so its name wins.
    let mut sessions: Vec<&SessionRow> = sessions.iter().collect();
    sessions.sort_by(|a, b| a.issued_at.cmp(&b.issued_at).then(a.sid.0.cmp(&b.sid.0)));
    for row in sessions {
        let asking = row.sid == *current;
        let entry = by_device
            .entry((row.device.0, asking))
            .or_insert_with(|| Listed {
                id: row.device.0,
                kind: DeviceKindJson::Web,
                name: String::new(),
                platform: None,
                created_at: row.issued_at,
                last_seen: row.last_seen,
                current: asking,
            });
        entry.name.clone_from(&row.device_name);
        entry.created_at = entry.created_at.min(row.issued_at);
        entry.last_seen = entry.last_seen.max(row.last_seen);
    }
    by_device.into_values().collect()
}

/// The routes of the page "Devices", on the vault listener only, each with a
/// session of the web vault:
///
/// * `GET /api/auth/devices`: the list ([`list`]), with a full session;
/// * `DELETE /api/auth/devices/{id}`: revokes the device with tokens `id`, or
///   ends every session of the browser `id` and what was handed over from
///   them, but never the session that asks. With the asking session's own
///   device id it ends the other sessions that carry that id (another
///   browser may have claimed it), and is `400 bad_request` when there are
///   none (to end this browser, sign out); `404 not_found` for an id the user
///   has neither as a device nor as a browser (another user's included);
/// * `POST /api/auth/devices/revoke-all`: with the master password again
///   (`ScopedSession<DeviceManage>` and `FreshReauth`), ends every other
///   session and revokes every device with tokens (`end_all_credentials`,
///   which also revokes a pending sign-in code: someone who suspects a
///   stolen device wants that gone too). This browser's vault session
///   stays; its admin session ends, as after a password change (it fails
///   safe: the user opens the admin pages again);
/// * `POST /api/auth/devices/forget-old`: revokes the devices with tokens not
///   seen for [`FORGET_OLD_SECS`] ([`forget_old`]).
///
/// Every change runs in one `BEGIN IMMEDIATE` transaction that first checks
/// that the asking session is still one, and what ended is announced after
/// the commit, on the database thread, so a request whose client went away
/// still closes the streams it ended.
///
/// Spec: Fase 1 § 4.6 (revoke all devices is a sensitive operation) and
/// § 7.6.
pub fn routes<S>() -> Router<S>
where
    S: Clone + Send + Sync + 'static,
    FerretState: FromRef<S>,
{
    Router::new()
        .route(DEVICES_PATH, get(list_route))
        .route(DEVICE_PATH, delete(revoke_route))
        .route(REVOKE_ALL_PATH, post(revoke_all_route))
        .route(FORGET_OLD_PATH, post(forget_old_route))
}

/// What a change of the list came to, inside its transaction.
enum Change {
    /// Done; these ended.
    Ended(Ended),
    /// The asking session ended in between: nothing was changed.
    SessionGone,
    /// The id is the browser that asks, and no other session carries it.
    OwnBrowser,
    /// The user has no such device or browser.
    Unknown,
}

/// The asking session is still one, in the transaction that changes the
/// list: the same rules as its extractor read it with.
fn session_counts(
    tx: &Transaction<'_>,
    sid: &SidHash,
    session_version: i64,
    now: i64,
) -> rusqlite::Result<bool> {
    session::still_valid(tx, sid, Origin::Vault, session_version, now)
}

/// Runs `change` in one `BEGIN IMMEDIATE` transaction on the database
/// thread, commits what it ended, and announces it right after the commit.
async fn change_list<F>(state: &FerretState, change: F) -> Result<Change, ApiError>
where
    F: FnOnce(&Transaction<'_>) -> rusqlite::Result<Change> + Send + 'static,
{
    let events: SyncEvents = state.events.clone();
    state
        .vault_db
        .with_conn(move |conn| {
            let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
            let changed = change(&tx)?;
            if let Change::Ended(ended) = &changed {
                tx.commit()?;
                events.announce_ended(ended);
            }
            Ok::<_, StoreError>(changed)
        })
        .await
        .map_err(ApiError::from)
}

/// `GET /api/auth/devices`.
async fn list_route(
    State(state): State<FerretState>,
    mut parts: Parts,
) -> Result<Response, ApiError> {
    let session = VaultSession::from_request_parts(&mut parts, &state).await?;
    let (user_id, sid, now) = (session.user_id, session.sid, session.now);
    let res = state
        .vault_db
        .with_conn(move |conn| Ok(list(conn, user_id, &sid, now)?))
        .await?;
    Ok(no_store(Json(res).into_response()))
}

/// `DELETE /api/auth/devices/{id}`.
async fn revoke_route(
    State(state): State<FerretState>,
    mut parts: Parts,
) -> Result<Response, ApiError> {
    let session = VaultSession::from_request_parts(&mut parts, &state).await?;
    let Path(id) = Path::<String>::from_request_parts(&mut parts, &state)
        .await
        .map_err(|_| ApiError::coded("bad_request"))?;
    let id = DeviceId(hex16::decode(&id).map_err(|_| ApiError::coded("bad_request"))?);
    let (sid, user_id, version, own, now) = (
        session.sid,
        session.user_id,
        session.session_version,
        session.device,
        session.now,
    );
    let changed = change_list(&state, move |tx| {
        if !session_counts(tx, &sid, version, now)? {
            return Ok(Change::SessionGone);
        }
        if revoke(tx, user_id, &id, now)? {
            return Ok(Change::Ended(Ended {
                sessions: Vec::new(),
                devices: vec![id],
            }));
        }
        // The asking session is never ended here (it signs out instead); any
        // other session of that browser id is, this browser's id included.
        let sessions = session::end_device_sessions(tx, user_id, &id, Some(&sid), now)?;
        if sessions.is_empty() {
            return Ok(if id == own {
                Change::OwnBrowser
            } else {
                Change::Unknown
            });
        }
        Ok(Change::Ended(Ended {
            sessions,
            devices: Vec::new(),
        }))
    })
    .await?;
    match changed {
        Change::Ended(ended) => {
            tracing::info!(
                sessions = ended.sessions.len(),
                devices = ended.devices.len(),
                "a device was revoked from the list"
            );
            Ok(no_store(StatusCode::NO_CONTENT.into_response()))
        }
        Change::SessionGone => Err(ApiError::unauthorized()),
        Change::OwnBrowser => Err(ApiError::coded("bad_request")),
        Change::Unknown => Err(ApiError::not_found()),
    }
}

/// `POST /api/auth/devices/revoke-all`.
async fn revoke_all_route(
    State(state): State<FerretState>,
    mut parts: Parts,
) -> Result<Response, ApiError> {
    let session =
        ScopedSession::<caps::DeviceManage>::from_request_parts(&mut parts, &state).await?;
    let fresh = FreshReauth::from_request_parts(&mut parts, &state).await?;
    let facts = session.session();
    if fresh.sid() != facts.sid() {
        tracing::error!("a re-authentication was used for another session");
        return Err(ApiError::internal());
    }
    let (sid, user_id, version, now) = (
        facts.sid(),
        facts.user_id(),
        facts.session_version(),
        facts.now(),
    );
    let changed = change_list(&state, move |tx| {
        if !session_counts(tx, &sid, version, now)? {
            return Ok(Change::SessionGone);
        }
        Ok(Change::Ended(session::end_all_credentials(
            tx,
            user_id,
            Some(&sid),
            now,
        )?))
    })
    .await?;
    match changed {
        Change::Ended(ended) => {
            tracing::info!(
                sessions = ended.sessions.len(),
                devices = ended.devices.len(),
                "every other session and every device was revoked"
            );
            revoked_answer(ended.len())
        }
        _ => Err(ApiError::unauthorized()),
    }
}

/// `POST /api/auth/devices/forget-old`.
async fn forget_old_route(
    State(state): State<FerretState>,
    mut parts: Parts,
) -> Result<Response, ApiError> {
    let session = VaultSession::from_request_parts(&mut parts, &state).await?;
    let (sid, user_id, version, now) = (
        session.sid,
        session.user_id,
        session.session_version,
        session.now,
    );
    let changed = change_list(&state, move |tx| {
        if !session_counts(tx, &sid, version, now)? {
            return Ok(Change::SessionGone);
        }
        Ok(Change::Ended(Ended {
            sessions: Vec::new(),
            devices: forget_old(tx, user_id, now)?,
        }))
    })
    .await?;
    match changed {
        Change::Ended(ended) => {
            tracing::info!(devices = ended.devices.len(), "old devices were forgotten");
            revoked_answer(ended.len())
        }
        _ => Err(ApiError::unauthorized()),
    }
}

/// `200 {revoked}`.
fn revoked_answer(revoked: usize) -> Result<Response, ApiError> {
    let revoked = u32::try_from(revoked).unwrap_or(u32::MAX);
    Ok(no_store(Json(RevokeAllRes { revoked }).into_response()))
}
