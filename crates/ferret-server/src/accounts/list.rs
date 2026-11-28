//! The list of accounts the Users page shows: one row per kit user, with what
//! an administrator may see of an account and nothing more.
//!
//! A row holds the e-mail, when the account was made and last signed in, how
//! many devices it has (devices with tokens that still count, and browsers
//! with a live session of the web vault, one per device id), whether the
//! kit's second factor is on, whether it is active, whether it is an
//! administrator or the one who asks, how many items its vault holds and how
//! many bytes they take (the vault's own `item_count` and `bytes_used`), and
//! until when a pending sign-in code works. No item, wrap, OPAQUE record or
//! key is read: the counts are the vault's columns, never its rows.
//!
//! Spec: Fase 1 § 11 ("The Users page": the columns, no PIN, counts and bytes
//! only).

use std::collections::{BTreeMap, BTreeSet};

use rusqlite::{Connection, params};

use crate::auth::refresh::ABSOLUTE_SECS;
use crate::auth::session::{Origin, live_sessions};

/// One account, as the Users page lists it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AccountRow {
    /// The kit user.
    pub user_id: i64,
    /// The e-mail (the kit's username).
    pub email: String,
    /// When the kit user was made (UTC, `YYYY-MM-DD HH:MM:SS`).
    pub created_at: String,
    /// The kit's last sign-in (UTC), if any.
    pub last_login_at: Option<String>,
    /// Devices with tokens that still count, plus browsers with a live
    /// session of the web vault (one per device id).
    pub devices: u32,
    /// The kit's second factor is on.
    pub totp: bool,
    /// The account is not disabled.
    pub active: bool,
    /// The account is an administrator.
    pub is_admin: bool,
    /// The account is the one that asks.
    pub is_self: bool,
    /// The items of its vault (0 without a vault).
    pub items: u32,
    /// The bytes its vault takes (0 without a vault).
    pub bytes: u64,
    /// Until when its pending sign-in code works (UTC), if it has one.
    pub code_until: Option<String>,
}

/// Every kit user, oldest first, as seen by the administrator `me` at `now`.
pub fn list(conn: &Connection, me: i64, now: i64) -> rusqlite::Result<Vec<AccountRow>> {
    let tokens = token_devices(conn, now)?;
    let codes: BTreeMap<i64, String> = vole_kit::db::sign_in_codes::pending_users(conn)?
        .into_iter()
        .collect();
    let mut statement = conn.prepare(
        "SELECT u.id, u.username, u.created_at, u.last_login_at, u.totp_enabled, u.active,
                u.role = 'admin', COALESCE(v.item_count, 0), COALESCE(v.bytes_used, 0)
         FROM users u
         LEFT JOIN ferret_accounts a ON a.user_id = u.id
         LEFT JOIN ferret_vaults v ON v.account_id = a.account_id
         ORDER BY u.id",
    )?;
    let users = statement
        .query_map([], |r| {
            Ok((
                r.get::<_, i64>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, String>(2)?,
                r.get::<_, Option<String>>(3)?,
                r.get::<_, bool>(4)?,
                r.get::<_, bool>(5)?,
                r.get::<_, bool>(6)?,
                r.get::<_, i64>(7)?,
                r.get::<_, i64>(8)?,
            ))
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    let mut rows = Vec::with_capacity(users.len());
    for (user_id, email, created_at, last_login_at, totp, active, is_admin, items, bytes) in users {
        let browsers: BTreeSet<[u8; 16]> = live_sessions(conn, user_id, Origin::Vault, now)?
            .into_iter()
            .map(|row| row.device.0)
            .collect();
        let devices = tokens
            .get(&user_id)
            .copied()
            .unwrap_or(0)
            .saturating_add(browsers.len());
        rows.push(AccountRow {
            user_id,
            email,
            created_at,
            last_login_at,
            devices: u32::try_from(devices).unwrap_or(u32::MAX),
            totp,
            active,
            is_admin,
            is_self: user_id == me,
            items: u32::try_from(items.max(0)).unwrap_or(u32::MAX),
            bytes: u64::try_from(bytes.max(0)).unwrap_or(0),
            code_until: codes.get(&user_id).cloned(),
        });
    }
    Ok(rows)
}

/// The devices with tokens that still count, per user: not revoked, signed in
/// under the user's current session version, less than [`ABSOLUTE_SECS`] ago
/// (the rule of the device list of `auth::devices`).
fn token_devices(conn: &Connection, now: i64) -> rusqlite::Result<BTreeMap<i64, usize>> {
    let mut statement = conn.prepare(
        "SELECT d.user_id, COUNT(*) FROM ferret_devices d JOIN users u ON u.id = d.user_id
         WHERE d.revoked_at IS NULL AND d.session_version = u.session_version
           AND d.created_at > ?1
         GROUP BY d.user_id",
    )?;
    let counts = statement
        .query_map(params![now.saturating_sub(ABSOLUTE_SECS)], |r| {
            Ok((r.get::<_, i64>(0)?, r.get::<_, i64>(1)?))
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    Ok(counts
        .into_iter()
        .map(|(user, n)| (user, usize::try_from(n).unwrap_or(0)))
        .collect())
}
