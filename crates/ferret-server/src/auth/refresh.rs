//! Renewing and revoking a device's tokens: `POST /api/auth/token/refresh` and
//! `POST /api/auth/token/revoke`, the grace period of a refresh token, and the
//! purge of old token rows. Spec: Fase 1 § 7.6.
//!
//! A refresh token is used once: a renewal marks it used and issues the next
//! one, in one `BEGIN IMMEDIATE` transaction. For [`GRACE_SECS`] after that,
//! the same token with a proof of the same key gets the same successor again
//! (an answer lost on the way); after that, or with another key, its use
//! revokes the device. A device that renews nothing for [`IDLE_SECS`], or
//! that signed in more than [`ABSOLUTE_SECS`] ago, signs in again.
//!
//! The routes and the bodies come later; [`routes`] serves nothing yet and
//! [`purge_expired`] purges nothing.

use axum::Router;
use axum::extract::FromRef;
use rusqlite::Transaction;

use crate::state::FerretState;

/// How long a used refresh token still gets its successor, with a proof of
/// the same key, in seconds.
pub const GRACE_SECS: i64 = 60;

/// How long a refresh token lives without being used, in seconds.
pub const IDLE_SECS: i64 = 30 * 86_400;

/// How long the tokens of one sign-in live at most, in seconds.
pub const ABSOLUTE_SECS: i64 = 90 * 86_400;

/// How long a used refresh row is kept after its use, in seconds, so a reuse
/// of an old token is still seen as one.
pub const USED_KEEP_SECS: i64 = 30 * 86_400;

/// The most successors held in memory for the grace period. A full store
/// refuses a renewal (`503 busy`) instead of dropping one.
pub const GRACE_CAPACITY: usize = 65_536;

/// The successors of the refresh tokens used in the last [`GRACE_SECS`], held
/// in memory only (the database has hashes only), keyed by the hash of the
/// used token. One store for the process, shared through an `Arc`. Filled in
/// later.
pub struct RefreshGrace {
    /// The most successors held.
    #[expect(dead_code, reason = "read by the renewal, which comes later")]
    capacity: usize,
}

impl RefreshGrace {
    /// An empty store that holds at most `capacity` successors.
    pub fn new(capacity: usize) -> Self {
        Self { capacity }
    }
}

/// The routes of the renewal and the revocation, on the vault listener. None
/// are served yet.
pub fn routes<S>() -> Router<S>
where
    S: Clone + Send + Sync + 'static,
    FerretState: FromRef<S>,
{
    Router::new()
}

/// What one purge removed, row by row.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Purged {
    /// Expired access rows.
    pub access: usize,
    /// Refresh rows used more than [`USED_KEEP_SECS`] ago, or of a device
    /// revoked that long ago.
    pub refresh: usize,
    /// Devices with no live refresh token left (revoked), or revoked that long
    /// ago (deleted).
    pub devices: usize,
}

/// Purges the old token rows and devices at `now` (Unix seconds), inside the
/// caller's transaction, which the caller opens with `BEGIN IMMEDIATE` and
/// commits.
///
/// Not built yet: purges nothing.
pub fn purge_expired(tx: &Transaction<'_>, now: i64) -> rusqlite::Result<Purged> {
    let _ = (tx, now);
    Ok(Purged::default())
}
