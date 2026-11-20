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
//! This module holds the types. The row, the quota, the revocation and the
//! routes come later; [`routes`] serves nothing yet.

use std::fmt;

use axum::Router;
use axum::extract::FromRef;

use crate::state::FerretState;
use crate::wire::PlatformJson;

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

/// The routes of the list of devices and of revoking them, on the vault
/// listener. None are served yet.
pub fn routes<S>() -> Router<S>
where
    S: Clone + Send + Sync + 'static,
    FerretState: FromRef<S>,
{
    Router::new()
}
