//! Retention: how long tombstones and idempotency records are kept, and the
//! background job that removes the older ones. Spec: Fase 1 § 8.4.
//!
//! The constants and the shape of the report are fixed here; the job itself
//! does nothing yet and [`run_once`] says so.

use std::sync::Arc;

use ferret_server_auth::Clock;
use rusqlite::Connection;

use crate::error::{NotImplemented, StoreError};
use crate::state::VaultDb;

/// Days a tombstone is kept before it may be purged.
pub const TOMBSTONE_DAYS: i64 = 400;

/// Days an idempotency record is kept.
pub const IDEM_DAYS: i64 = 30;

/// Idempotency records kept for one device at most.
pub const IDEM_PER_DEVICE: u32 = 1_000;

/// What one pass of the job did.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct RetentionReport {
    /// Vaults looked at.
    pub vaults: u64,
    /// Tombstones removed.
    pub tombstones_removed: u64,
    /// Idempotency records removed.
    pub idem_removed: u64,
}

/// One pass over every vault at time `now` (Unix seconds). Not implemented yet.
pub fn run_once(_conn: &mut Connection, _now: i64) -> Result<RetentionReport, StoreError> {
    Err(NotImplemented("retention::run_once").into())
}

/// Starts the job in the background. Does nothing yet.
pub fn spawn(_db: VaultDb, _clock: Arc<dyn Clock>) {}
