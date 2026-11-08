//! Reconciling after a restore (a later milestone).

use std::sync::Arc;

use axum::Router;
use axum::extract::FromRef;
use rusqlite::Connection;

use super::events::EventStreams;
use super::notify::SyncEvents;
use super::rate::{SyncLimits, WriteGate};
use crate::error::{NotImplemented, StoreError};
use crate::http::extract::SessionAuth;
use crate::state::VaultDb;

/// Raises the restore epoch (the counter that tells clients the server was
/// restored) and returns the new value. Not implemented yet.
pub fn bump_restore_epoch(_conn: &mut Connection) -> Result<u64, StoreError> {
    Err(NotImplemented("reconcile::bump_restore_epoch").into())
}

/// The listing routes. Serve nothing yet.
pub fn routes<S>() -> Router<S>
where
    S: Clone + Send + Sync + 'static,
    VaultDb: FromRef<S>,
    SessionAuth: FromRef<S>,
    SyncEvents: FromRef<S>,
    Arc<SyncLimits>: FromRef<S>,
    WriteGate: FromRef<S>,
    Arc<EventStreams>: FromRef<S>,
{
    Router::new()
}
