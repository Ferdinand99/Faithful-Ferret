//! Recovery material of an account (a later milestone).
//!
//! `GET /api/vault/recovery` hands out the recovery wrap to the session that
//! may read it, and `PUT /api/vault/unlock-methods/recovery` replaces it with a
//! new recovery key's wrap, through `unlock_write`.

use std::sync::Arc;

use axum::Router;
use axum::extract::FromRef;
use ferret_server_auth::Clock;

use super::notify::SyncEvents;
use crate::http::extract::SessionAuth;
use crate::state::{BackupStatus, Challenges, VaultDb};

/// The routes of the recovery material. None are served yet.
pub fn routes<S>() -> Router<S>
where
    S: Clone + Send + Sync + 'static,
    VaultDb: FromRef<S>,
    SessionAuth: FromRef<S>,
    Challenges: FromRef<S>,
    Arc<dyn Clock>: FromRef<S>,
    SyncEvents: FromRef<S>,
    BackupStatus: FromRef<S>,
{
    Router::new()
}
