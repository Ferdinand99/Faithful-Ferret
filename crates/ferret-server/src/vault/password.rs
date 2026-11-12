//! Changing the master password (a later milestone).
//!
//! `PUT /api/vault/unlock-methods/password`: a signed request in a session that
//! has proved the master password again, which writes the new OPAQUE record, the
//! new password wrap and the new manifest through `unlock_write`.

use std::sync::Arc;

use axum::Router;
use axum::extract::FromRef;
use ferret_server_auth::Clock;

use super::notify::SyncEvents;
use crate::http::extract::SessionAuth;
use crate::state::{BackupStatus, Challenges, VaultDb};

/// The routes of the password change. None are served yet.
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
