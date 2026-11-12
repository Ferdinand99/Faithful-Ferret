//! Recovering an account with the recovery key (a later milestone).
//!
//! `POST /api/vault/recover`: a signed request, in a full session or in the
//! short session that a one-time code opens, that replaces both wraps and the
//! OPAQUE record and ends the other sessions.

use std::sync::Arc;

use axum::Router;
use axum::extract::FromRef;
use ferret_server_auth::Clock;

use super::notify::SyncEvents;
use crate::http::extract::SessionAuth;
use crate::state::{BackupStatus, Challenges, VaultDb};

/// The routes of the recovery. None are served yet.
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
