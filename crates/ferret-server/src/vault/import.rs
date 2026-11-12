//! The import window (a later milestone).
//!
//! `POST /api/sync/import`: a session that has proved the master password again
//! opens one window per vault, in which the operations of an import are counted
//! apart from the ordinary per-device limit.

use std::sync::Arc;

use axum::Router;
use axum::extract::FromRef;
use ferret_server_auth::Clock;

use crate::http::extract::SessionAuth;
use crate::state::{ImportWindows, VaultDb};

/// The routes of the import window. None are served yet.
pub fn routes<S>() -> Router<S>
where
    S: Clone + Send + Sync + 'static,
    VaultDb: FromRef<S>,
    SessionAuth: FromRef<S>,
    ImportWindows: FromRef<S>,
    Arc<dyn Clock>: FromRef<S>,
{
    Router::new()
}
