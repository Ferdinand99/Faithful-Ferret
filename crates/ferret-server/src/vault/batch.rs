//! Batches of writes (a later milestone).

use std::sync::Arc;

use axum::Router;
use axum::extract::FromRef;

use super::events::EventStreams;
use super::notify::SyncEvents;
use super::rate::{SyncLimits, WriteGate};
use crate::http::extract::SessionAuth;
use crate::state::VaultDb;

/// The batch route. Serves nothing yet.
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
