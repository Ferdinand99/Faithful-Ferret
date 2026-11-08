//! Checkpoints the client uploads and verifies (a later milestone).
//! Spec: Fase 1 § 8.6.

use std::sync::Arc;

use axum::Router;
use axum::extract::FromRef;

use super::events::EventStreams;
use super::notify::SyncEvents;
use super::rate::{SyncLimits, WriteGate};
use crate::http::extract::SessionAuth;
use crate::state::VaultDb;

/// The checkpoint routes. Serve nothing yet.
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
