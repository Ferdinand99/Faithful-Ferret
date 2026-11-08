//! Server-sent events for changes (a later milestone).
//!
//! What is here is the place-holder of the stream slots: how many event
//! streams one device, one vault and the whole server may hold open.

use std::sync::Arc;

use axum::Router;
use axum::extract::FromRef;

use super::notify::SyncEvents;
use super::rate::{SyncLimits, WriteGate};
use crate::http::extract::SessionAuth;
use crate::ids::{DeviceId, VaultId};
use crate::state::VaultDb;

/// The open event streams, counted per device, per vault and in all.
pub struct EventStreams {
    _private: (),
}

/// One open stream's place; the place is free again when this is dropped.
pub struct StreamSlot {
    _private: (),
}

impl EventStreams {
    /// Streams that allow `per_device` for one device, `per_vault` for one
    /// vault and `total` on the server.
    pub fn new(_per_device: usize, _per_vault: usize, _total: usize) -> Self {
        Self { _private: () }
    }

    /// A place for a new stream of this device, or `None` when a limit is
    /// reached. The place stays taken until the slot is dropped.
    pub fn acquire(&self, _vault: &VaultId, _device: &DeviceId) -> Option<StreamSlot> {
        Some(StreamSlot { _private: () })
    }
}

/// The event stream route. Serves nothing yet.
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
