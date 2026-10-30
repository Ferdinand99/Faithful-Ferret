//! The hand-over of a session from the vault origin to the admin origin: the
//! vault origin mints a one-time code (`POST /api/auth/handoff`), the admin
//! origin redeems it (`POST /api/auth/handoff/redeem`). The password is typed
//! on the vault origin only. Spec: Fase 1 § 2.4.

use std::sync::Arc;

use axum::Router;
use ferret_server_auth::Clock;

use crate::state::VaultDb;

/// The routes of the vault listener: minting a code (none yet).
pub fn routes<S>() -> Router<S>
where
    S: Clone + Send + Sync + 'static,
{
    Router::new()
}

/// The routes of the admin listener: redeeming a code (none yet).
pub fn admin_routes<S>() -> Router<S>
where
    S: Clone + Send + Sync + 'static,
{
    Router::new()
}

/// Deletes expired hand-over rows every minute (not yet).
pub fn spawn_purge(_db: VaultDb, _clock: Arc<dyn Clock>) {}
