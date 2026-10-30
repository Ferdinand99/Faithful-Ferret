//! Sign-in and sign-out: `POST /api/auth/opaque/login/{start,finish}` (vault
//! listener only), `POST /api/auth/logout` and `GET /api/auth/session` (both
//! listeners). Spec: Fase 1 § 4.2.

use std::sync::{Arc, RwLock};

use axum::Router;
use ferret_core::KsfProfile;
use ferret_server_auth::{Clock, PreloginPolicy};
use rusqlite::Connection;

use crate::state::VaultDb;

/// The routes of the vault listener: both OPAQUE steps, sign-out and the
/// session info (none yet).
pub fn routes<S>() -> Router<S>
where
    S: Clone + Send + Sync + 'static,
{
    Router::new()
}

/// The routes of the admin listener: sign-out and the session info (none yet).
pub fn admin_routes<S>() -> Router<S>
where
    S: Clone + Send + Sync + 'static,
{
    Router::new()
}

/// How the made-up answers of unknown names are spread, from the real accounts:
/// the share of each key stretching profile and the share of accounts with a
/// second factor. For now: the one profile there is, for every answer.
pub fn load_prelogin_policy(_conn: &Connection) -> PreloginPolicy {
    PreloginPolicy::single(KsfProfile::P1)
}

/// Renews the policy in `policy` from the database every ten minutes (not yet).
pub fn spawn_prelogin_refresh(
    _db: VaultDb,
    _policy: Arc<RwLock<PreloginPolicy>>,
    _clock: Arc<dyn Clock>,
) {
}
