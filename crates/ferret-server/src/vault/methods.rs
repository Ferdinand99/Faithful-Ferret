//! `GET /api/vault/unlock-methods`: the wraps of the vault key, the public key
//! `pk_a`, the key epoch and the manifest row. Spec: Fase 1 § 4.6.

use axum::Router;

/// The unlock methods route (none yet).
pub fn routes<S>() -> Router<S>
where
    S: Clone + Send + Sync + 'static,
{
    Router::new()
}
