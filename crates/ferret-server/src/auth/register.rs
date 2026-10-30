//! Registration: `POST /api/auth/opaque/register/{start,finish}` (vault
//! listener only). The account, its vault, its unlock methods, the manifest row
//! and the first checkpoint are written in one transaction.

use axum::Router;

/// The registration routes (none yet).
pub fn routes<S>() -> Router<S>
where
    S: Clone + Send + Sync + 'static,
{
    Router::new()
}
