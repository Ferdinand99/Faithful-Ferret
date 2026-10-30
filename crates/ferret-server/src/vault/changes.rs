//! `GET /api/sync/changes?since&limit`: the rows that changed after a sequence
//! number, in sequence order. Spec: Fase 1 § 8.1.

use axum::Router;

/// The changes route (none yet).
pub fn routes<S>() -> Router<S>
where
    S: Clone + Send + Sync + 'static,
{
    Router::new()
}
