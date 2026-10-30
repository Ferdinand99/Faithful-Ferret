//! `PUT /api/sync/items/{id}`: one item write, live or tombstone.
//! Spec: Fase 1 § 8.1, § 8.3.

use axum::Router;

/// The item routes (none yet).
pub fn routes<S>() -> Router<S>
where
    S: Clone + Send + Sync + 'static,
{
    Router::new()
}
