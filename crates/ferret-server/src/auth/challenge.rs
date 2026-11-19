//! Nonces for signed requests (a later milestone). Spec: Fase 1 § 4.6.
//!
//! `POST /api/auth/challenge` hands a session a nonce to sign its next
//! sensitive request with.

use axum::Router;
use axum::extract::FromRef;

use crate::state::FerretState;

/// The routes of the challenge. None are served yet.
pub fn routes<S>() -> Router<S>
where
    S: Clone + Send + Sync + 'static,
    FerretState: FromRef<S>,
{
    Router::new()
}
