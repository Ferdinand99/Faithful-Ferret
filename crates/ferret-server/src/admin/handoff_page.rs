//! The small page of the admin origin that redeems a hand-over code: it begins
//! a hand-over (`/auth/handoff/begin`), serves the page (`/auth/handoff`) and
//! its one script (`/auth/handoff.mjs`).

use axum::Router;

/// The hand-over page routes (none yet).
pub fn routes<S>() -> Router<S>
where
    S: Clone + Send + Sync + 'static,
{
    Router::new()
}
