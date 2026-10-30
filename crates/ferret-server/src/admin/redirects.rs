//! The paths the kit sends people to for a password (`product::EXTERNAL`) are
//! redirects on the admin listener: they start the hand-over of a session from
//! the vault origin (`/auth/handoff/begin`).

use axum::Router;

/// `/vault/{login,setup,password,reauth}` (none yet).
pub fn routes<S>() -> Router<S>
where
    S: Clone + Send + Sync + 'static,
{
    Router::new()
}
