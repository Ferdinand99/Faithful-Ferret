//! The admin listener's own routes: the redirects that stand in for the kit's
//! password pages, the hand-over page and the guard that wraps the kit's pages.
//! The kit's pages themselves are mounted in `server::admin_router`.
//!
//! The admin listener never has a password field, never loads WASM and serves
//! no vault route.

pub mod guard;
pub mod handoff_page;
pub mod panel;
pub mod redirects;
pub mod settings;

use axum::Router;

/// The routes of the admin listener that are not the kit's and need no session.
pub fn routes<S>() -> Router<S>
where
    S: Clone + Send + Sync + 'static,
{
    Router::new()
        .merge(redirects::routes())
        .merge(handoff_page::routes())
}
