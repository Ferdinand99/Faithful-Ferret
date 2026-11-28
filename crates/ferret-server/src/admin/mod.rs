//! The admin listener's own routes: the redirects that stand in for the kit's
//! password pages, the hand-over page, the signed-out page, the Users page
//! ([`accounts`], in place of the kit's), the Backup page ([`panel`]), the
//! Unlock page (`unlock`, with the cargo feature
//! `quick-unlock`) and the guard that wraps the kit's pages.
//! The kit's pages themselves are mounted in `server::admin_router`.
//!
//! The admin listener never has a password field, never loads WASM and serves
//! no vault route.

pub mod accounts;
pub mod brand;
pub mod codes;
pub mod guard;
pub mod handoff_page;
pub mod panel;
pub mod redirects;
pub mod settings;
pub mod signed_out_page;
#[cfg(feature = "quick-unlock")]
pub mod unlock;

use axum::Router;
use axum::extract::FromRef;

use crate::config::Origins;
use crate::state::FerretState;

/// Ferret's own pages that need a full admin session: the Users page and its
/// actions, the Backup page and its action, and (with the cargo feature
/// `quick-unlock`) the Unlock page.
/// `server::admin_router` puts them behind the same guard as the kit's pages.
pub fn protected_routes() -> Router<FerretState> {
    let routes = accounts::routes().merge(panel::routes());
    #[cfg(feature = "quick-unlock")]
    let routes = routes.merge(unlock::routes());
    routes
}

/// The routes of the admin listener that are not the kit's and need no session.
pub fn routes<S>() -> Router<S>
where
    S: Clone + Send + Sync + 'static,
    Origins: FromRef<S>,
{
    Router::new()
        .merge(brand::routes())
        .merge(redirects::routes())
        .merge(handoff_page::routes())
        .merge(signed_out_page::routes())
}
