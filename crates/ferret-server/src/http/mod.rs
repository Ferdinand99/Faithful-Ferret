//! The HTTP layers of the two listeners, the static files of the web vault and
//! the extractors for sessions.
//!
//! Each listener gets its layers from here ([`vault_layers`], [`admin_layers`]),
//! in this order from the outside in: proxy trust (`proxy_guard`), the `Origin`
//! check (`origin_guard`), the security headers, and the rewriting of the kit's
//! cookies to `SameSite=Strict`. They are not built yet: both functions return
//! the router as it is.

pub mod extract;
pub mod headers;
pub mod origin_guard;
pub mod proxy_guard;
pub mod signed;
pub mod static_files;

use axum::Router;

use crate::state::FerretState;

/// The layers of the vault listener around `router` (whose state is already
/// set).
pub fn vault_layers(router: Router, _state: &FerretState) -> Router {
    router
}

/// The layers of the admin listener around `router` (whose state is already
/// set).
pub fn admin_layers(router: Router, _state: &FerretState) -> Router {
    router
}
