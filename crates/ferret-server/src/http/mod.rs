//! The HTTP layers of the two listeners, the static files of the web vault and
//! the extractors for sessions.
//!
//! Each listener gets its layers from here ([`vault_layers`], [`admin_layers`]),
//! in this order from the outside in: proxy trust (`proxy_guard`), the security
//! headers, the `Origin` check (`origin_guard`), and the rewriting of the kit's
//! cookies to `SameSite=Strict`. The headers sit outside the `Origin` check so
//! that its refusals carry them too.
//!
//! The security headers of the vault listener are the list of Spec: Fase 1
//! § 12 (`headers::VAULT_HEADERS`) on every response, plus `nosniff`. The admin
//! listener keeps the kit's headers and adds `nosniff` and
//! `Referrer-Policy: no-referrer` (the hand-over code travels in a fragment and
//! must not leak through a referrer either).

pub mod extract;
pub mod headers;
pub mod origin_guard;
pub mod proxy_guard;
pub mod signed;
pub mod static_files;

use axum::Router;
use axum::extract::Request;
use axum::http::header::{REFERRER_POLICY, X_CONTENT_TYPE_OPTIONS};
use axum::http::{HeaderName, HeaderValue};
use axum::middleware::{Next, from_fn, from_fn_with_state};
use axum::response::Response;

use crate::state::FerretState;
use origin_guard::{ListenerOrigin, origin_guard, strict_cookie};
use proxy_guard::proxy_guard;

/// Puts the headers of Spec: Fase 1 § 12 on every response of the vault
/// listener, replacing any value a handler set.
async fn vault_headers(request: Request, next: Next) -> Response {
    let mut response = next.run(request).await;
    let headers = response.headers_mut();
    for (name, value) in headers::VAULT_HEADERS {
        // Header names are case-insensitive; `from_bytes` lower-cases them.
        if let Ok(name) = HeaderName::from_bytes(name.as_bytes()) {
            headers.insert(name, HeaderValue::from_static(value));
        }
    }
    headers.insert(X_CONTENT_TYPE_OPTIONS, HeaderValue::from_static("nosniff"));
    response
}

/// Puts `nosniff` and `Referrer-Policy: no-referrer` on every response of the
/// admin listener, on top of what the kit sets.
async fn admin_headers(request: Request, next: Next) -> Response {
    let mut response = next.run(request).await;
    let headers = response.headers_mut();
    headers.insert(X_CONTENT_TYPE_OPTIONS, HeaderValue::from_static("nosniff"));
    headers.insert(REFERRER_POLICY, HeaderValue::from_static("no-referrer"));
    response
}

/// The layers of the vault listener around `router` (whose state is already
/// set).
pub fn vault_layers(router: Router, state: &FerretState) -> Router {
    router
        .layer(from_fn(strict_cookie))
        .layer(from_fn_with_state(
            ListenerOrigin(state.origins.vault().to_string()),
            origin_guard,
        ))
        .layer(from_fn(vault_headers))
        .layer(from_fn_with_state(state.proxies.clone(), proxy_guard))
}

/// The layers of the admin listener around `router` (whose state is already
/// set).
pub fn admin_layers(router: Router, state: &FerretState) -> Router {
    router
        .layer(from_fn(strict_cookie))
        .layer(from_fn_with_state(
            ListenerOrigin(state.origins.admin().to_string()),
            origin_guard,
        ))
        .layer(from_fn(admin_headers))
        .layer(from_fn_with_state(state.proxies.clone(), proxy_guard))
}
