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
//! § 12 (`headers::VAULT_HEADERS`) on every response, plus `nosniff` (which
//! `headers.json` does not list). The admin
//! listener keeps the kit's headers and adds `nosniff` and a `Referrer-Policy`:
//! `no-referrer` for the hand-over, the API and the redirect stubs (the
//! hand-over code travels in a fragment and must not leak through a referrer
//! either), and the kit's own `same-origin` for its pages (see
//! [`admin_referrer_policy`]).

pub mod extract;
pub mod headers;
pub mod origin_guard;
pub mod proxy_guard;
pub mod signed;
pub mod static_files;

use axum::Router;
use std::sync::Arc;

use axum::extract::{Request, State};
use axum::http::header::{CONTENT_SECURITY_POLICY, REFERRER_POLICY, X_CONTENT_TYPE_OPTIONS};
use axum::http::{HeaderName, HeaderValue};
use axum::middleware::{Next, from_fn, from_fn_with_state};
use axum::response::Response;
use vole_kit::http::headers::MACHINE_CSP;

use crate::state::FerretState;
use origin_guard::{ListenerOrigin, origin_guard, strict_cookie};
use proxy_guard::proxy_guard;

/// The headers of Spec: Fase 1 § 12 as ready values. A name that does not
/// parse stops the server at start-up instead of dropping a header.
fn header_list() -> Arc<Vec<(HeaderName, HeaderValue)>> {
    Arc::new(
        headers::VAULT_HEADERS
            .iter()
            .map(|(name, value)| {
                let name = HeaderName::from_bytes(name.as_bytes())
                    .expect("the names of VAULT_HEADERS are header names");
                (name, HeaderValue::from_static(value))
            })
            .collect(),
    )
}

/// Puts the headers of Spec: Fase 1 § 12 on every response of the vault
/// listener, replacing any value a handler set.
async fn vault_headers(
    State(list): State<Arc<Vec<(HeaderName, HeaderValue)>>>,
    request: Request,
    next: Next,
) -> Response {
    let mut response = next.run(request).await;
    let headers = response.headers_mut();
    for (name, value) in list.iter() {
        headers.insert(name.clone(), value.clone());
    }
    headers.insert(X_CONTENT_TYPE_OPTIONS, HeaderValue::from_static("nosniff"));
    response
}

/// The `Referrer-Policy` of an admin response, by path.
///
/// The hand-over pages, the API, the redirect stubs and `/setup` (whose query
/// carries the setup token) send no referrer at all.
/// The kit's one-time sign-in code page (`/sign-in-code`) sends the origin and
/// nothing more, and nothing at all to a less safe one (`strict-origin`): the
/// code may travel in its address, and the kit's form there is posted with
/// `Origin` and `Referer` like the rest of its pages.
/// The kit's other pages send one to their own origin only (`same-origin`, the kit's
/// policy): the kit's forms are posted with `Origin` and `Referer` as proof that
/// they come from its own pages (a plain form post is sent with `Origin: null`
/// under `no-referrer`, and the kit, like `origin_guard`, refuses that). No
/// referrer ever leaves the origin.
fn admin_referrer_policy(path: &str) -> &'static str {
    if path == "/setup"
        || ["/auth/", "/api/", "/vault/"]
            .iter()
            .any(|prefix| path.starts_with(prefix))
    {
        "no-referrer"
    } else if path == "/sign-in-code" {
        "strict-origin"
    } else {
        "same-origin"
    }
}

/// Puts `nosniff` and the `Referrer-Policy` of the path on every response of the
/// admin listener, on top of what the kit sets. A response without a policy
/// (a refusal of the `Origin` guard, which sits outside the kit's layers) gets
/// the kit's policy for machines, which allows nothing.
async fn admin_headers(request: Request, next: Next) -> Response {
    let policy = admin_referrer_policy(request.uri().path());
    let mut response = next.run(request).await;
    let headers = response.headers_mut();
    headers.insert(X_CONTENT_TYPE_OPTIONS, HeaderValue::from_static("nosniff"));
    headers.insert(REFERRER_POLICY, HeaderValue::from_static(policy));
    headers
        .entry(CONTENT_SECURITY_POLICY)
        .or_insert(HeaderValue::from_static(MACHINE_CSP));
    response
}

/// The layers of the vault listener around `router` (whose state is already
/// set).
pub fn vault_layers(router: Router, state: &FerretState) -> Router {
    let listener = ListenerOrigin::vault(state.origins.vault());
    router
        .layer(from_fn_with_state(listener.clone(), strict_cookie))
        .layer(from_fn_with_state(listener, origin_guard))
        .layer(from_fn_with_state(header_list(), vault_headers))
        .layer(from_fn_with_state(state.proxies.clone(), proxy_guard))
}

/// The layers of the admin listener around `router` (whose state is already
/// set).
pub fn admin_layers(router: Router, state: &FerretState) -> Router {
    let listener = ListenerOrigin::admin(state.origins.admin());
    router
        .layer(from_fn_with_state(listener.clone(), strict_cookie))
        .layer(from_fn_with_state(listener, origin_guard))
        .layer(from_fn(admin_headers))
        .layer(from_fn_with_state(state.proxies.clone(), proxy_guard))
}

#[cfg(test)]
mod tests {
    use super::admin_referrer_policy;
    use crate::product::FEATURES;

    #[test]
    fn the_setup_page_sends_no_referrer() {
        for path in [
            "/setup",
            "/auth/handoff",
            "/api/auth/session",
            "/vault/login",
        ] {
            assert_eq!(admin_referrer_policy(path), "no-referrer", "{path}");
        }
        // The kit's pages keep the kit's policy.
        for path in ["/settings/general", "/login", "/setup/other", "/setups"] {
            assert_eq!(admin_referrer_policy(path), "same-origin", "{path}");
        }
        // The page that takes a one-time sign-in code leaks no more than its
        // origin, and nothing to a less safe one.
        assert_eq!(admin_referrer_policy("/sign-in-code"), "strict-origin");
    }

    /// An invitation link and a sign-in code travel in the path of the page that
    /// takes them. Turning either feature on needs a strict policy for its page
    /// first: add the path to `admin_referrer_policy` and make it `no-referrer`
    /// or `strict-origin` (no referrer at all, or the origin only and nothing to
    /// a less safe one), then this test passes again. The features are off now.
    #[test]
    fn a_feature_with_a_secret_in_its_path_needs_a_strict_referrer_policy() {
        let strict =
            |path: &str| matches!(admin_referrer_policy(path), "no-referrer" | "strict-origin");
        if FEATURES.invites {
            assert!(
                strict("/invite/token"),
                "FEATURES.invites is on but /invite/ has no strict referrer policy"
            );
        }
        if FEATURES.sign_in_codes {
            assert!(
                strict("/sign-in-code"),
                "FEATURES.sign_in_codes is on but /sign-in-code has no strict referrer policy"
            );
        }
    }
}
