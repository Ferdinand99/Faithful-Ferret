//! The page the admin origin lands on after the kit's sign-out (`GET
//! /auth/signed-out`), from `web/admin/signed-out.html`.
//!
//! The kit sends a sign-out to `/login`, and with external credentials that is a
//! redirect on to the vault origin, so no page of the admin origin would load
//! after a sign-out. htmx keeps snapshots of the pages it left in the tab's
//! `sessionStorage` of the admin origin, and only a page of that origin can
//! drop them. This page does: its body has the kit's `data-clear-history`, and
//! the kit's `/static/app.js` removes the cache when it loads on such a page.
//! It holds no private data and sets no cookie; it is the same for everyone.

use axum::Router;
use axum::http::header::CONTENT_TYPE;
use axum::response::{IntoResponse, Response};
use axum::routing::get;

use crate::auth::login::no_store;

/// Where the sign-out of the admin origin ends.
pub const PATH: &str = "/auth/signed-out";

/// The page.
const PAGE: &str = include_str!("../../../../web/admin/signed-out.html");

/// `GET /auth/signed-out`.
async fn page() -> Response {
    no_store(([(CONTENT_TYPE, "text/html; charset=utf-8")], PAGE).into_response())
}

/// The signed-out page route.
pub fn routes<S>() -> Router<S>
where
    S: Clone + Send + Sync + 'static,
{
    Router::new().route(PATH, get(page))
}
