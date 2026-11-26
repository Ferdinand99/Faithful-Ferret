//! Ferret's own brand colour on the admin pages.
//!
//! vole-kit's design system (`/static/style.css`, and `/static/shell.css` for
//! the side menu) paints the family's colour. The kit has no setting for a
//! product's colour and serves its files before the product's, so these two
//! routes answer the same paths with the kit's file followed by
//! `brand/admin-brand.css`, which sets the brand tokens to the turquoise of
//! Ferret's logo (the values of the web vault's `base.css`). The kit itself,
//! and every other product on it, stays as it is.
//!
//! The answer is the kit's bytes plus ours, so it changes whenever either does;
//! its `ETag` is the SHA-256 of the whole. A path the kit does not have is
//! `404`, as before.

use std::sync::OnceLock;

use axum::Router;
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use sha2::{Digest as _, Sha256};
use vole_kit::http::assets::kit_file;

/// What is added to each of the kit's sheets.
pub const BRAND_CSS: &str = include_str!("../../brand/admin-brand.css");

/// The kit's sheet and ours, with the tag of the whole.
struct Branded {
    body: Vec<u8>,
    etag: String,
}

fn build(name: &str) -> Option<Branded> {
    let kit = kit_file(name)?;
    let mut body = kit.data.into_owned();
    body.extend_from_slice(b"\n");
    body.extend_from_slice(BRAND_CSS.as_bytes());
    let digest = Sha256::digest(&body);
    let etag = format!(
        "\"{}\"",
        digest[..16]
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>()
    );
    Some(Branded { body, etag })
}

fn respond(cell: &'static OnceLock<Option<Branded>>, name: &str, headers: &HeaderMap) -> Response {
    let Some(file) = cell.get_or_init(|| build(name)).as_ref() else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let not_modified = headers
        .get(header::IF_NONE_MATCH)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| v.split(',').any(|t| t.trim() == file.etag));
    let mut response = if not_modified {
        StatusCode::NOT_MODIFIED.into_response()
    } else {
        (
            [(header::CONTENT_TYPE, "text/css; charset=utf-8")],
            file.body.clone(),
        )
            .into_response()
    };
    let h = response.headers_mut();
    // A browser asks every time and gets `304` when nothing changed, so a new
    // release is never shown in the old colour.
    h.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-cache"));
    if let Ok(v) = HeaderValue::from_str(&file.etag) {
        h.insert(header::ETAG, v);
    }
    response
}

static STYLE: OnceLock<Option<Branded>> = OnceLock::new();
static SHELL: OnceLock<Option<Branded>> = OnceLock::new();

/// `GET /static/style.css` and `GET /static/shell.css`, in Ferret's colour.
pub fn routes<S>() -> Router<S>
where
    S: Clone + Send + Sync + 'static,
{
    Router::new()
        .route(
            "/static/style.css",
            get(|headers: HeaderMap| async move { respond(&STYLE, "style.css", &headers) }),
        )
        .route(
            "/static/shell.css",
            get(|headers: HeaderMap| async move { respond(&SHELL, "shell.css", &headers) }),
        )
}
