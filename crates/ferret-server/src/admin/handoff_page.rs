//! The small page of the admin origin that redeems a hand-over code: it begins
//! a hand-over (`/auth/handoff/begin`), serves the page (`/auth/handoff`) and
//! its one script (`/auth/handoff.mjs`). Spec: Fase 1 § 2.4.
//!
//! The page has no password field, loads no WASM and has no other script than
//! `/auth/handoff.mjs`. The code reaches it in the URL fragment, which is not
//! sent to the server and not in a `Referer`; the script reads it, removes the
//! fragment from the address and redeems the code with a `fetch`.

use axum::Router;
use axum::extract::{FromRef, RawQuery, State};
use axum::http::header::{CACHE_CONTROL, CONTENT_TYPE, LOCATION};
use axum::http::{HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum_extra::extract::CookieJar;
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use ferret_core::{OsRng, SecureRng as _};

use crate::admin::redirects::query_param;
use crate::auth::handoff::{challenge_of, sanitize_next, verifier_cookie};
use crate::auth::login::no_store;
use crate::config::Origins;
use crate::error::ApiError;
use crate::wire::HANDOFF_CODE_BYTES;

/// The page, from `web/admin/handoff.html`.
const PAGE: &str = include_str!("../../../../web/admin/handoff.html");
/// Its script, from `web/admin/handoff.mjs`.
const SCRIPT: &str = include_str!("../../../../web/admin/handoff.mjs");

/// Where on the vault origin a hand-over starts, by purpose.
const VAULT_LOGIN: &str = "/vault/login";
const VAULT_REAUTH: &str = "/vault/reauth";

/// `GET /auth/handoff/begin?next=<path>[&purpose=login|reauth]`: sets the
/// verifier cookie and sends the browser to the vault origin with the
/// challenge. A purpose other than the two is `bad_request`.
async fn begin(
    State(origins): State<Origins>,
    RawQuery(query): RawQuery,
) -> Result<Response, ApiError> {
    let reauth = match query_param(query.as_deref(), "purpose").as_deref() {
        None | Some("login") => false,
        Some("reauth") => true,
        Some(_) => return Err(ApiError::coded("bad_request")),
    };
    let next = sanitize_next(query_param(query.as_deref(), "next").as_deref());

    let mut verifier = [0u8; HANDOFF_CODE_BYTES];
    let mut rng = OsRng;
    rng.fill(&mut verifier);
    let challenge = URL_SAFE_NO_PAD.encode(challenge_of(&verifier));
    let mut vault_query = url::form_urlencoded::Serializer::new(String::new());
    vault_query.append_pair("handoff", "1");
    vault_query.append_pair("challenge", &challenge);
    vault_query.append_pair("next", &next);
    let location = format!(
        "{}{}?{}",
        origins.vault(),
        if reauth { VAULT_REAUTH } else { VAULT_LOGIN },
        vault_query.finish()
    );
    let location = HeaderValue::from_str(&location).map_err(|_| ApiError::internal())?;

    let mut response = Response::new(axum::body::Body::empty());
    *response.status_mut() = StatusCode::FOUND;
    response.headers_mut().insert(LOCATION, location);
    let jar = CookieJar::new().add(verifier_cookie(&verifier));
    Ok(no_store((jar, response).into_response()))
}

/// `GET /auth/handoff`.
async fn page() -> Response {
    no_store(([(CONTENT_TYPE, "text/html; charset=utf-8")], PAGE).into_response())
}

/// `GET /auth/handoff.mjs`.
async fn script() -> Response {
    let mut response = ([(CONTENT_TYPE, "text/javascript; charset=utf-8")], SCRIPT).into_response();
    response
        .headers_mut()
        .insert(CACHE_CONTROL, HeaderValue::from_static("no-cache"));
    response
}

/// The hand-over page routes.
pub fn routes<S>() -> Router<S>
where
    S: Clone + Send + Sync + 'static,
    Origins: FromRef<S>,
{
    Router::new()
        .route("/auth/handoff/begin", get(begin))
        .route("/auth/handoff", get(page))
        .route("/auth/handoff.mjs", get(script))
}
