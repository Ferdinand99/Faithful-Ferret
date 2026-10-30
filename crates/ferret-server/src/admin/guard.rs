//! The guard around the kit's pages on the admin listener: a request needs the
//! kit's signed cookie and Ferret's own session row, and both must agree. The
//! kit's cookie alone opens nothing.
//!
//! `server::admin_router` wraps only the kit's protected router in it. These
//! stay open: `/healthz`, `/static/`, the redirects of `admin::redirects`,
//! `/auth/handoff*`, `/api/auth/handoff/redeem` and `/api/auth/{logout,session}`
//! (the last two check the session themselves).
//!
//! Two more layers sit here because the kit has no switch for what they do:
//!
//! * [`block_unsupported_kit_routes`] answers 404 for the kit's passkey sign-in
//!   and second-factor sign-in, which would make a kit session without the
//!   password check, and for the kit's two-factor settings. A sign-in on the
//!   vault origin refuses an account with a second factor, so a user who turned
//!   it on here would lose the vault and the admin pages both.
//! * [`end_session_on_logout`] ends the session row when the kit's sign-out
//!   runs, so the session is over on the server and not only in the browser.

use axum::extract::{FromRequestParts, Request, State};
use axum::http::header::HeaderValue;
use axum::http::{Method, header};
use axum::middleware::Next;
use axum::response::{IntoResponse, Redirect, Response};
use axum_extra::extract::cookie::SignedCookieJar;
use vole_kit::auth::guard as kit_guard;

use crate::auth::session::{Origin, clear_cookies, lookup, revoke};
use crate::error::ApiError;
use crate::http::extract::AdminSession;
use crate::ids::SessionSecret;
use crate::product;
use crate::state::FerretState;

/// Lets a request through when it has a full session on the admin origin: the
/// session id cookie names a live row of the admin origin within its limits
/// (1 hour idle, 12 hours in all), the kit's cookie agrees with the row, and
/// the user is active and has not moved the kit's session version.
///
/// Otherwise a page that is read (a full-page `GET`) goes to `/login`, which
/// leads to the vault origin's sign-in through the hand-over (and a new
/// install to `/setup`), and everything else is `401 unauthorized`.
pub async fn admin_session_guard(
    State(state): State<FerretState>,
    request: Request,
    next: Next,
) -> Response {
    let (mut parts, body) = request.into_parts();
    match AdminSession::from_request_parts(&mut parts, &state).await {
        Ok(_) => next.run(Request::from_parts(parts, body)).await,
        Err(error) if error != ApiError::unauthorized() => error.into_response(),
        Err(refusal) => {
            let page = parts.method == Method::GET
                && !parts.headers.contains_key("hx-request")
                && !parts.uri.path().starts_with("/api/");
            if !page {
                return refusal.into_response();
            }
            match kit_guard::has_users(&state.core).await {
                Ok(false) => Redirect::to("/setup").into_response(),
                _ => kit_guard::unauthorized(&parts.method, &parts.uri, &parts.headers),
            }
        }
    }
}

/// Whether the kit's route at `path` is one this server turns off.
fn is_unsupported(path: &str) -> bool {
    let under = |prefix: &str| {
        path == prefix
            || path
                .strip_prefix(prefix)
                .is_some_and(|rest| rest.starts_with('/'))
    };
    under("/login/passkey") || under("/login/2fa") || under("/settings/security/2fa")
}

/// Answers 404 for the kit's routes that this server turns off (see the module
/// documentation), whoever asks and with whatever method.
pub async fn block_unsupported_kit_routes(request: Request, next: Next) -> Response {
    if is_unsupported(request.uri().path()) {
        return vole_kit::http::error::not_found().await.into_response();
    }
    next.run(request).await
}

/// On the kit's `POST /logout`: ends the admin session row that the request
/// names, and clears Ferret's cookies along with the kit's. The kit's handler
/// runs as before.
pub async fn end_session_on_logout(
    State(state): State<FerretState>,
    request: Request,
    next: Next,
) -> Response {
    if request.method() != Method::POST || request.uri().path() != "/logout" {
        return next.run(request).await;
    }
    let jar = SignedCookieJar::from_headers(request.headers(), state.core.session_key.clone());
    let sid = jar
        .get(product::SID_COOKIE)
        .and_then(|c| SessionSecret::from_cookie(c.value()).ok())
        .map(|secret| secret.hash());
    if let Some(sid) = sid
        && let Ok(now) = i64::try_from(state.clock.now_unix())
    {
        let ended = state
            .vault_db
            .with_conn(move |conn| {
                if let Some(row) = lookup(conn, &sid)?
                    && row.origin == Origin::Admin
                {
                    revoke(conn, &sid, now)?;
                }
                Ok(())
            })
            .await;
        if let Err(error) = ended {
            tracing::warn!(%error, "the admin session row was not ended at sign-out");
        }
    }
    let mut response = next.run(request).await;
    // The same cookies the sign-out of the API clears, as extra headers. The
    // jar is the request's: a jar removes only the cookies it holds.
    let cleared = clear_cookies(jar).into_response();
    for value in cleared.headers().get_all(header::SET_COOKIE) {
        response
            .headers_mut()
            .append(header::SET_COOKIE, HeaderValue::clone(value));
    }
    response
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_the_turned_off_kit_routes_are_blocked() {
        for path in [
            "/login/passkey",
            "/login/passkey/options",
            "/login/2fa",
            "/settings/security/2fa",
            "/settings/security/2fa/setup",
            "/settings/security/2fa/enable",
            "/settings/security/2fa/recovery",
        ] {
            assert!(is_unsupported(path), "{path}");
        }
        for path in [
            "/login",
            "/login/passkeys",
            "/login/2fax",
            "/settings/security",
            "/settings/security/passkeys",
            "/settings/security/2fanout",
            "/settings/users/3/2fa/reset",
            "/logout",
        ] {
            assert!(!is_unsupported(path), "{path}");
        }
    }
}
