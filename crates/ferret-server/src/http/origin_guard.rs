//! The `Origin` and `Ferret-Protocol` check on every mutating request, the
//! fetch-metadata check for requests with a cookie, and the rewriting of the
//! cookies the kit sets.
//!
//! Spec: Fase 1 § 8.2. The origin is compared with the configured public URL of
//! the listener (`config::Origins`), never with the `Host` header. Ferret sends
//! no CORS headers at all: a response never carries an `Access-Control-*`
//! header, and a pre-flight request gets no `Access-Control-Allow-Origin`, so
//! no other site can read an answer or send a request with the protocol header.

use axum::extract::{Request, State};
use axum::http::header::{COOKIE, ORIGIN, SET_COOKIE};
use axum::http::{HeaderMap, HeaderName, HeaderValue, Method};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};

use crate::error::ApiError;

/// The header every mutating call carries. A browser can send it cross-origin
/// only after a successful pre-flight, which Ferret never allows.
pub const PROTOCOL_HEADER: &str = "ferret-protocol";
/// The only value of [`PROTOCOL_HEADER`] this version speaks.
pub const PROTOCOL_VERSION: &str = "1";

/// The hand-over routes. They need the right `Origin` even without a cookie:
/// a hand-over code is minted and redeemed only by the page of the listener it
/// belongs to.
const ORIGIN_REQUIRED_PATHS: [&str; 2] = ["/api/auth/handoff", "/api/auth/handoff/redeem"];

/// The public address of the listener that a request came in on, as
/// `scheme://host[:port]` (what a browser sends as `Origin`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ListenerOrigin(pub String);

fn is_mutation(method: &Method) -> bool {
    matches!(
        *method,
        Method::POST | Method::PUT | Method::PATCH | Method::DELETE
    )
}

/// The only value of a header: `Ok(None)` if there is none, `Err` if there are
/// several or the value is not text.
fn single<'a>(headers: &'a HeaderMap, name: &HeaderName) -> Result<Option<&'a str>, ()> {
    let mut values = headers.get_all(name).iter();
    let Some(first) = values.next() else {
        return Ok(None);
    };
    if values.next().is_some() {
        return Err(());
    }
    first.to_str().map(Some).map_err(|_| ())
}

/// Whether the request carries any cookie at all.
fn has_cookie(headers: &HeaderMap) -> bool {
    headers
        .get_all(COOKIE)
        .iter()
        .any(|v| !v.as_bytes().iter().all(u8::is_ascii_whitespace))
}

/// Decides a mutating request: `Ok`, or the error to answer with.
fn check_mutation(listener: &ListenerOrigin, request: &Request) -> Result<(), ApiError> {
    let headers = request.headers();
    let protocol = single(headers, &HeaderName::from_static(PROTOCOL_HEADER));
    if protocol != Ok(Some(PROTOCOL_VERSION)) {
        return Err(ApiError::bad_request("protocol_header_missing"));
    }

    let origin = single(headers, &ORIGIN).map_err(|()| ApiError::forbidden_origin())?;
    let fetch_site = single(headers, &HeaderName::from_static("sec-fetch-site"))
        .map_err(|()| ApiError::forbidden_origin())?;
    let origin_matches = origin == Some(listener.0.as_str());

    // The hand-over routes need the listener's own page, cookie or not.
    if ORIGIN_REQUIRED_PATHS.contains(&request.uri().path()) && !origin_matches {
        return Err(ApiError::forbidden_origin());
    }

    if has_cookie(headers) {
        // A browser that says the request is from another site is believed,
        // whatever else the request claims.
        if !matches!(fetch_site, None | Some("same-origin" | "none")) {
            return Err(ApiError::forbidden_origin());
        }
        match origin {
            Some(_) if origin_matches => {}
            Some(_) => return Err(ApiError::forbidden_origin()),
            // Without `Origin`, only the browser's own word that the request
            // is from the same origin (or from the address bar) counts.
            None if fetch_site.is_some() => {}
            None => return Err(ApiError::forbidden_origin()),
        }
    }
    Ok(())
}

/// The `Origin` and protocol check of one listener, and the end of every
/// `Access-Control-*` header.
///
/// On `POST`, `PUT`, `PATCH` and `DELETE`:
///
/// * `Ferret-Protocol: 1` is required (`400 protocol_header_missing`);
/// * with a cookie, `Origin` must equal the listener's configured public URL
///   or, when there is no `Origin`, `Sec-Fetch-Site` must be `same-origin` or
///   `none` (`403 forbidden_origin`); `cross-site` and `same-site` are refused;
/// * `POST /api/auth/handoff` and `/api/auth/handoff/redeem` need the right
///   `Origin` with or without a cookie.
///
/// Spec: Fase 1 § 8.2.
pub async fn origin_guard(
    State(listener): State<ListenerOrigin>,
    request: Request,
    next: Next,
) -> Response {
    if is_mutation(request.method())
        && let Err(refusal) = check_mutation(&listener, &request)
    {
        return refusal.into_response();
    }
    let mut response = next.run(request).await;
    let cors: Vec<HeaderName> = response
        .headers()
        .keys()
        .filter(|name| name.as_str().starts_with("access-control-"))
        .cloned()
        .collect();
    for name in cors {
        response.headers_mut().remove(name);
    }
    response
}

/// `value` of one `Set-Cookie` header with `SameSite=Strict`, whatever it said
/// before (or nothing).
fn strictify(value: &str) -> String {
    let mut parts = value.split(';');
    let mut out = parts.next().unwrap_or_default().trim().to_string();
    for attribute in parts {
        let attribute = attribute.trim();
        let name = attribute.split('=').next().unwrap_or_default().trim();
        if name.is_empty() || name.eq_ignore_ascii_case("samesite") {
            continue;
        }
        out.push_str("; ");
        out.push_str(attribute);
    }
    out.push_str("; SameSite=Strict");
    out
}

/// Rewrites every `Set-Cookie` of the response to `SameSite=Strict`.
///
/// The kit sets its cookies with `SameSite=Lax` (the session cookie, also when
/// it is re-issued as the idle timer slides, the cookie between password and
/// second factor, the flash message). Ferret has no sign-in that comes from
/// another site, so none of its cookies is sent on a cross-site navigation.
/// A header that is not text is dropped.
pub async fn strict_cookie(request: Request, next: Next) -> Response {
    let mut response = next.run(request).await;
    let headers = response.headers_mut();
    let cookies: Vec<HeaderValue> = headers.get_all(SET_COOKIE).iter().cloned().collect();
    if cookies.is_empty() {
        return response;
    }
    headers.remove(SET_COOKIE);
    for cookie in cookies {
        let Ok(text) = cookie.to_str() else { continue };
        if let Ok(value) = HeaderValue::from_str(&strictify(text)) {
            headers.append(SET_COOKIE, value);
        }
    }
    response
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strictify_replaces_or_adds_the_attribute() {
        assert_eq!(
            strictify("a=b; Path=/; HttpOnly; SameSite=Lax; Secure; Max-Age=60"),
            "a=b; Path=/; HttpOnly; Secure; Max-Age=60; SameSite=Strict"
        );
        assert_eq!(strictify("a=b; samesite=None"), "a=b; SameSite=Strict");
        assert_eq!(strictify("a=b"), "a=b; SameSite=Strict");
        assert_eq!(
            strictify("a=b; Path=/; SameSite=Lax; SameSite=None"),
            "a=b; Path=/; SameSite=Strict"
        );
    }
}
