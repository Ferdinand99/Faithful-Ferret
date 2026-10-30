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

/// The listener that a request came in on: its public address, as
/// `scheme://host[:port]` (what a browser sends as `Origin`), and where the
/// protocol header is required.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ListenerOrigin {
    /// The configured public address.
    pub origin: String,
    /// Whether `Ferret-Protocol` is required only below `/api/`. The admin
    /// listener serves the kit's pages, whose forms and htmx requests cannot
    /// send a custom header; they are covered by the `Origin` check (and the
    /// kit's own CSRF guard). On the vault listener every mutation needs it.
    pub protocol_only_for_api: bool,
}

impl ListenerOrigin {
    /// The vault listener: the protocol header on every mutation.
    pub fn vault(origin: &str) -> Self {
        Self {
            origin: origin.to_string(),
            protocol_only_for_api: false,
        }
    }

    /// The admin listener: the protocol header on `/api/` mutations.
    pub fn admin(origin: &str) -> Self {
        Self {
            origin: origin.to_string(),
            protocol_only_for_api: true,
        }
    }

    fn is_https(&self) -> bool {
        self.origin.starts_with("https://")
    }
}

/// Whether a method may change state: everything but the safe methods.
fn is_unsafe(method: &Method) -> bool {
    !matches!(*method, Method::GET | Method::HEAD | Method::OPTIONS)
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
    let needs_protocol =
        !listener.protocol_only_for_api || request.uri().path().starts_with("/api/");
    if needs_protocol {
        let protocol = single(headers, &HeaderName::from_static(PROTOCOL_HEADER));
        if protocol != Ok(Some(PROTOCOL_VERSION)) {
            return Err(ApiError::bad_request("protocol_header_missing"));
        }
    }

    let origin = single(headers, &ORIGIN).map_err(|()| ApiError::forbidden_origin())?;
    let fetch_site = single(headers, &HeaderName::from_static("sec-fetch-site"))
        .map_err(|()| ApiError::forbidden_origin())?;
    let origin_matches = origin == Some(listener.origin.as_str());

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
/// On every method but `GET`, `HEAD` and `OPTIONS`:
///
/// * `Ferret-Protocol: 1` is required (`400 protocol_header_missing`), on the
///   admin listener only below `/api/`;
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
    if is_unsafe(request.method())
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

/// Whether a `Set-Cookie` deletes the cookie: an empty value, a `Max-Age` of
/// zero or less, or an `Expires` in a year before 2000.
fn is_removal(value: &str) -> bool {
    let mut parts = value.split(';');
    let first = parts.next().unwrap_or_default();
    if first
        .split_once('=')
        .is_none_or(|(_, v)| v.trim().is_empty())
    {
        return true;
    }
    parts.any(|attribute| {
        let attribute = attribute.trim();
        let (name, val) = attribute.split_once('=').unwrap_or((attribute, ""));
        let (name, val) = (name.trim(), val.trim());
        if name.eq_ignore_ascii_case("max-age") {
            return val.parse::<i64>().is_ok_and(|n| n <= 0);
        }
        if name.eq_ignore_ascii_case("expires") {
            return val
                .split(|c: char| !c.is_ascii_digit())
                .filter(|t| t.len() == 4)
                .filter_map(|t| t.parse::<u32>().ok())
                .any(|year| year < 2000);
        }
        false
    })
}

/// One `Set-Cookie` header with its attributes made safe: `Path=/`,
/// `HttpOnly`, no `Domain`, `SameSite=Strict`, and `Secure` when the listener
/// is https, when the name is `__Host-` or `__Secure-`, and on a removal
/// (browsers ignore the removal of a `__Host-` cookie that lacks `Secure`).
/// The name, the value and every other attribute stay as they were.
fn harden(value: &str, https: bool) -> String {
    let removal = is_removal(value);
    let mut parts = value.split(';');
    let first = parts.next().unwrap_or_default().trim();
    let name = first.split('=').next().unwrap_or_default();
    let secure = https || removal || name.starts_with("__Host-") || name.starts_with("__Secure-");
    let mut out = first.to_string();
    for attribute in parts {
        let attribute = attribute.trim();
        let attribute_name = attribute.split('=').next().unwrap_or_default().trim();
        let replaced = ["samesite", "domain", "path", "httponly", "secure"];
        if attribute_name.is_empty()
            || replaced
                .iter()
                .any(|r| attribute_name.eq_ignore_ascii_case(r))
        {
            continue;
        }
        out.push_str("; ");
        out.push_str(attribute);
    }
    out.push_str("; Path=/; HttpOnly");
    if secure {
        out.push_str("; Secure");
    }
    out.push_str("; SameSite=Strict");
    out
}

/// Hardens every `Set-Cookie` of the response (see [`harden`]).
///
/// The kit sets its cookies with `SameSite=Lax` (the session cookie, also when
/// it is re-issued as the idle timer slides, the cookie between password and
/// second factor, the flash message), and its removal cookies have a path and
/// nothing else. Ferret has no sign-in that comes from another site, so none
/// of its cookies is sent on a cross-site navigation, and every cookie is
/// host-only. A header that is not text is dropped.
pub async fn strict_cookie(
    State(listener): State<ListenerOrigin>,
    request: Request,
    next: Next,
) -> Response {
    let mut response = next.run(request).await;
    let headers = response.headers_mut();
    let cookies: Vec<HeaderValue> = headers.get_all(SET_COOKIE).iter().cloned().collect();
    if cookies.is_empty() {
        return response;
    }
    headers.remove(SET_COOKIE);
    for cookie in cookies {
        let Ok(text) = cookie.to_str() else { continue };
        if let Ok(value) = HeaderValue::from_str(&harden(text, listener.is_https())) {
            headers.append(SET_COOKIE, value);
        }
    }
    response
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn harden_replaces_or_adds_the_attributes() {
        assert_eq!(
            harden(
                "a=b; Domain=evil.test; Path=/x; SameSite=Lax; Max-Age=60",
                true
            ),
            "a=b; Max-Age=60; Path=/; HttpOnly; Secure; SameSite=Strict"
        );
        assert_eq!(
            harden("a=b; samesite=None; secure; httponly", true),
            "a=b; Path=/; HttpOnly; Secure; SameSite=Strict"
        );
        assert_eq!(
            harden("a=b", false),
            "a=b; Path=/; HttpOnly; SameSite=Strict"
        );
    }

    #[test]
    fn secure_is_added_for_prefixed_names_and_removals_on_any_listener() {
        assert!(harden("__Host-x=1; Path=/", false).contains("; Secure;"));
        assert!(harden("__Secure-x=1", false).contains("; Secure;"));
        assert!(harden("x=; Path=/", false).contains("; Secure;"));
        assert!(harden("x=1; Max-Age=0", false).contains("; Secure;"));
        assert!(harden("x=1; Max-Age=-5", false).contains("; Secure;"));
        assert!(harden("x=1; Expires=Thu, 01 Jan 1970 00:00:00 GMT", false).contains("; Secure;"));
        assert!(!harden("x=1; Max-Age=60", false).contains("Secure"));
        assert!(!harden("x=1; Expires=Fri, 01 Jan 2100 00:00:00 GMT", false).contains("Secure"));
    }
}
