//! The `Origin` guard, the protocol header, the absence of CORS and the
//! rewriting of the kit's cookies.

mod support;

use std::net::SocketAddr;

use axum::Router;
use axum::body::{Body, to_bytes};
use axum::extract::ConnectInfo;
use axum::http::header::SET_COOKIE;
use axum::http::{HeaderMap, HeaderValue, Method, Request, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{any, post};
use ferret_server::http::{admin_layers, vault_layers};
use ferret_server::state::FerretState;
use support::{ADMIN_URL, Req, TestApp, VAULT_URL, Which};
use tower::ServiceExt as _;
use vole_kit::auth::session::{PendingLogin, SessionClaims, pending_cookie, session_cookie};

const COOKIE: &str = "__Host-ferret_sid=abc";

async fn ok() -> StatusCode {
    StatusCode::NO_CONTENT
}

fn layered(app: &TestApp, which: Which, routes: Router<FerretState>) -> Router {
    let routes = routes.with_state(app.state.clone());
    match which {
        Which::Vault => vault_layers(routes, &app.state),
        Which::Admin => admin_layers(routes, &app.state),
    }
}

/// A listener with routes that answer `204` and the layers of the server.
fn listener(app: &TestApp, which: Which) -> Router {
    let routes: Router<FerretState> = Router::new()
        .route("/probe", any(ok))
        .route("/api/auth/handoff", post(ok))
        .route("/api/auth/handoff/redeem", post(ok));
    layered(app, which, routes)
}

async fn send(router: &Router, request: Request<Body>) -> (StatusCode, HeaderMap, Vec<u8>) {
    let mut request = request;
    let peer: SocketAddr = support::PEER.parse().expect("a peer");
    request.extensions_mut().insert(ConnectInfo(peer));
    let response = router.clone().oneshot(request).await.expect("a response");
    let (parts, body) = response.into_parts();
    let body = to_bytes(body, 1 << 20).await.expect("a body");
    (parts.status, parts.headers, body.to_vec())
}

fn error_code(body: &[u8]) -> String {
    let value: serde_json::Value = serde_json::from_slice(body).expect("a JSON body");
    value["error"].as_str().expect("an error code").to_string()
}

/// A mutation with the protocol header and a session cookie.
fn with_cookie(path: &str) -> Req {
    Req::post(path)
        .header("ferret-protocol", "1")
        .header("cookie", COOKIE)
}

#[tokio::test]
async fn origin_guard_requires_the_protocol_header_on_mutations() {
    let app = TestApp::new().await;
    for which in [Which::Vault, Which::Admin] {
        let router = listener(&app, which);
        for method in [Method::POST, Method::PUT, Method::PATCH, Method::DELETE] {
            for header in [
                None,
                Some(""),
                Some("0"),
                Some("2"),
                Some("1 "),
                Some("true"),
            ] {
                let mut req = Req::new(method.clone(), "/probe");
                if let Some(value) = header {
                    req = req.header("ferret-protocol", value);
                }
                let (status, _, body) = send(&router, req.build()).await;
                assert_eq!(status, StatusCode::BAD_REQUEST, "{method} {header:?}");
                assert_eq!(error_code(&body), "protocol_header_missing");
            }
            let req = Req::new(method.clone(), "/probe").header("ferret-protocol", "1");
            let (status, _, _) = send(&router, req.build()).await;
            assert_eq!(status, StatusCode::NO_CONTENT, "{method}");
        }
        // Reads need nothing.
        for method in [Method::GET, Method::HEAD, Method::OPTIONS] {
            let (status, _, _) = send(&router, Req::new(method.clone(), "/probe").build()).await;
            assert_eq!(status, StatusCode::NO_CONTENT, "{method}");
        }
        // The same header twice is not the header.
        let req = Req::post("/probe")
            .header("ferret-protocol", "1")
            .header("ferret-protocol", "1");
        let (status, _, _) = send(&router, req.build()).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
    }
}

#[tokio::test]
async fn the_protocol_header_is_checked_before_the_origin() {
    let app = TestApp::new().await;
    let router = listener(&app, Which::Vault);
    let req = Req::post("/probe")
        .header("cookie", COOKIE)
        .header("origin", "https://evil.test");
    let (status, _, body) = send(&router, req.build()).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(error_code(&body), "protocol_header_missing");
}

#[tokio::test]
async fn cross_site_and_same_site_requests_with_cookie_are_403() {
    let app = TestApp::new().await;
    for which in [Which::Vault, Which::Admin] {
        let router = listener(&app, which);
        for site in ["cross-site", "same-site", "other", ""] {
            // With the right Origin and without any.
            for origin in [Some(which.url()), None] {
                let mut req = with_cookie("/probe").header("sec-fetch-site", site);
                if let Some(origin) = origin {
                    req = req.header("origin", origin);
                }
                let (status, _, body) = send(&router, req.build()).await;
                assert_eq!(status, StatusCode::FORBIDDEN, "{which:?} {site} {origin:?}");
                assert_eq!(error_code(&body), "forbidden_origin");
            }
        }
        // Another site's origin, and the other listener's.
        let other = match which {
            Which::Vault => ADMIN_URL,
            Which::Admin => VAULT_URL,
        };
        for origin in ["https://evil.test", "null", other] {
            let req = with_cookie("/probe")
                .header("origin", origin)
                .header("sec-fetch-site", "same-origin");
            let (status, _, body) = send(&router, req.build()).await;
            assert_eq!(status, StatusCode::FORBIDDEN, "{which:?} {origin}");
            assert_eq!(error_code(&body), "forbidden_origin");
        }
    }
}

#[tokio::test]
async fn same_origin_fetch_passes() {
    let app = TestApp::new().await;
    for which in [Which::Vault, Which::Admin] {
        let router = listener(&app, which);
        // What a page sends with `fetch`.
        let req = Req::post("/probe")
            .page_fetch(which)
            .header("cookie", COOKIE)
            .header("sec-fetch-site", "same-origin");
        let (status, _, _) = send(&router, req.build()).await;
        assert_eq!(status, StatusCode::NO_CONTENT, "{which:?}");
        // The origin alone, and fetch metadata alone.
        let req = Req::put("/probe")
            .page_fetch(which)
            .header("cookie", COOKIE);
        let (status, _, _) = send(&router, req.build()).await;
        assert_eq!(status, StatusCode::NO_CONTENT, "{which:?} origin only");
        for site in ["same-origin", "none"] {
            let req = with_cookie("/probe").header("sec-fetch-site", site);
            let (status, _, _) = send(&router, req.build()).await;
            assert_eq!(status, StatusCode::NO_CONTENT, "{which:?} {site}");
        }
        // Without a cookie, a call with the protocol header passes.
        let req = Req::post("/probe").header("ferret-protocol", "1");
        let (status, _, _) = send(&router, req.build()).await;
        assert_eq!(status, StatusCode::NO_CONTENT, "{which:?} no cookie");
    }
}

#[tokio::test]
async fn cookie_without_origin_or_fetch_metadata_is_403() {
    let app = TestApp::new().await;
    for which in [Which::Vault, Which::Admin] {
        let router = listener(&app, which);
        for cookie in [COOKIE, "ferret_flash=x", "a=b; c=d"] {
            let req = Req::post("/probe")
                .header("ferret-protocol", "1")
                .header("cookie", cookie);
            let (status, _, body) = send(&router, req.build()).await;
            assert_eq!(status, StatusCode::FORBIDDEN, "{which:?} {cookie}");
            assert_eq!(error_code(&body), "forbidden_origin");
        }
    }
}

#[tokio::test]
async fn origin_is_compared_to_the_configured_url_not_the_host_header() {
    let app = TestApp::new().await;
    let router = listener(&app, Which::Vault);
    let call = |host: &str, origin: &str| {
        with_cookie("/probe")
            .header("host", host)
            .header("origin", origin)
            .build()
    };
    // A request whose Origin matches its own Host but not the configured URL.
    let (status, _, _) = send(&router, call("attacker.test", "https://attacker.test")).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    // The right Origin passes whatever the Host says (a proxy may rewrite it).
    let (status, _, _) = send(&router, call("attacker.test", VAULT_URL)).await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    let (status, _, _) = send(&router, call("vault.ferret.test", "https://evil.test")).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    // Only the exact configured origin: not another scheme, port or form.
    for origin in [
        "http://vault.ferret.test",
        "https://vault.ferret.test:443",
        "https://vault.ferret.test:8443",
        "https://vault.ferret.test/",
        "https://vault.ferret.test.evil.test",
        "https://evil.vault.ferret.test",
    ] {
        let (status, _, _) = send(&router, call("vault.ferret.test", origin)).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{origin}");
    }
}

#[tokio::test]
async fn the_hand_over_routes_need_the_listeners_origin_without_a_cookie() {
    let app = TestApp::new().await;
    for (which, other) in [(Which::Vault, ADMIN_URL), (Which::Admin, VAULT_URL)] {
        let router = listener(&app, which);
        for path in ["/api/auth/handoff", "/api/auth/handoff/redeem"] {
            for origin in [None, Some("https://evil.test"), Some(other), Some("null")] {
                let mut req = Req::post(path)
                    .header("ferret-protocol", "1")
                    .header("sec-fetch-site", "same-origin");
                if let Some(origin) = origin {
                    req = req.header("origin", origin);
                }
                let (status, _, body) = send(&router, req.build()).await;
                assert_eq!(status, StatusCode::FORBIDDEN, "{which:?} {path} {origin:?}");
                assert_eq!(error_code(&body), "forbidden_origin");
            }
            let (status, _, _) = send(&router, Req::post(path).page_fetch(which).build()).await;
            assert_eq!(status, StatusCode::NO_CONTENT, "{which:?} {path}");
        }
        // Another route needs no origin when there is no cookie.
        let req = Req::post("/probe").header("ferret-protocol", "1");
        let (status, _, _) = send(&router, req.build()).await;
        assert_eq!(status, StatusCode::NO_CONTENT);
    }
}

#[tokio::test]
async fn the_guard_is_in_front_of_both_real_listeners() {
    let app = TestApp::new().await;
    for which in [Which::Vault, Which::Admin] {
        let res = app
            .call(which, Req::post("/api/auth/login/start").build())
            .await;
        assert_eq!(res.status, StatusCode::BAD_REQUEST, "{which:?}");
        assert_eq!(res.json()["error"], "protocol_header_missing");
        let req = Req::post("/api/auth/handoff")
            .header("ferret-protocol", "1")
            .header("origin", "https://evil.test");
        let res = app.call(which, req.build()).await;
        assert_eq!(res.status, StatusCode::FORBIDDEN, "{which:?}");
        assert_eq!(res.json()["error"], "forbidden_origin");
    }
}

/// A listener whose one route answers with the given `Set-Cookie` values.
fn setting(app: &TestApp, which: Which, cookies: Vec<String>) -> Router {
    let routes: Router<FerretState> = Router::new().route(
        "/set",
        any(move || {
            let cookies = cookies.clone();
            async move {
                let mut response: Response = StatusCode::NO_CONTENT.into_response();
                for cookie in cookies {
                    response.headers_mut().append(
                        SET_COOKIE,
                        HeaderValue::from_str(&cookie).expect("a cookie"),
                    );
                }
                response
            }
        }),
    );
    layered(app, which, routes)
}

/// The cookie without its `SameSite` attribute.
fn without_same_site(cookie: &str) -> String {
    cookie
        .split("; ")
        .filter(|a| !a.to_ascii_lowercase().starts_with("samesite="))
        .collect::<Vec<_>>()
        .join("; ")
}

#[tokio::test]
async fn strict_cookie_rewrites_the_kits_lax_cookie_including_the_hourly_reissue() {
    // The app starts the kit's configuration that the cookie builders read.
    let app = TestApp::new().await;
    let now = 1_793_491_200;
    let claims = SessionClaims::new(7, 1, now);
    let reissued = claims.refreshed(now + 3600);
    let pending = PendingLogin {
        user_id: 7,
        version: 1,
        issued_at: now,
        next: "/".to_string(),
    };
    let kit = vec![
        session_cookie(&claims, true).to_string(),
        session_cookie(&reissued, true).to_string(),
        pending_cookie(&pending, true).to_string(),
        "ferret_flash=abc; Path=/; HttpOnly; SameSite=Lax; Secure".to_string(),
    ];
    for cookie in &kit {
        assert!(
            cookie.contains("SameSite=Lax"),
            "the kit sets Lax: {cookie}"
        );
    }
    let mut cookies = kit;
    cookies.push("no_attribute=1; Path=/".to_string());
    for which in [Which::Vault, Which::Admin] {
        let router = setting(&app, which, cookies.clone());
        let (status, headers, _) = send(&router, Req::get("/set").build()).await;
        assert_eq!(status, StatusCode::NO_CONTENT);
        let sent: Vec<&str> = headers
            .get_all(SET_COOKIE)
            .iter()
            .map(|v| v.to_str().expect("text"))
            .collect();
        assert_eq!(sent.len(), cookies.len(), "{which:?}");
        for (rewritten, original) in sent.iter().zip(&cookies) {
            assert_eq!(rewritten.matches("SameSite=").count(), 1, "{rewritten}");
            assert!(rewritten.ends_with("SameSite=Strict"), "{rewritten}");
            // The rest is as it was: name, value and the other attributes.
            assert_eq!(
                without_same_site(rewritten),
                without_same_site(original),
                "{rewritten}"
            );
        }
    }
}

#[tokio::test]
async fn no_cors_headers_are_ever_sent() {
    let app = TestApp::new().await;
    for which in [Which::Vault, Which::Admin] {
        for (method, path) in [
            (Method::GET, "/healthz"),
            (Method::GET, "/nope"),
            (Method::GET, "/"),
            (Method::POST, "/api/auth/login/start"),
            (Method::OPTIONS, "/api/auth/login/start"),
        ] {
            let req = Req::new(method.clone(), path)
                .header("origin", "https://evil.test")
                .header("access-control-request-method", "POST")
                .header("access-control-request-headers", "ferret-protocol");
            let res = app.call(which, req.build()).await;
            for name in res.headers.keys() {
                assert!(
                    !name.as_str().starts_with("access-control-"),
                    "{which:?} {method} {path}: {name}"
                );
            }
        }
    }
    // A handler that sets one has it removed.
    let routes: Router<FerretState> = Router::new().route(
        "/cors",
        any(|| async { ([("access-control-allow-origin", "*")], "x") }),
    );
    let router = layered(&app, Which::Vault, routes);
    let (_, headers, _) = send(&router, Req::get("/cors").build()).await;
    assert!(headers.get("access-control-allow-origin").is_none());
}

#[tokio::test]
async fn preflight_gets_no_allow_origin() {
    let app = TestApp::new().await;
    for which in [Which::Vault, Which::Admin] {
        for path in ["/api/auth/login/start", "/api/sync/changes", "/probe", "/"] {
            let req = Req::new(Method::OPTIONS, path)
                .header("origin", "https://evil.test")
                .header("access-control-request-method", "PUT")
                .header(
                    "access-control-request-headers",
                    "ferret-protocol, content-type",
                );
            let res = app.call(which, req.build()).await;
            assert!(
                res.headers.get("access-control-allow-origin").is_none(),
                "{which:?} {path}"
            );
            assert!(res.headers.get("access-control-allow-headers").is_none());
            assert!(res.headers.get("access-control-allow-methods").is_none());
            assert_ne!(res.status, StatusCode::OK, "{which:?} {path}");
            assert_ne!(res.status, StatusCode::NO_CONTENT, "{which:?} {path}");
        }
    }
}

#[tokio::test]
async fn the_admin_listener_keeps_no_referrer_and_nosniff() {
    let app = TestApp::new().await;
    for path in ["/healthz", "/login", "/nope"] {
        let res = app.call(Which::Admin, Req::get(path).build()).await;
        assert_eq!(res.header("referrer-policy"), "no-referrer", "{path}");
        assert_eq!(res.header("x-content-type-options"), "nosniff", "{path}");
    }
}

#[tokio::test]
async fn refusals_carry_the_headers_of_their_listener() {
    let app = TestApp::new().await;
    let headers: std::collections::BTreeMap<String, String> =
        serde_json::from_str(include_str!("fixtures/wire/headers.json")).expect("headers.json");
    let router = listener(&app, Which::Vault);
    for request in [
        Req::post("/probe").build(),
        with_cookie("/probe")
            .header("origin", "https://evil.test")
            .build(),
    ] {
        let (status, got, _) = send(&router, request).await;
        assert!(status.is_client_error());
        for (name, value) in &headers {
            assert_eq!(got[name.as_str()], value.as_str(), "{name}");
        }
    }
    let router = listener(&app, Which::Admin);
    let (status, got, _) = send(&router, Req::post("/probe").build()).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(got["referrer-policy"], "no-referrer");
    assert_eq!(got["x-content-type-options"], "nosniff");
}
