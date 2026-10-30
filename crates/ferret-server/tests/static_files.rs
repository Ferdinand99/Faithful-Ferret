//! The files of the web vault: their types and headers, the paths that are
//! served and the ones that are not, and what the admin listener does not
//! serve.

mod support;

use std::collections::{BTreeMap, BTreeSet};
use std::net::SocketAddr;
use std::sync::Arc;

use axum::Router;
use axum::body::{Body, to_bytes};
use axum::extract::ConnectInfo;
use axum::http::{HeaderMap, Request, StatusCode};
use ferret_server::error::ApiError;
use ferret_server::http::static_files::{MemorySource, StaticFile, vault_routes};
use ferret_server::http::vault_layers;
use ferret_server::state::FerretState;
use sha2::{Digest, Sha256};
use support::{Req, TestApp, Which};
use tower::ServiceExt as _;

const HEADERS: &str = include_str!("fixtures/wire/headers.json");
const INDEX: &str = "<!doctype html><title>Faithful Ferret</title>";
const JS: &str = "text/javascript; charset=utf-8";
const JSON: &str = "application/json; charset=utf-8";
const HTML: &str = "text/html; charset=utf-8";

fn file(bytes: &'static [u8], content_type: &'static str) -> StaticFile {
    StaticFile {
        bytes: bytes.into(),
        content_type,
        sha256: Sha256::digest(bytes).into(),
    }
}

/// A web vault of every kind of file, and a few that must never be served.
fn source() -> Arc<MemorySource> {
    let mut files = BTreeMap::new();
    files.insert("index.html", file(INDEX.as_bytes(), HTML));
    files.insert("app/boot.mjs", file(b"export {};", JS));
    files.insert("app/locales.en.json", file(b"{}", JSON));
    files.insert("js/client.js", file(b"1;", JS));
    files.insert("js/vault.worker.mjs", file(b"self.onmessage = null;", JS));
    files.insert(
        "pkg-web/ferret_core_wasm_bg.wasm",
        file(b"\0asm\x01\0\0\0", "application/wasm"),
    );
    files.insert("assets/app.css", file(b"body{}", "text/css; charset=utf-8"));
    // Not under a served directory, or of a type that is not served.
    files.insert("admin/redeem.mjs", file(b"export {};", JS));
    files.insert("manifest.json", file(b"{}", JSON));
    files.insert("secret.html", file(b"secret", HTML));
    files.insert("app/notes.txt", file(b"notes", "text/plain"));
    Arc::new(MemorySource(
        files.into_iter().map(|(k, v)| (k.to_string(), v)).collect(),
    ))
}

async fn not_found() -> ApiError {
    ApiError::not_found()
}

/// The vault listener with the layers of the server and the files of `source`.
fn vault(app: &TestApp, source: Arc<MemorySource>) -> Router {
    let routes: Router<FerretState> = Router::new()
        .merge(vault_routes(source))
        .fallback(not_found);
    vault_layers(routes.with_state(app.state.clone()), &app.state)
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

async fn get(router: &Router, path: &str) -> (StatusCode, HeaderMap, Vec<u8>) {
    send(router, Req::get(path).build()).await
}

fn fixture() -> BTreeMap<String, String> {
    serde_json::from_str(HEADERS).expect("headers.json")
}

fn assert_section_12(headers: &HeaderMap, what: &str) {
    for (name, value) in fixture() {
        assert_eq!(
            headers.get(&name).and_then(|v| v.to_str().ok()),
            Some(value.as_str()),
            "{what}: {name}"
        );
    }
    assert_eq!(headers["x-content-type-options"], "nosniff", "{what}");
}

#[tokio::test]
async fn static_files_carry_the_section_12_headers() {
    let app = TestApp::new().await;
    let router = vault(&app, source());
    for path in [
        "/",
        "/index.html",
        "/vault/login",
        "/app/boot.mjs",
        "/app/locales.en.json",
        "/js/client.js",
        "/js/vault.worker.mjs",
        "/pkg-web/ferret_core_wasm_bg.wasm",
        "/assets/app.css",
    ] {
        let (status, headers, _) = get(&router, path).await;
        assert_eq!(status, StatusCode::OK, "{path}");
        assert_section_12(&headers, path);
    }
    // The answers that carry no file have them too.
    let (status, headers, _) = get(&router, "/nope").await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_section_12(&headers, "404");
    let (_, headers, _) = get(&router, "/app/boot.mjs").await;
    let etag = headers["etag"].to_str().expect("etag").to_string();
    let (status, headers, _) = send(
        &router,
        Req::get("/app/boot.mjs")
            .header("if-none-match", &etag)
            .build(),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_MODIFIED);
    assert_section_12(&headers, "304");
}

#[tokio::test]
async fn wasm_is_served_as_application_wasm_and_mjs_as_javascript() {
    let app = TestApp::new().await;
    let router = vault(&app, source());
    let types = [
        ("/pkg-web/ferret_core_wasm_bg.wasm", "application/wasm"),
        ("/app/boot.mjs", JS),
        ("/js/client.js", JS),
        ("/js/vault.worker.mjs", JS),
        ("/assets/app.css", "text/css; charset=utf-8"),
        ("/app/locales.en.json", JSON),
        ("/index.html", HTML),
    ];
    for (path, content_type) in types {
        let (status, headers, _) = get(&router, path).await;
        assert_eq!(status, StatusCode::OK, "{path}");
        assert_eq!(headers["content-type"], content_type, "{path}");
    }
}

#[tokio::test]
async fn unknown_path_is_404_not_index_html_but_spa_paths_are_index() {
    let app = TestApp::new().await;
    let router = vault(&app, source());
    for path in [
        "/nope",
        "/login",
        "/app",
        "/app/",
        "/app/missing.mjs",
        "/js/",
        "/pkg-web/nothing.wasm",
        "/secret.html",
        "/admin/redeem.mjs",
        "/manifest.json",
        "/app/notes.txt",
        "/index.htm",
    ] {
        let (status, _, body) = get(&router, path).await;
        assert_eq!(status, StatusCode::NOT_FOUND, "{path}");
        assert_eq!(body, br#"{"error":"not_found"}"#, "{path}");
    }
    for path in [
        "/",
        "/index.html",
        "/vault",
        "/vault/",
        "/vault/login",
        "/vault/setup",
        "/vault/a/b/c",
    ] {
        let (status, headers, body) = get(&router, path).await;
        assert_eq!(status, StatusCode::OK, "{path}");
        assert_eq!(body, INDEX.as_bytes(), "{path}");
        assert_eq!(headers["content-type"], HTML, "{path}");
    }
}

#[tokio::test]
async fn path_traversal_variants_are_404() {
    let app = TestApp::new().await;
    let router = vault(&app, source());
    assert_eq!(get(&router, "/app/boot.mjs").await.0, StatusCode::OK);
    // A raw NUL never reaches the router: the parser refuses it. A raw
    // backslash does, and is refused by the path check.
    assert!("/app/boot.mjs\0".parse::<axum::http::Uri>().is_err());
    for path in [
        "/app/../index.html",
        "/app/../app/boot.mjs",
        "/app/./boot.mjs",
        "/app//boot.mjs",
        "/app/%2e%2e/index.html",
        "/app/%2E%2E/index.html",
        "/app/.%2e/index.html",
        "/app/..%2findex.html",
        "/app/%2e%2e%2findex.html",
        "/app/%2e%2e%2Findex.html",
        "/app/..\\index.html",
        "/app/..%5cindex.html",
        "/app/%5c..%5cindex.html",
        "/app/%252e%252e/index.html",
        "/app/%252e%252e%252findex.html",
        "/app/%2fboot.mjs",
        "/app/boot.mjs%00",
        "/app/boot.mjs%00.txt",
        "/app/boot%2emjs",
        "/js/..%2fapp%2fboot.mjs",
        "/pkg-web/%c0%ae%c0%ae/index.html",
        "/assets/app.css%20",
        "/assets/%61pp.css",
    ] {
        let (status, _, body) = get(&router, path).await;
        assert_eq!(status, StatusCode::NOT_FOUND, "{path}");
        assert_eq!(body, br#"{"error":"not_found"}"#, "{path}");
    }
}

#[tokio::test]
async fn etag_and_if_none_match_give_304() {
    let app = TestApp::new().await;
    let router = vault(&app, source());
    let (status, headers, body) = get(&router, "/app/boot.mjs").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, b"export {};");
    assert_eq!(headers["cache-control"], "no-cache");
    let digest: String = Sha256::digest(b"export {};")
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    let etag = format!("\"{digest}\"");
    assert_eq!(headers["etag"], etag.as_str());

    for presented in [
        etag.clone(),
        format!("W/{etag}"),
        format!("\"other\", {etag}"),
        "*".to_string(),
    ] {
        let (status, headers, body) = send(
            &router,
            Req::get("/app/boot.mjs")
                .header("if-none-match", &presented)
                .build(),
        )
        .await;
        assert_eq!(status, StatusCode::NOT_MODIFIED, "{presented}");
        assert!(body.is_empty(), "{presented}");
        assert_eq!(headers["etag"], etag.as_str());
        assert_eq!(headers["cache-control"], "no-cache");
    }
    let (status, _, body) = send(
        &router,
        Req::get("/app/boot.mjs")
            .header("if-none-match", "\"other\"")
            .build(),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, b"export {};");
    // The page answers the same way.
    let (_, headers, _) = get(&router, "/").await;
    let page_etag = headers["etag"].to_str().expect("etag").to_string();
    let (status, _, _) = send(
        &router,
        Req::get("/vault/login")
            .header("if-none-match", &page_etag)
            .build(),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_MODIFIED);
}

/// A redirect target of an answer that stays on the admin listener.
fn local_location(headers: &HeaderMap) -> Option<String> {
    let location = headers.get("location")?.to_str().ok()?;
    if location.starts_with('/') && !location.starts_with("//") {
        return Some(location.to_string());
    }
    location
        .strip_prefix(support::ADMIN_URL)
        .map(str::to_string)
        .filter(|rest| rest.starts_with('/'))
}

#[tokio::test]
async fn admin_listener_serves_no_wasm_no_workers_and_no_password_field() {
    let app = TestApp::new().await;
    // The vault's files are not served here whatever the path.
    for path in [
        "/index.html",
        "/app/boot.mjs",
        "/js/vault.worker.mjs",
        "/js/client.mjs",
        "/pkg-web/ferret_core_wasm_bg.wasm",
        "/pkg-web/ferret_core_wasm.js",
        "/assets/app.css",
        "/vault/app",
    ] {
        let res = app.call(Which::Admin, Req::get(path).build()).await;
        assert!(
            res.status == StatusCode::NOT_FOUND || res.status.is_redirection(),
            "{path}: {}",
            res.status
        );
        assert!(!res.header("content-type").contains("wasm"), "{path}");
    }
    // Every page the admin listener gives without a session, and what they
    // lead to on the same listener, has no password field, no WASM and no
    // worker.
    let mut queue: Vec<String> = [
        "/",
        "/login",
        "/setup",
        "/settings",
        "/users",
        "/security",
        "/healthz",
        "/static/favicon.svg",
        "/vault/login",
        "/vault/setup",
        "/vault/password",
        "/vault/reauth",
        "/auth/handoff",
        "/auth/handoff/begin",
        "/api/auth/session",
        "/docs",
    ]
    .iter()
    .map(ToString::to_string)
    .collect();
    let mut seen = BTreeSet::new();
    while let Some(path) = queue.pop() {
        if !seen.insert(path.clone()) {
            continue;
        }
        assert!(seen.len() <= 80, "the crawl does not end: {seen:?}");
        let res = app.call(Which::Admin, Req::get(&path).build()).await;
        let text = res.text().to_ascii_lowercase();
        assert!(!text.contains("type=\"password\""), "{path}");
        assert!(!text.contains("type='password'"), "{path}");
        assert!(!text.contains("/pkg-web"), "{path}");
        assert!(!text.contains("vault.worker"), "{path}");
        assert!(!text.contains(".wasm"), "{path}");
        assert!(!res.header("content-type").contains("wasm"), "{path}");
        if let Some(next) = local_location(&res.headers) {
            queue.push(next);
        }
    }
    assert!(seen.len() > 10, "{seen:?}");
}

#[tokio::test]
async fn vault_listener_does_not_serve_kit_pages() {
    let app = TestApp::new().await;
    for path in [
        "/login",
        "/setup",
        "/settings",
        "/users",
        "/security",
        "/static/favicon.svg",
        "/static/site.webmanifest",
        "/auth/handoff",
        "/docs",
        "/forgot",
    ] {
        let res = app.call(Which::Vault, Req::get(path).build()).await;
        assert_eq!(res.status, StatusCode::NOT_FOUND, "{path}");
        assert_eq!(res.json()["error"], "not_found", "{path}");
    }
}
