//! The two listeners, their routes and the harness that drives them.

mod support;

use axum::Router;
use axum::extract::State;
use axum::http::StatusCode;
use axum::routing::{get, post};
use ferret_server::server::{admin_router, vault_router};
use support::{ADMIN_URL, Req, START, TestApp, VAULT_URL, Which};

#[tokio::test]
async fn test_app_serves_requests_on_both_listeners_with_a_manual_clock() {
    let app = TestApp::new().await;
    for which in [Which::Vault, Which::Admin] {
        let res = app.call(which, Req::get("/healthz").build()).await;
        assert_eq!(res.status, StatusCode::OK, "{which:?}");
        assert_eq!(res.text(), "ok");
    }
    // The clock is the harness's, and it moves only by hand.
    assert_eq!(app.state.clock.now_unix(), START);
    app.clock.advance(3600);
    assert_eq!(app.state.clock.now_unix(), START + 3600);
    app.clock.set(START + 10);
    assert_eq!(app.state.clock.now_unix(), START + 10);
    // The two public addresses are the configured ones.
    assert_eq!(app.state.origins.vault(), VAULT_URL);
    assert_eq!(app.state.origins.admin(), ADMIN_URL);
}

#[tokio::test]
async fn two_listeners_share_one_state() {
    let app = TestApp::new().await;
    // One state is cloned into both routers: a probe route on each reaches the
    // same database, the same clock and the same pool.
    async fn write(State(state): State<ferret_server::FerretState>) -> String {
        let now = state.clock.now_unix();
        state
            .vault_db
            .with_conn(move |c| {
                c.execute(
                    "INSERT OR REPLACE INTO ferret_meta (key, value) VALUES ('probe', ?1)",
                    [now.to_string().into_bytes()],
                )?;
                Ok(())
            })
            .await
            .expect("write");
        now.to_string()
    }
    async fn read(State(state): State<ferret_server::FerretState>) -> String {
        let value: Vec<u8> = state
            .vault_db
            .with_conn(|c| {
                Ok(c.query_row(
                    "SELECT value FROM ferret_meta WHERE key = 'probe'",
                    [],
                    |r| r.get(0),
                )?)
            })
            .await
            .expect("read");
        format!(
            "{}@{}",
            String::from_utf8_lossy(&value),
            state.clock.now_unix()
        )
    }
    let probe = |router: Router| {
        router.merge(
            Router::new()
                .route("/probe/write", post(write))
                .route("/probe/read", get(read))
                .with_state(app.state.clone()),
        )
    };
    let vault = probe(vault_router(app.state.clone()));
    let admin = probe(admin_router(app.state.clone()));

    use tower::ServiceExt as _;
    let send = |router: Router, req: Req| async move {
        let response = router.oneshot(req.build()).await.expect("response");
        let bytes = axum::body::to_bytes(response.into_body(), 1 << 20)
            .await
            .expect("body");
        String::from_utf8(bytes.to_vec()).expect("text")
    };
    assert_eq!(
        send(vault.clone(), Req::post("/probe/write")).await,
        START.to_string()
    );
    app.clock.advance(5);
    let expected = format!("{START}@{}", START + 5);
    assert_eq!(send(admin.clone(), Req::get("/probe/read")).await, expected);
    assert_eq!(send(vault, Req::get("/probe/read")).await, expected);
}

#[tokio::test]
async fn healthz_answers_on_both_listeners() {
    let app = TestApp::new().await;
    for which in [Which::Vault, Which::Admin] {
        let res = app.call(which, Req::get("/healthz").build()).await;
        assert_eq!(res.status, StatusCode::OK);
        assert_eq!(res.text(), "ok");
        // No session, no cookie, nothing to remember.
        assert!(res.set_cookies().is_empty());
    }
    // It needs no session on the admin listener either, whatever the guard says.
    assert!(app.jar(Which::Admin).names().is_empty());
}

#[tokio::test]
async fn vault_router_does_not_serve_kit_pages() {
    let app = TestApp::new().await;
    for path in [
        "/settings",
        "/settings/general",
        "/settings/users",
        "/login",
        "/setup",
        "/login/2fa",
        "/static/style.css",
        "/api-docs",
    ] {
        let res = app.call(Which::Vault, Req::get(path).build()).await;
        assert_eq!(res.status, StatusCode::NOT_FOUND, "{path}");
        assert_eq!(
            res.json(),
            serde_json::json!({ "error": "not_found" }),
            "{path}"
        );
    }
    // Not with another method either.
    let res = app
        .call(
            Which::Vault,
            Req::post("/logout").page_fetch(Which::Vault).build(),
        )
        .await;
    assert_eq!(res.status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn admin_router_does_not_serve_sync_or_opaque_routes() {
    let app = TestApp::new().await;
    for (method, path) in [
        ("GET", "/api/sync/changes"),
        ("PUT", "/api/sync/items/00000000000000000000000000000001"),
        ("GET", "/api/vault/unlock-methods"),
        ("POST", "/api/auth/opaque/register/start"),
        ("POST", "/api/auth/opaque/register/finish"),
        ("POST", "/api/auth/opaque/login/start"),
        ("POST", "/api/auth/opaque/login/finish"),
        ("POST", "/api/auth/handoff"),
        ("GET", "/js/vault.worker.mjs"),
        ("GET", "/pkg-web/ferret_core_wasm.js"),
        ("GET", "/app/boot.mjs"),
    ] {
        let request = Req::new(method.parse().expect("method"), path)
            .page_fetch(Which::Admin)
            .build();
        let res = app.call(Which::Admin, request).await;
        assert_eq!(res.status, StatusCode::NOT_FOUND, "{method} {path}");
        assert!(!res.text().contains("type=\"password\""), "{path}");
    }
}

#[tokio::test]
async fn admin_guard_is_wired_around_only_the_kit_router() {
    let app = TestApp::new().await;

    // The kit's protected pages need a session: with none, the guard answers
    // before the kit's own check does (which would redirect to a sign-in page).
    for path in ["/settings/general", "/settings/users", "/settings/security"] {
        let res = app.call(Which::Admin, Req::get(path).build()).await;
        assert_eq!(res.status, StatusCode::UNAUTHORIZED, "{path}");
        assert_eq!(
            res.json(),
            serde_json::json!({ "error": "unauthorized" }),
            "{path}"
        );
    }

    // A cookie of the kit alone does not change that.
    let mut jar = support::Jar::default();
    jar.set("__Host-ferret_session", "v2.1.1.0.0");
    app.set_jar(Which::Admin, jar);
    let res = app
        .call(Which::Admin, Req::get("/settings/general").build())
        .await;
    assert_eq!(res.status, StatusCode::UNAUTHORIZED);
    app.clear_jar(Which::Admin);

    // The open routes work without a session: the health probe, the kit's
    // static files and the kit's sign-in page, which leads on to the vault
    // origin's sign-in through the redirect.
    let res = app.call(Which::Admin, Req::get("/healthz").build()).await;
    assert_eq!(res.status, StatusCode::OK);
    let res = app
        .call(Which::Admin, Req::get("/static/style.css").build())
        .await;
    assert_eq!(res.status, StatusCode::OK);
    let res = app
        .call(Which::Admin, Req::get("/static/favicon.svg").build())
        .await;
    assert_eq!(res.status, StatusCode::OK, "Ferret's own static files");
    let res = app.call(Which::Admin, Req::get("/login").build()).await;
    assert!(res.status.is_redirection(), "{}", res.status);
    assert!(
        res.header("location").starts_with("/vault/login"),
        "{}",
        res.header("location")
    );
    // A path that nothing serves is a 404, not a 401: the guard is on the kit's
    // routes, not on the whole listener.
    let res = app
        .call(Which::Admin, Req::get("/no/such/page").build())
        .await;
    assert_eq!(res.status, StatusCode::NOT_FOUND);
}

#[cfg(unix)]
#[test]
fn core_dumps_are_disabled() {
    use rustix::process::{Resource, getrlimit};
    ferret_server::server::disable_core_dumps().expect("setrlimit");
    let limit = getrlimit(Resource::Core);
    assert_eq!(limit.current, Some(0));
    assert_eq!(limit.maximum, Some(0));
}

#[tokio::test]
async fn the_pool_has_foreign_keys_on() {
    // The cascades of the schema (a deleted user takes the vault with it) rely
    // on it, and the server's pool is the kit's.
    let app = TestApp::new().await;
    let on: i64 = app
        .state
        .vault_db
        .with_conn(|c| Ok(c.query_row("PRAGMA foreign_keys", [], |r| r.get(0))?))
        .await
        .expect("pragma");
    assert_eq!(on, 1);
}
