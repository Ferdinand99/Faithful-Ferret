//! The admin listener: what the guard lets through, what it turns off, how long
//! an admin session lives, and what the admin origin serves (no password field,
//! no WASM, no OPAQUE endpoint). Spec: Fase 1 § 2.4.

mod support;

use std::collections::BTreeSet;

use axum::http::StatusCode;
use serde_json::json;
use support::handoff::{admin_user, set_cookie};
use support::session::seed;
use support::{Jar, Req, Res, TestApp, VAULT_URL, Which};

const SID_COOKIE: &str = "__Host-ferret_sid";
const SESSION_COOKIE: &str = "__Host-ferret_session";

async fn get(app: &TestApp, path: &str) -> Res {
    app.call(Which::Admin, Req::get(path).build()).await
}

async fn post(app: &TestApp, path: &str) -> Res {
    app.call(
        Which::Admin,
        Req::post(path).page_fetch(Which::Admin).build(),
    )
    .await
}

async fn session_status(app: &TestApp) -> StatusCode {
    get(app, "/api/auth/session").await.status
}

// ------------------------------------------------------------------- guard

#[tokio::test]
async fn kit_cookie_alone_cannot_open_an_admin_page() {
    let app = TestApp::new_at_real_time().await;
    let (_user, vault) = admin_user(&app, 1).await;
    let admin = app.jar(Which::Admin);
    let pages = ["/settings/general", "/settings/users", "/settings/security"];

    // With both cookies the pages open (a positive control).
    for path in pages {
        let res = get(&app, path).await;
        assert_eq!(res.status, StatusCode::OK, "{path}: {}", res.text());
    }

    // The kit's own cookie, signed by the kit's key, is not enough: not alone,
    // not with the session id of a vault session, not with the id of a session
    // that was ended.
    let kit = admin
        .get(SESSION_COOKIE)
        .expect("the kit's cookie")
        .to_string();
    let mut alone = Jar::default();
    alone.set(SESSION_COOKIE, &kit);
    let mut with_vault_sid = alone.clone();
    with_vault_sid.set(
        SID_COOKIE,
        vault.jar.get(SID_COOKIE).expect("the vault sid"),
    );
    let mut without_sid = admin.clone();
    without_sid.remove(SID_COOKIE);
    for (jar, why) in [
        (alone, "kit cookie alone"),
        (with_vault_sid, "kit cookie and a vault session id"),
        (without_sid, "kit cookie after the session id was dropped"),
    ] {
        app.set_jar(Which::Admin, jar);
        for path in pages {
            let res = get(&app, path).await;
            assert!(res.status.is_redirection(), "{why} {path}: {}", res.status);
            assert!(res.header("location").starts_with("/login"), "{why} {path}");
            assert!(!res.text().contains("<form"), "{why} {path}");
        }
        // And what is not a read is refused with the one 401.
        let res = post(&app, "/settings/security/sessions").await;
        assert_eq!(res.status, StatusCode::UNAUTHORIZED, "{why}");
        assert_eq!(res.json(), json!({ "error": "unauthorized" }), "{why}");
        assert_eq!(
            session_status(&app).await,
            StatusCode::UNAUTHORIZED,
            "{why}"
        );
    }

    // The session that was ended: its two cookies, put back, open nothing.
    app.set_jar(Which::Admin, admin.clone());
    assert_eq!(
        post(&app, "/api/auth/logout").await.status,
        StatusCode::NO_CONTENT
    );
    app.set_jar(Which::Admin, admin);
    assert!(get(&app, "/settings/general").await.status.is_redirection());
}

#[tokio::test]
async fn admin_guard_wraps_only_the_kit_router() {
    let app = TestApp::new().await;
    seed(&app, 1).await;

    // The kit's pages: a read goes to the sign-in, anything else is the one 401.
    for path in ["/settings/general", "/settings/users", "/settings/security"] {
        let res = get(&app, path).await;
        assert_eq!(res.status, StatusCode::SEE_OTHER, "{path}");
        assert!(res.header("location").starts_with("/login?next="), "{path}");
    }
    let res = post(&app, "/settings/users/1/disable").await;
    assert_eq!(res.status, StatusCode::UNAUTHORIZED);
    assert_eq!(res.json(), json!({ "error": "unauthorized" }));

    // These work with no session at all: the health probe, the kit's static
    // files, the redirect stubs, the hand-over page, the redeem and the
    // sign-out and session routes.
    assert_eq!(get(&app, "/healthz").await.status, StatusCode::OK);
    assert_eq!(get(&app, "/static/style.css").await.status, StatusCode::OK);
    assert_eq!(
        get(&app, "/static/favicon.svg").await.status,
        StatusCode::OK
    );
    assert_eq!(get(&app, "/auth/handoff").await.status, StatusCode::OK);
    assert_eq!(get(&app, "/auth/handoff.mjs").await.status, StatusCode::OK);
    assert_eq!(
        get(&app, "/auth/handoff/begin").await.status,
        StatusCode::FOUND
    );
    for path in [
        "/vault/login",
        "/vault/password",
        "/vault/reauth",
        "/vault/setup",
    ] {
        let res = get(&app, path).await;
        assert!(res.status.is_redirection(), "{path}: {}", res.status);
    }
    let res = app
        .call(
            Which::Admin,
            Req::post("/api/auth/handoff/redeem")
                .page_fetch(Which::Admin)
                .json(&json!({ "code": "A".repeat(43) }))
                .build(),
        )
        .await;
    assert_eq!(res.status, StatusCode::BAD_REQUEST);
    assert_eq!(res.json(), json!({ "error": "handoff_invalid" }));
    assert_eq!(
        post(&app, "/api/auth/logout").await.status,
        StatusCode::NO_CONTENT
    );
    assert_eq!(session_status(&app).await, StatusCode::UNAUTHORIZED);
    let res = get(&app, "/login").await;
    assert!(res.header("location").starts_with("/vault/login"));

    // The guard is on the kit's routes, not on the whole listener.
    assert_eq!(
        get(&app, "/no/such/page").await.status,
        StatusCode::NOT_FOUND
    );
}

#[tokio::test]
async fn a_new_install_sends_a_visitor_to_the_setup() {
    let app = TestApp::new().await;
    let res = get(&app, "/settings/general").await;
    assert_eq!(res.status, StatusCode::SEE_OTHER);
    assert_eq!(res.header("location"), "/setup");
}

#[tokio::test]
async fn the_redirect_stubs_start_the_handoff_and_keep_nothing_unclean() {
    let app = TestApp::new().await;
    for (path, expected) in [
        (
            "/vault/login?next=%2Fsettings%2Fusers",
            "/auth/handoff/begin?next=%2Fsettings%2Fusers",
        ),
        (
            "/vault/password?next=%2Fsettings",
            "/auth/handoff/begin?next=%2Fsettings",
        ),
        (
            "/vault/reauth?next=%2Fsettings%2Fsecurity",
            "/auth/handoff/begin?next=%2Fsettings%2Fsecurity&purpose=reauth",
        ),
        ("/vault/login", "/auth/handoff/begin?next=%2F"),
        (
            "/vault/login?next=%2F%2Fevil.test",
            "/auth/handoff/begin?next=%2F",
        ),
        (
            "/vault/login?next=https%3A%2F%2Fevil.test",
            "/auth/handoff/begin?next=%2F",
        ),
        (
            "/vault/reauth?next=%2Fvault%2Flogin",
            "/auth/handoff/begin?next=%2F&purpose=reauth",
        ),
    ] {
        let res = get(&app, path).await;
        assert!(res.status.is_redirection(), "{path}");
        assert_eq!(res.header("location"), expected, "{path}");
    }
    // The kit's setup link, with a setup token, goes to the vault origin's
    // setup page with the query; nothing is signed in by it.
    let res = get(&app, "/vault/setup?token=abc").await;
    assert_eq!(
        res.header("location"),
        format!("{VAULT_URL}/vault/setup?token=abc")
    );
    let res = get(&app, "/vault/setup").await;
    assert_eq!(res.header("location"), format!("{VAULT_URL}/vault/setup"));
    assert!(res.set_cookies().is_empty());
    // The kit's own sign-in page leads to the stub.
    let res = get(&app, "/login?next=%2Fsettings%2Fusers").await;
    assert_eq!(
        res.header("location"),
        "/vault/login?next=%2Fsettings%2Fusers"
    );
}

// ---------------------------------------------------------------- lifetimes

#[tokio::test]
async fn admin_session_lifetime_is_1h_idle_and_12h_absolute() {
    // Idle: an hour is fine, a second more is not.
    let app = TestApp::new().await;
    admin_user(&app, 1).await;
    app.clock.advance(3600);
    assert_eq!(
        session_status(&app).await,
        StatusCode::OK,
        "idle for 1 hour"
    );
    let app = TestApp::new().await;
    admin_user(&app, 1).await;
    app.clock.advance(3601);
    assert_eq!(
        session_status(&app).await,
        StatusCode::UNAUTHORIZED,
        "idle for 1 hour and 1 second"
    );

    // Absolute: a session that is used every 50 minutes still ends 12 hours
    // after it began, to the second.
    for (extra, want) in [(0u64, StatusCode::OK), (1, StatusCode::UNAUTHORIZED)] {
        let app = TestApp::new().await;
        admin_user(&app, 1).await;
        for _ in 0..14 {
            app.clock.advance(3000);
            assert_eq!(session_status(&app).await, StatusCode::OK);
        }
        // 14 * 3000 = 42000 seconds in; 1200 more is exactly 12 hours.
        app.clock.advance(1200 + extra);
        assert_eq!(session_status(&app).await, want, "12 hours + {extra}");
    }
}

// ------------------------------------------------------ what the kit turns on

#[tokio::test]
async fn kit_passkey_sign_in_returns_404_on_the_admin_origin() {
    let app = TestApp::new().await;
    seed(&app, 1).await;
    for path in [
        "/login/passkey/options",
        "/login/passkey",
        "/login/passkey/anything",
    ] {
        let res = post(&app, path).await;
        assert_eq!(res.status, StatusCode::NOT_FOUND, "{path}");
        assert!(res.set_cookies().is_empty(), "{path}");
    }
    for path in ["/login/passkey/options", "/login/passkey", "/login/2fa"] {
        assert_eq!(
            get(&app, path).await.status,
            StatusCode::NOT_FOUND,
            "GET {path}"
        );
    }
    assert_eq!(post(&app, "/login/2fa").await.status, StatusCode::NOT_FOUND);
    // No cookie of the kit can come out of any of them.
    let res = app
        .call(
            Which::Admin,
            Req::post("/login/passkey")
                .page_fetch(Which::Admin)
                .json(&json!({ "id": "x", "rawId": "x", "type": "public-key", "response": {} }))
                .build(),
        )
        .await;
    assert_eq!(res.status, StatusCode::NOT_FOUND);
    assert!(set_cookie(&res, SESSION_COOKIE).is_none());
}

#[tokio::test]
async fn kit_two_factor_settings_pages_return_404_on_the_admin_origin() {
    let app = TestApp::new_at_real_time().await;
    // Not signed in, and signed in: the same answer.
    seed(&app, 9).await;
    let paths = [
        "/settings/security/2fa/setup",
        "/settings/security/2fa/cancel",
        "/settings/security/2fa/enable",
        "/settings/security/2fa/disable",
        "/settings/security/2fa/recovery",
        "/settings/security/2fa/other",
    ];
    for path in paths {
        assert_eq!(
            post(&app, path).await.status,
            StatusCode::NOT_FOUND,
            "{path}"
        );
    }
    admin_user(&app, 1).await;
    for path in paths {
        let res = post(&app, path).await;
        assert_eq!(res.status, StatusCode::NOT_FOUND, "{path}");
        assert_eq!(
            get(&app, path).await.status,
            StatusCode::NOT_FOUND,
            "GET {path}"
        );
    }
    // Nothing was switched on for the user.
    let enabled: i64 = app
        .state
        .vault_db
        .with_conn(|c| {
            Ok(c.query_row(
                "SELECT COUNT(*) FROM users WHERE totp_enabled = 1",
                [],
                |r| r.get(0),
            )?)
        })
        .await
        .expect("count");
    assert_eq!(enabled, 0);
    // The rest of the security page is as it was, and a user's two-factor can
    // still be reset by an administrator.
    assert_eq!(get(&app, "/settings/security").await.status, StatusCode::OK);
    let res = post(&app, "/settings/users/1/2fa/reset").await;
    assert_ne!(res.status, StatusCode::NOT_FOUND, "{}", res.text());
}

#[tokio::test]
async fn kit_sign_out_ends_the_session_row_and_clears_the_cookies() {
    let app = TestApp::new_at_real_time().await;
    let (_user, _vault) = admin_user(&app, 1).await;
    let admin = app.jar(Which::Admin);
    assert_eq!(get(&app, "/settings/general").await.status, StatusCode::OK);

    let res = post(&app, "/logout").await;
    assert!(res.status.is_redirection(), "{}", res.status);
    for name in [SID_COOKIE, SESSION_COOKIE] {
        let cookie = set_cookie(&res, name).unwrap_or_else(|| panic!("{name} is cleared"));
        assert!(
            cookie.starts_with(&format!("{name}=;")) || cookie.contains("Max-Age=0"),
            "{cookie}"
        );
        assert!(cookie.contains("Secure"), "{cookie}");
    }
    assert!(app.jar(Which::Admin).get(SID_COOKIE).is_none());
    // The row is over on the server: the old cookies open nothing.
    app.set_jar(Which::Admin, admin);
    assert_eq!(session_status(&app).await, StatusCode::UNAUTHORIZED);
    let rows: Vec<Option<i64>> = app
        .state
        .vault_db
        .with_conn(|c| {
            Ok(
                c.prepare("SELECT revoked_at FROM ferret_sessions WHERE origin = 'admin'")?
                    .query_map([], |r| r.get(0))?
                    .collect::<Result<_, _>>()?,
            )
        })
        .await
        .expect("rows");
    assert_eq!(rows.len(), 1);
    assert!(rows[0].is_some());
    // The vault session is not touched by it.
    assert_eq!(
        app.call(Which::Vault, Req::get("/api/auth/session").build())
            .await
            .status,
        StatusCode::OK
    );
}

// ---------------------------------------------------------------- the crawl

/// The `<input>` tags of a page that are password fields, as their `name`.
fn password_fields(html: &str) -> Vec<String> {
    let lower = html.to_ascii_lowercase();
    let mut found = Vec::new();
    let mut rest = lower.as_str();
    while let Some(start) = rest.find("<input") {
        let tag_end = rest[start..].find('>').map_or(rest.len(), |e| start + e);
        let tag = &rest[start..tag_end];
        let is_password = ["type=\"password\"", "type='password'", "type=password"]
            .iter()
            .any(|p| tag.contains(p));
        if is_password {
            let name = tag
                .split("name=\"")
                .nth(1)
                .and_then(|n| n.split('"').next())
                .unwrap_or("")
                .to_string();
            found.push(name);
        }
        rest = &rest[tag_end..];
    }
    found
}

/// The local paths a page links to or loads: `href` and `src` values that start
/// with a single `/`, without the fragment.
fn local_links(html: &str) -> Vec<String> {
    let mut out = Vec::new();
    for attribute in ["href=\"", "src=\"", "action=\"", "hx-get=\"", "hx-post=\""] {
        let mut rest = html;
        while let Some(at) = rest.find(attribute) {
            rest = &rest[at + attribute.len()..];
            let Some(end) = rest.find('"') else { break };
            let value = &rest[..end];
            if value.starts_with('/') && !value.starts_with("//") {
                out.push(value.split('#').next().unwrap_or(value).to_string());
            }
        }
    }
    out
}

/// Tokens a script of the admin origin must not hold: anything of the vault's
/// WASM, its workers or its OPAQUE endpoints.
const SCRIPT_TOKENS: [&str; 6] = [
    "webassembly",
    ".wasm",
    "pkg-web",
    "vault.worker",
    "/api/auth/opaque",
    "ferret_core_wasm",
];

#[tokio::test]
async fn admin_listener_has_no_password_field_no_wasm_and_no_opaque_endpoints() {
    let app = TestApp::new_at_real_time().await;
    admin_user(&app, 1).await;

    // A signed-in crawl: every page the pages link to on this listener, and
    // every script they load.
    let mut queue: Vec<String> = [
        "/",
        "/settings",
        "/settings/general",
        "/settings/users",
        "/settings/security",
        "/auth/handoff",
        "/vault/login",
        "/vault/reauth",
        "/vault/setup",
        "/vault/password",
        "/login",
        "/setup",
        "/healthz",
        "/api/auth/session",
        "/static/favicon.svg",
    ]
    .iter()
    .map(ToString::to_string)
    .collect();
    let mut seen = BTreeSet::new();
    let mut scripts = BTreeSet::new();
    let mut ok_pages = BTreeSet::new();
    while let Some(path) = queue.pop() {
        if !seen.insert(path.clone()) {
            continue;
        }
        assert!(seen.len() <= 150, "the crawl does not end: {seen:?}");
        let res = get(&app, &path).await;
        let content_type = res.header("content-type").to_string();
        assert!(!content_type.contains("wasm"), "{path}: {content_type}");
        if let Some(location) = res.headers.get("location").and_then(|v| v.to_str().ok())
            && location.starts_with('/')
        {
            queue.push(location.to_string());
        }
        if res.status != StatusCode::OK {
            continue;
        }
        ok_pages.insert(path.clone());
        let text = res.text();
        let lower = text.to_ascii_lowercase();
        if content_type.starts_with("text/html") {
            // The one password field the admin origin may have is the kit's
            // SMTP password on its general settings page.
            for name in password_fields(&text) {
                assert!(
                    path == "/settings/general" && name == "smtp_password",
                    "a password field {name:?} on {path}"
                );
            }
            for token in ["/pkg-web", "vault.worker", ".wasm"] {
                assert!(!lower.contains(token), "{path} holds {token}");
            }
            for link in local_links(&text) {
                let file = link.split('?').next().unwrap_or(&link);
                if file.ends_with(".js") || file.ends_with(".mjs") {
                    scripts.insert(link.clone());
                }
                if !seen.contains(&link) {
                    queue.push(link);
                }
            }
        } else if content_type.contains("javascript") {
            scripts.insert(path.clone());
        }
    }
    assert!(seen.len() > 10, "{seen:?}");
    for page in ["/settings/general", "/settings/users", "/settings/security"] {
        assert!(
            ok_pages.contains(page),
            "{page} was not crawled: {ok_pages:?}"
        );
    }
    assert!(ok_pages.contains("/auth/handoff.mjs"), "{ok_pages:?}");

    // The scripts: ours, the kit's. None of them touches WASM, a worker of the
    // vault or the OPAQUE routes, and none builds a password field.
    assert!(scripts.len() >= 2, "{scripts:?}");
    for script in &scripts {
        let res = get(&app, script).await;
        assert_eq!(res.status, StatusCode::OK, "{script}");
        let lower = res.text().to_ascii_lowercase();
        for token in SCRIPT_TOKENS {
            assert!(!lower.contains(token), "{script} holds {token}");
        }
        // A comment may mention a password field (the kit's script explains its
        // strength meter); building one is what is refused.
        let squeezed: String = lower
            .chars()
            .filter(|c| !c.is_whitespace())
            .map(|c| if c == '\'' { '"' } else { c })
            .collect();
        for built in [
            ".type=\"password\"",
            "setattribute(\"type\",\"password\")",
            "type:\"password\"",
        ] {
            assert!(
                !squeezed.contains(built),
                "{script} builds a password field: {built}"
            );
        }
    }

    // No OPAQUE, sync or vault endpoint on this listener.
    for (method, path) in [
        ("POST", "/api/auth/opaque/register/start"),
        ("POST", "/api/auth/opaque/register/finish"),
        ("POST", "/api/auth/opaque/login/start"),
        ("POST", "/api/auth/opaque/login/finish"),
        ("POST", "/api/auth/handoff"),
        ("GET", "/api/vault/unlock-methods"),
        ("GET", "/api/sync/changes"),
        ("GET", "/pkg-web/ferret_core_wasm_bg.wasm"),
        ("GET", "/js/vault.worker.mjs"),
        ("GET", "/app/boot.mjs"),
        ("GET", "/vault"),
        ("GET", "/vault/items"),
    ] {
        let res = app
            .call(
                Which::Admin,
                Req::new(method.parse().expect("a method"), path)
                    .page_fetch(Which::Admin)
                    .build(),
            )
            .await;
        assert_eq!(res.status, StatusCode::NOT_FOUND, "{method} {path}");
    }
}
