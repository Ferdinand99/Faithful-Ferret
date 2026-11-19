//! What a session may reach by its scope (`ScopedSession<C>`), and the fresh
//! re-authentication of a sensitive operation (`FreshReauth`).
//! Spec: Fase 1 § 4.6 (partial session, (a) and (b)) and § 6.3.
//!
//! The extractors are tried on a small router with nothing but the narrow
//! `SessionAuth` as state, and the M2 routes on the real vault listener.

mod support;

use axum::extract::FromRef;
use axum::http::StatusCode;
use axum::routing::get;
use axum::{Json, Router};
use ferret_server::auth::session::{Origin, REAUTH_SECS, SessionRow, lookup, reauth_fresh};
use ferret_server::http::extract::{Cap, FreshReauth, ScopedSession, SessionAuth, caps};
use ferret_server_auth::{Capability, SessionScope};
use serde_json::{Value, json};
use support::session::{Issued, get_with, issue, reset_session, seed, set_reauth_at};
use support::{Req, TestApp, Which};

/// The capabilities of the M3 routes, by the path of the test router.
const CAPS: [(&str, Capability); 7] = [
    ("/cap/challenge", Capability::Challenge),
    ("/cap/reregister", Capability::OpaqueRegisterStart),
    ("/cap/recovery-read", Capability::RecoveryWrapRead),
    ("/cap/recover", Capability::Recover),
    ("/cap/password", Capability::PasswordPut),
    ("/cap/unlock-methods", Capability::UnlockMethodsWrite),
    ("/cap/sync-write", Capability::SyncWrite),
];

/// What a reset session may do, and nothing more (`Logout` has no route of
/// its own here: sign-out ends any session).
const RESET_ALLOWS: [Capability; 5] = [
    Capability::Challenge,
    Capability::OpaqueRegisterStart,
    Capability::RecoveryWrapRead,
    Capability::Recover,
    Capability::Logout,
];

async fn scoped<C: Cap>(session: ScopedSession<C>) -> Json<Value> {
    Json(json!({
        "scope": session.scope.as_str(),
        "user_id": session.session.user_id,
    }))
}

async fn fresh(fresh: FreshReauth) -> Json<Value> {
    Json(json!({ "reauth_at": fresh.reauth_at }))
}

fn router(app: &TestApp) -> Router {
    Router::new()
        .route("/cap/challenge", get(scoped::<caps::Challenge>))
        .route("/cap/reregister", get(scoped::<caps::OpaqueRegisterStart>))
        .route("/cap/recovery-read", get(scoped::<caps::RecoveryWrapRead>))
        .route("/cap/recover", get(scoped::<caps::Recover>))
        .route("/cap/password", get(scoped::<caps::PasswordPut>))
        .route(
            "/cap/unlock-methods",
            get(scoped::<caps::UnlockMethodsWrite>),
        )
        .route("/cap/sync-write", get(scoped::<caps::SyncWrite>))
        .route("/fresh", get(fresh))
        .with_state(SessionAuth::from_ref(&app.state))
}

fn now(app: &TestApp) -> i64 {
    use ferret_server_auth::Clock as _;
    i64::try_from(app.clock.now_unix()).expect("a time")
}

async fn full(app: &TestApp, n: u8) -> Issued {
    let user = seed(app, n).await.user_id;
    issue(app, user, Origin::Vault, SessionScope::Full, 1).await
}

async fn row(app: &TestApp, issued: &Issued) -> SessionRow {
    let sid = issued.sid;
    app.state
        .vault_db
        .with_conn(move |conn| Ok(lookup(conn, &sid)?))
        .await
        .expect("a lookup")
        .expect("the row")
}

#[tokio::test]
async fn full_session_gets_every_m3_capability() {
    let app = TestApp::new().await;
    let session = full(&app, 1).await;
    let router = router(&app);
    for (path, cap) in CAPS {
        let res = get_with(&router, &session.jar, path).await;
        assert_eq!(res.status, StatusCode::OK, "{cap:?}: {}", res.text());
        assert_eq!(res.json()["scope"], "full");
    }
    for cap in Capability::ALL {
        assert_eq!(
            SessionScope::Full.allows(*cap),
            *cap != Capability::SecondFactor,
            "{cap:?}"
        );
    }
}

#[tokio::test]
async fn account_reset_gets_only_challenge_reregister_recovery_read_recover_and_logout() {
    let app = TestApp::new().await;
    let (_, reset) = reset_session(&app).await;
    let router = router(&app);
    for (path, cap) in CAPS {
        let res = get_with(&router, &reset.jar, path).await;
        if RESET_ALLOWS.contains(&cap) {
            assert_eq!(res.status, StatusCode::OK, "{cap:?}: {}", res.text());
            assert_eq!(res.json()["scope"], "account_reset");
        } else {
            assert_eq!(res.status, StatusCode::FORBIDDEN, "{cap:?}");
            assert_eq!(res.json()["error"], "forbidden");
        }
    }
    for cap in Capability::ALL {
        assert_eq!(
            SessionScope::AccountReset.allows(*cap),
            RESET_ALLOWS.contains(cap),
            "{cap:?}"
        );
    }
    // A reset session is never fresh for a sensitive operation, even with a
    // time in its row.
    set_reauth_at(&app, reset.sid, Some(now(&app))).await;
    let res = get_with(&router, &reset.jar, "/fresh").await;
    assert_eq!(res.status, StatusCode::FORBIDDEN);
    assert_eq!(res.json()["error"], "forbidden");

    // Sign-out ends it.
    let res = app
        .call(
            Which::Vault,
            Req::post("/api/auth/logout")
                .page_fetch(Which::Vault)
                .build(),
        )
        .await;
    assert_eq!(res.status, StatusCode::NO_CONTENT);
    assert!(row(&app, &reset).await.revoked_at.is_some());
    let res = get_with(&router, &reset.jar, "/cap/recover").await;
    assert_eq!(res.status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn pending_2fa_and_unverified_get_none() {
    let app = TestApp::new().await;
    let user = seed(&app, 1).await.user_id;
    let router = router(&app);
    for (n, scope) in [(1, SessionScope::Pending2fa), (2, SessionScope::Unverified)] {
        let session = issue(&app, user, Origin::Vault, scope, n).await;
        set_reauth_at(&app, session.sid, Some(now(&app))).await;
        for (path, cap) in CAPS {
            let res = get_with(&router, &session.jar, path).await;
            assert_eq!(res.status, StatusCode::FORBIDDEN, "{scope:?} {cap:?}");
            assert_eq!(res.json()["error"], "forbidden");
        }
    }
    // Neither counts as fresh for a sensitive operation, whatever its row says.
    for (n, scope) in [(3, SessionScope::Pending2fa), (4, SessionScope::Unverified)] {
        let session = issue(&app, user, Origin::Vault, scope, n).await;
        set_reauth_at(&app, session.sid, Some(now(&app))).await;
        let res = get_with(&router, &session.jar, "/fresh").await;
        assert_eq!(res.status, StatusCode::FORBIDDEN, "{scope:?}");
        assert_eq!(res.json()["error"], "forbidden", "{scope:?}");
    }
}

#[tokio::test]
async fn m2_sync_routes_still_refuse_an_account_reset_session() {
    let app = TestApp::new().await;
    let (_, reset) = reset_session(&app).await;
    let id = "00".repeat(16);
    let item = format!("/api/sync/items/{id}");
    // The vault and sync routes only. The session answer
    // (`GET /api/auth/session`) is not one of them: `auth::login` decides what
    // a reset session reads there.
    let cases: Vec<(&str, &str)> = vec![
        ("GET", "/api/sync/changes?since=0"),
        ("GET", "/api/sync/items"),
        ("GET", "/api/sync/restore-rows"),
        ("GET", "/api/sync/checkpoint"),
        ("GET", "/api/sync/events"),
        ("GET", "/api/vault/unlock-methods"),
        ("PUT", &item),
        ("POST", "/api/sync/batch"),
        ("PUT", "/api/sync/checkpoint"),
    ];
    for (method, uri) in cases {
        let mut req = Req::new(method.parse().expect("a method"), uri)
            .page_fetch(Which::Vault)
            .header("cookie", &reset.jar.header().expect("cookies"));
        if method != "GET" {
            req = req.json(&json!({}));
        }
        let req = req.build();
        let res = app.call_raw(Which::Vault, req).await;
        assert_eq!(res.status, StatusCode::UNAUTHORIZED, "{method} {uri}");
        assert_eq!(res.json()["error"], "unauthorized", "{method} {uri}");
    }
    // A full session of the same user reads the same feed.
    let full = issue(
        &app,
        row(&app, &reset).await.user_id,
        Origin::Vault,
        SessionScope::Full,
        2,
    )
    .await;
    let req = Req::get("/api/sync/changes?since=0")
        .page_fetch(Which::Vault)
        .header("cookie", &full.jar.header().expect("cookies"))
        .build();
    let res = app.call_raw(Which::Vault, req).await;
    assert_eq!(res.status, StatusCode::OK, "{}", res.text());
}

#[tokio::test]
async fn fresh_reauth_holds_for_300_seconds_and_not_301() {
    let app = TestApp::new().await;
    let session = full(&app, 1).await;
    let router = router(&app);

    // Never re-authenticated: not fresh.
    let res = get_with(&router, &session.jar, "/fresh").await;
    assert_eq!(res.status, StatusCode::FORBIDDEN);
    assert_eq!(res.json()["error"], "reauth_required");

    let at = now(&app);
    set_reauth_at(&app, session.sid, Some(at)).await;
    for step in [0, 1, 299, 300] {
        app.clock.set(u64::try_from(at + step).expect("a time"));
        let res = get_with(&router, &session.jar, "/fresh").await;
        assert_eq!(res.status, StatusCode::OK, "{step} s: {}", res.text());
        assert_eq!(res.json()["reauth_at"], at);
        // Using it does not use it up.
        let res = get_with(&router, &session.jar, "/fresh").await;
        assert_eq!(res.status, StatusCode::OK, "{step} s, again");
    }
    app.clock.set(u64::try_from(at + 301).expect("a time"));
    let res = get_with(&router, &session.jar, "/fresh").await;
    assert_eq!(res.status, StatusCode::FORBIDDEN);
    assert_eq!(res.json()["error"], "reauth_required");

    // The rule itself, at both edges.
    assert_eq!(REAUTH_SECS, 300);
    let mut r = row(&app, &session).await;
    assert!(reauth_fresh(&r, at + 300));
    assert!(!reauth_fresh(&r, at + 301));
    r.reauth_at = None;
    assert!(!reauth_fresh(&r, at));

    // Freshness belongs to the session that proved the password: another
    // session of the same user stays stale.
    let other = issue(&app, r.user_id, Origin::Vault, SessionScope::Full, 2).await;
    set_reauth_at(&app, session.sid, Some(at + 301)).await;
    let res = get_with(&router, &session.jar, "/fresh").await;
    assert_eq!(res.status, StatusCode::OK);
    let res = get_with(&router, &other.jar, "/fresh").await;
    assert_eq!(res.status, StatusCode::FORBIDDEN);
    assert_eq!(res.json()["error"], "reauth_required");
}

#[tokio::test]
async fn a_clock_before_reauth_at_is_not_fresh() {
    let app = TestApp::new().await;
    let session = full(&app, 1).await;
    let router = router(&app);
    let at = now(&app);
    set_reauth_at(&app, session.sid, Some(at + 1)).await;
    let res = get_with(&router, &session.jar, "/fresh").await;
    assert_eq!(res.status, StatusCode::FORBIDDEN);
    assert_eq!(res.json()["error"], "reauth_required");

    let mut r = row(&app, &session).await;
    assert!(!reauth_fresh(&r, at));
    assert!(reauth_fresh(&r, at + 1));
    // Values at the ends of the range neither overflow nor count as fresh.
    r.reauth_at = Some(i64::MIN);
    assert!(!reauth_fresh(&r, i64::MAX));
    r.reauth_at = Some(i64::MAX);
    assert!(!reauth_fresh(&r, i64::MIN));
    assert!(reauth_fresh(&r, i64::MAX));
}

#[tokio::test]
async fn two_factor_on_refuses_with_second_factor_required() {
    let app = TestApp::new().await;
    let session = full(&app, 1).await;
    let router = router(&app);
    let user = row(&app, &session).await.user_id;
    set_reauth_at(&app, session.sid, Some(now(&app))).await;
    let res = get_with(&router, &session.jar, "/fresh").await;
    assert_eq!(res.status, StatusCode::OK, "{}", res.text());

    app.state
        .vault_db
        .with_conn(move |conn| {
            conn.execute(
                "UPDATE users SET totp_enabled = 1, totp_secret = 'x' WHERE id = ?1",
                [user],
            )?;
            Ok(())
        })
        .await
        .expect("turn the second factor on");
    // Fresh or not, the answer is the same until a second factor can be asked.
    let res = get_with(&router, &session.jar, "/fresh").await;
    assert_eq!(res.status, StatusCode::FORBIDDEN);
    assert_eq!(res.json()["error"], "second_factor_required");
    set_reauth_at(&app, session.sid, None).await;
    let res = get_with(&router, &session.jar, "/fresh").await;
    assert_eq!(res.status, StatusCode::FORBIDDEN);
    assert_eq!(res.json()["error"], "second_factor_required");
    // The capabilities themselves are not a sensitive operation.
    let res = get_with(&router, &session.jar, "/cap/challenge").await;
    assert_eq!(res.status, StatusCode::OK);
}
