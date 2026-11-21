//! Re-authentication: a sign-in with `purpose: "reauth"` marks the session's
//! own row (`reauth_at`) in the same transaction as the check of the session,
//! which makes that session, and no other, fresh for a sensitive operation for
//! 300 seconds; and what `GET /api/auth/session` says about it.
//!
//! The sign-ins are the real ones: the account row is registered against the
//! app's own OPAQUE keys with the small test key stretching, and the client is
//! the one of `ferret-core`.

mod support;

use axum::Router;
use axum::extract::FromRef;
use axum::response::IntoResponse as _;
use axum::routing::get;
use ferret_core::testing::opaque::{TestKsf, login_finish_with, register_finish_with};
use ferret_core::{
    MasterPassword, OPAQUE_CONTEXT, OpaqueInput, OsRng, PinState, TestRng, opaque_login_start,
    opaque_register_start,
};
use ferret_server::auth::session::{Origin, REAUTH_SECS, mark_reauth, revoke};
use ferret_server::http::extract::{FreshReauth, SessionAuth};
use ferret_server::http::proxy_guard::ProxyList;
use ferret_server::ids::{SessionSecret, SidHash};
use ferret_server::vault::store::create_account;
use ferret_server::wire::b64url;
use ferret_server_auth::testing::{SMALL, register_start_open};
use ferret_server_auth::{
    Clock as _, CredentialId, ProfileRules, RegistrationKind, SessionScope, StoredRecord,
    register_finish,
};
use serde_json::{Value, json};
use support::accounts::{account_ids, insert_user, rows};
use support::handoff::set_role;
use support::session::{get_with, issue};
use support::{Jar, PEER, Req, Res, TestApp, Which};

const PASSWORD: &str = "correct horse battery staple";
const ALICE: &str = "alice@example.com";

// ------------------------------------------------------------------ helpers

/// An app that believes the test peer as a proxy, so `https` requests count.
async fn app() -> TestApp {
    let proxies =
        ProxyList::parse(&[PEER.split(':').next().unwrap().to_string()]).expect("a proxy list");
    TestApp::builder().proxies(proxies).build().await
}

fn input(password: &str) -> OpaqueInput {
    MasterPassword::for_unlock(password.as_bytes())
        .unwrap()
        .opaque_input(None)
}

/// Registers `PASSWORD` for the account against the app's own keys.
fn record_for(app: &TestApp, account: &ferret_server::ids::AccountId) -> StoredRecord {
    let input = input(PASSWORD);
    let mut rng = TestRng::new(b"reauth test registration");
    let (request, state) = opaque_register_start(&mut rng, &input).unwrap();
    let response = register_start_open(
        &app.state.secrets.keys,
        &CredentialId::from(account),
        &request,
    )
    .unwrap();
    let done =
        register_finish_with(&mut rng, state, &input, &response, &TestKsf::new(SMALL)).unwrap();
    register_finish(
        &done.record,
        1,
        &ProfileRules::ferret_v1(),
        RegistrationKind::NewAccount,
    )
    .unwrap()
}

/// A user and a vault account named `email`, with a real record for
/// `PASSWORD`. Returns the user id.
async fn seed(app: &TestApp, n: u8, email: &str) -> i64 {
    let now = i64::try_from(app.clock.now_unix()).unwrap();
    let email = email.to_string();
    let record = record_for(app, &account_ids(0, n).account_id);
    app.state
        .vault_db
        .with_conn(move |conn| {
            let user_id = insert_user(conn, &email);
            let mut account_rows = rows(user_id, n, now);
            account_rows.record = record;
            let tx = conn.transaction()?;
            create_account(&tx, &account_rows).expect("create the account");
            tx.commit()?;
            Ok(user_id)
        })
        .await
        .expect("seed the account")
}

fn vault_post(path: &str, body: &Value) -> Req {
    Req::post(path)
        .page_fetch(Which::Vault)
        .header("x-forwarded-proto", "https")
        .json(body)
}

/// Sends a request on the vault listener with the cookies of `jar` and keeps
/// what the answer sets.
async fn send(app: &TestApp, jar: &mut Jar, mut req: Req) -> Res {
    if let Some(cookie) = jar.header() {
        req = req.header("cookie", &cookie);
    }
    let res = app.call_raw(Which::Vault, req.build()).await;
    jar.absorb(&res.headers);
    res
}

/// Both steps of a sign-in with `PASSWORD`, for `purpose` (`None` is an
/// ordinary sign-in).
async fn login(app: &TestApp, jar: &mut Jar, email: &str, purpose: Option<&str>) -> Res {
    let input = input(PASSWORD);
    let (ke1, state) = opaque_login_start(&mut OsRng, &input).unwrap();
    let mut body = json!({"email": email, "ke1": b64url::encode(&ke1)});
    if let Some(purpose) = purpose {
        body["purpose"] = json!(purpose);
    }
    let started = send(app, jar, vault_post("/api/auth/opaque/login/start", &body)).await;
    if started.status != 200 {
        return started;
    }
    let answer = started.json();
    let ke2 = b64url::decode(answer["ke2"].as_str().unwrap()).unwrap();
    let ke3 = login_finish_with(
        &mut OsRng,
        state,
        &input,
        &ke2,
        &TestKsf::new(SMALL),
        Some(OPAQUE_CONTEXT),
        PinState::FirstUse,
    )
    .unwrap()
    .finished
    .ke3;
    let mut body = json!({
        "login_id": answer["login_id"],
        "ke3": b64url::encode(&ke3),
        "device_id": "01".repeat(16),
        "device_name": "Test browser",
    });
    if let Some(purpose) = purpose {
        body["purpose"] = json!(purpose);
    }
    send(app, jar, vault_post("/api/auth/opaque/login/finish", &body)).await
}

async fn sign_in(app: &TestApp, jar: &mut Jar) {
    let res = login(app, jar, ALICE, None).await;
    assert_eq!(res.status, 200, "{}", res.text());
}

async fn reauth(app: &TestApp, jar: &mut Jar) -> Res {
    login(app, jar, ALICE, Some("reauth")).await
}

async fn session_info(app: &TestApp, jar: &mut Jar) -> Res {
    send(
        app,
        jar,
        Req::get("/api/auth/session").header("x-forwarded-proto", "https"),
    )
    .await
}

/// The session id hash of the browser `jar`.
fn sid_of(jar: &Jar) -> SidHash {
    let signed = jar.get("__Host-ferret_sid").expect("a session cookie");
    // The cookie value is the signature followed by the session id, whose 43
    // base64url characters are never escaped.
    let value = signed
        .get(signed.len().saturating_sub(43)..)
        .expect("a signed cookie");
    SessionSecret::from_cookie(value)
        .expect("a session id")
        .hash()
}

async fn reauth_at(app: &TestApp, sid: SidHash) -> Option<i64> {
    app.state
        .vault_db
        .with_conn(move |conn| {
            Ok(conn.query_row(
                "SELECT reauth_at FROM ferret_sessions WHERE sid_hash = ?1",
                [sid.0.as_slice()],
                |r| r.get(0),
            )?)
        })
        .await
        .expect("a row")
}

fn now(app: &TestApp) -> i64 {
    i64::try_from(app.clock.now_unix()).unwrap()
}

/// A router with one route behind `FreshReauth`: 200 when the session may run
/// a sensitive operation now.
fn fresh_router(app: &TestApp) -> Router {
    async fn fresh(fresh: FreshReauth) -> axum::response::Response {
        axum::Json(json!({ "reauth_at": fresh.reauth_at() })).into_response()
    }
    Router::new()
        .route("/fresh", get(fresh))
        .with_state(SessionAuth::from_ref(&app.state))
}

// -------------------------------------------------------------------- tests

#[tokio::test]
async fn reauth_finish_sets_reauth_at_in_the_same_transaction() {
    let app = app().await;
    seed(&app, 1, ALICE).await;
    let mut jar = Jar::default();
    sign_in(&app, &mut jar).await;
    let sid = sid_of(&jar);
    assert_eq!(reauth_at(&app, sid).await, None);

    app.clock.advance(90);
    let done = reauth(&app, &mut jar).await;
    assert_eq!(done.status, 200, "{}", done.text());
    assert_eq!(reauth_at(&app, sid).await, Some(now(&app)));
    assert_eq!(sid_of(&jar), sid, "the same session goes on");
    let router = fresh_router(&app);
    let res = get_with(&router, &jar, "/fresh").await;
    assert_eq!(res.status, 200, "{}", res.text());
    assert_eq!(res.json()["reauth_at"], now(&app));

    // The mark is written only for a session the same transaction finds
    // live, full and of the vault: an ended row, a reset session and an admin
    // session are left as they were.
    let user = app
        .state
        .vault_db
        .with_conn(|conn| {
            Ok(
                conn.query_row("SELECT id FROM users WHERE username = ?1", [ALICE], |r| {
                    r.get::<_, i64>(0)
                })?,
            )
        })
        .await
        .unwrap();
    let reset = issue(&app, user, Origin::Vault, SessionScope::AccountReset, 2).await;
    let admin = issue(&app, user, Origin::Admin, SessionScope::Full, 3).await;
    let ended = issue(&app, user, Origin::Vault, SessionScope::Full, 4).await;
    let t = now(&app);
    let (ended_sid, reset_sid, admin_sid) = (ended.sid, reset.sid, admin.sid);
    let marks = app
        .state
        .vault_db
        .with_conn(move |conn| {
            revoke(conn, &ended_sid, t)?;
            Ok([
                mark_reauth(conn, &ended_sid, t)?,
                mark_reauth(conn, &reset_sid, t)?,
                mark_reauth(conn, &admin_sid, t)?,
                mark_reauth(conn, &SidHash([0x77; 32]), t)?,
            ])
        })
        .await
        .unwrap();
    assert_eq!(marks, [false; 4]);
    for sid in [ended.sid, reset.sid, admin.sid] {
        assert_eq!(reauth_at(&app, sid).await, None);
    }

    // A user signed out everywhere between the two steps: the finish finds no
    // session that counts, and nothing is marked.
    let mut other = Jar::default();
    sign_in(&app, &mut other).await;
    let other_sid = sid_of(&other);
    let input = input(PASSWORD);
    let (ke1, state) = opaque_login_start(&mut OsRng, &input).unwrap();
    let started = send(
        &app,
        &mut other,
        vault_post(
            "/api/auth/opaque/login/start",
            &json!({"email": ALICE, "ke1": b64url::encode(&ke1), "purpose": "reauth"}),
        ),
    )
    .await;
    assert_eq!(started.status, 200, "{}", started.text());
    app.state
        .vault_db
        .with_conn(move |conn| {
            vole_kit::db::users::bump_session_version(conn, user)?;
            Ok(())
        })
        .await
        .unwrap();
    let answer = started.json();
    let ke2 = b64url::decode(answer["ke2"].as_str().unwrap()).unwrap();
    let ke3 = login_finish_with(
        &mut OsRng,
        state,
        &input,
        &ke2,
        &TestKsf::new(SMALL),
        Some(OPAQUE_CONTEXT),
        PinState::FirstUse,
    )
    .unwrap()
    .finished
    .ke3;
    let finished = send(
        &app,
        &mut other,
        vault_post(
            "/api/auth/opaque/login/finish",
            &json!({
                "login_id": answer["login_id"],
                "ke3": b64url::encode(&ke3),
                "device_id": "02".repeat(16),
                "purpose": "reauth",
            }),
        ),
    )
    .await;
    assert_eq!(finished.status, 401, "{}", finished.text());
    assert_eq!(reauth_at(&app, other_sid).await, None);
}

#[tokio::test]
async fn an_ordinary_login_does_not_set_reauth_at() {
    let app = app().await;
    seed(&app, 1, ALICE).await;
    let mut jar = Jar::default();
    sign_in(&app, &mut jar).await;
    assert_eq!(reauth_at(&app, sid_of(&jar)).await, None);
    let info = session_info(&app, &mut jar).await;
    assert_eq!(info.status, 200, "{}", info.text());
    assert!(info.json().get("reauth_until").is_none(), "{}", info.text());
    let res = get_with(&fresh_router(&app), &jar, "/fresh").await;
    assert_eq!(
        (res.status.as_u16(), res.json()["error"].clone()),
        (403, json!("reauth_required"))
    );

    // Signing in again on top of a fresh session gives a new session that is
    // not fresh, and the old fresh one is gone.
    assert_eq!(reauth(&app, &mut jar).await.status, 200);
    let fresh_sid = sid_of(&jar);
    assert!(reauth_at(&app, fresh_sid).await.is_some());
    sign_in(&app, &mut jar).await;
    assert_ne!(sid_of(&jar), fresh_sid);
    assert_eq!(reauth_at(&app, sid_of(&jar)).await, None);
    let res = get_with(&fresh_router(&app), &jar, "/fresh").await;
    assert_eq!(res.status, 403, "{}", res.text());
}

#[tokio::test]
async fn reauth_on_one_session_does_not_make_another_fresh() {
    let app = app().await;
    seed(&app, 1, ALICE).await;
    let mut first = Jar::default();
    let mut second = Jar::default();
    sign_in(&app, &mut first).await;
    sign_in(&app, &mut second).await;
    assert_ne!(sid_of(&first), sid_of(&second));

    assert_eq!(reauth(&app, &mut first).await.status, 200);
    assert!(reauth_at(&app, sid_of(&first)).await.is_some());
    assert_eq!(reauth_at(&app, sid_of(&second)).await, None);

    let router = fresh_router(&app);
    assert_eq!(get_with(&router, &first, "/fresh").await.status, 200);
    let refused = get_with(&router, &second, "/fresh").await;
    assert_eq!(refused.status, 403);
    assert_eq!(refused.json()["error"], "reauth_required");

    // The first browser's grant cookie in the second browser changes nothing:
    // the freshness is in the row, not in a cookie.
    let mut mixed = second.clone();
    if let Some(grant) = first.get("__Host-ferret_reauth") {
        mixed.set("__Host-ferret_reauth", grant);
    }
    assert_eq!(get_with(&router, &mixed, "/fresh").await.status, 403);
    let info = session_info(&app, &mut second).await;
    assert!(info.json().get("reauth_until").is_none(), "{}", info.text());
}

#[tokio::test]
async fn session_answer_says_only_an_administrator_is_one() {
    let app = app().await;
    let user = seed(&app, 1, ALICE).await;
    let mut jar = Jar::default();
    sign_in(&app, &mut jar).await;
    // A user with another role: the key is not there.
    let info = session_info(&app, &mut jar).await;
    assert_eq!(info.status, 200, "{}", info.text());
    assert!(info.json().get("admin").is_none(), "{}", info.text());
    // An administrator: `admin` is true.
    set_role(&app, user, "admin").await;
    let info = session_info(&app, &mut jar).await;
    assert_eq!(info.status, 200, "{}", info.text());
    assert_eq!(info.json()["admin"], json!(true), "{}", info.text());
}

#[tokio::test]
async fn session_answer_shows_scope_and_reauth_until() {
    let app = app().await;
    let user = seed(&app, 1, ALICE).await;
    let mut jar = Jar::default();
    sign_in(&app, &mut jar).await;
    let info = session_info(&app, &mut jar).await;
    assert_eq!(info.status, 200, "{}", info.text());
    let body = info.json();
    assert_eq!(body["scope"], "full");
    assert_eq!(body["origin"], "vault");
    assert_eq!(body["email"], ALICE);
    assert!(body.get("reauth_until").is_none());

    assert_eq!(reauth(&app, &mut jar).await.status, 200);
    let at = now(&app);
    let until = at + REAUTH_SECS;
    let shown = |res: &Res| res.json().get("reauth_until").cloned();
    assert_eq!(
        shown(&session_info(&app, &mut jar).await),
        Some(json!(until))
    );
    // Exactly 300 seconds later it still counts; one second more, it is gone.
    app.clock.advance(300);
    assert_eq!(
        shown(&session_info(&app, &mut jar).await),
        Some(json!(until))
    );
    app.clock.advance(1);
    assert_eq!(shown(&session_info(&app, &mut jar).await), None);
    assert_eq!(session_info(&app, &mut jar).await.json()["scope"], "full");

    // A reset session reads its scope, its account and nothing about
    // freshness, even with a mark in its row.
    let mut reset = issue(&app, user, Origin::Vault, SessionScope::AccountReset, 2)
        .await
        .jar;
    let reset_sid = sid_of(&reset);
    let t = now(&app);
    app.state
        .vault_db
        .with_conn(move |conn| {
            conn.execute(
                "UPDATE ferret_sessions SET reauth_at = ?1 WHERE sid_hash = ?2",
                rusqlite::params![t, reset_sid.0.as_slice()],
            )?;
            Ok(())
        })
        .await
        .unwrap();
    let info = session_info(&app, &mut reset).await;
    assert_eq!(info.status, 200, "{}", info.text());
    let body = info.json();
    assert_eq!(body["scope"], "account_reset");
    assert_eq!(body["origin"], "vault");
    assert_eq!(body["email"], ALICE);
    assert_eq!(
        body["account_id"],
        json!(format!("a001{}", "00".repeat(14)))
    );
    assert!(body.get("reauth_until").is_none(), "{}", info.text());

    // Any other scope is the one 401, byte for byte the answer to no session.
    let none = session_info(&app, &mut Jar::default()).await;
    for scope in [SessionScope::Pending2fa, SessionScope::Unverified] {
        let mut other = issue(&app, user, Origin::Vault, scope, 3).await.jar;
        let res = session_info(&app, &mut other).await;
        assert_eq!(res.status, 401, "{scope:?}");
        assert_eq!(res.body, none.body, "{scope:?}");
    }
}
