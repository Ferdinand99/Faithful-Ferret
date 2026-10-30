//! Sign-in, sign-out and the session info, driven through the real routers with
//! the real client of `ferret-core`.
//!
//! The key stretching of most tests is the test one with small parameters; the
//! account row is made by registering against the app's own OPAQUE keys, so the
//! exchange is the real one. `e2e_real_client_production_profile` uses profile 1
//! (64 MiB) on both sides.

mod support;

use std::io;
use std::sync::{Arc, Mutex, Once};
use std::time::Instant;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use ferret_core::testing::opaque::{TestKsf, login_finish_with, register_finish_with};
use ferret_core::{
    KsfProfile, LoginState, MasterPassword, OPAQUE_CONTEXT, OpaqueInput, OsRng, PinState, TestRng,
    opaque_login_finish, opaque_login_start, opaque_register_finish, opaque_register_start,
};
use ferret_server::auth::login::{
    PURGE_MARGIN_SECS, load_prelogin_policy, lookup_account, purge_sessions, refresh_once,
};
use ferret_server::auth::throttle::KitThrottle;
use ferret_server::http::proxy_guard::ProxyList;
use ferret_server::vault::store::create_account;
use ferret_server::wire::b64url;
use ferret_server_auth::testing::{SMALL, register_start_open};
use ferret_server_auth::{
    Clock, CredentialId, ManualClock, PreloginPolicy, ProfileRules, RecordingThrottle,
    RegistrationKind, Stage, StoredRecord, Throttle, ThrottleCall, ThrottleKey, fake_prelogin,
    normalize_login_name, register_finish,
};
use serde_json::{Value, json};
use support::accounts::{account_ids, insert_user, rows};
use support::{Jar, PEER, Req, Res, START, TestApp, Which};
use tracing_subscriber::fmt::MakeWriter;

const PASSWORD: &str = "correct horse battery staple";
const OTHER_PASSWORD: &str = "a quite different password";

// ------------------------------------------------------------------ helpers

fn proxies() -> ProxyList {
    ProxyList::parse(&[PEER.split(':').next().unwrap().to_string()]).expect("a proxy list")
}

/// An app that believes the test peer as a proxy, so `https` requests count.
async fn app() -> TestApp {
    TestApp::builder().proxies(proxies()).build().await
}

async fn app_with(throttle: Arc<dyn Throttle>) -> TestApp {
    TestApp::builder()
        .proxies(proxies())
        .throttle(throttle)
        .build()
        .await
}

fn input(password: &str) -> OpaqueInput {
    MasterPassword::for_unlock(password.as_bytes())
        .unwrap()
        .opaque_input(None)
}

/// Registers `password` for the account against the app's own keys.
fn small_record(
    app: &TestApp,
    account: &ferret_server::ids::AccountId,
    password: &str,
) -> StoredRecord {
    let input = input(password);
    let mut rng = TestRng::new(b"login test registration");
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

/// A user and a vault account with this name and a real record for `password`.
async fn seed_with(app: &TestApp, n: u8, email: &str, record: Option<StoredRecord>) -> i64 {
    let now = i64::try_from(app.clock.now_unix()).unwrap();
    let email = email.to_string();
    let account = account_ids(0, n).account_id;
    let record = record.unwrap_or_else(|| small_record(app, &account, PASSWORD));
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

async fn seed(app: &TestApp, n: u8, email: &str) -> i64 {
    seed_with(app, n, email, None).await
}

fn vault_post(path: &str, body: &Value) -> Req {
    Req::post(path)
        .page_fetch(Which::Vault)
        .header("x-forwarded-proto", "https")
        .json(body)
}

fn admin_get(path: &str) -> Req {
    Req::get(path).header("x-forwarded-proto", "https")
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

async fn send_admin(app: &TestApp, jar: &mut Jar, mut req: Req) -> Res {
    if let Some(cookie) = jar.header() {
        req = req.header("cookie", &cookie);
    }
    let res = app.call_raw(Which::Admin, req.build()).await;
    jar.absorb(&res.headers);
    res
}

/// The client's side of a login after the server's first answer.
struct Started {
    login_id: String,
    ke2: Vec<u8>,
    state: LoginState,
    input: OpaqueInput,
}

fn start_body(email: &str, ke1: &[u8], purpose: Option<&str>) -> Value {
    let mut body = json!({"email": email, "ke1": b64url::encode(ke1)});
    if let Some(purpose) = purpose {
        body["purpose"] = json!(purpose);
    }
    body
}

/// `login/start` with a real KE1 for `password`.
async fn start(
    app: &TestApp,
    jar: &mut Jar,
    email: &str,
    password: &str,
    purpose: Option<&str>,
) -> (Res, Option<Started>) {
    let input = input(password);
    let (ke1, state) = opaque_login_start(&mut OsRng, &input).unwrap();
    let res = send(
        app,
        jar,
        vault_post(
            "/api/auth/opaque/login/start",
            &start_body(email, &ke1, purpose),
        ),
    )
    .await;
    if res.status != StatusCode::OK {
        return (res, None);
    }
    let body = res.json();
    let started = Started {
        login_id: body["login_id"].as_str().unwrap().to_string(),
        ke2: b64url::decode(body["ke2"].as_str().unwrap()).unwrap(),
        state,
        input,
    };
    (res, Some(started))
}

/// The client's KE3, or its error.
fn ke3_of(started: Started) -> Result<Vec<u8>, ferret_core::Error> {
    login_finish_with(
        &mut OsRng,
        started.state,
        &started.input,
        &started.ke2,
        &TestKsf::new(SMALL),
        Some(OPAQUE_CONTEXT),
        PinState::FirstUse,
    )
    .map(|done| done.finished.ke3)
}

fn finish_body(login_id: &str, ke3: &[u8], device: u8, purpose: Option<&str>) -> Value {
    let mut body = json!({
        "login_id": login_id,
        "ke3": b64url::encode(ke3),
        "device_id": format!("{device:02x}").repeat(16),
        "device_name": "Test browser",
    });
    if let Some(purpose) = purpose {
        body["purpose"] = json!(purpose);
    }
    body
}

async fn finish_as(
    app: &TestApp,
    jar: &mut Jar,
    login_id: &str,
    ke3: &[u8],
    device: u8,
    purpose: Option<&str>,
) -> Res {
    send(
        app,
        jar,
        vault_post(
            "/api/auth/opaque/login/finish",
            &finish_body(login_id, ke3, device, purpose),
        ),
    )
    .await
}

async fn finish(app: &TestApp, jar: &mut Jar, login_id: &str, ke3: &[u8], device: u8) -> Res {
    finish_as(app, jar, login_id, ke3, device, None).await
}

/// A whole sign-in with the right password.
async fn sign_in(app: &TestApp, jar: &mut Jar, email: &str, device: u8) -> Res {
    let (res, started) = start(app, jar, email, PASSWORD, None).await;
    assert_eq!(res.status, StatusCode::OK, "{}", res.text());
    let started = started.unwrap();
    let login_id = started.login_id.clone();
    let ke3 = ke3_of(started).expect("the client opens the envelope");
    finish(app, jar, &login_id, &ke3, device).await
}

async fn session_info(app: &TestApp, jar: &mut Jar) -> Res {
    send(
        app,
        jar,
        Req::get("/api/auth/session").header("x-forwarded-proto", "https"),
    )
    .await
}

async fn count(app: &TestApp, sql: &'static str) -> i64 {
    app.state
        .vault_db
        .with_conn(move |conn| Ok(conn.query_row(sql, [], |r| r.get(0))?))
        .await
        .expect("a count")
}

async fn session_rows(app: &TestApp) -> i64 {
    count(app, "SELECT COUNT(*) FROM ferret_sessions").await
}

async fn live_session_rows(app: &TestApp) -> i64 {
    count(
        app,
        "SELECT COUNT(*) FROM ferret_sessions WHERE revoked_at IS NULL",
    )
    .await
}

fn error_code(res: &Res) -> String {
    res.json()["error"].as_str().unwrap_or("").to_string()
}

/// The headers of an answer, as name and value, sorted.
fn header_list(res: &Res) -> Vec<(String, String)> {
    let mut list: Vec<(String, String)> = res
        .headers
        .iter()
        .map(|(k, v)| {
            (
                k.as_str().to_string(),
                v.to_str().unwrap_or("?").to_string(),
            )
        })
        .collect();
    list.sort();
    list
}

// ------------------------------------------------------------ login/start

#[tokio::test]
async fn known_unknown_and_disabled_give_same_status_headers_and_body_shape() {
    let app = app().await;
    seed(&app, 1, "alice@example.com").await;
    let disabled_user = seed(&app, 2, "dora@example.com").await;
    app.state
        .vault_db
        .with_conn(move |conn| {
            conn.execute("UPDATE users SET active = 0 WHERE id = ?1", [disabled_user])?;
            Ok(())
        })
        .await
        .unwrap();

    let mut answers = Vec::new();
    for email in [
        "alice@example.com",
        "nobody@example.com",
        "dora@example.com",
        "admin-without-vault@example.com",
    ] {
        let mut jar = Jar::default();
        let (res, started) = start(&app, &mut jar, email, PASSWORD, None).await;
        assert_eq!(res.status, StatusCode::OK, "{email}");
        assert!(started.is_some());
        answers.push(res);
    }
    let first = &answers[0];
    for res in &answers {
        let body = res.json();
        let mut keys: Vec<&str> = body
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect();
        keys.sort_unstable();
        assert_eq!(keys, ["ke2", "ksf_profile", "login_id", "sk_hint"]);
        assert_eq!(body["login_id"].as_str().unwrap().len(), 32);
        assert_eq!(
            b64url::decode(body["ke2"].as_str().unwrap()).unwrap().len(),
            320
        );
        assert!([1].contains(&body["ksf_profile"].as_u64().unwrap()));
        assert!(body["sk_hint"].is_boolean());
        // Everything but the random values is identical, down to the length.
        assert_eq!(res.status, first.status);
        assert_eq!(res.body.len(), first.body.len());
        assert_eq!(header_list(res), header_list(first), "headers differ");
        assert_eq!(res.header("cache-control"), "no-store");
    }
}

#[tokio::test]
async fn unknown_email_answer_is_stable_across_calls() {
    let app = app().await;
    seed(&app, 1, "alice@example.com").await;
    let input = input(PASSWORD);
    let (ke1, _state) = opaque_login_start(&mut OsRng, &input).unwrap();
    let mut seen = Vec::new();
    for _ in 0..3 {
        let mut jar = Jar::default();
        let res = send(
            &app,
            &mut jar,
            vault_post(
                "/api/auth/opaque/login/start",
                &start_body("ghost@example.com", &ke1, None),
            ),
        )
        .await;
        assert_eq!(res.status, StatusCode::OK);
        let body = res.json();
        let ke2 = b64url::decode(body["ke2"].as_str().unwrap()).unwrap();
        seen.push((
            body["ksf_profile"].clone(),
            body["sk_hint"].clone(),
            // The first 32 bytes are the OPRF answer for the made-up record's
            // key: the same on every ask.
            ke2[..32].to_vec(),
        ));
    }
    assert!(seen.windows(2).all(|pair| pair[0] == pair[1]));
}

#[tokio::test]
async fn start_refuses_what_is_malformed_with_the_code_of_the_field() {
    let app = app().await;
    let mut jar = Jar::default();
    let ke1 = vec![7u8; 96];
    let res = send(
        &app,
        &mut jar,
        vault_post(
            "/api/auth/opaque/login/start",
            &start_body("a@example.com", &ke1[..95], None),
        ),
    )
    .await;
    assert_eq!(
        (res.status.as_u16(), error_code(&res).as_str()),
        (400, "malformed_ke1")
    );
    let res = send(
        &app,
        &mut jar,
        vault_post(
            "/api/auth/opaque/login/start",
            &start_body("bad\u{7}name@example.com", &ke1, None),
        ),
    )
    .await;
    assert_eq!(
        (res.status.as_u16(), error_code(&res).as_str()),
        (400, "malformed_login_name")
    );
    let raw = Request::builder()
        .method("POST")
        .uri("/api/auth/opaque/login/start")
        .header("origin", Which::Vault.url())
        .header("ferret-protocol", "1")
        .header("x-forwarded-proto", "https")
        .body(Body::from("{not json"))
        .unwrap();
    let res = app.call_raw(Which::Vault, raw).await;
    assert_eq!(
        (res.status.as_u16(), error_code(&res).as_str()),
        (400, "bad_request")
    );
    assert_eq!(
        count(&app, "SELECT COUNT(*) FROM ferret_login_states").await,
        0
    );
}

#[tokio::test]
async fn login_start_throttled_gives_429_retry_after_with_identical_body_for_unknown_email() {
    let throttle: Arc<dyn Throttle> = Arc::new(KitThrottle::new(
        Arc::new(ManualClock::new(START)) as Arc<dyn Clock>
    ));
    let app = app_with(throttle).await;
    seed(&app, 1, "alice@example.com").await;
    let (ke1, _s) = opaque_login_start(&mut OsRng, &input(PASSWORD)).unwrap();
    let mut blocked = Vec::new();
    for email in ["alice@example.com", "ghost@example.com"] {
        let mut jar = Jar::default();
        let mut last = None;
        for _ in 0..6 {
            last = Some(
                send(
                    &app,
                    &mut jar,
                    vault_post(
                        "/api/auth/opaque/login/start",
                        &start_body(email, &ke1, None),
                    ),
                )
                .await,
            );
        }
        blocked.push(last.unwrap());
    }
    for res in &blocked {
        assert_eq!(res.status, StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(error_code(res), "throttled");
        let wait: u32 = res.header("retry-after").parse().expect("a Retry-After");
        assert!((1..=3600).contains(&wait));
    }
    assert_eq!(blocked[0].body, blocked[1].body);
    assert_eq!(header_list(&blocked[0]), header_list(&blocked[1]));
}

// ----------------------------------------------------------- login/finish

#[tokio::test]
async fn sign_in_makes_a_session_with_both_cookies_and_the_session_info_works() {
    let app = app().await;
    let user = seed(&app, 1, "alice@example.com").await;
    let mut jar = Jar::default();
    let res = sign_in(&app, &mut jar, "alice@example.com", 1).await;
    assert_eq!(res.status, StatusCode::OK, "{}", res.text());
    let body = res.json();
    let ids = account_ids(user, 1);
    assert_eq!(
        body["account_id"],
        support::session::hex(ids.account_id.as_bytes())
    );
    assert_eq!(
        body["vault_id"],
        support::session::hex(ids.vault_id.as_bytes())
    );
    assert_eq!(body["vk_epoch"], 1);
    assert_eq!(res.header("cache-control"), "no-store");
    let names = jar.names();
    assert!(
        names.contains(&"__Host-ferret_sid".to_string()),
        "{names:?}"
    );
    assert!(
        names.contains(&"__Host-ferret_session".to_string()),
        "{names:?}"
    );
    assert_eq!(session_rows(&app).await, 1);
    // The sign-in is noted on the kit's user.
    assert_eq!(
        count(
            &app,
            "SELECT COUNT(*) FROM users WHERE last_login_at IS NOT NULL"
        )
        .await,
        1
    );

    let info = session_info(&app, &mut jar).await;
    assert_eq!(info.status, StatusCode::OK);
    let info = info.json();
    assert_eq!(info["email"], "alice@example.com");
    assert_eq!(info["scope"], "full");
    assert_eq!(info["origin"], "vault");
    assert_eq!(
        info["account_id"],
        support::session::hex(ids.account_id.as_bytes())
    );
}

#[tokio::test]
async fn wrong_ke3_is_401_denied_and_the_login_id_is_used_up() {
    let app = app().await;
    seed(&app, 1, "alice@example.com").await;
    let mut jar = Jar::default();
    let (_, started) = start(&app, &mut jar, "alice@example.com", PASSWORD, None).await;
    let started = started.unwrap();
    let login_id = started.login_id.clone();
    let good = ke3_of(started).unwrap();

    let res = finish(&app, &mut jar, &login_id, &[0x5a; 64], 1).await;
    assert_eq!(res.status, StatusCode::UNAUTHORIZED);
    assert_eq!(error_code(&res), "denied");
    // The state is gone: even the right KE3 now finds nothing.
    let again = finish(&app, &mut jar, &login_id, &good, 1).await;
    assert_eq!(again.status, StatusCode::UNAUTHORIZED);
    assert_eq!(again.body, res.body);
    assert_eq!(session_rows(&app).await, 0);
}

#[tokio::test]
async fn wrong_password_never_creates_a_session_row() {
    let app = app().await;
    seed(&app, 1, "alice@example.com").await;
    let mut jar = Jar::default();
    let (_, started) = start(&app, &mut jar, "alice@example.com", OTHER_PASSWORD, None).await;
    let started = started.unwrap();
    let login_id = started.login_id.clone();
    // The client cannot even build a KE3; a forged one is denied.
    assert!(ke3_of(started).is_err());
    let res = finish(&app, &mut jar, &login_id, &[0x11; 64], 1).await;
    assert_eq!(res.status, StatusCode::UNAUTHORIZED);
    assert_eq!(session_rows(&app).await, 0);
    assert!(
        jar.names().is_empty(),
        "no cookie is set: {:?}",
        jar.names()
    );
    assert!(res.set_cookies().is_empty());
}

#[tokio::test]
async fn login_id_is_single_use() {
    let app = app().await;
    seed(&app, 1, "alice@example.com").await;
    let mut jar = Jar::default();
    let (_, started) = start(&app, &mut jar, "alice@example.com", PASSWORD, None).await;
    let started = started.unwrap();
    let login_id = started.login_id.clone();
    let ke3 = ke3_of(started).unwrap();
    let first = finish(&app, &mut jar, &login_id, &ke3, 1).await;
    assert_eq!(first.status, StatusCode::OK);
    let mut other = Jar::default();
    let second = finish(&app, &mut other, &login_id, &ke3, 2).await;
    assert_eq!(second.status, StatusCode::UNAUTHORIZED);
    assert_eq!(error_code(&second), "denied");
    assert_eq!(session_rows(&app).await, 1);
    assert!(other.names().is_empty());
}

#[tokio::test]
async fn login_state_expires_after_60_seconds() {
    let app = app().await;
    seed(&app, 1, "alice@example.com").await;
    let mut jar = Jar::default();

    let (_, started) = start(&app, &mut jar, "alice@example.com", PASSWORD, None).await;
    let started = started.unwrap();
    let login_id = started.login_id.clone();
    let ke3 = ke3_of(started).unwrap();
    app.clock.advance(59);
    assert_eq!(
        finish(&app, &mut jar, &login_id, &ke3, 1).await.status,
        StatusCode::OK
    );

    let mut jar = Jar::default();
    let (_, started) = start(&app, &mut jar, "alice@example.com", PASSWORD, None).await;
    let started = started.unwrap();
    let login_id = started.login_id.clone();
    let ke3 = ke3_of(started).unwrap();
    app.clock.advance(60);
    let late = finish(&app, &mut jar, &login_id, &ke3, 1).await;
    assert_eq!(late.status, StatusCode::UNAUTHORIZED);
    assert_eq!(error_code(&late), "denied");
}

#[tokio::test]
async fn finish_refuses_what_is_malformed() {
    let app = app().await;
    let mut jar = Jar::default();
    let id = "ab".repeat(16);
    let res = finish(&app, &mut jar, &id, &[1u8; 63], 1).await;
    assert_eq!(
        (res.status.as_u16(), error_code(&res).as_str()),
        (400, "malformed_ke3")
    );
    let res = finish(&app, &mut jar, "NOT-HEX", &[1u8; 64], 1).await;
    assert_eq!(res.status, StatusCode::BAD_REQUEST);
    // A login id nobody was given: denied, like a used one.
    let res = finish(&app, &mut jar, &id, &[1u8; 64], 1).await;
    assert_eq!(
        (res.status.as_u16(), error_code(&res).as_str()),
        (401, "denied")
    );
}

#[tokio::test]
async fn a_user_disabled_between_the_two_steps_gets_no_session() {
    let app = app().await;
    let user = seed(&app, 1, "alice@example.com").await;
    let mut jar = Jar::default();
    let (_, started) = start(&app, &mut jar, "alice@example.com", PASSWORD, None).await;
    let started = started.unwrap();
    let login_id = started.login_id.clone();
    let ke3 = ke3_of(started).unwrap();
    app.state
        .vault_db
        .with_conn(move |conn| {
            conn.execute("UPDATE users SET active = 0 WHERE id = ?1", [user])?;
            Ok(())
        })
        .await
        .unwrap();
    let res = finish(&app, &mut jar, &login_id, &ke3, 1).await;
    assert_eq!(
        (res.status.as_u16(), error_code(&res).as_str()),
        (401, "denied")
    );
    assert_eq!(session_rows(&app).await, 0);
    assert!(res.set_cookies().is_empty());
}

// --------------------------------------------------------------- sessions

#[tokio::test]
async fn two_browsers_logged_in_at_once_have_independent_sessions() {
    let app = app().await;
    seed(&app, 1, "alice@example.com").await;
    let mut laptop = Jar::default();
    let mut phone = Jar::default();
    assert_eq!(
        sign_in(&app, &mut laptop, "alice@example.com", 1)
            .await
            .status,
        200
    );
    assert_eq!(
        sign_in(&app, &mut phone, "alice@example.com", 2)
            .await
            .status,
        200
    );
    assert_eq!(session_rows(&app).await, 2);
    assert_eq!(session_info(&app, &mut laptop).await.status, StatusCode::OK);
    assert_eq!(session_info(&app, &mut phone).await.status, StatusCode::OK);

    let out = send(
        &app,
        &mut laptop,
        Req::post("/api/auth/logout")
            .page_fetch(Which::Vault)
            .header("x-forwarded-proto", "https"),
    )
    .await;
    assert_eq!(out.status, StatusCode::NO_CONTENT);
    assert_eq!(session_info(&app, &mut phone).await.status, StatusCode::OK);
    assert_eq!(live_session_rows(&app).await, 1);
}

#[tokio::test]
async fn login_finish_revokes_the_presented_previous_session_and_only_that_one() {
    let app = app().await;
    seed(&app, 1, "alice@example.com").await;
    let mut laptop = Jar::default();
    let mut phone = Jar::default();
    assert_eq!(
        sign_in(&app, &mut laptop, "alice@example.com", 1)
            .await
            .status,
        200
    );
    assert_eq!(
        sign_in(&app, &mut phone, "alice@example.com", 2)
            .await
            .status,
        200
    );
    let old_laptop = laptop.clone();

    // The laptop signs in again while it still holds a valid session.
    let again = sign_in(&app, &mut laptop, "alice@example.com", 1).await;
    assert_eq!(again.status, StatusCode::OK, "{}", again.text());
    assert_eq!(session_rows(&app).await, 3);
    assert_eq!(live_session_rows(&app).await, 2);

    let mut stale = old_laptop;
    assert_eq!(
        session_info(&app, &mut stale).await.status,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(session_info(&app, &mut laptop).await.status, StatusCode::OK);
    assert_eq!(session_info(&app, &mut phone).await.status, StatusCode::OK);
}

#[tokio::test]
async fn logout_revokes_server_side() {
    let app = app().await;
    seed(&app, 1, "alice@example.com").await;
    let mut jar = Jar::default();
    assert_eq!(
        sign_in(&app, &mut jar, "alice@example.com", 1).await.status,
        200
    );
    let copied = jar.clone();

    let out = send(
        &app,
        &mut jar,
        Req::post("/api/auth/logout")
            .page_fetch(Which::Vault)
            .header("x-forwarded-proto", "https"),
    )
    .await;
    assert_eq!(out.status, StatusCode::NO_CONTENT);
    assert!(out.body.is_empty());
    let cookies = out.set_cookies().join("\n");
    for name in ["__Host-ferret_sid", "__Host-ferret_session"] {
        assert!(cookies.contains(name), "{name} is cleared: {cookies}");
    }
    assert!(cookies.to_lowercase().contains("secure"));
    assert!(
        jar.names().is_empty(),
        "the browser drops them: {:?}",
        jar.names()
    );
    assert_eq!(live_session_rows(&app).await, 0);

    // Both cookies copied before the logout are worth nothing.
    let mut replay = copied;
    assert_eq!(
        session_info(&app, &mut replay).await.status,
        StatusCode::UNAUTHORIZED
    );
}

#[tokio::test]
async fn logout_without_a_valid_session_is_204_too() {
    let app = app().await;
    let mut jar = Jar::default();
    let out = send(
        &app,
        &mut jar,
        Req::post("/api/auth/logout")
            .page_fetch(Which::Vault)
            .header("x-forwarded-proto", "https"),
    )
    .await;
    assert_eq!(out.status, StatusCode::NO_CONTENT);
    jar.set("__Host-ferret_sid", "not-a-real-cookie");
    let out = send(
        &app,
        &mut jar,
        Req::post("/api/auth/logout")
            .page_fetch(Which::Vault)
            .header("x-forwarded-proto", "https"),
    )
    .await;
    assert_eq!(out.status, StatusCode::NO_CONTENT);
}

#[tokio::test]
async fn session_info_requires_both_cookies() {
    let app = app().await;
    seed(&app, 1, "alice@example.com").await;
    let mut jar = Jar::default();
    assert_eq!(
        sign_in(&app, &mut jar, "alice@example.com", 1).await.status,
        200
    );
    assert_eq!(
        session_info(&app, &mut jar.clone()).await.status,
        StatusCode::OK
    );
    for dropped in ["__Host-ferret_sid", "__Host-ferret_session"] {
        let mut partial = jar.clone();
        partial.remove(dropped);
        let res = session_info(&app, &mut partial).await;
        assert_eq!(res.status, StatusCode::UNAUTHORIZED, "without {dropped}");
        assert_eq!(error_code(&res), "unauthorized");
    }
    let mut none = Jar::default();
    assert_eq!(
        session_info(&app, &mut none).await.status,
        StatusCode::UNAUTHORIZED
    );
}

#[tokio::test]
async fn the_vault_cookies_do_not_open_the_admin_listener() {
    let app = app().await;
    seed(&app, 1, "alice@example.com").await;
    let mut jar = Jar::default();
    assert_eq!(
        sign_in(&app, &mut jar, "alice@example.com", 1).await.status,
        200
    );
    let res = send_admin(&app, &mut jar.clone(), admin_get("/api/auth/session")).await;
    assert_eq!(res.status, StatusCode::UNAUTHORIZED);
    // Logging out on the admin listener with a vault cookie ends nothing.
    let out = send_admin(
        &app,
        &mut jar,
        Req::post("/api/auth/logout")
            .page_fetch(Which::Admin)
            .header("x-forwarded-proto", "https"),
    )
    .await;
    assert_eq!(out.status, StatusCode::NO_CONTENT);
    assert_eq!(live_session_rows(&app).await, 1);
    // The admin listener has no sign-in route.
    let res = send_admin(
        &app,
        &mut Jar::default(),
        Req::post("/api/auth/opaque/login/start")
            .page_fetch(Which::Admin)
            .json(&json!({})),
    )
    .await;
    assert_eq!(res.status, StatusCode::NOT_FOUND);
}

// ---------------------------------------------------------- re-authentication

#[tokio::test]
async fn reauth_purpose_keeps_the_session_and_sets_the_grant() {
    let app = app().await;
    seed(&app, 1, "alice@example.com").await;
    let mut jar = Jar::default();
    assert_eq!(
        sign_in(&app, &mut jar, "alice@example.com", 1).await.status,
        200
    );
    let sid_before = jar.get("__Host-ferret_sid").unwrap().to_string();
    assert!(jar.get("__Host-ferret_reauth").is_none());

    let (res, started) = start(
        &app,
        &mut jar,
        "alice@example.com",
        PASSWORD,
        Some("reauth"),
    )
    .await;
    assert_eq!(res.status, StatusCode::OK, "{}", res.text());
    let started = started.unwrap();
    let login_id = started.login_id.clone();
    let ke3 = ke3_of(started).unwrap();
    let done = finish_as(&app, &mut jar, &login_id, &ke3, 1, Some("reauth")).await;
    assert_eq!(done.status, StatusCode::OK, "{}", done.text());
    assert_eq!(done.json()["vk_epoch"], 1);

    // The same session, still valid; no new row; the grant is set.
    assert_eq!(jar.get("__Host-ferret_sid").unwrap(), sid_before);
    assert_eq!(session_rows(&app).await, 1);
    assert_eq!(live_session_rows(&app).await, 1);
    assert!(
        jar.get("__Host-ferret_reauth").is_some(),
        "{:?}",
        jar.names()
    );
    assert_eq!(session_info(&app, &mut jar).await.status, StatusCode::OK);
}

#[tokio::test]
async fn reauth_without_a_session_is_denied() {
    let app = app().await;
    seed(&app, 1, "alice@example.com").await;
    let mut jar = Jar::default();
    let (res, started) = start(
        &app,
        &mut jar,
        "alice@example.com",
        PASSWORD,
        Some("reauth"),
    )
    .await;
    assert!(started.is_none());
    assert_eq!(res.status, StatusCode::UNAUTHORIZED);
    assert_eq!(error_code(&res), "unauthorized");
    assert_eq!(
        count(&app, "SELECT COUNT(*) FROM ferret_login_states").await,
        0
    );
}

#[tokio::test]
async fn a_reauth_is_bound_to_the_sessions_own_account() {
    let app = app().await;
    seed(&app, 1, "alice@example.com").await;
    seed_with(
        &app,
        2,
        "bob@example.com",
        Some(small_record(
            &app,
            &account_ids(0, 2).account_id,
            OTHER_PASSWORD,
        )),
    )
    .await;
    let mut jar = Jar::default();
    assert_eq!(
        sign_in(&app, &mut jar, "alice@example.com", 1).await.status,
        200
    );
    // Alice's session with bob's name and bob's password: the server answers
    // from alice's record, so bob's password does not open it.
    let (res, started) = start(
        &app,
        &mut jar,
        "bob@example.com",
        OTHER_PASSWORD,
        Some("reauth"),
    )
    .await;
    assert_eq!(res.status, StatusCode::OK);
    assert!(ke3_of(started.unwrap()).is_err());
}

// ------------------------------------------------------------- transport, clock

#[tokio::test]
async fn insecure_transport_is_refused_before_any_work() {
    let recording = Arc::new(RecordingThrottle::new());
    let app = TestApp::builder()
        .throttle(recording.clone() as Arc<dyn Throttle>)
        .build()
        .await;
    seed(&app, 1, "alice@example.com").await;
    let (ke1, _s) = opaque_login_start(&mut OsRng, &input(PASSWORD)).unwrap();
    // No trusted proxy at all, and the header says https.
    let req = Req::post("/api/auth/opaque/login/start")
        .page_fetch(Which::Vault)
        .header("x-forwarded-proto", "https")
        .json(&start_body("alice@example.com", &ke1, None));
    let res = app.call_raw(Which::Vault, req.build()).await;
    assert_eq!(
        (res.status.as_u16(), error_code(&res).as_str()),
        (400, "insecure_transport")
    );
    let req = Req::post("/api/auth/opaque/login/finish")
        .page_fetch(Which::Vault)
        .json(&finish_body(&"ab".repeat(16), &[1u8; 64], 1, None));
    let res = app.call_raw(Which::Vault, req.build()).await;
    assert_eq!(
        (res.status.as_u16(), error_code(&res).as_str()),
        (400, "insecure_transport")
    );
    assert!(res.set_cookies().is_empty());
    // Nothing was asked of the throttle, stored or written.
    assert!(recording.calls().is_empty());
    assert_eq!(
        count(&app, "SELECT COUNT(*) FROM ferret_login_states").await,
        0
    );
    assert_eq!(session_rows(&app).await, 0);

    // A listed proxy that does not say https is refused as well.
    let app = app_with(recording.clone() as Arc<dyn Throttle>).await;
    let req = Req::post("/api/auth/opaque/login/start")
        .page_fetch(Which::Vault)
        .json(&start_body("alice@example.com", &ke1, None));
    let res = app.call_raw(Which::Vault, req.build()).await;
    assert_eq!(error_code(&res), "insecure_transport");
    assert!(recording.calls().is_empty());
}

#[tokio::test]
async fn a_failed_clock_refuses_both_steps_before_any_work() {
    let recording = Arc::new(RecordingThrottle::new());
    let app = app_with(recording.clone() as Arc<dyn Throttle>).await;
    seed(&app, 1, "alice@example.com").await;
    app.clock.set(u64::MAX);
    let mut jar = Jar::default();
    let (ke1, _s) = opaque_login_start(&mut OsRng, &input(PASSWORD)).unwrap();
    let res = send(
        &app,
        &mut jar,
        vault_post(
            "/api/auth/opaque/login/start",
            &start_body("alice@example.com", &ke1, None),
        ),
    )
    .await;
    assert_eq!(res.status, StatusCode::INTERNAL_SERVER_ERROR);
    let res = finish(&app, &mut jar, &"ab".repeat(16), &[1u8; 64], 1).await;
    assert_eq!(res.status, StatusCode::INTERNAL_SERVER_ERROR);
    assert!(recording.calls().is_empty());
    assert_eq!(
        count(&app, "SELECT COUNT(*) FROM ferret_login_states").await,
        0
    );
    assert_eq!(session_rows(&app).await, 0);
}

#[tokio::test]
async fn the_throttle_is_asked_once_per_step_and_before_the_proof() {
    let recording = Arc::new(RecordingThrottle::new());
    let app = app_with(recording.clone() as Arc<dyn Throttle>).await;
    seed(&app, 1, "alice@example.com").await;
    let stages = |calls: Vec<ThrottleCall>| -> Vec<(&'static str, Stage)> {
        calls
            .into_iter()
            .map(|c| match c {
                ThrottleCall::Admit { stage, .. } => ("admit", stage),
                ThrottleCall::Record { stage, .. } => ("record", stage),
            })
            .collect()
    };
    let mut jar = Jar::default();
    let (_, started) = start(&app, &mut jar, "alice@example.com", PASSWORD, None).await;
    let started = started.unwrap();
    let login_id = started.login_id.clone();
    let ke3 = ke3_of(started).unwrap();
    assert_eq!(
        stages(recording.calls()),
        [("admit", Stage::LoginStart), ("record", Stage::LoginStart)]
    );
    recording.clear();
    assert_eq!(finish(&app, &mut jar, &login_id, &ke3, 1).await.status, 200);
    assert_eq!(
        stages(recording.calls()),
        [
            ("admit", Stage::LoginFinish),
            ("record", Stage::LoginFinish)
        ]
    );
    // The same for a login id nobody was given: one admit, one record.
    recording.clear();
    let mut jar = Jar::default();
    assert_eq!(
        finish(&app, &mut jar, &"cd".repeat(16), &[1u8; 64], 1)
            .await
            .status,
        401
    );
    assert_eq!(
        stages(recording.calls()),
        [
            ("admit", Stage::LoginFinish),
            ("record", Stage::LoginFinish)
        ]
    );
}

// --------------------------------------------------------- policy and purge

#[tokio::test]
async fn the_prelogin_policy_follows_the_real_accounts_and_is_renewed() {
    let app = app().await;
    // No accounts: profile 1, with a second factor for every answer.
    let empty = app
        .state
        .vault_db
        .with_conn(|conn| Ok(load_prelogin_policy(conn)))
        .await
        .unwrap();
    assert_eq!(empty, PreloginPolicy::single(KsfProfile::P1));

    seed(&app, 1, "alice@example.com").await;
    seed(&app, 2, "bob@example.com").await;
    app.state
        .vault_db
        .with_conn(|conn| {
            conn.execute(
                "UPDATE ferret_accounts SET sk_hint = 0 WHERE account_id = ?1",
                [account_ids(0, 2).account_id.as_bytes().as_slice()],
            )?;
            Ok(())
        })
        .await
        .unwrap();
    let loaded = app
        .state
        .vault_db
        .with_conn(|conn| Ok(load_prelogin_policy(conn)))
        .await
        .unwrap();
    assert_eq!(loaded, PreloginPolicy::new(&[(1, 1000)], 500).unwrap());

    // The renewal puts it into the state's holder.
    assert_eq!(
        *app.state.prelogin.read().unwrap(),
        PreloginPolicy::single(KsfProfile::P1)
    );
    refresh_once(
        &app.state.vault_db,
        &app.state.prelogin,
        app.state.clock.as_ref(),
    )
    .await;
    assert_eq!(*app.state.prelogin.read().unwrap(), loaded);

    // A disabled account no longer counts.
    app.state
        .vault_db
        .with_conn(|conn| {
            conn.execute(
                "UPDATE users SET active = 0 WHERE username = 'bob@example.com'",
                [],
            )?;
            Ok(())
        })
        .await
        .unwrap();
    refresh_once(
        &app.state.vault_db,
        &app.state.prelogin,
        app.state.clock.as_ref(),
    )
    .await;
    assert_eq!(
        *app.state.prelogin.read().unwrap(),
        PreloginPolicy::new(&[(1, 1000)], 1000).unwrap()
    );
}

#[tokio::test]
async fn the_lookup_tells_active_disabled_and_unknown_apart() {
    let app = app().await;
    seed(&app, 1, "alice@example.com").await;
    let disabled = seed(&app, 2, "dora@example.com").await;
    let bare = app
        .state
        .vault_db
        .with_conn(|conn| Ok(insert_user(conn, "root@example.com")))
        .await
        .unwrap();
    assert!(bare > 0);
    app.state
        .vault_db
        .with_conn(move |conn| {
            conn.execute("UPDATE users SET active = 0 WHERE id = ?1", [disabled])?;
            let kind = |email: &str| {
                let name = normalize_login_name(email).unwrap();
                match lookup_account(conn, &name).unwrap() {
                    ferret_server::auth::login::AccountLookupOwned::Active { .. } => "active",
                    ferret_server::auth::login::AccountLookupOwned::Disabled => "disabled",
                    ferret_server::auth::login::AccountLookupOwned::Unknown => "unknown",
                }
            };
            assert_eq!(kind("alice@example.com"), "active");
            assert_eq!(kind("Alice@Example.com "), "active");
            assert_eq!(kind("dora@example.com"), "disabled");
            assert_eq!(kind("root@example.com"), "unknown");
            assert_eq!(kind("nobody@example.com"), "unknown");
            Ok(())
        })
        .await
        .unwrap();
}

/// Tag, origin, issued at, last seen, revoked at, and whether the row is kept.
type Case = (u8, &'static str, i64, i64, Option<i64>, bool);

#[tokio::test]
async fn old_session_rows_are_purged_and_live_ones_are_not() {
    let app = app().await;
    let user = seed(&app, 1, "alice@example.com").await;
    let day = PURGE_MARGIN_SECS;
    let now = i64::try_from(START).unwrap();
    let (vault_idle, vault_abs) = (12 * 3600, 7 * 86400);
    let (admin_idle, admin_abs) = (3600, 12 * 3600);
    // (tag, origin, issued_at, last_seen, revoked_at, kept)
    let cases: Vec<Case> = vec![
        (1, "vault", now - 100, now - 50, None, true),
        (2, "vault", now - 100, now - 50, Some(now - 10), true),
        (
            3,
            "vault",
            now - 3 * day,
            now - 2 * day,
            Some(now - 2 * day),
            false,
        ),
        (4, "vault", now - 2 * vault_abs, now - 10, None, false),
        (
            5,
            "vault",
            now - 10,
            now - vault_idle - 2 * day,
            None,
            false,
        ),
        (6, "vault", now - 10, now - vault_idle - 100, None, true),
        (7, "vault", now - vault_abs - 100, now - 10, None, true),
        (
            8,
            "admin",
            now - 100,
            now - admin_idle - 2 * day,
            None,
            false,
        ),
        (9, "admin", now - admin_abs - 2 * day, now - 10, None, false),
        (10, "admin", now - admin_abs - 100, now - 10, None, true),
    ];
    let expected_kept: Vec<u8> = cases.iter().filter(|c| c.5).map(|c| c.0).collect();
    app.state
        .vault_db
        .with_conn(move |conn| {
            for (tag, origin, issued, seen, revoked, _) in cases {
                let mut sid = [0u8; 32];
                sid[0] = tag;
                conn.execute(
                    "INSERT INTO ferret_sessions
                       (sid_hash, user_id, issued_at, origin, device_id, device_name, scope,
                        last_seen, revoked_at)
                     VALUES (?1, ?2, ?3, ?4, zeroblob(16), 'x', 'full', ?5, ?6)",
                    rusqlite::params![sid.as_slice(), user, issued, origin, seen, revoked],
                )?;
            }
            let removed = purge_sessions(conn, now)?;
            assert_eq!(removed, 5);
            let mut stmt = conn.prepare("SELECT sid_hash FROM ferret_sessions ORDER BY rowid")?;
            let mut kept: Vec<u8> = stmt
                .query_map([], |r| r.get::<_, Vec<u8>>(0).map(|s| s[0]))?
                .collect::<Result<_, _>>()?;
            kept.sort_unstable();
            assert_eq!(kept, expected_kept);
            Ok(())
        })
        .await
        .unwrap();
}

// ------------------------------------------------------------------ the log

#[derive(Clone, Default)]
struct Sink(Arc<Mutex<Vec<u8>>>);

impl io::Write for Sink {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl<'a> MakeWriter<'a> for Sink {
    type Writer = Sink;

    fn make_writer(&'a self) -> Sink {
        self.clone()
    }
}

fn log_sink() -> Sink {
    static ONCE: Once = Once::new();
    static SINK: Mutex<Option<Sink>> = Mutex::new(None);
    ONCE.call_once(|| {
        let sink = Sink::default();
        let subscriber = tracing_subscriber::fmt()
            .with_writer(sink.clone())
            .with_ansi(false)
            .with_max_level(tracing::Level::TRACE)
            .finish();
        // Tasks run on other threads, so the subscriber is the process's.
        let _ = tracing::subscriber::set_global_default(subscriber);
        *SINK.lock().unwrap() = Some(sink);
    });
    SINK.lock().unwrap().clone().expect("the sink")
}

#[tokio::test]
async fn login_bytes_never_reach_the_log() {
    let sink = log_sink();
    let app = app().await;
    let email = "canary-login-7f3a@example.com";
    seed(&app, 1, email).await;

    let mut seen: Vec<String> = vec![email.to_string(), PASSWORD.to_string()];
    let mut jar = Jar::default();
    // A good sign-in, a bad one, an unknown name and a reauth.
    let input = input(PASSWORD);
    let (ke1, state) = opaque_login_start(&mut OsRng, &input).unwrap();
    seen.push(b64url::encode(&ke1));
    let res = send(
        &app,
        &mut jar,
        vault_post(
            "/api/auth/opaque/login/start",
            &start_body(email, &ke1, None),
        ),
    )
    .await;
    let body = res.json();
    let login_id = body["login_id"].as_str().unwrap().to_string();
    let ke2 = b64url::decode(body["ke2"].as_str().unwrap()).unwrap();
    seen.push(login_id.clone());
    seen.push(body["ke2"].as_str().unwrap().to_string());
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
    seen.push(b64url::encode(&ke3));
    let res = finish(&app, &mut jar, &login_id, &ke3, 1).await;
    assert_eq!(res.status, StatusCode::OK);
    for name in ["__Host-ferret_sid", "__Host-ferret_session"] {
        seen.push(jar.get(name).unwrap().to_string());
    }
    let _ = finish(&app, &mut jar, &login_id, &ke3, 1).await;
    let _ = finish(&app, &mut Jar::default(), &"ee".repeat(16), &[0x42; 64], 1).await;
    let _ = start(
        &app,
        &mut Jar::default(),
        "canary-ghost-91c2@example.com",
        PASSWORD,
        None,
    )
    .await;
    seen.push("canary-ghost-91c2@example.com".to_string());
    let _ = start(&app, &mut jar, email, PASSWORD, Some("reauth")).await;

    let log = String::from_utf8(sink.0.lock().unwrap().clone()).unwrap();
    // The canary only counts if the log is being written at all.
    assert!(
        log.contains("sign-in step refused"),
        "the sink got nothing: {log}"
    );
    for secret in &seen {
        assert!(!log.contains(secret.as_str()), "the log holds {secret}");
    }
}

// ----------------------------------------------------------------- timing

#[tokio::test]
async fn response_length_and_median_delay_known_vs_unknown() {
    let app = app().await;
    seed(&app, 1, "alice@example.com").await;
    let (ke1, _s) = opaque_login_start(&mut OsRng, &input(PASSWORD)).unwrap();
    let mut known = Vec::new();
    let mut unknown = Vec::new();
    let mut lengths = (0, 0);
    for round in 0..200 {
        for (email, times, len) in [
            ("alice@example.com", &mut known, &mut lengths.0),
            ("ghost@example.com", &mut unknown, &mut lengths.1),
        ] {
            let mut jar = Jar::default();
            let began = Instant::now();
            let res = send(
                &app,
                &mut jar,
                vault_post(
                    "/api/auth/opaque/login/start",
                    &start_body(email, &ke1, None),
                ),
            )
            .await;
            times.push(began.elapsed().as_secs_f64());
            assert_eq!(res.status, StatusCode::OK, "round {round}");
            *len = res.body.len();
        }
    }
    assert_eq!(lengths.0, lengths.1, "the answers differ in length");
    let median = |times: &mut Vec<f64>| {
        times.sort_by(f64::total_cmp);
        times[times.len() / 2]
    };
    let (known, unknown) = (median(&mut known), median(&mut unknown));
    // The full analysis is a later milestone; this catches a gross difference.
    let slack = known.max(unknown) * 0.5 + 0.002;
    assert!(
        (known - unknown).abs() < slack,
        "median known {known:.6}s, unknown {unknown:.6}s"
    );
}

// -------------------------------------------------------------------- e2e

#[tokio::test]
async fn e2e_real_client_production_profile() {
    let app = app().await;
    let email = "alice@example.com";
    // Register with profile 1 (Argon2id, 64 MiB), the real client function.
    let account = account_ids(0, 1).account_id;
    let production = {
        let input = input(PASSWORD);
        let mut rng = TestRng::new(b"production registration");
        let (request, state) = opaque_register_start(&mut rng, &input).unwrap();
        let response = register_start_open(
            &app.state.secrets.keys,
            &CredentialId::from(&account),
            &request,
        )
        .unwrap();
        let done = opaque_register_finish(&mut rng, state, &input, &response, KsfProfile::P1)
            .expect("register with profile 1");
        register_finish(
            &done.record,
            1,
            &ProfileRules::ferret_v1(),
            RegistrationKind::NewAccount,
        )
        .unwrap()
    };
    let user = seed_with(&app, 1, email, Some(production)).await;

    let mut jar = Jar::default();
    let input = input(PASSWORD);
    let (ke1, state) = opaque_login_start(&mut OsRng, &input).unwrap();
    let res = send(
        &app,
        &mut jar,
        vault_post(
            "/api/auth/opaque/login/start",
            &start_body(email, &ke1, None),
        ),
    )
    .await;
    assert_eq!(res.status, StatusCode::OK);
    let body = res.json();
    assert_eq!(body["ksf_profile"], 1);
    let ke2 = b64url::decode(body["ke2"].as_str().unwrap()).unwrap();
    let done = opaque_login_finish(
        &mut OsRng,
        state,
        &input,
        &ke2,
        u32::try_from(body["ksf_profile"].as_u64().unwrap()).unwrap(),
        PinState::FirstUse,
    )
    .expect("the client finishes with profile 1");
    let res = finish(
        &app,
        &mut jar,
        body["login_id"].as_str().unwrap(),
        &done.ke3,
        1,
    )
    .await;
    assert_eq!(res.status, StatusCode::OK, "{}", res.text());
    assert_eq!(
        res.json()["account_id"],
        support::session::hex(account_ids(user, 1).account_id.as_bytes())
    );
    assert_eq!(session_info(&app, &mut jar).await.status, StatusCode::OK);
}

#[tokio::test]
async fn a_sign_in_ends_the_vault_session_the_browser_presented_whoever_owns_it() {
    let app = app().await;
    seed(&app, 1, "alice@example.com").await;
    seed(&app, 2, "bob@example.com").await;
    let mut alice = Jar::default();
    assert_eq!(
        sign_in(&app, &mut alice, "alice@example.com", 1)
            .await
            .status,
        200
    );
    let alice_cookies = alice.clone();
    // A browser that holds alice's session signs in as bob: its cookies are
    // replaced, so alice's row would be left live and unreachable.
    let mut browser = alice.clone();
    assert_eq!(
        sign_in(&app, &mut browser, "bob@example.com", 2)
            .await
            .status,
        200
    );
    assert_eq!(session_rows(&app).await, 2);
    assert_eq!(live_session_rows(&app).await, 1);
    let mut old = alice_cookies;
    assert_eq!(
        session_info(&app, &mut old).await.status,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        session_info(&app, &mut browser).await.json()["email"],
        "bob@example.com"
    );
}

/// Starts a re-authentication in `jar` and returns the login id and KE3.
async fn reauth_proof(app: &TestApp, jar: &mut Jar) -> (String, Vec<u8>) {
    let (res, started) = start(app, jar, "alice@example.com", PASSWORD, Some("reauth")).await;
    assert_eq!(res.status, StatusCode::OK, "{}", res.text());
    let started = started.unwrap();
    let login_id = started.login_id.clone();
    (login_id, ke3_of(started).unwrap())
}

fn assert_denied(res: &Res) {
    assert_eq!(
        (res.status.as_u16(), error_code(res).as_str()),
        (401, "denied"),
        "{}",
        res.text()
    );
    assert!(res.set_cookies().is_empty(), "{:?}", res.set_cookies());
}

#[tokio::test]
async fn a_reauth_state_finished_as_a_login_is_denied() {
    let app = app().await;
    seed(&app, 1, "alice@example.com").await;
    let mut jar = Jar::default();
    assert_eq!(
        sign_in(&app, &mut jar, "alice@example.com", 1).await.status,
        200
    );
    let (login_id, ke3) = reauth_proof(&app, &mut jar).await;
    // The session is presented, but the request says login: no new session.
    let res = finish_as(&app, &mut jar, &login_id, &ke3, 1, None).await;
    assert_denied(&res);
    assert_eq!(session_rows(&app).await, 1);
    assert!(jar.get("__Host-ferret_reauth").is_none());
    // The state was used up by the refusal.
    let again = finish_as(&app, &mut jar, &login_id, &ke3, 1, Some("reauth")).await;
    assert_denied(&again);
    assert_eq!(session_info(&app, &mut jar).await.status, StatusCode::OK);
}

#[tokio::test]
async fn a_login_state_finished_as_a_reauth_is_denied() {
    let app = app().await;
    seed(&app, 1, "alice@example.com").await;
    let mut session = Jar::default();
    assert_eq!(
        sign_in(&app, &mut session, "alice@example.com", 1)
            .await
            .status,
        200
    );
    // A login started with no cookies, finished as a re-authentication with a
    // live session: no grant.
    let mut fresh = Jar::default();
    let (_, started) = start(&app, &mut fresh, "alice@example.com", PASSWORD, None).await;
    let started = started.unwrap();
    let login_id = started.login_id.clone();
    let ke3 = ke3_of(started).unwrap();
    let res = finish_as(&app, &mut session, &login_id, &ke3, 1, Some("reauth")).await;
    assert_denied(&res);
    assert!(session.get("__Host-ferret_reauth").is_none());
    assert_eq!(session_rows(&app).await, 1);
    assert_eq!(
        session_info(&app, &mut session).await.status,
        StatusCode::OK
    );
}

#[tokio::test]
async fn a_reauth_state_finished_with_a_different_live_session_is_denied() {
    let app = app().await;
    seed(&app, 1, "alice@example.com").await;
    seed(&app, 2, "bob@example.com").await;
    let mut laptop = Jar::default();
    let mut phone = Jar::default();
    let mut bob = Jar::default();
    assert_eq!(
        sign_in(&app, &mut laptop, "alice@example.com", 1)
            .await
            .status,
        200
    );
    assert_eq!(
        sign_in(&app, &mut phone, "alice@example.com", 2)
            .await
            .status,
        200
    );
    assert_eq!(
        sign_in(&app, &mut bob, "bob@example.com", 3).await.status,
        200
    );
    for (other, name) in [
        (&mut phone, "the same user's other session"),
        (&mut bob, "another user's session"),
    ] {
        let (login_id, ke3) = reauth_proof(&app, &mut laptop).await;
        let res = finish_as(&app, other, &login_id, &ke3, 9, Some("reauth")).await;
        assert_denied(&res);
        assert!(other.get("__Host-ferret_reauth").is_none(), "{name}");
        // The session that was presented is still live, no row was made, and
        // the state is gone for the laptop as well.
        assert_eq!(session_rows(&app).await, 3, "{name}");
        assert_eq!(live_session_rows(&app).await, 3, "{name}");
        assert_eq!(session_info(&app, other).await.status, StatusCode::OK);
        let late = finish_as(&app, &mut laptop, &login_id, &ke3, 1, Some("reauth")).await;
        assert_denied(&late);
    }
}

#[tokio::test]
async fn a_reauth_finish_without_a_session_is_unauthorized() {
    let app = app().await;
    seed(&app, 1, "alice@example.com").await;
    let mut jar = Jar::default();
    assert_eq!(
        sign_in(&app, &mut jar, "alice@example.com", 1).await.status,
        200
    );
    let (login_id, ke3) = reauth_proof(&app, &mut jar).await;
    let mut stranger = Jar::default();
    let res = finish_as(&app, &mut stranger, &login_id, &ke3, 9, Some("reauth")).await;
    assert_eq!(
        (res.status.as_u16(), error_code(&res).as_str()),
        (401, "unauthorized")
    );
    // Nor can the same proof open a sign-in.
    let res = finish_as(&app, &mut stranger, &login_id, &ke3, 9, None).await;
    assert_denied(&res);
    assert_eq!(session_rows(&app).await, 1);
}

type Calls = Vec<(&'static str, Stage)>;

fn stages(calls: Vec<ThrottleCall>) -> Calls {
    calls
        .into_iter()
        .map(|c| match c {
            ThrottleCall::Admit { stage, .. } => ("admit", stage),
            ThrottleCall::Record { stage, .. } => ("record", stage),
        })
        .collect()
}

#[tokio::test]
async fn a_session_cookie_adds_no_throttle_call_to_either_step() {
    let recording = Arc::new(RecordingThrottle::new());
    let app = app_with(recording.clone() as Arc<dyn Throttle>).await;
    seed(&app, 1, "alice@example.com").await;
    let mut jar = Jar::default();
    assert_eq!(
        sign_in(&app, &mut jar, "alice@example.com", 1).await.status,
        200
    );
    let pair = |stage| -> Calls { vec![("admit", stage), ("record", stage)] };

    // A sign-in from a browser that holds a live session.
    recording.clear();
    let (_, started) = start(&app, &mut jar, "alice@example.com", PASSWORD, None).await;
    let started = started.unwrap();
    let login_id = started.login_id.clone();
    let ke3 = ke3_of(started).unwrap();
    assert_eq!(stages(recording.calls()), pair(Stage::LoginStart));
    recording.clear();
    assert_eq!(finish(&app, &mut jar, &login_id, &ke3, 1).await.status, 200);
    assert_eq!(stages(recording.calls()), pair(Stage::LoginFinish));

    // A re-authentication in that session.
    recording.clear();
    let (login_id, ke3) = reauth_proof(&app, &mut jar).await;
    assert_eq!(stages(recording.calls()), pair(Stage::LoginStart));
    recording.clear();
    let done = finish_as(&app, &mut jar, &login_id, &ke3, 1, Some("reauth")).await;
    assert_eq!(done.status, StatusCode::OK, "{}", done.text());
    assert_eq!(stages(recording.calls()), pair(Stage::LoginFinish));

    // A refused purpose is still one pair, taken with the address alone.
    recording.clear();
    let (login_id, ke3) = reauth_proof(&app, &mut jar).await;
    recording.clear();
    let res = finish_as(&app, &mut jar, &login_id, &ke3, 1, None).await;
    assert_denied(&res);
    let calls = recording.calls();
    assert_eq!(stages(calls.clone()), pair(Stage::LoginFinish));
    let ThrottleCall::Admit { keys, .. } = &calls[0] else {
        panic!("the first call is an admit");
    };
    assert!(
        keys.iter()
            .all(|k| matches!(k, ThrottleKey::Ip(_) | ThrottleKey::UnknownAddress)),
        "no account key before the state is known"
    );
}

#[tokio::test]
async fn a_user_with_the_kits_second_factor_gets_no_session_after_a_good_proof() {
    let app = app().await;
    let user = seed(&app, 1, "alice@example.com").await;
    app.state
        .vault_db
        .with_conn(move |conn| {
            conn.execute("UPDATE users SET totp_enabled = 1 WHERE id = ?1", [user])?;
            Ok(())
        })
        .await
        .unwrap();
    let mut jar = Jar::default();
    let res = sign_in(&app, &mut jar, "alice@example.com", 1).await;
    assert_eq!(
        (res.status.as_u16(), error_code(&res).as_str()),
        (403, "forbidden"),
        "{}",
        res.text()
    );
    assert!(res.set_cookies().is_empty(), "{:?}", res.set_cookies());
    assert!(jar.names().is_empty());
    assert_eq!(session_rows(&app).await, 0);
    assert_eq!(
        count(
            &app,
            "SELECT COUNT(*) FROM users WHERE last_login_at IS NOT NULL"
        )
        .await,
        0
    );

    // The 403 comes only after the proof: a wrong password for the same user
    // is the ordinary 401, and tells nothing about the second factor.
    let (_, started) = start(&app, &mut jar, "alice@example.com", OTHER_PASSWORD, None).await;
    let login_id = started.unwrap().login_id;
    let res = finish(&app, &mut jar, &login_id, &[0x33; 64], 1).await;
    assert_denied(&res);
    assert_eq!(session_rows(&app).await, 0);
}

#[tokio::test]
async fn reauth_is_unchanged_for_a_user_who_turned_the_second_factor_on() {
    let app = app().await;
    let user = seed(&app, 1, "alice@example.com").await;
    let mut jar = Jar::default();
    assert_eq!(
        sign_in(&app, &mut jar, "alice@example.com", 1).await.status,
        200
    );
    app.state
        .vault_db
        .with_conn(move |conn| {
            conn.execute("UPDATE users SET totp_enabled = 1 WHERE id = ?1", [user])?;
            Ok(())
        })
        .await
        .unwrap();
    let (login_id, ke3) = reauth_proof(&app, &mut jar).await;
    let done = finish_as(&app, &mut jar, &login_id, &ke3, 1, Some("reauth")).await;
    assert_eq!(done.status, StatusCode::OK, "{}", done.text());
    assert!(jar.get("__Host-ferret_reauth").is_some());
    assert_eq!(session_rows(&app).await, 1);
}

#[tokio::test]
async fn logout_with_a_failed_clock_still_clears_the_cookies() {
    let app = app().await;
    seed(&app, 1, "alice@example.com").await;
    let mut jar = Jar::default();
    assert_eq!(
        sign_in(&app, &mut jar, "alice@example.com", 1).await.status,
        200
    );
    app.clock.set(u64::MAX);
    let out = send(
        &app,
        &mut jar,
        Req::post("/api/auth/logout")
            .page_fetch(Which::Vault)
            .header("x-forwarded-proto", "https"),
    )
    .await;
    assert_eq!(out.status, StatusCode::NO_CONTENT);
    let cookies = out.set_cookies().join("\n");
    for name in ["__Host-ferret_sid", "__Host-ferret_session"] {
        assert!(cookies.contains(name), "{name} is cleared: {cookies}");
    }
    assert!(jar.names().is_empty(), "{:?}", jar.names());
    // Only the revoke was skipped.
    assert_eq!(live_session_rows(&app).await, 1);
}

/// Adds kit users with vault accounts `from..to`, all with the same hint.
async fn add_plain_accounts(app: &TestApp, from: u8, to: u8, hint: bool) {
    let now = i64::try_from(app.clock.now_unix()).unwrap();
    app.state
        .vault_db
        .with_conn(move |conn| {
            for n in from..to {
                let account = support::accounts::add_account(conn, n, now);
                conn.execute(
                    "UPDATE ferret_accounts SET sk_hint = ?1 WHERE account_id = ?2",
                    rusqlite::params![i64::from(hint), account.account_id.as_bytes().as_slice()],
                )?;
            }
            Ok(())
        })
        .await
        .unwrap();
}

async fn policy_now(app: &TestApp) -> PreloginPolicy {
    app.state
        .vault_db
        .with_conn(|conn| Ok(load_prelogin_policy(conn)))
        .await
        .unwrap()
}

/// What the made-up answer says for 300 names that nobody holds.
fn made_up_answers(app: &TestApp, policy: &PreloginPolicy) -> Vec<(u8, bool)> {
    (0..300)
        .map(|i| {
            let name = normalize_login_name(&format!("nobody-{i}@example.com")).unwrap();
            let answer = fake_prelogin(&app.state.secrets.prelogin, &name, policy);
            (answer.ksf_profile, answer.sk_hint)
        })
        .collect()
}

#[tokio::test]
async fn the_made_up_hint_does_not_move_while_the_real_share_stays_inside_the_band() {
    let app = app().await;
    // Ten accounts, five with a secret key: a share of 500.
    add_plain_accounts(&app, 1, 6, true).await;
    add_plain_accounts(&app, 6, 11, false).await;
    let first = policy_now(&app).await;
    assert_eq!(first, PreloginPolicy::new(&[(1, 1000)], 500).unwrap());
    let before = made_up_answers(&app, &first);
    assert!(
        before.iter().any(|a| a.1) && before.iter().any(|a| !a.1),
        "the check needs names on both sides"
    );

    // 6 of 11 (545) and 7 of 12 (583) stay inside the band around 500.
    add_plain_accounts(&app, 11, 12, true).await;
    add_plain_accounts(&app, 12, 13, true).await;
    let moved = policy_now(&app).await;
    assert_eq!(moved, first);
    assert_eq!(made_up_answers(&app, &moved), before);

    // 8 of 13 (615) is more than 50 past the edge of the bucket: it moves.
    add_plain_accounts(&app, 13, 14, true).await;
    let crossed = policy_now(&app).await;
    assert_eq!(crossed, PreloginPolicy::new(&[(1, 1000)], 600).unwrap());

    // The bucket is kept in the database: the real share falls back to 545 and
    // a fresh read (what a restart does) still gives 600.
    app.state
        .vault_db
        .with_conn(|conn| {
            conn.execute(
                "UPDATE users SET active = 0
                 WHERE username IN ('user12@example.com', 'user13@example.com')",
                [],
            )?;
            Ok(())
        })
        .await
        .unwrap();
    assert_eq!(policy_now(&app).await, crossed);
    let stored: Vec<u8> = app
        .state
        .vault_db
        .with_conn(|conn| {
            Ok(conn.query_row(
                "SELECT value FROM ferret_meta WHERE key = 'prelogin_buckets'",
                [],
                |r| r.get(0),
            )?)
        })
        .await
        .unwrap();
    assert_eq!(stored, b"sk=600;p1=1000;");
}

#[tokio::test]
async fn one_account_without_a_key_among_twenty_does_not_make_the_other_answer_proof() {
    let app = app().await;
    // 19 accounts with a secret key and 1 without: a share of 950, which used to
    // round to 1000 and make every `false` answer prove that the name exists.
    add_plain_accounts(&app, 1, 20, true).await;
    add_plain_accounts(&app, 20, 21, false).await;
    let policy = policy_now(&app).await;
    assert_eq!(policy, PreloginPolicy::new(&[(1, 1000)], 900).unwrap());
    let answers = made_up_answers(&app, &policy);
    assert!(
        answers.iter().any(|a| !a.1),
        "some made-up answers say false"
    );
    assert!(answers.iter().any(|a| a.1), "and most say true");

    // Everyone with a key: nothing to hide, and the extreme is exact.
    app.state
        .vault_db
        .with_conn(|conn| {
            conn.execute("UPDATE ferret_accounts SET sk_hint = 1", [])?;
            Ok(())
        })
        .await
        .unwrap();
    let all = policy_now(&app).await;
    assert_eq!(all, PreloginPolicy::new(&[(1, 1000)], 1000).unwrap());
    assert!(made_up_answers(&app, &all).iter().all(|a| a.1));

    // Nobody with a key, and 1 of 20 with one: 50 permille is bucket 100, never 0.
    app.state
        .vault_db
        .with_conn(|conn| {
            conn.execute("UPDATE ferret_accounts SET sk_hint = 0", [])?;
            Ok(())
        })
        .await
        .unwrap();
    let none = policy_now(&app).await;
    assert_eq!(none, PreloginPolicy::new(&[(1, 1000)], 0).unwrap());
    app.state
        .vault_db
        .with_conn(|conn| {
            conn.execute(
                "UPDATE ferret_accounts SET sk_hint = 1 WHERE rowid = (SELECT MIN(rowid) FROM ferret_accounts)",
                [],
            )?;
            Ok(())
        })
        .await
        .unwrap();
    let one = policy_now(&app).await;
    assert_eq!(one, PreloginPolicy::new(&[(1, 1000)], 100).unwrap());
}

#[tokio::test]
async fn a_failed_bucket_write_does_not_change_the_policy() {
    let app = app().await;
    add_plain_accounts(&app, 1, 20, true).await;
    add_plain_accounts(&app, 20, 21, false).await;
    // Storing the buckets fails (as a busy or full database would).
    app.state
        .vault_db
        .with_conn(|conn| {
            conn.execute_batch(
                "CREATE TRIGGER no_buckets BEFORE INSERT ON ferret_meta
                 WHEN NEW.key = 'prelogin_buckets'
                 BEGIN SELECT RAISE(ABORT, 'no'); END;",
            )?;
            Ok(())
        })
        .await
        .unwrap();
    // The policy is the computed one, not the fall-back with a hint for all.
    let policy = policy_now(&app).await;
    assert_eq!(policy, PreloginPolicy::new(&[(1, 1000)], 900).unwrap());
    assert_ne!(policy, PreloginPolicy::single(KsfProfile::P1));
    let stored = count(
        &app,
        "SELECT COUNT(*) FROM ferret_meta WHERE key = 'prelogin_buckets'",
    )
    .await;
    assert_eq!(stored, 0);
    // The renewal uses it too.
    refresh_once(
        &app.state.vault_db,
        &app.state.prelogin,
        app.state.clock.as_ref(),
    )
    .await;
    assert_eq!(*app.state.prelogin.read().unwrap(), policy);
}
