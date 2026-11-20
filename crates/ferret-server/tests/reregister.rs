//! `POST /api/auth/opaque/reregister/start`: the first step of a new OPAQUE
//! registration inside a session, for the session's own account only. Spec:
//! Fase 1 § 4.2 ("Registrering"), § 4.3 (changing MP) and § 6.3 step 1.

mod support;

use std::sync::Arc;

use axum::http::StatusCode;
use ferret_core::{TestRng, opaque_register_start};
use ferret_server::auth::session::Origin;
use ferret_server::auth::throttle::KitThrottle;
use ferret_server::ids::AccountId;
use ferret_server::wire::b64url;
use ferret_server_auth::testing::register_start_open;
use ferret_server_auth::{Clock, CredentialId, ManualClock, SessionScope, Throttle};
use serde_json::json;
use support::accounts::{
    CLIENT_PASSWORD, client_account, client_session, opaque_input, reregister_start,
};
use support::session::issue;
use support::{Jar, Req, Res, START, TestApp, Which};

const PATH: &str = "/api/auth/opaque/reregister/start";

/// A first message of a registration of `password`.
fn request(seed: &str) -> Vec<u8> {
    let mut rng = TestRng::new(seed.as_bytes());
    opaque_register_start(&mut rng, &opaque_input(CLIENT_PASSWORD))
        .expect("a first message")
        .0
}

/// What the server answers for `account`, made by the library directly.
fn answer_for(app: &TestApp, account: &AccountId, request: &[u8]) -> Vec<u8> {
    register_start_open(
        &app.state.secrets.keys,
        &CredentialId::from(account),
        request,
    )
    .expect("an answer")
}

fn response_of(res: &Res) -> Vec<u8> {
    assert_eq!(res.status, StatusCode::OK, "{}", res.text());
    b64url::decode(
        res.json()["registration_response"]
            .as_str()
            .expect("a response"),
    )
    .expect("base64url")
}

fn error_of(res: &Res) -> String {
    res.json()["error"].as_str().unwrap_or("").to_string()
}

/// A POST of `body` to the route on `which`, with the cookies of `jar`.
async fn post(app: &TestApp, which: Which, jar: &Jar, body: &serde_json::Value) -> Res {
    let mut req = Req::post(PATH).page_fetch(which).json(body);
    if let Some(cookie) = jar.header() {
        req = req.header("cookie", &cookie);
    }
    app.call_raw(which, req.build()).await
}

#[tokio::test]
async fn reregister_answers_for_the_sessions_own_account_only() {
    let app = TestApp::new().await;
    let alice = client_account(&app, 1).await;
    let bob = client_account(&app, 2).await;
    let alice_jar = client_session(&app, &alice, SessionScope::Full, 1)
        .await
        .jar;
    let bob_jar = client_session(&app, &bob, SessionScope::Full, 2).await.jar;
    let request = request("reregister own account");

    // Each session gets the answer under its own account's key, and the two
    // differ.
    let for_alice = response_of(&reregister_start(&app, &alice_jar, &request).await);
    let for_bob = response_of(&reregister_start(&app, &bob_jar, &request).await);
    assert_eq!(for_alice, answer_for(&app, &alice.ids.account_id, &request));
    assert_eq!(for_bob, answer_for(&app, &bob.ids.account_id, &request));
    assert_ne!(for_alice, for_bob);
    let res = reregister_start(&app, &alice_jar, &request).await;
    assert_eq!(res.header("cache-control"), "no-store");

    // The request cannot name another account: the body has one field.
    for body in [
        json!({
            "registration_request": b64url::encode(&request),
            "account_id": "a0".repeat(16),
        }),
        json!({
            "registration_request": b64url::encode(&request),
            "credential_id": "a0".repeat(16),
        }),
        json!({}),
    ] {
        let res = post(&app, Which::Vault, &alice_jar, &body).await;
        assert_eq!(
            res.status,
            StatusCode::BAD_REQUEST,
            "{body}: {}",
            res.text()
        );
    }
    // A request that is not 32 bytes, or not a group element.
    for bad in [vec![1u8; 31], vec![1u8; 33], vec![0xff; 32]] {
        let res = reregister_start(&app, &alice_jar, &bad).await;
        assert_eq!(res.status, StatusCode::BAD_REQUEST, "{}", res.text());
        assert_eq!(error_of(&res), "malformed_registration_request");
    }

    // No session: 401, the body unread.
    let res = reregister_start(&app, &Jar::default(), &request).await;
    assert_eq!(res.status, StatusCode::UNAUTHORIZED, "{}", res.text());
    let res = post(&app, Which::Vault, &Jar::default(), &json!("not a body")).await;
    assert_eq!(res.status, StatusCode::UNAUTHORIZED, "{}", res.text());
}

#[tokio::test]
async fn account_reset_may_reregister() {
    let app = TestApp::new().await;
    let client = client_account(&app, 3).await;
    let reset = client_session(&app, &client, SessionScope::AccountReset, 1).await;
    let request = request("reregister reset");
    let res = reregister_start(&app, &reset.jar, &request).await;
    assert_eq!(
        response_of(&res),
        answer_for(&app, &client.ids.account_id, &request)
    );

    // The scopes without the capability are refused before the body is read.
    for scope in [SessionScope::Pending2fa, SessionScope::Unverified] {
        let issued = issue(&app, client.ids.user_id, Origin::Vault, scope, 2).await;
        let res = reregister_start(&app, &issued.jar, &request).await;
        assert_eq!(
            res.status,
            StatusCode::FORBIDDEN,
            "{scope:?}: {}",
            res.text()
        );
        assert_eq!(error_of(&res), "forbidden");
    }
}

#[tokio::test]
async fn reregister_is_throttled() {
    let throttle: Arc<dyn Throttle> = Arc::new(KitThrottle::new(
        Arc::new(ManualClock::new(START)) as Arc<dyn Clock>
    ));
    let app = TestApp::builder().throttle(throttle).build().await;
    let client = client_account(&app, 4).await;
    let jar = client_session(&app, &client, SessionScope::Full, 1)
        .await
        .jar;
    let request = request("reregister throttled");
    for n in 0..5 {
        let res = reregister_start(&app, &jar, &request).await;
        assert_eq!(res.status, StatusCode::OK, "attempt {n}: {}", res.text());
    }
    let res = reregister_start(&app, &jar, &request).await;
    assert_eq!(res.status, StatusCode::TOO_MANY_REQUESTS, "{}", res.text());
    assert_eq!(error_of(&res), "throttled");
    assert!(!res.header("retry-after").is_empty());

    // The session comes first: without one the answer is 401, not 429.
    let res = reregister_start(&app, &Jar::default(), &request).await;
    assert_eq!(res.status, StatusCode::UNAUTHORIZED, "{}", res.text());
}

#[tokio::test]
async fn admin_listener_has_no_reregister_route() {
    let app = TestApp::new().await;
    let client = client_account(&app, 5).await;
    let admin = issue(
        &app,
        client.ids.user_id,
        Origin::Admin,
        SessionScope::Full,
        1,
    )
    .await;
    let body = json!({ "registration_request": b64url::encode(&request("admin")) });
    let res = post(&app, Which::Admin, &admin.jar, &body).await;
    assert_eq!(res.status, StatusCode::NOT_FOUND, "{}", res.text());
    let res = post(&app, Which::Admin, &Jar::default(), &body).await;
    assert_eq!(res.status, StatusCode::NOT_FOUND, "{}", res.text());
}
