//! `POST /api/auth/challenge`: the nonce of a signed request, its binding to
//! the session, its single use, its lifetime and the limit per session.
//! Spec: Fase 1 § 4.6.
//!
//! The nonces are used on the signed route of `support::session::signed_probe`,
//! which goes through the same extractors and library calls as the routes of
//! signed requests.

mod support;

use axum::http::StatusCode;
use ferret_core::AuthOp;
use ferret_server::auth::session::Origin;
use ferret_server::wire::b64url;
use ferret_server_auth::SessionScope;
use support::session::{
    Issued, call_probe, challenge_with, issue, make_fresh, nonce_for, reset_session, seed_signer,
    sign, signed_probe,
};
use support::{Req, TestApp, Which};

const BODY: &[u8] = br#"{"n":7}"#;

/// The signer and `n` full vault sessions of it, on devices 1 to `n`, each
/// just re-authenticated (the signed route asks for it).
async fn full_sessions(app: &TestApp, n: u8) -> Vec<Issued> {
    let user = seed_signer(app).await.user_id;
    let mut sessions = Vec::new();
    for device in 1..=n {
        let issued = issue(app, user, Origin::Vault, SessionScope::Full, device).await;
        make_fresh(app, issued.sid).await;
        sessions.push(issued);
    }
    sessions
}

async fn full_session(app: &TestApp) -> Issued {
    full_sessions(app, 1).await.remove(0)
}

/// Sends the probe's body with a proof made by the signer over `nonce`.
async fn use_nonce(app: &TestApp, jar: &support::Jar, nonce: &[u8; 32]) -> support::Res {
    let proof = sign(AuthOp::UnlockMethodRecoveryPut, nonce, BODY);
    call_probe(
        &signed_probe(app),
        jar,
        Some(&b64url::encode(nonce)),
        Some(&b64url::encode(&proof)),
        BODY.to_vec(),
    )
    .await
}

#[tokio::test]
async fn challenge_is_32_bytes_and_expires_in_300() {
    let app = TestApp::new().await;
    let session = full_session(&app).await;
    let res = challenge_with(&app, &session.jar).await;
    assert_eq!(res.status, StatusCode::OK, "{}", res.text());
    assert_eq!(res.header("cache-control"), "no-store");
    let body = res.json();
    let fields: Vec<&String> = body.as_object().expect("an object").keys().collect();
    assert_eq!(fields, ["expires_in", "nonce"]);
    assert_eq!(body["expires_in"], 300);
    let nonce = b64url::decode(body["nonce"].as_str().expect("a nonce")).expect("base64url");
    assert_eq!(nonce.len(), 32);
    // The store holds a hash of it, never the nonce.
    assert_eq!(app.challenges().store().len(), 1);
    // Two nonces are two different values.
    let again = nonce_for(&app, &session.jar).await;
    assert_ne!(again.as_slice(), nonce.as_slice());
    assert_eq!(app.challenges().store().len(), 2);
}

#[tokio::test]
async fn account_reset_may_ask_for_a_challenge() {
    let app = TestApp::new().await;
    let (_, reset) = reset_session(&app).await;
    let res = challenge_with(&app, &reset.jar).await;
    assert_eq!(res.status, StatusCode::OK, "{}", res.text());
    assert_eq!(res.json()["expires_in"], 300);
}

#[tokio::test]
async fn no_session_and_a_scope_without_the_capability_get_no_nonce() {
    let app = TestApp::new().await;
    let res = challenge_with(&app, &support::Jar::default()).await;
    assert_eq!(res.status, StatusCode::UNAUTHORIZED);
    assert_eq!(res.json()["error"], "unauthorized");
    let user = seed_signer(&app).await.user_id;
    for (n, scope) in [(2, SessionScope::Pending2fa), (3, SessionScope::Unverified)] {
        let session = issue(&app, user, Origin::Vault, scope, n).await;
        let res = challenge_with(&app, &session.jar).await;
        assert_eq!(res.status, StatusCode::FORBIDDEN, "{scope:?}");
        assert_eq!(res.json()["error"], "forbidden");
    }
    assert!(app.challenges().store().is_empty());
}

#[tokio::test]
async fn a_nonce_is_bound_to_its_session() {
    let app = TestApp::new().await;
    let sessions = full_sessions(&app, 2).await;
    let (first, second) = (&sessions[0], &sessions[1]);
    let nonce = nonce_for(&app, &first.jar).await;

    // The other session of the same user cannot use it, with a valid proof.
    let res = use_nonce(&app, &second.jar, &nonce).await;
    assert_eq!(res.status, StatusCode::UNAUTHORIZED, "{}", res.text());
    assert_eq!(res.json()["error"], "denied");

    // The session it was issued to still can, once.
    let res = use_nonce(&app, &first.jar, &nonce).await;
    assert_eq!(res.status, StatusCode::OK, "{}", res.text());
    assert_eq!(res.json()["n"], 7);
    let res = use_nonce(&app, &first.jar, &nonce).await;
    assert_eq!(res.status, StatusCode::UNAUTHORIZED);
    assert_eq!(res.json()["error"], "denied");
}

#[tokio::test]
async fn a_nonce_is_used_once_even_when_the_proof_is_wrong() {
    let app = TestApp::new().await;
    let session = full_session(&app).await;
    let nonce = nonce_for(&app, &session.jar).await;
    let mut wrong = sign(AuthOp::UnlockMethodRecoveryPut, &nonce, BODY);
    wrong[0] ^= 1;
    let res = call_probe(
        &signed_probe(&app),
        &session.jar,
        Some(&b64url::encode(&nonce)),
        Some(&b64url::encode(&wrong)),
        BODY.to_vec(),
    )
    .await;
    assert_eq!(res.status, StatusCode::UNAUTHORIZED);
    assert_eq!(res.json()["error"], "denied");
    assert!(app.challenges().store().is_empty(), "the nonce is gone");

    // The right proof over the same nonce comes too late.
    let res = use_nonce(&app, &session.jar, &nonce).await;
    assert_eq!(res.status, StatusCode::UNAUTHORIZED);
    assert_eq!(res.json()["error"], "denied");
}

#[tokio::test]
async fn an_expired_nonce_is_refused() {
    let app = TestApp::new().await;
    let session = full_session(&app).await;

    let nonce = nonce_for(&app, &session.jar).await;
    app.clock.advance(299);
    let res = use_nonce(&app, &session.jar, &nonce).await;
    assert_eq!(res.status, StatusCode::OK, "299 seconds: {}", res.text());

    let nonce = nonce_for(&app, &session.jar).await;
    app.clock.advance(300);
    // A new re-authentication, so the nonce is what is too old.
    make_fresh(&app, session.sid).await;
    let res = use_nonce(&app, &session.jar, &nonce).await;
    assert_eq!(res.status, StatusCode::UNAUTHORIZED, "300 seconds");
    assert_eq!(res.json()["error"], "denied");
}

#[tokio::test]
async fn challenge_issue_is_throttled_at_30_per_session_and_minute() {
    let app = TestApp::new().await;
    let sessions = full_sessions(&app, 2).await;
    let (first, second) = (&sessions[0], &sessions[1]);
    for i in 0..30 {
        let res = challenge_with(&app, &first.jar).await;
        assert_eq!(res.status, StatusCode::OK, "nonce {i}");
        app.clock.advance(1);
    }
    // The 31st within the minute is refused, and the refusal costs no nonce.
    let stored = app.challenges().store().len();
    let res = challenge_with(&app, &first.jar).await;
    assert_eq!(res.status, StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(res.json()["error"], "throttled");
    let wait: u64 = res.header("retry-after").parse().expect("a Retry-After");
    assert!((1..=60).contains(&wait), "{wait}");
    assert_eq!(app.challenges().store().len(), stored);
    // A refused request does not extend the block.
    let res = challenge_with(&app, &first.jar).await;
    assert_eq!(res.status, StatusCode::TOO_MANY_REQUESTS);

    // Another session of the same user has its own count.
    let res = challenge_with(&app, &second.jar).await;
    assert_eq!(res.status, StatusCode::OK);

    // A minute after the first nonce, the first one has left the window.
    app.clock.advance(wait);
    let res = challenge_with(&app, &first.jar).await;
    assert_eq!(res.status, StatusCode::OK, "{}", res.text());
}

#[tokio::test]
async fn admin_listener_has_no_challenge_route() {
    let app = TestApp::new().await;
    let user = seed_signer(&app).await.user_id;
    let admin = issue(&app, user, Origin::Admin, SessionScope::Full, 1).await;
    let req = Req::post("/api/auth/challenge")
        .page_fetch(Which::Admin)
        .header("cookie", &admin.jar.header().expect("cookies"))
        .build();
    let res = app.call_raw(Which::Admin, req).await;
    assert!(
        res.status == StatusCode::NOT_FOUND || res.status == StatusCode::FORBIDDEN,
        "{} {}",
        res.status,
        res.text()
    );
    assert!(app.challenges().store().is_empty());
}
