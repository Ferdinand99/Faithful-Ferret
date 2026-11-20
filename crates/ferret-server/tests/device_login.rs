//! The sign-in of a device client: `POST /api/auth/opaque/login/finish` with
//! the device body and a DPoP proof gives a device row, an access token and a
//! refresh token, and no cookie. Driven through the real router with the real
//! OPAQUE client of `ferret-core` and proofs of a test key.
//!
//! Spec: Fase 1 § 4.2, § 7.6, § 8.2; RFC 9449 § 4, § 5.

mod support;

use std::path::Path;
use std::sync::mpsc;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::body::to_bytes;
use axum::extract::ConnectInfo;
use axum::http::{HeaderValue, StatusCode, header};
use ferret_server::auth::devices::{revoke, still_valid, touch};
use ferret_server::auth::dpop::{JTI_PER_KEY, JTI_PER_USER, JtiCache};
use ferret_server::auth::refresh::{ABSOLUTE_SECS, IDLE_SECS};
use ferret_server::auth::tokens::{AccessLookup, lookup_access};
use ferret_server::ids::{DeviceId, TokenSecret};
use ferret_server::wire::{DeviceLoginFinishRes, MAX_DEVICES, TokenTypeJson, b64url};
use ferret_server_auth::{
    Outcome, RecordingThrottle, RetryAfter, SessionScope, Stage, Throttle, ThrottleCall,
    ThrottleKey,
};
use serde_json::{Value, json};
use support::accounts::{
    CLIENT_PASSWORD, Client, client_account, client_session, password_change, put_password,
};
use support::device::{
    DEVICE_NAME, DeviceClient, HalfWay, LOGIN_FINISH, device_app, device_app_builder, device_body,
    finish_req, login_start, now,
};
use support::dpop::{DeviceKey, claims, fresh_jti};
use support::{Jar, PEER, Req, Res, START, TestApp, VAULT_URL, Which};
use tower::ServiceExt as _;

const NEW_PASSWORD: &str = "a brand new horse battery staple";
const WRONG_PASSWORD: &str = "a quite different password";

// ------------------------------------------------------------------ helpers

fn email(n: u8) -> String {
    format!("client{n}@example.com")
}

fn error_code(res: &Res) -> String {
    res.json()["error"].as_str().unwrap_or("").to_string()
}

fn status_and_code(res: &Res) -> (u16, String) {
    (res.status.as_u16(), error_code(res))
}

/// Everything a client sees of an answer: the status, every header (sorted)
/// and the body.
type Seen = (StatusCode, Vec<(String, String)>, Vec<u8>);

/// What a client sees of `res`: see [`Seen`].
fn seen(res: &Res) -> Seen {
    let mut headers: Vec<(String, String)> = res
        .headers
        .iter()
        .map(|(k, v)| {
            (
                k.as_str().to_string(),
                v.to_str().unwrap_or("?").to_string(),
            )
        })
        .collect();
    headers.sort();
    (res.status, headers, res.body.clone())
}

async fn count(app: &TestApp, sql: &'static str) -> i64 {
    app.state
        .vault_db
        .with_conn(move |conn| Ok(conn.query_row(sql, [], |r| r.get(0))?))
        .await
        .expect("a count")
}

async fn device_count(app: &TestApp) -> i64 {
    count(app, "SELECT COUNT(*) FROM ferret_devices").await
}

async fn token_rows(app: &TestApp) -> (i64, i64) {
    (
        count(app, "SELECT COUNT(*) FROM ferret_access").await,
        count(app, "SELECT COUNT(*) FROM ferret_refresh").await,
    )
}

async fn exec(app: &TestApp, sql: &'static str, user_id: i64) {
    app.state
        .vault_db
        .with_conn(move |conn| {
            conn.execute(sql, [user_id])?;
            Ok(())
        })
        .await
        .expect("an update");
}

fn replay_len(app: &TestApp) -> usize {
    app.state.device_auth.replay().len()
}

/// A device row as the database holds it.
#[derive(Debug, PartialEq, Eq)]
struct DeviceRow {
    id: Vec<u8>,
    user_id: i64,
    jkt: Vec<u8>,
    name: String,
    platform: String,
    session_version: i64,
    created_at: i64,
    last_seen: i64,
    revoked_at: Option<i64>,
}

async fn device_rows(app: &TestApp) -> Vec<DeviceRow> {
    app.state
        .vault_db
        .with_conn(|conn| {
            let mut statement = conn.prepare(
                "SELECT device_id, user_id, jkt, name, platform, session_version, created_at,
                        last_seen, revoked_at
                 FROM ferret_devices ORDER BY created_at, rowid",
            )?;
            let rows = statement
                .query_map([], |r| {
                    Ok(DeviceRow {
                        id: r.get(0)?,
                        user_id: r.get(1)?,
                        jkt: r.get(2)?,
                        name: r.get(3)?,
                        platform: r.get(4)?,
                        session_version: r.get(5)?,
                        created_at: r.get(6)?,
                        last_seen: r.get(7)?,
                        revoked_at: r.get(8)?,
                    })
                })?
                .collect::<Result<Vec<_>, _>>()?;
            Ok(rows)
        })
        .await
        .expect("the device rows")
}

async fn lookup(app: &TestApp, token: &TokenSecret, at: i64) -> AccessLookup {
    let hash = token.hash();
    app.state
        .vault_db
        .with_conn(move |conn| Ok(lookup_access(conn, &hash, at)?))
        .await
        .expect("a lookup")
}

async fn valid(app: &TestApp, device: [u8; 16], at: i64) -> bool {
    app.state
        .vault_db
        .with_conn(move |conn| Ok(still_valid(conn, &DeviceId(device), at)?))
        .await
        .expect("a check")
}

async fn revoke_device(app: &TestApp, user_id: i64, device: [u8; 16], at: i64) -> bool {
    app.state
        .vault_db
        .with_conn(move |conn| {
            let tx = conn.transaction()?;
            let done = revoke(&tx, user_id, &DeviceId(device), at)?;
            tx.commit()?;
            Ok(done)
        })
        .await
        .expect("a revocation")
}

/// A signed-in device of account `n`, with key `key`.
async fn signed_in(app: &TestApp, n: u8, key: u8) -> DeviceClient {
    let mut device = DeviceClient::new(key);
    let res = device.sign_in(app, &email(n), CLIENT_PASSWORD).await;
    assert_eq!(res.status, StatusCode::OK, "{}", res.text());
    device
}

/// A pending sign-in code for `user`, as the kit stores it.
async fn code_for(app: &TestApp, user: i64, n: u8) {
    let hash = [n; 32];
    app.state
        .vault_db
        .with_conn(move |conn| {
            vole_kit::db::sign_in_codes::insert(conn, user, &hash, user)?;
            Ok(())
        })
        .await
        .expect("a code");
}

async fn pending_codes(app: &TestApp, user: i64) -> i64 {
    app.state
        .vault_db
        .with_conn(move |conn| Ok(vole_kit::db::sign_in_codes::count_pending(conn, user)?))
        .await
        .expect("a count")
}

async fn last_login_set(app: &TestApp) -> i64 {
    count(
        app,
        "SELECT COUNT(*) FROM users WHERE last_login_at IS NOT NULL",
    )
    .await
}

/// Sends a request to a router of our own (a state the test changed), as the
/// harness sends it to its own.
async fn call_router(router: axum::Router, req: Req) -> Res {
    let mut request = req.build();
    request
        .headers_mut()
        .insert(header::HOST, HeaderValue::from_static(Which::Vault.host()));
    let peer: std::net::SocketAddr = PEER.parse().expect("a peer");
    request.extensions_mut().insert(ConnectInfo(peer));
    let response = router.oneshot(request).await.expect("a response");
    let (parts, body) = response.into_parts();
    let body = to_bytes(body, 1024 * 1024).await.expect("a body");
    Res {
        status: parts.status,
        headers: parts.headers,
        body: body.to_vec(),
    }
}

/// A new master password for `client`, through the route.
async fn change_password(app: &TestApp, jar: &Jar, client: &mut Client) {
    let change = password_change(app, jar, client, NEW_PASSWORD).await;
    let res = put_password(app, jar, client, &change).await;
    assert_eq!(res.status, StatusCode::OK, "{}", res.text());
    client.took_password(&change, NEW_PASSWORD);
}

// -------------------------------------------------------------- the sign-in

#[tokio::test]
async fn device_login_returns_tokens_and_a_server_device_id_and_sets_no_cookie() {
    let app = device_app().await;
    let client = client_account(&app, 1).await;
    let t0 = now(&app);
    let mut device = DeviceClient::new(1);
    let res = device.sign_in(&app, &email(1), CLIENT_PASSWORD).await;
    assert_eq!(res.status, StatusCode::OK, "{}", res.text());
    assert!(res.set_cookies().is_empty(), "{:?}", res.set_cookies());
    assert_eq!(res.header("content-type"), "application/json");

    // The answer is the strict wire shape, and nothing else.
    let body: DeviceLoginFinishRes = serde_json::from_slice(&res.body).expect("the device answer");
    assert_eq!(&body.account_id, client.ids.account_id.as_bytes());
    assert_eq!(&body.vault_id, client.ids.vault_id.as_bytes());
    assert_eq!(body.vk_epoch, 1);
    assert_eq!(body.token_type, TokenTypeJson::DPoP);
    assert_eq!(body.expires_in, 900);
    let keys: Vec<String> = res
        .json()
        .as_object()
        .expect("an object")
        .keys()
        .cloned()
        .collect();
    assert_eq!(
        keys,
        [
            "access_token",
            "account_id",
            "device_id",
            "expires_in",
            "refresh_token",
            "token_type",
            "vault_id",
            "vk_epoch"
        ]
    );
    let access = device.access.as_ref().expect("an access token");
    let refresh = device.refresh.as_ref().expect("a refresh token");
    assert_ne!(access.hash(), refresh.hash());

    // One device row, with the id the server gave, bound to the proof's key.
    let rows = device_rows(&app).await;
    assert_eq!(
        rows,
        [DeviceRow {
            id: body.device_id.to_vec(),
            user_id: client.ids.user_id,
            jkt: device.key.jkt().to_vec(),
            name: DEVICE_NAME.to_string(),
            platform: "windows".to_string(),
            session_version: support::session::session_version(&app, client.ids.user_id).await,
            created_at: t0,
            last_seen: t0,
            revoked_at: None,
        }]
    );
    assert_eq!(token_rows(&app).await, (1, 1));
    // No session, no cookie: the device is not a browser.
    assert_eq!(count(&app, "SELECT COUNT(*) FROM ferret_sessions").await, 0);
    assert_eq!(last_login_set(&app).await, 1);
    // The proof's `jti` is recorded, now that its key is bound.
    assert_eq!(replay_len(&app), 1);
    match lookup(&app, access, t0).await {
        AccessLookup::Live(row) => {
            assert_eq!(row.device, DeviceId(body.device_id));
            assert_eq!(row.user_id, client.ids.user_id);
        }
        other => panic!("not live: {other:?}"),
    }
    assert!(valid(&app, body.device_id, t0).await);

    // A second sign-in with a new key is a second device with another id.
    let other = signed_in(&app, 1, 2).await;
    assert_ne!(other.device_id, device.device_id);
    assert_eq!(device_count(&app).await, 2);
}

#[tokio::test]
async fn device_login_without_a_valid_proof_is_the_single_auth_failure() {
    let throttle = Arc::new(RecordingThrottle::new());
    let app = device_app_builder()
        .throttle(throttle.clone() as Arc<dyn Throttle>)
        .build()
        .await;
    client_account(&app, 1).await;
    let disabled = client_account(&app, 2).await;
    exec(
        &app,
        "UPDATE users SET active = 0 WHERE id = ?1",
        disabled.ids.user_id,
    )
    .await;
    let key = DeviceKey::new(1);
    let other = DeviceKey::new(2);
    let at = now(&app);
    let htu = format!("{VAULT_URL}{LOGIN_FINISH}");
    let token = TokenSecret::from_wire(&"A".repeat(43)).expect("a token");
    let bad_proofs: Vec<(&str, Option<String>)> = vec![
        ("no proof", None),
        ("junk", Some("a.b.c".to_string())),
        (
            "another host",
            Some(key.proof(
                "POST",
                "https://elsewhere.test/api/auth/opaque/login/finish",
                at,
                None,
            )),
        ),
        ("another method", Some(key.proof("GET", &htu, at, None))),
        ("too old", Some(key.proof("POST", &htu, at - 61, None))),
        (
            "from the future",
            Some(key.proof("POST", &htu, at + 61, None)),
        ),
        ("with ath", Some(key.proof("POST", &htu, at, Some(&token)))),
        (
            "signed by another key",
            Some(other.sign(&key.header(), &claims("POST", &htu, at, &fresh_jti(), None))),
        ),
    ];

    let accounts = [email(1), "nobody@example.com".to_string(), email(2)];
    let mut halves: Vec<HalfWay> = Vec::new();
    for account in &accounts {
        halves.push(login_start(&app, account, CLIENT_PASSWORD).await);
    }
    assert!(halves[0].opened);
    throttle.clear();

    let mut first: Option<Seen> = None;
    for (half, account) in halves.iter().zip(&accounts) {
        for (what, proof) in &bad_proofs {
            let res = app
                .call_raw(
                    Which::Vault,
                    finish_req(&device_body(half), proof.as_deref()).build(),
                )
                .await;
            assert_eq!(
                status_and_code(&res),
                (401, "dpop_invalid".to_string()),
                "{account}, {what}"
            );
            let answer = seen(&res);
            match &first {
                None => first = Some(answer),
                Some(first) => assert_eq!(&answer, first, "{account}, {what}"),
            }
        }
    }
    // The library was never called: no throttle entry, no account read, no
    // state taken, no `jti` recorded, nothing written.
    assert!(throttle.calls().is_empty(), "{:?}", throttle.calls());
    assert_eq!(replay_len(&app), 0);
    assert_eq!(device_count(&app).await, 0);

    // The sign-in states are still there: with a good proof the known account
    // signs in, and the other two get the one answer of a failed sign-in.
    let mut device = DeviceClient::new(1);
    let res = device.finish(&app, &device_body(&halves[0])).await;
    assert_eq!(res.status, StatusCode::OK, "{}", res.text());
    let finishes = throttle
        .calls()
        .into_iter()
        .filter(|c| {
            matches!(
                c,
                ThrottleCall::Admit {
                    stage: Stage::LoginFinish,
                    ..
                }
            )
        })
        .count();
    assert_eq!(finishes, 1);
    for (n, half) in halves.iter().enumerate().skip(1) {
        let mut device = DeviceClient::new(10 + u8::try_from(n).expect("small"));
        let res = device.finish(&app, &device_body(half)).await;
        assert_eq!(status_and_code(&res), (401, "denied".to_string()));
    }
    // A failed sign-in binds no key, so it records no `jti`.
    assert_eq!(replay_len(&app), 1);
    assert_eq!(device_count(&app).await, 1);
}

#[tokio::test]
async fn a_wrong_password_records_no_jti_and_writes_nothing() {
    let app = device_app().await;
    let client = client_account(&app, 1).await;
    let mut device = DeviceClient::new(1);
    let res = device.sign_in(&app, &email(1), WRONG_PASSWORD).await;
    assert_eq!(status_and_code(&res), (401, "denied".to_string()));
    assert_eq!(replay_len(&app), 0);
    assert_eq!(device_count(&app).await, 0);
    assert_eq!(token_rows(&app).await, (0, 0));
    assert_eq!(last_login_set(&app).await, 0);
    assert!(device.access.is_none());
    // The same key signs in afterwards: nothing of it was kept.
    let res = device.sign_in(&app, &email(1), CLIENT_PASSWORD).await;
    assert_eq!(res.status, StatusCode::OK, "{}", res.text());
    assert_eq!(device_rows(&app).await[0].user_id, client.ids.user_id);
}

#[tokio::test]
async fn the_21st_device_is_refused_with_quota_exceeded() {
    let app = device_app().await;
    let client = client_account(&app, 1).await;
    client_account(&app, 2).await;
    // Another account's devices count for that account only.
    signed_in(&app, 2, 100).await;

    let mut devices = Vec::new();
    for key in 1..=u8::try_from(MAX_DEVICES).expect("small") {
        devices.push(signed_in(&app, 1, key).await);
    }
    let before = replay_len(&app);
    let mut extra = DeviceClient::new(21);
    let res = extra.sign_in(&app, &email(1), CLIENT_PASSWORD).await;
    assert_eq!(status_and_code(&res), (413, "quota_exceeded".to_string()));
    assert_eq!(device_count(&app).await, 21);
    assert_eq!(replay_len(&app), before, "a refused key records nothing");

    // A revoked device does not count.
    let first = devices[0].device_id.expect("an id");
    assert!(revoke_device(&app, client.ids.user_id, first, now(&app)).await);
    let res = extra.sign_in(&app, &email(1), CLIENT_PASSWORD).await;
    assert_eq!(res.status, StatusCode::OK, "{}", res.text());
    let res = DeviceClient::new(22)
        .sign_in(&app, &email(1), CLIENT_PASSWORD)
        .await;
    assert_eq!(status_and_code(&res), (413, "quota_exceeded".to_string()));

    // Nor does a device that signed in ninety days ago or more: no token of
    // its sign-in lives that long, and `still_valid` refuses it.
    let second = devices[1].device_id.expect("an id");
    let aged = now(&app) - ABSOLUTE_SECS;
    app.state
        .vault_db
        .with_conn(move |conn| {
            conn.execute(
                "UPDATE ferret_devices SET created_at = ?2, last_seen = ?2 WHERE device_id = ?1",
                rusqlite::params![second.as_slice(), aged],
            )?;
            Ok(())
        })
        .await
        .expect("an aged device");
    assert!(!valid(&app, second, now(&app)).await);
    assert!(valid(&app, second, now(&app) - 1).await, "a second younger");
    let res = DeviceClient::new(22)
        .sign_in(&app, &email(1), CLIENT_PASSWORD)
        .await;
    assert_eq!(res.status, StatusCode::OK, "{}", res.text());
    let res = DeviceClient::new(23)
        .sign_in(&app, &email(1), CLIENT_PASSWORD)
        .await;
    assert_eq!(status_and_code(&res), (413, "quota_exceeded".to_string()));

    // Nor does a device of an older `session_version` (signed out
    // everywhere), which can never be used again.
    exec(
        &app,
        "UPDATE users SET session_version = session_version + 1 WHERE id = ?1",
        client.ids.user_id,
    )
    .await;
    let res = DeviceClient::new(23)
        .sign_in(&app, &email(1), CLIENT_PASSWORD)
        .await;
    assert_eq!(res.status, StatusCode::OK, "{}", res.text());
}

#[tokio::test]
async fn cookie_login_is_unchanged() {
    let app = device_app().await;
    let client = client_account(&app, 1).await;
    let half = login_start(&app, &email(1), CLIENT_PASSWORD).await;
    let res = app
        .call_raw(
            Which::Vault,
            Req::post(LOGIN_FINISH)
                .page_fetch(Which::Vault)
                .header("x-forwarded-proto", "https")
                .json(&json!({
                    "login_id": half.login_id,
                    "ke3": b64url::encode(&half.ke3),
                    "device_id": "07".repeat(16),
                    "device_name": "Test browser",
                }))
                .build(),
        )
        .await;
    assert_eq!(res.status, StatusCode::OK, "{}", res.text());
    let mut jar = Jar::default();
    jar.absorb(&res.headers);
    assert!(
        jar.names().contains(&"__Host-ferret_sid".to_string()),
        "{:?}",
        jar.names()
    );
    assert_eq!(res.header("cache-control"), "no-store");
    assert_eq!(res.header("date"), "", "the cookie answer is as it was");
    assert_eq!(
        res.json(),
        json!({
            "account_id": support::session::hex(client.ids.account_id.as_bytes()),
            "vault_id": support::session::hex(client.ids.vault_id.as_bytes()),
            "vk_epoch": 1,
        })
    );
    assert_eq!(count(&app, "SELECT COUNT(*) FROM ferret_sessions").await, 1);
    assert_eq!(device_count(&app).await, 0);
    assert_eq!(token_rows(&app).await, (0, 0));

    // A malformed cookie body keeps the code of its field.
    let half = login_start(&app, &email(1), CLIENT_PASSWORD).await;
    let res = app
        .call_raw(
            Which::Vault,
            Req::post(LOGIN_FINISH)
                .page_fetch(Which::Vault)
                .header("x-forwarded-proto", "https")
                .json(&json!({
                    "login_id": half.login_id,
                    "ke3": b64url::encode(&half.ke3[..63]),
                    "device_id": "07".repeat(16),
                }))
                .build(),
        )
        .await;
    assert_eq!(status_and_code(&res), (400, "malformed_ke3".to_string()));
}

#[tokio::test]
async fn a_device_key_already_on_a_device_row_is_refused() {
    let app = device_app().await;
    let client = client_account(&app, 1).await;
    client_account(&app, 2).await;
    let mut device = signed_in(&app, 1, 1).await;
    assert_eq!(replay_len(&app), 1);

    // The same key again, for the same account or another: refused, and the
    // second proof is not recorded.
    for n in [1, 2] {
        let res = device.sign_in(&app, &email(n), CLIENT_PASSWORD).await;
        assert_eq!(status_and_code(&res), (400, "bad_request".to_string()));
    }
    assert_eq!(device_count(&app).await, 1);
    assert_eq!(token_rows(&app).await, (1, 1));
    assert_eq!(replay_len(&app), 1);

    // A revoked device keeps its row, and its key stays refused.
    let id = device.device_id.expect("an id");
    assert!(revoke_device(&app, client.ids.user_id, id, now(&app)).await);
    let res = device.sign_in(&app, &email(1), CLIENT_PASSWORD).await;
    assert_eq!(status_and_code(&res), (400, "bad_request".to_string()));
    assert_eq!(device_count(&app).await, 1);
}

#[tokio::test]
async fn device_login_revokes_pending_sign_in_codes() {
    let app = device_app().await;
    let alice = client_account(&app, 1).await;
    let bob = client_account(&app, 2).await;
    code_for(&app, alice.ids.user_id, 1).await;
    code_for(&app, bob.ids.user_id, 2).await;

    // A failed sign-in and a refused proof leave the code alone.
    let mut device = DeviceClient::new(1);
    let res = device.sign_in(&app, &email(1), WRONG_PASSWORD).await;
    assert_eq!(res.status, StatusCode::UNAUTHORIZED);
    let half = login_start(&app, &email(1), CLIENT_PASSWORD).await;
    let res = app
        .call_raw(Which::Vault, finish_req(&device_body(&half), None).build())
        .await;
    assert_eq!(status_and_code(&res), (401, "dpop_invalid".to_string()));
    assert_eq!(pending_codes(&app, alice.ids.user_id).await, 1);

    // A device sign-in proves the password: the user's codes go, and only
    // the user's.
    let res = device.finish(&app, &device_body(&half)).await;
    assert_eq!(res.status, StatusCode::OK, "{}", res.text());
    assert_eq!(pending_codes(&app, alice.ids.user_id).await, 0);
    assert_eq!(pending_codes(&app, bob.ids.user_id).await, 1);
}

#[tokio::test]
async fn device_login_for_a_user_with_a_second_factor_is_403() {
    let app = device_app().await;
    let client = client_account(&app, 1).await;
    exec(
        &app,
        "UPDATE users SET totp_enabled = 1 WHERE id = ?1",
        client.ids.user_id,
    )
    .await;
    code_for(&app, client.ids.user_id, 1).await;
    let mut device = DeviceClient::new(1);
    let res = device.sign_in(&app, &email(1), CLIENT_PASSWORD).await;
    assert_eq!(status_and_code(&res), (403, "forbidden".to_string()));
    assert!(res.set_cookies().is_empty());
    assert_eq!(device_count(&app).await, 0);
    assert_eq!(token_rows(&app).await, (0, 0));
    assert_eq!(replay_len(&app), 0);
    assert_eq!(last_login_set(&app).await, 0);
    assert_eq!(pending_codes(&app, client.ids.user_id).await, 1);

    // The 403 comes only after the proof: a wrong password is the ordinary
    // 401 and says nothing of the second factor.
    let res = DeviceClient::new(2)
        .sign_in(&app, &email(1), WRONG_PASSWORD)
        .await;
    assert_eq!(status_and_code(&res), (401, "denied".to_string()));
}

#[tokio::test]
async fn a_device_body_with_purpose_reauth_is_400() {
    let app = device_app().await;
    client_account(&app, 1).await;
    let half = login_start(&app, &email(1), CLIENT_PASSWORD).await;
    let mut device = DeviceClient::new(1);
    for (field, value) in [
        ("purpose", json!("reauth")),
        ("purpose", json!("login")),
        ("device_id", json!("07".repeat(16))),
        ("device_jwk", device.key.jwk()),
    ] {
        let mut body = device_body(&half);
        body[field] = value;
        let res = device.finish(&app, &body).await;
        assert_eq!(
            status_and_code(&res),
            (400, "bad_request".to_string()),
            "{field}"
        );
    }
    // The body is refused before the proof and the sign-in state.
    assert_eq!(replay_len(&app), 0);
    let res = device.finish(&app, &device_body(&half)).await;
    assert_eq!(res.status, StatusCode::OK, "{}", res.text());
}

/// Every file under `dir`, read.
fn files_under(dir: &Path) -> Vec<(String, Vec<u8>)> {
    let mut out = Vec::new();
    for entry in std::fs::read_dir(dir).expect("a directory") {
        let path = entry.expect("an entry").path();
        if path.is_dir() {
            out.extend(files_under(&path));
        } else if let Ok(bytes) = std::fs::read(&path) {
            out.push((path.display().to_string(), bytes));
        }
    }
    out
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack.windows(needle.len()).any(|w| w == needle)
}

#[tokio::test]
async fn tokens_are_stored_only_as_hashes() {
    let app = device_app().await;
    client_account(&app, 1).await;
    let t0 = now(&app);
    let device = signed_in(&app, 1, 1).await;
    let access = device.access.as_ref().expect("an access token");
    let refresh = device.refresh.as_ref().expect("a refresh token");
    let id = device.device_id.expect("an id").to_vec();

    let (access_hash, refresh_hash) = (access.hash(), refresh.hash());
    let (access_row, refresh_row) = app
        .state
        .vault_db
        .with_conn(|conn| {
            let access: (Vec<u8>, Vec<u8>, i64) = conn.query_row(
                "SELECT token_hash, device_id, expires_at FROM ferret_access",
                [],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )?;
            type RefreshRow = (
                Vec<u8>,
                Vec<u8>,
                Option<Vec<u8>>,
                i64,
                i64,
                i64,
                Option<i64>,
            );
            let refresh: RefreshRow = conn.query_row(
                "SELECT token_hash, device_id, prev_hash, issued_at, idle_expires_at,
                        abs_expires_at, used_at FROM ferret_refresh",
                [],
                |r| {
                    Ok((
                        r.get(0)?,
                        r.get(1)?,
                        r.get(2)?,
                        r.get(3)?,
                        r.get(4)?,
                        r.get(5)?,
                        r.get(6)?,
                    ))
                },
            )?;
            Ok((access, refresh))
        })
        .await
        .expect("the token rows");
    assert_eq!(access_row, (access_hash.0.to_vec(), id.clone(), t0 + 900));
    assert_eq!(
        refresh_row,
        (
            refresh_hash.0.to_vec(),
            id,
            None,
            t0,
            t0 + IDLE_SECS,
            t0 + ABSOLUTE_SECS,
            None
        )
    );

    // Neither token, as bytes or as text, is anywhere in the data directory:
    // the database, its journal, the state store.
    let mut secrets: Vec<Vec<u8>> = Vec::new();
    for token in [access, refresh] {
        let text = token.to_wire();
        secrets.push(b64url::decode(&text).expect("base64url"));
        secrets.push(text.into_bytes());
    }
    let files = files_under(&app.dir);
    assert!(!files.is_empty());
    for (name, bytes) in &files {
        for secret in &secrets {
            assert!(!contains(bytes, secret), "a token in {name}");
        }
    }
}

#[tokio::test]
async fn the_answer_has_no_store_and_a_date_header() {
    let app = device_app().await;
    client_account(&app, 1).await;
    assert_eq!(START, 1_793_491_200);
    let mut device = DeviceClient::new(1);
    let res = device.sign_in(&app, &email(1), CLIENT_PASSWORD).await;
    assert_eq!(res.status, StatusCode::OK, "{}", res.text());
    assert_eq!(res.header("cache-control"), "no-store");
    assert_eq!(res.header("date"), "Sun, 01 Nov 2026 00:00:00 GMT");
    assert_eq!(res.headers.get_all("date").iter().count(), 1);

    // A refused proof says the server's time too, so the client can sync to
    // it; the date follows the server's clock.
    app.clock.advance(3_661);
    let half = login_start(&app, &email(1), CLIENT_PASSWORD).await;
    let res = app
        .call_raw(Which::Vault, finish_req(&device_body(&half), None).build())
        .await;
    assert_eq!(status_and_code(&res), (401, "dpop_invalid".to_string()));
    assert_eq!(res.header("cache-control"), "no-store");
    assert_eq!(res.header("date"), "Sun, 01 Nov 2026 01:01:01 GMT");

    // And so does every other answer of the device sign-in.
    let res = device.finish(&app, &device_body(&half)).await;
    assert_eq!(status_and_code(&res), (400, "bad_request".to_string()));
    assert_eq!(res.header("cache-control"), "no-store");
    assert_eq!(res.header("date"), "Sun, 01 Nov 2026 01:01:01 GMT");
}

#[tokio::test]
async fn device_name_and_platform_are_required_and_bounded() {
    let app = device_app().await;
    client_account(&app, 1).await;
    let half = login_start(&app, &email(1), CLIENT_PASSWORD).await;
    let mut device = DeviceClient::new(1);
    let four_bytes = "\u{1F98A}";
    let refused: Vec<(&str, Option<Value>)> = vec![
        ("device_name", None),
        ("device_name", Some(json!(""))),
        ("device_name", Some(json!(null))),
        ("device_name", Some(json!("a".repeat(65)))),
        ("device_name", Some(json!(four_bytes.repeat(65)))),
        ("device_name", Some(json!("bell\u{7}"))),
        ("device_name", Some(json!("right\u{202e}left"))),
        ("device_name", Some(json!(7))),
        ("platform", None),
        ("platform", Some(json!(null))),
        ("platform", Some(json!("beos"))),
        ("platform", Some(json!("Windows"))),
        ("platform", Some(json!(""))),
        ("client", Some(json!("browser"))),
        ("client", Some(json!(null))),
    ];
    for (field, value) in refused {
        let mut body = device_body(&half);
        match &value {
            Some(value) => body[field] = value.clone(),
            None => {
                body.as_object_mut().expect("an object").remove(field);
            }
        }
        let res = device.finish(&app, &body).await;
        assert_eq!(res.status, StatusCode::BAD_REQUEST, "{field} = {value:?}");
    }
    assert_eq!(device_count(&app).await, 0);

    // Sixty-four characters of four bytes each are a good name.
    let name = four_bytes.repeat(64);
    let mut body = device_body(&half);
    body["device_name"] = json!(name);
    body["platform"] = json!("linux");
    let res = device.finish(&app, &body).await;
    assert_eq!(res.status, StatusCode::OK, "{}", res.text());
    let rows = device_rows(&app).await;
    assert_eq!(
        (rows[0].name.as_str(), rows[0].platform.as_str()),
        (name.as_str(), "linux")
    );
}

// ---------------------------------------------------------------- the rows

#[tokio::test]
async fn the_access_token_lives_900_seconds_and_lookup_says_expired_after() {
    let app = device_app().await;
    let client = client_account(&app, 1).await;
    let t0 = now(&app);
    let device = signed_in(&app, 1, 1).await;
    let access = device.access.as_ref().expect("an access token");
    for at in [t0, t0 + 1, t0 + 899] {
        match lookup(&app, access, at).await {
            AccessLookup::Live(row) => {
                assert_eq!(row.device, DeviceId(device.device_id.expect("an id")));
                assert_eq!(row.user_id, client.ids.user_id);
                assert_eq!(row.jkt, device.key.jkt());
                assert_eq!(row.expires_at, t0 + 900);
                assert_eq!(
                    row.session_version,
                    support::session::session_version(&app, client.ids.user_id).await
                );
            }
            other => panic!("not live at {at}: {other:?}"),
        }
    }
    for at in [t0 + 900, t0 + 901, t0 + 86_400] {
        assert_eq!(
            lookup(&app, access, at).await,
            AccessLookup::Expired,
            "{at}"
        );
    }
    // A token nobody issued, and the refresh token, are no access tokens.
    let unknown = TokenSecret::random(&mut ferret_core::TestRng::new(b"a token nobody issued"));
    assert_eq!(lookup(&app, &unknown, t0).await, AccessLookup::Expired);
    let refresh = device.refresh.as_ref().expect("a refresh token");
    assert_eq!(lookup(&app, refresh, t0).await, AccessLookup::Expired);
}

#[tokio::test]
async fn a_disabled_user_or_a_raised_session_version_makes_the_device_invalid() {
    let app = device_app().await;
    let client = client_account(&app, 1).await;
    let t0 = now(&app);
    let device = signed_in(&app, 1, 1).await;
    let id = device.device_id.expect("an id");
    assert!(valid(&app, id, t0).await);
    // No sign-in's tokens live past ninety days.
    assert!(valid(&app, id, t0 + ABSOLUTE_SECS - 1).await);
    assert!(!valid(&app, id, t0 + ABSOLUTE_SECS).await);
    assert!(!valid(&app, [0x5a; 16], t0).await, "an unknown device");

    let user = client.ids.user_id;
    exec(&app, "UPDATE users SET active = 0 WHERE id = ?1", user).await;
    assert!(!valid(&app, id, t0).await);
    exec(&app, "UPDATE users SET active = 1 WHERE id = ?1", user).await;
    assert!(valid(&app, id, t0).await);
    exec(
        &app,
        "UPDATE users SET session_version = session_version + 1 WHERE id = ?1",
        user,
    )
    .await;
    assert!(!valid(&app, id, t0).await);
}

#[tokio::test]
async fn revoke_keeps_the_hashes_and_lookup_says_device_revoked() {
    let app = device_app().await;
    let client = client_account(&app, 1).await;
    let other = client_account(&app, 2).await;
    let t0 = now(&app);
    let gone = signed_in(&app, 1, 1).await;
    let kept = signed_in(&app, 1, 2).await;
    let id = gone.device_id.expect("an id");

    // Only the device's own user revokes it, and only once.
    assert!(!revoke_device(&app, other.ids.user_id, id, t0 + 5).await);
    assert!(revoke_device(&app, client.ids.user_id, id, t0 + 5).await);
    assert!(!revoke_device(&app, client.ids.user_id, id, t0 + 6).await);
    assert!(!revoke_device(&app, client.ids.user_id, [0x5a; 16], t0 + 6).await);

    // The row and the token hashes stay; the tokens answer `device_revoked`,
    // also once the access token would have expired anyway.
    let rows = device_rows(&app).await;
    assert_eq!(rows[0].revoked_at, Some(t0 + 5));
    assert_eq!(rows[1].revoked_at, None);
    assert_eq!(token_rows(&app).await, (2, 2));
    let access = gone.access.as_ref().expect("an access token");
    for at in [t0 + 5, t0 + 900, t0 + 86_400] {
        assert_eq!(
            lookup(&app, access, at).await,
            AccessLookup::DeviceRevoked,
            "{at}"
        );
    }
    assert!(!valid(&app, id, t0 + 5).await);
    // The other device of the account is untouched.
    assert!(matches!(
        lookup(&app, kept.access.as_ref().expect("a token"), t0 + 5).await,
        AccessLookup::Live(_)
    ));
    assert!(valid(&app, kept.device_id.expect("an id"), t0 + 5).await);
}

#[tokio::test]
async fn touch_writes_last_seen_at_most_once_a_minute() {
    let app = device_app().await;
    client_account(&app, 1).await;
    let t0 = now(&app);
    let id = signed_in(&app, 1, 1).await.device_id.expect("an id");
    let seen_at = |at: i64| {
        let db = app.state.vault_db.clone();
        async move {
            db.with_conn(move |conn| {
                touch(conn, &DeviceId(id), at)?;
                Ok(
                    conn.query_row("SELECT last_seen FROM ferret_devices", [], |r| {
                        r.get::<_, i64>(0)
                    })?,
                )
            })
            .await
            .expect("a touch")
        }
    };
    assert_eq!(seen_at(t0 + 30).await, t0);
    assert_eq!(seen_at(t0 + 59).await, t0);
    assert_eq!(seen_at(t0 + 60).await, t0 + 60);
    assert_eq!(seen_at(t0 + 90).await, t0 + 60);
    assert_eq!(seen_at(t0 + 200).await, t0 + 200);
}

// ------------------------------------------------------- the jti of the proof

#[tokio::test]
async fn the_same_login_proof_twice_gives_one_device() {
    let app = device_app().await;
    client_account(&app, 1).await;
    let first = login_start(&app, &email(1), CLIENT_PASSWORD).await;
    let second = login_start(&app, &email(1), CLIENT_PASSWORD).await;
    let device = DeviceClient::new(1);
    let proof = device.login_proof(&app);
    let (a, b) = tokio::join!(
        app.call_raw(
            Which::Vault,
            finish_req(&device_body(&first), Some(&proof)).build()
        ),
        app.call_raw(
            Which::Vault,
            finish_req(&device_body(&second), Some(&proof)).build()
        ),
    );
    let mut answers = [status_and_code(&a), status_and_code(&b)];
    answers.sort();
    assert_eq!(
        answers,
        [(200, String::new()), (400, "bad_request".to_string())]
    );
    assert_eq!(device_count(&app).await, 1);
    assert_eq!(token_rows(&app).await, (1, 1));
    assert_eq!(replay_len(&app), 1);

    // The same proof once more, after both: still one device.
    let third = login_start(&app, &email(1), CLIENT_PASSWORD).await;
    let res = app
        .call_raw(
            Which::Vault,
            finish_req(&device_body(&third), Some(&proof)).build(),
        )
        .await;
    assert_eq!(res.status, StatusCode::BAD_REQUEST);
    assert_eq!(device_count(&app).await, 1);
}

#[tokio::test]
async fn a_full_jti_cache_rolls_the_device_login_back() {
    let app = device_app().await;
    let client = client_account(&app, 1).await;
    code_for(&app, client.ids.user_id, 1).await;

    // The same server with a cache that has no room left.
    let mut state = app.state.clone();
    state.device_auth = state
        .device_auth
        .with_replay(JtiCache::new(0, JTI_PER_KEY, JTI_PER_USER));
    let full = ferret_server::server::vault_router(state);
    let device = DeviceClient::new(1);
    let half = login_start(&app, &email(1), CLIENT_PASSWORD).await;
    let res = call_router(
        full,
        finish_req(&device_body(&half), Some(&device.login_proof(&app))),
    )
    .await;
    assert_eq!(status_and_code(&res), (503, "busy".to_string()));
    assert_eq!(res.header("retry-after"), "30");
    assert_eq!(res.header("cache-control"), "no-store");
    assert!(!res.header("date").is_empty());
    // Everything of the transaction is rolled back.
    assert_eq!(device_count(&app).await, 0);
    assert_eq!(token_rows(&app).await, (0, 0));
    assert_eq!(last_login_set(&app).await, 0);
    assert_eq!(pending_codes(&app, client.ids.user_id).await, 1);

    // An account with too many proofs in the window: 429, and rolled back.
    let mut state = app.state.clone();
    state.device_auth = state
        .device_auth
        .with_replay(JtiCache::new(16, JTI_PER_KEY, 0));
    let busy = ferret_server::server::vault_router(state);
    let half = login_start(&app, &email(1), CLIENT_PASSWORD).await;
    let res = call_router(
        busy,
        finish_req(&device_body(&half), Some(&device.login_proof(&app))),
    )
    .await;
    assert_eq!(status_and_code(&res), (429, "throttled".to_string()));
    assert_eq!(res.header("retry-after"), "60");
    assert_eq!(device_count(&app).await, 0);
    assert_eq!(pending_codes(&app, client.ids.user_id).await, 1);

    // The key was bound to nothing, so with room in the cache it signs in.
    let mut device = device;
    let res = device.sign_in(&app, &email(1), CLIENT_PASSWORD).await;
    assert_eq!(res.status, StatusCode::OK, "{}", res.text());
    assert_eq!(device_count(&app).await, 1);
}

// --------------------------------------------- the binding to the OPAQUE record

#[tokio::test]
async fn a_device_sign_in_begun_before_a_password_change_is_refused_like_a_wrong_password() {
    let app = device_app().await;
    let mut client = client_account(&app, 1).await;
    let this = client_session(&app, &client, SessionScope::Full, 1).await;
    let stale = login_start(&app, &email(1), CLIENT_PASSWORD).await;
    assert!(stale.opened);
    change_password(&app, &this.jar, &mut client).await;

    let mut device = DeviceClient::new(1);
    let refused = device.finish(&app, &device_body(&stale)).await;
    assert_eq!(status_and_code(&refused), (401, "denied".to_string()));
    assert_eq!(device_count(&app).await, 0);
    assert_eq!(replay_len(&app), 0);

    // A wrong password after the change gets the very same answer.
    let wrong = DeviceClient::new(2)
        .sign_in(&app, &email(1), WRONG_PASSWORD)
        .await;
    assert_eq!(seen(&wrong), seen(&refused));

    // The new password, begun after the change, signs in.
    let res = device.sign_in(&app, &email(1), NEW_PASSWORD).await;
    assert_eq!(res.status, StatusCode::OK, "{}", res.text());
}

/// A throttle that, once, holds the record of a successful `login/finish`
/// (the proof was checked against the record) until the test lets it go.
struct HoldFinish(Mutex<Option<(mpsc::Sender<()>, mpsc::Receiver<()>)>>);

impl Throttle for HoldFinish {
    fn admit(&self, _stage: Stage, _keys: &[ThrottleKey], _now: u64) -> Result<(), RetryAfter> {
        Ok(())
    }

    fn record(&self, stage: Stage, _keys: &[ThrottleKey], outcome: Outcome, _now: u64) {
        if stage == Stage::LoginFinish && outcome == Outcome::Success {
            let held = self.0.lock().expect("the channels").take();
            if let Some((entered, go)) = held {
                entered.send(()).expect("the test listens");
                go.recv_timeout(Duration::from_secs(10))
                    .expect("the test lets it go on");
            }
        }
    }
}

#[tokio::test]
async fn a_password_change_that_commits_after_the_proof_still_stops_the_device() {
    let (entered_tx, entered_rx) = mpsc::channel();
    let (go_tx, go_rx) = mpsc::channel();
    let throttle = Arc::new(HoldFinish(Mutex::new(Some((entered_tx, go_rx)))));
    let app = device_app_builder()
        .throttle(throttle as Arc<dyn Throttle>)
        .build()
        .await;
    let mut client = client_account(&app, 1).await;
    let this = client_session(&app, &client, SessionScope::Full, 1).await;
    let stale = login_start(&app, &email(1), CLIENT_PASSWORD).await;
    let mut device = DeviceClient::new(1);
    let body = device_body(&stale);

    // The proof is checked against the old record, which is still the
    // account's; the new password commits before the device is written.
    let (res, ()) = tokio::join!(device.finish(&app, &body), async {
        tokio::task::spawn_blocking(move || entered_rx.recv())
            .await
            .expect("a thread")
            .expect("the proof was checked");
        change_password(&app, &this.jar, &mut client).await;
        go_tx.send(()).expect("the sign-in waits");
    });
    assert_eq!(status_and_code(&res), (401, "denied".to_string()));
    assert_eq!(device_count(&app).await, 0);
    assert_eq!(token_rows(&app).await, (0, 0));
    assert_eq!(replay_len(&app), 0);
}

#[tokio::test]
async fn the_proof_names_the_configured_origin_whatever_the_host_header_says() {
    let app = device_app().await;
    client_account(&app, 1).await;
    let mut device = DeviceClient::new(1);
    let half = login_start(&app, &email(1), CLIENT_PASSWORD).await;
    let send = |proof: String| {
        let req = finish_req(&device_body(&half), Some(&proof))
            .header("host", "elsewhere.test")
            .header("x-forwarded-host", "elsewhere.test");
        app.call_raw(Which::Vault, req.build())
    };
    // A proof for the host the request names is not one for this server.
    let res = send(device.key.proof(
        "POST",
        "https://elsewhere.test/api/auth/opaque/login/finish",
        now(&app),
        None,
    ))
    .await;
    assert_eq!(status_and_code(&res), (401, "dpop_invalid".to_string()));
    // A proof for the configured origin is, whatever the headers say.
    let res = send(device.login_proof(&app)).await;
    assert_eq!(res.status, StatusCode::OK, "{}", res.text());
    device.keep(&res);
    assert!(device.access.is_some());
}

// ------------------------------------------------------- who may call what

/// The source files of the server.
fn server_sources(dir: &Path, out: &mut Vec<std::path::PathBuf>) {
    for entry in std::fs::read_dir(dir).expect("a directory") {
        let path = entry.expect("an entry").path();
        if path.is_dir() {
            server_sources(&path, out);
        } else if path.extension().is_some_and(|e| e == "rs") {
            out.push(path);
        }
    }
}

/// How often `text` names the identifier `name` in code (not in comments).
fn named_in_code(text: &str, name: &str) -> usize {
    let is_ident = |c: char| c.is_alphanumeric() || c == '_';
    text.lines()
        .map(|line| {
            let code = line.split("//").next().unwrap_or("");
            code.match_indices(name)
                .filter(|(at, _)| {
                    let before = code[..*at].chars().last();
                    let after = code[at + name.len()..].chars().next();
                    !before.is_some_and(is_ident) && !after.is_some_and(is_ident)
                })
                .count()
        })
        .sum()
}

#[test]
fn only_the_two_sign_ins_finish_a_login_and_no_route_swaps_the_jti_cache() {
    // `finish_blocking` gives a proof checked against a record that may be
    // replaced before the credential is written: only the two sign-ins call
    // it, and both check the record again in their write transaction
    // (`record_is_current`). `with_replay` gives a handle with a cache of its
    // own: only tests use it; the server has one cache.
    let src = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut files = Vec::new();
    server_sources(&src, &mut files);
    assert!(files.len() > 40, "the sources were found");
    let finishers = [src.join("auth/login.rs"), src.join("auth/device_login.rs")];
    let tokens = src.join("auth/tokens.rs");
    let mut problems = Vec::new();
    for file in &files {
        let text = std::fs::read_to_string(file).expect("a source file");
        if !finishers.contains(file) && named_in_code(&text, "finish_blocking") > 0 {
            problems.push(format!("{}: finish_blocking", file.display()));
        }
        let allowed = usize::from(*file == tokens);
        if named_in_code(&text, "with_replay") > allowed {
            problems.push(format!("{}: with_replay", file.display()));
        }
    }
    assert!(
        problems.is_empty(),
        "{}",
        problems.join(
            "
"
        )
    );
    for file in &finishers {
        let text = std::fs::read_to_string(file).expect("a source file");
        assert!(named_in_code(&text, "finish_blocking") > 0);
        assert!(
            named_in_code(&text, "record_is_current") > 0,
            "{}",
            file.display()
        );
    }

    // The rule catches what it is for, and not prose or longer names.
    for planted in [
        "fn f() { let v = finish_blocking(&s, c, &l, &k, None); }",
        "use crate::auth::login::{finish_blocking, no_store};",
        "fn f() { crate::auth::login::finish_blocking(s, c, l, k, None) }",
    ] {
        assert_eq!(named_in_code(planted, "finish_blocking"), 1, "{planted}");
    }
    for planted in [
        "let auth = state.device_auth.with_replay(JtiCache::new(1, 1, 1));",
        "fn f(a: &DeviceAuth) -> DeviceAuth { DeviceAuth::with_replay(a, c) }",
    ] {
        assert_eq!(named_in_code(planted, "with_replay"), 1, "{planted}");
    }
    for clean in [
        "// finish_blocking is called by the two sign-ins only",
        "fn finish_blocking_later() {}",
        "let with_replay_cache = 1;",
        "/// with_replay is for tests",
    ] {
        assert_eq!(named_in_code(clean, "finish_blocking"), 0, "{clean}");
        assert_eq!(named_in_code(clean, "with_replay"), 0, "{clean}");
    }
}
