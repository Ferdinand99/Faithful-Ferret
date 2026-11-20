//! Renewing and revoking a device's tokens: `POST /api/auth/token/refresh`
//! rotates the refresh token with a grace period for a lost answer and
//! revokes the device on reuse or with a proof of another key;
//! `POST /api/auth/token/revoke` signs a device out; the purge removes old
//! rows and ends dead devices. Driven through the real router, with devices
//! that signed in with the real OPAQUE client and proofs of test keys.
//!
//! Spec: Fase 1 § 7.6; RFC 9449 § 4, § 5, § 11.1.

mod support;

use axum::body::{Body, to_bytes};
use axum::extract::ConnectInfo;
use axum::http::{HeaderValue, StatusCode, header};
use axum::response::Response;
use ferret_core::TestRng;
use ferret_server::auth::devices::{REVOKED_KEEP_SECS, revoke};
use ferret_server::auth::refresh::{
    ABSOLUTE_SECS, GRACE_CAPACITY, GRACE_SECS, IDLE_SECS, MAX_BODY_BYTES, Purged, USED_KEEP_SECS,
    purge_once,
};
use ferret_server::auth::tokens::{AccessLookup, DeviceAuth, lookup_access, with_server_date};
use ferret_server::ids::{DeviceId, TokenHash, TokenSecret};
use ferret_server::vault::notify::Revoked;
use ferret_server::wire::{TokenRes, TokenTypeJson};
use serde_json::json;
use support::accounts::{CLIENT_PASSWORD, client_account};
use support::backup::capture_log;
use support::device::{DeviceClient, device_app, now};
use support::dpop::DeviceKey;
use support::{PEER, Req, Res, START, TestApp, VAULT_URL, Which};
use tower::ServiceExt as _;

const REFRESH: &str = "/api/auth/token/refresh";
const REVOKE: &str = "/api/auth/token/revoke";

// ------------------------------------------------------------------ helpers

fn email(n: u8) -> String {
    format!("client{n}@example.com")
}

fn error_code(res: &Res) -> String {
    res.json()["error"].as_str().unwrap_or("").to_string()
}

fn status_and_code(res: &Res) -> (u16, String) {
    let code = if res.body.is_empty() {
        String::new()
    } else {
        error_code(res)
    };
    (res.status.as_u16(), code)
}

fn refused(status: u16, code: &str) -> (u16, String) {
    (status, code.to_string())
}

/// A copy of a token (the tests hold several handles of one).
fn copy(token: &TokenSecret) -> TokenSecret {
    TokenSecret::from_wire(&token.to_wire()).expect("a token")
}

/// A signed-in device of account `n`, with key `key`.
async fn signed_in(app: &TestApp, n: u8, key: u8) -> DeviceClient {
    let mut device = DeviceClient::new(key);
    let res = device.sign_in(app, &email(n), CLIENT_PASSWORD).await;
    assert_eq!(res.status, StatusCode::OK, "{}", res.text());
    device
}

fn refresh_token(device: &DeviceClient) -> TokenSecret {
    copy(device.refresh.as_ref().expect("signed in"))
}

fn device_id(device: &DeviceClient) -> [u8; 16] {
    device.device_id.expect("signed in")
}

/// A request to `path` with the refresh token `token`, and `proof` in the
/// `DPoP` header when there is one, as a device client sends it.
fn token_body_req(path: &str, token: &str, proof: Option<&str>) -> Req {
    let mut req = Req::post(path)
        .header("ferret-protocol", "1")
        .header("x-forwarded-proto", "https");
    if let Some(proof) = proof {
        req = req.header("dpop", proof);
    }
    req.json(&json!({ "refresh_token": token }))
}

/// A good proof of `device` for a `POST` to `path`, without `ath`.
fn proof_for(app: &TestApp, device: &DeviceClient, path: &str) -> String {
    device.proof(app, "POST", path, None)
}

/// A proof of the test key `n` (bound to nothing, or to another device) for
/// a `POST` to `path`.
fn proof_of_key(app: &TestApp, n: u8, path: &str) -> String {
    DeviceKey::new(n).proof("POST", &format!("{VAULT_URL}{path}"), now(app), None)
}

/// `POST /api/auth/token/refresh` with `token` and `proof`.
async fn refresh_with(app: &TestApp, token: &TokenSecret, proof: Option<&str>) -> Res {
    app.call_raw(
        Which::Vault,
        token_body_req(REFRESH, &token.to_wire(), proof).build(),
    )
    .await
}

/// A renewal of `token` with a good proof of `device`.
async fn refresh(app: &TestApp, device: &DeviceClient, token: &TokenSecret) -> Res {
    let proof = proof_for(app, device, REFRESH);
    refresh_with(app, token, Some(&proof)).await
}

/// `POST /api/auth/token/revoke` with `token` and `proof`.
async fn revoke_with(app: &TestApp, token: &TokenSecret, proof: Option<&str>) -> Res {
    app.call_raw(
        Which::Vault,
        token_body_req(REVOKE, &token.to_wire(), proof).build(),
    )
    .await
}

/// The access token and the refresh token of a `200`.
fn tokens_of(res: &Res) -> (TokenSecret, TokenSecret) {
    assert_eq!(res.status, StatusCode::OK, "{}", res.text());
    let body = res.json();
    let token = |name: &str| {
        TokenSecret::from_wire(body[name].as_str().expect("a token")).expect("a token")
    };
    (token("access_token"), token("refresh_token"))
}

/// The renewal of `token` succeeds; its new tokens.
async fn renewed(
    app: &TestApp,
    device: &DeviceClient,
    token: &TokenSecret,
) -> (TokenSecret, TokenSecret) {
    tokens_of(&refresh(app, device, token).await)
}

async fn count(app: &TestApp, sql: &'static str) -> i64 {
    app.state
        .vault_db
        .with_conn(move |conn| Ok(conn.query_row(sql, [], |r| r.get(0))?))
        .await
        .expect("a count")
}

/// The number of access rows, refresh rows and device rows.
async fn rows(app: &TestApp) -> (i64, i64, i64) {
    (
        count(app, "SELECT COUNT(*) FROM ferret_access").await,
        count(app, "SELECT COUNT(*) FROM ferret_refresh").await,
        count(app, "SELECT COUNT(*) FROM ferret_devices").await,
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

/// A refresh row as the database holds it.
#[derive(Debug, PartialEq, Eq)]
struct RefreshRow {
    device: Vec<u8>,
    prev_hash: Option<Vec<u8>>,
    issued_at: i64,
    idle_expires_at: i64,
    abs_expires_at: i64,
    used_at: Option<i64>,
}

async fn refresh_row(app: &TestApp, token: &TokenSecret) -> Option<RefreshRow> {
    let hash = token.hash();
    app.state
        .vault_db
        .with_conn(move |conn| {
            use rusqlite::OptionalExtension as _;
            Ok(conn
                .query_row(
                    "SELECT device_id, prev_hash, issued_at, idle_expires_at, abs_expires_at,
                            used_at
                     FROM ferret_refresh WHERE token_hash = ?1",
                    [hash.0.as_slice()],
                    |r| {
                        Ok(RefreshRow {
                            device: r.get(0)?,
                            prev_hash: r.get(1)?,
                            issued_at: r.get(2)?,
                            idle_expires_at: r.get(3)?,
                            abs_expires_at: r.get(4)?,
                            used_at: r.get(5)?,
                        })
                    },
                )
                .optional()?)
        })
        .await
        .expect("a refresh row")
}

/// The device's `revoked_at`; `None` for a live device (and panics for a
/// device that has no row).
async fn revoked_at(app: &TestApp, device: [u8; 16]) -> Option<i64> {
    app.state
        .vault_db
        .with_conn(move |conn| {
            Ok(conn.query_row(
                "SELECT revoked_at FROM ferret_devices WHERE device_id = ?1",
                [device.as_slice()],
                |r| r.get(0),
            )?)
        })
        .await
        .expect("a device row")
}

async fn device_exists(app: &TestApp, device: [u8; 16]) -> bool {
    app.state
        .vault_db
        .with_conn(move |conn| {
            Ok(conn.query_row(
                "SELECT COUNT(*) FROM ferret_devices WHERE device_id = ?1",
                [device.as_slice()],
                |r| r.get::<_, i64>(0),
            )? == 1)
        })
        .await
        .expect("a count")
}

async fn lookup(app: &TestApp, token: &TokenSecret) -> AccessLookup {
    let hash = token.hash();
    let at = now(app);
    app.state
        .vault_db
        .with_conn(move |conn| Ok(lookup_access(conn, &hash, at)?))
        .await
        .expect("a lookup")
}

/// The device's revocations announced so far, from a receiver taken before.
fn announced(rx: &mut tokio::sync::broadcast::Receiver<Revoked>) -> Vec<Revoked> {
    let mut seen = Vec::new();
    while let Ok(revoked) = rx.try_recv() {
        seen.push(revoked);
    }
    seen
}

/// Sets the app's clock to `t0 + secs`.
fn set_clock(app: &TestApp, t0: i64, secs: i64) {
    app.clock
        .set(u64::try_from(t0 + secs).expect("a time after 1970"));
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

/// The same server after a restart: the same database and clock, an empty
/// `jti` cache and an empty grace store.
fn restarted(app: &TestApp) -> axum::Router {
    let mut state = app.state.clone();
    state.device_auth = DeviceAuth::new(state.vault_db.clone(), state.clock.clone(), VAULT_URL);
    ferret_server::server::vault_router(state)
}

/// The `Date` the server sends at the app's time now.
fn date_now(app: &TestApp) -> String {
    let dated = with_server_date(Response::new(Body::empty()), now(app));
    dated.headers()[header::DATE]
        .to_str()
        .expect("a date")
        .to_string()
}

// ------------------------------------------------------------- the rotation

#[tokio::test]
async fn refresh_rotates_and_the_old_token_is_dead_after_grace() {
    let app = device_app().await;
    client_account(&app, 1).await;
    let t0 = now(&app);
    let device = signed_in(&app, 1, 1).await;
    let id = device_id(&device);
    let first = refresh_token(&device);
    assert_eq!(
        refresh_row(&app, &first).await,
        Some(RefreshRow {
            device: id.to_vec(),
            prev_hash: None,
            issued_at: t0,
            idle_expires_at: t0 + IDLE_SECS,
            abs_expires_at: t0 + ABSOLUTE_SECS,
            used_at: None,
        })
    );

    app.clock.advance(10);
    let res = refresh(&app, &device, &first).await;
    assert_eq!(res.status, StatusCode::OK, "{}", res.text());
    // The answer is the strict wire shape, and nothing else.
    let body: TokenRes = serde_json::from_slice(&res.body).expect("a token answer");
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
        ["access_token", "expires_in", "refresh_token", "token_type"]
    );
    let (access, second) = tokens_of(&res);
    assert_ne!(second.hash(), first.hash());
    assert_ne!(
        access.hash(),
        device.access.as_ref().expect("signed in").hash()
    );

    // The old token is used; its one successor names it and keeps the
    // absolute end of the sign-in.
    let t1 = t0 + 10;
    assert_eq!(
        refresh_row(&app, &first).await.expect("kept").used_at,
        Some(t1)
    );
    assert_eq!(
        refresh_row(&app, &second).await,
        Some(RefreshRow {
            device: id.to_vec(),
            prev_hash: Some(first.hash().0.to_vec()),
            issued_at: t1,
            idle_expires_at: t1 + IDLE_SECS,
            abs_expires_at: t0 + ABSOLUTE_SECS,
            used_at: None,
        })
    );
    match lookup(&app, &access).await {
        AccessLookup::Live(row) => {
            assert_eq!(row.device, DeviceId(id));
            assert_eq!(row.expires_at, t1 + 900);
        }
        other => panic!("not live: {other:?}"),
    }
    assert_eq!(rows(&app).await, (2, 2, 1));

    // The successor renews in its turn.
    let (_, third) = renewed(&app, &device, &second).await;
    assert_eq!(
        refresh_row(&app, &third).await.expect("a row").prev_hash,
        Some(second.hash().0.to_vec())
    );

    // After the grace period the first token is dead: its use is a reuse,
    // which ends the device.
    app.clock
        .advance(u64::try_from(GRACE_SECS + 1).expect("seconds"));
    let res = refresh(&app, &device, &first).await;
    assert_eq!(status_and_code(&res), refused(401, "token_reused"));
    assert!(revoked_at(&app, id).await.is_some());
}

#[tokio::test]
async fn late_retry_inside_grace_with_the_same_key_gets_the_same_successor() {
    let app = device_app().await;
    client_account(&app, 1).await;
    let device = signed_in(&app, 1, 1).await;
    let id = device_id(&device);
    let first = refresh_token(&device);
    let (access, second) = renewed(&app, &device, &first).await;

    // The answer was lost; the device asks again with the same token and a
    // new proof, up to the last second of the grace period.
    for secs in [1, GRACE_SECS - 1] {
        app.clock.advance(u64::try_from(secs).expect("seconds"));
        let (again, same) = renewed(&app, &device, &first).await;
        assert_eq!(same.hash(), second.hash(), "the same successor");
        assert_ne!(again.hash(), access.hash(), "a new access token");
        assert!(matches!(lookup(&app, &again).await, AccessLookup::Live(_)));
    }
    // One successor only, and nothing revoked.
    assert_eq!(rows(&app).await, (4, 2, 1));
    assert_eq!(revoked_at(&app, id).await, None);
    // The successor works as usual.
    renewed(&app, &device, &second).await;
}

#[tokio::test]
async fn reuse_after_grace_revokes_the_family_and_the_device() {
    let app = device_app().await;
    client_account(&app, 1).await;
    let device = signed_in(&app, 1, 1).await;
    let id = device_id(&device);
    let first = refresh_token(&device);
    let (access, second) = renewed(&app, &device, &first).await;
    let mut rx = app.sync_events().subscribe_revocations();

    app.clock
        .advance(u64::try_from(GRACE_SECS + 1).expect("seconds"));
    let res = refresh(&app, &device, &first).await;
    assert_eq!(status_and_code(&res), refused(401, "token_reused"));
    assert_eq!(revoked_at(&app, id).await, Some(now(&app)));
    assert_eq!(announced(&mut rx), [Revoked::Device(DeviceId(id))]);

    // The whole family is dead, and the tokens are still known: every one of
    // them says `device_revoked` (final for the client).
    let res = refresh(&app, &device, &second).await;
    assert_eq!(status_and_code(&res), refused(401, "device_revoked"));
    assert_eq!(lookup(&app, &access).await, AccessLookup::DeviceRevoked);
    assert_eq!(rows(&app).await, (2, 2, 1), "nothing new");
    assert!(announced(&mut rx).is_empty(), "announced once");
}

#[tokio::test]
async fn reuse_with_a_proof_from_another_key_revokes_at_once() {
    let app = device_app().await;
    client_account(&app, 1).await;
    // An unused token with a proof of a key bound to nothing.
    let device = signed_in(&app, 1, 1).await;
    let mut rx = app.sync_events().subscribe_revocations();
    let before = replay_len(&app);
    let res = refresh_with(
        &app,
        &refresh_token(&device),
        Some(&proof_of_key(&app, 9, REFRESH)),
    )
    .await;
    assert_eq!(status_and_code(&res), refused(401, "token_reused"));
    let id = device_id(&device);
    assert_eq!(revoked_at(&app, id).await, Some(now(&app)));
    assert_eq!(announced(&mut rx), [Revoked::Device(DeviceId(id))]);
    // The proof was bound to nothing, so its `jti` took no place.
    assert_eq!(replay_len(&app), before);
    assert_eq!(rows(&app).await, (1, 1, 1), "nothing rotated");

    // A used token inside its grace period, with a proof of another device's
    // key: the same.
    let other = signed_in(&app, 1, 2).await;
    let third = signed_in(&app, 1, 3).await;
    let first = refresh_token(&other);
    renewed(&app, &other, &first).await;
    let before = replay_len(&app);
    let res = refresh_with(&app, &first, Some(&proof_for(&app, &third, REFRESH))).await;
    assert_eq!(status_and_code(&res), refused(401, "token_reused"));
    assert!(revoked_at(&app, device_id(&other)).await.is_some());
    assert_eq!(revoked_at(&app, device_id(&third)).await, None);
    assert_eq!(replay_len(&app), before);
}

#[tokio::test]
async fn refresh_needs_a_proof_from_the_bound_key() {
    let app = device_app().await;
    client_account(&app, 1).await;
    let device = signed_in(&app, 1, 1).await;
    let token = refresh_token(&device);
    let access = copy(device.access.as_ref().expect("signed in"));
    let htu = format!("{VAULT_URL}{REFRESH}");
    let before = (rows(&app).await, replay_len(&app));
    let bad = [
        None,
        // With `ath`, as for a request with an access token.
        Some(device.key.proof("POST", &htu, now(&app), Some(&access))),
        // For another path, another origin, another method.
        Some(proof_for(&app, &device, REVOKE)),
        Some(device.key.proof(
            "POST",
            &format!("https://other.example{REFRESH}"),
            now(&app),
            None,
        )),
        Some(device.key.proof("GET", &htu, now(&app), None)),
        // Out of the clock window.
        Some(device.key.proof("POST", &htu, now(&app) - 61, None)),
    ];
    for proof in &bad {
        let res = refresh_with(&app, &token, proof.as_deref()).await;
        assert_eq!(
            status_and_code(&res),
            refused(401, "dpop_invalid"),
            "{proof:?}"
        );
        assert_eq!(res.header("cache-control"), "no-store");
        assert_eq!(res.header("date"), date_now(&app));
    }
    // Nothing changed: not used, nothing written, no `jti` recorded, the
    // device is not revoked.
    assert_eq!((rows(&app).await, replay_len(&app)), before);
    assert_eq!(
        refresh_row(&app, &token).await.expect("a row").used_at,
        None
    );
    assert_eq!(revoked_at(&app, device_id(&device)).await, None);
    // The good proof renews.
    renewed(&app, &device, &token).await;

    // A body that is not a refresh token is refused before the proof.
    for body in [
        json!({}),
        json!({"refresh_token": "too short"}),
        json!({"refresh_token": format!("{}=", &token.to_wire()[..42])}),
        json!({"refresh_token": token.to_wire(), "extra": 1}),
    ] {
        let res = app
            .call_raw(
                Which::Vault,
                Req::post(REFRESH)
                    .header("ferret-protocol", "1")
                    .header("x-forwarded-proto", "https")
                    .header("dpop", &proof_for(&app, &device, REFRESH))
                    .json(&body)
                    .build(),
            )
            .await;
        assert_eq!(status_and_code(&res), refused(400, "bad_request"), "{body}");
    }
    let big = "x".repeat(MAX_BODY_BYTES);
    let res = app
        .call_raw(
            Which::Vault,
            Req::post(REFRESH)
                .header("ferret-protocol", "1")
                .header("x-forwarded-proto", "https")
                .json(&json!({ "refresh_token": big }))
                .build(),
        )
        .await;
    assert_eq!(status_and_code(&res), refused(413, "too_large"));
    // A plain-HTTP request to an `https` vault is refused before anything.
    let res = app
        .call_raw(
            Which::Vault,
            Req::post(REFRESH)
                .header("ferret-protocol", "1")
                .header("dpop", &proof_for(&app, &device, REFRESH))
                .json(&json!({ "refresh_token": token.to_wire() }))
                .build(),
        )
        .await;
    assert_eq!(status_and_code(&res), refused(400, "insecure_transport"));
}

#[tokio::test]
async fn idle_30_days_and_absolute_90_days_end_the_family() {
    let app = device_app().await;
    client_account(&app, 1).await;
    let t0 = now(&app);
    let long = signed_in(&app, 1, 1).await;
    let idle = signed_in(&app, 1, 2).await;
    let mut rx = app.sync_events().subscribe_revocations();

    // Idle: a token renews in the last second before its idle end, and not at
    // that second.
    set_clock(&app, t0, IDLE_SECS - 1);
    let (_, mut token) = renewed(&app, &long, &refresh_token(&long)).await;
    set_clock(&app, t0, IDLE_SECS);
    let res = refresh(&app, &idle, &refresh_token(&idle)).await;
    assert_eq!(status_and_code(&res), refused(401, "token_expired"));
    let idle_id = device_id(&idle);
    assert_eq!(revoked_at(&app, idle_id).await, Some(t0 + IDLE_SECS));
    assert_eq!(announced(&mut rx), [Revoked::Device(DeviceId(idle_id))]);
    // From then on the device is revoked.
    let res = refresh(&app, &idle, &refresh_token(&idle)).await;
    assert_eq!(status_and_code(&res), refused(401, "device_revoked"));

    // Absolute: renewing within every idle period, the family still ends 90
    // days after the sign-in, to the second.
    for at in [
        2 * IDLE_SECS - 10,
        ABSOLUTE_SECS - 10 * 86_400,
        ABSOLUTE_SECS - 1,
    ] {
        set_clock(&app, t0, at);
        token = renewed(&app, &long, &token).await.1;
    }
    assert_eq!(
        refresh_row(&app, &token)
            .await
            .expect("a row")
            .abs_expires_at,
        t0 + ABSOLUTE_SECS
    );
    set_clock(&app, t0, ABSOLUTE_SECS);
    let res = refresh(&app, &long, &token).await;
    assert_eq!(status_and_code(&res), refused(401, "token_expired"));
    let long_id = device_id(&long);
    assert_eq!(revoked_at(&app, long_id).await, Some(t0 + ABSOLUTE_SECS));
    assert_eq!(announced(&mut rx), [Revoked::Device(DeviceId(long_id))]);
    let res = refresh(&app, &long, &token).await;
    assert_eq!(status_and_code(&res), refused(401, "device_revoked"));
}

#[tokio::test]
async fn concurrent_refresh_with_the_same_token_gives_one_successor_and_no_revocation() {
    let app = device_app().await;
    client_account(&app, 1).await;
    let device = signed_in(&app, 1, 1).await;
    let token = refresh_token(&device);
    let (a, b) = tokio::join!(
        refresh(&app, &device, &token),
        refresh(&app, &device, &token)
    );
    let (access_a, next_a) = tokens_of(&a);
    let (access_b, next_b) = tokens_of(&b);
    assert_eq!(next_a.hash(), next_b.hash(), "one successor");
    assert_ne!(access_a.hash(), access_b.hash());
    assert_eq!(rows(&app).await, (3, 2, 1));
    assert_eq!(revoked_at(&app, device_id(&device)).await, None);
}

#[tokio::test]
async fn the_same_refresh_proof_twice_concurrently_gives_one_answer() {
    let app = device_app().await;
    client_account(&app, 1).await;
    let device = signed_in(&app, 1, 1).await;
    let token = refresh_token(&device);
    let proof = proof_for(&app, &device, REFRESH);
    let (a, b) = tokio::join!(
        refresh_with(&app, &token, Some(&proof)),
        refresh_with(&app, &token, Some(&proof))
    );
    let mut answers = [status_and_code(&a), status_and_code(&b)];
    answers.sort();
    assert_eq!(answers, [refused(200, ""), refused(401, "dpop_invalid")]);
    // One successor and one new access token, nothing more, and nothing
    // revoked.
    assert_eq!(rows(&app).await, (2, 2, 1));
    assert_eq!(revoked_at(&app, device_id(&device)).await, None);
    assert_eq!(replay_len(&app), 2, "the sign-in's and this one");
}

#[tokio::test]
async fn a_replayed_proof_rotates_nothing() {
    let app = device_app().await;
    client_account(&app, 1).await;
    let device = signed_in(&app, 1, 1).await;
    let first = refresh_token(&device);
    let proof = proof_for(&app, &device, REFRESH);
    let (_, second) = tokens_of(&refresh_with(&app, &first, Some(&proof)).await);
    let before = rows(&app).await;

    // The same proof with the successor, and with the used token inside its
    // grace period: both refused, and nothing is handed out.
    for token in [&second, &first] {
        let res = refresh_with(&app, token, Some(&proof)).await;
        assert_eq!(status_and_code(&res), refused(401, "dpop_invalid"));
    }
    assert_eq!(rows(&app).await, before);
    assert_eq!(
        refresh_row(&app, &second).await.expect("a row").used_at,
        None
    );
    assert_eq!(revoked_at(&app, device_id(&device)).await, None);
    // With a new proof the successor renews.
    renewed(&app, &device, &second).await;
}

#[tokio::test]
async fn a_retry_after_the_successor_was_used_is_reuse() {
    let app = device_app().await;
    client_account(&app, 1).await;
    let device = signed_in(&app, 1, 1).await;
    let first = refresh_token(&device);
    let (_, second) = renewed(&app, &device, &first).await;
    app.clock.advance(1);
    renewed(&app, &device, &second).await;
    // Inside the grace period of the first token, but its successor is used.
    app.clock.advance(1);
    let res = refresh(&app, &device, &first).await;
    assert_eq!(status_and_code(&res), refused(401, "token_reused"));
    assert!(revoked_at(&app, device_id(&device)).await.is_some());
}

#[tokio::test]
async fn a_restart_inside_grace_gives_token_expired_and_no_revocation() {
    let app = device_app().await;
    client_account(&app, 1).await;
    let device = signed_in(&app, 1, 1).await;
    let first = refresh_token(&device);
    let (_, second) = renewed(&app, &device, &first).await;
    assert_eq!(app.state.device_auth.grace().len(), 1);

    // The server restarts: the grace store is empty.
    let router = restarted(&app);
    app.clock.advance(5);
    let res = call_router(
        router.clone(),
        token_body_req(
            REFRESH,
            &first.to_wire(),
            Some(&proof_for(&app, &device, REFRESH)),
        ),
    )
    .await;
    assert_eq!(status_and_code(&res), refused(401, "token_expired"));
    assert_eq!(revoked_at(&app, device_id(&device)).await, None);
    assert_eq!(rows(&app).await, (2, 2, 1), "nothing written");
    // The successor, which the device kept, still renews.
    let res = call_router(
        router,
        token_body_req(
            REFRESH,
            &second.to_wire(),
            Some(&proof_for(&app, &device, REFRESH)),
        ),
    )
    .await;
    assert_eq!(res.status, StatusCode::OK, "{}", res.text());
}

#[tokio::test]
async fn a_full_grace_cache_refuses_with_busy_and_rotates_nothing() {
    let app = device_app().await;
    client_account(&app, 1).await;
    let device = signed_in(&app, 1, 1).await;
    let token = refresh_token(&device);

    // Other devices' successors fill the store.
    let grace = app.state.device_auth.grace();
    let filler = TokenSecret::random(&mut TestRng::new(b"filler"));
    let t = now(&app);
    for i in 0..GRACE_CAPACITY {
        let mut jkt = [0xee; 32];
        jkt[..8].copy_from_slice(&u64::try_from(i).expect("an index").to_be_bytes());
        let mut old = [0x11; 32];
        old[..8].copy_from_slice(&u64::try_from(i).expect("an index").to_be_bytes());
        grace.put(&TokenHash(old), &filler, jkt, t).expect("room");
    }
    assert_eq!(grace.len(), GRACE_CAPACITY);

    let res = refresh(&app, &device, &token).await;
    assert_eq!(status_and_code(&res), refused(503, "busy"));
    assert_eq!(res.header("retry-after"), "30");
    assert_eq!(res.header("date"), date_now(&app));
    // Nothing rotated: the token is unused, and no row was written.
    assert_eq!(rows(&app).await, (1, 1, 1));
    assert_eq!(
        refresh_row(&app, &token).await.expect("a row").used_at,
        None
    );
    assert_eq!(revoked_at(&app, device_id(&device)).await, None);

    // Once the others' grace periods are over there is room, and the same
    // token renews.
    app.clock
        .advance(u64::try_from(GRACE_SECS + 1).expect("seconds"));
    renewed(&app, &device, &token).await;
    assert_eq!(grace.len(), 1);
}

#[tokio::test]
async fn a_revoked_device_refreshes_to_device_revoked() {
    let app = device_app().await;
    let client = client_account(&app, 1).await;
    let device = signed_in(&app, 1, 1).await;
    let id = device_id(&device);
    let token = refresh_token(&device);
    let at = now(&app);
    let user = client.ids.user_id;
    let done = app
        .state
        .vault_db
        .with_conn(move |conn| {
            let tx = conn.transaction()?;
            let done = revoke(&tx, user, &DeviceId(id), at)?;
            tx.commit()?;
            Ok(done)
        })
        .await
        .expect("a revocation");
    assert!(done);

    let before = (rows(&app).await, replay_len(&app));
    // With its own key or with another one, the answer is the final
    // `device_revoked`, and nothing changes.
    for proof in [
        proof_for(&app, &device, REFRESH),
        proof_of_key(&app, 9, REFRESH),
    ] {
        let res = refresh_with(&app, &token, Some(&proof)).await;
        assert_eq!(status_and_code(&res), refused(401, "device_revoked"));
    }
    assert_eq!((rows(&app).await, replay_len(&app)), before);
    assert_eq!(revoked_at(&app, id).await, Some(at));
    // Its sign-out changes nothing either.
    let res = revoke_with(&app, &token, Some(&proof_for(&app, &device, REVOKE))).await;
    assert_eq!(res.status, StatusCode::NO_CONTENT);
    assert_eq!(revoked_at(&app, id).await, Some(at));
}

#[tokio::test]
async fn a_raised_session_version_ends_refresh() {
    let app = device_app().await;
    let client = client_account(&app, 1).await;
    let user = client.ids.user_id;
    let device = signed_in(&app, 1, 1).await;
    let disabled = signed_in(&app, 1, 2).await;
    let token = refresh_token(&device);

    // The kit's sign-out everywhere.
    exec(
        &app,
        "UPDATE users SET session_version = session_version + 1 WHERE id = ?1",
        user,
    )
    .await;
    let before = (rows(&app).await, replay_len(&app));
    let res = refresh(&app, &device, &token).await;
    assert_eq!(status_and_code(&res), refused(401, "device_revoked"));
    assert_eq!((rows(&app).await, replay_len(&app)), before);

    // The device signs out: it is ended, and its proof takes no place.
    let mut rx = app.sync_events().subscribe_revocations();
    let res = revoke_with(&app, &token, Some(&proof_for(&app, &device, REVOKE))).await;
    assert_eq!(res.status, StatusCode::NO_CONTENT);
    assert!(revoked_at(&app, device_id(&device)).await.is_some());
    assert_eq!(replay_len(&app), before.1);
    assert_eq!(
        announced(&mut rx),
        [Revoked::Device(DeviceId(device_id(&device)))]
    );

    // A disabled user's devices renew nothing either.
    let other = signed_in(&app, 1, 3).await;
    exec(&app, "UPDATE users SET active = 0 WHERE id = ?1", user).await;
    let res = refresh(&app, &other, &refresh_token(&other)).await;
    assert_eq!(status_and_code(&res), refused(401, "device_revoked"));
    let res = refresh(&app, &disabled, &refresh_token(&disabled)).await;
    assert_eq!(status_and_code(&res), refused(401, "device_revoked"));
}

// ------------------------------------------------------------- the sign-out

#[tokio::test]
async fn revoke_ends_the_device_and_its_stream_at_once() {
    let app = device_app().await;
    client_account(&app, 1).await;
    let device = signed_in(&app, 1, 1).await;
    let id = device_id(&device);
    let first = refresh_token(&device);
    let (access, second) = renewed(&app, &device, &first).await;
    let mut rx = app.sync_events().subscribe_revocations();
    let before = replay_len(&app);

    // A proof that is not good changes nothing.
    let res = revoke_with(&app, &second, None).await;
    assert_eq!(status_and_code(&res), refused(401, "dpop_invalid"));
    let res = revoke_with(&app, &second, Some(&proof_for(&app, &device, REFRESH))).await;
    assert_eq!(status_and_code(&res), refused(401, "dpop_invalid"));
    assert_eq!(revoked_at(&app, id).await, None);
    assert!(announced(&mut rx).is_empty());

    let res = revoke_with(&app, &second, Some(&proof_for(&app, &device, REVOKE))).await;
    assert_eq!(res.status, StatusCode::NO_CONTENT);
    assert!(res.body.is_empty());
    assert_eq!(res.header("cache-control"), "no-store");
    assert_eq!(res.header("date"), date_now(&app));
    assert_eq!(revoked_at(&app, id).await, Some(now(&app)));
    // Announced after the commit, so the device's streams close now.
    assert_eq!(announced(&mut rx), [Revoked::Device(DeviceId(id))]);
    // The proof was bound, so its `jti` is recorded.
    assert_eq!(replay_len(&app), before + 1);
    // Every token of the device is dead, and still known.
    assert_eq!(lookup(&app, &access).await, AccessLookup::DeviceRevoked);
    let res = refresh(&app, &device, &second).await;
    assert_eq!(status_and_code(&res), refused(401, "device_revoked"));
    // Signing out again changes nothing and announces nothing.
    let res = revoke_with(&app, &first, Some(&proof_for(&app, &device, REVOKE))).await;
    assert_eq!(res.status, StatusCode::NO_CONTENT);
    assert!(announced(&mut rx).is_empty());

    // With a proof of another key, the sign-out ends the device all the same
    // (its refresh token has leaked), and that proof takes no place.
    let other = signed_in(&app, 1, 2).await;
    let before = replay_len(&app);
    let res = revoke_with(
        &app,
        &refresh_token(&other),
        Some(&proof_of_key(&app, 9, REVOKE)),
    )
    .await;
    assert_eq!(res.status, StatusCode::NO_CONTENT);
    let other_id = device_id(&other);
    assert!(revoked_at(&app, other_id).await.is_some());
    assert_eq!(announced(&mut rx), [Revoked::Device(DeviceId(other_id))]);
    assert_eq!(replay_len(&app), before);
}

#[tokio::test]
async fn revoke_with_an_unknown_token_is_204_and_changes_nothing() {
    let app = device_app().await;
    client_account(&app, 1).await;
    let device = signed_in(&app, 1, 1).await;
    let mut rx = app.sync_events().subscribe_revocations();
    let before = (rows(&app).await, replay_len(&app));
    let unknown = TokenSecret::random(&mut TestRng::new(b"unknown token"));
    let res = revoke_with(&app, &unknown, Some(&proof_for(&app, &device, REVOKE))).await;
    assert_eq!(res.status, StatusCode::NO_CONTENT);
    assert_eq!(res.header("date"), date_now(&app));
    assert_eq!((rows(&app).await, replay_len(&app)), before);
    assert_eq!(revoked_at(&app, device_id(&device)).await, None);
    assert!(announced(&mut rx).is_empty());
    // A body that is not a token is refused.
    let res = app
        .call_raw(
            Which::Vault,
            token_body_req(
                REVOKE,
                "not a token",
                Some(&proof_for(&app, &device, REVOKE)),
            )
            .build(),
        )
        .await;
    assert_eq!(status_and_code(&res), refused(400, "bad_request"));
    // An unknown token on the renewal is `token_expired`.
    let res = refresh(&app, &device, &unknown).await;
    assert_eq!(status_and_code(&res), refused(401, "token_expired"));
    assert_eq!((rows(&app).await, replay_len(&app)), before);
}

// ---------------------------------------------------------------- the purge

#[tokio::test]
async fn purge_removes_expired_access_and_old_used_rows_and_revokes_dead_devices() {
    let app = device_app().await;
    client_account(&app, 1).await;
    let t0 = now(&app);
    let live = signed_in(&app, 1, 1).await;
    let dead = signed_in(&app, 1, 2).await;
    let used = refresh_token(&live);
    let (_, mut token) = renewed(&app, &live, &used).await;
    let purge = || purge_once(&app.state.vault_db, app.clock.as_ref());
    assert_eq!(purge().await.expect("a purge"), Purged::default());
    assert_eq!(rows(&app).await, (3, 3, 2));

    // Access tokens go at the second they expire.
    set_clock(&app, t0, 899);
    assert_eq!(purge().await.expect("a purge"), Purged::default());
    set_clock(&app, t0, 900);
    assert_eq!(
        purge().await.expect("a purge"),
        Purged {
            access: 3,
            ..Purged::default()
        }
    );

    // A device whose last refresh token went idle is revoked, and leaves the
    // quota; one that renewed in time is not.
    set_clock(&app, t0, IDLE_SECS - 1);
    token = renewed(&app, &live, &token).await.1;
    assert_eq!(purge().await.expect("a purge"), Purged::default());
    set_clock(&app, t0, IDLE_SECS);
    assert_eq!(
        purge().await.expect("a purge"),
        Purged {
            devices: 1,
            ..Purged::default()
        }
    );
    assert_eq!(
        revoked_at(&app, device_id(&dead)).await,
        Some(t0 + IDLE_SECS)
    );
    assert_eq!(revoked_at(&app, device_id(&live)).await, None);
    let res = refresh(&app, &dead, &refresh_token(&dead)).await;
    assert_eq!(status_and_code(&res), refused(401, "device_revoked"));

    // A used refresh row is kept for 30 days after its use, to the second.
    assert_eq!(USED_KEEP_SECS, 30 * 86_400);
    set_clock(&app, t0, USED_KEEP_SECS + 1);
    let purged = purge().await.expect("a purge");
    assert_eq!(purged.refresh, 1, "{purged:?}");
    assert_eq!(refresh_row(&app, &used).await, None);
    // A reuse of so old a token is no longer seen: `token_expired`, and the
    // device stays.
    let res = refresh(&app, &live, &used).await;
    assert_eq!(status_and_code(&res), refused(401, "token_expired"));
    assert_eq!(revoked_at(&app, device_id(&live)).await, None);
    renewed(&app, &live, &token).await;

    // An absolute end leaves no live refresh row either. By then the device
    // revoked at its idle end has been revoked for more than 30 days, so it
    // goes, with its rows.
    set_clock(&app, t0, ABSOLUTE_SECS);
    let purged = purge().await.expect("a purge");
    assert_eq!(purged.devices, 2, "{purged:?}");
    assert_eq!(
        revoked_at(&app, device_id(&live)).await,
        Some(t0 + ABSOLUTE_SECS)
    );
    assert!(!device_exists(&app, device_id(&dead)).await);
}

#[tokio::test]
async fn purge_deletes_devices_revoked_more_than_30_days_ago_with_their_tokens() {
    let app = device_app().await;
    client_account(&app, 1).await;
    let t0 = now(&app);
    let gone = signed_in(&app, 1, 1).await;
    let first = refresh_token(&gone);
    let (_, second) = renewed(&app, &gone, &first).await;
    let res = revoke_with(&app, &second, Some(&proof_for(&app, &gone, REVOKE))).await;
    assert_eq!(res.status, StatusCode::NO_CONTENT);
    let id = device_id(&gone);
    assert_eq!(revoked_at(&app, id).await, Some(t0));
    let purge = || purge_once(&app.state.vault_db, app.clock.as_ref());

    // For 30 days the rows stay, so the tokens are still known.
    set_clock(&app, t0, REVOKED_KEEP_SECS);
    assert_eq!(
        purge().await.expect("a purge"),
        Purged {
            access: 2,
            ..Purged::default()
        }
    );
    assert_eq!(rows(&app).await, (0, 2, 1));
    let res = refresh(&app, &gone, &second).await;
    assert_eq!(status_and_code(&res), refused(401, "device_revoked"));

    // After that the token rows and the device row go.
    set_clock(&app, t0, REVOKED_KEEP_SECS + 1);
    assert_eq!(
        purge().await.expect("a purge"),
        Purged {
            access: 0,
            refresh: 2,
            devices: 1,
        }
    );
    assert_eq!(rows(&app).await, (0, 0, 0));
    assert!(!device_exists(&app, id).await);
    let res = refresh(&app, &gone, &second).await;
    assert_eq!(status_and_code(&res), refused(401, "token_expired"));
}

// ----------------------------------------------------- the answers and logs

#[tokio::test]
async fn refresh_answers_have_no_store_and_a_date() {
    let app = device_app().await;
    client_account(&app, 1).await;
    assert_eq!(START, 1_793_491_200);
    let device = signed_in(&app, 1, 1).await;
    app.clock.advance(3_661);
    let res = refresh(&app, &device, &refresh_token(&device)).await;
    assert_eq!(res.status, StatusCode::OK, "{}", res.text());
    assert_eq!(res.header("cache-control"), "no-store");
    assert_eq!(res.header("content-type"), "application/json");
    assert_eq!(res.header("date"), "Sun, 01 Nov 2026 01:01:01 GMT");
    assert_eq!(res.headers.get_all("date").iter().count(), 1);
    assert!(res.set_cookies().is_empty());

    // Every refusal after the body says the server's time too.
    app.clock.advance(1);
    let unknown = TokenSecret::random(&mut TestRng::new(b"another token"));
    for res in [
        refresh_with(&app, &refresh_token(&device), None).await,
        refresh(&app, &device, &unknown).await,
        app.call_raw(
            Which::Vault,
            token_body_req(REFRESH, "nope", Some(&proof_for(&app, &device, REFRESH))).build(),
        )
        .await,
    ] {
        assert_eq!(res.status.as_u16() / 100, 4, "{}", res.text());
        assert_eq!(res.header("cache-control"), "no-store");
        assert_eq!(res.header("date"), "Sun, 01 Nov 2026 01:01:02 GMT");
    }
}

#[tokio::test]
async fn token_routes_are_not_on_the_admin_listener() {
    let app = device_app().await;
    client_account(&app, 1).await;
    let device = signed_in(&app, 1, 1).await;
    let token = refresh_token(&device);
    let before = (rows(&app).await, replay_len(&app));
    for path in [REFRESH, REVOKE] {
        // The admin listener has no such route.
        let res = app
            .call_raw(
                Which::Admin,
                Req::post(path)
                    .page_fetch(Which::Admin)
                    .header("x-forwarded-proto", "https")
                    .json(&json!({ "refresh_token": token.to_wire() }))
                    .build(),
            )
            .await;
        assert_eq!(res.status, StatusCode::NOT_FOUND, "{path}");
        // With a good proof it serves nothing either (the listener may refuse
        // the proof's header before it looks for a route).
        let res = app
            .call_raw(
                Which::Admin,
                token_body_req(
                    path,
                    &token.to_wire(),
                    Some(&proof_for(&app, &device, path)),
                )
                .header("origin", Which::Admin.url())
                .build(),
            )
            .await;
        assert!(
            [StatusCode::NOT_FOUND, StatusCode::BAD_REQUEST].contains(&res.status),
            "{path}: {}",
            res.status
        );
    }
    assert_eq!((rows(&app).await, replay_len(&app)), before);
    assert_eq!(
        refresh_row(&app, &token).await.expect("a row").used_at,
        None
    );
    assert_eq!(revoked_at(&app, device_id(&device)).await, None);
}

#[tokio::test]
async fn no_token_reaches_the_log() {
    let app = device_app().await;
    client_account(&app, 1).await;
    let device = signed_in(&app, 1, 1).await;
    let other = signed_in(&app, 1, 2).await;
    let first = refresh_token(&device);
    let mut secrets: Vec<String> =
        vec![first.to_wire(), device.key.x.clone(), device.key.y.clone()];
    let (log, guard) = capture_log();
    // A renewal, a lost answer's retry, a refused proof, a reuse, a sign-out
    // and a sign-out with another key.
    let proof = proof_for(&app, &device, REFRESH);
    let res = refresh_with(&app, &first, Some(&proof)).await;
    let (access, second) = tokens_of(&res);
    let (again, _) = renewed(&app, &device, &first).await;
    refresh_with(&app, &second, Some(&proof)).await;
    app.clock
        .advance(u64::try_from(GRACE_SECS + 1).expect("seconds"));
    let res = refresh(&app, &device, &first).await;
    assert_eq!(status_and_code(&res), refused(401, "token_reused"));
    let leaked = refresh_token(&other);
    let res = revoke_with(&app, &leaked, Some(&proof_of_key(&app, 9, REVOKE))).await;
    assert_eq!(res.status, StatusCode::NO_CONTENT);
    drop(guard);
    secrets.extend([
        proof,
        access.to_wire(),
        second.to_wire(),
        again.to_wire(),
        leaked.to_wire(),
    ]);
    // Whatever arrived (a log line is cached per call site, so with tests on
    // other threads not every line need arrive) holds none of them.
    let text = log.text();
    for secret in &secrets {
        assert!(!text.contains(secret.as_str()), "{text}");
    }
}
