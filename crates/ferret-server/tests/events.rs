//! `GET /api/sync/events`: what a stream says, when it ends and how many a
//! device, a vault and the server may hold open.
//!
//! The streams are driven through the real router with `TestApp::sync_events()`
//! as the writer of notifications: a write that ends in an event is a test of
//! the sync routes, not of this file. The reader of `support::events` takes the
//! answer frame by frame. Tests that move the clock of tokio start the stream
//! first and pause after, so nothing of the start-up runs on a frozen clock.

mod support;

use std::time::Duration;

use axum::http::StatusCode;
use ferret_core::OsRng;
use ferret_core::testing::opaque::{TestKsf, login_finish_with, register_finish_with};
use ferret_core::{
    LoginState, MasterPassword, OPAQUE_CONTEXT, OpaqueInput, PinState, TestRng, opaque_login_start,
    opaque_register_start,
};
use ferret_server::auth::session::{
    ADMIN_IDLE_SECS, Origin, VAULT_ABSOLUTE_SECS, VAULT_IDLE_SECS, still_valid,
};
use ferret_server::http::proxy_guard::ProxyList;
use ferret_server::ids::{AccountId, VaultId};
use ferret_server::vault::events::{EventStreams, HEARTBEAT, LIFETIME, QUIET};
use ferret_server::vault::notify::CAPACITY;
use ferret_server::vault::store::create_account;
use ferret_server::wire::b64url;
use ferret_server_auth::testing::{SMALL, register_start_open};
use ferret_server_auth::{
    Clock as _, CredentialId, ProfileRules, RegistrationKind, SessionScope, StoredRecord,
    register_finish,
};
use serde_json::{Value, json};
use support::accounts::{account_ids, insert_user, rows};
use support::events::{Frame, Next, Stream, wait_until};
use support::session::{Issued, Seeded, device, get_with, hex, issue, router, seed};
use support::{Jar, PEER, Req, TestApp, Which};

const SECOND: Duration = Duration::from_secs(1);
const SHORT: Duration = Duration::from_millis(400);

// ------------------------------------------------------------------ helpers

struct World {
    app: TestApp,
    seeded: Seeded,
    issued: Issued,
}

/// An app with a user, a vault and a vault session on device 1.
async fn world() -> World {
    let app = TestApp::new().await;
    let seeded = seed(&app, 1).await;
    let issued = issue(&app, seeded.user_id, Origin::Vault, SessionScope::Full, 1).await;
    World {
        app,
        seeded,
        issued,
    }
}

async fn sql(app: &TestApp, statement: &'static str, args: Vec<i64>) {
    app.state
        .vault_db
        .with_conn(move |conn| {
            conn.execute(statement, rusqlite::params_from_iter(args))?;
            Ok(())
        })
        .await
        .expect("a statement");
}

/// Statements run in one go, on one connection (a pragma needs that).
async fn batch(app: &TestApp, statements: &'static str) {
    app.state
        .vault_db
        .with_conn(move |conn| {
            conn.execute_batch(statements)?;
            Ok(())
        })
        .await
        .expect("statements");
}

async fn set_seq(app: &TestApp, vault: &VaultId, seq: i64) {
    let vault = *vault;
    app.state
        .vault_db
        .with_conn(move |conn| {
            conn.execute(
                "UPDATE ferret_vaults SET seq = ?2 WHERE vault_id = ?1",
                rusqlite::params![vault.as_bytes().as_slice(), seq],
            )?;
            Ok(())
        })
        .await
        .expect("set the seq");
}

/// A stream that has said hello.
async fn open(w: &World) -> Stream {
    let mut stream = w.app.events(&w.issued.jar).await;
    assert_eq!(stream.status, StatusCode::OK);
    stream.event("hello", SECOND).await;
    // Let the task of the stream start (it sets its timers when it first runs),
    // so a test that pauses the clock next has them on the clock it moves.
    stream.quiet(Duration::from_millis(50)).await;
    stream
}

/// Moves the clock of tokio, and lets the stream's own task run.
async fn advance(by: Duration) {
    tokio::time::advance(by).await;
}

async fn live_streams(app: &TestApp) -> usize {
    app.state.streams.open()
}

// ----------------------------------------------------------------- what it says

#[tokio::test]
async fn hello_comes_first_with_the_current_seq() {
    let w = world().await;
    set_seq(&w.app, &w.seeded.vault, 7).await;
    let mut stream = w.app.events(&w.issued.jar).await;
    assert_eq!(stream.status, StatusCode::OK);
    match stream.next(SECOND).await {
        Next::Frame(frame) => {
            assert!(frame.is_event("hello"), "{frame:?}");
            assert_eq!(frame.data(), json!({"seq": 7}));
        }
        other => panic!("expected hello, got {other:?}"),
    }
    stream.quiet(SHORT).await;
}

#[tokio::test]
async fn a_notify_gives_one_sync_event_within_one_second() {
    let w = world().await;
    let mut stream = open(&w).await;
    set_seq(&w.app, &w.seeded.vault, 8).await;
    w.app.sync_events().notify(w.seeded.vault, 8);
    let data = stream.event("sync", SECOND).await;
    assert_eq!(data, json!({"seq": 8}));
    stream.quiet(Duration::from_millis(700)).await;
}

#[tokio::test]
async fn a_burst_of_notifies_is_coalesced_into_one_event() {
    let w = world().await;
    let mut stream = open(&w).await;
    set_seq(&w.app, &w.seeded.vault, 60).await;
    for seq in 1..=60 {
        w.app.sync_events().notify(w.seeded.vault, seq);
    }
    let data = stream.event("sync", SECOND).await;
    assert_eq!(data, json!({"seq": 60}), "the number of now, not the first");
    stream.quiet(Duration::from_millis(700)).await;
}

#[tokio::test]
async fn a_change_that_waits_out_the_quiet_period_is_not_sent_before_it() {
    let w = world().await;
    let mut stream = open(&w).await;
    w.app.sync_events().notify(w.seeded.vault, 1);
    assert_eq!(QUIET, Duration::from_millis(250));
    stream.quiet(Duration::from_millis(120)).await;
    stream.event("sync", SECOND).await;
}

#[tokio::test]
async fn notifies_for_another_vault_send_nothing() {
    let w = world().await;
    let other = seed(&w.app, 2).await;
    let mut stream = open(&w).await;
    for seq in 1..=5 {
        w.app.sync_events().notify(other.vault, seq);
    }
    stream.quiet(Duration::from_millis(900)).await;
}

#[tokio::test]
async fn a_lagged_receiver_sends_sync() {
    let w = world().await;
    let other = seed(&w.app, 2).await;
    let mut stream = open(&w).await;
    set_seq(&w.app, &w.seeded.vault, 9).await;
    // The runtime runs one thread: the stream's task does not run while this
    // loop does, so its receiver falls behind by more than the capacity, and
    // none of it was for this vault. It may have missed one, so it says sync.
    for seq in 0..(CAPACITY * 3) {
        w.app
            .sync_events()
            .notify(other.vault, u64::try_from(seq).expect("a number"));
    }
    let data = stream.event("sync", SECOND).await;
    assert_eq!(data, json!({"seq": 9}));
}

#[tokio::test]
async fn event_payload_holds_only_the_seq() {
    let w = world().await;
    let mut stream = w.app.events(&w.issued.jar).await;
    set_seq(&w.app, &w.seeded.vault, 3).await;
    w.app.sync_events().notify(w.seeded.vault, 3);
    let (frames, ended) = stream.frames(Duration::from_millis(900)).await;
    assert!(!ended);
    assert_eq!(frames.len(), 2, "hello and one sync: {frames:?}");
    let secrets = [
        hex(w.seeded.vault.as_bytes()),
        hex(w.seeded.account.as_bytes()),
        hex(&device(1).0),
        hex(&w.issued.sid.0),
        w.issued.secret.clone(),
    ];
    for frame in &frames {
        let Frame::Event { name, data } = frame else {
            panic!("a comment too early: {frame:?}");
        };
        assert!(name == "hello" || name == "sync", "{name}");
        let json: Value = serde_json::from_str(data).expect("JSON");
        let object = json.as_object().expect("an object");
        assert_eq!(object.keys().collect::<Vec<_>>(), ["seq"], "{data}");
        assert!(object["seq"].is_u64());
        for secret in &secrets {
            assert!(!data.contains(secret.as_str()), "{data}");
        }
    }
}

// ------------------------------------------------------------------- headers

#[tokio::test]
async fn headers_disable_buffering_and_caching() {
    let w = world().await;
    let stream = w.app.events(&w.issued.jar).await;
    assert_eq!(stream.status, StatusCode::OK);
    assert_eq!(stream.header("content-type"), "text/event-stream");
    let cache: Vec<_> = stream
        .headers
        .get_all("cache-control")
        .iter()
        .map(|v| v.to_str().expect("text").to_string())
        .collect();
    assert_eq!(
        cache,
        ["no-store, no-transform"],
        "one header, and the stream is never transformed"
    );
    assert_eq!(stream.header("x-accel-buffering"), "no");
    assert_eq!(stream.header("content-encoding"), "");
    assert_eq!(stream.header("content-length"), "");
}

#[tokio::test]
async fn the_error_answers_are_no_store() {
    let w = world().await;
    let none = Jar::default();
    let stream = w.app.events(&none).await;
    assert_eq!(stream.status, StatusCode::UNAUTHORIZED);
    assert_eq!(stream.header("cache-control"), "no-store");
}

// --------------------------------------------------------------- the heartbeat

#[tokio::test]
async fn heartbeat_comment_every_25_seconds() {
    assert_eq!(HEARTBEAT, Duration::from_secs(25));
    let w = world().await;
    let mut stream = open(&w).await;
    tokio::time::pause();
    advance(Duration::from_secs(24)).await;
    stream.quiet(SHORT).await;
    // One second of margin: a timer is due at its millisecond, not before.
    advance(SECOND * 2).await;
    stream.comment(SECOND * 2).await;
    stream.quiet(SHORT).await;
    advance(Duration::from_secs(24)).await;
    stream.quiet(SHORT).await;
    advance(SECOND * 2).await;
    stream.comment(SECOND * 2).await;
    assert_eq!(live_streams(&w.app).await, 1);
}

// ---------------------------------------------------------------- it comes to an end

#[tokio::test]
async fn logout_ends_the_stream_at_once() {
    let w = world().await;
    let mut stream = open(&w).await;
    let out = w
        .app
        .call_raw(
            Which::Vault,
            Req::post("/api/auth/logout")
                .page_fetch(Which::Vault)
                .header("cookie", &w.issued.jar.header().expect("cookies"))
                .build(),
        )
        .await;
    assert_eq!(out.status, StatusCode::NO_CONTENT);
    // Well before the heartbeat of 25 seconds.
    stream.end(SECOND).await;
    wait_until(SECOND, || w.app.state.streams.open() == 0).await;
}

#[tokio::test]
async fn logout_of_another_session_leaves_the_stream_open() {
    let w = world().await;
    let mut stream = open(&w).await;
    let other = issue(
        &w.app,
        w.seeded.user_id,
        Origin::Vault,
        SessionScope::Full,
        2,
    )
    .await;
    let out = w
        .app
        .call_raw(
            Which::Vault,
            Req::post("/api/auth/logout")
                .page_fetch(Which::Vault)
                .header("cookie", &other.jar.header().expect("cookies"))
                .build(),
        )
        .await;
    assert_eq!(out.status, StatusCode::NO_CONTENT);
    stream.quiet(Duration::from_millis(900)).await;
}

#[tokio::test]
async fn the_logout_of_the_admin_listener_does_not_end_a_vault_stream() {
    // A vault session id shown to the admin listener's sign-out is not ended
    // there (the row belongs to the other listener), so its stream goes on.
    let w = world().await;
    let mut stream = open(&w).await;
    let out = w
        .app
        .call_raw(
            Which::Admin,
            Req::post("/api/auth/logout")
                .page_fetch(Which::Admin)
                .header("cookie", &w.issued.jar.header().expect("cookies"))
                .build(),
        )
        .await;
    assert_eq!(out.status, StatusCode::NO_CONTENT);
    stream.quiet(Duration::from_millis(900)).await;
    let again = get_with(&router(&w.app), &w.issued.jar, "/vault").await;
    assert_eq!(again.status, StatusCode::OK, "the row was not ended");
}

// The sign-in half of the sign-in that replaces a session: the same helpers as
// `tests/login.rs`, the real OPAQUE exchange with the small test parameters.

const PASSWORD: &str = "correct horse battery staple";

fn proxies() -> ProxyList {
    ProxyList::parse(&[PEER.split(':').next().expect("an address").to_string()])
        .expect("a proxy list")
}

fn opaque_input() -> OpaqueInput {
    MasterPassword::for_unlock(PASSWORD.as_bytes())
        .expect("a password")
        .opaque_input(None)
}

fn small_record(app: &TestApp, account: &AccountId) -> StoredRecord {
    let input = opaque_input();
    let mut rng = TestRng::new(b"events test registration");
    let (request, state) = opaque_register_start(&mut rng, &input).expect("a start");
    let response = register_start_open(
        &app.state.secrets.keys,
        &CredentialId::from(account),
        &request,
    )
    .expect("an answer");
    let done = register_finish_with(&mut rng, state, &input, &response, &TestKsf::new(SMALL))
        .expect("done");
    register_finish(
        &done.record,
        1,
        &ProfileRules::ferret_v1(),
        RegistrationKind::NewAccount,
    )
    .expect("a record")
}

async fn seed_login(app: &TestApp, n: u8, email: &str) {
    let now = i64::try_from(app.clock.now_unix()).expect("a time");
    let email = email.to_string();
    let account = account_ids(0, n).account_id;
    let record = small_record(app, &account);
    app.state
        .vault_db
        .with_conn(move |conn| {
            let user_id = insert_user(conn, &email);
            let mut account_rows = rows(user_id, n, now);
            account_rows.record = record;
            let tx = conn.transaction()?;
            create_account(&tx, &account_rows).expect("create the account");
            tx.commit()?;
            Ok(())
        })
        .await
        .expect("seed the account");
}

fn vault_post(path: &str, body: &Value) -> Req {
    Req::post(path)
        .page_fetch(Which::Vault)
        .header("x-forwarded-proto", "https")
        .json(body)
}

async fn send(app: &TestApp, jar: &mut Jar, mut req: Req) -> support::Res {
    if let Some(cookie) = jar.header() {
        req = req.header("cookie", &cookie);
    }
    let res = app.call_raw(Which::Vault, req.build()).await;
    jar.absorb(&res.headers);
    res
}

/// A whole sign-in with the right password; `jar` is presented, and replaced.
async fn sign_in(app: &TestApp, jar: &mut Jar, email: &str, device: u8) -> support::Res {
    let input = opaque_input();
    let (ke1, state): (_, LoginState) = opaque_login_start(&mut OsRng, &input).expect("a start");
    let res = send(
        app,
        jar,
        vault_post(
            "/api/auth/opaque/login/start",
            &json!({"email": email, "ke1": b64url::encode(&ke1)}),
        ),
    )
    .await;
    assert_eq!(res.status, StatusCode::OK, "{}", res.text());
    let body = res.json();
    let login_id = body["login_id"].as_str().expect("a login id").to_string();
    let ke2 = b64url::decode(body["ke2"].as_str().expect("a ke2")).expect("base64");
    let ke3 = login_finish_with(
        &mut OsRng,
        state,
        &input,
        &ke2,
        &TestKsf::new(SMALL),
        Some(OPAQUE_CONTEXT),
        PinState::FirstUse,
    )
    .expect("the client opens the envelope")
    .finished
    .ke3;
    send(
        app,
        jar,
        vault_post(
            "/api/auth/opaque/login/finish",
            &json!({
                "login_id": login_id,
                "ke3": b64url::encode(&ke3),
                "device_id": format!("{device:02x}").repeat(16),
                "device_name": "Test browser",
            }),
        ),
    )
    .await
}

#[tokio::test]
async fn a_login_that_replaces_the_session_ends_its_stream_at_once() {
    let app = TestApp::builder().proxies(proxies()).build().await;
    seed_login(&app, 1, "alice@example.com").await;
    let mut laptop = Jar::default();
    assert_eq!(
        sign_in(&app, &mut laptop, "alice@example.com", 1)
            .await
            .status,
        StatusCode::OK
    );
    let mut phone = Jar::default();
    assert_eq!(
        sign_in(&app, &mut phone, "alice@example.com", 2)
            .await
            .status,
        StatusCode::OK
    );
    let mut laptop_stream = app.events(&laptop).await;
    assert_eq!(laptop_stream.status, StatusCode::OK);
    laptop_stream.event("hello", SECOND).await;
    let mut phone_stream = app.events(&phone).await;
    phone_stream.event("hello", SECOND).await;

    // The laptop signs in again while it holds its session: that session ends,
    // and so does its stream, long before a heartbeat. The phone's goes on.
    let again = sign_in(&app, &mut laptop, "alice@example.com", 1).await;
    assert_eq!(again.status, StatusCode::OK, "{}", again.text());
    laptop_stream.end(SECOND).await;
    phone_stream.quiet(Duration::from_millis(900)).await;

    // The new session streams.
    let mut fresh = app.events(&laptop).await;
    assert_eq!(fresh.status, StatusCode::OK);
    fresh.event("hello", SECOND).await;
}

#[tokio::test]
async fn a_sign_in_that_ends_no_session_announces_no_revocation() {
    let app = TestApp::builder().proxies(proxies()).build().await;
    seed_login(&app, 1, "alice@example.com").await;
    let mut laptop = Jar::default();
    assert_eq!(
        sign_in(&app, &mut laptop, "alice@example.com", 1)
            .await
            .status,
        StatusCode::OK
    );
    // The session the browser presents is over already: nothing is ended now.
    sql(
        &app,
        "UPDATE ferret_sessions SET revoked_at = ?1",
        vec![i64::try_from(app.clock.now_unix()).expect("a time")],
    )
    .await;
    let mut heard = app.sync_events().subscribe_revocations();
    let again = sign_in(&app, &mut laptop, "alice@example.com", 1).await;
    assert_eq!(again.status, StatusCode::OK, "{}", again.text());
    assert!(matches!(
        heard.try_recv(),
        Err(tokio::sync::broadcast::error::TryRecvError::Empty)
    ));
}

#[tokio::test]
async fn shutdown_ends_open_streams_and_frees_their_slots() {
    let w = world().await;
    let mut first = open(&w).await;
    let mut second = open(&w).await;
    assert_eq!(live_streams(&w.app).await, 2);
    // The server is stopping: a graceful shutdown waits for every answer, so
    // the streams end now and not when their hour is out.
    w.app.state.streams.shutdown();
    first.end(SECOND * 2).await;
    second.end(SECOND * 2).await;
    wait_until(SECOND * 2, || w.app.state.streams.open() == 0).await;
    // One that opens after the stop says hello and ends.
    let mut late = w.app.events(&w.issued.jar).await;
    assert_eq!(late.status, StatusCode::OK);
    let (frames, ended) = late.frames(SECOND).await;
    assert!(ended, "{frames:?}");
    wait_until(SECOND * 2, || w.app.state.streams.open() == 0).await;
}

#[tokio::test]
async fn revoked_or_expired_session_ends_the_stream_at_the_next_heartbeat() {
    // Revoked in the database without a notification (an administrator, or an
    // earlier version of the code): the next heartbeat finds it.
    let w = world().await;
    let mut stream = open(&w).await;
    sql(
        &w.app,
        "UPDATE ferret_sessions SET revoked_at = ?1",
        vec![i64::try_from(w.app.clock.now_unix()).expect("a time")],
    )
    .await;
    stream.quiet(SHORT).await;
    tokio::time::pause();
    advance(HEARTBEAT + SECOND).await;
    stream.end(SECOND * 2).await;
    wait_until(SECOND, || w.app.state.streams.open() == 0).await;

    // Expired: idle for more than the limit of the vault origin.
    let w = world().await;
    let mut stream = open(&w).await;
    // A limit is inclusive: one second over it.
    let idle = u64::try_from(VAULT_IDLE_SECS).expect("a number") + 1;
    w.app.clock.advance(idle);
    stream.quiet(SHORT).await;
    advance(HEARTBEAT + SECOND).await;
    stream.end(SECOND * 2).await;
}

#[tokio::test]
async fn an_inactive_user_ends_the_stream_at_the_next_heartbeat() {
    let w = world().await;
    let mut stream = open(&w).await;
    sql(&w.app, "UPDATE users SET active = 0", vec![]).await;
    stream.quiet(SHORT).await;
    tokio::time::pause();
    advance(HEARTBEAT + SECOND).await;
    stream.end(SECOND * 2).await;
}

#[tokio::test]
async fn a_session_version_bump_ends_the_stream_at_the_next_heartbeat() {
    let w = world().await;
    let mut stream = open(&w).await;
    sql(
        &w.app,
        "UPDATE users SET session_version = session_version + 1",
        vec![],
    )
    .await;
    stream.quiet(SHORT).await;
    tokio::time::pause();
    advance(HEARTBEAT + SECOND).await;
    stream.end(SECOND * 2).await;
    wait_until(SECOND, || w.app.state.streams.open() == 0).await;
}

#[tokio::test]
async fn a_valid_session_survives_its_heartbeats() {
    let w = world().await;
    let mut stream = open(&w).await;
    tokio::time::pause();
    for _ in 0..3 {
        advance(HEARTBEAT + SECOND).await;
        stream.comment(SECOND * 2).await;
    }
    assert_eq!(live_streams(&w.app).await, 1);
}

#[tokio::test]
async fn stream_ends_after_the_lifetime() {
    assert_eq!(LIFETIME, Duration::from_secs(3600));
    let w = world().await;
    let mut stream = open(&w).await;
    tokio::time::pause();
    advance(LIFETIME - SECOND).await;
    // Comments on the way, and still open.
    let (frames, ended) = stream.frames(SHORT).await;
    assert!(!ended, "{frames:?}");
    assert!(frames.iter().all(|f| matches!(f, Frame::Comment(_))));
    advance(SECOND * 2).await;
    stream.end(SECOND * 2).await;
    wait_until(SECOND, || w.app.state.streams.open() == 0).await;
}

// ------------------------------------------------------------------- the places

#[tokio::test]
async fn third_stream_of_a_device_is_429_with_retry_after_30() {
    let w = world().await;
    let first = open(&w).await;
    let _second = open(&w).await;
    let mut third = w.app.events(&w.issued.jar).await;
    assert_eq!(third.status, StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(third.header("retry-after"), "30");
    assert_eq!(third.error().await, "throttled");
    assert_eq!(live_streams(&w.app).await, 2);
    drop(first);
}

#[tokio::test]
async fn the_same_device_id_in_another_vault_has_its_own_slots() {
    let w = world().await;
    let other = seed(&w.app, 2).await;
    let theirs = issue(&w.app, other.user_id, Origin::Vault, SessionScope::Full, 1).await;
    let mut held = Vec::new();
    for _ in 0..2 {
        held.push(open(&w).await);
        let mut stream = w.app.events(&theirs.jar).await;
        assert_eq!(stream.status, StatusCode::OK);
        stream.event("hello", SECOND).await;
        held.push(stream);
    }
    assert_eq!(live_streams(&w.app).await, 4);
    // And each vault's device is still held to two.
    assert_eq!(
        w.app.events(&w.issued.jar).await.status,
        StatusCode::TOO_MANY_REQUESTS
    );
    assert_eq!(
        w.app.events(&theirs.jar).await.status,
        StatusCode::TOO_MANY_REQUESTS
    );
}

#[tokio::test]
async fn the_41st_stream_of_a_vault_is_429() {
    let w = world().await;
    let mut held = Vec::new();
    for n in 1..=40u8 {
        let issued = issue(
            &w.app,
            w.seeded.user_id,
            Origin::Vault,
            SessionScope::Full,
            n,
        )
        .await;
        let mut stream = w.app.events(&issued.jar).await;
        assert_eq!(stream.status, StatusCode::OK, "stream {n}");
        stream.event("hello", SECOND).await;
        held.push(stream);
    }
    let last = issue(
        &w.app,
        w.seeded.user_id,
        Origin::Vault,
        SessionScope::Full,
        41,
    )
    .await;
    let mut refused = w.app.events(&last.jar).await;
    assert_eq!(refused.status, StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(refused.header("retry-after"), "30");
    assert_eq!(refused.error().await, "throttled");
    // Another vault is not held back by it.
    let other = seed(&w.app, 2).await;
    let theirs = issue(&w.app, other.user_id, Origin::Vault, SessionScope::Full, 1).await;
    assert_eq!(w.app.events(&theirs.jar).await.status, StatusCode::OK);
}

#[tokio::test]
async fn closing_a_stream_frees_its_slot() {
    let w = world().await;
    let first = open(&w).await;
    let second = open(&w).await;
    assert_eq!(
        w.app.events(&w.issued.jar).await.status,
        StatusCode::TOO_MANY_REQUESTS
    );
    // The client goes away: its place is free as soon as the task sees it.
    drop(first);
    wait_until(SECOND * 2, || w.app.state.streams.open() == 1).await;
    let mut third = w.app.events(&w.issued.jar).await;
    assert_eq!(third.status, StatusCode::OK);
    third.event("hello", SECOND).await;
    drop(second);
    drop(third);
    wait_until(SECOND * 2, || w.app.state.streams.open() == 0).await;
}

#[tokio::test]
async fn a_refused_request_takes_no_slot() {
    let w = world().await;
    let held = open(&w).await;
    let _held2 = open(&w).await;
    for _ in 0..5 {
        assert_eq!(
            w.app.events(&w.issued.jar).await.status,
            StatusCode::TOO_MANY_REQUESTS
        );
    }
    assert_eq!(live_streams(&w.app).await, 2);
    drop(held);
    wait_until(SECOND * 2, || w.app.state.streams.open() == 1).await;
    assert_eq!(w.app.events(&w.issued.jar).await.status, StatusCode::OK);
}

#[test]
fn the_total_cap_holds() {
    let streams = EventStreams::new(2, 40, 256);
    let mut slots = Vec::new();
    // Seven vaults of 40 devices (280 would fit the vaults, but not the server).
    'fill: for vault in 0..7u8 {
        for device in 0..40u8 {
            let vault_id = VaultId::from_bytes([vault; 16]);
            let device_id = ferret_server::ids::DeviceId([device; 16]);
            match streams.acquire(&vault_id, &device_id) {
                Some(slot) => slots.push(slot),
                None => break 'fill,
            }
        }
    }
    assert_eq!(slots.len(), 256);
    assert_eq!(streams.open(), 256);
    let vault_id = VaultId::from_bytes([6; 16]);
    let device_id = ferret_server::ids::DeviceId([39; 16]);
    assert!(streams.acquire(&vault_id, &device_id).is_none());
    // A place that is given back is the next one taken, and not one more.
    slots.pop();
    let again = streams.acquire(&vault_id, &device_id);
    assert!(again.is_some());
    assert!(
        streams
            .acquire(&vault_id, &ferret_server::ids::DeviceId([40; 16]))
            .is_none()
    );
    drop((slots, again));
    assert_eq!(streams.open(), 0);
}

#[test]
fn the_limits_are_per_device_per_vault_and_in_all() {
    let streams = EventStreams::new(2, 3, 4);
    let (v1, v2) = (VaultId::from_bytes([1; 16]), VaultId::from_bytes([2; 16]));
    let d = |n: u8| ferret_server::ids::DeviceId([n; 16]);
    let a = streams.acquire(&v1, &d(1)).expect("1");
    let b = streams.acquire(&v1, &d(1)).expect("2");
    assert!(streams.acquire(&v1, &d(1)).is_none(), "two per device");
    let c = streams.acquire(&v1, &d(2)).expect("3");
    assert!(streams.acquire(&v1, &d(3)).is_none(), "three per vault");
    let e = streams
        .acquire(&v2, &d(1))
        .expect("another vault, same device");
    assert!(streams.acquire(&v2, &d(2)).is_none(), "four in all");
    drop((a, b, c, e));
    assert_eq!(streams.open(), 0);
    // Nothing is left behind in the table: the places are all free again.
    for _ in 0..2 {
        assert!(streams.acquire(&v1, &d(1)).is_some());
    }
}

// ---------------------------------------------------------------- what is refused

#[tokio::test]
async fn missing_protocol_header_is_400_and_cross_site_fetch_metadata_is_403() {
    let w = world().await;
    let cookie = w.issued.jar.header().expect("cookies");

    let mut missing = w
        .app
        .open_stream(
            Req::get("/api/sync/events")
                .header("cookie", &cookie)
                .build(),
        )
        .await;
    assert_eq!(missing.status, StatusCode::BAD_REQUEST);
    assert_eq!(missing.error().await, "protocol_header_missing");

    let mut wrong = w
        .app
        .open_stream(
            Req::get("/api/sync/events")
                .header("cookie", &cookie)
                .header("ferret-protocol", "2")
                .build(),
        )
        .await;
    assert_eq!(wrong.status, StatusCode::BAD_REQUEST);
    assert_eq!(wrong.error().await, "protocol_header_missing");

    for site in ["cross-site", "same-site", "none", ""] {
        let mut refused = w
            .app
            .open_stream(
                Req::get("/api/sync/events")
                    .header("cookie", &cookie)
                    .header("ferret-protocol", "1")
                    .header("sec-fetch-site", site)
                    .build(),
            )
            .await;
        assert_eq!(refused.status, StatusCode::FORBIDDEN, "{site:?}");
        assert_eq!(refused.error().await, "forbidden_origin");
    }

    // No fetch metadata at all (curl, a non-browser client) is let through, and
    // so is the browser's own word that it is the same origin.
    let mut plain = w
        .app
        .open_stream(
            Req::get("/api/sync/events")
                .header("cookie", &cookie)
                .header("ferret-protocol", "1")
                .build(),
        )
        .await;
    assert_eq!(plain.status, StatusCode::OK);
    plain.event("hello", SECOND).await;
    let mut same = w.app.events(&w.issued.jar).await;
    assert_eq!(same.status, StatusCode::OK);
    same.event("hello", SECOND).await;

    // The refusals took no place.
    assert_eq!(live_streams(&w.app).await, 2);
}

#[tokio::test]
async fn without_a_session_is_401_and_no_slot_is_taken() {
    let w = world().await;
    let none = Jar::default();
    let mut stream = w.app.events(&none).await;
    assert_eq!(stream.status, StatusCode::UNAUTHORIZED);
    assert_eq!(stream.error().await, "unauthorized");

    // A cookie that names no session, and the cookies of a session that ended.
    let mut forged = Jar::default();
    forged.set("__Host-ferret_sid", "x".repeat(43).as_str());
    assert_eq!(w.app.events(&forged).await.status, StatusCode::UNAUTHORIZED);
    sql(
        &w.app,
        "UPDATE ferret_sessions SET revoked_at = ?1",
        vec![i64::try_from(w.app.clock.now_unix()).expect("a time")],
    )
    .await;
    assert_eq!(
        w.app.events(&w.issued.jar).await.status,
        StatusCode::UNAUTHORIZED
    );
    // The check of the session comes before the check of the headers: a caller
    // with no session learns nothing about what else is wrong.
    let mut bare = w
        .app
        .open_stream(Req::get("/api/sync/events").build())
        .await;
    assert_eq!(bare.status, StatusCode::UNAUTHORIZED);
    assert_eq!(bare.error().await, "unauthorized");
    assert_eq!(live_streams(&w.app).await, 0);
}

#[tokio::test]
async fn an_admin_session_has_no_stream_on_the_vault_listener() {
    let w = world().await;
    let admin = issue(
        &w.app,
        w.seeded.user_id,
        Origin::Admin,
        SessionScope::Full,
        1,
    )
    .await;
    assert_eq!(
        w.app.events(&admin.jar).await.status,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(live_streams(&w.app).await, 0);
}

#[tokio::test]
async fn admin_listener_has_no_events_route() {
    let w = world().await;
    let admin = issue(
        &w.app,
        w.seeded.user_id,
        Origin::Admin,
        SessionScope::Full,
        1,
    )
    .await;
    for jar in [&admin.jar, &w.issued.jar, &Jar::default()] {
        let mut req = Req::get("/api/sync/events")
            .header("ferret-protocol", "1")
            .header("sec-fetch-site", "same-origin");
        if let Some(cookie) = jar.header() {
            req = req.header("cookie", &cookie);
        }
        let res = w.app.call_raw(Which::Admin, req.build()).await;
        assert_eq!(res.status, StatusCode::NOT_FOUND);
    }
    assert_eq!(live_streams(&w.app).await, 0);
}

// --------------------------------------------------------------------- the pool

#[tokio::test]
async fn stream_holds_no_pool_connection_between_heartbeats() {
    let w = world().await;
    let max = w.app.state.core.db.status().max_size;
    let mut held = Vec::new();
    // More streams than the pool has connections.
    let count = u8::try_from(max.saturating_add(3).min(40)).expect("a small number");
    for n in 1..=count {
        let issued = issue(
            &w.app,
            w.seeded.user_id,
            Origin::Vault,
            SessionScope::Full,
            n,
        )
        .await;
        let mut stream = w.app.events(&issued.jar).await;
        assert_eq!(stream.status, StatusCode::OK, "stream {n}");
        stream.event("hello", SECOND).await;
        held.push(stream);
    }
    assert!(held.len() > max || max >= 40);
    // Every connection is back in the pool, and the pool still serves.
    let status = w.app.state.core.db.status();
    assert_eq!(
        i64::try_from(status.available).expect("a number"),
        i64::try_from(status.size).expect("a number"),
        "{status:?}"
    );
    assert_eq!(status.waiting, 0);
    let res = w
        .app
        .call_raw(
            Which::Vault,
            Req::get("/api/sync/changes?since=0")
                .header("cookie", &w.issued.jar.header().expect("cookies"))
                .build(),
        )
        .await;
    assert_eq!(res.status, StatusCode::OK, "{}", res.text());
}

// ----------------------------------------------------------------- still_valid

async fn still(app: &TestApp, issued: &Issued, origin: Origin, version: i64) -> bool {
    let sid = issued.sid;
    let now = i64::try_from(app.clock.now_unix()).expect("a time");
    app.state
        .vault_db
        .with_conn(move |conn| Ok(still_valid(conn, &sid, origin, version, now)?))
        .await
        .expect("a check")
}

/// What the extractor of the same listener says to the cookies of `issued`.
async fn extractor(app: &TestApp, issued: &Issued, origin: Origin) -> bool {
    let path = match origin {
        Origin::Vault => "/vault",
        Origin::Admin => "/admin",
    };
    get_with(&router(app), &issued.jar, path).await.status == StatusCode::OK
}

/// One cause of an ended session, applied to a fresh app; the extractor and
/// `still_valid` must say the same, and what is expected.
async fn agrees(cause: &str, expected: bool, apply: impl AsyncFnOnce(&TestApp, &Seeded, &Issued)) {
    let w = world().await;
    apply(&w.app, &w.seeded, &w.issued).await;
    let version = w.issued.claims.version;
    let from_function = still(&w.app, &w.issued, Origin::Vault, version).await;
    let from_extractor = extractor(&w.app, &w.issued, Origin::Vault).await;
    assert_eq!(
        from_function, from_extractor,
        "{cause}: still_valid and the extractor differ"
    );
    assert_eq!(from_function, expected, "{cause}");
}

#[tokio::test]
async fn still_valid_agrees_with_the_extractor_for_every_cause() {
    agrees("a good session", true, async |_, _, _| {}).await;
    agrees("revoked", false, async |app, _, _| {
        let now = i64::try_from(app.clock.now_unix()).expect("a time");
        sql(app, "UPDATE ferret_sessions SET revoked_at = ?1", vec![now]).await;
    })
    .await;
    agrees("no row", false, async |app, _, _| {
        batch(app, "DELETE FROM ferret_sessions").await;
    })
    .await;
    agrees("idle exactly at the limit", true, async |app, _, _| {
        app.clock
            .advance(u64::try_from(VAULT_IDLE_SECS).expect("n"));
    })
    .await;
    agrees("idle one second over", false, async |app, _, _| {
        app.clock
            .advance(u64::try_from(VAULT_IDLE_SECS).expect("n") + 1);
    })
    .await;
    agrees("absolute exactly at the limit", true, async |app, _, _| {
        app.clock
            .advance(u64::try_from(VAULT_ABSOLUTE_SECS).expect("n"));
        let now = i64::try_from(app.clock.now_unix()).expect("a time");
        sql(app, "UPDATE ferret_sessions SET last_seen = ?1", vec![now]).await;
    })
    .await;
    agrees("absolute one second over", false, async |app, _, _| {
        app.clock
            .advance(u64::try_from(VAULT_ABSOLUTE_SECS).expect("n") + 1);
        let now = i64::try_from(app.clock.now_unix()).expect("a time");
        sql(app, "UPDATE ferret_sessions SET last_seen = ?1", vec![now]).await;
    })
    .await;
    agrees("the user is inactive", false, async |app, _, _| {
        batch(app, "UPDATE users SET active = 0").await;
    })
    .await;
    agrees("the session version moved", false, async |app, _, _| {
        batch(
            app,
            "UPDATE users SET session_version = session_version + 1",
        )
        .await;
    })
    .await;
    agrees("the user is gone", false, async |app, _, _| {
        batch(
            app,
            "PRAGMA foreign_keys = OFF; DELETE FROM users; PRAGMA foreign_keys = ON;",
        )
        .await;
    })
    .await;
    agrees("the account is gone", false, async |app, _, _| {
        batch(
            app,
            "PRAGMA foreign_keys = OFF; DELETE FROM ferret_vaults; PRAGMA foreign_keys = ON;",
        )
        .await;
    })
    .await;
    agrees("the vault is gone", false, async |app, _, _| {
        batch(
            app,
            "PRAGMA foreign_keys = OFF; DELETE FROM ferret_accounts; PRAGMA foreign_keys = ON;",
        )
        .await;
    })
    .await;

    // The scope: only `full` counts.
    for scope in [
        SessionScope::Pending2fa,
        SessionScope::AccountReset,
        SessionScope::Unverified,
    ] {
        let w = world().await;
        let issued = issue(&w.app, w.seeded.user_id, Origin::Vault, scope, 5).await;
        let version = issued.claims.version;
        assert!(!still(&w.app, &issued, Origin::Vault, version).await);
        assert!(!extractor(&w.app, &issued, Origin::Vault).await);
    }
}

#[tokio::test]
async fn still_valid_holds_the_origin_the_version_and_the_admin_limits() {
    let w = world().await;
    let version = w.issued.claims.version;
    assert!(still(&w.app, &w.issued, Origin::Vault, version).await);
    // The right session on the wrong listener, and a version that is not the
    // user's.
    assert!(!still(&w.app, &w.issued, Origin::Admin, version).await);
    assert!(!still(&w.app, &w.issued, Origin::Vault, version + 1).await);
    assert!(!still(&w.app, &w.issued, Origin::Vault, version - 1).await);

    // An admin session is checked on its own listener, with its own limits.
    let admin = issue(
        &w.app,
        w.seeded.user_id,
        Origin::Admin,
        SessionScope::Full,
        1,
    )
    .await;
    let version = admin.claims.version;
    assert!(!still(&w.app, &admin, Origin::Vault, version).await);
    assert!(still(&w.app, &admin, Origin::Admin, version).await);
    assert!(extractor(&w.app, &admin, Origin::Admin).await);
    w.app
        .clock
        .advance(u64::try_from(ADMIN_IDLE_SECS).expect("n") + 1);
    assert!(!still(&w.app, &admin, Origin::Admin, version).await);
    assert!(!extractor(&w.app, &admin, Origin::Admin).await);
    // The vault session has 12 hours of idle time and is still good.
    let version = w.issued.claims.version;
    assert!(still(&w.app, &w.issued, Origin::Vault, version).await);
}

#[tokio::test]
async fn still_valid_reads_and_never_writes() {
    let w = world().await;
    let before = w.app.clock.now_unix();
    w.app.clock.advance(3 * 3600);
    let version = w.issued.claims.version;
    assert!(still(&w.app, &w.issued, Origin::Vault, version).await);
    let sid = w.issued.sid;
    let last_seen: i64 = w
        .app
        .state
        .vault_db
        .with_conn(move |conn| {
            Ok(conn.query_row(
                "SELECT last_seen FROM ferret_sessions WHERE sid_hash = ?1",
                [sid.0.as_slice()],
                |r| r.get(0),
            )?)
        })
        .await
        .expect("last_seen");
    assert_eq!(last_seen, i64::try_from(before).expect("a time"));
}
