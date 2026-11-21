//! `POST /api/sync/import` and the batches that name the window it opens: an
//! import's operations are counted apart from the per-device rate, and only
//! the writes that store something new are taken from the window.
//! Spec: Fase 1 § 8.2.
//!
//! The tests drive the whole vault router of a `TestApp`. The window is kept in
//! memory, so "a restart" is a router built over a state with an empty set of
//! windows and the same database.

#![allow(non_snake_case)]

mod support;

use std::time::{Duration, Instant};

use axum::body::{Body, to_bytes};
use axum::extract::ConnectInfo;
use axum::http::{HeaderValue, Method, Request, StatusCode, header};
use ferret_core::testing::TestRng;
use ferret_core::{ItemBody, ItemType, UnlockedVault, VaultContext, VaultKey, encrypt_item};
use ferret_server::auth::session::Origin;
use ferret_server::ids::{ItemId, SidHash};
use ferret_server::server;
use ferret_server::state::ImportWindows;
use ferret_server::vault::rate::{IMPORT_WINDOW_SECS, RateConfig};
use ferret_server::wire::{BatchRes, ImportWindowRes, b64url, hex16};
use ferret_server_auth::SessionScope;
use serde_json::{Value, json};
use support::accounts::{TestAccount, add_account_to_app};
use support::session::{issue, make_fresh, reset_session};
use support::{Jar, PEER, Req, Res, TestApp, Which};
use tower::ServiceExt as _;

/// A test user with a session of its first device, fresh or not.
struct User {
    account: TestAccount,
    jar: Jar,
    sid: SidHash,
    vault: UnlockedVault,
}

async fn user(app: &TestApp, n: u8) -> User {
    let account = add_account_to_app(app, n).await;
    let issued = issue(app, account.user_id, Origin::Vault, SessionScope::Full, n).await;
    let vault = UnlockedVault::from_vault_key(
        VaultContext {
            account_id: account.account_id,
            vault_id: account.vault_id,
            vk_epoch: 1,
        },
        VaultKey::from_test_bytes([n; 32]),
    )
    .expect("an unlocked vault");
    User {
        account,
        jar: issued.jar,
        sid: issued.sid,
        vault,
    }
}

/// A user that proved the master password again just now.
async fn fresh_user(app: &TestApp, n: u8) -> User {
    let u = user(app, n).await;
    make_fresh(app, u.sid).await;
    u
}

/// Another device of the same account, signed in and fresh.
async fn other_device(app: &TestApp, u: &User, device_n: u8) -> (Jar, SidHash) {
    let issued = issue(
        app,
        u.account.user_id,
        Origin::Vault,
        SessionScope::Full,
        device_n,
    )
    .await;
    make_fresh(app, issued.sid).await;
    (issued.jar, issued.sid)
}

fn item(n: u32) -> ItemId {
    let mut bytes = [0u8; 16];
    bytes[0] = 0x10;
    bytes[1..5].copy_from_slice(&n.to_be_bytes());
    ItemId::from_bytes(bytes)
}

fn idem(n: u32) -> [u8; 16] {
    let mut bytes = [0xee; 16];
    bytes[..4].copy_from_slice(&n.to_be_bytes());
    bytes
}

/// A live operation that creates item `n`.
fn op(u: &User, n: u32) -> Value {
    op_with_notes(u, n, format!("notes of {n}"))
}

/// A live operation that creates item `n` with these notes.
fn op_with_notes(u: &User, n: u32, notes: String) -> Value {
    let id = item(n);
    let mut body = ItemBody::new(ItemType::Note, format!("note {n}"), 1);
    body.notes = Some(notes);
    let sealed = encrypt_item(
        &mut TestRng::new(format!("import/{n}").as_bytes()),
        &u.vault,
        id,
        1,
        &body,
        None,
    )
    .expect("an item");
    json!({
        "id": hex16::encode(id.as_bytes()),
        "base_rev": 0,
        "blob": b64url::encode(&sealed.envelope),
        "tag": b64url::encode(&sealed.tag),
        "idem": hex16::encode(&idem(n)),
    })
}

fn ops(u: &User, from: u32, count: u32) -> Vec<Value> {
    (from..from + count).map(|n| op(u, n)).collect()
}

fn request(method: Method, uri: &str, jar: &Jar, body: Option<&Value>) -> Request<Body> {
    let mut req = Req::new(method, uri)
        .page_fetch(Which::Vault)
        .header("sec-fetch-site", "same-origin");
    if let Some(cookie) = jar.header() {
        req = req.header("cookie", &cookie);
    }
    if let Some(body) = body {
        req = req.json(body);
    }
    req.build()
}

async fn send(app: &TestApp, method: Method, uri: &str, jar: &Jar, body: Option<&Value>) -> Res {
    app.call_raw(Which::Vault, request(method, uri, jar, body))
        .await
}

/// Asks for a window of `ops` operations.
async fn open(app: &TestApp, jar: &Jar, ops: u64) -> Res {
    send(
        app,
        Method::POST,
        "/api/sync/import",
        jar,
        Some(&json!({ "ops": ops })),
    )
    .await
}

/// The id of the window in a `200` answer of the import route; the answer must
/// read as the contract says.
fn window_of(res: &Res) -> [u8; 16] {
    assert_eq!(res.status, StatusCode::OK, "{}", res.text());
    let parsed: ImportWindowRes = serde_json::from_slice(&res.body).expect("a window answer");
    assert_eq!(parsed.expires_in, IMPORT_WINDOW_SECS);
    parsed.window_id
}

/// A batch, with the window it names if there is one.
async fn batch(app: &TestApp, jar: &Jar, ops: &[Value], window: Option<[u8; 16]>) -> Res {
    let mut body = json!({ "ops": ops });
    if let Some(window) = window {
        body["import_window"] = json!(hex16::encode(&window));
    }
    send(app, Method::POST, "/api/sync/batch", jar, Some(&body)).await
}

fn error(res: &Res) -> String {
    res.json()["error"].as_str().unwrap_or("").to_string()
}

fn statuses(res: &Res) -> Vec<u64> {
    assert_eq!(res.status, StatusCode::OK, "{}", res.text());
    let parsed: BatchRes = serde_json::from_slice(&res.body).expect("a batch answer");
    parsed.validate().expect("a valid batch answer");
    res.json()["results"]
        .as_array()
        .expect("an array")
        .iter()
        .map(|r| r["status"].as_u64().expect("a status"))
        .collect()
}

fn now(app: &TestApp) -> i64 {
    use ferret_server_auth::Clock as _;
    i64::try_from(app.clock.now_unix()).expect("a time")
}

/// The operations the window of `u`'s vault has left.
fn left(app: &TestApp, u: &User) -> Option<u32> {
    app.state
        .import_windows
        .remaining(&u.account.vault_id, now(app))
}

async fn db<T: Send + 'static>(
    app: &TestApp,
    f: impl FnOnce(&mut rusqlite::Connection) -> rusqlite::Result<T> + Send + 'static,
) -> T {
    app.state
        .vault_db
        .with_conn(move |conn| Ok(f(conn)?))
        .await
        .expect("a database call")
}

/// How many rows (live and deleted, the manifest included) the vault has.
async fn item_rows(app: &TestApp, u: &User) -> i64 {
    let vault = u.account.vault_id;
    db(app, move |c| {
        c.query_row(
            "SELECT COUNT(*) FROM ferret_items WHERE vault_id = ?1",
            [vault.as_bytes().as_slice()],
            |r| r.get(0),
        )
    })
    .await
}

async fn vault_seq(app: &TestApp, u: &User) -> i64 {
    let vault = u.account.vault_id;
    db(app, move |c| {
        c.query_row(
            "SELECT seq FROM ferret_vaults WHERE vault_id = ?1",
            [vault.as_bytes().as_slice()],
            |r| r.get(0),
        )
    })
    .await
}

// ---------------------------------------------------------------------------
// Opening a window.

#[tokio::test]
async fn opening_a_window_needs_fresh_reauth() {
    let app = TestApp::new().await;
    let u = user(&app, 1).await;

    // No session at all.
    let none = open(&app, &Jar::default(), 10).await;
    assert_eq!(none.status, StatusCode::UNAUTHORIZED);

    // A session that never proved the password again.
    let res = open(&app, &u.jar, 10).await;
    assert_eq!(res.status, StatusCode::FORBIDDEN, "{}", res.text());
    assert_eq!(error(&res), "reauth_required");
    assert_eq!(left(&app, &u), None, "no window was opened");

    // A proof that is older than five minutes.
    make_fresh(&app, u.sid).await;
    app.clock.advance(301);
    let stale = open(&app, &u.jar, 10).await;
    assert_eq!(stale.status, StatusCode::FORBIDDEN);
    assert_eq!(error(&stale), "reauth_required");

    // A proof of the clock's time: the window opens, and it holds what was asked.
    make_fresh(&app, u.sid).await;
    let res = open(&app, &u.jar, 10).await;
    window_of(&res);
    assert_eq!(res.json()["ops"], 10);
    assert_eq!(res.header("cache-control"), "no-store");
    assert_eq!(left(&app, &u), Some(10));

    // A reset session reaches nothing of the sync routes.
    let app = TestApp::new().await;
    let (_, reset) = reset_session(&app).await;
    let res = open(&app, &reset.jar, 10).await;
    assert_eq!(res.status, StatusCode::FORBIDDEN, "{}", res.text());
}

#[tokio::test]
async fn a_request_that_is_not_a_window_request_is_400() {
    let app = TestApp::new().await;
    let u = fresh_user(&app, 1).await;
    let bodies: Vec<(&str, Value)> = vec![
        ("no ops", json!({})),
        ("zero ops", json!({ "ops": 0 })),
        ("ops is text", json!({ "ops": "5" })),
        ("a negative number", json!({ "ops": -1 })),
        ("a fraction", json!({ "ops": 1.5 })),
        ("above u32", json!({ "ops": 4_294_967_296u64 })),
        ("an unknown field", json!({ "ops": 5, "extra": 1 })),
    ];
    for (name, body) in bodies {
        let res = send(&app, Method::POST, "/api/sync/import", &u.jar, Some(&body)).await;
        assert_eq!(
            res.status,
            StatusCode::BAD_REQUEST,
            "{name}: {}",
            res.text()
        );
        assert_eq!(error(&res), "bad_request", "{name}");
    }
    let mut req = request(Method::POST, "/api/sync/import", &u.jar, None);
    *req.body_mut() = Body::from("not json");
    let res = app.call_raw(Which::Vault, req).await;
    assert_eq!(res.status, StatusCode::BAD_REQUEST);
    let mut req = request(Method::POST, "/api/sync/import", &u.jar, None);
    *req.body_mut() = Body::from(vec![b' '; 4096]);
    let res = app.call_raw(Which::Vault, req).await;
    assert_eq!(res.status, StatusCode::PAYLOAD_TOO_LARGE);
    assert_eq!(left(&app, &u), None, "no window was opened");
}

#[tokio::test]
async fn ops_above_the_free_quota_are_413() {
    let app = TestApp::new().await;
    let u = fresh_user(&app, 1).await;
    // The vault holds its manifest row: 9 999 of the 10 000 are free.
    let over = open(&app, &u.jar, 10_000).await;
    assert_eq!(
        over.status,
        StatusCode::PAYLOAD_TOO_LARGE,
        "{}",
        over.text()
    );
    assert_eq!(error(&over), "quota_exceeded");
    assert_eq!(left(&app, &u), None);
    let huge = open(&app, &u.jar, u64::from(u32::MAX)).await;
    assert_eq!(huge.status, StatusCode::PAYLOAD_TOO_LARGE);

    // Fewer rows are free once the vault holds more.
    let vault = u.account.vault_id;
    db(&app, move |c| {
        c.execute(
            "UPDATE ferret_vaults SET item_count = 9990 WHERE vault_id = ?1",
            [vault.as_bytes().as_slice()],
        )
    })
    .await;
    let over = open(&app, &u.jar, 11).await;
    assert_eq!(over.status, StatusCode::PAYLOAD_TOO_LARGE);
    window_of(&open(&app, &u.jar, 10).await);
    assert_eq!(left(&app, &u), Some(10));

    // A vault whose bytes are used up has no room for one operation.
    let app = TestApp::new().await;
    let u = fresh_user(&app, 1).await;
    let vault = u.account.vault_id;
    db(&app, move |c| {
        c.execute(
            "UPDATE ferret_vaults SET bytes_used = 268435456 WHERE vault_id = ?1",
            [vault.as_bytes().as_slice()],
        )
    })
    .await;
    let full = open(&app, &u.jar, 1).await;
    assert_eq!(full.status, StatusCode::PAYLOAD_TOO_LARGE);
    assert_eq!(error(&full), "quota_exceeded");

    // The most the vault has room for is a window.
    let app = TestApp::new().await;
    let u = fresh_user(&app, 1).await;
    window_of(&open(&app, &u.jar, 9_999).await);
}

#[tokio::test]
async fn one_open_window_per_vault() {
    let app = TestApp::new().await;
    let u = fresh_user(&app, 1).await;
    let first = window_of(&open(&app, &u.jar, 10).await);

    // Another device of the vault does not get a second one.
    let (jar2, _) = other_device(&app, &u, 2).await;
    let other = open(&app, &jar2, 10).await;
    assert_eq!(other.status, StatusCode::CONFLICT, "{}", other.text());
    assert_eq!(error(&other), "import_window_open");
    assert_eq!(left(&app, &u), Some(10), "the window is as it was");

    // The device that holds it may replace it: the old one closes at once.
    let replaced = window_of(&open(&app, &u.jar, 12).await);
    assert_ne!(first, replaced);
    assert_eq!(left(&app, &u), Some(12));
    let old = batch(&app, &u.jar, &ops(&u, 1, 1), Some(first)).await;
    assert_eq!(old.status, StatusCode::CONFLICT, "{}", old.text());
    assert_eq!(error(&old), "import_window_invalid");
    // Still one window for the vault: the other device is refused as before.
    let other = open(&app, &jar2, 10).await;
    assert_eq!(error(&other), "import_window_open");

    // Another vault has its own.
    let v2 = fresh_user(&app, 2).await;
    window_of(&open(&app, &v2.jar, 10).await);

    // A window that is used up makes room for the next, for any device.
    let used = batch(&app, &u.jar, &ops(&u, 1, 12), Some(replaced)).await;
    assert_eq!(statuses(&used), vec![200; 12]);
    assert_eq!(left(&app, &u), Some(0));
    let second = window_of(&open(&app, &jar2, 5).await);
    assert_ne!(replaced, second);

    // So does one that has ended; the old id is not the new window.
    app.clock.advance(u64::from(IMPORT_WINDOW_SECS));
    make_fresh(&app, u.sid).await;
    let third = window_of(&open(&app, &u.jar, 5).await);
    assert_ne!(second, third);
    let old = batch(&app, &jar2, &ops(&u, 100, 1), Some(second)).await;
    assert_eq!(old.status, StatusCode::CONFLICT);
    assert_eq!(error(&old), "import_window_invalid");
}

#[tokio::test]
async fn repeats_need_neither_window_operations_nor_free_rows() {
    // The vault has room for exactly 100 more rows.
    let app = TestApp::new().await;
    let u = fresh_user(&app, 1).await;
    let vault = u.account.vault_id;
    db(&app, move |c| {
        c.execute(
            "UPDATE ferret_vaults SET item_count = 9900 WHERE vault_id = ?1",
            [vault.as_bytes().as_slice()],
        )
    })
    .await;
    let window = window_of(&open(&app, &u.jar, 100).await);
    let last = ops(&u, 1, 100);
    let sent = batch(&app, &u.jar, &last, Some(window)).await;
    assert_eq!(statuses(&sent), vec![200; 100]);
    assert_eq!(left(&app, &u), Some(0), "the window is spent");
    let seq = vault_seq(&app, &u).await;
    let stored_rows = item_rows(&app, &u).await;

    // The vault is full, so there is no room for a window of any size.
    let none = open(&app, &u.jar, 1).await;
    assert_eq!(none.status, StatusCode::PAYLOAD_TOO_LARGE);

    // The answer of the last batch was lost. The retry is all repeats: it goes
    // through the spent window, and then through the ended one, and writes
    // nothing.
    for round in 0..2 {
        let res = batch(&app, &u.jar, &last, Some(window)).await;
        assert_eq!(statuses(&res), vec![200; 100], "round {round}");
        let results = res.json()["results"].clone();
        assert!(
            results
                .as_array()
                .expect("an array")
                .iter()
                .all(|r| r["replayed"] == true),
            "round {round}"
        );
        assert_eq!(vault_seq(&app, &u).await, seq);
        assert_eq!(item_rows(&app, &u).await, stored_rows, "no duplicates");
        app.clock.advance(u64::from(IMPORT_WINDOW_SECS));
        make_fresh(&app, u.sid).await;
    }
    assert_eq!(left(&app, &u), None);

    // A new item has no window to use, and a batch of a repeat and a new item
    // is refused as a whole.
    let new = batch(&app, &u.jar, &ops(&u, 200, 1), Some(window)).await;
    assert_eq!(new.status, StatusCode::CONFLICT);
    assert_eq!(error(&new), "import_window_invalid");
    let mixed = vec![last[0].clone(), op(&u, 201)];
    let res = batch(&app, &u.jar, &mixed, Some(window)).await;
    assert_eq!(error(&res), "import_window_invalid");
    assert_eq!(vault_seq(&app, &u).await, seq);

    // A repeat in a batch of another device is no repeat: that device has its
    // own records.
    let (jar2, _) = other_device(&app, &u, 2).await;
    let res = batch(&app, &jar2, &last[..1], Some(window)).await;
    assert_eq!(error(&res), "import_window_invalid");
}

// ---------------------------------------------------------------------------
// Using it.

#[tokio::test]
async fn a_window_admits_its_ops_beyond_the_per_device_rate() {
    // One operation a second and room for four at once.
    let rate = RateConfig {
        ops_per_min: 60,
        ops_burst: 4,
        ..RateConfig::DEFAULT
    };
    let app = TestApp::builder().rate(rate).build().await;
    let u = fresh_user(&app, 1).await;

    // Without a window, the bucket lets one batch through and turns the next away.
    let one = batch(&app, &u.jar, &ops(&u, 1, 4), None).await;
    assert_eq!(statuses(&one), vec![200; 4]);
    let next = batch(&app, &u.jar, &ops(&u, 5, 4), None).await;
    assert_eq!(next.status, StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(error(&next), "throttled");

    // With a window of thirty, five batches of six go through at the same time.
    let window = window_of(&open(&app, &u.jar, 30).await);
    for batch_n in 0..5 {
        let res = batch(&app, &u.jar, &ops(&u, 100 + batch_n * 6, 6), Some(window)).await;
        assert_eq!(statuses(&res), vec![200; 6], "batch {batch_n}");
    }
    assert_eq!(left(&app, &u), Some(0));
    // The thirty-first operation is not in it. The window is spent, so the
    // batch is counted like any other: the bucket is empty, and once it has
    // refilled the answer is that the window is no use.
    let past = batch(&app, &u.jar, &ops(&u, 200, 1), Some(window)).await;
    assert_eq!(past.status, StatusCode::TOO_MANY_REQUESTS);
    app.clock.advance(60);
    let past = batch(&app, &u.jar, &ops(&u, 200, 1), Some(window)).await;
    assert_eq!(past.status, StatusCode::CONFLICT);
    assert_eq!(error(&past), "import_window_invalid");
}

#[tokio::test]
async fn the_byte_bucket_and_the_write_gate_still_apply() {
    let sample = {
        let app = TestApp::new().await;
        let u = user(&app, 1).await;
        serde_json::to_vec(&json!({
            "ops": ops(&u, 1, 20),
            "import_window": hex16::encode(&[0u8; 16]),
        }))
        .expect("a body")
        .len() as u64
    };
    // A bucket of one and a half batches, plenty of operations.
    let rate = RateConfig {
        bytes_per_min: sample + sample / 2,
        ops_burst: 10_000,
        ops_per_min: 10_000,
        ..RateConfig::DEFAULT
    };
    let app = TestApp::builder().rate(rate).gate(1, 0).build().await;
    let u = fresh_user(&app, 1).await;
    let window = window_of(&open(&app, &u.jar, 100).await);

    let first = batch(&app, &u.jar, &ops(&u, 1, 20), Some(window)).await;
    assert_eq!(statuses(&first), vec![200; 20]);
    assert_eq!(left(&app, &u), Some(80));
    let seq = vault_seq(&app, &u).await;

    // The bucket of bytes is short: nothing is written, the window keeps
    // everything it has, and the answer says when to come back.
    let short = batch(&app, &u.jar, &ops(&u, 21, 20), Some(window)).await;
    assert_eq!(
        short.status,
        StatusCode::TOO_MANY_REQUESTS,
        "{}",
        short.text()
    );
    assert_eq!(error(&short), "throttled");
    assert!(short.header("retry-after").parse::<u32>().expect("seconds") >= 1);
    assert_eq!(left(&app, &u), Some(80));
    assert_eq!(vault_seq(&app, &u).await, seq);

    // The queue is full: the same.
    app.clock.advance(60);
    let turn = app.state.write_gate.enter().await.expect("a free turn");
    let busy = batch(&app, &u.jar, &ops(&u, 21, 20), Some(window)).await;
    assert_eq!(
        busy.status,
        StatusCode::SERVICE_UNAVAILABLE,
        "{}",
        busy.text()
    );
    assert_eq!(error(&busy), "busy");
    assert_eq!(
        left(&app, &u),
        Some(80),
        "a turned away batch holds nothing"
    );
    assert_eq!(vault_seq(&app, &u).await, seq);
    drop(turn);

    // (The turned away batch used the bytes it sent, as a batch without a window does.)
    app.clock.advance(60);
    let ok = batch(&app, &u.jar, &ops(&u, 21, 20), Some(window)).await;
    assert_eq!(statuses(&ok), vec![200; 20]);
    assert_eq!(left(&app, &u), Some(60));
}

#[tokio::test]
async fn a_window_of_another_device_or_vault_is_refused() {
    let app = TestApp::new().await;
    let u = fresh_user(&app, 1).await;
    let window = window_of(&open(&app, &u.jar, 10).await);
    let seq = vault_seq(&app, &u).await;

    // Another device of the same account.
    let (jar2, _) = other_device(&app, &u, 2).await;
    let res = batch(&app, &jar2, &ops(&u, 1, 2), Some(window)).await;
    assert_eq!(res.status, StatusCode::CONFLICT, "{}", res.text());
    assert_eq!(error(&res), "import_window_invalid");

    // Another vault.
    let v2 = fresh_user(&app, 2).await;
    let res = batch(&app, &v2.jar, &ops(&v2, 1, 2), Some(window)).await;
    assert_eq!(res.status, StatusCode::CONFLICT);
    assert_eq!(error(&res), "import_window_invalid");
    assert_eq!(vault_seq(&app, &v2).await, 1);

    // An id nobody was given: the same answer, so it says nothing of whose
    // window it is.
    let res = batch(&app, &u.jar, &ops(&u, 1, 2), Some([7u8; 16])).await;
    assert_eq!(res.status, StatusCode::CONFLICT);
    assert_eq!(error(&res), "import_window_invalid");

    // None of them held or wrote anything, and the device that opened it still has it all.
    assert_eq!(vault_seq(&app, &u).await, seq);
    assert_eq!(left(&app, &u), Some(10));
    let ok = batch(&app, &u.jar, &ops(&u, 1, 10), Some(window)).await;
    assert_eq!(statuses(&ok), vec![200; 10]);
}

#[tokio::test]
async fn an_expired_or_used_up_window_writes_nothing() {
    let app = TestApp::new().await;
    let u = fresh_user(&app, 1).await;

    // Used up.
    let window = window_of(&open(&app, &u.jar, 3).await);
    let ok = batch(&app, &u.jar, &ops(&u, 1, 3), Some(window)).await;
    assert_eq!(statuses(&ok), vec![200; 3]);
    let seq = vault_seq(&app, &u).await;
    let more = batch(&app, &u.jar, &ops(&u, 4, 1), Some(window)).await;
    assert_eq!(more.status, StatusCode::CONFLICT, "{}", more.text());
    assert_eq!(error(&more), "import_window_invalid");
    assert_eq!(vault_seq(&app, &u).await, seq);

    // More than it has left, as a whole: none of the operations is written.
    let window = window_of(&open(&app, &u.jar, 2).await);
    let over = batch(&app, &u.jar, &ops(&u, 10, 3), Some(window)).await;
    assert_eq!(over.status, StatusCode::CONFLICT);
    assert_eq!(error(&over), "import_window_invalid");
    assert_eq!(vault_seq(&app, &u).await, seq);
    assert_eq!(left(&app, &u), Some(2));

    // It lasts 1 800 seconds from the open: one second before the end it is
    // there, at the end it is not.
    app.clock.advance(u64::from(IMPORT_WINDOW_SECS) - 1);
    let last = batch(&app, &u.jar, &ops(&u, 10, 1), Some(window)).await;
    assert_eq!(statuses(&last), vec![200]);
    app.clock.advance(1);
    let ended = batch(&app, &u.jar, &ops(&u, 11, 1), Some(window)).await;
    assert_eq!(ended.status, StatusCode::CONFLICT);
    assert_eq!(error(&ended), "import_window_invalid");
    assert_eq!(vault_seq(&app, &u).await, seq + 1);
    assert_eq!(left(&app, &u), None, "an ended window is not open");
}

#[tokio::test]
async fn a_retried_batch_of_replays_does_not_debit_the_window_again() {
    let app = TestApp::new().await;
    let u = fresh_user(&app, 1).await;
    // A batch holds one operation of the window for each of its items while it
    // runs, repeats included, so the window has room for the batches below.
    let window = window_of(&open(&app, &u.jar, 6).await);
    let first = ops(&u, 1, 2);

    let sent = batch(&app, &u.jar, &first, Some(window)).await;
    assert_eq!(statuses(&sent), [200, 200]);
    assert_eq!(left(&app, &u), Some(4));
    let seq = vault_seq(&app, &u).await;

    // The answer was lost and the batch goes again: the same two results, as
    // repeats, and the window has what it had.
    let retried = batch(&app, &u.jar, &first, Some(window)).await;
    assert_eq!(statuses(&retried), [200, 200]);
    let results = retried.json()["results"].clone();
    assert_eq!(results[0]["replayed"], true);
    assert_eq!(results[1]["replayed"], true);
    assert_eq!(left(&app, &u), Some(4));
    assert_eq!(vault_seq(&app, &u).await, seq);

    // A batch of one repeat and one new item takes one.
    let mixed = vec![first[0].clone(), op(&u, 3)];
    let res = batch(&app, &u.jar, &mixed, Some(window)).await;
    assert_eq!(statuses(&res), [200, 200]);
    assert_eq!(left(&app, &u), Some(3));

    // A conflict and a refusal take nothing.
    let mut conflict = op(&u, 1);
    conflict["idem"] = json!(hex16::encode(&idem(900)));
    let mut manifest = op(&u, 50);
    manifest["id"] = json!(hex16::encode(&[0u8; 16]));
    let res = batch(&app, &u.jar, &[conflict, manifest], Some(window)).await;
    assert_eq!(statuses(&res), [409, 403]);
    assert_eq!(left(&app, &u), Some(3));

    // What is left is what new items can use.
    let rest = batch(&app, &u.jar, &ops(&u, 4, 3), Some(window)).await;
    assert_eq!(statuses(&rest), [200, 200, 200]);
    assert_eq!(left(&app, &u), Some(0));
}

/// Sends `request` to a router, as the app does.
async fn via(router: &axum::Router, mut request: Request<Body>) -> Res {
    request
        .headers_mut()
        .insert(header::HOST, HeaderValue::from_static(Which::Vault.host()));
    request.extensions_mut().insert(ConnectInfo(
        PEER.parse::<std::net::SocketAddr>().expect("a peer"),
    ));
    let response = router.clone().oneshot(request).await.expect("a response");
    let (parts, body) = response.into_parts();
    Res {
        status: parts.status,
        headers: parts.headers,
        body: to_bytes(body, 16 * 1024 * 1024)
            .await
            .expect("a body")
            .to_vec(),
    }
}

#[tokio::test]
async fn after_a_server_restart_the_window_is_gone_and_a_new_one_can_be_opened() {
    let app = TestApp::new().await;
    let u = fresh_user(&app, 1).await;
    let window = window_of(&open(&app, &u.jar, 10).await);
    let ok = batch(&app, &u.jar, &ops(&u, 1, 4), Some(window)).await;
    assert_eq!(statuses(&ok), vec![200; 4]);

    // The same database and the same sessions, and no window in memory.
    let mut state = app.state.clone();
    state.import_windows = ImportWindows::new();
    let restarted = server::vault_router(state);

    let body = json!({ "ops": ops(&u, 5, 2), "import_window": hex16::encode(&window) });
    let res = via(
        &restarted,
        request(Method::POST, "/api/sync/batch", &u.jar, Some(&body)),
    )
    .await;
    assert_eq!(res.status, StatusCode::CONFLICT, "{}", res.text());
    assert_eq!(error(&res), "import_window_invalid");
    let seq = vault_seq(&app, &u).await;
    assert_eq!(seq, 5, "nothing was written");

    // A new window opens at once (the session is still fresh), for what is left.
    let res = via(
        &restarted,
        request(
            Method::POST,
            "/api/sync/import",
            &u.jar,
            Some(&json!({ "ops": 6 })),
        ),
    )
    .await;
    let new_window = window_of(&res);
    assert_ne!(new_window, window);
    let body = json!({ "ops": ops(&u, 5, 6), "import_window": hex16::encode(&new_window) });
    let res = via(
        &restarted,
        request(Method::POST, "/api/sync/batch", &u.jar, Some(&body)),
    )
    .await;
    assert_eq!(statuses(&res), vec![200; 6]);
}

#[tokio::test]
async fn a_bogus_or_dead_window_gets_no_way_round_the_operation_limit() {
    // One operation a second and room for four at once.
    let rate = RateConfig {
        ops_per_min: 60,
        ops_burst: 4,
        ..RateConfig::DEFAULT
    };
    let app = TestApp::builder().rate(rate).build().await;
    let u = fresh_user(&app, 1).await;
    let (jar2, _) = other_device(&app, &u, 2).await;
    let real = window_of(&open(&app, &u.jar, 40).await);

    // A made-up id: the first batch takes the bucket and is refused as a
    // window, the next is throttled like any batch.
    let mut seen = Vec::new();
    for n in 0..4u32 {
        let res = batch(&app, &u.jar, &ops(&u, n * 4 + 1, 4), Some([9; 16])).await;
        seen.push((res.status.as_u16(), error(&res)));
    }
    assert_eq!(seen[0], (409, "import_window_invalid".to_string()));
    assert!(
        seen[1..].iter().all(|(s, e)| *s == 429 && e == "throttled"),
        "{seen:?}"
    );

    // The window of another device is the same for this device.
    let res = batch(&app, &jar2, &ops(&u, 50, 4), Some(real)).await;
    assert_eq!(error(&res), "import_window_invalid");
    let res = batch(&app, &jar2, &ops(&u, 54, 4), Some(real)).await;
    assert_eq!(res.status, StatusCode::TOO_MANY_REQUESTS, "{}", res.text());

    // The real window, for its own device, is not held back by that bucket.
    for n in 0..4u32 {
        let res = batch(&app, &u.jar, &ops(&u, 100 + n * 4, 4), Some(real)).await;
        assert_eq!(statuses(&res), vec![200; 4], "batch {n}");
    }
    assert_eq!(left(&app, &u), Some(24));

    // Once it has ended, its id counts like any other.
    app.clock.advance(u64::from(IMPORT_WINDOW_SECS));
    let first = batch(&app, &u.jar, &ops(&u, 200, 4), Some(real)).await;
    assert_eq!(error(&first), "import_window_invalid");
    let next = batch(&app, &u.jar, &ops(&u, 204, 4), Some(real)).await;
    assert_eq!(next.status, StatusCode::TOO_MANY_REQUESTS);
}

#[tokio::test]
async fn a_batch_names_its_window_in_the_envelope_only_as_32_hex_or_null() {
    let app = TestApp::new().await;
    let u = fresh_user(&app, 1).await;
    for (name, window) in [
        ("not hex", json!("zz")),
        ("short", json!("00ff")),
        ("a number", json!(5)),
        ("upper case", json!("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")),
    ] {
        let body = json!({ "ops": ops(&u, 1, 1), "import_window": window });
        let res = send(&app, Method::POST, "/api/sync/batch", &u.jar, Some(&body)).await;
        assert_eq!(
            res.status,
            StatusCode::BAD_REQUEST,
            "{name}: {}",
            res.text()
        );
        assert_eq!(error(&res), "bad_request", "{name}");
    }
    // `null` is a batch without a window, as the second milestone sent it.
    let body = json!({ "ops": ops(&u, 1, 1), "import_window": null });
    let res = send(&app, Method::POST, "/api/sync/batch", &u.jar, Some(&body)).await;
    assert_eq!(statuses(&res), [200]);
}

// ---------------------------------------------------------------------------
// At scale (ignored by default).

#[tokio::test]
#[ignore = "ten thousand items; run in release mode"]
async fn ten_thousand_items_import_within_five_minutes() {
    // The vault holds its manifest row, so 9 999 more items fill the 10 000.
    const ITEMS: u32 = 9_999;
    let app = TestApp::new().await;
    let u = fresh_user(&app, 1).await;
    let window = window_of(&open(&app, &u.jar, u64::from(ITEMS)).await);

    let started = Instant::now();
    let clock_start = now(&app);
    let mut next = 1;
    while next <= ITEMS {
        let count = (ITEMS - next + 1).min(100);
        // Notes of about 3 KiB, as a real item has them: the bucket of bytes
        // runs dry now and then, and the loop waits as the answer says.
        let body: Vec<Value> = (next..next + count)
            .map(|n| op_with_notes(&u, n, "x".repeat(3000)))
            .collect();
        loop {
            let res = batch(&app, &u.jar, &body, Some(window)).await;
            if res.status == StatusCode::TOO_MANY_REQUESTS {
                // Only the bytes can turn an import batch away: wait as told.
                let wait: u64 = res.header("retry-after").parse().expect("seconds");
                app.clock.advance(wait);
                continue;
            }
            assert_eq!(statuses(&res), vec![200; count as usize]);
            break;
        }
        next += count;
    }
    let took = started.elapsed();
    let simulated = now(&app) - clock_start;
    assert!(took < Duration::from_secs(300), "took {took:?}");
    // The waits for the byte bucket stayed inside the window's own time.
    assert!(
        simulated < i64::from(IMPORT_WINDOW_SECS),
        "{simulated} s of waiting"
    );
    assert_eq!(left(&app, &u), Some(0));
    assert_eq!(vault_seq(&app, &u).await, 1 + i64::from(ITEMS));
}
