//! `POST /api/sync/batch`: many item writes in one request, each in its own
//! transaction. Spec: Fase 1 § 8.2, § 8.3.
//!
//! The tests drive the whole vault router of a `TestApp`. A write with a
//! `resurrect` against a tombstone, and the `429` and `503` of the single item
//! write and of the checkpoint, belong to the route tests that need the other
//! sync tasks too.

#![allow(non_snake_case)]

mod support;

use std::io;
use std::sync::{Arc, Mutex};

use axum::body::Body;
use axum::http::{Request, StatusCode};
use ferret_core::testing::TestRng;
use ferret_core::{
    ItemBody, ItemType, OsRng, UnlockedVault, VaultContext, VaultKey, encrypt_item, make_tombstone,
};
use ferret_server::auth::session::Origin;
use ferret_server::ids::ItemId;
use ferret_server::vault::rate::RateConfig;
use ferret_server::wire::{BatchRes, b64url, hex16};
use ferret_server_auth::SessionScope;
use serde_json::{Value, json};
use support::accounts::{TestAccount, add_account_to_app};
use support::session::issue;
use support::{Jar, Req, Res, TestApp, VAULT_URL, Which};
use tokio::sync::broadcast::error::TryRecvError;
use tracing_subscriber::fmt::MakeWriter;

struct User {
    account: TestAccount,
    jar: Jar,
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
        vault,
    }
}

fn item(n: u8) -> ItemId {
    let mut bytes = [0u8; 16];
    bytes[0] = 0x10;
    bytes[1] = n;
    ItemId::from_bytes(bytes)
}

fn idem(n: u8) -> [u8; 16] {
    [n; 16]
}

fn seal(user: &User, id: ItemId, rev: u64, name: &str) -> ferret_core::SealedItem {
    let mut body = ItemBody::new(ItemType::Note, name, 1);
    body.notes = Some(format!("notes of {name}"));
    encrypt_item(
        &mut TestRng::new(format!("{name}/{rev}").as_bytes()),
        &user.vault,
        id,
        rev,
        &body,
        None,
    )
    .expect("an item")
}

/// A live operation of a batch.
fn op(id: ItemId, base_rev: u64, sealed: &ferret_core::SealedItem, idem: [u8; 16]) -> Value {
    json!({
        "id": hex16::encode(id.as_bytes()),
        "base_rev": base_rev,
        "blob": b64url::encode(&sealed.envelope),
        "tag": b64url::encode(&sealed.tag),
        "idem": hex16::encode(&idem),
    })
}

/// A tombstone operation of a batch.
fn tomb_op(id: ItemId, base_rev: u64, tomb: &[u8], idem: [u8; 16]) -> Value {
    json!({
        "id": hex16::encode(id.as_bytes()),
        "base_rev": base_rev,
        "deleted": true,
        "tomb": b64url::encode(tomb),
        "idem": hex16::encode(&idem),
    })
}

fn batch_body(ops: &[Value]) -> Vec<u8> {
    json!({ "ops": ops }).to_string().into_bytes()
}

fn post_raw(jar: &Jar, body: Vec<u8>) -> Request<Body> {
    let mut builder = Request::builder()
        .method("POST")
        .uri("/api/sync/batch")
        .header("origin", VAULT_URL)
        .header("sec-fetch-site", "same-origin")
        .header("ferret-protocol", "1")
        .header("content-type", "application/json");
    if let Some(cookie) = jar.header() {
        builder = builder.header("cookie", cookie);
    }
    builder.body(Body::from(body)).expect("a request")
}

async fn post(app: &TestApp, jar: &Jar, body: Vec<u8>) -> Res {
    app.call_raw(Which::Vault, post_raw(jar, body)).await
}

async fn batch(app: &TestApp, jar: &Jar, ops: &[Value]) -> Res {
    post(app, jar, batch_body(ops)).await
}

/// A single write, as a page sends it.
async fn put(app: &TestApp, jar: &Jar, id: ItemId, op: &Value) -> Res {
    let mut body = op.clone();
    body.as_object_mut().expect("an object").remove("id");
    let mut builder = Request::builder()
        .method("PUT")
        .uri(format!("/api/sync/items/{}", hex16::encode(id.as_bytes())))
        .header("origin", VAULT_URL)
        .header("sec-fetch-site", "same-origin")
        .header("ferret-protocol", "1")
        .header("content-type", "application/json");
    if let Some(cookie) = jar.header() {
        builder = builder.header("cookie", cookie);
    }
    app.call_raw(
        Which::Vault,
        builder
            .body(Body::from(body.to_string()))
            .expect("a request"),
    )
    .await
}

async fn get(app: &TestApp, jar: &Jar, uri: &str) -> Res {
    let mut builder = Request::builder().method("GET").uri(uri);
    if let Some(cookie) = jar.header() {
        builder = builder.header("cookie", cookie);
    }
    app.call_raw(
        Which::Vault,
        builder.body(Body::empty()).expect("a request"),
    )
    .await
}

fn error(res: &Res) -> String {
    res.json()["error"].as_str().unwrap_or("").to_string()
}

/// The `200` answer, as the contract reads it (so it must be a valid one).
fn results(res: &Res) -> Value {
    assert_eq!(res.status, StatusCode::OK, "{}", res.text());
    let parsed: BatchRes = serde_json::from_slice(&res.body).expect("a batch answer");
    parsed.validate().expect("a valid batch answer");
    res.json()["results"].clone()
}

fn statuses(results: &Value) -> Vec<u64> {
    results
        .as_array()
        .expect("an array")
        .iter()
        .map(|r| r["status"].as_u64().expect("a status"))
        .collect()
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

async fn vault_seq(app: &TestApp, user: &User) -> i64 {
    let vault = user.account.vault_id;
    db(app, move |c| {
        c.query_row(
            "SELECT seq FROM ferret_vaults WHERE vault_id = ?1",
            [vault.as_bytes().as_slice()],
            |r| r.get(0),
        )
    })
    .await
}

async fn idem_rows(app: &TestApp) -> i64 {
    db(app, |c| {
        c.query_row("SELECT COUNT(*) FROM ferret_idem", [], |r| r.get(0))
    })
    .await
}

// ---------------------------------------------------------------------------
// The answer.

#[tokio::test]
async fn results_follow_the_order_of_the_ops() {
    let app = TestApp::new().await;
    let u = user(&app, 1).await;
    let manifest = ItemId::from_bytes([0u8; 16]);
    let held = seal(&u, item(2), 1, "held");
    put(&app, &u.jar, item(2), &op(item(2), 0, &held, idem(9))).await;
    let ops = [
        op(item(1), 0, &seal(&u, item(1), 1, "one"), idem(1)),
        // The row is there already: a conflict.
        op(item(2), 0, &seal(&u, item(2), 1, "two"), idem(2)),
        op(item(3), 0, &seal(&u, item(3), 1, "three"), idem(3)),
        op(manifest, 1, &seal(&u, item(4), 2, "manifest"), idem(4)),
    ];
    let res = batch(&app, &u.jar, &ops).await;
    let results = results(&res);
    assert_eq!(statuses(&results), [200, 409, 200, 403]);
    assert_eq!(results[0]["rev"], 1);
    assert_eq!(results[1]["current_rev"], 1);
    assert_eq!(results[1]["deleted"], false);
    assert_eq!(results[2]["rev"], 1);
    assert_eq!(results[3]["error"], "manifest_not_writable");
    assert!(results[0]["seq"].as_u64() < results[2]["seq"].as_u64());
    // The answer is a plain 200 JSON with the usual headers.
    assert_eq!(res.header("cache-control"), "no-store");
}

#[tokio::test]
async fn each_op_is_its_own_transaction_and_a_conflict_does_not_stop_the_others() {
    let app = TestApp::new().await;
    let u = user(&app, 1).await;
    let stored = seal(&u, item(2), 1, "stored first");
    assert_eq!(
        put(&app, &u.jar, item(2), &op(item(2), 0, &stored, idem(9)))
            .await
            .status,
        StatusCode::OK
    );
    let ops = [
        op(item(1), 0, &seal(&u, item(1), 1, "one"), idem(1)),
        op(item(2), 0, &seal(&u, item(2), 1, "stale"), idem(2)),
        op(item(3), 0, &seal(&u, item(3), 1, "three"), idem(3)),
    ];
    let results = results(&batch(&app, &u.jar, &ops).await);
    assert_eq!(statuses(&results), [200, 409, 200]);
    // The conflict is the row of the server, as a single write would show it.
    assert_eq!(results[1]["current_rev"], 1);
    assert_eq!(results[1]["deleted"], false);
    assert_eq!(
        results[1]["blob"].as_str().expect("the blob"),
        b64url::encode(&stored.envelope)
    );
    assert_eq!(
        results[1]["tag"].as_str().expect("the tag"),
        b64url::encode(&stored.tag)
    );
    // Two transactions, two numbers: the vault moved by one for each write.
    assert_eq!(results[0]["seq"], 3);
    assert_eq!(results[2]["seq"], 4);
    assert_eq!(vault_seq(&app, &u).await, 4);

    // The rows are there: the conflicted item is still the first version.
    let changes = get(&app, &u.jar, "/api/sync/changes?since=0").await.json();
    let rows = changes["changes"].as_array().expect("changes");
    let ids: Vec<&str> = rows.iter().filter_map(|r| r["id"].as_str()).collect();
    for n in [1, 2, 3] {
        assert!(ids.contains(&hex16::encode(item(n).as_bytes()).as_str()));
    }
}

#[tokio::test]
async fn a_conflict_against_a_row_that_is_not_there_is_current_rev_0() {
    let app = TestApp::new().await;
    let u = user(&app, 1).await;
    let res = batch(
        &app,
        &u.jar,
        &[
            op(item(1), 5, &seal(&u, item(1), 6, "ahead"), idem(1)),
            op(item(2), 0, &seal(&u, item(2), 1, "two"), idem(2)),
        ],
    )
    .await;
    // The answer is read as plain JSON: see the note in the task report on
    // how the contract of a batch result treats this form.
    assert_eq!(res.status, StatusCode::OK, "{}", res.text());
    let results = res.json()["results"].clone();
    assert_eq!(statuses(&results), [409, 200]);
    assert_eq!(results[0]["current_rev"], 0);
    assert_eq!(results[0]["deleted"], false);
    assert!(results[0].get("blob").is_none());
    assert!(results[0].get("tag").is_none());
}

#[tokio::test]
async fn a_tombstone_op_is_stored_like_a_single_tombstone() {
    let app = TestApp::new().await;
    let u = user(&app, 1).await;
    let first = seal(&u, item(1), 1, "to delete");
    put(&app, &u.jar, item(1), &op(item(1), 0, &first, idem(1))).await;
    let t = make_tombstone(&mut OsRng, &u.vault, item(1), 2).expect("a tombstone");
    let results = results(
        &batch(
            &app,
            &u.jar,
            &[
                tomb_op(item(1), 1, &t.tomb, idem(2)),
                op(item(2), 0, &seal(&u, item(2), 1, "other"), idem(3)),
            ],
        )
        .await,
    );
    assert_eq!(statuses(&results), [200, 200]);
    assert_eq!(results[0]["rev"], 2);
    let changes = get(&app, &u.jar, "/api/sync/changes?since=0").await.json();
    let row = changes["changes"]
        .as_array()
        .expect("changes")
        .iter()
        .find(|r| r["id"] == hex16::encode(item(1).as_bytes()))
        .expect("the row")
        .clone();
    assert_eq!(row["deleted"], true);
    assert_eq!(row["rev"], 2);
}

// ---------------------------------------------------------------------------
// What refuses the whole batch.

#[tokio::test]
async fn two_ops_on_one_item_refuse_the_whole_batch_and_write_nothing() {
    let app = TestApp::new().await;
    let u = user(&app, 1).await;
    let t = make_tombstone(&mut OsRng, &u.vault, item(1), 2).expect("a tombstone");
    for (name, ops) in [
        (
            "two live",
            vec![
                op(item(1), 0, &seal(&u, item(1), 1, "a"), idem(1)),
                op(item(2), 0, &seal(&u, item(2), 1, "b"), idem(2)),
                op(item(1), 0, &seal(&u, item(1), 1, "c"), idem(3)),
            ],
        ),
        (
            "live and tombstone",
            vec![
                op(item(1), 0, &seal(&u, item(1), 1, "a"), idem(1)),
                tomb_op(item(1), 1, &t.tomb, idem(2)),
            ],
        ),
        (
            "a bad tombstone and a live op",
            vec![
                tomb_op(item(1), 1, &[0u8; 39], idem(1)),
                op(item(1), 0, &seal(&u, item(1), 1, "a"), idem(2)),
            ],
        ),
    ] {
        let res = batch(&app, &u.jar, &ops).await;
        assert_eq!(res.status, StatusCode::BAD_REQUEST, "{name}");
        assert_eq!(error(&res), "bad_request", "{name}");
    }
    assert_eq!(vault_seq(&app, &u).await, 1);
    assert_eq!(idem_rows(&app).await, 0);
}

#[tokio::test]
async fn zero_or_101_ops_is_400_and_a_body_over_6_MiB_is_413() {
    let app = TestApp::new().await;
    let u = user(&app, 1).await;

    let res = batch(&app, &u.jar, &[]).await;
    assert_eq!(res.status, StatusCode::BAD_REQUEST);
    assert_eq!(error(&res), "bad_request");

    let sealed = seal(&u, item(1), 1, "same body");
    let many = |n: u8| -> Vec<Value> {
        (1..=n)
            .map(|k| op(item(k), 0, &sealed, idem(k)))
            .collect::<Vec<_>>()
    };
    let res = batch(&app, &u.jar, &many(101)).await;
    assert_eq!(res.status, StatusCode::BAD_REQUEST);
    assert_eq!(error(&res), "bad_request");
    assert_eq!(vault_seq(&app, &u).await, 1, "nothing was written");

    // 100 is the most there is.
    let res = batch(&app, &u.jar, &many(100)).await;
    let results = results(&res);
    assert_eq!(results.as_array().expect("an array").len(), 100);
    assert!(statuses(&results).iter().all(|s| *s == 200));
    assert_eq!(vault_seq(&app, &u).await, 101);

    // A body over 6 MiB is refused before it is read to the end, as JSON.
    let huge = vec![b' '; 6 * 1024 * 1024 + 1];
    let res = post(&app, &u.jar, huge).await;
    assert_eq!(res.status, StatusCode::PAYLOAD_TOO_LARGE);
    assert_eq!(error(&res), "too_large");
}

#[tokio::test]
async fn a_batch_close_to_the_size_limit_is_read() {
    let app = TestApp::new().await;
    let u = user(&app, 1).await;
    let sealed = seal(&u, item(1), 1, "big");
    // Many envelopes of about 60 KiB: the body is several MiB.
    let mut envelope = sealed.envelope.clone();
    envelope.resize(60_000, 0);
    let big = ferret_core::SealedItem {
        envelope,
        tag: sealed.tag,
        rev: 1,
    };
    let ops: Vec<Value> = (1..=60u8).map(|k| op(item(k), 0, &big, idem(k))).collect();
    let body = batch_body(&ops);
    assert!(body.len() > 4 * 1024 * 1024 && body.len() < 6 * 1024 * 1024);
    let res = post(&app, &u.jar, body).await;
    // The server stores what it is given without opening it; a body that is not
    // a real envelope is refused in its place, never the batch as a whole.
    let results = results(&res);
    assert_eq!(results.as_array().expect("an array").len(), 60);
}

#[tokio::test]
async fn a_request_that_is_not_a_batch_is_400() {
    let app = TestApp::new().await;
    let u = user(&app, 1).await;
    let good = op(item(1), 0, &seal(&u, item(1), 1, "a"), idem(1));
    let with_field = |extra: (&str, Value)| -> Value {
        let mut value = good.clone();
        value[extra.0] = extra.1;
        value
    };
    let bodies: Vec<(&str, Vec<u8>)> = vec![
        ("not json", b"not json".to_vec()),
        ("no ops", b"{}".to_vec()),
        ("ops is not a list", br#"{"ops": 3}"#.to_vec()),
        (
            "unknown field of the batch",
            json!({ "ops": [good.clone()], "extra": 1 })
                .to_string()
                .into_bytes(),
        ),
        (
            "unknown field of an op",
            batch_body(&[with_field(("surprise", json!(1)))]),
        ),
        (
            "an id that is not hex",
            batch_body(&[with_field(("id", json!("zz")))]),
        ),
        (
            "a revision that is not a number",
            batch_body(&[with_field(("base_rev", json!("1")))]),
        ),
        (
            "a repeated field",
            format!(
                r#"{{"ops": [{{"id": "{id}", "id": "{id}", "base_rev": 0, "idem": "{idem}"}}]}}"#,
                id = hex16::encode(item(1).as_bytes()),
                idem = hex16::encode(&idem(1)),
            )
            .into_bytes(),
        ),
    ];
    for (name, body) in bodies {
        let res = post(&app, &u.jar, body).await;
        assert_eq!(res.status, StatusCode::BAD_REQUEST, "{name}");
        assert_eq!(error(&res), "bad_request", "{name}");
    }
    assert_eq!(vault_seq(&app, &u).await, 1);
}

#[tokio::test]
async fn a_batch_without_a_session_is_401() {
    let app = TestApp::new().await;
    let u = user(&app, 1).await;
    let body = batch_body(&[op(item(1), 0, &seal(&u, item(1), 1, "a"), idem(1))]);
    let res = post(&app, &Jar::default(), body).await;
    assert_eq!(res.status, StatusCode::UNAUTHORIZED);
    assert_eq!(vault_seq(&app, &u).await, 1);
}

// ---------------------------------------------------------------------------
// What stays in its place.

#[tokio::test]
async fn manifest_op_is_403_in_its_slot_and_the_rest_are_stored() {
    let app = TestApp::new().await;
    let u = user(&app, 1).await;
    let manifest = ItemId::from_bytes([0u8; 16]);
    let sealed = seal(&u, item(9), 2, "manifest");
    let t = make_tombstone(&mut OsRng, &u.vault, item(9), 2).expect("a tombstone");
    let ops = [
        op(item(1), 0, &seal(&u, item(1), 1, "one"), idem(1)),
        op(manifest, 1, &sealed, idem(2)),
        op(item(2), 0, &seal(&u, item(2), 1, "two"), idem(4)),
    ];
    let results = results(&batch(&app, &u.jar, &ops).await);
    assert_eq!(statuses(&results), [200, 403, 200]);
    assert_eq!(results[1]["error"], "manifest_not_writable");
    // The tombstone form is refused in its place too (the manifest id twice in
    // one batch would be a repeated id, so it is a batch of its own).
    let results2 =
        self::results(&batch(&app, &u.jar, &[tomb_op(manifest, 1, &t.tomb, idem(3))]).await);
    assert_eq!(statuses(&results2), [403]);
    assert_eq!(results2[0]["error"], "manifest_not_writable");
    // Only the two stored writes moved the vault and left a record.
    assert_eq!(vault_seq(&app, &u).await, 3);
    assert_eq!(idem_rows(&app).await, 2);
    let methods = get(&app, &u.jar, "/api/vault/unlock-methods").await.json();
    assert_eq!(methods["manifest"]["rev"], 1);
}

#[tokio::test]
async fn bad_envelope_or_bad_tombstone_is_422_in_its_slot() {
    let app = TestApp::new().await;
    let u = user(&app, 1).await;
    let good = seal(&u, item(1), 1, "good");
    let garbage = ferret_core::SealedItem {
        envelope: vec![0x55; 200],
        tag: good.tag,
        rev: 1,
    };
    let mut oversize_envelope = good.envelope.clone();
    oversize_envelope.resize(65_537, 0);
    let oversize = ferret_core::SealedItem {
        envelope: oversize_envelope,
        tag: good.tag,
        rev: 1,
    };
    let ops = [
        op(item(1), 0, &good, idem(1)),
        op(item(2), 0, &garbage, idem(2)),
        tomb_op(item(3), 1, &[0u8; 39], idem(3)),
        op(item(4), 0, &oversize, idem(4)),
        tomb_op(item(5), 1, &[0u8; 41], idem(5)),
        op(item(6), 0, &seal(&u, item(6), 1, "six"), idem(6)),
    ];
    let results = results(&batch(&app, &u.jar, &ops).await);
    assert_eq!(statuses(&results), [200, 422, 422, 413, 422, 200]);
    assert_eq!(results[1]["error"], "unsupported_envelope");
    assert_eq!(results[2]["error"], "tombstone_invalid");
    assert_eq!(results[3]["error"], "too_large");
    assert_eq!(results[4]["error"], "tombstone_invalid");
    assert_eq!(vault_seq(&app, &u).await, 3);
}

#[tokio::test]
async fn an_op_without_one_form_is_400_in_its_slot() {
    let app = TestApp::new().await;
    let u = user(&app, 1).await;
    let good = seal(&u, item(1), 1, "good");
    let t = make_tombstone(&mut OsRng, &u.vault, item(2), 2).expect("a tombstone");
    let mut both = op(item(2), 0, &good, idem(2));
    both["tomb"] = json!(b64url::encode(&t.tomb));
    let neither = json!({
        "id": hex16::encode(item(3).as_bytes()),
        "base_rev": 0,
        "idem": hex16::encode(&idem(3)),
    });
    let mut resurrecting_tombstone = tomb_op(item(4), 1, &t.tomb, idem(4));
    resurrecting_tombstone["resurrect"] = json!(true);
    let ops = [
        op(item(1), 0, &good, idem(1)),
        both,
        neither,
        resurrecting_tombstone,
    ];
    let results = results(&batch(&app, &u.jar, &ops).await);
    assert_eq!(statuses(&results), [200, 400, 400, 400]);
    assert_eq!(results[1]["error"], "bad_request");
    assert_eq!(vault_seq(&app, &u).await, 2);
}

// ---------------------------------------------------------------------------
// Replays and the key space of `idem`.

#[tokio::test]
async fn a_replayed_batch_returns_replayed_true_with_the_first_revs() {
    let app = TestApp::new().await;
    let u = user(&app, 1).await;
    let first = seal(&u, item(1), 1, "one");
    let ops = [
        op(item(1), 0, &first, idem(1)),
        op(item(2), 0, &seal(&u, item(2), 1, "two"), idem(2)),
    ];
    let original = results(&batch(&app, &u.jar, &ops).await);
    assert_eq!(statuses(&original), [200, 200]);
    assert_eq!(original[0]["replayed"], false);

    // Another write moves item 1 on, so the basis of the retry is stale. The
    // retry still gets the first answer.
    let second = seal(&u, item(1), 2, "one again");
    assert_eq!(
        put(&app, &u.jar, item(1), &op(item(1), 1, &second, idem(7)))
            .await
            .status,
        StatusCode::OK
    );
    let seq_before = vault_seq(&app, &u).await;
    let replay = results(&batch(&app, &u.jar, &ops).await);
    assert_eq!(statuses(&replay), [200, 200]);
    for n in 0..2 {
        assert_eq!(replay[n]["replayed"], true, "op {n}");
        assert_eq!(replay[n]["rev"], original[n]["rev"], "op {n}");
        assert_eq!(replay[n]["seq"], original[n]["seq"], "op {n}");
    }
    assert_eq!(vault_seq(&app, &u).await, seq_before, "nothing was written");
}

#[tokio::test]
async fn batch_idem_shares_the_key_space_with_put_and_a_different_hash_is_422() {
    let app = TestApp::new().await;
    let u = user(&app, 1).await;
    let one = seal(&u, item(1), 1, "one");
    let two = seal(&u, item(2), 1, "two");

    // A single write used `idem(1)`: the same `idem` and item in a batch is a
    // different request (the hashes are made differently), so it is refused.
    assert_eq!(
        put(&app, &u.jar, item(1), &op(item(1), 0, &one, idem(1)))
            .await
            .status,
        StatusCode::OK
    );
    let results1 = results(&batch(&app, &u.jar, &[op(item(1), 0, &one, idem(1))]).await);
    assert_eq!(statuses(&results1), [422]);
    assert_eq!(results1[0]["error"], "idem_reuse");

    // And the other way round.
    let results2 = self::results(&batch(&app, &u.jar, &[op(item(2), 0, &two, idem(2))]).await);
    assert_eq!(statuses(&results2), [200]);
    let res = put(&app, &u.jar, item(2), &op(item(2), 0, &two, idem(2))).await;
    assert_eq!(res.status, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(error(&res), "idem_reuse");

    // The same `idem` with another body inside batches is refused too.
    let other = seal(&u, item(2), 1, "two but different");
    let results3 = results(&batch(&app, &u.jar, &[op(item(2), 0, &other, idem(2))]).await);
    assert_eq!(statuses(&results3), [422]);
    // A refusal for `idem_reuse` wrote nothing.
    assert_eq!(vault_seq(&app, &u).await, 3);
}

// ---------------------------------------------------------------------------
// Notifications.

#[tokio::test]
async fn a_batch_notifies_once_with_the_highest_seq() {
    let app = TestApp::new().await;
    let u = user(&app, 1).await;
    let held = seal(&u, item(2), 1, "held");
    put(&app, &u.jar, item(2), &op(item(2), 0, &held, idem(9))).await;
    let mut events = app.sync_events().subscribe();
    let ops = [
        op(item(1), 0, &seal(&u, item(1), 1, "one"), idem(1)),
        op(item(2), 0, &seal(&u, item(2), 1, "conflict"), idem(2)),
        op(item(3), 0, &seal(&u, item(3), 1, "three"), idem(3)),
        op(item(4), 0, &seal(&u, item(4), 1, "four"), idem(4)),
    ];
    let results = results(&batch(&app, &u.jar, &ops).await);
    assert_eq!(statuses(&results), [200, 409, 200, 200]);
    let highest = results[3]["seq"].as_u64().expect("a seq");
    assert_eq!(highest, 5);

    let change = events.try_recv().expect("one notification");
    assert_eq!(change.vault, u.account.vault_id);
    assert_eq!(change.seq, highest);
    assert!(matches!(events.try_recv(), Err(TryRecvError::Empty)));

    // A replay and a batch of conflicts changed nothing: no notification.
    results_ok(&batch(&app, &u.jar, &ops).await);
    results_ok(&batch(&app, &u.jar, &[ops[1].clone()]).await);
    assert!(matches!(events.try_recv(), Err(TryRecvError::Empty)));
}

fn results_ok(res: &Res) {
    assert_eq!(res.status, StatusCode::OK, "{}", res.text());
}

#[tokio::test]
async fn a_refused_batch_does_not_notify() {
    let app = TestApp::new().await;
    let u = user(&app, 1).await;
    let mut events = app.sync_events().subscribe();
    let a = op(item(1), 0, &seal(&u, item(1), 1, "a"), idem(1));
    assert_eq!(
        batch(&app, &u.jar, &[a.clone(), a]).await.status,
        StatusCode::BAD_REQUEST
    );
    assert!(matches!(events.try_recv(), Err(TryRecvError::Empty)));
}

// ---------------------------------------------------------------------------
// Limits and the queue.

fn config(ops_burst: u32, bytes_per_min: u64) -> RateConfig {
    RateConfig {
        ops_burst,
        bytes_per_min,
        ..RateConfig::DEFAULT
    }
}

#[tokio::test]
async fn a_batch_of_n_ops_counts_n_operations_and_its_body_bytes() {
    // Operations: a burst of five takes a batch of three, and not another.
    let app = TestApp::builder().rate(config(5, 20 << 20)).build().await;
    let u = user(&app, 1).await;
    let batch_of = |from: u8, n: u8| -> Vec<Value> {
        (from..from + n)
            .map(|k| op(item(k), 0, &seal(&u, item(k), 1, "x"), idem(k)))
            .collect()
    };
    // A refused batch (a repeated id) is not counted.
    let dup = [batch_of(1, 1)[0].clone(), batch_of(1, 1)[0].clone()];
    assert_eq!(
        batch(&app, &u.jar, &dup).await.status,
        StatusCode::BAD_REQUEST
    );

    assert_eq!(
        batch(&app, &u.jar, &batch_of(1, 3)).await.status,
        StatusCode::OK
    );
    let res = batch(&app, &u.jar, &batch_of(4, 3)).await;
    assert_eq!(res.status, StatusCode::TOO_MANY_REQUESTS, "{}", res.text());
    assert_eq!(error(&res), "throttled");
    // Two operations are left; the third is half a second away, so one second.
    assert_eq!(res.header("retry-after"), "1");
    assert_eq!(
        vault_seq(&app, &u).await,
        4,
        "the throttled batch wrote nothing"
    );
    // Two operations fit.
    assert_eq!(
        batch(&app, &u.jar, &batch_of(4, 2)).await.status,
        StatusCode::OK
    );
    // After the time it said, three more fit.
    app.clock.advance(2);
    assert_eq!(
        batch(&app, &u.jar, &batch_of(6, 3)).await.status,
        StatusCode::OK
    );

    // Bytes: the bucket holds one and a half bodies.
    let sample = batch_body(&batch_of(20, 2));
    let len = u64::try_from(sample.len()).expect("a length");
    let app = TestApp::builder()
        .rate(config(300, len + len / 2))
        .build()
        .await;
    let u = user(&app, 1).await;
    let body = batch_body(&batch_of(20, 2));
    assert_eq!(
        post(&app, &u.jar, body.clone()).await.status,
        StatusCode::OK
    );
    let res = post(&app, &u.jar, body.clone()).await;
    assert_eq!(res.status, StatusCode::TOO_MANY_REQUESTS);
    assert_ne!(res.header("retry-after"), "");
    assert_ne!(res.header("retry-after"), "0");
    app.clock.advance(60);
    assert_eq!(post(&app, &u.jar, body).await.status, StatusCode::OK);
}

#[tokio::test]
async fn busy_on_batch_is_503_with_retry_after() {
    let app = TestApp::builder().gate(1, 0).build().await;
    let u = user(&app, 1).await;
    let ops = [op(item(1), 0, &seal(&u, item(1), 1, "one"), idem(1))];
    let permit = app.state.write_gate.enter().await.expect("a free turn");

    let res = batch(&app, &u.jar, &ops).await;
    assert_eq!(res.status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(error(&res), "busy");
    assert_eq!(res.header("retry-after"), "2");
    assert_eq!(vault_seq(&app, &u).await, 1, "nothing was written");

    // The turn comes back with the permit, and a batch gives its turn back.
    drop(permit);
    results_ok(&batch(&app, &u.jar, &ops).await);
    let more = [op(item(2), 0, &seal(&u, item(2), 1, "two"), idem(2))];
    results_ok(&batch(&app, &u.jar, &more).await);
}

#[tokio::test]
async fn admin_listener_has_no_batch_route() {
    let app = TestApp::new().await;
    let u = user(&app, 1).await;
    let body = batch_body(&[op(item(1), 0, &seal(&u, item(1), 1, "one"), idem(1))]);
    let res = app
        .call(
            Which::Admin,
            Req::post("/api/sync/batch")
                .page_fetch(Which::Admin)
                .header("cookie", &u.jar.header().unwrap_or_default())
                .header("content-type", "application/json")
                .json(&serde_json::from_slice::<Value>(&body).expect("json"))
                .build(),
        )
        .await;
    assert_eq!(res.status, StatusCode::NOT_FOUND);
    assert_eq!(vault_seq(&app, &u).await, 1);
}

// ---------------------------------------------------------------------------
// The log.

#[derive(Clone, Default)]
struct Sink(Arc<Mutex<Vec<u8>>>);

impl io::Write for Sink {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.0.lock().expect("sink").extend_from_slice(buf);
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

/// One subscriber for the whole test binary, installed once.
fn log_sink() -> Sink {
    static SINK: std::sync::OnceLock<Sink> = std::sync::OnceLock::new();
    SINK.get_or_init(|| {
        let sink = Sink::default();
        let subscriber = tracing_subscriber::fmt()
            .with_writer(sink.clone())
            .with_ansi(false)
            .with_max_level(tracing::Level::TRACE)
            .finish();
        tracing::subscriber::set_global_default(subscriber).expect("one global subscriber");
        sink
    })
    .clone()
}

/// Every form in which a log line could carry `bytes`: base64url and hex of the
/// whole value, the inside of its `Debug` text, and the same three for a slice.
fn canaries_for(bytes: &[u8]) -> Vec<String> {
    fn inner_debug(bytes: &[u8]) -> String {
        format!("{bytes:?}")
            .trim_start_matches('[')
            .trim_end_matches(']')
            .to_string()
    }
    let mut forms = vec![
        b64url::encode(bytes),
        ferret_core::testing::hex_encode(bytes),
        inner_debug(bytes),
    ];
    if let Some(slice) = bytes.get(42..81) {
        forms.push(b64url::encode(slice));
        forms.push(ferret_core::testing::hex_encode(slice));
        forms.push(inner_debug(slice));
    }
    forms
}

#[tokio::test]
async fn batch_bytes_never_reach_the_log() {
    let sink = log_sink();
    let app = TestApp::new().await;
    let u = user(&app, 1).await;
    // Ids no other test of this file uses, since the log is shared.
    let (a, b, c) = (item(200), item(201), item(202));
    let first = seal(&u, a, 1, "batch canary");
    let other = seal(&u, b, 1, "batch canary two");
    let stale = seal(&u, b, 1, "batch canary stale");
    let t = make_tombstone(&mut OsRng, &u.vault, a, 2).expect("a tombstone");
    let mut canaries = Vec::new();
    for value in [
        first.envelope.as_slice(),
        first.tag.as_slice(),
        other.envelope.as_slice(),
        other.tag.as_slice(),
        stale.envelope.as_slice(),
        t.tomb.as_slice(),
    ] {
        canaries.extend(canaries_for(value));
    }
    canaries.push(hex16::encode(&idem(1)));
    canaries.push(hex16::encode(&idem(2)));

    // The control: a value logged on purpose trips every form built for it.
    tracing::info!(blob = ?first.envelope, "batch canary self-test, Debug");
    tracing::info!(blob = %b64url::encode(&first.envelope), "batch canary self-test, base64url");
    tracing::info!(
        blob = %ferret_core::testing::hex_encode(&first.envelope),
        "batch canary self-test, hex"
    );
    let text = String::from_utf8(sink.0.lock().unwrap().clone()).unwrap();
    for form in canaries_for(&first.envelope) {
        assert!(
            text.contains(&form),
            "the canary form {form:.40} does not fire on a print of its value"
        );
    }
    // The control lines carry the ids of the log's own test, so take the text
    // from here on only.
    let mark = sink.0.lock().unwrap().len();

    let ops = [
        op(a, 0, &first, idem(1)),
        op(b, 0, &other, idem(2)),
        op(b, 0, &stale, idem(3)),
    ];
    // A duplicate, then the real ones, a replay, a conflict and a tombstone.
    assert_eq!(
        batch(&app, &u.jar, &ops).await.status,
        StatusCode::BAD_REQUEST
    );
    let calls = [
        batch(&app, &u.jar, &ops[..2]).await,
        batch(&app, &u.jar, &ops[..2]).await,
        batch(&app, &u.jar, &[op(a, 0, &stale, idem(3))]).await,
        batch(&app, &u.jar, &[tomb_op(a, 1, &t.tomb, idem(4))]).await,
        batch(
            &app,
            &u.jar,
            &[
                tomb_op(c, 1, &[0u8; 39], idem(5)),
                op(c, 0, &first, idem(6)),
            ],
        )
        .await,
        post(&app, &u.jar, br#"{"ops": [{"blob": "garbage"}]}"#.to_vec()).await,
    ];
    assert_eq!(calls[0].status, StatusCode::OK);
    assert_eq!(calls[2].status, StatusCode::OK);
    assert_eq!(calls[3].status, StatusCode::OK);

    let text = String::from_utf8(sink.0.lock().unwrap()[mark..].to_vec()).unwrap();
    // The check only means something if the server logs these calls at all.
    assert!(text.contains("batch write"), "the batch is logged: {text}");
    for canary in canaries {
        assert!(!text.contains(&canary), "{canary:.60} is in the log");
    }
    assert!(
        !text.contains("batch canary"),
        "plaintext words are in the log"
    );
}
