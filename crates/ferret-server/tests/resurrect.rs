//! Bringing a deleted item back: `PUT /api/sync/items/{id}` with
//! `resurrect: true`. Spec: Fase 1 § 8.4 ("No resurrection without an active
//! choice").
//!
//! The rule: against a tombstone, a live body with `resurrect: true` and a
//! `base_rev` equal to the tombstone's `rev` is stored at `rev + 1`; anything
//! else against a tombstone is `409` with `deleted: true`. Against a live row
//! (or no row) the flag changes nothing.

mod support;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use ferret_core::{
    ItemBody, ItemType, OsRng, UnlockedVault, VaultContext, VaultKey, decrypt_item, encrypt_item,
    make_tombstone,
};
use ferret_server::auth::session::Origin;
use ferret_server::ids::ItemId;
use ferret_server::vault::quota::Limits;
use ferret_server::vault::store::{PutBody, PutOutcome, PutRequest, put_item};
use ferret_server::wire::{b64url, hex16};
use ferret_server_auth::SessionScope;
use serde_json::{Value, json};
use support::accounts::{TestAccount, add_account_to_app};
use support::session::issue;
use support::{Jar, Res, TestApp, VAULT_URL, Which};

/// A signed-in user: the account, the browser's cookies and the keys the
/// browser would hold.
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
    encrypt_item(&mut OsRng, &user.vault, id, rev, &body, None).expect("an item")
}

fn live(base_rev: u64, sealed: &ferret_core::SealedItem, idem: [u8; 16]) -> Value {
    json!({
        "base_rev": base_rev,
        "blob": b64url::encode(&sealed.envelope),
        "tag": b64url::encode(&sealed.tag),
        "idem": hex16::encode(&idem),
    })
}

/// A live write that asks to bring a deleted item back.
fn resurrecting(base_rev: u64, sealed: &ferret_core::SealedItem, idem: [u8; 16]) -> Value {
    let mut body = live(base_rev, sealed, idem);
    body["resurrect"] = json!(true);
    body
}

fn tomb(base_rev: u64, tomb: &[u8], idem: [u8; 16]) -> Value {
    json!({
        "base_rev": base_rev,
        "deleted": true,
        "tomb": b64url::encode(tomb),
        "idem": hex16::encode(&idem),
    })
}

async fn put(app: &TestApp, jar: &Jar, id: ItemId, body: &Value) -> Res {
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
    let request = builder
        .body(Body::from(body.to_string().into_bytes()))
        .expect("a request");
    app.call_raw(Which::Vault, request).await
}

async fn changes(app: &TestApp, jar: &Jar, since: u64) -> Value {
    let mut builder = Request::builder().uri(format!("/api/sync/changes?since={since}"));
    if let Some(cookie) = jar.header() {
        builder = builder.header("cookie", cookie);
    }
    let res = app
        .call_raw(
            Which::Vault,
            builder.body(Body::empty()).expect("a request"),
        )
        .await;
    assert_eq!(res.status, StatusCode::OK, "{}", res.text());
    res.json()
}

fn error(res: &Res) -> String {
    res.json()["error"].as_str().unwrap_or("").to_string()
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

/// The live row count of the vault and the state of one item row.
async fn counters(app: &TestApp, user: &User, id: ItemId) -> (i64, bool) {
    let vault = user.account.vault_id;
    db(app, move |c| {
        let count: i64 = c.query_row(
            "SELECT item_count FROM ferret_vaults WHERE vault_id = ?1",
            [vault.as_bytes().as_slice()],
            |r| r.get(0),
        )?;
        let deleted: i64 = c.query_row(
            "SELECT deleted FROM ferret_items WHERE vault_id = ?1 AND item_id = ?2",
            rusqlite::params![vault.as_bytes().as_slice(), id.as_bytes().as_slice()],
            |r| r.get(0),
        )?;
        Ok((count, deleted == 1))
    })
    .await
}

/// Item 1 is created (rev 1, seq 2) and deleted (rev 2, seq 3).
async fn deleted_item(app: &TestApp, u: &User, id: ItemId) {
    let sealed = seal(u, id, 1, "gone");
    let res = put(app, &u.jar, id, &live(0, &sealed, idem(1))).await;
    assert_eq!(res.status, StatusCode::OK, "{}", res.text());
    let t = make_tombstone(&mut OsRng, &u.vault, id, 2).expect("a tombstone");
    let res = put(app, &u.jar, id, &tomb(1, &t.tomb, idem(2))).await;
    assert_eq!(res.status, StatusCode::OK, "{}", res.text());
    assert_eq!(vault_seq(app, u).await, 3);
}

#[tokio::test]
async fn resurrect_with_base_rev_equal_to_the_tombstone_rev_stores_rev_plus_1_and_a_new_seq() {
    let app = TestApp::new().await;
    let u = user(&app, 1).await;
    let id = item(1);
    deleted_item(&app, &u, id).await;

    let back = seal(&u, id, 3, "back");
    let res = put(&app, &u.jar, id, &resurrecting(2, &back, idem(3))).await;
    assert_eq!(res.status, StatusCode::OK, "{}", res.text());
    assert_eq!(
        res.json(),
        json!({ "rev": 3, "seq": 4, "replayed": false }),
        "rev + 1 of the tombstone, and the next seq of the vault"
    );
    assert_eq!(vault_seq(&app, &u).await, 4);

    // The feed shows the row live again, with the bytes that were sent.
    let feed = changes(&app, &u.jar, 3).await;
    let rows = feed["changes"].as_array().unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0]["rev"], 3);
    assert_eq!(rows[0]["seq"], 4);
    assert_eq!(rows[0]["deleted"], false);
    assert!(rows[0].get("tomb").is_none());
    let blob = b64url::decode(rows[0]["blob"].as_str().unwrap()).unwrap();
    let tag: [u8; 32] = b64url::decode(rows[0]["tag"].as_str().unwrap())
        .unwrap()
        .try_into()
        .unwrap();
    assert_eq!(blob, back.envelope);
    let opened = decrypt_item(&u.vault, id, 3, &blob, &tag).expect("opens at rev 3");
    assert_eq!(opened.body.name, "back");
    assert_eq!(counters(&app, &u, id).await, (2, false));
}

#[tokio::test]
async fn put_on_a_tombstone_without_resurrect_is_409_deleted_true() {
    let app = TestApp::new().await;
    let u = user(&app, 1).await;
    let id = item(1);
    deleted_item(&app, &u, id).await;

    for (base, n) in [(2u64, 3u8), (1, 4), (5, 5)] {
        let again = seal(&u, id, base + 1, "again");
        let res = put(&app, &u.jar, id, &live(base, &again, idem(n))).await;
        assert_eq!(res.status, StatusCode::CONFLICT, "base {base}");
        assert_eq!(
            res.json(),
            json!({ "current_rev": 2, "deleted": true }),
            "base {base}"
        );
    }
    // Nor does a second deletion write over the tombstone.
    let t = make_tombstone(&mut OsRng, &u.vault, id, 3).expect("a tombstone");
    let res = put(&app, &u.jar, id, &tomb(2, &t.tomb, idem(6))).await;
    assert_eq!(res.status, StatusCode::CONFLICT);
    assert_eq!(vault_seq(&app, &u).await, 3);
    assert_eq!(counters(&app, &u, id).await, (1, true));
}

#[tokio::test]
async fn resurrect_with_an_older_base_rev_is_409_and_writes_nothing() {
    let app = TestApp::new().await;
    let u = user(&app, 1).await;
    let id = item(1);
    deleted_item(&app, &u, id).await;

    // An older basis, and a basis ahead of the tombstone: both are refused,
    // whatever the flag says.
    for (base, n) in [(1u64, 3u8), (0, 4), (3, 5), (9, 6)] {
        let back = seal(&u, id, base + 1, "back");
        let res = put(&app, &u.jar, id, &resurrecting(base, &back, idem(n))).await;
        assert_eq!(res.status, StatusCode::CONFLICT, "base {base}");
        assert_eq!(
            res.json(),
            json!({ "current_rev": 2, "deleted": true }),
            "base {base}"
        );
    }
    assert_eq!(vault_seq(&app, &u).await, 3, "no seq was used");
    assert_eq!(counters(&app, &u, id).await, (1, true), "still deleted");
    let rows: i64 = db(&app, |c| {
        c.query_row("SELECT COUNT(*) FROM ferret_idem", [], |r| r.get(0))
    })
    .await;
    assert_eq!(rows, 2, "a refused write leaves no idempotency record");
}

#[tokio::test]
async fn resurrect_flag_on_a_live_row_is_an_ordinary_compare_and_set() {
    let app = TestApp::new().await;
    let u = user(&app, 1).await;
    let id = item(1);

    // No row yet: the flag changes nothing about a create.
    let first = seal(&u, id, 1, "first");
    let res = put(&app, &u.jar, id, &resurrecting(0, &first, idem(1))).await;
    assert_eq!(res.status, StatusCode::OK, "{}", res.text());
    assert_eq!(res.json()["rev"], 1);

    // The right basis against a live row is an edit.
    let second = seal(&u, id, 2, "second");
    let res = put(&app, &u.jar, id, &resurrecting(1, &second, idem(2))).await;
    assert_eq!(res.status, StatusCode::OK, "{}", res.text());
    assert_eq!(res.json(), json!({ "rev": 2, "seq": 3, "replayed": false }));

    // A stale basis is the conflict of a live row, with its content.
    let stale = seal(&u, id, 2, "stale");
    let res = put(&app, &u.jar, id, &resurrecting(1, &stale, idem(3))).await;
    assert_eq!(res.status, StatusCode::CONFLICT);
    let body = res.json();
    assert_eq!(body["current_rev"], 2);
    assert_eq!(body["deleted"], false);
    assert_eq!(body["blob"], b64url::encode(&second.envelope));
    assert_eq!(body["tag"], b64url::encode(&second.tag));
    assert_eq!(counters(&app, &u, id).await, (2, false));
}

#[tokio::test]
async fn resurrect_with_the_tombstone_form_is_400_bad_request() {
    let app = TestApp::new().await;
    let u = user(&app, 1).await;
    let id = item(1);
    deleted_item(&app, &u, id).await;
    let live_id = item(2);
    let sealed = seal(&u, live_id, 1, "live");
    put(&app, &u.jar, live_id, &live(0, &sealed, idem(7))).await;
    let seq = vault_seq(&app, &u).await;

    // A tombstone that asks to be brought back means nothing: against the
    // tombstone it replaces, and against a live row it would be a deletion.
    let t = make_tombstone(&mut OsRng, &u.vault, id, 3).expect("a tombstone");
    let t_live = make_tombstone(&mut OsRng, &u.vault, live_id, 2).expect("a tombstone");
    for (name, target, body) in [
        ("over a tombstone", id, tomb(2, &t.tomb, idem(3))),
        ("over a live row", live_id, tomb(1, &t_live.tomb, idem(4))),
    ] {
        let mut body = body;
        body["resurrect"] = json!(true);
        let res = put(&app, &u.jar, target, &body).await;
        assert_eq!(
            res.status,
            StatusCode::BAD_REQUEST,
            "{name}: {}",
            res.text()
        );
        assert_eq!(error(&res), "bad_request", "{name}");
    }
    assert_eq!(vault_seq(&app, &u).await, seq, "nothing was written");
    assert!(counters(&app, &u, id).await.1);
    assert!(!counters(&app, &u, live_id).await.1);
}

#[tokio::test]
async fn resurrect_false_is_still_accepted() {
    let app = TestApp::new().await;
    let u = user(&app, 1).await;
    let id = item(1);

    let sealed = seal(&u, id, 1, "one");
    let mut body = live(0, &sealed, idem(1));
    body["resurrect"] = json!(false);
    let res = put(&app, &u.jar, id, &body).await;
    assert_eq!(res.status, StatusCode::OK, "{}", res.text());

    // On a tombstone body too.
    let t = make_tombstone(&mut OsRng, &u.vault, id, 2).expect("a tombstone");
    let mut body = tomb(1, &t.tomb, idem(2));
    body["resurrect"] = json!(false);
    let res = put(&app, &u.jar, id, &body).await;
    assert_eq!(res.status, StatusCode::OK, "{}", res.text());
    assert_eq!(res.json()["rev"], 2);

    // And against the tombstone it is no request to bring the item back.
    let back = seal(&u, id, 3, "back");
    let mut body = live(2, &back, idem(3));
    body["resurrect"] = json!(false);
    let res = put(&app, &u.jar, id, &body).await;
    assert_eq!(res.status, StatusCode::CONFLICT);
    assert_eq!(res.json(), json!({ "current_rev": 2, "deleted": true }));
}

#[tokio::test]
async fn resurrect_counts_against_max_items_again() {
    let app = TestApp::new().await;
    let u = user(&app, 1).await;
    let id = item(1);
    deleted_item(&app, &u, id).await;
    // The manifest is the only live row.
    assert_eq!(counters(&app, &u, id).await, (1, true));

    // With room for the manifest alone, the item does not come back: the
    // tombstone was not counted, and the live row is.
    let back = seal(&u, id, 3, "back");
    let (vault, device) = (u.account.vault_id, u.account.device);
    let (envelope, tag) = (back.envelope.clone(), back.tag);
    let outcome = db(&app, move |conn| {
        let request = PutRequest {
            item_id: id,
            base_rev: 2,
            body: PutBody::Live {
                blob: &envelope,
                tag,
            },
            idem: idem(9),
            request_hash: [9; 32],
            resurrect: true,
        };
        let limits = Limits {
            max_items: 1,
            ..Limits::DEFAULT
        };
        Ok(put_item(conn, &vault, &device, &request, &limits, 1).expect("a write"))
    })
    .await;
    assert_eq!(outcome, PutOutcome::QuotaExceeded);
    assert_eq!(counters(&app, &u, id).await, (1, true), "nothing changed");
    assert_eq!(vault_seq(&app, &u).await, 3);

    // With room it does, and the count goes up by one.
    let res = put(&app, &u.jar, id, &resurrecting(2, &back, idem(10))).await;
    assert_eq!(res.status, StatusCode::OK, "{}", res.text());
    assert_eq!(counters(&app, &u, id).await, (2, false));
}

#[tokio::test]
async fn resurrect_replay_with_the_same_idem_is_replayed_true() {
    let app = TestApp::new().await;
    let u = user(&app, 1).await;
    let id = item(1);
    deleted_item(&app, &u, id).await;

    let back = seal(&u, id, 3, "back");
    let body = resurrecting(2, &back, idem(3));
    let first = put(&app, &u.jar, id, &body).await;
    assert_eq!(first.status, StatusCode::OK, "{}", first.text());
    assert_eq!(
        first.json(),
        json!({ "rev": 3, "seq": 4, "replayed": false })
    );

    // The same request again: the answer of the first, with `replayed`, and
    // no second write (the row is live now, so a second write would conflict).
    let again = put(&app, &u.jar, id, &body).await;
    assert_eq!(again.status, StatusCode::OK, "{}", again.text());
    assert_eq!(
        again.json(),
        json!({ "rev": 3, "seq": 4, "replayed": true })
    );
    assert_eq!(vault_seq(&app, &u).await, 4);

    // The same idem for another request is a reuse.
    let other = seal(&u, id, 4, "other");
    let res = put(&app, &u.jar, id, &live(3, &other, idem(3))).await;
    assert_eq!(res.status, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(error(&res), "idem_reuse");
}
