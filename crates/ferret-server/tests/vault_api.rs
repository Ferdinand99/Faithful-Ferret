//! The vault API of the vault listener: the unlock methods, the changes feed
//! and the item writes. Spec: Fase 1 § 4.6, § 8.1 to § 8.4.
//!
//! Most tests drive the whole vault router (layers, guards, sessions) of a
//! `TestApp`. The ones that must show that a request never reached the database
//! use a router whose item handlers get a database that cannot be opened: any
//! call to it is a 500, so a refusal with another status proves there was none.

mod support;

use std::io;
use std::sync::{Arc, Mutex};

use axum::Router;
use axum::body::{Body, to_bytes};
use axum::extract::FromRef;
use axum::http::{Request, StatusCode};
use ferret_core::testing::TestRng;
use ferret_core::{
    ItemBody, ItemType, OsRng, UnlockedVault, VaultContext, VaultKey, decrypt_item, encrypt_item,
    item_tag, make_tombstone, verify_item_tag, verify_tombstone,
};
use ferret_server::auth::session::Origin;
use ferret_server::http::extract::SessionAuth;
use ferret_server::ids::ItemId;
use ferret_server::state::VaultDb;
use ferret_server::vault::quota::Limits;
use ferret_server::vault::store::{PutBody, PutRequest, put_item};
use ferret_server::wire::{b64url, hex16};
use ferret_server_auth::SessionScope;
use serde_json::{Value, json};
use support::accounts::{TestAccount, add_account_to_app};
use support::session::issue;
use support::{Jar, Res, TestApp, VAULT_URL, Which};
use tower::ServiceExt as _;
use tracing_subscriber::fmt::MakeWriter;

/// A signed-in user: the account, the browser's cookies and the keys the
/// browser would hold.
struct User {
    account: TestAccount,
    jar: Jar,
    vault: UnlockedVault,
}

fn vault_for(account: &TestAccount, key: u8) -> UnlockedVault {
    UnlockedVault::from_vault_key(
        VaultContext {
            account_id: account.account_id,
            vault_id: account.vault_id,
            vk_epoch: 1,
        },
        VaultKey::from_test_bytes([key; 32]),
    )
    .expect("an unlocked vault")
}

/// Test account `n` with a session on device `n`.
async fn user(app: &TestApp, n: u8) -> User {
    let account = add_account_to_app(app, n).await;
    let issued = issue(app, account.user_id, Origin::Vault, SessionScope::Full, n).await;
    User {
        vault: vault_for(&account, n),
        account,
        jar: issued.jar,
    }
}

/// Another session of the same user, on another device.
async fn second_device(app: &TestApp, user: &User, device_n: u8) -> Jar {
    issue(
        app,
        user.account.user_id,
        Origin::Vault,
        SessionScope::Full,
        device_n,
    )
    .await
    .jar
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

/// Seals a note at `rev`, as the web vault would.
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

fn live(base_rev: u64, sealed: &ferret_core::SealedItem, idem: [u8; 16]) -> Value {
    json!({
        "base_rev": base_rev,
        "blob": b64url::encode(&sealed.envelope),
        "tag": b64url::encode(&sealed.tag),
        "idem": hex16::encode(&idem),
    })
}

fn tomb(base_rev: u64, tomb: &[u8], idem: [u8; 16]) -> Value {
    json!({
        "base_rev": base_rev,
        "deleted": true,
        "tomb": b64url::encode(tomb),
        "idem": hex16::encode(&idem),
    })
}

/// A write as a page of the vault sends it.
fn put_raw(id: &str, jar: &Jar, body: Vec<u8>) -> Request<Body> {
    let mut builder = Request::builder()
        .method("PUT")
        .uri(format!("/api/sync/items/{id}"))
        .header("origin", VAULT_URL)
        .header("sec-fetch-site", "same-origin")
        .header("ferret-protocol", "1")
        .header("content-type", "application/json");
    if let Some(cookie) = jar.header() {
        builder = builder.header("cookie", cookie);
    }
    builder.body(Body::from(body)).expect("a request")
}

fn get_req(uri: &str, jar: &Jar) -> Request<Body> {
    let mut builder = Request::builder().method("GET").uri(uri);
    if let Some(cookie) = jar.header() {
        builder = builder.header("cookie", cookie);
    }
    builder.body(Body::empty()).expect("a request")
}

async fn put(app: &TestApp, jar: &Jar, id: ItemId, body: &Value) -> Res {
    app.call_raw(
        Which::Vault,
        put_raw(
            &hex16::encode(id.as_bytes()),
            jar,
            body.to_string().into_bytes(),
        ),
    )
    .await
}

async fn get(app: &TestApp, jar: &Jar, uri: &str) -> Res {
    app.call_raw(Which::Vault, get_req(uri, jar)).await
}

async fn changes(app: &TestApp, jar: &Jar, since: u64, limit: u32) -> Value {
    let res = get(
        app,
        jar,
        &format!("/api/sync/changes?since={since}&limit={limit}"),
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

async fn idem_rows(app: &TestApp) -> i64 {
    db(app, |c| {
        c.query_row("SELECT COUNT(*) FROM ferret_idem", [], |r| r.get(0))
    })
    .await
}

fn b64(value: &Value) -> Vec<u8> {
    b64url::decode(value.as_str().expect("a string")).expect("base64url")
}

// ---------------------------------------------------------------------------
// The narrow state.

/// What the vault routes may see: the database handle, and the session handle
/// the `VaultSession` extractor reads. No kit state, no `FerretState`. The
/// database of the handlers is separate from that of the sessions, so a test
/// can make one of them unusable.
#[derive(Clone)]
struct Narrow {
    auth: SessionAuth,
    db: VaultDb,
}

impl FromRef<Narrow> for SessionAuth {
    fn from_ref(state: &Narrow) -> SessionAuth {
        state.auth.clone()
    }
}

impl FromRef<Narrow> for VaultDb {
    fn from_ref(state: &Narrow) -> VaultDb {
        state.db.clone()
    }
}

/// A database that cannot be opened: every call to it fails.
fn dead_db() -> VaultDb {
    let pool = deadpool_sqlite::Config::new("/ferret-no-such-directory/none.db")
        .create_pool(deadpool_sqlite::Runtime::Tokio1)
        .expect("a pool");
    VaultDb::new(pool)
}

/// The vault routes over [`Narrow`], with sessions from the app's database and
/// handlers that have no usable database.
fn tripwire(app: &TestApp) -> Router {
    ferret_server::vault::routes::<Narrow>().with_state(Narrow {
        auth: SessionAuth::from_ref(&app.state),
        db: dead_db(),
    })
}

async fn send(router: &Router, request: Request<Body>) -> Res {
    let response = router.clone().oneshot(request).await.expect("a response");
    let (parts, body) = response.into_parts();
    let body = to_bytes(body, 16 * 1024 * 1024).await.expect("a body");
    Res {
        status: parts.status,
        headers: parts.headers,
        body: body.to_vec(),
    }
}

// ---------------------------------------------------------------------------
// Writes.

#[tokio::test]
async fn put_new_item_then_changes_returns_it_with_rev_1() {
    let app = TestApp::new().await;
    let u = user(&app, 1).await;
    let id = item(1);
    let sealed = seal(&u, id, 1, "first");
    let res = put(&app, &u.jar, id, &live(0, &sealed, idem(1))).await;
    assert_eq!(res.status, StatusCode::OK, "{}", res.text());
    assert_eq!(
        res.json(),
        json!({ "rev": 1, "seq": 2, "replayed": false }),
        "the manifest took seq 1"
    );

    let feed = changes(&app, &u.jar, 0, 500).await;
    let rows = feed["changes"].as_array().unwrap();
    assert_eq!(rows.len(), 2, "the manifest row and the item");
    let mine = rows
        .iter()
        .find(|c| c["id"] == hex16::encode(id.as_bytes()))
        .expect("the item is in the feed");
    assert_eq!(mine["rev"], 1);
    assert_eq!(mine["seq"], 2);
    assert_eq!(mine["deleted"], false);
    assert_eq!(b64(&mine["blob"]), sealed.envelope);
    assert_eq!(b64(&mine["tag"]), sealed.tag.to_vec());
    assert!(mine.get("tomb").is_none());
    assert_eq!(feed["latest_seq"], 2);
    assert_eq!(feed["vk_epoch"], 1);
    assert_eq!(feed["has_more"], false);
}

#[tokio::test]
async fn put_without_session_is_401() {
    let app = TestApp::new().await;
    let u = user(&app, 1).await;
    let sealed = seal(&u, item(1), 1, "x");
    let body = live(0, &sealed, idem(1));
    let none = Jar::default();
    let res = put(&app, &none, item(1), &body).await;
    assert_eq!(res.status, StatusCode::UNAUTHORIZED);
    assert_eq!(res.json(), json!({ "error": "unauthorized" }));
    // The same for the reads.
    for uri in ["/api/sync/changes?since=0", "/api/vault/unlock-methods"] {
        let res = get(&app, &none, uri).await;
        assert_eq!(res.status, StatusCode::UNAUTHORIZED, "{uri}");
    }
    // Nothing was written.
    assert_eq!(vault_seq(&app, &u).await, 1);
    assert_eq!(idem_rows(&app).await, 0);
}

#[tokio::test]
async fn stale_base_rev_is_409_with_the_current_row() {
    let app = TestApp::new().await;
    let u = user(&app, 1).await;
    let id = item(1);
    let first = seal(&u, id, 1, "one");
    let second = seal(&u, id, 2, "two");
    assert_eq!(
        put(&app, &u.jar, id, &live(0, &first, idem(1)))
            .await
            .status,
        StatusCode::OK
    );
    assert_eq!(
        put(&app, &u.jar, id, &live(1, &second, idem(2)))
            .await
            .json()["rev"],
        2
    );
    let stale = seal(&u, id, 2, "stale");
    let res = put(&app, &u.jar, id, &live(1, &stale, idem(3))).await;
    assert_eq!(res.status, StatusCode::CONFLICT);
    let body = res.json();
    assert_eq!(body["current_rev"], 2);
    assert_eq!(body["deleted"], false);
    assert_eq!(b64(&body["blob"]), second.envelope);
    assert_eq!(b64(&body["tag"]), second.tag.to_vec());
    // A basis ahead of the server is a conflict too, and a row that is not
    // there has revision 0.
    let ahead = put(&app, &u.jar, id, &live(7, &stale, idem(4))).await;
    assert_eq!(ahead.status, StatusCode::CONFLICT);
    let ghost = put(&app, &u.jar, item(9), &live(3, &stale, idem(5))).await;
    assert_eq!(ghost.status, StatusCode::CONFLICT);
    assert_eq!(ghost.json(), json!({ "current_rev": 0, "deleted": false }));
}

#[tokio::test]
async fn retry_with_same_idem_and_body_is_200_replayed_true() {
    let app = TestApp::new().await;
    let u = user(&app, 1).await;
    let id = item(1);
    let sealed = seal(&u, id, 1, "once");
    let body = live(0, &sealed, idem(1)).to_string().into_bytes();
    let hex = hex16::encode(id.as_bytes());
    let first = app
        .call_raw(Which::Vault, put_raw(&hex, &u.jar, body.clone()))
        .await;
    assert_eq!(
        first.json(),
        json!({ "rev": 1, "seq": 2, "replayed": false })
    );
    let again = app
        .call_raw(Which::Vault, put_raw(&hex, &u.jar, body))
        .await;
    assert_eq!(again.status, StatusCode::OK);
    assert_eq!(
        again.json(),
        json!({ "rev": 1, "seq": 2, "replayed": true })
    );
    assert_eq!(vault_seq(&app, &u).await, 2, "a replay moves no counter");
}

#[tokio::test]
async fn same_idem_other_body_is_422_idem_reuse() {
    let app = TestApp::new().await;
    let u = user(&app, 1).await;
    let id = item(1);
    let a = seal(&u, id, 1, "a");
    let b = seal(&u, id, 1, "b");
    assert_eq!(
        put(&app, &u.jar, id, &live(0, &a, idem(1))).await.status,
        StatusCode::OK
    );
    let res = put(&app, &u.jar, id, &live(0, &b, idem(1))).await;
    assert_eq!(res.status, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(error(&res), "idem_reuse");
    // The same idem and body for another item is another request too: the hash
    // covers the item id, so a replay cannot return another item's revision.
    let other = put(&app, &u.jar, item(2), &live(0, &a, idem(1))).await;
    assert_eq!(other.status, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(error(&other), "idem_reuse");
}

#[tokio::test]
async fn idem_is_scoped_per_device() {
    let app = TestApp::new().await;
    let u = user(&app, 1).await;
    let other = second_device(&app, &u, 2).await;
    let a = seal(&u, item(1), 1, "device one");
    let b = seal(&u, item(2), 1, "device two");
    assert_eq!(
        put(&app, &u.jar, item(1), &live(0, &a, idem(7)))
            .await
            .status,
        StatusCode::OK
    );
    // The same request with the same idem from another device is not a replay
    // of the first device answer: it is looked up fresh, meets the row the first
    // device made and is a conflict.
    let clash = put(&app, &other, item(1), &live(0, &a, idem(7))).await;
    assert_eq!(clash.status, StatusCode::CONFLICT);
    // Another request with that idem is not an idem clash either.
    let res = put(&app, &other, item(2), &live(0, &b, idem(7))).await;
    assert_eq!(res.status, StatusCode::OK, "{}", res.text());
    assert_eq!(res.json()["replayed"], false);
}

#[tokio::test]
async fn unknown_version_suite_or_kind_is_422_before_any_db_write() {
    let app = TestApp::new().await;
    let u = user(&app, 1).await;
    let id = item(1);
    let good = seal(&u, id, 1, "good");
    let router = tripwire(&app);

    // The control: a good envelope reaches the (dead) database, and so is 500.
    let control = send(
        &router,
        put_raw(
            &hex16::encode(id.as_bytes()),
            &u.jar,
            live(0, &good, idem(1)).to_string().into_bytes(),
        ),
    )
    .await;
    assert_eq!(control.status, StatusCode::INTERNAL_SERVER_ERROR);

    for (name, position, value) in [
        ("version", 0usize, 2u8),
        ("version 0", 0, 0),
        ("suite", 1, 2),
        ("suite 0", 1, 0),
        ("kind manifest", 2, 2),
        ("kind unknown", 2, 9),
    ] {
        let mut envelope = good.envelope.clone();
        envelope[position] = value;
        let forged = ferret_core::SealedItem {
            envelope,
            tag: good.tag,
            rev: 1,
        };
        let res = send(
            &router,
            put_raw(
                &hex16::encode(id.as_bytes()),
                &u.jar,
                live(0, &forged, idem(2)).to_string().into_bytes(),
            ),
        )
        .await;
        assert_eq!(res.status, StatusCode::UNPROCESSABLE_ENTITY, "{name}");
        assert_eq!(error(&res), "unsupported_envelope", "{name}");
    }
    // Not an envelope at all.
    let junk = ferret_core::SealedItem {
        envelope: vec![1, 1, 1, 7, 7],
        tag: good.tag,
        rev: 1,
    };
    let res = send(
        &router,
        put_raw(
            &hex16::encode(id.as_bytes()),
            &u.jar,
            live(0, &junk, idem(3)).to_string().into_bytes(),
        ),
    )
    .await;
    assert_eq!(res.status, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(error(&res), "unsupported_envelope");

    // And on the real server nothing was written either.
    let mut envelope = good.envelope.clone();
    envelope[1] = 2;
    let forged = ferret_core::SealedItem {
        envelope,
        tag: good.tag,
        rev: 1,
    };
    let res = put(&app, &u.jar, id, &live(0, &forged, idem(4))).await;
    assert_eq!(res.status, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(vault_seq(&app, &u).await, 1);
    assert_eq!(idem_rows(&app).await, 0);
}

#[tokio::test]
async fn oversize_envelope_is_413() {
    let app = TestApp::new().await;
    let u = user(&app, 1).await;
    let good = seal(&u, item(1), 1, "big");
    let router = tripwire(&app);
    let hex = hex16::encode(item(1).as_bytes());

    // An envelope one byte over 64 KiB still fits the body limit (base64url of
    // 65 537 bytes is under 128 KiB), and is refused for its size.
    let mut envelope = good.envelope.clone();
    envelope.resize(65_537, 0);
    let big = ferret_core::SealedItem {
        envelope,
        tag: good.tag,
        rev: 1,
    };
    let body = live(0, &big, idem(1)).to_string().into_bytes();
    assert!(body.len() < 128 * 1024);
    let res = send(&router, put_raw(&hex, &u.jar, body)).await;
    assert_eq!(res.status, StatusCode::PAYLOAD_TOO_LARGE);
    assert_eq!(error(&res), "too_large");

    // A body over 128 KiB is refused before it is read to the end, as JSON.
    let huge = vec![b' '; 128 * 1024 + 1];
    let res = send(&router, put_raw(&hex, &u.jar, huge)).await;
    assert_eq!(res.status, StatusCode::PAYLOAD_TOO_LARGE);
    assert_eq!(error(&res), "too_large");

    // The same on the whole server.
    let res = put(&app, &u.jar, item(1), &live(0, &big, idem(2))).await;
    assert_eq!(res.status, StatusCode::PAYLOAD_TOO_LARGE);
    assert_eq!(vault_seq(&app, &u).await, 1);
}

#[tokio::test]
async fn unknown_json_fields_are_400() {
    let app = TestApp::new().await;
    let u = user(&app, 1).await;
    let sealed = seal(&u, item(1), 1, "x");
    let router = tripwire(&app);
    let hex = hex16::encode(item(1).as_bytes());

    let mut extra = live(0, &sealed, idem(1));
    extra["vault_id"] = json!("00000000000000000000000000000000");
    let repeated = {
        let text = live(0, &sealed, idem(1)).to_string();
        text.replacen('{', r#"{"base_rev":0,"#, 1).into_bytes()
    };
    for (name, body) in [
        ("an unknown field", extra.to_string().into_bytes()),
        ("a repeated field", repeated),
        ("not JSON", b"{".to_vec()),
        ("empty", Vec::new()),
        ("an array", b"[]".to_vec()),
        (
            "a string rev",
            live(0, &sealed, idem(1))
                .to_string()
                .replace("\"base_rev\":0", "\"base_rev\":\"0\"")
                .into_bytes(),
        ),
    ] {
        let res = send(&router, put_raw(&hex, &u.jar, body)).await;
        assert_eq!(
            res.status,
            StatusCode::BAD_REQUEST,
            "{name}: {}",
            res.text()
        );
        assert_eq!(error(&res), "bad_request", "{name}");
    }
    // An id that is not 32 lower-case hexadecimal characters.
    for bad in ["zz", "ABCDEF0123456789ABCDEF0123456789", "00"] {
        let res = send(
            &router,
            put_raw(
                bad,
                &u.jar,
                live(0, &sealed, idem(1)).to_string().into_bytes(),
            ),
        )
        .await;
        assert_eq!(res.status, StatusCode::BAD_REQUEST, "{bad}");
    }
}

#[tokio::test]
async fn both_blob_and_tomb_is_400() {
    let app = TestApp::new().await;
    let u = user(&app, 1).await;
    let sealed = seal(&u, item(1), 1, "x");
    let router = tripwire(&app);
    let hex = hex16::encode(item(1).as_bytes());

    let mut both = live(0, &sealed, idem(1));
    both["tomb"] = json!(b64url::encode(&[0u8; 40]));
    let mut deleted_with_blob = tomb(0, &[0u8; 40], idem(1));
    deleted_with_blob["blob"] = json!(b64url::encode(&sealed.envelope));
    deleted_with_blob["tag"] = json!(b64url::encode(&sealed.tag));
    let mut live_marked_deleted = live(0, &sealed, idem(1));
    live_marked_deleted["deleted"] = json!(true);
    let neither = json!({ "base_rev": 0, "idem": hex16::encode(&idem(1)) });
    let mut no_tag = live(0, &sealed, idem(1));
    no_tag.as_object_mut().unwrap().remove("tag");
    let mut resurrect = live(0, &sealed, idem(1));
    resurrect["resurrect"] = json!(true);
    for (name, body) in [
        ("blob and tomb", both),
        ("tomb and blob", deleted_with_blob),
        ("blob and deleted", live_marked_deleted),
        ("neither", neither),
        ("no tag", no_tag),
        ("resurrect", resurrect),
    ] {
        let res = send(
            &router,
            put_raw(&hex, &u.jar, body.to_string().into_bytes()),
        )
        .await;
        assert_eq!(
            res.status,
            StatusCode::BAD_REQUEST,
            "{name}: {}",
            res.text()
        );
        assert_eq!(error(&res), "bad_request", "{name}");
    }
    // `resurrect: false` is the same as leaving it out.
    let mut explicit = live(0, &sealed, idem(1));
    explicit["resurrect"] = json!(false);
    let res = put(&app, &u.jar, item(1), &explicit).await;
    assert_eq!(res.status, StatusCode::OK, "{}", res.text());
}

#[tokio::test]
async fn manifest_row_cannot_be_written() {
    let app = TestApp::new().await;
    let u = user(&app, 1).await;
    let sealed = seal(&u, item(1), 1, "x");
    let manifest = ItemId::from_bytes([0u8; 16]);
    let router = tripwire(&app);
    let hex = hex16::encode(&[0u8; 16]);

    for (name, body) in [
        ("live", live(1, &sealed, idem(1))),
        ("live at 0", live(0, &sealed, idem(2))),
        ("tombstone", tomb(1, &[0u8; 40], idem(3))),
    ] {
        // Refused before the database is touched ...
        let res = send(
            &router,
            put_raw(&hex, &u.jar, body.to_string().into_bytes()),
        )
        .await;
        assert_eq!(res.status, StatusCode::FORBIDDEN, "{name}");
        assert_eq!(error(&res), "manifest_not_writable", "{name}");
        // ... and on the whole server.
        let res = put(&app, &u.jar, manifest, &body).await;
        assert_eq!(res.status, StatusCode::FORBIDDEN, "{name}");
        assert_eq!(error(&res), "manifest_not_writable", "{name}");
    }
    assert_eq!(vault_seq(&app, &u).await, 1);
    assert_eq!(idem_rows(&app).await, 0);
    let methods = get(&app, &u.jar, "/api/vault/unlock-methods").await.json();
    assert_eq!(methods["manifest"]["rev"], 1);
    assert_eq!(b64(&methods["manifest"]["envelope"]), vec![0x4d; 40]);
}

#[tokio::test]
async fn tombstone_put_stores_tomb_and_marks_deleted() {
    let app = TestApp::new().await;
    let u = user(&app, 1).await;
    let id = item(1);
    let sealed = seal(&u, id, 1, "to delete");
    assert_eq!(
        put(&app, &u.jar, id, &live(0, &sealed, idem(1)))
            .await
            .status,
        StatusCode::OK
    );
    let t = make_tombstone(&mut OsRng, &u.vault, id, 2).expect("a tombstone");
    let res = put(&app, &u.jar, id, &tomb(1, &t.tomb, idem(2))).await;
    assert_eq!(res.status, StatusCode::OK, "{}", res.text());
    assert_eq!(res.json(), json!({ "rev": 2, "seq": 3, "replayed": false }));

    let feed = changes(&app, &u.jar, 2, 500).await;
    let rows = feed["changes"].as_array().unwrap();
    assert_eq!(rows.len(), 1);
    let row = &rows[0];
    assert_eq!(row["deleted"], true);
    assert_eq!(row["rev"], 2);
    assert_eq!(b64(&row["tomb"]), t.tomb);
    assert!(row.get("blob").is_none() && row.get("tag").is_none());
    // The client checks the tombstone with its key; the server could not.
    verify_tombstone(&u.vault, id, 2, &b64(&row["tomb"])).expect("a valid tombstone");
}

#[tokio::test]
async fn tombstone_with_wrong_length_is_422() {
    let app = TestApp::new().await;
    let u = user(&app, 1).await;
    let router = tripwire(&app);
    let hex = hex16::encode(item(1).as_bytes());
    for len in [0usize, 1, 39, 41, 100] {
        let res = send(
            &router,
            put_raw(
                &hex,
                &u.jar,
                tomb(1, &vec![0u8; len], idem(1)).to_string().into_bytes(),
            ),
        )
        .await;
        assert_eq!(res.status, StatusCode::UNPROCESSABLE_ENTITY, "length {len}");
        assert_eq!(error(&res), "tombstone_invalid", "length {len}");
    }
    let res = put(&app, &u.jar, item(1), &tomb(1, &[0u8; 39], idem(2))).await;
    assert_eq!(res.status, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(vault_seq(&app, &u).await, 1);
}

#[tokio::test]
async fn put_on_deleted_item_is_409_with_deleted_true() {
    let app = TestApp::new().await;
    let u = user(&app, 1).await;
    let id = item(1);
    let sealed = seal(&u, id, 1, "gone");
    put(&app, &u.jar, id, &live(0, &sealed, idem(1))).await;
    let t = make_tombstone(&mut OsRng, &u.vault, id, 2).expect("a tombstone");
    put(&app, &u.jar, id, &tomb(1, &t.tomb, idem(2))).await;

    // A write against the revision of the tombstone does not bring it back, and
    // neither does an old basis.
    for (base, n) in [(2u64, 3u8), (1, 4)] {
        let again = seal(&u, id, base + 1, "again");
        let res = put(&app, &u.jar, id, &live(base, &again, idem(n))).await;
        assert_eq!(res.status, StatusCode::CONFLICT);
        assert_eq!(res.json(), json!({ "current_rev": 2, "deleted": true }));
    }
}

// ---------------------------------------------------------------------------
// Reads.

#[tokio::test]
async fn changes_paging_has_more_and_since_is_exclusive() {
    let app = TestApp::new().await;
    let u = user(&app, 1).await;
    for n in 1..=5u8 {
        let sealed = seal(&u, item(n), 1, &format!("item {n}"));
        let res = put(&app, &u.jar, item(n), &live(0, &sealed, idem(n))).await;
        assert_eq!(res.status, StatusCode::OK);
    }
    // The manifest is seq 1; the items are 2 to 6.
    let first = changes(&app, &u.jar, 0, 2).await;
    let seqs: Vec<u64> = first["changes"]
        .as_array()
        .unwrap()
        .iter()
        .map(|c| c["seq"].as_u64().unwrap())
        .collect();
    assert_eq!(seqs, [1, 2]);
    assert_eq!(first["has_more"], true);
    assert_eq!(first["latest_seq"], 6, "the counter, not the page end");

    let second = changes(&app, &u.jar, 2, 2).await;
    let seqs: Vec<u64> = second["changes"]
        .as_array()
        .unwrap()
        .iter()
        .map(|c| c["seq"].as_u64().unwrap())
        .collect();
    assert_eq!(seqs, [3, 4], "since is exclusive");
    assert_eq!(second["has_more"], true);

    let last = changes(&app, &u.jar, 4, 2).await;
    let seqs: Vec<u64> = last["changes"]
        .as_array()
        .unwrap()
        .iter()
        .map(|c| c["seq"].as_u64().unwrap())
        .collect();
    assert_eq!(seqs, [5, 6]);
    assert_eq!(last["has_more"], false, "no row is left after seq 6");

    let none = changes(&app, &u.jar, 6, 2).await;
    assert_eq!(none["changes"].as_array().unwrap().len(), 0);
    assert_eq!(none["has_more"], false);

    // `limit` is held to 1..=500 and `since` may be left out.
    let clamped = changes(&app, &u.jar, 0, 100_000).await;
    assert_eq!(clamped["changes"].as_array().unwrap().len(), 6);
    let zero = changes(&app, &u.jar, 0, 0).await;
    assert_eq!(zero["changes"].as_array().unwrap().len(), 1);
    let bare = get(&app, &u.jar, "/api/sync/changes").await;
    assert_eq!(bare.status, StatusCode::OK);
    assert_eq!(bare.json()["changes"].as_array().unwrap().len(), 6);

    // A malformed query is a 400 with the usual body.
    for uri in [
        "/api/sync/changes?since=-1",
        "/api/sync/changes?since=x",
        "/api/sync/changes?limit=1.5",
        "/api/sync/changes?since=9007199254740992",
        "/api/sync/changes?cursor=3",
    ] {
        let res = get(&app, &u.jar, uri).await;
        assert_eq!(res.status, StatusCode::BAD_REQUEST, "{uri}");
        assert_eq!(error(&res), "bad_request", "{uri}");
    }
}

#[tokio::test]
async fn changes_never_cross_vaults() {
    let app = TestApp::new().await;
    let a = user(&app, 1).await;
    let b = user(&app, 2).await;
    let item_a = seal(&a, item(1), 1, "secret of a");
    let item_b = seal(&b, item(2), 1, "secret of b");
    assert_eq!(
        put(&app, &a.jar, item(1), &live(0, &item_a, idem(1)))
            .await
            .status,
        StatusCode::OK
    );
    assert_eq!(
        put(&app, &b.jar, item(2), &live(0, &item_b, idem(1)))
            .await
            .status,
        StatusCode::OK
    );
    for (me, other_id, own_id) in [(&a, item(2), item(1)), (&b, item(1), item(2))] {
        let feed = changes(&app, &me.jar, 0, 500).await;
        let ids: Vec<String> = feed["changes"]
            .as_array()
            .unwrap()
            .iter()
            .map(|c| c["id"].as_str().unwrap().to_string())
            .collect();
        assert!(ids.contains(&hex16::encode(own_id.as_bytes())));
        assert!(!ids.contains(&hex16::encode(other_id.as_bytes())));
        assert_eq!(ids.len(), 2, "its own manifest and its own item");
    }
    // The other user's item id answers like a new one: no row to conflict with.
    let probe = put(&app, &b.jar, item(1), &live(0, &item_b, idem(2))).await;
    assert_eq!(probe.status, StatusCode::OK, "{}", probe.text());
    assert_eq!(probe.json()["rev"], 1);
}

#[tokio::test]
#[allow(non_snake_case)]
async fn changes_response_stops_at_4_MiB() {
    let app = TestApp::new().await;
    let u = user(&app, 1).await;
    // 70 rows of 64 000 bytes: 4.5 MB of ciphertext, more than a page holds.
    let vault = u.account.vault_id;
    let device = u.account.device;
    db(&app, move |conn| {
        for n in 0..70u8 {
            let blob = vec![n; 64_000];
            let req = PutRequest {
                item_id: item(n),
                base_rev: 0,
                body: PutBody::Live {
                    blob: &blob,
                    tag: [n; 32],
                },
                idem: idem(n),
                request_hash: [n; 32],
            };
            put_item(conn, &vault, &device, &req, &Limits::DEFAULT, 1)
                .map_err(|e| rusqlite::Error::InvalidParameterName(e.to_string()))?;
        }
        Ok(())
    })
    .await;

    let mut since = 0;
    let mut seen = Vec::new();
    let mut pages = 0;
    loop {
        let res = get(
            &app,
            &u.jar,
            &format!("/api/sync/changes?since={since}&limit=500"),
        )
        .await;
        assert_eq!(res.status, StatusCode::OK);
        assert!(
            res.body.len() <= 4 * 1024 * 1024,
            "a page of {} bytes is over 4 MiB",
            res.body.len()
        );
        let page = res.json();
        let rows = page["changes"].as_array().unwrap();
        assert!(!rows.is_empty());
        for row in rows {
            let seq = row["seq"].as_u64().unwrap();
            assert!(seq > since, "rows are in order and after since");
            since = seq;
            seen.push(seq);
        }
        pages += 1;
        if !page["has_more"].as_bool().unwrap() {
            break;
        }
        assert!(pages < 20, "paging must end");
    }
    assert!(pages >= 2, "4.5 MB cannot fit in one page");
    assert_eq!(seen.len(), 71, "the manifest and 70 items, none twice");
    assert!(seen.windows(2).all(|w| w[0] < w[1]));
}

#[tokio::test]
async fn unlock_methods_returns_wraps_pk_a_epoch_and_manifest_row() {
    let app = TestApp::new().await;
    let u = user(&app, 1).await;
    let other = user(&app, 2).await;
    let res = get(&app, &u.jar, "/api/vault/unlock-methods").await;
    assert_eq!(res.status, StatusCode::OK, "{}", res.text());
    let body = res.json();
    let methods = body["methods"].as_array().unwrap();
    assert_eq!(methods.len(), 2);
    assert_eq!(methods[0]["method_type"], 1);
    assert_eq!(methods[0]["kek_generation"], 1);
    assert_eq!(b64(&methods[0]["wrap"]), vec![0x31; 60]);
    assert_eq!(
        methods[0]["method_id"],
        hex16::encode(&support::accounts::id16(0xc1, 1))
    );
    assert_eq!(methods[1]["method_type"], 2);
    assert_eq!(b64(&methods[1]["wrap"]), vec![0x32; 60]);
    assert!(methods[0].get("credential_id").is_none() && methods[0].get("prf_salt").is_none());
    assert_eq!(b64(&body["pk_a"]), vec![0x11; 32]);
    assert_eq!(body["vk_epoch"], 1);
    assert_eq!(body["manifest"]["rev"], 1);
    assert_eq!(b64(&body["manifest"]["envelope"]), vec![0x4d; 40]);
    assert_eq!(b64(&body["manifest"]["tag"]), vec![0x7a; 32]);
    // Only the fields of the contract.
    let mut keys: Vec<&str> = body
        .as_object()
        .unwrap()
        .keys()
        .map(String::as_str)
        .collect();
    keys.sort_unstable();
    assert_eq!(keys, ["manifest", "methods", "pk_a", "vk_epoch"]);

    // The other account sees its own wraps (the ids differ per account).
    let theirs = get(&app, &other.jar, "/api/vault/unlock-methods")
        .await
        .json();
    assert_eq!(
        theirs["methods"][0]["method_id"],
        hex16::encode(&support::accounts::id16(0xc1, 2))
    );
}

#[tokio::test]
async fn vault_handlers_take_only_vault_db_state() {
    // The routes build over a state with nothing but the database handle and
    // the session handle: no `FerretState`, no kit state. If a handler needed
    // more, this would not compile.
    let app = TestApp::new().await;
    let u = user(&app, 1).await;
    let router: Router = ferret_server::vault::routes::<Narrow>().with_state(Narrow {
        auth: SessionAuth::from_ref(&app.state),
        db: app.state.vault_db.clone(),
    });
    let sealed = seal(&u, item(1), 1, "narrow");
    let res = send(
        &router,
        put_raw(
            &hex16::encode(item(1).as_bytes()),
            &u.jar,
            live(0, &sealed, idem(1)).to_string().into_bytes(),
        ),
    )
    .await;
    assert_eq!(res.status, StatusCode::OK, "{}", res.text());
    for uri in ["/api/sync/changes?since=0", "/api/vault/unlock-methods"] {
        let res = send(&router, get_req(uri, &u.jar)).await;
        assert_eq!(res.status, StatusCode::OK, "{uri}");
    }
    let res = send(
        &router,
        get_req("/api/sync/changes?since=0", &Jar::default()),
    )
    .await;
    assert_eq!(res.status, StatusCode::UNAUTHORIZED);
}

// ---------------------------------------------------------------------------
// What leaves the server.

#[tokio::test]
async fn api_responses_have_no_store() {
    let app = TestApp::new().await;
    let u = user(&app, 1).await;
    let sealed = seal(&u, item(1), 1, "cache");
    let none = Jar::default();
    let ok_put = put(&app, &u.jar, item(1), &live(0, &sealed, idem(1))).await;
    let replay = put(&app, &u.jar, item(1), &live(0, &sealed, idem(1))).await;
    let conflict = put(&app, &u.jar, item(1), &live(0, &sealed, idem(2))).await;
    let bad = put(&app, &u.jar, item(1), &json!({ "nope": 1 })).await;
    let manifest = put(
        &app,
        &u.jar,
        ItemId::from_bytes([0; 16]),
        &live(0, &sealed, idem(3)),
    )
    .await;
    let responses = [
        ("put", ok_put, StatusCode::OK),
        ("replay", replay, StatusCode::OK),
        ("conflict", conflict, StatusCode::CONFLICT),
        ("bad request", bad, StatusCode::BAD_REQUEST),
        ("manifest", manifest, StatusCode::FORBIDDEN),
        (
            "changes",
            get(&app, &u.jar, "/api/sync/changes?since=0").await,
            StatusCode::OK,
        ),
        (
            "bad query",
            get(&app, &u.jar, "/api/sync/changes?since=x").await,
            StatusCode::BAD_REQUEST,
        ),
        (
            "methods",
            get(&app, &u.jar, "/api/vault/unlock-methods").await,
            StatusCode::OK,
        ),
        (
            "no session",
            get(&app, &none, "/api/vault/unlock-methods").await,
            StatusCode::UNAUTHORIZED,
        ),
    ];
    for (name, res, status) in &responses {
        assert_eq!(res.status, *status, "{name}: {}", res.text());
        assert_eq!(res.header("cache-control"), "no-store", "{name}");
        assert!(
            res.header("content-type").starts_with("application/json"),
            "{name}"
        );
    }
}

/// A log sink the test can read.
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

/// One subscriber for the whole test binary, installed once: a scoped one per
/// test would lose events to the callsite cache when tests run in parallel.
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
/// whole value, the inside of its `Debug` text (`1, 2, 3` without the brackets,
/// which is how a `Vec<u8>` prints), and, for a long value, the same three for a
/// slice. The slice starts and ends on multiples of 3 bytes, so its base64url
/// is a real substring of the base64url of the whole.
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

#[test]
fn every_canary_form_is_a_substring_of_the_printed_value() {
    // The forms only guard anything if a print of the value contains them.
    let bytes: Vec<u8> = (0..200u32).map(|n| (n * 7 + 3) as u8).collect();
    let printed = [
        b64url::encode(&bytes),
        ferret_core::testing::hex_encode(&bytes),
        format!("{bytes:?}"),
    ];
    let forms = canaries_for(&bytes);
    assert_eq!(forms.len(), 6);
    for (n, form) in forms.iter().enumerate() {
        assert!(
            printed[n % 3].contains(form.as_str()),
            "form {n} is not a substring of the print it stands for"
        );
    }
}

#[tokio::test]
async fn blob_bytes_never_reach_the_log() {
    let sink = log_sink();

    let app = TestApp::new().await;
    let u = user(&app, 1).await;
    // An id no other test uses, since the log is shared by the tests of this file.
    let id = item(77);
    let sealed = seal(&u, id, 1, "canary");
    let second = seal(&u, id, 2, "canary two");
    let t = make_tombstone(&mut OsRng, &u.vault, id, 2).expect("a tombstone");
    let mut canaries = Vec::new();
    for value in [
        sealed.envelope.as_slice(),
        sealed.tag.as_slice(),
        second.envelope.as_slice(),
        second.tag.as_slice(),
        t.tomb.as_slice(),
    ] {
        canaries.extend(canaries_for(value));
    }
    canaries.push(hex16::encode(&idem(1)));

    // The control: a value that is logged on purpose in each form must trip
    // every canary form built for it. If a form could not match, this fails.
    let control = seal(&u, item(78), 1, "control value");
    tracing::info!(blob = ?control.envelope, "canary self-test, Debug");
    tracing::info!(blob = %b64url::encode(&control.envelope), "canary self-test, base64url");
    tracing::info!(
        blob = %ferret_core::testing::hex_encode(&control.envelope),
        "canary self-test, hex"
    );
    let text = String::from_utf8(sink.0.lock().unwrap().clone()).unwrap();
    for form in canaries_for(&control.envelope) {
        assert!(
            text.contains(&form),
            "the canary form {form:.40} does not fire on a print of its value"
        );
    }

    // A write, a replay, a conflict, a refused one, a tombstone and the reads.
    let calls = [
        put(&app, &u.jar, id, &live(0, &sealed, idem(1))).await,
        put(&app, &u.jar, id, &live(0, &sealed, idem(1))).await,
        put(&app, &u.jar, id, &live(0, &second, idem(2))).await,
        put(&app, &u.jar, id, &live(1, &second, idem(3))).await,
        put(&app, &u.jar, id, &tomb(2, &t.tomb, idem(4))).await,
        put(&app, &u.jar, id, &json!({ "blob": "garbage" })).await,
    ];
    assert_eq!(calls[0].status, StatusCode::OK);
    assert_eq!(calls[2].status, StatusCode::CONFLICT);
    get(&app, &u.jar, "/api/sync/changes?since=0").await;
    get(&app, &u.jar, "/api/vault/unlock-methods").await;

    let text = String::from_utf8(sink.0.lock().unwrap().clone()).unwrap();
    // The canary only means something if the server logs these calls at all.
    assert!(
        text.contains(&hex16::encode(id.as_bytes())),
        "the item id is logged: {text}"
    );
    assert!(text.contains("409") || text.contains("conflict"), "{text}");
    for canary in canaries {
        assert!(!text.contains(&canary), "{canary:.60} is in the log");
    }
    assert!(
        !text.contains("canary two"),
        "plaintext words are in the log"
    );
}

// ---------------------------------------------------------------------------
// The client and the server together.

#[tokio::test]
async fn real_client_roundtrip() {
    let app = TestApp::new().await;
    let u = user(&app, 1).await;
    let id = item(1);

    // The client seals, the server stores.
    let mut body = ItemBody::new(ItemType::Note, "Bank", 1_700_000_000_000);
    body.notes = Some("the code is under the flower pot".to_string());
    let sealed = encrypt_item(&mut OsRng, &u.vault, id, 1, &body, None).expect("an item");
    let res = put(&app, &u.jar, id, &live(0, &sealed, idem(1))).await;
    assert_eq!(res.status, StatusCode::OK, "{}", res.text());
    let rev = res.json()["rev"].as_u64().unwrap();
    assert_eq!(rev, sealed.rev);

    // Another device reads the feed and opens the row.
    let feed = changes(&app, &u.jar, 0, 500).await;
    let row = feed["changes"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["id"] == hex16::encode(id.as_bytes()))
        .unwrap()
        .clone();
    let blob = b64(&row["blob"]);
    let tag: [u8; 32] = b64(&row["tag"]).try_into().unwrap();
    assert_eq!(blob, sealed.envelope, "the server changes no byte");
    assert_eq!(tag, sealed.tag);
    verify_item_tag(&u.vault, id, rev, &blob, &tag).expect("the tag is good");
    assert_eq!(
        item_tag(&u.vault, id, rev, &blob).expect("a tag"),
        tag,
        "the client computes the same tag"
    );
    let opened = decrypt_item(&u.vault, id, rev, &blob, &tag).expect("opens");
    assert_eq!(opened.body.name, "Bank");
    assert_eq!(
        opened.body.notes.as_deref(),
        Some("the code is under the flower pot")
    );
    assert_eq!(opened.body.created, 1_700_000_000_000);

    // A server that changes one byte, anywhere, is caught.
    for position in [0, 3, 40, 75, blob.len() / 2, blob.len() - 1] {
        let mut forged = blob.clone();
        forged[position] ^= 1;
        assert!(
            verify_item_tag(&u.vault, id, rev, &forged, &tag).is_err(),
            "envelope byte {position}"
        );
        assert!(
            decrypt_item(&u.vault, id, rev, &forged, &tag).is_err(),
            "envelope byte {position}"
        );
    }
    let mut forged_tag = tag;
    forged_tag[5] ^= 1;
    assert!(verify_item_tag(&u.vault, id, rev, &blob, &forged_tag).is_err());
    assert!(decrypt_item(&u.vault, id, rev, &blob, &forged_tag).is_err());
    // And a row served under another revision or another item.
    assert!(verify_item_tag(&u.vault, id, rev + 1, &blob, &tag).is_err());
    assert!(verify_item_tag(&u.vault, item(2), rev, &blob, &tag).is_err());

    // An edit, then a deletion, each against the revision the client saw.
    let mut edited = ItemBody::new(ItemType::Note, "Bank", 1_700_000_000_000);
    edited.notes = Some("moved the pot".to_string());
    let sealed2 =
        encrypt_item(&mut OsRng, &u.vault, id, 2, &edited, Some(blob.as_slice())).expect("an edit");
    let res = put(&app, &u.jar, id, &live(1, &sealed2, idem(2))).await;
    assert_eq!(res.json()["rev"], 2);
    let t = make_tombstone(&mut OsRng, &u.vault, id, 3).expect("a tombstone");
    let res = put(&app, &u.jar, id, &tomb(2, &t.tomb, idem(3))).await;
    assert_eq!(res.json()["rev"], 3);
    let feed = changes(&app, &u.jar, 2, 500).await;
    let rows = feed["changes"].as_array().unwrap();
    assert_eq!(rows.len(), 1, "one row per item, at its newest revision");
    let served = b64(&rows[0]["tomb"]);
    verify_tombstone(&u.vault, id, 3, &served).expect("a valid tombstone");
    let mut forged = served.clone();
    forged[10] ^= 1;
    assert!(verify_tombstone(&u.vault, id, 3, &forged).is_err());
    assert!(verify_tombstone(&u.vault, id, 2, &served).is_err());
    assert!(verify_tombstone(&u.vault, item(2), 3, &served).is_err());
}

// ---------------------------------------------------------------------------
// Limits, floors and the shape of refusals.

#[tokio::test]
async fn a_full_vault_refuses_a_new_item_with_413_quota_exceeded() {
    let app = TestApp::new().await;
    let u = user(&app, 1).await;
    // The vault holds as many rows as it may: the counter says so, as it would
    // after that many writes.
    let vault = u.account.vault_id;
    let max_items = i64::from(Limits::DEFAULT.max_items);
    db(&app, move |c| {
        c.execute(
            "UPDATE ferret_vaults SET item_count = ?2 WHERE vault_id = ?1",
            rusqlite::params![vault.as_bytes().as_slice(), max_items],
        )
    })
    .await;
    let sealed = seal(&u, item(1), 1, "one too many");
    let res = put(&app, &u.jar, item(1), &live(0, &sealed, idem(1))).await;
    assert_eq!(res.status, StatusCode::PAYLOAD_TOO_LARGE, "{}", res.text());
    assert_eq!(res.json(), json!({ "error": "quota_exceeded" }));
    assert_eq!(vault_seq(&app, &u).await, 1, "nothing was written");
    // A refusal for the size of one envelope is the other 413.
    assert_ne!(error(&res), "too_large");
}

#[tokio::test]
async fn the_feed_refuses_a_cursor_below_the_floor_with_410() {
    let app = TestApp::new().await;
    let u = user(&app, 1).await;
    for n in 1..=4u8 {
        let sealed = seal(&u, item(n), 1, &format!("item {n}"));
        put(&app, &u.jar, item(n), &live(0, &sealed, idem(n))).await;
    }
    // A purge of old tombstones raised the floor to 3.
    let vault = u.account.vault_id;
    db(&app, move |c| {
        c.execute(
            "UPDATE ferret_vaults SET min_valid_since = 3 WHERE vault_id = ?1",
            [vault.as_bytes().as_slice()],
        )
    })
    .await;
    for since in [0u64, 1, 2] {
        let res = get(&app, &u.jar, &format!("/api/sync/changes?since={since}")).await;
        assert_eq!(res.status, StatusCode::GONE, "since {since}");
        assert_eq!(
            res.json(),
            json!({ "error": "gone", "min_valid_since": 3 }),
            "since {since}"
        );
        assert_eq!(res.header("cache-control"), "no-store");
    }
    // At the floor and above it, the feed answers as before.
    for since in [3u64, 4, 5] {
        let res = get(&app, &u.jar, &format!("/api/sync/changes?since={since}")).await;
        assert_eq!(res.status, StatusCode::OK, "since {since}");
    }
}

#[tokio::test]
async fn a_bad_path_parameter_is_the_json_400() {
    let app = TestApp::new().await;
    let u = user(&app, 1).await;
    let sealed = seal(&u, item(1), 1, "x");
    let body = live(0, &sealed, idem(1)).to_string().into_bytes();
    // A segment that is not UTF-8 once decoded, one that is not an id, an
    // empty one.
    for id in ["%FF", "%ff%fe", "not-an-id", "%00"] {
        let res = app
            .call_raw(Which::Vault, put_raw(id, &u.jar, body.clone()))
            .await;
        assert_eq!(res.status, StatusCode::BAD_REQUEST, "{id}");
        assert_eq!(res.json(), json!({ "error": "bad_request" }), "{id}");
        assert!(
            res.header("content-type").starts_with("application/json"),
            "{id}"
        );
    }
    // The same through a router that has no layers of the server.
    let router = tripwire(&app);
    let res = send(&router, put_raw("%FF", &u.jar, body)).await;
    assert_eq!(res.status, StatusCode::BAD_REQUEST);
    assert_eq!(res.json(), json!({ "error": "bad_request" }));
}
