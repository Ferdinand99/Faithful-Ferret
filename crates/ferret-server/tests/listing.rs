//! `GET /api/sync/items`: the full listing a client uses to reconcile.
//! Spec: Fase 1 § 8.4 and § 8.6.
//!
//! Most tests drive the whole vault router of a `TestApp`. The ones about how a
//! page stops also use a connection, because they need rows the API would not
//! accept (a vault full of 64 KiB envelopes).

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
use ferret_server::error::StoreError;
use ferret_server::ids::{ItemId, MANIFEST_ITEM_ID, VaultId};
use ferret_server::product;
use ferret_server::vault::changes::{MAX_LIMIT, PAGE_BYTES};
use ferret_server::vault::reconcile::list_items;
use ferret_server::wire::{ItemsRes, b64url, hex16};
use ferret_server_auth::SessionScope;
use rusqlite::{Connection, params};
use serde_json::{Value, json};
use support::accounts::{TestAccount, add_account, add_account_to_app, id16};
use support::session::issue;
use support::{Jar, Res, TestApp, VAULT_URL, Which};
use tracing_subscriber::fmt::MakeWriter;
use vole_kit::db::migrate::apply_migrations;

/// A signed-in user: the account, the browser's cookies and the vault keys.
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

fn hex(id: ItemId) -> String {
    hex16::encode(id.as_bytes())
}

fn id_of(n: u8) -> [u8; 16] {
    *item(n).as_bytes()
}

fn get_req(uri: &str, jar: &Jar) -> Request<Body> {
    let mut builder = Request::builder().method("GET").uri(uri);
    if let Some(cookie) = jar.header() {
        builder = builder.header("cookie", cookie);
    }
    builder.body(Body::empty()).expect("a request")
}

async fn get(app: &TestApp, jar: &Jar, uri: &str) -> Res {
    app.call_raw(Which::Vault, get_req(uri, jar)).await
}

/// A write as a page of the vault sends it; it must succeed.
async fn put(app: &TestApp, u: &User, id: ItemId, body: &Value) {
    let request = Request::builder()
        .method("PUT")
        .uri(format!("/api/sync/items/{}", hex(id)))
        .header("origin", VAULT_URL)
        .header("sec-fetch-site", "same-origin")
        .header("ferret-protocol", "1")
        .header("content-type", "application/json")
        .header("cookie", u.jar.header().expect("a cookie"))
        .body(Body::from(body.to_string()))
        .expect("a request");
    let res = app.call_raw(Which::Vault, request).await;
    assert_eq!(res.status, StatusCode::OK, "{}", res.text());
}

/// Writes a live item at `rev` (the basis is `rev - 1`).
async fn put_live(app: &TestApp, u: &User, id: ItemId, rev: u64, name: &str) {
    let mut body = ItemBody::new(ItemType::Note, name, 1);
    body.notes = Some(format!("notes of {name}"));
    let sealed = encrypt_item(
        &mut TestRng::new(format!("{name}/{rev}").as_bytes()),
        &u.vault,
        id,
        rev,
        &body,
        None,
    )
    .expect("an item");
    let mut idem = [0u8; 16];
    idem[0] = id.as_bytes()[1];
    idem[1] = u8::try_from(rev).expect("a small revision");
    put(
        app,
        u,
        id,
        &json!({
            "base_rev": rev - 1,
            "blob": b64url::encode(&sealed.envelope),
            "tag": b64url::encode(&sealed.tag),
            "idem": hex16::encode(&idem),
        }),
    )
    .await;
}

/// Deletes an item whose current revision is `rev - 1`.
async fn put_tomb(app: &TestApp, u: &User, id: ItemId, rev: u64) {
    let t = make_tombstone(&mut OsRng, &u.vault, id, rev).expect("a tombstone");
    let mut idem = [0xee; 16];
    idem[0] = id.as_bytes()[1];
    idem[1] = u8::try_from(rev).expect("a small revision");
    put(
        app,
        u,
        id,
        &json!({
            "base_rev": rev - 1,
            "deleted": true,
            "tomb": b64url::encode(&t.tomb),
            "idem": hex16::encode(&idem),
        }),
    )
    .await;
}

async fn db<T: Send + 'static>(
    app: &TestApp,
    f: impl FnOnce(&mut Connection) -> rusqlite::Result<T> + Send + 'static,
) -> T {
    app.state
        .vault_db
        .with_conn(move |conn| Ok(f(conn)?))
        .await
        .expect("a database call")
}

/// One page, parsed with the wire type (which checks `has_more` against
/// `next_after`).
async fn page(app: &TestApp, u: &User, query: &str) -> ItemsRes {
    let res = get(app, &u.jar, &format!("/api/sync/items{query}")).await;
    assert_eq!(res.status, StatusCode::OK, "{}", res.text());
    assert_eq!(res.header("cache-control"), "no-store");
    let parsed: ItemsRes = serde_json::from_slice(&res.body).expect("an items page");
    parsed.validate().expect("next_after and has_more agree");
    parsed
}

fn ids(page: &ItemsRes) -> Vec<[u8; 16]> {
    page.items.iter().map(|row| row.id).collect()
}

/// Every page from the start, with the page size `limit`.
async fn all_pages(app: &TestApp, u: &User, limit: u32) -> Vec<ItemsRes> {
    let mut pages = Vec::new();
    let mut query = format!("?limit={limit}");
    loop {
        let next = page(app, u, &query).await;
        let more = next.next_after;
        pages.push(next);
        match more {
            Some(after) => {
                query = format!("?limit={limit}&after={}", hex16::encode(&after));
            }
            None => return pages,
        }
        assert!(pages.len() < 100, "the listing does not end");
    }
}

/// Inserts `count` live rows of `blob_len` bytes straight into the table. The
/// ids rise with `n` and come after the ids of `item()` (first byte `0x20`).
fn insert_rows(conn: &Connection, vault: &VaultId, count: u32, blob_len: usize) {
    let mut stmt = conn
        .prepare(
            "INSERT INTO ferret_items \
             (vault_id, item_id, rev, seq, deleted, blob, tag, tomb, size, changed_at) \
             VALUES (?1, ?2, 1, ?3, 0, zeroblob(?4), ?5, NULL, ?4, 0)",
        )
        .expect("prepare");
    for n in 0..count {
        let mut id = [0u8; 16];
        id[0] = 0x20;
        id[1..5].copy_from_slice(&n.to_be_bytes());
        stmt.execute(params![
            vault.as_bytes(),
            id,
            i64::from(n) + 1000,
            i64::try_from(blob_len).expect("a size"),
            [0x55u8; 32]
        ])
        .expect("a row");
    }
}

fn migrated() -> Connection {
    product::install();
    let mut conn = Connection::open_in_memory().expect("open");
    conn.execute_batch("PRAGMA foreign_keys = ON;")
        .expect("pragma");
    apply_migrations(&mut conn).expect("migrations apply");
    conn
}

// ------------------------------------------------------------------ the rows

#[tokio::test]
async fn listing_returns_every_row_in_item_id_order_with_tombstones_and_the_manifest() {
    let app = TestApp::new().await;
    let u = user(&app, 1).await;
    // Written out of id order, and one of them deleted again.
    put_live(&app, &u, item(5), 1, "five").await;
    put_live(&app, &u, item(2), 1, "two").await;
    put_live(&app, &u, item(9), 1, "nine").await;
    put_tomb(&app, &u, item(2), 2).await;

    let listed = page(&app, &u, "").await;
    assert!(!listed.has_more);
    assert_eq!(listed.next_after, None);
    assert_eq!(
        ids(&listed),
        [*MANIFEST_ITEM_ID.as_bytes(), id_of(2), id_of(5), id_of(9)],
        "the manifest row first, then by id, the tombstone in its place"
    );
    let [manifest, two, five, nine] = listed.items.as_slice() else {
        panic!("four rows");
    };
    assert!(!manifest.deleted && manifest.blob.is_some() && manifest.tag.is_some());
    assert_eq!(manifest.rev, 1);
    assert!(two.deleted && two.blob.is_none() && two.tag.is_none());
    assert_eq!(two.tomb.as_ref().map(Vec::len), Some(40));
    assert_eq!(two.rev, 2);
    for live in [five, nine] {
        assert!(!live.deleted && live.tomb.is_none());
        assert!(live.blob.is_some() && live.tag.is_some());
        assert_eq!(live.rev, 1);
    }

    // The raw JSON leaves out what a row does not have: no nulls.
    let raw = get(&app, &u.jar, "/api/sync/items").await.json();
    let tombstone = &raw["items"][1];
    assert_eq!(tombstone["deleted"], json!(true));
    assert!(tombstone.get("blob").is_none() && tombstone.get("tag").is_none());
    assert!(raw.get("next_after").is_none());
    assert_eq!(raw["vk_epoch"], json!(1));
    assert_eq!(raw["restore_epoch"], json!(0));
}

#[tokio::test]
async fn pages_follow_next_after_and_has_more() {
    let app = TestApp::new().await;
    let u = user(&app, 1).await;
    for n in [4u8, 1, 3, 2, 5] {
        put_live(&app, &u, item(n), 1, &format!("item {n}")).await;
    }
    // Six rows, two to a page.
    let first = page(&app, &u, "?limit=2").await;
    assert!(first.has_more);
    assert_eq!(ids(&first), [*MANIFEST_ITEM_ID.as_bytes(), id_of(1)]);
    assert_eq!(first.next_after, Some(id_of(1)), "the id of the last row");

    let second = page(&app, &u, &format!("?limit=2&after={}", hex(item(1)))).await;
    assert!(second.has_more);
    assert_eq!(ids(&second), [id_of(2), id_of(3)]);
    assert_eq!(second.next_after, Some(id_of(3)));

    let third = page(&app, &u, &format!("?limit=2&after={}", hex(item(3)))).await;
    assert!(
        !third.has_more && third.next_after.is_none(),
        "the last row is on this page"
    );
    assert_eq!(ids(&third), [id_of(4), id_of(5)]);

    // The row count is a multiple of the page size: the last page is full, and
    // says that nothing is behind it.
    let pages = all_pages(&app, &u, 2).await;
    assert_eq!(pages.len(), 3);
    let last = pages.last().expect("pages");
    assert!(!last.has_more && last.next_after.is_none());
    assert_eq!(last.items.len(), 2);

    // After the last id there is an empty page, not an error.
    let beyond = page(&app, &u, &format!("?after={}", hex(item(5)))).await;
    assert!(beyond.items.is_empty() && !beyond.has_more && beyond.next_after.is_none());
    // `after` the manifest id starts at the first real row.
    let after_manifest = page(&app, &u, &format!("?after={}", hex16::encode(&[0u8; 16]))).await;
    assert_eq!(after_manifest.items.len(), 5);
}

#[tokio::test]
async fn as_of_seq_is_the_vault_seq_read_with_the_page() {
    let app = TestApp::new().await;
    let u = user(&app, 1).await;
    assert_eq!(
        page(&app, &u, "").await.as_of_seq,
        1,
        "the manifest made seq 1"
    );
    put_live(&app, &u, item(1), 1, "one").await;
    put_live(&app, &u, item(2), 1, "two").await;
    let vault = u.account.vault_id;
    let counter: i64 = db(&app, move |c| {
        c.query_row(
            "SELECT seq FROM ferret_vaults WHERE vault_id = ?1",
            [vault.as_bytes().as_slice()],
            |r| r.get(0),
        )
    })
    .await;
    assert_eq!(counter, 3);
    // The same number on every page of a listing that nothing wrote to, and the
    // highest `seq` of the rows never passes it.
    let pages = all_pages(&app, &u, 1).await;
    assert_eq!(pages.len(), 3);
    for listed in &pages {
        assert_eq!(i64::try_from(listed.as_of_seq).unwrap(), counter);
        assert!(listed.items.iter().all(|row| row.seq <= listed.as_of_seq));
    }
    put_tomb(&app, &u, item(1), 2).await;
    assert_eq!(page(&app, &u, "").await.as_of_seq, 4);
}

#[tokio::test]
async fn listing_is_never_410_even_below_min_valid_since() {
    let app = TestApp::new().await;
    let u = user(&app, 1).await;
    put_live(&app, &u, item(1), 1, "one").await;
    put_live(&app, &u, item(2), 1, "two").await;
    put_tomb(&app, &u, item(2), 2).await;
    let vault = u.account.vault_id;
    db(&app, move |c| {
        c.execute(
            "UPDATE ferret_vaults SET min_valid_since = 4 WHERE vault_id = ?1",
            [vault.as_bytes().as_slice()],
        )
    })
    .await;
    // The feed refuses a cursor below the floor; the listing is the way out.
    let feed = get(&app, &u.jar, "/api/sync/changes?since=2").await;
    assert_eq!(feed.status, StatusCode::GONE);
    let listed = page(&app, &u, "").await;
    assert_eq!(listed.items.len(), 3);
    let after = page(&app, &u, &format!("?after={}", hex(item(1)))).await;
    assert_eq!(ids(&after), [id_of(2)]);
}

#[tokio::test]
async fn a_write_between_pages_is_in_a_later_page_or_in_changes_after_the_first_as_of_seq() {
    let app = TestApp::new().await;
    let u = user(&app, 1).await;
    for n in [2u8, 4, 6, 8] {
        put_live(&app, &u, item(n), 1, &format!("item {n}")).await;
    }
    let first = page(&app, &u, "?limit=3").await;
    assert_eq!(
        ids(&first),
        [*MANIFEST_ITEM_ID.as_bytes(), id_of(2), id_of(4)]
    );
    let as_of = first.as_of_seq;
    let cursor = first.next_after.expect("more rows");

    // Between the pages: a row before the cursor and a row after it.
    put_live(&app, &u, item(3), 1, "behind the cursor").await;
    put_live(&app, &u, item(7), 1, "ahead of the cursor").await;

    let mut seen: Vec<[u8; 16]> = ids(&first);
    let mut query = format!("?limit=3&after={}", hex16::encode(&cursor));
    let mut later = Vec::new();
    loop {
        let next = page(&app, &u, &query).await;
        assert!(
            next.as_of_seq > as_of,
            "a later page reads the later counter"
        );
        later.extend(ids(&next));
        seen.extend(ids(&next));
        match next.next_after {
            Some(after) => query = format!("?limit=3&after={}", hex16::encode(&after)),
            None => break,
        }
    }
    assert!(
        later.contains(&id_of(7)),
        "ahead of the cursor: on a later page"
    );
    assert!(
        !later.contains(&id_of(3)),
        "behind the cursor: not on a later page"
    );

    let feed = get(&app, &u.jar, &format!("/api/sync/changes?since={as_of}")).await;
    assert_eq!(feed.status, StatusCode::OK);
    let feed_ids: Vec<[u8; 16]> = feed.json()["changes"]
        .as_array()
        .expect("changes")
        .iter()
        .map(|c| hex16::decode(c["id"].as_str().expect("an id")).expect("hex"))
        .collect();
    assert!(
        feed_ids.contains(&id_of(3)),
        "behind the cursor: in the feed after the first as_of_seq"
    );
    seen.extend(feed_ids);
    for expected in [
        *MANIFEST_ITEM_ID.as_bytes(),
        id_of(2),
        id_of(3),
        id_of(4),
        id_of(6),
        id_of(7),
        id_of(8),
    ] {
        assert!(seen.contains(&expected), "{expected:?} was lost");
    }
}

// ----------------------------------------------------------------- the query

#[tokio::test]
async fn after_must_be_32_lower_hex_and_limit_is_clamped() {
    let app = TestApp::new().await;
    let u = user(&app, 1).await;
    let upper = "A".repeat(32);
    let long = "a".repeat(33);
    let short = "a".repeat(31);
    let prefixed = format!("0x{}", "a".repeat(30));
    let spaced = format!("{}%20", "a".repeat(31));
    let not_hex = "g".repeat(32);
    for bad in [
        "", &upper, &long, &short, &prefixed, &spaced, &not_hex, "%00", "null",
    ] {
        let res = get(&app, &u.jar, &format!("/api/sync/items?after={bad}")).await;
        assert_eq!(res.status, StatusCode::BAD_REQUEST, "after={bad:?}");
        assert_eq!(
            res.json(),
            json!({ "error": "bad_request" }),
            "after={bad:?}"
        );
        assert_eq!(res.header("cache-control"), "no-store");
    }
    // Other bad queries.
    for bad in [
        "limit=abc",
        "limit=-1",
        "limit=1.5",
        "limit=",
        "extra=1",
        "since=1",
    ] {
        let res = get(&app, &u.jar, &format!("/api/sync/items?{bad}")).await;
        assert_eq!(res.status, StatusCode::BAD_REQUEST, "{bad}");
    }
    // A good one is not refused, in lower case.
    let good = get(
        &app,
        &u.jar,
        &format!("/api/sync/items?after={}", "a".repeat(32)),
    )
    .await;
    assert_eq!(good.status, StatusCode::OK);

    // 0 is read as 1; a limit above 500 is read as 500.
    for n in 1..=9u8 {
        put_live(&app, &u, item(n), 1, &format!("item {n}")).await;
    }
    let zero = page(&app, &u, "?limit=0").await;
    assert_eq!(zero.items.len(), 1);
    assert!(zero.has_more);
    let vault = u.account.vault_id;
    db(&app, move |c| {
        insert_rows(c, &vault, 600, 8);
        Ok(())
    })
    .await;
    for limit in ["501", "100000", "4294967295"] {
        let big = page(&app, &u, &format!("?limit={limit}")).await;
        assert_eq!(big.items.len(), usize::try_from(MAX_LIMIT).unwrap());
        assert!(big.has_more);
    }
    // No limit is the same as 500, and every row is reached by paging.
    assert_eq!(page(&app, &u, "").await.items.len(), 500);
    let pages = all_pages(&app, &u, MAX_LIMIT).await;
    let total: usize = pages.iter().map(|p| p.items.len()).sum();
    assert_eq!(total, 1 + 9 + 600);
}

// ------------------------------------------------------------------ the size

#[tokio::test]
#[allow(non_snake_case)]
async fn listing_stops_before_4_MiB_and_holds_at_least_one_row() {
    // Through the API: 70 rows of 64 KiB hold more than a page may.
    let app = TestApp::new().await;
    let u = user(&app, 1).await;
    let vault = u.account.vault_id;
    db(&app, move |c| {
        insert_rows(c, &vault, 70, 65_536);
        Ok(())
    })
    .await;
    let res = get(&app, &u.jar, "/api/sync/items").await;
    assert_eq!(res.status, StatusCode::OK);
    assert!(
        res.body.len() < 4 * 1024 * 1024,
        "the page is {} bytes",
        res.body.len()
    );
    let first: ItemsRes = serde_json::from_slice(&res.body).expect("a page");
    assert!(first.has_more && first.next_after.is_some());
    assert!(first.items.len() < 70 && first.items.len() > 30);
    // The pages together are every row, in order, each under the limit.
    let mut total = 0;
    let mut query = String::new();
    loop {
        let res = get(&app, &u.jar, &format!("/api/sync/items{query}")).await;
        assert!(res.body.len() < 4 * 1024 * 1024);
        let next: ItemsRes = serde_json::from_slice(&res.body).expect("a page");
        total += next.items.len();
        match next.next_after {
            Some(after) => query = format!("?after={}", hex16::encode(&after)),
            None => break,
        }
    }
    assert_eq!(total, 71);

    // At the function: the row that does not fit still makes a page of one.
    let mut conn = migrated();
    let account = add_account(&mut conn, 1, 1_000);
    insert_rows(&conn, &account.vault_id, 3, 65_536);
    let one = list_items(&conn, &account.vault_id, None, 500, 0).expect("a page");
    assert_eq!(one.items.len(), 1, "a byte limit of 0 still gives one row");
    assert!(one.has_more);
    assert_eq!(one.next_after, Some(MANIFEST_ITEM_ID));
    // The limit is on the stored sizes: the manifest (40 bytes) and one row.
    let two = list_items(&conn, &account.vault_id, None, 500, 40 + 65_536).expect("a page");
    assert_eq!(two.items.len(), 2);
    let all = list_items(&conn, &account.vault_id, None, 500, PAGE_BYTES).expect("a page");
    assert_eq!(all.items.len(), 4);
    assert!(!all.has_more && all.next_after.is_none());
    // A limit of 0 is read as 1.
    let zero = list_items(&conn, &account.vault_id, None, 0, PAGE_BYTES).expect("a page");
    assert_eq!(zero.items.len(), 1);
}

#[test]
fn an_unknown_vault_is_not_found_not_an_empty_listing() {
    let conn = migrated();
    let err = list_items(
        &conn,
        &VaultId::from_bytes(id16(0xb0, 9)),
        None,
        10,
        PAGE_BYTES,
    )
    .expect_err("no such vault");
    assert!(matches!(err, StoreError::NotFound), "{err}");
}

// -------------------------------------------------------------------- scoping

#[tokio::test]
async fn listing_never_crosses_vaults() {
    let app = TestApp::new().await;
    let a = user(&app, 1).await;
    let b = user(&app, 2).await;
    put_live(&app, &a, item(1), 1, "a one").await;
    put_live(&app, &a, item(2), 1, "a two").await;
    put_live(&app, &b, item(3), 1, "b three").await;
    put_tomb(&app, &b, item(3), 2).await;
    put_live(&app, &b, item(4), 1, "b four").await;

    let of_a = all_pages(&app, &a, 1).await;
    let of_b = all_pages(&app, &b, 1).await;
    let ids_of = |pages: &[ItemsRes]| -> Vec<[u8; 16]> { pages.iter().flat_map(ids).collect() };
    assert_eq!(
        ids_of(&of_a),
        [*MANIFEST_ITEM_ID.as_bytes(), id_of(1), id_of(2)]
    );
    assert_eq!(
        ids_of(&of_b),
        [*MANIFEST_ITEM_ID.as_bytes(), id_of(3), id_of(4)]
    );
    // An `after` that only the other vault has is no hint about it.
    let probe = page(&app, &a, &format!("?after={}", hex(item(3)))).await;
    assert!(probe.items.is_empty());
    // Each listing says its own counter.
    assert_eq!(of_a[0].as_of_seq, 3);
    assert_eq!(of_b[0].as_of_seq, 4);
}

#[tokio::test]
async fn listing_needs_a_session() {
    let app = TestApp::new().await;
    let _ = user(&app, 1).await;
    let none = Jar::default();
    let res = get(&app, &none, "/api/sync/items").await;
    assert_eq!(res.status, StatusCode::UNAUTHORIZED);
    assert_eq!(res.json(), json!({ "error": "unauthorized" }));
    assert_eq!(res.header("cache-control"), "no-store");
}

#[tokio::test]
async fn admin_listener_has_no_listing_route() {
    let app = TestApp::new().await;
    let u = user(&app, 1).await;
    for uri in [
        "/api/sync/items",
        "/api/sync/items?limit=1",
        &format!("/api/sync/items?after={}", "a".repeat(32)),
    ] {
        let res = app.call_raw(Which::Admin, get_req(uri, &u.jar)).await;
        assert_eq!(res.status, StatusCode::NOT_FOUND, "{uri}");
    }
}

// ----------------------------------------------------------------------- logs

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

/// The forms in which a log line could carry `bytes`: base64url, hex, and the
/// inside of the `Debug` text of a `Vec<u8>`.
fn canaries_for(bytes: &[u8]) -> Vec<String> {
    vec![
        b64url::encode(bytes),
        ferret_core::testing::hex_encode(bytes),
        format!("{bytes:?}")
            .trim_start_matches('[')
            .trim_end_matches(']')
            .to_string(),
    ]
}

#[tokio::test]
async fn listing_bytes_never_reach_the_log() {
    let sink = Sink::default();
    tracing::subscriber::set_global_default(
        tracing_subscriber::fmt()
            .with_writer(sink.clone())
            .with_ansi(false)
            .with_max_level(tracing::Level::TRACE)
            .finish(),
    )
    .expect("one global subscriber in this test binary");
    let log = || String::from_utf8(sink.0.lock().unwrap().clone()).unwrap();

    let app = TestApp::new().await;
    let u = user(&app, 1).await;
    put_live(&app, &u, item(1), 1, "canary one").await;
    put_live(&app, &u, item(2), 1, "canary two").await;
    put_tomb(&app, &u, item(2), 2).await;

    // Every value of every row, in the forms a log line could print.
    let listed = page(&app, &u, "").await;
    let mut canaries: Vec<String> = Vec::new();
    for row in &listed.items {
        for value in [&row.blob, &row.tomb].into_iter().flatten() {
            canaries.extend(canaries_for(value));
        }
        if let Some(tag) = &row.tag {
            canaries.extend(canaries_for(tag));
        }
    }
    assert_eq!(
        canaries.len(),
        3 * 5,
        "blob and tag of two rows, one tombstone, three forms each"
    );

    // The control: a value that is logged on purpose trips its own forms.
    let control = vec![0x5a_u8; 80];
    tracing::info!(blob = ?control, "canary self-test, Debug");
    tracing::info!(blob = %b64url::encode(&control), "canary self-test, base64url");
    tracing::info!(
        blob = %ferret_core::testing::hex_encode(&control),
        "canary self-test, hex"
    );
    let text = log();
    for form in canaries_for(&control) {
        assert!(text.contains(&form), "{form:.40} does not fire");
    }

    // Pages, an empty page and a refused query.
    let _ = all_pages(&app, &u, 1).await;
    let _ = page(&app, &u, &format!("?after={}", hex(item(2)))).await;
    let refused = get(&app, &u.jar, "/api/sync/items?after=zz").await;
    assert_eq!(refused.status, StatusCode::BAD_REQUEST);

    let text = log();
    assert!(
        text.contains("listing page"),
        "the listing logs a line: {text}"
    );
    for canary in canaries {
        assert!(!text.contains(&canary), "{canary:.60} is in the log");
    }
    assert!(!text.contains("canary one") && !text.contains("canary two"));
}
