//! `restore_seq`, the frozen list of rows and `GET /api/sync/restore-rows`.
//! Spec: Fase 1 § 8.2, § 8.6 ("Legitimate rollbacks").
//!
//! `ferret restore-epoch bump` records the `seq` of each vault (`restore_seq`)
//! and freezes one row for every item the vault holds: its revision, its `seq`
//! and the SHA-256 of its envelope (nothing for a tombstone). The list has no
//! MAC, because the server has no key; a client uses it to tell a write made
//! after a restore from one that came before, in the honest case.
//!
//! The store tests use a connection; the route tests drive the whole vault
//! router of a `TestApp`.

mod support;

use std::io;
use std::sync::{Arc, Mutex};

use axum::body::Body;
use axum::http::{Request, StatusCode};
use ferret_server::auth::session::Origin;
use ferret_server::db::MIGRATION_FILES;
use ferret_server::error::StoreError;
use ferret_server::ids::{ItemId, MANIFEST_ITEM_ID, VaultId};
use ferret_server::product;
use ferret_server::vault::quota::Limits;
use ferret_server::vault::reconcile::{MAX_RESTORE_ROWS, bump_restore_epoch, restore_rows};
use ferret_server::vault::store::{PutBody, PutOutcome, PutRequest, put_item};
use ferret_server::wire::{ChangesRes, ItemsRes, RestoreRowsRes, b64url, hex16};
use ferret_server_auth::SessionScope;
use rusqlite::{Connection, params};
use serde_json::json;
use sha2::{Digest as _, Sha256};
use support::accounts::{TestAccount, add_account, add_account_to_app, id16};
use support::session::issue;
use support::{Jar, Res, TestApp, Which};
use tracing_subscriber::fmt::MakeWriter;
use vole_kit::db::migrate::apply_migrations;

const NOW: i64 = 1_793_491_200;

fn migrated() -> Connection {
    product::install();
    let mut conn = Connection::open_in_memory().expect("open");
    conn.execute_batch("PRAGMA foreign_keys = ON;")
        .expect("pragma");
    apply_migrations(&mut conn).expect("migrations apply");
    conn
}

fn item(n: u8) -> ItemId {
    let mut bytes = [0u8; 16];
    bytes[0] = 0x10;
    bytes[1] = n;
    ItemId::from_bytes(bytes)
}

/// A write straight into the store; it must be stored.
fn put(
    conn: &mut Connection,
    a: &TestAccount,
    id: ItemId,
    base_rev: u64,
    body: PutBody<'_>,
    key: u8,
) {
    let req = PutRequest {
        item_id: id,
        base_rev,
        body,
        idem: id16(0xe0, key),
        request_hash: [key; 32],
        resurrect: false,
        restore_epoch: None,
    };
    let outcome =
        put_item(conn, &a.vault_id, &a.device, &req, &Limits::DEFAULT, NOW).expect("put_item");
    assert!(
        matches!(outcome, PutOutcome::Stored { .. }),
        "{outcome:?} for item {id:?} at {base_rev}"
    );
}

fn envelope(n: u8, rev: u64) -> Vec<u8> {
    format!("envelope of item {n} at revision {rev}").into_bytes()
}

fn live(conn: &mut Connection, a: &TestAccount, n: u8, base_rev: u64, key: u8) {
    let blob = envelope(n, base_rev + 1);
    put(
        conn,
        a,
        item(n),
        base_rev,
        PutBody::Live {
            blob: &blob,
            tag: [n; 32],
        },
        key,
    );
}

fn tomb(conn: &mut Connection, a: &TestAccount, n: u8, base_rev: u64, key: u8) {
    put(
        conn,
        a,
        item(n),
        base_rev,
        PutBody::Deleted { tomb: &[0x7f; 40] },
        key,
    );
}

/// Two vaults. Vault 1 has items 1 (rev 1), 2 (rev 2) and 3 (deleted at rev 2)
/// besides the manifest, so `seq` is 6; vault 2 has item 1 at rev 1, so `seq`
/// is 2.
fn seeded() -> (Connection, TestAccount, TestAccount) {
    let mut conn = migrated();
    let a = add_account(&mut conn, 1, NOW);
    let b = add_account(&mut conn, 2, NOW);
    live(&mut conn, &a, 1, 0, 1);
    live(&mut conn, &a, 2, 0, 2);
    live(&mut conn, &a, 2, 1, 3);
    live(&mut conn, &a, 3, 0, 4);
    tomb(&mut conn, &a, 3, 1, 5);
    live(&mut conn, &b, 1, 0, 6);
    (conn, a, b)
}

/// A frozen row as the table holds it: item, epoch, revision, `seq`, hash.
type Frozen = (Vec<u8>, i64, i64, i64, Option<Vec<u8>>);

fn frozen(conn: &Connection, vault: &VaultId) -> Vec<Frozen> {
    conn.prepare(
        "SELECT item_id, restore_epoch, rev, seq, blob_sha256 FROM ferret_restore_rows \
         WHERE vault_id = ?1 ORDER BY item_id",
    )
    .expect("prepare")
    .query_map([vault.as_bytes()], |row| {
        Ok((
            row.get(0)?,
            row.get(1)?,
            row.get(2)?,
            row.get(3)?,
            row.get(4)?,
        ))
    })
    .expect("query")
    .map(|r| r.expect("row"))
    .collect()
}

/// An item row as the table holds it: item, revision, `seq`, deleted, blob.
type Row = (Vec<u8>, i64, i64, bool, Option<Vec<u8>>);

fn items(conn: &Connection, vault: &VaultId) -> Vec<Row> {
    conn.prepare(
        "SELECT item_id, rev, seq, deleted, blob FROM ferret_items \
         WHERE vault_id = ?1 ORDER BY item_id",
    )
    .expect("prepare")
    .query_map([vault.as_bytes()], |row| {
        Ok((
            row.get(0)?,
            row.get(1)?,
            row.get(2)?,
            row.get::<_, i64>(3)? != 0,
            row.get(4)?,
        ))
    })
    .expect("query")
    .map(|r| r.expect("row"))
    .collect()
}

fn vault_numbers(conn: &Connection, vault: &VaultId) -> (i64, i64, i64) {
    conn.query_row(
        "SELECT seq, restore_epoch, restore_seq FROM ferret_vaults WHERE vault_id = ?1",
        [vault.as_bytes()],
        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
    )
    .expect("the vault")
}

fn sha(blob: &[u8]) -> Vec<u8> {
    Sha256::digest(blob).to_vec()
}

// ------------------------------------------------------------- the migration

/// Every row of every table that migration 0006 leaves alone, as text; and of
/// `ferret_vaults` the columns that were there before.
fn dump(conn: &Connection) -> Vec<String> {
    let tables: Vec<String> = conn
        .prepare(
            "SELECT name FROM sqlite_master WHERE type = 'table' \
             AND name NOT LIKE 'sqlite_%' AND name <> 'ferret_restore_rows' \
             AND name <> 'ferret_vaults' AND name <> 'schema_migrations' ORDER BY name",
        )
        .expect("prepare")
        .query_map([], |row| row.get(0))
        .expect("query")
        .map(|r| r.expect("row"))
        .collect();
    let mut out = Vec::new();
    let mut dump_query = |label: &str, sql: &str| {
        let mut stmt = conn.prepare(sql).expect("prepare");
        let columns = stmt.column_count();
        let rows: Vec<String> = stmt
            .query_map([], |row| {
                let mut cells = Vec::new();
                for i in 0..columns {
                    cells.push(format!("{:?}", row.get_ref(i)?));
                }
                Ok(cells.join("|"))
            })
            .expect("query")
            .map(|r| r.expect("row"))
            .collect();
        out.push(format!("{label}: {}", rows.join("\n")));
    };
    for table in &tables {
        dump_query(table, &format!("SELECT * FROM \"{table}\" ORDER BY 1, 2"));
    }
    dump_query(
        "ferret_vaults",
        "SELECT vault_id, account_id, seq, item_count, bytes_used, restore_epoch, min_valid_since \
         FROM ferret_vaults ORDER BY vault_id",
    );
    out
}

#[test]
fn migration_0006_keeps_every_m1_and_m2_row_and_starts_restore_seq_at_0() {
    let names: Vec<&str> = MIGRATION_FILES.iter().map(|(name, _)| *name).collect();
    let at = |name: &str| names.iter().position(|n| *n == name).expect(name);
    assert_eq!(at("0006_restore_seq.sql"), at("0005_sync.sql") + 1);

    // Additive: new column with a default, one new table, nothing else.
    let sql = MIGRATION_FILES
        .iter()
        .find(|(name, _)| *name == "0006_restore_seq.sql")
        .map(|(_, sql)| *sql)
        .expect("the migration");
    let statements: Vec<String> = sql
        .lines()
        .filter(|line| !line.trim_start().starts_with("--"))
        .collect::<Vec<_>>()
        .join("\n")
        .split(';')
        .map(|s| s.split_whitespace().collect::<Vec<_>>().join(" "))
        .filter(|s| !s.is_empty())
        .collect();
    assert_eq!(statements.len(), 2, "{statements:?}");
    assert_eq!(
        statements[0],
        "ALTER TABLE ferret_vaults ADD COLUMN restore_seq INTEGER NOT NULL DEFAULT 0"
    );
    assert!(
        statements[1].starts_with("CREATE TABLE ferret_restore_rows ("),
        "{}",
        statements[1]
    );

    // A database with data in it, as it was before 0006 existed: take the new
    // column and the new table out and forget the migration.
    let (mut conn, a, b) = seeded();
    bump_restore_epoch(&mut conn, None, NOW).expect("a bump");
    conn.execute_batch(
        "DROP TABLE ferret_restore_rows; \
         ALTER TABLE ferret_vaults DROP COLUMN restore_seq; \
         DELETE FROM schema_migrations WHERE name = '0006_restore_seq.sql';",
    )
    .expect("the database before 0006");
    let before = dump(&conn);
    assert!(
        before.iter().any(|t| t.starts_with("ferret_items: ")),
        "items are in the dump"
    );
    let item_rows = (items(&conn, &a.vault_id), items(&conn, &b.vault_id));
    assert_eq!(item_rows.0.len(), 4);

    let applied = apply_migrations(&mut conn).expect("0006 applies over data");
    assert!(
        applied.iter().any(|n| n == "0006_restore_seq.sql"),
        "{applied:?}"
    );
    assert_eq!(applied.len(), 1, "only 0006 was missing: {applied:?}");

    assert_eq!(dump(&conn), before, "no row of any other table changed");
    assert_eq!(
        (items(&conn, &a.vault_id), items(&conn, &b.vault_id)),
        item_rows
    );
    // Every vault starts at 0 and has no frozen rows.
    for vault in [&a.vault_id, &b.vault_id] {
        let (_, epoch, restore_seq) = vault_numbers(&conn, vault);
        assert_eq!((epoch, restore_seq), (1, 0), "epoch kept, restore_seq 0");
        assert!(frozen(&conn, vault).is_empty());
    }
    // The new table is STRICT, WITHOUT ROWID, and refuses a short id or hash.
    let bad_id = conn.execute(
        "INSERT INTO ferret_restore_rows (vault_id, item_id, restore_epoch, rev, seq) \
         VALUES (?1, x'00', 1, 1, 1)",
        [a.vault_id.as_bytes()],
    );
    assert!(bad_id.is_err(), "an item id is 16 bytes");
    let bad_hash = conn.execute(
        "INSERT INTO ferret_restore_rows (vault_id, item_id, restore_epoch, rev, seq, blob_sha256) \
         VALUES (?1, ?2, 1, 1, 1, x'00')",
        params![a.vault_id.as_bytes(), [1u8; 16]],
    );
    assert!(bad_hash.is_err(), "a hash is 32 bytes");

    // And a bump works on the migrated database.
    assert_eq!(bump_restore_epoch(&mut conn, None, NOW).expect("a bump"), 2);
    let (seq, epoch, restore_seq) = vault_numbers(&conn, &a.vault_id);
    assert_eq!((seq, epoch, restore_seq), (6, 2, 6));
}

// ---------------------------------------------------------------- the bump

#[test]
fn bump_records_restore_seq_and_freezes_one_row_per_item_with_rev_seq_and_blob_hash() {
    let (mut conn, a, b) = seeded();
    // Before a bump: nothing is recorded.
    assert_eq!(vault_numbers(&conn, &a.vault_id), (6, 0, 0));
    assert_eq!(vault_numbers(&conn, &b.vault_id), (2, 0, 0));
    assert!(frozen(&conn, &a.vault_id).is_empty());

    assert_eq!(bump_restore_epoch(&mut conn, None, NOW).expect("a bump"), 1);

    // `restore_seq` is the `seq` of each vault at the bump.
    assert_eq!(vault_numbers(&conn, &a.vault_id), (6, 1, 6));
    assert_eq!(vault_numbers(&conn, &b.vault_id), (2, 1, 2));
    // One frozen row for every row of `ferret_items`, the manifest included,
    // with the revision and `seq` of that row and the SHA-256 of its envelope.
    for vault in [&a.vault_id, &b.vault_id] {
        let rows = items(&conn, vault);
        let list = frozen(&conn, vault);
        assert_eq!(list.len(), rows.len());
        for ((item_id, rev, seq, deleted, blob), (f_id, f_epoch, f_rev, f_seq, f_hash)) in
            rows.iter().zip(&list)
        {
            assert_eq!(f_id, item_id);
            assert_eq!(*f_epoch, 1);
            assert_eq!((f_rev, f_seq), (rev, seq));
            match (deleted, blob) {
                (false, Some(blob)) => assert_eq!(f_hash.as_deref(), Some(&sha(blob)[..])),
                _ => assert!(f_hash.is_none()),
            }
        }
    }
    // The vault with the most history: a rewritten item is at its latest.
    let list = frozen(&conn, &a.vault_id);
    let of = |n: u8| {
        list.iter()
            .find(|row| row.0 == item(n).as_bytes())
            .expect("a frozen row")
    };
    assert_eq!((of(1).2, of(1).3), (1, 2));
    assert_eq!((of(2).2, of(2).3), (2, 4));
    assert_eq!(of(2).4.as_deref(), Some(&sha(&envelope(2, 2))[..]));
    // The manifest is a row like any other.
    let manifest = list
        .iter()
        .find(|row| row.0 == MANIFEST_ITEM_ID.as_bytes())
        .expect("the manifest row");
    assert_eq!(manifest.4.as_deref(), Some(&sha(&[0x4d; 40])[..]));
    // Rows of a vault are never in the list of another.
    assert_eq!(frozen(&conn, &b.vault_id).len(), 2);
}

#[test]
fn tombstones_are_frozen_with_a_null_hash() {
    let (mut conn, a, _) = seeded();
    bump_restore_epoch(&mut conn, None, NOW).expect("a bump");
    let list = frozen(&conn, &a.vault_id);
    let gone = list
        .iter()
        .find(|row| row.0 == item(3).as_bytes())
        .expect("the tombstone is frozen");
    assert_eq!((gone.2, gone.3), (2, 6), "its revision and seq");
    assert!(gone.4.is_none(), "no envelope, no hash");
    let nulls: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM ferret_restore_rows \
             WHERE vault_id = ?1 AND blob_sha256 IS NULL",
            [a.vault_id.as_bytes()],
            |row| row.get(0),
        )
        .expect("count");
    assert_eq!(nulls, 1, "only the tombstone has none");
}

#[test]
fn a_second_bump_raises_restore_seq_and_replaces_the_frozen_rows() {
    let (mut conn, a, b) = seeded();
    bump_restore_epoch(&mut conn, None, NOW).expect("the first bump");
    let first = frozen(&conn, &a.vault_id);
    assert_eq!(vault_numbers(&conn, &a.vault_id).2, 6);

    // More writes: item 1 rewritten, item 3 brought back is not done here (a
    // tombstone stays), item 4 is new. Vault 2 changes nothing.
    live(&mut conn, &a, 1, 1, 7);
    live(&mut conn, &a, 4, 0, 8);
    assert_eq!(
        bump_restore_epoch(&mut conn, None, NOW).expect("the second bump"),
        2
    );

    // `restore_seq` is the new `seq`, for both vaults.
    assert_eq!(vault_numbers(&conn, &a.vault_id), (8, 2, 8));
    assert_eq!(vault_numbers(&conn, &b.vault_id), (2, 2, 2));
    let second = frozen(&conn, &a.vault_id);
    assert_eq!(second.len(), first.len() + 1, "the new item is in it");
    assert!(
        second.iter().all(|row| row.1 == 2),
        "no row of the first bump is left"
    );
    let one = second
        .iter()
        .find(|row| row.0 == item(1).as_bytes())
        .expect("item one");
    assert_eq!((one.2, one.3), (2, 7));
    assert_eq!(one.4.as_deref(), Some(&sha(&envelope(1, 2))[..]));
    assert!(second.iter().any(|row| row.0 == item(4).as_bytes()));
    // The list is the table as it is now, exactly.
    let rows = items(&conn, &a.vault_id);
    assert_eq!(second.len(), rows.len());
    for (row, f) in rows.iter().zip(&second) {
        assert_eq!((&row.0, row.1, row.2), (&f.0, f.2, f.3));
    }
    // And no frozen row is left over from the first list.
    let total: i64 = conn
        .query_row("SELECT COUNT(*) FROM ferret_restore_rows", [], |row| {
            row.get(0)
        })
        .expect("count");
    assert_eq!(
        usize::try_from(total).unwrap(),
        second.len() + frozen(&conn, &b.vault_id).len()
    );
}

#[test]
fn writes_after_the_bump_do_not_change_the_frozen_rows() {
    let (mut conn, a, _) = seeded();
    bump_restore_epoch(&mut conn, None, NOW).expect("a bump");
    let list = frozen(&conn, &a.vault_id);
    let numbers = vault_numbers(&conn, &a.vault_id);

    // A rewrite, a deletion, a new item and a deletion of the new one.
    live(&mut conn, &a, 1, 1, 10);
    tomb(&mut conn, &a, 2, 2, 11);
    live(&mut conn, &a, 5, 0, 12);
    tomb(&mut conn, &a, 5, 1, 13);

    assert_eq!(frozen(&conn, &a.vault_id), list);
    let (seq, epoch, restore_seq) = vault_numbers(&conn, &a.vault_id);
    assert_eq!(seq, 10, "the vault moved on");
    assert_eq!(
        (epoch, restore_seq),
        (numbers.1, numbers.2),
        "the bump did not"
    );
}

#[test]
fn a_failure_while_freezing_leaves_the_epochs_restore_seq_and_rows_as_they_were() {
    let (mut conn, a, _) = seeded();
    bump_restore_epoch(&mut conn, None, NOW).expect("a bump");
    live(&mut conn, &a, 1, 1, 10);
    let before = (
        vault_numbers(&conn, &a.vault_id),
        frozen(&conn, &a.vault_id),
    );
    conn.execute_batch(
        "CREATE TRIGGER fail_freeze BEFORE INSERT ON ferret_restore_rows \
         BEGIN SELECT RAISE(ABORT, 'no'); END;",
    )
    .expect("a trigger");
    assert!(bump_restore_epoch(&mut conn, None, NOW).is_err());
    assert_eq!(
        (
            vault_numbers(&conn, &a.vault_id),
            frozen(&conn, &a.vault_id)
        ),
        before,
        "nothing changed"
    );
}

#[test]
fn an_unknown_vault_is_not_found_not_an_empty_list() {
    let conn = migrated();
    let err = restore_rows(&conn, &VaultId::from_bytes(id16(0xb0, 9)), None, 10)
        .expect_err("no such vault");
    assert!(matches!(err, StoreError::NotFound), "{err}");
}

// ------------------------------------------------------------------ the routes

struct User {
    account: TestAccount,
    jar: Jar,
}

async fn user(app: &TestApp, n: u8) -> User {
    let account = add_account_to_app(app, n).await;
    let issued = issue(app, account.user_id, Origin::Vault, SessionScope::Full, n).await;
    User {
        account,
        jar: issued.jar,
    }
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

async fn db<T: Send + 'static>(
    app: &TestApp,
    f: impl FnOnce(&mut Connection) -> Result<T, StoreError> + Send + 'static,
) -> T {
    app.state
        .vault_db
        .with_conn(f)
        .await
        .expect("a database call")
}

/// A write of a live item into the vault of `u`.
async fn write(app: &TestApp, u: &User, n: u8, base_rev: u64, key: u8) {
    let account = u.account;
    db(app, move |conn| {
        live(conn, &account, n, base_rev, key);
        Ok(())
    })
    .await;
}

async fn bump(app: &TestApp) -> u64 {
    db(app, |conn| bump_restore_epoch(conn, None, NOW)).await
}

async fn changes(app: &TestApp, u: &User, query: &str) -> ChangesRes {
    let res = get(app, &u.jar, &format!("/api/sync/changes{query}")).await;
    assert_eq!(res.status, StatusCode::OK, "{}", res.text());
    serde_json::from_slice(&res.body).expect("a changes answer")
}

async fn listing(app: &TestApp, u: &User, query: &str) -> ItemsRes {
    let res = get(app, &u.jar, &format!("/api/sync/items{query}")).await;
    assert_eq!(res.status, StatusCode::OK, "{}", res.text());
    serde_json::from_slice(&res.body).expect("an items answer")
}

async fn rows_page(app: &TestApp, u: &User, query: &str) -> RestoreRowsRes {
    let res = get(app, &u.jar, &format!("/api/sync/restore-rows{query}")).await;
    assert_eq!(res.status, StatusCode::OK, "{}", res.text());
    assert_eq!(res.header("cache-control"), "no-store");
    let page: RestoreRowsRes = serde_json::from_slice(&res.body).expect("a restore-rows page");
    page.validate().expect("next_after and has_more agree");
    page
}

#[tokio::test]
async fn changes_and_items_carry_restore_seq_read_with_the_page() {
    let app = TestApp::new().await;
    let u = user(&app, 1).await;
    write(&app, &u, 1, 0, 1).await;
    write(&app, &u, 2, 0, 2).await;

    // Never restored: epoch 0 and `restore_seq` 0, on the wire.
    let raw = get(&app, &u.jar, "/api/sync/changes").await.json();
    assert_eq!(raw["restore_epoch"], json!(0));
    assert_eq!(raw["restore_seq"], json!(0));
    let raw = get(&app, &u.jar, "/api/sync/items").await.json();
    assert_eq!(raw["restore_epoch"], json!(0));
    assert_eq!(raw["restore_seq"], json!(0));

    assert_eq!(bump(&app).await, 1);

    // After the bump the vault stood at `seq` 3 (the manifest and two items).
    // A page of one row has the epoch and `restore_seq` of the whole vault.
    let feed = changes(&app, &u, "?since=0&limit=1").await;
    assert!(feed.has_more);
    assert_eq!(
        (feed.restore_epoch, feed.restore_seq, feed.latest_seq),
        (1, 3, 3)
    );
    let all = listing(&app, &u, "?limit=1").await;
    assert!(all.has_more);
    assert_eq!(
        (all.restore_epoch, all.restore_seq, all.as_of_seq),
        (1, 3, 3)
    );

    // The vault moves on; `restore_seq` stays where the bump put it, in both
    // answers, on every page.
    write(&app, &u, 3, 0, 3).await;
    write(&app, &u, 1, 1, 4).await;
    let feed = changes(&app, &u, "?since=0").await;
    assert_eq!(
        (feed.restore_epoch, feed.restore_seq, feed.latest_seq),
        (1, 3, 5)
    );
    for query in ["", "?limit=1"] {
        let page = listing(&app, &u, query).await;
        assert_eq!(
            (page.restore_epoch, page.restore_seq, page.as_of_seq),
            (1, 3, 5),
            "{query}"
        );
    }
    // A second restore raises it to the new `seq`.
    assert_eq!(bump(&app).await, 2);
    let feed = changes(&app, &u, "?since=0").await;
    assert_eq!(
        (feed.restore_epoch, feed.restore_seq, feed.latest_seq),
        (2, 5, 5)
    );
    // It sits right after `restore_epoch` on the wire, in both answers.
    let text = get(&app, &u.jar, "/api/sync/changes").await.text();
    assert!(
        text.contains(r#""restore_epoch":2,"restore_seq":5"#),
        "{text}"
    );
    let text = get(&app, &u.jar, "/api/sync/items").await.text();
    assert!(
        text.contains(r#""restore_epoch":2,"restore_seq":5"#),
        "{text}"
    );
}

#[tokio::test]
async fn restore_rows_pages_by_item_id_and_is_empty_before_any_restore() {
    let app = TestApp::new().await;
    let u = user(&app, 1).await;
    for n in 1..=5 {
        write(&app, &u, n, 0, n).await;
    }
    write(&app, &u, 2, 1, 6).await;

    // Never restored: `restore_seq` 0 and an empty list.
    let never = rows_page(&app, &u, "").await;
    assert_eq!(
        serde_json::to_string(&never).unwrap(),
        r#"{"restore_epoch":0,"restore_seq":0,"rows":[],"has_more":false}"#
    );

    bump(&app).await;
    // What the vault held at the bump, frozen: seven rows (the manifest too).
    write(&app, &u, 1, 1, 7).await;
    let whole = rows_page(&app, &u, "").await;
    assert_eq!((whole.restore_epoch, whole.restore_seq), (1, 7));
    assert_eq!(whole.rows.len(), 6);
    assert!(!whole.has_more && whole.next_after.is_none());
    let ids: Vec<[u8; 16]> = whole.rows.iter().map(|row| row.id).collect();
    let mut sorted = ids.clone();
    sorted.sort_unstable();
    sorted.dedup();
    assert_eq!(ids, sorted, "strictly rising item ids");
    assert_eq!(ids[0], *MANIFEST_ITEM_ID.as_bytes());
    // The frozen rows are not the live ones: item 1 was written after the bump.
    let one = whole
        .rows
        .iter()
        .find(|row| row.id == *item(1).as_bytes())
        .expect("item one");
    assert_eq!((one.rev, one.seq), (1, 2));
    let two = whole
        .rows
        .iter()
        .find(|row| row.id == *item(2).as_bytes())
        .expect("item two");
    assert_eq!((two.rev, two.seq), (2, 7));
    // The hash is the SHA-256 of the envelope that the listing shows.
    let current = listing(&app, &u, "").await;
    for row in &current.items {
        let Some(frozen_row) = whole.rows.iter().find(|r| r.id == row.id) else {
            panic!("a row without a frozen row");
        };
        if row.id == *item(1).as_bytes() {
            assert_ne!(frozen_row.rev, row.rev);
            continue;
        }
        let blob = row.blob.as_ref().expect("a live row");
        assert_eq!(frozen_row.hash, Some(Sha256::digest(blob).into()));
    }

    // Pages of 4, by `after` and `next_after`.
    let first = rows_page(&app, &u, "?limit=4").await;
    assert_eq!(first.rows.len(), 4);
    assert!(first.has_more);
    assert_eq!(first.next_after, Some(first.rows[3].id));
    let second = rows_page(
        &app,
        &u,
        &format!(
            "?limit=4&after={}",
            hex16::encode(&first.next_after.unwrap())
        ),
    )
    .await;
    assert_eq!(second.rows.len(), 2);
    assert!(!second.has_more && second.next_after.is_none());
    let joined: Vec<_> = first.rows.iter().chain(&second.rows).cloned().collect();
    assert!(joined == whole.rows, "the pages are the list");
    // `limit` 0 is read as 1; an `after` past the end is an empty last page.
    let one_row = rows_page(&app, &u, "?limit=0").await;
    assert_eq!(one_row.rows.len(), 1);
    assert!(one_row.has_more);
    let past = rows_page(&app, &u, &format!("?after={}", hex16::encode(&[0xff; 16]))).await;
    assert!(past.rows.is_empty() && !past.has_more);
    assert_eq!((past.restore_epoch, past.restore_seq), (1, 7));
}

#[tokio::test]
async fn restore_rows_pages_are_at_most_2000_rows() {
    let app = TestApp::new().await;
    let u = user(&app, 1).await;
    let vault = u.account.vault_id;
    db(&app, move |conn| {
        let mut stmt = conn
            .prepare(
                "INSERT INTO ferret_items \
                 (vault_id, item_id, rev, seq, deleted, blob, tag, tomb, size, changed_at) \
                 VALUES (?1, ?2, 1, ?3, 0, x'01', ?4, NULL, 1, 0)",
            )
            .map_err(StoreError::from)?;
        for n in 0..2100_u32 {
            let mut id = [0u8; 16];
            id[0] = 0x20;
            id[1..5].copy_from_slice(&n.to_be_bytes());
            stmt.execute(params![
                vault.as_bytes(),
                id,
                i64::from(n) + 1000,
                [0x55u8; 32]
            ])
            .map_err(StoreError::from)?;
        }
        Ok(())
    })
    .await;
    bump(&app).await;
    assert_eq!(MAX_RESTORE_ROWS, 2000);
    for query in ["", "?limit=5000", "?limit=2000"] {
        let page = rows_page(&app, &u, query).await;
        assert_eq!(page.rows.len(), 2000, "{query}");
        assert!(page.has_more, "{query}");
    }
    let page = rows_page(&app, &u, "?limit=2001").await;
    assert_eq!(page.rows.len(), 2000);
    let rest = rows_page(
        &app,
        &u,
        &format!("?after={}", hex16::encode(&page.next_after.unwrap())),
    )
    .await;
    // 2100 rows and the manifest, 2000 on the first page.
    assert_eq!(rest.rows.len(), 101);
    assert!(!rest.has_more);
}

#[tokio::test]
async fn restore_rows_never_cross_vaults() {
    let app = TestApp::new().await;
    let a = user(&app, 1).await;
    let b = user(&app, 2).await;
    write(&app, &a, 1, 0, 1).await;
    write(&app, &b, 7, 0, 2).await;
    write(&app, &b, 8, 0, 3).await;
    bump(&app).await;
    let of_a = rows_page(&app, &a, "").await;
    let of_b = rows_page(&app, &b, "").await;
    let ids = |page: &RestoreRowsRes| -> Vec<[u8; 16]> { page.rows.iter().map(|r| r.id).collect() };
    assert_eq!(
        ids(&of_a),
        [*MANIFEST_ITEM_ID.as_bytes(), *item(1).as_bytes()]
    );
    assert_eq!(
        ids(&of_b),
        [
            *MANIFEST_ITEM_ID.as_bytes(),
            *item(7).as_bytes(),
            *item(8).as_bytes()
        ]
    );
    assert_eq!((of_a.restore_seq, of_b.restore_seq), (2, 3));
    // An `after` that only the other vault has is no hint about it.
    let probe = rows_page(
        &app,
        &a,
        &format!("?after={}", hex16::encode(item(7).as_bytes())),
    )
    .await;
    assert!(probe.rows.is_empty());
}

#[tokio::test]
async fn restore_rows_needs_a_session_and_refuses_bad_queries() {
    let app = TestApp::new().await;
    let u = user(&app, 1).await;
    bump(&app).await;
    let none = Jar::default();
    let res = get(&app, &none, "/api/sync/restore-rows").await;
    assert_eq!(res.status, StatusCode::UNAUTHORIZED);
    assert_eq!(res.json(), json!({ "error": "unauthorized" }));
    assert_eq!(res.header("cache-control"), "no-store");
    for query in [
        "?after=zz",
        &format!("?after={}", "A".repeat(32)),
        &format!("?after={}", "a".repeat(31)),
        "?limit=abc",
        "?limit=-1",
        "?x=1",
        "?since=0",
    ] {
        let res = get(&app, &u.jar, &format!("/api/sync/restore-rows{query}")).await;
        assert_eq!(res.status, StatusCode::BAD_REQUEST, "{query}");
        assert_eq!(res.json(), json!({ "error": "bad_request" }), "{query}");
    }
}

#[tokio::test]
async fn admin_listener_has_no_restore_rows_route() {
    let app = TestApp::new().await;
    let u = user(&app, 1).await;
    bump(&app).await;
    for uri in [
        "/api/sync/restore-rows",
        "/api/sync/restore-rows?limit=1",
        &format!("/api/sync/restore-rows?after={}", "a".repeat(32)),
    ] {
        let res = app.call_raw(Which::Admin, get_req(uri, &u.jar)).await;
        assert_eq!(res.status, StatusCode::NOT_FOUND, "{uri}");
    }
}

#[tokio::test]
async fn restore_rows_answers_have_no_store() {
    let app = TestApp::new().await;
    let u = user(&app, 1).await;
    write(&app, &u, 1, 0, 1).await;
    for restored in [false, true] {
        if restored {
            bump(&app).await;
        }
        for uri in [
            "/api/sync/restore-rows",
            "/api/sync/restore-rows?limit=1",
            "/api/sync/restore-rows?after=zz",
        ] {
            let res = get(&app, &u.jar, uri).await;
            assert_eq!(res.header("cache-control"), "no-store", "{uri} {restored}");
        }
    }
    let res = get(&app, &Jar::default(), "/api/sync/restore-rows").await;
    assert_eq!(res.header("cache-control"), "no-store");
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
async fn restore_rows_never_reach_the_log() {
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
    write(&app, &u, 1, 0, 1).await;
    write(&app, &u, 2, 0, 2).await;
    bump(&app).await;

    // The hash and the id of every frozen row, in the forms a log line could
    // print them.
    let page = rows_page(&app, &u, "").await;
    let mut canaries: Vec<String> = Vec::new();
    for row in &page.rows {
        // The manifest id is all zeros: too common a text to be a canary.
        if row.id != *MANIFEST_ITEM_ID.as_bytes() {
            canaries.extend(canaries_for(&row.id));
        }
        if let Some(hash) = &row.hash {
            canaries.extend(canaries_for(hash));
        }
    }
    assert_eq!(
        canaries.len(),
        3 * (2 + 3),
        "two ids besides the manifest, three hashes, three forms each"
    );

    // The control: a value that is logged on purpose trips its own forms.
    let control = vec![0x5a_u8; 32];
    tracing::info!(hash = ?control, "canary self-test, Debug");
    tracing::info!(hash = %b64url::encode(&control), "canary self-test, base64url");
    tracing::info!(
        hash = %ferret_core::testing::hex_encode(&control),
        "canary self-test, hex"
    );
    let text = log();
    for form in canaries_for(&control) {
        assert!(text.contains(&form), "{form:.40} does not fire");
    }

    // Pages, an empty page and a refused query.
    let _ = rows_page(&app, &u, "?limit=1").await;
    let _ = rows_page(&app, &u, &format!("?after={}", hex16::encode(&[0xff; 16]))).await;
    let refused = get(&app, &u.jar, "/api/sync/restore-rows?after=zz").await;
    assert_eq!(refused.status, StatusCode::BAD_REQUEST);

    let text = log();
    assert!(
        text.contains("restore rows page"),
        "the route logs a line: {text}"
    );
    for canary in canaries {
        assert!(!text.contains(&canary), "{canary:.60} is in the log");
    }
}
