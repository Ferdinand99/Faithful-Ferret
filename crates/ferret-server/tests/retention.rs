//! Retention: tombstones kept 400 days, idempotency records 30 days and the
//! newest 1 000 per device, and the job that applies both. Spec: Fase 1 § 8.4.

mod support;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use ferret_server::ids::{ItemId, VaultId};
use ferret_server::product;
use ferret_server::vault::quota::Limits;
use ferret_server::vault::retention::{
    IDEM_DAYS, IDEM_PER_DEVICE, Job, RetentionReport, TOMBSTONE_DAYS, next_run, run_once,
};
use ferret_server::vault::store::{PutBody, PutOutcome, PutRequest, changes_since, put_item};
use rusqlite::{Connection, params};
use support::accounts::{TestAccount, add_account, id16};
use support::{Jar, TestApp, Which};
use vole_kit::db::migrate::apply_migrations;

const DAY: i64 = 86_400;
const NOW: i64 = 1_793_491_200;

fn migrated() -> Connection {
    product::install();
    let mut conn = Connection::open_in_memory().expect("open");
    conn.execute_batch("PRAGMA foreign_keys = ON;")
        .expect("pragma");
    apply_migrations(&mut conn).expect("migrations apply");
    conn
}

fn with_account() -> (Connection, TestAccount) {
    let mut conn = migrated();
    let account = add_account(&mut conn, 1, NOW);
    (conn, account)
}

fn item(n: u8) -> ItemId {
    ItemId::from_bytes(id16(0x10, n))
}

fn live(id: ItemId, base_rev: u64, n: u8) -> PutRequest<'static> {
    PutRequest {
        item_id: id,
        base_rev,
        body: PutBody::Live {
            blob: b"envelope",
            tag: [n; 32],
        },
        idem: id16(0xe0, n),
        request_hash: [n; 32],
        resurrect: false,
        restore_epoch: None,
    }
}

fn tomb(id: ItemId, base_rev: u64, n: u8) -> PutRequest<'static> {
    PutRequest {
        item_id: id,
        base_rev,
        body: PutBody::Deleted { tomb: b"tombstone" },
        idem: id16(0xe0, n),
        request_hash: [n; 32],
        resurrect: false,
        restore_epoch: None,
    }
}

fn put(conn: &mut Connection, a: &TestAccount, req: &PutRequest<'_>, now: i64) -> (u64, u64) {
    match put_item(conn, &a.vault_id, &a.device, req, &Limits::DEFAULT, now).expect("put_item") {
        PutOutcome::Stored { rev, seq, .. } => (rev, seq),
        other => panic!("not stored: {other:?}"),
    }
}

fn count(conn: &Connection, sql: &str) -> i64 {
    conn.query_row(sql, [], |row| row.get(0)).expect("count")
}

fn floor(conn: &Connection, a: &TestAccount) -> i64 {
    conn.query_row(
        "SELECT min_valid_since FROM ferret_vaults WHERE vault_id = ?1",
        [a.vault_id.as_bytes()],
        |r| r.get(0),
    )
    .expect("the floor")
}

fn bytes_used(conn: &Connection, a: &TestAccount) -> i64 {
    conn.query_row(
        "SELECT bytes_used FROM ferret_vaults WHERE vault_id = ?1",
        [a.vault_id.as_bytes()],
        |r| r.get(0),
    )
    .expect("bytes")
}

/// Puts `count` idempotency records for `(vault, device)` straight into the
/// table: `created_at` is `first_at + n` (or `first_at` for all when `same`),
/// and the `idem` is `n` as big-endian bytes.
fn insert_idem(
    conn: &mut Connection,
    vault: &VaultId,
    device: [u8; 16],
    count: u32,
    first_at: i64,
    same: bool,
) {
    let tx = conn.transaction().expect("a transaction");
    {
        let mut stmt = tx
            .prepare(
                "INSERT INTO ferret_idem \
                 (vault_id, device_id, idem, request_hash, rev, seq, created_at) \
                 VALUES (?1, ?2, ?3, ?4, 1, 1, ?5)",
            )
            .expect("prepare");
        for n in 0..count {
            let mut idem = [0u8; 16];
            idem[12..].copy_from_slice(&n.to_be_bytes());
            let at = if same {
                first_at
            } else {
                first_at + i64::from(n)
            };
            stmt.execute(params![vault.as_bytes(), device, idem, [7u8; 32], at])
                .expect("a record");
        }
    }
    tx.commit().expect("commit");
}

fn idem_count(conn: &Connection, vault: &VaultId, device: [u8; 16]) -> i64 {
    conn.query_row(
        "SELECT COUNT(*) FROM ferret_idem WHERE vault_id = ?1 AND device_id = ?2",
        params![vault.as_bytes(), device],
        |row| row.get(0),
    )
    .expect("count")
}

// ---------------------------------------------------------------- tombstones

#[test]
fn tombstones_older_than_400_days_are_purged_and_min_valid_since_rises() {
    assert_eq!(TOMBSTONE_DAYS, 400);
    let (mut conn, a) = with_account();
    let written = NOW;
    put(&mut conn, &a, &live(item(1), 0, 1), written); // seq 2
    put(&mut conn, &a, &live(item(2), 0, 2), written); // seq 3
    put(&mut conn, &a, &tomb(item(1), 1, 3), written); // seq 4
    put(&mut conn, &a, &tomb(item(2), 1, 4), written + DAY); // seq 5
    let before = bytes_used(&conn, &a);
    assert_eq!(floor(&conn, &a), 0);

    // Exactly 400 days after the write: not older than 400 days yet.
    let report = run_once(&mut conn, written + TOMBSTONE_DAYS * DAY).expect("a pass");
    assert_eq!(report.tombstones_removed, 0);
    assert_eq!(floor(&conn, &a), 0);

    // One second more: the first tombstone goes, the second (a day younger) not.
    let report = run_once(&mut conn, written + TOMBSTONE_DAYS * DAY + 1).expect("a pass");
    assert_eq!(report.vaults, 1);
    assert_eq!(report.tombstones_removed, 1);
    assert_eq!(floor(&conn, &a), 4, "the highest seq of the removed rows");
    assert_eq!(bytes_used(&conn, &a), before - 9, "its 9 bytes are freed");
    let rows = count(&conn, "SELECT COUNT(*) FROM ferret_items WHERE deleted = 1");
    assert_eq!(rows, 1);

    // The day after, the other one goes and the floor rises again.
    let report = run_once(&mut conn, written + (TOMBSTONE_DAYS + 1) * DAY + 1).expect("a pass");
    assert_eq!(report.tombstones_removed, 1);
    assert_eq!(floor(&conn, &a), 5);

    // A second pass has nothing to do and the floor never falls.
    let again = run_once(&mut conn, written + 1000 * DAY).expect("a pass");
    assert_eq!(again.tombstones_removed, 0);
    assert_eq!(floor(&conn, &a), 5);
}

#[test]
fn younger_tombstones_and_live_rows_stay() {
    let (mut conn, a) = with_account();
    let written = NOW;
    put(&mut conn, &a, &live(item(1), 0, 1), written);
    put(&mut conn, &a, &live(item(2), 0, 2), written);
    put(&mut conn, &a, &tomb(item(2), 1, 3), written + 300 * DAY);
    let before = changes_since(&conn, &a.vault_id, 0, 100, usize::MAX).expect("changes");

    // 1 000 days on, the live rows (old as they are) and the manifest stay; the
    // tombstone is 700 days old and goes. At 399 days after it was written it
    // would have stayed.
    let report = run_once(&mut conn, written + 300 * DAY + 399 * DAY).expect("a pass");
    assert_eq!(report.tombstones_removed, 0);
    assert_eq!(
        changes_since(&conn, &a.vault_id, 0, 100, usize::MAX)
            .expect("changes")
            .changes,
        before.changes
    );
    let report = run_once(&mut conn, written + 1000 * DAY).expect("a pass");
    assert_eq!(report.tombstones_removed, 1);
    let after = changes_since(&conn, &a.vault_id, 0, 100, usize::MAX).expect("changes");
    assert_eq!(after.changes.len(), 2, "the manifest and item 1");
    assert!(after.changes.iter().all(|c| !c.deleted));
    assert_eq!(
        count(&conn, "SELECT item_count FROM ferret_vaults"),
        2,
        "the live count is untouched"
    );
}

#[test]
fn a_pass_works_per_vault() {
    let mut conn = migrated();
    let a = add_account(&mut conn, 1, NOW);
    let b = add_account(&mut conn, 2, NOW);
    let c = add_account(&mut conn, 3, NOW);
    for (who, at) in [(&a, NOW), (&b, NOW + 399 * DAY), (&c, NOW)] {
        put(&mut conn, who, &live(item(1), 0, 1), at);
        put(&mut conn, who, &tomb(item(1), 1, 2), at);
    }
    let report = run_once(&mut conn, NOW + 401 * DAY).expect("a pass");
    assert_eq!(report.vaults, 3);
    assert_eq!(report.tombstones_removed, 2, "a and c, not b");
    assert!(floor(&conn, &a) > 0 && floor(&conn, &c) > 0);
    assert_eq!(floor(&conn, &b), 0);
    let rows = |who: &TestAccount| -> i64 {
        conn.query_row(
            "SELECT COUNT(*) FROM ferret_items WHERE vault_id = ?1 AND deleted = 1",
            [who.vault_id.as_bytes()],
            |r| r.get(0),
        )
        .expect("count")
    };
    assert_eq!((rows(&a), rows(&b), rows(&c)), (0, 1, 0));
}

// ---------------------------------------------------- idempotency records

#[test]
fn idem_rows_older_than_30_days_go() {
    assert_eq!(IDEM_DAYS, 30);
    let (mut conn, a) = with_account();
    put(&mut conn, &a, &live(item(1), 0, 1), NOW);
    put(&mut conn, &a, &live(item(2), 0, 2), NOW + 10 * DAY);
    assert_eq!(count(&conn, "SELECT COUNT(*) FROM ferret_idem"), 2);

    // Exactly 30 days: not older yet.
    let report = run_once(&mut conn, NOW + IDEM_DAYS * DAY).expect("a pass");
    assert_eq!(report.idem_removed, 0);
    // One second more: the first goes.
    let report = run_once(&mut conn, NOW + IDEM_DAYS * DAY + 1).expect("a pass");
    assert_eq!(report.idem_removed, 1);
    assert_eq!(count(&conn, "SELECT COUNT(*) FROM ferret_idem"), 1);
    let report = run_once(&mut conn, NOW + 41 * DAY).expect("a pass");
    assert_eq!(report.idem_removed, 1);
    assert_eq!(count(&conn, "SELECT COUNT(*) FROM ferret_idem"), 0);
    // The rows themselves are not touched by the idempotency purge.
    assert_eq!(count(&conn, "SELECT COUNT(*) FROM ferret_items"), 3);
}

#[test]
fn only_the_newest_1000_idem_rows_per_device_stay() {
    assert_eq!(IDEM_PER_DEVICE, 1_000);
    let mut conn = migrated();
    let a = add_account(&mut conn, 1, NOW);
    let b = add_account(&mut conn, 2, NOW);
    let device_x = id16(0xd1, 1);
    let device_y = id16(0xd1, 2);
    // All within the last day: only the cap applies.
    let first = NOW - 1000;
    insert_idem(&mut conn, &a.vault_id, device_x, 1_200, first, false);
    insert_idem(&mut conn, &a.vault_id, device_y, 5, first, false);
    // The same device id in another vault is another device.
    insert_idem(&mut conn, &b.vault_id, device_x, 1_100, first, false);
    // Exactly 1 000: nothing goes.
    let exact = id16(0xd1, 3);
    insert_idem(&mut conn, &a.vault_id, exact, 1_000, first, false);

    let report = run_once(&mut conn, NOW).expect("a pass");
    assert_eq!(report.idem_removed, 200 + 100);
    assert_eq!(idem_count(&conn, &a.vault_id, device_x), 1_000);
    assert_eq!(idem_count(&conn, &a.vault_id, device_y), 5);
    assert_eq!(idem_count(&conn, &b.vault_id, device_x), 1_000);
    assert_eq!(idem_count(&conn, &a.vault_id, exact), 1_000);

    // The newest stay: the oldest 200 of device x in vault a are the ones gone.
    let oldest_left: i64 = conn
        .query_row(
            "SELECT MIN(created_at) FROM ferret_idem WHERE vault_id = ?1 AND device_id = ?2",
            params![a.vault_id.as_bytes(), device_x],
            |r| r.get(0),
        )
        .expect("min");
    assert_eq!(oldest_left, first + 200);

    // Records of one second: which stay does not depend on luck, and the count
    // is still exact.
    let tied = id16(0xd1, 4);
    insert_idem(&mut conn, &a.vault_id, tied, 1_050, first, true);
    run_once(&mut conn, NOW).expect("a pass");
    assert_eq!(idem_count(&conn, &a.vault_id, tied), 1_000);
    let lowest_idem: Vec<u8> = conn
        .query_row(
            "SELECT MIN(idem) FROM ferret_idem WHERE vault_id = ?1 AND device_id = ?2",
            params![a.vault_id.as_bytes(), tied],
            |r| r.get(0),
        )
        .expect("min");
    assert_eq!(
        u32::from_be_bytes(lowest_idem[12..].try_into().unwrap()),
        50,
        "the highest idem of the tied records stay"
    );
}

#[test]
fn the_age_and_the_cap_apply_together() {
    let mut conn = migrated();
    let a = add_account(&mut conn, 1, NOW);
    let device = id16(0xd1, 1);
    // 600 records 40 days old, 700 records 1 day old.
    insert_idem(&mut conn, &a.vault_id, device, 600, NOW - 40 * DAY, false);
    let mut recent = Vec::new();
    for n in 0..700u32 {
        recent.push(n);
    }
    let tx = conn.transaction().expect("tx");
    for n in &recent {
        let mut idem = [0xffu8; 16];
        idem[12..].copy_from_slice(&n.to_be_bytes());
        tx.execute(
            "INSERT INTO ferret_idem (vault_id, device_id, idem, request_hash, rev, seq, created_at) \
             VALUES (?1, ?2, ?3, ?4, 1, 1, ?5)",
            params![a.vault_id.as_bytes(), device, idem, [1u8; 32], NOW - DAY + i64::from(*n)],
        )
        .expect("a record");
    }
    tx.commit().expect("commit");
    let report = run_once(&mut conn, NOW).expect("a pass");
    assert_eq!(report.idem_removed, 600);
    assert_eq!(idem_count(&conn, &a.vault_id, device), 700);
}

#[test]
fn run_once_on_an_empty_database_moves_nothing() {
    let mut conn = migrated();
    assert_eq!(
        run_once(&mut conn, NOW).expect("a pass"),
        RetentionReport::default()
    );
    // A vault with nothing old: it is looked at and nothing changes.
    let a = add_account(&mut conn, 1, NOW);
    put(&mut conn, &a, &live(item(1), 0, 1), NOW);
    let counters = |c: &Connection| -> (i64, i64, i64, i64) {
        c.query_row(
            "SELECT seq, min_valid_since, item_count, bytes_used FROM ferret_vaults",
            [],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
        )
        .expect("counters")
    };
    let before = counters(&conn);
    let rows = count(&conn, "SELECT COUNT(*) FROM ferret_items");
    let report = run_once(&mut conn, NOW + DAY).expect("a pass");
    assert_eq!(
        report,
        RetentionReport {
            vaults: 1,
            tombstones_removed: 0,
            idem_removed: 0,
            failed_vaults: 0
        }
    );
    assert_eq!(counters(&conn), before);
    assert_eq!(count(&conn, "SELECT COUNT(*) FROM ferret_items"), rows);
}

// ------------------------------------------------------------------ schedule

#[test]
fn next_run_is_ten_minutes_after_start_then_every_24_hours() {
    assert_eq!(next_run(1_000, None), 1_000 + 10 * 60);
    assert_eq!(next_run(1_000, Some(5_000)), 5_000 + 24 * 3600);
    // The run time, not the start, sets the next one.
    assert_eq!(next_run(0, Some(1_700_000_000)), 1_700_000_000 + 86_400);
}

fn tombstone_rows(app_db: &Connection) -> i64 {
    count(
        app_db,
        "SELECT COUNT(*) FROM ferret_items WHERE deleted = 1",
    )
}

async fn app_with_an_old_tombstone() -> (TestApp, TestAccount) {
    let app = TestApp::new().await;
    let account = support::accounts::add_account_to_app(&app, 1).await;
    let a = account;
    app.state
        .vault_db
        .with_conn(move |conn| {
            // Written long before the clock of the app: a pass finds it old.
            put(conn, &a, &live(item(1), 0, 1), 1_000);
            put(conn, &a, &tomb(item(1), 1, 2), 1_000);
            Ok(())
        })
        .await
        .expect("seed");
    (app, account)
}

async fn tombstones(app: &TestApp) -> i64 {
    app.state
        .vault_db
        .with_conn(|conn| Ok(tombstone_rows(conn)))
        .await
        .expect("count")
}

#[tokio::test]
async fn the_job_runs_ten_minutes_after_start_then_every_24_hours() {
    let (app, _) = app_with_an_old_tombstone().await;
    let clock = app.clock.clone();
    let db = app.state.vault_db.clone();
    let mut job = Job::new(clock.as_ref());

    assert!(job.poll(&db, clock.as_ref()).await.is_none(), "not due");
    clock.advance(599);
    assert!(
        job.poll(&db, clock.as_ref()).await.is_none(),
        "one second early"
    );
    assert_eq!(tombstones(&app).await, 1);
    clock.advance(1);
    let report = job
        .poll(&db, clock.as_ref())
        .await
        .expect("the first pass, 10 minutes after the start");
    assert_eq!(report.tombstones_removed, 1);
    assert_eq!(tombstones(&app).await, 0);

    // Not again until 24 hours after this run.
    assert!(job.poll(&db, clock.as_ref()).await.is_none());
    clock.advance(24 * 3600 - 1);
    assert!(job.poll(&db, clock.as_ref()).await.is_none());
    clock.advance(1);
    let second = job.poll(&db, clock.as_ref()).await.expect("the daily pass");
    assert_eq!(second.vaults, 1);
    // And 24 hours after that one, even if the poll came late.
    clock.advance(24 * 3600 + 500);
    assert!(job.poll(&db, clock.as_ref()).await.is_some());
    clock.advance(24 * 3600 - 1);
    assert!(job.poll(&db, clock.as_ref()).await.is_none());
}

#[tokio::test]
async fn a_clock_that_cannot_tell_the_time_purges_nothing() {
    let (app, _) = app_with_an_old_tombstone().await;
    let clock = app.clock.clone();
    let db = app.state.vault_db.clone();
    // The clock reads `u64::MAX` when it fails. Taken for "now" it would make
    // every tombstone old.
    clock.set(u64::MAX);
    let mut job = Job::new(clock.as_ref());
    assert!(job.poll(&db, clock.as_ref()).await.is_none());
    clock.advance(1_000_000);
    assert!(job.poll(&db, clock.as_ref()).await.is_none());
    assert_eq!(tombstones(&app).await, 1);

    // Repaired: the schedule starts from the first good reading.
    clock.set(1_793_491_200);
    assert!(job.poll(&db, clock.as_ref()).await.is_none());
    clock.advance(600);
    assert!(job.poll(&db, clock.as_ref()).await.is_some());
    assert_eq!(tombstones(&app).await, 0);
}

#[tokio::test]
async fn a_failed_pass_is_tried_again_in_ten_minutes() {
    let (app, _) = app_with_an_old_tombstone().await;
    let clock = app.clock.clone();
    let db = app.state.vault_db.clone();
    let mut job = Job::new(clock.as_ref());
    db.with_conn(|conn| {
        conn.execute_batch(
            "CREATE TRIGGER block_purge BEFORE DELETE ON ferret_items \
             BEGIN SELECT RAISE(ABORT, 'blocked'); END;",
        )?;
        Ok(())
    })
    .await
    .expect("a trigger");
    clock.advance(600);
    assert!(
        job.poll(&db, clock.as_ref()).await.is_none(),
        "the pass failed"
    );
    assert_eq!(tombstones(&app).await, 1);

    db.with_conn(|conn| Ok(conn.execute_batch("DROP TRIGGER block_purge;")?))
        .await
        .expect("drop");
    clock.advance(599);
    assert!(
        job.poll(&db, clock.as_ref()).await.is_none(),
        "not before 10 minutes"
    );
    clock.advance(1);
    assert!(job.poll(&db, clock.as_ref()).await.is_some());
    assert_eq!(tombstones(&app).await, 0);
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02X}")).collect()
}

fn block_one_vault_sql(vault: &VaultId) -> String {
    format!(
        "CREATE TRIGGER block_one_vault BEFORE DELETE ON ferret_items \
         WHEN hex(old.vault_id) = '{}' \
         BEGIN SELECT RAISE(ABORT, 'blocked'); END;",
        hex(vault.as_bytes())
    )
}

#[test]
fn a_vault_that_fails_does_not_keep_the_next_vault_from_being_purged() {
    let mut conn = migrated();
    let a = add_account(&mut conn, 1, NOW);
    let b = add_account(&mut conn, 2, NOW);
    for who in [&a, &b] {
        put(&mut conn, who, &live(item(1), 0, 1), NOW);
        put(&mut conn, who, &tomb(item(1), 1, 2), NOW);
    }
    // Only the purge of the vault that comes first in the order of the pass fails.
    let (first, second) = if a.vault_id.as_bytes() < b.vault_id.as_bytes() {
        (&a, &b)
    } else {
        (&b, &a)
    };
    conn.execute_batch(&block_one_vault_sql(&first.vault_id))
        .expect("a trigger");
    let report = run_once(&mut conn, NOW + 401 * DAY).expect("a pass that reports the failure");
    assert_eq!(report.vaults, 2);
    assert_eq!(report.failed_vaults, 1, "the failure is reported");
    assert_eq!(
        report.tombstones_removed, 1,
        "the vault after the failing one was purged"
    );
    let rows = |who: &TestAccount| -> i64 {
        conn.query_row(
            "SELECT COUNT(*) FROM ferret_items WHERE vault_id = ?1 AND deleted = 1",
            [who.vault_id.as_bytes()],
            |r| r.get(0),
        )
        .expect("count")
    };
    assert_eq!(rows(first), 1, "the failing vault keeps its tombstone");
    assert_eq!(rows(second), 0);
    assert_eq!(floor(&conn, first), 0, "its floor did not move");
    assert!(floor(&conn, second) > 0);
    // Nothing failing any more: the next pass reports no failure.
    conn.execute_batch("DROP TRIGGER block_one_vault;")
        .expect("drop");
    let again = run_once(&mut conn, NOW + 402 * DAY).expect("a pass");
    assert_eq!(again.failed_vaults, 0);
    assert_eq!(again.tombstones_removed, 1);
}

#[tokio::test]
async fn a_pass_with_one_failed_vault_is_tried_again_in_ten_minutes() {
    let app = TestApp::new().await;
    let a = support::accounts::add_account_to_app(&app, 1).await;
    let b = support::accounts::add_account_to_app(&app, 2).await;
    let clock = app.clock.clone();
    let db = app.state.vault_db.clone();
    let blocked = block_one_vault_sql(&a.vault_id);
    db.with_conn(move |conn| {
        for who in [&a, &b] {
            put(conn, who, &live(item(1), 0, 1), 1_000);
            put(conn, who, &tomb(item(1), 1, 2), 1_000);
        }
        conn.execute_batch(&blocked)?;
        Ok(())
    })
    .await
    .expect("seed");
    let mut job = Job::new(clock.as_ref());
    clock.advance(600);
    assert!(
        job.poll(&db, clock.as_ref()).await.is_none(),
        "a failed vault makes the pass a failure"
    );
    assert_eq!(tombstones(&app).await, 1, "the other vault was purged");
    db.with_conn(|conn| Ok(conn.execute_batch("DROP TRIGGER block_one_vault;")?))
        .await
        .expect("drop");
    clock.advance(599);
    assert!(
        job.poll(&db, clock.as_ref()).await.is_none(),
        "not before 10 minutes"
    );
    clock.advance(1);
    let report = job.poll(&db, clock.as_ref()).await.expect("the retry");
    assert_eq!(report.failed_vaults, 0);
    assert_eq!(tombstones(&app).await, 0);
}

// ----------------------------------------------- the way back to every row

fn get(uri: &str, jar: &Jar) -> Request<Body> {
    let mut builder = Request::builder().method("GET").uri(uri);
    if let Some(cookie) = jar.header() {
        builder = builder.header("cookie", cookie);
    }
    builder.body(Body::empty()).expect("a request")
}

#[tokio::test]
async fn purge_then_listing_then_changes_recovers_every_live_row() {
    use ferret_core::testing::TestRng;
    use ferret_core::{
        ItemBody, ItemType, OsRng, UnlockedVault, VaultContext, VaultKey, encrypt_item,
        make_tombstone,
    };
    use ferret_server::auth::session::Origin;
    use ferret_server::wire::{ItemsRes, b64url, hex16};
    use ferret_server_auth::SessionScope;
    use serde_json::json;
    use support::session::issue;

    let app = TestApp::new().await;
    let account = support::accounts::add_account_to_app(&app, 1).await;
    let issued = issue(&app, account.user_id, Origin::Vault, SessionScope::Full, 1).await;
    let jar = issued.jar;
    let vault = UnlockedVault::from_vault_key(
        VaultContext {
            account_id: account.account_id,
            vault_id: account.vault_id,
            vk_epoch: 1,
        },
        VaultKey::from_test_bytes([1; 32]),
    )
    .expect("a vault");
    let write = |id: ItemId, body: serde_json::Value| {
        let jar = jar.clone();
        let app = &app;
        async move {
            let request = Request::builder()
                .method("PUT")
                .uri(format!("/api/sync/items/{}", hex16::encode(id.as_bytes())))
                .header("origin", support::VAULT_URL)
                .header("sec-fetch-site", "same-origin")
                .header("ferret-protocol", "1")
                .header("content-type", "application/json")
                .header("cookie", jar.header().expect("a cookie"))
                .body(Body::from(body.to_string()))
                .expect("a request");
            let res = app.call_raw(Which::Vault, request).await;
            assert_eq!(res.status, StatusCode::OK, "{}", res.text());
        }
    };
    let live_body = |id: ItemId, rev: u64, name: &str, idem: u8| {
        let mut body = ItemBody::new(ItemType::Note, name, 1);
        body.notes = Some(name.to_string());
        let sealed = encrypt_item(
            &mut TestRng::new(name.as_bytes()),
            &vault,
            id,
            rev,
            &body,
            None,
        )
        .expect("an item");
        json!({
            "base_rev": rev - 1,
            "blob": b64url::encode(&sealed.envelope),
            "tag": b64url::encode(&sealed.tag),
            "idem": hex16::encode(&[idem; 16]),
        })
    };
    for n in 1..=4u8 {
        write(item(n), live_body(item(n), 1, &format!("item {n}"), n)).await;
    }
    let t = make_tombstone(&mut OsRng, &vault, item(2), 2).expect("a tombstone");
    write(
        item(2),
        json!({
            "base_rev": 1, "deleted": true,
            "tomb": b64url::encode(&t.tomb),
            "idem": hex16::encode(&[0x42; 16]),
        }),
    )
    .await;
    // A device that has seen everything up to here.
    let cursor = 3;

    // 401 days on, the tombstone is purged.
    let report = app
        .state
        .vault_db
        .with_conn(|conn| run_once(conn, NOW_PLUS_401_DAYS))
        .await
        .expect("a pass");
    assert_eq!(report.tombstones_removed, 1);

    // The device's cursor is below the floor: 410, and the floor is the
    // tombstone's seq.
    let gone = app
        .call_raw(
            Which::Vault,
            get(&format!("/api/sync/changes?since={cursor}"), &jar),
        )
        .await;
    assert_eq!(gone.status, StatusCode::GONE, "{}", gone.text());
    assert_eq!(
        gone.json(),
        json!({ "error": "gone", "min_valid_since": 6 })
    );

    // The listing, from the start, in small pages.
    let mut live_ids: Vec<[u8; 16]> = Vec::new();
    let mut as_of = None;
    let mut query = "?limit=2".to_string();
    loop {
        let res = app
            .call_raw(Which::Vault, get(&format!("/api/sync/items{query}"), &jar))
            .await;
        assert_eq!(res.status, StatusCode::OK, "{}", res.text());
        let page: ItemsRes = serde_json::from_slice(&res.body).expect("a page");
        as_of.get_or_insert(page.as_of_seq);
        live_ids.extend(page.items.iter().filter(|r| !r.deleted).map(|r| r.id));
        match page.next_after {
            Some(after) => query = format!("?limit=2&after={}", hex16::encode(&after)),
            None => break,
        }
    }
    // Every live row: the manifest and items 1, 3 and 4. The purged tombstone is
    // not listed, and nothing live is missing.
    let expected: Vec<[u8; 16]> = vec![
        [0; 16],
        *item(1).as_bytes(),
        *item(3).as_bytes(),
        *item(4).as_bytes(),
    ];
    assert_eq!(live_ids, expected);

    // From the first page's `as_of_seq` the feed is accepted again, and a row
    // written after the listing arrives through it.
    let as_of = as_of.expect("a page");
    write(item(5), live_body(item(5), 1, "after the listing", 9)).await;
    let feed = app
        .call_raw(
            Which::Vault,
            get(&format!("/api/sync/changes?since={as_of}"), &jar),
        )
        .await;
    assert_eq!(feed.status, StatusCode::OK, "{}", feed.text());
    let changes = feed.json()["changes"].as_array().expect("changes").clone();
    assert_eq!(changes.len(), 1);
    assert_eq!(changes[0]["id"], json!(hex16::encode(item(5).as_bytes())));
}

/// The time of the retention pass in the recovery test: 401 days after the
/// clock of the app started (`support::START`).
const NOW_PLUS_401_DAYS: i64 = 1_793_491_200 + 401 * DAY;
