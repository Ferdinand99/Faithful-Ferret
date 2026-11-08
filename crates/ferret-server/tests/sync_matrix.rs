//! The sync matrix: scenarios of two or three devices against the real server,
//! each device a [`SimClient`] with its own session, its own rollback memory
//! and the real core. Spec: Fase 1 § 8.1 to § 8.6 and § 14.7.
//!
//! The first group is the seven scenarios of the phase 0A prototype; the second
//! is the list of § 14.7 (full listing after `410`, batches, a server that
//! swaps or hides rows, checkpoints, `restore_epoch`, tombstones); the last is
//! the size test, which is `#[ignore]`d.
//!
//! Nothing sleeps. The server runs on the manual clock of the test app; the
//! clock of a device is that clock plus a skew a test sets.

mod support;

use std::time::{Duration, Instant};

use axum::http::{Method, StatusCode};
use ferret_core::{CheckpointFailure, ItemBody, ItemType, OsRng, encrypt_item, make_tombstone};
use ferret_server::ids::ItemId;
use ferret_server::vault::rate::RateConfig;
use ferret_server::wire::{ItemsRes, b64url, hex16};
use rusqlite::params;
use serde_json::{Value, json};

use support::sync::{
    SyncReport, View, Warning, World, as_op, batch_results, error_code, idem_of, item, live_body,
};
use support::{START, TestApp};

// ------------------------------------------------------------ the database

/// A row of `ferret_items` as the server holds it, to put back after a test
/// has tampered with it.
#[derive(Clone, Debug)]
struct DbRow {
    rev: i64,
    seq: i64,
    deleted: i64,
    blob: Option<Vec<u8>>,
    tag: Option<Vec<u8>>,
    tomb: Option<Vec<u8>>,
    size: i64,
    changed_at: i64,
}

async fn read_row(world: &World, id: ItemId) -> DbRow {
    let vault = world.account.vault_id;
    world
        .db(move |conn| {
            conn.query_row(
                "SELECT rev, seq, deleted, blob, tag, tomb, size, changed_at \
                 FROM ferret_items WHERE vault_id = ?1 AND item_id = ?2",
                params![vault.as_bytes(), id.as_bytes()],
                |row| {
                    Ok(DbRow {
                        rev: row.get(0)?,
                        seq: row.get(1)?,
                        deleted: row.get(2)?,
                        blob: row.get(3)?,
                        tag: row.get(4)?,
                        tomb: row.get(5)?,
                        size: row.get(6)?,
                        changed_at: row.get(7)?,
                    })
                },
            )
            .expect("a row")
        })
        .await
}

async fn write_row(world: &World, id: ItemId, row: DbRow) {
    let vault = world.account.vault_id;
    world
        .db(move |conn| {
            conn.execute(
                "INSERT OR REPLACE INTO ferret_items \
                 (vault_id, item_id, rev, seq, deleted, blob, tag, tomb, size, changed_at) \
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
                params![
                    vault.as_bytes(),
                    id.as_bytes(),
                    row.rev,
                    row.seq,
                    row.deleted,
                    row.blob,
                    row.tag,
                    row.tomb,
                    row.size,
                    row.changed_at
                ],
            )
            .expect("write a row");
        })
        .await;
}

async fn remove_row(world: &World, id: ItemId) {
    let vault = world.account.vault_id;
    world
        .db(move |conn| {
            conn.execute(
                "DELETE FROM ferret_items WHERE vault_id = ?1 AND item_id = ?2",
                params![vault.as_bytes(), id.as_bytes()],
            )
            .expect("remove a row");
        })
        .await;
}

async fn count(world: &World, sql: &'static str) -> i64 {
    world
        .db(move |conn| conn.query_row(sql, [], |row| row.get(0)).expect("a count"))
        .await
}

// ----------------------------------------------------- phase 0A scenarios

#[tokio::test]
async fn concurrent_edit_conflict() {
    let world = World::new().await;
    let mut a = world.client("laptop").await;
    let mut b = world.client("phone").await;
    let id = item(1);
    a.edit(id, "v0");
    assert_eq!(a.sync().await.pushed, 1);
    assert!(b.sync().await.warnings.is_empty());
    assert_eq!(b.view(id), View::note("v0"));

    // Both change it. The laptop gets there first.
    a.edit(id, "from the laptop");
    b.edit(id, "from the phone");
    let report = a.sync().await;
    assert_eq!((report.pushed, report.conflicts.len()), (1, 0));

    // The phone reads the feed: the row of the laptop is newer than the base of
    // its draft. That is a conflict, and nothing is merged and nothing is sent.
    let report = b.sync().await;
    assert_eq!(report.conflicts, vec![id]);
    assert_eq!(report.pushed, 0);
    assert!(report.warnings.is_empty(), "{:?}", report.warnings);
    assert!(b.has_conflict(id));
    assert_eq!(b.view(id), View::note("from the phone"));
    assert_eq!(b.server_view(id), View::note("from the laptop"));
    // Syncing again does not send the draft over the other one either.
    let again = b.sync().await;
    assert_eq!(again.pushed, 0);
    assert_eq!(a.view(id), View::note("from the laptop"));

    // "Keep mine": the draft goes out on top of the laptop's row.
    b.keep_mine(id);
    let report = b.sync().await;
    assert_eq!((report.pushed, report.conflicts.len()), (1, 0));
    assert!(a.sync().await.warnings.is_empty());
    for device in [&a, &b] {
        assert_eq!(device.view(id), View::note("from the phone"));
        assert_eq!(device.rev_of(id), 3);
        assert!(!device.has_draft(id) && !device.has_conflict(id));
    }

    // The other way in: the phone does not read the feed first, and the server
    // answers `409` to its write. "Keep theirs" drops the draft.
    a.edit(id, "laptop again");
    b.edit(id, "phone again");
    assert_eq!(a.sync().await.pushed, 1);
    let report = b.push().await;
    assert_eq!(report.conflicts, vec![id]);
    assert_eq!(report.pushed, 0);
    assert_eq!(b.server_view(id), View::note("laptop again"));
    assert_eq!(b.view(id), View::note("phone again"));
    b.keep_theirs(id);
    assert_eq!(b.view(id), View::note("laptop again"));
    assert_eq!(b.sync().await.pushed, 0);
    assert!(a.sync().await.warnings.is_empty());
    for device in [&a, &b] {
        assert_eq!(device.view(id), View::note("laptop again"));
        assert_eq!(device.rev_of(id), 4);
    }
    assert_eq!(world.server_seq().await, 5);
}

#[tokio::test]
async fn different_items_no_conflict() {
    let world = World::new().await;
    let mut a = world.client("laptop").await;
    let mut b = world.client("phone").await;
    a.go_offline();
    b.go_offline();
    a.edit(item(1), "laptop's");
    b.edit(item(2), "phone's");
    // Offline, nothing leaves the device.
    assert_eq!(a.sync().await.pushed, 0);
    assert_eq!(b.sync().await.pushed, 0);
    assert_eq!(world.server_seq().await, 1);

    a.go_online();
    b.go_online();
    let first = a.sync().await;
    let second = b.sync().await;
    let third = a.sync().await;
    for report in [&first, &second, &third] {
        assert!(report.conflicts.is_empty(), "{:?}", report.conflicts);
        assert!(report.warnings.is_empty(), "{:?}", report.warnings);
    }
    assert_eq!((first.pushed, second.pushed, third.pushed), (1, 1, 0));
    for device in [&a, &b] {
        assert_eq!(device.view(item(1)), View::note("laptop's"));
        assert_eq!(device.view(item(2)), View::note("phone's"));
        assert_eq!((device.rev_of(item(1)), device.rev_of(item(2))), (1, 1));
    }
    assert_eq!(world.server_seq().await, 3);
}

#[tokio::test]
async fn offline_delete_vs_edit() {
    let world = World::new().await;
    let mut a = world.client("laptop").await;
    let mut b = world.client("phone").await;

    // Deleted here, edited there.
    let one = item(1);
    a.edit(one, "v0");
    a.sync().await;
    b.sync().await;
    a.go_offline();
    a.delete(one);
    assert_eq!(a.view(one), View::Deleted);
    b.edit(one, "edited on the phone");
    assert_eq!(b.sync().await.pushed, 1);
    a.go_online();
    let report = a.sync().await;
    assert_eq!(report.conflicts, vec![one]);
    assert_eq!(report.pushed, 0, "the deletion is not sent over an edit");
    assert_eq!(a.view(one), View::Deleted);
    assert_eq!(a.server_view(one), View::note("edited on the phone"));
    // The phone still has its item.
    b.sync().await;
    assert_eq!(b.view(one), View::note("edited on the phone"));
    // The user chooses to delete: the tombstone goes out on top of the edit.
    a.keep_mine(one);
    assert_eq!(a.sync().await.pushed, 1);
    b.sync().await;
    assert_eq!(b.view(one), View::Deleted);
    assert_eq!(b.rev_of(one), 3);

    // Edited here, deleted there. The deletion is not undone by the edit.
    let two = item(2);
    a.edit(two, "w0");
    a.sync().await;
    b.sync().await;
    a.go_offline();
    a.edit(two, "a late edit");
    b.delete(two);
    assert_eq!(b.sync().await.pushed, 1);
    a.go_online();
    let report = a.sync().await;
    assert_eq!(report.conflicts, vec![two]);
    assert_eq!(report.pushed, 0);
    assert_eq!(a.view(two), View::note("a late edit"));
    assert_eq!(a.server_view(two), View::Deleted);
    // A new device sees a deleted item: the edit has not brought it back.
    let mut c = world.client("tablet").await;
    assert!(c.sync().await.warnings.is_empty());
    assert_eq!(c.view(two), View::Deleted);
    // The user chooses to keep the edit: only now is the item brought back.
    a.keep_mine(two);
    assert_eq!(a.sync().await.pushed, 1);
    c.sync().await;
    assert_eq!(c.view(two), View::note("a late edit"));
    assert_eq!(c.rev_of(two), 3);
}

#[tokio::test]
async fn tombstone_no_resurrection() {
    let world = World::new().await;
    let mut a = world.client("laptop").await;
    let vault = world.vault();
    let id = item(1);
    a.edit(id, "short-lived");
    a.sync().await;
    a.delete(id);
    a.sync().await;
    assert_eq!(a.rev_of(id), 2);
    let seq = world.server_seq().await;

    // Against a tombstone at rev 2 nothing brings the item back without the
    // flag and the right base: an old base, the right base without the flag,
    // a new item (base 0), and the flag on a base that is not the tombstone's.
    let mut n = 100;
    let mut attempts: Vec<(&str, Value)> = Vec::new();
    for (name, base, resurrect) in [
        ("old base", 1u64, false),
        ("right base, no flag", 2, false),
        ("base 0", 0, false),
        ("flag on an old base", 1, true),
        ("flag on a base above", 3, true),
    ] {
        n += 1;
        let mut body = live_body(&vault, id, base, name, n);
        if resurrect {
            body["resurrect"] = json!(true);
        }
        attempts.push((name, body));
    }
    for (name, body) in &attempts {
        let res = a.put(id, body).await;
        assert_eq!(res.status, StatusCode::CONFLICT, "{name}: {}", res.text());
        let answer = res.json();
        assert_eq!(answer["deleted"], json!(true), "{name}");
        assert_eq!(answer["current_rev"], json!(2), "{name}");
        assert!(
            answer.get("blob").is_none() && answer.get("tag").is_none(),
            "{name}"
        );
    }
    let on_the_same: Vec<Value> = attempts
        .iter()
        .enumerate()
        .map(|(i, (_, body))| {
            let mut body = body.clone();
            body["idem"] = json!(hex16::encode(&idem_of(
                300 + u32::try_from(i).expect("small")
            )));
            as_op(id, &body)
        })
        .collect();
    // One id twice in a batch is refused as a whole, so each goes alone.
    for op in on_the_same {
        let results = batch_results(&a.post_batch(&[op]).await).results;
        assert_eq!(results[0].status, 409);
        assert_eq!(results[0].deleted, Some(true));
        assert_eq!(results[0].current_rev, Some(2));
    }
    assert_eq!(world.server_seq().await, seq, "nothing was stored");

    // Another device sees the item deleted.
    let mut b = world.client("phone").await;
    assert!(b.sync().await.warnings.is_empty());
    assert_eq!(b.view(id), View::Deleted);

    // With the right base and the flag, the item comes back (a choice).
    let mut asked = live_body(&vault, id, 2, "chosen", 900);
    asked["resurrect"] = json!(true);
    let res = a.put(id, &asked).await;
    assert_eq!(res.status, StatusCode::OK, "{}", res.text());
    assert_eq!(res.json()["rev"], json!(3));
    b.sync().await;
    assert_eq!(b.view(id), View::note("chosen"));
}

#[tokio::test]
async fn retry_idempotent() {
    let world = World::new().await;
    let mut a = world.client("laptop").await;
    let mut b = world.client("phone").await;
    let vault = world.vault();

    // The server stores the write and the answer is lost. The retry is the same
    // request and gets the first answer: one row, `replayed`.
    let one = item(1);
    a.edit(one, "one");
    a.lose_next_response();
    let report = a.push().await;
    assert_eq!(report.pushed, 0);
    assert!(a.is_in_flight(one));
    assert_eq!(world.server_seq().await, 2, "the server stored it");
    let report = a.push().await;
    assert_eq!((report.pushed, report.replayed), (1, 1));
    assert_eq!(
        world.server_seq().await,
        2,
        "and stored nothing the second time"
    );
    assert!(!a.has_draft(one) && !a.is_in_flight(one));
    assert_eq!(a.rev_of(one), 1);
    b.sync().await;
    assert_eq!(b.view(one), View::note("one"));
    assert_eq!(b.rev_of(one), 1);

    // The `idem` is checked before the base: another device has written on top
    // in the meantime, and the retry of the old request still gets its answer.
    let two = item(2);
    a.edit(two, "first");
    a.sync().await;
    b.sync().await;
    a.edit(two, "second");
    a.lose_next_response();
    a.push().await;
    b.sync().await;
    assert_eq!(b.view(two), View::note("second"));
    b.edit(two, "third");
    assert_eq!(b.sync().await.pushed, 1);
    let report = a.push().await;
    assert_eq!((report.pushed, report.replayed), (1, 1));
    assert!(report.conflicts.is_empty());
    assert_eq!(
        a.rev_of(two),
        2,
        "the answer of the first try, not a conflict"
    );
    let report = a.sync().await;
    assert!(report.conflicts.is_empty() && report.warnings.is_empty());
    assert_eq!(a.view(two), View::note("third"));

    // A batch sent twice: the second time every operation is a replay with
    // the same `rev` and `seq`, and nothing new is stored.
    let ops = [
        as_op(item(3), &live_body(&vault, item(3), 0, "x", 41)),
        as_op(item(4), &live_body(&vault, item(4), 0, "y", 42)),
    ];
    let first = batch_results(&a.post_batch(&ops).await).results;
    assert!(
        first
            .iter()
            .all(|r| r.status == 200 && r.replayed == Some(false))
    );
    let seq = world.server_seq().await;
    let again = batch_results(&a.post_batch(&ops).await).results;
    for (before, after) in first.iter().zip(&again) {
        assert_eq!(after.status, 200);
        assert_eq!(after.replayed, Some(true));
        assert_eq!((after.rev, after.seq), (before.rev, before.seq));
    }
    assert_eq!(world.server_seq().await, seq);
    // The batch grows by one operation on the retry: the old ones replay and
    // the new one is stored.
    let mut more = ops.to_vec();
    more.push(as_op(item(5), &live_body(&vault, item(5), 0, "z", 43)));
    let third = batch_results(&a.post_batch(&more).await).results;
    assert_eq!(
        third.iter().map(|r| r.replayed).collect::<Vec<_>>(),
        vec![Some(true), Some(true), Some(false)]
    );
    assert_eq!(world.server_seq().await, seq + 1);
    // The same `idem` with another request is refused in its slot.
    let clash = [as_op(item(3), &live_body(&vault, item(3), 0, "other", 41))];
    let refused = batch_results(&a.post_batch(&clash).await).results;
    assert_eq!(refused[0].status, 422);
    assert_eq!(refused[0].error.as_deref(), Some("idem_reuse"));
}

/// One line of the log of a scenario.
fn note(log: &mut Vec<String>, what: &str, report: &SyncReport) {
    log.push(format!(
        "{what}: pushed {} conflicts {} warnings {}",
        report.pushed,
        report.conflicts.len(),
        report.warnings.len()
    ));
}

/// What two devices do with the same scenario, as text.
async fn conflict_outcome(skew_a: i64, skew_b: i64, jump_the_server: bool) -> Vec<String> {
    let world = World::new().await;
    let mut a = world.client("laptop").await;
    let mut b = world.client("phone").await;
    a.set_clock_skew_ms(skew_a);
    b.set_clock_skew_ms(skew_b);
    let id = item(1);
    let mut log = Vec::new();
    a.edit(id, "one");
    note(&mut log, "a first", &a.sync().await);
    note(&mut log, "b first", &b.sync().await);
    if jump_the_server {
        world.app.clock.advance(3600);
    }
    a.edit(id, "from a");
    b.edit(id, "from b");
    note(&mut log, "b second", &b.sync().await);
    if jump_the_server {
        world.app.clock.advance(5 * 3600);
    }
    note(&mut log, "a second", &a.sync().await);
    log.push(format!("a: {:?} {}", a.view(id), a.has_conflict(id)));
    log.push(format!("b: {:?} {}", b.view(id), b.has_conflict(id)));
    a.keep_mine(id);
    note(&mut log, "a third", &a.sync().await);
    note(&mut log, "b third", &b.sync().await);
    log.push(format!("b: {:?} rev {}", b.view(id), b.rev_of(id)));
    log.push(format!("a: {:?} rev {}", a.view(id), a.rev_of(id)));
    log.push(format!("seq {}", world.server_seq().await));
    log
}

#[tokio::test]
async fn skewed_clock_irrelevant() {
    const YEARS_MS: i64 = 10 * 365 * 86_400 * 1000;
    let honest = conflict_outcome(0, 0, false).await;
    // One device runs ten years ahead, the other ten years behind, and the
    // server's own clock jumps between the steps.
    let skewed = conflict_outcome(YEARS_MS, -YEARS_MS, true).await;
    assert_eq!(honest, skewed, "only `rev` decides a conflict");
    // The skew is real: the phone wrote last by the server's clock, but its
    // body says it was written ten years before the laptop's.
    let world = World::new().await;
    let mut a = world.client("laptop").await;
    let mut b = world.client("phone").await;
    a.set_clock_skew_ms(YEARS_MS);
    b.set_clock_skew_ms(-YEARS_MS);
    a.edit(item(1), "a");
    world.app.clock.advance(60);
    b.edit(item(2), "b");
    let (ma, mb) = (
        a.modified_ms(item(1)).expect("a time"),
        b.modified_ms(item(2)).expect("a time"),
    );
    assert!(ma > mb, "the laptop's body is dated later than the phone's");
    assert!(ma - mb > 19 * 365 * 86_400 * 1000);
}

#[tokio::test]
async fn sse_convergence() {
    let world = World::new().await;
    let mut a = world.client("laptop").await;
    let mut b = world.client("phone").await;
    a.edit(item(1), "v1");
    a.sync().await;
    b.sync().await;

    let mut events = b.open_events().await;
    assert_eq!(events.status, StatusCode::OK);
    let hello = events.event("hello", Duration::from_secs(5)).await;
    assert_eq!(hello, json!({ "seq": world.server_seq().await }));

    // A write by the laptop reaches the phone's stream, and the phone reads the
    // row itself and converges. The event carries a `seq` and nothing else.
    a.edit(item(1), "v2");
    assert_eq!(a.sync().await.pushed, 1);
    let seq = world.server_seq().await;
    let sync = events.event("sync", Duration::from_secs(5)).await;
    assert_eq!(sync, json!({ "seq": seq }));
    let report = b.sync().await;
    assert!(report.warnings.is_empty() && report.conflicts.is_empty());
    assert_eq!(b.view(item(1)), View::note("v2"));
    assert_eq!(b.cursor(), seq);
    assert_eq!(b.rev_of(item(1)), a.rev_of(item(1)));
}

// -------------------------------------------------------------- § 14.7

#[tokio::test]
async fn listing_after_410_recovers_every_live_row_after_a_purge() {
    let world = World::new().await;
    let mut a = world.client("laptop").await;
    let mut b = world.client("phone").await;
    for n in 1..=6u16 {
        a.edit(item(n), &format!("item {n}"));
    }
    assert_eq!(a.sync().await.pushed, 6);
    a.pull().await;
    assert_eq!(a.cursor(), 7);
    b.sync().await;

    // While the laptop is away the phone deletes two items, edits one and adds
    // one. The tombstones are at seq 8 and 10.
    b.delete(item(2));
    b.edit(item(3), "item 3 changed");
    b.delete(item(5));
    b.edit(item(7), "item 7");
    assert_eq!(b.sync().await.pushed, 4);
    b.pull().await;

    // The server purges tombstones older than 400 days (without moving the
    // clock: a session would run out). The floor of the feed is now 10, above
    // the cursor of the laptop.
    let day = 86_400i64;
    world
        .run_retention(i64::try_from(START).expect("a time") + 401 * day)
        .await;
    assert_eq!(
        count(
            &world,
            "SELECT COUNT(*) FROM ferret_items WHERE deleted = 1"
        )
        .await,
        0
    );
    let res = a.send(Method::GET, "/api/sync/changes?since=7", None).await;
    assert_eq!(res.status, StatusCode::GONE, "{}", res.text());
    assert_eq!(res.json()["min_valid_since"], json!(10));

    // The laptop lists everything, in pages of two.
    a.set_page_limit(2);
    let report = a.pull().await;
    assert!(report.warnings.is_empty(), "{:?}", report.warnings);
    assert_eq!(a.cursor(), world.server_seq().await);
    let on_server = [1u16, 3, 4, 6, 7];
    for n in on_server {
        assert_eq!(a.view(item(n)), b.view(item(n)), "item {n}");
        assert!(!a.is_missing_on_server(item(n)), "item {n}");
    }
    assert_eq!(a.view(item(3)), View::note("item 3 changed"));
    assert_eq!(a.view(item(7)), View::note("item 7"));
    // What the listing does not have is kept, and marked: the server's silence
    // is not a reason to delete the only copy.
    for n in [2u16, 5] {
        assert!(a.is_missing_on_server(item(n)), "item {n}");
        assert_eq!(a.view(item(n)), View::note(&format!("item {n}")));
    }
    // The floors held: the laptop remembers the edit of item 3.
    assert_eq!(a.memory().rev_of(&item(3)), Some(2));

    // A device with no state needs no listing: from 0 the feed is complete.
    let mut c = world.client("tablet").await;
    let report = c.pull().await;
    assert!(report.warnings.is_empty(), "{:?}", report.warnings);
    assert_eq!(c.live_items(), on_server.map(item).to_vec());
    assert_eq!(c.cursor(), world.server_seq().await);
}

#[tokio::test]
async fn batch_each_op_is_its_own_transaction() {
    let world = World::new().await;
    let a = world.client("laptop").await;
    let vault = world.vault();
    let short_tomb = json!({
        "base_rev": 0,
        "deleted": true,
        "tomb": b64url::encode(&[1u8; 10]),
        "idem": hex16::encode(&idem_of(53)),
    });
    let ops = [
        // stored
        as_op(item(1), &live_body(&vault, item(1), 0, "one", 51)),
        // a base that does not exist: a conflict with no row
        as_op(item(2), &live_body(&vault, item(2), 3, "no base", 52)),
        // a tombstone that cannot be one
        as_op(item(3), &short_tomb),
        // stored, after two refusals
        as_op(item(4), &live_body(&vault, item(4), 0, "four", 54)),
        // an `idem` that was used for another request
        as_op(item(5), &live_body(&vault, item(5), 0, "five", 51)),
        // stored, after three refusals
        as_op(item(6), &live_body(&vault, item(6), 0, "six", 56)),
    ];
    let results = batch_results(&a.post_batch(&ops).await).results;
    let statuses: Vec<u16> = results.iter().map(|r| r.status).collect();
    assert_eq!(statuses, vec![200, 409, 422, 200, 422, 200]);
    assert_eq!(results[1].current_rev, Some(0));
    assert_eq!(results[1].deleted, Some(false));
    assert_eq!(results[2].error.as_deref(), Some("tombstone_invalid"));
    assert_eq!(results[4].error.as_deref(), Some("idem_reuse"));
    // Each stored operation committed on its own and has its own `seq`; the
    // refused ones used none.
    assert_eq!(
        [results[0].seq, results[3].seq, results[5].seq],
        [Some(2), Some(3), Some(4)]
    );
    assert_eq!(world.server_seq().await, 4);

    // What a device finds on the server is exactly the stored three.
    let mut b = world.client("phone").await;
    let report = b.sync().await;
    assert!(report.warnings.is_empty(), "{:?}", report.warnings);
    assert_eq!(b.live_items(), vec![item(1), item(4), item(6)]);
    assert_eq!(b.view(item(4)), View::note("four"));
}

#[tokio::test]
async fn swapped_blobs_in_the_database_are_refused_by_the_client() {
    let world = World::new().await;
    let mut a = world.client("laptop").await;
    let mut d = world.client("phone").await;
    a.edit(item(1), "one");
    a.edit(item(2), "two");
    a.sync().await;
    d.sync().await;
    assert_eq!(d.cursor(), 3);

    let (one, two) = (item(1), item(2));
    let (r1, r2) = (read_row(&world, one).await, read_row(&world, two).await);

    // Two ways to swap: the blobs alone, and the blobs with their tags (the tag
    // is over the item id too, so it does not follow the blob).
    for (name, swap_tags) in [("blobs", false), ("blobs and tags", true)] {
        let mut s1 = r1.clone();
        let mut s2 = r2.clone();
        s1.blob.clone_from(&r2.blob);
        s2.blob.clone_from(&r1.blob);
        if swap_tags {
            s1.tag.clone_from(&r2.tag);
            s2.tag.clone_from(&r1.tag);
        }
        write_row(&world, one, s1).await;
        write_row(&world, two, s2).await;

        // A new device reads the feed: both rows are refused and it holds
        // neither; the manifest, which is not swapped, is fine.
        let mut c = world.client("tablet").await;
        let report = c.pull().await;
        assert_eq!(
            report.warnings,
            vec![
                Warning::RowRefused { id: one },
                Warning::RowRefused { id: two }
            ],
            "{name}"
        );
        assert_eq!(c.view(one), View::Absent, "{name}");
        assert_eq!(c.view(two), View::Absent, "{name}");
        assert_eq!(c.memory().tracked(), 1, "{name}: only the manifest");
        assert_eq!(c.cursor(), world.server_seq().await, "{name}");

        write_row(&world, one, r1.clone()).await;
        write_row(&world, two, r2.clone()).await;
    }

    // The same through the full listing: a device that has the honest rows
    // is sent to the listing (`410`), the swapped rows are refused one by one,
    // and its own good copies stay.
    a.edit(item(3), "three");
    a.sync().await;
    let mut s1 = r1.clone();
    let mut s2 = r2.clone();
    s1.blob.clone_from(&r2.blob);
    s2.blob.clone_from(&r1.blob);
    write_row(&world, one, s1).await;
    write_row(&world, two, s2).await;
    let seq = world.server_seq().await;
    world
        .db(move |conn| {
            conn.execute(
                "UPDATE ferret_vaults SET min_valid_since = ?1",
                [i64::try_from(seq).expect("small")],
            )
            .expect("a floor");
        })
        .await;
    d.set_page_limit(2);
    let report = d.pull().await;
    assert_eq!(
        report.warnings,
        vec![
            Warning::RowRefused { id: one },
            Warning::RowRefused { id: two }
        ]
    );
    assert_eq!(d.view(one), View::note("one"));
    assert_eq!(d.view(two), View::note("two"));
    assert_eq!(d.view(item(3)), View::note("three"));
    assert_eq!(d.cursor(), seq);
}

/// A device that has pulled the honest state and checks the stored checkpoint.
async fn verdict(world: &World) -> Result<(), Warning> {
    let mut c = world.client("checker").await;
    let report = c.pull().await;
    assert!(report.warnings.is_empty(), "{:?}", report.warnings);
    c.verify().await
}

#[tokio::test]
async fn checkpoint_passes_honest_and_catches_hidden_rolled_back_and_replaced_rows() {
    let world = World::new().await;
    let mut a = world.client("laptop").await;
    let vault = world.vault();
    for n in 1..=4u16 {
        a.edit(item(n), &format!("v{n}"));
    }
    a.sync().await;
    let old_two = read_row(&world, item(2)).await;
    a.edit(item(2), "v2 edited");
    a.sync().await;
    a.pull().await;
    assert_eq!(a.cursor(), 6);

    // The laptop uploads the checkpoint of its state at the top, and any device
    // that reads the honest server finds nothing wrong.
    let up = a.upload_checkpoint().await;
    assert_eq!(up.status, StatusCode::OK, "{}", up.text());
    assert_eq!(a.verify().await, Ok(()));
    assert_eq!(verdict(&world).await, Ok(()));

    // News after the checkpoint do not make it wrong: it is below the top now,
    // and every entry is still shown with the same or a higher revision.
    a.edit(item(5), "v5");
    a.sync().await;
    a.pull().await;
    assert_eq!(a.cursor(), 7);
    assert_eq!(verdict(&world).await, Ok(()));

    // A hidden row: the server leaves out an item the checkpoint lists.
    let three = read_row(&world, item(3)).await;
    remove_row(&world, item(3)).await;
    assert_eq!(
        verdict(&world).await,
        Err(Warning::Checkpoint(CheckpointFailure::HiddenOrRolledBack))
    );
    write_row(&world, item(3), three).await;

    // A rolled-back row: the server shows revision 1 of an item that is at 2
    // in the checkpoint. The old row is valid (its tag is), only old.
    let current_two = read_row(&world, item(2)).await;
    assert_eq!(old_two.rev, 1);
    write_row(&world, item(2), old_two).await;
    assert_eq!(
        verdict(&world).await,
        Err(Warning::Checkpoint(CheckpointFailure::LowerRev))
    );
    write_row(&world, item(2), current_two).await;

    // A replaced row: the same revision with another, valid, body.
    let four = read_row(&world, item(4)).await;
    let mut other = ItemBody::new(ItemType::Note, "not what was written", 1);
    other.notes = Some("replaced".to_string());
    let sealed = encrypt_item(&mut OsRng, &vault, item(4), 1, &other, None).expect("an item");
    write_row(
        &world,
        item(4),
        DbRow {
            size: i64::try_from(sealed.envelope.len()).expect("small"),
            blob: Some(sealed.envelope),
            tag: Some(sealed.tag.to_vec()),
            ..four.clone()
        },
    )
    .await;
    assert_eq!(
        verdict(&world).await,
        Err(Warning::Checkpoint(CheckpointFailure::SameRevDifferentHash))
    );
    write_row(&world, item(4), four).await;
    assert_eq!(verdict(&world).await, Ok(()));

    // At the top the rows must be the entries exactly: a new checkpoint at 7,
    // and now a hidden newest row is caught too.
    world.app.clock.advance(601);
    let up = a.upload_checkpoint().await;
    assert_eq!(up.status, StatusCode::OK, "{}", up.text());
    assert_eq!(verdict(&world).await, Ok(()));
    let five = read_row(&world, item(5)).await;
    remove_row(&world, item(5)).await;
    assert_eq!(
        verdict(&world).await,
        Err(Warning::Checkpoint(CheckpointFailure::TopDigestMismatch))
    );
    write_row(&world, item(5), five).await;
    assert_eq!(verdict(&world).await, Ok(()));
}

#[tokio::test]
async fn restore_epoch_bump_is_seen_and_accept_older_state_resets_the_floors() {
    let world = World::new().await;
    let mut a = world.client("laptop").await;
    let mut b = world.client("phone").await;
    a.edit(item(1), "one");
    a.edit(item(2), "two");
    a.sync().await;
    a.pull().await;
    b.sync().await;
    let up = a.upload_checkpoint().await;
    assert_eq!(up.status, StatusCode::OK, "{}", up.text());
    assert_eq!(b.verify().await, Ok(()));
    assert_eq!(b.memory().checkpoint_seq(), 3);
    let backup = world.snapshot().await;

    // Life goes on, and both devices read it.
    a.edit(item(1), "one, edited");
    a.edit(item(3), "three");
    a.sync().await;
    a.pull().await;
    b.sync().await;
    assert_eq!(b.memory().max_seq(), 5);
    assert_eq!(b.memory().rev_of(&item(1)), Some(2));
    assert_eq!(b.restore_epoch(), Some(0));

    // The server is put back from the backup. Without the bump of the epoch
    // that is a rollback, and the device stops.
    world.restore_snapshot(backup).await;
    assert_eq!(world.server_seq().await, 3);
    let report = b.pull().await;
    assert!(report.halted());
    assert_eq!(report.warnings, vec![Warning::RollbackSuspected]);

    // The administrator bumps the epoch. Now the same state is "the server was
    // restored", on both devices, and nothing is written meanwhile.
    assert_eq!(world.bump_restore_epoch().await, 1);
    for device in [&mut a, &mut b] {
        let report = device.pull().await;
        assert!(report.halted());
        assert_eq!(report.warnings, vec![Warning::ServerRestored { epoch: 1 }]);
    }
    b.edit(item(2), "two, from the phone");
    let report = b.sync().await;
    assert!(report.halted());
    assert_eq!(report.pushed, 0);
    assert_eq!(world.server_seq().await, 3, "nothing was written");
    // Nothing is lost locally, and the floors have not moved.
    assert_eq!(b.view(item(1)), View::note("one, edited"));
    assert_eq!(b.view(item(3)), View::note("three"));
    assert_eq!(b.memory().max_seq(), 5);
    assert_eq!(b.memory().rev_of(&item(1)), Some(2));

    // After the user has confirmed, the phone takes the older state: the
    // floors are those of the restored server, and what the server lacks is
    // sent up as new writes on top of the restored rows.
    b.accept_older_state().await.expect("an older state");
    assert_eq!(b.memory().max_seq(), 3);
    assert_eq!(b.memory().checkpoint_seq(), 3);
    assert_eq!(b.memory().rev_of(&item(1)), Some(1));
    assert_eq!(b.memory().rev_of(&item(3)), None);
    assert_eq!(b.restore_epoch(), Some(1));
    assert!(b.has_draft(item(1)) && b.has_draft(item(3)) && b.has_draft(item(2)));
    assert_eq!(b.view(item(1)), View::note("one, edited"));
    let report = b.sync().await;
    assert!(report.warnings.is_empty(), "{:?}", report.warnings);
    assert!(report.conflicts.is_empty(), "{:?}", report.conflicts);
    assert_eq!(report.pushed, 3);
    assert_eq!(world.server_seq().await, 6);

    // The laptop accepts it too, and has nothing newer than what the phone
    // sent up; it reads the same state and no conflict is shown.
    a.accept_older_state().await.expect("an older state");
    assert_eq!(a.memory().max_seq(), 6);
    assert_eq!(a.restore_epoch(), Some(1));
    let report = a.sync().await;
    assert!(report.warnings.is_empty(), "{:?}", report.warnings);
    assert!(report.conflicts.is_empty(), "{:?}", report.conflicts);
    for n in 1..=3u16 {
        assert_eq!(a.view(item(n)), b.view(item(n)), "item {n}");
        assert_eq!(a.rev_of(item(n)), b.rev_of(item(n)), "item {n}");
    }
    assert_eq!(a.view(item(1)), View::note("one, edited"));
    assert_eq!(a.view(item(2)), View::note("two, from the phone"));
}

#[tokio::test]
async fn tombstone_without_a_valid_tag_is_refused_by_the_client() {
    let world = World::new().await;
    let mut a = world.client("laptop").await;
    let vault = world.vault();

    let variants = [
        "garbage",
        "the tombstone of another item",
        "the tombstone of another revision",
    ];
    for (k, name) in variants.into_iter().enumerate() {
        let id = item(10 + u16::try_from(k).expect("small"));
        let other = item(50);
        a.edit(id, "keep me");
        a.edit(other, "bystander");
        a.sync().await;
        // A phone that has the item before it is deleted.
        let mut holder = world.client("phone").await;
        holder.sync().await;
        assert_eq!(holder.view(id), View::note("keep me"), "{name}");

        a.delete(id);
        a.sync().await;
        let honest = read_row(&world, id).await;
        assert_eq!(honest.deleted, 1);
        let bad = match k {
            0 => vec![0x55u8; 40],
            1 => {
                make_tombstone(&mut OsRng, &vault, other, 2)
                    .expect("a tombstone")
                    .tomb
            }
            _ => {
                make_tombstone(&mut OsRng, &vault, id, 3)
                    .expect("a tombstone")
                    .tomb
            }
        };
        write_row(
            &world,
            id,
            DbRow {
                tomb: Some(bad),
                ..honest.clone()
            },
        )
        .await;

        // The phone refuses the tombstone: the item is quarantined, the local
        // copy stays and the floor does not rise.
        let report = holder.pull().await;
        assert_eq!(
            report.warnings,
            vec![Warning::TombstoneRefused { id }],
            "{name}"
        );
        assert!(holder.is_quarantined(id), "{name}");
        assert_eq!(holder.view(id), View::note("keep me"), "{name}");
        assert_eq!(holder.memory().rev_of(&id), Some(1), "{name}");

        // A device with no copy does not delete anything either: it has no
        // such item, and the row is quarantined.
        let mut fresh = world.client("tablet").await;
        let report = fresh.pull().await;
        assert_eq!(
            report.warnings,
            vec![Warning::TombstoneRefused { id }],
            "{name}"
        );
        assert_eq!(fresh.view(id), View::Absent, "{name}");
        assert!(fresh.is_quarantined(id), "{name}");

        write_row(&world, id, honest).await;
        // Back to honest, everything is as before.
        let mut honest_reader = world.client("reader").await;
        let report = honest_reader.pull().await;
        assert!(report.warnings.is_empty(), "{name}: {:?}", report.warnings);
        assert_eq!(honest_reader.view(id), View::Deleted, "{name}");
    }
}

// ----------------------------------------------------------- the size test

#[tokio::test]
#[ignore = "10 000 items: run with --release --ignored; prints the times"]
async fn ten_thousand_items() {
    // The batch counts one operation for each item (10 000 of them), so the
    // limit is lifted here: the test is about size, not about the pace.
    let rate = RateConfig {
        ops_per_min: 1_000_000,
        ops_burst: 1_000_000,
        bytes_per_min: 1 << 40,
        ..RateConfig::DEFAULT
    };
    let world = World::on(TestApp::builder().rate(rate).build().await).await;
    let a = world.client("laptop").await;
    let vault = world.vault();

    // 100 batches. The manifest is a live row too, so 9 999 items fill a vault
    // of 10 000: 99 batches of 100 operations and a last one of 99.
    let started = Instant::now();
    let mut next: u16 = 1;
    let mut counter: u32 = 0;
    for batch in 0..100u32 {
        let size = if batch == 99 { 99 } else { 100 };
        let ops: Vec<Value> = (0..size)
            .map(|_| {
                let id = item(next);
                next += 1;
                counter += 1;
                as_op(id, &live_body(&vault, id, 0, "bulk", counter))
            })
            .collect();
        let results = batch_results(&a.post_batch(&ops).await).results;
        assert!(results.iter().all(|r| r.status == 200), "batch {batch}");
    }
    assert_eq!(next, 10_000);
    assert_eq!(world.server_seq().await, 10_000);
    println!("ten_thousand_items: 100 batches {:?}", started.elapsed());

    // The feed from 0, in pages of 500, checked row by row.
    let started = Instant::now();
    let mut b = world.client("phone").await;
    let report = b.pull().await;
    assert!(report.warnings.is_empty(), "{:?}", report.warnings);
    assert_eq!(b.live_items().len(), 9_999);
    assert_eq!(b.memory().tracked(), 10_000);
    assert_eq!(b.cursor(), 10_000);
    println!(
        "ten_thousand_items: /changes from 0 {:?}",
        started.elapsed()
    );

    // The full listing, in pages of 500.
    let started = Instant::now();
    let mut after: Option<[u8; 16]> = None;
    let (mut rows, mut pages) = (0usize, 0usize);
    loop {
        let mut uri = "/api/sync/items?limit=500".to_string();
        if let Some(id) = after {
            uri.push_str(&format!("&after={}", hex16::encode(&id)));
        }
        let res = a.send(Method::GET, &uri, None).await;
        assert_eq!(res.status, StatusCode::OK, "{}", res.text());
        let page: ItemsRes = serde_json::from_slice(&res.body).expect("a page");
        page.validate().expect("a valid page");
        assert_eq!(page.as_of_seq, 10_000);
        rows += page.items.len();
        pages += 1;
        if !page.has_more {
            break;
        }
        after = page.next_after;
    }
    assert_eq!((rows, pages), (10_000, 20));
    println!(
        "ten_thousand_items: listing {pages} pages {:?}",
        started.elapsed()
    );

    // A checkpoint of 10 000 entries, uploaded, read back and verified at the
    // top by another device.
    let started = Instant::now();
    let up = b.upload_checkpoint().await;
    assert_eq!(up.status, StatusCode::OK, "{}", up.text());
    assert_eq!(up.json(), json!({ "seq": 10_000 }));
    let stored = b.fetch_checkpoint().await.expect("a checkpoint");
    assert_eq!(stored.entries.len(), 10_000 * 56);
    assert_eq!(b.verify().await, Ok(()));
    let mut c = world.client("tablet").await;
    assert!(c.pull().await.warnings.is_empty());
    assert_eq!(c.verify().await, Ok(()));
    println!("ten_thousand_items: checkpoint {:?}", started.elapsed());

    // One more live row than a vault holds is refused.
    let over = a
        .put(
            item(10_000),
            &live_body(&vault, item(10_000), 0, "one too many", 99_999),
        )
        .await;
    assert_eq!(
        over.status,
        StatusCode::PAYLOAD_TOO_LARGE,
        "{}",
        over.text()
    );
    assert_eq!(error_code(&over), "quota_exceeded");
    assert_eq!(world.server_seq().await, 10_000);
}
