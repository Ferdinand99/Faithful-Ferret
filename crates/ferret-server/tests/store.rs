//! The vault store: item writes against a basis, idempotency, the changes feed,
//! quota, and the rows of a new account.

mod support;

use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Barrier};

use ferret_server::error::StoreError;
use ferret_server::ids::{AccountId, DeviceId, ItemId, MANIFEST_ITEM_ID, VaultId};
use ferret_server::product;
use ferret_server::vault::quota::Limits;
use ferret_server::vault::store::{
    Conflict, Purged, PutBody, PutOutcome, PutRequest, account_by_user, changes_since,
    create_account, methods_view, purge_tombstones, put_item,
};
use rusqlite::{Connection, params};
use support::accounts::{self, TestAccount, add_account, id16};
use vole_kit::db::migrate::apply_migrations;

const NOW: i64 = 1_793_491_200;

/// An in-memory database with every migration applied, foreign keys on as in
/// the pool.
fn migrated() -> Connection {
    product::install();
    let mut conn = Connection::open_in_memory().expect("open");
    conn.execute_batch("PRAGMA foreign_keys = ON;")
        .expect("pragma");
    apply_migrations(&mut conn).expect("migrations apply");
    conn
}

/// A database with one account (number 1).
fn with_account() -> (Connection, TestAccount) {
    let mut conn = migrated();
    let account = add_account(&mut conn, 1, NOW);
    (conn, account)
}

fn item(n: u8) -> ItemId {
    ItemId::from_bytes(id16(0x10, n))
}

fn hash(n: u8) -> [u8; 32] {
    [n; 32]
}

/// A write of a live item: `idem` and the request hash follow from `n`.
fn live<'a>(item_id: ItemId, base_rev: u64, blob: &'a [u8], n: u8) -> PutRequest<'a> {
    PutRequest {
        item_id,
        base_rev,
        body: PutBody::Live { blob, tag: [n; 32] },
        idem: id16(0xe0, n),
        request_hash: hash(n),
    }
}

fn tomb<'a>(item_id: ItemId, base_rev: u64, tomb: &'a [u8], n: u8) -> PutRequest<'a> {
    PutRequest {
        item_id,
        base_rev,
        body: PutBody::Deleted { tomb },
        idem: id16(0xe0, n),
        request_hash: hash(n),
    }
}

fn put(conn: &mut Connection, a: &TestAccount, req: &PutRequest<'_>) -> PutOutcome {
    put_at(conn, a, req, &Limits::DEFAULT, NOW)
}

fn put_at(
    conn: &mut Connection,
    a: &TestAccount,
    req: &PutRequest<'_>,
    limits: &Limits,
    now: i64,
) -> PutOutcome {
    put_item(conn, &a.vault_id, &a.device, req, limits, now).expect("put_item")
}

fn stored(outcome: &PutOutcome) -> (u64, u64) {
    match outcome {
        PutOutcome::Stored {
            rev,
            seq,
            replayed: false,
        } => (*rev, *seq),
        other => panic!("expected a fresh Stored, got {other:?}"),
    }
}

/// `deleted`, `blob`, `tag`, `tomb` and `size` of a row.
type TombRow = (i64, Option<Vec<u8>>, Option<Vec<u8>>, Option<Vec<u8>>, i64);

fn counters(conn: &Connection, a: &TestAccount) -> (i64, i64, i64) {
    conn.query_row(
        "SELECT seq, item_count, bytes_used FROM ferret_vaults WHERE vault_id = ?1",
        [a.vault_id.as_bytes()],
        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
    )
    .expect("the vault row")
}

fn idem_rows(conn: &Connection) -> i64 {
    conn.query_row("SELECT COUNT(*) FROM ferret_idem", [], |row| row.get(0))
        .expect("count")
}

#[test]
fn seq_comes_from_the_counter_row_and_is_never_reused() {
    let (mut conn, a) = with_account();
    // The account made seq 1 (the manifest).
    assert_eq!(counters(&conn, &a).0, 1);
    let first = put(&mut conn, &a, &live(item(1), 0, b"one", 1));
    let second = put(&mut conn, &a, &live(item(2), 0, b"two", 2));
    assert_eq!((stored(&first).1, stored(&second).1), (2, 3));

    // The row with the highest seq goes away (a purge): the counter goes on
    // from where it was, MAX(seq) + 1 would hand out 3 again.
    conn.execute(
        "DELETE FROM ferret_items WHERE vault_id = ?1 AND item_id = ?2",
        params![a.vault_id.as_bytes(), item(2).as_bytes()],
    )
    .expect("purge");
    let third = put(&mut conn, &a, &live(item(3), 0, b"three", 3));
    assert_eq!(stored(&third).1, 4);
    assert_eq!(counters(&conn, &a).0, 4);
}

#[test]
fn new_item_gets_rev_1_and_update_gets_base_rev_plus_1() {
    let (mut conn, a) = with_account();
    let created = put(&mut conn, &a, &live(item(1), 0, b"v1", 1));
    assert_eq!(stored(&created).0, 1);
    let updated = put(&mut conn, &a, &live(item(1), 1, b"v2", 2));
    assert_eq!(stored(&updated).0, 2);
    let again = put(&mut conn, &a, &live(item(1), 2, b"v3", 3));
    assert_eq!(stored(&again).0, 3);

    let page = changes_since(&conn, &a.vault_id, 0, 100, usize::MAX).expect("changes");
    let row = page
        .changes
        .iter()
        .find(|c| c.id == item(1))
        .expect("the item");
    assert_eq!(row.rev, 3);
    assert_eq!(row.blob.as_deref(), Some(&b"v3"[..]));
    assert_eq!(row.tag, Some([3; 32]));
}

#[test]
fn stale_or_ahead_base_rev_is_a_conflict_with_the_current_row() {
    let (mut conn, a) = with_account();
    put(&mut conn, &a, &live(item(1), 0, b"v1", 1));
    put(&mut conn, &a, &live(item(1), 1, b"v2", 2));
    let before = counters(&conn, &a);
    let idems = idem_rows(&conn);

    let current = Conflict {
        current_rev: 2,
        blob: Some(b"v2".to_vec()),
        tag: Some([2; 32]),
        deleted: false,
    };
    // Stale (1), "new" (0) and ahead (3, 99) are all refused with the row.
    for (base_rev, n) in [(1, 10), (0, 11), (3, 12), (99, 13)] {
        assert_eq!(
            put(&mut conn, &a, &live(item(1), base_rev, b"x", n)),
            PutOutcome::Conflict(current.clone()),
            "base_rev {base_rev}"
        );
    }
    // A basis for an item that does not exist is ahead too.
    assert_eq!(
        put(&mut conn, &a, &live(item(9), 4, b"x", 14)),
        PutOutcome::Conflict(Conflict {
            current_rev: 0,
            blob: None,
            tag: None,
            deleted: false,
        })
    );
    // A refusal changes nothing: not the counters, the row or the idem table.
    assert_eq!(counters(&conn, &a), before);
    assert_eq!(idem_rows(&conn), idems);
    let page = changes_since(&conn, &a.vault_id, 0, 100, usize::MAX).expect("changes");
    assert_eq!(page.changes.len(), 2);
}

#[test]
fn writes_to_different_items_never_conflict() {
    let (mut conn, a) = with_account();
    let one = put(&mut conn, &a, &live(item(1), 0, b"a", 1));
    let two = put(&mut conn, &a, &live(item(2), 0, b"b", 2));
    assert_eq!((stored(&one).0, stored(&two).0), (1, 1));
    // An update of one item does not need the revision of the other.
    let update = put(&mut conn, &a, &live(item(1), 1, b"a2", 3));
    assert_eq!(stored(&update).0, 2);
    let other = put(&mut conn, &a, &live(item(2), 1, b"b2", 4));
    assert_eq!(stored(&other).0, 2);
}

#[test]
fn idem_is_checked_before_base_rev() {
    let (mut conn, a) = with_account();
    let first = put(&mut conn, &a, &live(item(1), 0, b"v1", 1));
    let (rev, seq) = stored(&first);
    // A later write moves the row on: base_rev 0 is stale now.
    put(&mut conn, &a, &live(item(1), 1, b"v2", 2));
    let before = counters(&conn, &a);

    // The first write again (a lost answer): the original answer, no conflict.
    assert_eq!(
        put(&mut conn, &a, &live(item(1), 0, b"v1", 1)),
        PutOutcome::Stored {
            rev,
            seq,
            replayed: true
        }
    );
    assert_eq!(counters(&conn, &a), before);
}

#[test]
fn a_replayed_delete_gives_the_original_answer() {
    let (mut conn, a) = with_account();
    put(&mut conn, &a, &live(item(1), 0, b"v1", 1));
    let deleted = put(&mut conn, &a, &tomb(item(1), 1, b"gone", 2));
    let (rev, seq) = stored(&deleted);
    assert_eq!(
        put(&mut conn, &a, &tomb(item(1), 1, b"gone", 2)),
        PutOutcome::Stored {
            rev,
            seq,
            replayed: true
        }
    );
}

#[test]
fn same_idem_other_request_hash_is_a_mismatch() {
    let (mut conn, a) = with_account();
    put(&mut conn, &a, &live(item(1), 0, b"v1", 1));
    let before = counters(&conn, &a);
    // The idem of write 1, another request hash.
    let mut other = live(item(2), 0, b"other", 1);
    other.request_hash = hash(0x99);
    assert_eq!(put(&mut conn, &a, &other), PutOutcome::IdemMismatch);
    assert_eq!(counters(&conn, &a), before);
    assert_eq!(
        changes_since(&conn, &a.vault_id, 0, 100, usize::MAX)
            .expect("changes")
            .changes
            .len(),
        2,
        "the manifest and the first item"
    );
}

#[test]
fn idem_is_scoped_to_vault_and_device() {
    let mut conn = migrated();
    let a = add_account(&mut conn, 1, NOW);
    let b = add_account(&mut conn, 2, NOW);
    let other_device = DeviceId(id16(0xd9, 1));

    let req = live(item(1), 0, b"v1", 7);
    let first = put(&mut conn, &a, &req);
    assert!(matches!(
        first,
        PutOutcome::Stored {
            replayed: false,
            ..
        }
    ));

    // The same idem and request from another vault, by the same device: a
    // write of its own (not a replay and not a mismatch). A lookup that ignored
    // the vault would find the record of the first write here.
    let other_vault = put_item(
        &mut conn,
        &b.vault_id,
        &a.device,
        &req,
        &Limits::DEFAULT,
        NOW,
    )
    .expect("put_item");
    assert!(matches!(
        other_vault,
        PutOutcome::Stored {
            rev: 1,
            replayed: false,
            ..
        }
    ));

    // From another device of the same vault: the item exists now, so this is a
    // conflict with the row, and it is not read as a replay.
    let device_write = put_item(
        &mut conn,
        &a.vault_id,
        &other_device,
        &req,
        &Limits::DEFAULT,
        NOW,
    )
    .expect("put_item");
    assert!(
        matches!(device_write, PutOutcome::Conflict(_)),
        "{device_write:?}"
    );
    // With a basis that fits it is stored, and the table holds both records.
    let fresh = put_item(
        &mut conn,
        &a.vault_id,
        &other_device,
        &live(item(1), 1, b"v2", 7),
        &Limits::DEFAULT,
        NOW,
    )
    .expect("put_item");
    assert!(matches!(
        fresh,
        PutOutcome::Stored {
            rev: 2,
            replayed: false,
            ..
        }
    ));
    assert_eq!(idem_rows(&conn), 3);
}

#[test]
fn old_idem_records_can_be_purged() {
    let (mut conn, a) = with_account();
    put_at(
        &mut conn,
        &a,
        &live(item(1), 0, b"v1", 1),
        &Limits::DEFAULT,
        100,
    );
    put_at(
        &mut conn,
        &a,
        &live(item(2), 0, b"v1", 2),
        &Limits::DEFAULT,
        200,
    );
    assert_eq!(
        ferret_server::vault::idem::purge_before(&conn, 150).expect("purge"),
        1
    );
    assert_eq!(idem_rows(&conn), 1);
}

#[test]
fn delete_stores_tomb_and_clears_blob() {
    let (mut conn, a) = with_account();
    put(&mut conn, &a, &live(item(1), 0, b"secret envelope", 1));
    let deleted = put(&mut conn, &a, &tomb(item(1), 1, b"tombstone", 2));
    assert_eq!(stored(&deleted).0, 2);

    let (flag, blob, tag, tomb, size): TombRow = conn
        .query_row(
            "SELECT deleted, blob, tag, tomb, size FROM ferret_items \
             WHERE vault_id = ?1 AND item_id = ?2",
            params![a.vault_id.as_bytes(), item(1).as_bytes()],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                ))
            },
        )
        .expect("the row");
    assert_eq!(flag, 1);
    assert_eq!((blob, tag), (None, None));
    assert_eq!(tomb.as_deref(), Some(&b"tombstone"[..]));
    assert_eq!(size, 9);

    let page = changes_since(&conn, &a.vault_id, 1, 100, usize::MAX).expect("changes");
    let change = page.changes.last().expect("a change");
    assert!(change.deleted);
    assert_eq!(change.tomb.as_deref(), Some(&b"tombstone"[..]));
    assert!(change.blob.is_none() && change.tag.is_none());
}

#[test]
fn put_on_a_deleted_item_conflicts_with_deleted_true() {
    let (mut conn, a) = with_account();
    put(&mut conn, &a, &live(item(1), 0, b"v1", 1));
    put(&mut conn, &a, &tomb(item(1), 1, b"gone", 2));
    let before = counters(&conn, &a);
    let expected = PutOutcome::Conflict(Conflict {
        current_rev: 2,
        blob: None,
        tag: None,
        deleted: true,
    });
    // With the matching basis, with a stale one, and a second delete.
    assert_eq!(put(&mut conn, &a, &live(item(1), 2, b"back", 3)), expected);
    assert_eq!(put(&mut conn, &a, &live(item(1), 1, b"back", 4)), expected);
    assert_eq!(put(&mut conn, &a, &tomb(item(1), 2, b"again", 5)), expected);
    assert_eq!(counters(&conn, &a), before);
}

#[test]
fn check_constraints_reject_blob_on_tombstone_and_tombstone_without_tomb() {
    let (conn, a) = with_account();
    let insert = |deleted: i64,
                  blob: Option<&[u8]>,
                  tag: Option<&[u8]>,
                  tomb: Option<&[u8]>,
                  item_id: [u8; 16]| {
        conn.execute(
            "INSERT INTO ferret_items \
               (vault_id, item_id, rev, seq, deleted, blob, tag, tomb, size, changed_at) \
             VALUES (?1, ?2, 1, 9, ?3, ?4, ?5, ?6, 1, 0)",
            params![a.vault_id.as_bytes(), item_id, deleted, blob, tag, tomb],
        )
    };
    let tag = [1u8; 32];
    // A tombstone with a blob, a tombstone with a tag, a tombstone without a
    // tomb, a live row with a tomb, a live row without a tag or with a short
    // one, and a live row without a blob.
    assert!(insert(1, Some(b"x"), None, Some(b"t"), id16(1, 1)).is_err());
    assert!(insert(1, None, Some(&tag), Some(b"t"), id16(1, 2)).is_err());
    assert!(insert(1, None, None, None, id16(1, 3)).is_err());
    assert!(insert(0, Some(b"x"), Some(&tag), Some(b"t"), id16(1, 4)).is_err());
    assert!(insert(0, Some(b"x"), None, None, id16(1, 5)).is_err());
    assert!(insert(0, Some(b"x"), Some(&tag[..31]), None, id16(1, 6)).is_err());
    assert!(insert(0, None, Some(&tag), None, id16(1, 7)).is_err());
    // The two valid shapes go in.
    assert!(insert(0, Some(b"x"), Some(&tag), None, id16(1, 8)).is_ok());
    assert!(insert(1, None, None, Some(b"t"), id16(1, 9)).is_ok());
}

#[test]
fn zero_changed_rows_is_a_refusal_and_undoes_the_counter() {
    // A trigger that swallows the write stands in for a row that is not what
    // it was when the store read it: the statement reports no changed row.
    for (event, existing) in [("UPDATE", true), ("INSERT", false)] {
        let (mut conn, a) = with_account();
        if existing {
            put(&mut conn, &a, &live(item(1), 0, b"v1", 1));
        }
        let before = counters(&conn, &a);
        let idems = idem_rows(&conn);
        conn.execute_batch(&format!(
            "CREATE TRIGGER swallow BEFORE {event} ON ferret_items              BEGIN SELECT RAISE(IGNORE); END;"
        ))
        .expect("trigger");
        let (base_rev, id) = if existing { (1, item(1)) } else { (0, item(2)) };
        let outcome = put(&mut conn, &a, &live(id, base_rev, b"v2", 2));
        assert!(
            matches!(outcome, PutOutcome::Conflict(_)),
            "{event}: {outcome:?}"
        );
        assert_eq!(counters(&conn, &a), before, "{event}");
        assert_eq!(idem_rows(&conn), idems, "{event}");
    }
}

#[test]
fn changes_since_orders_by_seq_and_sets_has_more() {
    let (mut conn, a) = with_account();
    for n in 1..=5u8 {
        put(&mut conn, &a, &live(item(n), 0, b"row", n));
    }
    // Rewrite item 2: it moves to the end of the feed.
    put(&mut conn, &a, &live(item(2), 1, b"row2", 20));

    let all = changes_since(&conn, &a.vault_id, 0, 100, usize::MAX).expect("changes");
    let seqs: Vec<u64> = all.changes.iter().map(|c| c.seq).collect();
    assert_eq!(seqs, vec![1, 2, 4, 5, 6, 7]);
    assert_eq!(all.changes[0].id, MANIFEST_ITEM_ID);
    assert_eq!(all.changes.last().expect("last").id, item(2));
    assert_eq!(all.latest_seq, 7);
    assert_eq!((all.vk_epoch, all.restore_epoch), (1, 0));
    assert!(!all.has_more);

    let page = changes_since(&conn, &a.vault_id, 0, 2, usize::MAX).expect("changes");
    assert_eq!(page.changes.len(), 2);
    assert!(page.has_more);
    assert_eq!(page.latest_seq, 7);
    // The next page starts after the last seq of this one.
    let last = page.changes.last().expect("last").seq;
    let rest = changes_since(&conn, &a.vault_id, last, 100, usize::MAX).expect("changes");
    assert_eq!(rest.changes.len(), 4);
    assert!(!rest.has_more);
    // Exactly `limit` rows left is not "more".
    let exact = changes_since(&conn, &a.vault_id, last, 4, usize::MAX).expect("changes");
    assert_eq!(exact.changes.len(), 4);
    assert!(!exact.has_more);
    // Nothing after the counter.
    let none = changes_since(&conn, &a.vault_id, 7, 100, usize::MAX).expect("changes");
    assert!(none.changes.is_empty() && !none.has_more);
}

#[test]
fn changes_stop_before_max_bytes_but_return_at_least_one_row() {
    let (mut conn, a) = with_account();
    for n in 1..=3u8 {
        put(&mut conn, &a, &live(item(n), 0, &[n; 100], n));
    }
    // The manifest is 40 bytes, each item 100: 40 + 100 fits 150, a third row
    // would not.
    let page = changes_since(&conn, &a.vault_id, 0, 100, 150).expect("changes");
    assert_eq!(page.changes.len(), 2);
    assert!(page.has_more);
    // A limit below the first row still gives that row, and the rest follows.
    let one = changes_since(&conn, &a.vault_id, 1, 100, 10).expect("changes");
    assert_eq!(one.changes.len(), 1);
    assert_eq!(one.changes[0].id, item(1));
    assert!(one.has_more);
    let mut since = 0;
    let mut seen = 0;
    loop {
        let page = changes_since(&conn, &a.vault_id, since, 100, 1).expect("changes");
        seen += page.changes.len();
        since = page.changes.last().expect("a row per page").seq;
        if !page.has_more {
            break;
        }
    }
    assert_eq!(seen, 4);
}

#[test]
fn quota_stops_at_max_items_and_max_bytes() {
    // Live rows: the manifest (40 bytes) counts as one of three.
    let limits = Limits {
        max_envelope: 100,
        max_items: 3,
        max_tombstones: 100,
        max_bytes: 1000,
    };
    let (mut conn, a) = with_account();
    let ok1 = put_at(&mut conn, &a, &live(item(1), 0, b"a", 1), &limits, NOW);
    let ok2 = put_at(&mut conn, &a, &live(item(2), 0, b"b", 2), &limits, NOW);
    assert_eq!((stored(&ok1).0, stored(&ok2).0), (1, 1));
    let before = counters(&conn, &a);
    assert_eq!(before.1, 3);
    // A fourth live row is refused; an update of an existing one is not.
    let idems = idem_rows(&conn);
    assert_eq!(
        put_at(&mut conn, &a, &live(item(3), 0, b"c", 3), &limits, NOW),
        PutOutcome::QuotaExceeded
    );
    assert_eq!(counters(&conn, &a), before);
    assert_eq!(idem_rows(&conn), idems, "a refusal records nothing");
    let update = put_at(&mut conn, &a, &live(item(1), 1, b"a2", 4), &limits, NOW);
    assert_eq!(stored(&update).0, 2);
    // A deletion frees the slot of a live row: the refused write fits now.
    put_at(&mut conn, &a, &tomb(item(2), 1, b"t", 5), &limits, NOW);
    assert_eq!(counters(&conn, &a).1, 2);
    stored(&put_at(
        &mut conn,
        &a,
        &live(item(3), 0, b"c", 3),
        &limits,
        NOW,
    ));
    assert_eq!(
        put_at(&mut conn, &a, &live(item(4), 0, b"d", 6), &limits, NOW),
        PutOutcome::QuotaExceeded
    );

    // Bytes: the manifest has 40, so 60 more fit exactly.
    let limits = Limits {
        max_envelope: 100,
        max_items: 100,
        max_tombstones: 100,
        max_bytes: 100,
    };
    let (mut conn, a) = with_account();
    stored(&put_at(
        &mut conn,
        &a,
        &live(item(1), 0, &[1; 30], 1),
        &limits,
        NOW,
    ));
    stored(&put_at(
        &mut conn,
        &a,
        &live(item(2), 0, &[2; 30], 2),
        &limits,
        NOW,
    ));
    assert_eq!(counters(&conn, &a).2, 100);
    let before = counters(&conn, &a);
    assert_eq!(
        put_at(&mut conn, &a, &live(item(3), 0, &[3; 1], 3), &limits, NOW),
        PutOutcome::QuotaExceeded
    );
    // Growing an item is a byte question too; the refused write left no trace.
    assert_eq!(
        put_at(&mut conn, &a, &live(item(1), 1, &[4; 31], 4), &limits, NOW),
        PutOutcome::QuotaExceeded
    );
    assert_eq!(counters(&conn, &a), before);
    // Shrinking frees bytes, and then the same write that was refused fits.
    stored(&put_at(
        &mut conn,
        &a,
        &live(item(1), 1, &[5; 10], 5),
        &limits,
        NOW,
    ));
    assert_eq!(counters(&conn, &a).2, 80);
    stored(&put_at(
        &mut conn,
        &a,
        &live(item(3), 0, &[3; 1], 3),
        &limits,
        NOW,
    ));

    // An envelope above the limit is refused whatever the vault holds.
    let limits = Limits {
        max_envelope: 10,
        ..Limits::DEFAULT
    };
    let (mut conn, a) = with_account();
    assert_eq!(
        put_at(&mut conn, &a, &live(item(1), 0, &[0; 11], 1), &limits, NOW),
        PutOutcome::QuotaExceeded
    );
    stored(&put_at(
        &mut conn,
        &a,
        &live(item(1), 0, &[0; 10], 1),
        &limits,
        NOW,
    ));
}

#[test]
fn quota_counts_tombstone_sizes_and_the_vault_may_shrink_when_over_a_lowered_limit() {
    let (mut conn, a) = with_account();
    put(&mut conn, &a, &live(item(1), 0, &[1; 50], 1));
    assert_eq!(counters(&conn, &a).2, 90);
    put(&mut conn, &a, &tomb(item(1), 1, &[2; 8], 2));
    assert_eq!(counters(&conn, &a).2, 48);

    // The limit is lowered below what the vault holds: writes that grow are
    // refused, writes that shrink go through.
    let low = Limits {
        max_bytes: 30,
        ..Limits::DEFAULT
    };
    assert_eq!(
        put_at(&mut conn, &a, &live(item(2), 0, b"x", 3), &low, NOW),
        PutOutcome::QuotaExceeded
    );
    put(&mut conn, &a, &live(item(3), 0, &[3; 20], 4));
    let shrink = put_at(&mut conn, &a, &live(item(3), 1, &[3; 5], 5), &low, NOW);
    assert_eq!(stored(&shrink).0, 2);
}

#[test]
fn create_account_is_atomic() {
    let mut conn = migrated();
    let user_id = accounts::insert_user(&conn, "atomic@example.com");
    // The checkpoint is the last row written; make it fail.
    conn.execute_batch(
        "CREATE TRIGGER fail_checkpoint BEFORE INSERT ON ferret_checkpoints \
         BEGIN SELECT RAISE(ABORT, 'no checkpoint'); END;",
    )
    .expect("trigger");

    let tx = conn.transaction().expect("transaction");
    let result = create_account(&tx, &accounts::rows(user_id, 1, NOW));
    assert!(result.is_err());
    // Even if the caller goes on with the transaction and commits, nothing of
    // the failed account is in it.
    tx.commit().expect("commit");
    for table in [
        "ferret_accounts",
        "ferret_unlock_methods",
        "ferret_vaults",
        "ferret_items",
        "ferret_checkpoints",
    ] {
        let rows: i64 = conn
            .query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |r| r.get(0))
            .expect("count");
        assert_eq!(rows, 0, "{table}");
    }

    // Without the trigger the same rows go in.
    conn.execute_batch("DROP TRIGGER fail_checkpoint;")
        .expect("drop");
    let tx = conn.transaction().expect("transaction");
    create_account(&tx, &accounts::rows(user_id, 1, NOW)).expect("create_account");
    tx.commit().expect("commit");
    // A second account for the same user is refused (UNIQUE) and the first
    // stays whole.
    let tx = conn.transaction().expect("transaction");
    assert!(create_account(&tx, &accounts::rows(user_id, 2, NOW)).is_err());
    tx.commit().expect("commit");
    let accounts_left: i64 = conn
        .query_row("SELECT COUNT(*) FROM ferret_accounts", [], |r| r.get(0))
        .expect("count");
    assert_eq!(accounts_left, 1);
    let vaults_left: i64 = conn
        .query_row("SELECT COUNT(*) FROM ferret_vaults", [], |r| r.get(0))
        .expect("count");
    assert_eq!(vaults_left, 1);
}

#[test]
fn manifest_row_is_an_ordinary_row_with_zero_id() {
    let (mut conn, a) = with_account();
    let page = changes_since(&conn, &a.vault_id, 0, 100, usize::MAX).expect("changes");
    assert_eq!(page.changes.len(), 1);
    let manifest = &page.changes[0];
    assert_eq!(manifest.id.as_bytes(), &[0u8; 16]);
    assert_eq!(
        (manifest.rev, manifest.seq, manifest.deleted),
        (1, 1, false)
    );
    assert_eq!(manifest.blob.as_deref(), Some(&[0x4d; 40][..]));
    assert_eq!(manifest.tag, Some([0x7a; 32]));
    assert!(manifest.tomb.is_none());

    // The item write path never touches it: not with a live body, not with a
    // tombstone, whatever the basis. Nothing is written and nothing recorded.
    let before = counters(&conn, &a);
    for (n, req) in [
        live(MANIFEST_ITEM_ID, 1, b"manifest 2", 1),
        live(MANIFEST_ITEM_ID, 0, b"manifest 2", 2),
        tomb(MANIFEST_ITEM_ID, 1, b"gone", 3),
        tomb(MANIFEST_ITEM_ID, 0, b"gone", 4),
    ]
    .iter()
    .enumerate()
    {
        assert_eq!(
            put(&mut conn, &a, req),
            PutOutcome::ManifestNotWritable,
            "request {n}"
        );
    }
    assert_eq!(counters(&conn, &a), before);
    assert_eq!(idem_rows(&conn), 0);
    let page = changes_since(&conn, &a.vault_id, 0, 100, usize::MAX).expect("changes");
    assert_eq!(page.changes, vec![manifest.clone()]);
}

#[test]
fn a_replay_cannot_reach_the_manifest_either() {
    // The refusal comes before the idempotency lookup, so an idem that was
    // recorded for another item cannot turn into an answer for the manifest.
    let (mut conn, a) = with_account();
    put(&mut conn, &a, &live(item(1), 0, b"v1", 1));
    assert_eq!(
        put(&mut conn, &a, &live(MANIFEST_ITEM_ID, 0, b"v1", 1)),
        PutOutcome::ManifestNotWritable
    );
}

#[test]
fn vault_seq_is_1_after_create_account() {
    let (conn, a) = with_account();
    let (seq, item_count, bytes_used) = counters(&conn, &a);
    assert_eq!((seq, item_count, bytes_used), (1, 1, 40));
    let (restore, min_valid): (i64, i64) = conn
        .query_row(
            "SELECT restore_epoch, min_valid_since FROM ferret_vaults WHERE vault_id = ?1",
            [a.vault_id.as_bytes()],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .expect("vault");
    assert_eq!((restore, min_valid), (0, 0));
    let (cp_seq, digest, mac, entries): (i64, Vec<u8>, Vec<u8>, Vec<u8>) = conn
        .query_row(
            "SELECT seq, digest, mac, entries FROM ferret_checkpoints WHERE vault_id = ?1",
            [a.vault_id.as_bytes()],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
        )
        .expect("checkpoint");
    assert_eq!(cp_seq, 1);
    assert_eq!(
        (digest, mac, entries),
        (vec![0x41; 32], vec![0x42; 32], vec![0x43; 20])
    );
}

#[test]
fn changed_at_comes_from_the_injected_clock_and_is_set_on_every_write() {
    let (mut conn, a) = with_account();
    let changed_at = |conn: &Connection, id: ItemId| -> i64 {
        conn.query_row(
            "SELECT changed_at FROM ferret_items WHERE vault_id = ?1 AND item_id = ?2",
            params![a.vault_id.as_bytes(), id.as_bytes()],
            |r| r.get(0),
        )
        .expect("changed_at")
    };
    assert_eq!(changed_at(&conn, MANIFEST_ITEM_ID), NOW);
    let limits = Limits::DEFAULT;
    put_at(&mut conn, &a, &live(item(1), 0, b"v1", 1), &limits, 1000);
    assert_eq!(changed_at(&conn, item(1)), 1000);
    put_at(&mut conn, &a, &live(item(1), 1, b"v2", 2), &limits, 2000);
    assert_eq!(changed_at(&conn, item(1)), 2000);
    put_at(&mut conn, &a, &tomb(item(1), 2, b"t", 3), &limits, 3000);
    assert_eq!(changed_at(&conn, item(1)), 3000);
    // A replay writes nothing.
    put_at(&mut conn, &a, &tomb(item(1), 2, b"t", 3), &limits, 4000);
    assert_eq!(changed_at(&conn, item(1)), 3000);
    // The idempotency record has the time of the write.
    let created: i64 = conn
        .query_row(
            "SELECT created_at FROM ferret_idem WHERE idem = ?1",
            [id16(0xe0, 3)],
            |r| r.get(0),
        )
        .expect("idem");
    assert_eq!(created, 3000);
}

#[test]
fn methods_view_and_account_by_user_read_what_create_account_wrote() {
    let (mut conn, a) = with_account();
    put(&mut conn, &a, &live(item(1), 0, b"v1", 1));

    let view = methods_view(&conn, &a.account_id).expect("view");
    assert_eq!(view.methods.len(), 2);
    assert_eq!(view.methods[0].method_type, 1);
    assert_eq!(view.methods[1].method_type, 2);
    assert_eq!(view.methods[0].wrap, vec![0x31; 60]);
    assert_eq!(view.methods[0].kek_generation, 1);
    assert_eq!(view.pk_a, [0x11; 32]);
    assert_eq!(view.vk_epoch, 1);
    assert_eq!(view.manifest.id, MANIFEST_ITEM_ID);
    assert_eq!((view.manifest.rev, view.manifest.seq), (1, 1));

    let account = account_by_user(&conn, a.user_id)
        .expect("lookup")
        .expect("an account");
    assert_eq!(account.account_id, a.account_id);
    assert_eq!(account.vault_id, a.vault_id);
    assert_eq!(account.user_id, a.user_id);
    assert!(account.sk_hint);
    assert_eq!((account.pk_a, account.pk_r), ([0x11; 32], [0x22; 32]));
    assert_eq!(account.vk_epoch, 1);
    assert_eq!(account.created_at, NOW);
    assert_eq!(
        account.record.record.as_bytes(),
        accounts::stored_record().record.as_bytes()
    );
    assert_eq!(
        account.record.ksf_profile,
        accounts::stored_record().ksf_profile
    );

    assert!(
        account_by_user(&conn, a.user_id + 100)
            .expect("lookup")
            .is_none()
    );
}

#[test]
fn unknown_vaults_are_errors_not_empty_answers() {
    let (mut conn, a) = with_account();
    let ghost = VaultId::from_bytes([7; 16]);
    assert!(matches!(
        changes_since(&conn, &ghost, 0, 10, usize::MAX),
        Err(StoreError::NotFound)
    ));
    // Whatever the basis: a basis other than 0 is not read as a conflict.
    for base_rev in [0, 3] {
        let req = live(item(1), base_rev, b"x", 1);
        assert!(matches!(
            put_item(&mut conn, &ghost, &a.device, &req, &Limits::DEFAULT, NOW),
            Err(StoreError::NotFound)
        ));
    }
    assert!(matches!(
        methods_view(&conn, &AccountId::from_bytes([9; 16])),
        Err(StoreError::NotFound)
    ));
    assert!(matches!(
        purge_tombstones(&mut conn, &ghost, i64::MAX),
        Err(StoreError::NotFound)
    ));
    // Nothing was left behind.
    assert_eq!(idem_rows(&conn), 0);
}

#[test]
fn debug_output_shows_no_envelope_bytes() {
    let (mut conn, a) = with_account();
    let blob = b"SENTINEL-ENVELOPE";
    let req = live(item(1), 0, blob, 1);
    assert!(!format!("{req:?}").contains("SENTINEL"));
    put(&mut conn, &a, &req);
    let conflict = put(&mut conn, &a, &live(item(1), 0, blob, 2));
    assert!(!format!("{conflict:?}").contains("SENTINEL"));
    let page = changes_since(&conn, &a.vault_id, 0, 10, usize::MAX).expect("changes");
    assert!(!format!("{page:?}").contains("SENTINEL"));
    assert!(!format!("{:?}", page.changes).contains("SENTINEL"));
    let view = methods_view(&conn, &a.account_id).expect("view");
    assert!(!format!("{view:?}").contains("SENTINEL"));
    let account = account_by_user(&conn, a.user_id).expect("l").expect("a");
    let shown = format!("{account:?}");
    assert!(shown.contains("AccountRow"));
    // Nothing of the OPAQUE record shows, as bytes or as hex.
    let record = account.record.record.as_bytes();
    let hex: String = record[..16].iter().map(|b| format!("{b:02x}")).collect();
    assert!(!shown.contains(&hex) && !shown.contains(&format!("{:?}", &record[..16])));
}

/// The counters of a vault equal what its rows add up to.
fn assert_counters_match_rows(conn: &Connection, a: &TestAccount) {
    let (live, bytes): (i64, i64) = conn
        .query_row(
            "SELECT COALESCE(SUM(deleted = 0), 0), COALESCE(SUM(size), 0) FROM ferret_items \
             WHERE vault_id = ?1",
            [a.vault_id.as_bytes()],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .expect("sums");
    let (_, item_count, bytes_used) = counters(conn, a);
    assert_eq!((item_count, bytes_used), (live, bytes));
}

#[test]
fn tombstones_have_a_cap_of_their_own() {
    let limits = Limits {
        max_tombstones: 2,
        ..Limits::DEFAULT
    };
    let (mut conn, a) = with_account();
    for n in 1..=3u8 {
        stored(&put_at(
            &mut conn,
            &a,
            &live(item(n), 0, b"row", n),
            &limits,
            NOW,
        ));
    }
    stored(&put_at(
        &mut conn,
        &a,
        &tomb(item(1), 1, b"t", 11),
        &limits,
        NOW,
    ));
    stored(&put_at(
        &mut conn,
        &a,
        &tomb(item(2), 1, b"t", 12),
        &limits,
        NOW,
    ));
    let before = counters(&conn, &a);
    let idems = idem_rows(&conn);
    // A third tombstone is refused: from a live row and from no row at all.
    assert_eq!(
        put_at(&mut conn, &a, &tomb(item(3), 1, b"t", 13), &limits, NOW),
        PutOutcome::QuotaExceeded
    );
    assert_eq!(
        put_at(&mut conn, &a, &tomb(item(9), 0, b"t", 14), &limits, NOW),
        PutOutcome::QuotaExceeded
    );
    assert_eq!(counters(&conn, &a), before);
    assert_eq!(idem_rows(&conn), idems);
    // Live writes are not affected, and a purge makes room again.
    stored(&put_at(
        &mut conn,
        &a,
        &live(item(3), 1, b"row2", 15),
        &limits,
        NOW,
    ));
    purge_tombstones(&mut conn, &a.vault_id, NOW + 1).expect("purge");
    stored(&put_at(
        &mut conn,
        &a,
        &tomb(item(3), 2, b"t", 13),
        &limits,
        NOW,
    ));
    assert_counters_match_rows(&conn, &a);
}

#[test]
fn deleting_and_recreating_items_does_not_exhaust_max_items() {
    // The churn the quota must allow: import, delete everything, import again.
    let limits = Limits {
        max_items: 4,
        ..Limits::DEFAULT
    };
    let (mut conn, a) = with_account();
    for n in 1..=3u8 {
        stored(&put_at(
            &mut conn,
            &a,
            &live(item(n), 0, b"row", n),
            &limits,
            NOW,
        ));
    }
    assert_eq!(
        put_at(&mut conn, &a, &live(item(4), 0, b"row", 4), &limits, NOW),
        PutOutcome::QuotaExceeded
    );
    for n in 1..=3u8 {
        stored(&put_at(
            &mut conn,
            &a,
            &tomb(item(n), 1, b"t", 20 + n),
            &limits,
            NOW,
        ));
    }
    assert_eq!(counters(&conn, &a).1, 1, "only the manifest is live");
    for n in 4..=6u8 {
        stored(&put_at(
            &mut conn,
            &a,
            &live(item(n), 0, b"row", n),
            &limits,
            NOW,
        ));
    }
    assert_counters_match_rows(&conn, &a);
}

#[test]
fn counters_equal_the_rows_after_a_mixed_sequence() {
    let (mut conn, a) = with_account();
    let limits = Limits::DEFAULT;
    assert_counters_match_rows(&conn, &a);
    put_at(&mut conn, &a, &live(item(1), 0, &[1; 30], 1), &limits, 100);
    put_at(&mut conn, &a, &live(item(2), 0, &[2; 12], 2), &limits, 200);
    put_at(&mut conn, &a, &live(item(1), 1, &[3; 50], 3), &limits, 300);
    put_at(&mut conn, &a, &tomb(item(1), 2, &[4; 9], 4), &limits, 400);
    put_at(&mut conn, &a, &tomb(item(7), 0, &[5; 9], 5), &limits, 500);
    put_at(&mut conn, &a, &live(item(3), 0, &[6; 20], 6), &limits, 600);
    assert_counters_match_rows(&conn, &a);
    purge_tombstones(&mut conn, &a.vault_id, 450).expect("purge");
    assert_counters_match_rows(&conn, &a);
    purge_tombstones(&mut conn, &a.vault_id, 1000).expect("purge");
    assert_counters_match_rows(&conn, &a);
    assert_eq!(counters(&conn, &a).1, 3, "the manifest and two live items");
}

#[test]
fn purging_tombstones_moves_the_counters_in_one_transaction() {
    let (mut conn, a) = with_account();
    let limits = Limits::DEFAULT;
    put_at(&mut conn, &a, &live(item(1), 0, &[1; 30], 1), &limits, 100); // seq 2
    put_at(&mut conn, &a, &live(item(2), 0, &[2; 30], 2), &limits, 100); // seq 3
    put_at(&mut conn, &a, &live(item(3), 0, &[3; 30], 3), &limits, 100); // seq 4
    put_at(&mut conn, &a, &tomb(item(1), 1, &[4; 8], 4), &limits, 200); // seq 5
    put_at(&mut conn, &a, &tomb(item(2), 1, &[5; 6], 5), &limits, 300); // seq 6
    assert_eq!(counters(&conn, &a), (6, 2, 40 + 30 + 8 + 6));

    // Only the tombstone older than 250 goes.
    let purged = purge_tombstones(&mut conn, &a.vault_id, 250).expect("purge");
    assert_eq!(
        purged,
        Purged {
            removed: 1,
            min_valid_since: 5
        }
    );
    // `seq` and the live count stay, the bytes of the removed row go.
    assert_eq!(counters(&conn, &a), (6, 2, 40 + 30 + 6));
    assert_counters_match_rows(&conn, &a);

    // Nothing to purge: nothing moves, and the horizon never falls.
    let none = purge_tombstones(&mut conn, &a.vault_id, 250).expect("purge");
    assert_eq!((none.removed, none.min_valid_since), (0, 5));

    let rest = purge_tombstones(&mut conn, &a.vault_id, 1000).expect("purge");
    assert_eq!((rest.removed, rest.min_valid_since), (1, 6));
    assert_eq!(counters(&conn, &a), (6, 2, 40 + 30));
    // Live rows were not touched (the manifest and item 3 remain).
    let page = changes_since(&conn, &a.vault_id, 0, 100, usize::MAX).expect("changes");
    assert_eq!(page.changes.len(), 2);
    let horizon: i64 = conn
        .query_row(
            "SELECT min_valid_since FROM ferret_vaults WHERE vault_id = ?1",
            [a.vault_id.as_bytes()],
            |r| r.get(0),
        )
        .expect("horizon");
    assert_eq!(horizon, 6);
}

#[test]
fn a_purge_leaves_other_vaults_alone() {
    let mut conn = migrated();
    let a = add_account(&mut conn, 1, NOW);
    let b = add_account(&mut conn, 2, NOW);
    for who in [&a, &b] {
        put(&mut conn, who, &live(item(1), 0, b"v1", 1));
        put(&mut conn, who, &tomb(item(1), 1, b"t", 2));
    }
    assert_eq!(
        purge_tombstones(&mut conn, &a.vault_id, i64::MAX)
            .expect("purge")
            .removed,
        1
    );
    assert_counters_match_rows(&conn, &a);
    assert_counters_match_rows(&conn, &b);
    let b_rows: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM ferret_items WHERE vault_id = ?1 AND deleted = 1",
            [b.vault_id.as_bytes()],
            |r| r.get(0),
        )
        .expect("count");
    assert_eq!(b_rows, 1);
}

#[test]
fn a_limit_of_zero_is_read_as_one_so_paging_advances() {
    let (mut conn, a) = with_account();
    put(&mut conn, &a, &live(item(1), 0, b"v1", 1));
    let page = changes_since(&conn, &a.vault_id, 0, 0, usize::MAX).expect("changes");
    assert_eq!(page.changes.len(), 1);
    assert!(page.has_more);
}

#[test]
fn create_account_needs_the_first_manifest_and_checkpoint_numbers() {
    let mut conn = migrated();
    let user_id = accounts::insert_user(&conn, "first@example.com");
    for (manifest_rev, checkpoint_seq) in [(0, 1), (2, 1), (1, 0), (1, 2)] {
        let mut rows = accounts::rows(user_id, 1, NOW);
        rows.manifest.rev = manifest_rev;
        rows.checkpoint.seq = checkpoint_seq;
        let tx = conn.transaction().expect("transaction");
        assert!(
            matches!(create_account(&tx, &rows), Err(StoreError::Invalid(_))),
            "rev {manifest_rev}, seq {checkpoint_seq}"
        );
        tx.commit().expect("commit");
    }
    let left: i64 = conn
        .query_row("SELECT COUNT(*) FROM ferret_accounts", [], |r| r.get(0))
        .expect("count");
    assert_eq!(left, 0);
}

#[test]
fn deleting_an_item_the_server_does_not_have_stores_a_tombstone_at_rev_1() {
    // A client outbox may merge a create and a delete that the server never
    // saw apart: the tombstone is the answer, and later puts conflict with it.
    let (mut conn, a) = with_account();
    let outcome = put(&mut conn, &a, &tomb(item(5), 0, b"t", 1));
    assert_eq!(stored(&outcome).0, 1);
    assert_eq!(counters(&conn, &a).1, 1, "a tombstone is not a live row");
    assert_eq!(
        put(&mut conn, &a, &live(item(5), 1, b"back", 2)),
        PutOutcome::Conflict(Conflict {
            current_rev: 1,
            blob: None,
            tag: None,
            deleted: true,
        })
    );
    assert_counters_match_rows(&conn, &a);
}

static DIRS: AtomicUsize = AtomicUsize::new(0);

/// A database file in a directory of its own, removed on drop.
struct FileDb {
    dir: PathBuf,
}

impl FileDb {
    fn new() -> Self {
        let dir = std::env::temp_dir().join(format!(
            "ferret-store-{}-{}",
            std::process::id(),
            DIRS.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&dir).expect("mkdir");
        Self { dir }
    }

    fn open(&self) -> Connection {
        let conn = Connection::open(self.dir.join("ferret.db")).expect("open");
        conn.execute_batch(
            "PRAGMA journal_mode = WAL; PRAGMA foreign_keys = ON; PRAGMA busy_timeout = 10000;",
        )
        .expect("pragmas");
        conn
    }
}

impl Drop for FileDb {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

#[test]
fn concurrent_writers_serialise_one_wins() {
    product::install();
    let db = FileDb::new();
    let mut setup = db.open();
    apply_migrations(&mut setup).expect("migrations");
    let a = add_account(&mut setup, 1, NOW);

    for round in 0..20u8 {
        let item_id = item(round);
        let barrier = Arc::new(Barrier::new(2));
        let handles: Vec<_> = (0..2u8)
            .map(|who| {
                let mut conn = db.open();
                let barrier = barrier.clone();
                std::thread::spawn(move || {
                    let n = round.wrapping_mul(2).wrapping_add(who).wrapping_add(1);
                    let blob = [who; 8];
                    let req = live(item_id, 0, &blob, n);
                    barrier.wait();
                    put_item(
                        &mut conn,
                        &a.vault_id,
                        &a.device,
                        &req,
                        &Limits::DEFAULT,
                        NOW,
                    )
                    .expect("put_item")
                })
            })
            .collect();
        let outcomes: Vec<PutOutcome> = handles
            .into_iter()
            .map(|h| h.join().expect("a writer"))
            .collect();
        let winners = outcomes
            .iter()
            .filter(|o| {
                matches!(
                    o,
                    PutOutcome::Stored {
                        replayed: false,
                        ..
                    }
                )
            })
            .count();
        let losers = outcomes
            .iter()
            .filter(|o| matches!(o, PutOutcome::Conflict(c) if c.current_rev == 1 && !c.deleted))
            .count();
        assert_eq!((winners, losers), (1, 1), "round {round}: {outcomes:?}");
    }

    // 20 items and the manifest, and a counter that never skipped or repeated.
    let (seq, count): (i64, i64) = setup
        .query_row(
            "SELECT seq, item_count FROM ferret_vaults WHERE vault_id = ?1",
            [a.vault_id.as_bytes()],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .expect("vault");
    assert_eq!((seq, count), (21, 21));
    let distinct: i64 = setup
        .query_row("SELECT COUNT(DISTINCT seq) FROM ferret_items", [], |r| {
            r.get(0)
        })
        .expect("distinct");
    assert_eq!(distinct, 21);
}
