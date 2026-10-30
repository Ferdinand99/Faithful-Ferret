//! The rollback memory (Fase 1 § 8.6, "Lokalt minne"): the floors, their
//! serialisation, the size bound and `vectors/internal/sync.json`.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]

mod common;

use common::*;
use ferret_core::testing::vector::Outcome;
use ferret_core::{
    Checkpoint, CheckpointEntry, CheckpointFailure as F, Error, ItemId, MAX_TRACKED_ITEMS,
    MalformedKind, RollbackMemory, RowState, ServerRow, SyncMemory, make_checkpoint,
    verify_checkpoint,
};
use serde_json::{Value, json};

fn item_id(n: u32) -> ItemId {
    let mut id = [0u8; 16];
    id[12..].copy_from_slice(&n.to_be_bytes());
    ItemId::from_bytes(id)
}

fn live(n: u32, rev: u64) -> ServerRow {
    ServerRow {
        item_id: item_id(n),
        rev,
        state: RowState::Live {
            blob_sha256: [n.to_be_bytes()[3].max(1); 32],
        },
    }
}

fn dead(n: u32, rev: u64) -> ServerRow {
    ServerRow {
        item_id: item_id(n),
        rev,
        state: RowState::Deleted,
    }
}

fn rollback(kind: F) -> Result<(), Error> {
    Err(Error::Checkpoint(kind))
}

fn entries_of(rows: &[ServerRow]) -> Vec<CheckpointEntry> {
    rows.iter()
        .map(|r| CheckpointEntry {
            item_id: r.item_id,
            rev: r.rev,
            live_hash: match r.state {
                RowState::Live { blob_sha256 } => Some(blob_sha256),
                RowState::Deleted => None,
            },
        })
        .collect()
}

// ------------------------------------------------------------------ rows

#[test]
fn a_new_record_remembers_nothing() {
    let m = SyncMemory::new();
    assert_eq!((m.max_seq(), m.checkpoint_seq(), m.tracked()), (0, 0, 0));
    m.check_rows(&[live(1, 1)], 0).unwrap();
    m.check_checkpoint_seq(0).unwrap();
    assert_eq!(m.rev_of(&item_id(1)), None);
}

#[test]
fn rows_raise_the_floors_and_never_lower_them() {
    let mut m = SyncMemory::new();
    m.accept_rows(&[live(1, 3), live(2, 5)], 10).unwrap();
    assert_eq!((m.max_seq(), m.tracked()), (10, 2));
    assert_eq!(m.rev_of(&item_id(1)), Some(3));
    // The same rows again, and higher ones, are fine.
    m.accept_rows(&[live(1, 3), live(2, 6), live(3, 1)], 10)
        .unwrap();
    assert_eq!(m.rev_of(&item_id(2)), Some(6));
    assert_eq!(m.rev_of(&item_id(3)), Some(1));
    // A tombstone counts like a live row.
    m.accept_rows(&[dead(1, 4)], 11).unwrap();
    assert_eq!(m.rev_of(&item_id(1)), Some(4));
    assert_eq!(m.accept_rows(&[live(1, 3)], 12), rollback(F::RememberedRev));
    assert_eq!(m.accept_rows(&[], 9), rollback(F::RememberedTopSeq));
    assert_eq!(m.max_seq(), 11, "a refusal changes nothing");
}

#[test]
fn one_bad_row_refuses_the_whole_set() {
    let mut m = SyncMemory::new();
    m.accept_rows(&[live(1, 3), live(2, 5)], 10).unwrap();
    let before = m.clone();
    assert_eq!(
        m.accept_rows(&[live(2, 9), live(1, 2), live(3, 1)], 20),
        rollback(F::RememberedRev)
    );
    assert_eq!(m, before);
}

#[test]
fn the_record_holds_at_most_the_stated_number_of_items() {
    let mut m = SyncMemory::new();
    let rows: Vec<ServerRow> = (0..u32::try_from(MAX_TRACKED_ITEMS).unwrap())
        .map(|n| live(n, 1))
        .collect();
    m.accept_rows(&rows, 1).unwrap();
    assert_eq!(m.tracked(), MAX_TRACKED_ITEMS);
    // Known items still move; a new one does not fit, and nothing changes.
    m.accept_rows(&[live(0, 2)], 2).unwrap();
    let before = m.clone();
    let extra = u32::try_from(MAX_TRACKED_ITEMS).unwrap();
    assert_eq!(
        m.accept_rows(&[live(1, 2), live(extra, 1)], 3),
        Err(Error::TooLarge)
    );
    assert_eq!(m, before);
    // The full record round-trips.
    let back = SyncMemory::from_bytes(&m.to_bytes()).unwrap();
    assert_eq!(back, m);
}

// ----------------------------------------------------------------- bytes

#[test]
fn the_record_round_trips_and_is_sorted() {
    let mut m = SyncMemory::new();
    m.accept_rows(&[live(9, 2), live(1, 7), dead(5, 3)], 40)
        .unwrap();
    let bytes = m.to_bytes();
    assert_eq!(bytes.len(), 1 + 8 + 8 + 4 + 3 * 24);
    assert_eq!(bytes[0], 1);
    assert_eq!(&bytes[1..9], &40u64.to_be_bytes());
    assert_eq!(&bytes[17..21], &3u32.to_be_bytes());
    let ids: Vec<&[u8]> = bytes[21..].chunks(24).map(|c| &c[..16]).collect();
    assert!(ids.windows(2).all(|w| w[0] < w[1]));
    assert_eq!(SyncMemory::from_bytes(&bytes).unwrap(), m);
}

#[test]
fn a_record_that_was_not_written_by_the_core_is_refused() {
    let good = {
        let mut m = SyncMemory::new();
        m.accept_rows(&[live(1, 1), live(2, 2)], 5).unwrap();
        m.to_bytes()
    };
    let bad = Err(Error::Malformed(MalformedKind::PinnedRecord));
    assert_eq!(SyncMemory::from_bytes(&[]), bad);
    for cut in [1, 8, 20, good.len() - 1] {
        assert_eq!(SyncMemory::from_bytes(&good[..cut]), bad, "cut at {cut}");
    }
    let mut longer = good.clone();
    longer.push(0);
    assert_eq!(SyncMemory::from_bytes(&longer), bad);
    let mut version = good.clone();
    version[0] = 2;
    assert_eq!(SyncMemory::from_bytes(&version), bad);
    let mut above = good.clone();
    above[9..17].copy_from_slice(&6u64.to_be_bytes());
    assert_eq!(SyncMemory::from_bytes(&above), bad);
    // The entries swapped, and one repeated.
    let mut swapped = good.clone();
    let (a, b) = (good[21..45].to_vec(), good[45..69].to_vec());
    swapped[21..45].copy_from_slice(&b);
    swapped[45..69].copy_from_slice(&a);
    assert_eq!(SyncMemory::from_bytes(&swapped), bad);
    let mut repeated = good.clone();
    repeated[45..69].copy_from_slice(&a);
    assert_eq!(SyncMemory::from_bytes(&repeated), bad);
    // A count above the bound, whatever the length.
    let mut huge = good[..21].to_vec();
    huge[17..21].copy_from_slice(&u32::try_from(MAX_TRACKED_ITEMS + 1).unwrap().to_be_bytes());
    assert_eq!(SyncMemory::from_bytes(&huge), bad);
}

// ----------------------------------------------------------- checkpoints

fn state(revs: &[(u32, u64)]) -> Vec<ServerRow> {
    revs.iter().map(|(n, r)| live(*n, *r)).collect()
}

fn checkpoint_of(vault: &ferret_core::UnlockedVault, seq: u64, rows: &[ServerRow]) -> Checkpoint {
    make_checkpoint(vault, seq, entries_of(rows)).unwrap()
}

#[test]
fn verify_checkpoint_advances_the_memory_only_on_success() {
    let vault = unlocked(0x5a);
    let s40 = state(&[(1, 3), (2, 5)]);
    let s50 = state(&[(1, 4), (2, 5), (3, 1)]);
    let (cp40, cp50) = (
        checkpoint_of(&vault, 40, &s40),
        checkpoint_of(&vault, 50, &s50),
    );
    let mut m = SyncMemory::new();

    verify_checkpoint(&vault, &cp40, &s40, 40, RollbackMemory::Remembered(&mut m)).unwrap();
    assert_eq!((m.max_seq(), m.checkpoint_seq(), m.tracked()), (40, 40, 2));
    verify_checkpoint(&vault, &cp50, &s50, 50, RollbackMemory::Remembered(&mut m)).unwrap();
    assert_eq!((m.max_seq(), m.checkpoint_seq(), m.tracked()), (50, 50, 3));

    // Equal is not lower.
    verify_checkpoint(&vault, &cp50, &s50, 55, RollbackMemory::Remembered(&mut m)).unwrap();
    assert_eq!(m.max_seq(), 55);
    let before = m.clone();

    // An older checkpoint, even a valid one with its own rows at its own top.
    assert_eq!(
        verify_checkpoint(&vault, &cp40, &s40, 40, RollbackMemory::Remembered(&mut m)),
        rollback(F::RememberedCheckpointSeq)
    );
    // The same checkpoint with the server's top below the highest seen.
    assert_eq!(
        verify_checkpoint(&vault, &cp50, &s50, 50, RollbackMemory::Remembered(&mut m)),
        rollback(F::RememberedTopSeq)
    );
    // A row below the remembered revision.
    let mut low = m.clone();
    low.accept_rows(&[live(2, 9)], 60).unwrap();
    let mut keep = low.clone();
    assert_eq!(
        verify_checkpoint(
            &vault,
            &cp50,
            &s50,
            60,
            RollbackMemory::Remembered(&mut keep)
        ),
        rollback(F::RememberedRev)
    );
    assert_eq!(keep, low, "a refusal changes nothing");
    assert_eq!(m, before);

    // The checkpoint's own checks come first.
    let mut forged = cp50.clone();
    forged.mac[0] ^= 1;
    assert_eq!(
        verify_checkpoint(
            &vault,
            &forged,
            &s50,
            60,
            RollbackMemory::Remembered(&mut m)
        ),
        rollback(F::BadMac)
    );
}

#[test]
fn no_memory_is_a_named_choice_and_checks_only_the_checkpoint() {
    let vault = unlocked(0x5a);
    let s = state(&[(1, 3)]);
    let cp = checkpoint_of(&vault, 40, &s);
    verify_checkpoint(&vault, &cp, &s, 40, RollbackMemory::NoMemory).unwrap();
}

#[test]
fn accepting_an_older_state_is_explicit_and_still_verified() {
    let vault = unlocked(0x5a);
    let s30 = state(&[(1, 2), (2, 4)]);
    let s50 = state(&[(1, 4), (2, 5)]);
    let (cp30, cp50) = (
        checkpoint_of(&vault, 30, &s30),
        checkpoint_of(&vault, 50, &s50),
    );
    let mut m = SyncMemory::new();
    verify_checkpoint(&vault, &cp50, &s50, 60, RollbackMemory::Remembered(&mut m)).unwrap();
    assert_eq!(
        verify_checkpoint(&vault, &cp30, &s30, 30, RollbackMemory::Remembered(&mut m)),
        rollback(F::RememberedCheckpointSeq)
    );

    // A state that does not verify by itself is refused, and nothing moves.
    let before = m.clone();
    let mut forged = cp30.clone();
    forged.mac[0] ^= 1;
    assert_eq!(
        m.accept_older_state(&vault, &forged, &s30, 30),
        rollback(F::BadMac)
    );
    assert_eq!(m, before);

    m.accept_older_state(&vault, &cp30, &s30, 30).unwrap();
    assert_eq!((m.max_seq(), m.checkpoint_seq(), m.tracked()), (30, 30, 2));
    assert_eq!(m.rev_of(&item_id(1)), Some(2));
    // From here the older state is the floor.
    verify_checkpoint(&vault, &cp30, &s30, 30, RollbackMemory::Remembered(&mut m)).unwrap();
    verify_checkpoint(&vault, &cp50, &s50, 50, RollbackMemory::Remembered(&mut m)).unwrap();
}

// ----------------------------------------------------------------- vectors

fn rows_of_input(input: &Value) -> Vec<ServerRow> {
    input["rows"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| ServerRow {
            item_id: ItemId::from_bytes(hexn(&v["item_id"])),
            rev: u64s(&v["rev"]),
            state: match v["state"].as_str().unwrap() {
                "live" => RowState::Live {
                    blob_sha256: hexn(&v["hash"]),
                },
                _ => RowState::Deleted,
            },
        })
        .collect()
}

#[test]
fn sync_vectors_from_file() {
    let file = load_ops("sync.json", |op| op == "sync.memory");
    let report = ferret_core::testing::vector::run_all(&file, |c, _rng| {
        let input = &c.input;
        let mut memory = match &input["memory"] {
            Value::Null => SyncMemory::new(),
            stored => SyncMemory::from_bytes(&hex(stored))?,
        };
        let action = input["action"].as_str().unwrap();
        if action != "decode" {
            let rows = rows_of_input(input);
            let top = u64s(&input["top_seq"]);
            if action == "accept_rows" {
                memory.accept_rows(&rows, top)?;
            } else {
                let vault = vault_of(input);
                let given = &input["checkpoint"];
                let cp = Checkpoint {
                    seq: u64s(&given["seq"]),
                    digest: hexn(&given["digest"]),
                    mac: hexn(&given["mac"]),
                    entries: hex(&given["entries"]),
                };
                match action {
                    "verify_checkpoint" => verify_checkpoint(
                        &vault,
                        &cp,
                        &rows,
                        top,
                        RollbackMemory::Remembered(&mut memory),
                    )?,
                    "accept_older_state" => memory.accept_older_state(&vault, &cp, &rows, top)?,
                    other => panic!("unknown action {other}"),
                }
            }
        }
        Ok(Outcome {
            output: json!({
                "memory": he(&memory.to_bytes()),
                "max_seq": memory.max_seq().to_string(),
                "checkpoint_seq": memory.checkpoint_seq().to_string(),
                "tracked": memory.tracked(),
            }),
            intermediate: None,
        })
    });
    assert_all_passed(&report, 29);
}
