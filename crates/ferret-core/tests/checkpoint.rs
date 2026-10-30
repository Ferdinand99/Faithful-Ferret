//! Signed checkpoints (Fase 1 § 8.6): the entries list, the MAC, the five
//! checks of a receiver, and `vectors/internal/checkpoint.json`.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]

mod common;

use common::*;
use ferret_core::integrity::{ENTRY_LEN, MAX_ENTRIES, blob_hash, encode_entries, parse_entries};
use ferret_core::testing::integrity::checkpoint_mac_message;
use ferret_core::testing::keys::unlocked_vault_keys;
use ferret_core::testing::prim::hmac_sha256;
use ferret_core::testing::vector::Outcome;
use ferret_core::testing::{ReplayRng, TestRng};
use ferret_core::{
    Checkpoint, CheckpointEntry, Error, ItemId, MalformedKind, RowState, ServerRow, UnlockedVault,
    make_checkpoint, make_tombstone, verify_checkpoint,
};
use serde_json::{Value as Json, json};
use sha2::{Digest, Sha256};

fn item_id(b: u8) -> ItemId {
    ItemId::from_bytes([b; 16])
}

fn failure(kind: ferret_core::CheckpointFailure) -> Result<(), Error> {
    Err(Error::Checkpoint(kind))
}

use ferret_core::CheckpointFailure as F;

fn hash(b: u8) -> [u8; 32] {
    [b; 32]
}

fn live(b: u8, rev: u64, h: u8) -> CheckpointEntry {
    CheckpointEntry {
        item_id: item_id(b),
        rev,
        live_hash: Some(hash(h)),
    }
}

fn dead(b: u8, rev: u64) -> CheckpointEntry {
    CheckpointEntry {
        item_id: item_id(b),
        rev,
        live_hash: None,
    }
}

fn row_live(b: u8, rev: u64, h: u8) -> ServerRow {
    ServerRow {
        item_id: item_id(b),
        rev,
        state: RowState::Live {
            blob_sha256: hash(h),
        },
    }
}

fn row_dead(b: u8, rev: u64) -> ServerRow {
    ServerRow {
        item_id: item_id(b),
        rev,
        state: RowState::Deleted,
    }
}

/// The base state: two live items, one tombstone and the manifest.
fn base() -> Vec<CheckpointEntry> {
    vec![
        CheckpointEntry {
            item_id: ItemId::MANIFEST,
            rev: 4,
            live_hash: Some(hash(0xee)),
        },
        live(0x41, 3, 0xa1),
        live(0x42, 5, 0xa2),
        dead(0x43, 2),
    ]
}

fn rows_of(entries: &[CheckpointEntry]) -> Vec<ServerRow> {
    entries
        .iter()
        .map(|e| ServerRow {
            item_id: e.item_id,
            rev: e.rev,
            state: match e.live_hash {
                Some(h) => RowState::Live { blob_sha256: h },
                None => RowState::Deleted,
            },
        })
        .collect()
}

const SEQ: u64 = 40;

fn cp(vault: &UnlockedVault, entries: Vec<CheckpointEntry>) -> Checkpoint {
    make_checkpoint(vault, SEQ, entries).unwrap()
}

// ----------------------------------------------------------------- entries

#[test]
fn checkpoint_entries_are_sorted_by_raw_item_id() {
    let vault = unlocked(0x5a);
    let mut entries = vec![
        live(0x80, 1, 1),
        live(0xff, 2, 2),
        dead(0x00, 3),
        live(0x7f, 4, 4),
        live(0x41, 5, 5),
    ];
    let a = cp(&vault, entries.clone());
    entries.reverse();
    let b = cp(&vault, entries.clone());
    assert_eq!(a, b, "the input order does not matter");
    assert_eq!(a.entries.len(), 56 * 5);
    // Ascending by the unsigned bytes: 0x00, 0x41, 0x7f, 0x80, 0xff.
    let firsts: Vec<u8> = a.entries.chunks(56).map(|c| c[0]).collect();
    assert_eq!(firsts, vec![0x00, 0x41, 0x7f, 0x80, 0xff]);
    // Each entry is item_id (16) ‖ u64be(rev) ‖ h (32), written out here.
    let mut expected = Vec::new();
    for (id, rev, h) in [
        (0x00u8, 3u64, [0u8; 32]),
        (0x41, 5, hash(5)),
        (0x7f, 4, hash(4)),
        (0x80, 1, hash(1)),
        (0xff, 2, hash(2)),
    ] {
        expected.extend_from_slice(&[id; 16]);
        expected.extend_from_slice(&rev.to_be_bytes());
        expected.extend_from_slice(&h);
    }
    assert_eq!(a.entries, expected);
    assert_eq!(a.digest.as_slice(), Sha256::digest(&expected).as_slice());
    // Ids that differ only in a late byte sort by that byte.
    let mut late = [0x10u8; 16];
    let mut late2 = late;
    late[15] = 0xf0;
    late2[15] = 0x0f;
    let c = cp(
        &vault,
        vec![
            CheckpointEntry {
                item_id: ItemId::from_bytes(late),
                rev: 1,
                live_hash: None,
            },
            CheckpointEntry {
                item_id: ItemId::from_bytes(late2),
                rev: 1,
                live_hash: None,
            },
        ],
    );
    assert_eq!(&c.entries[..16], &late2);
}

#[test]
fn checkpoint_tombstone_hash_is_32_zero_bytes() {
    let vault = unlocked(0x5a);
    let c = cp(&vault, vec![dead(0x41, 9)]);
    assert_eq!(c.entries.len(), 56);
    assert_eq!(&c.entries[24..], &[0u8; 32]);
    let parsed = parse_entries(&c.entries).unwrap();
    assert_eq!(parsed, vec![dead(0x41, 9)]);
    // A live row keeps its hash.
    let envelope = [1u8, 2, 3];
    let entry = CheckpointEntry::live(item_id(1), 2, &envelope);
    assert_eq!(entry.live_hash, Some(blob_hash(&envelope)));
    assert_eq!(
        blob_hash(&envelope).as_slice(),
        Sha256::digest(envelope).as_slice()
    );
}

#[test]
fn checkpoint_mac_is_the_documented_hmac() {
    let vault = unlocked(0x5a);
    let c = cp(&vault, base());
    let message = [
        label("ferret/v1/checkpoint"),
        t(0x23, &SEQ.to_be_bytes()),
        t(0x35, &c.digest),
    ]
    .concat();
    assert_eq!(checkpoint_mac_message(SEQ, &c.digest).unwrap(), message);
    assert_eq!(
        c.mac,
        hmac_sha256(&unlocked_vault_keys(&vault)[1], &message).unwrap()
    );
}

#[test]
fn checkpoint_digest_is_independent_of_the_server_state() {
    // A checkpoint is a pure function of (K_head, seq, entries).
    let vault = unlocked(0x5a);
    assert_eq!(cp(&vault, base()), cp(&vault, base()));
    assert_ne!(cp(&vault, base()).mac, cp(&unlocked(0x5b), base()).mac);
    assert_ne!(
        make_checkpoint(&vault, SEQ + 1, base()).unwrap().mac,
        cp(&vault, base()).mac
    );
}

#[test]
fn entries_must_be_unique_sorted_and_whole() {
    let vault = unlocked(0x5a);
    assert_eq!(
        make_checkpoint(&vault, 1, vec![live(1, 1, 1), live(1, 2, 2)]).err(),
        Some(Error::Malformed(MalformedKind::Entries))
    );
    let good = encode_entries(&base()).unwrap();
    assert_eq!(good.len(), 4 * ENTRY_LEN);
    assert_eq!(parse_entries(&good).unwrap().len(), 4);
    assert!(parse_entries(&[]).unwrap().is_empty());
    let mut ragged = good.clone();
    ragged.push(0);
    assert_eq!(
        parse_entries(&ragged).err(),
        Some(Error::Malformed(MalformedKind::Entries))
    );
    let mut swapped = good.clone();
    let (a, b) = swapped.split_at_mut(ENTRY_LEN);
    a.swap_with_slice(&mut b[..ENTRY_LEN]);
    assert_eq!(
        parse_entries(&swapped).err(),
        Some(Error::Malformed(MalformedKind::Entries))
    );
    let twice = [&good[..ENTRY_LEN], &good[..ENTRY_LEN]].concat();
    assert_eq!(
        parse_entries(&twice).err(),
        Some(Error::Malformed(MalformedKind::Entries))
    );
    assert_eq!(
        parse_entries(&vec![0u8; ENTRY_LEN * (MAX_ENTRIES + 1)]).err(),
        Some(Error::TooLarge)
    );
}

// -------------------------------------------------------------- the checks

#[test]
fn checkpoint_accepts_consistent_state() {
    let vault = unlocked(0x5a);
    let c = cp(&vault, base());
    let rows = rows_of(&base());
    verify_checkpoint(&vault, &c, &rows, SEQ).unwrap();
    verify_checkpoint(&vault, &c, &rows, SEQ + 10).unwrap();
    // The order of the server's rows does not matter.
    let mut reversed = rows.clone();
    reversed.reverse();
    verify_checkpoint(&vault, &c, &reversed, SEQ).unwrap();
    // Newer state is fine below the top: a higher revision, a new item.
    let mut newer = rows.clone();
    newer[2] = row_live(0x42, 6, 0xb2);
    newer.push(row_live(0x44, 1, 0xb4));
    verify_checkpoint(&vault, &c, &newer, SEQ + 1).unwrap();
    // An empty state.
    let empty = make_checkpoint(&vault, 0, vec![]).unwrap();
    verify_checkpoint(&vault, &empty, &[], 0).unwrap();
}

// Check 1: the row tags. A row that nobody verified cannot become a
// `ServerRow`.
#[test]
fn server_rows_are_made_from_verified_tags_and_tombstones() {
    let vault = unlocked(0x5a);
    let envelope = vec![1u8, 1, 1, 9, 9, 9];
    let id = item_id(7);
    let tag = ferret_core::item_tag(&vault, id, 3, &envelope).unwrap();
    let row = ServerRow::live(&vault, id, 3, &envelope, &tag).unwrap();
    assert_eq!(
        row.state,
        RowState::Live {
            blob_sha256: blob_hash(&envelope)
        }
    );
    let mut bad_tag = tag;
    bad_tag[0] ^= 1;
    assert_eq!(
        ServerRow::live(&vault, id, 3, &envelope, &bad_tag).err(),
        Some(Error::Decrypt)
    );
    assert_eq!(
        ServerRow::live(&vault, id, 4, &envelope, &tag).err(),
        Some(Error::Decrypt)
    );
    let tomb = make_tombstone(&mut TestRng::new(b"row"), &vault, id, 5).unwrap();
    let row = ServerRow::deleted(&vault, id, 5, &tomb.tomb).unwrap();
    assert_eq!(row.state, RowState::Deleted);
    assert_eq!(
        ServerRow::deleted(&vault, id, 6, &tomb.tomb).err(),
        Some(Error::TombstoneInvalid)
    );
}

// Check 2: the MAC and the digest.
#[test]
fn checkpoint_rejects_bad_mac_and_bad_digest() {
    let vault = unlocked(0x5a);
    let good = cp(&vault, base());
    let rows = rows_of(&base());

    let mut bad_mac = good.clone();
    bad_mac.mac[0] ^= 1;
    assert_eq!(
        verify_checkpoint(&vault, &bad_mac, &rows, SEQ),
        failure(F::BadMac)
    );
    // The seq is covered by the MAC.
    let mut other_seq = good.clone();
    other_seq.seq += 1;
    assert_eq!(
        verify_checkpoint(&vault, &other_seq, &rows, SEQ + 5),
        failure(F::BadMac)
    );
    // A changed digest field no longer fits the MAC.
    let mut bad_digest_field = good.clone();
    bad_digest_field.digest[0] ^= 1;
    assert_eq!(
        verify_checkpoint(&vault, &bad_digest_field, &rows, SEQ),
        failure(F::BadMac)
    );
    // Entries that do not hash to the signed digest.
    let mut bad_entries = good.clone();
    bad_entries.entries[20] ^= 1;
    assert_eq!(
        verify_checkpoint(&vault, &bad_entries, &rows, SEQ),
        failure(F::BadDigest)
    );
    let mut cut = good.clone();
    cut.entries.truncate(cut.entries.len() - ENTRY_LEN);
    assert_eq!(
        verify_checkpoint(&vault, &cut, &rows, SEQ),
        failure(F::BadDigest)
    );
    // Another vault's key.
    assert_eq!(
        verify_checkpoint(&unlocked(0x5b), &good, &rows, SEQ),
        failure(F::BadMac)
    );
    // The codes are distinct and stable.
    assert_ne!(
        Error::Checkpoint(F::BadMac).code(),
        Error::Checkpoint(F::BadDigest).code()
    );
}

#[test]
fn checkpoint_with_authentic_but_malformed_entries_is_refused() {
    let vault = unlocked(0x5a);
    let sorted = encode_entries(&base()).unwrap();
    let rows = rows_of(&base());
    let make = |entries: Vec<u8>| {
        let digest: [u8; 32] = Sha256::digest(&entries).into();
        let mac = hmac_sha256(
            &unlocked_vault_keys(&vault)[1],
            &checkpoint_mac_message(SEQ, &digest).unwrap(),
        )
        .unwrap();
        Checkpoint {
            seq: SEQ,
            digest,
            mac,
            entries,
        }
    };
    let mut ragged = sorted.clone();
    ragged.push(1);
    let mut unsorted = sorted.clone();
    let (a, b) = unsorted.split_at_mut(ENTRY_LEN);
    a.swap_with_slice(&mut b[..ENTRY_LEN]);
    let repeated = [&sorted[..ENTRY_LEN], &sorted[..ENTRY_LEN]].concat();
    for (name, entries) in [
        ("ragged", ragged),
        ("unsorted", unsorted),
        ("repeat", repeated),
    ] {
        assert_eq!(
            verify_checkpoint(&vault, &make(entries), &rows, SEQ),
            Err(Error::Malformed(MalformedKind::Entries)),
            "{name}"
        );
    }
}

// Check 3: a live entry against the server's row.
#[test]
fn checkpoint_rejects_hidden_item() {
    let vault = unlocked(0x5a);
    let c = cp(&vault, base());
    for gone in [0usize, 1, 2] {
        let mut rows = rows_of(&base());
        rows.remove(gone);
        assert_eq!(
            verify_checkpoint(&vault, &c, &rows, SEQ + 5),
            failure(F::HiddenOrRolledBack),
            "row {gone}"
        );
    }
    assert_eq!(
        verify_checkpoint(&vault, &c, &[], SEQ + 5),
        failure(F::HiddenOrRolledBack)
    );
    assert_eq!(
        Error::Checkpoint(F::HiddenOrRolledBack).code(),
        "checkpoint_hidden_or_rolled_back"
    );
}

#[test]
fn checkpoint_rejects_lower_rev() {
    let vault = unlocked(0x5a);
    let c = cp(&vault, base());
    let mut rows = rows_of(&base());
    rows[2] = row_live(0x42, 4, 0xa2);
    assert_eq!(
        verify_checkpoint(&vault, &c, &rows, SEQ + 5),
        failure(F::LowerRev)
    );
}

#[test]
fn checkpoint_rejects_same_rev_different_hash() {
    let vault = unlocked(0x5a);
    let c = cp(&vault, base());
    let mut rows = rows_of(&base());
    rows[2] = row_live(0x42, 5, 0xff);
    assert_eq!(
        verify_checkpoint(&vault, &c, &rows, SEQ + 5),
        failure(F::SameRevDifferentHash)
    );
}

#[test]
fn checkpoint_deleted_row_must_have_a_higher_rev() {
    let vault = unlocked(0x5a);
    let c = cp(&vault, base());
    let rows_with = |row: ServerRow| {
        let mut rows = rows_of(&base());
        rows[2] = row;
        rows
    };
    // Higher: the item was deleted after the checkpoint.
    verify_checkpoint(&vault, &c, &rows_with(row_dead(0x42, 6)), SEQ + 5).unwrap();
    // The same revision cannot be both live and deleted.
    assert_eq!(
        verify_checkpoint(&vault, &c, &rows_with(row_dead(0x42, 5)), SEQ + 5),
        failure(F::SameRevDifferentHash)
    );
    // Lower is a roll back.
    assert_eq!(
        verify_checkpoint(&vault, &c, &rows_with(row_dead(0x42, 4)), SEQ + 5),
        failure(F::LowerRev)
    );
}

// Check 4: a tombstone entry.
#[test]
fn checkpoint_accepts_missing_tombstone() {
    let vault = unlocked(0x5a);
    let c = cp(&vault, base());
    let mut rows = rows_of(&base());
    rows.pop();
    assert_eq!(rows.len(), 3);
    verify_checkpoint(&vault, &c, &rows, SEQ + 5).unwrap();
    // The same, with a tombstone row of a higher revision, and with the
    // item live again at a higher revision.
    let mut up = rows_of(&base());
    up[3] = row_dead(0x43, 9);
    verify_checkpoint(&vault, &c, &up, SEQ + 5).unwrap();
    let mut revived = rows_of(&base());
    revived[3] = row_live(0x43, 3, 0xcc);
    verify_checkpoint(&vault, &c, &revived, SEQ + 5).unwrap();
}

#[test]
fn checkpoint_rejects_live_row_older_than_tombstone() {
    let vault = unlocked(0x5a);
    let c = cp(&vault, base());
    let mut rows = rows_of(&base());
    rows[3] = row_live(0x43, 1, 0xcc);
    assert_eq!(
        verify_checkpoint(&vault, &c, &rows, SEQ + 5),
        failure(F::LiveBehindTombstone)
    );
    // A live row at the revision of the tombstone: two stories for one rev.
    rows[3] = row_live(0x43, 2, 0xcc);
    assert_eq!(
        verify_checkpoint(&vault, &c, &rows, SEQ + 5),
        failure(F::SameRevDifferentHash)
    );
    // A tombstone shown at a lower revision than the checkpoint's.
    rows[3] = row_dead(0x43, 1);
    assert_eq!(
        verify_checkpoint(&vault, &c, &rows, SEQ + 5),
        failure(F::LowerRev)
    );
}

// Check 5: at the top, the rows must be exactly the entries (a purged
// tombstone excepted).
#[test]
fn checkpoint_top_seq_digest_recomputed() {
    let vault = unlocked(0x5a);
    let c = cp(&vault, base());
    let rows = rows_of(&base());
    verify_checkpoint(&vault, &c, &rows, SEQ).unwrap();

    // A row the checkpoint does not have: every entry still checks out, but
    // at the top the state must be exactly the checkpoint's.
    let mut extra = rows.clone();
    extra.push(row_live(0x44, 1, 0xdd));
    assert_eq!(
        verify_checkpoint(&vault, &c, &extra, SEQ),
        failure(F::TopDigestMismatch)
    );
    verify_checkpoint(&vault, &c, &extra, SEQ + 1).unwrap();

    // A higher revision.
    let mut higher = rows.clone();
    higher[2] = row_live(0x42, 6, 0xb2);
    assert_eq!(
        verify_checkpoint(&vault, &c, &higher, SEQ),
        failure(F::TopDigestMismatch)
    );

    // A tombstone that has been purged is accepted, at the top too.
    let mut no_tomb = rows.clone();
    no_tomb.pop();
    verify_checkpoint(&vault, &c, &no_tomb, SEQ).unwrap();

    // A live entry without its row is not, at the top: the state is not the
    // checkpoint's (below the top it is a hidden or rolled back item).
    for gone in [0usize, 1, 2] {
        let mut hidden = rows.clone();
        hidden.remove(gone);
        assert_eq!(
            verify_checkpoint(&vault, &c, &hidden, SEQ),
            failure(F::TopDigestMismatch),
            "row {gone}"
        );
        assert_eq!(
            verify_checkpoint(&vault, &c, &hidden, SEQ + 1),
            failure(F::HiddenOrRolledBack),
            "row {gone}"
        );
    }

    // A purged tombstone does not excuse an extra row.
    let mut both = no_tomb.clone();
    both.push(row_live(0x44, 1, 0xdd));
    assert_eq!(
        verify_checkpoint(&vault, &c, &both, SEQ),
        failure(F::TopDigestMismatch)
    );

    // A tombstone row at another revision than its entry, and a live row
    // where the checkpoint has a tombstone at a higher revision, are not the
    // checkpoint's state.
    let mut tomb_up = rows.clone();
    tomb_up[3] = row_dead(0x43, 9);
    assert_eq!(
        verify_checkpoint(&vault, &c, &tomb_up, SEQ),
        failure(F::TopDigestMismatch)
    );
    let mut revived = rows.clone();
    revived[3] = row_live(0x43, 3, 0xcc);
    assert_eq!(
        verify_checkpoint(&vault, &c, &revived, SEQ),
        failure(F::TopDigestMismatch)
    );

    // A blob changed without a new revision. The entry check reports it
    // first, with the more precise code.
    let mut changed = rows.clone();
    changed[2] = row_live(0x42, 5, 0xff);
    assert_eq!(
        verify_checkpoint(&vault, &c, &changed, SEQ),
        failure(F::SameRevDifferentHash)
    );
}

#[test]
fn checkpoint_seq_above_top_rejected() {
    let vault = unlocked(0x5a);
    let c = cp(&vault, base());
    let rows = rows_of(&base());
    assert_eq!(
        verify_checkpoint(&vault, &c, &rows, SEQ - 1),
        failure(F::SeqAboveTop)
    );
    assert_eq!(
        verify_checkpoint(&vault, &c, &rows, 0),
        failure(F::SeqAboveTop)
    );
}

#[test]
fn server_rows_with_one_item_twice_are_refused() {
    let vault = unlocked(0x5a);
    let c = cp(&vault, base());
    let mut rows = rows_of(&base());
    rows.push(rows[1]);
    assert_eq!(
        verify_checkpoint(&vault, &c, &rows, SEQ + 5),
        Err(Error::Malformed(MalformedKind::Entries))
    );
}

#[test]
fn rows_not_in_the_checkpoint_are_fine_below_the_top() {
    let vault = unlocked(0x5a);
    let c = make_checkpoint(&vault, 3, vec![live(1, 1, 1)]).unwrap();
    let rows = vec![row_live(1, 1, 1), row_live(2, 7, 2), row_dead(3, 9)];
    verify_checkpoint(&vault, &c, &rows, 4).unwrap();
    assert_eq!(
        verify_checkpoint(&vault, &c, &rows, 3),
        failure(F::TopDigestMismatch)
    );
}

// ---------------------------------------------------------------- vectors

/// The rows of the generated state, in index order. See `OPS.md`.
fn generated(count: u32) -> Vec<CheckpointEntry> {
    (0..count)
        .map(|i| {
            let id = Sha256::new()
                .chain_update(b"ferret/checkpoint-vector/id")
                .chain_update(i.to_be_bytes())
                .finalize();
            let h = Sha256::new()
                .chain_update(b"ferret/checkpoint-vector/hash")
                .chain_update(i.to_be_bytes())
                .finalize();
            CheckpointEntry {
                item_id: ItemId::from_bytes(id[..16].try_into().unwrap()),
                rev: 1 + u64::from(i % 7),
                live_hash: if i % 5 == 0 { None } else { Some(h.into()) },
            }
        })
        .collect()
}

fn entry_of(v: &Json) -> CheckpointEntry {
    CheckpointEntry {
        item_id: ItemId::from_bytes(id16(&v["item_id"])),
        rev: u64s(&v["rev"]),
        live_hash: if v["hash"].is_null() {
            None
        } else {
            Some(hexn(&v["hash"]))
        },
    }
}

fn row_of(v: &Json) -> ServerRow {
    ServerRow {
        item_id: ItemId::from_bytes(id16(&v["item_id"])),
        rev: u64s(&v["rev"]),
        state: match v["state"].as_str().unwrap() {
            "live" => RowState::Live {
                blob_sha256: hexn(&v["hash"]),
            },
            "deleted" => RowState::Deleted,
            other => panic!("unknown state {other}"),
        },
    }
}

#[test]
fn checkpoint_vectors_from_file() {
    let file = load_ops("checkpoint.json", |_| true);
    let report = ferret_core::testing::vector::run_all(&file, |case, _rng: &mut ReplayRng| {
        let input = &case.input;
        let vault = vault_of(input);
        match case.op.as_str() {
            "checkpoint.make" => {
                let list = match input.get("generate") {
                    Some(g) => generated(u32::try_from(g["count"].as_u64().unwrap()).unwrap()),
                    None => input["entries"]
                        .as_array()
                        .unwrap()
                        .iter()
                        .map(entry_of)
                        .collect(),
                };
                let c = make_checkpoint(&vault, u64s(&input["seq"]), list)?;
                let mut out = json!({
                    "entries_len": c.entries.len(),
                    "entries_sha256": he(&Sha256::digest(&c.entries)),
                    "digest": he(&c.digest),
                    "mac": he(&c.mac),
                });
                if c.entries.len() <= 20 * ENTRY_LEN {
                    out["entries"] = json!(he(&c.entries));
                }
                Ok(Outcome {
                    output: out,
                    intermediate: Some(
                        json!({ "message": he(&checkpoint_mac_message(c.seq, &c.digest)?) }),
                    ),
                })
            }
            "checkpoint.verify" => {
                let given = &input["checkpoint"];
                let entries = match given.get("generate") {
                    Some(g) => encode_entries(&generated(
                        u32::try_from(g["count"].as_u64().unwrap()).unwrap(),
                    ))?,
                    None => hex(&given["entries"]),
                };
                let c = Checkpoint {
                    seq: u64s(&given["seq"]),
                    digest: hexn(&given["digest"]),
                    mac: hexn(&given["mac"]),
                    entries,
                };
                let rows: Vec<ServerRow> = match &input["rows"] {
                    Json::Array(list) => list.iter().map(row_of).collect(),
                    spec => {
                        assert_eq!(spec["all_entries"], json!(true));
                        let omit: Vec<usize> = spec["omit"]
                            .as_array()
                            .unwrap()
                            .iter()
                            .map(|i| usize::try_from(i.as_u64().unwrap()).unwrap())
                            .collect();
                        rows_of(&parse_entries(&c.entries)?)
                            .into_iter()
                            .enumerate()
                            .filter(|(i, _)| !omit.contains(i))
                            .map(|(_, r)| r)
                            .collect()
                    }
                };
                verify_checkpoint(&vault, &c, &rows, u64s(&input["top_seq"]))?;
                Ok(Outcome {
                    output: json!({ "ok": true }),
                    intermediate: None,
                })
            }
            other => panic!("unknown op {other}"),
        }
    });
    assert_all_passed(&report, 40);
}

#[test]
fn a_live_hash_of_32_zero_bytes_is_refused() {
    // It would read back as a tombstone, so it never gets into an entry list.
    let vault = unlocked(0x5a);
    let zero = CheckpointEntry {
        item_id: item_id(1),
        rev: 1,
        live_hash: Some([0; 32]),
    };
    assert_eq!(
        make_checkpoint(&vault, 1, vec![zero]).err(),
        Some(Error::Malformed(MalformedKind::Entries))
    );
    assert_eq!(
        encode_entries(&[zero]).err(),
        Some(Error::Malformed(MalformedKind::Entries))
    );
    // A server row like that is refused as well, whatever the entries.
    let c = cp(&vault, base());
    let mut rows = rows_of(&base());
    rows.push(ServerRow {
        item_id: item_id(0x44),
        rev: 1,
        state: RowState::Live {
            blob_sha256: [0; 32],
        },
    });
    assert_eq!(
        verify_checkpoint(&vault, &c, &rows, SEQ + 1),
        Err(Error::Malformed(MalformedKind::Entries))
    );
}

#[test]
fn encode_entries_refuses_more_than_the_limit_and_repeated_ids() {
    let one = |n: usize| {
        let mut id = [0u8; 16];
        id[8..].copy_from_slice(&u64::try_from(n).unwrap().to_be_bytes());
        CheckpointEntry::tombstone(ItemId::from_bytes(id), 1)
    };
    let many: Vec<CheckpointEntry> = (0..=MAX_ENTRIES).map(one).collect();
    assert_eq!(encode_entries(&many).err(), Some(Error::TooLarge));
    // Exactly at the limit is fine, and the list is sorted.
    let at_limit = &many[..MAX_ENTRIES];
    assert_eq!(
        encode_entries(at_limit).unwrap().len(),
        MAX_ENTRIES * ENTRY_LEN
    );
    // The same id twice is not a checkpoint.
    let twice = vec![one(1), one(1)];
    assert_eq!(
        encode_entries(&twice).err(),
        Some(Error::Malformed(ferret_core::MalformedKind::Entries))
    );
}
