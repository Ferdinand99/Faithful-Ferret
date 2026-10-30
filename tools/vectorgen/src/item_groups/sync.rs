//! The vector group for the rollback memory (`sync.json`).
//!
//! Spec: Fase 1 § 8.6 ("Lokalt minne", "Legitime tilbakerullinger"). The
//! record, its bytes and the comparisons are worked out here from the rules,
//! not taken from the core: `version (1) ‖ max_seq (8) ‖ checkpoint_seq (8) ‖
//! count (4)`, then `count` entries of `item_id (16) ‖ rev (8)` in ascending
//! order of `item_id`, big-endian.

use super::integrity::{Cp, Ent, Row, blob, cp_json, entries_bytes, make_cp, rev_s};
use super::*;
use std::collections::BTreeMap;

/// The model of the record.
#[derive(Clone, Default)]
struct Mem {
    max_seq: u64,
    checkpoint_seq: u64,
    revs: BTreeMap<[u8; 16], u64>,
}

impl Mem {
    fn new(max_seq: u64, checkpoint_seq: u64, revs: &[([u8; 16], u64)]) -> Self {
        Mem {
            max_seq,
            checkpoint_seq,
            revs: revs.iter().copied().collect(),
        }
    }

    fn bytes(&self) -> Vec<u8> {
        let mut out = vec![1];
        out.extend_from_slice(&self.max_seq.to_be_bytes());
        out.extend_from_slice(&self.checkpoint_seq.to_be_bytes());
        out.extend_from_slice(&(self.revs.len() as u32).to_be_bytes());
        for (id, rev) in &self.revs {
            out.extend_from_slice(id);
            out.extend_from_slice(&rev.to_be_bytes());
        }
        out
    }

    /// The record after rows are accepted at `top`, and, with `cp`, a
    /// checkpoint at that `seq`: floors only go up.
    fn after(&self, rows: &[Row], top: u64, cp: Option<u64>) -> Mem {
        let mut next = self.clone();
        for r in rows {
            let e = next.revs.entry(r.id).or_insert(r.rev);
            *e = (*e).max(r.rev);
        }
        next.max_seq = next.max_seq.max(top);
        if let Some(seq) = cp {
            next.checkpoint_seq = next.checkpoint_seq.max(seq);
        }
        next
    }

    fn expect(&self) -> Value {
        json!({
            "memory": h(&self.bytes()),
            "max_seq": self.max_seq.to_string(),
            "checkpoint_seq": self.checkpoint_seq.to_string(),
            "tracked": self.revs.len(),
        })
    }
}

fn base_input(action: &str, memory: Option<&[u8]>) -> Value {
    json!({
        "action": action,
        "memory": memory.map_or(Value::Null, h),
    })
}

fn with_checkpoint(mut i: Value, ctx: &Ctx, cp: &Cp, rows: &[Row], top: u64) -> Value {
    for (k, v) in ctx.input().as_object().into_iter().flatten() {
        i[k] = v.clone();
    }
    i["checkpoint"] = cp_json(cp);
    i["rows"] = Value::Array(rows.iter().map(Row::json).collect());
    i["top_seq"] = rev_s(top);
    i
}

fn with_rows(mut i: Value, rows: &[Row], top: u64) -> Value {
    i["rows"] = Value::Array(rows.iter().map(Row::json).collect());
    i["top_seq"] = rev_s(top);
    i
}

pub(crate) fn sync() -> Result<Vec<u8>, Error> {
    let mut cases: Vec<Case> = Vec::new();
    let c1 = ctx1();
    let k1 = c1.keys()?;

    let manifest = [0u8; 16];
    let (a, b, c, tomb) = (id(0x41), id(0x42), id(0x44), id(0x43));
    let live = |id: [u8; 16], rev: u64, tag: &str| Ent {
        id,
        rev,
        hash: Some(blob(tag)),
    };
    let dead = |id: [u8; 16], rev: u64| Ent {
        id,
        rev,
        hash: None,
    };
    // The server's state at seq 30, 40 and 50.
    let s30 = [
        live(manifest, 3, "m3"),
        live(a, 2, "a2"),
        live(b, 4, "b4"),
        dead(tomb, 1),
    ];
    let s40 = [
        live(manifest, 4, "m4"),
        live(a, 3, "a3"),
        live(b, 5, "b5"),
        dead(tomb, 2),
    ];
    let s50 = [
        live(manifest, 4, "m4"),
        live(a, 4, "a4"),
        live(b, 5, "b5"),
        dead(tomb, 2),
        live(c, 1, "c1"),
    ];
    let rows = |s: &[Ent]| -> Vec<Row> { s.iter().copied().map(Row::from).collect() };
    let revs = |s: &[Ent]| -> Vec<([u8; 16], u64)> { s.iter().map(|e| (e.id, e.rev)).collect() };
    let cp30 = make_cp(&k1.k_head, 30, entries_bytes(&s30))?;
    let cp40 = make_cp(&k1.k_head, 40, entries_bytes(&s40))?;
    let cp50 = make_cp(&k1.k_head, 50, entries_bytes(&s50))?;

    let mut valid = |name: &str, title: &str, input: Value, out: &Mem| {
        cases.push(valid_case(
            &format!("sync/memory/{name}"),
            title,
            "sync.memory",
            vec![],
            input,
            out.expect(),
        ));
    };

    // ---- decode, accepted
    let empty = Mem::default();
    valid(
        "decode_empty",
        "an empty record reads back as it is",
        base_input("decode", Some(&empty.bytes())),
        &empty,
    );
    let three = Mem::new(77, 40, &[(manifest, 4), (a, 3), (b, 5)]);
    valid(
        "decode_three",
        "a record with three items, max_seq 77 and checkpoint_seq 40",
        base_input("decode", Some(&three.bytes())),
        &three,
    );

    // ---- accept_rows, accepted
    let fresh = Mem::default().after(&rows(&s40), 40, None);
    valid(
        "rows_first",
        "no record yet: the rows and the top seq become the floors",
        with_rows(base_input("accept_rows", None), &rows(&s40), 40),
        &fresh,
    );
    let raised = fresh.after(&rows(&s50), 50, None);
    valid(
        "rows_raise",
        "higher revisions and a new item raise the floors",
        with_rows(
            base_input("accept_rows", Some(&fresh.bytes())),
            &rows(&s50),
            50,
        ),
        &raised,
    );
    valid(
        "rows_same",
        "the same revisions at the same top are accepted and change nothing",
        with_rows(
            base_input("accept_rows", Some(&fresh.bytes())),
            &rows(&s40),
            40,
        ),
        &fresh,
    );
    let deleted_a = [dead(a, 4)];
    valid(
        "rows_tombstone_counts",
        "a deleted row also records its revision",
        with_rows(
            base_input("accept_rows", Some(&fresh.bytes())),
            &rows(&deleted_a),
            41,
        ),
        &fresh.after(&rows(&deleted_a), 41, None),
    );

    // ---- verify_checkpoint, accepted
    let mem40 = Mem::new(40, 40, &revs(&s40));
    valid(
        "checkpoint_first",
        "no record yet: a checkpoint that verifies sets all three floors",
        with_checkpoint(
            base_input("verify_checkpoint", None),
            &c1,
            &cp40,
            &rows(&s40),
            40,
        ),
        &Mem::default().after(&rows(&s40), 40, Some(40)),
    );
    valid(
        "checkpoint_newer",
        "a newer checkpoint and the matching rows raise the floors",
        with_checkpoint(
            base_input("verify_checkpoint", Some(&mem40.bytes())),
            &c1,
            &cp50,
            &rows(&s50),
            50,
        ),
        &mem40.after(&rows(&s50), 50, Some(50)),
    );
    valid(
        "checkpoint_same",
        "the checkpoint the device already holds, with a higher top, is accepted",
        with_checkpoint(
            base_input("verify_checkpoint", Some(&mem40.bytes())),
            &c1,
            &cp40,
            &rows(&s40),
            45,
        ),
        &mem40.after(&rows(&s40), 45, Some(40)),
    );
    valid(
        "checkpoint_rows_ahead",
        "newer rows than the checkpoint show: only max_seq and the revisions rise",
        with_checkpoint(
            base_input("verify_checkpoint", Some(&mem40.bytes())),
            &c1,
            &cp40,
            &rows(&s50),
            50,
        ),
        &mem40.after(&rows(&s50), 50, Some(40)),
    );

    // ---- accept_older_state, accepted
    let mem50 = Mem::new(60, 50, &revs(&s50));
    let restored = Mem::default().after(&rows(&s30), 30, Some(30));
    valid(
        "older_state",
        "after the user confirms, the record becomes the older, verified state",
        with_checkpoint(
            base_input("accept_older_state", Some(&mem50.bytes())),
            &c1,
            &cp30,
            &rows(&s30),
            30,
        ),
        &restored,
    );

    drop(valid);
    let mut invalid = |name: &str, title: &str, input: Value, code: &str| {
        cases.push(invalid_case(
            &format!("sync/memory_invalid/{name}"),
            title,
            "sync.memory",
            vec![],
            input,
            code,
        ));
    };

    // ---- decode, refused
    let good = three.bytes();
    let malformed = "malformed_pinned_record";
    let mut wrong_version = good.clone();
    wrong_version[0] = 2;
    invalid(
        "decode_version",
        "another version byte",
        base_input("decode", Some(&wrong_version)),
        malformed,
    );
    invalid(
        "decode_truncated",
        "a record shorter than its header",
        base_input("decode", Some(&good[..20])),
        malformed,
    );
    let mut extra = good.clone();
    extra.push(0);
    invalid(
        "decode_extra_byte",
        "a byte more than the count says",
        base_input("decode", Some(&extra)),
        malformed,
    );
    let mut too_many = vec![1u8];
    too_many.extend_from_slice(&5u64.to_be_bytes());
    too_many.extend_from_slice(&5u64.to_be_bytes());
    too_many.extend_from_slice(&50_001u32.to_be_bytes());
    invalid(
        "decode_count_over_cap",
        "a count above the 50 000 items the record may track",
        base_input("decode", Some(&too_many)),
        malformed,
    );
    let mut unsorted = vec![1u8];
    unsorted.extend_from_slice(&9u64.to_be_bytes());
    unsorted.extend_from_slice(&0u64.to_be_bytes());
    unsorted.extend_from_slice(&2u32.to_be_bytes());
    for item in [b, a] {
        unsorted.extend_from_slice(&item);
        unsorted.extend_from_slice(&1u64.to_be_bytes());
    }
    invalid(
        "decode_unsorted",
        "entries not in ascending order of item_id",
        base_input("decode", Some(&unsorted)),
        malformed,
    );
    let mut twice = vec![1u8];
    twice.extend_from_slice(&9u64.to_be_bytes());
    twice.extend_from_slice(&0u64.to_be_bytes());
    twice.extend_from_slice(&2u32.to_be_bytes());
    for rev in [1u64, 2] {
        twice.extend_from_slice(&a);
        twice.extend_from_slice(&rev.to_be_bytes());
    }
    invalid(
        "decode_repeated_item",
        "the same item_id twice",
        base_input("decode", Some(&twice)),
        malformed,
    );
    let mut above = Mem::new(5, 0, &[]).bytes();
    above[9..17].copy_from_slice(&6u64.to_be_bytes());
    invalid(
        "decode_checkpoint_above_max",
        "checkpoint_seq above max_seq",
        base_input("decode", Some(&above)),
        malformed,
    );

    // ---- accept_rows, refused
    invalid(
        "rows_lower_rev",
        "a row below the highest revision seen for its item",
        with_rows(
            base_input("accept_rows", Some(&fresh.bytes())),
            &rows(&[live(a, 2, "a2")]),
            41,
        ),
        "checkpoint_rev_below_remembered",
    );
    let after_delete = fresh.after(&rows(&deleted_a), 41, None);
    invalid(
        "rows_live_behind_tombstone",
        "a live row older than the deletion the device has seen",
        with_rows(
            base_input("accept_rows", Some(&after_delete.bytes())),
            &rows(&[live(a, 3, "a3")]),
            42,
        ),
        "checkpoint_rev_below_remembered",
    );
    invalid(
        "rows_top_below",
        "the server's top seq is below the highest seen",
        with_rows(
            base_input("accept_rows", Some(&Mem::new(50, 0, &[]).bytes())),
            &[],
            49,
        ),
        "checkpoint_top_seq_below_remembered",
    );
    invalid(
        "rows_one_bad_row_refuses_all",
        "one row below its floor refuses the whole set",
        with_rows(
            base_input("accept_rows", Some(&fresh.bytes())),
            &rows(&[live(b, 6, "b6"), live(a, 2, "a2")]),
            45,
        ),
        "checkpoint_rev_below_remembered",
    );

    // ---- verify_checkpoint, refused
    invalid(
        "checkpoint_older",
        "a valid checkpoint below the highest verified one",
        with_checkpoint(
            base_input("verify_checkpoint", Some(&mem50.bytes())),
            &c1,
            &cp40,
            &rows(&s50),
            60,
        ),
        "checkpoint_seq_below_remembered",
    );
    invalid(
        "checkpoint_whole_vault_rolled_back",
        "an older, consistent checkpoint with its matching older rows",
        with_checkpoint(
            base_input("verify_checkpoint", Some(&mem50.bytes())),
            &c1,
            &cp30,
            &rows(&s30),
            30,
        ),
        "checkpoint_seq_below_remembered",
    );
    invalid(
        "checkpoint_top_below",
        "the checkpoint is not older, but the server's top is below the highest seen",
        with_checkpoint(
            base_input("verify_checkpoint", Some(&mem50.bytes())),
            &c1,
            &cp50,
            &rows(&s50),
            50,
        ),
        "checkpoint_top_seq_below_remembered",
    );
    let high_a = Mem::new(50, 40, &[(a, 7)]);
    invalid(
        "checkpoint_rev_below",
        "a row below the revision the device has seen, though the checkpoint accepts it",
        with_checkpoint(
            base_input("verify_checkpoint", Some(&high_a.bytes())),
            &c1,
            &cp40,
            &rows(&s50),
            50,
        ),
        "checkpoint_rev_below_remembered",
    );
    let mut bad_mac = cp_json(&cp40);
    bad_mac["mac"] = h(&{
        let mut m = cp40.mac;
        m[3] ^= 1;
        m
    });
    let mut bad_input = with_checkpoint(
        base_input("verify_checkpoint", Some(&mem50.bytes())),
        &c1,
        &cp40,
        &rows(&s50),
        60,
    );
    bad_input["checkpoint"] = bad_mac;
    invalid(
        "checkpoint_bad_mac_first",
        "the checkpoint's own checks run before the memory is consulted",
        bad_input,
        "checkpoint_bad_mac",
    );

    // ---- accept_older_state, refused
    let mut bad_older = with_checkpoint(
        base_input("accept_older_state", Some(&mem50.bytes())),
        &c1,
        &cp30,
        &rows(&s30),
        30,
    );
    let mut bad_older_mac = cp_json(&cp30);
    bad_older_mac["mac"] = h(&{
        let mut m = cp30.mac;
        m[0] ^= 1;
        m
    });
    bad_older["checkpoint"] = bad_older_mac;
    invalid(
        "older_state_bad_mac",
        "the older state must verify by itself",
        bad_older,
        "checkpoint_bad_mac",
    );
    invalid(
        "older_state_hidden_item",
        "an older state that hides an item is still refused",
        with_checkpoint(
            base_input("accept_older_state", Some(&mem50.bytes())),
            &c1,
            &cp30,
            &rows(&s30[1..]),
            31,
        ),
        "checkpoint_hidden_or_rolled_back",
    );

    file("sync", "Fase 1 § 8.6", cases)
}
