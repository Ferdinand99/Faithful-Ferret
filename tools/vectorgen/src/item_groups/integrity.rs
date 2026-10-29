//! The vector groups for the integrity layer: tombstones and item tags
//! (`tomb-tag.json`), checkpoints (`checkpoint.json`), mutation and
//! recovery proofs (`proofs.json`) and the full rekey (`rekey.json`).
//!
//! As in the item groups, every expected value is made here from the
//! specification (Fase 1 § 4.5, § 4.6, § 4.7, § 8.4 and § 8.6), with the TLV
//! bytes written out by hand and the entries, digests, MACs and keys worked
//! out again; the core's integrity code is not called. Only the primitive
//! wrappers (AEAD, HKDF, HMAC, Ed25519), which have their own RFC and
//! Wycheproof vectors, are shared.
//!
//! This module is a child of `item_groups` so that it can use the item
//! helpers (`Ctx`, `seal_item`, `pad`, the hand-made CBOR) without making
//! them public.

use super::*;
use crate::key_groups::{commit, kek_recovery, seed_r};
use ferret_core::testing::prim::{ed25519_public_key, ed25519_sign};

// ---------------------------------------------------------------- helpers

fn rev_s(rev: u64) -> Value {
    json!(rev.to_string())
}

fn sha_raw(parts: &[&[u8]]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    for p in parts {
        hasher.update(p);
    }
    hasher.finalize().into()
}

fn hmac(key: &[u8; 32], msg: &[u8]) -> Result<[u8; 32], Error> {
    hmac_sha256(key, msg).map_err(|e| format!("hmac failed: {e}").into())
}

fn flip_at(bytes: &[u8], at: usize) -> Vec<u8> {
    let mut out = bytes.to_vec();
    if let Some(b) = out.get_mut(at) {
        *b ^= 0x01;
    }
    out
}

fn flip_arr(bytes: &[u8; 32], at: usize) -> [u8; 32] {
    let mut out = *bytes;
    if let Some(b) = out.get_mut(at) {
        *b ^= 0x01;
    }
    out
}

fn with_rng(mut case: Case, draws: &[Vec<u8>]) -> Case {
    case.rng = draws.iter().map(|d| hex_encode(d)).collect();
    case
}

fn replay(draws: Vec<Vec<u8>>) -> ReplayRng {
    ReplayRng::new(draws)
}

fn seal_raw(nonce: &[u8; 24], key: &[u8; 32], aad: &[u8], pt: &[u8]) -> Result<Vec<u8>, Error> {
    seal_with(replay(vec![nonce.to_vec()]), key, aad, pt)
}

// ------------------------------------------------------------- tombstones

/// `TLV[label="ferret/v1/tomb", version, suite, vault_id, item_id, rev]`.
fn tomb_aad(version: u8, suite: u8, vault: &[u8; 16], item: &[u8; 16], rev: u64) -> Vec<u8> {
    cat(&[
        label("ferret/v1/tomb"),
        t(0x02, &[version]),
        t(0x03, &[suite]),
        t(0x11, vault),
        t(0x12, item),
        t(0x22, &rev.to_be_bytes()),
    ])
}

fn tomb_input(ctx: &Ctx, item: &[u8; 16], rev: u64) -> Value {
    let mut i = ctx.input();
    i["item_id"] = h(item);
    i["rev"] = rev_s(rev);
    i
}

fn tomb_verify_input(ctx: &Ctx, item: &[u8; 16], rev: u64, tomb: &[u8]) -> Value {
    let mut i = tomb_input(ctx, item, rev);
    i["tomb"] = h(tomb);
    i
}

fn tomb_cases(cases: &mut Vec<Case>) -> Result<(), Error> {
    let c1 = ctx1();
    let c2 = ctx2();
    let k1 = c1.keys()?;
    let k2 = c2.keys()?;

    // ---- tomb.seal
    struct T {
        name: &'static str,
        title: &'static str,
        ctx: Ctx,
        item: u8,
        rev: u64,
    }
    let list = [
        T {
            name: "first",
            title: "a tombstone at revision 2",
            ctx: c1,
            item: 0x41,
            rev: 2,
        },
        T {
            name: "other_vault",
            title: "a tombstone in a later epoch, large revision",
            ctx: c2,
            item: 0x42,
            rev: 0x0102_0304_0506_0708,
        },
        T {
            name: "same_item_next_rev",
            title: "the same item at the next revision",
            ctx: c1,
            item: 0x41,
            rev: 3,
        },
    ];
    let mut sealed: Vec<(Ctx, [u8; 16], u64, Vec<u8>)> = Vec::new();
    for tc in &list {
        let item = id(tc.item);
        let keys = tc.ctx.keys()?;
        let nonce: [u8; 24] = draw(&format!("tomb-tag/tomb/{}/nonce", tc.name));
        let aad = tomb_aad(1, 1, &tc.ctx.vault, &item, tc.rev);
        let tomb = seal_raw(&nonce, &keys.k_del, &aad, &[])?;
        assert_eq!(tomb.len(), 40);
        let mut c = valid_case(
            &format!("tomb-tag/tomb_seal/{}", tc.name),
            tc.title,
            "tomb.seal",
            vec![],
            tomb_input(&tc.ctx, &item, tc.rev),
            json!({ "tomb": h(&tomb) }),
        );
        c.intermediate = Some(json!({ "k_del": h(&keys.k_del), "aad": h(&aad) }));
        cases.push(with_rng(c, &[nonce.to_vec()]));
        cases.push(valid_case(
            &format!("tomb-tag/tomb_verify/{}", tc.name),
            &format!("verifies: {}", tc.title),
            "tomb.verify",
            vec![],
            tomb_verify_input(&tc.ctx, &item, tc.rev, &tomb),
            json!({ "ok": true }),
        ));
        sealed.push((tc.ctx, item, tc.rev, tomb));
    }

    // ---- tomb.verify, refused
    let (ctx, item, rev, tomb) = sealed[0].clone();
    let mut bad = |name: &str, title: &str, input: Value| {
        cases.push(invalid_case(
            &format!("tomb-tag/tomb_invalid/{name}"),
            title,
            "tomb.verify",
            vec![],
            input,
            "tombstone_invalid",
        ));
    };
    bad(
        "item_id",
        "another item_id",
        tomb_verify_input(&ctx, &id(0x44), rev, &tomb),
    );
    bad(
        "rev",
        "another rev",
        tomb_verify_input(&ctx, &item, rev + 1, &tomb),
    );
    bad(
        "vault_id",
        "another vault_id, same keys otherwise",
        tomb_verify_input(
            &Ctx {
                vault: arr(0x32),
                ..ctx
            },
            &item,
            rev,
            &tomb,
        ),
    );
    bad(
        "epoch",
        "another vk_epoch",
        tomb_verify_input(
            &Ctx {
                epoch: ctx.epoch + 1,
                ..ctx
            },
            &item,
            rev,
            &tomb,
        ),
    );
    bad(
        "vault_key",
        "another vault key",
        tomb_verify_input(
            &Ctx {
                vk: arr(0x62),
                ..ctx
            },
            &item,
            rev,
            &tomb,
        ),
    );
    bad(
        "account_id",
        "another account (another K_del)",
        tomb_verify_input(
            &Ctx {
                account: arr(0x12),
                ..ctx
            },
            &item,
            rev,
            &tomb,
        ),
    );
    bad(
        "nonce_bit",
        "a flipped bit in the nonce",
        tomb_verify_input(&ctx, &item, rev, &flip_at(&tomb, 0)),
    );
    bad(
        "tag_bit",
        "a flipped bit in the tag",
        tomb_verify_input(&ctx, &item, rev, &flip_at(&tomb, 39)),
    );
    bad(
        "short",
        "39 bytes",
        tomb_verify_input(&ctx, &item, rev, &tomb[..39]),
    );
    let mut long = tomb.clone();
    long.push(0);
    bad(
        "long",
        "41 bytes",
        tomb_verify_input(&ctx, &item, rev, &long),
    );
    bad(
        "empty",
        "no bytes",
        tomb_verify_input(&ctx, &item, rev, &[]),
    );
    // Sealed under another key with the right AAD.
    let aad = tomb_aad(1, 1, &ctx.vault, &item, rev);
    let nonce: [u8; 24] = draw("tomb-tag/tomb_invalid/nonce");
    for (name, title, key) in [
        ("under_k_head", "sealed under K_head", k1.k_head),
        ("under_k_meta", "sealed under K_meta", k1.k_meta),
        ("under_vault_key", "sealed under VK", ctx.vk),
        ("under_item_key", "sealed under an item key", arr(0x90)),
    ] {
        let wrong = seal_raw(&nonce, &key, &aad, &[])?;
        bad(name, title, tomb_verify_input(&ctx, &item, rev, &wrong));
    }
    // Sealed under K_del with a wrong AAD field.
    for (name, title, aad) in [
        (
            "aad_version",
            "version 2 in the AAD",
            tomb_aad(2, 1, &ctx.vault, &item, rev),
        ),
        (
            "aad_suite",
            "suite 2 in the AAD",
            tomb_aad(1, 2, &ctx.vault, &item, rev),
        ),
        (
            "aad_label",
            "the item label instead of the tomb label",
            cat(&[
                label("ferret/v1/item"),
                t(0x02, &[1]),
                t(0x03, &[1]),
                t(0x11, &ctx.vault),
                t(0x12, &item),
                t(0x22, &rev.to_be_bytes()),
            ]),
        ),
        (
            "aad_no_version",
            "no version field in the AAD",
            cat(&[
                label("ferret/v1/tomb"),
                t(0x03, &[1]),
                t(0x11, &ctx.vault),
                t(0x12, &item),
                t(0x22, &rev.to_be_bytes()),
            ]),
        ),
    ] {
        let wrong = seal_raw(&nonce, &k1.k_del, &aad, &[])?;
        bad(name, title, tomb_verify_input(&ctx, &item, rev, &wrong));
    }
    // A tombstone with a plaintext byte (41 bytes) is refused by length; one
    // for the manifest's reserved id is refused too.
    let manifest_aad = tomb_aad(1, 1, &c2.vault, &[0; 16], 1);
    let reserved = seal_raw(&nonce, &k2.k_del, &manifest_aad, &[])?;
    bad(
        "manifest_id",
        "the reserved manifest item_id cannot be deleted",
        tomb_verify_input(&c2, &[0; 16], 1, &reserved),
    );
    Ok(())
}

// -------------------------------------------------------------- item tags

fn tag_message(item: &[u8; 16], rev: u64, envelope: &[u8]) -> Vec<u8> {
    cat(&[
        label("ferret/v1/item-tag"),
        t(0x12, item),
        t(0x22, &rev.to_be_bytes()),
        t(0x35, &sha_raw(&[envelope])),
    ])
}

fn tag_input(ctx: &Ctx, item: &[u8; 16], rev: u64, envelope: &[u8]) -> Value {
    let mut i = ctx.input();
    i["item_id"] = h(item);
    i["rev"] = rev_s(rev);
    i["envelope"] = h(envelope);
    i
}

/// Name, title, vault state, item id, revision, envelope and tag.
type TagPart = (
    &'static str,
    &'static str,
    Ctx,
    [u8; 16],
    u64,
    Vec<u8>,
    [u8; 32],
);

fn tag_cases(cases: &mut Vec<Case>) -> Result<(), Error> {
    let c1 = ctx1();
    let c2 = ctx2();
    let login = Body::new("login", "Example");
    let mut note = Body::new("note", "Shopping");
    note.notes = Some("milk".into());
    let a = seal_item(
        "tomb-tag/tag/a",
        &c1,
        id(0x41),
        3,
        &login.cbor(),
        None,
        &GOOD_ITEM,
    )?;
    let b = seal_item(
        "tomb-tag/tag/b",
        &c2,
        id(0x42),
        9,
        &note.cbor(),
        None,
        &GOOD_ITEM,
    )?;
    let m = seal_manifest(
        "tomb-tag/tag/m",
        &c1,
        5,
        &manifest_cbor(1, 1, &[method(1, 0x70, 1, &[])], &[]),
    )?;
    let parts: [TagPart; 3] = [
        (
            "item_a",
            "an item",
            c1,
            a.id,
            a.rev,
            a.envelope.clone(),
            a.tag,
        ),
        (
            "item_b",
            "an item in a later epoch",
            c2,
            b.id,
            b.rev,
            b.envelope.clone(),
            b.tag,
        ),
        (
            "manifest",
            "the manifest has a tag under the reserved id",
            c1,
            [0; 16],
            m.rev,
            m.envelope.clone(),
            m.tag,
        ),
    ];
    for (name, title, ctx, item, rev, envelope, tag) in &parts {
        let message = tag_message(item, *rev, envelope);
        let expect = hmac(&ctx.keys()?.k_head, &message)?;
        assert_eq!(&expect, tag);
        let mut c = valid_case(
            &format!("tomb-tag/item_tag/{name}"),
            title,
            "item.tag",
            vec![],
            tag_input(ctx, item, *rev, envelope),
            json!({ "tag": h(tag) }),
        );
        c.intermediate = Some(json!({ "message": h(&message) }));
        cases.push(c);
        let mut v = tag_input(ctx, item, *rev, envelope);
        v["tag"] = h(tag);
        cases.push(valid_case(
            &format!("tomb-tag/item_tag_verify/{name}"),
            &format!("verifies: {title}"),
            "item.tag.verify",
            vec![],
            v,
            json!({ "ok": true }),
        ));
    }

    // The tag binds every field: item_id, rev, the blob, the key, the tag.
    let (_, _, ctx, item, rev, envelope, tag) = parts[0].clone();
    let mut bad = |name: &str,
                   title: &str,
                   ctx: &Ctx,
                   item: &[u8; 16],
                   rev: u64,
                   env: &[u8],
                   tag: &[u8; 32]| {
        let mut v = tag_input(ctx, item, rev, env);
        v["tag"] = h(tag);
        cases.push(invalid_case(
            &format!("tomb-tag/item_tag_invalid/{name}"),
            title,
            "item.tag.verify",
            vec![],
            v,
            "decrypt",
        ));
    };
    bad(
        "item_id",
        "another item_id",
        &ctx,
        &id(0x43),
        rev,
        &envelope,
        &tag,
    );
    bad("rev", "another rev", &ctx, &item, rev + 1, &envelope, &tag);
    bad(
        "blob_bit",
        "a flipped bit in the blob",
        &ctx,
        &item,
        rev,
        &flip_at(&envelope, 100),
        &tag,
    );
    let mut longer = envelope.clone();
    longer.push(0);
    bad(
        "blob_longer",
        "one byte more in the blob",
        &ctx,
        &item,
        rev,
        &longer,
        &tag,
    );
    bad(
        "tag_bit",
        "a flipped bit in the tag",
        &ctx,
        &item,
        rev,
        &envelope,
        &flip_arr(&tag, 5),
    );
    bad(
        "vault_key",
        "another vault key (another K_head)",
        &Ctx {
            vk: arr(0x62),
            ..ctx
        },
        &item,
        rev,
        &envelope,
        &tag,
    );
    bad(
        "epoch",
        "another vk_epoch (another K_head)",
        &Ctx { epoch: 2, ..ctx },
        &item,
        rev,
        &envelope,
        &tag,
    );
    // The tag of the other item, from the same vault: a different blob.
    let other = seal_item(
        "tomb-tag/tag/c",
        &c1,
        id(0x41),
        3,
        &Body::new("note", "x").cbor(),
        None,
        &GOOD_ITEM,
    )?;
    bad(
        "other_blob_same_ids",
        "the tag of another blob with the same item_id and rev",
        &ctx,
        &item,
        rev,
        &envelope,
        &other.tag,
    );
    // The tag under K_del or the checkpoint label is not an item tag.
    let k = ctx.keys()?;
    let under_del = hmac(&k.k_del, &tag_message(&item, rev, &envelope))?;
    bad(
        "under_k_del",
        "a tag made with K_del",
        &ctx,
        &item,
        rev,
        &envelope,
        &under_del,
    );
    let wrong_label = hmac(
        &k.k_head,
        &cat(&[
            label("ferret/v1/checkpoint"),
            t(0x12, &item),
            t(0x22, &rev.to_be_bytes()),
            t(0x35, &sha_raw(&[&envelope])),
        ]),
    )?;
    bad(
        "label",
        "a tag made with another label",
        &ctx,
        &item,
        rev,
        &envelope,
        &wrong_label,
    );
    Ok(())
}

pub(crate) fn tomb_tag() -> Result<Vec<u8>, Error> {
    let mut cases = Vec::new();
    tomb_cases(&mut cases)?;
    tag_cases(&mut cases)?;
    file("tomb-tag", "Fase 1 § 8.4 and § 8.6", cases)
}

// ------------------------------------------------------------- checkpoints

#[derive(Clone, Copy)]
struct Ent {
    id: [u8; 16],
    rev: u64,
    hash: Option<[u8; 32]>,
}

impl Ent {
    fn json(&self) -> Value {
        json!({
            "item_id": h(&self.id),
            "rev": rev_s(self.rev),
            "hash": self.hash.as_ref().map_or(Value::Null, |x| h(x)),
        })
    }
}

/// The `entries` bytes: sorted ascending by the raw bytes of `item_id`,
/// `item_id ‖ u64be(rev) ‖ h` each. Written out here, not taken from the
/// core.
fn entries_bytes(list: &[Ent]) -> Vec<u8> {
    let mut sorted = list.to_vec();
    sorted.sort_by_key(|e| e.id);
    let mut out = Vec::new();
    for e in &sorted {
        out.extend_from_slice(&e.id);
        out.extend_from_slice(&e.rev.to_be_bytes());
        out.extend_from_slice(&e.hash.unwrap_or([0; 32]));
    }
    out
}

fn cp_message(seq: u64, digest: &[u8; 32]) -> Vec<u8> {
    cat(&[
        label("ferret/v1/checkpoint"),
        t(0x23, &seq.to_be_bytes()),
        t(0x35, digest),
    ])
}

struct Cp {
    seq: u64,
    entries: Vec<u8>,
    digest: [u8; 32],
    mac: [u8; 32],
}

fn make_cp(k_head: &[u8; 32], seq: u64, entries: Vec<u8>) -> Result<Cp, Error> {
    let digest = sha_raw(&[&entries]);
    let mac = hmac(k_head, &cp_message(seq, &digest))?;
    Ok(Cp {
        seq,
        entries,
        digest,
        mac,
    })
}

/// `count` entries from a fixed recipe, in index order (not sorted):
/// `item_id` is the first 16 bytes of `SHA-256("ferret/checkpoint-vector/id"
/// ‖ u32be(i))`, `rev = 1 + i mod 7`, and `h` is
/// `SHA-256("ferret/checkpoint-vector/hash" ‖ u32be(i))`, or a tombstone
/// when `i mod 5 = 0`.
fn generated(count: u32) -> Vec<Ent> {
    (0..count)
        .map(|i| {
            let idh = sha_raw(&[b"ferret/checkpoint-vector/id", &i.to_be_bytes()]);
            let mut id = [0u8; 16];
            id.copy_from_slice(&idh[..16]);
            Ent {
                id,
                rev: 1 + u64::from(i % 7),
                hash: if i % 5 == 0 {
                    None
                } else {
                    Some(sha_raw(&[
                        b"ferret/checkpoint-vector/hash",
                        &i.to_be_bytes(),
                    ]))
                },
            }
        })
        .collect()
}

#[derive(Clone, Copy)]
struct Row {
    id: [u8; 16],
    rev: u64,
    /// `None`: deleted.
    hash: Option<[u8; 32]>,
}

impl Row {
    fn json(&self) -> Value {
        match &self.hash {
            Some(x) => json!({
                "item_id": h(&self.id), "rev": rev_s(self.rev), "state": "live", "hash": h(x),
            }),
            None => json!({
                "item_id": h(&self.id), "rev": rev_s(self.rev), "state": "deleted",
            }),
        }
    }
}

impl From<Ent> for Row {
    fn from(e: Ent) -> Self {
        Row {
            id: e.id,
            rev: e.rev,
            hash: e.hash,
        }
    }
}

fn blob(tag: &str) -> [u8; 32] {
    sha_raw(&[b"ferret/checkpoint-vector/blob/", tag.as_bytes()])
}

fn cp_json(cp: &Cp) -> Value {
    json!({
        "seq": cp.seq.to_string(),
        "digest": h(&cp.digest),
        "mac": h(&cp.mac),
        "entries": h(&cp.entries),
    })
}

fn verify_input(ctx: &Ctx, cp: Value, rows: Vec<Row>, top: u64) -> Value {
    let mut i = ctx.input();
    i["checkpoint"] = cp;
    i["rows"] = Value::Array(rows.iter().map(Row::json).collect());
    i["top_seq"] = rev_s(top);
    i
}

fn make_input(ctx: &Ctx, seq: u64, list: &[Ent]) -> Value {
    let mut i = ctx.input();
    i["seq"] = rev_s(seq);
    i["entries"] = Value::Array(list.iter().map(Ent::json).collect());
    i
}

/// The expected output of `checkpoint.make`: the entries themselves when
/// they are at most 20 rows, their length and SHA-256 always.
fn make_expect(cp: &Cp) -> Value {
    let mut e = json!({
        "entries_len": cp.entries.len(),
        "entries_sha256": h(&sha_raw(&[&cp.entries])),
        "digest": h(&cp.digest),
        "mac": h(&cp.mac),
    });
    if cp.entries.len() <= 20 * 56 {
        e["entries"] = h(&cp.entries);
    }
    e
}

fn checkpoint_cases(cases: &mut Vec<Case>) -> Result<(), Error> {
    let c1 = ctx1();
    let c2 = ctx2();
    let k1 = c1.keys()?;

    // ---- the base state, in the order a client might hold it
    let live = |b: u8, rev: u64, tag: &str| Ent {
        id: id(b),
        rev,
        hash: Some(blob(tag)),
    };
    let tomb = |b: u8, rev: u64| Ent {
        id: id(b),
        rev,
        hash: None,
    };
    let mut high_a = [0x7f; 16];
    high_a[15] = 1;
    let mut high_b = [0x80; 16];
    high_b[15] = 1;
    let state: Vec<Ent> = vec![
        Ent {
            id: [0xff; 16],
            rev: 1,
            hash: None,
        },
        live(0x42, 5, "b"),
        Ent {
            id: high_b,
            rev: 6,
            hash: Some(blob("high-b")),
        },
        live(0x41, 3, "a"),
        tomb(0x43, 2),
        Ent {
            id: [0; 16],
            rev: 4,
            hash: Some(blob("manifest")),
        },
        Ent {
            id: high_a,
            rev: 1,
            hash: Some(blob("high-a")),
        },
    ];
    let seq = 40;
    let bytes = entries_bytes(&state);
    assert_eq!(bytes.len(), 56 * state.len());
    let cp = make_cp(&k1.k_head, seq, bytes.clone())?;
    // The sorted order, spelled out: the manifest id (zeros), 0x41.., 0x42..,
    // 0x43.., 0x7f.., 0x80.. and 0xff.. (an unsigned comparison).
    let order: Vec<&[u8]> = bytes.chunks(56).map(|c| &c[..16]).collect();
    assert!(order.windows(2).all(|w| w[0] < w[1]));

    // ---- checkpoint.make
    let mut make =
        |name: &str, title: &str, ctx: &Ctx, seq: u64, list: &[Ent]| -> Result<(), Error> {
            let keys = ctx.keys()?;
            let cp = make_cp(&keys.k_head, seq, entries_bytes(list))?;
            let mut c = valid_case(
                &format!("checkpoint/make/{name}"),
                title,
                "checkpoint.make",
                vec![],
                make_input(ctx, seq, list),
                make_expect(&cp),
            );
            c.intermediate = Some(json!({ "message": h(&cp_message(seq, &cp.digest)) }));
            cases.push(c);
            Ok(())
        };
    make(
        "seven_rows",
        "seven rows given in no order; the output is sorted",
        &c1,
        seq,
        &state,
    )?;
    let mut reversed = state.clone();
    reversed.reverse();
    make(
        "reversed_input",
        "the same rows in reverse order give the same entries",
        &c1,
        seq,
        &reversed,
    )?;
    make("empty", "no rows", &c1, 0, &[])?;
    make(
        "one_live",
        "a single live row",
        &c2,
        7,
        &[live(0x41, 1, "a")],
    )?;
    make(
        "one_tombstone",
        "a single tombstone has 32 zero bytes as its hash",
        &c2,
        7,
        &[tomb(0x41, 9)],
    )?;
    make(
        "large_rev_and_seq",
        "revision and seq above 2^53",
        &c2,
        u64::MAX,
        &[Ent {
            id: id(0x50),
            rev: 0x0102_0304_0506_0708,
            hash: Some(blob("big")),
        }],
    )?;
    make(
        "last_byte_differs",
        "ids that differ only in the last byte",
        &c1,
        3,
        &[
            Ent {
                id: {
                    let mut x = id(0x60);
                    x[15] = 0xff;
                    x
                },
                rev: 1,
                hash: Some(blob("1")),
            },
            Ent {
                id: {
                    let mut x = id(0x60);
                    x[15] = 0x00;
                    x
                },
                rev: 1,
                hash: Some(blob("2")),
            },
            Ent {
                id: {
                    let mut x = id(0x60);
                    x[15] = 0x80;
                    x
                },
                rev: 1,
                hash: Some(blob("3")),
            },
        ],
    )?;
    // A live row whose hash is 32 zero bytes would read back as a tombstone.
    cases.push(invalid_case(
        "checkpoint/make/live_zero_hash",
        "a live row whose hash is 32 zero bytes",
        "checkpoint.make",
        vec![],
        make_input(
            &c1,
            seq,
            &[Ent {
                id: id(0x41),
                rev: 1,
                hash: Some([0; 32]),
            }],
        ),
        "malformed_entries",
    ));
    // Duplicate item ids are refused.
    let mut dup = state.clone();
    dup.push(live(0x41, 9, "dup"));
    cases.push(invalid_case(
        "checkpoint/make/duplicate_item_id",
        "two rows with the same item_id",
        "checkpoint.make",
        vec![],
        make_input(&c1, seq, &dup),
        "malformed_entries",
    ));
    // 10 000 rows, generated.
    let big = generated(10_000);
    let big_cp = make_cp(&k1.k_head, 123_456, entries_bytes(&big))?;
    assert_eq!(big_cp.entries.len(), 560_000);
    let mut input = c1.input();
    input["seq"] = rev_s(123_456);
    input["generate"] = json!({ "count": 10_000 });
    let mut c = valid_case(
        "checkpoint/make/ten_thousand",
        "10 000 generated rows (560 000 bytes of entries)",
        "checkpoint.make",
        vec![],
        input,
        make_expect(&big_cp),
    );
    c.intermediate = Some(json!({ "message": h(&cp_message(123_456, &big_cp.digest)) }));
    cases.push(c);

    // ---- checkpoint.verify, accepted
    let rows_of = |list: &[Ent]| -> Vec<Row> { list.iter().copied().map(Row::from).collect() };
    let same = rows_of(&state);
    let mut ok = |name: &str, title: &str, ctx: &Ctx, cp: &Cp, rows: Vec<Row>, top: u64| {
        cases.push(valid_case(
            &format!("checkpoint/verify/{name}"),
            title,
            "checkpoint.verify",
            vec![],
            verify_input(ctx, cp_json(cp), rows, top),
            json!({ "ok": true }),
        ));
    };
    ok(
        "consistent_at_top",
        "rows equal the entries and the top is the checkpoint's seq",
        &c1,
        &cp,
        same.clone(),
        seq,
    );
    let mut shuffled = same.clone();
    shuffled.reverse();
    ok(
        "rows_in_any_order",
        "the order of the rows does not matter",
        &c1,
        &cp,
        shuffled,
        seq,
    );
    ok(
        "consistent_below_top",
        "the same rows with a higher top",
        &c1,
        &cp,
        same.clone(),
        seq + 5,
    );
    let mut newer = same.clone();
    for r in &mut newer {
        if r.id == id(0x42) {
            r.rev = 6;
            r.hash = Some(blob("b2"));
        }
    }
    newer.push(Row {
        id: id(0x44),
        rev: 1,
        hash: Some(blob("new")),
    });
    ok(
        "newer_rows_and_a_new_item",
        "a higher revision and a new item",
        &c1,
        &cp,
        newer,
        seq + 5,
    );
    let gone: Vec<Row> = same.iter().copied().filter(|r| r.hash.is_some()).collect();
    ok(
        "tombstones_may_be_missing",
        "tombstone entries need no row (tombstones expire)",
        &c1,
        &cp,
        gone,
        seq + 5,
    );
    let purged: Vec<Row> = same.iter().copied().filter(|r| r.hash.is_some()).collect();
    ok(
        "top_purged_tombstone",
        "at the top, a tombstone entry without a row is accepted (the server purged it)",
        &c1,
        &cp,
        purged,
        seq,
    );
    let mut purged_one = same.clone();
    purged_one.retain(|r| r.id != id(0x43));
    ok(
        "top_purged_one_tombstone",
        "at the top, one purged tombstone, the other rows as they were",
        &c1,
        &cp,
        purged_one,
        seq,
    );
    let mut deleted_later = same.clone();
    for r in &mut deleted_later {
        if r.id == id(0x41) {
            r.rev = 4;
            r.hash = None;
        }
    }
    ok(
        "deleted_later",
        "a live entry that is now a tombstone with a higher revision",
        &c1,
        &cp,
        deleted_later,
        seq + 5,
    );
    let mut revived = same.clone();
    for r in &mut revived {
        if r.id == id(0x43) {
            r.rev = 3;
            r.hash = Some(blob("revived"));
        }
    }
    ok(
        "revived",
        "a tombstone entry that is live again with a higher revision",
        &c1,
        &cp,
        revived,
        seq + 5,
    );
    let mut tomb_up = same.clone();
    for r in &mut tomb_up {
        if r.id == id(0x43) {
            r.rev = 8;
        }
    }
    ok(
        "tombstone_rev_up",
        "a tombstone entry seen as a tombstone with a higher revision",
        &c1,
        &cp,
        tomb_up,
        seq + 5,
    );
    let empty_cp = make_cp(&k1.k_head, 0, vec![])?;
    ok(
        "empty_state",
        "an empty checkpoint and no rows",
        &c1,
        &empty_cp,
        vec![],
        0,
    );
    ok(
        "empty_checkpoint_newer_rows",
        "an empty checkpoint, rows added since",
        &c1,
        &empty_cp,
        same.clone(),
        9,
    );

    // ---- checkpoint.verify, refused
    let mut bad =
        |name: &str, title: &str, ctx: &Ctx, cpv: Value, rows: Vec<Row>, top: u64, code: &str| {
            cases.push(invalid_case(
                &format!("checkpoint/verify_invalid/{name}"),
                title,
                "checkpoint.verify",
                vec![],
                verify_input(ctx, cpv, rows, top),
                code,
            ));
        };
    // 2. MAC and digest.
    let mut bad_mac = cp_json(&cp);
    bad_mac["mac"] = h(&flip_arr(&cp.mac, 3));
    bad(
        "bad_mac",
        "a flipped bit in the MAC",
        &c1,
        bad_mac,
        same.clone(),
        seq,
        "checkpoint_bad_mac",
    );
    let mut bad_seq = cp_json(&cp);
    bad_seq["seq"] = rev_s(seq + 1);
    bad(
        "seq_not_covered",
        "the MAC covers seq: another seq fails",
        &c1,
        bad_seq,
        same.clone(),
        seq + 9,
        "checkpoint_bad_mac",
    );
    let mut bad_digest_field = cp_json(&cp);
    bad_digest_field["digest"] = h(&flip_arr(&cp.digest, 0));
    bad(
        "digest_field",
        "a flipped bit in the digest: the MAC no longer fits",
        &c1,
        bad_digest_field,
        same.clone(),
        seq,
        "checkpoint_bad_mac",
    );
    bad(
        "other_key",
        "a checkpoint made under another K_head",
        &c2,
        cp_json(&cp),
        same.clone(),
        seq,
        "checkpoint_bad_mac",
    );
    let mut bad_entries = cp_json(&cp);
    bad_entries["entries"] = h(&flip_at(&cp.entries, 20));
    bad(
        "entries_bit",
        "a flipped bit in the entries: the digest does not fit",
        &c1,
        bad_entries,
        same.clone(),
        seq,
        "checkpoint_bad_digest",
    );
    let mut short_entries = cp_json(&cp);
    short_entries["entries"] = h(&cp.entries[..cp.entries.len() - 56]);
    bad(
        "entries_cut",
        "the last row cut off the entries",
        &c1,
        short_entries,
        same.clone(),
        seq,
        "checkpoint_bad_digest",
    );
    // Authentic but malformed entries (made with the right key).
    let mut unsorted = cp.entries.clone();
    let (first, rest) = unsorted.split_at_mut(56);
    first.swap_with_slice(&mut rest[..56]);
    let unsorted_cp = make_cp(&k1.k_head, seq, unsorted)?;
    bad(
        "entries_unsorted",
        "entries that are authentic but not sorted",
        &c1,
        cp_json(&unsorted_cp),
        same.clone(),
        seq,
        "malformed_entries",
    );
    let mut ragged = cp.entries.clone();
    ragged.push(7);
    let ragged_cp = make_cp(&k1.k_head, seq, ragged)?;
    bad(
        "entries_ragged",
        "entries that are authentic but 1 byte too long",
        &c1,
        cp_json(&ragged_cp),
        same.clone(),
        seq,
        "malformed_entries",
    );
    let mut twice = cp.entries[..56].to_vec();
    twice.extend_from_slice(&cp.entries[..56]);
    let twice_cp = make_cp(&k1.k_head, seq, twice)?;
    bad(
        "entries_repeat",
        "entries that are authentic but repeat an item_id",
        &c1,
        cp_json(&twice_cp),
        same.clone(),
        seq,
        "malformed_entries",
    );
    // seq above the top.
    bad(
        "seq_above_top",
        "the checkpoint is for a seq above the server's top",
        &c1,
        cp_json(&cp),
        same.clone(),
        seq - 1,
        "checkpoint_seq_above_top",
    );
    // 3. A live entry.
    let without = |wanted: [u8; 16]| -> Vec<Row> {
        same.iter().copied().filter(|r| r.id != wanted).collect()
    };
    bad(
        "hidden_item",
        "a live item is missing from the server's rows",
        &c1,
        cp_json(&cp),
        without(id(0x42)),
        seq + 5,
        "checkpoint_hidden_or_rolled_back",
    );
    bad(
        "hidden_manifest",
        "the manifest row is missing",
        &c1,
        cp_json(&cp),
        without([0; 16]),
        seq + 5,
        "checkpoint_hidden_or_rolled_back",
    );
    let mut lower = same.clone();
    for r in &mut lower {
        if r.id == id(0x42) {
            r.rev = 4;
        }
    }
    bad(
        "lower_rev",
        "a live item at a lower revision",
        &c1,
        cp_json(&cp),
        lower,
        seq + 5,
        "checkpoint_lower_rev",
    );
    let mut other_hash = same.clone();
    for r in &mut other_hash {
        if r.id == id(0x42) {
            r.hash = Some(blob("other"));
        }
    }
    bad(
        "same_rev_other_hash",
        "the same revision with another blob",
        &c1,
        cp_json(&cp),
        other_hash.clone(),
        seq + 5,
        "checkpoint_same_rev_different_hash",
    );
    let mut deleted_same = same.clone();
    for r in &mut deleted_same {
        if r.id == id(0x42) {
            r.hash = None;
        }
    }
    bad(
        "deleted_at_same_rev",
        "a live entry shown as a tombstone at the same revision",
        &c1,
        cp_json(&cp),
        deleted_same,
        seq + 5,
        "checkpoint_same_rev_different_hash",
    );
    let mut deleted_lower = same.clone();
    for r in &mut deleted_lower {
        if r.id == id(0x42) {
            r.rev = 4;
            r.hash = None;
        }
    }
    bad(
        "deleted_at_lower_rev",
        "a live entry shown as a tombstone at a lower revision",
        &c1,
        cp_json(&cp),
        deleted_lower,
        seq + 5,
        "checkpoint_lower_rev",
    );
    // 4. A tombstone entry.
    let mut behind = same.clone();
    for r in &mut behind {
        if r.id == id(0x43) {
            r.rev = 1;
            r.hash = Some(blob("old"));
        }
    }
    bad(
        "live_behind_tombstone",
        "a live row with a lower revision than the tombstone",
        &c1,
        cp_json(&cp),
        behind,
        seq + 5,
        "checkpoint_live_behind_tombstone",
    );
    let mut live_same = same.clone();
    for r in &mut live_same {
        if r.id == id(0x43) {
            r.hash = Some(blob("old"));
        }
    }
    bad(
        "live_at_tombstone_rev",
        "a live row at the revision of the tombstone",
        &c1,
        cp_json(&cp),
        live_same,
        seq + 5,
        "checkpoint_same_rev_different_hash",
    );
    let mut tomb_lower = same.clone();
    for r in &mut tomb_lower {
        if r.id == id(0x43) {
            r.rev = 1;
        }
    }
    bad(
        "tombstone_rolled_back",
        "a tombstone at a lower revision than the checkpoint's",
        &c1,
        cp_json(&cp),
        tomb_lower,
        seq + 5,
        "checkpoint_lower_rev",
    );
    // 5. At the top, the rows must equal the entries.
    let mut extra = same.clone();
    extra.push(Row {
        id: id(0x44),
        rev: 1,
        hash: Some(blob("extra")),
    });
    bad(
        "top_extra_row",
        "at the top, a row that the checkpoint does not have",
        &c1,
        cp_json(&cp),
        extra.clone(),
        seq,
        "checkpoint_top_digest_mismatch",
    );
    let mut higher = same.clone();
    for r in &mut higher {
        if r.id == id(0x42) {
            r.rev = 6;
            r.hash = Some(blob("b2"));
        }
    }
    bad(
        "top_higher_rev",
        "at the top, a higher revision than the checkpoint's",
        &c1,
        cp_json(&cp),
        higher,
        seq,
        "checkpoint_top_digest_mismatch",
    );
    bad(
        "top_changed_hash",
        "at the top, a blob changed without a new revision (found by the entry check first)",
        &c1,
        cp_json(&cp),
        other_hash,
        seq,
        "checkpoint_same_rev_different_hash",
    );
    for (name, title, wanted) in [
        (
            "top_missing_live",
            "at the top, a live item is missing",
            id(0x42),
        ),
        (
            "top_missing_manifest",
            "at the top, the manifest row is missing",
            [0u8; 16],
        ),
    ] {
        bad(
            name,
            title,
            &c1,
            cp_json(&cp),
            without(wanted),
            seq,
            "checkpoint_top_digest_mismatch",
        );
    }
    // A tombstone row that the checkpoint has as a tombstone at an older
    // revision is a roll back even at the top.
    let mut tomb_other_rev = same.clone();
    for r in &mut tomb_other_rev {
        if r.id == id(0x43) {
            r.rev = 9;
        }
    }
    bad(
        "top_tombstone_higher_rev",
        "at the top, a tombstone at a higher revision than the checkpoint's",
        &c1,
        cp_json(&cp),
        tomb_other_rev,
        seq,
        "checkpoint_top_digest_mismatch",
    );
    // A live row whose hash is 32 zero bytes cannot be told from a tombstone.
    let mut zero_row = same.clone();
    zero_row.push(Row {
        id: id(0x44),
        rev: 1,
        hash: Some([0; 32]),
    });
    bad(
        "live_row_with_zero_hash",
        "a live row whose hash is 32 zero bytes",
        &c1,
        cp_json(&cp),
        zero_row,
        seq + 5,
        "malformed_entries",
    );
    // Rows.
    let mut twice_row = same.clone();
    twice_row.push(same[0]);
    bad(
        "duplicate_rows",
        "the same item_id twice in the server's rows",
        &c1,
        cp_json(&cp),
        twice_row,
        seq + 5,
        "malformed_entries",
    );

    // ---- 10 000 rows
    let big_cp_json = json!({
        "seq": "123456",
        "digest": h(&big_cp.digest),
        "mac": h(&big_cp.mac),
        "generate": { "count": 10_000 },
    });
    let mut v = c1.input();
    v["checkpoint"] = big_cp_json.clone();
    v["rows"] = json!({ "all_entries": true, "omit": [] });
    v["top_seq"] = rev_s(123_456);
    cases.push(valid_case(
        "checkpoint/verify/ten_thousand",
        "10 000 rows equal to the entries, at the top",
        "checkpoint.verify",
        vec![],
        v,
        json!({ "ok": true }),
    ));
    let mut v = c1.input();
    v["checkpoint"] = big_cp_json.clone();
    v["top_seq"] = rev_s(200_000);
    // One live row of the sorted entries is hidden (a tombstone may be
    // missing without harm, so the case picks a live one).
    let sorted_big = {
        let mut s = generated(10_000);
        s.sort_by_key(|e| e.id);
        s
    };
    let live_index = (4_321..sorted_big.len())
        .find(|i| sorted_big[*i].hash.is_some())
        .ok_or("no live row")?;
    v["rows"] = json!({ "all_entries": true, "omit": [live_index] });
    cases.push(invalid_case(
        "checkpoint/verify_invalid/ten_thousand_hidden",
        "10 000 entries, one live row hidden",
        "checkpoint.verify",
        vec![],
        v,
        "checkpoint_hidden_or_rolled_back",
    ));
    let mut v = c1.input();
    v["checkpoint"] = big_cp_json;
    v["rows"] = json!({ "all_entries": true, "omit": [] });
    v["top_seq"] = rev_s(123_455);
    cases.push(invalid_case(
        "checkpoint/verify_invalid/ten_thousand_seq_above_top",
        "10 000 entries, the top is below the checkpoint's seq",
        "checkpoint.verify",
        vec![],
        v,
        "checkpoint_seq_above_top",
    ));
    Ok(())
}

pub(crate) fn checkpoint() -> Result<Vec<u8>, Error> {
    let mut cases = Vec::new();
    checkpoint_cases(&mut cases)?;
    file("checkpoint", "Fase 1 § 8.6", cases)
}

// ----------------------------------------------------------------- proofs

const OPS: [&str; 6] = [
    "unlock-method.add",
    "unlock-method.remove",
    "unlock-method.password.put",
    "unlock-method.recovery.put",
    "recover",
    "rekey",
];

/// `TLV[label, op, account_id, nonce, vk_epoch, hash = SHA-256(body)]`.
fn proof_message(
    label_s: &str,
    op: &str,
    account: &[u8; 16],
    nonce: &[u8; 32],
    epoch: u64,
    body: &[u8],
) -> Vec<u8> {
    cat(&[
        label(label_s),
        t(0x36, op.as_bytes()),
        t(0x10, account),
        t(0x33, nonce),
        t(0x20, &epoch.to_be_bytes()),
        t(0x35, &sha_raw(&[body])),
    ])
}

fn label_of(op: &str) -> &'static str {
    if op == "recover" {
        "ferret/v1/recovery-req"
    } else {
        "ferret/v1/mutation"
    }
}

fn verify_proof_input(
    pk: &[u8; 32],
    op: &str,
    account: &[u8; 16],
    nonce: &[u8; 32],
    epoch: u64,
    body: &[u8],
    sig: &[u8; 64],
) -> Value {
    json!({
        "pk": h(pk),
        "op": op,
        "account_id": h(account),
        "nonce": h(nonce),
        "vk_epoch": epoch.to_string(),
        "body": h(body),
        "proof": h(sig),
    })
}

/// The group order of Ed25519, little-endian.
const L_LE: [u8; 32] = [
    0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x10,
];

/// `sig` with `S` replaced by `S + L`: the same point equation holds, but `S`
/// is not canonical, and strict verification refuses it.
fn malleable(sig: &[u8; 64]) -> [u8; 64] {
    let mut out = *sig;
    let mut carry = 0u16;
    for (byte, l) in out.iter_mut().skip(32).zip(L_LE) {
        let sum = u16::from(*byte) + u16::from(l) + carry;
        *byte = (sum & 0xff) as u8;
        carry = sum >> 8;
    }
    assert_eq!(carry, 0);
    out
}

fn proof_cases(cases: &mut Vec<Case>) -> Result<(), Error> {
    let c1 = ctx1();
    let c2 = ctx2();
    let nonce: [u8; 32] = arr(0xa0);
    let nonce2: [u8; 32] = arr(0xa1);

    // ---- proof.sign with sk_a
    let bodies: [(&str, Vec<u8>); 3] = [
        ("json", br#"{"method_type":3,"method_id":"01"}"#.to_vec()),
        ("empty", vec![]),
        ("binary", (0u8..=255).collect()),
    ];
    let mut signed: Vec<(Ctx, &str, Vec<u8>, [u8; 64])> = Vec::new();
    for (n, op) in OPS.iter().enumerate().filter(|(_, op)| **op != "recover") {
        let ctx = if n % 2 == 0 { c1 } else { c2 };
        let (bname, body) = &bodies[n % bodies.len()];
        let keys = ctx.keys()?;
        let message = proof_message(label_of(op), op, &ctx.account, &nonce, ctx.epoch, body);
        let sig = ed25519_sign(&keys.seed_a, &message).map_err(|e| format!("sign failed: {e}"))?;
        let pk = ed25519_public_key(&keys.seed_a);
        let mut input = ctx.input();
        input["op"] = json!(op);
        input["nonce"] = h(&nonce);
        input["body"] = h(body);
        let mut c = valid_case(
            &format!("proofs/sign/{}_{bname}", op.replace(['.', '-'], "_")),
            &format!("proof for {op}, {bname} body"),
            "proof.sign",
            vec![],
            input,
            json!({ "proof": h(&sig), "pk_a": h(&pk) }),
        );
        c.intermediate = Some(json!({ "message": h(&message) }));
        cases.push(c);
        cases.push(valid_case(
            &format!("proofs/verify/{}", op.replace(['.', '-'], "_")),
            &format!("verifies: proof for {op}"),
            "proof.verify",
            vec![],
            verify_proof_input(&pk, op, &ctx.account, &nonce, ctx.epoch, body, &sig),
            json!({ "ok": true }),
        ));
        signed.push((ctx, *op, body.clone(), sig));
    }
    // `recover` is not signed by sk_a.
    let mut input = c1.input();
    input["op"] = json!("recover");
    input["nonce"] = h(&nonce);
    input["body"] = h(b"{}");
    cases.push(invalid_case(
        "proofs/sign_invalid/recover_with_auth_key",
        "sk_a does not sign a recover request",
        "proof.sign",
        vec![],
        input,
        "unsupported",
    ));

    // ---- recovery proof with sk_r
    let rk: [u8; 32] = arr(0xc0);
    let rbody = br#"{"wrap":"..","pk_a":".."}"#.to_vec();
    let mut recovery_signed = Vec::new();
    for (name, ctx) in [("first", c1), ("second", c2)] {
        let seed = seed_r(&ctx.account, &rk)?;
        let pk_r = ed25519_public_key(&seed);
        let message = proof_message(
            "ferret/v1/recovery-req",
            "recover",
            &ctx.account,
            &nonce,
            ctx.epoch,
            &rbody,
        );
        let sig = ed25519_sign(&seed, &message).map_err(|e| format!("sign failed: {e}"))?;
        let input = json!({
            "account_id": h(&ctx.account),
            "vk_epoch": ctx.epoch.to_string(),
            "rk": h(&rk),
            "nonce": h(&nonce),
            "body": h(&rbody),
        });
        let mut c = valid_case(
            &format!("proofs/recovery_sign/{name}"),
            "recovery proof, label ferret/v1/recovery-req",
            "proof.recovery_sign",
            vec![],
            input,
            json!({ "proof": h(&sig), "pk_r": h(&pk_r) }),
        );
        c.intermediate = Some(json!({ "message": h(&message) }));
        cases.push(c);
        cases.push(valid_case(
            &format!("proofs/verify/recover_{name}"),
            "verifies: a recovery proof against pk_r",
            "proof.verify",
            vec![],
            verify_proof_input(
                &pk_r,
                "recover",
                &ctx.account,
                &nonce,
                ctx.epoch,
                &rbody,
                &sig,
            ),
            json!({ "ok": true }),
        ));
        recovery_signed.push((ctx, pk_r, sig));
    }

    // ---- refused
    let (ctx, op, body, sig) = signed[0].clone();
    let keys = ctx.keys()?;
    let pk = ed25519_public_key(&keys.seed_a);
    let mut bad = |name: &str, title: &str, input: Value| {
        cases.push(invalid_case(
            &format!("proofs/verify_invalid/{name}"),
            title,
            "proof.verify",
            vec![],
            input,
            "decrypt",
        ));
    };
    bad(
        "body",
        "another body",
        verify_proof_input(&pk, op, &ctx.account, &nonce, ctx.epoch, b"x", &sig),
    );
    bad(
        "body_bit",
        "one flipped bit in the body",
        verify_proof_input(
            &pk,
            op,
            &ctx.account,
            &nonce,
            ctx.epoch,
            &flip_at(&body, 3),
            &sig,
        ),
    );
    bad(
        "nonce",
        "another nonce",
        verify_proof_input(&pk, op, &ctx.account, &nonce2, ctx.epoch, &body, &sig),
    );
    bad(
        "op",
        "another op",
        verify_proof_input(
            &pk,
            "unlock-method.remove",
            &ctx.account,
            &nonce,
            ctx.epoch,
            &body,
            &sig,
        ),
    );
    bad(
        "epoch",
        "another vk_epoch",
        verify_proof_input(&pk, op, &ctx.account, &nonce, ctx.epoch + 1, &body, &sig),
    );
    bad(
        "account",
        "another account_id",
        verify_proof_input(&pk, op, &arr(0x12), &nonce, ctx.epoch, &body, &sig),
    );
    let other_pk = ed25519_public_key(&c2.keys()?.seed_a);
    bad(
        "public_key",
        "another public key",
        verify_proof_input(&other_pk, op, &ctx.account, &nonce, ctx.epoch, &body, &sig),
    );
    let mut flipped = sig;
    flipped[10] ^= 1;
    bad(
        "signature_bit",
        "a flipped bit in R",
        verify_proof_input(&pk, op, &ctx.account, &nonce, ctx.epoch, &body, &flipped),
    );
    let mut flipped_s = sig;
    flipped_s[40] ^= 1;
    bad(
        "signature_s_bit",
        "a flipped bit in S",
        verify_proof_input(&pk, op, &ctx.account, &nonce, ctx.epoch, &body, &flipped_s),
    );
    bad(
        "s_plus_l",
        "S + L: the same equation, but S is not canonical",
        verify_proof_input(
            &pk,
            op,
            &ctx.account,
            &nonce,
            ctx.epoch,
            &body,
            &malleable(&sig),
        ),
    );
    let mut identity = [0u8; 32];
    identity[0] = 1;
    bad(
        "small_order_key",
        "the identity as the public key",
        verify_proof_input(&identity, op, &ctx.account, &nonce, ctx.epoch, &body, &sig),
    );
    // Recovery proofs.
    let (rctx, pk_r, rsig) = recovery_signed[0];
    bad(
        "recovery_against_pk_a",
        "a recovery proof against pk_a",
        verify_proof_input(
            &pk,
            "recover",
            &rctx.account,
            &nonce,
            rctx.epoch,
            &rbody,
            &rsig,
        ),
    );
    bad(
        "recovery_with_mutation_op",
        "a recovery proof verified as an unlock-method.add",
        verify_proof_input(
            &pk_r,
            "unlock-method.add",
            &rctx.account,
            &nonce,
            rctx.epoch,
            &rbody,
            &rsig,
        ),
    );
    bad(
        "recovery_epoch",
        "a recovery proof with another vk_epoch",
        verify_proof_input(
            &pk_r,
            "recover",
            &rctx.account,
            &nonce,
            rctx.epoch + 1,
            &rbody,
            &rsig,
        ),
    );
    bad(
        "recovery_body",
        "a recovery proof with another body",
        verify_proof_input(
            &pk_r,
            "recover",
            &rctx.account,
            &nonce,
            rctx.epoch,
            b"{}",
            &rsig,
        ),
    );
    // A mutation proof is not a recovery proof: same fields, other label.
    let seed_a = c1.keys()?.seed_a;
    let message = proof_message(
        "ferret/v1/mutation",
        "recover",
        &c1.account,
        &nonce,
        c1.epoch,
        &rbody,
    );
    let as_mutation = ed25519_sign(&seed_a, &message).map_err(|e| format!("sign failed: {e}"))?;
    bad(
        "mutation_label_for_recover",
        "the op recover signed with the mutation label",
        verify_proof_input(
            &ed25519_public_key(&seed_a),
            "recover",
            &c1.account,
            &nonce,
            c1.epoch,
            &rbody,
            &as_mutation,
        ),
    );
    // A name that is not on the list.
    bad(
        "unknown_op",
        "an op that is not on the list",
        verify_proof_input(
            &pk,
            "unlock-method.frobnicate",
            &ctx.account,
            &nonce,
            ctx.epoch,
            &body,
            &sig,
        ),
    );
    Ok(())
}

pub(crate) fn proofs() -> Result<Vec<u8>, Error> {
    let mut cases = Vec::new();
    proof_cases(&mut cases)?;
    file("proofs", "Fase 1 § 4.5 and § 4.6, plan U8", cases)
}

// ------------------------------------------------------------------ rekey

fn wrap_aad(
    account: &[u8; 16],
    vault: &[u8; 16],
    method_type: u8,
    method_id: &[u8; 16],
    epoch: u64,
    generation: u64,
    kdf: Option<[u8; 12]>,
) -> Vec<u8> {
    let mut parts = vec![
        label("ferret/v1/wrap"),
        t(0x03, &[1]),
        t(0x10, account),
        t(0x11, vault),
        t(0x14, &[method_type]),
        t(0x13, method_id),
        t(0x20, &epoch.to_be_bytes()),
        t(0x21, &generation.to_be_bytes()),
    ];
    if let Some(kdf) = kdf {
        parts.push(t(0x30, &kdf));
    }
    cat(&parts)
}

/// One old item or tombstone as the server has it.
struct OldItem {
    item: Item,
}

struct RekeyCase {
    name: &'static str,
    title: &'static str,
    ctx: Ctx,
    base_seq: u64,
    items: Vec<(u8, u64, Vec<u8>)>,
    tombs: Vec<(u8, u64)>,
    /// The generations of the new wraps and the revision of the new
    /// manifest; the old ones (the floors, the old manifest) are one less.
    password_gen: u64,
    recovery_gen: u64,
    manifest_rev: u64,
}

const PW_ID: u8 = 0x70;
const REC_ID: u8 = 0x71;
const KEK_PW: u8 = 0xd0;

/// A manifest entry `{ t, id, g }` for a method id of 16 given bytes.
fn manifest_method(method_type: u64, id_bytes: &[u8; 16], generation: u64) -> Vec<u8> {
    cb::map(&[
        ("t", cb::uint(method_type)),
        ("id", cb::bytes(id_bytes)),
        ("g", cb::uint(generation)),
    ])
}

fn old_tomb(ctx: &Ctx, seed: &str, item: u8, rev: u64) -> Result<Vec<u8>, Error> {
    let nonce: [u8; 24] = draw(&format!("{seed}/old-nonce"));
    seal_raw(
        &nonce,
        &ctx.keys()?.k_del,
        &tomb_aad(1, 1, &ctx.vault, &id(item), rev),
        &[],
    )
}

/// The old state the server holds: items, tombstones, the manifest and the
/// last checkpoint the client verified.
struct OldState {
    olds: Vec<OldItem>,
    tombs: Vec<(u8, u64, Vec<u8>)>,
    manifest: Sealed,
    cp: Cp,
}

fn old_state(c: &RekeyCase, seed: &str) -> Result<OldState, Error> {
    old_state_lag(c, seed, 0)
}

/// The old state with a checkpoint that is `lag` behind `base_seq`.
fn old_state_lag(c: &RekeyCase, seed: &str, lag: u64) -> Result<OldState, Error> {
    let mut olds = Vec::new();
    for (b, rev, plain) in &c.items {
        let it = seal_item(
            &format!("{seed}/old{b:02x}"),
            &c.ctx,
            id(*b),
            *rev,
            plain,
            None,
            &GOOD_ITEM,
        )?;
        olds.push(OldItem { item: it });
    }
    let mut tombs = Vec::new();
    for (b, rev) in &c.tombs {
        tombs.push((
            *b,
            *rev,
            old_tomb(&c.ctx, &format!("{seed}/t{b:02x}"), *b, *rev)?,
        ));
    }
    let manifest = seal_manifest(
        &format!("{seed}/old-manifest"),
        &c.ctx,
        c.manifest_rev - 1,
        &manifest_cbor(
            1,
            c.ctx.epoch,
            &[
                manifest_method(1, &arr(PW_ID), c.password_gen - 1),
                manifest_method(2, &arr(REC_ID), c.recovery_gen - 1),
            ],
            &[],
        ),
    )?;
    let mut ents: Vec<Ent> = olds
        .iter()
        .map(|o| Ent {
            id: o.item.id,
            rev: o.item.rev,
            hash: Some(sha_raw(&[&o.item.envelope])),
        })
        .collect();
    ents.extend(tombs.iter().map(|(b, rev, _)| Ent {
        id: id(*b),
        rev: *rev,
        hash: None,
    }));
    ents.push(Ent {
        id: [0; 16],
        rev: manifest.rev,
        hash: Some(sha_raw(&[&manifest.envelope])),
    });
    let cp = make_cp(
        &c.ctx.keys()?.k_head,
        c.base_seq - lag,
        entries_bytes(&ents),
    )?;
    Ok(OldState {
        olds,
        tombs,
        manifest,
        cp,
    })
}

fn rekey_input(c: &RekeyCase, st: &OldState) -> Value {
    let mut i = c.ctx.input();
    i["base_seq"] = rev_s(c.base_seq);
    i["old_checkpoint"] = cp_json(&st.cp);
    i["old_manifest"] = json!({
        "rev": rev_s(st.manifest.rev),
        "envelope": h(&st.manifest.envelope),
        "tag": h(&st.manifest.tag),
    });
    i["items"] = Value::Array(
        st.olds
            .iter()
            .map(|o| {
                json!({
                    "item_id": h(&o.item.id),
                    "rev": rev_s(o.item.rev),
                    "envelope": h(&o.item.envelope),
                    "tag": h(&o.item.tag),
                })
            })
            .collect(),
    );
    i["tombstones"] = Value::Array(
        st.tombs
            .iter()
            .map(|(b, rev, tomb)| {
                json!({ "item_id": h(&id(*b)), "rev": rev_s(*rev), "tomb": h(tomb) })
            })
            .collect(),
    );
    i["password_kek"] = h(&arr::<32>(KEK_PW));
    i["password_method_id"] = h(&arr::<16>(PW_ID));
    i["password_ksf_profile"] = json!(1);
    i["recovery_method_id"] = h(&arr::<16>(REC_ID));
    // The pinned floors: the generations of the new wraps are these plus one.
    i["password_floor"] = rev_s(c.password_gen - 1);
    i["recovery_floor"] = rev_s(c.recovery_gen - 1);
    i
}

fn rekey_cases(cases: &mut Vec<Case>) -> Result<(), Error> {
    let c1 = ctx1();
    let c2 = ctx2();
    let login = Body::new("login", "Example");
    let mut note = Body::new("note", "Shopping");
    note.notes = Some("milk, bread and ål".into());
    let mut card = Body::new("card", "Visa");
    card.fields = vec![field(
        "number",
        "Card number",
        "hidden",
        "4111111111111111",
        &[],
    )];
    let identity = Body::new("identity", "Me");
    let mut future = Body::new("login", "From the future");
    future.schema = 2;
    future.extra = vec![("shiny".into(), cb::text("new"))];

    let five: Vec<(u8, u64, Vec<u8>)> = vec![
        (0x41, 3, login.cbor()),
        (0x42, 1, note.cbor()),
        (0x43, 7, card.cbor()),
        (0x44, 2, identity.cbor()),
        (0x45, 4, future.cbor()),
    ];
    let valid = [
        RekeyCase {
            name: "five_items_two_tombstones",
            title: "5 items (one with a future schema) and 2 tombstones",
            ctx: c1,
            base_seq: 77,
            items: five.clone(),
            tombs: vec![(0x51, 6), (0x52, 2)],
            password_gen: 4,
            recovery_gen: 2,
            manifest_rev: 9,
        },
        RekeyCase {
            name: "empty_vault_later_epoch",
            title: "no items, from epoch 4294967298",
            ctx: c2,
            base_seq: 0,
            items: vec![],
            tombs: vec![],
            password_gen: 1,
            recovery_gen: 1,
            manifest_rev: 2,
        },
        RekeyCase {
            name: "one_item",
            title: "a single item and a large revision",
            ctx: c2,
            base_seq: 0x0102_0304_0506,
            items: vec![(0x46, 0x0102_0304_0506_0708, note.cbor())],
            tombs: vec![],
            password_gen: 3,
            recovery_gen: 3,
            manifest_rev: 0x0102_0304_0506_0708,
        },
    ];

    for c in &valid {
        let seed = format!("rekey/{}", c.name);
        let st = old_state(c, &seed)?;
        let olds = &st.olds;
        let old_tombs = &st.tombs;

        // ---- the new state, worked out from the specification
        let vk_new: [u8; 32] = draw(&format!("{seed}/vk"));
        let new_ctx = Ctx {
            epoch: c.ctx.epoch + 1,
            vk: vk_new,
            ..c.ctx
        };
        let nk = new_ctx.keys()?;
        let mut draws: Vec<Vec<u8>> = vec![vk_new.to_vec()];
        let mut new_items = Vec::new();
        for o in olds {
            let it = seal_padded(
                &format!("{seed}/new{:02x}", o.item.id[0]),
                &new_ctx,
                o.item.id,
                o.item.rev + 1,
                &o.item.plain,
                &pad(&o.item.plain)?,
                None,
                &GOOD_ITEM,
            )?;
            draws.extend(it.rng.iter().cloned());
            new_items.push(it);
        }
        let mut new_tombs = Vec::new();
        for (b, rev, _) in old_tombs {
            let nonce: [u8; 24] = draw(&format!("{seed}/t{b:02x}/new-nonce"));
            let tomb = seal_raw(
                &nonce,
                &nk.k_del,
                &tomb_aad(1, 1, &new_ctx.vault, &id(*b), rev + 1),
                &[],
            )?;
            draws.push(nonce.to_vec());
            new_tombs.push((*b, rev + 1, tomb));
        }
        // The password wrap: the same KEK, the next generation.
        let kek_pw: [u8; 32] = arr(KEK_PW);
        let p1: [u8; 12] = [0, 1, 0, 0, 0, 0, 0, 3, 0, 0, 0, 1];
        let pw_nonce: [u8; 24] = draw(&format!("{seed}/pw-nonce"));
        let mut pw_wrap = seal_raw(
            &pw_nonce,
            &kek_pw,
            &wrap_aad(
                &c.ctx.account,
                &c.ctx.vault,
                1,
                &arr(PW_ID),
                new_ctx.epoch,
                c.password_gen,
                Some(p1),
            ),
            &vk_new,
        )?;
        pw_wrap.extend_from_slice(&commit(&kek_pw)?);
        draws.push(pw_nonce.to_vec());
        // The recovery wrap: always a new recovery key.
        let rk: [u8; 32] = draw(&format!("{seed}/rk"));
        draws.push(rk.to_vec());
        let rec_nonce: [u8; 24] = draw(&format!("{seed}/rec-nonce"));
        let rec_wrap = seal_raw(
            &rec_nonce,
            &kek_recovery(&c.ctx.account, &rk)?,
            &wrap_aad(
                &c.ctx.account,
                &c.ctx.vault,
                2,
                &arr(REC_ID),
                new_ctx.epoch,
                c.recovery_gen,
                None,
            ),
            &vk_new,
        )?;
        draws.push(rec_nonce.to_vec());
        let pk_r = ed25519_public_key(&seed_r(&c.ctx.account, &rk)?);
        // The manifest.
        let manifest = seal_manifest(
            &format!("{seed}/manifest"),
            &new_ctx,
            c.manifest_rev,
            &manifest_cbor(
                1,
                new_ctx.epoch,
                &[
                    manifest_method(1, &arr(PW_ID), c.password_gen),
                    manifest_method(2, &arr(REC_ID), c.recovery_gen),
                ],
                &[],
            ),
        )?;
        draws.push(manifest.nonce.to_vec());
        // The checkpoint of the new state, for seq = base_seq.
        let mut ents: Vec<Ent> = new_items
            .iter()
            .map(|it| Ent {
                id: it.id,
                rev: it.rev,
                hash: Some(sha_raw(&[&it.envelope])),
            })
            .collect();
        ents.extend(new_tombs.iter().map(|(b, rev, _)| Ent {
            id: id(*b),
            rev: *rev,
            hash: None,
        }));
        ents.push(Ent {
            id: [0; 16],
            rev: manifest.rev,
            hash: Some(sha_raw(&[&manifest.envelope])),
        });
        let cp = make_cp(&nk.k_head, c.base_seq, entries_bytes(&ents))?;

        let input = rekey_input(c, &st);
        let expect = json!({
            "vk_epoch": new_ctx.epoch.to_string(),
            "vk": h(&vk_new),
            "pk_a": h(&ed25519_public_key(&nk.seed_a)),
            "pk_r": h(&pk_r),
            "recovery_key": h(&rk),
            "items": new_items.iter().map(|it| json!({
                "item_id": h(&it.id), "rev": rev_s(it.rev),
                "envelope": h(&it.envelope), "tag": h(&it.tag),
            })).collect::<Vec<_>>(),
            "tombstones": new_tombs.iter().map(|(b, rev, tomb)| json!({
                "item_id": h(&id(*b)), "rev": rev_s(*rev), "tomb": h(tomb),
            })).collect::<Vec<_>>(),
            "wraps": [
                { "method_id": h(&arr::<16>(PW_ID)), "kek_generation": c.password_gen.to_string(), "wrap": h(&pw_wrap) },
                { "method_id": h(&arr::<16>(REC_ID)), "kek_generation": c.recovery_gen.to_string(), "wrap": h(&rec_wrap) },
            ],
            "manifest": { "rev": rev_s(manifest.rev), "envelope": h(&manifest.envelope), "tag": h(&manifest.tag) },
            "checkpoint": cp_json(&cp),
        });
        let case = valid_case(
            &format!("rekey/run/{}", c.name),
            c.title,
            "rekey.run",
            vec![],
            input,
            expect,
        );
        cases.push(with_rng(case, &draws));
    }

    // ---- refused: nothing is returned, and nothing is drawn, because the
    // rows are checked against the old checkpoint before the plan is built.
    let mut refused = |name: &str, title: &str, input: Value, code: &str| {
        cases.push(invalid_case(
            &format!("rekey/refused/{name}"),
            title,
            "rekey.run",
            vec![],
            input,
            code,
        ));
    };
    // The first case: the checkpoint is at the top (`base_seq`).
    let c = &valid[0];
    let st = old_state(c, "rekey/refused")?;
    let tombs = &st.tombs;
    let olds = &st.olds;
    let base = || rekey_input(c, &st);

    let mut broken = base();
    broken["items"][0]["tag"] = h(&flip_arr(&olds[0].item.tag, 0));
    refused(
        "first_item_bad_tag",
        "the first item has a wrong tag",
        broken,
        "decrypt",
    );
    let mut broken = base();
    let last = olds.len() - 1;
    broken["items"][last]["envelope"] = h(&flip_at(&olds[last].item.envelope, 200));
    refused(
        "last_item_damaged",
        "the last item is damaged: no partial result",
        broken,
        "decrypt",
    );
    let mut broken = base();
    broken["items"][1]["item_id"] = h(&id(0x4f));
    refused(
        "item_wrong_id",
        "an item under another item_id",
        broken,
        "decrypt",
    );
    let mut broken = base();
    broken["tombstones"][1]["tomb"] = h(&flip_at(&tombs[1].2, 30));
    refused(
        "forged_tombstone",
        "a forged tombstone is not turned into a real one",
        broken,
        "tombstone_invalid",
    );
    // A server that hides a row in the download.
    for (name, title, at) in [
        (
            "hidden_item_at_top",
            "a live item is missing and the checkpoint is at the top",
            1usize,
        ),
        (
            "hidden_item_at_top_other",
            "another live item is missing at the top",
            3,
        ),
    ] {
        let mut broken = base();
        if let Some(list) = broken["items"].as_array_mut() {
            list.remove(at);
        }
        refused(name, title, broken, "checkpoint_top_digest_mismatch");
    }
    // A row the checkpoint does not have, at the top.
    let extra = seal_item(
        "rekey/refused/extra",
        &c.ctx,
        id(0x4e),
        1,
        &Body::new("note", "extra").cbor(),
        None,
        &GOOD_ITEM,
    )?;
    let mut broken = base();
    if let Some(list) = broken["items"].as_array_mut() {
        list.push(json!({
            "item_id": h(&extra.id), "rev": rev_s(extra.rev),
            "envelope": h(&extra.envelope), "tag": h(&extra.tag),
        }));
    }
    refused(
        "extra_item_at_top",
        "a live item that the checkpoint does not have, at the top",
        broken,
        "checkpoint_top_digest_mismatch",
    );
    // An item at a lower revision than the checkpoint's: a rolled back row.
    let older = seal_item(
        "rekey/refused/older",
        &c.ctx,
        olds[0].item.id,
        olds[0].item.rev - 1,
        &olds[0].item.plain,
        None,
        &GOOD_ITEM,
    )?;
    let mut broken = base();
    broken["items"][0] = json!({
        "item_id": h(&older.id), "rev": rev_s(older.rev),
        "envelope": h(&older.envelope), "tag": h(&older.tag),
    });
    refused(
        "rolled_back_item",
        "an old revision of an item that the checkpoint has newer",
        broken,
        "checkpoint_lower_rev",
    );
    // The checkpoint must be for base_seq itself: behind it, or above it, is
    // refused (the client makes a fresh one before it rekeys).
    let behind = old_state_lag(c, "rekey/refused", 5)?;
    refused(
        "checkpoint_behind",
        "the old checkpoint is behind base_seq",
        rekey_input(c, &behind),
        "malformed_entries",
    );
    let mut broken = base();
    broken["base_seq"] = rev_s(c.base_seq - 1);
    refused(
        "checkpoint_above_top",
        "the old checkpoint is for a seq above base_seq",
        broken,
        "malformed_entries",
    );
    // A row below the checkpoint's revision: the old manifest, a tombstone.
    let older_manifest = seal_manifest(
        "rekey/refused/older-manifest",
        &c.ctx,
        st.manifest.rev - 1,
        &st.manifest.plain,
    )?;
    let mut broken = base();
    broken["old_manifest"] = json!({
        "rev": rev_s(older_manifest.rev),
        "envelope": h(&older_manifest.envelope),
        "tag": h(&older_manifest.tag),
    });
    refused(
        "manifest_below_checkpoint_rev",
        "the old manifest is at a lower revision than the checkpoint's",
        broken,
        "checkpoint_lower_rev",
    );
    let older_tomb = old_tomb(&c.ctx, "rekey/refused/older-tomb", 0x51, tombs[0].1 - 1)?;
    let mut broken = base();
    broken["tombstones"][0]["rev"] = rev_s(tombs[0].1 - 1);
    broken["tombstones"][0]["tomb"] = h(&older_tomb);
    refused(
        "tombstone_below_checkpoint_rev",
        "a tombstone at a lower revision than the checkpoint's",
        broken,
        "checkpoint_lower_rev",
    );
    let mut broken = base();
    broken["old_checkpoint"]["mac"] = h(&flip_arr(&st.cp.mac, 0));
    refused(
        "checkpoint_bad_mac",
        "the old checkpoint does not verify",
        broken,
        "checkpoint_bad_mac",
    );
    // The old manifest.
    let mut broken = base();
    broken["old_manifest"]["tag"] = h(&flip_arr(&st.manifest.tag, 0));
    refused(
        "manifest_bad_tag",
        "the old manifest has a wrong tag",
        broken,
        "decrypt",
    );
    // Input that cannot make a plan.
    let mut broken = base();
    broken["tombstones"][0]["item_id"] = h(&olds[0].item.id);
    refused(
        "duplicate_item_id",
        "an item_id in the items and the tombstones",
        broken,
        "malformed_entries",
    );
    let mut broken = base();
    broken["items"][0]["rev"] = rev_s(u64::MAX);
    refused(
        "rev_overflow",
        "a revision that cannot be raised",
        broken,
        "malformed_entries",
    );
    let mut broken = base();
    broken["items"][0]["item_id"] = h(&[0; 16]);
    refused(
        "manifest_id",
        "an item with the manifest's item_id",
        broken,
        "malformed_envelope",
    );
    // The pinned floors.
    let mut broken = base();
    broken["password_floor"] = rev_s(u64::from(u32::MAX));
    refused(
        "generation_too_high",
        "a floor whose next generation no pinned device accepts",
        broken,
        "malformed_pinned_record",
    );
    let mut broken = base();
    broken["recovery_floor"] = Value::Null;
    refused(
        "no_recovery_floor",
        "no floor for the recovery wrap (seed the floors from the manifest first)",
        broken,
        "malformed_pinned_record",
    );
    Ok(())
}

pub(crate) fn rekey() -> Result<Vec<u8>, Error> {
    let mut cases = Vec::new();
    rekey_cases(&mut cases)?;
    file("rekey", "Fase 1 § 4.7 and § 8.6", cases)
}
