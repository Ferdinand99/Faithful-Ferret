//! Full rekey (Fase 1 § 4.7) and `vectors/internal/rekey.json`.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]

mod common;

use common::*;
use ferret_core::envelope::IK_WRAP_LEN;
use ferret_core::testing::item::{intermediate, open_plaintext, seal_plaintext};
use ferret_core::testing::keys::{recovery_seed, unlocked_vault_keys, wrap_aad};
use ferret_core::testing::vector::Outcome;
use ferret_core::testing::{ReplayRng, TestRng};
use ferret_core::{
    Error, ItemBody, ItemId, ItemType, Kek, MalformedKind, Method, MethodId, MethodManifestView,
    MutationOp, RecoveryKey, RekeyBundle, RekeyInput, RekeyItem, RekeyTombstone, SealedItem,
    ServerRow, Tombstone, UnlockedVault, auth_sign, decrypt_item, decrypt_manifest, encrypt_item,
    make_tombstone, recovery_public_key, unwrap_vk, verify_checkpoint, verify_mutation_proof,
    verify_tombstone,
};
use serde_json::json;

const BASE_SEQ: u64 = 77;

fn item_id(b: u8) -> ItemId {
    ItemId::from_bytes([b; 16])
}

fn kek() -> Kek {
    Kek::from_test_bytes([0xd0; 32])
}

struct Fixture {
    old: UnlockedVault,
    items: Vec<(ItemId, SealedItem)>,
    tombs: Vec<(ItemId, Tombstone)>,
    plain: Vec<(ItemId, Vec<u8>, Vec<u8>)>,
}

fn fixture() -> Fixture {
    let old = unlocked(0x5a);
    let mut rng = TestRng::new(b"rekey-fixture");
    let mut items = Vec::new();
    let mut plain = Vec::new();
    for (b, rev, name) in [
        (0x41u8, 3u64, "Example"),
        (0x42, 1, "Shopping"),
        (0x43, 7, "Visa"),
    ] {
        let body = ItemBody::new(ItemType::Login, name, 1_700_000_000_000);
        let s = encrypt_item(&mut rng, &old, item_id(b), rev, &body, None).unwrap();
        let (padded, p) = open_plaintext(&old, item_id(b), rev, &s.envelope, &s.tag).unwrap();
        plain.push((item_id(b), padded, p));
        items.push((item_id(b), s));
    }
    // An item from a future schema: it can be read-only opened, never edited.
    let future = {
        use ferret_core::cbor::{Value, encode};
        let v = Value::Map(vec![
            ("schema".into(), Value::uint(2)),
            ("type".into(), Value::text("login")),
            ("name".into(), Value::text("From the future")),
            ("fields".into(), Value::Array(vec![])),
            ("urls".into(), Value::Array(vec![])),
            ("created".into(), Value::uint(1)),
            ("modified".into(), Value::uint(2)),
            ("favorite".into(), Value::Bool(false)),
            ("shiny".into(), Value::text("new")),
        ]);
        encode(&v).unwrap()
    };
    let s = seal_plaintext(&mut rng, &old, item_id(0x44), 4, &future, None).unwrap();
    let (padded, p) = open_plaintext(&old, item_id(0x44), 4, &s.envelope, &s.tag).unwrap();
    plain.push((item_id(0x44), padded, p));
    items.push((item_id(0x44), s));
    let tombs = vec![
        (
            item_id(0x51),
            make_tombstone(&mut rng, &old, item_id(0x51), 6).unwrap(),
        ),
        (
            item_id(0x52),
            make_tombstone(&mut rng, &old, item_id(0x52), 2).unwrap(),
        ),
    ];
    Fixture {
        old,
        items,
        tombs,
        plain,
    }
}

fn rekey_with<R: ferret_core::SecureRng>(
    f: &Fixture,
    vault: &UnlockedVault,
    rng: &mut R,
    edit: impl FnOnce(&mut Vec<(ItemId, SealedItem)>, &mut Vec<(ItemId, Tombstone)>),
) -> Result<RekeyBundle, Error> {
    let mut items = f.items.clone();
    let mut tombs = f.tombs.clone();
    edit(&mut items, &mut tombs);
    let ritems: Vec<RekeyItem<'_>> = items
        .iter()
        .map(|(id, s)| RekeyItem {
            item_id: *id,
            rev: s.rev,
            envelope: &s.envelope,
            tag: &s.tag,
        })
        .collect();
    let rtombs: Vec<RekeyTombstone<'_>> = tombs
        .iter()
        .map(|(id, t)| RekeyTombstone {
            item_id: *id,
            rev: t.rev,
            tomb: &t.tomb,
        })
        .collect();
    let k = kek();
    let input = RekeyInput {
        base_seq: BASE_SEQ,
        items: &ritems,
        tombstones: &rtombs,
        password_kek: &k,
        password_method: (method_id(0x70), password_method()),
        password_next_generation: 4,
        recovery_method_id: method_id(0x71),
        recovery_next_generation: 2,
        manifest_rev: 9,
    };
    vault.rekey(rng, &input)
}

fn rekey(f: &Fixture, seed: &str) -> RekeyBundle {
    rekey_with(f, &f.old, &mut TestRng::new(seed.as_bytes()), |_, _| {}).unwrap()
}

#[test]
fn rekey_changes_every_key_and_epoch() {
    let f = fixture();
    let b = rekey(&f, "a");
    assert_eq!(b.vk_epoch, 2);
    assert_eq!(b.vault.context().vk_epoch, 2);
    assert_eq!(b.vault.context().account_id, f.old.context().account_id);
    assert_eq!(b.vault.context().vault_id, f.old.context().vault_id);
    assert_eq!(b.base_seq, BASE_SEQ);
    assert_ne!(b.pk_a, f.old.auth_public_key());
    assert_eq!(b.pk_a, b.vault.auth_public_key());
    assert!(!b.vault.same_vault_key(&f.old));
    // VK, K_head, K_del and K_meta are all new.
    let (old_keys, new_keys) = (unlocked_vault_keys(&f.old), unlocked_vault_keys(&b.vault));
    for (i, (old, new)) in old_keys.iter().zip(&new_keys).enumerate() {
        assert_ne!(old, new, "key {i}");
    }
    // pk_r belongs to the new recovery key, which is not a key we had.
    let account = f.old.context().account_id;
    assert_eq!(
        b.pk_r,
        recovery_public_key(&b.recovery_key, &account).unwrap()
    );
    assert_ne!(
        b.pk_r,
        recovery_public_key(&RecoveryKey::from_test_bytes([0xc0; 32]), &account).unwrap()
    );
    // Two rekeys of the same state share nothing.
    let b2 = rekey(&f, "b");
    assert_ne!(unlocked_vault_keys(&b2.vault)[0], new_keys[0]);
    assert_ne!(b2.pk_r, b.pk_r);
    assert_ne!(b2.pk_a, b.pk_a);
}

#[test]
fn rekey_reencrypts_all_items_with_rev_plus_one_and_fresh_ik() {
    let f = fixture();
    let b = rekey(&f, "a");
    assert_eq!(b.items.len(), f.items.len());
    let mut wraps = Vec::new();
    for ((old_id, old), (new_id, new)) in f.items.iter().zip(&b.items) {
        assert_eq!(old_id, new_id);
        assert_eq!(new.rev, old.rev + 1);
        // A fresh item key: the wrap, the body and the key itself differ.
        let ik_old = intermediate(&f.old, *old_id, old.rev, &old.envelope, &old.tag)
            .unwrap()
            .ik;
        let ik_new = intermediate(&b.vault, *new_id, new.rev, &new.envelope, &new.tag)
            .unwrap()
            .ik;
        assert_ne!(ik_old, ik_new);
        let wrap = new.envelope[3..3 + IK_WRAP_LEN].to_vec();
        assert_ne!(wrap, old.envelope[3..3 + IK_WRAP_LEN]);
        wraps.push(wrap);
        // The old vault opens nothing of the new state.
        assert_eq!(
            decrypt_item(&f.old, *new_id, new.rev, &new.envelope, &new.tag).err(),
            Some(Error::Decrypt)
        );
        assert_eq!(
            open_plaintext(&f.old, *new_id, new.rev, &new.envelope, &new.tag).err(),
            Some(Error::Decrypt)
        );
        // And the new vault does not open the old.
        assert_eq!(
            decrypt_item(&b.vault, *old_id, old.rev, &old.envelope, &old.tag).err(),
            Some(Error::Decrypt)
        );
    }
    wraps.sort();
    wraps.dedup();
    assert_eq!(wraps.len(), f.items.len(), "every ik_wrap is different");
}

#[test]
fn rekey_preserves_plaintext_bytes() {
    let f = fixture();
    let b = rekey(&f, "a");
    for ((id, padded, plain), (_, new)) in f.plain.iter().zip(&b.items) {
        let (padded2, plain2) =
            open_plaintext(&b.vault, *id, new.rev, &new.envelope, &new.tag).unwrap();
        assert_eq!(&padded2, padded, "padded bytes");
        assert_eq!(&plain2, plain, "plaintext bytes");
    }
    // The ordinary items also decode to the same body.
    let (id, old) = &f.items[0];
    let before = decrypt_item(&f.old, *id, old.rev, &old.envelope, &old.tag).unwrap();
    let (_, new) = &b.items[0];
    let after = decrypt_item(&b.vault, *id, new.rev, &new.envelope, &new.tag).unwrap();
    assert_eq!(
        before.body.to_cbor().unwrap(),
        after.body.to_cbor().unwrap()
    );
}

#[test]
fn rekey_handles_future_schema_items() {
    let f = fixture();
    let (id, old) = &f.items[3];
    assert!(
        decrypt_item(&f.old, *id, old.rev, &old.envelope, &old.tag)
            .unwrap()
            .read_only
    );
    let b = rekey(&f, "a");
    let (_, new) = &b.items[3];
    let opened = decrypt_item(&b.vault, *id, new.rev, &new.envelope, &new.tag).unwrap();
    assert!(opened.read_only, "still read-only");
    assert_eq!(new.rev, old.rev + 1);
}

#[test]
fn rekey_retags_tombstones_under_new_k_del() {
    let f = fixture();
    let b = rekey(&f, "a");
    assert_eq!(b.tombstones.len(), 2);
    for ((old_id, old), (new_id, new)) in f.tombs.iter().zip(&b.tombstones) {
        assert_eq!(old_id, new_id);
        assert_eq!(new.rev, old.rev + 1);
        assert_eq!(new.tomb.len(), 40);
        verify_tombstone(&b.vault, *new_id, new.rev, &new.tomb).unwrap();
        assert_eq!(
            verify_tombstone(&f.old, *new_id, new.rev, &new.tomb),
            Err(Error::TombstoneInvalid)
        );
        assert_eq!(
            verify_tombstone(&b.vault, *old_id, old.rev, &old.tomb),
            Err(Error::TombstoneInvalid)
        );
        assert_ne!(new.tomb, old.tomb);
    }
}

#[test]
fn rekey_password_wrap_uses_same_kek_new_aad_generation_plus_one() {
    let f = fixture();
    let b = rekey(&f, "a");
    let new_ctx = *b.vault.context();
    let pw = &b.wraps[0];
    assert!(matches!(pw.method, Method::Password { .. }));
    assert_eq!(pw.method_id, method_id(0x70));
    assert_eq!(pw.kek_generation, 4);
    assert_eq!(pw.wrap.len(), 104, "with the key commitment");
    // The same KEK_pw opens it, in the new epoch, to the new vault.
    let opened = unwrap_vk(&new_ctx, &kek(), pw).unwrap();
    assert!(opened.same_vault_key(&b.vault));
    // The AAD is the new one: the epoch and generation are in it.
    let aad = wrap_aad(&new_ctx, pw).unwrap();
    assert!(aad.windows(8).any(|w| w == 2u64.to_be_bytes()));
    assert!(aad.windows(8).any(|w| w == 4u64.to_be_bytes()));
    // The old epoch, another KEK and another generation do not open it.
    assert_eq!(
        unwrap_vk(f.old.context(), &kek(), pw).err(),
        Some(Error::Decrypt)
    );
    assert_eq!(
        unwrap_vk(&new_ctx, &Kek::from_test_bytes([0xd1; 32]), pw).err(),
        Some(Error::Decrypt)
    );
    let mut other_gen = pw.clone();
    other_gen.kek_generation = 3;
    assert_eq!(
        unwrap_vk(&new_ctx, &kek(), &other_gen).err(),
        Some(Error::Decrypt)
    );
}

#[test]
fn rekey_drops_prf_and_device() {
    let f = fixture();
    let b = rekey(&f, "a");
    // Only the password and the recovery wraps are made again.
    assert_eq!(b.wraps.len(), 2);
    let kinds: Vec<u8> = b.wraps.iter().map(|w| w.method.type_code()).collect();
    assert_eq!(kinds, vec![1, 2]);
    // The manifest lists exactly those two, for the new epoch.
    let m = decrypt_manifest(
        &b.vault,
        b.manifest.rev,
        &b.manifest.envelope,
        &b.manifest.tag,
    )
    .unwrap();
    assert_eq!(m.vk_epoch, 2);
    let listed: Vec<(u8, MethodId, u64)> = m
        .methods
        .iter()
        .map(|e| (e.method_type, e.method_id, e.kek_generation))
        .collect();
    assert_eq!(
        listed,
        vec![(1, method_id(0x70), 4), (2, method_id(0x71), 2)]
    );
    assert_eq!(b.manifest.rev, 9);
    // It seeds the pinning floors without a passkey or local method.
    let view = MethodManifestView::from_manifest(&m).unwrap();
    assert_eq!(view.methods.len(), 2);
    // The old vault cannot open the new manifest.
    assert!(
        decrypt_manifest(
            &f.old,
            b.manifest.rev,
            &b.manifest.envelope,
            &b.manifest.tag
        )
        .is_err()
    );
}

#[test]
fn rekey_recovery_wrap_new_rk() {
    let f = fixture();
    let b = rekey(&f, "a");
    let account = f.old.context().account_id;
    let rec = &b.wraps[1];
    assert!(matches!(rec.method, Method::Recovery));
    assert_eq!(rec.method_id, method_id(0x71));
    assert_eq!(rec.kek_generation, 2);
    assert_eq!(rec.wrap.len(), 72);
    let new_ctx = *b.vault.context();
    let kek_rk = Kek::from_recovery_key(&account, &b.recovery_key).unwrap();
    let opened = unwrap_vk(&new_ctx, &kek_rk, rec).unwrap();
    assert!(opened.same_vault_key(&b.vault));
    // The old recovery key (any key but the new one) does not open it.
    let old_rk = RecoveryKey::from_test_bytes([0xc0; 32]);
    let old_kek = Kek::from_recovery_key(&account, &old_rk).unwrap();
    assert_eq!(
        unwrap_vk(&new_ctx, &old_kek, rec).err(),
        Some(Error::Decrypt)
    );
    // pk_r is that of seed_r of the new key.
    assert_eq!(
        b.pk_r,
        ferret_core::testing::prim::ed25519_public_key(
            &recovery_seed(&b.recovery_key, &account).unwrap()
        )
    );
}

#[test]
fn rekey_is_all_or_nothing() {
    let f = fixture();
    // A damaged tag on the first, a middle and the last item.
    for victim in [0usize, 1, 3] {
        let r = rekey_with(&f, &f.old, &mut TestRng::new(b"x"), |items, _| {
            items[victim].1.tag[0] ^= 1;
        });
        assert_eq!(r.err(), Some(Error::Decrypt), "item {victim}");
    }
    // A damaged envelope.
    let r = rekey_with(&f, &f.old, &mut TestRng::new(b"x"), |items, _| {
        let n = items[3].1.envelope.len();
        items[3].1.envelope[n - 1] ^= 1;
    });
    assert_eq!(r.err(), Some(Error::Decrypt));
    // An item from another vault state (the wrong revision).
    let r = rekey_with(&f, &f.old, &mut TestRng::new(b"x"), |items, _| {
        items[2].1.rev += 1;
    });
    assert_eq!(r.err(), Some(Error::Decrypt));
    // A forged tombstone is not turned into a real one.
    let r = rekey_with(&f, &f.old, &mut TestRng::new(b"x"), |_, tombs| {
        tombs[1].1.tomb[10] ^= 1;
    });
    assert_eq!(r.err(), Some(Error::TombstoneInvalid));
    // A tombstone from another item.
    let r = rekey_with(&f, &f.old, &mut TestRng::new(b"x"), |_, tombs| {
        tombs[0].0 = item_id(0x53);
    });
    assert_eq!(r.err(), Some(Error::TombstoneInvalid));
    // The same inputs, undamaged, work.
    rekey_with(&f, &f.old, &mut TestRng::new(b"x"), |_, _| {}).unwrap();
}

#[test]
fn rekey_refuses_input_that_cannot_make_a_plan() {
    let f = fixture();
    let mut draws = ReplayRng::new(vec![]);
    // Nothing is drawn: a draw would panic the replay RNG.
    let dup = rekey_with(&f, &f.old, &mut draws, |items, tombs| {
        tombs[0].0 = items[0].0;
    });
    assert_eq!(dup.err(), Some(Error::Malformed(MalformedKind::Entries)));
    let manifest_id = rekey_with(&f, &f.old, &mut draws, |_, tombs| {
        tombs[0].0 = ItemId::MANIFEST;
    });
    assert_eq!(
        manifest_id.err(),
        Some(Error::Malformed(MalformedKind::Envelope))
    );
    let overflow = rekey_with(&f, &f.old, &mut draws, |items, _| {
        items[0].1.rev = u64::MAX;
    });
    assert_eq!(
        overflow.err(),
        Some(Error::Malformed(MalformedKind::Entries))
    );
    assert_eq!(draws.remaining(), 0);

    // The password method must be a password method.
    let k = kek();
    let input = RekeyInput {
        base_seq: 0,
        items: &[],
        tombstones: &[],
        password_kek: &k,
        password_method: (method_id(0x70), Method::Recovery),
        password_next_generation: 2,
        recovery_method_id: method_id(0x71),
        recovery_next_generation: 2,
        manifest_rev: 2,
    };
    assert_eq!(
        f.old.rekey(&mut draws, &input).err(),
        Some(Error::Unsupported)
    );
    // A generation that no pinned device accepts.
    let input = RekeyInput {
        password_method: (method_id(0x70), password_method()),
        password_next_generation: u64::from(u32::MAX) + 1,
        ..input
    };
    assert_eq!(
        f.old.rekey(&mut draws, &input).err(),
        Some(Error::Malformed(MalformedKind::PinnedRecord))
    );
}

#[test]
fn rekey_new_checkpoint_verifies_under_new_k_head() {
    let f = fixture();
    let b = rekey(&f, "a");
    let mut rows: Vec<ServerRow> = Vec::new();
    for (id, s) in &b.items {
        rows.push(ServerRow::live(&b.vault, *id, s.rev, &s.envelope, &s.tag).unwrap());
    }
    for (id, t) in &b.tombstones {
        rows.push(ServerRow::deleted(&b.vault, *id, t.rev, &t.tomb).unwrap());
    }
    rows.push(
        ServerRow::live(
            &b.vault,
            ItemId::MANIFEST,
            b.manifest.rev,
            &b.manifest.envelope,
            &b.manifest.tag,
        )
        .unwrap(),
    );
    assert_eq!(b.checkpoint.seq, BASE_SEQ);
    assert_eq!(b.checkpoint.entries.len(), 56 * (4 + 2 + 1));
    verify_checkpoint(&b.vault, &b.checkpoint, &rows, BASE_SEQ).unwrap();
    // After the rekey the server's seq is higher; the checkpoint still holds.
    verify_checkpoint(&b.vault, &b.checkpoint, &rows, BASE_SEQ + 20).unwrap();
    // It is signed with the new K_head only.
    assert_eq!(
        verify_checkpoint(&f.old, &b.checkpoint, &rows, BASE_SEQ).err(),
        Some(Error::Checkpoint(ferret_core::CheckpointFailure::BadMac))
    );
    // The old rows (the old state) are not what this checkpoint describes.
    let old_rows: Vec<ServerRow> = f
        .items
        .iter()
        .map(|(id, s)| ServerRow::live(&f.old, *id, s.rev, &s.envelope, &s.tag).unwrap())
        .collect();
    assert!(verify_checkpoint(&b.vault, &b.checkpoint, &old_rows, BASE_SEQ + 1).is_err());
}

#[test]
fn rekey_request_is_signed_by_the_old_key() {
    let f = fixture();
    let b = rekey(&f, "a");
    let nonce = [7u8; 32];
    let body = b"{\"rekey\":true}";
    // The caller signs the request body with the old vault.
    let proof = auth_sign(&f.old, MutationOp::Rekey, &nonce, body).unwrap();
    let account = f.old.context().account_id;
    verify_mutation_proof(
        &f.old.auth_public_key(),
        MutationOp::Rekey,
        &account,
        &nonce,
        1,
        body,
        &proof,
    )
    .unwrap();
    // The new pk_a does not verify it: a device that pinned the old pk_a
    // checks the rekey with that one.
    assert!(
        verify_mutation_proof(
            &b.pk_a,
            MutationOp::Rekey,
            &account,
            &nonce,
            1,
            body,
            &proof
        )
        .is_err()
    );
}

#[test]
fn rekey_can_be_repeated() {
    let f = fixture();
    let b = rekey(&f, "a");
    let f2 = Fixture {
        old: b.vault,
        items: b.items,
        tombs: b.tombstones,
        plain: vec![],
    };
    let b2 = rekey_with(&f2, &f2.old, &mut TestRng::new(b"second"), |_, _| {}).unwrap();
    assert_eq!(b2.vk_epoch, 3);
    assert_eq!(b2.items[0].1.rev, f.items[0].1.rev + 2);
}

fn run_vectors() -> ferret_core::testing::vector::RunReport {
    let file = load_ops("rekey.json", |_| true);
    ferret_core::testing::vector::run_all(&file, |case, rng| {
        assert_eq!(case.op, "rekey.run");
        let input = &case.input;
        let vault = vault_of(input);
        let items: Vec<(ItemId, u64, Vec<u8>, [u8; 32])> = input["items"]
            .as_array()
            .unwrap()
            .iter()
            .map(|i| {
                (
                    ItemId::from_bytes(id16(&i["item_id"])),
                    u64s(&i["rev"]),
                    hex(&i["envelope"]),
                    hexn(&i["tag"]),
                )
            })
            .collect();
        let tombs: Vec<(ItemId, u64, Vec<u8>)> = input["tombstones"]
            .as_array()
            .unwrap()
            .iter()
            .map(|i| {
                (
                    ItemId::from_bytes(id16(&i["item_id"])),
                    u64s(&i["rev"]),
                    hex(&i["tomb"]),
                )
            })
            .collect();
        let ritems: Vec<RekeyItem<'_>> = items
            .iter()
            .map(|(id, rev, envelope, tag)| RekeyItem {
                item_id: *id,
                rev: *rev,
                envelope,
                tag,
            })
            .collect();
        let rtombs: Vec<RekeyTombstone<'_>> = tombs
            .iter()
            .map(|(id, rev, tomb)| RekeyTombstone {
                item_id: *id,
                rev: *rev,
                tomb,
            })
            .collect();
        let k = Kek::from_test_bytes(hexn(&input["password_kek"]));
        assert_eq!(input["password_ksf_profile"], json!(1));
        let rekey_input = RekeyInput {
            base_seq: u64s(&input["base_seq"]),
            items: &ritems,
            tombstones: &rtombs,
            password_kek: &k,
            password_method: (
                MethodId::from_bytes(id16(&input["password_method_id"])),
                password_method(),
            ),
            password_next_generation: u64s(&input["password_next_generation"]),
            recovery_method_id: MethodId::from_bytes(id16(&input["recovery_method_id"])),
            recovery_next_generation: u64s(&input["recovery_next_generation"]),
            manifest_rev: u64s(&input["manifest_rev"]),
        };
        let b = vault.rekey(rng, &rekey_input)?;
        let keys = unlocked_vault_keys(&b.vault);
        Ok(Outcome {
            output: json!({
                "vk_epoch": b.vk_epoch.to_string(),
                "vk": he(&keys[0]),
                "pk_a": he(&b.pk_a),
                "pk_r": he(&b.pk_r),
                "recovery_key": he(&ferret_core::testing::integrity::recovery_key_bytes(&b.recovery_key)),
                "items": b.items.iter().map(|(id, s)| json!({
                    "item_id": he(id.as_bytes()), "rev": s.rev.to_string(),
                    "envelope": he(&s.envelope), "tag": he(&s.tag),
                })).collect::<Vec<_>>(),
                "tombstones": b.tombstones.iter().map(|(id, t)| json!({
                    "item_id": he(id.as_bytes()), "rev": t.rev.to_string(), "tomb": he(&t.tomb),
                })).collect::<Vec<_>>(),
                "wraps": b.wraps.iter().map(|w| json!({
                    "method_id": he(w.method_id.as_bytes()),
                    "kek_generation": w.kek_generation.to_string(),
                    "wrap": he(&w.wrap),
                })).collect::<Vec<_>>(),
                "manifest": {
                    "rev": b.manifest.rev.to_string(),
                    "envelope": he(&b.manifest.envelope),
                    "tag": he(&b.manifest.tag),
                },
                "checkpoint": {
                    "seq": b.checkpoint.seq.to_string(),
                    "digest": he(&b.checkpoint.digest),
                    "mac": he(&b.checkpoint.mac),
                    "entries": he(&b.checkpoint.entries),
                },
            }),
            intermediate: None,
        })
    })
}

#[test]
fn rekey_vectors_from_file() {
    assert_all_passed(&run_vectors(), 10);
}
