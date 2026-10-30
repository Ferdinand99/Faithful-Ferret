//! Full rekey (Fase 1 § 4.7) and `vectors/internal/rekey.json`.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]

mod common;

use common::*;
use ferret_core::envelope::IK_WRAP_LEN;
use ferret_core::testing::item::{intermediate, open_plaintext, seal_plaintext};
use ferret_core::testing::keys::{recovery_seed, unlocked_vault_keys, wrap_aad};
use ferret_core::testing::pinning::view_from_manifest;
use ferret_core::testing::vector::Outcome;
use ferret_core::testing::{ReplayRng, TestRng};
use ferret_core::{
    AuthOp, AuthPublicKey, Checkpoint, CheckpointEntry, CheckpointFailure, Error, ItemBody, ItemId,
    ItemType, Kek, MalformedKind, Manifest, ManifestEntry, Method, MethodId, MethodKey, Pinned,
    PinnedField, RecoveryKey, RekeyBundle, RekeyInput, RekeyItem, RekeyTombstone, SealedItem,
    ServerRow, Tombstone, UnlockedVault, auth_sign, decrypt_item, decrypt_manifest, encrypt_item,
    encrypt_manifest, make_checkpoint, make_tombstone, recovery_public_key, unwrap_vk,
    verify_auth_proof, verify_checkpoint, verify_tombstone,
};
use serde_json::json;

const BASE_SEQ: u64 = 77;
/// Floors of the pinned record: the new wraps get these plus one.
const PASSWORD_FLOOR: u64 = 3;
const RECOVERY_FLOOR: u64 = 1;
const OLD_MANIFEST_REV: u64 = 8;

fn item_id(b: u8) -> ItemId {
    ItemId::from_bytes([b; 16])
}

fn kek() -> Kek {
    Kek::from_test_bytes([0xd0; 32])
}

fn pinned_for(vault: &UnlockedVault, password: u64, recovery: u64) -> Pinned {
    let c = vault.context();
    Pinned {
        server_url: "https://ferret.example".into(),
        account_id: c.account_id,
        vault_id: c.vault_id,
        ksf_profile: 1,
        kek_generation_max: vec![
            (MethodKey::Password, password),
            (MethodKey::Recovery, recovery),
        ],
        vk_epoch_max: c.vk_epoch,
        sk_bit: true,
        pk_a: vault.auth_public_key(),
        server_public_key: None,
    }
}

struct Fixture {
    old: UnlockedVault,
    items: Vec<(ItemId, SealedItem)>,
    tombs: Vec<(ItemId, Tombstone)>,
    manifest: SealedItem,
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
    let manifest = encrypt_manifest(
        &mut rng,
        &old,
        OLD_MANIFEST_REV,
        &Manifest::new(
            1,
            vec![
                ManifestEntry::new(1, method_id(0x70), PASSWORD_FLOOR),
                ManifestEntry::new(2, method_id(0x71), RECOVERY_FLOOR),
            ],
        ),
    )
    .unwrap();
    Fixture {
        old,
        items,
        tombs,
        manifest,
        plain,
    }
}

impl Fixture {
    /// The checkpoint of the old state as a client would have made it at
    /// `seq`.
    fn checkpoint(&self, seq: u64) -> Checkpoint {
        let mut entries: Vec<CheckpointEntry> = self
            .items
            .iter()
            .map(|(id, s)| CheckpointEntry::live(*id, s.rev, &s.envelope))
            .collect();
        entries.extend(
            self.tombs
                .iter()
                .map(|(id, t)| CheckpointEntry::tombstone(*id, t.rev)),
        );
        entries.push(CheckpointEntry::live(
            ItemId::MANIFEST,
            self.manifest.rev,
            &self.manifest.envelope,
        ));
        make_checkpoint(&self.old, seq, entries).unwrap()
    }
}

/// Everything a rekey takes, so a test can change one part.
struct Inputs {
    cp: Checkpoint,
    pinned: Pinned,
    base_seq: u64,
    manifest: SealedItem,
}

fn inputs(f: &Fixture) -> Inputs {
    Inputs {
        cp: f.checkpoint(BASE_SEQ),
        pinned: pinned_for(&f.old, PASSWORD_FLOOR, RECOVERY_FLOOR),
        base_seq: BASE_SEQ,
        manifest: f.manifest.clone(),
    }
}

fn rekey_full<R: ferret_core::SecureRng>(
    f: &Fixture,
    i: &Inputs,
    rng: &mut R,
    edit: impl FnOnce(&mut Vec<(ItemId, SealedItem)>, &mut Vec<(ItemId, Tombstone)>),
) -> Result<RekeyBundle, Error> {
    rekey_remembering(f, i, rng, ferret_core::RollbackMemory::NoMemory, edit)
}

fn rekey_remembering<R: ferret_core::SecureRng>(
    f: &Fixture,
    i: &Inputs,
    rng: &mut R,
    memory: ferret_core::RollbackMemory<'_>,
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
        base_seq: i.base_seq,
        old_checkpoint: &i.cp,
        old_manifest: RekeyItem {
            item_id: ItemId::MANIFEST,
            rev: i.manifest.rev,
            envelope: &i.manifest.envelope,
            tag: &i.manifest.tag,
        },
        items: &ritems,
        tombstones: &rtombs,
        pinned: &i.pinned,
        password_kek: &k,
        password_method: (method_id(0x70), password_method()),
        recovery_method_id: method_id(0x71),
    };
    f.old.rekey(rng, &input, memory)
}

fn rekey_with<R: ferret_core::SecureRng>(
    f: &Fixture,
    rng: &mut R,
    edit: impl FnOnce(&mut Vec<(ItemId, SealedItem)>, &mut Vec<(ItemId, Tombstone)>),
) -> Result<RekeyBundle, Error> {
    rekey_full(f, &inputs(f), rng, edit)
}

fn rekey(f: &Fixture, seed: &str) -> RekeyBundle {
    rekey_with(f, &mut TestRng::new(seed.as_bytes()), |_, _| {}).unwrap()
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
    // The pinned floor plus one.
    assert_eq!(pw.kek_generation, PASSWORD_FLOOR + 1);
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
        vec![
            (1, method_id(0x70), PASSWORD_FLOOR + 1),
            (2, method_id(0x71), RECOVERY_FLOOR + 1)
        ]
    );
    // The old manifest's revision plus one.
    assert_eq!(b.manifest.rev, OLD_MANIFEST_REV + 1);
    // It seeds the pinning floors without a passkey or local method.
    let view = view_from_manifest(&m).unwrap();
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
    assert_eq!(rec.kek_generation, RECOVERY_FLOOR + 1);
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
fn rekey_generations_and_manifest_rev_come_from_the_floors_not_the_caller() {
    let f = fixture();
    let mut i = inputs(&f);
    i.pinned = pinned_for(&f.old, 9, 5);
    let b = rekey_full(&f, &i, &mut TestRng::new(b"g"), |_, _| {}).unwrap();
    assert_eq!(b.wraps[0].kek_generation, 10);
    assert_eq!(b.wraps[1].kek_generation, 6);
    // Stale floors: the pinned record is behind the old manifest (the
    // password wrap at 3, the recovery wrap at 1), so the generations follow
    // the manifest, not the lower floors.
    let mut stale = inputs(&f);
    stale.pinned = pinned_for(&f.old, 1, 0);
    let b = rekey_full(&f, &stale, &mut TestRng::new(b"s"), |_, _| {}).unwrap();
    assert_eq!(b.wraps[0].kek_generation, PASSWORD_FLOOR + 1);
    assert_eq!(b.wraps[1].kek_generation, RECOVERY_FLOOR + 1);
    // One floor above the manifest and one below.
    let mut mixed = inputs(&f);
    mixed.pinned = pinned_for(&f.old, 1, 6);
    let b = rekey_full(&f, &mixed, &mut TestRng::new(b"s"), |_, _| {}).unwrap();
    assert_eq!(b.wraps[0].kek_generation, PASSWORD_FLOOR + 1);
    assert_eq!(b.wraps[1].kek_generation, 7);
    // A floor of the password wrap that cannot be raised, or a missing
    // floor, makes no plan (and draws nothing).
    let mut draws = ReplayRng::new(vec![]);
    for (pw, rec) in [
        (ferret_core::pinning::MAX_GENERATION, 1),
        (1, ferret_core::pinning::MAX_GENERATION),
    ] {
        let mut i = inputs(&f);
        i.pinned = pinned_for(&f.old, pw, rec);
        assert_eq!(
            rekey_full(&f, &i, &mut draws, |_, _| {}).err(),
            Some(Error::Malformed(MalformedKind::PinnedRecord))
        );
    }
    for missing in [MethodKey::Password, MethodKey::Recovery] {
        let mut i = inputs(&f);
        i.pinned.kek_generation_max.retain(|(k, _)| *k != missing);
        assert_eq!(
            rekey_full(&f, &i, &mut draws, |_, _| {}).err(),
            Some(Error::Malformed(MalformedKind::PinnedRecord)),
            "{missing:?}"
        );
    }
    // A pinned record of another account, vault, epoch or key.
    let mut i = inputs(&f);
    i.pinned.account_id = ferret_core::AccountId::from_bytes([9; 16]);
    assert_eq!(
        rekey_full(&f, &i, &mut draws, |_, _| {}).err(),
        Some(Error::Pinned(PinnedField::AccountId))
    );
    let mut i = inputs(&f);
    i.pinned.vault_id = ferret_core::VaultId::from_bytes([9; 16]);
    assert_eq!(
        rekey_full(&f, &i, &mut draws, |_, _| {}).err(),
        Some(Error::Pinned(PinnedField::VaultId))
    );
    let mut i = inputs(&f);
    i.pinned.vk_epoch_max = 2;
    assert_eq!(
        rekey_full(&f, &i, &mut draws, |_, _| {}).err(),
        Some(Error::Pinned(PinnedField::VkEpoch))
    );
    let mut i = inputs(&f);
    i.pinned.pk_a = [7; 32];
    assert_eq!(
        rekey_full(&f, &i, &mut draws, |_, _| {}).err(),
        Some(Error::Pinned(PinnedField::AuthKey))
    );
    assert_eq!(draws.remaining(), 0);
}

#[test]
fn rekey_is_all_or_nothing() {
    let f = fixture();
    // A damaged tag on the first, a middle and the last item.
    for victim in [0usize, 1, 3] {
        let r = rekey_with(&f, &mut TestRng::new(b"x"), |items, _| {
            items[victim].1.tag[0] ^= 1;
        });
        assert_eq!(r.err(), Some(Error::Decrypt), "item {victim}");
    }
    // A damaged envelope.
    let r = rekey_with(&f, &mut TestRng::new(b"x"), |items, _| {
        let n = items[3].1.envelope.len();
        items[3].1.envelope[n - 1] ^= 1;
    });
    assert_eq!(r.err(), Some(Error::Decrypt));
    // An item from another vault state (the wrong revision).
    let r = rekey_with(&f, &mut TestRng::new(b"x"), |items, _| {
        items[2].1.rev += 1;
    });
    assert_eq!(r.err(), Some(Error::Decrypt));
    // A forged tombstone is not turned into a real one.
    let r = rekey_with(&f, &mut TestRng::new(b"x"), |_, tombs| {
        tombs[1].1.tomb[10] ^= 1;
    });
    assert_eq!(r.err(), Some(Error::TombstoneInvalid));
    // A tombstone from another item.
    let r = rekey_with(&f, &mut TestRng::new(b"x"), |_, tombs| {
        tombs[0].0 = item_id(0x53);
    });
    assert_eq!(r.err(), Some(Error::TombstoneInvalid));
    // The same inputs, undamaged, work.
    rekey_with(&f, &mut TestRng::new(b"x"), |_, _| {}).unwrap();
}

#[test]
fn rekey_refuses_rows_that_are_not_the_state_of_the_old_checkpoint() {
    let f = fixture();
    // Nothing is drawn for any of these: a draw would panic the replay RNG.
    let mut draws = ReplayRng::new(vec![]);
    let failure = |kind| Some(Error::Checkpoint(kind));

    // A server that hides a live item: the checkpoint is at the top, so the
    // state is not the checkpoint's.
    for victim in 0..f.items.len() {
        let r = rekey_with(&f, &mut draws, |items, _| {
            items.remove(victim);
        });
        assert_eq!(
            r.err(),
            failure(CheckpointFailure::TopDigestMismatch),
            "hide item {victim}"
        );
    }

    // An item at an older revision than the checkpoint's.
    let body = ItemBody::new(ItemType::Login, "Old", 1);
    let older = encrypt_item(
        &mut TestRng::new(b"older"),
        &f.old,
        f.items[0].0,
        f.items[0].1.rev - 1,
        &body,
        None,
    )
    .unwrap();
    let r = rekey_with(&f, &mut draws, |items, _| items[0].1 = older.clone());
    assert_eq!(r.err(), failure(CheckpointFailure::LowerRev));

    // A tombstone at an older revision than the checkpoint's.
    let older_tomb = make_tombstone(
        &mut TestRng::new(b"older-tomb"),
        &f.old,
        f.tombs[0].0,
        f.tombs[0].1.rev - 1,
    )
    .unwrap();
    let r = rekey_with(&f, &mut draws, |_, tombs| tombs[0].1 = older_tomb.clone());
    assert_eq!(r.err(), failure(CheckpointFailure::LowerRev));

    // The old manifest at an older revision than the checkpoint's.
    let mut stale_manifest = inputs(&f);
    stale_manifest.manifest = encrypt_manifest(
        &mut TestRng::new(b"older-manifest"),
        &f.old,
        OLD_MANIFEST_REV - 1,
        &decrypt_manifest(
            &f.old,
            f.manifest.rev,
            &f.manifest.envelope,
            &f.manifest.tag,
        )
        .unwrap(),
    )
    .unwrap();
    assert_eq!(
        rekey_full(&f, &stale_manifest, &mut draws, |_, _| {}).err(),
        failure(CheckpointFailure::LowerRev)
    );

    // A live row that the checkpoint does not have, at the top.
    let extra = encrypt_item(
        &mut TestRng::new(b"extra"),
        &f.old,
        item_id(0x4e),
        1,
        &body,
        None,
    )
    .unwrap();
    let r = rekey_with(&f, &mut draws, |items, _| {
        items.push((item_id(0x4e), extra.clone()));
    });
    assert_eq!(r.err(), failure(CheckpointFailure::TopDigestMismatch));

    // The checkpoint must verify.
    let mut bad = inputs(&f);
    bad.cp.mac[0] ^= 1;
    assert_eq!(
        rekey_full(&f, &bad, &mut draws, |_, _| {}).err(),
        failure(CheckpointFailure::BadMac)
    );
    // The old manifest is checked too: its tag.
    let mut bad_manifest = inputs(&f);
    bad_manifest.manifest.tag[0] ^= 1;
    assert_eq!(
        rekey_full(&f, &bad_manifest, &mut draws, |_, _| {}).err(),
        Some(Error::Decrypt)
    );
    assert_eq!(draws.remaining(), 0);
}

#[test]
fn rekey_requires_a_current_checkpoint() {
    let f = fixture();
    let mut draws = ReplayRng::new(vec![]);
    let refused = Some(Error::Malformed(MalformedKind::Entries));
    // A checkpoint behind `base_seq` leaves the rows written since without
    // protection: an item written after it, which the server hides, would
    // be dropped for good. The rows passed here are consistent with the stale
    // checkpoint (they are exactly its state, as when the server hides the
    // newer item), and the rekey is still refused, with no draws.
    for seq in [0, BASE_SEQ - 3, BASE_SEQ - 1] {
        let mut behind = inputs(&f);
        behind.cp = f.checkpoint(seq);
        assert_eq!(
            rekey_full(&f, &behind, &mut draws, |_, _| {}).err(),
            refused,
            "checkpoint at {seq}"
        );
    }
    // A checkpoint above `base_seq` is refused as well.
    let mut ahead = inputs(&f);
    ahead.cp = f.checkpoint(BASE_SEQ + 1);
    assert_eq!(rekey_full(&f, &ahead, &mut draws, |_, _| {}).err(), refused);
    let mut lower_base = inputs(&f);
    lower_base.base_seq = BASE_SEQ - 1;
    assert_eq!(
        rekey_full(&f, &lower_base, &mut draws, |_, _| {}).err(),
        refused
    );
    assert_eq!(draws.remaining(), 0);
    // At `base_seq` it works.
    rekey_with(&f, &mut TestRng::new(b"current"), |_, _| {}).unwrap();
}

#[test]
fn rekey_accepts_a_purged_tombstone() {
    let f = fixture();
    // The server dropped a tombstone: the new state simply has one less.
    let b = rekey_with(&f, &mut TestRng::new(b"p"), |_, tombs| {
        tombs.remove(0);
    })
    .unwrap();
    assert_eq!(b.tombstones.len(), 1);
    let b = rekey_with(&f, &mut TestRng::new(b"p"), |_, tombs| {
        tombs.clear();
    })
    .unwrap();
    assert!(b.tombstones.is_empty());
    assert_eq!(b.checkpoint.entries.len(), 56 * (4 + 1));
}

#[test]
fn rekey_refuses_input_that_cannot_make_a_plan() {
    let f = fixture();
    let mut draws = ReplayRng::new(vec![]);
    // Nothing is drawn: a draw would panic the replay RNG.
    let dup = rekey_with(&f, &mut draws, |items, tombs| {
        tombs[0].0 = items[0].0;
    });
    assert_eq!(dup.err(), Some(Error::Malformed(MalformedKind::Entries)));
    let manifest_id = rekey_with(&f, &mut draws, |_, tombs| {
        tombs[0].0 = ItemId::MANIFEST;
    });
    assert_eq!(
        manifest_id.err(),
        Some(Error::Malformed(MalformedKind::Envelope))
    );
    let overflow = rekey_with(&f, &mut draws, |items, _| {
        items[0].1.rev = u64::MAX;
    });
    assert_eq!(
        overflow.err(),
        Some(Error::Malformed(MalformedKind::Entries))
    );
    assert_eq!(draws.remaining(), 0);

    // The password method must be a password method.
    let i = inputs(&f);
    let k = kek();
    let input = RekeyInput {
        base_seq: i.base_seq,
        old_checkpoint: &i.cp,
        old_manifest: RekeyItem {
            item_id: ItemId::MANIFEST,
            rev: i.manifest.rev,
            envelope: &i.manifest.envelope,
            tag: &i.manifest.tag,
        },
        items: &[],
        tombstones: &[],
        pinned: &i.pinned,
        password_kek: &k,
        password_method: (method_id(0x70), Method::Recovery),
        recovery_method_id: method_id(0x71),
    };
    assert_eq!(
        f.old
            .rekey(&mut draws, &input, ferret_core::RollbackMemory::NoMemory)
            .err(),
        Some(Error::Unsupported)
    );
    // The old manifest must carry the manifest's reserved id.
    let wrong_id = RekeyInput {
        old_manifest: RekeyItem {
            item_id: item_id(5),
            ..input.old_manifest
        },
        password_method: (method_id(0x70), password_method()),
        ..input
    };
    assert_eq!(
        f.old
            .rekey(&mut draws, &wrong_id, ferret_core::RollbackMemory::NoMemory)
            .err(),
        Some(Error::Malformed(MalformedKind::Envelope))
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
    verify_checkpoint(
        &b.vault,
        &b.checkpoint,
        &rows,
        BASE_SEQ,
        ferret_core::RollbackMemory::NoMemory,
    )
    .unwrap();
    // After the rekey the server's seq is higher; the checkpoint still holds.
    verify_checkpoint(
        &b.vault,
        &b.checkpoint,
        &rows,
        BASE_SEQ + 20,
        ferret_core::RollbackMemory::NoMemory,
    )
    .unwrap();
    // It is signed with the new K_head only.
    assert_eq!(
        verify_checkpoint(
            &f.old,
            &b.checkpoint,
            &rows,
            BASE_SEQ,
            ferret_core::RollbackMemory::NoMemory
        )
        .err(),
        Some(Error::Checkpoint(CheckpointFailure::BadMac))
    );
    // The old rows (the old state) are not what this checkpoint describes.
    let old_rows: Vec<ServerRow> = f
        .items
        .iter()
        .map(|(id, s)| ServerRow::live(&f.old, *id, s.rev, &s.envelope, &s.tag).unwrap())
        .collect();
    assert!(
        verify_checkpoint(
            &b.vault,
            &b.checkpoint,
            &old_rows,
            BASE_SEQ + 1,
            ferret_core::RollbackMemory::NoMemory
        )
        .is_err()
    );
}

#[test]
fn rekey_request_is_signed_by_the_old_key() {
    let f = fixture();
    let b = rekey(&f, "a");
    let nonce = [7u8; 32];
    let body = b"{\"rekey\":true}";
    // The caller signs the request body with the old vault.
    let proof = auth_sign(&f.old, AuthOp::Rekey, &nonce, body).unwrap();
    let account = f.old.context().account_id;
    verify_auth_proof(
        &AuthPublicKey::new(f.old.auth_public_key()),
        AuthOp::Rekey,
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
        verify_auth_proof(
            &AuthPublicKey::new(b.pk_a),
            AuthOp::Rekey,
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
    let second = Fixture {
        items: b.items.clone(),
        tombs: b.tombstones.clone(),
        manifest: b.manifest.clone(),
        plain: vec![],
        // The next rekey starts from the new vault.
        old: b.vault,
    };
    let i = Inputs {
        cp: b.checkpoint,
        pinned: pinned_for(
            &second.old,
            b.wraps[0].kek_generation,
            b.wraps[1].kek_generation,
        ),
        base_seq: BASE_SEQ,
        manifest: b.manifest,
    };
    let b2 = rekey_full(&second, &i, &mut TestRng::new(b"second"), |_, _| {}).unwrap();
    assert_eq!(b2.vk_epoch, 3);
    assert_eq!(b2.items[0].1.rev, f.items[0].1.rev + 2);
    assert_eq!(b2.wraps[0].kek_generation, PASSWORD_FLOOR + 2);
    assert_eq!(b2.manifest.rev, OLD_MANIFEST_REV + 2);
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
        let old_cp = Checkpoint {
            seq: u64s(&input["old_checkpoint"]["seq"]),
            digest: hexn(&input["old_checkpoint"]["digest"]),
            mac: hexn(&input["old_checkpoint"]["mac"]),
            entries: hex(&input["old_checkpoint"]["entries"]),
        };
        let m = &input["old_manifest"];
        let (m_envelope, m_tag) = (hex(&m["envelope"]), hexn::<32>(&m["tag"]));
        // The floors of the pinned record; a null floor is a missing one.
        let mut pinned = pinned_for(&vault, 0, 0);
        pinned.kek_generation_max.clear();
        for (key, name) in [
            (MethodKey::Password, "password_floor"),
            (MethodKey::Recovery, "recovery_floor"),
        ] {
            if !input[name].is_null() {
                pinned.kek_generation_max.push((key, u64s(&input[name])));
            }
        }
        let rekey_input = RekeyInput {
            base_seq: u64s(&input["base_seq"]),
            old_checkpoint: &old_cp,
            old_manifest: RekeyItem {
                item_id: ItemId::MANIFEST,
                rev: u64s(&m["rev"]),
                envelope: &m_envelope,
                tag: &m_tag,
            },
            items: &ritems,
            tombstones: &rtombs,
            pinned: &pinned,
            password_kek: &k,
            password_method: (
                MethodId::from_bytes(id16(&input["password_method_id"])),
                password_method(),
            ),
            recovery_method_id: MethodId::from_bytes(id16(&input["recovery_method_id"])),
        };
        let b = vault.rekey(rng, &rekey_input, ferret_core::RollbackMemory::NoMemory)?;
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
    assert_all_passed(&run_vectors(), 20);
}

#[test]
fn a_rekey_gives_the_pinned_record_to_store() {
    let f = fixture();
    let b = rekey(&f, "pinned");
    let old = pinned_for(&f.old, PASSWORD_FLOOR, RECOVERY_FLOOR);
    let after = b.pinned(&old).unwrap();
    // The epoch and pk_a are the new vault's, the floors are the generations
    // of the new wraps, and the record that was passed in is untouched.
    assert_eq!(after.vk_epoch_max, 2);
    assert_eq!(after.pk_a, b.pk_a);
    assert_eq!(old.vk_epoch_max, 1);
    assert_eq!(old.pk_a, f.old.auth_public_key());
    let floor = |p: &Pinned, k: MethodKey| {
        p.kek_generation_max
            .iter()
            .find(|(key, _)| *key == k)
            .map(|(_, g)| *g)
    };
    assert_eq!(
        floor(&after, MethodKey::Password),
        Some(b.wraps[0].kek_generation)
    );
    assert_eq!(
        floor(&after, MethodKey::Recovery),
        Some(b.wraps[1].kek_generation)
    );
    assert_eq!(b.wraps[0].kek_generation, PASSWORD_FLOOR + 1);
    // The new password wrap unlocks under it, the old epoch does not.
    let mut p = after.clone();
    let seen = ferret_core::ServerView {
        server_url: "https://ferret.example",
        context: *b.vault.context(),
        sk_bit: true,
        server_public_key: None,
    };
    let vault = p.unlock_server(&seen, &b.wraps[0], &kek()).unwrap();
    assert!(vault.same_vault_key(&b.vault));
    // A record of another account or vault is refused.
    let mut other = old.clone();
    other.vault_id = ferret_core::VaultId::from_bytes([9; 16]);
    assert_eq!(
        b.pinned(&other).err(),
        Some(Error::Pinned(PinnedField::VaultId))
    );
}

#[test]
fn the_pinned_record_after_a_rekey_is_refused_for_a_bundle_that_does_not_fit() {
    let f = fixture();
    let old = pinned_for(&f.old, PASSWORD_FLOOR, RECOVERY_FLOOR);
    let mut b = rekey(&f, "pinned refusals");
    // Another account.
    let mut other = old.clone();
    other.account_id = ferret_core::AccountId::from_bytes([9; 16]);
    assert_eq!(
        b.pinned(&other).err(),
        Some(Error::Pinned(PinnedField::AccountId))
    );
    // A bundle with one wrap, or with a password wrap that is not one.
    let recovery = b.wraps.pop().unwrap();
    assert_eq!(
        b.pinned(&old).err(),
        Some(Error::Malformed(MalformedKind::Entries))
    );
    b.wraps.push(recovery);
    b.wraps[0].method = Method::Recovery;
    assert_eq!(b.pinned(&old).err(), Some(Error::Unsupported));
}

#[test]
fn rekey_refuses_a_password_wrap_below_the_pinned_profile() {
    // The new wrap would lock this device out at its next unlock
    // (`kdf_profile_downgrade`), so nothing is drawn and nothing is made.
    let f = fixture();
    let mut draws = ReplayRng::new(vec![]);
    let mut i = inputs(&f);
    i.pinned.ksf_profile = 2;
    assert_eq!(
        rekey_full(&f, &i, &mut draws, |_, _| {}).err(),
        Some(Error::KdfProfileDowngrade)
    );
    assert_eq!(draws.remaining(), 0);
}

#[test]
fn rekey_checks_the_state_it_replaces_against_the_rollback_memory() {
    use ferret_core::{CheckpointFailure as F, RollbackMemory, SyncMemory};
    let f = fixture();
    let i = inputs(&f);
    fn no_edit(_: &mut Vec<(ItemId, SealedItem)>, _: &mut Vec<(ItemId, Tombstone)>) {}

    // A device that has seen a newer state refuses to rekey the older one,
    // before any draw and without changing the record.
    let mut newer = SyncMemory::new();
    newer.accept_rows(&[], BASE_SEQ + 5).unwrap();
    let before = newer.clone();
    let mut draws = ReplayRng::new(vec![]);
    assert_eq!(
        rekey_remembering(
            &f,
            &i,
            &mut draws,
            RollbackMemory::Remembered(&mut newer),
            no_edit
        )
        .err(),
        Some(Error::Checkpoint(F::RememberedTopSeq))
    );
    assert_eq!(newer, before);
    assert_eq!(draws.remaining(), 0);

    // A device that has seen the state it is based on may rekey it, and its
    // record advances to that state.
    let mut seen = SyncMemory::new();
    let mut rng = TestRng::new(b"remembered");
    rekey_remembering(
        &f,
        &i,
        &mut rng,
        RollbackMemory::Remembered(&mut seen),
        no_edit,
    )
    .unwrap();
    assert_eq!(
        (seen.max_seq(), seen.checkpoint_seq()),
        (BASE_SEQ, BASE_SEQ)
    );
}
