//! Tombstones (Fase 1 § 8.4) and item tags (§ 8.6), and
//! `vectors/internal/tomb-tag.json`.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]

mod common;

use common::*;
use ferret_core::testing::integrity::tombstone_aad;
use ferret_core::testing::keys::unlocked_vault_keys;
use ferret_core::testing::prim::{aead_open, aead_seal, hmac_sha256};
use ferret_core::testing::vector::Outcome;
use ferret_core::testing::{ReplayRng, TestRng};
use ferret_core::{
    AccountId, Error, ItemId, UnlockedVault, VaultContext, VaultId, item_tag, make_tombstone,
    verify_item_tag, verify_tombstone,
};
use serde_json::json;
use sha2::{Digest, Sha256};

fn item_id(b: u8) -> ItemId {
    ItemId::from_bytes([b; 16])
}

fn rng(seed: &str) -> TestRng {
    TestRng::new(seed.as_bytes())
}

/// A tombstone made by hand under `key`, with the AAD of Fase 1 § 8.4 written
/// out field by field so that each field can be changed.
fn hand_tomb(
    key: &[u8; 32],
    label_s: &str,
    version: u8,
    suite: u8,
    vault_id: [u8; 16],
    item: [u8; 16],
    rev: u64,
) -> Vec<u8> {
    let aad = [
        label(label_s),
        t(0x02, &[version]),
        t(0x03, &[suite]),
        t(0x11, &vault_id),
        t(0x12, &item),
        t(0x22, &rev.to_be_bytes()),
    ]
    .concat();
    let mut r = ReplayRng::new(vec![vec![0x77; 24]]);
    aead_seal(&mut r, key, &aad, &[]).unwrap()
}

#[test]
fn tomb_is_40_bytes_and_binds_fields() {
    let vault = unlocked(0x5a);
    let tomb = make_tombstone(&mut rng("tomb"), &vault, item_id(1), 7).unwrap();
    assert_eq!(tomb.tomb.len(), 40);
    assert_eq!(tomb.rev, 7);
    verify_tombstone(&vault, item_id(1), 7, &tomb.tomb).unwrap();

    let invalid = Err(Error::TombstoneInvalid);
    assert_eq!(verify_tombstone(&vault, item_id(2), 7, &tomb.tomb), invalid);
    assert_eq!(verify_tombstone(&vault, item_id(1), 8, &tomb.tomb), invalid);
    // Another vault id gives other keys (the id is in the HKDF salt) and the
    // AAD differs too; both end in the same error.
    let other = UnlockedVault::from_vault_key(
        VaultContext {
            vault_id: VaultId::from_bytes([0x23; 16]),
            ..ctx()
        },
        vk(0x5a),
    )
    .unwrap();
    assert_eq!(verify_tombstone(&other, item_id(1), 7, &tomb.tomb), invalid);
    // Another epoch, account and key.
    for c in [
        VaultContext {
            vk_epoch: 2,
            ..ctx()
        },
        VaultContext {
            account_id: AccountId::from_bytes([0x12; 16]),
            ..ctx()
        },
    ] {
        let v = UnlockedVault::from_vault_key(c, vk(0x5a)).unwrap();
        assert_eq!(verify_tombstone(&v, item_id(1), 7, &tomb.tomb), invalid);
    }
    assert_eq!(
        verify_tombstone(&unlocked(0x5b), item_id(1), 7, &tomb.tomb),
        invalid
    );
}

#[test]
fn tomb_has_exactly_one_nonce_draw() {
    let vault = unlocked(0x5a);
    let mut r = ReplayRng::new(vec![vec![9; 24]]);
    let tomb = make_tombstone(&mut r, &vault, item_id(1), 2).unwrap();
    r.finish().unwrap();
    assert_eq!(&tomb.tomb[..24], &[9; 24]);
}

#[test]
fn tomb_aad_is_exact_tlv() {
    let vault = unlocked(0x5a);
    let c = ctx();
    let tomb = make_tombstone(&mut rng("aad"), &vault, item_id(3), 5).unwrap();
    let k_del = unlocked_vault_keys(&vault)[2];
    let expected = [
        label("ferret/v1/tomb"),
        t(0x02, &[1]),
        t(0x03, &[1]),
        t(0x11, c.vault_id.as_bytes()),
        t(0x12, &[3; 16]),
        t(0x22, &5u64.to_be_bytes()),
    ]
    .concat();
    assert_eq!(
        tombstone_aad(&c.vault_id, &item_id(3), 5).unwrap(),
        expected
    );
    // It opens with the hand-made AAD, under K_del, to an empty plaintext.
    assert!(aead_open(&k_del, &expected, &tomb.tomb).unwrap().is_empty());
}

#[test]
fn tomb_uses_k_del_not_item_key() {
    let vault = unlocked(0x5a);
    let c = ctx();
    let [vk_bytes, k_head, k_del, _] = unlocked_vault_keys(&vault);
    let item = [4u8; 16];
    // Made by hand under K_del: verifies.
    let good = hand_tomb(
        &k_del,
        "ferret/v1/tomb",
        1,
        1,
        *c.vault_id.as_bytes(),
        item,
        9,
    );
    verify_tombstone(&vault, ItemId::from_bytes(item), 9, &good).unwrap();
    // The same bytes under any other key (K_head, VK, an item key) do not.
    for (name, key) in [
        ("K_head", k_head),
        ("VK", vk_bytes),
        ("an item key", [0x33; 32]),
    ] {
        let wrong = hand_tomb(
            &key,
            "ferret/v1/tomb",
            1,
            1,
            *c.vault_id.as_bytes(),
            item,
            9,
        );
        assert_eq!(
            verify_tombstone(&vault, ItemId::from_bytes(item), 9, &wrong),
            Err(Error::TombstoneInvalid),
            "{name}"
        );
    }
}

#[test]
fn tomb_binds_each_aad_field() {
    let vault = unlocked(0x5a);
    let c = ctx();
    let k_del = unlocked_vault_keys(&vault)[2];
    let vid = *c.vault_id.as_bytes();
    let item = [5u8; 16];
    let make = |label_s: &str, version, suite, vault_id, item_id, rev| {
        hand_tomb(&k_del, label_s, version, suite, vault_id, item_id, rev)
    };
    let ok = make("ferret/v1/tomb", 1, 1, vid, item, 3);
    verify_tombstone(&vault, ItemId::from_bytes(item), 3, &ok).unwrap();
    let id = ItemId::from_bytes(item);
    for (name, tomb) in [
        ("label", make("ferret/v1/item", 1, 1, vid, item, 3)),
        ("version", make("ferret/v1/tomb", 2, 1, vid, item, 3)),
        ("suite", make("ferret/v1/tomb", 1, 2, vid, item, 3)),
        (
            "vault_id",
            make("ferret/v1/tomb", 1, 1, [0x23; 16], item, 3),
        ),
        ("item_id", make("ferret/v1/tomb", 1, 1, vid, [6; 16], 3)),
        ("rev", make("ferret/v1/tomb", 1, 1, vid, item, 4)),
    ] {
        assert_eq!(
            verify_tombstone(&vault, id, 3, &tomb),
            Err(Error::TombstoneInvalid),
            "{name}"
        );
    }
}

#[test]
fn tomb_rejects_every_length_and_bit() {
    let vault = unlocked(0x5a);
    let tomb = make_tombstone(&mut rng("bits"), &vault, item_id(1), 2)
        .unwrap()
        .tomb;
    for len in [0usize, 1, 23, 24, 39, 41, 64] {
        let mut bytes = tomb.clone();
        bytes.resize(len, 0);
        assert_eq!(
            verify_tombstone(&vault, item_id(1), 2, &bytes),
            Err(Error::TombstoneInvalid),
            "length {len}"
        );
    }
    for i in 0..tomb.len() {
        for bit in 0..8 {
            let mut bytes = tomb.clone();
            bytes[i] ^= 1 << bit;
            assert_eq!(
                verify_tombstone(&vault, item_id(1), 2, &bytes),
                Err(Error::TombstoneInvalid)
            );
        }
    }
}

#[test]
fn the_manifest_id_has_no_tombstone() {
    let vault = unlocked(0x5a);
    assert_eq!(
        make_tombstone(&mut rng("m"), &vault, ItemId::MANIFEST, 2).err(),
        Some(Error::Malformed(ferret_core::MalformedKind::Envelope))
    );
    let tomb = hand_tomb(
        &unlocked_vault_keys(&vault)[2],
        "ferret/v1/tomb",
        1,
        1,
        *ctx().vault_id.as_bytes(),
        [0; 16],
        2,
    );
    assert_eq!(
        verify_tombstone(&vault, ItemId::MANIFEST, 2, &tomb),
        Err(Error::TombstoneInvalid)
    );
}

#[test]
fn tomb_error_has_a_stable_code() {
    assert_eq!(Error::TombstoneInvalid.code(), "tombstone_invalid");
}

#[test]
fn item_tag_is_the_documented_hmac() {
    let vault = unlocked(0x5a);
    let envelope = vec![1u8, 1, 1, 7, 8, 9];
    let k_head = unlocked_vault_keys(&vault)[1];
    let message = [
        label("ferret/v1/item-tag"),
        t(0x12, &[2; 16]),
        t(0x22, &6u64.to_be_bytes()),
        t(0x35, &Sha256::digest(&envelope)),
    ]
    .concat();
    let expected = hmac_sha256(&k_head, &message).unwrap();
    assert_eq!(
        item_tag(&vault, item_id(2), 6, &envelope).unwrap(),
        expected
    );
    verify_item_tag(&vault, item_id(2), 6, &envelope, &expected).unwrap();
}

fn run(ops: &[&str]) -> ferret_core::testing::vector::RunReport {
    let file = load_ops("tomb-tag.json", |op| ops.contains(&op));
    ferret_core::testing::vector::run_all(&file, |case, rng| {
        let input = &case.input;
        let vault = vault_of(input);
        let item = ItemId::from_bytes(id16(&input["item_id"]));
        let rev = u64s(&input["rev"]);
        match case.op.as_str() {
            "tomb.seal" => {
                let tomb = make_tombstone(rng, &vault, item, rev)?;
                let keys = unlocked_vault_keys(&vault);
                Ok(Outcome {
                    output: json!({ "tomb": he(&tomb.tomb) }),
                    intermediate: Some(json!({
                        "k_del": he(&keys[2]),
                        "aad": he(&tombstone_aad(&vault.context().vault_id, &item, rev)?),
                    })),
                })
            }
            "tomb.verify" => {
                verify_tombstone(&vault, item, rev, &hex(&input["tomb"]))?;
                Ok(Outcome {
                    output: json!({ "ok": true }),
                    intermediate: None,
                })
            }
            "item.tag" => {
                let envelope = hex(&input["envelope"]);
                let tag = item_tag(&vault, item, rev, &envelope)?;
                // The message, written out here, and the MAC over it.
                let message = [
                    label("ferret/v1/item-tag"),
                    t(0x12, item.as_bytes()),
                    t(0x22, &rev.to_be_bytes()),
                    t(0x35, &Sha256::digest(&envelope)),
                ]
                .concat();
                assert_eq!(
                    tag,
                    hmac_sha256(&unlocked_vault_keys(&vault)[1], &message).unwrap()
                );
                Ok(Outcome {
                    output: json!({ "tag": he(&tag) }),
                    intermediate: Some(json!({ "message": he(&message) })),
                })
            }
            "item.tag.verify" => {
                verify_item_tag(
                    &vault,
                    item,
                    rev,
                    &hex(&input["envelope"]),
                    &hexn(&input["tag"]),
                )?;
                Ok(Outcome {
                    output: json!({ "ok": true }),
                    intermediate: None,
                })
            }
            other => panic!("unknown op {other}"),
        }
    })
}

#[test]
fn tomb_vectors_from_file() {
    assert_all_passed(&run(&["tomb.seal", "tomb.verify"]), 20);
}

#[test]
fn item_tag_vectors_from_file() {
    assert_all_passed(&run(&["item.tag", "item.tag.verify"]), 10);
}
