//! Property tests for the integrity layer: tombstones,
//! item tags, checkpoints and mutation proofs.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]

mod common;

use common::*;
use ferret_core::testing::TestRng;
use ferret_core::{
    AuthOp, AuthPublicKey, CheckpointEntry, CheckpointFailure, Error, ItemId, RowState, ServerRow,
    auth_sign, item_tag, make_checkpoint, make_tombstone, verify_auth_proof, verify_checkpoint,
    verify_item_tag, verify_tombstone,
};
use proptest::prelude::*;
use std::collections::BTreeMap;

fn config() -> ProptestConfig {
    let cases = std::env::var("PROPTEST_CASES")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(256);
    ProptestConfig {
        cases,
        ..ProptestConfig::default()
    }
}

fn id(bytes: [u8; 16]) -> ItemId {
    ItemId::from_bytes(bytes)
}

/// A hash that is not the 32 zero bytes of a tombstone.
fn hash() -> impl Strategy<Value = [u8; 32]> {
    any::<[u8; 32]>().prop_filter("not the tombstone hash", |h| *h != [0; 32])
}

fn non_manifest() -> impl Strategy<Value = [u8; 16]> {
    any::<[u8; 16]>().prop_filter("not the manifest id", |b| *b != [0; 16])
}

/// A state: unique item ids, each live (with a hash) or a tombstone.
fn state() -> impl Strategy<Value = Vec<CheckpointEntry>> {
    prop::collection::btree_map(
        any::<[u8; 16]>(),
        (1u64..1_000, prop::option::of(hash())),
        0..24,
    )
    .prop_map(|m: BTreeMap<[u8; 16], (u64, Option<[u8; 32]>)>| {
        m.into_iter()
            .map(|(item, (rev, live_hash))| CheckpointEntry {
                item_id: id(item),
                rev,
                live_hash,
            })
            .collect()
    })
}

fn rows(entries: &[CheckpointEntry]) -> Vec<ServerRow> {
    entries
        .iter()
        .map(|e| ServerRow {
            item_id: e.item_id,
            rev: e.rev,
            state: match e.live_hash {
                Some(blob_sha256) => RowState::Live { blob_sha256 },
                None => RowState::Deleted,
            },
        })
        .collect()
}

proptest! {
    #![proptest_config(config())]

    #[test]
    fn tombstone_binds_all_fields(
        item in non_manifest(),
        other in non_manifest(),
        rev in 0u64..u64::MAX,
        seed in any::<[u8; 8]>(),
        flip in 0usize..40,
        bit in 0u8..8,
    ) {
        let vault = unlocked(0x5a);
        let tomb = make_tombstone(&mut TestRng::new(&seed), &vault, id(item), rev).unwrap();
        prop_assert_eq!(tomb.tomb.len(), 40);
        prop_assert!(verify_tombstone(&vault, id(item), rev, &tomb.tomb).is_ok());
        if other != item {
            prop_assert_eq!(
                verify_tombstone(&vault, id(other), rev, &tomb.tomb),
                Err(Error::TombstoneInvalid)
            );
        }
        prop_assert_eq!(
            verify_tombstone(&vault, id(item), rev + 1, &tomb.tomb),
            Err(Error::TombstoneInvalid)
        );
        prop_assert_eq!(
            verify_tombstone(&unlocked(0x5b), id(item), rev, &tomb.tomb),
            Err(Error::TombstoneInvalid)
        );
        let mut changed = tomb.tomb.clone();
        changed[flip] ^= 1 << bit;
        prop_assert_eq!(
            verify_tombstone(&vault, id(item), rev, &changed),
            Err(Error::TombstoneInvalid)
        );
    }

    #[test]
    fn item_tag_binds_blob(
        item in any::<[u8; 16]>(),
        rev in 0u64..u64::MAX,
        blob in prop::collection::vec(any::<u8>(), 1..200),
        at in any::<prop::sample::Index>(),
        bit in 0u8..8,
    ) {
        let vault = unlocked(0x5a);
        let tag = item_tag(&vault, id(item), rev, &blob).unwrap();
        prop_assert!(verify_item_tag(&vault, id(item), rev, &blob, &tag).is_ok());
        let mut changed = blob.clone();
        let i = at.index(changed.len());
        changed[i] ^= 1 << bit;
        prop_assert_eq!(
            verify_item_tag(&vault, id(item), rev, &changed, &tag),
            Err(Error::Decrypt)
        );
        let mut longer = blob.clone();
        longer.push(0);
        prop_assert_eq!(
            verify_item_tag(&vault, id(item), rev, &longer, &tag),
            Err(Error::Decrypt)
        );
        prop_assert_eq!(
            verify_item_tag(&vault, id(item), rev + 1, &blob, &tag),
            Err(Error::Decrypt)
        );
        let mut other = item;
        other[0] ^= 1;
        prop_assert_eq!(
            verify_item_tag(&vault, id(other), rev, &blob, &tag),
            Err(Error::Decrypt)
        );
        prop_assert_eq!(
            verify_item_tag(&unlocked(0x5b), id(item), rev, &blob, &tag),
            Err(Error::Decrypt)
        );
    }

    #[test]
    fn checkpoint_digest_order_independent(
        entries in state(),
        seed in any::<u64>(),
        seq in any::<u64>(),
    ) {
        let vault = unlocked(0x5a);
        let a = make_checkpoint(&vault, seq, entries.clone()).unwrap();
        let mut shuffled = entries.clone();
        // A deterministic shuffle from the seed.
        let n = shuffled.len();
        let mut s = seed;
        for i in (1..n).rev() {
            s = s.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
            shuffled.swap(i, (s >> 33) as usize % (i + 1));
        }
        let b = make_checkpoint(&vault, seq, shuffled).unwrap();
        prop_assert_eq!(&a, &b);
        prop_assert_eq!(a.entries.len(), 56 * entries.len());
        // The entries are ascending by the raw bytes of item_id.
        let ids: Vec<&[u8]> = a.entries.chunks(56).map(|c| &c[..16]).collect();
        prop_assert!(ids.windows(2).all(|w| w[0] < w[1]));
    }

    #[test]
    fn checkpoint_detects_hidden_or_rolled_back(
        entries in state(),
        pick in any::<prop::sample::Index>(),
        other_hash in hash(),
    ) {
        let vault = unlocked(0x5a);
        let seq = 1_000;
        let cp = make_checkpoint(&vault, seq, entries.clone()).unwrap();
        let good = rows(&entries);
        // The state itself passes, at the top and above it.
        prop_assert!(verify_checkpoint(&vault, &cp, &good, seq, ferret_core::RollbackMemory::NoMemory).is_ok());
        prop_assert!(verify_checkpoint(&vault, &cp, &good, seq + 1, ferret_core::RollbackMemory::NoMemory).is_ok());
        prop_assert_eq!(
            verify_checkpoint(&vault, &cp, &good, seq - 1, ferret_core::RollbackMemory::NoMemory),
            Err(Error::Checkpoint(CheckpointFailure::SeqAboveTop))
        );
        let live: Vec<usize> = entries
            .iter()
            .enumerate()
            .filter(|(_, e)| e.live_hash.is_some())
            .map(|(i, _)| i)
            .collect();
        if live.is_empty() {
            return Ok(());
        }
        let i = live[pick.index(live.len())];
        // Hiding a live item.
        let mut hidden = good.clone();
        hidden.remove(i);
        prop_assert_eq!(
            verify_checkpoint(&vault, &cp, &hidden, seq + 1, ferret_core::RollbackMemory::NoMemory),
            Err(Error::Checkpoint(CheckpointFailure::HiddenOrRolledBack))
        );
        // A lower revision.
        if entries[i].rev > 0 {
            let mut older = good.clone();
            older[i].rev -= 1;
            prop_assert_eq!(
                verify_checkpoint(&vault, &cp, &older, seq + 1, ferret_core::RollbackMemory::NoMemory),
                Err(Error::Checkpoint(CheckpointFailure::LowerRev))
            );
        }
        // The same revision with another blob.
        if entries[i].live_hash != Some(other_hash) {
            let mut swapped = good.clone();
            swapped[i].state = RowState::Live { blob_sha256: other_hash };
            prop_assert_eq!(
                verify_checkpoint(&vault, &cp, &swapped, seq + 1, ferret_core::RollbackMemory::NoMemory),
                Err(Error::Checkpoint(CheckpointFailure::SameRevDifferentHash))
            );
        }
        // A higher revision is fine below the top, and a different state at
        // the top is not.
        let mut newer = good.clone();
        newer[i].rev += 1;
        prop_assert!(verify_checkpoint(&vault, &cp, &newer, seq + 1, ferret_core::RollbackMemory::NoMemory).is_ok());
        prop_assert_eq!(
            verify_checkpoint(&vault, &cp, &newer, seq, ferret_core::RollbackMemory::NoMemory),
            Err(Error::Checkpoint(CheckpointFailure::TopDigestMismatch))
        );
    }

    #[test]
    fn mutation_proof_binds_body(
        body in prop::collection::vec(any::<u8>(), 0..200),
        nonce in any::<[u8; 32]>(),
        at in any::<prop::sample::Index>(),
        bit in 0u8..8,
        op_index in 0usize..5,
    ) {
        let vault = unlocked(0x5a);
        let c = ctx();
        let ops = [
            AuthOp::UnlockMethodAdd,
            AuthOp::UnlockMethodRemove,
            AuthOp::UnlockMethodPasswordPut,
            AuthOp::UnlockMethodRecoveryPut,
            AuthOp::Rekey,
        ];
        let op = ops[op_index];
        let pk = AuthPublicKey::new(vault.auth_public_key());
        let sig = auth_sign(&vault, op, &nonce, &body).unwrap();
        prop_assert!(verify_auth_proof(&pk, op, &c.account_id, &nonce, 1, &body, &sig).is_ok());
        if !body.is_empty() {
            let mut changed = body.clone();
            let i = at.index(changed.len());
            changed[i] ^= 1 << bit;
            prop_assert_eq!(
                verify_auth_proof(&pk, op, &c.account_id, &nonce, 1, &changed, &sig),
                Err(Error::Decrypt)
            );
        }
        let mut longer = body.clone();
        longer.push(0);
        prop_assert_eq!(
            verify_auth_proof(&pk, op, &c.account_id, &nonce, 1, &longer, &sig),
            Err(Error::Decrypt)
        );
        let mut n2 = nonce;
        n2[0] ^= 1;
        prop_assert_eq!(
            verify_auth_proof(&pk, op, &c.account_id, &n2, 1, &body, &sig),
            Err(Error::Decrypt)
        );
        prop_assert_eq!(
            verify_auth_proof(&pk, op, &c.account_id, &nonce, 2, &body, &sig),
            Err(Error::Decrypt)
        );
    }
}
