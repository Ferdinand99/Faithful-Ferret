//! Mutation and recovery proofs (Fase 1 § 4.5 and § 4.6, plan U8) and
//! `vectors/internal/proofs.json`.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]

mod common;

use common::*;
use ferret_core::recovery_public_key;
use ferret_core::testing::integrity::mutation_proof_message;
use ferret_core::testing::keys::recovery_seed;
use ferret_core::testing::prim::{ed25519_public_key, ed25519_verify};
use ferret_core::testing::vector::Outcome;
use ferret_core::{
    AccountId, Error, MutationOp, RecoveryKey, auth_sign, recovery_sign, verify_mutation_proof,
};
use serde_json::json;
use sha2::{Digest, Sha256};

const NONCE: [u8; 32] = [0xa0; 32];
const BODY: &[u8] = br#"{"method_type":3}"#;

fn rk() -> RecoveryKey {
    RecoveryKey::from_test_bytes([0xc0; 32])
}

fn name_to_op(name: &str) -> Option<MutationOp> {
    MutationOp::from_name(name)
}

/// The proof message of Fase 1 § 4.6, written out field by field.
fn hand_message(
    label_s: &str,
    op: &str,
    account: &AccountId,
    nonce: &[u8; 32],
    epoch: u64,
    body: &[u8],
) -> Vec<u8> {
    [
        label(label_s),
        t(0x36, op.as_bytes()),
        t(0x10, account.as_bytes()),
        t(0x33, nonce),
        t(0x20, &epoch.to_be_bytes()),
        t(0x35, &Sha256::digest(body)),
    ]
    .concat()
}

#[test]
fn mutation_proof_message_is_exact_tlv() {
    let vault = unlocked(0x5a);
    let c = ctx();
    let pk = vault.auth_public_key();
    for op in MutationOp::ALL {
        if op == MutationOp::Recover {
            continue;
        }
        let sig = auth_sign(&vault, op, &NONCE, BODY).unwrap();
        let message = hand_message(
            "ferret/v1/mutation",
            op.name(),
            &c.account_id,
            &NONCE,
            1,
            BODY,
        );
        // The signature verifies over the hand-made bytes, with an Ed25519
        // verifier that is not the proof code.
        ed25519_verify(&pk, &message, &sig).unwrap();
        assert_eq!(
            mutation_proof_message(op, &c.account_id, &NONCE, 1, BODY).unwrap(),
            message
        );
    }
}

#[test]
fn mutation_proof_verifies_for_each_op() {
    assert_eq!(MutationOp::ALL.len(), 6);
    let vault = unlocked(0x5a);
    let c = ctx();
    let pk = vault.auth_public_key();
    let names: Vec<&str> = MutationOp::ALL.iter().map(|op| op.name()).collect();
    assert_eq!(
        names,
        vec![
            "unlock-method.add",
            "unlock-method.remove",
            "unlock-method.password.put",
            "unlock-method.recovery.put",
            "recover",
            "rekey"
        ]
    );
    for op in MutationOp::ALL {
        assert_eq!(name_to_op(op.name()), Some(op));
        if op == MutationOp::Recover {
            // sk_a does not sign a recovery request.
            assert_eq!(auth_sign(&vault, op, &NONCE, BODY), Err(Error::Unsupported));
            continue;
        }
        let sig = auth_sign(&vault, op, &NONCE, BODY).unwrap();
        verify_mutation_proof(&pk, op, &c.account_id, &NONCE, 1, BODY, &sig).unwrap();
        // It is for this op only.
        for other in MutationOp::ALL {
            if other != op {
                assert_eq!(
                    verify_mutation_proof(&pk, other, &c.account_id, &NONCE, 1, BODY, &sig),
                    Err(Error::Decrypt),
                    "{} as {}",
                    op.name(),
                    other.name()
                );
            }
        }
    }
    assert_eq!(name_to_op("unlock-method.frobnicate"), None);
    assert_eq!(name_to_op(""), None);
    assert_eq!(name_to_op("Rekey"), None);
}

#[test]
fn mutation_proof_fails_if_body_nonce_op_or_epoch_changed() {
    let vault = unlocked(0x5a);
    let c = ctx();
    let pk = vault.auth_public_key();
    let op = MutationOp::UnlockMethodAdd;
    let sig = auth_sign(&vault, op, &NONCE, BODY).unwrap();
    verify_mutation_proof(&pk, op, &c.account_id, &NONCE, 1, BODY, &sig).unwrap();
    let bad = Err(Error::Decrypt);
    assert_eq!(
        verify_mutation_proof(&pk, op, &c.account_id, &NONCE, 1, b"{}", &sig),
        bad
    );
    let mut body2 = BODY.to_vec();
    body2[3] ^= 1;
    assert_eq!(
        verify_mutation_proof(&pk, op, &c.account_id, &NONCE, 1, &body2, &sig),
        bad
    );
    assert_eq!(
        verify_mutation_proof(&pk, op, &c.account_id, &[0xa1; 32], 1, BODY, &sig),
        bad
    );
    assert_eq!(
        verify_mutation_proof(
            &pk,
            MutationOp::UnlockMethodRemove,
            &c.account_id,
            &NONCE,
            1,
            BODY,
            &sig
        ),
        bad
    );
    assert_eq!(
        verify_mutation_proof(&pk, op, &c.account_id, &NONCE, 2, BODY, &sig),
        bad
    );
    assert_eq!(
        verify_mutation_proof(
            &pk,
            op,
            &AccountId::from_bytes([0x12; 16]),
            &NONCE,
            1,
            BODY,
            &sig
        ),
        bad
    );
    // Another public key, a flipped bit, a malformed key.
    assert_eq!(
        verify_mutation_proof(
            &unlocked(0x5b).auth_public_key(),
            op,
            &c.account_id,
            &NONCE,
            1,
            BODY,
            &sig
        ),
        bad
    );
    for i in [0usize, 31, 32, 63] {
        let mut flipped = sig;
        flipped[i] ^= 1;
        assert_eq!(
            verify_mutation_proof(&pk, op, &c.account_id, &NONCE, 1, BODY, &flipped),
            bad,
            "byte {i}"
        );
    }
    let mut identity = [0u8; 32];
    identity[0] = 1;
    assert_eq!(
        verify_mutation_proof(&identity, op, &c.account_id, &NONCE, 1, BODY, &sig),
        bad
    );
}

#[test]
fn the_epoch_in_the_proof_is_the_signing_vaults() {
    // At a rekey the old vault signs, so the proof carries the old epoch.
    let old = unlocked(0x5a);
    let sig = auth_sign(&old, MutationOp::Rekey, &NONCE, BODY).unwrap();
    let c = ctx();
    verify_mutation_proof(
        &old.auth_public_key(),
        MutationOp::Rekey,
        &c.account_id,
        &NONCE,
        1,
        BODY,
        &sig,
    )
    .unwrap();
}

#[test]
fn proofs_are_deterministic() {
    let vault = unlocked(0x5a);
    let a = auth_sign(&vault, MutationOp::Rekey, &NONCE, BODY).unwrap();
    let b = auth_sign(&vault, MutationOp::Rekey, &NONCE, BODY).unwrap();
    assert_eq!(a, b);
}

#[test]
fn recovery_proof_uses_sk_r_and_recovery_label() {
    let c = ctx();
    let vault = unlocked(0x5a);
    let pk_a = vault.auth_public_key();
    let pk_r = recovery_public_key(&rk(), &c.account_id).unwrap();
    assert_ne!(pk_a, pk_r);
    let sig = recovery_sign(&rk(), &c.account_id, 1, &NONCE, BODY).unwrap();

    // The message, written out, with the recovery label; verified with a
    // separate Ed25519 verifier against pk_r.
    let message = hand_message(
        "ferret/v1/recovery-req",
        "recover",
        &c.account_id,
        &NONCE,
        1,
        BODY,
    );
    ed25519_verify(&pk_r, &message, &sig).unwrap();
    assert_eq!(
        mutation_proof_message(MutationOp::Recover, &c.account_id, &NONCE, 1, BODY).unwrap(),
        message
    );
    verify_mutation_proof(
        &pk_r,
        MutationOp::Recover,
        &c.account_id,
        &NONCE,
        1,
        BODY,
        &sig,
    )
    .unwrap();

    // Not against pk_a, and not with the mutation label or another op.
    assert_eq!(
        verify_mutation_proof(
            &pk_a,
            MutationOp::Recover,
            &c.account_id,
            &NONCE,
            1,
            BODY,
            &sig
        ),
        Err(Error::Decrypt)
    );
    assert_eq!(
        verify_mutation_proof(
            &pk_r,
            MutationOp::Rekey,
            &c.account_id,
            &NONCE,
            1,
            BODY,
            &sig
        ),
        Err(Error::Decrypt)
    );
    assert!(
        ed25519_verify(
            &pk_r,
            &hand_message(
                "ferret/v1/mutation",
                "recover",
                &c.account_id,
                &NONCE,
                1,
                BODY
            ),
            &sig
        )
        .is_err()
    );
    // And a proof by sk_a with the recover op fields is not a recovery proof.
    let forged = ferret_core::testing::prim::ed25519_sign(
        &ferret_core::testing::keys::derived_keys(&ctx(), &vk(0x5a))
            .unwrap()
            .seed_a,
        &hand_message(
            "ferret/v1/mutation",
            "recover",
            &c.account_id,
            &NONCE,
            1,
            BODY,
        ),
    )
    .unwrap();
    assert_eq!(
        verify_mutation_proof(
            &pk_a,
            MutationOp::Recover,
            &c.account_id,
            &NONCE,
            1,
            BODY,
            &forged
        ),
        Err(Error::Decrypt)
    );
}

#[test]
fn recovery_public_key_is_deterministic() {
    let c = ctx();
    let a = recovery_public_key(&rk(), &c.account_id).unwrap();
    let b = recovery_public_key(&rk(), &c.account_id).unwrap();
    assert_eq!(a, b);
    // It is the public key of seed_r (Fase 1 § 4.5).
    let seed = recovery_seed(&rk(), &c.account_id).unwrap();
    assert_eq!(a, ed25519_public_key(&seed));
    // Another account or another recovery key gives another key.
    assert_ne!(
        a,
        recovery_public_key(&rk(), &AccountId::from_bytes([0x12; 16])).unwrap()
    );
    assert_ne!(
        a,
        recovery_public_key(&RecoveryKey::from_test_bytes([0xc1; 32]), &c.account_id).unwrap()
    );
}

fn run() -> ferret_core::testing::vector::RunReport {
    let file = load_ops("proofs.json", |_| true);
    ferret_core::testing::vector::run_all(&file, |case, _rng| {
        let input = &case.input;
        match case.op.as_str() {
            "proof.sign" => {
                let vault = vault_of(input);
                let op = name_to_op(input["op"].as_str().unwrap()).unwrap();
                let nonce: [u8; 32] = hexn(&input["nonce"]);
                let body = hex(&input["body"]);
                let sig = auth_sign(&vault, op, &nonce, &body)?;
                let ctx = vault.context();
                Ok(Outcome {
                    output: json!({ "proof": he(&sig), "pk_a": he(&vault.auth_public_key()) }),
                    intermediate: Some(json!({
                        "message": he(&mutation_proof_message(op, &ctx.account_id, &nonce, ctx.vk_epoch, &body)?),
                    })),
                })
            }
            "proof.recovery_sign" => {
                let account = AccountId::from_bytes(id16(&input["account_id"]));
                let rk = RecoveryKey::from_test_bytes(hexn(&input["rk"]));
                let epoch = u64s(&input["vk_epoch"]);
                let nonce: [u8; 32] = hexn(&input["nonce"]);
                let body = hex(&input["body"]);
                let sig = recovery_sign(&rk, &account, epoch, &nonce, &body)?;
                Ok(Outcome {
                    output: json!({
                        "proof": he(&sig),
                        "pk_r": he(&recovery_public_key(&rk, &account)?),
                    }),
                    intermediate: Some(json!({
                        "message": he(&mutation_proof_message(MutationOp::Recover, &account, &nonce, epoch, &body)?),
                    })),
                })
            }
            "proof.verify" => {
                // A name that is not on the list is refused like any other
                // bad proof.
                let op = name_to_op(input["op"].as_str().unwrap()).ok_or(Error::Decrypt)?;
                verify_mutation_proof(
                    &hexn(&input["pk"]),
                    op,
                    &AccountId::from_bytes(id16(&input["account_id"])),
                    &hexn(&input["nonce"]),
                    u64s(&input["vk_epoch"]),
                    &hex(&input["body"]),
                    &hexn(&input["proof"]),
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
fn proof_vectors_from_file() {
    assert_all_passed(&run(), 25);
}
