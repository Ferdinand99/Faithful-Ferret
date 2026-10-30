//! The body of a record replacement (a password change, an upgrade or a
//! recovery), as the endpoint reads it: JSON with the new record as hex, the
//! profile and, for a recovery, the new recovery key.
//!
//! The library reads the body only after the proof has verified, and a random
//! body never carries a valid proof. So this target signs whatever the fuzzer
//! makes with the keys of a fixed account, as the client would, and runs
//! `authorize_replacement` with the reference JSON parser of `test-support`.
//! The first byte picks the kind (password change or recovery); the rest is
//! the body.
//!
//! * No body panics.
//! * The parser gets exactly the signed bytes, and always (the proof is valid).
//! * The answer is the one that the fields of the body decide, worked out here
//!   again from the parser's own output: a body that does not parse, a record
//!   that is not a valid 192 byte record, a missing, unwanted or unchanged
//!   recovery key, and an unknown or lowered profile are the refusals; nothing
//!   else is. A permit carries the record, the profile and the key of the
//!   body, and no other.
//! * One flipped bit of the body, or a proof made for the other request, is
//!   `ProofInvalid` and the parser is not called; a nonce is used once.
#![no_main]

#[path = "../common/server.rs"]
mod server;

use std::cell::Cell;

use ferret_core::MutationOp;
use ferret_server_auth::testing::vectors::parse_body;
use ferret_server_auth::testing::{LoginFixture, put_nonce};
use ferret_server_auth::{
    AccountAuthState, AuthError, DenyReason, InMemoryChallengeStore, Malformed, ReplaceFields,
    ReplaceKind, ReplacePermit, ReplaceRequest, SessionBinding, SessionScope, ValidatedRecord,
    authorize_replacement,
};
use libfuzzer_sys::fuzz_target;
use server::{Signer, World};

struct Fixed {
    world: World,
    signer: Signer,
}

thread_local! {
    static FIXED: Fixed = Fixed { world: World::new(), signer: Signer::new() };
}

const SESSION: SessionBinding = SessionBinding([0xA1; 32]);
const NONCE: [u8; 32] = [0x5A; 32];

fn call(
    fixed: &Fixed,
    kind: ReplaceKind,
    proof: &[u8; 64],
    body: &[u8],
    called: &Cell<bool>,
) -> (InMemoryChallengeStore, Result<ReplacePermit, AuthError>) {
    let store = InMemoryChallengeStore::new();
    put_nonce(&store, &SESSION, &NONCE, LoginFixture::START);
    let result = again(fixed, &store, kind, proof, body, called);
    (store, result)
}

fn again(
    fixed: &Fixed,
    store: &InMemoryChallengeStore,
    kind: ReplaceKind,
    proof: &[u8; 64],
    body: &[u8],
    called: &Cell<bool>,
) -> Result<ReplacePermit, AuthError> {
    authorize_replacement(
        &fixed.world.cx(),
        store,
        &AccountAuthState {
            account: fixed.signer.account,
            current: &fixed.world.f.record,
        },
        &ReplaceRequest {
            caller: World::caller(),
            kind,
            scope: SessionScope::Full,
            session: SESSION,
            nonce: &NONCE,
            proof,
            body,
        },
        |proven| {
            assert_eq!(proven, body, "the parser got other bytes than were signed");
            called.set(true);
            parse_body(proven)
        },
    )
}

/// The answer that the fields of a body decide, worked out again from what
/// the parser returns.
fn expected(
    fixed: &Fixed,
    kind: ReplaceKind,
    fields: Result<ReplaceFields, AuthError>,
) -> Result<(Vec<u8>, u8, Option<[u8; 32]>), AuthError> {
    let fields = fields?;
    ValidatedRecord::parse(&fields.record)?;
    let stored = fixed.world.f.record.ksf_profile;
    let new_key = match (kind, fields.pk_r_new) {
        (ReplaceKind::Recover, Some(key)) if key == fixed.signer.account.pk_r => {
            return Err(AuthError::Malformed(Malformed::RecoveryKey));
        }
        (ReplaceKind::Recover, Some(key)) => Some(*key.as_bytes()),
        (ReplaceKind::PasswordPut, None) => None,
        _ => return Err(AuthError::Malformed(Malformed::RecoveryKey)),
    };
    // Profile 1 is the lowest; ferret_v1 knows the numbers of the client's
    // table. A password change may not go below the stored profile.
    let rules = &fixed.world.f.profiles;
    let profile = match kind {
        ReplaceKind::Recover => rules.accept_recovery(fields.ksf_profile)?,
        ReplaceKind::PasswordPut => rules.accept(
            fields.ksf_profile,
            ferret_server_auth::RegistrationKind::Existing(stored),
        )?,
    };
    Ok((fields.record, profile, new_key))
}

fuzz_target!(|data: &[u8]| {
    let Some((&select, body)) = data.split_first() else {
        return;
    };
    FIXED.with(|fixed| {
        let (kind, op, other_op) = if select & 1 == 0 {
            (
                ReplaceKind::PasswordPut,
                MutationOp::UnlockMethodPasswordPut,
                MutationOp::Recover,
            )
        } else {
            (
                ReplaceKind::Recover,
                MutationOp::Recover,
                MutationOp::UnlockMethodPasswordPut,
            )
        };
        let called = Cell::new(false);
        let proof = fixed.signer.sign(op, &NONCE, body);

        // 1. A signed body: the parser sees it, and the answer is the one its
        // fields decide.
        let (store, result) = call(fixed, kind, &proof, body, &called);
        assert!(called.get(), "a valid proof did not reach the parser");
        match (result, expected(fixed, kind, parse_body(body))) {
            (Ok(permit), Ok((record, profile, new_key))) => {
                assert!(permit.account_id == fixed.signer.account.account_id);
                assert_eq!(permit.kind, kind);
                assert_eq!(permit.new.record.as_bytes(), record.as_slice());
                assert_eq!(permit.new.record.as_bytes().len(), 192);
                assert_eq!(permit.new.ksf_profile, profile);
                assert_eq!(permit.new_pk_r.map(|key| *key.as_bytes()), new_key);
                assert_eq!(permit.stored_ksf_profile, fixed.world.f.record.ksf_profile);
                assert!(permit.basis.pk_a == fixed.signer.account.pk_a);
            }
            (Err(got), Err(want)) => assert_eq!(got, want),
            (got, want) => panic!(
                "the library says {:?}, the fields say {:?}",
                got.map(|_| "a permit"),
                want.map(|_| "a permit")
            ),
        }

        // 2. The nonce is used up, accepted or not.
        let replay = again(fixed, &store, kind, &proof, body, &called);
        assert_eq!(
            replay.err(),
            Some(AuthError::Denied(DenyReason::NonceUnknown)),
            "a nonce was used twice"
        );

        // 3. One flipped bit of the body, and a proof for another request, are
        // not the signed request: the body is not read.
        let bit = data
            .last_chunk::<2>()
            .map_or(0, |b| usize::from(u16::from_be_bytes(*b)));
        let mut damaged = body.to_vec();
        if damaged.is_empty() {
            damaged.push(0);
        } else {
            let at = (bit / 8) % damaged.len();
            damaged[at] ^= 1 << (bit % 8);
        }
        let other_proof = fixed.signer.sign(other_op, &NONCE, body);
        for (proof, presented) in [(&proof, damaged.as_slice()), (&other_proof, body)] {
            let called = Cell::new(false);
            let (_, refused) = call(fixed, kind, proof, presented, &called);
            assert_eq!(
                refused.err(),
                Some(AuthError::Denied(DenyReason::ProofInvalid)),
                "a request that was not signed was accepted"
            );
            assert!(!called.get(), "the body was read without a valid proof");
        }
    });
});
