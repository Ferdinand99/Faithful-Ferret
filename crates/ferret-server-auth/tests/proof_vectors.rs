//! The fixed proofs of `vectors/internal/proofs.json` through the server's
//! entry points. The other tests sign with the functions of `ferret-core`
//! that the server verifies with; these cases pin the server to the bytes
//! of the specification on their own.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]

use std::sync::OnceLock;

use ferret_core::testing::hex_decode;
use ferret_core::{AccountId, AuthPublicKey, MutationOp, RecoveryPublicKey};
use ferret_server_auth::testing::{LoginFixture, put_nonce};
use ferret_server_auth::{
    AccountAuthState, AuthError, DenyReason, InMemoryChallengeStore, ReplaceFields, ReplaceKind,
    ReplaceRequest, SessionBinding, SessionScope, SignedAccount, SignedRequest,
    authorize_replacement, authorize_signed,
};

const SESSION: SessionBinding = SessionBinding([0x33; 32]);

/// A well formed record that every case's parser hands out: the vectors fix
/// the proof and the body, and the body of the vectors is not a request body.
fn record() -> &'static [u8] {
    static RECORD: OnceLock<Vec<u8>> = OnceLock::new();
    RECORD.get_or_init(|| LoginFixture::new().record.record.as_bytes().to_vec())
}

fn parse_put(_: &[u8]) -> Result<ReplaceFields, AuthError> {
    Ok(ReplaceFields {
        record: record().to_vec(),
        ksf_profile: 1,
        pk_r_new: None,
    })
}

fn parse_recover(_: &[u8]) -> Result<ReplaceFields, AuthError> {
    Ok(ReplaceFields {
        record: record().to_vec(),
        ksf_profile: 1,
        pk_r_new: Some(RecoveryPublicKey::new([0x44; 32])),
    })
}

fn bytes<const N: usize>(case: &serde_json::Value, key: &str) -> [u8; N] {
    hex_decode(case["input"][key].as_str().unwrap())
        .unwrap()
        .try_into()
        .unwrap()
}

#[test]
fn the_fixed_proofs_decide_the_same_way_through_the_server() {
    let text = std::fs::read_to_string(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../vectors/internal/proofs.json"),
    )
    .unwrap();
    let file: serde_json::Value = serde_json::from_str(&text).unwrap();
    let mut checked = 0;
    for case in file["cases"].as_array().unwrap() {
        if case["op"] != "proof.verify" {
            continue;
        }
        let id = case["id"].as_str().unwrap();
        let name = case["input"]["op"].as_str().unwrap();
        let valid = case["status"] == "valid";
        let Some(op) = MutationOp::from_name(name) else {
            // An operation that is not on the list: nothing can be asked.
            assert!(!valid, "{id}");
            continue;
        };

        let f = LoginFixture::new();
        let store = InMemoryChallengeStore::new();
        let nonce: [u8; 32] = bytes(case, "nonce");
        put_nonce(&store, &SESSION, &nonce, LoginFixture::START);
        let key: [u8; 32] = bytes(case, "pk");
        let account = SignedAccount {
            account_id: AccountId::from_bytes(bytes(case, "account_id")),
            pk_a: AuthPublicKey::new(key),
            pk_r: RecoveryPublicKey::new(key),
            vk_epoch: case["input"]["vk_epoch"].as_str().unwrap().parse().unwrap(),
            row_version: 0,
        };
        let proof: [u8; 64] = bytes(case, "proof");
        let body = hex_decode(case["input"]["body"].as_str().unwrap()).unwrap();
        let cx = f.cx();

        let result = match op {
            MutationOp::UnlockMethodPasswordPut | MutationOp::Recover => {
                let kind = if op == MutationOp::Recover {
                    ReplaceKind::Recover
                } else {
                    ReplaceKind::PasswordPut
                };
                let state = AccountAuthState {
                    account,
                    current: &f.record,
                };
                let request = ReplaceRequest {
                    caller: LoginFixture::caller(),
                    kind,
                    scope: SessionScope::Full,
                    session: SESSION,
                    nonce: &nonce,
                    proof: &proof,
                    body: &body,
                };
                let parser = if kind == ReplaceKind::Recover {
                    parse_recover
                } else {
                    parse_put
                };
                authorize_replacement(&cx, &store, &state, &request, parser).map(|_| ())
            }
            _ => authorize_signed(
                &cx,
                &store,
                &account,
                &SignedRequest {
                    caller: LoginFixture::caller(),
                    op,
                    scope: SessionScope::Full,
                    session: SESSION,
                    nonce: &nonce,
                    proof: &proof,
                    body: &body,
                },
            )
            .map(|_| ()),
        };
        if valid {
            assert_eq!(result, Ok(()), "{id}");
        } else {
            assert_eq!(
                result,
                Err(AuthError::Denied(DenyReason::ProofInvalid)),
                "{id}"
            );
        }
        checked += 1;
    }
    // Every verify case of the file that names a known operation.
    assert!(checked >= 20, "only {checked} cases were checked");
}
