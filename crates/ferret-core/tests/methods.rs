//! Adding and removing an unlock method, the comparison of the server's
//! list with the manifest, the PRF salt, and `vectors/internal/methods.json`.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]

mod common;

use common::*;
use ferret_core::testing::vector::Outcome;
use ferret_core::testing::{ReplayRng, TestRng};
use ferret_core::{
    AuthOp, CurrentManifest, Error, InputError, MalformedKind, Manifest, ManifestEntry,
    MethodChange, MethodId, MethodListFailure as L, SealedItem, ServerMethod, UnlockedVault,
    WrapRecord, auth_sign, check_server_methods, decrypt_manifest, encrypt_manifest,
    manifest_add_method, manifest_remove_method, prf_salt_new, verify_auth_proof,
};
use ferret_core::{AuthPublicKey, Method};
use serde_json::{Value, json};

fn mid(b: u8) -> MethodId {
    method_id(b)
}

fn manifest(list: Vec<ManifestEntry>) -> Manifest {
    Manifest::new(1, list)
}

fn password() -> ManifestEntry {
    ManifestEntry::new(1, mid(0x70), 3)
}

fn recovery() -> ManifestEntry {
    ManifestEntry::new(2, mid(0x71), 1)
}

fn passkey(b: u8, credential: u8) -> ManifestEntry {
    ManifestEntry::passkey(mid(b), 1, vec![credential; 20])
}

fn prf_wrap(b: u8, credential: u8) -> WrapRecord {
    WrapRecord {
        method_id: mid(b),
        kek_generation: 2,
        method: Method::Prf {
            credential_id: vec![credential; 20],
            prf_salt: [0x33; 32],
        },
        wrap: vec![0x5a; 72],
    }
}

fn sealed(vault: &UnlockedVault, rev: u64, m: &Manifest) -> SealedItem {
    let mut rng = TestRng::new(b"methods tests");
    encrypt_manifest(&mut rng, vault, rev, m).unwrap()
}

fn row(s: &SealedItem) -> CurrentManifest<'_> {
    CurrentManifest {
        rev: s.rev,
        envelope: &s.envelope,
        tag: &s.tag,
    }
}

// ------------------------------------------------------------- the lists

#[test]
fn with_method_adds_one_passkey_and_keeps_the_rest() {
    let mut m = manifest(vec![password(), recovery()]);
    m.extra
        .push(("future".into(), ferret_core::cbor::Value::uint(1)));
    let next = m.with_method(&prf_wrap(0x72, 1)).unwrap();
    assert_eq!(next.methods.len(), 3);
    assert_eq!(&next.methods[..2], &m.methods[..]);
    assert_eq!(next.extra, m.extra);
    let added = &next.methods[2];
    assert_eq!(
        (added.method_type, added.method_id, added.kek_generation),
        (3, mid(0x72), 2)
    );
    assert_eq!(added.credential_id.as_deref(), Some(&[1u8; 20][..]));
}

#[test]
fn with_method_refuses_what_the_design_does_not_allow() {
    let m = manifest(vec![password(), recovery(), passkey(0x72, 1)]);
    let malformed = Err(Error::Malformed(MalformedKind::Entries));
    // An id or a credential the manifest lists already.
    assert_eq!(m.with_method(&prf_wrap(0x72, 9)).map(|_| ()), malformed);
    assert_eq!(m.with_method(&prf_wrap(0x73, 1)).map(|_| ()), malformed);
    assert_eq!(m.with_method(&prf_wrap(0x70, 9)).map(|_| ()), malformed);
    // Another kind of wrap.
    let mut recovery_wrap = prf_wrap(0x74, 2);
    recovery_wrap.method = Method::Recovery;
    assert_eq!(
        m.with_method(&recovery_wrap).map(|_| ()),
        Err(Error::Unsupported)
    );
    // Length, credential and salt.
    let mut long = prf_wrap(0x74, 2);
    long.wrap = vec![0; 104];
    assert_eq!(
        m.with_method(&long).map(|_| ()),
        Err(Error::Malformed(MalformedKind::Envelope))
    );
    let mut empty = prf_wrap(0x74, 2);
    empty.method = Method::Prf {
        credential_id: vec![],
        prf_salt: [1; 32],
    };
    assert_eq!(
        m.with_method(&empty).map(|_| ()),
        Err(Error::InvalidInput(InputError::TooShort))
    );
    let mut zero = prf_wrap(0x74, 2);
    zero.method = Method::Prf {
        credential_id: vec![2; 20],
        prf_salt: [0; 32],
    };
    assert_eq!(
        m.with_method(&zero).map(|_| ()),
        Err(Error::InvalidInput(InputError::AllZero))
    );
    // A generation past 2^32 - 1.
    let mut high = prf_wrap(0x74, 2);
    high.kek_generation = 1 << 32;
    assert_eq!(m.with_method(&high).map(|_| ()), malformed);
    // The most methods a manifest lists.
    let full = manifest(
        (0..64u8)
            .map(|n| ManifestEntry::new(9, mid(n.saturating_add(1)), 1))
            .collect(),
    );
    assert_eq!(full.with_method(&prf_wrap(0xee, 2)).map(|_| ()), malformed);
}

#[test]
fn without_method_keeps_the_last_password_and_the_last_recovery() {
    let m = manifest(vec![password(), recovery(), passkey(0x72, 1)]);
    let last = Err(Error::InvalidInput(InputError::LastMethod));
    assert_eq!(m.without_method(&mid(0x70)).map(|_| ()), last);
    assert_eq!(m.without_method(&mid(0x71)).map(|_| ()), last);
    assert_eq!(
        m.without_method(&mid(0x7f)).map(|_| ()),
        Err(Error::Malformed(MalformedKind::Entries))
    );
    let next = m.without_method(&mid(0x72)).unwrap();
    assert_eq!(next.methods, vec![password(), recovery()]);
    // A manifest with two recovery methods (as a hand-made one may) lets
    // one of them go.
    let two = manifest(vec![
        password(),
        recovery(),
        ManifestEntry::new(2, mid(0x76), 1),
    ]);
    assert_eq!(two.without_method(&mid(0x71)).unwrap().methods.len(), 2);
}

#[test]
fn the_server_list_must_match_the_manifest() {
    let m = manifest(vec![password(), recovery(), passkey(0x72, 1)]);
    let s = |ty: u8, b: u8, g: u64| ServerMethod {
        method_type: ty,
        method_id: mid(b),
        kek_generation: g,
    };
    let same = [s(3, 0x72, 1), s(1, 0x70, 3), s(2, 0x71, 1)];
    check_server_methods(&m, &same).unwrap();
    let fail = |kind: L| Err(Error::MethodList(kind));
    assert_eq!(
        check_server_methods(&m, &[same[0], same[1], same[2], s(3, 0x7e, 1)]),
        fail(L::Unknown)
    );
    assert_eq!(
        check_server_methods(&m, &[same[0], same[1], same[2], same[0]]),
        fail(L::Unknown)
    );
    assert_eq!(
        check_server_methods(&m, &[s(3, 0x72, 2), same[1], same[2]]),
        fail(L::Changed)
    );
    assert_eq!(
        check_server_methods(&m, &[s(4, 0x72, 1), same[1], same[2]]),
        fail(L::Changed)
    );
    assert_eq!(
        check_server_methods(&m, &[same[1], same[2]]),
        fail(L::Missing)
    );
    // Unknown before changed before missing.
    assert_eq!(
        check_server_methods(&m, &[s(1, 0x70, 9), s(3, 0x7e, 1)]),
        fail(L::Unknown)
    );
    assert_eq!(check_server_methods(&m, &[s(1, 0x70, 9)]), fail(L::Changed));
    check_server_methods(&manifest(vec![]), &[]).unwrap();
}

// -------------------------------------------------------------- requests

#[test]
fn add_and_remove_make_the_next_manifest_and_a_signed_body() {
    let vault = unlocked(0x5a);
    let before = manifest(vec![password(), recovery()]);
    let cur = sealed(&vault, 2, &before);
    let mut rng = TestRng::new(b"add");
    let add = manifest_add_method(&mut rng, &vault, &row(&cur), prf_wrap(0x72, 1)).unwrap();

    assert_eq!(add.op, AuthOp::UnlockMethodAdd);
    assert_eq!(
        add.manifest,
        before.with_method(&prf_wrap(0x72, 1)).unwrap()
    );
    assert_eq!(add.sealed.rev, 3);
    assert_eq!(
        decrypt_manifest(
            &vault,
            add.sealed.rev,
            &add.sealed.envelope,
            &add.sealed.tag
        )
        .unwrap(),
        add.manifest
    );
    let text = String::from_utf8(add.body.clone()).unwrap();
    assert!(text.starts_with("{\"method_type\":3,\"method_id\":\"72727272"));
    assert!(text.contains("\"kek_generation\":2,"));
    assert!(text.ends_with("}}"));
    assert!(text.contains(&format!("\"envelope\":\"{}\"", he(&add.sealed.envelope))));

    // The proof is over exactly this body.
    let nonce = [0xa5u8; 32];
    let proof = add.sign(&vault, &nonce).unwrap();
    verify_auth_proof(
        &AuthPublicKey::new(add.pk_a),
        AuthOp::UnlockMethodAdd,
        &vault.context().account_id,
        &nonce,
        vault.context().vk_epoch,
        &add.body,
        &proof,
    )
    .unwrap();
    assert_eq!(
        proof,
        auth_sign(&vault, AuthOp::UnlockMethodAdd, &nonce, &add.body).unwrap()
    );

    // Remove it again.
    let mut rng = TestRng::new(b"remove");
    let removed = manifest_remove_method(&mut rng, &vault, &row(&add.sealed), &mid(0x72)).unwrap();
    assert_eq!(removed.op, AuthOp::UnlockMethodRemove);
    assert_eq!(removed.manifest, before);
    assert_eq!(removed.sealed.rev, 4);
    let text = String::from_utf8(removed.body.clone()).unwrap();
    assert!(text.starts_with("{\"method_id\":\"72727272"));
    assert!(!text.contains("method_type"));
}

#[test]
fn a_change_is_signed_only_by_the_vault_it_was_made_for() {
    let vault = unlocked(0x5a);
    let other = unlocked(0x5b);
    let cur = sealed(&vault, 2, &manifest(vec![password(), recovery()]));
    let mut rng = TestRng::new(b"who");
    let add = manifest_add_method(&mut rng, &vault, &row(&cur), prf_wrap(0x72, 1)).unwrap();
    assert_eq!(
        add.sign(&other, &[1; 32]),
        Err(Error::Pinned(ferret_core::PinnedField::AuthKey))
    );
}

#[test]
fn a_refused_change_draws_nothing() {
    let vault = unlocked(0x5a);
    let cur = sealed(&vault, 2, &manifest(vec![password(), recovery()]));
    let mut none = ReplayRng::new(vec![]);
    assert_eq!(
        manifest_remove_method(&mut none, &vault, &row(&cur), &mid(0x70)).map(|_| ()),
        Err(Error::InvalidInput(InputError::LastMethod))
    );
    assert_eq!(
        manifest_add_method(&mut none, &vault, &row(&cur), prf_wrap(0x70, 1)).map(|_| ()),
        Err(Error::Malformed(MalformedKind::Entries))
    );
    none.finish().unwrap();
}

#[test]
fn the_current_manifest_must_be_the_vaults_own_and_current() {
    let vault = unlocked(0x5a);
    let m = manifest(vec![password(), recovery()]);
    let cur = sealed(&vault, 2, &m);
    let mut none = ReplayRng::new(vec![]);
    let mut stale = row(&cur);
    stale.rev = 3;
    assert_eq!(
        manifest_add_method(&mut none, &vault, &stale, prf_wrap(0x72, 1)).map(|_| ()),
        Err(Error::Decrypt)
    );
    let mut tag = cur.tag;
    tag[0] ^= 1;
    let forged = CurrentManifest {
        tag: &tag,
        ..row(&cur)
    };
    assert_eq!(
        manifest_remove_method(&mut none, &vault, &forged, &mid(0x72)).map(|_| ()),
        Err(Error::Decrypt)
    );
}

// ---------------------------------------------------------------- salt

#[test]
fn prf_salt_new_is_one_draw_of_32_bytes() {
    let mut rng = ReplayRng::new(vec![vec![7; 32]]);
    assert_eq!(prf_salt_new(&mut rng), [7; 32]);
    rng.finish().unwrap();
    let mut a = TestRng::new(b"a");
    let mut b = TestRng::new(b"b");
    assert_ne!(prf_salt_new(&mut a), prf_salt_new(&mut b));
}

// ---------------------------------------------------------------- vectors

fn entry_of(v: &Value) -> ManifestEntry {
    let id = MethodId::from_bytes(hexn(&v["id"]));
    let generation = u64s(&v["generation"]);
    match v.get("credential_id") {
        Some(c) => ManifestEntry::passkey(id, generation, hex(c)),
        None => ManifestEntry::new(v["type"].as_u64().unwrap() as u8, id, generation),
    }
}

fn change_output(c: &MethodChange, input: &Value, vault: &UnlockedVault) -> Result<Value, Error> {
    let mut out = json!({
        "manifest": he(&c.manifest.to_cbor()?),
        "sealed": {
            "rev": c.sealed.rev.to_string(),
            "envelope": he(&c.sealed.envelope),
            "tag": he(&c.sealed.tag),
        },
        "body": he(&c.body),
    });
    if let Some(sign) = input.get("sign") {
        out["op"] = json!(c.op.name());
        out["pk_a"] = json!(he(&c.pk_a));
        out["proof"] = json!(he(&c.sign(vault, &hexn(&sign["nonce"]))?));
    }
    Ok(out)
}

#[test]
fn methods_vectors_from_file() {
    let file = load_ops("methods.json", |_| true);
    let report = ferret_core::testing::vector::run_all(&file, |c, rng| {
        let input = &c.input;
        let output = match c.op.as_str() {
            "prf.salt_new" => json!({ "salt": he(&prf_salt_new(rng)) }),
            "methods.check_server" => {
                let m = &input["manifest"];
                let list = manifest(
                    m["methods"]
                        .as_array()
                        .unwrap()
                        .iter()
                        .map(entry_of)
                        .collect(),
                );
                let server: Vec<ServerMethod> = input["server"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|s| ServerMethod {
                        method_type: s["method_type"].as_u64().unwrap() as u8,
                        method_id: MethodId::from_bytes(hexn(&s["method_id"])),
                        kek_generation: u64s(&s["kek_generation"]),
                    })
                    .collect();
                check_server_methods(&list, &server)?;
                json!({ "ok": true })
            }
            "methods.add" | "methods.remove" => {
                let vault = vault_of(input);
                let envelope = hex(&input["current"]["envelope"]);
                let tag: [u8; 32] = hexn(&input["current"]["tag"]);
                let current = CurrentManifest {
                    rev: u64s(&input["current"]["rev"]),
                    envelope: &envelope,
                    tag: &tag,
                };
                let change = if c.op == "methods.add" {
                    let w = &input["wrap"];
                    let method = if w["method_type"].as_u64() == Some(3) {
                        Method::Prf {
                            credential_id: hex(&w["credential_id"]),
                            prf_salt: hexn(&w["prf_salt"]),
                        }
                    } else {
                        Method::Recovery
                    };
                    let wrap = WrapRecord {
                        method_id: MethodId::from_bytes(hexn(&w["method_id"])),
                        kek_generation: u64s(&w["kek_generation"]),
                        method,
                        wrap: hex(&w["wrap"]),
                    };
                    manifest_add_method(rng, &vault, &current, wrap)?
                } else {
                    let id = MethodId::from_bytes(hexn(&input["method_id"]));
                    manifest_remove_method(rng, &vault, &current, &id)?
                };
                change_output(&change, input, &vault)?
            }
            other => panic!("unknown op {other}"),
        };
        Ok(Outcome {
            output,
            intermediate: None,
        })
    });
    assert_all_passed(&report, 30);
}
