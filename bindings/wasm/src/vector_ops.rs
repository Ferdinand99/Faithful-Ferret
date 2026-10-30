//! Test-support builds only: the operations of `vectors/OPS.md` as one
//! exported function, plus the primitives that the third-party vector files
//! need, a test OPAQUE server and a few memory probes. The Node tests run
//! every vector file through the WASM build with these, so the very code
//! that ships (compiled for `wasm32`) is the code that is checked against
//! the published and the recorded vectors.
//!
//! Every export here is named `test_*` (or is a method named `test_*`).
//! `scripts/check-no-test-support.sh` fails the build if the release `.wasm`
//! has one.
//!
//! This module is test tooling: the strict lints of the binding are relaxed.
//! An op the Rust runner does not know is an error code, not a trap.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::arithmetic_side_effects
)]

use crate::job::UnlockJob;
use crate::vault::Vault;
use ferret_core::testing::keys::{
    derived_keys, export_key_bytes, kek_bytes, recovery_seed, unlocked_vault_keys,
};
use ferret_core::testing::opaque::{Server, ServerLoginState};
use ferret_core::testing::passkey::{item_of, private_scalar, reveal_prf_output};
use ferret_core::testing::text::{
    export_password_bytes, master_password_bytes, opaque_input_bytes, recovery_key_bytes,
    secret_key_bytes,
};
use ferret_core::testing::{ReplayRng, TestRng, hex_decode, hex_encode};
use ferret_core::{
    AccountId, AuthOp, AuthPublicKey, CallerContext, Checkpoint, CheckpointEntry, CreateRequest,
    Error, ExistingCredential, ExportItem, ExportKey, ExportPassword, GetRequest, ItemBody, ItemId,
    KdfParams, Kek, KekDevPin, KsfProfile, Manifest, MasterPassword, Method, MethodId, MethodKey,
    MpPolicy, MutationOp, PasskeyRecord, Pin, PinState, Pinned, PlainExportOptions, PrfOutput,
    RecoveryKey, RecoveryPublicKey, RekeyInput, RekeyItem, RekeyTombstone, RowState, SecretKey,
    ServerRow, TotpAlgorithm, UnlockedVault, UserVerification, UvOutcome, VaultContext, VaultId,
    VaultKey, WrapRecord, auth_sign, canonical_origin, decode_recovery_key, decode_secret_key,
    decrypt_item, decrypt_manifest, encode_recovery_key, encode_secret_key, encrypt_item,
    encrypt_manifest, export_encrypt, export_plain_csv, export_plain_json, import_decrypt,
    item_tag, make_checkpoint, make_tombstone, opaque_login_finish, opaque_login_start,
    opaque_register_finish, opaque_register_start, parse_export_header, parse_otpauth,
    passkey_create, passkey_get, prf_output, recovery_public_key, recovery_sign, totp_code,
    totp_seconds_left, unwrap_vk, validate_rp_id, verify_auth_proof, verify_checkpoint,
    verify_item_tag, verify_recovery_proof, verify_tombstone, wrap_vk,
};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use wasm_bindgen::prelude::*;

// ---------------------------------------------------------------- helpers

fn hx(v: &Value) -> Vec<u8> {
    hex_decode(v.as_str().unwrap()).unwrap()
}

fn hn<const N: usize>(v: &Value) -> [u8; N] {
    hx(v).try_into().unwrap()
}

fn he(b: &[u8]) -> String {
    hex_encode(b)
}

fn u64s(v: &Value) -> u64 {
    v.as_str().unwrap().parse().unwrap()
}

fn ctx_of(i: &Value) -> VaultContext {
    VaultContext {
        account_id: AccountId::from_bytes(hn(&i["account_id"])),
        vault_id: VaultId::from_bytes(hn(&i["vault_id"])),
        vk_epoch: u64s(&i["vk_epoch"]),
    }
}

fn vault_of(i: &Value) -> UnlockedVault {
    UnlockedVault::from_vault_key(ctx_of(i), VaultKey::from_test_bytes(hn(&i["vk"]))).unwrap()
}

/// Bytes from `{ "segments": [ { "hex", "repeat" } | { "keys": ... } ] }`.
fn segments(input: &Value) -> Vec<u8> {
    let mut out = Vec::new();
    for seg in input["segments"].as_array().unwrap() {
        if let Some(keys) = seg.get("keys") {
            let value = hx(&keys["value_hex"]);
            for i in 0..keys["count"].as_u64().unwrap() {
                out.push(0x65);
                out.extend_from_slice(format!("{i:05}").as_bytes());
                out.extend_from_slice(&value);
            }
            continue;
        }
        let unit = hx(&seg["hex"]);
        for _ in 0..seg["repeat"].as_u64().unwrap() {
            out.extend_from_slice(&unit);
        }
    }
    out
}

/// The bytes of a text input: `{ "utf8": hex }` or segments of escapes.
fn text_bytes(input: &Value) -> Vec<u8> {
    if let Some(h) = input.get("utf8") {
        return hx(h);
    }
    let mut out = String::new();
    for segment in input["segments"].as_array().unwrap() {
        let chars: String = segment["escapes"]
            .as_str()
            .unwrap()
            .split_whitespace()
            .map(|e| {
                let h = e.strip_prefix("U+").unwrap();
                char::from_u32(u32::from_str_radix(h, 16).unwrap()).unwrap()
            })
            .collect();
        for _ in 0..segment["repeat"].as_u64().unwrap() {
            out.push_str(&chars);
        }
    }
    if let Some(text) = input.get("text") {
        assert_eq!(text.as_str().unwrap(), out, "text differs from its escapes");
    }
    out.into_bytes()
}

fn policy_of(input: &Value) -> MpPolicy {
    match input["policy"].as_str().unwrap() {
        "with_secret_key" => MpPolicy::WithSecretKey,
        _ => MpPolicy::WithoutSecretKey,
    }
}

fn method_of(v: &Value) -> Method {
    match v["type"].as_str().unwrap() {
        "password" => Method::Password {
            ksf: KsfProfile::from_wire(v["ksf_profile"].as_u64().unwrap() as u32).unwrap(),
        },
        "recovery" => Method::Recovery,
        "prf" => Method::Prf {
            credential_id: hx(&v["credential_id"]),
            prf_salt: hn(&v["prf_salt"]),
        },
        "pin" => Method::Pin {
            device_salt: hn(&v["device_salt"]),
        },
        _ => Method::Device,
    }
}

fn kdf_of(v: &Value) -> KdfParams {
    KdfParams {
        m_kib: v["m_kib"].as_u64().unwrap() as u32,
        t: v["t"].as_u64().unwrap() as u32,
        p: v["p"].as_u64().unwrap() as u32,
    }
}

// -------------------------------------------------------- the ops, a-z

fn tlv_build(i: &Value) -> Result<Value, Error> {
    let mut tlv = ferret_core::Tlv::new();
    for field in i["fields"].as_array().unwrap() {
        let tag_byte = || hx(&field["tag"])[0];
        tlv = match field["type"].as_str().unwrap() {
            "label" => tlv.label(Box::leak(
                field["value"]
                    .as_str()
                    .unwrap()
                    .to_string()
                    .into_boxed_str(),
            )),
            "label_hex" => tlv.label(Box::leak(
                String::from_utf8(hx(&field["value"]))
                    .unwrap()
                    .into_boxed_str(),
            )),
            "u8" => tlv.u8(tag_byte(), field["value"].as_u64().unwrap() as u8),
            "u64" => tlv.u64(tag_byte(), u64s(&field["value"])),
            "bytes" => {
                let value = match field.get("fill") {
                    Some(f) => vec![hx(&f["byte"])[0]; f["len"].as_u64().unwrap() as usize],
                    None => hx(&field["value"]),
                };
                tlv.bytes(tag_byte(), &value)?
            }
            other => panic!("field type {other}"),
        };
    }
    Ok(json!({ "tlv": he(&tlv.finish()?) }))
}

fn kdf_ops(method: &str, i: &Value) -> Result<Value, Error> {
    Ok(match method {
        "kdf_argon2id" => {
            let mut out = vec![0u8; i["out_len"].as_u64().unwrap() as usize];
            ferret_core::testing::prim::argon2id(
                &hx(&i["password"]),
                &hx(&i["salt"]),
                kdf_of(i),
                &mut out,
            )?;
            json!({ "hash": he(&out) })
        }
        "kek_from_export_key" => {
            let ek = ExportKey::from_test_bytes(hn(&i["export_key"]));
            let acct = AccountId::from_bytes(hn(&i["account_id"]));
            json!({ "kek": he(&kek_bytes(&Kek::from_export_key(&acct, &ek)?)) })
        }
        "kek_from_recovery_key" => {
            let rk = RecoveryKey::from_test_bytes(hn(&i["rk"]));
            let acct = AccountId::from_bytes(hn(&i["account_id"]));
            json!({
                "kek": he(&kek_bytes(&Kek::from_recovery_key(&acct, &rk)?)),
                "seed_r": he(&recovery_seed(&rk, &acct)?),
                "pk_r": he(&recovery_public_key(&rk, &acct)?),
            })
        }
        "vault_derive_keys" => {
            let c = ctx_of(i);
            let vk = VaultKey::from_test_bytes(hn(&i["vk"]));
            let k = derived_keys(&c, &vk)?;
            json!({
                "k_head": he(&k.k_head), "k_del": he(&k.k_del), "k_meta": he(&k.k_meta),
                "seed_a": he(&k.seed_a), "pk_a": he(&k.pk_a),
            })
        }
        "kek_from_prf" => {
            let out = PrfOutput::from_test_bytes(hn(&i["prf_output"]));
            json!({ "kek": he(&kek_bytes(&Kek::from_prf(&hx(&i["credential_id"]), &out)?)) })
        }
        "kek_from_pin_extension" => {
            let pin = Pin::new(i["pin"].as_str().unwrap().as_bytes())?;
            let kek = Kek::from_pin_extension(&pin, &hn(&i["device_salt"]))?;
            json!({ "kek": he(&kek_bytes(&kek)) })
        }
        "kek_from_pin_mobile" => {
            let pin = Pin::new(i["pin"].as_str().unwrap().as_bytes())?;
            let dev = KekDevPin::from_test_bytes(hn(&i["kek_dev_pin"]));
            let kek = Kek::from_pin_mobile(&pin, &hn(&i["device_salt"]), &dev)?;
            json!({ "kek": he(&kek_bytes(&kek)) })
        }
        _ => unreachable!(),
    })
}

fn text_ops(method: &str, i: &Value) -> Result<Value, Error> {
    let bytes = text_bytes(i);
    Ok(match method {
        "text_nfkd" => {
            let text = String::from_utf8(bytes).unwrap();
            json!({ "nfkd": he(ferret_core::text::unicode::nfkd(&text).as_bytes()) })
        }
        "master_password_check" => {
            let mp = MasterPassword::new(&bytes, policy_of(i))?;
            json!({ "mp": he(&master_password_bytes(&mp)) })
        }
        "opaque_input_build" => {
            let mp = MasterPassword::new(&bytes, policy_of(i))?;
            let sk = i["secret_key"]
                .as_str()
                .map(|h| SecretKey::from_test_bytes(hex_decode(h).unwrap().try_into().unwrap()));
            json!({ "opaque_input": he(&opaque_input_bytes(&mp.opaque_input(sk.as_ref()))) })
        }
        "export_password_check" => {
            let master = match i.get("master_password") {
                Some(Value::Null) | None => None,
                Some(other) => Some(MasterPassword::new(
                    &text_bytes(other),
                    MpPolicy::WithSecretKey,
                )?),
            };
            let pw = ExportPassword::new(&bytes, master.as_ref())?;
            json!({ "export_password": he(&export_password_bytes(&pw)) })
        }
        _ => unreachable!(),
    })
}

fn code_ops(method: &str, i: &Value) -> Result<Value, Error> {
    Ok(match method {
        "recovery_key_encode" => {
            let rk = RecoveryKey::from_test_bytes(hn(&i["key"]));
            json!({ "code": encode_recovery_key(&rk).to_string() })
        }
        "secret_key_encode" => {
            let sk = SecretKey::from_test_bytes(hn(&i["key"]));
            json!({ "code": encode_secret_key(&sk).to_string() })
        }
        "recovery_key_decode" => {
            let rk = decode_recovery_key(i["code"].as_str().unwrap())?;
            json!({ "key": he(&recovery_key_bytes(&rk)) })
        }
        "secret_key_decode" => {
            let sk = decode_secret_key(i["code"].as_str().unwrap())?;
            json!({ "key": he(&secret_key_bytes(&sk)) })
        }
        _ => unreachable!(),
    })
}

fn wrap_ops(method: &str, op: &str, i: &Value, rng: &mut ReplayRng) -> Result<Value, Error> {
    let c = ctx_of(i);
    if method == "wrap_open" {
        let rec = WrapRecord {
            method_id: MethodId::from_bytes(hn(&i["method_id"])),
            kek_generation: u64s(&i["kek_generation"]),
            method: method_of(&i["method"]),
            wrap: hx(&i["wrap"]),
        };
        let kek = Kek::from_test_bytes(hn(&i["kek"]));
        let vault = unwrap_vk(&c, &kek, &rec)?;
        return Ok(json!({
            "vk": he(&unlocked_vault_keys(&vault)[0]),
            "pk_a": he(&vault.auth_public_key()),
        }));
    }
    let vk = VaultKey::from_test_bytes(hn(&i["vk"]));
    let id = MethodId::from_bytes(hn(&i["method_id"]));
    let generation = u64s(&i["kek_generation"]);
    let (kek, m) = match op {
        "wrap.seal.password" => {
            let ek = ExportKey::from_test_bytes(hn(&i["export_key"]));
            (
                Kek::from_export_key(&c.account_id, &ek)?,
                Method::Password {
                    ksf: KsfProfile::from_wire(i["ksf_profile"].as_u64().unwrap() as u32)?,
                },
            )
        }
        "wrap.seal.recovery" => {
            let rk = RecoveryKey::from_test_bytes(hn(&i["rk"]));
            (
                Kek::from_recovery_key(&c.account_id, &rk)?,
                Method::Recovery,
            )
        }
        "wrap.seal.prf" => {
            let out = PrfOutput::from_test_bytes(hn(&i["prf_output"]));
            let credential_id = hx(&i["credential_id"]);
            (
                Kek::from_prf(&credential_id, &out)?,
                Method::Prf {
                    credential_id,
                    prf_salt: hn(&i["prf_salt"]),
                },
            )
        }
        "wrap.seal.pin" => {
            let salt = hn(&i["device_salt"]);
            let pin = Pin::new(i["pin"].as_str().unwrap().as_bytes())?;
            (
                Kek::from_pin_extension(&pin, &salt)?,
                Method::Pin { device_salt: salt },
            )
        }
        "wrap.seal.pin_mobile" => {
            let salt = hn(&i["device_salt"]);
            let pin = Pin::new(i["pin"].as_str().unwrap().as_bytes())?;
            let dev = KekDevPin::from_test_bytes(hn(&i["kek_dev_pin"]));
            (
                Kek::from_pin_mobile(&pin, &salt, &dev)?,
                Method::Pin { device_salt: salt },
            )
        }
        "wrap.seal.device" => (Kek::generate(rng), Method::Device),
        other => panic!("op {other}"),
    };
    let rec = wrap_vk(rng, &c, &vk, &kek, id, generation, m)?;
    // Every wrap the vectors seal must also open again.
    unwrap_vk(&c, &kek, &rec).expect("a sealed wrap opens");
    Ok(json!({ "wrap": he(&rec.wrap) }))
}

fn data_ops(method: &str, op: &str, i: &Value, rng: &mut ReplayRng) -> Result<Value, Error> {
    Ok(match method {
        "cbor_check" => {
            let v = ferret_core::cbor::decode(&segments(i))?;
            let again = ferret_core::cbor::encode(&v)?;
            json!({ "len": again.len(), "sha256": he(&Sha256::digest(&again)) })
        }
        "pad_apply" => {
            let padded = ferret_core::item::pad::pad(&segments(&i["plain"]))?;
            json!({ "padded_len": padded.len(), "padded_sha256": he(&Sha256::digest(&*padded)) })
        }
        "pad_remove" => {
            let padded = segments(&i["padded"]);
            let n = ferret_core::item::pad::unpad(&padded)?;
            json!({ "plain_len": n, "plain_sha256": he(&Sha256::digest(&padded[..n])) })
        }
        "item_seal" => {
            let vault = vault_of(i);
            let body = ItemBody::from_cbor(&segments(&i["body"]))?.body;
            let id = ItemId::from_bytes(hn(&i["item_id"]));
            let existing = i.get("existing").map(hx);
            let s = encrypt_item(rng, &vault, id, u64s(&i["rev"]), &body, existing.as_deref())?;
            if op == "item.seal.digest" {
                json!({
                    "envelope_len": s.envelope.len(),
                    "envelope_sha256": he(&Sha256::digest(&s.envelope)),
                    "tag": he(&s.tag),
                })
            } else {
                json!({ "envelope": he(&s.envelope), "tag": he(&s.tag) })
            }
        }
        "item_open" => {
            let vault = vault_of(i);
            let got = decrypt_item(
                &vault,
                ItemId::from_bytes(hn(&i["item_id"])),
                u64s(&i["rev"]),
                &hx(&i["envelope"]),
                &hn(&i["tag"]),
            )?;
            json!({ "read_only": got.read_only, "body": he(&got.body.to_cbor()?) })
        }
        "manifest_seal" => {
            let vault = vault_of(i);
            let m = Manifest::from_cbor(&hx(&i["manifest"]))?;
            let s = encrypt_manifest(rng, &vault, u64s(&i["rev"]), &m)?;
            json!({ "envelope": he(&s.envelope), "tag": he(&s.tag) })
        }
        "manifest_open" => {
            let vault = vault_of(i);
            let m = decrypt_manifest(&vault, u64s(&i["rev"]), &hx(&i["envelope"]), &hn(&i["tag"]))?;
            json!({ "manifest": he(&m.to_cbor()?) })
        }
        "tombstone_make" => {
            let vault = vault_of(i);
            let id = ItemId::from_bytes(hn(&i["item_id"]));
            let t = make_tombstone(rng, &vault, id, u64s(&i["rev"]))?;
            json!({ "tomb": he(&t.tomb) })
        }
        "tombstone_verify" => {
            let vault = vault_of(i);
            let id = ItemId::from_bytes(hn(&i["item_id"]));
            verify_tombstone(&vault, id, u64s(&i["rev"]), &hx(&i["tomb"]))?;
            json!({ "ok": true })
        }
        "item_tag" => {
            let vault = vault_of(i);
            let id = ItemId::from_bytes(hn(&i["item_id"]));
            let tag = item_tag(&vault, id, u64s(&i["rev"]), &hx(&i["envelope"]))?;
            json!({ "tag": he(&tag) })
        }
        "item_tag_verify" => {
            let vault = vault_of(i);
            let id = ItemId::from_bytes(hn(&i["item_id"]));
            verify_item_tag(
                &vault,
                id,
                u64s(&i["rev"]),
                &hx(&i["envelope"]),
                &hn(&i["tag"]),
            )?;
            json!({ "ok": true })
        }
        _ => unreachable!(),
    })
}

/// The rows of the generated state. See `OPS.md`.
fn generated(count: u32) -> Vec<CheckpointEntry> {
    (0..count)
        .map(|i| {
            let id = Sha256::new()
                .chain_update(b"ferret/checkpoint-vector/id")
                .chain_update(i.to_be_bytes())
                .finalize();
            let h = Sha256::new()
                .chain_update(b"ferret/checkpoint-vector/hash")
                .chain_update(i.to_be_bytes())
                .finalize();
            CheckpointEntry {
                item_id: ItemId::from_bytes(id[..16].try_into().unwrap()),
                rev: 1 + u64::from(i % 7),
                live_hash: if i % 5 == 0 {
                    None
                } else {
                    Some(h.as_slice().try_into().unwrap())
                },
            }
        })
        .collect()
}

fn entry_of(v: &Value) -> CheckpointEntry {
    CheckpointEntry {
        item_id: ItemId::from_bytes(hn(&v["item_id"])),
        rev: u64s(&v["rev"]),
        live_hash: if v["hash"].is_null() {
            None
        } else {
            Some(hn(&v["hash"]))
        },
    }
}

fn row_of(v: &Value) -> ServerRow {
    ServerRow {
        item_id: ItemId::from_bytes(hn(&v["item_id"])),
        rev: u64s(&v["rev"]),
        state: match v["state"].as_str().unwrap() {
            "live" => RowState::Live {
                blob_sha256: hn(&v["hash"]),
            },
            _ => RowState::Deleted,
        },
    }
}

fn rows_of(entries: &[CheckpointEntry]) -> Vec<ServerRow> {
    entries
        .iter()
        .map(|e| ServerRow {
            item_id: e.item_id,
            rev: e.rev,
            state: match e.live_hash {
                Some(h) => RowState::Live { blob_sha256: h },
                None => RowState::Deleted,
            },
        })
        .collect()
}

fn integrity_ops(method: &str, i: &Value) -> Result<Value, Error> {
    Ok(match method {
        "checkpoint_make" => {
            let vault = vault_of(i);
            let list = match i.get("generate") {
                Some(g) => generated(g["count"].as_u64().unwrap() as u32),
                None => i["entries"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(entry_of)
                    .collect(),
            };
            let c = make_checkpoint(&vault, u64s(&i["seq"]), list)?;
            let mut out = json!({
                "entries_len": c.entries.len(),
                "entries_sha256": he(&Sha256::digest(&c.entries)),
                "digest": he(&c.digest),
                "mac": he(&c.mac),
            });
            if c.entries.len() <= 20 * ferret_core::integrity::ENTRY_LEN {
                out["entries"] = json!(he(&c.entries));
            }
            out
        }
        "checkpoint_verify" => {
            let vault = vault_of(i);
            let given = &i["checkpoint"];
            let entries = match given.get("generate") {
                Some(g) => ferret_core::integrity::encode_entries(&generated(
                    g["count"].as_u64().unwrap() as u32,
                ))?,
                None => hx(&given["entries"]),
            };
            let c = Checkpoint {
                seq: u64s(&given["seq"]),
                digest: hn(&given["digest"]),
                mac: hn(&given["mac"]),
                entries,
            };
            let rows: Vec<ServerRow> = match &i["rows"] {
                Value::Array(list) => list.iter().map(row_of).collect(),
                spec => {
                    let omit: Vec<usize> = spec["omit"]
                        .as_array()
                        .unwrap()
                        .iter()
                        .map(|x| x.as_u64().unwrap() as usize)
                        .collect();
                    rows_of(&ferret_core::integrity::parse_entries(&c.entries)?)
                        .into_iter()
                        .enumerate()
                        .filter(|(n, _)| !omit.contains(n))
                        .map(|(_, r)| r)
                        .collect()
                }
            };
            verify_checkpoint(&vault, &c, &rows, u64s(&i["top_seq"]))?;
            json!({ "ok": true })
        }
        "proof_auth_sign" => {
            let vault = vault_of(i);
            let op = AuthOp::from_name(i["op"].as_str().unwrap()).ok_or(Error::Unsupported)?;
            let sig = auth_sign(&vault, op, &hn(&i["nonce"]), &hx(&i["body"]))?;
            json!({ "proof": he(&sig), "pk_a": he(&vault.auth_public_key()) })
        }
        "proof_recovery_sign" => {
            let account = AccountId::from_bytes(hn(&i["account_id"]));
            let rk = RecoveryKey::from_test_bytes(hn(&i["rk"]));
            let sig = recovery_sign(
                &rk,
                &account,
                u64s(&i["vk_epoch"]),
                &hn(&i["nonce"]),
                &hx(&i["body"]),
            )?;
            json!({ "proof": he(&sig), "pk_r": he(&recovery_public_key(&rk, &account)?) })
        }
        "proof_verify" => {
            let op = MutationOp::from_name(i["op"].as_str().unwrap()).ok_or(Error::Decrypt)?;
            let account = AccountId::from_bytes(hn(&i["account_id"]));
            let (nonce, epoch) = (hn(&i["nonce"]), u64s(&i["vk_epoch"]));
            let (body, sig): (Vec<u8>, [u8; 64]) = (hx(&i["body"]), hn(&i["proof"]));
            let pk: [u8; 32] = hn(&i["pk"]);
            match op.auth() {
                Some(auth) => verify_auth_proof(
                    &AuthPublicKey::new(pk),
                    auth,
                    &account,
                    &nonce,
                    epoch,
                    &body,
                    &sig,
                )?,
                None => verify_recovery_proof(
                    &RecoveryPublicKey::new(pk),
                    &account,
                    &nonce,
                    epoch,
                    &body,
                    &sig,
                )?,
            }
            json!({ "ok": true })
        }
        _ => unreachable!(),
    })
}

fn rekey_run(i: &Value, rng: &mut ReplayRng) -> Result<Value, Error> {
    let vault = vault_of(i);
    let items: Vec<(ItemId, u64, Vec<u8>, [u8; 32])> = i["items"]
        .as_array()
        .unwrap()
        .iter()
        .map(|x| {
            (
                ItemId::from_bytes(hn(&x["item_id"])),
                u64s(&x["rev"]),
                hx(&x["envelope"]),
                hn(&x["tag"]),
            )
        })
        .collect();
    let tombs: Vec<(ItemId, u64, Vec<u8>)> = i["tombstones"]
        .as_array()
        .unwrap()
        .iter()
        .map(|x| {
            (
                ItemId::from_bytes(hn(&x["item_id"])),
                u64s(&x["rev"]),
                hx(&x["tomb"]),
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
    let k = Kek::from_test_bytes(hn(&i["password_kek"]));
    assert_eq!(i["password_ksf_profile"], json!(1));
    let old_cp = Checkpoint {
        seq: u64s(&i["old_checkpoint"]["seq"]),
        digest: hn(&i["old_checkpoint"]["digest"]),
        mac: hn(&i["old_checkpoint"]["mac"]),
        entries: hx(&i["old_checkpoint"]["entries"]),
    };
    let m = &i["old_manifest"];
    let (m_envelope, m_tag) = (hx(&m["envelope"]), hn::<32>(&m["tag"]));
    let c = vault.context();
    let mut floors = Vec::new();
    for (key, name) in [
        (MethodKey::Password, "password_floor"),
        (MethodKey::Recovery, "recovery_floor"),
    ] {
        if !i[name].is_null() {
            floors.push((key, u64s(&i[name])));
        }
    }
    let pinned = Pinned {
        server_url: "https://ferret.example".into(),
        account_id: c.account_id,
        vault_id: c.vault_id,
        ksf_profile: 1,
        kek_generation_max: floors,
        vk_epoch_max: c.vk_epoch,
        sk_bit: true,
        pk_a: vault.auth_public_key(),
        server_public_key: None,
    };
    let b = vault.rekey(
        rng,
        &RekeyInput {
            base_seq: u64s(&i["base_seq"]),
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
                MethodId::from_bytes(hn(&i["password_method_id"])),
                Method::Password {
                    ksf: KsfProfile::P1,
                },
            ),
            recovery_method_id: MethodId::from_bytes(hn(&i["recovery_method_id"])),
        },
    )?;
    let keys = unlocked_vault_keys(&b.vault);
    Ok(json!({
        "vk_epoch": b.vk_epoch.to_string(),
        "vk": he(&keys[0]),
        "pk_a": he(&b.pk_a),
        "pk_r": he(&b.pk_r),
        "recovery_key": he(&recovery_key_bytes(&b.recovery_key)),
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
    }))
}

fn input_items(v: &Value) -> Vec<ExportItem> {
    v.as_array()
        .unwrap()
        .iter()
        .map(|x| ExportItem {
            item_id: ItemId::from_bytes(hn(&x["id"])),
            body: ItemBody::from_cbor(&hx(&x["body"])).unwrap().body,
        })
        .collect()
}

fn output_items(items: &[ExportItem]) -> Value {
    json!(
        items
            .iter()
            .map(|x| json!({
                "id": he(x.item_id.as_bytes()),
                "body": he(&x.body.to_cbor().unwrap()),
            }))
            .collect::<Vec<_>>()
    )
}

fn export_ops(method: &str, op: &str, i: &Value, rng: &mut ReplayRng) -> Result<Value, Error> {
    let password = || ExportPassword::for_open(i["password"].as_str().unwrap().as_bytes()).unwrap();
    Ok(match method {
        "export_encrypt" => {
            let file = export_encrypt(
                rng,
                &password(),
                kdf_of(&i["kdf"]),
                u64s(&i["created_at"]),
                &input_items(&i["items"]),
            )?;
            json!({ "file": he(&file) })
        }
        "export_decrypt" => {
            let file = hx(&i["file"]);
            let items = import_decrypt(&password(), &file)?;
            let (h, _) = parse_export_header(&file)?;
            json!({
                "created_at": h.created_at.to_string(),
                "kdf": { "m_kib": h.kdf.m_kib, "t": h.kdf.t, "p": h.kdf.p },
                "items": output_items(&items),
            })
        }
        "export_header" => {
            let (h, used) = parse_export_header(&hx(&i["file"]))?;
            json!({
                "created_at": h.created_at.to_string(),
                "kdf": { "m_kib": h.kdf.m_kib, "t": h.kdf.t, "p": h.kdf.p },
                "salt": he(&h.salt),
                "header_len": used,
            })
        }
        "export_plain_json" | "export_plain_csv" => {
            let items = input_items(&i["items"]);
            let o = PlainExportOptions {
                include_passkeys: i["include_passkeys"].as_bool().unwrap(),
            };
            let text = if op == "export.plain.json" {
                export_plain_json(&items, &o)?
            } else {
                export_plain_csv(&items, &o)?
            };
            json!({ "text": text })
        }
        _ => unreachable!(),
    })
}

fn pinned_of(p: &Value) -> Pinned {
    Pinned {
        server_url: "https://ferret.example".into(),
        account_id: AccountId::from_bytes([0x11; 16]),
        vault_id: VaultId::from_bytes([0x22; 16]),
        ksf_profile: p["ksf_profile"].as_u64().unwrap() as u8,
        kek_generation_max: vec![],
        vk_epoch_max: 1,
        sk_bit: p["sk_bit"].as_bool().unwrap(),
        pk_a: [7; 32],
        server_public_key: p["server_public_key"]
            .as_str()
            .map(|_| hn(&p["server_public_key"])),
    }
}

fn opaque_ops(method: &str, i: &Value, rng: &mut ReplayRng) -> Result<Value, Error> {
    let sk = i["secret_key"]
        .as_str()
        .map(|_| SecretKey::from_test_bytes(hn(&i["secret_key"])));
    let pw = MasterPassword::for_unlock(&hx(&i["password_hex"]))
        .unwrap()
        .opaque_input(sk.as_ref());
    Ok(match method {
        "opaque_register" => {
            let (request, state) = opaque_register_start(rng, &pw)?;
            let profile = KsfProfile::from_wire(i["ksf_profile"].as_u64().unwrap() as u32)?;
            let done = opaque_register_finish(rng, state, &pw, &hx(&i["response"]), profile)?;
            json!({
                "request": he(&request),
                "record": he(&done.record),
                "export_key": he(&export_key_bytes(&done.export_key)),
                "server_public_key": he(&done.server_public_key),
            })
        }
        "opaque_login" => {
            let (ke1, state) = opaque_login_start(rng, &pw)?;
            let pin = i.get("pinned").filter(|p| !p.is_null()).map(pinned_of);
            let done = opaque_login_finish(
                rng,
                state,
                &pw,
                &hx(&i["ke2"]),
                i["server_profile"].as_u64().unwrap() as u32,
                pin.as_ref().map_or(PinState::FirstUse, PinState::Pinned),
            )?;
            json!({
                "ke1": he(&ke1),
                "ke3": he(&done.ke3),
                "export_key": he(&export_key_bytes(&done.export_key)),
                "server_public_key": he(&done.server_public_key),
            })
        }
        _ => unreachable!(),
    })
}

fn totp_ops(method: &str, i: &Value) -> Result<Value, Error> {
    let p = parse_otpauth(i["uri"].as_str().unwrap())?;
    Ok(match method {
        "totp_parse" => json!({
            "secret": he(&ferret_core::testing::totp::secret_bytes(&p)),
            "algorithm": p.algorithm().name(),
            "digits": p.digits(),
            "period": p.period(),
            "issuer": p.issuer(),
            "label": p.label(),
        }),
        _ => {
            let t = u64s(&i["unix_seconds"]);
            let code = totp_code(&p, t)?;
            json!({ "code": code.to_string(), "seconds_left": totp_seconds_left(&p, t) })
        }
    })
}

fn passkey_ops(method: &str, i: &Value, rng: &mut ReplayRng) -> Result<Value, Error> {
    use ferret_core::PrfSeed;
    use ferret_core::passkey::{PrfCreate, PrfEval, PrfRequest, prf_salt};
    let eval_of = |v: &Value| PrfEval {
        first: hx(&v["first"]),
        second: v["second"].as_str().map(|s| hex_decode(s).unwrap()),
    };
    let uv_kind = |s: &str| match s {
        "required" => UserVerification::Required,
        "preferred" => UserVerification::Preferred,
        _ => UserVerification::Discouraged,
    };
    let hex_list = |v: &Value| -> Vec<Vec<u8>> { v.as_array().unwrap().iter().map(hx).collect() };
    if method == "passkey_prf" {
        let seed = PrfSeed::from_test_bytes(hn(&i["seed"]));
        let bytes = segments(&i["input"]);
        let out = prf_output(&seed, &bytes)?;
        return Ok(json!({
            "salt": he(&prf_salt(&bytes)),
            "output": he(reveal_prf_output(&out)),
        }));
    }
    let uv = UvOutcome {
        user_present: i["uv"]["user_present"].as_bool().unwrap(),
        user_verified: i["uv"]["user_verified"].as_bool().unwrap(),
    };
    let ctx = CallerContext {
        origin: canonical_origin(i["origin"].as_str().unwrap())?,
        top_origin_is_same: i["top_origin_is_same"].as_bool().unwrap(),
    };
    if method == "passkey_create" {
        let r = &i["request"];
        let req = CreateRequest {
            challenge: hx(&r["challenge"]),
            rp_id: r["rp_id"].as_str().map(str::to_owned),
            rp_name: r["rp_name"].as_str().unwrap().to_owned(),
            user_id: hx(&r["user_id"]),
            user_name: r["user_name"].as_str().unwrap().to_owned(),
            user_display_name: r["user_display_name"].as_str().unwrap().to_owned(),
            algorithms: r["algorithms"]
                .as_array()
                .unwrap()
                .iter()
                .map(|a| a.as_i64().unwrap())
                .collect(),
            exclude: hex_list(&r["exclude"]),
            user_verification: uv_kind(r["user_verification"].as_str().unwrap()),
            prf: r["prf"].as_object().map(|p| PrfCreate {
                eval: p.get("eval").filter(|e| !e.is_null()).map(eval_of),
            }),
        };
        let existing: Vec<ExistingCredential> = i["existing_credentials"]
            .as_array()
            .unwrap()
            .iter()
            .map(|e| ExistingCredential {
                rp_id: e["rp_id"].as_str().unwrap().to_owned(),
                cred_id: hx(&e["id"]),
            })
            .collect();
        let created = passkey_create(rng, &req, &ctx, uv, &existing, u64s(&i["created_ms"]))?;
        let item = item_of(&created.record);
        let r = &created.response;
        let prf = match &r.prf {
            None => Value::Null,
            Some(p) => json!({
                "enabled": p.enabled,
                "first": p.results.as_ref().map_or(Value::Null, |x| Value::from(he(x.reveal_first()))),
                "second": p.results.as_ref().and_then(|x| x.reveal_second()).map_or(Value::Null, |s| Value::from(he(s))),
            }),
        };
        return Ok(json!({
            "record": {
                "cred_id": he(&item.cred_id),
                "rp_id": item.rp_id,
                "user_handle": he(&item.user_handle),
                "user_name": item.user_name,
                "created": item.created.to_string(),
                "private_scalar": he(&private_scalar(&created.record).unwrap()),
                "priv_pkcs8": he(&item.private_key),
                "prf_seed_uv": item.prf_seed_uv.as_deref().map_or(Value::Null, |s| Value::from(he(s))),
                "prf_seed_nouv": item.prf_seed_nouv.as_deref().map_or(Value::Null, |s| Value::from(he(s))),
            },
            "response": {
                "id": he(&r.id),
                "attestation_object": he(&r.attestation_object),
                "client_data_json": String::from_utf8(r.client_data_json.clone()).unwrap(),
                "authenticator_data": he(&r.authenticator_data),
                "public_key_spki": he(&r.public_key_spki),
                "alg": r.alg,
                "prf": prf,
            },
        }));
    }
    // passkey_get
    let rec = &i["record"];
    let optb = |v: &Value| v.as_str().map(|s| hex_decode(s).unwrap());
    let record = PasskeyRecord::from_item(&ferret_core::Passkey {
        cred_id: hx(&rec["cred_id"]),
        rp_id: rec["rp_id"].as_str().unwrap().to_owned(),
        user_handle: hx(&rec["user_handle"]),
        user_name: rec["user_name"].as_str().unwrap().to_owned(),
        private_key: hx(&rec["priv_pkcs8"]),
        sign_count: 0,
        created: u64s(&rec["created"]),
        prf_seed_uv: optb(&rec["prf_seed_uv"]),
        prf_seed_nouv: optb(&rec["prf_seed_nouv"]),
        extra: vec![],
    })?;
    let r = &i["request"];
    let req = GetRequest {
        challenge: hx(&r["challenge"]),
        rp_id: r["rp_id"].as_str().map(str::to_owned),
        allow: hex_list(&r["allow"]),
        user_verification: uv_kind(r["user_verification"].as_str().unwrap()),
        prf: r["prf"].as_object().map(|p| PrfRequest {
            eval: p.get("eval").filter(|e| !e.is_null()).map(eval_of),
            eval_by_credential: p["eval_by_credential"]
                .as_array()
                .unwrap()
                .iter()
                .map(|e| (hx(&e["id"]), eval_of(e)))
                .collect(),
        }),
    };
    let out = passkey_get(&record, &req, &ctx, uv)?;
    Ok(json!({
        "id": he(&out.id),
        "authenticator_data": he(&out.authenticator_data),
        "client_data_json": String::from_utf8(out.client_data_json.clone()).unwrap(),
        "signature": he(&out.signature),
        "user_handle": he(&out.user_handle),
        "prf": match &out.prf {
            None => Value::Null,
            Some(p) => json!({
                "first": he(p.reveal_first()),
                "second": p.reveal_second().map_or(Value::Null, |s| Value::from(he(s))),
            }),
        },
    }))
}

fn dispatch(
    method: &str,
    op: &str,
    i: &Value,
    rng: &mut ReplayRng,
) -> Result<Value, Option<Error>> {
    let r = match method {
        "tlv_build" => tlv_build(i),
        "kdf_argon2id"
        | "kek_from_export_key"
        | "kek_from_recovery_key"
        | "vault_derive_keys"
        | "kek_from_prf"
        | "kek_from_pin_extension"
        | "kek_from_pin_mobile" => kdf_ops(method, i),
        "text_nfkd" | "master_password_check" | "opaque_input_build" | "export_password_check" => {
            text_ops(method, i)
        }
        "recovery_key_encode"
        | "recovery_key_decode"
        | "secret_key_encode"
        | "secret_key_decode" => code_ops(method, i),
        "wrap_password" | "wrap_recovery" | "wrap_prf" | "wrap_pin" | "wrap_pin_mobile"
        | "wrap_device" | "wrap_open" => wrap_ops(method, op, i, rng),
        "cbor_check" | "pad_apply" | "pad_remove" | "item_seal" | "item_open" | "manifest_seal"
        | "manifest_open" | "tombstone_make" | "tombstone_verify" | "item_tag"
        | "item_tag_verify" => data_ops(method, op, i, rng),
        "checkpoint_make"
        | "checkpoint_verify"
        | "proof_auth_sign"
        | "proof_recovery_sign"
        | "proof_verify" => integrity_ops(method, i),
        "vault_rekey" => rekey_run(i, rng),
        "export_encrypt" | "export_decrypt" | "export_header" | "export_plain_json"
        | "export_plain_csv" => export_ops(method, op, i, rng),
        "opaque_register" | "opaque_login" => opaque_ops(method, i, rng),
        "account_create"
        | "account_change_password"
        | "account_recover"
        | "account_verify_recovery"
        | "account_verify_secret_key"
        | "setup_qr_build"
        | "setup_qr_parse" => ferret_core::testing::account::run_case(op, i, rng),
        "totp_parse" | "totp_code" => totp_ops(method, i),
        "origin_canonical" => canonical_origin(&String::from_utf8(hx(&i["raw_utf8"])).unwrap())
            .map(|o| json!({ "origin": o.as_str(), "host": o.host() })),
        "origin_rp_id" => canonical_origin(&String::from_utf8(hx(&i["origin_utf8"])).unwrap())
            .and_then(|o| {
                validate_rp_id(&o, &String::from_utf8(hx(&i["rp_id_utf8"])).unwrap())
                    .map(|rp| json!({ "rp_id": rp.as_str() }))
            }),
        "passkey_create" | "passkey_get" | "passkey_prf" => passkey_ops(method, i, rng),
        _ => return Err(None),
    };
    r.map_err(Some)
}

/// Runs one case of an internal vector file. `case_json` is the case as it is
/// in the file; `method` is the WASM method that `OPS.md` lists for its `op`.
/// Returns `{ ok: true, output, rng_left }` or `{ ok: false, code, rng_left }`;
/// an op that is not known here is `{ ok: false, code: "unknown_op" }`. The
/// intermediate values of a case are not produced (the Rust runner checks
/// them).
#[wasm_bindgen]
pub fn test_run_case(method: &str, case_json: &str) -> String {
    let case: Value = serde_json::from_str(case_json).unwrap();
    let draws: Vec<Vec<u8>> = case["rng"].as_array().unwrap().iter().map(hx).collect();
    let mut rng = ReplayRng::new(draws);
    let op = case["op"].as_str().unwrap().to_owned();
    let result = dispatch(method, &op, &case["input"], &mut rng);
    let rng_left = rng.finish().is_err();
    match result {
        Ok(output) => json!({ "ok": true, "output": output, "rng_left": rng_left }),
        Err(Some(e)) => json!({ "ok": false, "code": e.code(), "rng_left": rng_left }),
        Err(None) => json!({ "ok": false, "code": "unknown_op", "rng_left": rng_left }),
    }
    .to_string()
}

// ------------------------------------------------ third-party vector files

fn identities(i: &Value) -> Option<(Vec<u8>, Vec<u8>)> {
    match (i.get("client_identity"), i.get("server_identity")) {
        (Some(c), Some(s)) => Some((hx(c), hx(s))),
        _ => None,
    }
}

fn external(kind: &str, i: &Value) -> Result<Value, Error> {
    use ferret_core::testing::prim;
    Ok(match kind {
        "aead_open" => {
            let key: [u8; 32] = hx(&i["key"]).try_into().map_err(|_| Error::Decrypt)?;
            let pt = prim::aead_open(&key, &hx(&i["aad"]), &hx(&i["blob"]))?;
            json!({ "pt": he(&pt) })
        }
        "aead_seal_fixed" => {
            let mut rng = ReplayRng::new(vec![hx(&i["nonce"])]);
            let blob = prim::aead_seal(&mut rng, &hn(&i["key"]), &hx(&i["aad"]), &hx(&i["pt"]))?;
            json!({ "blob": he(&blob), "rng_left": rng.finish().is_err() })
        }
        "ed25519_public_key" => json!({ "pk": he(&prim::ed25519_public_key(&hn(&i["seed"]))) }),
        "ed25519_sign" => {
            json!({ "sig": he(&prim::ed25519_sign(&hn(&i["seed"]), &hx(&i["msg"]))?) })
        }
        "ed25519_verify" => {
            let sig: [u8; 64] = hx(&i["sig"]).try_into().map_err(|_| Error::Decrypt)?;
            let pk: [u8; 32] = hx(&i["pk"]).try_into().map_err(|_| Error::Decrypt)?;
            prim::ed25519_verify(&pk, &hx(&i["msg"]), &sig)?;
            json!({})
        }
        "hkdf" => {
            let mut okm = vec![0u8; i["len"].as_u64().unwrap() as usize];
            prim::hkdf_sha256(&hx(&i["salt"]), &hx(&i["ikm"]), &hx(&i["info"]), &mut okm)?;
            json!({ "okm": he(&okm) })
        }
        "hmac" => json!({ "mac": he(&prim::hmac_sha256(&hx(&i["key"]), &hx(&i["msg"]))?) }),
        "argon2id_unchecked" => {
            let mut out = vec![0u8; i["len"].as_u64().unwrap() as usize];
            prim::argon2id_unchecked(
                &hx(&i["password"]),
                &hx(&i["salt"]),
                &hx(&i["secret"]),
                &hx(&i["ad"]),
                kdf_of(i),
                &mut out,
            )?;
            json!({ "tag": he(&out) })
        }
        "hotp" => {
            let algorithm = match i["algorithm"].as_str().unwrap() {
                "SHA1" => TotpAlgorithm::Sha1,
                "SHA256" => TotpAlgorithm::Sha256,
                _ => TotpAlgorithm::Sha512,
            };
            let key = hx(&i["key"]);
            let counter = u64s(&i["counter"]);
            let digits = i["digits"].as_u64().unwrap() as u8;
            json!({
                "hotp": ferret_core::testing::totp::hotp(algorithm, &key, counter, digits)?,
                "digest": he(&ferret_core::testing::totp::hotp_digest(algorithm, &key, counter)?),
            })
        }
        "p256_verify" => {
            use p256::ecdsa::signature::Verifier;
            use p256::ecdsa::{Signature, VerifyingKey};
            let key = VerifyingKey::from_sec1_bytes(&hx(&i["pk"])).map_err(|_| Error::Decrypt)?;
            let sig = Signature::from_der(&hx(&i["sig"])).map_err(|_| Error::Decrypt)?;
            key.verify(&hx(&i["msg"]), &sig)
                .map_err(|_| Error::Decrypt)?;
            json!({})
        }
        "chacha20poly1305_open" => {
            use chacha20poly1305::{AeadInOut, ChaCha20Poly1305, KeyInit};
            let key: [u8; 32] = hx(&i["key"]).try_into().map_err(|_| Error::Decrypt)?;
            let iv: [u8; 12] = hx(&i["iv"]).try_into().map_err(|_| Error::Decrypt)?;
            let mut buf = hx(&i["ct"]);
            buf.extend_from_slice(&hx(&i["tag"]));
            ChaCha20Poly1305::new(&key.into())
                .decrypt_in_place(&iv.into(), &hx(&i["aad"]), &mut buf)
                .map_err(|_| Error::Decrypt)?;
            json!({ "pt": he(&buf) })
        }
        "opaque_rfc_register" => {
            let draws: Vec<Vec<u8>> = i["draws"].as_array().unwrap().iter().map(hx).collect();
            let mut rng = ReplayRng::new(draws);
            let ids = identities(i);
            let reg = ferret_core::testing::opaque::rfc_register(
                &mut rng,
                &hx(&i["password"]),
                &hx(&i["response"]),
                ids.as_ref().map(|(c, s)| (c.as_slice(), s.as_slice())),
            )?;
            json!({
                "request": he(&reg.request),
                "upload": he(&reg.upload),
                "export_key": he(&reg.export_key),
                "server_public_key": he(&reg.server_public_key),
                "rng_left": rng.finish().is_err(),
            })
        }
        "opaque_rfc_login" => {
            let draws: Vec<Vec<u8>> = i["draws"].as_array().unwrap().iter().map(hx).collect();
            let mut rng = ReplayRng::new(draws);
            let ids = identities(i);
            let login = ferret_core::testing::opaque::rfc_login(
                &mut rng,
                &hx(&i["password"]),
                &hx(&i["ke2"]),
                &hx(&i["context"]),
                ids.as_ref().map(|(c, s)| (c.as_slice(), s.as_slice())),
            )?;
            json!({
                "ke1": he(&login.ke1),
                "ke3": he(&login.ke3),
                "export_key": he(&login.export_key),
                "session_key": he(&login.session_key),
                "server_public_key": he(&login.server_public_key),
                "rng_left": rng.finish().is_err(),
            })
        }
        _ => return Err(Error::Unsupported),
    })
}

/// A primitive on behalf of the adapters of the third-party vector files
/// (RFC 9106, 5869, 8032, 6238, 4226, 9807, the XChaCha draft and
/// Wycheproof). `kind` names the primitive; `input_json` holds its arguments
/// as hex. Returns `{ ok: true, ... }` or `{ ok: false, code }`.
#[wasm_bindgen]
pub fn test_external(kind: &str, input_json: &str) -> String {
    let input: Value = serde_json::from_str(input_json).unwrap();
    match external(kind, &input) {
        Ok(mut out) => {
            out["ok"] = json!(true);
            out
        }
        Err(e) => json!({ "ok": false, "code": e.code() }),
    }
    .to_string()
}

// ------------------------------------------------------------ probes

/// Argon2id with `m_kib` KiB and no floor or ceiling, for the out-of-memory
/// test. Returns the code of the error, or `"ok"`.
#[wasm_bindgen]
pub fn test_argon2_unchecked(m_kib: u32) -> String {
    let mut out = [0u8; 32];
    match ferret_core::testing::prim::argon2id_unchecked(
        b"password",
        &[7u8; 16],
        &[],
        &[],
        KdfParams { m_kib, t: 1, p: 1 },
        &mut out,
    ) {
        Ok(()) => "ok".to_owned(),
        Err(e) => e.code().to_owned(),
    }
}

/// Reads `len` bytes of WASM linear memory at `ptr`. For the test that a
/// locked vault's key region is wiped.
#[wasm_bindgen]
#[allow(unsafe_code)]
pub fn test_read_memory(ptr: u32, len: u32) -> Vec<u8> {
    // SAFETY: a test probe. It reads inside the linear memory of this
    // instance, at an address the caller got from `test_vk_region`.
    unsafe { core::slice::from_raw_parts(ptr as usize as *const u8, len as usize).to_vec() }
}

#[wasm_bindgen]
impl Vault {
    /// Address and length of the vault key inside the vault, for
    /// `test_read_memory`.
    pub fn test_vk_region(&self) -> Result<Vec<u32>, JsValue> {
        let v = &self
            .inner
            .as_ref()
            .ok_or_else(|| JsValue::from_str("locked"))?
            .vault;
        let (ptr, len) = v.test_vk_buffer();
        Ok(vec![ptr as usize as u32, len as u32])
    }
}

/// An OPAQUE server for the end-to-end tests of the flows (the client side
/// runs the real production Argon2id profile).
#[wasm_bindgen]
pub struct TestServer {
    server: Server,
    rng: TestRng,
    login: Option<ServerLoginState>,
}

#[wasm_bindgen]
impl TestServer {
    #[wasm_bindgen(constructor)]
    pub fn new(seed: &[u8]) -> TestServer {
        let mut rng = TestRng::new(seed);
        let server = Server::new(&mut rng);
        TestServer {
            server,
            rng,
            login: None,
        }
    }

    pub fn public_key(&self) -> Vec<u8> {
        self.server.public_key().to_vec()
    }

    pub fn register_response(
        &self,
        credential_id: &[u8],
        request: &[u8],
    ) -> Result<Vec<u8>, JsValue> {
        self.server
            .register_response(credential_id, request)
            .map_err(|e| JsValue::from_str(e.code()))
    }

    pub fn login_start(
        &mut self,
        record: Option<Vec<u8>>,
        credential_id: &[u8],
        ke1: &[u8],
    ) -> Result<Vec<u8>, JsValue> {
        let (ke2, state) = self
            .server
            .login_start(&mut self.rng, record.as_deref(), credential_id, ke1)
            .map_err(|e| JsValue::from_str(e.code()))?;
        self.login = Some(state);
        Ok(ke2)
    }

    pub fn login_finish(&mut self, ke3: &[u8]) -> Result<(), JsValue> {
        let state = self
            .login
            .take()
            .ok_or_else(|| JsValue::from_str("no login"))?;
        state
            .finish(ke3)
            .map(drop)
            .map_err(|e| JsValue::from_str(e.code()))
    }
}

/// The size of the linear memory of this instance in bytes: it only grows,
/// so after a run it is the high-water mark of the heap.
#[wasm_bindgen]
pub fn test_memory_bytes() -> f64 {
    #[cfg(target_arch = "wasm32")]
    {
        (core::arch::wasm32::memory_size(0) as f64) * 65_536.0
    }
    #[cfg(not(target_arch = "wasm32"))]
    {
        0.0
    }
}

#[wasm_bindgen]
impl UnlockJob {
    /// The OPAQUE export key the job holds (64 bytes), or nothing.
    pub fn test_export_key(&self) -> Option<Vec<u8>> {
        self.export_key_for_test()
    }
}

#[wasm_bindgen]
impl Vault {
    /// The item key `IK` of a sealed item (32 bytes).
    pub fn test_item_key(
        &self,
        item_id: Vec<u8>,
        rev: f64,
        envelope: Vec<u8>,
        tag: Vec<u8>,
    ) -> Result<Vec<u8>, JsValue> {
        let v = &self
            .inner
            .as_ref()
            .ok_or_else(|| JsValue::from_str("locked"))?
            .vault;
        let id = ItemId::from_bytes(item_id.try_into().unwrap());
        let tag: [u8; 32] = tag.try_into().unwrap();
        ferret_core::testing::item::intermediate(v, id, rev as u64, &envelope, &tag)
            .map(|i| i.ik.to_vec())
            .map_err(|e| JsValue::from_str(e.code()))
    }
}
