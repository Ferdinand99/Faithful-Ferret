//! The `account.*` and `sheet.*` vector operations: the table-driven runner
//! behind `vectors/internal/account.json` and `sheet.json` (see
//! `vectors/OPS.md` for the shape of each op). Behind `test-support`; never
//! part of a release.
//!
//! The flows take a finished OPAQUE registration, so an `account.*` case
//! carries the recorded `record`, `export_key` and `server_public_key` of one
//! (made by the generator with a small Argon2id) and runs no key stretching.

use super::keys::unlocked_vault_keys;
use super::{hex_decode, hex_encode};
use crate::account::{
    ManifestRow, NewAccountIds, NewPassword, RecoveryInput, change_password, create_account,
    recover, verify_recovery_setup, verify_secret_key_entry,
};
use crate::envelope::SealedItem;
use crate::error::Error;
use crate::ids::{AccountId, MethodId, VaultId};
use crate::integrity::{Checkpoint, MutationOp};
use crate::keys::{UnlockedVault, VaultContext};
use crate::ksf_profile::KsfProfile;
use crate::opaque::{PinState, RegistrationFinished};
use crate::pinning::{MethodKey, Pinned};
use crate::rng::SecureRng;
use crate::secret::{ExportKey, SecretKey, VaultKey};
use crate::sheet::{parse_setup_qr, setup_qr_payload};
use crate::text::{MasterPassword, MpPolicy, OpaqueInput};
use crate::wrap::{Method, WrapRecord};
use serde_json::{Value, json};

fn text<'a>(v: &'a Value, key: &str) -> &'a str {
    v[key]
        .as_str()
        .unwrap_or_else(|| panic!("input.{key} is not a string"))
}

fn bytes(v: &Value, key: &str) -> Vec<u8> {
    hex_decode(text(v, key)).unwrap_or_else(|_| panic!("input.{key} is not hex"))
}

fn array<const N: usize>(v: &Value, key: &str) -> [u8; N] {
    bytes(v, key)
        .try_into()
        .unwrap_or_else(|_| panic!("input.{key} is not {N} bytes"))
}

fn number(v: &Value, key: &str) -> u64 {
    text(v, key)
        .parse()
        .unwrap_or_else(|_| panic!("input.{key} is not a decimal string"))
}

fn optional_array<const N: usize>(v: &Value, key: &str) -> Option<[u8; N]> {
    v.get(key)
        .filter(|x| !x.is_null())
        .map(|_| array::<N>(v, key))
}

fn context(v: &Value) -> VaultContext {
    VaultContext {
        account_id: AccountId::from_bytes(array(v, "account_id")),
        vault_id: VaultId::from_bytes(array(v, "vault_id")),
        vk_epoch: number(v, "vk_epoch"),
    }
}

fn vault_of(v: &Value) -> UnlockedVault {
    UnlockedVault::from_vault_key(context(v), VaultKey::from_test_bytes(array(v, "vk")))
        .expect("derive")
}

fn profile(v: &Value, key: &str) -> Result<KsfProfile, Error> {
    KsfProfile::from_wire(v[key].as_u64().expect("a profile number") as u32)
}

fn wrap_record(v: &Value) -> Result<WrapRecord, Error> {
    let method = match text(v, "type") {
        "password" => Method::Password {
            ksf: profile(v, "ksf_profile")?,
        },
        "recovery" => Method::Recovery,
        other => panic!("unknown wrap type {other}"),
    };
    Ok(WrapRecord {
        method_id: MethodId::from_bytes(array(v, "method_id")),
        kek_generation: number(v, "kek_generation"),
        method,
        wrap: bytes(v, "wrap"),
    })
}

fn wrap_json(w: &WrapRecord) -> Value {
    json!({
        "method_id": hex_encode(w.method_id.as_bytes()),
        "kek_generation": w.kek_generation.to_string(),
        "wrap": hex_encode(&w.wrap),
    })
}

fn sealed_json(s: &SealedItem) -> Value {
    json!({
        "rev": s.rev.to_string(),
        "envelope": hex_encode(&s.envelope),
        "tag": hex_encode(&s.tag),
    })
}

fn checkpoint_json(c: &Checkpoint) -> Value {
    json!({
        "seq": c.seq.to_string(),
        "digest": hex_encode(&c.digest),
        "mac": hex_encode(&c.mac),
        "entries": hex_encode(&c.entries),
    })
}

fn registration(v: &Value) -> RegistrationFinished {
    RegistrationFinished {
        record: bytes(v, "record"),
        export_key: ExportKey::from_test_bytes(array(v, "export_key")),
        server_public_key: array(v, "server_public_key"),
    }
}

/// The password input of a case: `password` (text), `policy` (`with_secret_key`,
/// `without_secret_key` or `unlock`) and the secret key that is part of it.
fn opaque_input(v: &Value, key: Option<&SecretKey>) -> Result<OpaqueInput, Error> {
    let pw = text(v, "password").as_bytes();
    let mp = match text(v, "policy") {
        "with_secret_key" => MasterPassword::new(pw, MpPolicy::WithSecretKey)?,
        "without_secret_key" => MasterPassword::new(pw, MpPolicy::WithoutSecretKey)?,
        "unlock" => MasterPassword::for_unlock(pw)?,
        other => panic!("unknown policy {other}"),
    };
    Ok(mp.opaque_input(key))
}

fn pinned(v: &Value, ctx: &VaultContext) -> Pinned {
    let mut floors = Vec::new();
    for (key, name) in [
        (MethodKey::Password, "password_floor"),
        (MethodKey::Recovery, "recovery_floor"),
    ] {
        if v.get(name).is_some_and(|x| !x.is_null()) {
            floors.push((key, number(v, name)));
        }
    }
    Pinned {
        server_url: text(v, "server_url").to_owned(),
        account_id: ctx.account_id,
        vault_id: ctx.vault_id,
        ksf_profile: v["ksf_profile"].as_u64().expect("a profile") as u8,
        kek_generation_max: floors,
        vk_epoch_max: number(v, "vk_epoch_max"),
        sk_bit: v["sk_bit"].as_bool().expect("a bool"),
        pk_a: array(v, "pk_a"),
        server_public_key: optional_array(v, "server_public_key"),
    }
}

fn manifest_row(v: &Value) -> (u64, Vec<u8>, [u8; 32]) {
    (number(v, "rev"), bytes(v, "envelope"), array(v, "tag"))
}

fn sign_input(v: &Value) -> Option<([u8; 32], Vec<u8>)> {
    v.get("sign")
        .filter(|x| !x.is_null())
        .map(|s| (array(s, "nonce"), bytes(s, "body")))
}

/// Runs one op of `account.json` or `sheet.json`.
pub fn run_case<R: SecureRng>(op: &str, i: &Value, rng: &mut R) -> Result<Value, Error> {
    match op {
        "account.create" => {
            let ids = NewAccountIds {
                account_id: AccountId::from_bytes(array(i, "account_id")),
                vault_id: VaultId::from_bytes(array(i, "vault_id")),
                password_method_id: MethodId::from_bytes(array(i, "password_method_id")),
                recovery_method_id: MethodId::from_bytes(array(i, "recovery_method_id")),
            };
            // The key in the OPAQUE input, and the key handed to the flow.
            let in_input =
                optional_array::<16>(i, "input_secret_key").map(SecretKey::from_test_bytes);
            let given = optional_array::<16>(i, "secret_key").map(SecretKey::from_test_bytes);
            let input = opaque_input(i, in_input.as_ref())?;
            let account = create_account(
                rng,
                &ids,
                NewPassword {
                    input: &input,
                    registration: registration(&i["registration"]),
                    profile: profile(i, "ksf_profile")?,
                },
                given,
            )?;
            let keys = unlocked_vault_keys(&account.vault);
            Ok(json!({
                "vk": hex_encode(&keys[0]),
                "rk": hex_encode(&super::integrity::recovery_key_bytes(&account.recovery_key)),
                "pk_a": hex_encode(&account.pk_a),
                "pk_r": hex_encode(&account.pk_r),
                "wraps": account.wraps.iter().map(wrap_json).collect::<Vec<_>>(),
                "manifest": sealed_json(&account.manifest),
                "checkpoint": checkpoint_json(&account.checkpoint),
                "registration_record": hex_encode(&account.registration_record),
                "server_public_key": hex_encode(&account.server_public_key),
            }))
        }
        "account.change_password" => {
            let vault = vault_of(i);
            let key = optional_array::<16>(i, "input_secret_key").map(SecretKey::from_test_bytes);
            let input = opaque_input(i, key.as_ref())?;
            let current = wrap_record(&i["current"])?;
            let (rev, envelope, tag) = manifest_row(&i["manifest"]);
            let pinned = pinned(&i["pinned"], vault.context());
            let change = change_password(
                rng,
                &vault,
                NewPassword {
                    input: &input,
                    registration: registration(&i["registration"]),
                    profile: profile(i, "ksf_profile")?,
                },
                &pinned,
                &current,
                &ManifestRow {
                    rev,
                    envelope: &envelope,
                    tag: &tag,
                },
            )?;
            let mut out = json!({
                "wrap": wrap_json(&change.wrap),
                "manifest": sealed_json(&change.manifest),
                "registration_record": hex_encode(&change.registration_record),
                "server_public_key": hex_encode(&change.server_public_key),
                "ksf_profile": change.ksf_profile.number(),
            });
            if let Some((nonce, body)) = sign_input(i) {
                out["proof"] = json!(hex_encode(&change.sign(&vault, &nonce, &body)?));
                out["proof_op"] = json!(MutationOp::UnlockMethodPasswordPut.name());
            }
            Ok(out)
        }
        "account.recover" => {
            let ctx = context(i);
            let key = optional_array::<16>(i, "input_secret_key").map(SecretKey::from_test_bytes);
            let input = opaque_input(i, key.as_ref())?;
            let rk_wrap = wrap_record(&i["rk_wrap"])?;
            let (rev, envelope, tag) = manifest_row(&i["manifest"]);
            let pin_record = i
                .get("pinned")
                .filter(|p| !p.is_null())
                .map(|p| pinned(p, &ctx));
            let pin = pin_record
                .as_ref()
                .map_or(PinState::FirstUse, PinState::Pinned);
            let recovered = recover(
                rng,
                &RecoveryInput {
                    ctx: &ctx,
                    rk_code: text(i, "rk_code"),
                    rk_wrap: &rk_wrap,
                    manifest: ManifestRow {
                        rev,
                        envelope: &envelope,
                        tag: &tag,
                    },
                    new_recovery_method_id: MethodId::from_bytes(array(
                        i,
                        "new_recovery_method_id",
                    )),
                },
                NewPassword {
                    input: &input,
                    registration: registration(&i["registration"]),
                    profile: profile(i, "ksf_profile")?,
                },
                pin,
            )?;
            let mut out = json!({
                "vk": hex_encode(&vault_key_bytes_of(&recovered.vault)),
                "recovery_key": hex_encode(&super::integrity::recovery_key_bytes(&recovered.recovery_key)),
                "pk_r": hex_encode(&recovered.pk_r),
                "password_wrap": wrap_json(&recovered.password_wrap),
                "recovery_wrap": wrap_json(&recovered.recovery_wrap),
                "manifest": sealed_json(&recovered.manifest),
                "registration_record": hex_encode(&recovered.registration_record),
                "server_public_key": hex_encode(&recovered.server_public_key),
                "sk_bit": recovered.sk_bit,
            });
            if let Some((nonce, body)) = sign_input(i) {
                out["proof"] = json!(hex_encode(&recovered.sign(&nonce, &body)?));
                out["proof_op"] = json!(MutationOp::Recover.name());
            }
            Ok(out)
        }
        "account.verify_recovery" => {
            let vault = vault_of(i);
            let rk_wrap = wrap_record(&i["rk_wrap"])?;
            verify_recovery_setup(text(i, "entered"), &rk_wrap, &vault)?;
            Ok(json!({ "ok": true }))
        }
        "account.verify_secret_key" => {
            let expected = SecretKey::from_test_bytes(array(i, "secret_key"));
            verify_secret_key_entry(text(i, "entered"), &expected)?;
            Ok(json!({ "ok": true }))
        }
        "sheet.qr.build" => {
            let payload = setup_qr_payload(
                text(i, "server_url"),
                &AccountId::from_bytes(array(i, "account_id")),
                profile(i, "ksf_profile")?,
                i["sk_bit"].as_bool().expect("a bool"),
                &array(i, "server_public_key"),
            )?;
            Ok(json!({ "payload": payload }))
        }
        "sheet.qr.parse" => {
            let qr = parse_setup_qr(text(i, "payload"))?;
            Ok(json!({
                "server_url": qr.server_url,
                "account_id": hex_encode(qr.account_id.as_bytes()),
                "ksf_profile": qr.ksf_profile.number(),
                "sk_bit": qr.sk_bit,
                "server_public_key": hex_encode(&qr.server_public_key),
            }))
        }
        other => panic!("unknown op {other}"),
    }
}

fn vault_key_bytes_of(vault: &UnlockedVault) -> [u8; 32] {
    unlocked_vault_keys(vault)[0]
}
