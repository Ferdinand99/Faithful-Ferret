//! Helpers shared by the key hierarchy tests.
#![allow(dead_code)]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]

use ferret_core::testing::{hex_decode, hex_encode};
use ferret_core::{AccountId, KsfProfile, Method, MethodId, VaultContext, VaultId, VaultKey};
use serde_json::Value;
use std::path::{Path, PathBuf};

pub fn vectors_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../vectors")
}

pub fn hex(v: &Value) -> Vec<u8> {
    hex_decode(v.as_str().unwrap()).unwrap()
}

pub fn hexn<const N: usize>(v: &Value) -> [u8; N] {
    hex(v).try_into().unwrap()
}

pub fn he(bytes: &[u8]) -> String {
    hex_encode(bytes)
}

pub fn u64s(v: &Value) -> u64 {
    v.as_str().unwrap().parse().unwrap()
}

pub fn account(b: u8) -> AccountId {
    AccountId::from_bytes([b; 16])
}

pub fn vault(b: u8) -> VaultId {
    VaultId::from_bytes([b; 16])
}

pub fn method_id(b: u8) -> MethodId {
    MethodId::from_bytes([b; 16])
}

pub fn ctx() -> VaultContext {
    VaultContext {
        account_id: account(0x11),
        vault_id: vault(0x22),
        vk_epoch: 1,
    }
}

pub fn vk(b: u8) -> VaultKey {
    VaultKey::from_test_bytes([b; 32])
}

/// `tag ‖ len(u16be) ‖ value`, written out by hand with literal tag numbers
/// so that the expected bytes in the tests do not depend on the core's
/// builder or its tag constants.
pub fn t(tag: u8, value: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    out.extend_from_slice(&u16::try_from(value.len()).unwrap().to_be_bytes());
    out.extend_from_slice(value);
    out
}

pub fn label(s: &str) -> Vec<u8> {
    t(0x01, s.as_bytes())
}

/// Splits a TLV string into its `(tag, value)` fields.
pub fn parse_tlv(mut bytes: &[u8]) -> Vec<(u8, Vec<u8>)> {
    let mut out = Vec::new();
    while !bytes.is_empty() {
        let tag = bytes[0];
        let len = usize::from(u16::from_be_bytes([bytes[1], bytes[2]]));
        out.push((tag, bytes[3..3 + len].to_vec()));
        bytes = &bytes[3 + len..];
    }
    out
}

pub fn password_method() -> Method {
    Method::Password {
        ksf: KsfProfile::P1,
    }
}

pub fn prf_method() -> Method {
    Method::Prf {
        credential_id: (0u8..16).map(|i| 0xa0 + i).collect(),
        prf_salt: [0xb0; 32],
    }
}

pub fn pin_method() -> Method {
    Method::Pin {
        device_salt: [0xc0; 16],
    }
}

/// All five methods, in the order of `method_type`.
pub fn all_methods() -> Vec<Method> {
    vec![
        password_method(),
        Method::Recovery,
        prf_method(),
        pin_method(),
        Method::Device,
    ]
}

/// Concatenates the `segments` of a vector input `{ "segments": [...] }`:
/// each `hex` repeated `repeat` times.
pub fn segments(input: &Value) -> Vec<u8> {
    let mut out = Vec::new();
    for seg in input["segments"].as_array().unwrap() {
        if let Some(keys) = seg.get("keys") {
            // `count` map entries: the five-digit counter as a CBOR text,
            // then `value_hex`.
            let value =
                ferret_core::testing::hex_decode(keys["value_hex"].as_str().unwrap()).unwrap();
            for i in 0..keys["count"].as_u64().unwrap() {
                out.push(0x65);
                out.extend_from_slice(format!("{i:05}").as_bytes());
                out.extend_from_slice(&value);
            }
            continue;
        }
        let unit = ferret_core::testing::hex_decode(seg["hex"].as_str().unwrap()).unwrap();
        for _ in 0..seg["repeat"].as_u64().unwrap() {
            out.extend_from_slice(&unit);
        }
    }
    out
}

/// An unlocked vault with the vault key `[b; 32]` in the context `ctx()`.
pub fn unlocked(b: u8) -> ferret_core::UnlockedVault {
    ferret_core::UnlockedVault::from_vault_key(ctx(), vk(b)).unwrap()
}
