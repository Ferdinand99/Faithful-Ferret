//! `ferret-core-wasm`: the WebAssembly binding of the Ferret crypto core, made
//! for a **long-lived crypto worker**.
//!
//! The vault key, the key encryption keys, the item keys, the private keys of
//! passkeys and every decrypted item stay in WASM memory. JavaScript holds
//! pointers (a `Vault`, an `UnlockJob`) and numbers (item handles) and gets
//! redacted views, one secret at a time on request, and the public values of
//! requests (wraps, envelopes, tags, signatures).
//!
//! * [`vault`](crate::vault) and the files that extend it (`item`, `export`,
//!   `passkey`): everything an unlocked vault does.
//! * `job`: sign-in, registration and the account flows. They run in the same
//!   worker as the vault and return a `Vault` object.
//! * `export::argon2_export_key`: the one call of the short-lived job worker.
//! * The functions in this file need no state.
//!
//! Failures are JavaScript `Error`s whose `message` and `code` are a stable
//! code and nothing else (see `error`). There is no panic hook: a panic
//! aborts the instance (`panic = "abort"`), and nothing is written.

#![deny(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::arithmetic_side_effects
)]

mod convert;
mod error;
mod export;
mod item;
mod job;
mod methods;
mod passkey;
mod vault;

#[cfg(feature = "test-support")]
mod vector_ops;

pub use export::{argon2_export_key, import_header};
pub use job::UnlockJob;
pub use vault::Vault;

use crate::convert::{ByteBuf, arr, b16, b32, bytes, from_js_list, to_js};
use crate::error::{Fail, run};
use crate::item::normalize_otpauth;
use ferret_core::{
    AccountId, ItemId, KsfProfile, MasterPassword, MpPolicy, OsRng, SyncMemory,
    decode_recovery_key, decode_secret_key, parse_otpauth, parse_server_address, parse_setup_qr,
    setup_qr_payload,
};
use serde::Serialize;
use wasm_bindgen::prelude::*;
use zeroize::Zeroizing;

/// The pieces of a server address that the user is asked to confirm when a
/// new device scans the QR code of the emergency sheet. The QR check in the
/// core is about the form of the address only.
#[derive(Serialize)]
struct QrDto {
    server_url: String,
    scheme: String,
    /// The host a browser connects to, in lower case (the core refuses an
    /// address in which it could differ from what is written: `user@`, a
    /// backslash, a `%` escape). An IPv6 literal keeps its brackets.
    host: String,
    /// The port, when the address has one.
    port: Option<u16>,
    #[serde(with = "b16")]
    account_id: [u8; 16],
    ksf_profile: u8,
    sk_bit: bool,
    /// The `o` value: the OPAQUE server key to compare, inside `recover`.
    #[serde(with = "b32")]
    server_public_key: [u8; 32],
}

/// The AAGUID that Ferret writes into every passkey it makes (16 bytes,
/// `dc704a44-b994-410c-a689-ed8d71a84ac3`). It is public. A client that
/// registers a passkey as an unlock method passes the AAGUID of that
/// registration to `Vault.wrap_prf`, which refuses Ferret's own: such a
/// passkey's PRF seeds are inside the vault it would have to open.
/// `FERRET_AAGUID` in the client is the same value.
#[wasm_bindgen]
pub fn ferret_aaguid() -> Vec<u8> {
    ferret_core::passkey::AAGUID.to_vec()
}

/// A fresh PRF salt for one passkey registration: 32 random bytes. It is
/// public and is stored with the wrap; every registration needs its own. Pass
/// it as the salt of the PRF evaluation and then as `prf_salt` to `wrap_prf`,
/// which refuses an all-zero salt (`input_all_zero`), as does the unlock.
#[wasm_bindgen]
pub fn prf_salt_new() -> Vec<u8> {
    ferret_core::prf_salt_new(&mut OsRng).to_vec()
}

/// An empty rollback memory (`SyncMemory`) as bytes, for a device that has
/// seen nothing of this vault yet. The client stores the bytes, hands them to
/// `verify_checkpoint` and `rekey` (which return the updated bytes) and
/// replaces its copy each time. The record holds item ids and revision
/// numbers only; it is public data.
#[wasm_bindgen]
pub fn sync_memory_new() -> Vec<u8> {
    SyncMemory::new().to_bytes()
}

/// What `sync_memory_prune` returns.
#[derive(Serialize)]
struct PrunedDto {
    #[serde(with = "bytes")]
    sync_memory: Vec<u8>,
    dropped: usize,
}

/// Drops the entries of items that are gone for good (their tombstones have
/// expired on the server, or the user purged them) from the stored rollback
/// memory, so that a full record can take new items. `ids` is a list of
/// 16-byte item ids; ids that are not tracked are ignored. The floor of a
/// dropped id is gone: a row for it with any revision is accepted again, so
/// call it only for items that no longer exist. Nothing calls it on its own.
/// Returns `{ sync_memory, dropped }`.
#[wasm_bindgen]
pub fn sync_memory_prune(sync_memory: Vec<u8>, ids: JsValue) -> Result<JsValue, JsValue> {
    run(|| {
        let mut memory = SyncMemory::from_bytes(&sync_memory)?;
        let ids: Vec<ByteBuf> = from_js_list(ids)?;
        let ids = ids
            .iter()
            .map(|b| arr::<16>(&b.0).map(ItemId::from_bytes))
            .collect::<Result<Vec<_>, _>>()?;
        let dropped = memory.prune(&ids);
        to_js(&PrunedDto {
            sync_memory: memory.to_bytes(),
            dropped,
        })
    })
}

/// The payload of the QR code of the emergency sheet
/// (`ferret-setup:v1?u=...&a=...&k=...&s=...&o=...`).
#[wasm_bindgen]
pub fn setup_qr_build(
    server_url: &str,
    account_id: Vec<u8>,
    ksf_profile: u32,
    sk_bit: bool,
    server_public_key: Vec<u8>,
) -> Result<String, JsValue> {
    run(|| {
        Ok(setup_qr_payload(
            server_url,
            &AccountId::from_bytes(arr(&account_id)?),
            KsfProfile::from_wire(ksf_profile)?,
            sk_bit,
            &arr::<32>(&server_public_key)?,
        )?)
    })
}

/// Reads the text of a scanned QR code. Returns `{ server_url, scheme, host,
/// port, account_id, ksf_profile, sk_bit, server_public_key }`. Show `host`
/// (and `port`) to the user and ask them to confirm it before the device
/// talks to it; pass the whole text to `UnlockJob.recover` on a new device,
/// which compares the address, the account and the server key with it.
#[wasm_bindgen]
pub fn setup_qr_parse(payload: &str) -> Result<JsValue, JsValue> {
    run(|| {
        let qr = parse_setup_qr(payload)?;
        let address = parse_server_address(&qr.server_url)?;
        to_js(&QrDto {
            scheme: if address.https { "https" } else { "http" }.to_owned(),
            host: address.host,
            port: address.port,
            server_url: qr.server_url.clone(),
            account_id: *qr.account_id.as_bytes(),
            ksf_profile: qr.ksf_profile.number(),
            sk_bit: qr.sk_bit,
            server_public_key: qr.server_public_key,
        })
    })
}

/// Checks a master password against the creation floor without keeping it:
/// `policy` is `"with_secret_key"` (12 characters) or `"without_secret_key"`
/// (15). A password that is not valid text is `input_not_utf8`, one with a
/// forbidden character `input_forbidden_character`, a short one
/// `input_too_short`, a long one `input_too_long`. The text is wiped.
#[wasm_bindgen]
pub fn check_master_password(utf8: Vec<u8>, policy: &str) -> Result<(), JsValue> {
    run(|| {
        let utf8 = Zeroizing::new(utf8);
        let policy = match policy {
            "with_secret_key" => MpPolicy::WithSecretKey,
            "without_secret_key" => MpPolicy::WithoutSecretKey,
            _ => return Err(Fail::Input),
        };
        MasterPassword::new(&utf8, policy)?;
        Ok(())
    })
}

/// Checks the text of a recovery key (`FFR1-...`) or a secret key
/// (`FFS1-...`) as the user typed it, without keeping it: a typo is
/// `checksum`, a wrong prefix or letter `malformed_code`.
#[wasm_bindgen]
pub fn check_code(kind: &str, code: String) -> Result<(), JsValue> {
    run(|| {
        let code = Zeroizing::new(code);
        match kind {
            "recovery_key" => decode_recovery_key(&code).map(drop)?,
            "secret_key" => decode_secret_key(&code).map(drop)?,
            _ => return Err(Fail::Input),
        }
        Ok(())
    })
}

#[derive(Serialize)]
struct TotpInfoDto {
    algorithm: &'static str,
    digits: u8,
    period: u32,
    issuer: Option<String>,
    label: String,
}

/// Reads an `otpauth://` address the user pasted or scanned, so that the
/// interface can show what it is before it is saved: `{ algorithm, digits,
/// period, issuer, label }`, never the secret. The address is trimmed, the
/// algorithm name may be in any case and the issuer is trimmed; everything
/// else is the strict parser's (a failure is `malformed_otpauth` or
/// `too_large`).
#[wasm_bindgen]
pub fn totp_parse(uri: String) -> Result<JsValue, JsValue> {
    run(|| {
        let uri = Zeroizing::new(uri);
        let normalized = Zeroizing::new(normalize_otpauth(&uri)?);
        let p = parse_otpauth(&normalized)?;
        to_js(&TotpInfoDto {
            algorithm: p.algorithm().name(),
            digits: p.digits(),
            period: p.period(),
            issuer: p.issuer().map(|s| s.trim().to_owned()),
            label: p.label().to_owned(),
        })
    })
}
