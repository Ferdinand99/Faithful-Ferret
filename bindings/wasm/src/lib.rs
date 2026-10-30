//! `ferret-core-wasm`: the WebAssembly binding of the Ferret crypto core, made
//! for a **long-lived crypto worker** (plan Task 12, U2, U15).
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
mod passkey;
mod vault;

#[cfg(feature = "test-support")]
mod vector_ops;

pub use export::{argon2_export_key, import_header};
pub use job::UnlockJob;
pub use vault::Vault;

use crate::convert::{arr, b16, b32, to_js};
use crate::error::{Fail, run};
use crate::item::normalize_otpauth;
use ferret_core::{
    AccountId, KsfProfile, MasterPassword, MpPolicy, decode_recovery_key, decode_secret_key,
    parse_otpauth, parse_setup_qr, setup_qr_payload,
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
    /// The host and port the address really points at: after any `user@`.
    host: String,
    /// Whether the address has a `user@` part, which can hide the real host
    /// (`https://good.example@evil.example`).
    has_userinfo: bool,
    #[serde(with = "b16")]
    account_id: [u8; 16],
    ksf_profile: u8,
    sk_bit: bool,
    /// The `o` value: the OPAQUE server key to compare, inside `recover`.
    #[serde(with = "b32")]
    server_public_key: [u8; 32],
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
/// has_userinfo, account_id, ksf_profile, sk_bit, server_public_key }`. Show
/// `host` to the user and ask them to confirm it before the device talks to
/// it; pass `server_public_key` to `UnlockJob.recover`.
#[wasm_bindgen]
pub fn setup_qr_parse(payload: &str) -> Result<JsValue, JsValue> {
    run(|| {
        let qr = parse_setup_qr(payload)?;
        let (scheme, rest) = qr.server_url.split_once("://").ok_or(Fail::Input)?;
        let end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
        let authority = rest.get(..end).ok_or(Fail::Input)?;
        let (has_userinfo, host) = match authority.rsplit_once('@') {
            Some((_, host)) => (true, host),
            None => (false, authority),
        };
        to_js(&QrDto {
            scheme: scheme.to_owned(),
            host: host.to_owned(),
            has_userinfo,
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
