//! Sign-in, registration and the account flows.
//!
//! `UnlockJob` holds the state of the multi-step OPAQUE protocol and the
//! flows built on it. It lives in the **vault worker**, the same long-lived
//! worker as the `Vault`. Argon2id of the login,
//! the registration, the PIN and the recovery runs here, and what comes out
//! is a `Vault` object in WASM memory: the vault key and the key encryption
//! keys never cross into JavaScript.
//!
//! # The pin state is always stated
//!
//! Every unlock and every flow that talks to a server takes a pin state, an
//! object that is either `{ kind: "first_use", sk_bit }` (a device that has
//! never unlocked this account: trust on first use) or `{ kind: "pinned",
//! record }`. There is no default and no way to leave it out: a missing or
//! malformed one is `invalid_input`. The core then checks the SK bit, the
//! KSF profile, the OPAQUE server key, the generation floors and the epoch.
//! Every unlock and flow that changes the record returns the **new record**
//! (`pinned`) for the client to store, so the next unlock already checks
//! against it.
//!
//! # The flows
//!
//! | Flow | Calls |
//! |---|---|
//! | sign in | `login_start`, `login_finish`, `unlock_password` |
//! | new account | `register_start`, `register_finish`, `create_account` |
//! | change password, KSF upgrade | `register_start`, `register_finish`, `Vault.seed_pinned`, `change_password` |
//! | recovery on a device with a record | `register_start`, `register_finish`, `recover` (pin state `pinned`) |
//! | recovery on a new device | `register_start`, `register_finish`, `recover` (pin state `first_use`, with the `o` value of the scanned emergency sheet QR) |
//! | recovery key unlock | `unlock_recovery` |
//! | passkey unlock | `unlock_prf` |
//! | PIN unlock | `pin_unlock` |
//! | full rekey | `login_start`, `login_finish`, `rekey`, `Vault.auth_sign("rekey")`, `Vault.rekey_commit` |
//! | plaintext export | `login_start`, `login_finish`, `reauth_grant`, `Vault.reveal_plain_export` |
//!
//! The core's `ferret_core::change_password` is the KSF upgrade as well: the
//! same password with a higher profile.
//!
//! There is no single call for "change the master password and rotate the
//! keys". A client does it in two flows, in this order: first the password
//! change above, then, once the server has accepted it, a fresh sign-in with
//! the new password and the full rekey. The rekey wraps the new vault key
//! under the key of that new sign-in, so the order cannot be reversed without
//! the rekey being made under the old password.

use crate::convert::{
    ANY, CheckpointDto, CtxDto, IdsDto, Pin, PinArg, PinnedDto, RowDto, SealedDto, Shape, Shaped,
    WrapDto, b16, b32, bytes, core, from_js, to_js,
};
use crate::error::{Fail, Res, run};
use crate::vault::{PendingRekey, ReauthGrant, Setup, Vault};
use ferret_core::{
    Error, ExportKey, Kek, KekDevPin, KsfProfile, LoginState, MasterPassword, Method, MethodId,
    MpPolicy, NewAccountIds, NewPassword, OpaqueInput, OsRng, Pin as PinDigits, Pinned,
    PinnedField, PrfOutput, Recovered, RecoveryInput, RecoveryKey, RegistrationFinished,
    RegistrationState, RekeyInput, RekeyItem, RekeyTombstone, SecretKey, ServerView, SetupQr,
    UnlockedVault, VaultContext, change_password, create_account, decode_recovery_key,
    decode_secret_key, encode_recovery_key, encode_secret_key, opaque_login_finish,
    opaque_login_start, opaque_register_finish, opaque_register_start, parse_setup_qr, recover,
    unwrap_vk,
};
use js_sys::{Object, Reflect};
use serde::{Deserialize, Serialize};
use wasm_bindgen::prelude::*;
use zeroize::Zeroizing;

/// How the account's secret key enters a registration.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SecretKeyArg {
    /// `"generate"` (a new account with a secret key), `"code"` (the
    /// account's own, `FFS1-...`) or `"none"`.
    kind: String,
    #[serde(default)]
    code: Option<String>,
}

#[derive(Serialize)]
struct LoginFinishedDto {
    #[serde(with = "bytes")]
    ke3: Vec<u8>,
    #[serde(with = "b32")]
    server_public_key: [u8; 32],
}

#[derive(Serialize)]
struct RegistrationDto {
    #[serde(with = "bytes")]
    record: Vec<u8>,
    #[serde(with = "b32")]
    server_public_key: [u8; 32],
    ksf_profile: u8,
}

#[derive(Serialize)]
struct NewAccountDto {
    wraps: Vec<WrapDto>,
    manifest: SealedDto,
    checkpoint: CheckpointDto,
    #[serde(with = "b32")]
    pk_a: [u8; 32],
    #[serde(with = "b32")]
    pk_r: [u8; 32],
    #[serde(with = "bytes")]
    registration_record: Vec<u8>,
    ksf_profile: u8,
    #[serde(with = "b32")]
    server_public_key: [u8; 32],
    pinned: PinnedDto,
}

#[derive(Serialize)]
struct ChangedDto {
    wrap: WrapDto,
    manifest: SealedDto,
    #[serde(with = "bytes")]
    registration_record: Vec<u8>,
    ksf_profile: u8,
    #[serde(with = "b32")]
    server_public_key: [u8; 32],
    pinned: PinnedDto,
}

#[derive(Serialize)]
struct RecoveredDto {
    password_wrap: WrapDto,
    recovery_wrap: WrapDto,
    manifest: SealedDto,
    #[serde(with = "b32")]
    pk_r: [u8; 32],
    #[serde(with = "bytes")]
    registration_record: Vec<u8>,
    ksf_profile: u8,
    #[serde(with = "b32")]
    server_public_key: [u8; 32],
    sk_bit: bool,
    pinned: PinnedDto,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RekeyItemDto {
    #[serde(with = "b16")]
    item_id: [u8; 16],
    rev: u64,
    #[serde(with = "bytes")]
    envelope: Vec<u8>,
    #[serde(with = "b32")]
    tag: [u8; 32],
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RekeyTombDto {
    #[serde(with = "b16")]
    item_id: [u8; 16],
    rev: u64,
    #[serde(with = "bytes")]
    tomb: Vec<u8>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RekeyInputDto {
    base_seq: u64,
    old_checkpoint: CheckpointDto,
    old_manifest: RowDto,
    items: Vec<RekeyItemDto>,
    tombstones: Vec<RekeyTombDto>,
    #[serde(with = "b16")]
    password_method_id: [u8; 16],
    #[serde(with = "b16")]
    recovery_method_id: [u8; 16],
}

#[derive(Serialize)]
struct RekeyedItemDto {
    #[serde(with = "b16")]
    item_id: [u8; 16],
    rev: u64,
    #[serde(with = "bytes")]
    envelope: Vec<u8>,
    #[serde(with = "b32")]
    tag: [u8; 32],
}

#[derive(Serialize)]
struct RekeyedTombDto {
    #[serde(with = "b16")]
    item_id: [u8; 16],
    rev: u64,
    #[serde(with = "bytes")]
    tomb: Vec<u8>,
}

#[derive(Serialize)]
struct RekeyBundleDto {
    vk_epoch: u64,
    base_seq: u64,
    #[serde(with = "b32")]
    pk_a: [u8; 32],
    #[serde(with = "b32")]
    pk_r: [u8; 32],
    items: Vec<RekeyedItemDto>,
    tombstones: Vec<RekeyedTombDto>,
    wraps: Vec<WrapDto>,
    manifest: SealedDto,
    checkpoint: CheckpointDto,
    pinned: PinnedDto,
}

/// The export key and server key of a login that has been finished, kept in
/// WASM for the step after it.
struct LoginDone {
    export_key: ExportKey,
    server_public_key: [u8; 32],
    profile: KsfProfile,
}

/// A finished registration, kept for the flow that uses it.
struct Registered {
    finished: RegistrationFinished,
    profile: KsfProfile,
}

/// The state of the sign-in, registration and account flows. See the module
/// documentation.
#[wasm_bindgen]
pub struct UnlockJob {
    input: Option<OpaqueInput>,
    secret_key: Option<SecretKey>,
    login: Option<LoginState>,
    registration: Option<RegistrationState>,
    login_done: Option<LoginDone>,
    registered: Option<Registered>,
    recovered: Option<Recovered>,
}

impl Default for UnlockJob {
    fn default() -> Self {
        Self::new()
    }
}

/// A second copy of a secret key, through its code.
fn copy_secret_key(sk: &SecretKey) -> Res<SecretKey> {
    core(decode_secret_key(&encode_secret_key(sk)))
}

/// A recovery key as a new value, through its code.
fn copy_recovery_key(rk: &RecoveryKey) -> Res<RecoveryKey> {
    core(decode_recovery_key(&encode_recovery_key(rk)))
}

fn account_ids(ids: &IdsDto) -> NewAccountIds {
    NewAccountIds {
        account_id: ferret_core::AccountId::from_bytes(ids.account_id),
        vault_id: ferret_core::VaultId::from_bytes(ids.vault_id),
        password_method_id: MethodId::from_bytes(ids.password_method_id),
        recovery_method_id: MethodId::from_bytes(ids.recovery_method_id),
    }
}

/// `{ vault, pinned }`.
fn outcome(vault: Vault, pinned: &Pinned) -> Res<JsValue> {
    let obj = Object::new();
    let set = |key: &str, value: JsValue| {
        Reflect::set(&obj, &JsValue::from_str(key), &value)
            .map(drop)
            .map_err(|_| Fail::Input)
    };
    set("vault", JsValue::from(vault))?;
    set("pinned", to_js(&PinnedDto::of(pinned))?)?;
    Ok(obj.into())
}

/// `{ vault, ...rest }` where `rest` is an object.
fn outcome_with(vault: Vault, rest: JsValue) -> Res<JsValue> {
    Reflect::set(&rest, &JsValue::from_str("vault"), &JsValue::from(vault))
        .map_err(|_| Fail::Input)?;
    Ok(rest)
}

/// Opens a server-side wrap with `kek` under the pin state.
///
/// * `first_use`: [`Pinned::first_unlock`] makes the record and the vault.
/// * `pinned`: [`Pinned::unlock_server`] checks every pin first.
fn unlock_server(
    pin: Pin,
    server_url: &str,
    sk_bit_of_input: Option<bool>,
    login_key: Option<[u8; 32]>,
    ctx: &ferret_core::VaultContext,
    rec: &ferret_core::WrapRecord,
    kek: &Kek,
) -> Res<(Pinned, UnlockedVault)> {
    match pin {
        Pin::FirstUse {
            sk_bit,
            server_public_key,
        } => {
            // The answer of the user; a password login knows it from its own
            // input.
            let sk_bit = sk_bit_of_input.or(sk_bit).ok_or(Fail::Input)?;
            core(Pinned::first_unlock(
                server_url,
                sk_bit,
                login_key.or(server_public_key),
                ctx,
                rec,
                kek,
            ))
        }
        Pin::Pinned {
            record,
            server_public_key,
        } => {
            let mut record = *record;
            let seen = ServerView {
                server_url,
                context: *ctx,
                sk_bit: sk_bit_of_input.unwrap_or(record.sk_bit),
                server_public_key: login_key.or(server_public_key),
            };
            let vault = core(record.unlock_server(&seen, rec, kek))?;
            Ok((record, vault))
        }
    }
}

/// What the scanned emergency sheet states, against what the caller states:
/// the account (`ctx`) and the address. Both are `pinned_*` hard errors.
fn check_qr(qr: &SetupQr, ctx: &VaultContext, server_url: &str) -> Res<()> {
    if qr.account_id != ctx.account_id {
        return Err(Error::Pinned(PinnedField::AccountId).into());
    }
    if qr.server_url != server_url {
        return Err(Error::Pinned(PinnedField::ServerUrl).into());
    }
    Ok(())
}

/// Binds an unlock without the password to the scanned sheet.
///
/// * `first_use` (a new device) needs the sheet: its account and address are
///   compared with the call, its secret key bit with the one the caller
///   answered, its server key with the one the caller has seen (if any), and
///   what the record then pins is the sheet's key and bit.
/// * `pinned` may bring the sheet too; then the same account and address
///   checks are made, and its key must be the record's.
fn bind_to_qr(pin: Pin, qr: Option<String>, ctx: &VaultContext, server_url: &str) -> Res<Pin> {
    let qr = qr.map(|t| parse_setup_qr(&t)).transpose()?;
    match (pin, qr) {
        (Pin::FirstUse { .. }, None) => Err(Fail::Input),
        (
            Pin::FirstUse {
                sk_bit,
                server_public_key,
            },
            Some(qr),
        ) => {
            check_qr(&qr, ctx, server_url)?;
            if sk_bit.is_some_and(|b| b != qr.sk_bit) {
                return Err(Error::Pinned(PinnedField::SkBit).into());
            }
            if server_public_key.is_some_and(|k| k != qr.server_public_key) {
                return Err(Error::Pinned(PinnedField::ServerKey).into());
            }
            Ok(Pin::FirstUse {
                sk_bit: Some(qr.sk_bit),
                server_public_key: Some(qr.server_public_key),
            })
        }
        (
            Pin::Pinned {
                record,
                server_public_key,
            },
            Some(qr),
        ) => {
            check_qr(&qr, ctx, server_url)?;
            if record
                .server_public_key
                .is_some_and(|k| k != qr.server_public_key)
            {
                return Err(Error::Pinned(PinnedField::ServerKey).into());
            }
            Ok(Pin::Pinned {
                record,
                server_public_key,
            })
        }
        (pin, None) => Ok(pin),
    }
}

#[wasm_bindgen]
impl UnlockJob {
    /// An empty job.
    #[wasm_bindgen(constructor)]
    pub fn new() -> UnlockJob {
        UnlockJob {
            input: None,
            secret_key: None,
            login: None,
            registration: None,
            login_done: None,
            registered: None,
            recovered: None,
        }
    }

    // ---------------------------------------------------------- sign in

    /// Sign-in, step 1: `mp_utf8` is the master password as typed (any
    /// length that was valid when it was set), `sk_code` the secret key
    /// (`FFS1-...`) when the account has one. Returns `KE1` (96 bytes). The
    /// password is normalized here and wiped after use.
    pub fn login_start(
        &mut self,
        mp_utf8: Vec<u8>,
        sk_code: Option<String>,
    ) -> Result<Vec<u8>, JsValue> {
        run(|| {
            let mp_utf8 = Zeroizing::new(mp_utf8);
            let sk_code = sk_code.map(Zeroizing::new);
            let mp = MasterPassword::for_unlock(&mp_utf8)?;
            let sk = sk_code
                .as_deref()
                .map(|c| decode_secret_key(c))
                .transpose()?;
            let input = mp.opaque_input(sk.as_ref());
            let (ke1, state) = opaque_login_start(&mut OsRng, &input)?;
            self.reset();
            self.input = Some(input);
            self.secret_key = sk;
            self.login = Some(state);
            Ok(ke1)
        })
    }

    /// Sign-in, step 2: `ke2` is the server's answer, `server_profile` the
    /// KSF profile number it states, `pin` the pin state (always required).
    /// The profile and the pins are checked before Argon2id runs. Returns
    /// `{ ke3, server_public_key }`; the export key stays in WASM for
    /// `unlock_password` and `rekey`.
    pub fn login_finish(
        &mut self,
        ke2: Vec<u8>,
        server_profile: u32,
        pin: JsValue,
    ) -> Result<JsValue, JsValue> {
        run(|| {
            let pin = from_js::<PinArg>(pin)?.core()?;
            let state = self.login.take().ok_or(Fail::Input)?;
            let input = self.input.as_ref().ok_or(Fail::Input)?;
            let done =
                opaque_login_finish(&mut OsRng, state, input, &ke2, server_profile, pin.state())?;
            let ferret_core::LoginFinished {
                ke3,
                export_key,
                server_public_key,
            } = done;
            self.login_done = Some(LoginDone {
                export_key,
                server_public_key,
                profile: KsfProfile::from_wire(server_profile)?,
            });
            to_js(&LoginFinishedDto {
                ke3,
                server_public_key,
            })
        })
    }

    /// Sign-in, step 3: opens the password wrap the server sent after `KE3`.
    /// `ctx` is `{ account_id, vault_id, vk_epoch }` and `pw_wrap` the wrap
    /// record. The pins are checked as in `login_finish`, and the wrap
    /// against the generation floor and the epoch. Returns `{ vault, pinned
    /// }`: the vault and the record to store.
    pub fn unlock_password(
        &mut self,
        server_url: &str,
        ctx: JsValue,
        pw_wrap: JsValue,
        pin: JsValue,
    ) -> Result<JsValue, JsValue> {
        run(|| {
            let pin = from_js::<PinArg>(pin)?.core()?;
            let ctx = from_js::<CtxDto>(ctx)?.core();
            let rec = from_js::<WrapDto>(pw_wrap)?.core()?;
            if !matches!(rec.method, Method::Password { .. }) {
                return Err(Fail::Input);
            }
            let done = self.login_done.as_ref().ok_or(Fail::Input)?;
            let sk_bit = self
                .input
                .as_ref()
                .ok_or(Fail::Input)?
                .includes_secret_key();
            let kek = Kek::from_export_key(&ctx.account_id, &done.export_key)?;
            let (pinned, vault) = unlock_server(
                pin,
                server_url,
                Some(sk_bit),
                Some(done.server_public_key),
                &ctx,
                &rec,
                &kek,
            )?;
            let out = outcome(Vault::from_unlocked(vault, None), &pinned)?;
            // The export key and the password input are not kept past the
            // unlock; a rekey signs in again.
            self.reset();
            Ok(out)
        })
    }

    // ---------------------------------------- unlock without the password

    /// Unlocks with the recovery key as typed (`FFR1-...`) and the recovery
    /// wrap. The code is read first: a typo is `checksum` before any key is
    /// used. `pin` is always required; with `first_use` it carries the
    /// answer to "does the account have a secret key" (`sk_bit`), with
    /// either it may carry the OPAQUE server key the caller has seen.
    ///
    /// On a new device (`first_use`) `qr`, the text of the scanned emergency
    /// sheet, is required: its account and address must be `ctx` and
    /// `server_url`, its secret key bit the answer given, and the record that
    /// is returned pins its server key. A pinned device may pass it too.
    /// Returns `{ vault, pinned }`.
    pub fn unlock_recovery(
        &mut self,
        server_url: &str,
        ctx: JsValue,
        rk_code: String,
        rk_wrap: JsValue,
        pin: JsValue,
        qr: Option<String>,
    ) -> Result<JsValue, JsValue> {
        run(|| {
            let rk_code = Zeroizing::new(rk_code);
            let pin = from_js::<PinArg>(pin)?.core()?;
            let ctx = from_js::<CtxDto>(ctx)?.core();
            let pin = bind_to_qr(pin, qr, &ctx, server_url)?;
            let rec = from_js::<WrapDto>(rk_wrap)?.core()?;
            let rk = decode_recovery_key(&rk_code)?;
            if !matches!(rec.method, Method::Recovery) {
                return Err(Fail::Input);
            }
            let kek = Kek::from_recovery_key(&ctx.account_id, &rk)?;
            let (pinned, vault) = unlock_server(pin, server_url, None, None, &ctx, &rec, &kek)?;
            outcome(Vault::from_unlocked(vault, None), &pinned)
        })
    }

    /// Unlocks with a passkey: `prf_output` is the 32 bytes the authenticator
    /// returned for the salt in the wrap. `pin` and `qr` as for
    /// `unlock_recovery`.
    /// Returns `{ vault, pinned }`.
    pub fn unlock_prf(
        &mut self,
        server_url: &str,
        ctx: JsValue,
        prf_output: Vec<u8>,
        prf_wrap: JsValue,
        pin: JsValue,
        qr: Option<String>,
    ) -> Result<JsValue, JsValue> {
        run(|| {
            let prf_output = Zeroizing::new(prf_output);
            let pin = from_js::<PinArg>(pin)?.core()?;
            let ctx = from_js::<CtxDto>(ctx)?.core();
            let pin = bind_to_qr(pin, qr, &ctx, server_url)?;
            let rec = from_js::<WrapDto>(prf_wrap)?.core()?;
            let Method::Prf { credential_id, .. } = &rec.method else {
                return Err(Fail::Input);
            };
            let kek = Kek::from_prf(credential_id, &PrfOutput::from_slice(&prf_output)?)?;
            let (pinned, vault) = unlock_server(pin, server_url, None, None, &ctx, &rec, &kek)?;
            outcome(Vault::from_unlocked(vault, None), &pinned)
        })
    }

    /// Unlocks with the local PIN (`pin` are the digits). The record of this
    /// device is always required; there is no first-use path for a local
    /// method. With `kek_dev_pin` (32 bytes from the platform keystore) it is
    /// the mobile variant. Argon2id runs here. Returns `{ vault, pinned }`
    /// (the record as it was: a local unlock changes nothing).
    pub fn pin_unlock(
        &mut self,
        pin: Vec<u8>,
        pinned: JsValue,
        pin_wrap: JsValue,
        kek_dev_pin: Option<Vec<u8>>,
    ) -> Result<JsValue, JsValue> {
        run(|| {
            let pin = Zeroizing::new(pin);
            let dev = kek_dev_pin.map(Zeroizing::new);
            let record = from_js::<PinnedDto>(pinned)?.core()?;
            let rec = from_js::<WrapDto>(pin_wrap)?.core()?;
            let Method::Pin { device_salt } = &rec.method else {
                return Err(Fail::Input);
            };
            let digits = PinDigits::new(&pin)?;
            let kek = match &dev {
                Some(d) => Kek::from_pin_mobile(&digits, device_salt, &KekDevPin::from_slice(d)?)?,
                None => Kek::from_pin_extension(&digits, device_salt)?,
            };
            let vault = record.unlock_local(&rec, &kek)?;
            outcome(Vault::from_unlocked(vault, None), &record)
        })
    }

    // ------------------------------------------------------ registration

    /// Registration, step 1 (a new account, a new password, a recovery):
    /// `mp_utf8` is the new master password, which must meet the creation
    /// floor (12 characters with a secret key, 15 without). `secret_key` is
    /// `{ kind: "generate" }` (a new account with a secret key),
    /// `{ kind: "code", code }` (the account's own secret key; a password
    /// change or recovery) or `{ kind: "none" }`. Returns the registration
    /// request (32 bytes).
    pub fn register_start(
        &mut self,
        mp_utf8: Vec<u8>,
        secret_key: JsValue,
    ) -> Result<Vec<u8>, JsValue> {
        run(|| {
            let mp_utf8 = Zeroizing::new(mp_utf8);
            let arg: SecretKeyArg = from_js(secret_key)?;
            let (policy, sk) = match (arg.kind.as_str(), arg.code) {
                ("generate", None) => (
                    MpPolicy::WithSecretKey,
                    Some(SecretKey::generate(&mut OsRng)),
                ),
                ("code", Some(code)) => {
                    let code = Zeroizing::new(code);
                    (MpPolicy::WithSecretKey, Some(decode_secret_key(&code)?))
                }
                ("none", None) => (MpPolicy::WithoutSecretKey, None),
                _ => return Err(Fail::Input),
            };
            let mp = MasterPassword::new(&mp_utf8, policy)?;
            let input = mp.opaque_input(sk.as_ref());
            let (request, state) = opaque_register_start(&mut OsRng, &input)?;
            self.reset();
            self.input = Some(input);
            self.secret_key = sk;
            self.registration = Some(state);
            Ok(request)
        })
    }

    /// Registration, step 2: `response` is the server's answer (64 bytes),
    /// `profile` the KSF profile number to register with. Runs Argon2id.
    /// Returns `{ record, server_public_key, ksf_profile }`; the export key
    /// stays in WASM for the flow that follows.
    pub fn register_finish(&mut self, response: Vec<u8>, profile: u32) -> Result<JsValue, JsValue> {
        run(|| {
            let profile = KsfProfile::from_wire(profile)?;
            let state = self.registration.take().ok_or(Fail::Input)?;
            let input = self.input.as_ref().ok_or(Fail::Input)?;
            let finished = opaque_register_finish(&mut OsRng, state, input, &response, profile)?;
            let out = to_js(&RegistrationDto {
                record: finished.record.clone(),
                server_public_key: finished.server_public_key,
                ksf_profile: profile.number(),
            })?;
            self.registered = Some(Registered { finished, profile });
            Ok(out)
        })
    }

    // -------------------------------------------------------- the flows

    /// Makes the account: a vault key, a recovery key, the password and
    /// recovery wraps, the manifest, `pk_a`, `pk_r` and the first
    /// checkpoint. `ids` is `{ account_id, vault_id, password_method_id,
    /// recovery_method_id }`; `server_url` is pinned with the OPAQUE server
    /// key of the registration. Returns `{ vault, wraps, manifest,
    /// checkpoint, pk_a, pk_r, registration_record, ksf_profile,
    /// server_public_key, pinned }`. The recovery key and the secret key are
    /// shown with `vault.reveal_recovery_code()`, `reveal_secret_key_code()`
    /// or `reveal_emergency_sheet()`, then confirmed with
    /// `verify_recovery_setup` and `verify_secret_key_entry`.
    pub fn create_account(&mut self, server_url: &str, ids: JsValue) -> Result<JsValue, JsValue> {
        run(|| {
            let ids: IdsDto = from_js(ids)?;
            let registered = self.registered.take().ok_or(Fail::Input)?;
            let input = self.input.take().ok_or(Fail::Input)?;
            let sk = self.secret_key.take();
            let account = create_account(
                &mut OsRng,
                &account_ids(&ids),
                NewPassword {
                    input: &input,
                    registration: registered.finished,
                    profile: registered.profile,
                },
                sk,
            )?;
            let pinned = account.pinned(server_url)?;
            let ferret_core::NewAccount {
                vault,
                recovery_key,
                secret_key,
                wraps,
                manifest,
                checkpoint,
                pk_a,
                pk_r,
                registration_record,
                ksf_profile,
                server_public_key,
            } = account;
            let dto = to_js(&NewAccountDto {
                wraps: wraps.iter().map(WrapDto::of).collect(),
                manifest: SealedDto::of(&manifest),
                checkpoint: CheckpointDto {
                    seq: checkpoint.seq,
                    digest: checkpoint.digest,
                    mac: checkpoint.mac,
                    entries: checkpoint.entries,
                },
                pk_a,
                pk_r,
                registration_record,
                ksf_profile: ksf_profile.number(),
                server_public_key,
                pinned: PinnedDto::of(&pinned),
            })?;
            let setup = Setup::new(
                Some(recovery_key),
                secret_key,
                server_public_key,
                ksf_profile,
            );
            outcome_with(Vault::from_unlocked(vault, Some(setup)), dto)
        })
    }

    /// Changes the master password, or upgrades the KSF profile (the same
    /// password with a higher profile). The new password was registered with
    /// `register_start` / `register_finish`. `pinned` is the record of this
    /// device, with its floors seeded (`vault.seed_pinned`); `current` the
    /// password wrap the server holds and `manifest` the current manifest
    /// row. The registration's server key is compared with the pinned one.
    /// Sign the request with `vault.auth_sign("unlock-method.password.put",
    /// nonce, body)`. Returns `{ wrap, manifest, registration_record,
    /// ksf_profile, server_public_key, pinned }` where `pinned` is the record
    /// to store once the server has accepted the change.
    pub fn change_password(
        &mut self,
        vault: &Vault,
        pinned: JsValue,
        current: JsValue,
        manifest: JsValue,
    ) -> Result<JsValue, JsValue> {
        run(|| {
            let record = from_js::<PinnedDto>(pinned)?.core()?;
            let current = from_js::<WrapDto>(current)?.core()?;
            let row: RowDto = from_js(manifest)?;
            let registered = self.registered.take().ok_or(Fail::Input)?;
            let input = self.input.take().ok_or(Fail::Input)?;
            self.secret_key = None;
            let change = change_password(
                &mut OsRng,
                vault.unlocked()?,
                NewPassword {
                    input: &input,
                    registration: registered.finished,
                    profile: registered.profile,
                },
                &record,
                &current,
                &row.core(),
            )?;
            let new_record = change.pinned(&record)?;
            to_js(&ChangedDto {
                wrap: WrapDto::of(&change.wrap),
                manifest: SealedDto::of(&change.manifest),
                registration_record: change.registration_record,
                ksf_profile: change.ksf_profile.number(),
                server_public_key: change.server_public_key,
                pinned: PinnedDto::of(&new_record),
            })
        })
    }

    /// Recovers the account with the recovery key as typed. The new password
    /// was registered with `register_start` / `register_finish` (with the
    /// account's secret key, if it has one).
    ///
    /// * `pin` is always required. With `{ kind: "pinned", record }` (a
    ///   device that knows the account) every pin is checked, the server key
    ///   against the record's.
    /// * With `{ kind: "first_use", sk_bit }` (a new device) `qr`, the text
    ///   of the scanned emergency sheet QR, is **required**. It is read here
    ///   (`setup_qr_parse` shows the host to the user first) and this call
    ///   compares, before anything is returned: the account with `ctx`
    ///   (`pinned_account_id`), the address with `server_url`
    ///   (`pinned_server_url`; the record that is returned pins that
    ///   address) and the server key the registration showed with the `o`
    ///   value (`pinned_server_key`). A pinned device may pass it too, and
    ///   then the same comparisons are made.
    ///
    /// Returns `{ vault, password_wrap, recovery_wrap, manifest, pk_r,
    /// registration_record, ksf_profile, server_public_key, sk_bit, pinned }`
    /// where `pinned` is the record to store once the server has accepted the
    /// recovery. The request is signed with the **old** recovery key by
    /// `recover_sign`; call `recover_done` afterwards. The new recovery key
    /// is shown with `vault.reveal_recovery_code()`.
    #[allow(clippy::too_many_arguments)]
    pub fn recover(
        &mut self,
        server_url: &str,
        ctx: JsValue,
        rk_code: String,
        rk_wrap: JsValue,
        manifest: JsValue,
        new_recovery_method_id: Vec<u8>,
        pin: JsValue,
        qr: Option<String>,
    ) -> Result<JsValue, JsValue> {
        run(|| {
            let rk_code = Zeroizing::new(rk_code);
            let pin = from_js::<PinArg>(pin)?.core()?;
            let ctx = from_js::<CtxDto>(ctx)?.core();
            let rec = from_js::<WrapDto>(rk_wrap)?.core()?;
            let row: RowDto = from_js(manifest)?;
            let new_id = MethodId::from_bytes(crate::convert::arr(&new_recovery_method_id)?);
            let qr = qr.map(Zeroizing::new);
            let qr = qr.as_deref().map(|t| parse_setup_qr(t)).transpose()?;
            let registered = self.registered.take().ok_or(Fail::Input)?;
            let input = self.input.take().ok_or(Fail::Input)?;
            self.secret_key = None;

            // A new device pins what the emergency sheet states, not what the
            // server shows now: the two must be the same.
            match (&pin, &qr) {
                (Pin::FirstUse { .. }, None) => return Err(Fail::Input),
                (_, Some(qr)) => {
                    check_qr(qr, &ctx, server_url)?;
                    if qr.server_public_key != registered.finished.server_public_key {
                        return Err(Error::Pinned(PinnedField::ServerKey).into());
                    }
                    // The sheet states whether the account has a secret key
                    // and the profile it was set up with. The new password
                    // must have the same secret key bit, and a profile that
                    // is not lower (a sheet printed before an upgrade is
                    // older than the account, which is fine).
                    if input.includes_secret_key() != qr.sk_bit {
                        return Err(Error::Pinned(PinnedField::SkBit).into());
                    }
                    if registered.profile.number() < qr.ksf_profile.number() {
                        return Err(Error::KdfProfileDowngrade.into());
                    }
                    if let Pin::FirstUse {
                        sk_bit: Some(answered),
                        ..
                    } = &pin
                        && *answered != qr.sk_bit
                    {
                        return Err(Error::Pinned(PinnedField::SkBit).into());
                    }
                }
                _ => {}
            }

            // `KEK_pw` of the new password, to open the vault again below.
            let password_kek =
                Kek::from_export_key(&ctx.account_id, &registered.finished.export_key)?;
            let recovered = recover(
                &mut OsRng,
                &RecoveryInput {
                    ctx: &ctx,
                    rk_code: &rk_code,
                    rk_wrap: &rec,
                    manifest: row.core(),
                    new_recovery_method_id: new_id,
                },
                NewPassword {
                    input: &input,
                    registration: registered.finished,
                    profile: registered.profile,
                },
                pin.state(),
            )?;
            // Defence in depth: the result carries the key again.
            if let Some(qr) = &qr
                && qr.server_public_key != recovered.server_public_key
            {
                return Err(Error::Pinned(PinnedField::ServerKey).into());
            }
            let old = match &pin {
                Pin::Pinned { record, .. } => Some(record.as_ref()),
                Pin::FirstUse { .. } => None,
            };
            let new_record = recovered.pinned(server_url, old)?;
            let dto = to_js(&RecoveredDto {
                password_wrap: WrapDto::of(&recovered.password_wrap),
                recovery_wrap: WrapDto::of(&recovered.recovery_wrap),
                manifest: SealedDto::of(&recovered.manifest),
                pk_r: recovered.pk_r,
                registration_record: recovered.registration_record.clone(),
                ksf_profile: recovered.ksf_profile.number(),
                server_public_key: recovered.server_public_key,
                sk_bit: recovered.sk_bit,
                pinned: PinnedDto::of(&new_record),
            })?;
            let setup = Setup::new(
                Some(copy_recovery_key(&recovered.recovery_key)?),
                None,
                recovered.server_public_key,
                recovered.ksf_profile,
            );
            // The vault object is opened again from the new password wrap,
            // because the result keeps its own vault for the proof.
            let vault = unwrap_vk(&ctx, &password_kek, &recovered.password_wrap)?;
            self.recovered = Some(recovered);
            outcome_with(Vault::from_unlocked(vault, Some(setup)), dto)
        })
    }

    /// Signs the `recover` request with `sk_r` of the **old** recovery key
    /// (`nonce` is 32 bytes, `body` the exact bytes that are sent). Returns the
    /// signature (64 bytes).
    pub fn recover_sign(&self, nonce: Vec<u8>, body: Vec<u8>) -> Result<Vec<u8>, JsValue> {
        run(|| {
            let recovered = self.recovered.as_ref().ok_or(Fail::Input)?;
            let sig = recovered.sign(&crate::convert::arr::<32>(&nonce)?, &body)?;
            Ok(sig.to_vec())
        })
    }

    /// Wipes the old recovery key that `recover` kept for `recover_sign`.
    pub fn recover_done(&mut self) {
        self.recovered = None;
    }

    /// A full rekey: a new vault key, new item keys for every item, a new
    /// recovery key, new wraps, a new manifest and a new checkpoint, as one
    /// plan. It needs a fresh sign-in of this job (`login_start`,
    /// `login_finish`) for `KEK_pw`. `input` is `{ base_seq, old_checkpoint,
    /// old_manifest, items, tombstones, password_method_id,
    /// recovery_method_id }`; `pinned` is the record of this device with its
    /// floors seeded. Returns the plan (`vk_epoch`, `base_seq`, `pk_a`,
    /// `pk_r`, `items`, `tombstones`, `wraps`, `manifest`, `checkpoint`,
    /// `pinned`: the record to store once the server has applied it).
    ///
    /// The new vault is held by `vault` as pending. Sign the request with the
    /// old vault (`vault.auth_sign("rekey", nonce, body)`), and when the
    /// server has accepted it, call `vault.rekey_commit()`; `rekey_abort()`
    /// drops it.
    pub fn rekey(
        &mut self,
        vault: &mut Vault,
        input: JsValue,
        pinned: JsValue,
    ) -> Result<JsValue, JsValue> {
        run(|| {
            let dto: RekeyInputDto = from_js(input)?;
            let record = from_js::<PinnedDto>(pinned)?.core()?;
            let done = self.login_done.as_ref().ok_or(Fail::Input)?;
            let old_checkpoint = ferret_core::Checkpoint {
                seq: dto.old_checkpoint.seq,
                digest: dto.old_checkpoint.digest,
                mac: dto.old_checkpoint.mac,
                entries: dto.old_checkpoint.entries.clone(),
            };
            let items: Vec<RekeyItem<'_>> = dto
                .items
                .iter()
                .map(|i| RekeyItem {
                    item_id: ferret_core::ItemId::from_bytes(i.item_id),
                    rev: i.rev,
                    envelope: &i.envelope,
                    tag: &i.tag,
                })
                .collect();
            let tombstones: Vec<RekeyTombstone<'_>> = dto
                .tombstones
                .iter()
                .map(|t| RekeyTombstone {
                    item_id: ferret_core::ItemId::from_bytes(t.item_id),
                    rev: t.rev,
                    tomb: &t.tomb,
                })
                .collect();
            let unlocked = vault.unlocked()?;
            let kek = Kek::from_export_key(&unlocked.context().account_id, &done.export_key)?;
            // The rollback memory (`SyncMemory`) is not exposed through this
            // binding yet, so the rekey runs without one.
            let bundle = unlocked.rekey(
                &mut OsRng,
                &RekeyInput {
                    base_seq: dto.base_seq,
                    old_checkpoint: &old_checkpoint,
                    old_manifest: RekeyItem {
                        item_id: ferret_core::ItemId::MANIFEST,
                        rev: dto.old_manifest.rev,
                        envelope: &dto.old_manifest.envelope,
                        tag: &dto.old_manifest.tag,
                    },
                    items: &items,
                    tombstones: &tombstones,
                    password_kek: &kek,
                    password_method: (
                        MethodId::from_bytes(dto.password_method_id),
                        Method::Password { ksf: done.profile },
                    ),
                    recovery_method_id: MethodId::from_bytes(dto.recovery_method_id),
                    pinned: &record,
                },
                ferret_core::RollbackMemory::NoMemory,
            )?;
            let new_record = bundle.pinned(&record)?;
            let out = to_js(&RekeyBundleDto {
                vk_epoch: bundle.vk_epoch,
                base_seq: bundle.base_seq,
                pk_a: bundle.pk_a,
                pk_r: bundle.pk_r,
                items: bundle
                    .items
                    .iter()
                    .map(|(id, s)| RekeyedItemDto {
                        item_id: *id.as_bytes(),
                        rev: s.rev,
                        envelope: s.envelope.clone(),
                        tag: s.tag,
                    })
                    .collect(),
                tombstones: bundle
                    .tombstones
                    .iter()
                    .map(|(id, t)| RekeyedTombDto {
                        item_id: *id.as_bytes(),
                        rev: t.rev,
                        tomb: t.tomb.clone(),
                    })
                    .collect(),
                wraps: bundle.wraps.iter().map(WrapDto::of).collect(),
                manifest: SealedDto::of(&bundle.manifest),
                checkpoint: CheckpointDto {
                    seq: bundle.checkpoint.seq,
                    digest: bundle.checkpoint.digest,
                    mac: bundle.checkpoint.mac,
                    entries: bundle.checkpoint.entries.clone(),
                },
                pinned: PinnedDto::of(&new_record),
            })?;
            let secret_key = self.secret_key.as_ref().map(copy_secret_key).transpose()?;
            let ferret_core::RekeyBundle {
                vault: new_vault,
                recovery_key,
                ..
            } = bundle;
            let inner = vault.inner_mut()?;
            inner.pending = Some(PendingRekey {
                vault: new_vault,
                setup: Setup::new(
                    Some(recovery_key),
                    secret_key,
                    done.server_public_key,
                    done.profile,
                ),
            });
            // The sign-in is used up.
            self.reset();
            Ok(out)
        })
    }

    /// Makes the one-time token that `Vault.reveal_plain_export` needs. Like
    /// a rekey it needs a fresh sign-in of this job (`login_start`,
    /// `login_finish`) in which the master password was typed again. `pw_wrap`
    /// is the vault's password wrap record from the server: it is opened with
    /// the key of this sign-in, and has to hold this vault's key, so a
    /// sign-in to another account (or with a wrong password, which already
    /// failed at `login_finish`) gives no token. The sign-in is used up.
    ///
    /// Returns 32 bytes. The vault keeps a copy until the export uses it, a
    /// new token replaces it, or the vault is locked or rekeyed.
    pub fn reauth_grant(
        &mut self,
        vault: &mut Vault,
        pw_wrap: JsValue,
    ) -> Result<Vec<u8>, JsValue> {
        run(|| {
            let rec = from_js::<WrapDto>(pw_wrap)?.core()?;
            if !matches!(rec.method, Method::Password { .. }) {
                return Err(Fail::Input);
            }
            let done = self.login_done.as_ref().ok_or(Fail::Input)?;
            let unlocked = vault.unlocked()?;
            let ctx = unlocked.context();
            let kek = Kek::from_export_key(&ctx.account_id, &done.export_key)?;
            let opened = unwrap_vk(ctx, &kek, &rec)?;
            if !opened.same_vault_key(unlocked) {
                return Err(Error::Decrypt.into());
            }
            let mut token = Zeroizing::new([0u8; 32]);
            ferret_core::SecureRng::fill(&mut OsRng, &mut *token);
            let out = token.to_vec();
            vault.inner_mut()?.grant = Some(ReauthGrant(token));
            self.reset();
            Ok(out)
        })
    }

    /// Drops everything the job holds (keys of a sign-in, a registration, a
    /// recovery).
    pub fn clear(&mut self) {
        self.reset();
    }
}

impl UnlockJob {
    fn reset(&mut self) {
        self.input = None;
        self.secret_key = None;
        self.login = None;
        self.registration = None;
        self.login_done = None;
        self.registered = None;
        self.recovered = None;
    }
}

impl Shaped for SecretKeyArg {
    const SHAPE: Shape = Shape::Obj(&[("kind", &ANY), ("code", &ANY)]);
}

impl Shaped for RekeyItemDto {
    const SHAPE: Shape = Shape::Obj(&[
        ("item_id", &ANY),
        ("rev", &ANY),
        ("envelope", &ANY),
        ("tag", &ANY),
    ]);
}

impl Shaped for RekeyTombDto {
    const SHAPE: Shape = Shape::Obj(&[("item_id", &ANY), ("rev", &ANY), ("tomb", &ANY)]);
}

impl Shaped for RekeyInputDto {
    const SHAPE: Shape = Shape::Obj(&[
        ("base_seq", &ANY),
        ("old_checkpoint", &CheckpointDto::SHAPE),
        ("old_manifest", &RowDto::SHAPE),
        ("items", &Shape::List(&RekeyItemDto::SHAPE)),
        ("tombstones", &Shape::List(&RekeyTombDto::SHAPE)),
        ("password_method_id", &ANY),
        ("recovery_method_id", &ANY),
    ]);
}

#[cfg(feature = "test-support")]
impl UnlockJob {
    /// The OPAQUE export key held after `login_finish` or `register_finish`,
    /// for the test that no reply holds it.
    pub(crate) fn export_key_for_test(&self) -> Option<Vec<u8>> {
        let key = self
            .login_done
            .as_ref()
            .map(|d| &d.export_key)
            .or_else(|| self.registered.as_ref().map(|r| &r.finished.export_key))?;
        Some(ferret_core::testing::keys::export_key_bytes(key).to_vec())
    }
}
