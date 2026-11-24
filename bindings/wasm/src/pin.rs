//! The local PIN of the browser extension: what `Vault.wrap_pin`,
//! `Vault.wrap_pin_key`, `argon2_pin_key` and `UnlockJob.pin_unlock` share.
//!
//! ```text
//! set a PIN, small vault, or tests:
//!   vault.wrap_pin(pin, method_id, rule)         -> { method_id, wrap, device_salt, profile, vk_epoch, ms }
//!                                                   (Argon2id runs in the vault worker)
//! set a PIN in the product:
//!   argon2_pin_key(pin, rule)                    -> { key, device_salt, profile, ms }   (job worker)
//!   vault.wrap_pin_key(key, device_salt, id)     -> { method_id, wrap, device_salt, profile, vk_epoch }
//! unlock:
//!   job.pin_unlock(pin, pinned, pin_wrap, rule)  -> { vault, pinned }
//! ```
//!
//! Why two ways to set a PIN: the Argon2id of the PIN profile reserves 256
//! MiB. The vault worker may already have grown by the 64 MiB of the master
//! password check, and WebAssembly memory never shrinks, so the product runs
//! the PIN's Argon2id in the short-lived job worker and only the 32 bytes of
//! `KEK_pin` cross to the vault worker. The PIN goes to one worker only, and
//! `KEK_pin` is wiped on both sides (the copies the JavaScript engine makes
//! of a transferred buffer cannot be).
//!
//! Every refusal that does not need the PIN's Argon2id comes before it: a
//! rule that forbids PINs, a PIN below the rule's minimum or the floor of
//! four, an unknown or too low PIN profile, a stored wrap of an older epoch
//! (`pin_stale`). A device that is too slow (more than ten seconds) or out of
//! memory (`kdf_out_of_memory`) gets an error and no wrap.
//!
//! Nothing here depends on the PIN's content after the normaliser, and
//! nothing returned says what kind of PIN it was or how long.

use crate::convert::{PinRuleDto, PinWrapOut, from_js};
use crate::error::{Fail, Res, run};
use ferret_core::{
    Error, Kek, Method, MethodId, OsRng, Pin, PinProfile, SecureRng, UnlockedVault,
    pin_extension_key, pin_meets_rule,
};
use wasm_bindgen::prelude::*;
use zeroize::Zeroizing;

/// The most time a device may take for the Argon2id of one PIN, in
/// milliseconds. A slower device is told so and stores no PIN.
pub(crate) const MAX_PIN_MS: f64 = 10_000.0;

#[cfg(feature = "test-support")]
std::thread_local! {
    /// The budget the tests set (never a release).
    pub(crate) static LIMIT_MS: core::cell::Cell<f64> = const { core::cell::Cell::new(MAX_PIN_MS) };
}

fn limit_ms() -> f64 {
    #[cfg(feature = "test-support")]
    {
        LIMIT_MS.get()
    }
    #[cfg(not(feature = "test-support"))]
    {
        MAX_PIN_MS
    }
}

fn now_ms() -> f64 {
    js_sys::Date::now()
}

/// Normalises the PIN and checks it against the server's rule. A rule that
/// forbids PINs refuses before the PIN is even read; a PIN below the minimum
/// (never below four) is `input_too_short`. Nothing is computed from it.
pub(crate) fn checked_pin(pin: &[u8], rule: JsValue) -> Res<Pin> {
    let rule = from_js::<PinRuleDto>(rule)?.core();
    if !rule.allowed {
        return Err(Error::PinNotAllowed.into());
    }
    let digits = Pin::new(pin)?;
    pin_meets_rule(&digits, &rule)?;
    Ok(digits)
}

/// Runs `body` (the Argon2id of a PIN) and times it. More than the budget is
/// `pin_too_slow` and the result is dropped, so nothing is returned.
pub(crate) fn timed<T>(body: impl FnOnce() -> Res<T>) -> Res<(T, u32)> {
    let start = now_ms();
    let out = body()?;
    let elapsed = (now_ms() - start).max(0.0);
    if elapsed > limit_ms() {
        return Err(Fail::PinTooSlow);
    }
    Ok((out, elapsed.round().min(f64::from(u32::MAX)) as u32))
}

/// The Argon2id of a new PIN, for the **job worker**: checks the rule, draws
/// a fresh device salt, runs the PIN profile 1 Argon2id (timed) and returns
/// `{ key, device_salt, profile, ms }`, where `key` is the 32 bytes of
/// `KEK_pin`. Pass them to `Vault.wrap_pin_key` in the vault worker and wipe
/// them. A PIN the rule refuses, a device that runs out of memory
/// (`kdf_out_of_memory`) or takes more than ten seconds (`pin_too_slow`)
/// gets an error and nothing else. The PIN is wiped.
///
/// The key is the one byte array of the binding that is a PIN key; it is
/// listed with this reason in `tests/node/exports.test.mjs`.
#[wasm_bindgen]
pub fn argon2_pin_key(pin: Vec<u8>, rule: JsValue) -> Result<JsValue, JsValue> {
    run(|| {
        let pin = Zeroizing::new(pin);
        let digits = checked_pin(&pin, rule)?;
        let mut salt = [0u8; 16];
        SecureRng::fill(&mut OsRng, &mut salt);
        let (key, ms) = timed(|| Ok(pin_extension_key(&digits, &salt, PinProfile::P1)?))?;
        let out = js_sys::Object::new();
        let set = |name: &str, value: JsValue| {
            js_sys::Reflect::set(&out, &JsValue::from_str(name), &value)
                .map(drop)
                .map_err(|_| Fail::Input)
        };
        set("key", js_sys::Uint8Array::from(key.as_slice()).into())?;
        set("device_salt", js_sys::Uint8Array::from(&salt[..]).into())?;
        set("profile", JsValue::from(u32::from(PinProfile::P1.number())))?;
        set("ms", JsValue::from(ms))?;
        Ok(out.into())
    })
}

/// Wraps the vault key under `kek` as a PIN wrap of profile 1 and states
/// what the extension stores of it.
pub(crate) fn pin_wrap_out(
    vault: &UnlockedVault,
    kek: &Kek,
    device_salt: [u8; 16],
    method_id: [u8; 16],
    ms: u32,
) -> Res<PinWrapOut> {
    let rec = vault.wrap_for_method(
        &mut OsRng,
        kek,
        MethodId::from_bytes(method_id),
        1,
        Method::Pin {
            device_salt,
            profile: PinProfile::P1,
        },
    )?;
    Ok(PinWrapOut {
        method_id: *rec.method_id.as_bytes(),
        wrap: rec.wrap,
        device_salt,
        profile: u32::from(PinProfile::P1.number()),
        vk_epoch: vault.context().vk_epoch,
        ms,
    })
}
