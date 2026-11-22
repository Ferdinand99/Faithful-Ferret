//! The password and passphrase generator of the core, for JavaScript.
//!
//! Both functions need no vault: they draw from the operating system's
//! random number generator (Web Crypto in a browser) through the core and
//! return `{ value, bits }`. The rules, the order of the draws and the
//! estimate are the core's (`ferret_core::generator`); nothing outside the
//! core makes a password.
//!
//! The value is a new secret that the caller asked for: it is in the reply
//! by design, like the answer of a `reveal_` method, and the core wipes its
//! own copy when the reply has been made.

use crate::convert::{ANY, Shape, Shaped, from_js, to_js};
use crate::error::{Fail, run};
use ferret_core::{
    OsRng, PassphraseOptions, PasswordOptions, generate_passphrase as core_passphrase,
    generate_password as core_password,
};
use serde::{Deserialize, Serialize};
use wasm_bindgen::prelude::*;

/// The options of a password. Every key is required.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PasswordOptionsDto {
    length: u16,
    lower: bool,
    upper: bool,
    digits: bool,
    symbols: bool,
    min_each: u8,
    avoid_ambiguous: bool,
}

/// The options of a passphrase. Every key is required; `separator` is a
/// string of one character.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PassphraseOptionsDto {
    words: u8,
    separator: String,
    capitalize: bool,
    number: bool,
}

/// `{ value, bits }`.
#[derive(Serialize)]
struct GeneratedDto<'a> {
    value: &'a str,
    bits: f64,
}

impl Shaped for PasswordOptionsDto {
    const SHAPE: Shape = Shape::Obj(&[
        ("length", &ANY),
        ("lower", &ANY),
        ("upper", &ANY),
        ("digits", &ANY),
        ("symbols", &ANY),
        ("min_each", &ANY),
        ("avoid_ambiguous", &ANY),
    ]);
}

impl Shaped for PassphraseOptionsDto {
    const SHAPE: Shape = Shape::Obj(&[
        ("words", &ANY),
        ("separator", &ANY),
        ("capitalize", &ANY),
        ("number", &ANY),
    ]);
}

/// A random password: `options` is `{ length, lower, upper, digits, symbols,
/// min_each, avoid_ambiguous }` (all required: `length` 4 to 128, the four
/// classes as booleans, `min_each` 0 to 8, `avoid_ambiguous` a boolean).
/// Returns `{ value, bits }`, where `bits` is the entropy estimate for
/// display. Options out of range are `generator_options`; a missing or
/// unknown key, or a value of the wrong type, is `invalid_input`.
#[wasm_bindgen]
pub fn generate_password(options: JsValue) -> Result<JsValue, JsValue> {
    run(|| {
        let o: PasswordOptionsDto = from_js(options)?;
        let g = core_password(
            &PasswordOptions {
                length: o.length,
                lower: o.lower,
                upper: o.upper,
                digits: o.digits,
                symbols: o.symbols,
                min_each: o.min_each,
                avoid_ambiguous: o.avoid_ambiguous,
            },
            &mut OsRng,
        )?;
        to_js(&GeneratedDto {
            value: &g.value,
            bits: g.bits,
        })
    })
}

/// A random passphrase from the EFF large word list: `options` is `{ words,
/// separator, capitalize, number }` (all required: `words` 3 to 20,
/// `separator` one of `"-"`, `"."`, `"_"` and `" "`, `capitalize` and
/// `number` booleans). Returns `{ value, bits }`. A separator that is one
/// other character, or options out of range, is `generator_options`; a
/// separator that is not exactly one character, a missing or unknown key, or
/// a value of the wrong type is `invalid_input`.
#[wasm_bindgen]
pub fn generate_passphrase(options: JsValue) -> Result<JsValue, JsValue> {
    run(|| {
        let o: PassphraseOptionsDto = from_js(options)?;
        let mut chars = o.separator.chars();
        let separator = match (chars.next(), chars.next()) {
            (Some(c), None) => c,
            _ => return Err(Fail::Input),
        };
        let g = core_passphrase(
            &PassphraseOptions {
                words: o.words,
                separator,
                capitalize: o.capitalize,
                number: o.number,
            },
            &mut OsRng,
        )?;
        to_js(&GeneratedDto {
            value: &g.value,
            bits: g.bits,
        })
    })
}
