// Base64url (RFC 4648 section 5, no padding) reading without lookup tables and
// without data-dependent branches. Spec: Fase 1 section 9.1 (a passkey that is
// imported from a file: the private scalar of a JWK is text).
//
// This file is the single source of the code: `crates/ferret-core/src/passkey/
// import.rs` includes it with `include!`, and the constant-time analyzer reads
// the same file on its own. So it uses `core` only (no `std`, no `alloc`), has
// no inner attributes and no `use` of the crate it is included in, and
// compiles as a library on its own:
//
//     rustc --crate-type=lib --edition=2024 ct/harness/base64url.rs
//
// Every public function is `#[inline(never)]`, as in the other harness files:
// the code the analyzer reads is a function of its own, and so it is in the
// core.
//
// What may depend on secret data here is the *value* of the symbols. Every
// loop count, every branch and every index depends on the lengths of the
// slices only, which are public. A symbol is turned into six bits with
// arithmetic and masks. A symbol that is not in the alphabet reads as six
// zero bits and clears the `all_valid` flag; the flag is public by design (the
// caller refuses the text), but which symbol was wrong is not shown.
//
// The alphabet is ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_.

/// 1 if `value >= bound`, else 0. Both must be below 2^31.
#[inline(always)]
fn ge(value: u32, bound: u32) -> u32 {
    value.wrapping_sub(bound).wrapping_shr(31) ^ 1
}

/// 1 if `lo <= value <= hi`, else 0. All must be below 2^31.
#[inline(always)]
fn in_range(value: u32, lo: u32, hi: u32) -> u32 {
    ge(value, lo) & ge(hi, value)
}

/// 1 if `a == b`, else 0. Both must be below 2^31.
#[inline(always)]
fn is_equal(a: u32, b: u32) -> u32 {
    ge(a, b) & ge(b, a)
}

/// The 6-bit value of a base64url symbol and 1 if the symbol is valid, else
/// 0. The value of an invalid symbol is 0.
#[inline(never)]
pub fn decode_symbol(symbol: u8) -> (u8, u8) {
    let c = u32::from(symbol);
    let upper = in_range(c, 65, 90);
    let lower = in_range(c, 97, 122);
    let digit = in_range(c, 48, 57);
    let minus = is_equal(c, 45);
    let under = is_equal(c, 95);
    // Each term is multiplied by its range flag, so a symbol outside every
    // range gives 0. 'A' is 0, 'a' is 26 (97 - 71), '0' is 52 (48 + 4).
    let value = upper
        .wrapping_mul(c.wrapping_sub(65))
        .wrapping_add(lower.wrapping_mul(c.wrapping_sub(71)))
        .wrapping_add(digit.wrapping_mul(c.wrapping_add(4)))
        .wrapping_add(minus.wrapping_mul(62))
        .wrapping_add(under.wrapping_mul(63));
    let valid = upper | lower | digit | minus | under;
    ((value & 63) as u8, (valid & 1) as u8)
}

/// What [`decode`] found.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Decoded {
    /// True if every symbol was in the alphabet.
    pub all_valid: bool,
    /// The bits left over after `out` was filled, as a number (the "spare"
    /// bits of the text; zero in a canonical encoding).
    pub spare: u32,
}

/// Reads base64url symbols into bytes: each symbol of `symbols` is turned into
/// six bits, and the bit stream is written most significant bit first into
/// `out`. The bits that do not fill a whole byte at the end are returned in
/// [`Decoded::spare`]. An invalid symbol reads as six zero bits and clears
/// [`Decoded::all_valid`].
///
/// The caller passes lengths with `6 * symbols.len() - 8 * out.len()` in
/// `0..8` (a text of a length that is 1 more than a multiple of 4 cannot be
/// base64); with any other lengths `out` is only partly written.
#[inline(never)]
pub fn decode(symbols: &[u8], out: &mut [u8]) -> Decoded {
    let mut slots = out.iter_mut();
    let mut acc: u32 = 0;
    let mut bits: u32 = 0;
    let mut all_valid: u32 = 1;
    for &symbol in symbols {
        let (value, valid) = decode_symbol(symbol);
        all_valid &= u32::from(valid);
        acc = acc.wrapping_shl(6) | u32::from(value);
        bits = bits.wrapping_add(6);
        if bits >= 8 {
            bits = bits.wrapping_sub(8);
            if let Some(slot) = slots.next() {
                *slot = (acc.wrapping_shr(bits) & 0xff) as u8;
            }
            acc &= 1u32.wrapping_shl(bits).wrapping_sub(1);
        }
    }
    Decoded {
        all_valid: all_valid == 1,
        spare: acc,
    }
}
