// RFC 4648 base32 reading without lookup tables and without data-dependent
// branches. Spec: Fase 1 section 5.2 (F-31).
//
// This file is the single source of the code: `crates/ferret-core/src/totp.rs`
// includes it with `include!`, and the constant-time analyzer reads the same
// file on its own. So it uses `core` only (no `std`, no `alloc`), has no
// inner attributes and no `use` of the crate it is included in, and compiles
// as a library on its own:
//
//     rustc --crate-type=lib --edition=2024 ct/harness/base32.rs
//
// Every public function is `#[inline(never)]`. Without it rustc leaves a
// small function out of the compiled library when nothing in the file calls
// it, and the analyzer would find nothing to look at. With it, the code the
// analyzer reads is a function of its own, and so it is in the core.
//
// The input here is a TOTP secret, so the value of every letter is secret.
// What may be public: the number of letters and so the number of output
// bytes. Every loop count, branch and index depends on the lengths of the
// slices only. Letters are turned into values with arithmetic and masks.
//
// The alphabet is `A`-`Z` and `2`-`7`; lower case is accepted. Blanks and
// fill characters are removed by the caller before this code runs (they are
// not secret, and the caller tests for them with ordinary comparisons).

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

/// The 5-bit value of a base32 letter (RFC 4648: `A`-`Z`, `2`-`7`, either
/// case) and 1 if the letter is valid, else 0. Arithmetic and masks, no
/// table and no branch on the letter: the secret is the input here.
#[inline(never)]
pub fn symbol(byte: u8) -> (u32, u32) {
    let c = u32::from(byte);
    let upper = c.wrapping_sub(in_range(c, 97, 122).wrapping_mul(32));
    let letter = in_range(upper, 65, 90);
    let digit = in_range(upper, 50, 55);
    let value = letter
        .wrapping_mul(upper.wrapping_sub(65))
        .wrapping_add(digit.wrapping_mul(upper.wrapping_sub(24)));
    (value & 31, letter | digit)
}

/// Reads letters into bytes: each letter is turned into five bits with
/// [`symbol`], and the bit stream is written most significant bit first into
/// `out`. Returns 1 if every letter was valid, else 0; an invalid letter
/// reads as five zero bits.
///
/// The caller passes `out.len() == symbols.len() * 5 / 8` (rounded down);
/// with other lengths `out` is only partly written, or the last bits are
/// dropped.
#[inline(never)]
pub fn decode_letters(symbols: &[u8], out: &mut [u8]) -> u32 {
    let mut slots = out.iter_mut();
    let mut acc: u32 = 0;
    let mut bits: u32 = 0;
    let mut all_valid: u32 = 1;
    for &letter in symbols {
        let (value, valid) = symbol(letter);
        all_valid &= valid;
        acc = (acc.wrapping_shl(5) | value) & 0x1fff;
        bits = bits.wrapping_add(5);
        if bits >= 8 {
            bits = bits.wrapping_sub(8);
            if let Some(slot) = slots.next() {
                *slot = (acc.wrapping_shr(bits) & 0xff) as u8;
            }
        }
    }
    all_valid
}
