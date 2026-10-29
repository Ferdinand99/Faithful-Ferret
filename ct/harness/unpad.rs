// ISO/IEC 7816-4 padding removal without data-dependent branches or early
// exits. Spec: Fase 1 section 5.2 ("Fjernes ved å lete bakfra etter siste
// 0x80 med bare nullbyte etter"), plan section 10 point 2.
//
// This file is the single source of the scan: `crates/ferret-core/src/item/pad.rs`
// includes it with `include!`, and the constant-time analyzer reads the same
// file on its own. So it uses `core` only, has no inner attributes and no
// `use` of the crate it is included in, and compiles as a library on its own:
//
//     rustc --crate-type=lib --edition=2024 ct/harness/unpad.rs
//
// What may depend on secret data here is the *content* of the buffer. The
// loop runs once for every byte of the buffer (its length is public), and
// every comparison, selection and update is done with arithmetic and masks.
// The scan never stops at the marker and never skips the zero bytes.
//
// The padding is removed only after the AEAD has accepted the ciphertext, so
// a buffer that reaches this function is authentic. The scan is still
// branch-free so that the *position* of the marker (the length of the
// plaintext) does not show in the time it takes.

/// 1 if `a == b`, else 0.
#[inline(always)]
fn byte_is(a: u8, b: u8) -> u32 {
    // `a ^ b` is below 256, so subtracting 1 wraps to the top bit only for 0.
    u32::from(a ^ b).wrapping_sub(1).wrapping_shr(31)
}

/// Looks for the padding marker from the back of `padded`.
///
/// Returns `(ok, len)`. `ok` is 1 when the buffer ends in `0x80` followed by
/// zero bytes only (possibly none), and 0 otherwise. When `ok` is 1, `len` is
/// the index of the marker, which is the length of the plaintext. When `ok`
/// is 0, `len` is not meaningful.
pub fn unpad_scan(padded: &[u8]) -> (u32, usize) {
    // `found`: the marker has been seen. `invalid`: a byte other than 0x00
    // was seen after the marker's position was still open.
    let mut found: u32 = 0;
    let mut invalid: u32 = 0;
    let mut at: usize = 0;
    let mut index = padded.len();
    for &byte in padded.iter().rev() {
        index = index.wrapping_sub(1);
        let is_marker = byte_is(byte, 0x80);
        let is_zero = byte_is(byte, 0x00);
        let open = found ^ 1;
        let hit = open & is_marker;
        // Before the marker is found, only zero bytes are allowed.
        invalid |= (open & (is_marker | is_zero)) ^ open;
        let mask = (hit as usize).wrapping_neg();
        at = (index & mask) | (at & !mask);
        found |= hit;
    }
    (found & (invalid ^ 1), at)
}
