// Branch-free selection between two values. Plan section 10 point 2.
//
// This file is the single source of the selects: `crates/ferret-core/src/prim/ct.rs`
// includes it with `include!`, and the constant-time analyzer reads the same
// file on its own. It uses `core` only, has no inner attributes and no `use`
// of the crate it is included in, and compiles as a library on its own:
//
//     rustc --crate-type=lib --edition=2024 ct/harness/ct_select.rs
//
// The flag is the secret in the general case, and so are both values. The
// flag is turned into an all-ones or all-zeros mask with arithmetic, and the
// result is `(a & mask) | (b & !mask)`. No branch and no index depends on
// the flag or on the values. Only the lengths of the slices, which are
// public, decide how often the loop runs.
//
// The mask goes through `black_box`. Without it LLVM sees that the mask is
// all-ones or all-zeros and turns `ct_select_bytes` into "choose the source
// pointer with `cmov`, then copy", which reads only one of the two slices
// (the x86_64 O2 output of an earlier version of this file did that). The
// flag would then show in which memory is read. `black_box` is the same
// barrier `subtle` uses.

use core::hint::black_box;

/// `a` if `flag` is 1, else `b`. Only the lowest bit of `flag` is used.
#[inline(never)]
pub fn ct_select_u8(flag: u8, a: u8, b: u8) -> u8 {
    let mask = black_box(0u8.wrapping_sub(flag & 1));
    (a & mask) | (b & !mask)
}

/// `a` if `flag` is 1, else `b`. Only the lowest bit of `flag` is used.
#[inline(never)]
pub fn ct_select_u32(flag: u32, a: u32, b: u32) -> u32 {
    let mask = black_box(0u32.wrapping_sub(flag & 1));
    (a & mask) | (b & !mask)
}

/// `a` if `flag` is 1, else `b`. Only the lowest bit of `flag` is used.
#[inline(never)]
pub fn ct_select_usize(flag: usize, a: usize, b: usize) -> usize {
    let mask = black_box(0usize.wrapping_sub(flag & 1));
    (a & mask) | (b & !mask)
}

/// Writes `a` (if `flag` is 1) or `b` (else) into `out`, byte by byte. The
/// three slices are walked in step up to the shortest length, which the
/// caller makes equal.
#[inline(never)]
pub fn ct_select_bytes(flag: u8, a: &[u8], b: &[u8], out: &mut [u8]) {
    let mask = black_box(0u8.wrapping_sub(flag & 1));
    for ((slot, &x), &y) in out.iter_mut().zip(a.iter()).zip(b.iter()) {
        *slot = (x & mask) | (y & !mask);
    }
}
