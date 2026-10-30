// Branch-free selection between two values. Plan section 10 point 2.
//
// This file is the single source of the selects: `crates/ferret-core/src/prim/ct.rs`
// includes it with `include!`, and the constant-time analyzer reads the same
// file on its own. Like `ct_eq.rs` it needs the `subtle` crate, so the
// analyzer gets it with `--extern` (see `ct/run.sh`). It compiles as a library
// with
//
//     rustc --crate-type=lib --edition=2024 --extern subtle=<libsubtle.rlib> ct/harness/ct_select.rs
//
// The flag is the secret in the general case, and so are both values. The
// selection is `subtle::ConditionallySelectable`, which builds an all-ones or
// all-zeros mask from a `Choice`. No branch and no index depends on the flag
// or on the values; only the lengths of the slices, which are public, decide
// how often the loop runs.
//
// Why `subtle` and not a mask written here. A mask that is made with
// arithmetic is all-ones or all-zeros, and LLVM can see that: without a
// barrier it turned `ct_select_bytes` into "choose the source pointer with
// `cmov`, then copy", which reads only one of the two slices (an earlier
// version of this file did that at O2 on x86_64), and the flag then shows in
// which memory is read. `Choice::from` hides the value behind a
// `#[inline(never)]` function that stores it on the stack and reads it back
// with a volatile read, which the optimizer cannot see through. That is a
// stronger barrier than `core::hint::black_box`, whose documentation says it
// is best effort and gives no guarantee for cryptographic purposes. It is
// still a property of today's compiler, not of the language: `ct/run.sh
// select-asm` reads the assembly of `ct_select_bytes` at O2, O3 and Os on
// x86_64 and arm64 and fails if it does not read both slices in the loop.

use subtle::{Choice, ConditionallySelectable};

/// `a` if `flag` is 1, else `b`. Only the lowest bit of `flag` is used.
#[inline(never)]
pub fn ct_select_u8(flag: u8, a: u8, b: u8) -> u8 {
    u8::conditional_select(&b, &a, Choice::from(flag & 1))
}

/// `a` if `flag` is 1, else `b`. Only the lowest bit of `flag` is used.
#[inline(never)]
pub fn ct_select_u32(flag: u32, a: u32, b: u32) -> u32 {
    // The low bit, as the `u8` that `Choice::from` takes.
    u32::conditional_select(&b, &a, Choice::from((flag & 1) as u8))
}

/// `a` if `flag` is 1, else `b`. Only the lowest bit of `flag` is used.
#[inline(never)]
pub fn ct_select_u64(flag: u64, a: u64, b: u64) -> u64 {
    u64::conditional_select(&b, &a, Choice::from((flag & 1) as u8))
}

/// Writes `a` (if `flag` is 1) or `b` (else) into `out`, byte by byte. The
/// three slices are walked in step up to the shortest length, which the
/// caller makes equal.
#[inline(never)]
pub fn ct_select_bytes(flag: u8, a: &[u8], b: &[u8], out: &mut [u8]) {
    let choice = Choice::from(flag & 1);
    for ((slot, &x), &y) in out.iter_mut().zip(a.iter()).zip(b.iter()) {
        *slot = u8::conditional_select(&y, &x, choice);
    }
}
