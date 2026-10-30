// Constant-time equality of byte strings, a thin wrapper around `subtle`.
// Spec: Fase 1 section 14, plan section 10 point 1.
//
// This file is the single source of the wrapper: `crates/ferret-core/src/prim/ct.rs`
// includes it with `include!`, and the constant-time analyzer reads the same
// file on its own. Unlike the other files in this folder it needs the
// `subtle` crate, so the analyzer gets it with `--extern` (see
// `scripts/lanbox-ct.sh`). It compiles as a library with
//
//     rustc --crate-type=lib --edition=2024 --extern subtle=<libsubtle.rlib> ct/harness/ct_eq.rs
//
// `subtle` compares every byte, folds the differences into one value that an
// optimization barrier hides from the compiler, and only then turns it into a
// boolean. What may be secret here is the content of both strings; the
// lengths are public.
//
// `commit_eq` and `mac_eq` are the two fixed-size forms: the key commitment
// of a wrap (Fase 1 section 4.3) and an HMAC-SHA-256 tag of a row or a
// checkpoint (section 8.6). Both are 32 bytes.

use subtle::ConstantTimeEq;

/// Compares two byte strings without a data-dependent branch or early exit
/// on their contents. Strings of different length are unequal; the length is
/// not secret.
///
/// Spec: Fase 1 § 14 (constant-time comparison of `commit`, MACs, tags and
/// keys through `subtle`).
#[inline(never)]
pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    bool::from(a.ct_eq(b))
}

/// Compares two key commitments (32 bytes each).
///
/// Spec: Fase 1 § 4.3 (`commit` is compared in constant time before the
/// AEAD is opened).
#[inline(never)]
pub fn commit_eq(a: &[u8; 32], b: &[u8; 32]) -> bool {
    bool::from(a.as_slice().ct_eq(b.as_slice()))
}

/// Compares two HMAC-SHA-256 tags (32 bytes each).
///
/// Spec: Fase 1 § 8.6 (the row tag and the checkpoint MAC are compared in
/// constant time).
#[inline(never)]
pub fn mac_eq(a: &[u8; 32], b: &[u8; 32]) -> bool {
    bool::from(a.as_slice().ct_eq(b.as_slice()))
}
