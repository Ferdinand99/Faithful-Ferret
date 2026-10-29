//! Constant-time comparison.

use subtle::ConstantTimeEq;

/// Compares two byte strings without a data-dependent branch or early exit
/// on their contents. Strings of different length are unequal; the length is
/// not secret.
///
/// Spec: Fase 1 § 14 (constant-time comparison of `commit`, MACs, tags and
/// keys through `subtle`).
#[allow(dead_code)] // first used by Task 4 (commit check)
pub(crate) fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    bool::from(a.ct_eq(b))
}
