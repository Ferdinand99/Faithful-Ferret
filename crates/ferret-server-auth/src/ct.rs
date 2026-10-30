//! Constant-time comparison and selection.
//!
//! The code lives in `ct/harness/`, in the same single files that the
//! constant-time analyzer reads and that `ferret-core` includes, so the code
//! that runs here is the code that was analyzed. This crate has no copy of
//! its own. Every comparison where one side may be secret goes through
//! `ct_eq`.

/// Equality of byte strings through `subtle`: `ct_eq`, and the fixed-size
/// forms `commit_eq` and `mac_eq`.
#[allow(dead_code)]
pub(crate) mod eq {
    include!("../../../ct/harness/ct_eq.rs");
}

/// Branch-free selection through `subtle`, for choosing between a real and a
/// made-up record without a branch on which one it is.
#[allow(dead_code)]
pub(crate) mod select {
    include!("../../../ct/harness/ct_select.rs");
}

#[allow(unused_imports)]
pub(crate) use eq::{commit_eq, ct_eq, mac_eq};
#[allow(unused_imports)]
pub(crate) use select::{ct_select_bytes, ct_select_u8, ct_select_u32, ct_select_u64};

#[cfg(test)]
mod tests {
    use super::{ct_eq, ct_select_bytes};

    #[test]
    fn ct_eq_compares_equal_unequal_and_different_lengths() {
        assert!(ct_eq(b"", b""));
        assert!(ct_eq(b"abc", b"abc"));
        assert!(!ct_eq(b"abc", b"abd"));
        assert!(!ct_eq(b"abc", b"abcd"));
        assert!(!ct_eq(b"abcd", b"abc"));
        assert!(!ct_eq(b"", b"a"));
        let a = [7u8; 64];
        for at in 0..64 {
            for bit in 0..8 {
                let mut b = a;
                b[at] ^= 1 << bit;
                assert!(!ct_eq(&a, &b), "byte {at} bit {bit}");
            }
        }
    }

    #[test]
    fn ct_select_bytes_picks_by_flag() {
        let (a, b) = ([1u8, 2, 3], [9u8, 8, 7]);
        let mut out = [0u8; 3];
        ct_select_bytes(1, &a, &b, &mut out);
        assert_eq!(out, a);
        ct_select_bytes(0, &a, &b, &mut out);
        assert_eq!(out, b);
        // Only the lowest bit counts.
        ct_select_bytes(3, &a, &b, &mut out);
        assert_eq!(out, a);
        ct_select_bytes(2, &a, &b, &mut out);
        assert_eq!(out, b);
    }
}
