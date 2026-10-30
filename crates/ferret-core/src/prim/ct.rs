//! Constant-time comparison and selection.
//!
//! The code lives in `ct/harness/`, in single files that the constant-time
//! analyzer reads on its own and that the timing tests (`ct/dudect`) include
//! as well. They are included here, so the code that runs is the code that
//! was analyzed.

/// Equality of byte strings through `subtle`: [`ct_eq`], and the fixed-size
/// forms [`commit_eq`] and [`mac_eq`].
///
/// [`ct_eq`]: eq::ct_eq
/// [`commit_eq`]: eq::commit_eq
/// [`mac_eq`]: eq::mac_eq
pub(crate) mod eq {
    include!("../../../../ct/harness/ct_eq.rs");
}

/// Branch-free selection. Not used by the core yet; it is analyzed and
/// timed with the rest, so it is ready for the first caller.
#[allow(dead_code)]
pub(crate) mod select {
    include!("../../../../ct/harness/ct_select.rs");
}

pub(crate) use eq::{commit_eq, ct_eq, mac_eq};

#[cfg(test)]
mod tests {
    use super::{commit_eq, ct_eq, mac_eq, select};

    #[test]
    fn select_picks_by_the_lowest_bit_of_the_flag() {
        for flag in 0u8..=255 {
            let pick_a = flag & 1 == 1;
            assert_eq!(
                select::ct_select_u8(flag, 0xaa, 0x55),
                if pick_a { 0xaa } else { 0x55 }
            );
            assert_eq!(
                select::ct_select_u32(u32::from(flag), 0xdead_beef, 0x0123_4567),
                if pick_a { 0xdead_beef } else { 0x0123_4567 }
            );
            assert_eq!(
                select::ct_select_usize(usize::from(flag), usize::MAX, 7),
                if pick_a { usize::MAX } else { 7 }
            );
        }
    }

    #[test]
    fn select_bytes_copies_the_chosen_slice_and_nothing_else() {
        let a: Vec<u8> = (0..100).collect();
        let b: Vec<u8> = (0..100).map(|i: u8| 255 - i).collect();
        for len in [0usize, 1, 7, 8, 31, 32, 33, 99, 100] {
            let mut out = [0x5a; 100];
            select::ct_select_bytes(1, &a[..len], &b[..len], &mut out[..len]);
            assert_eq!(&out[..len], &a[..len], "len {len}, flag 1");
            assert!(
                out[len..].iter().all(|x| *x == 0x5a),
                "len {len}: wrote past the end"
            );
            select::ct_select_bytes(0, &a[..len], &b[..len], &mut out[..len]);
            assert_eq!(&out[..len], &b[..len], "len {len}, flag 0");
        }
        // The walk stops at the shortest slice.
        let mut out = [0u8; 8];
        select::ct_select_bytes(1, &a[..4], &b[..8], &mut out);
        assert_eq!(out, [0, 1, 2, 3, 0, 0, 0, 0]);
    }

    #[test]
    fn fixed_size_comparisons_see_a_change_in_every_byte() {
        let a: [u8; 32] = core::array::from_fn(|i| u8::try_from(i).unwrap().wrapping_mul(7));
        assert!(commit_eq(&a, &a));
        assert!(mac_eq(&a, &a));
        for at in 0..32 {
            for bit in 0..8 {
                let mut b = a;
                b[at] ^= 1 << bit;
                assert!(!commit_eq(&a, &b), "commit byte {at} bit {bit}");
                assert!(!mac_eq(&a, &b), "mac byte {at} bit {bit}");
                assert!(!ct_eq(&a, &b), "ct_eq byte {at} bit {bit}");
            }
        }
    }

    #[test]
    fn strings_of_different_length_are_unequal() {
        assert!(ct_eq(b"", b""));
        assert!(ct_eq(b"abc", b"abc"));
        assert!(!ct_eq(b"abc", b"abcd"));
        assert!(!ct_eq(b"abcd", b"abc"));
        assert!(!ct_eq(b"", b"a"));
    }
}
