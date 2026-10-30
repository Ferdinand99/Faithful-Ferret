//! The content of a sealed login state wipes the session key and the expected
//! MAC when it is dropped.
//!
//! The crate is `forbid(unsafe_code)`; reading the bytes after the drop needs
//! `unsafe`, which lives here. The probe builds the content, hands out a
//! pointer to its `ServerLogin` bytes, drops the content in place and hands
//! out the same pointer again. The memory is still allocated: the content sits
//! in a vector that keeps its buffer.

#![allow(unsafe_code)]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]

use ferret_core::secret::WipePhase;
use ferret_server_auth::testing::state_plain_wipe_probe;

fn read(ptr: *const u8, len: usize) -> Vec<u8> {
    (0..len)
        // SAFETY: the probe keeps the allocation alive until it returns, and
        // `len` is the length of the array that `ptr` points into.
        .map(|i| unsafe { ptr.add(i).read_volatile() })
        .collect()
}

#[test]
fn state_plain_zeroizes_on_drop() {
    for fill in [0xa5u8, 0x01, 0xff] {
        let mut seen: Vec<(WipePhase, Vec<u8>)> = Vec::new();
        state_plain_wipe_probe(fill, &mut |phase, ptr, len| {
            assert_eq!(len, 128);
            seen.push((phase, read(ptr, len)));
        });
        assert_eq!(seen.len(), 2, "the probe reads before and after");
        let (before_phase, before) = &seen[0];
        let (after_phase, after) = &seen[1];
        assert_eq!(*before_phase, WipePhase::Before);
        assert_eq!(*after_phase, WipePhase::After);
        assert_eq!(before, &vec![fill; 128], "the state holds its bytes alive");
        assert!(
            after.iter().all(|b| *b == 0),
            "the ServerLogin bytes are not wiped on drop: {after:02x?}"
        );
    }
}

/// The probe is not vacuous: the same steps on a plain array show the bytes
/// still there after the drop.
#[test]
fn the_probe_sees_a_buffer_that_is_not_wiped() {
    struct Plain([u8; 128]);
    let mut held: Vec<Plain> = Vec::with_capacity(1);
    held.push(Plain([0xa5; 128]));
    let ptr = held.first().unwrap().0.as_ptr();
    assert_eq!(read(ptr, 128), vec![0xa5; 128]);
    held.clear();
    assert_eq!(
        read(ptr, 128),
        vec![0xa5; 128],
        "a plain array keeps its bytes"
    );
}
