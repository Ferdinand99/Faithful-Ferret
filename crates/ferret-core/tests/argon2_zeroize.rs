//! Argon2id: the `zeroize` feature of the `argon2` crate is on, and the
//! 64 MiB memory matrix is zero when it is freed.
//!
//! The core wipes the matrix itself (`prim::argon2::derive` allocates the
//! blocks in a `Zeroizing<Vec<Block>>`). To see that without reading freed
//! memory, this test binary installs a global allocator that, when the
//! matrix-sized allocation is freed, looks at every byte first.

#![allow(unsafe_code)]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]

use ferret_core::KDF_FLOOR;
use ferret_core::testing::prim::argon2id;
use std::alloc::{GlobalAlloc, Layout, System};
use std::process::Command;
use std::sync::atomic::{AtomicUsize, Ordering};

/// The size of the Argon2id matrix at the floor: 64 MiB.
const MATRIX: usize = 64 * 1024 * 1024;

/// How many allocations of exactly [`MATRIX`] bytes were freed, and how many
/// of those still held a non-zero byte.
static FREED: AtomicUsize = AtomicUsize::new(0);
static FREED_DIRTY: AtomicUsize = AtomicUsize::new(0);

struct Watching;

// SAFETY: every call is forwarded to `System`; `dealloc` only reads the block
// before it hands it back.
unsafe impl GlobalAlloc for Watching {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        // SAFETY: same contract as the caller's.
        unsafe { System.alloc(layout) }
    }
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        if layout.size() == MATRIX {
            // SAFETY: the block is still allocated and `size` bytes long;
            // reading raw bytes of it is fine for any content.
            let dirty = unsafe { std::slice::from_raw_parts(ptr, MATRIX) }
                .iter()
                .any(|b| *b != 0);
            FREED.fetch_add(1, Ordering::SeqCst);
            if dirty {
                FREED_DIRTY.fetch_add(1, Ordering::SeqCst);
            }
        }
        // SAFETY: same contract as the caller's.
        unsafe { System.dealloc(ptr, layout) }
    }
    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        // SAFETY: same contract as the caller's.
        unsafe { System.alloc_zeroed(layout) }
    }
    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        // SAFETY: same contract as the caller's.
        unsafe { System.realloc(ptr, layout, new_size) }
    }
}

#[global_allocator]
static ALLOCATOR: Watching = Watching;

/// One test body, so that nothing else in this binary allocates 64 MiB at the
/// same time.
#[test]
fn argon2_zeroize_feature_enabled() {
    // 1. The feature is on in the graph that is released (normal edges, not
    //    the dev-only argon2 0.5.3).
    let out = Command::new(env!("CARGO"))
        .args(["tree", "--manifest-path"])
        .arg(concat!(env!("CARGO_MANIFEST_DIR"), "/Cargo.toml"))
        .args([
            "-p",
            "ferret-core",
            "-e",
            "normal,features",
            "-i",
            "argon2@0.6.0",
        ])
        .output()
        .unwrap();
    let tree = String::from_utf8_lossy(&out.stdout).into_owned();
    assert!(
        out.status.success(),
        "cargo tree failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        tree.contains("argon2 feature \"zeroize\""),
        "argon2/zeroize is off:\n{tree}"
    );

    // 2. The detector works: a 64 MiB buffer full of 0xff is seen as dirty
    //    when freed, a zeroed one is not.
    let freed = FREED.load(Ordering::SeqCst);
    let dirty = FREED_DIRTY.load(Ordering::SeqCst);
    drop(vec![0xffu8; MATRIX]);
    assert_eq!(FREED.load(Ordering::SeqCst), freed + 1);
    assert_eq!(FREED_DIRTY.load(Ordering::SeqCst), dirty + 1, "control");
    drop(vec![0u8; MATRIX]);
    assert_eq!(FREED.load(Ordering::SeqCst), freed + 2);
    assert_eq!(FREED_DIRTY.load(Ordering::SeqCst), dirty + 1, "control");

    // 3. One Argon2id run at the floor (64 MiB, t = 3, p = 1) frees exactly
    //    one matrix, and every byte of it is zero at that moment.
    let freed = FREED.load(Ordering::SeqCst);
    let dirty = FREED_DIRTY.load(Ordering::SeqCst);
    let mut out = [0u8; 32];
    argon2id(
        b"synthetic password",
        b"synthetic salt 16",
        KDF_FLOOR,
        &mut out,
    )
    .unwrap();
    assert!(out.iter().any(|b| *b != 0), "the run produced output");
    assert_eq!(
        FREED.load(Ordering::SeqCst),
        freed + 1,
        "exactly one 64 MiB matrix was allocated and freed"
    );
    assert_eq!(
        FREED_DIRTY.load(Ordering::SeqCst),
        dirty,
        "the Argon2 memory matrix still held bytes when it was freed"
    );
}
