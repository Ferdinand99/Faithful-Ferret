//! Every secret key type wipes its bytes when it is dropped.
//!
//! `secret_types!` in `src/secret.rs` defines the types and lists them in
//! `SECRET_TYPES` (with `test-support`), so a new type cannot be added
//! without being in this test. The core is `forbid(unsafe_code)`; reading
//! the bytes after the drop needs `unsafe`, which lives here.

#![allow(unsafe_code)]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]

use ferret_core::secret::{SECRET_TYPES, WipePhase};
use std::collections::BTreeSet;
use std::path::Path;

fn read(ptr: *const u8, len: usize) -> Vec<u8> {
    (0..len)
        // SAFETY: the probe keeps the allocation alive until it returns, and
        // `len` is the length of the array that `ptr` points into.
        .map(|i| unsafe { ptr.add(i).read_volatile() })
        .collect()
}

#[test]
fn key_types_zeroize_on_drop_all() {
    assert!(!SECRET_TYPES.is_empty());
    let mut names = BTreeSet::new();
    for entry in SECRET_TYPES {
        assert!(names.insert(entry.name), "{} is listed twice", entry.name);
        for fill in [0xa5u8, 0x01, 0xff] {
            let mut seen: Vec<(WipePhase, Vec<u8>)> = Vec::new();
            (entry.wipe_probe)(fill, &mut |phase, ptr, len| {
                assert_eq!(len, entry.len, "{}", entry.name);
                seen.push((phase, read(ptr, len)));
            });
            assert_eq!(
                seen.len(),
                2,
                "{}: the probe reads before and after",
                entry.name
            );
            let (before_phase, before) = &seen[0];
            let (after_phase, after) = &seen[1];
            assert_eq!(*before_phase, WipePhase::Before);
            assert_eq!(*after_phase, WipePhase::After);
            assert_eq!(
                before,
                &vec![fill; entry.len],
                "{}: the key holds its bytes while alive",
                entry.name
            );
            assert!(
                after.iter().all(|b| *b == 0),
                "{} is not zeroized on drop: {after:02x?}",
                entry.name
            );
        }
    }
}

/// The probe is not vacuous: the same steps on a type that does not wipe on
/// drop show the bytes still there.
#[test]
fn wipe_probe_sees_a_type_that_does_not_wipe() {
    struct Plain([u8; 32]);
    let mut keys: Vec<Plain> = Vec::with_capacity(1);
    keys.push(Plain([0xa5; 32]));
    let ptr = keys.first().unwrap().0.as_ptr();
    assert_eq!(read(ptr, 32), vec![0xa5; 32]);
    keys.clear();
    assert_eq!(
        read(ptr, 32),
        vec![0xa5; 32],
        "a plain array keeps its bytes"
    );
}

/// The registry covers every secret type of `src/secret.rs`: the names in
/// the `secret_types!` list, the `pub struct` lines the macro generates, and
/// the crate-root re-exports all agree with it. A type defined next to the
/// macro, or a `secret_type!` call outside it, fails here.
#[test]
fn secret_type_registry_is_complete() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let secret = std::fs::read_to_string(root.join("secret.rs"))
        .unwrap()
        .replace("\r\n", "\n");
    let lib = std::fs::read_to_string(root.join("lib.rs"))
        .unwrap()
        .replace("\r\n", "\n");

    // `secret_type!(` is called once, inside `secret_types!`.
    assert_eq!(
        secret.matches("secret_type!(").count(),
        1,
        "secret_type! is only for secret_types!"
    );
    // Types written out by hand (a `pub struct` outside the macro bodies).
    let outside = secret
        .lines()
        .filter(|l| l.trim_start().starts_with("pub struct "))
        .filter(|l| !l.contains("$name") && !l.contains("SecretTypeEntry"))
        .count();
    assert_eq!(outside, 0, "a secret type is defined outside secret_types!");

    // The names in the list: lines `    Name, 32;` after `secret_types! {`.
    let list = secret.split("\nsecret_types! {\n").nth(1).unwrap();
    let list = list.split("\n}\n").next().unwrap();
    let listed: BTreeSet<&str> = list
        .lines()
        .filter_map(|l| {
            let (name, len) = l.trim().strip_suffix(';')?.split_once(", ")?;
            len.parse::<usize>().ok()?;
            Some(name)
        })
        .collect();
    let registered: BTreeSet<&str> = SECRET_TYPES.iter().map(|e| e.name).collect();
    assert_eq!(listed, registered);
    assert_eq!(registered.len(), SECRET_TYPES.len());

    // Every one is re-exported at the crate root.
    let exports = lib.split("pub use secret::{").nth(1).unwrap();
    let exports = exports.split("};").next().unwrap();
    let exported: BTreeSet<&str> = exports
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .collect();
    assert_eq!(exported, registered);
}
