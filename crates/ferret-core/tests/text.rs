//! Password text: NFKD with the Unicode 16.0 tables, the character and length
//! rules, the OPAQUE input and the export password, plus the generated
//! vectors in `vectors/internal/unicode.json`.

#![allow(unsafe_code)]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]

use ferret_core::testing::text::{
    export_password_bytes, master_password_bytes, opaque_input_bytes,
};
use ferret_core::testing::vector::{self, Case, Outcome};
use ferret_core::testing::{ReplayRng, TestRng, hex_decode, hex_encode};
use ferret_core::text::unicode::{
    CATEGORY_UNICODE_VERSION, MAX_BYTES, MAX_SCALARS, UNICODE_VERSION, is_allowed, is_assigned,
    nfkd,
};
use ferret_core::{
    Error, ExportPassword, InputError, MasterPassword, MpPolicy, OpaqueInput, SecretKey,
};
use serde_json::{Value, json};
use static_assertions::{assert_impl_all, assert_not_impl_any};
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use zeroize::{Zeroize, ZeroizeOnDrop};

fn vectors_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../vectors")
}

fn too_short() -> Error {
    Error::InvalidInput(InputError::TooShort)
}
fn too_long() -> Error {
    Error::InvalidInput(InputError::TooLong)
}
fn forbidden() -> Error {
    Error::InvalidInput(InputError::ForbiddenCharacter)
}
fn not_utf8() -> Error {
    Error::InvalidInput(InputError::NotUtf8)
}

fn mp(text: &str, policy: MpPolicy) -> Result<MasterPassword, Error> {
    MasterPassword::new(text.as_bytes(), policy)
}

fn mp_bytes(text: &str) -> Vec<u8> {
    master_password_bytes(&mp(text, MpPolicy::WithSecretKey).unwrap())
}

// ------------------------------------------------------- the locked tables

#[test]
fn unicode_version_is_16_0() {
    assert_eq!(UNICODE_VERSION, (16, 0, 0), "NFKD tables");
    assert_eq!(CATEGORY_UNICODE_VERSION, (16, 0, 0), "general categories");

    // The versions come from exact pins; Cargo.lock must agree with them.
    let lock =
        std::fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("../../Cargo.lock"))
            .unwrap();
    for (name, version) in [
        ("unicode-normalization", "0.1.24"),
        ("unicode-general-category", "1.1.0"),
    ] {
        let want = format!("name = \"{name}\"\nversion = \"{version}\"");
        assert!(
            lock.replace("\r\n", "\n").contains(&want),
            "Cargo.lock must pin {name} {version}"
        );
    }
}

#[test]
fn unicode_17_characters_are_unassigned() {
    // First assigned in Unicode 17.0; unassigned in the locked 16.0 tables.
    for c in ['\u{20C1}', '\u{323B0}', '\u{10940}'] {
        assert!(!is_assigned(c), "{c:?}");
    }
    // Assigned in 16.0 (the last additions of that version are the Garay
    // block).
    for c in ['a', '\u{00E5}', '\u{1F600}', '\u{10D40}', '\u{1CC00}'] {
        assert!(is_assigned(c), "{c:?}");
    }
}

#[test]
fn nfkd_of_allowed_text_is_allowed_for_every_scalar_value() {
    // `normalize_password` checks the characters of the input only. This is
    // the reason that is enough: no allowed character decomposes into a
    // control or unassigned one.
    for value in 0..=0x10_FFFFu32 {
        let Some(c) = char::from_u32(value) else {
            continue;
        };
        if is_allowed(c) {
            let decomposed = nfkd(&c.to_string());
            assert!(
                decomposed.chars().all(is_allowed),
                "NFKD of U+{value:04X} contains a forbidden character"
            );
        }
    }
}

// ---------------------------------------------------------- vector runner

/// The bytes of a text input of a vector case.
fn input_bytes(input: &Value) -> Vec<u8> {
    if let Some(hex) = input.get("utf8") {
        return hex_decode(hex.as_str().unwrap()).unwrap();
    }
    let mut out = String::new();
    for segment in input["segments"].as_array().unwrap() {
        let chars: String = segment["escapes"]
            .as_str()
            .unwrap()
            .split_whitespace()
            .map(|e| {
                let hex = e.strip_prefix("U+").unwrap();
                char::from_u32(u32::from_str_radix(hex, 16).unwrap()).unwrap()
            })
            .collect();
        let repeat = usize::try_from(segment["repeat"].as_u64().unwrap()).unwrap();
        for _ in 0..repeat {
            out.push_str(&chars);
        }
    }
    // The readable `text` of a short case must equal the escapes; an editor
    // that normalized the file would break exactly this.
    if let Some(text) = input.get("text") {
        assert_eq!(text.as_str().unwrap(), out, "text differs from its escapes");
    }
    out.into_bytes()
}

fn policy_of(input: &Value) -> MpPolicy {
    match input["policy"].as_str().unwrap() {
        "with_secret_key" => MpPolicy::WithSecretKey,
        "without_secret_key" => MpPolicy::WithoutSecretKey,
        other => panic!("unknown policy {other}"),
    }
}

fn run_case(case: &Case) -> Result<Outcome, Error> {
    let bytes = input_bytes(&case.input);
    let output = match case.op.as_str() {
        "text.nfkd" => {
            let text = String::from_utf8(bytes).expect("nfkd cases are valid UTF-8");
            json!({ "nfkd": hex_encode(nfkd(&text).as_bytes()) })
        }
        "text.mp" => {
            let mp = MasterPassword::new(&bytes, policy_of(&case.input))?;
            json!({ "mp": hex_encode(&master_password_bytes(&mp)) })
        }
        "text.opaque_input" => {
            let mp = MasterPassword::new(&bytes, policy_of(&case.input))?;
            let sk = match case.input["secret_key"].as_str() {
                Some(hex) => {
                    let key: [u8; 16] = hex_decode(hex).unwrap().try_into().unwrap();
                    Some(SecretKey::from_test_bytes(key))
                }
                None => None,
            };
            let input = mp.opaque_input(sk.as_ref());
            json!({ "opaque_input": hex_encode(&opaque_input_bytes(&input)) })
        }
        "text.export_password" => {
            let master = match case.input.get("master_password") {
                Some(Value::Null) | None => None,
                Some(other) => Some(MasterPassword::new(
                    &input_bytes(other),
                    MpPolicy::WithSecretKey,
                )?),
            };
            let pw = ExportPassword::new(&bytes, master.as_ref())?;
            json!({ "export_password": hex_encode(&export_password_bytes(&pw)) })
        }
        other => panic!("unknown op {other}"),
    };
    Ok(Outcome {
        output,
        intermediate: None,
    })
}

#[test]
fn nfkd_vectors_from_file() {
    let file = vector::load(&vectors_dir().join("internal/unicode.json")).unwrap();
    assert!(
        file.cases.len() >= 45,
        "the plan asks for at least 45 cases"
    );
    let report = vector::run_all(&file, |case: &Case, _rng: &mut ReplayRng| run_case(case));
    assert!(report.failures.is_empty(), "{:?}", report.failures);
    assert_eq!(report.passed, file.cases.len());

    // Every operation and every error code of this group is covered.
    let ops: BTreeSet<&str> = file.cases.iter().map(|c| c.op.as_str()).collect();
    assert_eq!(
        ops,
        BTreeSet::from([
            "text.export_password",
            "text.mp",
            "text.nfkd",
            "text.opaque_input"
        ])
    );
    let errors: BTreeSet<&str> = file
        .cases
        .iter()
        .filter_map(|c| c.expect_error.as_deref())
        .collect();
    assert_eq!(
        errors,
        BTreeSet::from([
            "input_forbidden_character",
            "input_not_utf8",
            "input_same_as_master_password",
            "input_too_long",
            "input_too_short",
        ])
    );
}

#[test]
fn nfkd_known_answers_in_the_test_itself() {
    // Written out here, apart from the vector file.
    assert_eq!(&*nfkd("\u{FB01}"), "fi");
    assert_eq!(&*nfkd("\u{FF11}\u{FF12}\u{FF13}"), "123");
    assert_eq!(&*nfkd("\u{212B}"), "A\u{030A}");
    assert_eq!(&*nfkd("\u{2126}"), "\u{03A9}");
    assert_eq!(&*nfkd("\u{D55C}"), "\u{1112}\u{1161}\u{11AB}");
    assert_eq!(&*nfkd("a\u{0301}\u{0323}"), "a\u{0323}\u{0301}");
    // NFC and NFD of the Norwegian letters give equal bytes.
    assert_eq!(
        nfkd("\u{00E6}\u{00F8}\u{00E5}").as_bytes(),
        nfkd("\u{00E6}\u{00F8}a\u{030A}").as_bytes()
    );
    assert_eq!(
        mp_bytes(
            "\u{00E6}\u{00F8}\u{00E5}\u{00E6}\u{00F8}\u{00E5}\u{00E6}\u{00F8}\u{00E5}\u{00E6}\u{00F8}\u{00E5}"
        ),
        mp_bytes(
            "\u{00E6}\u{00F8}a\u{030A}\u{00E6}\u{00F8}a\u{030A}\u{00E6}\u{00F8}a\u{030A}\u{00E6}\u{00F8}a\u{030A}"
        )
    );
}

// ------------------------------------------------------------ master password

#[test]
fn mp_rejects_control_and_unassigned() {
    let around = |c: char| format!("abcdef{c}ghijkl");
    for (c, why) in [
        ('\u{0000}', "U+0000"),
        ('\u{0009}', "tab"),
        ('\u{0085}', "U+0085 (Cc)"),
        ('\u{007F}', "delete"),
        ('\u{0378}', "U+0378 (Cn)"),
        ('\u{FFFF}', "U+FFFF"),
        ('\u{FDD0}', "U+FDD0"),
        ('\u{10FFFF}', "U+10FFFF"),
        ('\u{20C1}', "first assigned in Unicode 17"),
        ('\u{323B0}', "first assigned in Unicode 17"),
    ] {
        for policy in [MpPolicy::WithSecretKey, MpPolicy::WithoutSecretKey] {
            assert_eq!(
                mp(&around(c), policy).err(),
                Some(forbidden()),
                "{why} with {policy:?}"
            );
        }
    }
    // Neighbours that are fine.
    for c in [
        ' ',
        '\u{00A0}',
        '\u{200D}',
        '\u{00AD}',
        '\u{E000}',
        '\u{1F600}',
    ] {
        assert!(mp(&around(c), MpPolicy::WithSecretKey).is_ok(), "{c:?}");
    }
}

#[test]
fn mp_length_rules() {
    let n = |count: usize| "a".repeat(count);
    // The minimum: 12 with a secret key, 15 without.
    assert_eq!(mp(&n(11), MpPolicy::WithSecretKey).err(), Some(too_short()));
    assert!(mp(&n(12), MpPolicy::WithSecretKey).is_ok());
    assert_eq!(
        mp(&n(14), MpPolicy::WithoutSecretKey).err(),
        Some(too_short())
    );
    assert!(mp(&n(15), MpPolicy::WithoutSecretKey).is_ok());
    assert_eq!(MpPolicy::WithSecretKey.min_len(), 12);
    assert_eq!(MpPolicy::WithoutSecretKey.min_len(), 15);
    assert_eq!(mp("", MpPolicy::WithSecretKey).err(), Some(too_short()));

    // The minimum is counted in NFC scalars (U9): eleven a-with-ring are
    // eleven characters in NFC and in NFD, though NFD has 22 scalars.
    let nfd_a_ring = "a\u{030A}";
    assert_eq!(
        mp(&nfd_a_ring.repeat(11), MpPolicy::WithSecretKey).err(),
        Some(too_short())
    );
    assert!(mp(&nfd_a_ring.repeat(12), MpPolicy::WithSecretKey).is_ok());
    assert_eq!(
        mp(&"\u{00E5}".repeat(11), MpPolicy::WithSecretKey).err(),
        Some(too_short())
    );
    // Ligatures are one character each, though NFKD makes two scalars.
    assert_eq!(
        mp(&"\u{FB01}".repeat(11), MpPolicy::WithSecretKey).err(),
        Some(too_short())
    );

    // The maximum: 1 024 scalars and 4 096 bytes, measured after NFKD.
    assert!(mp(&n(MAX_SCALARS), MpPolicy::WithSecretKey).is_ok());
    assert_eq!(
        mp(&n(MAX_SCALARS + 1), MpPolicy::WithSecretKey).err(),
        Some(too_long())
    );
    let emoji = "\u{1F600}"; // four bytes
    let at_limit = mp(&emoji.repeat(MAX_SCALARS), MpPolicy::WithSecretKey).unwrap();
    assert_eq!(master_password_bytes(&at_limit).len(), MAX_BYTES);
    assert_eq!(
        mp(&emoji.repeat(MAX_SCALARS + 1), MpPolicy::WithSecretKey).err(),
        Some(too_long())
    );
    // NFKD counts: 600 ligatures are 1 200 scalars; 513 e-acute are 1 026.
    assert_eq!(
        mp(&"\u{FB01}".repeat(600), MpPolicy::WithSecretKey).err(),
        Some(too_long())
    );
    assert!(mp(&"\u{00E9}".repeat(512), MpPolicy::WithSecretKey).is_ok());
    assert_eq!(
        mp(&"\u{00E9}".repeat(513), MpPolicy::WithSecretKey).err(),
        Some(too_long())
    );
    // A very long input is rejected without building its NFKD.
    let huge = "a".repeat(5_000_000);
    assert_eq!(mp(&huge, MpPolicy::WithSecretKey).err(), Some(too_long()));
}

#[test]
fn long_runs_of_combining_marks_are_bounded() {
    // The normalizer holds a run of combining marks until the next starter.
    // The scalar limit is checked on the input first, so the run never gets
    // there: this returns at once and allocates no big buffer.
    let started = std::time::Instant::now();
    let bomb = format!("a{}", "\u{0301}".repeat(1_000_000));
    for policy in [MpPolicy::WithSecretKey, MpPolicy::WithoutSecretKey] {
        assert_eq!(mp(&bomb, policy).err(), Some(too_long()));
    }
    assert_eq!(
        MasterPassword::for_unlock(bomb.as_bytes()).err(),
        Some(too_long())
    );
    assert_eq!(
        ExportPassword::new(bomb.as_bytes(), None).err(),
        Some(too_long())
    );
    // The same with marks that decompose further, and with a run of 1 025
    // scalars, the smallest case that must be refused.
    let marks = format!("a{}", "\u{0344}".repeat(500_000));
    assert_eq!(mp(&marks, MpPolicy::WithSecretKey).err(), Some(too_long()));
    let edge = format!("a{}", "\u{0301}".repeat(1_024));
    assert_eq!(mp(&edge, MpPolicy::WithSecretKey).err(), Some(too_long()));
    assert!(
        started.elapsed() < std::time::Duration::from_secs(5),
        "took {:?}",
        started.elapsed()
    );

    // A run that fits is accepted: 1 000 marks, 1 001 scalars after NFKD.
    let fits = format!("a{}", "\u{0301}".repeat(1_000));
    let ok = mp(&fits, MpPolicy::WithSecretKey).unwrap();
    assert_eq!(master_password_bytes(&ok).len(), 1 + 2 * 1_000);
    // And exactly 1 024 scalars is the limit.
    let limit = format!("a{}", "\u{0301}".repeat(1_023));
    assert!(mp(&limit, MpPolicy::WithSecretKey).is_ok());
}

#[test]
fn nfkd_allocates_once() {
    // Exact size first: the capacity of the result is its length, also when
    // NFKD is longer than the input in UTF-8.
    for text in ["\u{00E5}", "a\u{030A}", "\u{FDFA}", "\u{FB03}", "plain", ""] {
        let out = nfkd(text);
        assert_eq!(out.capacity(), out.len(), "{text:?}");
    }
}

#[test]
fn unlock_and_open_have_no_minimum() {
    // The creation floor applies when a password is created or changed.
    for short in ["a", "abcdefghijk", "a\u{030A}"] {
        assert_eq!(mp(short, MpPolicy::WithSecretKey).err(), Some(too_short()));
        assert_eq!(
            ExportPassword::new(short.as_bytes(), None).err(),
            Some(too_short())
        );
        assert!(MasterPassword::for_unlock(short.as_bytes()).is_ok());
        assert!(ExportPassword::for_open(short.as_bytes()).is_ok());
    }
    // Same bytes as the creation path when both accept.
    let text = "\u{00E5}\u{FB01}\u{FF11}abcdefghi";
    assert_eq!(
        master_password_bytes(&MasterPassword::for_unlock(text.as_bytes()).unwrap()),
        mp_bytes(text)
    );
    assert_eq!(
        export_password_bytes(&ExportPassword::for_open(text.as_bytes()).unwrap()),
        export_password_bytes(&ExportPassword::new(text.as_bytes(), None).unwrap())
    );
    // The maximum and the character rules still hold.
    let mut bad_utf8 = b"abc".to_vec();
    bad_utf8.push(0xff);
    for result in [
        MasterPassword::for_unlock(&bad_utf8).map(|_| ()),
        ExportPassword::for_open(&bad_utf8).map(|_| ()),
    ] {
        assert_eq!(result.err(), Some(not_utf8()));
    }
    for result in [
        MasterPassword::for_unlock(b"abc\tdef").map(|_| ()),
        ExportPassword::for_open(b"abc\0def").map(|_| ()),
        MasterPassword::for_unlock("abc\u{0378}".as_bytes()).map(|_| ()),
    ] {
        assert_eq!(result.err(), Some(forbidden()));
    }
    let long = "a".repeat(MAX_SCALARS + 1);
    assert_eq!(
        MasterPassword::for_unlock(long.as_bytes()).err(),
        Some(too_long())
    );
    assert_eq!(
        ExportPassword::for_open(long.as_bytes()).err(),
        Some(too_long())
    );
    let ok = "a".repeat(MAX_SCALARS);
    assert!(MasterPassword::for_unlock(ok.as_bytes()).is_ok());
    assert!(ExportPassword::for_open(ok.as_bytes()).is_ok());
    // Opening does not compare with the master password.
    let master = mp("abcdefghijkl", MpPolicy::WithSecretKey).unwrap();
    assert_eq!(
        ExportPassword::new(b"abcdefghijkl", Some(&master)).err(),
        Some(Error::InvalidInput(InputError::SameAsMasterPassword))
    );
    assert!(ExportPassword::for_open(b"abcdefghijkl").is_ok());
}

#[test]
fn mp_error_precedence() {
    // not UTF-8, then forbidden characters, then too long, then too short.
    let mut bad = b"a\tb".to_vec();
    bad.push(0xff);
    assert_eq!(
        MasterPassword::new(&bad, MpPolicy::WithSecretKey).err(),
        Some(not_utf8())
    );
    assert_eq!(
        mp(&format!("\t{}", "a".repeat(2_000)), MpPolicy::WithSecretKey).err(),
        Some(forbidden())
    );
    assert_eq!(mp("a\tb", MpPolicy::WithSecretKey).err(), Some(forbidden()));
}

#[test]
fn mp_invalid_utf8_rejected() {
    for bytes in [
        &[0xff][..],
        &[0xc0, 0xaf],
        &[0xed, 0xa0, 0x80],       // an encoded surrogate
        &[0xe2, 0x82],             // truncated
        &[0xf4, 0x90, 0x80, 0x80], // above U+10FFFF
        &[0x80],
    ] {
        let mut input = b"abcdefghijkl".to_vec();
        input.extend_from_slice(bytes);
        assert_eq!(
            MasterPassword::new(&input, MpPolicy::WithSecretKey).err(),
            Some(not_utf8()),
            "{bytes:02x?}"
        );
    }
}

// --------------------------------------------------------------- OPAQUE input

#[test]
fn opaque_input_with_sk_is_mp_00_sk() {
    let pw = mp("correct horse battery", MpPolicy::WithSecretKey).unwrap();
    let sk_bytes: [u8; 16] = core::array::from_fn(|i| u8::try_from(i).unwrap() + 0x10);
    let sk = SecretKey::from_test_bytes(sk_bytes);

    let with = opaque_input_bytes(&pw.opaque_input(Some(&sk)));
    let mut want = b"correct horse battery".to_vec();
    want.push(0x00);
    want.extend_from_slice(&sk_bytes);
    assert_eq!(with, want);
    assert_eq!(with.len(), 21 + 1 + 16);

    let without = opaque_input_bytes(&pw.opaque_input(None));
    assert_eq!(without, b"correct horse battery");

    // The separator is unambiguous: the password never has a zero byte.
    assert!(!master_password_bytes(&pw).contains(&0));

    // A secret key with leading zero bytes is still 16 bytes after the 0x00.
    let zero_sk = SecretKey::from_test_bytes([0; 16]);
    let with_zero = opaque_input_bytes(&pw.opaque_input(Some(&zero_sk)));
    assert_eq!(with_zero.len(), 21 + 1 + 16);
    assert!(with_zero[21..].iter().all(|b| *b == 0));
}

#[test]
fn opaque_input_uses_the_normalized_password() {
    let a = mp("\u{00E5}\u{FB01}\u{FF11}abcdefghi", MpPolicy::WithSecretKey).unwrap();
    assert_eq!(
        opaque_input_bytes(&a.opaque_input(None)),
        "a\u{030A}fi1abcdefghi".as_bytes()
    );
}

// ----------------------------------------------------------------- wiping

assert_impl_all!(MasterPassword: Zeroize, ZeroizeOnDrop);
assert_impl_all!(OpaqueInput: Zeroize, ZeroizeOnDrop);
assert_impl_all!(ExportPassword: Zeroize, ZeroizeOnDrop);
assert_not_impl_any!(
    MasterPassword: Clone, Copy, core::fmt::Debug, core::fmt::Display, PartialEq, Eq,
    core::hash::Hash, serde::Serialize
);
assert_not_impl_any!(
    OpaqueInput: Clone, Copy, core::fmt::Debug, core::fmt::Display, PartialEq, Eq,
    core::hash::Hash, serde::Serialize
);
assert_not_impl_any!(
    ExportPassword: Clone, Copy, core::fmt::Debug, core::fmt::Display, PartialEq, Eq,
    core::hash::Hash, serde::Serialize
);

/// Reads `len` bytes at `ptr`.
///
/// # Safety
/// `ptr` must point to `len` initialized bytes of a live allocation.
unsafe fn read(ptr: *const u8, len: usize) -> Vec<u8> {
    // SAFETY: the caller guarantees the range; volatile so that the read
    // cannot be removed or reordered against the wipe.
    (0..len)
        .map(|i| unsafe { ptr.add(i).read_volatile() })
        .collect()
}

#[test]
fn mp_zeroized_on_drop() {
    // `ZeroizeOnDrop` is asserted above for the three types. Here, the wipe
    // itself: the whole buffer (the length and the spare capacity) is zero
    // afterwards, and the buffer was big enough from the start, so the
    // password was never copied to a larger one while it grew.
    let mut pw = mp("correct horse battery staple", MpPolicy::WithSecretKey).unwrap();
    let (ptr, cap) = pw.test_buffer();
    assert_eq!(cap, MAX_BYTES, "reserved once, no regrowth");
    // SAFETY: the buffer is alive and the first `len` bytes are initialized.
    let before = unsafe { read(ptr, 28) };
    assert_eq!(before, b"correct horse battery staple");
    pw.zeroize();
    // SAFETY: `zeroize` keeps the allocation and writes zeros over all of
    // its capacity, so every byte is initialized; `pw` is still alive.
    let after = unsafe { read(ptr, cap) };
    assert!(after.iter().all(|b| *b == 0), "MasterPassword not wiped");
    drop(pw);

    let pw = mp("correct horse battery staple", MpPolicy::WithSecretKey).unwrap();
    let sk = SecretKey::from_test_bytes([0x55; 16]);
    let mut input = pw.opaque_input(Some(&sk));
    let (ptr, cap) = input.test_buffer();
    assert_eq!(cap, 28 + 1 + 16, "sized exactly, no regrowth");
    // SAFETY: as above.
    let before = unsafe { read(ptr, cap) };
    assert_eq!(&before[29..], &[0x55; 16]);
    input.zeroize();
    // SAFETY: as above.
    let after = unsafe { read(ptr, cap) };
    assert!(after.iter().all(|b| *b == 0), "OpaqueInput not wiped");
}

// -------------------------------------------------------- export password

#[test]
fn export_password_rules() {
    let rules = |text: &str, master: Option<&MasterPassword>| {
        ExportPassword::new(text.as_bytes(), master).map(|p| export_password_bytes(&p))
    };
    // At least 12 characters, NFC-counted.
    assert_eq!(rules("abcdefghijk", None).err(), Some(too_short()));
    assert_eq!(rules("abcdefghijkl", None).unwrap(), b"abcdefghijkl");
    assert_eq!(
        rules(&"a\u{030A}".repeat(11), None).err(),
        Some(too_short())
    );
    // Same NFKD, same rejections.
    assert_eq!(
        rules("\u{00E5}\u{FB01}\u{FF11}abcdefghi", None).unwrap(),
        "a\u{030A}fi1abcdefghi".as_bytes()
    );
    assert_eq!(rules("abcdef\tghijkl", None).err(), Some(forbidden()));
    assert_eq!(
        ExportPassword::new(&[b'a', 0xff], None).err(),
        Some(not_utf8())
    );
    assert_eq!(rules(&"a".repeat(1_025), None).err(), Some(too_long()));
    assert!(rules(&"a".repeat(1_024), None).is_ok());

    // Not equal to the master password, compared after normalization.
    let master = mp("\u{00E5}abcdefghijk", MpPolicy::WithSecretKey).unwrap();
    let same = Error::InvalidInput(InputError::SameAsMasterPassword);
    assert_eq!(
        rules("\u{00E5}abcdefghijk", Some(&master)).err(),
        Some(same)
    );
    assert_eq!(
        rules("a\u{030A}abcdefghijk", Some(&master)).err(),
        Some(same),
        "NFD of the same text"
    );
    assert!(rules("\u{00E5}abcdefghijl", Some(&master)).is_ok());
    assert!(rules("\u{00E5}abcdefghijk", None).is_ok());
    // Too short wins over equal only when the text is short; an equal text
    // that is long enough is the equality error.
    let master = mp("abcdefghijkl", MpPolicy::WithSecretKey).unwrap();
    assert_eq!(rules("abcdefghijkl", Some(&master)).err(), Some(same));
}

#[test]
fn error_codes_of_the_new_variants() {
    assert_eq!(
        Error::InvalidInput(InputError::SameAsMasterPassword).code(),
        "input_same_as_master_password"
    );
    assert_eq!(
        Error::Malformed(ferret_core::MalformedKind::Code).code(),
        "malformed_code"
    );
}

// A TestRng-made secret key works as the second factor (smoke test of the
// public path used by the account flows later).
#[test]
fn generated_secret_key_in_the_opaque_input() {
    let mut rng = TestRng::new(b"text-smoke");
    let sk = SecretKey::generate(&mut rng);
    let pw = mp("correct horse battery", MpPolicy::WithSecretKey).unwrap();
    let input = opaque_input_bytes(&pw.opaque_input(Some(&sk)));
    assert_eq!(input.len(), 21 + 1 + 16);
    assert_eq!(input[21], 0);
}
