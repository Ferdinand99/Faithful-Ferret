//! Tests of the workspace skeleton: secret types, RNGs, error codes, the
//! vector framework and the vector generator.
//!
//! The core itself has `#![forbid(unsafe_code)]`. The one test that must read
//! freed-looking memory lives here, in a separate test crate.

#![allow(unsafe_code)]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]

use ferret_core::testing::vector::{self, Outcome};
use ferret_core::testing::{ReplayError, hex_decode, hex_encode};
use ferret_core::{
    AuthSeed, Error, ExportContentKey, ExportKey, ItemKey, KDel, KHead, KMeta, Kek, KekDevPin,
    OsRng, PrfOutput, PrfSeed, RecoveryKey, ReplayRng, SecretKey, SecureRng, TestRng, VaultKey,
};
use serde_json::json;
use static_assertions::assert_not_impl_any;
use std::collections::BTreeSet;
use std::mem::{ManuallyDrop, size_of};
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::path::{Path, PathBuf};
use subtle::ConstantTimeEq;

fn vectors_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../vectors")
}

// ---------------------------------------------------------------- secrets

macro_rules! assert_secret {
    ($($t:ty),+ $(,)?) => {
        $(assert_not_impl_any!(
            $t: Clone, Copy, core::fmt::Debug, core::fmt::Display, PartialEq, Eq,
            core::hash::Hash, serde::Serialize
        );)+
    };
}

#[test]
fn secret_types_are_not_clone_or_debug() {
    assert_secret!(
        VaultKey,
        ItemKey,
        Kek,
        KekDevPin,
        RecoveryKey,
        SecretKey,
        ExportKey,
        PrfOutput,
        PrfSeed,
        KHead,
        KDel,
        KMeta,
        AuthSeed,
        ExportContentKey,
    );
}

/// Drops a heap value in place (without freeing the allocation, so the
/// allocator cannot overwrite the bytes) and reads the bytes back.
fn bytes_before_and_after_drop<T>(value: T) -> (Vec<u8>, Vec<u8>) {
    let slot: *mut ManuallyDrop<T> = Box::into_raw(Box::new(ManuallyDrop::new(value)));
    let base = slot.cast::<u8>();
    let read = || -> Vec<u8> {
        (0..size_of::<T>())
            // SAFETY: the allocation behind `slot` lives until `Box::from_raw`
            // below, and every byte of it is initialized.
            .map(|i| unsafe { base.add(i).read_volatile() })
            .collect()
    };
    let before = read();
    // SAFETY: `slot` is a valid, unique pointer; the value is dropped once.
    unsafe { ManuallyDrop::drop(&mut *slot) };
    let after = read();
    // SAFETY: `slot` came from `Box::into_raw`; `ManuallyDrop` never drops again.
    drop(unsafe { Box::from_raw(slot) });
    (before, after)
}

#[test]
fn secret_type_zeroizes_on_drop() {
    let mut rng = TestRng::new(b"zeroize");

    let (before, after) = bytes_before_and_after_drop(VaultKey::generate(&mut rng));
    assert_eq!(before.len(), 32);
    assert!(before.iter().any(|b| *b != 0), "key was random, not zero");
    assert!(after.iter().all(|b| *b == 0), "VaultKey not zeroized");

    let (before, after) = bytes_before_and_after_drop(SecretKey::generate(&mut rng));
    assert_eq!(before.len(), 16);
    assert!(before.iter().any(|b| *b != 0));
    assert!(after.iter().all(|b| *b == 0), "SecretKey not zeroized");

    let (before, after) = bytes_before_and_after_drop(RecoveryKey::generate(&mut rng));
    assert!(before.iter().any(|b| *b != 0));
    assert!(after.iter().all(|b| *b == 0), "RecoveryKey not zeroized");

    let (before, after) = bytes_before_and_after_drop(ExportKey::from_test_bytes([0xa5; 64]));
    assert_eq!(before, vec![0xa5; 64]);
    assert!(after.iter().all(|b| *b == 0), "ExportKey not zeroized");
}

#[test]
fn secret_ct_eq_works() {
    let a = VaultKey::from_test_bytes([7; 32]);
    let same = VaultKey::from_test_bytes([7; 32]);
    let mut other_bytes = [7; 32];
    other_bytes[31] = 8;
    let other = VaultKey::from_test_bytes(other_bytes);
    assert_eq!(a.ct_eq(&same).unwrap_u8(), 1);
    assert_eq!(a.ct_eq(&other).unwrap_u8(), 0);

    let x = ExportKey::from_test_bytes([1; 64]);
    let y = ExportKey::from_test_bytes([1; 64]);
    assert_eq!(x.ct_eq(&y).unwrap_u8(), 1);

    // Generated through a replayed draw: equal draws give equal keys.
    let mut r1 = ReplayRng::new(vec![vec![9; 16]]);
    let mut r2 = ReplayRng::new(vec![vec![9; 16]]);
    let mut r3 = ReplayRng::new(vec![vec![10; 16]]);
    let (s1, s2, s3) = (
        SecretKey::generate(&mut r1),
        SecretKey::generate(&mut r2),
        SecretKey::generate(&mut r3),
    );
    assert_eq!(s1.ct_eq(&s2).unwrap_u8(), 1);
    assert_eq!(s1.ct_eq(&s3).unwrap_u8(), 0);
}

// ------------------------------------------------------------------- rngs

#[test]
fn os_rng_fills_and_differs() {
    let mut rng = OsRng;
    let mut a = [0u8; 32];
    let mut b = [0u8; 32];
    rng.fill(&mut a);
    rng.fill(&mut b);
    assert_ne!(a, b);
    assert_ne!(a, [0u8; 32]);
    assert_ne!(b, [0u8; 32]);
}

#[test]
fn replay_rng_replays_draws_in_order() {
    let mut rng = ReplayRng::new(vec![vec![1, 2, 3], vec![4, 5]]);
    let mut first = [0u8; 3];
    let mut second = [0u8; 2];
    rng.fill(&mut first);
    rng.fill(&mut second);
    assert_eq!(first, [1, 2, 3]);
    assert_eq!(second, [4, 5]);
    assert_eq!(rng.finish(), Ok(()));
}

#[test]
fn replay_rng_rejects_wrong_length() {
    let mut rng = ReplayRng::new(vec![vec![0xab; 32]]);
    let mut short = [0u8; 24];
    let outcome = catch_unwind(AssertUnwindSafe(|| rng.fill(&mut short)));
    assert!(
        outcome.is_err(),
        "a 24 byte draw against 32 recorded bytes must fail"
    );

    // With no draws left, any draw fails too.
    let mut empty = ReplayRng::new(vec![]);
    let outcome = catch_unwind(AssertUnwindSafe(|| empty.fill(&mut [0u8; 1])));
    assert!(outcome.is_err());

    // The runner turns the panic into a failed case instead of crashing.
    let file = sample_file();
    let report = vector::run_all(&file, |_, rng| {
        let mut wrong = [0u8; 24];
        rng.fill(&mut wrong);
        Ok(Outcome {
            output: json!("ok"),
            intermediate: None,
        })
    });
    assert_eq!(report.passed, 0);
    assert_eq!(report.failures.len(), 2);
}

#[test]
fn replay_rng_requires_exhaustion() {
    let mut rng = ReplayRng::new(vec![vec![1; 32], vec![2; 16]]);
    rng.fill(&mut [0u8; 32]);
    assert_eq!(rng.remaining(), 1);
    assert_eq!(
        rng.finish(),
        Err(ReplayError::NotExhausted { remaining: 1 })
    );

    // The runner reports a case that leaves a recorded draw unused.
    let file = sample_file();
    let report = vector::run_all(&file, |case, _rng| {
        // Does not draw although the case records one draw.
        if case.status == vector::Status::Valid {
            Ok(Outcome {
                output: json!({ "wrap": "00" }),
                intermediate: None,
            })
        } else {
            Err(Error::Decrypt)
        }
    });
    assert_eq!(report.passed, 1, "the invalid case records no draw");
    assert_eq!(report.failures.len(), 1);
    assert!(report.failures[0].reason.contains("not all consumed"));
}

#[test]
fn test_rng_is_deterministic_and_seed_dependent() {
    let draw = |seed: &[u8]| {
        let mut rng = TestRng::new(seed);
        let mut out = [0u8; 100];
        rng.fill(&mut out);
        out
    };
    assert_eq!(draw(b"seed"), draw(b"seed"));
    assert_ne!(draw(b"seed"), draw(b"seed2"));

    // Draw sizes do not change the stream: it is one byte stream.
    let mut a = TestRng::new(b"s");
    let mut b = TestRng::new(b"s");
    let mut whole = [0u8; 70];
    a.fill(&mut whole);
    let (mut p1, mut p2) = ([0u8; 31], [0u8; 39]);
    b.fill(&mut p1);
    b.fill(&mut p2);
    assert_eq!(&whole[..31], &p1);
    assert_eq!(&whole[31..], &p2);
}

#[test]
fn hex_roundtrip_and_strictness() {
    assert_eq!(hex_encode(&[0, 1, 0xab, 0xff]), "0001abff");
    assert_eq!(hex_decode("0001abff").unwrap(), vec![0, 1, 0xab, 0xff]);
    assert!(hex_decode("ABFF").is_err(), "capitals are not allowed");
    assert!(hex_decode("abc").is_err(), "odd length");
    assert!(hex_decode("0x00").is_err(), "no prefix");
    assert!(hex_decode(" 00").is_err(), "no whitespace");
}

// ----------------------------------------------------------------- errors

/// The codes in the first column of the tables in a Markdown file: lines
/// that start with ``| `code` ``.
fn codes_in_table(path: &Path) -> BTreeSet<String> {
    let text = std::fs::read_to_string(path).unwrap();
    text.lines()
        .filter_map(|line| line.strip_prefix("| `"))
        .filter_map(|rest| rest.split_once('`').map(|(code, _)| code.to_string()))
        .collect()
}

#[test]
fn error_codes_are_unique_and_documented() {
    let mut seen = BTreeSet::new();
    for error in Error::ALL {
        let code = error.code();
        assert!(
            code.chars()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_'),
            "code {code} must be snake_case"
        );
        assert!(seen.insert(code), "duplicate error code {code}");
    }
    let documented = codes_in_table(&vectors_dir().join("ERRORS.md"));
    let in_code: BTreeSet<String> = seen.iter().map(|c| (*c).to_string()).collect();
    let missing: Vec<_> = in_code.difference(&documented).collect();
    let stale: Vec<_> = documented.difference(&in_code).collect();
    assert!(
        missing.is_empty(),
        "codes missing from ERRORS.md: {missing:?}"
    );
    assert!(stale.is_empty(), "ERRORS.md lists unknown codes: {stale:?}");
}

#[test]
fn error_display_is_the_code_and_leaks_nothing() {
    for error in Error::ALL {
        assert_eq!(error.to_string(), error.code());
    }
}

// ---------------------------------------------------------------- vectors

fn sample_json() -> String {
    let nonce = "00".repeat(24);
    format!(
        r#"{{
  "format": "ferret-vectors/1",
  "group": "wrap",
  "suite": 1,
  "spec": "Fase 1 § 4.3",
  "generator": {{ "tool": "ferret-vectorgen", "core": "0.1.0", "commit": "abc",
                 "unicode": "16.0.0", "rng": "hmac-sha256-ctr(seed)" }},
  "cases": [
    {{
      "id": "wrap/password/valid/001",
      "title": "password wrap, profile 1",
      "op": "wrap.seal.password",
      "status": "valid",
      "tags": ["slow"],
      "synthetic": true,
      "rng": ["{nonce}"],
      "input": {{ "vk_epoch": "1", "kek_generation": "1", "ksf_profile": 1 }},
      "intermediate": {{ "kek": "00" }},
      "expect": {{ "wrap": "00" }},
      "expect_error": null
    }},
    {{
      "id": "wrap/password/invalid/001",
      "title": "tampered wrap",
      "op": "wrap.open.password",
      "status": "invalid",
      "tags": [],
      "synthetic": true,
      "rng": [],
      "input": {{}},
      "expect_error": "decrypt"
    }}
  ]
}}"#
    )
}

fn sample_file() -> vector::VectorFile {
    vector::load_str(&sample_json()).unwrap()
}

#[test]
fn vector_loader_accepts_the_schema_example_and_runs_it() {
    let file = sample_file();
    assert_eq!(file.cases.len(), 2);
    let report = vector::run_all(&file, |case, rng| {
        if case.status == vector::Status::Invalid {
            return Err(Error::Decrypt);
        }
        let mut nonce = [0u8; 24];
        rng.fill(&mut nonce);
        Ok(Outcome {
            output: json!({ "wrap": "00" }),
            intermediate: Some(json!({ "kek": "00" })),
        })
    });
    assert_eq!(report.failures, vec![]);
    assert_eq!(report.passed, 2);
}

#[test]
fn vector_loader_rejects_what_the_schema_rejects() {
    let good = sample_json();
    let bad: Vec<(&str, String)> = vec![
        (
            "unknown field",
            good.replace("\"suite\": 1,", "\"suite\": 1, \"extra\": 1,"),
        ),
        (
            "wrong format",
            good.replace("ferret-vectors/1", "ferret-vectors/2"),
        ),
        (
            "capital hex",
            good.replacen(&"00".repeat(24), &"AB".repeat(24), 1),
        ),
        (
            "not synthetic",
            good.replacen("\"synthetic\": true", "\"synthetic\": false", 1),
        ),
        ("unknown tag", good.replace("\"slow\"", "\"fast\"")),
        (
            "id outside group",
            good.replace("wrap/password/valid/001", "tlv/x/001"),
        ),
        (
            "duplicate id",
            good.replace("wrap/password/invalid/001", "wrap/password/valid/001"),
        ),
        (
            "valid without expect",
            good.replace("\"expect\": { \"wrap\": \"00\" },", ""),
        ),
        (
            "invalid with expect",
            good.replace(
                "\"expect_error\": \"decrypt\"",
                "\"expect_error\": \"decrypt\", \"expect\": 1",
            ),
        ),
        (
            "invalid without code",
            good.replace("\"expect_error\": \"decrypt\"", "\"expect_error\": null"),
        ),
        (
            "native-only without reason",
            good.replacen("[\"slow\"]", "[\"native-only\"]", 1),
        ),
    ];
    for (what, text) in bad {
        assert!(vector::load_str(&text).is_err(), "should reject: {what}");
    }
}

#[test]
fn vector_loader_accepts_native_only_with_reason() {
    let text = sample_json().replacen(
        "\"synthetic\": true,",
        "\"synthetic\": true, \"skip_reason\": \"needs 1 GiB\",",
        1,
    );
    let text = text.replacen("[\"slow\"]", "[\"native-only\"]", 1);
    vector::load_str(&text).unwrap();
}

/// Names in the first column of the table in `OPS.md` (``| `op.name` ``).
fn known_ops() -> BTreeSet<String> {
    codes_in_table(&vectors_dir().join("OPS.md"))
}

#[test]
fn vector_files_match_schema() {
    // The schema file itself must parse and agree with the Rust types.
    let schema: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(vectors_dir().join("schema/vector-file.schema.json")).unwrap(),
    )
    .unwrap();
    assert_eq!(schema["properties"]["format"]["const"], vector::FORMAT);
    let case = &schema["$defs"]["case"];
    let required: BTreeSet<&str> = case["required"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap())
        .collect();
    let expected: BTreeSet<&str> = [
        "id",
        "title",
        "op",
        "status",
        "tags",
        "synthetic",
        "rng",
        "input",
        "expect_error",
    ]
    .into_iter()
    .collect();
    assert_eq!(required, expected);
    let properties: BTreeSet<&str> = case["properties"]
        .as_object()
        .unwrap()
        .keys()
        .map(String::as_str)
        .collect();
    let all_fields: BTreeSet<&str> = [
        "id",
        "title",
        "op",
        "status",
        "tags",
        "synthetic",
        "skip_reason",
        "rng",
        "input",
        "intermediate",
        "expect",
        "expect_error",
    ]
    .into_iter()
    .collect();
    assert_eq!(properties, all_fields);
    assert_eq!(case["additionalProperties"], json!(false));

    // Every generated file that exists must load, use registered ops and
    // documented error codes, and be named after its group.
    let codes: BTreeSet<String> = Error::ALL.iter().map(|e| e.code().to_string()).collect();
    let ops = known_ops();
    let dir = vectors_dir().join("internal");
    let Ok(entries) = std::fs::read_dir(&dir) else {
        return;
    };
    for entry in entries {
        let path = entry.unwrap().path();
        if path.extension().and_then(|e| e.to_str()) != Some("json") {
            continue;
        }
        let file = vector::load(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
        assert_eq!(
            path.file_stem().and_then(|s| s.to_str()),
            Some(file.group.as_str()),
            "{}: file name must be the group",
            path.display()
        );
        for case in &file.cases {
            assert!(
                ops.contains(&case.op),
                "{}: op {} not in OPS.md",
                case.id,
                case.op
            );
            if let Some(code) = &case.expect_error {
                assert!(
                    codes.contains(code),
                    "{}: unknown error code {code}",
                    case.id
                );
            }
        }
    }
}

// -------------------------------------------------------------- vectorgen

fn copy_tree(from: &Path, to: &Path) {
    std::fs::create_dir_all(to).unwrap();
    for entry in std::fs::read_dir(from).unwrap() {
        let entry = entry.unwrap();
        let target = to.join(entry.file_name());
        if entry.file_type().unwrap().is_dir() {
            copy_tree(&entry.path(), &target);
        } else {
            std::fs::copy(entry.path(), target).unwrap();
        }
    }
}

fn scratch(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("ferret-core-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    dir
}

#[test]
fn vectorgen_check_is_deterministic() {
    use ferret_vectorgen::{MANIFEST_FILE, check, collect_dir, generate};

    // The committed vectors are what the generator produces.
    check(&vectors_dir()).unwrap_or_else(|p| panic!("vectorgen check failed: {p:?}"));

    let (a, b) = (scratch("vecgen-a"), scratch("vecgen-b"));
    copy_tree(&vectors_dir(), &a);
    copy_tree(&vectors_dir(), &b);
    generate(&a).unwrap();
    generate(&b).unwrap();
    let first = collect_dir(&a).unwrap();
    assert_eq!(
        first,
        collect_dir(&b).unwrap(),
        "two runs give different bytes"
    );
    assert_eq!(
        std::fs::read(a.join(MANIFEST_FILE)).unwrap(),
        std::fs::read(b.join(MANIFEST_FILE)).unwrap()
    );

    // A third run over its own output changes nothing, and equals the repo.
    generate(&a).unwrap();
    assert_eq!(first, collect_dir(&a).unwrap());
    assert_eq!(first, collect_dir(&vectors_dir()).unwrap());
    check(&a).unwrap();

    // A changed file is caught.
    std::fs::write(a.join("OPS.md"), b"changed").unwrap();
    assert!(check(&a).is_err(), "manifest must catch a changed file");

    let _ = std::fs::remove_dir_all(&a);
    let _ = std::fs::remove_dir_all(&b);
}

#[test]
fn vector_loader_accepts_every_documented_error_code() {
    for error in Error::ALL {
        let text = sample_json().replace("\"decrypt\"", &format!("\"{}\"", error.code()));
        vector::load_str(&text).unwrap_or_else(|e| panic!("{}: {e}", error.code()));
    }
}
