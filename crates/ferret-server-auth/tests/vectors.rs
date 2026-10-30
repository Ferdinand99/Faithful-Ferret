//! The server vector files (`vectors/internal/server-opaque.json` and
//! `server-secrets.json`) through the library.
//!
//! The expected values of the secret files, the fingerprint, the made-up
//! answers, the challenge key and the sealed state were worked out apart from
//! this crate (by the generator, from the layouts in `vectors/OPS.md`, and again
//! by `tools/xcheck`), so these cases check the library against bytes it did
//! not make. The OPAQUE answers are recorded from the library; they pin its
//! behaviour, and `rfc9807_server.rs` ties the same code to the standard.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use ferret_core::testing::vector::{self, Status, Tag, VectorFile};
use ferret_server_auth::Malformed;
use ferret_server_auth::testing::vectors::run_case;
use sha2::{Digest, Sha256};

const FILES: &[&str] = &["server-opaque", "server-secrets"];

fn vectors_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../vectors")
}

fn load(group: &str) -> VectorFile {
    vector::load(&vectors_dir().join("internal").join(format!("{group}.json"))).unwrap()
}

#[test]
fn server_vectors_run_in_rust() {
    let mut cases = 0;
    for group in FILES {
        for case in load(group).cases {
            let got = run_case(&case);
            match case.status {
                Status::Valid => {
                    assert_eq!(
                        got.as_ref().ok(),
                        case.expect.as_ref(),
                        "{}: {got:?}",
                        case.id
                    );
                }
                Status::Invalid => {
                    assert_eq!(
                        got.as_ref().err(),
                        case.expect_error.as_ref(),
                        "{}: {got:?}",
                        case.id
                    );
                }
            }
            cases += 1;
        }
    }
    assert!(cases >= 150, "only {cases} cases were run");
}

/// Changes the first leaf of a value.
fn damage(value: &serde_json::Value) -> serde_json::Value {
    use serde_json::Value;
    match value {
        Value::String(s) => {
            let mut chars: Vec<char> = s.chars().collect();
            if let Some(first) = chars.first_mut() {
                *first = if *first == '0' { '1' } else { '0' };
            }
            Value::String(chars.into_iter().collect())
        }
        Value::Bool(b) => Value::Bool(!b),
        Value::Number(n) => Value::from(n.as_u64().unwrap_or(0) + 1),
        Value::Array(items) => Value::Array(items.iter().take(1).map(damage).collect()),
        Value::Object(map) => {
            let mut map = map.clone();
            if let Some(key) = map.keys().next().cloned() {
                let changed = damage(&map[&key]);
                map.insert(key, changed);
            }
            Value::Object(map)
        }
        Value::Null => Value::Bool(true),
    }
}

/// A changed expectation is caught, so the test above cannot pass by
/// comparing a value with itself.
#[test]
fn a_changed_expectation_fails() {
    for group in FILES {
        let mut valid = 0;
        for mut case in load(group).cases {
            if case.status != Status::Valid {
                continue;
            }
            case.expect = case.expect.as_ref().map(damage);
            assert_ne!(run_case(&case).ok(), case.expect, "{}", case.id);
            valid += 1;
        }
        assert!(valid > 10, "{group}: only {valid} valid cases");
    }
}

/// Every case of the server files is skipped by the bindings, with a reason.
#[test]
fn server_cases_are_native_only() {
    for group in FILES {
        let file = load(group);
        for case in &file.cases {
            assert!(case.tags.contains(&Tag::NativeOnly), "{}", case.id);
            assert!(case.skip_reason.is_some(), "{}", case.id);
            assert!(case.synthetic, "{}", case.id);
            assert!(case.op.starts_with("server."), "{}", case.id);
        }
    }
}

/// The codes the server library can answer with, as `ERRORS.md` lists them in
/// its server section (lines that start with ``* ` ``).
fn documented_codes() -> BTreeSet<String> {
    let text = std::fs::read_to_string(vectors_dir().join("ERRORS.md")).unwrap();
    let section = text
        .split("## Server codes")
        .nth(1)
        .expect("server section");
    section
        .lines()
        .filter_map(|line| line.strip_prefix("* `"))
        .filter_map(|rest| rest.split_once('`').map(|(code, _)| code.to_string()))
        .collect()
}

/// The code of every error the library reports.
fn library_codes() -> BTreeSet<String> {
    let mut codes: BTreeSet<String> = Malformed::ALL
        .iter()
        .map(|kind| kind.public_code().to_string())
        .collect();
    for code in [
        "denied",
        "forbidden",
        "profile_rejected",
        "throttled",
        "internal",
    ] {
        codes.insert(code.to_string());
    }
    codes
}

/// The codes of a secret file that does not decode.
fn file_codes() -> BTreeSet<String> {
    [
        "bad_magic",
        "unsupported_version",
        "wrong_kind",
        "unsupported_suite",
        "bad_length",
        "bad_checksum",
        "trailing_bytes",
    ]
    .into_iter()
    .map(String::from)
    .collect()
}

#[test]
fn server_vectors_cover_every_error_code() {
    let mut expected = library_codes();
    expected.extend(file_codes());
    assert_eq!(
        documented_codes(),
        expected,
        "ERRORS.md and the library disagree"
    );

    let mut seen = BTreeSet::new();
    for group in FILES {
        for case in load(group).cases {
            if let Some(code) = case.expect_error {
                seen.insert(code);
            }
        }
    }
    let missing: Vec<_> = expected.difference(&seen).collect();
    let unknown: Vec<_> = seen.difference(&expected).collect();
    assert!(missing.is_empty(), "no invalid case for {missing:?}");
    assert!(
        unknown.is_empty(),
        "codes that ERRORS.md does not list: {unknown:?}"
    );
}

/// The files and `VERSION` are the ones `MANIFEST.json` lists. (The whole of
/// `vectors/` is checked byte for byte by `vectorgen check`, which the CI job
/// for the vectors and the test of `ferret-core` run.)
#[test]
fn vectors_are_up_to_date() {
    let root = vectors_dir();
    let manifest: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(root.join("MANIFEST.json")).unwrap())
            .unwrap();
    let version: u64 = std::fs::read_to_string(root.join("VERSION"))
        .unwrap()
        .trim()
        .parse()
        .unwrap();
    assert_eq!(manifest["version"], version);
    for group in FILES {
        let path = format!("internal/{group}.json");
        let bytes = std::fs::read(root.join(&path)).unwrap();
        let hash: String = Sha256::digest(&bytes)
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        assert_eq!(
            manifest["files"][&path], hash,
            "{path} is not in the manifest"
        );
    }
}
