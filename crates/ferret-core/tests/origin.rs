//! Origins, RP IDs and the Public Suffix List snapshot (Fase 1 § 9.2, F-12,
//! plan U11) and `vectors/internal/origin.json`.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]

mod common;

use common::*;
use ferret_core::testing::passkey::{is_public_suffix, psl_rule_counts, psl_rule_lines};
use ferret_core::testing::vector::Outcome;
use ferret_core::{Error, MalformedKind, canonical_origin, validate_rp_id};
use serde_json::json;

fn utf8(v: &serde_json::Value) -> String {
    String::from_utf8(hex(v)).unwrap()
}

#[test]
fn origin_vectors_from_file() {
    let file = load_ops("origin.json", |_| true);
    let report = ferret_core::testing::vector::run_all(&file, |case, _rng| {
        let input = &case.input;
        match case.op.as_str() {
            "origin.canonical" => {
                let o = canonical_origin(&utf8(&input["raw_utf8"]))?;
                Ok(Outcome {
                    output: json!({ "origin": o.as_str(), "host": o.host() }),
                    intermediate: None,
                })
            }
            "origin.rp_id" => {
                let o = canonical_origin(&utf8(&input["origin_utf8"]))?;
                let rp = validate_rp_id(&o, &utf8(&input["rp_id_utf8"]))?;
                Ok(Outcome {
                    output: json!({ "rp_id": rp.as_str() }),
                    intermediate: None,
                })
            }
            other => panic!("unknown op {other}"),
        }
    });
    assert_all_passed(&report, 90);
}

#[test]
fn rp_id_rules() {
    let origin = canonical_origin("https://login.example.com").unwrap();
    // Equal host: fine. A dot-delimited parent: fine.
    assert_eq!(
        validate_rp_id(&origin, "login.example.com")
            .unwrap()
            .as_str(),
        "login.example.com"
    );
    assert_eq!(
        validate_rp_id(&origin, "example.com").unwrap().as_str(),
        "example.com"
    );
    // A public suffix: refused.
    assert_eq!(
        validate_rp_id(&origin, "com"),
        Err(Error::Malformed(MalformedKind::RpId))
    );
    // A foreign domain: refused.
    assert_eq!(
        validate_rp_id(&origin, "other.com"),
        Err(Error::Malformed(MalformedKind::RpId))
    );
    // A partial string of the host, not on a dot: refused.
    assert_eq!(
        validate_rp_id(&origin, "ample.com"),
        Err(Error::Malformed(MalformedKind::RpId))
    );
    // Private domains of the list.
    let gh = canonical_origin("https://a.github.io").unwrap();
    assert!(validate_rp_id(&gh, "a.github.io").is_ok());
    assert!(validate_rp_id(&gh, "github.io").is_err());
}

#[test]
fn origin_error_codes() {
    assert_eq!(
        canonical_origin("null").unwrap_err().code(),
        "malformed_origin"
    );
    assert_eq!(
        validate_rp_id(&canonical_origin("https://a.example").unwrap(), "b.example")
            .unwrap_err()
            .code(),
        "malformed_rp_id"
    );
}

#[test]
fn origin_is_bounded() {
    let long = format!("https://{}.com", "a".repeat(300));
    assert!(canonical_origin(&long).is_err());
    let label64 = format!("https://{}.example", "a".repeat(64));
    assert!(canonical_origin(&label64).is_err());
    let label63 = format!("https://{}.example", "a".repeat(63));
    assert!(canonical_origin(&label63).is_ok());
}

/// Days since 1970-01-01 of a civil date (Howard Hinnant's algorithm).
fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let mp = (m + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

#[test]
fn psl_snapshot_is_not_older_than_90_days() {
    let (y, m, d) = ferret_core::passkey::snapshot_date().expect("VERSION line in the snapshot");
    let snapshot_days = days_from_civil(i64::from(y), i64::from(m), i64::from(d));
    let now_secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let today = i64::try_from(now_secs / 86_400).unwrap();
    let age = today - snapshot_days;
    assert!(
        age <= 90,
        "the Public Suffix List snapshot is {age} days old (VERSION {y}-{m:02}-{d:02}): \
         run scripts/update-psl.sh and commit the new snapshot"
    );
    // A clock in the past would hide an old snapshot.
    assert!(age >= -1, "the snapshot is dated in the future");
}

#[test]
fn psl_snapshot_records_its_source() {
    assert!(ferret_core::passkey::snapshot_commit().is_some_and(|c| c.len() == 40));
}

#[test]
fn psl_snapshot_has_private_domains() {
    for d in ["github.io", "vercel.app", "blogspot.com", "herokuapp.com"] {
        assert!(is_public_suffix(d), "{d} should be a public suffix");
    }
    for d in ["a.github.io", "example.com", "x.vercel.app"] {
        assert!(!is_public_suffix(d), "{d} should not be a public suffix");
    }
}

#[test]
fn psl_every_rule_is_loaded() {
    // A rule that failed the conversion to an A-label would be dropped
    // silently and weaken the list.
    let (exact, wildcard, exception) = psl_rule_counts();
    assert_eq!(exact + wildcard + exception, psl_rule_lines());
    assert!(exact > 8_000 && wildcard > 5 && exception > 1);
}

#[test]
fn psl_idn_rules_match_a_labels() {
    // `公司.cn` is a rule of the list in Unicode; the lookup is on A-labels.
    assert!(is_public_suffix("xn--55qx5d.cn"));
    assert!(!is_public_suffix("a.xn--55qx5d.cn"));
}

#[test]
fn origin_canonicalization_is_idempotent_on_the_vectors() {
    let file = load_ops("origin.json", |op| op == "origin.canonical");
    for case in file.cases.iter().filter(|c| c.expect.is_some()) {
        let once = canonical_origin(&utf8(&case.input["raw_utf8"])).unwrap();
        let twice = canonical_origin(once.as_str()).unwrap();
        assert_eq!(once, twice, "{}", case.id);
    }
}
