//! Origins, RP IDs and the Public Suffix List snapshot (Fase 1 § 9.2, F-12,
//! plan U11) and `vectors/internal/origin.json`.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]

mod common;

use common::*;
use ferret_core::testing::passkey::{
    is_public_suffix, psl_rule_counts, psl_rule_lines, psl_snapshot_text, public_suffix_labels,
};
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

#[test]
fn psl_snapshot_date_is_recorded() {
    // The age limit (90 days) is checked by scripts/check-psl-age.sh, weekly
    // and on release pull requests, not here: an ordinary test run must not
    // depend on the clock.
    let (y, m, d) = ferret_core::passkey::snapshot_date().expect("VERSION line in the snapshot");
    assert!(y >= 2026 && (1..=12).contains(&m) && (1..=31).contains(&d));
    let text = psl_snapshot_text();
    assert!(text.contains(&format!("// VERSION: {y}-{m:02}-{d:02}_")));
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

// ------------------------------------------------- upstream test file

/// The registrable domain of `input` by the embedded list, as the upstream
/// test file defines it: `None` for a public suffix, an empty name or a name
/// with a leading dot.
fn registrable_domain(input: &str) -> Option<String> {
    if input.is_empty() || input.starts_with('.') {
        return None;
    }
    let name = idna::domain_to_ascii(input).ok()?;
    let labels: Vec<&str> = name.split('.').collect();
    let suffix = public_suffix_labels(&name);
    if suffix >= labels.len() {
        return None;
    }
    Some(labels[labels.len() - suffix - 1..].join("."))
}

fn quoted(arg: &str) -> Option<String> {
    let arg = arg.trim();
    if arg == "null" {
        None
    } else {
        Some(arg.trim_matches('\'').to_owned())
    }
}

#[test]
fn psl_upstream_test_file() {
    // vectors/external/publicsuffix-test_psl.txt, unchanged (see SOURCE.md).
    let text =
        std::fs::read_to_string(vectors_dir().join("external/publicsuffix-test_psl.txt")).unwrap();
    let mut n = 0;
    for line in text.lines() {
        let Some(args) = line
            .strip_prefix("checkPublicSuffix(")
            .and_then(|l| l.strip_suffix(");"))
        else {
            continue;
        };
        let (input, expected) = args.split_once(", ").unwrap();
        let (input, expected) = (quoted(input), quoted(expected));
        let want = expected.map(|e| idna::domain_to_ascii(&e).unwrap());
        let got = input.as_deref().and_then(registrable_domain);
        assert_eq!(got, want, "checkPublicSuffix({args})");
        n += 1;
    }
    assert!(n == 78, "only {n} cases in the upstream file");
}

// ------------------------------------------------ reference matcher

/// One rule of the list, labels from the right.
struct Rule {
    labels: Vec<String>,
    exception: bool,
}

/// The algorithm of https://publicsuffix.org/list/ written out literally:
/// every rule that matches label by label (`*` matches one label); the
/// exception rule prevails, then the rule with the most labels; otherwise `*`.
fn reference_suffix_labels(
    name: &str,
    rules: &std::collections::HashMap<String, Vec<Rule>>,
) -> usize {
    let labels: Vec<&str> = name.rsplit('.').collect();
    let mut best = 1;
    let mut exception = None;
    for rule in rules.get(labels[0]).into_iter().flatten() {
        if rule.labels.len() > labels.len() {
            continue;
        }
        let matches = rule
            .labels
            .iter()
            .zip(&labels)
            .all(|(r, l)| r == "*" || r == l);
        if !matches {
            continue;
        }
        if rule.exception {
            exception = Some(rule.labels.len() - 1);
        } else {
            best = best.max(rule.labels.len());
        }
    }
    exception.unwrap_or(best)
}

#[test]
fn psl_matcher_agrees_with_the_reference_on_every_rule() {
    use std::collections::HashMap;
    let mut rules: HashMap<String, Vec<Rule>> = HashMap::new();
    let mut names: Vec<String> = Vec::new();
    for line in psl_snapshot_text().lines() {
        if line.starts_with("//") {
            continue;
        }
        let Some(token) = line.split_whitespace().next() else {
            continue;
        };
        let (exception, body) = match token.strip_prefix('!') {
            Some(rest) => (true, rest),
            None => (false, token),
        };
        let ascii = if body.is_ascii() {
            body.to_owned()
        } else {
            idna::domain_to_ascii(body).unwrap()
        };
        let labels: Vec<String> = ascii.rsplit('.').map(str::to_owned).collect();
        // Names around the rule: the rule itself (a wildcard filled in), one
        // and two labels below it, `www` below it, and the parent of an
        // exception.
        let concrete = ascii.replace('*', "wild");
        names.push(concrete.clone());
        names.push(format!("x.{concrete}"));
        names.push(format!("x.y.{concrete}"));
        names.push(format!("www.{concrete}"));
        if exception && let Some((_, parent)) = concrete.split_once('.') {
            names.push(parent.to_owned());
        }
        if let Some(base) = ascii.strip_prefix("*.") {
            names.push(base.to_owned());
        }
        rules
            .entry(labels[0].clone())
            .or_default()
            .push(Rule { labels, exception });
    }
    assert!(names.len() > 40_000);
    for name in &names {
        assert_eq!(
            public_suffix_labels(name),
            reference_suffix_labels(name, &rules),
            "{name}"
        );
    }
}
