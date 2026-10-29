//! The embedded Public Suffix List snapshot and the matching algorithm.
//!
//! Spec: Fase 1 § 9.2 ("Public Suffix List er innebygd, med de private
//! domenene"). The snapshot is `public_suffix_list.dat`, the upstream list
//! with the comments removed except the MPL notice and the `VERSION` and
//! `COMMIT` lines (see `scripts/update-psl.sh`). Both the ICANN and the
//! PRIVATE sections are used, so `github.io` and `vercel.app` are public
//! suffixes. The list is published under the Mozilla Public License 2.0; the
//! notice stays at the top of the file.
//!
//! The date of the snapshot is the `VERSION` line in the file itself;
//! [`snapshot_date`] reads it, and the test
//! `scripts/check-psl-age.sh`, run weekly and on release pull requests by
//! `.github/workflows/psl-age.yml`, fails when it is more than 90 days old.
//! The snapshot is refreshed at every release.
//!
//! The matching is the algorithm of <https://publicsuffix.org/list/>:
//! 1. a rule matches a domain when its labels equal the domain's last labels,
//!    a `*` label matching any one label;
//! 2. with no match the prevailing rule is `*` (an unknown top-level domain is
//!    a public suffix);
//! 3. an exception rule (`!`) prevails over the others, and the public suffix
//!    is then the exception without its leftmost label;
//! 4. otherwise the rule with the most labels prevails.
//!
//! Rules with non-ASCII labels are stored as A-labels, so the lookup works on
//! the canonical (A-label, lowercase) names that [`super::origin`] produces.

use std::collections::BTreeSet;
use std::sync::OnceLock;

/// The snapshot, as embedded.
const SNAPSHOT: &str = include_str!("public_suffix_list.dat");

struct Rules {
    /// `a.b` for the rule `a.b`.
    exact: BTreeSet<String>,
    /// `b` for the rule `*.b`.
    wildcard: BTreeSet<String>,
    /// `a.b` for the rule `!a.b`.
    exception: BTreeSet<String>,
}

static RULES: OnceLock<Rules> = OnceLock::new();

fn rules() -> &'static Rules {
    RULES.get_or_init(build)
}

fn ascii_rule(text: &str) -> Option<String> {
    if text.is_ascii() {
        Some(text.to_owned())
    } else {
        idna::domain_to_ascii(text).ok()
    }
}

fn build() -> Rules {
    let mut r = Rules {
        exact: BTreeSet::new(),
        wildcard: BTreeSet::new(),
        exception: BTreeSet::new(),
    };
    for line in SNAPSHOT.lines() {
        if line.starts_with("//") {
            continue;
        }
        let Some(rule) = line.split_whitespace().next() else {
            continue;
        };
        if let Some(rest) = rule.strip_prefix('!') {
            if let Some(a) = ascii_rule(rest) {
                r.exception.insert(a);
            }
        } else if let Some(rest) = rule.strip_prefix("*.") {
            if let Some(a) = ascii_rule(rest) {
                r.wildcard.insert(a);
            }
        } else if let Some(a) = ascii_rule(rule) {
            r.exact.insert(a);
        }
    }
    r
}

/// The snapshot text, for the reference matcher in the tests.
#[cfg(any(test, feature = "test-support"))]
pub(crate) fn snapshot_text() -> &'static str {
    SNAPSHOT
}

/// The number of rules in the snapshot (every kind), after the conversion of
/// the non-ASCII ones. For the tests: a rule that fails to convert would
/// silently weaken the list.
#[cfg(any(test, feature = "test-support"))]
pub(crate) fn rule_counts() -> (usize, usize, usize) {
    let r = rules();
    (r.exact.len(), r.wildcard.len(), r.exception.len())
}

/// The number of rule lines in the snapshot file (for the same test).
#[cfg(any(test, feature = "test-support"))]
pub(crate) fn rule_lines() -> usize {
    SNAPSHOT
        .lines()
        .filter(|l| !l.starts_with("//") && l.split_whitespace().next().is_some())
        .count()
}

/// The labels of `domain` from the right: the last label, the last two, and
/// so on. `domain` is a canonical name (no empty labels).
fn suffixes(domain: &str) -> Vec<&str> {
    let mut out = Vec::new();
    let mut end = domain.len();
    while let Some(head) = domain.get(..end) {
        match head.rfind('.') {
            Some(dot) => {
                if let Some(s) = domain.get(dot.saturating_add(1)..) {
                    out.push(s);
                }
                end = dot;
            }
            None => {
                out.push(domain);
                break;
            }
        }
    }
    out
}

/// How many of the last labels of `domain` form its public suffix. At least
/// 1 for a non-empty name; equal to the number of labels when the name itself
/// is a public suffix.
pub(crate) fn public_suffix_labels(domain: &str) -> usize {
    let rules = rules();
    let sfx = suffixes(domain);
    let mut best: usize = 1;
    let mut exception: Option<usize> = None;
    for (i, s) in sfx.iter().enumerate() {
        let k = i.saturating_add(1);
        if rules.exception.contains(*s) {
            exception = Some(k);
        }
        if rules.exact.contains(*s) {
            best = best.max(k);
        }
        // `*.b` matches the suffix `x.b`: look `b` up (the previous entry).
        if i > 0
            && sfx
                .get(i.saturating_sub(1))
                .is_some_and(|rest| rules.wildcard.contains(*rest))
        {
            best = best.max(k);
        }
    }
    match exception {
        Some(k) => k.saturating_sub(1),
        None => best,
    }
}

/// True when `domain` is itself a public suffix (a rule, or an unknown
/// top-level domain).
pub(crate) fn is_public_suffix(domain: &str) -> bool {
    let labels = domain.split('.').count();
    public_suffix_labels(domain) >= labels
}

/// The date written in the `VERSION` line of the snapshot, as
/// `(year, month, day)`.
pub fn snapshot_date() -> Option<(u16, u8, u8)> {
    let line = SNAPSHOT
        .lines()
        .find_map(|l| l.strip_prefix("// VERSION: "))?;
    let date = line.get(..10)?;
    let mut parts = date.split('-');
    let y = parts.next()?.parse().ok()?;
    let m = parts.next()?.parse().ok()?;
    let d = parts.next()?.parse().ok()?;
    if parts.next().is_some() || !(1..=12).contains(&m) || !(1..=31).contains(&d) {
        return None;
    }
    Some((y, m, d))
}

/// The `COMMIT` line of the snapshot (the upstream revision).
pub fn snapshot_commit() -> Option<&'static str> {
    SNAPSHOT.lines().find_map(|l| l.strip_prefix("// COMMIT: "))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matches_the_list_algorithm() {
        // Rules from the upstream test suite (test_psl.txt), on the embedded list.
        assert!(is_public_suffix("com"));
        assert!(is_public_suffix("co.uk"));
        assert!(!is_public_suffix("example.co.uk"));
        assert!(is_public_suffix("github.io"));
        assert!(!is_public_suffix("a.github.io"));
        // Unknown top-level domain: the implicit `*` rule.
        assert!(is_public_suffix("zzzunknown"));
        assert!(!is_public_suffix("a.zzzunknown"));
        // Wildcard `*.ck` with the exception `!www.ck`.
        assert!(is_public_suffix("foo.ck"));
        assert!(!is_public_suffix("www.ck"));
        assert_eq!(public_suffix_labels("a.b.foo.ck"), 2);
        assert_eq!(public_suffix_labels("www.ck"), 1);
    }

    #[test]
    fn date_is_read_from_the_version_line() {
        let (y, m, d) = snapshot_date().unwrap();
        assert!(y >= 2026);
        assert!((1..=12).contains(&m) && (1..=31).contains(&d));
    }
}
