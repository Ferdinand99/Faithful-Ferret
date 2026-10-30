//! The response headers of the web vault's origin (Spec: Fase 1 § 12).

use std::collections::BTreeMap;

use ferret_server::http::headers::{VAULT_CSP, VAULT_HEADERS};

const SPEC: &str = include_str!("../../../docs/design/phase-1-security-design.md");
const FIXTURE: &str = include_str!("fixtures/wire/headers.json");

/// The header block of section 12 as the specification prints it: the lines of
/// the fenced block after "with these headers:". A line that does not start a
/// new `Name: value` continues the value before it (the policy is wrapped).
fn spec_headers() -> BTreeMap<String, String> {
    let start = SPEC
        .find("It is delivered from a **separate origin** with these headers:")
        .expect("the sentence that introduces the header list");
    let block = SPEC[start..]
        .split("```")
        .nth(1)
        .expect("the fenced header block");
    let mut headers: Vec<(String, String)> = Vec::new();
    for line in block.lines().map(str::trim).filter(|l| !l.is_empty()) {
        let starts_header = line.split_once(": ").is_some_and(|(name, _)| {
            !name.is_empty() && name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
        });
        if starts_header {
            let (name, value) = line.split_once(": ").expect("a header line");
            headers.push((name.to_string(), value.trim().to_string()));
        } else {
            let last = headers.last_mut().expect("a continuation of a header");
            last.1.push(' ');
            last.1.push_str(line);
        }
    }
    headers.into_iter().collect()
}

fn fixture_headers() -> BTreeMap<String, String> {
    serde_json::from_str(FIXTURE).expect("headers.json is an object of strings")
}

#[test]
fn headers_json_is_section_12_verbatim() {
    let spec = spec_headers();
    assert_eq!(spec.len(), 5, "section 12 lists five headers: {spec:?}");
    assert_eq!(fixture_headers(), spec);
}

#[test]
fn vault_csp_constant_equals_the_fixture() {
    let fixture = fixture_headers();
    assert_eq!(fixture["Content-Security-Policy"], VAULT_CSP);
    let constants: BTreeMap<String, String> = VAULT_HEADERS
        .iter()
        .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
        .collect();
    assert_eq!(constants, fixture);
}

#[test]
fn the_policy_allows_no_inline_script_or_style_and_no_other_origin() {
    for forbidden in ["'unsafe-inline'", "'unsafe-eval'", "http:", "https:", "*"] {
        assert!(!VAULT_CSP.contains(forbidden), "{forbidden}");
    }
    assert!(VAULT_CSP.starts_with("default-src 'none';"));
    assert!(VAULT_CSP.contains("require-trusted-types-for 'script'"));
    assert!(VAULT_CSP.contains("trusted-types ferret"));
}
