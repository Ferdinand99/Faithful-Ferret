//! Checks on the source and the manifest of the crate: no `derive(Debug)` except
//! on the listed public types, no own cipher suite, no OPAQUE or Argon2
//! dependency of its own.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]

use std::path::{Path, PathBuf};

fn manifest_dir() -> &'static Path {
    Path::new(env!("CARGO_MANIFEST_DIR"))
}

fn sources() -> Vec<(PathBuf, String)> {
    fn walk(dir: &Path, out: &mut Vec<(PathBuf, String)>) {
        for entry in std::fs::read_dir(dir).unwrap() {
            let path = entry.unwrap().path();
            if path.is_dir() {
                walk(&path, out);
            } else if path.extension().is_some_and(|e| e == "rs") {
                let text = std::fs::read_to_string(&path).unwrap();
                out.push((path, text));
            }
        }
    }
    let mut out = Vec::new();
    walk(&manifest_dir().join("src"), &mut out);
    assert!(!out.is_empty());
    out
}

/// The only types of the crate that may derive `Debug`: they hold no secret
/// and no identifier. Every other `struct` or `enum` in `src/` must write its
/// own `Debug` that shows no content, so a new type is safe by default.
const MAY_DERIVE_DEBUG: &[&str] = &[
    "AuthError",
    "Malformed",
    "DenyReason",
    "InternalKind",
    "ErrorClass",
    "SystemClock",
    "ManualClock",
    "Stage",
    "Outcome",
    // Secret files and start-up: names and switches. The fingerprint is a
    // one-way hash of the set-up, safe to store and to print. None holds file
    // content.
    "FileKind",
    "SecretFileError",
    "SetupFingerprint",
    "CreatePolicy",
    "FileOrigin",
    "StartupDecision",
    "StartupRefusal",
    // Pre-login: the public shares of the real accounts, the public answer
    // for a name, with no name, key or secret in them.
    "PreloginPolicy",
    "PreloginAnswer",
    // Login state store: the three ways a store can refuse. No content.
    "StoreError",
    // Session scopes: closed sets of names, no content.
    "SessionScope",
    "Capability",
    "ScopeEffect",
    // Signed requests: closed sets of names, no content.
    "ReplaceKind",
    "ConsumeOutcome",
    "WriteRefused",
];

/// Source text with comments and string literals replaced by spaces (newlines
/// are kept), as characters.
fn blank_comments_and_strings(text: &str) -> Vec<char> {
    let c: Vec<char> = text.chars().collect();
    let mut out = Vec::with_capacity(c.len());
    let mut i = 0;
    while i < c.len() {
        let next = c.get(i + 1).copied();
        if c[i] == '/' && next == Some('/') {
            while i < c.len() && c[i] != '\n' {
                i += 1;
            }
        } else if c[i] == '/' && next == Some('*') {
            i += 2;
            while i < c.len() && !(c[i] == '*' && c.get(i + 1) == Some(&'/')) {
                i += 1;
            }
            i += 2;
            out.push(' ');
        } else if c[i] == '\'' && next == Some('"') && c.get(i + 2) == Some(&'\'') {
            out.extend([' ', ' ', ' ']);
            i += 3;
        } else if c[i] == '"' {
            out.push(' ');
            i += 1;
            while i < c.len() && c[i] != '"' {
                if c[i] == '\\' {
                    i += 1;
                }
                if let Some(ch) = c.get(i) {
                    out.push(if *ch == '\n' { '\n' } else { ' ' });
                }
                i += 1;
            }
            out.push(' ');
            i += 1;
        } else {
            out.push(c[i]);
            i += 1;
        }
    }
    out
}

fn is_ident(c: char) -> bool {
    c.is_alphanumeric() || c == '_'
}

/// The identifier that starts at `i` (and is not the tail of a longer one).
fn word_at(t: &[char], i: usize) -> Option<String> {
    if i >= t.len() || !is_ident(t[i]) || (i > 0 && is_ident(t[i - 1])) {
        return None;
    }
    Some(t[i..].iter().take_while(|c| is_ident(**c)).collect())
}

fn skip_ws(t: &[char], mut i: usize) -> usize {
    while i < t.len() && t[i].is_whitespace() {
        i += 1;
    }
    i
}

/// Moves back over white space; returns the position after the last
/// non-white-space character.
fn back_ws(t: &[char], mut pos: usize) -> usize {
    while pos > 0 && t[pos - 1].is_whitespace() {
        pos -= 1;
    }
    pos
}

/// The position of the bracket that opens the one that closes at `pos - 1`.
fn matching_open(t: &[char], pos: usize, open: char, close: char) -> Option<usize> {
    let mut depth = 0usize;
    let mut p = pos;
    while p > 0 {
        p -= 1;
        if t[p] == close {
            depth += 1;
        } else if t[p] == open {
            depth = depth.saturating_sub(1);
            if depth == 0 {
                return Some(p);
            }
        }
    }
    None
}

/// The word that ends at `pos` and the position where it starts.
fn word_ending_at(t: &[char], pos: usize) -> Option<(String, usize)> {
    let mut start = pos;
    while start > 0 && is_ident(t[start - 1]) {
        start -= 1;
    }
    (start < pos).then(|| (t[start..pos].iter().collect(), start))
}

/// The attributes in front of the declaration whose keyword is at `kw`, after
/// any visibility. An attribute may span lines.
fn attributes_before(t: &[char], kw: usize) -> Vec<String> {
    let mut pos = back_ws(t, kw);
    if pos > 0 && t[pos - 1] == ')' {
        // `pub(crate)`, `pub(in path)`
        let Some(open) = matching_open(t, pos, '(', ')') else {
            return Vec::new();
        };
        match word_ending_at(t, back_ws(t, open)) {
            Some((w, start)) if w == "pub" => pos = start,
            _ => return Vec::new(),
        }
    } else if let Some((w, start)) = word_ending_at(t, pos)
        && w == "pub"
    {
        pos = start;
    }
    let mut attrs = Vec::new();
    loop {
        pos = back_ws(t, pos);
        if pos == 0 || t[pos - 1] != ']' {
            return attrs;
        }
        let Some(open) = matching_open(t, pos, '[', ']') else {
            return attrs;
        };
        let hash = back_ws(t, open);
        if hash == 0 || t[hash - 1] != '#' {
            return attrs;
        }
        attrs.push(t[open..pos].iter().collect());
        pos = hash - 1;
    }
}

fn mentions_debug(attribute: &str) -> bool {
    attribute
        .split(|c: char| !is_ident(c))
        .any(|w| w == "Debug")
}

struct Declaration {
    name: String,
    attributes: Vec<String>,
}

/// Every `struct`, `enum` and `union` declared in the text.
fn declarations(text: &str) -> Vec<Declaration> {
    let t = blank_comments_and_strings(text);
    let mut out = Vec::new();
    for i in 0..t.len() {
        let Some(word) = word_at(&t, i) else { continue };
        if !matches!(word.as_str(), "struct" | "enum" | "union") {
            continue;
        }
        let name_at = skip_ws(&t, i + word.len());
        if name_at == i + word.len() {
            continue;
        }
        if let Some(name) = word_at(&t, name_at) {
            out.push(Declaration {
                name,
                attributes: attributes_before(&t, i),
            });
        }
    }
    out
}

/// The type of every `impl ... Debug for <type>` in the text.
fn handwritten_debug(text: &str) -> Vec<String> {
    let t = blank_comments_and_strings(text);
    let mut out = Vec::new();
    for i in 0..t.len() {
        if word_at(&t, i).as_deref() != Some("Debug") {
            continue;
        }
        let for_at = skip_ws(&t, i + "Debug".len());
        if word_at(&t, for_at).as_deref() != Some("for") {
            continue;
        }
        let name_at = skip_ws(&t, for_at + "for".len());
        if let Some(name) = word_at(&t, name_at) {
            out.push(name);
        }
    }
    out
}

#[test]
fn only_listed_types_derive_debug() {
    let files = sources();
    let mut seen = Vec::new();
    for (path, text) in &files {
        for decl in declarations(text) {
            seen.push(decl.name.clone());
            if MAY_DERIVE_DEBUG.contains(&decl.name.as_str()) {
                continue;
            }
            assert!(
                !decl.attributes.iter().any(|a| mentions_debug(a)),
                "{} in {} derives Debug; write a Debug that shows no content, or add the \
                 type to MAY_DERIVE_DEBUG if it holds nothing secret",
                decl.name,
                path.display()
            );
            let written: usize = files
                .iter()
                .map(|(_, t)| {
                    handwritten_debug(t)
                        .iter()
                        .filter(|n| **n == decl.name)
                        .count()
                })
                .sum();
            assert_eq!(
                written,
                1,
                "{} in {} needs exactly one hand-written Debug impl, found {written}",
                decl.name,
                path.display()
            );
        }
    }
    // A stale entry in the allowlist would let a new type of that name through.
    for name in MAY_DERIVE_DEBUG {
        assert_eq!(
            seen.iter().filter(|n| n == name).count(),
            1,
            "{name} is in MAY_DERIVE_DEBUG but is not declared exactly once"
        );
    }
}

#[test]
fn the_detector_sees_every_shape_of_derive() {
    // The check above would pass for the wrong reason if it could not see a
    // derive. Feed it the shapes it must catch.
    let text = r#"
/// Doc that mentions `struct Fake` and #[derive(Debug)].
#[derive(
    Clone,
    Copy,
    Debug,
)]
pub(crate) struct Wrapped<T>(T);

#[cfg_attr(test, derive(Debug))]
#[non_exhaustive]
pub enum Gated { A }

#[derive(Clone, Debug)] struct SameLine;

#[derive(Clone)]
pub struct Quiet([u8; 4]);

pub struct Bare;

const TEXT: &str = "struct InString { } #[derive(Debug)]";
// struct InComment
/* struct InBlock */
impl core::fmt::Debug for Quiet {}
impl<T> fmt::Debug for Wrapped<T> {}
impl Debug
    for Bare {}
"#;
    let found = declarations(text);
    let names: Vec<&str> = found.iter().map(|d| d.name.as_str()).collect();
    assert_eq!(names, ["Wrapped", "Gated", "SameLine", "Quiet", "Bare"]);
    let derives: Vec<bool> = found
        .iter()
        .map(|d| d.attributes.iter().any(|a| mentions_debug(a)))
        .collect();
    assert_eq!(derives, [true, true, true, false, false]);
    assert_eq!(handwritten_debug(text), ["Quiet", "Wrapped", "Bare"]);
}

#[test]
fn no_direct_argon2_dependency() {
    let manifest = std::fs::read_to_string(manifest_dir().join("Cargo.toml")).unwrap();
    // The comment in the manifest may name the key stretching function; no
    // dependency line or feature may.
    for line in manifest
        .lines()
        .filter(|l| !l.trim_start().starts_with('#'))
    {
        assert!(!line.contains("argon2"), "Cargo.toml names argon2: {line}");
        assert!(
            !line.contains("opaque-ke"),
            "Cargo.toml names opaque-ke: {line}"
        );
        assert!(
            !line.contains("opaque_ke"),
            "Cargo.toml names opaque_ke: {line}"
        );
    }
}

#[test]
fn there_is_one_suite_and_it_is_the_cores() {
    for (path, text) in sources() {
        for needle in [
            "impl CipherSuite",
            "OPAQUE_CONTEXT: ",
            "argon2::",
            "tracing::",
        ] {
            assert!(
                !text.contains(needle),
                "{} contains `{needle}`",
                path.display()
            );
        }
    }
}

#[test]
fn ct_include_is_the_analyzer_source() {
    let root = manifest_dir().join("../..");
    let own = std::fs::read_to_string(manifest_dir().join("src/ct.rs")).unwrap();
    let core = std::fs::read_to_string(root.join("crates/ferret-core/src/prim/ct.rs")).unwrap();
    for file in ["ct_eq.rs", "ct_select.rs"] {
        // This crate includes the analyzer's file by path ...
        let line = format!("include!(\"../../../ct/harness/{file}\");");
        assert!(
            own.contains(&line),
            "ct.rs does not include ct/harness/{file}"
        );
        // ... and so does ferret-core, from one folder deeper: one source.
        let core_line = format!("include!(\"../../../../ct/harness/{file}\");");
        assert!(
            core.contains(&core_line),
            "ferret-core does not include {file}"
        );
        assert!(
            root.join("ct/harness").join(file).is_file(),
            "{file} is missing"
        );
    }
    // No second definition of the comparison or the selection elsewhere in the
    // crate (src/ct.rs itself only includes the files).
    let (eq, select) = ("fn ct_eq", "fn ct_select");
    for (path, text) in sources() {
        if path.file_name().is_some_and(|n| n == "ct.rs") {
            continue;
        }
        assert!(
            !text.contains(eq) && !text.contains(select),
            "{} defines its own constant-time function",
            path.display()
        );
    }
}

/// A proof is verified in `replace.rs` and nowhere else, so every proof meets
/// the single-use nonce first. The comment-free text is searched, so a mention
/// in documentation does not count.
#[test]
fn proofs_are_verified_in_one_module_only() {
    let mut found = 0;
    for (path, text) in sources() {
        let code: String = blank_comments_and_strings(&text).into_iter().collect();
        for name in ["verify_auth_proof", "verify_recovery_proof"] {
            let count = code.matches(name).count();
            if path.file_name().is_some_and(|n| n == "replace.rs") {
                found += count;
            } else {
                assert_eq!(count, 0, "{} calls {name}", path.display());
            }
        }
    }
    // The module itself uses both (an import and a call each).
    assert!(found >= 2, "replace.rs no longer verifies proofs");
}

// ------------------------------------------------------------ comparisons

/// The text of a source file as it is shipped: no test module, and no
/// comments or string literals.
fn shipped(text: &str) -> String {
    let text = text.replace("\r\n", "\n");
    let cut = text.find("#[cfg(test)]\nmod ").unwrap_or(text.len());
    blank_comments_and_strings(&text[..cut])
        .into_iter()
        .collect()
}

/// The shipped files of `src/` with the name of each, without the test
/// tooling (`testing.rs` and `testing/`, which are behind a feature and never
/// part of a release build).
fn shipped_sources() -> Vec<(String, String)> {
    sources()
        .into_iter()
        .filter(|(path, _)| {
            !path
                .components()
                .any(|c| c.as_os_str().to_string_lossy().starts_with("testing"))
        })
        .map(|(path, text)| {
            let name = path.file_name().unwrap().to_string_lossy().into_owned();
            (name, shipped(&text))
        })
        .collect()
}

/// Whether the line has an `==` or a `!=` operator.
fn has_equality(line: &str) -> bool {
    let c: Vec<char> = line.chars().collect();
    (0..c.len().saturating_sub(1)).any(|i| {
        let before = i.checked_sub(1).map(|j| c[j]);
        let after = c.get(i + 2).copied();
        let equals = c[i] == '='
            && c[i + 1] == '='
            && !matches!(before, Some('=' | '!' | '<' | '>'))
            && after != Some('=');
        let differs = c[i] == '!' && c[i + 1] == '=' && after != Some('=');
        equals || differs
    })
}

/// Every place in the shipped code that has `==` or `!=`, with the reason it
/// cannot leak. The compare of a value that may be secret goes through
/// `ct_eq` (`src/ct.rs`), and those do not show here. A new line with an
/// operator fails the test until it is read and listed: (file, text of the
/// line, how many lines have it, why it is not a secret).
const COMPARISONS: &[(&str, &str, usize, &str)] = &[
    // Lengths and counts: public.
    ("ids.rs", "text.len() != Self::HEX_LEN", 1, "a length"),
    (
        "keys.rs",
        "payload.len() != SERVER_SETUP_LEN",
        1,
        "a length",
    ),
    (
        "keys.rs",
        "payload.len() != PRELOGIN_PAYLOAD_LEN",
        1,
        "a length",
    ),
    (
        "login.rs",
        "serialized.len() == SERVER_LOGIN_LEN",
        1,
        "a length",
    ),
    ("login.rs", "bytes.len() != KE1_LEN", 1, "a length"),
    ("login.rs", "bytes.len() != KE3_LEN", 1, "a length"),
    (
        "record.rs",
        "bytes.len() != REGISTRATION_RECORD_LEN",
        1,
        "a length",
    ),
    (
        "registration.rs",
        "request.len() != REGISTRATION_REQUEST_LEN",
        1,
        "a length",
    ),
    (
        "secret_file.rs",
        "payload.len() != kind.payload_len()",
        1,
        "a length",
    ),
    (
        "secret_file.rs",
        "declared != kind.payload_len()",
        1,
        "a length in the header of a file",
    ),
    ("replace.rs", "self.len() == 0", 1, "a count of entries"),
    ("state.rs", "self.len() == 0", 1, "a count of entries"),
    (
        "replace.rs",
        "self.capacity == 0",
        1,
        "a setting of the store",
    ),
    (
        "state.rs",
        "self.capacity == 0",
        1,
        "a setting of the store",
    ),
    // Times, numbers and closed sets.
    ("login.rs", "now == u64::MAX", 1, "the time"),
    ("replace.rs", "now == u64::MAX", 2, "the time"),
    (
        "login.rs",
        "stored.sk_hint, u8::from(fake.sk_hint)) == 1",
        1,
        "the one bit that the branch-free choice of the hint gives; the hint is in the answer to the client",
    ),
    (
        "name.rs",
        "stable = next == current",
        1,
        "the normalisation of a login name has reached a fixed point; a login name is public",
    ),
    (
        "prelogin.rs",
        "== profiles.len();",
        1,
        "numbers of the server's own policy",
    ),
    (
        "prelogin.rs",
        "total == Some(u32::from(WHOLE))",
        1,
        "numbers of the server's own policy",
    ),
    (
        "prelogin.rs",
        "*profile != 0",
        1,
        "numbers of the server's own policy",
    ),
    (
        "secret_file.rs",
        "error.kind() == io::ErrorKind::NotFound",
        1,
        "an error kind",
    ),
    (
        "secret_file.rs",
        "version != FORMAT_VERSION",
        1,
        "a number in the header of a file",
    ),
    (
        "secret_file.rs",
        "file_kind != kind.code()",
        1,
        "a number in the header of a file",
    ),
    (
        "secret_file.rs",
        "suite != SUITE_RISTRETTO255",
        1,
        "a number in the header of a file",
    ),
    (
        "secret_file.rs",
        "(a.dev() == b.dev()) & (a.ino() == b.ino())",
        1,
        "device and inode numbers of two files",
    ),
    (
        "secret_file.rs",
        "(owner == euid) | (owner == 0)",
        1,
        "user numbers",
    ),
    ("secret_file.rs", "mode & 0o077 != 0", 1, "permission bits"),
    (
        "startup.rs",
        "loaded.prelogin_origin == FileOrigin::Created",
        1,
        "a closed set",
    ),
    (
        "state.rs",
        "self.code() == other.code()",
        1,
        "the purpose byte; the session and account bytes next to it go through ct_eq",
    ),
    (
        "state.rs",
        "*version != BLOB_VERSION",
        1,
        "the version byte of a blob, which is in the clear",
    ),
    // Public data compared with public data.
    (
        "replace.rs",
        "key == account.account.pk_r",
        1,
        "two public keys (a recovery may not name the key the account already has)",
    ),
    (
        "secret_file.rs",
        "bytes.get(..seen) != MAGIC.get(..seen)",
        1,
        "the first bytes of a file against the public magic of the format",
    ),
    (
        "startup.rs",
        "stored != actual",
        1,
        "two set-up fingerprints at start-up, with the constant-time compare of SetupFingerprint, and no remote caller",
    ),
];

#[test]
fn no_secret_comparison_uses_eq() {
    let mut used = vec![0usize; COMPARISONS.len()];
    for (file, code) in shipped_sources() {
        for line in code.lines().map(str::trim).filter(|l| has_equality(l)) {
            let hit = COMPARISONS
                .iter()
                .position(|(f, text, _, _)| *f == file && line.contains(text));
            match hit {
                Some(n) => used[n] += 1,
                None => panic!(
                    "{file}: `{line}` compares with == or !=. Compare a value that may be \
                     secret with ct_eq (src/ct.rs); if nothing here can be secret, list \
                     the line in COMPARISONS with the reason"
                ),
            }
        }
    }
    for (n, (file, text, count, _)) in COMPARISONS.iter().enumerate() {
        assert_eq!(
            used[n], *count,
            "COMPARISONS: {file} `{text}` is on {} lines, listed for {count}",
            used[n]
        );
    }
}

#[test]
fn the_comparison_detector_sees_every_operator() {
    for line in [
        "if a == b {",
        "x = a != b;",
        "a.ct_value() == 1",
        "if (a == b) & c {",
        "assert!(a ==b)",
        "w == [1; 8]",
    ] {
        assert!(has_equality(line), "{line}");
    }
    for line in [
        "a <= b",
        "a >= b",
        "a => b",
        "x = y;",
        "a >>= 1;",
        "a <<= 1;",
        "a |= b;",
        "let f = |x| x;",
        "if !ready {",
    ] {
        assert!(!has_equality(line), "{line}");
    }
    // The text is compared without comments and strings, and without the test
    // module.
    let code = shipped(
        "// a == b\nfn f() { let s = \"a == b\"; }\n#[cfg(test)]\nmod tests {\n    fn g() { assert!(a == b); }\n}\n",
    );
    assert!(!code.lines().any(has_equality), "{code}");
}

/// The calls of the constant-time functions, per file: how many times each
/// is called in shipped code. Each call has a row in `ct/TRIAGE.md` (the part
/// on the server library) and a timing test in `ct/dudect`; a call that is
/// added or moved fails here until both have been looked at.
const CT_CALLS: &[(&str, &str, usize)] = &[
    ("ct_eq(", "keys.rs", 1),
    ("ct_eq(", "login.rs", 1),
    ("ct_eq(", "registration.rs", 1),
    ("ct_eq(", "secret_file.rs", 1),
    ("ct_eq(", "state.rs", 2),
    ("ct_select_bytes(", "login.rs", 2),
    ("ct_select_bytes(", "prelogin.rs", 1),
    ("ct_select_u8(", "login.rs", 2),
    ("ct_select_u32(", "", 0),
    ("ct_select_u64(", "", 0),
    ("commit_eq(", "", 0),
    ("mac_eq(", "", 0),
];

#[test]
fn the_constant_time_call_sites_are_the_ones_that_were_checked() {
    let files = shipped_sources();
    for (call, _, _) in CT_CALLS {
        for (file, code) in &files {
            if file == "ct.rs" {
                continue;
            }
            // `fn ct_eq(` and the like are definitions, not calls.
            let count = code.matches(call).count() - code.matches(&format!("fn {call}")).count();
            let expected = CT_CALLS
                .iter()
                .filter(|(c, f, _)| c == call && f == file)
                .map(|(_, _, n)| *n)
                .sum::<usize>();
            assert_eq!(
                count, expected,
                "{file} calls {call} {count} times, {expected} were checked (ct/TRIAGE.md, ct/dudect)"
            );
        }
    }
}

/// Types that derive `PartialEq` and hold bytes or text, with why a derived
/// (early-exit) compare of them cannot leak a secret. A type that holds a
/// bearer value (a login id, a session) is compared through its SHA-256 store
/// key, never as it is: the maps of the stores are keyed by the digest.
const DERIVES_PARTIAL_EQ_ON_BYTES: &[(&str, &str)] = &[
    (
        "CredentialId",
        "an account identifier; it is stored in the clear and sent by the server",
    ),
    (
        "LoginId",
        "a bearer value: no code compares it; the store is keyed by its SHA-256 digest (StateKey)",
    ),
    ("StateKey", "a SHA-256 digest, the key of the state map"),
    ("ChallengeKey", "a SHA-256 digest, the key of the nonce map"),
    ("NormalizedLoginName", "a login name, which is public"),
];

/// The text between the brackets that follow the name of a declaration.
fn declaration_body(t: &[char], from: usize) -> String {
    let mut i = from;
    while i < t.len() && !matches!(t[i], '{' | '(' | ';') {
        i += 1;
    }
    if i >= t.len() || t[i] == ';' {
        return String::new();
    }
    let (open, close) = if t[i] == '{' { ('{', '}') } else { ('(', ')') };
    let mut depth = 0usize;
    let mut j = i;
    while j < t.len() {
        if t[j] == open {
            depth += 1;
        } else if t[j] == close {
            depth -= 1;
            if depth == 0 {
                return t[i..=j].iter().collect();
            }
        }
        j += 1;
    }
    String::new()
}

fn holds_bytes(body: &str) -> bool {
    body.contains("[u8") || body.contains("Vec<u8>") || body.contains("String")
}

#[test]
fn types_with_bytes_derive_partial_eq_only_when_listed() {
    let mut seen = Vec::new();
    for (name, code) in shipped_sources() {
        let t: Vec<char> = code.chars().collect();
        for i in 0..t.len() {
            let Some(word) = word_at(&t, i) else { continue };
            if !matches!(word.as_str(), "struct" | "enum") {
                continue;
            }
            let name_at = skip_ws(&t, i + word.len());
            let Some(type_name) = word_at(&t, name_at) else {
                continue;
            };
            let derives = attributes_before(&t, i)
                .iter()
                .any(|a| a.split(|c: char| !is_ident(c)).any(|w| w == "PartialEq"));
            if derives && holds_bytes(&declaration_body(&t, name_at + type_name.len())) {
                assert!(
                    DERIVES_PARTIAL_EQ_ON_BYTES
                        .iter()
                        .any(|(n, _)| *n == type_name),
                    "{type_name} in {name} derives PartialEq over bytes or text; its == would \
                     stop at the first difference. Compare with ct_eq in a hand-written \
                     PartialEq, or list the type in DERIVES_PARTIAL_EQ_ON_BYTES with the reason"
                );
                seen.push(type_name);
            }
        }
    }
    for (name, _) in DERIVES_PARTIAL_EQ_ON_BYTES {
        assert!(
            seen.iter().any(|n| n == name),
            "{name} is listed in DERIVES_PARTIAL_EQ_ON_BYTES but does not derive PartialEq over bytes"
        );
    }
}

/// The WebAssembly scan and the WebAssembly timing tests (`ct/`) read the
/// binding of the core. The server library and the OPAQUE server suite are
/// not in it, so those checks have nothing of this crate to scan; this keeps
/// it that way.
#[test]
fn the_server_library_is_not_in_the_webassembly_build() {
    let root = manifest_dir().join("../..");
    let binding = std::fs::read_to_string(root.join("bindings/wasm/Cargo.toml")).unwrap();
    for needle in ["ferret-server-auth", "server-suite", "opaque"] {
        assert!(
            !binding.contains(needle),
            "bindings/wasm/Cargo.toml names {needle}: the constant-time checks of the \
             WebAssembly build (ct/wasm-allow.toml, ct/dudect-wasm) would have to cover it"
        );
    }
}
