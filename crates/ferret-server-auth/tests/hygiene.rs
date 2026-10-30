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
