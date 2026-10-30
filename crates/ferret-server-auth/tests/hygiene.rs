//! Checks on the source and the manifest of the crate: no `derive(Debug)` over
//! secret values, no own cipher suite, no OPAQUE or Argon2 dependency of its
//! own.

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

/// Types that hold a message, a key, a state or an identifier that must not be
/// told apart in a log. Each needs a hand-written `Debug` that shows no
/// content, and none may derive it. Add every new type of this kind here.
const REDACTED: &[&str] = &["CredentialId", "LoginId", "StateKey", "SessionBinding"];

/// The attribute lines directly above the line at `at`.
fn attributes_above(lines: &[&str], at: usize) -> String {
    let mut above = Vec::new();
    for line in lines[..at].iter().rev() {
        let t = line.trim_start();
        if t.starts_with("#[") || t.starts_with("///") || t.starts_with("//") {
            above.push(t);
        } else {
            break;
        }
    }
    above.join("\n")
}

fn declares(line: &str, name: &str) -> bool {
    let t = line.trim_start();
    let t = t
        .strip_prefix("pub(crate) ")
        .or_else(|| t.strip_prefix("pub "))
        .unwrap_or(t);
    ["struct ", "enum "].iter().any(|kw| {
        t.strip_prefix(kw).is_some_and(|rest| {
            rest.strip_prefix(name)
                .is_some_and(|after| !after.starts_with(|c: char| c.is_alphanumeric() || c == '_'))
        })
    })
}

#[test]
fn no_derive_debug_on_secret_types() {
    let files = sources();
    for name in REDACTED {
        let mut declared = 0;
        let mut handwritten = 0;
        for (path, text) in &files {
            let lines: Vec<&str> = text.lines().collect();
            for (i, line) in lines.iter().enumerate() {
                if declares(line, name) {
                    declared += 1;
                    let attrs = attributes_above(&lines, i);
                    assert!(
                        !attrs.contains("Debug"),
                        "{name} in {} derives Debug:\n{attrs}",
                        path.display()
                    );
                }
                let t = line.trim_start();
                if (t.starts_with("impl fmt::Debug for ")
                    || t.starts_with("impl core::fmt::Debug for ")
                    || t.starts_with("impl std::fmt::Debug for ")
                    || t.starts_with("impl Debug for "))
                    && t.split_whitespace().nth(3).is_some_and(|n| n == *name)
                {
                    handwritten += 1;
                }
            }
        }
        assert_eq!(declared, 1, "{name} is declared {declared} times");
        assert_eq!(handwritten, 1, "{name} needs one hand-written Debug impl");
    }
}

#[test]
fn the_detector_sees_a_derive() {
    // The check above would pass for the wrong reason if it could not see a
    // derive. Feed it the shapes it must catch.
    let text = "/// Doc.\n#[derive(Clone, Copy, Debug)]\npub struct Thing([u8; 4]);\n";
    let lines: Vec<&str> = text.lines().collect();
    assert!(declares(lines[2], "Thing"));
    assert!(!declares(lines[2], "Thin"));
    assert!(attributes_above(&lines, 2).contains("Debug"));
    let text = "#[derive(Debug)]\n#[allow(dead_code)]\npub(crate) enum Thing {}\n";
    let lines: Vec<&str> = text.lines().collect();
    assert!(declares(lines[2], "Thing"));
    assert!(attributes_above(&lines, 2).contains("Debug"));
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
