//! The single-file constant-time code in `ct/harness/` added with the constant-time checks:
//! `base32.rs` compiles on its own with `core` only, `ct_select.rs` and
//! `ct_eq.rs` need `subtle` (the analyzer is given it with `--extern`), and the
//! core includes the same files that the analyzer reads. (`crockford.rs` and
//! `unpad.rs` are checked in `codes.rs` and `pad.rs`.)

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]

use std::path::{Path, PathBuf};
use std::process::Command;

fn manifest() -> &'static Path {
    Path::new(env!("CARGO_MANIFEST_DIR"))
}

fn harness(file: &str) -> PathBuf {
    manifest().join("../../ct/harness").join(file)
}

fn compile(source: &Path, name: &str) {
    let out = std::env::temp_dir().join(format!("ferret-ct-{name}-{}", std::process::id()));
    std::fs::create_dir_all(&out).unwrap();
    let rustc = std::env::var("RUSTC").unwrap_or_else(|_| "rustc".into());
    let result = Command::new(rustc)
        .args([
            "--crate-type=lib",
            "--edition=2024",
            "--emit=metadata",
            "-D",
            "warnings",
        ])
        .arg("--crate-name")
        .arg(name)
        .arg("--out-dir")
        .arg(&out)
        .arg(source)
        .output()
        .expect("rustc must be on the PATH to compile the constant-time harness");
    let _ = std::fs::remove_dir_all(&out);
    assert!(
        result.status.success(),
        "rustc failed on {}:\n{}",
        source.display(),
        String::from_utf8_lossy(&result.stderr)
    );
}

/// The file is included by `included_by`, and every `pub fn` in it is
/// `#[inline(never)]` (or rustc may leave it out of the compiled file and the
/// analyzer has nothing to look at).
fn check_included(file: &str, included_by: &str) {
    let source = harness(file);
    let user = std::fs::read_to_string(manifest().join(included_by)).unwrap();
    assert!(
        user.contains(&format!("ct/harness/{file}\")")),
        "{included_by} does not include ct/harness/{file}"
    );
    let text = std::fs::read_to_string(&source).unwrap();
    let lines: Vec<&str> = text.lines().collect();
    for (i, line) in lines.iter().enumerate() {
        if line.starts_with("pub fn ") {
            let before = lines[..i]
                .iter()
                .rev()
                .take_while(|l| l.starts_with("///") || l.starts_with("#["))
                .any(|l| l.trim() == "#[inline(never)]");
            assert!(before, "{file}: `{line}` is not #[inline(never)]");
        }
    }
}

/// A file with `core` only: it also compiles on its own, and under `no_std`.
fn check_file(file: &str, name: &str, included_by: &str) {
    let source = harness(file);
    compile(&source, name);
    let dir = std::env::temp_dir().join(format!("ferret-ct-nostd-{name}-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let wrapper = dir.join("no_std_wrapper.rs");
    std::fs::write(
        &wrapper,
        format!(
            "#![no_std]
include!(r\"{}\");
",
            source.canonicalize().unwrap().display()
        ),
    )
    .unwrap();
    compile(&wrapper, &format!("{name}_no_std"));
    let _ = std::fs::remove_dir_all(&dir);
    check_included(file, included_by);
}

#[test]
fn base32_harness_is_one_file_with_core_only() {
    check_file("base32.rs", "base32_single_file", "src/totp.rs");
    let text = std::fs::read_to_string(harness("base32.rs")).unwrap();
    for line in text.lines() {
        let code = line.split("//").next().unwrap();
        assert!(!code.contains("ABCDEFGH"), "alphabet in code: {line}");
        assert!(
            !code.contains("const ") && !code.contains("static "),
            "table in code: {line}"
        );
    }
}

#[test]
fn select_harness_selects_through_subtle() {
    check_included("ct_select.rs", "src/prim/ct.rs");
    // The mask comes from `subtle::Choice`, whose barrier is a volatile read
    // behind `#[inline(never)]`; `black_box` is best effort only (F-1 in
    // ct/TRIAGE.md).
    let text = std::fs::read_to_string(harness("ct_select.rs")).unwrap();
    let code: String = text
        .lines()
        .filter(|l| !l.trim_start().starts_with("//"))
        .collect::<Vec<_>>()
        .join(
            "
",
        );
    assert!(code.contains("ConditionallySelectable") && code.contains("Choice::from"));
    assert!(!code.contains("black_box"));
}

#[test]
fn eq_harness_is_included_by_the_core() {
    let user = std::fs::read_to_string(manifest().join("src/prim/ct.rs")).unwrap();
    assert!(user.contains("ct/harness/ct_eq.rs\")"));
    let wrap = std::fs::read_to_string(manifest().join("src/wrap.rs")).unwrap();
    assert!(
        wrap.contains("commit_eq"),
        "the key commitment uses commit_eq"
    );
    let envelope = std::fs::read_to_string(manifest().join("src/envelope.rs")).unwrap();
    assert!(envelope.contains("mac_eq"), "the row tag uses mac_eq");
}
