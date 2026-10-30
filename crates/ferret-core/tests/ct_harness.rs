//! The single-file constant-time code in `ct/harness/` that is new in Task 14:
//! `base32.rs` and `ct_select.rs` compile on their own with `core` only, and
//! the core includes the same files that the analyzer reads. (`crockford.rs`
//! and `unpad.rs` are checked in `codes.rs` and `pad.rs`; `ct_eq.rs` needs
//! `subtle`, and the analyzer is given it with `--extern`.)

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

fn check_file(file: &str, name: &str, included_by: &str) {
    let source = harness(file);
    compile(&source, name);

    // With `#![no_std]` around it: nothing from `std` or `alloc`.
    let dir = std::env::temp_dir().join(format!("ferret-ct-nostd-{name}-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let wrapper = dir.join("no_std_wrapper.rs");
    std::fs::write(
        &wrapper,
        format!(
            "#![no_std]\ninclude!(r\"{}\");\n",
            source.canonicalize().unwrap().display()
        ),
    )
    .unwrap();
    compile(&wrapper, &format!("{name}_no_std"));
    let _ = std::fs::remove_dir_all(&dir);

    // It is the file the core runs.
    let user = std::fs::read_to_string(manifest().join(included_by)).unwrap();
    assert!(
        user.contains(&format!("ct/harness/{file}\")")),
        "{included_by} does not include ct/harness/{file}"
    );

    // Every public function is `#[inline(never)]`, or rustc may leave it out
    // of the compiled file and the analyzer has nothing to look at.
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
fn select_harness_is_one_file_with_core_only() {
    check_file("ct_select.rs", "select_single_file", "src/prim/ct.rs");
    // The mask is hidden from the optimizer (F-1 in ct/TRIAGE.md).
    let text = std::fs::read_to_string(harness("ct_select.rs")).unwrap();
    assert_eq!(text.matches("black_box(0").count(), 4);
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
