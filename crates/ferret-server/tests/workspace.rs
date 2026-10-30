//! The server is a workspace of its own next to the root one. These tests keep
//! the two honest: no second copy of the crypto crates, the same release
//! profile, the same versions under ferret-core, a lock that release-please can
//! bump, and a root workspace that the server did not change.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use serde_json::Value;

fn server_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn root_dir() -> PathBuf {
    server_dir()
        .parent()
        .and_then(Path::parent)
        .expect("the repository root")
        .to_path_buf()
}

fn read(path: &Path) -> String {
    std::fs::read_to_string(path).unwrap_or_else(|e| panic!("{}: {e}", path.display()))
}

fn cargo() -> Command {
    Command::new(std::env::var_os("CARGO").unwrap_or_else(|| "cargo".into()))
}

fn run(command: &mut Command) -> Output {
    command
        .output()
        .unwrap_or_else(|e| panic!("{command:?}: {e}"))
}

fn text(output: &[u8]) -> String {
    String::from_utf8_lossy(output).into_owned()
}

/// The lines of the `[profile.release]` section (up to the next header).
fn release_profile(manifest: &str) -> Vec<String> {
    let mut lines = Vec::new();
    let mut inside = false;
    for line in manifest.lines() {
        let line = line.trim();
        if line.starts_with('[') {
            inside = line == "[profile.release]";
            continue;
        }
        if inside && !line.is_empty() && !line.starts_with('#') {
            lines.push(line.to_string());
        }
    }
    lines
}

fn setting(lines: &[String], key: &str) -> Option<String> {
    lines.iter().find_map(|line| {
        let (name, value) = line.split_once('=')?;
        (name.trim() == key).then(|| value.trim().to_string())
    })
}

#[test]
fn no_argon2_or_opaque_ke_dependency() {
    // The key stretching and the OPAQUE suite are the core's. A direct line of
    // our own, under any name, would be a second copy with its own settings.
    let output = run(cargo()
        .args([
            "metadata",
            "--no-deps",
            "--format-version",
            "1",
            "--manifest-path",
        ])
        .arg(server_dir().join("Cargo.toml")));
    assert!(output.status.success(), "{}", text(&output.stderr));
    let metadata: Value = serde_json::from_slice(&output.stdout).expect("metadata is JSON");
    let package = metadata["packages"]
        .as_array()
        .expect("packages")
        .iter()
        .find(|p| p["name"] == "ferret-server")
        .expect("the server package");
    for dependency in package["dependencies"].as_array().expect("dependencies") {
        let name = dependency["name"].as_str().expect("a name");
        assert!(
            !name.starts_with("argon2")
                && !name.starts_with("opaque-ke")
                && !name.starts_with("opaque_ke"),
            "ferret-server depends on {name} directly"
        );
    }
}

#[test]
fn release_profile_has_overflow_checks_and_panic_abort() {
    let ours = release_profile(&read(&server_dir().join("Cargo.toml")));
    let root = release_profile(&read(&root_dir().join("Cargo.toml")));
    // The two settings that matter, equal to the root's (the root's size
    // setting is for the WebAssembly package and is not compared).
    for key in ["overflow-checks", "panic"] {
        assert_eq!(setting(&ours, key), setting(&root, key), "{key}");
    }
    assert_eq!(setting(&ours, "overflow-checks").as_deref(), Some("true"));
    assert_eq!(setting(&ours, "panic").as_deref(), Some("\"abort\""));
}

/// Every `.rs` file under `dir`.
fn rust_files(dir: &Path, out: &mut Vec<PathBuf>) {
    for entry in std::fs::read_dir(dir).expect("read_dir") {
        let path = entry.expect("entry").path();
        if path.is_dir() {
            rust_files(&path, out);
        } else if path.extension().is_some_and(|e| e == "rs") {
            out.push(path);
        }
    }
}

#[test]
fn client_integers_use_checked_arithmetic() {
    let src = server_dir().join("src");
    let deny = "#![deny(clippy::arithmetic_side_effects)]";
    for module in ["auth", "vault"] {
        let mod_rs = read(&src.join(module).join("mod.rs"));
        assert!(
            mod_rs.lines().any(|l| l.trim() == deny),
            "src/{module}/mod.rs must have {deny}"
        );
    }
    // Nothing in auth/ and vault/ (or at the crate root) may switch the lint
    // off, except a test module.
    let mut files = Vec::new();
    rust_files(&src.join("auth"), &mut files);
    rust_files(&src.join("vault"), &mut files);
    files.push(src.join("lib.rs"));
    files.push(src.join("main.rs"));
    let manifest = read(&server_dir().join("Cargo.toml"));
    assert!(
        !manifest.contains("[lints"),
        "Cargo.toml must not set lint levels: the rule is the attribute in auth/ and vault/"
    );
    for file in files {
        let lines: Vec<String> = read(&file).lines().map(|l| l.trim().to_string()).collect();
        for (i, line) in lines.iter().enumerate() {
            let switches_off = line.contains("arithmetic_side_effects")
                && (line.contains("allow(") || line.contains("expect(") || line.contains("warn("));
            if !switches_off || line.contains("cfg_attr(test") {
                continue;
            }
            let previous = lines[..i].iter().rev().find(|l| !l.is_empty());
            assert!(
                previous.is_some_and(|l| l.contains("#[cfg(test)]")),
                "{} line {}: {line}",
                file.display(),
                i + 1
            );
        }
    }
}

fn script() -> PathBuf {
    server_dir().join("check-lock.sh")
}

fn bash(args: &[&Path]) -> Output {
    run(Command::new("bash")
        .arg(script())
        .args(args)
        .current_dir(root_dir()))
}

#[cfg(unix)]
#[test]
fn check_lock_passes_and_detects_a_planted_version_mismatch() {
    // The real locks agree.
    let real = run(Command::new("bash").arg(script()).current_dir(root_dir()));
    assert!(
        real.status.success(),
        "check-lock.sh failed:\n{}",
        text(&real.stderr)
    );

    // A planted mismatch: the server tree has sha2 at another version than the
    // root tree.
    let dir = std::env::temp_dir().join(format!("ferret-lock-{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("mkdir");
    let root_tree = dir.join("root.txt");
    let same = dir.join("same.txt");
    let doctored = dir.join("doctored.txt");
    std::fs::write(
        &root_tree,
        "ferret-core v0.1.0 (/src/crates/ferret-core)\nsha2 v0.11.1\nsubtle v2.6.1\nzeroize v1.9.1 (*)\n",
    )
    .expect("write");
    std::fs::write(
        &same,
        "ferret-core v0.1.0 (/src/crates/ferret-core)\nsha2 v0.11.1\nzeroize v1.9.1\n",
    )
    .expect("write");
    std::fs::write(
        &doctored,
        "ferret-core v0.1.0 (/src/crates/ferret-core)\nsha2 v0.11.0\nzeroize v1.9.1\n",
    )
    .expect("write");
    let ok = bash(&[Path::new("--compare"), &root_tree, &same]);
    assert!(ok.status.success(), "{}", text(&ok.stderr));
    let bad = bash(&[Path::new("--compare"), &root_tree, &doctored]);
    assert!(!bad.status.success(), "a version mismatch must fail");
    assert!(
        text(&bad.stderr).contains("sha2 v0.11.0"),
        "{}",
        text(&bad.stderr)
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn release_please_extra_files_name_three_server_lock_paths_and_the_manifest_version() {
    let config: Value =
        serde_json::from_str(&read(&root_dir().join("release-please-config.json"))).expect("JSON");
    let files = config["packages"]["."]["extra-files"]
        .as_array()
        .expect("extra-files");
    let entries = |path: &str| -> Vec<String> {
        files
            .iter()
            .filter(|f| f["path"] == path)
            .map(|f| f["jsonpath"].as_str().expect("a jsonpath").to_string())
            .collect()
    };
    assert_eq!(
        entries("crates/ferret-server/Cargo.toml"),
        ["$.package.version"]
    );
    let lock = entries("crates/ferret-server/Cargo.lock");
    let names = ["ferret-core", "ferret-server-auth", "ferret-server"];
    assert_eq!(lock.len(), 3, "{lock:?}");
    for name in names {
        let want = format!("$.package[?(@.name.value=='{name}')].version");
        assert!(lock.contains(&want), "{name}: {lock:?}");
    }

    // The path dependencies carry no version requirement: a bump of the
    // version of the repository must not need an edit of this manifest.
    let manifest = read(&server_dir().join("Cargo.toml"));
    for line in manifest.lines().filter(|l| l.contains("path = \"../")) {
        assert!(!line.contains("version"), "{line}");
    }

    // The bump itself: set a new version in the manifest, in the root
    // workspace's package version and in the three lock entries, as
    // release-please does, and the lock must still be accepted.
    let scratch = std::env::temp_dir().join(format!("ferret-bump-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&scratch);
    copy_tree(
        &root_dir().join("crates/ferret-core"),
        &scratch.join("crates/ferret-core"),
    );
    copy_tree(
        &root_dir().join("crates/ferret-server-auth"),
        &scratch.join("crates/ferret-server-auth"),
    );
    // ferret-core has a development dependency on the vector generator.
    copy_tree(
        &root_dir().join("tools/vectorgen"),
        &scratch.join("tools/vectorgen"),
    );
    copy_tree(&server_dir(), &scratch.join("crates/ferret-server"));
    let root_manifest = read(&root_dir().join("Cargo.toml"));
    let members =
        "members = [\"crates/ferret-core\", \"crates/ferret-server-auth\", \"tools/vectorgen\"]";
    let root_manifest: String = root_manifest
        .lines()
        .map(|l| {
            if l.starts_with("members = ") {
                members.to_string()
            } else if l.starts_with("exclude = ") {
                "exclude = [\"crates/ferret-server\"]".to_string()
            } else {
                l.to_string()
            }
        })
        .collect::<Vec<_>>()
        .join("\n");
    let old = "0.1.0";
    let new = "9.8.7";
    std::fs::write(
        scratch.join("Cargo.toml"),
        root_manifest.replacen(
            &format!("version = \"{old}\""),
            &format!("version = \"{new}\""),
            1,
        ),
    )
    .expect("write root");
    let server_manifest = scratch.join("crates/ferret-server/Cargo.toml");
    let text_manifest = read(&server_manifest)
        .replacen(
            &format!("version = \"{old}\""),
            &format!("version = \"{new}\""),
            1,
        )
        // Absolute paths: the copy sits in a different tree.
        .replace(
            "path = \"../ferret-core\"",
            &format!("path = {:?}", scratch.join("crates/ferret-core")),
        )
        .replace(
            "path = \"../ferret-server-auth\"",
            &format!("path = {:?}", scratch.join("crates/ferret-server-auth")),
        );
    std::fs::write(&server_manifest, text_manifest).expect("write manifest");
    let lock_path = scratch.join("crates/ferret-server/Cargo.lock");
    let bumped = bump_lock(&read(&lock_path), &names, old, new);
    std::fs::write(&lock_path, &bumped).expect("write lock");
    let metadata = |manifest: &Path| {
        run(cargo()
            .args([
                "metadata",
                "--locked",
                "--format-version",
                "1",
                "--manifest-path",
            ])
            .arg(manifest))
    };
    let good = metadata(&server_manifest);
    assert!(
        good.status.success(),
        "a bumped lock is refused:\n{}",
        text(&good.stderr)
    );
    // A lock in which release-please missed one entry is refused.
    let missed = bump_lock(&read(&lock_path), &["ferret-core"], new, old);
    std::fs::write(&lock_path, missed).expect("write lock");
    let bad = metadata(&server_manifest);
    assert!(!bad.status.success(), "a half-bumped lock must be refused");
    let _ = std::fs::remove_dir_all(&scratch);
}

/// Sets `version` of the `[[package]]` entries named in `names` from `old` to
/// `new`.
fn bump_lock(lock: &str, names: &[&str], old: &str, new: &str) -> String {
    let mut out = Vec::new();
    let mut current = String::new();
    for line in lock.lines() {
        if let Some(name) = line.strip_prefix("name = \"") {
            current = name.trim_end_matches('"').to_string();
        }
        if line == format!("version = \"{old}\"") && names.contains(&current.as_str()) {
            out.push(format!("version = \"{new}\""));
        } else {
            out.push(line.to_string());
        }
    }
    out.join("\n") + "\n"
}

/// Copies a crate: its manifest, its sources and its other files, but not a
/// build directory.
fn copy_tree(from: &Path, to: &Path) {
    std::fs::create_dir_all(to).expect("mkdir");
    for entry in std::fs::read_dir(from).expect("read_dir") {
        let entry = entry.expect("entry");
        let name = entry.file_name();
        if name == "target" {
            continue;
        }
        let path = entry.path();
        let target = to.join(&name);
        if path.is_dir() {
            copy_tree(&path, &target);
        } else {
            std::fs::copy(&path, &target).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
        }
    }
}

#[test]
fn root_workspace_is_unchanged() {
    // The root workspace has the same members as before, none of them is the
    // server, and its lock does not need a change: no new package, no new
    // crate. `--locked` fails if the lock would change.
    let root_manifest = root_dir().join("Cargo.toml");
    let output = run(cargo()
        .args([
            "metadata",
            "--locked",
            "--format-version",
            "1",
            "--manifest-path",
        ])
        .arg(&root_manifest));
    assert!(
        output.status.success(),
        "the root workspace needs a lock change:\n{}",
        text(&output.stderr)
    );
    let metadata: Value = serde_json::from_slice(&output.stdout).expect("metadata is JSON");
    let mut members: Vec<String> = metadata["packages"]
        .as_array()
        .expect("packages")
        .iter()
        .filter(|p| {
            metadata["workspace_members"]
                .as_array()
                .expect("members")
                .contains(&p["id"])
        })
        .map(|p| p["name"].as_str().expect("a name").to_string())
        .collect();
    members.sort();
    assert_eq!(
        members,
        [
            "ferret-core",
            "ferret-core-wasm",
            "ferret-server-auth",
            "ferret-vectorgen"
        ]
    );
    let lock = read(&root_dir().join("Cargo.lock"));
    for name in ["ferret-server", "vole-kit", "axum", "rusqlite"] {
        assert!(
            !lock.contains(&format!("name = \"{name}\"")),
            "the root lock has {name}"
        );
    }
    let exclude = read(&root_manifest);
    assert!(exclude.contains("\"crates/ferret-server\""));
}

#[test]
fn test_support_stays_out_of_the_release_graph_of_the_server() {
    // What the server ships (normal and build edges only) never has the test
    // helpers of the core or of the OPAQUE library switched on. The server
    // suite of the core is on by design.
    let output = run(cargo()
        .args(["tree", "-e", "normal,build", "-f", "{p} [{f}]", "--prefix", "none", "--locked", "--manifest-path"])
        .arg(server_dir().join("Cargo.toml")));
    assert!(output.status.success(), "{}", text(&output.stderr));
    let tree = text(&output.stdout);
    let core = tree
        .lines()
        .find(|l| l.starts_with("ferret-core "))
        .expect("ferret-core is in the graph");
    assert!(core.contains("server-suite"), "{core}");
    assert!(!core.contains("test-support"), "{core}");
    let auth = tree
        .lines()
        .find(|l| l.starts_with("ferret-server-auth "))
        .expect("ferret-server-auth is in the graph");
    assert!(!auth.contains("test-support"), "{auth}");
}
