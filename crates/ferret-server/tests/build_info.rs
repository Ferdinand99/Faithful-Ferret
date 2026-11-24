//! `ferret --build-info` and the `e2e-clock` feature: a release build reports no
//! features, contains neither the clock hook nor the name of its variable, and
//! ignores `FERRET_E2E_CLOCK_FILE`. The same tests run against the real binary
//! (`CARGO_BIN_EXE_ferret`); the image tests of the test stack
//! (scripts/lanbox-ferret-e2e-check.sh) run them again on the built images.
//!
//! The binary also says where its web vault's WebAssembly package came from (the `wasm:` line),
//! and a release image refuses one that was built from the tree.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::process::Command;

// The code of the build script that reads and checks the record of the WebAssembly package.
#[path = "../build_support/wasm_source.rs"]
mod wasm_source;

const BIN: &str = env!("CARGO_BIN_EXE_ferret");

/// Bytes whose presence in a binary means the clock hook is in it: the name of
/// the variable, the feature name and the module name (which shows up in
/// symbols and in the file names of panic locations).
#[cfg(not(feature = "e2e-clock"))]
const HOOK_MARKERS: [&str; 3] = ["FERRET_E2E_CLOCK_FILE", "e2e-clock", "e2e_clock"];

fn contains(haystack: &[u8], needle: &str) -> bool {
    let needle = needle.as_bytes();
    haystack.windows(needle.len()).any(|w| w == needle)
}

/// The second line of the build info (`features: …`).
fn features_line(text: &str) -> &str {
    text.lines().nth(1).unwrap_or("")
}

fn run_build_info(env: &[(&str, &str)]) -> String {
    let mut cmd = Command::new(BIN);
    cmd.arg("--build-info");
    for (k, v) in env {
        cmd.env(k, v);
    }
    let out = cmd.output().unwrap();
    assert!(out.status.success(), "{out:?}");
    assert!(out.stderr.is_empty(), "{out:?}");
    String::from_utf8(out.stdout).unwrap()
}

#[test]
fn build_info_prints_the_version_and_the_features_of_this_build() {
    let text = run_build_info(&[]);
    let expected = if cfg!(feature = "e2e-clock") {
        "features: e2e-clock"
    } else {
        "features: none"
    };
    assert_eq!(
        text,
        format!(
            "ferret {}\n{expected}\nwasm: {}\n",
            env!("CARGO_PKG_VERSION"),
            ferret_server::build_info::wasm()
        )
    );
}

const SHA: &str = "8c50c5ea011c619e63c76c9b4790ba8d873d2077068f82e5712c2f135f5af48c";

#[test]
fn the_binary_says_where_its_web_vault_wasm_came_from() {
    let text = run_build_info(&[]);
    let line = text.lines().nth(2).unwrap();
    let wasm = line.strip_prefix("wasm: ").unwrap();
    if wasm != "none" {
        let (source, sha256) = wasm.split_once(' ').unwrap();
        assert!(["lock", "release", "tree"].contains(&source), "{wasm}");
        assert_eq!(sha256.len(), 64, "{wasm}");
        assert!(sha256.bytes().all(|b| b.is_ascii_hexdigit()), "{wasm}");
    }
    // An image built as a release (the Dockerfile sets this when it gets a revision) never says tree.
    if option_env!("FERRET_RELEASE_BUILD").is_some_and(|v| !v.is_empty()) {
        assert!(!wasm.starts_with("tree"), "{wasm}");
        assert_ne!(wasm, "none");
    }
}

#[test]
fn the_release_server_image_refuses_a_tree_built_web_vault() {
    let record =
        |source: &str| format!("{{\n  \"source\": \"{source}\",\n  \"sha256\": \"{SHA}\"\n}}\n");
    // What the web build writes for each source is read as it is.
    let lock = wasm_source::parse(&format!(
        "{{\n  \"source\": \"lock\",\n  \"version\": \"0.8.0\",\n  \"sha256\": \"{SHA}\"\n}}\n"
    ))
    .unwrap();
    assert_eq!((lock.source.as_str(), lock.sha256.as_str()), ("lock", SHA));
    let release = wasm_source::parse(&record("release")).unwrap();
    let tree = wasm_source::parse(&format!(
        "{{\n  \"source\": \"tree\",\n  \"commit\": \"0123456789abcdef0123456789abcdef01234567-dirty\",\n  \"sha256\": \"{SHA}\"\n}}\n"
    ))
    .unwrap();
    assert_eq!(tree.source, "tree");

    // A release image takes the locked package or the package of its own release run, and nothing else.
    wasm_source::check_release(&lock).unwrap();
    wasm_source::check_release(&release).unwrap();
    let refused = wasm_source::check_release(&tree).unwrap_err();
    assert!(refused.contains("tree"), "{refused}");

    // A record that is not one of the three, or whose digest is not a digest, never gets as far as the check.
    for bad in [
        record("elsewhere"),
        record("Tree"),
        record(""),
        "{}".to_string(),
        format!(
            "{{\"source\": \"lock\", \"sha256\": \"{}\"}}",
            SHA.to_uppercase()
        ),
        format!("{{\"source\": \"lock\", \"sha256\": \"{}\"}}", &SHA[1..]),
        "{\"source\": \"lock\"}".to_string(),
    ] {
        assert!(wasm_source::parse(&bad).is_err(), "{bad}");
    }

    // What the build script decides, in the four situations that matter (it calls this function).
    let tree_record = format!(
        "{{\"source\": \"tree\", \"commit\": \"0123456789abcdef0123456789abcdef01234567\", \"sha256\": \"{SHA}\"}}"
    );
    let lock_record = format!("{{\"source\": \"lock\", \"version\": \"0.8.0\", \"sha256\": \"{SHA}\"}}");
    // a release image with a tree package: refused, in either profile
    for profile in [true, false] {
        let refused = wasm_source::decide(Some(&tree_record), true, profile, false).unwrap_err();
        assert!(refused.contains("tree"), "{refused}");
    }
    // a test build may carry it, and says so
    assert_eq!(
        wasm_source::decide(Some(&tree_record), false, true, false).unwrap(),
        ("tree".to_string(), SHA.to_string())
    );
    // a release image with the locked package, or this release's own
    assert_eq!(
        wasm_source::decide(Some(&lock_record), true, true, false).unwrap(),
        ("lock".to_string(), SHA.to_string())
    );
    assert_eq!(wasm_source::decide(Some(&record("release")), true, true, false).unwrap().0, "release");
    // no record: an error in a release-profile build with a vault, `none` otherwise
    assert!(wasm_source::decide(None, true, true, false).is_err());
    assert!(wasm_source::decide(None, false, true, false).is_err());
    assert_eq!(wasm_source::decide(None, false, true, true).unwrap().0, "none");
    assert_eq!(wasm_source::decide(None, false, false, false).unwrap().0, "none");
    // a record that is not one is an error too
    assert!(wasm_source::decide(Some("{}"), false, false, false).is_err());

    // The wiring: the build script calls it with the release marker, and the Dockerfile sets the
    // marker for every build that gets a revision.
    let manifest = env!("CARGO_MANIFEST_DIR");
    let build_rs = std::fs::read_to_string(format!("{manifest}/build.rs")).unwrap();
    assert!(build_rs.contains("wasm_source::decide(") && build_rs.contains("\"FERRET_RELEASE_BUILD\""));
    let dockerfile =
        std::fs::read_to_string(format!("{manifest}/../../docker/server.Dockerfile")).unwrap();
    assert!(dockerfile.contains("FERRET_RELEASE_BUILD=${REVISION:+1}"));
}

#[test]
fn build_info_needs_no_configuration() {
    // The flag works without the vault and admin URLs that the server needs.
    let out = Command::new(BIN)
        .arg("--build-info")
        .env_clear()
        .output()
        .unwrap();
    assert!(out.status.success(), "{out:?}");
    assert!(out.stdout.starts_with(b"ferret "));
}

#[test]
fn another_flag_next_to_build_info_is_refused() {
    let out = Command::new(BIN)
        .args(["--build-info", "--vault-url", "https://v.example.com"])
        .output()
        .unwrap();
    assert!(!out.status.success());
}

#[cfg(not(feature = "e2e-clock"))]
mod release {
    use super::*;

    #[test]
    fn release_binary_has_no_e2e_clock() {
        let binary = std::fs::read(BIN).unwrap();
        for marker in HOOK_MARKERS {
            assert!(!contains(&binary, marker), "the binary contains {marker}");
        }
        assert_eq!(features_line(&run_build_info(&[])), "features: none");
    }

    #[test]
    fn e2e_clock_cannot_be_enabled_by_environment_alone() {
        // Without the feature there is no code that reads the variable, so
        // setting it changes nothing, and the name is not even in the binary.
        let file = std::env::temp_dir().join(format!("ferret-clock-{}", std::process::id()));
        std::fs::write(&file, "31536000").unwrap();
        let text = run_build_info(&[("FERRET_E2E_CLOCK_FILE", file.to_str().unwrap())]);
        assert_eq!(features_line(&text), "features: none", "{text}");
        std::fs::remove_file(&file).unwrap();
        assert!(!contains(
            &std::fs::read(BIN).unwrap(),
            "FERRET_E2E_CLOCK_FILE"
        ));
    }
}

#[cfg(feature = "e2e-clock")]
mod e2e {
    use super::*;

    #[test]
    fn e2e_binary_has_the_clock_hook_and_says_so() {
        let binary = std::fs::read(BIN).unwrap();
        assert!(contains(&binary, "FERRET_E2E_CLOCK_FILE"));
        assert_eq!(features_line(&run_build_info(&[])), "features: e2e-clock");
    }
}

#[cfg(unix)]
#[test]
fn an_argument_that_is_not_utf8_is_refused_by_clap_and_does_not_panic() {
    use std::os::unix::ffi::OsStrExt as _;
    let out = Command::new(BIN)
        .arg(std::ffi::OsStr::from_bytes(b"--vault-url=\xff"))
        .env_clear()
        .output()
        .unwrap();
    // clap's usage error is exit code 2; a panic would be 101 (or a signal with
    // `panic = "abort"`).
    assert_eq!(out.status.code(), Some(2), "{out:?}");
    assert!(!String::from_utf8_lossy(&out.stderr).contains("panicked"));
}
