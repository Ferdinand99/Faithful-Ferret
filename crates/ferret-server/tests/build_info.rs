//! `ferret --build-info` and the `e2e-clock` feature: a release build reports no
//! features, contains neither the clock hook nor the name of its variable, and
//! ignores `FERRET_E2E_CLOCK_FILE`. The same tests run against the real binary
//! (`CARGO_BIN_EXE_ferret`); the image tests of the test stack
//! (scripts/lanbox-ferret-e2e-check.sh) run them again on the built images.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::process::Command;

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
        format!("ferret {}\n{expected}\n", env!("CARGO_PKG_VERSION"))
    );
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
        assert!(run_build_info(&[]).ends_with("features: none\n"));
    }

    #[test]
    fn e2e_clock_cannot_be_enabled_by_environment_alone() {
        // Without the feature there is no code that reads the variable, so
        // setting it changes nothing, and the name is not even in the binary.
        let file = std::env::temp_dir().join(format!("ferret-clock-{}", std::process::id()));
        std::fs::write(&file, "31536000").unwrap();
        let text = run_build_info(&[("FERRET_E2E_CLOCK_FILE", file.to_str().unwrap())]);
        assert!(text.ends_with("features: none\n"), "{text}");
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
        assert!(run_build_info(&[]).ends_with("features: e2e-clock\n"));
    }
}
