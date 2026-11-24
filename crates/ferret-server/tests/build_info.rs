//! `ferret --build-info` and the cargo features that only a test or a later release has on:
//! `e2e-clock` (the test clock) and `quick-unlock` (PIN and passkey unlock). A release build reports no
//! features, contains neither the clock hook nor the name of its variable, nor the name of the unlock
//! feature, has no Unlock tab and no passkey routes, and ignores `FERRET_E2E_CLOCK_FILE`. The same tests
//! run against the real binary (`CARGO_BIN_EXE_ferret`); the image tests of the test stack
//! (scripts/lanbox-ferret-e2e-check.sh) run them again on the built images.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::process::Command;

const BIN: &str = env!("CARGO_BIN_EXE_ferret");

/// Bytes whose presence in a binary means the clock hook is in it: the name of
/// the variable, the feature name and the module name (which shows up in
/// symbols and in the file names of panic locations).
#[cfg(not(feature = "e2e-clock"))]
const HOOK_MARKERS: [&str; 3] = ["FERRET_E2E_CLOCK_FILE", "e2e-clock", "e2e_clock"];

/// Bytes whose presence in a binary means that the unlock feature is in it: the feature name (both spellings) and the
/// path of the Unlock tab of the admin pages. Each part of the feature that has a route or a page of its own adds its
/// path here, in the change that adds it.
#[cfg(not(feature = "quick-unlock"))]
const UNLOCK_MARKERS: [&str; 3] = ["quick-unlock", "quick_unlock", "/settings/unlock"];

/// The features line that this build must print, in the order of `active_features`.
fn expected_features() -> String {
    let mut on: Vec<&str> = Vec::new();
    if cfg!(feature = "e2e-clock") {
        on.push("e2e-clock");
    }
    if cfg!(feature = "quick-unlock") {
        on.push("quick-unlock");
    }
    if on.is_empty() {
        "none".to_string()
    } else {
        on.join(", ")
    }
}

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
    assert_eq!(
        text,
        format!(
            "ferret {}\nfeatures: {}\n",
            env!("CARGO_PKG_VERSION"),
            expected_features()
        )
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
        assert!(!run_build_info(&[]).contains("e2e-clock"));
    }

    #[test]
    fn e2e_clock_cannot_be_enabled_by_environment_alone() {
        // Without the feature there is no code that reads the variable, so
        // setting it changes nothing, and the name is not even in the binary.
        let file = std::env::temp_dir().join(format!("ferret-clock-{}", std::process::id()));
        std::fs::write(&file, "31536000").unwrap();
        let text = run_build_info(&[("FERRET_E2E_CLOCK_FILE", file.to_str().unwrap())]);
        assert!(!text.contains("e2e-clock"), "{text}");
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
        assert!(run_build_info(&[]).contains("e2e-clock"));
    }
}

#[cfg(not(feature = "quick-unlock"))]
mod release_unlock {
    use super::*;

    /// A release server has no unlock feature: it does not say so, and nothing of it is in the binary. The routes of
    /// the passkey methods and the Unlock tab of the admin pages are mounted only with the feature, so their paths
    /// are not there either.
    #[test]
    fn a_release_server_has_no_prf_routes_and_no_unlock_tab() {
        let binary = std::fs::read(BIN).unwrap();
        for marker in UNLOCK_MARKERS {
            assert!(!contains(&binary, marker), "the binary contains {marker}");
        }
        assert!(!run_build_info(&[]).contains("quick-unlock"));
    }

    #[test]
    fn the_feature_cannot_be_turned_on_by_environment_alone() {
        // There is no variable that reads the feature: whatever is set, the build says what it was built with.
        let text = run_build_info(&[
            ("FERRET_QUICK_UNLOCK", "1"),
            ("QUICK_UNLOCK", "1"),
            ("FERRET_FEATURES", "quick-unlock"),
        ]);
        assert!(!text.contains("quick-unlock"), "{text}");
    }
}

#[cfg(feature = "quick-unlock")]
mod unlock_build {
    use super::*;

    #[test]
    fn a_build_with_the_unlock_feature_says_so() {
        assert!(run_build_info(&[]).contains("quick-unlock"));
        assert!(contains(&std::fs::read(BIN).unwrap(), "quick-unlock"));
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
