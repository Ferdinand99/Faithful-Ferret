//! `ferret --build-info`: the version and the cargo features this binary was
//! built with and where its web vault's WebAssembly package came from, as three lines of plain
//! text:
//!
//! ```text
//! ferret 0.1.0
//! features: quick-unlock
//! wasm: lock 8c50c5ea011c619e63c76c9b4790ba8d873d2077068f82e5712c2f135f5af48c
//! ```
//!
//! The third line says where the web vault's WebAssembly package came from and its SHA-256:
//! `lock` (the published package of web/wasm.lock.json), `release` (the package of the release
//! run that built the image, equal to its entry in the signed SHA256SUMS) or `tree` (a test
//! build from the commit, never a release image). `wasm: none` is a build without a vault.
//!
//! The release image says `features: quick-unlock` (the release workflow, the stack with real data and
//! the deploy drill require exactly that line); the image of the end-to-end stack says
//! `features: e2e-clock, quick-unlock`, so a release image is told from a test image by the clock.

use std::ffi::{OsStr, OsString};

use crate::product::VERSION;

/// The cargo features of this build that change what the server does, in
/// alphabetical order. A release build has `quick-unlock` and nothing else.
///
/// Each name is pushed under its own `cfg`, so a feature that is off leaves no
/// trace of its name in the binary.
#[allow(unused_mut, clippy::vec_init_then_push)]
pub fn active_features() -> Vec<&'static str> {
    let mut features: Vec<&'static str> = Vec::new();
    #[cfg(feature = "dev-no-web")]
    features.push("dev-no-web");
    #[cfg(feature = "e2e-clock")]
    features.push("e2e-clock");
    #[cfg(feature = "quick-unlock")]
    features.push("quick-unlock");
    features
}

/// Where the web vault's WebAssembly package came from and its SHA-256, as `build.rs` read them
/// from `web/dist/wasm-source.json`: `lock <sha256>`, `release <sha256>`, `tree <sha256>` or
/// `none` (no vault in this build).
pub fn wasm() -> String {
    let source = option_env!("FERRET_WASM_SOURCE").unwrap_or("none");
    match option_env!("FERRET_WASM_SHA256") {
        Some(sha256) if !sha256.is_empty() && source != "none" => format!("{source} {sha256}"),
        _ => "none".to_string(),
    }
}

/// The text printed by `--build-info`, with a final newline.
pub fn text() -> String {
    let features = active_features();
    let list = if features.is_empty() {
        "none".to_string()
    } else {
        features.join(", ")
    };
    let wasm = wasm();
    format!("ferret {VERSION}\nfeatures: {list}\nwasm: {wasm}\n")
}

/// Whether the command line is exactly `ferret --build-info`.
pub fn requested(mut args: impl Iterator<Item = OsString>) -> bool {
    args.next(); // the program name
    args.next().as_deref() == Some(OsStr::new("--build-info")) && args.next().is_none()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(list: &[&str]) -> impl Iterator<Item = OsString> {
        list.iter()
            .map(OsString::from)
            .collect::<Vec<_>>()
            .into_iter()
    }

    #[test]
    fn only_the_bare_flag_asks_for_the_build_info() {
        assert!(requested(args(&["ferret", "--build-info"])));
        assert!(!requested(args(&["ferret"])));
        assert!(!requested(args(&[
            "ferret",
            "--build-info",
            "--vault-url",
            "x"
        ])));
        assert!(!requested(args(&["ferret", "--version"])));
    }

    #[cfg(unix)]
    #[test]
    fn an_argument_that_is_not_utf8_is_not_the_flag() {
        use std::os::unix::ffi::OsStringExt as _;
        let bad = OsString::from_vec(vec![0xff, 0xfe]);
        assert!(!requested([OsString::from("ferret"), bad].into_iter()));
    }

    #[test]
    fn the_text_names_the_version_the_features_and_the_wasm_package() {
        let text = text();
        let mut lines = text.lines();
        assert_eq!(lines.next(), Some(format!("ferret {VERSION}").as_str()));
        let expected = if active_features().is_empty() {
            "features: none".to_string()
        } else {
            format!("features: {}", active_features().join(", "))
        };
        assert_eq!(lines.next(), Some(expected.as_str()));
        assert_eq!(lines.next(), Some(format!("wasm: {}", wasm()).as_str()));
        assert_eq!(lines.next(), None);
    }
}
