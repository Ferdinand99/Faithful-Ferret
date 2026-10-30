//! `ferret --build-info`: the version and the cargo features this binary was
//! built with, as two lines of plain text:
//!
//! ```text
//! ferret 0.1.0
//! features: none
//! ```
//!
//! The test stack uses it to tell a release image (no features) from the image
//! of the end-to-end stack (`features: e2e-clock`).

use std::ffi::{OsStr, OsString};

use crate::product::VERSION;

/// The cargo features of this build that change what the server does, in
/// alphabetical order. Empty for a release build.
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
    features
}

/// The text printed by `--build-info`, with a final newline.
pub fn text() -> String {
    let features = active_features();
    let list = if features.is_empty() {
        "none".to_string()
    } else {
        features.join(", ")
    };
    format!("ferret {VERSION}\nfeatures: {list}\n")
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
        list.iter().map(OsString::from).collect::<Vec<_>>().into_iter()
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
    fn the_text_names_the_version_and_the_features() {
        let text = text();
        let mut lines = text.lines();
        assert_eq!(lines.next(), Some(format!("ferret {VERSION}").as_str()));
        let expected = if active_features().is_empty() {
            "features: none".to_string()
        } else {
            format!("features: {}", active_features().join(", "))
        };
        assert_eq!(lines.next(), Some(expected.as_str()));
        assert_eq!(lines.next(), None);
    }
}
