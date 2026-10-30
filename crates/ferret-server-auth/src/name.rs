//! The login name, in the one form the server uses for it.
//!
//! The same text is used to look an account up and to derive the made-up
//! credential id of a name that has no account. If those two used different
//! forms, `Alice@Example.com` could find the account while
//! `alice@example.com` got a made-up answer, and the difference would tell an
//! observer which spelling is registered. [`normalize_login_name`] is the
//! single place that decides the form, and [`NormalizedLoginName`] can only be
//! made through it.
//!
//! # Rules
//!
//! * The text is normalized with NFKC (so a full-width `Ａ` is `A`), then
//!   written in lower case, then normalized again, and trimmed of white space
//!   at both ends. These steps are repeated until the text no longer changes,
//!   so the result is stable: normalizing it again gives the same text.
//! * The result is not empty, has no control character and is at most
//!   [`LOGIN_NAME_MAX_BYTES`] bytes (the length limit of an e-mail address).
//! * Every refusal is the same error, `Malformed(LoginName)`. It depends on
//!   the bytes of the name alone: no account, no secret and no stored state
//!   takes part in the decision.

use core::fmt;

use unicode_normalization::UnicodeNormalization;

use crate::error::{AuthError, Malformed};

/// The longest login name, in bytes, after normalization.
///
/// Claudes valg: the limit of an e-mail address (RFC 5321, 254 octets).
pub const LOGIN_NAME_MAX_BYTES: usize = 254;

/// The longest input that is looked at, in bytes, before normalization. NFKC
/// can make some characters much longer, and white space is cut off, so the
/// limit is wider than the one for the result; it only keeps the work for a
/// hostile request small.
const RAW_MAX_BYTES: usize = 4096;

/// How many times the steps are repeated while looking for a stable text.
/// Real names are stable after the second round; a text that is not stable
/// after this many is refused.
const MAX_ROUNDS: usize = 4;

/// A login name in its normalized form. Made only by
/// [`normalize_login_name`].
///
/// The name is personal data. `Debug` shows nothing of it.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct NormalizedLoginName(String);

impl NormalizedLoginName {
    /// The normalized text.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for NormalizedLoginName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("NormalizedLoginName([redacted])")
    }
}

/// One round: NFKC, lower case, NFKC, trim.
fn round(text: &str) -> String {
    let folded: String = text.nfkc().collect::<String>().to_lowercase();
    folded.nfkc().collect::<String>().trim().to_owned()
}

/// Brings a login name into the one form used for lookups and for made-up
/// credential ids.
///
/// Claudes valg: NFKC and lower case, trimmed, at most 254 bytes, no control
/// character. Refused names are `Malformed(LoginName)`, all alike.
pub fn normalize_login_name(raw: &str) -> Result<NormalizedLoginName, AuthError> {
    let refused = AuthError::Malformed(Malformed::LoginName);
    if raw.len() > RAW_MAX_BYTES {
        return Err(refused);
    }
    let mut current = round(raw);
    let mut stable = false;
    for _ in 0..MAX_ROUNDS {
        let next = round(&current);
        stable = next == current;
        current = next;
        if stable {
            break;
        }
    }
    let usable = stable
        && !current.is_empty()
        && current.len() <= LOGIN_NAME_MAX_BYTES
        && !current.chars().any(char::is_control);
    if usable {
        Ok(NormalizedLoginName(current))
    } else {
        Err(refused)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    fn name(raw: &str) -> String {
        normalize_login_name(raw).unwrap().as_str().to_owned()
    }

    fn refused() -> AuthError {
        AuthError::Malformed(Malformed::LoginName)
    }

    #[test]
    fn normalize_trims_and_lowers() {
        assert_eq!(name("  Alice@Example.COM \t\n"), "alice@example.com");
        assert_eq!(name("alice@example.com"), "alice@example.com");
        // Ideographic space is white space once NFKC has made it a space.
        assert_eq!(name("\u{3000}bob@x.no\u{3000}"), "bob@x.no");
    }

    #[test]
    fn normalize_folds_full_width_and_compatibility_forms() {
        assert_eq!(name("ＡＢ@Ex.com"), "ab@ex.com");
        // The ligature fi, the circled digit, and a precomposed and a
        // decomposed e acute all land on one spelling.
        assert_eq!(name("ﬁnn@x.no"), "finn@x.no");
        assert_eq!(name("a①@x.no"), "a1@x.no");
        assert_eq!(name("caf\u{e9}@x.no"), name("cafe\u{301}@x.no"));
        // Upper case of non-ASCII letters.
        assert_eq!(name("ÅSE@X.NO"), "åse@x.no");
    }

    #[test]
    fn normalize_refuses_empty_and_blank() {
        for raw in ["", " ", "   \t\r\n ", "\u{3000}", "\u{a0}\u{2003}"] {
            assert_eq!(normalize_login_name(raw).unwrap_err(), refused(), "{raw:?}");
        }
    }

    #[test]
    fn normalize_enforces_the_length_limit_on_the_result() {
        let limit = "a".repeat(LOGIN_NAME_MAX_BYTES);
        assert_eq!(name(&limit), limit);
        let over = "a".repeat(LOGIN_NAME_MAX_BYTES + 1);
        assert_eq!(normalize_login_name(&over).unwrap_err(), refused());
        // Bytes, not characters: 127 two-byte letters fit, 128 do not.
        assert!(normalize_login_name(&"é".repeat(127)).is_ok());
        assert!(normalize_login_name(&"é".repeat(128)).is_err());
        // White space does not count against the limit...
        let padded = format!("  {limit}  ");
        assert_eq!(name(&padded), limit);
        // ...and a huge input is refused without being normalized.
        let huge = " ".repeat(RAW_MAX_BYTES + 1);
        assert_eq!(normalize_login_name(&huge).unwrap_err(), refused());
        // The length is checked after NFKC: this is 3 bytes in, 18 characters out.
        let expands = "\u{fdfa}".repeat(20);
        assert_eq!(normalize_login_name(&expands).unwrap_err(), refused());
    }

    #[test]
    fn normalize_refuses_nul_and_other_control_characters() {
        for raw in [
            "\0",
            "a\0b",
            "ab\0",
            "\0ab",
            "a\u{1}b@x.no",
            "a\u{7}b",
            "a\u{1b}[0m@x.no",
            "a\u{7f}b",
            "a\u{85}b",
            "a\tb",
            "a\nb@x.no",
            "a\rb",
        ] {
            assert_eq!(normalize_login_name(raw).unwrap_err(), refused(), "{raw:?}");
        }
    }

    #[test]
    fn every_refusal_is_the_same_error() {
        let bad = [
            String::new(),
            "   ".into(),
            "a".repeat(300),
            "x\0y".into(),
            " ".repeat(RAW_MAX_BYTES + 1),
        ];
        let errors: Vec<AuthError> = bad
            .iter()
            .map(|raw| normalize_login_name(raw).unwrap_err())
            .collect();
        assert!(errors.iter().all(|e| *e == refused()));
        assert_eq!(refused().public_code(), "malformed_login_name");
    }

    #[test]
    fn debug_shows_nothing_of_the_name() {
        let n = normalize_login_name("alice@example.com").unwrap();
        let shown = format!("{n:?}");
        assert!(!shown.contains("alice"), "{shown}");
        assert!(shown.contains("redacted"));
    }

    /// Characters that move under NFKC or lower-casing, or do both.
    fn tricky_char() -> impl Strategy<Value = char> {
        prop::sample::select(vec![
            'a', 'A', 'Z', '@', '.', ' ', '\u{3000}', '\u{a0}', 'İ', 'ı', 'Σ', 'ς', 'σ', 'ß', 'ẞ',
            'ǅ', 'Ǆ', 'ﬁ', 'ﬃ', 'Å', 'Å', 'å', 'é', '\u{301}', '\u{307}', 'Ａ', 'ａ', 'ｱ', 'ﾞ', '①',
            '\u{fdfa}', '\u{1e9e}', '\u{2126}', '\u{212a}', '\u{1f1}', '\u{1c5}', '\u{3a3}',
            '\u{0}', '\u{9}', '\u{200b}', '\u{fb03}', '\u{2160}', '\u{3392}', '😀',
        ])
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(512))]

        #[test]
        fn normalize_is_idempotent(raw in any::<String>()) {
            if let Ok(first) = normalize_login_name(&raw) {
                let second = normalize_login_name(first.as_str()).unwrap();
                prop_assert_eq!(first.as_str(), second.as_str());
            }
        }

        #[test]
        fn normalize_is_idempotent_on_awkward_text(
            chars in prop::collection::vec(tricky_char(), 0..24)
        ) {
            let raw: String = chars.into_iter().collect();
            if let Ok(first) = normalize_login_name(&raw) {
                let second = normalize_login_name(first.as_str()).unwrap();
                prop_assert_eq!(first.as_str(), second.as_str());
            }
        }

        #[test]
        fn a_result_always_meets_the_rules(
            chars in prop::collection::vec(tricky_char(), 0..24)
        ) {
            let raw: String = chars.into_iter().collect();
            if let Ok(done) = normalize_login_name(&raw) {
                let text = done.as_str();
                prop_assert!(!text.is_empty());
                prop_assert!(text.len() <= LOGIN_NAME_MAX_BYTES);
                prop_assert!(!text.chars().any(char::is_control));
                prop_assert_eq!(text, text.trim());
            }
        }
    }
}
