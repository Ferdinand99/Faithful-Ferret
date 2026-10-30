//! The normalisation of a login name on arbitrary text. The bytes are read as
//! UTF-8, with the broken parts replaced, so that every input is a string and
//! the Unicode tables of the normaliser are reached.
//!
//! * No input panics, however long or strange.
//! * A refusal is always the one error `Malformed(LoginName)`.
//! * An accepted name is not empty, at most 254 bytes, trimmed, and free of
//!   control and invisible format characters.
//! * Normalising is idempotent: the accepted name normalises to itself.
//! * White space around the text does not change the answer.
#![no_main]

use ferret_server_auth::{AuthError, LOGIN_NAME_MAX_BYTES, Malformed, normalize_login_name};
use libfuzzer_sys::fuzz_target;

/// The input is cut off by the library above this many bytes.
const RAW_MAX_BYTES: usize = 4096;

fuzz_target!(|data: &[u8]| {
    let text = String::from_utf8_lossy(data);
    let first = normalize_login_name(&text);
    match &first {
        Err(error) => assert_eq!(*error, AuthError::Malformed(Malformed::LoginName)),
        Ok(name) => {
            let name = name.as_str();
            assert!(!name.is_empty());
            assert!(name.len() <= LOGIN_NAME_MAX_BYTES, "{} bytes", name.len());
            assert_eq!(name, name.trim());
            assert!(
                !name.chars().any(|c| c.is_control()),
                "a control character is left in {name:?}"
            );
            assert!(
                !name.chars().any(|c| matches!(
                    c,
                    '\u{200b}'..='\u{200f}'
                        | '\u{2028}'..='\u{202e}'
                        | '\u{2060}'..='\u{2064}'
                        | '\u{2066}'..='\u{206f}'
                        | '\u{feff}'
                        | '\u{fff9}'..='\u{fffb}'
                )),
                "an invisible character is left in {name:?}"
            );
            let again = normalize_login_name(name).expect("a normal name stays normal");
            assert_eq!(again.as_str(), name, "normalising is idempotent");
        }
    }

    if text.len() + 4 <= RAW_MAX_BYTES {
        let padded = normalize_login_name(&format!("  {text}\t "));
        match (&first, &padded) {
            (Ok(a), Ok(b)) => assert_eq!(a.as_str(), b.as_str(), "padding changed the name"),
            (Err(_), Err(_)) => {}
            _ => panic!("padding changed whether the name is accepted"),
        }
    }
});
