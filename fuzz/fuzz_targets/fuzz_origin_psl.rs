//! Origin canonicalisation and RP ID validation (including the Public Suffix
//! List lookup) on arbitrary text: never a panic, canonical form is a fixed
//! point, and an RP ID that is accepted is a dot-delimited suffix of the host
//! and not a public suffix.
#![no_main]

use ferret_core::passkey::origin::{canonical_origin, validate_rp_id};
use ferret_core::testing::passkey::is_public_suffix;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // The origin text, a NUL byte, the RP ID text.
    let (origin_bytes, rp_bytes) = match data.iter().position(|b| *b == 0) {
        Some(i) => (&data[..i], &data[i + 1..]),
        None => (data, &data[..0]),
    };
    let (Ok(origin_text), Ok(rp_text)) = (
        std::str::from_utf8(origin_bytes),
        std::str::from_utf8(rp_bytes),
    ) else {
        return;
    };
    let Ok(origin) = canonical_origin(origin_text) else {
        return;
    };
    let again = canonical_origin(origin.as_str()).expect("a canonical origin reads again");
    assert_eq!(origin, again);

    if let Ok(rp) = validate_rp_id(&origin, rp_text) {
        let dotted = format!(".{}", rp.as_str());
        assert!(origin.host() == rp.as_str() || origin.host().ends_with(&dotted));
        assert!(rp.as_str() == "localhost" || !is_public_suffix(rp.as_str()));
        // The accepted ID is itself canonical.
        assert_eq!(
            validate_rp_id(&origin, rp.as_str()).expect("fixed point"),
            rp
        );
    }
});
