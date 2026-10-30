//! The `otpauth://` parser on arbitrary text: never a panic, and what parses
//! is inside the allow-list ranges and can make a code.
#![no_main]

use ferret_core::testing::totp::secret_bytes;
use ferret_core::{parse_otpauth, totp_code, totp_seconds_left};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(text) = core::str::from_utf8(data) else {
        return;
    };
    if let Ok(p) = parse_otpauth(text) {
        assert!((6..=8).contains(&p.digits()));
        assert!((1..=120).contains(&p.period()));
        assert!((1..=128).contains(&secret_bytes(&p).len()));
        for t in [0, 29, 30, 1_700_000_000, u64::MAX] {
            let code = totp_code(&p, t).expect("a parsed address makes a code");
            assert_eq!(code.len(), usize::from(p.digits()));
            let left = totp_seconds_left(&p, t);
            assert!((1..=p.period()).contains(&left));
        }
    }
});
