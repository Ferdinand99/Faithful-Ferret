//! Property tests for TOTP and `otpauth://` parsing (plan section 9.1):
//! `totp_matches_reference` and `otpauth_allowlist`.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]

#[path = "common/totp_ref.rs"]
mod totp_ref;

use ferret_core::testing::totp::secret_bytes;
use ferret_core::{
    Error, MalformedKind, TotpAlgorithm, TotpParams, TotpSecret, parse_otpauth, totp_code,
    totp_seconds_left,
};
use proptest::prelude::*;
use totp_ref::{ref_base32, ref_totp};

const OTPAUTH: Error = Error::Malformed(MalformedKind::Otpauth);

fn config() -> ProptestConfig {
    let cases = std::env::var("PROPTEST_CASES")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(512);
    ProptestConfig {
        cases,
        ..ProptestConfig::default()
    }
}

fn algorithms() -> impl Strategy<Value = TotpAlgorithm> {
    prop_oneof![
        Just(TotpAlgorithm::Sha1),
        Just(TotpAlgorithm::Sha256),
        Just(TotpAlgorithm::Sha512),
    ]
}

/// Secrets from one byte up to the limit, also past every hash block size.
fn secrets() -> impl Strategy<Value = Vec<u8>> {
    prop::collection::vec(any::<u8>(), 1..=128)
}

/// A time: small, near the edges of a period, or anywhere.
fn times() -> impl Strategy<Value = u64> {
    prop_oneof![
        0u64..10_000,
        1_000_000_000u64..4_000_000_000,
        any::<u64>(),
        Just(u64::MAX),
    ]
}

/// Names for `algorithm=`.
fn name(alg: TotpAlgorithm) -> &'static str {
    alg.name()
}

proptest! {
    #![proptest_config(config())]

    // The code from the core equals an independent computation (HMAC built
    // by hand from the plain hash) for any secret, hash, digits, period and
    // time, and the time left is consistent with the period.
    #[test]
    fn totp_matches_reference(
        secret in secrets(),
        alg in algorithms(),
        digits in 6u8..=8,
        period in 1u32..=120,
        t in times(),
    ) {
        let p = TotpParams::new(
            TotpSecret::from_bytes(&secret).unwrap(),
            alg,
            digits,
            period,
            None,
            String::new(),
        )
        .unwrap();
        let code = totp_code(&p, t).unwrap();
        prop_assert_eq!(code.len(), usize::from(digits));
        prop_assert!(code.bytes().all(|b| b.is_ascii_digit()));
        prop_assert_eq!(
            code.as_str(),
            ref_totp(alg, &secret, t, u64::from(period), u32::from(digits))
        );
        let left = totp_seconds_left(&p, t);
        prop_assert!((1..=period).contains(&left));
        prop_assert_eq!((u128::from(t) + u128::from(left)) % u128::from(period), 0);
        // The code is the same for every second of the period.
        let start = t - t % u64::from(period);
        let again = totp_code(&p, start).unwrap();
        prop_assert_eq!(again.as_str(), code.as_str());
    }

    // Parsing an address built from the allowed parts gives those parts back.
    #[test]
    fn otpauth_roundtrip_of_allowed_parts(
        secret in secrets(),
        alg in algorithms(),
        digits in 6u8..=8,
        period in 1u32..=120,
        pad in any::<bool>(),
        lower in any::<bool>(),
        issuer in "[A-Za-z0-9]{1,12}",
        account in "[a-z0-9.]{1,12}",
    ) {
        let mut text = ref_base32(&secret, pad);
        if lower {
            text = text.to_lowercase();
        }
        let uri = format!(
            "otpauth://totp/{issuer}:{account}?secret={text}&issuer={issuer}&algorithm={}&digits={digits}&period={period}",
            name(alg)
        );
        let p = parse_otpauth(&uri).unwrap();
        prop_assert_eq!(secret_bytes(&p), secret);
        prop_assert_eq!(p.algorithm(), alg);
        prop_assert_eq!(p.digits(), digits);
        prop_assert_eq!(p.period(), period);
        prop_assert_eq!(p.issuer(), Some(issuer.as_str()));
        prop_assert_eq!(p.label(), account.as_str());
    }

    // Anything outside the allow-list is refused: an unknown parameter, a
    // type other than totp, digits and periods out of range.
    #[test]
    fn otpauth_allowlist(
        secret in secrets(),
        extra in "[A-Za-z0-9_]{1,10}",
        kind in "[a-z]{0,6}",
        digits in prop_oneof![0u32..6, 9u32..1000],
        period in prop_oneof![Just(0u32), 121u32..100_000],
        alg in "[A-Za-z0-9-]{1,8}",
    ) {
        let text = ref_base32(&secret, false);
        let allowed = ["secret", "issuer", "algorithm", "digits", "period"];
        let good = format!("otpauth://totp/x?secret={text}");
        prop_assert!(parse_otpauth(&good).is_ok());

        // An unknown parameter name.
        if !allowed.contains(&extra.as_str()) {
            let uri = format!("{good}&{extra}=1");
            prop_assert_eq!(parse_otpauth(&uri).err(), Some(OTPAUTH));
        }
        // A type other than totp.
        if kind != "totp" {
            let uri = format!("otpauth://{kind}/x?secret={text}");
            prop_assert_eq!(parse_otpauth(&uri).err(), Some(OTPAUTH));
        }
        // Digits out of range, period out of range.
        let uri = format!("{good}&digits={digits}");
        prop_assert_eq!(parse_otpauth(&uri).err(), Some(OTPAUTH));
        let uri = format!("{good}&period={period}");
        prop_assert_eq!(parse_otpauth(&uri).err(), Some(OTPAUTH));
        // An algorithm name that is not one of the three.
        if !["SHA1", "SHA256", "SHA512"].contains(&alg.as_str()) {
            let uri = format!("{good}&algorithm={alg}");
            prop_assert_eq!(parse_otpauth(&uri).err(), Some(OTPAUTH));
        }
        // Each allowed parameter given twice.
        for dup in ["issuer=a", "algorithm=SHA1", "digits=6", "period=30"] {
            let uri = format!("{good}&{dup}&{dup}");
            prop_assert_eq!(parse_otpauth(&uri).err(), Some(OTPAUTH));
        }
    }

    // The parser is total: any text gives Ok or an error, and an Ok result
    // has values inside the allowed ranges and can make a code.
    #[test]
    fn otpauth_parser_total(uri in ".{0,300}", tail in "[ -~]{0,100}") {
        for candidate in [uri.clone(), format!("otpauth://totp/x?secret=MFRGG&{tail}")] {
            if let Ok(p) = parse_otpauth(&candidate) {
                prop_assert!((6..=8).contains(&p.digits()));
                prop_assert!((1..=120).contains(&p.period()));
                prop_assert!((1..=128).contains(&secret_bytes(&p).len()));
                prop_assert_eq!(totp_code(&p, 0).unwrap().len(), usize::from(p.digits()));
            }
        }
    }
}
