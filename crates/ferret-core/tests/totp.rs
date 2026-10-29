//! TOTP and `otpauth://` parsing: the RFC 4226 and RFC 6238 test values, the
//! reading rules, the generated vectors in `vectors/internal/totp.json`, and
//! the guards on the secret type and on logging.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]

#[path = "common/totp_ref.rs"]
mod totp_ref;

use ferret_core::testing::totp::{hotp, hotp_digest, secret_bytes};
use ferret_core::testing::vector::{self, Case, Outcome};
use ferret_core::testing::{ReplayRng, hex_decode, hex_encode};
use ferret_core::{
    Error, MalformedKind, TotpAlgorithm, TotpParams, TotpSecret, parse_otpauth, totp_code,
    totp_seconds_left,
};
use serde_json::{Value, json};
use static_assertions::{assert_impl_all, assert_not_impl_any};
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use totp_ref::{ref_base32, ref_hotp, ref_totp};
use zeroize::{Zeroize, ZeroizeOnDrop};

const OTPAUTH: Error = Error::Malformed(MalformedKind::Otpauth);

fn vectors_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../vectors")
}

fn load_json(relative: &str) -> Value {
    let path = vectors_dir().join(relative);
    serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
}

fn algorithm(name: &str) -> TotpAlgorithm {
    match name {
        "SHA1" => TotpAlgorithm::Sha1,
        "SHA256" => TotpAlgorithm::Sha256,
        "SHA512" => TotpAlgorithm::Sha512,
        other => panic!("unknown algorithm {other}"),
    }
}

fn params(secret: &[u8], alg: TotpAlgorithm, digits: u8, period: u32) -> TotpParams {
    TotpParams::new(
        TotpSecret::from_bytes(secret).unwrap(),
        alg,
        digits,
        period,
        None,
        String::new(),
    )
    .unwrap()
}

fn code(p: &TotpParams, t: u64) -> String {
    totp_code(p, t).unwrap().to_string()
}

// ------------------------------------------------------- RFC test values

#[test]
fn totp_rfc6238_appendix_b() {
    let file = load_json("external/rfc6238-totp.json");
    let cases = file["cases"].as_array().unwrap();
    assert_eq!(cases.len(), 18, "SHA-1, SHA-256 and SHA-512 at six times");
    let mut seeds = BTreeSet::new();
    for case in cases {
        let secret = hex_decode(case["secret"].as_str().unwrap()).unwrap();
        let alg = algorithm(case["algorithm"].as_str().unwrap());
        let digits = u8::try_from(case["digits"].as_u64().unwrap()).unwrap();
        let period = u32::try_from(case["period"].as_u64().unwrap()).unwrap();
        let t = case["time"].as_u64().unwrap();
        let p = params(&secret, alg, digits, period);
        assert_eq!(
            code(&p, t),
            case["totp"].as_str().unwrap(),
            "{}",
            case["id"]
        );
        // The hand-built reference agrees with the RFC too.
        assert_eq!(
            ref_totp(alg, &secret, t, u64::from(period), u32::from(digits)),
            case["totp"].as_str().unwrap(),
            "{}",
            case["id"]
        );
        seeds.insert((case["algorithm"].as_str().unwrap().to_owned(), secret.len()));
    }
    // The seed of each algorithm has the length the RFC gives it.
    assert_eq!(
        seeds,
        BTreeSet::from([
            ("SHA1".to_owned(), 20),
            ("SHA256".to_owned(), 32),
            ("SHA512".to_owned(), 64)
        ])
    );
}

#[test]
fn hotp_rfc4226_appendix_d() {
    let file = load_json("external/rfc4226-hotp.json");
    let cases = file["cases"].as_array().unwrap();
    assert_eq!(cases.len(), 10);
    for case in cases {
        let secret = hex_decode(case["secret"].as_str().unwrap()).unwrap();
        let counter = case["counter"].as_u64().unwrap();
        // The HMAC digest, then the truncated number.
        let digest = hotp_digest(TotpAlgorithm::Sha1, &secret, counter).unwrap();
        assert_eq!(hex_encode(&digest), case["hmac"].as_str().unwrap());
        let value = hotp(TotpAlgorithm::Sha1, &secret, counter, 6).unwrap();
        assert_eq!(value, case["hotp"].as_str().unwrap(), "{}", case["id"]);
        assert_eq!(ref_hotp(TotpAlgorithm::Sha1, &secret, counter, 6), value);
        // With a period of one second, the time is the counter.
        let p = params(&secret, TotpAlgorithm::Sha1, 6, 1);
        assert_eq!(code(&p, counter), value);
    }
}

// --------------------------------------------------- digits and periods

const RFC_SHA1_SEED: &[u8] = b"12345678901234567890";

#[test]
fn totp_digits_6_7_8_and_periods() {
    // At t = 59 the SHA-1 value of the RFC is 94287082 (eight digits); the
    // shorter codes are its last digits.
    for (digits, want) in [(6u8, "287082"), (7, "4287082"), (8, "94287082")] {
        let p = params(RFC_SHA1_SEED, TotpAlgorithm::Sha1, digits, 30);
        assert_eq!(code(&p, 59), want, "{digits} digits");
        assert_eq!(p.digits(), digits);
    }
    // A code with leading zeros keeps them (RFC 6238, t = 1111111109).
    let p = params(RFC_SHA1_SEED, TotpAlgorithm::Sha1, 8, 30);
    assert_eq!(code(&p, 1_111_111_109), "07081804");
    let p = params(RFC_SHA1_SEED, TotpAlgorithm::Sha1, 6, 30);
    assert_eq!(code(&p, 1_111_111_109), "081804");

    // Periods: the counter is t / period, so t = 59 is counter 1 with 30 s,
    // counter 0 with 60 s and counter 59 with 1 s.
    for (period, counter) in [(30u32, 1u64), (60, 0), (120, 0), (1, 59), (7, 8)] {
        let p = params(RFC_SHA1_SEED, TotpAlgorithm::Sha1, 6, period);
        let want = hotp(TotpAlgorithm::Sha1, RFC_SHA1_SEED, counter, 6).unwrap();
        assert_eq!(code(&p, 59), want, "period {period}");
        assert_eq!(p.period(), period);
    }

    // The range of digits and period is closed.
    for (digits, period) in [
        (5u8, 30u32),
        (9, 30),
        (0, 30),
        (6, 0),
        (6, 121),
        (6, u32::MAX),
    ] {
        let secret = TotpSecret::from_bytes(RFC_SHA1_SEED).unwrap();
        let made = TotpParams::new(
            secret,
            TotpAlgorithm::Sha1,
            digits,
            period,
            None,
            String::new(),
        );
        assert_eq!(made.err(), Some(OTPAUTH), "digits {digits} period {period}");
    }
}

#[test]
fn totp_seconds_left_counts_down_to_the_change() {
    let p = params(RFC_SHA1_SEED, TotpAlgorithm::Sha1, 6, 30);
    assert_eq!(totp_seconds_left(&p, 0), 30);
    assert_eq!(totp_seconds_left(&p, 1), 29);
    assert_eq!(totp_seconds_left(&p, 29), 1);
    assert_eq!(totp_seconds_left(&p, 30), 30);
    assert_eq!(totp_seconds_left(&p, 59), 1);
    let one = params(RFC_SHA1_SEED, TotpAlgorithm::Sha1, 6, 1);
    assert_eq!(totp_seconds_left(&one, 12345), 1);
    let long = params(RFC_SHA1_SEED, TotpAlgorithm::Sha1, 6, 120);
    assert_eq!(totp_seconds_left(&long, 119), 1);
    assert_eq!(totp_seconds_left(&long, 120), 120);
    // The largest time does not overflow.
    let left = totp_seconds_left(&p, u64::MAX);
    assert!((1..=30).contains(&left));
    assert_eq!(code(&p, u64::MAX).len(), 6);
}

#[test]
fn totp_boundary_second() {
    // t = k * period - 1 is the last second of a code; t = k * period is the
    // first second of the next one.
    for alg in [
        TotpAlgorithm::Sha1,
        TotpAlgorithm::Sha256,
        TotpAlgorithm::Sha512,
    ] {
        for period in [1u32, 30, 60, 120] {
            let p = params(b"boundary-secret-0123456789", alg, 8, period);
            for k in [1u64, 2, 37, 1_000_003] {
                let edge = k * u64::from(period);
                let before = code(&p, edge - 1);
                let at = code(&p, edge);
                assert_ne!(before, at, "{alg:?} period {period} k {k}");
                assert_eq!(code(&p, edge - u64::from(period)), before);
                assert_eq!(code(&p, edge + u64::from(period) - 1), at);
                assert_eq!(totp_seconds_left(&p, edge - 1), 1);
                assert_eq!(totp_seconds_left(&p, edge), period);
            }
        }
    }
}

// ------------------------------------------------------------- otpauth

fn parsed(uri: &str) -> TotpParams {
    parse_otpauth(uri).unwrap()
}

#[test]
fn otpauth_accepts_google_authenticator_style_uri() {
    let p =
        parsed("otpauth://totp/Example:alice@google.com?secret=JBSWY3DPEHPK3PXP&issuer=Example");
    assert_eq!(secret_bytes(&p), b"Hello!\xde\xad\xbe\xef");
    assert_eq!(p.algorithm(), TotpAlgorithm::Sha1);
    assert_eq!((p.digits(), p.period()), (6, 30));
    assert_eq!(p.issuer(), Some("Example"));
    assert_eq!(p.label(), "alice@google.com");
    assert_eq!(code(&p, 59).len(), 6);

    // Every allowed parameter, in another order.
    let p = parsed(
        "otpauth://totp/ACME%20Co:john.doe@email.com?period=45&digits=7&algorithm=SHA512\
         &issuer=ACME%20Co&secret=HXDMVJECJJWSRB3HWIZR4IFUGFTMXBOZ",
    );
    assert_eq!(p.algorithm(), TotpAlgorithm::Sha512);
    assert_eq!((p.digits(), p.period()), (7, 45));
    assert_eq!(p.issuer(), Some("ACME Co"));
    assert_eq!(p.label(), "john.doe@email.com");
    assert_eq!(secret_bytes(&p).len(), 20);
}

#[test]
fn otpauth_rejects_unknown_param_hotp_type_digits_9_period_0_oversize_secret() {
    let ok = "secret=JBSWY3DPEHPK3PXP";
    let too_big = format!("otpauth://totp/x?secret={}", ref_base32(&[7u8; 129], false));
    let limit = format!("otpauth://totp/x?secret={}", ref_base32(&[7u8; 128], false));
    let huge = format!("otpauth://totp/{}?{ok}", "a".repeat(2100));
    assert!(parse_otpauth(&limit).is_ok(), "128 bytes is the limit");

    let refused: Vec<(String, Error)> = vec![
        (format!("otpauth://totp/x?{ok}&foo=bar"), OTPAUTH),
        (format!("otpauth://totp/x?{ok}&counter=0"), OTPAUTH),
        (format!("otpauth://totp/x?{ok}&image=a"), OTPAUTH),
        (format!("otpauth://hotp/x?{ok}&counter=0"), OTPAUTH),
        (format!("otpauth://totp/x?{ok}&digits=9"), OTPAUTH),
        (format!("otpauth://totp/x?{ok}&digits=5"), OTPAUTH),
        (format!("otpauth://totp/x?{ok}&period=0"), OTPAUTH),
        (format!("otpauth://totp/x?{ok}&period=121"), OTPAUTH),
        (format!("otpauth://totp/x?{ok}&algorithm=MD5"), OTPAUTH),
        (format!("otpauth://totp/x?{ok}&{ok}"), OTPAUTH),
        ("otpauth://totp/x?issuer=Example".to_owned(), OTPAUTH),
        (too_big, Error::TooLarge),
        (huge, Error::TooLarge),
        (format!("http://totp/x?{ok}"), OTPAUTH),
    ];
    for (uri, want) in refused {
        let got = parse_otpauth(&uri).err();
        assert_eq!(got, Some(want), "{}", &uri[..uri.len().min(80)]);
    }
}

#[test]
fn otpauth_base32_tolerant_padding_case_whitespace() {
    // 1 to 24 bytes cover every length of fill and every spare-bit count.
    for len in 1..=24usize {
        let secret: Vec<u8> = (0..len).map(|i| (i * 37 + 11) as u8).collect();
        let plain = ref_base32(&secret, false);
        let padded = ref_base32(&secret, true);
        let variants: Vec<String> = vec![
            plain.clone(),
            padded.clone(),
            plain.to_lowercase(),
            padded.to_lowercase(),
            // Spaces anywhere.
            plain
                .chars()
                .enumerate()
                .map(|(i, c)| {
                    if i % 3 == 0 {
                        format!(" {c}")
                    } else {
                        c.to_string()
                    }
                })
                .collect::<String>(),
            // An encoded line feed at the end.
            format!("{padded}%0A"),
            padded.replace('=', "%3D"),
            // `+` and `%20` are spaces in a value.
            plain.chars().flat_map(|c| [c, '+']).collect::<String>(),
            plain
                .chars()
                .flat_map(|c| [c, '%', '2', '0'])
                .collect::<String>(),
        ];
        for text in variants {
            let uri = format!("otpauth://totp/x?secret={text}");
            let p = parse_otpauth(&uri).unwrap_or_else(|e| panic!("{e}: {uri}"));
            assert_eq!(secret_bytes(&p), secret, "{uri}");
        }
        // The same through the secret type, with raw spaces and line breaks.
        let spaced = format!("\t{}\r\n", plain.to_lowercase());
        for text in [&spaced, &padded] {
            let secret_type = TotpSecret::from_base32(text).unwrap();
            let made =
                TotpParams::new(secret_type, TotpAlgorithm::Sha1, 6, 30, None, String::new())
                    .unwrap();
            assert_eq!(secret_bytes(&made), secret);
        }
    }
    // The fill must be complete or absent.
    for bad in [
        "MFRGG=",
        "MFRGG==",
        "MFRGG====",
        "MFRGG=====",
        "MFRGGZDFMZTWQ2L==",
        "ME=",
        "ME=======",
    ] {
        let uri = format!("otpauth://totp/x?secret={bad}");
        assert_eq!(parse_otpauth(&uri).err(), Some(OTPAUTH), "{bad}");
    }
    // Letters outside the alphabet, also the ones that look like it.
    for bad in [
        "JBSWY3DP1HPK3PXP",
        "JBSWY3DP0HPK3PXP",
        "JBSWY3DP8HPK3PXP",
        "JBSWY3DP9HPK3PXP",
        "JBSW-Y3DP",
        "JBSWY3D\u{00d8}",
        "MFRG=GZDFMZTWQ2LK",
    ] {
        let uri = format!("otpauth://totp/x?secret={bad}");
        assert_eq!(parse_otpauth(&uri).err(), Some(OTPAUTH), "{bad}");
    }
    // A length that no byte string has (1, 3 or 6 letters over a block of eight).
    for bad in [
        "M",
        "MFR",
        "MFRGGZ",
        "MFRGGZDFM",
        "MFRGGZDFMZT",
        "MFRGGZDFMZTWQ2",
    ] {
        let uri = format!("otpauth://totp/x?secret={bad}");
        assert_eq!(parse_otpauth(&uri).err(), Some(OTPAUTH), "{bad}");
    }
    // Spare bits are ignored: the last letter of 26 only needs its top bits.
    let a = parsed("otpauth://totp/x?secret=MFRGGZDFMZTWQ2LKNNWG23TPOA");
    let b = parsed("otpauth://totp/x?secret=MFRGGZDFMZTWQ2LKNNWG23TPOB");
    assert_eq!(secret_bytes(&a), secret_bytes(&b));
    assert_eq!(secret_bytes(&a).len(), 16);
}

#[test]
fn otpauth_allowlist() {
    let ok = "secret=JBSWY3DPEHPK3PXP";
    // Every allowed parameter alone and together.
    for query in [
        ok.to_owned(),
        format!("{ok}&issuer=I"),
        format!("{ok}&algorithm=SHA256"),
        format!("{ok}&digits=8"),
        format!("{ok}&period=120"),
        format!("{ok}&issuer=I&algorithm=SHA512&digits=7&period=1"),
    ] {
        assert!(
            parse_otpauth(&format!("otpauth://totp/x?{query}")).is_ok(),
            "{query}"
        );
    }
    // Each repeated.
    for (name, value) in [
        ("secret", "MFRGG"),
        ("issuer", "A"),
        ("algorithm", "SHA1"),
        ("digits", "6"),
        ("period", "30"),
    ] {
        let uri = format!("otpauth://totp/x?{ok}&{name}={value}&{name}={value}");
        assert_eq!(parse_otpauth(&uri).err(), Some(OTPAUTH), "twice: {name}");
    }
    // Names that are not on the list, also with an allowed name as a prefix,
    // in another case or encoded.
    for name in [
        "counter",
        "image",
        "lock",
        "Secret",
        "SECRET",
        "secrets",
        "secret ",
        "issuer2",
        "algo",
        "digit",
        "periods",
        "",
        "%73ecret2",
        "s",
        "type",
        "label",
    ] {
        let uri = format!("otpauth://totp/x?{ok}&{name}=1");
        assert_eq!(parse_otpauth(&uri).err(), Some(OTPAUTH), "name {name:?}");
    }
    // Types other than totp.
    for kind in ["hotp", "TOTP", "Totp", "totp2", "tot", "", "steam", "motp"] {
        let uri = format!("otpauth://{kind}/x?{ok}");
        assert_eq!(parse_otpauth(&uri).err(), Some(OTPAUTH), "type {kind:?}");
    }
    // Values.
    for (name, value) in [
        ("digits", "5"),
        ("digits", "9"),
        ("digits", "06"),
        ("digits", " 6"),
        ("digits", "6 "),
        ("digits", "+6"),
        ("digits", "6.0"),
        ("digits", ""),
        ("digits", "0x6"),
        ("period", "0"),
        ("period", "121"),
        ("period", "030"),
        ("period", "-1"),
        ("period", "1e1"),
        ("period", "4294967326"),
        ("period", ""),
        ("algorithm", "sha1"),
        ("algorithm", "Sha1"),
        ("algorithm", "SHA-1"),
        ("algorithm", "MD5"),
        ("algorithm", "SHA224"),
        ("algorithm", "SHA384"),
        ("algorithm", "SHA3-256"),
        ("algorithm", "SHA1 "),
        ("algorithm", ""),
    ] {
        let uri = format!("otpauth://totp/x?{ok}&{name}={value}");
        assert_eq!(parse_otpauth(&uri).err(), Some(OTPAUTH), "{name}={value:?}");
    }
}

#[test]
fn otpauth_fixed_structure() {
    let ok = "secret=JBSWY3DPEHPK3PXP";
    for uri in [
        format!("otpauth://totp/x?{ok}#frag"),
        format!("otpauth://totp?{ok}"),
        "otpauth://totp/x".to_owned(),
        "otpauth://totp/x?".to_owned(),
        format!("otpauth:totp/x?{ok}"),
        format!("otpauth://totp/x?{ok}&"),
        format!("otpauth://totp/x?{ok}&&digits=6"),
        format!("otpauth://totp/x?{ok}&digits"),
        format!("otpauth://totp/x?{ok};digits=6"),
        format!("otpauth://totp/x%zz?{ok}"),
        format!("otpauth://totp/x?{ok}&issuer=%4"),
        format!("otpauth://totp/x?{ok}&issuer=%FF"),
        format!("otpauth://totp/a%00b?{ok}"),
        format!("otpauth://totp/a\tb?{ok}"),
        format!("otpauth://totp/x?{ok}&issuer=a%0Ab"),
        format!(" otpauth://totp/x?{ok}"),
        String::new(),
    ] {
        assert_eq!(parse_otpauth(&uri).err(), Some(OTPAUTH), "{uri:?}");
    }
    // Sizes: the address, the issuer and the label.
    let max_label = "a".repeat(256);
    assert!(parse_otpauth(&format!("otpauth://totp/{max_label}?{ok}")).is_ok());
    for uri in [
        format!("otpauth://totp/{}?{ok}", "a".repeat(257)),
        format!("otpauth://totp/x?{ok}&issuer={}", "a".repeat(257)),
        format!("otpauth://totp/x?{ok}&issuer={}", "a".repeat(2100)),
    ] {
        assert_eq!(parse_otpauth(&uri).err(), Some(Error::TooLarge));
    }
    // Issuer and label rules.
    let p = parsed(&format!("otpauth://totp/Old:%20%20gina?{ok}&issuer="));
    assert_eq!((p.issuer(), p.label()), (Some("Old"), "gina"));
    let p = parsed(&format!("otpauth://totp/a:b:c?{ok}"));
    assert_eq!((p.issuer(), p.label()), (Some("a"), "b:c"));
    let p = parsed(&format!("otpauth://totp/:x?{ok}"));
    assert_eq!((p.issuer(), p.label()), (None, "x"));
}

// -------------------------------------------- secret type and logging

assert_impl_all!(TotpSecret: Zeroize, ZeroizeOnDrop);
assert_not_impl_any!(
    TotpSecret: Clone, Copy, core::fmt::Debug, core::fmt::Display, PartialEq, Eq,
    core::hash::Hash, serde::Serialize
);
assert_not_impl_any!(
    TotpParams: Clone, Copy, core::fmt::Display, PartialEq, Eq, core::hash::Hash,
    serde::Serialize
);

/// Reads `len` bytes at `ptr`.
///
/// # Safety
/// `ptr` must point to `len` initialized bytes of a live allocation.
unsafe fn read(ptr: *const u8, len: usize) -> Vec<u8> {
    // SAFETY: the caller guarantees the range; volatile so that the read
    // cannot be removed or reordered against the wipe.
    (0..len)
        .map(|i| unsafe { ptr.add(i).read_volatile() })
        .collect()
}

#[test]
fn totp_secret_zeroized_and_not_debug() {
    // The wipe itself: the whole buffer is zero afterwards, and it was
    // reserved once at the full size, so the secret was never copied to a
    // bigger buffer.
    for mut secret in [
        TotpSecret::from_bytes(&[0xa5; 20]).unwrap(),
        TotpSecret::from_base32("JBSWY3DPEHPK3PXP").unwrap(),
    ] {
        let (ptr, cap) = secret.test_buffer();
        assert_eq!(cap, 128, "reserved once");
        // SAFETY: the buffer is alive and its first bytes are initialized.
        let before = unsafe { read(ptr, 10) };
        assert!(before.iter().any(|b| *b != 0));
        secret.zeroize();
        // SAFETY: `zeroize` keeps the allocation and writes zeros over all
        // of its capacity; `secret` is still alive.
        let after = unsafe { read(ptr, cap) };
        assert!(after.iter().all(|b| *b == 0), "TotpSecret not wiped");
    }
    // The Debug text of the settings has no content in it.
    let p = parsed("otpauth://totp/Example:alice?secret=JBSWY3DPEHPK3PXP&issuer=Example");
    assert_eq!(format!("{p:?}"), "TotpParams { .. }");
    // The code is a `Zeroizing<String>`: wiped when it goes.
    let c = totp_code(&p, 59).unwrap();
    let _: &zeroize::Zeroizing<String> = &c;
}

#[test]
fn secret_length_limits() {
    assert_eq!(TotpSecret::from_bytes(&[]).err(), Some(OTPAUTH));
    assert!(TotpSecret::from_bytes(&[1]).is_ok());
    assert!(TotpSecret::from_bytes(&[1; 128]).is_ok());
    assert_eq!(
        TotpSecret::from_bytes(&[1; 129]).err(),
        Some(Error::TooLarge)
    );
    assert_eq!(TotpSecret::from_base32("").err(), Some(OTPAUTH));
    assert_eq!(TotpSecret::from_base32("  \n").err(), Some(OTPAUTH));
}

#[test]
fn totp_code_not_logged() {
    // Nothing in the module prints, logs or formats text: a code or secret
    // can only leave through the return value.
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("src/totp.rs");
    let source = std::fs::read_to_string(path).unwrap();
    let code: String = source
        .lines()
        .filter(|l| !l.trim_start().starts_with("//"))
        .collect::<Vec<_>>()
        .join("\n");
    for banned in [
        "println!",
        "eprintln!",
        "print!",
        "eprint!",
        "dbg!",
        "log::",
        "tracing",
        "trace!(",
        "debug!(",
        "info!(",
        "warn!(",
        "error!(",
        "format!",
        "format_args!",
        "write!",
        "writeln!",
        "to_string()",
        "console",
        "std::io",
    ] {
        assert!(!code.contains(banned), "totp.rs contains {banned}");
    }
    // The only Debug impl is the empty one.
    assert_eq!(code.matches("fmt::Debug for").count(), 1);
    assert!(code.contains("finish_non_exhaustive"));
}

// ---------------------------------------------------------- vector file

fn run_vector(case: &Case) -> Result<Outcome, Error> {
    let uri = case.input["uri"].as_str().unwrap();
    let p = parse_otpauth(uri)?;
    let output = match case.op.as_str() {
        "totp.parse" => json!({
            "secret": hex_encode(&secret_bytes(&p)),
            "algorithm": p.algorithm().name(),
            "digits": p.digits(),
            "period": p.period(),
            "issuer": p.issuer(),
            "label": p.label(),
        }),
        "totp.code" => {
            let t: u64 = case.input["unix_seconds"]
                .as_str()
                .unwrap()
                .parse()
                .unwrap();
            let code = totp_code(&p, t)?;
            // The independent reference must agree with every recorded code.
            assert_eq!(
                *code,
                ref_totp(
                    p.algorithm(),
                    &secret_bytes(&p),
                    t,
                    u64::from(p.period()),
                    u32::from(p.digits())
                ),
                "{}",
                case.id
            );
            json!({ "code": code.to_string(), "seconds_left": totp_seconds_left(&p, t) })
        }
        other => panic!("unknown op {other}"),
    };
    Ok(Outcome {
        output,
        intermediate: None,
    })
}

#[test]
fn totp_vectors_from_file() {
    let file = vector::load(&vectors_dir().join("internal/totp.json")).unwrap();
    assert!(
        file.cases.len() >= 26,
        "the plan asks for at least 26 cases"
    );
    let report = vector::run_all(&file, |case: &Case, _rng: &mut ReplayRng| run_vector(case));
    assert!(report.failures.is_empty(), "{:?}", report.failures);
    assert_eq!(report.passed, file.cases.len());

    let ops: BTreeSet<&str> = file.cases.iter().map(|c| c.op.as_str()).collect();
    assert_eq!(ops, BTreeSet::from(["totp.code", "totp.parse"]));
    let errors: BTreeSet<&str> = file
        .cases
        .iter()
        .filter_map(|c| c.expect_error.as_deref())
        .collect();
    assert_eq!(errors, BTreeSet::from(["malformed_otpauth", "too_large"]));
    let algs: BTreeSet<&str> = file
        .cases
        .iter()
        .filter_map(|c| c.expect.as_ref()?["algorithm"].as_str())
        .collect();
    assert_eq!(algs, BTreeSet::from(["SHA1", "SHA256", "SHA512"]));
    let digits: BTreeSet<u64> = file
        .cases
        .iter()
        .filter_map(|c| c.expect.as_ref()?["digits"].as_u64())
        .collect();
    assert_eq!(digits, BTreeSet::from([6, 7, 8]));
}
