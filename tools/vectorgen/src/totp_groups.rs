//! The vector group for TOTP and `otpauth://` addresses (`totp.json`).
//!
//! The expected values are written apart from the core: secrets are encoded
//! to base32 with a small table here, and the codes come from a reference
//! HOTP/TOTP below (HMAC from the `hmac` crate, truncation and decimal
//! digits done with plain integers). The official RFC 4226 and RFC 6238
//! values are in `vectors/external/` and are checked by the tests of the core.

use crate::groups::{generator, invalid_case, valid_case};
use crate::{Error, render};
use ferret_core::testing::hex_encode;
use ferret_core::testing::vector::{Case, VectorFile};
use hmac::{Hmac, KeyInit, Mac};
use serde_json::{Value, json};
use sha1::Sha1;
use sha2::{Sha256, Sha512};

const ALPHABET: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

/// RFC 4648 base32 of `data`, with the `=` fill when `pad`.
fn b32(data: &[u8], pad: bool) -> String {
    let mut out = String::new();
    let mut acc: u32 = 0;
    let mut bits = 0;
    for &b in data {
        acc = (acc << 8) | u32::from(b);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out.push(char::from(ALPHABET[((acc >> bits) & 31) as usize]));
        }
        acc &= (1 << bits) - 1;
    }
    if bits > 0 {
        out.push(char::from(ALPHABET[((acc << (5 - bits)) & 31) as usize]));
    }
    if pad {
        while !out.len().is_multiple_of(8) {
            out.push('=');
        }
    }
    out
}

/// Bytes `start, start + 1, ...` (a recognisable synthetic secret).
fn run(start: u8, len: usize) -> Vec<u8> {
    (0..len).map(|i| start.wrapping_add(i as u8)).collect()
}

#[derive(Clone, Copy)]
enum Alg {
    Sha1,
    Sha256,
    Sha512,
}

impl Alg {
    fn name(self) -> &'static str {
        match self {
            Alg::Sha1 => "SHA1",
            Alg::Sha256 => "SHA256",
            Alg::Sha512 => "SHA512",
        }
    }
}

fn mac(alg: Alg, key: &[u8], msg: &[u8]) -> Vec<u8> {
    fn go<M: Mac + KeyInit>(key: &[u8], msg: &[u8]) -> Vec<u8> {
        let mut m = <M as KeyInit>::new_from_slice(key).expect("any key length");
        m.update(msg);
        m.finalize().into_bytes().to_vec()
    }
    match alg {
        Alg::Sha1 => go::<Hmac<Sha1>>(key, msg),
        Alg::Sha256 => go::<Hmac<Sha256>>(key, msg),
        Alg::Sha512 => go::<Hmac<Sha512>>(key, msg),
    }
}

/// RFC 6238 with the RFC 4226 truncation, written out with plain integers.
fn reference_code(alg: Alg, key: &[u8], t: u64, period: u64, digits: u32) -> String {
    let digest = mac(alg, key, &(t / period).to_be_bytes());
    let offset = usize::from(digest[digest.len() - 1] & 0xf);
    let word = (u32::from(digest[offset]) & 0x7f) << 24
        | u32::from(digest[offset + 1]) << 16
        | u32::from(digest[offset + 2]) << 8
        | u32::from(digest[offset + 3]);
    let code = u64::from(word) % 10u64.pow(digits);
    format!("{code:0width$}", width = digits as usize)
}

/// What a successful parse reports.
struct Parsed<'a> {
    secret: &'a [u8],
    alg: Alg,
    digits: u32,
    period: u32,
    issuer: Option<&'a str>,
    label: &'a str,
}

impl Parsed<'_> {
    fn expect(&self) -> Value {
        json!({
            "secret": hex_encode(self.secret),
            "algorithm": self.alg.name(),
            "digits": self.digits,
            "period": self.period,
            "issuer": self.issuer,
            "label": self.label,
        })
    }
}

fn accept(cases: &mut Vec<Case>, name: &str, title: &str, uri: &str, p: &Parsed<'_>) {
    cases.push(valid_case(
        &format!("totp/{name}/1"),
        title,
        "totp.parse",
        vec![],
        json!({ "uri": uri }),
        p.expect(),
    ));
}

fn reject(cases: &mut Vec<Case>, name: &str, title: &str, uri: &str, code: &str) {
    cases.push(invalid_case(
        &format!("totp/{name}/1"),
        title,
        "totp.parse",
        vec![],
        json!({ "uri": uri }),
        code,
    ));
}

/// The algorithm, period and digits a code case expects.
#[derive(Clone, Copy)]
struct Spec {
    alg: Alg,
    period: u32,
    digits: u32,
}

fn code_case(
    cases: &mut Vec<Case>,
    name: &str,
    title: &str,
    uri: &str,
    secret: &[u8],
    spec: Spec,
    t: u64,
) {
    let Spec {
        alg,
        period,
        digits,
    } = spec;
    let left = u64::from(period) - t % u64::from(period);
    cases.push(valid_case(
        &format!("totp/{name}/1"),
        title,
        "totp.code",
        vec![],
        json!({ "uri": uri, "unix_seconds": t.to_string() }),
        json!({
            "code": reference_code(alg, secret, t, u64::from(period), digits),
            "seconds_left": left,
        }),
    ));
}

const OTHER: &str = "malformed_otpauth";

fn parse_cases(cases: &mut Vec<Case>) {
    let s10 = run(0x10, 10);
    let s20 = run(0x20, 20);
    let s32 = run(0x30, 32);
    let s64 = run(0x40, 64);
    let s128 = run(0x50, 128);
    let b10 = b32(&s10, false);
    let b20 = b32(&s20, false);
    let sha1 = Parsed {
        secret: &s10,
        alg: Alg::Sha1,
        digits: 6,
        period: 30,
        issuer: Some("Example"),
        label: "alice@example.com",
    };

    // Accepted.
    accept(
        cases,
        "accept-google-style",
        "Google Authenticator style address",
        &format!("otpauth://totp/Example:alice@example.com?secret={b10}&issuer=Example"),
        &sha1,
    );
    accept(
        cases,
        "accept-defaults",
        "only the secret: SHA1, 6 digits, 30 s, no issuer",
        &format!("otpauth://totp/bob?secret={b10}"),
        &Parsed {
            issuer: None,
            label: "bob",
            ..sha1
        },
    );
    accept(
        cases,
        "accept-all-parameters-sha256",
        "every allowed parameter, SHA256, 8 digits, 60 s",
        &format!(
            "otpauth://totp/Corp:carol?secret={}&issuer=Corp&algorithm=SHA256&digits=8&period=60",
            b32(&s32, false)
        ),
        &Parsed {
            secret: &s32,
            alg: Alg::Sha256,
            digits: 8,
            period: 60,
            issuer: Some("Corp"),
            label: "carol",
        },
    );
    accept(
        cases,
        "accept-sha512-7-digits-120s",
        "SHA512, 7 digits, 120 s (the longest period)",
        &format!(
            "otpauth://totp/dave?secret={}&algorithm=SHA512&digits=7&period=120",
            b32(&s64, false)
        ),
        &Parsed {
            secret: &s64,
            alg: Alg::Sha512,
            digits: 7,
            period: 120,
            issuer: None,
            label: "dave",
        },
    );
    accept(
        cases,
        "accept-period-1",
        "period 1 s (the shortest) and 8 digits",
        &format!("otpauth://totp/e?secret={b20}&period=1&digits=8"),
        &Parsed {
            secret: &s20,
            alg: Alg::Sha1,
            digits: 8,
            period: 1,
            issuer: None,
            label: "e",
        },
    );
    accept(
        cases,
        "accept-issuer-in-label-only",
        "issuer only as the label prefix (%3A)",
        &format!("otpauth://totp/Example%3Afrank?secret={b10}"),
        &Parsed {
            issuer: Some("Example"),
            label: "frank",
            ..sha1
        },
    );
    accept(
        cases,
        "accept-issuer-parameter-wins",
        "the issuer parameter wins over the label prefix",
        &format!("otpauth://totp/Old:gina?secret={b10}&issuer=New"),
        &Parsed {
            issuer: Some("New"),
            label: "gina",
            ..sha1
        },
    );
    accept(
        cases,
        "accept-label-space-after-colon",
        "a space after the colon of the label is dropped",
        &format!("otpauth://totp/Example:%20hal?secret={b10}"),
        &Parsed {
            issuer: Some("Example"),
            label: "hal",
            ..sha1
        },
    );
    accept(
        cases,
        "accept-label-unicode-and-plus",
        "percent-encoded UTF-8 and a plus sign in the label",
        &format!("otpauth://totp/%C3%86gir:a+b@x.no?secret={b10}"),
        &Parsed {
            issuer: Some("Ægir"),
            label: "a+b@x.no",
            ..sha1
        },
    );
    accept(
        cases,
        "accept-issuer-plus-is-space",
        "a plus in a parameter value is a space",
        &format!("otpauth://totp/ida?secret={b10}&issuer=Big+Co"),
        &Parsed {
            issuer: Some("Big Co"),
            label: "ida",
            ..sha1
        },
    );
    accept(
        cases,
        "accept-lowercase-secret",
        "lower case secret",
        &format!("otpauth://totp/jo?secret={}", b10.to_lowercase()),
        &Parsed {
            issuer: None,
            label: "jo",
            ..sha1
        },
    );
    accept(
        cases,
        "accept-spaces-in-secret",
        "groups of four letters separated by %20, + and a raw space",
        &format!(
            "otpauth://totp/kim?secret={}%20{}+{} {}",
            &b10[0..4],
            &b10[4..8],
            &b10[8..12],
            &b10[12..]
        ),
        &Parsed {
            issuer: None,
            label: "kim",
            ..sha1
        },
    );
    // 11 bytes are 18 letters; the fill is six `=`.
    let s11 = run(0x60, 11);
    for (name, pad) in [("padded", true), ("unpadded", false)] {
        accept(
            cases,
            &format!("accept-fill-{name}"),
            &format!("11 byte secret, fill {name}"),
            &format!("otpauth://totp/lee?secret={}", b32(&s11, pad)),
            &Parsed {
                secret: &s11,
                alg: Alg::Sha1,
                digits: 6,
                period: 30,
                issuer: None,
                label: "lee",
            },
        );
    }
    accept(
        cases,
        "accept-fill-percent-encoded",
        "the fill as %3D",
        &format!(
            "otpauth://totp/lee?secret={}",
            b32(&s11, true).replace('=', "%3D")
        ),
        &Parsed {
            secret: &s11,
            alg: Alg::Sha1,
            digits: 6,
            period: 30,
            issuer: None,
            label: "lee",
        },
    );
    accept(
        cases,
        "accept-secret-128-bytes",
        "a secret of exactly 128 bytes (the longest)",
        &format!("otpauth://totp/max?secret={}", b32(&s128, false)),
        &Parsed {
            secret: &s128,
            alg: Alg::Sha1,
            digits: 6,
            period: 30,
            issuer: None,
            label: "max",
        },
    );
    accept(
        cases,
        "accept-secret-1-byte",
        "a secret of one byte",
        "otpauth://totp/min?secret=ME",
        &Parsed {
            secret: b"a",
            alg: Alg::Sha1,
            digits: 6,
            period: 30,
            issuer: None,
            label: "min",
        },
    );
    // 26 letters hold 130 bits: 16 bytes and two spare bits, which are ignored.
    let s16 = run(0x70, 16);
    let mut spare = b32(&s16, false);
    assert_eq!(spare.len(), 26);
    let last = spare
        .pop()
        .and_then(|c| ALPHABET.iter().position(|a| char::from(*a) == c));
    // The two low bits of the last letter are spare bits and are 00; set one.
    spare.push(char::from(ALPHABET[last.unwrap() | 1]));
    accept(
        cases,
        "accept-spare-bits-ignored",
        "spare bits at the end of the secret are ignored",
        &format!("otpauth://totp/spare?secret={spare}"),
        &Parsed {
            secret: &s16,
            alg: Alg::Sha1,
            digits: 6,
            period: 30,
            issuer: None,
            label: "spare",
        },
    );
    accept(
        cases,
        "accept-empty-label",
        "an empty label",
        &format!("otpauth://totp/?secret={b10}"),
        &Parsed {
            issuer: None,
            label: "",
            ..sha1
        },
    );

    // Refused.
    let ok = format!("secret={b10}");
    reject(
        cases,
        "reject-hotp-type",
        "type hotp",
        &format!("otpauth://hotp/x?{ok}&counter=1"),
        OTHER,
    );
    reject(
        cases,
        "reject-type-uppercase",
        "type TOTP in capitals",
        &format!("otpauth://TOTP/x?{ok}"),
        OTHER,
    );
    reject(
        cases,
        "reject-no-type",
        "no type before the label",
        &format!("otpauth://x?{ok}"),
        OTHER,
    );
    reject(
        cases,
        "reject-scheme-http",
        "another scheme",
        &format!("https://totp/x?{ok}"),
        OTHER,
    );
    reject(
        cases,
        "reject-scheme-uppercase",
        "scheme in capitals",
        &format!("OTPAUTH://totp/x?{ok}"),
        OTHER,
    );
    reject(
        cases,
        "reject-no-query",
        "no query at all",
        "otpauth://totp/x",
        OTHER,
    );
    reject(
        cases,
        "reject-unknown-parameter",
        "an unknown parameter",
        &format!("otpauth://totp/x?{ok}&foo=bar"),
        OTHER,
    );
    reject(
        cases,
        "reject-counter-parameter",
        "counter on a totp address",
        &format!("otpauth://totp/x?{ok}&counter=1"),
        OTHER,
    );
    reject(
        cases,
        "reject-image-parameter",
        "an image parameter",
        &format!("otpauth://totp/x?{ok}&image=https%3A%2F%2Fexample.com%2Fi.png"),
        OTHER,
    );
    reject(
        cases,
        "reject-parameter-name-case",
        "parameter names are case sensitive",
        &format!("otpauth://totp/x?SECRET={b10}"),
        OTHER,
    );
    reject(
        cases,
        "reject-parameter-name-encoded-unknown",
        "an encoded name that is not on the list",
        &format!("otpauth://totp/x?{ok}&%66oo=1"),
        OTHER,
    );
    reject(
        cases,
        "reject-duplicate-secret",
        "the secret twice",
        &format!("otpauth://totp/x?{ok}&secret={}", b32(&s20, false)),
        OTHER,
    );
    reject(
        cases,
        "reject-duplicate-secret-encoded",
        "the secret twice, one name percent-encoded",
        &format!("otpauth://totp/x?{ok}&%73ecret={}", b32(&s20, false)),
        OTHER,
    );
    reject(
        cases,
        "reject-duplicate-digits",
        "digits twice",
        &format!("otpauth://totp/x?{ok}&digits=6&digits=8"),
        OTHER,
    );
    reject(
        cases,
        "reject-no-secret",
        "no secret",
        "otpauth://totp/x?issuer=Example",
        OTHER,
    );
    reject(
        cases,
        "reject-empty-secret",
        "an empty secret",
        "otpauth://totp/x?secret=",
        OTHER,
    );
    reject(
        cases,
        "reject-blank-secret",
        "a secret of spaces only",
        "otpauth://totp/x?secret=%20%20%20",
        OTHER,
    );
    reject(
        cases,
        "reject-secret-invalid-letter-1",
        "the digit 1 is not base32",
        "otpauth://totp/x?secret=JBSWY3DP1HPK3PXP",
        OTHER,
    );
    reject(
        cases,
        "reject-secret-invalid-letter-8",
        "the digit 8 is not base32",
        "otpauth://totp/x?secret=JBSWY3DP8HPK3PXP",
        OTHER,
    );
    reject(
        cases,
        "reject-secret-invalid-letter-dash",
        "a hyphen is not base32",
        "otpauth://totp/x?secret=JBSW-Y3DP-EHPK-3PXP",
        OTHER,
    );
    reject(
        cases,
        "reject-secret-one-letter",
        "one letter cannot be a byte string",
        "otpauth://totp/x?secret=M",
        OTHER,
    );
    reject(
        cases,
        "reject-secret-three-letters",
        "three letters cannot be a byte string",
        "otpauth://totp/x?secret=MFR",
        OTHER,
    );
    reject(
        cases,
        "reject-fill-wrong-count",
        "the wrong number of fill signs",
        "otpauth://totp/x?secret=MFRGG==",
        OTHER,
    );
    reject(
        cases,
        "reject-fill-inside",
        "a fill sign inside the secret",
        "otpauth://totp/x?secret=MFRG=GZDFMZTWQ2LK",
        OTHER,
    );
    reject(
        cases,
        "reject-fill-only",
        "fill signs only",
        "otpauth://totp/x?secret=========",
        OTHER,
    );
    reject(
        cases,
        "reject-secret-129-bytes",
        "a secret of 129 bytes",
        &format!("otpauth://totp/x?secret={}", b32(&run(0x50, 129), false)),
        "too_large",
    );
    reject(
        cases,
        "reject-uri-too-long",
        "an address of 2049 bytes",
        &format!("otpauth://totp/{}?{ok}", "a".repeat(2049 - 16 - ok.len())),
        "too_large",
    );
    reject(
        cases,
        "reject-label-too-long",
        "a label of 257 bytes",
        &format!("otpauth://totp/{}?{ok}", "a".repeat(257)),
        "too_large",
    );
    reject(
        cases,
        "reject-digits-5",
        "5 digits",
        &format!("otpauth://totp/x?{ok}&digits=5"),
        OTHER,
    );
    reject(
        cases,
        "reject-digits-9",
        "9 digits",
        &format!("otpauth://totp/x?{ok}&digits=9"),
        OTHER,
    );
    reject(
        cases,
        "reject-digits-leading-zero",
        "digits with a leading zero",
        &format!("otpauth://totp/x?{ok}&digits=06"),
        OTHER,
    );
    reject(
        cases,
        "reject-digits-sign",
        "digits with a plus sign",
        &format!("otpauth://totp/x?{ok}&digits=%2B6"),
        OTHER,
    );
    reject(
        cases,
        "reject-digits-text",
        "digits that are not a number",
        &format!("otpauth://totp/x?{ok}&digits=six"),
        OTHER,
    );
    reject(
        cases,
        "reject-digits-empty",
        "empty digits",
        &format!("otpauth://totp/x?{ok}&digits="),
        OTHER,
    );
    reject(
        cases,
        "reject-period-0",
        "period 0",
        &format!("otpauth://totp/x?{ok}&period=0"),
        OTHER,
    );
    reject(
        cases,
        "reject-period-121",
        "period 121",
        &format!("otpauth://totp/x?{ok}&period=121"),
        OTHER,
    );
    reject(
        cases,
        "reject-period-huge",
        "a period that overflows",
        &format!("otpauth://totp/x?{ok}&period=99999999999999999999"),
        OTHER,
    );
    reject(
        cases,
        "reject-period-negative",
        "a negative period",
        &format!("otpauth://totp/x?{ok}&period=-30"),
        OTHER,
    );
    reject(
        cases,
        "reject-algorithm-md5",
        "algorithm MD5",
        &format!("otpauth://totp/x?{ok}&algorithm=MD5"),
        OTHER,
    );
    reject(
        cases,
        "reject-algorithm-sha224",
        "algorithm SHA224",
        &format!("otpauth://totp/x?{ok}&algorithm=SHA224"),
        OTHER,
    );
    reject(
        cases,
        "reject-algorithm-lowercase",
        "algorithm in lower case",
        &format!("otpauth://totp/x?{ok}&algorithm=sha1"),
        OTHER,
    );
    reject(
        cases,
        "reject-algorithm-hyphen",
        "algorithm SHA-1",
        &format!("otpauth://totp/x?{ok}&algorithm=SHA-1"),
        OTHER,
    );
    reject(
        cases,
        "reject-fragment",
        "a fragment",
        &format!("otpauth://totp/x?{ok}#frag"),
        OTHER,
    );
    reject(
        cases,
        "reject-bad-percent",
        "a percent sign without two hex digits",
        &format!("otpauth://totp/x%zz?{ok}"),
        OTHER,
    );
    reject(
        cases,
        "reject-truncated-percent",
        "a percent sign at the end of a value",
        &format!("otpauth://totp/x?{ok}&issuer=a%4"),
        OTHER,
    );
    reject(
        cases,
        "reject-control-in-label",
        "an encoded NUL in the label",
        &format!("otpauth://totp/a%00b?{ok}"),
        OTHER,
    );
    reject(
        cases,
        "reject-control-in-issuer",
        "an encoded line feed in the issuer",
        &format!("otpauth://totp/x?{ok}&issuer=a%0Ab"),
        OTHER,
    );
    reject(
        cases,
        "reject-raw-control",
        "a raw tab in the address",
        &format!("otpauth://totp/x?{ok}&issuer=a\tb"),
        OTHER,
    );
    reject(
        cases,
        "reject-invalid-utf8",
        "an encoded byte that is not UTF-8",
        &format!("otpauth://totp/x?{ok}&issuer=%FF"),
        OTHER,
    );
    reject(
        cases,
        "reject-empty-pair",
        "an empty pair between two ampersands",
        &format!("otpauth://totp/x?{ok}&&issuer=A"),
        OTHER,
    );
    reject(
        cases,
        "reject-trailing-ampersand",
        "a trailing ampersand",
        &format!("otpauth://totp/x?{ok}&"),
        OTHER,
    );
    reject(
        cases,
        "reject-pair-without-equals",
        "a parameter without a value sign",
        &format!("otpauth://totp/x?{ok}&issuer"),
        OTHER,
    );
    reject(
        cases,
        "reject-semicolon-separator",
        "a semicolon is not a separator",
        &format!("otpauth://totp/x?{ok};issuer=A"),
        OTHER,
    );
}

fn code_cases(cases: &mut Vec<Case>) {
    let s20 = run(0x20, 20);
    let s32 = run(0x30, 32);
    let s64 = run(0x40, 64);
    // Longer than the 64 byte block of SHA-1, so HMAC hashes the key first.
    let long = run(0x80, 100);
    let sha1 = format!("otpauth://totp/c?secret={}", b32(&s20, false));
    let sha256 = format!(
        "otpauth://totp/c?secret={}&algorithm=SHA256&digits=8",
        b32(&s32, false)
    );
    let sha512 = format!(
        "otpauth://totp/c?secret={}&algorithm=SHA512&digits=7",
        b32(&s64, false)
    );

    for (name, t) in [
        ("sha1-t0", 0u64),
        ("sha1-t29", 29),
        ("sha1-t30", 30),
        ("sha1-t59", 59),
        ("sha1-t1111111109", 1_111_111_109),
        ("sha1-t-max", u64::MAX),
    ] {
        code_case(
            cases,
            name,
            &format!("SHA1, 6 digits, 30 s at {t}"),
            &sha1,
            &s20,
            Spec {
                alg: Alg::Sha1,
                period: 30,
                digits: 6,
            },
            t,
        );
    }
    for (name, t) in [("sha256-t59", 59u64), ("sha256-t1234567890", 1_234_567_890)] {
        code_case(
            cases,
            name,
            &format!("SHA256, 8 digits, 30 s at {t}"),
            &sha256,
            &s32,
            Spec {
                alg: Alg::Sha256,
                period: 30,
                digits: 8,
            },
            t,
        );
    }
    for (name, t) in [
        ("sha512-t59", 59u64),
        ("sha512-t20000000000", 20_000_000_000),
    ] {
        code_case(
            cases,
            name,
            &format!("SHA512, 7 digits, 30 s at {t}"),
            &sha512,
            &s64,
            Spec {
                alg: Alg::Sha512,
                period: 30,
                digits: 7,
            },
            t,
        );
    }
    // The second before and the second of a period change differ.
    for (name, t) in [("period60-t119", 119u64), ("period60-t120", 120)] {
        code_case(
            cases,
            name,
            &format!("SHA1, 8 digits, 60 s at {t}"),
            &format!(
                "otpauth://totp/c?secret={}&period=60&digits=8",
                b32(&s20, false)
            ),
            &s20,
            Spec {
                alg: Alg::Sha1,
                period: 60,
                digits: 8,
            },
            t,
        );
    }
    for (name, t) in [("period1-t5", 5u64), ("period1-t6", 6)] {
        code_case(
            cases,
            name,
            &format!("SHA1, 6 digits, 1 s at {t}"),
            &format!("otpauth://totp/c?secret={}&period=1", b32(&s20, false)),
            &s20,
            Spec {
                alg: Alg::Sha1,
                period: 1,
                digits: 6,
            },
            t,
        );
    }
    for (name, t) in [("period120-t119", 119u64), ("period120-t120", 120)] {
        code_case(
            cases,
            name,
            &format!("SHA1, 6 digits, 120 s at {t}"),
            &format!("otpauth://totp/c?secret={}&period=120", b32(&s20, false)),
            &s20,
            Spec {
                alg: Alg::Sha1,
                period: 120,
                digits: 6,
            },
            t,
        );
    }
    code_case(
        cases,
        "sha1-long-key",
        "SHA1 with a 100 byte key (longer than the 64 byte block)",
        &format!("otpauth://totp/c?secret={}", b32(&long, false)),
        &long,
        Spec {
            alg: Alg::Sha1,
            period: 30,
            digits: 6,
        },
        1_700_000_000,
    );
    code_case(
        cases,
        "sha512-short-digits",
        "SHA512 with the default 6 digits",
        &format!(
            "otpauth://totp/c?secret={}&algorithm=SHA512",
            b32(&s64, false)
        ),
        &s64,
        Spec {
            alg: Alg::Sha512,
            period: 30,
            digits: 6,
        },
        1_700_000_001,
    );
    // A code with leading zeros: search for a time whose SHA1 code starts
    // with 0, so that the zero padding is in the file.
    let t = (0u64..)
        .map(|k| k * 30)
        .find(|t| reference_code(Alg::Sha1, &s20, *t, 30, 6).starts_with('0'))
        .unwrap_or(0);
    code_case(
        cases,
        "sha1-leading-zero",
        "a code that starts with zero is zero padded",
        &sha1,
        &s20,
        Spec {
            alg: Alg::Sha1,
            period: 30,
            digits: 6,
        },
        t,
    );
}

pub(crate) fn totp() -> Result<Vec<u8>, Error> {
    let mut cases = Vec::new();
    parse_cases(&mut cases);
    code_cases(&mut cases);
    let file = VectorFile {
        format: ferret_core::testing::vector::FORMAT.into(),
        group: "totp".into(),
        suite: 1,
        spec: "Fase 1 § 5.2 (F-31); RFC 4226; RFC 6238".into(),
        generator: generator(),
        cases,
    };
    render(&file)
}
