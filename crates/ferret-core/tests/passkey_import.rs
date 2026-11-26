//! Import of a passkey from another password manager (Fase 1 § 9.1, § 9.6):
//! `passkey_import`, and `vectors/internal/passkey_import.json`.
//!
//! The data files in `tests/data/import/` are exports of throwaway test keys
//! in the formats of Bitwarden (unencrypted JSON, PKCS#8) and AliasVault
//! (`manifest.json` of an `.avux` file, JWK), and two PKCS#8 keys that a
//! browser's own WebCrypto wrote.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]

mod common;

use common::*;
use ferret_core::testing::passkey::{item_of, private_scalar};
use ferret_core::testing::prim::hmac_sha256;
use ferret_core::testing::vector::Outcome;
use ferret_core::{
    CallerContext, Error, GetRequest, ImportKey, ImportNotes, ImportPrf, ImportedPasskeyInput,
    MalformedKind, PasskeyRecord, UserVerification, UvOutcome, canonical_origin, canonical_rp_id,
    passkey_get, passkey_import,
};
use p256::ecdsa::signature::Verifier;
use p256::ecdsa::{Signature, SigningKey, VerifyingKey};
use p256::pkcs8::{DecodePublicKey, EncodePrivateKey, EncodePublicKey};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use static_assertions::assert_not_impl_any;

assert_not_impl_any!(ImportedPasskeyInput<'static>: Clone, PartialEq, core::fmt::Display);
assert_not_impl_any!(ImportKey<'static>: Clone, PartialEq, core::fmt::Display);
assert_not_impl_any!(ImportPrf<'static>: Clone, PartialEq, core::fmt::Display);

const BITWARDEN: &str = include_str!("data/import/bitwarden.json");
const ALIASVAULT: &str = include_str!("data/import/aliasvault-manifest.json");
const EXPECTED: &str = include_str!("data/import/expected.json");
const FIREFOX: &str = include_str!("data/import/firefox-pkcs8.txt");

// ------------------------------------------------------------- helpers

fn b64_value(c: u8) -> u8 {
    match c {
        b'A'..=b'Z' => c - b'A',
        b'a'..=b'z' => c - b'a' + 26,
        b'0'..=b'9' => c - b'0' + 52,
        b'-' | b'+' => 62,
        b'_' | b'/' => 63,
        other => panic!("not base64: {other}"),
    }
}

/// Base64 or base64url, with or without padding.
fn b64(text: &str) -> Vec<u8> {
    let mut out = vec![];
    let (mut acc, mut bits) = (0u32, 0u32);
    for c in text.bytes().filter(|c| *c != b'=') {
        acc = (acc << 6) | u32::from(b64_value(c));
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push(((acc >> bits) & 0xff) as u8);
            acc &= (1 << bits) - 1;
        }
    }
    out
}

fn b64url(bytes: &[u8]) -> String {
    const A: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut out = String::new();
    let (mut acc, mut bits) = (0u32, 0u32);
    for b in bytes {
        acc = (acc << 8) | u32::from(*b);
        bits += 8;
        while bits >= 6 {
            bits -= 6;
            out.push(A[((acc >> bits) & 63) as usize] as char);
        }
        acc &= (1 << bits) - 1;
    }
    if bits > 0 {
        out.push(A[((acc << (6 - bits)) & 63) as usize] as char);
    }
    out
}

fn bitwarden() -> Vec<Value> {
    let file: Value = serde_json::from_str(BITWARDEN).unwrap();
    file["items"]
        .as_array()
        .unwrap()
        .iter()
        .map(|i| i["login"]["fido2Credentials"][0].clone())
        .collect()
}

fn aliasvault() -> Vec<Value> {
    let file: Value = serde_json::from_str(ALIASVAULT).unwrap();
    file["items"]
        .as_array()
        .unwrap()
        .iter()
        .map(|i| i["passkeys"][0].clone())
        .collect()
}

fn expected(n: usize) -> Value {
    let file: Value = serde_json::from_str(EXPECTED).unwrap();
    file["passkeys"][n].clone()
}

fn firefox() -> Vec<Vec<u8>> {
    FIREFOX
        .lines()
        .filter_map(|l| l.split_once(' ').map(|(_, k)| b64(k)))
        .collect()
}

/// PKCS#8 of a P-256 key with the public key included, written as
/// RFC 5958 and RFC 5915 give it (no use of the crate under test).
fn pkcs8_of(scalar: &[u8; 32]) -> Vec<u8> {
    SigningKey::from_slice(scalar)
        .unwrap()
        .to_pkcs8_der()
        .unwrap()
        .as_bytes()
        .to_vec()
}

fn jwk_of(scalar: &[u8; 32], with_public: bool) -> String {
    let key = SigningKey::from_slice(scalar).unwrap();
    let point = key.verifying_key().to_sec1_point(false);
    let public = if with_public {
        format!(
            ",\"x\":\"{}\",\"y\":\"{}\"",
            b64url(point.x().unwrap()),
            b64url(point.y().unwrap())
        )
    } else {
        String::new()
    };
    format!(
        "{{\"kty\":\"EC\",\"crv\":\"P-256\"{public},\"d\":\"{}\"}}",
        b64url(scalar)
    )
}

const SCALAR: [u8; 32] = [
    0x1f, 0x2e, 0x3d, 0x4c, 0x5b, 0x6a, 0x79, 0x88, 0x97, 0xa6, 0xb5, 0xc4, 0xd3, 0xe2, 0xf1, 0x01,
    0x12, 0x23, 0x34, 0x45, 0x56, 0x67, 0x78, 0x89, 0x9a, 0xab, 0xbc, 0xcd, 0xde, 0xef, 0xf0, 0x11,
];

fn input<'a>(key: ImportKey<'a>) -> ImportedPasskeyInput<'a> {
    ImportedPasskeyInput {
        cred_id: &[7; 16],
        rp_id: "example.com",
        user_handle: &[9; 16],
        user_name: "alice@example.com",
        rp_name: Some("Example"),
        user_display_name: Some("Alice"),
        created: 1_700_000_000_000,
        key,
        prf: ImportPrf::None,
        counter: 0,
    }
}

fn import_err(i: &ImportedPasskeyInput<'_>) -> Error {
    passkey_import(i).expect_err("the import must be refused")
}

fn ctx(origin: &str) -> CallerContext {
    CallerContext {
        origin: canonical_origin(origin).unwrap(),
        top_origin_is_same: true,
    }
}

const BAD_KEY: Error = Error::Malformed(MalformedKind::ItemBody);
const BAD_RP: Error = Error::Malformed(MalformedKind::RpId);
const BAD_INPUT: Error = Error::Malformed(MalformedKind::WebauthnOptions);

// --------------------------------------------------------------- tests

#[test]
fn import_accepts_pkcs8_and_jwk_p256_and_writes_the_canonical_form() {
    let mut seen = 0;
    // Bitwarden: PKCS#8 as base64url, three passkeys.
    for (n, cred) in bitwarden().iter().enumerate() {
        let der = b64(cred["keyValue"].as_str().unwrap());
        let (record, notes) = passkey_import(&input(ImportKey::Pkcs8Der(&der))).unwrap();
        let item = item_of(&record);
        let want = expected(n);
        let key = SigningKey::from_slice(&private_scalar(&record).unwrap()).unwrap();
        let spki = key.verifying_key().to_public_key_der().unwrap();
        assert_eq!(
            spki.as_bytes(),
            b64(want["publicKeySpkiB64"].as_str().unwrap()).as_slice()
        );
        // The stored form is the one `p256` writes, whatever form came in.
        assert_eq!(
            item.private_key,
            pkcs8_of(&private_scalar(&record).unwrap())
        );
        assert_eq!(notes.counter, 0);
        seen += 1;
    }
    // Keys that a browser's own WebCrypto wrote (the Bitwarden browser path).
    for der in firefox() {
        let (record, _) = passkey_import(&input(ImportKey::Pkcs8Der(&der))).unwrap();
        assert_eq!(
            item_of(&record).private_key,
            pkcs8_of(&private_scalar(&record).unwrap())
        );
        seen += 1;
    }
    // AliasVault: a JWK with `d`, and `x` and `y`.
    for (n, cred) in aliasvault().iter().enumerate() {
        let text = cred["privateKey"].as_str().unwrap();
        let (record, _) = passkey_import(&input(ImportKey::JwkJson(text))).unwrap();
        let want = expected(3 + n);
        let key = SigningKey::from_slice(&private_scalar(&record).unwrap()).unwrap();
        let spki = key.verifying_key().to_public_key_der().unwrap();
        assert_eq!(
            spki.as_bytes(),
            b64(want["publicKeySpkiB64"].as_str().unwrap()).as_slice()
        );
        assert_eq!(
            item_of(&record).private_key,
            pkcs8_of(&private_scalar(&record).unwrap())
        );
        seen += 1;
    }
    assert_eq!(seen, 7);

    // The same scalar in both forms is the same stored key.
    let from_der = passkey_import(&input(ImportKey::Pkcs8Der(&pkcs8_of(&SCALAR))))
        .unwrap()
        .0;
    for with_public in [true, false] {
        let text = jwk_of(&SCALAR, with_public);
        let from_jwk = passkey_import(&input(ImportKey::JwkJson(&text))).unwrap().0;
        assert_eq!(
            item_of(&from_jwk).private_key,
            item_of(&from_der).private_key
        );
    }
    // A PKCS#8 without the public key reads too, and is written with it.
    let mut short =
        hex_decode_str("3041020100301306072a8648ce3d020106082a8648ce3d030107042730250201010420");
    short.extend_from_slice(&SCALAR);
    let (record, _) = passkey_import(&input(ImportKey::Pkcs8Der(&short))).unwrap();
    assert_eq!(item_of(&record).private_key, pkcs8_of(&SCALAR));
}

fn hex_decode_str(s: &str) -> Vec<u8> {
    ferret_core::testing::hex_decode(s).unwrap()
}

#[test]
fn jwk_reading_is_strict_about_the_key_and_lenient_about_other_members() {
    let d = b64url(&SCALAR);
    let ok = |text: &str| passkey_import(&input(ImportKey::JwkJson(text)));
    // `kty` may be missing; other members and their values are skipped.
    let text = format!(
        "{{ \"ext\": true, \"key_ops\": [\"sign\", {{\"a\": [1, -2.5e3, null]}}], \"crv\" : \"P-256\",\n \"d\":\"{d}\", \"kid\": \"a\\\"b\" }}"
    );
    assert!(ok(&text).is_ok());
    // Padding of the base64url text is accepted.
    assert!(ok(&format!("{{\"crv\":\"P-256\",\"d\":\"{d}=\"}}")).is_ok());
    // `alg` ES256 is fine.
    assert!(
        ok(&format!(
            "{{\"crv\":\"P-256\",\"alg\":\"ES256\",\"d\":\"{d}\"}}"
        ))
        .is_ok()
    );

    // Not a key for Ferret: another kind, curve or algorithm.
    for (text, want) in [
        (
            format!("{{\"kty\":\"RSA\",\"n\":\"AQAB\",\"e\":\"AQAB\",\"d\":\"{d}\"}}"),
            Error::Unsupported,
        ),
        (
            format!("{{\"kty\":\"OKP\",\"crv\":\"Ed25519\",\"d\":\"{d}\"}}"),
            Error::Unsupported,
        ),
        (
            format!("{{\"kty\":\"EC\",\"crv\":\"P-384\",\"d\":\"{d}\"}}"),
            Error::Unsupported,
        ),
        (
            format!("{{\"kty\":\"EC\",\"crv\":\"secp256k1\",\"d\":\"{d}\"}}"),
            Error::Unsupported,
        ),
        (
            format!("{{\"crv\":\"P-256\",\"alg\":\"ES384\",\"d\":\"{d}\"}}"),
            Error::Unsupported,
        ),
    ] {
        assert_eq!(ok(&text).err(), Some(want), "{text}");
    }
    // Broken: no curve, no `d`, a `d` that is the wrong size, not base64url,
    // has spare bits set, or is a scalar that is not valid.
    let spare = {
        // 43 symbols; the last one carries two spare bits that must be zero.
        // Its value is a multiple of 4, so the next symbol sets a spare bit.
        const ALPHABET: &str = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
        let mut t = d.clone();
        let last = t.pop().unwrap();
        let at = ALPHABET.find(last).unwrap();
        assert_eq!(at % 4, 0);
        t.push(ALPHABET.as_bytes()[at + 1] as char);
        t
    };
    let zero = b64url(&[0u8; 32]);
    let order = b64url(&hex_decode_str(
        "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551",
    ));
    for text in [
        format!("{{\"kty\":\"EC\",\"d\":\"{d}\"}}"),
        "{\"kty\":\"EC\",\"crv\":\"P-256\"}".to_owned(),
        format!("{{\"crv\":\"P-256\",\"d\":\"{}\"}}", &d[1..]),
        format!("{{\"crv\":\"P-256\",\"d\":\"{d}A\"}}"),
        format!("{{\"crv\":\"P-256\",\"d\":\"{}+\"}}", &d[..42]),
        format!("{{\"crv\":\"P-256\",\"d\":\"{spare}\"}}"),
        format!("{{\"crv\":\"P-256\",\"d\":\"{zero}\"}}"),
        format!("{{\"crv\":\"P-256\",\"d\":\"{order}\"}}"),
        // Two `d`; an escape in a member that is read; a value that is not text.
        format!("{{\"crv\":\"P-256\",\"d\":\"{d}\",\"d\":\"{d}\"}}"),
        format!("{{\"crv\":\"P-256\",\"d\":\"{}\\u0041\"}}", &d[..42]),
        "{\"crv\":\"P-256\",\"d\":7}".to_owned(),
        // Only one coordinate, and a coordinate of another key.
        format!(
            "{{\"crv\":\"P-256\",\"x\":\"{}\",\"d\":\"{d}\"}}",
            b64url(&[1; 32])
        ),
        // Not an object, trailing text, an unfinished object, a control character.
        format!("[\"{d}\"]"),
        format!("{{\"crv\":\"P-256\",\"d\":\"{d}\"}} x"),
        format!("{{\"crv\":\"P-256\",\"d\":\"{d}\""),
        format!("{{\"crv\":\"P-256\",\"d\":\"{d}\",\"n\":\"a\nb\"}}"),
        String::new(),
        "null".to_owned(),
        // A member name with an escape (a reader that unescapes it would see
        // a second `d`, or another `kty`), and a second token after a skipped
        // value (that hides a member from the check for a duplicate).
        format!("{{\"crv\":\"P-256\",\"d\":\"{d}\",\"\\u0064\":\"{d}\"}}"),
        format!("{{\"crv\":\"P-256\",\"\\u006bty\":\"RSA\",\"d\":\"{d}\"}}"),
        format!("{{\"crv\":\"P-256\",\"d\":\"{d}\",\"n\":0 \"d\":\"{d}\"}}"),
        format!("{{\"crv\":\"P-256\",\"d\":\"{d}\",\"n\":[1] [2]}}"),
        format!("{{\"crv\":\"P-256\",\"d\":\"{d}\",\"n\":\"a\"x}}"),
        // A skipped value with its brackets mismatched, missing, or unclosed.
        format!("{{\"crv\":\"P-256\",\"d\":\"{d}\",\"n\":[1}}"),
        format!("{{\"crv\":\"P-256\",\"d\":\"{d}\",\"n\":{{\"a\":[1]]}}"),
        format!("{{\"crv\":\"P-256\",\"d\":\"{d}\",\"n\":}}"),
        format!("{{\"crv\":\"P-256\",\"d\":\"{d}\",\"n\":,\"m\":1}}"),
        format!("{{\"crv\":\"P-256\",\"d\":\"{d}\",\"n\":[1,2"),
    ] {
        assert_eq!(ok(&text).err(), Some(BAD_KEY), "{text}");
    }
    // The coordinates of the key are checked.
    let key = SigningKey::from_slice(&SCALAR).unwrap();
    let point = key.verifying_key().to_sec1_point(false);
    let other = SigningKey::from_slice(&[5; 32]).unwrap();
    let other_point = other.verifying_key().to_sec1_point(false);
    let wrong = format!(
        "{{\"crv\":\"P-256\",\"x\":\"{}\",\"y\":\"{}\",\"d\":\"{d}\"}}",
        b64url(other_point.x().unwrap()),
        b64url(point.y().unwrap())
    );
    assert_eq!(ok(&wrong).err(), Some(BAD_KEY));
    // Too long, and nested too deep to skip.
    let long = format!(
        "{{\"crv\":\"P-256\",\"d\":\"{d}\",\"n\":\"{}\"}}",
        "a".repeat(5000)
    );
    assert_eq!(ok(&long).err(), Some(Error::TooLarge));
    let deep = format!(
        "{{\"crv\":\"P-256\",\"d\":\"{d}\",\"n\":{}1{}}}",
        "[".repeat(20),
        "]".repeat(20)
    );
    assert_eq!(ok(&deep).err(), Some(BAD_KEY));
}

#[test]
fn import_refuses_other_curves_rsa_and_ed25519() {
    // Ed25519 (RFC 8410): 302e 0201 00 3005 0603 2b6570 0422 0420 <32 bytes>
    let mut ed = hex_decode_str("302e020100300506032b657004220420");
    ed.extend_from_slice(&SCALAR);
    // RSA (RFC 8017): a PKCS#8 whose algorithm is rsaEncryption.
    let rsa = hex_decode_str("3016020100300d06092a864886f70d010101050004023030");
    // P-384: the curve prime256v1 replaced by secp384r1 (1.3.132.0.34).
    let mut p384 =
        hex_decode_str("303e020100301006072a8648ce3d020106052b81040022042730250201010420");
    p384.extend_from_slice(&SCALAR);
    for (name, der) in [("ed25519", &ed), ("rsa", &rsa), ("p384", &p384)] {
        assert_eq!(
            import_err(&input(ImportKey::Pkcs8Der(der))),
            Error::Unsupported,
            "{name}"
        );
    }
    // Not PKCS#8 at all, empty, or too long to be a key.
    for der in [vec![], vec![0x30], vec![0u8; 138], SCALAR.to_vec()] {
        assert_eq!(import_err(&input(ImportKey::Pkcs8Der(&der))), BAD_KEY);
    }
    assert_eq!(
        import_err(&input(ImportKey::Pkcs8Der(&vec![0x30; 2000]))),
        Error::TooLarge
    );
    // A P-256 key whose scalar is zero, and one whose public key is not its
    // own, are broken keys and not "another kind".
    let mut zero = pkcs8_of(&SCALAR);
    zero[36..68].fill(0);
    assert_eq!(import_err(&input(ImportKey::Pkcs8Der(&zero))), BAD_KEY);
    let mut other_public = pkcs8_of(&SCALAR);
    let last = other_public.len() - 1;
    other_public[last] ^= 1;
    assert_eq!(
        import_err(&input(ImportKey::Pkcs8Der(&other_public))),
        BAD_KEY
    );
}

#[test]
fn import_refuses_a_public_suffix_or_ip_rp_id() {
    let der = pkcs8_of(&SCALAR);
    for rp in [
        "com",
        "co.uk",
        "github.io",
        "foo.ck",
        "localhost",
        "127.0.0.1",
        "0x7f.1",
        "10.0.0.1",
        "[::1]",
        "::1",
        "example.com:8443",
        "https://example.com",
        "example.com/path",
        "user@example.com",
        "exa mple.com",
        "-example.com",
        "exa_mple.com",
        "",
        ".",
        "..",
        "example..com",
        "*.example.com",
    ] {
        let mut i = input(ImportKey::Pkcs8Der(&der));
        i.rp_id = rp;
        assert_eq!(import_err(&i), BAD_RP, "{rp:?}");
    }
    // Written in any case, with a trailing dot or as Unicode, the same ID.
    for (written, canonical) in [
        ("example.com", "example.com"),
        ("Example.COM", "example.com"),
        ("example.com.", "example.com"),
        ("login.example.co.uk", "login.example.co.uk"),
        ("a.github.io", "a.github.io"),
        ("b\u{fc}cher.example", "xn--bcher-kva.example"),
        ("B\u{dc}CHER.example.", "xn--bcher-kva.example"),
        ("xn--bcher-kva.example", "xn--bcher-kva.example"),
    ] {
        let mut i = input(ImportKey::Pkcs8Der(&der));
        i.rp_id = written;
        let (record, _) = passkey_import(&i).unwrap();
        assert_eq!(record.rp_id, canonical, "{written}");
        assert_eq!(canonical_rp_id(written).unwrap().as_str(), canonical);
    }
    assert_eq!(
        canonical_rp_id("co.uk").err(),
        Some(BAD_RP),
        "the public function agrees"
    );
}

#[test]
fn import_accepts_credential_ids_of_1_to_1023_bytes() {
    let der = pkcs8_of(&SCALAR);
    for len in [1usize, 15, 16, 32, 64, 255, 256, 1022, 1023] {
        let id = vec![0xA5; len];
        let mut i = input(ImportKey::Pkcs8Der(&der));
        i.cred_id = &id;
        let (record, _) = passkey_import(&i).unwrap();
        assert_eq!(record.cred_id, id, "{len}");
    }
    let mut i = input(ImportKey::Pkcs8Der(&der));
    i.cred_id = &[];
    assert_eq!(import_err(&i), BAD_INPUT);
    let long = vec![1u8; 1024];
    i.cred_id = &long;
    assert_eq!(import_err(&i), Error::TooLarge);
    // The user handle is 1 to 64 bytes.
    i.cred_id = &[1; 16];
    for len in [1usize, 16, 64] {
        let handle = vec![3u8; len];
        let mut j = input(ImportKey::Pkcs8Der(&der));
        j.user_handle = &handle;
        assert!(passkey_import(&j).is_ok(), "{len}");
    }
    for len in [0usize, 65, 1000] {
        let handle = vec![3u8; len];
        let mut j = input(ImportKey::Pkcs8Der(&der));
        j.user_handle = &handle;
        assert_eq!(import_err(&j), BAD_INPUT, "{len}");
    }
    // A text of more than 1 KiB is refused, whichever it is.
    i.user_handle = &[3; 16];
    let long = "a".repeat(1025);
    i.user_name = &long;
    assert_eq!(import_err(&i), Error::TooLarge);
    i.user_name = "u";
    i.rp_name = Some(&long);
    assert_eq!(import_err(&i), Error::TooLarge);
    i.rp_name = None;
    i.user_display_name = Some(&long);
    assert_eq!(import_err(&i), Error::TooLarge);
    i.user_display_name = None;
    i.rp_id = &long;
    assert_eq!(import_err(&i), Error::TooLarge);
}

#[test]
fn site_texts_are_cleaned_as_for_a_passkey_made_by_ferret() {
    let der = pkcs8_of(&SCALAR);
    let mut i = input(ImportKey::Pkcs8Der(&der));
    i.user_name = "al\u{202e}ice\u{0}@example.com\u{200b}";
    i.rp_name = Some("Exam\u{2066}ple\n");
    i.user_display_name = Some("\u{7f}\u{0}");
    let (record, _) = passkey_import(&i).unwrap();
    assert_eq!(record.user_name, "alice@example.com");
    assert_eq!(record.rp_name.as_deref(), Some("Example"));
    assert_eq!(record.user_display_name, None);
    i.rp_name = None;
    i.user_display_name = Some("\u{c5}se");
    let (record, _) = passkey_import(&i).unwrap();
    assert_eq!(record.rp_name, None);
    assert_eq!(record.user_display_name.as_deref(), Some("\u{c5}se"));
}

#[test]
fn an_imported_passkey_signs_and_verifies_with_p256() {
    let want = expected(0);
    let cred = &bitwarden()[0];
    let der = b64(cred["keyValue"].as_str().unwrap());
    let id = b64(want["credentialIdRawB64u"].as_str().unwrap());
    let handle = b64(want["userHandleB64u"].as_str().unwrap());
    let mut i = input(ImportKey::Pkcs8Der(&der));
    i.cred_id = &id;
    i.user_handle = &handle;
    i.rp_id = "rp-a.test";
    let (record, _) = passkey_import(&i).unwrap();
    let vk = VerifyingKey::from_public_key_der(&b64(want["publicKeySpkiB64"].as_str().unwrap()))
        .unwrap();

    for verified in [true, false] {
        let req = GetRequest {
            challenge: vec![0x42; 32],
            rp_id: None,
            allow: vec![id.clone()],
            user_verification: UserVerification::Preferred,
            prf: None,
        };
        let uv = UvOutcome {
            user_present: true,
            user_verified: verified,
        };
        let r = passkey_get(&record, &req, &ctx("https://rp-a.test"), uv).unwrap();
        assert_eq!(r.id, id);
        assert_eq!(r.user_handle, handle);
        // The counter in the authenticator data is 0.
        assert_eq!(&r.authenticator_data[33..37], &[0, 0, 0, 0]);
        let mut msg = r.authenticator_data.clone();
        msg.extend_from_slice(&Sha256::digest(&r.client_data_json));
        let sig = Signature::from_der(&r.signature).unwrap();
        vk.verify(&msg, &sig).unwrap();
    }
    // The ID is the one of the site and no other.
    let req = GetRequest {
        challenge: vec![1; 32],
        rp_id: None,
        allow: vec![],
        user_verification: UserVerification::Preferred,
        prf: None,
    };
    let uv = UvOutcome {
        user_present: true,
        user_verified: false,
    };
    assert_eq!(
        passkey_get(&record, &req, &ctx("https://other.test"), uv).err(),
        Some(Error::NotAllowed)
    );
}

#[test]
fn import_notes_a_counter_above_zero_as_register_again() {
    let der = pkcs8_of(&SCALAR);
    for (counter, again) in [(0u32, false), (1, true), (7, true), (u32::MAX, true)] {
        let mut i = input(ImportKey::Pkcs8Der(&der));
        i.counter = counter;
        let (record, notes) = passkey_import(&i).unwrap();
        assert_eq!(
            notes,
            ImportNotes {
                register_again: again,
                counter,
                prf: false
            }
        );
        // Whatever the source had, Ferret's own counter is 0.
        assert_eq!(item_of(&record).sign_count, 0);
    }
    // The Bitwarden passkey with counter 7.
    let cred = &bitwarden()[1];
    assert_eq!(cred["counter"], "7");
    let der = b64(cred["keyValue"].as_str().unwrap());
    let mut i = input(ImportKey::Pkcs8Der(&der));
    i.counter = cred["counter"].as_str().unwrap().parse().unwrap();
    assert!(passkey_import(&i).unwrap().1.register_again);
}

#[test]
fn import_without_matching_prf_formula_drops_prf() {
    let der = pkcs8_of(&SCALAR);
    // No PRF: no seeds, and the note says so.
    let (record, notes) = passkey_import(&input(ImportKey::Pkcs8Der(&der))).unwrap();
    assert!(!record.has_prf());
    assert!(!notes.prf);
    let item = item_of(&record);
    assert!(item.prf_seed_uv.is_none() && item.prf_seed_nouv.is_none());

    // The AliasVault key with a PRF secret: both seeds are the secret, and
    // the outputs are the ones of AliasVault's formula,
    // HMAC-SHA256(prfKey, SHA-256("WebAuthn PRF" || 0x00 || salt)).
    let cred = &aliasvault()[1];
    let secret = b64(cred["prfKey"].as_str().unwrap());
    assert_eq!(secret.len(), 32);
    let jwk = cred["privateKey"].as_str().unwrap();
    let mut i = input(ImportKey::JwkJson(jwk));
    i.rp_id = "rp-a.test";
    i.prf = ImportPrf::Seeds {
        uv: &secret,
        nouv: &secret,
    };
    let (record, notes) = passkey_import(&i).unwrap();
    assert!(record.has_prf() && notes.prf);
    let item = item_of(&record);
    assert_eq!(item.prf_seed_uv.as_deref(), Some(secret.as_slice()));
    assert_eq!(item.prf_seed_nouv.as_deref(), Some(secret.as_slice()));

    let salt_input = b"a site's salt".to_vec();
    let mut hashed = b"WebAuthn PRF\0".to_vec();
    hashed.extend_from_slice(&salt_input);
    let salt = Sha256::digest(&hashed);
    let reference = hmac_sha256(&secret, &salt).unwrap();
    for verified in [true, false] {
        let req = GetRequest {
            challenge: vec![1; 32],
            rp_id: Some("rp-a.test".into()),
            allow: vec![],
            user_verification: UserVerification::Preferred,
            prf: Some(ferret_core::passkey::PrfRequest {
                eval: Some(ferret_core::passkey::PrfEval {
                    first: salt_input.clone(),
                    second: None,
                }),
                eval_by_credential: vec![],
            }),
        };
        let uv = UvOutcome {
            user_present: true,
            user_verified: verified,
        };
        let r = passkey_get(&record, &req, &ctx("https://rp-a.test"), uv).unwrap();
        assert_eq!(
            r.prf.unwrap().reveal_first().as_slice(),
            reference.as_slice()
        );
    }

    // Two different seeds are kept as they are.
    let (a, b) = ([1u8; 32], [2u8; 32]);
    i.prf = ImportPrf::Seeds { uv: &a, nouv: &b };
    let item = item_of(&passkey_import(&i).unwrap().0);
    assert_eq!(item.prf_seed_uv.as_deref(), Some(a.as_slice()));
    assert_eq!(item.prf_seed_nouv.as_deref(), Some(b.as_slice()));
    // A seed that is not 32 bytes is refused: the caller must drop the PRF
    // of a source with another formula, not pass it on.
    for bad in [&a[..31], &[][..], &[3u8; 33][..], &[3u8; 64][..]] {
        i.prf = ImportPrf::Seeds { uv: bad, nouv: &b };
        assert_eq!(import_err(&i), BAD_KEY);
        i.prf = ImportPrf::Seeds { uv: &a, nouv: bad };
        assert_eq!(import_err(&i), BAD_KEY);
    }
}

#[test]
fn the_input_and_the_record_hide_the_key_in_debug() {
    let der = pkcs8_of(&SCALAR);
    let text = jwk_of(&SCALAR, true);
    let seed = [0xEEu8; 32];
    for key in [ImportKey::Pkcs8Der(&der), ImportKey::JwkJson(&text)] {
        let mut i = input(key);
        i.prf = ImportPrf::Seeds {
            uv: &seed,
            nouv: &seed,
        };
        let shown = format!("{i:?}");
        assert!(!shown.contains("238") && !shown.contains("0xee"), "{shown}");
        assert!(
            !shown.contains("P-256") && !shown.contains("alice"),
            "{shown}"
        );
        let (record, _) = passkey_import(&i).unwrap();
        let shown = format!("{record:?}");
        assert!(!shown.contains("alice"), "{shown}");
    }
}

#[test]
fn an_imported_record_attaches_to_an_item_body() {
    let der = pkcs8_of(&SCALAR);
    let (record, _) = passkey_import(&input(ImportKey::Pkcs8Der(&der))).unwrap();
    let mut body = ferret_core::ItemBody::new(ferret_core::ItemType::Login, "Example", 5);
    record.attach_to(&mut body);
    let again = PasskeyRecord::from_item(body.passkey.as_ref().unwrap()).unwrap();
    assert_eq!(again.rp_id, "example.com");
    assert_eq!(again.cred_id, vec![7; 16]);
}

// ------------------------------------------------------------- vectors

fn key_of(v: &Value) -> (String, Vec<u8>) {
    match v["format"].as_str().unwrap() {
        "pkcs8" => ("pkcs8".into(), hex(&v["hex"])),
        "jwk" => (
            "jwk".into(),
            v["text"].as_str().unwrap().as_bytes().to_vec(),
        ),
        other => panic!("format {other}"),
    }
}

fn run_vectors() -> ferret_core::testing::vector::RunReport {
    let file = load_ops("passkey_import.json", |op| op == "passkey.import");
    ferret_core::testing::vector::run_all(&file, |case, _rng| {
        let i = &case.input;
        let (format, key_bytes) = key_of(&i["key"]);
        let key_text;
        let key = if format == "pkcs8" {
            ImportKey::Pkcs8Der(&key_bytes)
        } else {
            key_text = String::from_utf8(key_bytes.clone()).unwrap();
            ImportKey::JwkJson(&key_text)
        };
        let seeds = i["prf"]
            .as_object()
            .map(|p| (hex(&p["uv"]), hex(&p["nouv"])));
        let cred_id = hex(&i["cred_id"]);
        let handle = hex(&i["user_handle"]);
        let input = ImportedPasskeyInput {
            cred_id: &cred_id,
            rp_id: i["rp_id"].as_str().unwrap(),
            user_handle: &handle,
            user_name: i["user_name"].as_str().unwrap(),
            rp_name: i["rp_name"].as_str(),
            user_display_name: i["user_display_name"].as_str(),
            created: u64s(&i["created"]),
            key,
            prf: match &seeds {
                Some((uv, nouv)) => ImportPrf::Seeds { uv, nouv },
                None => ImportPrf::None,
            },
            counter: u32::try_from(i["counter"].as_u64().unwrap()).unwrap(),
        };
        let (record, notes) = passkey_import(&input)?;
        let item = item_of(&record);
        let key = SigningKey::from_slice(&private_scalar(&record).unwrap()).unwrap();
        let spki = key.verifying_key().to_public_key_der().unwrap();
        let opt = |b: &Option<Vec<u8>>| b.as_deref().map_or(Value::Null, |s| Value::from(he(s)));
        Ok(Outcome {
            output: json!({
                "record": {
                    "cred_id": he(&item.cred_id),
                    "rp_id": item.rp_id,
                    "user_handle": he(&item.user_handle),
                    "user_name": item.user_name,
                    "rp_name": item.rp_name,
                    "user_display_name": item.user_display_name,
                    "created": item.created.to_string(),
                    "priv_pkcs8": he(&item.private_key),
                    "public_key_spki": he(spki.as_bytes()),
                    "prf_seed_uv": opt(&item.prf_seed_uv),
                    "prf_seed_nouv": opt(&item.prf_seed_nouv),
                },
                "notes": {
                    "register_again": notes.register_again,
                    "counter": notes.counter,
                    "prf": notes.prf,
                },
            }),
            intermediate: None,
        })
    })
}

#[test]
fn vectors_passkey_import_pass() {
    let report = run_vectors();
    assert_all_passed(&report, 40);
    let file = load_ops("passkey_import.json", |op| op == "passkey.import");
    assert!(file.cases.len() >= 40, "{} cases", file.cases.len());
    assert!(
        file.cases
            .iter()
            .any(|c| c.status == ferret_core::testing::vector::Status::Invalid)
    );
}
