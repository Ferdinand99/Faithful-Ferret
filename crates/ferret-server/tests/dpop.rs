//! The DPoP check (RFC 9449): the strict reading of a proof, its signature
//! through the JOSE library, its claims against the request, and the cache of
//! used `jti` values that only a bound proof fills. Spec: Fase 1 § 7.6.

mod support;

use std::path::{Path, PathBuf};

use axum::extract::FromRef;
use axum::http::{HeaderMap, HeaderName, HeaderValue, Method, StatusCode, header};
use axum::response::IntoResponse as _;
use ferret_core::TestRng;
use ferret_server::auth::dpop::proof::{self, ProofError};
use ferret_server::auth::dpop::{
    self, DpopError, Expect, JTI_TTL_SECS, JtiCache, MAX_PROOF_LEN, VerifiedProof,
};
use ferret_server::auth::tokens::DeviceAuth;
use ferret_server::error::ApiError;
use ferret_server::ids::TokenSecret;
use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};
use support::backup::capture_log;
use support::dpop::{DeviceKey, b64, claims, fresh_jti, headers_with, segments, unhex};
use support::{Req, START, TestApp, VAULT_URL, Which};

const NOW: i64 = START as i64;
const PATH: &str = "/api/sync/changes";

fn htu() -> String {
    format!("{VAULT_URL}{PATH}")
}

fn token(seed: &[u8]) -> TokenSecret {
    TokenSecret::random(&mut TestRng::new(seed))
}

/// Checks `proof` for a `GET` of [`PATH`] with `access`, at `now`.
fn check(proof: &str, access: Option<&TokenSecret>, now: i64) -> Result<VerifiedProof, DpopError> {
    check_for(proof, &Method::GET, &htu(), access, now)
}

fn check_for(
    proof: &str,
    method: &Method,
    htu: &str,
    access: Option<&TokenSecret>,
    now: i64,
) -> Result<VerifiedProof, DpopError> {
    let expect = Expect {
        method,
        htu,
        access,
    };
    dpop::verify(&headers_with(proof), &expect, now)
}

/// A good proof of `key` for a `GET` of [`PATH`] at [`NOW`], without a token.
fn good(key: &DeviceKey) -> String {
    key.proof("GET", &htu(), NOW, None)
}

/// A proof of `key` whose header is `header` and whose claims are good.
fn with_header(key: &DeviceKey, header: &Value) -> String {
    key.sign(header, &claims("GET", &htu(), NOW, &fresh_jti(), None))
}

/// A proof of `key` whose header is these exact bytes.
fn with_header_text(key: &DeviceKey, header: &str) -> String {
    let claims = claims("GET", &htu(), NOW, &fresh_jti(), None);
    key.sign_bytes(
        header.as_bytes(),
        serde_json::to_string(&claims).expect("json").as_bytes(),
    )
}

/// A proof of `key` whose claims are these exact bytes.
fn with_claims_text(key: &DeviceKey, claims: &str) -> String {
    key.sign_bytes(
        serde_json::to_string(&key.header())
            .expect("json")
            .as_bytes(),
        claims.as_bytes(),
    )
}

/// The refusal of `proof`, by the strict reader and by the whole check.
fn refused(proof: &str) -> (Result<(), ProofError>, DpopError) {
    let split = proof::split(proof).map(|_| ());
    let whole = check(proof, None, NOW).expect_err("refused");
    (split, whole)
}

fn verified(proof: &str) -> VerifiedProof {
    check(proof, None, NOW).expect("a good proof")
}

// -------------------------------------------------------- algorithm and header

#[test]
fn proof_with_hs256_none_or_rs256_is_refused() {
    let key = DeviceKey::new(1);
    assert!(
        check(&good(&key), None, NOW).is_ok(),
        "the good proof passes"
    );
    for alg in [
        "HS256", "none", "None", "RS256", "PS256", "ES384", "ES512", "EdDSA", "es256", "ES256K", "",
    ] {
        let mut header = key.header();
        header["alg"] = json!(alg);
        let proof = with_header(&key, &header);
        assert_eq!(
            refused(&proof),
            (Err(ProofError::Header), DpopError::Malformed),
            "{alg}"
        );
    }
    // No `alg` at all, and `alg` that is not a string.
    let mut header = key.header();
    header.as_object_mut().expect("an object").remove("alg");
    assert_eq!(refused(&with_header(&key, &header)).1, DpopError::Malformed);
    header["alg"] = json!(["ES256"]);
    assert_eq!(refused(&with_header(&key, &header)).1, DpopError::Malformed);

    // An unsecured JWS (`alg: none`) has an empty signature segment.
    let (head, body, _) = segments(&good(&key));
    let mut header = key.header();
    header["alg"] = json!("none");
    let none = format!("{}.{body}.", b64(header.to_string().as_bytes()));
    assert_eq!(
        refused(&none),
        (Err(ProofError::Segments), DpopError::Malformed)
    );
    let bare = format!("{head}.{body}.");
    assert_eq!(
        refused(&bare),
        (Err(ProofError::Segments), DpopError::Malformed)
    );

    // An HMAC "signature" with the public key as the secret, the classic
    // confusion, is refused before any key is used.
    let mut header = key.header();
    header["alg"] = json!("HS256");
    let input = format!(
        "{}.{body}",
        b64(serde_json::to_string(&header).expect("json").as_bytes())
    );
    let forged = format!("{input}.{}", b64(&[0u8; 32]));
    assert_eq!(refused(&forged).1, DpopError::Malformed);
}

#[test]
fn proof_with_a_private_jwk_member_is_refused() {
    let key = DeviceKey::new(2);
    for (member, value) in [
        ("d", json!(b64(&[2u8; 32]))),
        ("p", json!("AQAB")),
        ("q", json!("AQAB")),
        ("dp", json!("AQAB")),
        ("k", json!("c2VjcmV0")),
    ] {
        let mut header = key.header();
        header["jwk"][member] = value;
        assert_eq!(
            refused(&with_header(&key, &header)),
            (Err(ProofError::Header), DpopError::Malformed),
            "{member}"
        );
    }
}

#[test]
fn proof_with_kid_jku_x5c_or_a_duplicate_member_is_refused() {
    let key = DeviceKey::new(3);
    // Members of the header that would name a key elsewhere, or anything else.
    for (member, value) in [
        ("kid", json!("key-1")),
        ("jku", json!("https://evil.test/keys")),
        ("x5c", json!(["MIIB"])),
        ("x5u", json!("https://evil.test/cert")),
        ("x5t", json!("AAAA")),
        ("crit", json!(["exp"])),
        ("cty", json!("JWT")),
        ("nonce", json!("abc")),
    ] {
        let mut header = key.header();
        header[member] = value;
        assert_eq!(
            refused(&with_header(&key, &header)),
            (Err(ProofError::Header), DpopError::Malformed),
            "{member}"
        );
    }
    // Members of the key beyond the four, as WebCrypto's export adds them.
    for (member, value) in [
        ("ext", json!(true)),
        ("key_ops", json!(["verify"])),
        ("alg", json!("ES256")),
        ("use", json!("sig")),
        ("kid", json!("a")),
    ] {
        let mut header = key.header();
        header["jwk"][member] = value;
        assert_eq!(
            refused(&with_header(&key, &header)).1,
            DpopError::Malformed,
            "jwk {member}"
        );
    }

    let jwk = serde_json::to_string(&key.jwk()).expect("json");
    let x = &key.x;
    let y = &key.y;
    for text in [
        // A member twice, with the same or another value.
        format!(r#"{{"typ":"dpop+jwt","typ":"dpop+jwt","alg":"ES256","jwk":{jwk}}}"#),
        format!(r#"{{"typ":"dpop+jwt","alg":"none","alg":"ES256","jwk":{jwk}}}"#),
        format!(r#"{{"typ":"dpop+jwt","alg":"ES256","jwk":{jwk},"jwk":{jwk}}}"#),
        format!(r#"{{"typ":"dpop+jwt","alg":"HS256","alg":"ES256","jwk":{jwk}}}"#),
        format!(
            r#"{{"typ":"dpop+jwt","alg":"ES256","jwk":{{"kty":"EC","crv":"P-256","x":"{x}","x":"{x}","y":"{y}"}}}}"#
        ),
        // Not an object, or something after it.
        format!(r#"["dpop+jwt","ES256",{jwk}]"#),
        format!(r#"{{"typ":"dpop+jwt","alg":"ES256","jwk":["EC","P-256","{x}","{y}"]}}"#),
        format!(r#"{{"typ":"dpop+jwt","alg":"ES256","jwk":{jwk}}}x"#),
        format!(r#"{{"typ":"dpop+jwt","alg":"ES256","jwk":{jwk}}}{{}}"#),
        r#"{"typ":"dpop+jwt","alg":"ES256","jwk":null}"#.to_string(),
        String::from("null"),
    ] {
        assert_eq!(
            refused(&with_header_text(&key, &text)),
            (Err(ProofError::Header), DpopError::Malformed),
            "{text}"
        );
    }
    // The good header written by hand passes, so the cases above fail for
    // their one change only.
    let plain = format!(r#"{{"typ":"dpop+jwt","alg":"ES256","jwk":{jwk}}}"#);
    assert!(check(&with_header_text(&key, &plain), None, NOW).is_ok());

    // The claims: a member twice, an unknown member, an array, `ath: null`.
    let htu = htu();
    for text in [
        format!(
            r#"{{"jti":"{0}","jti":"{0}","htm":"GET","htu":"{htu}","iat":{NOW}}}"#,
            fresh_jti()
        ),
        format!(
            r#"{{"jti":"{}","htm":"POST","htm":"GET","htu":"{htu}","iat":{NOW}}}"#,
            fresh_jti()
        ),
        format!(
            r#"{{"jti":"{}","htm":"GET","htu":"{htu}","iat":{NOW},"nonce":"n"}}"#,
            fresh_jti()
        ),
        format!(
            r#"{{"jti":"{}","htm":"GET","htu":"{htu}","iat":{NOW},"exp":{NOW}}}"#,
            fresh_jti()
        ),
        format!(
            r#"{{"jti":"{}","htm":"GET","htu":"{htu}","iat":{NOW},"ath":null}}"#,
            fresh_jti()
        ),
        format!(
            r#"{{"jti":"{}","htm":"GET","htu":"{htu}","iat":"{NOW}"}}"#,
            fresh_jti()
        ),
        format!(
            r#"{{"jti":"{}","htm":"GET","htu":"{htu}","iat":{NOW}.5}}"#,
            fresh_jti()
        ),
        format!(r#"{{"jti":"{}","htm":"GET","htu":"{htu}"}}"#, fresh_jti()),
        format!(r#"["{}","GET","{htu}",{NOW}]"#, fresh_jti()),
        format!(
            r#"{{"jti":"{}","htm":"GET","htu":"{htu}","iat":{NOW}}}x"#,
            fresh_jti()
        ),
    ] {
        let proof = with_claims_text(&key, &text);
        assert!(proof::split(&proof).is_ok(), "the header is good: {text}");
        assert_eq!(
            check(&proof, None, NOW).unwrap_err(),
            DpopError::Claims,
            "{text}"
        );
    }
    let plain = format!(
        r#"{{"jti":"{}","htm":"GET","htu":"{htu}","iat":{NOW}}}"#,
        fresh_jti()
    );
    assert!(check(&with_claims_text(&key, &plain), None, NOW).is_ok());
}

#[test]
fn typ_other_than_dpop_jwt_is_refused() {
    let key = DeviceKey::new(4);
    for typ in [
        json!("JWT"),
        json!("jwt"),
        json!("DPOP+JWT"),
        json!("application/dpop+jwt"),
        json!("dpop+jwt "),
        json!("at+jwt"),
        json!(""),
        json!(null),
    ] {
        let mut header = key.header();
        header["typ"] = typ.clone();
        assert_eq!(
            refused(&with_header(&key, &header)),
            (Err(ProofError::Header), DpopError::Malformed),
            "{typ}"
        );
    }
    let mut header = key.header();
    header.as_object_mut().expect("an object").remove("typ");
    assert_eq!(refused(&with_header(&key, &header)).1, DpopError::Malformed);
}

#[test]
fn a_jwk_that_is_not_p256_or_has_short_coordinates_is_refused() {
    let key = DeviceKey::new(5);
    let x = unhex_b64(&key.x);
    let cases: Vec<(&str, Value)> = vec![
        (
            "P-384",
            json!({"kty": "EC", "crv": "P-384", "x": key.x, "y": key.y}),
        ),
        (
            "secp256k1",
            json!({"kty": "EC", "crv": "secp256k1", "x": key.x, "y": key.y}),
        ),
        (
            "p-256",
            json!({"kty": "EC", "crv": "p-256", "x": key.x, "y": key.y}),
        ),
        (
            "OKP",
            json!({"kty": "OKP", "crv": "P-256", "x": key.x, "y": key.y}),
        ),
        (
            "RSA",
            json!({"kty": "RSA", "crv": "P-256", "x": key.x, "y": key.y}),
        ),
        (
            "short x",
            json!({"kty": "EC", "crv": "P-256", "x": b64(&x[..31]), "y": key.y}),
        ),
        (
            "long x",
            json!({"kty": "EC", "crv": "P-256", "x": b64(&[&x[..], &[0u8][..]].concat()), "y": key.y}),
        ),
        (
            "empty y",
            json!({"kty": "EC", "crv": "P-256", "x": key.x, "y": ""}),
        ),
        ("no y", json!({"kty": "EC", "crv": "P-256", "x": key.x})),
        (
            "number x",
            json!({"kty": "EC", "crv": "P-256", "x": 1, "y": key.y}),
        ),
    ];
    for (what, jwk) in cases {
        let mut header = key.header();
        header["jwk"] = jwk;
        let (split, whole) = refused(&with_header(&key, &header));
        assert!(
            matches!(split, Err(ProofError::Key | ProofError::Header)),
            "{what}: {split:?}"
        );
        assert_eq!(whole, DpopError::Malformed, "{what}");
    }

    // Coordinates of the right size that are not a point of the curve pass
    // the reader and fail at the library.
    let mut header = key.header();
    header["jwk"]["y"] = json!(b64(&[1u8; 32]));
    let proof = with_header(&key, &header);
    assert!(proof::split(&proof).is_ok());
    assert_eq!(check(&proof, None, NOW).unwrap_err(), DpopError::Signature);
    // Another key's coordinates: a good point, the wrong one.
    let other = DeviceKey::new(6);
    let mut header = key.header();
    header["jwk"] = other.jwk();
    assert_eq!(
        check(&with_header(&key, &header), None, NOW).unwrap_err(),
        DpopError::Signature
    );
}

fn unhex_b64(text: &str) -> Vec<u8> {
    use base64::Engine as _;
    base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(text)
        .expect("base64url")
}

#[test]
fn a_jwk_with_non_canonical_base64_is_refused() {
    let key = DeviceKey::new(7);
    // The last character of 43 carries 2 spare bits that must be zero: a
    // neighbour of it decodes to the same 32 bytes with a spare bit set.
    let last = key.x.chars().last().expect("a character");
    let alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let index = alphabet.find(last).expect("in the alphabet");
    let neighbour = alphabet.chars().nth(index ^ 1).expect("a neighbour");
    let spare = format!("{}{neighbour}", &key.x[..42]);
    let standard = key.x.replace('-', "+").replace('_', "/");
    for x in [
        spare,
        format!("{}=", key.x),
        format!("{} ", key.x),
        format!(" {}", key.x),
        standard.clone(),
    ] {
        if x == key.x {
            continue;
        }
        let mut header = key.header();
        header["jwk"]["x"] = json!(x);
        assert_eq!(
            refused(&with_header(&key, &header)),
            (Err(ProofError::Key), DpopError::Malformed),
            "{x}"
        );
    }
    // The canonical form passes.
    assert!(check(&good(&key), None, NOW).is_ok());

    // A segment of the proof itself with spare bits, padding or white space
    // is refused too.
    let (head, body, signature) = segments(&good(&key));
    let flip = |text: &str| {
        let last = text.chars().last().expect("a character");
        let index = alphabet.find(last).expect("in the alphabet");
        format!(
            "{}{}",
            &text[..text.len() - 1],
            alphabet.chars().nth(index ^ 1).expect("a neighbour")
        )
    };
    if !signature.len().is_multiple_of(4) {
        assert_eq!(
            refused(&format!("{head}.{body}.{}", flip(&signature))).0,
            Err(ProofError::Encoding)
        );
    }
    for proof in [
        format!("{head}=.{body}.{signature}"),
        format!("{head}.{body}=.{signature}"),
        format!("{head}.{body}.{signature}="),
        format!("{head}.{body}.{signature}=="),
        format!("{head} .{body}.{signature}"),
        format!("{head}.+{}.{signature}", &body[1..]),
    ] {
        assert!(proof::split(&proof).is_err(), "{proof}");
    }
}

#[test]
fn a_proof_over_4_kib_is_refused_before_decoding() {
    // Long, and not even base64: refused for its length, before anything
    // is decoded.
    let long = "!".repeat(MAX_PROOF_LEN + 1);
    assert_eq!(proof::split(&long).unwrap_err(), ProofError::TooLong);
    let mut long_good = good(&DeviceKey::new(8));
    long_good.push_str(&"A".repeat(MAX_PROOF_LEN + 1 - long_good.len()));
    assert_eq!(long_good.len(), MAX_PROOF_LEN + 1);
    assert_eq!(proof::split(&long_good).unwrap_err(), ProofError::TooLong);
    assert_eq!(
        check(&long_good, None, NOW).unwrap_err(),
        DpopError::Malformed
    );
    // At the limit it is read (and refused for what it is).
    let at_limit = "!".repeat(MAX_PROOF_LEN);
    assert_eq!(proof::split(&at_limit).unwrap_err(), ProofError::Segments);
    // A header value of more than the limit, whatever it holds.
    let mut headers = HeaderMap::new();
    headers.insert(
        "dpop",
        HeaderValue::from_str(&"a.".repeat(MAX_PROOF_LEN)).expect("a value"),
    );
    let method = Method::GET;
    let htu = htu();
    let expect = Expect {
        method: &method,
        htu: &htu,
        access: None,
    };
    assert_eq!(
        dpop::verify(&headers, &expect, NOW).unwrap_err(),
        DpopError::Malformed
    );
}

#[test]
fn two_dpop_headers_are_refused() {
    let key = DeviceKey::new(9);
    let proof = good(&key);
    let method = Method::GET;
    let htu = htu();
    let expect = Expect {
        method: &method,
        htu: &htu,
        access: None,
    };
    let mut two = headers_with(&proof);
    two.append("dpop", HeaderValue::from_str(&good(&key)).expect("a value"));
    assert_eq!(
        dpop::verify(&two, &expect, NOW).unwrap_err(),
        DpopError::Missing
    );
    let mut same = headers_with(&proof);
    same.append(
        HeaderName::from_bytes(b"DPoP").expect("a name"),
        HeaderValue::from_str(&proof).expect("a value"),
    );
    assert_eq!(
        dpop::verify(&same, &expect, NOW).unwrap_err(),
        DpopError::Missing
    );
    assert_eq!(
        dpop::verify(&HeaderMap::new(), &expect, NOW).unwrap_err(),
        DpopError::Missing
    );
    // One header, in any case of its name, passes.
    let mut one = HeaderMap::new();
    one.insert(
        HeaderName::from_bytes(b"DPoP").expect("a name"),
        HeaderValue::from_str(&proof).expect("a value"),
    );
    assert!(dpop::verify(&one, &expect, NOW).is_ok());
    // A value that is not visible ASCII is refused.
    let mut odd = HeaderMap::new();
    odd.insert(
        "dpop",
        HeaderValue::from_bytes(b"a.b.\xff").expect("a value"),
    );
    assert_eq!(
        dpop::verify(&odd, &expect, NOW).unwrap_err(),
        DpopError::Malformed
    );
}

#[test]
fn the_signature_is_checked_over_the_exact_signing_input() {
    let key = DeviceKey::new(10);
    let proof = good(&key);
    let (head, body, signature) = segments(&proof);
    assert!(check(&proof, None, NOW).is_ok());

    // The same header with other white space: the same meaning, other bytes.
    let spaced = serde_json::to_string_pretty(&key.header()).expect("json");
    let swapped = format!("{}.{body}.{signature}", b64(spaced.as_bytes()));
    assert!(proof::split(&swapped).is_ok());
    assert_eq!(
        check(&swapped, None, NOW).unwrap_err(),
        DpopError::Signature
    );

    // Claims changed by one byte (another `iat`, another `jti`), the old
    // signature kept.
    let claims_text = String::from_utf8(unhex_b64(&body)).expect("utf-8");
    for changed in [
        claims_text.replace(&NOW.to_string(), &(NOW + 1).to_string()),
        claims_text.replacen("jti-", "jti_", 1),
        claims_text.replace("GET", "PUT"),
    ] {
        assert_ne!(changed, claims_text);
        let forged = format!("{head}.{}.{signature}", b64(changed.as_bytes()));
        assert_eq!(check(&forged, None, NOW).unwrap_err(), DpopError::Signature);
    }
    // Every byte of the signature matters.
    let mut raw = unhex_b64(&signature);
    for i in [0, 31, 32, 63] {
        raw[i] ^= 1;
        let forged = format!("{head}.{body}.{}", b64(&raw));
        assert_eq!(
            check(&forged, None, NOW).unwrap_err(),
            DpopError::Signature,
            "byte {i}"
        );
        raw[i] ^= 1;
    }
    // A signature of another length, or in DER, is refused by the reader.
    for length in [0usize, 63, 65, 70, 72] {
        let forged = format!("{head}.{body}.{}", b64(&vec![1u8; length]));
        assert!(check(&forged, None, NOW).is_err(), "{length}");
    }
    // The signature of another proof, or of the same proof by another key.
    let other = DeviceKey::new(11);
    let (_, _, theirs) = segments(&other.proof("GET", &htu(), NOW, None));
    let forged = format!("{head}.{body}.{theirs}");
    assert_eq!(check(&forged, None, NOW).unwrap_err(), DpopError::Signature);
    assert_eq!(
        proof::signing_input(&proof::split(&proof).expect("parts")),
        format!("{head}.{body}")
    );
    assert_eq!(
        proof::signature_b64(&proof::split(&proof).expect("parts")),
        signature
    );
}

// ---------------------------------------------------------------- the claims

#[test]
fn htu_with_query_or_other_host_is_refused() {
    let key = DeviceKey::new(12);
    let htu = htu();
    for wrong in [
        format!("{htu}?since=0"),
        format!("{htu}?"),
        format!("{htu}#x"),
        format!("{htu}/"),
        "https://evil.test/api/sync/changes".to_string(),
        "https://vault.ferret.test.evil.test/api/sync/changes".to_string(),
        "http://vault.ferret.test/api/sync/changes".to_string(),
        "https://VAULT.ferret.test/api/sync/changes".to_string(),
        "https://vault.ferret.test:443/api/sync/changes".to_string(),
        "https://vault.ferret.test/api/sync/../sync/changes".to_string(),
        "https://vault.ferret.test/api/sync/%63hanges".to_string(),
        "https://vault.ferret.test/api/sync/items".to_string(),
        "/api/sync/changes".to_string(),
        String::new(),
    ] {
        let proof = key.proof("GET", &wrong, NOW, None);
        assert_eq!(
            check(&proof, None, NOW).unwrap_err(),
            DpopError::Claims,
            "{wrong}"
        );
    }
    assert!(check(&key.proof("GET", &htu, NOW, None), None, NOW).is_ok());
}

#[test]
fn htm_must_match_the_method() {
    let key = DeviceKey::new(13);
    let htu = htu();
    for (signed, method) in [
        ("GET", Method::POST),
        ("get", Method::GET),
        ("POST", Method::PUT),
        ("PUT", Method::GET),
        ("", Method::GET),
        ("GET ", Method::GET),
    ] {
        let proof = key.proof(signed, &htu, NOW, None);
        assert_eq!(
            check_for(&proof, &method, &htu, None, NOW).unwrap_err(),
            DpopError::Claims,
            "{signed} for {method}"
        );
    }
    for method in [Method::GET, Method::POST, Method::PUT, Method::DELETE] {
        let proof = key.proof(method.as_str(), &htu, NOW, None);
        assert!(
            check_for(&proof, &method, &htu, None, NOW).is_ok(),
            "{method}"
        );
    }
}

#[test]
fn iat_outside_60_seconds_is_refused() {
    let key = DeviceKey::new(14);
    let htu = htu();
    for (offset, holds) in [
        (0, true),
        (59, true),
        (60, true),
        (61, false),
        (-59, true),
        (-60, true),
        (-61, false),
        (3_600, false),
        (-3_600, false),
    ] {
        let proof = key.proof("GET", &htu, NOW + offset, None);
        let result = check(&proof, None, NOW);
        if holds {
            assert!(result.is_ok(), "{offset}");
        } else {
            assert_eq!(result.unwrap_err(), DpopError::Clock, "{offset}");
        }
    }
    // The extremes of the number do not overflow anything.
    for iat in [i64::MIN, i64::MAX, -1] {
        let proof = key.proof("GET", &htu, iat, None);
        assert_eq!(
            check(&proof, None, NOW).unwrap_err(),
            DpopError::Clock,
            "{iat}"
        );
    }
    let proof = key.proof("GET", &htu, i64::MAX, None);
    assert!(check(&proof, None, i64::MAX).is_ok());
    let proof = key.proof("GET", &htu, i64::MIN, None);
    assert!(check(&proof, None, i64::MIN).is_ok());
}

#[test]
fn jti_is_16_to_64_visible_ascii_characters() {
    let key = DeviceKey::new(15);
    let htu = htu();
    for (jti, holds) in [
        ("a".repeat(15), false),
        ("a".repeat(16), true),
        ("~!#$%&'()*+,-./:".to_string(), true),
        ("a".repeat(64), true),
        ("a".repeat(65), false),
        (format!("{} ", "a".repeat(16)), false),
        (format!("{}\t", "a".repeat(16)), false),
        (format!("{}é", "a".repeat(15)), false),
        (format!("{}\u{7f}", "a".repeat(16)), false),
        (String::new(), false),
    ] {
        let proof = key.sign(&key.header(), &claims("GET", &htu, NOW, &jti, None));
        let result = check(&proof, None, NOW);
        assert_eq!(result.is_ok(), holds, "{jti:?}");
        if !holds {
            assert_eq!(result.unwrap_err(), DpopError::Claims);
        }
    }
}

#[test]
fn ath_must_match_the_access_token() {
    let key = DeviceKey::new(16);
    let htu = htu();
    let mine = token(b"dpop ath mine");
    let theirs = token(b"dpop ath theirs");

    // The right token passes; the hash is over the 43 ASCII characters.
    let proof = key.proof("GET", &htu, NOW, Some(&mine));
    assert!(check(&proof, Some(&mine), NOW).is_ok());
    let expected = support::dpop::ath(&mine);
    assert_eq!(expected, b64(&mine.ath()));

    // Another token's hash, no `ath` with a token, `ath` without one.
    let other = key.proof("GET", &htu, NOW, Some(&theirs));
    assert_eq!(
        check(&other, Some(&mine), NOW).unwrap_err(),
        DpopError::Claims
    );
    let without = key.proof("GET", &htu, NOW, None);
    assert_eq!(
        check(&without, Some(&mine), NOW).unwrap_err(),
        DpopError::Claims
    );
    assert_eq!(check(&proof, None, NOW).unwrap_err(), DpopError::Claims);

    // The hash of the raw bytes, a padded or non-canonical hash, an empty one.
    let raw = b64(&Sha256::digest(mine.hash().0));
    let last = expected.chars().last().expect("a character");
    let alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let index = alphabet.find(last).expect("in the alphabet");
    let spare = format!(
        "{}{}",
        &expected[..42],
        alphabet.chars().nth(index ^ 1).expect("a neighbour")
    );
    for ath in [
        raw,
        format!("{expected}="),
        spare,
        String::new(),
        expected.to_uppercase(),
    ] {
        if ath == expected {
            continue;
        }
        let mut c = claims("GET", &htu, NOW, &fresh_jti(), None);
        c["ath"] = json!(ath);
        let proof = key.sign(&key.header(), &c);
        assert_eq!(
            check(&proof, Some(&mine), NOW).unwrap_err(),
            DpopError::Claims,
            "{ath}"
        );
    }
}

// ------------------------------------------------------------ the thumbprint

fn wire_fixture(name: &str) -> Value {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/wire")
        .join(name);
    serde_json::from_slice(&std::fs::read(path).expect("a fixture")).expect("json")
}

#[test]
fn jkt_is_the_rfc7638_thumbprint() {
    // The key of RFC 9449 § 4.1 and the thumbprint § 6.1 prints for it.
    let fixture = wire_fixture("dpop_jwk.json");
    let jwk = proof::PublicJwk {
        kty: fixture["jwk"]["kty"].as_str().expect("kty").to_string(),
        crv: fixture["jwk"]["crv"].as_str().expect("crv").to_string(),
        x: fixture["jwk"]["x"].as_str().expect("x").to_string(),
        y: fixture["jwk"]["y"].as_str().expect("y").to_string(),
    };
    assert_eq!(
        b64(&proof::jkt(&jwk)),
        fixture["jkt"].as_str().expect("jkt")
    );
    assert_eq!(
        fixture["jkt"].as_str().expect("jkt"),
        "0ZcOCORZNYy-DWpqq30jZyJGHTN0d2HglBV3uiguA4I"
    );

    // The thumbprint of a checked proof is its key's, whatever the order of
    // the members in the header.
    let key = DeviceKey::new(17);
    assert_eq!(verified(&good(&key)).jkt(), &key.jkt());
    let reordered = format!(
        r#"{{"jwk":{{"y":"{}","x":"{}","crv":"P-256","kty":"EC"}},"alg":"ES256","typ":"dpop+jwt"}}"#,
        key.y, key.x
    );
    assert_eq!(
        verified(&with_header_text(&key, &reordered)).jkt(),
        &key.jkt()
    );
    assert_ne!(verified(&good(&DeviceKey::new(18))).jkt(), &key.jkt());
}

// ------------------------------------------------------------- the library

/// The SHA-256 of a fixture file, against its manifest.
fn checked_fixture(dir: &Path, name: &str) -> Vec<u8> {
    let manifest: Value =
        serde_json::from_slice(&std::fs::read(dir.join("MANIFEST.json")).expect("the manifest"))
            .expect("json");
    let entry = manifest["files"]
        .as_array()
        .expect("files")
        .iter()
        .find(|f| f["name"] == name)
        .expect("listed in the manifest");
    let bytes = std::fs::read(dir.join(name)).expect("the fixture");
    let digest: String = Sha256::digest(&bytes)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    assert_eq!(digest, entry["sha256"].as_str().expect("sha256"), "{name}");
    bytes
}

#[test]
fn wycheproof_ecdsa_p256_sha256_vectors_pass() {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/wycheproof");
    checked_fixture(&dir, "LICENSE.txt");
    let file: Value = serde_json::from_slice(&checked_fixture(
        &dir,
        "ecdsa_secp256r1_sha256_p1363_test.json",
    ))
    .expect("json");
    assert_eq!(file["algorithm"], "ECDSA");
    assert_eq!(file["schema"], "ecdsa_p1363_verify_schema_v1.json");

    let (mut valid, mut invalid) = (0usize, 0usize);
    for group in file["testGroups"].as_array().expect("groups") {
        assert_eq!(group["type"], "EcdsaP1363Verify");
        assert_eq!(group["sha"], "SHA-256");
        assert_eq!(group["publicKey"]["curve"], "secp256r1");
        let point = unhex(group["publicKey"]["uncompressed"].as_str().expect("a key"));
        assert_eq!((point.len(), point[0]), (65, 0x04));
        let (x, y) = (b64(&point[1..33]), b64(&point[33..]));
        let key = jsonwebtoken::DecodingKey::from_ec_components(&x, &y).expect("a key");

        for case in group["tests"].as_array().expect("tests") {
            let id = &case["tcId"];
            let message = unhex(case["msg"].as_str().expect("msg"));
            let signature = b64(&unhex(case["sig"].as_str().expect("sig")));
            let library = jsonwebtoken::crypto::verify(
                &signature,
                &message,
                &key,
                jsonwebtoken::Algorithm::ES256,
            );
            let ours = dpop::signature_holds(&signature, &message, &x, &y);
            match case["result"].as_str().expect("result") {
                "valid" => {
                    assert!(matches!(library, Ok(true)), "tcId {id}: {library:?}");
                    assert!(ours, "tcId {id}");
                    valid += 1;
                }
                "invalid" => {
                    assert!(!matches!(library, Ok(true)), "tcId {id}");
                    assert!(!ours, "tcId {id}");
                    invalid += 1;
                }
                other => panic!("tcId {id}: result {other} is not expected in this file"),
            }
        }
    }
    assert_eq!(
        valid + invalid,
        file["numberOfTests"].as_u64().expect("count") as usize
    );
    assert_eq!((valid, invalid), (173, 89));
}

#[test]
fn the_jose_library_has_its_one_backend() {
    assert!(dpop::backend_ready());
}

// ------------------------------------------------------------ the jti cache

#[tokio::test]
async fn verify_records_nothing_and_record_is_the_only_writer() {
    let app = TestApp::new().await;
    let auth = DeviceAuth::from_ref(&app.state);
    assert!(auth.replay().is_empty());

    let key = DeviceKey::new(19);
    let proof = good(&key);
    for _ in 0..5 {
        assert!(
            check(&proof, None, NOW).is_ok(),
            "the same proof checks again"
        );
    }
    assert_eq!(auth.replay().len(), 0, "a check records nothing");

    let first = verified(&proof);
    auth.replay().record(&first, 1, NOW).expect("recorded");
    assert_eq!(auth.replay().len(), 1);
    // The proof still checks (the check has no state), and only `record`
    // refuses it now.
    let again = verified(&proof);
    assert_eq!(auth.replay().record(&again, 1, NOW), Err(DpopError::Replay));
    assert_eq!(auth.replay().len(), 1);
    // A clone of the handle shares the cache.
    assert_eq!(auth.clone().replay().len(), 1);
}

#[test]
fn replayed_jti_for_the_same_key_is_refused_within_five_minutes() {
    let cache = JtiCache::new(100, 100, 100);
    let key = DeviceKey::new(20);
    let proof = good(&key);
    cache.record(&verified(&proof), 1, NOW).expect("first use");
    for later in [0, 1, 60, 120, JTI_TTL_SECS - 1] {
        assert_eq!(
            cache.record(&verified(&proof), 1, NOW + later),
            Err(DpopError::Replay),
            "{later}"
        );
    }
    // From another account too: the key and the jti decide.
    assert_eq!(
        cache.record(&verified(&proof), 2, NOW + 1),
        Err(DpopError::Replay)
    );
    // After the time the proof could pass the clock check at all, its place
    // is free.
    assert_eq!(
        cache.record(&verified(&proof), 1, NOW + JTI_TTL_SECS),
        Ok(())
    );
    // The refusal is the one answer.
    assert_eq!(
        ApiError::from(DpopError::Replay),
        ApiError::coded("dpop_invalid")
    );
}

#[test]
fn the_same_jti_from_another_key_is_not_a_replay() {
    let cache = JtiCache::new(100, 100, 100);
    let jti = fresh_jti();
    let htu = htu();
    let one = DeviceKey::new(21);
    let two = DeviceKey::new(22);
    let a = one.sign(&one.header(), &claims("GET", &htu, NOW, &jti, None));
    let b = two.sign(&two.header(), &claims("GET", &htu, NOW, &jti, None));
    cache.record(&verified(&a), 1, NOW).expect("key one");
    cache.record(&verified(&b), 1, NOW).expect("key two");
    assert_eq!(cache.len(), 2);
    assert_eq!(cache.record(&verified(&a), 1, NOW), Err(DpopError::Replay));
    assert_eq!(cache.record(&verified(&b), 1, NOW), Err(DpopError::Replay));
}

#[test]
fn a_full_jti_cache_refuses_with_busy_and_never_evicts() {
    let cache = JtiCache::new(3, 10, 10);
    let proofs: Vec<String> = (0..3).map(|n| good(&DeviceKey::new(30 + n))).collect();
    for (n, proof) in proofs.iter().enumerate() {
        let user = i64::try_from(n).expect("small");
        cache.record(&verified(proof), user, NOW).expect("room");
    }
    // Full: a new proof of a new key and a new account is refused.
    let late = good(&DeviceKey::new(40));
    assert_eq!(
        cache.record(&verified(&late), 9, NOW + 10),
        Err(DpopError::Full)
    );
    assert_eq!(cache.len(), 3);
    // Nothing was dropped to make room: each of the three is still a replay.
    for proof in &proofs {
        assert_eq!(
            cache.record(&verified(proof), 0, NOW + 10),
            Err(DpopError::Replay)
        );
    }
    // The answer is `503 busy` with a wait, never `dpop_invalid`.
    let res = ApiError::from(DpopError::Full).into_response();
    assert_eq!(res.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(res.headers()[header::RETRY_AFTER], "30");
}

#[test]
fn expired_jti_entries_free_their_place() {
    let cache = JtiCache::new(2, 2, 2);
    let key = DeviceKey::new(41);
    cache.record(&verified(&good(&key)), 1, NOW).expect("one");
    cache
        .record(&verified(&good(&key)), 1, NOW + 100)
        .expect("two");
    assert_eq!(
        cache.record(&verified(&good(&key)), 1, NOW + 200),
        Err(DpopError::KeyBusy)
    );
    // The first is out at NOW + 300: its place, for the key, the account and
    // the cache, is free again; the second is not out yet.
    cache
        .record(&verified(&good(&key)), 1, NOW + JTI_TTL_SECS)
        .expect("the first's place");
    assert_eq!(cache.len(), 2);
    assert_eq!(
        cache.record(&verified(&good(&key)), 1, NOW + JTI_TTL_SECS),
        Err(DpopError::KeyBusy)
    );
    // Long after, everything is out.
    let much_later = NOW + 10 * JTI_TTL_SECS;
    cache
        .record(&verified(&good(&key)), 1, much_later)
        .expect("room");
    assert_eq!(cache.len(), 1);
}

#[test]
fn the_per_key_cap_refuses_that_key_only() {
    let cache = JtiCache::new(100, 2, 100);
    let busy = DeviceKey::new(42);
    let calm = DeviceKey::new(43);
    cache.record(&verified(&good(&busy)), 1, NOW).expect("one");
    cache.record(&verified(&good(&busy)), 1, NOW).expect("two");
    assert_eq!(
        cache.record(&verified(&good(&busy)), 1, NOW),
        Err(DpopError::KeyBusy)
    );
    // Another key of the same account still gets in.
    cache
        .record(&verified(&good(&calm)), 1, NOW)
        .expect("another key");
    let res = ApiError::from(DpopError::KeyBusy).into_response();
    assert_eq!(res.status(), StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(res.headers()[header::RETRY_AFTER], "60");
}

#[test]
fn the_per_user_cap_refuses_that_user_only() {
    let cache = JtiCache::new(100, 100, 3);
    for n in 0..3 {
        cache
            .record(&verified(&good(&DeviceKey::new(50 + n))), 7, NOW)
            .expect("room");
    }
    // A fourth key of the same account: refused.
    let fourth = good(&DeviceKey::new(53));
    assert_eq!(
        cache.record(&verified(&fourth), 7, NOW),
        Err(DpopError::UserBusy)
    );
    // The same proof for another account gets in.
    cache
        .record(&verified(&fourth), 8, NOW)
        .expect("another account");
    let res = ApiError::from(DpopError::UserBusy).into_response();
    assert_eq!(res.status(), StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(res.headers()[header::RETRY_AFTER], "60");
}

#[test]
fn debug_of_the_proof_types_hides_the_key_and_the_jti() {
    let key = DeviceKey::new(54);
    let jti = fresh_jti();
    let proof = key.sign(&key.header(), &claims("GET", &htu(), NOW, &jti, None));
    let parts = proof::split(&proof).expect("parts");
    let claims = proof::claims(&parts).expect("claims");
    let checked = verified(&proof);
    let cache = JtiCache::new(10, 10, 10);
    cache.record(&checked, 1, NOW).expect("recorded");
    for shown in [
        format!("{parts:?}"),
        format!("{:?}", parts.header),
        format!("{:?}", parts.header.jwk),
        format!("{claims:?}"),
        format!("{checked:?}"),
        format!("{cache:?}"),
    ] {
        for secret in [&key.x, &key.y, &jti, &proof, &htu()] {
            assert!(!shown.contains(secret.as_str()), "{shown}");
        }
    }
}

// ---------------------------------------------------------------- the logs

#[tokio::test]
async fn dpop_header_never_reaches_the_logs() {
    let (log, _guard) = capture_log();
    const CANARY: &str = "CanaryDpopProof7f3a";
    let key = DeviceKey::new(55);
    let htu = htu();
    let jti = format!("{CANARY}-jti");
    let good = key.sign(&key.header(), &claims("GET", &htu, NOW, &jti, None));
    let mut header = key.header();
    header["kid"] = json!(CANARY);
    let bad_header = with_header(&key, &header);
    let mut c = claims("GET", &format!("{htu}?{CANARY}"), NOW, &jti, None);
    c["nonce"] = json!(CANARY);
    let bad_claims = key.sign(&key.header(), &c);
    let late = key.sign(&key.header(), &claims("GET", &htu, NOW + 3_600, &jti, None));
    let junk = format!("{CANARY}.{CANARY}.{CANARY}");
    let proofs = [good.clone(), bad_header, bad_claims, late, junk];

    // The check and every one of its refusals, and the answers they give.
    let cache = JtiCache::new(1, 1, 1);
    for proof in &proofs {
        if let Err(e) = check(proof, None, NOW) {
            let _ = ApiError::from(e).into_response();
        }
    }
    let checked = verified(&good);
    cache.record(&checked, 1, NOW).expect("recorded");
    for e in [
        cache.record(&checked, 1, NOW),
        cache.record(&verified(&good), 2, NOW),
    ] {
        let _ = ApiError::from(e.expect_err("refused")).into_response();
    }

    // The proofs as headers of requests to both listeners, with a token in
    // `Authorization` as a device would send it.
    let app = TestApp::new().await;
    let token = format!("{CANARY}AccessToken0123456789abcdefghijk");
    for proof in &proofs {
        for (which, path) in [
            (Which::Vault, PATH),
            (Which::Vault, "/api/auth/token/refresh"),
            (Which::Admin, "/api/auth/session"),
        ] {
            let res = app
                .call_raw(
                    which,
                    Req::get(path)
                        .header("dpop", proof)
                        .header("authorization", &format!("DPoP {token}"))
                        .header("ferret-protocol", "1")
                        .build(),
                )
                .await;
            assert!(!res.text().contains(CANARY), "{path}: {}", res.text());
            for value in res.headers.values() {
                assert!(!value.to_str().unwrap_or("").contains(CANARY), "{path}");
            }
        }
    }

    let text = log.text();
    assert!(!text.contains(CANARY), "{text}");
    assert!(!text.contains(&key.x) && !text.contains(&key.y), "{text}");
}
