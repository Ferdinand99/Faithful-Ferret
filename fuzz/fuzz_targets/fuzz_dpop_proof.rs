//! The server's own reading of a DPoP proof: the size and the three segments of
//! the compact JWS, the strict decoding of its header and claims, the key
//! thumbprint and the checks of the claims. The signature is the JOSE
//! library's and is not here. The file that is fuzzed is the server's own
//! `auth/dpop/proof.rs`, taken in as it is (it uses no other file of the
//! server), so the target runs the code of the release build. The first byte
//! picks the shape of the input.
//!
//! * 0: the bytes are the text of a proof.
//! * 1: a header, a claims object and a signature, split at NUL bytes, are
//!   written in base64url and joined to a proof (an empty signature is a fixed
//!   one of 64 bytes), so the fuzzer changes the JSON and not its encoding.
//! * 2: the claims alone, with the request they are checked against: eight
//!   bytes of time, a flag byte (bit 0: the request has an access token; bit 1:
//!   check against the method and the URL of the claims; bit 2: put the time
//!   within a few seconds of `iat`), then the method, the URL and the claims
//!   object, split at NUL bytes.
//!
//! The properties:
//!
//! * `split` never panics and never accepts a proof of more than 4 096 bytes.
//! * What `split` accepts has every segment in canonical base64url, a header
//!   with exactly the members `typ`, `alg` and `jwk` and a `jwk` with exactly
//!   `kty`, `crv`, `x` and `y` (so no private member), and the one accepted
//!   words and sizes; the signing input and the signature segment are the
//!   proof cut at its last dot.
//! * `jkt` gives the same value twice, equals the SHA-256 of the RFC 7638
//!   string of the four members, and does not change when the same key is
//!   written with its members in another order.
//! * What `claims` accepts has exactly the members `jti`, `htm`, `htu`, `iat`
//!   and, if present, `ath`, with a whole number for `iat`.
//! * `check_claims` accepts a proof if and only if `jti` is 16 to 64 visible
//!   ASCII bytes, `htm` and `htu` are equal to the request's, `ath` is the
//!   canonical base64url of the access token's hash exactly when the request
//!   has a token, and `iat` is at most 60 seconds from the time. It never
//!   accepts an `iat` outside the window or an `htu` that is not equal.
#![no_main]

#[path = "../../crates/ferret-server/src/auth/dpop/proof.rs"]
#[allow(dead_code)]
mod proof;

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use libfuzzer_sys::fuzz_target;
use proof::{
    DpopClaims, DpopHeader, IAT_WINDOW_SECS, MAX_PROOF_LEN, Parts, ProofError, PublicJwk,
    check_claims, claims, jkt, signature_b64, signing_input, split,
};
use serde_json::Value;
use sha2::{Digest as _, Sha256};

/// The signature of a proof that has none in the input: 64 bytes, which `split`
/// takes for a signature (the signature itself is never checked here).
const FIXED_SIGNATURE: [u8; 64] = [0x5a; 64];

/// The access token hash a request with a token is checked against.
const TOKEN_HASH: [u8; 32] = [0x22; 32];

fuzz_target!(|data: &[u8]| {
    let Some((&mode, body)) = data.split_first() else {
        return;
    };
    match mode % 3 {
        0 => {
            if let Ok(text) = std::str::from_utf8(body) {
                proof_text(text);
            }
        }
        1 => assembled(body),
        _ => claims_alone(body),
    }
});

// ------------------------------------------------------------ the proof

/// Runs `split` on `text` and, if it accepts it, everything that follows.
fn proof_text(text: &str) {
    let result = split(text);
    if text.len() > MAX_PROOF_LEN {
        assert_eq!(
            result.err(),
            Some(ProofError::TooLong),
            "a proof over the limit was not refused first"
        );
        return;
    }
    let Ok(parts) = result else {
        return;
    };
    assert!(
        text.len() <= MAX_PROOF_LEN,
        "a proof over 4 096 bytes was accepted"
    );
    header_shape(&parts);
    thumbprint(&parts);
    if let Ok(read) = claims(&parts) {
        claims_shape(&parts, &read);
        every_check(&read);
    }
}

/// A header, claims and a signature joined to a proof.
fn assembled(body: &[u8]) {
    let mut pieces = body.splitn(3, |b| *b == 0);
    let header = pieces.next().unwrap_or_default();
    let claims_json = pieces.next().unwrap_or_default();
    let signature = match pieces.next() {
        Some(s) if !s.is_empty() => s,
        _ => &FIXED_SIGNATURE,
    };
    let text = format!(
        "{}.{}.{}",
        URL_SAFE_NO_PAD.encode(header),
        URL_SAFE_NO_PAD.encode(claims_json),
        URL_SAFE_NO_PAD.encode(signature)
    );
    proof_text(&text);
}

/// What a header that `split` accepted is.
fn header_shape(parts: &Parts<'_>) {
    let segments: Vec<&str> = parts.compact.split('.').collect();
    assert_eq!(segments.len(), 3, "an accepted proof has three segments");
    for segment in &segments {
        assert!(
            !segment.is_empty(),
            "an accepted proof has an empty segment"
        );
        let bytes = URL_SAFE_NO_PAD
            .decode(segment)
            .expect("an accepted segment decodes");
        assert_eq!(
            URL_SAFE_NO_PAD.encode(bytes),
            *segment,
            "an accepted segment is canonical"
        );
    }
    assert_eq!(
        URL_SAFE_NO_PAD.decode(segments[2]).map(|s| s.len()).ok(),
        Some(64),
        "the signature is 64 bytes"
    );
    assert_eq!(
        signing_input(parts),
        format!("{}.{}", segments[0], segments[1]),
        "the signing input is the first two segments"
    );
    assert_eq!(
        signature_b64(parts),
        segments[2],
        "the signature segment is the last one"
    );

    let header_bytes = URL_SAFE_NO_PAD.decode(segments[0]).expect("checked above");
    let value: Value = serde_json::from_slice(&header_bytes).expect("an accepted header is JSON");
    let object = value.as_object().expect("an accepted header is an object");
    assert_eq!(
        object.len(),
        3,
        "an accepted header has exactly three members"
    );
    assert_eq!(object.get("typ").and_then(Value::as_str), Some("dpop+jwt"));
    assert_eq!(object.get("alg").and_then(Value::as_str), Some("ES256"));
    let jwk = object
        .get("jwk")
        .and_then(Value::as_object)
        .expect("an accepted header has a jwk object");
    assert_eq!(jwk.len(), 4, "an accepted jwk has exactly four members");
    for (name, want) in [("kty", "EC"), ("crv", "P-256")] {
        assert_eq!(jwk.get(name).and_then(Value::as_str), Some(want));
    }
    for name in ["x", "y"] {
        let coordinate = jwk
            .get(name)
            .and_then(Value::as_str)
            .expect("an accepted jwk has x and y");
        assert_eq!(coordinate.len(), 43);
        let bytes = URL_SAFE_NO_PAD
            .decode(coordinate)
            .expect("a coordinate decodes");
        assert_eq!(bytes.len(), 32);
        assert_eq!(
            URL_SAFE_NO_PAD.encode(bytes),
            coordinate,
            "a coordinate is canonical"
        );
    }
    // The struct holds what the object says.
    let DpopHeader { typ, alg, jwk: key } = &parts.header;
    assert_eq!((typ.as_str(), alg.as_str()), ("dpop+jwt", "ES256"));
    assert_eq!(Some(key.x.as_str()), jwk.get("x").and_then(Value::as_str));
    assert_eq!(Some(key.y.as_str()), jwk.get("y").and_then(Value::as_str));
}

/// The thumbprint of the key of an accepted header.
fn thumbprint(parts: &Parts<'_>) {
    let key: &PublicJwk = &parts.header.jwk;
    let first = jkt(key);
    assert_eq!(first, jkt(key), "jkt is not deterministic");
    let rfc7638 = format!(
        r#"{{"crv":"P-256","kty":"EC","x":"{}","y":"{}"}}"#,
        key.x, key.y
    );
    let expected: [u8; 32] = Sha256::digest(rfc7638.as_bytes()).into();
    assert_eq!(first, expected, "jkt is not the RFC 7638 thumbprint");

    // The same key and the same claims and signature, with the members in
    // another order and no white space: one key has one thumbprint.
    let segments: Vec<&str> = parts.compact.split('.').collect();
    let reordered = format!(
        r#"{{"jwk":{{"y":"{}","x":"{}","crv":"P-256","kty":"EC"}},"alg":"ES256","typ":"dpop+jwt"}}"#,
        key.y, key.x
    );
    let again = format!(
        "{}.{}.{}",
        URL_SAFE_NO_PAD.encode(reordered),
        segments[1],
        segments[2]
    );
    let other = split(&again).expect("the same key in another member order is accepted");
    assert_eq!(
        jkt(&other.header.jwk),
        first,
        "the thumbprint depends on the member order"
    );
}

// ------------------------------------------------------------ the claims

/// What claims that `claims` accepted are.
fn claims_shape(parts: &Parts<'_>, read: &DpopClaims) {
    let segment = parts
        .compact
        .split('.')
        .nth(1)
        .expect("an accepted proof has claims");
    let bytes = URL_SAFE_NO_PAD
        .decode(segment)
        .expect("the claims segment decodes");
    let value: Value = serde_json::from_slice(&bytes).expect("accepted claims are JSON");
    let object = value.as_object().expect("accepted claims are an object");
    for name in object.keys() {
        assert!(
            ["jti", "htm", "htu", "iat", "ath"].contains(&name.as_str()),
            "accepted claims have an unknown member"
        );
    }
    assert_eq!(
        object.len(),
        4 + usize::from(read.ath.is_some()),
        "accepted claims have the wrong members"
    );
    assert_eq!(
        object.get("jti").and_then(Value::as_str),
        Some(read.jti.as_str())
    );
    assert_eq!(
        object.get("htm").and_then(Value::as_str),
        Some(read.htm.as_str())
    );
    assert_eq!(
        object.get("htu").and_then(Value::as_str),
        Some(read.htu.as_str())
    );
    assert_eq!(
        object.get("iat").and_then(Value::as_i64),
        Some(read.iat),
        "iat is not a whole number"
    );
    assert_eq!(
        object.get("ath").and_then(Value::as_str),
        read.ath.as_deref()
    );
}

/// The oracle of `check_claims`: spelled out from the rules, not from the code.
fn expected_verdict(
    c: &DpopClaims,
    method: &str,
    htu: &str,
    token: Option<&[u8; 32]>,
    now: i64,
) -> (bool, bool) {
    let jti = (16..=64).contains(&c.jti.len()) && c.jti.bytes().all(|b| (0x21..=0x7e).contains(&b));
    let ath = match (token, c.ath.as_deref()) {
        (None, None) => true,
        (Some(hash), Some(text)) => URL_SAFE_NO_PAD.encode(hash) == text,
        _ => false,
    };
    let in_window = (i128::from(c.iat) - i128::from(now)).abs() <= i128::from(IAT_WINDOW_SECS);
    let rest = jti && c.htm == method && c.htu == htu && ath;
    (rest && in_window, rest)
}

/// Checks `check_claims` against the oracle for one request and one time.
fn one_check(c: &DpopClaims, method: &str, htu: &str, token: Option<&[u8; 32]>, now: i64) {
    let got = check_claims(c, method, htu, token, now);
    let (accept, rest) = expected_verdict(c, method, htu, token, now);
    assert_eq!(
        got.is_ok(),
        accept,
        "check_claims disagrees with the rules (iat {}, now {now})",
        c.iat
    );
    if rest && !accept {
        assert_eq!(
            got,
            Err(ProofError::Clock),
            "a time outside the window is a clock error"
        );
    }
    if !rest {
        assert_ne!(
            got,
            Err(ProofError::Clock),
            "a claim that is wrong is not a clock error"
        );
    }
    if c.htu != htu {
        assert!(got.is_err(), "a different htu was accepted");
    }
}

/// The requests and the times that claims are checked against: the request the
/// claims name, with and without the token, a request that differs in one
/// place, and the edges of the window.
fn every_check(c: &DpopClaims) {
    let token = c.ath.as_deref().and_then(|text| {
        let bytes = URL_SAFE_NO_PAD.decode(text).ok()?;
        <[u8; 32]>::try_from(bytes.as_slice()).ok()
    });
    let mut flipped = token;
    if let Some(hash) = flipped.as_mut() {
        hash[0] ^= 1;
    }
    let longer = format!("{}/", c.htu);
    let other_method = if c.htm == "GET" { "POST" } else { "GET" };
    let times = [
        c.iat,
        c.iat.saturating_sub(IAT_WINDOW_SECS),
        c.iat.saturating_add(IAT_WINDOW_SECS),
        c.iat.saturating_sub(IAT_WINDOW_SECS + 1),
        c.iat.saturating_add(IAT_WINDOW_SECS + 1),
        0,
        i64::MIN,
        i64::MAX,
    ];
    for now in times {
        for (method, htu) in [
            (c.htm.as_str(), c.htu.as_str()),
            (c.htm.as_str(), longer.as_str()),
            (other_method, c.htu.as_str()),
        ] {
            one_check(c, method, htu, token.as_ref(), now);
            one_check(c, method, htu, None, now);
            one_check(c, method, htu, Some(&TOKEN_HASH), now);
            one_check(c, method, htu, flipped.as_ref(), now);
        }
    }
}

/// A proof of fixed shape around `claims_json`, so that `claims` reads it.
fn claims_alone(body: &[u8]) {
    let Some((head, rest)) = body.split_at_checked(9) else {
        return;
    };
    let mut time_bytes = [0u8; 8];
    time_bytes.copy_from_slice(&head[..8]);
    let flags = head[8];
    let mut pieces = rest.splitn(3, |b| *b == 0);
    let method = std::str::from_utf8(pieces.next().unwrap_or_default());
    let htu = std::str::from_utf8(pieces.next().unwrap_or_default());
    let claims_json = pieces.next().unwrap_or_default();

    let header = DpopHeader {
        typ: "dpop+jwt".to_owned(),
        alg: "ES256".to_owned(),
        jwk: PublicJwk {
            kty: "EC".to_owned(),
            crv: "P-256".to_owned(),
            x: String::new(),
            y: String::new(),
        },
    };
    let compact = format!(
        "e30.{}.{}",
        URL_SAFE_NO_PAD.encode(claims_json),
        URL_SAFE_NO_PAD.encode(FIXED_SIGNATURE)
    );
    let parts = Parts {
        header,
        compact: &compact,
    };
    let Ok(read) = claims(&parts) else {
        return;
    };
    claims_shape(&parts, &read);

    let mut now = i64::from_be_bytes(time_bytes);
    if flags & 4 != 0 {
        now = read
            .iat
            .saturating_add(i64::from(i8::from_be_bytes([time_bytes[0]])));
    }
    let token = (flags & 1 != 0).then_some(&TOKEN_HASH);
    let (method, htu) = if flags & 2 != 0 {
        (read.htm.as_str(), read.htu.as_str())
    } else {
        let (Ok(method), Ok(htu)) = (method, htu) else {
            return;
        };
        (method, htu)
    };
    one_check(&read, method, htu, token, now);
    every_check(&read);
}
