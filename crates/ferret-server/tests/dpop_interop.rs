//! The web client's DPoP proofs against the server's check: proofs made by
//! `web/src/auth/dpop.mjs` with a key from `web/src/auth/deviceKey.mjs`
//! (tests/fixtures/dpop/js_proofs.json, written by generate.mjs there), and
//! the example proofs of RFC 9449, all through `dpop::verify` at a fixed time.
//! Two implementations (WebCrypto in the client, the JOSE library over
//! aws-lc-rs in the server) agree on every byte that counts.
//!
//! RFC 9449 § 4.2, § 4.3; RFC 7638 § 3; Spec: Fase 1 § 7.6.

mod support;

use std::path::PathBuf;

use axum::http::Method;
use ferret_server::auth::dpop::{self, DpopError, Expect, JtiCache, VerifiedProof};
use ferret_server::auth::tokens::{DeviceAuth, Htu};
use ferret_server::ids::TokenSecret;
use serde_json::Value;
use support::dpop::{DeviceKey, b64, headers_with, segments, vault_htu};
use support::{START, VAULT_URL};

/// The server time the fixture's proofs were made at.
const NOW: i64 = START as i64;

fn fixture(dir: &str, name: &str) -> Value {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(dir)
        .join(name);
    serde_json::from_slice(&std::fs::read(path).expect("a fixture")).expect("json")
}

fn js() -> Value {
    fixture("dpop", "js_proofs.json")
}

fn text<'a>(value: &'a Value, key: &str) -> &'a str {
    value[key]
        .as_str()
        .unwrap_or_else(|| panic!("{key} is a string"))
}

fn method(name: &str) -> Method {
    Method::from_bytes(name.as_bytes()).expect("a method")
}

/// Runs the server's check on `proof` for `method` and `htu`, with `access`.
fn check(
    proof: &str,
    method: &Method,
    htu: &Htu,
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

/// The access token of the fixture, as the server reads it.
fn access_token(file: &Value) -> TokenSecret {
    TokenSecret::from_wire(text(file, "access_token")).expect("a token")
}

/// The test key of the fixture: the scalar of 32 bytes of 0x11.
fn test_key() -> DeviceKey {
    DeviceKey::new(0x11)
}

#[test]
fn js_proofs_verify_in_rust() {
    let file = js();
    assert_eq!(file["format"], "ferret-dpop-js-proofs/1");
    assert_eq!(file["now"].as_i64(), Some(NOW));
    assert_eq!(text(&file, "vault_url"), VAULT_URL);
    let token = access_token(&file);
    let key = test_key();
    let jkt = key.jkt();
    // The thumbprint the client computed is the server's for the same key.
    assert_eq!(text(&file["key"], "jkt"), b64(&jkt));

    let proofs = file["proofs"].as_array().expect("proofs");
    assert_eq!(proofs.len(), 5);
    let cache = JtiCache::new(64, 64, 64);
    for entry in proofs {
        let name = text(entry, "name");
        let proof = text(entry, "proof");
        let access = entry["token"].as_bool().expect("token").then_some(&token);
        let verified = check(
            proof,
            &method(text(entry, "method")),
            &vault_htu(text(entry, "path")),
            access,
            NOW,
        )
        .unwrap_or_else(|e| panic!("{name}: the server accepts the client's proof ({e:?})"));
        assert_eq!(verified.jkt(), &jkt, "{name}");
        assert_eq!(verified.iat(), NOW, "{name}: iat is the server's time");
        // 16 random bytes as base64url.
        assert_eq!(verified.jti().len(), 22, "{name}");
        // Each proof has its own `jti`: recording one never refuses another.
        cache.record(&verified, 1, NOW).expect("a new jti");
        assert!(matches!(
            cache.record(&verified, 1, NOW),
            Err(DpopError::Replay)
        ));

        // The header is exactly what the server's strict reader takes.
        let (header, _, signature) = segments(proof);
        let header = String::from_utf8(
            base64::Engine::decode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, header)
                .expect("base64url"),
        )
        .expect("utf-8");
        assert_eq!(
            header,
            format!(
                r#"{{"typ":"dpop+jwt","alg":"ES256","jwk":{{"kty":"EC","crv":"P-256","x":"{}","y":"{}"}}}}"#,
                key.x, key.y
            ),
            "{name}"
        );
        assert_eq!(signature.len(), 86, "{name}: r ‖ s, 64 bytes");
    }
}

#[test]
fn js_proofs_are_refused_for_another_request() {
    let file = js();
    let token = access_token(&file);
    let other = TokenSecret::from_wire(&b64(&[0x33; 32])).expect("a token");
    for entry in file["proofs"].as_array().expect("proofs") {
        let name = text(entry, "name");
        let proof = text(entry, "proof");
        let good_method = method(text(entry, "method"));
        let path = text(entry, "path");
        let with_token = entry["token"].as_bool().expect("token");
        let access = with_token.then_some(&token);
        let refused = |m: &Method, htu: &Htu, access: Option<&TokenSecret>, now: i64| {
            check(proof, m, htu, access, now).is_err()
        };
        let other_method = if good_method == Method::GET {
            Method::POST
        } else {
            Method::GET
        };
        assert!(
            refused(&other_method, &vault_htu(path), access, NOW),
            "{name}: htm"
        );
        assert!(
            refused(&good_method, &vault_htu("/api/sync/other"), access, NOW),
            "{name}: htu"
        );
        assert!(
            refused(&good_method, &vault_htu(path), access, NOW + 61),
            "{name}: iat, late"
        );
        assert!(
            refused(&good_method, &vault_htu(path), access, NOW - 61),
            "{name}: iat, early"
        );
        assert!(
            !refused(&good_method, &vault_htu(path), access, NOW + 60),
            "{name}: 60 seconds is still within the window"
        );
        if with_token {
            assert!(
                refused(&good_method, &vault_htu(path), None, NOW),
                "{name}: ath without a token"
            );
            assert!(
                refused(&good_method, &vault_htu(path), Some(&other), NOW),
                "{name}: ath of another token"
            );
        } else {
            assert!(
                refused(&good_method, &vault_htu(path), Some(&token), NOW),
                "{name}: a token without ath"
            );
        }
    }
}

#[test]
fn the_public_jwk_has_exactly_four_members_from_a_real_export() {
    let file = js();
    let key = &file["key"];
    // The export the client copied from had `ext` and `key_ops` as well
    // (WebCrypto adds them), and the copy has only the four members.
    let exported: Vec<&str> = key["exported_members"]
        .as_array()
        .expect("members")
        .iter()
        .map(|m| m.as_str().expect("a name"))
        .collect();
    assert_eq!(exported, ["crv", "ext", "key_ops", "kty", "x", "y"]);
    let jwk = key["jwk"].as_object().expect("a jwk");
    let members: Vec<&str> = jwk.keys().map(String::as_str).collect();
    let mut sorted = members.clone();
    sorted.sort_unstable();
    assert_eq!(sorted, ["crv", "kty", "x", "y"]);
    assert_eq!(key["jwk"], test_key().jwk());
    // And every proof carries that same JWK in its header.
    for entry in file["proofs"].as_array().expect("proofs") {
        let (header, _, _) = segments(text(entry, "proof"));
        let header: Value = serde_json::from_slice(
            &base64::Engine::decode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, header)
                .expect("base64url"),
        )
        .expect("json");
        assert_eq!(header["jwk"], key["jwk"]);
    }
}

#[test]
fn jkt_matches_the_wire_fixture() {
    // The client's thumbprint of the key of RFC 9449 is the one the wire
    // fixture holds (RFC 9449 § 6.1).
    let file = js();
    let wire = fixture("wire", "dpop_jwk.json");
    assert_eq!(file["rfc9449"]["jwk"], wire["jwk"]);
    assert_eq!(text(&file["rfc9449"], "jkt"), text(&wire, "jkt"));
    assert_eq!(
        text(&wire, "jkt"),
        "0ZcOCORZNYy-DWpqq30jZyJGHTN0d2HglBV3uiguA4I"
    );
}

#[test]
fn rfc9449_example_proofs_verify_in_rust() {
    // The examples of RFC 9449 (Figures 2 and 7) are proofs for
    // `POST https://server.example.com/token`, signed with the key of
    // dpop_jwk.json; the server's check takes them at their own time.
    let file = js();
    let wire = fixture("wire", "dpop_jwk.json");
    let examples = file["rfc9449"]["examples"].as_array().expect("examples");
    assert_eq!(examples.len(), 2);
    for example in examples {
        let figure = example["figure"].as_i64().expect("figure");
        let iat = example["iat"].as_i64().expect("iat");
        let auth = auth_for(text(example, "origin"));
        let htu = auth.htu(text(example, "path"));
        let m = method(text(example, "method"));
        let proof = text(example, "proof");
        let verified = check(proof, &m, &htu, None, iat)
            .unwrap_or_else(|e| panic!("Figure {figure}: the server accepts the example ({e:?})"));
        assert_eq!(b64(verified.jkt()), text(&wire, "jkt"), "Figure {figure}");
        assert_eq!(verified.iat(), iat);
        assert!(
            check(proof, &m, &htu, None, iat + 61).is_err(),
            "Figure {figure}: too late"
        );
        assert!(
            check(proof, &m, &auth.htu("/token2"), None, iat).is_err(),
            "Figure {figure}: htu"
        );
    }
}

/// A handle for proofs on `origin`.
fn auth_for(origin: &str) -> DeviceAuth {
    DeviceAuth::new(origin)
}
