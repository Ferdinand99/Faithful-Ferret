//! The passkey authenticator (Fase 1 § 9, F-12, F-13, F-29)
//! and `vectors/internal/passkey.json`.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]

mod common;

use common::*;
use ferret_core::VaultContext;
use ferret_core::passkey::{
    AAGUID, CreatePrfResponse, CreateResponse, FLAG_AT, FLAG_BE, FLAG_BS, FLAG_ED, FLAG_UP,
    FLAG_UV, GetResponse, PasskeyPrivateKey, PrfCreate, PrfEval, PrfRequest, prf_output, prf_salt,
};
use ferret_core::testing::passkey::{client_data_json, item_of, private_scalar};
use ferret_core::testing::prim::hmac_sha256;
use ferret_core::testing::vector::Outcome;
use ferret_core::testing::{TestRng, hex_decode};
use ferret_core::{
    CallerContext, CreateRequest, Error, ExistingCredential, GetRequest, MalformedKind, Passkey,
    PasskeyRecord, PrfSeed, StoredPasskeyRef, UserVerification, UvOutcome, canonical_origin,
    passkey_candidates, passkey_candidates_for, passkey_create, passkey_get, passkey_site,
};
use p256::ecdsa::signature::Verifier;
use p256::ecdsa::{Signature, VerifyingKey};
use p256::pkcs8::DecodePublicKey;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use static_assertions::assert_not_impl_any;

assert_not_impl_any!(PasskeyPrivateKey: Clone, core::fmt::Debug, PartialEq, core::fmt::Display);
assert_not_impl_any!(PasskeyRecord: Clone, PartialEq, core::fmt::Display);
assert_not_impl_any!(ferret_core::passkey::PrfResults: Clone, PartialEq);

// ------------------------------------------------------------- helpers

const YES: UvOutcome = UvOutcome {
    user_present: true,
    user_verified: true,
};
const NO_UV: UvOutcome = UvOutcome {
    user_present: true,
    user_verified: false,
};

fn ctx(origin: &str) -> CallerContext {
    CallerContext {
        origin: canonical_origin(origin).unwrap(),
        top_origin_is_same: true,
    }
}

fn create_req() -> CreateRequest {
    CreateRequest {
        challenge: vec![7; 32],
        rp_id: None,
        rp_name: "Example".into(),
        user_id: vec![1; 16],
        user_name: "alice@example.com".into(),
        user_display_name: "Alice".into(),
        algorithms: vec![-7, -257],
        exclude: vec![],
        user_verification: UserVerification::Preferred,
        prf: None,
        cred_props: false,
    }
}

fn get_req() -> GetRequest {
    GetRequest {
        challenge: vec![9; 32],
        rp_id: None,
        allow: vec![],
        user_verification: UserVerification::Preferred,
        prf: None,
    }
}

fn make(req: &CreateRequest, uv: UvOutcome) -> (PasskeyRecord, CreateResponse) {
    let mut rng = TestRng::new(b"passkey tests");
    let c = passkey_create(
        &mut rng,
        req,
        &ctx("https://example.com"),
        uv,
        &[],
        1_700_000_000_000,
    )
    .unwrap();
    (c.record, c.response)
}

fn flags(auth: &[u8]) -> u8 {
    auth[32]
}

// ------------------------------------------------------ vector parsing

fn eval_of(v: &Value) -> PrfEval {
    PrfEval {
        first: hex(&v["first"]),
        second: v["second"].as_str().map(|s| hex_decode(s).unwrap()),
    }
}

fn uv_kind(s: &str) -> UserVerification {
    match s {
        "required" => UserVerification::Required,
        "preferred" => UserVerification::Preferred,
        "discouraged" => UserVerification::Discouraged,
        other => panic!("user verification {other}"),
    }
}

fn hex_list(v: &Value) -> Vec<Vec<u8>> {
    v.as_array().unwrap().iter().map(hex).collect()
}

fn existing_of(v: &Value) -> Vec<ExistingCredential> {
    v.as_array()
        .unwrap()
        .iter()
        .map(|e| ExistingCredential {
            rp_id: e["rp_id"].as_str().unwrap().to_owned(),
            cred_id: hex(&e["id"]),
        })
        .collect()
}

fn uv_of(v: &Value) -> UvOutcome {
    UvOutcome {
        user_present: v["user_present"].as_bool().unwrap(),
        user_verified: v["user_verified"].as_bool().unwrap(),
    }
}

fn ctx_of(input: &Value) -> CallerContext {
    CallerContext {
        origin: canonical_origin(input["origin"].as_str().unwrap()).unwrap(),
        top_origin_is_same: input["top_origin_is_same"].as_bool().unwrap(),
    }
}

fn create_request_of(r: &Value) -> CreateRequest {
    CreateRequest {
        challenge: hex(&r["challenge"]),
        rp_id: r["rp_id"].as_str().map(str::to_owned),
        rp_name: r["rp_name"].as_str().unwrap().to_owned(),
        user_id: hex(&r["user_id"]),
        user_name: r["user_name"].as_str().unwrap().to_owned(),
        user_display_name: r["user_display_name"].as_str().unwrap().to_owned(),
        algorithms: r["algorithms"]
            .as_array()
            .unwrap()
            .iter()
            .map(|a| a.as_i64().unwrap())
            .collect(),
        exclude: hex_list(&r["exclude"]),
        user_verification: uv_kind(r["user_verification"].as_str().unwrap()),
        prf: r["prf"].as_object().map(|p| PrfCreate {
            eval: p.get("eval").filter(|e| !e.is_null()).map(eval_of),
        }),
        cred_props: r["cred_props"].as_bool().unwrap(),
    }
}

fn get_request_of(r: &Value) -> GetRequest {
    GetRequest {
        challenge: hex(&r["challenge"]),
        rp_id: r["rp_id"].as_str().map(str::to_owned),
        allow: hex_list(&r["allow"]),
        user_verification: uv_kind(r["user_verification"].as_str().unwrap()),
        prf: r["prf"].as_object().map(|p| PrfRequest {
            eval: p.get("eval").filter(|e| !e.is_null()).map(eval_of),
            eval_by_credential: p["eval_by_credential"]
                .as_array()
                .unwrap()
                .iter()
                .map(|e| (hex(&e["id"]), eval_of(e)))
                .collect(),
        }),
    }
}

fn record_of(r: &Value) -> PasskeyRecord {
    let opt = |v: &Value| v.as_str().map(|s| hex_decode(s).unwrap());
    PasskeyRecord::from_item(&Passkey {
        cred_id: hex(&r["cred_id"]),
        rp_id: r["rp_id"].as_str().unwrap().to_owned(),
        user_handle: hex(&r["user_handle"]),
        user_name: r["user_name"].as_str().unwrap().to_owned(),
        private_key: hex(&r["priv_pkcs8"]),
        sign_count: 0,
        created: u64s(&r["created"]),
        prf_seed_uv: opt(&r["prf_seed_uv"]),
        prf_seed_nouv: opt(&r["prf_seed_nouv"]),
        rp_name: r["rp_name"].as_str().map(str::to_owned),
        user_display_name: r["user_display_name"].as_str().map(str::to_owned),
        extra: vec![],
    })
    .unwrap()
}

fn opt_hex(b: Option<&[u8; 32]>) -> Value {
    b.map_or(Value::Null, |b| Value::from(he(b)))
}

fn create_prf_json(p: &Option<CreatePrfResponse>) -> Value {
    match p {
        None => Value::Null,
        Some(p) => json!({
            "enabled": p.enabled,
            "first": opt_hex(p.results.as_ref().map(|r| r.reveal_first())),
            "second": opt_hex(p.results.as_ref().and_then(|r| r.reveal_second())),
        }),
    }
}

fn get_prf_json(p: &Option<ferret_core::passkey::PrfResults>) -> Value {
    match p {
        None => Value::Null,
        Some(r) => json!({
            "first": he(r.reveal_first()),
            "second": opt_hex(r.reveal_second()),
        }),
    }
}

fn cose_key_of(auth: &[u8]) -> Vec<u8> {
    // rpIdHash(32) flags(1) signCount(4) aaguid(16) credIdLen(2) credId, COSE_Key (77)
    let len = usize::from(u16::from_be_bytes([auth[53], auth[54]]));
    auth[55 + len..55 + len + 77].to_vec()
}

fn run_vectors(keep: impl Fn(&str) -> bool) -> ferret_core::testing::vector::RunReport {
    let file = load_ops("passkey.json", keep);
    ferret_core::testing::vector::run_all(&file, |case, rng| {
        let input = &case.input;
        match case.op.as_str() {
            "passkey.create" => {
                let req = create_request_of(&input["request"]);
                let created = passkey_create(
                    rng,
                    &req,
                    &ctx_of(input),
                    uv_of(&input["uv"]),
                    &existing_of(&input["existing_credentials"]),
                    u64s(&input["created_ms"]),
                )?;
                let item = item_of(&created.record);
                let r = &created.response;
                let auth = &r.authenticator_data;
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
                            "private_scalar": he(&private_scalar(&created.record).unwrap()),
                            "priv_pkcs8": he(&item.private_key),
                            "prf_seed_uv": item.prf_seed_uv.as_deref().map_or(Value::Null, |s| Value::from(he(s))),
                            "prf_seed_nouv": item.prf_seed_nouv.as_deref().map_or(Value::Null, |s| Value::from(he(s))),
                        },
                        "response": {
                            "id": he(&r.id),
                            "attestation_object": he(&r.attestation_object),
                            "client_data_json": String::from_utf8(r.client_data_json.clone()).unwrap(),
                            "authenticator_data": he(auth),
                            "public_key_spki": he(&r.public_key_spki),
                            "alg": r.alg,
                            "authenticator_attachment": r.authenticator_attachment,
                            "transports": r.transports,
                            "cred_props": r.cred_props.map_or(Value::Null, |c| json!({ "rk": c.rk })),
                            "prf": create_prf_json(&r.prf),
                        },
                    }),
                    intermediate: Some(json!({
                        "flags": flags(auth),
                        "cose_key": he(&cose_key_of(auth)),
                    })),
                })
            }
            "passkey.get" => {
                let record = record_of(&input["record"]);
                let r = passkey_get(
                    &record,
                    &get_request_of(&input["request"]),
                    &ctx_of(input),
                    uv_of(&input["uv"]),
                )?;
                Ok(Outcome {
                    output: json!({
                        "id": he(&r.id),
                        "authenticator_attachment": r.authenticator_attachment,
                        "authenticator_data": he(&r.authenticator_data),
                        "client_data_json": String::from_utf8(r.client_data_json.clone()).unwrap(),
                        "signature": he(&r.signature),
                        "user_handle": he(&r.user_handle),
                        "prf": get_prf_json(&r.prf),
                    }),
                    intermediate: Some(json!({ "flags": flags(&r.authenticator_data) })),
                })
            }
            "passkey.candidates" => {
                let stored: Vec<(String, Vec<u8>)> = input["stored"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|e| (e["rp_id"].as_str().unwrap().to_owned(), hex(&e["id"])))
                    .collect();
                let refs: Vec<StoredPasskeyRef<'_>> = stored
                    .iter()
                    .map(|(rp_id, cred_id)| StoredPasskeyRef { rp_id, cred_id })
                    .collect();
                let indexes = passkey_candidates(
                    &ctx_of(input),
                    input["rp_id"].as_str(),
                    &hex_list(&input["allow"]),
                    &refs,
                )?;
                Ok(Outcome {
                    output: json!({ "indexes": indexes }),
                    intermediate: None,
                })
            }
            "passkey.site" => {
                let site = passkey_site(&ctx_of(input), input["rp_id"].as_str())?;
                Ok(Outcome {
                    output: json!({
                        "origin": site.origin,
                        "host_unicode": site.host_unicode,
                        "rp_id": site.rp_id,
                        "rp_id_unicode": site.rp_id_unicode,
                    }),
                    intermediate: None,
                })
            }
            "passkey.prf" => {
                let seed = PrfSeed::from_test_bytes(hexn(&input["seed"]));
                let bytes = segments(&input["input"]);
                let out = prf_output(&seed, &bytes)?;
                Ok(Outcome {
                    output: json!({
                        "salt": he(&prf_salt(&bytes)),
                        "output": he(ferret_core::testing::passkey::reveal_prf_output(&out)),
                    }),
                    intermediate: None,
                })
            }
            other => panic!("unknown op {other}"),
        }
    })
}

/// Bytes from `{ "segments": [ { "hex": hex, "repeat": n } ] }`.
fn segments(v: &Value) -> Vec<u8> {
    let mut out = vec![];
    for s in v["segments"].as_array().unwrap() {
        let piece = hex(&s["hex"]);
        for _ in 0..s["repeat"].as_u64().unwrap() {
            out.extend_from_slice(&piece);
        }
    }
    out
}

#[test]
fn passkey_vectors_from_file() {
    let report = run_vectors(|op| matches!(op, "passkey.create" | "passkey.get" | "passkey.prf"));
    assert_all_passed(&report, 18);
}

// --------------------------------------------------------------- tests

#[test]
fn cross_origin_is_denied() {
    let mut c = ctx("https://example.com");
    c.top_origin_is_same = false;
    let mut rng = TestRng::new(b"x");
    let err = passkey_create(&mut rng, &create_req(), &c, YES, &[], 0).err();
    assert_eq!(err, Some(Error::NotAllowed));
    let (record, _) = make(&create_req(), YES);
    let err = passkey_get(&record, &get_req(), &c, YES).err();
    assert_eq!(err, Some(Error::NotAllowed));
}

#[test]
fn client_data_json_exact_bytes() {
    // Created in the core and written by hand here.
    let (_, r) = make(&create_req(), YES);
    let want = format!(
        "{{\"type\":\"webauthn.create\",\"challenge\":\"{}\",\"origin\":\"https://example.com\",\"crossOrigin\":false}}",
        "BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc"
    );
    assert_eq!(String::from_utf8(r.client_data_json).unwrap(), want);

    // The escaping of the specification: ", \ and everything below U+0020 as
    // \u and four lower-case hex digits; everything else, including U+007F
    // and non-ASCII, as it is.
    let json = client_data_json(false, b"", "a\"b\\c\n\u{1}\u{1f}\u{7f}é日\u{1f600}/");
    assert_eq!(
        json,
        "{\"type\":\"webauthn.get\",\"challenge\":\"\",\"origin\":\"a\\\"b\\\\c\\u000a\\u0001\\u001f\u{7f}é日\u{1f600}/\",\"crossOrigin\":false}"
    );
    // Every challenge length gives unpadded base64url.
    for (n, want) in [
        (0usize, ""),
        (1, "AA"),
        (2, "AAA"),
        (3, "AAAA"),
        (4, "AAAAAA"),
    ] {
        let j = client_data_json(true, &vec![0; n], "x");
        assert!(j.contains(&format!("\"challenge\":\"{want}\"")), "{n}: {j}");
    }
    let j = client_data_json(true, &[0xfb, 0xff, 0xfe], "x");
    assert!(j.contains("\"challenge\":\"-__-\""), "{j}");
}

#[test]
fn authdata_flags_invariants() {
    for create_uv in [YES, NO_UV] {
        let (record, created) = make(&create_req(), create_uv);
        let a = &created.authenticator_data;
        // BE and BS always, UP always, AT only here, signCount 0.
        assert_eq!(
            flags(a) & (FLAG_BE | FLAG_BS | FLAG_UP),
            FLAG_BE | FLAG_BS | FLAG_UP
        );
        assert_ne!(flags(a) & FLAG_AT, 0);
        assert_eq!(flags(a) & FLAG_ED, 0, "no prf, no extension data");
        assert_eq!(a[33..37], [0, 0, 0, 0]);
        assert_eq!(flags(a) & FLAG_UV != 0, create_uv.user_verified);
        for get_uv in [YES, NO_UV] {
            let g = passkey_get(&record, &get_req(), &ctx("https://example.com"), get_uv).unwrap();
            let f = flags(&g.authenticator_data);
            assert_eq!(
                f & (FLAG_BE | FLAG_BS | FLAG_UP),
                FLAG_BE | FLAG_BS | FLAG_UP
            );
            assert_eq!(f & FLAG_AT, 0, "AT is for create only");
            assert_eq!(f & FLAG_ED, 0);
            assert_eq!(f & FLAG_UV != 0, get_uv.user_verified);
            assert_eq!(g.authenticator_data.len(), 37);
            assert_eq!(g.authenticator_data[33..37], [0, 0, 0, 0]);
            // Reserved bits stay clear.
            assert_eq!(f & !(FLAG_BE | FLAG_BS | FLAG_UP | FLAG_UV), 0);
        }
    }
}

#[test]
fn authdata_layout_create() {
    let (record, r) = make(&create_req(), YES);
    let a = &r.authenticator_data;
    // 32 + 1 + 4 + 16 + 2 + 32 + 77, and no extension data.
    assert_eq!(a.len(), 164);
    assert_eq!(a[..32], Sha256::digest(b"example.com")[..]);
    assert_eq!(a[37..53], AAGUID);
    assert_eq!(u16::from_be_bytes([a[53], a[54]]), 32);
    assert_eq!(a[55..87], record.cred_id[..]);
    assert_eq!(a[87..], cose_key_of(a)[..]);
    assert_eq!(r.id, record.cred_id);

    // With prf: ED and the 14-byte extension map after the COSE key.
    let mut req = create_req();
    req.prf = Some(PrfCreate::default());
    let (_, r) = make(&req, YES);
    let a = &r.authenticator_data;
    assert_eq!(a.len(), 164 + 14);
    assert_ne!(flags(a) & FLAG_ED, 0);
    assert_eq!(
        a[164..],
        hex_decode("a16b686d61632d736563726574f5").unwrap()[..]
    );
    // The same bytes are in the attestation object.
    assert!(
        r.attestation_object
            .windows(a.len())
            .any(|w| w == a.as_slice())
    );
}

#[test]
fn aaguid_is_fixed_constant_exposed_in_create() {
    // dc704a44-b994-410c-a689-ed8d71a84ac3, a UUID version 4 (variant 10).
    assert_eq!(
        AAGUID.to_vec(),
        hex_decode("dc704a44b994410ca689ed8d71a84ac3").unwrap()
    );
    assert_eq!(AAGUID[6] >> 4, 4);
    assert_eq!(AAGUID[8] >> 6, 0b10);
    // The same in every create, whatever the user, the RP or the randomness.
    let mut other = create_req();
    other.user_id = vec![9; 64];
    for req in [create_req(), other] {
        let mut rng = TestRng::new(b"another seed");
        let c = passkey_create(
            &mut rng,
            &req,
            &ctx("https://login.example.com"),
            YES,
            &[],
            0,
        )
        .unwrap();
        assert_eq!(c.response.authenticator_data[37..53], AAGUID);
    }
}

#[test]
fn cose_key_encoding_matches_vector() {
    let (record, r) = make(&create_req(), YES);
    let cose = cose_key_of(&r.authenticator_data);
    assert_eq!(cose.len(), 77);
    assert_eq!(cose[..10], hex_decode("a5010203262001215820").unwrap()[..]);
    assert_eq!(cose[10..42], r.public_key_spki[27..59]);
    assert_eq!(cose[42..45], [0x22, 0x58, 0x20]);
    assert_eq!(cose[45..], r.public_key_spki[59..91]);
    // The SPKI is the 26-byte P-256 prefix and the uncompressed point of d.
    assert_eq!(r.public_key_spki.len(), 91);
    assert_eq!(
        r.public_key_spki[..27],
        hex_decode("3059301306072a8648ce3d020106082a8648ce3d03010703420004").unwrap()[..]
    );
    assert_eq!(r.alg, -7);
    let d = private_scalar(&record).unwrap();
    let key = p256::ecdsa::SigningKey::from_slice(&d).unwrap();
    let point = key.verifying_key().to_sec1_point(false);
    assert_eq!(&r.public_key_spki[26..], point.as_bytes());
}

#[test]
fn attestation_object_is_none_format() {
    let (_, r) = make(&create_req(), YES);
    let o = &r.attestation_object;
    let prefix = hex_decode("a363666d74646e6f6e656761747453746d74a0686175746844617461").unwrap();
    assert_eq!(o[..prefix.len()], prefix[..]);
    // bstr of 164 bytes: 0x58 0xa4.
    assert_eq!(o[prefix.len()..prefix.len() + 2], [0x58, 164]);
    assert_eq!(o[prefix.len() + 2..], r.authenticator_data[..]);
}

#[test]
fn passkey_signature_verifies_with_p256() {
    let (record, created) = make(&create_req(), YES);
    let vk = VerifyingKey::from_public_key_der(&created.public_key_spki).unwrap();
    for uv in [YES, NO_UV] {
        let g = passkey_get(&record, &get_req(), &ctx("https://example.com"), uv).unwrap();
        let mut msg = g.authenticator_data.clone();
        msg.extend_from_slice(&Sha256::digest(&g.client_data_json));
        let sig = Signature::from_der(&g.signature).unwrap();
        vk.verify(&msg, &sig).unwrap();
        // Any change to the signed bytes breaks it.
        msg[0] ^= 1;
        assert!(vk.verify(&msg, &sig).is_err());
    }
}

#[test]
fn passkey_get_requires_exact_rp_id() {
    let (record, _) = make(&create_req(), YES);
    assert_eq!(record.rp_id, "example.com");
    // Stored example.com, asked for sub.example.com: NotAllowed.
    let sub = ctx("https://sub.example.com");
    assert_eq!(
        passkey_get(&record, &get_req(), &sub, YES).err(),
        Some(Error::NotAllowed)
    );
    // The same with the parent named in the request (valid for the origin,
    // and exactly the stored one): signs.
    let mut req = get_req();
    req.rp_id = Some("example.com".into());
    assert!(passkey_get(&record, &req, &sub, YES).is_ok());
    // Case and trailing dot are canonicalised before the exact comparison.
    req.rp_id = Some("EXAMPLE.com.".into());
    assert!(passkey_get(&record, &req, &sub, YES).is_ok());
    // A different parent is not the stored one.
    let other = ctx("https://sub.other.com");
    assert_eq!(
        passkey_get(&record, &get_req(), &other, YES).err(),
        Some(Error::NotAllowed)
    );
    // An RP ID the origin may not use is its own error, not NotAllowed.
    req.rp_id = Some("com".into());
    assert_eq!(
        passkey_get(&record, &req, &sub, YES).err(),
        Some(Error::Malformed(MalformedKind::RpId))
    );
}

#[test]
fn uv_required_without_uv_is_not_allowed() {
    let mut req = create_req();
    req.user_verification = UserVerification::Required;
    let mut rng = TestRng::new(b"x");
    let uv_missing =
        passkey_create(&mut rng, &req, &ctx("https://example.com"), NO_UV, &[], 0).err();
    assert_eq!(uv_missing, Some(Error::NotAllowed));

    // The same value as "no match" (stored RP differs) and "cancelled" (no
    // user presence): the page cannot tell them apart.
    let (record, _) = make(&create_req(), YES);
    let mut get = get_req();
    get.user_verification = UserVerification::Required;
    let c = ctx("https://example.com");
    let no_uv = passkey_get(&record, &get, &c, NO_UV).err();
    let no_match = passkey_get(&record, &get_req(), &ctx("https://other.example"), YES).err();
    let cancelled = passkey_get(
        &record,
        &get_req(),
        &c,
        UvOutcome {
            user_present: false,
            user_verified: false,
        },
    )
    .err();
    assert_eq!(no_uv, Some(Error::NotAllowed));
    assert_eq!(no_uv, no_match);
    assert_eq!(no_uv, cancelled);
    // And with UV it works.
    assert!(passkey_get(&record, &get, &c, YES).is_ok());
}

#[test]
fn uv_discouraged_without_uv_ok_flag_clear() {
    for kind in [UserVerification::Discouraged, UserVerification::Preferred] {
        let mut req = create_req();
        req.user_verification = kind;
        let (record, r) = make(&req, NO_UV);
        assert_eq!(flags(&r.authenticator_data) & FLAG_UV, 0);
        let mut get = get_req();
        get.user_verification = kind;
        let g = passkey_get(&record, &get, &ctx("https://example.com"), NO_UV).unwrap();
        assert_eq!(flags(&g.authenticator_data) & FLAG_UV, 0);
        assert_ne!(flags(&g.authenticator_data) & FLAG_UP, 0);
    }
}

#[test]
fn exclude_credentials_respected() {
    let (record, _) = make(&create_req(), YES);
    let stored = vec![
        ExistingCredential {
            rp_id: "example.com".into(),
            cred_id: record.cred_id.clone(),
        },
        ExistingCredential {
            rp_id: "example.com".into(),
            cred_id: vec![5; 32],
        },
    ];
    let mut req = create_req();
    req.exclude = vec![vec![1; 32], record.cred_id.clone()];
    let mut rng = TestRng::new(b"x");
    let c = ctx("https://example.com");
    // A hit is InvalidStateError, after the presence check.
    assert_eq!(
        passkey_create(&mut rng, &req, &c, YES, &stored, 0).err(),
        Some(Error::InvalidState)
    );
    assert_eq!(Error::InvalidState.code(), "invalid_state");
    let no_presence = UvOutcome {
        user_present: false,
        user_verified: false,
    };
    assert_eq!(
        passkey_create(&mut rng, &req, &c, no_presence, &stored, 0).err(),
        Some(Error::NotAllowed)
    );
    // Not excluded when the list names other credentials, or the store is empty.
    req.exclude = vec![vec![1; 32]];
    assert!(passkey_create(&mut rng, &req, &c, YES, &stored, 0).is_ok());
    req.exclude = vec![record.cred_id.clone()];
    assert!(passkey_create(&mut rng, &req, &c, YES, &[], 0).is_ok());
    // A credential stored for another RP ID is invisible to this request.
    let other_rp = vec![ExistingCredential {
        rp_id: "other.example".into(),
        cred_id: record.cred_id.clone(),
    }];
    assert!(passkey_create(&mut rng, &req, &c, YES, &other_rp, 0).is_ok());
}

#[test]
fn prf_vectors_from_file() {
    // The file's prf cases are byte-for-byte HMAC-SHA256(seed, SHA-256("WebAuthn PRF" ‖ 0x00 ‖ input)).
    let file = load_ops("passkey.json", |op| op == "passkey.prf");
    assert!(file.cases.len() >= 3);
    let report = ferret_core::testing::vector::run_all(&file, |case, _| {
        let seed = hexn::<32>(&case.input["seed"]);
        let bytes = segments(&case.input["input"]);
        let mut salt_input = b"WebAuthn PRF\0".to_vec();
        salt_input.extend_from_slice(&bytes);
        let salt = Sha256::digest(&salt_input);
        let want = hmac_sha256(&seed, &salt).unwrap();
        let got = prf_output(&PrfSeed::from_test_bytes(seed), &bytes)?;
        assert_eq!(
            ferret_core::testing::passkey::reveal_prf_output(&got),
            &want
        );
        Ok(Outcome {
            output: json!({ "salt": he(&salt), "output": he(&want) }),
            intermediate: None,
        })
    });
    assert_all_passed(&report, 3);

    // Same input, UV and no UV: different outputs.
    let mut req = create_req();
    req.prf = Some(PrfCreate {
        eval: Some(PrfEval {
            first: b"salt".to_vec(),
            second: None,
        }),
    });
    let (_, with_uv) = make(&req, YES);
    let (_, without_uv) = make(&req, NO_UV);
    let a = with_uv.prf.unwrap().results.unwrap();
    let b = without_uv.prf.unwrap().results.unwrap();
    assert_ne!(a.reveal_first(), b.reveal_first());
}

#[test]
fn prf_seed_chosen_by_actual_uv() {
    let mut req = create_req();
    req.prf = Some(PrfCreate::default());
    let (record, created) = make(&req, YES);
    assert_eq!(created.prf.as_ref().map(|p| p.enabled), Some(true));
    assert!(created.prf.unwrap().results.is_none());
    let item = item_of(&record);
    let seed_uv = item.prf_seed_uv.clone().unwrap();
    let seed_nouv = item.prf_seed_nouv.clone().unwrap();
    assert_eq!(seed_uv.len(), 32);
    assert_ne!(seed_uv, seed_nouv);

    let mut get = get_req();
    get.prf = Some(PrfRequest {
        eval: Some(PrfEval {
            first: b"in".to_vec(),
            second: Some(b"in2".to_vec()),
        }),
        eval_by_credential: vec![],
    });
    let c = ctx("https://example.com");
    let salt = |input: &[u8]| {
        let mut m = b"WebAuthn PRF\0".to_vec();
        m.extend_from_slice(input);
        Sha256::digest(&m)
    };
    for (uv, seed) in [(YES, &seed_uv), (NO_UV, &seed_nouv)] {
        let g = passkey_get(&record, &get, &c, uv).unwrap();
        let r = g.prf.unwrap();
        assert_eq!(r.reveal_first(), &hmac_sha256(seed, &salt(b"in")).unwrap());
        assert_eq!(
            r.reveal_second().unwrap(),
            &hmac_sha256(seed, &salt(b"in2")).unwrap()
        );
    }
    // The UV outputs and the no-UV outputs differ.
    let a = passkey_get(&record, &get, &c, YES).unwrap().prf.unwrap();
    let b = passkey_get(&record, &get, &c, NO_UV).unwrap().prf.unwrap();
    assert_ne!(a.reveal_first(), b.reveal_first());
}

#[test]
fn prf_not_requested_means_no_seeds() {
    let (record, created) = make(&create_req(), YES);
    assert!(created.prf.is_none());
    let item = item_of(&record);
    assert!(item.prf_seed_uv.is_none() && item.prf_seed_nouv.is_none());
    assert!(!record.has_prf());
    // A get that asks for prf gets no results, not an error.
    let mut get = get_req();
    get.prf = Some(PrfRequest {
        eval: Some(PrfEval {
            first: b"in".to_vec(),
            second: None,
        }),
        eval_by_credential: vec![],
    });
    let g = passkey_get(&record, &get, &ctx("https://example.com"), YES).unwrap();
    assert!(g.prf.is_none());
    // The randomness drawn is exactly cred id and key without prf.
    let mut rng = ferret_core::testing::ReplayRng::new(vec![vec![1; 32], vec![2; 32]]);
    passkey_create(
        &mut rng,
        &create_req(),
        &ctx("https://example.com"),
        YES,
        &[],
        0,
    )
    .unwrap();
    rng.finish().unwrap();
}

#[test]
fn prf_eval_by_credential_requires_allow_list() {
    let (record, _) = make(&create_req(), YES);
    let by_cred = |id: Vec<u8>| PrfRequest {
        eval: None,
        eval_by_credential: vec![(
            id,
            PrfEval {
                first: b"x".to_vec(),
                second: None,
            },
        )],
    };
    let mut get = get_req();
    get.prf = Some(by_cred(record.cred_id.clone()));
    // No allowCredentials: NotSupported (validated before anything else).
    assert_eq!(get.validate(), Err(Error::Unsupported));
    assert_eq!(
        passkey_get(&record, &get, &ctx("https://example.com"), YES).err(),
        Some(Error::Unsupported)
    );
    // A key that is not in allowCredentials: SyntaxError.
    get.allow = vec![record.cred_id.clone()];
    get.prf = Some(by_cred(vec![8; 32]));
    assert_eq!(
        get.validate(),
        Err(Error::Malformed(MalformedKind::WebauthnOptions))
    );
    // In the list: fine.
    get.prf = Some(by_cred(record.cred_id.clone()));
    assert_eq!(get.validate(), Ok(()));
}

#[test]
fn create_options_validation_limits() {
    let ok = create_req();
    assert_eq!(ok.validate(), Ok(()));
    let mut r = create_req();
    r.challenge = vec![0; 1024];
    assert_eq!(r.validate(), Ok(()));
    r.challenge = vec![0; 1025];
    assert_eq!(r.validate(), Err(Error::TooLarge));
    let mut r = create_req();
    r.exclude = vec![vec![1; 16]; 200];
    assert_eq!(r.validate(), Ok(()));
    r.exclude = vec![vec![1; 16]; 201];
    assert_eq!(r.validate(), Err(Error::TooLarge));
    let mut r = create_req();
    r.exclude = vec![vec![1; 1024]];
    assert_eq!(r.validate(), Err(Error::TooLarge));
    let mut r = create_req();
    r.user_id = vec![];
    assert_eq!(
        r.validate(),
        Err(Error::Malformed(MalformedKind::WebauthnOptions))
    );
    r.user_id = vec![0; 65];
    assert_eq!(
        r.validate(),
        Err(Error::Malformed(MalformedKind::WebauthnOptions))
    );
    r.user_id = vec![0; 64];
    assert_eq!(r.validate(), Ok(()));
    let mut r = create_req();
    r.algorithms = vec![-257, -8];
    assert_eq!(r.validate(), Err(Error::Unsupported));
    r.algorithms = vec![];
    assert_eq!(r.validate(), Ok(()));
    let mut r = create_req();
    r.user_name = "x".repeat(1025);
    assert_eq!(r.validate(), Err(Error::TooLarge));

    let mut g = get_req();
    g.challenge = vec![0; 1025];
    assert_eq!(g.validate(), Err(Error::TooLarge));
    let mut g = get_req();
    g.allow = vec![vec![1; 8]; 201];
    assert_eq!(g.validate(), Err(Error::TooLarge));
    let mut g = get_req();
    g.prf = Some(PrfRequest {
        eval: Some(PrfEval {
            first: vec![0; 1025],
            second: None,
        }),
        eval_by_credential: vec![],
    });
    assert_eq!(g.validate(), Err(Error::TooLarge));
}

#[test]
fn passkey_private_key_never_in_debug_or_clone() {
    // The static part is the assert_not_impl_any! at the top of the file.
    // Here: the Debug that exists shows nothing.
    let mut req = create_req();
    req.prf = Some(PrfCreate {
        eval: Some(PrfEval {
            first: b"in".to_vec(),
            second: None,
        }),
    });
    let mut rng = TestRng::new(b"debug");
    let c = passkey_create(&mut rng, &req, &ctx("https://example.com"), YES, &[], 0).unwrap();
    let item = item_of(&c.record);
    let secret_hex = [
        he(&item.private_key),
        he(&private_scalar(&c.record).unwrap()),
        he(&item.prf_seed_uv.clone().unwrap()),
        he(c.response
            .prf
            .as_ref()
            .unwrap()
            .results
            .as_ref()
            .unwrap()
            .reveal_first()),
    ];
    let shown = format!("{:?} {:?}", c.record, c.response);
    let shown_all = format!("{shown} {:?}", c);
    for s in secret_hex {
        assert!(!shown_all.contains(&s));
    }
    assert!(!shown_all.contains(&c.record.user_name));
}

#[test]
fn record_roundtrips_through_the_item_body() {
    let mut req = create_req();
    req.prf = Some(PrfCreate::default());
    let (record, _) = make(&req, YES);
    let item = item_of(&record);
    assert_eq!(item.sign_count, 0);
    assert_eq!(item.cred_id.len(), 32);
    let back = PasskeyRecord::from_item(&item).unwrap();
    assert_eq!(item_of(&back).private_key, item.private_key);
    assert!(back.has_prf());
    // The key must be a P-256 PKCS#8 key; a seed must be 32 bytes.
    let mut bad = item.clone();
    bad.private_key = vec![1, 2, 3];
    assert_eq!(
        PasskeyRecord::from_item(&bad).err(),
        Some(Error::Malformed(MalformedKind::ItemBody))
    );
    let mut bad = item.clone();
    bad.prf_seed_uv = Some(vec![0; 31]);
    assert_eq!(
        PasskeyRecord::from_item(&bad).err(),
        Some(Error::Malformed(MalformedKind::ItemBody))
    );
    // The record can be signed with after the round trip.
    let g = passkey_get(&back, &get_req(), &ctx("https://example.com"), YES).unwrap();
    assert!(!g.signature.is_empty());
}

#[test]
fn signing_is_deterministic_and_draws_nothing() {
    let (record, _) = make(&create_req(), YES);
    let c = ctx("https://example.com");
    let a: GetResponse = passkey_get(&record, &get_req(), &c, YES).unwrap();
    let b = passkey_get(&record, &get_req(), &c, YES).unwrap();
    assert_eq!(a.signature, b.signature);
}

#[test]
fn creation_draws_in_the_documented_order() {
    // cred id, scalar, then (prf) prf_seed_uv and prf_seed_nouv.
    let mut req = create_req();
    req.prf = Some(PrfCreate::default());
    let draws = vec![
        vec![0xa1; 32],
        vec![0x11; 32],
        vec![0x31; 32],
        vec![0x51; 32],
    ];
    let mut rng = ferret_core::testing::ReplayRng::new(draws);
    let c = passkey_create(&mut rng, &req, &ctx("https://example.com"), YES, &[], 5).unwrap();
    rng.finish().unwrap();
    let item = item_of(&c.record);
    assert_eq!(item.cred_id, vec![0xa1; 32]);
    assert_eq!(private_scalar(&c.record).unwrap(), [0x11; 32]);
    assert_eq!(item.prf_seed_uv.clone().unwrap(), vec![0x31; 32]);
    assert_eq!(item.prf_seed_nouv.clone().unwrap(), vec![0x51; 32]);
    assert_eq!(item.created, 5);
}

#[test]
fn seal_passkey_item_keeps_the_key_inside_the_envelope() {
    use ferret_core::{ItemId, UnlockedVault, decrypt_item, seal_passkey_item};
    let vault = UnlockedVault::from_vault_key(ctx_vault(), vk(0x5a)).unwrap();
    let mut req = create_req();
    req.prf = Some(PrfCreate::default());
    let (record, created) = make(&req, YES);
    let key_der = item_of(&record).private_key.clone();
    let seed = item_of(&record).prf_seed_uv.clone().unwrap();
    let mut rng = TestRng::new(b"seal");
    let id = ItemId::from_bytes([3; 16]);
    let sealed =
        seal_passkey_item(&mut rng, &vault, id, 1, &record, "example.com", 5, None).unwrap();
    // The envelope is ciphertext: neither the key nor a seed is in it.
    let contains = |needle: &[u8]| sealed.envelope.windows(needle.len()).any(|w| w == needle);
    assert!(!contains(&key_der) && !contains(&seed));
    // Opened again, the record still signs.
    let opened = decrypt_item(&vault, id, 1, &sealed.envelope, &sealed.tag).unwrap();
    let back = PasskeyRecord::from_item(opened.body.passkey.as_ref().unwrap()).unwrap();
    assert!(back.has_prf());
    let g = passkey_get(&back, &get_req(), &ctx("https://example.com"), YES).unwrap();
    let vk = VerifyingKey::from_public_key_der(&created.public_key_spki).unwrap();
    let mut msg = g.authenticator_data.clone();
    msg.extend_from_slice(&Sha256::digest(&g.client_data_json));
    vk.verify(&msg, &Signature::from_der(&g.signature).unwrap())
        .unwrap();
}

fn ctx_vault() -> VaultContext {
    common::ctx()
}

// ------------------------------------------- candidates, site, new fields

fn stored_ref<'a>(rp_id: &'a str, cred_id: &'a [u8]) -> StoredPasskeyRef<'a> {
    StoredPasskeyRef { rp_id, cred_id }
}

#[test]
fn candidates_need_the_exact_rp_id_and_respect_allow() {
    let (a, b, c) = ([1u8; 32], [2u8; 32], [3u8; 32]);
    let stored = [
        stored_ref("example.com", &a),
        stored_ref("login.example.com", &b),
        stored_ref("login.example.com", &c),
        stored_ref("other.test", &a),
    ];
    let page = ctx("https://login.example.com");
    // The RP ID defaults to the host of the origin: only the passkeys of
    // exactly that host, in the order they are stored.
    assert_eq!(
        passkey_candidates(&page, None, &[], &stored).unwrap(),
        [1, 2]
    );
    // `rpId` names the parent: only the passkey of the parent.
    assert_eq!(
        passkey_candidates(&page, Some("example.com"), &[], &stored).unwrap(),
        [0]
    );
    // A non-empty `allow` keeps the listed ids, and only those.
    assert_eq!(
        passkey_candidates(&page, None, &[c.to_vec()], &stored).unwrap(),
        [2]
    );
    assert_eq!(
        passkey_candidates(&page, None, &[c.to_vec(), b.to_vec(), vec![9; 5]], &stored).unwrap(),
        [1, 2]
    );
    // An id that is stored for another RP ID is not a candidate here, and
    // an id that is not stored at all is not an error.
    assert!(
        passkey_candidates(&page, None, &[a.to_vec()], &stored)
            .unwrap()
            .is_empty()
    );
    assert!(
        passkey_candidates(&page, None, &[vec![0; 32]], &stored)
            .unwrap()
            .is_empty()
    );
    // Nothing stored, nothing found.
    assert!(
        passkey_candidates(&page, None, &[], &[])
            .unwrap()
            .is_empty()
    );
}

#[test]
fn candidates_never_cross_rp_ids() {
    let id = [7u8; 32];
    // Looks like a neighbour of the page, but is not the RP ID of the
    // request: a sibling or a child host, a parent, another registrable
    // domain, a longer name that ends the same way, a name that is not in
    // canonical form (upper case, trailing dot, a space).
    let near = [
        "evil.example.com",
        "sub.login.example.com",
        "notlogin.example.com",
        "login.example.com.evil.test",
        "LOGIN.EXAMPLE.COM",
        "Login.example.com",
        "login.example.com.",
        " login.example.com",
        "login.example.org",
        "example.com",
        "com",
        "",
    ];
    let stored: Vec<StoredPasskeyRef<'_>> = near.iter().map(|rp| stored_ref(rp, &id)).collect();
    let page = ctx("https://login.example.com");
    assert!(
        passkey_candidates(&page, None, &[], &stored)
            .unwrap()
            .is_empty()
    );
    // From the parent's own page, and with the parent named, only the
    // parent's passkey is one.
    let parent = ctx("https://example.com");
    assert_eq!(
        passkey_candidates(&parent, None, &[], &stored).unwrap(),
        [9]
    );
    assert_eq!(
        passkey_candidates(&page, Some("example.com"), &[], &stored).unwrap(),
        [9]
    );
    // An internationalized name is the A-label in the store; the Unicode
    // text is another string and finds nothing.
    let idn = [
        stored_ref("xn--bcher-kva.example", &id),
        stored_ref("b\u{fc}cher.example", &id),
    ];
    assert_eq!(
        passkey_candidates(&ctx("https://xn--bcher-kva.example"), None, &[], &idn).unwrap(),
        [0]
    );
    assert_eq!(
        passkey_candidates(&ctx("https://b\u{fc}cher.example"), None, &[], &idn).unwrap(),
        [0]
    );
    // The two rules are the same rule: a candidate answers a get, and a
    // passkey that is not one does not.
    let (mine, _) = make(&create_req(), YES);
    let other = {
        let mut rng = TestRng::new(b"other site");
        let c = passkey_create(
            &mut rng,
            &create_req(),
            &ctx("https://login.example.com"),
            YES,
            &[],
            1,
        )
        .unwrap();
        c.record
    };
    assert_eq!(other.rp_id, "login.example.com");
    let both = [
        stored_ref(&mine.rp_id, &mine.cred_id),
        stored_ref(&other.rp_id, &other.cred_id),
    ];
    let at = ctx("https://example.com");
    assert_eq!(passkey_candidates(&at, None, &[], &both).unwrap(), [0]);
    assert!(passkey_get(&mine, &get_req(), &at, YES).is_ok());
    assert_eq!(
        passkey_get(&other, &get_req(), &at, YES).err(),
        Some(Error::NotAllowed)
    );
}

#[test]
fn candidates_judge_the_request_as_get_does() {
    let id = [1u8; 32];
    let stored = [stored_ref("example.com", &id)];
    let page = ctx("https://example.com");
    // An RP ID the origin may not use has its own code, which the caller
    // gives the page as SecurityError.
    for bad in [
        "com",
        "other.test",
        "example.com:443",
        "1.2.3.4",
        "*.example.com",
        "",
    ] {
        let err = passkey_candidates(&page, Some(bad), &[], &stored).unwrap_err();
        assert_eq!(err, Error::Malformed(MalformedKind::RpId), "{bad:?}");
        assert_eq!(err.code(), "malformed_rp_id");
    }
    // Cross-origin is the one NotAllowed.
    let mut framed = ctx("https://example.com");
    framed.top_origin_is_same = false;
    assert_eq!(
        passkey_candidates(&framed, None, &[], &stored).err(),
        Some(Error::NotAllowed)
    );
    // The limits of § 9.2.
    let long = vec![vec![0u8; 32]; 201];
    assert_eq!(
        passkey_candidates(&page, None, &long, &stored).err(),
        Some(Error::TooLarge)
    );
    assert_eq!(
        passkey_candidates(&page, None, &[vec![0u8; 1024]], &stored).err(),
        Some(Error::TooLarge)
    );
    let ok = vec![vec![0u8; 1023]; 200];
    assert!(passkey_candidates(&page, None, &ok, &stored).is_ok());
    let long_rp = "a".repeat(1025);
    assert_eq!(
        passkey_candidates(&page, Some(&long_rp), &[], &stored).err(),
        Some(Error::TooLarge)
    );
}

#[test]
fn candidates_for_a_request_check_the_whole_request() {
    let id = [1u8; 32];
    let stored = [stored_ref("example.com", &id)];
    let page = ctx("https://example.com");
    let mut req = get_req();
    req.allow = vec![id.to_vec()];
    assert_eq!(passkey_candidates_for(&page, &req, &stored).unwrap(), [0]);
    // What `passkey_get` would refuse is refused before a chooser is shown.
    let mut big = get_req();
    big.challenge = vec![0; 1025];
    assert_eq!(
        passkey_candidates_for(&page, &big, &stored).err(),
        Some(Error::TooLarge)
    );
    assert_eq!(passkey_get_check(&big), Some(Error::TooLarge));
    let mut prf = get_req();
    prf.prf = Some(PrfRequest {
        eval: None,
        eval_by_credential: vec![(
            vec![9; 32],
            PrfEval {
                first: vec![1],
                second: None,
            },
        )],
    });
    let err = passkey_candidates_for(&page, &prf, &stored).err();
    assert!(err.is_some(), "evalByCredential without allowCredentials");
    assert_eq!(passkey_get_check(&prf), err);
    // The same errors for the parts it shares with passkey_candidates.
    let mut bad_rp = get_req();
    bad_rp.rp_id = Some("com".into());
    assert_eq!(
        passkey_candidates_for(&page, &bad_rp, &stored).err(),
        Some(Error::Malformed(MalformedKind::RpId))
    );
}

/// The error `passkey_get` gives for a request that does not pass
/// validation, for a record that would otherwise match.
fn passkey_get_check(req: &GetRequest) -> Option<Error> {
    let (record, _) = make(&create_req(), YES);
    passkey_get(&record, req, &ctx("https://example.com"), YES).err()
}

#[test]
fn passkey_site_gives_the_canonical_origin_rp_id_and_a_label() {
    let site = passkey_site(&ctx("https://Login.Example.COM:443"), None).unwrap();
    assert_eq!(site.origin, "https://login.example.com");
    assert_eq!(site.rp_id, "login.example.com");
    assert_eq!(site.rp_id_unicode, "login.example.com");
    assert_eq!(site.host_unicode, "login.example.com");
    let site = passkey_site(&ctx("https://login.example.com:8443"), Some("EXAMPLE.com")).unwrap();
    assert_eq!(site.origin, "https://login.example.com:8443");
    assert_eq!(site.rp_id, "example.com");
    // An internationalized name: the A-label is what is compared and signed,
    // the Unicode form is what the window shows next to it.
    let site = passkey_site(&ctx("https://xn--bcher-kva.example"), None).unwrap();
    assert_eq!(site.origin, "https://xn--bcher-kva.example");
    assert_eq!(site.rp_id, "xn--bcher-kva.example");
    assert_eq!(site.rp_id_unicode, "b\u{fc}cher.example");
    assert_eq!(site.host_unicode, "b\u{fc}cher.example");
    let site = passkey_site(
        &ctx("https://b\u{fc}cher.example"),
        Some("b\u{fc}cher.example"),
    )
    .unwrap();
    assert_eq!(site.rp_id, "xn--bcher-kva.example");
    // A label that mixes scripts stays an A-label: Latin letters with a
    // Cyrillic a.
    let mixed = passkey_site(&ctx("https://ex\u{430}mple.com"), None).unwrap();
    assert!(mixed.rp_id.starts_with("xn--"));
    assert_eq!(mixed.rp_id_unicode, mixed.rp_id);
    // The request is judged as it is for a get: a wrong RP ID is
    // `malformed_rp_id`, a cross-origin caller is NotAllowed.
    assert_eq!(
        passkey_site(&ctx("https://example.com"), Some("com")).err(),
        Some(Error::Malformed(MalformedKind::RpId))
    );
    assert_eq!(
        passkey_site(&ctx("https://example.com"), Some("evil.test")).err(),
        Some(Error::Malformed(MalformedKind::RpId))
    );
    let mut framed = ctx("https://example.com");
    framed.top_origin_is_same = false;
    assert_eq!(passkey_site(&framed, None).err(), Some(Error::NotAllowed));
    assert_eq!(
        passkey_site(&ctx("https://example.com"), Some(&"a".repeat(1025))).err(),
        Some(Error::TooLarge)
    );
}

#[test]
fn create_response_has_platform_attachment_and_transports() {
    let (_, response) = make(&create_req(), YES);
    assert_eq!(response.authenticator_attachment, "platform");
    assert_eq!(response.transports, ["hybrid", "internal"]);
    // The same for every request, with or without UV and with prf.
    let mut req = create_req();
    req.prf = Some(PrfCreate::default());
    for uv in [YES, NO_UV] {
        let (_, response) = make(&req, uv);
        assert_eq!(response.authenticator_attachment, "platform");
        assert_eq!(response.transports, ["hybrid", "internal"]);
    }
    // And a get says it was a platform authenticator too.
    let (record, _) = make(&create_req(), YES);
    let got = passkey_get(&record, &get_req(), &ctx("https://example.com"), YES).unwrap();
    assert_eq!(got.authenticator_attachment, "platform");
}

#[test]
fn cred_props_only_when_asked() {
    let mut req = create_req();
    assert!(!req.cred_props);
    let (_, response) = make(&req, YES);
    assert_eq!(response.cred_props, None);
    req.cred_props = true;
    let (record, response) = make(&req, YES);
    assert_eq!(
        response.cred_props.map(|c| c.rk),
        Some(true),
        "the passkey is discoverable"
    );
    // Asking for it changes nothing else: the key and the flags are the
    // ones of the request that did not ask (same draws).
    let (plain, plain_response) = make(&create_req(), YES);
    assert_eq!(item_of(&record).cred_id, item_of(&plain).cred_id);
    assert_eq!(
        response.authenticator_data,
        plain_response.authenticator_data
    );
    // A refused request has no answer, so no credProps either.
    req.user_verification = UserVerification::Required;
    let mut rng = TestRng::new(b"refused");
    assert!(passkey_create(&mut rng, &req, &ctx("https://example.com"), NO_UV, &[], 1).is_err());
}

#[test]
fn an_empty_alg_list_means_es256() {
    // WebAuthn: an empty `pubKeyCredParams` means ES256 and RS256. Ferret
    // makes ES256.
    let mut req = create_req();
    req.algorithms = vec![];
    let (_, response) = make(&req, YES);
    assert_eq!(response.alg, -7);
    // ES256 anywhere in the list is enough.
    req.algorithms = vec![-257, -7];
    assert_eq!(make(&req, YES).1.alg, -7);
    // A list without it is `unsupported`; the extension hands that request
    // to the browser.
    req.algorithms = vec![-257];
    let mut rng = TestRng::new(b"alg");
    assert_eq!(
        passkey_create(&mut rng, &req, &ctx("https://example.com"), YES, &[], 1).err(),
        Some(Error::Unsupported)
    );
    req.algorithms = vec![-8, -36];
    assert_eq!(req.validate().err(), Some(Error::Unsupported));
}

#[test]
fn prf_exists_only_when_create_asked_for_it() {
    // Made without `prf`: no seeds, now and later.
    let (plain, response) = make(&create_req(), YES);
    assert!(!plain.has_prf());
    assert!(response.prf.is_none());
    assert!(item_of(&plain).prf_seed_uv.is_none() && item_of(&plain).prf_seed_nouv.is_none());
    let mut get = get_req();
    get.prf = Some(PrfRequest {
        eval: Some(PrfEval {
            first: vec![1; 16],
            second: None,
        }),
        eval_by_credential: vec![],
    });
    for uv in [YES, NO_UV] {
        let got = passkey_get(&plain, &get, &ctx("https://example.com"), uv).unwrap();
        assert!(got.prf.is_none(), "a later get cannot add prf");
    }
    // The same request to a passkey made with `prf` does answer.
    let mut req = create_req();
    req.prf = Some(PrfCreate::default());
    let (with_prf, response) = make(&req, YES);
    assert!(with_prf.has_prf());
    assert!(response.prf.as_ref().is_some_and(|p| p.enabled));
    let got = passkey_get(&with_prf, &get, &ctx("https://example.com"), YES).unwrap();
    assert!(got.prf.is_some());
    // And a get that does not ask for prf gets none.
    let got = passkey_get(&with_prf, &get_req(), &ctx("https://example.com"), YES).unwrap();
    assert!(got.prf.is_none());
}

/// The entries of the `passkey` member of a body, in the order they are
/// written.
fn passkey_entries(body: &ferret_core::ItemBody) -> Vec<(String, ferret_core::cbor::Value)> {
    use ferret_core::cbor::Value as Cbor;
    let value = body.to_value();
    let Cbor::Map(entries) = &value else {
        panic!("a body is a map")
    };
    let (_, Cbor::Map(passkey)) = entries
        .iter()
        .find(|(k, _)| k.as_str() == "passkey")
        .unwrap()
    else {
        panic!("the passkey is a map")
    };
    passkey.clone()
}

#[test]
fn rp_name_and_display_name_are_optional_and_kept_by_older_readers() {
    use ferret_core::cbor::{self, Value as Cbor};
    use ferret_core::{ItemBody, ItemType};
    // New passkeys carry both texts, as made by create.
    let (record, _) = make(&create_req(), YES);
    let item = item_of(&record);
    assert_eq!(item.rp_name.as_deref(), Some("Example"));
    assert_eq!(item.user_display_name.as_deref(), Some("Alice"));
    assert_eq!(record.rp_name.as_deref(), Some("Example"));
    assert_eq!(record.user_display_name.as_deref(), Some("Alice"));
    let mut body = ItemBody::new(ItemType::Login, "example.com", 1);
    record.attach_to(&mut body);
    let keys: Vec<String> = passkey_entries(&body).into_iter().map(|(k, _)| k).collect();
    assert_eq!(
        keys,
        [
            "cred_id",
            "rp_id",
            "user_handle",
            "user_name",
            "priv",
            "sign_count",
            "created",
            "rp_name",
            "user_display_name"
        ],
        "after the keys the first version wrote, in a fixed order"
    );
    // Written, read and written again: the same bytes, the texts back.
    let bytes = body.to_cbor().unwrap();
    let read = ItemBody::from_cbor(&bytes).unwrap().body;
    let p = read.passkey.as_ref().unwrap();
    assert_eq!(p.rp_name.as_deref(), Some("Example"));
    assert_eq!(p.user_display_name.as_deref(), Some("Alice"));
    assert_eq!(*read.to_cbor().unwrap(), *bytes);
    let back = PasskeyRecord::from_item(p).unwrap();
    assert_eq!(back.rp_name.as_deref(), Some("Example"));

    // Optional: a request without them (empty texts) stores neither key, and
    // a body from before them reads as `None` and is written back without.
    let mut req = create_req();
    req.rp_name = String::new();
    req.user_display_name = String::new();
    let (bare, _) = make(&req, YES);
    let mut bare_body = ItemBody::new(ItemType::Login, "example.com", 1);
    bare.attach_to(&mut bare_body);
    assert!(
        !passkey_entries(&bare_body)
            .iter()
            .any(|(k, _)| k == "rp_name" || k == "user_display_name")
    );
    let bytes = bare_body.to_cbor().unwrap();
    let read = ItemBody::from_cbor(&bytes).unwrap().body;
    assert_eq!(read.passkey.as_ref().unwrap().rp_name, None);
    assert_eq!(read.passkey.as_ref().unwrap().user_display_name, None);
    assert_eq!(*read.to_cbor().unwrap(), *bytes);

    // An older reader does not know the two keys. It keeps every unknown key
    // of the passkey map after the keys it knows, in the order it read them,
    // and writes them back; with the two keys where they are, that is the
    // same bytes.
    const KNOWN_BEFORE: [&str; 7] = [
        "cred_id",
        "rp_id",
        "user_handle",
        "user_name",
        "priv",
        "sign_count",
        "created",
    ];
    let passkey = passkey_entries(&body);
    let mut old_view: Vec<(String, Cbor)> = KNOWN_BEFORE
        .iter()
        .filter_map(|k| passkey.iter().find(|(key, _)| key == k).cloned())
        .collect();
    old_view.extend(
        passkey
            .iter()
            .filter(|(k, _)| !KNOWN_BEFORE.contains(&k.as_str()))
            .cloned(),
    );
    assert_eq!(
        cbor::encode(&Cbor::Map(old_view)).unwrap(),
        cbor::encode(&Cbor::Map(passkey)).unwrap()
    );
    // The mechanism it relies on, with the real reader: an unknown key at
    // that place survives a read and a write, byte for byte.
    let mut future = ItemBody::new(ItemType::Login, "example.com", 1);
    let mut item = item_of(&bare);
    item.extra = vec![("rp_nickname".into(), Cbor::text("kept"))];
    future.passkey = Some(item);
    let bytes = future.to_cbor().unwrap();
    let read = ItemBody::from_cbor(&bytes).unwrap().body;
    assert_eq!(
        read.passkey.as_ref().unwrap().extra,
        [("rp_nickname".to_owned(), Cbor::text("kept"))]
    );
    assert_eq!(*read.to_cbor().unwrap(), *bytes);
    // A name of another type is not a name: it is kept as it is, and no name
    // is invented.
    let mut value = future.to_value();
    let Cbor::Map(entries) = &mut value else {
        panic!()
    };
    for (k, v) in entries.iter_mut() {
        if k.as_str() == "passkey" {
            let Cbor::Map(pk) = v else { panic!() };
            pk.push(("rp_name".into(), Cbor::Bytes(vec![1, 2, 3])));
        }
    }
    // In a body of this schema that is refused, as for the other keys; a body
    // of a newer schema is read leniently and keeps the key as it is.
    assert_eq!(
        ItemBody::from_cbor(&cbor::encode(&value).unwrap()).err(),
        Some(Error::Malformed(MalformedKind::ItemBody))
    );
    let Cbor::Map(entries) = &mut value else {
        panic!()
    };
    for (k, v) in entries.iter_mut() {
        if k.as_str() == "schema" {
            *v = Cbor::uint(2);
        }
    }
    let odd = ItemBody::from_cbor(&cbor::encode(&value).unwrap())
        .unwrap()
        .body;
    assert_eq!(odd.passkey.as_ref().unwrap().rp_name, None);
    assert!(
        odd.passkey
            .as_ref()
            .unwrap()
            .extra
            .iter()
            .any(|(k, v)| k == "rp_name" && *v == Cbor::Bytes(vec![1, 2, 3]))
    );
}

#[test]
fn control_characters_are_removed_from_site_texts() {
    let mut req = create_req();
    req.rp_name = "Ex\u{0}am\nple\u{7f}\u{85}\t site".into();
    req.user_name = "al\u{1b}[31mice\r\n@example.com".into();
    req.user_display_name = "\u{8}Alice \u{9c}A\u{0}".into();
    let (record, _) = make(&req, YES);
    assert_eq!(record.rp_name.as_deref(), Some("Example site"));
    assert_eq!(record.user_name, "al[31mice@example.com");
    assert_eq!(record.user_display_name.as_deref(), Some("Alice A"));
    let item = item_of(&record);
    assert_eq!(item.rp_name.as_deref(), Some("Example site"));
    assert_eq!(item.user_name, "al[31mice@example.com");
    // Every class the name rule of folders and methods refuses goes: bidi
    // controls (an override would reorder the RP ID next to the name),
    // line and paragraph separators, the Arabic letter mark, zero-width
    // space and the byte order mark. A joiner is no part of the list.
    for c in [
        '\u{202a}', '\u{202b}', '\u{202c}', '\u{202d}', '\u{202e}', '\u{2066}', '\u{2067}',
        '\u{2068}', '\u{2069}', '\u{200e}', '\u{200f}', '\u{061c}', '\u{2028}', '\u{2029}',
        '\u{200b}', '\u{feff}',
    ] {
        req.rp_name = format!("ab{c}cd");
        req.user_name = format!("{c}name{c}");
        req.user_display_name = format!("{c}{c}");
        let (record, _) = make(&req, YES);
        assert_eq!(
            record.rp_name.as_deref(),
            Some("abcd"),
            "U+{:04X}",
            u32::from(c)
        );
        assert_eq!(record.user_name, "name", "U+{:04X}", u32::from(c));
        assert_eq!(record.user_display_name, None, "U+{:04X}", u32::from(c));
    }
    req.rp_name = "\u{202e}moc.elgoog\u{2066} bank".into();
    req.user_name = "x".into();
    req.user_display_name = "Al\u{200d}ice \u{1f469}\u{200d}\u{1f4bb}".into();
    let (record, _) = make(&req, YES);
    assert_eq!(record.rp_name.as_deref(), Some("moc.elgoog bank"));
    assert_eq!(
        record.user_display_name.as_deref(),
        Some("Al\u{200d}ice \u{1f469}\u{200d}\u{1f4bb}")
    );
    // Text of other scripts and emoji is text: kept as it is.
    req.rp_name = "Caf\u{e9} \u{65e5}\u{672c} \u{1f980}".into();
    req.user_display_name = "\u{c5}se".into();
    let (record, _) = make(&req, YES);
    assert_eq!(
        record.rp_name.as_deref(),
        Some("Caf\u{e9} \u{65e5}\u{672c} \u{1f980}")
    );
    assert_eq!(record.user_display_name.as_deref(), Some("\u{c5}se"));
    // Nothing but control characters is no name.
    req.rp_name = "\u{0}\n\t".into();
    req.user_display_name = "\u{7f}".into();
    let (record, _) = make(&req, YES);
    assert_eq!(record.rp_name, None);
    assert_eq!(record.user_display_name, None);
    // The limit is 1 KiB of the text as the site sent it.
    req.rp_name = "a".repeat(1025);
    assert_eq!(req.validate().err(), Some(Error::TooLarge));
    req.rp_name = "a".repeat(1024);
    req.user_display_name = format!("{}{}", "b".repeat(1024), "\u{0}");
    assert_eq!(req.validate().err(), Some(Error::TooLarge));
    req.user_display_name = "b".repeat(1024);
    assert!(req.validate().is_ok());
    let (record, _) = make(&req, YES);
    assert_eq!(record.rp_name.as_deref().map(str::len), Some(1024));
}

#[test]
fn user_id_of_0_or_65_bytes_is_refused() {
    let mut req = create_req();
    let mut rng = TestRng::new(b"user id");
    let c = ctx("https://example.com");
    for len in [0usize, 65, 1000] {
        req.user_id = vec![5; len];
        assert_eq!(
            passkey_create(&mut rng, &req, &c, YES, &[], 1).err(),
            Some(Error::Malformed(MalformedKind::WebauthnOptions)),
            "{len} bytes"
        );
    }
    for len in [1usize, 16, 64] {
        req.user_id = vec![5; len];
        assert!(
            passkey_create(&mut rng, &req, &c, YES, &[], 1).is_ok(),
            "{len} bytes"
        );
    }
}

#[test]
fn vectors_passkey_candidates_pass() {
    let keep = |op: &str| matches!(op, "passkey.candidates" | "passkey.site");
    let file = load_ops("passkey.json", keep);
    let report = run_vectors(keep);
    assert_all_passed(&report, 20);
    for op in ["passkey.candidates", "passkey.site"] {
        let n = file.cases.iter().filter(|c| c.op == op).count();
        assert!(n >= 8, "{op} has {n} cases");
    }
    assert!(
        file.cases
            .iter()
            .any(|c| c.status == ferret_core::testing::vector::Status::Invalid)
    );
}
