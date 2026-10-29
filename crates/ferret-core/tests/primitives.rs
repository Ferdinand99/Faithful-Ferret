//! Known-answer and behaviour tests of the primitives: Argon2id and its
//! bounds, HKDF, XChaCha20-Poly1305, HMAC and Ed25519.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]

use ed25519_dalek::Verifier as _;
use ferret_core::testing::prim::{
    aead_open, aead_seal, argon2_run_count, argon2id, argon2id_unchecked, ct_eq,
    ed25519_public_key, ed25519_sign, ed25519_verify, hkdf_sha256, hmac_sha256,
};
use ferret_core::testing::vector::{self, Case, Outcome};
use ferret_core::testing::{ReplayRng, hex_decode, hex_encode};
use ferret_core::{
    Error, InputError, KDF_CEIL, KDF_FLOOR, KdfParams, OsRng, SecureRng, check_kdf_params,
};
use serde_json::{Value, json};
use std::collections::HashSet;
use std::path::{Path, PathBuf};

fn vectors_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../vectors")
}

fn load_json(relative: &str) -> Value {
    let path = vectors_dir().join(relative);
    serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
}

fn hex(v: &Value) -> Vec<u8> {
    hex_decode(v.as_str().unwrap()).unwrap()
}

fn hex32(v: &Value) -> [u8; 32] {
    hex(v).try_into().unwrap()
}

// ------------------------------------------------------------- Argon2id

#[test]
fn argon2id_rfc9106_vector() {
    // RFC 9106 section 5.3: secret 8 x 03, associated data 12 x 04,
    // m = 32 KiB, t = 3, p = 4. Only the unchecked test path can run it,
    // because 32 KiB is far below the floor.
    let file = load_json("external/rfc9106-argon2id.json");
    let case = &file["cases"][0];
    let mut out = [0u8; 32];
    argon2id_unchecked(
        &hex(&case["password"]),
        &hex(&case["salt"]),
        &hex(&case["secret"]),
        &hex(&case["associated_data"]),
        KdfParams {
            m_kib: 32,
            t: 3,
            p: 4,
        },
        &mut out,
    )
    .unwrap();
    assert_eq!(hex_encode(&out), case["tag"].as_str().unwrap());
    assert_eq!(
        hex_encode(&out),
        "0d640df58d78766c08c037a34a8b53c9d01ef0452d75b65eb52520e96b01e659"
    );
}

#[test]
fn argon2id_public_path_cannot_run_the_rfc_vector() {
    // The same parameters through the checked path are refused.
    let mut out = [0u8; 32];
    let before = argon2_run_count();
    assert_eq!(
        argon2id(
            &[1; 32],
            &[2; 16],
            KdfParams {
                m_kib: 32,
                t: 3,
                p: 4
            },
            &mut out
        ),
        Err(Error::KdfOutOfRange)
    );
    assert_eq!(argon2_run_count(), before);
}

/// Argon2id from the previous generation of the crate (0.5), an independent
/// implementation of the same algorithm.
fn argon2id_05(pwd: &[u8], salt: &[u8], p: KdfParams, out_len: usize) -> Vec<u8> {
    use argon2_05::{Algorithm, Argon2, Params, Version};
    let params = Params::new(p.m_kib, p.t, p.p, Some(out_len)).unwrap();
    let mut out = vec![0u8; out_len];
    Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
        .hash_password_into(pwd, salt, &mut out)
        .unwrap();
    out
}

#[test]
fn argon2id_profile1_known_answer() {
    let file = vector::load(&vectors_dir().join("internal/kdf.json")).unwrap();
    let report = vector::run_all(&file, |case: &Case, _rng: &mut ReplayRng| {
        assert_eq!(case.op, "kdf.argon2id");
        let input = &case.input;
        let (pwd, salt) = (hex(&input["password"]), hex(&input["salt"]));
        let p = KdfParams {
            m_kib: u32::try_from(input["m_kib"].as_u64().unwrap()).unwrap(),
            t: u32::try_from(input["t"].as_u64().unwrap()).unwrap(),
            p: u32::try_from(input["p"].as_u64().unwrap()).unwrap(),
        };
        let out_len = usize::try_from(input["out_len"].as_u64().unwrap()).unwrap();
        let mut out = vec![0u8; out_len];
        argon2id(&pwd, &salt, p, &mut out)?;
        Ok(Outcome {
            output: json!({ "hash": hex_encode(&out) }),
            intermediate: None,
        })
    });
    assert!(report.failures.is_empty(), "{:?}", report.failures);
    assert_eq!(report.passed, file.cases.len());

    // Every valid case also agrees with the independent implementation.
    let mut known_answers = 0;
    for case in file.cases.iter().filter(|c| c.expect.is_some()) {
        let input = &case.input;
        let p = KdfParams {
            m_kib: u32::try_from(input["m_kib"].as_u64().unwrap()).unwrap(),
            t: u32::try_from(input["t"].as_u64().unwrap()).unwrap(),
            p: u32::try_from(input["p"].as_u64().unwrap()).unwrap(),
        };
        let out_len = usize::try_from(input["out_len"].as_u64().unwrap()).unwrap();
        let independent = argon2id_05(&hex(&input["password"]), &hex(&input["salt"]), p, out_len);
        assert_eq!(
            hex_encode(&independent),
            case.expect.as_ref().unwrap()["hash"].as_str().unwrap(),
            "{}: argon2 0.5 disagrees",
            case.id
        );
        known_answers += 1;
    }
    assert!(known_answers >= 3);
}

#[test]
fn kdf_floor_rejects_below() {
    for p in [
        KdfParams {
            m_kib: 65_535,
            t: 3,
            p: 1,
        },
        KdfParams {
            m_kib: 65_536,
            t: 2,
            p: 1,
        },
        KdfParams {
            m_kib: 65_536,
            t: 3,
            p: 0,
        },
        KdfParams {
            m_kib: 65_536,
            t: 3,
            p: 5,
        },
    ] {
        let before = argon2_run_count();
        let mut out = [0u8; 32];
        assert_eq!(
            argon2id(b"password", b"saltsalt", p, &mut out),
            Err(Error::KdfOutOfRange),
            "{p:?}"
        );
        assert_eq!(check_kdf_params(p), Err(Error::KdfOutOfRange), "{p:?}");
        assert_eq!(argon2_run_count(), before, "{p:?}: nothing may be computed");
        assert_eq!(out, [0u8; 32], "{p:?}: the output must stay untouched");
    }
}

#[test]
fn kdf_ceil_rejects_above() {
    for p in [
        KdfParams {
            m_kib: 1_048_577,
            t: 3,
            p: 1,
        },
        KdfParams {
            m_kib: 65_536,
            t: 17,
            p: 1,
        },
        // Above the clarified 512 MiB memory ceiling, below the design's 1 GiB.
        KdfParams {
            m_kib: 524_289,
            t: 3,
            p: 1,
        },
        KdfParams {
            m_kib: u32::MAX,
            t: u32::MAX,
            p: u32::MAX,
        },
    ] {
        let before = argon2_run_count();
        let mut out = [0u8; 32];
        assert_eq!(
            argon2id(b"password", b"saltsalt", p, &mut out),
            Err(Error::KdfOutOfRange),
            "{p:?}"
        );
        assert_eq!(argon2_run_count(), before, "{p:?}: nothing may be computed");
    }
}

#[test]
fn kdf_bounds_are_inclusive_and_constant() {
    assert_eq!(
        KDF_FLOOR,
        KdfParams {
            m_kib: 65_536,
            t: 3,
            p: 1
        }
    );
    assert_eq!(
        KDF_CEIL,
        KdfParams {
            m_kib: 524_288,
            t: 16,
            p: 4
        }
    );
    // The floor and the ceiling themselves are accepted, as is every lane count 1..=4.
    assert_eq!(check_kdf_params(KDF_FLOOR), Ok(KDF_FLOOR));
    assert_eq!(check_kdf_params(KDF_CEIL), Ok(KDF_CEIL));
    for p in 1..=4 {
        let params = KdfParams { p, ..KDF_FLOOR };
        assert_eq!(check_kdf_params(params), Ok(params));
    }
    // Every dimension is checked on its own.
    assert!(check_kdf_params(KdfParams { t: 17, ..KDF_CEIL }).is_err());
    assert!(check_kdf_params(KdfParams { p: 5, ..KDF_CEIL }).is_err());
    assert!(
        check_kdf_params(KdfParams {
            m_kib: 524_289,
            ..KDF_CEIL
        })
        .is_err()
    );
}

#[test]
fn argon2id_short_inputs_are_input_errors() {
    let mut out = [0u8; 32];
    // The salt must be at least 8 bytes; this is not an authentication error.
    assert_eq!(
        argon2id(b"password", b"1234567", KDF_FLOOR, &mut out),
        Err(Error::InvalidInput(InputError::TooShort))
    );
    // Output of fewer than 4 bytes.
    let mut tiny = [0u8; 3];
    assert_eq!(
        argon2id(b"password", b"12345678", KDF_FLOOR, &mut tiny),
        Err(Error::InvalidInput(InputError::TooShort))
    );
}

// ----------------------------------------------------------------- HKDF

#[test]
fn hkdf_rfc5869_cases_1_to_3() {
    let file = load_json("external/rfc5869-hkdf.json");
    let cases = file["cases"].as_array().unwrap();
    assert_eq!(cases.len(), 3);
    for case in cases {
        let (ikm, salt, info) = (hex(&case["ikm"]), hex(&case["salt"]), hex(&case["info"]));
        let len = usize::try_from(case["length"].as_u64().unwrap()).unwrap();
        let mut okm = vec![0u8; len];
        hkdf_sha256(&salt, &ikm, &info, &mut okm).unwrap();
        assert_eq!(
            hex_encode(&okm),
            case["okm"].as_str().unwrap(),
            "{}",
            case["id"]
        );
        // The extract step is HMAC(salt, ikm); an empty salt is the same as
        // 32 zero bytes (case A.3).
        let prk = hmac_sha256(&salt, &ikm).unwrap();
        assert_eq!(
            hex_encode(&prk),
            case["prk"].as_str().unwrap(),
            "{}",
            case["id"]
        );
    }
}

#[test]
fn hkdf_output_limit_is_255_blocks() {
    let mut max = vec![0u8; 255 * 32];
    hkdf_sha256(b"salt", b"ikm", b"info", &mut max).unwrap();
    let mut too_long = vec![0u8; 255 * 32 + 1];
    assert_eq!(
        hkdf_sha256(b"salt", b"ikm", b"info", &mut too_long),
        Err(Error::TooLarge)
    );
}

// ------------------------------------------------------ XChaCha20-Poly1305

#[test]
fn xchacha_draft_vector() {
    // draft-irtf-cfrg-xchacha-03, appendix A.3.1.
    let file = load_json("external/xchacha-draft-03.json");
    let case = &file["cases"][0];
    let (key, nonce) = (hex32(&case["key"]), hex(&case["nonce"]));
    let (aad, pt) = (hex(&case["aad"]), hex(&case["plaintext"]));
    let mut expected = nonce.clone();
    expected.extend_from_slice(&hex(&case["ciphertext"]));
    expected.extend_from_slice(&hex(&case["tag"]));

    // The draw of the nonce is replayed, so the output is fixed.
    let mut rng = ReplayRng::new(vec![nonce]);
    let sealed = aead_seal(&mut rng, &key, &aad, &pt).unwrap();
    rng.finish().unwrap();
    assert_eq!(sealed, expected);
    assert_eq!(aead_open(&key, &aad, &expected).unwrap(), pt);

    // A fresh random nonce still round-trips.
    let again = aead_seal(&mut OsRng, &key, &aad, &pt).unwrap();
    assert_ne!(again, sealed);
    assert_eq!(aead_open(&key, &aad, &again).unwrap(), pt);
}

#[test]
fn aead_layout_and_roundtrip() {
    let key = [7u8; 32];
    for len in [0usize, 1, 15, 16, 17, 63, 64, 65, 1000] {
        let pt = vec![0x5a; len];
        let blob = aead_seal(&mut OsRng, &key, b"aad", &pt).unwrap();
        assert_eq!(blob.len(), 24 + len + 16, "nonce, ciphertext, tag");
        assert_eq!(aead_open(&key, b"aad", &blob).unwrap(), pt);
    }
}

/// A draw-counting RNG: proves that one `aead_seal` is one 24-byte draw.
struct CountingRng {
    draws: Vec<usize>,
}

impl SecureRng for CountingRng {
    fn fill(&mut self, dest: &mut [u8]) {
        self.draws.push(dest.len());
        OsRng.fill(dest);
    }
}

#[test]
fn aead_nonce_unique_10000() {
    let key = [9u8; 32];
    let mut nonces = HashSet::new();
    let mut rng = CountingRng { draws: Vec::new() };
    for _ in 0..10_000 {
        let blob = aead_seal(&mut rng, &key, b"", b"x").unwrap();
        assert!(nonces.insert(blob[..24].to_vec()), "a nonce repeated");
    }
    assert_eq!(nonces.len(), 10_000);
    assert_eq!(rng.draws.len(), 10_000);
    assert!(
        rng.draws.iter().all(|n| *n == 24),
        "one 24-byte draw per seal"
    );
}

#[test]
fn aead_all_failures_same_error() {
    let key = [1u8; 32];
    let blob = aead_seal(&mut OsRng, &key, b"context", b"secret plaintext").unwrap();
    let mut flipped = blob.clone();
    flipped[30] ^= 1;

    let failures = [
        aead_open(&[2u8; 32], b"context", &blob), // wrong key
        aead_open(&key, b"other", &blob),         // wrong AAD
        aead_open(&key, b"", &blob),              // missing AAD
        aead_open(&key, b"context", &flipped),    // changed byte
        aead_open(&key, b"context", &blob[..blob.len() - 1]), // truncated
        aead_open(&key, b"context", &blob[..39]), // shorter than nonce + tag
        aead_open(&key, b"context", &blob[..24]), // nonce only
        aead_open(&key, b"context", &[]),         // empty
    ];
    for failure in failures {
        assert_eq!(failure, Err(Error::Decrypt));
        assert_eq!(failure.unwrap_err().code(), "decrypt");
    }
    // And the untouched blob still opens.
    assert_eq!(
        aead_open(&key, b"context", &blob).unwrap(),
        b"secret plaintext"
    );
}

#[test]
fn aead_every_bit_flip_fails() {
    let key = [3u8; 32];
    let blob = aead_seal(&mut OsRng, &key, b"aad", b"short").unwrap();
    assert_eq!(blob.len(), 24 + 5 + 16);
    for byte in 0..blob.len() {
        for bit in 0..8 {
            let mut broken = blob.clone();
            broken[byte] ^= 1 << bit;
            assert_eq!(
                aead_open(&key, b"aad", &broken),
                Err(Error::Decrypt),
                "byte {byte} bit {bit}"
            );
        }
    }
}

// ----------------------------------------------------------------- HMAC

#[test]
fn hmac_sha256_known_answers() {
    // RFC 4231 test case 1 and 2.
    let tag = hmac_sha256(&[0x0b; 20], b"Hi There").unwrap();
    assert_eq!(
        hex_encode(&tag),
        "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"
    );
    let tag = hmac_sha256(b"Jefe", b"what do ya want for nothing?").unwrap();
    assert_eq!(
        hex_encode(&tag),
        "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
    );
}

#[test]
fn ct_eq_compares_content_and_length() {
    assert!(ct_eq(b"", b""));
    assert!(ct_eq(b"abc", b"abc"));
    assert!(!ct_eq(b"abc", b"abd"));
    assert!(!ct_eq(b"abc", b"ab"));
    assert!(!ct_eq(b"ab", b"abc"));
}

// -------------------------------------------------------------- Ed25519

#[test]
fn rfc8032_test_vectors_1_2_3_1024_sha() {
    let file = load_json("external/rfc8032-ed25519.json");
    let cases = file["cases"].as_array().unwrap();
    let ids: Vec<&str> = cases.iter().map(|c| c["id"].as_str().unwrap()).collect();
    assert_eq!(
        ids,
        [
            "rfc8032/1",
            "rfc8032/2",
            "rfc8032/3",
            "rfc8032/1024",
            "rfc8032/SHA(abc)"
        ]
    );
    for case in cases {
        let (seed, public) = (hex32(&case["secret_key"]), hex32(&case["public_key"]));
        let (msg, sig) = (hex(&case["message"]), hex(&case["signature"]));
        let sig: [u8; 64] = sig.try_into().unwrap();
        let id = case["id"].as_str().unwrap();

        assert_eq!(ed25519_public_key(&seed), public, "{id}: public key");
        assert_eq!(ed25519_sign(&seed, &msg).unwrap(), sig, "{id}: signature");
        assert_eq!(ed25519_verify(&public, &msg, &sig), Ok(()), "{id}: verify");

        // A changed message, signature or key is refused with the one error.
        let mut other_msg = msg.clone();
        other_msg.push(0);
        assert_eq!(
            ed25519_verify(&public, &other_msg, &sig),
            Err(Error::Decrypt),
            "{id}"
        );
        for byte in [0usize, 31, 32, 63] {
            let mut broken = sig;
            broken[byte] ^= 0x01;
            assert_eq!(
                ed25519_verify(&public, &msg, &broken),
                Err(Error::Decrypt),
                "{id}"
            );
        }
        let mut other_key = public;
        other_key[5] ^= 0x01;
        assert_eq!(
            ed25519_verify(&other_key, &msg, &sig),
            Err(Error::Decrypt),
            "{id}"
        );
    }
}

/// The group order L of Ed25519, little-endian (RFC 8032 section 5.1).
const GROUP_ORDER_LE: [u8; 32] = [
    0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x10,
];

/// `s + L` as 32 little-endian bytes (no overflow for `s < L`).
fn add_group_order(s: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    let mut carry = 0u16;
    for i in 0..32 {
        let sum = u16::from(s[i]) + u16::from(GROUP_ORDER_LE[i]) + carry;
        out[i] = (sum & 0xff) as u8;
        carry = sum >> 8;
    }
    assert_eq!(carry, 0);
    out
}

#[test]
fn ed25519_rejects_identity_key_with_zero_s() {
    // The public key is the identity point (small order) and the signature is
    // R = identity, S = 0. The plain RFC 8032 check [S]B = R + [k]A passes for
    // every message; the strict check refuses small-order keys.
    let mut identity = [0u8; 32];
    identity[0] = 1;
    let mut sig = [0u8; 64];
    sig[0] = 1; // R = identity, S = 0

    for msg in [&b""[..], b"any message", &[0u8; 100]] {
        // Guard: the lenient verifier of the same crate accepts it, so this
        // test fails if `verify_strict` is ever swapped for `verify`.
        let lenient = ed25519_dalek::VerifyingKey::from_bytes(&identity).unwrap();
        assert!(
            lenient
                .verify(msg, &ed25519_dalek::Signature::from_bytes(&sig))
                .is_ok(),
            "the crate's plain verify should accept this signature"
        );
        assert_eq!(ed25519_verify(&identity, msg, &sig), Err(Error::Decrypt));
    }
}

#[test]
fn ed25519_rejects_small_order_r() {
    // A small-order R (the identity) under an honest key with S = 0: refused
    // as an ordinary bad signature.
    let seed = [0x42u8; 32];
    let public = ed25519_public_key(&seed);
    let mut sig = [0u8; 64];
    sig[0] = 1;
    assert_eq!(ed25519_verify(&public, b"msg", &sig), Err(Error::Decrypt));
}

#[test]
fn ed25519_rejects_non_canonical_s() {
    let file = load_json("external/rfc8032-ed25519.json");
    for case in file["cases"].as_array().unwrap() {
        let public = hex32(&case["public_key"]);
        let msg = hex(&case["message"]);
        let sig: [u8; 64] = hex(&case["signature"]).try_into().unwrap();
        assert_eq!(ed25519_verify(&public, &msg, &sig), Ok(()));

        // S + L is the same scalar modulo L but not the canonical encoding.
        let mut malleable = sig;
        malleable[32..].copy_from_slice(&add_group_order(&sig[32..]));
        assert_ne!(malleable, sig);
        assert_eq!(
            ed25519_verify(&public, &msg, &malleable),
            Err(Error::Decrypt),
            "{}: S + L must be rejected",
            case["id"]
        );
    }
}
