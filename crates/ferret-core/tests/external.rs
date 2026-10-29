//! Adapters that run the Wycheproof files (vectors/external/wycheproof/)
//! against the primitives. The files are kept in their original format; each
//! test knows how to read one of them.
//!
//! Wycheproof results: `valid` must succeed, `invalid` must fail, and
//! `acceptable` may go either way (the outcome is printed).

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]

use chacha20poly1305::{AeadInOut, ChaCha20Poly1305, KeyInit};
use ferret_core::Error;
use ferret_core::testing::prim::{aead_open, aead_seal, ed25519_verify, hkdf_sha256, hmac_sha256};
use ferret_core::testing::{ReplayRng, hex_decode};
use serde_json::Value;
use std::path::{Path, PathBuf};

fn wycheproof(name: &str) -> Value {
    let path: PathBuf = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../vectors/external/wycheproof")
        .join(name);
    let value: Value = serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
    value
}

fn hex(v: &Value) -> Vec<u8> {
    hex_decode(v.as_str().unwrap()).unwrap()
}

/// Every test of every group, with its group, checking the file's own count.
fn tests(file: &Value) -> Vec<(&Value, &Value)> {
    let all: Vec<(&Value, &Value)> = file["testGroups"]
        .as_array()
        .unwrap()
        .iter()
        .flat_map(|g| g["tests"].as_array().unwrap().iter().map(move |t| (g, t)))
        .collect();
    assert_eq!(
        all.len() as u64,
        file["numberOfTests"].as_u64().unwrap(),
        "the file's own count"
    );
    all
}

#[derive(Default, Debug)]
struct Tally {
    valid: usize,
    invalid: usize,
    acceptable_accepted: usize,
    acceptable_rejected: usize,
}

impl Tally {
    fn result(&mut self, kind: &str, accepted: bool, id: &str, what: &str) {
        match (kind, accepted) {
            ("valid", true) => self.valid += 1,
            ("invalid", false) => self.invalid += 1,
            ("acceptable", true) => self.acceptable_accepted += 1,
            ("acceptable", false) => self.acceptable_rejected += 1,
            (kind, accepted) => panic!("{what} {id}: result {kind} but accepted = {accepted}"),
        }
    }
}

// ------------------------------------------------------------- AEAD

#[test]
fn wycheproof_xchacha20_poly1305() {
    let file = wycheproof("xchacha20_poly1305_test.json");
    let mut tally = Tally::default();
    for (group, t) in tests(&file) {
        assert_eq!(group["tagSize"], 128);
        let id = t["tcId"].to_string();
        let key: Result<[u8; 32], _> = hex(&t["key"]).try_into();
        let (iv, aad, msg) = (hex(&t["iv"]), hex(&t["aad"]), hex(&t["msg"]));
        let (ct, tag) = (hex(&t["ct"]), hex(&t["tag"]));
        let mut blob = iv.clone();
        blob.extend_from_slice(&ct);
        blob.extend_from_slice(&tag);

        let opened = match key {
            Ok(key) => aead_open(&key, &aad, &blob),
            Err(_) => Err(Error::Decrypt),
        };
        match t["result"].as_str().unwrap() {
            "valid" => {
                assert_eq!(opened, Ok(msg.clone()), "tc {id}: open");
                // Sealing with the same nonce gives the same blob.
                let key: [u8; 32] = hex(&t["key"]).try_into().unwrap();
                let mut rng = ReplayRng::new(vec![iv]);
                let sealed = aead_seal(&mut rng, &key, &aad, &msg).unwrap();
                rng.finish().unwrap();
                assert_eq!(sealed, blob, "tc {id}: seal");
                tally.valid += 1;
            }
            "invalid" => {
                assert_eq!(
                    opened,
                    Err(Error::Decrypt),
                    "tc {id}: must fail with decrypt"
                );
                tally.invalid += 1;
            }
            other => panic!("tc {id}: unexpected result {other}"),
        }
    }
    println!("xchacha20-poly1305: {tally:?}");
    assert_eq!(tally.valid + tally.invalid, 315);
}

#[test]
fn wycheproof_chacha20_poly1305() {
    // Not used by the core (the design uses the extended-nonce variant); this
    // checks the same crate's 96-bit-nonce cipher against the same vectors.
    let file = wycheproof("chacha20_poly1305_test.json");
    let mut tally = Tally::default();
    for (_, t) in tests(&file) {
        let id = t["tcId"].to_string();
        let (key, iv) = (hex(&t["key"]), hex(&t["iv"]));
        let (aad, msg) = (hex(&t["aad"]), hex(&t["msg"]));
        let (ct, tag) = (hex(&t["ct"]), hex(&t["tag"]));
        let mut buf = ct.clone();
        buf.extend_from_slice(&tag);

        let accepted = match (
            <[u8; 32]>::try_from(key.as_slice()),
            <[u8; 12]>::try_from(iv.as_slice()),
        ) {
            (Ok(key), Ok(iv)) => {
                let cipher = ChaCha20Poly1305::new(&key.into());
                let ok = cipher.decrypt_in_place(&iv.into(), &aad, &mut buf).is_ok();
                if ok {
                    assert_eq!(buf, msg, "tc {id}");
                }
                ok
            }
            _ => false,
        };
        tally.result(
            t["result"].as_str().unwrap(),
            accepted,
            &id,
            "chacha20-poly1305",
        );
    }
    println!("chacha20-poly1305: {tally:?}");
    assert_eq!(tally.valid + tally.invalid, 325);
}

// ---------------------------------------------------------- signatures

#[test]
fn wycheproof_ed25519_verify() {
    let file = wycheproof("ed25519_test.json");
    let mut tally = Tally::default();
    for (group, t) in tests(&file) {
        let id = t["tcId"].to_string();
        let public: [u8; 32] = hex(&group["publicKey"]["pk"]).try_into().unwrap();
        let (msg, sig) = (hex(&t["msg"]), hex(&t["sig"]));
        let accepted = match <[u8; 64]>::try_from(sig.as_slice()) {
            Ok(sig) => ed25519_verify(&public, &msg, &sig).is_ok(),
            Err(_) => false,
        };
        tally.result(t["result"].as_str().unwrap(), accepted, &id, "ed25519");
    }
    println!("ed25519 verify: {tally:?}");
    assert_eq!(tally.valid, 117);
    assert_eq!(tally.invalid, 64);
    // The strict verifier pins the "acceptable" cases: the 8 small-order public
    // keys are rejected and the 21 mixed-order ones are accepted. Swapping
    // `verify_strict` for `verify` accepts all 8 and fails here.
    assert_eq!(
        tally.acceptable_rejected, 8,
        "small-order keys are rejected"
    );
    assert_eq!(
        tally.acceptable_accepted, 21,
        "mixed-order keys are accepted"
    );
}

#[test]
fn wycheproof_ecdsa_p256_sha256_verify() {
    // The verifier is the one the passkey code will use (p256 0.14).
    use p256::ecdsa::signature::Verifier;
    use p256::ecdsa::{Signature, VerifyingKey};

    let file = wycheproof("ecdsa_secp256r1_sha256_test.json");
    let mut tally = Tally::default();
    for (group, t) in tests(&file) {
        assert_eq!(group["sha"], "SHA-256");
        let id = t["tcId"].to_string();
        let key = VerifyingKey::from_sec1_bytes(&hex(&group["publicKey"]["uncompressed"])).unwrap();
        let (msg, sig) = (hex(&t["msg"]), hex(&t["sig"]));
        let accepted = match Signature::from_der(&sig) {
            Ok(sig) => key.verify(&msg, &sig).is_ok(),
            Err(_) => false,
        };
        tally.result(t["result"].as_str().unwrap(), accepted, &id, "ecdsa p256");
    }
    println!("ecdsa p256 verify: {tally:?}");
    assert_eq!(tally.valid, 174);
    assert_eq!(tally.invalid, 310);
}

// ------------------------------------------------------------ HKDF, HMAC

#[test]
fn wycheproof_hkdf_sha256_and_hmac_sha256() {
    // HKDF-SHA256.
    let file = wycheproof("hkdf_sha256_test.json");
    let mut tally = Tally::default();
    for (_, t) in tests(&file) {
        let id = t["tcId"].to_string();
        let (ikm, salt, info) = (hex(&t["ikm"]), hex(&t["salt"]), hex(&t["info"]));
        let size = usize::try_from(t["size"].as_u64().unwrap()).unwrap();
        let mut okm = vec![0u8; size];
        let accepted = hkdf_sha256(&salt, &ikm, &info, &mut okm).is_ok();
        if accepted {
            assert_eq!(okm, hex(&t["okm"]), "hkdf tc {id}");
        }
        tally.result(t["result"].as_str().unwrap(), accepted, &id, "hkdf");
    }
    println!("hkdf-sha256: {tally:?}");
    assert_eq!(tally.valid, 83);
    assert_eq!(tally.invalid, 3);

    // HMAC-SHA256, including tags truncated to 128 bits.
    let file = wycheproof("hmac_sha256_test.json");
    let mut tally = Tally::default();
    for (group, t) in tests(&file) {
        let id = t["tcId"].to_string();
        let tag_len = usize::try_from(group["tagSize"].as_u64().unwrap()).unwrap() / 8;
        let full = hmac_sha256(&hex(&t["key"]), &hex(&t["msg"])).unwrap();
        let expected = hex(&t["tag"]);
        // Compare the first `tag_len` bytes of ours with the file's tag; a tag
        // of the wrong length never matches.
        let accepted = expected.len() == tag_len
            && ferret_core::testing::prim::ct_eq(&full[..tag_len], &expected);
        tally.result(t["result"].as_str().unwrap(), accepted, &id, "hmac");
    }
    println!("hmac-sha256: {tally:?}");
    assert_eq!(tally.valid, 66);
    assert_eq!(tally.invalid, 108);
}
