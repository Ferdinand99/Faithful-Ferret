//! The OPAQUE client against the published vectors.
//!
//! * RFC 9807 Appendix C.1.1 and C.1.2 (`ristretto255-SHA512`, group
//!   ristretto255, KSF identity): the client code that runs in production,
//!   instantiated for the RFC's suite (the same configuration as Ferret's in
//!   every part but the KSF and the context), gives the exact
//!   `registration_request`, `registration_upload`, `KE1`, `KE3`,
//!   `export_key` and `session_key`.
//! * RFC 9497 Appendix A.1.1 (`ristretto255-SHA512`, OPRF mode): the OPRF
//!   that OPAQUE builds on, in the `voprf` crate that `opaque-ke` uses.
//!
//! The vectors fix the randomness, so the draws the library makes are
//! replayed through `ReplayRng`: the blind (a 32-byte scalar in the RFC, 64
//! bytes wide in the library: the scalar followed by 32 zero bytes reduces to
//! itself), the envelope nonce, the seed of the ephemeral key and the client
//! nonce. A change in the number, length or order of the draws fails the
//! test.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]

mod common;

use common::hex;
use ferret_core::Error;
use ferret_core::testing::ReplayRng;
use ferret_core::testing::opaque::{rfc_login, rfc_register};
use serde_json::Value;
use std::path::PathBuf;

fn external(name: &str) -> Value {
    let path: PathBuf = common::vectors_dir().join("external").join(name);
    serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
}

/// The 64 bytes `opaque-ke` draws for a blind: the scalar, then zeros.
fn wide(scalar32: &[u8]) -> Vec<u8> {
    assert_eq!(scalar32.len(), 32);
    let mut v = scalar32.to_vec();
    v.extend_from_slice(&[0u8; 32]);
    v
}

fn identifiers(input: &Value) -> Option<(Vec<u8>, Vec<u8>)> {
    match (input.get("client_identity"), input.get("server_identity")) {
        (Some(c), Some(s)) => Some((hex(c), hex(s))),
        (None, None) => None,
        _ => panic!("one identity only"),
    }
}

fn as_refs(ids: &Option<(Vec<u8>, Vec<u8>)>) -> Option<(&[u8], &[u8])> {
    ids.as_ref().map(|(c, s)| (c.as_slice(), s.as_slice()))
}

#[test]
fn rfc9807_ristretto255_vectors() {
    let file = external("rfc9807-opaque-ristretto255.json");
    let vectors = file["vectors"].as_array().unwrap();
    assert_eq!(vectors.len(), 2, "C.1.1 and C.1.2");
    for v in vectors {
        let id = v["id"].as_str().unwrap();
        let (input, out) = (&v["input"], &v["output"]);
        let password = hex(&input["password"]);
        let ids = identifiers(input);

        // Registration: the blind, then the envelope nonce.
        let mut rng = ReplayRng::new(vec![
            wide(&hex(&input["blind_registration"])),
            hex(&input["envelope_nonce"]),
        ]);
        let reg = rfc_register(
            &mut rng,
            &password,
            &hex(&out["registration_response"]),
            as_refs(&ids),
        )
        .unwrap();
        rng.finish()
            .unwrap_or_else(|e| panic!("{id}: draws left: {e:?}"));
        assert_eq!(reg.request, hex(&out["registration_request"]), "{id}");
        assert_eq!(reg.upload, hex(&out["registration_upload"]), "{id}");
        assert_eq!(
            reg.export_key.to_vec(),
            hex(&out["export_key"]),
            "{id}: export_key (registration)"
        );
        assert_eq!(
            reg.server_public_key.to_vec(),
            hex(&input["server_public_key"]),
            "{id}"
        );

        // Login: the blind, the seed of the ephemeral key, the client nonce.
        let mut rng = ReplayRng::new(vec![
            wide(&hex(&input["blind_login"])),
            hex(&input["client_keyshare_seed"]),
            hex(&input["client_nonce"]),
        ]);
        let login = rfc_login(
            &mut rng,
            &password,
            &hex(&out["KE2"]),
            &hex(&v["configuration"]["Context"]),
            as_refs(&ids),
        )
        .unwrap();
        rng.finish()
            .unwrap_or_else(|e| panic!("{id}: draws left: {e:?}"));
        assert_eq!(login.ke1, hex(&out["KE1"]), "{id}");
        assert_eq!(login.ke3, hex(&out["KE3"]), "{id}");
        assert_eq!(login.export_key.to_vec(), hex(&out["export_key"]), "{id}");
        assert_eq!(login.session_key, hex(&out["session_key"]), "{id}");
        assert_eq!(
            login.server_public_key.to_vec(),
            hex(&input["server_public_key"]),
            "{id}"
        );
    }
}

/// The same vectors, but with a context, an identity or a byte changed, are
/// refused with the single authentication error: the preamble of the 3DH
/// transcript and the envelope's AAD depend on all of them.
#[test]
fn rfc9807_vectors_refuse_changed_context_identity_or_message() {
    let file = external("rfc9807-opaque-ristretto255.json");
    let v = &file["vectors"][0];
    let (input, out) = (&v["input"], &v["output"]);
    let password = hex(&input["password"]);
    let draws = || {
        ReplayRng::new(vec![
            wide(&hex(&input["blind_login"])),
            hex(&input["client_keyshare_seed"]),
            hex(&input["client_nonce"]),
        ])
    };
    let ke2 = hex(&out["KE2"]);
    let context = hex(&v["configuration"]["Context"]);

    // Control.
    assert!(rfc_login(&mut draws(), &password, &ke2, &context, None).is_ok());
    // Another context.
    let mut other = context.clone();
    other.push(b'!');
    assert_eq!(
        rfc_login(&mut draws(), &password, &ke2, &other, None).err(),
        Some(Error::Decrypt)
    );
    // An identity the record was not made with.
    assert_eq!(
        rfc_login(
            &mut draws(),
            &password,
            &ke2,
            &context,
            Some((b"alice", b"bob"))
        )
        .err(),
        Some(Error::Decrypt)
    );
    // A wrong password.
    assert_eq!(
        rfc_login(
            &mut draws(),
            b"WrongHorseBatteryStaple",
            &ke2,
            &context,
            None
        )
        .err(),
        Some(Error::Decrypt)
    );
    // Every byte of KE2 changed in turn gives Decrypt or Malformed, never Ok.
    for i in 0..ke2.len() {
        let mut bad = ke2.clone();
        bad[i] ^= 0x01;
        match rfc_login(&mut draws(), &password, &bad, &context, None) {
            Err(Error::Decrypt | Error::Malformed(_)) => {}
            other => panic!("byte {i} changed: {:?}", other.map(|_| ())),
        }
    }
}

// ----------------------------------------------------------- RFC 9497

#[test]
fn rfc9497_oprf_vectors() {
    use opaque_ke::generic_array::{GenericArray, typenum::U32};
    use voprf::{Group, Mode, OprfClient, OprfServer, Ristretto255, derive_key};

    let file = external("rfc9497-oprf-ristretto255.json");
    assert_eq!(file["identifier"], "ristretto255-SHA512");
    assert_eq!(file["mode"], "OPRF");

    // The server's key from the seed and key info (DeriveKeyPair).
    let sk = derive_key::<Ristretto255>(&hex(&file["seed"]), &hex(&file["key_info"]), Mode::Oprf)
        .unwrap();
    let sk_bytes = Ristretto255::serialize_scalar(sk);
    assert_eq!(sk_bytes.to_vec(), hex(&file["sk_sm"]), "DeriveKeyPair");
    let server = OprfServer::<Ristretto255>::new_with_key(&sk_bytes).unwrap();

    for v in file["vectors"].as_array().unwrap() {
        let id = v["id"].as_str().unwrap();
        let input = hex(&v["input"]);
        let blind_bytes = hex(&v["blind"]);
        let blind = Ristretto255::deserialize_scalar(&GenericArray::<u8, U32>::clone_from_slice(
            &blind_bytes,
        ))
        .unwrap();

        let blinded =
            OprfClient::<Ristretto255>::deterministic_blind_unchecked(&input, blind).unwrap();
        assert_eq!(
            blinded.message.serialize().to_vec(),
            hex(&v["blinded_element"]),
            "{id}: BlindedElement"
        );
        let evaluated = server.blind_evaluate(&blinded.message);
        assert_eq!(
            evaluated.serialize().to_vec(),
            hex(&v["evaluation_element"]),
            "{id}: EvaluationElement"
        );
        let output = blinded.state.finalize(&input, &evaluated).unwrap();
        assert_eq!(output.to_vec(), hex(&v["output"]), "{id}: Output");
    }
}
