//! The server half against the published vectors of RFC 9807 (Appendix C.1.1
//! and C.1.2, `ristretto255-SHA512`, key stretching function identity).
//!
//! The functions that run are the ones the server runs: `register_start`,
//! `login_start` (with the context, the identities and the credential
//! identifier of the RFC instead of Ferret's, which is what
//! `testing::login_start_with_identifier` sets) and `login_finish`. The server
//! key pair and the OPRF seed of the RFC are put into a payload of
//! `opaque_setup`; the dummy key is any valid point, since a real record is
//! used. The vectors fix every draw, so `ReplayRng` plays them back: the fake
//! masking key (zero here: it is replaced by the record), the masking nonce, the
//! seed of the server's key and the server nonce, then the login id and the nonce
//! of the seal, which the RFC does not have.
//!
//! The server never gives out the session key. The one way to see it is the
//! state `login_start` seals: its first 64 bytes. `login_finish` is then run
//! on the client's `KE3` of the RFC.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]

use std::net::IpAddr;
use std::path::Path;

use ferret_core::KsfProfile;
use ferret_core::testing::{ReplayRng, TestRng, hex_decode};
use ferret_server_auth::testing::vectors::{
    login_start_with_identifier, peek_server_login, rfc_register_response,
};
use ferret_server_auth::{
    AccountLookup, AuthContext, AuthError, Caller, CredentialId, DenyReason,
    InMemoryLoginStateStore, LoginFinishRequest, LoginPurpose, LoginStartRequest,
    LoginStartResponse, Malformed, ManualClock, PreloginPolicy, PreloginSecret, ProfileRules,
    RecordingThrottle, RegistrationKind, ServerKeys, StateSealKey, normalize_login_name,
    register_finish,
};
use serde_json::Value;

const START: u64 = 1_700_000_000;

fn external() -> Value {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../vectors/external/rfc9807-opaque-ristretto255.json");
    serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
}

fn hex(value: &Value) -> Vec<u8> {
    hex_decode(value.as_str().unwrap()).unwrap()
}

/// One vector, read.
struct Vector {
    id: String,
    keys_payload: Vec<u8>,
    server_public_key: Vec<u8>,
    identifier: Vec<u8>,
    context: Vec<u8>,
    identities: Option<(Vec<u8>, Vec<u8>)>,
    registration_request: Vec<u8>,
    registration_response: Vec<u8>,
    upload: Vec<u8>,
    ke1: Vec<u8>,
    ke2: Vec<u8>,
    ke3: Vec<u8>,
    session_key: Vec<u8>,
    draws: Vec<Vec<u8>>,
}

fn vectors() -> Vec<Vector> {
    let file = external();
    file["vectors"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| {
            let (input, output) = (&v["input"], &v["output"]);
            let identities = match (input.get("client_identity"), input.get("server_identity")) {
                (Some(c), Some(s)) => Some((hex(c), hex(s))),
                (None, None) => None,
                _ => panic!("one identity only"),
            };
            // Seed 64, private key 32, then the dummy key.
            let keys_payload = [
                hex(&input["oprf_seed"]),
                hex(&input["server_private_key"]),
                hex(&input["server_public_key"]),
            ]
            .concat();
            Vector {
                id: v["id"].as_str().unwrap().to_string(),
                keys_payload,
                server_public_key: hex(&input["server_public_key"]),
                identifier: hex(&input["credential_identifier"]),
                context: hex(&v["configuration"]["Context"]),
                identities,
                registration_request: hex(&output["registration_request"]),
                registration_response: hex(&output["registration_response"]),
                upload: hex(&output["registration_upload"]),
                ke1: hex(&output["KE1"]),
                ke2: hex(&output["KE2"]),
                ke3: hex(&output["KE3"]),
                session_key: hex(&output["session_key"]),
                draws: vec![
                    // The fake masking key of `ServerLogin::start`.
                    vec![0; 64],
                    hex(&input["masking_nonce"]),
                    hex(&input["server_keyshare_seed"]),
                    hex(&input["server_nonce"]),
                    // The login id and the nonce of the seal.
                    vec![0x11; 16],
                    vec![0x22; 24],
                ],
            }
        })
        .collect()
}

/// A server of one vector: its keys, secrets and stores.
struct Server {
    keys: ServerKeys,
    prelogin: PreloginSecret,
    seal: StateSealKey,
    clock: ManualClock,
    throttle: RecordingThrottle,
    policy: PreloginPolicy,
    profiles: ProfileRules,
    store: InMemoryLoginStateStore,
}

fn caller() -> Caller {
    Caller {
        ip: Some(IpAddr::from([192, 0, 2, 9])),
    }
}

impl Server {
    fn new(payload: &[u8]) -> Self {
        let prelogin = PreloginSecret::generate(&mut TestRng::new(b"rfc 9807 server"));
        Self {
            keys: ServerKeys::from_payload(payload).unwrap(),
            seal: StateSealKey::derive(&prelogin).unwrap(),
            prelogin,
            clock: ManualClock::new(START),
            throttle: RecordingThrottle::new(),
            policy: PreloginPolicy::single(KsfProfile::from_wire(1).unwrap()),
            profiles: ProfileRules::ferret_v1(),
            store: InMemoryLoginStateStore::new(),
        }
    }

    fn cx(&self) -> AuthContext<'_> {
        AuthContext::new(
            &self.keys,
            &self.prelogin,
            &self.seal,
            &self.clock,
            &self.throttle,
            &self.policy,
            &self.profiles,
        )
    }

    /// `login_start` of the vector's account, with the chosen context,
    /// identities, identifier and `KE1`, and the draws of the vector.
    fn start(
        &self,
        v: &Vector,
        context: &[u8],
        identities: Option<(&[u8], &[u8])>,
        identifier: &[u8],
        ke1: &[u8],
    ) -> Result<LoginStartResponse, AuthError> {
        let record =
            register_finish(&v.upload, 1, &self.profiles, RegistrationKind::NewAccount).unwrap();
        let name = normalize_login_name("rfc9807@example.com").unwrap();
        let request = LoginStartRequest {
            caller: caller(),
            name: &name,
            credential: CredentialId::from_bytes([0x09; 16]),
            lookup: AccountLookup::Active {
                record: &record,
                sk_hint: false,
            },
            purpose: LoginPurpose::Login,
            session_scope: None,
            ke1,
        };
        let mut rng = ReplayRng::new(v.draws.clone());
        let response = login_start_with_identifier(
            &self.cx(),
            &self.store,
            &mut rng,
            &request,
            context,
            identities,
            identifier,
        );
        // Every draw is used by a start that got as far as OPAQUE; a start
        // that refused KE1 has used none.
        match &response {
            Ok(_) => rng.finish().expect("every draw of the vector is used"),
            Err(_) => assert_eq!(rng.remaining(), v.draws.len()),
        }
        response
    }

    fn finish(&self, response: &LoginStartResponse, ke3: &[u8]) -> Result<(), AuthError> {
        ferret_server_auth::login_finish(
            &self.cx(),
            &self.store,
            &LoginFinishRequest {
                caller: caller(),
                login_id: response.login_id.to_hex().as_bytes(),
                ke3,
                current_session: None,
            },
        )
        .map(|_| ())
    }
}

fn as_refs(ids: &Option<(Vec<u8>, Vec<u8>)>) -> Option<(&[u8], &[u8])> {
    ids.as_ref().map(|(c, s)| (c.as_slice(), s.as_slice()))
}

#[test]
fn rfc9807_server_vectors_c11_and_c12() {
    let all = vectors();
    assert_eq!(all.len(), 2, "C.1.1 and C.1.2");
    for v in &all {
        let id = &v.id;
        let server = Server::new(&v.keys_payload);
        assert_eq!(
            server.keys.public_key().to_vec(),
            v.server_public_key,
            "{id}"
        );

        // Registration: the evaluated element and the server's public key.
        let response =
            rfc_register_response(&server.keys, &v.identifier, &v.registration_request).unwrap();
        assert_eq!(
            response, v.registration_response,
            "{id}: registration_response"
        );

        // Login: KE2 byte for byte.
        let started = server
            .start(v, &v.context, as_refs(&v.identities), &v.identifier, &v.ke1)
            .unwrap();
        assert_eq!(started.ke2, v.ke2, "{id}: KE2");

        // The state holds the session key, then the MAC the client must send,
        // which is KE3.
        let state =
            peek_server_login(&server.seal, &server.store, &started.login_id, START).unwrap();
        assert_eq!(state[..64], v.session_key[..], "{id}: session_key");
        assert_eq!(state[64..], v.ke3[..], "{id}: the expected MAC is KE3");

        // The client's KE3 of the RFC finishes the login.
        assert_eq!(server.finish(&started, &v.ke3), Ok(()), "{id}: KE3");
    }
}

#[test]
fn rfc9807_server_refuses_changed_context_identity_or_message() {
    let all = vectors();
    let v = &all[0];
    let new = || Server::new(&v.keys_payload);

    // A start that is not the RFC's gives another KE2, and the KE3 of the RFC
    // is refused for it (or the KE1 is not accepted at all).
    let diverges = |context: &[u8],
                    identities: Option<(&[u8], &[u8])>,
                    identifier: &[u8],
                    ke1: &[u8],
                    what: &str| {
        let server = new();
        match server.start(v, context, identities, identifier, ke1) {
            Err(error) => assert_eq!(error, AuthError::Malformed(Malformed::Ke1), "{what}"),
            Ok(started) => {
                assert_ne!(started.ke2, v.ke2, "{what}: KE2");
                assert_eq!(
                    server.finish(&started, &v.ke3),
                    Err(AuthError::Denied(DenyReason::Ke3)),
                    "{what}: KE3"
                );
            }
        }
    };

    // Control: the RFC's own values finish.
    let server = new();
    let started = server
        .start(v, &v.context, None, &v.identifier, &v.ke1)
        .unwrap();
    assert_eq!(server.finish(&started, &v.ke3), Ok(()));

    let mut context = v.context.clone();
    context.push(b'!');
    diverges(&context, None, &v.identifier, &v.ke1, "another context");
    diverges(&[], None, &v.identifier, &v.ke1, "no context");
    diverges(
        &v.context,
        Some((b"alice", b"bob")),
        &v.identifier,
        &v.ke1,
        "identities the record was not made with",
    );
    diverges(
        &v.context,
        None,
        b"1235",
        &v.ke1,
        "another credential identifier",
    );
    for at in 0..v.ke1.len() {
        let mut ke1 = v.ke1.clone();
        ke1[at] ^= 0x01;
        diverges(
            &v.context,
            None,
            &v.identifier,
            &ke1,
            &format!("KE1 byte {at}"),
        );
    }

    // A KE3 with any changed byte is refused.
    for at in 0..v.ke3.len() {
        let server = new();
        let started = server
            .start(v, &v.context, None, &v.identifier, &v.ke1)
            .unwrap();
        let mut ke3 = v.ke3.clone();
        ke3[at] ^= 0x01;
        assert_eq!(
            server.finish(&started, &ke3),
            Err(AuthError::Denied(DenyReason::Ke3)),
            "KE3 byte {at}"
        );
    }
    // The second vector's KE3 is not the first one's.
    let server = new();
    let started = server
        .start(v, &v.context, None, &v.identifier, &v.ke1)
        .unwrap();
    assert_eq!(
        server.finish(&started, &all[1].ke3),
        Err(AuthError::Denied(DenyReason::Ke3))
    );
}

/// The draws of the vector are the ones `opaque-ke` makes, in its order: a
/// start with one draw less cannot complete, and a replay with one more is not
/// used up.
#[test]
fn rfc9807_server_draws_are_exactly_those_of_the_vector() {
    let all = vectors();
    let v = &all[0];
    let run = |draws: Vec<Vec<u8>>| {
        // A server of its own for each run: a start puts its state in the store.
        let server = Server::new(&v.keys_payload);
        let record =
            register_finish(&v.upload, 1, &server.profiles, RegistrationKind::NewAccount).unwrap();
        let name = normalize_login_name("rfc9807@example.com").unwrap();
        let request = LoginStartRequest {
            caller: Caller { ip: None },
            name: &name,
            credential: CredentialId::from_bytes([0x09; 16]),
            lookup: AccountLookup::Active {
                record: &record,
                sk_hint: false,
            },
            purpose: LoginPurpose::Login,
            session_scope: None,
            ke1: &v.ke1,
        };
        let mut rng = ReplayRng::new(draws);
        let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            login_start_with_identifier(
                &server.cx(),
                &server.store,
                &mut rng,
                &request,
                &v.context,
                None,
                &v.identifier,
            )
            .map(|_| ())
        }));
        (outcome, rng)
    };
    let (outcome, rng) = run(v.draws.clone());
    assert!(matches!(outcome, Ok(Ok(()))));
    assert!(rng.finish().is_ok());

    let (outcome, _) = run(v.draws[..5].to_vec());
    assert!(
        outcome.is_err(),
        "a start with a draw missing must not complete"
    );

    let mut more = v.draws.clone();
    more.push(vec![0; 8]);
    let (outcome, rng) = run(more);
    assert!(matches!(outcome, Ok(Ok(()))));
    assert!(rng.finish().is_err(), "a draw left over is seen");
}
