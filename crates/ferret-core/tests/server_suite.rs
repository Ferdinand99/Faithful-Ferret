//! The server suite (`opaque::server_suite`, feature `server-suite`) and what
//! was read in `opaque-ke` 4.0.1 about its server side (`NOTES-server.md`).
//!
//! The server half here is built from the exports alone: `FerretSuite`,
//! `Rng06`, `OPAQUE_CONTEXT`, `opaque_ke` and the length constants. The client
//! is the production client with a small Argon2id (`TestKsf`).

#![cfg(feature = "server-suite")]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]

use ferret_core::opaque::server_suite::opaque_ke::keypair::{OprfSeed, PrivateKey, PublicKey};
use ferret_core::opaque::server_suite::opaque_ke::{
    CredentialFinalization, CredentialRequest, Identifiers, RegistrationRequest,
    RegistrationUpload, Ristretto255, ServerLogin, ServerLoginParameters, ServerRegistration,
    ServerSetup,
};
use ferret_core::opaque::server_suite::{
    FerretSuite, KE1_LEN, KE2_LEN, KE3_LEN, OPAQUE_CONTEXT, REGISTRATION_RECORD_LEN,
    REGISTRATION_REQUEST_LEN, REGISTRATION_RESPONSE_LEN, Rng06, SERVER_LOGIN_STATE_LEN,
    SERVER_SETUP_LEN,
};
use ferret_core::testing::keys::export_key_bytes;
use ferret_core::testing::opaque::{
    KE2_BYTES, REGISTRATION_RESPONSE_BYTES, TestKsf, login_finish_with, register_finish_with,
};
use ferret_core::testing::{ReplayRng, TestRng};
use ferret_core::{
    ExportKey, KdfParams, LoginState, MasterPassword, OpaqueInput, PinState, SecureRng,
    opaque_login_start, opaque_register_start,
};
use static_assertions::{assert_impl_all, assert_not_impl_any};
use std::panic::{AssertUnwindSafe, catch_unwind};
use zeroize::ZeroizeOnDrop;

/// A few KiB: far below the floor, so that the tests run in milliseconds.
const SMALL: KdfParams = KdfParams {
    m_kib: 64,
    t: 1,
    p: 1,
};
const CRED: &[u8] = b"0123456789abcdef";

fn rng(seed: &str) -> TestRng {
    TestRng::new(seed.as_bytes())
}

fn password() -> OpaqueInput {
    MasterPassword::for_unlock(b"correct horse battery staple")
        .unwrap()
        .opaque_input(None)
}

fn params() -> ServerLoginParameters<'static, 'static> {
    ServerLoginParameters {
        context: Some(OPAQUE_CONTEXT),
        identifiers: Identifiers::default(),
    }
}

fn setup(seed: &str) -> ServerSetup<FerretSuite> {
    ServerSetup::<FerretSuite>::new(&mut Rng06(&mut rng(seed)))
}

fn ksf() -> TestKsf {
    TestKsf::new(SMALL)
}

/// A completed registration: the stored record and the client's export key.
struct Registered {
    record: Vec<u8>,
    export_key: ExportKey,
    request: Vec<u8>,
    response: Vec<u8>,
}

fn register(setup: &ServerSetup<FerretSuite>, seed: &str) -> Registered {
    let pw = password();
    let mut r = rng(seed);
    let (request, state) = opaque_register_start(&mut r, &pw).unwrap();
    let started = ServerRegistration::<FerretSuite>::start(
        setup,
        RegistrationRequest::deserialize(&request).unwrap(),
        CRED,
    )
    .unwrap();
    let response = started.message.serialize().to_vec();
    let done = register_finish_with(&mut r, state, &pw, &response, &ksf()).unwrap();
    Registered {
        record: done.record,
        export_key: done.export_key,
        request,
        response,
    }
}

/// The server's stored form of an uploaded record.
fn stored(record: &[u8]) -> ServerRegistration<FerretSuite> {
    ServerRegistration::finish(RegistrationUpload::<FerretSuite>::deserialize(record).unwrap())
}

/// A login up to `KE2`: the client's `KE1` and state, the server's state and
/// the `KE2` message.
struct LoginStarted {
    client: LoginState,
    server: ServerLogin<FerretSuite>,
    ke1: Vec<u8>,
    ke2: Vec<u8>,
}

fn login_start(
    setup: &ServerSetup<FerretSuite>,
    record: Option<ServerRegistration<FerretSuite>>,
    seed: &str,
) -> LoginStarted {
    let (ke1, client) = opaque_login_start(&mut rng(seed), &password()).unwrap();
    let started = ServerLogin::<FerretSuite>::start(
        &mut Rng06(&mut rng(&format!("{seed}/server"))),
        setup,
        record,
        CredentialRequest::deserialize(&ke1).unwrap(),
        CRED,
        params(),
    )
    .unwrap();
    LoginStarted {
        client,
        server: started.state,
        ke1,
        ke2: started.message.serialize().to_vec(),
    }
}

/// The client's side of the second step.
struct ClientDone {
    ke3: Vec<u8>,
    export_key: ExportKey,
    session_key: Vec<u8>,
    server: ServerLogin<FerretSuite>,
}

fn client_finish(started: LoginStarted, seed: &str) -> ClientDone {
    let done = login_finish_with(
        &mut rng(seed),
        started.client,
        &password(),
        &started.ke2,
        &ksf(),
        Some(OPAQUE_CONTEXT),
        PinState::FirstUse,
    )
    .unwrap();
    ClientDone {
        ke3: done.finished.ke3,
        export_key: done.finished.export_key,
        session_key: done.session_key,
        server: started.server,
    }
}

// ---------------------------------------------------------------- the suite

/// A `ServerSetup<FerretSuite>` built from the exports alone serves the
/// production client; both sides agree on the export key and the session key.
#[test]
fn exported_suite_serves_the_client() {
    let setup = setup("setup");
    let reg = register(&setup, "register");
    assert_eq!(reg.record.len(), REGISTRATION_RECORD_LEN);

    let started = login_start(&setup, Some(stored(&reg.record)), "login");
    let done = client_finish(started, "login/finish");
    assert_eq!(
        export_key_bytes(&done.export_key),
        export_key_bytes(&reg.export_key)
    );

    let finished = done
        .server
        .finish(
            CredentialFinalization::deserialize(&done.ke3).unwrap(),
            params(),
        )
        .unwrap();
    assert_eq!(finished.session_key.to_vec(), done.session_key);
}

/// A wrong password does not get as far as a `KE3`: the client cannot open the
/// envelope.
#[test]
fn a_wrong_password_never_reaches_the_server_check() {
    let setup = setup("setup");
    let reg = register(&setup, "register");
    let started = login_start(&setup, Some(stored(&reg.record)), "login");
    let other = MasterPassword::for_unlock(b"not the password")
        .unwrap()
        .opaque_input(None);
    let outcome = login_finish_with(
        &mut rng("login/finish"),
        started.client,
        &other,
        &started.ke2,
        &ksf(),
        Some(OPAQUE_CONTEXT),
        PinState::FirstUse,
    );
    assert!(outcome.is_err());
}

/// Every length constant is the length of the real message.
#[test]
fn lengths_match_the_wire_format() {
    let setup = setup("setup");
    let reg = register(&setup, "register");
    assert_eq!(reg.request.len(), REGISTRATION_REQUEST_LEN);
    assert_eq!(reg.response.len(), REGISTRATION_RESPONSE_LEN);
    assert_eq!(reg.record.len(), REGISTRATION_RECORD_LEN);
    assert_eq!(
        stored(&reg.record).serialize().len(),
        REGISTRATION_RECORD_LEN
    );

    let started = login_start(&setup, Some(stored(&reg.record)), "login");
    assert_eq!(started.ke1.len(), KE1_LEN);
    assert_eq!(started.ke2.len(), KE2_LEN);
    assert_eq!(started.server.serialize().len(), SERVER_LOGIN_STATE_LEN);
    let done = client_finish(started, "login/finish");
    assert_eq!(done.ke3.len(), KE3_LEN);
    assert_eq!(setup.serialize().len(), SERVER_SETUP_LEN);

    // The two constants that are re-exports of the client's, not copies.
    assert_eq!(REGISTRATION_RESPONSE_LEN, REGISTRATION_RESPONSE_BYTES);
    assert_eq!(KE2_LEN, KE2_BYTES);
}

/// `ServerSetup` is the OPRF seed (64), the private key (32) and the public
/// "dummy" key (32), in that order.
#[test]
fn server_setup_is_128_bytes_seed_key_dummy() {
    let setup = setup("setup");
    let bytes = setup.serialize();
    assert_eq!(bytes.len(), 128);

    // The private key sits at 64..96 and is the one the key pair holds.
    assert_eq!(
        &bytes[64..96],
        setup.keypair().private().serialize().as_slice()
    );
    // The dummy key at 96..128 is a valid public key, and not the real one.
    PublicKey::<Ristretto255>::deserialize(&bytes[96..128]).unwrap();
    assert_ne!(
        &bytes[96..128],
        setup.keypair().public().serialize().as_slice()
    );
    // The setup round-trips, and a dummy key that is not a point is refused.
    let again = ServerSetup::<FerretSuite>::deserialize(&bytes).unwrap();
    assert_eq!(again.serialize(), bytes);
    let mut broken = bytes.to_vec();
    broken[96..128].fill(0xff);
    assert!(ServerSetup::<FerretSuite>::deserialize(&broken).is_err());
    // Short input is an error, not a panic.
    for len in 0..SERVER_SETUP_LEN {
        assert!(ServerSetup::<FerretSuite>::deserialize(&bytes[..len]).is_err());
    }
}

/// `ServerLogin::start` draws, in this order: the masking key of the fake
/// record (64, always drawn, even when a real record is given), the masking
/// nonce (32), the seed of the server's ephemeral key (32) and the server nonce
/// (32). `finish` draws nothing.
#[test]
fn server_login_draws_in_documented_order() {
    let setup = setup("setup");
    let reg = register(&setup, "register");
    let (ke1, _client) = opaque_login_start(&mut rng("login"), &password()).unwrap();

    let mut source = rng("draws");
    let mut draw = |n: usize| {
        let mut d = vec![0u8; n];
        source.fill(&mut d);
        d
    };
    let draws = vec![draw(64), draw(32), draw(32), draw(32)];
    let (masking_nonce, server_nonce) = (draws[1].clone(), draws[3].clone());

    let mut replay = ReplayRng::new(draws.clone());
    let started = ServerLogin::<FerretSuite>::start(
        &mut Rng06(&mut replay),
        &setup,
        Some(stored(&reg.record)),
        CredentialRequest::deserialize(&ke1).unwrap(),
        CRED,
        params(),
    )
    .unwrap();
    assert_eq!(replay.remaining(), 0);
    let ke2 = started.message.serialize();
    // KE2 = evaluated element 32 | masking nonce 32 | masked response 128 |
    // server nonce 32 | server ephemeral public key 32 | MAC 64.
    assert_eq!(&ke2[32..64], masking_nonce.as_slice());
    assert_eq!(&ke2[192..224], server_nonce.as_slice());
    assert!(replay.finish().is_ok());

    // A fifth draw has nothing to replay.
    let mut spent = ReplayRng::new(Vec::new());
    assert!(catch_unwind(AssertUnwindSafe(|| spent.fill(&mut [0u8; 32]))).is_err());

    // And with only three of the four draws the start cannot complete.
    let mut short = ReplayRng::new(draws[..3].to_vec());
    let outcome = catch_unwind(AssertUnwindSafe(|| {
        ServerLogin::<FerretSuite>::start(
            &mut Rng06(&mut short),
            &setup,
            Some(stored(&reg.record)),
            CredentialRequest::deserialize(&ke1).unwrap(),
            CRED,
            params(),
        )
        .map(|_| ())
    }));
    assert!(outcome.is_err());
}

/// The fake record of `opaque-ke` is not available to the server
/// (`ServerRegistration::dummy` is `pub(crate)`: the doctest of the module
/// shows that it does not compile). The only dummy there is lives inside
/// `ServerLogin::start(.., None, ..)`, and it draws a fresh masking key at
/// each call, so the answer for an unknown name changes with the draw. A
/// server that wants the same answer every time must build its own fake record
/// and pass it in as a record.
#[test]
fn dummy_record_is_not_reachable() {
    let setup = setup("setup");
    let (ke1, _client) = opaque_login_start(&mut rng("login"), &password()).unwrap();
    let ke2_for = |masking_key_draw: u8| {
        let mut replay = ReplayRng::new(vec![
            vec![masking_key_draw; 64],
            vec![7u8; 32],
            vec![9u8; 32],
            vec![11u8; 32],
        ]);
        ServerLogin::<FerretSuite>::start(
            &mut Rng06(&mut replay),
            &setup,
            None,
            CredentialRequest::deserialize(&ke1).unwrap(),
            CRED,
            params(),
        )
        .unwrap()
        .message
        .serialize()
        .to_vec()
    };
    let first = ke2_for(1);
    assert_eq!(first.len(), KE2_LEN);
    // Same draws, same answer; another first draw, another masked response.
    assert_eq!(first, ke2_for(1));
    let second = ke2_for(2);
    assert_eq!(first[..64], second[..64]);
    assert_ne!(first[64..192], second[64..192]);
}

/// The state between `KE2` and `KE3` is the session key (64) and the expected
/// MAC (64). It round-trips and finishes to the same session key.
#[test]
fn server_login_state_roundtrips_128_bytes() {
    let setup = setup("setup");
    let reg = register(&setup, "register");

    // Direct.
    let started = login_start(&setup, Some(stored(&reg.record)), "login");
    let done = client_finish(started, "login/finish");
    let direct = done
        .server
        .finish(
            CredentialFinalization::deserialize(&done.ke3).unwrap(),
            params(),
        )
        .unwrap();

    // The same login (same draws), with the server state sent through bytes.
    let started = login_start(&setup, Some(stored(&reg.record)), "login");
    let again = client_finish(started, "login/finish");
    assert_eq!(done.ke3, again.ke3);
    let bytes = again.server.serialize();
    assert_eq!(bytes.len(), 128);
    let restored = ServerLogin::<FerretSuite>::deserialize(&bytes).unwrap();
    let via_bytes = restored
        .finish(
            CredentialFinalization::deserialize(&again.ke3).unwrap(),
            params(),
        )
        .unwrap();

    assert_eq!(direct.session_key, via_bytes.session_key);
    assert_eq!(direct.session_key.to_vec(), done.session_key);

    // Short input is an error, not a panic.
    for len in 0..128 {
        assert!(ServerLogin::<FerretSuite>::deserialize(&bytes[..len]).is_err());
    }
}

/// One changed bit at any of the 64 positions of the MAC of `KE3` is an error,
/// not a panic.
#[test]
fn ke3_mac_mismatch_is_an_error_not_a_panic() {
    let setup = setup("setup");
    let reg = register(&setup, "register");
    let started = login_start(&setup, Some(stored(&reg.record)), "login");
    let done = client_finish(started, "login/finish");
    assert_eq!(done.ke3.len(), KE3_LEN);
    for i in 0..KE3_LEN {
        let mut bad = done.ke3.clone();
        bad[i] ^= 0x01;
        let message = CredentialFinalization::<FerretSuite>::deserialize(&bad).unwrap();
        assert!(
            done.server.clone().finish(message, params()).is_err(),
            "byte {i}"
        );
    }
    // The unchanged one still works: the failed attempts did not spoil a copy.
    assert!(
        done.server
            .finish(
                CredentialFinalization::deserialize(&done.ke3).unwrap(),
                params()
            )
            .is_ok()
    );
}

/// Points that are not on the group, and inputs that are too short, are
/// errors.
#[test]
fn malformed_points_are_errors() {
    // None of these is a ristretto255 element that the protocol accepts.
    let all_ones = [0xffu8; 32];
    let negative = {
        let mut b = [0u8; 32];
        b[0] = 1; // s = 1 is negative (odd)
        b
    };
    let above_modulus = {
        let mut b = [0xffu8; 32];
        b[31] = 0x7f; // s = 2^255 - 1 is not below the field modulus
        b
    };
    let identity = [0u8; 32]; // decodes, but is refused as an OPRF input
    let bad = [all_ones, negative, above_modulus, identity];

    let setup = setup("setup");
    let reg = register(&setup, "register");
    let started = login_start(&setup, Some(stored(&reg.record)), "login");

    for point in &bad {
        // Registration request.
        assert!(RegistrationRequest::<FerretSuite>::deserialize(point).is_err());
        // KE1: the blinded element (0..32) and the ephemeral key (64..96).
        for at in [0usize, 64] {
            let mut ke1 = started.ke1.clone();
            ke1[at..at + 32].copy_from_slice(point);
            assert!(CredentialRequest::<FerretSuite>::deserialize(&ke1).is_err());
        }
        // The client public key of a stored record (0..32).
        let mut record = reg.record.clone();
        record[..32].copy_from_slice(point);
        assert!(RegistrationUpload::<FerretSuite>::deserialize(&record).is_err());
    }

    // Short input at every length.
    for len in 0..REGISTRATION_REQUEST_LEN {
        assert!(RegistrationRequest::<FerretSuite>::deserialize(&reg.request[..len]).is_err());
    }
    for len in 0..KE1_LEN {
        assert!(CredentialRequest::<FerretSuite>::deserialize(&started.ke1[..len]).is_err());
    }
    for len in 0..REGISTRATION_RECORD_LEN {
        assert!(RegistrationUpload::<FerretSuite>::deserialize(&reg.record[..len]).is_err());
    }
    let done = client_finish(started, "login/finish");
    for len in 0..KE3_LEN {
        assert!(CredentialFinalization::<FerretSuite>::deserialize(&done.ke3[..len]).is_err());
    }
}

/// The parsers of `opaque-ke` read a prefix and ignore what follows. The
/// server library therefore checks each length itself; this test is the reason.
#[test]
fn library_parsers_ignore_trailing_bytes() {
    let setup = setup("setup");
    let reg = register(&setup, "register");
    let started = login_start(&setup, Some(stored(&reg.record)), "login");
    let ke1 = started.ke1.clone();
    let done = client_finish(started, "login/finish");

    let with_tail = |b: &[u8]| {
        let mut v = b.to_vec();
        v.push(0);
        v
    };
    assert!(RegistrationRequest::<FerretSuite>::deserialize(&with_tail(&reg.request)).is_ok());
    assert!(CredentialRequest::<FerretSuite>::deserialize(&with_tail(&ke1)).is_ok());
    assert!(RegistrationUpload::<FerretSuite>::deserialize(&with_tail(&reg.record)).is_ok());
    assert!(CredentialFinalization::<FerretSuite>::deserialize(&with_tail(&done.ke3)).is_ok());
    assert!(ServerLogin::<FerretSuite>::deserialize(&with_tail(&done.server.serialize())).is_ok());
}

// ------------------------------------------------------------ zeroization

/// What the read of `opaque-ke` 4.0.1 showed: `ServerSetup` has no `Drop` and
/// is not `ZeroizeOnDrop` itself, but the two secrets it holds are: the OPRF
/// seed (`OprfSeed`) and the private key (`PrivateKey`) wipe themselves when
/// the setup is dropped. `ServerLogin` and `ServerRegistration` are
/// `ZeroizeOnDrop`. (The public parts are not secret.)
///
/// What the setup also has is a derived `Debug` that prints the key material.
/// The server library therefore wraps it in a guard of its own that has no
/// `Debug` (`ServerKeys`); the setup is never put in a struct that derives
/// `Debug`.
#[test]
fn server_setup_zeroize_on_drop() {
    assert_not_impl_any!(ServerSetup<FerretSuite>: ZeroizeOnDrop);
    assert_impl_all!(OprfSeed<sha2_010::Sha512>: ZeroizeOnDrop);
    assert_impl_all!(PrivateKey<Ristretto255>: ZeroizeOnDrop);
    assert_impl_all!(ServerLogin<FerretSuite>: ZeroizeOnDrop);
    assert_impl_all!(ServerRegistration<FerretSuite>: ZeroizeOnDrop);
    // The setup is dropped field by field, so it does need dropping.
    assert!(std::mem::needs_drop::<ServerSetup<FerretSuite>>());
}
