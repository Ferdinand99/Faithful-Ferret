//! Property tests for the OPAQUE client (plan section 9.1).
//!
//! The key stretching function runs with parameters far below the floor
//! (through `testing::opaque`), so that the cases run in milliseconds.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]

use ferret_core::testing::TestRng;
use ferret_core::testing::keys::export_key_bytes;
use ferret_core::testing::opaque::{Server, TestKsf, login_finish_with, register_finish_with};
use ferret_core::{
    Error, KdfParams, MalformedKind, MasterPassword, OPAQUE_CONTEXT, PinState, SecretKey,
    opaque_login_start, opaque_register_start,
};
use proptest::prelude::*;

const SMALL: KdfParams = KdfParams {
    m_kib: 64,
    t: 1,
    p: 1,
};
const CRED: &[u8] = b"0123456789abcdef";

fn cases() -> u32 {
    std::env::var("PROPTEST_CASES")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(32)
}

/// A password of printable characters, letters of several scripts included.
fn password() -> impl Strategy<Value = String> {
    prop::collection::vec(
        prop_oneof![
            4 => prop::char::range('a', 'z'),
            2 => prop::char::range('A', 'Z'),
            2 => prop::char::range('0', '9'),
            1 => prop::sample::select(vec!['å', 'é', 'Ω', '漢', ' ', '-', '_', '!', '\u{fb01}']),
        ],
        1..40,
    )
    .prop_map(|v| v.into_iter().collect())
}

fn input(pw: &str, sk: Option<[u8; 16]>) -> ferret_core::OpaqueInput {
    MasterPassword::for_unlock(pw.as_bytes())
        .unwrap()
        .opaque_input(sk.map(SecretKey::from_test_bytes).as_ref())
}

proptest! {
    #![proptest_config(ProptestConfig { cases: cases(), ..ProptestConfig::default() })]

    /// Registration then login against the server gives the same export key;
    /// another password or secret key gives the one authentication error.
    #[test]
    fn opaque_roundtrip_against_server(
        pw in password(),
        other in password(),
        sk in prop::option::of(any::<[u8; 16]>()),
        other_sk in prop::option::of(any::<[u8; 16]>()),
        seed in any::<[u8; 8]>(),
    ) {
        let ksf = TestKsf::new(SMALL);
        let server = Server::new(&mut TestRng::new(&[&seed[..], b"s"].concat()));
        let right = input(&pw, sk);
        let mut rng = TestRng::new(&[&seed[..], b"c"].concat());

        let (request, state) = opaque_register_start(&mut rng, &right).unwrap();
        let response = server.register_response(CRED, &request).unwrap();
        let reg = register_finish_with(&mut rng, state, &right, &response, &ksf).unwrap();

        let login = |attempt: &ferret_core::OpaqueInput, rng: &mut TestRng| {
            let (ke1, state) = opaque_login_start(rng, attempt).unwrap();
            let (ke2, server_state) = server
                .login_start(rng, Some(&reg.record), CRED, &ke1)
                .unwrap();
            let done = login_finish_with(
                rng, state, attempt, &ke2, &ksf, Some(OPAQUE_CONTEXT), PinState::FirstUse,
            )?;
            Ok::<_, Error>((done, server_state))
        };

        let (done, server_state) = login(&right, &mut rng).unwrap();
        prop_assert_eq!(export_key_bytes(&done.finished.export_key), export_key_bytes(&reg.export_key));
        prop_assert_eq!(done.finished.server_public_key, server.public_key());
        let server_session = server_state.finish(&done.finished.ke3).unwrap();
        prop_assert_eq!(server_session, done.session_key);

        // The same password and secret key again: the same export key, a
        // fresh KE3 (the nonces are fresh).
        let (again, _) = login(&right, &mut rng).unwrap();
        prop_assert_eq!(export_key_bytes(&again.finished.export_key), export_key_bytes(&reg.export_key));
        prop_assert_ne!(again.finished.ke3, done.finished.ke3);

        // Something else: the single authentication error, and nothing else
        // (unless it is the same password and secret key after NFKD).
        let wrong = input(&other, other_sk);
        let same = nfkd_equal(&pw, &other) && sk == other_sk;
        match login(&wrong, &mut rng) {
            Ok((ok, _)) => {
                prop_assert!(same);
                prop_assert_eq!(
                    export_key_bytes(&ok.finished.export_key),
                    export_key_bytes(&reg.export_key)
                );
            }
            Err(e) => {
                prop_assert_eq!(e, Error::Decrypt);
                prop_assert!(!same);
            }
        }
    }

    /// Arbitrary bytes as the server's messages are refused with a structure
    /// error or the authentication error, never accepted and never a panic.
    #[test]
    fn opaque_rejects_arbitrary_server_messages(
        bytes in prop::collection::vec(any::<u8>(), 0..400),
        response in prop::collection::vec(any::<u8>(), 0..100),
    ) {
        let ksf = TestKsf::new(SMALL);
        let pw = input("correct horse battery", None);
        let mut rng = TestRng::new(b"arbitrary");
        let (_ke1, state) = opaque_login_start(&mut rng, &pw).unwrap();
        match login_finish_with(&mut rng, state, &pw, &bytes, &ksf, Some(OPAQUE_CONTEXT), PinState::FirstUse) {
            Ok(_) => prop_assert!(false, "accepted"),
            Err(e) => prop_assert!(
                matches!(e, Error::Decrypt | Error::Malformed(MalformedKind::OpaqueMessage)),
                "{:?}", e
            ),
        }
        let (_req, state) = opaque_register_start(&mut rng, &pw).unwrap();
        match register_finish_with(&mut rng, state, &pw, &response, &ksf) {
            Ok(done) => {
                // 64 bytes that happen to decode as two valid points: the
                // client cannot tell (registration has nothing to verify).
                prop_assert_eq!(response.len(), 64);
                prop_assert_eq!(done.record.len(), 192);
            }
            Err(e) => prop_assert!(
                matches!(e, Error::Decrypt | Error::Malformed(MalformedKind::OpaqueMessage)),
                "{:?}", e
            ),
        }
    }
}

/// Two passwords that normalize (NFKD) to the same bytes are the same
/// password for OPAQUE.
fn nfkd_equal(a: &str, b: &str) -> bool {
    use ferret_core::testing::text::master_password_bytes;
    let norm = |s: &str| master_password_bytes(&MasterPassword::for_unlock(s.as_bytes()).unwrap());
    norm(a) == norm(b)
}
