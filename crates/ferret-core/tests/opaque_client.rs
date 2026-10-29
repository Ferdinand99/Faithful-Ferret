//! The OPAQUE client (Fase 1 § 4.1 and § 4.2, plan Task 8) against
//! `opaque-ke`'s own server, and its key stretching function.
//!
//! Most tests use Argon2id parameters far below the floor through
//! `testing::opaque` (a few KiB, milliseconds). The ones that name the
//! profile, the pins or the production vectors use the production functions
//! at profile 1 (64 MiB) and are marked `slow` in the name or the comment.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]

mod common;

use common::*;
use ferret_core::testing::TestRng;
use ferret_core::testing::opaque::{
    KE2_BYTES, REGISTRATION_RESPONSE_BYTES, Server, ServerLoginState, TestKsf, default_ksf_hash,
    login_finish_with, register_finish_with,
};
use ferret_core::testing::prim::{argon2_run_count, argon2id_unchecked};
use ferret_core::testing::vector::Outcome;
use ferret_core::{
    Error, ExportKey, InputError, KDF_FLOOR, KdfParams, KsfProfile, LoginFinished, LoginState,
    MalformedKind, MasterPassword, OPAQUE_CONTEXT, OpaqueInput, PinState, Pinned, PinnedField,
    RegistrationFinished, RegistrationState, SecretKey, SecureRng, VaultId, opaque_login_finish,
    opaque_login_start, opaque_register_finish, opaque_register_start,
};
use serde_json::json;
use static_assertions::assert_not_impl_any;
use zeroize::Zeroize;

/// A few KiB: far below the floor, so that tests run in milliseconds.
const SMALL: KdfParams = KdfParams {
    m_kib: 64,
    t: 1,
    p: 1,
};
const CRED: &[u8] = b"0123456789abcdef";

fn rng(seed: &str) -> TestRng {
    TestRng::new(seed.as_bytes())
}

fn mp(text: &str) -> MasterPassword {
    MasterPassword::for_unlock(text.as_bytes()).unwrap()
}

fn sk(b: u8) -> SecretKey {
    SecretKey::from_test_bytes([b; 16])
}

fn input(text: &str, with_sk: Option<u8>) -> OpaqueInput {
    mp(text).opaque_input(with_sk.map(sk).as_ref())
}

fn export_bytes(k: &ExportKey) -> [u8; 64] {
    ferret_core::testing::keys::export_key_bytes(k)
}

fn same_export(a: &ExportKey, b: &ExportKey) -> bool {
    export_bytes(a) == export_bytes(b)
}

/// A registered account on a test server.
struct Account {
    server: Server,
    record: Vec<u8>,
    export_key: ExportKey,
    server_public_key: [u8; 32],
}

fn register(server: Server, pw: &OpaqueInput, ksf: &TestKsf, seed: &str) -> Account {
    let mut r = rng(seed);
    let (request, state) = opaque_register_start(&mut r, pw).unwrap();
    let response = server.register_response(CRED, &request).unwrap();
    assert_eq!(response.len(), REGISTRATION_RESPONSE_BYTES);
    let done = register_finish_with(&mut r, state, pw, &response, ksf).unwrap();
    assert_eq!(done.record.len(), 192);
    assert_eq!(done.server_public_key, server.public_key());
    Account {
        server,
        record: done.record,
        export_key: done.export_key,
        server_public_key: done.server_public_key,
    }
}

/// The client's state, the server's state and the server's `KE2`.
fn login_up_to_ke2(
    acc: &Account,
    pw: &OpaqueInput,
    seed: &str,
) -> (LoginState, ServerLoginState, Vec<u8>) {
    let mut r = rng(seed);
    let (ke1, state) = opaque_login_start(&mut r, pw).unwrap();
    assert_eq!(ke1.len(), 96);
    let mut sr = rng(&format!("{seed}/server"));
    let (ke2, server_state) = acc
        .server
        .login_start(&mut sr, Some(&acc.record), CRED, &ke1)
        .unwrap();
    assert_eq!(ke2.len(), KE2_BYTES);
    (state, server_state, ke2)
}

fn small() -> TestKsf {
    TestKsf::new(SMALL)
}

// ------------------------------------------------------------------ KSF

/// `FerretKsf::hash(x)` is Argon2id v1.3 of `x` with a salt of 16 zero
/// bytes, profile 1, 64 bytes out (the RFC 9106 implementation of Task 2,
/// asked for directly). Slow: 64 MiB.
#[test]
fn ksf_matches_direct_argon2id() {
    let x: [u8; 64] = core::array::from_fn(|i| u8::try_from(i).unwrap().wrapping_mul(7));
    let ksf = TestKsf::of_profile(KsfProfile::P1);
    assert_eq!(ksf.params(), KsfProfile::P1.params());
    assert_eq!(ksf.params(), KDF_FLOOR);
    let got = ksf.hash(&x).unwrap();
    let mut want = [0u8; 64];
    argon2id_unchecked(&x, &[0u8; 16], &[], &[], KDF_FLOOR, &mut want).unwrap();
    assert_eq!(got, want);
    // And `Default` is profile 1.
    assert_eq!(default_ksf_hash(&x).unwrap(), want);
}

/// The same output as `opaque-ke`'s own `Argon2` key stretching function,
/// which is `argon2` 0.5 with `hash_password_into(input, [0; 16], out)`:
/// here that code is written out over the independent `argon2_05` crate, for
/// profile-1 parameters and for small ones. Slow for the first.
#[test]
fn ksf_matches_opaque_ke_builtin_argon2() {
    use argon2_05::{Algorithm, Argon2, Params, Version};
    let x: [u8; 64] = core::array::from_fn(|i| u8::try_from(i).unwrap() ^ 0xa5);
    for p in [
        SMALL,
        KdfParams {
            m_kib: 4096,
            t: 2,
            p: 2,
        },
        KDF_FLOOR,
    ] {
        let params = Params::new(p.m_kib, p.t, p.p, None).unwrap();
        let theirs = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
        let mut want = [0u8; 64];
        theirs
            .hash_password_into(&x, &[0u8; 16], &mut want)
            .unwrap();
        let got = TestKsf::new(p).hash(&x).unwrap();
        assert_eq!(got, want, "m={} t={} p={}", p.m_kib, p.t, p.p);
    }
}

/// The client hands the instance it was given to `opaque-ke`: two
/// instances with other parameters give other export keys for the very same
/// protocol run, and the `Default` instance (profile 1) is not what is used.
#[test]
fn ksf_uses_supplied_instance_not_default() {
    let pw = input("correct horse battery", None);
    let other = KdfParams {
        m_kib: 128,
        t: 2,
        p: 1,
    };
    let keys: Vec<ExportKey> = [SMALL, other, SMALL]
        .into_iter()
        .map(|p| {
            let server = Server::new(&mut rng("ksf/server"));
            register(server, &pw, &TestKsf::new(p), "ksf/client").export_key
        })
        .collect();
    assert!(
        !same_export(&keys[0], &keys[1]),
        "other parameters, other key"
    );
    assert!(same_export(&keys[0], &keys[2]), "same parameters, same key");
    // The default instance is a different function (profile 1) from both.
    let x = [9u8; 64];
    assert_ne!(
        TestKsf::new(SMALL).hash(&x).unwrap(),
        TestKsf::new(other).hash(&x).unwrap()
    );
    assert_ne!(
        TestKsf::new(SMALL).hash(&x).unwrap(),
        default_ksf_hash(&x).unwrap()
    );
}

// ------------------------------------------------------------ the profile

fn pinned(profile: u8, sk_bit: bool, server_key: Option<[u8; 32]>) -> Pinned {
    Pinned {
        server_url: "https://ferret.example".into(),
        account_id: account(0x11),
        vault_id: VaultId::from_bytes([0x22; 16]),
        ksf_profile: profile,
        kek_generation_max: vec![],
        vk_epoch_max: 1,
        sk_bit,
        pk_a: [7; 32],
        server_public_key: server_key,
    }
}

/// A login that has got as far as `KE2`, for the tests of what the finish
/// refuses before it computes anything.
fn ready_login(with_sk: Option<u8>) -> (Account, OpaqueInput, LoginState, Vec<u8>) {
    let pw = input("correct horse battery", with_sk);
    let acc = register(Server::new(&mut rng("p/server")), &pw, &small(), "p/reg");
    let (state, _server, ke2) = login_up_to_ke2(&acc, &pw, "p/login");
    (acc, pw, state, ke2)
}

#[test]
fn profile_unknown_is_hard_error_before_argon() {
    for unknown in [0u32, 2, 3, 255, 257, u32::MAX] {
        let (_acc, pw, state, ke2) = ready_login(None);
        let before = argon2_run_count();
        let err = opaque_login_finish(&mut rng("x"), state, &pw, &ke2, unknown, PinState::FirstUse)
            .err()
            .unwrap();
        assert_eq!(err, Error::KdfProfileUnknown, "profile {unknown}");
        assert_eq!(err.code(), "kdf_profile_unknown");
        assert_eq!(argon2_run_count(), before, "no Argon2 for {unknown}");
    }
    // Through the wire parser too.
    assert_eq!(KsfProfile::from_wire(2), Err(Error::KdfProfileUnknown));
    assert_eq!(KsfProfile::from_wire(1), Ok(KsfProfile::P1));
}

#[test]
fn profile_below_pinned_is_downgrade_error() {
    let (_acc, pw, state, ke2) = ready_login(None);
    // A device that pinned profile 2 (a later release) sees the server state 1.
    let pin = pinned(2, false, None);
    let before = argon2_run_count();
    let err = opaque_login_finish(&mut rng("x"), state, &pw, &ke2, 1, PinState::Pinned(&pin))
        .err()
        .unwrap();
    assert_eq!(err, Error::KdfProfileDowngrade);
    assert_eq!(err.code(), "kdf_profile_downgrade");
    assert_eq!(argon2_run_count(), before, "no Argon2");
}

/// The floor and ceiling of the profile's parameters are checked before the
/// stretching, by the same function the rest of the core uses; the table
/// itself is inside them.
#[test]
fn profile_parameters_are_inside_floor_and_ceiling() {
    let p = KsfProfile::P1.params();
    assert_eq!(ferret_core::check_kdf_params(p), Ok(p));
    assert_eq!(p, KDF_FLOOR);
}

/// The SK bit comes from the pinned record and the input, never from the
/// server: a mismatch is a hard error, and no Argon2 runs.
#[test]
fn sk_bit_mismatch_with_pinned_is_hard_error_before_argon() {
    for (with_sk, pinned_bit) in [(None, true), (Some(5), false)] {
        let (_acc, pw, state, ke2) = ready_login(with_sk);
        let before = argon2_run_count();
        let pin = pinned(1, pinned_bit, None);
        let err = opaque_login_finish(&mut rng("x"), state, &pw, &ke2, 1, PinState::Pinned(&pin))
            .err()
            .unwrap();
        assert_eq!(err, Error::Pinned(PinnedField::SkBit));
        assert_eq!(argon2_run_count(), before, "no Argon2");
    }
}

#[test]
fn password_input_remembers_the_secret_key_bit() {
    assert!(!input("correct horse battery", None).includes_secret_key());
    assert!(input("correct horse battery", Some(1)).includes_secret_key());
}

// ----------------------------------------------------------- round trips

#[test]
fn opaque_roundtrip_against_server() {
    for with_sk in [None, Some(0x33)] {
        let pw = input("correct horse battery", with_sk);
        let acc = register(Server::new(&mut rng("rt/server")), &pw, &small(), "rt/reg");

        let (state, server_state, ke2) = login_up_to_ke2(&acc, &pw, "rt/login");
        let done = login_finish_with(
            &mut rng("rt/fin"),
            state,
            &pw,
            &ke2,
            &small(),
            Some(OPAQUE_CONTEXT),
            PinState::FirstUse,
        )
        .unwrap();
        // The same export key as at registration.
        assert!(same_export(&done.finished.export_key, &acc.export_key));
        assert_eq!(done.finished.server_public_key, acc.server_public_key);
        assert_eq!(done.finished.ke3.len(), 64);
        // The server accepts KE3 and both sides hold the same session key.
        let server_key = server_state.finish(&done.finished.ke3).unwrap();
        assert_eq!(server_key, done.session_key);
        assert_eq!(done.session_key.len(), 64);
    }
}

#[test]
fn wrong_password_wrong_sk_and_missing_sk_are_one_error() {
    let right = input("correct horse battery", Some(0x33));
    let acc = register(Server::new(&mut rng("w/server")), &right, &small(), "w/reg");
    let attempts = [
        ("wrong password", input("correct horse batterz", Some(0x33))),
        ("wrong SK", input("correct horse battery", Some(0x34))),
        ("no SK", input("correct horse battery", None)),
        (
            "password with a trailing space",
            input("correct horse battery ", Some(0x33)),
        ),
    ];
    for (what, wrong) in attempts {
        let (state, _server, ke2) = login_up_to_ke2(&acc, &wrong, "w/login");
        let err = login_finish_with(
            &mut rng("w/fin"),
            state,
            &wrong,
            &ke2,
            &small(),
            Some(OPAQUE_CONTEXT),
            PinState::FirstUse,
        )
        .err()
        .unwrap();
        assert_eq!(err, Error::Decrypt, "{what}");
        assert_eq!(err.code(), "decrypt", "{what}");
    }
}

#[test]
fn with_and_without_sk_give_different_export_keys() {
    let plain = input("correct horse battery", None);
    let with = input("correct horse battery", Some(0x33));
    let a = register(
        Server::new(&mut rng("sk/server")),
        &plain,
        &small(),
        "sk/reg",
    );
    let b = register(
        Server::new(&mut rng("sk/server")),
        &with,
        &small(),
        "sk/reg",
    );
    assert!(!same_export(&a.export_key, &b.export_key));
}

#[test]
fn another_server_key_gives_another_record_and_export_key() {
    let pw = input("correct horse battery", None);
    let a = register(Server::new(&mut rng("s1")), &pw, &small(), "same");
    let b = register(Server::new(&mut rng("s2")), &pw, &small(), "same");
    assert_ne!(a.server_public_key, b.server_public_key);
    assert!(!same_export(&a.export_key, &b.export_key));
}

#[test]
fn opaque_context_is_ferret_v1_opaque() {
    assert_eq!(OPAQUE_CONTEXT, b"ferret/v1/opaque");
    let pw = input("correct horse battery", None);
    // A server with another context cannot be logged in to.
    let acc = register(
        Server::new(&mut rng("c/server")).with_context(b"ferret/v1/other"),
        &pw,
        &small(),
        "c/reg",
    );
    let (state, _server, ke2) = login_up_to_ke2(&acc, &pw, "c/login");
    let err = login_finish_with(
        &mut rng("c/fin"),
        state,
        &pw,
        &ke2,
        &small(),
        Some(OPAQUE_CONTEXT),
        PinState::FirstUse,
    )
    .err()
    .unwrap();
    assert_eq!(err, Error::Decrypt);
    // And a client with another context cannot log in to Ferret's server.
    let acc = register(Server::new(&mut rng("c/server")), &pw, &small(), "c/reg");
    let (state, _server, ke2) = login_up_to_ke2(&acc, &pw, "c/login");
    let err = login_finish_with(
        &mut rng("c/fin"),
        state,
        &pw,
        &ke2,
        &small(),
        Some(b"ferret/v1/opaque "),
        PinState::FirstUse,
    )
    .err()
    .unwrap();
    assert_eq!(err, Error::Decrypt);
    // The right context on both sides works (control).
    let (state, _server, ke2) = login_up_to_ke2(&acc, &pw, "c/login");
    assert!(
        login_finish_with(
            &mut rng("c/fin"),
            state,
            &pw,
            &ke2,
            &small(),
            Some(OPAQUE_CONTEXT),
            PinState::FirstUse
        )
        .is_ok()
    );
}

/// Client and server identities are empty (the public keys stand in): a
/// server that sets identities cannot be logged in to, and the RFC vector
/// test shows that the same code works when both sides set them.
#[test]
fn opaque_identifiers_are_none() {
    let pw = input("correct horse battery", None);
    let acc = register(
        Server::new(&mut rng("i/server")).with_identities(b"alice", b"bob"),
        &pw,
        &small(),
        "i/reg",
    );
    let (state, _server, ke2) = login_up_to_ke2(&acc, &pw, "i/login");
    let err = login_finish_with(
        &mut rng("i/fin"),
        state,
        &pw,
        &ke2,
        &small(),
        Some(OPAQUE_CONTEXT),
        PinState::FirstUse,
    )
    .err()
    .unwrap();
    assert_eq!(err, Error::Decrypt);
}

// ----------------------------------------------------------- draws

struct Recording<'a>(&'a mut TestRng, Vec<usize>);

impl SecureRng for Recording<'_> {
    fn fill(&mut self, dest: &mut [u8]) {
        self.1.push(dest.len());
        self.0.fill(dest);
    }
}

/// The draws of each step, in order and length (the vectors list them).
#[test]
fn draws_are_blind_then_nonce_and_blind_seed_nonce() {
    let pw = input("correct horse battery", None);
    let server = Server::new(&mut rng("d/server"));
    let mut base = rng("d/client");
    let mut rec = Recording(&mut base, vec![]);
    let (request, state) = opaque_register_start(&mut rec, &pw).unwrap();
    assert_eq!(rec.1, [64]);
    let response = server.register_response(CRED, &request).unwrap();
    let done = register_finish_with(&mut rec, state, &pw, &response, &small()).unwrap();
    assert_eq!(rec.1, [64, 32]);
    let (ke1, state) = opaque_login_start(&mut rec, &pw).unwrap();
    assert_eq!(rec.1, [64, 32, 64, 32, 32]);
    let (ke2, _s) = server
        .login_start(&mut rng("d/s2"), Some(&done.record), CRED, &ke1)
        .unwrap();
    login_finish_with(
        &mut rec,
        state,
        &pw,
        &ke2,
        &small(),
        Some(OPAQUE_CONTEXT),
        PinState::FirstUse,
    )
    .unwrap();
    assert_eq!(
        rec.1,
        [64, 32, 64, 32, 32],
        "the login finish draws nothing"
    );
}

// ------------------------------------------------------ server's key pin

#[test]
fn first_use_is_trusted_and_a_pinned_key_shown_again_is_accepted() {
    let pw = input("correct horse battery", None);
    let acc = register(Server::new(&mut rng("k/server")), &pw, &small(), "k/reg");
    let run = |pin: PinState<'_>| {
        let (state, _server, ke2) = login_up_to_ke2(&acc, &pw, "k/login");
        login_finish_with(
            &mut rng("k/fin"),
            state,
            &pw,
            &ke2,
            &small(),
            Some(OPAQUE_CONTEXT),
            pin,
        )
    };
    // First use (trust on first use): accepted, and the key is returned to
    // be pinned.
    assert_eq!(
        run(PinState::FirstUse).unwrap().finished.server_public_key,
        acc.server_public_key
    );
    // A record with no server key pinned yet (TOFU of the key): accepted.
    assert!(run(PinState::Pinned(&pinned(1, false, None))).is_ok());
    // The pinned key shown again: accepted.
    let pin = pinned(1, false, Some(acc.server_public_key));
    assert!(run(PinState::Pinned(&pin)).is_ok());
}

/// A server that keeps the account's record and OPRF seed but presents
/// another OPAQUE key pair is *not* reported as `pinned_server_key` at login:
/// the server's key is covered by the envelope's MAC, so the envelope fails
/// first and the client sees the single authentication error. (The detection
/// of a changed key is the comparison of `RegistrationFinished::server_public_key`
/// with the pinned key on re-registration; the comparison at login is
/// defence in depth, exercised by the vector `opaque/login/017`.)
#[test]
fn a_changed_server_key_at_login_is_decrypt() {
    let pw = input("correct horse battery", None);
    let acc = register(Server::new(&mut rng("k/server")), &pw, &small(), "k/reg");
    let other = Server::new(&mut rng("k/other"));
    assert_ne!(other.public_key(), acc.server_public_key);
    let moved = Account {
        server: acc.server.with_key_of(&other),
        record: acc.record.clone(),
        export_key: ExportKey::from_test_bytes(export_bytes(&acc.export_key)),
        server_public_key: other.public_key(),
    };
    assert_eq!(moved.server.public_key(), other.public_key());
    // The pinned record has the old key, as a device that has used the
    // account before.
    let pin = pinned(1, false, Some(acc.server_public_key));
    for state_of_pin in [PinState::FirstUse, PinState::Pinned(&pin)] {
        let (state, _server, ke2) = login_up_to_ke2(&moved, &pw, "k/login");
        let err = login_finish_with(
            &mut rng("k/fin"),
            state,
            &pw,
            &ke2,
            &small(),
            Some(OPAQUE_CONTEXT),
            state_of_pin,
        )
        .err()
        .unwrap();
        assert_eq!(err, Error::Decrypt);
    }
    // Control: the unmoved server logs in.
    let (state, _server, ke2) = login_up_to_ke2(&acc, &pw, "k/login");
    assert!(
        login_finish_with(
            &mut rng("k/fin"),
            state,
            &pw,
            &ke2,
            &small(),
            Some(OPAQUE_CONTEXT),
            PinState::Pinned(&pin),
        )
        .is_ok()
    );
}

/// Re-registration is where a changed key is seen: the response carries the
/// server's key, and `RegistrationFinished::server_public_key` differs from
/// the pinned one. (Task 9 turns that into the U19 warning.)
#[test]
fn registration_shows_the_server_key_for_the_caller_to_compare() {
    let pw = input("correct horse battery", None);
    let acc = register(Server::new(&mut rng("r/server")), &pw, &small(), "r/reg");
    let other = Server::new(&mut rng("r/other"));
    let moved = acc.server.with_key_of(&other);
    let mut r = rng("r/again");
    let (request, state) = opaque_register_start(&mut r, &pw).unwrap();
    let response = moved.register_response(CRED, &request).unwrap();
    let done = register_finish_with(&mut r, state, &pw, &response, &small()).unwrap();
    assert_eq!(done.server_public_key, other.public_key());
    assert_ne!(done.server_public_key, acc.server_public_key);
}

// --------------------------------------------------- malformed messages

#[test]
fn opaque_rejects_malformed_server_messages() {
    let pw = input("correct horse battery", None);
    let acc = register(Server::new(&mut rng("m/server")), &pw, &small(), "m/reg");
    let mut variants: Vec<(String, Vec<u8>)> = vec![
        ("empty".into(), vec![]),
        ("one byte".into(), vec![1]),
        ("zeros".into(), vec![0; KE2_BYTES]),
        ("ff".into(), vec![0xff; KE2_BYTES]),
        ("short".into(), vec![7; KE2_BYTES - 1]),
        ("long".into(), vec![7; KE2_BYTES + 1]),
        ("long x2".into(), vec![7; KE2_BYTES * 2]),
    ];
    let (_s, _server, good) = login_up_to_ke2(&acc, &pw, "m/login");
    for cut in [1usize, 32, 64, 100, 319] {
        variants.push((format!("good, cut to {cut}"), good[..cut].to_vec()));
    }
    let mut longer = good.clone();
    longer.push(0);
    variants.push(("good + 1".into(), longer));
    // An invalid group element where the evaluated element is.
    let mut bad_point = good.clone();
    bad_point[..32].copy_from_slice(&[0xee; 32]);
    variants.push(("invalid evaluated element".into(), bad_point));
    // An invalid server ephemeral public key.
    let mut bad_pk = good.clone();
    bad_pk[224..256].copy_from_slice(&[0xee; 32]);
    variants.push(("invalid server ephemeral key".into(), bad_pk));

    for (what, bytes) in variants {
        let (state, _server, _ke2) = login_up_to_ke2(&acc, &pw, "m/login");
        let err = login_finish_with(
            &mut rng("m/fin"),
            state,
            &pw,
            &bytes,
            &small(),
            Some(OPAQUE_CONTEXT),
            PinState::FirstUse,
        )
        .err()
        .unwrap_or_else(|| panic!("{what}: accepted"));
        assert!(
            matches!(
                err,
                Error::Decrypt | Error::Malformed(MalformedKind::OpaqueMessage)
            ),
            "{what}: {err:?}"
        );
        if bytes.len() != KE2_BYTES {
            assert_eq!(
                err,
                Error::Malformed(MalformedKind::OpaqueMessage),
                "{what}"
            );
        }
    }
    // The registration response too.
    for len in [0usize, 1, 31, 32, 63, 65, 96, 200] {
        let (_r, state) = opaque_register_start(&mut rng("m/r"), &pw).unwrap();
        let err = register_finish_with(&mut rng("m/rf"), state, &pw, &vec![5; len], &small())
            .err()
            .unwrap();
        assert_eq!(
            err,
            Error::Malformed(MalformedKind::OpaqueMessage),
            "len {len}"
        );
    }
    for bytes in [vec![0u8; 64], vec![0xffu8; 64], vec![0xeeu8; 64]] {
        let (_r, state) = opaque_register_start(&mut rng("m/r"), &pw).unwrap();
        let err = register_finish_with(&mut rng("m/rf"), state, &pw, &bytes, &small())
            .err()
            .unwrap();
        assert!(
            matches!(err, Error::Decrypt | Error::Malformed(_)),
            "{err:?}"
        );
    }
    assert_eq!(
        Error::Malformed(MalformedKind::OpaqueMessage).code(),
        "malformed_opaque_message"
    );
}

/// Any single changed byte of a good `KE2` is refused, never accepted, and
/// the error is either the one authentication error or (when the byte turns
/// a point invalid) the structure error.
#[test]
fn every_changed_byte_of_ke2_is_refused() {
    let pw = input("correct horse battery", None);
    let acc = register(Server::new(&mut rng("e/server")), &pw, &small(), "e/reg");
    let (_s, _server, good) = login_up_to_ke2(&acc, &pw, "e/login");
    for i in 0..good.len() {
        let (state, _server, _x) = login_up_to_ke2(&acc, &pw, "e/login");
        let mut bad = good.clone();
        bad[i] ^= 0x40;
        let err = login_finish_with(
            &mut rng("e/fin"),
            state,
            &pw,
            &bad,
            &small(),
            Some(OPAQUE_CONTEXT),
            PinState::FirstUse,
        )
        .err()
        .unwrap_or_else(|| panic!("byte {i} changed: accepted"));
        assert!(
            matches!(
                err,
                Error::Decrypt | Error::Malformed(MalformedKind::OpaqueMessage)
            ),
            "byte {i}: {err:?}"
        );
    }
}

#[test]
fn empty_password_is_refused_before_anything_runs() {
    let empty = mp("").opaque_input(None);
    assert_eq!(
        opaque_register_start(&mut rng("z"), &empty).err(),
        Some(Error::InvalidInput(InputError::TooShort))
    );
    assert_eq!(
        opaque_login_start(&mut rng("z"), &empty).err(),
        Some(Error::InvalidInput(InputError::TooShort))
    );
}

// ------------------------------------------------- types and the secrets

assert_not_impl_any!(
    RegistrationState: Clone, Copy, core::fmt::Debug, core::fmt::Display, PartialEq
);
assert_not_impl_any!(LoginState: Clone, Copy, core::fmt::Debug, core::fmt::Display, PartialEq);
assert_not_impl_any!(
    RegistrationFinished: Clone, Copy, core::fmt::Debug, core::fmt::Display, PartialEq
);
assert_not_impl_any!(
    LoginFinished: Clone, Copy, core::fmt::Debug, core::fmt::Display, PartialEq
);

#[test]
fn opaque_states_are_not_clone_or_debug() {
    // Checked at compile time above. The states are also wiped on drop:
    // `opaque-ke`'s `ClientRegistration` and `ClientLogin` are `ZeroizeOnDrop`
    // (derive-where), and our wrappers own them without copying.
    fn needs_drop<T>() -> bool {
        core::mem::needs_drop::<T>()
    }
    assert!(needs_drop::<RegistrationState>());
    assert!(needs_drop::<LoginState>());
}

/// `LoginFinished` has exactly three fields, and none is the session key:
/// this pattern stops compiling if one is added. (The session key is also
/// the subject of a `compile_fail` doctest on the type.)
#[test]
fn opaque_session_key_is_not_exposed() {
    let pw = input("correct horse battery", None);
    let acc = register(
        Server::new(&mut rng("sess/server")),
        &pw,
        &small(),
        "sess/reg",
    );
    let (state, _server, ke2) = login_up_to_ke2(&acc, &pw, "sess/login");
    let session = login_finish_with(
        &mut rng("sess/fin"),
        state,
        &pw,
        &ke2,
        &small(),
        Some(OPAQUE_CONTEXT),
        PinState::FirstUse,
    )
    .unwrap();
    let LoginFinished {
        ke3,
        export_key: _,
        server_public_key,
    } = session.finished;
    assert_eq!(ke3.len(), 64);
    assert_eq!(server_public_key, acc.server_public_key);
    // The test-support build can see the key (to compare with the server's);
    // nothing in `LoginFinished` or the production function carries it.
    assert_eq!(session.session_key.len(), 64);
    assert!(
        !ke3.windows(8)
            .any(|w| session.session_key.windows(8).any(|s| s == w)),
        "KE3 does not contain the session key"
    );
    let RegistrationFinished {
        record,
        export_key: _,
        server_public_key,
    } = RegistrationFinished {
        record: acc.record.clone(),
        export_key: ExportKey::from_test_bytes([0; 64]),
        server_public_key: acc.server_public_key,
    };
    assert_eq!(record.len(), 192);
    assert_eq!(server_public_key, acc.server_public_key);
}

#[test]
fn opaque_input_is_zeroized() {
    // The password input `mp ‖ 0x00 ‖ SK` is built once, at its final size,
    // and wiped by `zeroize` and on drop (the wipe of the buffer itself is
    // checked in `tests/text.rs`); OPAQUE reads it and never copies it into
    // anything it keeps.
    use zeroize::ZeroizeOnDrop;
    static_assertions::assert_impl_all!(OpaqueInput: Zeroize, ZeroizeOnDrop);
    let mut pw = input("correct horse battery", Some(0x55));
    let (ptr, cap) = pw.test_buffer();
    assert_eq!(cap, "correct horse battery".len() + 1 + 16);
    let before: Vec<u8> = (0..cap)
        // SAFETY: the buffer is alive and `cap` bytes were written.
        .map(|i| unsafe { ptr.add(i).read_volatile() })
        .collect();
    assert_eq!(before[21], 0x00);
    assert_eq!(&before[22..], &[0x55; 16]);
    let _ = login_start_only(&pw);
    pw.zeroize();
    let after: Vec<u8> = (0..cap)
        // SAFETY: `zeroize` keeps the allocation and writes zeros over it.
        .map(|i| unsafe { ptr.add(i).read_volatile() })
        .collect();
    assert!(after.iter().all(|b| *b == 0));
}

fn login_start_only(pw: &OpaqueInput) -> Vec<u8> {
    opaque_login_start(&mut rng("zero"), pw).unwrap().0
}

// ------------------------------------------------- production vectors

fn run_vectors() -> ferret_core::testing::vector::RunReport {
    let path = vectors_dir().join("internal/opaque.json");
    let file = ferret_core::testing::vector::load(&path).unwrap();
    ferret_core::testing::vector::run_all(&file, |case, rng| {
        let i = &case.input;
        let sk_bytes: Option<[u8; 16]> = i["secret_key"].as_str().map(|s| hexn(&json!(s)));
        let pw = MasterPassword::for_unlock(&hex(&i["password_hex"]))
            .unwrap()
            .opaque_input(sk_bytes.map(SecretKey::from_test_bytes).as_ref());
        match case.op.as_str() {
            "opaque.register" => {
                let (request, state) = opaque_register_start(rng, &pw)?;
                let profile = KsfProfile::from_wire(i["ksf_profile"].as_u64().unwrap() as u32)?;
                let done = opaque_register_finish(rng, state, &pw, &hex(&i["response"]), profile)?;
                Ok(Outcome {
                    output: json!({
                        "request": he(&request),
                        "record": he(&done.record),
                        "export_key": he(&export_bytes(&done.export_key)),
                        "server_public_key": he(&done.server_public_key),
                    }),
                    intermediate: None,
                })
            }
            "opaque.login" => {
                let (ke1, state) = opaque_login_start(rng, &pw)?;
                let pin = i.get("pinned").filter(|p| !p.is_null()).map(|p| {
                    pinned(
                        p["ksf_profile"].as_u64().unwrap() as u8,
                        p["sk_bit"].as_bool().unwrap(),
                        p["server_public_key"].as_str().map(|s| hexn(&json!(s))),
                    )
                });
                let done = opaque_login_finish(
                    rng,
                    state,
                    &pw,
                    &hex(&i["ke2"]),
                    i["server_profile"].as_u64().unwrap() as u32,
                    pin.as_ref().map_or(PinState::FirstUse, PinState::Pinned),
                )?;
                Ok(Outcome {
                    output: json!({
                        "ke1": he(&ke1),
                        "ke3": he(&done.ke3),
                        "export_key": he(&export_bytes(&done.export_key)),
                        "server_public_key": he(&done.server_public_key),
                    }),
                    intermediate: None,
                })
            }
            other => panic!("unknown op {other}"),
        }
    })
}

/// Every case of `vectors/internal/opaque.json` through the production
/// functions (profile 1, 64 MiB for each case that gets that far). Slow.
#[test]
fn opaque_production_vectors_from_file() {
    let report = run_vectors();
    assert!(report.failures.is_empty(), "{:#?}", report.failures);
    assert!(report.passed >= 10, "{} cases", report.passed);
}
