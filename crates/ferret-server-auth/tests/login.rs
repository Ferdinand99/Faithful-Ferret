//! Login on the server, against the login of the `ferret-core` client.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::arithmetic_side_effects
)]

use std::net::IpAddr;
use std::sync::Barrier;
use std::sync::atomic::{AtomicUsize, Ordering};

use ferret_core::opaque::server_suite::{KE1_LEN, KE3_LEN};
use ferret_core::testing::opaque::KE2_BYTES;
use ferret_core::{Error as ClientError, KsfProfile, OPAQUE_CONTEXT, ReplayRng, TestRng};
use ferret_server_auth::testing::{
    FIXTURE_IP, FIXTURE_PASSWORD, LoginFixture, login_start_with_context, put_state, take_state,
};
use ferret_server_auth::{
    AccountLookup, AuthError, DenyReason, ErrorClass, LoginFinishRequest, LoginId, LoginPurpose,
    LoginStartRequest, Malformed, Outcome, PreloginPolicy, RetryAfter, SessionBinding, Stage,
    ThrottleCall, ThrottleKey, fake_credential_id, login_start, register_start,
};

const NOW: u64 = LoginFixture::START;
const WRONG: &str = "wrong horse battery";

fn denied(reason: DenyReason) -> AuthError {
    AuthError::Denied(reason)
}

fn ip() -> IpAddr {
    FIXTURE_IP.parse().unwrap()
}

/// A client start and the server's answer for the account of the fixture.
fn started(
    f: &LoginFixture,
    password: &str,
    seed: &str,
) -> (
    ferret_server_auth::LoginStartResponse,
    ferret_core::LoginState,
) {
    let (ke1, state) = f.client_start(password, seed);
    let response = f.start(f.active(), &ke1, LoginPurpose::Login).unwrap();
    (response, state)
}

/// A whole login with the right password.
fn right_ke3(f: &LoginFixture) -> (LoginId, Vec<u8>) {
    let (response, state) = started(f, FIXTURE_PASSWORD, "client");
    let ke3 = f
        .client_finish(state, FIXTURE_PASSWORD, &response.ke2, OPAQUE_CONTEXT)
        .unwrap();
    (response.login_id, ke3)
}

fn session(fill: u8) -> SessionBinding {
    SessionBinding([fill; 32])
}

trait ReauthFor {
    /// A re-authentication of the session `a` for the account of the fixture.
    fn reauth(&self, a: SessionBinding) -> LoginPurpose;
}

impl ReauthFor for LoginFixture {
    fn reauth(&self, a: SessionBinding) -> LoginPurpose {
        LoginPurpose::Reauth {
            session: a,
            account: self.credential,
        }
    }
}

/// Byte strings that are not a ristretto255 element the protocol accepts.
fn invalid_points() -> Vec<[u8; 32]> {
    let all_ones = [0xffu8; 32];
    let mut negative = [0u8; 32];
    negative[0] = 1;
    let mut above_modulus = [0xffu8; 32];
    above_modulus[31] = 0x7f;
    vec![all_ones, negative, above_modulus, [0u8; 32]]
}

fn last_record(f: &LoginFixture) -> (Stage, Vec<ThrottleKey>, Outcome) {
    match f.throttle.calls().pop() {
        Some(ThrottleCall::Record {
            stage,
            keys,
            outcome,
            ..
        }) => (stage, keys, outcome),
        other => panic!("the last call is not a record: {other:?}"),
    }
}

// ------------------------------------------------------------- a full login

#[test]
fn finish_after_start_succeeds() {
    let f = LoginFixture::new();
    let (login_id, ke3) = right_ke3(&f);
    let verified = f.finish(&login_id, &ke3, None).unwrap();
    assert_eq!(verified.credential, f.credential);
    assert!(matches!(verified.purpose, LoginPurpose::Login));
    assert!(f.store.is_empty());
}

#[test]
fn finish_for_a_reauthentication_returns_that_purpose() {
    let f = LoginFixture::new();
    let (ke1, state) = f.client_start(FIXTURE_PASSWORD, "client");
    let a = session(7);
    let response = f.start(f.active(), &ke1, f.reauth(a)).unwrap();
    let ke3 = f
        .client_finish(state, FIXTURE_PASSWORD, &response.ke2, OPAQUE_CONTEXT)
        .unwrap();
    let verified = f
        .finish(&response.login_id, &ke3, Some((a, f.credential)))
        .unwrap();
    assert_eq!(verified.credential, f.credential);
    assert!(matches!(verified.purpose, LoginPurpose::Reauth { .. }));
}

#[test]
fn the_answer_carries_the_stored_profile_and_hint() {
    let f = LoginFixture::new();
    let (ke1, _) = f.client_start(FIXTURE_PASSWORD, "client");
    let lookup = AccountLookup::Active {
        record: &f.record,
        sk_hint: true,
    };
    let response = f.start(lookup, &ke1, LoginPurpose::Login).unwrap();
    assert_eq!(response.ksf_profile, f.record.ksf_profile);
    assert!(response.sk_hint);
    let response = f.start(f.active(), &ke1, LoginPurpose::Login).unwrap();
    assert!(!response.sk_hint);
}

// --------------------------------------------------------------- the shape

#[test]
fn login_start_has_the_same_shape_for_known_unknown_and_disabled() {
    let f = LoginFixture::new();
    let (ke1, _) = f.client_start(FIXTURE_PASSWORD, "client");
    for lookup in [f.active(), AccountLookup::Unknown, AccountLookup::Disabled] {
        let response = f.start(lookup, &ke1, LoginPurpose::Login).unwrap();
        assert_eq!(response.ke2.len(), KE2_BYTES);
        assert_eq!(response.ke2.len(), 320);
        assert!(KsfProfile::from_wire(u32::from(response.ksf_profile)).is_ok());
        assert_eq!(response.login_id.to_hex().len(), LoginId::HEX_LEN);
    }
    assert_eq!(f.store.len(), 3);
}

#[test]
fn disabled_account_looks_unknown() {
    let f = LoginFixture::new();
    let (ke1, _) = f.client_start(FIXTURE_PASSWORD, "client");
    let run = |lookup| {
        let request = LoginStartRequest {
            caller: LoginFixture::caller(),
            name: &f.name,
            credential: f.credential,
            lookup,
            purpose: LoginPurpose::Login,
            ke1: &ke1,
        };
        // A fresh store and the same random source: nothing may differ.
        let store = ferret_server_auth::InMemoryLoginStateStore::new();
        login_start(&f.cx(), &store, &mut TestRng::new(b"same draws"), &request).unwrap()
    };
    let unknown = run(AccountLookup::Unknown);
    let disabled = run(AccountLookup::Disabled);
    assert_eq!(unknown.ke2, disabled.ke2);
    assert_eq!(unknown.ksf_profile, disabled.ksf_profile);
    assert_eq!(unknown.sk_hint, disabled.sk_hint);
    assert_eq!(unknown.login_id.to_hex(), disabled.login_id.to_hex());
    // The caller's credential id plays no part for a name without an account.
    let other = |credential| {
        let request = LoginStartRequest {
            caller: LoginFixture::caller(),
            name: &f.name,
            credential,
            lookup: AccountLookup::Unknown,
            purpose: LoginPurpose::Login,
            ke1: &ke1,
        };
        let store = ferret_server_auth::InMemoryLoginStateStore::new();
        login_start(&f.cx(), &store, &mut TestRng::new(b"same draws"), &request)
            .unwrap()
            .ke2
    };
    assert_eq!(
        other(ferret_server_auth::CredentialId::from_bytes([9; 16])),
        unknown.ke2
    );
}

#[test]
fn repeated_probes_for_an_unknown_account_are_consistent() {
    let f = LoginFixture::new();
    let (ke1, _) = f.client_start(FIXTURE_PASSWORD, "client");
    let probe = |seed: &str| {
        let request = LoginStartRequest {
            caller: LoginFixture::caller(),
            name: &f.name,
            credential: f.credential,
            lookup: AccountLookup::Unknown,
            purpose: LoginPurpose::Login,
            ke1: &ke1,
        };
        login_start(
            &f.cx(),
            &f.store,
            &mut TestRng::new(seed.as_bytes()),
            &request,
        )
        .unwrap()
    };
    let (a, b) = (probe("one"), probe("two"));
    assert_eq!(a.ksf_profile, b.ksf_profile);
    assert_eq!(a.sk_hint, b.sk_hint);
    // The evaluated OPRF element is a function of the id and the blinded
    // element; the masking nonce is fresh.
    assert_eq!(&a.ke2[..32], &b.ke2[..32]);
    assert_ne!(&a.ke2[32..64], &b.ke2[32..64]);
    assert_ne!(a.login_id.to_hex(), b.login_id.to_hex());
}

#[test]
fn oprf_element_is_the_same_in_register_and_login() {
    let f = LoginFixture::new();
    let blind = vec![5u8; 64];
    let input = LoginFixture::input(FIXTURE_PASSWORD);
    // The same blind in registration and in login gives the same blinded
    // element.
    let (request, _) =
        ferret_core::opaque_register_start(&mut ReplayRng::new(vec![blind.clone()]), &input)
            .unwrap();
    let (ke1, _) = ferret_core::opaque_login_start(
        &mut ReplayRng::new(vec![blind, vec![1; 32], vec![2; 32]]),
        &input,
    )
    .unwrap();
    assert_eq!(request.as_slice(), &ke1[..32]);
    let registered = register_start(&f.keys, &f.credential, &request).unwrap();
    let response = f.start(f.active(), &ke1, LoginPurpose::Login).unwrap();
    assert_eq!(&registered[..32], &response.ke2[..32]);
    // The same holds for a made-up account under its made-up id.
    let fake = fake_credential_id(&f.prelogin, &f.name);
    let registered = register_start(&f.keys, &fake, &request).unwrap();
    let response = f
        .start(AccountLookup::Unknown, &ke1, LoginPurpose::Login)
        .unwrap();
    assert_eq!(&registered[..32], &response.ke2[..32]);
}

#[test]
fn login_start_draws_only_the_documented_values() {
    let f = LoginFixture::new();
    let (ke1, _) = f.client_start(FIXTURE_PASSWORD, "client");
    // ServerLogin::start: fake masking key, masking nonce, ephemeral seed,
    // server nonce. Then the login id and the nonce of the seal.
    for lookup in [f.active(), AccountLookup::Unknown, AccountLookup::Disabled] {
        let mut rng = ReplayRng::new(vec![
            vec![1; 64],
            vec![2; 32],
            vec![3; 32],
            vec![4; 32],
            vec![5; 16],
            vec![6; 24],
        ]);
        let request = LoginStartRequest {
            caller: LoginFixture::caller(),
            name: &f.name,
            credential: f.credential,
            lookup,
            purpose: LoginPurpose::Login,
            ke1: &ke1,
        };
        let store = ferret_server_auth::InMemoryLoginStateStore::new();
        let response = login_start(&f.cx(), &store, &mut rng, &request).unwrap();
        rng.finish().unwrap();
        assert_eq!(response.login_id.to_hex(), "05".repeat(16));
    }
}

// ------------------------------------------------------ malformed first message

#[test]
fn login_start_rejects_every_ke1_length_except_96() {
    let f = LoginFixture::new();
    let (ke1, _) = f.client_start(FIXTURE_PASSWORD, "client");
    assert_eq!(ke1.len(), KE1_LEN);
    let mut lengths: Vec<usize> = (0..=200).collect();
    lengths.push(1024 * 1024);
    for lookup in [f.active(), AccountLookup::Unknown, AccountLookup::Disabled] {
        for &len in &lengths {
            if len == KE1_LEN {
                continue;
            }
            let mut input = ke1.clone();
            input.resize(len, 0);
            let request = LoginStartRequest {
                caller: LoginFixture::caller(),
                name: &f.name,
                credential: f.credential,
                lookup,
                purpose: LoginPurpose::Login,
                ke1: &input,
            };
            // An empty replay panics on the first draw: nothing is drawn.
            let result = login_start(&f.cx(), &f.store, &mut ReplayRng::new(vec![]), &request);
            assert_eq!(
                result.unwrap_err(),
                AuthError::Malformed(Malformed::Ke1),
                "length {len}"
            );
        }
    }
    assert!(f.store.is_empty());
}

#[test]
fn login_start_rejects_bad_point_as_malformed() {
    let f = LoginFixture::new();
    let (ke1, _) = f.client_start(FIXTURE_PASSWORD, "client");
    for lookup in [f.active(), AccountLookup::Unknown] {
        for point in invalid_points() {
            // The blinded element and the ephemeral public key.
            for at in [0usize, 64] {
                let mut input = ke1.clone();
                input[at..at + 32].copy_from_slice(&point);
                let request = LoginStartRequest {
                    caller: LoginFixture::caller(),
                    name: &f.name,
                    credential: f.credential,
                    lookup,
                    purpose: LoginPurpose::Login,
                    ke1: &input,
                };
                let result = login_start(&f.cx(), &f.store, &mut ReplayRng::new(vec![]), &request);
                assert_eq!(result.unwrap_err(), AuthError::Malformed(Malformed::Ke1));
            }
        }
    }
    assert!(f.store.is_empty());
}

#[test]
fn a_malformed_start_is_recorded_as_a_failure() {
    let f = LoginFixture::new();
    let error = f
        .start(f.active(), &[0u8; 95], LoginPurpose::Login)
        .unwrap_err();
    assert_eq!(error.http_class(), ErrorClass::BadRequest);
    let calls = f.throttle.calls();
    assert_eq!(calls.len(), 2);
    let (stage, _, outcome) = last_record(&f);
    assert_eq!((stage, outcome), (Stage::LoginStart, Outcome::Failure));
}

// ---------------------------------------------------------------- the clock

#[test]
fn a_failed_clock_refuses_to_start_a_login() {
    let f = LoginFixture::new();
    let (ke1, _) = f.client_start(FIXTURE_PASSWORD, "client");
    f.clock.set(u64::MAX);
    for lookup in [f.active(), AccountLookup::Unknown] {
        let error = f.start(lookup, &ke1, LoginPurpose::Login).unwrap_err();
        assert_eq!(
            error,
            AuthError::Internal(ferret_server_auth::InternalKind::Clock)
        );
    }
    assert!(f.store.is_empty());
    // The limiter was not asked: nothing was done for the request.
    assert!(f.throttle.calls().is_empty());
}

// -------------------------------------------------------------- the throttle

#[test]
fn throttled_start_does_no_work() {
    let f = LoginFixture::new();
    let (ke1, _) = f.client_start(FIXTURE_PASSWORD, "client");
    f.throttle.refuse_with(Some(RetryAfter::new(7)));
    for lookup in [f.active(), AccountLookup::Unknown, AccountLookup::Disabled] {
        let request = LoginStartRequest {
            caller: LoginFixture::caller(),
            name: &f.name,
            credential: f.credential,
            lookup,
            purpose: LoginPurpose::Login,
            ke1: &ke1,
        };
        // No draw (an empty replay panics on one), no state, no parsing: a
        // KE1 that is garbage gets the same answer.
        let error =
            login_start(&f.cx(), &f.store, &mut ReplayRng::new(vec![]), &request).unwrap_err();
        assert_eq!(
            error,
            AuthError::Throttled {
                retry_after_secs: 7
            }
        );
        let garbage = LoginStartRequest {
            ke1: &[1, 2, 3],
            ..request
        };
        let error =
            login_start(&f.cx(), &f.store, &mut ReplayRng::new(vec![]), &garbage).unwrap_err();
        assert_eq!(
            error,
            AuthError::Throttled {
                retry_after_secs: 7
            }
        );
    }
    assert!(f.store.is_empty());
    // Only admits, and nothing was recorded for a refused request.
    assert!(
        f.throttle
            .calls()
            .iter()
            .all(|call| matches!(call, ThrottleCall::Admit { .. }))
    );
}

#[test]
fn unknown_account_is_throttled_with_the_same_keys() {
    let f = LoginFixture::new();
    let (ke1, _) = f.client_start(FIXTURE_PASSWORD, "client");
    f.throttle.refuse_with(Some(RetryAfter::new(7)));
    let fake = fake_credential_id(&f.prelogin, &f.name);
    let shapes = [
        (f.active(), f.credential),
        (AccountLookup::Unknown, fake),
        (AccountLookup::Disabled, fake),
    ];
    for (lookup, id) in shapes {
        f.throttle.clear();
        let error = f.start(lookup, &ke1, LoginPurpose::Login).unwrap_err();
        assert_eq!(
            error,
            AuthError::Throttled {
                retry_after_secs: 7
            }
        );
        let calls = f.throttle.calls();
        assert_eq!(
            calls,
            vec![ThrottleCall::Admit {
                stage: Stage::LoginStart,
                keys: vec![ThrottleKey::Ip(ip()), ThrottleKey::AccountIp(id, ip())],
                now: NOW,
            }]
        );
    }
}

#[test]
fn finish_records_the_outcome_in_the_throttle() {
    let f = LoginFixture::new();
    // Success.
    let (login_id, ke3) = right_ke3(&f);
    f.throttle.clear();
    f.finish(&login_id, &ke3, None).unwrap();
    let (stage, keys, outcome) = last_record(&f);
    assert_eq!((stage, outcome), (Stage::LoginFinish, Outcome::Success));
    assert_eq!(
        keys,
        vec![
            ThrottleKey::AccountIp(f.credential, ip()),
            ThrottleKey::Account(f.credential)
        ]
    );
    // A wrong KE3: the account is known from the state.
    let (response, _) = started(&f, FIXTURE_PASSWORD, "client");
    f.throttle.clear();
    assert_eq!(
        f.finish(&response.login_id, &[7u8; KE3_LEN], None)
            .unwrap_err(),
        denied(DenyReason::Ke3)
    );
    let (stage, keys, outcome) = last_record(&f);
    assert_eq!((stage, outcome), (Stage::LoginFinish, Outcome::Failure));
    assert_eq!(keys.len(), 2);
    // A missing state: the address alone.
    f.throttle.clear();
    assert_eq!(
        f.finish(&response.login_id, &[7u8; KE3_LEN], None)
            .unwrap_err(),
        denied(DenyReason::StateMissing)
    );
    let (stage, keys, outcome) = last_record(&f);
    assert_eq!((stage, outcome), (Stage::LoginFinish, Outcome::Failure));
    assert_eq!(keys, vec![ThrottleKey::Ip(ip())]);
    // A structure error: also the address alone.
    f.throttle.clear();
    let error = f.finish(&response.login_id, &[7u8; 63], None).unwrap_err();
    assert_eq!(error, AuthError::Malformed(Malformed::Ke3));
    let (stage, keys, outcome) = last_record(&f);
    assert_eq!((stage, outcome), (Stage::LoginFinish, Outcome::Failure));
    assert_eq!(keys, vec![ThrottleKey::Ip(ip())]);
}

#[test]
fn a_throttled_finish_does_no_opaque_work_and_uses_up_the_state() {
    let f = LoginFixture::new();
    let (login_id, ke3) = right_ke3(&f);
    f.throttle.clear();
    f.throttle.refuse_with(Some(RetryAfter::new(30)));
    let error = f.finish(&login_id, &ke3, None).unwrap_err();
    assert_eq!(
        error,
        AuthError::Throttled {
            retry_after_secs: 30
        }
    );
    assert!(f.store.is_empty());
    // The limiter was asked with the account of the state, and told nothing.
    let calls = f.throttle.calls();
    let Some(ThrottleCall::Admit { stage, keys, .. }) = calls.last() else {
        panic!("no admit")
    };
    assert_eq!(*stage, Stage::LoginFinish);
    assert_eq!(keys[1], ThrottleKey::Account(f.credential));
    assert!(
        calls
            .iter()
            .all(|call| matches!(call, ThrottleCall::Admit { .. }))
    );
    // Once the caller is let in again, the right KE3 no longer helps.
    f.throttle.refuse_with(None);
    assert_eq!(
        f.finish(&login_id, &ke3, None).unwrap_err(),
        denied(DenyReason::StateMissing)
    );
}

// ------------------------------------------------------------ wrong answers

#[test]
fn a_wrong_password_never_gets_to_the_server() {
    // The client cannot open the envelope with another password, so it has
    // no KE3 to send; for a made-up record it fails the same way.
    let f = LoginFixture::new();
    let (ke1, state) = f.client_start(WRONG, "client");
    let response = f.start(f.active(), &ke1, LoginPurpose::Login).unwrap();
    let wrong = f
        .client_finish(state, WRONG, &response.ke2, OPAQUE_CONTEXT)
        .unwrap_err();
    let (ke1, state) = f.client_start(FIXTURE_PASSWORD, "client");
    let response = f
        .start(AccountLookup::Unknown, &ke1, LoginPurpose::Login)
        .unwrap();
    let unknown = f
        .client_finish(state, FIXTURE_PASSWORD, &response.ke2, OPAQUE_CONTEXT)
        .unwrap_err();
    assert!(matches!(wrong, ClientError::Decrypt));
    assert!(matches!(unknown, ClientError::Decrypt));
}

#[test]
fn wrong_ke3_is_denied_and_uses_up_the_state() {
    let f = LoginFixture::new();
    let (response, state) = started(&f, FIXTURE_PASSWORD, "client");
    let ke3 = f
        .client_finish(state, FIXTURE_PASSWORD, &response.ke2, OPAQUE_CONTEXT)
        .unwrap();
    let mut forged = ke3.clone();
    forged[0] ^= 1;
    assert_eq!(
        f.finish(&response.login_id, &forged, None).unwrap_err(),
        denied(DenyReason::Ke3)
    );
    // The state is gone: the right KE3 now fails too.
    assert_eq!(
        f.finish(&response.login_id, &ke3, None).unwrap_err(),
        denied(DenyReason::StateMissing)
    );
}

#[test]
fn a_guess_at_ke3_for_a_made_up_account_is_denied_the_same_way() {
    let f = LoginFixture::new();
    let (ke1, _) = f.client_start(FIXTURE_PASSWORD, "client");
    let response = f
        .start(AccountLookup::Unknown, &ke1, LoginPurpose::Login)
        .unwrap();
    assert_eq!(
        f.finish(&response.login_id, &[3u8; KE3_LEN], None)
            .unwrap_err(),
        denied(DenyReason::Ke3)
    );
    assert_eq!(
        f.finish(&response.login_id, &[3u8; KE3_LEN], None)
            .unwrap_err(),
        denied(DenyReason::StateMissing)
    );
}

#[test]
fn second_finish_with_the_right_ke3_is_denied() {
    let f = LoginFixture::new();
    let (login_id, ke3) = right_ke3(&f);
    f.finish(&login_id, &ke3, None).unwrap();
    assert_eq!(
        f.finish(&login_id, &ke3, None).unwrap_err(),
        denied(DenyReason::StateMissing)
    );
}

#[test]
fn finish_without_start_and_with_other_login_id_are_denied() {
    let f = LoginFixture::new();
    let (login_id, ke3) = right_ke3(&f);
    let never = LoginId::parse(b"00000000000000000000000000000000").unwrap();
    assert_eq!(
        f.finish(&never, &ke3, None).unwrap_err(),
        denied(DenyReason::StateMissing)
    );
    // The real login is untouched by the miss.
    f.finish(&login_id, &ke3, None).unwrap();
    // A state under another id, even when it is moved there, does not open.
    let (first, ke3) = right_ke3(&f);
    let (second, _) = started(&f, FIXTURE_PASSWORD, "another client");
    let second = second.login_id;
    let moved = take_state(&f.store, &first, NOW);
    let _own = take_state(&f.store, &second, NOW);
    put_state(&f.store, &second, moved, NOW);
    assert_eq!(
        f.finish(&second, &ke3, None).unwrap_err(),
        denied(DenyReason::StateInvalid)
    );
}

#[test]
fn a_changed_state_is_denied() {
    let f = LoginFixture::new();
    let (login_id, ke3) = right_ke3(&f);
    let mut bytes = take_state(&f.store, &login_id, NOW).into_bytes();
    let last = bytes.len() - 1;
    bytes[last] ^= 1;
    let changed = ferret_server_auth::SealedState::from_bytes(bytes);
    put_state(&f.store, &login_id, changed, NOW);
    assert_eq!(
        f.finish(&login_id, &ke3, None).unwrap_err(),
        denied(DenyReason::StateInvalid)
    );
}

#[test]
fn expired_state_is_denied() {
    let f = LoginFixture::new();
    // Valid in the seconds 0 to 59 after the start.
    let (login_id, ke3) = right_ke3(&f);
    f.clock.set(NOW + 59);
    f.finish(&login_id, &ke3, None).unwrap();
    // Gone from second 60.
    f.clock.set(NOW);
    let (login_id, ke3) = right_ke3(&f);
    f.clock.set(NOW + 60);
    assert!(matches!(
        f.finish(&login_id, &ke3, None).unwrap_err(),
        AuthError::Denied(DenyReason::StateMissing | DenyReason::StateExpired)
    ));
    assert!(f.store.is_empty());
    assert_eq!(f.store.len(), 0);
}

#[test]
fn concurrent_finish_has_exactly_one_winner() {
    let f = LoginFixture::new();
    for round in 0..5 {
        let (response, state) = started(&f, FIXTURE_PASSWORD, &format!("client {round}"));
        let ke3 = f
            .client_finish(state, FIXTURE_PASSWORD, &response.ke2, OPAQUE_CONTEXT)
            .unwrap();
        let wins = AtomicUsize::new(0);
        let barrier = Barrier::new(16);
        std::thread::scope(|scope| {
            for _ in 0..16 {
                scope.spawn(|| {
                    barrier.wait();
                    if f.finish(&response.login_id, &ke3, None).is_ok() {
                        wins.fetch_add(1, Ordering::SeqCst);
                    }
                });
            }
        });
        assert_eq!(wins.load(Ordering::SeqCst), 1, "round {round}");
    }
}

// -------------------------------------------------------- malformed finish

#[test]
fn malformed_ke3_does_not_consume_the_state() {
    let f = LoginFixture::new();
    let (login_id, ke3) = right_ke3(&f);
    let mut lengths: Vec<usize> = (0..=130).collect();
    lengths.push(1024 * 1024);
    for len in lengths {
        if len == KE3_LEN {
            continue;
        }
        let mut input = ke3.clone();
        input.resize(len, 0);
        assert_eq!(
            f.finish(&login_id, &input, None).unwrap_err(),
            AuthError::Malformed(Malformed::Ke3),
            "length {len}"
        );
    }
    assert_eq!(f.store.len(), 1);
    f.finish(&login_id, &ke3, None).unwrap();
}

#[test]
fn a_malformed_login_id_does_not_touch_the_store() {
    let f = LoginFixture::new();
    let (login_id, ke3) = right_ke3(&f);
    let hex = login_id.to_hex();
    let upper = hex.to_uppercase();
    for bad in [
        String::new(),
        hex[..31].to_string(),
        format!("{hex}0"),
        upper,
        "zz".repeat(16),
    ] {
        let request = LoginFinishRequest {
            caller: LoginFixture::caller(),
            login_id: bad.as_bytes(),
            ke3: &ke3,
            current_session: None,
        };
        let error = ferret_server_auth::login_finish(&f.cx(), &f.store, &request).unwrap_err();
        assert_eq!(error, AuthError::Malformed(Malformed::LoginId), "{bad:?}");
    }
    assert_eq!(f.store.len(), 1);
    f.finish(&login_id, &ke3, None).unwrap();
}

// ------------------------------------------------------- purpose and session

#[test]
fn reauth_state_is_bound_to_the_session() {
    let f = LoginFixture::new();
    let (a, b) = (session(1), session(2));
    // `Reauth{a}` succeeds only for `a`; each failure uses the state up, so
    // every try starts again.
    let account = f.credential;
    for (given, ok) in [
        (Some((a, account)), true),
        (Some((b, account)), false),
        (None, false),
    ] {
        let (ke1, state) = f.client_start(FIXTURE_PASSWORD, "client");
        let response = f.start(f.active(), &ke1, f.reauth(a)).unwrap();
        let ke3 = f
            .client_finish(state, FIXTURE_PASSWORD, &response.ke2, OPAQUE_CONTEXT)
            .unwrap();
        let result = f.finish(&response.login_id, &ke3, given);
        if ok {
            assert!(result.is_ok());
        } else {
            assert_eq!(result.unwrap_err(), denied(DenyReason::StateInvalid));
        }
        assert!(f.store.is_empty());
    }
    // A login is not a re-authentication, whichever session is given.
    for given in [Some((a, account)), Some((b, account))] {
        let (response, state) = started(&f, FIXTURE_PASSWORD, "client");
        let ke3 = f
            .client_finish(state, FIXTURE_PASSWORD, &response.ke2, OPAQUE_CONTEXT)
            .unwrap();
        assert_eq!(
            f.finish(&response.login_id, &ke3, given).unwrap_err(),
            denied(DenyReason::StateInvalid)
        );
    }
}

#[test]
fn finish_denials_have_one_public_code() {
    let f = LoginFixture::new();
    let mut errors = Vec::new();
    // Missing, used, wrong KE3, wrong purpose, wrong session, wrong account.
    let never = LoginId::parse(b"11111111111111111111111111111111").unwrap();
    errors.push(f.finish(&never, &[0; KE3_LEN], None).unwrap_err());
    let (response, _) = started(&f, FIXTURE_PASSWORD, "client");
    errors.push(
        f.finish(&response.login_id, &[0; KE3_LEN], None)
            .unwrap_err(),
    );
    errors.push(
        f.finish(&response.login_id, &[0; KE3_LEN], None)
            .unwrap_err(),
    );
    let (response, _) = started(&f, FIXTURE_PASSWORD, "client");
    errors.push(
        f.finish(
            &response.login_id,
            &[0; KE3_LEN],
            Some((session(1), f.credential)),
        )
        .unwrap_err(),
    );
    let (ke1, _) = f.client_start(FIXTURE_PASSWORD, "client");
    let response = f.start(f.active(), &ke1, f.reauth(session(1))).unwrap();
    errors.push(
        f.finish(
            &response.login_id,
            &[0; KE3_LEN],
            Some((session(2), f.credential)),
        )
        .unwrap_err(),
    );
    // Another account than the one of the session.
    let (ke1, _) = f.client_start(FIXTURE_PASSWORD, "client");
    let response = f.start(f.active(), &ke1, f.reauth(session(1))).unwrap();
    let other = ferret_server_auth::CredentialId::from_bytes([0x43; 16]);
    errors.push(
        f.finish(&response.login_id, &[0; KE3_LEN], Some((session(1), other)))
            .unwrap_err(),
    );
    let reasons: Vec<_> = errors
        .iter()
        .map(|e| match e {
            AuthError::Denied(reason) => *reason,
            other => panic!("not a denial: {other:?}"),
        })
        .collect();
    assert_eq!(reasons.len(), 6);
    for error in &errors {
        assert_eq!(error.public_code(), "denied");
        assert_eq!(error.http_class(), ErrorClass::Denied);
    }
}

// ---------------------------------------------------- context and start-up

#[test]
fn server_with_another_context_cannot_authenticate() {
    let f = LoginFixture::new();
    let (ke1, state) = f.client_start(FIXTURE_PASSWORD, "client");
    let request = LoginStartRequest {
        caller: LoginFixture::caller(),
        name: &f.name,
        credential: f.credential,
        lookup: f.active(),
        purpose: LoginPurpose::Login,
        ke1: &ke1,
    };
    let response = login_start_with_context(
        &f.cx(),
        &f.store,
        &mut TestRng::new(b"server"),
        &request,
        b"ferret/v1/other",
        None,
    )
    .unwrap();
    let error = f
        .client_finish(state, FIXTURE_PASSWORD, &response.ke2, OPAQUE_CONTEXT)
        .unwrap_err();
    assert!(matches!(error, ClientError::Decrypt));

    // Other identities do the same.
    let (ke1, state) = f.client_start(FIXTURE_PASSWORD, "client");
    let request = LoginStartRequest {
        ke1: &ke1,
        ..request
    };
    let response = login_start_with_context(
        &f.cx(),
        &f.store,
        &mut TestRng::new(b"server 2"),
        &request,
        OPAQUE_CONTEXT,
        Some((b"alice", b"server")),
    )
    .unwrap();
    let error = f
        .client_finish(state, FIXTURE_PASSWORD, &response.ke2, OPAQUE_CONTEXT)
        .unwrap_err();
    assert!(matches!(error, ClientError::Decrypt));
}

#[test]
fn a_policy_with_an_unknown_profile_cannot_be_built() {
    // The server builds its policy when it starts, so a bad one stops the
    // start and not the first request.
    let bad = AuthError::Internal(ferret_server_auth::InternalKind::Policy);
    assert_eq!(PreloginPolicy::new(&[(200, 1000)], 500).unwrap_err(), bad);
    assert_eq!(
        PreloginPolicy::new(&[(1, 500), (2, 500)], 500).unwrap_err(),
        bad
    );
    assert!(PreloginPolicy::new(&[(1, 1000)], 500).is_ok());
    // Tests may build a longer table.
    assert!(PreloginPolicy::for_tests(&[(200, 1000)], 500).is_ok());
}

#[test]
fn nothing_secret_shows_in_debug() {
    let f = LoginFixture::new();
    let (response, _) = started(&f, FIXTURE_PASSWORD, "client");
    assert_eq!(format!("{response:?}"), "LoginStartResponse([redacted])");
    assert_eq!(format!("{:?}", f.active()), "AccountLookup([redacted])");
    assert_eq!(format!("{:?}", f.cx()), "AuthContext { .. }");
    let (login_id, ke3) = right_ke3(&f);
    let verified = f.finish(&login_id, &ke3, None).unwrap();
    assert_eq!(format!("{verified:?}"), "LoginVerified([redacted])");
}

// ------------------------------------------------------- the account of a session

/// The attack of a caller who holds a session of account A (a stolen cookie),
/// does not know the password of A, and knows the password of an account M of
/// their own: they start a re-authentication for the session of A, but log in
/// as M.
#[test]
fn a_reauthentication_for_another_account_is_denied_in_the_session_of_a() {
    const MALLORY: &str = "mallory's own password";
    let f = LoginFixture::new();
    let account_a = f.credential;
    let account_m = ferret_server_auth::CredentialId::from_bytes([0x4d; 16]);
    let record_m = f.register(&account_m, MALLORY);
    let stolen = session(9);

    let attempt =
        |as_account: ferret_server_auth::CredentialId,
         record: &ferret_server_auth::StoredRecord,
         password: &str,
         finish_for: (SessionBinding, ferret_server_auth::CredentialId)| {
            let (ke1, state) = f.client_start(password, "mallory");
            let request = LoginStartRequest {
                caller: LoginFixture::caller(),
                name: &f.name,
                credential: as_account,
                lookup: AccountLookup::Active {
                    record,
                    sk_hint: false,
                },
                // The endpoint sets the account of the session it has found: A.
                purpose: LoginPurpose::Reauth {
                    session: stolen,
                    account: account_a,
                },
                ke1: &ke1,
            };
            let response = login_start(
                &f.cx(),
                &f.store,
                &mut TestRng::new(password.as_bytes()),
                &request,
            )
            .unwrap();
            let ke3 = f
                .client_finish(state, password, &response.ke2, OPAQUE_CONTEXT)
                .unwrap();
            f.finish(&response.login_id, &ke3, Some(finish_for))
        };

    // Control: the owner of A re-authenticates with the password of A.
    let owner = attempt(account_a, &f.record, FIXTURE_PASSWORD, (stolen, account_a)).unwrap();
    assert_eq!(owner.credential, account_a);

    // The attacker logs in as M, in the session of A: refused, however the
    // finish is asked.
    for finish_for in [(stolen, account_a), (stolen, account_m)] {
        let error = attempt(account_m, &record_m, MALLORY, finish_for).unwrap_err();
        assert_eq!(error, denied(DenyReason::StateInvalid));
        assert_eq!(error.public_code(), "denied");
    }
    // The same holds for a made-up account: a name that does not exist.
    let (ke1, _) = f.client_start(MALLORY, "mallory");
    let request = LoginStartRequest {
        caller: LoginFixture::caller(),
        name: &f.name,
        credential: account_m,
        lookup: AccountLookup::Unknown,
        purpose: LoginPurpose::Reauth {
            session: stolen,
            account: account_a,
        },
        ke1: &ke1,
    };
    let response = login_start(&f.cx(), &f.store, &mut TestRng::new(b"unknown"), &request).unwrap();
    let error = f
        .finish(&response.login_id, &[1; KE3_LEN], Some((stolen, account_a)))
        .unwrap_err();
    assert_eq!(error, denied(DenyReason::StateInvalid));
    // The throttle was told the address alone failed, not the account of M.
    let (stage, keys, outcome) = last_record(&f);
    assert_eq!((stage, outcome), (Stage::LoginFinish, Outcome::Failure));
    assert_eq!(keys, vec![ThrottleKey::Ip(ip())]);
}

// ---------------------------------------------------- expiry in the sealed state

/// A store that does not look at the expiry when it hands a state back, as a
/// broken store might. The check on the sealed state itself must still hold.
struct ForgetfulStore(ferret_server_auth::InMemoryLoginStateStore);

impl ferret_server_auth::LoginStateStore for ForgetfulStore {
    fn put(
        &self,
        key: ferret_server_auth::StateKey,
        sealed: ferret_server_auth::SealedState,
        expires_at: u64,
        now: u64,
    ) -> Result<(), ferret_server_auth::StoreError> {
        self.0.put(key, sealed, expires_at, now)
    }

    fn take(
        &self,
        key: &ferret_server_auth::StateKey,
        _now: u64,
    ) -> Result<Option<ferret_server_auth::SealedState>, ferret_server_auth::StoreError> {
        self.0.take(key, 0)
    }

    fn purge_expired(&self, now: u64) -> Result<usize, ferret_server_auth::StoreError> {
        self.0.purge_expired(now)
    }
}

#[test]
fn an_expired_state_is_refused_even_when_the_store_hands_it_back() {
    use ferret_server_auth::LoginStateStore as _;
    let f = LoginFixture::new();
    let store = ForgetfulStore(ferret_server_auth::InMemoryLoginStateStore::new());
    let (ke1, state) = f.client_start(FIXTURE_PASSWORD, "client");
    let request = LoginStartRequest {
        caller: LoginFixture::caller(),
        name: &f.name,
        credential: f.credential,
        lookup: f.active(),
        purpose: LoginPurpose::Login,
        ke1: &ke1,
    };
    let response = login_start(&f.cx(), &store, &mut TestRng::new(b"forgetful"), &request).unwrap();
    let ke3 = f
        .client_finish(state, FIXTURE_PASSWORD, &response.ke2, OPAQUE_CONTEXT)
        .unwrap();
    let hex = response.login_id.to_hex();
    let finish = LoginFinishRequest {
        caller: LoginFixture::caller(),
        login_id: hex.as_bytes(),
        ke3: &ke3,
        current_session: None,
    };
    f.clock.set(NOW + 60);
    let error = ferret_server_auth::login_finish(&f.cx(), &store, &finish).unwrap_err();
    assert_eq!(error, denied(DenyReason::StateExpired));
    let _ = store.purge_expired(NOW);
}
