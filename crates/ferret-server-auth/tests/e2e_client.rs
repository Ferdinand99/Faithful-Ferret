//! The whole server library against the real client of `ferret-core`.
//!
//! Every flow goes through the public API only, the way an endpoint calls it:
//! the context with its throttle and clock, the login state store, the
//! challenge store, the signed proofs, and a test store for the conditional
//! writes. Where a flow could not be wired from the public API alone, that
//! is a finding for the report and not something to work around here.
//!
//! The quick scenarios use the test stretching function with small
//! parameters. `full_profile_one_registration_and_login` uses Argon2id with
//! the real parameters of profile 1 (64 MiB) from end to end.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]

mod support;

use ferret_core::testing::keys::export_key_bytes;
use ferret_core::{
    AuthOp, Error, KsfProfile, ManifestRow, NewPassword, OsRng, PinState, PinnedField, SecureRng,
    TestRng, auth_sign, change_password,
};
use ferret_server_auth::testing::WriteRefused;
use ferret_server_auth::{
    AuthError, Capability, CredentialId, DenyReason, ErrorClass, InternalKind, LoginPurpose,
    Outcome, ProfileRules, RegistrationKind, RetryAfter, ScopeEffect, SessionBinding, SessionScope,
    SignedRequest, Stage, authorize, authorize_signed, fake_prelogin, normalize_login_name,
    register_finish,
};
use support::{
    Ksf, LoginFailure, PASSWORD, PASSWORD_2, PROFILE_2_PARAMS, Server, Target, URL, caller,
    new_input, session, stored,
};

fn denied(reason: DenyReason) -> AuthError {
    AuthError::Denied(reason)
}

fn alice(server: &Server) -> support::Account {
    server.create_account(0x11, "alice@example.com", PASSWORD, Ksf::Small)
}

fn forged_ke3() -> [u8; 64] {
    let mut ke3 = [0u8; 64];
    TestRng::new(b"forged ke3").fill(&mut ke3);
    ke3
}

// ----------------------------------------------------- registration, login

#[test]
fn registration_login_roundtrip() {
    let s = Server::new();
    let a = alice(&s);

    // The record the server stores is the record the client uploaded.
    let row = a.row.read();
    assert_eq!(row.record.ksf_profile, 1);
    assert_eq!(
        row.record.record.as_bytes(),
        a.new.registration_record.as_slice()
    );

    s.throttle.clear();
    let done = s
        .login(
            &Target::Active(&a),
            PASSWORD,
            Ksf::Small,
            LoginPurpose::Login,
            None,
        )
        .unwrap();
    // The export key of the login is the one the registration gave.
    assert_eq!(done.export, a.registration_export);
    assert!(done.verified.credential == a.credential);
    assert!(matches!(done.verified.purpose, LoginPurpose::Login));
    // The server key the login shows is the one the account pinned.
    assert_eq!(done.server_key, a.new.server_public_key);
    // Each stage was admitted before it did any work and reported once.
    assert_eq!(
        s.stages(),
        [
            (Stage::LoginStart, None),
            (Stage::LoginStart, Some(Outcome::Success)),
            (Stage::LoginFinish, None),
            (Stage::LoginFinish, Some(Outcome::Success)),
        ]
    );
    // The state is used up.
    assert!(s.logins.is_empty());
}

#[test]
fn full_profile_one_registration_and_login() {
    // Argon2id with 64 MiB, twice: the registration and the login. The
    // server side draws from the operating system, as a real server does.
    let s = Server::new();
    let a = s.create_account(0x21, "bob@example.com", PASSWORD, Ksf::Production);
    assert_eq!(a.row.read().record.ksf_profile, 1);

    let started = s
        .begin_with(
            &Target::Active(&a),
            PASSWORD,
            LoginPurpose::Login,
            (&mut OsRng, &mut OsRng),
        )
        .unwrap();
    assert_eq!(started.response.ksf_profile, 1);
    let (login_id, answer) = started.client_answer(Ksf::Production);
    let answer = answer.unwrap();
    assert_eq!(export_key_bytes(&answer.export_key), a.registration_export);
    let verified = s.finish(&login_id, &answer.ke3, None).unwrap();
    assert!(verified.credential == a.credential);
}

#[test]
fn wrong_password_fails_at_the_client_and_a_forged_ke3_is_denied() {
    let s = Server::new();
    let a = alice(&s);

    let started = s
        .begin(&Target::Active(&a), "not the password", LoginPurpose::Login)
        .unwrap();
    let (login_id, answer) = started.client_answer(Ksf::Small);
    // The client cannot open the envelope, so it never has a KE3 to send.
    assert_eq!(answer.err(), Some(Error::Decrypt));

    // Somebody who sends a made-up KE3 for that login is denied...
    s.throttle.clear();
    assert_eq!(
        s.finish(&login_id, &forged_ke3(), None).unwrap_err(),
        denied(DenyReason::Ke3)
    );
    assert_eq!(
        s.stages().last(),
        Some(&(Stage::LoginFinish, Some(Outcome::Failure)))
    );
    // ...and the state is used up: not even the next guess finds it.
    assert!(s.logins.is_empty());
    assert_eq!(
        s.finish(&login_id, &forged_ke3(), None).unwrap_err(),
        denied(DenyReason::StateMissing)
    );
}

#[test]
fn unknown_user_looks_like_a_known_one() {
    let s = Server::new();
    let a = alice(&s);
    let nobody = Target::Unknown("nobody@example.com");

    s.throttle.clear();
    let first = s.begin(&nobody, PASSWORD, LoginPurpose::Login).unwrap();
    let unknown_shape = s.shape();
    s.throttle.clear();
    let known = s
        .begin(&Target::Active(&a), "not the password", LoginPurpose::Login)
        .unwrap();
    // The throttle sees the same calls for a name with an account and one
    // without.
    assert_eq!(s.shape(), unknown_shape);

    let second = s.begin(&nobody, PASSWORD, LoginPurpose::Login).unwrap();
    let disabled = s
        .begin(&Target::Disabled(&a), PASSWORD, LoginPurpose::Login)
        .unwrap();

    // The same length and field layout as a real answer.
    for response in [
        &first.response,
        &second.response,
        &known.response,
        &disabled.response,
    ] {
        assert_eq!(response.ke2.len(), 320);
        assert_eq!(response.ksf_profile, 1);
    }
    // The profile and the hint do not change between two attempts, and they
    // are what the pre-login function says for the name.
    let name = normalize_login_name("nobody@example.com").unwrap();
    let expected = fake_prelogin(&s.prelogin, &name, &s.policy);
    for response in [&first.response, &second.response] {
        assert_eq!(response.ksf_profile, expected.ksf_profile);
        assert_eq!(response.sk_hint, expected.sk_hint);
    }
    assert_eq!(first.response.sk_hint, second.response.sk_hint);

    // The client cannot tell it from a known account with a wrong password:
    // it fails with `Decrypt`, whatever the password.
    for started in [first, second, known, disabled] {
        let (_, answer) = started.client_answer(Ksf::Small);
        assert_eq!(answer.err(), Some(Error::Decrypt));
    }
    // Nothing is left behind that would tell them apart.
    assert_eq!(s.logins.len(), 4);
}

// -------------------------------------------------------- password change

#[test]
fn change_password_with_a_proof_replaces_the_record() {
    let s = Server::new();
    let a = alice(&s);
    let before = stored(&a);

    let change = s.password_change(&a, PASSWORD_2, "new password");
    s.throttle.clear();
    let req = s.put_req(&a, &change, 1, session(0xA1));
    let permit = s.replace(&a, &req).unwrap();
    assert_eq!(permit.new.record.as_bytes(), change.registration_record);
    assert_eq!(permit.new.ksf_profile, 1);
    assert_eq!(permit.session_effect, ScopeEffect::Keep);
    // The nonce and the replacement were both admitted and reported.
    assert_eq!(
        s.stages(),
        [
            (Stage::Challenge, None),
            (Stage::Challenge, Some(Outcome::Success)),
            (Stage::Replace, None),
            (Stage::Replace, Some(Outcome::Success)),
        ]
    );
    // Nothing changes until the endpoint writes the permit.
    assert_eq!(
        stored(&a).record.as_bytes(),
        before.record.as_bytes(),
        "the permit alone does not write"
    );
    a.row.apply_replacement(&permit).unwrap();
    assert_eq!(stored(&a).record.as_bytes(), change.registration_record);

    // The new password logs in, with an export key that is not the old one;
    // the old password gets the client's `Decrypt`.
    let done = s
        .login(
            &Target::Active(&a),
            PASSWORD_2,
            Ksf::Small,
            LoginPurpose::Login,
            None,
        )
        .unwrap();
    assert_ne!(done.export, a.registration_export);
    assert!(matches!(
        s.login(
            &Target::Active(&a),
            PASSWORD,
            Ksf::Small,
            LoginPurpose::Login,
            None
        ),
        Err(LoginFailure::Client(Error::Decrypt))
    ));
}

#[test]
fn change_password_without_or_with_a_bad_proof_changes_nothing() {
    let s = Server::new();
    let a = alice(&s);
    let before = stored(&a);
    let change = s.password_change(&a, PASSWORD_2, "new password");
    s.throttle.clear();

    // A proof of zeros, a flipped proof, and a proof over another body.
    let good = s.put_req(&a, &change, 1, session(0xA1));
    let mut zeros = good.clone();
    zeros.proof = [0; 64];
    let mut flipped = s.put_req(&a, &change, 1, session(0xA1));
    flipped.proof[10] ^= 1;
    let mut other_body = s.put_req(&a, &change, 1, session(0xA1));
    other_body.proof = change
        .sign(&a.new.vault, &other_body.nonce, b"another body")
        .unwrap();
    for req in [&zeros, &flipped, &other_body] {
        assert_eq!(
            s.replace(&a, req).unwrap_err(),
            denied(DenyReason::ProofInvalid)
        );
    }
    // A proof that is missing is not even well formed.
    let mut absent = s.put_req(&a, &change, 1, session(0xA1));
    let mut request = absent.as_request();
    request.proof = &[];
    assert_eq!(
        s.replace_raw(&a, &request).unwrap_err(),
        AuthError::Malformed(ferret_server_auth::Malformed::Proof)
    );
    absent.proof = [0; 64];

    // Every refusal was reported as a failure and none as a success.
    assert!(
        s.stages()
            .iter()
            .filter(|(stage, _)| *stage == Stage::Replace)
            .all(|(_, outcome)| *outcome != Some(Outcome::Success))
    );
    // The stored record is untouched, and the old password still works.
    assert_eq!(stored(&a).record.as_bytes(), before.record.as_bytes());
    assert_eq!(a.row.read().account.row_version, 1);
    let done = s
        .login(
            &Target::Active(&a),
            PASSWORD,
            Ksf::Small,
            LoginPurpose::Login,
            None,
        )
        .unwrap();
    assert_eq!(done.export, a.registration_export);
}

#[test]
fn recover_with_a_proof_replaces_the_record() {
    let s = Server::new();
    let a = alice(&s);
    let rec = s.recovered(&a, PASSWORD_2, Ksf::Small, "recovery");

    let req = s.recover_req(&a, &rec, 1, session(0xB2));
    let permit = s.replace(&a, &req).unwrap();
    assert_eq!(permit.kind, ferret_server_auth::ReplaceKind::Recover);
    // A recovery in a reset session ends that session, and brings the new
    // recovery key with it.
    assert_eq!(permit.session_effect, ScopeEffect::EndSession);
    assert_eq!(permit.new_pk_r.map(|k| *k.as_bytes()), Some(rec.pk_r));
    a.row.apply_replacement(&permit).unwrap();
    assert_eq!(a.row.read().account.pk_r.as_bytes(), &rec.pk_r);

    assert!(
        s.login(
            &Target::Active(&a),
            PASSWORD_2,
            Ksf::Small,
            LoginPurpose::Login,
            None
        )
        .is_ok()
    );
    assert!(matches!(
        s.login(
            &Target::Active(&a),
            PASSWORD,
            Ksf::Small,
            LoginPurpose::Login,
            None
        ),
        Err(LoginFailure::Client(Error::Decrypt))
    ));
    // The recovery cannot be run twice: the nonce is used up.
    assert_eq!(
        s.replace(&a, &req).unwrap_err(),
        denied(DenyReason::NonceUnknown)
    );
}

#[test]
fn ksf_upgrade_and_downgrade() {
    let s = Server::with_two_profiles();
    let a = alice(&s);

    // The same password again, claiming profile 2: an upgrade.
    let change = s.password_change(&a, PASSWORD, "upgrade");
    let req = s.put_req(&a, &change, 2, session(0xA1));
    let permit = s.replace(&a, &req).unwrap();
    assert_eq!(permit.stored_ksf_profile, 1);
    assert_eq!(permit.new.ksf_profile, 2);
    a.row.apply_replacement(&permit).unwrap();
    assert_eq!(stored(&a).ksf_profile, 2);
    // Login now tells the client to use profile 2.
    let started = s
        .begin(&Target::Active(&a), PASSWORD, LoginPurpose::Login)
        .unwrap();
    assert_eq!(started.response.ksf_profile, 2);

    // A downgrade is refused even though the proof is valid.
    let back = s.password_change(&a, PASSWORD_2, "downgrade");
    let req = s.put_req(&a, &back, 1, session(0xA1));
    assert_eq!(s.replace(&a, &req).unwrap_err(), AuthError::ProfileRejected);
    assert_eq!(stored(&a).ksf_profile, 2);

    // A server that knows profile 1 only refuses the claim of profile 2.
    let single = Server::new();
    let b = alice(&single);
    let change = single.password_change(&b, PASSWORD, "upgrade");
    let req = single.put_req(&b, &change, 2, session(0xA1));
    assert_eq!(
        single.replace(&b, &req).unwrap_err(),
        AuthError::ProfileRejected
    );
}

// --------------------------------------------------------- state and time

#[test]
fn replay_of_finish_is_denied() {
    let s = Server::new();
    let a = alice(&s);
    let started = s
        .begin(&Target::Active(&a), PASSWORD, LoginPurpose::Login)
        .unwrap();
    let (login_id, answer) = started.client_answer(Ksf::Small);
    let ke3 = answer.unwrap().ke3;

    assert!(s.finish(&login_id, &ke3, None).is_ok());
    assert_eq!(
        s.finish(&login_id, &ke3, None).unwrap_err(),
        denied(DenyReason::StateMissing)
    );
}

#[test]
fn expired_state_is_denied() {
    let s = Server::new();
    let a = alice(&s);

    // One second short of a minute still works.
    let started = s
        .begin(&Target::Active(&a), PASSWORD, LoginPurpose::Login)
        .unwrap();
    let (login_id, answer) = started.client_answer(Ksf::Small);
    s.clock.advance(59);
    assert!(s.finish(&login_id, &answer.unwrap().ke3, None).is_ok());

    // A minute later the state is gone, and the correct KE3 does not help.
    let started = s
        .begin(&Target::Active(&a), PASSWORD, LoginPurpose::Login)
        .unwrap();
    let (login_id, answer) = started.client_answer(Ksf::Small);
    s.clock.advance(60);
    assert_eq!(
        s.finish(&login_id, &answer.unwrap().ke3, None).unwrap_err(),
        denied(DenyReason::StateMissing)
    );
}

#[test]
fn concurrent_finish_has_one_winner() {
    let s = Server::new();
    let a = alice(&s);
    for round in 0..8 {
        let started = s
            .begin(&Target::Active(&a), PASSWORD, LoginPurpose::Login)
            .unwrap();
        let (login_id, answer) = started.client_answer(Ksf::Small);
        let ke3 = answer.unwrap().ke3;

        let results: Vec<_> = std::thread::scope(|scope| {
            let handles: Vec<_> = (0..16)
                .map(|_| scope.spawn(|| s.finish(&login_id, &ke3, None)))
                .collect();
            handles.into_iter().map(|h| h.join().unwrap()).collect()
        });
        let winners = results.iter().filter(|r| r.is_ok()).count();
        assert_eq!(winners, 1, "round {round}");
        assert!(
            results
                .iter()
                .filter_map(|r| r.as_ref().err())
                .all(|e| *e == denied(DenyReason::StateMissing)),
            "round {round}"
        );
    }
}

// --------------------------------------------------------------- re-auth

#[test]
fn reauth_login_is_bound_to_its_session() {
    let s = Server::new();
    let a = alice(&s);
    let m = s.create_account(0x31, "mallory@example.com", PASSWORD_2, Ksf::Small);
    let mine = session(0xA1);
    let reauth = |who: &CredentialId, bound: SessionBinding| LoginPurpose::Reauth {
        session: bound,
        account: *who,
    };

    // The owner re-authenticates in their own session.
    let done = s
        .login(
            &Target::Active(&a),
            PASSWORD,
            Ksf::Small,
            reauth(&a.credential, mine),
            Some((mine, a.credential)),
        )
        .unwrap();
    assert!(done.verified.credential == a.credential);
    assert!(matches!(done.verified.purpose, LoginPurpose::Reauth { .. }));

    // The same proof presented in another session, in none, or as an
    // ordinary login is refused, and each refusal is the same plain denial.
    let attempts: [(&str, Option<(SessionBinding, CredentialId)>); 2] = [
        ("another session", Some((session(0xA2), a.credential))),
        ("no session", None),
    ];
    for (what, current) in attempts {
        assert!(
            matches!(
                s.login(
                    &Target::Active(&a),
                    PASSWORD,
                    Ksf::Small,
                    reauth(&a.credential, mine),
                    current,
                ),
                Err(LoginFailure::Finish(e)) if e == denied(DenyReason::StateInvalid)
            ),
            "{what}"
        );
    }
    // A state made for an ordinary login does not serve a session.
    assert!(matches!(
        s.login(
            &Target::Active(&a),
            PASSWORD,
            Ksf::Small,
            LoginPurpose::Login,
            Some((mine, a.credential)),
        ),
        Err(LoginFailure::Finish(e)) if e == denied(DenyReason::StateInvalid)
    ));
    // The session of Alice with the password of Mallory is no re-auth of
    // Alice: the login is for the other account.
    assert!(matches!(
        s.login(
            &Target::Active(&m),
            PASSWORD_2,
            Ksf::Small,
            reauth(&m.credential, mine),
            Some((mine, a.credential)),
        ),
        Err(LoginFailure::Finish(e)) if e == denied(DenyReason::StateInvalid)
    ));
}

// ------------------------------------------------------- pins and V8

#[test]
fn server_key_change_is_seen_at_reregistration() {
    let s = Server::new();
    let a = alice(&s);
    // The same accounts behind other keys: a server that was set up again.
    let rotated = Server::seeded("rotated", ProfileRules::ferret_v1());

    // The old records do not open any more.
    assert!(matches!(
        rotated.login(
            &Target::Active(&a),
            PASSWORD,
            Ksf::Small,
            LoginPurpose::Login,
            None
        ),
        Err(LoginFailure::Client(Error::Decrypt))
    ));

    // A client that registers again sees another server key than the one it
    // pinned, for a password change and for a recovery.
    let pinned = a.new.pinned(URL).unwrap();
    let input = new_input(PASSWORD_2);
    let registration = rotated.client_register(&a.credential, &input, Ksf::Small, "rotated");
    assert_ne!(registration.server_public_key, a.new.server_public_key);
    let err = change_password(
        &mut TestRng::new(b"change"),
        &a.new.vault,
        NewPassword {
            input: &input,
            registration,
            profile: KsfProfile::P1,
        },
        &pinned,
        &a.new.wraps[0],
        &ManifestRow {
            rev: a.new.manifest.rev,
            envelope: &a.new.manifest.envelope,
            tag: &a.new.manifest.tag,
        },
    )
    .err();
    assert_eq!(err, Some(Error::Pinned(PinnedField::ServerKey)));

    let registration = rotated.client_register(&a.credential, &input, Ksf::Small, "rotated 2");
    let err = rotated
        .try_recovered(&a, &input, registration, PinState::Pinned(&pinned))
        .err();
    assert_eq!(err, Some(Error::Pinned(PinnedField::ServerKey)));

    // The same flow against the real server is accepted.
    s.password_change(&a, PASSWORD_2, "control");
}

#[test]
fn claimed_profile_that_does_not_match_the_record_locks_the_account_out() {
    // The server cannot see the real stretching profile of a record: it
    // trusts the claim. A record made with profile 1 but stored as profile 2
    // never opens, and the way out is a recovery that makes the record
    // again with the parameters of profile 2.
    let s = Server::with_two_profiles();
    let mut a = alice(&s);
    let wrong = register_finish(
        &a.new.registration_record,
        2,
        &s.profiles,
        RegistrationKind::NewAccount,
    )
    .unwrap();
    a.row = ferret_server_auth::testing::TestAccountStore::new(a.row.read().account, wrong);

    // The server now tells the client to use profile 2. The client of the
    // core has no profile 2, so a real client stops before any work; a
    // client with the parameters of profile 2 fails to open the envelope.
    assert!(matches!(
        s.login(
            &Target::Active(&a),
            PASSWORD,
            Ksf::Production,
            LoginPurpose::Login,
            None
        ),
        Err(LoginFailure::Client(Error::KdfProfileUnknown))
    ));
    assert!(matches!(
        s.login(
            &Target::Active(&a),
            PASSWORD,
            Ksf::Params(PROFILE_2_PARAMS),
            LoginPurpose::Login,
            None
        ),
        Err(LoginFailure::Client(Error::Decrypt))
    ));

    // A recovery that claims profile 1 is a downgrade of what is stored.
    let rec = s.recovered(&a, PASSWORD, Ksf::Small, "back to one");
    let req = s.recover_req(&a, &rec, 1, session(0xB2));
    assert_eq!(s.replace(&a, &req).unwrap_err(), AuthError::ProfileRejected);

    // A recovery that makes the record with the parameters of profile 2 and
    // says so gets the owner back in.
    let rec = s.recovered(&a, PASSWORD, Ksf::Params(PROFILE_2_PARAMS), "way out");
    let req = s.recover_req(&a, &rec, 2, session(0xB3));
    let permit = s.replace(&a, &req).unwrap();
    a.row.apply_replacement(&permit).unwrap();
    assert!(
        s.login(
            &Target::Active(&a),
            PASSWORD,
            Ksf::Params(PROFILE_2_PARAMS),
            LoginPurpose::Login,
            None
        )
        .is_ok()
    );
}

// ------------------------------------------------------------ scopes

#[test]
fn account_reset_session_can_recover_but_nothing_else() {
    let s = Server::new();
    let a = alice(&s);
    let reset = SessionScope::AccountReset;
    let allowed = [
        Capability::Challenge,
        Capability::OpaqueRegisterStart,
        Capability::RecoveryWrapRead,
        Capability::Recover,
        Capability::Logout,
    ];

    // The capability gate, for every capability there is.
    for cap in Capability::ALL {
        let decision = authorize(reset, *cap);
        if allowed.contains(cap) {
            assert!(decision.is_ok(), "{cap:?}");
        } else {
            assert_eq!(
                decision.unwrap_err(),
                denied(DenyReason::ScopeForbids),
                "{cap:?}"
            );
        }
    }
    assert_eq!(
        denied(DenyReason::ScopeForbids).http_class(),
        ErrorClass::Forbidden
    );

    // The recovery goes through the library and ends the session.
    let rec = s.recovered(&a, PASSWORD_2, Ksf::Small, "reset");
    let req = s.recover_req(&a, &rec, 1, session(0xC1));
    let permit = s.replace(&a, &req).unwrap();
    assert_eq!(permit.session_effect, ScopeEffect::EndSession);

    // Every other entry point that takes a scope refuses it, and a refusal
    // touches nothing: the nonce below is still good afterwards.
    let session_id = session(0xC2);
    let nonce = s.challenge(reset, &session_id, &a.account_id).unwrap();
    s.throttle.clear();
    let body = br#"{"method_id":"a","wrap":1}"#.to_vec();
    for op in [
        AuthOp::UnlockMethodAdd,
        AuthOp::UnlockMethodRemove,
        AuthOp::UnlockMethodRecoveryPut,
        AuthOp::Rekey,
    ] {
        let proof = auth_sign(&a.new.vault, op, &nonce, &body).unwrap();
        let request = SignedRequest {
            caller: caller(),
            op: op.op(),
            scope: reset,
            session: session_id,
            nonce: &nonce,
            proof: &proof,
            body: &body,
        };
        assert_eq!(
            authorize_signed(&s.cx(), &s.nonces, &a.row.read().account, &request).unwrap_err(),
            denied(DenyReason::ScopeForbids),
            "{op:?}"
        );
    }
    assert!(s.stages().is_empty(), "a refused scope reaches no throttle");
    let change = s.password_change(&a, PASSWORD_2, "from a reset session");
    let mut put = s.put_req(&a, &change, 1, session(0xC3));
    put.scope = reset;
    s.throttle.clear();
    assert_eq!(
        s.replace(&a, &put).unwrap_err(),
        denied(DenyReason::ScopeForbids)
    );
    assert!(s.stages().is_empty(), "a refused scope reaches no throttle");
    // The nonce of the reset session was not consumed by any refusal.
    let proof = auth_sign(&a.new.vault, AuthOp::UnlockMethodAdd, &nonce, &body).unwrap();
    let request = SignedRequest {
        caller: caller(),
        op: AuthOp::UnlockMethodAdd.op(),
        scope: SessionScope::Full,
        session: session_id,
        nonce: &nonce,
        proof: &proof,
        body: &body,
    };
    assert!(authorize_signed(&s.cx(), &s.nonces, &a.row.read().account, &request).is_ok());
}

// --------------------------------------------- signed unlock-method calls

#[test]
fn signed_unlock_method_operations_are_checked_and_written_conditionally() {
    let s = Server::new();
    let a = alice(&s);
    let mine = session(0xA1);
    let bodies = [
        (
            AuthOp::UnlockMethodAdd,
            br#"{"method_id":"a","wrap":1}"#.to_vec(),
        ),
        (
            AuthOp::UnlockMethodRemove,
            br#"{"method_id":"a","manifest":1}"#.to_vec(),
        ),
        (
            AuthOp::UnlockMethodRecoveryPut,
            br#"{"wrap":2,"pk_r":3}"#.to_vec(),
        ),
        (AuthOp::Rekey, br#"{"items":[]}"#.to_vec()),
    ];

    for (op, body) in &bodies {
        let nonce = s
            .challenge(SessionScope::Full, &mine, &a.account_id)
            .unwrap();
        let proof = auth_sign(&a.new.vault, *op, &nonce, body).unwrap();
        let request = SignedRequest {
            caller: caller(),
            op: op.op(),
            scope: SessionScope::Full,
            session: mine,
            nonce: &nonce,
            proof: &proof,
            body,
        };
        let account = a.row.read().account;
        let permit = authorize_signed(&s.cx(), &s.nonces, &account, &request).unwrap();
        assert_eq!(permit.op, op.op());
        assert_eq!(permit.account_id, a.account_id);
        // The same request again finds no nonce.
        assert_eq!(
            authorize_signed(&s.cx(), &s.nonces, &account, &request).unwrap_err(),
            denied(DenyReason::NonceUnknown),
            "{op:?}"
        );
        // The write is conditional on the row the proof was checked against:
        // the first one wins, a second permit from the same snapshot is
        // refused.
        let second_nonce = s
            .challenge(SessionScope::Full, &mine, &a.account_id)
            .unwrap();
        let second_proof = auth_sign(&a.new.vault, *op, &second_nonce, body).unwrap();
        let second = SignedRequest {
            nonce: &second_nonce,
            proof: &second_proof,
            ..request
        };
        let stale = authorize_signed(&s.cx(), &s.nonces, &account, &second).unwrap();
        a.row.apply_signed(&permit).unwrap();
        assert_eq!(
            a.row.apply_signed(&stale),
            Err(WriteRefused::Stale),
            "{op:?}"
        );
    }
    assert_eq!(a.row.read().account.row_version, 5);

    // A proof for one operation does not serve another, and the library
    // refuses the two operations that replace the record.
    let nonce = s
        .challenge(SessionScope::Full, &mine, &a.account_id)
        .unwrap();
    let proof = auth_sign(&a.new.vault, AuthOp::UnlockMethodAdd, &nonce, b"{}").unwrap();
    let request = SignedRequest {
        caller: caller(),
        op: AuthOp::Rekey.op(),
        scope: SessionScope::Full,
        session: mine,
        nonce: &nonce,
        proof: &proof,
        body: b"{}",
    };
    let account = a.row.read().account;
    assert_eq!(
        authorize_signed(&s.cx(), &s.nonces, &account, &request).unwrap_err(),
        denied(DenyReason::ProofInvalid)
    );
    let request = SignedRequest {
        op: AuthOp::UnlockMethodPasswordPut.op(),
        ..request
    };
    assert_eq!(
        authorize_signed(&s.cx(), &s.nonces, &account, &request).unwrap_err(),
        AuthError::Internal(InternalKind::Policy)
    );
}

// ---------------------------------------------------------------- throttle

#[test]
fn a_refusing_throttle_stops_every_entry_point_before_any_work() {
    let s = Server::new();
    let a = alice(&s);
    let wait = RetryAfter::new(30);
    let throttled = AuthError::Throttled {
        retry_after_secs: 30,
    };

    // A login that is under way when the throttle starts to refuse.
    let started = s
        .begin(&Target::Active(&a), PASSWORD, LoginPurpose::Login)
        .unwrap();
    let (login_id, answer) = started.client_answer(Ksf::Small);
    let ke3 = answer.unwrap().ke3;
    let change = s.password_change(&a, PASSWORD_2, "change");
    let req = s.put_req(&a, &change, 1, session(0xA1));

    s.throttle.refuse_with(Some(wait));
    assert_eq!(
        s.begin(&Target::Active(&a), PASSWORD, LoginPurpose::Login)
            .err(),
        Some(throttled)
    );
    assert_eq!(
        s.challenge(SessionScope::Full, &session(0xA1), &a.account_id)
            .unwrap_err(),
        throttled
    );
    assert_eq!(s.replace(&a, &req).unwrap_err(), throttled);
    assert_eq!(throttled.http_class(), ErrorClass::TooManyRequests);
    assert_eq!(throttled.public_code(), "throttled");

    // Once the throttle lets go, the request that was refused still works:
    // a refusal at the throttle consumed no nonce.
    s.throttle.refuse_with(None);
    assert!(s.replace(&a, &req).is_ok());
    assert!(s.finish(&login_id, &ke3, None).is_ok());
}

#[test]
fn a_nonce_is_good_for_five_minutes_in_its_own_session_only() {
    let s = Server::new();
    let a = alice(&s);
    let change = s.password_change(&a, PASSWORD_2, "change");

    // Another session's nonce does not serve, and is not burned by trying.
    let req = s.put_req(&a, &change, 1, session(0xA1));
    let mut elsewhere = req.clone();
    elsewhere.session = session(0xA2);
    assert_eq!(
        s.replace(&a, &elsewhere).unwrap_err(),
        denied(DenyReason::NonceUnknown)
    );

    // Five minutes less a second is still fine; the full five is not.
    let late = s.put_req(&a, &change, 1, session(0xA3));
    s.clock.advance(299);
    assert!(s.replace(&a, &req).is_ok());
    s.clock.advance(1);
    assert_eq!(
        s.replace(&a, &late).unwrap_err(),
        denied(DenyReason::NonceExpired)
    );
}
