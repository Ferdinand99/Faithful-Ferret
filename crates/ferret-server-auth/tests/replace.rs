//! Challenges, signed proofs and the replacement of the OPAQUE record, with
//! the client of `ferret-core` making the account, the password change, the
//! recovery and the proofs.
//!
//! The body of a request in these tests is `profile (4 bytes, big endian) ‖
//! record`. The library does not read bodies, so the format belongs to the
//! test's parser, the way the JSON of an endpoint belongs to the endpoint.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]

use std::net::IpAddr;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU32, AtomicUsize, Ordering};

use ferret_core::testing::opaque::{TestKsf, login_finish_with, register_finish_with};
use ferret_core::{
    AccountId, AuthOp, AuthPublicKey, KsfProfile, ManifestRow, MasterPassword, MethodId, MpPolicy,
    NewAccount, NewAccountIds, NewPassword, OpaqueInput, PasswordChange, PinState, Recovered,
    RecoveryInput, RecoveryPublicKey, RegistrationFinished, TestRng, VaultId, auth_sign,
    change_password, create_account, encode_recovery_key, opaque_login_start,
    opaque_register_start, recover, recovery_sign,
};
use ferret_server_auth::testing::{LoginFixture, SMALL};
use ferret_server_auth::{
    AccountAuthState, AccountLookup, AuthContext, AuthError, ChallengeKey, ChallengeStore,
    ConsumeOutcome, CredentialId, DenyReason, InMemoryChallengeStore, LoginFinishRequest,
    LoginPurpose, LoginStartRequest, Malformed, Outcome, ProfileRules, RegistrationKind,
    ReplaceFields, ReplaceKind, ReplacePermit, ReplaceRequest, ScopeEffect, SessionBinding,
    SessionScope, Stage, StoreError, StoredRecord, ThrottleCall, ThrottleKey,
    authorize_replacement, issue_challenge, login_finish, login_start, register_finish,
    register_start,
};
use sha2::{Digest, Sha256};

const URL: &str = "https://ferret.example";
const PASSWORD: &str = "correct horse battery staple";
const PASSWORD_2: &str = "tr0ub4dor and three more words";

fn session(fill: u8) -> SessionBinding {
    SessionBinding([fill; 32])
}

/// The default session of a test.
fn s1() -> SessionBinding {
    session(0xA1)
}

fn account_id() -> AccountId {
    AccountId::from_bytes([0x11; 16])
}

fn credential() -> CredentialId {
    CredentialId::from(&account_id())
}

/// The body the test's endpoint reads: the claimed profile, then the record.
fn body_of(profile: u32, record: &[u8]) -> Vec<u8> {
    let mut body = profile.to_be_bytes().to_vec();
    body.extend_from_slice(record);
    body
}

/// The parser of the test's endpoint. A body too short for a profile is not
/// well formed.
fn parse(body: &[u8]) -> Result<ReplaceFields<'_>, AuthError> {
    let (profile, record) = body
        .split_first_chunk::<4>()
        .ok_or(AuthError::Malformed(Malformed::RegistrationRecord))?;
    Ok(ReplaceFields {
        record,
        ksf_profile: u32::from_be_bytes(*profile),
    })
}

/// A parser that remembers every body it was given.
fn spy(
    seen: &Mutex<Vec<Vec<u8>>>,
) -> impl for<'b> FnOnce(&'b [u8]) -> Result<ReplaceFields<'b>, AuthError> + '_ {
    move |body| {
        seen.lock().unwrap().push(body.to_vec());
        parse(body)
    }
}

/// A request as it goes to the library, with owned bytes.
#[derive(Clone)]
struct Req {
    kind: ReplaceKind,
    scope: SessionScope,
    session: SessionBinding,
    nonce: [u8; 32],
    proof: [u8; 64],
    body: Vec<u8>,
}

impl Req {
    fn as_request(&self) -> ReplaceRequest<'_> {
        ReplaceRequest {
            caller: LoginFixture::caller(),
            kind: self.kind,
            scope: self.scope,
            session: self.session,
            nonce: &self.nonce,
            proof: &self.proof,
            body: &self.body,
        }
    }
}

/// A server, an account that the client of the core made on it, and a store
/// of nonces.
struct World {
    f: LoginFixture,
    profiles: ProfileRules,
    nonces: InMemoryChallengeStore,
    account: NewAccount,
    stored: StoredRecord,
    seeds: AtomicU32,
}

impl World {
    fn new() -> Self {
        Self::with_profiles(ProfileRules::for_tests(&[1, 2], 1))
    }

    fn with_profiles(profiles: ProfileRules) -> Self {
        let f = LoginFixture::new();
        let world_seed = AtomicU32::new(0);
        let input = password_input(PASSWORD);
        let registration = register_with(&f, &input, "initial");
        let account = create_account(
            &mut TestRng::new(b"account"),
            &NewAccountIds {
                account_id: account_id(),
                vault_id: VaultId::from_bytes([0x22; 16]),
                password_method_id: MethodId::from_bytes([0x70; 16]),
                recovery_method_id: MethodId::from_bytes([0x71; 16]),
            },
            NewPassword {
                input: &input,
                registration,
                profile: KsfProfile::P1,
            },
            None,
        )
        .unwrap();
        let stored = register_finish(
            &account.registration_record,
            1,
            &profiles,
            RegistrationKind::NewAccount,
        )
        .unwrap();
        Self {
            f,
            profiles,
            nonces: InMemoryChallengeStore::new(),
            account,
            stored,
            seeds: world_seed,
        }
    }

    fn cx(&self) -> AuthContext<'_> {
        AuthContext::new(
            &self.f.keys,
            &self.f.prelogin,
            &self.f.seal,
            &self.f.clock,
            &self.f.throttle,
            &self.f.policy,
            &self.profiles,
        )
    }

    /// What the server holds for the account now.
    fn state<'a>(&'a self, current: &'a StoredRecord) -> AccountAuthState<'a> {
        AccountAuthState {
            account_id: account_id(),
            pk_a: AuthPublicKey::new(self.account.pk_a),
            pk_r: RecoveryPublicKey::new(self.account.pk_r),
            vk_epoch: 1,
            current,
        }
    }

    fn seed(&self, what: &str) -> TestRng {
        let n = self.seeds.fetch_add(1, Ordering::Relaxed);
        TestRng::new(format!("{what} {n}").as_bytes())
    }

    /// A nonce for `session`, issued the way an endpoint does it.
    fn challenge(&self, session: &SessionBinding) -> [u8; 32] {
        issue_challenge(
            &self.cx(),
            &self.nonces,
            &mut self.seed("nonce"),
            &LoginFixture::caller(),
            SessionScope::Full,
            session,
        )
        .unwrap()
        .nonce
    }

    fn pinned(&self) -> ferret_core::Pinned {
        self.account.pinned(URL).unwrap()
    }

    /// The change of password to `text` that the client makes.
    fn change(&self, text: &str) -> PasswordChange {
        let input = password_input(text);
        let registration = register_with(&self.f, &input, text);
        let a = &self.account;
        change_password(
            &mut self.seed("change"),
            &a.vault,
            NewPassword {
                input: &input,
                registration,
                profile: KsfProfile::P1,
            },
            &self.pinned(),
            &a.wraps[0],
            &ManifestRow {
                rev: a.manifest.rev,
                envelope: &a.manifest.envelope,
                tag: &a.manifest.tag,
            },
        )
        .unwrap()
    }

    /// The recovery to `text` that the client makes with the recovery key of
    /// the account.
    fn recovered(&self, text: &str) -> Recovered {
        let input = password_input(text);
        let registration = register_with(&self.f, &input, text);
        let a = &self.account;
        let code = encode_recovery_key(&a.recovery_key).to_string();
        recover(
            &mut self.seed("recover"),
            &RecoveryInput {
                ctx: a.vault.context(),
                rk_code: &code,
                rk_wrap: &a.wraps[1],
                manifest: ManifestRow {
                    rev: a.manifest.rev,
                    envelope: &a.manifest.envelope,
                    tag: &a.manifest.tag,
                },
                new_recovery_method_id: MethodId::from_bytes([0x73; 16]),
            },
            NewPassword {
                input: &input,
                registration,
                profile: KsfProfile::P1,
            },
            PinState::FirstUse,
        )
        .unwrap()
    }

    /// A signed request for a password change, over `body`, with a nonce
    /// issued to `session`.
    fn put_req(&self, change: &PasswordChange, session: SessionBinding, body: Vec<u8>) -> Req {
        let nonce = self.challenge(&session);
        let proof = change.sign(&self.account.vault, &nonce, &body).unwrap();
        Req {
            kind: ReplaceKind::PasswordPut,
            scope: SessionScope::Full,
            session,
            nonce,
            proof,
            body,
        }
    }

    /// A signed request for a recovery, over `body`.
    fn recover_req(&self, rec: &Recovered, session: SessionBinding, body: Vec<u8>) -> Req {
        let nonce = self.challenge(&session);
        let proof = rec.sign(&nonce, &body).unwrap();
        Req {
            kind: ReplaceKind::Recover,
            scope: SessionScope::AccountReset,
            session,
            nonce,
            proof,
            body,
        }
    }

    fn run(&self, req: &Req) -> Result<ReplacePermit, AuthError> {
        self.run_as(&self.stored, req)
    }

    fn run_as(&self, current: &StoredRecord, req: &Req) -> Result<ReplacePermit, AuthError> {
        authorize_replacement(
            &self.cx(),
            &self.nonces,
            &self.state(current),
            &req.as_request(),
            parse,
        )
    }

    /// A full OPAQUE login of `input` against `record`, through the library.
    /// `true` when the server accepts it.
    fn can_log_in(&self, record: &StoredRecord, input: &OpaqueInput) -> bool {
        let (ke1, state) = opaque_login_start(&mut self.seed("login client"), input).unwrap();
        let started = login_start(
            &self.cx(),
            &self.f.store,
            &mut self.seed("login server"),
            &LoginStartRequest {
                caller: LoginFixture::caller(),
                name: &self.f.name,
                credential: credential(),
                lookup: AccountLookup::Active {
                    record,
                    sk_hint: false,
                },
                purpose: LoginPurpose::Login,
                ke1: &ke1,
            },
        )
        .unwrap();
        let Ok(done) = login_finish_with(
            &mut self.seed("login finish"),
            state,
            input,
            &started.ke2,
            &TestKsf::new(SMALL),
            Some(ferret_core::OPAQUE_CONTEXT),
            PinState::FirstUse,
        ) else {
            return false;
        };
        login_finish(
            &self.cx(),
            &self.f.store,
            &LoginFinishRequest {
                caller: LoginFixture::caller(),
                login_id: started.login_id.to_hex().as_bytes(),
                ke3: &done.finished.ke3,
                current_session: None,
            },
        )
        .is_ok()
    }
}

/// The OPAQUE input of a password for a new account or a change.
fn password_input(text: &str) -> OpaqueInput {
    MasterPassword::new(text.as_bytes(), MpPolicy::WithoutSecretKey)
        .unwrap()
        .opaque_input(None)
}

/// The client's OPAQUE registration of `input` against the server of `f`,
/// under the credential id of the account.
fn register_with(f: &LoginFixture, input: &OpaqueInput, seed: &str) -> RegistrationFinished {
    let mut client = TestRng::new(format!("client {seed}").as_bytes());
    let (request, state) = opaque_register_start(&mut client, input).unwrap();
    let response = register_start(&f.keys, &credential(), &request).unwrap();
    register_finish_with(&mut client, state, input, &response, &TestKsf::new(SMALL)).unwrap()
}

fn denied(reason: DenyReason) -> AuthError {
    AuthError::Denied(reason)
}

fn flip(bytes: &mut [u8], at: usize) {
    bytes[at] ^= 0x01;
}

// ----------------------------------------------------------------- success

#[test]
fn password_put_with_valid_proof_is_permitted() {
    let w = World::new();
    let change = w.change(PASSWORD_2);
    let body = body_of(1, &change.registration_record);
    let req = w.put_req(&change, s1(), body.clone());
    w.f.throttle.clear();
    let permit = w.run(&req).unwrap();
    assert_eq!(permit.account_id, account_id());
    assert_eq!(permit.kind, ReplaceKind::PasswordPut);
    assert_eq!(permit.new.ksf_profile, 1);
    assert_eq!(
        permit.new.record.as_bytes(),
        change.registration_record.as_slice()
    );
    assert_eq!(permit.session_effect, ScopeEffect::Keep);

    // The library asks first and reports once, by address and account.
    let ip: IpAddr = "192.0.2.7".parse().unwrap();
    let keys = vec![ThrottleKey::Ip(ip), ThrottleKey::Account(credential())];
    assert_eq!(
        w.f.throttle.calls(),
        vec![
            ThrottleCall::Admit {
                stage: Stage::Replace,
                keys: keys.clone(),
                now: LoginFixture::START
            },
            ThrottleCall::Record {
                stage: Stage::Replace,
                keys,
                outcome: Outcome::Success,
                now: LoginFixture::START
            },
        ]
    );

    // The new record logs in with the new password and not with the old one.
    assert!(w.can_log_in(&permit.new, &password_input(PASSWORD_2)));
    assert!(!w.can_log_in(&permit.new, &password_input(PASSWORD)));
    assert!(w.can_log_in(&w.stored, &password_input(PASSWORD)));
}

#[test]
fn recover_with_valid_proof_is_permitted() {
    let w = World::new();
    let rec = w.recovered(PASSWORD_2);
    let body = body_of(1, &rec.registration_record);
    let req = w.recover_req(&rec, s1(), body);
    let permit = w.run(&req).unwrap();
    assert_eq!(permit.kind, ReplaceKind::Recover);
    assert_eq!(
        permit.new.record.as_bytes(),
        rec.registration_record.as_slice()
    );
    // The session of a reset account ends with the recovery.
    assert_eq!(permit.session_effect, ScopeEffect::EndSession);
    assert!(w.can_log_in(&permit.new, &password_input(PASSWORD_2)));
}

#[test]
fn a_recovery_in_a_full_session_keeps_the_session() {
    let w = World::new();
    let rec = w.recovered(PASSWORD_2);
    let mut req = w.recover_req(&rec, s1(), body_of(1, &rec.registration_record));
    req.scope = SessionScope::Full;
    assert_eq!(w.run(&req).unwrap().session_effect, ScopeEffect::Keep);
}

#[test]
fn a_ksf_upgrade_is_a_password_put_with_a_higher_profile() {
    let w = World::new();
    let change = w.change(PASSWORD);
    let req = w.put_req(&change, s1(), body_of(2, &change.registration_record));
    assert_eq!(w.run(&req).unwrap().new.ksf_profile, 2);
}

// ------------------------------------------------------------ the proof

#[test]
fn proof_for_another_op_is_denied() {
    let w = World::new();
    let change = w.change(PASSWORD_2);
    let body = body_of(1, &change.registration_record);
    for op in AuthOp::ALL {
        if op == AuthOp::UnlockMethodPasswordPut {
            continue;
        }
        let nonce = w.challenge(&s1());
        let proof = auth_sign(&w.account.vault, op, &nonce, &body).unwrap();
        let req = Req {
            kind: ReplaceKind::PasswordPut,
            scope: SessionScope::Full,
            session: s1(),
            nonce,
            proof,
            body: body.clone(),
        };
        assert_eq!(
            w.run(&req).unwrap_err(),
            denied(DenyReason::ProofInvalid),
            "{op:?}"
        );
    }
    // The control: the right op for the same body is accepted.
    assert!(w.run(&w.put_req(&change, s1(), body)).is_ok());
}

#[test]
fn proof_over_another_body_is_denied() {
    let w = World::new();
    let change = w.change(PASSWORD_2);
    let body = body_of(1, &change.registration_record);
    for at in [0, 3, 4, 100, body.len() - 1] {
        let mut req = w.put_req(&change, s1(), body.clone());
        flip(&mut req.body, at);
        assert_eq!(
            w.run(&req).unwrap_err(),
            denied(DenyReason::ProofInvalid),
            "byte {at}"
        );
    }
    // A longer or a shorter body is another body too.
    let mut longer = body.clone();
    longer.push(0);
    for other in [body[..body.len() - 1].to_vec(), longer] {
        let mut req = w.put_req(&change, s1(), body.clone());
        req.body = other;
        assert_eq!(w.run(&req).unwrap_err(), denied(DenyReason::ProofInvalid));
    }
}

#[test]
fn proof_for_another_account_epoch_or_nonce_is_denied() {
    let w = World::new();
    let rec = w.recovered(PASSWORD_2);
    let body = body_of(1, &rec.registration_record);
    let rk = &w.account.recovery_key;
    let other_account = AccountId::from_bytes([0x12; 16]);

    // Another account: valid for the key and the nonce, but not for this
    // account.
    let nonce = w.challenge(&s1());
    let proof = recovery_sign(rk, &other_account, 1, &nonce, &body).unwrap();
    let req = Req {
        kind: ReplaceKind::Recover,
        scope: SessionScope::AccountReset,
        session: s1(),
        nonce,
        proof,
        body: body.clone(),
    };
    assert_eq!(w.run(&req).unwrap_err(), denied(DenyReason::ProofInvalid));

    // Another epoch.
    let nonce = w.challenge(&s1());
    let proof = recovery_sign(rk, &account_id(), 2, &nonce, &body).unwrap();
    let req = Req {
        nonce,
        proof,
        ..req.clone()
    };
    assert_eq!(w.run(&req).unwrap_err(), denied(DenyReason::ProofInvalid));

    // Another nonce: signed for one, sent with another that is also live.
    let signed_for = w.challenge(&s1());
    let sent_with = w.challenge(&s1());
    let proof = recovery_sign(rk, &account_id(), 1, &signed_for, &body).unwrap();
    let req = Req {
        nonce: sent_with,
        proof,
        ..req.clone()
    };
    assert_eq!(w.run(&req).unwrap_err(), denied(DenyReason::ProofInvalid));
}

#[test]
fn recover_signed_by_sk_a_is_denied_and_password_put_signed_by_sk_r_is_denied() {
    let w = World::new();
    let change = w.change(PASSWORD_2);
    let body = body_of(1, &change.registration_record);

    // `sk_a` for `unlock-method.password.put`, offered as a recovery.
    let nonce = w.challenge(&s1());
    let proof = change.sign(&w.account.vault, &nonce, &body).unwrap();
    let req = Req {
        kind: ReplaceKind::Recover,
        scope: SessionScope::AccountReset,
        session: s1(),
        nonce,
        proof,
        body: body.clone(),
    };
    assert_eq!(w.run(&req).unwrap_err(), denied(DenyReason::ProofInvalid));

    // `sk_r` with the label of a recovery, offered as a password change.
    let nonce = w.challenge(&s1());
    let proof = recovery_sign(&w.account.recovery_key, &account_id(), 1, &nonce, &body).unwrap();
    let req = Req {
        kind: ReplaceKind::PasswordPut,
        scope: SessionScope::Full,
        session: s1(),
        nonce,
        proof,
        body,
    };
    assert_eq!(w.run(&req).unwrap_err(), denied(DenyReason::ProofInvalid));
}

#[test]
fn a_recovery_proof_made_with_the_old_recovery_key_is_denied_after_the_recovery() {
    let w = World::new();
    let rec = w.recovered(PASSWORD_2);
    let body = body_of(1, &rec.registration_record);
    let permit = w.run(&w.recover_req(&rec, s1(), body.clone())).unwrap();

    // The server now holds the new `pk_r` and the new record.
    let after = AccountAuthState {
        pk_r: RecoveryPublicKey::new(rec.pk_r),
        ..w.state(&permit.new)
    };
    let attempt = |rk: &ferret_core::RecoveryKey| {
        let nonce = w.challenge(&s1());
        let proof = recovery_sign(rk, &account_id(), 1, &nonce, &body).unwrap();
        let req = Req {
            kind: ReplaceKind::Recover,
            scope: SessionScope::AccountReset,
            session: s1(),
            nonce,
            proof,
            body: body.clone(),
        };
        authorize_replacement(&w.cx(), &w.nonces, &after, &req.as_request(), parse)
    };
    // The old recovery key is no longer enough, even with a live nonce.
    assert_eq!(
        attempt(&w.account.recovery_key).unwrap_err(),
        denied(DenyReason::ProofInvalid)
    );
    // The new one is.
    assert!(attempt(&rec.recovery_key).is_ok());
}

#[test]
fn vk_epoch_comes_from_the_server() {
    let w = World::new();
    let rec = w.recovered(PASSWORD_2);
    let body = body_of(1, &rec.registration_record);
    let rk = &w.account.recovery_key;
    // A proof that is valid for epoch 7.
    let signed = |nonce: &[u8; 32]| recovery_sign(rk, &account_id(), 7, nonce, &body).unwrap();
    let make = || {
        let nonce = w.challenge(&s1());
        Req {
            kind: ReplaceKind::Recover,
            scope: SessionScope::AccountReset,
            session: s1(),
            nonce,
            proof: signed(&nonce),
            body: body.clone(),
        }
    };
    // The server holds epoch 1: the valid signature for 7 does not count.
    assert_eq!(
        w.run(&make()).unwrap_err(),
        denied(DenyReason::ProofInvalid)
    );
    // The same signature is accepted once the server's epoch is 7.
    let at_seven = AccountAuthState {
        vk_epoch: 7,
        ..w.state(&w.stored)
    };
    let req = make();
    authorize_replacement(&w.cx(), &w.nonces, &at_seven, &req.as_request(), parse).unwrap();
}

// ---------------------------------------------------------------- the nonce

#[test]
fn nonce_is_single_use() {
    let w = World::new();
    let change = w.change(PASSWORD_2);
    let req = w.put_req(&change, s1(), body_of(1, &change.registration_record));
    assert!(w.run(&req).is_ok());
    // The identical request again: a replayed proof.
    assert_eq!(w.run(&req).unwrap_err(), denied(DenyReason::NonceUnknown));
}

#[test]
fn simultaneous_requests_with_one_nonce_give_one_permit() {
    let w = World::new();
    let change = w.change(PASSWORD_2);
    let req = w.put_req(&change, s1(), body_of(1, &change.registration_record));
    let (cx, state) = (w.cx(), w.state(&w.stored));
    let permits = AtomicUsize::new(0);
    let barrier = std::sync::Barrier::new(16);
    std::thread::scope(|scope| {
        for _ in 0..16 {
            scope.spawn(|| {
                barrier.wait();
                match authorize_replacement(&cx, &w.nonces, &state, &req.as_request(), parse) {
                    Ok(_) => {
                        permits.fetch_add(1, Ordering::SeqCst);
                    }
                    Err(error) => assert_eq!(error, denied(DenyReason::NonceUnknown)),
                }
            });
        }
    });
    assert_eq!(permits.load(Ordering::SeqCst), 1);
}

#[test]
fn nonce_from_another_session_is_denied() {
    let w = World::new();
    let change = w.change(PASSWORD_2);
    let body = body_of(1, &change.registration_record);
    // The nonce was issued to session 1 and is presented in session 2.
    let req = w.put_req(&change, s1(), body);
    let elsewhere = Req {
        session: session(0xB2),
        ..req.clone()
    };
    assert_eq!(
        w.run(&elsewhere).unwrap_err(),
        denied(DenyReason::NonceUnknown)
    );
    // The failed attempt in another session did not use the nonce up.
    assert!(w.run(&req).is_ok());
}

#[test]
fn expired_nonce_is_denied() {
    let w = World::new();
    let change = w.change(PASSWORD_2);
    let body = body_of(1, &change.registration_record);
    let fresh = w.put_req(&change, s1(), body.clone());
    let late = w.put_req(&change, s1(), body);
    // 299 seconds after the nonce was issued it still works ...
    w.f.clock.set(LoginFixture::START + 299);
    assert!(w.run(&fresh).is_ok());
    // ... and at 300 it does not.
    w.f.clock.set(LoginFixture::START + 300);
    assert_eq!(w.run(&late).unwrap_err(), denied(DenyReason::NonceExpired));
    // An expired nonce is used up by the attempt.
    assert_eq!(w.run(&late).unwrap_err(), denied(DenyReason::NonceUnknown));
}

#[test]
fn a_failed_signature_burns_the_nonce() {
    let w = World::new();
    let change = w.change(PASSWORD_2);
    let body = body_of(1, &change.registration_record);
    let good = w.put_req(&change, s1(), body);
    let mut bad = good.clone();
    flip(&mut bad.proof, 0);
    assert_eq!(w.run(&bad).unwrap_err(), denied(DenyReason::ProofInvalid));
    // The right proof for the same nonce comes too late.
    assert_eq!(w.run(&good).unwrap_err(), denied(DenyReason::NonceUnknown));
}

#[test]
fn a_nonce_that_was_never_issued_is_denied() {
    let w = World::new();
    let change = w.change(PASSWORD_2);
    let body = body_of(1, &change.registration_record);
    let nonce = [0x5a; 32];
    let proof = change.sign(&w.account.vault, &nonce, &body).unwrap();
    let req = Req {
        kind: ReplaceKind::PasswordPut,
        scope: SessionScope::Full,
        session: s1(),
        nonce,
        proof,
        body,
    };
    assert_eq!(w.run(&req).unwrap_err(), denied(DenyReason::NonceUnknown));
}

#[test]
fn nonce_and_proof_must_have_the_exact_length() {
    let w = World::new();
    let change = w.change(PASSWORD_2);
    let req = w.put_req(&change, s1(), body_of(1, &change.registration_record));
    for len in [0usize, 1, 31, 33, 64] {
        let nonce = vec![0u8; len];
        let request = ReplaceRequest {
            nonce: &nonce,
            ..req.as_request()
        };
        let error = authorize_replacement(&w.cx(), &w.nonces, &w.state(&w.stored), &request, parse)
            .unwrap_err();
        assert_eq!(error, AuthError::Malformed(Malformed::Nonce), "nonce {len}");
    }
    for len in [0usize, 1, 63, 65, 128] {
        let proof = vec![0u8; len];
        let request = ReplaceRequest {
            proof: &proof,
            ..req.as_request()
        };
        let error = authorize_replacement(&w.cx(), &w.nonces, &w.state(&w.stored), &request, parse)
            .unwrap_err();
        assert_eq!(error, AuthError::Malformed(Malformed::Proof), "proof {len}");
    }
    // A request that is malformed does not use the nonce up.
    assert!(w.run(&req).is_ok());
}

// ------------------------------------------------------------- the profile

#[test]
fn downgrade_is_rejected_even_with_a_valid_proof() {
    let w = World::new();
    let change = w.change(PASSWORD_2);
    let on_two = StoredRecord {
        record: w.stored.record.clone(),
        ksf_profile: 2,
    };
    // The account is on profile 2 and the signed request asks for profile 1.
    let down = w.put_req(&change, s1(), body_of(1, &change.registration_record));
    assert_eq!(
        w.run_as(&on_two, &down).unwrap_err(),
        AuthError::ProfileRejected
    );
    // The same profile, and a higher one, are accepted.
    let same = w.put_req(&change, s1(), body_of(2, &change.registration_record));
    assert_eq!(w.run_as(&on_two, &same).unwrap().new.ksf_profile, 2);
    // From profile 1 a higher one is an upgrade.
    let up = w.put_req(&change, s1(), body_of(2, &change.registration_record));
    assert_eq!(w.run(&up).unwrap().new.ksf_profile, 2);
    // A recovery may not go down either: the stored profile is what counts.
    let rec = w.recovered(PASSWORD_2);
    let req = w.recover_req(&rec, s1(), body_of(1, &rec.registration_record));
    assert_eq!(
        w.run_as(&on_two, &req).unwrap_err(),
        AuthError::ProfileRejected
    );
}

#[test]
fn unknown_profile_is_rejected_with_a_valid_proof() {
    let w = World::with_profiles(ProfileRules::ferret_v1());
    let change = w.change(PASSWORD_2);
    for claimed in [0u32, 2, 9, 255, 256, u32::MAX] {
        let req = w.put_req(&change, s1(), body_of(claimed, &change.registration_record));
        assert_eq!(
            w.run(&req).unwrap_err(),
            AuthError::ProfileRejected,
            "profile {claimed}"
        );
    }
    let req = w.put_req(&change, s1(), body_of(1, &change.registration_record));
    assert!(w.run(&req).is_ok());
}

// ------------------------------------------------------------- the record

#[test]
fn record_is_only_taken_from_the_proven_bytes() {
    let w = World::new();
    let change = w.change(PASSWORD_2);
    let body = body_of(1, &change.registration_record);

    // The parser gets exactly the body the proof covers.
    let seen = Mutex::new(Vec::new());
    let req = w.put_req(&change, s1(), body.clone());
    authorize_replacement(
        &w.cx(),
        &w.nonces,
        &w.state(&w.stored),
        &req.as_request(),
        spy(&seen),
    )
    .unwrap();
    assert_eq!(*seen.lock().unwrap(), vec![body.clone()]);

    // A body that was changed after signing is stopped by the proof before
    // the parser is called.
    let seen = Mutex::new(Vec::new());
    let mut req = w.put_req(&change, s1(), body);
    flip(&mut req.body, 10);
    let error = authorize_replacement(
        &w.cx(),
        &w.nonces,
        &w.state(&w.stored),
        &req.as_request(),
        spy(&seen),
    )
    .unwrap_err();
    assert_eq!(error, denied(DenyReason::ProofInvalid));
    assert!(seen.lock().unwrap().is_empty());
}

#[test]
fn record_in_body_is_validated() {
    let w = World::new();
    let change = w.change(PASSWORD_2);
    let good = change.registration_record.clone();
    let mut bad_key = good.clone();
    bad_key[..32].fill(0xff);
    let mut trailing = good.clone();
    trailing.push(0);
    for (name, record) in [
        ("191 bytes", good[..191].to_vec()),
        ("empty", Vec::new()),
        ("invalid key", bad_key),
        ("trailing byte", trailing),
    ] {
        // The proof is valid; the record is not.
        let req = w.put_req(&change, s1(), body_of(1, &record));
        assert_eq!(
            w.run(&req).unwrap_err(),
            AuthError::Malformed(Malformed::RegistrationRecord),
            "{name}"
        );
    }
    // A body the parser cannot read is the parser's error.
    let req = w.put_req(&change, s1(), vec![0, 0]);
    assert_eq!(
        w.run(&req).unwrap_err(),
        AuthError::Malformed(Malformed::RegistrationRecord)
    );
}

#[test]
fn permit_carries_the_body_hash() {
    let w = World::new();
    let change = w.change(PASSWORD_2);
    let body = body_of(1, &change.registration_record);
    let req = w.put_req(&change, s1(), body.clone());
    let permit = w.run(&req).unwrap();
    let expected: [u8; 32] = Sha256::digest(&body).into();
    assert_eq!(permit.body_sha256, expected);
}

// ------------------------------------------------------------ no work done

/// Every way a request can fail before the proof is accepted.
fn unproven(w: &World) -> Vec<(&'static str, Req, AuthError)> {
    let change = w.change(PASSWORD_2);
    let body = body_of(1, &change.registration_record);
    let good = w.put_req(&change, s1(), body.clone());
    let mut cases = Vec::new();

    let mut bad_proof = w.put_req(&change, s1(), body.clone());
    flip(&mut bad_proof.proof, 5);
    cases.push(("bad proof", bad_proof, denied(DenyReason::ProofInvalid)));

    let mut bad_body = w.put_req(&change, s1(), body.clone());
    flip(&mut bad_body.body, 7);
    cases.push(("bad body", bad_body, denied(DenyReason::ProofInvalid)));

    let other_session = Req {
        session: session(0xB2),
        ..w.put_req(&change, s1(), body.clone())
    };
    cases.push((
        "other session",
        other_session,
        denied(DenyReason::NonceUnknown),
    ));

    let never = Req {
        nonce: [0x77; 32],
        ..w.put_req(&change, s1(), body.clone())
    };
    cases.push(("never issued", never, denied(DenyReason::NonceUnknown)));

    let used = good.clone();
    w.run(&used).unwrap();
    cases.push(("used", used, denied(DenyReason::NonceUnknown)));

    let mut forbidden = w.put_req(&change, s1(), body.clone());
    forbidden.scope = SessionScope::Pending2fa;
    cases.push(("scope", forbidden, denied(DenyReason::ScopeForbids)));

    let mut short = w.put_req(&change, s1(), body);
    short.proof = [0; 64];
    cases.push(("zero proof", short, denied(DenyReason::ProofInvalid)));
    cases
}

#[test]
fn unproven_requests_never_call_the_parser() {
    let w = World::new();
    let seen = Mutex::new(Vec::new());
    for (name, req, expected) in unproven(&w) {
        let error = authorize_replacement(
            &w.cx(),
            &w.nonces,
            &w.state(&w.stored),
            &req.as_request(),
            spy(&seen),
        )
        .unwrap_err();
        assert_eq!(error, expected, "{name}");
    }
    // Wrong lengths, an expired nonce and a refused caller as well.
    let change = w.change(PASSWORD_2);
    let req = w.put_req(&change, s1(), body_of(1, &change.registration_record));
    for (nonce_len, proof_len) in [(31usize, 64usize), (32, 63)] {
        let (nonce, proof) = (vec![0u8; nonce_len], vec![0u8; proof_len]);
        let request = ReplaceRequest {
            nonce: &nonce,
            proof: &proof,
            ..req.as_request()
        };
        authorize_replacement(
            &w.cx(),
            &w.nonces,
            &w.state(&w.stored),
            &request,
            spy(&seen),
        )
        .unwrap_err();
    }
    w.f.clock.set(LoginFixture::START + 300);
    authorize_replacement(
        &w.cx(),
        &w.nonces,
        &w.state(&w.stored),
        &req.as_request(),
        spy(&seen),
    )
    .unwrap_err();
    w.f.clock.set(LoginFixture::START);
    assert!(seen.lock().unwrap().is_empty());

    // Control: the same spy is called for a request that holds.
    let req = w.put_req(&change, s1(), body_of(1, &change.registration_record));
    authorize_replacement(
        &w.cx(),
        &w.nonces,
        &w.state(&w.stored),
        &req.as_request(),
        spy(&seen),
    )
    .unwrap();
    assert_eq!(seen.lock().unwrap().len(), 1);
}

#[test]
fn every_refusal_is_reported_to_the_throttle_as_a_failure() {
    let w = World::new();
    for (name, req, _) in unproven(&w) {
        // A scope refusal is decided before the limiter is asked.
        let scope = name == "scope";
        w.f.throttle.clear();
        w.run(&req).unwrap_err();
        let calls = w.f.throttle.calls();
        if scope {
            assert!(calls.is_empty(), "{name}");
            continue;
        }
        assert_eq!(calls.len(), 2, "{name}");
        assert!(matches!(
            calls.first(),
            Some(ThrottleCall::Admit {
                stage: Stage::Replace,
                ..
            })
        ));
        assert!(matches!(
            calls.last(),
            Some(ThrottleCall::Record {
                stage: Stage::Replace,
                outcome: Outcome::Failure,
                ..
            })
        ));
    }
}

#[test]
fn throttled_replace_does_no_work() {
    let w = World::new();
    let change = w.change(PASSWORD_2);
    let req = w.put_req(&change, s1(), body_of(1, &change.registration_record));
    let before = w.nonces.len();
    w.f.throttle
        .refuse_with(Some(ferret_server_auth::throttle::RetryAfter::new(9)));
    w.f.throttle.clear();
    let seen = Mutex::new(Vec::new());
    let error = authorize_replacement(
        &w.cx(),
        &w.nonces,
        &w.state(&w.stored),
        &req.as_request(),
        spy(&seen),
    )
    .unwrap_err();
    assert_eq!(
        error,
        AuthError::Throttled {
            retry_after_secs: 9
        }
    );
    // One call to the limiter, nothing recorded, nothing consumed, no parse.
    assert_eq!(w.f.throttle.calls().len(), 1);
    assert_eq!(w.nonces.len(), before);
    assert!(seen.lock().unwrap().is_empty());
    // The nonce is still good once the limiter lets the caller through.
    w.f.throttle.refuse_with(None);
    assert!(w.run(&req).is_ok());
}

/// A nonce store that logs the calls made to it, in order, into one list
/// that the throttle writes to as well.
struct LoggingStore<'a> {
    log: &'a Mutex<Vec<&'static str>>,
    inner: &'a InMemoryChallengeStore,
}

impl ChallengeStore for LoggingStore<'_> {
    fn put(&self, key: ChallengeKey, expires_at: u64, now: u64) -> Result<(), StoreError> {
        self.log.lock().unwrap().push("put");
        self.inner.put(key, expires_at, now)
    }

    fn consume(&self, key: &ChallengeKey, now: u64) -> Result<ConsumeOutcome, StoreError> {
        self.log.lock().unwrap().push("consume");
        self.inner.consume(key, now)
    }

    fn purge_expired(&self, now: u64) -> Result<usize, StoreError> {
        self.inner.purge_expired(now)
    }
}

struct LoggingThrottle<'a> {
    log: &'a Mutex<Vec<&'static str>>,
}

impl ferret_server_auth::Throttle for LoggingThrottle<'_> {
    fn admit(
        &self,
        _: Stage,
        _: &[ThrottleKey],
        _: u64,
    ) -> Result<(), ferret_server_auth::throttle::RetryAfter> {
        self.log.lock().unwrap().push("admit");
        Ok(())
    }

    fn record(&self, _: Stage, _: &[ThrottleKey], _: Outcome, _: u64) {
        self.log.lock().unwrap().push("record");
    }
}

#[test]
fn admit_is_the_first_effect_of_every_entry_point() {
    let w = World::new();
    let change = w.change(PASSWORD_2);
    let req = w.put_req(&change, s1(), body_of(1, &change.registration_record));
    let log = Mutex::new(Vec::new());
    let throttle = LoggingThrottle { log: &log };
    let store = LoggingStore {
        log: &log,
        inner: &w.nonces,
    };
    let cx = AuthContext::new(
        &w.f.keys,
        &w.f.prelogin,
        &w.f.seal,
        &w.f.clock,
        &throttle,
        &w.f.policy,
        &w.profiles,
    );

    authorize_replacement(&cx, &store, &w.state(&w.stored), &req.as_request(), parse).unwrap();
    assert_eq!(*log.lock().unwrap(), ["admit", "consume", "record"]);
    log.lock().unwrap().clear();

    issue_challenge(
        &cx,
        &store,
        &mut w.seed("nonce"),
        &LoginFixture::caller(),
        SessionScope::Full,
        &s1(),
    )
    .unwrap();
    assert_eq!(*log.lock().unwrap(), ["admit", "put", "record"]);
}

// ------------------------------------------------------------------- scope

#[test]
fn the_scope_of_the_session_decides_before_anything_else() {
    let w = World::new();
    let change = w.change(PASSWORD_2);
    let rec = w.recovered(PASSWORD_2);
    let put_body = body_of(1, &change.registration_record);
    let rec_body = body_of(1, &rec.registration_record);
    for scope in [
        SessionScope::Pending2fa,
        SessionScope::Unverified,
        SessionScope::AccountReset,
    ] {
        let mut req = w.put_req(&change, s1(), put_body.clone());
        req.scope = scope;
        let before = w.nonces.len();
        assert_eq!(w.run(&req).unwrap_err(), denied(DenyReason::ScopeForbids));
        // The nonce is not used up by a refused scope.
        assert_eq!(w.nonces.len(), before, "{scope:?}");
        req.scope = SessionScope::Full;
        assert!(w.run(&req).is_ok(), "{scope:?}");
    }
    for scope in [SessionScope::Pending2fa, SessionScope::Unverified] {
        let mut req = w.recover_req(&rec, s1(), rec_body.clone());
        req.scope = scope;
        assert_eq!(w.run(&req).unwrap_err(), denied(DenyReason::ScopeForbids));
    }
    // The reset account may recover, and nothing else.
    let req = w.recover_req(&rec, s1(), rec_body);
    assert!(w.run(&req).is_ok());
}

#[test]
fn only_sessions_that_may_recover_or_sign_get_a_nonce() {
    let w = World::new();
    for (scope, allowed) in [
        (SessionScope::Full, true),
        (SessionScope::AccountReset, true),
        (SessionScope::Pending2fa, false),
        (SessionScope::Unverified, false),
    ] {
        w.f.throttle.clear();
        let result = issue_challenge(
            &w.cx(),
            &w.nonces,
            &mut w.seed("scope"),
            &LoginFixture::caller(),
            scope,
            &s1(),
        );
        assert_eq!(result.is_ok(), allowed, "{scope:?}");
        if !allowed {
            assert_eq!(result.unwrap_err(), denied(DenyReason::ScopeForbids));
            assert!(w.f.throttle.calls().is_empty());
        }
    }
}

// --------------------------------------------------------------- challenge

/// A nonce store that remembers every key it was given.
struct RecordingStore {
    keys: Mutex<Vec<ChallengeKey>>,
    inner: InMemoryChallengeStore,
}

impl ChallengeStore for RecordingStore {
    fn put(&self, key: ChallengeKey, expires_at: u64, now: u64) -> Result<(), StoreError> {
        self.keys.lock().unwrap().push(key);
        self.inner.put(key, expires_at, now)
    }

    fn consume(&self, key: &ChallengeKey, now: u64) -> Result<ConsumeOutcome, StoreError> {
        self.inner.consume(key, now)
    }

    fn purge_expired(&self, now: u64) -> Result<usize, StoreError> {
        self.inner.purge_expired(now)
    }
}

#[test]
fn issue_challenge_binds_to_the_session_hash() {
    let w = World::new();
    let store = RecordingStore {
        keys: Mutex::new(Vec::new()),
        inner: InMemoryChallengeStore::new(),
    };
    let session = s1();
    let challenge = issue_challenge(
        &w.cx(),
        &store,
        &mut TestRng::new(b"nonce"),
        &LoginFixture::caller(),
        SessionScope::Full,
        &session,
    )
    .unwrap();
    assert_eq!(challenge.expires_in, 300);
    assert_eq!(challenge.nonce.len(), 32);

    // The store saw one key: the hash of session binding and nonce. It never
    // saw the nonce.
    let keys = store.keys.lock().unwrap();
    assert_eq!(keys.len(), 1);
    let mut hash = Sha256::new();
    hash.update(session.0);
    hash.update(challenge.nonce);
    let expected: [u8; 32] = hash.finalize().into();
    assert_eq!(keys[0].as_bytes(), &expected);
    assert_ne!(keys[0].as_bytes(), &challenge.nonce);
    assert!(
        !keys[0]
            .as_bytes()
            .windows(8)
            .any(|window| challenge.nonce.windows(8).any(|n| n == window))
    );
    // The nonce is the 32 bytes the random source gave.
    let mut rng = TestRng::new(b"nonce");
    let mut drawn = [0u8; 32];
    ferret_core::SecureRng::fill(&mut rng, &mut drawn);
    assert_eq!(challenge.nonce, drawn);
    // The throttle was asked for a challenge, by address.
    let calls = w.f.throttle.calls();
    assert!(matches!(
        calls.last(),
        Some(ThrottleCall::Record {
            stage: Stage::Challenge,
            outcome: Outcome::Success,
            ..
        })
    ));
}

#[test]
fn debug_never_shows_content() {
    let w = World::new();
    let change = w.change(PASSWORD_2);
    let req = w.put_req(&change, s1(), body_of(1, &change.registration_record));
    let permit = w.run(&req).unwrap();
    let shown = format!(
        "{:?} {:?} {:?} {:?}",
        permit,
        req.as_request(),
        w.state(&w.stored),
        parse(&req.body).unwrap(),
    );
    assert_eq!(
        shown,
        "ReplacePermit([redacted]) ReplaceRequest([redacted]) AccountAuthState([redacted]) ReplaceFields([redacted])"
    );
}
