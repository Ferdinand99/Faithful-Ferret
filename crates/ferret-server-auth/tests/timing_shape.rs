//! What a caller or an observer of the server's side effects can see of
//! `login_start` and `login_finish`: the calls to the throttle, the writes to
//! the store and the draws from the random source. For a known account, an
//! unknown name and a disabled account they must have the same shape.
//!
//! This is a check of the shape of the work, not a measurement of time: the
//! steps are the same, and the selection between the real and the made-up
//! record is the branch-free one of the constant-time analysis
//! (`scripts/lanbox-ct.sh`). A clock does not decide anything here.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::arithmetic_side_effects
)]

use std::sync::Mutex;

use ferret_core::{SecureRng, TestRng};
use ferret_server_auth::testing::{FIXTURE_PASSWORD, LoginFixture};
use ferret_server_auth::{
    AccountLookup, AuthError, CredentialId, DenyReason, InMemoryLoginStateStore, InternalKind,
    LoginFinishRequest, LoginPurpose, LoginStartRequest, LoginStateStore, Malformed, RetryAfter,
    SealedState, SessionBinding, StateKey, StoreError, ThrottleCall, ThrottleKey, login_finish,
    login_start,
};

/// One effect on the outside of the library.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Effect {
    Draw(usize),
    Put { sealed_len: usize, lifetime: u64 },
    Take,
}

struct Effects(Mutex<Vec<Effect>>);

impl Effects {
    fn push(&self, effect: Effect) {
        self.0.lock().unwrap().push(effect);
    }

    fn take(&self) -> Vec<Effect> {
        std::mem::take(&mut *self.0.lock().unwrap())
    }
}

struct SeenStore<'a> {
    effects: &'a Effects,
    inner: InMemoryLoginStateStore,
}

impl LoginStateStore for SeenStore<'_> {
    fn put(
        &self,
        key: StateKey,
        sealed: SealedState,
        expires_at: u64,
        now: u64,
    ) -> Result<(), StoreError> {
        self.effects.push(Effect::Put {
            sealed_len: sealed.as_bytes().len(),
            lifetime: expires_at - now,
        });
        self.inner.put(key, sealed, expires_at, now)
    }

    fn take(&self, key: &StateKey, now: u64) -> Result<Option<SealedState>, StoreError> {
        self.effects.push(Effect::Take);
        self.inner.take(key, now)
    }

    fn purge_expired(&self, now: u64) -> Result<usize, StoreError> {
        self.inner.purge_expired(now)
    }
}

struct SeenRng<'a> {
    effects: &'a Effects,
    inner: TestRng,
}

impl SecureRng for SeenRng<'_> {
    fn fill(&mut self, dest: &mut [u8]) {
        self.effects.push(Effect::Draw(dest.len()));
        self.inner.fill(dest);
    }
}

/// The kinds of a list of keys, without the identifiers and addresses in
/// them: the same kinds in the same order are the same shape.
fn kinds(keys: &[ThrottleKey]) -> String {
    keys.iter()
        .map(|key| match key {
            ThrottleKey::Ip(_) => "Ip",
            ThrottleKey::AccountIp(..) => "AccountIp",
            ThrottleKey::Account(_) => "Account",
            ThrottleKey::UnknownAddress => "UnknownAddress",
        })
        .collect::<Vec<_>>()
        .join("+")
}

/// The calls to the throttle with the identifiers left out: their number,
/// order, stage, number of keys and outcome.
fn throttle_shape(f: &LoginFixture) -> Vec<String> {
    f.throttle
        .calls()
        .iter()
        .map(|call| match call {
            ThrottleCall::Admit { stage, keys, now } => {
                format!("admit {stage:?} {} at {now}", kinds(keys))
            }
            ThrottleCall::Record {
                stage,
                keys,
                outcome,
                now,
            } => format!("record {stage:?} {} {outcome:?} at {now}", kinds(keys)),
        })
        .collect()
}

fn lookups(f: &LoginFixture) -> [AccountLookup<'_>; 3] {
    [f.active(), AccountLookup::Unknown, AccountLookup::Disabled]
}

#[test]
fn login_start_has_the_same_outside_effects_for_every_lookup() {
    let f = LoginFixture::new();
    let (ke1, _) = f.client_start(FIXTURE_PASSWORD, "client");
    let mut shapes = Vec::new();
    for lookup in lookups(&f) {
        let effects = Effects(Mutex::new(Vec::new()));
        let store = SeenStore {
            effects: &effects,
            inner: InMemoryLoginStateStore::new(),
        };
        let mut rng = SeenRng {
            effects: &effects,
            inner: TestRng::new(b"shape"),
        };
        f.throttle.clear();
        let request = LoginStartRequest {
            caller: LoginFixture::caller(),
            name: &f.name,
            credential: f.credential,
            lookup,
            purpose: LoginPurpose::Login,
            session_scope: None,
            ke1: &ke1,
        };
        let response = login_start(&f.cx(), &store, &mut rng, &request).unwrap();
        assert_eq!(response.ke2.len(), 320);
        shapes.push((effects.take(), throttle_shape(&f), response.ke2.len()));
    }
    let (first, rest) = shapes.split_first().unwrap();
    // The draws are the documented six, the write is one state of the same
    // size and lifetime, and the throttle sees one admit and one outcome.
    assert_eq!(first.0.len(), 7);
    assert_eq!(first.1.len(), 2);
    for other in rest {
        assert_eq!(other, first);
    }
}

#[test]
fn a_bad_ke1_has_the_same_outside_effects_for_every_lookup() {
    let f = LoginFixture::new();
    let mut shapes = Vec::new();
    for lookup in lookups(&f) {
        let effects = Effects(Mutex::new(Vec::new()));
        let store = SeenStore {
            effects: &effects,
            inner: InMemoryLoginStateStore::new(),
        };
        let mut rng = SeenRng {
            effects: &effects,
            inner: TestRng::new(b"shape"),
        };
        f.throttle.clear();
        let request = LoginStartRequest {
            caller: LoginFixture::caller(),
            name: &f.name,
            credential: f.credential,
            lookup,
            purpose: LoginPurpose::Login,
            session_scope: None,
            ke1: &[1u8; 96],
        };
        let error = login_start(&f.cx(), &store, &mut rng, &request).unwrap_err();
        assert_eq!(error, AuthError::Malformed(Malformed::Ke1));
        shapes.push((effects.take(), throttle_shape(&f)));
    }
    // No draw and no write, one admit and one failure.
    assert!(shapes[0].0.is_empty());
    assert_eq!(shapes[0].1.len(), 2);
    assert_eq!(shapes[1], shapes[0]);
    assert_eq!(shapes[2], shapes[0]);
}

#[test]
fn login_finish_has_the_same_outside_effects_for_every_lookup() {
    let f = LoginFixture::new();
    let (ke1, _) = f.client_start(FIXTURE_PASSWORD, "client");
    let mut shapes = Vec::new();
    for lookup in lookups(&f) {
        let effects = Effects(Mutex::new(Vec::new()));
        let store = SeenStore {
            effects: &effects,
            inner: InMemoryLoginStateStore::new(),
        };
        let mut rng = SeenRng {
            effects: &effects,
            inner: TestRng::new(b"shape"),
        };
        let request = LoginStartRequest {
            caller: LoginFixture::caller(),
            name: &f.name,
            credential: f.credential,
            lookup,
            purpose: LoginPurpose::Login,
            session_scope: None,
            ke1: &ke1,
        };
        let response = login_start(&f.cx(), &store, &mut rng, &request).unwrap();
        effects.take();
        f.throttle.clear();
        let hex = response.login_id.to_hex();
        // A guess at KE3 is what an attacker sends to every kind of account.
        let finish = LoginFinishRequest {
            caller: LoginFixture::caller(),
            login_id: hex.as_bytes(),
            ke3: &[5u8; 64],
            current_session: None,
        };
        let error = login_finish(&f.cx(), &store, &finish).unwrap_err();
        assert_eq!(error, AuthError::Denied(DenyReason::Ke3));
        assert_eq!(error.public_code(), "denied");
        shapes.push((effects.take(), throttle_shape(&f)));
        // The state is gone whatever the account.
        assert!(store.inner.is_empty());
    }
    assert_eq!(shapes[0].0, [Effect::Take]);
    assert_eq!(
        shapes[0].1,
        [
            "admit LoginFinish AccountIp+Account at 1700000000",
            "record LoginFinish AccountIp+Account Failure at 1700000000"
        ]
    );
    assert_eq!(shapes[1], shapes[0]);
    assert_eq!(shapes[2], shapes[0]);
}

#[test]
fn the_documented_draws_and_lifetime() {
    let f = LoginFixture::new();
    let (ke1, _) = f.client_start(FIXTURE_PASSWORD, "client");
    let effects = Effects(Mutex::new(Vec::new()));
    let store = SeenStore {
        effects: &effects,
        inner: InMemoryLoginStateStore::new(),
    };
    let mut rng = SeenRng {
        effects: &effects,
        inner: TestRng::new(b"shape"),
    };
    let request = LoginStartRequest {
        caller: LoginFixture::caller(),
        name: &f.name,
        credential: f.credential,
        lookup: f.active(),
        purpose: LoginPurpose::Login,
        session_scope: None,
        ke1: &ke1,
    };
    login_start(&f.cx(), &store, &mut rng, &request).unwrap();
    assert_eq!(
        effects.take(),
        [
            Effect::Draw(64),
            Effect::Draw(32),
            Effect::Draw(32),
            Effect::Draw(32),
            Effect::Draw(16),
            Effect::Draw(24),
            Effect::Put {
                // version 1 + nonce 24 + plaintext 203 + tag 16
                sealed_len: 244,
                lifetime: 60,
            },
        ]
    );
}

/// A store whose `take` fails, as a database that is down would.
struct FailingTake;

impl LoginStateStore for FailingTake {
    fn put(&self, _: StateKey, _: SealedState, _: u64, _: u64) -> Result<(), StoreError> {
        Ok(())
    }

    fn take(&self, _: &StateKey, _: u64) -> Result<Option<SealedState>, StoreError> {
        Err(StoreError::Backend)
    }

    fn purge_expired(&self, _: u64) -> Result<usize, StoreError> {
        Ok(0)
    }
}

const ADDRESS_ONLY: [&str; 2] = [
    "admit LoginFinish Ip at 1700000000",
    "record LoginFinish Ip Failure at 1700000000",
];

fn finish_with<S: LoginStateStore>(
    f: &LoginFixture,
    store: &S,
    login_id: &[u8],
    ke3: &[u8],
    current_session: Option<(SessionBinding, CredentialId)>,
) -> (AuthError, Vec<String>) {
    f.throttle.clear();
    let request = LoginFinishRequest {
        caller: LoginFixture::caller(),
        login_id,
        ke3,
        current_session,
    };
    let error = login_finish(&f.cx(), store, &request).unwrap_err();
    (error, throttle_shape(f))
}

/// A finish that is refused before the account is known (a login id or KE3
/// that is not well formed, no state, a store that fails, a state that is for
/// another purpose, session or account) is asked of the limiter with the
/// address alone, and told it failed. The same kinds of key for every one of
/// them, so what is charged does not tell a real account from a made-up one.
#[test]
fn a_finish_refused_before_the_account_is_known_charges_the_address_alone() {
    let f = LoginFixture::new();
    let (ke1, _) = f.client_start(FIXTURE_PASSWORD, "client");
    let session = SessionBinding([0x11; 32]);
    let other = CredentialId::from_bytes([0x99; 16]);
    for lookup in lookups(&f) {
        let store = InMemoryLoginStateStore::new();
        let seeds = std::cell::Cell::new(0u32);
        let start = |purpose| {
            seeds.set(seeds.get() + 1);
            let request = LoginStartRequest {
                caller: LoginFixture::caller(),
                name: &f.name,
                credential: f.credential,
                lookup,
                purpose,
                session_scope: Some(ferret_server_auth::SessionScope::Full),
                ke1: &ke1,
            };
            let mut rng = TestRng::new(format!("kinds {}", seeds.get()).as_bytes());
            login_start(&f.cx(), &store, &mut rng, &request).unwrap()
        };

        // A login id that is not hex, and a KE3 of the wrong length.
        let (error, shape) = finish_with(&f, &store, b"not a login id", &[5u8; 64], None);
        assert_eq!(error, AuthError::Malformed(Malformed::LoginId));
        assert_eq!(shape, ADDRESS_ONLY);
        let real = start(LoginPurpose::Login).login_id.to_hex();
        let (error, shape) = finish_with(&f, &store, real.as_bytes(), &[5u8; 63], None);
        assert_eq!(error, AuthError::Malformed(Malformed::Ke3));
        assert_eq!(shape, ADDRESS_ONLY);

        // No state under that id (it was never made, or it was used).
        let (error, shape) = finish_with(&f, &store, &[b'0'; 32], &[5u8; 64], None);
        assert_eq!(error, AuthError::Denied(DenyReason::StateMissing));
        assert_eq!(shape, ADDRESS_ONLY);

        // A store that fails: an internal error, charged to the address.
        let (error, shape) = finish_with(&f, &FailingTake, real.as_bytes(), &[5u8; 64], None);
        assert_eq!(error, AuthError::Internal(InternalKind::Storage));
        assert_eq!(shape, ADDRESS_ONLY);

        // A state for a login, asked for as a re-authentication, and one for
        // the session of another request.
        let (error, shape) = finish_with(
            &f,
            &store,
            real.as_bytes(),
            &[5u8; 64],
            Some((session, f.credential)),
        );
        assert_eq!(error, AuthError::Denied(DenyReason::StateInvalid));
        assert_eq!(shape, ADDRESS_ONLY);
        let reauth = |account| LoginPurpose::Reauth { session, account };
        let id = start(reauth(f.credential)).login_id.to_hex();
        let wrong_session = Some((SessionBinding([0x22; 32]), f.credential));
        let (error, shape) = finish_with(&f, &store, id.as_bytes(), &[5u8; 64], wrong_session);
        assert_eq!(error, AuthError::Denied(DenyReason::StateInvalid));
        assert_eq!(shape, ADDRESS_ONLY);

        // A re-authentication in the right session whose login was for
        // another account than the one of the session: the compare of the
        // credential in `login_finish`.
        let id = start(reauth(other)).login_id.to_hex();
        let (error, shape) = finish_with(
            &f,
            &store,
            id.as_bytes(),
            &[5u8; 64],
            Some((session, other)),
        );
        assert_eq!(error, AuthError::Denied(DenyReason::StateInvalid));
        assert_eq!(shape, ADDRESS_ONLY);
    }
}

/// A limiter that refuses ends each of these before any further work, and the
/// refusal reaches the caller whatever the error would have been.
#[test]
fn a_refusing_limiter_decides_a_finish_whose_store_fails() {
    let f = LoginFixture::new();
    f.throttle.refuse_with(Some(RetryAfter::new(3)));
    let request = LoginFinishRequest {
        caller: LoginFixture::caller(),
        login_id: &[b'0'; 32],
        ke3: &[5u8; 64],
        current_session: None,
    };
    let error = login_finish(&f.cx(), &FailingTake, &request).unwrap_err();
    assert_eq!(
        error,
        AuthError::Throttled {
            retry_after_secs: 3
        }
    );
    // One question to the limiter with the address alone, and no outcome.
    assert_eq!(throttle_shape(&f), ["admit LoginFinish Ip at 1700000000"]);
}
