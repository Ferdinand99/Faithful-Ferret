//! Helpers for tests of this crate and of the crates that build on it. Behind
//! the `test-support` feature, which is never part of a release build.
//!
//! * [`conformance`] is the set of checks every [`LoginStateStore`] must
//!   pass. The memory store runs it in this crate; the database store of the
//!   next layer runs the same checks.
//! * [`challenge_conformance`] is the same set of checks for a
//!   [`ChallengeStore`](crate::ChallengeStore).
//! * [`state_plain_wipe_probe`] lets a test crate look at the memory of a
//!   sealed state's content before and after it is dropped.
//! * [`LoginFixture`] is a server with one registered account and the pieces
//!   to run the client of `ferret-core` against it. [`login_start_with_context`]
//!   runs the first step with another OPAQUE context or other identities than
//!   Ferret's, to show that such a server cannot authenticate.
//!
//! This is test tooling, not production code, so the strict production lints
//! are relaxed here.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::arithmetic_side_effects
)]

use std::collections::HashSet;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Barrier, Mutex};

use ferret_core::secret::WipePhase;
use zeroize::Zeroizing;

use crate::state::{LoginPurpose, SERVER_LOGIN_LEN, StatePlain};
use crate::{CredentialId, LoginId, LoginStateStore, STATE_TTL_SECS, SealedState, StateKey};
use crate::{SessionBinding, StoreError};

/// Room enough that no check but the capacity checks reaches the limit.
const ROOMY: usize = 1_000;

/// The key of the n-th test state: the store key of a login id made from `n`.
pub fn state_key(n: u32) -> StateKey {
    LoginId::parse(format!("{n:032x}").as_bytes())
        .unwrap()
        .store_key()
}

/// A distinct blob for the n-th test state, as long as a real one.
pub fn sealed_blob(n: u32) -> SealedState {
    SealedState::from_bytes(n.to_be_bytes().repeat(57))
}

fn key(n: u32) -> StateKey {
    state_key(n)
}

fn blob(n: u32) -> SealedState {
    sealed_blob(n)
}

/// The seconds a state made at `now` is valid.
fn expiry(now: u64) -> u64 {
    now + STATE_TTL_SECS
}

/// Runs every check on stores made by `make`. `make(capacity)` must give a
/// fresh, empty store that holds at most `capacity` states.
pub fn conformance<S: LoginStateStore>(make: impl Fn(usize) -> S) {
    put_then_take_returns_once(&make);
    take_unknown_key_is_none(&make);
    expiry_boundary(&make);
    expired_entries_are_removed_by_take_and_purge(&make);
    put_same_key_twice_is_collision(&make);
    put_of_an_expired_entry_is_refused(&make);
    capacity_evicts_oldest_first(&make);
    concurrent_take_yields_exactly_one(&make);
    concurrent_put_and_take_never_duplicate(&make);
    concurrent_put_respects_capacity(&make);
}

/// A state is returned once; the second `take` finds nothing.
pub fn put_then_take_returns_once<S: LoginStateStore>(make: impl Fn(usize) -> S) {
    let store = make(ROOMY);
    store.put(key(1), blob(1), expiry(1_000), 1_000).unwrap();
    store.put(key(2), blob(2), expiry(1_000), 1_000).unwrap();
    let first = store.take(&key(1), 1_001).unwrap().unwrap();
    assert_eq!(first.as_bytes(), blob(1).as_bytes());
    assert!(store.take(&key(1), 1_001).unwrap().is_none());
    // Only that key was taken.
    let second = store.take(&key(2), 1_001).unwrap().unwrap();
    assert_eq!(second.as_bytes(), blob(2).as_bytes());
    // The key is free again.
    store.put(key(1), blob(3), expiry(1_002), 1_002).unwrap();
    let again = store.take(&key(1), 1_003).unwrap().unwrap();
    assert_eq!(again.as_bytes(), blob(3).as_bytes());
}

/// A key that was never stored gives `None`, not an error.
pub fn take_unknown_key_is_none<S: LoginStateStore>(make: impl Fn(usize) -> S) {
    let store = make(ROOMY);
    assert!(store.take(&key(9), 1_000).unwrap().is_none());
    store.put(key(1), blob(1), expiry(1_000), 1_000).unwrap();
    assert!(store.take(&key(9), 1_000).unwrap().is_none());
}

/// With a lifetime of 60 seconds a state is valid in the seconds `t` to
/// `t + 59`, and gone from `t + 60`.
pub fn expiry_boundary<S: LoginStateStore>(make: impl Fn(usize) -> S) {
    let expires_at = expiry(1_000);
    assert_eq!(expires_at, 1_060);
    for (now, valid) in [
        (1_000, true),
        (1_059, true),
        (1_060, false),
        (1_061, false),
        (u64::MAX, false),
    ] {
        let store = make(ROOMY);
        store.put(key(1), blob(1), expires_at, 1_000).unwrap();
        let got = store.take(&key(1), now).unwrap();
        assert_eq!(got.is_some(), valid, "take at {now}");
    }
}

/// An expired state is removed by `take`, and the rest by `purge_expired`,
/// which counts only what it removes. A live state is left alone.
pub fn expired_entries_are_removed_by_take_and_purge<S: LoginStateStore>(
    make: impl Fn(usize) -> S,
) {
    let store = make(ROOMY);
    assert_eq!(store.purge_expired(0).unwrap(), 0);
    store.put(key(1), blob(1), 100, 50).unwrap();
    store.put(key(2), blob(2), 100, 50).unwrap();
    store.put(key(3), blob(3), 200, 50).unwrap();
    store.put(key(4), blob(4), 1_000, 50).unwrap();
    // `take` of an expired state finds nothing and removes it ...
    assert!(store.take(&key(1), 100).unwrap().is_none());
    // ... so the purge counts only the other expired one.
    assert_eq!(store.purge_expired(100).unwrap(), 1);
    assert!(store.take(&key(2), 100).unwrap().is_none());
    // The live ones are still there; the one that expires at 200 is not
    // removed at 150.
    assert_eq!(store.purge_expired(150).unwrap(), 0);
    assert!(store.take(&key(3), 150).unwrap().is_some());
    assert_eq!(store.purge_expired(999).unwrap(), 0);
    assert_eq!(store.purge_expired(1_000).unwrap(), 1);
    assert!(store.take(&key(4), 1_000).unwrap().is_none());
    // A removed key can be used again.
    store.put(key(1), blob(5), 300, 200).unwrap();
    assert!(store.take(&key(1), 250).unwrap().is_some());
}

/// A live state is never overwritten; the first one stays.
pub fn put_same_key_twice_is_collision<S: LoginStateStore>(make: impl Fn(usize) -> S) {
    let store = make(ROOMY);
    store.put(key(1), blob(1), expiry(1_000), 1_000).unwrap();
    assert_eq!(
        store.put(key(1), blob(2), expiry(1_010), 1_010),
        Err(StoreError::Collision)
    );
    let got = store.take(&key(1), 1_011).unwrap().unwrap();
    assert_eq!(got.as_bytes(), blob(1).as_bytes());
    // An expired state does not block its key.
    store.put(key(2), blob(3), 1_100, 1_000).unwrap();
    store.put(key(2), blob(4), 1_300, 1_100).unwrap();
    let got = store.take(&key(2), 1_101).unwrap().unwrap();
    assert_eq!(got.as_bytes(), blob(4).as_bytes());
}

/// A state that is already expired when it is put, or a put at `u64::MAX`
/// (the reading of a failed clock), is refused with `Expired` and stores
/// nothing: it must not take a slot, push out a live state, or become valid
/// when the clock reads a normal time again.
pub fn put_of_an_expired_entry_is_refused<S: LoginStateStore>(make: impl Fn(usize) -> S) {
    let store = make(1);
    store.put(key(1), blob(1), expiry(1_000), 1_000).unwrap();
    for (expires_at, now) in [
        (1_000, 1_000),
        (999, 1_000),
        (0, 1),
        (u64::MAX, u64::MAX),
        (expiry(1_000), u64::MAX),
    ] {
        assert_eq!(
            store.put(key(2), blob(2), expires_at, now),
            Err(StoreError::Expired),
            "expires_at {expires_at}, now {now}"
        );
    }
    // Nothing was stored, and the live state was not pushed out by a refused one.
    assert!(store.take(&key(2), 1_001).unwrap().is_none());
    assert!(store.take(&key(2), 0).unwrap().is_none());
    let kept = store.take(&key(1), 1_001).unwrap().unwrap();
    assert_eq!(kept.as_bytes(), blob(1).as_bytes());
    // A state that expires one second after it is made is accepted.
    store.put(key(3), blob(3), 1_001, 1_000).unwrap();
    assert!(store.take(&key(3), 1_000).unwrap().is_some());
}

/// At the limit the oldest state is removed to make room, whatever its
/// expiry; states that were taken make room without removing others.
pub fn capacity_evicts_oldest_first<S: LoginStateStore>(make: impl Fn(usize) -> S) {
    let store = make(3);
    for n in 1..=3 {
        store.put(key(n), blob(n), expiry(1_000), 1_000).unwrap();
    }
    store.put(key(4), blob(4), expiry(1_000), 1_000).unwrap();
    assert!(store.take(&key(1), 1_001).unwrap().is_none());
    for n in 2..=4 {
        let got = store.take(&key(n), 1_001).unwrap().unwrap();
        assert_eq!(got.as_bytes(), blob(n).as_bytes());
    }

    // Taking a state frees its place; the next oldest goes first after that.
    let store = make(2);
    store.put(key(1), blob(1), expiry(1_000), 1_000).unwrap();
    store.put(key(2), blob(2), expiry(1_000), 1_000).unwrap();
    assert!(store.take(&key(1), 1_001).unwrap().is_some());
    store.put(key(3), blob(3), expiry(1_001), 1_001).unwrap();
    store.put(key(4), blob(4), expiry(1_001), 1_001).unwrap();
    assert!(store.take(&key(2), 1_002).unwrap().is_none());
    assert!(store.take(&key(3), 1_002).unwrap().is_some());
    assert!(store.take(&key(4), 1_002).unwrap().is_some());

    // The oldest goes first even if it would live longer than a newer one.
    let store = make(2);
    store.put(key(1), blob(1), 9_000, 1_000).unwrap();
    store.put(key(2), blob(2), 1_100, 1_000).unwrap();
    store.put(key(3), blob(3), 1_100, 1_000).unwrap();
    assert!(store.take(&key(1), 1_001).unwrap().is_none());
    assert!(store.take(&key(2), 1_001).unwrap().is_some());
    assert!(store.take(&key(3), 1_001).unwrap().is_some());
}

/// 32 threads take the same state at the same moment: exactly one gets it.
pub fn concurrent_take_yields_exactly_one<S: LoginStateStore>(make: impl Fn(usize) -> S) {
    const THREADS: usize = 32;
    let store = make(ROOMY);
    for round in 0..20u32 {
        store
            .put(key(round), blob(round), expiry(1_000), 1_000)
            .unwrap();
        let barrier = Barrier::new(THREADS);
        let winners = AtomicUsize::new(0);
        std::thread::scope(|scope| {
            for _ in 0..THREADS {
                scope.spawn(|| {
                    barrier.wait();
                    if let Some(got) = store.take(&key(round), 1_001).unwrap() {
                        assert_eq!(got.as_bytes(), blob(round).as_bytes());
                        winners.fetch_add(1, Ordering::SeqCst);
                    }
                });
            }
        });
        assert_eq!(winners.load(Ordering::SeqCst), 1, "round {round}");
        assert!(store.take(&key(round), 1_001).unwrap().is_none());
    }
}

/// Threads put and take the same key at the same moment. Every blob that was
/// stored is handed out exactly once, and none twice.
pub fn concurrent_put_and_take_never_duplicate<S: LoginStateStore>(make: impl Fn(usize) -> S) {
    const WRITERS: u32 = 8;
    const READERS: usize = 8;
    let store = make(ROOMY);
    for round in 0..20u32 {
        let barrier = Barrier::new(WRITERS as usize + READERS);
        let stored = AtomicUsize::new(0);
        let taken = Mutex::new(Vec::<Vec<u8>>::new());
        std::thread::scope(|scope| {
            for writer in 0..WRITERS {
                let (store, barrier, stored) = (&store, &barrier, &stored);
                scope.spawn(move || {
                    barrier.wait();
                    for attempt in 0..5u32 {
                        let n = 10_000 + round * 1_000 + writer * 10 + attempt;
                        match store.put(key(7), blob(n), expiry(1_000), 1_000) {
                            Ok(()) => {
                                stored.fetch_add(1, Ordering::SeqCst);
                            }
                            Err(StoreError::Collision) => {}
                            Err(other) => panic!("put failed with {other:?}"),
                        }
                    }
                });
            }
            for _ in 0..READERS {
                scope.spawn(|| {
                    barrier.wait();
                    for _ in 0..5 {
                        if let Some(got) = store.take(&key(7), 1_001).unwrap() {
                            taken.lock().unwrap().push(got.as_bytes().to_vec());
                        }
                    }
                });
            }
        });
        // Whatever is left is handed out once more.
        if let Some(got) = store.take(&key(7), 1_001).unwrap() {
            taken.lock().unwrap().push(got.as_bytes().to_vec());
        }
        assert!(store.take(&key(7), 1_001).unwrap().is_none());
        let taken = taken.into_inner().unwrap();
        let distinct: HashSet<&Vec<u8>> = taken.iter().collect();
        assert_eq!(distinct.len(), taken.len(), "round {round}: a blob twice");
        assert_eq!(
            taken.len(),
            stored.load(Ordering::SeqCst),
            "round {round}: a stored blob was lost"
        );
    }
}

/// Threads put different keys at a store that has room for few states, at the
/// same moment. The store never holds more than its limit, and every state it
/// still holds can be taken once.
pub fn concurrent_put_respects_capacity<S: LoginStateStore>(make: impl Fn(usize) -> S) {
    const LIMIT: usize = 10;
    const THREADS: u32 = 16;
    const EACH: u32 = 20;
    for round in 0..5u32 {
        let store = make(LIMIT);
        let barrier = Barrier::new(THREADS as usize);
        std::thread::scope(|scope| {
            for thread in 0..THREADS {
                let (store, barrier) = (&store, &barrier);
                scope.spawn(move || {
                    barrier.wait();
                    for n in 0..EACH {
                        let id = 100 + round * 1_000 + thread * EACH + n;
                        store.put(key(id), blob(id), expiry(1_000), 1_000).unwrap();
                    }
                });
            }
        });
        let mut held = 0;
        for thread in 0..THREADS {
            for n in 0..EACH {
                let id = 100 + round * 1_000 + thread * EACH + n;
                if store.take(&key(id), 1_001).unwrap().is_some() {
                    held += 1;
                }
            }
        }
        // 320 states were put and nothing was taken: exactly the limit is left.
        assert_eq!(held, LIMIT, "round {round}");
    }
}

/// Builds a sealed state's content filled with `fill`, calls
/// `reader(Before, ptr, len)` on the bytes of its `ServerLogin`, drops the
/// content in place and calls `reader(After, ptr, len)`. The allocation lives
/// until the probe returns, so the reader may look at both. The reader needs
/// `unsafe` for that, so the check lives in a test crate; this crate forbids
/// it.
pub fn state_plain_wipe_probe(fill: u8, reader: &mut dyn FnMut(WipePhase, *const u8, usize)) {
    let mut held: Vec<StatePlain> = Vec::with_capacity(1);
    held.push(StatePlain {
        credential: CredentialId::from_bytes([fill; 16]),
        purpose: LoginPurpose::Reauth {
            session: SessionBinding([fill; 32]),
            account: CredentialId::from_bytes([fill; 16]),
        },
        expires_at: 1,
        ksf_profile: 1,
        server_login: Zeroizing::new([fill; SERVER_LOGIN_LEN]),
    });
    // The address comes from the vector's own buffer pointer plus the offset
    // of the field, with no reference to the element in between.
    let offset = core::mem::offset_of!(StatePlain, server_login);
    let ptr = held
        .as_mut_ptr()
        .cast::<u8>()
        .wrapping_add(offset)
        .cast_const();
    reader(WipePhase::Before, ptr, SERVER_LOGIN_LEN);
    held.clear();
    reader(WipePhase::After, ptr, SERVER_LOGIN_LEN);
}

// ------------------------------------------------------------- login fixture

/// Key stretching cost for the tests: far below the floor of the real
/// profiles, so that a login takes milliseconds. Only the test KSF of the
/// core accepts it.
pub const SMALL: ferret_core::KdfParams = ferret_core::KdfParams {
    m_kib: 64,
    t: 1,
    p: 1,
};

/// The password of the account of a [`LoginFixture`].
pub const FIXTURE_PASSWORD: &str = "correct horse battery";

/// The address the fixture's caller comes from.
pub const FIXTURE_IP: &str = "192.0.2.7";

/// A server with one registered account, and the pieces to run the client of
/// `ferret-core` against it.
pub struct LoginFixture {
    /// The OPAQUE keys.
    pub keys: crate::ServerKeys,
    /// The pre-login secret.
    pub prelogin: crate::PreloginSecret,
    /// The key that seals login states.
    pub seal: crate::StateSealKey,
    /// A clock the test sets.
    pub clock: crate::ManualClock,
    /// A throttle that admits and remembers every call.
    pub throttle: crate::RecordingThrottle,
    /// Every made-up answer uses profile 1.
    pub policy: crate::PreloginPolicy,
    /// The profile rules of suite 1.
    pub profiles: crate::ProfileRules,
    /// The login state store.
    pub store: crate::InMemoryLoginStateStore,
    /// The login name of the account.
    pub name: crate::NormalizedLoginName,
    /// The credential id of the account.
    pub credential: CredentialId,
    /// The record the account registered, with profile 1.
    pub record: crate::StoredRecord,
    /// How many logins `start` has begun: each gets its own random source.
    starts: AtomicUsize,
}

impl LoginFixture {
    /// The time the fixture's clock starts at.
    pub const START: u64 = 1_700_000_000;

    /// A server and an account `alice@example.com` registered with
    /// [`FIXTURE_PASSWORD`].
    pub fn new() -> Self {
        use ferret_core::TestRng;

        let keys = crate::ServerKeys::generate(&mut TestRng::new(b"fixture keys")).unwrap();
        let prelogin = crate::PreloginSecret::generate(&mut TestRng::new(b"fixture prelogin"));
        let seal = crate::StateSealKey::derive(&prelogin).unwrap();
        let credential = CredentialId::from_bytes([0x42; 16]);
        let profiles = crate::ProfileRules::ferret_v1();
        let record = register_account(&keys, &profiles, &credential, FIXTURE_PASSWORD);
        Self {
            keys,
            prelogin,
            seal,
            clock: crate::ManualClock::new(Self::START),
            throttle: crate::RecordingThrottle::new(),
            policy: crate::PreloginPolicy::single(ferret_core::KsfProfile::from_wire(1).unwrap()),
            profiles,
            store: crate::InMemoryLoginStateStore::new(),
            name: crate::normalize_login_name("alice@example.com").unwrap(),
            credential,
            record,
            starts: AtomicUsize::new(0),
        }
    }

    /// Registers another account on this server, with its own record, for
    /// tests of two accounts. The record is not known to the fixture.
    pub fn register(&self, credential: &CredentialId, password: &str) -> crate::StoredRecord {
        register_account(&self.keys, &self.profiles, credential, password)
    }

    /// The OPAQUE input of a password.
    pub fn input(password: &str) -> ferret_core::OpaqueInput {
        ferret_core::MasterPassword::for_unlock(password.as_bytes())
            .unwrap()
            .opaque_input(None)
    }

    /// The server's context.
    pub fn cx(&self) -> crate::AuthContext<'_> {
        crate::AuthContext::new(
            &self.keys,
            &self.prelogin,
            &self.seal,
            &self.clock,
            &self.throttle,
            &self.policy,
            &self.profiles,
        )
    }

    /// The caller of the fixture.
    pub fn caller() -> crate::Caller {
        crate::Caller {
            ip: Some(FIXTURE_IP.parse().unwrap()),
        }
    }

    /// The lookup of the account.
    pub fn active(&self) -> crate::AccountLookup<'_> {
        crate::AccountLookup::Active {
            record: &self.record,
            sk_hint: false,
        }
    }

    /// KE1 of a client that types `password`, and the state to finish with.
    /// The client's random source is a `TestRng` seeded with `seed`.
    pub fn client_start(&self, password: &str, seed: &str) -> (Vec<u8>, ferret_core::LoginState) {
        ferret_core::opaque_login_start(
            &mut ferret_core::TestRng::new(seed.as_bytes()),
            &Self::input(password),
        )
        .unwrap()
    }

    /// The client's last step with the test KSF: KE3, or the client's error.
    pub fn client_finish(
        &self,
        state: ferret_core::LoginState,
        password: &str,
        ke2: &[u8],
        context: &[u8],
    ) -> Result<Vec<u8>, ferret_core::Error> {
        use ferret_core::testing::opaque::{TestKsf, login_finish_with};
        login_finish_with(
            &mut ferret_core::TestRng::new(b"client finish"),
            state,
            &Self::input(password),
            ke2,
            &TestKsf::new(SMALL),
            Some(context),
            ferret_core::PinState::FirstUse,
        )
        .map(|done| done.finished.ke3)
    }

    /// `login_start` for the fixture's name. Every call draws from its own
    /// `TestRng`, so the login ids differ.
    pub fn start(
        &self,
        lookup: crate::AccountLookup<'_>,
        ke1: &[u8],
        purpose: LoginPurpose,
    ) -> Result<crate::LoginStartResponse, crate::AuthError> {
        let request = crate::LoginStartRequest {
            caller: Self::caller(),
            name: &self.name,
            credential: self.credential,
            lookup,
            purpose,
            ke1,
        };
        let n = self.starts.fetch_add(1, Ordering::Relaxed);
        crate::login_start(
            &self.cx(),
            &self.store,
            &mut ferret_core::TestRng::new(format!("fixture server {n}").as_bytes()),
            &request,
        )
    }

    /// `login_finish` from the fixture's caller.
    pub fn finish(
        &self,
        login_id: &LoginId,
        ke3: &[u8],
        current_session: Option<(SessionBinding, CredentialId)>,
    ) -> Result<crate::LoginVerified, crate::AuthError> {
        crate::login_finish(
            &self.cx(),
            &self.store,
            &crate::LoginFinishRequest {
                caller: Self::caller(),
                login_id: login_id.to_hex().as_bytes(),
                ke3,
                current_session,
            },
        )
    }
}

/// A client registration of `password` under `credential` against the server's
/// keys, packed as the server stores it (profile 1).
fn register_account(
    keys: &crate::ServerKeys,
    profiles: &crate::ProfileRules,
    credential: &CredentialId,
    password: &str,
) -> crate::StoredRecord {
    use ferret_core::testing::opaque::{TestKsf, register_finish_with};
    use ferret_core::{TestRng, opaque_register_start};

    let input = LoginFixture::input(password);
    let mut client = TestRng::new(b"fixture registration");
    let (request, state) = opaque_register_start(&mut client, &input).unwrap();
    let response = crate::register_start(keys, credential, &request).unwrap();
    let done =
        register_finish_with(&mut client, state, &input, &response, &TestKsf::new(SMALL)).unwrap();
    crate::register_finish(
        &done.record,
        1,
        profiles,
        crate::RegistrationKind::NewAccount,
    )
    .unwrap()
}

impl Default for LoginFixture {
    fn default() -> Self {
        Self::new()
    }
}

impl core::fmt::Debug for LoginFixture {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("LoginFixture([redacted])")
    }
}

/// `login_start` run with another OPAQUE context and other identities than
/// Ferret's. A client of Ferret cannot authenticate such a server.
pub fn login_start_with_context<R: ferret_core::SecureRng, S: LoginStateStore>(
    cx: &crate::AuthContext<'_>,
    store: &S,
    rng: &mut R,
    req: &crate::LoginStartRequest<'_>,
    context: &[u8],
    identities: Option<(&[u8], &[u8])>,
) -> Result<crate::LoginStartResponse, crate::AuthError> {
    let params = crate::login::Params {
        context,
        client_identity: identities.map(|(client, _)| client),
        server_identity: identities.map(|(_, server)| server),
    };
    crate::login::start_with(cx, store, rng, req, &params)
}

/// Takes the sealed state of the login `id` out of `store`, as the first
/// step of `login_finish` does.
pub fn take_state<S: LoginStateStore>(store: &S, id: &LoginId, now: u64) -> SealedState {
    store.take(&id.store_key(), now).unwrap().unwrap()
}

/// Puts a sealed state in `store` under the key of the login `id`, valid for
/// the usual time from `now`. For tests that move or change a state.
pub fn put_state<S: LoginStateStore>(store: &S, id: &LoginId, sealed: SealedState, now: u64) {
    store
        .put(id.store_key(), sealed, now + STATE_TTL_SECS, now)
        .unwrap();
}

// ------------------------------------------------------------ challenge store

/// The key of the n-th test nonce: the key of a nonce made from `n` in a
/// session of zeros.
pub fn challenge_key(n: u32) -> crate::ChallengeKey {
    let mut nonce = [0u8; 32];
    nonce[..4].copy_from_slice(&n.to_be_bytes());
    crate::ChallengeKey::new(&SessionBinding([0; 32]), &nonce)
}

/// Runs every check on challenge stores made by `make`. `make(capacity)` must
/// give a fresh, empty store that holds at most `capacity` keys.
pub fn challenge_conformance<S: crate::ChallengeStore>(make: impl Fn(usize) -> S) {
    challenge_is_consumed_once(&make);
    challenge_unknown_key_is_unknown(&make);
    challenge_expiry_boundary(&make);
    challenge_expired_is_removed_by_consume_and_purge(&make);
    challenge_same_key_twice_is_collision(&make);
    challenge_put_of_an_expired_key_is_refused(&make);
    challenge_capacity_evicts_oldest_first(&make);
    challenge_concurrent_consume_yields_exactly_one(&make);
    challenge_concurrent_put_respects_capacity(&make);
}

/// A key is consumed once; the second `consume` finds nothing.
pub fn challenge_is_consumed_once<S: crate::ChallengeStore>(make: impl Fn(usize) -> S) {
    use crate::ConsumeOutcome::{Consumed, Unknown};
    let store = make(ROOMY);
    store.put(challenge_key(1), 1_300, 1_000).unwrap();
    store.put(challenge_key(2), 1_300, 1_000).unwrap();
    assert_eq!(store.consume(&challenge_key(1), 1_001).unwrap(), Consumed);
    assert_eq!(store.consume(&challenge_key(1), 1_001).unwrap(), Unknown);
    // Only that key was consumed.
    assert_eq!(store.consume(&challenge_key(2), 1_001).unwrap(), Consumed);
    // The key is free again.
    store.put(challenge_key(1), 1_400, 1_002).unwrap();
    assert_eq!(store.consume(&challenge_key(1), 1_003).unwrap(), Consumed);
}

/// A key that was never stored is `Unknown`, not an error.
pub fn challenge_unknown_key_is_unknown<S: crate::ChallengeStore>(make: impl Fn(usize) -> S) {
    use crate::ConsumeOutcome::Unknown;
    let store = make(ROOMY);
    assert_eq!(store.consume(&challenge_key(9), 1_000).unwrap(), Unknown);
    store.put(challenge_key(1), 1_300, 1_000).unwrap();
    assert_eq!(store.consume(&challenge_key(9), 1_000).unwrap(), Unknown);
}

/// With a lifetime of 300 seconds a key is valid in the seconds `t` to
/// `t + 299`, and `Expired` from `t + 300`.
pub fn challenge_expiry_boundary<S: crate::ChallengeStore>(make: impl Fn(usize) -> S) {
    use crate::ConsumeOutcome::{Consumed, Expired};
    let expires_at = 1_000 + crate::CHALLENGE_TTL_SECS;
    assert_eq!(expires_at, 1_300);
    for (now, expected) in [
        (1_000, Consumed),
        (1_299, Consumed),
        (1_300, Expired),
        (1_301, Expired),
        (u64::MAX, Expired),
    ] {
        let store = make(ROOMY);
        store.put(challenge_key(1), expires_at, 1_000).unwrap();
        assert_eq!(
            store.consume(&challenge_key(1), now).unwrap(),
            expected,
            "consume at {now}"
        );
    }
}

/// An expired key is reported once by `consume` and removed with it; the rest
/// are removed by `purge_expired`, which counts only what it removes. A live
/// key is left alone.
pub fn challenge_expired_is_removed_by_consume_and_purge<S: crate::ChallengeStore>(
    make: impl Fn(usize) -> S,
) {
    use crate::ConsumeOutcome::{Consumed, Expired, Unknown};
    let store = make(ROOMY);
    assert_eq!(store.purge_expired(0).unwrap(), 0);
    store.put(challenge_key(1), 100, 50).unwrap();
    store.put(challenge_key(2), 100, 50).unwrap();
    store.put(challenge_key(3), 200, 50).unwrap();
    store.put(challenge_key(4), 1_000, 50).unwrap();
    assert_eq!(store.consume(&challenge_key(1), 100).unwrap(), Expired);
    assert_eq!(store.consume(&challenge_key(1), 100).unwrap(), Unknown);
    assert_eq!(store.purge_expired(100).unwrap(), 1);
    assert_eq!(store.consume(&challenge_key(2), 100).unwrap(), Unknown);
    assert_eq!(store.purge_expired(150).unwrap(), 0);
    assert_eq!(store.consume(&challenge_key(3), 150).unwrap(), Consumed);
    assert_eq!(store.purge_expired(999).unwrap(), 0);
    assert_eq!(store.purge_expired(1_000).unwrap(), 1);
    assert_eq!(store.consume(&challenge_key(4), 1_000).unwrap(), Unknown);
}

/// A live key is never stored twice. An expired one does not block its key.
pub fn challenge_same_key_twice_is_collision<S: crate::ChallengeStore>(make: impl Fn(usize) -> S) {
    use crate::ConsumeOutcome::Consumed;
    let store = make(ROOMY);
    store.put(challenge_key(1), 1_300, 1_000).unwrap();
    assert_eq!(
        store.put(challenge_key(1), 1_310, 1_010),
        Err(StoreError::Collision)
    );
    assert_eq!(store.consume(&challenge_key(1), 1_011).unwrap(), Consumed);
    store.put(challenge_key(2), 1_100, 1_000).unwrap();
    store.put(challenge_key(2), 1_400, 1_100).unwrap();
    assert_eq!(store.consume(&challenge_key(2), 1_101).unwrap(), Consumed);
}

/// A key that is already expired when it is put, or a put at `u64::MAX`, is
/// refused with `Expired` and stores nothing: it must not take a slot, push
/// out a live key, or become valid when the clock reads a normal time again.
pub fn challenge_put_of_an_expired_key_is_refused<S: crate::ChallengeStore>(
    make: impl Fn(usize) -> S,
) {
    use crate::ConsumeOutcome::{Consumed, Unknown};
    let store = make(1);
    store.put(challenge_key(1), 1_300, 1_000).unwrap();
    for (expires_at, now) in [
        (1_000, 1_000),
        (999, 1_000),
        (0, 1),
        (u64::MAX, u64::MAX),
        (1_300, u64::MAX),
    ] {
        assert_eq!(
            store.put(challenge_key(2), expires_at, now),
            Err(StoreError::Expired),
            "expires_at {expires_at}, now {now}"
        );
    }
    assert_eq!(store.consume(&challenge_key(2), 1_001).unwrap(), Unknown);
    assert_eq!(store.consume(&challenge_key(2), 0).unwrap(), Unknown);
    assert_eq!(store.consume(&challenge_key(1), 1_001).unwrap(), Consumed);
    // A key that expires one second after it is made is accepted.
    store.put(challenge_key(3), 1_001, 1_000).unwrap();
    assert_eq!(store.consume(&challenge_key(3), 1_000).unwrap(), Consumed);
}

/// At the limit the oldest key is removed to make room.
pub fn challenge_capacity_evicts_oldest_first<S: crate::ChallengeStore>(make: impl Fn(usize) -> S) {
    use crate::ConsumeOutcome::{Consumed, Unknown};
    let store = make(3);
    for n in 1..=3 {
        store.put(challenge_key(n), 1_300, 1_000).unwrap();
    }
    store.put(challenge_key(4), 1_300, 1_000).unwrap();
    assert_eq!(store.consume(&challenge_key(1), 1_001).unwrap(), Unknown);
    for n in 2..=4 {
        assert_eq!(store.consume(&challenge_key(n), 1_001).unwrap(), Consumed);
    }
    // A consumed key frees its place; the next oldest goes first after that.
    let store = make(2);
    store.put(challenge_key(1), 1_300, 1_000).unwrap();
    store.put(challenge_key(2), 1_300, 1_000).unwrap();
    assert_eq!(store.consume(&challenge_key(1), 1_001).unwrap(), Consumed);
    store.put(challenge_key(3), 1_301, 1_001).unwrap();
    store.put(challenge_key(4), 1_301, 1_001).unwrap();
    assert_eq!(store.consume(&challenge_key(2), 1_002).unwrap(), Unknown);
    assert_eq!(store.consume(&challenge_key(3), 1_002).unwrap(), Consumed);
    assert_eq!(store.consume(&challenge_key(4), 1_002).unwrap(), Consumed);
}

/// 32 threads consume the same key at the same moment: exactly one gets it.
pub fn challenge_concurrent_consume_yields_exactly_one<S: crate::ChallengeStore>(
    make: impl Fn(usize) -> S,
) {
    use crate::ConsumeOutcome::{Consumed, Unknown};
    const THREADS: usize = 32;
    let store = make(ROOMY);
    for round in 0..20u32 {
        store.put(challenge_key(round), 1_300, 1_000).unwrap();
        let barrier = Barrier::new(THREADS);
        let winners = AtomicUsize::new(0);
        std::thread::scope(|scope| {
            for _ in 0..THREADS {
                scope.spawn(|| {
                    barrier.wait();
                    match store.consume(&challenge_key(round), 1_001).unwrap() {
                        Consumed => {
                            winners.fetch_add(1, Ordering::SeqCst);
                        }
                        other => assert_eq!(other, Unknown),
                    }
                });
            }
        });
        assert_eq!(winners.load(Ordering::SeqCst), 1, "round {round}");
        assert_eq!(
            store.consume(&challenge_key(round), 1_001).unwrap(),
            Unknown
        );
    }
}

/// Threads put different keys at a store that has room for few, at the same
/// moment. The store never holds more than its limit.
pub fn challenge_concurrent_put_respects_capacity<S: crate::ChallengeStore>(
    make: impl Fn(usize) -> S,
) {
    use crate::ConsumeOutcome::Consumed;
    const LIMIT: usize = 10;
    const THREADS: u32 = 16;
    const EACH: u32 = 20;
    for round in 0..5u32 {
        let store = make(LIMIT);
        let barrier = Barrier::new(THREADS as usize);
        std::thread::scope(|scope| {
            for thread in 0..THREADS {
                let (store, barrier) = (&store, &barrier);
                scope.spawn(move || {
                    barrier.wait();
                    for n in 0..EACH {
                        let id = 100 + round * 1_000 + thread * EACH + n;
                        store.put(challenge_key(id), 1_300, 1_000).unwrap();
                    }
                });
            }
        });
        let mut held = 0;
        for thread in 0..THREADS {
            for n in 0..EACH {
                let id = 100 + round * 1_000 + thread * EACH + n;
                if store.consume(&challenge_key(id), 1_001).unwrap() == Consumed {
                    held += 1;
                }
            }
        }
        assert_eq!(held, LIMIT, "round {round}");
    }
}
