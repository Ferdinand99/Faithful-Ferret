//! Timing tests of the OPAQUE server library (`crates/ferret-server-auth`).
//!
//! They time the library and nothing around it: no database, no HTTP, no
//! throttle (a limiter that admits everything), a store that keeps nothing,
//! a clock that stands still and a random source that replays one tape. What
//! an observer of the whole endpoint sees (the bytes of the answers and the
//! distribution of the delays) is a separate test of the endpoint.
//!
//! | target | operation | Left | Right |
//! |---|---|---|---|
//! | `server_login_start_known_vs_unknown` | `login_start`, the same KE1 and the same draws | a name with an account | a name without |
//! | `server_login_start_known_vs_disabled` | `login_start`, the same | a name with an account | the name of an account that may not log in |
//! | `server_prelogin_known_vs_unknown` | `fake_prelogin` and the branch-free choice of the answer (`ct_select_u8`) by a flag | a name with an account | a name without |
//! | `info_server_prelogin_resolve_credential` | the same with `resolve_credential`, which takes the lookup as `Option<&AccountId>` (information only) | a name with an account | a name without |
//! | `server_state_binding` | `open_fields` of a re-authentication state (the AEAD, then the purpose, session and account compare of `state.rs`) | session wrong in the first byte | account wrong in the last byte |
//! | `server_finish_credential_vs_account` | `login_finish` of a re-authentication whose state is for another account (the compare of `login.rs`) | other account, first byte differs | other account, last byte differs |
//! | `info_server_finish_state_vs_missing` | `login_finish` | the state is there | there is none (information only: shows that an end-to-end timing of `login_finish` sees a difference of one AEAD open) |
//!
//! The classes of the first three differ in nothing but whether the name has
//! an account. Every name has the same length (the length is public and goes
//! into the HMAC), and the inputs of a class come from a pool of 256 names, so
//! the data are not the same on every measurement. As in the rest of the
//! crate the input of a measurement is copied into one working cell before
//! the timer starts, so the memory the library reads is at the same place for
//! both classes.

use crate::{Class, Mix, Target};
use ferret_core::testing::TestRng;
use ferret_core::{AccountId, SecureRng};
use ferret_server_auth::testing::{
    FIXTURE_PASSWORD, LoginFixture, StateFields, open_fields, seal_fields,
};
use ferret_server_auth::{
    AccountLookup, AuthContext, Caller, Clock, CredentialId, LoginFinishRequest, LoginId,
    LoginPurpose, LoginStartRequest, LoginStateStore, NoThrottle, NormalizedLoginName, SealedState,
    SessionBinding, StateKey, StoreError, StoredRecord, fake_prelogin, login_finish, login_start,
    normalize_login_name, resolve_credential,
};
use std::cell::RefCell;
use std::hint::black_box;
use std::sync::Mutex;

/// The inputs of each class.
const SERVER_POOL: usize = 256;

/// The time every measurement sees.
const NOW: u64 = LoginFixture::START;

struct FixedClock;

impl Clock for FixedClock {
    fn now_unix(&self) -> u64 {
        NOW
    }
}

/// A random source that plays one tape from the start, again and again: the
/// draws of two logins are the same bytes, so what they cost is the same.
struct Tape {
    bytes: Vec<u8>,
    at: usize,
}

impl Tape {
    fn new(seed: u64) -> Self {
        let mut rng = TestRng::new(&seed.to_le_bytes());
        // `login_start` draws 200 bytes in six calls.
        let mut bytes = vec![0u8; 256];
        rng.fill(&mut bytes);
        Self { bytes, at: 0 }
    }

    fn rewind(&mut self) {
        self.at = 0;
    }
}

impl SecureRng for Tape {
    fn fill(&mut self, dest: &mut [u8]) {
        let end = self.at + dest.len();
        // A tape that is too short is a mistake of this harness, not of the
        // library: stop loudly.
        dest.copy_from_slice(&self.bytes[self.at..end]);
        self.at = end;
    }
}

/// Keeps nothing and finds nothing: what the timing of a start or a refused
/// finish needs of a store.
struct NullStore;

impl LoginStateStore for NullStore {
    fn put(&self, _: StateKey, _: SealedState, _: u64, _: u64) -> Result<(), StoreError> {
        Ok(())
    }
    fn take(&self, _: &StateKey, _: u64) -> Result<Option<SealedState>, StoreError> {
        Ok(None)
    }
    fn purge_expired(&self, _: u64) -> Result<usize, StoreError> {
        Ok(0)
    }
}

/// A store with one slot: `take` gives what the slot holds, once.
struct SlotStore(Mutex<Option<SealedState>>);

impl LoginStateStore for SlotStore {
    fn put(&self, _: StateKey, _: SealedState, _: u64, _: u64) -> Result<(), StoreError> {
        Ok(())
    }
    fn take(&self, _: &StateKey, _: u64) -> Result<Option<SealedState>, StoreError> {
        Ok(self.0.lock().map_err(|_| StoreError::Backend)?.take())
    }
    fn purge_expired(&self, _: u64) -> Result<usize, StoreError> {
        Ok(0)
    }
}

/// Names of one length: `u` and eight hex digits of `n`, at the same domain.
fn name_of(prefix: char, n: u32) -> NormalizedLoginName {
    normalize_login_name(&format!("{prefix}{n:08x}@example.com")).expect("a valid name")
}

fn cx<'a>(f: &'a LoginFixture, clock: &'a FixedClock) -> AuthContext<'a> {
    AuthContext::new(
        &f.keys,
        &f.prelogin,
        &f.seal,
        clock,
        &NoThrottle,
        &f.policy,
        &f.profiles,
    )
}

// ------------------------------------------------------------ login_start

/// What the other class (Right) of a start is.
#[derive(Clone, Copy)]
enum Other {
    /// A name without an account.
    Unknown,
    /// The name of an account that may not log in.
    Disabled,
}

struct Account {
    name: NormalizedLoginName,
    credential: CredentialId,
    record: StoredRecord,
}

struct Start {
    name: &'static str,
    other: Other,
    f: LoginFixture,
    clock: FixedClock,
    ke1: Vec<u8>,
    /// Accounts for Left (and for Right of `Disabled`).
    accounts: Vec<Account>,
    /// Names without an account.
    unknown: Vec<NormalizedLoginName>,
    tape: RefCell<Tape>,
    // The working cell.
    right: bool,
    cell: Account,
}

impl Target for Start {
    fn name(&self) -> &'static str {
        self.name
    }
    fn reps(&self) -> u32 {
        1
    }
    fn prepare(&mut self, class: Class, i: usize) {
        let i = i % SERVER_POOL;
        self.right = class == Class::Right;
        // The same copies for both classes (a clone allocates, and the state
        // of the allocator and of the caches after the copy must not tell
        // the classes apart): the name comes from the pool of the class, the
        // credential and the record are those of account `i` either way, and
        // the library does not read them for a name without an account.
        let account = &self.accounts[i];
        let name = match (class, self.other) {
            (Class::Right, Other::Unknown) => &self.unknown[i],
            _ => &account.name,
        };
        self.cell.name = name.clone();
        self.cell.credential = account.credential;
        self.cell.record = account.record.clone();
        self.tape.get_mut().rewind();
    }
    fn run(&self, reps: u32) -> u64 {
        let mut acc = 0u64;
        let cx = cx(&self.f, &self.clock);
        for _ in 0..reps {
            let lookup = if !self.right {
                AccountLookup::Active {
                    record: &self.cell.record,
                    sk_hint: false,
                }
            } else {
                match self.other {
                    Other::Unknown => AccountLookup::Unknown,
                    Other::Disabled => AccountLookup::Disabled,
                }
            };
            let request = LoginStartRequest {
                caller: LoginFixture::caller(),
                name: &self.cell.name,
                credential: self.cell.credential,
                lookup,
                purpose: LoginPurpose::Login,
                session_scope: None,
                ke1: black_box(&self.ke1),
            };
            let mut tape = self.tape.borrow_mut();
            tape.rewind();
            let answer = login_start(&cx, &NullStore, &mut *tape, &request);
            if let Ok(response) = &answer {
                acc = acc
                    .wrapping_add(u64::from(response.ke2[0]))
                    .wrapping_add(u64::from(response.ksf_profile));
            }
            black_box(&answer);
        }
        black_box(acc)
    }
}

fn accounts(f: &LoginFixture, mix: &mut Mix) -> Vec<Account> {
    (0..SERVER_POOL as u32)
        .map(|n| {
            let credential = CredentialId::from_bytes(mix.array::<16>());
            Account {
                name: name_of('k', n),
                credential,
                record: f.register(&credential, FIXTURE_PASSWORD),
            }
        })
        .collect()
}

fn start_target(mix: &mut Mix, name: &'static str, other: Other) -> Start {
    let f = LoginFixture::new();
    let (ke1, _) = f.client_start(FIXTURE_PASSWORD, "dudect client");
    let accounts = accounts(&f, mix);
    let unknown = (0..SERVER_POOL as u32).map(|n| name_of('u', n)).collect();
    let cell = Account {
        name: accounts[0].name.clone(),
        credential: accounts[0].credential,
        record: accounts[0].record.clone(),
    };
    Start {
        name,
        other,
        f,
        clock: FixedClock,
        ke1,
        accounts,
        unknown,
        tape: RefCell::new(Tape::new(mix.next())),
        right: false,
        cell,
    }
}

// ---------------------------------------------------------------- prelogin

/// What a prelogin target times.
#[derive(Clone, Copy)]
enum PreloginMode {
    /// `resolve_credential` with `Some(account)` or `None`, then the answer.
    /// The library takes the lookup as a reference that may be absent, and
    /// reading through it takes a branch on whether it is there: information
    /// only, see `ct/TRIAGE.md`.
    Resolve,
    /// The made-up answer is always computed, and the real or the made-up
    /// profile and hint are chosen by a flag (as `login_start` does): the part
    /// that is branch-free by design.
    Select,
}

struct Prelogin {
    mode: PreloginMode,
    f: LoginFixture,
    known: Vec<(NormalizedLoginName, AccountId)>,
    unknown: Vec<NormalizedLoginName>,
    name: NormalizedLoginName,
    /// What the lookup of the name found. Set before the timer starts, so the
    /// timed code does not branch on the class to build it.
    account: Option<AccountId>,
    /// The same as a flag, for the choice of the answer.
    active: u8,
    /// The profile and hint of the stored account.
    stored: (u8, u8),
}

impl Target for Prelogin {
    fn name(&self) -> &'static str {
        match self.mode {
            PreloginMode::Resolve => "info_server_prelogin_resolve_credential",
            PreloginMode::Select => "server_prelogin_known_vs_unknown",
        }
    }
    fn reps(&self) -> u32 {
        // A few microseconds, close to the noise of the timer and of the
        // machine: repeated, as the short targets of the core are.
        8
    }
    fn informational(&self) -> bool {
        matches!(self.mode, PreloginMode::Resolve)
    }
    fn prepare(&mut self, class: Class, i: usize) {
        let i = i % SERVER_POOL;
        if class == Class::Right {
            self.name = self.unknown[i].clone();
            self.account = None;
            self.active = 0;
        } else {
            self.name = self.known[i].0.clone();
            self.account = Some(self.known[i].1);
            self.active = 1;
        }
    }
    fn run(&self, reps: u32) -> u64 {
        let mut acc = 0u64;
        for _ in 0..reps {
            // What an endpoint does with a name: the id OPAQUE uses, and the
            // made-up answer, which are both always computed; the real answer
            // and the made-up one are chosen without a branch.
            let fake = fake_prelogin(&self.f.prelogin, black_box(&self.name), &self.f.policy);
            let (active, first) = match self.mode {
                PreloginMode::Resolve => {
                    let account = black_box(self.account.as_ref());
                    let id = resolve_credential(&self.f.prelogin, &self.name, account);
                    (u8::from(account.is_some()), id.as_bytes()[0])
                }
                PreloginMode::Select => (black_box(self.active), 0),
            };
            let profile =
                crate::harness::ct_select::ct_select_u8(active, self.stored.0, fake.ksf_profile);
            let hint = crate::harness::ct_select::ct_select_u8(
                active,
                self.stored.1,
                u8::from(fake.sk_hint),
            );
            acc = acc
                .wrapping_add(u64::from(first))
                .wrapping_add(u64::from(profile))
                .wrapping_add(u64::from(hint));
        }
        black_box(acc)
    }
}

fn prelogin_target(mix: &mut Mix, mode: PreloginMode) -> Prelogin {
    let f = LoginFixture::new();
    let known = (0..SERVER_POOL as u32)
        .map(|n| (name_of('k', n), AccountId::from_bytes(mix.array::<16>())))
        .collect::<Vec<_>>();
    let unknown = (0..SERVER_POOL as u32).map(|n| name_of('u', n)).collect();
    Prelogin {
        mode,
        name: known[0].0.clone(),
        account: Some(known[0].1),
        active: 1,
        known,
        unknown,
        stored: (1, 1),
        f,
    }
}

// ------------------------------------------------- state binding (open)

/// The session, the account and the credential of the fixed states.
const SESSION: [u8; 32] = [0x5a; 32];
const ACCOUNT: [u8; 16] = [0xa7; 16];
const STATE_ID: &str = "0123456789abcdef0123456789abcdef";

fn fields(credential: [u8; 16]) -> StateFields {
    StateFields {
        credential,
        reauth: Some((SESSION, ACCOUNT)),
        expires_at: NOW + 60,
        ksf_profile: 1,
        server_login: [0x33; 128],
    }
}

fn sealed(f: &LoginFixture, mix: &mut Mix, id: &LoginId, credential: [u8; 16]) -> SealedState {
    let mut rng = TestRng::new(&mix.next().to_le_bytes());
    seal_fields(&f.seal, &mut rng, id, &fields(credential), NOW).expect("a state seals")
}

/// A value with one byte changed to something else.
fn flipped<const N: usize>(mut a: [u8; N], at: usize, mix: &mut Mix) -> [u8; N] {
    a[at] ^= (mix.next() as u8) | 1;
    a
}

struct Binding {
    f: LoginFixture,
    id: LoginId,
    sealed: SealedState,
    /// What the request expects: wrong in the first byte of the session
    /// (Left) or in the last byte of the account (Right).
    left: Vec<([u8; 32], [u8; 16])>,
    right: Vec<([u8; 32], [u8; 16])>,
    cell: ([u8; 32], [u8; 16]),
}

impl Target for Binding {
    fn name(&self) -> &'static str {
        "server_state_binding"
    }
    fn reps(&self) -> u32 {
        1
    }
    fn prepare(&mut self, class: Class, i: usize) {
        let i = i % SERVER_POOL;
        self.cell = match class {
            Class::Left => self.left[i],
            Class::Right => self.right[i],
        };
    }
    fn run(&self, reps: u32) -> u64 {
        let mut acc = 0u64;
        for _ in 0..reps {
            let opened = open_fields(
                &self.f.seal,
                &self.id,
                black_box(&self.sealed),
                Some(self.cell),
                NOW,
            );
            acc = acc.wrapping_add(u64::from(opened.is_err()));
        }
        black_box(acc)
    }
}

fn binding_target(mix: &mut Mix) -> Binding {
    let f = LoginFixture::new();
    let id = LoginId::parse(STATE_ID.as_bytes()).expect("a login id");
    let sealed = sealed(&f, mix, &id, ACCOUNT);
    let left = (0..SERVER_POOL)
        .map(|_| (flipped(SESSION, 0, mix), ACCOUNT))
        .collect();
    let right = (0..SERVER_POOL)
        .map(|_| (SESSION, flipped(ACCOUNT, 15, mix)))
        .collect();
    Binding {
        f,
        id,
        sealed,
        left,
        right,
        cell: (SESSION, ACCOUNT),
    }
}

// ------------------------------------------------------ login_finish

/// What differs between the two classes of a finish.
#[derive(Clone, Copy)]
enum FinishKind {
    /// The credential of the state differs from the account of the session
    /// in the first byte (Left) or in the last byte (Right).
    Credential,
    /// A state for another account is there (Left) or there is none (Right).
    StateVsMissing,
}

struct Finish {
    name: &'static str,
    kind: FinishKind,
    f: LoginFixture,
    clock: FixedClock,
    hex: String,
    store: SlotStore,
    left: Vec<SealedState>,
    right: Vec<SealedState>,
}

impl Target for Finish {
    fn name(&self) -> &'static str {
        self.name
    }
    fn reps(&self) -> u32 {
        1
    }
    fn informational(&self) -> bool {
        matches!(self.kind, FinishKind::StateVsMissing)
    }
    fn prepare(&mut self, class: Class, i: usize) {
        let i = i % SERVER_POOL;
        let state = match (class, self.kind) {
            (Class::Left, _) => Some(self.left[i].clone()),
            (Class::Right, FinishKind::Credential) => Some(self.right[i].clone()),
            (Class::Right, FinishKind::StateVsMissing) => None,
        };
        if let Ok(mut slot) = self.store.0.lock() {
            *slot = state;
        }
    }
    fn run(&self, reps: u32) -> u64 {
        let mut acc = 0u64;
        let cx = cx(&self.f, &self.clock);
        for _ in 0..reps {
            let request = LoginFinishRequest {
                caller: Caller { ip: None },
                login_id: self.hex.as_bytes(),
                ke3: black_box(&[0x77; 64]),
                current_session: Some((SessionBinding(SESSION), CredentialId::from_bytes(ACCOUNT))),
            };
            let result = login_finish(&cx, &self.store, &request);
            acc = acc.wrapping_add(u64::from(result.is_err()));
        }
        black_box(acc)
    }
}

fn finish_target(mix: &mut Mix, name: &'static str, kind: FinishKind) -> Finish {
    let f = LoginFixture::new();
    let id = LoginId::parse(STATE_ID.as_bytes()).expect("a login id");
    let other = |at: usize, mix: &mut Mix| {
        let credential = flipped(ACCOUNT, at, mix);
        sealed(&f, mix, &id, credential)
    };
    let (left, right) = match kind {
        FinishKind::Credential => (
            (0..SERVER_POOL).map(|_| other(0, mix)).collect(),
            (0..SERVER_POOL).map(|_| other(15, mix)).collect(),
        ),
        FinishKind::StateVsMissing => (
            (0..SERVER_POOL).map(|_| other(0, mix)).collect(),
            Vec::new(),
        ),
    };
    Finish {
        name,
        kind,
        hex: id.to_hex(),
        f,
        clock: FixedClock,
        store: SlotStore(Mutex::new(None)),
        left,
        right,
    }
}

/// The targets of the server library.
pub fn targets(mix: &mut Mix) -> Vec<Box<dyn Target + Send>> {
    vec![
        Box::new(start_target(
            mix,
            "server_login_start_known_vs_unknown",
            Other::Unknown,
        )),
        Box::new(start_target(
            mix,
            "server_login_start_known_vs_disabled",
            Other::Disabled,
        )),
        Box::new(prelogin_target(mix, PreloginMode::Select)),
        Box::new(prelogin_target(mix, PreloginMode::Resolve)),
        Box::new(binding_target(mix)),
        Box::new(finish_target(
            mix,
            "server_finish_credential_vs_account",
            FinishKind::Credential,
        )),
        Box::new(finish_target(
            mix,
            "info_server_finish_state_vs_missing",
            FinishKind::StateVsMissing,
        )),
    ]
}
