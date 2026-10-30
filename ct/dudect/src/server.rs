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
//! into the HMAC), and both classes use the same pool of 256 names, so the data
//! are not the same on every measurement but are the same in the two classes. As in the rest of the
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
        // the classes apart): the name, credential and record are those of
        // account `i` either way, and the library does not read the
        // credential and the record when the lookup says there is no
        // account. The same names in both classes: the time of the HMAC over
        // a name varies a little with the name, and two pools of names would
        // give the classes a different mean however many measurements are made.
        let account = &self.accounts[i];
        self.cell.name = account.name.clone();
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
    names: Vec<(NormalizedLoginName, AccountId)>,
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
        // The same name for both classes: the time of the HMAC over a name
        // varies a little with the name, and two pools of names would give
        // the classes a different mean however many measurements are made.
        self.name = self.names[i].0.clone();
        if class == Class::Right {
            self.account = None;
            self.active = 0;
        } else {
            self.account = Some(self.names[i].1);
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
    let names = (0..SERVER_POOL as u32)
        .map(|n| (name_of('k', n), AccountId::from_bytes(mix.array::<16>())))
        .collect::<Vec<_>>();
    Prelogin {
        mode,
        name: names[0].0.clone(),
        account: Some(names[0].1),
        active: 1,
        names,
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
    /// A non-zero byte to xor into the expected value, per input.
    masks: Vec<u8>,
    /// What the request expects: session and account, 48 bytes. One byte is
    /// wrong: the first (Left, in the session) or the last (Right, in the
    /// account). Both classes read the same pool and run the same code to
    /// make the cell; they differ in the index of the byte alone.
    cell: [u8; 48],
}

impl Target for Binding {
    fn name(&self) -> &'static str {
        "server_state_binding"
    }
    fn reps(&self) -> u32 {
        1
    }
    fn prepare(&mut self, class: Class, i: usize) {
        let mut cell = [0u8; 48];
        cell[..32].copy_from_slice(&SESSION);
        cell[32..].copy_from_slice(&ACCOUNT);
        let at = (class as usize) * 47;
        cell[at] ^= self.masks[i % SERVER_POOL];
        self.cell = cell;
    }
    fn run(&self, reps: u32) -> u64 {
        let mut acc = 0u64;
        for _ in 0..reps {
            let mut session = [0u8; 32];
            let mut account = [0u8; 16];
            session.copy_from_slice(&self.cell[..32]);
            account.copy_from_slice(&self.cell[32..]);
            let opened = open_fields(
                &self.f.seal,
                &self.id,
                black_box(&self.sealed),
                Some((session, account)),
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
    let masks = (0..SERVER_POOL).map(|_| (mix.next() as u8) | 1).collect();
    Binding {
        f,
        id,
        sealed,
        masks,
        cell: [0; 48],
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
    /// Input `i` of class `c` is at `2 * i + c`: one allocation for both
    /// classes, so neither has a place of its own in memory.
    pool: Vec<SealedState>,
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
            (Class::Right, FinishKind::StateVsMissing) => None,
            _ => Some(self.pool[2 * i + class as usize].clone()),
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
    let at = |class: usize| if class == 0 { 0 } else { 15 };
    let mut pool = Vec::with_capacity(2 * SERVER_POOL);
    for _ in 0..SERVER_POOL {
        for class in 0..2 {
            pool.push(other(at(class), mix));
        }
    }
    Finish {
        name,
        kind,
        hex: id.to_hex(),
        f,
        clock: FixedClock,
        store: SlotStore(Mutex::new(None)),
        pool,
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
