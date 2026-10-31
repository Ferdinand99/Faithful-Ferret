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
//! | `server_login_start_known_vs_disabled` | `login_start`, the same (runs the same library path as `Unknown`: a replicate, not a second piece of evidence) | a name with an account | the name of an account that may not log in |
//! | `control_server_login_start_null` | `login_start`, the same (null control of the same cost: the classes are the same) | an account | the same account |
//! | `info_server_login_start_lookup_only` | `login_start` with every byte OPAQUE sees the same: the record and id are the made-up ones in both | `Active` with the made-up record | `Unknown` |
//! | `info_server_login_start_real_vs_made_up` | `login_start`, both `Active`: only the data differ | the real record and id | the made-up record and id |
//! | `server_prelogin_known_vs_unknown` | `prelogin_answer`: the made-up answer always computed, the lookup unpacked as in `login_start`, the profile and hint chosen with `ct_select_u8` | a name with an account | a name without |
//! | `info_server_prelogin_resolve_credential` | `resolve_credential` with `Some(account)` or `None`: the account id chosen between two references (information only) | a name with an account | a name without |
//! | `server_state_binding` | `open_fields` of a re-authentication state (the AEAD, then the purpose, session and account compare of `state.rs`) | session wrong in the first byte | account wrong in the last byte |
//! | `server_finish_credential_vs_account` | `login_finish` of a re-authentication whose state is for another account (the compare of `login.rs`) | other account, first byte differs | other account, last byte differs |
//! | `info_server_finish_state_vs_missing` | `login_finish` | the state is there | there is none (information only: shows that an end-to-end timing of `login_finish` sees a difference of one AEAD open) |
//!
//! The classes of the login start benches differ in nothing but the variant
//! of the lookup (and, for the data bench, the record). The lookup is built in
//! `prepare`, before the timer starts, so the timed code has no branch on the
//! class of its own; the records of both kinds are read in `prepare` for
//! either class. Every name has the same length (the length is public and
//! goes into the HMAC), and both classes use the same pool of 256 names, so
//! the data are not the same on every measurement but are the same in the two
//! classes. As in the rest of the crate the input of a measurement is set
//! before the timer starts.
//!
//! The benches of the compares (`server_state_binding`,
//! `server_finish_credential_vs_account`) put a first-byte difference against
//! a last-byte difference behind an AEAD open of about a microsecond. They are
//! smoke tests: they cannot tell `ct_eq` from `==` on 16 or 48 bytes. What
//! shows that the compares are `ct_eq` is `ct/TRIAGE.md` (T5) and the
//! call-site test in the crate.

use crate::{Class, Mix, Target};
use ferret_core::testing::TestRng;
use ferret_core::{AccountId, SecureRng};
use ferret_server_auth::testing::{
    FIXTURE_PASSWORD, LoginFixture, StateFields, made_up_record, open_fields, seal_fields,
};
use ferret_server_auth::{
    AccountLookup, AuthContext, Caller, Clock, CredentialId, LoginFinishRequest, LoginId,
    LoginPurpose, LoginStartRequest, LoginStateStore, NoThrottle, NormalizedLoginName, SealedState,
    SessionBinding, StateKey, StoreError, StoredRecord, fake_credential_id, login_finish,
    login_start, normalize_login_name, prelogin_answer, resolve_credential,
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

/// What the two classes of a start are.
#[derive(Clone, Copy)]
enum StartKind {
    /// Left: an account of the name. Right: no account for the name.
    KnownVsUnknown,
    /// Left: an account. Right: the same account, which may not log in.
    KnownVsDisabled,
    /// Null control: both classes are the account, so the classes are the
    /// same and the noise floor of a target of this size is what t shows.
    Null,
    /// Left: an account whose record and id are the made-up ones of the name,
    /// so every byte OPAQUE sees is what the `Unknown` path computes. Right:
    /// `Unknown`. Only the variant of the lookup differs (information only).
    LookupOnly,
    /// Both classes are `Active`: Left with the real record and id, Right
    /// with the made-up ones. Only the data differ (information only).
    RealVsMadeUp,
}

/// An account of the pool and what the made-up answer for its name is. Leaked
/// once, so a lookup that points into it can be built before the timer starts.
struct Entry {
    name: NormalizedLoginName,
    id: CredentialId,
    real: StoredRecord,
    made_up_id: CredentialId,
    made_up: StoredRecord,
}

/// What the timed code reads, set by `prepare`.
struct Cell {
    name: &'static NormalizedLoginName,
    credential: CredentialId,
    lookup: AccountLookup<'static>,
}

struct Start {
    name: &'static str,
    kind: StartKind,
    f: LoginFixture,
    clock: FixedClock,
    ke1: Vec<u8>,
    entries: Vec<&'static Entry>,
    tape: RefCell<Tape>,
    cell: Cell,
    /// Keeps the reads of `prepare` from being optimised away.
    touched: u64,
}

/// Reads every byte of a record, so that it is in the cache when the timer
/// starts, whichever class reads it.
fn touch(record: &StoredRecord) -> u64 {
    record
        .record
        .as_bytes()
        .iter()
        .fold(0u64, |sum, byte| sum.wrapping_add(u64::from(*byte)))
}

impl Target for Start {
    fn name(&self) -> &'static str {
        self.name
    }
    fn reps(&self) -> u32 {
        1
    }
    fn informational(&self) -> bool {
        matches!(self.kind, StartKind::LookupOnly | StartKind::RealVsMadeUp)
    }
    fn prepare(&mut self, class: Class, i: usize) {
        let e = self.entries[i % SERVER_POOL];
        // Both records are read for either class, so that the caches and the
        // allocator are in the same state; the class decides only what the
        // lookup points at, and that is settled here, not in the timed code.
        self.touched = touch(&e.real).wrapping_add(touch(&e.made_up));
        let right = class == Class::Right;
        let (credential, lookup) = match (self.kind, right) {
            (StartKind::KnownVsUnknown, true) => (e.id, AccountLookup::Unknown),
            (StartKind::KnownVsDisabled, true) => (e.id, AccountLookup::Disabled),
            (StartKind::LookupOnly, true) => (e.made_up_id, AccountLookup::Unknown),
            (StartKind::LookupOnly, false) => (
                e.made_up_id,
                AccountLookup::Active {
                    record: &e.made_up,
                    sk_hint: true,
                },
            ),
            (StartKind::RealVsMadeUp, true) => (
                e.made_up_id,
                AccountLookup::Active {
                    record: &e.made_up,
                    sk_hint: true,
                },
            ),
            _ => (
                e.id,
                AccountLookup::Active {
                    record: &e.real,
                    sk_hint: true,
                },
            ),
        };
        self.cell = Cell {
            name: &e.name,
            credential,
            lookup,
        };
        self.tape.get_mut().rewind();
    }
    fn run(&self, reps: u32) -> u64 {
        let mut acc = black_box(self.touched) & 0;
        let cx = cx(&self.f, &self.clock);
        for _ in 0..reps {
            let request = LoginStartRequest {
                caller: LoginFixture::caller(),
                name: self.cell.name,
                credential: self.cell.credential,
                lookup: self.cell.lookup,
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

fn entries(f: &LoginFixture, mix: &mut Mix) -> Vec<&'static Entry> {
    (0..SERVER_POOL as u32)
        .map(|n| {
            let id = CredentialId::from_bytes(mix.array::<16>());
            let name = name_of('k', n);
            let made_up_id = fake_credential_id(&f.prelogin, &name);
            let entry = Entry {
                made_up: made_up_record(&f.keys, &f.prelogin, &made_up_id, 1),
                made_up_id,
                real: f.register(&id, FIXTURE_PASSWORD),
                id,
                name,
            };
            // Bench data, kept for the life of the process.
            &*Box::leak(Box::new(entry))
        })
        .collect()
}

fn start_target(mix: &mut Mix, name: &'static str, kind: StartKind) -> Start {
    let f = LoginFixture::new();
    let (ke1, _) = f.client_start(FIXTURE_PASSWORD, "dudect client");
    let entries = entries(&f, mix);
    let first = entries[0];
    let cell = Cell {
        name: &first.name,
        credential: first.id,
        lookup: AccountLookup::Active {
            record: &first.real,
            sk_hint: true,
        },
    };
    Start {
        name,
        kind,
        f,
        clock: FixedClock,
        ke1,
        entries,
        tape: RefCell::new(Tape::new(mix.next())),
        cell,
        touched: 0,
    }
}

// ---------------------------------------------------------------- prelogin

/// What a prelogin target times.
#[derive(Clone, Copy)]
enum PreloginMode {
    /// `prelogin_answer` of the library: the made-up answer is always
    /// computed, the lookup is unpacked as in `login_start`, and the profile
    /// and hint are chosen with `ct_select_u8`.
    Answer,
    /// `resolve_credential` with `Some(account)` or `None` (information only):
    /// the account id is chosen between two references and read once.
    Resolve,
}

/// A name of the pool with its account and record. Leaked once, so the lookup
/// can point into it and be built before the timer starts.
struct PreloginEntry {
    name: NormalizedLoginName,
    account: AccountId,
    record: StoredRecord,
}

struct Prelogin {
    mode: PreloginMode,
    f: LoginFixture,
    entries: Vec<&'static PreloginEntry>,
    // What the timed code reads, set by `prepare`.
    name: &'static NormalizedLoginName,
    lookup: AccountLookup<'static>,
    account: Option<&'static AccountId>,
    /// Keeps the reads of `prepare` from being optimised away.
    touched: u64,
}

impl Target for Prelogin {
    fn name(&self) -> &'static str {
        match self.mode {
            PreloginMode::Resolve => "info_server_prelogin_resolve_credential",
            PreloginMode::Answer => "server_prelogin_known_vs_unknown",
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
        let e = self.entries[i % SERVER_POOL];
        // The same name for both classes: the time of the HMAC over a name
        // varies with the name, and two pools of names would give the
        // classes a different mean however many measurements are made. The
        // record and the account are read for either class, and the lookup
        // and the reference are built here, so the timed code has no branch
        // of its own on the class.
        self.touched = touch(&e.record).wrapping_add(u64::from(e.account.as_bytes()[0]));
        self.name = &e.name;
        let right = class == Class::Right;
        self.lookup = if right {
            AccountLookup::Unknown
        } else {
            AccountLookup::Active {
                record: &e.record,
                sk_hint: false,
            }
        };
        self.account = if right { None } else { Some(&e.account) };
    }
    fn run(&self, reps: u32) -> u64 {
        let mut acc = black_box(self.touched) & 0;
        for _ in 0..reps {
            match self.mode {
                PreloginMode::Answer => {
                    let answer = prelogin_answer(
                        &self.f.prelogin,
                        black_box(self.name),
                        &self.f.policy,
                        self.lookup,
                    );
                    acc = acc
                        .wrapping_add(u64::from(answer.ksf_profile))
                        .wrapping_add(u64::from(answer.sk_hint));
                }
                PreloginMode::Resolve => {
                    let id = resolve_credential(
                        &self.f.prelogin,
                        black_box(self.name),
                        black_box(self.account),
                    );
                    acc = acc.wrapping_add(u64::from(id.as_bytes()[0]));
                }
            }
        }
        black_box(acc)
    }
}

fn prelogin_target(mix: &mut Mix, mode: PreloginMode) -> Prelogin {
    let f = LoginFixture::new();
    let entries: Vec<&'static PreloginEntry> = (0..SERVER_POOL as u32)
        .map(|n| {
            let entry = PreloginEntry {
                name: name_of('k', n),
                account: AccountId::from_bytes(mix.array::<16>()),
                record: f.record.clone(),
            };
            // Bench data, kept for the life of the process.
            &*Box::leak(Box::new(entry))
        })
        .collect();
    let first = entries[0];
    Prelogin {
        mode,
        name: &first.name,
        lookup: AccountLookup::Unknown,
        account: Some(&first.account),
        entries,
        touched: 0,
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
            StartKind::KnownVsUnknown,
        )),
        Box::new(start_target(
            mix,
            "server_login_start_known_vs_disabled",
            StartKind::KnownVsDisabled,
        )),
        Box::new(start_target(
            mix,
            "control_server_login_start_null",
            StartKind::Null,
        )),
        Box::new(start_target(
            mix,
            "info_server_login_start_lookup_only",
            StartKind::LookupOnly,
        )),
        Box::new(start_target(
            mix,
            "info_server_login_start_real_vs_made_up",
            StartKind::RealVsMadeUp,
        )),
        Box::new(prelogin_target(mix, PreloginMode::Answer)),
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

#[cfg(test)]
mod tests {
    use super::*;

    /// Every target builds, and runs for both classes and several inputs.
    #[test]
    fn every_server_target_builds_and_runs_for_both_classes() {
        let mut mix = Mix::new(1);
        for mut target in targets(&mut mix) {
            for i in 0..4 {
                for class in [Class::Left, Class::Right] {
                    target.prepare(class, i);
                    let _ = target.run(target.reps());
                }
            }
        }
    }

    /// In the lookup-only bench both classes give `login_start` the same
    /// bytes to work on, so the answers are the same: the made-up record
    /// handed over as an account's own gives the answer of an unknown name.
    #[test]
    fn the_lookup_only_bench_gives_the_same_answer_in_both_classes() {
        let mut mix = Mix::new(2);
        let target = start_target(&mut mix, "t", StartKind::LookupOnly);
        let answer = |target: &mut Start, class| {
            target.prepare(class, 3);
            let cx = cx(&target.f, &target.clock);
            let request = LoginStartRequest {
                caller: LoginFixture::caller(),
                name: target.cell.name,
                credential: target.cell.credential,
                lookup: target.cell.lookup,
                purpose: LoginPurpose::Login,
                session_scope: None,
                ke1: &target.ke1,
            };
            let mut tape = target.tape.borrow_mut();
            tape.rewind();
            let response = login_start(&cx, &NullStore, &mut *tape, &request).unwrap();
            (response.ke2, response.ksf_profile, response.sk_hint)
        };
        let mut target = target;
        let left = answer(&mut target, Class::Left);
        let right = answer(&mut target, Class::Right);
        assert_eq!(left, right);
    }
}
