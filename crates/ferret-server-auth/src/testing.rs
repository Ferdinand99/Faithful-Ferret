//! Helpers for tests of this crate and of the crates that build on it. Behind
//! the `test-support` feature, which is never part of a release build.
//!
//! * [`conformance`] is the set of checks every [`LoginStateStore`] must
//!   pass. The memory store runs it in this crate; the database store of the
//!   next layer runs the same checks.
//! * [`state_plain_wipe_probe`] lets a test crate look at the memory of a
//!   sealed state's content before and after it is dropped.
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
