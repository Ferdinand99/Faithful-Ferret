//! The login state store: the checks every store must pass, run against the
//! memory store, and the properties that belong to the memory store alone.

use ferret_server_auth::testing::{self, conformance, sealed_blob, state_key};
use ferret_server_auth::{InMemoryLoginStateStore, LoginStateStore, StoreError};

fn make(capacity: usize) -> InMemoryLoginStateStore {
    InMemoryLoginStateStore::with_capacity(capacity)
}

#[test]
fn memory_store_passes_the_conformance_suite() {
    conformance(make);
}

#[test]
fn put_then_take_returns_once() {
    testing::put_then_take_returns_once(make);
}

#[test]
fn take_unknown_key_is_none() {
    testing::take_unknown_key_is_none(make);
}

#[test]
fn expiry_boundary() {
    testing::expiry_boundary(make);
}

#[test]
fn expired_entries_are_removed_by_take_and_purge() {
    testing::expired_entries_are_removed_by_take_and_purge(make);
}

#[test]
fn put_same_key_twice_is_collision() {
    testing::put_same_key_twice_is_collision(make);
}

#[test]
fn capacity_evicts_oldest_first() {
    testing::capacity_evicts_oldest_first(make);
}

#[test]
fn concurrent_take_yields_exactly_one() {
    testing::concurrent_take_yields_exactly_one(make);
}

#[test]
fn concurrent_put_and_take_never_duplicate() {
    testing::concurrent_put_and_take_never_duplicate(make);
}

#[test]
fn the_default_store_holds_20_000_states() {
    assert_eq!(InMemoryLoginStateStore::DEFAULT_CAPACITY, 20_000);
    let store = InMemoryLoginStateStore::default();
    assert!(store.is_empty());
    // Fill it, then one more: the oldest goes, the count stays at the limit.
    for n in 0..20_000u32 {
        store.put(state_key(n), sealed_blob(n), 1_000, 0).unwrap();
    }
    assert_eq!(store.len(), 20_000);
    store
        .put(state_key(20_000), sealed_blob(20_000), 1_000, 0)
        .unwrap();
    assert_eq!(store.len(), 20_000);
    assert!(store.take(&state_key(0), 1).unwrap().is_none());
    assert!(store.take(&state_key(1), 1).unwrap().is_some());
    assert_eq!(store.len(), 19_999);
}

#[test]
fn len_counts_what_is_held() {
    let store = make(10);
    for n in 0..3 {
        store.put(state_key(n), sealed_blob(n), 100, 0).unwrap();
    }
    assert_eq!(store.len(), 3);
    assert!(!store.is_empty());
    // An expired state still counts until a take or a purge removes it.
    assert_eq!(store.purge_expired(100).unwrap(), 3);
    assert!(store.is_empty());
}

#[test]
fn a_store_with_no_room_refuses() {
    let store = make(0);
    assert_eq!(
        store.put(state_key(1), sealed_blob(1), 100, 0),
        Err(StoreError::Full)
    );
}

#[test]
fn the_store_works_behind_a_trait_object_across_threads() {
    fn assert_send_sync<T: Send + Sync + ?Sized>() {}
    assert_send_sync::<dyn LoginStateStore>();
    assert_send_sync::<InMemoryLoginStateStore>();
}

/// Stores with one deliberate mistake each. The checks of the suite must
/// notice every one of them, or they would pass for any store.
mod broken_stores {
    use std::sync::Mutex;
    use std::time::Duration;

    use ferret_server_auth::testing;
    use ferret_server_auth::{LoginStateStore, SealedState, StateKey, StoreError};

    #[derive(Clone, Copy)]
    enum Mistake {
        /// `take` reads, lets go of the lock, and removes later.
        NonAtomicTake,
        /// `put` overwrites a live state.
        OverwriteOnPut,
        /// A state is still valid in the second of its expiry.
        ExpiresInclusive,
        /// A full store refuses instead of making room.
        NoEviction,
        /// A full store removes the newest state instead of the oldest.
        NewestOut,
        /// `take` hands out the state but leaves it in the store.
        TakeKeeps,
    }

    struct Broken {
        mistake: Option<Mistake>,
        capacity: usize,
        /// Oldest first.
        states: Mutex<Vec<(StateKey, Vec<u8>, u64)>>,
    }

    impl Broken {
        fn new(mistake: Option<Mistake>, capacity: usize) -> Self {
            Self {
                mistake,
                capacity,
                states: Mutex::new(Vec::new()),
            }
        }

        fn live(&self, expires_at: u64, now: u64) -> bool {
            match self.mistake {
                Some(Mistake::ExpiresInclusive) => now <= expires_at,
                _ => now < expires_at,
            }
        }
    }

    impl LoginStateStore for Broken {
        fn put(
            &self,
            key: StateKey,
            sealed: SealedState,
            expires_at: u64,
            now: u64,
        ) -> Result<(), StoreError> {
            let mut states = self.states.lock().unwrap();
            if let Some(at) = states.iter().position(|(k, _, _)| *k == key) {
                let live = self.live(states[at].2, now);
                if live && !matches!(self.mistake, Some(Mistake::OverwriteOnPut)) {
                    return Err(StoreError::Collision);
                }
                states.remove(at);
            }
            if states.len() >= self.capacity {
                match self.mistake {
                    Some(Mistake::NoEviction) => return Err(StoreError::Full),
                    Some(Mistake::NewestOut) => {
                        states.pop();
                    }
                    _ => {
                        states.remove(0);
                    }
                }
            }
            states.push((key, sealed.into_bytes(), expires_at));
            Ok(())
        }

        fn take(&self, key: &StateKey, now: u64) -> Result<Option<SealedState>, StoreError> {
            let entry = match self.mistake {
                Some(Mistake::NonAtomicTake) => {
                    // Read, let go of the lock, remove later.
                    let found = {
                        let states = self.states.lock().unwrap();
                        states.iter().find(|(k, _, _)| k == key).cloned()
                    };
                    std::thread::sleep(Duration::from_millis(2));
                    self.states.lock().unwrap().retain(|(k, _, _)| k != key);
                    found
                }
                Some(Mistake::TakeKeeps) => {
                    let states = self.states.lock().unwrap();
                    states.iter().find(|(k, _, _)| k == key).cloned()
                }
                _ => {
                    // Find and remove under one lock.
                    let mut states = self.states.lock().unwrap();
                    states
                        .iter()
                        .position(|(k, _, _)| k == key)
                        .map(|at| states.remove(at))
                }
            };
            Ok(entry.and_then(|(_, bytes, expires_at)| {
                self.live(expires_at, now)
                    .then(|| SealedState::from_bytes(bytes))
            }))
        }

        fn purge_expired(&self, now: u64) -> Result<usize, StoreError> {
            let mut states = self.states.lock().unwrap();
            let before = states.len();
            states.retain(|(_, _, expires_at)| self.live(*expires_at, now));
            Ok(before - states.len())
        }
    }

    fn make(mistake: Option<Mistake>) -> impl Fn(usize) -> Broken {
        move |capacity| Broken::new(mistake, capacity)
    }

    #[test]
    fn the_model_without_a_mistake_passes() {
        testing::conformance(make(None));
    }

    #[test]
    #[should_panic(expected = "assertion")]
    fn a_take_that_is_not_atomic_is_caught() {
        testing::concurrent_take_yields_exactly_one(make(Some(Mistake::NonAtomicTake)));
    }

    #[test]
    #[should_panic(expected = "assertion")]
    fn a_take_that_is_not_atomic_is_caught_with_writers() {
        testing::concurrent_put_and_take_never_duplicate(make(Some(Mistake::NonAtomicTake)));
    }

    #[test]
    #[should_panic(expected = "assertion")]
    fn a_take_that_keeps_the_state_is_caught() {
        testing::put_then_take_returns_once(make(Some(Mistake::TakeKeeps)));
    }

    #[test]
    #[should_panic(expected = "assertion")]
    fn an_overwriting_put_is_caught() {
        testing::put_same_key_twice_is_collision(make(Some(Mistake::OverwriteOnPut)));
    }

    #[test]
    #[should_panic(expected = "assertion")]
    fn an_expiry_that_is_one_second_late_is_caught() {
        testing::expiry_boundary(make(Some(Mistake::ExpiresInclusive)));
    }

    #[test]
    #[should_panic(expected = "assertion")]
    fn a_purge_with_the_same_mistake_is_caught() {
        testing::expired_entries_are_removed_by_take_and_purge(make(Some(
            Mistake::ExpiresInclusive,
        )));
    }

    #[test]
    #[should_panic]
    fn a_full_store_that_refuses_is_caught() {
        testing::capacity_evicts_oldest_first(make(Some(Mistake::NoEviction)));
    }

    #[test]
    #[should_panic(expected = "assertion")]
    fn a_full_store_that_drops_the_newest_is_caught() {
        testing::capacity_evicts_oldest_first(make(Some(Mistake::NewestOut)));
    }
}
