//! The login state store on SQLite: the conformance suite of the OPAQUE
//! library, and what only a database can get wrong (two connections on one
//! file, a database that was not migrated, a restart).

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU32, AtomicUsize, Ordering};
use std::sync::{Arc, Barrier};
use std::time::Duration;

use ferret_server::auth::state_store::{SqliteLoginStateStore, spawn_purge_every};
use ferret_server_auth::testing::{self, sealed_blob, state_key};
use ferret_server_auth::{Clock, LoginStateStore, ManualClock, StoreError};
use rusqlite::Connection;

const AUTH_MIGRATION: &str = include_str!("../migrations/0002_auth.sql");

/// A directory that is removed again at the end of the test.
struct TempDir(PathBuf);

impl TempDir {
    fn new() -> Self {
        static COUNTER: AtomicU32 = AtomicU32::new(0);
        let path = std::env::temp_dir().join(format!(
            "ferret-state-store-{}-{}",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&path).unwrap();
        Self(path)
    }

    /// A new database file with the table of the login states.
    fn database(&self, name: &str) -> PathBuf {
        let path = self.0.join(name);
        Connection::open(&path)
            .unwrap()
            .execute_batch(AUTH_MIGRATION)
            .unwrap();
        path
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// Stores on a fresh file each, as `make(capacity)` of the suite asks.
struct Files {
    dir: TempDir,
    next: AtomicU32,
}

impl Files {
    fn new() -> Self {
        Self {
            dir: TempDir::new(),
            next: AtomicU32::new(0),
        }
    }

    fn make(&self, capacity: usize) -> SqliteLoginStateStore {
        let name = format!("db-{}.sqlite", self.next.fetch_add(1, Ordering::Relaxed));
        let path = self.dir.database(&name);
        SqliteLoginStateStore::open_with_capacity(&path, capacity).unwrap()
    }
}

fn rows(path: &Path) -> i64 {
    Connection::open(path)
        .unwrap()
        .query_row("SELECT COUNT(*) FROM ferret_login_states", [], |r| r.get(0))
        .unwrap()
}

// ------------------------------------------------- the library's own suite

#[test]
fn the_whole_suite_passes_on_a_file() {
    let files = Files::new();
    testing::conformance(|capacity| files.make(capacity));
}

#[test]
fn the_whole_suite_passes_in_memory() {
    testing::conformance(SqliteLoginStateStore::in_memory_with_capacity);
}

macro_rules! conformance_case {
    ($($name:ident),* $(,)?) => {$(
        #[test]
        fn $name() {
            let files = Files::new();
            testing::$name(|capacity| files.make(capacity));
        }
    )*};
}

conformance_case!(
    put_then_take_returns_once,
    take_unknown_key_is_none,
    expiry_boundary,
    expired_entries_are_removed_by_take_and_purge,
    put_same_key_twice_is_collision,
    put_of_an_expired_entry_is_refused,
    capacity_evicts_oldest_first,
    concurrent_take_yields_exactly_one,
    concurrent_put_and_take_never_duplicate,
    concurrent_put_respects_capacity,
);

// ------------------------------------------------------------- the rest

#[test]
fn the_default_limit_is_the_one_of_the_memory_store() {
    assert_eq!(SqliteLoginStateStore::DEFAULT_CAPACITY, 20_000);
}

#[test]
fn a_store_that_cannot_hold_a_state_is_full() {
    let files = Files::new();
    let store = files.make(0);
    assert_eq!(
        store.put(state_key(1), sealed_blob(1), 1_100, 1_000),
        Err(StoreError::Full)
    );
}

#[test]
fn purge_removes_only_expired() {
    let files = Files::new();
    let store = files.make(100);
    store
        .put(state_key(1), sealed_blob(1), 1_100, 1_000)
        .unwrap();
    store
        .put(state_key(2), sealed_blob(2), 1_100, 1_000)
        .unwrap();
    store
        .put(state_key(3), sealed_blob(3), 1_200, 1_000)
        .unwrap();
    store
        .put(state_key(4), sealed_blob(4), 1_300, 1_000)
        .unwrap();
    // Nothing has expired yet.
    assert_eq!(store.purge_expired(1_099).unwrap(), 0);
    // Two expire at 1_100 and not one second before.
    assert_eq!(store.purge_expired(1_100).unwrap(), 2);
    assert_eq!(store.purge_expired(1_100).unwrap(), 0);
    // The others are still there, and only they.
    assert!(store.take(&state_key(1), 1_100).unwrap().is_none());
    assert!(store.take(&state_key(3), 1_100).unwrap().is_some());
    assert_eq!(store.purge_expired(1_250).unwrap(), 0);
    assert!(store.take(&state_key(4), 1_250).unwrap().is_some());
}

#[test]
fn take_is_atomic_across_two_connections() {
    const THREADS: usize = 16;
    let dir = TempDir::new();
    let path = dir.database("atomic.sqlite");
    let (a, b) = (
        SqliteLoginStateStore::open(&path).unwrap(),
        SqliteLoginStateStore::open(&path).unwrap(),
    );
    for round in 0..30u32 {
        // Put on one connection, take on both at once.
        a.put(
            state_key(round),
            sealed_blob(round),
            1_060 + u64::from(round),
            1_000,
        )
        .unwrap();
        let barrier = Barrier::new(THREADS * 2);
        let winners = AtomicUsize::new(0);
        std::thread::scope(|scope| {
            for store in [&a, &b] {
                for _ in 0..THREADS {
                    scope.spawn(|| {
                        barrier.wait();
                        if let Some(got) = store.take(&state_key(round), 1_001).unwrap() {
                            assert_eq!(got.as_bytes(), sealed_blob(round).as_bytes());
                            winners.fetch_add(1, Ordering::SeqCst);
                        }
                    });
                }
            }
        });
        assert_eq!(winners.load(Ordering::SeqCst), 1, "round {round}");
    }
    assert_eq!(rows(&path), 0);
}

#[test]
fn a_live_state_is_a_collision_across_two_connections() {
    const THREADS: usize = 8;
    let dir = TempDir::new();
    let path = dir.database("collision.sqlite");
    let (a, b) = (
        SqliteLoginStateStore::open(&path).unwrap(),
        SqliteLoginStateStore::open(&path).unwrap(),
    );
    for round in 0..20u32 {
        let barrier = Barrier::new(THREADS * 2);
        let stored = AtomicUsize::new(0);
        std::thread::scope(|scope| {
            for store in [&a, &b] {
                for thread in 0..THREADS {
                    let (barrier, stored) = (&barrier, &stored);
                    scope.spawn(move || {
                        barrier.wait();
                        let blob = sealed_blob(round * 100 + thread as u32);
                        match store.put(state_key(round), blob, 1_060, 1_000) {
                            Ok(()) => {
                                stored.fetch_add(1, Ordering::SeqCst);
                            }
                            Err(StoreError::Collision) => {}
                            Err(other) => panic!("put failed with {other:?}"),
                        }
                    });
                }
            }
        });
        assert_eq!(stored.load(Ordering::SeqCst), 1, "round {round}");
    }
}

#[test]
fn the_limit_holds_across_two_connections() {
    const LIMIT: usize = 7;
    let dir = TempDir::new();
    let path = dir.database("limit.sqlite");
    let a = SqliteLoginStateStore::open_with_capacity(&path, LIMIT).unwrap();
    let b = SqliteLoginStateStore::open_with_capacity(&path, LIMIT).unwrap();
    let barrier = Barrier::new(8);
    std::thread::scope(|scope| {
        for thread in 0..8u32 {
            let (store, barrier) = (if thread % 2 == 0 { &a } else { &b }, &barrier);
            scope.spawn(move || {
                barrier.wait();
                for n in 0..25u32 {
                    let id = thread * 25 + n;
                    store
                        .put(state_key(id), sealed_blob(id), 1_060, 1_000)
                        .unwrap();
                }
            });
        }
    });
    assert_eq!(rows(&path), LIMIT as i64);
}

#[test]
fn the_oldest_row_goes_first_after_rows_were_taken_and_purged() {
    // Row ids are reused above the highest one left; age must still be the
    // order of the puts.
    let dir = TempDir::new();
    let path = dir.database("age.sqlite");
    let store = SqliteLoginStateStore::open_with_capacity(&path, 3).unwrap();
    for n in 1..=3 {
        store
            .put(state_key(n), sealed_blob(n), 2_000, 1_000)
            .unwrap();
    }
    // Take the newest, then put two more: the table was at 2 rows, so the first
    // fits, the second pushes out state 1 (the oldest), not state 2.
    assert!(store.take(&state_key(3), 1_001).unwrap().is_some());
    store
        .put(state_key(4), sealed_blob(4), 2_000, 1_001)
        .unwrap();
    store
        .put(state_key(5), sealed_blob(5), 2_000, 1_001)
        .unwrap();
    assert!(store.take(&state_key(1), 1_002).unwrap().is_none());
    for n in [2, 4, 5] {
        assert!(store.take(&state_key(n), 1_002).unwrap().is_some(), "{n}");
    }
}

#[test]
fn states_survive_a_restart_of_the_store() {
    let dir = TempDir::new();
    let path = dir.database("restart.sqlite");
    {
        let store = SqliteLoginStateStore::open(&path).unwrap();
        store
            .put(state_key(1), sealed_blob(1), 1_060, 1_000)
            .unwrap();
        store
            .put(state_key(2), sealed_blob(2), 1_060, 1_000)
            .unwrap();
    }
    let store = SqliteLoginStateStore::open(&path).unwrap();
    let got = store.take(&state_key(1), 1_001).unwrap().unwrap();
    assert_eq!(got.as_bytes(), sealed_blob(1).as_bytes());
    // Taken once, gone for every later reader.
    drop(store);
    let store = SqliteLoginStateStore::open(&path).unwrap();
    assert!(store.take(&state_key(1), 1_001).unwrap().is_none());
    assert!(store.take(&state_key(2), 1_001).unwrap().is_some());
}

#[test]
fn a_database_without_the_table_is_refused() {
    let dir = TempDir::new();
    let path = dir.0.join("empty.sqlite");
    Connection::open(&path)
        .unwrap()
        .execute_batch("CREATE TABLE other (x INTEGER);")
        .unwrap();
    assert!(SqliteLoginStateStore::open(&path).is_err());
    // A path that cannot be opened is refused too, and nothing is made.
    let missing_dir = dir.0.join("no-such-directory").join("db.sqlite");
    assert!(SqliteLoginStateStore::open(&missing_dir).is_err());
    assert!(!missing_dir.exists());
}

#[test]
fn the_file_is_in_wal_mode() {
    let dir = TempDir::new();
    let path = dir.database("wal.sqlite");
    let _store = SqliteLoginStateStore::open(&path).unwrap();
    let mode: String = Connection::open(&path)
        .unwrap()
        .query_row("PRAGMA journal_mode", [], |r| r.get(0))
        .unwrap();
    assert_eq!(mode, "wal");
}

#[test]
fn the_table_holds_the_bytes_it_was_given_and_the_hash_key() {
    let dir = TempDir::new();
    let path = dir.database("bytes.sqlite");
    let store = SqliteLoginStateStore::open(&path).unwrap();
    store
        .put(state_key(7), sealed_blob(7), 1_060, 1_000)
        .unwrap();
    let (key, sealed, expires): (Vec<u8>, Vec<u8>, i64) = Connection::open(&path)
        .unwrap()
        .query_row(
            "SELECT key, sealed, expires_at FROM ferret_login_states",
            [],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )
        .unwrap();
    assert_eq!(key, state_key(7).as_bytes().to_vec());
    assert_eq!(sealed, sealed_blob(7).as_bytes().to_vec());
    assert_eq!(expires, 1_060);
}

#[test]
fn a_far_expiry_is_kept_and_a_far_clock_is_expired() {
    let files = Files::new();
    let store = files.make(10);
    // An expiry no database integer can hold is held as the latest moment.
    store
        .put(state_key(1), sealed_blob(1), u64::MAX - 1, 1_000)
        .unwrap();
    assert!(store.take(&state_key(1), 5_000).unwrap().is_some());
    // A clock past what the database holds is a failed clock: refused.
    assert_eq!(
        store.put(state_key(2), sealed_blob(2), u64::MAX - 1, u64::MAX / 2 + 1),
        Err(StoreError::Expired)
    );
    assert!(store.take(&state_key(2), 0).unwrap().is_none());
}

#[test]
fn the_memory_store_is_a_table_too() {
    let store = SqliteLoginStateStore::in_memory();
    store
        .put(state_key(1), sealed_blob(1), 1_060, 1_000)
        .unwrap();
    assert_eq!(
        store.put(state_key(1), sealed_blob(2), 1_070, 1_001),
        Err(StoreError::Collision)
    );
    let got = store.take(&state_key(1), 1_002).unwrap().unwrap();
    assert_eq!(got.as_bytes(), sealed_blob(1).as_bytes());
}

#[tokio::test]
async fn the_purge_task_removes_what_has_expired() {
    let dir = TempDir::new();
    let path = dir.database("purge-task.sqlite");
    let store = Arc::new(SqliteLoginStateStore::open(&path).unwrap());
    let clock = Arc::new(ManualClock::new(1_000));
    store
        .put(state_key(1), sealed_blob(1), 1_060, 1_000)
        .unwrap();
    store
        .put(state_key(2), sealed_blob(2), 1_200, 1_000)
        .unwrap();
    spawn_purge_every(
        store.clone(),
        clock.clone() as Arc<dyn Clock>,
        Duration::from_millis(20),
    );
    // While nothing has expired the task removes nothing.
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert_eq!(rows(&path), 2);
    clock.set(1_100);
    let mut left = rows(&path);
    for _ in 0..100 {
        if left == 1 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
        left = rows(&path);
    }
    assert_eq!(left, 1, "the expired state is removed, the live one stays");
    assert!(store.take(&state_key(2), 1_100).unwrap().is_some());
}
