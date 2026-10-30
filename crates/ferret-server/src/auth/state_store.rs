//! Where sealed login states wait between the two sign-in steps: a table in the
//! database (`ferret_login_states`), read and written on a short connection of
//! its own.
//!
//! The store holds sealed bytes under the hash of the login id. It cannot read
//! what it holds and keeps no value a client could present. It follows the
//! rules of [`LoginStateStore`]:
//!
//! * `take` removes the row and reads it in one statement (`DELETE ...
//!   RETURNING`), so two connections, or two processes, can never both get a
//!   state. A state that has expired is removed too, and not returned.
//! * `put` refuses a state that is already expired (and any call at
//!   `u64::MAX`), refuses a live state under the same key, and when the table is
//!   at its limit removes the oldest row first. All of that is one immediate
//!   transaction, so the limit holds across connections.
//! * The age of a row is its `rowid`: SQLite hands out a rowid above every
//!   existing one, so the smallest rowid is the oldest state.
//!
//! The table comes from the migrations; `open` refuses a database that does not
//! have it. Every failure of the database is [`LoginStoreError::Backend`]: the
//! caller can only refuse the request, and the cause goes to the log.

use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use ferret_server_auth::{
    Clock, InMemoryLoginStateStore, LoginStateStore, SealedState, StateKey,
    StoreError as LoginStoreError,
};
use rusqlite::{Connection, OptionalExtension as _, TransactionBehavior, params};

use crate::error::StoreError;

/// The migration that makes the table. The in-memory store runs it as it is,
/// so there is one text of the table.
const AUTH_MIGRATION: &str = include_str!("../../migrations/0002_auth.sql");

/// How often expired states are removed.
const PURGE_EVERY: Duration = Duration::from_secs(60);

/// The login state store on SQLite.
///
/// One connection of its own, behind a mutex. Several stores on one file (two
/// connections, or two processes) are safe: every change is a single statement
/// or an immediate transaction.
pub struct SqliteLoginStateStore {
    /// `None` only for an in-memory store that could not be made: every call
    /// then fails with `Backend`.
    conn: Mutex<Option<Connection>>,
    capacity: usize,
}

impl SqliteLoginStateStore {
    /// The default limit on the number of states, as in the memory store.
    pub const DEFAULT_CAPACITY: usize = InMemoryLoginStateStore::DEFAULT_CAPACITY;

    /// Opens the store on the database file with the default limit. The
    /// database must be migrated: a file without the table is an error.
    pub fn open(db_path: &Path) -> Result<Self, StoreError> {
        Self::open_with_capacity(db_path, Self::DEFAULT_CAPACITY)
    }

    /// Opens the store on the database file; it holds at most `capacity`
    /// states.
    pub fn open_with_capacity(db_path: &Path, capacity: usize) -> Result<Self, StoreError> {
        let conn = Connection::open(db_path)?;
        conn.execute_batch("PRAGMA busy_timeout = 5000;")?;
        // WAL is a property of the file, set by the kit's pool already; asking
        // again keeps this store right when it is the first to open the file.
        conn.query_row("PRAGMA journal_mode = WAL", [], |row| {
            row.get::<_, String>(0)
        })?;
        conn.execute_batch("PRAGMA synchronous = NORMAL;")?;
        // Fails when the table is missing (a database that was not migrated).
        conn.prepare("SELECT key, sealed, expires_at FROM ferret_login_states LIMIT 0")?;
        Ok(Self {
            conn: Mutex::new(Some(conn)),
            capacity,
        })
    }

    /// A store that lives in memory, for tests.
    pub fn in_memory() -> Self {
        Self::in_memory_with_capacity(Self::DEFAULT_CAPACITY)
    }

    /// A store in memory that holds at most `capacity` states.
    pub fn in_memory_with_capacity(capacity: usize) -> Self {
        let conn = Connection::open_in_memory()
            .and_then(|conn| conn.execute_batch(AUTH_MIGRATION).map(|()| conn))
            .map_err(|e| tracing::error!("can't make the in-memory login state store: {e}"))
            .ok();
        Self {
            conn: Mutex::new(conn),
            capacity,
        }
    }

    /// Runs `f` on the connection. A poisoned lock or a store that could not
    /// be made is `Backend`.
    fn with<T>(
        &self,
        f: impl FnOnce(&mut Connection) -> rusqlite::Result<T>,
    ) -> Result<T, LoginStoreError> {
        let mut guard = self.conn.lock().map_err(|_| LoginStoreError::Backend)?;
        let conn = guard.as_mut().ok_or(LoginStoreError::Backend)?;
        f(conn).map_err(backend)
    }
}

/// Logs what SQLite said (no state, key or secret is in it) and gives the
/// store's one answer for a database failure.
fn backend(error: rusqlite::Error) -> LoginStoreError {
    tracing::error!("login state store: {error}");
    LoginStoreError::Backend
}

/// A moment as the database holds it. A moment past `i64::MAX` (which no clock
/// reaches) is the latest the database can hold.
fn to_db(moment: u64) -> i64 {
    i64::try_from(moment).unwrap_or(i64::MAX)
}

impl LoginStateStore for SqliteLoginStateStore {
    fn put(
        &self,
        key: StateKey,
        sealed: SealedState,
        expires_at: u64,
        now: u64,
    ) -> Result<(), LoginStoreError> {
        // This includes `now == u64::MAX`, whatever the expiry.
        if now >= expires_at {
            return Err(LoginStoreError::Expired);
        }
        if self.capacity == 0 {
            return Err(LoginStoreError::Full);
        }
        // A clock past what the database can hold has failed.
        let now_db = i64::try_from(now).map_err(|_| LoginStoreError::Expired)?;
        let capacity = i64::try_from(self.capacity).unwrap_or(i64::MAX);
        let expires_db = to_db(expires_at);
        self.with(|conn| {
            let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
            // An expired state under the key counts as absent.
            tx.execute(
                "DELETE FROM ferret_login_states WHERE key = ?1 AND expires_at <= ?2",
                params![key.as_bytes().as_slice(), now_db],
            )?;
            let taken = tx
                .query_row(
                    "SELECT 1 FROM ferret_login_states WHERE key = ?1",
                    [key.as_bytes().as_slice()],
                    |_| Ok(()),
                )
                .optional()?
                .is_some();
            if taken {
                // A live state is never overwritten; nothing else changes.
                return Ok(Err(LoginStoreError::Collision));
            }
            // Room for one more: the oldest rows go first, whatever their expiry.
            let count: i64 =
                tx.query_row("SELECT COUNT(*) FROM ferret_login_states", [], |r| r.get(0))?;
            if count >= capacity {
                tx.execute(
                    "DELETE FROM ferret_login_states WHERE rowid IN \
                     (SELECT rowid FROM ferret_login_states ORDER BY rowid LIMIT ?1)",
                    [count.saturating_sub(capacity).saturating_add(1)],
                )?;
            }
            tx.execute(
                "INSERT INTO ferret_login_states (key, sealed, expires_at) VALUES (?1, ?2, ?3)",
                params![key.as_bytes().as_slice(), sealed.as_bytes(), expires_db],
            )?;
            tx.commit()?;
            Ok(Ok(()))
        })?
    }

    fn take(&self, key: &StateKey, now: u64) -> Result<Option<SealedState>, LoginStoreError> {
        let row: Option<(Vec<u8>, i64)> = self.with(|conn| {
            // One statement: the row is removed and read together, so a second
            // taker, on this connection or another, finds nothing. An expired
            // row is removed as well and not handed out.
            conn.query_row(
                "DELETE FROM ferret_login_states WHERE key = ?1 RETURNING sealed, expires_at",
                [key.as_bytes().as_slice()],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()
        })?;
        Ok(row.and_then(|(sealed, expires_at)| {
            // A negative expiry cannot be written by this store; it reads as
            // expired.
            let expires_at = u64::try_from(expires_at).unwrap_or(0);
            (now < expires_at).then(|| SealedState::from_bytes(sealed))
        }))
    }

    fn purge_expired(&self, now: u64) -> Result<usize, LoginStoreError> {
        let now_db = to_db(now);
        self.with(|conn| {
            conn.execute(
                "DELETE FROM ferret_login_states WHERE expires_at <= ?1",
                [now_db],
            )
        })
    }
}

/// Removes expired states every minute, on a task of the runtime. Call it
/// inside the runtime.
pub fn spawn_purge(store: Arc<SqliteLoginStateStore>, clock: Arc<dyn Clock>) {
    spawn_purge_every(store, clock, PURGE_EVERY);
}

/// [`spawn_purge`] with another period (tests use a short one).
pub fn spawn_purge_every(
    store: Arc<SqliteLoginStateStore>,
    clock: Arc<dyn Clock>,
    period: Duration,
) {
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(period);
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            tick.tick().await;
            let (store, now) = (store.clone(), clock.now_unix());
            match tokio::task::spawn_blocking(move || store.purge_expired(now)).await {
                Ok(Ok(removed)) if removed > 0 => {
                    tracing::debug!(removed, "expired login states removed");
                }
                // `backend` has logged a database error.
                Ok(_) => {}
                Err(e) => tracing::error!("login state purge task failed: {e}"),
            }
        }
    });
}
