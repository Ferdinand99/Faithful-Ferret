//! Where sealed login states wait between the two sign-in steps: a table in the
//! database, read on a short connection of its own.

use std::path::Path;
use std::sync::Arc;

use ferret_server_auth::{
    Clock, InMemoryLoginStateStore, LoginStateStore, SealedState, StateKey,
    StoreError as LoginStoreError,
};

use crate::error::{NotImplemented, StoreError};

/// The login state store. For now it keeps the states in memory (`in_memory`)
/// and cannot be opened on the database yet.
pub struct SqliteLoginStateStore {
    memory: InMemoryLoginStateStore,
}

impl SqliteLoginStateStore {
    /// Opens the store on the database file. Not yet built: it says so.
    pub fn open(_db_path: &Path) -> Result<Self, StoreError> {
        Err(NotImplemented("the SQLite login state store").into())
    }

    /// A store that lives in memory, for tests.
    pub fn in_memory() -> Self {
        Self {
            memory: InMemoryLoginStateStore::new(),
        }
    }
}

impl LoginStateStore for SqliteLoginStateStore {
    fn put(
        &self,
        key: StateKey,
        sealed: SealedState,
        expires_at: u64,
        now: u64,
    ) -> Result<(), LoginStoreError> {
        self.memory.put(key, sealed, expires_at, now)
    }

    fn take(&self, key: &StateKey, now: u64) -> Result<Option<SealedState>, LoginStoreError> {
        self.memory.take(key, now)
    }

    fn purge_expired(&self, now: u64) -> Result<usize, LoginStoreError> {
        self.memory.purge_expired(now)
    }
}

/// Removes expired states every minute (not yet).
pub fn spawn_purge(_store: Arc<SqliteLoginStateStore>, _clock: Arc<dyn Clock>) {}
