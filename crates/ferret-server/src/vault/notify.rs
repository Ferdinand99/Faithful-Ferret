//! Wake-ups for the event streams: "something changed in this vault" and
//! "this session was revoked". Spec: Fase 1 § 8.2, § 7.6.
//!
//! A notification carries a vault id and a sequence number, never content, and
//! it is only a hint: a client that hears it fetches the rows itself and checks
//! them. A notification that nobody hears is dropped without a trace, and a
//! subscriber that falls more than the capacity behind loses the oldest ones
//! (it sees `Lagged` and fetches anyway), so a slow stream can never hold up a
//! write.

use tokio::sync::broadcast;

use crate::ids::{SidHash, VaultId};

/// How many notifications of each kind wait for a slow subscriber.
pub const CAPACITY: usize = 1024;

/// A vault whose sequence number moved.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VaultChange {
    /// The vault that changed.
    pub vault: VaultId,
    /// Its sequence number after the change.
    pub seq: u64,
}

/// The two channels the event streams listen to. Cheap to clone: every clone
/// sends on and subscribes to the same channels.
#[derive(Clone)]
pub struct SyncEvents {
    changes: broadcast::Sender<VaultChange>,
    revocations: broadcast::Sender<SidHash>,
}

impl SyncEvents {
    /// Channels that keep `capacity` notifications each for a slow subscriber
    /// (at least one).
    pub fn new(capacity: usize) -> Self {
        let capacity = capacity.max(1);
        Self {
            changes: broadcast::channel(capacity).0,
            revocations: broadcast::channel(capacity).0,
        }
    }

    /// Tells the streams that `vault` is now at `seq`. Never fails: with no
    /// stream open, nobody hears it.
    pub fn notify(&self, vault: VaultId, seq: u64) {
        let _ = self.changes.send(VaultChange { vault, seq });
    }

    /// A receiver of the changes sent from now on.
    pub fn subscribe(&self) -> broadcast::Receiver<VaultChange> {
        self.changes.subscribe()
    }

    /// Tells the streams that the session with this hash is over, so the
    /// stream of that session closes at once. Never fails.
    pub fn session_revoked(&self, sid: SidHash) {
        let _ = self.revocations.send(sid);
    }

    /// A receiver of the revocations sent from now on.
    pub fn subscribe_revocations(&self) -> broadcast::Receiver<SidHash> {
        self.revocations.subscribe()
    }
}
