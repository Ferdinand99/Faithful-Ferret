//! Wake-ups for the event streams: "something changed in this vault", and
//! "this session was revoked" or "this device was revoked". Spec: Fase 1
//! § 8.2, § 7.6.
//!
//! A notification carries a vault id and a sequence number, never content, and
//! it is only a hint: a client that hears it fetches the rows itself and checks
//! them. A notification that nobody hears is dropped without a trace, and a
//! subscriber that falls more than the capacity behind loses the oldest ones
//! (it sees `Lagged` and fetches anyway), so a slow stream can never hold up a
//! write.

use tokio::sync::broadcast;

use crate::auth::session::Ended;
use crate::ids::{DeviceId, SidHash, VaultId};

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

/// What ended, so the streams that belong to it close at once: one session
/// (its id's hash), or a device that signed in for tokens (its id). A
/// device of the web vault is a session, so a cookie stream closes only for
/// `Session`.
///
/// Spec: Fase 1 § 7.6 (revocation closes all open streams of the device).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Revoked {
    /// The session with this hash ended.
    Session(SidHash),
    /// The token device with this id was revoked.
    Device(DeviceId),
}

/// The two channels the event streams listen to. Cheap to clone: every clone
/// sends on and subscribes to the same channels.
#[derive(Clone)]
pub struct SyncEvents {
    changes: broadcast::Sender<VaultChange>,
    revocations: broadcast::Sender<Revoked>,
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
        let _ = self.revocations.send(Revoked::Session(sid));
    }

    /// Tells the streams that the token device `device` was revoked, so its
    /// streams close at once. Never fails.
    pub fn device_revoked(&self, device: DeviceId) {
        let _ = self.revocations.send(Revoked::Device(device));
    }

    /// Tells the streams about everything a bulk end of credentials ended
    /// (`session::end_all_credentials` and the routes of the list of devices):
    /// `session_revoked` for each session and `device_revoked` for each
    /// device, so every stream of each closes at once. Call it after the
    /// commit, never before: a stream that wakes up must find its row ended.
    ///
    /// Spec: Fase 1 § 7.6 (revocation closes all open streams of the device).
    pub fn announce_ended(&self, ended: &Ended) {
        for sid in &ended.sessions {
            self.session_revoked(*sid);
        }
        for device in &ended.devices {
            self.device_revoked(*device);
        }
    }

    /// A receiver of the revocations sent from now on.
    pub fn subscribe_revocations(&self) -> broadcast::Receiver<Revoked> {
        self.revocations.subscribe()
    }
}
