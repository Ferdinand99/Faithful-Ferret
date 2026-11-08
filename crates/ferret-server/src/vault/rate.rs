//! Limits on writes: operations and bytes per minute for each device, how often
//! a device may upload a checkpoint, and the queue in front of the write
//! transactions. Spec: Fase 1 § 8.2.
//!
//! This is the shape of the limits and the handles the routes take. The
//! limiter here admits everything and the gate lets everyone in; the real
//! bodies come with the write path that uses them.

use std::sync::Arc;

use ferret_server_auth::Clock;

use crate::ids::{DeviceId, VaultId};

/// The numbers the limits run on.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RateConfig {
    /// Operations a device may do per minute, once the burst is used.
    pub ops_per_min: u32,
    /// Operations a device may do at once from a full bucket.
    pub ops_burst: u32,
    /// Request bytes a device may send per minute.
    pub bytes_per_min: u64,
    /// Seconds between two stored checkpoint uploads of one device.
    pub checkpoint_every_secs: u64,
    /// Buckets kept in memory at most; the oldest are dropped first.
    pub max_keys: usize,
    /// Devices of one vault that get a bucket each; further devices share one.
    pub max_devices_per_vault: usize,
}

impl RateConfig {
    /// The limits the server runs with.
    pub const DEFAULT: RateConfig = RateConfig {
        ops_per_min: 120,
        ops_burst: 300,
        bytes_per_min: 20 << 20,
        checkpoint_every_secs: 600,
        max_keys: 4096,
        max_devices_per_vault: 40,
    };
}

/// A request that a limit turned away.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Refused {
    /// Seconds until the same request may succeed; at least 1.
    pub retry_after_secs: u32,
}

/// The rate limits of the write routes.
pub struct SyncLimits {
    config: RateConfig,
}

impl SyncLimits {
    /// Limits that follow `cfg`, with time from `clock`.
    pub fn new(cfg: RateConfig, _clock: Arc<dyn Clock>) -> Self {
        Self { config: cfg }
    }

    /// The numbers these limits run on.
    pub fn config(&self) -> &RateConfig {
        &self.config
    }

    /// Takes `ops` operations and `bytes` request bytes from the bucket of
    /// this device, or says when to come back.
    pub fn admit(
        &self,
        _vault: &VaultId,
        _device: &DeviceId,
        _ops: u32,
        _bytes: u64,
    ) -> Result<(), Refused> {
        Ok(())
    }

    /// Whether this device may upload a checkpoint now. It only looks: a
    /// refused or failed upload must not use up the turn.
    pub fn checkpoint_allowed(&self, _vault: &VaultId, _device: &DeviceId) -> Result<(), Refused> {
        Ok(())
    }

    /// Records that a checkpoint of this device was stored.
    pub fn checkpoint_stored(&self, _vault: &VaultId, _device: &DeviceId) {}
}

/// The queue in front of the write transactions.
#[derive(Clone)]
pub struct WriteGate {
    _private: (),
}

/// The right to run one write transaction; held until the write is done.
pub struct WritePermit {
    _private: (),
}

/// The queue is full: the write is turned away, not waited for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Busy;

impl WriteGate {
    /// A gate that lets `concurrency` writes run at once and keeps `queue`
    /// more waiting.
    pub fn new(_concurrency: usize, _queue: usize) -> Self {
        Self { _private: () }
    }

    /// Waits for a turn, or fails with [`Busy`] when too many already wait.
    pub async fn enter(&self) -> Result<WritePermit, Busy> {
        Ok(WritePermit { _private: () })
    }
}

#[cfg(test)]
mod tests {
    use ferret_server_auth::SystemClock;

    use super::*;

    #[tokio::test]
    async fn stub_limits_admit_everything_and_the_stub_gate_always_enters() {
        let limits = SyncLimits::new(RateConfig::DEFAULT, Arc::new(SystemClock));
        let vault = VaultId::from_bytes([1; 16]);
        let device = DeviceId([2; 16]);
        assert_eq!(limits.config(), &RateConfig::DEFAULT);
        for _ in 0..1000 {
            assert_eq!(limits.admit(&vault, &device, u32::MAX, u64::MAX), Ok(()));
        }
        assert_eq!(limits.checkpoint_allowed(&vault, &device), Ok(()));
        limits.checkpoint_stored(&vault, &device);
        assert_eq!(limits.checkpoint_allowed(&vault, &device), Ok(()));

        let gate = WriteGate::new(1, 0);
        let mut permits = Vec::new();
        for _ in 0..10 {
            permits.push(gate.enter().await.expect("the stub gate lets everyone in"));
        }
    }

    #[test]
    fn default_numbers_are_the_documented_ones() {
        let d = RateConfig::DEFAULT;
        assert_eq!((d.ops_per_min, d.ops_burst), (120, 300));
        assert_eq!(d.bytes_per_min, 20 * 1024 * 1024);
        assert_eq!(d.checkpoint_every_secs, 600);
        assert_eq!((d.max_keys, d.max_devices_per_vault), (4096, 40));
    }
}
