//! Limits on writes: operations and bytes per minute for each device, how often
//! a device may upload a checkpoint, and the queue in front of the write
//! transactions.
//!
//! The buckets live in memory. They are keyed on the vault and the device (a
//! `device_id` is chosen by the client, so the vault is part of the key, and
//! the number of devices one vault can use is capped), and they read the time
//! only from the [`Clock`] they were built with.

use std::collections::{BTreeMap, HashMap};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use ferret_core::{OsRng, SecureRng};
use ferret_server_auth::Clock;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

use crate::error::ApiError;
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

/// Units per token. A bucket holds sixty times the tokens it stands for, so a
/// refill of `per_min` tokens a minute is exactly `per_min` units a second and
/// no fraction is lost between two readings of a clock that counts seconds.
const UNITS: u64 = 60;

/// Whose bucket: a device with a bucket of its own, or the overflow bucket of
/// the vault.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
enum Slot {
    Device(DeviceId),
    Overflow,
}

type BucketKey = (VaultId, Slot);

/// The two buckets and the last stored checkpoint of one key.
struct Entry {
    /// Operations left, in units of 1/60 operation.
    ops: u64,
    /// Request bytes left, in units of 1/60 byte.
    bytes: u64,
    /// The second the buckets were last filled up to.
    filled_at: u64,
    /// The second a checkpoint of this key was last stored.
    checkpoint_at: Option<u64>,
    /// Place in [`Table::order`].
    tick: u64,
}

#[derive(Default)]
struct Table {
    entries: HashMap<BucketKey, Entry>,
    /// The keys by time of last use, the one used longest ago first.
    order: BTreeMap<u64, BucketKey>,
    /// How many devices of each vault have a bucket of their own.
    devices: HashMap<VaultId, usize>,
    tick: u64,
}

impl Table {
    /// The key a device uses: its own if it has one, a new own one while its
    /// vault has room for one, else the overflow bucket of the vault. Does not
    /// change the table.
    fn key_of(&self, cfg: &RateConfig, vault: &VaultId, device: &DeviceId) -> BucketKey {
        let own = (*vault, Slot::Device(*device));
        if self.entries.contains_key(&own) {
            return own;
        }
        let count = self.devices.get(vault).copied().unwrap_or(0);
        if count < cfg.max_devices_per_vault {
            own
        } else {
            (*vault, Slot::Overflow)
        }
    }

    /// Drops the entry of `key`, if there is one.
    fn remove(&mut self, key: &BucketKey) {
        let Some(entry) = self.entries.remove(key) else {
            return;
        };
        self.order.remove(&entry.tick);
        if matches!(key.1, Slot::Device(_)) {
            let count = self.devices.entry(key.0).or_insert(0);
            *count = count.saturating_sub(1);
            if *count == 0 {
                self.devices.remove(&key.0);
            }
        }
    }

    /// The entry of `key`, made (with full buckets) if it is not there, and
    /// marked as used now. A new entry gets its room first, so the table never
    /// holds more than `max_keys` entries.
    fn touch(&mut self, cfg: &RateConfig, key: BucketKey, now: u64) -> &mut Entry {
        self.tick = self.tick.saturating_add(1);
        let tick = self.tick;
        if !self.entries.contains_key(&key) {
            let cap = cfg.max_keys.max(1);
            while self.entries.len() >= cap {
                let Some(oldest) = self.order.first_key_value().map(|(_, k)| *k) else {
                    break;
                };
                self.remove(&oldest);
            }
            if matches!(key.1, Slot::Device(_)) {
                let count = self.devices.entry(key.0).or_insert(0);
                *count = count.saturating_add(1);
            }
        }
        let entry = self.entries.entry(key).or_insert_with(|| Entry {
            ops: u64::from(cfg.ops_burst).saturating_mul(UNITS),
            bytes: cfg.bytes_per_min.saturating_mul(UNITS),
            filled_at: now,
            checkpoint_at: None,
            tick,
        });
        // A new entry is not in the order yet; removing its own tick is a no-op.
        self.order.remove(&entry.tick);
        entry.tick = tick;
        self.order.insert(tick, key);
        entry
    }
}

impl Entry {
    /// Fills the buckets for the time since they were last filled. A clock
    /// that went back is taken as the new start, and nothing is given back.
    fn fill(&mut self, cfg: &RateConfig, now: u64) {
        if now < self.filled_at {
            self.filled_at = now;
            return;
        }
        let secs = now.saturating_sub(self.filled_at);
        self.filled_at = now;
        let ops_cap = u64::from(cfg.ops_burst).saturating_mul(UNITS);
        let bytes_cap = cfg.bytes_per_min.saturating_mul(UNITS);
        self.ops = self
            .ops
            .saturating_add(secs.saturating_mul(u64::from(cfg.ops_per_min)))
            .min(ops_cap);
        self.bytes = self
            .bytes
            .saturating_add(secs.saturating_mul(cfg.bytes_per_min))
            .min(bytes_cap);
    }
}

/// Seconds until a bucket that holds `have` units has `cost` tokens, when it
/// gets `per_min` units a second; `None` if it has them already.
fn wait_for(have: u64, cost: u64, per_min: u64) -> Option<u64> {
    let need = cost.saturating_mul(UNITS);
    if have >= need {
        return None;
    }
    let deficit = need.saturating_sub(have);
    // A bucket that never refills never lets the request through.
    Some(if per_min == 0 {
        u64::MAX
    } else {
        deficit.div_ceil(per_min)
    })
}

/// The answer for a wait of `secs`: never less than one second.
fn refused(secs: u64) -> Refused {
    Refused {
        retry_after_secs: u32::try_from(secs).unwrap_or(u32::MAX).max(1),
    }
}

/// The seconds a client waits after `503 busy`.
pub const BUSY_RETRY_AFTER_SECS: u32 = 2;

/// The answer for a request that a rate limit turned away: `429 throttled`
/// with the wait. The write routes all answer this way.
pub fn throttled(refused: Refused) -> ApiError {
    ApiError::throttled(refused.retry_after_secs)
}

/// The answer for a write that found the queue full: `503 busy` with a wait
/// of [`BUSY_RETRY_AFTER_SECS`]. The write routes all answer this way.
pub fn busy(_: Busy) -> ApiError {
    ApiError {
        retry_after: Some(BUSY_RETRY_AFTER_SECS),
        ..ApiError::coded("busy")
    }
}

/// The rate limits of the write routes.
///
/// Two token buckets for each (vault, device): operations (`ops_per_min`
/// refill, `ops_burst` capacity) and request bytes (`bytes_per_min` refill and
/// capacity). A bucket starts full. At most `max_devices_per_vault` devices of
/// one vault get a bucket of their own; the others share one overflow bucket
/// of the vault. At most `max_keys` buckets exist in all: when a new one is
/// needed at the cap, the one used longest ago is dropped (an idle bucket has
/// refilled, so dropping it takes nothing back). The time of the last stored
/// checkpoint of a device is kept with its bucket, so dropping a bucket also
/// clears the pace of that device's checkpoints: it may upload again at once.
pub struct SyncLimits {
    config: RateConfig,
    clock: Arc<dyn Clock>,
    table: Mutex<Table>,
}

impl SyncLimits {
    /// Limits that follow `cfg`, with time from `clock`.
    pub fn new(cfg: RateConfig, clock: Arc<dyn Clock>) -> Self {
        Self {
            config: cfg,
            clock,
            table: Mutex::new(Table::default()),
        }
    }

    /// The numbers these limits run on.
    pub fn config(&self) -> &RateConfig {
        &self.config
    }

    /// How many buckets are in memory now; never more than `max_keys`.
    #[doc(hidden)]
    pub fn tracked_keys(&self) -> usize {
        self.table().entries.len()
    }

    fn table(&self) -> MutexGuard<'_, Table> {
        // A panic elsewhere cannot leave the table half changed: every change
        // is made under this lock with no call that can panic in between.
        self.table.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Takes `ops` operations and `bytes` request bytes from the bucket of
    /// this device, or says when to come back. Nothing is taken from either
    /// bucket when one of them is short. A request larger than a whole bucket
    /// counts as a whole bucket, so it can pass once the bucket is full.
    ///
    /// Spec: Fase 1 § 8.2.
    pub fn admit(
        &self,
        vault: &VaultId,
        device: &DeviceId,
        ops: u32,
        bytes: u64,
    ) -> Result<(), Refused> {
        let cfg = self.config;
        let now = self.clock.now_unix();
        let mut table = self.table();
        let key = table.key_of(&cfg, vault, device);
        let entry = table.touch(&cfg, key, now);
        entry.fill(&cfg, now);

        let ops_cost = u64::from(ops).min(u64::from(cfg.ops_burst));
        let bytes_cost = bytes.min(cfg.bytes_per_min);
        let ops_wait = wait_for(entry.ops, ops_cost, u64::from(cfg.ops_per_min));
        let bytes_wait = wait_for(entry.bytes, bytes_cost, cfg.bytes_per_min);
        if ops_wait.is_none() && bytes_wait.is_none() {
            entry.ops = entry.ops.saturating_sub(ops_cost.saturating_mul(UNITS));
            entry.bytes = entry.bytes.saturating_sub(bytes_cost.saturating_mul(UNITS));
            return Ok(());
        }
        Err(refused(ops_wait.unwrap_or(0).max(bytes_wait.unwrap_or(0))))
    }

    /// Takes only `bytes` request bytes from the bucket of this device, or says
    /// when to come back. This is the check of a batch that has its operations
    /// counted in an import window: the byte bucket still applies to it, the
    /// operation bucket does not.
    ///
    /// Spec: Fase 1 § 8.2.
    pub fn admit_bytes(
        &self,
        vault: &VaultId,
        device: &DeviceId,
        bytes: u64,
    ) -> Result<(), Refused> {
        self.admit(vault, device, 0, bytes)
    }

    /// Whether this device may upload a checkpoint now. It only looks: a
    /// refused or failed upload must not use up the turn.
    pub fn checkpoint_allowed(&self, vault: &VaultId, device: &DeviceId) -> Result<(), Refused> {
        let cfg = self.config;
        let now = self.clock.now_unix();
        let table = self.table();
        let key = table.key_of(&cfg, vault, device);
        let Some(at) = table.entries.get(&key).and_then(|e| e.checkpoint_at) else {
            return Ok(());
        };
        // A clock that went back since the store gives the device its turn.
        if now < at {
            return Ok(());
        }
        let waited = now.saturating_sub(at);
        if waited >= cfg.checkpoint_every_secs {
            return Ok(());
        }
        Err(refused(cfg.checkpoint_every_secs.saturating_sub(waited)))
    }

    /// Records that a checkpoint of this device was stored.
    pub fn checkpoint_stored(&self, vault: &VaultId, device: &DeviceId) {
        let cfg = self.config;
        let now = self.clock.now_unix();
        let mut table = self.table();
        let key = table.key_of(&cfg, vault, device);
        table.touch(&cfg, key, now).checkpoint_at = Some(now);
    }
}

/// How long an import window lasts, in seconds.
pub const IMPORT_WINDOW_SECS: u32 = 1800;

/// Why an import window was not opened or not used.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ImportRefused {
    /// The vault has an open window that another device opened (`409
    /// import_window_open`).
    Open,
    /// There is no such window for this vault and device, it has ended, or
    /// it has too few operations left (`409 import_window_invalid`). One
    /// answer for all of them: the caller learns nothing about whose window
    /// it is.
    Invalid,
}

/// One open window.
struct Window {
    id: [u8; 16],
    /// The device that opened it; no other device may use it.
    device: DeviceId,
    /// Operations that no stored write has used yet.
    remaining: u32,
    /// Operations that running batches hold out of `remaining`.
    reserved: u32,
    /// The second the window ends (the first second it is not usable).
    expires_at: i64,
}

impl Window {
    /// Whether the window can still take operations at `now`.
    fn is_open(&self, now: i64) -> bool {
        now < self.expires_at && self.remaining > 0
    }
}

/// The open import windows, one per vault at most, kept in memory: a restart
/// forgets them all, and the page opens a new one (it proves the master
/// password again to get it).
///
/// A window lets one device send a number of operations in batches without the
/// per-device operation limit of [`SyncLimits`]; the byte limit and the write
/// queue still apply. It lasts [`IMPORT_WINDOW_SECS`] and holds the number of
/// operations it was opened for. One set for the process, shared by every
/// handle (`Clone` shares it).
///
/// Spec: Fase 1 § 8.2. This goes past the operation limit of the spec on
/// purpose: ten thousand items would take 83 minutes at 120 operations a
/// minute.
#[derive(Clone, Default)]
pub struct ImportWindows {
    windows: Arc<Mutex<HashMap<VaultId, Window>>>,
}

impl std::fmt::Debug for ImportWindows {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ImportWindows([redacted])")
    }
}

impl ImportWindows {
    /// No window open.
    pub fn new() -> Self {
        Self::default()
    }

    fn table(&self) -> MutexGuard<'_, HashMap<VaultId, Window>> {
        // A panic elsewhere cannot leave the table half changed: every change
        // is made under this lock with no call that can panic in between.
        self.windows.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Opens a window of `ops` operations for `device` of `vault`, and gives
    /// its id. It lasts [`IMPORT_WINDOW_SECS`] from `now`.
    ///
    /// A vault has one open window. One that has ended, or has no operation
    /// left, is replaced, and so is one that this device opened (it has just
    /// proved the master password again; the old window closes at once and a
    /// batch still running on it is not counted in the new one). A window that
    /// another device opened and that is still open is
    /// [`ImportRefused::Open`]. `ops` of 0 is [`ImportRefused::Invalid`]: the
    /// caller checks the number against the room of the vault first.
    ///
    /// Spec: Fase 1 § 8.2.
    pub fn open(
        &self,
        vault: &VaultId,
        device: &DeviceId,
        ops: u32,
        now: i64,
    ) -> Result<[u8; 16], ImportRefused> {
        if ops == 0 {
            return Err(ImportRefused::Invalid);
        }
        let mut table = self.table();
        // A window nobody can use any more is gone; one with a batch still
        // running is kept until that batch has settled.
        table.retain(|_, w| w.is_open(now) || w.reserved > 0);
        if table
            .get(vault)
            .is_some_and(|w| w.is_open(now) && w.device != *device)
        {
            return Err(ImportRefused::Open);
        }
        let mut id = [0u8; 16];
        OsRng.fill(&mut id);
        table.insert(
            *vault,
            Window {
                id,
                device: *device,
                remaining: ops,
                reserved: 0,
                expires_at: now.saturating_add(i64::from(IMPORT_WINDOW_SECS)),
            },
        );
        Ok(id)
    }

    /// Holds `n` operations of the window `window` for a batch of `device` of
    /// `vault`. The window must be this vault's, opened by this device, not
    /// ended at `now`, and have `n` operations that nothing holds or used.
    /// Anything else is [`ImportRefused::Invalid`], and nothing is held.
    ///
    /// The hold ends when the [`Reservation`] is dropped or committed.
    ///
    /// Spec: Fase 1 § 8.2.
    pub fn reserve(
        &self,
        vault: &VaultId,
        device: &DeviceId,
        window: &[u8; 16],
        n: u32,
        now: i64,
    ) -> Result<Reservation, ImportRefused> {
        let mut table = self.table();
        let w = table
            .get_mut(vault)
            .filter(|w| w.id == *window && w.device == *device && w.is_open(now))
            .ok_or(ImportRefused::Invalid)?;
        let free = w.remaining.saturating_sub(w.reserved);
        if n == 0 || n > free {
            return Err(ImportRefused::Invalid);
        }
        w.reserved = w.reserved.saturating_add(n);
        Ok(Reservation {
            windows: self.clone(),
            vault: *vault,
            window: *window,
            n,
            stored: 0,
        })
    }

    /// Gives back the `n` operations a reservation held, and takes `stored`
    /// of them for good. A window that is not there any more (or is another
    /// one, opened since) is left alone.
    fn settle(&self, vault: &VaultId, window: &[u8; 16], n: u32, stored: u32) {
        let mut table = self.table();
        if let Some(w) = table.get_mut(vault).filter(|w| w.id == *window) {
            w.reserved = w.reserved.saturating_sub(n);
            w.remaining = w.remaining.saturating_sub(stored);
        }
    }

    /// How many operations the window of `vault` has left, if it has one that
    /// has not ended at `now`.
    #[doc(hidden)]
    pub fn remaining(&self, vault: &VaultId, now: i64) -> Option<u32> {
        self.table()
            .get(vault)
            .filter(|w| now < w.expires_at)
            .map(|w| w.remaining)
    }
}

/// Operations of a window held for one batch. Dropped without
/// [`Reservation::commit`], it gives all of them back.
pub struct Reservation {
    windows: ImportWindows,
    vault: VaultId,
    window: [u8; 16],
    n: u32,
    stored: u32,
}

impl Reservation {
    /// Ends the hold: `stored` operations (the writes that stored something
    /// new, never the repeats of an earlier `idem`) are taken from the window
    /// for good, and the rest are given back. More than were held counts as
    /// all of them.
    pub fn commit(mut self, stored: u32) {
        self.stored = stored.min(self.n);
    }
}

impl Drop for Reservation {
    fn drop(&mut self) {
        self.windows
            .settle(&self.vault, &self.window, self.n, self.stored);
    }
}

impl std::fmt::Debug for Reservation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Reservation([redacted])")
    }
}

/// The queue in front of the write transactions: `concurrency` writes run at
/// once, up to `queue` more wait for a turn, and one more than that is turned
/// away at once.
#[derive(Clone)]
pub struct WriteGate {
    inner: Arc<GateInner>,
}

struct GateInner {
    slots: Arc<Semaphore>,
    waiting: AtomicUsize,
    queue: usize,
}

/// The right to run one write transaction; held until the write is done. A
/// dropped permit frees its turn.
pub struct WritePermit {
    _slot: OwnedSemaphorePermit,
}

/// The queue is full: the write is turned away, not waited for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Busy;

/// Counts one waiter for as long as it lives, also when the wait is given up
/// (the request was cancelled).
struct Waiting<'a>(&'a AtomicUsize);

impl Drop for Waiting<'_> {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::AcqRel);
    }
}

impl WriteGate {
    /// A gate that lets `concurrency` writes run at once (at least one) and
    /// keeps `queue` more waiting.
    pub fn new(concurrency: usize, queue: usize) -> Self {
        Self {
            inner: Arc::new(GateInner {
                slots: Arc::new(Semaphore::new(concurrency.max(1))),
                waiting: AtomicUsize::new(0),
                queue,
            }),
        }
    }

    /// Waits for a turn, or fails with [`Busy`] when `queue` writes wait
    /// already.
    pub async fn enter(&self) -> Result<WritePermit, Busy> {
        let inner = &self.inner;
        if let Ok(slot) = inner.slots.clone().try_acquire_owned() {
            return Ok(WritePermit { _slot: slot });
        }
        // No free turn: take a place in the queue, if there is one.
        let reserved = inner
            .waiting
            .try_update(Ordering::AcqRel, Ordering::Acquire, |n| {
                (n < inner.queue).then(|| n.saturating_add(1))
            });
        if reserved.is_err() {
            return Err(Busy);
        }
        let _waiting = Waiting(&inner.waiting);
        match inner.slots.clone().acquire_owned().await {
            Ok(slot) => Ok(WritePermit { _slot: slot }),
            // The semaphore is never closed.
            Err(_) => Err(Busy),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_numbers_are_the_documented_ones() {
        let d = RateConfig::DEFAULT;
        assert_eq!((d.ops_per_min, d.ops_burst), (120, 300));
        assert_eq!(d.bytes_per_min, 20 * 1024 * 1024);
        assert_eq!(d.checkpoint_every_secs, 600);
        assert_eq!((d.max_keys, d.max_devices_per_vault), (4096, 40));
    }

    fn vault(n: u8) -> VaultId {
        VaultId::from_bytes([n; 16])
    }

    fn device(n: u8) -> DeviceId {
        DeviceId([n; 16])
    }

    #[test]
    fn a_reservation_is_taken_for_what_was_stored_and_the_rest_is_given_back() {
        let windows = ImportWindows::new();
        let id = windows.open(&vault(1), &device(1), 10, 100).expect("open");
        let held = windows
            .reserve(&vault(1), &device(1), &id, 6, 100)
            .expect("six");
        // Six are held, so four are free: five more do not fit.
        assert_eq!(
            windows.reserve(&vault(1), &device(1), &id, 5, 100).err(),
            Some(ImportRefused::Invalid)
        );
        held.commit(2);
        assert_eq!(windows.remaining(&vault(1), 100), Some(8));
        // The four given back are free again.
        let all = windows
            .reserve(&vault(1), &device(1), &id, 8, 100)
            .expect("eight");
        drop(all);
        assert_eq!(windows.remaining(&vault(1), 100), Some(8));
    }

    #[test]
    fn a_window_is_for_its_vault_its_device_and_its_id_until_it_ends() {
        let windows = ImportWindows::new();
        let id = windows.open(&vault(1), &device(1), 10, 100).expect("open");
        let refused =
            |v, d, w: &[u8; 16], now| windows.reserve(&vault(v), &device(d), w, 1, now).err();
        assert_eq!(refused(2, 1, &id, 100), Some(ImportRefused::Invalid));
        assert_eq!(refused(1, 2, &id, 100), Some(ImportRefused::Invalid));
        assert_eq!(refused(1, 1, &[0; 16], 100), Some(ImportRefused::Invalid));
        assert!(windows.reserve(&vault(1), &device(1), &id, 1, 1899).is_ok());
        assert_eq!(refused(1, 1, &id, 1900), Some(ImportRefused::Invalid));
        // Nothing of this held anything.
        assert_eq!(windows.remaining(&vault(1), 1899), Some(10));
        assert_eq!(windows.remaining(&vault(1), 1900), None);
    }

    #[test]
    fn a_window_of_another_device_is_replaced_only_when_it_has_ended_or_is_used_up() {
        let windows = ImportWindows::new();
        let id = windows.open(&vault(1), &device(1), 2, 100).expect("open");
        assert_eq!(
            windows.open(&vault(1), &device(2), 5, 101),
            Err(ImportRefused::Open)
        );
        assert_eq!(
            windows.open(&vault(1), &device(1), 0, 101),
            Err(ImportRefused::Invalid)
        );
        windows
            .reserve(&vault(1), &device(1), &id, 2, 101)
            .expect("both")
            .commit(2);
        let second = windows
            .open(&vault(1), &device(2), 5, 102)
            .expect("used up");
        assert_ne!(id, second);
        // A batch that was running when the window was replaced settles on
        // nothing of the new one.
        let held = windows
            .reserve(&vault(1), &device(2), &second, 5, 103)
            .expect("five");
        let third = windows
            .open(&vault(1), &device(2), 5, 103 + 1800)
            .expect("ended");
        held.commit(5);
        assert_eq!(windows.remaining(&vault(1), 103 + 1800), Some(5));
        assert_ne!(second, third);
        // The device that holds an open window may replace it: the old id
        // stops working at once.
        let again = windows
            .open(&vault(1), &device(2), 4, 103 + 1801)
            .expect("replaced");
        assert_ne!(third, again);
        assert_eq!(
            windows
                .reserve(&vault(1), &device(2), &third, 1, 103 + 1801)
                .err(),
            Some(ImportRefused::Invalid)
        );
        assert!(
            windows
                .reserve(&vault(1), &device(2), &again, 1, 103 + 1801)
                .is_ok()
        );
    }

    #[test]
    fn the_byte_bucket_alone_is_asked_for_a_batch_in_a_window() {
        let clock = Arc::new(ferret_server_auth::ManualClock::new(1_000));
        let cfg = RateConfig {
            ops_per_min: 1,
            ops_burst: 1,
            bytes_per_min: 100,
            ..RateConfig::DEFAULT
        };
        let limits = SyncLimits::new(cfg, clock);
        // Far more operations than the bucket holds: only bytes count.
        assert!(limits.admit_bytes(&vault(1), &device(1), 60).is_ok());
        assert!(limits.admit_bytes(&vault(1), &device(1), 40).is_ok());
        let refused = limits
            .admit_bytes(&vault(1), &device(1), 1)
            .expect_err("empty");
        assert_eq!(refused.retry_after_secs, 1);
    }

    #[test]
    fn the_debug_of_the_windows_and_a_reservation_prints_nothing() {
        let windows = ImportWindows::new();
        let id = windows.open(&vault(1), &device(1), 2, 0).expect("open");
        let held = windows
            .reserve(&vault(1), &device(1), &id, 1, 0)
            .expect("one");
        assert_eq!(format!("{windows:?}"), "ImportWindows([redacted])");
        assert_eq!(format!("{held:?}"), "Reservation([redacted])");
    }
}
