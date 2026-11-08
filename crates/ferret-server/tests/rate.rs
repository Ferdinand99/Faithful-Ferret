//! The rate limits of the write routes and the queue in front of the write
//! transactions. Spec: Fase 1 § 8.2.
//!
//! The limits are driven with a clock that only moves when a test says so.

#![allow(non_snake_case)]

use std::sync::Arc;
use std::time::Duration;

use ferret_server::ids::{DeviceId, VaultId};
use ferret_server::vault::rate::{Busy, RateConfig, Refused, SyncLimits, WriteGate};
use ferret_server_auth::{Clock, ManualClock};

const START: u64 = 1_793_491_200;
const MIB: u64 = 1024 * 1024;

fn make(cfg: RateConfig) -> (SyncLimits, Arc<ManualClock>) {
    let clock = Arc::new(ManualClock::new(START));
    (SyncLimits::new(cfg, clock.clone() as Arc<dyn Clock>), clock)
}

fn vault(n: u8) -> VaultId {
    VaultId::from_bytes([n; 16])
}

fn device(n: u8) -> DeviceId {
    DeviceId([n; 16])
}

fn retry(result: Result<(), Refused>) -> u32 {
    result.expect_err("the request is refused").retry_after_secs
}

// ---------------------------------------------------------------------------
// Operations and bytes.

#[test]
fn a_burst_of_300_is_admitted_and_then_ops_refill_at_120_per_minute() {
    let (limits, clock) = make(RateConfig::DEFAULT);
    let (v, d) = (vault(1), device(1));
    for n in 0..300 {
        assert_eq!(limits.admit(&v, &d, 1, 0), Ok(()), "operation {n}");
    }
    // Empty: one operation is half a second away, so the answer is one second.
    assert_eq!(retry(limits.admit(&v, &d, 1, 0)), 1);

    // Two operations a second, exactly.
    clock.advance(1);
    assert_eq!(limits.admit(&v, &d, 2, 0), Ok(()));
    assert!(limits.admit(&v, &d, 1, 0).is_err());

    // Half a minute is sixty operations: a batch of 60 passes, one more does not.
    clock.advance(30);
    assert_eq!(limits.admit(&v, &d, 60, 0), Ok(()));
    assert!(limits.admit(&v, &d, 1, 0).is_err());

    // A long rest fills the bucket and no further.
    clock.advance(3600);
    assert_eq!(limits.admit(&v, &d, 100, 0), Ok(()));
    assert_eq!(limits.admit(&v, &d, 100, 0), Ok(()));
    assert_eq!(limits.admit(&v, &d, 100, 0), Ok(()));
    assert!(limits.admit(&v, &d, 1, 0).is_err());
}

#[test]
fn bytes_bucket_stops_at_20_MiB_per_minute() {
    let (limits, clock) = make(RateConfig::DEFAULT);
    let (v, d) = (vault(1), device(1));
    assert_eq!(limits.admit(&v, &d, 1, 20 * MIB), Ok(()));
    assert_eq!(retry(limits.admit(&v, &d, 1, 1)), 1);

    clock.advance(60);
    assert_eq!(limits.admit(&v, &d, 1, 20 * MIB), Ok(()));
    assert!(limits.admit(&v, &d, 1, 1).is_err());

    // Half a minute is half the bucket.
    clock.advance(30);
    assert!(limits.admit(&v, &d, 1, 10 * MIB + 1).is_err());
    assert_eq!(limits.admit(&v, &d, 1, 10 * MIB), Ok(()));
    assert!(limits.admit(&v, &d, 1, 1).is_err());
}

#[test]
fn a_refused_request_takes_nothing_from_either_bucket() {
    let cfg = RateConfig {
        ops_per_min: 6,
        ops_burst: 10,
        bytes_per_min: 1000,
        ..RateConfig::DEFAULT
    };
    let (limits, clock) = make(cfg);
    let (v, d) = (vault(1), device(1));
    assert_eq!(limits.admit(&v, &d, 1, 1000), Ok(()));
    // Bytes are short: 500 bytes are half a minute away. Ten operations are
    // there but must not be spent.
    assert_eq!(retry(limits.admit(&v, &d, 9, 500)), 30);
    clock.advance(30);
    assert_eq!(limits.admit(&v, &d, 9, 500), Ok(()));
}

#[test]
fn a_request_larger_than_a_bucket_counts_as_a_whole_bucket() {
    let cfg = RateConfig {
        ops_burst: 10,
        bytes_per_min: 1000,
        ..RateConfig::DEFAULT
    };
    let (limits, clock) = make(cfg);
    let (v, d) = (vault(1), device(1));
    // From a full bucket it passes (and empties it); it can never be stuck.
    assert_eq!(limits.admit(&v, &d, 50, 5000), Ok(()));
    assert!(limits.admit(&v, &d, 1, 1).is_err());
    clock.advance(60);
    assert_eq!(limits.admit(&v, &d, 50, 5000), Ok(()));
}

#[test]
fn retry_after_is_never_zero() {
    let (limits, clock) = make(RateConfig::DEFAULT);
    let (v, d) = (vault(1), device(1));
    assert_eq!(limits.admit(&v, &d, 300, 0), Ok(()));
    // A fraction of a second short, in operations and in bytes.
    clock.advance(1);
    assert_eq!(retry(limits.admit(&v, &d, 3, 0)), 1);
    assert_eq!(limits.admit(&v, &d, 0, 20 * MIB), Ok(()));
    assert_eq!(retry(limits.admit(&v, &d, 0, 1)), 1);
    // A bucket that never refills is a very long wait, not zero.
    let (never, _) = limits_never();
    assert_eq!(never.admit(&v, &d, 1, 0), Ok(()));
    assert_eq!(retry(never.admit(&v, &d, 1, 0)), u32::MAX);
    // A checkpoint with one second left.
    let (cp, clock) = make(RateConfig::DEFAULT);
    cp.checkpoint_stored(&v, &d);
    clock.advance(599);
    assert_eq!(retry(cp.checkpoint_allowed(&v, &d)), 1);
}

fn limits_never() -> (SyncLimits, Arc<ManualClock>) {
    make(RateConfig {
        ops_per_min: 0,
        ops_burst: 1,
        ..RateConfig::DEFAULT
    })
}

#[test]
fn a_clock_that_goes_back_gives_nothing_and_blocks_nothing() {
    let (limits, clock) = make(RateConfig::DEFAULT);
    let (v, d) = (vault(1), device(1));
    assert_eq!(limits.admit(&v, &d, 300, 0), Ok(()));
    clock.set(START - 10_000);
    assert!(limits.admit(&v, &d, 1, 0).is_err());
    // From the new time on, the bucket refills as usual.
    clock.advance(30);
    assert_eq!(limits.admit(&v, &d, 60, 0), Ok(()));
    assert!(limits.admit(&v, &d, 1, 0).is_err());
}

// ---------------------------------------------------------------------------
// Whose bucket.

#[test]
fn buckets_are_keyed_on_vault_and_device() {
    let cfg = RateConfig {
        ops_burst: 3,
        ..RateConfig::DEFAULT
    };
    let (limits, _) = make(cfg);
    let d = device(7);
    assert_eq!(limits.admit(&vault(1), &d, 3, 0), Ok(()));
    assert!(limits.admit(&vault(1), &d, 1, 0).is_err());
    // The same `device_id` in another vault is another bucket ...
    assert_eq!(limits.admit(&vault(2), &d, 3, 0), Ok(()));
    assert!(limits.admit(&vault(2), &d, 1, 0).is_err());
    // ... and so is another device of the first vault.
    assert_eq!(limits.admit(&vault(1), &device(8), 3, 0), Ok(()));
    assert_eq!(limits.tracked_keys(), 3);
}

#[test]
fn the_41st_device_of_a_vault_shares_the_overflow_bucket() {
    let cfg = RateConfig {
        ops_burst: 5,
        ..RateConfig::DEFAULT
    };
    let (limits, _) = make(cfg);
    let v = vault(1);
    for n in 0..40 {
        assert_eq!(limits.admit(&v, &device(n), 1, 0), Ok(()), "device {n}");
    }
    assert_eq!(limits.tracked_keys(), 40);

    // The 41st and the 42nd draw on one bucket of five.
    assert_eq!(limits.admit(&v, &device(40), 3, 0), Ok(()));
    assert_eq!(limits.admit(&v, &device(41), 2, 0), Ok(()));
    assert!(limits.admit(&v, &device(40), 1, 0).is_err());
    assert!(limits.admit(&v, &device(41), 1, 0).is_err());
    assert!(limits.admit(&v, &device(99), 1, 0).is_err());
    assert_eq!(limits.tracked_keys(), 41);

    // A device that has a bucket of its own keeps it: four operations left.
    assert_eq!(limits.admit(&v, &device(0), 4, 0), Ok(()));
    assert!(limits.admit(&v, &device(0), 1, 0).is_err());

    // Another vault is not touched by any of this.
    assert_eq!(limits.admit(&vault(2), &device(40), 5, 0), Ok(()));
}

#[test]
fn the_key_table_evicts_the_oldest_at_the_cap_and_never_grows() {
    let cfg = RateConfig {
        ops_burst: 2,
        max_keys: 8,
        ..RateConfig::DEFAULT
    };
    let (limits, _) = make(cfg);
    let (a, b) = (vault(1), vault(2));
    let d = device(1);
    // Two drained buckets, then `a` is used again, so `b` is the oldest.
    assert_eq!(limits.admit(&a, &d, 2, 0), Ok(()));
    assert_eq!(limits.admit(&b, &d, 2, 0), Ok(()));
    assert!(limits.admit(&a, &d, 1, 0).is_err());
    for n in 0..6u8 {
        assert_eq!(limits.admit(&vault(10 + n), &d, 1, 0), Ok(()));
    }
    assert_eq!(limits.tracked_keys(), 8);

    // One more key: the one used longest ago (`b`) goes, `a` stays.
    assert_eq!(limits.admit(&vault(20), &d, 1, 0), Ok(()));
    assert_eq!(limits.tracked_keys(), 8);
    assert!(
        limits.admit(&a, &d, 1, 0).is_err(),
        "a was kept, still empty"
    );
    assert_eq!(limits.admit(&b, &d, 2, 0), Ok(()), "b was dropped, now new");

    // Never more than the cap, however many keys come.
    for n in 0..=255u8 {
        for m in 0..4u8 {
            let _ = limits.admit(&vault(n), &device(m), 1, 0);
            assert!(limits.tracked_keys() <= 8);
        }
    }
    assert_eq!(limits.tracked_keys(), 8);
}

#[test]
fn a_dropped_device_gives_its_place_in_the_vault_back() {
    let cfg = RateConfig {
        ops_burst: 2,
        max_keys: 3,
        max_devices_per_vault: 2,
        ..RateConfig::DEFAULT
    };
    let (limits, _) = make(cfg);
    let (v, w) = (vault(1), vault(2));
    // Two devices of `v` and then the overflow bucket: three keys.
    assert_eq!(limits.admit(&v, &device(1), 1, 0), Ok(()));
    assert_eq!(limits.admit(&v, &device(2), 1, 0), Ok(()));
    assert_eq!(limits.admit(&v, &device(3), 2, 0), Ok(()));
    assert!(limits.admit(&v, &device(4), 1, 0).is_err());
    // A key of another vault drops the oldest (device 1 of `v`) ...
    assert_eq!(limits.admit(&w, &device(1), 1, 0), Ok(()));
    assert_eq!(limits.tracked_keys(), 3);
    // ... and `v` has room for a device of its own again: it is not served
    // from the (drained) overflow bucket.
    assert_eq!(limits.admit(&v, &device(5), 2, 0), Ok(()));
}

// ---------------------------------------------------------------------------
// Checkpoints.

#[test]
fn checkpoint_allowed_does_not_use_the_slot_and_checkpoint_stored_does() {
    let (limits, clock) = make(RateConfig::DEFAULT);
    let (v, d) = (vault(1), device(1));
    for _ in 0..5 {
        assert_eq!(limits.checkpoint_allowed(&v, &d), Ok(()));
    }
    assert_eq!(limits.tracked_keys(), 0, "looking leaves no trace");

    limits.checkpoint_stored(&v, &d);
    assert_eq!(retry(limits.checkpoint_allowed(&v, &d)), 600);
    clock.advance(100);
    assert_eq!(retry(limits.checkpoint_allowed(&v, &d)), 500);
    // Another device, and the same device in another vault, have their own turn.
    assert_eq!(limits.checkpoint_allowed(&v, &device(2)), Ok(()));
    assert_eq!(limits.checkpoint_allowed(&vault(2), &d), Ok(()));
    clock.advance(500);
    assert_eq!(limits.checkpoint_allowed(&v, &d), Ok(()));

    // A second store starts the ten minutes again.
    limits.checkpoint_stored(&v, &d);
    assert_eq!(retry(limits.checkpoint_allowed(&v, &d)), 600);
}

#[test]
fn a_checkpoint_does_not_use_up_operations() {
    let (limits, _) = make(RateConfig::DEFAULT);
    let (v, d) = (vault(1), device(1));
    limits.checkpoint_stored(&v, &d);
    assert_eq!(limits.admit(&v, &d, 300, 20 * MIB), Ok(()));
}

// ---------------------------------------------------------------------------
// The queue.

#[tokio::test]
async fn gate_admits_concurrency_then_queues_then_answers_busy() {
    let gate = WriteGate::new(2, 1);
    let first = gate.enter().await.expect("a free turn");
    let _second = gate.enter().await.expect("a free turn");

    // The third waits in the queue (the test runtime runs one task at a time,
    // so it is queued after one yield).
    let waiter = {
        let gate = gate.clone();
        tokio::spawn(async move { gate.enter().await.map(|_| ()) })
    };
    tokio::task::yield_now().await;
    assert!(!waiter.is_finished(), "the third write waits");

    // The queue holds one, so the fourth is turned away at once.
    assert!(matches!(gate.enter().await, Err(Busy)));

    // A turn that frees goes to the waiter.
    drop(first);
    let third = tokio::time::timeout(Duration::from_secs(5), waiter)
        .await
        .expect("the waiter got its turn")
        .expect("the task ran");
    assert!(third.is_ok());
}

#[tokio::test]
async fn a_waiter_that_gives_up_frees_its_place_in_the_queue() {
    let gate = WriteGate::new(1, 1);
    let _held = gate.enter().await.expect("a free turn");
    for _ in 0..3 {
        // Waits (does not answer busy) and is cancelled by the timeout.
        let waited = tokio::time::timeout(Duration::from_millis(20), gate.enter()).await;
        assert!(waited.is_err(), "the write waits, it is not turned away");
    }
}

#[tokio::test]
async fn a_dropped_permit_frees_the_slot() {
    let gate = WriteGate::new(1, 0);
    let permit = gate.enter().await.expect("a free turn");
    assert!(matches!(gate.enter().await, Err(Busy)));
    drop(permit);
    let again = gate.enter().await.expect("the turn is free again");
    assert!(matches!(gate.enter().await, Err(Busy)));
    drop(again);
    assert!(gate.enter().await.is_ok());
}
