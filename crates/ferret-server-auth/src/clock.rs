//! Time. The library reads the time only through a [`Clock`] that the caller
//! passes in, so every expiry can be tested without waiting.

use std::time::{SystemTime, UNIX_EPOCH};

/// A source of the current time.
pub trait Clock: Send + Sync {
    /// Seconds since 1970-01-01 00:00:00 UTC.
    ///
    /// A clock that cannot tell the time returns `u64::MAX`, so that every
    /// expiry check sees every stored state and nonce as expired. Code that
    /// computes an expiry from this value must not let the sum wrap, and must
    /// refuse a sum that does not fit (`checked_add`) rather than store
    /// `u64::MAX`, which would be valid again once the clock is repaired.
    fn now_unix(&self) -> u64;
}

/// The system clock. A system clock set before 1970 fails closed: it reads
/// as `u64::MAX`, so every state and nonce counts as expired until the clock
/// is repaired. (Reading 0 would make everything look new.)
#[derive(Clone, Copy, Debug, Default)]
pub struct SystemClock;

impl SystemClock {
    /// The reading for a moment in time.
    fn reading(moment: SystemTime) -> u64 {
        match moment.duration_since(UNIX_EPOCH) {
            Ok(elapsed) => elapsed.as_secs(),
            Err(_) => u64::MAX,
        }
    }
}

impl Clock for SystemClock {
    fn now_unix(&self) -> u64 {
        Self::reading(SystemTime::now())
    }
}

/// A clock that only moves when a test says so.
#[cfg(feature = "test-support")]
#[derive(Debug)]
pub struct ManualClock {
    now: std::sync::Mutex<u64>,
}

#[cfg(feature = "test-support")]
impl ManualClock {
    /// A clock that reads `now`.
    pub fn new(now: u64) -> Self {
        Self {
            now: std::sync::Mutex::new(now),
        }
    }

    /// Sets the time to `now`.
    pub fn set(&self, now: u64) {
        *self.lock() = now;
    }

    /// Moves the time forward by `secs`, stopping at the largest value.
    pub fn advance(&self, secs: u64) {
        let mut now = self.lock();
        *now = now.saturating_add(secs);
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, u64> {
        // A panic in another test thread cannot leave a half-written integer.
        self.now
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

#[cfg(feature = "test-support")]
impl Clock for ManualClock {
    fn now_unix(&self) -> u64 {
        *self.lock()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn system_clock_is_after_2025() {
        // 2025-01-01T00:00:00Z
        assert!(SystemClock.now_unix() > 1_735_689_600);
    }

    #[test]
    fn a_clock_before_1970_fails_closed() {
        let before = UNIX_EPOCH - Duration::from_secs(1);
        assert_eq!(SystemClock::reading(before), u64::MAX);
        assert_eq!(SystemClock::reading(UNIX_EPOCH), 0);
        assert_eq!(
            SystemClock::reading(UNIX_EPOCH + Duration::from_secs(1_000)),
            1_000
        );
        // An expiry computed from the failed reading never lies in the future.
        let now = SystemClock::reading(before);
        let expires_at = now.saturating_add(crate::STATE_TTL_SECS);
        assert!(expires_at <= now);
    }

    #[cfg(feature = "test-support")]
    #[test]
    fn manual_clock_moves_only_when_told() {
        let clock = ManualClock::new(1_000);
        assert_eq!(clock.now_unix(), 1_000);
        assert_eq!(clock.now_unix(), 1_000);
        clock.advance(60);
        assert_eq!(clock.now_unix(), 1_060);
        clock.set(5);
        assert_eq!(clock.now_unix(), 5);
        clock.advance(u64::MAX);
        assert_eq!(clock.now_unix(), u64::MAX);
        clock.advance(1);
        assert_eq!(clock.now_unix(), u64::MAX);
    }

    #[cfg(feature = "test-support")]
    #[test]
    fn clock_works_as_a_trait_object() {
        let clock: &dyn Clock = &ManualClock::new(7);
        assert_eq!(clock.now_unix(), 7);
    }
}
