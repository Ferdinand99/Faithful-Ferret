//! Time. The library reads the time only through a [`Clock`] that the caller
//! passes in, so every expiry can be tested without waiting.

use std::time::{SystemTime, UNIX_EPOCH};

/// A source of the current time.
pub trait Clock: Send + Sync {
    /// Seconds since 1970-01-01 00:00:00 UTC.
    fn now_unix(&self) -> u64;
}

/// The system clock. A system clock set before 1970 reads as 0.
#[derive(Clone, Copy, Debug, Default)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now_unix(&self) -> u64 {
        match SystemTime::now().duration_since(UNIX_EPOCH) {
            Ok(elapsed) => elapsed.as_secs(),
            Err(_) => 0,
        }
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

    #[test]
    fn system_clock_is_after_2025() {
        // 2025-01-01T00:00:00Z
        assert!(SystemClock.now_unix() > 1_735_689_600);
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
