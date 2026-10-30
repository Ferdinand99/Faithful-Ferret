//! Rate limits for the sign-in and the registration, counted in memory. Spec:
//! Fase 1 § 11.
//!
//! [`KitThrottle`] is the limiter the server hands to `ferret-server-auth`. The
//! library builds the keys (it groups an IPv6 address by its /64, maps an
//! IPv4-mapped address back to IPv4 and puts callers without a readable address
//! in one shared bucket) and asks through its admit/finish pair; this module
//! only counts.
//!
//! | Stage           | Key                 | Limit         |
//! |-----------------|---------------------|---------------|
//! | `LoginStart`    | address             | 10 per minute |
//! | `LoginStart`    | account and address | 5 per minute  |
//! | `RegisterStart` | address             | 5 per minute  |
//!
//! Every other stage is not limited yet; the full set comes with the accounts
//! milestone.
//!
//! An attempt counts when it is admitted, not when it ends, so requests that
//! arrive together cannot all slip under the limit. A refused attempt is not
//! counted: hammering a blocked address does not extend the block. The window
//! is a sliding minute.

use std::collections::{HashMap, VecDeque};
use std::net::SocketAddr;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use axum::http::HeaderMap;
use ferret_server_auth::{Caller, Clock, Outcome, RetryAfter, Stage, Throttle, ThrottleKey};

/// Length of the sliding window in seconds.
const WINDOW_SECS: u64 = 60;
/// `LoginStart` attempts per address per window.
const LOGIN_PER_ADDRESS: usize = 10;
/// `LoginStart` attempts per account and address per window.
const LOGIN_PER_ACCOUNT_ADDRESS: usize = 5;
/// `RegisterStart` attempts per address per window.
const REGISTER_PER_ADDRESS: usize = 5;
/// Above this many counters in a stage, the expired ones are swept out before a
/// new one is added.
const SWEEP_ABOVE: usize = 1024;
/// The most counters kept per stage. Beyond it a new key is refused: a limiter
/// that forgot keys under pressure would switch itself off.
const MAX_KEYS: usize = 200_000;

/// The limit a stage puts on a key, or `None` for a key that is not counted.
const fn limit(stage: Stage, key: &ThrottleKey) -> Option<usize> {
    match (stage, key) {
        (Stage::LoginStart, ThrottleKey::Ip(_) | ThrottleKey::UnknownAddress) => {
            Some(LOGIN_PER_ADDRESS)
        }
        (Stage::LoginStart, ThrottleKey::AccountIp(..)) => Some(LOGIN_PER_ACCOUNT_ADDRESS),
        (Stage::RegisterStart, ThrottleKey::Ip(_) | ThrottleKey::UnknownAddress) => {
            Some(REGISTER_PER_ADDRESS)
        }
        _ => None,
    }
}

/// The attempts of one key inside the window, oldest first.
type Attempts = VecDeque<u64>;

/// The counters of the two limited stages.
#[derive(Default)]
struct Counters {
    login: HashMap<ThrottleKey, Attempts>,
    register: HashMap<ThrottleKey, Attempts>,
}

impl Counters {
    fn stage_mut(&mut self, stage: Stage) -> Option<&mut HashMap<ThrottleKey, Attempts>> {
        match stage {
            Stage::LoginStart => Some(&mut self.login),
            Stage::RegisterStart => Some(&mut self.register),
            Stage::LoginFinish | Stage::Challenge | Stage::Replace => None,
        }
    }
}

/// Drops the attempts that left the window at `now`.
fn expire(attempts: &mut Attempts, now: u64) {
    while attempts
        .front()
        .is_some_and(|&t| t.saturating_add(WINDOW_SECS) <= now)
    {
        attempts.pop_front();
    }
}

/// The limiter the server hands to `ferret-server-auth`.
pub struct KitThrottle {
    _clock: Arc<dyn Clock>,
    counters: Mutex<Counters>,
}

impl KitThrottle {
    /// A limiter. The library passes the time with every call, read from the
    /// same clock; `clock` is kept so the limiter and the server stay on one
    /// source of time.
    pub fn new(clock: Arc<dyn Clock>) -> Self {
        Self {
            _clock: clock,
            counters: Mutex::new(Counters::default()),
        }
    }

    fn lock(&self) -> MutexGuard<'_, Counters> {
        // A panic in another thread cannot leave a half-written counter that
        // matters: the worst case is one attempt too many or too few.
        self.counters.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

impl Throttle for KitThrottle {
    fn admit(&self, stage: Stage, keys: &[ThrottleKey], now: u64) -> Result<(), RetryAfter> {
        let mut counters = self.lock();
        let Some(map) = counters.stage_mut(stage) else {
            return Ok(());
        };

        // Every limited key is checked first; nothing is counted unless all of
        // them admit.
        let mut wait: Option<u64> = None;
        for key in keys {
            let Some(max) = limit(stage, key) else {
                continue;
            };
            let Some(attempts) = map.get_mut(key) else {
                continue;
            };
            expire(attempts, now);
            if attempts.len() >= max {
                // The oldest attempt in the window is the first to leave it.
                let free_at = attempts
                    .front()
                    .map_or(now, |&t| t.saturating_add(WINDOW_SECS));
                let this_wait = free_at.saturating_sub(now).max(1);
                wait = Some(wait.map_or(this_wait, |w| w.max(this_wait)));
            }
        }
        if let Some(secs) = wait {
            return Err(RetryAfter::new(u32::try_from(secs).unwrap_or(u32::MAX)));
        }

        // New keys need room.
        let new_keys = keys
            .iter()
            .filter(|key| limit(stage, key).is_some() && !map.contains_key(*key))
            .count();
        if map.len().saturating_add(new_keys) > SWEEP_ABOVE {
            map.retain(|_, attempts| {
                expire(attempts, now);
                !attempts.is_empty()
            });
        }
        if map.len().saturating_add(new_keys) > MAX_KEYS {
            return Err(RetryAfter::new(
                u32::try_from(WINDOW_SECS).unwrap_or(u32::MAX),
            ));
        }

        for key in keys {
            if limit(stage, key).is_some() {
                map.entry(*key).or_default().push_back(now);
            }
        }
        Ok(())
    }

    /// Outcomes are not used: attempts count when they are admitted.
    fn record(&self, _stage: Stage, _keys: &[ThrottleKey], _outcome: Outcome, _now: u64) {}
}

/// Who is calling: the address the proxy layer left in the request, else the
/// peer's. Call it after `proxy_guard` has run, which removes the forwarding
/// headers of every peer that is not a trusted proxy; the kit then reads the
/// right-most `X-Forwarded-For` entry (the address the last proxy saw) or
/// `X-Real-IP`.
pub fn caller_from(headers: &HeaderMap, peer: Option<SocketAddr>) -> Caller {
    Caller {
        ip: vole_kit::auth::session::client_ip(headers, peer, true),
    }
}
