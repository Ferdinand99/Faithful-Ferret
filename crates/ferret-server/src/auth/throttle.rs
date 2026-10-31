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
//! Every other stage is not limited yet; the full set comes in a later release.
//!
//! An attempt counts when it is admitted, not when it ends, so requests that
//! arrive together cannot all slip under the limit. A refused attempt is not
//! counted: hammering a blocked address does not extend the block. The window
//! is a sliding minute.
//!
//! # Memory
//!
//! A stage keeps at most [`KitThrottle::DEFAULT_MAX_KEYS`] address keys and as
//! many account keys, in tables of their own. A full table
//! never refuses a caller (that would let anyone lock everybody out of signing
//! in, which Fase 1 § 11 rules out): the key that was added first is dropped to
//! make room, and its counter starts again from zero if it comes back. An address
//! costs an attacker nothing (an IPv6 /64 holds countless ones), so address keys
//! only ever push out other address keys: the counter of an account is dropped
//! only for another account key, never by a flood of addresses. Keys
//! whose attempts have all left the window are swept out a few at a time on
//! each call ([`KitThrottle::SWEEP_BUDGET`]), so no call walks the whole table
//! under the lock.

use std::borrow::Cow;
use std::collections::{HashMap, VecDeque};
use std::net::SocketAddr;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use axum::http::{HeaderMap, HeaderValue};
use ferret_server_auth::{Caller, Clock, Outcome, RetryAfter, Stage, Throttle, ThrottleKey};

/// Length of the sliding window in seconds.
const WINDOW_SECS: u64 = 60;
/// `LoginStart` attempts per address per window.
const LOGIN_PER_ADDRESS: usize = 10;
/// `LoginStart` attempts per account and address per window.
const LOGIN_PER_ACCOUNT_ADDRESS: usize = 5;
/// `RegisterStart` attempts per address per window.
const REGISTER_PER_ADDRESS: usize = 5;

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

/// Drops the attempts that left the window at `now`.
fn expire(attempts: &mut Attempts, now: u64) {
    while attempts
        .front()
        .is_some_and(|&t| t.saturating_add(WINDOW_SECS) <= now)
    {
        attempts.pop_front();
    }
}

/// The counters of one stage: the attempts of each key, and the keys in the
/// order they were added. Every key in the map has exactly one entry in the
/// queue and the other way round.
#[derive(Default)]
struct Table {
    attempts: HashMap<ThrottleKey, Attempts>,
    queue: VecDeque<(ThrottleKey, u64)>,
}

impl Table {
    fn len(&self) -> usize {
        self.attempts.len()
    }

    /// Counts an attempt for `key`, adding the key if it is new.
    fn count(&mut self, key: ThrottleKey, now: u64) {
        match self.attempts.get_mut(&key) {
            Some(attempts) => attempts.push_back(now),
            None => {
                self.attempts.insert(key, Attempts::from([now]));
                self.queue.push_back((key, now));
            }
        }
    }

    /// Looks at the oldest keys: one that has nothing left in the window is
    /// removed, one that is still in use goes to the back of the queue. At most
    /// `budget` keys are looked at, and only those added a window ago or more.
    fn sweep(&mut self, now: u64, budget: usize) {
        for _ in 0..budget {
            let Some(&(key, added)) = self.queue.front() else {
                return;
            };
            if added.saturating_add(WINDOW_SECS) > now {
                return;
            }
            self.queue.pop_front();
            if let Some(attempts) = self.attempts.get_mut(&key) {
                expire(attempts, now);
                if attempts.is_empty() {
                    self.attempts.remove(&key);
                } else {
                    self.queue.push_back((key, now));
                }
            }
        }
    }

    /// Drops the key that was added first. `false` if the table is empty.
    fn evict_oldest(&mut self) -> bool {
        let Some((key, _)) = self.queue.pop_front() else {
            return false;
        };
        self.attempts.remove(&key);
        true
    }
}

/// The counters of one stage: address keys and account keys in tables of their
/// own. An address costs an attacker nothing (an IPv6 /64 holds countless
/// ones), so a flood of address keys may only push out other address keys; the
/// counter of an account is dropped only to make room for another account key.
#[derive(Default)]
struct Tables {
    address: Table,
    account: Table,
}

impl Tables {
    fn table_mut(&mut self, key: &ThrottleKey) -> &mut Table {
        match key {
            ThrottleKey::Account(_) | ThrottleKey::AccountIp(..) => &mut self.account,
            ThrottleKey::Ip(_) | ThrottleKey::UnknownAddress => &mut self.address,
        }
    }

    fn len(&self) -> usize {
        self.address.len().saturating_add(self.account.len())
    }
}

/// The two limited stages.
#[derive(Default)]
struct Counters {
    login: Tables,
    register: Tables,
}

impl Counters {
    fn stage_mut(&mut self, stage: Stage) -> Option<&mut Tables> {
        match stage {
            Stage::LoginStart => Some(&mut self.login),
            Stage::RegisterStart => Some(&mut self.register),
            Stage::LoginFinish | Stage::Challenge | Stage::Replace => None,
        }
    }
}

/// The limiter the server hands to `ferret-server-auth`.
pub struct KitThrottle {
    _clock: Arc<dyn Clock>,
    max_keys: usize,
    counters: Mutex<Counters>,
}

impl KitThrottle {
    /// The most keys a stage keeps in each of its two tables (address keys and
    /// account keys).
    pub const DEFAULT_MAX_KEYS: usize = 100_000;
    /// How many old keys one call looks at.
    pub const SWEEP_BUDGET: usize = 32;

    /// A limiter. The library passes the time with every call, read from the
    /// same clock; `clock` is kept so the limiter and the server stay on one
    /// source of time.
    pub fn new(clock: Arc<dyn Clock>) -> Self {
        Self::with_max_keys(clock, Self::DEFAULT_MAX_KEYS)
    }

    /// A limiter that keeps at most `max_keys` address keys and `max_keys`
    /// account keys per stage.
    pub fn with_max_keys(clock: Arc<dyn Clock>, max_keys: usize) -> Self {
        Self {
            _clock: clock,
            max_keys,
            counters: Mutex::new(Counters::default()),
        }
    }

    /// How many keys the two stages hold in all.
    pub fn tracked_keys(&self) -> usize {
        let counters = self.lock();
        counters.login.len().saturating_add(counters.register.len())
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
        let Some(tables) = counters.stage_mut(stage) else {
            return Ok(());
        };
        tables.address.sweep(now, Self::SWEEP_BUDGET);
        tables.account.sweep(now, Self::SWEEP_BUDGET);

        // Every limited key is checked first; nothing is counted unless all of
        // them admit.
        let mut wait: Option<u64> = None;
        for key in keys {
            let Some(max) = limit(stage, key) else {
                continue;
            };
            let Some(attempts) = tables.table_mut(key).attempts.get_mut(key) else {
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

        // New keys need room; a full table drops its oldest keys.
        // Room is made in the table of the key's own kind.
        for key in keys {
            if limit(stage, key).is_none() {
                continue;
            }
            let table = tables.table_mut(key);
            if !table.attempts.contains_key(key) {
                while table.len() >= self.max_keys && table.evict_oldest() {}
            }
            table.count(*key, now);
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
///
/// If the header comes in several lines (a proxy that adds a line of its own
/// instead of appending), only the last line counts: the first may be the
/// client's.
pub fn caller_from(headers: &HeaderMap, peer: Option<SocketAddr>) -> Caller {
    Caller {
        ip: vole_kit::auth::session::client_ip(&last_forwarded_line(headers), peer, true),
    }
}

/// The headers as the kit's address reading should see them: when
/// `X-Forwarded-For` comes in several lines, only the last one is kept (the
/// first may have been written by the client, and the kit reads the first
/// line). With one line or none the headers are returned as they are.
pub fn last_forwarded_line(headers: &HeaderMap) -> Cow<'_, HeaderMap> {
    let lines = headers.get_all("x-forwarded-for");
    if lines.iter().nth(1).is_none() {
        return Cow::Borrowed(headers);
    }
    let mut only_last = headers.clone();
    if let Some(last) = lines.iter().next_back() {
        only_last.insert("x-forwarded-for", HeaderValue::clone(last));
    }
    Cow::Owned(only_last)
}
