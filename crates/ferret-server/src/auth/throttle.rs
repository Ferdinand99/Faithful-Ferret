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
//! The nonces of signed requests have a limit of their own, by session, which
//! the library cannot key on: [`ChallengeLimit`], 30 per session per minute.
//! So has the redeeming of a sign-in code, which the library never sees:
//! [`RedeemLimit`], 10 per address per minute and 5 per typed e-mail address
//! and address per hour. So has `invite/check`: [`InviteCheckLimit`], 10 per
//! address per minute.
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
use std::hash::Hash;
use std::net::{IpAddr, Ipv6Addr, SocketAddr};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use axum::http::{HeaderMap, HeaderValue};
use ferret_server_auth::{
    Caller, Clock, Outcome, RetryAfter, Stage, Throttle, ThrottleKey, normalize_login_name,
};
use sha2::{Digest as _, Sha256};

use crate::ids::SidHash;

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

/// Drops the attempts that left a window of `window` seconds at `now`.
fn expire(attempts: &mut Attempts, now: u64, window: u64) {
    while attempts
        .front()
        .is_some_and(|&t| t.saturating_add(window) <= now)
    {
        attempts.pop_front();
    }
}

/// The counters of one stage: the attempts of each key, and the keys in the
/// order they were added. Every key in the map has exactly one entry in the
/// queue and the other way round.
struct Table<K = ThrottleKey> {
    attempts: HashMap<K, Attempts>,
    queue: VecDeque<(K, u64)>,
}

impl<K> Default for Table<K> {
    fn default() -> Self {
        Self {
            attempts: HashMap::new(),
            queue: VecDeque::new(),
        }
    }
}

impl<K: Copy + Eq + Hash> Table<K> {
    fn len(&self) -> usize {
        self.attempts.len()
    }

    /// Counts an attempt for `key`, adding the key if it is new.
    fn count(&mut self, key: K, now: u64) {
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
    /// `budget` keys are looked at, and only those added a window (`window`
    /// seconds) ago or more.
    fn sweep(&mut self, now: u64, budget: usize, window: u64) {
        for _ in 0..budget {
            let Some(&(key, added)) = self.queue.front() else {
                return;
            };
            if added.saturating_add(window) > now {
                return;
            }
            self.queue.pop_front();
            if let Some(attempts) = self.attempts.get_mut(&key) {
                expire(attempts, now, window);
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
        tables.address.sweep(now, Self::SWEEP_BUDGET, WINDOW_SECS);
        tables.account.sweep(now, Self::SWEEP_BUDGET, WINDOW_SECS);

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
            expire(attempts, now, WINDOW_SECS);
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

/// Nonces for signed requests one session may ask for per window.
///
/// Spec: Fase 1 § 4.6 (the nonce of a signed request).
pub const CHALLENGES_PER_SESSION: usize = 30;

/// The limit on `POST /api/auth/challenge`: [`CHALLENGES_PER_SESSION`] nonces
/// per session in a sliding minute, keyed by the hash of the session id.
///
/// The OPAQUE library asks its own throttle by address and account; it never
/// sees the session. This limit is asked first, before the library, and
/// counts the same way as [`KitThrottle`]: an attempt counts when it is
/// admitted, a refused one does not, and a full table drops the session that
/// was added first ([`ChallengeLimit::DEFAULT_MAX_KEYS`] sessions at most).
/// A dropped session starts again from zero, which costs an attacker a fresh
/// session per [`ChallengeLimit::DEFAULT_MAX_KEYS`] others: each one is a
/// sign-in, which has limits of its own.
pub struct ChallengeLimit {
    max_keys: usize,
    table: Mutex<Table<[u8; 32]>>,
}

impl ChallengeLimit {
    /// The most sessions the limit keeps counters for.
    pub const DEFAULT_MAX_KEYS: usize = 100_000;

    /// A limit with room for [`ChallengeLimit::DEFAULT_MAX_KEYS`] sessions.
    pub fn new() -> Self {
        Self::with_max_keys(Self::DEFAULT_MAX_KEYS)
    }

    /// A limit that keeps counters for at most `max_keys` sessions.
    pub fn with_max_keys(max_keys: usize) -> Self {
        Self {
            max_keys,
            table: Mutex::new(Table::default()),
        }
    }

    /// Counts a request for a nonce by the session `sid` at `now` (Unix
    /// seconds), or says how long the session must wait.
    pub fn admit(&self, sid: &SidHash, now: u64) -> Result<(), RetryAfter> {
        // The same reasoning as `KitThrottle::lock`: a poisoned lock holds at
        // worst one count too many or too few.
        let mut table = self.table.lock().unwrap_or_else(PoisonError::into_inner);
        table.sweep(now, KitThrottle::SWEEP_BUDGET, WINDOW_SECS);
        let key = sid.0;
        if let Some(attempts) = table.attempts.get_mut(&key) {
            expire(attempts, now, WINDOW_SECS);
            if attempts.len() >= CHALLENGES_PER_SESSION {
                let free_at = attempts
                    .front()
                    .map_or(now, |&t| t.saturating_add(WINDOW_SECS));
                let wait = free_at.saturating_sub(now).max(1);
                return Err(RetryAfter::new(u32::try_from(wait).unwrap_or(u32::MAX)));
            }
        } else {
            while table.len() >= self.max_keys && table.evict_oldest() {}
        }
        table.count(key, now);
        Ok(())
    }

    /// How many sessions the limit holds counters for.
    pub fn tracked_sessions(&self) -> usize {
        self.table
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .len()
    }
}

impl Default for ChallengeLimit {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Debug for ChallengeLimit {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ChallengeLimit([redacted])")
    }
}

/// Redeems of a sign-in code one address may try per minute.
///
/// Spec: Fase 1 § 6.3 step 1 and § 11.
pub const REDEEMS_PER_ADDRESS: usize = 10;

/// Redeems of a sign-in code one address may try for one typed e-mail address
/// per [`REDEEM_NAME_WINDOW_SECS`].
pub const REDEEMS_PER_NAME_AND_ADDRESS: usize = 5;

/// The window of [`REDEEMS_PER_NAME_AND_ADDRESS`]: an hour.
pub const REDEEM_NAME_WINDOW_SECS: u64 = 60 * 60;

/// The domain label of the digest that stands for a typed e-mail address in
/// the keys of [`RedeemLimit`].
const REDEEM_NAME_LABEL: &[u8] = b"ferret redeem name v1\0";

/// The key of an address in [`RedeemLimit`]: the counted address, or `None`
/// for every caller whose address could not be read (one shared bucket).
type RedeemAddress = Option<IpAddr>;

/// The key of a typed e-mail address from an address in [`RedeemLimit`].
type RedeemNameAddress = ([u8; 32], RedeemAddress);

/// The address a limit counts, by the same rule as the OPAQUE library's
/// throttle keys: an IPv4 address as it is, an IPv6 address as its /64 (host
/// bits zero), and an IPv4-mapped IPv6 address as the IPv4 address it carries.
fn counted_address(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V4(_) => ip,
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => IpAddr::V4(v4),
            None => IpAddr::V6(Ipv6Addr::from(u128::from(v6) & V6_NETWORK_MASK)),
        },
    }
}

/// The network part of an IPv6 address: the upper 64 bits.
const V6_NETWORK_MASK: u128 = 0xffff_ffff_ffff_ffff_0000_0000_0000_0000;

/// The digest that stands for a typed e-mail address: of the normalized login
/// name when the text is one, else of the text trimmed and in lower case. Only
/// what was typed goes in, never whether an account has that name, so the
/// limit says nothing about which names exist. The digest keeps the key small
/// and the name out of memory dumps of the table.
pub fn redeem_name_key(typed: &str) -> [u8; 32] {
    let name = normalize_login_name(typed).map_or_else(
        |_| typed.trim().to_lowercase(),
        |name| name.as_str().to_string(),
    );
    let mut hasher = Sha256::new();
    hasher.update(REDEEM_NAME_LABEL);
    hasher.update(name.as_bytes());
    let digest = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    out
}

/// The address table and the name table of [`RedeemLimit`].
#[derive(Default)]
struct RedeemTables {
    address: Table<RedeemAddress>,
    name: Table<RedeemNameAddress>,
}

/// The limit on `POST /api/auth/redeem`: [`REDEEMS_PER_ADDRESS`] attempts per
/// address in a sliding minute, and [`REDEEMS_PER_NAME_AND_ADDRESS`] per typed
/// e-mail address and address in a sliding hour.
///
/// The keys are built from the request alone: the address and the e-mail
/// address as typed (normalized, see [`redeem_name_key`]). Whether an account
/// has that name never takes part, so a name with an account and one without
/// are limited, and answered, alike.
///
/// It counts like [`KitThrottle`]: an attempt counts when it is admitted (both
/// keys must admit it, and then both count it), a refused one does not, and a
/// full table drops the key that was added first, in its own table
/// ([`RedeemLimit::DEFAULT_MAX_KEYS`] keys in each). The kit's own throttle of
/// sign-in codes (per name and per address, with back-off) runs behind this
/// one.
pub struct RedeemLimit {
    max_keys: usize,
    tables: Mutex<RedeemTables>,
}

impl RedeemLimit {
    /// The most keys each of the two tables keeps.
    pub const DEFAULT_MAX_KEYS: usize = 100_000;

    /// A limit with room for [`RedeemLimit::DEFAULT_MAX_KEYS`] keys per table.
    pub fn new() -> Self {
        Self::with_max_keys(Self::DEFAULT_MAX_KEYS)
    }

    /// A limit that keeps at most `max_keys` keys in each table.
    pub fn with_max_keys(max_keys: usize) -> Self {
        Self {
            max_keys,
            tables: Mutex::new(RedeemTables::default()),
        }
    }

    /// Counts an attempt by `caller` for the typed e-mail address `typed` at
    /// `now` (Unix seconds), or says how long the caller must wait.
    pub fn admit(&self, caller: &Caller, typed: &str, now: u64) -> Result<(), RetryAfter> {
        let address: RedeemAddress = caller.ip.map(counted_address);
        let name: RedeemNameAddress = (redeem_name_key(typed), address);
        // The same reasoning as `KitThrottle::lock`.
        let mut tables = self.tables.lock().unwrap_or_else(PoisonError::into_inner);
        tables
            .address
            .sweep(now, KitThrottle::SWEEP_BUDGET, WINDOW_SECS);
        tables
            .name
            .sweep(now, KitThrottle::SWEEP_BUDGET, REDEEM_NAME_WINDOW_SECS);

        let waits = [
            wait_for(
                &mut tables.address,
                &address,
                REDEEMS_PER_ADDRESS,
                WINDOW_SECS,
                now,
            ),
            wait_for(
                &mut tables.name,
                &name,
                REDEEMS_PER_NAME_AND_ADDRESS,
                REDEEM_NAME_WINDOW_SECS,
                now,
            ),
        ];
        if let Some(secs) = waits.into_iter().flatten().max() {
            return Err(RetryAfter::new(u32::try_from(secs).unwrap_or(u32::MAX)));
        }
        admit_key(&mut tables.address, address, self.max_keys, now);
        admit_key(&mut tables.name, name, self.max_keys, now);
        Ok(())
    }

    /// How many keys the two tables hold in all.
    pub fn tracked_keys(&self) -> usize {
        let tables = self.tables.lock().unwrap_or_else(PoisonError::into_inner);
        tables.address.len().saturating_add(tables.name.len())
    }
}

impl Default for RedeemLimit {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Debug for RedeemLimit {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("RedeemLimit([redacted])")
    }
}

/// How long `key` must wait at `now` when it has `max` attempts in a window of
/// `window` seconds already, else `None`.
fn wait_for<K: Copy + Eq + Hash>(
    table: &mut Table<K>,
    key: &K,
    max: usize,
    window: u64,
    now: u64,
) -> Option<u64> {
    let attempts = table.attempts.get_mut(key)?;
    expire(attempts, now, window);
    if attempts.len() < max {
        return None;
    }
    // The oldest attempt in the window is the first to leave it.
    let free_at = attempts.front().map_or(now, |&t| t.saturating_add(window));
    Some(free_at.saturating_sub(now).max(1))
}

/// Counts an attempt for `key`, dropping the oldest keys of a full table first.
fn admit_key<K: Copy + Eq + Hash>(table: &mut Table<K>, key: K, max_keys: usize, now: u64) {
    if !table.attempts.contains_key(&key) {
        while table.len() >= max_keys && table.evict_oldest() {}
    }
    table.count(key, now);
}

/// One limit on one kind of key: `max` attempts per key in a sliding window
/// of `window` seconds, counted like [`KitThrottle`] (an attempt counts when
/// it is admitted, a refused one does not, and a full table drops the key that
/// was added first, never refusing for lack of room).
pub(crate) struct WindowLimit<K> {
    max: usize,
    window: u64,
    max_keys: usize,
    table: Mutex<Table<K>>,
}

impl<K: Copy + Eq + Hash> WindowLimit<K> {
    /// A limit of `max` per `window` seconds, with room for `max_keys` keys.
    pub(crate) fn new(max: usize, window: u64, max_keys: usize) -> Self {
        Self {
            max,
            window,
            max_keys,
            table: Mutex::new(Table::default()),
        }
    }

    /// Counts an attempt for `key` at `now`, or says how long it must wait.
    pub(crate) fn admit(&self, key: K, now: u64) -> Result<(), RetryAfter> {
        // The same reasoning as `KitThrottle::lock`.
        let mut table = self.table.lock().unwrap_or_else(PoisonError::into_inner);
        table.sweep(now, KitThrottle::SWEEP_BUDGET, self.window);
        if let Some(secs) = wait_for(&mut table, &key, self.max, self.window, now) {
            return Err(RetryAfter::new(u32::try_from(secs).unwrap_or(u32::MAX)));
        }
        admit_key(&mut table, key, self.max_keys, now);
        Ok(())
    }

    /// How many keys the limit holds.
    pub(crate) fn tracked_keys(&self) -> usize {
        self.table
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .len()
    }
}

/// The limit on `POST /api/auth/invite/check`:
/// [`CHECKS_PER_ADDRESS`](crate::accounts::invites::CHECKS_PER_ADDRESS) checks
/// per address in a sliding minute, for every token alike (a pending one, a
/// dead one and one that never existed), so the limit says nothing about
/// which tokens are real. The address is counted by the same rule as the
/// library's keys (an IPv6 address by its /64), and callers whose address
/// cannot be read share one bucket. At most
/// [`InviteCheckLimit::DEFAULT_MAX_KEYS`] addresses are kept; a full table
/// drops the one added first.
///
/// Spec: Fase 1 § 4.2 (`invite/check`) and § 11.
pub struct InviteCheckLimit(WindowLimit<RedeemAddress>);

impl InviteCheckLimit {
    /// The most addresses the limit keeps counters for.
    pub const DEFAULT_MAX_KEYS: usize = 100_000;

    /// A limit with room for [`InviteCheckLimit::DEFAULT_MAX_KEYS`] addresses.
    pub fn new() -> Self {
        Self(WindowLimit::new(
            crate::accounts::invites::CHECKS_PER_ADDRESS,
            WINDOW_SECS,
            Self::DEFAULT_MAX_KEYS,
        ))
    }

    /// Counts a check by `caller` at `now` (Unix seconds), or says how long the
    /// caller must wait.
    pub fn admit(&self, caller: &Caller, now: u64) -> Result<(), RetryAfter> {
        self.0.admit(caller.ip.map(counted_address), now)
    }

    /// How many addresses the limit holds counters for.
    pub fn tracked_keys(&self) -> usize {
        self.0.tracked_keys()
    }
}

impl Default for InviteCheckLimit {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Debug for InviteCheckLimit {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("InviteCheckLimit([redacted])")
    }
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

#[cfg(test)]
mod tests {
    use super::*;

    fn sid(n: u8) -> SidHash {
        SidHash([n; 32])
    }

    #[test]
    fn a_session_gets_30_nonces_a_minute_and_a_wait_for_the_31st() {
        let limit = ChallengeLimit::new();
        for i in 0..30 {
            assert!(
                limit.admit(&sid(1), 1_000_u64.saturating_add(i)).is_ok(),
                "{i}"
            );
        }
        let wait = limit.admit(&sid(1), 1_030).expect_err("the 31st");
        assert_eq!(wait.secs(), 30);
        // A refusal is not counted, and another session has its own count.
        assert!(limit.admit(&sid(1), 1_030).is_err());
        assert!(limit.admit(&sid(2), 1_030).is_ok());
        // The first attempt leaves the window after 60 seconds.
        assert!(limit.admit(&sid(1), 1_060).is_ok());
        assert!(limit.admit(&sid(1), 1_060).is_err());
    }

    fn from(ip: &str) -> Caller {
        Caller {
            ip: Some(ip.parse().expect("an address")),
        }
    }

    #[test]
    fn redeems_are_ten_per_address_a_minute() {
        let limit = RedeemLimit::new();
        let a = from("203.0.113.7");
        for i in 0..10_u64 {
            let name = format!("name{i}@example.com");
            assert!(
                limit.admit(&a, &name, 1_000_u64.saturating_add(i)).is_ok(),
                "{i}"
            );
        }
        let wait = limit
            .admit(&a, "other@example.com", 1_010)
            .expect_err("the 11th");
        assert_eq!(wait.secs(), 50);
        // Another address has its own count; the first attempt leaves the
        // window after 60 seconds.
        assert!(
            limit
                .admit(&from("203.0.113.8"), "x@example.com", 1_010)
                .is_ok()
        );
        assert!(limit.admit(&a, "other@example.com", 1_060).is_ok());
        assert!(limit.admit(&a, "more@example.com", 1_060).is_err());
    }

    #[test]
    fn redeems_are_five_per_typed_name_and_address_an_hour() {
        let limit = RedeemLimit::new();
        let a = from("203.0.113.7");
        // Spread over more than the minute of the address limit.
        for i in 0..5_u64 {
            assert!(
                limit
                    .admit(
                        &a,
                        "ada@example.com",
                        1_000_u64.saturating_add(i.saturating_mul(100))
                    )
                    .is_ok()
            );
        }
        // Spellings of one name are one name.
        for typed in ["ada@example.com", " ADA@Example.COM ", "ａｄａ@example.com"] {
            let wait = limit.admit(&a, typed, 1_400).expect_err(typed);
            assert_eq!(wait.secs(), 3_200, "{typed}");
        }
        // Another name from the same address and the same name from another
        // address go on.
        assert!(limit.admit(&a, "bob@example.com", 1_400).is_ok());
        assert!(
            limit
                .admit(&from("203.0.113.8"), "ada@example.com", 1_400)
                .is_ok()
        );
        // An hour after the first attempt one more is allowed.
        assert!(limit.admit(&a, "ada@example.com", 4_600).is_ok());
        assert!(limit.admit(&a, "ada@example.com", 4_600).is_err());
    }

    #[test]
    fn a_refused_redeem_counts_for_neither_key() {
        let limit = RedeemLimit::new();
        let a = from("203.0.113.7");
        for i in 0..5_u64 {
            assert!(
                limit
                    .admit(&a, "ada@example.com", 1_000_u64.saturating_add(i))
                    .is_ok()
            );
        }
        // Refused by the name key: the address key is not counted either.
        for _ in 0..20 {
            assert!(limit.admit(&a, "ada@example.com", 1_010).is_err());
        }
        for i in 0..5_u64 {
            let name = format!("n{i}@example.com");
            assert!(limit.admit(&a, &name, 1_010).is_ok(), "{i}");
        }
        assert!(limit.admit(&a, "n9@example.com", 1_010).is_err());
    }

    #[test]
    fn a_redeem_address_is_counted_by_its_network() {
        let limit = RedeemLimit::new();
        for i in 0..10_u16 {
            let caller = from(&format!("2001:db8:1:2::{i:x}"));
            assert!(limit.admit(&caller, &format!("{i}@x.test"), 5).is_ok());
        }
        assert!(
            limit
                .admit(&from("2001:db8:1:2:ffff::1"), "z@x.test", 5)
                .is_err()
        );
        assert!(limit.admit(&from("2001:db8:1:3::1"), "z@x.test", 5).is_ok());
        // A mapped IPv4 address is that IPv4 address.
        for i in 0..10_u64 {
            let typed = format!("{i}@y.test");
            assert!(
                limit
                    .admit(&from("192.0.2.1"), &typed, 5_u64.saturating_add(i))
                    .is_ok()
            );
        }
        assert!(
            limit
                .admit(&from("::ffff:192.0.2.1"), "q@y.test", 20)
                .is_err()
        );
        // Callers without an address share one bucket.
        let nobody = Caller { ip: None };
        for i in 0..10_u64 {
            assert!(limit.admit(&nobody, &format!("{i}@z.test"), 5).is_ok());
        }
        assert!(limit.admit(&nobody, "q@z.test", 5).is_err());
    }

    #[test]
    fn the_name_key_is_the_typed_text_and_nothing_else() {
        assert_eq!(
            redeem_name_key("Ada@Example.com"),
            redeem_name_key("ada@example.com")
        );
        assert_ne!(
            redeem_name_key("ada@example.com"),
            redeem_name_key("bob@example.com")
        );
        // A text that is no login name still gets a key of its own.
        let bad = "a\u{0}b";
        assert!(normalize_login_name(bad).is_err());
        assert_eq!(redeem_name_key(bad), redeem_name_key(" A\u{0}B "));
        assert_ne!(redeem_name_key(bad), redeem_name_key("ab"));
    }

    #[test]
    fn a_full_redeem_table_drops_the_oldest_key() {
        let limit = RedeemLimit::with_max_keys(2);
        for i in 1..=3_u8 {
            let caller = from(&format!("203.0.113.{i}"));
            assert!(limit.admit(&caller, "ada@example.com", 5).is_ok());
        }
        assert_eq!(limit.tracked_keys(), 4);
        assert!(format!("{limit:?}").contains("redacted"));
    }

    #[test]
    fn a_full_table_drops_the_oldest_session() {
        let limit = ChallengeLimit::with_max_keys(2);
        for n in 1..=3 {
            assert!(limit.admit(&sid(n), 5).is_ok());
        }
        assert_eq!(limit.tracked_sessions(), 2);
        // Expired sessions are swept as the clock moves on.
        assert!(limit.admit(&sid(9), WINDOW_SECS.saturating_add(5)).is_ok());
        assert_eq!(limit.tracked_sessions(), 1);
    }
}
