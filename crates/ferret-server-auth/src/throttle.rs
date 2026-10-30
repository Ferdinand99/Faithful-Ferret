//! Hooks for rate limiting. The library counts nothing itself.
//!
//! Before it does any work for a request, the library asks a [`Throttle`]
//! whether the caller may proceed. When the request is over, it reports how it
//! went. The server wraps its own limiter (token buckets, a back-off per
//! account) in an implementation of the trait.
//!
//! Inside the crate, the two calls go through an `Admission`: `admit`
//! builds the keys, asks the throttle and hands back a ticket on success. The
//! ticket is the only way to report an outcome, and `Admission::finish`
//! consumes it, so an outcome cannot be reported without a prior admit, and
//! cannot be reported twice. A ticket that is dropped without `finish` (an
//! early return) is reported as a failure.
//!
//! The check comes first and costs the same for every credential id. For an
//! account that does not exist, the id is the made-up one, so a limiter
//! cannot tell the two apart by what it is asked and a caller cannot tell
//! them apart by what it is told.
//!
//! # Addresses
//!
//! `keys_for` groups the address before it goes into a key: an IPv6 address
//! counts as the /64 network it belongs to, and an IPv4-mapped IPv6 address
//! (`::ffff:a.b.c.d`, as a dual-stack listener reports an IPv4 client) counts
//! as the IPv4 address it carries. A caller without a readable address is
//! counted in one shared [`ThrottleKey::UnknownAddress`] bucket, so a missing
//! or misconfigured proxy header never switches a limit off.
//!
//! Spec: Fase 1 § 11 (F-34): a limit per address, a limit per account and
//! address, and a soft limit per account with exponential back-off. There is
//! no hard lock-out, because that would let anyone lock a user out.

use core::fmt;
use core::net::{IpAddr, Ipv6Addr};

use crate::{AuthError, CredentialId};

/// The shortest wait a throttle can ask for, in seconds.
const MIN_RETRY_SECS: u32 = 1;
/// The longest wait a throttle can ask for, in seconds: one hour.
const MAX_RETRY_SECS: u32 = 3600;
/// The first 64 bits of an IPv6 address: the network part of a /64.
const V6_NETWORK_MASK: u128 = 0xFFFF_FFFF_FFFF_FFFF_0000_0000_0000_0000;

/// What a limiter counts against.
///
/// The addresses in a key are already grouped (see `keys_for`): an IPv4
/// address as it is, an IPv6 address as its /64 network with the host bits
/// zero. A counter is scoped per [`Stage`]: the same key in two stages is two
/// counters, so registration probes from an address cannot use up the budget
/// of its logins.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub enum ThrottleKey {
    /// Everything from one (grouped) address.
    Ip(IpAddr),
    /// One account from one (grouped) address.
    AccountIp(CredentialId, IpAddr),
    /// One account, from anywhere.
    Account(CredentialId),
    /// Everything from callers whose address could not be read. One shared
    /// bucket for all of them, so the limit still applies when the address
    /// is missing.
    UnknownAddress,
}

/// Shows the kind of key and nothing else: an address is personal data and a
/// credential id must not be told apart from a made-up one in a log.
impl fmt::Debug for ThrottleKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            ThrottleKey::Ip(_) => "ThrottleKey::Ip([redacted])",
            ThrottleKey::AccountIp(..) => "ThrottleKey::AccountIp([redacted])",
            ThrottleKey::Account(_) => "ThrottleKey::Account([redacted])",
            ThrottleKey::UnknownAddress => "ThrottleKey::UnknownAddress",
        })
    }
}

/// The step of a flow a request belongs to. A limiter keeps its counters per
/// stage.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Stage {
    /// The first message of a registration.
    RegisterStart,
    /// The first message of a login.
    LoginStart,
    /// The last message of a login.
    LoginFinish,
    /// A request for a nonce for a signed call.
    Challenge,
    /// A signed call that replaces the OPAQUE record.
    Replace,
}

/// How a request ended, as reported to [`Throttle::record`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    /// The request did what it was meant to do.
    Success,
    /// The request was refused or failed.
    Failure,
}

/// How long a refused caller should wait, in whole seconds.
///
/// The value is always between one second and one hour, whatever a limiter
/// asks for: a zero would make a client retry in a tight loop, and an
/// unbounded value would be an error in the limiter, not a wait.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct RetryAfter(u32);

impl RetryAfter {
    /// A wait of `secs` seconds, raised to one second or lowered to one hour
    /// when it is outside that range.
    pub const fn new(secs: u32) -> Self {
        if secs < MIN_RETRY_SECS {
            Self(MIN_RETRY_SECS)
        } else if secs > MAX_RETRY_SECS {
            Self(MAX_RETRY_SECS)
        } else {
            Self(secs)
        }
    }

    /// The wait in seconds, from 1 to 3600.
    pub const fn secs(self) -> u32 {
        self.0
    }
}

impl fmt::Debug for RetryAfter {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "RetryAfter({})", self.0)
    }
}

impl From<RetryAfter> for AuthError {
    fn from(wait: RetryAfter) -> Self {
        AuthError::Throttled {
            retry_after_secs: wait.secs(),
        }
    }
}

/// Who is calling, as far as the server can tell.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Caller {
    /// The address of the caller as the session layer of the server reads it,
    /// raw, or `None` when it cannot be read. The library groups it (IPv6 to
    /// its /64, IPv4-mapped to IPv4); a `None` is counted in the shared
    /// [`ThrottleKey::UnknownAddress`] bucket.
    pub ip: Option<IpAddr>,
}

impl fmt::Debug for Caller {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Caller([redacted])")
    }
}

/// The limiter the library asks. Implemented by the server.
///
/// `now` is the time in seconds since the Unix epoch, read from the library's
/// [`Clock`](crate::Clock). The calls take `&self`, so an implementation
/// keeps its counters behind its own lock. Counters are kept per [`Stage`].
///
/// The key list is never empty: a caller without an address is given
/// [`ThrottleKey::UnknownAddress`].
pub trait Throttle: Send + Sync {
    /// Asks whether a request may start. Called before any work is done for
    /// it, with every key of the stage. `Err` carries how long the caller
    /// should wait; the request ends there and nothing is recorded for it.
    fn admit(&self, stage: Stage, keys: &[ThrottleKey], now: u64) -> Result<(), RetryAfter>;

    /// Reports how an admitted request ended, with the same keys.
    fn record(&self, stage: Stage, keys: &[ThrottleKey], outcome: Outcome, now: u64);
}

/// A throttle that admits everything and counts nothing. For tests and for
/// callers that limit somewhere else.
#[derive(Clone, Copy, Default)]
pub struct NoThrottle;

impl fmt::Debug for NoThrottle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("NoThrottle")
    }
}

impl Throttle for NoThrottle {
    fn admit(&self, _stage: Stage, _keys: &[ThrottleKey], _now: u64) -> Result<(), RetryAfter> {
        Ok(())
    }

    fn record(&self, _stage: Stage, _keys: &[ThrottleKey], _outcome: Outcome, _now: u64) {}
}

/// The address a limiter counts: an IPv4 address as it is, an IPv6 address as
/// the /64 network it belongs to (host bits zero). An IPv4-mapped IPv6
/// address (`::ffff:a.b.c.d`) is the IPv4 address it carries, because a
/// dual-stack listener reports IPv4 clients that way and all of them would
/// otherwise fall into the single network `::/64`.
#[cfg_attr(not(test), expect(dead_code, reason = "no entry point calls it yet"))]
fn counted_address(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V4(_) => ip,
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => IpAddr::V4(v4),
            None => IpAddr::V6(Ipv6Addr::from(u128::from(v6) & V6_NETWORK_MASK)),
        },
    }
}

/// The keys a stage counts against. Every address in a key goes through
/// [`counted_address`]. The list is never empty.
///
/// With a known address `ip` and credential id `id`:
///
/// * `LoginStart`: `[Ip(ip), AccountIp(id, ip)]`.
/// * `LoginFinish`: `[AccountIp(id, ip), Account(id)]` (a soft limit with
///   back-off, never a lock-out).
/// * `RegisterStart`, `Challenge`, `Replace`: `[Ip(ip), Account(id)]`.
///
/// Where the caller has no address, the key that needs one is
/// [`ThrottleKey::UnknownAddress`] (for `LoginFinish` it stands in for
/// `AccountIp`, and `Account(id)` stays). Where the id is not known (a login
/// state that is not found has no account), only address keys are used:
/// `Ip(ip)` for every stage, or `UnknownAddress` without an address.
///
/// The id is used as given, so a made-up id gives keys of the same shape as a
/// real one.
///
/// Spec: Fase 1 § 11 (F-34).
#[cfg_attr(not(test), expect(dead_code, reason = "no entry point calls it yet"))]
fn keys_for(stage: Stage, caller: &Caller, id: Option<&CredentialId>) -> Vec<ThrottleKey> {
    let ip = caller.ip.map(counted_address);
    let id = id.copied();
    let address_key = ip.map_or(ThrottleKey::UnknownAddress, ThrottleKey::Ip);
    match (stage, id, ip) {
        (Stage::LoginStart, Some(id), Some(ip)) => {
            vec![address_key, ThrottleKey::AccountIp(id, ip)]
        }
        (Stage::LoginFinish, Some(id), Some(ip)) => {
            vec![ThrottleKey::AccountIp(id, ip), ThrottleKey::Account(id)]
        }
        (Stage::LoginFinish, Some(id), None) => {
            vec![ThrottleKey::UnknownAddress, ThrottleKey::Account(id)]
        }
        (Stage::RegisterStart | Stage::Challenge | Stage::Replace, Some(id), _) => {
            vec![address_key, ThrottleKey::Account(id)]
        }
        // No id, or a login start without a usable pair: the address alone.
        (_, _, _) => vec![address_key],
    }
}

/// The right to report one outcome for one admitted request.
///
/// Only [`admit`] makes one. [`finish`](Admission::finish) consumes it, so an
/// outcome cannot be reported without an admit or twice. A ticket dropped
/// without `finish` (an early return or an unwinding panic) is reported as
/// [`Outcome::Failure`], at the time of the admit, because a request that
/// never said how it ended did not succeed.
#[must_use = "report the outcome with `finish`; a dropped ticket counts as a failure"]
#[cfg_attr(not(test), expect(dead_code, reason = "no entry point calls it yet"))]
pub(crate) struct Admission<'a> {
    throttle: &'a dyn Throttle,
    stage: Stage,
    keys: Vec<ThrottleKey>,
    admitted_at: u64,
    reported: bool,
}

#[cfg_attr(not(test), expect(dead_code, reason = "no entry point calls it yet"))]
impl Admission<'_> {
    /// Reports how the request ended, with the stage and keys of the admit.
    pub(crate) fn finish(mut self, outcome: Outcome, now: u64) {
        self.reported = true;
        self.throttle.record(self.stage, &self.keys, outcome, now);
    }
}

impl Drop for Admission<'_> {
    fn drop(&mut self) {
        if !self.reported {
            self.throttle
                .record(self.stage, &self.keys, Outcome::Failure, self.admitted_at);
        }
    }
}

impl fmt::Debug for Admission<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Admission([redacted])")
    }
}

/// Builds the keys of `stage` for this caller, asks the throttle, and returns
/// the ticket for the outcome, or the error to answer with. Call it before
/// any work for the request.
///
/// `id` is `None` when the credential id is not known yet; see [`keys_for`].
#[cfg_attr(not(test), expect(dead_code, reason = "no entry point calls it yet"))]
pub(crate) fn admit<'a>(
    throttle: &'a dyn Throttle,
    stage: Stage,
    caller: &Caller,
    id: Option<&CredentialId>,
    now: u64,
) -> Result<Admission<'a>, AuthError> {
    let keys = keys_for(stage, caller, id);
    throttle.admit(stage, &keys, now)?;
    Ok(Admission {
        throttle,
        stage,
        keys,
        admitted_at: now,
        reported: false,
    })
}

/// One call a [`RecordingThrottle`] has seen.
#[cfg(feature = "test-support")]
#[derive(Clone, PartialEq, Eq)]
pub enum ThrottleCall {
    /// A call to [`Throttle::admit`].
    Admit {
        /// The stage given.
        stage: Stage,
        /// The keys given.
        keys: Vec<ThrottleKey>,
        /// The time given.
        now: u64,
    },
    /// A call to [`Throttle::record`].
    Record {
        /// The stage given.
        stage: Stage,
        /// The keys given.
        keys: Vec<ThrottleKey>,
        /// The outcome given.
        outcome: Outcome,
        /// The time given.
        now: u64,
    },
}

#[cfg(feature = "test-support")]
impl fmt::Debug for ThrottleCall {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let (name, stage) = match self {
            ThrottleCall::Admit { stage, .. } => ("Admit", stage),
            ThrottleCall::Record { stage, .. } => ("Record", stage),
        };
        write!(f, "ThrottleCall::{name}({stage:?})")
    }
}

/// A throttle for tests: it remembers every call in order and can be told to
/// refuse. Behind the `test-support` feature, never part of a release.
#[cfg(feature = "test-support")]
pub struct RecordingThrottle {
    state: std::sync::Mutex<RecordingState>,
}

#[cfg(feature = "test-support")]
struct RecordingState {
    refuse: Option<RetryAfter>,
    calls: Vec<ThrottleCall>,
}

#[cfg(feature = "test-support")]
impl fmt::Debug for RecordingState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("RecordingState")
    }
}

#[cfg(feature = "test-support")]
impl RecordingThrottle {
    /// A throttle that admits every request.
    pub fn new() -> Self {
        Self {
            state: std::sync::Mutex::new(RecordingState {
                refuse: None,
                calls: Vec::new(),
            }),
        }
    }

    /// A throttle that refuses every request with `wait`.
    pub fn refusing(wait: RetryAfter) -> Self {
        let throttle = Self::new();
        throttle.refuse_with(Some(wait));
        throttle
    }

    /// Makes later `admit` calls refuse with `wait`, or admit again for
    /// `None`.
    pub fn refuse_with(&self, wait: Option<RetryAfter>) {
        self.lock().refuse = wait;
    }

    /// Every call so far, oldest first. A refused `admit` is in the list too.
    pub fn calls(&self) -> Vec<ThrottleCall> {
        self.lock().calls.clone()
    }

    /// Forgets the calls so far. The refusal setting stays.
    pub fn clear(&self) {
        self.lock().calls.clear();
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, RecordingState> {
        // A panic in another test thread cannot leave a half-written list.
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

#[cfg(feature = "test-support")]
impl Default for RecordingThrottle {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(feature = "test-support")]
impl fmt::Debug for RecordingThrottle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("RecordingThrottle")
    }
}

#[cfg(feature = "test-support")]
impl Throttle for RecordingThrottle {
    fn admit(&self, stage: Stage, keys: &[ThrottleKey], now: u64) -> Result<(), RetryAfter> {
        let mut state = self.lock();
        state.calls.push(ThrottleCall::Admit {
            stage,
            keys: keys.to_vec(),
            now,
        });
        match state.refuse {
            Some(wait) => Err(wait),
            None => Ok(()),
        }
    }

    fn record(&self, stage: Stage, keys: &[ThrottleKey], outcome: Outcome, now: u64) {
        self.lock().calls.push(ThrottleCall::Record {
            stage,
            keys: keys.to_vec(),
            outcome,
            now,
        });
    }
}

#[cfg(test)]
mod tests {
    use core::net::{Ipv4Addr, Ipv6Addr};

    use super::*;

    const ID: CredentialId = CredentialId::from_bytes([7; 16]);
    const V4: IpAddr = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1));
    const V4_OTHER: IpAddr = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 2));
    const NO_IP: Caller = Caller { ip: None };
    const ALL_STAGES: [Stage; 5] = [
        Stage::RegisterStart,
        Stage::LoginStart,
        Stage::LoginFinish,
        Stage::Challenge,
        Stage::Replace,
    ];

    fn v6(segments: [u16; 8]) -> IpAddr {
        IpAddr::V6(Ipv6Addr::from(segments))
    }

    fn with_ip(ip: IpAddr) -> Caller {
        Caller { ip: Some(ip) }
    }

    fn keys(stage: Stage, caller: &Caller) -> Vec<ThrottleKey> {
        keys_for(stage, caller, Some(&ID))
    }

    /// A throttle that refuses with a huge wait. No feature needed.
    struct Refuse;

    impl fmt::Debug for Refuse {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_str("Refuse")
        }
    }

    impl Throttle for Refuse {
        fn admit(&self, _: Stage, _: &[ThrottleKey], _: u64) -> Result<(), RetryAfter> {
            Err(RetryAfter::new(u32::MAX))
        }

        fn record(&self, _: Stage, _: &[ThrottleKey], _: Outcome, _: u64) {
            panic!("a refused request must not be recorded");
        }
    }

    #[test]
    fn keys_for_login_start_is_address_then_account_from_address() {
        assert_eq!(
            keys(Stage::LoginStart, &with_ip(V4)),
            vec![ThrottleKey::Ip(V4), ThrottleKey::AccountIp(ID, V4)]
        );
    }

    #[test]
    fn keys_for_login_finish_is_account_from_address_then_account() {
        assert_eq!(
            keys(Stage::LoginFinish, &with_ip(V4)),
            vec![ThrottleKey::AccountIp(ID, V4), ThrottleKey::Account(ID)]
        );
    }

    #[test]
    fn keys_for_signed_and_registration_stages_are_address_and_account() {
        for stage in [Stage::RegisterStart, Stage::Challenge, Stage::Replace] {
            assert_eq!(
                keys(stage, &with_ip(V4)),
                vec![ThrottleKey::Ip(V4), ThrottleKey::Account(ID)]
            );
        }
    }

    #[test]
    fn keys_for_ipv6_holds_the_zeroed_network_in_every_key() {
        let network = v6([0x2001, 0xdb8, 0, 0, 0, 0, 0, 0]);
        let host = with_ip(v6([0x2001, 0xdb8, 0, 0, 0x1234, 0x5678, 0x9abc, 0xdef0]));
        assert_eq!(
            keys(Stage::LoginStart, &host),
            vec![
                ThrottleKey::Ip(network),
                ThrottleKey::AccountIp(ID, network)
            ]
        );
        assert_eq!(
            keys(Stage::LoginFinish, &host),
            vec![
                ThrottleKey::AccountIp(ID, network),
                ThrottleKey::Account(ID)
            ]
        );
        for stage in [Stage::RegisterStart, Stage::Challenge, Stage::Replace] {
            assert_eq!(
                keys(stage, &host),
                vec![ThrottleKey::Ip(network), ThrottleKey::Account(ID)]
            );
        }
    }

    #[test]
    fn addresses_in_one_slash_64_share_keys_and_neighbours_do_not() {
        let a = with_ip(v6([0x2001, 0xdb8, 1, 2, 0, 0, 0, 1]));
        let b = with_ip(v6([0x2001, 0xdb8, 1, 2, 0xffff, 0xffff, 0xffff, 0xffff]));
        let next = with_ip(v6([0x2001, 0xdb8, 1, 3, 0, 0, 0, 1]));
        for stage in ALL_STAGES {
            assert_eq!(keys(stage, &a), keys(stage, &b), "{stage:?}");
            assert_ne!(keys(stage, &a), keys(stage, &next), "{stage:?}");
        }
    }

    #[test]
    fn an_ipv4_mapped_address_counts_as_the_ipv4_address() {
        let mapped = |a: Ipv4Addr| with_ip(IpAddr::V6(a.to_ipv6_mapped()));
        for stage in ALL_STAGES {
            assert_eq!(
                keys(stage, &mapped(Ipv4Addr::new(192, 0, 2, 1))),
                keys(stage, &with_ip(V4)),
                "{stage:?}"
            );
            // Two IPv4 clients behind one dual-stack listener are two buckets.
            assert_ne!(
                keys(stage, &mapped(Ipv4Addr::new(192, 0, 2, 1))),
                keys(stage, &mapped(Ipv4Addr::new(192, 0, 2, 2))),
                "{stage:?}"
            );
        }
    }

    #[test]
    fn an_ipv4_address_is_counted_as_it_is() {
        assert_eq!(counted_address(V4), V4);
        assert_ne!(counted_address(V4), counted_address(V4_OTHER));
    }

    #[test]
    fn counted_address_keeps_the_mapped_prefix_check_exact() {
        // `::ffff:0:0/96` is the mapped range; a neighbour is an ordinary
        // IPv6 address and counts as its /64.
        let not_mapped = v6([0, 0, 0, 0, 0xfffe, 0, 0xc000, 0x201]);
        assert_eq!(counted_address(not_mapped), v6([0; 8]));
    }

    #[test]
    fn a_caller_without_an_address_is_never_an_empty_key_list() {
        for stage in ALL_STAGES {
            for id in [Some(&ID), None] {
                let keys = keys_for(stage, &NO_IP, id);
                assert!(!keys.is_empty(), "{stage:?}");
                assert!(keys.contains(&ThrottleKey::UnknownAddress), "{stage:?}");
            }
        }
    }

    #[test]
    fn callers_without_an_address_share_one_address_bucket() {
        let other = CredentialId::from_bytes([9; 16]);
        for stage in ALL_STAGES {
            let mine = keys_for(stage, &NO_IP, Some(&ID));
            let theirs = keys_for(stage, &NO_IP, Some(&other));
            let unknown = |keys: &[ThrottleKey]| {
                keys.iter()
                    .filter(|k| matches!(k, ThrottleKey::UnknownAddress))
                    .count()
            };
            assert_eq!(unknown(&mine), 1, "{stage:?}");
            assert_eq!(unknown(&theirs), 1, "{stage:?}");
        }
        assert_eq!(
            keys_for(Stage::LoginStart, &NO_IP, Some(&ID)),
            vec![ThrottleKey::UnknownAddress]
        );
        assert_eq!(
            keys_for(Stage::LoginStart, &NO_IP, None),
            vec![ThrottleKey::UnknownAddress]
        );
        assert_eq!(
            keys_for(Stage::LoginFinish, &NO_IP, Some(&ID)),
            vec![ThrottleKey::UnknownAddress, ThrottleKey::Account(ID)]
        );
    }

    #[test]
    fn a_missing_address_fails_closed_through_a_refusing_throttle() {
        let err = admit(&Refuse, Stage::LoginStart, &NO_IP, Some(&ID), 5).unwrap_err();
        assert_eq!(err.http_class(), crate::ErrorClass::TooManyRequests);
    }

    #[test]
    fn keys_for_an_unknown_id_are_address_keys_only() {
        for stage in ALL_STAGES {
            assert_eq!(
                keys_for(stage, &with_ip(V4), None),
                vec![ThrottleKey::Ip(V4)],
                "{stage:?}"
            );
        }
    }

    #[test]
    fn no_throttle_admits_everything() {
        let throttle = NoThrottle;
        for stage in ALL_STAGES {
            let keys = keys(stage, &with_ip(V4));
            assert_eq!(throttle.admit(stage, &keys, 0), Ok(()));
            assert_eq!(throttle.admit(stage, &[], u64::MAX), Ok(()));
            throttle.record(stage, &keys, Outcome::Failure, 1);
            throttle.record(stage, &keys, Outcome::Success, 2);
        }
        let ticket = admit(&throttle, Stage::LoginStart, &with_ip(V4), Some(&ID), 3).unwrap();
        ticket.finish(Outcome::Success, 4);
    }

    #[test]
    fn retry_after_is_clamped_to_one_hour() {
        assert_eq!(RetryAfter::new(3600).secs(), 3600);
        assert_eq!(RetryAfter::new(3601).secs(), 3600);
        assert_eq!(RetryAfter::new(u32::MAX).secs(), 3600);
    }

    #[test]
    fn retry_after_is_at_least_one_second() {
        assert_eq!(RetryAfter::new(0).secs(), 1);
        assert_eq!(RetryAfter::new(1).secs(), 1);
        assert_eq!(RetryAfter::new(2).secs(), 2);
    }

    #[test]
    fn a_refusal_becomes_a_429_error_with_the_clamped_wait() {
        let err = AuthError::from(RetryAfter::new(u32::MAX));
        assert_eq!(
            err,
            AuthError::Throttled {
                retry_after_secs: 3600
            }
        );
        assert_eq!(err.http_class(), crate::ErrorClass::TooManyRequests);
    }

    #[test]
    fn a_refused_admit_is_a_throttled_error_with_no_ticket() {
        // `Refuse` panics if it is recorded to, so this also shows that a
        // refusal hands out no ticket that could report.
        let result = admit(&Refuse, Stage::LoginFinish, &with_ip(V4), Some(&ID), 9);
        assert_eq!(
            result.err(),
            Some(AuthError::Throttled {
                retry_after_secs: 3600
            })
        );
    }

    #[test]
    fn debug_shows_no_address_and_no_id() {
        let ticket = admit(&NoThrottle, Stage::Replace, &with_ip(V4), Some(&ID), 1).unwrap();
        let shown = format!(
            "{:?} {:?} {:?} {:?} {:?} {:?}",
            ThrottleKey::AccountIp(ID, V4),
            ThrottleKey::Ip(V4),
            ThrottleKey::Account(ID),
            with_ip(V4),
            ticket,
            Refuse
        );
        ticket.finish(Outcome::Success, 2);
        assert!(!shown.contains("192"), "{shown}");
        assert!(!shown.contains('7'), "{shown}");
    }
}

#[cfg(all(test, feature = "test-support"))]
mod recording_tests {
    use core::net::Ipv4Addr;

    use super::*;

    const ID: CredentialId = CredentialId::from_bytes([7; 16]);
    const FAKE: CredentialId = CredentialId::from_bytes([9; 16]);
    const IP: IpAddr = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1));
    const CALLER: Caller = Caller { ip: Some(IP) };

    /// The kind of a key, without the values in it.
    fn shape(key: &ThrottleKey) -> u8 {
        match key {
            ThrottleKey::Ip(_) => 0,
            ThrottleKey::AccountIp(..) => 1,
            ThrottleKey::Account(_) => 2,
            ThrottleKey::UnknownAddress => 3,
        }
    }

    fn shapes(calls: &[ThrottleCall]) -> Vec<(Stage, Vec<u8>)> {
        calls
            .iter()
            .map(|call| match call {
                ThrottleCall::Admit { stage, keys, .. }
                | ThrottleCall::Record { stage, keys, .. } => {
                    (*stage, keys.iter().map(shape).collect())
                }
            })
            .collect()
    }

    #[test]
    fn recording_throttle_remembers_calls_in_order() {
        let throttle = RecordingThrottle::new();
        let login = keys_for(Stage::LoginStart, &CALLER, Some(&ID));
        let finish = keys_for(Stage::LoginFinish, &CALLER, Some(&ID));

        assert_eq!(throttle.admit(Stage::LoginStart, &login, 10), Ok(()));
        throttle.record(Stage::LoginStart, &login, Outcome::Success, 11);
        assert_eq!(throttle.admit(Stage::LoginFinish, &finish, 12), Ok(()));
        throttle.record(Stage::LoginFinish, &finish, Outcome::Failure, 13);

        assert_eq!(
            throttle.calls(),
            vec![
                ThrottleCall::Admit {
                    stage: Stage::LoginStart,
                    keys: login.clone(),
                    now: 10
                },
                ThrottleCall::Record {
                    stage: Stage::LoginStart,
                    keys: login,
                    outcome: Outcome::Success,
                    now: 11
                },
                ThrottleCall::Admit {
                    stage: Stage::LoginFinish,
                    keys: finish.clone(),
                    now: 12
                },
                ThrottleCall::Record {
                    stage: Stage::LoginFinish,
                    keys: finish,
                    outcome: Outcome::Failure,
                    now: 13
                },
            ]
        );
    }

    #[test]
    fn recording_throttle_refuses_when_told_to_and_still_remembers_the_call() {
        let throttle = RecordingThrottle::refusing(RetryAfter::new(30));
        assert_eq!(
            throttle.admit(Stage::Challenge, &[], 1),
            Err(RetryAfter::new(30))
        );
        assert_eq!(throttle.calls().len(), 1);

        throttle.refuse_with(None);
        assert_eq!(throttle.admit(Stage::Challenge, &[], 2), Ok(()));
        assert_eq!(throttle.calls().len(), 2);

        throttle.clear();
        assert!(throttle.calls().is_empty());
    }

    #[test]
    fn the_throttles_can_be_shared_between_threads() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<RecordingThrottle>();
        assert_send_sync::<NoThrottle>();
    }

    #[test]
    fn the_recording_debug_shows_no_keys() {
        let throttle = RecordingThrottle::new();
        let keys = [ThrottleKey::Account(ID)];
        let _ = throttle.admit(Stage::Replace, &keys, 3);
        let shown = format!("{throttle:?} {:?}", throttle.calls());
        assert!(!shown.contains('7'), "{shown}");
    }

    #[test]
    fn a_refused_admit_asks_once_with_the_keys_and_the_time_and_records_nothing() {
        let throttle = RecordingThrottle::refusing(RetryAfter::new(u32::MAX));
        let result = admit(&throttle, Stage::LoginStart, &CALLER, Some(&ID), 42);
        assert_eq!(
            result.err(),
            Some(AuthError::Throttled {
                retry_after_secs: 3600
            })
        );
        assert_eq!(
            throttle.calls(),
            vec![ThrottleCall::Admit {
                stage: Stage::LoginStart,
                keys: vec![ThrottleKey::Ip(IP), ThrottleKey::AccountIp(ID, IP)],
                now: 42
            }]
        );
    }

    #[test]
    fn finish_records_once_with_the_admitted_stage_and_keys() {
        let throttle = RecordingThrottle::new();
        let ticket = admit(&throttle, Stage::LoginFinish, &CALLER, Some(&ID), 10).unwrap();
        ticket.finish(Outcome::Success, 15);
        assert_eq!(
            throttle.calls(),
            vec![
                ThrottleCall::Admit {
                    stage: Stage::LoginFinish,
                    keys: vec![ThrottleKey::AccountIp(ID, IP), ThrottleKey::Account(ID)],
                    now: 10
                },
                ThrottleCall::Record {
                    stage: Stage::LoginFinish,
                    keys: vec![ThrottleKey::AccountIp(ID, IP), ThrottleKey::Account(ID)],
                    outcome: Outcome::Success,
                    now: 15
                },
            ]
        );
    }

    #[test]
    fn a_dropped_ticket_is_recorded_as_a_failure_at_the_admit_time() {
        let throttle = RecordingThrottle::new();
        {
            let _ticket = admit(&throttle, Stage::Replace, &CALLER, Some(&ID), 20).unwrap();
            // An early return would leave the scope here.
        }
        let calls = throttle.calls();
        assert_eq!(calls.len(), 2);
        assert_eq!(
            calls.get(1),
            Some(&ThrottleCall::Record {
                stage: Stage::Replace,
                keys: vec![ThrottleKey::Ip(IP), ThrottleKey::Account(ID)],
                outcome: Outcome::Failure,
                now: 20
            })
        );
    }

    #[test]
    fn a_finished_ticket_is_not_recorded_again_when_it_drops() {
        let throttle = RecordingThrottle::new();
        let ticket = admit(&throttle, Stage::Challenge, &CALLER, Some(&ID), 1).unwrap();
        ticket.finish(Outcome::Failure, 2);
        // `finish` consumed the ticket and it has been dropped: one admit, one record.
        assert_eq!(throttle.calls().len(), 2);
    }

    #[test]
    fn a_real_and_a_made_up_id_give_the_same_calls_in_shape() {
        // The same path for both ids: only the id differs.
        for stage in [
            Stage::RegisterStart,
            Stage::LoginStart,
            Stage::LoginFinish,
            Stage::Challenge,
            Stage::Replace,
        ] {
            for caller in [CALLER, Caller { ip: None }] {
                let run = |id: &CredentialId| {
                    let throttle = RecordingThrottle::new();
                    let ticket = admit(&throttle, stage, &caller, Some(id), 5).unwrap();
                    ticket.finish(Outcome::Failure, 6);
                    throttle.calls()
                };
                let real = run(&ID);
                let fake = run(&FAKE);
                assert_eq!(shapes(&real), shapes(&fake), "{stage:?}");
                assert_eq!(real.len(), 2);
                // The ids reach the keys (a login start without an address has none),
                // so the check above is not comparing identical lists.
                if !(stage == Stage::LoginStart && caller.ip.is_none()) {
                    assert_ne!(real, fake, "{stage:?}");
                }
            }
        }
    }
}
