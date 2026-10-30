//! Hooks for rate limiting. The library counts nothing itself.
//!
//! Before it does any work for a request, the library asks a [`Throttle`]
//! whether the caller may proceed ([`Throttle::admit`]). When the request is
//! over, it reports how it went ([`Throttle::record`]). The server wraps its
//! own limiter (token buckets, a back-off per account, the grouping of IPv6
//! addresses into /64 networks) in an implementation of the trait.
//!
//! The check comes first and costs the same for every credential id. For an
//! account that does not exist, the id is the made-up one, so a limiter
//! cannot tell the two apart by what it is asked and a caller cannot tell
//! them apart by what it is told.
//!
//! Spec: Fase 1 § 11 (F-34): a limit per address, a limit per account and
//! address, and a soft limit per account with exponential back-off. There is
//! no hard lock-out, because that would let anyone lock a user out.

use core::fmt;
use core::net::IpAddr;

use crate::{AuthError, CredentialId};

/// The shortest wait a throttle can ask for, in seconds.
const MIN_RETRY_SECS: u32 = 1;
/// The longest wait a throttle can ask for, in seconds: one hour.
const MAX_RETRY_SECS: u32 = 3600;

/// What a limiter counts against.
///
/// An address is the one the server reads from the request. The library does
/// not group addresses: a server that wants every IPv6 address of a /64
/// network to count as one passes the grouped address in [`Caller::ip`].
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub enum ThrottleKey {
    /// Everything from one address.
    Ip(IpAddr),
    /// One account from one address.
    AccountIp(CredentialId, IpAddr),
    /// One account, from anywhere.
    Account(CredentialId),
}

/// Shows the kind of key and nothing else: an address is personal data and a
/// credential id must not be told apart from a made-up one in a log.
impl fmt::Debug for ThrottleKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            ThrottleKey::Ip(_) => "ThrottleKey::Ip([redacted])",
            ThrottleKey::AccountIp(..) => "ThrottleKey::AccountIp([redacted])",
            ThrottleKey::Account(_) => "ThrottleKey::Account([redacted])",
        })
    }
}

/// The step of a flow a request belongs to.
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
    /// The address of the caller, from the session layer of the server, or
    /// `None` when it cannot be read. Without an address, only the keys that
    /// do not need one are used.
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
/// keeps its counters behind its own lock.
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

/// The keys a stage counts against.
///
/// * `LoginStart`: the address, and the account from that address.
/// * `LoginFinish`: the account from that address, and the account alone (a
///   soft limit with back-off, never a lock-out).
/// * `RegisterStart`, `Challenge`, `Replace`: the address, and the account.
///
/// A key that needs an address is left out when the caller has none. `id` is
/// the credential id of the request; for an account that does not exist it is
/// the made-up id, so the keys have the same shape for both.
///
/// Spec: Fase 1 § 11 (F-34).
// The login and signed-call functions are the callers.
#[allow(dead_code)]
pub(crate) fn keys_for(stage: Stage, caller: &Caller, id: &CredentialId) -> Vec<ThrottleKey> {
    let id = *id;
    let mut keys = Vec::with_capacity(2);
    match stage {
        Stage::LoginStart => {
            keys.extend(caller.ip.map(ThrottleKey::Ip));
            keys.extend(caller.ip.map(|ip| ThrottleKey::AccountIp(id, ip)));
        }
        Stage::LoginFinish => {
            keys.extend(caller.ip.map(|ip| ThrottleKey::AccountIp(id, ip)));
            keys.push(ThrottleKey::Account(id));
        }
        Stage::RegisterStart | Stage::Challenge | Stage::Replace => {
            keys.extend(caller.ip.map(ThrottleKey::Ip));
            keys.push(ThrottleKey::Account(id));
        }
    }
    keys
}

/// Asks the throttle and turns a refusal into the error to return.
// The login and signed-call functions are the callers.
#[allow(dead_code)]
pub(crate) fn admit_or_throttle(
    throttle: &dyn Throttle,
    stage: Stage,
    keys: &[ThrottleKey],
    now: u64,
) -> Result<(), AuthError> {
    throttle.admit(stage, keys, now).map_err(AuthError::from)
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
    const V6: IpAddr = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1));
    const NO_IP: Caller = Caller { ip: None };
    const ALL_STAGES: [Stage; 5] = [
        Stage::RegisterStart,
        Stage::LoginStart,
        Stage::LoginFinish,
        Stage::Challenge,
        Stage::Replace,
    ];

    fn with_ip(ip: IpAddr) -> Caller {
        Caller { ip: Some(ip) }
    }

    #[test]
    fn keys_for_login_start_is_address_then_account_from_address() {
        assert_eq!(
            keys_for(Stage::LoginStart, &with_ip(V4), &ID),
            vec![ThrottleKey::Ip(V4), ThrottleKey::AccountIp(ID, V4)]
        );
        assert_eq!(
            keys_for(Stage::LoginStart, &with_ip(V6), &ID),
            vec![ThrottleKey::Ip(V6), ThrottleKey::AccountIp(ID, V6)]
        );
    }

    #[test]
    fn keys_for_login_start_without_an_address_is_empty() {
        assert!(keys_for(Stage::LoginStart, &NO_IP, &ID).is_empty());
    }

    #[test]
    fn keys_for_login_finish_is_account_from_address_then_account() {
        assert_eq!(
            keys_for(Stage::LoginFinish, &with_ip(V4), &ID),
            vec![ThrottleKey::AccountIp(ID, V4), ThrottleKey::Account(ID)]
        );
    }

    #[test]
    fn keys_for_login_finish_without_an_address_keeps_the_account() {
        assert_eq!(
            keys_for(Stage::LoginFinish, &NO_IP, &ID),
            vec![ThrottleKey::Account(ID)]
        );
    }

    #[test]
    fn keys_for_signed_and_registration_stages_are_address_and_account() {
        for stage in [Stage::RegisterStart, Stage::Challenge, Stage::Replace] {
            assert_eq!(
                keys_for(stage, &with_ip(V4), &ID),
                vec![ThrottleKey::Ip(V4), ThrottleKey::Account(ID)]
            );
            assert_eq!(keys_for(stage, &NO_IP, &ID), vec![ThrottleKey::Account(ID)]);
        }
    }

    #[test]
    fn keys_for_a_made_up_id_has_the_same_shape_as_a_real_one() {
        let other = CredentialId::from_bytes([9; 16]);
        for stage in ALL_STAGES {
            for caller in [with_ip(V4), NO_IP] {
                let real = keys_for(stage, &caller, &ID);
                let fake = keys_for(stage, &caller, &other);
                assert_eq!(real.len(), fake.len());
                assert!(real.len() <= 2);
                // Every key that names an account names the id given.
                assert!(fake.iter().all(|k| match k {
                    ThrottleKey::Ip(_) => true,
                    ThrottleKey::AccountIp(id, _) | ThrottleKey::Account(id) => *id == other,
                }));
            }
        }
        // A login start has nothing to count without an address.
        assert!(keys_for(Stage::LoginStart, &NO_IP, &ID).is_empty());
    }

    #[test]
    fn no_throttle_admits_everything() {
        let throttle = NoThrottle;
        for stage in ALL_STAGES {
            let keys = keys_for(stage, &with_ip(V4), &ID);
            assert_eq!(throttle.admit(stage, &keys, 0), Ok(()));
            assert_eq!(throttle.admit(stage, &[], u64::MAX), Ok(()));
            throttle.record(stage, &keys, Outcome::Failure, 1);
            throttle.record(stage, &keys, Outcome::Success, 2);
        }
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
    fn admit_or_throttle_passes_the_decision_on() {
        assert_eq!(
            admit_or_throttle(&NoThrottle, Stage::LoginStart, &[], 5),
            Ok(())
        );
    }

    #[test]
    fn debug_shows_no_address_and_no_id() {
        let shown = format!(
            "{:?} {:?} {:?} {:?}",
            ThrottleKey::AccountIp(ID, V4),
            ThrottleKey::Ip(V4),
            ThrottleKey::Account(ID),
            with_ip(V4)
        );
        assert!(!shown.contains("192"), "{shown}");
        assert!(!shown.contains('7'), "{shown}");
    }
}

#[cfg(all(test, feature = "test-support"))]
mod recording_tests {
    use core::net::Ipv4Addr;

    use super::*;

    const ID: CredentialId = CredentialId::from_bytes([7; 16]);
    const IP: IpAddr = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1));

    #[test]
    fn recording_throttle_remembers_calls_in_order() {
        let throttle = RecordingThrottle::new();
        let caller = Caller { ip: Some(IP) };
        let login = keys_for(Stage::LoginStart, &caller, &ID);
        let finish = keys_for(Stage::LoginFinish, &caller, &ID);

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
}
