//! The rate limits of the sign-in and the registration. The sign-in tests run
//! through `ferret-server-auth`'s `login_start`, so they also cover the keys the
//! library builds (the /64 grouping, the shared bucket for unknown addresses);
//! the others call the limiter directly.

mod support;

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;

use axum::http::{HeaderMap, HeaderValue};
use ferret_core::TestRng;
use ferret_server::auth::throttle::{KitThrottle, caller_from};
use ferret_server_auth::testing::LoginFixture;
use ferret_server_auth::{
    AccountLookup, AuthContext, AuthError, Caller, Clock, LoginPurpose, LoginStartRequest,
    ManualClock, Outcome, Stage, Throttle, ThrottleKey, login_start, normalize_login_name,
};

const START: u64 = 1_700_000_000;

/// A server with the kit throttle and a clock the test moves.
struct Harness {
    fixture: LoginFixture,
    clock: Arc<ManualClock>,
    throttle: KitThrottle,
    ke1: Vec<u8>,
    calls: std::sync::atomic::AtomicU32,
}

impl Harness {
    fn new() -> Self {
        let fixture = LoginFixture::new();
        let clock = Arc::new(ManualClock::new(START));
        let throttle = KitThrottle::new(clock.clone() as Arc<dyn Clock>);
        let (ke1, _state) = fixture.client_start("a password", "throttle test");
        Self {
            fixture,
            clock,
            throttle,
            ke1,
            calls: std::sync::atomic::AtomicU32::new(0),
        }
    }

    /// A first message of a login for `name` from `ip`, through the library.
    fn login_start(&self, name: &str, ip: Option<IpAddr>) -> Result<(), AuthError> {
        let name = normalize_login_name(name).expect("a login name");
        let f = &self.fixture;
        let cx = AuthContext::new(
            &f.keys,
            &f.prelogin,
            &f.seal,
            &*self.clock,
            &self.throttle,
            &f.policy,
            &f.profiles,
        );
        let n = self
            .calls
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        login_start(
            &cx,
            &f.store,
            &mut TestRng::new(format!("throttle {n}").as_bytes()),
            &LoginStartRequest {
                caller: Caller { ip },
                name: &name,
                credential: f.credential,
                lookup: AccountLookup::Unknown,
                purpose: LoginPurpose::Login,
                session_scope: None,
                ke1: &self.ke1,
            },
        )
        .map(|_| ())
    }
}

fn ip(text: &str) -> Option<IpAddr> {
    Some(text.parse().expect("an address"))
}

fn retry_after(result: Result<(), AuthError>) -> u32 {
    match result {
        Err(AuthError::Throttled { retry_after_secs }) => retry_after_secs,
        other => panic!("expected a throttle, got {other:?}"),
    }
}

#[test]
fn eleventh_login_start_from_one_ip_is_throttled_with_retry_after() {
    let h = Harness::new();
    // Ten different names from one address: the address limit, not the
    // account limit, is what counts.
    for n in 0..10 {
        h.login_start(&format!("user{n}@example.com"), ip("192.0.2.7"))
            .unwrap_or_else(|e| panic!("attempt {n}: {e:?}"));
    }
    let wait = retry_after(h.login_start("user10@example.com", ip("192.0.2.7")));
    assert_eq!(wait, 60, "all ten came in the same second");

    // Another address is not affected.
    h.login_start("user10@example.com", ip("192.0.2.8"))
        .expect("another address");

    // The wait is honest: just before it ends the answer is still no, and at
    // the end it is yes.
    h.clock.advance(u64::from(wait) - 1);
    assert_eq!(
        retry_after(h.login_start("user11@example.com", ip("192.0.2.7"))),
        1
    );
    h.clock.advance(1);
    h.login_start("user11@example.com", ip("192.0.2.7"))
        .expect("the window has passed");
}

#[test]
fn a_refused_attempt_is_not_counted_so_hammering_does_not_extend_the_block() {
    let h = Harness::new();
    for n in 0..10 {
        h.login_start(&format!("user{n}@example.com"), ip("192.0.2.7"))
            .expect("within the limit");
    }
    for n in 0..50 {
        h.clock.advance(1);
        let _ = h.login_start(&format!("hammer{n}@example.com"), ip("192.0.2.7"));
    }
    // 50 seconds on; the ten counted attempts left the window at +60.
    h.clock.advance(10);
    h.login_start("after@example.com", ip("192.0.2.7"))
        .expect("the block ended on time");
}

#[test]
fn the_sixth_login_start_for_one_account_from_one_ip_is_throttled() {
    let h = Harness::new();
    for n in 0..5 {
        h.login_start("alice@example.com", ip("192.0.2.7"))
            .unwrap_or_else(|e| panic!("attempt {n}: {e:?}"));
    }
    assert!(retry_after(h.login_start("alice@example.com", ip("192.0.2.7"))) >= 1);
    // The same name from another address, and another name from this one.
    h.login_start("alice@example.com", ip("192.0.2.8"))
        .expect("another address");
    h.login_start("bob@example.com", ip("192.0.2.7"))
        .expect("another account");
}

#[test]
fn unknown_address_shares_one_bucket() {
    let h = Harness::new();
    for n in 0..10 {
        h.login_start(&format!("user{n}@example.com"), None)
            .unwrap_or_else(|e| panic!("attempt {n}: {e:?}"));
    }
    // An eleventh without an address, under yet another name, shares the
    // bucket of the ten.
    assert!(retry_after(h.login_start("user10@example.com", None)) >= 1);
    // A caller with an address has its own.
    h.login_start("user10@example.com", ip("192.0.2.7"))
        .expect("a readable address");

    // `caller_from` gives no address when there is no peer and no header.
    assert_eq!(caller_from(&HeaderMap::new(), None).ip, None);
}

#[test]
fn ipv6_is_grouped_by_64() {
    let h = Harness::new();
    // Ten addresses of one /64.
    for n in 1..=10u16 {
        h.login_start(
            &format!("user{n}@example.com"),
            ip(&format!("2001:db8:1:2::{n:x}")),
        )
        .unwrap_or_else(|e| panic!("attempt {n}: {e:?}"));
    }
    // An eleventh address of the same /64 is throttled, one of the next /64 is
    // not.
    assert!(retry_after(h.login_start("user11@example.com", ip("2001:db8:1:2:ffff::1"))) >= 1);
    h.login_start("user11@example.com", ip("2001:db8:1:3::1"))
        .expect("another /64");
}

#[test]
fn an_ipv4_mapped_address_counts_as_the_ipv4_address() {
    let h = Harness::new();
    for n in 0..5 {
        h.login_start("alice@example.com", ip("192.0.2.7"))
            .unwrap_or_else(|e| panic!("attempt {n}: {e:?}"));
    }
    assert!(retry_after(h.login_start("alice@example.com", ip("::ffff:192.0.2.7"))) >= 1);
}

#[test]
fn register_start_is_limited_to_five_per_ip_per_minute() {
    let clock = Arc::new(ManualClock::new(START));
    let throttle = KitThrottle::new(clock.clone() as Arc<dyn Clock>);
    let keys = [ThrottleKey::Ip("192.0.2.7".parse().unwrap())];
    for _ in 0..5 {
        throttle
            .admit(Stage::RegisterStart, &keys, START)
            .expect("within the limit");
    }
    let wait = throttle
        .admit(Stage::RegisterStart, &keys, START)
        .expect_err("the sixth");
    assert_eq!(wait.secs(), 60);
    // The login limit of the same address is a counter of its own.
    throttle
        .admit(Stage::LoginStart, &keys, START)
        .expect("a login from the same address");
    // And the window slides.
    throttle
        .admit(Stage::RegisterStart, &keys, START + 60)
        .expect("a minute later");
}

#[test]
fn stages_without_a_limit_admit_everything() {
    let throttle = KitThrottle::new(Arc::new(ManualClock::new(START)));
    let keys = [ThrottleKey::Ip("192.0.2.7".parse().unwrap())];
    for stage in [Stage::LoginFinish, Stage::Challenge, Stage::Replace] {
        for _ in 0..100 {
            throttle.admit(stage, &keys, START).expect("not limited");
            throttle.record(stage, &keys, Outcome::Failure, START);
        }
    }
}

#[test]
fn all_keys_must_admit_and_nothing_is_counted_for_a_refusal() {
    let throttle = KitThrottle::new(Arc::new(ManualClock::new(START)));
    let address = ThrottleKey::Ip("192.0.2.7".parse().unwrap());
    let account = ThrottleKey::AccountIp(
        ferret_server_auth::CredentialId::from_bytes([1; 16]),
        "192.0.2.7".parse().unwrap(),
    );
    for _ in 0..5 {
        throttle
            .admit(Stage::LoginStart, &[address, account], START)
            .expect("within both limits");
    }
    // The account limit is spent; the address key is not charged for the
    // refusal, so five more attempts under other accounts still fit.
    throttle
        .admit(Stage::LoginStart, &[address, account], START)
        .expect_err("the account limit");
    let other = ThrottleKey::AccountIp(
        ferret_server_auth::CredentialId::from_bytes([2; 16]),
        "192.0.2.7".parse().unwrap(),
    );
    for _ in 0..5 {
        throttle
            .admit(Stage::LoginStart, &[address, other], START)
            .expect("the address has five left");
    }
    throttle
        .admit(Stage::LoginStart, &[address, other], START)
        .expect_err("now the address is spent");
}

#[test]
fn caller_from_reads_the_forwarded_address_or_the_peer() {
    let peer: SocketAddr = "10.0.3.26:4000".parse().unwrap();
    let mut headers = HeaderMap::new();
    assert_eq!(
        caller_from(&headers, Some(peer)).ip,
        Some(IpAddr::V4(Ipv4Addr::new(10, 0, 3, 26)))
    );
    // `proxy_guard` has already removed these from untrusted peers, so what is
    // left is believed: the right-most entry, which the last proxy wrote.
    headers.insert(
        "x-forwarded-for",
        HeaderValue::from_static("203.0.113.9, 198.51.100.4"),
    );
    assert_eq!(caller_from(&headers, Some(peer)).ip, ip("198.51.100.4"));
    let mut real = HeaderMap::new();
    real.insert("x-real-ip", HeaderValue::from_static("198.51.100.77"));
    assert_eq!(caller_from(&real, Some(peer)).ip, ip("198.51.100.77"));
    // Junk falls back to the peer.
    let mut junk = HeaderMap::new();
    junk.insert(
        "x-forwarded-for",
        HeaderValue::from_static("not an address"),
    );
    assert_eq!(caller_from(&junk, Some(peer)).ip, Some(peer.ip()));
}

fn address(n: u32) -> ThrottleKey {
    ThrottleKey::Ip(IpAddr::V4(Ipv4Addr::from(0xc000_0200 + n)))
}

#[test]
fn a_full_table_drops_its_oldest_keys_instead_of_refusing_anyone() {
    let clock = Arc::new(ManualClock::new(START));
    let throttle = KitThrottle::with_max_keys(clock as Arc<dyn Clock>, 50);

    // The first address spends its whole registration allowance.
    for _ in 0..5 {
        throttle
            .admit(Stage::RegisterStart, &[address(0)], START)
            .expect("within the limit");
    }
    throttle
        .admit(Stage::RegisterStart, &[address(0)], START)
        .expect_err("the sixth");

    // Fill the table, and go on: nobody is refused, the table stays at its cap.
    for n in 1..200 {
        throttle
            .admit(Stage::RegisterStart, &[address(n)], START)
            .unwrap_or_else(|_| panic!("a new address ({n}) is refused by a full table"));
        assert!(throttle.tracked_keys() <= 50, "{}", throttle.tracked_keys());
    }
    assert_eq!(throttle.tracked_keys(), 50);

    // The oldest key was dropped to make room, so its counter starts again;
    // a recent key still has its own.
    throttle
        .admit(Stage::RegisterStart, &[address(0)], START)
        .expect("the dropped key starts again");
    for _ in 1..5 {
        throttle
            .admit(Stage::RegisterStart, &[address(199)], START)
            .expect("a recent key is kept and counts");
    }
    throttle
        .admit(Stage::RegisterStart, &[address(199)], START)
        .expect_err("the recent key's counter was kept");
}

#[test]
fn flooding_the_login_table_does_not_lock_out_a_new_caller() {
    let clock = Arc::new(ManualClock::new(START));
    let throttle = KitThrottle::with_max_keys(clock as Arc<dyn Clock>, 100);
    for n in 0..1_000 {
        let _ = throttle.admit(Stage::LoginStart, &[address(n)], START);
    }
    assert!(throttle.tracked_keys() <= 100);
    throttle
        .admit(Stage::LoginStart, &[address(5_000)], START)
        .expect("a caller that was never seen before");
}

#[test]
fn expired_keys_are_swept_a_few_per_call() {
    let clock = Arc::new(ManualClock::new(START));
    let throttle = KitThrottle::new(clock as Arc<dyn Clock>);
    for n in 0..100 {
        throttle
            .admit(Stage::RegisterStart, &[address(n)], START)
            .expect("within the limit");
    }
    assert_eq!(throttle.tracked_keys(), 100);

    // A minute later every key has expired. One call looks at a bounded number
    // of them, not at the whole table.
    let later = START + 61;
    let budget = KitThrottle::SWEEP_BUDGET;
    throttle
        .admit(Stage::RegisterStart, &[address(1_000)], later)
        .expect("a new key");
    assert_eq!(throttle.tracked_keys(), 100 - budget + 1);

    // The next calls go on where the last one stopped, until none is left but
    // the new ones.
    for n in 1..=4 {
        throttle
            .admit(Stage::RegisterStart, &[address(1_000 + n)], later)
            .expect("a new key");
    }
    assert_eq!(throttle.tracked_keys(), 5);
}

#[test]
fn a_key_in_use_is_kept_by_the_sweep() {
    let clock = Arc::new(ManualClock::new(START));
    let throttle = KitThrottle::new(clock as Arc<dyn Clock>);
    let busy = address(1);
    // Added at START, used again at START + 50: the sweep at START + 70 finds
    // it old in the queue but still in use.
    throttle
        .admit(Stage::RegisterStart, &[busy], START)
        .expect("first");
    for _ in 0..4 {
        throttle
            .admit(Stage::RegisterStart, &[busy], START + 50)
            .expect("within the limit");
    }
    throttle
        .admit(Stage::RegisterStart, &[address(2)], START + 70)
        .expect("a new key");
    assert_eq!(throttle.tracked_keys(), 2);
    // Its four recent attempts still count: one more fits, the next does not.
    throttle
        .admit(Stage::RegisterStart, &[busy], START + 70)
        .expect("five attempts in the window");
    throttle
        .admit(Stage::RegisterStart, &[busy], START + 70)
        .expect_err("six");
}

#[test]
fn only_the_last_forwarded_for_line_counts() {
    let peer: SocketAddr = "10.0.3.26:4000".parse().unwrap();
    let mut headers = HeaderMap::new();
    // A proxy that adds a line of its own instead of appending to the client's.
    headers.append("x-forwarded-for", HeaderValue::from_static("1.2.3.4"));
    headers.append("x-forwarded-for", HeaderValue::from_static("198.51.100.4"));
    assert_eq!(caller_from(&headers, Some(peer)).ip, ip("198.51.100.4"));
}
