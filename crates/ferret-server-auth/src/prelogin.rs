//! Answers for a name that has no account.
//!
//! A server that answers a first login message differently for a known and an
//! unknown name hands out a list of its users. Everything here lets the
//! server answer an unknown name from a secret instead of from a stored
//! account, in a way that looks the same and stays the same on every ask:
//!
//! * [`fake_credential_id`]: the credential id OPAQUE binds the answer to.
//!   `resolve_credential` (behind `test-support`: no request path uses it)
//!   picks the account's own id or this one, in one place.
//! * [`fake_prelogin`]: the key stretching profile and the second-factor hint
//!   that a pre-login answer carries. They are drawn from the shares of the
//!   real accounts ([`PreloginPolicy`]), so the made-up answers are spread as
//!   the real ones are and carry no information about whether an account
//!   exists.
//! * `fake_record_bytes` (crate-internal): a record that OPAQUE accepts in place of a stored
//!   one, the same for the same id every time.
//!
//! All three are derived from the [`PreloginSecret`]. With a different
//! secret every value changes, which is why that secret is never replaced
//! while accounts exist.
//!
//! The functions cannot fail, so no error can tell an unknown name from a
//! known one. The only error of the module is a policy that is out of range,
//! which depends on the server's own settings and not on a request.

use std::collections::HashSet;

#[cfg(feature = "test-support")]
use ferret_core::AccountId;
use ferret_core::KsfProfile;
use ferret_core::opaque::server_suite::REGISTRATION_RECORD_LEN;
use hkdf::Hkdf;
use hmac::{Hmac, KeyInit, Mac};
use sha2::{Sha256, Sha512};
use zeroize::Zeroizing;

#[cfg(feature = "test-support")]
use crate::ct::ct_select_bytes;
use crate::error::{AuthError, InternalKind};
use crate::ids::CredentialId;
use crate::keys::{PreloginSecret, ServerKeys};
use crate::login::{AccountLookup, NO_ACCOUNT, choose_answer, stored_for};
use crate::name::NormalizedLoginName;
use crate::record::StoredRecord;

/// Label in front of the name for the made-up credential id.
///
/// Spec: Fase 1 § 4.2 (`HMAC-SHA256(server_secret_prelogin, "prelogin-id" ‖ lower(email))[..16]`).
const ID_LABEL: &[u8] = b"prelogin-id";

/// Label in front of the name for the draws of profile and hint.
///
/// The same construction as the id, with its own label.
const HINT_LABEL: &[u8] = b"prelogin-hint";

/// Label of the derivation of a made-up record, followed by the credential id.
///
/// HKDF-SHA512 with the pre-login secret as the key material, no salt, and
/// this label and the id as `info`.
const RECORD_LABEL: &[u8] = b"ferret/v1/prelogin/record";

/// The shares of a policy add up to this many permille.
const WHOLE: u16 = 1000;

/// Length of a made-up record: the length of a stored one (public key 32,
/// masking key 64, envelope 96).
const FAKE_RECORD_LEN: usize = REGISTRATION_RECORD_LEN;

/// Bytes drawn for the masking key and the envelope.
const FAKE_BODY_LEN: usize = 160;

// Records which steps ran, so a test can see that a known and an unknown
// name take the same ones.
#[cfg(test)]
thread_local! {
    static STEPS: core::cell::RefCell<Vec<&'static str>> =
        const { core::cell::RefCell::new(Vec::new()) };
}

#[cfg(test)]
pub(crate) fn step(name: &'static str) {
    STEPS.with(|steps| steps.borrow_mut().push(name));
}

#[cfg(test)]
pub(crate) fn clear_steps() {
    STEPS.with(|steps| steps.borrow_mut().clear());
}

#[cfg(test)]
pub(crate) fn steps() -> Vec<&'static str> {
    STEPS.with(|steps| steps.borrow().clone())
}

#[cfg(not(test))]
#[inline(always)]
pub(crate) fn step(_name: &'static str) {}

/// `HMAC-SHA256(secret, label ‖ name)`.
fn hmac_with_name(
    secret: &PreloginSecret,
    label: &[u8],
    name: &NormalizedLoginName,
) -> Zeroizing<[u8; 32]> {
    // HMAC accepts a key of any length, so making it cannot fail.
    let mac = <Hmac<Sha256> as KeyInit>::new_from_slice(secret.as_bytes());
    debug_assert!(mac.is_ok());
    mac.map(|mut mac| {
        mac.update(label);
        mac.update(name.as_str().as_bytes());
        Zeroizing::new(mac.finalize().into_bytes().into())
    })
    .unwrap_or_default()
}

/// The credential id of a name that has no account.
///
/// `HMAC-SHA256(prelogin_secret, "prelogin-id" ‖ name)[..16]`: the same name
/// and secret always give the same id, and a different name or secret gives
/// another one.
///
/// Spec: Fase 1 § 4.2.
pub fn fake_credential_id(secret: &PreloginSecret, name: &NormalizedLoginName) -> CredentialId {
    step("fake-id");
    let mac = hmac_with_name(secret, ID_LABEL, name);
    let mut id = [0u8; 16];
    for (slot, byte) in id.iter_mut().zip(mac.iter()) {
        *slot = *byte;
    }
    CredentialId::from_bytes(id)
}

/// The credential id OPAQUE uses for a login name: the account's own id when
/// there is an account, the made-up one when there is not.
///
/// This is the one place that decides. The made-up id is derived in both
/// cases and the choice is made without a branch, so a known and an unknown
/// name run the same steps. Calling it with the account looked up for the
/// normalized name is what keeps the two forms from drifting apart.
///
/// This is a helper for tests and benchmarks, and it is behind the
/// `test-support` feature on purpose: no request path calls it. `login_start`
/// makes this choice itself, and the pre-login answer is
/// [`prelogin_answer`]. The information bench that times it
/// (`info_server_prelogin_resolve_credential`) has a small stable offset
/// that has not been isolated, so a request path must not start to use it
/// before that bench is made a gate and passes.
///
/// Spec: Fase 1 § 4.2.
#[cfg(feature = "test-support")]
pub fn resolve_credential(
    secret: &PreloginSecret,
    name: &NormalizedLoginName,
    account: Option<&AccountId>,
) -> CredentialId {
    let fake = fake_credential_id(secret, name);
    // The account is read through a reference that may be absent, and a load
    // through a pointer that may be null is a branch. So the pointer is
    // chosen first (the account's own, or a fixed all-zero id), in a function
    // of its own that `ct/run.sh lookup-asm` checks for a conditional jump,
    // and the load is the same for both.
    static NO_ACCOUNT_ID: [u8; 16] = [0; 16];
    let real = pick_account(account, &NO_ACCOUNT_ID);
    let active = u8::from(account.is_some());
    // The stand-in id is read on every path too: the account's id (or the
    // stand-in again) on one side of a select, the stand-in on the other.
    let mut own = [0u8; 16];
    ct_select_bytes(active, real, &NO_ACCOUNT_ID, &mut own);
    step("select-id");
    let mut chosen = [0u8; 16];
    ct_select_bytes(active, &own, fake.as_bytes(), &mut chosen);
    CredentialId::from_bytes(chosen)
}

/// The account id to read: the account's own, or `none`. A choice between two
/// references, with no read before it; see [`resolve_credential`].
#[cfg(feature = "test-support")]
#[inline(never)]
pub(crate) fn pick_account<'a>(account: Option<&'a AccountId>, none: &'a [u8; 16]) -> &'a [u8; 16] {
    account.map_or(none, AccountId::as_bytes)
}

/// The pre-login answer for a name: the key stretching profile and the
/// second-factor hint of the account when `lookup` is one that may log in, the
/// made-up ones of the name when it is not (no account, or a disabled one).
///
/// The made-up answer is always computed, the lookup is unpacked by the same
/// function as in `login_start` (which chooses between two references and
/// reads through the chosen one), and the choice of the two values is
/// `ct_select_u8`; no step looks at which kind of lookup it is. It is the
/// function for a pre-login endpoint, so that a known name, an unknown one and
/// a disabled one do the same work. The server has no such route yet (the
/// profile and hint go out in the answer of `login/start`, chosen by the same
/// `choose_answer`), so nothing calls it but the tests and the timing bench.
pub fn prelogin_answer(
    secret: &PreloginSecret,
    name: &NormalizedLoginName,
    policy: &PreloginPolicy,
    lookup: AccountLookup<'_>,
) -> PreloginAnswer {
    let fake = fake_prelogin(secret, name, policy);
    let placeholder: &StoredRecord = &NO_ACCOUNT;
    let stored = stored_for(lookup, placeholder);
    choose_answer(&stored, fake)
}

/// How the made-up pre-login answers are spread: the share of each key
/// stretching profile, and the share of "has a second factor", both in
/// permille.
///
/// The server sets them from its real accounts. If every real account used
/// profile 2, a made-up answer of profile 1 would show that the name has no
/// account; with the same shares, an answer says nothing. Public: it holds
/// totals over all accounts and no single account.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct PreloginPolicy {
    /// Profile numbers and their shares, in the order given.
    profiles: Vec<(u8, u16)>,
    /// The share of answers that say the account has a second factor.
    sk_true_permille: u16,
}

impl PreloginPolicy {
    /// A policy from `(profile, share)` pairs and the share of "yes" for the
    /// hint, both in permille.
    ///
    /// The shares of the profiles must add up to exactly 1000. The list must
    /// not be empty, must not name a profile twice, profile 0 does not exist,
    /// and every profile must be one that clients know (`KsfProfile` of the
    /// core). The hint share is at most 1000. Anything else is
    /// `Internal(Policy)`: it is the server's own setting, not a request.
    ///
    /// A made-up answer with a profile no client accepts would make every
    /// unknown name fail while real names work, so such a policy cannot be
    /// built: a server that builds its policy when it starts fails to start.
    pub fn new(profiles: &[(u8, u16)], sk_true_permille: u16) -> Result<Self, AuthError> {
        let policy = Self::shaped(profiles, sk_true_permille)?;
        policy.check_known_profiles()?;
        Ok(policy)
    }

    /// Like [`new`](Self::new), but profiles that no client knows yet are
    /// accepted, for tests that need a longer table than the clients have.
    #[cfg(feature = "test-support")]
    pub fn for_tests(profiles: &[(u8, u16)], sk_true_permille: u16) -> Result<Self, AuthError> {
        Self::shaped(profiles, sk_true_permille)
    }

    /// The checks of the numbers: shares, duplicates, profile 0, the hint.
    fn shaped(profiles: &[(u8, u16)], sk_true_permille: u16) -> Result<Self, AuthError> {
        let total = profiles
            .iter()
            .try_fold(0u32, |sum, (_, share)| sum.checked_add(u32::from(*share)));
        let distinct = profiles
            .iter()
            .map(|(profile, _)| *profile)
            .collect::<HashSet<u8>>()
            .len()
            == profiles.len();
        let valid = total == Some(u32::from(WHOLE))
            && distinct
            && profiles.iter().all(|(profile, _)| *profile != 0)
            && sk_true_permille <= WHOLE;
        if valid {
            Ok(Self {
                profiles: profiles.to_vec(),
                sk_true_permille,
            })
        } else {
            Err(AuthError::Internal(InternalKind::Policy))
        }
    }

    /// Every made-up answer uses `profile` and says the account has a second
    /// factor: the setting of a server whose accounts all look like that (the
    /// second factor is on by default).
    ///
    /// The profile is a [`KsfProfile`] of the core, so a number that clients do
    /// not know cannot be given.
    pub fn single(profile: KsfProfile) -> Self {
        Self {
            profiles: vec![(profile.number(), WHOLE)],
            sk_true_permille: WHOLE,
        }
    }

    /// Checks that every profile of the policy is one that clients know
    /// (`KsfProfile` of the core). [`new`](Self::new) calls it, so a policy
    /// that was built with `new` always passes.
    ///
    /// An unknown profile is `Internal(Policy)`.
    pub fn check_known_profiles(&self) -> Result<(), AuthError> {
        let known = self
            .profiles
            .iter()
            .all(|(profile, _)| KsfProfile::from_wire(u32::from(*profile)).is_ok());
        if known {
            Ok(())
        } else {
            Err(AuthError::Internal(InternalKind::Policy))
        }
    }
}

/// The pre-login data of a name: which key stretching profile to use and
/// whether the account has a second factor.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct PreloginAnswer {
    /// The key stretching profile the client must use.
    pub ksf_profile: u8,
    /// Whether the account has a second factor.
    pub sk_hint: bool,
}

/// Draws a number below 1000 from eight bytes. The remainder of a 64-bit
/// number is off by less than one in 10^16.
fn permille(word: &[u8; 8]) -> u64 {
    u64::from_be_bytes(*word)
        .checked_rem(u64::from(WHOLE))
        .unwrap_or_default()
}

/// The pre-login answer for a name that has no account.
///
/// Both values come from `HMAC-SHA256(prelogin_secret, "prelogin-hint" ‖
/// name)`: the first eight bytes pick the profile and the next eight pick the
/// hint, each as a number below 1000 set against the shares of `policy`. The
/// answer is the same on every call for the same name, secret and policy.
///
/// Spec: Fase 1 § 4.2. The spread follows the policy instead of a fixed
/// default, so a made-up answer does not stand out from the real ones. Each
/// value follows its own share; the two draws are independent, so the pair
/// does not follow the joint spread of the real accounts. The policy is a
/// setting that changes rarely: when it changes, the made-up answers change
/// with it.
pub fn fake_prelogin(
    secret: &PreloginSecret,
    name: &NormalizedLoginName,
    policy: &PreloginPolicy,
) -> PreloginAnswer {
    step("fake-prelogin");
    let digest = hmac_with_name(secret, HINT_LABEL, name);
    let (words, _) = digest.as_chunks::<8>();
    let mut draws = words.iter().map(permille);
    let profile_draw = draws.next().unwrap_or_default();
    let hint_draw = draws.next().unwrap_or_default();

    let mut upper = 0u64;
    let chosen = policy.profiles.iter().find_map(|(profile, share)| {
        upper = upper.saturating_add(u64::from(*share));
        (profile_draw < upper).then_some(*profile)
    });
    // The shares add up to 1000 and the draw is below 1000, so a profile is
    // always found; the last one stands in if that ever changes.
    let ksf_profile = chosen
        .or_else(|| policy.profiles.last().map(|(profile, _)| *profile))
        .unwrap_or_default();
    PreloginAnswer {
        ksf_profile,
        sk_hint: hint_draw < u64::from(policy.sk_true_permille),
    }
}

/// A record for a name that has no account, in the form OPAQUE stores:
/// `dummy_pk ‖ masking key (64) ‖ envelope (96)`, 192 bytes.
///
/// The public key is the server's own dummy key, as `opaque-ke` uses for its
/// made-up record. The next 160 bytes are
/// `HKDF-SHA512(prelogin_secret, "ferret/v1/prelogin/record" ‖ credential_id)`:
/// 64 for the masking key and 96 for the envelope. The same id gives the same
/// record every time (`opaque-ke` draws a new masking key on each call), and
/// another id or secret gives another one.
///
/// Spec: Fase 1 § 4.2 (the answer for an unknown name). The record is handed to
/// the OPAQUE login as if it were the stored one, because `opaque-ke` draws a
/// new masking key for its own made-up record on every call.
pub(crate) fn fake_record_bytes(
    keys: &ServerKeys,
    secret: &PreloginSecret,
    id: &CredentialId,
) -> Zeroizing<[u8; FAKE_RECORD_LEN]> {
    step("fake-record");
    let mut body = Zeroizing::new([0u8; FAKE_BODY_LEN]);
    // Expanding 160 bytes from SHA-512 is far below the limit of 255 blocks,
    // so this cannot fail.
    let expanded = Hkdf::<Sha512>::new(None, secret.as_bytes())
        .expand_multi_info(&[RECORD_LABEL, id.as_bytes()], body.as_mut_slice());
    debug_assert!(expanded.is_ok());
    let dummy = keys.dummy_public_key();
    let mut record = Zeroizing::new([0u8; FAKE_RECORD_LEN]);
    for (slot, byte) in record.iter_mut().zip(dummy.iter().chain(body.iter())) {
        *slot = *byte;
    }
    record
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::name::normalize_login_name;
    use crate::throttle::{Caller, RecordingThrottle, Stage, ThrottleCall, admit};
    use ferret_core::TestRng;
    use ferret_core::opaque::server_suite::FerretSuite;
    use ferret_core::opaque::server_suite::opaque_ke::ServerRegistration;
    use sha2::Digest;

    fn secret(byte: u8) -> PreloginSecret {
        PreloginSecret::from_payload(&[byte; 32]).unwrap()
    }

    fn keys() -> ServerKeys {
        ServerKeys::generate(&mut TestRng::new(b"prelogin keys")).unwrap()
    }

    fn name(raw: &str) -> NormalizedLoginName {
        normalize_login_name(raw).unwrap()
    }

    fn id(n: u8) -> CredentialId {
        CredentialId::from_bytes([n; 16])
    }

    /// HMAC-SHA256 from its definition (RFC 2104), with no use of `hmac`.
    fn hmac_sha256(key: &[u8], message: &[u8]) -> [u8; 32] {
        let mut block = [0u8; 64];
        block[..key.len()].copy_from_slice(key);
        let mut inner = Sha256::new();
        inner.update(block.map(|b| b ^ 0x36));
        inner.update(message);
        let mut outer = Sha256::new();
        outer.update(block.map(|b| b ^ 0x5c));
        outer.update(inner.finalize());
        outer.finalize().into()
    }

    /// HMAC-SHA512 from its definition.
    fn hmac_sha512(key: &[u8], message: &[u8]) -> [u8; 64] {
        let mut block = [0u8; 128];
        block[..key.len()].copy_from_slice(key);
        let mut inner = Sha512::new();
        inner.update(block.map(|b| b ^ 0x36));
        inner.update(message);
        let mut outer = Sha512::new();
        outer.update(block.map(|b| b ^ 0x5c));
        outer.update(inner.finalize());
        outer.finalize().into()
    }

    /// HKDF-SHA512 with no salt, from RFC 5869, with no use of `hkdf`.
    fn hkdf_sha512(ikm: &[u8], info: &[u8], len: usize) -> Vec<u8> {
        let prk = hmac_sha512(&[0u8; 64], ikm);
        let mut out = Vec::new();
        let mut previous: Vec<u8> = Vec::new();
        let mut counter = 1u8;
        while out.len() < len {
            let mut message = previous.clone();
            message.extend_from_slice(info);
            message.push(counter);
            previous = hmac_sha512(&prk, &message).to_vec();
            out.extend_from_slice(&previous);
            counter += 1;
        }
        out.truncate(len);
        out
    }

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    fn synthetic_secret() -> PreloginSecret {
        secret(0x42)
    }

    // ---------------------------------------------------------- credential id

    #[test]
    fn fake_credential_id_matches_spec_formula() {
        let secret = synthetic_secret();
        for raw in ["alice@example.com", "bob@x.no", "ÅSE@X.NO"] {
            let n = name(raw);
            let mut message = b"prelogin-id".to_vec();
            message.extend_from_slice(n.as_str().as_bytes());
            let expected = hmac_sha256(&[0x42; 32], &message);
            assert_eq!(fake_credential_id(&secret, &n).as_bytes(), &expected[..16]);
        }
    }

    #[test]
    fn fake_credential_id_byte_vector() {
        // Computed outside this crate with Python's hmac module.
        let id = fake_credential_id(&synthetic_secret(), &name("alice@example.com"));
        assert_eq!(hex(id.as_bytes()), "e71e618c7a6cb38d7d00f183c5ee28b9");
    }

    #[test]
    fn fake_id_is_stable_and_distinct() {
        let (a, b) = (secret(1), secret(2));
        let (alice, bob) = (name("alice@example.com"), name("bob@example.com"));
        assert_eq!(
            fake_credential_id(&a, &alice),
            fake_credential_id(&a, &alice)
        );
        assert_ne!(fake_credential_id(&a, &alice), fake_credential_id(&a, &bob));
        assert_ne!(
            fake_credential_id(&a, &alice),
            fake_credential_id(&b, &alice)
        );
    }

    #[test]
    fn two_spellings_of_one_name_give_one_fake_id() {
        let secret = synthetic_secret();
        let plain = name("ab@ex.com");
        let spelled = name("  ＡＢ@Ex.COM ");
        assert_eq!(
            fake_credential_id(&secret, &plain),
            fake_credential_id(&secret, &spelled)
        );
        let account = AccountId::from_bytes([9; 16]);
        assert_eq!(
            resolve_credential(&secret, &plain, Some(&account)),
            resolve_credential(&secret, &spelled, Some(&account))
        );
    }

    #[test]
    fn resolve_returns_the_account_id_or_the_fake_one() {
        let secret = synthetic_secret();
        let n = name("alice@example.com");
        let account = AccountId::from_bytes([0xa5; 16]);
        assert_eq!(
            resolve_credential(&secret, &n, Some(&account)),
            CredentialId::from(&account)
        );
        assert_eq!(
            resolve_credential(&secret, &n, None),
            fake_credential_id(&secret, &n)
        );
        // An account whose id happens to be all zeros is still its own id.
        let zero = AccountId::from_bytes([0; 16]);
        assert_eq!(
            resolve_credential(&secret, &n, Some(&zero)),
            CredentialId::from(&zero)
        );
    }

    // ------------------------------------------------------------- same work

    #[test]
    fn known_and_unknown_names_run_the_same_steps() {
        let secret = synthetic_secret();
        let n = name("alice@example.com");
        let account = AccountId::from_bytes([3; 16]);
        let trace = |account: Option<&AccountId>| {
            STEPS.with(|s| s.borrow_mut().clear());
            let _ = resolve_credential(&secret, &n, account);
            STEPS.with(|s| s.borrow().clone())
        };
        let known = trace(Some(&account));
        let unknown = trace(None);
        assert_eq!(known, vec!["fake-id", "select-id"]);
        assert_eq!(known, unknown);
    }

    #[test]
    fn the_throttle_sees_the_same_calls_for_known_and_unknown_names() {
        let secret = synthetic_secret();
        let n = name("alice@example.com");
        let account = AccountId::from_bytes([3; 16]);
        let caller = Caller {
            ip: Some("192.0.2.7".parse().unwrap()),
        };
        // The calls, with the credential id of each key blanked out: those
        // differ by design, the number, order and kind of calls must not.
        let shape = |account: Option<&AccountId>| {
            let throttle = RecordingThrottle::new();
            let credential = resolve_credential(&secret, &n, account);
            let ticket = admit(
                &throttle,
                Stage::LoginStart,
                &caller,
                Some(&credential),
                100,
            )
            .unwrap();
            ticket.finish(crate::throttle::Outcome::Failure, 100);
            throttle
                .calls()
                .iter()
                .map(|call| match call {
                    ThrottleCall::Admit { stage, keys, now } => {
                        format!("admit {stage:?} {keys:?} {now}")
                    }
                    ThrottleCall::Record {
                        stage,
                        keys,
                        outcome,
                        now,
                    } => format!("record {stage:?} {keys:?} {outcome:?} {now}"),
                })
                .collect::<Vec<_>>()
        };
        let known = shape(Some(&account));
        let unknown = shape(None);
        assert_eq!(known.len(), 2);
        assert_eq!(known, unknown);
    }

    // ------------------------------------------------------------------ policy

    #[test]
    fn policy_must_sum_to_1000() {
        assert!(PreloginPolicy::for_tests(&[(1, 1000)], 500).is_ok());
        assert!(PreloginPolicy::for_tests(&[(1, 600), (2, 400)], 0).is_ok());
        let bad = AuthError::Internal(InternalKind::Policy);
        for shares in [
            vec![(1, 999)],
            vec![(1, 1001)],
            vec![(1, 500), (2, 400)],
            vec![(1, 600), (2, 600)],
            vec![(1, 0)],
            vec![],
            vec![(1, u16::MAX), (2, u16::MAX), (3, u16::MAX)],
        ] {
            assert_eq!(
                PreloginPolicy::for_tests(&shares, 500).unwrap_err(),
                bad,
                "{shares:?}"
            );
        }
        // The hint share is a share of 1000, too.
        assert!(PreloginPolicy::for_tests(&[(1, 1000)], 1000).is_ok());
        assert_eq!(
            PreloginPolicy::for_tests(&[(1, 1000)], 1001).unwrap_err(),
            bad
        );
    }

    #[test]
    fn policy_rejects_unknown_profile_zero() {
        let bad = AuthError::Internal(InternalKind::Policy);
        assert_eq!(
            PreloginPolicy::for_tests(&[(0, 1000)], 500).unwrap_err(),
            bad
        );
        assert_eq!(
            PreloginPolicy::for_tests(&[(1, 500), (0, 500)], 500).unwrap_err(),
            bad
        );
        // A profile named twice is a mistake, too.
        assert_eq!(
            PreloginPolicy::for_tests(&[(1, 500), (1, 500)], 500).unwrap_err(),
            bad
        );
    }

    #[test]
    fn a_policy_error_does_not_depend_on_any_request() {
        // The error is the same value whatever is wrong, and it is internal.
        let bad = AuthError::Internal(InternalKind::Policy);
        assert_eq!(bad.public_code(), "internal");
        assert_eq!(bad.http_class(), crate::ErrorClass::Internal);
    }

    #[test]
    fn a_policy_is_checked_against_the_profiles_clients_know() {
        let known = PreloginPolicy::new(&[(1, 1000)], 500).unwrap();
        assert_eq!(known.check_known_profiles(), Ok(()));
        assert_eq!(
            PreloginPolicy::single(KsfProfile::P1).check_known_profiles(),
            Ok(())
        );
        // Well formed, but no client has a profile 2 (or 200) yet.
        let bad = AuthError::Internal(InternalKind::Policy);
        for profiles in [
            vec![(2, 1000)],
            vec![(1, 500), (2, 500)],
            vec![(200, 1000)],
            vec![(255, 1000)],
        ] {
            let policy = PreloginPolicy::for_tests(&profiles, 500).unwrap();
            assert_eq!(policy.check_known_profiles(), Err(bad), "{profiles:?}");
            // The constructor for servers refuses the same tables.
            assert_eq!(PreloginPolicy::new(&profiles, 500).unwrap_err(), bad);
        }
    }

    #[test]
    fn single_is_one_profile_and_always_yes() {
        let policy = PreloginPolicy::single(KsfProfile::P1);
        assert_eq!(
            policy,
            PreloginPolicy::for_tests(&[(1, 1000)], 1000).unwrap()
        );
        let secret = synthetic_secret();
        for i in 0..200 {
            let answer = fake_prelogin(&secret, &name(&format!("user{i}@example.com")), &policy);
            assert_eq!(
                answer,
                PreloginAnswer {
                    ksf_profile: 1,
                    sk_hint: true
                }
            );
        }
    }

    // ----------------------------------------------------------- pre-login

    #[test]
    fn fake_prelogin_byte_vector() {
        // For the synthetic secret and "alice@example.com" the hint digest
        // is the value below (computed with Python's hmac module). Its first
        // eight bytes give the draw 630 and the next eight the draw 344.
        let secret = synthetic_secret();
        let n = name("alice@example.com");
        let digest = hmac_sha256(
            &[0x42; 32],
            &[b"prelogin-hint".as_slice(), n.as_str().as_bytes()].concat(),
        );
        assert_eq!(
            hex(&digest),
            "6d1367790777526eeb1746a9640c9bf019d22553805fb8bebf5d9659b12c13d2"
        );
        // Draw 630 of 1000 falls in the second profile of 400/400/200
        // (400 <= 630 < 800); draw 344 is below 500, so the hint is yes.
        let policy = PreloginPolicy::for_tests(&[(1, 400), (2, 400), (3, 200)], 500).unwrap();
        assert_eq!(
            fake_prelogin(&secret, &n, &policy),
            PreloginAnswer {
                ksf_profile: 2,
                sk_hint: true
            }
        );
        // With a hint share of 344 the draw 344 is not below it.
        let policy = PreloginPolicy::for_tests(&[(1, 400), (2, 400), (3, 200)], 344).unwrap();
        assert!(!fake_prelogin(&secret, &n, &policy).sk_hint);
        let policy = PreloginPolicy::for_tests(&[(1, 400), (2, 400), (3, 200)], 345).unwrap();
        assert!(fake_prelogin(&secret, &n, &policy).sk_hint);
        // Draw 630 is the border of 630/370.
        let policy = PreloginPolicy::for_tests(&[(1, 630), (2, 370)], 0).unwrap();
        assert_eq!(fake_prelogin(&secret, &n, &policy).ksf_profile, 2);
        let policy = PreloginPolicy::for_tests(&[(1, 631), (2, 369)], 0).unwrap();
        assert_eq!(fake_prelogin(&secret, &n, &policy).ksf_profile, 1);
    }

    #[test]
    fn fake_prelogin_is_stable_across_calls() {
        let secret = synthetic_secret();
        let n = name("alice@example.com");
        let policy = PreloginPolicy::for_tests(&[(1, 500), (2, 500)], 500).unwrap();
        let first = fake_prelogin(&secret, &n, &policy);
        for _ in 0..1000 {
            assert_eq!(fake_prelogin(&secret, &n, &policy), first);
        }
    }

    /// The share of names, out of 20 000, for which `pick` holds.
    fn share(
        secret: &PreloginSecret,
        policy: &PreloginPolicy,
        pick: impl Fn(PreloginAnswer) -> bool,
    ) -> f64 {
        const COUNT: u32 = 20_000;
        let hits = (0..COUNT)
            .filter(|i| {
                let n = name(&format!("user{i}@example.com"));
                pick(fake_prelogin(secret, &n, policy))
            })
            .count();
        hits as f64 / f64::from(COUNT)
    }

    #[test]
    fn fake_prelogin_follows_policy() {
        let secret = synthetic_secret();
        let cases: [(&[(u8, u16)], u16); 4] = [
            (&[(1, 700), (2, 300)], 800),
            (&[(1, 500), (2, 300), (3, 200)], 500),
            (&[(1, 1000)], 0),
            (&[(1, 100), (2, 900)], 1000),
        ];
        for (profiles, sk) in cases {
            let policy = PreloginPolicy::for_tests(profiles, sk).unwrap();
            let yes = share(&secret, &policy, |a| a.sk_hint);
            let wanted = f64::from(sk) / 1000.0;
            assert!((yes - wanted).abs() <= 0.02, "hint {yes} against {wanted}");
            for (profile, permille) in profiles {
                let got = share(&secret, &policy, |a| a.ksf_profile == *profile);
                let wanted = f64::from(*permille) / 1000.0;
                assert!(
                    (got - wanted).abs() <= 0.02,
                    "profile {profile}: {got} against {wanted}"
                );
            }
        }
    }

    #[test]
    fn policy_with_two_profiles_serves_both() {
        let secret = synthetic_secret();
        // Even a small share is drawn now and then.
        let policy = PreloginPolicy::for_tests(&[(1, 990), (2, 10)], 500).unwrap();
        let mut seen = HashSet::new();
        for i in 0..5000 {
            let n = name(&format!("someone{i}@example.com"));
            seen.insert(fake_prelogin(&secret, &n, &policy).ksf_profile);
        }
        assert_eq!(seen, HashSet::from([1, 2]));
    }

    #[test]
    fn the_hint_and_the_profile_are_drawn_independently() {
        // Each of the four combinations turns up under a half-and-half policy.
        let secret = synthetic_secret();
        let policy = PreloginPolicy::for_tests(&[(1, 500), (2, 500)], 500).unwrap();
        let mut seen = HashSet::new();
        for i in 0..2000 {
            let n = name(&format!("pair{i}@example.com"));
            let a = fake_prelogin(&secret, &n, &policy);
            seen.insert((a.ksf_profile, a.sk_hint));
        }
        assert_eq!(seen.len(), 4);
    }

    // ------------------------------------------------------------ fake record

    #[test]
    fn the_prelogin_answer_is_the_accounts_own_or_the_made_up_one() {
        use crate::login::AccountLookup;
        use crate::testing::LoginFixture;
        let f = LoginFixture::new();
        let made_up = fake_prelogin(&f.prelogin, &f.name, &f.policy);
        let own = prelogin_answer(&f.prelogin, &f.name, &f.policy, f.active());
        // The fixture's account has profile 1 and no second factor; the policy
        // says "profile 1, second factor" for a name without an account.
        assert_eq!(
            own,
            PreloginAnswer {
                ksf_profile: f.record.ksf_profile,
                sk_hint: false
            }
        );
        assert!(made_up.sk_hint);
        for lookup in [AccountLookup::Unknown, AccountLookup::Disabled] {
            assert_eq!(
                prelogin_answer(&f.prelogin, &f.name, &f.policy, lookup),
                made_up
            );
        }
    }

    #[test]
    fn pick_account_chooses_between_two_references() {
        let (own, none) = ([7u8; 16], [0u8; 16]);
        let account = AccountId::from_bytes(own);
        assert_eq!(pick_account(Some(&account), &none), &own);
        assert_eq!(pick_account(None, &none), &none);
    }

    #[test]
    fn fake_record_is_a_valid_opaque_record() {
        let (keys, secret) = (keys(), synthetic_secret());
        let record = fake_record_bytes(&keys, &secret, &id(1));
        assert_eq!(record.len(), 192);
        assert_eq!(record[..32], keys.dummy_public_key());
        assert!(ServerRegistration::<FerretSuite>::deserialize(record.as_slice()).is_ok());
    }

    #[test]
    fn fake_record_matches_the_derivation() {
        let (keys, secret) = (keys(), synthetic_secret());
        let credential = fake_credential_id(&secret, &name("alice@example.com"));
        let record = fake_record_bytes(&keys, &secret, &credential);
        let mut info = b"ferret/v1/prelogin/record".to_vec();
        info.extend_from_slice(credential.as_bytes());
        let body = hkdf_sha512(&[0x42; 32], &info, 160);
        assert_eq!(record[32..], body[..]);
        // The masking key is the first 64 bytes of that, the envelope the rest.
        assert_eq!(record[32..96], body[..64]);
        assert_eq!(record[96..], body[64..]);
        // Computed outside this crate with Python's hmac module.
        assert_eq!(
            hex(&record[32..96]),
            "0f7a5eee6ce12c3d0dc4450d6ff7ba94a5e0f39acb0f71ed065bbff1844fc522\
             492279d547022cf30504747b30a7bc6a4145e1b08bb59034be6b1ce76ed19d11"
        );
        assert_eq!(
            hex(&record[96..]),
            "0c91eeaa20bab30595510d32d2faa084cf041ee96660aabfcadebf3b407af335\
             c7aa7acabfe7c1403bbaf30bc65069bf535ad5e35e4445f9f1fcb7a91a23f5e4\
             8b27a95a99616fc2bbcaf2c2bf038d5980b1cc975a5bf50b02b81b50ae3a61c9"
        );
    }

    #[test]
    fn fake_record_is_deterministic_per_id() {
        let (keys, secret) = (keys(), synthetic_secret());
        let first = fake_record_bytes(&keys, &secret, &id(7));
        for _ in 0..50 {
            assert_eq!(*fake_record_bytes(&keys, &secret, &id(7)), *first);
        }
    }

    #[test]
    fn fake_masking_keys_differ_per_id() {
        let (keys, secret) = (keys(), synthetic_secret());
        let mut masking = HashSet::new();
        let mut envelopes = HashSet::new();
        for n in 0..100u8 {
            let record = fake_record_bytes(&keys, &secret, &id(n));
            masking.insert(record[32..96].to_vec());
            envelopes.insert(record[96..].to_vec());
            // The public key is the one dummy key of the server for all.
            assert_eq!(record[..32], keys.dummy_public_key());
        }
        assert_eq!(masking.len(), 100);
        assert_eq!(envelopes.len(), 100);
    }

    #[test]
    fn fake_material_depends_on_secret() {
        let (keys, a, b) = (keys(), secret(1), secret(2));
        let n = name("alice@example.com");
        assert_ne!(fake_credential_id(&a, &n), fake_credential_id(&b, &n));
        let same_id = id(5);
        let (ra, rb) = (
            fake_record_bytes(&keys, &a, &same_id),
            fake_record_bytes(&keys, &b, &same_id),
        );
        assert_eq!(ra[..32], rb[..32], "the public key is the server's");
        assert_ne!(ra[32..96], rb[32..96]);
        assert_ne!(ra[96..], rb[96..]);
        // The answers differ for some names (a single name can match by chance).
        let policy = PreloginPolicy::for_tests(&[(1, 500), (2, 500)], 500).unwrap();
        let differing = (0..200)
            .filter(|i| {
                let n = name(&format!("user{i}@example.com"));
                fake_prelogin(&a, &n, &policy) != fake_prelogin(&b, &n, &policy)
            })
            .count();
        assert!(differing > 50, "{differing}");
    }

    #[test]
    fn fake_record_depends_on_the_server_key() {
        let secret = synthetic_secret();
        let other = ServerKeys::generate(&mut TestRng::new(b"another server")).unwrap();
        let (a, b) = (
            fake_record_bytes(&keys(), &secret, &id(1)),
            fake_record_bytes(&other, &secret, &id(1)),
        );
        assert_ne!(a[..32], b[..32]);
        assert_eq!(a[32..], b[32..]);
    }
}
