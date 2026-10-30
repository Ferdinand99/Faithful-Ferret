//! The decision for every scope and capability pair, written out in full.
//!
//! The table below lists each pair once. A test checks that the table covers
//! `Capability::ALL` for every scope with no gap and no repeat, so a new
//! capability fails here until each scope has a decision for it.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::arithmetic_side_effects
)]

use ferret_server_auth::{
    AuthError, Capability, DenyReason, ErrorClass, ScopeEffect, SessionScope, authorize,
};
use proptest::prelude::*;

use Capability::*;
use SessionScope::{AccountReset, Full, Pending2fa, Unverified};

const SCOPES: [SessionScope; 4] = [Full, Pending2fa, AccountReset, Unverified];

/// `(scope, capability, allowed)` for all 64 pairs.
const MATRIX: &[(SessionScope, Capability, bool)] = &[
    // Full: everything except the second factor.
    (Full, Challenge, true),
    (Full, Logout, true),
    (Full, SecondFactor, false),
    (Full, OpaqueRegisterStart, true),
    (Full, ReauthLogin, true),
    (Full, RecoveryWrapRead, true),
    (Full, Recover, true),
    (Full, UnlockMethodsRead, true),
    (Full, UnlockMethodsWrite, true),
    (Full, PasswordPut, true),
    (Full, Rekey, true),
    (Full, VaultRead, true),
    (Full, SyncRead, true),
    (Full, SyncWrite, true),
    (Full, DeviceManage, true),
    (Full, AccountSettings, true),
    // Pending2fa: the second factor and logout.
    (Pending2fa, Challenge, false),
    (Pending2fa, Logout, true),
    (Pending2fa, SecondFactor, true),
    (Pending2fa, OpaqueRegisterStart, false),
    (Pending2fa, ReauthLogin, false),
    (Pending2fa, RecoveryWrapRead, false),
    (Pending2fa, Recover, false),
    (Pending2fa, UnlockMethodsRead, false),
    (Pending2fa, UnlockMethodsWrite, false),
    (Pending2fa, PasswordPut, false),
    (Pending2fa, Rekey, false),
    (Pending2fa, VaultRead, false),
    (Pending2fa, SyncRead, false),
    (Pending2fa, SyncWrite, false),
    (Pending2fa, DeviceManage, false),
    (Pending2fa, AccountSettings, false),
    // AccountReset: the recovery and what it needs, and logout.
    (AccountReset, Challenge, true),
    (AccountReset, Logout, true),
    (AccountReset, SecondFactor, false),
    (AccountReset, OpaqueRegisterStart, true),
    (AccountReset, ReauthLogin, false),
    (AccountReset, RecoveryWrapRead, true),
    (AccountReset, Recover, true),
    (AccountReset, UnlockMethodsRead, false),
    (AccountReset, UnlockMethodsWrite, false),
    (AccountReset, PasswordPut, false),
    (AccountReset, Rekey, false),
    (AccountReset, VaultRead, false),
    (AccountReset, SyncRead, false),
    (AccountReset, SyncWrite, false),
    (AccountReset, DeviceManage, false),
    (AccountReset, AccountSettings, false),
    // Unverified: logout only.
    (Unverified, Challenge, false),
    (Unverified, Logout, true),
    (Unverified, SecondFactor, false),
    (Unverified, OpaqueRegisterStart, false),
    (Unverified, ReauthLogin, false),
    (Unverified, RecoveryWrapRead, false),
    (Unverified, Recover, false),
    (Unverified, UnlockMethodsRead, false),
    (Unverified, UnlockMethodsWrite, false),
    (Unverified, PasswordPut, false),
    (Unverified, Rekey, false),
    (Unverified, VaultRead, false),
    (Unverified, SyncRead, false),
    (Unverified, SyncWrite, false),
    (Unverified, DeviceManage, false),
    (Unverified, AccountSettings, false),
];

fn allowed_by(scope: SessionScope) -> Vec<Capability> {
    Capability::ALL
        .iter()
        .copied()
        .filter(|cap| scope.allows(*cap))
        .collect()
}

fn same_set(mut a: Vec<Capability>, expected: &[Capability]) -> bool {
    let mut b = expected.to_vec();
    let key = |c: &Capability| Capability::ALL.iter().position(|x| x == c).unwrap();
    a.sort_by_key(key);
    b.sort_by_key(key);
    a == b
}

#[test]
fn the_matrix_decides_every_pair_exactly_once() {
    assert_eq!(MATRIX.len(), SCOPES.len() * Capability::ALL.len());
    for scope in SCOPES {
        for cap in Capability::ALL {
            let rows = MATRIX
                .iter()
                .filter(|(s, c, _)| *s == scope && c == cap)
                .count();
            assert_eq!(rows, 1, "{scope:?} x {cap:?} has {rows} rows in the matrix");
        }
    }
}

#[test]
fn allows_and_authorize_follow_the_matrix() {
    for (scope, cap, allowed) in MATRIX {
        assert_eq!(scope.allows(*cap), *allowed, "{scope:?} x {cap:?}");
        let result = authorize(*scope, *cap);
        if *allowed {
            assert_eq!(result, Ok(()), "{scope:?} x {cap:?}");
        } else {
            assert_eq!(
                result,
                Err(AuthError::Denied(DenyReason::ScopeForbids)),
                "{scope:?} x {cap:?}"
            );
        }
    }
}

#[test]
fn a_refusal_is_a_403_with_the_code_forbidden() {
    let error = authorize(Unverified, VaultRead).unwrap_err();
    assert_eq!(error.http_class(), ErrorClass::Forbidden);
    assert_eq!(error.public_code(), "forbidden");
}

#[test]
fn account_reset_allows_exactly_five_capabilities() {
    assert!(same_set(
        allowed_by(AccountReset),
        &[
            Challenge,
            OpaqueRegisterStart,
            RecoveryWrapRead,
            Recover,
            Logout
        ]
    ));
    assert_eq!(allowed_by(AccountReset).len(), 5);
}

#[test]
fn pending_2fa_allows_exactly_two() {
    assert!(same_set(allowed_by(Pending2fa), &[SecondFactor, Logout]));
}

#[test]
fn unverified_allows_only_logout() {
    assert_eq!(allowed_by(Unverified), vec![Logout]);
}

#[test]
fn full_allows_everything_but_second_factor() {
    let expected: Vec<Capability> = Capability::ALL
        .iter()
        .copied()
        .filter(|c| *c != SecondFactor)
        .collect();
    assert!(same_set(allowed_by(Full), &expected));
    assert!(!Full.allows(SecondFactor));
}

#[test]
fn account_reset_never_reaches_items_wraps_sync_devices_or_password_put() {
    for cap in [
        VaultRead,
        SyncRead,
        SyncWrite,
        DeviceManage,
        AccountSettings,
        UnlockMethodsRead,
        UnlockMethodsWrite,
        PasswordPut,
        Rekey,
        ReauthLogin,
        SecondFactor,
    ] {
        assert!(!AccountReset.allows(cap), "{cap:?}");
        assert_eq!(
            authorize(AccountReset, cap),
            Err(AuthError::Denied(DenyReason::ScopeForbids)),
            "{cap:?}"
        );
    }
}

#[test]
fn recover_ends_an_account_reset_session() {
    assert_eq!(AccountReset.effect_of(Recover), ScopeEffect::EndSession);
}

#[test]
fn recover_keeps_a_full_session() {
    assert_eq!(Full.effect_of(Recover), ScopeEffect::Keep);
}

#[test]
fn only_the_recovery_of_a_reset_account_ends_a_session() {
    for scope in SCOPES {
        for cap in Capability::ALL {
            let expected = if scope == AccountReset && *cap == Recover {
                ScopeEffect::EndSession
            } else {
                ScopeEffect::Keep
            };
            assert_eq!(scope.effect_of(*cap), expected, "{scope:?} x {cap:?}");
        }
    }
}

#[test]
fn reauth_login_requires_full() {
    for scope in SCOPES {
        assert_eq!(scope.allows(ReauthLogin), scope == Full, "{scope:?}");
    }
}

#[test]
fn as_str_and_parse_stored_roundtrip() {
    for scope in SCOPES {
        assert_eq!(SessionScope::parse_stored(Some(scope.as_str())), scope);
    }
    assert_eq!(Full.as_str(), "full");
    assert_eq!(Pending2fa.as_str(), "pending_2fa");
    assert_eq!(AccountReset.as_str(), "account_reset");
    assert_eq!(Unverified.as_str(), "unverified");
}

#[test]
fn parse_stored_fails_closed() {
    assert_eq!(SessionScope::parse_stored(None), Unverified);
    for text in [
        "",
        "FULL",
        "Full",
        "full ",
        " full",
        "full\n",
        "full\0",
        "admin",
        "PENDING_2FA",
        "pending2fa",
        "account_reset ",
        "Account_Reset",
        "fu11",
        "ﬂull",
    ] {
        assert_eq!(
            SessionScope::parse_stored(Some(text)),
            Unverified,
            "{text:?}"
        );
    }
    assert_eq!(SessionScope::parse_stored(Some("full")), Full);
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(10_000))]

    /// Anything that is not exactly one of the four names is `Unverified`.
    #[test]
    fn random_strings_parse_to_unverified(text in ".*") {
        let known = SCOPES.iter().any(|s| s.as_str() == text);
        prop_assume!(!known);
        prop_assert_eq!(SessionScope::parse_stored(Some(&text)), Unverified);
    }

    /// Only the exact name gives `Full`.
    #[test]
    fn only_the_exact_name_gives_full(text in "[a-zA-Z_ ]{0,8}") {
        let parsed = SessionScope::parse_stored(Some(&text));
        prop_assert_eq!(parsed == Full, text == "full");
    }
}
