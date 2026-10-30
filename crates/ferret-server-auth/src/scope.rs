//! What a session may do: its scope and the capabilities each scope allows.
//!
//! The library defines the scopes and the rules. Where the scope of a session
//! is stored is the business of the server that embeds it; a session that has
//! no stored scope is [`SessionScope::Unverified`], which may do nothing but
//! end itself. That is the fail-closed default: a missing or unreadable row
//! never widens what a session may do.
//!
//! | scope | allowed |
//! |---|---|
//! | [`Full`](SessionScope::Full) | everything except [`Capability::SecondFactor`] |
//! | [`Pending2fa`](SessionScope::Pending2fa) | `SecondFactor`, `Logout` |
//! | [`AccountReset`](SessionScope::AccountReset) | `Challenge`, `OpaqueRegisterStart`, `RecoveryWrapRead`, `Recover`, `Logout` |
//! | [`Unverified`](SessionScope::Unverified) | `Logout` |
//!
//! A session that has only passed the first factor holds no vault data, no
//! unlock methods and no sync until the second factor is done. A session
//! that was opened by a sign-in code after a reset reaches nothing but the
//! recovery itself, which needs a nonce for its proof (`Challenge`) and runs
//! a new OPAQUE registration (`OpaqueRegisterStart`); it never reaches items,
//! sync, devices, wraps other than the recovery wrap, or a password change.
//!
//! The decision for every scope and capability pair is written out in
//! `decide` without a wildcard arm, so adding a capability does not compile
//! until each scope has an answer for it.
//!
//! Spec: Fase 1 § 4.6 (partial session), § 6.3 (reset account).

use crate::error::{AuthError, DenyReason};

/// What a session is allowed to do.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum SessionScope {
    /// A complete sign-in: the second factor is done, or none is required.
    Full,
    /// The first factor is done; the second is still to come.
    Pending2fa,
    /// Opened by a sign-in code after a reset. May run the recovery and
    /// nothing else.
    AccountReset,
    /// No scope is known for the session. The default.
    Unverified,
}

/// One thing a session may be asked to do.
///
/// A route names the capability it needs and asks [`authorize`] before it
/// does anything else.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[non_exhaustive]
pub enum Capability {
    /// Get a nonce for a signed request.
    Challenge,
    /// End the session.
    Logout,
    /// Answer the second factor.
    SecondFactor,
    /// Start an OPAQUE registration.
    OpaqueRegisterStart,
    /// Start or finish a re-authentication login.
    ReauthLogin,
    /// Read the recovery wrap.
    RecoveryWrapRead,
    /// Replace the account with a recovered one.
    Recover,
    /// Read the unlock methods.
    UnlockMethodsRead,
    /// Add, change or remove an unlock method.
    UnlockMethodsWrite,
    /// Change the master password.
    PasswordPut,
    /// Re-key the vault.
    Rekey,
    /// Read vault items and wraps.
    VaultRead,
    /// Read sync data.
    SyncRead,
    /// Write sync data.
    SyncWrite,
    /// Add, list or remove devices.
    DeviceManage,
    /// Read or change account settings.
    AccountSettings,
}

impl Capability {
    /// Every capability, for tests and for code that must handle all of them.
    pub const ALL: &'static [Capability] = &[
        Capability::Challenge,
        Capability::Logout,
        Capability::SecondFactor,
        Capability::OpaqueRegisterStart,
        Capability::ReauthLogin,
        Capability::RecoveryWrapRead,
        Capability::Recover,
        Capability::UnlockMethodsRead,
        Capability::UnlockMethodsWrite,
        Capability::PasswordPut,
        Capability::Rekey,
        Capability::VaultRead,
        Capability::SyncRead,
        Capability::SyncWrite,
        Capability::DeviceManage,
        Capability::AccountSettings,
    ];
}

/// What happens to the session when a capability is used.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ScopeEffect {
    /// The session goes on.
    Keep,
    /// The session ends when the call succeeds.
    EndSession,
}

impl SessionScope {
    /// Whether a session of this scope may use the capability.
    pub const fn allows(self, cap: Capability) -> bool {
        decide(self, cap)
    }

    /// What using the capability does to the session. Only the recovery of a
    /// reset account ends its session: the user signs in again with the new
    /// master password. A capability the scope does not allow has no effect.
    pub const fn effect_of(self, cap: Capability) -> ScopeEffect {
        match (self, cap) {
            (SessionScope::AccountReset, Capability::Recover) => ScopeEffect::EndSession,
            _ => ScopeEffect::Keep,
        }
    }

    /// The name stored for the scope.
    pub const fn as_str(self) -> &'static str {
        match self {
            SessionScope::Full => "full",
            SessionScope::Pending2fa => "pending_2fa",
            SessionScope::AccountReset => "account_reset",
            SessionScope::Unverified => "unverified",
        }
    }

    /// The scope for a stored name. Anything that is not exactly one of the
    /// names of [`as_str`](Self::as_str), a missing value included, is
    /// [`SessionScope::Unverified`]: no case folding, no trimming.
    pub fn parse_stored(stored: Option<&str>) -> SessionScope {
        match stored {
            Some("full") => SessionScope::Full,
            Some("pending_2fa") => SessionScope::Pending2fa,
            Some("account_reset") => SessionScope::AccountReset,
            _ => SessionScope::Unverified,
        }
    }
}

/// Checks that a session of this scope may use the capability.
///
/// # Errors
///
/// [`AuthError::Denied`] with [`DenyReason::ScopeForbids`], which an endpoint
/// answers as 403 with the code `forbidden`.
pub fn authorize(scope: SessionScope, cap: Capability) -> Result<(), AuthError> {
    if scope.allows(cap) {
        Ok(())
    } else {
        Err(AuthError::Denied(DenyReason::ScopeForbids))
    }
}

/// The rule for every scope and capability pair. No arm is a wildcard.
const fn decide(scope: SessionScope, cap: Capability) -> bool {
    match scope {
        SessionScope::Full => match cap {
            Capability::SecondFactor => false,
            Capability::Challenge
            | Capability::Logout
            | Capability::OpaqueRegisterStart
            | Capability::ReauthLogin
            | Capability::RecoveryWrapRead
            | Capability::Recover
            | Capability::UnlockMethodsRead
            | Capability::UnlockMethodsWrite
            | Capability::PasswordPut
            | Capability::Rekey
            | Capability::VaultRead
            | Capability::SyncRead
            | Capability::SyncWrite
            | Capability::DeviceManage
            | Capability::AccountSettings => true,
        },
        SessionScope::Pending2fa => match cap {
            Capability::SecondFactor | Capability::Logout => true,
            Capability::Challenge
            | Capability::OpaqueRegisterStart
            | Capability::ReauthLogin
            | Capability::RecoveryWrapRead
            | Capability::Recover
            | Capability::UnlockMethodsRead
            | Capability::UnlockMethodsWrite
            | Capability::PasswordPut
            | Capability::Rekey
            | Capability::VaultRead
            | Capability::SyncRead
            | Capability::SyncWrite
            | Capability::DeviceManage
            | Capability::AccountSettings => false,
        },
        SessionScope::AccountReset => match cap {
            Capability::Challenge
            | Capability::OpaqueRegisterStart
            | Capability::RecoveryWrapRead
            | Capability::Recover
            | Capability::Logout => true,
            Capability::SecondFactor
            | Capability::ReauthLogin
            | Capability::UnlockMethodsRead
            | Capability::UnlockMethodsWrite
            | Capability::PasswordPut
            | Capability::Rekey
            | Capability::VaultRead
            | Capability::SyncRead
            | Capability::SyncWrite
            | Capability::DeviceManage
            | Capability::AccountSettings => false,
        },
        SessionScope::Unverified => match cap {
            Capability::Logout => true,
            Capability::Challenge
            | Capability::SecondFactor
            | Capability::OpaqueRegisterStart
            | Capability::ReauthLogin
            | Capability::RecoveryWrapRead
            | Capability::Recover
            | Capability::UnlockMethodsRead
            | Capability::UnlockMethodsWrite
            | Capability::PasswordPut
            | Capability::Rekey
            | Capability::VaultRead
            | Capability::SyncRead
            | Capability::SyncWrite
            | Capability::DeviceManage
            | Capability::AccountSettings => false,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `ALL` must list every capability once: this match has no wildcard arm,
    /// so a new variant stops compiling here until it is added to both places.
    #[test]
    fn capability_list_is_exhaustive() {
        const fn index(cap: Capability) -> usize {
            match cap {
                Capability::Challenge => 0,
                Capability::Logout => 1,
                Capability::SecondFactor => 2,
                Capability::OpaqueRegisterStart => 3,
                Capability::ReauthLogin => 4,
                Capability::RecoveryWrapRead => 5,
                Capability::Recover => 6,
                Capability::UnlockMethodsRead => 7,
                Capability::UnlockMethodsWrite => 8,
                Capability::PasswordPut => 9,
                Capability::Rekey => 10,
                Capability::VaultRead => 11,
                Capability::SyncRead => 12,
                Capability::SyncWrite => 13,
                Capability::DeviceManage => 14,
                Capability::AccountSettings => 15,
            }
        }
        const COUNT: usize = 16;
        assert_eq!(Capability::ALL.len(), COUNT);
        for (position, cap) in Capability::ALL.iter().enumerate() {
            assert_eq!(index(*cap), position, "{cap:?} is out of place in ALL");
        }
    }

    #[test]
    fn scope_names_are_distinct() {
        let all = [
            SessionScope::Full,
            SessionScope::Pending2fa,
            SessionScope::AccountReset,
            SessionScope::Unverified,
        ];
        for (i, a) in all.iter().enumerate() {
            for b in &all[i + 1..] {
                assert_ne!(a.as_str(), b.as_str());
            }
        }
    }
}
