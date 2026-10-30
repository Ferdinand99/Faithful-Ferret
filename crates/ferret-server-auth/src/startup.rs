//! The decision on start: may the server run with the secrets it found?
//!
//! The files can be lost or swapped without anything in them saying so. The
//! database knows better: once it holds accounts, every record is bound to
//! one key pair, and the made-up answers for unknown names to one pre-login
//! secret. [`startup_decision`] compares what
//! [`load_or_create`](crate::load_or_create) found with what the database
//! remembers, and refuses to start when the server would otherwise lock
//! everyone out or change its made-up answers without a word.
//!
//! The function reads nothing and writes nothing. The caller reads the stored
//! fingerprint and whether accounts exist, and stores the fingerprint when
//! the decision asks for it. The fingerprint is public.

use crate::keys::{FileOrigin, LoadedSecrets, SetupFingerprint};

/// What the server must do before it accepts a request.
#[derive(Debug, PartialEq, Eq)]
pub enum StartupDecision {
    /// Everything fits: start.
    Proceed,
    /// Start, and keep this fingerprint in the database. (The first start,
    /// or a database from before the fingerprint existed and with no
    /// accounts.)
    RecordFingerprint(SetupFingerprint),
    /// Do not start.
    Refuse(StartupRefusal),
}

/// Why the server must not start.
#[derive(Debug, PartialEq, Eq)]
pub enum StartupRefusal {
    /// `opaque_setup` had to be created, but the database has accounts or a
    /// fingerprint: the old file is lost, and a new one would lock every
    /// account out.
    SetupLostWhileAccountsExist,
    /// `opaque_setup` exists but is not the one the database remembers.
    SetupReplaced,
    /// The database has accounts but no fingerprint, so the file cannot be
    /// checked.
    FingerprintMissingWithAccounts,
    /// `prelogin_secret` had to be created while accounts exist. A new one
    /// would change the made-up answers, so it is never rotated silently.
    PreloginSecretLost,
}

/// Decides from what was loaded, the fingerprint the database remembers
/// (`stored`) and whether the database has any accounts.
///
/// | `opaque_setup` | stored | accounts | decision |
/// |---|---|---|---|
/// | created | none | none | `RecordFingerprint` (first start) |
/// | created | some | any | `Refuse(SetupLostWhileAccountsExist)` |
/// | created | none | some | `Refuse(SetupLostWhileAccountsExist)` |
/// | existing | none | none | `RecordFingerprint` |
/// | existing | none | some | `Refuse(FingerprintMissingWithAccounts)` |
/// | existing | differs | any | `Refuse(SetupReplaced)` |
/// | existing | equal | some, `prelogin_secret` created | `Refuse(PreloginSecretLost)` |
/// | existing | equal | otherwise | `Proceed` |
///
/// A `prelogin_secret` that was created while the database has no accounts
/// is harmless: no made-up answer has been given for a real account yet.
pub fn startup_decision(
    loaded: &LoadedSecrets,
    stored: Option<SetupFingerprint>,
    accounts_with_records: bool,
) -> StartupDecision {
    let actual = loaded.keys.fingerprint();
    match (loaded.setup_origin, stored) {
        (FileOrigin::Created, Some(_)) => {
            StartupDecision::Refuse(StartupRefusal::SetupLostWhileAccountsExist)
        }
        (FileOrigin::Created, None) if accounts_with_records => {
            StartupDecision::Refuse(StartupRefusal::SetupLostWhileAccountsExist)
        }
        (FileOrigin::Created, None) => StartupDecision::RecordFingerprint(actual),
        (FileOrigin::Existing, None) if accounts_with_records => {
            StartupDecision::Refuse(StartupRefusal::FingerprintMissingWithAccounts)
        }
        (FileOrigin::Existing, None) => StartupDecision::RecordFingerprint(actual),
        (FileOrigin::Existing, Some(stored)) if stored != actual => {
            StartupDecision::Refuse(StartupRefusal::SetupReplaced)
        }
        (FileOrigin::Existing, Some(_))
            if accounts_with_records && loaded.prelogin_origin == FileOrigin::Created =>
        {
            StartupDecision::Refuse(StartupRefusal::PreloginSecretLost)
        }
        (FileOrigin::Existing, Some(_)) => StartupDecision::Proceed,
    }
}
