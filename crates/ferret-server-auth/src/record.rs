//! The stored OPAQUE record and the key stretching profiles the server
//! accepts.
//!
//! The server cannot tell which password or which profile a record was made
//! with. All it can check is the shape: the length, and that the client's
//! public key inside it is a valid ristretto255 element. Everything else is
//! the client's to get right, and a record that is wrong in some other way
//! only locks its own account (see [`StoredRecord`]).

use core::fmt;

use ferret_core::KsfProfile;
use ferret_core::opaque::server_suite::opaque_ke::RegistrationUpload;
use ferret_core::opaque::server_suite::{FerretSuite, REGISTRATION_RECORD_LEN};
use sha2::{Digest as _, Sha256};
use zeroize::Zeroizing;

use crate::ct::ct_eq;
use crate::error::{AuthError, Malformed};

/// Label of the hash that ties a login state to a record.
const RECORD_BINDING_LABEL: &[u8] = b"ferret/v1/server/login-record";

/// A record that is well formed: exactly 192 bytes, with a client public key
/// that is a valid ristretto255 element. The one exception is the stand-in
/// record of the crate (`zeroed`), which holds zeros, is never parsed and can
/// never be chosen for an account that may log in.
///
/// The server cannot know more than that. The bytes hold the masking key of
/// the record, so they are wiped when the value is dropped.
///
/// Spec: Fase 1 § 4.2 ("Registrering", step 3).
#[derive(Clone)]
pub struct ValidatedRecord(Zeroizing<Vec<u8>>);

impl ValidatedRecord {
    /// Checks `bytes` and keeps a copy.
    ///
    /// The length is checked first and must be exactly 192: the parser of
    /// `opaque-ke` reads a prefix and ignores whatever follows, so a record
    /// with trailing bytes would otherwise be stored as it came. The answer
    /// depends on the given bytes and on nothing else.
    pub fn parse(bytes: &[u8]) -> Result<Self, AuthError> {
        let malformed = AuthError::Malformed(Malformed::RegistrationRecord);
        if bytes.len() != REGISTRATION_RECORD_LEN {
            return Err(malformed);
        }
        RegistrationUpload::<FerretSuite>::deserialize(bytes).map_err(|_| malformed)?;
        Ok(Self(Zeroizing::new(bytes.to_vec())))
    }

    /// 192 zero bytes: the stand-in for the record of a name without an
    /// account, so that the code that reads a record reads one on every path.
    /// It is not a valid OPAQUE record and is never parsed.
    pub(crate) fn zeroed() -> Self {
        Self(Zeroizing::new(vec![0u8; REGISTRATION_RECORD_LEN]))
    }

    /// The 192 bytes, as the client made them.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Debug for ValidatedRecord {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ValidatedRecord([redacted])")
    }
}

/// The record a login was started from, as a hash:
/// `SHA-256("ferret/v1/server/login-record" ‖ record)`.
///
/// `login_start` seals the binding of the record it answered from into the
/// login state, and `login_finish` compares it with the binding of the record
/// the account has when the login finishes ([`crate::login::CurrentRecord`]).
/// A password change, a recovery and a restore each put another record in
/// place, so a login that was started before one of them cannot finish after
/// it, even with the password that was right when it started.
///
/// The record is a fixed 192 bytes after a fixed label, so the input is not
/// ambiguous. The comparison is in constant time ([`RecordBinding::same_as`]);
/// there is no `PartialEq`.
///
/// Spec: Fase 1 § 4.2 ("Innlogging").
#[derive(Clone)]
pub struct RecordBinding([u8; 32]);

impl RecordBinding {
    /// The binding of the stored bytes of a record. The server passes the
    /// bytes it has stored for the account, as they are.
    pub fn of(record: &[u8]) -> Self {
        let mut hash = Sha256::new();
        hash.update(RECORD_BINDING_LABEL);
        hash.update(record);
        Self(hash.finalize().into())
    }

    /// Whether the two are the binding of the same record, in constant time.
    pub fn same_as(&self, other: &RecordBinding) -> bool {
        ct_eq(&self.0, &other.0)
    }

    /// The 32 bytes, for the sealed state.
    pub(crate) const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// A binding read back from a sealed state.
    pub(crate) const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
}

impl fmt::Debug for RecordBinding {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("RecordBinding([redacted])")
    }
}

/// What the server stores for an account after a registration: the record
/// and the key stretching profile the client said it used.
///
/// The server cannot see the profile in the record. It trusts the number the
/// caller passed with a signed or invited request. A wrong claim does not
/// help an attacker: the client then stretches with another profile than the
/// one it stored, and its own unlock fails until the account is recovered.
#[derive(Clone)]
pub struct StoredRecord {
    /// The record.
    pub record: ValidatedRecord,
    /// The profile number that goes with it.
    pub ksf_profile: u8,
}

impl fmt::Debug for StoredRecord {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("StoredRecord([redacted])")
    }
}

/// Whether a registration creates an account or replaces the record of one
/// that exists.
///
/// The caller has to say which, so a missing stored profile cannot pass as a
/// new account. `Existing` carries the profile stored for the account. It
/// must come from the stored row and never from the request.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum RegistrationKind {
    /// A new account: only the table and the minimum apply.
    NewAccount,
    /// An account that already has a record with this profile number. The
    /// new profile may not be lower.
    Existing(u8),
}

impl fmt::Debug for RegistrationKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RegistrationKind::NewAccount => f.write_str("RegistrationKind::NewAccount"),
            RegistrationKind::Existing(_) => f.write_str("RegistrationKind::Existing(..)"),
        }
    }
}

/// Which profile numbers the server accepts, and the lowest one for a new
/// account.
///
/// Built from the table of the client itself, so the two cannot disagree on
/// which numbers exist.
///
/// Spec: Fase 1 § 4.2 (table "KSF-profiler"). A password change or an upgrade
/// never gets a profile lower than the one stored. A recovery is the one
/// exception, see [`ProfileRules::accept_recovery`].
#[derive(Clone)]
pub struct ProfileRules {
    known: Vec<u8>,
    minimum: u8,
}

impl ProfileRules {
    /// The profiles of suite 1: every number the client's table knows, and
    /// profile 1 as the lowest.
    pub fn ferret_v1() -> Self {
        let known = (1..=u32::from(u8::MAX))
            .filter_map(|n| KsfProfile::from_wire(n).ok())
            .map(KsfProfile::number)
            .collect();
        Self { known, minimum: 1 }
    }

    /// Rules with chosen numbers, for tests that need a table longer than
    /// the one of the client.
    #[cfg(feature = "test-support")]
    pub fn for_tests(known: &[u8], minimum: u8) -> Self {
        Self {
            known: known.to_vec(),
            minimum,
        }
    }

    /// Checks the profile a caller claims and returns it as a stored number.
    ///
    /// The claim is refused with [`AuthError::ProfileRejected`] when it is
    ///
    /// * not a number the table knows (this includes anything above 255),
    /// * below the minimum for a new account, or
    /// * below the profile already stored for the account
    ///   ([`RegistrationKind::Existing`]).
    ///
    /// A new account is not compared with anything stored. The answer
    /// depends on the stored profile, so an endpoint may give it only after
    /// the caller has been authorized.
    pub fn accept(&self, claimed: u32, kind: RegistrationKind) -> Result<u8, AuthError> {
        let rejected = AuthError::ProfileRejected;
        let claimed = u8::try_from(claimed).map_err(|_| rejected)?;
        if !self.known.contains(&claimed) || claimed < self.minimum {
            return Err(rejected);
        }
        match kind {
            RegistrationKind::Existing(stored) if claimed < stored => Err(rejected),
            RegistrationKind::Existing(_) | RegistrationKind::NewAccount => Ok(claimed),
        }
    }

    /// Checks the profile a recovery claims and returns it as a stored
    /// number.
    ///
    /// A recovery needs the holder of the recovery key, who can replace the
    /// whole record anyway. It may therefore set any profile the rules
    /// accept, one lower than the stored profile included: that is how a
    /// wrongly claimed higher profile is undone (a client that claimed a
    /// profile it did not use cannot unlock its account until it is
    /// recovered). The claim is refused with [`AuthError::ProfileRejected`]
    /// when it is not a number the table knows or is below the minimum. The
    /// stored profile is not read, so the answer does not depend on it.
    ///
    /// A recovery that lowers a profile that was really in use has a client
    /// side cost: a device that pinned the higher profile refuses the lower
    /// one (the pin only goes up) until it is pinned again. In the lock-out
    /// case this does not happen, because the record never opened and no
    /// device pinned the claimed profile.
    pub fn accept_recovery(&self, claimed: u32) -> Result<u8, AuthError> {
        self.accept(claimed, RegistrationKind::NewAccount)
    }
}

impl fmt::Debug for ProfileRules {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ProfileRules { .. }")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    /// `SHA-256("ferret/v1/server/login-record" ‖ record)`, worked out
    /// outside this crate.
    #[test]
    fn the_binding_is_the_labelled_hash_of_the_record() {
        let zeros = [0u8; REGISTRATION_RECORD_LEN];
        assert_eq!(
            hex(RecordBinding::of(&zeros).as_bytes()),
            "70d4b55003f855b1c9fe6aca050ab75a07b8461d89bc5487a01a6604e6e2060b"
        );
        let counting: Vec<u8> = (0..=191u8).collect();
        assert_eq!(
            hex(RecordBinding::of(&counting).as_bytes()),
            "ef6fb30e13c04f9ff3894fc0647dd9878c94b4e718794d1791b12029fffd1bdb"
        );
    }

    #[test]
    fn one_changed_byte_is_another_record() {
        let record: Vec<u8> = (0..=191u8).collect();
        let binding = RecordBinding::of(&record);
        assert!(binding.same_as(&RecordBinding::of(&record)));
        for at in [0, 95, 191] {
            let mut other = record.clone();
            other[at] ^= 1;
            assert!(!binding.same_as(&RecordBinding::of(&other)), "byte {at}");
        }
        assert_eq!(format!("{binding:?}"), "RecordBinding([redacted])");
    }
}
