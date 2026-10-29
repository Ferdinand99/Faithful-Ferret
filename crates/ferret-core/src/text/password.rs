//! The master password and the export password.
//!
//! Spec: Fase 1 section 3.1 (F-23), section 4.1 steps 1 and 3, section 6.4;
//! plan U9.
//!
//! The minimum length (the creation floor) applies only when a password is
//! created or changed: [`MasterPassword::new`] and [`ExportPassword::new`].
//! The floor can be raised in a later release, and a user must never be
//! refused at unlock or import because an existing password is now "too
//! short". [`MasterPassword::for_unlock`] and [`ExportPassword::for_open`]
//! normalize the same way and keep the maximum and the character rules, but
//! have no minimum.
//!
//! Every buffer that holds password text is a `Zeroizing` value,
//! and none of these types has `Clone`, `Debug` or `PartialEq`.

use super::unicode::{Normalized, normalize_password};
use crate::error::{Error, InputError};
use crate::prim::ct::ct_eq;
use crate::secret::SecretKey;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

/// Minimum length of a master password when a secret key is used (E8).
pub const MIN_LEN_WITH_SECRET_KEY: usize = 12;

/// Minimum length of a master password without a secret key (E8).
pub const MIN_LEN_WITHOUT_SECRET_KEY: usize = 15;

/// Minimum length of an export password (plan U9 b).
pub const MIN_LEN_EXPORT: usize = 12;

/// Which minimum length applies to the master password.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum MpPolicy {
    /// A secret key is part of the OPAQUE input: at least 12 characters.
    WithSecretKey,
    /// No secret key: at least 15 characters.
    WithoutSecretKey,
}

impl MpPolicy {
    /// The minimum length in NFC scalar values.
    pub const fn min_len(self) -> usize {
        match self {
            MpPolicy::WithSecretKey => MIN_LEN_WITH_SECRET_KEY,
            MpPolicy::WithoutSecretKey => MIN_LEN_WITHOUT_SECRET_KEY,
        }
    }
}

/// A master password: `NFKD(MP)` as UTF-8, validated.
///
/// Spec: Fase 1 section 3.1: NFKD with the Unicode 16.0 tables; reject
/// control characters (also U+0000) and unassigned characters; at most 1 024
/// scalar values and 4 096 bytes after NFKD; at least 12 (with SK) or 15
/// (without SK) characters, counted in NFC scalar values (plan U9 a).
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct MasterPassword(Zeroizing<Vec<u8>>);

impl MasterPassword {
    /// Validates and normalizes `utf8`.
    ///
    /// Errors, in this order of precedence: `input_not_utf8`,
    /// `input_forbidden_character`, `input_too_long`, `input_too_short`.
    ///
    /// Use this when a password is created or changed. To unlock an existing
    /// account use [`MasterPassword::for_unlock`].
    pub fn new(utf8: &[u8], policy: MpPolicy) -> Result<Self, Error> {
        let Normalized { bytes, nfc_len } = normalize_password(utf8)?;
        if nfc_len < policy.min_len() {
            return Err(Error::InvalidInput(InputError::TooShort));
        }
        Ok(Self(bytes))
    }

    /// Normalizes a master password that already exists, for unlocking or
    /// signing in: the same bytes as [`MasterPassword::new`] gives, with the
    /// maximum length and the character rules but no minimum length (the
    /// creation floor may have been raised since the password was set).
    ///
    /// Errors: `input_not_utf8`, `input_forbidden_character`,
    /// `input_too_long`.
    pub fn for_unlock(utf8: &[u8]) -> Result<Self, Error> {
        let Normalized { bytes, .. } = normalize_password(utf8)?;
        Ok(Self(bytes))
    }

    /// The OPAQUE password input: `mp`, or `mp ‖ 0x00 ‖ SK` with the 16 raw
    /// bytes of the secret key. The separator is unambiguous because `mp`
    /// never contains U+0000.
    ///
    /// Spec: Fase 1 section 4.1 step 3.
    pub fn opaque_input(&self, sk: Option<&SecretKey>) -> OpaqueInput {
        let extra = if sk.is_some() {
            SecretKey::LEN.saturating_add(1)
        } else {
            0
        };
        // Reserved at once so that the buffer is never reallocated.
        let mut buf = Zeroizing::new(Vec::with_capacity(self.0.len().saturating_add(extra)));
        buf.extend_from_slice(&self.0);
        if let Some(sk) = sk {
            buf.push(0x00);
            buf.extend_from_slice(sk.expose());
        }
        OpaqueInput(buf)
    }

    /// The normalized bytes.
    #[allow(dead_code)] // first used by Task 8 (OPAQUE client)
    pub(crate) fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Start of the buffer and its capacity, so that a test in a separate
    /// crate can check that a wipe clears the whole allocation.
    #[cfg(feature = "test-support")]
    pub fn test_buffer(&self) -> (*const u8, usize) {
        (self.0.as_ptr(), self.0.capacity())
    }
}

/// The password input of OPAQUE (`mp` or `mp ‖ 0x00 ‖ SK`).
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct OpaqueInput(Zeroizing<Vec<u8>>);

impl OpaqueInput {
    /// The input bytes.
    #[allow(dead_code)] // first used by Task 8 (OPAQUE client)
    pub(crate) fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Start of the buffer and its capacity (see `MasterPassword::test_buffer`).
    #[cfg(feature = "test-support")]
    pub fn test_buffer(&self) -> (*const u8, usize) {
        (self.0.as_ptr(), self.0.capacity())
    }
}

/// An export password: the same NFKD and character rules as the master
/// password, at least 12 characters, and not equal to the master password.
///
/// Spec: Fase 1 section 6.4; plan U9 (b).
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct ExportPassword(Zeroizing<Vec<u8>>);

impl ExportPassword {
    /// Validates and normalizes `utf8`. If the master password is given, an
    /// export password that normalizes to the same bytes is rejected with
    /// `input_same_as_master_password`. The comparison is constant-time.
    pub fn new(utf8: &[u8], mp: Option<&MasterPassword>) -> Result<Self, Error> {
        let Normalized { bytes, nfc_len } = normalize_password(utf8)?;
        if nfc_len < MIN_LEN_EXPORT {
            return Err(Error::InvalidInput(InputError::TooShort));
        }
        if let Some(mp) = mp
            && ct_eq(&bytes, mp.as_bytes())
        {
            return Err(Error::InvalidInput(InputError::SameAsMasterPassword));
        }
        Ok(Self(bytes))
    }

    /// Normalizes the password of an export file that is being opened: the
    /// maximum length and the character rules, but no minimum length and no
    /// comparison with the master password (those apply when the file is
    /// written). The file may come from a release with a lower floor.
    pub fn for_open(utf8: &[u8]) -> Result<Self, Error> {
        let Normalized { bytes, .. } = normalize_password(utf8)?;
        Ok(Self(bytes))
    }

    /// The normalized bytes.
    pub(crate) fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}
