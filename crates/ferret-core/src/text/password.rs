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
pub struct MasterPassword {
    bytes: Zeroizing<Vec<u8>>,
    /// The creation policy this password was checked against, if it was made
    /// with [`MasterPassword::new`]; `None` for [`MasterPassword::for_unlock`].
    #[zeroize(skip)]
    checked: Option<MpPolicy>,
}

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
        Ok(Self {
            bytes,
            checked: Some(policy),
        })
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
        Ok(Self {
            bytes,
            checked: None,
        })
    }

    /// The OPAQUE password input: `mp`, or `mp ‖ 0x00 ‖ SK` with the 16 raw
    /// bytes of the secret key. The separator is unambiguous because `mp`
    /// never contains U+0000.
    ///
    /// The input remembers whether it meets the creation floor of this
    /// password (see [`OpaqueInput::meets_creation_floor`]): only a password
    /// made with [`MasterPassword::new`] does, and one checked against
    /// [`MpPolicy::WithSecretKey`] only when `sk` is given.
    ///
    /// Spec: Fase 1 section 4.1 step 3.
    pub fn opaque_input(&self, sk: Option<&SecretKey>) -> OpaqueInput {
        let extra = if sk.is_some() {
            SecretKey::LEN.saturating_add(1)
        } else {
            0
        };
        // Reserved at once so that the buffer is never reallocated.
        let mut buf = Zeroizing::new(Vec::with_capacity(self.bytes.len().saturating_add(extra)));
        buf.extend_from_slice(&self.bytes);
        if let Some(sk) = sk {
            buf.push(0x00);
            buf.extend_from_slice(sk.expose());
        }
        let floor_met = match self.checked {
            // 15 characters satisfy both policies.
            Some(MpPolicy::WithoutSecretKey) => true,
            Some(MpPolicy::WithSecretKey) => sk.is_some(),
            None => false,
        };
        OpaqueInput {
            bytes: buf,
            with_sk: sk.is_some(),
            floor_met,
        }
    }

    /// The normalized bytes.
    pub(crate) fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Start of the buffer and its capacity, so that a test in a separate
    /// crate can check that a wipe clears the whole allocation.
    #[cfg(feature = "test-support")]
    pub fn test_buffer(&self) -> (*const u8, usize) {
        (self.bytes.as_ptr(), self.bytes.capacity())
    }
}

/// The password input of OPAQUE (`mp` or `mp ‖ 0x00 ‖ SK`).
///
/// It remembers whether a secret key went in, so that the OPAQUE login can
/// check that against the SK bit pinned on the device before any key
/// stretching is done (Fase 1 § 4.2: the SK bit is never taken from the
/// server).
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct OpaqueInput {
    bytes: Zeroizing<Vec<u8>>,
    with_sk: bool,
    floor_met: bool,
}

impl OpaqueInput {
    /// The input bytes.
    pub(crate) fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Whether the input has the secret key appended.
    pub fn includes_secret_key(&self) -> bool {
        self.with_sk
    }

    /// Whether the password behind this input was checked with
    /// [`MasterPassword::new`] against the creation floor that fits the
    /// input: at least 12 characters when a secret key is part of it, at
    /// least 15 when it is not (E8). The account flows that set a password
    /// (creation, change, recovery) refuse an input for which this is false,
    /// so a password made with [`MasterPassword::for_unlock`] cannot be set.
    ///
    /// The zxcvbn estimate and the blocklist that the design asks for without
    /// a secret key are the client's: they are not part of the core.
    pub fn meets_creation_floor(&self) -> bool {
        self.floor_met
    }

    /// Whether the last 16 bytes of the input, after a `0x00` separator, are
    /// exactly `sk`, compared in constant time. False for an input without a
    /// secret key.
    pub(crate) fn ends_with_secret_key(&self, sk: &SecretKey) -> bool {
        if !self.with_sk {
            return false;
        }
        let len = self.bytes.len();
        let Some(split) = len.checked_sub(SecretKey::LEN.saturating_add(1)) else {
            return false;
        };
        let (_, tail) = self.bytes.split_at(split);
        let (separator, key) = tail.split_at(1);
        separator == [0x00] && ct_eq(key, sk.expose())
    }

    /// Start of the buffer and its capacity (see `MasterPassword::test_buffer`).
    #[cfg(feature = "test-support")]
    pub fn test_buffer(&self) -> (*const u8, usize) {
        (self.bytes.as_ptr(), self.bytes.capacity())
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

    /// [`ExportPassword::new`] with the master password required: an export
    /// password that normalizes to the same bytes as `mp` is rejected with
    /// `input_same_as_master_password`. This is the constructor for the export
    /// flow, where the master password is known because the vault is open, so
    /// the check cannot be left out by passing `None`.
    ///
    /// Spec: Fase 1 section 6.4.
    pub fn new_checked(utf8: &[u8], mp: &MasterPassword) -> Result<Self, Error> {
        Self::new(utf8, Some(mp))
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
