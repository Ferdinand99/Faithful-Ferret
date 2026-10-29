//! TLV encoding for AAD and HKDF salts.
//!
//! Spec: Fase 1 § 3.1. `tlv(tag, value) = tag (1 byte) ‖ len (u16be) ‖
//! value`, with `value` at most 65 535 bytes. AAD and HKDF salts are the
//! plain concatenation of TLV fields in the order given, with no other
//! separator. Each field name has one fixed tag, listed in [`tag`].
//!
//! Every field carries its own length, so a list of fields has exactly one
//! encoding and two different lists never encode to the same bytes.

use crate::error::{Error, MalformedKind};

/// Every label of suite 1 starts with this prefix. Spec: Fase 1 § 3.1.
pub const LABEL_PREFIX: &str = "ferret/v1/";

/// The `suite` byte of every structure written by this version. Suite 1 is
/// OPAQUE with the Argon2id profiles of Fase 1 § 4.2, HKDF-SHA256,
/// XChaCha20-Poly1305 and Ed25519. Spec: Fase 1 § 3.
pub const SUITE: u8 = 1;

/// Largest value a single TLV field can carry.
pub const MAX_VALUE_LEN: usize = u16::MAX as usize;

/// Tags of the TLV fields. Spec: Fase 1 § 3.1 (table).
///
/// These constants are the only place a tag number is written; everything
/// else refers to them by name.
pub mod tag {
    /// `label`: ASCII, starts with `ferret/v1/` for suite 1.
    pub const LABEL: u8 = 0x01;
    /// `version`: u8.
    pub const VERSION: u8 = 0x02;
    /// `suite`: u8.
    pub const SUITE: u8 = 0x03;
    /// `kind`: u8 (1 = item, 2 = manifest).
    pub const KIND: u8 = 0x04;
    /// `account_id`: 16 bytes.
    pub const ACCOUNT_ID: u8 = 0x10;
    /// `vault_id`: 16 bytes.
    pub const VAULT_ID: u8 = 0x11;
    /// `item_id`: 16 bytes.
    pub const ITEM_ID: u8 = 0x12;
    /// `method_id`: 16 bytes.
    pub const METHOD_ID: u8 = 0x13;
    /// `method_type`: u8 (1 = password, 2 = recovery, 3 = prf, 4 = pin,
    /// 5 = device).
    pub const METHOD_TYPE: u8 = 0x14;
    /// `vk_epoch`: u64be.
    pub const VK_EPOCH: u8 = 0x20;
    /// `kek_generation`: u64be.
    pub const KEK_GENERATION: u8 = 0x21;
    /// `rev`: u64be.
    pub const REV: u8 = 0x22;
    /// `seq`: u64be.
    pub const SEQ: u8 = 0x23;
    /// `kdf`: `m_kib` u32be ‖ `t` u32be ‖ `p` u32be (12 bytes).
    pub const KDF: u8 = 0x30;
    /// `credential_id`: bytes.
    pub const CREDENTIAL_ID: u8 = 0x31;
    /// `prf_salt`: 32 bytes.
    pub const PRF_SALT: u8 = 0x32;
    /// `nonce` (challenge from the server): 32 bytes.
    pub const NONCE: u8 = 0x33;
    /// `hash`: 32 bytes.
    pub const HASH: u8 = 0x35;
    /// `op`: ASCII.
    pub const OP: u8 = 0x36;
    /// `device_salt`: 16 bytes.
    pub const DEVICE_SALT: u8 = 0x37;
    /// `salt_a` (appendix A only): 16 bytes.
    pub const SALT_A: u8 = 0x38;
    /// `header`: bytes (export header, stored verbatim).
    pub const HEADER: u8 = 0x39;

    /// Every tag of the table, in table order. Used by tests that check
    /// that the numbers are unique.
    pub const ALL: [u8; 22] = [
        LABEL,
        VERSION,
        SUITE,
        KIND,
        ACCOUNT_ID,
        VAULT_ID,
        ITEM_ID,
        METHOD_ID,
        METHOD_TYPE,
        VK_EPOCH,
        KEK_GENERATION,
        REV,
        SEQ,
        KDF,
        CREDENTIAL_ID,
        PRF_SALT,
        NONCE,
        HASH,
        OP,
        DEVICE_SALT,
        SALT_A,
        HEADER,
    ];
}

/// Builder for a sequence of TLV fields, in the order the fields are added.
///
/// ```
/// use ferret_core::{Tlv, tlv::tag};
///
/// let aad = Tlv::new()
///     .label("ferret/v1/wrap")
///     .u8(tag::SUITE, 1)
///     .finish()
///     .unwrap();
/// assert_eq!(&aad[..3], &[0x01, 0x00, 0x0e]);
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Tlv {
    bytes: Vec<u8>,
    /// Set by `label` when the label cannot be encoded; reported by `finish`
    /// so a bad label can never silently produce a shorter AAD.
    failed: Option<Error>,
}

impl Default for Tlv {
    fn default() -> Self {
        Self::new()
    }
}

impl Tlv {
    /// An empty list of fields.
    pub fn new() -> Self {
        Self {
            bytes: Vec::new(),
            failed: None,
        }
    }

    /// Appends the `label` field (tag `0x01`). The label must be ASCII and
    /// start with [`LABEL_PREFIX`] (`ferret/v1/`, suite 1); any other label,
    /// or one longer than [`MAX_VALUE_LEN`], makes [`Tlv::finish`] fail with
    /// `Malformed(Tlv)`, so a mistyped label cannot silently change the
    /// domain separation of an AAD or salt.
    pub fn label(mut self, s: &'static str) -> Self {
        if !s.is_ascii() || !s.starts_with(LABEL_PREFIX) {
            self.failed = Some(Error::Malformed(MalformedKind::Tlv));
            return self;
        }
        self.push_or_fail(tag::LABEL, s.as_bytes());
        self
    }

    /// Appends a one-byte field (`version`, `suite`, `kind`, `method_type`).
    pub fn u8(mut self, tag: u8, v: u8) -> Self {
        self.push_or_fail(tag, &[v]);
        self
    }

    /// Appends a `u64be` field (`vk_epoch`, `kek_generation`, `rev`, `seq`).
    pub fn u64(mut self, tag: u8, v: u64) -> Self {
        self.push_or_fail(tag, &v.to_be_bytes());
        self
    }

    /// Appends a byte field of at most 65 535 bytes. An empty value is
    /// allowed. A longer value is an error and is never truncated.
    pub fn bytes(mut self, tag: u8, v: &[u8]) -> Result<Self, Error> {
        self.push(tag, v)?;
        Ok(self)
    }

    /// The encoded fields, `tag ‖ len ‖ value` for each in order. Fails if an
    /// earlier [`Tlv::label`] could not be encoded.
    pub fn finish(self) -> Result<Vec<u8>, Error> {
        match self.failed {
            Some(e) => Err(e),
            None => Ok(self.bytes),
        }
    }

    /// Appends a field without a `Result`: a failure is remembered and
    /// reported by [`Tlv::finish`]. For one- and eight-byte values the length
    /// always fits, and a label is checked here too.
    fn push_or_fail(&mut self, tag: u8, value: &[u8]) {
        if let Err(e) = self.push(tag, value) {
            self.failed = Some(e);
        }
    }

    fn push(&mut self, tag: u8, value: &[u8]) -> Result<(), Error> {
        let len = u16::try_from(value.len()).map_err(|_| Error::TooLarge)?;
        self.bytes.push(tag);
        self.bytes.extend_from_slice(&len.to_be_bytes());
        self.bytes.extend_from_slice(value);
        Ok(())
    }
}
