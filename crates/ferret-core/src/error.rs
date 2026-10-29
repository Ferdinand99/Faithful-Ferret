//! Errors. Every error is `Copy` and carries no data about secrets.
//!
//! All authentication failures (wrong key, AAD, tag, commit, signature,
//! padding) are the single [`Error::Decrypt`] without a cause. Structure and
//! parameter errors, which do not depend on secrets, have their own stable
//! codes ([`Error::code`]). The codes are listed in `vectors/ERRORS.md`, and
//! the test vectors refer to them.

use core::fmt;

/// Why a text or byte input was rejected.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InputError {
    /// Shorter than the minimum.
    TooShort,
    /// Longer than the maximum.
    TooLong,
    /// Not valid UTF-8.
    NotUtf8,
    /// Contains a forbidden or unassigned character.
    ForbiddenCharacter,
    /// An export password equal to the master password.
    SameAsMasterPassword,
}

/// Which structure was malformed.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MalformedKind {
    /// Item or manifest envelope.
    Envelope,
    /// CBOR: syntax error, truncated input, bad UTF-8 or a reserved byte.
    Cbor,
    /// CBOR: a map with the same key twice.
    CborDuplicateKey,
    /// CBOR: indefinite length (`0x5f`, `0x7f`, `0x9f`, `0xbf`).
    CborIndefinite,
    /// CBOR: a tag (the allow-list is empty in v1).
    CborTag,
    /// CBOR: more than 16 levels of arrays and maps.
    CborDepth,
    /// CBOR: an array or map with more than 10 000 entries, or (where the
    /// caller sets a limit, as for an export body) too many nodes in all.
    CborCount,
    /// CBOR: text or bytes longer than 64 KiB.
    CborSize,
    /// CBOR: a map key that is not text.
    CborKeyType,
    /// CBOR: `undefined` or a simple value other than `true`, `false`, `null`.
    CborSimple,
    /// CBOR: an integer outside the range of `i64` and `u64`.
    CborInt,
    /// CBOR: bytes after the first data item.
    CborTrailing,
    /// An item body or manifest whose CBOR does not have the shape of
    /// Appendix B (a missing or mistyped field).
    ItemBody,
    /// Export file header, or the layout of the file around it (a file too
    /// short to hold the wrapped content key and a body).
    ExportHeader,
    /// TLV encoding.
    Tlv,
    /// Checkpoint entries.
    Entries,
    /// Recovery or secret key code: wrong prefix or a letter outside the
    /// alphabet.
    Code,
    /// The pinned record: a value out of range or a record that would grow
    /// without bound.
    PinnedRecord,
}

/// Why a checkpoint did not verify.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CheckpointFailure {
    /// The checkpoint MAC is wrong.
    BadMac,
    /// The digest does not match the entries.
    BadDigest,
    /// An entry in the checkpoint is missing from the server's rows.
    HiddenOrRolledBack,
    /// A row has a lower `rev` than the checkpoint records.
    LowerRev,
    /// A row has the same `rev` but a different hash.
    SameRevDifferentHash,
    /// A live row is older than a tombstone.
    LiveBehindTombstone,
    /// The checkpoint's `seq` is above the server's top `seq`.
    SeqAboveTop,
    /// At the top `seq` the recomputed digest differs.
    TopDigestMismatch,
}

/// Which pinned value a server or record contradicted. Spec: Fase 1 § 4.2
/// ("Pinning og SK-bit") and § 4.3 (the client remembers the highest
/// `kek_generation` and `vk_epoch` and rejects lower ones).
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PinnedField {
    /// The server address differs from the pinned one.
    ServerUrl,
    /// The account differs from the pinned one.
    AccountId,
    /// The vault differs from the pinned one.
    VaultId,
    /// A wrap has a lower `kek_generation` than the highest seen.
    KekGeneration,
    /// The vault context has a lower `vk_epoch` than the highest seen.
    VkEpoch,
    /// The secret key (SK) bit differs from the pinned one.
    SkBit,
    /// The OPAQUE server public key differs from the pinned one, or is
    /// missing.
    ServerKey,
    /// The vault's authentication public key `pk_a` differs from the pinned
    /// one within the same `vk_epoch`.
    AuthKey,
}

/// The error type of the whole crate.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    /// Every authentication failure, without a cause.
    Decrypt,
    /// Argon2id parameters outside the floor and ceiling.
    KdfOutOfRange,
    /// Unknown KSF profile.
    KdfProfileUnknown,
    /// KSF profile below the pinned one.
    KdfProfileDowngrade,
    /// Argon2id could not allocate its memory.
    KdfOutOfMemory,
    /// Rejected input (master password rules, UTF-8, length, characters).
    InvalidInput(InputError),
    /// Malformed envelope, CBOR, export header, TLV or entries.
    Malformed(MalformedKind),
    /// Larger than the allowed size.
    TooLarge,
    /// The item has a newer schema and is read-only.
    ReadOnlySchema,
    /// A tombstone failed verification.
    TombstoneInvalid,
    /// Checkpoint verification failed.
    Checkpoint(CheckpointFailure),
    /// Recovery or secret key checksum error.
    Checksum,
    /// Recovery or secret key is valid but not in canonical form.
    NonCanonical,
    /// Passkey: user verification missing, cancelled or no match (same value).
    NotAllowed,
    /// Not supported by this build or version.
    Unsupported,
    /// A value pinned on this device was contradicted. A hard error with a
    /// loud warning, never reported as a wrong password (Fase 1 § 4.2).
    Pinned(PinnedField),
}

impl Error {
    /// Every error value, one per code. Keep in sync with `code()` and with
    /// `vectors/ERRORS.md`; a test checks all three.
    pub const ALL: &'static [Error] = &[
        Error::Decrypt,
        Error::KdfOutOfRange,
        Error::KdfProfileUnknown,
        Error::KdfProfileDowngrade,
        Error::KdfOutOfMemory,
        Error::InvalidInput(InputError::TooShort),
        Error::InvalidInput(InputError::TooLong),
        Error::InvalidInput(InputError::NotUtf8),
        Error::InvalidInput(InputError::ForbiddenCharacter),
        Error::InvalidInput(InputError::SameAsMasterPassword),
        Error::Malformed(MalformedKind::Envelope),
        Error::Malformed(MalformedKind::Cbor),
        Error::Malformed(MalformedKind::CborDuplicateKey),
        Error::Malformed(MalformedKind::CborIndefinite),
        Error::Malformed(MalformedKind::CborTag),
        Error::Malformed(MalformedKind::CborDepth),
        Error::Malformed(MalformedKind::CborCount),
        Error::Malformed(MalformedKind::CborSize),
        Error::Malformed(MalformedKind::CborKeyType),
        Error::Malformed(MalformedKind::CborSimple),
        Error::Malformed(MalformedKind::CborInt),
        Error::Malformed(MalformedKind::CborTrailing),
        Error::Malformed(MalformedKind::ItemBody),
        Error::Malformed(MalformedKind::ExportHeader),
        Error::Malformed(MalformedKind::Tlv),
        Error::Malformed(MalformedKind::Entries),
        Error::Malformed(MalformedKind::Code),
        Error::Malformed(MalformedKind::PinnedRecord),
        Error::TooLarge,
        Error::ReadOnlySchema,
        Error::TombstoneInvalid,
        Error::Checkpoint(CheckpointFailure::BadMac),
        Error::Checkpoint(CheckpointFailure::BadDigest),
        Error::Checkpoint(CheckpointFailure::HiddenOrRolledBack),
        Error::Checkpoint(CheckpointFailure::LowerRev),
        Error::Checkpoint(CheckpointFailure::SameRevDifferentHash),
        Error::Checkpoint(CheckpointFailure::LiveBehindTombstone),
        Error::Checkpoint(CheckpointFailure::SeqAboveTop),
        Error::Checkpoint(CheckpointFailure::TopDigestMismatch),
        Error::Checksum,
        Error::NonCanonical,
        Error::NotAllowed,
        Error::Unsupported,
        Error::Pinned(PinnedField::ServerUrl),
        Error::Pinned(PinnedField::AccountId),
        Error::Pinned(PinnedField::VaultId),
        Error::Pinned(PinnedField::KekGeneration),
        Error::Pinned(PinnedField::VkEpoch),
        Error::Pinned(PinnedField::SkBit),
        Error::Pinned(PinnedField::ServerKey),
        Error::Pinned(PinnedField::AuthKey),
    ];

    /// The stable, data-free code that test vectors and bindings use.
    pub const fn code(&self) -> &'static str {
        match self {
            Error::Decrypt => "decrypt",
            Error::KdfOutOfRange => "kdf_out_of_range",
            Error::KdfProfileUnknown => "kdf_profile_unknown",
            Error::KdfProfileDowngrade => "kdf_profile_downgrade",
            Error::KdfOutOfMemory => "kdf_out_of_memory",
            Error::InvalidInput(kind) => match kind {
                InputError::TooShort => "input_too_short",
                InputError::TooLong => "input_too_long",
                InputError::NotUtf8 => "input_not_utf8",
                InputError::ForbiddenCharacter => "input_forbidden_character",
                InputError::SameAsMasterPassword => "input_same_as_master_password",
            },
            Error::Malformed(kind) => match kind {
                MalformedKind::Envelope => "malformed_envelope",
                MalformedKind::Cbor => "malformed_cbor",
                MalformedKind::CborDuplicateKey => "malformed_cbor_duplicate_key",
                MalformedKind::CborIndefinite => "malformed_cbor_indefinite",
                MalformedKind::CborTag => "malformed_cbor_tag",
                MalformedKind::CborDepth => "malformed_cbor_depth",
                MalformedKind::CborCount => "malformed_cbor_count",
                MalformedKind::CborSize => "malformed_cbor_size",
                MalformedKind::CborKeyType => "malformed_cbor_key_type",
                MalformedKind::CborSimple => "malformed_cbor_simple",
                MalformedKind::CborInt => "malformed_cbor_int",
                MalformedKind::CborTrailing => "malformed_cbor_trailing",
                MalformedKind::ItemBody => "malformed_item_body",
                MalformedKind::ExportHeader => "malformed_export_header",
                MalformedKind::Tlv => "malformed_tlv",
                MalformedKind::Entries => "malformed_entries",
                MalformedKind::Code => "malformed_code",
                MalformedKind::PinnedRecord => "malformed_pinned_record",
            },
            Error::TooLarge => "too_large",
            Error::ReadOnlySchema => "read_only_schema",
            Error::TombstoneInvalid => "tombstone_invalid",
            Error::Checkpoint(kind) => match kind {
                CheckpointFailure::BadMac => "checkpoint_bad_mac",
                CheckpointFailure::BadDigest => "checkpoint_bad_digest",
                CheckpointFailure::HiddenOrRolledBack => "checkpoint_hidden_or_rolled_back",
                CheckpointFailure::LowerRev => "checkpoint_lower_rev",
                CheckpointFailure::SameRevDifferentHash => "checkpoint_same_rev_different_hash",
                CheckpointFailure::LiveBehindTombstone => "checkpoint_live_behind_tombstone",
                CheckpointFailure::SeqAboveTop => "checkpoint_seq_above_top",
                CheckpointFailure::TopDigestMismatch => "checkpoint_top_digest_mismatch",
            },
            Error::Checksum => "checksum",
            Error::NonCanonical => "non_canonical",
            Error::NotAllowed => "not_allowed",
            Error::Unsupported => "unsupported",
            Error::Pinned(field) => match field {
                PinnedField::ServerUrl => "pinned_server_url",
                PinnedField::AccountId => "pinned_account_id",
                PinnedField::VaultId => "pinned_vault_id",
                PinnedField::KekGeneration => "pinned_kek_generation",
                PinnedField::VkEpoch => "pinned_vk_epoch",
                PinnedField::SkBit => "pinned_sk_bit",
                PinnedField::ServerKey => "pinned_server_key",
                PinnedField::AuthKey => "pinned_auth_key",
            },
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.code())
    }
}

impl core::error::Error for Error {}
