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
    /// CBOR body.
    Cbor,
    /// Export file header.
    ExportHeader,
    /// TLV encoding.
    Tlv,
    /// Checkpoint entries.
    Entries,
    /// Recovery or secret key code: wrong prefix or a letter outside the
    /// alphabet.
    Code,
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
        Error::Malformed(MalformedKind::ExportHeader),
        Error::Malformed(MalformedKind::Tlv),
        Error::Malformed(MalformedKind::Entries),
        Error::Malformed(MalformedKind::Code),
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
                MalformedKind::ExportHeader => "malformed_export_header",
                MalformedKind::Tlv => "malformed_tlv",
                MalformedKind::Entries => "malformed_entries",
                MalformedKind::Code => "malformed_code",
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
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.code())
    }
}

impl core::error::Error for Error {}
