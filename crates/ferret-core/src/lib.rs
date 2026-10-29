//! Crypto core of Faithful Ferret, a self-hosted zero-knowledge password
//! manager.
//!
//! The core is written in safe Rust, takes all randomness from a
//! [`SecureRng`], and reports failures as stable [`Error`] codes. Nothing in
//! this crate does I/O.
//!
//! # Features
//!
//! * `test-support` (off by default, never part of a release): a replaying
//!   RNG, a deterministic test RNG and the test-vector loader and runner in
//!   [`testing`].

#![forbid(unsafe_code)]
#![deny(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::arithmetic_side_effects
)]
// Unit tests inside the crate may use the panicking helpers; the rules above
// are for production code.
#![cfg_attr(
    test,
    allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::indexing_slicing,
        clippy::panic,
        clippy::arithmetic_side_effects
    )
)]

pub mod cbor;
pub mod codes;
pub mod envelope;
pub mod error;
pub mod export;
pub mod ids;
pub mod integrity;
pub mod item;
pub mod keys;
pub mod ksf_profile;
pub mod opaque;
pub mod passkey;
pub mod pinning;
pub mod prim;
pub mod rng;
pub mod secret;
#[cfg(feature = "test-support")]
pub mod testing;
pub mod text;
pub mod tlv;
pub mod totp;
pub mod wrap;

pub use codes::{decode_recovery_key, decode_secret_key, encode_recovery_key, encode_secret_key};
pub use envelope::{
    SealedItem, decrypt_item, decrypt_manifest, encrypt_item, encrypt_manifest, item_tag,
    parse_envelope, verify_item_tag,
};
pub use error::{CheckpointFailure, Error, InputError, MalformedKind, PinnedField};
pub use export::{
    EXPORT_KDF, ExportHeader, ExportItem, PlainExportOptions, export_encrypt, export_plain_csv,
    export_plain_json, import_decrypt, parse_export_header,
};
pub use ids::{AccountId, ItemId, MethodId, VaultId};
pub use integrity::{
    AuthOp, AuthPublicKey, Checkpoint, CheckpointEntry, MutationOp, RecoveryPublicKey, RekeyBundle,
    RekeyInput, RekeyItem, RekeyTombstone, RowState, ServerRow, Tombstone, auth_sign,
    make_checkpoint, make_tombstone, recovery_sign, verify_auth_proof, verify_checkpoint,
    verify_recovery_proof, verify_tombstone,
};
pub use item::{
    DecodedItem, Field, FieldKind, ItemBody, ItemType, Manifest, ManifestEntry, Passkey, Totp,
    UrlEntry, UrlMatch,
};
pub use keys::{UnlockedVault, VaultContext, recovery_public_key};
pub use ksf_profile::KsfProfile;
pub use opaque::{
    LoginFinished, LoginState, OPAQUE_CONTEXT, PinState, RegistrationFinished, RegistrationState,
    opaque_login_finish, opaque_login_start, opaque_register_finish, opaque_register_start,
};
pub use passkey::{
    CallerContext, CanonicalOrigin, CreateRequest, CreatedPasskey, GetRequest, PasskeyRecord, RpId,
    UserVerification, UvOutcome, canonical_origin, passkey_create, passkey_get, prf_output,
    validate_rp_id,
};
pub use pinning::{MethodFloor, MethodKey, MethodManifestView, Pinned, ServerView};
pub use prim::{KDF_CEIL, KDF_FLOOR, KdfParams, check_kdf_params};
pub use rng::{OsRng, SecureRng};
pub use secret::{
    AuthSeed, ExportContentKey, ExportKey, ItemKey, KDel, KHead, KMeta, Kek, KekDevPin, PrfOutput,
    PrfSeed, RecoveryKey, SecretKey, VaultKey,
};
#[cfg(feature = "test-support")]
pub use testing::{ReplayRng, TestRng};
pub use text::{
    ExportPassword, MasterPassword, MpPolicy, OpaqueInput, PIN_MAX_DIGITS, PIN_MIN_DIGITS, Pin,
};
pub use tlv::Tlv;
pub use totp::{
    TotpAlgorithm, TotpParams, TotpSecret, parse_otpauth, totp_code, totp_seconds_left,
};
pub use wrap::{Method, WrapRecord, unwrap_vk, wrap_vk};
