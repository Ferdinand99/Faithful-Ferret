//! Vault items: the typed body, the manifest, padding and the redacted view.
//!
//! Spec: Fase 1 § 5.2. The envelope that seals them is in
//! [`crate::envelope`].

pub mod body;
pub mod manifest;
pub mod pad;
pub mod view;

pub use body::{Field, FieldKind, ItemBody, ItemType, Passkey, Totp, UrlEntry, UrlMatch};
pub use manifest::{Manifest, ManifestEntry};
pub use view::{FieldView, ItemView, PasskeyView, UrlView};

/// A decrypted item and whether it may be written back.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct DecodedItem {
    /// The body.
    pub body: ItemBody,
    /// True when the body has a newer `schema` than this version writes: it
    /// can be shown and never rewritten.
    pub read_only: bool,
}
