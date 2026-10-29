//! A redacted view of an item for the user interface.
//!
//! Spec: Fase 1 § 5.2 and plan Task 12: what crosses into the interface
//! holds no private key, no PRF seed, no TOTP address and no value of a
//! hidden field. The secrets are fetched one at a time on request.

use super::body::{ItemBody, ItemType};

/// A custom field as the interface sees it. `value` is `None` for a field
/// that is hidden by default (`password`, `hidden` and every kind this
/// version does not know).
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct FieldView {
    /// Identifies the field within the item.
    pub id: String,
    /// The label.
    pub label: String,
    /// The kind, as written in the body.
    pub kind: String,
    /// The value, for the kinds that are not secret.
    pub value: Option<String>,
}

/// A saved address as the interface sees it.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct UrlView {
    /// The address.
    pub url: String,
    /// The matching rule, as written in the body.
    pub matching: String,
}

/// A passkey as the interface sees it: who it is for, nothing it signs with.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct PasskeyView {
    /// The relying party id.
    pub rp_id: String,
    /// The user name.
    pub user_name: String,
    /// When it was made, unix milliseconds.
    pub created: u64,
    /// Whether the passkey carries PRF seeds.
    pub has_prf: bool,
}

/// An item without its secrets.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct ItemView {
    /// The type, as written in the body.
    pub item_type: String,
    /// The name.
    pub name: String,
    /// The fields.
    pub fields: Vec<FieldView>,
    /// The addresses.
    pub urls: Vec<UrlView>,
    /// Whether the item has a one-time-password setup.
    pub has_totp: bool,
    /// The passkey, without its keys.
    pub passkey: Option<PasskeyView>,
    /// Whether the item has notes.
    pub has_notes: bool,
    /// When it was made.
    pub created: u64,
    /// When it was last changed.
    pub modified: u64,
    /// The favorite mark.
    pub favorite: bool,
    /// The device that wrote it.
    pub device: Option<String>,
    /// Whether the item is read-only because its schema is newer.
    pub read_only: bool,
}

impl ItemBody {
    /// The redacted view of this body.
    pub fn view(&self) -> ItemView {
        ItemView {
            item_type: ItemType::as_str(&self.item_type).to_owned(),
            name: self.name.clone(),
            fields: self
                .fields
                .iter()
                .map(|f| FieldView {
                    id: f.id.clone(),
                    label: f.label.clone(),
                    kind: f.kind.as_str().to_owned(),
                    value: (!f.kind.is_secret()).then(|| f.value.clone()),
                })
                .collect(),
            urls: self
                .urls
                .iter()
                .map(|u| UrlView {
                    url: u.url.clone(),
                    matching: u.matching.as_str().to_owned(),
                })
                .collect(),
            has_totp: self.totp.is_some(),
            passkey: self.passkey.as_ref().map(|p| PasskeyView {
                rp_id: p.rp_id.clone(),
                user_name: p.user_name.clone(),
                created: p.created,
                has_prf: p.prf_seed_uv.is_some() || p.prf_seed_nouv.is_some(),
            }),
            has_notes: self.notes.is_some(),
            created: self.created,
            modified: self.modified,
            favorite: self.favorite,
            device: self.device.clone(),
            read_only: self.is_read_only(),
        }
    }
}
