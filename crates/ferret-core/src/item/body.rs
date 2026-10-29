//! The item body: the typed part of the schema, and the unknown part kept
//! as it was.
//!
//! Spec: Fase 1 § 5.2 ("Kropp", "Ukjente felt bevares") and plan Appendix B
//! (approved as U4).
//!
//! ```text
//! { "schema": 1,
//!   "type": "login" | "note" | "card" | "identity" | <other text, kept>,
//!   "name": text,
//!   "fields": [ { "id", "label", "kind", "value" } ],
//!   "urls":   [ { "url", "match": "host" | "domain" | "exact" } ],
//!   "totp":    { "uri" }?,
//!   "passkey": { "cred_id", "rp_id", "user_handle", "user_name", "priv",
//!                "sign_count", "created", "prf_seed_uv"?, "prf_seed_nouv"? }?,
//!   "notes": text?, "created": u64, "modified": u64, "favorite": bool,
//!   "device": text? }
//! ```
//!
//! Every object, at every level, keeps the keys it does not know in an
//! `extra` list, in the order they were read, and writes them again after
//! the known keys. A body with `schema` above 1 is read leniently (anything
//! that does not fit the schema of this version goes to `extra`) and is
//! read-only: it can be shown and never written.

use super::DecodedItem;
use crate::cbor::{self, Entries, Value, redacted_debug};
use crate::error::{Error, MalformedKind};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

/// The `schema` this version reads and writes.
pub const SCHEMA: u64 = 1;

const fn bad() -> Error {
    Error::Malformed(MalformedKind::ItemBody)
}

/// A text-valued enumeration with a catch-all for values this version does
/// not know. The unknown text is kept and written back unchanged.
macro_rules! text_enum {
    ($(#[$meta:meta])* $name:ident { $($(#[$vmeta:meta])* $var:ident => $text:literal),+ $(,)? }) => {
        $(#[$meta])*
        #[derive(Clone, PartialEq, Eq, Debug)]
        pub enum $name {
            $($(#[$vmeta])* $var,)+
            /// A value this version does not know, kept as it was.
            Other(String),
        }

        impl $name {
            /// The text as written in the body.
            pub fn as_str(&self) -> &str {
                match self {
                    $(Self::$var => $text,)+
                    Self::Other(s) => s,
                }
            }

            /// The value for a text read from a body.
            pub fn from_text(s: String) -> Self {
                match s.as_str() {
                    $($text => Self::$var,)+
                    _ => Self::Other(s),
                }
            }
        }

        impl Zeroize for $name {
            fn zeroize(&mut self) {
                if let Self::Other(s) = self {
                    s.zeroize();
                }
            }
        }
    };
}

text_enum!(
    /// What kind of item this is.
    ItemType {
        /// A login.
        Login => "login",
        /// A secure note.
        Note => "note",
        /// A payment card.
        Card => "card",
        /// An identity.
        Identity => "identity",
    }
);

text_enum!(
    /// How a custom field is shown and treated.
    FieldKind {
        /// Plain text.
        Text => "text",
        /// A secret that is hidden by default.
        Password => "password",
        /// Hidden text.
        Hidden => "hidden",
        /// A web address.
        Url => "url",
        /// An e-mail address.
        Email => "email",
        /// A phone number.
        Phone => "phone",
    }
);

text_enum!(
    /// How a saved address is matched against a page.
    UrlMatch {
        /// The host must be equal (the default).
        Host => "host",
        /// The registrable domain must be equal.
        Domain => "domain",
        /// The whole address must be equal.
        Exact => "exact",
    }
);

impl FieldKind {
    /// Whether the value is hidden from a redacted view. Unknown kinds are
    /// treated as secret.
    pub fn is_secret(&self) -> bool {
        !matches!(
            self,
            FieldKind::Text | FieldKind::Url | FieldKind::Email | FieldKind::Phone
        )
    }
}

/// Reads the entries of a map one key at a time and keeps what is left.
struct Reader {
    entries: Entries,
    /// In lenient mode (a newer `schema`): known keys that do not fit, kept
    /// as they were.
    rejected: Vec<(String, Value)>,
    strict: bool,
}

impl Reader {
    fn new(value: Value, strict: bool) -> Result<Self, Error> {
        let entries = value.into_map().map_err(|_| bad())?;
        Ok(Self {
            entries: Entries::new(entries),
            rejected: Vec::new(),
            strict,
        })
    }

    /// The parsed value of `key`, if there is one. A value that does not
    /// parse is an error in strict mode and goes to the unknown part in
    /// lenient mode.
    fn get<T>(
        &mut self,
        key: &str,
        parse: impl FnOnce(Value, bool) -> Result<T, Error>,
    ) -> Result<Option<T>, Error> {
        let Some(value) = self.entries.take(key) else {
            return Ok(None);
        };
        let backup = if self.strict {
            None
        } else {
            Some(value.clone())
        };
        match parse(value, self.strict) {
            Ok(t) => Ok(Some(t)),
            Err(e) => match backup {
                None => Err(e),
                Some(original) => {
                    self.rejected.push((key.to_owned(), original));
                    Ok(None)
                }
            },
        }
    }

    /// Like [`Reader::get`], but the key must be there in strict mode. In
    /// lenient mode a missing (or rejected) key gives `default`.
    fn require<T>(
        &mut self,
        key: &str,
        parse: impl FnOnce(Value, bool) -> Result<T, Error>,
        default: impl FnOnce() -> T,
    ) -> Result<T, Error> {
        match self.get(key, parse)? {
            Some(t) => Ok(t),
            None if self.strict => Err(bad()),
            None => Ok(default()),
        }
    }

    /// The unknown part, in the order it was read.
    fn finish(self) -> Vec<(String, Value)> {
        let mut extra = self.rejected;
        extra.extend(self.entries.into_rest());
        extra
    }
}

fn text(v: Value, _strict: bool) -> Result<String, Error> {
    v.into_text().map_err(|_| bad())
}

fn bytes(v: Value, _strict: bool) -> Result<Vec<u8>, Error> {
    v.into_bytes().map_err(|_| bad())
}

fn uint(v: Value, _strict: bool) -> Result<u64, Error> {
    v.as_u64().ok_or_else(bad)
}

fn boolean(v: Value, _strict: bool) -> Result<bool, Error> {
    match v {
        Value::Bool(b) => Ok(b),
        _ => Err(bad()),
    }
}

fn list<T>(
    v: Value,
    strict: bool,
    one: impl Fn(Value, bool) -> Result<T, Error>,
) -> Result<Vec<T>, Error> {
    let items = v.into_array().map_err(|_| bad())?;
    let mut out = Vec::with_capacity(items.len());
    for item in items {
        out.push(one(item, strict)?);
    }
    Ok(out)
}

fn put(map: &mut Vec<(String, Value)>, key: &str, value: Value) {
    map.push((key.to_owned(), value));
}

fn put_extra(map: &mut Vec<(String, Value)>, extra: &[(String, Value)]) {
    map.extend(extra.iter().cloned());
}

/// A custom field of an item.
#[derive(Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct Field {
    /// Identifies the field within the item.
    pub id: String,
    /// The label shown to the user.
    pub label: String,
    /// How the field is shown.
    pub kind: FieldKind,
    /// The value.
    pub value: String,
    /// Keys this version does not know.
    pub extra: Vec<(String, Value)>,
}

impl Field {
    fn from_value(v: Value, strict: bool) -> Result<Self, Error> {
        let mut r = Reader::new(v, strict)?;
        Ok(Self {
            id: r.require("id", text, String::new)?,
            label: r.require("label", text, String::new)?,
            kind: r.require(
                "kind",
                |v, s| text(v, s).map(FieldKind::from_text),
                || FieldKind::Text,
            )?,
            value: r.require("value", text, String::new)?,
            extra: r.finish(),
        })
    }

    fn to_value(&self) -> Value {
        let mut m = Vec::new();
        put(&mut m, "id", Value::text(self.id.clone()));
        put(&mut m, "label", Value::text(self.label.clone()));
        put(&mut m, "kind", Value::text(self.kind.as_str()));
        put(&mut m, "value", Value::text(self.value.clone()));
        put_extra(&mut m, &self.extra);
        Value::Map(m)
    }
}

/// A saved address of an item.
#[derive(Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct UrlEntry {
    /// The address.
    pub url: String,
    /// How it is matched against a page.
    pub matching: UrlMatch,
    /// Keys this version does not know.
    pub extra: Vec<(String, Value)>,
}

impl UrlEntry {
    fn from_value(v: Value, strict: bool) -> Result<Self, Error> {
        let mut r = Reader::new(v, strict)?;
        Ok(Self {
            url: r.require("url", text, String::new)?,
            matching: r
                .get("match", |v, s| text(v, s).map(UrlMatch::from_text))?
                .unwrap_or(UrlMatch::Host),
            extra: r.finish(),
        })
    }

    fn to_value(&self) -> Value {
        let mut m = Vec::new();
        put(&mut m, "url", Value::text(self.url.clone()));
        put(&mut m, "match", Value::text(self.matching.as_str()));
        put_extra(&mut m, &self.extra);
        Value::Map(m)
    }
}

/// The one-time-password setup of an item.
#[derive(Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct Totp {
    /// The `otpauth://` address, including the secret.
    pub uri: String,
    /// Keys this version does not know.
    pub extra: Vec<(String, Value)>,
}

impl Totp {
    fn from_value(v: Value, strict: bool) -> Result<Self, Error> {
        let mut r = Reader::new(v, strict)?;
        Ok(Self {
            uri: r.require("uri", text, String::new)?,
            extra: r.finish(),
        })
    }

    fn to_value(&self) -> Value {
        let mut m = Vec::new();
        put(&mut m, "uri", Value::text(self.uri.clone()));
        put_extra(&mut m, &self.extra);
        Value::Map(m)
    }
}

/// A passkey stored in an item (Fase 1 § 9.1).
#[derive(Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct Passkey {
    /// The credential id.
    pub cred_id: Vec<u8>,
    /// The relying party id.
    pub rp_id: String,
    /// The user handle.
    pub user_handle: Vec<u8>,
    /// The user name shown to the user.
    pub user_name: String,
    /// The private key, PKCS#8 DER (`priv` in the body).
    pub private_key: Vec<u8>,
    /// Always 0 for passkeys made by Ferret.
    pub sign_count: u64,
    /// When the passkey was made, unix milliseconds.
    pub created: u64,
    /// The PRF seed used when user verification was performed.
    pub prf_seed_uv: Option<Vec<u8>>,
    /// The PRF seed used when it was not.
    pub prf_seed_nouv: Option<Vec<u8>>,
    /// Keys this version does not know.
    pub extra: Vec<(String, Value)>,
}

impl Passkey {
    fn from_value(v: Value, strict: bool) -> Result<Self, Error> {
        let mut r = Reader::new(v, strict)?;
        Ok(Self {
            cred_id: r.require("cred_id", bytes, Vec::new)?,
            rp_id: r.require("rp_id", text, String::new)?,
            user_handle: r.require("user_handle", bytes, Vec::new)?,
            user_name: r.require("user_name", text, String::new)?,
            private_key: r.require("priv", bytes, Vec::new)?,
            sign_count: r.require("sign_count", uint, || 0)?,
            created: r.require("created", uint, || 0)?,
            prf_seed_uv: r.get("prf_seed_uv", bytes)?,
            prf_seed_nouv: r.get("prf_seed_nouv", bytes)?,
            extra: r.finish(),
        })
    }

    fn to_value(&self) -> Value {
        let mut m = Vec::new();
        put(&mut m, "cred_id", Value::Bytes(self.cred_id.clone()));
        put(&mut m, "rp_id", Value::text(self.rp_id.clone()));
        put(
            &mut m,
            "user_handle",
            Value::Bytes(self.user_handle.clone()),
        );
        put(&mut m, "user_name", Value::text(self.user_name.clone()));
        put(&mut m, "priv", Value::Bytes(self.private_key.clone()));
        put(&mut m, "sign_count", Value::uint(self.sign_count));
        put(&mut m, "created", Value::uint(self.created));
        if let Some(seed) = &self.prf_seed_uv {
            put(&mut m, "prf_seed_uv", Value::Bytes(seed.clone()));
        }
        if let Some(seed) = &self.prf_seed_nouv {
            put(&mut m, "prf_seed_nouv", Value::Bytes(seed.clone()));
        }
        put_extra(&mut m, &self.extra);
        Value::Map(m)
    }
}

/// The decrypted body of an item.
///
/// The body wipes its text and bytes when it is dropped. `Debug` shows
/// nothing of the contents.
#[derive(Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct ItemBody {
    /// The schema version; 1 is the one this version writes.
    pub schema: u64,
    /// What kind of item this is.
    pub item_type: ItemType,
    /// The name shown in lists.
    pub name: String,
    /// Custom fields.
    pub fields: Vec<Field>,
    /// Saved addresses.
    pub urls: Vec<UrlEntry>,
    /// The one-time-password setup.
    pub totp: Option<Totp>,
    /// The passkey.
    pub passkey: Option<Passkey>,
    /// Free-form notes.
    pub notes: Option<String>,
    /// When the item was made, unix milliseconds.
    pub created: u64,
    /// When the item was last changed, unix milliseconds.
    pub modified: u64,
    /// Whether the user marked the item as a favorite.
    pub favorite: bool,
    /// The name of the device that wrote the item (for the conflict view).
    pub device: Option<String>,
    /// Keys this version does not know, in the order they were read.
    pub extra: Vec<(String, Value)>,
}

redacted_debug!(Field, UrlEntry, Totp, Passkey, ItemBody);

impl ItemBody {
    /// A new, empty body of `schema` 1, made at `now_ms`.
    pub fn new(item_type: ItemType, name: impl Into<String>, now_ms: u64) -> Self {
        Self {
            schema: SCHEMA,
            item_type,
            name: name.into(),
            fields: Vec::new(),
            urls: Vec::new(),
            totp: None,
            passkey: None,
            notes: None,
            created: now_ms,
            modified: now_ms,
            favorite: false,
            device: None,
            extra: Vec::new(),
        }
    }

    /// Whether this body has a newer schema than the one this version
    /// writes. Such a body can be shown and never written.
    pub fn is_read_only(&self) -> bool {
        self.schema > SCHEMA
    }

    /// Reads a body from CBOR bytes.
    ///
    /// Fails with `Malformed(..)` if the bytes break the CBOR rules or, for
    /// `schema` 1, if a field is missing or has the wrong type. A `schema`
    /// above 1 is read leniently and marked read-only.
    ///
    /// Spec: Fase 1 § 5.2.
    pub fn from_cbor(bytes: &[u8]) -> Result<DecodedItem, Error> {
        Self::from_value(cbor::decode(bytes)?)
    }

    /// Reads a body from a CBOR tree.
    pub fn from_value(value: Value) -> Result<DecodedItem, Error> {
        let mut r = Reader::new(value, true)?;
        let schema = r.entries.take("schema").and_then(|v| v.as_u64());
        let schema = schema.filter(|s| *s >= SCHEMA).ok_or_else(bad)?;
        r.strict = schema == SCHEMA;
        let body = Self {
            schema,
            item_type: r.require(
                "type",
                |v, s| text(v, s).map(ItemType::from_text),
                || ItemType::Other(String::new()),
            )?,
            name: r.require("name", text, String::new)?,
            fields: r.require("fields", |v, s| list(v, s, Field::from_value), Vec::new)?,
            urls: r.require("urls", |v, s| list(v, s, UrlEntry::from_value), Vec::new)?,
            totp: r.get("totp", Totp::from_value)?,
            passkey: r.get("passkey", Passkey::from_value)?,
            notes: r.get("notes", text)?,
            created: r.require("created", uint, || 0)?,
            modified: r.require("modified", uint, || 0)?,
            favorite: r.require("favorite", boolean, || false)?,
            device: r.get("device", text)?,
            extra: r.finish(),
        };
        let read_only = body.is_read_only();
        Ok(DecodedItem { body, read_only })
    }

    /// The body as a CBOR tree: the known keys in schema order, then the
    /// unknown ones in the order they were read.
    pub fn to_value(&self) -> Value {
        let mut m = Vec::new();
        put(&mut m, "schema", Value::uint(self.schema));
        put(&mut m, "type", Value::text(self.item_type.as_str()));
        put(&mut m, "name", Value::text(self.name.clone()));
        put(
            &mut m,
            "fields",
            Value::Array(self.fields.iter().map(Field::to_value).collect()),
        );
        put(
            &mut m,
            "urls",
            Value::Array(self.urls.iter().map(UrlEntry::to_value).collect()),
        );
        if let Some(totp) = &self.totp {
            put(&mut m, "totp", totp.to_value());
        }
        if let Some(passkey) = &self.passkey {
            put(&mut m, "passkey", passkey.to_value());
        }
        if let Some(notes) = &self.notes {
            put(&mut m, "notes", Value::text(notes.clone()));
        }
        put(&mut m, "created", Value::uint(self.created));
        put(&mut m, "modified", Value::uint(self.modified));
        put(&mut m, "favorite", Value::Bool(self.favorite));
        if let Some(device) = &self.device {
            put(&mut m, "device", Value::text(device.clone()));
        }
        put_extra(&mut m, &self.extra);
        Value::Map(m)
    }

    /// The body as CBOR bytes, in a buffer that is wiped when dropped.
    ///
    /// Fails if the body breaks a limit of the decoder (more than 10 000
    /// entries, text over 64 KiB, nesting over 16) or has a key twice.
    pub fn to_cbor(&self) -> Result<Zeroizing<Vec<u8>>, Error> {
        cbor::encode(&self.to_value()).map(Zeroizing::new)
    }
}
