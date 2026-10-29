//! The manifest: the list of unlock methods and their generations.
//!
//! Spec: Fase 1 § 4.3 (the client remembers the highest `kek_generation`),
//! plan Appendix B and U5. The manifest is sealed like an item with
//! `item_id` = 16 zero bytes, `kind` = 2 and the key `K_meta`.
//!
//! ```text
//! { "v": 1, "vk_epoch": u64,
//!   "methods": [ { "t": u8 method_type, "id": bytes(16), "g": u64,
//!                  "c": bytes? } ] }
//! ```
//!
//! `c` is the credential id of a passkey (`t` = 3). It is what ties a
//! passkey's `kek_generation` floor to the credential: the manifest is
//! authenticated, so the floor never has to rely on a `method_id` to
//! credential mapping that the server supplies.
//!
//! Like the item body, every object keeps the keys it does not know and
//! writes them again after the known ones.

use crate::cbor::{self, Entries, Value};
use crate::error::{Error, MalformedKind};
use crate::ids::MethodId;

/// The manifest `v` this version reads and writes.
pub const MANIFEST_VERSION: u64 = 1;

const fn bad() -> Error {
    Error::Malformed(MalformedKind::ItemBody)
}

/// One unlock method in the manifest.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct ManifestEntry {
    /// The `method_type` byte (Fase 1 § 3.1).
    pub method_type: u8,
    /// The method's id.
    pub method_id: MethodId,
    /// The current `kek_generation` of the method.
    pub kek_generation: u64,
    /// The credential id of a passkey method (`t` = 3), if the entry states
    /// it.
    pub credential_id: Option<Vec<u8>>,
    /// Keys this version does not know, in the order they were read.
    pub extra: Vec<(String, Value)>,
}

impl ManifestEntry {
    /// An entry without unknown keys and without a credential id.
    pub fn new(method_type: u8, method_id: MethodId, kek_generation: u64) -> Self {
        Self {
            method_type,
            method_id,
            kek_generation,
            credential_id: None,
            extra: Vec::new(),
        }
    }

    /// The entry of a passkey method: `method_type` 3 with its credential
    /// id.
    pub fn passkey(method_id: MethodId, kek_generation: u64, credential_id: Vec<u8>) -> Self {
        Self {
            method_type: 3,
            method_id,
            kek_generation,
            credential_id: Some(credential_id),
            extra: Vec::new(),
        }
    }

    fn from_value(value: Value) -> Result<Self, Error> {
        let mut e = Entries::new(value.into_map().map_err(|_| bad())?);
        let method_type = e
            .take("t")
            .and_then(|v| v.as_u64())
            .and_then(|n| u8::try_from(n).ok())
            .ok_or_else(bad)?;
        let id = e
            .take("id")
            .ok_or_else(bad)?
            .into_bytes()
            .map_err(|_| bad())?;
        let method_id = MethodId::from_bytes(id.as_slice().try_into().map_err(|_| bad())?);
        let kek_generation = e.take("g").and_then(|v| v.as_u64()).ok_or_else(bad)?;
        let credential_id = match e.take("c") {
            None => None,
            Some(v) => Some(v.into_bytes().map_err(|_| bad())?),
        };
        Ok(Self {
            method_type,
            method_id,
            kek_generation,
            credential_id,
            extra: e.into_rest(),
        })
    }

    fn to_value(&self) -> Value {
        let mut m = vec![
            ("t".to_owned(), Value::uint(u64::from(self.method_type))),
            (
                "id".to_owned(),
                Value::Bytes(self.method_id.as_bytes().to_vec()),
            ),
            ("g".to_owned(), Value::uint(self.kek_generation)),
        ];
        if let Some(credential_id) = &self.credential_id {
            m.push(("c".to_owned(), Value::Bytes(credential_id.clone())));
        }
        m.extend(self.extra.iter().cloned());
        Value::Map(m)
    }
}

/// The manifest of a vault.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Manifest {
    /// The epoch of the vault key the manifest was made for.
    pub vk_epoch: u64,
    /// The unlock methods.
    pub methods: Vec<ManifestEntry>,
    /// Keys this version does not know, in the order they were read.
    pub extra: Vec<(String, Value)>,
}

impl Manifest {
    /// A manifest without unknown keys.
    pub fn new(vk_epoch: u64, methods: Vec<ManifestEntry>) -> Self {
        Self {
            vk_epoch,
            methods,
            extra: Vec::new(),
        }
    }

    /// Reads a manifest from CBOR bytes. A `v` other than 1 is
    /// `Error::Unsupported`.
    pub fn from_cbor(bytes: &[u8]) -> Result<Self, Error> {
        Self::from_value(cbor::decode(bytes)?)
    }

    /// Reads a manifest from a CBOR tree.
    pub fn from_value(value: Value) -> Result<Self, Error> {
        let mut e = Entries::new(value.into_map().map_err(|_| bad())?);
        let v = e.take("v").and_then(|v| v.as_u64()).ok_or_else(bad)?;
        if v != MANIFEST_VERSION {
            return Err(Error::Unsupported);
        }
        let vk_epoch = e
            .take("vk_epoch")
            .and_then(|v| v.as_u64())
            .ok_or_else(bad)?;
        let items = e
            .take("methods")
            .ok_or_else(bad)?
            .into_array()
            .map_err(|_| bad())?;
        let mut methods = Vec::with_capacity(items.len());
        for item in items {
            methods.push(ManifestEntry::from_value(item)?);
        }
        Ok(Self {
            vk_epoch,
            methods,
            extra: e.into_rest(),
        })
    }

    /// The manifest as a CBOR tree.
    pub fn to_value(&self) -> Value {
        let mut m = vec![
            ("v".to_owned(), Value::uint(MANIFEST_VERSION)),
            ("vk_epoch".to_owned(), Value::uint(self.vk_epoch)),
            (
                "methods".to_owned(),
                Value::Array(self.methods.iter().map(ManifestEntry::to_value).collect()),
            ),
        ];
        m.extend(self.extra.iter().cloned());
        Value::Map(m)
    }

    /// The manifest as CBOR bytes.
    pub fn to_cbor(&self) -> Result<Vec<u8>, Error> {
        cbor::encode(&self.to_value())
    }
}
