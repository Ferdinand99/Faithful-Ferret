//! Conversion between JavaScript values and the core's types.
//!
//! Binary values are `Uint8Array`s and numbers are JavaScript numbers that
//! must be safe integers (at most 2^53), never strings and never floats. An
//! object with a key this binding does not know is refused (see [`Shape`]), so
//! a misspelled name cannot silently be ignored. Every conversion failure is
//! `invalid_input` and says nothing about the value.

use crate::error::{Fail, Res};
use ferret_core::{
    AccountId, Error, KsfProfile, ManifestRow, Method, MethodId, MethodKey, Pinned, SealedItem,
    VaultContext, VaultId, WrapRecord,
};
use serde::de::{self, DeserializeOwned, Deserializer, Visitor};
use serde::{Deserialize, Serialize, Serializer};
use std::fmt;
use wasm_bindgen::{JsCast, JsValue};

/// The largest integer that a JavaScript number holds exactly.
pub(crate) const MAX_SAFE: f64 = 9_007_199_254_740_992.0;

// ---------------------------------------------------------------- values

/// The keys an object may have. `serde-wasm-bindgen` reads the fields a
/// struct declares and ignores every other key of the JavaScript object, so
/// `deny_unknown_fields` does not see them. A key that is not known is
/// therefore refused here, before the value is read: a misspelled name, or a
/// field that does not exist (a private key in a draft), is `invalid_input`
/// and never silently dropped.
pub(crate) enum Shape {
    /// Anything (a number, a string, bytes); `serde` judges the type.
    Any,
    /// An object with these keys at most, each with its shape.
    Obj(&'static [(&'static str, &'static Shape)]),
    /// An array of values of one shape.
    List(&'static Shape),
}

/// A type that is read from a JavaScript object and knows its keys.
pub(crate) trait Shaped {
    const SHAPE: Shape;
}

pub(crate) const ANY: Shape = Shape::Any;

fn check(v: &JsValue, shape: &Shape) -> Res<()> {
    match shape {
        Shape::Any => Ok(()),
        Shape::List(inner) => {
            if let Some(list) = v.dyn_ref::<js_sys::Array>() {
                for item in list.iter() {
                    check(&item, inner)?;
                }
            }
            Ok(())
        }
        Shape::Obj(fields) => {
            if v.is_null() || v.is_undefined() || js_sys::Array::is_array(v) {
                return Ok(());
            }
            let Some(obj) = v.dyn_ref::<js_sys::Object>() else {
                return Ok(());
            };
            if obj.is_instance_of::<js_sys::Uint8Array>() {
                return Ok(());
            }
            for key in js_sys::Object::keys(obj).iter() {
                let name = key.as_string().ok_or(Fail::Input)?;
                let Some((_, inner)) = fields.iter().find(|(k, _)| *k == name) else {
                    return Err(Fail::Input);
                };
                let value = js_sys::Reflect::get(obj, &key).map_err(|_| Fail::Input)?;
                check(&value, inner)?;
            }
            Ok(())
        }
    }
}

/// Reads a JavaScript value into `T`; an object with a key `T` does not
/// have is `invalid_input`.
pub(crate) fn from_js<T: DeserializeOwned + Shaped>(v: JsValue) -> Res<T> {
    check(&v, &T::SHAPE)?;
    serde_wasm_bindgen::from_value(v).map_err(|_| Fail::Input)
}

/// Reads a JavaScript array of `T`.
pub(crate) fn from_js_list<T: DeserializeOwned + Shaped>(v: JsValue) -> Res<Vec<T>> {
    check(&v, &Shape::List(&T::SHAPE))?;
    serde_wasm_bindgen::from_value(v).map_err(|_| Fail::Input)
}

/// Writes `v` as a JavaScript value (missing values are `null`).
pub(crate) fn to_js<T: Serialize + ?Sized>(v: &T) -> Res<JsValue> {
    let serializer = serde_wasm_bindgen::Serializer::new().serialize_missing_as_null(true);
    v.serialize(&serializer).map_err(|_| Fail::Input)
}

/// `bytes` as an exact-size array.
pub(crate) fn arr<const N: usize>(bytes: &[u8]) -> Res<[u8; N]> {
    bytes.try_into().map_err(|_| Fail::Input)
}

/// A JavaScript number as a `u64`: finite, a whole number, from 0 to 2^53.
pub(crate) fn js_u64(v: f64) -> Res<u64> {
    if v.is_finite() && (0.0..=MAX_SAFE).contains(&v) && v.fract() == 0.0 {
        Ok(v as u64)
    } else {
        Err(Fail::Input)
    }
}

/// A time in seconds or milliseconds from JavaScript (`Date.now() / 1000`
/// may have a fraction): finite, from 0 to 2^53; the fraction is dropped.
pub(crate) fn js_time(v: f64) -> Res<u64> {
    if v.is_finite() && (0.0..=MAX_SAFE).contains(&v) {
        Ok(v.floor() as u64)
    } else {
        Err(Fail::Input)
    }
}

// ----------------------------------------------------------- serde bytes

struct BytesVisitor;

impl<'de> Visitor<'de> for BytesVisitor {
    type Value = Vec<u8>;

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("a Uint8Array")
    }

    fn visit_bytes<E: de::Error>(self, v: &[u8]) -> Result<Vec<u8>, E> {
        Ok(v.to_vec())
    }

    fn visit_byte_buf<E: de::Error>(self, v: Vec<u8>) -> Result<Vec<u8>, E> {
        Ok(v)
    }
}

/// `Vec<u8>` as a `Uint8Array`.
pub(crate) mod bytes {
    use super::*;

    pub(crate) fn serialize<S: Serializer>(v: &[u8], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_bytes(v)
    }

    pub(crate) fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        d.deserialize_byte_buf(BytesVisitor)
    }
}

/// `Option<Vec<u8>>` as a `Uint8Array` or `null`/`undefined`.
pub(crate) mod opt_bytes {
    use super::*;

    pub(crate) fn serialize<S: Serializer>(v: &Option<Vec<u8>>, s: S) -> Result<S::Ok, S::Error> {
        match v {
            Some(b) => s.serialize_bytes(b),
            None => s.serialize_none(),
        }
    }

    pub(crate) fn deserialize<'de, D: Deserializer<'de>>(
        d: D,
    ) -> Result<Option<Vec<u8>>, D::Error> {
        struct V;
        impl<'de> Visitor<'de> for V {
            type Value = Option<Vec<u8>>;
            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("a Uint8Array or null")
            }
            fn visit_none<E: de::Error>(self) -> Result<Self::Value, E> {
                Ok(None)
            }
            fn visit_unit<E: de::Error>(self) -> Result<Self::Value, E> {
                Ok(None)
            }
            fn visit_some<D2: Deserializer<'de>>(self, d: D2) -> Result<Self::Value, D2::Error> {
                d.deserialize_byte_buf(BytesVisitor).map(Some)
            }
        }
        d.deserialize_option(V)
    }
}

macro_rules! fixed_bytes {
    ($name:ident, $opt:ident, $n:expr) => {
        /// A byte array of fixed size as a `Uint8Array`.
        pub(crate) mod $name {
            use super::*;

            pub(crate) fn serialize<S: Serializer>(v: &[u8; $n], s: S) -> Result<S::Ok, S::Error> {
                s.serialize_bytes(v)
            }

            pub(crate) fn deserialize<'de, D: Deserializer<'de>>(
                d: D,
            ) -> Result<[u8; $n], D::Error> {
                let v = d.deserialize_byte_buf(BytesVisitor)?;
                <[u8; $n]>::try_from(v).map_err(|_| de::Error::custom("length"))
            }
        }

        /// An optional byte array of fixed size.
        pub(crate) mod $opt {
            use super::*;

            pub(crate) fn serialize<S: Serializer>(
                v: &Option<[u8; $n]>,
                s: S,
            ) -> Result<S::Ok, S::Error> {
                match v {
                    Some(b) => s.serialize_bytes(b),
                    None => s.serialize_none(),
                }
            }

            pub(crate) fn deserialize<'de, D: Deserializer<'de>>(
                d: D,
            ) -> Result<Option<[u8; $n]>, D::Error> {
                match super::opt_bytes::deserialize(d)? {
                    None => Ok(None),
                    Some(v) => <[u8; $n]>::try_from(v)
                        .map(Some)
                        .map_err(|_| de::Error::custom("length")),
                }
            }
        }
    };
}

fixed_bytes!(b16, opt_b16, 16);
fixed_bytes!(b32, opt_b32, 32);

// ------------------------------------------------------------- the DTOs

/// Account, vault and epoch.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct CtxDto {
    #[serde(with = "b16")]
    pub(crate) account_id: [u8; 16],
    #[serde(with = "b16")]
    pub(crate) vault_id: [u8; 16],
    pub(crate) vk_epoch: u64,
}

impl CtxDto {
    pub(crate) fn core(&self) -> VaultContext {
        VaultContext {
            account_id: AccountId::from_bytes(self.account_id),
            vault_id: VaultId::from_bytes(self.vault_id),
            vk_epoch: self.vk_epoch,
        }
    }
}

/// An unlock method as the vectors write it.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct MethodDto {
    pub(crate) r#type: String,
    #[serde(default)]
    pub(crate) ksf_profile: Option<u32>,
    #[serde(default, with = "opt_bytes")]
    pub(crate) credential_id: Option<Vec<u8>>,
    #[serde(default, with = "opt_b32")]
    pub(crate) prf_salt: Option<[u8; 32]>,
    #[serde(default, with = "opt_b16")]
    pub(crate) device_salt: Option<[u8; 16]>,
}

impl MethodDto {
    pub(crate) fn core(&self) -> Res<Method> {
        Ok(match self.r#type.as_str() {
            "password" => Method::Password {
                ksf: KsfProfile::from_wire(self.ksf_profile.ok_or(Fail::Input)?)?,
            },
            "recovery" => Method::Recovery,
            "prf" => Method::Prf {
                credential_id: self.credential_id.clone().ok_or(Fail::Input)?,
                prf_salt: self.prf_salt.ok_or(Fail::Input)?,
            },
            "pin" => Method::Pin {
                device_salt: self.device_salt.ok_or(Fail::Input)?,
            },
            "device" => Method::Device,
            _ => return Err(Fail::Input),
        })
    }

    pub(crate) fn of(method: &Method) -> Self {
        let mut dto = Self {
            r#type: String::new(),
            ksf_profile: None,
            credential_id: None,
            prf_salt: None,
            device_salt: None,
        };
        match method {
            Method::Password { ksf } => {
                dto.r#type = "password".into();
                dto.ksf_profile = Some(u32::from(ksf.number()));
            }
            Method::Recovery => dto.r#type = "recovery".into(),
            Method::Prf {
                credential_id,
                prf_salt,
            } => {
                dto.r#type = "prf".into();
                dto.credential_id = Some(credential_id.clone());
                dto.prf_salt = Some(*prf_salt);
            }
            Method::Pin { device_salt } => {
                dto.r#type = "pin".into();
                dto.device_salt = Some(*device_salt);
            }
            Method::Device => dto.r#type = "device".into(),
            // `Method` is `#[non_exhaustive]` in spirit only; an unknown one
            // cannot be built by this version.
        }
        dto
    }
}

/// A stored wrap of the vault key.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct WrapDto {
    #[serde(with = "b16")]
    pub(crate) method_id: [u8; 16],
    pub(crate) kek_generation: u64,
    pub(crate) method: MethodDto,
    #[serde(with = "bytes")]
    pub(crate) wrap: Vec<u8>,
}

impl WrapDto {
    pub(crate) fn core(&self) -> Res<WrapRecord> {
        Ok(WrapRecord {
            method_id: MethodId::from_bytes(self.method_id),
            kek_generation: self.kek_generation,
            method: self.method.core()?,
            wrap: self.wrap.clone(),
        })
    }

    pub(crate) fn of(rec: &WrapRecord) -> Self {
        Self {
            method_id: *rec.method_id.as_bytes(),
            kek_generation: rec.kek_generation,
            method: MethodDto::of(&rec.method),
            wrap: rec.wrap.clone(),
        }
    }
}

/// A row the server holds: revision, envelope and tag.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RowDto {
    pub(crate) rev: u64,
    #[serde(with = "bytes")]
    pub(crate) envelope: Vec<u8>,
    #[serde(with = "b32")]
    pub(crate) tag: [u8; 32],
}

impl RowDto {
    pub(crate) fn core(&self) -> ManifestRow<'_> {
        ManifestRow {
            rev: self.rev,
            envelope: &self.envelope,
            tag: &self.tag,
        }
    }
}

/// An item or manifest the binding has sealed.
#[derive(Serialize)]
pub(crate) struct SealedDto {
    pub(crate) rev: u64,
    #[serde(with = "bytes")]
    pub(crate) envelope: Vec<u8>,
    #[serde(with = "b32")]
    pub(crate) tag: [u8; 32],
}

impl SealedDto {
    pub(crate) fn of(s: &SealedItem) -> Self {
        Self {
            rev: s.rev,
            envelope: s.envelope.clone(),
            tag: s.tag,
        }
    }
}

/// A checkpoint.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct CheckpointDto {
    pub(crate) seq: u64,
    #[serde(with = "b32")]
    pub(crate) digest: [u8; 32],
    #[serde(with = "b32")]
    pub(crate) mac: [u8; 32],
    #[serde(with = "bytes")]
    pub(crate) entries: Vec<u8>,
}

/// One pinned generation floor.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct FloorDto {
    pub(crate) r#type: String,
    #[serde(default, with = "opt_bytes")]
    pub(crate) credential_id: Option<Vec<u8>>,
    pub(crate) generation: u64,
}

/// The pinned record of an account on this device. Not secret: the client
/// stores it as it stores any setting.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct PinnedDto {
    pub(crate) server_url: String,
    #[serde(with = "b16")]
    pub(crate) account_id: [u8; 16],
    #[serde(with = "b16")]
    pub(crate) vault_id: [u8; 16],
    pub(crate) ksf_profile: u8,
    pub(crate) kek_generation_max: Vec<FloorDto>,
    pub(crate) vk_epoch_max: u64,
    pub(crate) sk_bit: bool,
    #[serde(with = "b32")]
    pub(crate) pk_a: [u8; 32],
    #[serde(default, with = "opt_b32")]
    pub(crate) server_public_key: Option<[u8; 32]>,
}

impl PinnedDto {
    pub(crate) fn core(&self) -> Res<Pinned> {
        let mut floors = Vec::with_capacity(self.kek_generation_max.len());
        for f in &self.kek_generation_max {
            let key = match f.r#type.as_str() {
                "password" => MethodKey::Password,
                "recovery" => MethodKey::Recovery,
                "prf" => MethodKey::Prf(f.credential_id.clone().ok_or(Fail::Input)?),
                _ => return Err(Fail::Input),
            };
            floors.push((key, f.generation));
        }
        let pinned = Pinned {
            server_url: self.server_url.clone(),
            account_id: AccountId::from_bytes(self.account_id),
            vault_id: VaultId::from_bytes(self.vault_id),
            ksf_profile: self.ksf_profile,
            kek_generation_max: floors,
            vk_epoch_max: self.vk_epoch_max,
            sk_bit: self.sk_bit,
            pk_a: self.pk_a,
            server_public_key: self.server_public_key,
        };
        pinned.validate()?;
        Ok(pinned)
    }

    pub(crate) fn of(p: &Pinned) -> Self {
        Self {
            server_url: p.server_url.clone(),
            account_id: *p.account_id.as_bytes(),
            vault_id: *p.vault_id.as_bytes(),
            ksf_profile: p.ksf_profile,
            kek_generation_max: p
                .kek_generation_max
                .iter()
                .map(|(key, generation)| {
                    let (r#type, credential_id) = match key {
                        MethodKey::Password => ("password", None),
                        MethodKey::Recovery => ("recovery", None),
                        MethodKey::Prf(id) => ("prf", Some(id.clone())),
                    };
                    FloorDto {
                        r#type: r#type.into(),
                        credential_id,
                        generation: *generation,
                    }
                })
                .collect(),
            vk_epoch_max: p.vk_epoch_max,
            sk_bit: p.sk_bit,
            pk_a: p.pk_a,
            server_public_key: p.server_public_key,
        }
    }
}

/// What the device knows about the account when it unlocks, always stated:
/// there is no default. `kind` is `"first_use"` (a device that has never
/// unlocked this account: trust on first use, with the SK bit the user
/// answered) or `"pinned"` (the record of this device).
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct PinArg {
    pub(crate) kind: String,
    /// `first_use` only: whether the account has a secret key.
    #[serde(default)]
    pub(crate) sk_bit: Option<bool>,
    /// The OPAQUE server key the caller has seen, where no login shows one
    /// (an unlock with the recovery key or a passkey).
    #[serde(default, with = "opt_b32")]
    pub(crate) server_public_key: Option<[u8; 32]>,
    /// `pinned` only: the record.
    #[serde(default)]
    pub(crate) record: Option<PinnedDto>,
}

/// A pin state, checked: either trust on first use or a validated record.
pub(crate) enum Pin {
    FirstUse {
        sk_bit: Option<bool>,
        server_public_key: Option<[u8; 32]>,
    },
    Pinned {
        record: Box<Pinned>,
        server_public_key: Option<[u8; 32]>,
    },
}

impl PinArg {
    /// Reads the pin state. A value that is neither of the two kinds, a
    /// `first_use` with a record or a `pinned` without one is `invalid_input`.
    pub(crate) fn core(self) -> Res<Pin> {
        match (self.kind.as_str(), self.record) {
            ("first_use", None) => Ok(Pin::FirstUse {
                sk_bit: self.sk_bit,
                server_public_key: self.server_public_key,
            }),
            ("pinned", Some(record)) if self.sk_bit.is_none() => Ok(Pin::Pinned {
                record: Box::new(record.core()?),
                server_public_key: self.server_public_key,
            }),
            _ => Err(Fail::Input),
        }
    }
}

impl Pin {
    /// The core's pin state.
    pub(crate) fn state(&self) -> ferret_core::PinState<'_> {
        match self {
            Pin::FirstUse { .. } => ferret_core::PinState::FirstUse,
            Pin::Pinned { record, .. } => ferret_core::PinState::Pinned(record),
        }
    }
}

/// The ids of a new account.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct IdsDto {
    #[serde(with = "b16")]
    pub(crate) account_id: [u8; 16],
    #[serde(with = "b16")]
    pub(crate) vault_id: [u8; 16],
    #[serde(with = "b16")]
    pub(crate) password_method_id: [u8; 16],
    #[serde(with = "b16")]
    pub(crate) recovery_method_id: [u8; 16],
}

/// Argon2id parameters.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct KdfDto {
    pub(crate) m_kib: u32,
    pub(crate) t: u32,
    pub(crate) p: u32,
}

impl KdfDto {
    pub(crate) fn core(&self) -> ferret_core::KdfParams {
        ferret_core::KdfParams {
            m_kib: self.m_kib,
            t: self.t,
            p: self.p,
        }
    }

    pub(crate) fn of(k: ferret_core::KdfParams) -> Self {
        Self {
            m_kib: k.m_kib,
            t: k.t,
            p: k.p,
        }
    }
}

/// The error code of a failed core call as a [`Fail`], for `?` in closures.
pub(crate) fn core<T>(r: Result<T, Error>) -> Res<T> {
    r.map_err(Fail::from)
}

// ------------------------------------------------------------- the shapes

impl Shaped for CtxDto {
    const SHAPE: Shape =
        Shape::Obj(&[("account_id", &ANY), ("vault_id", &ANY), ("vk_epoch", &ANY)]);
}

impl Shaped for MethodDto {
    const SHAPE: Shape = Shape::Obj(&[
        ("type", &ANY),
        ("ksf_profile", &ANY),
        ("credential_id", &ANY),
        ("prf_salt", &ANY),
        ("device_salt", &ANY),
    ]);
}

impl Shaped for WrapDto {
    const SHAPE: Shape = Shape::Obj(&[
        ("method_id", &ANY),
        ("kek_generation", &ANY),
        ("method", &MethodDto::SHAPE),
        ("wrap", &ANY),
    ]);
}

impl Shaped for RowDto {
    const SHAPE: Shape = Shape::Obj(&[("rev", &ANY), ("envelope", &ANY), ("tag", &ANY)]);
}

impl Shaped for CheckpointDto {
    const SHAPE: Shape = Shape::Obj(&[
        ("seq", &ANY),
        ("digest", &ANY),
        ("mac", &ANY),
        ("entries", &ANY),
    ]);
}

impl Shaped for FloorDto {
    const SHAPE: Shape = Shape::Obj(&[
        ("type", &ANY),
        ("credential_id", &ANY),
        ("generation", &ANY),
    ]);
}

impl Shaped for PinnedDto {
    const SHAPE: Shape = Shape::Obj(&[
        ("server_url", &ANY),
        ("account_id", &ANY),
        ("vault_id", &ANY),
        ("ksf_profile", &ANY),
        ("kek_generation_max", &Shape::List(&FloorDto::SHAPE)),
        ("vk_epoch_max", &ANY),
        ("sk_bit", &ANY),
        ("pk_a", &ANY),
        ("server_public_key", &ANY),
    ]);
}

impl Shaped for PinArg {
    const SHAPE: Shape = Shape::Obj(&[
        ("kind", &ANY),
        ("sk_bit", &ANY),
        ("server_public_key", &ANY),
        ("record", &PinnedDto::SHAPE),
    ]);
}

impl Shaped for IdsDto {
    const SHAPE: Shape = Shape::Obj(&[
        ("account_id", &ANY),
        ("vault_id", &ANY),
        ("password_method_id", &ANY),
        ("recovery_method_id", &ANY),
    ]);
}

impl Shaped for KdfDto {
    const SHAPE: Shape = Shape::Obj(&[("m_kib", &ANY), ("t", &ANY), ("p", &ANY)]);
}
