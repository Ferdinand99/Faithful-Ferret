//! The encrypted export file (`.ferretexport`) and the plaintext exports.
//!
//! Spec: Fase 1 § 6.4 and finding F-27; plan U15 (memory ceiling) and U18
//! (file layout).
//!
//! ```text
//! header  = cbor{ v: 1, suite: 1, kdf: { salt, m, t, p }, created_at }
//! file    = header ‖ ek_wrap ‖ body
//!
//! K_exp   = HKDF(salt = TLV[label="ferret/v1/export"],
//!                ikm  = Argon2id(export_pw, salt, m, t, p, 32),
//!                info = "ferret/v1/export/key")
//! EK      = 32 random bytes
//! ek_wrap = AEAD(K_exp, nonce, EK,
//!                aad = TLV[label="ferret/v1/export/ek", header])        72 bytes
//! body    = AEAD(EK, nonce, cbor{ v: 1, items: [ { id, body } ] },
//!                aad = TLV[label="ferret/v1/export/body", header])
//! ```
//!
//! * The header is one CBOR element, stored exactly as written. The reader
//!   learns where it ends from the decoder ([`parse_export_header`] returns
//!   the number of bytes used) and uses **those bytes, as they stand in the
//!   file**, as the `header` field of both AADs. They are never encoded
//!   again, so a header that is a different but equivalent CBOR encoding
//!   (another map order, a longer integer head) is a different AAD and does
//!   not open. The whole header, the Argon2id parameters included, is
//!   therefore bound to both ciphertexts (F-27).
//! * `m` is in KiB, like [`KdfParams::m_kib`] and the `kdf` TLV field. `salt`
//!   is exactly 16 bytes. The header holds no other key: an unknown key is a
//!   [`MalformedKind::ExportHeader`] error, because a later format changes
//!   `v`.
//! * An export is written with [`EXPORT_KDF`] (256 MiB, 3 passes, 1 lane).
//!   [`export_encrypt`] and [`import_decrypt`] check the parameters against
//!   the floor and ceiling of Fase 1 § 4.1 (the ceiling for memory is
//!   512 MiB, plan U15) **before** Argon2id runs or any memory is reserved,
//!   so a hostile file cannot make the reader allocate or compute more than
//!   the ceiling allows. The only way past the bounds is the `test-support`
//!   feature.
//! * The body has no padding and is at most [`MAX_BODY_LEN`] (128 MiB). It
//!   follows the CBOR rules of Fase 1 § 5.2, so an export holds at most
//!   10 000 items.
//! * Every authentication failure (wrong password, any changed byte of the
//!   header, `ek_wrap` or body) is the single [`Error::Decrypt`]. Structure
//!   errors that do not depend on a secret are `Malformed(ExportHeader)`,
//!   `Unsupported` (another `v` or `suite`), `KdfOutOfRange` and `TooLarge`.
//!
//! The export password is an [`ExportPassword`]: `ExportPassword::new` when a
//! file is written (at least 12 characters, not equal to the master
//! password), `ExportPassword::for_open` when one is read (no minimum).

mod plain;

use crate::cbor::{self, Entries, Value};
use crate::error::{Error, MalformedKind};
use crate::ids::ItemId;
use crate::item::ItemBody;
use crate::item::body::SCHEMA;
use crate::prim::aead::{OVERHEAD, aead_open, aead_seal};
use crate::prim::argon2::argon2id;
use crate::prim::hkdf::hkdf_sha256;
use crate::prim::{KdfParams, check_kdf_params};
use crate::rng::SecureRng;
use crate::secret::ExportContentKey;
use crate::text::ExportPassword;
use crate::tlv::{SUITE, Tlv, tag};
use std::collections::BTreeSet;
use zeroize::Zeroizing;

pub use plain::{PlainExportOptions, export_plain_csv, export_plain_json};

/// The parameters an export is written with: 256 MiB, 3 passes, 1 lane.
///
/// Stronger than the login profile, because the file can lie with other
/// people and be attacked offline. Spec: Fase 1 § 6.4.
pub const EXPORT_KDF: KdfParams = KdfParams {
    m_kib: 262_144,
    t: 3,
    p: 1,
};

/// Length of the salt in the header.
pub const SALT_LEN: usize = 16;

/// Length of `ek_wrap`: `nonce (24) ‖ EK (32) ‖ tag (16)`.
pub const EK_WRAP_LEN: usize = 72;

/// The largest body (nonce, ciphertext and tag) that is written or read:
/// 128 MiB. Plan U18.
pub const MAX_BODY_LEN: usize = 128 * 1024 * 1024;

/// The most items in one export (the array limit of Fase 1 § 5.2).
pub const MAX_ITEMS: usize = cbor::MAX_ITEMS as usize;

/// The `v` of the header and of the body.
const FORMAT_VERSION: u64 = 1;

/// Label of the HKDF salt. Spec: Fase 1 § 6.4.
const LABEL_EXPORT: &str = "ferret/v1/export";
/// Label of the AAD of `ek_wrap`. Spec: Fase 1 § 6.4.
const LABEL_EK: &str = "ferret/v1/export/ek";
/// Label of the AAD of the body. Spec: Fase 1 § 6.4.
const LABEL_BODY: &str = "ferret/v1/export/body";
/// `info` of `K_exp`. Spec: Fase 1 § 6.4.
const INFO_KEY: &[u8] = b"ferret/v1/export/key";

fn bad() -> Error {
    Error::Malformed(MalformedKind::ExportHeader)
}

fn bad_body() -> Error {
    Error::Malformed(MalformedKind::ItemBody)
}

/// One item of an export: its id and its decrypted body.
///
/// The body keeps the fields this version does not know, so they survive an
/// export and an import unchanged.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct ExportItem {
    /// The item's id.
    pub item_id: ItemId,
    /// The body.
    pub body: ItemBody,
}

/// The header of an export file, read but not yet checked against the floor
/// and ceiling (see [`import_decrypt`]).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct ExportHeader {
    /// When the file was written, unix milliseconds. Not secret.
    pub created_at: u64,
    /// The Argon2id parameters.
    pub kdf: KdfParams,
    /// The Argon2id salt.
    pub salt: [u8; SALT_LEN],
}

/// How Argon2id is run and which parameters are accepted. In production this
/// is the checked path only; the `test-support` feature adds one that
/// accepts small parameters, so the vectors can use them.
#[derive(Clone, Copy)]
pub(crate) struct KdfRunner {
    pub(crate) gate: fn(KdfParams) -> Result<KdfParams, Error>,
    pub(crate) run: KdfFn,
}

/// `Argon2id(password, salt, params, out)`.
pub(crate) type KdfFn = fn(&[u8], &[u8], KdfParams, &mut [u8]) -> Result<(), Error>;

impl KdfRunner {
    /// The floor and ceiling of Fase 1 § 4.1 and Argon2id behind them.
    pub(crate) const PRODUCTION: KdfRunner = KdfRunner {
        gate: check_kdf_params,
        run: argon2id,
    };
}

// ------------------------------------------------------------------ header

/// Encodes the header: `{ "v": 1, "suite": 1, "kdf": { "salt", "m", "t",
/// "p" }, "created_at" }`, in that order, shortest integer heads.
///
/// Spec: Fase 1 § 6.4.
fn encode_header(salt: &[u8; SALT_LEN], kdf: KdfParams, created_at: u64) -> Result<Vec<u8>, Error> {
    let header = Value::Map(vec![
        ("v".into(), Value::uint(FORMAT_VERSION)),
        ("suite".into(), Value::uint(u64::from(SUITE))),
        (
            "kdf".into(),
            Value::Map(vec![
                ("salt".into(), Value::Bytes(salt.to_vec())),
                ("m".into(), Value::uint(u64::from(kdf.m_kib))),
                ("t".into(), Value::uint(u64::from(kdf.t))),
                ("p".into(), Value::uint(u64::from(kdf.p))),
            ]),
        ),
        ("created_at".into(), Value::uint(created_at)),
    ]);
    cbor::encode(&header)
}

/// A map with exactly the given keys, taken out in the order asked for.
fn exact_map<const N: usize>(value: Value, keys: [&str; N]) -> Result<[Value; N], Error> {
    let entries = value.into_map().map_err(|_| bad())?;
    let mut entries = Entries::new(entries);
    let mut out = Vec::with_capacity(N);
    for key in keys {
        out.push(entries.take(key).ok_or_else(bad)?);
    }
    if !entries.into_rest().is_empty() {
        return Err(bad());
    }
    out.try_into().map_err(|_| bad())
}

/// An `m`, `t` or `p` of the header: an integer, and one that does not fit
/// 32 bits is out of range (it is above the ceiling whatever the ceiling is).
fn kdf_param(value: &Value) -> Result<u32, Error> {
    match value {
        Value::Int(n) => u32::try_from(*n).map_err(|_| Error::KdfOutOfRange),
        _ => Err(bad()),
    }
}

/// Reads the header at the start of `file` and reports how many bytes it
/// took. The bytes `file[..used]` are the `header` of both AADs.
///
/// Checks only the structure: the keys and types, `v` and `suite` (another
/// value is [`Error::Unsupported`]), and that `m`, `t` and `p` fit 32 bits.
/// The floor and ceiling are checked by [`import_decrypt`], so that a caller
/// can show a header (its date, say) without a password.
///
/// Spec: Fase 1 § 6.4 (the header is one CBOR element stored as written).
pub fn parse_export_header(file: &[u8]) -> Result<(ExportHeader, usize), Error> {
    let (value, used) = cbor::decode_prefix(file).map_err(|_| bad())?;
    let [v, suite, kdf, created_at] = exact_map(value, ["v", "suite", "kdf", "created_at"])?;
    let [salt, m, t, p] = exact_map(kdf, ["salt", "m", "t", "p"])?;
    let v = v.as_u64().ok_or_else(bad)?;
    let suite = suite.as_u64().ok_or_else(bad)?;
    let created_at = created_at.as_u64().ok_or_else(bad)?;
    let salt: [u8; SALT_LEN] = salt
        .into_bytes()
        .map_err(|_| bad())?
        .try_into()
        .map_err(|_| bad())?;
    let kdf = KdfParams {
        m_kib: kdf_param(&m)?,
        t: kdf_param(&t)?,
        p: kdf_param(&p)?,
    };
    if v != FORMAT_VERSION || suite != u64::from(SUITE) {
        return Err(Error::Unsupported);
    }
    Ok((
        ExportHeader {
            created_at,
            kdf,
            salt,
        },
        used,
    ))
}

// -------------------------------------------------------------------- keys

/// The AAD of `ek_wrap` (`LABEL_EK`) or of the body (`LABEL_BODY`): the label
/// and the header bytes as they stand in the file.
///
/// Spec: Fase 1 § 6.4.
pub(crate) fn export_aad(label: &'static str, header: &[u8]) -> Result<Vec<u8>, Error> {
    Tlv::new().label(label).bytes(tag::HEADER, header)?.finish()
}

pub(crate) fn aad_ek(header: &[u8]) -> Result<Vec<u8>, Error> {
    export_aad(LABEL_EK, header)
}

pub(crate) fn aad_body(header: &[u8]) -> Result<Vec<u8>, Error> {
    export_aad(LABEL_BODY, header)
}

/// `K_exp = HKDF(salt = TLV[label="ferret/v1/export"], ikm = Argon2id(pw,
/// salt, m, t, p, 32), info = "ferret/v1/export/key")`. The parameters have
/// been through `runner.gate` already.
///
/// Spec: Fase 1 § 6.4.
pub(crate) fn derive_k_exp(
    runner: KdfRunner,
    pw: &ExportPassword,
    salt: &[u8; SALT_LEN],
    kdf: KdfParams,
) -> Result<Zeroizing<[u8; 32]>, Error> {
    let mut stretched = Zeroizing::new([0u8; 32]);
    (runner.run)(pw.as_bytes(), salt, kdf, &mut *stretched)?;
    let hkdf_salt = Tlv::new().label(LABEL_EXPORT).finish()?;
    let mut k_exp = Zeroizing::new([0u8; 32]);
    hkdf_sha256(&hkdf_salt, &*stretched, INFO_KEY, &mut *k_exp)?;
    Ok(k_exp)
}

// -------------------------------------------------------------------- body

/// `cbor{ v: 1, items: [ { id, body } ] }`.
///
/// An item that is read-only (a newer `schema`), the reserved manifest id
/// or a repeated id is refused, as is a list over the 10 000 items that the
/// CBOR rules allow.
fn encode_items(items: &[ExportItem]) -> Result<Zeroizing<Vec<u8>>, Error> {
    if items.len() > MAX_ITEMS {
        return Err(Error::TooLarge);
    }
    let mut seen = BTreeSet::new();
    let mut list = Vec::with_capacity(items.len());
    for item in items {
        if item.body.schema != SCHEMA || item.body.is_read_only() {
            return Err(Error::ReadOnlySchema);
        }
        if item.item_id == ItemId::MANIFEST || !seen.insert(*item.item_id.as_bytes()) {
            return Err(bad_body());
        }
        list.push(Value::Map(vec![
            ("id".into(), Value::Bytes(item.item_id.as_bytes().to_vec())),
            ("body".into(), item.body.to_value()),
        ]));
    }
    let body = Value::Map(vec![
        ("v".into(), Value::uint(FORMAT_VERSION)),
        ("items".into(), Value::Array(list)),
    ]);
    cbor::encode(&body).map(Zeroizing::new)
}

/// The inverse of [`encode_items`]. Unknown keys in the wrapper or in an item
/// entry are refused (a later format changes `v`); unknown keys inside a body
/// are kept by [`ItemBody`].
fn decode_items(plain: &[u8]) -> Result<Vec<ExportItem>, Error> {
    let value = cbor::decode(plain)?;
    let [v, items] = exact_map(value, ["v", "items"]).map_err(|_| bad_body())?;
    match v.as_u64() {
        Some(FORMAT_VERSION) => {}
        Some(_) => return Err(Error::Unsupported),
        None => return Err(bad_body()),
    }
    let items = items.into_array().map_err(|_| bad_body())?;
    let mut seen = BTreeSet::new();
    let mut out = Vec::with_capacity(items.len());
    for entry in items {
        let [id, body] = exact_map(entry, ["id", "body"]).map_err(|_| bad_body())?;
        let id: [u8; ItemId::LEN] = id
            .into_bytes()
            .map_err(|_| bad_body())?
            .try_into()
            .map_err(|_| bad_body())?;
        let item_id = ItemId::from_bytes(id);
        if item_id == ItemId::MANIFEST || !seen.insert(id) {
            return Err(bad_body());
        }
        out.push(ExportItem {
            item_id,
            body: ItemBody::from_value(body)?.body,
        });
    }
    Ok(out)
}

// ------------------------------------------------------------ encrypt/open

/// Writes an export file.
///
/// Draws, in this order: the salt (16 bytes), `EK` (32), the nonce of
/// `ek_wrap` (24), the nonce of the body (24). `kdf` is checked against the
/// floor and ceiling first ([`Error::KdfOutOfRange`]); use [`EXPORT_KDF`].
/// The items are checked before anything is drawn.
///
/// Spec: Fase 1 § 6.4.
pub fn export_encrypt<R: SecureRng>(
    rng: &mut R,
    pw: &ExportPassword,
    kdf: KdfParams,
    created_at: u64,
    items: &[ExportItem],
) -> Result<Vec<u8>, Error> {
    encrypt_with(KdfRunner::PRODUCTION, rng, pw, kdf, created_at, items)
}

pub(crate) fn encrypt_with<R: SecureRng>(
    runner: KdfRunner,
    rng: &mut R,
    pw: &ExportPassword,
    kdf: KdfParams,
    created_at: u64,
    items: &[ExportItem],
) -> Result<Vec<u8>, Error> {
    let kdf = (runner.gate)(kdf)?;
    let plain = encode_items(items)?;
    seal_file(runner, rng, pw, kdf, created_at, &plain)
}

/// The key chain and the layout of [`export_encrypt`], for a body that has
/// been encoded already. `kdf` has been through `runner.gate`.
pub(crate) fn seal_file<R: SecureRng>(
    runner: KdfRunner,
    rng: &mut R,
    pw: &ExportPassword,
    kdf: KdfParams,
    created_at: u64,
    plain: &[u8],
) -> Result<Vec<u8>, Error> {
    if plain.len().saturating_add(OVERHEAD) > MAX_BODY_LEN {
        return Err(Error::TooLarge);
    }

    let mut salt = [0u8; SALT_LEN];
    rng.fill(&mut salt);
    let header = encode_header(&salt, kdf, created_at)?;
    let aad_ek = aad_ek(&header)?;
    let aad_body = aad_body(&header)?;

    let ek = ExportContentKey::random(rng);
    let k_exp = derive_k_exp(runner, pw, &salt, kdf)?;
    let ek_wrap = aead_seal(rng, &k_exp, &aad_ek, ek.expose())?;
    let body = aead_seal(rng, ek.expose(), &aad_body, plain)?;

    let mut file = Vec::with_capacity(
        header
            .len()
            .saturating_add(ek_wrap.len())
            .saturating_add(body.len()),
    );
    file.extend_from_slice(&header);
    file.extend_from_slice(&ek_wrap);
    file.extend_from_slice(&body);
    Ok(file)
}

/// Opens an export file and returns its items.
///
/// Order of the checks: the structure of the header, then the floor and
/// ceiling of the Argon2id parameters ([`Error::KdfOutOfRange`]), then the
/// length of the file ([`Error::Malformed`], [`Error::TooLarge`] over 128
/// MiB of body), and only then Argon2id. After that, every failure to
/// authenticate is [`Error::Decrypt`]: a wrong password and a changed byte
/// anywhere in the file look the same.
///
/// Use `ExportPassword::for_open` for `pw`.
///
/// Spec: Fase 1 § 6.4.
pub fn import_decrypt(pw: &ExportPassword, file: &[u8]) -> Result<Vec<ExportItem>, Error> {
    decrypt_with(KdfRunner::PRODUCTION, pw, file)
}

pub(crate) fn decrypt_with(
    runner: KdfRunner,
    pw: &ExportPassword,
    file: &[u8],
) -> Result<Vec<ExportItem>, Error> {
    let (header, used) = parse_export_header(file)?;
    let kdf = (runner.gate)(header.kdf)?;
    let header_bytes = file.get(..used).ok_or_else(bad)?;
    let rest = file.get(used..).ok_or_else(bad)?;
    let (ek_wrap, body) = rest.split_at_checked(EK_WRAP_LEN).ok_or_else(bad)?;
    if body.len() < OVERHEAD {
        return Err(bad());
    }
    if body.len() > MAX_BODY_LEN {
        return Err(Error::TooLarge);
    }

    let k_exp = derive_k_exp(runner, pw, &header.salt, kdf)?;
    let ek_plain = aead_open(&k_exp, &aad_ek(header_bytes)?, ek_wrap)?;
    let mut ek_bytes: [u8; 32] = ek_plain.as_slice().try_into().map_err(|_| Error::Decrypt)?;
    let ek = ExportContentKey::from_array_wiping(&mut ek_bytes);
    let plain = aead_open(ek.expose(), &aad_body(header_bytes)?, body)?;
    decode_items(&plain)
}
