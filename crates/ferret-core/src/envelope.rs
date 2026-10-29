//! The envelope: what the server stores for an item or the manifest, and the
//! two AEADs inside it.
//!
//! Spec: Fase 1 § 4.4 (item keys), § 5.1 (envelope), § 5.2 (body, padding,
//! AEAD), § 5.3 (what the AAD binds), § 5.4 (nonces) and § 8.6 (item tag).
//!
//! ```text
//! envelope = version u8 = 1 ‖ suite u8 = 1 ‖ kind u8 ‖ [ik_wrap 72] ‖ body
//!
//! ik_wrap = AEAD(VK, nonce, IK,
//!                aad = TLV[label="ferret/v1/item-key", version, suite,
//!                          vault_id, item_id, vk_epoch])
//! body    = AEAD(IK, nonce, padded_cbor,
//!                aad = TLV[label="ferret/v1/item", version, suite, kind,
//!                          vault_id, item_id, rev])
//! tag     = HMAC-SHA256(K_head,
//!                TLV[label="ferret/v1/item-tag", item_id, rev,
//!                    hash = SHA-256(envelope)])
//! ```
//!
//! `kind` 1 is an item, `kind` 2 is the manifest. The manifest has no
//! `ik_wrap`: its body is sealed with `K_meta`, with the label
//! `ferret/v1/manifest` and the reserved `item_id` of 16 zero bytes. The
//! whole envelope is at most 65 536 bytes, and the padded body at most
//! 61 440 (plan U6).
//!
//! The item key (IK) is made when an item is created and kept when it is
//! edited: the old `ik_wrap` is opened and copied unchanged, and only the
//! body is sealed again, with a new random nonce and `rev + 1` (plan U7).
//!
//! Opening goes in a fixed order, and each step is cheap to tell apart only
//! when it does not depend on a secret: the structure of the bytes
//! (`Malformed`/`Unsupported`/`TooLarge`), then the tag, then the AEADs, and
//! only then the padding and the CBOR. Every failure from the tag on is the
//! single `Decrypt`.

use crate::error::{Error, MalformedKind};
use crate::ids::{ItemId, VaultId};
use crate::item::body::SCHEMA;
use crate::item::pad::{self, is_padded_len};
use crate::item::{DecodedItem, ItemBody, Manifest};
use crate::keys::UnlockedVault;
use crate::prim::aead::{OVERHEAD, aead_open, aead_seal};
use crate::prim::{ct::ct_eq, mac::hmac_sha256};
use crate::rng::SecureRng;
use crate::secret::ItemKey;
use crate::tlv::{SUITE, Tlv, tag};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

/// The `version` byte of every envelope this version writes. Spec: Fase 1
/// § 5.1.
pub const VERSION: u8 = 1;
/// `kind` of an item.
pub const KIND_ITEM: u8 = 1;
/// `kind` of the manifest.
pub const KIND_MANIFEST: u8 = 2;
/// The largest envelope in bytes (plan U6).
pub const MAX_ENVELOPE_LEN: usize = 65_536;
/// Length of `ik_wrap`: `nonce (24) ‖ IK (32) ‖ tag (16)`.
pub const IK_WRAP_LEN: usize = 72;
/// Length of `version ‖ suite ‖ kind`.
pub const HEADER_LEN: usize = 3;

/// Label of the item key wrap AAD. Spec: Fase 1 § 4.4.
const LABEL_ITEM_KEY: &str = "ferret/v1/item-key";
/// Label of the item body AAD. Spec: Fase 1 § 5.2.
const LABEL_ITEM: &str = "ferret/v1/item";
/// Label of the manifest body AAD. Spec: Fase 1 § 5.2.
const LABEL_MANIFEST: &str = "ferret/v1/manifest";
/// Label of the item tag. Spec: Fase 1 § 8.6.
const LABEL_ITEM_TAG: &str = "ferret/v1/item-tag";

fn malformed() -> Error {
    Error::Malformed(MalformedKind::Envelope)
}

/// An envelope with its tag, as it goes to the server.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct SealedItem {
    /// The bytes the server stores.
    pub envelope: Vec<u8>,
    /// The item tag (Fase 1 § 8.6).
    pub tag: [u8; 32],
    /// The revision the envelope was sealed for (it is in the AAD).
    pub rev: u64,
}

/// The parts of an envelope, borrowed from its bytes.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct EnvelopeView<'a> {
    /// 1 for an item, 2 for the manifest.
    pub kind: u8,
    /// The wrapped item key (72 bytes); `None` for the manifest.
    pub ik_wrap: Option<&'a [u8]>,
    /// The sealed body: `nonce ‖ ciphertext ‖ tag`.
    pub body: &'a [u8],
}

/// Splits an envelope into its parts and checks its structure, without any
/// key.
///
/// * longer than 65 536 bytes: `TooLarge` (public, checked first);
/// * a `version`, `suite` or `kind` byte that is not a supported one:
///   `Decrypt`, the same error as any other change to the envelope. Suite 1
///   is the only suite. A server must not be able to make the client say
///   "update the app" by flipping a header byte; the bytes are also bound by
///   the AAD (Fase 1 § 5.3, all change gives a decryption error). When a
///   second suite exists, values that are structurally unsupported but
///   otherwise well formed may map to `Unsupported`, and only after review;
/// * a missing part, or a body whose padded length is not one of the padding
///   classes: `Malformed(Envelope)`.
///
/// Spec: Fase 1 § 5.1 and § 5.3, plan U6.
pub fn parse_envelope(bytes: &[u8]) -> Result<EnvelopeView<'_>, Error> {
    parse_as(bytes, None)
}

/// [`parse_envelope`], and when `expected` is given the `kind` byte must be
/// that one: a different (even supported) kind is the same `Decrypt`, so
/// flipping the kind byte of an item to the manifest's is not told apart from
/// any other change.
fn parse_as(bytes: &[u8], expected: Option<u8>) -> Result<EnvelopeView<'_>, Error> {
    if bytes.len() > MAX_ENVELOPE_LEN {
        return Err(Error::TooLarge);
    }
    let (header, rest) = bytes
        .split_first_chunk::<HEADER_LEN>()
        .ok_or_else(malformed)?;
    let [version, suite, kind] = *header;
    let kind_ok = kind == KIND_ITEM || kind == KIND_MANIFEST;
    if version != VERSION || suite != SUITE || !kind_ok || expected.is_some_and(|k| k != kind) {
        return Err(Error::Decrypt);
    }
    let (ik_wrap, body) = if kind == KIND_ITEM {
        let (wrap, body) = rest.split_at_checked(IK_WRAP_LEN).ok_or_else(malformed)?;
        (Some(wrap), body)
    } else {
        (None, rest)
    };
    let padded = body.len().checked_sub(OVERHEAD).ok_or_else(malformed)?;
    if !is_padded_len(padded) {
        return Err(malformed());
    }
    Ok(EnvelopeView {
        kind,
        ik_wrap,
        body,
    })
}

// ------------------------------------------------------------------- AADs

/// The `version`, `suite` and `kind` that go into an AAD. Always
/// `[VERSION, SUITE, kind]` in production; tests seal with other values to
/// show that each one is bound.
#[derive(Clone, Copy, Debug)]
pub(crate) struct AadHeader {
    pub(crate) version: u8,
    pub(crate) suite: u8,
    pub(crate) kind: u8,
}

impl AadHeader {
    pub(crate) const fn new(kind: u8) -> Self {
        Self {
            version: VERSION,
            suite: SUITE,
            kind,
        }
    }
}

/// What a seal writes that tests change: the header in the AAD, the three
/// bytes at the start of the envelope, and the `vk_epoch` in the AAD of
/// `ik_wrap`. [`SealOpts::PRODUCTION`] is the only value used outside tests.
#[derive(Clone, Copy, Debug)]
pub(crate) struct SealOpts {
    pub(crate) aad: AadHeader,
    pub(crate) written: [u8; HEADER_LEN],
    /// `None`: the epoch of the vault.
    pub(crate) ik_epoch: Option<u64>,
}

impl SealOpts {
    pub(crate) const PRODUCTION: SealOpts = SealOpts {
        aad: AadHeader::new(KIND_ITEM),
        written: [VERSION, SUITE, KIND_ITEM],
        ik_epoch: None,
    };
}

/// `TLV[label="ferret/v1/item-key", version, suite, vault_id, item_id,
/// vk_epoch]`. Spec: Fase 1 § 4.4.
pub(crate) fn item_key_aad(
    h: AadHeader,
    vault_id: &VaultId,
    item_id: &ItemId,
    vk_epoch: u64,
) -> Result<Vec<u8>, Error> {
    Tlv::new()
        .label(LABEL_ITEM_KEY)
        .u8(tag::VERSION, h.version)
        .u8(tag::SUITE, h.suite)
        .bytes(tag::VAULT_ID, vault_id.as_bytes())?
        .bytes(tag::ITEM_ID, item_id.as_bytes())?
        .u64(tag::VK_EPOCH, vk_epoch)
        .finish()
}

/// `TLV[label="ferret/v1/item" (manifest: "ferret/v1/manifest"), version,
/// suite, kind, vault_id, item_id, rev]`. Spec: Fase 1 § 5.2.
pub(crate) fn body_aad(
    h: AadHeader,
    manifest: bool,
    vault_id: &VaultId,
    item_id: &ItemId,
    rev: u64,
) -> Result<Vec<u8>, Error> {
    Tlv::new()
        .label(if manifest { LABEL_MANIFEST } else { LABEL_ITEM })
        .u8(tag::VERSION, h.version)
        .u8(tag::SUITE, h.suite)
        .u8(tag::KIND, h.kind)
        .bytes(tag::VAULT_ID, vault_id.as_bytes())?
        .bytes(tag::ITEM_ID, item_id.as_bytes())?
        .u64(tag::REV, rev)
        .finish()
}

// -------------------------------------------------------------------- tag

/// The item tag.
///
/// `HMAC-SHA256(K_head, TLV[label="ferret/v1/item-tag", item_id, rev,
/// hash = SHA-256(envelope)])`. The manifest has a tag too, with the
/// reserved `item_id`.
///
/// Spec: Fase 1 § 8.6.
pub fn item_tag(
    vault: &UnlockedVault,
    item_id: ItemId,
    rev: u64,
    envelope: &[u8],
) -> Result<[u8; 32], Error> {
    let hash = Sha256::digest(envelope);
    let message = Tlv::new()
        .label(LABEL_ITEM_TAG)
        .bytes(tag::ITEM_ID, item_id.as_bytes())?
        .u64(tag::REV, rev)
        .bytes(tag::HASH, hash.as_slice())?
        .finish()?;
    hmac_sha256(vault.k_head().expose(), &message)
}

/// Checks the tag of a row, in constant time. A wrong tag is `Decrypt`.
///
/// Spec: Fase 1 § 8.6 ("Klienten verifiserer merket før den godtar en rad").
pub fn verify_item_tag(
    vault: &UnlockedVault,
    item_id: ItemId,
    rev: u64,
    envelope: &[u8],
    tag: &[u8; 32],
) -> Result<(), Error> {
    let expected = item_tag(vault, item_id, rev, envelope).map_err(|_| Error::Decrypt)?;
    if ct_eq(&expected, tag) {
        Ok(())
    } else {
        Err(Error::Decrypt)
    }
}

// ---------------------------------------------------------------- sealing

/// An item key together with the `ik_wrap` that holds it.
struct KeyWrap {
    ik: ItemKey,
    ik_wrap: Vec<u8>,
}

/// Opens an `ik_wrap` with the vault key. Every failure is `Decrypt`.
fn open_ik(
    vault: &UnlockedVault,
    h: AadHeader,
    item_id: &ItemId,
    ik_wrap: &[u8],
) -> Result<ItemKey, Error> {
    let ctx = vault.context();
    let aad = item_key_aad(h, &ctx.vault_id, item_id, ctx.vk_epoch)?;
    let pt = aead_open(vault.vault_key().expose(), &aad, ik_wrap)?;
    let mut bytes = [0u8; ItemKey::LEN];
    if pt.len() != bytes.len() {
        return Err(Error::Decrypt);
    }
    bytes.copy_from_slice(&pt);
    Ok(ItemKey::from_array_wiping(&mut bytes))
}

/// The item key of an existing envelope, to be kept (plan U7).
fn existing_key(
    vault: &UnlockedVault,
    item_id: &ItemId,
    existing: &[u8],
) -> Result<KeyWrap, Error> {
    let view = parse_as(existing, Some(KIND_ITEM))?;
    let Some(ik_wrap) = view.ik_wrap else {
        return Err(malformed());
    };
    let ik = open_ik(vault, AadHeader::new(KIND_ITEM), item_id, ik_wrap)?;
    Ok(KeyWrap {
        ik,
        ik_wrap: ik_wrap.to_vec(),
    })
}

/// A new item key and its wrap: draws the key, then the nonce.
fn new_key<R: SecureRng>(
    rng: &mut R,
    vault: &UnlockedVault,
    item_id: &ItemId,
    opts: &SealOpts,
) -> Result<KeyWrap, Error> {
    let ik = ItemKey::random(rng);
    let ctx = vault.context();
    let epoch = opts.ik_epoch.unwrap_or(ctx.vk_epoch);
    let aad = item_key_aad(opts.aad, &ctx.vault_id, item_id, epoch)?;
    let ik_wrap = aead_seal(
        rng,
        vault.vault_key().expose(),
        &aad,
        ik.expose().as_slice(),
    )?;
    Ok(KeyWrap { ik, ik_wrap })
}

/// Seals an already padded body as an item envelope.
///
/// With `keep`, the item key and its wrap are reused and only the body gets
/// a new nonce (an edit). Without it, a new item key is drawn first, then
/// the nonce of its wrap, then the nonce of the body.
pub(crate) fn seal_item_padded<R: SecureRng>(
    rng: &mut R,
    vault: &UnlockedVault,
    item_id: &ItemId,
    rev: u64,
    padded: &[u8],
    keep: Option<&[u8]>,
    opts: &SealOpts,
) -> Result<Vec<u8>, Error> {
    if !is_padded_len(padded.len()) {
        return Err(Error::Malformed(MalformedKind::Envelope));
    }
    let key = match keep {
        Some(existing) => existing_key(vault, item_id, existing)?,
        None => new_key(rng, vault, item_id, opts)?,
    };
    let body_aad = body_aad(opts.aad, false, &vault.context().vault_id, item_id, rev)?;
    let body = aead_seal(rng, key.ik.expose(), &body_aad, padded)?;
    let mut envelope = Vec::with_capacity(
        HEADER_LEN
            .saturating_add(key.ik_wrap.len())
            .saturating_add(body.len()),
    );
    envelope.extend_from_slice(&opts.written);
    envelope.extend_from_slice(&key.ik_wrap);
    envelope.extend_from_slice(&body);
    Ok(envelope)
}

/// An item must not use the reserved id of the manifest.
pub(crate) fn check_item_id(item_id: &ItemId) -> Result<(), Error> {
    if *item_id == ItemId::MANIFEST {
        return Err(malformed());
    }
    Ok(())
}

/// Seals an item.
///
/// * The body must not be read-only (`schema` above 1): `ReadOnlySchema`.
/// * The CBOR must fit the padded limit of 61 440 bytes: `TooLarge`.
/// * With `existing` (the envelope being replaced) the item key is kept:
///   the old `ik_wrap` is opened and copied, only the body is sealed again,
///   with a new nonce. Without it, a new item key is made.
/// * Every call draws new nonces from `rng`; there is no counter.
///
/// `rev` is the revision the item gets with this write (`base_rev + 1`); it
/// goes into the AAD.
///
/// Spec: Fase 1 § 4.4, § 5.1, § 5.2 and § 5.4; plan U6 and U7.
pub fn encrypt_item<R: SecureRng>(
    rng: &mut R,
    vault: &UnlockedVault,
    item_id: ItemId,
    rev: u64,
    body: &ItemBody,
    existing: Option<&[u8]>,
) -> Result<SealedItem, Error> {
    check_item_id(&item_id)?;
    // Only schema 1, and nothing that came from a newer schema.
    if body.schema != SCHEMA || body.is_read_only() {
        return Err(Error::ReadOnlySchema);
    }
    let cbor = body.to_cbor()?;
    let padded = pad::pad(&cbor)?;
    seal_item_plaintext(rng, vault, item_id, rev, &padded, existing)
}

/// Seals a padded body and computes the tag. Shared by items and the
/// re-sealing used by rekey, which never looks at the contents.
fn seal_item_plaintext<R: SecureRng>(
    rng: &mut R,
    vault: &UnlockedVault,
    item_id: ItemId,
    rev: u64,
    padded: &[u8],
    existing: Option<&[u8]>,
) -> Result<SealedItem, Error> {
    let envelope = seal_item_padded(
        rng,
        vault,
        &item_id,
        rev,
        padded,
        existing,
        &SealOpts::PRODUCTION,
    )?;
    let tag = item_tag(vault, item_id, rev, &envelope)?;
    Ok(SealedItem { envelope, tag, rev })
}

// ---------------------------------------------------------------- opening

/// Opens an item envelope down to the padded body: structure, tag, key
/// unwrap, body AEAD. Every failure after the structure check is `Decrypt`.
pub(crate) fn open_item_padded(
    vault: &UnlockedVault,
    item_id: ItemId,
    rev: u64,
    envelope: &[u8],
    tag: &[u8; 32],
) -> Result<Zeroizing<Vec<u8>>, Error> {
    let view = parse_as(envelope, Some(KIND_ITEM))?;
    let Some(ik_wrap) = view.ik_wrap else {
        return Err(malformed());
    };
    verify_item_tag(vault, item_id, rev, envelope, tag)?;
    let ik = open_ik(vault, AadHeader::new(KIND_ITEM), &item_id, ik_wrap)?;
    let aad = body_aad(
        AadHeader::new(KIND_ITEM),
        false,
        &vault.context().vault_id,
        &item_id,
        rev,
    )?;
    aead_open(ik.expose(), &aad, view.body)
}

/// Removes the padding of an authentic padded body. Call it only on the
/// output of a successful AEAD.
fn plaintext_of(padded: &Zeroizing<Vec<u8>>) -> Result<&[u8], Error> {
    let len = pad::unpad(padded)?;
    padded.get(..len).ok_or(Error::Decrypt)
}

/// Opens an item.
///
/// The tag is checked first; if it is wrong, no AEAD is run. Then the item
/// key is unwrapped with the vault key and the body is opened, and only
/// then are the padding removed and the CBOR read. A body with a `schema`
/// above 1 opens with `read_only` set.
///
/// A wrong key, `item_id`, `rev`, vault, epoch, tag or any changed byte is
/// `Decrypt`, without a cause.
///
/// Spec: Fase 1 § 5.2, § 5.3 and § 8.6.
pub fn decrypt_item(
    vault: &UnlockedVault,
    item_id: ItemId,
    rev: u64,
    envelope: &[u8],
    tag: &[u8; 32],
) -> Result<DecodedItem, Error> {
    check_item_id(&item_id)?;
    let padded = open_item_padded(vault, item_id, rev, envelope, tag)?;
    ItemBody::from_cbor(plaintext_of(&padded)?)
}

/// Seals the manifest with `K_meta`, with `item_id` = 16 zero bytes.
///
/// Spec: Fase 1 § 5.1 ("For `kind = 2` finnes ingen `ik_wrap`"), § 5.2 and
/// plan U5.
pub fn encrypt_manifest<R: SecureRng>(
    rng: &mut R,
    vault: &UnlockedVault,
    rev: u64,
    manifest: &Manifest,
) -> Result<SealedItem, Error> {
    // The manifest says for which epoch it is; it must be the epoch of the
    // key that seals it.
    if manifest.vk_epoch != vault.context().vk_epoch {
        return Err(Error::Malformed(MalformedKind::ItemBody));
    }
    let cbor = Zeroizing::new(manifest.to_cbor()?);
    seal_manifest_cbor(rng, vault, rev, &cbor)
}

/// Pads and seals manifest CBOR as it is.
pub(crate) fn seal_manifest_cbor<R: SecureRng>(
    rng: &mut R,
    vault: &UnlockedVault,
    rev: u64,
    cbor: &[u8],
) -> Result<SealedItem, Error> {
    let padded = pad::pad(cbor)?;
    let item_id = ItemId::MANIFEST;
    let aad = body_aad(
        AadHeader::new(KIND_MANIFEST),
        true,
        &vault.context().vault_id,
        &item_id,
        rev,
    )?;
    let body = aead_seal(rng, vault.k_meta().expose(), &aad, &padded)?;
    let mut envelope = Vec::with_capacity(HEADER_LEN.saturating_add(body.len()));
    envelope.extend_from_slice(&[VERSION, SUITE, KIND_MANIFEST]);
    envelope.extend_from_slice(&body);
    let tag = item_tag(vault, item_id, rev, &envelope)?;
    Ok(SealedItem { envelope, tag, rev })
}

/// Opens the manifest: structure, tag, AEAD, then padding and CBOR. A `v`
/// other than 1 is `Unsupported`.
pub fn decrypt_manifest(
    vault: &UnlockedVault,
    rev: u64,
    envelope: &[u8],
    tag: &[u8; 32],
) -> Result<Manifest, Error> {
    let view = parse_as(envelope, Some(KIND_MANIFEST))?;
    let item_id = ItemId::MANIFEST;
    verify_item_tag(vault, item_id, rev, envelope, tag)?;
    let aad = body_aad(
        AadHeader::new(KIND_MANIFEST),
        true,
        &vault.context().vault_id,
        &item_id,
        rev,
    )?;
    let padded = aead_open(vault.k_meta().expose(), &aad, view.body)?;
    let manifest = Manifest::from_cbor(plaintext_of(&padded)?)?;
    // Authentic, but for another epoch than the key that opened it: a writer
    // bug, treated as any other failure so that no caller sees it.
    if manifest.vk_epoch != vault.context().vk_epoch {
        return Err(Error::Decrypt);
    }
    Ok(manifest)
}

/// Seals an item again under another vault state, for a full rekey, without
/// reading the contents.
///
/// The old envelope is opened (structure, tag, both AEADs); the padded body
/// is then sealed as it is, under a fresh item key of `new`, with new
/// nonces and the revision `new_rev`. The CBOR is never parsed, so a body
/// with a future `schema` can be rekeyed even though it can never be
/// edited.
///
/// Spec: Fase 1 § 4.7 (rekey wraps every item key again and re-seals).
#[allow(clippy::too_many_arguments)]
pub(crate) fn reseal_item<R: SecureRng>(
    rng: &mut R,
    old: &UnlockedVault,
    new: &UnlockedVault,
    item_id: ItemId,
    old_rev: u64,
    new_rev: u64,
    envelope: &[u8],
    tag: &[u8; 32],
) -> Result<SealedItem, Error> {
    check_item_id(&item_id)?;
    // A rekey stays in the same account and vault, moves to a later epoch,
    // and gives the item a later revision.
    let (o, n) = (old.context(), new.context());
    if o.account_id != n.account_id
        || o.vault_id != n.vault_id
        || n.vk_epoch <= o.vk_epoch
        || new_rev <= old_rev
    {
        return Err(malformed());
    }
    let padded = open_item_padded(old, item_id, old_rev, envelope, tag)?;
    seal_item_plaintext(rng, new, item_id, new_rev, &padded, None)
}
