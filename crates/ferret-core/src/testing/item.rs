//! Access to the plaintext bytes and the AADs of the item envelope, for
//! tests and vector runners. Behind `test-support`; never part of a release.
//!
//! These functions seal and open the bytes inside an envelope without
//! reading the CBOR, which is how a body with a future `schema` (that
//! `encrypt_item` refuses) gets into a test, and how the rekey path is shown
//! never to parse a body.

use crate::envelope::{
    AadHeader, HEADER_LEN, KIND_ITEM, SealOpts, SealedItem, body_aad, item_key_aad, item_tag,
    open_item_padded, parse_envelope, reseal_item, seal_item_padded, seal_manifest_cbor,
};
use crate::error::Error;
use crate::ids::ItemId;
use crate::item::pad;
use crate::keys::UnlockedVault;
use crate::rng::SecureRng;

/// Pads `plain_cbor` as it is (no CBOR parsing) and seals it as an item. With
/// `existing`, the item key is kept.
pub fn seal_plaintext<R: SecureRng>(
    rng: &mut R,
    vault: &UnlockedVault,
    item_id: ItemId,
    rev: u64,
    plain_cbor: &[u8],
    existing: Option<&[u8]>,
) -> Result<SealedItem, Error> {
    seal_with(
        rng,
        vault,
        item_id,
        rev,
        plain_cbor,
        existing,
        &Sabotage::default(),
    )
}

/// What a sealed envelope gets wrong on purpose.
#[derive(Clone, Copy, Debug, Default)]
pub struct Sabotage {
    /// `[version, suite, kind]` in the AAD, if not the right ones.
    pub aad_header: Option<[u8; HEADER_LEN]>,
    /// The three bytes written at the start of the envelope, if not the
    /// right ones.
    pub written_header: Option<[u8; HEADER_LEN]>,
    /// The `vk_epoch` in the AAD of `ik_wrap`, if not the vault's.
    pub ik_epoch: Option<u64>,
}

/// Like [`seal_plaintext`], with a [`Sabotage`]. The envelope parses but does
/// not open when it differs from the right one in an AAD field.
pub fn seal_with<R: SecureRng>(
    rng: &mut R,
    vault: &UnlockedVault,
    item_id: ItemId,
    rev: u64,
    plain_cbor: &[u8],
    existing: Option<&[u8]>,
    sabotage: &Sabotage,
) -> Result<SealedItem, Error> {
    let padded = pad::pad(plain_cbor)?;
    let aad = sabotage
        .aad_header
        .map_or(AadHeader::new(KIND_ITEM), |[version, suite, kind]| {
            AadHeader {
                version,
                suite,
                kind,
            }
        });
    let opts = SealOpts {
        aad,
        written: sabotage
            .written_header
            .unwrap_or(SealOpts::PRODUCTION.written),
        ik_epoch: sabotage.ik_epoch,
    };
    let envelope = seal_item_padded(rng, vault, &item_id, rev, &padded, existing, &opts)?;
    let tag = item_tag(vault, item_id, rev, &envelope)?;
    Ok(SealedItem { envelope, tag, rev })
}

/// The padded plaintext of an item envelope, after the tag and both AEADs
/// have passed, and the plaintext with the padding removed.
pub fn open_plaintext(
    vault: &UnlockedVault,
    item_id: ItemId,
    rev: u64,
    envelope: &[u8],
    tag: &[u8; 32],
) -> Result<(Vec<u8>, Vec<u8>), Error> {
    let padded = open_item_padded(vault, item_id, rev, envelope, tag)?;
    let len = pad::unpad(&padded)?;
    let plain = padded.get(..len).ok_or(Error::Decrypt)?.to_vec();
    Ok((padded.to_vec(), plain))
}

/// The item key inside an envelope, and the two AADs, for a vector.
pub struct ItemIntermediate {
    /// The 32 bytes of IK.
    pub ik: [u8; 32],
    /// The AAD of `ik_wrap`.
    pub ik_aad: Vec<u8>,
    /// The AAD of the body.
    pub body_aad: Vec<u8>,
    /// The padded body.
    pub padded: Vec<u8>,
}

/// Opens an item envelope and reports IK, the AADs and the padded body.
pub fn intermediate(
    vault: &UnlockedVault,
    item_id: ItemId,
    rev: u64,
    envelope: &[u8],
    tag: &[u8; 32],
) -> Result<ItemIntermediate, Error> {
    let padded = open_item_padded(vault, item_id, rev, envelope, tag)?;
    let view = parse_envelope(envelope)?;
    let ik_wrap = view.ik_wrap.ok_or(Error::Decrypt)?;
    let ctx = vault.context();
    let ik_aad = item_key_aad(
        AadHeader::new(KIND_ITEM),
        &ctx.vault_id,
        &item_id,
        ctx.vk_epoch,
    )?;
    let ik_bytes = crate::prim::aead::aead_open(vault.vault_key().expose(), &ik_aad, ik_wrap)?;
    let ik: [u8; 32] = ik_bytes.as_slice().try_into().map_err(|_| Error::Decrypt)?;
    let body_aad = body_aad(
        AadHeader::new(KIND_ITEM),
        false,
        &ctx.vault_id,
        &item_id,
        rev,
    )?;
    Ok(ItemIntermediate {
        ik,
        ik_aad,
        body_aad,
        padded: padded.to_vec(),
    })
}

/// Seals an item again under `new`, as the rekey does, without reading the
/// contents.
#[allow(clippy::too_many_arguments)]
pub fn reseal<R: SecureRng>(
    rng: &mut R,
    old: &UnlockedVault,
    new: &UnlockedVault,
    item_id: ItemId,
    old_rev: u64,
    new_rev: u64,
    envelope: &[u8],
    tag: &[u8; 32],
) -> Result<SealedItem, Error> {
    reseal_item(rng, old, new, item_id, old_rev, new_rev, envelope, tag)
}

/// Pads `cbor` as it is (no reading) and seals it as the manifest, so that a
/// manifest that is authentic and wrong can be made.
pub fn seal_manifest_plaintext<R: SecureRng>(
    rng: &mut R,
    vault: &UnlockedVault,
    rev: u64,
    cbor: &[u8],
) -> Result<SealedItem, Error> {
    seal_manifest_cbor(rng, vault, rev, cbor)
}
