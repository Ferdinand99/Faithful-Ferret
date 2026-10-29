//! Full rekey.
//!
//! Spec: Fase 1 § 4.7 (F-03). A rekey is one atomic request to
//! `POST /api/vault/rekey`; a series of single requests would leave a mixed
//! state if it stopped half way. [`UnlockedVault::rekey`] therefore builds
//! the whole plan in memory and returns it only when every part has been
//! made **and checked**. If anything fails, nothing is returned: the caller
//! gets an error, and every key made on the way is wiped when it is dropped.
//! The core never sends anything and never applies half of a plan.
//!
//! What the plan holds:
//!
//! * a new vault key `VK'`, `vk_epoch + 1`, and with them a new `K_head`,
//!   `K_del`, `K_meta` and `pk_a'`;
//! * every item opened with the old keys and sealed again under a **fresh**
//!   item key, with new nonces and `rev + 1`, without reading the CBOR (so
//!   an item with a future `schema` is rekeyed too);
//! * every tombstone checked and made again under `K_del'` at `rev + 1`;
//! * the `password` wrap under the same `KEK_pw` with the next generation,
//!   and the `recovery` wrap under a **new** recovery key with `pk_r'`. A
//!   `prf` wrap is not made again: the user registers the passkey again;
//! * a new manifest, with the two methods, and a new checkpoint under
//!   `K_head'`.
//!
//! # What is checked first
//!
//! Before anything is drawn or built, the rows the caller passes (the items,
//! the tombstones and the old manifest) are checked against the old
//! checkpoint at `base_seq` with the rules of [`verify_checkpoint`], so a
//! server that hides a row in the download cannot make the rekey drop it:
//! a live row that the checkpoint has but the caller did not pass is an
//! error (`HiddenOrRolledBack`, or `TopDigestMismatch` when the checkpoint
//! is at `base_seq`, which the server requires to be its top), and so is a
//! row at `base_seq` that the checkpoint does not have. The checkpoint is
//! the last one the client verified; a client that has none makes one from
//! its own verified cache.
//!
//! The generations of the two new wraps are the pinned floors plus one, and
//! the new manifest's revision is the old manifest's plus one; none of them
//! is supplied by the caller. The pinned record must be for this account,
//! vault, epoch and `pk_a`, and must have floors for the password and the
//! recovery wrap (seed them from the manifest with
//! `Pinned::seed_from_manifest`).
//!
//! The caller signs the request with the **old** vault:
//! `auth_sign(&old, AuthOp::Rekey, nonce, body)`.
//!
//! # Draws
//!
//! In this order, from `rng`: `VK'` (32); per item, in input order, `IK'`
//! (32), the nonce of its `ik_wrap` (24) and the nonce of its body (24); per
//! tombstone the nonce (24); the nonce of the password wrap (24); the new
//! recovery key (32); the nonce of the recovery wrap (24); the nonce of the
//! manifest (24).

use super::checkpoint::{
    Checkpoint, CheckpointEntry, ServerRow, make_checkpoint, verify_checkpoint,
};
use super::tomb::{Tombstone, make_tombstone};
use crate::envelope::{
    SealedItem, check_item_id, decrypt_manifest, encrypt_manifest, open_item_padded, reseal_item,
};
use crate::error::{Error, MalformedKind, PinnedField};
use crate::ids::{ItemId, MethodId};
use crate::item::{Manifest, ManifestEntry};
use crate::keys::{UnlockedVault, VaultContext, recovery_public_key};
use crate::pinning::{MethodKey, Pinned};
use crate::rng::SecureRng;
use crate::secret::{Kek, RecoveryKey, VaultKey};
use crate::wrap::{Method, WrapRecord, unwrap_vk, wrap_vk};
use std::collections::BTreeSet;

/// `method_type` of the password wrap in the manifest. Spec: Fase 1 § 3.1.
const TYPE_PASSWORD: u8 = 1;
/// `method_type` of the recovery wrap in the manifest. Spec: Fase 1 § 3.1.
const TYPE_RECOVERY: u8 = 2;

/// One live item as the server has it.
#[derive(Clone, Copy, Debug)]
pub struct RekeyItem<'a> {
    /// The item.
    pub item_id: ItemId,
    /// Its current revision.
    pub rev: u64,
    /// The envelope.
    pub envelope: &'a [u8],
    /// The tag the server stores with it.
    pub tag: &'a [u8; 32],
}

/// One tombstone as the server has it.
#[derive(Clone, Copy, Debug)]
pub struct RekeyTombstone<'a> {
    /// The item.
    pub item_id: ItemId,
    /// The revision of the deletion.
    pub rev: u64,
    /// The 40 bytes of the tombstone. They are checked under the old `K_del`
    /// before they are made again, so that a forged tombstone is not turned
    /// into an authentic one.
    pub tomb: &'a [u8],
}

/// What a rekey needs besides the old vault.
pub struct RekeyInput<'a> {
    /// The server `seq` the request is based on; the server applies the
    /// request only if this is its top. The new checkpoint is made for it.
    pub base_seq: u64,
    /// The last checkpoint the client verified (any `seq` up to `base_seq`).
    pub old_checkpoint: &'a Checkpoint,
    /// The current manifest row (its `item_id` is `ItemId::MANIFEST`).
    pub old_manifest: RekeyItem<'a>,
    /// Every live item.
    pub items: &'a [RekeyItem<'a>],
    /// Every tombstone the server still has.
    pub tombstones: &'a [RekeyTombstone<'a>],
    /// `KEK_pw`, which stays the same.
    pub password_kek: &'a Kek,
    /// The id and method of the password wrap (`Method::Password`).
    pub password_method: (MethodId, Method),
    /// The id of the new recovery wrap.
    pub recovery_method_id: MethodId,
    /// The pinned record of this device: it gives the generations of the new
    /// wraps (the floors plus one).
    pub pinned: &'a Pinned,
}

/// A complete rekey plan. It holds secrets (the new vault and the new
/// recovery key), so it has no `Clone` and no `Debug`.
pub struct RekeyBundle {
    /// The new vault, at `vk_epoch + 1`.
    pub vault: UnlockedVault,
    /// The new recovery key, to be shown to the user once.
    pub recovery_key: RecoveryKey,
    /// `pk_a'`.
    pub pk_a: [u8; 32],
    /// `pk_r'`.
    pub pk_r: [u8; 32],
    /// The new epoch.
    pub vk_epoch: u64,
    /// The `base_seq` of the request.
    pub base_seq: u64,
    /// Every item sealed again, at `rev + 1`.
    pub items: Vec<(ItemId, SealedItem)>,
    /// Every tombstone made again, at `rev + 1`.
    pub tombstones: Vec<(ItemId, Tombstone)>,
    /// The password wrap and the recovery wrap, in that order.
    pub wraps: Vec<WrapRecord>,
    /// The new manifest.
    pub manifest: SealedItem,
    /// The checkpoint under `K_head'`, for `seq = base_seq`.
    pub checkpoint: Checkpoint,
}

fn malformed() -> Error {
    Error::Malformed(MalformedKind::Entries)
}

fn next(rev: u64) -> Result<u64, Error> {
    rev.checked_add(1).ok_or_else(malformed)
}

impl UnlockedVault {
    /// Builds a full rekey as described in the module documentation.
    ///
    /// Input that cannot make a valid plan is refused before any random
    /// number is drawn: an `item_id` twice (or the manifest's), a `rev` of
    /// `u64::MAX`, a password method that is not `Method::Password`, a
    /// generation above the pinning maximum. Every item and tombstone is
    /// opened under the old keys first, and an item that does not open is
    /// `Decrypt` for the whole rekey.
    ///
    /// The result is checked before it is returned: every tag and
    /// tombstone, the bodies, the two wraps, the manifest, and the
    /// checkpoint against the new rows.
    ///
    /// Spec: Fase 1 § 4.7 and § 8.6.
    pub fn rekey<R: SecureRng>(
        &self,
        rng: &mut R,
        input: &RekeyInput<'_>,
    ) -> Result<RekeyBundle, Error> {
        let old = *self.context();
        let (password_id, password_method) = &input.password_method;
        if !matches!(password_method, Method::Password { .. }) {
            return Err(Error::Unsupported);
        }
        // The pinned record must be this vault's, at this epoch.
        let pinned = input.pinned;
        if pinned.account_id != old.account_id {
            return Err(Error::Pinned(PinnedField::AccountId));
        }
        if pinned.vault_id != old.vault_id {
            return Err(Error::Pinned(PinnedField::VaultId));
        }
        if pinned.vk_epoch_max != old.vk_epoch {
            return Err(Error::Pinned(PinnedField::VkEpoch));
        }
        if pinned.pk_a != self.auth_public_key() {
            return Err(Error::Pinned(PinnedField::AuthKey));
        }
        let password_generation = pinned.next_generation(&MethodKey::Password)?;
        let recovery_generation = pinned.next_generation(&MethodKey::Recovery)?;
        if input.old_manifest.item_id != ItemId::MANIFEST {
            return Err(Error::Malformed(MalformedKind::Envelope));
        }
        let manifest_rev = next(input.old_manifest.rev)?;
        let mut seen: BTreeSet<[u8; 16]> = BTreeSet::new();
        let ids = input
            .items
            .iter()
            .map(|i| &i.item_id)
            .chain(input.tombstones.iter().map(|t| &t.item_id));
        for id in ids {
            check_item_id(id)?;
            if !seen.insert(*id.as_bytes()) {
                return Err(malformed());
            }
        }
        let new_ctx = VaultContext {
            account_id: old.account_id,
            vault_id: old.vault_id,
            vk_epoch: next(old.vk_epoch)?,
        };
        for item in input.items {
            next(item.rev)?;
        }
        for tomb in input.tombstones {
            next(tomb.rev)?;
        }

        // The rows must be the whole state the old checkpoint describes.
        let mut rows: Vec<ServerRow> = Vec::with_capacity(
            input
                .items
                .len()
                .saturating_add(input.tombstones.len())
                .saturating_add(1),
        );
        for item in input.items {
            rows.push(ServerRow::live(
                self,
                item.item_id,
                item.rev,
                item.envelope,
                item.tag,
            )?);
        }
        for t in input.tombstones {
            rows.push(ServerRow::deleted(self, t.item_id, t.rev, t.tomb)?);
        }
        let m = &input.old_manifest;
        decrypt_manifest(self, m.rev, m.envelope, m.tag)?;
        rows.push(ServerRow::live(
            self,
            ItemId::MANIFEST,
            m.rev,
            m.envelope,
            m.tag,
        )?);
        verify_checkpoint(self, input.old_checkpoint, &rows, input.base_seq)?;

        // The new vault.
        let new = UnlockedVault::from_vault_key(new_ctx, VaultKey::generate(rng))?;

        // Items and tombstones.
        let mut items = Vec::with_capacity(input.items.len());
        for item in input.items {
            let sealed = reseal_item(
                rng,
                self,
                &new,
                item.item_id,
                item.rev,
                next(item.rev)?,
                item.envelope,
                item.tag,
            )?;
            items.push((item.item_id, sealed));
        }
        let mut tombstones = Vec::with_capacity(input.tombstones.len());
        for t in input.tombstones {
            tombstones.push((
                t.item_id,
                make_tombstone(rng, &new, t.item_id, next(t.rev)?)?,
            ));
        }

        // The wraps: the same KEK_pw, and a new recovery key.
        let password_wrap = wrap_vk(
            rng,
            &new_ctx,
            new.vault_key(),
            input.password_kek,
            *password_id,
            password_generation,
            password_method.clone(),
        )?;
        let recovery_key = RecoveryKey::generate(rng);
        let recovery_kek = Kek::from_recovery_key(&new_ctx.account_id, &recovery_key)?;
        let recovery_wrap = wrap_vk(
            rng,
            &new_ctx,
            new.vault_key(),
            &recovery_kek,
            input.recovery_method_id,
            recovery_generation,
            Method::Recovery,
        )?;
        let pk_r = recovery_public_key(&recovery_key, &new_ctx.account_id)?;

        // The manifest.
        let manifest_plain = Manifest::new(
            new_ctx.vk_epoch,
            vec![
                ManifestEntry::new(TYPE_PASSWORD, *password_id, password_generation),
                ManifestEntry::new(TYPE_RECOVERY, input.recovery_method_id, recovery_generation),
            ],
        );
        let manifest = encrypt_manifest(rng, &new, manifest_rev, &manifest_plain)?;

        // The checkpoint of the new state.
        let mut entries: Vec<CheckpointEntry> = Vec::with_capacity(
            items
                .len()
                .saturating_add(tombstones.len())
                .saturating_add(1),
        );
        for (id, s) in &items {
            entries.push(CheckpointEntry::live(*id, s.rev, &s.envelope));
        }
        for (id, t) in &tombstones {
            entries.push(CheckpointEntry::tombstone(*id, t.rev));
        }
        entries.push(CheckpointEntry::live(
            ItemId::MANIFEST,
            manifest.rev,
            &manifest.envelope,
        ));
        let checkpoint = make_checkpoint(&new, input.base_seq, entries)?;

        let bundle = RekeyBundle {
            pk_a: new.auth_public_key(),
            pk_r,
            vk_epoch: new_ctx.vk_epoch,
            base_seq: input.base_seq,
            vault: new,
            recovery_key,
            items,
            tombstones,
            wraps: vec![password_wrap, recovery_wrap],
            manifest,
            checkpoint,
        };
        bundle.check(input, &recovery_kek)?;
        Ok(bundle)
    }
}

impl RekeyBundle {
    /// Checks the whole plan against the new keys, as a device that gets the
    /// state after the rekey would. Any failure is returned as it is; with a
    /// correct core there is none.
    fn check(&self, input: &RekeyInput<'_>, recovery_kek: &Kek) -> Result<(), Error> {
        let new = &self.vault;
        let ctx = *new.context();
        let mut rows: Vec<ServerRow> = Vec::new();
        for (id, s) in &self.items {
            open_item_padded(new, *id, s.rev, &s.envelope, &s.tag)?;
            rows.push(ServerRow::live(new, *id, s.rev, &s.envelope, &s.tag)?);
        }
        for (id, t) in &self.tombstones {
            rows.push(ServerRow::deleted(new, *id, t.rev, &t.tomb)?);
        }
        let manifest = decrypt_manifest(
            new,
            self.manifest.rev,
            &self.manifest.envelope,
            &self.manifest.tag,
        )?;
        if manifest.vk_epoch != ctx.vk_epoch {
            return Err(Error::Decrypt);
        }
        rows.push(ServerRow::live(
            new,
            ItemId::MANIFEST,
            self.manifest.rev,
            &self.manifest.envelope,
            &self.manifest.tag,
        )?);
        verify_checkpoint(new, &self.checkpoint, &rows, self.checkpoint.seq)?;

        let [password_wrap, recovery_wrap] = self.wraps.as_slice() else {
            return Err(Error::Decrypt);
        };
        for (wrap, kek) in [
            (password_wrap, input.password_kek),
            (recovery_wrap, recovery_kek),
        ] {
            let opened = unwrap_vk(&ctx, kek, wrap)?;
            if !opened.same_vault_key(new) || opened.auth_public_key() != self.pk_a {
                return Err(Error::Decrypt);
            }
        }
        Ok(())
    }
}
