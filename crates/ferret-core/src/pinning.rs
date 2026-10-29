//! The pinned record: what a device remembers about an account after the
//! first successful unlock, and the only two ways to unlock with it.
//!
//! Spec: Fase 1 § 4.2 ("Pinning og SK-bit"), § 4.3 ("Klienten husker høyeste
//! `kek_generation` og `vk_epoch` per konto og avviser lavere") and plan
//! U19 (the OPAQUE server public key is pinned too).
//!
//! # Entry points
//!
//! * [`Pinned::unlock_server`] for the wraps the server stores (password,
//!   recovery, passkey). It checks the pins, opens the wrap, checks the vault
//!   and advances the record, as one step. The record changes only when the
//!   whole unlock succeeded; a failure of any kind leaves it as it was.
//! * [`Pinned::unlock_local`] for the PIN and device wraps. It works offline
//!   and has no server to compare with, so it checks only that the wrap
//!   belongs to the pinned account, vault and epoch (through the AAD) and
//!   that the vault's `pk_a` is the pinned one.
//!
//! The checks themselves are private: there is no way to open a wrap with a
//! pinned record and forget to check, or to check one wrap and open another.
//! ([`crate::unwrap_vk`] stays public for flows that have no pinned record
//! yet, such as the first unlock of a new device and account creation.)
//!
//! # What is recorded
//!
//! Only server-side methods have a `kek_generation` floor, and only floors
//! that cannot be reset by the server: the password and recovery wraps are
//! singletons (Fase 1 § 4.3: at least one of each), so they are keyed by
//! method **type**, and a fresh `method_id` after a password change does not
//! start from zero. A passkey wrap is keyed by its `credential_id`. PIN and
//! device wraps are never recorded: their AAD does not bind a generation, and
//! a local wrap that someone can edit must not be able to raise a floor.
//!
//! A device that unlocks with the password never sees the recovery or
//! passkey wraps. Their floors are seeded from the decrypted method manifest
//! with [`Pinned::seed_from_manifest`] (see [`MethodManifestView`]); a passkey
//! floor is keyed by the credential id that the manifest itself carries.
//!
//! The record has a fixed upper size ([`MAX_FLOORS`], [`MAX_URL_LEN`],
//! [`MAX_CREDENTIAL_ID_LEN`]) and rejects generations above
//! [`MAX_GENERATION`] as malformed, so a hostile value cannot brick later
//! unlocks or make the record grow without bound.
//!
//! # What may change
//!
//! `ksf_profile`, the generation floors and `vk_epoch` (with its `pk_a`) only
//! go up, and only through a successful unlock. The account, the vault, the
//! server address, the SK bit and a set server public key never change.
//! Moving to another server means a new pinned record from the emergency
//! sheet, not an edit of this one.
//!
//! # Trust on first use of the server key
//!
//! `server_public_key` is optional so that a record can exist before the
//! first login has shown the key. While it is `None`, the next successful
//! server unlock pins whatever key the server shows, once (TOFU, by design,
//! plan U19). From then on a different or missing key is a hard error.

use crate::error::{Error, MalformedKind, PinnedField};
use crate::ids::{AccountId, VaultId};
use crate::item::Manifest;
use crate::keys::{UnlockedVault, VaultContext};
use crate::ksf_profile::KsfProfile;
use crate::secret::Kek;
use crate::wrap::{Method, WrapRecord, unwrap_vk};

/// The most generation floors a record holds (password, recovery and passkey
/// wraps).
pub const MAX_FLOORS: usize = 64;
/// The longest server address a record holds, in bytes (plan U17).
pub const MAX_URL_LEN: usize = 512;
/// The longest passkey credential id a record holds, in bytes (WebAuthn
/// allows 1023).
pub const MAX_CREDENTIAL_ID_LEN: usize = 1024;
/// The highest `kek_generation` a record accepts. A generation counts
/// password changes; a larger one is not a real value.
pub const MAX_GENERATION: u64 = u32::MAX as u64;

/// Which server-side wrap a generation floor belongs to.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum MethodKey {
    /// The password wrap, whatever its `method_id`.
    Password,
    /// The recovery wrap, whatever its `method_id`.
    Recovery,
    /// A passkey wrap, by credential id.
    Prf(Vec<u8>),
}

impl MethodKey {
    /// The key of a method, or `None` for the local methods (PIN, device),
    /// which have no floor.
    pub fn of(method: &Method) -> Option<MethodKey> {
        match method {
            Method::Password { .. } => Some(MethodKey::Password),
            Method::Recovery => Some(MethodKey::Recovery),
            Method::Prf { credential_id, .. } => Some(MethodKey::Prf(credential_id.clone())),
            Method::Pin { .. } | Method::Device => None,
        }
    }
}

/// One entry of [`MethodManifestView`].
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct MethodFloor {
    /// The wrap.
    pub key: MethodKey,
    /// Its `kek_generation` according to the manifest.
    pub kek_generation: u64,
}

/// What the pinned record needs from the decrypted method manifest (Fase 1
/// § 4.3, F-07): the `kek_generation` of every server-stored method.
///
/// Made from a decrypted [`Manifest`] only: the credential id of a passkey
/// floor comes from the authenticated manifest entry, never from a mapping
/// the server supplies. [`Pinned::seed_from_manifest`] takes the manifest and
/// builds the view itself, so a client cannot seed floors from a hand-made
/// list. (A view can be built by hand only with `test-support`.) It holds at
/// most one entry per key and at most [`MAX_FLOORS`] entries.
#[derive(Clone, PartialEq, Eq, Debug, Default)]
pub struct MethodManifestView {
    /// The methods, at most one entry per key.
    pub methods: Vec<MethodFloor>,
}

impl MethodManifestView {
    /// The floors of the server-stored methods in a decrypted manifest.
    ///
    /// * password (`t` = 1) and recovery (`t` = 2) are keyed by type;
    /// * a passkey (`t` = 3) is keyed by the `credential_id` in its manifest
    ///   entry; an entry without one is `Malformed(ItemBody)`;
    /// * PIN and device (`t` = 4, 5) are local and have no floor, and a
    ///   method type this version does not know has none either;
    /// * two entries for the same key are `Malformed(ItemBody)`: an
    ///   authentic manifest never has them, and picking one would be a
    ///   guess.
    ///
    /// Spec: Fase 1 § 4.3 (method manifest, F-07).
    pub(crate) fn from_manifest(manifest: &Manifest) -> Result<Self, Error> {
        let mut methods: Vec<MethodFloor> = Vec::new();
        for entry in &manifest.methods {
            let key = match entry.method_type {
                1 => MethodKey::Password,
                2 => MethodKey::Recovery,
                3 => MethodKey::Prf(
                    entry
                        .credential_id
                        .clone()
                        .ok_or(Error::Malformed(MalformedKind::ItemBody))?,
                ),
                _ => continue,
            };
            if methods.iter().any(|m| m.key == key) {
                return Err(Error::Malformed(MalformedKind::ItemBody));
            }
            methods.push(MethodFloor {
                key,
                kek_generation: entry.kek_generation,
            });
        }
        Ok(Self { methods })
    }
}

/// What the device has pinned for one account.
///
/// Spec: Fase 1 § 4.2: `(server_url, account_id, ksf_profile,
/// kek_generation_max, vk_epoch_max, sk_bit, pk_a)`, plus the vault and the
/// OPAQUE server public key (plan U19).
///
/// Build it with [`Pinned::first_unlock`] and store it. The fields are public
/// so that a client can save and load the record; changing them by hand
/// bypasses the checks.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Pinned {
    /// The server address, exactly as the client states it.
    pub server_url: String,
    /// The account.
    pub account_id: AccountId,
    /// The vault.
    pub vault_id: VaultId,
    /// The highest KSF profile used for the password wrap.
    pub ksf_profile: u8,
    /// The highest `kek_generation` seen per server-side wrap.
    pub kek_generation_max: Vec<(MethodKey, u64)>,
    /// The highest `vk_epoch` seen.
    pub vk_epoch_max: u64,
    /// Whether the account has a secret key (SK). Never taken from the
    /// server.
    pub sk_bit: bool,
    /// `pk_a` of the vault at `vk_epoch_max`.
    pub pk_a: [u8; 32],
    /// The OPAQUE server public key, if pinned yet (see the module docs).
    pub server_public_key: Option<[u8; 32]>,
}

/// What the server (and the user) say at this unlock.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct ServerView<'a> {
    /// The address the client is talking to.
    pub server_url: &'a str,
    /// The account, vault and epoch the server presents the wrap for.
    pub context: VaultContext,
    /// Whether the account has a secret key, as the server hints or the user
    /// answers. On a pinned device it must equal the pinned bit.
    pub sk_bit: bool,
    /// The OPAQUE server public key from the login, if the login has run.
    pub server_public_key: Option<[u8; 32]>,
}

fn malformed() -> Error {
    Error::Malformed(MalformedKind::PinnedRecord)
}

/// Checks the size limits of one floor.
fn check_floor(key: &MethodKey, generation: u64) -> Result<(), Error> {
    if generation > MAX_GENERATION {
        return Err(malformed());
    }
    if let MethodKey::Prf(credential_id) = key
        && credential_id.len() > MAX_CREDENTIAL_ID_LEN
    {
        return Err(malformed());
    }
    Ok(())
}

impl Pinned {
    /// The first unlock of an account on this device: opens `rec` with `kek`
    /// and pins what it showed. The caller has already checked `ksf`
    /// against the client's own table and the floor, and `sk_bit` comes from
    /// the user. `rec` must be a server-side wrap.
    pub fn first_unlock(
        server_url: &str,
        ksf: KsfProfile,
        sk_bit: bool,
        server_public_key: Option<[u8; 32]>,
        ctx: &VaultContext,
        rec: &WrapRecord,
        kek: &Kek,
    ) -> Result<(Pinned, UnlockedVault), Error> {
        let key = MethodKey::of(&rec.method).ok_or(Error::Unsupported)?;
        check_floor(&key, rec.kek_generation)?;
        if server_url.len() > MAX_URL_LEN {
            return Err(malformed());
        }
        let vault = unwrap_vk(ctx, kek, rec)?;
        let pinned = Pinned {
            server_url: server_url.to_owned(),
            account_id: ctx.account_id,
            vault_id: ctx.vault_id,
            ksf_profile: ksf.number(),
            kek_generation_max: vec![(key, rec.kek_generation)],
            vk_epoch_max: ctx.vk_epoch,
            sk_bit,
            pk_a: vault.auth_public_key(),
            server_public_key,
        };
        Ok((pinned, vault))
    }

    /// The floor recorded for `key`.
    fn floor(&self, key: &MethodKey) -> Option<u64> {
        self.kek_generation_max
            .iter()
            .find(|(k, _)| k == key)
            .map(|(_, g)| *g)
    }

    /// Raises (or creates) the floor of `key`. The caller has checked the
    /// limits.
    fn raise_floor(&mut self, key: MethodKey, generation: u64) {
        match self.kek_generation_max.iter_mut().find(|(k, _)| *k == key) {
            Some((_, g)) => *g = (*g).max(generation),
            None => self.kek_generation_max.push((key, generation)),
        }
    }

    /// The `kek_generation` a new wrap of `key` gets: the floor plus one. A
    /// key without a floor, or a generation past [`MAX_GENERATION`], is
    /// `Malformed(PinnedRecord)`: seed the floors from the manifest first.
    pub(crate) fn next_generation(&self, key: &MethodKey) -> Result<u64, Error> {
        let next = self
            .floor(key)
            .and_then(|floor| floor.checked_add(1))
            .ok_or_else(malformed)?;
        if next > MAX_GENERATION {
            return Err(malformed());
        }
        Ok(next)
    }

    /// Seeds the floors of methods this device never unlocks with from the
    /// decrypted method manifest. Password and recovery entries are keyed by
    /// type, a passkey by the credential id in its entry; PIN, device and
    /// unknown method types give no floor. A floor only goes up. Everything is
    /// checked first; on an error the record is unchanged.
    ///
    /// The manifest must be for the pinned epoch or a later one, and gives
    /// `Malformed(ItemBody)` for a passkey entry without a credential id or
    /// two entries for one key.
    pub fn seed_from_manifest(&mut self, manifest: &Manifest) -> Result<(), Error> {
        if manifest.vk_epoch < self.vk_epoch_max {
            return Err(Error::Pinned(PinnedField::VkEpoch));
        }
        let view = MethodManifestView::from_manifest(manifest)?;
        self.seed_from_view(&view)
    }

    /// The seeding step of [`Pinned::seed_from_manifest`] for a view.
    ///
    /// The view must have at most one entry per key and at most
    /// [`MAX_FLOORS`] entries (a longer view is refused before it is
    /// scanned, so the work is bounded). It fails with
    /// `malformed_pinned_record` for a repeated key, a generation above
    /// [`MAX_GENERATION`], an over-long credential id, or more than
    /// [`MAX_FLOORS`] floors in total.
    pub(crate) fn seed_from_view(&mut self, view: &MethodManifestView) -> Result<(), Error> {
        if view.methods.len() > MAX_FLOORS {
            return Err(malformed());
        }
        let mut new_keys: usize = 0;
        for (i, entry) in view.methods.iter().enumerate() {
            check_floor(&entry.key, entry.kek_generation)?;
            if view
                .methods
                .iter()
                .take(i)
                .any(|earlier| earlier.key == entry.key)
            {
                return Err(malformed());
            }
            if self.floor(&entry.key).is_none() {
                new_keys = new_keys.saturating_add(1);
            }
        }
        if self.kek_generation_max.len().saturating_add(new_keys) > MAX_FLOORS {
            return Err(malformed());
        }
        for entry in &view.methods {
            self.raise_floor(entry.key.clone(), entry.kek_generation);
        }
        Ok(())
    }

    /// Unlocks with a wrap the server stores (password, recovery, passkey).
    ///
    /// In this order, and only the last step changes anything:
    ///
    /// 1. the pins: account, vault, server address, SK bit, server public
    ///    key (when pinned), KSF profile ([`Error::KdfProfileDowngrade`] if
    ///    lower), the wrap's `kek_generation` against its floor, and the
    ///    epoch against `vk_epoch_max`;
    /// 2. the wrap is opened ([`Error::Decrypt`] for any failure);
    /// 3. within the pinned epoch the vault's `pk_a` must be the pinned one
    ///    (in a higher epoch it is new, by design);
    /// 4. the record advances: KSF profile, the wrap's floor, epoch and
    ///    `pk_a`, and a server key that was not pinned yet.
    ///
    /// A PIN or device wrap is refused with [`Error::Unsupported`]; use
    /// [`Pinned::unlock_local`].
    pub fn unlock_server(
        &mut self,
        seen: &ServerView<'_>,
        rec: &WrapRecord,
        kek: &Kek,
    ) -> Result<UnlockedVault, Error> {
        let ctx = seen.context;
        let key = MethodKey::of(&rec.method).ok_or(Error::Unsupported)?;

        // 1. The pins.
        if ctx.account_id != self.account_id {
            return Err(Error::Pinned(PinnedField::AccountId));
        }
        if ctx.vault_id != self.vault_id {
            return Err(Error::Pinned(PinnedField::VaultId));
        }
        if seen.server_url != self.server_url {
            return Err(Error::Pinned(PinnedField::ServerUrl));
        }
        if seen.sk_bit != self.sk_bit {
            return Err(Error::Pinned(PinnedField::SkBit));
        }
        if let Some(pinned) = &self.server_public_key
            && seen.server_public_key.as_ref() != Some(pinned)
        {
            return Err(Error::Pinned(PinnedField::ServerKey));
        }
        if let Method::Password { ksf } = &rec.method
            && ksf.number() < self.ksf_profile
        {
            return Err(Error::KdfProfileDowngrade);
        }
        check_floor(&key, rec.kek_generation)?;
        match self.floor(&key) {
            Some(floor) if rec.kek_generation < floor => {
                return Err(Error::Pinned(PinnedField::KekGeneration));
            }
            None if self.kek_generation_max.len() >= MAX_FLOORS => return Err(malformed()),
            _ => {}
        }
        if ctx.vk_epoch < self.vk_epoch_max {
            return Err(Error::Pinned(PinnedField::VkEpoch));
        }

        // 2. Open the wrap.
        let vault = unwrap_vk(&ctx, kek, rec)?;

        // 3. The vault.
        if ctx.vk_epoch == self.vk_epoch_max && vault.auth_public_key() != self.pk_a {
            return Err(Error::Pinned(PinnedField::AuthKey));
        }

        // 4. Advance.
        if let Method::Password { ksf } = &rec.method {
            self.ksf_profile = self.ksf_profile.max(ksf.number());
        }
        self.raise_floor(key, rec.kek_generation);
        self.vk_epoch_max = ctx.vk_epoch;
        self.pk_a = vault.auth_public_key();
        if self.server_public_key.is_none() {
            self.server_public_key = seen.server_public_key;
        }
        Ok(vault)
    }

    /// Unlocks with a PIN or device wrap. Works offline and changes nothing.
    ///
    /// The wrap is opened for the pinned account, vault and epoch, so a wrap
    /// made for another account, vault or epoch (for example before a
    /// rekey) fails with [`Error::Decrypt`]. The vault's `pk_a` must be the
    /// pinned one. A server-side wrap is refused with [`Error::Unsupported`];
    /// use [`Pinned::unlock_server`].
    pub fn unlock_local(&self, rec: &WrapRecord, kek: &Kek) -> Result<UnlockedVault, Error> {
        if MethodKey::of(&rec.method).is_some() {
            return Err(Error::Unsupported);
        }
        let ctx = VaultContext {
            account_id: self.account_id,
            vault_id: self.vault_id,
            vk_epoch: self.vk_epoch_max,
        };
        let vault = unwrap_vk(&ctx, kek, rec)?;
        if vault.auth_public_key() != self.pk_a {
            return Err(Error::Pinned(PinnedField::AuthKey));
        }
        Ok(vault)
    }
}
