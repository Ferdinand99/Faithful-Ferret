//! The pinned record: what a device remembers about an account after the
//! first successful unlock, and the checks against it.
//!
//! Spec: Fase 1 § 4.2 ("Pinning og SK-bit"), § 4.3 ("Klienten husker høyeste
//! `kek_generation` og `vk_epoch` per konto og avviser lavere") and plan
//! U19 (the OPAQUE server public key is pinned too).
//!
//! The record is not secret, so its fields are public and it can be stored
//! as it is. The server cannot change any of it. A mismatch is a hard,
//! loud error ([`Error::Pinned`] or [`Error::KdfProfileDowngrade`]), never
//! "wrong password". The core only checks and updates the record; storing it
//! is the client's job.
//!
//! What may change, and only through [`Pinned::accept_unlock`]:
//!
//! * `ksf_profile` and the `kek_generation` of a method may go **up** (the
//!   client-driven KSF upgrade of § 4.2 and a changed password, § 4.3);
//! * `vk_epoch` may go up (a full rekey, § 4.7); `pk_a` follows the epoch;
//! * a missing `server_public_key` is filled in once.
//!
//! Everything else (the account, the server address, the SK bit and a set
//! server public key) never changes. Moving to another server means a new
//! pinned record made from the emergency sheet, not an edit of this one.

use crate::error::{Error, PinnedField};
use crate::ids::{AccountId, MethodId};
use crate::keys::{UnlockedVault, VaultContext};
use crate::ksf_profile::KsfProfile;
use crate::wrap::{Method, WrapRecord};

/// What the device has pinned for one account.
///
/// Spec: Fase 1 § 4.2: `(server_url, account_id, ksf_profile,
/// kek_generation_max, vk_epoch_max, sk_bit, pk_a)`, plus the OPAQUE server
/// public key (plan U19).
///
/// `kek_generation_max` is kept per method id: the generations of the
/// password, recovery and passkey wraps are independent counters (each wrap
/// is replaced on its own), so one number per account would reject a valid
/// recovery wrap after a password change.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Pinned {
    /// The server address, exactly as the client states it.
    pub server_url: String,
    /// The account.
    pub account_id: AccountId,
    /// The highest KSF profile used for the password wrap.
    pub ksf_profile: u8,
    /// The highest `kek_generation` seen per method id.
    pub kek_generation_max: Vec<(MethodId, u64)>,
    /// The highest `vk_epoch` seen.
    pub vk_epoch_max: u64,
    /// Whether the account has a secret key (SK). Never taken from the
    /// server.
    pub sk_bit: bool,
    /// `pk_a` of the vault at `vk_epoch_max`.
    pub pk_a: [u8; 32],
    /// The OPAQUE server public key, if pinned yet.
    pub server_public_key: Option<[u8; 32]>,
}

/// What the server (and the user) say at this unlock.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct ServerView<'a> {
    /// The address the client is talking to.
    pub server_url: &'a str,
    /// Whether the account has a secret key, as the server hints or the user
    /// answers. On a pinned device it must equal the pinned bit.
    pub sk_bit: bool,
    /// The OPAQUE server public key from the login, if the login has run.
    pub server_public_key: Option<[u8; 32]>,
}

impl Pinned {
    /// The record to store after the first successful unlock of an account
    /// on this device. The caller has already checked `ksf` against the
    /// client's own table and the floor, and the SK bit comes from the user.
    pub fn first_unlock(
        server_url: &str,
        ksf: KsfProfile,
        sk_bit: bool,
        server_public_key: Option<[u8; 32]>,
        ctx: &VaultContext,
        rec: &WrapRecord,
        vault: &UnlockedVault,
    ) -> Result<Pinned, Error> {
        if vault.context() != ctx {
            return Err(Error::Decrypt);
        }
        Ok(Pinned {
            server_url: server_url.to_owned(),
            account_id: ctx.account_id,
            ksf_profile: ksf.number(),
            kek_generation_max: vec![(rec.method_id, rec.kek_generation)],
            vk_epoch_max: ctx.vk_epoch,
            sk_bit,
            pk_a: vault.auth_public_key(),
            server_public_key,
        })
    }

    /// Checks what the server presents before a wrap is opened.
    ///
    /// Rejects, in this order: another account, another server address, a
    /// different SK bit, a different or missing server public key (when one
    /// is pinned), a password wrap with a lower KSF profile
    /// ([`Error::KdfProfileDowngrade`]), a wrap with a lower
    /// `kek_generation` than seen for that method, and a lower `vk_epoch`.
    /// Higher values are the allowed upgrade paths.
    ///
    /// Spec: Fase 1 § 4.2 and § 4.3.
    pub fn check_unlock(
        &self,
        ctx: &VaultContext,
        rec: &WrapRecord,
        seen: &ServerView<'_>,
    ) -> Result<(), Error> {
        if ctx.account_id != self.account_id {
            return Err(Error::Pinned(PinnedField::AccountId));
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
        if let Some((_, max)) = self
            .kek_generation_max
            .iter()
            .find(|(id, _)| *id == rec.method_id)
            && rec.kek_generation < *max
        {
            return Err(Error::Pinned(PinnedField::KekGeneration));
        }
        if ctx.vk_epoch < self.vk_epoch_max {
            return Err(Error::Pinned(PinnedField::VkEpoch));
        }
        Ok(())
    }

    /// Checks the opened vault: the same account and context as presented,
    /// and, within the pinned epoch, the pinned `pk_a`. In a higher epoch
    /// (a rekey) `pk_a` is new by design.
    pub fn check_unlocked(&self, vault: &UnlockedVault) -> Result<(), Error> {
        let ctx = vault.context();
        if ctx.account_id != self.account_id {
            return Err(Error::Pinned(PinnedField::AccountId));
        }
        if ctx.vk_epoch < self.vk_epoch_max {
            return Err(Error::Pinned(PinnedField::VkEpoch));
        }
        if ctx.vk_epoch == self.vk_epoch_max && vault.auth_public_key() != self.pk_a {
            return Err(Error::Pinned(PinnedField::AuthKey));
        }
        Ok(())
    }

    /// Runs both checks and, only if both pass, records the new maxima: the
    /// KSF profile of a password wrap, the wrap's `kek_generation`, the
    /// epoch (with its `pk_a`) and a server public key that was not pinned
    /// yet. Nothing changes when a check fails.
    pub fn accept_unlock(
        &mut self,
        ctx: &VaultContext,
        rec: &WrapRecord,
        seen: &ServerView<'_>,
        vault: &UnlockedVault,
    ) -> Result<(), Error> {
        self.check_unlock(ctx, rec, seen)?;
        if vault.context() != ctx {
            return Err(Error::Decrypt);
        }
        self.check_unlocked(vault)?;

        if let Method::Password { ksf } = &rec.method {
            self.ksf_profile = self.ksf_profile.max(ksf.number());
        }
        match self
            .kek_generation_max
            .iter_mut()
            .find(|(id, _)| *id == rec.method_id)
        {
            Some((_, max)) => *max = (*max).max(rec.kek_generation),
            None => self
                .kek_generation_max
                .push((rec.method_id, rec.kek_generation)),
        }
        self.vk_epoch_max = ctx.vk_epoch;
        self.pk_a = vault.auth_public_key();
        if self.server_public_key.is_none() {
            self.server_public_key = seen.server_public_key;
        }
        Ok(())
    }
}
