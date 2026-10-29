//! The key hierarchy: the vault context, the keys derived from the vault key
//! (VK), the key-encryption keys (KEK) of the unlock methods and the
//! recovery signing key.
//!
//! Spec: Fase 1 § 4.3 (KEK derivations), § 4.5 (derivations from VK and
//! signature keys) and § 7.4 (PIN KEK). Every derivation is HKDF-SHA256
//! with a TLV salt (Fase 1 § 3.1) and a fixed `info`. Intermediate key bytes
//! live in [`Zeroizing`] buffers and are wiped on every path.

use crate::error::Error;
use crate::ids::{AccountId, VaultId};
use crate::ksf_profile::KsfProfile;
use crate::prim::ed25519::{Ed25519Key, ed25519_from_seed};
use crate::prim::{ct::ct_eq, hkdf::hkdf_sha256};
use crate::rng::SecureRng;
use crate::secret::{
    AuthSeed, ExportKey, KDel, KHead, KMeta, Kek, KekDevPin, PrfOutput, RecoveryKey, VaultKey,
};
use crate::text::Pin;
use crate::tlv::{Tlv, tag};
use zeroize::{ZeroizeOnDrop, Zeroizing};

/// Label of the vault key derivations. Spec: Fase 1 § 4.5.
const LABEL_VK_DERIVE: &str = "ferret/v1/vk-derive";
/// `info` of `K_head`. Spec: Fase 1 § 4.5.
const INFO_HEAD: &[u8] = b"ferret/v1/head";
/// `info` of `K_del`. Spec: Fase 1 § 4.5.
const INFO_TOMB: &[u8] = b"ferret/v1/tomb";
/// `info` of `K_meta`. Spec: Fase 1 § 4.5.
const INFO_META: &[u8] = b"ferret/v1/meta";
/// `info` of `seed_a`. Spec: Fase 1 § 4.5.
const INFO_AUTH_SIGN: &[u8] = b"ferret/v1/auth-sign";

/// Label and `info` of `seed_r`. Spec: Fase 1 § 4.5.
const LABEL_RECOVERY_SIGN: &str = "ferret/v1/recovery-sign";
const INFO_RECOVERY_SIGN: &[u8] = b"ferret/v1/recovery-sign";

/// Labels and `info` of the KEKs. Spec: Fase 1 § 4.3.
const LABEL_KEK_PASSWORD: &str = "ferret/v1/kek/password";
const INFO_KEK_PASSWORD: &[u8] = b"ferret/v1/kek/password";
const LABEL_KEK_RECOVERY: &str = "ferret/v1/recovery";
const INFO_KEK_RECOVERY: &[u8] = b"ferret/v1/kek/recovery";
const LABEL_KEK_PRF: &str = "ferret/v1/prf";
const INFO_KEK_PRF: &[u8] = b"ferret/v1/kek/prf";
/// Label and `info` of the mobile PIN KEK. Spec: Fase 1 § 7.4.
const LABEL_KEK_PIN: &str = "ferret/v1/kek/pin";
const INFO_KEK_PIN: &[u8] = b"ferret/v1/kek/pin";

/// What identifies a vault epoch: the account, the vault and `vk_epoch`.
/// Public, not secret.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct VaultContext {
    /// The account.
    pub account_id: AccountId,
    /// The vault.
    pub vault_id: VaultId,
    /// The epoch of the vault key; 1 at setup, +1 at every full rekey.
    pub vk_epoch: u64,
}

/// One HKDF-SHA256 output of 32 bytes in a wiping buffer.
fn derive32(salt: &[u8], ikm: &[u8], info: &[u8]) -> Result<Zeroizing<[u8; 32]>, Error> {
    let mut out = Zeroizing::new([0u8; 32]);
    hkdf_sha256(salt, ikm, info, out.as_mut_slice())?;
    Ok(out)
}

/// `vk_derive(name)` of Fase 1 § 4.5.
///
/// Spec: Fase 1 § 4.5:
/// `HKDF-SHA256(salt = TLV[label="ferret/v1/vk-derive", account_id,
/// vault_id, vk_epoch], ikm = VK, info = name, L = 32)`.
fn vk_derive(ctx: &VaultContext, vk: &VaultKey, name: &[u8]) -> Result<Zeroizing<[u8; 32]>, Error> {
    let salt = Tlv::new()
        .label(LABEL_VK_DERIVE)
        .bytes(tag::ACCOUNT_ID, ctx.account_id.as_bytes())?
        .bytes(tag::VAULT_ID, ctx.vault_id.as_bytes())?
        .u64(tag::VK_EPOCH, ctx.vk_epoch)
        .finish()?;
    derive32(&salt, vk.expose(), name)
}

/// The four keys derived from a vault key, as plain wiping buffers.
struct DerivedKeys {
    k_head: Zeroizing<[u8; 32]>,
    k_del: Zeroizing<[u8; 32]>,
    k_meta: Zeroizing<[u8; 32]>,
    seed_a: Zeroizing<[u8; 32]>,
}

fn derive_all(ctx: &VaultContext, vk: &VaultKey) -> Result<DerivedKeys, Error> {
    Ok(DerivedKeys {
        k_head: vk_derive(ctx, vk, INFO_HEAD)?,
        k_del: vk_derive(ctx, vk, INFO_TOMB)?,
        k_meta: vk_derive(ctx, vk, INFO_META)?,
        seed_a: vk_derive(ctx, vk, INFO_AUTH_SIGN)?,
    })
}

/// An unlocked vault: the vault key and everything derived from it for one
/// `vk_epoch`. There is no `Clone` and no `Debug`; all keys are wiped when
/// the value is dropped.
#[derive(ZeroizeOnDrop)]
pub struct UnlockedVault {
    /// Public ids and the epoch; nothing to wipe.
    #[zeroize(skip)]
    ctx: VaultContext,
    vk: VaultKey,
    k_head: KHead,
    k_del: KDel,
    k_meta: KMeta,
    /// `sk_a`, made from `seed_a`. The seed is wiped as soon as the key
    /// exists.
    sk_a: Ed25519Key,
}

impl UnlockedVault {
    /// Derives `K_head`, `K_del`, `K_meta` and `(sk_a, pk_a)` from `vk` for
    /// the epoch in `ctx`. Fails only if a TLV field cannot be encoded,
    /// which cannot happen for 16-byte ids.
    ///
    /// Spec: Fase 1 § 4.5.
    pub fn from_vault_key(ctx: VaultContext, vk: VaultKey) -> Result<Self, Error> {
        let mut keys = derive_all(&ctx, &vk)?;
        // `AuthSeed` wipes the seed as soon as the signing key exists.
        let seed_a = AuthSeed::from_array_wiping(&mut keys.seed_a);
        let sk_a = ed25519_from_seed(seed_a.expose());
        Ok(Self {
            ctx,
            vk,
            k_head: KHead::from_array_wiping(&mut keys.k_head),
            k_del: KDel::from_array_wiping(&mut keys.k_del),
            k_meta: KMeta::from_array_wiping(&mut keys.k_meta),
            sk_a,
        })
    }

    /// The account, vault and epoch of this vault.
    pub fn context(&self) -> &VaultContext {
        &self.ctx
    }

    /// `pk_a`, the public key of the authentication key pair.
    ///
    /// Spec: Fase 1 § 4.5 (auth-sign key).
    pub fn auth_public_key(&self) -> [u8; 32] {
        self.sk_a.public_key()
    }

    /// Whether both vaults hold the same vault key, in constant time.
    pub fn same_vault_key(&self, other: &UnlockedVault) -> bool {
        ct_eq(self.vk.expose(), other.vk.expose())
    }

    /// The vault key.
    pub(crate) fn vault_key(&self) -> &VaultKey {
        &self.vk
    }

    /// `K_head`.
    pub(crate) fn k_head(&self) -> &KHead {
        &self.k_head
    }

    /// `K_del`.
    #[allow(dead_code)] // first used by Task 6 (tombstones)
    pub(crate) fn k_del(&self) -> &KDel {
        &self.k_del
    }

    /// `K_meta`.
    pub(crate) fn k_meta(&self) -> &KMeta {
        &self.k_meta
    }

    /// `sk_a`.
    #[allow(dead_code)] // first used by Task 6 (mutation proofs)
    pub(crate) fn auth_key(&self) -> &Ed25519Key {
        &self.sk_a
    }
}

/// `seed_r` and its key pair.
///
/// Spec: Fase 1 § 4.5:
/// `seed_r = HKDF-SHA256(salt = TLV[label="ferret/v1/recovery-sign",
/// account_id], ikm = RK, info = "ferret/v1/recovery-sign", L = 32)`.
#[allow(dead_code)] // first used by Task 6 (recovery proofs)
pub(crate) fn recovery_signing_key(
    rk: &RecoveryKey,
    account_id: &AccountId,
) -> Result<Ed25519Key, Error> {
    let seed = recovery_seed(rk, account_id)?;
    Ok(ed25519_from_seed(&seed))
}

fn recovery_seed(rk: &RecoveryKey, account_id: &AccountId) -> Result<Zeroizing<[u8; 32]>, Error> {
    let salt = Tlv::new()
        .label(LABEL_RECOVERY_SIGN)
        .bytes(tag::ACCOUNT_ID, account_id.as_bytes())?
        .finish()?;
    derive32(&salt, rk.expose(), INFO_RECOVERY_SIGN)
}

/// `pk_r`, the public key that the server keeps to verify recovery proofs.
///
/// Spec: Fase 1 § 4.5 (`(sk_r, pk_r) = Ed25519(seed_r)`).
pub fn recovery_public_key(rk: &RecoveryKey, account_id: &AccountId) -> Result<[u8; 32], Error> {
    Ok(ed25519_from_seed(&*recovery_seed(rk, account_id)?).public_key())
}

/// `Argon2id(PIN, device_salt, profile 1, 32)`.
fn pin_stretch(pin: &Pin, device_salt: &[u8; 16]) -> Result<Zeroizing<[u8; 32]>, Error> {
    let mut out = Zeroizing::new([0u8; 32]);
    crate::prim::argon2::argon2id(
        pin.as_bytes(),
        device_salt,
        KsfProfile::P1.params(),
        out.as_mut_slice(),
    )?;
    Ok(out)
}

impl Kek {
    /// `KEK_pw`, from the OPAQUE export key.
    ///
    /// Spec: Fase 1 § 4.3:
    /// `HKDF(salt = TLV[label="ferret/v1/kek/password", account_id],
    /// ikm = export_key, info = "ferret/v1/kek/password")`.
    pub fn from_export_key(account_id: &AccountId, k: &ExportKey) -> Result<Kek, Error> {
        let salt = Tlv::new()
            .label(LABEL_KEK_PASSWORD)
            .bytes(tag::ACCOUNT_ID, account_id.as_bytes())?
            .finish()?;
        let mut kek = derive32(&salt, k.expose(), INFO_KEK_PASSWORD)?;
        Ok(Kek::from_array_wiping(&mut kek))
    }

    /// `KEK_rk`, from the recovery key.
    ///
    /// Spec: Fase 1 § 4.3:
    /// `HKDF(salt = TLV[label="ferret/v1/recovery", account_id], ikm = RK,
    /// info = "ferret/v1/kek/recovery")`.
    pub fn from_recovery_key(account_id: &AccountId, rk: &RecoveryKey) -> Result<Kek, Error> {
        let salt = Tlv::new()
            .label(LABEL_KEK_RECOVERY)
            .bytes(tag::ACCOUNT_ID, account_id.as_bytes())?
            .finish()?;
        let mut kek = derive32(&salt, rk.expose(), INFO_KEK_RECOVERY)?;
        Ok(Kek::from_array_wiping(&mut kek))
    }

    /// `KEK_prf`, from the output of the WebAuthn PRF extension.
    ///
    /// The salt has the `credential_id` and, by design, **no** `account_id`:
    /// the same credential and PRF output give the same KEK on every
    /// account. The wrap's AAD binds the account instead.
    ///
    /// Spec: Fase 1 § 4.3:
    /// `HKDF(salt = TLV[label="ferret/v1/prf", credential_id],
    /// ikm = prf_output, info = "ferret/v1/kek/prf")`.
    pub fn from_prf(credential_id: &[u8], out: &PrfOutput) -> Result<Kek, Error> {
        let salt = Tlv::new()
            .label(LABEL_KEK_PRF)
            .bytes(tag::CREDENTIAL_ID, credential_id)?
            .finish()?;
        let mut kek = derive32(&salt, out.expose(), INFO_KEK_PRF)?;
        Ok(Kek::from_array_wiping(&mut kek))
    }

    /// `KEK_pin` of the browser extension: Argon2id of the PIN alone, with
    /// profile 1 (64 MiB, `t = 3`, `p = 1`) and `device_salt` as the salt.
    ///
    /// The PIN is a convenience, not a security boundary, in the extension
    /// (Fase 1 § 7.1).
    ///
    /// Spec: Fase 1 § 7.2: `KEK_pin = Argon2id(PIN, device_salt, m = 64 MiB,
    /// t = 3, p = 1, L = 32)`.
    pub fn from_pin_extension(pin: &Pin, device_salt: &[u8; 16]) -> Result<Kek, Error> {
        let mut kek = pin_stretch(pin, device_salt)?;
        Ok(Kek::from_array_wiping(&mut kek))
    }

    /// `KEK_pin` on mobile (step B): the stretched PIN mixed with the
    /// hardware-bound `KEK_dev_pin`, so the PIN can only be tried on the
    /// device.
    ///
    /// Spec: Fase 1 § 7.4:
    /// `HKDF(salt = TLV[label="ferret/v1/kek/pin", device_salt],
    /// ikm = KEK_dev_pin ‖ Argon2id(PIN, device_salt, m=64 MiB, t=3, p=1, 32),
    /// info = "ferret/v1/kek/pin")`.
    pub fn from_pin_mobile(
        pin: &Pin,
        device_salt: &[u8; 16],
        kek_dev_pin: &KekDevPin,
    ) -> Result<Kek, Error> {
        let stretched = pin_stretch(pin, device_salt)?;
        let mut ikm = Zeroizing::new([0u8; 64]);
        let (head, tail) = ikm.split_at_mut(32);
        head.copy_from_slice(kek_dev_pin.expose());
        tail.copy_from_slice(stretched.as_slice());
        let salt = Tlv::new()
            .label(LABEL_KEK_PIN)
            .bytes(tag::DEVICE_SALT, device_salt)?
            .finish()?;
        let mut kek = derive32(&salt, ikm.as_slice(), INFO_KEK_PIN)?;
        Ok(Kek::from_array_wiping(&mut kek))
    }

    /// A fresh random KEK, for the local `device` method.
    pub fn generate<R: SecureRng>(rng: &mut R) -> Kek {
        Kek::random(rng)
    }
}

/// The raw derived keys of a vault key, for the vector runners (behind
/// `test-support`).
#[cfg(feature = "test-support")]
pub(crate) fn derived_key_bytes(ctx: &VaultContext, vk: &VaultKey) -> Result<[[u8; 32]; 4], Error> {
    let keys = derive_all(ctx, vk)?;
    Ok([*keys.k_head, *keys.k_del, *keys.k_meta, *keys.seed_a])
}

/// `seed_r` for the vector runners (behind `test-support`).
#[cfg(feature = "test-support")]
pub(crate) fn recovery_seed_bytes(
    rk: &RecoveryKey,
    account_id: &AccountId,
) -> Result<[u8; 32], Error> {
    Ok(*recovery_seed(rk, account_id)?)
}
