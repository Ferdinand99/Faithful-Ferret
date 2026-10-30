//! Wrapping the vault key under an unlock method's KEK, with key commitment,
//! and opening it again.
//!
//! Spec: Fase 1 § 4.3 ("Innpakning", "Nøkkelforpliktelse") and § 7.2 (PIN).
//!
//! ```text
//! wrap     = AEAD(key = KEK_x, nonce, pt = VK, aad = aad_wrap)         72 bytes
//! aad_wrap = TLV[label="ferret/v1/wrap", suite, account_id, vault_id,
//!                method_type, method_id, vk_epoch, kek_generation,
//!                + method-specific]
//! ```
//!
//! `password` and local `pin` wraps carry a key commitment, 32 bytes at the
//! end: `commit = HKDF(salt = none, ikm = KEK, info = "ferret/v1/commit")`.
//! [`unwrap_vk`] compares it in constant time **before** the AEAD is opened.
//! Every failure of [`unwrap_vk`] is the single [`Error::Decrypt`].

use crate::error::{Error, InputError};
use crate::ids::MethodId;
use crate::keys::{UnlockedVault, VaultContext};
use crate::ksf_profile::KsfProfile;
use crate::prim::aead::{aead_open, aead_seal};
use crate::prim::{ct::commit_eq, hkdf::hkdf_sha256};
use crate::rng::SecureRng;
use crate::secret::{Kek, VaultKey};
use crate::tlv::{SUITE, Tlv, tag};

/// Label of the generic wrap AAD. Spec: Fase 1 § 4.3.
const LABEL_WRAP: &str = "ferret/v1/wrap";
/// Label of the PIN wrap AAD. Spec: Fase 1 § 7.2.
const LABEL_PIN: &str = "ferret/v1/pin";
/// `info` of the key commitment. Spec: Fase 1 § 4.3.
const INFO_COMMIT: &[u8] = b"ferret/v1/commit";

/// Length of the key commitment in bytes.
pub const COMMIT_LEN: usize = 32;
/// Length of a wrap without a commitment: `nonce (24) ‖ VK (32) ‖ tag (16)`.
pub const WRAP_LEN: usize = 24 + 32 + 16;
/// Length of a wrap with a commitment.
pub const WRAP_WITH_COMMIT_LEN: usize = WRAP_LEN + COMMIT_LEN;

/// `method_type` values. Spec: Fase 1 § 3.1 (table).
const TYPE_PASSWORD: u8 = 1;
const TYPE_RECOVERY: u8 = 2;
const TYPE_PRF: u8 = 3;
const TYPE_PIN: u8 = 4;
const TYPE_DEVICE: u8 = 5;

/// An unlock method and its method-specific data (the part that is in the
/// AAD).
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum Method {
    /// The master password, through OPAQUE. The `kdf` field of the AAD is
    /// the profile's parameters.
    Password {
        /// The KSF profile the `export_key` was made with.
        ksf: KsfProfile,
    },
    /// The recovery key.
    Recovery,
    /// A passkey with the PRF extension.
    Prf {
        /// The credential id (also part of the KEK salt).
        credential_id: Vec<u8>,
        /// The 32-byte PRF salt of this registration.
        prf_salt: [u8; 32],
    },
    /// A local PIN (browser extension, step B on mobile). Never uploaded.
    Pin {
        /// The 16-byte salt of the Argon2id stretching.
        device_salt: [u8; 16],
    },
    /// A local device key. Never uploaded; no commitment.
    Device,
}

impl Method {
    /// The `method_type` byte. Spec: Fase 1 § 3.1.
    pub const fn type_code(&self) -> u8 {
        match self {
            Method::Password { .. } => TYPE_PASSWORD,
            Method::Recovery => TYPE_RECOVERY,
            Method::Prf { .. } => TYPE_PRF,
            Method::Pin { .. } => TYPE_PIN,
            Method::Device => TYPE_DEVICE,
        }
    }

    /// Whether wraps of this method end with a key commitment. Spec: Fase 1
    /// § 4.3 (`password` and `pin` only).
    pub const fn has_commit(&self) -> bool {
        matches!(self, Method::Password { .. } | Method::Pin { .. })
    }

    /// The length of a wrap of this method.
    pub const fn wrap_len(&self) -> usize {
        if self.has_commit() {
            WRAP_WITH_COMMIT_LEN
        } else {
            WRAP_LEN
        }
    }
}

/// A stored wrap of the vault key.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct WrapRecord {
    /// The method's id.
    pub method_id: MethodId,
    /// Counts how often the method's KEK has changed.
    pub kek_generation: u64,
    /// The method and its AAD data.
    pub method: Method,
    /// `nonce ‖ ct ‖ tag`, plus the commitment for `password` and `pin`.
    pub wrap: Vec<u8>,
}

/// The AAD of a wrap.
///
/// Spec: Fase 1 § 4.3. The generic AAD has no `version` field (unlike the
/// item and item-key AADs): `TLV[label="ferret/v1/wrap", suite, account_id,
/// vault_id, method_type, method_id, vk_epoch, kek_generation, + method-specific]`
/// with `kdf` (12 bytes) for `password`, `credential_id` and `prf_salt` for
/// `prf`, and nothing for `recovery` and `device`.
///
/// The `pin` wrap uses the AAD of Fase 1 § 7.2, in the same field order as
/// `aad_wrap`: `TLV[label="ferret/v1/pin", suite, account_id, vault_id,
/// method_type=4, method_id, vk_epoch, device_salt]`. It has no
/// `kek_generation`: the wrap exists only on this device and is replaced,
/// never rolled forward.
pub(crate) fn wrap_aad(
    ctx: &VaultContext,
    method_id: &MethodId,
    kek_generation: u64,
    method: &Method,
) -> Result<Vec<u8>, Error> {
    if let Method::Pin { device_salt } = method {
        return Tlv::new()
            .label(LABEL_PIN)
            .u8(tag::SUITE, SUITE)
            .bytes(tag::ACCOUNT_ID, ctx.account_id.as_bytes())?
            .bytes(tag::VAULT_ID, ctx.vault_id.as_bytes())?
            .u8(tag::METHOD_TYPE, TYPE_PIN)
            .bytes(tag::METHOD_ID, method_id.as_bytes())?
            .u64(tag::VK_EPOCH, ctx.vk_epoch)
            .bytes(tag::DEVICE_SALT, device_salt)?
            .finish();
    }
    let aad = Tlv::new()
        .label(LABEL_WRAP)
        .u8(tag::SUITE, SUITE)
        .bytes(tag::ACCOUNT_ID, ctx.account_id.as_bytes())?
        .bytes(tag::VAULT_ID, ctx.vault_id.as_bytes())?
        .u8(tag::METHOD_TYPE, method.type_code())
        .bytes(tag::METHOD_ID, method_id.as_bytes())?
        .u64(tag::VK_EPOCH, ctx.vk_epoch)
        .u64(tag::KEK_GENERATION, kek_generation);
    match method {
        Method::Password { ksf } => {
            let p = ksf.params();
            let mut kdf = [0u8; 12];
            let (m, tp) = kdf.split_at_mut(4);
            m.copy_from_slice(&p.m_kib.to_be_bytes());
            let (t, par) = tp.split_at_mut(4);
            t.copy_from_slice(&p.t.to_be_bytes());
            par.copy_from_slice(&p.p.to_be_bytes());
            aad.bytes(tag::KDF, &kdf)?.finish()
        }
        Method::Prf {
            credential_id,
            prf_salt,
        } => {
            // The salt is public and random per registration (Fase 1 § 7.2,
            // F-11); all zero is a missing salt, never a random one.
            if prf_salt.iter().all(|b| *b == 0) {
                return Err(Error::InvalidInput(InputError::AllZero));
            }
            aad.bytes(tag::CREDENTIAL_ID, credential_id)?
                .bytes(tag::PRF_SALT, prf_salt)?
                .finish()
        }
        Method::Recovery | Method::Device => aad.finish(),
        // Handled above; kept explicit so a new method cannot fall through.
        Method::Pin { .. } => Err(Error::Unsupported),
    }
}

/// The key commitment of a KEK.
///
/// Spec: Fase 1 § 4.3: `commit = HKDF(salt = none, ikm = KEK_x,
/// info = "ferret/v1/commit")`. An empty salt is the same as 32 zero bytes
/// (RFC 5869 section 2.2).
pub(crate) fn commit_of(kek: &Kek) -> Result<[u8; COMMIT_LEN], Error> {
    let mut out = [0u8; COMMIT_LEN];
    hkdf_sha256(&[], kek.expose(), INFO_COMMIT, &mut out)?;
    Ok(out)
}

/// A fresh PRF salt for one passkey registration: 32 random bytes from
/// `rng` (one draw). Every registration needs its own; the salt is public
/// and stored with the wrap. A salt that is all zero is refused by
/// [`wrap_vk`] and by the unlock.
///
/// Spec: Fase 1 § 7.2 (F-11: the PRF salt is 32 random bytes per
/// registration).
pub fn prf_salt_new<R: SecureRng>(rng: &mut R) -> [u8; 32] {
    let mut salt = [0u8; 32];
    rng.fill(&mut salt);
    salt
}

/// Wraps `vk` under `kek` for one unlock method.
///
/// Draws the 24-byte nonce from `rng` in one call (the only draw). The
/// result is 104 bytes for `password` and `pin`, 72 bytes for the others.
/// A `prf` method with an all-zero salt is `input_all_zero`.
///
/// Spec: Fase 1 § 4.3, § 5.4 and § 7.2.
pub fn wrap_vk<R: SecureRng>(
    rng: &mut R,
    ctx: &VaultContext,
    vk: &VaultKey,
    kek: &Kek,
    method_id: MethodId,
    kek_generation: u64,
    method: Method,
) -> Result<WrapRecord, Error> {
    let aad = wrap_aad(ctx, &method_id, kek_generation, &method)?;
    let mut wrap = aead_seal(rng, kek.expose(), &aad, vk.expose().as_slice())?;
    if method.has_commit() {
        wrap.extend_from_slice(&commit_of(kek)?);
    }
    Ok(WrapRecord {
        method_id,
        kek_generation,
        method,
        wrap,
    })
}

impl UnlockedVault {
    /// Wraps this vault's key for another unlock method (a PIN, a passkey):
    /// [`wrap_vk`] with the vault's own context and key, so a binding never
    /// needs the vault key itself. Draws the 24-byte nonce.
    ///
    /// Spec: Fase 1 § 4.3 and § 7.2.
    pub fn wrap_for_method<R: SecureRng>(
        &self,
        rng: &mut R,
        kek: &Kek,
        method_id: MethodId,
        kek_generation: u64,
        method: Method,
    ) -> Result<WrapRecord, Error> {
        wrap_vk(
            rng,
            self.context(),
            self.vault_key(),
            kek,
            method_id,
            kek_generation,
            method,
        )
    }
}

/// Opens a wrap and derives everything from the vault key it holds.
///
/// For `password` and `pin` the commitment is compared first, in constant
/// time through `subtle`, and the AEAD is not run when it differs. Every
/// failure (a wrong length, a wrong commitment, a wrong key, a changed AAD
/// field, a changed byte) is the single [`Error::Decrypt`], so nothing tells
/// the caller which step failed.
///
/// Spec: Fase 1 § 4.3 ("Mottaker sjekker `commit` i konstant tid **før**
/// AEAD åpnes") and § 5.3.
pub fn unwrap_vk(ctx: &VaultContext, kek: &Kek, rec: &WrapRecord) -> Result<UnlockedVault, Error> {
    open_vault_key(ctx, kek, rec)
        .and_then(|vk| UnlockedVault::from_vault_key(*ctx, vk))
        .map_err(|_| Error::Decrypt)
}

fn open_vault_key(ctx: &VaultContext, kek: &Kek, rec: &WrapRecord) -> Result<VaultKey, Error> {
    if rec.wrap.len() != rec.method.wrap_len() {
        return Err(Error::Decrypt);
    }
    let (sealed, commit) = rec.wrap.split_at(WRAP_LEN);
    if rec.method.has_commit() {
        let expected = commit_of(kek)?;
        // `commit` has COMMIT_LEN bytes (the length of the wrap was checked).
        let same = <&[u8; COMMIT_LEN]>::try_from(commit)
            .map(|got| commit_eq(&expected, got))
            .unwrap_or(false);
        if !same {
            return Err(Error::Decrypt);
        }
    }
    let aad = wrap_aad(ctx, &rec.method_id, rec.kek_generation, &rec.method)?;
    let mut pt = aead_open(kek.expose(), &aad, sealed)?;
    let mut bytes = [0u8; 32];
    if pt.len() != bytes.len() {
        return Err(Error::Decrypt);
    }
    bytes.copy_from_slice(&pt);
    zeroize::Zeroize::zeroize(&mut *pt);
    Ok(VaultKey::from_array_wiping(&mut bytes))
}
