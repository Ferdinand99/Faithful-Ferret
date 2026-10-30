//! Signed proofs for sensitive requests.
//!
//! Spec: Fase 1 § 4.6.
//!
//! ```text
//! Ferret-Proof = Ed25519.Sign(sk_a,
//!     TLV[label="ferret/v1/mutation", op, account_id, nonce, vk_epoch,
//!         hash = SHA-256(request body)])
//! ```
//!
//! At recovery the key is `sk_r` and the label is `ferret/v1/recovery-req`.
//! `nonce` is the 32-byte challenge from `POST /api/auth/challenge`, used
//! once. `vk_epoch` is the epoch of the key that signs: the old epoch at a
//! rekey, the current one at recovery. The body is the exact bytes that are
//! sent; the core hashes them and never serialises JSON.
//!
//! `op` is a closed list ([`MutationOp`]). A new operation needs a change in
//! the design.

use crate::error::Error;
use crate::ids::AccountId;
use crate::keys::{UnlockedVault, recovery_signing_key};
use crate::prim::ed25519::{ed25519_sign, ed25519_verify};
use crate::secret::RecoveryKey;
use crate::tlv::{Tlv, tag};
use sha2::{Digest, Sha256};

/// Label of a proof signed by `sk_a`. Spec: Fase 1 § 4.6.
const LABEL_MUTATION: &str = "ferret/v1/mutation";
/// Label of a proof signed by `sk_r`. Spec: Fase 1 § 4.6.
const LABEL_RECOVERY_REQ: &str = "ferret/v1/recovery-req";

/// The operations a proof can be for. The list is closed; a new operation needs a change of the design.
#[non_exhaustive]
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum MutationOp {
    /// `unlock-method.add`
    UnlockMethodAdd,
    /// `unlock-method.remove`
    UnlockMethodRemove,
    /// `unlock-method.password.put`
    UnlockMethodPasswordPut,
    /// `unlock-method.recovery.put`
    UnlockMethodRecoveryPut,
    /// `recover`: signed by `sk_r` (see [`recovery_sign`]).
    Recover,
    /// `rekey`: signed by the old `sk_a`.
    Rekey,
}

impl MutationOp {
    /// Every operation, in the order of the design.
    pub const ALL: [MutationOp; 6] = [
        MutationOp::UnlockMethodAdd,
        MutationOp::UnlockMethodRemove,
        MutationOp::UnlockMethodPasswordPut,
        MutationOp::UnlockMethodRecoveryPut,
        MutationOp::Recover,
        MutationOp::Rekey,
    ];

    /// The ASCII name that goes into the proof.
    pub const fn name(self) -> &'static str {
        match self {
            MutationOp::UnlockMethodAdd => "unlock-method.add",
            MutationOp::UnlockMethodRemove => "unlock-method.remove",
            MutationOp::UnlockMethodPasswordPut => "unlock-method.password.put",
            MutationOp::UnlockMethodRecoveryPut => "unlock-method.recovery.put",
            MutationOp::Recover => "recover",
            MutationOp::Rekey => "rekey",
        }
    }

    /// The operation with this name, if it is on the list.
    pub fn from_name(name: &str) -> Option<MutationOp> {
        MutationOp::ALL.into_iter().find(|op| op.name() == name)
    }

    /// The label of the proof: `recover` has its own.
    const fn label(self) -> &'static str {
        match self {
            MutationOp::Recover => LABEL_RECOVERY_REQ,
            _ => LABEL_MUTATION,
        }
    }
}

/// `TLV[label, op, account_id, nonce, vk_epoch, hash = SHA-256(body)]`, the
/// bytes that are signed.
///
/// Spec: Fase 1 § 4.6.
pub(crate) fn proof_message(
    op: MutationOp,
    account_id: &AccountId,
    nonce: &[u8; 32],
    vk_epoch: u64,
    body: &[u8],
) -> Result<Vec<u8>, Error> {
    Tlv::new()
        .label(op.label())
        .bytes(tag::OP, op.name().as_bytes())?
        .bytes(tag::ACCOUNT_ID, account_id.as_bytes())?
        .bytes(tag::NONCE, nonce)?
        .u64(tag::VK_EPOCH, vk_epoch)
        .bytes(tag::HASH, &Sha256::digest(body))?
        .finish()
}

/// The operations that `sk_a` signs: [`MutationOp`] without `recover`.
#[non_exhaustive]
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum AuthOp {
    /// `unlock-method.add`
    UnlockMethodAdd,
    /// `unlock-method.remove`
    UnlockMethodRemove,
    /// `unlock-method.password.put`
    UnlockMethodPasswordPut,
    /// `unlock-method.recovery.put`
    UnlockMethodRecoveryPut,
    /// `rekey`: signed by the old `sk_a`.
    Rekey,
}

impl AuthOp {
    /// Every operation, in the order of the design.
    pub const ALL: [AuthOp; 5] = [
        AuthOp::UnlockMethodAdd,
        AuthOp::UnlockMethodRemove,
        AuthOp::UnlockMethodPasswordPut,
        AuthOp::UnlockMethodRecoveryPut,
        AuthOp::Rekey,
    ];

    /// The same operation in the full list.
    pub const fn op(self) -> MutationOp {
        match self {
            AuthOp::UnlockMethodAdd => MutationOp::UnlockMethodAdd,
            AuthOp::UnlockMethodRemove => MutationOp::UnlockMethodRemove,
            AuthOp::UnlockMethodPasswordPut => MutationOp::UnlockMethodPasswordPut,
            AuthOp::UnlockMethodRecoveryPut => MutationOp::UnlockMethodRecoveryPut,
            AuthOp::Rekey => MutationOp::Rekey,
        }
    }

    /// The ASCII name that goes into the proof.
    pub const fn name(self) -> &'static str {
        self.op().name()
    }

    /// The operation with this name, if `sk_a` signs it.
    pub fn from_name(name: &str) -> Option<AuthOp> {
        AuthOp::ALL.into_iter().find(|op| op.name() == name)
    }
}

impl MutationOp {
    /// The operation as one that `sk_a` signs; `None` for `recover`.
    pub const fn auth(self) -> Option<AuthOp> {
        match self {
            MutationOp::UnlockMethodAdd => Some(AuthOp::UnlockMethodAdd),
            MutationOp::UnlockMethodRemove => Some(AuthOp::UnlockMethodRemove),
            MutationOp::UnlockMethodPasswordPut => Some(AuthOp::UnlockMethodPasswordPut),
            MutationOp::UnlockMethodRecoveryPut => Some(AuthOp::UnlockMethodRecoveryPut),
            MutationOp::Recover => None,
            MutationOp::Rekey => Some(AuthOp::Rekey),
        }
    }
}

/// `pk_a`, the key that checks proofs of [`AuthOp`]s. A different type from
/// [`RecoveryPublicKey`], so the one cannot be passed for the other.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct AuthPublicKey([u8; 32]);

impl AuthPublicKey {
    /// Wraps the 32 bytes of `pk_a`.
    pub const fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// The 32 bytes.
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// `pk_r`, the key that checks recovery proofs.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct RecoveryPublicKey([u8; 32]);

impl RecoveryPublicKey {
    /// Wraps the 32 bytes of `pk_r`.
    pub const fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// The 32 bytes.
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// Signs a request with `sk_a`. The account and `vk_epoch` are those of
/// `vault`; at a rekey that is the old vault. `recover` is not an [`AuthOp`]:
/// only `sk_r` signs it, with [`recovery_sign`].
///
/// Spec: Fase 1 § 4.6.
pub fn auth_sign(
    vault: &UnlockedVault,
    op: AuthOp,
    nonce: &[u8; 32],
    body: &[u8],
) -> Result<[u8; 64], Error> {
    let ctx = vault.context();
    let message = proof_message(op.op(), &ctx.account_id, nonce, ctx.vk_epoch, body)?;
    ed25519_sign(vault.auth_key(), &message)
}

/// Signs a recovery request with `sk_r`, made from the recovery key.
/// `vk_epoch` is the current epoch of the vault.
///
/// Spec: Fase 1 § 4.5 and § 4.6.
pub fn recovery_sign(
    rk: &RecoveryKey,
    account_id: &AccountId,
    vk_epoch: u64,
    nonce: &[u8; 32],
    body: &[u8],
) -> Result<[u8; 64], Error> {
    let key = recovery_signing_key(rk, account_id)?;
    let message = proof_message(MutationOp::Recover, account_id, nonce, vk_epoch, body)?;
    ed25519_sign(&key, &message)
}

/// Checks the proof of an [`AuthOp`] against `pk_a`. Every failure is
/// `Decrypt`: a wrong key, op, account, nonce, epoch or body, a malformed
/// key, or a signature that is not canonical.
///
/// A server checks in addition that `nonce` is unused and under five minutes
/// old.
///
/// Spec: Fase 1 § 4.6.
pub fn verify_auth_proof(
    pk: &AuthPublicKey,
    op: AuthOp,
    account_id: &AccountId,
    nonce: &[u8; 32],
    vk_epoch: u64,
    body: &[u8],
    sig: &[u8; 64],
) -> Result<(), Error> {
    let message =
        proof_message(op.op(), account_id, nonce, vk_epoch, body).map_err(|_| Error::Decrypt)?;
    ed25519_verify(pk.as_bytes(), &message, sig)
}

/// Checks a recovery proof (`recover`, label `ferret/v1/recovery-req`)
/// against `pk_r`. Every failure is `Decrypt`.
///
/// Spec: Fase 1 § 4.6.
pub fn verify_recovery_proof(
    pk: &RecoveryPublicKey,
    account_id: &AccountId,
    nonce: &[u8; 32],
    vk_epoch: u64,
    body: &[u8],
    sig: &[u8; 64],
) -> Result<(), Error> {
    let message = proof_message(MutationOp::Recover, account_id, nonce, vk_epoch, body)
        .map_err(|_| Error::Decrypt)?;
    ed25519_verify(pk.as_bytes(), &message, sig)
}
