//! The one way to write a change of unlock methods.
//!
//! A change of the password wrap, of the recovery wrap, or of both goes through
//! [`apply`]: one `BEGIN IMMEDIATE` transaction that
//!
//! 1. checks that the session that asks is still one (it may have ended while
//!    its request waited for the write lock);
//! 2. reads the account: the OPAQUE record, the keys, the epoch;
//! 3. lets the route's `authorize` check the proof against exactly that row
//!    (the OPAQUE library, through `Proofs`) and parse the proven body;
//! 4. checks the content: the manifest envelope, the manifest's `rev` (the
//!    current one plus 1) and each new generation (strictly above the stored
//!    one, by at most `MAX_GENERATION_STEP`);
//! 5. writes the account, each wrap under its stored `method_id`, the manifest
//!    row and the vault's `seq`, each with a condition on what was read, so a
//!    write that finds the row changed is `409 write_conflict` and never a
//!    silent success;
//! 6. for a new master password and a recovery, ends every other session of
//!    the user on both origins and the user's pending sign-in codes, the
//!    sessions handed over from the asking session too (its admin session:
//!    it fails safe, the user signs in to the admin pages again); and the
//!    asking session when the permit says so (a recovery in a reset session).
//!    A new recovery key ends no session.
//!
//! Either all of it is in, or none of it. [`after_commit`] then tells the
//! streams about the new `seq` and the ended sessions, and asks for a backup.
//! The route calls it on the database thread right after the commit, so a
//! request whose client has gone away still announces what it committed.
//!
//! **Half-way sign-ins.** A sign-in that started with the old password keeps
//! what it needs to finish in its sealed login state. That state is bound to
//! the record it was made from (`ferret_server_auth::RecordBinding`), and the
//! sign-in route compares it with the account's record when the sign-in
//! finishes and again in the transaction that writes the session. A new
//! record written here therefore stops every such sign-in of this account,
//! whenever its state was saved, and touches no sign-in of anyone else. This
//! module does not have to remove login states.
//!
//! Nothing else writes these rows. The manifest row is written here with SQL
//! of its own: the item store refuses the manifest (a change to it needs a
//! signature of the account) and opens a transaction of its own.
//!
//! Spec: Fase 1 § 4.3 (changing MP, generations, the manifest), § 4.6 and
//! § 6.3.

use std::fmt;

use ed25519_dalek::VerifyingKey;
use ferret_core::envelope::{KIND_MANIFEST, parse_envelope};
use ferret_core::{AuthPublicKey, Error as CoreError, RecoveryPublicKey};
use ferret_server_auth::{
    AccountAuthState, ScopeEffect, SignedAccount, StoredRecord, ValidatedRecord, WriteBasis,
};
use rusqlite::{OptionalExtension as _, Transaction, TransactionBehavior, params};

use super::notify::SyncEvents;
use crate::auth::session::{Origin, end_all_credentials, lookup, within_limits};
use crate::error::{ApiError, StoreError};
use crate::ids::{AccountId, MANIFEST_ITEM_ID, MethodId, SidHash, VaultId};
use crate::state::BackupStatus;
use crate::wire::SealedRowJson;

/// `method_type` of the password wrap.
const TYPE_PASSWORD: u8 = 1;
/// `method_type` of the recovery wrap.
const TYPE_RECOVERY: u8 = 2;

/// The reason a backup is asked for after a change of unlock methods.
pub const BACKUP_REASON: &str = "unlock_methods";

/// The session that asks for a change, as its extractor read it.
#[derive(Clone, Copy, Debug)]
pub struct Writer {
    /// The account of the session.
    pub account: AccountId,
    /// The kit user of the session.
    pub user_id: i64,
    /// The session.
    pub sid: SidHash,
    /// The kit's session version the session was checked against.
    pub session_version: i64,
    /// Whether the session goes on after the change. It still ends when the
    /// permit says so ([`ScopeEffect::EndSession`]).
    pub keep_session: bool,
    /// The kind of change the route makes. `authorize` must give a change of
    /// this kind.
    pub kind: ChangeKind,
}

/// The kinds of [`UnlockChange`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ChangeKind {
    /// A new master password.
    Password,
    /// A new recovery key.
    Recovery,
    /// A recovery with the recovery key.
    Recover,
}

/// What a change writes, besides the manifest.
pub enum UnlockChange {
    /// A new master password: a new OPAQUE record and a new password wrap.
    Password {
        /// The new record, as the library checked it.
        record: ValidatedRecord,
        /// The profile the library accepted for it.
        profile: u8,
        /// The new password wrap.
        wrap: Vec<u8>,
        /// Its generation.
        generation: u32,
    },
    /// A new recovery key: a new recovery wrap and a new `pk_r`.
    Recovery {
        /// The new recovery wrap.
        wrap: Vec<u8>,
        /// Its generation.
        generation: u32,
        /// The new `pk_r`.
        pk_r: [u8; 32],
    },
    /// A recovery: a new record, both wraps and a new `pk_r`.
    Recover {
        /// The new record, as the library checked it.
        record: ValidatedRecord,
        /// The profile the library accepted for it.
        profile: u8,
        /// The new password wrap.
        pw_wrap: Vec<u8>,
        /// Its generation.
        pw_generation: u32,
        /// The new recovery wrap.
        rk_wrap: Vec<u8>,
        /// Its generation.
        rk_generation: u32,
        /// The new `pk_r`.
        pk_r: [u8; 32],
    },
}

impl UnlockChange {
    /// The kind of the change.
    pub fn kind(&self) -> ChangeKind {
        match self {
            UnlockChange::Password { .. } => ChangeKind::Password,
            UnlockChange::Recovery { .. } => ChangeKind::Recovery,
            UnlockChange::Recover { .. } => ChangeKind::Recover,
        }
    }

    /// Whether the change ends the user's other sessions: a new master
    /// password and a recovery do (with the user's pending sign-in codes); a
    /// new recovery key does not, since it changes nothing about how the user
    /// signs in.
    ///
    /// Spec: Fase 1 § 4.6 (after an MP change and a recovery).
    pub fn ends_other_sessions(&self) -> bool {
        match self {
            UnlockChange::Password { .. } | UnlockChange::Recover { .. } => true,
            UnlockChange::Recovery { .. } => false,
        }
    }
}

impl fmt::Debug for UnlockChange {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            UnlockChange::Password { .. } => "UnlockChange::Password([redacted])",
            UnlockChange::Recovery { .. } => "UnlockChange::Recovery([redacted])",
            UnlockChange::Recover { .. } => "UnlockChange::Recover([redacted])",
        })
    }
}

/// What `authorize` gives back once the library has given its permit: the
/// change, the manifest of the proven body and what the change does to the
/// asking session.
pub struct Authorized {
    /// The change.
    pub change: UnlockChange,
    /// The new manifest, from the proven body.
    pub manifest: SealedRowJson,
    /// The permit's effect on the asking session.
    pub session_effect: ScopeEffect,
    /// The snapshot of the account the permit was checked against
    /// (`permit.basis`). Only the OPAQUE library makes one (a vault module
    /// may not build it), so a value here means a proof was checked; `apply`
    /// also compares it with the row it handed to `authorize`.
    pub basis: WriteBasis,
}

impl fmt::Debug for Authorized {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Authorized([redacted])")
    }
}

/// What a committed change came to.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Applied {
    /// The vault's `seq` of the new manifest row.
    pub seq: u64,
    /// Every session that ended, each once: the other sessions of the user,
    /// their children, and the asking one when it ended too.
    pub ended: Vec<SidHash>,
}

/// One stored wrap, as the change reads it before it writes.
struct StoredWrap {
    method_id: MethodId,
    generation: u32,
}

/// The manifest row, as the change reads it before it writes.
struct StoredManifest {
    rev: u64,
    size: i64,
}

/// The account, as the change reads it before it writes.
struct StoredAccount {
    vault: VaultId,
    record: StoredRecord,
    pk_a: [u8; 32],
    pk_r: [u8; 32],
    vk_epoch: u64,
}

/// Writes a change of unlock methods in one `BEGIN IMMEDIATE` transaction:
/// see the module documentation for the steps.
///
/// `authorize` runs inside the transaction, against the account as it was
/// just read (`AccountAuthState`, with the row version 0: the write lock is
/// held from the read to the commit, so the row cannot change in between).
/// It checks the proof (which uses up the nonce) and parses the proven body.
/// Its error is the answer, and nothing is written.
///
/// Answers, besides those of `authorize`:
///
/// * the asking session ended, its user was disabled or signed out
///   everywhere, or it has no account any more: `401 unauthorized`, before
///   `authorize` runs (the nonce is kept);
/// * a manifest envelope that is not a manifest of a version and suite this
///   server stores: `422 unsupported_envelope` (`413 too_large` over 65 536
///   bytes);
/// * a manifest `rev` that is not the current one plus 1, a generation that
///   is not above the stored one, or a row that is not what was read: `409
///   write_conflict`;
/// * a new `pk_r` equal to the stored one, or not a usable Ed25519 key: `400
///   malformed_recovery_key`;
/// * a permit whose snapshot is not the row that was read: `500 internal`.
///
/// Spec: Fase 1 § 4.3 (changing MP: `kek_generation + 1`; the manifest is
/// updated in the same request as a change to wraps), § 4.6 (the proof; all
/// other sessions end after an MP change and a recovery) and § 6.3.
pub fn apply<F>(
    conn: &mut rusqlite::Connection,
    writer: &Writer,
    now: i64,
    authorize: F,
) -> Result<Applied, ApiError>
where
    F: FnOnce(&AccountAuthState<'_>) -> Result<Authorized, ApiError>,
{
    let tx = conn
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(sql)?;
    if !session_counts(&tx, writer, now)? {
        return Err(ApiError::unauthorized());
    }
    let account = read_account(&tx, writer)?.ok_or_else(ApiError::unauthorized)?;
    let state = AccountAuthState {
        account: SignedAccount {
            account_id: writer.account,
            pk_a: AuthPublicKey::new(account.pk_a),
            pk_r: RecoveryPublicKey::new(account.pk_r),
            vk_epoch: account.vk_epoch,
            row_version: 0,
        },
        current: &account.record,
    };
    let authorized = authorize(&state)?;
    check_basis(&authorized.basis, &state.account)?;
    if authorized.change.kind() != writer.kind {
        tracing::error!("a route authorized another kind of change than it named");
        return Err(ApiError::internal());
    }

    check_manifest_envelope(&authorized.manifest.envelope)?;
    let manifest = read_manifest(&tx, &account.vault)?;
    let wanted_rev = manifest.rev.checked_add(1).ok_or_else(write_conflict)?;
    if authorized.manifest.rev != wanted_rev {
        return Err(write_conflict());
    }

    write_change(&tx, writer, &account, &authorized.change)?;
    let seq = write_manifest(&tx, &account.vault, &manifest, &authorized.manifest, now)?;

    let keeps_asking = writer.keep_session && authorized.session_effect == ScopeEffect::Keep;
    let mut ended = if authorized.change.ends_other_sessions() {
        let keep = keeps_asking.then_some(&writer.sid);
        let mut ended = end_all_credentials(&tx, writer.user_id, keep, now).map_err(sql)?;
        if keeps_asking {
            // The asking session goes on; what was handed over from it (its
            // admin session) does not.
            ended.extend(revoke(&tx, &writer.sid, now, Revoke::HandedOver)?);
        }
        ended
    } else if keeps_asking {
        Vec::new()
    } else {
        revoke(&tx, &writer.sid, now, Revoke::WithHandedOver)?
    };
    ended.sort_unstable_by_key(|sid| sid.0);
    ended.dedup();
    tx.commit().map_err(sql)?;
    Ok(Applied { seq, ended })
}

/// After the commit of [`apply`]: the streams of the vault hear of the new
/// `seq`, every ended session's stream is closed, and a backup is asked for,
/// so the newest set holds the newest wraps.
///
/// Spec: Fase 1 § 7.6 and § 11.
pub fn after_commit(
    applied: &Applied,
    events: &SyncEvents,
    backup: &BackupStatus,
    vault: &VaultId,
) {
    events.notify(*vault, applied.seq);
    for sid in &applied.ended {
        events.session_revoked(*sid);
    }
    backup.request_run(BACKUP_REASON);
}

// ------------------------------------------------------------------ reads

/// The asking session is still one: its row is live, of the vault, of this
/// user and within its limits; the user is active and still at the session
/// version the request was checked against.
fn session_counts(tx: &Transaction<'_>, writer: &Writer, now: i64) -> Result<bool, ApiError> {
    let Some(row) = lookup(tx, &writer.sid).map_err(sql)? else {
        return Ok(false);
    };
    if row.revoked_at.is_some()
        || row.origin != Origin::Vault
        || row.user_id != writer.user_id
        || !within_limits(&row, now)
    {
        return Ok(false);
    }
    let user: Option<(i64, bool)> = tx
        .query_row(
            "SELECT session_version, active FROM users WHERE id = ?1",
            params![writer.user_id],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .optional()
        .map_err(sql)?;
    Ok(matches!(user, Some((version, true)) if version == writer.session_version))
}

/// The columns of an account row, as SQLite gives them.
type AccountColumns = (Vec<u8>, Vec<u8>, i64, Vec<u8>, Vec<u8>, i64);

/// The account of the writer, if it is still the user's.
fn read_account(tx: &Transaction<'_>, writer: &Writer) -> Result<Option<StoredAccount>, ApiError> {
    let row: Option<AccountColumns> = tx
        .query_row(
            "SELECT vault_id, opaque_record, ksf_profile, pk_a, pk_r, vk_epoch
             FROM ferret_accounts WHERE account_id = ?1 AND user_id = ?2",
            params![writer.account.as_bytes(), writer.user_id],
            |r| {
                Ok((
                    r.get(0)?,
                    r.get(1)?,
                    r.get(2)?,
                    r.get(3)?,
                    r.get(4)?,
                    r.get(5)?,
                ))
            },
        )
        .optional()
        .map_err(sql)?;
    let Some((vault, record, profile, pk_a, pk_r, vk_epoch)) = row else {
        return Ok(None);
    };
    // The row was written by this server; anything that does not read back is
    // a fault of the database, not of the client.
    let corrupt = |what: &'static str| {
        tracing::error!(what, "a stored account does not read back");
        ApiError::internal()
    };
    let record = ValidatedRecord::parse(&record).map_err(|_| corrupt("record"))?;
    Ok(Some(StoredAccount {
        vault: VaultId::from_bytes(<[u8; 16]>::try_from(vault).map_err(|_| corrupt("vault"))?),
        record: StoredRecord {
            record,
            ksf_profile: u8::try_from(profile).map_err(|_| corrupt("profile"))?,
        },
        pk_a: <[u8; 32]>::try_from(pk_a).map_err(|_| corrupt("pk_a"))?,
        pk_r: <[u8; 32]>::try_from(pk_r).map_err(|_| corrupt("pk_r"))?,
        vk_epoch: u64::try_from(vk_epoch).map_err(|_| corrupt("epoch"))?,
    }))
}

/// The one stored wrap of `method_type`. None, or more than one, is a fault
/// of the database: every account has exactly one of each.
fn read_wrap(
    tx: &Transaction<'_>,
    account: &AccountId,
    method_type: u8,
) -> Result<StoredWrap, ApiError> {
    let mut stmt = tx
        .prepare(
            "SELECT method_id, kek_generation FROM ferret_unlock_methods
             WHERE account_id = ?1 AND method_type = ?2",
        )
        .map_err(sql)?;
    let rows = stmt
        .query_map(params![account.as_bytes(), i64::from(method_type)], |r| {
            Ok((r.get::<_, Vec<u8>>(0)?, r.get::<_, i64>(1)?))
        })
        .map_err(sql)?
        .collect::<Result<Vec<_>, _>>()
        .map_err(sql)?;
    let [(method_id, generation)] = rows.as_slice() else {
        tracing::error!(
            method_type,
            count = rows.len(),
            "an account does not have exactly one wrap of a type"
        );
        return Err(ApiError::internal());
    };
    let method_id = <[u8; 16]>::try_from(method_id.as_slice()).map_err(|_| ApiError::internal())?;
    let generation = u32::try_from(*generation).map_err(|_| ApiError::internal())?;
    Ok(StoredWrap {
        method_id: MethodId::from_bytes(method_id),
        generation,
    })
}

/// The live manifest row of the vault.
fn read_manifest(tx: &Transaction<'_>, vault: &VaultId) -> Result<StoredManifest, ApiError> {
    let row: Option<(i64, i64)> = tx
        .query_row(
            "SELECT rev, size FROM ferret_items
             WHERE vault_id = ?1 AND item_id = ?2 AND deleted = 0",
            params![vault.as_bytes(), MANIFEST_ITEM_ID.as_bytes()],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .optional()
        .map_err(sql)?;
    let Some((rev, size)) = row else {
        tracing::error!("a vault has no live manifest row");
        return Err(ApiError::internal());
    };
    Ok(StoredManifest {
        rev: u64::try_from(rev).map_err(|_| ApiError::internal())?,
        size,
    })
}

// ----------------------------------------------------------------- checks

/// The new manifest is a manifest envelope of a version and suite this server
/// stores. Its content is sealed; whether it opens is for the client.
fn check_manifest_envelope(envelope: &[u8]) -> Result<(), ApiError> {
    match parse_envelope(envelope) {
        Ok(view) if view.kind == KIND_MANIFEST => Ok(()),
        Err(CoreError::TooLarge) => Err(ApiError::coded("too_large")),
        // A version, suite or kind that is not a manifest, or a structure
        // that is no envelope: one answer, so the server tells nothing about
        // which.
        _ => Err(ApiError::coded("unsupported_envelope")),
    }
}

/// How far one change may move a generation. An honest client moves it by
/// one, a few more after changes whose answers it never saw, and after a
/// restore of an older backup by the number of changes since that backup.
/// Without a bound, one request (a compromised session, a client bug) could
/// set `u32::MAX` and leave no generation for any later change, the recovery
/// path included.
pub const MAX_GENERATION_STEP: u32 = 1 << 16;

/// A generation goes only up, and by at most [`MAX_GENERATION_STEP`]: the new
/// one must be strictly above the stored one and not more than the step
/// above it (`409 write_conflict` otherwise). A `u32` cannot pass `u32::MAX`,
/// so the ceiling holds by its type.
///
/// Spec: Fase 1 § 4.3 (`kek_generation + 1`; the client rejects a lower one,
/// so the server never stores one).
fn check_generation(stored: u32, new: u32) -> Result<(), ApiError> {
    match new.checked_sub(stored) {
        Some(step) if (1..=MAX_GENERATION_STEP).contains(&step) => Ok(()),
        _ => Err(write_conflict()),
    }
}

/// A new recovery key brings a new `pk_r`: one equal to the stored key would
/// leave the old recovery key able to sign. `400 malformed_recovery_key`, as
/// the OPAQUE library answers a recovery that keeps its key.
///
/// Spec: Fase 1 § 4.6 and § 6.3 (step 4: a new `pk_r`).
///
/// The key must also be one that can ever check a proof: the canonical
/// encoding of an Ed25519 point that is not of small order. Proofs are
/// verified strictly, so another key forges nothing, but it would leave the
/// account with a recovery key that never works.
fn check_new_recovery_key(account: &StoredAccount, pk_r: &[u8; 32]) -> Result<(), ApiError> {
    if *pk_r == account.pk_r || !is_recovery_public_key(pk_r) {
        Err(ApiError::coded("malformed_recovery_key"))
    } else {
        Ok(())
    }
}

/// A canonically encoded Ed25519 point that is not of small order.
///
/// Spec: Fase 1 § 4.5 (`pk_r` is an Ed25519 public key).
pub fn is_recovery_public_key(bytes: &[u8; 32]) -> bool {
    VerifyingKey::from_bytes(bytes)
        .is_ok_and(|key| !key.is_weak() && key.to_edwards().compress().to_bytes() == *bytes)
}

/// The permit's snapshot is the row `apply` read and handed to `authorize`.
/// Another one is a mistake of the route (`500 internal`), never something a
/// client chose.
fn check_basis(basis: &WriteBasis, read: &SignedAccount) -> Result<(), ApiError> {
    if basis.account_id == read.account_id
        && basis.pk_a == read.pk_a
        && basis.pk_r == read.pk_r
        && basis.vk_epoch == read.vk_epoch
        && basis.row_version == read.row_version
    {
        Ok(())
    } else {
        tracing::error!("a change was authorized against another row than the one read");
        Err(ApiError::internal())
    }
}

// ----------------------------------------------------------------- writes

/// Writes the account and the wraps of `change`, each against what was read.
fn write_change(
    tx: &Transaction<'_>,
    writer: &Writer,
    account: &StoredAccount,
    change: &UnlockChange,
) -> Result<(), ApiError> {
    match change {
        UnlockChange::Password {
            record,
            profile,
            wrap,
            generation,
        } => {
            let stored = read_wrap(tx, &writer.account, TYPE_PASSWORD)?;
            check_generation(stored.generation, *generation)?;
            write_account(tx, writer, account, Some((record, *profile)), None)?;
            write_wrap(tx, &writer.account, &stored, wrap, *generation)
        }
        UnlockChange::Recovery {
            wrap,
            generation,
            pk_r,
        } => {
            check_new_recovery_key(account, pk_r)?;
            let stored = read_wrap(tx, &writer.account, TYPE_RECOVERY)?;
            check_generation(stored.generation, *generation)?;
            write_account(tx, writer, account, None, Some(pk_r))?;
            write_wrap(tx, &writer.account, &stored, wrap, *generation)
        }
        UnlockChange::Recover {
            record,
            profile,
            pw_wrap,
            pw_generation,
            rk_wrap,
            rk_generation,
            pk_r,
        } => {
            check_new_recovery_key(account, pk_r)?;
            let password = read_wrap(tx, &writer.account, TYPE_PASSWORD)?;
            let recovery = read_wrap(tx, &writer.account, TYPE_RECOVERY)?;
            check_generation(password.generation, *pw_generation)?;
            check_generation(recovery.generation, *rk_generation)?;
            write_account(tx, writer, account, Some((record, *profile)), Some(pk_r))?;
            write_wrap(tx, &writer.account, &password, pw_wrap, *pw_generation)?;
            write_wrap(tx, &writer.account, &recovery, rk_wrap, *rk_generation)
        }
    }
}

/// Replaces the record (with its profile) and `pk_r` that are given, on the
/// condition that the row is still the one that was read: record, profile,
/// keys and epoch.
fn write_account(
    tx: &Transaction<'_>,
    writer: &Writer,
    read: &StoredAccount,
    record: Option<(&ValidatedRecord, u8)>,
    pk_r: Option<&[u8; 32]>,
) -> Result<(), ApiError> {
    let (new_record, new_profile) = match record {
        Some((record, profile)) => (record.as_bytes(), profile),
        None => (read.record.record.as_bytes(), read.record.ksf_profile),
    };
    let new_pk_r = pk_r.unwrap_or(&read.pk_r);
    let changed = tx
        .execute(
            "UPDATE ferret_accounts SET opaque_record = ?1, ksf_profile = ?2, pk_r = ?3
             WHERE account_id = ?4 AND user_id = ?5
               AND opaque_record = ?6 AND ksf_profile = ?7
               AND pk_a = ?8 AND pk_r = ?9 AND vk_epoch = ?10",
            params![
                new_record,
                i64::from(new_profile),
                new_pk_r.as_slice(),
                writer.account.as_bytes(),
                writer.user_id,
                read.record.record.as_bytes(),
                i64::from(read.record.ksf_profile),
                read.pk_a.as_slice(),
                read.pk_r.as_slice(),
                i64::try_from(read.vk_epoch).map_err(|_| ApiError::internal())?,
            ],
        )
        .map_err(sql)?;
    one_row(changed)
}

/// Replaces a wrap under its stored `method_id`, on the condition that it is
/// still at the generation that was read.
fn write_wrap(
    tx: &Transaction<'_>,
    account: &AccountId,
    stored: &StoredWrap,
    wrap: &[u8],
    generation: u32,
) -> Result<(), ApiError> {
    let changed = tx
        .execute(
            "UPDATE ferret_unlock_methods SET wrap = ?1, kek_generation = ?2
             WHERE method_id = ?3 AND account_id = ?4 AND kek_generation = ?5",
            params![
                wrap,
                i64::from(generation),
                stored.method_id.as_bytes(),
                account.as_bytes(),
                i64::from(stored.generation),
            ],
        )
        .map_err(sql)?;
    one_row(changed)
}

/// Writes the manifest row at its next revision with the vault's next `seq`,
/// and moves the vault's byte count by the change in size. Gives the `seq`.
///
/// The item quota is not asked: the manifest replaces itself, it is one row
/// of at most 65 536 bytes, and a vault without room must still be able to
/// change its master password.
fn write_manifest(
    tx: &Transaction<'_>,
    vault: &VaultId,
    read: &StoredManifest,
    manifest: &SealedRowJson,
    now: i64,
) -> Result<u64, ApiError> {
    let new_size = i64::try_from(manifest.envelope.len()).map_err(|_| ApiError::internal())?;
    let seq: Option<i64> = tx
        .query_row(
            "UPDATE ferret_vaults SET seq = seq + 1, bytes_used = bytes_used - ?2 + ?3
             WHERE vault_id = ?1 RETURNING seq",
            params![vault.as_bytes(), read.size, new_size],
            |r| r.get(0),
        )
        .optional()
        .map_err(sql)?;
    let seq = seq.ok_or_else(write_conflict)?;
    let changed = tx
        .execute(
            "UPDATE ferret_items
             SET rev = ?3, seq = ?4, blob = ?5, tag = ?6, size = ?7, changed_at = ?8
             WHERE vault_id = ?1 AND item_id = ?2 AND rev = ?9 AND deleted = 0",
            params![
                vault.as_bytes(),
                MANIFEST_ITEM_ID.as_bytes(),
                i64::try_from(manifest.rev).map_err(|_| write_conflict())?,
                seq,
                manifest.envelope,
                manifest.tag.as_slice(),
                new_size,
                now,
                i64::try_from(read.rev).map_err(|_| ApiError::internal())?,
            ],
        )
        .map_err(sql)?;
    one_row(changed)?;
    u64::try_from(seq).map_err(|_| ApiError::internal())
}

/// Which sessions [`revoke`] ends.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Revoke {
    /// Only the sessions handed over from the session (its admin session).
    HandedOver,
    /// The session itself and the sessions handed over from it.
    WithHandedOver,
}

/// Ends the sessions handed over from `sid` (and `sid` itself for
/// [`Revoke::WithHandedOver`]) that are still live, and gives their ids.
fn revoke(
    tx: &Transaction<'_>,
    sid: &SidHash,
    now: i64,
    which: Revoke,
) -> Result<Vec<SidHash>, ApiError> {
    let with_self = which == Revoke::WithHandedOver;
    let mut stmt = tx
        .prepare(
            "UPDATE ferret_sessions SET revoked_at = ?2
             WHERE ((?3 AND sid_hash = ?1) OR parent_sid = ?1) AND revoked_at IS NULL
             RETURNING sid_hash",
        )
        .map_err(sql)?;
    let rows = stmt
        .query_map(params![sid.0.as_slice(), now, with_self], |r| {
            r.get::<_, Vec<u8>>(0)
        })
        .map_err(sql)?
        .collect::<Result<Vec<_>, _>>()
        .map_err(sql)?;
    rows.into_iter()
        .map(|bytes| {
            <[u8; 32]>::try_from(bytes)
                .map(SidHash)
                .map_err(|_| ApiError::internal())
        })
        .collect()
}

// ---------------------------------------------------------------- answers

/// Exactly one changed row, or the row was not what was read.
fn one_row(changed: usize) -> Result<(), ApiError> {
    if changed == 1 {
        Ok(())
    } else {
        Err(write_conflict())
    }
}

/// `409 write_conflict`: another write got there first.
fn write_conflict() -> ApiError {
    ApiError::coded("write_conflict")
}

/// A database error: `500 internal`, with the cause in the log only.
fn sql(error: rusqlite::Error) -> ApiError {
    ApiError::from(StoreError::from(error))
}

#[cfg(test)]
mod tests {
    use super::*;
    use ferret_core::envelope::MAX_ENVELOPE_LEN;

    #[test]
    fn a_generation_must_rise_by_a_bounded_step() {
        assert!(check_generation(1, 2).is_ok());
        assert!(check_generation(1, 1 + MAX_GENERATION_STEP).is_ok());
        assert!(check_generation(u32::MAX - 1, u32::MAX).is_ok());
        for (stored, new) in [
            (2, 2),
            (2, 1),
            (u32::MAX, u32::MAX),
            (5, 0),
            (1, 2 + MAX_GENERATION_STEP),
            (1, u32::MAX),
            (0, u32::MAX),
        ] {
            let refused = check_generation(stored, new).expect_err("refused");
            assert_eq!(refused.code, "write_conflict", "{stored} -> {new}");
        }
    }

    #[test]
    fn only_a_manifest_envelope_passes() {
        let refused = check_manifest_envelope(&[0u8; 100]).expect_err("no envelope");
        assert_eq!(refused.code, "unsupported_envelope");
        let big = vec![0u8; MAX_ENVELOPE_LEN + 1];
        let refused = check_manifest_envelope(&big).expect_err("too big");
        assert_eq!(refused.code, "too_large");
    }

    #[test]
    fn exactly_one_row_is_a_write() {
        assert!(one_row(1).is_ok());
        assert_eq!(one_row(0).expect_err("none").code, "write_conflict");
        assert_eq!(one_row(2).expect_err("two").code, "write_conflict");
    }
}
