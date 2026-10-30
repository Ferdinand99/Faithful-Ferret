//! The unlocked vault. It lives in the long-lived vault worker; JavaScript
//! holds a pointer to it and nothing else. The vault key and everything
//! derived from it stay in WASM memory, and `lock()` wipes them.
//!
//! Rules of the whole binding (also checked by the Node tests):
//!
//! 1. No exported function returns key bytes. The only methods that return a
//!    secret are those whose name starts with `reveal_` and that are in
//!    `reveal-allowlist.txt`. The byte arrays that do leave are listed with a
//!    reason in `tests/node/exports.test.mjs`.
//! 2. All state with keys is in these objects.
//! 3. A failure is a stable code, never text with data (see `error.rs`).
//! 4. `lock()` wipes; so does dropping the object.
//! 5. Sensitive fields are shown one at a time.

use crate::convert::{
    ANY, ByteBuf, CheckpointDto, PinnedDto, RowDto, SealedDto, Shape, Shaped, WrapDto, arr, b16,
    bytes, core, from_js, from_js_list, js_time, js_u64, opt_b32, to_js,
};
use crate::error::{Fail, Res, run};
use crate::item::{DraftDto, ViewDto, build_body};
use ferret_core::{
    AuthOp, Checkpoint, CheckpointEntry, Error, ExportDraft, ExportItem, ItemBody, ItemId, Kek,
    KekDevPin, KsfProfile, Manifest, MethodId, OsRng, Pin, PrfOutput, RecoveryKey, RollbackMemory,
    SecretKey, ServerRow, SyncMemory, UnlockedVault, auth_sign, decrypt_item, decrypt_manifest,
    emergency_sheet, encode_recovery_key, encode_secret_key, encrypt_item, make_checkpoint,
    make_tombstone, parse_otpauth, totp_code, totp_seconds_left, verify_checkpoint,
    verify_recovery_setup, verify_secret_key_entry, verify_tombstone,
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use wasm_bindgen::prelude::*;
use zeroize::Zeroizing;

/// The most items that can be open at once. An open item holds its decrypted
/// body in WASM memory.
pub(crate) const MAX_OPEN: usize = 4_096;

/// An item that is open: its decrypted body and the envelope it came from
/// (kept so that an edit can keep the item key).
pub(crate) struct OpenItem {
    pub(crate) item_id: ItemId,
    pub(crate) envelope: Vec<u8>,
    pub(crate) body: ItemBody,
}

/// Secrets of an account setup, kept so the user can be shown the recovery
/// key and the secret key and be asked to type them back. They go as soon as
/// every key the setup holds has been typed back correctly
/// (`verify_recovery_setup`, `verify_secret_key_entry`), with
/// [`Vault::clear_setup_secrets`] and with `lock()`.
pub(crate) struct Setup {
    pub(crate) recovery_key: Option<RecoveryKey>,
    pub(crate) secret_key: Option<SecretKey>,
    pub(crate) server_public_key: [u8; 32],
    pub(crate) ksf_profile: KsfProfile,
    rk_confirmed: bool,
    sk_confirmed: bool,
}

impl Setup {
    pub(crate) fn new(
        recovery_key: Option<RecoveryKey>,
        secret_key: Option<SecretKey>,
        server_public_key: [u8; 32],
        ksf_profile: KsfProfile,
    ) -> Self {
        Self {
            recovery_key,
            secret_key,
            server_public_key,
            ksf_profile,
            rk_confirmed: false,
            sk_confirmed: false,
        }
    }

    /// Whether every key this setup holds has been confirmed.
    fn confirmed(&self) -> bool {
        (self.recovery_key.is_none() || self.rk_confirmed)
            && (self.secret_key.is_none() || self.sk_confirmed)
    }
}

/// A rekey that is made but not yet in force: the old vault still signs the
/// request, then `rekey_commit` makes the new one the vault.
pub(crate) struct PendingRekey {
    pub(crate) vault: UnlockedVault,
    pub(crate) setup: Setup,
}

/// A passkey that has been made but not yet released: the answer for the
/// page is held here until the caller has stored the sealed item
/// (`passkey_create_confirm`), and the item it goes into is not open before
/// that either.
pub(crate) struct PendingPasskey {
    pub(crate) handle: u32,
    pub(crate) response: ferret_core::passkey::CreateResponse,
    /// The item as sealed: its id, envelope (the item key is kept) and body.
    pub(crate) item: OpenItem,
    /// The open item the passkey was added to and the envelope it had then.
    pub(crate) attach_to: Option<(u32, Vec<u8>)>,
}

/// How long a re-authentication token is good for, in milliseconds.
pub(crate) const GRANT_TTL_MS: u64 = 300_000;

/// A one-time permission for a plaintext export. Only a fresh sign-in with
/// the master password makes one (`UnlockJob.reauth_grant`); the vault keeps
/// it until the export consumes it, a new one replaces it, it is
/// [`GRANT_TTL_MS`] old, or the vault is locked or rekeyed.
pub(crate) struct ReauthGrant {
    pub(crate) token: Zeroizing<[u8; 32]>,
    /// The caller's clock when the token was made (unix milliseconds).
    pub(crate) granted_ms: u64,
}

/// Everything an unlocked vault holds.
pub(crate) struct Inner {
    pub(crate) vault: UnlockedVault,
    pub(crate) items: BTreeMap<u32, OpenItem>,
    /// The next handle to hand out. It starts at a random value for each
    /// vault, so a handle kept from an earlier session is almost surely not
    /// open in this one (`invalid_handle`) instead of naming another item.
    next_handle: u32,
    pub(crate) pending: Option<PendingRekey>,
    pub(crate) setup: Option<Setup>,
    pub(crate) export: Option<ExportDraft>,
    pub(crate) import: Option<Vec<ExportItem>>,
    pub(crate) passkey: Option<PendingPasskey>,
    pub(crate) grant: Option<ReauthGrant>,
}

impl Inner {
    /// A handle that is not in use. Item handles and the handle of a pending
    /// passkey share one space, so none is handed out twice.
    pub(crate) fn new_handle(&mut self) -> Res<u32> {
        for _ in 0..=MAX_OPEN {
            let handle = self.next_handle;
            self.next_handle = handle.wrapping_add(1);
            let in_use = self.items.contains_key(&handle)
                || self.passkey.as_ref().is_some_and(|p| p.handle == handle);
            if !in_use {
                return Ok(handle);
            }
        }
        Err(Error::TooLarge.into())
    }

    pub(crate) fn open(&mut self, item: OpenItem) -> Res<u32> {
        if self.items.len() >= MAX_OPEN {
            return Err(Error::TooLarge.into());
        }
        let handle = self.new_handle()?;
        self.items.insert(handle, item);
        Ok(handle)
    }

    pub(crate) fn item(&self, handle: u32) -> Res<&OpenItem> {
        self.items.get(&handle).ok_or(Fail::Handle)
    }
}

/// The unlocked vault. See the module documentation.
#[wasm_bindgen]
pub struct Vault {
    pub(crate) inner: Option<Box<Inner>>,
}

impl Vault {
    /// A vault around an unlocked one (a flow made it). `setup` holds the
    /// secrets that are shown once.
    pub(crate) fn from_unlocked(vault: UnlockedVault, setup: Option<Setup>) -> Vault {
        let mut start = [0u8; 4];
        ferret_core::SecureRng::fill(&mut OsRng, &mut start);
        Vault {
            inner: Some(Box::new(Inner {
                vault,
                items: BTreeMap::new(),
                next_handle: u32::from_le_bytes(start),
                pending: None,
                setup,
                export: None,
                import: None,
                passkey: None,
                grant: None,
            })),
        }
    }

    pub(crate) fn inner(&self) -> Res<&Inner> {
        self.inner.as_deref().ok_or(Fail::Locked)
    }

    pub(crate) fn inner_mut(&mut self) -> Res<&mut Inner> {
        self.inner.as_deref_mut().ok_or(Fail::Locked)
    }

    /// Marks the recovery key (`recovery`) or the secret key as typed back,
    /// and drops the setup secrets once all of them are.
    fn setup_confirmed(&mut self, recovery: bool) {
        if let Some(inner) = self.inner.as_deref_mut()
            && let Some(setup) = inner.setup.as_mut()
        {
            if recovery {
                setup.rk_confirmed = true;
            } else {
                setup.sk_confirmed = true;
            }
            if setup.confirmed() {
                inner.setup = None;
            }
        }
    }

    pub(crate) fn unlocked(&self) -> Res<&UnlockedVault> {
        Ok(&self.inner()?.vault)
    }
}

// ------------------------------------------------------------ DTOs here

#[derive(Serialize)]
struct TotpCodeDto {
    code: String,
    seconds_left: u32,
}

#[derive(Serialize)]
struct TombDto {
    rev: u64,
    #[serde(with = "bytes")]
    tomb: Vec<u8>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct EntryDto {
    #[serde(with = "b16")]
    item_id: [u8; 16],
    rev: u64,
    /// `SHA-256` of the envelope of a live row; `null` for a tombstone.
    #[serde(default, with = "opt_b32")]
    hash: Option<[u8; 32]>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ServerRowDto {
    #[serde(with = "b16")]
    item_id: [u8; 16],
    rev: u64,
    /// `"live"` (with `envelope` and `tag`) or `"deleted"` (with `tomb`).
    state: String,
    #[serde(default, with = "crate::convert::opt_bytes")]
    envelope: Option<Vec<u8>>,
    #[serde(default, with = "opt_b32")]
    tag: Option<[u8; 32]>,
    #[serde(default, with = "crate::convert::opt_bytes")]
    tomb: Option<Vec<u8>>,
}

#[derive(Serialize)]
struct ContextDto {
    #[serde(with = "b16")]
    account_id: [u8; 16],
    #[serde(with = "b16")]
    vault_id: [u8; 16],
    vk_epoch: u64,
}

#[derive(Serialize)]
struct AccessPageDto {
    server_url: String,
    email: String,
    account_id: String,
    ksf_profile: u8,
    secret_key_code: Option<String>,
    qr_payload: String,
}

#[derive(Serialize)]
struct SheetDto {
    access: AccessPageDto,
    recovery_key_code: String,
}

/// The core's checkpoint from the one the client sends.
fn checkpoint_of(cp: CheckpointDto) -> Checkpoint {
    Checkpoint {
        seq: cp.seq,
        digest: cp.digest,
        mac: cp.mac,
        entries: cp.entries,
    }
}

/// The rows the server shows, each with its tag or tombstone checked.
fn server_rows_of(vault: &UnlockedVault, list: Vec<ServerRowDto>) -> Res<Vec<ServerRow>> {
    let mut server_rows = Vec::with_capacity(list.len());
    for r in &list {
        let id = ItemId::from_bytes(r.item_id);
        server_rows.push(match r.state.as_str() {
            "live" => ServerRow::live(
                vault,
                id,
                r.rev,
                r.envelope.as_deref().ok_or(Fail::Input)?,
                &r.tag.ok_or(Fail::Input)?,
            )?,
            "deleted" => {
                ServerRow::deleted(vault, id, r.rev, r.tomb.as_deref().ok_or(Fail::Input)?)?
            }
            _ => return Err(Fail::Input),
        });
    }
    Ok(server_rows)
}

/// The value of `stored_credential_ids` that says the vault has no passkey
/// items. An empty array is refused instead, so that "none" is a decision.
const NO_STORED_PASSKEYS: &str = "no_stored_passkeys";

/// The credential ids the caller lists as stored, or none when it says so.
fn stored_list(v: JsValue) -> Res<Vec<ByteBuf>> {
    if v.as_string().as_deref() == Some(NO_STORED_PASSKEYS) {
        return Ok(Vec::new());
    }
    let list: Vec<ByteBuf> = from_js_list(v)?;
    if list.is_empty() {
        return Err(Fail::Input);
    }
    Ok(list)
}

fn auth_op(name: &str) -> Res<AuthOp> {
    match AuthOp::from_name(name) {
        Some(op) => Ok(op),
        // `recover` is signed with the recovery key, by the account flow.
        None if name == "recover" => Err(Error::Unsupported.into()),
        None => Err(Fail::Input),
    }
}

#[wasm_bindgen]
impl Vault {
    /// Locks the vault: the vault key, the derived keys, every open item and
    /// every secret of a setup are wiped and freed. Every later call fails
    /// with `vault_locked`. (JavaScript also ends the worker, which frees the
    /// heap that Argon2id used.)
    pub fn lock(&mut self) {
        self.inner = None;
    }

    /// Whether the vault has been locked.
    pub fn is_locked(&self) -> bool {
        self.inner.is_none()
    }

    /// Account, vault and epoch of the vault.
    pub fn context(&self) -> Result<JsValue, JsValue> {
        run(|| {
            let c = self.unlocked()?.context();
            to_js(&ContextDto {
                account_id: *c.account_id.as_bytes(),
                vault_id: *c.vault_id.as_bytes(),
                vk_epoch: c.vk_epoch,
            })
        })
    }

    /// `pk_a`, the public key of the authentication key pair. Public.
    pub fn auth_public_key(&self) -> Result<Vec<u8>, JsValue> {
        run(|| Ok(self.unlocked()?.auth_public_key().to_vec()))
    }

    /// Signs the body of a request: `unlock-method.add`,
    /// `unlock-method.remove`, `unlock-method.password.put`,
    /// `unlock-method.recovery.put` or `rekey`. `nonce` is 32 bytes. The
    /// signature (64 bytes) is public.
    pub fn auth_sign(&self, op: &str, nonce: Vec<u8>, body: Vec<u8>) -> Result<Vec<u8>, JsValue> {
        run(|| {
            let sig = auth_sign(self.unlocked()?, auth_op(op)?, &arr::<32>(&nonce)?, &body)?;
            Ok(sig.to_vec())
        })
    }

    // ------------------------------------------------------------ items

    /// Opens an item: checks its tag, decrypts it and keeps the body inside
    /// WASM. Returns the handle (a number) that the other item methods take.
    /// A wrong key, id, revision or any changed byte is `decrypt`.
    pub fn open_item(
        &mut self,
        item_id: Vec<u8>,
        rev: f64,
        envelope: Vec<u8>,
        tag: Vec<u8>,
    ) -> Result<u32, JsValue> {
        run(|| {
            let id = ItemId::from_bytes(arr(&item_id)?);
            let inner = self.inner_mut()?;
            let decoded =
                decrypt_item(&inner.vault, id, js_u64(rev)?, &envelope, &arr::<32>(&tag)?)?;
            inner.open(OpenItem {
                item_id: id,
                envelope,
                body: decoded.body,
            })
        })
    }

    /// Closes an item and wipes its body.
    pub fn close_item(&mut self, handle: u32) -> Result<(), JsValue> {
        run(|| {
            self.inner_mut()?
                .items
                .remove(&handle)
                .map(drop)
                .ok_or(Fail::Handle)
        })
    }

    /// The item without its secrets: no private key, no PRF seed, no TOTP
    /// address, no notes, no value of a hidden field. A passkey shows its
    /// public ids (`cred_id`, `rp_id`, `user_handle`), which are what
    /// `excludeCredentials`, `allowCredentials` and the check of
    /// `wrap_prf` are built from.
    pub fn item_view(&self, handle: u32) -> Result<JsValue, JsValue> {
        run(|| {
            let body = &self.inner()?.item(handle)?.body;
            let view = body.view();
            to_js(&ViewDto::of(&view, body))
        })
    }

    /// The value of the custom field with this index. One secret at a time,
    /// on an explicit request by the user.
    pub fn reveal_item_field(&self, handle: u32, field_index: u32) -> Result<String, JsValue> {
        run(|| {
            let index = usize::try_from(field_index).map_err(|_| Fail::Input)?;
            let item = self.inner()?.item(handle)?;
            Ok(item
                .body
                .fields
                .get(index)
                .ok_or(Fail::Input)?
                .value
                .clone())
        })
    }

    /// The notes of the item, on an explicit request by the user.
    pub fn reveal_item_notes(&self, handle: u32) -> Result<String, JsValue> {
        run(|| {
            let item = self.inner()?.item(handle)?;
            Ok(item.body.notes.clone().unwrap_or_default())
        })
    }

    /// The `otpauth://` address of the item with its secret, on an explicit
    /// request by the user (to copy it or show it as a QR code).
    pub fn reveal_totp_secret(&self, handle: u32) -> Result<String, JsValue> {
        run(|| {
            let item = self.inner()?.item(handle)?;
            let totp = item.body.totp.as_ref().ok_or(Fail::Input)?;
            Ok(totp.uri.clone())
        })
    }

    /// The current one-time code of the item and the seconds it still holds.
    /// `unix_seconds` comes from the caller's clock: it must be a finite
    /// number from 0 to 2^53, otherwise `invalid_input`.
    pub fn totp_code(&self, handle: u32, unix_seconds: f64) -> Result<JsValue, JsValue> {
        run(|| {
            let seconds = js_time(unix_seconds)?;
            let item = self.inner()?.item(handle)?;
            let totp = item.body.totp.as_ref().ok_or(Fail::Input)?;
            let params = parse_otpauth(&totp.uri)?;
            let code = totp_code(&params, seconds)?;
            to_js(&TotpCodeDto {
                code: code.to_string(),
                seconds_left: totp_seconds_left(&params, seconds),
            })
        })
    }

    /// Seals an item from a draft and returns `{ rev, envelope, tag }`.
    ///
    /// `rev` is the revision the item gets with this write. For a new item,
    /// `existing_handle` is absent and the draft needs `item_type` and
    /// `name`. For an edit it is the handle of the open item: the new body is
    /// that body with the draft applied, so everything the draft does not
    /// mention (a private key, PRF seeds, a TOTP secret, hidden fields,
    /// unknown keys) is kept without leaving WASM. `now_ms` is the time of
    /// the write in unix milliseconds.
    pub fn encrypt_item(
        &mut self,
        item_id: Vec<u8>,
        rev: f64,
        draft: JsValue,
        existing_handle: Option<u32>,
        now_ms: f64,
    ) -> Result<JsValue, JsValue> {
        run(|| {
            let id = ItemId::from_bytes(arr(&item_id)?);
            let rev = js_u64(rev)?;
            let now = js_time(now_ms)?;
            let draft: DraftDto = from_js(draft)?;
            let inner = self.inner_mut()?;
            let (body, envelope) = match existing_handle {
                Some(h) => {
                    let open = inner.item(h)?;
                    if open.item_id != id {
                        return Err(Fail::Input);
                    }
                    (
                        build_body(&draft, Some(&open.body), now)?,
                        Some(open.envelope.clone()),
                    )
                }
                None => (build_body(&draft, None, now)?, None),
            };
            let sealed = encrypt_item(
                &mut OsRng,
                &inner.vault,
                id,
                rev,
                &body,
                envelope.as_deref(),
            )?;
            let out = to_js(&SealedDto::of(&sealed))?;
            if let Some(open) = existing_handle.and_then(|h| inner.items.get_mut(&h)) {
                open.envelope = sealed.envelope;
                open.body = body;
            }
            Ok(out)
        })
    }

    /// The tombstone of a deleted item at revision `rev`: `{ rev, tomb }`.
    pub fn make_tombstone(&self, item_id: Vec<u8>, rev: f64) -> Result<JsValue, JsValue> {
        run(|| {
            let t = make_tombstone(
                &mut OsRng,
                self.unlocked()?,
                ItemId::from_bytes(arr(&item_id)?),
                js_u64(rev)?,
            )?;
            to_js(&TombDto {
                rev: t.rev,
                tomb: t.tomb,
            })
        })
    }

    /// Checks the tombstone of `item_id` at revision `rev` under the deletion
    /// key of this vault. A tombstone that does not verify (a wrong
    /// revision, another item id, a changed byte or a wrong length) is
    /// `tombstone_invalid`; the client keeps its local copy of the item and
    /// puts it in quarantine. An `item_id` that is not 16 bytes is
    /// `invalid_input`.
    ///
    /// Spec: Fase 1 § 8.4.
    pub fn verify_tombstone(
        &self,
        item_id: Vec<u8>,
        rev: f64,
        tomb: Vec<u8>,
    ) -> Result<(), JsValue> {
        run(|| {
            core(verify_tombstone(
                self.unlocked()?,
                ItemId::from_bytes(arr(&item_id)?),
                js_u64(rev)?,
                &tomb,
            ))
        })
    }

    // ------------------------------------------------------ checkpoints

    /// Signs the state of the client: `entries` is a list of
    /// `{ item_id, rev, hash }` (`hash` is the SHA-256 of the envelope of a
    /// live row, `null` for a tombstone). Returns
    /// `{ seq, digest, mac, entries }`.
    pub fn make_checkpoint(&self, seq: f64, entries: JsValue) -> Result<JsValue, JsValue> {
        run(|| {
            let list: Vec<EntryDto> = from_js_list(entries)?;
            let entries = list
                .iter()
                .map(|e| CheckpointEntry {
                    item_id: ItemId::from_bytes(e.item_id),
                    rev: e.rev,
                    live_hash: e.hash,
                })
                .collect();
            let cp = make_checkpoint(self.unlocked()?, js_u64(seq)?, entries)?;
            to_js(&CheckpointDto {
                seq: cp.seq,
                digest: cp.digest,
                mac: cp.mac,
                entries: cp.entries,
            })
        })
    }

    /// Checks a checkpoint against the rows the server shows. Each row is
    /// `{ item_id, rev, state: "live", envelope, tag }` or
    /// `{ item_id, rev, state: "deleted", tomb }`; its tag or tombstone is
    /// checked here, before the rows are compared. A failure is a
    /// `checkpoint_*` code.
    ///
    /// `sync_memory` is required: the client's stored rollback memory
    /// (`SyncMemory` bytes; `sync_memory_new()` for a device that has seen
    /// nothing of this vault yet). A checkpoint below the highest verified
    /// one, a top `seq` below the highest seen, or a row with a lower `rev`
    /// than the highest seen for its item is refused
    /// (`checkpoint_seq_below_remembered`,
    /// `checkpoint_top_seq_below_remembered`,
    /// `checkpoint_rev_below_remembered`). Returns the updated memory bytes,
    /// which the client stores in place of the old ones; on any error nothing
    /// is returned and the old bytes stay valid.
    pub fn verify_checkpoint(
        &self,
        checkpoint: JsValue,
        rows: JsValue,
        top_seq: f64,
        sync_memory: Vec<u8>,
    ) -> Result<Vec<u8>, JsValue> {
        run(|| {
            let vault = self.unlocked()?;
            let checkpoint = checkpoint_of(from_js(checkpoint)?);
            let server_rows = server_rows_of(vault, from_js_list(rows)?)?;
            let mut memory = SyncMemory::from_bytes(&sync_memory)?;
            core(verify_checkpoint(
                vault,
                &checkpoint,
                &server_rows,
                js_u64(top_seq)?,
                RollbackMemory::Remembered(&mut memory),
            ))?;
            Ok(memory.to_bytes())
        })
    }

    /// Remembers the rows of an incremental `/changes` answer in the rollback
    /// memory. `rows` are as in `verify_checkpoint`: each tag or tombstone
    /// is checked here before the row counts. `top_seq` is the highest `seq`
    /// the server shows and `sync_memory` the stored memory bytes
    /// (`sync_memory_new()` for a device that has seen nothing yet). The
    /// highest seen `seq` and the `rev` of each item go up and never down: a
    /// `top_seq` below the highest seen is
    /// `checkpoint_top_seq_below_remembered` and a row with a lower `rev`
    /// than the highest seen for its item is `checkpoint_rev_below_remembered`.
    /// Returns the new memory bytes, which the client stores in place of the
    /// old ones; on any error nothing is returned and the old bytes stay
    /// valid.
    pub fn accept_rows(
        &self,
        rows: JsValue,
        top_seq: f64,
        sync_memory: Vec<u8>,
    ) -> Result<Vec<u8>, JsValue> {
        run(|| {
            let vault = self.unlocked()?;
            let server_rows = server_rows_of(vault, from_js_list(rows)?)?;
            let mut memory = SyncMemory::from_bytes(&sync_memory)?;
            core(memory.accept_rows(&server_rows, js_u64(top_seq)?))?;
            Ok(memory.to_bytes())
        })
    }

    /// Accepts an older state **after the user has confirmed** it (for
    /// example a server restored from a backup): the memory is replaced by
    /// the state of `checkpoint` and `rows`, which must verify on their own.
    /// This is the only call that lowers the floors of the rollback memory;
    /// it is never made by another call. `rows` and `top_seq` are as in
    /// `verify_checkpoint`. The old memory is not needed: the result is a new
    /// record. Returns the new memory bytes.
    pub fn accept_older_state(
        &self,
        checkpoint: JsValue,
        rows: JsValue,
        top_seq: f64,
    ) -> Result<Vec<u8>, JsValue> {
        run(|| {
            let vault = self.unlocked()?;
            let checkpoint = checkpoint_of(from_js(checkpoint)?);
            let server_rows = server_rows_of(vault, from_js_list(rows)?)?;
            let mut memory = SyncMemory::new();
            core(memory.accept_older_state(vault, &checkpoint, &server_rows, js_u64(top_seq)?))?;
            Ok(memory.to_bytes())
        })
    }

    // -------------------------------------------------- unlock methods

    /// Opens the method manifest row with the vault key and adds the
    /// generation floors of the server-side wraps to a pinned record. The
    /// record must be this vault's; returns the new record. Without it a
    /// device that unlocked with the password has no floor for the recovery
    /// wrap, and a rekey refuses.
    pub fn seed_pinned(&self, pinned: JsValue, manifest: JsValue) -> Result<JsValue, JsValue> {
        run(|| {
            let vault = self.unlocked()?;
            let mut record = from_js::<PinnedDto>(pinned)?.core()?;
            let row: RowDto = from_js(manifest)?;
            let m: Manifest = decrypt_manifest(vault, row.rev, &row.envelope, &row.tag)?;
            record.seed_from_manifest(&m)?;
            to_js(&PinnedDto::of(&record))
        })
    }

    /// A PIN wrap of the vault key (for the local PIN unlock, never
    /// uploaded). The device salt is drawn here. With `kek_dev_pin` (32 bytes
    /// from the platform keystore) it is the mobile variant. Argon2id runs in
    /// this worker. Returns the wrap record.
    pub fn wrap_pin(
        &self,
        pin: Vec<u8>,
        method_id: Vec<u8>,
        kek_dev_pin: Option<Vec<u8>>,
    ) -> Result<JsValue, JsValue> {
        run(|| {
            let pin = Zeroizing::new(pin);
            let dev = kek_dev_pin.map(Zeroizing::new);
            let vault = self.unlocked()?;
            let pin = Pin::new(&pin)?;
            let mut salt = [0u8; 16];
            ferret_core::SecureRng::fill(&mut OsRng, &mut salt);
            let kek = match &dev {
                Some(d) => Kek::from_pin_mobile(&pin, &salt, &KekDevPin::from_slice(d)?)?,
                None => Kek::from_pin_extension(&pin, &salt)?,
            };
            let rec = vault.wrap_for_method(
                &mut OsRng,
                &kek,
                MethodId::from_bytes(arr(&method_id)?),
                1,
                ferret_core::Method::Pin { device_salt: salt },
            )?;
            to_js(&WrapDto::of(&rec))
        })
    }

    /// A passkey (PRF) wrap of the vault key: `prf_output` is the 32 bytes
    /// the authenticator returned for `prf_salt`. Returns the wrap record.
    ///
    /// A passkey that Ferret itself stores cannot unlock the vault that holds
    /// it: its PRF seeds are inside the vault, so the method would lock the
    /// user out of the very vault it was meant to open (spec § 9.4). It is
    /// refused with `invalid_state` when
    ///
    /// * `aaguid` (16 bytes, from the attestation of the registration) is
    ///   Ferret's own (`ferret_aaguid()`), or
    /// * `credential_id` is the id of a passkey in an open item, or of one
    ///   in `stored_credential_ids`.
    ///
    /// `stored_credential_ids` is required: pass the `cred_id` of every
    /// passkey item of the vault (from `item_view`), as a non-empty array of
    /// `Uint8Array`, or the marker `"no_stored_passkeys"`
    /// (`NO_STORED_PASSKEYS` in the client) when there are none. An empty
    /// array is `invalid_input`. The binding cannot see items that are not
    /// open.
    ///
    /// `aaguid` is the 16 bytes at offset 37 of the authenticator data that
    /// the client parsed from the registration. It is the client's claim; the
    /// binding cannot see the attestation.
    #[allow(clippy::too_many_arguments)]
    pub fn wrap_prf(
        &self,
        credential_id: Vec<u8>,
        prf_salt: Vec<u8>,
        prf_output: Vec<u8>,
        method_id: Vec<u8>,
        kek_generation: f64,
        aaguid: Vec<u8>,
        stored_credential_ids: JsValue,
    ) -> Result<JsValue, JsValue> {
        run(|| {
            let prf_output = Zeroizing::new(prf_output);
            let vault = self.unlocked()?;
            let aaguid: [u8; 16] = arr(&aaguid)?;
            let stored = stored_list(stored_credential_ids)?;
            if aaguid == ferret_core::passkey::AAGUID
                || stored.iter().any(|s| s.0 == credential_id)
                || self.inner()?.items.values().any(|i| {
                    i.body
                        .passkey
                        .as_ref()
                        .is_some_and(|p| p.cred_id == credential_id)
                })
            {
                return Err(Error::InvalidState.into());
            }
            let kek = Kek::from_prf(&credential_id, &PrfOutput::from_slice(&prf_output)?)?;
            let rec = vault.wrap_for_method(
                &mut OsRng,
                &kek,
                MethodId::from_bytes(arr(&method_id)?),
                js_u64(kek_generation)?,
                ferret_core::Method::Prf {
                    credential_id,
                    prf_salt: arr(&prf_salt)?,
                },
            )?;
            to_js(&WrapDto::of(&rec))
        })
    }

    // ------------------------------------------------ setup and secrets

    /// The recovery key as `FFR1-...`, to be shown once after the setup, a
    /// recovery or a rekey. Available until the key has been typed back
    /// (`verify_recovery_setup`), `clear_setup_secrets` or `lock`.
    pub fn reveal_recovery_code(&self) -> Result<String, JsValue> {
        run(|| {
            let setup = self.inner()?.setup.as_ref().ok_or(Fail::Input)?;
            let rk = setup.recovery_key.as_ref().ok_or(Fail::Input)?;
            Ok(encode_recovery_key(rk).to_string())
        })
    }

    /// The secret key as `FFS1-...`, to be shown once after the setup.
    pub fn reveal_secret_key_code(&self) -> Result<String, JsValue> {
        run(|| {
            let setup = self.inner()?.setup.as_ref().ok_or(Fail::Input)?;
            let sk = setup.secret_key.as_ref().ok_or(Fail::Input)?;
            Ok(encode_secret_key(sk).to_string())
        })
    }

    /// The text of the emergency sheet: page 1 (address, e-mail, account id,
    /// secret key, QR payload) and the recovery key of page 2.
    pub fn reveal_emergency_sheet(
        &self,
        server_url: &str,
        email: &str,
    ) -> Result<JsValue, JsValue> {
        run(|| {
            let inner = self.inner()?;
            let setup = inner.setup.as_ref().ok_or(Fail::Input)?;
            let rk = setup.recovery_key.as_ref().ok_or(Fail::Input)?;
            let sheet = emergency_sheet(
                server_url,
                email,
                &inner.vault.context().account_id,
                setup.ksf_profile,
                &setup.server_public_key,
                setup.secret_key.as_ref(),
                rk,
            )?;
            to_js(&SheetDto {
                access: AccessPageDto {
                    server_url: sheet.access.server_url,
                    email: sheet.access.email,
                    account_id: sheet.access.account_id,
                    ksf_profile: sheet.access.ksf_profile,
                    secret_key_code: sheet.access.secret_key_code.map(|c| c.to_string()),
                    qr_payload: sheet.access.qr_payload,
                },
                recovery_key_code: sheet.recovery.recovery_key_code.to_string(),
            })
        })
    }

    /// The confirmation of the recovery key at setup: reads what the user
    /// typed, **opens the recovery wrap with it** and compares the vault key
    /// it holds with this vault's. A typo is `checksum`, a wrong key
    /// `decrypt`.
    pub fn verify_recovery_setup(
        &mut self,
        entered: &str,
        rk_wrap: JsValue,
    ) -> Result<(), JsValue> {
        run(|| {
            let rec = from_js::<WrapDto>(rk_wrap)?.core()?;
            core(verify_recovery_setup(entered, &rec, self.unlocked()?))?;
            self.setup_confirmed(true);
            Ok(())
        })
    }

    /// The confirmation of the secret key at setup: reads what the user typed
    /// and compares it with the secret key of this setup. A typo is
    /// `checksum`, another valid key `decrypt`.
    pub fn verify_secret_key_entry(&mut self, entered: &str) -> Result<(), JsValue> {
        run(|| {
            let setup = self.inner()?.setup.as_ref().ok_or(Fail::Input)?;
            let sk = setup.secret_key.as_ref().ok_or(Fail::Input)?;
            core(verify_secret_key_entry(entered, sk))?;
            self.setup_confirmed(false);
            Ok(())
        })
    }

    /// Wipes the recovery key and the secret key that a setup kept. They also
    /// go by themselves when the user has typed back every key the setup
    /// holds.
    pub fn clear_setup_secrets(&mut self) -> Result<(), JsValue> {
        run(|| {
            self.inner_mut()?.setup = None;
            Ok(())
        })
    }

    // ------------------------------------------------------------ rekey

    /// Puts a rekey that `UnlockJob.rekey` made into force: the new vault
    /// replaces this one (the old keys are wiped), every open item is closed
    /// and the new recovery key can be shown with `reveal_recovery_code`. Call
    /// it after the old vault has signed the request (`auth_sign("rekey")`)
    /// and the server has accepted it.
    pub fn rekey_commit(&mut self) -> Result<(), JsValue> {
        run(|| {
            let inner = self.inner_mut()?;
            let pending = inner.pending.take().ok_or(Fail::Input)?;
            inner.vault = pending.vault;
            inner.setup = Some(pending.setup);
            inner.items.clear();
            inner.export = None;
            inner.import = None;
            inner.passkey = None;
            inner.grant = None;
            Ok(())
        })
    }

    /// Drops a rekey that was made and not put into force (and wipes its
    /// keys).
    pub fn rekey_abort(&mut self) -> Result<(), JsValue> {
        run(|| {
            self.inner_mut()?.pending = None;
            Ok(())
        })
    }
}

impl Shaped for EntryDto {
    const SHAPE: Shape = Shape::Obj(&[("item_id", &ANY), ("rev", &ANY), ("hash", &ANY)]);
}

impl Shaped for ServerRowDto {
    const SHAPE: Shape = Shape::Obj(&[
        ("item_id", &ANY),
        ("rev", &ANY),
        ("state", &ANY),
        ("envelope", &ANY),
        ("tag", &ANY),
        ("tomb", &ANY),
    ]);
}
