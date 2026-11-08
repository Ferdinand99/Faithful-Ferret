//! A simulated client for the sync tests.
//!
//! [`World`] is one account on one in-process server with a real manifest and
//! a first checkpoint that verifies. [`SimClient`] is one device of that
//! account: it holds its own copy of the vault key, its own session (so its own
//! `device_id` on the server), its own [`SyncMemory`] and its own picture of
//! the rows, and it syncs through the real routes of the server with the real
//! core: tags, tombstones, checkpoints and the rollback memory are checked with
//! `ferret-core`, the way a client does it.
//!
//! The simulator is small on purpose. It follows the rules of the protocol that
//! a matrix of scenarios needs (Fase 1 § 8.3 to § 8.6) and nothing else:
//!
//! * a change is a draft until the server has stored it; a request that was
//!   sent is kept as it is and sent again, byte for byte, until an answer
//!   comes (the same `idem`);
//! * a `409`, or a row from the feed that is newer than the base of a draft,
//!   is a conflict; nothing is merged and nothing is thrown away until the
//!   user chooses ([`SimClient::keep_mine`], [`SimClient::keep_theirs`]);
//! * every row is verified before it is used, and a row that fails is refused
//!   with a warning while the rest of the page is kept;
//! * the rollback memory is checked before a page is applied and advanced
//!   after it, and a server that shows an older state stops the sync;
//! * a cursor below the floor of the feed (`410`) means a full listing, and
//!   a local row the listing lacks is kept and marked, never deleted.
//!
//! Nothing here sleeps and nothing reads the real time: the server runs on the
//! manual clock of the [`TestApp`], and a client's own clock (the `modified`
//! of a body) is that clock plus a skew a test sets.

use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicU8, Ordering};

use axum::body::Body;
use axum::http::{Method, Request, StatusCode};
use ferret_core::{
    Checkpoint, CheckpointEntry, CheckpointFailure, Error as CoreError, ItemBody, ItemType,
    Manifest, ManifestEntry, MethodId, OsRng, RollbackMemory, ServerRow, SyncMemory, UnlockedVault,
    VaultContext, VaultKey, decrypt_item, encrypt_item, encrypt_manifest, make_checkpoint,
    make_tombstone, verify_checkpoint,
};
use ferret_server::auth::session::Origin;
use ferret_server::ids::{ItemId, MANIFEST_ITEM_ID};
use ferret_server::vault::store::{CheckpointIn, ManifestIn, create_account};
use ferret_server::wire::{
    BatchRes, ChangeJson, ChangesRes, CheckpointJson, ConflictRes, ItemsRes, PutItemRes, b64url,
    hex16,
};
use ferret_server_auth::SessionScope;
use rusqlite::Connection;
use serde_json::{Value, json};

use super::accounts::{TestAccount, account_ids, id16, insert_user, rows};
use super::events::Stream;
use super::session::issue;
use super::{Jar, Req, Res, TestApp, Which};

/// The id of test item `n`: `0x10`, then `n` big-endian. The manifest id (16
/// zero bytes) is never one of them.
pub fn item(n: u16) -> ItemId {
    let mut bytes = [0u8; 16];
    bytes[0] = 0x10;
    bytes[1..3].copy_from_slice(&n.to_be_bytes());
    ItemId::from_bytes(bytes)
}

/// The id as 32 lower-case hexadecimal characters.
pub fn hex_of(id: ItemId) -> String {
    hex16::encode(id.as_bytes())
}

/// An `idem` that is `n` in its last bytes.
pub fn idem_of(n: u32) -> [u8; 16] {
    let mut bytes = [0xee; 16];
    bytes[12..].copy_from_slice(&n.to_be_bytes());
    bytes
}

/// The vault of account `n` as a device holds it. Every device of the world
/// has the same vault key: that is what makes them one account.
pub fn unlocked(account: &TestAccount, n: u8) -> UnlockedVault {
    UnlockedVault::from_vault_key(
        VaultContext {
            account_id: account.account_id,
            vault_id: account.vault_id,
            vk_epoch: 1,
        },
        VaultKey::from_test_bytes([n; 32]),
    )
    .expect("an unlocked vault")
}

/// A path as the text of a SQL string.
fn sql_text(path: &std::path::Path) -> String {
    path.to_string_lossy().replace('\'', "''")
}

/// One account with one vault on one server, and the devices that sync it.
pub struct World {
    pub app: Arc<TestApp>,
    pub account: TestAccount,
    n: u8,
    next_device: AtomicU8,
}

impl World {
    /// A server with the defaults and one account.
    pub async fn new() -> World {
        Self::on(TestApp::new().await).await
    }

    /// One account on `app`. The manifest is a real sealed manifest and the
    /// checkpoint at `seq` 1 is a real one over it, so a client that checks
    /// everything finds nothing wrong with a fresh vault.
    pub async fn on(app: TestApp) -> World {
        let n = 1u8;
        let app = Arc::new(app);
        let now = i64::try_from(app.state.clock.now_unix()).expect("a time");
        let ids = account_ids(0, n);
        let vault = unlocked(&ids, n);
        let manifest = Manifest::new(
            1,
            vec![
                ManifestEntry::new(1, MethodId::from_bytes(id16(0xc1, n)), 1),
                ManifestEntry::new(2, MethodId::from_bytes(id16(0xc2, n)), 1),
            ],
        );
        let sealed = encrypt_manifest(&mut OsRng, &vault, 1, &manifest).expect("a manifest");
        let first = make_checkpoint(
            &vault,
            1,
            vec![CheckpointEntry::live(MANIFEST_ITEM_ID, 1, &sealed.envelope)],
        )
        .expect("a checkpoint");
        let account = app
            .state
            .vault_db
            .with_conn(move |conn| {
                let user_id = insert_user(conn, &format!("user{n}@example.com"));
                let tx = conn.transaction()?;
                let mut new = rows(user_id, n, now);
                new.manifest = ManifestIn {
                    rev: 1,
                    envelope: sealed.envelope,
                    tag: sealed.tag,
                };
                new.checkpoint = CheckpointIn {
                    seq: 1,
                    digest: first.digest.to_vec(),
                    mac: first.mac.to_vec(),
                    entries: first.entries,
                };
                create_account(&tx, &new)?;
                tx.commit()?;
                Ok(account_ids(user_id, n))
            })
            .await
            .expect("an account");
        World {
            app,
            account,
            n,
            next_device: AtomicU8::new(10),
        }
    }

    /// A new device with its own session, signed in at the clock's time.
    pub async fn client(&self, name: &str) -> SimClient {
        let device_n = self.next_device.fetch_add(1, Ordering::Relaxed);
        let issued = issue(
            &self.app,
            self.account.user_id,
            Origin::Vault,
            SessionScope::Full,
            device_n,
        )
        .await;
        SimClient {
            name: name.to_string(),
            app: self.app.clone(),
            jar: issued.jar,
            vault: unlocked(&self.account, self.n),
            online: true,
            skew_ms: 0,
            counter: 0,
            device_n,
            lose_next: false,
            page_limit: 500,
            cursor: 0,
            top_seq: 0,
            restore_epoch: None,
            memory: SyncMemory::new(),
            locals: BTreeMap::new(),
        }
    }

    /// A new session of a device that was made before (the same `device_id`).
    pub async fn session_of(&self, device_n: u8) -> Jar {
        issue(
            &self.app,
            self.account.user_id,
            Origin::Vault,
            SessionScope::Full,
            device_n,
        )
        .await
        .jar
    }

    /// The vault as a device holds it.
    pub fn vault(&self) -> UnlockedVault {
        unlocked(&self.account, self.n)
    }

    /// Runs `f` on a connection to the database of the server.
    pub async fn db<T: Send + 'static>(
        &self,
        f: impl FnOnce(&mut Connection) -> T + Send + 'static,
    ) -> T {
        self.app
            .state
            .vault_db
            .with_conn(move |conn| Ok(f(conn)))
            .await
            .expect("the database")
    }

    /// The `seq` of the vault now.
    pub async fn server_seq(&self) -> u64 {
        let vault = self.account.vault_id;
        let seq = self
            .db(move |conn| {
                conn.query_row(
                    "SELECT seq FROM ferret_vaults WHERE vault_id = ?1",
                    [vault.as_bytes()],
                    |row| row.get::<_, i64>(0),
                )
                .expect("a seq")
            })
            .await;
        u64::try_from(seq).expect("a seq")
    }

    /// Copies the database to a file (a backup of the server).
    pub async fn snapshot(&self) -> PathBuf {
        let path = self.app.dir.join("snapshot.sqlite");
        let target = path.clone();
        self.db(move |conn| {
            let _ = std::fs::remove_file(&target);
            conn.execute_batch(&format!("VACUUM INTO '{}'", sql_text(&target)))
                .expect("a snapshot");
        })
        .await;
        path
    }

    /// Puts the rows of the vault back as the snapshot had them: the vault
    /// counters, the items, the checkpoint and the idempotency records. The
    /// sessions are left alone. This is what restoring the data directory of a
    /// server from a backup does to the vault.
    pub async fn restore_snapshot(&self, path: PathBuf) {
        self.db(move |conn| {
            conn.execute_batch(&format!(
                "ATTACH DATABASE '{}' AS snap",
                sql_text(&path)
            ))
            .expect("attach");
            let restored = conn.execute_batch(
                "BEGIN IMMEDIATE;
                 UPDATE ferret_vaults SET
                   seq = (SELECT s.seq FROM snap.ferret_vaults s WHERE s.vault_id = ferret_vaults.vault_id),
                   min_valid_since = (SELECT s.min_valid_since FROM snap.ferret_vaults s WHERE s.vault_id = ferret_vaults.vault_id),
                   restore_epoch = (SELECT s.restore_epoch FROM snap.ferret_vaults s WHERE s.vault_id = ferret_vaults.vault_id),
                   item_count = (SELECT s.item_count FROM snap.ferret_vaults s WHERE s.vault_id = ferret_vaults.vault_id),
                   bytes_used = (SELECT s.bytes_used FROM snap.ferret_vaults s WHERE s.vault_id = ferret_vaults.vault_id);
                 DELETE FROM main.ferret_items;
                 INSERT INTO main.ferret_items SELECT * FROM snap.ferret_items;
                 DELETE FROM main.ferret_checkpoints;
                 INSERT INTO main.ferret_checkpoints SELECT * FROM snap.ferret_checkpoints;
                 DELETE FROM main.ferret_idem;
                 INSERT INTO main.ferret_idem SELECT * FROM snap.ferret_idem;
                 COMMIT;",
            );
            restored.expect("restore the snapshot");
            conn.execute_batch("DETACH DATABASE snap").expect("detach");
        })
        .await;
    }

    /// `ferret restore-epoch bump`: the epoch of every vault goes up by one.
    pub async fn bump_restore_epoch(&self) -> u64 {
        self.db(|conn| ferret_server::vault::reconcile::bump_restore_epoch(conn).expect("a bump"))
            .await
    }

    /// Runs the retention pass at `now` (Unix seconds), as the daily job does,
    /// without moving the clock of the server (a session would run out).
    pub async fn run_retention(&self, now: i64) {
        self.db(move |conn| {
            ferret_server::vault::retention::run_once(conn, now).expect("a retention pass");
        })
        .await;
    }
}

// ------------------------------------------------------------------ rows

/// What a row is on the server, as a client holds it after checking it.
#[derive(Clone, Debug, PartialEq, Eq)]
enum RowKind {
    Live {
        blob: Vec<u8>,
        tag: [u8; 32],
    },
    /// An empty `tomb` is a tombstone that a `409` announced and the feed has
    /// not yet shown (so it is not checked).
    Deleted {
        tomb: Vec<u8>,
    },
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct Seen {
    rev: u64,
    row: RowKind,
}

/// A change the user made that the server has not stored yet.
#[derive(Clone, Debug)]
enum Draft {
    Edit(Box<ItemBody>),
    Delete,
}

/// The request that was sent, kept as it is.
#[derive(Clone, Debug)]
struct Inflight {
    request: Value,
    row: RowKind,
}

#[derive(Clone, Debug, Default)]
struct Local {
    /// The newest row of the server that was checked, as far as this device
    /// knows.
    seen: Option<Seen>,
    draft: Option<Draft>,
    inflight: Option<Inflight>,
    /// The server has a row newer than the base of the draft. The server's row
    /// is `seen`; the draft is the local version.
    conflict: bool,
    /// Set by "keep mine" against a deleted row.
    resurrect: bool,
    /// The server shows this tombstone with a tag that is not valid.
    quarantined: bool,
    /// A listing did not have this row, and this device still has it.
    missing_on_server: bool,
}

/// An item as the user would see it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum View {
    Absent,
    Deleted,
    Live {
        name: String,
        notes: Option<String>,
    },
    /// The row is there and cannot be opened.
    Unreadable,
}

impl View {
    /// The view of a note made by [`SimClient::edit`] with this name.
    pub fn note(name: &str) -> View {
        View::Live {
            name: name.to_string(),
            notes: Some(format!("notes of {name}")),
        }
    }
}

/// Something a client would show to the user as a warning.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Warning {
    /// A live row whose tag is not valid. The row is not used.
    RowRefused { id: ItemId },
    /// A tombstone that is not valid. The item is quarantined and the local
    /// copy stays.
    TombstoneRefused { id: ItemId },
    /// A row below the highest `rev` this device has seen.
    RolledBackRow { id: ItemId },
    /// The server's top is below the highest `seq` this device has seen.
    RollbackSuspected,
    /// A higher `restore_epoch` and something lower than before.
    ServerRestored { epoch: u64 },
    /// A lower `restore_epoch` than the one remembered.
    RestoreEpochLowered,
    /// The checkpoint did not match what the server shows.
    Checkpoint(CheckpointFailure),
    /// The memory holds as many items as it can.
    MemoryFull,
    /// The server sent something that a server cannot send.
    BadFeed(&'static str),
    /// The server has no row for something this device sent a revision of.
    RowMissing { id: ItemId },
    /// Another error from the core.
    Core(String),
}

impl Warning {
    fn from_core(e: CoreError) -> Warning {
        match e {
            CoreError::Checkpoint(kind) => Warning::Checkpoint(kind),
            other => Warning::Core(format!("{other:?}")),
        }
    }

    /// A warning that stops the sync (nothing is read or written until the
    /// user acts).
    pub fn halts(&self) -> bool {
        matches!(
            self,
            Warning::RollbackSuspected
                | Warning::ServerRestored { .. }
                | Warning::RestoreEpochLowered
                | Warning::MemoryFull
        )
    }
}

/// What one call of [`SimClient::sync`], [`SimClient::push`] or
/// [`SimClient::pull`] did.
#[derive(Clone, Debug, Default)]
pub struct SyncReport {
    /// Items that became conflicts in this call.
    pub conflicts: Vec<ItemId>,
    pub warnings: Vec<Warning>,
    /// Writes the server stored (replays included).
    pub pushed: usize,
    /// Of those, the ones the server answered from its record of the `idem`.
    pub replayed: usize,
    /// Writes the server refused: the item, the status and the code.
    pub refused: Vec<(ItemId, u16, String)>,
    /// `Retry-After` of a `429` or `503`.
    pub retry_after: Option<u32>,
}

impl SyncReport {
    /// Whether a warning in the report stops the sync.
    pub fn halted(&self) -> bool {
        self.warnings.iter().any(Warning::halts)
    }

    fn merge(&mut self, other: SyncReport) {
        for id in other.conflicts {
            if !self.conflicts.contains(&id) {
                self.conflicts.push(id);
            }
        }
        self.warnings.extend(other.warnings);
        self.pushed += other.pushed;
        self.replayed += other.replayed;
        self.refused.extend(other.refused);
        self.retry_after = other.retry_after.or(self.retry_after);
    }
}

/// A row that has been checked.
type Verified = (ItemId, ServerRow, Seen);

/// A full listing, as the pages gave it.
struct Listing {
    items: Vec<ChangeJson>,
    as_of_seq: u64,
    restore_epoch: u64,
}

fn error_of(res: &Res) -> String {
    serde_json::from_slice::<Value>(&res.body)
        .ok()
        .and_then(|v| v["error"].as_str().map(str::to_string))
        .unwrap_or_default()
}

/// One device of the account.
pub struct SimClient {
    pub name: String,
    app: Arc<TestApp>,
    jar: Jar,
    vault: UnlockedVault,
    online: bool,
    skew_ms: i64,
    counter: u32,
    device_n: u8,
    lose_next: bool,
    page_limit: u32,
    cursor: u64,
    top_seq: u64,
    restore_epoch: Option<u64>,
    memory: SyncMemory,
    locals: BTreeMap<[u8; 16], Local>,
}

impl SimClient {
    // ---------------------------------------------------------- the user

    /// Writes (or rewrites) a note called `name` as a draft. Nothing is sent.
    pub fn edit(&mut self, id: ItemId, name: &str) {
        assert_ne!(id, MANIFEST_ITEM_ID, "the manifest is not an item");
        let now = self.local_ms();
        let mut body = ItemBody::new(ItemType::Note, name, now);
        body.notes = Some(format!("notes of {name}"));
        body.device = Some(self.name.clone());
        let local = self.locals.entry(*id.as_bytes()).or_default();
        assert!(
            local.inflight.is_none(),
            "an edit while a request is in flight: sync first"
        );
        local.draft = Some(Draft::Edit(Box::new(body)));
    }

    /// Deletes an item as a draft. Nothing is sent.
    pub fn delete(&mut self, id: ItemId) {
        let local = self.locals.entry(*id.as_bytes()).or_default();
        assert!(
            local.inflight.is_none(),
            "a delete while a request is in flight: sync first"
        );
        local.draft = Some(Draft::Delete);
    }

    /// The network goes away: syncing does nothing until it is back.
    pub fn go_offline(&mut self) {
        self.online = false;
    }

    pub fn go_online(&mut self) {
        self.online = true;
    }

    pub fn is_online(&self) -> bool {
        self.online
    }

    /// The clock of this device is `ms` milliseconds away from the server's.
    pub fn set_clock_skew_ms(&mut self, ms: i64) {
        self.skew_ms = ms;
    }

    /// The server will have handled the next write, and the answer is lost on
    /// the way back.
    pub fn lose_next_response(&mut self) {
        self.lose_next = true;
    }

    /// Pages of this many rows (at most 500), to make a listing or a pull use
    /// several requests.
    pub fn set_page_limit(&mut self, limit: u32) {
        self.page_limit = limit;
    }

    /// The user keeps the local version: the draft goes out on top of the
    /// server's row, and against a deleted row it asks for a resurrection.
    pub fn keep_mine(&mut self, id: ItemId) {
        let local = self.locals.get_mut(id.as_bytes()).expect("an item");
        assert!(local.conflict, "no conflict on this item");
        local.resurrect = matches!(
            (&local.draft, local.seen.as_ref().map(|s| &s.row)),
            (Some(Draft::Edit(_)), Some(RowKind::Deleted { .. }))
        );
        local.conflict = false;
        local.inflight = None;
    }

    /// The user keeps the server's version: the draft is thrown away.
    pub fn keep_theirs(&mut self, id: ItemId) {
        let local = self.locals.get_mut(id.as_bytes()).expect("an item");
        assert!(local.conflict, "no conflict on this item");
        local.draft = None;
        local.conflict = false;
        local.inflight = None;
    }

    // ----------------------------------------------------------- what is known

    /// The item as the user sees it here: the draft if there is one, else the
    /// row of the server.
    pub fn view(&self, id: ItemId) -> View {
        let Some(local) = self.locals.get(id.as_bytes()) else {
            return View::Absent;
        };
        match &local.draft {
            Some(Draft::Edit(body)) => View::Live {
                name: body.name.clone(),
                notes: body.notes.clone(),
            },
            Some(Draft::Delete) => View::Deleted,
            None => self.server_view(id),
        }
    }

    /// The row of the server as this device last checked it.
    pub fn server_view(&self, id: ItemId) -> View {
        match self.locals.get(id.as_bytes()).and_then(|l| l.seen.as_ref()) {
            None => View::Absent,
            Some(seen) => self.decode(id, seen),
        }
    }

    fn decode(&self, id: ItemId, seen: &Seen) -> View {
        match &seen.row {
            RowKind::Deleted { .. } => View::Deleted,
            RowKind::Live { blob, tag } => {
                match decrypt_item(&self.vault, id, seen.rev, blob, tag) {
                    Ok(item) => View::Live {
                        name: item.body.name.clone(),
                        notes: item.body.notes.clone(),
                    },
                    Err(_) => View::Unreadable,
                }
            }
        }
    }

    /// The revision of the server's row that this device has seen (0: none).
    pub fn rev_of(&self, id: ItemId) -> u64 {
        self.locals
            .get(id.as_bytes())
            .and_then(|l| l.seen.as_ref())
            .map_or(0, |s| s.rev)
    }

    /// Whether the item has a draft that has not been stored.
    pub fn has_draft(&self, id: ItemId) -> bool {
        self.locals
            .get(id.as_bytes())
            .is_some_and(|l| l.draft.is_some())
    }

    /// Whether a request for the item was sent and no answer came.
    pub fn is_in_flight(&self, id: ItemId) -> bool {
        self.locals
            .get(id.as_bytes())
            .is_some_and(|l| l.inflight.is_some())
    }

    pub fn has_conflict(&self, id: ItemId) -> bool {
        self.locals.get(id.as_bytes()).is_some_and(|l| l.conflict)
    }

    /// The items in conflict now.
    pub fn conflicts(&self) -> Vec<ItemId> {
        self.locals
            .iter()
            .filter(|(_, l)| l.conflict)
            .map(|(id, _)| ItemId::from_bytes(*id))
            .collect()
    }

    pub fn is_quarantined(&self, id: ItemId) -> bool {
        self.locals
            .get(id.as_bytes())
            .is_some_and(|l| l.quarantined)
    }

    /// The listing did not have this item, and this device keeps it.
    pub fn is_missing_on_server(&self, id: ItemId) -> bool {
        self.locals
            .get(id.as_bytes())
            .is_some_and(|l| l.missing_on_server)
    }

    /// The items that are live here (a draft or a row), in id order.
    pub fn live_items(&self) -> Vec<ItemId> {
        self.locals
            .keys()
            .map(|k| ItemId::from_bytes(*k))
            .filter(|id| *id != MANIFEST_ITEM_ID)
            .filter(|id| matches!(self.view(*id), View::Live { .. }))
            .collect()
    }

    /// What this device knows of the server, as `(id, rev, deleted)` of every
    /// row it has checked, the manifest and the tombstones included.
    pub fn known_rows(&self) -> Vec<(ItemId, u64, bool)> {
        self.locals
            .iter()
            .filter_map(|(id, l)| {
                l.seen.as_ref().map(|s| {
                    (
                        ItemId::from_bytes(*id),
                        s.rev,
                        matches!(s.row, RowKind::Deleted { .. }),
                    )
                })
            })
            .collect()
    }

    pub fn memory(&self) -> &SyncMemory {
        &self.memory
    }

    pub fn memory_mut(&mut self) -> &mut SyncMemory {
        &mut self.memory
    }

    /// The `seq` the feed is read up to.
    pub fn cursor(&self) -> u64 {
        self.cursor
    }

    pub fn restore_epoch(&self) -> Option<u64> {
        self.restore_epoch
    }

    /// The cookies of this device, to send a request that the simulator does
    /// not make itself.
    pub fn jar(&self) -> &Jar {
        &self.jar
    }

    /// The vault of this device (to seal a row by hand).
    pub fn vault(&self) -> &UnlockedVault {
        &self.vault
    }

    /// The number of this device, as the server sees it.
    pub fn device_n(&self) -> u8 {
        self.device_n
    }

    /// The event stream of this device's session.
    pub async fn open_events(&self) -> Stream {
        self.app.events(&self.jar).await
    }

    /// The `modified` of the body of the item here: the draft's, else the
    /// server's row's. It is the device's own clock.
    pub fn modified_ms(&self, id: ItemId) -> Option<u64> {
        let local = self.locals.get(id.as_bytes())?;
        if let Some(Draft::Edit(body)) = &local.draft {
            return Some(body.modified);
        }
        local
            .seen
            .as_ref()
            .and_then(|seen| self.decode_body(id, seen))
            .map(|body| body.modified)
    }

    // ------------------------------------------------------------------ sync

    /// A sync: read the feed first (so a halt stops the writes), then send
    /// the drafts.
    pub async fn sync(&mut self) -> SyncReport {
        let mut report = self.pull().await;
        if report.halted() {
            return report;
        }
        let pushed = self.push().await;
        report.merge(pushed);
        report
    }

    /// Sends the drafts, one request each. An item in conflict waits for the
    /// user's choice.
    pub async fn push(&mut self) -> SyncReport {
        let mut report = SyncReport::default();
        if !self.online {
            return report;
        }
        let ids: Vec<[u8; 16]> = self
            .locals
            .iter()
            .filter(|(_, l)| (l.draft.is_some() || l.inflight.is_some()) && !l.conflict)
            .map(|(id, _)| *id)
            .collect();
        for key in ids {
            if !self.push_one(ItemId::from_bytes(key), &mut report).await {
                break;
            }
        }
        report
    }

    /// Reads the feed from the cursor to the top (or lists everything after a
    /// `410`), checks what comes and applies it.
    pub async fn pull(&mut self) -> SyncReport {
        let mut report = SyncReport::default();
        if !self.online {
            return report;
        }
        let mut since = self.cursor;
        let mut listed = false;
        loop {
            let uri = format!("/api/sync/changes?since={since}&limit={}", self.page_limit);
            let res = self.send(Method::GET, &uri, None).await;
            if res.status == StatusCode::GONE {
                if listed {
                    report
                        .warnings
                        .push(Warning::BadFeed("410 right after a listing"));
                    return report;
                }
                listed = true;
                if !self.reconcile(&mut report).await {
                    return report;
                }
                since = self.cursor;
                continue;
            }
            if res.status != StatusCode::OK {
                report
                    .refused
                    .push((MANIFEST_ITEM_ID, res.status.as_u16(), error_of(&res)));
                return report;
            }
            let Ok(page) = serde_json::from_slice::<ChangesRes>(&res.body) else {
                report
                    .warnings
                    .push(Warning::BadFeed("a page that is not a page"));
                return report;
            };
            if !self.check_head(page.restore_epoch, page.latest_seq, &mut report) {
                return report;
            }
            let mut verified = Vec::new();
            for change in &page.changes {
                match self.verify_row(change) {
                    Ok(v) => verified.push(v),
                    Err(w) => self.refuse(w, &mut report),
                }
            }
            let Some(accepted) = self.remember(verified, page.latest_seq, &mut report) else {
                return report;
            };
            for (id, _, seen) in accepted {
                self.apply(id, seen, &mut report);
            }
            if self.restore_epoch.is_none_or(|e| page.restore_epoch > e) {
                self.restore_epoch = Some(page.restore_epoch);
            }
            if page.has_more {
                let Some(last) = page.changes.last() else {
                    report
                        .warnings
                        .push(Warning::BadFeed("more rows, but an empty page"));
                    return report;
                };
                since = last.seq;
                self.cursor = since;
            } else {
                // The feed is drained: the top the server named is where this
                // device stands now.
                self.cursor = page.latest_seq;
                self.top_seq = page.latest_seq;
                return report;
            }
        }
    }

    // --------------------------------------------------------------- pushing

    async fn push_one(&mut self, id: ItemId, report: &mut SyncReport) -> bool {
        let key = *id.as_bytes();
        if self.locals.get(&key).is_some_and(|l| l.inflight.is_none()) {
            let inflight = self.seal(id);
            self.locals.get_mut(&key).expect("a local").inflight = Some(inflight);
        }
        let inflight = self
            .locals
            .get(&key)
            .and_then(|l| l.inflight.clone())
            .expect("a request in flight");
        let uri = format!("/api/sync/items/{}", hex_of(id));
        let res = self.send(Method::PUT, &uri, Some(&inflight.request)).await;
        if self.lose_next {
            // The server did its part; the answer never arrives.
            self.lose_next = false;
            return true;
        }
        self.handle_put(id, inflight, res, report)
    }

    /// Seals the draft of `id` on top of the row of the server that this device
    /// has seen, and makes the request that will be sent again as it is.
    fn seal(&mut self, id: ItemId) -> Inflight {
        self.counter += 1;
        let idem = idem_of((u32::from(self.device_n) << 24) | self.counter);
        let local = self.locals.get(id.as_bytes()).expect("a local");
        let base = local.seen.as_ref().map_or(0, |s| s.rev);
        let rev = base + 1;
        match local.draft.as_ref().expect("a draft") {
            Draft::Edit(body) => {
                let existing = match local.seen.as_ref().map(|s| &s.row) {
                    Some(RowKind::Live { blob, .. }) => Some(blob.as_slice()),
                    _ => None,
                };
                let sealed = encrypt_item(&mut OsRng, &self.vault, id, rev, body, existing)
                    .expect("a sealed item");
                let mut request = json!({
                    "base_rev": base,
                    "blob": b64url::encode(&sealed.envelope),
                    "tag": b64url::encode(&sealed.tag),
                    "idem": hex16::encode(&idem),
                });
                if local.resurrect {
                    request["resurrect"] = json!(true);
                }
                Inflight {
                    request,
                    row: RowKind::Live {
                        blob: sealed.envelope,
                        tag: sealed.tag,
                    },
                }
            }
            Draft::Delete => {
                let tomb = make_tombstone(&mut OsRng, &self.vault, id, rev).expect("a tombstone");
                Inflight {
                    request: json!({
                        "base_rev": base,
                        "deleted": true,
                        "tomb": b64url::encode(&tomb.tomb),
                        "idem": hex16::encode(&idem),
                    }),
                    row: RowKind::Deleted { tomb: tomb.tomb },
                }
            }
        }
    }

    /// Whether to go on with the next item.
    fn handle_put(
        &mut self,
        id: ItemId,
        inflight: Inflight,
        res: Res,
        report: &mut SyncReport,
    ) -> bool {
        let key = *id.as_bytes();
        match res.status.as_u16() {
            200 => {
                let done: PutItemRes = serde_json::from_slice(&res.body).expect("a put answer");
                report.pushed += 1;
                if done.replayed {
                    report.replayed += 1;
                }
                let local = self.locals.get_mut(&key).expect("a local");
                local.seen = Some(Seen {
                    rev: done.rev,
                    row: inflight.row,
                });
                local.draft = None;
                local.inflight = None;
                local.resurrect = false;
                true
            }
            409 => {
                let c: ConflictRes = serde_json::from_slice(&res.body).expect("a conflict");
                c.validate().expect("a valid conflict answer");
                self.handle_conflict(id, inflight, c, report);
                true
            }
            429 | 503 => {
                report.retry_after = res.header("retry-after").parse().ok();
                false
            }
            status => {
                // Refused for good: the request is not sent again.
                report.refused.push((id, status, error_of(&res)));
                self.locals.get_mut(&key).expect("a local").inflight = None;
                true
            }
        }
    }

    fn handle_conflict(
        &mut self,
        id: ItemId,
        inflight: Inflight,
        c: ConflictRes,
        report: &mut SyncReport,
    ) {
        let key = *id.as_bytes();
        // The row of the server is the row this device sent: the write is
        // stored, and the answer to the first try is gone (§ 8.3).
        if let (Some(blob), Some(tag)) = (&c.blob, &c.tag)
            && inflight.row
                == (RowKind::Live {
                    blob: blob.clone(),
                    tag: *tag,
                })
        {
            let local = self.locals.get_mut(&key).expect("a local");
            local.seen = Some(Seen {
                rev: c.current_rev,
                row: inflight.row,
            });
            local.draft = None;
            local.inflight = None;
            local.resurrect = false;
            report.pushed += 1;
            return;
        }
        let seen = match (c.deleted, c.blob, c.tag) {
            (true, _, _) => Seen {
                rev: c.current_rev,
                row: RowKind::Deleted { tomb: Vec::new() },
            },
            (false, Some(blob), Some(tag)) => {
                match ServerRow::live(&self.vault, id, c.current_rev, &blob, &tag) {
                    Ok(row) => {
                        // A row that checks out is a row the server showed.
                        let top = self.memory.max_seq();
                        if self.memory.accept_rows(&[row], top).is_err() {
                            report.warnings.push(Warning::RolledBackRow { id });
                            self.locals.get_mut(&key).expect("a local").inflight = None;
                            return;
                        }
                        Seen {
                            rev: c.current_rev,
                            row: RowKind::Live { blob, tag },
                        }
                    }
                    Err(_) => {
                        report.warnings.push(Warning::RowRefused { id });
                        self.locals.get_mut(&key).expect("a local").inflight = None;
                        return;
                    }
                }
            }
            _ => {
                // No row on the server for a revision this device built on.
                report.warnings.push(Warning::RowMissing { id });
                self.locals.get_mut(&key).expect("a local").inflight = None;
                return;
            }
        };
        let local = self.locals.get_mut(&key).expect("a local");
        local.seen = Some(seen);
        local.inflight = None;
        if !local.conflict {
            local.conflict = true;
            report.conflicts.push(id);
        }
    }

    // --------------------------------------------------------------- reading

    /// The checks on the head of a page that come before the rows: a lower
    /// `restore_epoch`, and a higher one with a lower top than remembered.
    fn check_head(&self, restore_epoch: u64, top: u64, report: &mut SyncReport) -> bool {
        match self.restore_epoch {
            Some(known) if restore_epoch < known => {
                report.warnings.push(Warning::RestoreEpochLowered);
                false
            }
            Some(known) if restore_epoch > known && top < self.memory.max_seq() => {
                report.warnings.push(Warning::ServerRestored {
                    epoch: restore_epoch,
                });
                false
            }
            _ => true,
        }
    }

    fn verify_row(&self, change: &ChangeJson) -> Result<Verified, Warning> {
        let id = ItemId::from_bytes(change.id);
        if change.deleted {
            let tomb = change
                .tomb
                .clone()
                .ok_or(Warning::BadFeed("a tombstone without a tomb"))?;
            let row = ServerRow::deleted(&self.vault, id, change.rev, &tomb)
                .map_err(|_| Warning::TombstoneRefused { id })?;
            Ok((
                id,
                row,
                Seen {
                    rev: change.rev,
                    row: RowKind::Deleted { tomb },
                },
            ))
        } else {
            let (Some(blob), Some(tag)) = (change.blob.clone(), change.tag) else {
                return Err(Warning::BadFeed("a live row without a blob and a tag"));
            };
            let row = ServerRow::live(&self.vault, id, change.rev, &blob, &tag)
                .map_err(|_| Warning::RowRefused { id })?;
            Ok((
                id,
                row,
                Seen {
                    rev: change.rev,
                    row: RowKind::Live { blob, tag },
                },
            ))
        }
    }

    /// Notes a refused row: a tombstone that does not check out quarantines the
    /// item and leaves the local copy where it is.
    fn refuse(&mut self, warning: Warning, report: &mut SyncReport) {
        if let Warning::TombstoneRefused { id } = &warning {
            self.locals.entry(*id.as_bytes()).or_default().quarantined = true;
        }
        report.warnings.push(warning);
    }

    /// Checks verified rows against the memory, row by row, and remembers the
    /// ones that pass. `None`: the sync must stop.
    fn remember(
        &mut self,
        verified: Vec<Verified>,
        top: u64,
        report: &mut SyncReport,
    ) -> Option<Vec<Verified>> {
        // The top itself, whatever the rows are.
        if self.memory.check_rows(&[], top).is_err() {
            report.warnings.push(Warning::RollbackSuspected);
            return None;
        }
        let mut accepted = Vec::new();
        for entry in verified {
            match self.memory.check_rows(&[entry.1], top) {
                Ok(()) => accepted.push(entry),
                Err(CoreError::Checkpoint(CheckpointFailure::RememberedRev)) => {
                    report.warnings.push(Warning::RolledBackRow { id: entry.0 });
                }
                Err(e) => {
                    report.warnings.push(Warning::from_core(e));
                    return None;
                }
            }
        }
        let rows: Vec<ServerRow> = accepted.iter().map(|v| v.1).collect();
        match self.memory.accept_rows(&rows, top) {
            Ok(()) => Some(accepted),
            Err(CoreError::TooLarge) => {
                report.warnings.push(Warning::MemoryFull);
                None
            }
            Err(e) => {
                report.warnings.push(Warning::from_core(e));
                None
            }
        }
    }

    /// Takes a checked row of the server into the local picture.
    fn apply(&mut self, id: ItemId, seen: Seen, report: &mut SyncReport) {
        let local = self.locals.entry(*id.as_bytes()).or_default();
        let newer = match &local.seen {
            None => true,
            Some(old) => {
                seen.rev > old.rev
                    || (seen.rev == old.rev
                        && matches!(&old.row, RowKind::Deleted { tomb } if tomb.is_empty()))
            }
        };
        if !newer {
            return;
        }
        // The row is the one this device sent and never got an answer for.
        let own = local
            .inflight
            .as_ref()
            .is_some_and(|inflight| inflight.row == seen.row);
        local.seen = Some(seen.clone());
        local.missing_on_server = false;
        local.quarantined = false;
        if own {
            local.draft = None;
            local.inflight = None;
            local.resurrect = false;
            local.conflict = false;
            return;
        }
        match (&local.draft, &seen.row) {
            (None, _) => {}
            // Deleted here and deleted there: nothing to choose.
            (Some(Draft::Delete), RowKind::Deleted { .. }) => {
                local.draft = None;
                local.inflight = None;
                local.conflict = false;
            }
            (Some(_), _) => {
                local.inflight = None;
                if !local.conflict {
                    local.conflict = true;
                    report.conflicts.push(id);
                }
            }
        }
    }

    // --------------------------------------------------------------- listing

    /// The whole vault in pages, checked for order and for the same epochs on
    /// every page.
    async fn list_all(&mut self, report: &mut SyncReport) -> Option<Listing> {
        let mut items: Vec<ChangeJson> = Vec::new();
        let mut after: Option<[u8; 16]> = None;
        let mut first: Option<(u64, u64, u64)> = None;
        let mut last_id: Option<[u8; 16]> = None;
        loop {
            let mut uri = format!("/api/sync/items?limit={}", self.page_limit);
            if let Some(a) = after {
                uri.push_str(&format!("&after={}", hex16::encode(&a)));
            }
            let res = self.send(Method::GET, &uri, None).await;
            if res.status != StatusCode::OK {
                report
                    .refused
                    .push((MANIFEST_ITEM_ID, res.status.as_u16(), error_of(&res)));
                return None;
            }
            let Ok(page) = serde_json::from_slice::<ItemsRes>(&res.body) else {
                report
                    .warnings
                    .push(Warning::BadFeed("a listing page that is not one"));
                return None;
            };
            if page.validate().is_err() {
                report
                    .warnings
                    .push(Warning::BadFeed("next_after and has_more disagree"));
                return None;
            }
            match first {
                None => first = Some((page.as_of_seq, page.vk_epoch, page.restore_epoch)),
                Some((_, vk, re)) if vk != page.vk_epoch || re != page.restore_epoch => {
                    report
                        .warnings
                        .push(Warning::BadFeed("an epoch changed during the listing"));
                    return None;
                }
                Some(_) => {}
            }
            for it in &page.items {
                if last_id.is_some_and(|l| it.id <= l) {
                    report
                        .warnings
                        .push(Warning::BadFeed("ids that do not rise across pages"));
                    return None;
                }
                last_id = Some(it.id);
            }
            items.extend(page.items);
            if page.has_more {
                after = page.next_after;
            } else {
                break;
            }
        }
        let (as_of_seq, _, restore_epoch) = first.expect("one page at least");
        Some(Listing {
            items,
            as_of_seq,
            restore_epoch,
        })
    }

    /// The full listing after a `410`: every row is checked, the memory is
    /// advanced, the rows are applied, and what the listing lacks is kept and
    /// marked. The cursor is the `as_of_seq` of the first page.
    async fn reconcile(&mut self, report: &mut SyncReport) -> bool {
        let Some(listing) = self.list_all(report).await else {
            return false;
        };
        if !self.check_head(listing.restore_epoch, listing.as_of_seq, report) {
            return false;
        }
        let mut verified = Vec::new();
        for change in &listing.items {
            match self.verify_row(change) {
                Ok(v) => verified.push(v),
                Err(w) => self.refuse(w, report),
            }
        }
        let Some(accepted) = self.remember(verified, listing.as_of_seq, report) else {
            return false;
        };
        for (id, _, seen) in accepted {
            self.apply(id, seen, report);
        }
        let listed: BTreeSet<[u8; 16]> = listing.items.iter().map(|c| c.id).collect();
        for (key, local) in &mut self.locals {
            let live_here = matches!(
                local.seen.as_ref().map(|s| &s.row),
                Some(RowKind::Live { .. })
            );
            if *key != *MANIFEST_ITEM_ID.as_bytes() && !listed.contains(key) && live_here {
                local.missing_on_server = true;
            }
        }
        if self.restore_epoch.is_none_or(|e| listing.restore_epoch > e) {
            self.restore_epoch = Some(listing.restore_epoch);
        }
        self.cursor = listing.as_of_seq;
        self.top_seq = listing.as_of_seq;
        true
    }

    // ------------------------------------------------------------ checkpoints

    /// Every row this device has checked, as the core wants them.
    fn server_rows(&self) -> Vec<ServerRow> {
        self.locals
            .iter()
            .filter_map(|(key, l)| {
                let seen = l.seen.as_ref()?;
                let id = ItemId::from_bytes(*key);
                match &seen.row {
                    RowKind::Live { blob, tag } => {
                        ServerRow::live(&self.vault, id, seen.rev, blob, tag).ok()
                    }
                    RowKind::Deleted { tomb } => {
                        ServerRow::deleted(&self.vault, id, seen.rev, tomb).ok()
                    }
                }
            })
            .collect()
    }

    /// The checkpoint the server holds, as the server serves it.
    pub async fn fetch_checkpoint(&self) -> Result<Checkpoint, Warning> {
        let res = self.send(Method::GET, "/api/sync/checkpoint", None).await;
        if res.status != StatusCode::OK {
            return Err(Warning::BadFeed("no checkpoint"));
        }
        let json: CheckpointJson = serde_json::from_slice(&res.body)
            .map_err(|_| Warning::BadFeed("a checkpoint that is not one"))?;
        Ok(Checkpoint {
            seq: json.seq,
            digest: json.digest,
            mac: json.mac,
            entries: json.entries,
        })
    }

    /// Checks the stored checkpoint against what this device has seen, with the
    /// rollback memory (§ 8.6).
    pub async fn verify(&mut self) -> Result<(), Warning> {
        let checkpoint = self.fetch_checkpoint().await?;
        let rows = self.server_rows();
        verify_checkpoint(
            &self.vault,
            &checkpoint,
            &rows,
            self.top_seq,
            RollbackMemory::Remembered(&mut self.memory),
        )
        .map_err(Warning::from_core)
    }

    /// The checkpoint of this device's state at the top it has read to.
    pub fn make_checkpoint(&self) -> Checkpoint {
        let entries: Vec<CheckpointEntry> = self
            .locals
            .iter()
            .filter_map(|(key, l)| {
                let seen = l.seen.as_ref()?;
                let id = ItemId::from_bytes(*key);
                Some(match &seen.row {
                    RowKind::Live { blob, .. } => CheckpointEntry::live(id, seen.rev, blob),
                    RowKind::Deleted { .. } => CheckpointEntry::tombstone(id, seen.rev),
                })
            })
            .collect();
        make_checkpoint(&self.vault, self.top_seq, entries).expect("a checkpoint")
    }

    /// Uploads the checkpoint of this device's state; the answer as it came.
    pub async fn upload_checkpoint(&self) -> Res {
        let cp = self.make_checkpoint();
        self.send(
            Method::PUT,
            "/api/sync/checkpoint",
            Some(&checkpoint_body(&cp)),
        )
        .await
    }

    /// "Accept older state", after the user has confirmed: list everything,
    /// verify the stored checkpoint on its own against the listing, replace the
    /// floors, and turn every local version that is newer than the listing into
    /// a draft on top of the listing's row (a conflict then shows up as usual
    /// if someone else has written since).
    pub async fn accept_older_state(&mut self) -> Result<(), Warning> {
        let mut report = SyncReport::default();
        let Some(listing) = self.list_all(&mut report).await else {
            return Err(report
                .warnings
                .pop()
                .unwrap_or(Warning::BadFeed("the listing failed")));
        };
        let mut verified = Vec::new();
        for change in &listing.items {
            verified.push(self.verify_row(change)?);
        }
        let checkpoint = self.fetch_checkpoint().await?;
        let rows: Vec<ServerRow> = verified.iter().map(|v| v.1).collect();
        self.memory
            .accept_older_state(&self.vault, &checkpoint, &rows, listing.as_of_seq)
            .map_err(Warning::from_core)?;

        let on_server: BTreeMap<[u8; 16], Seen> = verified
            .into_iter()
            .map(|(id, _, seen)| (*id.as_bytes(), seen))
            .collect();
        let keys: Vec<[u8; 16]> = self.locals.keys().copied().collect();
        for key in keys {
            let id = ItemId::from_bytes(key);
            let theirs = on_server.get(&key).cloned();
            let mut next = self.locals.get(&key).expect("a local").clone();
            let ahead = match (&next.seen, &theirs) {
                (Some(mine), Some(theirs)) => mine.rev > theirs.rev,
                (Some(_), None) => true,
                _ => false,
            };
            if ahead && next.draft.is_none() && key != *MANIFEST_ITEM_ID.as_bytes() {
                next.draft = match next.seen.as_ref() {
                    Some(seen) => match &seen.row {
                        RowKind::Live { .. } => self
                            .decode_body(id, seen)
                            .map(|body| Draft::Edit(Box::new(body))),
                        RowKind::Deleted { .. } => Some(Draft::Delete),
                    },
                    None => None,
                };
            }
            next.seen = theirs;
            next.inflight = None;
            next.conflict = false;
            next.resurrect = false;
            next.missing_on_server = false;
            self.locals.insert(key, next);
        }
        for (key, seen) in on_server {
            self.locals.entry(key).or_default().seen = Some(seen);
        }
        self.restore_epoch = Some(listing.restore_epoch);
        self.cursor = listing.as_of_seq;
        self.top_seq = listing.as_of_seq;
        Ok(())
    }

    fn decode_body(&self, id: ItemId, seen: &Seen) -> Option<ItemBody> {
        match &seen.row {
            RowKind::Live { blob, tag } => decrypt_item(&self.vault, id, seen.rev, blob, tag)
                .ok()
                .map(|item| item.body),
            RowKind::Deleted { .. } => None,
        }
    }

    // ------------------------------------------------------------------ http

    /// A request as a page of the vault makes it, with this device's cookies.
    pub fn request(&self, method: Method, uri: &str, body: Option<&Value>) -> Request<Body> {
        let mut req = Req::new(method, uri)
            .page_fetch(Which::Vault)
            .header("sec-fetch-site", "same-origin");
        if let Some(cookie) = self.jar.header() {
            req = req.header("cookie", &cookie);
        }
        if let Some(body) = body {
            req = req.json(body);
        }
        req.build()
    }

    /// Sends a request and reads the answer.
    pub async fn send(&self, method: Method, uri: &str, body: Option<&Value>) -> Res {
        self.app
            .call_raw(Which::Vault, self.request(method, uri, body))
            .await
    }

    /// A write of one item as it is, with this device's session.
    pub async fn put(&self, id: ItemId, body: &Value) -> Res {
        self.send(
            Method::PUT,
            &format!("/api/sync/items/{}", hex_of(id)),
            Some(body),
        )
        .await
    }

    /// A batch of operations as they are.
    pub async fn post_batch(&self, ops: &[Value]) -> Res {
        self.send(
            Method::POST,
            "/api/sync/batch",
            Some(&json!({ "ops": ops })),
        )
        .await
    }

    /// A checkpoint upload as it is.
    pub async fn put_checkpoint(&self, body: &Value) -> Res {
        self.send(Method::PUT, "/api/sync/checkpoint", Some(body))
            .await
    }

    /// The clock of this device in milliseconds: the server's, plus the skew.
    fn local_ms(&self) -> u64 {
        let server =
            i64::try_from(self.app.state.clock.now_unix().saturating_mul(1000)).unwrap_or(i64::MAX);
        u64::try_from(server.saturating_add(self.skew_ms).max(0)).unwrap_or(0)
    }
}

/// The JSON of a checkpoint upload.
pub fn checkpoint_body(cp: &Checkpoint) -> Value {
    json!({
        "seq": cp.seq,
        "digest": b64url::encode(&cp.digest),
        "mac": b64url::encode(&cp.mac),
        "entries": b64url::encode(&cp.entries),
    })
}

/// The body of a live write on top of `base_rev`, sealed with `vault`.
pub fn live_body(vault: &UnlockedVault, id: ItemId, base_rev: u64, name: &str, idem: u32) -> Value {
    let mut body = ItemBody::new(ItemType::Note, name, 1);
    body.notes = Some(format!("notes of {name}"));
    let sealed =
        encrypt_item(&mut OsRng, vault, id, base_rev + 1, &body, None).expect("a sealed item");
    json!({
        "base_rev": base_rev,
        "blob": b64url::encode(&sealed.envelope),
        "tag": b64url::encode(&sealed.tag),
        "idem": hex16::encode(&idem_of(idem)),
    })
}

/// The body of a deletion on top of `base_rev`, sealed with `vault`.
pub fn tomb_body(vault: &UnlockedVault, id: ItemId, base_rev: u64, idem: u32) -> Value {
    let tomb = make_tombstone(&mut OsRng, vault, id, base_rev + 1).expect("a tombstone");
    json!({
        "base_rev": base_rev,
        "deleted": true,
        "tomb": b64url::encode(&tomb.tomb),
        "idem": hex16::encode(&idem_of(idem)),
    })
}

/// The same body as an operation of a batch.
pub fn as_op(id: ItemId, body: &Value) -> Value {
    let mut op = body.clone();
    op["id"] = json!(hex_of(id));
    op
}

/// The `error` code of an answer.
pub fn error_code(res: &Res) -> String {
    error_of(res)
}

/// The answer of a batch, which must be `200` and a valid one.
pub fn batch_results(res: &Res) -> BatchRes {
    assert_eq!(res.status, StatusCode::OK, "{}", res.text());
    let batch: BatchRes = serde_json::from_slice(&res.body).expect("a batch answer");
    batch.validate().expect("a valid batch answer");
    batch
}
