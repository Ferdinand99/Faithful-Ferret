//! Test accounts straight into the database, with `create_account` of the vault
//! store: no registration, no OPAQUE exchange, just the rows.
//!
//! The ids of an account follow from a small number, so two accounts of a test
//! never share one, and a test can name an account by its number.

use std::sync::OnceLock;

use ferret_server::ids::{AccountId, DeviceId, MANIFEST_ITEM_ID, MethodId, VaultId};
use ferret_server::state::VaultDb;
use ferret_server::vault::store::{
    CheckpointIn, ManifestIn, MethodRow, NewAccountRows, create_account,
};
use ferret_server_auth::StoredRecord;
use ferret_server_auth::testing::LoginFixture;
use rusqlite::Connection;

use super::TestApp;

/// The ids of a test account and its kit user.
#[derive(Clone, Copy, Debug)]
pub struct TestAccount {
    /// The kit user.
    pub user_id: i64,
    /// The account.
    pub account_id: AccountId,
    /// Its vault.
    pub vault_id: VaultId,
    /// A device that writes to it.
    pub device: DeviceId,
}

/// A 16-byte id: a kind byte, the number of the account and zeros.
pub fn id16(kind: u8, n: u8) -> [u8; 16] {
    let mut bytes = [0u8; 16];
    bytes[0] = kind;
    bytes[1] = n;
    bytes
}

/// A valid OPAQUE record. Made once: registering is the slow part.
pub fn stored_record() -> StoredRecord {
    static RECORD: OnceLock<StoredRecord> = OnceLock::new();
    RECORD.get_or_init(|| LoginFixture::new().record).clone()
}

/// A kit user with this name; returns its id.
pub fn insert_user(conn: &Connection, name: &str) -> i64 {
    conn.execute(
        "INSERT INTO users (username, password_hash, role) VALUES (?1, 'x', 'editor')",
        [name],
    )
    .expect("a user");
    conn.last_insert_rowid()
}

/// The ids of test account `n` (the kit user comes from `user_id`).
pub fn account_ids(user_id: i64, n: u8) -> TestAccount {
    TestAccount {
        user_id,
        account_id: AccountId::from_bytes(id16(0xa0, n)),
        vault_id: VaultId::from_bytes(id16(0xb0, n)),
        device: DeviceId(id16(0xd0, n)),
    }
}

/// The rows of test account `n` for kit user `user_id`: a password wrap and a
/// recovery wrap, a manifest of 40 bytes at revision 1, a checkpoint at 1.
pub fn rows(user_id: i64, n: u8, now: i64) -> NewAccountRows {
    let ids = account_ids(user_id, n);
    NewAccountRows {
        account_id: ids.account_id,
        user_id,
        vault_id: ids.vault_id,
        record: stored_record(),
        sk_hint: true,
        pk_a: [0x11; 32],
        pk_r: [0x22; 32],
        methods: vec![
            MethodRow {
                method_id: MethodId::from_bytes(id16(0xc1, n)),
                method_type: 1,
                wrap: vec![0x31; 60],
                kek_generation: 1,
                credential_id: None,
                prf_salt: None,
                aaguid: None,
            },
            MethodRow {
                method_id: MethodId::from_bytes(id16(0xc2, n)),
                method_type: 2,
                wrap: vec![0x32; 60],
                kek_generation: 1,
                credential_id: None,
                prf_salt: None,
                aaguid: None,
            },
        ],
        manifest: ManifestIn {
            rev: 1,
            envelope: vec![0x4d; 40],
            tag: [0x7a; 32],
        },
        checkpoint: CheckpointIn {
            seq: 1,
            digest: vec![0x41; 32],
            mac: vec![0x42; 32],
            entries: vec![0x43; 20],
        },
        now,
    }
}

/// Inserts a user and test account `n` into `conn`, in one transaction.
pub fn add_account(conn: &mut Connection, n: u8, now: i64) -> TestAccount {
    let user_id = insert_user(conn, &format!("user{n}@example.com"));
    let tx = conn.transaction().expect("a transaction");
    create_account(&tx, &rows(user_id, n, now)).expect("create_account");
    tx.commit().expect("commit");
    account_ids(user_id, n)
}

/// Inserts a user and test account `n` into the database of a running
/// [`TestApp`], with the app's clock as `created_at`.
pub async fn add_account_to_app(app: &TestApp, n: u8) -> TestAccount {
    let db: VaultDb = app.state.vault_db.clone();
    let now = i64::try_from(app.state.clock.now_unix()).expect("a time");
    db.with_conn(move |conn| Ok(add_account(conn, n, now)))
        .await
        .expect("an account")
}

/// The id of the manifest row, for tests that read it back.
pub const MANIFEST: ferret_server::ids::ItemId = MANIFEST_ITEM_ID;
