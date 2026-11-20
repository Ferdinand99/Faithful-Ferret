//! The migrations and the tables they make.

#[path = "../build_support/registry.rs"]
mod registry;
mod support;

use std::path::Path;

use ferret_server::db::{CORE_MIGRATIONS, MIGRATION_FILES};
use ferret_server::ids::ItemId;
use ferret_server::product;
use ferret_server::vault::quota::Limits;
use ferret_server::vault::store::{PutBody, PutOutcome, PutRequest, put_item};
use rusqlite::{Connection, params};
use support::accounts::{TestAccount, add_account, id16};
use vole_kit::db::migrate::{
    CORE, MigrationError, MigrationSet, SIGN_IN_CODES, all_migration_names, apply_migrations,
    apply_migrations_with,
};

/// A database with every migration applied, foreign keys on as in the pool.
fn migrated() -> Connection {
    product::install();
    let mut conn = Connection::open_in_memory().expect("open");
    conn.execute_batch("PRAGMA foreign_keys = ON;")
        .expect("pragma");
    apply_migrations(&mut conn).expect("migrations apply");
    conn
}

fn ferret_applied(conn: &Connection) -> Vec<String> {
    let mut stmt = conn
        .prepare("SELECT name FROM schema_migrations WHERE name LIKE '0%' ORDER BY rowid")
        .expect("prepare");
    stmt.query_map([], |row| row.get::<_, String>(0))
        .expect("query")
        .map(|r| r.expect("row"))
        .collect()
}

#[test]
fn migrations_apply_in_name_order_and_twice_without_change() {
    product::install();
    let names: Vec<&str> = MIGRATION_FILES.iter().map(|(name, _)| *name).collect();
    assert_eq!(
        names,
        [
            "0001_vault.sql",
            "0002_auth.sql",
            "0003_sessions.sql",
            "0004_handoff_links.sql",
            "0005_sync.sql",
            "0006_restore_seq.sql",
            "0007_reauth.sql",
            "0008_devices.sql"
        ]
    );
    let mut sorted = names.clone();
    sorted.sort_unstable();
    assert_eq!(names, sorted);

    let mut conn = Connection::open_in_memory().expect("open");
    conn.execute_batch("PRAGMA foreign_keys = ON;")
        .expect("pragma");
    let first = apply_migrations(&mut conn).expect("first run");
    for name in &names {
        assert!(first.iter().any(|n| n == name), "{name} was not applied");
    }
    // Ours run in name order, after the kit's core set.
    let order = ferret_applied(&conn);
    assert_eq!(order, names);
    let kit_last = first
        .iter()
        .rposition(|n| n.starts_with("kit/"))
        .expect("the kit's core migrations ran");
    let ours_first = first
        .iter()
        .position(|n| n == "0001_vault.sql")
        .expect("our first migration ran");
    assert!(kit_last < ours_first);

    let snapshot = schema_of(&conn);
    assert_eq!(
        apply_migrations(&mut conn).expect("second run"),
        Vec::<String>::new()
    );
    assert_eq!(schema_of(&conn), snapshot);
    let mut all = all_migration_names();
    all.sort();
    let mut recorded: Vec<String> = conn
        .prepare("SELECT name FROM schema_migrations")
        .expect("prepare")
        .query_map([], |row| row.get::<_, String>(0))
        .expect("query")
        .map(|r| r.expect("row"))
        .collect();
    recorded.sort();
    assert_eq!(recorded, all);
}

fn schema_of(conn: &Connection) -> Vec<(String, String)> {
    conn.prepare("SELECT name, sql FROM sqlite_master WHERE sql IS NOT NULL ORDER BY name")
        .expect("prepare")
        .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))
        .expect("query")
        .map(|r| r.expect("row"))
        .collect()
}

#[test]
fn build_rs_registry_needs_no_code_change_for_a_new_file() {
    let dir = std::env::temp_dir().join(format!("ferret-registry-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("mkdir");
    let write = |name: &str| std::fs::write(dir.join(name), "SELECT 1;").expect("write");

    write("0002_second.sql");
    write("0001_first.sql");
    let before = registry::render(&dir).expect("render");
    let position = |text: &str, name: &str| text.find(name).unwrap_or_else(|| panic!("{name}"));
    assert!(position(&before, "0001_first.sql") < position(&before, "0002_second.sql"));
    assert!(!before.contains("0003_third.sql"));

    // A new migration is one new file and nothing else.
    write("0003_third.sql");
    let after = registry::render(&dir).expect("render");
    assert!(position(&after, "0002_second.sql") < position(&after, "0003_third.sql"));
    assert!(after.contains("include_str!"));

    // Mistakes stop the build instead of leaving a migration out.
    write("0003_other.sql");
    let clash = registry::render(&dir).unwrap_err();
    assert!(clash.contains("same number"), "{clash}");
    std::fs::remove_file(dir.join("0003_other.sql")).expect("rm");
    write("notes.txt");
    let stray = registry::render(&dir).unwrap_err();
    assert!(stray.contains("notes.txt"), "{stray}");
    std::fs::remove_file(dir.join("notes.txt")).expect("rm");
    write("3_short.sql");
    assert!(registry::render(&dir).is_err());
    let _ = std::fs::remove_dir_all(&dir);
    assert!(registry::render(Path::new("/definitely/not/here")).is_err());
}

const ID16: [u8; 16] = [7; 16];
const ID15: [u8; 15] = [7; 15];
const ID17: [u8; 17] = [7; 17];

fn insert_user(conn: &Connection) -> i64 {
    conn.execute(
        "INSERT INTO users (username, password_hash, role) VALUES ('a@example.com', 'x', 'admin')",
        [],
    )
    .expect("a user");
    conn.last_insert_rowid()
}

fn account_args(id: &[u8], vault: &[u8], pk: &[u8]) -> rusqlite::Result<usize> {
    let conn = migrated();
    let user = insert_user(&conn);
    insert_account(&conn, user, id, vault, &[1u8; 192], pk)
}

fn insert_account(
    conn: &Connection,
    user: i64,
    id: &[u8],
    vault: &[u8],
    record: &[u8],
    pk: &[u8],
) -> rusqlite::Result<usize> {
    conn.execute(
        "INSERT INTO ferret_accounts (account_id, user_id, vault_id, opaque_record, ksf_profile, sk_hint, pk_a, pk_r, created_at) \
         VALUES (?1, ?2, ?3, ?4, 1, 0, ?5, ?5, 0)",
        params![id, user, vault, record, pk],
    )
}

#[test]
fn schema_matches_section_7() {
    let conn = migrated();

    // Every table of ours is STRICT, and there are exactly the ones section 7
    // lists.
    let mut tables: Vec<(String, bool)> = conn
        .prepare("SELECT name, strict FROM pragma_table_list WHERE schema = 'main' AND name LIKE 'ferret\\_%' ESCAPE '\\' ORDER BY name")
        .expect("prepare")
        .query_map([], |row| Ok((row.get(0)?, row.get::<_, i64>(1)? == 1)))
        .expect("query")
        .map(|r| r.expect("row"))
        .collect();
    tables.sort();
    let names: Vec<&str> = tables.iter().map(|(n, _)| n.as_str()).collect();
    assert_eq!(
        names,
        [
            "ferret_access",
            "ferret_accounts",
            "ferret_checkpoints",
            "ferret_devices",
            "ferret_handoffs",
            "ferret_idem",
            "ferret_items",
            "ferret_login_states",
            "ferret_meta",
            "ferret_refresh",
            "ferret_registrations",
            "ferret_restore_rows",
            "ferret_sessions",
            "ferret_unlock_methods",
            "ferret_vaults",
        ]
    );
    for (name, strict) in &tables {
        assert!(strict, "{name} is not STRICT");
    }

    // Foreign keys are on for this connection, and a row that points nowhere
    // is refused.
    let on: i64 = conn
        .query_row("PRAGMA foreign_keys", [], |r| r.get(0))
        .expect("pragma");
    assert_eq!(on, 1);
    assert!(insert_account(&conn, 4242, &ID16, &[8; 16], &[1; 192], &[2; 32]).is_err());

    // Id columns refuse the wrong length.
    assert!(account_args(&ID16, &[8; 16], &[2; 32]).is_ok());
    assert!(
        account_args(&ID15, &[8; 16], &[2; 32]).is_err(),
        "account_id of 15 bytes"
    );
    assert!(
        account_args(&ID17, &[8; 16], &[2; 32]).is_err(),
        "account_id of 17 bytes"
    );
    assert!(
        account_args(&ID16, &[8; 15], &[2; 32]).is_err(),
        "vault_id of 15 bytes"
    );
    assert!(
        account_args(&ID16, &[8; 16], &[2; 31]).is_err(),
        "pk of 31 bytes"
    );
    let short_record = {
        let conn = migrated();
        let user = insert_user(&conn);
        insert_account(&conn, user, &ID16, &[8; 16], &[1u8; 191], &[2; 32])
    };
    assert!(short_record.is_err(), "record of 191 bytes");
}

/// A vault with an account, to put items in.
fn with_vault() -> Connection {
    let conn = migrated();
    let user = insert_user(&conn);
    insert_account(&conn, user, &ID16, &[8; 16], &[1u8; 192], &[2; 32]).expect("account");
    conn.execute(
        "INSERT INTO ferret_vaults (vault_id, account_id) VALUES (?1, ?2)",
        params![&[8u8; 16][..], &ID16[..]],
    )
    .expect("vault");
    conn
}

fn insert_item(
    conn: &Connection,
    item: &[u8],
    deleted: i64,
    blob: Option<&[u8]>,
    tag: Option<&[u8]>,
    tomb: Option<&[u8]>,
) -> rusqlite::Result<usize> {
    conn.execute(
        "INSERT INTO ferret_items (vault_id, item_id, rev, seq, deleted, blob, tag, tomb, size, changed_at) \
         VALUES (?1, ?2, 1, 1, ?3, ?4, ?5, ?6, 0, 0)",
        params![&[8u8; 16][..], item, deleted, blob, tag, tomb],
    )
}

#[test]
fn ferret_items_keeps_blob_tag_and_tombstone_apart() {
    let conn = with_vault();
    let blob = [1u8; 40];
    let tag = [2u8; 32];
    let tomb = [3u8; 40];
    // A live row has a blob and a 32-byte tag and no tombstone.
    assert!(insert_item(&conn, &[1; 16], 0, Some(&blob), Some(&tag), None).is_ok());
    assert!(
        insert_item(&conn, &[2; 16], 0, Some(&blob), None, None).is_err(),
        "live row without a tag"
    );
    assert!(
        insert_item(&conn, &[3; 16], 0, Some(&blob), Some(&tag[..31]), None).is_err(),
        "tag of 31 bytes"
    );
    assert!(
        insert_item(&conn, &[4; 16], 0, None, Some(&tag), None).is_err(),
        "live row without a blob"
    );
    assert!(
        insert_item(&conn, &[5; 16], 0, Some(&blob), Some(&tag), Some(&tomb)).is_err(),
        "live row with a tombstone"
    );
    // A tombstone has a tomb and neither blob nor tag.
    assert!(insert_item(&conn, &[6; 16], 1, None, None, Some(&tomb)).is_ok());
    assert!(
        insert_item(&conn, &[7; 16], 1, None, None, None).is_err(),
        "tombstone without tomb"
    );
    assert!(
        insert_item(&conn, &[8; 16], 1, Some(&blob), None, Some(&tomb)).is_err(),
        "blob on a tombstone"
    );
    assert!(
        insert_item(&conn, &[9; 16], 1, None, Some(&tag), Some(&tomb)).is_err(),
        "tag on a tombstone"
    );
    // Ids are 16 bytes.
    assert!(insert_item(&conn, &[1; 15], 0, Some(&blob), Some(&tag), None).is_err());
}

#[test]
fn sessions_and_handoffs_keep_their_rules() {
    let conn = migrated();
    let user = insert_user(&conn);
    let session = |hash: &[u8], origin: &str, scope: &str| {
        conn.execute(
            "INSERT INTO ferret_sessions (sid_hash, user_id, issued_at, origin, device_id, scope, last_seen) \
             VALUES (?1, ?2, 0, ?3, ?4, ?5, 0)",
            params![hash, user, origin, &[1u8; 16][..], scope],
        )
    };
    assert!(session(&[1; 32], "vault", "full").is_ok());
    assert!(session(&[2; 32], "admin", "pending_2fa").is_ok());
    assert!(
        session(&[3; 31], "vault", "full").is_err(),
        "hash of 31 bytes"
    );
    assert!(
        session(&[4; 32], "elsewhere", "full").is_err(),
        "unknown origin"
    );
    assert!(session(&[5; 32], "vault", "root").is_err(), "unknown scope");
    // The same hash twice is the same row: no INSERT OR IGNORE hides it.
    assert!(session(&[1; 32], "vault", "full").is_err());

    // The parent link of a handed-over session is empty or 32 bytes.
    let linked = |hash: &[u8], parent: Option<&[u8]>| {
        conn.execute(
            "INSERT INTO ferret_sessions (sid_hash, user_id, issued_at, origin, device_id, scope, last_seen, parent_sid)              VALUES (?1, ?2, 0, 'admin', ?3, 'full', 0, ?4)",
            params![hash, user, &[1u8; 16][..], parent],
        )
    };
    assert!(linked(&[6; 32], Some(&[1; 32][..])).is_ok());
    assert!(linked(&[7; 32], None).is_ok());
    assert!(
        linked(&[8; 32], Some(&[1; 31][..])).is_err(),
        "parent of 31 bytes"
    );

    let handoff = |code: &[u8], sid: &[u8], purpose: &str, next: &str, challenge: &[u8]| {
        conn.execute(
            "INSERT INTO ferret_handoffs (code_hash, sid_hash, user_id, purpose, next, challenge, expires_at) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, 60)",
            params![code, sid, user, purpose, next, challenge],
        )
    };
    assert!(handoff(&[1; 32], &[1; 32], "login", "/settings", &[9; 32]).is_ok());
    assert!(
        handoff(&[2; 32], &[9; 32], "login", "/settings", &[9; 32]).is_err(),
        "no such session"
    );
    assert!(
        handoff(&[3; 32], &[1; 32], "other", "/settings", &[9; 32]).is_err(),
        "unknown purpose"
    );
    assert!(
        handoff(&[4; 32], &[1; 32], "login", "", &[9; 32]).is_err(),
        "empty next"
    );
    assert!(
        handoff(&[5; 32], &[1; 32], "login", &"x".repeat(513), &[9; 32]).is_err(),
        "next over 512"
    );
    assert!(
        handoff(&[6; 32], &[1; 32], "login", "/a", &[9; 31]).is_err(),
        "challenge of 31 bytes"
    );
    // A session that goes takes its codes with it.
    conn.execute(
        "DELETE FROM ferret_sessions WHERE sid_hash = ?1",
        params![&[1u8; 32][..]],
    )
    .expect("delete");
    let left: i64 = conn
        .query_row("SELECT COUNT(*) FROM ferret_handoffs", [], |r| r.get(0))
        .expect("count");
    assert_eq!(left, 0);
}

#[test]
fn the_other_tables_check_their_ids_too() {
    let conn = with_vault();
    let reg = |id: &[u8], email: &str| {
        conn.execute(
            "INSERT INTO ferret_registrations (registration_id, account_id, vault_id, email, expires_at) VALUES (?1, ?2, ?3, ?4, 0)",
            params![id, &[1u8; 16][..], &[2u8; 16][..], email],
        )
    };
    assert!(reg(&[1; 16], "a@example.com").is_ok());
    assert!(reg(&[2; 15], "b@example.com").is_err());
    assert!(
        reg(&[3; 16], "a@example.com").is_err(),
        "one registration per e-mail"
    );

    let idem = |device: &[u8], key: &[u8], hash: &[u8]| {
        conn.execute(
            "INSERT INTO ferret_idem (vault_id, device_id, idem, request_hash, rev, seq, created_at) VALUES (?1, ?2, ?3, ?4, 1, 1, 0)",
            params![&[8u8; 16][..], device, key, hash],
        )
    };
    assert!(idem(&[1; 16], &[1; 16], &[1; 32]).is_ok());
    assert!(idem(&[1; 15], &[2; 16], &[1; 32]).is_err());
    assert!(idem(&[1; 16], &[2; 15], &[1; 32]).is_err());
    assert!(idem(&[1; 16], &[3; 16], &[1; 31]).is_err());
    assert!(
        idem(&[1; 16], &[1; 16], &[1; 32]).is_err(),
        "the same idem twice"
    );

    let method = |id: &[u8], kind: i64, generation: i64| {
        conn.execute(
            "INSERT INTO ferret_unlock_methods (method_id, account_id, method_type, wrap, kek_generation, created_at) VALUES (?1, ?2, ?3, x'00', ?4, 0)",
            params![id, &ID16[..], kind, generation],
        )
    };
    assert!(method(&[1; 16], 1, 1).is_ok());
    assert!(method(&[2; 16], 4, 1).is_err(), "unknown method type");
    assert!(method(&[3; 16], 1, 0).is_err(), "generation 0");
    assert!(
        method(&[4; 16], 1, 4_294_967_296).is_err(),
        "generation over 2^32 - 1"
    );
    assert!(method(&[5; 15], 1, 1).is_err());

    // The vault row and the checkpoint have 16-byte ids as well.
    assert!(conn
        .execute(
            "INSERT INTO ferret_checkpoints (vault_id, seq, digest, mac, entries) VALUES (?1, 1, x'00', x'00', x'00')",
            params![&[8u8; 15][..]],
        )
        .is_err());
}

fn insert_named_user(conn: &Connection, name: &str, role: &str) -> i64 {
    conn.execute(
        "INSERT INTO users (username, password_hash, role) VALUES (?1, 'x', ?2)",
        params![name, role],
    )
    .expect("a user");
    conn.last_insert_rowid()
}

/// Gives `user` an account and a vault, and one row of everything that belongs
/// to them. `n` tells the ids of one user's rows from another's.
fn fill_vault(conn: &Connection, user: i64, n: u8) {
    let account = [n; 16];
    let vault = [n.wrapping_add(100); 16];
    insert_account(conn, user, &account, &vault, &[1u8; 192], &[2; 32]).expect("account");
    let run = |sql: &str, args: &[&dyn rusqlite::ToSql]| {
        conn.execute(sql, args)
            .unwrap_or_else(|e| panic!("{sql}: {e}"));
    };
    run(
        "INSERT INTO ferret_vaults (vault_id, account_id) VALUES (?1, ?2)",
        params![&vault[..], &account[..]],
    );
    run(
        "INSERT INTO ferret_unlock_methods (method_id, account_id, method_type, wrap, kek_generation, created_at) VALUES (?1, ?2, 1, x'00', 1, 0)",
        params![&[n; 16][..], &account[..]],
    );
    let (blob, tag, tomb) = ([1u8; 40], [2u8; 32], [3u8; 40]);
    run(
        "INSERT INTO ferret_items (vault_id, item_id, rev, seq, deleted, blob, tag, size, changed_at) VALUES (?1, ?2, 1, 1, 0, ?3, ?4, 0, 0)",
        params![&vault[..], &[1u8; 16][..], &blob[..], &tag[..]],
    );
    run(
        "INSERT INTO ferret_items (vault_id, item_id, rev, seq, deleted, tomb, size, changed_at) VALUES (?1, ?2, 2, 2, 1, ?3, 0, 0)",
        params![&vault[..], &[2u8; 16][..], &tomb[..]],
    );
    run(
        "INSERT INTO ferret_checkpoints (vault_id, seq, digest, mac, entries) VALUES (?1, 2, x'00', x'00', x'00')",
        params![&vault[..]],
    );
    run(
        "INSERT INTO ferret_idem (vault_id, device_id, idem, request_hash, rev, seq, created_at) VALUES (?1, ?2, ?3, ?4, 1, 1, 0)",
        params![&vault[..], &[9u8; 16][..], &[9u8; 16][..], &[9u8; 32][..]],
    );
    run(
        "INSERT INTO ferret_sessions (sid_hash, user_id, issued_at, origin, device_id, scope, last_seen) VALUES (?1, ?2, 0, 'vault', ?3, 'full', 0)",
        params![&[n; 32][..], user, &[1u8; 16][..]],
    );
    run(
        "INSERT INTO ferret_handoffs (code_hash, sid_hash, user_id, purpose, next, challenge, expires_at) VALUES (?1, ?2, ?3, 'login', '/settings', ?4, 60)",
        params![&[n; 32][..], &[n; 32][..], user, &[5u8; 32][..]],
    );
}

fn count(conn: &Connection, table: &str, column: &str, value: &[u8]) -> i64 {
    conn.query_row(
        &format!("SELECT COUNT(*) FROM {table} WHERE {column} = ?1"),
        params![value],
        |r| r.get(0),
    )
    .expect("count")
}

fn count_user(conn: &Connection, table: &str, user: i64) -> i64 {
    conn.query_row(
        &format!("SELECT COUNT(*) FROM {table} WHERE user_id = ?1"),
        params![user],
        |r| r.get(0),
    )
    .expect("count")
}

#[test]
fn deleting_a_user_removes_the_vault_and_everything_in_it() {
    let mut conn = migrated();
    let admin = insert_named_user(&conn, "admin@example.com", "admin");
    let member = insert_named_user(&conn, "member@example.com", "editor");
    fill_vault(&conn, admin, 1);
    fill_vault(&conn, member, 2);
    let (account, vault) = ([2u8; 16], [102u8; 16]);
    let owned = [
        ("ferret_accounts", "account_id", &account[..]),
        ("ferret_unlock_methods", "account_id", &account[..]),
        ("ferret_vaults", "vault_id", &vault[..]),
        ("ferret_items", "vault_id", &vault[..]),
        ("ferret_checkpoints", "vault_id", &vault[..]),
        ("ferret_idem", "vault_id", &vault[..]),
    ];
    // Everything is there before.
    for (table, column, value) in owned {
        assert!(count(&conn, table, column, value) >= 1, "{table}");
    }
    assert_eq!(count(&conn, "ferret_items", "vault_id", &vault), 2);

    // The kit's way to delete a user (the Users page calls it).
    let result = vole_kit::db::users::delete_user(&mut conn, member).expect("delete");
    assert!(result.is_ok(), "the user could not be deleted");

    for (table, column, value) in owned {
        assert_eq!(count(&conn, table, column, value), 0, "{table} keeps rows");
    }
    for table in ["ferret_sessions", "ferret_handoffs"] {
        assert_eq!(count_user(&conn, table, member), 0, "{table} keeps rows");
    }
    // Nothing of the other user went.
    let (account, vault) = ([1u8; 16], [101u8; 16]);
    assert_eq!(count(&conn, "ferret_accounts", "account_id", &account), 1);
    assert_eq!(
        count(&conn, "ferret_unlock_methods", "account_id", &account),
        1
    );
    assert_eq!(count(&conn, "ferret_vaults", "vault_id", &vault), 1);
    assert_eq!(count(&conn, "ferret_items", "vault_id", &vault), 2);
    assert_eq!(count(&conn, "ferret_checkpoints", "vault_id", &vault), 1);
    assert_eq!(count(&conn, "ferret_idem", "vault_id", &vault), 1);
    assert_eq!(count_user(&conn, "ferret_sessions", admin), 1);
    assert_eq!(count_user(&conn, "ferret_handoffs", admin), 1);
}

#[test]
fn rows_of_a_vault_that_does_not_exist_are_refused() {
    let conn = migrated();
    let ghost = [77u8; 16];
    assert!(
        conn.execute(
            "INSERT INTO ferret_items (vault_id, item_id, rev, seq, deleted, tomb, size, changed_at) VALUES (?1, ?2, 1, 1, 1, x'00', 0, 0)",
            params![&ghost[..], &[1u8; 16][..]],
        )
        .is_err()
    );
    assert!(
        conn.execute(
            "INSERT INTO ferret_checkpoints (vault_id, seq, digest, mac, entries) VALUES (?1, 1, x'00', x'00', x'00')",
            params![&ghost[..]],
        )
        .is_err()
    );
    assert!(
        conn.execute(
            "INSERT INTO ferret_idem (vault_id, device_id, idem, request_hash, rev, seq, created_at) VALUES (?1, ?2, ?2, ?3, 1, 1, 0)",
            params![&ghost[..], &[1u8; 16][..], &[1u8; 32][..]],
        )
        .is_err()
    );
}

#[test]
fn an_account_has_one_user_and_one_vault_and_the_hint_is_a_flag() {
    let conn = migrated();
    let user = insert_user(&conn);
    let other = insert_named_user(&conn, "other@example.com", "viewer");
    insert_account(&conn, user, &[1; 16], &[11; 16], &[1u8; 192], &[2; 32]).expect("account");
    assert!(
        insert_account(&conn, user, &[2; 16], &[12; 16], &[1u8; 192], &[2; 32]).is_err(),
        "a second account for one user"
    );
    assert!(
        insert_account(&conn, other, &[3; 16], &[11; 16], &[1u8; 192], &[2; 32]).is_err(),
        "a second account for one vault id"
    );
    let hint = |value: i64, account: &[u8; 16], vault: &[u8; 16]| {
        conn.execute(
            "INSERT INTO ferret_accounts (account_id, user_id, vault_id, opaque_record, ksf_profile, sk_hint, pk_a, pk_r, created_at) \
             VALUES (?1, ?2, ?3, ?4, 1, ?5, ?6, ?6, 0)",
            params![&account[..], other, &vault[..], &[1u8; 192][..], value, &[2u8; 32][..]],
        )
    };
    assert!(hint(2, &[4; 16], &[14; 16]).is_err(), "sk_hint 2");
    assert!(hint(1, &[4; 16], &[14; 16]).is_ok());
}

// ---------------------------------------------------------------- the schema with re-authentication and sign-in codes

const NOW: i64 = 1_793_491_200;

fn files_up_to(last: &str) -> Vec<(String, String)> {
    MIGRATION_FILES
        .iter()
        .filter(|(name, _)| *name <= last)
        .map(|(name, sql)| ((*name).to_string(), (*sql).to_string()))
        .collect()
}

fn up_to_0006() -> Vec<(String, String)> {
    files_up_to("0006_restore_seq.sql")
}

fn up_to_0007() -> Vec<(String, String)> {
    files_up_to("0007_reauth.sql")
}

fn no_fixups(_: &mut Connection) -> Result<(), MigrationError> {
    Ok(())
}

/// What the previous release ran: the kit's core set as it was, and our
/// migrations up to 0006.
static BUILD_AT_0006: MigrationSet = MigrationSet {
    core: CORE,
    adopt_core: None,
    migrations: up_to_0006,
    fk_off_marker: "-- ff:foreign_keys=off",
    baseline: None,
    after: no_fixups,
};

/// A build with 0007 and without the kit's tables of sign-in codes.
static BUILD_AT_0007: MigrationSet = MigrationSet {
    core: CORE,
    adopt_core: None,
    migrations: up_to_0007,
    fk_off_marker: "-- ff:foreign_keys=off",
    baseline: None,
    after: no_fixups,
};

/// What the third milestone ran: the kit's core set with the sign-in codes, and
/// our migrations up to 0007. `tests/fixtures/schema/m3.sql` is its schema.
static BUILD_AT_M3: MigrationSet = MigrationSet {
    core: &CORE_MIGRATIONS,
    adopt_core: None,
    migrations: up_to_0007,
    fk_off_marker: "-- ff:foreign_keys=off",
    baseline: None,
    after: no_fixups,
};

fn empty_database() -> Connection {
    product::install();
    let conn = Connection::open_in_memory().expect("open");
    conn.execute_batch("PRAGMA foreign_keys = ON;")
        .expect("pragma");
    conn
}

fn put_live(conn: &mut Connection, a: &TestAccount, n: u8, base_rev: u8) {
    let blob = format!("envelope of item {n} at revision {}", base_rev + 1).into_bytes();
    let mut item = [0u8; 16];
    item[0] = 0x10;
    item[1] = n;
    let req = PutRequest {
        item_id: ItemId::from_bytes(item),
        base_rev: u64::from(base_rev),
        body: PutBody::Live {
            blob: &blob,
            tag: [n; 32],
        },
        idem: id16(0xe0, n.wrapping_mul(16).wrapping_add(base_rev)),
        request_hash: [n; 32],
        resurrect: false,
        restore_epoch: None,
    };
    let outcome =
        put_item(conn, &a.vault_id, &a.device, &req, &Limits::DEFAULT, NOW).expect("put_item");
    assert!(matches!(outcome, PutOutcome::Stored { .. }), "{outcome:?}");
}

/// A database as the previous release left it: its migrations only, two
/// accounts with items, and sessions of every scope, one of them ended.
fn database_at_0006() -> Connection {
    let mut conn = empty_database();
    apply_migrations_with(&mut conn, &BUILD_AT_0006).expect("the old migrations");
    let a = add_account(&mut conn, 1, NOW);
    let b = add_account(&mut conn, 2, NOW);
    put_live(&mut conn, &a, 1, 0);
    put_live(&mut conn, &a, 2, 0);
    put_live(&mut conn, &a, 2, 1);
    put_live(&mut conn, &b, 1, 0);
    for (n, user, scope, revoked) in [
        (1u8, a.user_id, "full", None),
        (2, a.user_id, "account_reset", None),
        (3, b.user_id, "full", Some(NOW + 5)),
        (4, b.user_id, "pending_2fa", None),
    ] {
        conn.execute(
            "INSERT INTO ferret_sessions \
             (sid_hash, user_id, issued_at, origin, device_id, device_name, scope, last_seen, \
              revoked_at) \
             VALUES (?1, ?2, ?3, 'vault', ?4, 'a browser', ?5, ?6, ?7)",
            params![
                [n; 32].as_slice(),
                user,
                NOW,
                id16(0xd0, n).as_slice(),
                scope,
                NOW + 1,
                revoked
            ],
        )
        .expect("a session");
    }
    conn
}

/// Every row of the named tables, as text, in a fixed order.
fn dump_rows(conn: &Connection, tables: &[String]) -> Vec<String> {
    let mut out = Vec::new();
    for table in tables {
        let mut stmt = conn
            .prepare(&format!("SELECT * FROM \"{table}\" ORDER BY 1, 2"))
            .expect("prepare");
        let columns = stmt.column_count();
        let rows: Vec<String> = stmt
            .query_map([], |row| {
                let mut cells = Vec::new();
                for i in 0..columns {
                    cells.push(format!("{:?}", row.get_ref(i)?));
                }
                Ok(cells.join("|"))
            })
            .expect("query")
            .map(|r| r.expect("row"))
            .collect();
        out.push(format!("{table}: {}", rows.join("\n")));
    }
    out
}

/// The tables of a database, not the bookkeeping of the migrations.
fn tables(conn: &Connection) -> Vec<String> {
    conn.prepare(
        "SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%' \
         AND name <> 'schema_migrations' ORDER BY name",
    )
    .expect("prepare")
    .query_map([], |row| row.get(0))
    .expect("query")
    .map(|r| r.expect("row"))
    .collect()
}

fn recorded(conn: &Connection) -> Vec<String> {
    conn.prepare("SELECT name FROM schema_migrations ORDER BY rowid")
        .expect("prepare")
        .query_map([], |row| row.get(0))
        .expect("query")
        .map(|r| r.expect("row"))
        .collect()
}

/// The statements of a migration file, comments left out, spaces collapsed.
fn statements(file: &str) -> Vec<String> {
    let sql = MIGRATION_FILES
        .iter()
        .find(|(name, _)| *name == file)
        .map(|(_, sql)| *sql)
        .expect("the migration");
    sql.lines()
        .filter(|line| !line.trim_start().starts_with("--"))
        .collect::<Vec<_>>()
        .join("\n")
        .split(';')
        .map(|s| s.split_whitespace().collect::<Vec<_>>().join(" "))
        .filter(|s| !s.is_empty())
        .collect()
}

/// The rows of the tables that were there before, compared before and after
/// a migration. `ferret_sessions` is only compared by its row count: it has a
/// new column.
fn assert_rows_kept(before: &[String], after: &[String]) {
    assert_eq!(before.len(), after.len());
    for (was, now) in before.iter().zip(after) {
        if was.starts_with("ferret_sessions: ") {
            assert_eq!(was.lines().count(), now.lines().count());
        } else {
            assert_eq!(was, now);
        }
    }
}

#[test]
fn migration_0007_adds_reauth_at_and_keeps_every_m2_row() {
    let names: Vec<&str> = MIGRATION_FILES.iter().map(|(name, _)| *name).collect();
    let at = |name: &str| names.iter().position(|n| *n == name).expect(name);
    assert_eq!(at("0007_reauth.sql"), at("0006_restore_seq.sql") + 1);

    // Additive: one column, nullable, checked, nothing else.
    assert_eq!(
        statements("0007_reauth.sql"),
        ["ALTER TABLE ferret_sessions ADD COLUMN reauth_at INTEGER \
             CHECK(reauth_at IS NULL OR reauth_at >= 0)"]
    );

    let mut conn = database_at_0006();
    let has_reauth_at = |conn: &Connection| -> bool {
        conn.query_row(
            "SELECT COUNT(*) FROM pragma_table_info('ferret_sessions') WHERE name = 'reauth_at'",
            [],
            |row| row.get::<_, i64>(0),
        )
        .expect("columns")
            == 1
    };
    assert!(!has_reauth_at(&conn));
    let kept_tables = tables(&conn);
    let before = dump_rows(&conn, &kept_tables);
    let rows_of = |table: &str| -> usize {
        before
            .iter()
            .find(|t| t.starts_with(&format!("{table}: ")))
            .map_or(0, |t| t.lines().count())
    };
    assert_eq!(
        rows_of("ferret_sessions"),
        4,
        "the sessions are in the dump"
    );
    assert!(rows_of("ferret_items") >= 4, "the items are in the dump");

    let applied = apply_migrations(&mut conn).expect("0007 applies over data");
    assert!(
        applied.iter().any(|n| n == "0007_reauth.sql"),
        "{applied:?}"
    );

    // Every row of every table that was there is as it was, the sessions with
    // one more column that is empty.
    assert!(has_reauth_at(&conn));
    assert_rows_kept(&before, &dump_rows(&conn, &kept_tables));
    let (count, empty): (i64, i64) = conn
        .query_row(
            "SELECT COUNT(*), COUNT(*) FILTER (WHERE reauth_at IS NULL) FROM ferret_sessions",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .expect("count");
    assert_eq!((count, empty), (4, 4), "no session has a re-authentication");
    let ended: Option<i64> = conn
        .query_row(
            "SELECT revoked_at FROM ferret_sessions WHERE sid_hash = ?1",
            [[3u8; 32].as_slice()],
            |row| row.get(0),
        )
        .expect("the ended session");
    assert_eq!(ended, Some(NOW + 5), "the ended session is still ended");

    // The column takes a time and refuses a negative one.
    conn.execute(
        "UPDATE ferret_sessions SET reauth_at = ?1 WHERE sid_hash = ?2",
        params![NOW, [1u8; 32].as_slice()],
    )
    .expect("a time");
    assert!(
        conn.execute(
            "UPDATE ferret_sessions SET reauth_at = -1 WHERE sid_hash = ?1",
            [[1u8; 32].as_slice()],
        )
        .is_err(),
        "a time is not negative"
    );
}

#[test]
fn kit_sign_in_codes_migration_runs_after_0006_and_0007_and_keeps_every_row() {
    product::install();
    // The kit's migration is part of the core set of this build, and the last
    // of it, after everything the kit's own core set holds.
    assert_eq!(
        CORE_MIGRATIONS.last().map(|(name, _)| *name),
        Some(SIGN_IN_CODES.0)
    );
    assert_eq!(
        &CORE_MIGRATIONS[..CORE.len()],
        CORE,
        "all of the kit's core set is there"
    );
    let fresh = {
        let mut conn = empty_database();
        apply_migrations_with(&mut conn, &BUILD_AT_M3).expect("a fresh database");
        conn
    };
    let fresh_schema = dump_schema(&fresh);
    assert!(fresh_schema.contains("CREATE TABLE sign_in_codes"));
    assert!(fresh_schema.contains("CREATE TABLE user_emails"));

    // A database as the previous release left it gets the kit's tables and
    // 0007, and keeps every row.
    let mut direct = database_at_0006();
    let kept_tables = tables(&direct);
    let before = dump_rows(&direct, &kept_tables);
    let applied = apply_migrations_with(&mut direct, &BUILD_AT_M3).expect("the new migrations");
    assert!(applied.iter().any(|n| n == SIGN_IN_CODES.0), "{applied:?}");
    assert!(
        applied.iter().any(|n| n == "0007_reauth.sql"),
        "{applied:?}"
    );
    assert_eq!(applied.len(), 2, "{applied:?}");
    let order = recorded(&direct);
    let position = |name: &str| order.iter().position(|n| n == name).expect(name);
    assert!(position("0006_restore_seq.sql") < position(SIGN_IN_CODES.0));
    // The kit runs a pending core migration before a pending migration of ours;
    // neither touches a table of the other.
    assert!(position(SIGN_IN_CODES.0) < position("0007_reauth.sql"));
    assert_rows_kept(&before, &dump_rows(&direct, &kept_tables));
    assert_eq!(
        dump_schema(&direct),
        fresh_schema,
        "the same schema as a fresh database"
    );

    // A database that already has 0007 and then gets the codes (a build between
    // the two) ends up the same, with its rows.
    let mut stepped = database_at_0006();
    apply_migrations_with(&mut stepped, &BUILD_AT_0007).expect("0007 first");
    assert!(!tables(&stepped).iter().any(|t| t == "sign_in_codes"));
    let kept_tables = tables(&stepped);
    let before = dump_rows(&stepped, &kept_tables);
    let applied = apply_migrations_with(&mut stepped, &BUILD_AT_M3).expect("then the codes");
    assert_eq!(applied, [SIGN_IN_CODES.0], "only the codes were missing");
    let order = recorded(&stepped);
    let position = |name: &str| order.iter().position(|n| n == name).expect(name);
    assert!(position("0007_reauth.sql") < position(SIGN_IN_CODES.0));
    assert_eq!(before, dump_rows(&stepped, &kept_tables), "every row kept");
    assert_eq!(dump_schema(&stepped), fresh_schema);

    // The tables are usable: a code belongs to a user.
    let user: i64 = stepped
        .query_row("SELECT id FROM users ORDER BY id LIMIT 1", [], |r| r.get(0))
        .expect("a user");
    stepped
        .execute(
            "INSERT INTO sign_in_codes (user_id, code_hash, created_by, expires_at) \
             VALUES (?1, x'0102', ?1, datetime('now', '+24 hours'))",
            [user],
        )
        .expect("a code");
}

/// The comment at the top of the frozen schema.
const GOLDEN_HEADER: &str = "\
-- The schema of the database after every migration of this build: Faithful
-- Ferret's own and the ones that vole-kit runs, as SQLite stores them
-- (`sqlite_master`, in name order). A migration changes this file in the same
-- change; a test compares it with a database that the migrations made. To write
-- it again after a migration was added, run the schema tests with
-- FERRET_UPDATE_GOLDEN=1.
";

/// The tables, indexes, views and triggers of a database, in name order, as
/// SQLite stores them.
fn dump_schema(conn: &Connection) -> String {
    let rows: Vec<(String, String, String)> = conn
        .prepare(
            "SELECT type, name, sql FROM sqlite_master \
             WHERE sql IS NOT NULL AND name NOT LIKE 'sqlite_%' ORDER BY name, type",
        )
        .expect("prepare")
        .query_map([], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))
        .expect("query")
        .map(|r| r.expect("row"))
        .collect();
    rows.iter()
        .map(|(kind, name, sql)| format!("-- {kind} {name}\n{};\n", sql.replace('\r', "")))
        .collect::<Vec<_>>()
        .join("\n")
}

#[test]
fn the_m3_schema_still_matches_m3_sql() {
    let mut conn = empty_database();
    apply_migrations_with(&mut conn, &BUILD_AT_M3).expect("migrations apply");
    let actual = format!("{GOLDEN_HEADER}\n{}", dump_schema(&conn));
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/schema/m3.sql");
    if std::env::var("FERRET_UPDATE_GOLDEN").is_ok_and(|v| v == "1") {
        std::fs::create_dir_all(path.parent().expect("a folder")).expect("mkdir");
        std::fs::write(&path, &actual).expect("write the frozen schema");
        return;
    }
    let frozen = std::fs::read_to_string(&path)
        .expect("tests/fixtures/schema/m3.sql")
        .replace('\r', "");
    let first_difference = frozen
        .lines()
        .zip(actual.lines())
        .position(|(a, b)| a != b)
        .unwrap_or_else(|| frozen.lines().count().min(actual.lines().count()))
        + 1;
    assert!(
        frozen == actual,
        "the schema is not the frozen one. A change of the schema needs a migration and a new \
         frozen file (FERRET_UPDATE_GOLDEN=1); the first difference is at line {first_difference}"
    );
    // Ferret's tables and the kit's are both in it, and the new column.
    for needle in [
        "CREATE TABLE ferret_sessions",
        "reauth_at INTEGER CHECK(reauth_at IS NULL OR reauth_at >= 0)",
        "CREATE TABLE ferret_vaults",
        "CREATE TABLE ferret_restore_rows",
        "CREATE TABLE \"users\"",
        "CREATE TABLE sign_in_codes",
        "CREATE TABLE user_emails",
        "CREATE TABLE passkeys",
    ] {
        assert!(frozen.contains(needle), "{needle}");
    }
}

#[test]
fn an_older_build_refuses_a_database_with_a_newer_migration() {
    // A database made by this build: 0007 and the kit's tables of codes are in
    // it.
    let mut conn = empty_database();
    apply_migrations(&mut conn).expect("migrations apply");
    let before = dump_schema(&conn);
    let recorded_before = recorded(&conn);

    // The previous release (up to 0006, without the codes) says no.
    let refused = apply_migrations_with(&mut conn, &BUILD_AT_0006).expect_err("a newer schema");
    assert!(
        matches!(refused, MigrationError::NewerSchema { .. }),
        "{refused}"
    );
    // A release in between (with 0007, without the codes) says no too: the
    // kit's migration is unknown to it.
    let refused = apply_migrations_with(&mut conn, &BUILD_AT_0007).expect_err("a newer schema");
    assert!(
        matches!(refused, MigrationError::NewerSchema { .. }),
        "{refused}"
    );
    assert_eq!(dump_schema(&conn), before, "nothing was changed");
    assert_eq!(recorded(&conn), recorded_before, "nothing was recorded");

    // This build goes on, and an old build goes on with a database that only
    // has what it knows (a control: the refusal is about the newer migration
    // and nothing else).
    assert!(
        apply_migrations(&mut conn)
            .expect("the same build")
            .is_empty()
    );
    let mut old = database_at_0006();
    assert!(
        apply_migrations_with(&mut old, &BUILD_AT_0006)
            .expect("the old build")
            .is_empty()
    );
}

// ---------------------------------------------------------------- devices and their tokens

/// The three tables of migration 0008.
const DEVICE_TABLES: [&str; 3] = ["ferret_access", "ferret_devices", "ferret_refresh"];

/// The five indexes of migration 0008.
const DEVICE_INDEXES: [&str; 5] = [
    "ferret_access_device",
    "ferret_devices_user",
    "ferret_refresh_device",
    "ferret_refresh_prev",
    "ferret_refresh_used",
];

/// Adds a device row; the arguments that the checks look at are given.
fn insert_device(
    conn: &Connection,
    device: &[u8],
    user: i64,
    jkt: &[u8],
    name: &str,
    platform: &str,
) -> rusqlite::Result<usize> {
    conn.execute(
        "INSERT INTO ferret_devices \
         (device_id, user_id, jkt, name, platform, session_version, created_at, last_seen) \
         VALUES (?1, ?2, ?3, ?4, ?5, 1, ?6, ?6)",
        params![device, user, jkt, name, platform, NOW],
    )
}

/// Adds a refresh row of `device`.
fn insert_refresh(
    conn: &Connection,
    hash: &[u8],
    device: &[u8],
    prev: Option<&[u8]>,
) -> rusqlite::Result<usize> {
    conn.execute(
        "INSERT INTO ferret_refresh \
         (token_hash, device_id, prev_hash, issued_at, idle_expires_at, abs_expires_at) \
         VALUES (?1, ?2, ?3, ?4, ?4, ?4)",
        params![hash, device, prev, NOW],
    )
}

/// Adds an access row of `device`.
fn insert_access(conn: &Connection, hash: &[u8], device: &[u8]) -> rusqlite::Result<usize> {
    conn.execute(
        "INSERT INTO ferret_access (token_hash, device_id, expires_at) VALUES (?1, ?2, ?3)",
        params![hash, device, NOW],
    )
}

#[test]
fn migration_adds_three_strict_tables_with_length_checks() {
    let conn = migrated();
    let strict: Vec<(String, i64)> = conn
        .prepare(
            "SELECT name, strict FROM pragma_table_list \
             WHERE schema = 'main' AND name IN ('ferret_access', 'ferret_devices', 'ferret_refresh') \
             ORDER BY name",
        )
        .expect("prepare")
        .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))
        .expect("query")
        .map(|r| r.expect("row"))
        .collect();
    assert_eq!(
        strict,
        DEVICE_TABLES.map(|t| (t.to_string(), 1)).to_vec(),
        "the three tables are there and STRICT"
    );
    let user = insert_user(&conn);
    let jkt = |n: u8| [n; 32];

    // A device: 16-byte id, 32-byte thumbprint, a known platform, a name of
    // 1 to 64 characters.
    assert!(
        insert_device(
            &conn,
            &[1; 16],
            user,
            &jkt(1),
            "Ferret for Firefox",
            "windows"
        )
        .is_ok()
    );
    assert!(
        insert_device(&conn, &[2; 15], user, &jkt(2), "a", "linux").is_err(),
        "a 15-byte id"
    );
    assert!(
        insert_device(&conn, &[3; 16], user, &[3; 31], "a", "linux").is_err(),
        "a 31-byte jkt"
    );
    assert!(
        insert_device(&conn, &[4; 16], user, &jkt(4), "a", "freebsd").is_err(),
        "an unknown platform"
    );
    assert!(
        insert_device(&conn, &[5; 16], user, &jkt(5), "a", "Windows").is_err(),
        "a platform is lower case"
    );
    assert!(
        insert_device(&conn, &[6; 16], user, &jkt(6), "", "linux").is_err(),
        "an empty name"
    );
    // Characters, not bytes: 64 four-byte characters (256 bytes) are a name,
    // 65 are not.
    let clef = "\u{1d11e}";
    assert_eq!(clef.len(), 4);
    assert!(insert_device(&conn, &[7; 16], user, &jkt(7), &clef.repeat(64), "macos").is_ok());
    assert!(
        insert_device(&conn, &[8; 16], user, &jkt(8), &clef.repeat(65), "macos").is_err(),
        "65 characters"
    );
    assert!(insert_device(&conn, &[9; 16], user, &jkt(9), &"a".repeat(64), "other").is_ok());
    assert!(
        insert_device(&conn, &[10; 16], user, &jkt(10), &"a".repeat(65), "other").is_err(),
        "65 characters"
    );
    // Every platform of the wire is one the table takes.
    for (n, platform) in (40u8..).zip(ferret_server::wire::PLATFORMS) {
        assert!(
            insert_device(&conn, &[n; 16], user, &jkt(n), "a", platform).is_ok(),
            "{platform}"
        );
    }
    // No NUL: SQLite's `length()` stops at the first one, so it would hide the
    // rest of a long name.
    assert!(
        insert_device(
            &conn,
            &[13; 16],
            user,
            &jkt(13),
            &format!("a {}", "b".repeat(1000)),
            "linux"
        )
        .is_err(),
        "a NUL before 1000 more characters"
    );
    assert!(
        insert_device(&conn, &[14; 16], user, &jkt(14), "a b", "linux").is_err(),
        "a NUL in a short name"
    );
    assert!(
        insert_device(&conn, &[15; 16], user, &jkt(15), " ", "linux").is_err(),
        "a NUL alone"
    );
    // A key names one device only, and a device belongs to a user.
    assert!(
        insert_device(&conn, &[11; 16], user, &jkt(1), "again", "linux").is_err(),
        "the same jkt twice"
    );
    assert!(
        insert_device(&conn, &[12; 16], 4242, &jkt(12), "a", "linux").is_err(),
        "no such user"
    );
    // Times are not negative.
    for column in ["revoked_at", "last_seen", "created_at"] {
        assert!(
            conn.execute(
                &format!("UPDATE ferret_devices SET {column} = -1 WHERE device_id = ?1"),
                [&[1u8; 16][..]],
            )
            .is_err(),
            "{column}"
        );
    }

    // Token rows: 32-byte hashes of a device that exists.
    assert!(insert_refresh(&conn, &[1; 32], &[1; 16], None).is_ok());
    assert!(
        insert_refresh(&conn, &[2; 31], &[1; 16], None).is_err(),
        "a 31-byte hash"
    );
    assert!(
        insert_refresh(&conn, &[3; 32], &[1; 16], Some(&[1; 31][..])).is_err(),
        "a 31-byte prev_hash"
    );
    assert!(
        insert_refresh(&conn, &[4; 32], &[99; 16], None).is_err(),
        "no such device"
    );
    assert!(
        insert_refresh(&conn, &[5; 32], &[1; 15], None).is_err(),
        "a 15-byte device id"
    );
    for column in ["used_at", "issued_at", "idle_expires_at", "abs_expires_at"] {
        assert!(
            conn.execute(
                &format!("UPDATE ferret_refresh SET {column} = -1 WHERE token_hash = ?1"),
                [&[1u8; 32][..]],
            )
            .is_err(),
            "{column}"
        );
    }
    assert!(insert_access(&conn, &[1; 32], &[1; 16]).is_ok());
    assert!(
        insert_access(&conn, &[2; 31], &[1; 16]).is_err(),
        "a 31-byte hash"
    );
    assert!(
        insert_access(&conn, &[3; 32], &[99; 16]).is_err(),
        "no such device"
    );
    assert!(
        insert_access(&conn, &[1; 32], &[1; 16]).is_err(),
        "the same hash twice"
    );
    assert!(
        conn.execute(
            "INSERT INTO ferret_access (token_hash, device_id, expires_at) VALUES (?1, ?2, -1)",
            params![&[4u8; 32][..], &[1u8; 16][..]],
        )
        .is_err(),
        "a negative expiry"
    );

    // The indexes are there.
    for index in DEVICE_INDEXES {
        let found: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master WHERE type = 'index' AND name = ?1",
                [index],
                |r| r.get(0),
            )
            .expect("count");
        assert_eq!(found, 1, "{index}");
    }
}

#[test]
fn a_token_has_at_most_one_successor() {
    let conn = migrated();
    let user = insert_user(&conn);
    insert_device(&conn, &[1; 16], user, &[1; 32], "a", "linux").expect("a device");
    assert!(insert_refresh(&conn, &[1; 32], &[1; 16], None).is_ok());
    // Many tokens start a chain (no predecessor), but a token has one
    // successor.
    assert!(insert_refresh(&conn, &[2; 32], &[1; 16], None).is_ok());
    assert!(insert_refresh(&conn, &[3; 32], &[1; 16], Some(&[1; 32][..])).is_ok());
    assert!(
        insert_refresh(&conn, &[4; 32], &[1; 16], Some(&[1; 32][..])).is_err(),
        "a second successor of the same token"
    );
    assert!(insert_refresh(&conn, &[5; 32], &[1; 16], Some(&[3; 32][..])).is_ok());
    // The index that holds it is unique and partial.
    let sql: String = conn
        .query_row(
            "SELECT sql FROM sqlite_master WHERE name = 'ferret_refresh_prev'",
            [],
            |r| r.get(0),
        )
        .expect("the index");
    assert_eq!(
        sql,
        "CREATE UNIQUE INDEX ferret_refresh_prev ON ferret_refresh(prev_hash) WHERE prev_hash IS NOT NULL"
    );
}

/// A database as the third milestone left it: its migrations only, two
/// accounts with items, sessions of every scope (one with a fresh
/// re-authentication, one ended) and a sign-in code.
fn database_at_m3() -> Connection {
    let mut conn = database_at_0006();
    apply_migrations_with(&mut conn, &BUILD_AT_M3).expect("the migrations of the third milestone");
    conn.execute(
        "UPDATE ferret_sessions SET reauth_at = ?1 WHERE sid_hash = ?2",
        params![NOW + 2, [1u8; 32].as_slice()],
    )
    .expect("a fresh re-authentication");
    let user: i64 = conn
        .query_row("SELECT id FROM users ORDER BY id LIMIT 1", [], |r| r.get(0))
        .expect("a user");
    conn.execute(
        "INSERT INTO sign_in_codes (user_id, code_hash, created_by, expires_at) \
         VALUES (?1, x'0102', ?1, '2026-11-02 00:00:00')",
        [user],
    )
    .expect("a code");
    conn
}

#[test]
fn migration_0008_keeps_every_m3_row() {
    let names: Vec<&str> = MIGRATION_FILES.iter().map(|(name, _)| *name).collect();
    let at = |name: &str| names.iter().position(|n| *n == name).expect(name);
    assert_eq!(at("0008_devices.sql"), at("0007_reauth.sql") + 1);

    // Additive: three new tables and five new indexes, nothing else.
    let made = statements("0008_devices.sql");
    assert_eq!(made.len(), 8, "{made:?}");
    for table in DEVICE_TABLES {
        assert!(
            made.iter()
                .any(|s| s.starts_with(&format!("CREATE TABLE {table} ("))),
            "{table}"
        );
    }
    for index in DEVICE_INDEXES {
        assert!(
            made.iter().any(|s| {
                s.starts_with(&format!("CREATE INDEX {index} ON "))
                    || s.starts_with(&format!("CREATE UNIQUE INDEX {index} ON "))
            }),
            "{index}"
        );
    }

    let mut conn = database_at_m3();
    let kept_tables = tables(&conn);
    for table in DEVICE_TABLES {
        assert!(!kept_tables.iter().any(|t| t == table), "{table}");
    }
    let before = dump_rows(&conn, &kept_tables);
    let rows_of = |table: &str| -> usize {
        before
            .iter()
            .find(|t| t.starts_with(&format!("{table}: ")))
            .map_or(0, |t| t.lines().count())
    };
    assert_eq!(rows_of("ferret_sessions"), 4);
    assert!(rows_of("ferret_items") >= 4);
    assert_eq!(rows_of("sign_in_codes"), 1);
    let schema_before = dump_schema(&conn);

    let applied = apply_migrations(&mut conn).expect("0008 applies over data");
    assert_eq!(applied, ["0008_devices.sql"], "only 0008 was missing");

    // Every row of every table that was there is as it was, and so is the
    // schema of those tables; the new tables are empty.
    assert_eq!(before, dump_rows(&conn, &kept_tables), "every row kept");
    let schema_after = dump_schema(&conn);
    for entry in schema_before.split("\n\n") {
        assert!(schema_after.contains(entry), "changed: {entry}");
    }
    for table in DEVICE_TABLES {
        let rows: i64 = conn
            .query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |r| r.get(0))
            .expect("count");
        assert_eq!(rows, 0, "{table}");
    }
    // The same schema as a fresh database of this build.
    let mut fresh = empty_database();
    apply_migrations(&mut fresh).expect("a fresh database");
    assert_eq!(schema_after, dump_schema(&fresh));
}

/// The entries of a frozen schema file, without its header: one per table,
/// index, view or trigger.
fn golden_entries(text: &str) -> Vec<String> {
    text.split("\n-- ")
        .skip(1)
        .filter(|entry| {
            entry.starts_with("table ")
                || entry.starts_with("index ")
                || entry.starts_with("view ")
                || entry.starts_with("trigger ")
        })
        .map(|entry| entry.trim_end().to_string())
        .collect()
}

#[test]
fn schema_after_m5a_matches_the_frozen_schema() {
    let mut conn = empty_database();
    apply_migrations(&mut conn).expect("migrations apply");
    let actual = format!("{GOLDEN_HEADER}\n{}", dump_schema(&conn));
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/schema");
    let path = dir.join("m5a.sql");
    if std::env::var("FERRET_UPDATE_GOLDEN").is_ok_and(|v| v == "1") {
        std::fs::create_dir_all(&dir).expect("mkdir");
        std::fs::write(&path, &actual).expect("write the frozen schema");
        return;
    }
    let frozen = std::fs::read_to_string(&path)
        .expect("tests/fixtures/schema/m5a.sql")
        .replace('\r', "");
    let first_difference = frozen
        .lines()
        .zip(actual.lines())
        .position(|(a, b)| a != b)
        .unwrap_or_else(|| frozen.lines().count().min(actual.lines().count()))
        + 1;
    assert!(
        frozen == actual,
        "the schema is not the frozen one. A change of the schema needs a migration and a new \
         frozen file (FERRET_UPDATE_GOLDEN=1); the first difference is at line {first_difference}"
    );

    // Against the schema of the third milestone: every entry of it is still
    // there, the same, and only the three tables and five indexes are new.
    let m3 = std::fs::read_to_string(dir.join("m3.sql"))
        .expect("tests/fixtures/schema/m3.sql")
        .replace('\r', "");
    let old = golden_entries(&m3);
    let new = golden_entries(&frozen);
    assert!(old.len() > 20, "the entries of m3.sql were found");
    for entry in &old {
        assert!(new.contains(entry), "changed or gone: {entry}");
    }
    let mut added: Vec<String> = new
        .iter()
        .filter(|entry| !old.contains(entry))
        .map(|entry| entry.lines().next().unwrap_or_default().to_string())
        .collect();
    added.sort();
    let mut expected: Vec<String> = DEVICE_TABLES
        .iter()
        .map(|t| format!("table {t}"))
        .chain(DEVICE_INDEXES.iter().map(|i| format!("index {i}")))
        .collect();
    expected.sort();
    assert_eq!(added, expected);
    for needle in [
        "jkt BLOB NOT NULL UNIQUE CHECK(length(jkt) = 32)",
        "name TEXT NOT NULL CHECK(length(name) BETWEEN 1 AND 64 AND instr(name, char(0)) = 0)",
        "CREATE UNIQUE INDEX ferret_refresh_prev ON ferret_refresh(prev_hash) WHERE prev_hash IS NOT NULL",
        "CREATE INDEX ferret_refresh_used ON ferret_refresh(used_at) WHERE used_at IS NOT NULL",
    ] {
        assert!(frozen.contains(needle), "{needle}");
    }
    // SQLite keeps indexes of its own for the primary keys and for
    // `UNIQUE(jkt)`; they have no SQL and are not in the file.
    let auto = |table: &str| -> i64 {
        conn.query_row(
            "SELECT COUNT(*) FROM sqlite_master WHERE type = 'index' \
             AND tbl_name = ?1 AND name LIKE 'sqlite_autoindex_%'",
            [table],
            |r| r.get(0),
        )
        .expect("count")
    };
    assert_eq!(auto("ferret_devices"), 2, "the primary key and jkt");
    assert_eq!(auto("ferret_refresh"), 1, "the primary key");
    assert_eq!(auto("ferret_access"), 1, "the primary key");
}

#[test]
fn an_m3_build_refuses_a_database_with_0008() {
    // A database made by this build.
    let mut conn = empty_database();
    apply_migrations(&mut conn).expect("migrations apply");
    let before = dump_schema(&conn);
    let recorded_before = recorded(&conn);

    // A build of the third milestone does not know 0008 and says no.
    let refused = apply_migrations_with(&mut conn, &BUILD_AT_M3).expect_err("a newer schema");
    assert!(
        matches!(refused, MigrationError::NewerSchema { .. }),
        "{refused}"
    );
    assert_eq!(dump_schema(&conn), before, "nothing was changed");
    assert_eq!(recorded(&conn), recorded_before, "nothing was recorded");

    // A control: the same build goes on with a database that has only what it
    // knows, and this build adds 0008 to it.
    let mut old = database_at_m3();
    assert!(
        apply_migrations_with(&mut old, &BUILD_AT_M3)
            .expect("the same build")
            .is_empty()
    );
    assert_eq!(
        apply_migrations(&mut old).expect("this build"),
        ["0008_devices.sql"]
    );
}

#[test]
fn deleting_a_user_removes_its_devices_and_tokens() {
    let mut conn = migrated();
    let admin = insert_named_user(&conn, "admin@example.com", "admin");
    let member = insert_named_user(&conn, "member@example.com", "editor");
    for (user, n) in [(admin, 1u8), (member, 2u8)] {
        // Two devices each, a live one and a revoked one, both with tokens.
        for d in [n, n + 10] {
            insert_device(&conn, &[d; 16], user, &[d; 32], "a device", "linux").expect("device");
            insert_refresh(&conn, &[d; 32], &[d; 16], None).expect("refresh");
            insert_refresh(&conn, &[d + 100; 32], &[d; 16], Some(&[d; 32][..])).expect("next");
            insert_access(&conn, &[d; 32], &[d; 16]).expect("access");
        }
        conn.execute(
            "UPDATE ferret_devices SET revoked_at = ?1 WHERE device_id = ?2",
            params![NOW, [n + 10; 16].as_slice()],
        )
        .expect("revoke");
    }
    assert_eq!(count(&conn, "ferret_refresh", "device_id", &[2; 16]), 2);
    assert_eq!(count(&conn, "ferret_access", "device_id", &[12; 16]), 1);

    // The kit's way to delete a user (the Users page calls it).
    let result = vole_kit::db::users::delete_user(&mut conn, member).expect("delete");
    assert!(result.is_ok(), "the user could not be deleted");

    for device in [2u8, 12] {
        for table in ["ferret_devices", "ferret_refresh", "ferret_access"] {
            assert_eq!(
                count(&conn, table, "device_id", &[device; 16]),
                0,
                "{table} keeps rows of the user"
            );
        }
    }
    assert_eq!(count_user(&conn, "ferret_devices", member), 0);
    // Nothing of the other user went.
    for device in [1u8, 11] {
        assert_eq!(
            count(&conn, "ferret_devices", "device_id", &[device; 16]),
            1
        );
        assert_eq!(
            count(&conn, "ferret_refresh", "device_id", &[device; 16]),
            2
        );
        assert_eq!(count(&conn, "ferret_access", "device_id", &[device; 16]), 1);
    }
    assert_eq!(count_user(&conn, "ferret_devices", admin), 2);
}
