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
            "0007_reauth.sql"
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
            "ferret_accounts",
            "ferret_checkpoints",
            "ferret_handoffs",
            "ferret_idem",
            "ferret_items",
            "ferret_login_states",
            "ferret_meta",
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

// ---------------------------------------------------------------- the M3 schema

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
        apply_migrations(&mut conn).expect("a fresh database");
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
    let applied = apply_migrations(&mut direct).expect("the new migrations");
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
    let applied = apply_migrations(&mut stepped).expect("then the codes");
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
fn schema_after_m3_matches_the_frozen_schema() {
    let mut conn = empty_database();
    apply_migrations(&mut conn).expect("migrations apply");
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
        "CREATE TABLE users",
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
