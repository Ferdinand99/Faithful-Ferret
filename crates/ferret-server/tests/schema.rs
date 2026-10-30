//! The migrations and the tables they make.

#[path = "../build_support/registry.rs"]
mod registry;

use std::path::Path;

use ferret_server::db::MIGRATION_FILES;
use ferret_server::product;
use rusqlite::{Connection, params};
use vole_kit::db::migrate::{all_migration_names, apply_migrations};

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
            "0004_handoff_links.sql"
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
