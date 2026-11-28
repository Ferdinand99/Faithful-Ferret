//! The schema of the 0.12.x releases (v0.12.0 and v0.12.1), frozen, and a
//! database as such a release leaves it: the starting point of every upgrade
//! test of several accounts (`tests/schema.rs`, and the restore of a 0.12.x
//! backup set in `tests/restore.rs`).
//!
//! 0.12.x ran the kit's seven core migrations ([`CORE_AT_0_12`]) and Ferret's
//! migrations 0001 to 0009; its schema is `tests/fixtures/schema/u3.sql`.

use ferret_server::db::MIGRATION_FILES;
use ferret_server::ids::ItemId;
use ferret_server::product;
use ferret_server::vault::quota::Limits;
use ferret_server::vault::store::{PutBody, PutOutcome, PutRequest, put_item};
use rusqlite::{Connection, params};
use vole_kit::db::migrate::{
    CORE_TABLES, MigrationError, MigrationSet, PASSKEYS, PUSH, SEALED_SECRETS, SEALED_TOTP,
    SIGN_IN_CODES, TOKEN_SCOPES, apply_migrations_with,
};

use super::accounts::{TestAccount, add_account, id16};

/// The clock of these databases: 2026-11-01 00:00:00 UTC.
pub const NOW: i64 = 1_793_491_200;

/// The kit's core migrations as 0.12.x ran them: the kit's core set and the
/// sign-in codes. A later build adds to the end of its own list; this one
/// stays as it was, so the older builds below keep their schema.
pub static CORE_AT_0_12: [(&str, &str); 7] = [
    CORE_TABLES,
    TOKEN_SCOPES,
    PASSKEYS,
    SEALED_SECRETS,
    SEALED_TOTP,
    PUSH,
    SIGN_IN_CODES,
];

/// Ferret's migrations up to and with `last`.
pub fn files_up_to(last: &str) -> Vec<(String, String)> {
    MIGRATION_FILES
        .iter()
        .filter(|(name, _)| *name <= last)
        .map(|(name, sql)| ((*name).to_string(), (*sql).to_string()))
        .collect()
}

fn up_to_0009() -> Vec<(String, String)> {
    files_up_to("0009_unlock.sql")
}

fn no_fixups(_: &mut Connection) -> Result<(), MigrationError> {
    Ok(())
}

/// What 0.12.x ran: [`CORE_AT_0_12`] and our migrations 0001 to 0009.
/// `tests/fixtures/schema/u3.sql` is its schema.
pub static BUILD_AT_U3: MigrationSet = MigrationSet {
    core: &CORE_AT_0_12,
    adopt_core: None,
    migrations: up_to_0009,
    fk_off_marker: "-- ff:foreign_keys=off",
    baseline: None,
    after: no_fixups,
};

/// An empty database with foreign keys on, as in the pool.
pub fn empty_database() -> Connection {
    product::install();
    let conn = Connection::open_in_memory().expect("open");
    conn.execute_batch("PRAGMA foreign_keys = ON;")
        .expect("pragma");
    conn
}

/// Writes revision `base_rev + 1` of item `n` of account `a`.
pub fn put_live(conn: &mut Connection, a: &TestAccount, n: u8, base_rev: u8) {
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

/// Runs `sql` and panics with the statement if it fails.
fn run(conn: &Connection, sql: &str, args: &[&dyn rusqlite::ToSql]) {
    conn.execute(sql, args)
        .unwrap_or_else(|e| panic!("{sql}: {e}"));
}

/// A database as 0.12.x leaves it: its migrations only ([`BUILD_AT_U3`]) and
/// its one account, the first administrator, with everything that account
/// can have: items with an older revision, the manifest and a checkpoint, the
/// password, recovery and passkey unlock methods, a device with its refresh
/// chain and an access token, a changed PIN rule, a pending one-time sign-in
/// code with its e-mail, sessions of the vault and the admin pages (one with a
/// fresh re-authentication, one ended), a hand-over code, a pending
/// registration, a login state and a row of the server's own settings; and
/// rows in the kit's tables of 0.12.x ([`seed_kit_tables`]).
/// Returns the database and the account.
pub fn database_at_0_12() -> (Connection, TestAccount) {
    let mut conn = empty_database();
    apply_migrations_with(&mut conn, &BUILD_AT_U3).expect("the migrations of 0.12.x");
    let a = add_account(&mut conn, 1, NOW);
    run(
        &conn,
        "UPDATE users SET role = 'admin' WHERE id = ?1",
        params![a.user_id],
    );
    put_live(&mut conn, &a, 1, 0);
    put_live(&mut conn, &a, 2, 0);
    put_live(&mut conn, &a, 2, 1);

    // A passkey unlock method beside the password and the recovery key.
    run(
        &conn,
        "INSERT INTO ferret_unlock_methods \
         (method_id, account_id, method_type, wrap, kek_generation, credential_id, prf_salt, \
          aaguid, created_at) \
         VALUES (?1, ?2, 3, ?3, 2, ?4, ?5, ?6, ?7)",
        params![
            id16(0xc3, 1).as_slice(),
            a.account_id.as_bytes().as_slice(),
            [0x33u8; 104].as_slice(),
            [0x34u8; 32].as_slice(),
            [0x35u8; 32].as_slice(),
            [0x36u8; 16].as_slice(),
            NOW
        ],
    );

    // A device with tokens: a refresh chain of two (the first used) and an
    // access token.
    let device = id16(0xd5, 1);
    run(
        &conn,
        "INSERT INTO ferret_devices \
         (device_id, user_id, jkt, name, platform, session_version, created_at, last_seen) \
         VALUES (?1, ?2, ?3, 'Ferret for Firefox (Linux)', 'linux', 1, ?4, ?5)",
        params![
            device.as_slice(),
            a.user_id,
            [0x51u8; 32].as_slice(),
            NOW,
            NOW + 60
        ],
    );
    run(
        &conn,
        "INSERT INTO ferret_refresh \
         (token_hash, device_id, prev_hash, issued_at, idle_expires_at, abs_expires_at, used_at) \
         VALUES (?1, ?2, NULL, ?3, ?4, ?5, ?6)",
        params![
            [0x61u8; 32].as_slice(),
            device.as_slice(),
            NOW,
            NOW + 86_400,
            NOW + 2_592_000,
            NOW + 30
        ],
    );
    run(
        &conn,
        "INSERT INTO ferret_refresh \
         (token_hash, device_id, prev_hash, issued_at, idle_expires_at, abs_expires_at) \
         VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        params![
            [0x62u8; 32].as_slice(),
            device.as_slice(),
            [0x61u8; 32].as_slice(),
            NOW + 30,
            NOW + 86_430,
            NOW + 2_592_000
        ],
    );
    run(
        &conn,
        "INSERT INTO ferret_access (token_hash, device_id, expires_at) VALUES (?1, ?2, ?3)",
        params![[0x71u8; 32].as_slice(), device.as_slice(), NOW + 930],
    );

    // The PIN rule an administrator changed.
    run(
        &conn,
        "UPDATE ferret_unlock_policy \
         SET pin_allowed = 1, pin_after_restart = 0, pin_min_length = 8, updated_at = ?1 \
         WHERE id = 1",
        params![NOW + 5],
    );

    // A pending one-time sign-in code, made by the server command.
    run(
        &conn,
        "INSERT INTO sign_in_codes (user_id, code_hash, created_by, created_at, expires_at) \
         VALUES (?1, ?2, ?1, '2026-11-01 00:00:10', '2026-11-02 00:00:10')",
        params![a.user_id, [0x81u8; 32].as_slice()],
    );
    run(
        &conn,
        "INSERT INTO user_emails (user_id, email) VALUES (?1, 'user1@example.com')",
        params![a.user_id],
    );

    // Sessions: a vault session with a fresh re-authentication, an admin
    // session handed over from it, an ended reset session, a pending one.
    for (n, origin, scope, reauth, parent, revoked) in [
        (1u8, "vault", "full", Some(NOW + 2), None, None),
        (2, "admin", "full", None, Some([1u8; 32]), None),
        (3, "vault", "account_reset", None, None, Some(NOW + 7)),
        (4, "vault", "pending_2fa", None, None, None),
    ] {
        run(
            &conn,
            "INSERT INTO ferret_sessions \
             (sid_hash, user_id, issued_at, origin, device_id, device_name, scope, last_seen, \
              revoked_at, reauth_at, parent_sid) \
             VALUES (?1, ?2, ?3, ?4, ?5, 'a browser', ?6, ?7, ?8, ?9, ?10)",
            params![
                [n; 32].as_slice(),
                a.user_id,
                NOW,
                origin,
                id16(0xd0, n).as_slice(),
                scope,
                NOW + 1,
                revoked,
                reauth,
                parent.as_ref().map(<[u8; 32]>::as_slice)
            ],
        );
    }
    run(
        &conn,
        "INSERT INTO ferret_handoffs \
         (code_hash, sid_hash, user_id, purpose, next, challenge, expires_at) \
         VALUES (?1, ?2, ?3, 'login', '/settings', ?4, ?5)",
        params![
            [0x91u8; 32].as_slice(),
            [1u8; 32].as_slice(),
            a.user_id,
            [0x92u8; 32].as_slice(),
            NOW + 60
        ],
    );

    // A registration that was started and not finished, a login state, and a
    // row of the server's own settings.
    run(
        &conn,
        "INSERT INTO ferret_registrations (registration_id, account_id, vault_id, email, expires_at) \
         VALUES (?1, ?2, ?3, 'late@example.com', ?4)",
        params![
            id16(0xf1, 1).as_slice(),
            id16(0xa0, 9).as_slice(),
            id16(0xb0, 9).as_slice(),
            NOW + 600
        ],
    );
    run(
        &conn,
        "INSERT INTO ferret_login_states (key, sealed, expires_at) VALUES (?1, ?2, ?3)",
        params![[0xa1u8; 16].as_slice(), [0xa2u8; 48].as_slice(), NOW + 300],
    );
    run(
        &conn,
        "INSERT INTO ferret_meta (key, value) VALUES ('upgrade_probe', x'0102')",
        &[],
    );
    seed_kit_tables(&conn, a.user_id);
    (conn, a)
}

/// The kit's tables of 0.12.x with rows in them: the user's sealed second-factor
/// columns, an API token with its scopes, a sign-in passkey and a challenge,
/// the push tables and the server's settings. Ferret uses few of them (the
/// kit's own sign-in pages are closed in its mode), but a database of 0.12.x
/// can hold them all, and an upgrade keeps every row.
fn seed_kit_tables(conn: &Connection, user_id: i64) {
    run(
        conn,
        "UPDATE users SET totp_secret = 'sealed:v1:c2VjcmV0LW9mLTAuMTI', totp_enabled = 0, \
         recovery_codes = '[\"$argon2id$v=19$m=19456,t=2,p=1$c2FsdA$aGFzaA\"]', \
         totp_last_step = 59000000, language = 'nb', last_login_at = '2026-11-01 00:00:20' \
         WHERE id = ?1",
        params![user_id],
    );
    run(
        conn,
        "INSERT INTO api_tokens (id, user_id, name, prefix, token_hash, scope, created_at, \
          last_used_at, expires_at) \
         VALUES (7, ?1, 'a script', 'vk_abcd', ?2, 'write', '2026-11-01 00:00:30', \
          '2026-11-01 00:01:00', '2027-11-01 00:00:00')",
        params![user_id, "ab".repeat(32)],
    );
    for scope in ["monitors:read", "monitors:write"] {
        run(
            conn,
            "INSERT INTO api_token_scopes (token_id, scope) VALUES (7, ?1)",
            params![scope],
        );
    }
    run(
        conn,
        "INSERT INTO passkeys (id, user_id, credential_id, public_key, alg, user_handle, name, \
          sign_count, transports, backup_eligible, backed_up, created_at, last_used_at) \
         VALUES (3, ?1, ?2, ?3, -7, ?4, 'a sign-in passkey', 4, 'internal,hybrid', 1, 1, \
          '2026-11-01 00:00:40', '2026-11-01 00:02:00')",
        params![
            user_id,
            [0xa7u8; 32].as_slice(),
            [0xa8u8; 77].as_slice(),
            [0xa9u8; 32].as_slice()
        ],
    );
    run(
        conn,
        "INSERT INTO passkey_challenges (challenge, purpose, user_id, user_handle, expires_at) \
         VALUES ('Y2hhbGxlbmdlLW9mLTAuMTI', 'register', ?1, ?2, ?3)",
        params![user_id, [0xa9u8; 32].as_slice(), NOW + 300],
    );
    run(
        conn,
        "INSERT INTO push_devices (id, user_id, token_id, handle_sealed, handle_hash, created_at) \
         VALUES (5, ?1, 7, 'sealed:v1:aGFuZGxl', ?2, '2026-11-01 00:00:50')",
        params![user_id, "cd".repeat(32)],
    );
    run(
        conn,
        "INSERT INTO push_events (ref, title, body, kind, level, occurred_at, created_at) \
         VALUES ('cmVmLW9mLTAuMTItZXZlbnQ', 'Backup', 'A set was made', 'recovered', 'ok', \
          '2026-11-01T00:01:00Z', '2026-11-01 00:01:00')",
        &[],
    );
    run(
        conn,
        "INSERT INTO push_registrations (user_id, created_at) VALUES (?1, '2026-11-01 00:01:10')",
        params![user_id],
    );
    for (key, value) in [
        ("site_name", "Ferret at home"),
        ("timezone", "Europe/Oslo"),
        ("language", "nb"),
    ] {
        run(
            conn,
            "INSERT INTO settings (key, value) VALUES (?1, ?2)",
            params![key, value],
        );
    }
}
