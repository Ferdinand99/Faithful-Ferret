//! The server's migration set. The pool, the runner and the core tables (users,
//! settings, passkeys, one-time sign-in codes) are vole-kit's; the tables of the
//! vault, the login and the sessions are in `migrations/`.
//!
//! A migration is a file `migrations/NNNN_name.sql`. `build.rs` lists them
//! (`include_str!` per file), so a new migration is a new file and no edited
//! line. An applied migration is never edited: a change is a new file.

use rusqlite::Connection;
use vole_kit::db::migrate::{self, MigrationError, MigrationSet};

mod registry {
    include!(concat!(env!("OUT_DIR"), "/migrations.rs"));
}

pub use registry::MIGRATION_FILES;

fn migrations() -> Vec<(String, String)> {
    MIGRATION_FILES
        .iter()
        .map(|(name, sql)| ((*name).to_string(), (*sql).to_string()))
        .collect()
}

fn no_fixups(_: &mut Connection) -> Result<(), MigrationError> {
    Ok(())
}

/// The kit's core migrations that this server runs: every one of
/// [`migrate::CORE`] and then [`migrate::SIGN_IN_CODES`] (the tables of
/// one-time sign-in codes, which `FEATURES.sign_in_codes` needs). The kit
/// runs a pending core migration before a pending migration of ours, so on a
/// database from before the codes it runs first and touches no table of ours.
/// `tests/schema.rs` checks that the list still holds all of the kit's core.
pub static CORE_MIGRATIONS: [(&str, &str); 7] = [
    migrate::CORE_TABLES,
    migrate::TOKEN_SCOPES,
    migrate::PASSKEYS,
    migrate::SEALED_SECRETS,
    migrate::SEALED_TOTP,
    migrate::PUSH,
    migrate::SIGN_IN_CODES,
];

/// The kit's core set first (users, settings, passkeys, push, sign-in codes),
/// then ours: a fresh product, nothing to adopt.
pub static MIGRATIONS: MigrationSet = MigrationSet {
    core: &CORE_MIGRATIONS,
    adopt_core: None,
    migrations,
    fk_off_marker: "-- ff:foreign_keys=off",
    baseline: None,
    after: no_fixups,
};
