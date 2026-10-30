//! The server's migration set. The pool, the runner and the core tables (users,
//! settings, passkeys) are vole-kit's; the tables of the vault, the login and the
//! sessions are in `migrations/`.
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

/// The kit's core set first (users, settings, passkeys, push), then ours: a
/// fresh product, nothing to adopt.
pub static MIGRATIONS: MigrationSet = MigrationSet {
    core: migrate::CORE,
    adopt_core: None,
    migrations,
    fk_off_marker: "-- ff:foreign_keys=off",
    baseline: None,
    after: no_fixups,
};
