//! The commands of `ferret` that are not "run the server".
//!
//! `ferret restore-epoch bump --yes [--data-dir <dir>]` raises the restore epoch
//! of every vault in the database of the data directory, so that every client
//! that remembers a lower one sees that the server was restored (Spec: Fase 1
//! § 8.6). Run it once after restoring the server from a copy, with the server
//! stopped.
//!
//! The command changes the database, so it has three guards:
//!
//! * it does nothing without `--yes`, which works without a terminal
//!   (`docker compose run --rm ferret restore-epoch bump --yes`);
//! * it needs a database that all the migrations of this build have run on, and
//!   never makes one;
//! * it takes the lock of the data directory (`data_lock`), which the server
//!   holds for as long as it runs, so it refuses while a server uses the same
//!   directory. `--data-dir` falls back to `FERRET_DATA_DIR`, so a command run
//!   inside the container of a live server would otherwise reach the live data.
//!
//! No listener is started and no URL setting is read.
//!
//! [`parse`] looks only at the first word after the program name. A command
//! line that does not start with a command is the server's own and is left to
//! [`crate::config::Config`], so the server flags and their `FERRET_`
//! environment variables stay in one place.

use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::time::Duration;

use clap::{Parser, Subcommand};
use rusqlite::{Connection, OpenFlags};

use crate::data_lock;
use crate::db::MIGRATION_FILES;
use crate::error::StartError;
use crate::product::DB_FILE;
use crate::vault::reconcile;

/// A command that is not the server.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Command {
    /// Raise the restore epoch of the database in `data_dir`.
    RestoreEpochBump {
        /// The data directory that holds the database.
        data_dir: PathBuf,
        /// Whether `--yes` was given: the command changes the database and
        /// does nothing without it.
        confirmed: bool,
    },
}

/// The words that start a command.
const COMMANDS: &[&str] = &["restore-epoch"];

/// How long the command waits for a write lock inside the database.
const BUSY_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Parser)]
#[command(name = "ferret", about = "Faithful Ferret server commands")]
struct Cli {
    #[command(subcommand)]
    command: Top,
}

#[derive(Subcommand)]
enum Top {
    /// The restore epoch tells clients that the server was restored.
    RestoreEpoch {
        #[command(subcommand)]
        action: RestoreEpochAction,
    },
}

#[derive(Subcommand)]
enum RestoreEpochAction {
    /// Raise the restore epoch of every vault by one. Stop the server first.
    Bump {
        /// Directory that holds the database.
        #[arg(long, env = "FERRET_DATA_DIR", default_value = "./data")]
        data_dir: PathBuf,
        /// Yes, change the database. Without it nothing is changed.
        #[arg(long)]
        yes: bool,
    },
}

/// Reads a command line (program name first).
///
/// `None` means that this is not a command and the server starts as usual. A
/// command that is spelled wrong, or has a flag it does not know, is
/// `Some(Err(..))`; so is `--help` of a command (clap's error prints the help
/// text).
pub fn parse(args: impl IntoIterator<Item = OsString>) -> Option<Result<Command, clap::Error>> {
    let args: Vec<OsString> = args.into_iter().collect();
    let first = args.get(1)?.to_str()?;
    if !COMMANDS.contains(&first) {
        return None;
    }
    Some(Cli::try_parse_from(&args).map(|cli| match cli.command {
        Top::RestoreEpoch {
            action: RestoreEpochAction::Bump { data_dir, yes },
        } => Command::RestoreEpochBump {
            data_dir,
            confirmed: yes,
        },
    }))
}

/// Runs a command and returns the line to print.
pub fn run(cmd: Command) -> Result<String, StartError> {
    match cmd {
        Command::RestoreEpochBump {
            data_dir,
            confirmed,
        } => bump_restore_epoch(&data_dir, confirmed),
    }
}

/// `ferret restore-epoch bump`: the guards in the order that leaves the data
/// untouched on every refusal.
fn bump_restore_epoch(data_dir: &Path, confirmed: bool) -> Result<String, StartError> {
    if !confirmed {
        return Err(
            "restore-epoch bump changes the database in the data directory: \
             pass --yes to go on"
                .into(),
        );
    }
    let db_path = data_dir.join(DB_FILE);
    if !db_path.is_file() {
        return Err(format!(
            "there is no database ({DB_FILE}) in {}: check --data-dir or FERRET_DATA_DIR",
            data_dir.display()
        )
        .into());
    }
    // Held until the function returns. Taken before the database is opened, so
    // a live server is never touched.
    let _lock = data_lock::acquire_existing(data_dir)?;

    let mut conn = Connection::open_with_flags(
        &db_path,
        OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .map_err(|e| format!("can't open the database {}: {e}", db_path.display()))?;
    conn.busy_timeout(BUSY_TIMEOUT)?;
    conn.execute_batch("PRAGMA foreign_keys = ON;")?;
    require_migrated(&conn)?;

    let bumped = reconcile::bump_all_vaults(&mut conn)?;
    Ok(format!(
        "restore epoch is now {} ({} vault{} raised)",
        bumped.restore_epoch,
        bumped.vaults,
        if bumped.vaults == 1 { "" } else { "s" }
    ))
}

/// The database must have every migration of this build: a directory with
/// another kind of file, or a database the server has not started on, is
/// refused.
fn require_migrated(conn: &Connection) -> Result<(), StartError> {
    let applied: Vec<String> = conn
        .prepare("SELECT name FROM schema_migrations")
        .and_then(|mut stmt| stmt.query_map([], |row| row.get(0))?.collect())
        .map_err(|_| "the database is not a migrated Faithful Ferret database")?;
    let missing: Vec<&str> = MIGRATION_FILES
        .iter()
        .map(|(name, _)| *name)
        .filter(|name| !applied.iter().any(|done| done == name))
        .collect();
    if missing.is_empty() {
        return Ok(());
    }
    Err(format!(
        "the database is missing the migrations {}: start the server once to migrate it, \
         stop it, and run this again",
        missing.join(", ")
    )
    .into())
}
