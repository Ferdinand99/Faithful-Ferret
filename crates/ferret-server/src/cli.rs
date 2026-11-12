//! The commands of `ferret` that are not "run the server".
//!
//! * `ferret restore-epoch bump --yes [--at-least <n>] [--data-dir <dir>]` raises
//!   the restore epoch of every vault in the database of the data directory, so
//!   that every client that remembers a lower one sees that the server was
//!   restored (Spec: Fase 1 § 8.6).
//! * `ferret backup create|list [--data-dir <dir>]` and `ferret backup verify
//!   <set>`: make, list and check backup sets. They change nothing that exists,
//!   so they need no `--yes`.
//! * `ferret backup restore --from <set> --yes [--at-least <n>]` and `ferret
//!   backup restore --abort --yes`: put a set back, or undo a restore that did
//!   not finish.
//! * `ferret sign-in-code issue --email <e> --yes`: make a one-time sign-in code
//!   while the server runs, for an administrator who has forgotten the master
//!   password.
//!
//! The commands that change something have guards:
//!
//! * `restore-epoch bump`, `backup restore`, `backup restore --abort` and
//!   `sign-in-code issue` do nothing without `--yes`, which works without a
//!   terminal (`docker compose run --rm ferret restore-epoch bump --yes`);
//! * `restore-epoch bump` needs a database that all the migrations of this build
//!   have run on, and never makes one;
//! * `restore-epoch bump` and `backup create` refuse while a restore is in
//!   progress ([`restore::refuse_if_in_progress`]);
//! * `restore-epoch bump` takes the lock of the data directory (`data_lock`),
//!   which the server holds for as long as it runs, so it refuses while a server
//!   uses the same directory. `--data-dir` falls back to `FERRET_DATA_DIR`, so a
//!   command run inside the container of a live server would otherwise reach the
//!   live data.
//!
//! No listener is started and no URL setting is read.
//!
//! [`parse`] looks only at the first word after the program name. A command
//! line that does not start with a command is the server's own and is left to
//! [`crate::config::Config`], so the server flags and their `FERRET_`
//! environment variables stay in one place.

use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use clap::{Parser, Subcommand};
use rusqlite::{Connection, OpenFlags};

use crate::admin::codes;
use crate::backup::{BackupConfig, restore, set};
use crate::data_lock;
use crate::db::{CORE_MIGRATIONS, MIGRATION_FILES};
use crate::error::StartError;
use crate::product::DB_FILE;
use crate::vault::reconcile;
use crate::wire::MAX_JSON_INT;

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
        /// The lowest epoch the vaults may get (`--at-least`).
        at_least: Option<u64>,
    },
    /// Make a backup set now.
    BackupCreate {
        /// The data directory that holds the database.
        data_dir: PathBuf,
    },
    /// List the backup sets.
    BackupList {
        /// The data directory (the folder of the sets is under it unless
        /// `FERRET_BACKUP_DIR` says otherwise).
        data_dir: PathBuf,
    },
    /// Check a backup set.
    BackupVerify {
        /// The folder of the set.
        set: PathBuf,
    },
    /// Put a backup set back.
    BackupRestore {
        /// The data directory to restore into.
        data_dir: PathBuf,
        /// The folder of the set.
        from: PathBuf,
        /// Whether `--yes` was given.
        confirmed: bool,
        /// The lowest epoch the vaults may get (`--at-least`).
        at_least: Option<u64>,
    },
    /// Undo a restore that did not finish.
    BackupAbort {
        /// The data directory the restore was started in.
        data_dir: PathBuf,
        /// Whether `--yes` was given.
        confirmed: bool,
    },
    /// Make a one-time sign-in code for a user.
    SignInCodeIssue {
        /// The data directory that holds the database.
        data_dir: PathBuf,
        /// The user's email address.
        email: String,
        /// Whether `--yes` was given.
        confirmed: bool,
    },
}

/// The words that start a command.
const COMMANDS: &[&str] = &["restore-epoch", "backup", "sign-in-code"];

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
    /// Backup sets of the database and the secret files.
    Backup {
        #[command(subcommand)]
        action: BackupAction,
    },
    /// One-time sign-in codes.
    SignInCode {
        #[command(subcommand)]
        action: SignInCodeAction,
    },
}

#[derive(Subcommand)]
enum RestoreEpochAction {
    /// Raise the restore epoch of every vault. Stop the server first.
    Bump {
        /// Directory that holds the database.
        #[arg(long, env = "FERRET_DATA_DIR", default_value = "./data")]
        data_dir: PathBuf,
        /// Yes, change the database. Without it nothing is changed.
        #[arg(long)]
        yes: bool,
        /// The lowest epoch the vaults may get.
        #[arg(long, value_parser = clap::value_parser!(u64).range(0..=MAX_JSON_INT))]
        at_least: Option<u64>,
    },
}

#[derive(Subcommand)]
enum BackupAction {
    /// Make a backup set now.
    Create {
        /// Directory that holds the database.
        #[arg(long, env = "FERRET_DATA_DIR", default_value = "./data")]
        data_dir: PathBuf,
    },
    /// List the backup sets.
    List {
        /// Directory that holds the database.
        #[arg(long, env = "FERRET_DATA_DIR", default_value = "./data")]
        data_dir: PathBuf,
    },
    /// Check a backup set against its manifest.
    Verify {
        /// The folder of the set.
        set: PathBuf,
    },
    /// Put a backup set back, or (with `--abort`) undo a restore that did not
    /// finish. Stop the server first.
    Restore {
        /// Directory to restore into.
        #[arg(long, env = "FERRET_DATA_DIR", default_value = "./data")]
        data_dir: PathBuf,
        /// The folder of the set to put back.
        #[arg(long, required_unless_present = "abort", conflicts_with = "abort")]
        from: Option<PathBuf>,
        /// Undo a restore that did not finish.
        #[arg(long, conflicts_with = "at_least")]
        abort: bool,
        /// Yes, change the data directory. Without it nothing is changed.
        #[arg(long)]
        yes: bool,
        /// The lowest epoch the vaults may get.
        #[arg(long, value_parser = clap::value_parser!(u64).range(0..=MAX_JSON_INT))]
        at_least: Option<u64>,
    },
}

#[derive(Subcommand)]
enum SignInCodeAction {
    /// Make a one-time sign-in code for a user, good for 24 hours and one use.
    Issue {
        /// Directory that holds the database.
        #[arg(long, env = "FERRET_DATA_DIR", default_value = "./data")]
        data_dir: PathBuf,
        /// The email address of the user.
        #[arg(long)]
        email: String,
        /// Yes, make the code. Without it nothing is made.
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
            action:
                RestoreEpochAction::Bump {
                    data_dir,
                    yes,
                    at_least,
                },
        } => Command::RestoreEpochBump {
            data_dir,
            confirmed: yes,
            at_least,
        },
        Top::Backup { action } => match action {
            BackupAction::Create { data_dir } => Command::BackupCreate { data_dir },
            BackupAction::List { data_dir } => Command::BackupList { data_dir },
            BackupAction::Verify { set } => Command::BackupVerify { set },
            BackupAction::Restore {
                data_dir,
                from,
                abort,
                yes,
                at_least,
            } => match (abort, from) {
                (false, Some(from)) => Command::BackupRestore {
                    data_dir,
                    from,
                    confirmed: yes,
                    at_least,
                },
                // clap has made sure that `--abort` or `--from` is there, and
                // that they are not both.
                _ => Command::BackupAbort {
                    data_dir,
                    confirmed: yes,
                },
            },
        },
        Top::SignInCode {
            action:
                SignInCodeAction::Issue {
                    data_dir,
                    email,
                    yes,
                },
        } => Command::SignInCodeIssue {
            data_dir,
            email,
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
            at_least,
        } => bump_restore_epoch(&data_dir, confirmed, at_least),
        Command::BackupCreate { data_dir } => backup_create(&data_dir),
        Command::BackupList { data_dir } => backup_list(&data_dir),
        Command::BackupVerify { set } => backup_verify(&set),
        Command::BackupRestore {
            data_dir,
            from,
            confirmed,
            at_least,
        } => {
            require_yes("backup restore changes the data directory", confirmed)?;
            let report = restore::restore(&data_dir, &from, at_least, now_unix()?)?;
            Ok(format!(
                "restored {} vault{}: restore epoch is now {}, {} session{} ended, the files \
                 that were there are in {}",
                report.vaults,
                plural(report.vaults),
                report.restore_epoch,
                report.sessions_ended,
                plural(report.sessions_ended),
                report.moved_aside.display()
            ))
        }
        Command::BackupAbort {
            data_dir,
            confirmed,
        } => {
            require_yes(
                "backup restore --abort changes the data directory",
                confirmed,
            )?;
            restore::abort(&data_dir)?;
            Ok("the restore was undone: the old files are back".to_string())
        }
        Command::SignInCodeIssue {
            data_dir,
            email,
            confirmed,
        } => {
            require_yes("sign-in-code issue makes a code in the database", confirmed)?;
            let issued = codes::issue_sign_in_code(&data_dir, &email)?;
            Ok(format!(
                "sign-in code for {email}: {}\ngood for one use until {} UTC; a newer code \
                 replaces it",
                issued.code(),
                issued.expires_at()
            ))
        }
    }
}

fn plural(n: u64) -> &'static str {
    if n == 1 { "" } else { "s" }
}

/// The guard of every command that changes something: nothing without `--yes`.
fn require_yes(what: &str, confirmed: bool) -> Result<(), StartError> {
    if confirmed {
        Ok(())
    } else {
        Err(format!("{what}: pass --yes to go on").into())
    }
}

/// The time now, in Unix seconds.
fn now_unix() -> Result<i64, StartError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|elapsed| i64::try_from(elapsed.as_secs()).ok())
        .ok_or_else(|| "the system clock is not set".into())
}

/// Opens the database of `data_dir` for a command that reads or changes it: it
/// must be there and have every migration of this build, and none is made.
fn open_migrated(data_dir: &Path) -> Result<Connection, StartError> {
    let db_path = data_dir.join(DB_FILE);
    if !db_path.is_file() {
        return Err(format!(
            "there is no database ({DB_FILE}) in {}: check --data-dir or FERRET_DATA_DIR",
            data_dir.display()
        )
        .into());
    }
    let conn = Connection::open_with_flags(
        &db_path,
        OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .map_err(|e| format!("can't open the database {}: {e}", db_path.display()))?;
    conn.busy_timeout(BUSY_TIMEOUT)?;
    conn.execute_batch("PRAGMA foreign_keys = ON;")?;
    require_migrated(&conn)?;
    Ok(conn)
}

/// `ferret restore-epoch bump`: the guards in the order that leaves the data
/// untouched on every refusal.
fn bump_restore_epoch(
    data_dir: &Path,
    confirmed: bool,
    at_least: Option<u64>,
) -> Result<String, StartError> {
    require_yes(
        "restore-epoch bump changes the database in the data directory",
        confirmed,
    )?;
    restore::refuse_if_in_progress(data_dir)?;
    if !data_dir.join(DB_FILE).is_file() {
        return Err(format!(
            "there is no database ({DB_FILE}) in {}: check --data-dir or FERRET_DATA_DIR",
            data_dir.display()
        )
        .into());
    }
    // Held until the function returns. Taken before the database is opened, so
    // a live server is never touched.
    let _lock = data_lock::acquire_existing(data_dir)?;

    let mut conn = open_migrated(data_dir)?;
    let bumped = reconcile::bump(&mut conn, at_least, now_unix()?)?;
    Ok(format!(
        "restore epoch is now {} ({} vault{} raised)",
        bumped.restore_epoch,
        bumped.vaults,
        plural(bumped.vaults)
    ))
}

/// `ferret backup create`: refuses while a restore is in progress. It does not
/// take the lock of the data directory: a set is made from a consistent copy
/// while the server runs.
fn backup_create(data_dir: &Path) -> Result<String, StartError> {
    restore::refuse_if_in_progress(data_dir)?;
    let cfg = BackupConfig::from_env(data_dir)?;
    let conn = open_migrated(data_dir)?;
    let info = set::create(data_dir, &conn, &cfg, now_unix()?)?;
    Ok(format!(
        "backup set {} made ({} bytes, {})",
        info.name,
        info.bytes,
        if info.verified {
            "checked"
        } else {
            "not checked"
        }
    ))
}

/// `ferret backup list`.
fn backup_list(data_dir: &Path) -> Result<String, StartError> {
    let cfg = BackupConfig::from_env(data_dir)?;
    let sets = set::list(&cfg)?;
    if sets.is_empty() {
        return Ok(format!("no backup sets in {}", cfg.dir.display()));
    }
    Ok(sets
        .iter()
        .map(|info| {
            format!(
                "{}  {} bytes  {}",
                info.name,
                info.bytes,
                if info.verified { "ok" } else { "NOT CHECKED" }
            )
        })
        .collect::<Vec<_>>()
        .join("\n"))
}

/// The migration names this build knows: the kit's core set and ours.
fn build_migrations() -> Vec<&'static str> {
    CORE_MIGRATIONS
        .iter()
        .map(|(name, _)| *name)
        .chain(MIGRATION_FILES.iter().map(|(name, _)| *name))
        .collect()
}

/// `ferret backup verify`.
fn backup_verify(set_dir: &Path) -> Result<String, StartError> {
    let manifest = set::verify(set_dir, &build_migrations())?;
    let count = |n: usize| u64::try_from(n).unwrap_or(u64::MAX);
    Ok(format!(
        "backup set is good: format {}, {} file{}, {} vault{}",
        manifest.format,
        manifest.files.len(),
        plural(count(manifest.files.len())),
        manifest.vaults.len(),
        plural(count(manifest.vaults.len()))
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
    let missing: Vec<&str> = build_migrations()
        .into_iter()
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
