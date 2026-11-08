//! The commands of `ferret` that are not "run the server".
//!
//! `ferret restore-epoch bump [--data-dir <dir>]` raises the restore epoch of
//! the database in the data directory, so that every client that remembers a
//! lower one sees that the server was restored (Spec: Fase 1 § 8.6). It runs
//! with the server stopped.
//!
//! [`parse`] looks only at the first word after the program name. A command
//! line that does not start with a command is the server's own and is left to
//! [`crate::config::Config`], so the server flags and their `FERRET_`
//! environment variables stay in one place.

use std::ffi::OsString;
use std::path::PathBuf;

use clap::{Parser, Subcommand};

use crate::error::{NotImplemented, StartError};

/// A command that is not the server.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Command {
    /// Raise the restore epoch of the database in `data_dir`.
    RestoreEpochBump {
        /// The data directory that holds the database.
        data_dir: PathBuf,
    },
}

/// The words that start a command.
const COMMANDS: &[&str] = &["restore-epoch"];

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
    /// Raise the restore epoch by one. Stop the server first.
    Bump {
        /// Directory that holds the database.
        #[arg(long, env = "FERRET_DATA_DIR", default_value = "./data")]
        data_dir: PathBuf,
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
            action: RestoreEpochAction::Bump { data_dir },
        } => Command::RestoreEpochBump { data_dir },
    }))
}

/// Runs a command and returns the line to print. Not implemented yet.
pub fn run(cmd: Command) -> Result<String, StartError> {
    match cmd {
        Command::RestoreEpochBump { .. } => {
            Err(NotImplemented("restore-epoch bump").to_string().into())
        }
    }
}
