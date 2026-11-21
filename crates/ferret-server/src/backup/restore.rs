//! Putting a set back, and the marker that stops everything else while a
//! restore is under way.
//!
//! `ferret backup restore --from <set> --yes [--at-least <n>]` puts a backup set
//! in place of the data in the data directory. It is built so that a kill at any
//! moment leaves either the old data or the new data, never a mix, and so that
//! the server does not start on anything in between:
//!
//! 1. The lock of the data directory (`data_lock`): a running server holds it,
//!    so the restore refuses while one runs. The command must run as the user
//!    that owns the data directory. The set is checked ([`set::verify`]: no
//!    triggers or views, among the rest) before anything is written.
//! 2. The marker [`RESTORE_MARKER`] (JSON: the set, the step, the two folders)
//!    is written and synced before anything moves. While it is there the
//!    server, `ferret restore-epoch bump` and `ferret backup create` refuse to
//!    start ([`refuse_if_in_progress`]).
//! 3. With room for twice the set, the set is copied into
//!    `<data>/.restore-<time>/` (staged), checked again there with
//!    [`set::verify`] (the copy is what gets used, so the copy is what is
//!    checked), given the migrations of this build and compared with the schema
//!    this build makes, and then one transaction raises the restore epoch
//!    ([`reconcile::bump`]'s rule, above the epoch of the data that is there)
//!    and ends every session, hand-over, sign-in state, pending registration
//!    and sign-in code and raises every user's session version
//!    ([`end_everything_after_restore`]).
//! 4. The database of the data directory with its `-wal`, `-shm` and
//!    `-journal`, and the three secret files, are moved with `rename` into
//!    `<data>/pre-restore-<time>/`. The command never deletes them.
//! 5. The staged database and secret files are moved into place with `rename`.
//! 6. The staged folder and, last of all, the marker are removed, once the
//!    restored files are all in place.
//!
//! The marker records each step once it is done and synced. Run again with the
//! marker there, the command goes on: before step 4 nothing in the data
//! directory has changed, so it stages the set again from the start; from step
//! 4 on it finishes the moves that are left. `ferret backup restore --abort
//! --yes` puts the moved files back ([`abort`]); it records in the marker that
//! it has started, so it can be run again after a kill and a restore does not
//! go on after it. A step that fails before anything in the data directory has
//! moved cleans up after itself; one that fails later leaves the marker for a
//! second run or an abort.
//!
//! The database of a set is only ever opened through [`set::verify`] until it
//! has passed that check in the staged folder.
//!
//! Spec: Fase 1 § 11 (the set and its `opaque_setup`; the restore checks that
//! `opaque_setup` is in place before the server starts) and § 8.6,
//! "Legitimate rollbacks" (the restore epoch goes up).

use std::io::{self, ErrorKind, Read as _, Write as _};
use std::path::{Path, PathBuf};

use ferret_server_auth::{OPAQUE_SETUP_FILE, PRELOGIN_SECRET_FILE};
use rusqlite::{Connection, OpenFlags, TransactionBehavior};
use serde::{Deserialize, Serialize};

use super::set::{
    self, COMPLETE_FILE, MANIFEST_FILE, Platform as _, SECRET_FILES, SESSION_KEY_FILE,
};
use super::{BackupError, RESTORE_MARKER};
use crate::auth::session::end_everything_after_restore;
use crate::data_lock::{self, DataDirLock};
use crate::error::{StartError, StoreError};
use crate::product::DB_FILE;
use crate::vault::reconcile;
use crate::wire::MAX_JSON_INT;

/// The `format` of the marker.
pub const MARKER_FORMAT: &str = "ferret-restore/1";

/// The start of the name of the folder the set is staged in.
pub const STAGING_PREFIX: &str = ".restore-";

/// The start of the name of the folder the old files are moved into.
pub const ASIDE_PREFIX: &str = "pre-restore-";

/// The marker before it is put in place with `rename`.
const MARKER_TEMP: &str = "RESTORE_IN_PROGRESS.tmp";

/// The most a marker is read as.
const MAX_MARKER: u64 = 64 * 1024;

/// The names of the steps, in order, as the marker records them. A test can
/// stop a restore after any of them ([`restore_until`]).
pub const RESTORE_STEPS: [&str; 7] = [
    "marker",
    "staged",
    "verified",
    "migrated",
    "bumped",
    "moved_aside",
    "placed",
];

/// The points an abort records or reaches, in order: the restored files are
/// back in the staged folder and the marker says the abort is under way
/// (`undoing`), the old files are back in the data directory (`old_back`), the
/// marker is gone (`unmarked`). A test can stop an abort after any of them
/// ([`abort_until`]).
pub const ABORT_STEPS: [&str; 3] = ["undoing", "old_back", "unmarked"];

/// The steps of a restore. The marker records the last one that is done.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum RestoreStep {
    /// The marker is written; nothing else has changed.
    Marker,
    /// The set is copied into the staged folder.
    Staged,
    /// The staged copy passed the check.
    Verified,
    /// The staged database has the migrations of this build.
    Migrated,
    /// The restore epoch is raised and every session and code ended, in one
    /// transaction, in the staged database.
    Bumped,
    /// The old files are in the moved-aside folder.
    MovedAside,
    /// The restored files are in place.
    Placed,
}

impl RestoreStep {
    const ALL: [RestoreStep; 7] = [
        RestoreStep::Marker,
        RestoreStep::Staged,
        RestoreStep::Verified,
        RestoreStep::Migrated,
        RestoreStep::Bumped,
        RestoreStep::MovedAside,
        RestoreStep::Placed,
    ];

    /// The name in the marker.
    pub(crate) fn name(self) -> &'static str {
        let index = Self::ALL.iter().position(|s| *s == self).unwrap_or(0);
        RESTORE_STEPS[index]
    }

    fn from_name(name: &str) -> Option<Self> {
        let index = RESTORE_STEPS.iter().position(|s| *s == name)?;
        Self::ALL.get(index).copied()
    }

    fn next(self) -> Option<Self> {
        let index = Self::ALL.iter().position(|s| *s == self)?;
        Self::ALL.get(index + 1).copied()
    }
}

/// Refuses when the marker is in `data_dir`. Anything but a clear "not there"
/// (an error reading the directory, say) refuses too: the answer must be a yes
/// before anything goes on.
pub fn refuse_if_in_progress(data_dir: &Path) -> Result<(), StartError> {
    let marker = data_dir.join(RESTORE_MARKER);
    match std::fs::symlink_metadata(&marker) {
        Ok(_) => Err(format!(
            "a restore is in progress in {}: {} is there. Run `ferret backup restore --from <set> \
             --yes` again to finish it, or `ferret backup restore --abort --yes` to put the old \
             files back",
            data_dir.display(),
            RESTORE_MARKER
        )
        .into()),
        Err(e) if e.kind() == ErrorKind::NotFound => Ok(()),
        Err(e) => Err(format!(
            "can't tell whether a restore is in progress in {}: {e}",
            data_dir.display()
        )
        .into()),
    }
}

/// What a restore did. Counts, the epoch and a folder: nothing from the set.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RestoreReport {
    /// The restore epoch every vault has now (the highest, if they differ).
    pub restore_epoch: u64,
    /// How many vaults were restored.
    pub vaults: u64,
    /// How many sessions were ended.
    pub sessions_ended: u64,
    /// Where the files that were in the data directory before went.
    pub moved_aside: PathBuf,
    /// Whether the restore epoch of the data that was in the data directory
    /// could not be read (no database, or not a readable one). The new epoch is
    /// then above the backup's and the time, but not checked against what that
    /// data had: an epoch a client saw that was once above the clock (an
    /// earlier `--at-least`) needs `restore-epoch bump --at-least`.
    pub seen_epoch_unknown: bool,
}

/// Restores the set in `from` into `data_dir`, with a restore epoch of at least
/// `at_least`, at `now` (Unix seconds). With a restore marker in `data_dir`, it
/// goes on with the restore the marker describes (`from` must name the same
/// set). See the module documentation for the steps.
pub fn restore(
    data_dir: &Path,
    from: &Path,
    at_least: Option<u64>,
    now: i64,
) -> Result<RestoreReport, BackupError> {
    run(data_dir, from, at_least, now, None)?
        .ok_or(BackupError::Io("the restore stopped before it was done"))
}

/// [`restore`] that stops right after the step named `stop_after` (one of
/// [`RESTORE_STEPS`]) is done and recorded, as a kill there would: nothing is
/// cleaned up. `None` when it stopped; the report when the restore was already
/// past that step and finished. For the tests of a restore that is cut off; the
/// command never calls it.
#[doc(hidden)]
pub fn restore_until(
    data_dir: &Path,
    from: &Path,
    at_least: Option<u64>,
    now: i64,
    stop_after: &str,
) -> Result<Option<RestoreReport>, BackupError> {
    let step = RestoreStep::from_name(stop_after).ok_or(BackupError::Refused("no such step"))?;
    run(data_dir, from, at_least, now, Some(step))
}

/// Undoes a restore that did not finish: puts the files that were moved aside
/// back and removes the marker, then the staged folder. Refuses while the
/// server runs and when no restore is in progress.
///
/// An abort that is cut off can be run again, and a restore does not go on
/// after one has started:
///
/// 1. Unless the marker already says `undoing`: from `moved_aside` on, every
///    file of the live data in the data directory is a restored one (the old
///    ones were all moved before the marker said so), and goes back into the
///    staged folder. Then the marker is written with `undoing`, so a second run
///    never takes the old files, once they are back, for restored ones.
/// 2. The files in the moved-aside folder go back into the data directory; one
///    that is back already is skipped.
/// 3. The marker goes, and only then the copies: the staged folder and the
///    moved-aside folder if it is empty.
pub fn abort(data_dir: &Path) -> Result<(), BackupError> {
    abort_with(data_dir, None)
}

/// [`abort`] that stops right after the point named `stop_after` (one of
/// [`ABORT_STEPS`]), as a kill there would. For the tests of an abort that is
/// cut off; the command never calls it.
#[doc(hidden)]
pub fn abort_until(data_dir: &Path, stop_after: &str) -> Result<(), BackupError> {
    if !ABORT_STEPS.contains(&stop_after) {
        return Err(BackupError::Refused("no such step"));
    }
    abort_with(data_dir, Some(stop_after))
}

fn abort_with(data_dir: &Path, stop: Option<&str>) -> Result<(), BackupError> {
    let _lock = lock(data_dir)?;
    let mut marker =
        read_marker(data_dir)?.ok_or(BackupError::Refused("no restore is in progress"))?;
    let step = marker.step()?;
    let staging = data_dir.join(&marker.staging);
    let aside = data_dir.join(&marker.moved_aside);

    if !marker.undoing {
        if step >= RestoreStep::MovedAside {
            make_private_dir(&staging)?;
            for name in live_files() {
                let live = data_dir.join(&name);
                if there(&live)? {
                    if there(&staging.join(&name))? {
                        return Err(BackupError::Refused(
                            "a restored file is both in the data directory and in the staged \
                             folder",
                        ));
                    }
                    rename(&live, &staging.join(&name))?;
                }
            }
            sync_dir(&staging)?;
        }
        marker.undoing = true;
        write_marker(data_dir, &marker)?;
    }
    tracing::info!("undoing a restore");
    if stop == Some("undoing") {
        return Ok(());
    }

    if there(&aside)? {
        for name in live_files() {
            let moved = aside.join(&name);
            if !there(&moved)? {
                // Not moved aside, or back already.
                continue;
            }
            let live = data_dir.join(&name);
            if there(&live)? {
                return Err(BackupError::Refused(
                    "a file is both in the data directory and in the moved-aside folder",
                ));
            }
            rename(&moved, &live)?;
        }
        sync_dir(data_dir)?;
    }
    if stop == Some("old_back") {
        return Ok(());
    }

    // The marker first: what is left after it are copies.
    remove_marker(data_dir)?;
    if stop == Some("unmarked") {
        return Ok(());
    }
    // Only an empty folder goes; anything else in it stays for a person.
    let _ = std::fs::remove_dir(&aside);
    remove_tree(&staging);
    tracing::info!("restore undone: the old files are back");
    Ok(())
}

// ---------------------------------------------------------------------------
// The run
// ---------------------------------------------------------------------------

/// The marker: what a restore is doing, so that a second run or an abort knows.
/// It holds paths, the step and numbers, never anything from the set's files.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Marker {
    /// [`MARKER_FORMAT`].
    format: String,
    /// The last step that is done, one of [`RESTORE_STEPS`].
    step: String,
    /// The set, as an absolute path.
    source: String,
    /// The name of the staged folder in the data directory.
    staging: String,
    /// The name of the moved-aside folder in the data directory.
    moved_aside: String,
    /// When the restore started (Unix seconds).
    started_at: i64,
    /// The lowest restore epoch the caller asked for.
    at_least: Option<u64>,
    /// The highest restore epoch of the data that was in the data directory
    /// when the restore started (0 when there was none, or it could not be read).
    seen_epoch: u64,
    /// Whether that epoch could not be read.
    #[serde(default)]
    seen_epoch_unknown: bool,
    /// What the bump did, once it is done.
    done: Option<Done>,
    /// Whether an abort has started: the restore does not go on after that,
    /// and a second abort does not move the files of the data directory into
    /// the staged folder again.
    #[serde(default)]
    undoing: bool,
}

/// What the transaction of the bump did.
#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Done {
    restore_epoch: u64,
    vaults: u64,
    sessions_ended: u64,
}

impl Marker {
    fn step(&self) -> Result<RestoreStep, BackupError> {
        RestoreStep::from_name(&self.step).ok_or(UNREADABLE_MARKER)
    }

    /// The lowest epoch the bump uses: what the caller asked for, and one above
    /// every epoch the data that was there had.
    fn lowest_epoch(&self) -> Option<u64> {
        let above_seen = if self.seen_epoch == 0 {
            0
        } else {
            self.seen_epoch.saturating_add(1)
        };
        let lowest = self.at_least.unwrap_or(0).max(above_seen);
        (lowest > 0).then_some(lowest)
    }
}

const UNREADABLE_MARKER: BackupError = BackupError::Refused(
    "the restore marker is not one this build can read: look at it and the data directory by hand",
);

fn run(
    data_dir: &Path,
    from: &Path,
    at_least: Option<u64>,
    now: i64,
    stop: Option<RestoreStep>,
) -> Result<Option<RestoreReport>, BackupError> {
    if at_least.is_some_and(|n| n > MAX_JSON_INT) {
        return Err(BackupError::Refused(
            "--at-least is above the largest JSON integer",
        ));
    }
    let _lock = lock(data_dir)?;
    let (marker, step) = match read_marker(data_dir)? {
        None => (start(data_dir, from, at_least, now)?, RestoreStep::Marker),
        Some(marker) => resume(marker, from, at_least)?,
    };
    let mut run = Run {
        data_dir,
        marker,
        stop,
    };
    run.go(step, now)
}

/// The data directory must be there, the command must run as the user that
/// owns it, and no other process may hold its lock.
fn lock(data_dir: &Path) -> Result<DataDirLock, BackupError> {
    let meta = std::fs::metadata(data_dir)
        .ok()
        .filter(std::fs::Metadata::is_dir)
        .ok_or(BackupError::Refused("the data directory does not exist"))?;
    // The server checks that its secret files belong to the user it runs as:
    // files restored by another user (root, say) would stop it from starting.
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt as _;
        if rustix::process::geteuid().as_raw() != meta.uid() {
            return Err(BackupError::Refused(
                "run the command as the user that owns the data directory (the server's user, \
                 for example with `docker compose run --rm <service> ...`), not as root or \
                 another user",
            ));
        }
    }
    #[cfg(not(unix))]
    let _ = meta;
    data_lock::acquire_existing(data_dir).map_err(|error| {
        tracing::warn!(%error, "the data directory could not be locked");
        BackupError::Refused(
            "the data directory is in use or can not be locked: stop the server first",
        )
    })
}

/// A new restore: the set is checked, then the marker is written.
fn start(
    data_dir: &Path,
    from: &Path,
    at_least: Option<u64>,
    now: i64,
) -> Result<Marker, BackupError> {
    // A marker that was never put in place: nothing had moved.
    remove_file_if_there(&data_dir.join(MARKER_TEMP))?;
    let source = std::fs::canonicalize(from).map_err(io_err("the set can not be found"))?;
    // Spec: Fase 1 § 11: a set that does not pass the check (no `opaque_setup`,
    // a set-up that is not the one the database names, a damaged file, a
    // migration this build does not know) changes nothing.
    set::verify(&source, &set::build_migrations())?;
    let source = source
        .to_str()
        .ok_or(BackupError::Refused("the path of the set is not UTF-8"))?
        .to_string();
    let (staging, moved_aside) = free_names(data_dir, now)?;
    let seen = highest_epoch_there(data_dir);
    let marker = Marker {
        format: MARKER_FORMAT.to_string(),
        step: RestoreStep::Marker.name().to_string(),
        source,
        staging,
        moved_aside,
        started_at: now,
        at_least,
        seen_epoch: seen.unwrap_or(0),
        seen_epoch_unknown: seen.is_none(),
        done: None,
        undoing: false,
    };
    write_marker(data_dir, &marker)?;
    tracing::info!(step = RestoreStep::Marker.name(), "restore step done");
    Ok(marker)
}

/// A restore that was cut off. It must be the same set. Before the old files
/// move nothing in the data directory has changed, so the set is staged again
/// from the start; after that the moves that are left are finished.
fn resume(
    mut marker: Marker,
    from: &Path,
    at_least: Option<u64>,
) -> Result<(Marker, RestoreStep), BackupError> {
    let step = marker.step()?;
    if marker.undoing {
        return Err(BackupError::Refused(
            "an abort of this restore is under way: run `ferret backup restore --abort --yes` \
             again to finish it",
        ));
    }
    let given = std::fs::canonicalize(from)
        .or_else(|_| std::path::absolute(from))
        .map_err(io_err("the set can not be found"))?;
    if given.to_str() != Some(marker.source.as_str()) {
        return Err(BackupError::Refused(
            "a restore of another set is in progress: run it again with the same --from, or undo \
             it with --abort",
        ));
    }
    tracing::info!(step = step.name(), "going on with a restore");
    if step < RestoreStep::Bumped {
        // Only raising: a second run may ask for more, never for less.
        marker.at_least = match (marker.at_least, at_least) {
            (Some(a), Some(b)) => Some(a.max(b)),
            (a, b) => a.or(b),
        };
        return Ok((marker, RestoreStep::Marker));
    }
    // The bump is done: a higher epoch than it gave can not be had from this
    // run, and is never dropped without a word.
    let raised = marker.done.map_or(0, |done| done.restore_epoch);
    if at_least.is_some_and(|wanted| wanted > raised) {
        return Err(BackupError::Refused(
            "the restore epoch was already raised, below the --at-least asked for now: run the \
             restore again without --at-least to finish it, then `ferret restore-epoch bump \
             --yes --at-least <n>`",
        ));
    }
    Ok((marker, step))
}

struct Run<'a> {
    data_dir: &'a Path,
    marker: Marker,
    stop: Option<RestoreStep>,
}

impl Run<'_> {
    fn staging(&self) -> PathBuf {
        self.data_dir.join(&self.marker.staging)
    }

    fn aside(&self) -> PathBuf {
        self.data_dir.join(&self.marker.moved_aside)
    }

    /// Goes on after `done`, the last step that is done, up to the end or to
    /// the step the caller stops after.
    fn go(
        &mut self,
        mut done: RestoreStep,
        now: i64,
    ) -> Result<Option<RestoreReport>, BackupError> {
        if self.stop == Some(done) {
            return Ok(None);
        }
        while let Some(step) = done.next() {
            if let Err(error) = self.step(step, now) {
                return Err(self.failed(step, error));
            }
            self.marker.step = step.name().to_string();
            if let Err(error) = write_marker(self.data_dir, &self.marker) {
                return Err(self.failed(step, error));
            }
            tracing::info!(step = step.name(), "restore step done");
            done = step;
            if self.stop == Some(step) {
                return Ok(None);
            }
        }
        self.finish().map(Some)
    }

    fn step(&mut self, step: RestoreStep, now: i64) -> Result<(), BackupError> {
        let staged_db = self.staging().join(DB_FILE);
        match step {
            RestoreStep::Marker => Ok(()),
            RestoreStep::Staged => stage(Path::new(&self.marker.source), &self.staging()),
            // The copy is what will be used, so the copy is what is checked.
            RestoreStep::Verified => {
                set::verify(&self.staging(), &set::build_migrations()).map(|_| ())
            }
            RestoreStep::Migrated => migrate(&staged_db),
            RestoreStep::Bumped => {
                let done = bump(&staged_db, self.marker.lowest_epoch(), now)?;
                self.marker.done = Some(done);
                Ok(())
            }
            RestoreStep::MovedAside => self.move_aside(),
            RestoreStep::Placed => self.place(),
        }
    }

    /// A step failed. Before the old files move nothing in the data directory
    /// has changed, so the staged folder and the marker go and the data
    /// directory is as it was. Later the marker stays for a second run or an
    /// abort.
    fn failed(&self, step: RestoreStep, error: BackupError) -> BackupError {
        tracing::warn!(
            step = step.name(),
            code = error.code(),
            "a restore step failed"
        );
        if step <= RestoreStep::Bumped {
            remove_tree(&self.staging());
            if let Err(cleanup) = remove_marker(self.data_dir) {
                tracing::warn!(
                    code = cleanup.code(),
                    "the restore marker could not be removed"
                );
            }
        }
        error
    }

    /// Step 4: the database with its journal files and the three secret files
    /// move into the moved-aside folder. A file that is already there was moved
    /// by a run that was cut off.
    fn move_aside(&self) -> Result<(), BackupError> {
        let aside = self.aside();
        make_private_dir(&aside)?;
        sync_dir(self.data_dir)?;
        for name in live_files() {
            let live = self.data_dir.join(&name);
            let moved = aside.join(&name);
            match (there(&live)?, there(&moved)?) {
                (true, false) => rename(&live, &moved)?,
                (true, true) => {
                    return Err(BackupError::Refused(
                        "a file is both in the data directory and in the moved-aside folder",
                    ));
                }
                (false, _) => {}
            }
        }
        sync_dir(&aside)?;
        sync_dir(self.data_dir)
    }

    /// Step 5: the restored database and secret files move into place. No
    /// `-wal`, `-shm` or `-journal` may be next to the restored database: those
    /// of the old one were moved aside with it.
    fn place(&self) -> Result<(), BackupError> {
        for journal in journal_files() {
            if there(&self.data_dir.join(journal))? {
                return Err(BackupError::Refused(
                    "a journal file is in the data directory where the restored database goes",
                ));
            }
        }
        let staging = self.staging();
        for name in placed_files() {
            let staged = staging.join(name);
            let live = self.data_dir.join(name);
            match (there(&staged)?, there(&live)?) {
                (true, false) => rename(&staged, &live)?,
                // Put in place by a run that was cut off.
                (false, true) => {}
                (true, true) => {
                    return Err(BackupError::Refused(
                        "a file is in the data directory where a restored one goes",
                    ));
                }
                (false, false) => return Err(BackupError::Io("a restored file is missing")),
            }
        }
        sync_dir(self.data_dir)
    }

    /// Step 6: the staged folder (only the manifest is left in it) and then the
    /// marker go.
    fn finish(&self) -> Result<RestoreReport, BackupError> {
        let done = self.marker.done.ok_or(BackupError::Io(
            "the restore marker lacks what the bump did",
        ))?;
        // Nothing is removed unless the restored database and secret files are
        // all in place: a cut-off abort can have taken some of them back.
        for name in placed_files() {
            if !std::fs::symlink_metadata(self.data_dir.join(name)).is_ok_and(|m| m.is_file()) {
                return Err(BackupError::Refused(
                    "the restored files are not all in the data directory: undo the restore with \
                     `ferret backup restore --abort --yes`",
                ));
            }
        }
        remove_tree(&self.staging());
        remove_marker(self.data_dir)?;
        tracing::info!(
            vaults = done.vaults,
            restore_epoch = done.restore_epoch,
            sessions_ended = done.sessions_ended,
            "restore finished"
        );
        Ok(RestoreReport {
            restore_epoch: done.restore_epoch,
            vaults: done.vaults,
            sessions_ended: done.sessions_ended,
            moved_aside: self.aside(),
            seen_epoch_unknown: self.marker.seen_epoch_unknown,
        })
    }
}

// ---------------------------------------------------------------------------
// The staged copy
// ---------------------------------------------------------------------------

/// Copies the six files of the set into a new staged folder (`0700`, files
/// `0600`). A staged folder of an earlier run is removed first.
fn stage(source: &Path, staging: &Path) -> Result<(), BackupError> {
    remove_tree(staging);
    if there(staging)? {
        return Err(BackupError::Io(
            "the staged folder of an earlier run can not be removed",
        ));
    }
    let names: Vec<&str> = [DB_FILE, MANIFEST_FILE, COMPLETE_FILE]
        .into_iter()
        .chain(SECRET_FILES)
        .collect();
    // Spec: Fase 1 § 11, the rule of the backups: free space for twice what is
    // written, or the step stops before it writes anything.
    let size = names
        .iter()
        .map(|name| std::fs::symlink_metadata(source.join(name)).map_or(0, |m| m.len()))
        .fold(0u64, u64::saturating_add);
    let parent = staging.parent().unwrap_or(staging);
    if !enough_space(set::RealPlatform.free_bytes(parent), size) {
        return Err(BackupError::NoSpace);
    }
    make_private_dir(staging)?;
    for name in names {
        copy_file(&source.join(name), &staging.join(name))?;
    }
    sync_dir(staging)
}

/// Whether `free` bytes (unknown counts as enough) hold twice `size`.
fn enough_space(free: Option<u64>, size: u64) -> bool {
    free.is_none_or(|free| free >= size.saturating_mul(2))
}

/// Opens a file of the set for reading: never through a link (the open itself
/// refuses one, so it can not be swapped in after a check), and only a plain
/// file.
fn open_plain(path: &Path) -> Result<std::fs::File, BackupError> {
    #[cfg(unix)]
    let file = {
        use rustix::fs::{Mode, OFlags};
        let fd = rustix::fs::open(
            path,
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK,
            Mode::empty(),
        )
        .map_err(|error| io_err("a file of the set can not be read")(error.into()))?;
        std::fs::File::from(fd)
    };
    #[cfg(not(unix))]
    let file = {
        let meta =
            std::fs::symlink_metadata(path).map_err(io_err("a file of the set is missing"))?;
        if !meta.is_file() {
            return Err(BackupError::Verify("a set file is not a plain file"));
        }
        std::fs::File::open(path).map_err(io_err("a file of the set can not be read"))?
    };
    let meta = file
        .metadata()
        .map_err(io_err("a file of the set can not be read"))?;
    if !meta.is_file() {
        return Err(BackupError::Verify("a set file is not a plain file"));
    }
    Ok(file)
}

/// Copies a plain file (never a link) into a new `0600` file and syncs it.
fn copy_file(from: &Path, to: &Path) -> Result<(), BackupError> {
    let mut input = open_plain(from)?;
    let mut output = new_private_file(to).map_err(io_err("could not write the staged copy"))?;
    // File to file: the kernel copies it, without a buffer in this process.
    io::copy(&mut input, &mut output).map_err(io_err("could not write the staged copy"))?;
    output
        .sync_all()
        .map_err(io_err("could not sync the staged copy"))
}

/// Opens the staged database, which has passed [`set::verify`], to change it:
/// no function or view of its schema runs, its schema can not be written
/// around SQL, and it keeps a rollback journal (no `-wal` or `-shm`).
fn open_staged(db: &Path) -> Result<Connection, BackupError> {
    let bad = |error: rusqlite::Error| {
        tracing::warn!(code = ?error.sqlite_error_code(), "the staged database can not be opened");
        BackupError::Io("could not open the staged database")
    };
    let conn = Connection::open_with_flags(
        db,
        OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .map_err(bad)?;
    conn.set_db_config(rusqlite::config::DbConfig::SQLITE_DBCONFIG_DEFENSIVE, true)
        .map_err(bad)?;
    conn.execute_batch(
        "PRAGMA foreign_keys = ON; PRAGMA trusted_schema = OFF; PRAGMA cell_size_check = ON;",
    )
    .map_err(bad)?;
    let mode: String = conn
        .query_row("PRAGMA journal_mode = DELETE", [], |row| row.get(0))
        .map_err(bad)?;
    if !mode.eq_ignore_ascii_case("delete") {
        return Err(BackupError::Io("the staged database keeps its WAL"));
    }
    Ok(conn)
}

/// Closes the staged database, checks that it left no journal file behind, and
/// syncs it.
fn close_staged(conn: Connection, db: &Path) -> Result<(), BackupError> {
    conn.close().map_err(|(_, error)| {
        tracing::warn!(code = ?error.sqlite_error_code(), "the staged database did not close");
        BackupError::Io("could not close the staged database")
    })?;
    let folder = db.parent().unwrap_or(db);
    for journal in journal_files() {
        if there(&folder.join(journal))? {
            return Err(BackupError::Io("the staged database left a journal file"));
        }
    }
    std::fs::File::open(db)
        .and_then(|file| file.sync_all())
        .map_err(io_err("could not sync the staged database"))?;
    sync_dir(folder)
}

/// Step 3: the migrations of this build (the kit's set and ours), each in its
/// own transaction. A set from before a migration is brought up to this build
/// here, before the bump.
fn migrate(db: &Path) -> Result<(), BackupError> {
    // The kit's runner reads the installed product (installing is idempotent).
    crate::product::install();
    let mut conn = open_staged(db)?;
    let applied = vole_kit::db::migrate::apply_migrations_with(&mut conn, &crate::db::MIGRATIONS)
        .map_err(|error| {
        tracing::warn!(%error, "the staged database could not be migrated");
        BackupError::Refused("the set could not be migrated to this build")
    })?;
    tracing::info!(applied = applied.len(), "staged database migrated");
    // The bump runs SQL against this database next, and the server after it:
    // its schema must be the one this build makes, with nothing added (a
    // trigger could undo the end of the sessions, say).
    let staged = schema_of(&conn).map_err(|_| BackupError::Io("could not read the schema"))?;
    if staged != expected_schema()? {
        return Err(BackupError::Refused(
            "the schema of the set is not the one this build makes",
        ));
    }
    close_staged(conn, db)
}

/// One object of a schema: type, name, table and its SQL with the spaces
/// evened out (an `ALTER TABLE` writes the text it changes a little
/// differently from a `CREATE TABLE`).
type SchemaRow = (String, String, String, String);

/// The schema of a database, without SQLite's own objects, in a fixed order.
fn schema_of(conn: &Connection) -> rusqlite::Result<Vec<SchemaRow>> {
    let mut stmt = conn.prepare(
        "SELECT type, name, tbl_name, COALESCE(sql, '') FROM sqlite_schema \
         WHERE name NOT LIKE 'sqlite\\_%' ESCAPE '\\' ORDER BY type, name",
    )?;
    let rows = stmt.query_map([], |row| {
        Ok((
            row.get(0)?,
            row.get(1)?,
            row.get(2)?,
            even_spaces(&row.get::<_, String>(3)?),
        ))
    })?;
    rows.collect()
}

/// `sql` with every run of white space as one space, and none next to a
/// parenthesis or a comma.
fn even_spaces(sql: &str) -> String {
    let collapsed = sql.split_whitespace().collect::<Vec<_>>().join(" ");
    let mut out = String::with_capacity(collapsed.len());
    let mut chars = collapsed.chars().peekable();
    while let Some(c) = chars.next() {
        if c == ' '
            && (out.ends_with(['(', ')', ','])
                || chars
                    .peek()
                    .is_some_and(|next| matches!(next, '(' | ')' | ',')))
        {
            continue;
        }
        out.push(c);
    }
    out
}

/// The schema this build makes: every migration run on an empty database in
/// memory.
fn expected_schema() -> Result<Vec<SchemaRow>, BackupError> {
    const FAILED: BackupError = BackupError::Io("could not make the schema of this build");
    let mut conn = Connection::open_in_memory().map_err(|_| FAILED)?;
    conn.execute_batch("PRAGMA foreign_keys = ON;")
        .map_err(|_| FAILED)?;
    vole_kit::db::migrate::apply_migrations_with(&mut conn, &crate::db::MIGRATIONS)
        .map_err(|_| FAILED)?;
    schema_of(&conn).map_err(|_| FAILED)
}

/// Step 3, the last part: one transaction raises the restore epoch of every
/// vault with the rule of [`reconcile::bump`] and ends everything a backup
/// would bring back to life.
///
/// Spec: Fase 1 § 8.6, "Legitimate rollbacks", and § 11.
fn bump(db: &Path, at_least: Option<u64>, now: i64) -> Result<Done, BackupError> {
    let sql = |error: rusqlite::Error| {
        tracing::warn!(code = ?error.sqlite_error_code(), "the restore transaction failed");
        BackupError::Io("could not raise the restore epoch")
    };
    let mut conn = open_staged(db)?;
    let tx = conn
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(sql)?;
    let bumped = reconcile::bump_in(&tx, at_least, now).map_err(|error| match error {
        StoreError::Invalid(why) => BackupError::Refused(why),
        other => {
            tracing::warn!(error = %other, "the restore epoch could not be raised");
            BackupError::Io("could not raise the restore epoch")
        }
    })?;
    let swept = end_everything_after_restore(&tx, now).map_err(sql)?;
    tx.commit().map_err(sql)?;
    let verdict: String = conn
        .query_row("PRAGMA quick_check", [], |row| row.get(0))
        .map_err(sql)?;
    if verdict != "ok" {
        return Err(BackupError::Verify(
            "the restored database failed its check",
        ));
    }
    close_staged(conn, db)?;
    Ok(Done {
        restore_epoch: bumped.restore_epoch,
        vaults: bumped.vaults,
        sessions_ended: u64::try_from(swept.sessions).unwrap_or(u64::MAX),
    })
}

/// The highest restore epoch of the database that is in the data directory
/// now, so that the restored one goes above it too, or `None` when there is no
/// database or it can not be read.
///
/// The database is opened read-only, as it is (its WAL counts: the lock of the
/// data directory is held, and a `-shm` this may make moves aside with it).
/// When that fails it is read once more `immutable` (the main file only). A
/// missing or unreadable database is not an error: a broken database is what a
/// restore is for, and the time in the rule still holds; the report says so.
fn highest_epoch_there(data_dir: &Path) -> Option<u64> {
    let db = data_dir.join(DB_FILE);
    if !std::fs::symlink_metadata(&db).is_ok_and(|meta| meta.is_file()) {
        tracing::warn!("there is no database in the data directory to read the restore epoch of");
        return None;
    }
    let read = |conn: Connection| -> rusqlite::Result<u64> {
        conn.set_db_config(rusqlite::config::DbConfig::SQLITE_DBCONFIG_DEFENSIVE, true)?;
        conn.execute_batch("PRAGMA query_only = ON; PRAGMA trusted_schema = OFF;")?;
        let highest: i64 = conn.query_row(
            "SELECT COALESCE(MAX(restore_epoch), 0) FROM ferret_vaults",
            [],
            |row| row.get(0),
        )?;
        Ok(u64::try_from(highest).unwrap_or(0))
    };
    let as_it_is = Connection::open_with_flags(
        &db,
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .and_then(read);
    let found = as_it_is.ok().or_else(|| {
        let uri = set::immutable_uri(&db).ok()?;
        Connection::open_with_flags(
            uri,
            OpenFlags::SQLITE_OPEN_READ_ONLY
                | OpenFlags::SQLITE_OPEN_URI
                | OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )
        .and_then(read)
        .ok()
    });
    if found.is_none() {
        tracing::warn!("the restore epoch of the database in the data directory could not be read");
    }
    found
}

// ---------------------------------------------------------------------------
// Files and folders
// ---------------------------------------------------------------------------

/// The files of the live data, which move together: the database with its
/// WAL, shared memory and rollback journal, and the three secret files.
fn live_files() -> Vec<String> {
    let mut names = vec![DB_FILE.to_string()];
    names.extend(journal_files());
    names.extend(SECRET_FILES.iter().map(|name| (*name).to_string()));
    names
}

/// The files next to a database that belong to it.
fn journal_files() -> [String; 3] {
    [
        format!("{DB_FILE}-wal"),
        format!("{DB_FILE}-shm"),
        format!("{DB_FILE}-journal"),
    ]
}

/// The files that a restore puts in place.
fn placed_files() -> [&'static str; 4] {
    [
        DB_FILE,
        OPAQUE_SETUP_FILE,
        PRELOGIN_SECRET_FILE,
        SESSION_KEY_FILE,
    ]
}

/// The staged and the moved-aside folder names, both free.
fn free_names(data_dir: &Path, now: i64) -> Result<(String, String), BackupError> {
    let base = set::set_name(now);
    for n in 0..1000 {
        let stamp = if n == 0 {
            base.clone()
        } else {
            format!("{base}-{n}")
        };
        let staging = format!("{STAGING_PREFIX}{stamp}");
        let aside = format!("{ASIDE_PREFIX}{stamp}");
        if !there(&data_dir.join(&staging))? && !there(&data_dir.join(&aside))? {
            return Ok((staging, aside));
        }
    }
    Err(BackupError::Io("no free name for the restore folders"))
}

/// Whether a name is one of ours: the prefix and a set name, nothing else (no
/// `/`, no `..`), so a marker that was changed by hand can not send a move
/// somewhere else.
fn our_folder(name: &str, prefix: &str) -> bool {
    name.strip_prefix(prefix)
        .and_then(set::parse_set_name)
        .is_some()
}

fn read_marker(data_dir: &Path) -> Result<Option<Marker>, BackupError> {
    let path = data_dir.join(RESTORE_MARKER);
    let meta = match std::fs::symlink_metadata(&path) {
        Ok(meta) => meta,
        Err(error) if error.kind() == ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(io_err("the restore marker can not be read")(error)),
    };
    if !meta.is_file() || meta.len() > MAX_MARKER {
        return Err(UNREADABLE_MARKER);
    }
    let mut text = Vec::new();
    std::fs::File::open(&path)
        .and_then(|file| file.take(MAX_MARKER + 1).read_to_end(&mut text))
        .map_err(io_err("the restore marker can not be read"))?;
    let marker: Marker = serde_json::from_slice(&text).map_err(|_| UNREADABLE_MARKER)?;
    let fine = marker.format == MARKER_FORMAT
        && RestoreStep::from_name(&marker.step).is_some()
        && our_folder(&marker.staging, STAGING_PREFIX)
        && our_folder(&marker.moved_aside, ASIDE_PREFIX)
        && Path::new(&marker.source).is_absolute();
    if !fine {
        return Err(UNREADABLE_MARKER);
    }
    Ok(Some(marker))
}

/// Writes the marker whole or not at all: a temporary file, synced, renamed
/// over the marker, and the data directory synced.
fn write_marker(data_dir: &Path, marker: &Marker) -> Result<(), BackupError> {
    let json = serde_json::to_vec_pretty(marker)
        .map_err(|_| BackupError::Io("could not write the restore marker"))?;
    let temp = data_dir.join(MARKER_TEMP);
    remove_file_if_there(&temp)?;
    let mut file = new_private_file(&temp).map_err(io_err("could not write the restore marker"))?;
    file.write_all(&json)
        .and_then(|()| file.sync_all())
        .map_err(io_err("could not write the restore marker"))?;
    drop(file);
    rename(&temp, &data_dir.join(RESTORE_MARKER))?;
    sync_dir(data_dir)
}

fn remove_marker(data_dir: &Path) -> Result<(), BackupError> {
    remove_file_if_there(&data_dir.join(MARKER_TEMP))?;
    remove_file_if_there(&data_dir.join(RESTORE_MARKER))?;
    sync_dir(data_dir)
}

/// A new file with mode `0600` from the start. Never replaces a file.
fn new_private_file(path: &Path) -> io::Result<std::fs::File> {
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }
    options.open(path)
}

/// Makes a folder with mode `0700`, or takes one that is there (not a link).
fn make_private_dir(path: &Path) -> Result<(), BackupError> {
    if let Ok(meta) = std::fs::symlink_metadata(path) {
        return if meta.is_dir() {
            Ok(())
        } else {
            Err(BackupError::Refused(
                "a restore folder name is taken by a file",
            ))
        };
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt as _;
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(path)
            .map_err(io_err("could not make a restore folder"))
    }
    #[cfg(not(unix))]
    std::fs::create_dir(path).map_err(io_err("could not make a restore folder"))
}

/// Whether something (a file, a folder, a link) has this name.
fn there(path: &Path) -> Result<bool, BackupError> {
    match std::fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(error) if error.kind() == ErrorKind::NotFound => Ok(false),
        Err(error) => Err(io_err("could not look at the data directory")(error)),
    }
}

fn rename(from: &Path, to: &Path) -> Result<(), BackupError> {
    std::fs::rename(from, to).map_err(io_err("could not move a file"))
}

fn remove_file_if_there(path: &Path) -> Result<(), BackupError> {
    match std::fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == ErrorKind::NotFound => Ok(()),
        Err(error) => Err(io_err("could not remove a file")(error)),
    }
}

/// Removes a folder of ours and what is in it, without following links. Best
/// effort: what is left is only a copy of the set.
fn remove_tree(path: &Path) {
    match std::fs::symlink_metadata(path) {
        Ok(meta) if meta.is_dir() => {
            if let Err(error) = std::fs::remove_dir_all(path) {
                tracing::warn!(kind = ?error.kind(), "could not remove the staged folder");
            }
        }
        Ok(_) => {
            let _ = std::fs::remove_file(path);
        }
        Err(_) => {}
    }
}

fn sync_dir(path: &Path) -> Result<(), BackupError> {
    set::sync_dir_path(path).map_err(io_err("could not sync a folder"))
}

/// Logs the kind of an I/O error (never the message, which may hold a path)
/// and turns it into [`BackupError::Io`] with a fixed text.
fn io_err(what: &'static str) -> impl Fn(io::Error) -> BackupError {
    move |error| {
        tracing::warn!(step = what, kind = ?error.kind(), "restore step failed");
        BackupError::Io(what)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_dir(name: &str) -> PathBuf {
        static NEXT: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
        let dir = std::env::temp_dir().join(format!(
            "ferret-restore-{name}-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("a directory");
        dir
    }

    #[test]
    fn the_marker_refuses_and_its_absence_does_not() {
        let dir = temp_dir("marker");
        assert!(refuse_if_in_progress(&dir).is_ok());
        std::fs::write(dir.join(RESTORE_MARKER), "{}").expect("the marker");
        let err = refuse_if_in_progress(&dir).expect_err("a restore is in progress");
        assert!(err.to_string().contains(RESTORE_MARKER), "{err}");
        assert!(err.to_string().contains("--abort"), "{err}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_marker_that_is_a_folder_refuses_too() {
        let dir = temp_dir("folder");
        std::fs::create_dir(dir.join(RESTORE_MARKER)).expect("a folder");
        assert!(refuse_if_in_progress(&dir).is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_directory_that_cannot_be_read_refuses_instead_of_going_on() {
        // A "directory" that is a file: the marker cannot be told apart from
        // missing by a lookup, and the answer must not be yes.
        let dir = temp_dir("file");
        let file = dir.join("not-a-directory");
        std::fs::write(&file, b"x").expect("a file");
        assert!(refuse_if_in_progress(&file).is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn the_steps_have_one_name_each_in_order() {
        assert_eq!(RestoreStep::ALL.len(), RESTORE_STEPS.len());
        for (step, name) in RestoreStep::ALL.iter().zip(RESTORE_STEPS) {
            assert_eq!(step.name(), name);
            assert_eq!(RestoreStep::from_name(name), Some(*step));
        }
        assert!(RestoreStep::ALL.windows(2).all(|pair| pair[0] < pair[1]));
        assert_eq!(RestoreStep::Marker.next(), Some(RestoreStep::Staged));
        assert_eq!(RestoreStep::Placed.next(), None);
        assert_eq!(RestoreStep::from_name("finished"), None);
    }

    fn marker(at_least: Option<u64>, seen_epoch: u64) -> Marker {
        Marker {
            format: MARKER_FORMAT.to_string(),
            step: "bumped".to_string(),
            source: "/srv/backups/20261120T010000Z".to_string(),
            staging: ".restore-20261120T020000Z".to_string(),
            moved_aside: "pre-restore-20261120T020000Z".to_string(),
            started_at: 1,
            at_least,
            seen_epoch,
            seen_epoch_unknown: false,
            done: None,
            undoing: false,
        }
    }

    #[test]
    fn a_marker_with_folders_that_are_not_ours_is_not_read() {
        let dir = temp_dir("names");
        let good = marker(None, 0);
        write_marker(&dir, &good).expect("a marker");
        assert!(read_marker(&dir).expect("readable").is_some());
        for bad in [
            Marker {
                staging: "../elsewhere".to_string(),
                ..good.clone()
            },
            Marker {
                moved_aside: "pre-restore-20261120T020000Z/../../x".to_string(),
                ..good.clone()
            },
            Marker {
                step: "done".to_string(),
                ..good.clone()
            },
            Marker {
                format: "ferret-restore/2".to_string(),
                ..good.clone()
            },
            Marker {
                source: "relative/set".to_string(),
                ..good.clone()
            },
        ] {
            write_marker(&dir, &bad).expect("a marker");
            assert!(read_marker(&dir).is_err(), "{bad:?}");
        }
        std::fs::write(dir.join(RESTORE_MARKER), b"{\"step\":").expect("a broken marker");
        assert!(read_marker(&dir).is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn the_lowest_epoch_is_one_above_what_was_seen_and_at_least_what_was_asked() {
        assert_eq!(marker(None, 0).lowest_epoch(), None);
        assert_eq!(marker(None, 7).lowest_epoch(), Some(8));
        assert_eq!(marker(Some(20), 7).lowest_epoch(), Some(20));
        assert_eq!(marker(Some(3), 7).lowest_epoch(), Some(8));
    }

    #[test]
    fn a_marker_from_before_the_undo_flag_reads_as_not_undoing() {
        let dir = temp_dir("old-marker");
        let mut json = serde_json::to_value(marker(None, 0)).expect("json");
        let fields = json.as_object_mut().expect("an object");
        fields.remove("undoing");
        fields.remove("seen_epoch_unknown");
        std::fs::write(dir.join(RESTORE_MARKER), json.to_string()).expect("a marker");
        let read = read_marker(&dir).expect("readable").expect("there");
        assert!(!read.undoing && !read.seen_epoch_unknown);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn there_must_be_room_for_twice_the_set() {
        assert!(enough_space(Some(200), 100));
        assert!(!enough_space(Some(199), 100));
        assert!(enough_space(None, 100), "unknown is not a refusal");
        assert!(!enough_space(Some(u64::MAX - 1), u64::MAX), "no wrap");
    }

    #[test]
    fn spaces_are_evened_out_and_nothing_else() {
        assert_eq!(
            even_spaces("CREATE TABLE t (\n  a INTEGER ,\n  b TEXT\n)"),
            "CREATE TABLE t(a INTEGER,b TEXT)"
        );
        assert_eq!(even_spaces("a  b"), "a b");
        assert_ne!(even_spaces("CHECK (a >= 0)"), even_spaces("CHECK (a >= 1)"));
    }
}
