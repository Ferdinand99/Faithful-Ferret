//! What the scheduled backup reports, and the requests for a run.
//!
//! One [`BackupStatus`] is shared by the scheduler, the places that ask for a
//! backup (a change of unlock methods) and the admin panel. It lives in memory
//! and is written to `status.json` in the backup folder after every run, so a
//! restart shows the last good time and the last failure instead of a blank.
//!
//! The status holds no secret and no name: times, counts and fixed codes. The
//! push address of the monitor is never part of it (it lives in
//! [`super::BackupConfig`] and is read only by [`super::push`]).
//!
//! The file is replaced atomically (written beside it, synced, renamed, the
//! folder synced), `0600`, and read back with a size limit. A file that does not
//! parse is ignored with a warning: the status is a convenience, never the
//! truth about the sets (those are read from the folder).

use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, MutexGuard};

use serde::{Deserialize, Serialize};
use tokio::sync::Notify;

/// The reason of a run that the admin panel asked for.
pub const MANUAL_REASON: &str = "manual";

/// A backup is already going on or on its way: [`BackupStatus::request_manual_run`]
/// asked for one too many.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Busy;

/// The name of the status file in the backup folder.
pub const STATUS_FILE: &str = "status.json";

/// The most `status.json` is read as. The file is a few hundred bytes.
const MAX_FILE_BYTES: u64 = 64 * 1024;

/// A failure of the last run.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Failure {
    /// When it failed (Unix seconds).
    pub at: i64,
    /// A fixed code (`no_space`, `io`, `verify`, ...), never a message.
    pub code: String,
}

/// What the last message to the monitor came to.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PushReport {
    /// When it was tried (Unix seconds).
    pub at: i64,
    /// Whether the monitor took it.
    pub ok: bool,
    /// A fixed code when it did not (`timeout`, `connect`, `status`, ...).
    pub code: Option<String>,
}

/// A read of the status for the admin panel and for tests.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct BackupSnapshot {
    /// When the last good set was made (Unix seconds), if one was.
    pub last_good_at: Option<i64>,
    /// The failure of the last run, if the last run failed. A good run clears
    /// it.
    pub last_failure: Option<Failure>,
    /// How many finished sets the folder held after the last run.
    pub sets: u32,
    /// What the last message to the monitor came to, if one was sent.
    pub last_push: Option<PushReport>,
    /// When the next run is due (Unix seconds), if it is known.
    pub next_run_at: Option<i64>,
    /// Whether a run is going on now.
    pub running: bool,
    /// Whether a run that was asked for has not started yet: the request is
    /// waiting to be picked up, or the job is collecting requests (60 seconds).
    pub waiting: bool,
}

/// The coarse state of the backup, for a badge.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum State {
    /// No run has finished since the start and none failed.
    Unknown,
    /// A run is going on.
    Running,
    /// The last run made a good set.
    Ok,
    /// The last run failed (see [`BackupSnapshot::last_failure`]).
    Failed,
}

impl BackupSnapshot {
    /// The coarse state: a run in progress first, then the last result.
    pub fn state(&self) -> State {
        if self.running {
            State::Running
        } else if self.last_failure.is_some() {
            State::Failed
        } else if self.last_good_at.is_some() {
            State::Ok
        } else {
            State::Unknown
        }
    }
}

/// The part of the status that is written to `status.json`.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
struct Saved {
    /// The version of this file.
    v: u32,
    last_good_at: Option<i64>,
    last_failure: Option<Failure>,
    sets: u32,
    last_push: Option<PushReport>,
}

#[derive(Debug, Default)]
struct Inner {
    saved: Saved,
    next_run_at: Option<i64>,
    running: bool,
    /// A request was taken by the job and its run has not started yet.
    waiting: bool,
    /// The reason of the first request that has not been taken yet.
    requested: Option<&'static str>,
}

struct Shared {
    state: Mutex<Inner>,
    /// Held while `status.json` is written, so two writers cannot put an older
    /// snapshot last: the one that writes reads the newest state under it.
    write: Mutex<()>,
    wake: Notify,
    /// Where `status.json` goes; none for a status that is kept in memory only.
    file: Option<PathBuf>,
}

/// What the scheduled backup reports and is asked for. One status for the
/// process, shared by every handle (`Clone` shares it).
#[derive(Clone)]
pub struct BackupStatus {
    shared: Arc<Shared>,
}

impl std::fmt::Debug for BackupStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BackupStatus")
            .field("snapshot", &self.snapshot())
            .finish_non_exhaustive()
    }
}

impl Default for BackupStatus {
    fn default() -> Self {
        Self::new()
    }
}

impl BackupStatus {
    /// A status that has seen no run and writes no file.
    pub fn new() -> Self {
        Self::with(Saved::default(), None)
    }

    /// A status that keeps `status.json` in `dir` and starts from what that
    /// file holds (nothing when it is missing or unreadable).
    pub fn persistent(dir: &Path) -> Self {
        let file = dir.join(STATUS_FILE);
        let saved = read_saved(&file).unwrap_or_default();
        Self::with(saved, Some(file))
    }

    fn with(saved: Saved, file: Option<PathBuf>) -> Self {
        Self {
            shared: Arc::new(Shared {
                state: Mutex::new(Inner {
                    saved,
                    ..Inner::default()
                }),
                write: Mutex::new(()),
                wake: Notify::new(),
                file,
            }),
        }
    }

    fn lock(&self) -> MutexGuard<'_, Inner> {
        // A panic while the lock was held leaves plain data behind: go on.
        self.shared
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Asks for a backup soon, for `reason` (a fixed word, never a value that a
    /// client chose). The scheduler collects the requests that come in the next
    /// 60 seconds into one run ([`super::schedule`]); calls in that time add
    /// nothing. Never blocks and never fails.
    ///
    /// Spec: Fase 1 § 11; a set after every change of unlock methods
    /// holds the newest wraps.
    pub fn request_run(&self, reason: &'static str) {
        {
            let mut inner = self.lock();
            inner.requested.get_or_insert(reason);
        }
        self.shared.wake.notify_one();
    }

    /// Asks for a backup now, for the "Take a backup now" button of the admin
    /// panel: like [`Self::request_run`] with the reason `manual`, but refused
    /// while a run is going on or an earlier request has not been run yet (one
    /// click is one backup; a second click while it is on its way does nothing
    /// but say so). The check and the request are one step, so two clicks at
    /// once cannot both go through.
    ///
    /// # Errors
    ///
    /// [`Busy`] when a run is going on or a requested run has not started.
    pub fn request_manual_run(&self) -> Result<(), Busy> {
        {
            let mut inner = self.lock();
            if inner.running || inner.waiting || inner.requested.is_some() {
                return Err(Busy);
            }
            inner.requested = Some(MANUAL_REASON);
        }
        self.shared.wake.notify_one();
        Ok(())
    }

    /// Takes the pending request, if there is one (the scheduler's side). Until
    /// the run starts ([`Self::set_running`]) the status says a run is waiting.
    pub fn take_request(&self) -> Option<&'static str> {
        let mut inner = self.lock();
        let taken = inner.requested.take();
        if taken.is_some() {
            inner.waiting = true;
        }
        taken
    }

    /// The job dropped the requests it had collected without running (after a
    /// panic): nothing is waiting any more.
    pub fn clear_waiting(&self) {
        self.lock().waiting = false;
    }

    /// Whether a request is waiting.
    pub fn has_request(&self) -> bool {
        self.lock().requested.is_some()
    }

    /// Resolves when a request comes in (or one was waiting).
    pub async fn requested(&self) {
        self.shared.wake.notified().await;
    }

    /// The status as it is now.
    pub fn snapshot(&self) -> BackupSnapshot {
        let inner = self.lock();
        BackupSnapshot {
            last_good_at: inner.saved.last_good_at,
            last_failure: inner.saved.last_failure.clone(),
            sets: inner.saved.sets,
            last_push: inner.saved.last_push.clone(),
            next_run_at: inner.next_run_at,
            running: inner.running,
            waiting: inner.waiting || inner.requested.is_some(),
        }
    }

    /// A run starts or ends. A run that starts is the one that was waiting.
    pub fn set_running(&self, running: bool) {
        let mut inner = self.lock();
        inner.running = running;
        if running {
            inner.waiting = false;
        }
    }

    /// When the next run is due.
    pub fn set_next_run(&self, at: Option<i64>) {
        self.lock().next_run_at = at;
    }

    /// A run made a good set at `now`; the folder now holds `sets`. Clears the
    /// last failure.
    pub fn record_success(&self, now: i64, sets: u32) {
        {
            let mut inner = self.lock();
            inner.saved.last_good_at = Some(now);
            inner.saved.last_failure = None;
            inner.saved.sets = sets;
        }
        self.persist();
    }

    /// A run failed at `now` with a fixed `code`. The last good time stays.
    pub fn record_failure(&self, now: i64, code: &str) {
        {
            let mut inner = self.lock();
            inner.saved.last_failure = Some(Failure {
                at: now,
                code: code.to_string(),
            });
        }
        self.persist();
    }

    /// The message to the monitor was tried at `now`: `Ok` or a fixed code.
    pub fn record_push(&self, now: i64, result: Result<(), &str>) {
        {
            let mut inner = self.lock();
            inner.saved.last_push = Some(PushReport {
                at: now,
                ok: result.is_ok(),
                code: result.err().map(str::to_string),
            });
        }
        self.persist();
    }

    /// How many sets the folder holds (after a prune).
    pub fn set_sets(&self, sets: u32) {
        self.lock().saved.sets = sets;
        self.persist();
    }

    /// Writes the newest state to `status.json`. This is blocking file I/O: a
    /// caller on the async runtime calls the `record_*` methods from a blocking
    /// task (the job does).
    fn persist(&self) {
        let Some(file) = &self.shared.file else {
            return;
        };
        let _writer = self
            .shared
            .write
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let mut saved = self.lock().saved.clone();
        saved.v = 1;
        if let Err(error) = write_saved(file, &saved) {
            // The status is a convenience: a run that made a good set is good.
            tracing::warn!(kind = ?error.kind(), "could not write the backup status file");
        }
    }
}

/// Reads `status.json`: at most [`MAX_FILE_BYTES`], and only a regular file.
fn read_saved(file: &Path) -> Option<Saved> {
    use std::io::Read as _;
    let meta = std::fs::symlink_metadata(file).ok()?;
    if !meta.is_file() || meta.len() > MAX_FILE_BYTES {
        return None;
    }
    let mut bytes = Vec::new();
    std::fs::File::open(file)
        .ok()?
        .take(MAX_FILE_BYTES)
        .read_to_end(&mut bytes)
        .ok()?;
    match serde_json::from_slice::<Saved>(&bytes) {
        Ok(saved) => Some(saved),
        Err(_) => {
            tracing::warn!("the backup status file did not parse and is ignored");
            None
        }
    }
}

/// Replaces `file` atomically: written beside it, synced, renamed over it, and
/// the folder synced. `0600`.
fn write_saved(file: &Path, saved: &Saved) -> std::io::Result<()> {
    let dir = file.parent().unwrap_or_else(|| Path::new("."));
    super::set::ensure_private_dir(dir)?;
    let temp = file.with_extension("json.tmp");
    let _ = std::fs::remove_file(&temp);
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }
    let mut out = options.open(&temp)?;
    let bytes = serde_json::to_vec_pretty(saved).map_err(std::io::Error::other)?;
    let written = out.write_all(&bytes).and_then(|()| out.sync_all());
    drop(out);
    if let Err(error) = written.and_then(|()| std::fs::rename(&temp, file)) {
        let _ = std::fs::remove_file(&temp);
        return Err(error);
    }
    super::set::sync_dir_path(dir)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_status_that_saw_nothing_is_unknown() {
        let status = BackupStatus::new();
        let snap = status.snapshot();
        assert_eq!(snap.state(), State::Unknown);
        assert_eq!(snap, BackupSnapshot::default());
    }

    #[test]
    fn requests_collapse_into_one_that_is_taken_once() {
        let status = BackupStatus::new();
        assert!(!status.has_request());
        status.request_run("unlock_methods");
        status.request_run("other");
        assert!(status.has_request());
        assert_eq!(status.take_request(), Some("unlock_methods"));
        assert_eq!(status.take_request(), None);
    }

    #[test]
    fn a_manual_request_is_refused_while_one_is_on_its_way_or_running() {
        let status = BackupStatus::new();
        assert_eq!(status.request_manual_run(), Ok(()));
        // Asked for, not yet taken.
        assert_eq!(status.request_manual_run(), Err(Busy));
        // Taken by the job, collecting.
        assert_eq!(status.take_request(), Some(MANUAL_REASON));
        assert!(status.snapshot().waiting);
        assert_eq!(status.request_manual_run(), Err(Busy));
        // Running.
        status.set_running(true);
        assert!(!status.snapshot().waiting);
        assert_eq!(status.request_manual_run(), Err(Busy));
        // Done: a new request goes through again.
        status.set_running(false);
        assert_eq!(status.request_manual_run(), Ok(()));
    }

    #[test]
    fn success_clears_the_failure_and_failure_keeps_the_good_time() {
        let status = BackupStatus::new();
        status.record_success(10, 2);
        status.record_failure(20, "no_space");
        let snap = status.snapshot();
        assert_eq!(snap.last_good_at, Some(10));
        assert_eq!(snap.state(), State::Failed);
        status.record_success(30, 3);
        let snap = status.snapshot();
        assert_eq!(snap.state(), State::Ok);
        assert_eq!(snap.last_failure, None);
        assert_eq!(snap.sets, 3);
        status.set_running(true);
        assert_eq!(status.snapshot().state(), State::Running);
    }
}
