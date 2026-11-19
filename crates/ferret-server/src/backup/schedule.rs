//! The job that makes a set on a timer and when it is asked to.
//!
//! * The first set is made 15 minutes after the job starts, then one every
//!   `FERRET_BACKUP_EVERY_HOURS` (24 by default). Spec: Fase 1 § 11.
//! * A change of unlock methods asks for a run
//!   ([`BackupStatus::request_run`]): requests are collected for 60 seconds into
//!   one run, so a burst of changes makes one set that holds the newest wraps.
//! * One run at a time: the job is one loop, and a request that comes in during
//!   a run waits for its own collection window after it.
//! * A run that fails is tried again after 30 minutes. It never touches the older
//!   sets, so a long failure leaves the last good ones (and [`super::set::prune`]
//!   keeps the three newest good sets whatever their age).
//! * After a good set the old ones are pruned, and the monitor is told
//!   ([`super::push`]). A failed message does not make the set bad; it is
//!   reported in the status.
//!
//! The job reads the time from the injected clock and looks at it every few
//! seconds, so a test moves the clock by hand and calls [`Job::poll`]. A clock
//! that cannot tell the time (`u64::MAX`) makes it do nothing.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use ferret_server_auth::Clock;
use futures_util::FutureExt as _;

use super::set::{self, Loaded, Pending, Platform};
use super::{BackupConfig, BackupError, SetInfo, push};
use crate::secret::SecretUrl;
use crate::state::{BackupStatus, VaultDb};

/// Seconds from the start of the job to the first set.
pub const FIRST_RUN_AFTER: i64 = 15 * 60;

/// Seconds a request waits for others before the run starts.
pub const COLLECT_FOR: i64 = 60;

/// Seconds to wait before another try after a run that failed.
pub const RETRY_AFTER: i64 = 30 * 60;

/// How often the job looks at the clock.
const POLL: Duration = Duration::from_secs(5);

/// The time of the clock as the job counts it, or `None` when the clock cannot
/// tell the time (it reads `u64::MAX`) or reads something no database holds.
fn seconds(clock: &dyn Clock) -> Option<i64> {
    match clock.now_unix() {
        u64::MAX => None,
        now => i64::try_from(now).ok(),
    }
}

/// The schedule of the backup job and what it needs to make a set.
pub struct Job {
    db: VaultDb,
    data_dir: PathBuf,
    cfg: BackupConfig,
    status: BackupStatus,
    clock: Arc<dyn Clock>,
    http: reqwest::Client,
    platform: Arc<dyn Platform>,
    loaded: Option<Arc<Loaded>>,
    started_at: Option<i64>,
    next_scheduled: Option<i64>,
    request_due: Option<i64>,
}

impl Job {
    /// A job that starts now, by `clock`.
    pub fn new(
        db: VaultDb,
        data_dir: PathBuf,
        cfg: BackupConfig,
        status: BackupStatus,
        clock: Arc<dyn Clock>,
        http: reqwest::Client,
    ) -> Self {
        let started_at = seconds(clock.as_ref());
        Self {
            db,
            data_dir,
            cfg,
            status,
            clock,
            http,
            platform: set::real_platform(),
            loaded: None,
            started_at,
            next_scheduled: started_at.map(|at| at.saturating_add(FIRST_RUN_AFTER)),
            request_due: None,
        }
    }

    /// The same job on another machine layer (a test's fsync spy or a disk
    /// that is full).
    #[must_use]
    pub fn with_platform(mut self, platform: Arc<dyn Platform>) -> Self {
        self.platform = platform;
        self
    }

    /// The secrets the server has loaded: a set is made only from files on disk
    /// that are the same.
    #[must_use]
    pub fn with_loaded(mut self, loaded: Arc<Loaded>) -> Self {
        self.loaded = Some(loaded);
        self
    }

    /// After a panic in a run: waits before the next try, so that a run that
    /// panics every time does not run every few seconds.
    pub fn after_panic(&mut self) {
        let now = seconds(self.clock.as_ref()).unwrap_or(0);
        self.request_due = None;
        self.next_scheduled = Some(now.saturating_add(RETRY_AFTER));
    }

    /// Looks at the clock and the requests and makes a set if one is due.
    /// Returns what the run did, or `None` when nothing was due.
    pub async fn poll(&mut self) -> Option<Result<SetInfo, BackupError>> {
        let now = seconds(self.clock.as_ref())?;
        let started_at = *self.started_at.get_or_insert(now);
        let next = *self
            .next_scheduled
            .get_or_insert(started_at.saturating_add(FIRST_RUN_AFTER));
        // The requests of the window are one: a request that comes in while one
        // is collecting adds nothing.
        if self.status.take_request().is_some() {
            self.request_due
                .get_or_insert(now.saturating_add(COLLECT_FOR));
        }
        let soonest = self.request_due.map_or(next, |due| due.min(next));
        self.status.set_next_run(Some(soonest));
        if now < soonest {
            return None;
        }
        self.request_due = None;

        let result = self.run(now).await;
        let after = seconds(self.clock.as_ref()).unwrap_or(now);
        let wait = match &result {
            Ok(_) => i64::try_from(self.cfg.every.as_secs()).unwrap_or(i64::MAX),
            Err(_) => RETRY_AFTER,
        };
        let next = after.saturating_add(wait);
        self.next_scheduled = Some(next);
        self.status.set_next_run(Some(next));
        Some(result)
    }

    /// One run: the set, then (if it is good) the prune and the message.
    async fn run(&self, now: i64) -> Result<SetInfo, BackupError> {
        // The guard clears `running` however this function ends, a panic or a
        // dropped future included.
        let _running = Running::start(&self.status);
        let result = self.make_set(now).await;
        match &result {
            Ok(info) => {
                let sets = self.prune_and_count(now).await;
                self.record(move |status| status.record_success(now, sets))
                    .await;
                tracing::info!(set = %info.name, sets, "backup set made");
                self.tell_monitor(now).await;
            }
            Err(error) => {
                let code = error.code();
                self.record(move |status| status.record_failure(now, code))
                    .await;
                tracing::warn!(code, "backup failed");
            }
        }
        result
    }

    /// Writes into the status from a blocking thread: the status file is
    /// written and synced there.
    async fn record(&self, change: impl FnOnce(&BackupStatus) + Send + 'static) {
        let status = self.status.clone();
        let _ = tokio::task::spawn_blocking(move || change(&status)).await;
    }

    /// The set in three steps (see [`Pending`]): the checks and the files on a
    /// blocking thread, the copy of the database on a pooled connection that is
    /// let go at once, the rest on a blocking thread again.
    async fn make_set(&self, now: i64) -> Result<SetInfo, BackupError> {
        const STOPPED: BackupError = BackupError::Io("a backup task stopped");
        let (data_dir, cfg, platform, loaded) = (
            self.data_dir.clone(),
            self.cfg.clone(),
            self.platform.clone(),
            self.loaded.clone(),
        );
        let pending = tokio::task::spawn_blocking(move || {
            Pending::begin(&data_dir, &cfg, now, platform.as_ref(), loaded.as_deref())
        })
        .await
        .map_err(|_| STOPPED)??;
        let (pending, copied) = self
            .db
            .with_conn(move |conn| {
                let copied = pending.copy_database(conn);
                Ok((pending, copied))
            })
            .await
            .map_err(|_| BackupError::Io("could not use the database"))?;
        copied?;
        let platform = self.platform.clone();
        tokio::task::spawn_blocking(move || pending.finish(platform.as_ref()))
            .await
            .map_err(|_| STOPPED)?
    }

    /// Removes the old sets and returns how many sets are left. A failure here
    /// is logged, not a failure of the run: the new set is good.
    async fn prune_and_count(&self, now: i64) -> u32 {
        let cfg = self.cfg.clone();
        let done = tokio::task::spawn_blocking(move || {
            if let Err(error) = set::prune(&cfg, now) {
                tracing::warn!(code = error.code(), "pruning the backup sets failed");
            }
            set::list(&cfg).map(|sets| u32::try_from(sets.len()).unwrap_or(u32::MAX))
        })
        .await;
        done.ok().and_then(Result::ok).unwrap_or(0)
    }

    /// Tells the monitor, if there is one. The answer goes in the status as a
    /// fixed code; nothing here logs or keeps the address.
    async fn tell_monitor(&self, now: i64) {
        let Some(address) = &self.cfg.push_url else {
            return;
        };
        let result = send_message(&self.http, address).await;
        if let Err(code) = result {
            tracing::warn!(code, "the backup message to the monitor failed");
        }
        self.record(move |status| status.record_push(now, result))
            .await;
    }
}

/// Sets the status to running for as long as it lives.
struct Running<'a>(&'a BackupStatus);

impl<'a> Running<'a> {
    fn start(status: &'a BackupStatus) -> Self {
        status.set_running(true);
        Self(status)
    }
}

impl Drop for Running<'_> {
    fn drop(&mut self) {
        self.0.set_running(false);
    }
}

async fn send_message(http: &reqwest::Client, address: &SecretUrl) -> Result<(), &'static str> {
    push::send(http, address)
        .await
        .map_err(push::PushError::code)
}

/// Starts the backup job: a set every `cfg.every` (the first one 15 minutes
/// after start), one soon after a change of unlock methods is asked for through
/// `status`, and the report of each run into `status`. `http` is the client for
/// the message to the monitor ([`push::client`]), `loaded` the secrets the
/// server runs with.
pub fn spawn(
    db: VaultDb,
    data_dir: PathBuf,
    cfg: BackupConfig,
    status: BackupStatus,
    clock: Arc<dyn Clock>,
    http: reqwest::Client,
    loaded: Loaded,
) {
    let mut job =
        Job::new(db, data_dir, cfg, status.clone(), clock, http).with_loaded(Arc::new(loaded));
    tokio::spawn(async move {
        loop {
            // A panic in a run (a release build aborts instead) is logged and
            // the job waits and goes on.
            let polled = std::panic::AssertUnwindSafe(job.poll())
                .catch_unwind()
                .await;
            if polled.is_err() {
                tracing::error!("the backup job panicked; it tries again later");
                job.after_panic();
            }
            tokio::select! {
                () = tokio::time::sleep(POLL) => {}
                () = status.requested() => {}
            }
        }
    });
}
