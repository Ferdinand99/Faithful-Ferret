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

use super::set::{self, Platform};
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
        self.status.set_running(true);
        let result = self.make_set(now).await;
        match &result {
            Ok(info) => {
                let sets = self.prune_and_count(now).await;
                self.status.record_success(now, sets);
                tracing::info!(set = %info.name, sets, "backup set made");
                self.tell_monitor(now).await;
            }
            Err(error) => {
                self.status.record_failure(now, error.code());
                tracing::warn!(code = error.code(), "backup failed");
            }
        }
        self.status.set_running(false);
        result
    }

    async fn make_set(&self, now: i64) -> Result<SetInfo, BackupError> {
        let (data_dir, cfg, platform) = (
            self.data_dir.clone(),
            self.cfg.clone(),
            self.platform.clone(),
        );
        self.db
            .with_conn(move |conn| {
                Ok(set::create_with(
                    &data_dir,
                    conn,
                    &cfg,
                    now,
                    platform.as_ref(),
                ))
            })
            .await
            .map_err(|_| BackupError::Io("could not use the database"))?
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
        self.status.record_push(now, result);
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
/// the message to the monitor.
pub fn spawn(
    db: VaultDb,
    data_dir: PathBuf,
    cfg: BackupConfig,
    status: BackupStatus,
    clock: Arc<dyn Clock>,
    http: reqwest::Client,
) {
    let mut job = Job::new(db, data_dir, cfg, status.clone(), clock, http);
    tokio::spawn(async move {
        loop {
            job.poll().await;
            tokio::select! {
                () = tokio::time::sleep(POLL) => {}
                () = status.requested() => {}
            }
        }
    });
}
