//! Retention: how long tombstones and idempotency records are kept, and the
//! background job that removes the older ones. Spec: Fase 1 § 8.4.
//!
//! * A tombstone is kept for 400 days. Removing one raises the feed floor of its
//!   vault (`min_valid_since`), so a client that has not been seen since then
//!   gets `410` and lists the vault again (`reconcile`).
//! * An idempotency record is kept for 30 days, and for one device only the
//!   newest 1 000 of them stay.
//!
//! The job works one vault at a time, and one device at a time inside a vault,
//! each in a short transaction of its own: it uses the indexes of migration
//! 0005 (`vault_id, deleted, changed_at` and `vault_id, device_id, created_at`)
//! and never holds the write lock for the whole database.
//!
//! The job runs 10 minutes after the server starts and then every 24 hours. It
//! reads the time from the injected clock, and a clock that cannot tell the time
//! (`u64::MAX`) makes it do nothing: taking that for "now" would purge every
//! tombstone.

use std::sync::Arc;
use std::time::Duration;

use ferret_server_auth::Clock;
use rusqlite::{Connection, TransactionBehavior, params};

use super::store;
use crate::error::StoreError;
use crate::ids::{DeviceId, VaultId};
use crate::state::VaultDb;

/// Days a tombstone is kept before it may be purged.
pub const TOMBSTONE_DAYS: i64 = 400;

/// Days an idempotency record is kept.
pub const IDEM_DAYS: i64 = 30;

/// Idempotency records kept for one device at most.
pub const IDEM_PER_DEVICE: u32 = 1_000;

/// Seconds in a day.
const DAY: i64 = 86_400;

/// Seconds a tombstone is kept.
pub const TOMBSTONE_SECS: i64 = TOMBSTONE_DAYS * DAY;

/// Seconds an idempotency record is kept.
pub const IDEM_SECS: i64 = IDEM_DAYS * DAY;

/// Seconds from the start of the server to the first pass.
pub const FIRST_RUN_AFTER: i64 = 10 * 60;

/// Seconds between two passes.
pub const RUN_EVERY: i64 = DAY;

/// Seconds to wait before another try after a pass that failed.
const RETRY_AFTER: i64 = 10 * 60;

/// How often the job looks at the clock.
const POLL: Duration = Duration::from_secs(30);

/// What one pass of the job did.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct RetentionReport {
    /// Vaults looked at.
    pub vaults: u64,
    /// Tombstones removed.
    pub tombstones_removed: u64,
    /// Idempotency records removed.
    pub idem_removed: u64,
}

/// One pass over every vault at time `now` (Unix seconds): the tombstones last
/// written more than 400 days ago go, then the idempotency records older than 30
/// days and, per device, those beyond the newest 1 000.
///
/// Spec: Fase 1 § 8.4 (retention of 400 days).
pub fn run_once(conn: &mut Connection, now: i64) -> Result<RetentionReport, StoreError> {
    let tombstones_before = now.saturating_sub(TOMBSTONE_SECS);
    let idem_before = now.saturating_sub(IDEM_SECS);
    let mut report = RetentionReport::default();

    let vaults: Vec<VaultId> = {
        let mut stmt = conn.prepare("SELECT vault_id FROM ferret_vaults ORDER BY vault_id")?;
        let rows = stmt.query_map([], |row| {
            let bytes: Vec<u8> = row.get(0)?;
            <[u8; 16]>::try_from(bytes.as_slice())
                .map(VaultId::from_bytes)
                .map_err(|e| {
                    rusqlite::Error::FromSqlConversionFailure(
                        0,
                        rusqlite::types::Type::Blob,
                        Box::new(e),
                    )
                })
        })?;
        rows.collect::<Result<_, _>>()?
    };

    for vault in vaults {
        report.vaults = report.vaults.saturating_add(1);
        if has_tombstones_before(conn, &vault, tombstones_before)? {
            let purged = store::purge_tombstones(conn, &vault, tombstones_before)?;
            report.tombstones_removed = report.tombstones_removed.saturating_add(purged.removed);
        }
        for device in idem_devices(conn, &vault)? {
            let removed = purge_idem_of_device(conn, &vault, &device, idem_before)?;
            report.idem_removed = report.idem_removed.saturating_add(removed);
        }
    }
    Ok(report)
}

/// Whether the vault has a tombstone last written before `before`: a read on the
/// index, so a vault with nothing to purge takes no write lock.
fn has_tombstones_before(
    conn: &Connection,
    vault: &VaultId,
    before: i64,
) -> Result<bool, StoreError> {
    Ok(conn.query_row(
        SQL_TOMBSTONES_BEFORE,
        params![vault.as_bytes(), before],
        |row| row.get(0),
    )?)
}

/// Whether a vault has a tombstone last written before `?2`. Uses
/// `ferret_items_tombstones (vault_id, deleted, changed_at)`.
const SQL_TOMBSTONES_BEFORE: &str = "SELECT EXISTS(SELECT 1 FROM ferret_items \
     WHERE vault_id = ?1 AND deleted = 1 AND changed_at < ?2)";

/// The devices of a vault that have records. Uses
/// `ferret_idem_by_device_time (vault_id, device_id, created_at)`.
const SQL_DEVICES: &str = "SELECT DISTINCT device_id FROM ferret_idem WHERE vault_id = ?1";

/// The records of one device made before `?3`. Uses the same index.
const SQL_IDEM_OLD: &str =
    "DELETE FROM ferret_idem WHERE vault_id = ?1 AND device_id = ?2 AND created_at < ?3";

/// The records of one device beyond the newest `?3`; the records of one second
/// are ordered by `idem`. Uses the same index.
const SQL_IDEM_SURPLUS: &str = "DELETE FROM ferret_idem \
     WHERE vault_id = ?1 AND device_id = ?2 AND idem IN ( \
       SELECT idem FROM ferret_idem WHERE vault_id = ?1 AND device_id = ?2 \
       ORDER BY created_at DESC, idem DESC LIMIT -1 OFFSET ?3)";

/// The devices of a vault that have idempotency records.
fn idem_devices(conn: &Connection, vault: &VaultId) -> Result<Vec<DeviceId>, StoreError> {
    let mut stmt = conn.prepare(SQL_DEVICES)?;
    let rows = stmt.query_map([vault.as_bytes()], |row| {
        let bytes: Vec<u8> = row.get(0)?;
        <[u8; 16]>::try_from(bytes.as_slice())
            .map(DeviceId)
            .map_err(|e| {
                rusqlite::Error::FromSqlConversionFailure(
                    0,
                    rusqlite::types::Type::Blob,
                    Box::new(e),
                )
            })
    })?;
    Ok(rows.collect::<Result<_, _>>()?)
}

/// Removes the records of one device that were made before `before`, and then
/// every record beyond the newest [`IDEM_PER_DEVICE`]. Returns how many went.
///
/// Both statements run on `(vault_id, device_id, created_at)`. The records of
/// one second are ordered by their `idem`, so which of them stay is the same
/// every time.
fn purge_idem_of_device(
    conn: &mut Connection,
    vault: &VaultId,
    device: &DeviceId,
    before: i64,
) -> Result<u64, StoreError> {
    let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let old = tx.execute(SQL_IDEM_OLD, params![vault.as_bytes(), device.0, before])?;
    let surplus = tx.execute(
        SQL_IDEM_SURPLUS,
        params![vault.as_bytes(), device.0, IDEM_PER_DEVICE],
    )?;
    tx.commit()?;
    Ok(u64::try_from(old.saturating_add(surplus)).unwrap_or(u64::MAX))
}

/// When the job runs next: 10 minutes after `started_at` while it has not run,
/// then 24 hours after the last run. Unix seconds.
pub fn next_run(started_at: i64, last_run: Option<i64>) -> i64 {
    match last_run {
        None => started_at.saturating_add(FIRST_RUN_AFTER),
        Some(last) => last.saturating_add(RUN_EVERY),
    }
}

/// The time of the clock as the job counts it, or `None` when the clock cannot
/// tell the time (it reads `u64::MAX`) or reads something no database holds.
fn seconds(clock: &dyn Clock) -> Option<i64> {
    match clock.now_unix() {
        u64::MAX => None,
        now => i64::try_from(now).ok(),
    }
}

/// The schedule of the job: when it started and when it runs next.
#[derive(Clone, Copy, Debug)]
pub struct Job {
    started_at: Option<i64>,
    next: Option<i64>,
}

impl Job {
    /// A job that starts now, by `clock`. A clock that cannot tell the time
    /// starts the schedule at the first reading that can be trusted.
    pub fn new(clock: &dyn Clock) -> Self {
        let started_at = seconds(clock);
        Self {
            started_at,
            next: started_at.map(|at| next_run(at, None)),
        }
    }

    /// Looks at the clock and runs a pass if one is due. Returns what the pass
    /// did. A pass that fails is logged and tried again in 10 minutes.
    pub async fn poll(&mut self, db: &VaultDb, clock: &dyn Clock) -> Option<RetentionReport> {
        let now = seconds(clock)?;
        let started_at = *self.started_at.get_or_insert(now);
        let next = *self.next.get_or_insert_with(|| next_run(started_at, None));
        if now < next {
            return None;
        }
        match db.with_conn(move |conn| run_once(conn, now)).await {
            Ok(report) => {
                self.next = Some(next_run(started_at, Some(now)));
                Some(report)
            }
            Err(error) => {
                tracing::warn!(%error, "retention pass failed");
                self.next = Some(now.saturating_add(RETRY_AFTER));
                None
            }
        }
    }
}

/// Starts the job in the background: a pass 10 minutes after start and then
/// every 24 hours. Call it once, inside the runtime.
pub fn spawn(db: VaultDb, clock: Arc<dyn Clock>) {
    tokio::spawn(async move {
        let mut job = Job::new(clock.as_ref());
        loop {
            tokio::time::sleep(POLL).await;
            if let Some(report) = job.poll(&db, clock.as_ref()).await {
                tracing::info!(
                    vaults = report.vaults,
                    tombstones_removed = report.tombstones_removed,
                    idem_removed = report.idem_removed,
                    "retention pass"
                );
            }
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_constants_are_the_documented_ones() {
        assert_eq!(TOMBSTONE_DAYS, 400);
        assert_eq!(IDEM_DAYS, 30);
        assert_eq!(IDEM_PER_DEVICE, 1_000);
        assert_eq!(TOMBSTONE_SECS, 34_560_000);
        assert_eq!(IDEM_SECS, 2_592_000);
    }

    /// The `detail` column of `EXPLAIN QUERY PLAN` for `sql`, all parameters
    /// bound to a blob or a number as the statement needs.
    fn plan(conn: &Connection, sql: &str, params: &[&dyn rusqlite::ToSql]) -> String {
        let mut stmt = conn
            .prepare(&format!("EXPLAIN QUERY PLAN {sql}"))
            .expect("prepare");
        let rows = stmt
            .query_map(params, |row| row.get::<_, String>(3))
            .expect("plan");
        rows.map(|r| r.expect("a plan row"))
            .collect::<Vec<_>>()
            .join(" | ")
    }

    #[test]
    fn every_statement_of_the_job_uses_the_indexes_of_migration_0005() {
        crate::product::install();
        let mut conn = Connection::open_in_memory().expect("open");
        vole_kit::db::migrate::apply_migrations(&mut conn).expect("migrations");
        let vault = [1u8; 16];
        let device = [2u8; 16];
        let tombstones = plan(&conn, SQL_TOMBSTONES_BEFORE, &[&vault, &1_i64]);
        assert!(
            tombstones.contains("ferret_items_tombstones"),
            "{tombstones}"
        );
        let devices = plan(&conn, SQL_DEVICES, &[&vault]);
        assert!(devices.contains("ferret_idem_by_device_time"), "{devices}");
        let old = plan(&conn, SQL_IDEM_OLD, &[&vault, &device, &1_i64]);
        assert!(old.contains("ferret_idem_by_device_time"), "{old}");
        let surplus = plan(&conn, SQL_IDEM_SURPLUS, &[&vault, &device, &1_i64]);
        assert!(surplus.contains("ferret_idem_by_device_time"), "{surplus}");
        assert!(!surplus.contains("SCAN ferret_idem "), "{surplus}");
    }

    #[test]
    fn next_run_arithmetic_saturates() {
        assert_eq!(next_run(i64::MAX, None), i64::MAX);
        assert_eq!(next_run(0, Some(i64::MAX)), i64::MAX);
    }
}
