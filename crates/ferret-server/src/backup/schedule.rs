//! The job that makes a set on a timer and when it is asked to.
//!
//! [`spawn`] has its final signature; until the scheduler is built it starts
//! nothing.

use std::path::PathBuf;
use std::sync::Arc;

use ferret_server_auth::Clock;

use super::BackupConfig;
use crate::state::{BackupStatus, VaultDb};

/// Starts the backup job: a set every `cfg.every` (the first one shortly after
/// start), one soon after a change of unlock methods is asked for through
/// `status`, and the report of each run into `status`. `http` is the client
/// for the message to the monitor.
pub fn spawn(
    db: VaultDb,
    data_dir: PathBuf,
    cfg: BackupConfig,
    status: BackupStatus,
    clock: Arc<dyn Clock>,
    http: reqwest::Client,
) {
    let _ = (db, data_dir, cfg, status, clock, http);
}
