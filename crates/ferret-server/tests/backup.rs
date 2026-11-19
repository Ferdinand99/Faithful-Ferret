//! The backup set, its check, its keeping, the schedule, the request for a run
//! after a change, the message to the monitor and the commands.
//!
//! Spec: Fase 1 § 11. The set also holds `prelogin_secret` and `session.key`,
//! which the spec text does not name.

mod support;

use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use ferret_server::backup::schedule::{COLLECT_FOR, FIRST_RUN_AFTER, RETRY_AFTER};
use ferret_server::backup::set::{self, build_migrations};
use ferret_server::backup::status::{BackupStatus, State};
use ferret_server::backup::{BackupConfig, BackupError, Manifest, SET_FORMAT, push};
use ferret_server::cli::{self, Command};
use ferret_server::data_lock;
use ferret_server::secret::SecretUrl;
use rusqlite::{Connection, OpenFlags, params};
use support::accounts::add_account_to_app;
use support::backup::{
    Event, Reply, SpyPlatform, StandIn, capture_log, cfg, cfg_with_push, closed_port, copy_set,
    entries, job, listed, make,
};
use support::{START, TestApp};

const DAY: i64 = 86_400;
const NOW: i64 = START as i64;

/// A test app with one account, so a vault is in the database.
async fn app_with_vault() -> TestApp {
    let app = TestApp::new().await;
    add_account_to_app(&app, 1).await;
    app
}

fn read_manifest(set_dir: &Path) -> Manifest {
    serde_json::from_slice(&std::fs::read(set_dir.join("MANIFEST.json")).expect("a manifest"))
        .expect("a manifest that parses")
}

/// Opens a database copy of ours read-only and immutable.
fn open_copy(path: &Path) -> Connection {
    Connection::open_with_flags(
        format!("file:{}?immutable=1", path.display()),
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_URI,
    )
    .expect("a copy that opens")
}

fn verify_error(set_dir: &Path) -> String {
    match set::verify(set_dir, &build_migrations()) {
        Err(BackupError::Verify(why)) => why.to_string(),
        other => panic!("expected a failed check, got {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// The set
// ---------------------------------------------------------------------------

#[tokio::test]
async fn a_set_holds_the_database_the_three_secret_files_and_a_manifest() {
    let app = app_with_vault().await;
    let cfg = cfg(&app);
    let info = make(&app, &cfg, NOW).await.expect("a set");
    assert!(info.verified);
    assert_eq!(info.name, "20261101T000000Z");

    let dir = cfg.dir.join(&info.name);
    assert_eq!(
        entries(&dir),
        vec![
            ".complete",
            "MANIFEST.json",
            "ferret.sqlite",
            "opaque_setup",
            "prelogin_secret",
            "session.key"
        ]
    );
    // The secret files are the loaded ones, byte for byte.
    for name in ["opaque_setup", "prelogin_secret", "session.key"] {
        assert_eq!(
            std::fs::read(dir.join(name)).expect("a copy"),
            std::fs::read(app.dir.join(name)).expect("the original"),
            "{name}"
        );
    }
    let manifest = read_manifest(&dir);
    assert_eq!(manifest.format, SET_FORMAT);
    assert_eq!(manifest.created_at, NOW);
    assert_eq!(manifest.files.len(), 4);
    assert_eq!(manifest.vaults.len(), 1);
    assert_eq!(manifest.vaults[0].seq, 1);
    assert_eq!(manifest.vaults[0].restore_epoch, 0);
    for name in build_migrations() {
        assert!(manifest.migrations.iter().any(|m| m == name), "{name}");
    }
    assert_eq!(manifest.setup_fingerprint.len(), 64);
    // The copy is a database with the account in it, and the set passes the check.
    let copy = open_copy(&dir.join("ferret.sqlite"));
    let accounts: i64 = copy
        .query_row("SELECT count(*) FROM ferret_accounts", [], |r| r.get(0))
        .expect("a count");
    assert_eq!(accounts, 1);
    set::verify(&dir, &build_migrations()).expect("a good set");
    // No half-written folder is left.
    assert!(!entries(&cfg.dir).iter().any(|n| n.starts_with(".tmp-")));
}

#[tokio::test]
async fn complete_is_written_inside_the_temp_dir_and_the_set_appears_with_one_rename() {
    let app = app_with_vault().await;
    let cfg = cfg(&app);
    let spy = SpyPlatform::new();
    let platform: Arc<dyn set::Platform> = spy.clone();
    let mut job = job(&app, cfg.clone(), platform);
    app.clock.advance(FIRST_RUN_AFTER as u64);
    job.poll().await.expect("a run").expect("a set");

    let renames: Vec<Event> = spy
        .events()
        .into_iter()
        .filter(|e| matches!(e, Event::Rename { .. }))
        .collect();
    assert_eq!(renames.len(), 1, "one rename: {renames:?}");
    let Event::Rename {
        from,
        to,
        complete_inside,
        target_existed,
    } = &renames[0]
    else {
        unreachable!()
    };
    assert!(
        *complete_inside,
        ".complete is inside the temp folder at the rename"
    );
    assert!(
        !*target_existed,
        "the set name did not exist before the rename"
    );
    assert!(
        from.file_name()
            .expect("a name")
            .to_string_lossy()
            .starts_with(".tmp-"),
        "{from:?}"
    );
    assert_eq!(from.parent(), to.parent());
    assert!(to.join(".complete").is_file());
    assert!(!from.exists());
}

#[tokio::test]
async fn files_and_directories_are_fsynced_before_the_rename() {
    let app = app_with_vault().await;
    let cfg = cfg(&app);
    let spy = SpyPlatform::new();
    let platform: Arc<dyn set::Platform> = spy.clone();
    let mut job = job(&app, cfg.clone(), platform);
    app.clock.advance(FIRST_RUN_AFTER as u64);
    job.poll().await.expect("a run").expect("a set");

    let events = spy.events();
    let position = |wanted: &Event| events.iter().position(|e| e == wanted);
    let rename = events
        .iter()
        .position(|e| matches!(e, Event::Rename { .. }))
        .expect("a rename");
    for name in [
        "ferret.sqlite",
        "opaque_setup",
        "prelogin_secret",
        "session.key",
        "MANIFEST.json",
        ".complete",
    ] {
        let at = position(&Event::SyncFile(name.to_string())).unwrap_or_else(|| panic!("{name}"));
        assert!(at < rename, "{name} is synced before the rename");
    }
    let Event::Rename { from, .. } = &events[rename] else {
        unreachable!()
    };
    let temp_sync = position(&Event::SyncDir(from.clone())).expect("the temp folder is synced");
    assert!(
        temp_sync < rename,
        "the temp folder is synced before the rename"
    );
    let parent_sync = position(&Event::SyncDir(cfg.dir.clone())).expect("the parent is synced");
    assert!(
        parent_sync > rename,
        "the parent is synced after the rename"
    );
}

#[tokio::test]
async fn the_database_copy_is_consistent_while_writes_go_on() {
    let app = app_with_vault().await;
    let cfg = cfg(&app);
    let db_path = app.dir.join("ferret.sqlite");
    let stop = Arc::new(AtomicBool::new(false));
    // Every transaction adds a pair of rows: a copy that is a consistent
    // snapshot never holds one half of a pair.
    let writer = {
        let stop = stop.clone();
        std::thread::spawn(move || {
            let conn = Connection::open(db_path).expect("a connection");
            conn.busy_timeout(Duration::from_secs(10))
                .expect("a timeout");
            let mut i = 0u64;
            while !stop.load(Ordering::SeqCst) {
                conn.execute_batch("BEGIN IMMEDIATE").expect("begin");
                conn.execute(
                    "INSERT INTO ferret_meta (key, value) VALUES (?1, x'01')",
                    params![format!("w_a_{i:06}")],
                )
                .expect("a row");
                conn.execute(
                    "INSERT INTO ferret_meta (key, value) VALUES (?1, x'01')",
                    params![format!("w_b_{i:06}")],
                )
                .expect("a row");
                conn.execute_batch("COMMIT").expect("commit");
                i += 1;
            }
            i
        })
    };
    let mut made = Vec::new();
    for n in 0..4 {
        made.push(make(&app, &cfg, NOW + n).await.expect("a set under writes"));
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    stop.store(true, Ordering::SeqCst);
    let written = writer.join().expect("the writer");
    assert!(written > 0, "the writer got to write");

    for info in made {
        let dir = cfg.dir.join(&info.name);
        set::verify(&dir, &build_migrations()).expect("a good set");
        let copy = open_copy(&dir.join("ferret.sqlite"));
        let count = |prefix: &str| -> i64 {
            copy.query_row(
                "SELECT count(*) FROM ferret_meta WHERE key LIKE ?1",
                [format!("{prefix}%")],
                |r| r.get(0),
            )
            .expect("a count")
        };
        assert_eq!(count("w_a_"), count("w_b_"), "{}", info.name);
    }
}

#[cfg(unix)]
#[tokio::test]
async fn files_are_0600_and_the_set_directory_0700() {
    use std::os::unix::fs::PermissionsExt as _;
    let app = app_with_vault().await;
    let cfg = cfg(&app);
    let info = make(&app, &cfg, NOW).await.expect("a set");
    let mode = |path: &Path| {
        std::fs::metadata(path)
            .expect("metadata")
            .permissions()
            .mode()
            & 0o7777
    };
    let dir = cfg.dir.join(&info.name);
    assert_eq!(mode(&dir), 0o700);
    assert_eq!(mode(&cfg.dir) & 0o077, 0, "the backup folder is private");
    for name in entries(&dir) {
        assert_eq!(mode(&dir.join(&name)), 0o600, "{name}");
    }
    // The status file of a run is private too.
    let status = BackupStatus::persistent(&cfg.dir);
    status.record_success(NOW, 1);
    assert_eq!(mode(&cfg.dir.join("status.json")), 0o600);
}

#[tokio::test]
async fn verify_catches_a_changed_byte_a_missing_file_a_wrong_fingerprint_and_a_newer_migration() {
    let app = app_with_vault().await;
    let cfg = cfg(&app);
    let info = make(&app, &cfg, NOW).await.expect("a set");
    let good = cfg.dir.join(&info.name);
    let scratch = app.dir.join("scratch");
    set::verify(&good, &build_migrations()).expect("a good set");

    // A changed byte in the database.
    let case = scratch.join("flipped");
    copy_set(&good, &case);
    let mut bytes = std::fs::read(case.join("ferret.sqlite")).expect("a database");
    let last = bytes.len() / 2;
    bytes[last] ^= 0x01;
    std::fs::write(case.join("ferret.sqlite"), bytes).expect("a write");
    assert!(
        verify_error(&case).contains("manifest"),
        "{}",
        verify_error(&case)
    );

    // A missing file.
    let case = scratch.join("missing");
    copy_set(&good, &case);
    std::fs::remove_file(case.join("session.key")).expect("a removal");
    assert!(
        verify_error(&case).contains("missing"),
        "{}",
        verify_error(&case)
    );

    // A stray -wal beside the database: refused before the database is opened.
    let case = scratch.join("wal");
    copy_set(&good, &case);
    std::fs::write(case.join("ferret.sqlite-wal"), b"not ours").expect("a write");
    assert!(
        verify_error(&case).contains("should not"),
        "{}",
        verify_error(&case)
    );
    assert!(
        !case.join("ferret.sqlite-shm").exists(),
        "nothing was opened"
    );
    let case = scratch.join("shm");
    copy_set(&good, &case);
    std::fs::write(case.join("ferret.sqlite-shm"), b"not ours").expect("a write");
    assert!(verify_error(&case).contains("should not"));

    // Another OPAQUE set-up, with the manifest brought into line with it: only
    // the fingerprint is wrong.
    let other = TestApp::new().await;
    let case = scratch.join("fingerprint");
    copy_set(&good, &case);
    let foreign = std::fs::read(other.dir.join("opaque_setup")).expect("another set-up");
    assert_ne!(
        foreign,
        std::fs::read(case.join("opaque_setup")).expect("ours")
    );
    std::fs::write(case.join("opaque_setup"), &foreign).expect("a write");
    let mut manifest = read_manifest(&case);
    {
        use sha2::{Digest as _, Sha256};
        let entry = manifest
            .files
            .iter_mut()
            .find(|f| f.name == "opaque_setup")
            .expect("an entry");
        entry.bytes = foreign.len() as u64;
        entry.sha256 = Sha256::digest(&foreign)
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
    }
    std::fs::write(
        case.join("MANIFEST.json"),
        serde_json::to_vec_pretty(&manifest).expect("json"),
    )
    .expect("a write");
    assert!(
        verify_error(&case).contains("fingerprint"),
        "{}",
        verify_error(&case)
    );

    // A newer migration than this build knows.
    let names = build_migrations();
    let older = &names[..names.len() - 1];
    match set::verify(&good, older) {
        Err(BackupError::Verify(why)) => assert!(why.contains("newer build"), "{why}"),
        other => panic!("expected a refusal, got {other:?}"),
    }
}

#[tokio::test]
async fn a_half_written_set_is_never_listed_and_is_cleaned_after_a_day() {
    let app = app_with_vault().await;
    let cfg = cfg(&app);
    let info = make(&app, &cfg, NOW).await.expect("a set");
    let good = cfg.dir.join(&info.name);

    // A temp folder from two days ago and one from an hour ago, each with the
    // files of a set that was never renamed; and a folder with a set's name but
    // no `.complete`.
    let old_temp = cfg
        .dir
        .join(format!(".tmp-{}", set::set_name(NOW - 2 * DAY)));
    let new_temp = cfg.dir.join(format!(".tmp-{}", set::set_name(NOW - 3600)));
    copy_set(&good, &old_temp);
    copy_set(&good, &new_temp);
    let unmarked = cfg.dir.join(set::set_name(NOW - 100));
    copy_set(&good, &unmarked);
    std::fs::remove_file(unmarked.join(".complete")).expect("a removal");

    assert_eq!(
        listed(&cfg),
        vec![info.name.clone()],
        "only the finished set is listed"
    );
    let removed = set::prune(&cfg, NOW).expect("a prune");
    assert_eq!(removed, 0, "no finished set is old");
    assert!(!old_temp.exists(), "the folder from two days ago is gone");
    assert!(
        new_temp.exists(),
        "the folder from an hour ago is left alone"
    );
    assert_eq!(listed(&cfg), vec![info.name]);
}

#[tokio::test]
async fn retention_keeps_30_days_and_always_the_three_newest_good_sets() {
    let app = app_with_vault().await;
    let cfg = cfg(&app);
    let now = NOW + 200 * DAY;
    let mut names = Vec::new();
    for age in [100, 90, 80, 50, 35, 10, 1] {
        let info = make(&app, &cfg, now - age * DAY).await.expect("a set");
        names.push((age, info.name));
    }
    // The set from 50 days ago is damaged: it does not count as good.
    let bad = &names.iter().find(|(age, _)| *age == 50).expect("a set").1;
    let bad_db = cfg.dir.join(bad).join("ferret.sqlite");
    let mut bytes = std::fs::read(&bad_db).expect("a database");
    bytes[100] ^= 0xff;
    std::fs::write(&bad_db, bytes).expect("a write");
    // The cheap listing reads no file content, so a flipped byte passes it; the
    // listing that hashes does not.
    let cheap = set::list(&cfg).expect("a listing");
    assert!(cheap.iter().all(|s| s.verified));
    let listing = set::list_verified(&cfg).expect("a listing");
    assert_eq!(listing.len(), 7);
    assert!(
        !listing
            .iter()
            .find(|s| &s.name == bad)
            .expect("listed")
            .verified
    );

    // Within 30 days: 10 and 1. The three newest good ones: 1, 10 and 35. The
    // rest (100, 90, 80, and the bad 50) go.
    let removed = set::prune(&cfg, now).expect("a prune");
    assert_eq!(removed, 4);
    let kept: Vec<i64> = names
        .iter()
        .filter(|(_, name)| listed(&cfg).contains(name))
        .map(|(age, _)| *age)
        .collect();
    assert_eq!(kept, vec![35, 10, 1]);

    // Long after: the window keeps nothing, and the three newest good stay.
    let removed = set::prune(&cfg, now + 1000 * DAY).expect("a prune");
    assert_eq!(removed, 0);
    assert_eq!(listed(&cfg).len(), 3);

    // A backup folder that holds a database is no backup folder.
    let data_like = BackupConfig {
        dir: app.dir.clone(),
        ..cfg.clone()
    };
    assert!(matches!(
        set::prune(&data_like, now + 5000 * DAY),
        Err(BackupError::Refused(_))
    ));
    assert!(app.dir.join("ferret.sqlite").is_file());
}

#[tokio::test]
async fn a_backup_folder_that_holds_the_data_directory_is_refused_before_anything_is_touched() {
    let app = app_with_vault().await;
    // By its spelling, in the settings.
    assert!(BackupConfig::from_parts(&app.dir, Some(&app.dir), 24, 30, None).is_err());
    let parent = app.dir.parent().expect("a parent").to_path_buf();
    assert!(BackupConfig::from_parts(&app.dir, Some(&parent), 24, 30, None).is_err());
    // Through a link, at the moment of the run.
    #[cfg(unix)]
    {
        let link = std::env::temp_dir().join(format!("ferret-backup-link-{}", std::process::id()));
        let _ = std::fs::remove_file(&link);
        std::os::unix::fs::symlink(&app.dir, &link).expect("a link");
        let cfg = BackupConfig::from_parts(&app.dir, Some(&link), 24, 30, None);
        // The spelling differs, so the settings let it through; the run does not.
        if let Ok(cfg) = cfg {
            assert!(matches!(
                make(&app, &cfg, NOW).await,
                Err(BackupError::Refused(_))
            ));
        }
        let _ = std::fs::remove_file(&link);
    }
    assert!(app.dir.join("ferret.sqlite").is_file());
    assert!(app.dir.join("session.key").is_file());
}

// ---------------------------------------------------------------------------
// Failures
// ---------------------------------------------------------------------------

#[tokio::test]
async fn a_failed_backup_keeps_the_older_sets_and_sets_status_failed() {
    let app = app_with_vault().await;
    let cfg = cfg(&app);
    let spy = SpyPlatform::new();
    let platform: Arc<dyn set::Platform> = spy.clone();
    let mut job = job(&app, cfg.clone(), platform);
    let status = app.backup_status();

    app.clock.advance(FIRST_RUN_AFTER as u64);
    let first = job.poll().await.expect("a run").expect("a set");
    assert_eq!(status.snapshot().state(), State::Ok);
    assert_eq!(status.snapshot().last_good_at, Some(NOW + FIRST_RUN_AFTER));

    spy.fail_rename.store(true, Ordering::SeqCst);
    app.clock.advance(DAY as u64);
    let failed = job.poll().await.expect("a run");
    assert!(matches!(failed, Err(BackupError::Io(_))), "{failed:?}");

    let snap = status.snapshot();
    assert_eq!(snap.state(), State::Failed);
    assert_eq!(snap.last_failure.expect("a failure").code, "io");
    assert_eq!(
        snap.last_good_at,
        Some(NOW + FIRST_RUN_AFTER),
        "the good time stays"
    );
    assert_eq!(listed(&cfg), vec![first.name], "the older set is kept");
    assert!(
        !entries(&cfg.dir).iter().any(|n| n.starts_with(".tmp-")),
        "no half-written folder is left"
    );
    // The next try comes after the retry time, and a good run clears the failure.
    spy.fail_rename.store(false, Ordering::SeqCst);
    app.clock.advance((RETRY_AFTER - 1) as u64);
    assert!(job.poll().await.is_none());
    app.clock.advance(1);
    job.poll().await.expect("a run").expect("a set");
    assert_eq!(status.snapshot().state(), State::Ok);
    assert_eq!(listed(&cfg).len(), 2);
}

#[tokio::test]
async fn low_disk_space_skips_with_no_space() {
    let app = app_with_vault().await;
    let cfg = cfg(&app);
    let spy = SpyPlatform::new();
    let platform: Arc<dyn set::Platform> = spy.clone();
    let mut job = job(&app, cfg.clone(), platform);
    let status = app.backup_status();

    app.clock.advance(FIRST_RUN_AFTER as u64);
    let first = job.poll().await.expect("a run").expect("a set");

    *spy.free.lock().expect("free") = Some(1);
    spy.clear();
    app.clock.advance(DAY as u64);
    let skipped = job.poll().await.expect("a run");
    assert!(matches!(skipped, Err(BackupError::NoSpace)), "{skipped:?}");
    let snap = status.snapshot();
    assert_eq!(snap.state(), State::Failed);
    assert_eq!(snap.last_failure.expect("a failure").code, "no_space");
    assert_eq!(listed(&cfg), vec![first.name], "no set was touched");
    assert!(
        !entries(&cfg.dir).iter().any(|n| n.starts_with(".tmp-")),
        "nothing was started"
    );
    assert!(spy.events().is_empty(), "nothing was written or moved");
}

// ---------------------------------------------------------------------------
// The schedule
// ---------------------------------------------------------------------------

#[tokio::test]
async fn the_schedule_runs_15_minutes_after_start_then_every_24_hours() {
    let app = app_with_vault().await;
    let cfg = cfg(&app);
    let mut job = job(&app, cfg.clone(), Arc::new(set::RealPlatform));

    assert!(job.poll().await.is_none(), "nothing at the start");
    app.clock.advance((FIRST_RUN_AFTER - 1) as u64);
    assert!(
        job.poll().await.is_none(),
        "nothing after 14 minutes 59 seconds"
    );
    assert_eq!(
        app.backup_status().snapshot().next_run_at,
        Some(NOW + FIRST_RUN_AFTER)
    );
    app.clock.advance(1);
    job.poll().await.expect("the first run").expect("a set");
    assert_eq!(listed(&cfg).len(), 1);

    app.clock.advance((DAY - 1) as u64);
    assert!(
        job.poll().await.is_none(),
        "not yet 24 hours after the first set"
    );
    app.clock.advance(1);
    job.poll().await.expect("the second run").expect("a set");
    assert_eq!(listed(&cfg).len(), 2);
    assert_eq!(
        app.backup_status().snapshot().next_run_at,
        Some(NOW + FIRST_RUN_AFTER + 2 * DAY)
    );
}

#[tokio::test]
async fn request_run_after_an_unlock_change_runs_once_within_60_seconds() {
    let app = app_with_vault().await;
    let cfg = cfg(&app);
    let status = app.backup_status();
    let mut job = job(&app, cfg.clone(), Arc::new(set::RealPlatform));

    app.clock.advance(10);
    // A burst of changes.
    status.request_run("unlock_methods");
    status.request_run("unlock_methods");
    assert!(job.poll().await.is_none(), "the window is collecting");
    status.request_run("unlock_methods");
    app.clock.advance((COLLECT_FOR - 1) as u64);
    assert!(job.poll().await.is_none(), "59 seconds in");
    assert_eq!(status.snapshot().next_run_at, Some(NOW + 10 + COLLECT_FOR));
    app.clock.advance(1);
    job.poll().await.expect("one run").expect("a set");
    assert_eq!(listed(&cfg).len(), 1, "one set for the whole burst");
    assert!(!status.has_request());

    // Nothing more is run: the next set is 24 hours after this one.
    app.clock.advance(60);
    assert!(job.poll().await.is_none());

    // A new change starts a new window, and one more set.
    status.request_run("unlock_methods");
    assert!(job.poll().await.is_none());
    app.clock.advance(COLLECT_FOR as u64);
    job.poll().await.expect("a second run").expect("a set");
    assert_eq!(listed(&cfg).len(), 2);
}

// ---------------------------------------------------------------------------
// The message to the monitor
// ---------------------------------------------------------------------------

#[tokio::test]
async fn a_good_set_pushes_once_with_no_name_path_or_secret() {
    let app = app_with_vault().await;
    let monitor = StandIn::start(Reply::Ok).await;
    let cfg = cfg_with_push(
        &app,
        &format!("http://{}/api/push/tokenabc123", monitor.addr),
    );
    let mut job = job(&app, cfg.clone(), Arc::new(set::RealPlatform));
    app.clock.advance(FIRST_RUN_AFTER as u64);
    job.poll().await.expect("a run").expect("a set");

    let requests = monitor.requests();
    assert_eq!(requests.len(), 1, "one message per good set");
    let request = &requests[0];
    assert!(
        request.starts_with("GET /api/push/tokenabc123?status=up&msg=backup+ok HTTP/1.1"),
        "{request}"
    );
    // Nothing of the server is in it.
    let data_dir = app.dir.to_string_lossy().into_owned();
    for forbidden in [
        data_dir.as_str(),
        "ferret.sqlite",
        "opaque_setup",
        "prelogin_secret",
        "session.key",
        "MANIFEST",
    ] {
        assert!(!request.contains(forbidden), "{forbidden} in {request}");
    }
    let snap = app.backup_status().snapshot();
    let push = snap.last_push.clone().expect("a push");
    assert!(push.ok);
    assert_eq!(push.code, None);
    assert_eq!(snap.state(), State::Ok);
}

#[tokio::test]
async fn a_failed_push_leaves_the_set_good_and_shows_in_status() {
    let app = app_with_vault().await;
    // The monitor refuses the connection.
    let cfg = cfg_with_push(
        &app,
        &format!("http://{}/api/push/tokenabc123", closed_port().await),
    );
    let mut refused_job = job(&app, cfg.clone(), Arc::new(set::RealPlatform));
    app.clock.advance(FIRST_RUN_AFTER as u64);
    let info = refused_job
        .poll()
        .await
        .expect("a run")
        .expect("a good set");
    assert!(info.verified);
    let snap = app.backup_status().snapshot();
    assert_eq!(snap.state(), State::Ok, "the set is good");
    assert_eq!(snap.last_failure, None);
    let push = snap.last_push.expect("a push");
    assert!(!push.ok);
    assert_eq!(push.code.as_deref(), Some("connect"));
    assert_eq!(listed(&cfg), vec![info.name]);

    // The monitor answers with an error.
    let monitor = StandIn::start(Reply::Status(500)).await;
    let cfg = cfg_with_push(&app, &format!("http://{}/api/push/tok", monitor.addr));
    let mut error_job = job(&app, cfg.clone(), Arc::new(set::RealPlatform));
    app.clock.advance(DAY as u64);
    error_job.poll().await.expect("a run").expect("a good set");
    let push = app.backup_status().snapshot().last_push.expect("a push");
    assert_eq!((push.ok, push.code.as_deref()), (false, Some("status")));
    assert_eq!(app.backup_status().snapshot().state(), State::Ok);
}

#[tokio::test(start_paused = true)]
async fn a_push_that_never_answers_gives_up_after_ten_seconds() {
    let monitor = StandIn::start(Reply::Hang).await;
    let address = SecretUrl::new(&format!("http://{}/api/push/tok", monitor.addr));
    let started = tokio::time::Instant::now();
    let result = push::send(&push::client().expect("a client"), &address).await;
    assert_eq!(result, Err(push::PushError::Timeout));
    let waited = started.elapsed();
    assert!(
        waited >= push::TIMEOUT && waited < push::TIMEOUT + Duration::from_secs(1),
        "{waited:?}"
    );
    assert_eq!(push::TIMEOUT, Duration::from_secs(10));
}

#[tokio::test]
async fn the_push_url_never_reaches_the_log() {
    let (log, _guard) = capture_log();
    let app = app_with_vault().await;
    // One push that works and one that fails; both addresses hold a secret.
    let monitor = StandIn::start(Reply::Ok).await;
    let secret_ok = "tokenOKsecret987";
    let secret_bad = "tokenBADsecret654";
    let good = cfg_with_push(
        &app,
        &format!("http://{}/api/push/{secret_ok}", monitor.addr),
    );
    let closed = closed_port().await;
    let bad = cfg_with_push(&app, &format!("http://{closed}/api/push/{secret_bad}"));

    let mut job_ok = job(&app, good, Arc::new(set::RealPlatform));
    app.clock.advance(FIRST_RUN_AFTER as u64);
    job_ok.poll().await.expect("a run").expect("a set");
    let mut job_bad = job(&app, bad, Arc::new(set::RealPlatform));
    app.clock.advance(DAY as u64);
    job_bad.poll().await.expect("a run").expect("a set");

    let text = log.text();
    assert!(!text.is_empty(), "the log was captured");
    assert!(
        text.contains("the backup message to the monitor failed"),
        "{text}"
    );
    // The address of the monitor is not secret; its path is.
    assert_no_secret(&text, &[secret_ok, secret_bad]);
    // Nor the status, in memory or on disk.
    let snapshot = format!("{:?}", app.backup_status());
    assert_no_secret(&snapshot, &[secret_ok, secret_bad, &closed.to_string()]);
    let file = std::fs::read_to_string(app.dir.join("backups/auto/status.json")).expect("a file");
    assert_no_secret(&file, &[secret_ok, secret_bad, &closed.to_string()]);
    // Nor the settings when printed.
    assert!(
        !format!("{:?}", cfg_with_push(&app, "http://h.test/p/secretxyz")).contains("secretxyz")
    );
}

fn assert_no_secret(text: &str, needles: &[&str]) {
    for needle in needles {
        assert!(!text.contains(needle), "{needle} found in {text}");
    }
}

#[tokio::test]
async fn backup_never_logs_file_contents() {
    let app = app_with_vault().await;
    let cfg = cfg(&app);
    const CANARY: &str = "CANARY-vault-content-4f9c2a";
    let db_path = app.dir.join("ferret.sqlite");
    {
        let conn = Connection::open(&db_path).expect("a connection");
        conn.execute(
            "INSERT INTO ferret_meta (key, value) VALUES ('canary', ?1)",
            [CANARY.as_bytes()],
        )
        .expect("a row");
    }
    let (log, _guard) = capture_log();
    // On this thread, so the log lines are caught: a set, a listing, a check,
    // a prune, and a run that fails.
    let conn = Connection::open(&db_path).expect("a connection");
    let info = set::create(&app.dir, &conn, &cfg, NOW).expect("a set");
    set::list(&cfg).expect("a listing");
    set::verify(&cfg.dir.join(&info.name), &build_migrations()).expect("a good set");
    set::prune(&cfg, NOW).expect("a prune");
    let hidden = app.dir.join("session.key.hidden");
    std::fs::rename(app.dir.join("session.key"), &hidden).expect("a move");
    let failed = set::create(&app.dir, &conn, &cfg, NOW + 1);
    assert!(failed.is_err());
    std::fs::rename(&hidden, app.dir.join("session.key")).expect("a move back");

    let key_hex: String = std::fs::read(app.dir.join("session.key"))
        .expect("a key")
        .iter()
        .take(16)
        .map(|b| format!("{b:02x}"))
        .collect();
    let text = log.text();
    assert_no_secret(&text, &[CANARY, &key_hex, "opaque_setup"]);
    let error_text = format!("{failed:?}");
    assert_no_secret(&error_text, &[CANARY, &key_hex]);
}

// ---------------------------------------------------------------------------
// The status
// ---------------------------------------------------------------------------

#[tokio::test]
async fn status_survives_a_restart() {
    let dir = std::env::temp_dir().join(format!("ferret-status-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    {
        let status = BackupStatus::persistent(&dir);
        assert_eq!(status.snapshot().state(), State::Unknown);
        status.record_success(NOW, 3);
        status.record_push(NOW + 1, Ok(()));
        status.record_failure(NOW + 2, "no_space");
        status.record_push(NOW + 3, Err("timeout"));
    }
    // A new process: the same folder, a new status.
    let status = BackupStatus::persistent(&dir);
    let snap = status.snapshot();
    assert_eq!(snap.last_good_at, Some(NOW));
    assert_eq!(snap.sets, 3);
    let failure = snap.last_failure.clone().expect("a failure");
    assert_eq!((failure.at, failure.code.as_str()), (NOW + 2, "no_space"));
    let push = snap.last_push.clone().expect("a push");
    assert_eq!(
        (push.at, push.ok, push.code.as_deref()),
        (NOW + 3, false, Some("timeout"))
    );
    assert_eq!(snap.state(), State::Failed);
    assert!(!snap.running);
    assert_eq!(
        snap.next_run_at, None,
        "the next run is the scheduler's to say"
    );
    // The file is replaced atomically: no leftover beside it.
    assert_eq!(entries(&dir), vec!["status.json"]);

    // A file that does not parse is ignored.
    std::fs::write(dir.join("status.json"), b"{ not json").expect("a write");
    assert_eq!(
        BackupStatus::persistent(&dir).snapshot().state(),
        State::Unknown
    );
    let _ = std::fs::remove_dir_all(&dir);
}

// ---------------------------------------------------------------------------
// The commands
// ---------------------------------------------------------------------------

#[tokio::test]
async fn cli_backup_create_needs_the_server_stopped() {
    let app = app_with_vault().await;
    let data_dir = app.dir.clone();
    // A server holds the lock of the data directory.
    let lock = data_lock::acquire_existing(&data_dir).expect("the lock");
    let refused = cli::run(Command::BackupCreate {
        data_dir: data_dir.clone(),
    })
    .expect_err("refused while the server runs");
    assert!(refused.to_string().contains("stop"), "{refused}");
    assert!(listed(&cfg(&app)).is_empty(), "no set was made");
    drop(lock);

    // Stopped: the set is made, and checked.
    let line = cli::run(Command::BackupCreate {
        data_dir: data_dir.clone(),
    })
    .expect("a set");
    assert!(line.contains("made") && line.contains("checked"), "{line}");
    assert_eq!(listed(&cfg(&app)).len(), 1);

    // A restore in progress refuses too.
    std::fs::write(data_dir.join("RESTORE_IN_PROGRESS"), "{}").expect("a marker");
    assert!(
        cli::run(Command::BackupCreate {
            data_dir: data_dir.clone()
        })
        .expect_err("refused")
        .to_string()
        .contains("RESTORE_IN_PROGRESS")
    );
    std::fs::remove_file(data_dir.join("RESTORE_IN_PROGRESS")).expect("a removal");
}

#[tokio::test]
async fn cli_backup_list_and_verify_print_no_secret() {
    let app = app_with_vault().await;
    let data_dir = app.dir.clone();
    const CANARY: &str = "CANARY-cli-content-7d1e";
    Connection::open(data_dir.join("ferret.sqlite"))
        .expect("a connection")
        .execute(
            "INSERT INTO ferret_meta (key, value) VALUES ('canary', ?1)",
            [CANARY.as_bytes()],
        )
        .expect("a row");
    cli::run(Command::BackupCreate {
        data_dir: data_dir.clone(),
    })
    .expect("a set");
    let cfg = cfg(&app);
    let name = listed(&cfg).pop().expect("a set");
    let manifest = read_manifest(&cfg.dir.join(&name));

    let list = cli::run(Command::BackupList {
        data_dir: data_dir.clone(),
    })
    .expect("a listing");
    assert!(list.contains(&name) && list.contains("ok"), "{list}");
    let verify = cli::run(Command::BackupVerify {
        set: cfg.dir.join(&name),
    })
    .expect("a check");
    assert!(verify.contains("backup set is good"), "{verify}");

    let key_hex: String = std::fs::read(data_dir.join("session.key"))
        .expect("a key")
        .iter()
        .take(16)
        .map(|b| format!("{b:02x}"))
        .collect();
    for output in [&list, &verify] {
        assert_no_secret(
            output,
            &[
                CANARY,
                &key_hex,
                &manifest.setup_fingerprint,
                &manifest.files[0].sha256,
                &manifest.vaults[0].vault_id,
            ],
        );
    }

    // A set that fails its check says so without content.
    let damaged = cfg.dir.join(&name).join("session.key");
    let mut bytes = std::fs::read(&damaged).expect("a key");
    bytes[0] ^= 0xff;
    std::fs::write(&damaged, bytes).expect("a write");
    let error = cli::run(Command::BackupVerify {
        set: cfg.dir.join(&name),
    })
    .expect_err("a damaged set");
    assert_no_secret(&error.to_string(), &[CANARY, &key_hex]);
    let list = cli::run(Command::BackupList { data_dir }).expect("a listing");
    assert!(list.contains("NOT CHECKED"), "{list}");
}

// ---------------------------------------------------------------------------
// The client, the loaded secrets, the status and the check of a foreign set
// ---------------------------------------------------------------------------

#[tokio::test]
async fn a_redirect_from_the_monitor_is_not_followed_and_counts_as_a_failure() {
    let app = app_with_vault().await;
    let elsewhere = StandIn::start(Reply::Ok).await;
    let monitor = StandIn::start(Reply::Redirect(format!(
        "http://{}/landing",
        elsewhere.addr
    )))
    .await;
    let cfg = cfg_with_push(
        &app,
        &format!("http://{}/api/push/tokenabc123", monitor.addr),
    );
    let mut job = job(&app, cfg.clone(), Arc::new(set::RealPlatform));
    app.clock.advance(FIRST_RUN_AFTER as u64);
    let info = job.poll().await.expect("a run").expect("a good set");

    assert_eq!(monitor.requests().len(), 1);
    assert!(
        elsewhere.requests().is_empty(),
        "the redirect was not followed: {:?}",
        elsewhere.requests()
    );
    // No Referer goes anywhere either.
    assert!(!monitor.requests()[0].to_lowercase().contains("referer"));
    let snap = app.backup_status().snapshot();
    let push = snap.last_push.clone().expect("a push");
    assert_eq!((push.ok, push.code.as_deref()), (false, Some("status")));
    assert_eq!(snap.state(), State::Ok, "the set is still good");
    assert_eq!(listed(&cfg), vec![info.name]);
}

#[tokio::test]
async fn a_secret_file_that_differs_from_the_loaded_one_is_not_backed_up() {
    use ferret_server::backup::set::Loaded;
    let app = app_with_vault().await;
    let cfg = cfg(&app);
    let state = &app.state;
    let loaded = |session_key: &[u8]| {
        Arc::new(Loaded::new(
            state.secrets.keys.fingerprint().0,
            state.secrets.prelogin.payload(),
            session_key,
        ))
    };
    let right = loaded(state.core.session_key.master());
    let mut job = job(&app, cfg.clone(), Arc::new(set::RealPlatform)).with_loaded(right);
    app.clock.advance(FIRST_RUN_AFTER as u64);
    job.poll()
        .await
        .expect("a run")
        .expect("a set made from the loaded files");

    // The cookie key in memory is not the one on disk.
    let mut other = state.core.session_key.master().to_vec();
    other[0] ^= 0xff;
    let mut job =
        self::job(&app, cfg.clone(), Arc::new(set::RealPlatform)).with_loaded(loaded(&other));
    app.clock.advance(FIRST_RUN_AFTER as u64);
    let refused = job.poll().await.expect("a run");
    assert!(
        matches!(refused, Err(BackupError::Verify(why)) if why.contains("differs")),
        "{refused:?}"
    );
    assert_eq!(listed(&cfg).len(), 1, "no second set");
    assert!(!entries(&cfg.dir).iter().any(|n| n.starts_with(".tmp-")));
}

#[tokio::test]
async fn the_status_leaves_running_when_a_run_panics() {
    let app = app_with_vault().await;
    let cfg = cfg(&app);
    let spy = SpyPlatform::new();
    let platform: Arc<dyn set::Platform> = spy.clone();
    let mut job = job(&app, cfg.clone(), platform);
    spy.panic_rename.store(true, Ordering::SeqCst);
    app.clock.advance(FIRST_RUN_AFTER as u64);
    let result = job.poll().await.expect("a run");
    assert!(result.is_err(), "{result:?}");
    let snap = app.backup_status().snapshot();
    assert!(!snap.running, "the run is over");
    assert_eq!(snap.state(), State::Failed);
    assert!(listed(&cfg).is_empty());
    assert!(
        !entries(&cfg.dir).iter().any(|n| n.starts_with(".tmp-")),
        "the half-written folder is gone"
    );
}

#[tokio::test]
async fn a_failed_sync_of_the_backup_folder_after_the_rename_still_counts_as_a_set() {
    let app = app_with_vault().await;
    let cfg = cfg(&app);
    let spy = SpyPlatform::new();
    *spy.parent.lock().expect("parent") = Some(cfg.dir.clone());
    spy.fail_parent_sync.store(true, Ordering::SeqCst);
    let platform: Arc<dyn set::Platform> = spy.clone();
    let mut job = job(&app, cfg.clone(), platform);
    app.clock.advance(FIRST_RUN_AFTER as u64);
    let info = job.poll().await.expect("a run").expect("a set");
    assert_eq!(listed(&cfg), vec![info.name]);
    assert_eq!(app.backup_status().snapshot().state(), State::Ok);
}

#[tokio::test]
async fn a_set_whose_schema_has_a_view_in_place_of_a_table_is_refused() {
    let app = app_with_vault().await;
    let cfg = cfg(&app);
    let info = make(&app, &cfg, NOW).await.expect("a set");
    let case = app.dir.join("scratch-view");
    copy_set(&cfg.dir.join(&info.name), &case);
    // Make a copy whose manifest agrees with a changed database, so that only the
    // schema is wrong.
    {
        let db = Connection::open(case.join("ferret.sqlite")).expect("a copy");
        db.execute_batch(
            "DROP TABLE ferret_meta; CREATE VIEW ferret_meta AS SELECT 'k' AS key, x'00' AS value;",
        )
        .expect("a view");
    }
    let mut manifest = read_manifest(&case);
    {
        use sha2::{Digest as _, Sha256};
        let bytes = std::fs::read(case.join("ferret.sqlite")).expect("a database");
        let entry = manifest
            .files
            .iter_mut()
            .find(|f| f.name == "ferret.sqlite")
            .expect("an entry");
        entry.bytes = bytes.len() as u64;
        entry.sha256 = Sha256::digest(&bytes)
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
    }
    std::fs::write(
        case.join("MANIFEST.json"),
        serde_json::to_vec_pretty(&manifest).expect("json"),
    )
    .expect("a write");
    assert!(
        verify_error(&case).contains("lacks a table"),
        "{}",
        verify_error(&case)
    );
}
