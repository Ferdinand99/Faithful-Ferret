//! The matrix of the backup: that the newest set holds the newest wraps after
//! every change of the unlock methods, and that a restore, cut off at any
//! point, leaves a whole database and (once it is done) a higher epoch. Spec:
//! Fase 1 § 11 (the set, a backup after a change of the unlock methods), § 8.6
//! ("Legitimate rollbacks": the restore epoch goes up) and § 6.3.
//!
//! Real server state throughout: the unlock methods are changed through the
//! routes with the client of `ferret-core`, the sets are made by the backup job
//! on the app's manual clock, and a restore is the real one, stopped after the
//! step a seed picks (`restore_until`) and then finished, undone or left; the
//! data it leaves is started with the real start-up and signed in to through
//! the real routes.
//!
//! `FERRET_BACKUP_MATRIX_RUNS` sets the number of runs of each test and
//! `FERRET_BACKUP_MATRIX_SEED` the base seed; a failure names its seed.

mod support;

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU32, Ordering};

use axum::http::StatusCode;
use ferret_core::{VaultContext, WrapRecord, encode_recovery_key};
use ferret_server::auth::session::Origin;
use ferret_server::backup::restore::{self, RESTORE_STEPS, RestoreReport};
use ferret_server::backup::schedule::Job;
use ferret_server::backup::set::{self, SECRET_FILES};
use ferret_server::backup::{BackupConfig, RESTORE_MARKER};
use ferret_server::http::proxy_guard::ProxyList;
use ferret_server::product::DB_FILE;
use ferret_server::vault::quota::Limits;
use ferret_server::vault::reconcile;
use ferret_server::vault::store::{PutBody, PutOutcome, PutRequest, put_item};
use ferret_server_auth::{Clock as _, SessionScope};
use sha2::{Digest as _, Sha256};
use support::accounts::{
    Client, Snapshot, client_account, client_session, password_change, post_recover, put_password,
    put_recovery, recovered, renewed_recovery, snapshot,
};
use support::backup::{cfg, job, make};
use support::m3::{
    Ledger, Rng, Served, Vault, count_in, database_is_whole, env_number, epochs_in, only_seed,
    peek, recovery_key_opens, run_in_parallel, seed_of, signs_in, snapshot_in, took_recovered,
    took_recovery, vault_get, vault_post,
};
use support::session::{issue, make_fresh};
use support::{Jar, PEER, START, TestApp};

const BASE_SEED: u64 = 0x4241_434B_5550_4D58;
const RUNS_NEWEST: u64 = 60;
const RUNS_RESTORE: u64 = 150;
const THREADS: u64 = 4;
/// From this many runs on, every row must have been reached.
const RUNS_FOR_ALL_ROWS: u64 = 40;
/// The time the restores run at.
const NOW: i64 = START as i64 + 40_000;

// -------------------------------------------------------------------- helpers

/// An app that believes the test peer as a proxy, so sign-ins over `https`
/// count, with a client account `n` and a fresh full session of it.
async fn app_with_client(n: u8) -> (TestApp, Client, Jar, ferret_server::ids::SidHash) {
    let proxies = ProxyList::parse(&[PEER.split(':').next().expect("an address").to_string()])
        .expect("a proxy list");
    let app = TestApp::builder().proxies(proxies).build().await;
    let client = client_account(&app, n).await;
    let issued = client_session(&app, &client, SessionScope::Full, 1).await;
    (app, client, issued.jar, issued.sid)
}

fn email(client: &Client) -> String {
    format!("client{}@example.com", client.ids.account_id.as_bytes()[1])
}

/// The three changes of the unlock methods.
#[derive(Clone, Copy, Debug)]
enum Change {
    Password,
    Renew,
    Recover,
}

/// Makes one change through the routes, in the full session `jar` (made fresh
/// first), and checks that the server took it.
async fn change(
    app: &TestApp,
    client: &mut Client,
    jar: &Jar,
    sid: ferret_server::ids::SidHash,
    kind: Change,
    counter: &mut u32,
) {
    make_fresh(app, sid).await;
    *counter += 1;
    let password = format!("backup matrix {counter} horse battery staple");
    match kind {
        Change::Password => {
            let made = password_change(app, jar, client, &password).await;
            let res = put_password(app, jar, client, &made).await;
            assert_eq!(res.status, StatusCode::OK, "{}", res.text());
            client.took_password(&made, &password);
        }
        Change::Renew => {
            let renewed = renewed_recovery(client);
            let res = put_recovery(app, jar, client, &renewed).await;
            assert_eq!(res.status, StatusCode::OK, "{}", res.text());
            took_recovery(client, renewed);
        }
        Change::Recover => {
            let made = recovered(app, jar, client, &password, true).await;
            let res = post_recover(app, jar, &made).await;
            assert_eq!(res.status, StatusCode::OK, "{}", res.text());
            took_recovered(client, made, &password);
        }
    }
}

fn random_change(rng: &mut Rng) -> Change {
    *rng.pick(&[Change::Password, Change::Renew, Change::Recover])
}

/// The data of an account as a client holds it, to compare with a database.
struct Held {
    password: String,
    recovery_key: String,
    recovery_wrap: WrapRecord,
    ctx: VaultContext,
}

fn held(client: &Client) -> Held {
    Held {
        password: client.password.clone(),
        recovery_key: encode_recovery_key(&client.recovery_key).to_string(),
        recovery_wrap: client.recovery_wrap.clone(),
        ctx: *client.vault.context(),
    }
}

/// The wraps, the record and the manifest of the database at `db` are what the
/// client holds.
fn db_holds(db: &Path, client: &Client, what: &str) {
    let conn = peek(db);
    let found = snapshot_in(&conn, client.ids.account_id, client.ids.vault_id);
    let password = &client.password_wrap;
    let recovery = &client.recovery_wrap;
    assert_eq!(found.wraps.len(), 2, "{what}: two wraps");
    assert_eq!(found.wraps[0].3, password.wrap, "{what}: the password wrap");
    assert_eq!(
        u64::from(found.wraps[0].2),
        password.kek_generation,
        "{what}: its generation"
    );
    assert_eq!(found.wraps[1].3, recovery.wrap, "{what}: the recovery wrap");
    assert_eq!(
        u64::from(found.wraps[1].2),
        recovery.kek_generation,
        "{what}: its generation"
    );
    assert_eq!(
        u64::try_from(found.manifest_rev).ok(),
        Some(client.manifest.rev),
        "{what}: the manifest revision"
    );
    assert_eq!(
        found.manifest_envelope, client.manifest.envelope,
        "{what}: the manifest"
    );
    assert_eq!(
        found.manifest_tag, client.manifest.tag,
        "{what}: the manifest tag"
    );
}

fn sha(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// A temporary directory of its own, removed when dropped.
struct Dir(PathBuf);

impl Dir {
    fn new(name: &str) -> Dir {
        static NEXT: AtomicU32 = AtomicU32::new(0);
        loop {
            let path = std::env::temp_dir().join(format!(
                "ferret-backup-matrix-{name}-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            match std::fs::create_dir(&path) {
                Ok(()) => return Dir(path),
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(e) => panic!("a directory: {e}"),
            }
        }
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for Dir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// The files of the live data of a data directory, by name, with their hashes.
fn live_files(dir: &Path) -> BTreeMap<String, String> {
    let mut names = vec![
        DB_FILE.to_string(),
        format!("{DB_FILE}-wal"),
        format!("{DB_FILE}-shm"),
        format!("{DB_FILE}-journal"),
    ];
    names.extend(SECRET_FILES.iter().map(|name| (*name).to_string()));
    names
        .into_iter()
        .filter_map(|name| {
            let bytes = std::fs::read(dir.join(&name)).ok()?;
            Some((name, sha(&bytes)))
        })
        .collect()
}

/// Copies the database and the secret files of a set into a data directory,
/// as a stopped server leaves them.
fn copy_data(set_dir: &Path, data: &Path) {
    for name in [DB_FILE].into_iter().chain(SECRET_FILES) {
        std::fs::copy(set_dir.join(name), data.join(name)).expect("a copy");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            std::fs::set_permissions(data.join(name), std::fs::Permissions::from_mode(0o600))
                .expect("private");
        }
    }
}

/// The items of a database: id, revision, `seq`, and a hash of the envelope.
fn items_in(db: &Path) -> Vec<(Vec<u8>, i64, i64, Option<String>)> {
    let conn = peek(db);
    let mut stmt = conn
        .prepare("SELECT item_id, rev, seq, blob FROM ferret_items ORDER BY item_id")
        .expect("prepare");
    stmt.query_map([], |r| {
        let blob: Option<Vec<u8>> = r.get(3)?;
        Ok((r.get(0)?, r.get(1)?, r.get(2)?, blob.map(|b| sha(&b))))
    })
    .expect("query")
    .collect::<Result<Vec<_>, _>>()
    .expect("rows")
}

/// Puts a live item straight into the store.
async fn put_live(app: &TestApp, client: &Client, n: u8) {
    let (vault, device) = (client.ids.vault_id, client.ids.device);
    let now = i64::try_from(app.clock.now_unix()).expect("a time");
    app.state
        .vault_db
        .with_conn(move |conn| {
            let blob = format!("envelope of item {n}").into_bytes();
            let mut item = [0u8; 16];
            item[0] = 0x10;
            item[1] = n;
            let mut idem = [0u8; 16];
            idem[0] = 0xe0;
            idem[1] = n;
            let req = PutRequest {
                item_id: ferret_server::ids::ItemId::from_bytes(item),
                base_rev: 0,
                body: PutBody::Live {
                    blob: &blob,
                    tag: [n; 32],
                },
                idem,
                request_hash: [n; 32],
                resurrect: false,
                restore_epoch: None,
            };
            let outcome = put_item(conn, &vault, &device, &req, &Limits::DEFAULT, now)?;
            assert!(matches!(outcome, PutOutcome::Stored { .. }), "{outcome:?}");
            Ok(())
        })
        .await
        .expect("an item");
}

/// A pending one-time code for the user, as the kit's Users page makes one.
async fn pending_code(app: &TestApp, user: i64) -> String {
    let code = vole_kit::auth::sign_in_codes::generate();
    let hash = vole_kit::auth::sign_in_codes::hash(&code);
    app.state
        .vault_db
        .with_conn(move |conn| {
            vole_kit::db::sign_in_codes::insert(conn, user, &hash, user)?;
            Ok(())
        })
        .await
        .expect("a code");
    code
}

// ----------------------------------------------- the newest set holds the newest wraps

const NEWEST_ROWS: &[&str] = &[
    "newest.burst_of_changes_makes_one_set",
    "newest.no_set_before_the_window_ends",
    "newest.set_holds_the_newest_wraps",
    "newest.set_made_before_a_change_is_behind",
    "newest.set_restores_to_the_newest_password_and_recovery_key",
    "newest.set_verifies",
];

/// One run: bursts of changes of the unlock methods, each answered by one set
/// that holds what the server held when it was made.
async fn newest_run(seed: u64, ledger: &Ledger) {
    let mut rng = Rng::new(seed);
    let (app, mut client, jar, sid) = app_with_client(1).await;
    let config = cfg(&app);
    let mut job: Job = job(&app, config.clone(), set::real_platform());
    let mut counter = 0u32;
    let mut sets = 0usize;
    let mut newest_name: Option<String> = None;
    let mut last_set_snapshot: Option<Snapshot> = None;
    let bursts = 1 + rng.below(4);
    for burst in 0..bursts {
        let changes = 1 + rng.below(3);
        let started = i64::try_from(app.clock.now_unix()).expect("a time");
        let mut waited = 0i64;
        for index in 0..changes {
            // The first change starts the window of 60 seconds; the others
            // come inside it, each a little later.
            if index > 0 {
                let gap = i64::try_from(1 + rng.below(20)).expect("a gap");
                if waited + gap < 59 {
                    app.clock.advance(u64::try_from(gap).expect("a gap"));
                    waited += gap;
                }
            }
            change(
                &app,
                &mut client,
                &jar,
                sid,
                random_change(&mut rng),
                &mut counter,
            )
            .await;
            if let Some(before) = &last_set_snapshot {
                // The set that was made before this change is behind the server.
                let live = snapshot(&app, &client).await;
                assert_ne!(before, &live, "seed {seed}: the older set is behind");
                ledger.hit("newest.set_made_before_a_change_is_behind");
            }
            let early = job.poll().await;
            assert!(
                early.is_none(),
                "seed {seed}: a set before the window of 60 seconds ended"
            );
            ledger.hit("newest.no_set_before_the_window_ends");
        }
        // The window ends 60 seconds after the first request.
        let remaining = 60 - waited;
        assert!(remaining > 0, "seed {seed}");
        app.clock
            .advance(u64::try_from(remaining - 1).expect("a time"));
        assert!(
            job.poll().await.is_none(),
            "seed {seed}: a set one second early"
        );
        app.clock.advance(1);
        let made = job
            .poll()
            .await
            .unwrap_or_else(|| panic!("seed {seed}: no set when the window ended (burst {burst})"))
            .unwrap_or_else(|e| panic!("seed {seed}: the set failed: {e}"));
        assert!(
            i64::try_from(app.clock.now_unix()).expect("a time") - started >= 60,
            "seed {seed}"
        );
        sets += 1;
        ledger.hit("newest.burst_of_changes_makes_one_set");
        let listed = set::list(&config).expect("a listing");
        assert_eq!(listed.len(), sets, "seed {seed}: one set for the burst");
        let dir = config.dir.join(&made.name);
        set::verify(&dir, &set::build_migrations())
            .unwrap_or_else(|e| panic!("seed {seed}: the set does not verify: {e}"));
        ledger.hit("newest.set_verifies");

        // The set holds exactly what the server holds now, and what the client
        // holds.
        let in_set = snapshot_in(
            &peek(&dir.join(DB_FILE)),
            client.ids.account_id,
            client.ids.vault_id,
        );
        let live = snapshot(&app, &client).await;
        assert_eq!(
            in_set, live,
            "seed {seed}: the newest set is the live state"
        );
        db_holds(
            &dir.join(DB_FILE),
            &client,
            &format!("seed {seed}: the set"),
        );
        ledger.hit("newest.set_holds_the_newest_wraps");
        last_set_snapshot = Some(in_set);
        newest_name = Some(made.name);
        // Nothing is left to do for the job: a poll makes no second set.
        assert!(job.poll().await.is_none(), "seed {seed}: a second set");
        app.clock.advance(120);
    }

    // The newest set restores to the newest password and the newest recovery
    // key.
    let name = newest_name.expect("a set");
    let data = Dir::new("newest");
    copy_data(&config.dir.join(&name), data.path());
    let report = restore::restore(data.path(), &config.dir.join(&name), None, NOW)
        .unwrap_or_else(|e| panic!("seed {seed}: the restore failed: {e}"));
    assert!(report.restore_epoch >= u64::try_from(NOW).expect("a time"));
    let state = Served::start(data.path(), NOW + 60)
        .await
        .unwrap_or_else(|e| panic!("seed {seed}: the server does not start: {e}"));
    let kept = held(&client);
    assert!(
        signs_in(&state, &email(&client), &kept.password).await,
        "seed {seed}: the newest password signs in on the restored set"
    );
    let stored = state
        .state
        .vault_db
        .with_conn({
            let account = client.ids.account_id;
            move |conn| Ok(support::m3::stored_wraps_in(conn, account))
        })
        .await
        .expect("wraps");
    let recovery = stored.iter().find(|w| w.0 == 2).expect("a recovery wrap");
    assert!(
        recovery_key_opens(
            &kept.ctx,
            &kept.recovery_key,
            &kept.recovery_wrap,
            &recovery.3
        ),
        "seed {seed}: the newest recovery key opens the restored recovery wrap"
    );
    ledger.hit("newest.set_restores_to_the_newest_password_and_recovery_key");
}

#[test]
fn the_newest_set_after_an_unlock_change_holds_the_newest_wraps() {
    let ledger = Ledger::new();
    if let Some(seed) = only_seed("FERRET_BACKUP_MATRIX_ONLY") {
        run_in_parallel(1, 1, |_| {
            let ledger = ledger.clone();
            async move { newest_run(seed, &ledger).await }
        });
        return;
    }
    let runs = env_number("FERRET_BACKUP_MATRIX_RUNS", RUNS_NEWEST);
    let base = env_number("FERRET_BACKUP_MATRIX_SEED", BASE_SEED);
    run_in_parallel(runs, THREADS, |range| {
        let ledger = ledger.clone();
        async move {
            for index in range {
                newest_run(seed_of(base, index), &ledger).await;
            }
        }
    });
    if runs >= RUNS_FOR_ALL_ROWS && base == BASE_SEED {
        ledger.assert_covers(NEWEST_ROWS);
    }
}

// ------------------------------------------------- a restore at any point

const RESTORE_ROWS: &[&str] = &[
    "restore.aborted_after_a_kill_leaves_the_old_data",
    "restore.aborted_cut_off_leaves_the_old_data",
    "restore.every_session_and_code_ends",
    "restore.finished_after_a_kill",
    "restore.finished_in_one_go",
    "restore.higher_epoch_than_any_seen",
    "restore.killed_and_left_refuses_to_start",
    "restore.restored_data_is_the_backups",
    "restore.restored_server_signs_in_with_the_backups_password",
    "restore.rows_of_the_backup_are_back",
    "restore.at_least_is_honoured",
    "restore.killed_at_a_step",
];

/// What the scene knows of the two moments.
struct Scene {
    /// The backup (a set), and what the client held then.
    backup: PathBuf,
    at_backup: Held,
    backup_snapshot: Snapshot,
    backup_epoch: u64,
    /// The data that is there: a stopped server's directory.
    data: Dir,
    before: BTreeMap<String, String>,
    live_epoch: u64,
    /// What the client holds now, and the sessions of both moments.
    at_live: Held,
    session_before: Jar,
    session_after: Jar,
    /// A one-time code that was pending when the backup was made.
    pending_code: String,
    client: Client,
    /// The app, which holds the folder of the backup sets.
    _app: TestApp,
}

impl Scene {
    fn data(&self) -> &Path {
        self.data.path()
    }

    fn aside(&self) -> PathBuf {
        self.data()
            .join(format!("{}{}", restore::ASIDE_PREFIX, set::set_name(NOW)))
    }

    fn staging(&self) -> PathBuf {
        self.data()
            .join(format!("{}{}", restore::STAGING_PREFIX, set::set_name(NOW)))
    }
}

/// A server with an account whose unlock methods change before and after a
/// backup: the backup, and the data a stopped server leaves later.
async fn scene(rng: &mut Rng, seed: u64) -> Scene {
    let (app, mut client, jar, sid) = app_with_client(1).await;
    let config: BackupConfig = cfg(&app);
    let mut counter = 0u32;
    let user = client.ids.user_id;
    for _ in 0..rng.below(3) {
        change(
            &app,
            &mut client,
            &jar,
            sid,
            random_change(rng),
            &mut counter,
        )
        .await;
    }
    for n in 0..rng.below(3) {
        put_live(&app, &client, u8::try_from(n + 1).expect("an item")).await;
    }
    let code = pending_code(&app, user).await;
    let session_before = issue(&app, user, Origin::Vault, SessionScope::Full, 5)
        .await
        .jar;
    let at_backup = held(&client);
    let backup_snapshot = snapshot(&app, &client).await;
    let t1 = START as i64 + 600;
    let one = make(&app, &config, t1)
        .await
        .unwrap_or_else(|e| panic!("seed {seed}: the backup: {e}"));
    let backup = config.dir.join(&one.name);
    let backup_epoch = epochs_in(&backup.join(DB_FILE))[0];

    // After the backup: more changes, more items, a session, a code that
    // goes, maybe a bump that put the epoch far above the clock.
    app.clock.advance(700);
    for _ in 0..1 + rng.below(3) {
        change(
            &app,
            &mut client,
            &jar,
            sid,
            random_change(rng),
            &mut counter,
        )
        .await;
    }
    put_live(&app, &client, 9).await;
    let session_after = issue(&app, user, Origin::Vault, SessionScope::Full, 6)
        .await
        .jar;
    if rng.chance(1, 3) {
        let far = u64::try_from(NOW).expect("a time")
            + 5_000
            + u64::try_from(rng.below(5_000)).expect("a number");
        let now = i64::try_from(app.clock.now_unix()).expect("a time");
        app.state
            .vault_db
            .with_conn(move |conn| reconcile::bump(conn, Some(far), now))
            .await
            .expect("a bump");
    }
    let two = make(&app, &config, START as i64 + 1_300)
        .await
        .unwrap_or_else(|e| panic!("seed {seed}: the later set: {e}"));
    let data = Dir::new("data");
    copy_data(&config.dir.join(&two.name), data.path());
    let before = live_files(data.path());
    let live_epoch = epochs_in(&data.path().join(DB_FILE))[0];
    Scene {
        backup,
        at_backup,
        backup_snapshot,
        backup_epoch,
        before,
        live_epoch,
        at_live: held(&client),
        session_before,
        session_after,
        pending_code: code,
        data,
        client,
        _app: app,
    }
}

/// The live files are the old ones, the restored ones, or (between the two
/// moves) none; never a mix, and any database that is there is whole.
fn assert_old_or_new(scene: &Scene, step: &str, seed: u64) {
    let live = live_files(scene.data());
    if live == scene.before {
        return;
    }
    if live.is_empty() {
        assert_eq!(
            step, "moved_aside",
            "seed {seed}: no live files only between the moves"
        );
        assert_eq!(
            live_files(&scene.aside()),
            scene.before,
            "seed {seed}: {step}: the old files"
        );
        return;
    }
    assert_eq!(
        step, "placed",
        "seed {seed}: {step}: the data directory changed"
    );
    database_is_whole(&scene.data().join(DB_FILE))
        .unwrap_or_else(|e| panic!("seed {seed}: {step}: {e}"));
    assert_eq!(
        live_files(&scene.aside()),
        scene.before,
        "seed {seed}: {step}: the old files"
    );
}

fn marker_step(dir: &Path) -> Option<String> {
    let bytes = std::fs::read(dir.join(RESTORE_MARKER)).ok()?;
    let value: serde_json::Value = serde_json::from_slice(&bytes).expect("JSON");
    value["step"].as_str().map(str::to_string)
}

/// What a finished restore must have left.
async fn assert_restored(
    scene: &Scene,
    report: &RestoreReport,
    at_least: Option<u64>,
    seed: u64,
    ledger: &Ledger,
) {
    let data = scene.data();
    let db = data.join(DB_FILE);
    assert!(
        !data.join(RESTORE_MARKER).exists(),
        "seed {seed}: no marker"
    );
    assert!(!scene.staging().exists(), "seed {seed}: no staged folder");
    for journal in ["-wal", "-shm", "-journal"] {
        assert!(
            !data.join(format!("{DB_FILE}{journal}")).exists(),
            "seed {seed}: no {journal} next to the restored database"
        );
    }
    database_is_whole(&db).unwrap_or_else(|e| panic!("seed {seed}: the restored database: {e}"));
    assert_eq!(
        live_files(&scene.aside()),
        scene.before,
        "seed {seed}: the old files moved aside whole"
    );
    for name in SECRET_FILES {
        assert_eq!(
            std::fs::read(data.join(name)).expect("a secret file"),
            std::fs::read(scene.backup.join(name)).expect("the set's file"),
            "seed {seed}: {name} is the set's"
        );
    }
    ledger.hit("restore.restored_data_is_the_backups");

    // The epoch is above every epoch seen: the data that was there, the backup's,
    // the clock, and what was asked for.
    let epochs = epochs_in(&db);
    assert_eq!(epochs.len(), 1, "seed {seed}");
    let epoch = epochs[0];
    assert_eq!(
        epoch, report.restore_epoch,
        "seed {seed}: the report says the epoch"
    );
    assert!(
        epoch > scene.live_epoch,
        "seed {seed}: {epoch} is not above the epoch that was there ({})",
        scene.live_epoch
    );
    assert!(
        epoch > scene.backup_epoch,
        "seed {seed}: not above the backup's epoch"
    );
    assert!(
        epoch >= u64::try_from(NOW).expect("a time"),
        "seed {seed}: not at the time of the restore"
    );
    ledger.hit("restore.higher_epoch_than_any_seen");
    if let Some(least) = at_least {
        assert!(
            epoch >= least,
            "seed {seed}: {epoch} is below --at-least {least}"
        );
        ledger.hit("restore.at_least_is_honoured");
    }

    // What the backup held is what the restored database holds.
    let restored = snapshot_in(
        &peek(&db),
        scene.client.ids.account_id,
        scene.client.ids.vault_id,
    );
    assert_eq!(
        restored, scene.backup_snapshot,
        "seed {seed}: the account is the backup's"
    );
    assert_eq!(
        items_in(&db),
        items_in(&scene.backup.join(DB_FILE)),
        "seed {seed}: the items are the backup's"
    );
    ledger.hit("restore.rows_of_the_backup_are_back");

    // No session, no code, no half-way sign-in.
    assert_eq!(
        count_in(
            &db,
            "SELECT COUNT(*) FROM ferret_sessions WHERE revoked_at IS NULL"
        ),
        0,
        "seed {seed}: every session ended"
    );
    assert_eq!(
        count_in(
            &db,
            "SELECT COUNT(*) FROM sign_in_codes WHERE used_at IS NULL AND revoked_at IS NULL"
        ),
        0,
        "seed {seed}: every pending code ended"
    );
    assert_eq!(
        count_in(&db, "SELECT COUNT(*) FROM ferret_login_states"),
        0,
        "seed {seed}"
    );

    // The server starts on it: the sessions of both moments are dead, the
    // password of the backup signs in, and the recovery key of the backup
    // opens the recovery wrap.
    let state = Served::start(data, NOW + 60)
        .await
        .unwrap_or_else(|e| panic!("seed {seed}: the server does not start: {e}"));
    for (jar, what) in [
        (&scene.session_before, "a session from the backup"),
        (&scene.session_after, "a session made after the backup"),
    ] {
        let res = vault_get(&state, jar, "/api/vault/recovery").await;
        assert_eq!(
            res.status,
            StatusCode::UNAUTHORIZED,
            "seed {seed}: {what}: {}",
            res.text()
        );
    }
    // The code that was pending when the backup was made is refused, by the route.
    let redeem = state
        .send(
            vault_post(
                "/api/auth/redeem",
                &serde_json::json!({ "email": email(&scene.client), "code": scene.pending_code }),
            )
            .header("x-forwarded-for", "203.0.113.77")
            .build(),
        )
        .await;
    assert_eq!(
        redeem.status,
        StatusCode::UNAUTHORIZED,
        "seed {seed}: the pending code: {}",
        redeem.text()
    );
    assert_eq!(
        redeem.body, br#"{"error":"denied"}"#,
        "seed {seed}: the pending code is refused as any other"
    );
    ledger.hit("restore.every_session_and_code_ends");
    let address = email(&scene.client);
    assert!(
        signs_in(&state, &address, &scene.at_backup.password).await,
        "seed {seed}: the password of the backup signs in"
    );
    if scene.at_live.password != scene.at_backup.password {
        assert!(
            !signs_in(&state, &address, &scene.at_live.password).await,
            "seed {seed}: a password changed after the backup signs in"
        );
    }
    let stored = state
        .state
        .vault_db
        .with_conn({
            let account = scene.client.ids.account_id;
            move |conn| Ok(support::m3::stored_wraps_in(conn, account))
        })
        .await
        .expect("wraps");
    let recovery = stored
        .iter()
        .find(|w| w.2 > 0 && w.0 == 2)
        .expect("a recovery wrap");
    let at_backup = &scene.at_backup;
    assert!(
        recovery_key_opens(
            &at_backup.ctx,
            &at_backup.recovery_key,
            &at_backup.recovery_wrap,
            &recovery.3
        ),
        "seed {seed}: the recovery key of the backup opens the restored wrap"
    );
    if scene.at_live.recovery_key != at_backup.recovery_key {
        assert!(
            !recovery_key_opens(
                &at_backup.ctx,
                &scene.at_live.recovery_key,
                &at_backup.recovery_wrap,
                &recovery.3
            ),
            "seed {seed}: a recovery key made after the backup opens the restored wrap"
        );
    }
    ledger.hit("restore.restored_server_signs_in_with_the_backups_password");
}

/// What an undone or untouched restore must have left: the old data, whole.
async fn assert_untouched(scene: &Scene, seed: u64, why: &str, copies_gone: bool) {
    assert_eq!(
        live_files(scene.data()),
        scene.before,
        "seed {seed}: {why}: the old files"
    );
    assert!(
        !scene.data().join(RESTORE_MARKER).exists(),
        "seed {seed}: {why}: no marker"
    );
    assert!(
        !copies_gone || !scene.staging().exists(),
        "seed {seed}: {why}: no staged folder"
    );
    assert!(
        !copies_gone || !scene.aside().exists(),
        "seed {seed}: {why}: no moved-aside folder"
    );
    database_is_whole(&scene.data().join(DB_FILE))
        .unwrap_or_else(|e| panic!("seed {seed}: {why}: {e}"));
    assert_eq!(
        epochs_in(&scene.data().join(DB_FILE)),
        [scene.live_epoch],
        "seed {seed}: {why}: the epoch"
    );
    // And the old data serves: its newest password signs in.
    let state = Served::start(scene.data(), NOW + 60)
        .await
        .unwrap_or_else(|e| {
            panic!("seed {seed}: {why}: the server does not start on the old data: {e}")
        });
    assert!(
        signs_in(&state, &email(&scene.client), &scene.at_live.password).await,
        "seed {seed}: {why}: the newest password signs in on the old data"
    );
}

/// One run: a scene, then a restore that is cut off after the steps a seed
/// picks, and then finished, undone (also cut off) or left.
async fn restore_run(seed: u64, ledger: &Ledger) {
    let mut rng = Rng::new(seed);
    let scene = scene(&mut rng, seed).await;
    let at_least = match rng.below(3) {
        0 => None,
        1 => Some(
            u64::try_from(NOW).expect("a time")
                + 20_000
                + u64::try_from(rng.below(1_000)).expect("a number"),
        ),
        _ => Some(10),
    };
    // Up to three kills, each at a step later than the one before, so that the
    // run goes on; a kill at an earlier step finishes the restore instead.
    let mut steps: Vec<&str> = Vec::new();
    for _ in 0..rng.below(4) {
        steps.push(RESTORE_STEPS[rng.below(RESTORE_STEPS.len())]);
    }
    steps.sort_by_key(|s| RESTORE_STEPS.iter().position(|x| x == s));
    let mut finished: Option<RestoreReport> = None;
    let mut last_kill: Option<&str> = None;
    for &step in &steps {
        match restore::restore_until(scene.data(), &scene.backup, at_least, NOW, step) {
            Ok(None) => {
                last_kill = Some(step);
                assert_eq!(
                    marker_step(scene.data()).as_deref(),
                    Some(step),
                    "seed {seed}: the marker"
                );
                assert_old_or_new(&scene, step, seed);
                let refused = Served::start(scene.data(), NOW + 60).await;
                assert!(
                    refused.is_err_and(|e| e.to_string().contains(RESTORE_MARKER)),
                    "seed {seed}: {step}: the server started with a restore in progress"
                );
                ledger.hit("restore.killed_and_left_refuses_to_start");
                ledger.hit("restore.killed_at_a_step");
            }
            Ok(Some(report)) => {
                // Already past that step: the run finished.
                finished = Some(report);
                break;
            }
            Err(e) => panic!("seed {seed}: the restore until {step}: {e}"),
        }
    }
    // The ending.
    let ending = if finished.is_some() || last_kill.is_none() {
        0
    } else {
        rng.below(4)
    };
    match (finished, last_kill, ending) {
        (Some(report), _, _) => {
            assert_restored(&scene, &report, at_least, seed, ledger).await;
            ledger.hit("restore.finished_after_a_kill");
        }
        (None, None, _) => {
            // No kill at all: one go.
            let report = restore::restore(scene.data(), &scene.backup, at_least, NOW)
                .unwrap_or_else(|e| panic!("seed {seed}: the restore: {e}"));
            assert_restored(&scene, &report, at_least, seed, ledger).await;
            ledger.hit("restore.finished_in_one_go");
        }
        (None, Some(_), 0 | 1) => {
            let report = restore::restore(scene.data(), &scene.backup, at_least, NOW)
                .unwrap_or_else(|e| panic!("seed {seed}: the restore run again: {e}"));
            assert_restored(&scene, &report, at_least, seed, ledger).await;
            ledger.hit("restore.finished_after_a_kill");
        }
        (None, Some(_), 2) => {
            restore::abort(scene.data()).unwrap_or_else(|e| panic!("seed {seed}: the abort: {e}"));
            assert_untouched(&scene, seed, "after an abort", true).await;
            ledger.hit("restore.aborted_after_a_kill_leaves_the_old_data");
        }
        (None, Some(_), _) => {
            // An abort that is cut off after one of its moves, then run again.
            let cut = rng.pick(&restore::ABORT_STEPS);
            restore::abort_until(scene.data(), cut)
                .unwrap_or_else(|e| panic!("seed {seed}: the abort until {cut}: {e}"));
            if *cut != "unmarked" {
                assert!(
                    Served::start(scene.data(), NOW + 60).await.is_err(),
                    "seed {seed}: the server started in the middle of an abort"
                );
                restore::abort(scene.data())
                    .unwrap_or_else(|e| panic!("seed {seed}: the abort again: {e}"));
            }
            assert_untouched(
                &scene,
                seed,
                "after an abort that was cut off",
                *cut != "unmarked",
            )
            .await;
            ledger.hit("restore.aborted_cut_off_leaves_the_old_data");
        }
    }
}

#[test]
fn a_restore_at_any_point_leaves_a_consistent_database_and_a_higher_epoch() {
    let ledger = Ledger::new();
    if let Some(seed) = only_seed("FERRET_BACKUP_MATRIX_ONLY") {
        run_in_parallel(1, 1, |_| {
            let ledger = ledger.clone();
            async move { restore_run(seed, &ledger).await }
        });
        return;
    }
    let runs = env_number("FERRET_BACKUP_MATRIX_RUNS", RUNS_RESTORE);
    let base = env_number("FERRET_BACKUP_MATRIX_SEED", BASE_SEED ^ 0x55);
    run_in_parallel(runs, THREADS, |range| {
        let ledger = ledger.clone();
        async move {
            for index in range {
                restore_run(seed_of(base, index), &ledger).await;
            }
        }
    });
    // The steps, in the order of the restore, are all covered by a plain pass
    // too: each is killed once, finished once, and undone once.
    if runs >= RUNS_FOR_ALL_ROWS && base == BASE_SEED ^ 0x55 {
        ledger.assert_covers(RESTORE_ROWS);
    }
}

/// Every step of the restore, one by one: killed there, then finished, and
/// killed there, then undone, on the same scene shape as the runs.
#[test]
fn a_kill_after_each_step_then_either_end_leaves_the_old_data_or_the_restored_data() {
    let ledger = Ledger::new();
    run_in_parallel(
        u64::try_from(RESTORE_STEPS.len()).expect("a count"),
        THREADS,
        |range| {
            let ledger = ledger.clone();
            async move {
                for index in range {
                    let step = RESTORE_STEPS[usize::try_from(index).expect("an index")];
                    for undo in [false, true] {
                        let mut rng = Rng::new(seed_of(0x5354_4550, index));
                        let seed = seed_of(0x5354_4550, index);
                        let scene = scene(&mut rng, seed).await;
                        let stopped =
                            restore::restore_until(scene.data(), &scene.backup, None, NOW, step)
                                .unwrap_or_else(|e| panic!("{step}: {e}"));
                        assert!(stopped.is_none(), "{step}: stopped");
                        assert_old_or_new(&scene, step, seed);
                        if undo {
                            restore::abort(scene.data()).unwrap_or_else(|e| panic!("{step}: {e}"));
                            assert_untouched(&scene, seed, step, true).await;
                        } else {
                            let report = restore::restore(scene.data(), &scene.backup, None, NOW)
                                .unwrap_or_else(|e| panic!("{step}: {e}"));
                            assert_restored(&scene, &report, None, seed, &ledger).await;
                        }
                    }
                }
            }
        },
    );
}

#[test]
fn the_restore_steps_are_the_ones_the_matrix_covers() {
    // A new step of the restore needs a decision here: the kill tests walk
    // `RESTORE_STEPS`, so a step that is added is walked too; this pins the
    // list the matrix was written for.
    assert_eq!(
        RESTORE_STEPS,
        [
            "marker",
            "staged",
            "verified",
            "migrated",
            "bumped",
            "moved_aside",
            "placed"
        ],
        "a step of the restore was added or renamed: check the matrix"
    );
    assert_eq!(restore::ABORT_STEPS, ["undoing", "old_back", "unmarked"]);
}
