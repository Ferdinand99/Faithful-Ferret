//! `ferret backup restore`: putting a backup set back in place of the data of a
//! stopped server, safe against a kill at every step. Spec: Fase 1 § 11 (the
//! set, `opaque_setup` in place before the server starts) and § 8.6,
//! "Legitimate rollbacks" (the restore epoch goes up).
//!
//! The scene of most tests: a running server (a `TestApp`) with one account and
//! two items makes the backup; then a second account is added and a second set
//! is made, and that later state is copied into a data directory of its own,
//! as a stopped server leaves it. The backup has one account, the data that is
//! there has two, so a look at the database tells the old data from the new.

mod support;

use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};

use axum::body::{Body, to_bytes};
use axum::extract::ConnectInfo;
use axum::http::{Request, StatusCode, header};
use axum::response::IntoResponse as _;
use axum_extra::extract::cookie::SignedCookieJar;
use ferret_core::OsRng;
use ferret_server::auth::session::{Origin, insert_session, new_session, session_cookies};
use ferret_server::backup::restore::{self, RESTORE_STEPS, RestoreReport};
use ferret_server::backup::set::{self, MANIFEST_FILE, SECRET_FILES};
use ferret_server::backup::{BackupError, Manifest, RESTORE_MARKER};
use ferret_server::cli::{self, Command};
use ferret_server::config::Config;
use ferret_server::data_lock;
use ferret_server::ids::{DeviceId, ItemId};
use ferret_server::product::DB_FILE;
use ferret_server::server;
use ferret_server::state::FerretState;
use ferret_server::vault::quota::Limits;
use ferret_server::vault::reconcile::{self, restore_rows};
use ferret_server::vault::store::{PutBody, PutOutcome, PutRequest, put_item};
use ferret_server_auth::{ManualClock, SessionScope};
use rusqlite::{Connection, OpenFlags};
use serde_json::Value;
use sha2::{Digest as _, Sha256};
use support::accounts::{TestAccount, add_account_to_app, id16};
use support::backup::{capture_log, cfg, copy_set, make};
use support::session::issue;
use support::{ADMIN_URL, Jar, PEER, Res, START, TestApp, VAULT_URL, Which};
use tower::ServiceExt as _;

/// When the backup is made.
const T1: i64 = START as i64 + 600;
/// When the later set, the data that is there, is made.
const T2: i64 = START as i64 + 1200;
/// When the restore runs.
const NOW: i64 = START as i64 + 3600;

// ---------------------------------------------------------------- helpers

/// A temporary directory of its own, removed when dropped: a number no other
/// test in this process gets, and `create_dir`, which never hands out a folder
/// that is already there.
struct Dir(PathBuf);

impl Dir {
    fn new(name: &str) -> Dir {
        static NEXT: AtomicU32 = AtomicU32::new(0);
        loop {
            let path = std::env::temp_dir().join(format!(
                "ferret-restore-test-{name}-{}-{}",
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

/// The files of the live data of a data directory.
fn live_names() -> Vec<String> {
    let mut names = vec![
        DB_FILE.to_string(),
        format!("{DB_FILE}-wal"),
        format!("{DB_FILE}-shm"),
        format!("{DB_FILE}-journal"),
    ];
    names.extend(SECRET_FILES.iter().map(|name| (*name).to_string()));
    names
}

fn sha(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// The SHA-256 of every file of the live data that is in `dir`.
fn live_files(dir: &Path) -> BTreeMap<String, String> {
    live_names()
        .into_iter()
        .filter_map(|name| {
            let bytes = std::fs::read(dir.join(&name)).ok()?;
            Some((name, sha(&bytes)))
        })
        .collect()
}

/// Copies the database and the secret files of a set into a data directory,
/// as a stopped server leaves them (`0600`).
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

/// Opens a database read-only without touching it or its folder.
fn peek(db: &Path) -> Connection {
    Connection::open_with_flags(
        format!("file:{}?immutable=1", db.display()),
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_URI,
    )
    .expect("open read-only")
}

fn count(db: &Path, sql: &str) -> i64 {
    peek(db)
        .query_row(sql, [], |row| row.get(0))
        .expect("a count")
}

fn accounts(dir: &Path) -> i64 {
    count(&dir.join(DB_FILE), "SELECT COUNT(*) FROM ferret_accounts")
}

fn epochs(db: &Path) -> Vec<u64> {
    let conn = peek(db);
    let mut stmt = conn
        .prepare("SELECT restore_epoch FROM ferret_vaults ORDER BY vault_id")
        .expect("prepare");
    stmt.query_map([], |row| row.get::<_, i64>(0))
        .expect("query")
        .map(|r| u64::try_from(r.expect("row")).expect("unsigned"))
        .collect()
}

/// Puts a live item straight into the store of the app.
async fn put_live(app: &TestApp, account: TestAccount, n: u8) {
    app.state
        .vault_db
        .with_conn(move |conn| {
            let blob = format!("envelope of item {n}").into_bytes();
            let req = PutRequest {
                item_id: ItemId::from_bytes(id16(0x10, n)),
                base_rev: 0,
                body: PutBody::Live {
                    blob: &blob,
                    tag: [n; 32],
                },
                idem: id16(0xe0, n),
                request_hash: [n; 32],
                resurrect: false,
                restore_epoch: None,
            };
            let outcome = put_item(
                conn,
                &account.vault_id,
                &account.device,
                &req,
                &Limits::DEFAULT,
                T1 - 60,
            )?;
            assert!(matches!(outcome, PutOutcome::Stored { .. }), "{outcome:?}");
            Ok(())
        })
        .await
        .expect("an item");
}

/// A row of `ferret_items` as stored: id, revision, `seq` and envelope.
type StoredRow = (Vec<u8>, i64, i64, Option<Vec<u8>>);

/// The scene: see the module documentation.
struct Scene {
    app: TestApp,
    first: TestAccount,
    /// The backup, made at `T1`.
    backup: PathBuf,
    /// The data directory of the stopped server, with the state at `T2`.
    data: Dir,
    /// The live files of `data` before the restore.
    before: BTreeMap<String, String>,
}

impl Scene {
    fn data(&self) -> &Path {
        self.data.path()
    }

    /// The folder the restore at `NOW` moves the old files into.
    fn aside(&self) -> PathBuf {
        self.data()
            .join(format!("{}{}", restore::ASIDE_PREFIX, set::set_name(NOW)))
    }

    /// The folder the restore at `NOW` stages the set in.
    fn staging(&self) -> PathBuf {
        self.data()
            .join(format!("{}{}", restore::STAGING_PREFIX, set::set_name(NOW)))
    }

    /// The old data is in the data directory, untouched, with nothing of a
    /// restore next to it.
    fn assert_untouched(&self, why: &str) {
        assert_eq!(live_files(self.data()), self.before, "{why}: the old files");
        assert!(
            !self.data().join(RESTORE_MARKER).exists(),
            "{why}: no marker"
        );
        assert!(!self.staging().exists(), "{why}: no staged folder");
        assert!(!self.aside().exists(), "{why}: no moved-aside folder");
    }

    /// The restore is done: the backup's data is in place, the old files are
    /// in the moved-aside folder, and nothing of the restore is left.
    fn assert_restored(&self, why: &str) {
        assert!(
            !self.data().join(RESTORE_MARKER).exists(),
            "{why}: no marker"
        );
        assert!(!self.staging().exists(), "{why}: no staged folder");
        assert_eq!(accounts(self.data()), 1, "{why}: the backup's database");
        for name in SECRET_FILES {
            assert_eq!(
                std::fs::read(self.data().join(name)).expect("a secret file"),
                std::fs::read(self.backup.join(name)).expect("the set's file"),
                "{why}: {name} is the set's"
            );
        }
        for journal in ["-wal", "-shm", "-journal"] {
            assert!(
                !self.data().join(format!("{DB_FILE}{journal}")).exists(),
                "{why}: no {journal} next to the restored database"
            );
        }
        assert_eq!(
            live_files(&self.aside()),
            self.before,
            "{why}: the old files are moved aside whole"
        );
    }
}

async fn new_scene() -> Scene {
    let app = TestApp::new().await;
    let first = add_account_to_app(&app, 1).await;
    put_live(&app, first, 1).await;
    put_live(&app, first, 2).await;
    let cfg = cfg(&app);
    let one = make(&app, &cfg, T1).await.expect("the backup");
    add_account_to_app(&app, 2).await;
    let two = make(&app, &cfg, T2).await.expect("the later set");
    let data = Dir::new("data");
    copy_data(&cfg.dir.join(&two.name), data.path());
    let before = live_files(data.path());
    assert_eq!(accounts(data.path()), 2);
    Scene {
        backup: cfg.dir.join(&one.name),
        app,
        first,
        data,
        before,
    }
}

fn config_for(dir: &Path) -> Config {
    Config {
        data_dir: dir.to_path_buf(),
        host: std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
        vault_port: 3041,
        admin_port: 3040,
        vault_url: VAULT_URL.to_string(),
        admin_url: ADMIN_URL.to_string(),
        trusted_proxies: Vec::new(),
        backup_dir: None,
        backup_every_hours: 24,
        backup_keep_days: 30,
        backup_push_url: None,
    }
}

/// The server's start-up on a data directory, with a clock just after the
/// restore.
async fn start_on(dir: &Path) -> Result<FerretState, ferret_server::StartError> {
    let clock = Arc::new(ManualClock::new(u64::try_from(NOW + 60).expect("a time")));
    ferret_server::start(&config_for(dir), clock).await
}

/// A start on the data directory is refused because of the marker, and the
/// refusal says so.
async fn assert_start_refused(dir: &Path, why: &str) {
    let refused = start_on(dir)
        .await
        .err()
        .unwrap_or_else(|| panic!("{why}: started"));
    assert!(
        refused.to_string().contains(RESTORE_MARKER),
        "{why}: {refused}"
    );
}

/// A session of the vault for `user_id` on a started server, and its cookies.
async fn sign_in(state: &FerretState, user_id: i64) -> Jar {
    let version: i64 = state
        .vault_db
        .with_conn(move |conn| {
            Ok(conn.query_row(
                "SELECT session_version FROM users WHERE id = ?1",
                [user_id],
                |r| r.get(0),
            )?)
        })
        .await
        .expect("a session version");
    let (secret, session, claims) = new_session(
        &mut OsRng,
        NOW + 60,
        user_id,
        version,
        Origin::Vault,
        DeviceId(id16(0xd7, 1)),
        "Test browser",
        SessionScope::Full,
    );
    state
        .vault_db
        .with_conn(move |conn| Ok(insert_session(conn, &session)?))
        .await
        .expect("a session");
    let cookies = session_cookies(
        SignedCookieJar::new(state.core.session_key.clone()),
        &secret,
        &claims,
        true,
    )
    .into_response();
    let mut jar = Jar::default();
    jar.absorb(cookies.headers());
    jar
}

/// A `GET` to the vault listener of a started server.
async fn vault_get(state: &FerretState, jar: &Jar, uri: &str) -> Res {
    let mut builder = Request::builder()
        .method("GET")
        .uri(uri)
        .header(header::HOST, Which::Vault.host());
    if let Some(cookie) = jar.header() {
        builder = builder.header(header::COOKIE, cookie);
    }
    let mut request = builder.body(Body::empty()).expect("a request");
    let peer: SocketAddr = PEER.parse().expect("a peer");
    request.extensions_mut().insert(ConnectInfo(peer));
    let response = server::vault_router(state.clone())
        .oneshot(request)
        .await
        .expect("a response");
    let (parts, body) = response.into_parts();
    Res {
        status: parts.status,
        headers: parts.headers,
        body: to_bytes(body, 1024 * 1024).await.expect("a body").to_vec(),
    }
}

/// The marker as JSON.
fn marker(dir: &Path) -> Value {
    serde_json::from_slice(&std::fs::read(dir.join(RESTORE_MARKER)).expect("the marker"))
        .expect("JSON")
}

/// Changes the database of a copied set with `sql` and writes the manifest
/// again from what the folder holds, so that only the change is wrong.
fn change_set(set_dir: &Path, sql: &str) {
    {
        let conn = Connection::open(set_dir.join(DB_FILE)).expect("open the copy");
        let _: String = conn
            .query_row("PRAGMA journal_mode = DELETE", [], |r| r.get(0))
            .expect("rollback journal");
        conn.execute_batch(sql).expect("the change");
    }
    reseal(set_dir);
}

/// Writes the manifest of a set again from its files.
fn reseal(set_dir: &Path) {
    let path = set_dir.join(MANIFEST_FILE);
    let mut manifest: Manifest =
        serde_json::from_slice(&std::fs::read(&path).expect("a manifest")).expect("parses");
    for file in &mut manifest.files {
        let bytes = std::fs::read(set_dir.join(&file.name)).expect("a file");
        file.bytes = u64::try_from(bytes.len()).expect("a size");
        file.sha256 = sha(&bytes);
    }
    let conn = peek(&set_dir.join(DB_FILE));
    manifest.migrations = conn
        .prepare("SELECT name FROM schema_migrations ORDER BY name")
        .expect("prepare")
        .query_map([], |row| row.get(0))
        .expect("query")
        .map(|r| r.expect("a name"))
        .collect();
    drop(conn);
    std::fs::write(&path, serde_json::to_vec_pretty(&manifest).expect("json")).expect("write");
}

/// A copy of the scene's backup in a folder of its own.
fn copy_of_backup(scene: &Scene, name: &str) -> (Dir, PathBuf) {
    let dir = Dir::new(name);
    let set_dir = dir.path().join("set");
    copy_set(&scene.backup, &set_dir);
    (dir, set_dir)
}

/// The restore at `NOW` of `from` into the scene's data directory.
fn restore_scene(scene: &Scene, from: &Path) -> Result<RestoreReport, BackupError> {
    restore::restore(scene.data(), from, None, NOW)
}

// ---------------------------------------------------------------- the restore

#[tokio::test]
async fn restore_puts_the_set_back_and_moves_the_current_data_aside() {
    let scene = new_scene().await;
    let report = restore_scene(&scene, &scene.backup).expect("a restore");
    assert_eq!(
        report,
        RestoreReport {
            restore_epoch: u64::try_from(NOW).unwrap(),
            vaults: 1,
            sessions_ended: 0,
            devices_revoked: 0,
            moved_aside: scene.aside(),
            seen_epoch_unknown: false,
        }
    );
    scene.assert_restored("after the restore");
    // The restored files are private.
    #[cfg(unix)]
    for name in [DB_FILE].into_iter().chain(SECRET_FILES) {
        use std::os::unix::fs::PermissionsExt as _;
        let mode = std::fs::metadata(scene.data().join(name))
            .expect("a file")
            .permissions()
            .mode();
        assert_eq!(mode & 0o077, 0, "{name} is {mode:o}");
    }
    // The restored database is whole, and is the backup's with the bump.
    let db = scene.data().join(DB_FILE);
    let verdict: String = peek(&db)
        .query_row("PRAGMA integrity_check", [], |r| r.get(0))
        .expect("a check");
    assert_eq!(verdict, "ok");
    assert_eq!(epochs(&db), [u64::try_from(NOW).unwrap()]);
    // The set itself is not changed.
    set::verify(&scene.backup, &set::build_migrations()).expect("the set is as it was");
    // A second restore needs a marker no more: there is none to finish.
    let aborted = restore::abort(scene.data()).expect_err("nothing to undo");
    assert!(matches!(aborted, BackupError::Refused(_)), "{aborted}");
}

#[tokio::test]
async fn restore_refuses_while_the_server_runs() {
    let scene = new_scene().await;
    // A running server holds the lock of its data directory from before it
    // opens the database until it ends (`server::run`).
    let held = data_lock::acquire(scene.data()).expect("the server's lock");
    let refused = restore_scene(&scene, &scene.backup).expect_err("the server runs");
    assert!(matches!(refused, BackupError::Refused(_)), "{refused}");
    assert!(refused.to_string().contains("stop the server"), "{refused}");
    let aborted = restore::abort(scene.data()).expect_err("the server runs");
    assert!(matches!(aborted, BackupError::Refused(_)), "{aborted}");
    scene.assert_untouched("while the server runs");

    // The command says the same, and that nothing was changed.
    let said = cli::run(Command::BackupRestore {
        data_dir: scene.data().to_path_buf(),
        from: scene.backup.clone(),
        confirmed: true,
        at_least: None,
    })
    .expect_err("the server runs")
    .to_string();
    assert!(said.contains("stop the server"), "{said}");
    assert!(said.contains("not changed"), "{said}");
    scene.assert_untouched("the command while the server runs");

    // Once it has stopped, the restore goes through.
    drop(held);
    restore_scene(&scene, &scene.backup).expect("a restore");
    scene.assert_restored("after the server stopped");
}

#[tokio::test]
async fn restore_refuses_without_opaque_setup_or_with_a_wrong_fingerprint() {
    let scene = new_scene().await;

    // No `opaque_setup` in the set.
    let (_without, without) = copy_of_backup(&scene, "no-setup");
    std::fs::remove_file(without.join(ferret_server_auth::OPAQUE_SETUP_FILE)).expect("remove");
    let refused = restore_scene(&scene, &without).expect_err("no set-up");
    assert!(matches!(refused, BackupError::Verify(_)), "{refused}");
    scene.assert_untouched("a set without opaque_setup");

    // The set-up of another server, with a manifest that names it: the
    // database still remembers its own.
    let other = TestApp::new().await;
    add_account_to_app(&other, 1).await;
    let other_cfg = cfg(&other);
    let other_set = other_cfg
        .dir
        .join(make(&other, &other_cfg, T1).await.expect("a set").name);
    let (_swapped, swapped) = copy_of_backup(&scene, "swapped-setup");
    std::fs::copy(
        other_set.join(ferret_server_auth::OPAQUE_SETUP_FILE),
        swapped.join(ferret_server_auth::OPAQUE_SETUP_FILE),
    )
    .expect("swap");
    let other_manifest: Manifest =
        serde_json::from_slice(&std::fs::read(other_set.join(MANIFEST_FILE)).expect("a manifest"))
            .expect("parses");
    reseal(&swapped);
    let path = swapped.join(MANIFEST_FILE);
    let mut manifest: Manifest =
        serde_json::from_slice(&std::fs::read(&path).expect("a manifest")).expect("parses");
    manifest.setup_fingerprint = other_manifest.setup_fingerprint;
    std::fs::write(&path, serde_json::to_vec(&manifest).expect("json")).expect("write");
    let refused = restore_scene(&scene, &swapped).expect_err("another set-up");
    assert_eq!(
        refused,
        BackupError::Verify("the OPAQUE set-up does not match the fingerprint in the database")
    );
    scene.assert_untouched("a set with another set-up");

    // The right set-up, but a manifest that names another fingerprint.
    let (_named, named) = copy_of_backup(&scene, "wrong-fingerprint");
    let path = named.join(MANIFEST_FILE);
    let mut manifest: Manifest =
        serde_json::from_slice(&std::fs::read(&path).expect("a manifest")).expect("parses");
    manifest.setup_fingerprint = "00".repeat(32);
    std::fs::write(&path, serde_json::to_vec(&manifest).expect("json")).expect("write");
    let refused = restore_scene(&scene, &named).expect_err("a wrong fingerprint");
    assert!(matches!(refused, BackupError::Verify(_)), "{refused}");
    scene.assert_untouched("a manifest with a wrong fingerprint");

    // The good set still goes through.
    restore_scene(&scene, &scene.backup).expect("a restore");
    scene.assert_restored("the good set");
}

#[tokio::test]
async fn restore_refuses_a_set_that_fails_verify_or_has_newer_migrations() {
    let scene = new_scene().await;

    // A damaged database: its hash no longer matches.
    let (_damaged, damaged) = copy_of_backup(&scene, "damaged");
    let db = damaged.join(DB_FILE);
    let mut bytes = std::fs::read(&db).expect("the copy");
    let last = bytes.len() - 1;
    bytes[last] ^= 0xff;
    std::fs::write(&db, bytes).expect("damage");
    let refused = restore_scene(&scene, &damaged).expect_err("damaged");
    assert!(matches!(refused, BackupError::Verify(_)), "{refused}");
    scene.assert_untouched("a damaged set");

    // A stray `-wal` beside the database of the set.
    let (_stray, stray) = copy_of_backup(&scene, "stray-wal");
    std::fs::write(stray.join(format!("{DB_FILE}-wal")), b"not ours").expect("a stray file");
    let refused = restore_scene(&scene, &stray).expect_err("a stray file");
    assert!(matches!(refused, BackupError::Verify(_)), "{refused}");
    scene.assert_untouched("a set with a stray -wal");

    // Made by a newer build: a migration this build does not know.
    let (_newer, newer) = copy_of_backup(&scene, "newer");
    change_set(
        &newer,
        "INSERT INTO schema_migrations (name) VALUES ('9999_from_a_newer_build.sql');",
    );
    let refused = restore_scene(&scene, &newer).expect_err("newer");
    assert_eq!(
        refused,
        BackupError::Verify(
            "the set was made by a newer build (it has a migration this build does not know)"
        )
    );
    scene.assert_untouched("a set from a newer build");

    // Not a set at all, and a set that is not there.
    let refused = restore_scene(&scene, scene.data()).expect_err("the data directory");
    assert!(matches!(refused, BackupError::Verify(_)), "{refused}");
    let refused = restore_scene(&scene, &scene.data().join("no-such-set")).expect_err("missing");
    assert!(matches!(refused, BackupError::Io(_)), "{refused}");
    scene.assert_untouched("no set");
}

#[tokio::test]
async fn restore_migrates_an_older_set_before_the_bump() {
    let scene = new_scene().await;
    // A set from before the sign-in codes and the re-auth column: the bump
    // revokes sign-in codes, so it can only run after the migrations.
    let (_older, older) = copy_of_backup(&scene, "older");
    change_set(
        &older,
        "DROP TABLE sign_in_codes; DROP TABLE user_emails; \
         DELETE FROM schema_migrations WHERE name = 'kit/0008_sign_in_codes.sql'; \
         ALTER TABLE ferret_sessions DROP COLUMN reauth_at; \
         DELETE FROM schema_migrations WHERE name = '0007_reauth.sql';",
    );
    set::verify(&older, &set::build_migrations()).expect("an older set is a good set");

    let report = restore_scene(&scene, &older).expect("a restore");
    assert_eq!(report.vaults, 1);
    let db = scene.data().join(DB_FILE);
    let conn = peek(&db);
    let applied: Vec<String> = conn
        .prepare("SELECT name FROM schema_migrations")
        .expect("prepare")
        .query_map([], |row| row.get(0))
        .expect("query")
        .map(|r| r.expect("a name"))
        .collect();
    for name in set::build_migrations() {
        assert!(applied.iter().any(|a| a == name), "{name} is applied");
    }
    let has_column: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM pragma_table_info('ferret_sessions') WHERE name = 'reauth_at'",
            [],
            |r| r.get(0),
        )
        .expect("a count");
    assert_eq!(has_column, 1);
    assert_eq!(count(&db, "SELECT COUNT(*) FROM sign_in_codes"), 0);
    drop(conn);
    assert_eq!(epochs(&db), [u64::try_from(NOW).unwrap()]);

    // And the server starts on it.
    let state = start_on(scene.data()).await.expect("the server starts");
    drop(state);
}

// ---------------------------------------------------------------- a kill at every step

/// The live files of the data directory are the old ones, the restored ones or
/// (between the two moves) none: never a mix.
fn assert_old_or_new(scene: &Scene, step: &str) {
    let live = live_files(scene.data());
    if live == scene.before {
        return;
    }
    if live.is_empty() {
        assert_eq!(step, "moved_aside", "no live files only between the moves");
        assert_eq!(
            live_files(&scene.aside()),
            scene.before,
            "{step}: the old files"
        );
        return;
    }
    assert_eq!(step, "placed", "{step}: the data directory changed");
    assert_eq!(accounts(scene.data()), 1, "{step}: the restored database");
    for name in SECRET_FILES {
        assert_eq!(
            std::fs::read(scene.data().join(name)).expect("a file"),
            std::fs::read(scene.backup.join(name)).expect("the set's"),
            "{step}: {name}"
        );
    }
    assert_eq!(
        live_files(&scene.aside()),
        scene.before,
        "{step}: the old files"
    );
}

#[tokio::test]
async fn a_kill_after_each_step_leaves_either_the_old_data_or_a_server_that_refuses_to_start() {
    for step in RESTORE_STEPS {
        let scene = new_scene().await;
        let stopped = restore::restore_until(scene.data(), &scene.backup, None, NOW, step)
            .unwrap_or_else(|e| panic!("{step}: {e}"));
        assert_eq!(stopped, None, "{step}: stopped");
        assert_eq!(marker(scene.data())["step"], step, "{step}: the marker");
        assert_old_or_new(&scene, step);
        assert_start_refused(scene.data(), step).await;
        // The commands that change the database refuse too.
        let bump = cli::run(Command::RestoreEpochBump {
            data_dir: scene.data().to_path_buf(),
            confirmed: true,
            at_least: None,
        })
        .expect_err("a restore is in progress");
        assert!(bump.to_string().contains(RESTORE_MARKER), "{step}: {bump}");
        // A restore of another set does not mix in.
        let (_other, other) = copy_of_backup(&scene, "other");
        let refused = restore_scene(&scene, &other).expect_err("another set");
        assert!(
            refused.to_string().contains("another set"),
            "{step}: {refused}"
        );
        assert_eq!(marker(scene.data())["step"], step, "{step}: unchanged");
    }
}

#[tokio::test]
async fn rerunning_after_a_kill_finishes_the_restore() {
    for step in RESTORE_STEPS {
        let scene = new_scene().await;
        restore::restore_until(scene.data(), &scene.backup, None, NOW, step)
            .unwrap_or_else(|e| panic!("{step}: {e}"));
        let report = restore_scene(&scene, &scene.backup).unwrap_or_else(|e| panic!("{step}: {e}"));
        assert_eq!(report.vaults, 1, "{step}");
        assert_eq!(report.restore_epoch, u64::try_from(NOW).unwrap(), "{step}");
        assert_eq!(report.moved_aside, scene.aside(), "{step}");
        scene.assert_restored(step);
    }

    // A kill half way through the moves: one old file moved aside, the rest
    // not yet.
    let scene = new_scene().await;
    restore::restore_until(scene.data(), &scene.backup, None, NOW, "bumped").expect("stopped");
    std::fs::create_dir(scene.aside()).expect("the folder");
    std::fs::rename(scene.data().join(DB_FILE), scene.aside().join(DB_FILE)).expect("a move");
    assert_start_refused(scene.data(), "half moved aside").await;
    restore_scene(&scene, &scene.backup).expect("finished");
    scene.assert_restored("after half the moves aside");

    // A kill half way through putting the files in place.
    let scene = new_scene().await;
    restore::restore_until(scene.data(), &scene.backup, None, NOW, "moved_aside").expect("stopped");
    std::fs::rename(scene.staging().join(DB_FILE), scene.data().join(DB_FILE)).expect("a move");
    assert_start_refused(scene.data(), "half placed").await;
    restore_scene(&scene, &scene.backup).expect("finished");
    scene.assert_restored("after half the files were placed");

    // The server starts on what the second run left.
    let state = start_on(scene.data()).await.expect("the server starts");
    drop(state);
}

#[tokio::test]
async fn abort_after_a_kill_puts_the_old_data_back() {
    for step in RESTORE_STEPS {
        let scene = new_scene().await;
        restore::restore_until(scene.data(), &scene.backup, None, NOW, step)
            .unwrap_or_else(|e| panic!("{step}: {e}"));
        restore::abort(scene.data()).unwrap_or_else(|e| panic!("{step}: {e}"));
        scene.assert_untouched(step);
        // Nothing left to undo.
        assert!(restore::abort(scene.data()).is_err(), "{step}");
    }

    // Half way through the moves aside.
    let scene = new_scene().await;
    restore::restore_until(scene.data(), &scene.backup, None, NOW, "bumped").expect("stopped");
    std::fs::create_dir(scene.aside()).expect("the folder");
    for name in [DB_FILE, ferret_server_auth::OPAQUE_SETUP_FILE] {
        std::fs::rename(scene.data().join(name), scene.aside().join(name)).expect("a move");
    }
    restore::abort(scene.data()).expect("undone");
    scene.assert_untouched("half moved aside");

    // Half way through putting the files in place.
    let scene = new_scene().await;
    restore::restore_until(scene.data(), &scene.backup, None, NOW, "moved_aside").expect("stopped");
    std::fs::rename(scene.staging().join(DB_FILE), scene.data().join(DB_FILE)).expect("a move");
    restore::abort(scene.data()).expect("undone");
    scene.assert_untouched("half placed");

    // The command, and the server on the old data.
    restore::restore_until(scene.data(), &scene.backup, None, NOW, "placed").expect("stopped");
    let said = cli::run(Command::BackupAbort {
        data_dir: scene.data().to_path_buf(),
        confirmed: true,
    })
    .expect("undone");
    assert_eq!(said, "the restore was undone: the old files are back");
    scene.assert_untouched("the command");
    let state = start_on(scene.data()).await.expect("the server starts");
    let accounts: i64 = state
        .vault_db
        .with_conn(|conn| {
            Ok(conn.query_row("SELECT COUNT(*) FROM ferret_accounts", [], |r| r.get(0))?)
        })
        .await
        .expect("a count");
    assert_eq!(accounts, 2, "the old data");
}

#[tokio::test]
async fn the_marker_is_removed_only_after_the_bump_commits_and_the_files_are_in_place() {
    let scene = new_scene().await;
    let data = scene.data();
    let mut seen = Vec::new();
    for step in RESTORE_STEPS {
        restore::restore_until(data, &scene.backup, None, NOW, step)
            .unwrap_or_else(|e| panic!("{step}: {e}"));
        let now = marker(data);
        assert_eq!(now["step"], step);
        assert_eq!(now["format"], restore::MARKER_FORMAT);
        // What the bump did is in the marker from the step of the bump on.
        let bumped = RESTORE_STEPS
            .iter()
            .position(|s| *s == step)
            .expect("a step")
            >= RESTORE_STEPS
                .iter()
                .position(|s| *s == "bumped")
                .expect("bumped");
        assert_eq!(!now["done"].is_null(), bumped, "{step}: {now}");
        seen.push(step);
    }
    // After `placed` the bump has committed and the files are in place, and
    // the marker is still there: only the end of the run removes it.
    assert_eq!(seen, RESTORE_STEPS);
    assert_eq!(accounts(data), 1);
    assert!(data.join(RESTORE_MARKER).exists());
    restore_scene(&scene, &scene.backup).expect("finished");
    scene.assert_restored("the end");

    // A bump that does not commit (a vault at the largest epoch) moves
    // nothing: the old data stays live, so no marker is left either.
    let scene = new_scene().await;
    let (_full, full) = copy_of_backup(&scene, "full-epoch");
    change_set(
        &full,
        &format!(
            "UPDATE ferret_vaults SET restore_epoch = {};",
            ferret_server::wire::MAX_JSON_INT
        ),
    );
    reseal_vaults(&full);
    let refused = restore_scene(&scene, &full).expect_err("the bump fails");
    assert_eq!(
        refused,
        BackupError::Refused("restore_epoch is at its largest value")
    );
    scene.assert_untouched("a bump that failed");
    let state = start_on(scene.data()).await.expect("the old data serves");
    drop(state);
}

/// Writes the vaults of the manifest again from the database (after a change
/// of their epochs).
fn reseal_vaults(set_dir: &Path) {
    let path = set_dir.join(MANIFEST_FILE);
    let mut manifest: Manifest =
        serde_json::from_slice(&std::fs::read(&path).expect("a manifest")).expect("parses");
    let epochs = epochs(&set_dir.join(DB_FILE));
    for (vault, epoch) in manifest.vaults.iter_mut().zip(epochs) {
        vault.restore_epoch = epoch;
    }
    std::fs::write(&path, serde_json::to_vec_pretty(&manifest).expect("json")).expect("write");
}

// ---------------------------------------------------------------- the restore epoch

#[tokio::test]
async fn the_restored_epoch_is_above_every_epoch_seen_before() {
    let scene = new_scene().await;
    // The data that is there was bumped ahead of the clock (an `--at-least`
    // earlier, or a clock that ran fast): its clients saw this epoch.
    let ahead = u64::try_from(NOW).unwrap() + 5000;
    {
        let mut conn = Connection::open(scene.data().join(DB_FILE)).expect("open");
        reconcile::bump(&mut conn, Some(ahead), NOW).expect("a bump");
    }
    let report = restore_scene(&scene, &scene.backup).expect("a restore");
    assert_eq!(report.restore_epoch, ahead + 1);
    assert_eq!(epochs(&scene.data().join(DB_FILE)), [ahead + 1]);
    // Above the epoch of the backup, the time and the data that was there.
    let backup_epochs = epochs(&scene.backup.join(DB_FILE));
    assert!(backup_epochs.iter().all(|e| *e < report.restore_epoch));
    assert!(report.restore_epoch > u64::try_from(NOW).unwrap());

    // A backup ahead of everything: one more than its own epoch.
    let scene = new_scene().await;
    let (_high, high) = copy_of_backup(&scene, "high");
    let far = u64::try_from(NOW).unwrap() + 90_000;
    change_set(
        &high,
        &format!("UPDATE ferret_vaults SET restore_epoch = {far};"),
    );
    reseal_vaults(&high);
    let report = restore_scene(&scene, &high).expect("a restore");
    assert_eq!(report.restore_epoch, far + 1);
}

#[tokio::test]
async fn at_least_raises_it_further() {
    let scene = new_scene().await;
    let wanted = u64::try_from(NOW).unwrap() + 777_777;
    let report =
        restore::restore(scene.data(), &scene.backup, Some(wanted), NOW).expect("a restore");
    assert_eq!(report.restore_epoch, wanted);
    assert_eq!(epochs(&scene.data().join(DB_FILE)), [wanted]);

    // A lower one changes nothing: the time is higher.
    let scene = new_scene().await;
    let report = restore::restore(scene.data(), &scene.backup, Some(3), NOW).expect("a restore");
    assert_eq!(report.restore_epoch, u64::try_from(NOW).unwrap());

    // One above what a JSON integer carries is refused before anything.
    let scene = new_scene().await;
    let refused = restore::restore(
        scene.data(),
        &scene.backup,
        Some(ferret_server::wire::MAX_JSON_INT + 1),
        NOW,
    )
    .expect_err("too large");
    assert!(matches!(refused, BackupError::Refused(_)), "{refused}");
    scene.assert_untouched("a lowest epoch that is too large");
}

#[tokio::test]
async fn restore_keeps_restore_seq_and_freezes_the_rows() {
    let scene = new_scene().await;
    let manifest: Manifest = serde_json::from_slice(
        &std::fs::read(scene.backup.join(MANIFEST_FILE)).expect("a manifest"),
    )
    .expect("parses");
    let backup_seq = manifest.vaults[0].seq;
    // The rows of the vault in the backup.
    let backup_rows: Vec<StoredRow> = {
        let conn = peek(&scene.backup.join(DB_FILE));
        let mut stmt = conn
            .prepare("SELECT item_id, rev, seq, blob FROM ferret_items ORDER BY item_id")
            .expect("prepare");
        stmt.query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)))
            .expect("query")
            .map(|r| r.expect("a row"))
            .collect()
    };
    assert!(backup_rows.len() >= 3, "the manifest and two items");

    let report = restore_scene(&scene, &scene.backup).expect("a restore");
    let conn = peek(&scene.data().join(DB_FILE));
    let page = restore_rows(&conn, &scene.first.vault_id, None, 2000).expect("the rows");
    assert_eq!(page.restore_epoch, report.restore_epoch);
    assert_eq!(
        page.restore_seq, backup_seq,
        "restore_seq is the seq of the backup"
    );
    assert!(!page.has_more);
    assert_eq!(page.rows.len(), backup_rows.len());
    for (row, (id, rev, seq, blob)) in page.rows.iter().zip(&backup_rows) {
        assert_eq!(row.item_id.as_bytes().as_slice(), id.as_slice());
        assert_eq!(row.rev, u64::try_from(*rev).unwrap());
        assert_eq!(row.seq, u64::try_from(*seq).unwrap());
        let hash: Option<[u8; 32]> = blob.as_ref().map(|b| Sha256::digest(b).into());
        assert_eq!(row.blob_sha256, hash);
    }
}

#[tokio::test]
async fn restore_epoch_bump_uses_the_same_rule() {
    let scene = new_scene().await;
    let at_least = 4_000_000_000_u64;

    // The command on a copy of the data, and the restore of the backup, with
    // the same lowest epoch: both give it.
    let copy = Dir::new("bump-copy");
    copy_data(&scene.backup, copy.path());
    let said = cli::run(Command::RestoreEpochBump {
        data_dir: copy.path().to_path_buf(),
        confirmed: true,
        at_least: Some(at_least),
    })
    .expect("a bump");
    assert!(
        said.starts_with(&format!(
            "restore epoch is now {at_least} (1 vault raised); "
        )),
        "{said}"
    );
    let report =
        restore::restore(scene.data(), &scene.backup, Some(at_least), NOW).expect("a restore");
    assert_eq!(report.restore_epoch, at_least);
    assert_eq!(
        epochs(&copy.path().join(DB_FILE)),
        epochs(&scene.data().join(DB_FILE))
    );

    // Both again: one more than the stored epoch, which is above the time.
    let said = cli::run(Command::RestoreEpochBump {
        data_dir: copy.path().to_path_buf(),
        confirmed: true,
        at_least: None,
    })
    .expect("a bump");
    // The first bump ended everything in the copy, so the second ends nothing.
    assert_eq!(
        said,
        format!(
            "restore epoch is now {} (1 vault raised); 0 sessions ended, 0 sign-in codes revoked, 0 devices signed out",
            at_least + 1
        )
    );
    let mut conn = Connection::open(scene.data().join(DB_FILE)).expect("open");
    assert_eq!(
        reconcile::bump_restore_epoch(&mut conn, None, NOW).expect("a bump"),
        at_least + 1
    );
}

// ---------------------------------------------------------------- what a restore ends

#[tokio::test]
async fn every_session_and_pending_code_ends_and_a_session_revoked_after_the_backup_stays_dead() {
    let app = TestApp::new().await;
    let first = add_account_to_app(&app, 1).await;
    let live = issue(&app, first.user_id, Origin::Vault, SessionScope::Full, 1).await;
    let admin = issue(&app, first.user_id, Origin::Admin, SessionScope::Full, 2).await;
    let user = first.user_id;
    app.state
        .vault_db
        .with_conn(move |conn| {
            conn.execute(
                "INSERT INTO sign_in_codes (user_id, code_hash, expires_at) \
                 VALUES (?1, randomblob(32), datetime('now', '+1 day'))",
                [user],
            )?;
            Ok(())
        })
        .await
        .expect("a pending code");
    let version_in_backup = support::session::session_version(&app, user).await;
    let cfg = cfg(&app);
    let one = make(&app, &cfg, T1).await.expect("the backup");
    let backup = cfg.dir.join(&one.name);

    // After the backup: the session is signed out and the code is used.
    let sid = live.sid;
    app.state
        .vault_db
        .with_conn(move |conn| {
            conn.execute(
                "UPDATE ferret_sessions SET revoked_at = ?1 WHERE sid_hash = ?2",
                rusqlite::params![T1 + 1, sid.0.as_slice()],
            )?;
            conn.execute("UPDATE sign_in_codes SET used_at = datetime('now')", [])?;
            Ok(())
        })
        .await
        .expect("signed out");
    let two = make(&app, &cfg, T2).await.expect("the later set");
    let data = Dir::new("sessions");
    copy_data(&cfg.dir.join(&two.name), data.path());

    let report = restore::restore(data.path(), &backup, None, NOW).expect("a restore");
    assert_eq!(
        report.sessions_ended, 2,
        "both sessions were live in the backup"
    );

    let db = data.path().join(DB_FILE);
    assert_eq!(
        count(
            &db,
            "SELECT COUNT(*) FROM ferret_sessions WHERE revoked_at IS NULL"
        ),
        0
    );
    assert_eq!(
        count(
            &db,
            "SELECT COUNT(*) FROM sign_in_codes WHERE used_at IS NULL AND revoked_at IS NULL"
        ),
        0,
        "the code that was pending in the backup is revoked"
    );
    assert_eq!(count(&db, "SELECT COUNT(*) FROM ferret_login_states"), 0);
    assert_eq!(
        count(
            &db,
            &format!("SELECT session_version FROM users WHERE id = {user}")
        ),
        version_in_backup + 1
    );

    // On the restored server neither session gets in.
    let state = start_on(data.path()).await.expect("the server starts");
    for (jar, what) in [
        (&live.jar, "the session revoked after the backup"),
        (&admin.jar, "the admin session"),
    ] {
        let res = vault_get(&state, jar, "/api/sync/items").await;
        assert_eq!(
            res.status,
            StatusCode::UNAUTHORIZED,
            "{what}: {}",
            res.text()
        );
    }
    // A new sign-in does.
    let jar = sign_in(&state, user).await;
    let res = vault_get(&state, &jar, "/api/sync/items").await;
    assert_eq!(res.status, StatusCode::OK, "{}", res.text());
}

#[tokio::test]
async fn the_server_starts_on_the_restored_data_and_a_client_sees_server_restored() {
    let scene = new_scene().await;
    // What a client of the old server remembers.
    let client = issue(
        &scene.app,
        scene.first.user_id,
        Origin::Vault,
        SessionScope::Full,
        1,
    )
    .await;
    let seen = scene
        .app
        .call_raw(Which::Vault, {
            let mut request = Request::builder()
                .method("GET")
                .uri("/api/sync/changes")
                .body(Body::empty())
                .expect("a request");
            request.headers_mut().insert(
                header::COOKIE,
                client
                    .jar
                    .header()
                    .expect("cookies")
                    .parse()
                    .expect("a header"),
            );
            request
        })
        .await
        .json();
    let seen_epoch = seen["restore_epoch"].as_u64().expect("an epoch");
    let seen_seq = seen["latest_seq"].as_u64().expect("a seq");

    let report = restore_scene(&scene, &scene.backup).expect("a restore");
    // The server starts: `opaque_setup` and the other secret files are in place
    // and match the database.
    let state = start_on(scene.data()).await.expect("the server starts");
    let jar = sign_in(&state, scene.first.user_id).await;
    for uri in ["/api/sync/changes", "/api/sync/items"] {
        let res = vault_get(&state, &jar, uri).await;
        assert_eq!(res.status, StatusCode::OK, "{uri}: {}", res.text());
        let body = res.json();
        // A higher epoch with a feed that is not ahead: "the server was
        // restored from an older backup".
        assert_eq!(
            body["restore_epoch"].as_u64(),
            Some(report.restore_epoch),
            "{uri}"
        );
        assert!(report.restore_epoch > seen_epoch, "{uri}");
    }
    let changes = vault_get(&state, &jar, "/api/sync/changes").await.json();
    assert!(changes["latest_seq"].as_u64().expect("a seq") <= seen_seq);
    let rows = vault_get(&state, &jar, "/api/sync/restore-rows").await;
    assert_eq!(rows.status, StatusCode::OK, "{}", rows.text());
    assert_eq!(
        rows.json()["restore_epoch"].as_u64(),
        Some(report.restore_epoch)
    );
}

#[tokio::test]
async fn the_wal_and_shm_of_the_current_data_never_mix_with_the_restored_file() {
    let scene = new_scene().await;
    // The server that wrote the data that is there was killed: a write sits in
    // its WAL, not yet in the database file, and so does a bump of the restore
    // epoch ahead of the clock.
    let mut conn = Connection::open(scene.data().join(DB_FILE)).expect("open");
    let _: String = conn
        .query_row("PRAGMA journal_mode = WAL", [], |r| r.get(0))
        .expect("WAL");
    conn.execute_batch(
        "PRAGMA wal_autocheckpoint = 0; \
         INSERT INTO ferret_meta (key, value) VALUES ('only_in_the_wal', x'01');",
    )
    .expect("a write");
    let ahead = u64::try_from(NOW).unwrap() + 9000;
    reconcile::bump(&mut conn, Some(ahead), NOW).expect("a bump");
    // No close: a close would fold the WAL into the file.
    std::mem::forget(conn);
    let wal = scene.data().join(format!("{DB_FILE}-wal"));
    let shm = scene.data().join(format!("{DB_FILE}-shm"));
    assert!(wal.exists() && shm.exists());
    let before = live_files(scene.data());

    let report = restore_scene(&scene, &scene.backup).expect("a restore");
    // The epoch in the WAL counts.
    assert_eq!(report.restore_epoch, ahead + 1);
    assert!(!report.seen_epoch_unknown);
    assert!(
        !wal.exists() && !shm.exists(),
        "the old -wal and -shm are gone"
    );
    assert!(!scene.data().join(format!("{DB_FILE}-journal")).exists());
    // They moved with their database. The `-shm` is moved too, but it is the
    // index of the WAL that a reader of it updates (the restore read the epoch
    // through it), not data: only that it went along is compared.
    let without_shm = |mut files: BTreeMap<String, String>| {
        files.remove(&format!("{DB_FILE}-shm"));
        files
    };
    assert_eq!(
        without_shm(live_files(&scene.aside())),
        without_shm(before),
        "they moved with their database"
    );
    assert!(scene.aside().join(format!("{DB_FILE}-shm")).exists());
    let in_the_wal = "SELECT COUNT(*) FROM ferret_meta WHERE key = 'only_in_the_wal'";
    assert_eq!(count(&scene.data().join(DB_FILE), in_the_wal), 0);

    // The old database and its WAL still belong together.
    let old = Dir::new("old-with-wal");
    for name in [DB_FILE.to_string(), format!("{DB_FILE}-wal")] {
        std::fs::copy(scene.aside().join(&name), old.path().join(&name)).expect("a copy");
    }
    let conn = Connection::open(old.path().join(DB_FILE)).expect("open the old one");
    let found: i64 = conn
        .query_row(in_the_wal, [], |r| r.get(0))
        .expect("a count");
    assert_eq!(found, 1, "the write is in the old database's WAL");
    drop(conn);

    // The server on the restored data does not see it either.
    let state = start_on(scene.data()).await.expect("the server starts");
    let found: i64 = state
        .vault_db
        .with_conn(move |conn| Ok(conn.query_row(in_the_wal, [], |r| r.get(0))?))
        .await
        .expect("a count");
    assert_eq!(found, 0);
}

#[tokio::test]
async fn the_report_holds_no_secret() {
    let scene = new_scene().await;
    let client = issue(
        &scene.app,
        scene.first.user_id,
        Origin::Vault,
        SessionScope::Full,
        1,
    )
    .await;
    let (log, guard) = capture_log();
    // A run that stops before the end, so the marker can be read, and the
    // command that finishes it.
    restore::restore_until(scene.data(), &scene.backup, None, NOW, "placed").expect("stopped");
    let marker_text = std::fs::read_to_string(scene.data().join(RESTORE_MARKER)).expect("marker");
    let report = restore_scene(&scene, &scene.backup).expect("finished");
    drop(guard);
    let said = {
        let scene = new_scene().await;
        cli::run(Command::BackupRestore {
            data_dir: scene.data().to_path_buf(),
            from: scene.backup.clone(),
            confirmed: true,
            at_least: None,
        })
        .expect("a restore")
    };
    let logged = log.text();
    assert!(
        logged.contains("restore step done"),
        "the capture works: {logged}"
    );
    assert!(
        said.starts_with("restored 1 vault: restore epoch is now "),
        "{said}"
    );

    let manifest: Manifest = serde_json::from_slice(
        &std::fs::read(scene.backup.join(MANIFEST_FILE)).expect("a manifest"),
    )
    .expect("parses");
    let mut secrets: Vec<String> = vec![
        manifest.setup_fingerprint.clone(),
        support::session::hex(&client.sid.0),
        client.secret.clone(),
        support::session::hex(scene.first.vault_id.as_bytes()),
        "user1@example.com".to_string(),
    ];
    for name in SECRET_FILES {
        let bytes = std::fs::read(scene.backup.join(name)).expect("a secret file");
        secrets.push(sha(&bytes));
        secrets.push(support::session::hex(&bytes[..16]));
        if let Ok(text) = std::str::from_utf8(&bytes) {
            secrets.extend(
                text.split_whitespace()
                    .filter(|part| part.len() >= 16)
                    .map(str::to_string),
            );
        }
    }
    let texts = [
        ("the report", format!("{report:?}")),
        ("the command", said),
        ("the marker", marker_text),
        ("the log", logged),
    ];
    for (what, text) in &texts {
        for secret in &secrets {
            assert!(
                !text.contains(secret.as_str()),
                "{what} holds a secret: {text}"
            );
        }
    }
}

// ---------------------------------------------------------------- an abort that is cut off

/// The marker says that an abort is under way.
fn undoing(dir: &Path) -> bool {
    marker(dir)["undoing"] == Value::Bool(true)
}

#[tokio::test]
async fn an_abort_cut_off_after_each_of_its_moves_finishes_when_run_again() {
    for step in RESTORE_STEPS {
        for cut in restore::ABORT_STEPS {
            let why = format!("restore cut after {step}, abort cut after {cut}");
            let scene = new_scene().await;
            restore::restore_until(scene.data(), &scene.backup, None, NOW, step)
                .unwrap_or_else(|e| panic!("{why}: {e}"));
            restore::abort_until(scene.data(), cut).unwrap_or_else(|e| panic!("{why}: {e}"));
            if cut == "unmarked" {
                // The old data is back and the marker is gone: only copies are
                // left, and the server starts on the old data.
                assert_eq!(live_files(scene.data()), scene.before, "{why}");
                assert!(!scene.data().join(RESTORE_MARKER).exists(), "{why}");
                assert!(
                    restore::abort(scene.data()).is_err(),
                    "{why}: nothing to undo"
                );
                let state = start_on(scene.data()).await.expect("the server starts");
                drop(state);
                continue;
            }
            assert!(undoing(scene.data()), "{why}");
            assert_start_refused(scene.data(), &why).await;
            // The second abort finishes, and never takes the old files for
            // restored ones.
            restore::abort(scene.data()).unwrap_or_else(|e| panic!("{why}: {e}"));
            scene.assert_untouched(&why);
        }
    }

    // Cut off half way through taking the restored files back (the marker does
    // not say `undoing` yet).
    let scene = new_scene().await;
    restore::restore_until(scene.data(), &scene.backup, None, NOW, "placed").expect("stopped");
    std::fs::rename(scene.data().join(DB_FILE), scene.staging().join(DB_FILE)).expect("a move");
    assert!(!undoing(scene.data()));
    restore::abort(scene.data()).expect("undone");
    scene.assert_untouched("half the restored files taken back");

    // Cut off half way through putting the old files back.
    let scene = new_scene().await;
    restore::restore_until(scene.data(), &scene.backup, None, NOW, "placed").expect("stopped");
    restore::abort_until(scene.data(), "undoing").expect("stopped");
    std::fs::rename(scene.aside().join(DB_FILE), scene.data().join(DB_FILE)).expect("a move");
    restore::abort(scene.data()).expect("undone");
    scene.assert_untouched("half the old files put back");
    let state = start_on(scene.data()).await.expect("the server starts");
    let accounts: i64 = state
        .vault_db
        .with_conn(|conn| {
            Ok(conn.query_row("SELECT COUNT(*) FROM ferret_accounts", [], |r| r.get(0))?)
        })
        .await
        .expect("a count");
    assert_eq!(accounts, 2, "the old data");
}

#[tokio::test]
async fn a_restore_rerun_after_a_cut_off_abort_refuses() {
    for cut in ["undoing", "old_back"] {
        let scene = new_scene().await;
        restore::restore_until(scene.data(), &scene.backup, None, NOW, "placed").expect("stopped");
        restore::abort_until(scene.data(), cut).expect("stopped");
        let before = live_files(scene.data());
        let refused = restore_scene(&scene, &scene.backup).expect_err("an abort is under way");
        assert!(refused.to_string().contains("--abort"), "{cut}: {refused}");
        assert_eq!(live_files(scene.data()), before, "{cut}: nothing moved");
        assert!(undoing(scene.data()), "{cut}");
        restore::abort(scene.data()).expect("undone");
        scene.assert_untouched(cut);
    }

    // An abort cut off before the marker said `undoing`, with a restored file
    // already taken back: a rerun of the restore removes nothing and says to
    // undo it.
    let scene = new_scene().await;
    restore::restore_until(scene.data(), &scene.backup, None, NOW, "placed").expect("stopped");
    std::fs::rename(scene.data().join(DB_FILE), scene.staging().join(DB_FILE)).expect("a move");
    let refused = restore_scene(&scene, &scene.backup).expect_err("files are missing");
    assert!(refused.to_string().contains("--abort"), "{refused}");
    assert!(
        scene.staging().join(DB_FILE).exists(),
        "the staged copy is kept"
    );
    assert!(scene.data().join(RESTORE_MARKER).exists());
    restore::abort(scene.data()).expect("undone");
    scene.assert_untouched("after the refused rerun");
}

// ---------------------------------------------------------------- what the operator is told

#[tokio::test]
async fn the_epoch_of_missing_or_broken_data_is_reported_as_unknown() {
    let scene = new_scene().await;
    // No database there at all (a new host).
    let empty = Dir::new("empty-data");
    let said = cli::run(Command::BackupRestore {
        data_dir: empty.path().to_path_buf(),
        from: scene.backup.clone(),
        confirmed: true,
        at_least: None,
    })
    .expect("a restore");
    assert!(
        said.contains("\nwarning: the restore epoch of the data that was there could not be read"),
        "{said}"
    );
    assert!(said.contains("--at-least"), "{said}");

    // A broken one.
    let broken = Dir::new("broken-data");
    std::fs::write(broken.path().join(DB_FILE), b"not a database").expect("junk");
    let report = restore::restore(broken.path(), &scene.backup, None, NOW).expect("a restore");
    assert!(report.seen_epoch_unknown);
    assert_eq!(accounts(broken.path()), 1);

    // A readable one: no warning.
    let report = restore_scene(&scene, &scene.backup).expect("a restore");
    assert!(!report.seen_epoch_unknown);
}

#[tokio::test]
async fn a_higher_at_least_on_a_rerun_is_used_or_refused_never_dropped() {
    // Before the bump: the higher one is used.
    let scene = new_scene().await;
    restore::restore_until(scene.data(), &scene.backup, None, NOW, "migrated").expect("stopped");
    let wanted = u64::try_from(NOW).unwrap() + 4242;
    let report =
        restore::restore(scene.data(), &scene.backup, Some(wanted), NOW).expect("finished");
    assert_eq!(report.restore_epoch, wanted);

    // After the bump: refused, and nothing changes; without it the run ends.
    let scene = new_scene().await;
    restore::restore_until(scene.data(), &scene.backup, None, NOW, "bumped").expect("stopped");
    let refused = restore::restore(scene.data(), &scene.backup, Some(wanted), NOW)
        .expect_err("already raised");
    assert!(
        refused.to_string().contains("restore-epoch bump"),
        "{refused}"
    );
    assert_eq!(marker(scene.data())["step"], "bumped");
    // One at or below what the bump gave is fine.
    let report = restore::restore(
        scene.data(),
        &scene.backup,
        Some(u64::try_from(NOW).unwrap()),
        NOW,
    )
    .expect("finished");
    assert_eq!(report.restore_epoch, u64::try_from(NOW).unwrap());
    scene.assert_restored("after the refused --at-least");
}

// ---------------------------------------------------------------- a set that was made by hand

#[tokio::test]
async fn a_set_with_a_trigger_or_an_object_this_build_does_not_make_is_refused() {
    let scene = new_scene().await;

    // A trigger that would undo the end of the sessions.
    let (_trigger, trigger) = copy_of_backup(&scene, "trigger");
    change_set(
        &trigger,
        "CREATE TRIGGER keep_sessions AFTER UPDATE ON ferret_sessions \
         BEGIN UPDATE ferret_sessions SET revoked_at = NULL; END;",
    );
    let refused = restore_scene(&scene, &trigger).expect_err("a trigger");
    assert_eq!(
        refused,
        BackupError::Verify("the database copy holds a trigger or a view")
    );
    set::verify(&trigger, &set::build_migrations()).expect_err("verify says it too");
    scene.assert_untouched("a set with a trigger");

    // A view.
    let (_view, view) = copy_of_backup(&scene, "view");
    change_set(
        &view,
        "CREATE VIEW everything AS SELECT * FROM ferret_items;",
    );
    let refused = restore_scene(&scene, &view).expect_err("a view");
    assert!(matches!(refused, BackupError::Verify(_)), "{refused}");
    scene.assert_untouched("a set with a view");

    // A table and an index this build does not make: the schema is compared
    // after the migrations, and the staged copy and the marker go.
    for (name, sql) in [
        ("extra-table", "CREATE TABLE extra (x);"),
        (
            "extra-index",
            "CREATE INDEX extra_index ON ferret_items (size);",
        ),
    ] {
        let (_odd, odd) = copy_of_backup(&scene, name);
        change_set(&odd, sql);
        set::verify(&odd, &set::build_migrations()).expect("a set that verifies");
        let refused = restore_scene(&scene, &odd).expect_err("another schema");
        assert_eq!(
            refused,
            BackupError::Refused("the schema of the set is not the one this build makes"),
            "{name}"
        );
        scene.assert_untouched(name);
    }

    // The set as the server made it goes through.
    restore_scene(&scene, &scene.backup).expect("a restore");
    scene.assert_restored("the server's own set");
}

#[cfg(unix)]
#[tokio::test]
async fn the_command_runs_only_as_the_user_that_owns_the_data_directory() {
    use std::os::unix::fs::MetadataExt as _;
    let scene = new_scene().await;
    let me = std::fs::metadata(scene.data()).expect("the folder").uid();
    // Only a test run as root can give the folder to another user.
    if rustix::process::geteuid().is_root() {
        std::os::unix::fs::chown(scene.data(), Some(1000), None).expect("chown");
        let refused = restore_scene(&scene, &scene.backup).expect_err("another user");
        assert!(refused.to_string().contains("user that owns"), "{refused}");
        let refused = restore::abort(scene.data()).expect_err("another user");
        assert!(refused.to_string().contains("user that owns"), "{refused}");
        scene.assert_untouched("as another user");
        std::os::unix::fs::chown(scene.data(), Some(me), None).expect("chown back");
    }
    restore_scene(&scene, &scene.backup).expect("a restore");
    scene.assert_restored("as the user of the data directory");
}
