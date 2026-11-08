//! `restore_epoch` and `ferret restore-epoch bump`. Spec: Fase 1 § 8.6,
//! "Legitimate rollbacks".
//!
//! The command is run as the real binary (`CARGO_BIN_EXE_ferret`) with an empty
//! environment, because what it must not need (a listener, the URL settings) and
//! what it must refuse (a live server, a missing confirmation) are properties of
//! the process.

mod support;

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use axum::body::Body;
use axum::http::{Request, StatusCode};
use ferret_server::auth::session::Origin;
use ferret_server::cli::{self, Command as Cmd};
use ferret_server::config::Config;
use ferret_server::data_lock;
use ferret_server::error::StoreError;
use ferret_server::product;
use ferret_server::vault::reconcile::{bump_all_vaults, bump_restore_epoch};
use ferret_server::wire::MAX_JSON_INT;
use ferret_server_auth::SessionScope;
use rusqlite::Connection;
use serde_json::Value;
use support::accounts::{add_account, add_account_to_app};
use support::session::issue;
use support::{ADMIN_URL, TestApp, VAULT_URL, Which};
use vole_kit::db::migrate::apply_migrations;

const BIN: &str = env!("CARGO_BIN_EXE_ferret");
const NOW: i64 = 1_793_491_200;

fn migrated() -> Connection {
    product::install();
    let mut conn = Connection::open_in_memory().expect("open");
    conn.execute_batch("PRAGMA foreign_keys = ON;")
        .expect("pragma");
    apply_migrations(&mut conn).expect("migrations apply");
    conn
}

fn epochs(conn: &Connection) -> Vec<i64> {
    let mut stmt = conn
        .prepare("SELECT restore_epoch FROM ferret_vaults ORDER BY vault_id")
        .expect("prepare");
    stmt.query_map([], |row| row.get(0))
        .expect("query")
        .map(|r| r.expect("row"))
        .collect()
}

fn set_epoch(conn: &Connection, n: u8, epoch: i64) {
    conn.execute(
        "UPDATE ferret_vaults SET restore_epoch = ?2 WHERE vault_id = ?1",
        rusqlite::params![support::accounts::id16(0xb0, n).as_slice(), epoch],
    )
    .expect("set the epoch");
}

// ------------------------------------------------------------------ the bump

#[test]
fn bump_raises_every_vault_by_one_in_one_transaction() {
    let mut conn = migrated();
    for n in 1..=3 {
        add_account(&mut conn, n, NOW);
    }
    set_epoch(&conn, 2, 4);
    assert_eq!(epochs(&conn), [0, 4, 0]);

    let bumped = bump_all_vaults(&mut conn).expect("a bump");
    assert_eq!(bumped.vaults, 3);
    assert_eq!(bumped.restore_epoch, 5, "the highest epoch now");
    assert_eq!(epochs(&conn), [1, 5, 1]);
    assert_eq!(bump_restore_epoch(&mut conn).expect("a bump"), 6);
    assert_eq!(epochs(&conn), [2, 6, 2]);

    // One transaction: a failure on the last vault leaves every vault as it
    // was.
    conn.execute_batch(&format!(
        "CREATE TRIGGER fail_one BEFORE UPDATE ON ferret_vaults \
         WHEN NEW.vault_id = x'{}' BEGIN SELECT RAISE(ABORT, 'no'); END;",
        "b003".to_string() + &"00".repeat(14)
    ))
    .expect("a trigger");
    let before = epochs(&conn);
    assert!(bump_all_vaults(&mut conn).is_err());
    assert_eq!(epochs(&conn), before, "nothing was raised");
    conn.execute_batch("DROP TRIGGER fail_one;").expect("drop");
    assert_eq!(bump_restore_epoch(&mut conn).expect("a bump"), 7);
    assert_eq!(epochs(&conn), [3, 7, 3]);
}

#[test]
fn a_bump_without_vaults_changes_nothing_and_says_zero() {
    let mut conn = migrated();
    let bumped = bump_all_vaults(&mut conn).expect("a bump");
    assert_eq!((bumped.vaults, bumped.restore_epoch), (0, 0));
}

#[test]
fn a_vault_at_the_largest_json_integer_refuses_the_whole_bump() {
    let mut conn = migrated();
    add_account(&mut conn, 1, NOW);
    add_account(&mut conn, 2, NOW);
    set_epoch(&conn, 2, i64::try_from(MAX_JSON_INT).unwrap());
    let err = bump_all_vaults(&mut conn).expect_err("at the limit");
    assert!(matches!(err, StoreError::Invalid(_)), "{err}");
    assert_eq!(
        epochs(&conn),
        [0, i64::try_from(MAX_JSON_INT).unwrap()],
        "nothing changed"
    );
}

fn get(uri: &str, jar: &support::Jar) -> Request<Body> {
    let mut builder = Request::builder().method("GET").uri(uri);
    if let Some(cookie) = jar.header() {
        builder = builder.header("cookie", cookie);
    }
    builder.body(Body::empty()).expect("a request")
}

#[tokio::test]
async fn changes_and_listing_show_the_new_restore_epoch() {
    let app = TestApp::new().await;
    let account = add_account_to_app(&app, 1).await;
    let other = add_account_to_app(&app, 2).await;
    let jar = issue(&app, account.user_id, Origin::Vault, SessionScope::Full, 1)
        .await
        .jar;
    let other_jar = issue(&app, other.user_id, Origin::Vault, SessionScope::Full, 2)
        .await
        .jar;
    let read = |uri: &'static str, jar: support::Jar| {
        let app = &app;
        async move {
            let res = app.call_raw(Which::Vault, get(uri, &jar)).await;
            assert_eq!(res.status, StatusCode::OK, "{}", res.text());
            res.json()
        }
    };
    let field = |value: &Value| value["restore_epoch"].as_u64().expect("an epoch");
    assert_eq!(field(&read("/api/sync/changes", jar.clone()).await), 0);
    assert_eq!(field(&read("/api/sync/items", jar.clone()).await), 0);

    let bumped = app
        .state
        .vault_db
        .with_conn(bump_restore_epoch)
        .await
        .expect("a bump");
    assert_eq!(bumped, 1);

    // Both calls, in both vaults.
    for jar in [&jar, &other_jar] {
        assert_eq!(field(&read("/api/sync/changes", jar.clone()).await), 1);
        assert_eq!(field(&read("/api/sync/items", jar.clone()).await), 1);
    }
    // The epoch does not move `seq`: a bump is not a change of the feed.
    let changes = read("/api/sync/changes", jar.clone()).await;
    assert_eq!(changes["latest_seq"], serde_json::json!(1));
    // The unlock-methods answer is not the place for it, and stays as it was.
    let methods = read("/api/vault/unlock-methods", jar.clone()).await;
    assert!(methods.get("restore_epoch").is_none());
}

// ------------------------------------------------------------ the command line

/// A temporary directory, removed when dropped.
struct Dir(PathBuf);

impl Dir {
    fn new(name: &str) -> Dir {
        let path = std::env::temp_dir().join(format!(
            "ferret-restore-{name}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |d| d.as_nanos())
        ));
        std::fs::create_dir_all(&path).expect("a directory");
        Dir(path)
    }

    fn path(&self) -> &Path {
        &self.0
    }

    fn db(&self) -> Connection {
        Connection::open(self.0.join(product::DB_FILE)).expect("open the copy")
    }
}

impl Drop for Dir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// What a run of the binary printed and how it ended.
struct Ran {
    ok: bool,
    stdout: String,
    stderr: String,
}

/// Runs `ferret args` with an empty environment plus `env`, and kills it if it
/// has not ended after a minute (a command that started a server would not).
fn ferret(args: &[&str], env: &[(&str, &Path)]) -> Ran {
    let mut child = Command::new(BIN)
        .args(args)
        .env_clear()
        .envs(env.iter().map(|(k, v)| (*k, v.as_os_str())))
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("start ferret");
    let started = Instant::now();
    loop {
        if child.try_wait().expect("wait").is_some() {
            break;
        }
        if started.elapsed() > Duration::from_secs(60) {
            let _ = child.kill();
            let _ = child.wait();
            panic!("ferret {args:?} did not end: it must not start a server");
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    let out = child.wait_with_output().expect("output");
    Ran {
        ok: out.status.success(),
        stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
    }
}

/// A copy of the database of a running app in a directory of its own, with
/// two accounts in it.
async fn copy_of_a_database() -> (Dir, TestApp) {
    let app = TestApp::new().await;
    add_account_to_app(&app, 1).await;
    add_account_to_app(&app, 2).await;
    let copy = Dir::new("copy");
    let target = copy.path().join(product::DB_FILE);
    let target_text = target.to_string_lossy().into_owned();
    app.state
        .vault_db
        .with_conn(move |conn| {
            conn.execute("VACUUM INTO ?1", [target_text])?;
            Ok(())
        })
        .await
        .expect("copy the database");
    (copy, app)
}

#[tokio::test]
async fn cli_bump_on_a_copy_of_the_database_raises_the_epoch_and_starts_no_listener() {
    let (copy, app) = copy_of_a_database().await;
    assert_eq!(epochs(&copy.db()), [0, 0]);

    // With the flag, and with the variable the server also reads.
    let ran = ferret(
        &[
            "restore-epoch",
            "bump",
            "--yes",
            "--data-dir",
            copy.path().to_str().unwrap(),
        ],
        &[],
    );
    assert!(ran.ok, "{} {}", ran.stdout, ran.stderr);
    assert_eq!(
        ran.stdout.trim(),
        "restore epoch is now 1 (2 vaults raised)"
    );
    assert!(
        !ran.stdout.contains("vault on") && !ran.stderr.contains("vault on"),
        "no server was started"
    );
    assert_eq!(epochs(&copy.db()), [1, 1]);

    let ran = ferret(
        &["restore-epoch", "bump", "--yes"],
        &[("FERRET_DATA_DIR", copy.path())],
    );
    assert!(ran.ok, "{} {}", ran.stdout, ran.stderr);
    assert_eq!(
        ran.stdout.trim(),
        "restore epoch is now 2 (2 vaults raised)"
    );
    assert_eq!(epochs(&copy.db()), [2, 2]);

    // The database the copy came from is not touched.
    let original: Vec<i64> = app
        .state
        .vault_db
        .with_conn(|conn| {
            let mut stmt = conn.prepare("SELECT restore_epoch FROM ferret_vaults")?;
            Ok(stmt
                .query_map([], |row| row.get(0))?
                .collect::<Result<_, _>>()?)
        })
        .await
        .expect("read the original");
    assert_eq!(original, [0, 0]);

    // The command leaves its lock file and nothing else behind.
    let mut names: Vec<String> = std::fs::read_dir(copy.path())
        .expect("list")
        .map(|e| e.expect("entry").file_name().to_string_lossy().into_owned())
        .collect();
    names.sort();
    assert!(names.contains(&"ferret.lock".to_string()), "{names:?}");
    assert!(
        !names
            .iter()
            .any(|n| n.contains("secret") || n.ends_with(".key")),
        "{names:?}"
    );
}

#[tokio::test]
async fn cli_needs_no_url_flags() {
    let (copy, _app) = copy_of_a_database().await;
    // The server refuses to start without its two URLs; the command does not
    // read them, nor the ports, nor the proxy list.
    let server = ferret(&["--data-dir", copy.path().to_str().unwrap()], &[]);
    assert!(!server.ok, "the server needs its URLs");
    assert!(server.stderr.contains("vault-url") || server.stderr.contains("VAULT_URL"));

    let ran = ferret(
        &[
            "restore-epoch",
            "bump",
            "--yes",
            "--data-dir",
            copy.path().to_str().unwrap(),
        ],
        &[],
    );
    assert!(ran.ok, "{} {}", ran.stdout, ran.stderr);
    assert_eq!(epochs(&copy.db()), [1, 1]);
}

#[tokio::test]
async fn cli_refuses_without_the_confirmation_flag() {
    let (copy, _app) = copy_of_a_database().await;
    let ran = ferret(
        &[
            "restore-epoch",
            "bump",
            "--data-dir",
            copy.path().to_str().unwrap(),
        ],
        &[],
    );
    assert!(!ran.ok);
    assert!(ran.stderr.contains("--yes"), "{}", ran.stderr);
    assert_eq!(epochs(&copy.db()), [0, 0], "nothing was changed");
    assert!(
        !copy.path().join("ferret.lock").exists(),
        "it refused before it touched the directory"
    );
    // The same through the library, with a directory that does not exist.
    let err = cli::run(Cmd::RestoreEpochBump {
        data_dir: copy.path().join("nowhere"),
        confirmed: false,
    })
    .expect_err("needs --yes");
    assert!(err.to_string().contains("--yes"), "{err}");
}

#[tokio::test]
async fn cli_refuses_a_directory_without_a_migrated_database() {
    // A directory that is not there, and one that is empty: nothing is made.
    let empty = Dir::new("empty");
    for dir in [empty.path().join("nowhere"), empty.path().to_path_buf()] {
        let ran = ferret(
            &[
                "restore-epoch",
                "bump",
                "--yes",
                "--data-dir",
                dir.to_str().unwrap(),
            ],
            &[],
        );
        assert!(!ran.ok);
        assert!(ran.stderr.contains("no database"), "{}", ran.stderr);
    }
    let left: Vec<_> = std::fs::read_dir(empty.path()).expect("list").collect();
    assert!(left.is_empty(), "nothing was created: {left:?}");
    assert!(!empty.path().join("nowhere").exists());

    // A database file with nothing in it.
    let blank = Dir::new("blank");
    Connection::open(blank.path().join(product::DB_FILE))
        .expect("a blank database")
        .execute_batch("CREATE TABLE unrelated (x INTEGER);")
        .expect("a table");
    let ran = ferret(
        &[
            "restore-epoch",
            "bump",
            "--yes",
            "--data-dir",
            blank.path().to_str().unwrap(),
        ],
        &[],
    );
    assert!(!ran.ok);
    assert!(ran.stderr.contains("not a migrated"), "{}", ran.stderr);

    // Something that is not a database at all.
    let junk = Dir::new("junk");
    std::fs::write(junk.path().join(product::DB_FILE), b"this is not sqlite").expect("a file");
    let ran = ferret(
        &[
            "restore-epoch",
            "bump",
            "--yes",
            "--data-dir",
            junk.path().to_str().unwrap(),
        ],
        &[],
    );
    assert!(!ran.ok);

    // A database that lacks the last migration: the server must migrate it
    // first, and the vaults are not touched.
    let (copy, _app) = copy_of_a_database().await;
    copy.db()
        .execute(
            "DELETE FROM schema_migrations WHERE name = '0005_sync.sql'",
            [],
        )
        .expect("forget a migration");
    let ran = ferret(
        &[
            "restore-epoch",
            "bump",
            "--yes",
            "--data-dir",
            copy.path().to_str().unwrap(),
        ],
        &[],
    );
    assert!(!ran.ok);
    assert!(ran.stderr.contains("0005_sync.sql"), "{}", ran.stderr);
    assert_eq!(epochs(&copy.db()), [0, 0]);
}

#[tokio::test]
async fn cli_refuses_while_another_process_holds_the_data_directory() {
    let (copy, _app) = copy_of_a_database().await;
    // What the server holds for as long as it runs.
    let held = data_lock::acquire(copy.path()).expect("the lock");

    let ran = ferret(
        &[
            "restore-epoch",
            "bump",
            "--yes",
            "--data-dir",
            copy.path().to_str().unwrap(),
        ],
        &[],
    );
    assert!(!ran.ok);
    assert!(
        ran.stderr.contains("another ferret process"),
        "{}",
        ran.stderr
    );
    // Through the environment variable a container sets, as `docker exec`
    // inside the live container would.
    let ran = ferret(
        &["restore-epoch", "bump", "--yes"],
        &[("FERRET_DATA_DIR", copy.path())],
    );
    assert!(!ran.ok);
    assert!(
        ran.stderr.contains("another ferret process"),
        "{}",
        ran.stderr
    );
    let err = cli::run(Cmd::RestoreEpochBump {
        data_dir: copy.path().to_path_buf(),
        confirmed: true,
    })
    .expect_err("in use");
    assert!(err.to_string().contains("another ferret process"), "{err}");
    assert_eq!(epochs(&copy.db()), [0, 0], "nothing was changed");

    // Released, the same command goes through.
    drop(held);
    let ran = ferret(
        &[
            "restore-epoch",
            "bump",
            "--yes",
            "--data-dir",
            copy.path().to_str().unwrap(),
        ],
        &[],
    );
    assert!(ran.ok, "{} {}", ran.stdout, ran.stderr);
    assert_eq!(epochs(&copy.db()), [1, 1]);
}

fn free_port() -> u16 {
    let socket = std::net::TcpListener::bind("127.0.0.1:0").expect("a free port");
    socket.local_addr().expect("an address").port()
}

#[tokio::test]
async fn cli_refuses_while_the_server_runs_on_the_same_data_directory() {
    let dir = Dir::new("live");
    let (vault_port, admin_port) = (free_port(), free_port());
    let config = Config {
        data_dir: dir.path().to_path_buf(),
        host: std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
        vault_port,
        admin_port,
        vault_url: VAULT_URL.to_string(),
        admin_url: ADMIN_URL.to_string(),
        trusted_proxies: Vec::new(),
    };
    let server = tokio::spawn(ferret_server::server::run(config.clone()));
    // Up when the vault port takes a connection.
    let started = Instant::now();
    while tokio::net::TcpStream::connect(("127.0.0.1", vault_port))
        .await
        .is_err()
    {
        if server.is_finished() {
            panic!("the server ended: {:?}", server.await);
        }
        assert!(
            started.elapsed() < Duration::from_secs(60),
            "the server did not start"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }

    let data_dir = dir.path().to_path_buf();
    let ran = tokio::task::spawn_blocking(move || {
        ferret(
            &[
                "restore-epoch",
                "bump",
                "--yes",
                "--data-dir",
                data_dir.to_str().unwrap(),
            ],
            &[],
        )
    })
    .await
    .expect("the command");
    assert!(!ran.ok, "it must not run beside a live server");
    assert!(
        ran.stderr.contains("another ferret process"),
        "{}",
        ran.stderr
    );

    // A second server on the same directory is refused for the same reason.
    let second = Config {
        vault_port: free_port(),
        admin_port: free_port(),
        ..config
    };
    let err = ferret_server::server::run(second)
        .await
        .expect_err("in use");
    assert!(err.to_string().contains("another ferret process"), "{err}");

    // Stopped, the directory is free again and the command goes through.
    server.abort();
    let _ = server.await;
    let started = Instant::now();
    loop {
        match data_lock::acquire(dir.path()) {
            Ok(lock) => {
                drop(lock);
                break;
            }
            Err(_) => {
                assert!(
                    started.elapsed() < Duration::from_secs(10),
                    "the lock stayed"
                );
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        }
    }
    let mut conn = dir.db();
    add_account(&mut conn, 1, NOW);
    drop(conn);
    let ran = ferret(
        &[
            "restore-epoch",
            "bump",
            "--yes",
            "--data-dir",
            dir.path().to_str().unwrap(),
        ],
        &[],
    );
    assert!(ran.ok, "{} {}", ran.stdout, ran.stderr);
    assert_eq!(ran.stdout.trim(), "restore epoch is now 1 (1 vault raised)");
}
