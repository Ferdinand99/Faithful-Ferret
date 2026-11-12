//! The foundation of the recovery, export and backup routes: the handles the
//! state hands out, the paths that the admin listener never serves, the
//! command line, the backup settings and the marker of a restore that is not
//! finished.

mod support;

use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::process::Command as Process;
use std::sync::Arc;

use axum::Router;
use axum::body::Body;
use axum::extract::FromRef;
use axum::http::{Method, Request, StatusCode};
use clap::{CommandFactory as _, Parser as _};
use ferret_server::backup::{BackupConfig, RESTORE_MARKER};
use ferret_server::cli::{self, Command};
use ferret_server::config::Config;
use ferret_server::http::extract::SessionAuth;
use ferret_server::product;
use ferret_server::state::{BackupStatus, Challenges, ImportWindows, VaultDb};
use ferret_server::vault::events::EventStreams;
use ferret_server::vault::notify::SyncEvents;
use ferret_server::vault::rate::{SyncLimits, WriteGate};
use ferret_server::vault::reconcile::{self, bump_restore_epoch};
use ferret_server_auth::{Clock, ManualClock};
use rusqlite::Connection;
use support::accounts::add_account;
use support::{Req, TestApp, Which};
use tower::ServiceExt as _;
use vole_kit::db::migrate::apply_migrations;

const NOW: i64 = 1_793_491_200;
const BIN: &str = env!("CARGO_BIN_EXE_ferret");

fn args(words: &[&str]) -> Vec<OsString> {
    words.iter().map(OsString::from).collect()
}

/// A directory of its own, removed when it goes out of scope.
struct Dir(PathBuf);

impl Dir {
    fn new(name: &str) -> Self {
        let dir = std::env::temp_dir().join(format!("ferret-m3-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("a directory");
        Dir(dir)
    }

    fn path(&self) -> &Path {
        &self.0
    }

    fn names(&self) -> Vec<String> {
        let mut names: Vec<String> = std::fs::read_dir(&self.0)
            .expect("list")
            .map(|e| e.expect("entry").file_name().to_string_lossy().into_owned())
            .collect();
        names.sort();
        names
    }
}

impl Drop for Dir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

// ------------------------------------------------------------------ the state

/// What the vault routes may see now: the database, the session handle, the
/// handles of the sync routes, and the handles of the routes that change the
/// unlock methods and import. Nothing else of the state.
#[derive(Clone)]
struct Handles {
    db: VaultDb,
    auth: SessionAuth,
    events: SyncEvents,
    limits: Arc<SyncLimits>,
    gate: WriteGate,
    streams: Arc<EventStreams>,
    challenges: Challenges,
    import_windows: ImportWindows,
    backup: BackupStatus,
    clock: Arc<dyn Clock>,
}

macro_rules! handle {
    ($name:ident, $ty:ty) => {
        impl FromRef<Handles> for $ty {
            fn from_ref(state: &Handles) -> $ty {
                state.$name.clone()
            }
        }
    };
}
handle!(db, VaultDb);
handle!(auth, SessionAuth);
handle!(events, SyncEvents);
handle!(limits, Arc<SyncLimits>);
handle!(gate, WriteGate);
handle!(streams, Arc<EventStreams>);
handle!(challenges, Challenges);
handle!(import_windows, ImportWindows);
handle!(backup, BackupStatus);
handle!(clock, Arc<dyn Clock>);

#[tokio::test]
async fn state_hands_out_challenges_import_windows_and_backup_status_through_from_ref() {
    let app = TestApp::new().await;
    let state = &app.state;

    // The handles are the state's own, not new ones: the store of nonces is one
    // store however many copies of its handle there are.
    let challenges = Challenges::from_ref(state);
    assert!(std::ptr::eq(challenges.store(), state.challenges.store()));
    assert!(std::ptr::eq(
        app.challenges().store(),
        state.challenges.store()
    ));
    assert!(challenges.store().is_empty());
    let _ = ImportWindows::from_ref(state);
    let status = BackupStatus::from_ref(state);
    // Asking for a run is harmless: the scheduler is not built yet.
    status.request_run("unlock_methods");
    app.backup_status().request_run("unlock_methods");
    assert!(!format!("{challenges:?}").contains("InMemory"));

    // The routes build over a state of just these handles, and answer.
    let clock: Arc<dyn Clock> = Arc::new(ManualClock::new(1));
    let handles = Handles {
        db: VaultDb::from_ref(state),
        auth: SessionAuth::from_ref(state),
        events: SyncEvents::from_ref(state),
        limits: Arc::<SyncLimits>::from_ref(state),
        gate: WriteGate::from_ref(state),
        streams: Arc::<EventStreams>::from_ref(state),
        challenges,
        import_windows: ImportWindows::from_ref(state),
        backup: status,
        clock,
    };
    let router: Router = ferret_server::vault::routes::<Handles>().with_state(handles);
    let res = router
        .oneshot(
            Request::builder()
                .uri("/api/sync/changes?since=0")
                .body(Body::empty())
                .expect("a request"),
        )
        .await
        .expect("a response");
    assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn new_m3_paths_are_404_on_the_admin_listener() {
    let app = TestApp::new().await;
    for (method, path) in [
        ("POST", "/api/auth/challenge"),
        ("POST", "/api/auth/opaque/reregister/start"),
        ("PUT", "/api/vault/unlock-methods/password"),
        ("PUT", "/api/vault/unlock-methods/recovery"),
        ("GET", "/api/vault/recovery"),
        ("POST", "/api/vault/recover"),
        ("POST", "/api/auth/redeem"),
        ("POST", "/api/sync/import"),
    ] {
        let res = app
            .call(
                Which::Admin,
                Req::new(method.parse::<Method>().expect("a method"), path)
                    .page_fetch(Which::Admin)
                    .build(),
            )
            .await;
        assert_eq!(res.status, StatusCode::NOT_FOUND, "{method} {path}");
    }
}

// ----------------------------------------------------------------- the restore

#[tokio::test]
async fn server_start_bump_and_backup_create_refuse_while_a_restore_is_in_progress() {
    let dir = Dir::new("marker");
    std::fs::write(dir.path().join(RESTORE_MARKER), r#"{"step":"files moved"}"#)
        .expect("the marker");
    let before = dir.names();
    assert_eq!(before, [RESTORE_MARKER]);

    // The server's start-up, as the tests and the binary share it.
    let config = Config::try_parse_from([
        "ferret",
        "--vault-url",
        "https://vault.example.test",
        "--admin-url",
        "https://admin.example.test",
        "--data-dir",
        dir.path().to_str().expect("a path"),
    ])
    .expect("a config");
    let clock: Arc<dyn Clock> = Arc::new(ManualClock::new(1));
    let refused = ferret_server::start(&config, clock)
        .await
        .err()
        .expect("the start is refused");
    assert!(refused.to_string().contains(RESTORE_MARKER), "{refused}");

    // The two commands, through the library.
    let bump = cli::run(Command::RestoreEpochBump {
        data_dir: dir.path().to_path_buf(),
        confirmed: true,
        at_least: None,
    })
    .expect_err("bump is refused");
    assert!(bump.to_string().contains(RESTORE_MARKER), "{bump}");
    let create = cli::run(Command::BackupCreate {
        data_dir: dir.path().to_path_buf(),
    })
    .expect_err("create is refused");
    assert!(create.to_string().contains(RESTORE_MARKER), "{create}");

    // The binary: it exits with an error, says why, and makes nothing, not even
    // the lock file of the data directory.
    let out = Process::new(BIN)
        .env_clear()
        .args([
            "--vault-url",
            "https://vault.example.test",
            "--admin-url",
            "https://admin.example.test",
            "--data-dir",
        ])
        .arg(dir.path())
        .output()
        .expect("run the server binary");
    assert!(!out.status.success());
    let said = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(said.contains(RESTORE_MARKER), "{said}");
    let out = Process::new(BIN)
        .env_clear()
        .args(["restore-epoch", "bump", "--yes", "--data-dir"])
        .arg(dir.path())
        .output()
        .expect("run the command");
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains(RESTORE_MARKER));
    assert_eq!(dir.names(), before, "nothing was made or changed");

    // Without the marker the same call is refused for what it lacks: there is
    // no database in an empty directory.
    std::fs::remove_file(dir.path().join(RESTORE_MARKER)).expect("remove the marker");
    let bump = cli::run(Command::RestoreEpochBump {
        data_dir: dir.path().to_path_buf(),
        confirmed: true,
        at_least: None,
    })
    .expect_err("no database");
    assert!(!bump.to_string().contains(RESTORE_MARKER), "{bump}");
    assert!(bump.to_string().contains("no database"), "{bump}");
}

// ------------------------------------------------------------ the command line

#[test]
fn cli_parses_every_m3_command() {
    let parse = |words: &[&str]| {
        cli::parse(args(words))
            .expect("a command")
            .expect("it parses")
    };
    let dir = PathBuf::from("/srv/ferret");
    assert_eq!(
        parse(&[
            "ferret",
            "restore-epoch",
            "bump",
            "--data-dir",
            "/srv/ferret"
        ]),
        Command::RestoreEpochBump {
            data_dir: dir.clone(),
            confirmed: false,
            at_least: None,
        }
    );
    assert_eq!(
        parse(&[
            "ferret",
            "restore-epoch",
            "bump",
            "--yes",
            "--at-least",
            "1800000000",
            "--data-dir",
            "/srv/ferret"
        ]),
        Command::RestoreEpochBump {
            data_dir: dir.clone(),
            confirmed: true,
            at_least: Some(1_800_000_000),
        }
    );
    assert_eq!(
        parse(&["ferret", "backup", "create", "--data-dir", "/srv/ferret"]),
        Command::BackupCreate {
            data_dir: dir.clone()
        }
    );
    assert_eq!(
        parse(&["ferret", "backup", "list", "--data-dir", "/srv/ferret"]),
        Command::BackupList {
            data_dir: dir.clone()
        }
    );
    assert_eq!(
        parse(&[
            "ferret",
            "backup",
            "verify",
            "/srv/ferret/backups/auto/set1"
        ]),
        Command::BackupVerify {
            set: PathBuf::from("/srv/ferret/backups/auto/set1")
        }
    );
    assert_eq!(
        parse(&[
            "ferret",
            "backup",
            "restore",
            "--from",
            "/mnt/set1",
            "--data-dir",
            "/srv/ferret"
        ]),
        Command::BackupRestore {
            data_dir: dir.clone(),
            from: PathBuf::from("/mnt/set1"),
            confirmed: false,
            at_least: None,
        }
    );
    assert_eq!(
        parse(&[
            "ferret",
            "backup",
            "restore",
            "--from",
            "/mnt/set1",
            "--yes",
            "--at-least",
            "7",
            "--data-dir",
            "/srv/ferret"
        ]),
        Command::BackupRestore {
            data_dir: dir.clone(),
            from: PathBuf::from("/mnt/set1"),
            confirmed: true,
            at_least: Some(7),
        }
    );
    assert_eq!(
        parse(&[
            "ferret",
            "backup",
            "restore",
            "--abort",
            "--yes",
            "--data-dir",
            "/srv/ferret"
        ]),
        Command::BackupAbort {
            data_dir: dir.clone(),
            confirmed: true,
        }
    );
    assert_eq!(
        parse(&[
            "ferret",
            "sign-in-code",
            "issue",
            "--email",
            "admin@example.test",
            "--yes",
            "--data-dir",
            "/srv/ferret"
        ]),
        Command::SignInCodeIssue {
            data_dir: dir,
            email: "admin@example.test".to_string(),
            confirmed: true,
        }
    );

    // A mistake is an error, not a server start and not another command.
    for line in [
        &["ferret", "backup"][..],
        &["ferret", "backup", "snapshot"],
        &["ferret", "backup", "verify"],
        &["ferret", "backup", "restore"],
        &["ferret", "backup", "restore", "--from", "/a", "--abort"],
        &["ferret", "backup", "restore", "--abort", "--at-least", "5"],
        &[
            "ferret",
            "backup",
            "restore",
            "--from",
            "/a",
            "--at-least",
            "-1",
        ],
        &[
            "ferret",
            "backup",
            "restore",
            "--from",
            "/a",
            "--at-least",
            "9007199254740992",
        ],
        &["ferret", "sign-in-code"],
        &["ferret", "sign-in-code", "issue"],
        &["ferret", "sign-in-code", "issue", "--yes"],
        &["ferret", "restore-epoch", "bump", "--at-least", "x"],
    ] {
        assert!(matches!(cli::parse(args(line)), Some(Err(_))), "{line:?}");
    }
}

#[test]
fn restore_bump_restore_abort_and_sign_in_code_change_nothing_without_yes() {
    let dir = Dir::new("noyes");
    let data_dir = dir.path().to_path_buf();
    let set = dir.path().join("set1");
    let commands = [
        Command::RestoreEpochBump {
            data_dir: data_dir.clone(),
            confirmed: false,
            at_least: None,
        },
        Command::BackupRestore {
            data_dir: data_dir.clone(),
            from: set,
            confirmed: false,
            at_least: Some(3),
        },
        Command::BackupAbort {
            data_dir: data_dir.clone(),
            confirmed: false,
        },
        Command::SignInCodeIssue {
            data_dir: data_dir.clone(),
            email: "admin@example.test".to_string(),
            confirmed: false,
        },
    ];
    for command in commands {
        let name = format!("{command:?}");
        let err = cli::run(command).expect_err(&name);
        assert!(err.to_string().contains("--yes"), "{name}: {err}");
    }
    assert!(
        dir.names().is_empty(),
        "nothing was made: {:?}",
        dir.names()
    );

    // Make, list and check change nothing that exists, so they do not ask for
    // `--yes`: whatever they say, it is not that.
    for command in [
        Command::BackupCreate {
            data_dir: data_dir.clone(),
        },
        Command::BackupList { data_dir },
        Command::BackupVerify {
            set: dir.path().join("set1"),
        },
    ] {
        let name = format!("{command:?}");
        let err = cli::run(command).expect_err(&name);
        assert!(!err.to_string().contains("--yes"), "{name}: {err}");
    }
    assert!(
        dir.names().is_empty(),
        "nothing was made: {:?}",
        dir.names()
    );
}

#[test]
fn cli_leaves_server_flags_to_config() {
    // Not a command: the server starts, and Config reads the flags.
    for line in [
        &["ferret"][..],
        &["ferret", "--backup-dir", "/backups"],
        &["ferret", "--backup-every-hours", "12"],
        &["ferret", "--backup-keep-days", "7"],
        &[
            "ferret",
            "--backup-push-url",
            "https://monitor.example.test/x",
        ],
        &[
            "ferret",
            "--data-dir",
            "/srv/ferret",
            "--vault-url",
            "https://v.test",
        ],
        &["ferret", "create"],
        &["ferret", "issue"],
        &["ferret", "sign-in"],
    ] {
        assert!(cli::parse(args(line)).is_none(), "{line:?}");
    }
    // The flags are Config's.
    let config = Config::try_parse_from([
        "ferret",
        "--vault-url",
        "https://vault.example.test",
        "--admin-url",
        "https://admin.example.test",
        "--backup-dir",
        "/backups",
        "--backup-every-hours",
        "12",
        "--backup-keep-days",
        "7",
    ])
    .expect("the server's flags");
    assert_eq!(config.backup_dir.as_deref(), Some(Path::new("/backups")));
    assert_eq!(
        (config.backup_every_hours, config.backup_keep_days),
        (12, 7)
    );
    // And a command does not take them.
    assert!(matches!(
        cli::parse(args(&["ferret", "backup", "create", "--backup-dir", "/x"])),
        Some(Err(_))
    ));
}

// ------------------------------------------------------------- the restore epoch

fn migrated() -> Connection {
    product::install();
    let mut conn = Connection::open_in_memory().expect("open");
    conn.execute_batch("PRAGMA foreign_keys = ON;")
        .expect("pragma");
    apply_migrations(&mut conn).expect("migrations apply");
    conn
}

fn epochs(conn: &Connection) -> Vec<i64> {
    conn.prepare("SELECT restore_epoch FROM ferret_vaults ORDER BY vault_id")
        .expect("prepare")
        .query_map([], |row| row.get(0))
        .expect("query")
        .map(|r| r.expect("row"))
        .collect()
}

#[test]
fn bump_keeps_the_m2_rule_with_the_new_signature() {
    let mut conn = migrated();
    for n in 1..=2 {
        add_account(&mut conn, n, NOW);
    }
    // One more than the stored epoch, whatever `now` is.
    assert_eq!(bump_restore_epoch(&mut conn, None, NOW).expect("a bump"), 1);
    assert_eq!(bump_restore_epoch(&mut conn, None, 5).expect("a bump"), 2);
    assert_eq!(epochs(&conn), [2, 2]);
    let bumped = reconcile::bump(&mut conn, None, NOW).expect("a bump");
    assert_eq!((bumped.vaults, bumped.restore_epoch), (2, 3));
    assert_eq!(
        bumped,
        reconcile::Bumped {
            vaults: 2,
            restore_epoch: 3
        }
    );

    // A lowest epoch is refused for now, and nothing changes: no command says
    // that it raised the epoch to a number that it did not.
    let refused = bump_restore_epoch(&mut conn, Some(10), NOW).expect_err("not supported yet");
    assert!(
        matches!(refused, ferret_server::error::StoreError::Invalid(_)),
        "{refused}"
    );
    assert_eq!(epochs(&conn), [3, 3]);
}

// ------------------------------------------------------------ the backup settings

fn config(extra: &[&str]) -> Result<Config, clap::Error> {
    let mut line = vec![
        "ferret",
        "--vault-url",
        "https://vault.example.test",
        "--admin-url",
        "https://admin.example.test",
        "--data-dir",
        "/srv/ferret",
    ];
    line.extend_from_slice(extra);
    Config::try_parse_from(line)
}

#[test]
fn backup_config_has_defaults_and_bounds_and_never_prints_the_push_url() {
    // Defaults: a folder under the data directory, every 24 hours, 30 days, no
    // push address.
    let cfg = config(&[])
        .expect("defaults")
        .backup_config()
        .expect("valid");
    assert_eq!(cfg.dir, Path::new("/srv/ferret/backups/auto"));
    assert_eq!(cfg.every.as_secs(), 24 * 3600);
    assert_eq!(cfg.keep_days, 30);
    assert!(cfg.push_url.is_none());

    // Bounds: 1 to 168 hours and 1 to 365 days, checked as the flags are read.
    for (flag, ok, bad) in [
        ("--backup-every-hours", ["1", "168"], ["0", "169"]),
        ("--backup-keep-days", ["1", "365"], ["0", "366"]),
    ] {
        for value in ok {
            assert!(config(&[flag, value]).is_ok(), "{flag} {value}");
        }
        for value in bad {
            assert!(config(&[flag, value]).is_err(), "{flag} {value}");
        }
    }
    let custom = config(&["--backup-dir", "/mnt/backups", "--backup-every-hours", "6"])
        .expect("flags")
        .backup_config()
        .expect("valid");
    assert_eq!(custom.dir, Path::new("/mnt/backups"));
    assert_eq!(custom.every.as_secs(), 6 * 3600);
    // The same bounds as the ones the settings are checked against later.
    assert_eq!(
        (
            ferret_server::backup::EVERY_HOURS_RANGE,
            ferret_server::backup::KEEP_DAYS_RANGE
        ),
        (1..=168, 1..=365)
    );

    // The push address is a secret: not in `Debug` of the settings or of the
    // configuration, not in an error, and not in the help text.
    let secret = "https://monitor.example.test/api/push/tokenvalue123";
    let with = config(&["--backup-push-url", secret]).expect("a config");
    let shown = format!("{with:?} {with:#?}");
    assert!(
        !shown.contains("tokenvalue123") && !shown.contains("monitor.example.test"),
        "{shown}"
    );
    let cfg = with.backup_config().expect("valid");
    assert_eq!(cfg.push_url.as_ref().map(|u| u.expose()), Some(secret));
    let shown = format!("{cfg:?} {cfg:#?}");
    assert!(
        !shown.contains("tokenvalue123") && !shown.contains("monitor.example.test"),
        "{shown}"
    );
    assert!(
        Config::command()
            .get_arguments()
            .find(|arg| arg.get_id() == "backup_push_url")
            .expect("the argument")
            .is_hide_env_values_set()
    );

    // A bad address is refused without quoting it, by clap or by the check.
    for bad in [
        "ftp://monitor.example.test/tokenvalue123",
        "tokenvalue123",
        "",
    ] {
        match config(&["--backup-push-url", bad]) {
            Err(error) => {
                let message = error.to_string();
                assert!(!message.contains("tokenvalue123"), "{message}");
            }
            Ok(parsed) => match parsed.backup_config() {
                // An empty address is read as none.
                Ok(cfg) => assert!(bad.is_empty() && cfg.push_url.is_none(), "{bad:?}"),
                Err(error) => {
                    let message = error.to_string();
                    assert!(!message.contains("tokenvalue123"), "{message}");
                    assert!(message.contains("FERRET_BACKUP_PUSH_URL"), "{message}");
                }
            },
        }
    }

    // The settings of the commands come from the environment and have the same
    // defaults.
    let cfg = BackupConfig::from_env(Path::new("/srv/ferret")).expect("defaults");
    if std::env::var_os("FERRET_BACKUP_DIR").is_none() {
        assert_eq!(cfg.dir, Path::new("/srv/ferret/backups/auto"));
    }
    assert!(cfg.push_url.is_none(), "a command never pushes");
}
