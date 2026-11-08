//! The foundation of the sync routes: the migration that adds indexes, the
//! notification channels, the handles the state hands out, the command line and
//! the check that was moved.

mod support;

use std::ffi::OsString;
use std::path::PathBuf;
use std::sync::Arc;

use axum::Router;
use axum::body::{Body, to_bytes};
use axum::extract::FromRef;
use axum::http::{Request, StatusCode};
use ferret_core::testing::TestRng;
use ferret_core::{ItemBody, ItemType, UnlockedVault, VaultContext, VaultKey, encrypt_item};
use ferret_server::auth::session::Origin;
use ferret_server::cli::{self, Command};
use ferret_server::db::MIGRATION_FILES;
use ferret_server::http::extract::SessionAuth;
use ferret_server::ids::{AccountId, ItemId, SidHash, VaultId};
use ferret_server::product;
use ferret_server::state::VaultDb;
use ferret_server::vault::events::EventStreams;
use ferret_server::vault::notify::{SyncEvents, VaultChange};
use ferret_server::vault::rate::{SyncLimits, WriteGate};
use ferret_server::vault::validate::check_envelope;
use ferret_server_auth::SessionScope;
use rusqlite::Connection;
use support::accounts::add_account_to_app;
use support::session::issue;
use support::{Jar, Req, TestApp, Which};
use tokio::sync::broadcast::error::TryRecvError;
use tower::ServiceExt as _;
use vole_kit::db::migrate::apply_migrations;

// ------------------------------------------------------------- migration 0005

fn index_columns(conn: &Connection, index: &str) -> Vec<String> {
    conn.prepare(&format!("PRAGMA index_info({index})"))
        .expect("prepare")
        .query_map([], |row| row.get::<_, String>(2))
        .expect("query")
        .map(|r| r.expect("row"))
        .collect()
}

#[test]
fn migration_0005_applies_after_0004_and_only_adds_indexes() {
    product::install();
    let names: Vec<&str> = MIGRATION_FILES.iter().map(|(name, _)| *name).collect();
    let at = |name: &str| names.iter().position(|n| *n == name).expect(name);
    assert_eq!(at("0005_sync.sql"), at("0004_handoff_links.sql") + 1);

    // Every statement of the file is a `CREATE INDEX`: no table, column or row
    // changes.
    let sql = MIGRATION_FILES
        .iter()
        .find(|(name, _)| *name == "0005_sync.sql")
        .map(|(_, sql)| *sql)
        .expect("the migration");
    let statements: Vec<String> = sql
        .lines()
        .filter(|line| !line.trim_start().starts_with("--"))
        .collect::<Vec<_>>()
        .join("\n")
        .split(';')
        .map(|s| s.split_whitespace().collect::<Vec<_>>().join(" "))
        .filter(|s| !s.is_empty())
        .collect();
    assert_eq!(statements.len(), 2, "{statements:?}");
    for statement in &statements {
        assert!(statement.starts_with("CREATE INDEX "), "{statement}");
    }

    let mut conn = Connection::open_in_memory().expect("open");
    conn.execute_batch("PRAGMA foreign_keys = ON;")
        .expect("pragma");
    let applied = apply_migrations(&mut conn).expect("migrations apply");
    assert!(applied.iter().any(|n| n == "0005_sync.sql"));
    assert_eq!(
        index_columns(&conn, "ferret_idem_by_device_time"),
        ["vault_id", "device_id", "created_at"]
    );
    assert_eq!(
        index_columns(&conn, "ferret_items_tombstones"),
        ["vault_id", "deleted", "changed_at"]
    );
}

// ------------------------------------------------------------ notifications

fn vault(n: u8) -> VaultId {
    VaultId::from_bytes([n; 16])
}

#[tokio::test]
async fn sync_events_reach_every_subscriber_and_a_notify_without_subscribers_is_harmless() {
    let events = SyncEvents::new(1024);
    // Nobody listens: nothing happens, and nothing is kept for a later listener.
    events.notify(vault(1), 5);
    let mut late = events.subscribe();
    assert!(matches!(late.try_recv(), Err(TryRecvError::Empty)));

    let mut first = events.subscribe();
    let mut second = events.clone().subscribe();
    events.notify(vault(1), 6);
    events.notify(vault(2), 9);
    for rx in [&mut first, &mut second, &mut late] {
        assert_eq!(
            rx.recv().await.expect("a change"),
            VaultChange {
                vault: vault(1),
                seq: 6
            }
        );
        assert_eq!(
            rx.recv().await.expect("a change"),
            VaultChange {
                vault: vault(2),
                seq: 9
            }
        );
        assert!(matches!(rx.try_recv(), Err(TryRecvError::Empty)));
    }

    // A subscriber that falls behind loses the oldest and is told so; the
    // sender is never held up.
    let small = SyncEvents::new(2);
    let mut slow = small.subscribe();
    for seq in 1..=5 {
        small.notify(vault(1), seq);
    }
    assert!(matches!(slow.try_recv(), Err(TryRecvError::Lagged(3))));
    assert_eq!(slow.recv().await.expect("a change").seq, 4);
    assert_eq!(slow.recv().await.expect("a change").seq, 5);
}

#[tokio::test]
async fn revocations_reach_a_subscriber() {
    let events = SyncEvents::new(1024);
    // Without a subscriber a revocation is harmless too.
    events.session_revoked(SidHash([1; 32]));
    let mut rx = events.subscribe_revocations();
    let mut other = events.subscribe_revocations();
    events.session_revoked(SidHash([2; 32]));
    assert_eq!(rx.recv().await.expect("a revocation"), SidHash([2; 32]));
    assert_eq!(other.recv().await.expect("a revocation"), SidHash([2; 32]));
    // The two channels are separate.
    let mut changes = events.subscribe();
    events.session_revoked(SidHash([3; 32]));
    assert!(matches!(changes.try_recv(), Err(TryRecvError::Empty)));
}

// ------------------------------------------------------------------ the state

/// What the vault routes may see: the database, the session handle and the
/// handles of the sync routes. Nothing else of the state.
#[derive(Clone)]
struct Handles {
    db: VaultDb,
    auth: SessionAuth,
    events: SyncEvents,
    limits: Arc<SyncLimits>,
    gate: WriteGate,
    streams: Arc<EventStreams>,
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

#[tokio::test]
async fn state_hands_out_the_new_handles_through_from_ref() {
    let app = TestApp::new().await;
    let account = add_account_to_app(&app, 1).await;
    let issued = issue(&app, account.user_id, Origin::Vault, SessionScope::Full, 1).await;

    // Every handle comes out of the state through `FromRef`, and they are the
    // state's own: a notification sent through the copy is heard by a
    // subscriber of the original.
    let handles = Handles {
        db: VaultDb::from_ref(&app.state),
        auth: SessionAuth::from_ref(&app.state),
        events: SyncEvents::from_ref(&app.state),
        limits: Arc::<SyncLimits>::from_ref(&app.state),
        gate: WriteGate::from_ref(&app.state),
        streams: Arc::<EventStreams>::from_ref(&app.state),
    };
    assert!(Arc::ptr_eq(&handles.limits, &app.state.limits));
    assert!(Arc::ptr_eq(&handles.streams, &app.state.streams));
    let mut rx = app.sync_events().subscribe();
    handles.events.notify(vault(7), 3);
    assert_eq!(rx.recv().await.expect("a change").seq, 3);
    let _turn = handles.gate.enter().await.expect("a turn");

    // The routes build over a state of just these handles, and answer.
    let router: Router = ferret_server::vault::routes::<Handles>().with_state(handles);
    let ask = |jar: &Jar| {
        let mut builder = Request::builder().uri("/api/sync/changes?since=0");
        if let Some(cookie) = jar.header() {
            builder = builder.header("cookie", cookie);
        }
        builder.body(Body::empty()).expect("a request")
    };
    let res = router
        .clone()
        .oneshot(ask(&issued.jar))
        .await
        .expect("a response");
    assert_eq!(res.status(), StatusCode::OK);
    let body = to_bytes(res.into_body(), 1 << 20).await.expect("a body");
    let json: serde_json::Value = serde_json::from_slice(&body).expect("JSON");
    assert_eq!(json["latest_seq"], 1);
    let res = router
        .oneshot(ask(&Jar::default()))
        .await
        .expect("a response");
    assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn new_sync_paths_are_404_on_the_admin_listener() {
    let app = TestApp::new().await;
    for (method, path) in [
        ("GET", "/api/sync/events"),
        ("GET", "/api/sync/items?limit=1"),
        ("GET", "/api/sync/checkpoint"),
        ("PUT", "/api/sync/checkpoint"),
        ("POST", "/api/sync/batch"),
    ] {
        let res = app
            .call(
                Which::Admin,
                Req::new(method.parse().expect("a method"), path)
                    .page_fetch(Which::Admin)
                    .build(),
            )
            .await;
        assert_eq!(res.status, StatusCode::NOT_FOUND, "{method} {path}");
    }
}

// ------------------------------------------------------------ the command line

fn args(words: &[&str]) -> Vec<OsString> {
    words.iter().map(OsString::from).collect()
}

#[test]
fn restore_epoch_command_is_parsed_and_server_flags_are_left_to_config() {
    let parsed = cli::parse(args(&[
        "ferret",
        "restore-epoch",
        "bump",
        "--data-dir",
        "/srv/ferret",
    ]))
    .expect("a command")
    .expect("it parses");
    assert_eq!(
        parsed,
        Command::RestoreEpochBump {
            data_dir: PathBuf::from("/srv/ferret")
        }
    );

    // Not a command: the server starts, and Config reads the flags.
    for line in [
        &["ferret"][..],
        &["ferret", "--vault-port", "3041"],
        &["ferret", "--data-dir", "/srv/ferret"],
        &["ferret", "--help"],
        &["ferret", "--build-info"],
        &["ferret", "bump"],
    ] {
        assert!(cli::parse(args(line)).is_none(), "{line:?}");
    }
    assert!(cli::parse(Vec::new()).is_none());

    // A command with a mistake is an error, not a server start.
    for line in [
        &["ferret", "restore-epoch"][..],
        &["ferret", "restore-epoch", "reset"],
        &["ferret", "restore-epoch", "bump", "--no-such-flag"],
        &["ferret", "restore-epoch", "bump", "--vault-port", "1"],
    ] {
        assert!(matches!(cli::parse(args(line)), Some(Err(_))), "{line:?}");
    }

    // The stub refuses without panicking.
    let err = cli::run(parsed).expect_err("not implemented yet");
    assert!(err.to_string().contains("not implemented"), "{err}");
}

// --------------------------------------------------------------- the envelope

#[test]
fn check_envelope_moved_without_change() {
    let context = VaultContext {
        account_id: AccountId::from_bytes([1; 16]),
        vault_id: vault(2),
        vk_epoch: 1,
    };
    let unlocked =
        UnlockedVault::from_vault_key(context, VaultKey::from_test_bytes([3; 32])).expect("vault");
    let sealed = encrypt_item(
        &mut TestRng::new(b"envelope"),
        &unlocked,
        ItemId::from_bytes([4; 16]),
        1,
        &ItemBody::new(ItemType::Note, "note", 1),
        None,
    )
    .expect("an item");
    assert!(check_envelope(&sealed.envelope).is_ok());

    let refused = |blob: &[u8]| check_envelope(blob).expect_err("refused");
    let junk = refused(b"not an envelope");
    assert_eq!(junk.code, "unsupported_envelope");
    assert_eq!(junk.status, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(refused(&[]).code, "unsupported_envelope");
    // The kind byte of something that is not an item.
    let mut other_kind = sealed.envelope.clone();
    other_kind[2] = 0xff;
    assert_eq!(refused(&other_kind).code, "unsupported_envelope");
    let big = refused(&vec![0u8; 64 * 1024 + 1]);
    assert_eq!(big.code, "too_large");
    assert_eq!(big.status, StatusCode::PAYLOAD_TOO_LARGE);
}
