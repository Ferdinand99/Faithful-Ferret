//! The foundation of devices and their tokens: the limits, the types that the
//! routes of later parts build on, how a refused DPoP proof is answered, and
//! the paths that the admin listener never serves.

mod support;

use std::sync::Arc;

use axum::extract::FromRef;
use axum::http::{HeaderMap, Method, StatusCode, header};
use axum::response::IntoResponse as _;
use ferret_core::TestRng;
use ferret_server::auth::devices::{
    DeviceInsertError, FORGET_OLD_SECS, NewDevice, REVOKED_KEEP_SECS,
};
use ferret_server::auth::dpop::{
    self, DpopError, Expect, IAT_WINDOW_SECS, JTI_CAPACITY, JTI_PER_KEY, JTI_PER_USER,
    JTI_TTL_SECS, MAX_PROOF_LEN,
};
use ferret_server::auth::refresh::{
    ABSOLUTE_SECS, GRACE_CAPACITY, GRACE_SECS, IDLE_SECS, PURGE_EVERY, Purged, USED_KEEP_SECS,
    purge_expired, purge_once,
};
use ferret_server::auth::tokens::{AccessLookup, AccessRow, DeviceAuth, IssuedTokens};
use ferret_server::error::ApiError;
use ferret_server::ids::{DeviceId, TokenSecret};
use ferret_server::state::VaultDb;
use ferret_server::wire::PlatformJson;
use ferret_server_auth::{Clock, ManualClock};
use rusqlite::Connection;
use support::{Req, TestApp, VAULT_URL, Which};
use vole_kit::db::migrate::apply_migrations;

const NOW: i64 = 1_793_491_200;

#[tokio::test]
async fn token_and_device_paths_are_404_on_the_admin_listener() {
    // The routes are empty for now, so this holds trivially; it is the guard
    // that the routes of tokens and devices, once they are served, are served
    // on the vault listener only.
    let app = TestApp::new().await;
    for (method, path) in [
        ("POST", "/api/auth/token/refresh"),
        ("POST", "/api/auth/token/revoke"),
        ("GET", "/api/auth/devices"),
        (
            "DELETE",
            "/api/auth/devices/00112233445566778899aabbccddeeff",
        ),
        ("POST", "/api/auth/devices/revoke-all"),
        ("POST", "/api/auth/devices/forget-old"),
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

#[test]
fn every_refusal_of_a_proof_is_one_answer_and_a_busy_cache_asks_to_wait() {
    // Every refusal of the proof itself is the one answer, with no reason.
    for reason in [
        DpopError::Missing,
        DpopError::Malformed,
        DpopError::Signature,
        DpopError::Claims,
        DpopError::Clock,
        DpopError::Replay,
    ] {
        let api = ApiError::from(reason);
        assert_eq!(api.status, StatusCode::UNAUTHORIZED, "{reason:?}");
        assert_eq!(api.code, "dpop_invalid", "{reason:?}");
        assert_eq!(api.retry_after, None, "{reason:?}");
        assert_eq!(api, ApiError::coded("dpop_invalid"));
    }
    // Too many proofs of one key or one account: a throttle with a wait.
    for reason in [DpopError::KeyBusy, DpopError::UserBusy] {
        let res = ApiError::from(reason).into_response();
        assert_eq!(res.status(), StatusCode::TOO_MANY_REQUESTS, "{reason:?}");
        assert_eq!(res.headers()[header::RETRY_AFTER], "60", "{reason:?}");
    }
    // A full cache refuses instead of forgetting.
    let full = ApiError::from(DpopError::Full);
    assert_eq!(
        (full.status, full.code),
        (StatusCode::SERVICE_UNAVAILABLE, "busy")
    );
    let res = full.into_response();
    assert_eq!(res.headers()[header::RETRY_AFTER], "30");
    assert_eq!(res.headers()[header::CACHE_CONTROL], "no-store");
}

#[test]
fn the_limits_are_the_ones_of_the_design() {
    // DPoP (RFC 9449 § 4.3, § 11.1).
    assert_eq!(IAT_WINDOW_SECS, 60);
    assert_eq!(JTI_TTL_SECS, 300);
    const { assert!(JTI_TTL_SECS > 2 * IAT_WINDOW_SECS) };
    assert_eq!(JTI_CAPACITY, 65_536);
    assert_eq!(JTI_PER_KEY, 1_024);
    assert_eq!(JTI_PER_USER, 4_096);
    const { assert!(JTI_PER_KEY < JTI_PER_USER && JTI_PER_USER < JTI_CAPACITY) };
    assert_eq!(MAX_PROOF_LEN, 4_096);
    // Refresh tokens (Spec: Fase 1 § 7.6).
    assert_eq!(GRACE_SECS, 60);
    assert_eq!(IDLE_SECS, 30 * 86_400);
    assert_eq!(ABSOLUTE_SECS, 90 * 86_400);
    assert_eq!(USED_KEEP_SECS, 30 * 86_400);
    assert_eq!(GRACE_CAPACITY, 65_536);
    // Devices.
    assert_eq!(FORGET_OLD_SECS, 7 * 86_400);
    assert_eq!(REVOKED_KEEP_SECS, 30 * 86_400);
}

#[test]
fn a_bare_or_broken_proof_is_refused_and_the_purge_purges_nothing_yet() {
    let token = TokenSecret::random(&mut TestRng::new(b"m5a wiring token"));
    let method = Method::GET;
    let htu = support::dpop::vault_htu("/api/sync/changes");
    assert_eq!(htu.as_str(), "https://vault.ferret.test/api/sync/changes");
    let expect = Expect {
        method: &method,
        htu: &htu,
        access: Some(&token),
    };
    let mut headers = HeaderMap::new();
    headers.insert("dpop", "a.b.c".parse().expect("a header value"));
    assert_eq!(
        dpop::verify(&headers, &expect, NOW).unwrap_err(),
        DpopError::Malformed
    );
    assert_eq!(
        dpop::verify(&HeaderMap::new(), &expect, NOW).unwrap_err(),
        DpopError::Missing
    );

    ferret_server::product::install();
    let mut conn = Connection::open_in_memory().expect("open");
    conn.execute_batch("PRAGMA foreign_keys = ON;")
        .expect("pragma");
    apply_migrations(&mut conn).expect("migrations");
    let tx = conn
        .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
        .expect("BEGIN IMMEDIATE");
    assert_eq!(purge_expired(&tx, NOW).expect("a purge"), Purged::default());
    tx.commit().expect("commit");
}

#[tokio::test]
async fn device_auth_names_the_vault_origin_in_htu_and_prints_nothing() {
    let app = TestApp::new().await;
    let db = VaultDb::from_ref(&app.state);
    let clock: Arc<dyn Clock> = Arc::new(ManualClock::new(1));
    let auth = DeviceAuth::new(db.clone(), clock.clone(), VAULT_URL);
    assert_eq!(
        auth.htu("/api/sync/changes").as_str(),
        "https://vault.ferret.test/api/sync/changes"
    );
    assert_eq!(
        auth.htu("/api/auth/token/refresh").as_str(),
        format!("{VAULT_URL}/api/auth/token/refresh")
    );
    // A trailing `/` of the origin is not doubled.
    let slashed = DeviceAuth::new(db, clock, &format!("{VAULT_URL}/"));
    assert_eq!(
        slashed.htu("/api/auth/devices"),
        auth.htu("/api/auth/devices")
    );
    // A clone shares the caches.
    let _shared = auth.clone();
    assert_eq!(format!("{auth:?}"), "DeviceAuth([redacted])");
}

#[tokio::test]
async fn state_hands_out_device_auth() {
    let app = TestApp::new().await;
    // One handle in the state, built at start-up from the configured vault
    // origin, with an empty cache that every clone shares.
    let auth = DeviceAuth::from_ref(&app.state);
    assert_eq!(
        auth.htu("/api/auth/token/refresh").as_str(),
        format!("{VAULT_URL}/api/auth/token/refresh")
    );
    assert!(auth.replay().is_empty());
    assert!(std::ptr::eq(
        DeviceAuth::from_ref(&app.state).replay(),
        auth.replay()
    ));
    assert!(std::ptr::eq(app.state.device_auth.grace(), auth.grace()));
    // The purge job has a pass to run, and it removes nothing yet.
    let purged = purge_once(&VaultDb::from_ref(&app.state), app.clock.as_ref())
        .await
        .expect("a purge");
    assert_eq!(purged, Purged::default());
    assert_eq!(PURGE_EVERY, std::time::Duration::from_secs(600));
}

#[test]
fn token_machinery_debug_hides_the_tokens_and_the_key() {
    let mut rng = TestRng::new(b"m5a wiring debug");
    let issued = IssuedTokens {
        access: TokenSecret::random(&mut rng),
        refresh: TokenSecret::random(&mut rng),
        expires_in: 900,
    };
    let shown = format!("{issued:?}");
    assert!(shown.contains("900"), "{shown}");
    assert!(!shown.contains(&issued.access.to_wire()), "{shown}");
    assert!(!shown.contains(&issued.refresh.to_wire()), "{shown}");

    // A key's thumbprint is never printed, in any form.
    let jkt = [0xab; 32];
    let hex: String = jkt.iter().map(|b| format!("{b:02x}")).collect();
    let row = AccessRow {
        device: DeviceId([7; 16]),
        user_id: 5,
        jkt,
        expires_at: NOW,
        session_version: 3,
    };
    let device = NewDevice {
        user_id: 5,
        jkt,
        name: "Ferret for Firefox (Windows)",
        platform: PlatformJson::Windows,
        session_version: 3,
        now: NOW,
    };
    for shown in [
        format!("{row:?}"),
        format!("{:?}", AccessLookup::Live(row.clone())),
        format!("{device:?}"),
    ] {
        assert!(!shown.contains("jkt"), "{shown}");
        assert!(!shown.contains("171"), "{shown}");
        assert!(
            !shown.contains("ab, ab") && !shown.contains(&hex),
            "{shown}"
        );
    }
    assert!(format!("{row:?}").contains("session_version: 3"));
    assert!(format!("{device:?}").contains("Ferret for Firefox (Windows)"));
    assert_eq!(format!("{:?}", AccessLookup::Expired), "Expired");
    assert_eq!(
        format!("{:?}", AccessLookup::DeviceRevoked),
        "DeviceRevoked"
    );
    assert!(matches!(
        DeviceInsertError::Store(rusqlite::Error::QueryReturnedNoRows),
        DeviceInsertError::Store(_)
    ));
    assert!(!matches!(
        DeviceInsertError::Quota,
        DeviceInsertError::KeyInUse
    ));
}
