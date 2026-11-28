//! The account log (`ferret_account_events`) and `GET /api/account/events`:
//! each account reads its own log, newest first and a page at a time, with a
//! full vault session only; an account keeps its newest 1 000 events; and an
//! event never holds a code or a token. Spec: Fase 1 § 11 (the account log),
//! § 6.3 (every code is in the account log) and § 8.8.

mod support;

use axum::http::{Method, StatusCode};
use ferret_server::accounts::log::{self, Actor, EventKind, MAX_EVENTS_PER_USER};
use ferret_server::auth::session::Origin;
use ferret_server::cli::{self, Command};
use ferret_server::wire::{AccountEventsRes, MAX_EVENTS_PAGE};
use ferret_server_auth::{Clock as _, SessionScope};
use serde_json::{Value, json};
use support::accounts::{CLIENT_PASSWORD, client_account};
use support::backup::capture_log;
use support::device::{DeviceClient, device_app};
use support::handoff::set_role;
use support::session::{hex, issue, seed};
use support::{Jar, Req, Res, TestApp, Which};

const PATH: &str = "/api/account/events";

fn now(app: &TestApp) -> i64 {
    i64::try_from(app.clock.now_unix()).expect("a time")
}

/// Writes `n` events of `kind` by `actor` for `user`, one second apart, from
/// the clock's time on.
async fn record_many(app: &TestApp, user: i64, kind: EventKind, actor: Actor, n: usize) {
    let start = now(app);
    app.state
        .vault_db
        .with_conn(move |conn| {
            let tx = conn.transaction()?;
            for i in 0..n {
                let at = start + i64::try_from(i).expect("a count");
                log::record(&tx, user, kind, &actor, at)?;
            }
            tx.commit()?;
            Ok(())
        })
        .await
        .expect("the events");
}

/// The rows of a user's log, oldest first: `(id, kind, actor, actor_name)`.
async fn rows_of(app: &TestApp, user: i64) -> Vec<(i64, String, String, String)> {
    app.state
        .vault_db
        .with_conn(move |conn| {
            let mut stmt = conn.prepare(
                "SELECT id, kind, actor, actor_name FROM ferret_account_events
                 WHERE user_id = ?1 ORDER BY id",
            )?;
            let rows = stmt
                .query_map([user], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)))?
                .collect::<Result<Vec<_>, _>>()?;
            Ok(rows)
        })
        .await
        .expect("the log")
}

/// `GET /api/account/events` with `query` from the web vault, with the
/// cookies of `jar`.
async fn events_res(app: &TestApp, jar: &Jar, query: &str) -> Res {
    let mut req = Req::get(&format!("{PATH}{query}"))
        .page_fetch(Which::Vault)
        .header("x-forwarded-proto", "https")
        .header("sec-fetch-site", "same-origin");
    if let Some(cookie) = jar.header() {
        req = req.header("cookie", &cookie);
    }
    app.call_raw(Which::Vault, req.build()).await
}

/// The page, checked as the client checks it.
async fn events(app: &TestApp, jar: &Jar, query: &str) -> (Value, AccountEventsRes) {
    let res = events_res(app, jar, query).await;
    assert_eq!(res.status, StatusCode::OK, "{query}: {}", res.text());
    assert_eq!(res.header("cache-control"), "no-store");
    let page: AccountEventsRes = serde_json::from_slice(&res.body).expect("the wire shape");
    (res.json(), page)
}

fn ids(page: &AccountEventsRes) -> Vec<u64> {
    page.events.iter().map(|e| e.id).collect()
}

// ------------------------------------------------------------- reading

#[tokio::test]
async fn each_account_sees_only_its_own_events() {
    let app = device_app().await;
    let admin = seed(&app, 1).await;
    set_role(&app, admin.user_id, "admin").await;
    let a = seed(&app, 2).await;
    let b = seed(&app, 3).await;
    let by_admin = Actor::Admin {
        user_id: Some(admin.user_id),
        name: "user1@example.com".into(),
    };
    record_many(
        &app,
        a.user_id,
        EventKind::SignInCodeIssued,
        by_admin.clone(),
        1,
    )
    .await;
    record_many(&app, b.user_id, EventKind::AccountDisabled, by_admin, 1).await;
    record_many(
        &app,
        b.user_id,
        EventKind::SignInCodeRedeemed,
        Actor::Account,
        1,
    )
    .await;
    record_many(&app, a.user_id, EventKind::ServerRestored, Actor::Server, 1).await;

    let jar_a = issue(&app, a.user_id, Origin::Vault, SessionScope::Full, 1)
        .await
        .jar;
    let jar_b = issue(&app, b.user_id, Origin::Vault, SessionScope::Full, 2)
        .await
        .jar;
    let jar_admin = issue(&app, admin.user_id, Origin::Vault, SessionScope::Full, 3)
        .await
        .jar;

    let (json_a, page_a) = events(&app, &jar_a, "").await;
    let at = now(&app);
    assert_eq!(
        json_a["events"]
            .as_array()
            .expect("a list")
            .iter()
            .map(|e| {
                (
                    e["kind"].as_str().unwrap().to_string(),
                    e["actor"].as_str().unwrap().to_string(),
                    e["actor_name"].as_str().unwrap().to_string(),
                    e["at"].as_i64().unwrap(),
                )
            })
            .collect::<Vec<_>>(),
        vec![
            ("server_restored".into(), "server".into(), String::new(), at),
            (
                "sign_in_code_issued".into(),
                "admin".into(),
                "user1@example.com".into(),
                at
            ),
        ],
        "newest first: {json_a}"
    );
    assert!(!page_a.more);

    let (json_b, page_b) = events(&app, &jar_b, "").await;
    let kinds: Vec<&str> = page_b.events.iter().map(|e| e.kind.as_str()).collect();
    assert_eq!(
        kinds,
        ["sign_in_code_redeemed", "account_disabled"],
        "{json_b}"
    );
    assert_eq!(json_b["events"][0]["actor"], "account");
    // No id of one account's log is in the other's.
    for id in ids(&page_a) {
        assert!(!ids(&page_b).contains(&id));
    }
    // A `before` that names an event of the other account shows nothing of it.
    let before = page_b.events[0].id + 1;
    let (_, from_a) = events(&app, &jar_a, &format!("?before={before}")).await;
    let older_of_a: Vec<u64> = ids(&page_a).into_iter().filter(|id| *id < before).collect();
    assert!(!older_of_a.is_empty());
    assert_eq!(ids(&from_a), older_of_a);

    // The administrator's own log is empty: the events are not the actor's.
    let (_, own) = events(&app, &jar_admin, "").await;
    assert!(own.events.is_empty());
    assert!(!own.more);
}

#[tokio::test]
async fn events_page_backwards_and_say_more() {
    let app = device_app().await;
    let user = seed(&app, 1).await;
    record_many(
        &app,
        user.user_id,
        EventKind::ServerRestored,
        Actor::Server,
        250,
    )
    .await;
    let all: Vec<u64> = rows_of(&app, user.user_id)
        .await
        .into_iter()
        .rev()
        .map(|r| u64::try_from(r.0).unwrap())
        .collect();
    assert_eq!(all.len(), 250);
    let jar = issue(&app, user.user_id, Origin::Vault, SessionScope::Full, 1)
        .await
        .jar;

    // Without a limit, a page of 50; the largest page is 100.
    let (_, first) = events(&app, &jar, "").await;
    assert_eq!(ids(&first), all[..50]);
    assert!(first.more);
    let (_, first) = events(&app, &jar, &format!("?limit={MAX_EVENTS_PAGE}")).await;
    assert_eq!(ids(&first), all[..100]);
    assert!(first.more);

    // Backwards from the oldest of each page.
    let before = first.events.last().expect("an event").id;
    let (_, second) = events(&app, &jar, &format!("?before={before}&limit=100")).await;
    assert_eq!(ids(&second), all[100..200]);
    assert!(second.more);
    let before = second.events.last().expect("an event").id;
    let (_, third) = events(&app, &jar, &format!("?limit=100&before={before}")).await;
    assert_eq!(ids(&third), all[200..]);
    assert!(!third.more, "nothing older");
    // Exactly the rest: no more.
    let before = all[199];
    let (_, exact) = events(&app, &jar, &format!("?before={before}&limit=50")).await;
    assert_eq!(ids(&exact), all[200..]);
    assert!(!exact.more);
    let (_, one) = events(&app, &jar, "?limit=1").await;
    assert_eq!(ids(&one), all[..1]);
    assert!(one.more);
    // Before the oldest: an empty page.
    let (_, none) = events(&app, &jar, &format!("?before={}", all[249])).await;
    assert!(none.events.is_empty());
    assert!(!none.more);

    // A limit outside 1 to 100, or a query that is not one, is refused.
    for query in [
        "?limit=0",
        "?limit=101",
        "?limit=-1",
        "?before=abc",
        "?before=-5",
        "?before=9007199254740992",
        "?after=1",
    ] {
        let res = events_res(&app, &jar, query).await;
        assert_eq!(
            res.status,
            StatusCode::BAD_REQUEST,
            "{query}: {}",
            res.text()
        );
        assert_eq!(res.json(), json!({ "error": "bad_request" }), "{query}");
    }
}

#[tokio::test]
async fn a_user_keeps_at_most_1000_events() {
    let app = device_app().await;
    let user = seed(&app, 1).await;
    let other = seed(&app, 2).await;
    assert_eq!(MAX_EVENTS_PER_USER, 1_000);
    record_many(
        &app,
        other.user_id,
        EventKind::ServerRestored,
        Actor::Server,
        3,
    )
    .await;
    record_many(
        &app,
        user.user_id,
        EventKind::SignInCodeIssued,
        Actor::ServerCommand,
        1_000,
    )
    .await;
    let full = rows_of(&app, user.user_id).await;
    assert_eq!(full.len(), 1_000);

    // Five more push the five oldest out; the newest stay.
    record_many(
        &app,
        user.user_id,
        EventKind::SignInCodeRedeemed,
        Actor::Account,
        5,
    )
    .await;
    let kept = rows_of(&app, user.user_id).await;
    assert_eq!(kept.len(), 1_000);
    assert_eq!(kept[0].0, full[5].0, "the oldest went first");
    assert_eq!(
        kept.iter()
            .filter(|r| r.1 == "sign_in_code_redeemed")
            .count(),
        5
    );
    // The other account lost nothing.
    assert_eq!(rows_of(&app, other.user_id).await.len(), 3);

    // The restore's event for every account keeps the limit too.
    let at = now(&app);
    let logged = app
        .state
        .vault_db
        .with_conn(move |conn| Ok(log::record_restored_for_all(conn, at)?))
        .await
        .expect("the restore's events");
    assert_eq!(logged, 2);
    let kept_after = rows_of(&app, user.user_id).await;
    assert_eq!(kept_after.len(), 1_000);
    assert_eq!(kept_after[0].0, kept[1].0);
    assert_eq!(kept_after.last().expect("a row").1, "server_restored");
    assert_eq!(rows_of(&app, other.user_id).await.len(), 4);
}

#[tokio::test]
async fn a_reset_session_a_device_token_and_the_admin_listener_cannot_read_events() {
    let app = device_app().await;
    let client = client_account(&app, 1).await;
    let user = client.ids.user_id;
    record_many(&app, user, EventKind::ServerRestored, Actor::Server, 2).await;

    // A full session reads it (the control).
    let full = issue(&app, user, Origin::Vault, SessionScope::Full, 1).await;
    let (_, page) = events(&app, &full.jar, "").await;
    assert_eq!(page.events.len(), 2);

    // A reset session (a redeemed sign-in code) does not.
    let reset = issue(&app, user, Origin::Vault, SessionScope::AccountReset, 2).await;
    let res = events_res(&app, &reset.jar, "").await;
    assert_eq!(res.status, StatusCode::UNAUTHORIZED, "{}", res.text());
    assert_eq!(res.json(), json!({ "error": "unauthorized" }));

    // No session at all.
    let res = events_res(&app, &Jar::default(), "").await;
    assert_eq!(res.status, StatusCode::UNAUTHORIZED, "{}", res.text());

    // A device's access token with a good proof does not either.
    let mut device = DeviceClient::new(1);
    let res = device
        .sign_in(&app, "client1@example.com", CLIENT_PASSWORD)
        .await;
    assert_eq!(res.status, StatusCode::OK, "{}", res.text());
    let res = device
        .send(&app, device.token_req(&app, Method::GET, PATH))
        .await;
    assert_eq!(res.status, StatusCode::UNAUTHORIZED, "{}", res.text());
    // The device's sync route works with the same token (the control).
    let res = device
        .send(&app, device.token_req(&app, Method::GET, "/api/sync/items"))
        .await;
    assert_eq!(res.status, StatusCode::OK, "{}", res.text());

    // The admin listener has no such route, with an admin session or the
    // vault's cookies.
    set_role(&app, user, "admin").await;
    let admin = issue(&app, user, Origin::Admin, SessionScope::Full, 3).await;
    for jar in [&admin.jar, &full.jar] {
        let mut req = Req::get(PATH).page_fetch(Which::Admin);
        if let Some(cookie) = jar.header() {
            req = req.header("cookie", &cookie);
        }
        let res = app.call_raw(Which::Admin, req.build()).await;
        assert_eq!(res.status, StatusCode::NOT_FOUND, "{}", res.text());
        assert!(!res.text().contains("server_restored"));
    }
}

// ------------------------------------------------------------- no secrets

#[tokio::test]
async fn an_event_holds_no_code_and_no_token() {
    let app = device_app().await;
    let admin = seed(&app, 1).await;
    set_role(&app, admin.user_id, "admin").await;
    let user = seed(&app, 2).await;

    let (log_text, guard) = capture_log();
    // A code made with the command, then redeemed for a reset session.
    let said = cli::run(Command::SignInCodeIssue {
        data_dir: app.dir.clone(),
        email: "user2@example.com".into(),
        confirmed: true,
    })
    .expect("a code");
    let code = said
        .split_whitespace()
        .find(|w| w.len() == 39 && w.matches('-').count() == 7)
        .expect("the code in the output")
        .to_string();
    let res = app
        .call_raw(
            Which::Vault,
            Req::post("/api/auth/redeem")
                .page_fetch(Which::Vault)
                .header("x-forwarded-proto", "https")
                .json(&json!({ "email": "user2@example.com", "code": code }))
                .build(),
        )
        .await;
    assert_eq!(res.status, StatusCode::OK, "{}", res.text());
    let mut jar = Jar::default();
    jar.absorb(&res.headers);
    drop(guard);
    let logged = log_text.text();
    assert!(
        logged.contains("a sign-in code was redeemed"),
        "the capture works: {logged}"
    );

    // Both events are there.
    let rows = rows_of(&app, user.user_id).await;
    let kinds: Vec<(&str, &str)> = rows.iter().map(|r| (r.1.as_str(), r.2.as_str())).collect();
    assert_eq!(
        kinds,
        [
            ("sign_in_code_issued", "server_command"),
            ("sign_in_code_redeemed", "account")
        ]
    );

    // Every column of every event, as text and as hex.
    let table: String = app
        .state
        .vault_db
        .with_conn(|conn| {
            let mut stmt = conn.prepare(
                "SELECT id, user_id, at, kind, actor, actor_name, hex(kind), hex(actor_name)
                 FROM ferret_account_events",
            )?;
            let rows = stmt
                .query_map([], |r| {
                    let mut text = String::new();
                    for i in 0..8 {
                        let value: rusqlite::types::Value = r.get(i)?;
                        text.push_str(&format!("{value:?} "));
                    }
                    Ok(text)
                })?
                .collect::<Result<Vec<_>, _>>()?;
            Ok(rows.join("\n"))
        })
        .await
        .expect("the table");
    let hash = vole_kit::auth::sign_in_codes::hash(&code);
    let sid = jar.get("__Host-ferret_sid").expect("a session cookie");
    let canaries = [
        code.clone(),
        code.replace('-', ""),
        code.to_lowercase(),
        hex(&hash),
        hex(&hash).to_uppercase(),
        sid.to_string(),
    ];
    for canary in &canaries {
        assert!(!table.contains(canary.as_str()), "the log holds {canary}");
        assert!(!logged.contains(canary.as_str()), "tracing holds {canary}");
    }
}
