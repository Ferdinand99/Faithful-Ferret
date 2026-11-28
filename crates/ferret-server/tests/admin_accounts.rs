//! The Users page of the admin pages (`/settings/accounts`): the list of
//! accounts with Ferret's columns, the invitations, the one-time sign-in code,
//! the kit's closed user pages and who may reach any of it.
//! Spec: Fase 1 § 11 ("Several accounts", "The Users page"), § 6.3, § 4.2.

mod support;

use std::time::Duration;

use axum::http::{Method, StatusCode};
use base64::Engine as _;
use base64::engine::general_purpose::{STANDARD, STANDARD_NO_PAD, URL_SAFE_NO_PAD};
use ferret_server::accounts::actions::{self, ActionError};
use ferret_server::accounts::log::Actor;
use ferret_server::auth::login;
use ferret_server::auth::session::{Origin, lookup};
use ferret_server::ids::{DeviceId, SidHash};
use ferret_server::vault::notify::Revoked;
use ferret_server_auth::{PreloginPolicy, SessionScope};
use serde_json::json;
use support::accounts::{CLIENT_PASSWORD, add_account_to_app, client_account, insert_user};
use support::device::{DeviceClient, login_start};
use support::events::Stream;
use support::handoff::{
    admin_user, begin, code_of, hand_over, mint, now, redeem, set_cookie, set_role, vault_session,
};
use support::session::{Issued, issue, seed, session_version};
use support::{ADMIN_URL, Req, Res, TestApp, VAULT_URL, Which};
use vole_kit::db::role::Role;

const SECOND: Duration = Duration::from_secs(1);

const PATH: &str = "/settings/accounts";
const INVITES: &str = "/settings/accounts/invites";
const SID_COOKIE: &str = "__Host-ferret_sid";
const REAUTH_COOKIE: &str = "__Host-ferret_reauth";

// ---------------------------------------------------------------- helpers

async fn get(app: &TestApp, path: &str) -> Res {
    app.call(Which::Admin, Req::get(path).build()).await
}

async fn get_in(app: &TestApp, path: &str, language: &str) -> Res {
    app.call(
        Which::Admin,
        Req::get(path).header("accept-language", language).build(),
    )
    .await
}

/// A form post from a page of the admin origin, as a browser sends one.
async fn post(app: &TestApp, path: &str) -> Res {
    app.call(
        Which::Admin,
        Req::post(path)
            .header("origin", ADMIN_URL)
            .form(&[])
            .build(),
    )
    .await
}

/// A fresh confirmation of the master password for the admin session: a
/// re-auth grant on the vault origin, handed over as `reauth`.
async fn confirm(app: &TestApp, vault: &Issued) {
    support::handoff::grant_reauth(app, vault, 0);
    let res = hand_over(app, PATH, "reauth").await;
    assert_eq!(res.status, StatusCode::OK, "reauth: {}", res.text());
}

/// An administrator with a fresh confirmation, and the app.
async fn confirmed_admin() -> (TestApp, i64, Issued) {
    let app = TestApp::new_at_real_time().await;
    let (admin, vault) = admin_user(&app, 1).await;
    confirm(&app, &vault).await;
    (app, admin.user_id, vault)
}

async fn count(app: &TestApp, query: &'static str) -> i64 {
    app.state
        .vault_db
        .with_conn(move |conn| Ok(conn.query_row(query, [], |r| r.get(0))?))
        .await
        .expect("a count")
}

async fn pending_invites(app: &TestApp) -> i64 {
    app.state
        .vault_db
        .with_conn(|conn| Ok(vole_kit::db::invites::count_pending(conn)?))
        .await
        .expect("a count")
}

/// Whether the invitation with this token is pending, and its role and maker.
async fn pending_of(app: &TestApp, token: &str) -> Option<(Role, Option<i64>)> {
    let hash = vole_kit::auth::invites::hash(token);
    app.state
        .vault_db
        .with_conn(move |conn| {
            Ok(vole_kit::db::invites::find_pending(conn, &hash)?
                .map(|invite| (invite.role, invite.created_by)))
        })
        .await
        .expect("a lookup")
}

/// An invitation straight into the database, as the page would make it.
async fn insert_invite(app: &TestApp, by: i64) -> (i64, String) {
    let token = vole_kit::auth::invites::generate();
    let hash = vole_kit::auth::invites::hash(&token);
    let id = app
        .state
        .vault_db
        .with_conn(move |conn| {
            Ok(vole_kit::db::invites::insert(
                conn,
                &hash,
                Role::Viewer,
                "",
                by,
            )?)
        })
        .await
        .expect("an invitation");
    (id, token)
}

async fn pending_code(app: &TestApp, user: i64) -> i64 {
    app.state
        .vault_db
        .with_conn(move |conn| Ok(vole_kit::db::sign_in_codes::count_pending(conn, user)?))
        .await
        .expect("a count")
}

/// The events of an account: kind, actor, actor name.
async fn events_of(app: &TestApp, user: i64) -> Vec<(String, String, String)> {
    app.state
        .vault_db
        .with_conn(move |conn| {
            let mut statement = conn.prepare(
                "SELECT kind, actor, actor_name FROM ferret_account_events
                 WHERE user_id = ?1 ORDER BY id",
            )?;
            let rows = statement
                .query_map([user], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))?
                .collect::<Result<Vec<_>, _>>()?;
            Ok(rows)
        })
        .await
        .expect("the events")
}

/// The invitation tokens of the links on a page.
fn invite_tokens(html: &str) -> Vec<String> {
    html.split("#invite=")
        .skip(1)
        .map(|rest| {
            rest.chars()
                .take_while(char::is_ascii_alphanumeric)
                .collect::<String>()
        })
        .collect()
}

/// The sign-in code a page shows, if it shows one.
fn shown_code(html: &str) -> Option<String> {
    let start = html.find("id=\"created-sign-in-code\">")? + "id=\"created-sign-in-code\">".len();
    let rest = &html[start..];
    Some(rest[..rest.find("</code>")?].to_string())
}

/// The row of an account on the page.
fn row_of(html: &str, user: i64) -> &str {
    let marker = format!("id=\"account-{user}\"");
    let start = html
        .find(&marker)
        .unwrap_or_else(|| panic!("no row of account {user}"));
    let rest = &html[start..];
    &rest[..rest.find("</li>").expect("the row closes")]
}

/// The value of a column of a row.
fn column<'a>(row: &'a str, name: &str) -> &'a str {
    let marker = format!("data-col=\"{name}\"");
    let start = row
        .find(&marker)
        .unwrap_or_else(|| panic!("no column {name}"));
    let rest = &row[start..];
    let rest = &rest[rest.find('>').expect("the tag closes") + 1..];
    &rest[..rest.find('<').expect("the value ends")]
}

fn assert_back(res: &Res) {
    assert_eq!(res.status, StatusCode::SEE_OTHER, "{}", res.text());
    assert_eq!(res.header("location"), PATH);
}

/// The answer of a post that made a link: `303` to the page with the slot of
/// the link (32 hex digits), and nothing of the link in the answer. Answers
/// the address of that page.
fn assert_to_link(res: &Res) -> String {
    assert_eq!(res.status, StatusCode::SEE_OTHER, "{}", res.text());
    let location = res.header("location").to_string();
    let slot = location
        .strip_prefix(&format!("{PATH}?shown="))
        .unwrap_or_else(|| panic!("the page of the link: {location}"));
    assert!(
        slot.len() == 32 && slot.bytes().all(|b| b.is_ascii_hexdigit()),
        "{slot}"
    );
    assert!(!res.text().contains("#invite="), "no link in the answer");
    location
}

/// A post that makes a link, and the page that shows it (read once).
async fn made_link(app: &TestApp, path: &str) -> (Res, Res) {
    let res = post(app, path).await;
    let location = assert_to_link(&res);
    let page = get(app, &location).await;
    assert_eq!(page.status, StatusCode::OK, "{}", page.text());
    (res, page)
}

// ---------------------------------------------------------------- the list

#[tokio::test]
async fn the_users_page_lists_every_account_with_the_ferret_columns() {
    let app = TestApp::new_at_real_time().await;
    let (admin, _vault) = admin_user(&app, 1).await;
    let other = add_account_to_app(&app, 7).await;
    let user = other.user_id;
    let at = now(&app);
    // The vault's own counters, two devices with tokens (one revoked, which
    // does not count) and three live vault sessions on two browsers.
    app.state
        .vault_db
        .with_conn(move |conn| {
            conn.execute(
                "UPDATE ferret_vaults SET item_count = 7, bytes_used = 123456
                 WHERE account_id = (SELECT account_id FROM ferret_accounts WHERE user_id = ?1)",
                [user],
            )?;
            for (n, revoked) in [(1u8, None), (2u8, Some(at))] {
                conn.execute(
                    "INSERT INTO ferret_devices
                       (device_id, user_id, jkt, name, platform, session_version,
                        created_at, last_seen, revoked_at)
                     VALUES (?1, ?2, ?3, 'Laptop', 'linux',
                             (SELECT session_version FROM users WHERE id = ?2), ?4, ?4, ?5)",
                    rusqlite::params![
                        vec![0xe0, n, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
                        user,
                        vec![n; 32],
                        at,
                        revoked
                    ],
                )?;
            }
            Ok(())
        })
        .await
        .expect("the counters and devices");
    for device in [21, 21, 22] {
        issue(&app, user, Origin::Vault, SessionScope::Full, device).await;
    }
    // A pending sign-in code.
    let hash = vole_kit::auth::sign_in_codes::hash("a-code");
    let admin_id = admin.user_id;
    app.state
        .vault_db
        .with_conn(move |conn| {
            vole_kit::db::sign_in_codes::insert(conn, user, &hash, admin_id)?;
            Ok(())
        })
        .await
        .expect("a code");

    let res = get_in(&app, PATH, "en").await;
    assert_eq!(res.status, StatusCode::OK, "{}", res.text());
    let page = res.text();
    let row = row_of(&page, user);
    assert!(row.contains("user7@example.com"), "{row}");
    assert_eq!(column(row, "items"), "7");
    assert_eq!(column(row, "space"), "120.5 KB");
    assert_eq!(
        column(row, "devices"),
        "3",
        "one token device and two browsers"
    );
    assert_eq!(column(row, "totp"), "off");
    assert_eq!(column(row, "status"), "Active");
    assert!(column(row, "code").contains("Sign-in code until"), "{row}");
    assert!(row.contains("datetime="), "times are the kit's: {row}");
    // The administrator's own row says so and has no action.
    let own = row_of(&page, admin.user_id);
    assert!(own.contains("user1@example.com"), "{own}");
    assert!(own.contains("(you)"), "{own}");
    assert!(!own.contains("sign-in-code"), "{own}");
    // No PIN column: the server does not know whether a device has one.
    assert!(!page.contains("PIN"), "a PIN column");
    // Every account is listed, the one without a vault too.
    let bare = app
        .state
        .vault_db
        .with_conn(|conn| Ok(insert_user(conn, "bare@example.com")))
        .await
        .expect("a user");
    let page = get(&app, PATH).await.text();
    assert_eq!(column(row_of(&page, bare), "items"), "0");
    assert_eq!(column(row_of(&page, bare), "space"), "0 B");
    // In Norwegian the decimal mark is a comma.
    let nb = get_in(&app, PATH, "nb").await.text();
    assert_eq!(column(row_of(&nb, user), "space"), "120,5 KB");
    assert_eq!(column(row_of(&nb, user), "status"), "Aktiv");
}

/// Every blob of a vault, of an account's record and of its keys.
async fn vault_blobs(app: &TestApp) -> Vec<Vec<u8>> {
    app.state
        .vault_db
        .with_conn(|conn| {
            let mut out = Vec::new();
            for (table, columns) in [
                ("ferret_accounts", "opaque_record, pk_a, pk_r"),
                ("ferret_unlock_methods", "wrap"),
                ("ferret_items", "*"),
                ("ferret_checkpoints", "digest, mac, entries"),
            ] {
                let mut statement = conn.prepare(&format!("SELECT {columns} FROM {table}"))?;
                let n = statement.column_count();
                let mut rows = statement.query([])?;
                while let Some(row) = rows.next()? {
                    for i in 0..n {
                        if let rusqlite::types::ValueRef::Blob(b) = row.get_ref(i)? {
                            out.push(b.to_vec());
                        }
                    }
                }
            }
            Ok(out)
        })
        .await
        .expect("the blobs")
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[tokio::test]
async fn the_page_never_shows_a_vault_secret() {
    let app = TestApp::new_at_real_time().await;
    admin_user(&app, 1).await;
    add_account_to_app(&app, 7).await;
    let page = get(&app, PATH).await.text();
    let blobs = vault_blobs(&app).await;
    assert!(
        blobs.len() >= 8,
        "the account has its rows: {}",
        blobs.len()
    );
    for blob in blobs.iter().filter(|b| b.len() >= 16) {
        // Any 12-byte stretch of a blob, in every form a page could print it.
        // (A stretch of zeros is the padding of an id, not a secret.)
        for window in blob
            .chunks(12)
            .filter(|w| w.len() == 12 && w.iter().any(|b| *b != 0))
        {
            for shown in [
                hex(window),
                hex(window).to_uppercase(),
                STANDARD.encode(window),
                STANDARD_NO_PAD.encode(window),
                URL_SAFE_NO_PAD.encode(window),
            ] {
                assert!(!page.contains(&shown), "the page holds {shown}");
            }
        }
    }
}

// ------------------------------------------------------ the kit's pages

#[tokio::test]
async fn the_kit_users_routes_are_closed() {
    let (app, _admin, _vault) = confirmed_admin().await;
    let other = add_account_to_app(&app, 7).await;
    let user = other.user_id;
    let version = session_version(&app, user).await;

    let res = get(&app, "/settings/users").await;
    assert_eq!(res.status, StatusCode::SEE_OTHER);
    assert_eq!(res.header("location"), PATH);
    assert!(!res.text().contains("<form"));
    for path in [
        "/settings/users".to_string(),
        format!("/settings/users/{user}"),
        format!("/settings/users/{user}/password"),
        format!("/settings/users/{user}/2fa/reset"),
        format!("/settings/users/{user}/passkeys/reset"),
        format!("/settings/users/{user}/enable"),
        format!("/settings/users/{user}/disable"),
        format!("/settings/users/{user}/delete"),
        format!("/settings/users/{user}/sign-in-code"),
        format!("/settings/users/{user}/sign-in-code/revoke"),
    ] {
        let res = post(&app, &path).await;
        assert_eq!(res.status, StatusCode::NOT_FOUND, "POST {path}");
    }
    assert_eq!(
        get(&app, &format!("/settings/users/{user}")).await.status,
        StatusCode::NOT_FOUND
    );
    // The kit's invitation routes are not there either.
    assert_eq!(
        post(&app, "/settings/invites").await.status,
        StatusCode::NOT_FOUND
    );
    // Nothing was changed.
    let row: (i64, String, i64) = app
        .state
        .vault_db
        .with_conn(move |conn| {
            Ok(conn.query_row(
                "SELECT active, role, totp_enabled FROM users WHERE id = ?1",
                [user],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )?)
        })
        .await
        .expect("the user");
    assert_eq!(row, (1, "editor".to_string(), 0));
    assert_eq!(session_version(&app, user).await, version);
    assert_eq!(pending_code(&app, user).await, 0);
    assert!(events_of(&app, user).await.is_empty());
    // The menu has Ferret's Users tab, not the kit's.
    let page = get(&app, "/settings/security").await.text();
    assert!(page.contains("href=\"/settings/accounts\""));
    assert!(!page.contains("href=\"/settings/users\""));
}

// ------------------------------------------------------------ invitations

#[tokio::test]
async fn an_invitation_link_is_shown_once_with_no_store_and_points_at_the_vault_fragment() {
    let (app, admin, _vault) = confirmed_admin().await;
    // The post answers with a redirect to the page that shows the link once.
    let (res, shown) = made_link(&app, INVITES).await;
    assert_eq!(shown.header("cache-control"), "no-store");
    let page = shown.text();
    let tokens = invite_tokens(&page);
    assert_eq!(tokens.len(), 1, "one link on the page");
    let token = &tokens[0];
    assert_eq!(token.len(), 43);
    assert!(page.contains(&format!("{VAULT_URL}/vault/setup#invite={token}")));
    assert!(page.contains("Invitation made"), "the flash says so");
    // Never in a cookie (the message is a flash cookie), a header or the
    // address of the redirect.
    for answer in [&res, &shown] {
        for (name, value) in &answer.headers {
            let value = value.to_str().unwrap_or_default();
            assert!(!value.contains(token.as_str()), "{name}: {value}");
        }
    }
    // A reload of that page shows the link no more and makes nothing.
    let again = get(&app, res.header("location")).await;
    assert_eq!(again.status, StatusCode::OK);
    assert!(invite_tokens(&again.text()).is_empty(), "read once");
    assert_eq!(
        pending_invites(&app).await,
        1,
        "a reload makes no invitation"
    );
    assert_eq!(count(&app, "SELECT COUNT(*) FROM invites").await, 1);
    // The invitation is pending, for a viewer, made by the administrator.
    assert_eq!(
        pending_of(&app, token).await,
        Some((Role::Viewer, Some(admin)))
    );
    // The page that is read later lists it with its times, not its link.
    let res = get(&app, PATH).await;
    assert_eq!(res.status, StatusCode::OK);
    let later = res.text();
    assert!(!later.contains(token.as_str()));
    assert!(invite_tokens(&later).is_empty());
    let id: i64 = count(&app, "SELECT MAX(id) FROM invites").await;
    let marker = format!("id=\"invite-{id}\"");
    let entry = &later[later.find(&marker).expect("the pending invitation")..];
    let entry = &entry[..entry.find("</li>").expect("closes")];
    assert_eq!(
        entry.matches("datetime=").count(),
        2,
        "made and runs out: {entry}"
    );
    assert!(entry.contains("user1@example.com"), "who made it: {entry}");
}

#[tokio::test]
async fn creating_or_resending_an_invitation_needs_a_fresh_reauth() {
    let app = TestApp::new_at_real_time().await;
    let (admin, _vault) = admin_user(&app, 1).await;
    // Without a confirmation the page leads to one, coming back here.
    let page = get(&app, PATH).await.text();
    assert!(page.contains("href=\"/vault/reauth?next=%2Fsettings%2Faccounts\""));
    assert!(!page.contains(&format!("action=\"{INVITES}\"")));

    let res = post(&app, INVITES).await;
    assert_back(&res);
    assert!(invite_tokens(&res.text()).is_empty());
    assert_eq!(pending_invites(&app).await, 0, "nothing was made");

    let (id, token) = insert_invite(&app, admin.user_id).await;
    let res = post(&app, &format!("{INVITES}/{id}/resend")).await;
    assert_back(&res);
    assert!(
        pending_of(&app, &token).await.is_some(),
        "the old link works"
    );
    assert_eq!(pending_invites(&app).await, 1);
    // The page the redirect leads to says why.
    let res = get(&app, res.header("location")).await;
    assert!(
        res.text().contains("Confirm it’s you to make this change."),
        "the message says why"
    );
}

#[tokio::test]
async fn revoking_an_invitation_needs_none() {
    let app = TestApp::new_at_real_time().await;
    let (admin, _vault) = admin_user(&app, 1).await;
    let (id, token) = insert_invite(&app, admin.user_id).await;
    let (_other, kept) = insert_invite(&app, admin.user_id).await;
    let res = post(&app, &format!("{INVITES}/{id}/revoke")).await;
    assert_back(&res);
    assert!(pending_of(&app, &token).await.is_none(), "revoked");
    assert!(pending_of(&app, &kept).await.is_some(), "only that one");
    // Again, or an id that is not there: nothing changes.
    for gone in [id, 9_999] {
        assert_back(&post(&app, &format!("{INVITES}/{gone}/revoke")).await);
    }
    assert_eq!(pending_invites(&app).await, 1);
}

#[tokio::test]
async fn resend_revokes_the_old_link() {
    let (app, admin, _vault) = confirmed_admin().await;
    let first = invite_tokens(&made_link(&app, INVITES).await.1.text()).remove(0);
    let id: i64 = count(&app, "SELECT MAX(id) FROM invites").await;
    let (_res, shown) = made_link(&app, &format!("{INVITES}/{id}/resend")).await;
    assert_eq!(shown.header("cache-control"), "no-store");
    let tokens = invite_tokens(&shown.text());
    assert_eq!(tokens.len(), 1);
    let second = &tokens[0];
    assert_ne!(second, &first);
    assert!(
        pending_of(&app, &first).await.is_none(),
        "the old link is dead"
    );
    assert_eq!(
        pending_of(&app, second).await,
        Some((Role::Viewer, Some(admin)))
    );
    assert_eq!(pending_invites(&app).await, 1);
    // The old one cannot be sent again: nothing new is made.
    let res = post(&app, &format!("{INVITES}/{id}/resend")).await;
    assert_back(&res);
    assert_eq!(pending_invites(&app).await, 1);
    assert_eq!(count(&app, "SELECT COUNT(*) FROM invites").await, 2);
}

#[tokio::test]
async fn fifty_pending_invitations_is_the_limit() {
    let (app, admin, _vault) = confirmed_admin().await;
    for _ in 0..49 {
        insert_invite(&app, admin).await;
    }
    let res = post(&app, INVITES).await;
    assert_to_link(&res);
    assert_eq!(pending_invites(&app).await, 50, "the 50th");
    let res = post(&app, INVITES).await;
    assert_back(&res);
    assert_eq!(pending_invites(&app).await, 50, "no 51st");
    let page = get(&app, PATH).await.text();
    assert!(
        page.contains("50 invitations are open"),
        "the page says why"
    );
    // Sending one again keeps the count.
    let id: i64 = count(&app, "SELECT MAX(id) FROM invites").await;
    let res = post(&app, &format!("{INVITES}/{id}/resend")).await;
    assert_to_link(&res);
    assert_eq!(pending_invites(&app).await, 50);
    // The action refuses the 51st by itself too.
    let by = Actor::Admin {
        user_id: Some(admin),
        name: "user1@example.com".into(),
    };
    let full = app
        .state
        .vault_db
        .with_conn(move |conn| Ok(actions::create_invite(conn, &by).map(|_| ())))
        .await
        .expect("the database");
    assert!(matches!(full, Err(ActionError::Full)), "{full:?}");
}

// --------------------------------------------------------- the sign-in code

#[tokio::test]
async fn a_sign_in_code_needs_a_fresh_reauth_and_is_logged_for_the_user() {
    let app = TestApp::new_at_real_time().await;
    let (_admin, vault) = admin_user(&app, 1).await;
    let user = add_account_to_app(&app, 7).await.user_id;
    let path = format!("/settings/accounts/{user}/sign-in-code");

    let res = post(&app, &path).await;
    assert_back(&res);
    assert_eq!(pending_code(&app, user).await, 0);
    assert!(events_of(&app, user).await.is_empty());

    confirm(&app, &vault).await;
    let res = post(&app, &path).await;
    assert_eq!(res.status, StatusCode::OK, "{}", res.text());
    assert_eq!(res.header("cache-control"), "no-store");
    let page = res.text();
    let code = shown_code(&page).expect("the code on the page");
    assert!(!code.is_empty());
    assert!(page.contains(&format!("{VAULT_URL}/vault/#/recover")));
    assert!(page.contains("user7@example.com"));
    for (name, value) in &res.headers {
        let value = value.to_str().unwrap_or_default();
        assert!(!value.contains(code.as_str()), "{name}");
    }
    // It is the account's pending code, and its log says who made it.
    let hash = vole_kit::auth::sign_in_codes::hash(&code);
    let is_pending = app
        .state
        .vault_db
        .with_conn(move |conn| Ok(vole_kit::db::sign_in_codes::is_pending(conn, &hash, user)?))
        .await
        .expect("a lookup");
    assert!(is_pending);
    assert_eq!(
        events_of(&app, user).await,
        vec![(
            "sign_in_code_issued".to_string(),
            "admin".to_string(),
            "user1@example.com".to_string()
        )]
    );
    // The page that is read later does not show it again.
    let later = get(&app, PATH).await.text();
    assert!(shown_code(&later).is_none());
    assert!(!later.contains(code.as_str()));
    assert!(column(row_of(&later, user), "code").contains("Sign-in code until"));
}

#[tokio::test]
async fn a_sign_in_code_uses_the_confirmation_up() {
    let (app, _admin, vault) = confirmed_admin().await;
    let first = add_account_to_app(&app, 7).await.user_id;
    let second = add_account_to_app(&app, 8).await.user_id;
    let res = post(&app, &format!("/settings/accounts/{first}/sign-in-code")).await;
    assert_eq!(res.status, StatusCode::OK, "{}", res.text());
    assert!(shown_code(&res.text()).is_some());
    // The answer removes the grant, and the page it shows asks again.
    let removed = set_cookie(&res, REAUTH_COOKIE).expect("the grant is removed");
    assert!(
        removed.starts_with(&format!("{REAUTH_COOKIE}=;")) || removed.contains("Max-Age=0"),
        "{removed}"
    );
    assert!(app.jar(Which::Admin).get(REAUTH_COOKIE).is_none());
    assert!(
        res.text()
            .contains("href=\"/vault/reauth?next=%2Fsettings%2Faccounts\"")
    );

    // A second code, for another account, needs a new confirmation.
    let res = post(&app, &format!("/settings/accounts/{second}/sign-in-code")).await;
    assert_back(&res);
    assert_eq!(pending_code(&app, second).await, 0);
    assert!(events_of(&app, second).await.is_empty());
    // A new confirmation makes it.
    confirm(&app, &vault).await;
    let res = post(&app, &format!("/settings/accounts/{second}/sign-in-code")).await;
    assert_eq!(res.status, StatusCode::OK, "{}", res.text());
    assert_eq!(pending_code(&app, second).await, 1);
    // That code used the new confirmation up too; an invitation, once
    // confirmed again, keeps it (two in a row): only a code spends it.
    let res = post(&app, INVITES).await;
    assert_back(&res);
    confirm(&app, &vault).await;
    assert_to_link(&post(&app, INVITES).await);
    assert_to_link(&post(&app, INVITES).await);
}

#[tokio::test]
async fn a_code_whose_account_changes_before_its_event_is_revoked() {
    let app = TestApp::new().await;
    let admin = seed(&app, 1).await.user_id;
    set_role(&app, admin, "admin").await;
    let user = add_account_to_app(&app, 7).await.user_id;
    let by = Actor::Admin {
        user_id: Some(admin),
        name: "user1@example.com".into(),
    };
    let at = now(&app);
    // The account is disabled in the moment between the first check and the
    // event: the kit's insert does it here, through a trigger of this
    // connection.
    let result = app
        .state
        .vault_db
        .with_conn(move |conn| {
            conn.execute_batch(
                "CREATE TEMP TRIGGER disable_on_code AFTER INSERT ON sign_in_codes
                 BEGIN UPDATE users SET active = 0 WHERE id = NEW.user_id; END;",
            )?;
            let result = actions::issue_sign_in_code(conn, user, &by, at).map(|_| ());
            conn.execute_batch("DROP TRIGGER temp.disable_on_code")?;
            Ok(result)
        })
        .await
        .expect("the database");
    assert!(matches!(result, Err(ActionError::Disabled)), "{result:?}");
    assert_eq!(pending_code(&app, user).await, 0, "the code is revoked");
    assert!(events_of(&app, user).await.is_empty(), "and not logged");
}

// ------------------------------------------------- the rules of the target

#[tokio::test]
async fn no_action_works_on_your_own_account_or_an_admin() {
    let (app, admin, _vault) = confirmed_admin().await;
    let other_admin = seed(&app, 2).await.user_id;
    set_role(&app, other_admin, "admin").await;
    let bare = app
        .state
        .vault_db
        .with_conn(|conn| Ok(insert_user(conn, "bare@example.com")))
        .await
        .expect("a user");
    let user = add_account_to_app(&app, 7).await.user_id;

    for (target, status) in [
        (admin, StatusCode::FORBIDDEN),
        (other_admin, StatusCode::FORBIDDEN),
        (bare, StatusCode::NOT_FOUND),
        (9_999, StatusCode::NOT_FOUND),
    ] {
        let res = post(&app, &format!("/settings/accounts/{target}/sign-in-code")).await;
        assert_eq!(res.status, status, "{target}: {}", res.text());
        assert!(shown_code(&res.text()).is_none());
        assert_eq!(pending_code(&app, target).await, 0, "{target}");
        assert!(events_of(&app, target).await.is_empty(), "{target}");
    }
    // Nor any other action: disable, enable, sign out everywhere, delete.
    for (target, status) in [
        (admin, StatusCode::FORBIDDEN),
        (other_admin, StatusCode::FORBIDDEN),
        (bare, StatusCode::NOT_FOUND),
        (9_999, StatusCode::NOT_FOUND),
    ] {
        let version = if target == 9_999 {
            0
        } else {
            session_version(&app, target).await
        };
        for name in ["disable", "enable", "sign-out", "delete"] {
            let path = format!("/settings/accounts/{target}/{name}");
            let res = app
                .call(
                    Which::Admin,
                    Req::post(&path)
                        .header("origin", ADMIN_URL)
                        .form(&[("email", "user2@example.com")])
                        .build(),
                )
                .await;
            assert_eq!(res.status, status, "{name} {target}: {}", res.text());
        }
        if target != 9_999 {
            assert_eq!(session_version(&app, target).await, version, "{target}");
            assert!(events_of(&app, target).await.is_empty(), "{target}");
        }
    }
    let active: i64 = count(&app, "SELECT COUNT(*) FROM users WHERE active = 1").await;
    let users: i64 = count(&app, "SELECT COUNT(*) FROM users").await;
    assert_eq!((active, users), (4, 4), "nothing was disabled or deleted");
    // The page offers no action on those rows either.
    let page = get(&app, PATH).await.text();
    for target in [admin, other_admin] {
        let row = row_of(&page, target);
        for name in ["sign-in-code", "disable", "enable", "sign-out", "delete"] {
            assert!(!row.contains(&format!("/{name}\"")), "{target} {name}");
        }
    }
    for name in ["disable", "sign-out"] {
        assert!(row_of(&page, user).contains(&format!("/settings/accounts/{user}/{name}")));
    }
    assert!(row_of(&page, user).contains(&format!("/settings/accounts/{user}/sign-in-code")));

    // The rules themselves.
    let me = Actor::Admin {
        user_id: Some(admin),
        name: "user1@example.com".into(),
    };
    let rules = app
        .state
        .vault_db
        .with_conn(move |conn| {
            let ask = |by: &Actor, id| actions::target(conn, by, id).map(|t| t.user_id);
            Ok([
                ask(&me, admin),
                ask(&me, other_admin),
                ask(&me, bare),
                ask(&me, user),
                ask(&Actor::ServerCommand, other_admin),
                ask(&Actor::ServerCommand, bare),
            ])
        })
        .await
        .expect("the database");
    assert!(
        matches!(rules[0], Err(ActionError::NotAllowed)),
        "own account"
    );
    assert!(
        matches!(rules[1], Err(ActionError::NotAllowed)),
        "another admin"
    );
    assert!(matches!(rules[2], Err(ActionError::NotFound)), "no vault");
    assert!(matches!(rules[3], Ok(id) if id == user), "a user");
    assert!(
        matches!(rules[4], Ok(id) if id == other_admin),
        "the command"
    );
    assert!(
        matches!(rules[5], Err(ActionError::NotFound)),
        "the command, no vault"
    );
}

// ----------------------------------------------------------- who reaches it

#[tokio::test]
async fn a_viewer_never_reaches_the_page() {
    let (app, admin, _vault) = confirmed_admin().await;
    let user = add_account_to_app(&app, 7).await.user_id;
    let (id, token) = insert_invite(&app, admin).await;
    for role in ["viewer", "editor"] {
        set_role(&app, admin, role).await;
        assert_eq!(
            get(&app, PATH).await.status,
            StatusCode::FORBIDDEN,
            "{role}"
        );
        for path in [
            INVITES.to_string(),
            format!("{INVITES}/{id}/resend"),
            format!("{INVITES}/{id}/revoke"),
            format!("/settings/accounts/{user}/sign-in-code"),
            format!("/settings/accounts/{user}/disable"),
            format!("/settings/accounts/{user}/enable"),
            format!("/settings/accounts/{user}/sign-out"),
            format!("/settings/accounts/{user}/delete"),
        ] {
            let res = post(&app, &path).await;
            assert_eq!(res.status, StatusCode::FORBIDDEN, "{role} {path}");
        }
    }
    assert!(events_of(&app, user).await.is_empty());
    let active: i64 = count(&app, "SELECT COUNT(*) FROM users WHERE active = 1").await;
    assert_eq!(active, 2, "nothing was disabled or deleted");
    // The actions ask for an active administrator by themselves too.
    for name in ["disable", "sign-out", "enable", "delete"] {
        let by = Actor::Admin {
            user_id: Some(admin),
            name: "user1@example.com".into(),
        };
        let at = now(&app);
        let refused = app
            .state
            .vault_db
            .with_conn(move |conn| {
                Ok(match name {
                    "disable" => actions::disable(conn, user, &by, at).map(|_| ()),
                    "sign-out" => actions::sign_out_everywhere(conn, user, &by, at).map(|_| ()),
                    "enable" => actions::enable(conn, user, &by, at),
                    _ => actions::delete(conn, user, &by, "user7@example.com", Some(i64::MAX), at),
                })
            })
            .await
            .expect("the database");
        assert!(
            matches!(refused, Err(ActionError::NotAllowed)),
            "{name}: {refused:?}"
        );
    }
    assert_eq!(pending_invites(&app).await, 1);
    assert!(pending_of(&app, &token).await.is_some());
    assert_eq!(pending_code(&app, user).await, 0);
    // The action asks for an active administrator by itself too.
    let by = Actor::Admin {
        user_id: Some(admin),
        name: "user1@example.com".into(),
    };
    let refused = app
        .state
        .vault_db
        .with_conn(move |conn| Ok(actions::create_invite(conn, &by).map(|_| ())))
        .await
        .expect("the database");
    assert!(
        matches!(refused, Err(ActionError::NotAllowed)),
        "{refused:?}"
    );
}

#[tokio::test]
async fn the_hand_over_to_the_admin_pages_is_for_admins_only() {
    let app = TestApp::new_at_real_time().await;
    let user = seed(&app, 1).await;
    vault_session(&app, user.user_id, 1).await;
    for role in ["viewer", "editor"] {
        set_role(&app, user.user_id, role).await;
        let begun = begin(&app, "next=%2Fsettings%2Faccounts").await;
        let res = mint(&app, "login", PATH, &begun.challenge).await;
        assert_eq!(res.status, StatusCode::FORBIDDEN, "{role}: {}", res.text());
        assert_eq!(res.json(), json!({ "error": "forbidden" }));
    }
    assert_eq!(count(&app, "SELECT COUNT(*) FROM ferret_handoffs").await, 0);

    // A code made while the user was an administrator is refused at the
    // redeem once they are not, and spent.
    set_role(&app, user.user_id, "admin").await;
    let begun = begin(&app, "next=%2Fsettings%2Faccounts").await;
    let code = code_of(&mint(&app, "login", PATH, &begun.challenge).await);
    set_role(&app, user.user_id, "viewer").await;
    let res = redeem(&app, &code).await;
    assert_eq!(res.status, StatusCode::FORBIDDEN, "{}", res.text());
    assert_eq!(res.json(), json!({ "error": "forbidden" }));
    assert!(set_cookie(&res, SID_COOKIE).is_none());
    assert!(app.jar(Which::Admin).get(SID_COOKIE).is_none());
    assert_eq!(
        count(
            &app,
            "SELECT COUNT(*) FROM ferret_sessions WHERE origin = 'admin'"
        )
        .await,
        0
    );
    assert_eq!(count(&app, "SELECT COUNT(*) FROM ferret_handoffs").await, 0);
    // An administrator still gets through.
    set_role(&app, user.user_id, "admin").await;
    let res = hand_over(&app, PATH, "login").await;
    assert_eq!(res.status, StatusCode::OK, "{}", res.text());
}

#[tokio::test]
async fn the_page_and_its_forms_pass_the_kit_csrf_guard() {
    let (app, admin, _vault) = confirmed_admin().await;
    add_account_to_app(&app, 7).await;
    let (id, token) = insert_invite(&app, admin).await;
    // Every form of the page posts to this page's own routes (or the
    // sign-out of the layout).
    let page = get(&app, PATH).await.text();
    let forms: Vec<&str> = page.split("<form").skip(1).collect();
    assert!(forms.len() >= 4, "{}", forms.len());
    for form in forms {
        let head = &form[..form.find('>').expect("the tag closes")];
        assert!(head.contains("method=\"post\""), "{head}");
        assert!(
            head.contains("action=\"/settings/accounts") || head.contains("action=\"/logout\""),
            "{head}"
        );
    }
    // Without the admin origin, or from another site: refused, nothing made.
    for origin in [None, Some("https://evil.test"), Some(VAULT_URL)] {
        for path in [INVITES.to_string(), format!("{INVITES}/{id}/revoke")] {
            let mut req = Req::post(&path).form(&[]);
            if let Some(origin) = origin {
                req = req.header("origin", origin);
            }
            let res = app.call(Which::Admin, req.build()).await;
            assert_eq!(res.status, StatusCode::FORBIDDEN, "{origin:?} {path}");
        }
    }
    assert_eq!(pending_invites(&app).await, 1);
    assert!(pending_of(&app, &token).await.is_some());
    // From the page itself: through.
    assert_to_link(&post(&app, INVITES).await);
    assert_eq!(pending_invites(&app).await, 2);
}

// ------------------------------------- disable, enable, sign out, delete

/// An app whose clock is the machine's (for the kit's re-auth grant) and that
/// believes the test peer as a proxy (so device clients count as `https`).
async fn real_time_app() -> TestApp {
    let now = u64::try_from(vole_kit::auth::session::now_unix()).expect("a time");
    support::device::device_app_builder()
        .start(now)
        .build()
        .await
}

/// A form post with fields from a page of the admin origin.
async fn post_form(app: &TestApp, path: &str, fields: &[(&str, &str)]) -> Res {
    app.call(
        Which::Admin,
        Req::post(path)
            .header("origin", ADMIN_URL)
            .form(fields)
            .build(),
    )
    .await
}

fn action(user: i64, name: &str) -> String {
    format!("/settings/accounts/{user}/{name}")
}

/// The page the redirect of an action leads to, with its message.
async fn followed(app: &TestApp, res: &Res) -> String {
    assert_back(res);
    get_in(app, res.header("location"), "en").await.text()
}

/// The administrator as the actions see it.
fn admin_actor(admin: i64) -> Actor {
    Actor::Admin {
        user_id: Some(admin),
        name: "user1@example.com".into(),
    }
}

/// A device of `email` with key `key`, signed in with the client password.
async fn device_of(app: &TestApp, email: &str, key: u8) -> DeviceClient {
    let mut device = DeviceClient::new(key);
    let res = device.sign_in(app, email, CLIENT_PASSWORD).await;
    assert_eq!(res.status, StatusCode::OK, "{}", res.text());
    device
}

/// A sync request of `device` with its access token.
async fn device_sync(app: &TestApp, device: &DeviceClient) -> Res {
    device
        .send(app, device.token_req(app, Method::GET, "/api/sync/changes"))
        .await
}

/// The open event stream of `device`, past its hello.
async fn device_stream(app: &TestApp, device: &DeviceClient) -> Stream {
    let stream = app
        .open_stream(
            device
                .token_req(app, Method::GET, "/api/sync/events")
                .build(),
        )
        .await;
    said_hello(stream).await
}

/// `stream`, which must have opened, past its hello.
async fn said_hello(mut stream: Stream) -> Stream {
    if stream.status != StatusCode::OK {
        let status = stream.status;
        panic!("{status}: {}", stream.text().await);
    }
    stream.event("hello", SECOND).await;
    stream
}

/// The open event stream of a browser session, past its hello.
async fn browser_stream(app: &TestApp, issued: &Issued) -> Stream {
    said_hello(app.events(&issued.jar).await).await
}

fn error_of(res: &Res) -> String {
    res.json()["error"].as_str().unwrap_or("").to_string()
}

async fn ended(app: &TestApp, sid: SidHash) -> bool {
    app.state
        .vault_db
        .with_conn(move |conn| Ok(lookup(conn, &sid)?))
        .await
        .expect("a read")
        .expect("the session")
        .revoked_at
        .is_some()
}

async fn device_revoked_at(app: &TestApp, device: &DeviceClient) -> Option<i64> {
    let id = device.device_id.expect("signed in");
    app.state
        .vault_db
        .with_conn(move |conn| {
            Ok(conn.query_row(
                "SELECT revoked_at FROM ferret_devices WHERE device_id = ?1",
                [id.as_slice()],
                |r| r.get(0),
            )?)
        })
        .await
        .expect("the device row")
}

async fn is_active(app: &TestApp, user: i64) -> bool {
    app.state
        .vault_db
        .with_conn(move |conn| {
            Ok(
                conn.query_row("SELECT active FROM users WHERE id = ?1", [user], |r| {
                    r.get(0)
                })?,
            )
        })
        .await
        .expect("the user")
}

async fn user_exists(app: &TestApp, user: i64) -> bool {
    app.state
        .vault_db
        .with_conn(move |conn| {
            Ok(
                conn.query_row("SELECT COUNT(*) FROM users WHERE id = ?1", [user], |r| {
                    r.get::<_, i64>(0)
                })? == 1,
            )
        })
        .await
        .expect("a count")
}

/// A pending sign-in code for `user`, made by `admin`.
async fn give_code(app: &TestApp, user: i64, admin: i64) {
    let hash = vole_kit::auth::sign_in_codes::hash(&vole_kit::auth::sign_in_codes::generate());
    app.state
        .vault_db
        .with_conn(move |conn| {
            vole_kit::db::sign_in_codes::insert(conn, user, &hash, admin)?;
            Ok(())
        })
        .await
        .expect("a code");
}

fn heard(rx: &mut tokio::sync::broadcast::Receiver<Revoked>) -> Vec<String> {
    let mut out = Vec::new();
    while let Ok(revoked) = rx.try_recv() {
        out.push(format!("{revoked:?}"));
    }
    out.sort();
    out
}

fn sorted(revoked: &[Revoked]) -> Vec<String> {
    let mut out: Vec<String> = revoked.iter().map(|r| format!("{r:?}")).collect();
    out.sort();
    out
}

/// The time of the account's last `account_disabled`.
async fn disabled_at(app: &TestApp, user: i64) -> i64 {
    app.state
        .vault_db
        .with_conn(move |conn| Ok(actions::disabled_at(conn, user)?))
        .await
        .expect("a read")
        .expect("the account was disabled")
}

/// Disables `user` on the page and records a good backup run that started
/// the second after.
async fn disable_and_back_up(app: &TestApp, user: i64) {
    let res = post(app, &action(user, "disable")).await;
    assert_back(&res);
    let at = disabled_at(app, user).await;
    app.backup_status().record_success(at + 1, 1);
}

/// Drops the re-auth grant of the admin jar.
fn forget_grant(app: &TestApp) {
    let mut jar = app.jar(Which::Admin);
    jar.remove(REAUTH_COOKIE);
    app.set_jar(Which::Admin, jar);
}

#[tokio::test]
async fn disabling_ends_sessions_devices_and_codes_at_once_and_closes_streams() {
    let app = real_time_app().await;
    let (admin, _vault) = admin_user(&app, 1).await;
    let client = client_account(&app, 2).await;
    let user = client.ids.user_id;
    let device = device_of(&app, "client2@example.com", 2).await;
    let browser = issue(&app, user, Origin::Vault, SessionScope::Full, 21).await;
    let admin_side = issue(&app, user, Origin::Admin, SessionScope::Full, 22).await;
    give_code(&app, user, admin.user_id).await;
    // Another account, with a browser and a device of its own.
    let bystander = client_account(&app, 3).await;
    let their_device = device_of(&app, "client3@example.com", 3).await;
    let their_browser = issue(
        &app,
        bystander.ids.user_id,
        Origin::Vault,
        SessionScope::Full,
        31,
    )
    .await;
    give_code(&app, bystander.ids.user_id, admin.user_id).await;

    let mut browser_events = browser_stream(&app, &browser).await;
    let mut device_events = device_stream(&app, &device).await;
    let mut their_events = browser_stream(&app, &their_browser).await;
    let version = session_version(&app, user).await;
    let mut revocations = app.sync_events().subscribe_revocations();

    // A protective action: no confirmation of the master password needed.
    let page = followed(&app, &post(&app, &action(user, "disable")).await).await;
    assert!(page.contains("The account is disabled."), "the message");

    // Every stream of the account closes at once, and only those.
    browser_events.end(SECOND).await;
    device_events.end(SECOND).await;
    their_events.quiet(Duration::from_millis(300)).await;
    assert_eq!(
        heard(&mut revocations),
        sorted(&[
            Revoked::Device(DeviceId(device.device_id.expect("signed in"))),
            Revoked::Session(browser.sid),
            Revoked::Session(admin_side.sid),
        ])
    );
    // The device's next request is refused, its renewal too.
    let res = device_sync(&app, &device).await;
    assert_eq!(res.status, StatusCode::UNAUTHORIZED, "{}", res.text());
    assert_eq!(error_of(&res), "device_revoked");
    assert!(device_revoked_at(&app, &device).await.is_some());
    // Every session of both origins ended, and the code is gone.
    assert!(ended(&app, browser.sid).await);
    assert!(ended(&app, admin_side.sid).await);
    assert_eq!(pending_code(&app, user).await, 0);
    assert!(session_version(&app, user).await > version);
    assert!(!is_active(&app, user).await);
    assert_eq!(
        events_of(&app, user).await,
        vec![(
            "account_disabled".to_string(),
            "admin".to_string(),
            "user1@example.com".to_string()
        )]
    );
    // The page says so.
    assert_eq!(column(row_of(&page, user), "status"), "Disabled");
    // Nothing of the other account changed.
    assert!(!ended(&app, their_browser.sid).await);
    assert_eq!(
        device_sync(&app, &their_device).await.status,
        StatusCode::OK
    );
    assert_eq!(pending_code(&app, bystander.ids.user_id).await, 1);
    assert!(events_of(&app, bystander.ids.user_id).await.is_empty());
    // Disabling it again changes nothing and says why.
    let page = followed(&app, &post(&app, &action(user, "disable")).await).await;
    assert!(page.contains("That account is disabled already."), "again");
    assert_eq!(events_of(&app, user).await.len(), 1);
}

/// The answer to `login/start` for `email`, as a device client sends it.
async fn login_start_raw(app: &TestApp, email: &str) -> Res {
    let (ke1, _state) = ferret_core::opaque_login_start(
        &mut ferret_core::OsRng,
        &support::accounts::opaque_input(CLIENT_PASSWORD),
    )
    .expect("a first message");
    app.call_raw(
        Which::Vault,
        Req::post("/api/auth/opaque/login/start")
            .header("ferret-protocol", "1")
            .header("x-forwarded-proto", "https")
            .json(&json!({"email": email, "ke1": ferret_server::wire::b64url::encode(&ke1)}))
            .build(),
    )
    .await
}

/// The headers of an answer, as name and value, sorted.
fn header_list(res: &Res) -> Vec<(String, String)> {
    let mut list: Vec<(String, String)> = res
        .headers
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_str().unwrap_or("?").to_string()))
        .collect();
    list.sort();
    list
}

#[tokio::test]
async fn a_disabled_account_answers_sign_in_like_an_unknown_one() {
    let app = real_time_app().await;
    admin_user(&app, 1).await;
    let user = client_account(&app, 2).await.ids.user_id;
    assert!(
        login_start(&app, "client2@example.com", CLIENT_PASSWORD)
            .await
            .opened,
        "before, the password opens the record"
    );
    assert_back(&post(&app, &action(user, "disable")).await);

    // The answers of a disabled and an unknown name have the same status,
    // headers, keys and length; the client cannot open either.
    let disabled = login_start_raw(&app, "client2@example.com").await;
    let unknown = login_start_raw(&app, "nobody@example.com").await;
    for res in [&disabled, &unknown] {
        assert_eq!(res.status, StatusCode::OK, "{}", res.text());
        let body = res.json();
        let mut keys: Vec<&str> = body
            .as_object()
            .expect("an object")
            .keys()
            .map(String::as_str)
            .collect();
        keys.sort_unstable();
        assert_eq!(keys, ["ke2", "ksf_profile", "login_id", "sk_hint"]);
    }
    assert_eq!(disabled.body.len(), unknown.body.len());
    assert_eq!(header_list(&disabled), header_list(&unknown));
    assert!(
        !login_start(&app, "client2@example.com", CLIENT_PASSWORD)
            .await
            .opened
    );
    // A whole sign-in ends as for an unknown name.
    let mut device = DeviceClient::new(2);
    let refused = device
        .sign_in(&app, "client2@example.com", CLIENT_PASSWORD)
        .await;
    let mut other = DeviceClient::new(3);
    let nobody = other
        .sign_in(&app, "nobody@example.com", CLIENT_PASSWORD)
        .await;
    assert_eq!(
        refused.status,
        StatusCode::UNAUTHORIZED,
        "{}",
        refused.text()
    );
    assert_eq!(refused.status, nobody.status);
    assert_eq!(refused.json(), nobody.json());
}

#[tokio::test]
async fn enabling_needs_a_fresh_reauth_and_is_logged() {
    let app = real_time_app().await;
    let (_admin, vault) = admin_user(&app, 1).await;
    let user = client_account(&app, 2).await.ids.user_id;
    let device = device_of(&app, "client2@example.com", 2).await;
    assert_back(&post(&app, &action(user, "disable")).await);
    let revoked_at = device_revoked_at(&app, &device).await;
    assert!(revoked_at.is_some());

    // Without a confirmation the page leads to one, and the post is refused.
    let page = get(&app, PATH).await.text();
    let row = row_of(&page, user);
    assert!(
        !row.contains(&format!("action=\"{}\"", action(user, "enable"))),
        "{row}"
    );
    assert!(
        row.contains("href=\"/vault/reauth?next=%2Fsettings%2Faccounts\""),
        "{row}"
    );
    let page = followed(&app, &post(&app, &action(user, "enable")).await).await;
    assert!(page.contains("Confirm it’s you to make this change."));
    assert!(!is_active(&app, user).await);
    assert_eq!(events_of(&app, user).await.len(), 1);

    confirm(&app, &vault).await;
    let page = get(&app, PATH).await.text();
    assert!(row_of(&page, user).contains(&format!("action=\"{}\"", action(user, "enable"))));
    let page = followed(&app, &post(&app, &action(user, "enable")).await).await;
    assert!(
        page.contains("The account is enabled again."),
        "the message"
    );
    assert!(is_active(&app, user).await);
    assert_eq!(column(row_of(&page, user), "status"), "Active");
    let admin = |kind: &str| {
        (
            kind.to_string(),
            "admin".to_string(),
            "user1@example.com".to_string(),
        )
    };
    assert_eq!(
        events_of(&app, user).await,
        vec![admin("account_disabled"), admin("account_enabled")]
    );
    // A device the disable revoked stays revoked, and signs in again.
    assert_eq!(device_revoked_at(&app, &device).await, revoked_at);
    let res = device_sync(&app, &device).await;
    assert_eq!(res.status, StatusCode::UNAUTHORIZED);
    assert_eq!(error_of(&res), "device_revoked");
    let again = device_of(&app, "client2@example.com", 4).await;
    assert_eq!(device_sync(&app, &again).await.status, StatusCode::OK);
    // Enabling gives the administrator no way into the account, so the
    // confirmation is kept; an account that is active is not enabled again.
    assert!(app.jar(Which::Admin).get(REAUTH_COOKIE).is_some());
    let page = followed(&app, &post(&app, &action(user, "enable")).await).await;
    assert!(page.contains("That account is active already."));
    assert_eq!(events_of(&app, user).await.len(), 2);
}

#[tokio::test]
async fn sign_out_everywhere_ends_every_credential_and_is_logged() {
    let app = real_time_app().await;
    let (admin, _vault) = admin_user(&app, 1).await;
    let user = client_account(&app, 2).await.ids.user_id;
    let device = device_of(&app, "client2@example.com", 2).await;
    let browser = issue(&app, user, Origin::Vault, SessionScope::Full, 21).await;
    let admin_side = issue(&app, user, Origin::Admin, SessionScope::Full, 22).await;
    give_code(&app, user, admin.user_id).await;
    let bystander = client_account(&app, 3).await.ids.user_id;
    let their_device = device_of(&app, "client3@example.com", 3).await;
    let mut browser_events = browser_stream(&app, &browser).await;
    let mut device_events = device_stream(&app, &device).await;
    let version = session_version(&app, user).await;
    let mut revocations = app.sync_events().subscribe_revocations();

    // Protective: no confirmation needed.
    let page = followed(&app, &post(&app, &action(user, "sign-out")).await).await;
    assert!(page.contains("The account is signed out everywhere."));

    browser_events.end(SECOND).await;
    device_events.end(SECOND).await;
    assert_eq!(
        heard(&mut revocations),
        sorted(&[
            Revoked::Device(DeviceId(device.device_id.expect("signed in"))),
            Revoked::Session(browser.sid),
            Revoked::Session(admin_side.sid),
        ])
    );
    let res = device_sync(&app, &device).await;
    assert_eq!(res.status, StatusCode::UNAUTHORIZED);
    assert_eq!(error_of(&res), "device_revoked");
    assert!(ended(&app, browser.sid).await);
    assert!(ended(&app, admin_side.sid).await);
    assert_eq!(pending_code(&app, user).await, 0);
    assert!(session_version(&app, user).await > version);
    assert_eq!(
        events_of(&app, user).await,
        vec![(
            "signed_out_everywhere".to_string(),
            "admin".to_string(),
            "user1@example.com".to_string()
        )]
    );
    // The account stays active and signs in again at once.
    assert!(is_active(&app, user).await);
    let again = device_of(&app, "client2@example.com", 4).await;
    assert_eq!(device_sync(&app, &again).await.status, StatusCode::OK);
    // Nothing of the other account changed.
    assert_eq!(
        device_sync(&app, &their_device).await.status,
        StatusCode::OK
    );
    assert!(events_of(&app, bystander).await.is_empty());
}

/// "Delete for good" for `user` with `typed` as the e-mail.
async fn delete_as(app: &TestApp, user: i64, typed: &str) -> Res {
    post_form(app, &action(user, "delete"), &[("email", typed)]).await
}

#[tokio::test]
async fn delete_needs_disable_a_later_good_backup_reauth_and_the_typed_email() {
    let app = real_time_app().await;
    let (admin, vault) = admin_user(&app, 1).await;
    let user = add_account_to_app(&app, 7).await.user_id;
    let email = "user7@example.com";
    let by = admin_actor(admin.user_id);
    let direct = |typed: &'static str, last_good: Option<i64>| {
        let by = by.clone();
        let at = now(&app);
        app.state
            .vault_db
            .with_conn(move |conn| Ok(actions::delete(conn, user, &by, typed, last_good, at)))
    };
    confirm(&app, &vault).await;

    // 1. The account is active.
    app.backup_status().record_success(now(&app) + 60, 1);
    let page = followed(&app, &delete_as(&app, user, email).await).await;
    assert!(page.contains("Disable the account first."), "not disabled");
    assert!(!row_of(&page, user).contains(&action(user, "delete")));
    let result = direct("user7@example.com", Some(i64::MAX))
        .await
        .expect("the db");
    assert!(
        matches!(result, Err(ActionError::NotDisabled)),
        "{result:?}"
    );
    assert!(user_exists(&app, user).await);

    // 2. Disabled, but no good set started after the disable: one started in
    // the same second does not count, nor one before, nor none.
    assert_back(&post(&app, &action(user, "disable")).await);
    let at = disabled_at(&app, user).await;
    app.backup_status().record_success(at, 1);
    let page = followed(&app, &delete_as(&app, user, email).await).await;
    assert!(page.contains("Take a backup first"), "needs a backup");
    let row = row_of(&page, user);
    assert!(
        !row.contains(&format!("action=\"{}\"", action(user, "delete"))),
        "{row}"
    );
    assert!(row.contains("href=\"/settings/backup\""), "{row}");
    for last_good in [None, Some(at - 1), Some(at)] {
        let result = direct("user7@example.com", last_good)
            .await
            .expect("the db");
        assert!(
            matches!(result, Err(ActionError::NeedsBackup)),
            "{last_good:?}: {result:?}"
        );
    }
    assert!(user_exists(&app, user).await);

    // 3. A good set after the disable, but no fresh confirmation.
    app.backup_status().record_success(at + 1, 2);
    forget_grant(&app);
    let page = get(&app, PATH).await.text();
    let row = row_of(&page, user);
    assert!(
        !row.contains(&format!("action=\"{}\"", action(user, "delete"))),
        "{row}"
    );
    assert!(
        row.contains("href=\"/vault/reauth?next=%2Fsettings%2Faccounts\""),
        "{row}"
    );
    let page = followed(&app, &delete_as(&app, user, email).await).await;
    assert!(page.contains("Confirm it’s you to make this change."));
    assert!(user_exists(&app, user).await);

    // 4. Confirmed, but the e-mail is wrong (or missing).
    confirm(&app, &vault).await;
    let page = get(&app, PATH).await.text();
    let row = row_of(&page, user);
    assert!(
        row.contains(&format!("action=\"{}\"", action(user, "delete"))),
        "{row}"
    );
    assert!(row.contains("name=\"email\""), "{row}");
    assert!(
        row.contains("in the backup sets until"),
        "the text about the backups: {row}"
    );
    for typed in ["user8@example.com", "user7@example", ""] {
        let page = followed(&app, &delete_as(&app, user, typed).await).await;
        assert!(
            page.contains("That is not the account’s e-mail."),
            "{typed:?}"
        );
        assert!(user_exists(&app, user).await, "{typed:?}");
    }
    let result = direct("someone@example.com", Some(at + 1))
        .await
        .expect("the db");
    assert!(
        matches!(result, Err(ActionError::EmailMismatch)),
        "{result:?}"
    );
    // A refused deletion keeps the confirmation.
    assert!(app.jar(Which::Admin).get(REAUTH_COOKIE).is_some());
    assert!(user_exists(&app, user).await);

    // 5. Everything in place: deleted, and the confirmation is used up.
    let res = delete_as(&app, user, email).await;
    let removed = set_cookie(&res, REAUTH_COOKIE).expect("the grant is removed");
    assert!(
        removed.starts_with(&format!("{REAUTH_COOKIE}=;")) || removed.contains("Max-Age=0"),
        "{removed}"
    );
    let page = followed(&app, &res).await;
    assert!(
        page.contains("The account and its vault are deleted."),
        "the message"
    );
    assert!(!user_exists(&app, user).await);
    assert!(!page.contains(&format!("id=\"account-{user}\"")));
    assert!(!page.contains("user7@example.com"));
    // Again: not there.
    let res = delete_as(&app, user, email).await;
    assert!(
        res.status == StatusCode::NOT_FOUND || res.status == StatusCode::SEE_OTHER,
        "{}",
        res.status
    );
}

/// Every row of every table of the database, as text, by table.
///
/// The sessions of `admin` are left out: every request of the admin pages
/// moves their `last_seen`.
async fn every_row(
    app: &TestApp,
    admin: i64,
) -> std::collections::BTreeMap<String, Vec<Vec<String>>> {
    app.state
        .vault_db
        .with_conn(move |conn| {
            let tables: Vec<String> = conn
                .prepare("SELECT name FROM sqlite_master WHERE type = 'table' ORDER BY name")?
                .query_map([], |r| r.get(0))?
                .collect::<Result<_, _>>()?;
            let mut out = std::collections::BTreeMap::new();
            for table in tables {
                let filter = if table == "ferret_sessions" {
                    format!("user_id <> {admin}")
                } else {
                    "1".to_string()
                };
                out.insert(table.clone(), rows_where(conn, &table, &filter)?);
            }
            Ok(out)
        })
        .await
        .expect("the rows")
}

/// The rows of `table` that match `filter`, as text, sorted.
fn rows_where(
    conn: &rusqlite::Connection,
    table: &str,
    filter: &str,
) -> rusqlite::Result<Vec<Vec<String>>> {
    rows_of_query(conn, &format!("SELECT * FROM \"{table}\" WHERE {filter}"))
}

/// The rows `query` gives, as text, sorted.
fn rows_of_query(conn: &rusqlite::Connection, query: &str) -> rusqlite::Result<Vec<Vec<String>>> {
    let mut statement = conn.prepare(query)?;
    let columns = statement.column_count();
    let mut rows = statement
        .query_map([], |row| {
            (0..columns)
                .map(|i| {
                    Ok(match row.get_ref(i)? {
                        rusqlite::types::ValueRef::Null => "NULL".to_string(),
                        rusqlite::types::ValueRef::Integer(n) => n.to_string(),
                        rusqlite::types::ValueRef::Real(x) => x.to_string(),
                        rusqlite::types::ValueRef::Text(t) => {
                            format!("'{}'", String::from_utf8_lossy(t))
                        }
                        rusqlite::types::ValueRef::Blob(b) => format!("x{}", hex(b)),
                    })
                })
                .collect()
        })?
        .collect::<Result<Vec<Vec<String>>, _>>()?;
    rows.sort();
    Ok(rows)
}

/// The rows of every table that belong to the kit user `user`: by its id, its
/// account, its vault, its devices or its sessions, by table.
async fn rows_of_user(
    app: &TestApp,
    user: i64,
) -> std::collections::BTreeMap<String, Vec<Vec<String>>> {
    app.state
        .vault_db
        .with_conn(move |conn| {
            let tables: Vec<String> = conn
                .prepare("SELECT name FROM sqlite_master WHERE type = 'table' ORDER BY name")?
                .query_map([], |r| r.get(0))?
                .collect::<Result<_, _>>()?;
            let mut out = std::collections::BTreeMap::new();
            for table in tables {
                let columns: Vec<String> = conn
                    .prepare(&format!("SELECT name FROM pragma_table_info('{table}')"))?
                    .query_map([], |r| r.get(0))?
                    .collect::<Result<_, _>>()?;
                let has = |name: &str| columns.iter().any(|c| c == name);
                let mut ors = Vec::new();
                if table == "users" {
                    ors.push(format!("id = {user}"));
                }
                if has("user_id") {
                    ors.push(format!("user_id = {user}"));
                }
                if has("account_id") {
                    ors.push(format!(
                        "account_id IN (SELECT account_id FROM ferret_accounts WHERE user_id = {user})"
                    ));
                }
                if has("vault_id") {
                    ors.push(format!(
                        "vault_id IN (SELECT v.vault_id FROM ferret_vaults v
                           JOIN ferret_accounts a ON a.account_id = v.account_id
                           WHERE a.user_id = {user})"
                    ));
                }
                if has("device_id") && table != "ferret_sessions" {
                    ors.push(format!(
                        "device_id IN (SELECT device_id FROM ferret_devices WHERE user_id = {user})"
                    ));
                }
                if has("sid_hash") && table != "ferret_sessions" {
                    ors.push(format!(
                        "sid_hash IN (SELECT sid_hash FROM ferret_sessions WHERE user_id = {user})"
                    ));
                }
                if has("token_id") {
                    ors.push(format!(
                        "token_id IN (SELECT id FROM api_tokens WHERE user_id = {user})"
                    ));
                }
                let rows = if ors.is_empty() {
                    Vec::new()
                } else {
                    rows_where(conn, &table, &ors.join(" OR "))?
                };
                out.insert(table, rows);
            }
            Ok(out)
        })
        .await
        .expect("the rows")
}

/// The kit's own tables that hold rows of a user.
const KIT_USER_TABLES: [&str; 7] = [
    "api_tokens",
    "api_token_scopes",
    "passkeys",
    "passkey_challenges",
    "push_devices",
    "push_registrations",
    "user_emails",
];

/// One row for `user` in each of [`KIT_USER_TABLES`] (`n` keeps the unique
/// columns apart): an API token and its scope, a passkey and a pending
/// passkey challenge, a push device on that token and a push registration,
/// the address for codes; and a sealed TOTP secret, recovery codes and a
/// language on the user row itself.
async fn fill_kit_rows(app: &TestApp, user: i64, n: u8) {
    app.state
        .vault_db
        .with_conn(move |conn| {
            let tag = format!("{n:02x}");
            conn.execute(
                "INSERT INTO api_tokens (user_id, name, prefix, token_hash, scope)
                 VALUES (?1, 'cli', ?2, ?3, 'write')",
                rusqlite::params![user, format!("ff_{tag}"), format!("{tag:0>64}")],
            )?;
            let token = conn.last_insert_rowid();
            conn.execute(
                "INSERT INTO api_token_scopes (token_id, scope) VALUES (?1, 'vault:read')",
                [token],
            )?;
            conn.execute(
                "INSERT INTO passkeys (user_id, credential_id, public_key, alg, user_handle, name)
                 VALUES (?1, ?2, ?3, -7, ?4, 'Security key')",
                rusqlite::params![user, vec![n; 16], vec![0xa0 ^ n; 77], vec![0x50 ^ n; 32]],
            )?;
            conn.execute(
                "INSERT INTO passkey_challenges (challenge, purpose, user_id, expires_at)
                 VALUES (?1, 'register', ?2, 4102444800)",
                rusqlite::params![format!("challenge-{tag}"), user],
            )?;
            conn.execute(
                "INSERT INTO push_devices (user_id, token_id, handle_sealed, handle_hash)
                 VALUES (?1, ?2, ?3, ?4)",
                rusqlite::params![user, token, format!("sealed-{tag}"), format!("{tag:f>64}")],
            )?;
            conn.execute(
                "INSERT INTO push_registrations (user_id) VALUES (?1)",
                [user],
            )?;
            conn.execute(
                "INSERT INTO user_emails (user_id, email) VALUES (?1, ?2)",
                rusqlite::params![user, format!("codes-{tag}@example.com")],
            )?;
            conn.execute(
                "UPDATE users SET totp_secret = ?2, recovery_codes = '[\"h1\",\"h2\"]',
                   language = 'nb' WHERE id = ?1",
                rusqlite::params![user, format!("sealed-totp-{tag}")],
            )?;
            Ok(())
        })
        .await
        .expect("the kit's rows");
}

/// An invitation made by `by` and used by `used_by` (still open when
/// `None`); returns its id.
async fn used_invite(app: &TestApp, by: i64, used_by: Option<i64>) -> i64 {
    app.state
        .vault_db
        .with_conn(move |conn| {
            conn.execute(
                "INSERT INTO invites (token_hash, role, created_by, expires_at, used_at, used_by)
                 VALUES (randomblob(32), 'viewer', ?1, datetime('now', '+7 days'),
                         CASE WHEN ?2 IS NULL THEN NULL ELSE datetime('now') END, ?2)",
                rusqlite::params![by, used_by],
            )?;
            Ok(conn.last_insert_rowid())
        })
        .await
        .expect("an invitation")
}

/// Every row of every table as it must be after `gone` is deleted, read
/// before the deletion: every row but those of `gone`, and the invitation
/// `gone` used with `used_by` set to NULL (the kit's `ON DELETE SET NULL`).
async fn expected_after_delete(
    app: &TestApp,
    admin: i64,
    gone: i64,
) -> std::collections::BTreeMap<String, Vec<Vec<String>>> {
    let mut expected = every_row(app, admin).await;
    let of_gone = rows_of_user(app, gone).await;
    for (table, rows) in &mut expected {
        for row in &of_gone[table] {
            let at = rows
                .iter()
                .position(|r| r == row)
                .expect("a row of the account");
            rows.remove(at);
        }
    }
    let invites = app
        .state
        .vault_db
        .with_conn(move |conn| {
            Ok(rows_of_query(
                conn,
                &format!(
                    "SELECT id, token_hash, role, display_name, created_by, created_at,
                            expires_at, used_at,
                            CASE WHEN used_by = {gone} THEN NULL ELSE used_by END, revoked_at
                     FROM invites"
                ),
            )?)
        })
        .await
        .expect("the invitations");
    expected.insert("invites".to_string(), invites);
    expected
}

/// `after` is `expected`, table by table.
fn assert_tables(
    after: &std::collections::BTreeMap<String, Vec<Vec<String>>>,
    expected: &std::collections::BTreeMap<String, Vec<Vec<String>>>,
) {
    assert_eq!(
        after.keys().collect::<Vec<_>>(),
        expected.keys().collect::<Vec<_>>()
    );
    for (table, rows) in expected {
        assert_eq!(&after[table], rows, "{table}");
    }
}

#[tokio::test]
async fn delete_removes_the_vault_and_everything_in_it() {
    let app = real_time_app().await;
    let (admin, vault) = admin_user(&app, 1).await;
    let client = client_account(&app, 2).await;
    let user = client.ids.user_id;
    let _device = device_of(&app, "client2@example.com", 2).await;
    issue(&app, user, Origin::Vault, SessionScope::Full, 21).await;
    give_code(&app, user, admin.user_id).await;
    fill_kit_rows(&app, user, 2).await;
    // The account came in through an invitation of the administrator.
    let invite = used_invite(&app, admin.user_id, Some(user)).await;
    let before = rows_of_user(&app, user).await;
    for table in KIT_USER_TABLES {
        assert_eq!(before[table].len(), 1, "the account has a row in {table}");
    }
    for table in [
        "users",
        "ferret_accounts",
        "ferret_vaults",
        "ferret_unlock_methods",
        "ferret_items",
        "ferret_checkpoints",
        "ferret_sessions",
        "ferret_devices",
        "ferret_refresh",
        "ferret_access",
        "sign_in_codes",
    ] {
        assert!(!before[table].is_empty(), "the account has rows in {table}");
    }

    disable_and_back_up(&app, user).await;
    confirm(&app, &vault).await;
    let expected = expected_after_delete(&app, admin.user_id, user).await;
    let res = post_form(
        &app,
        &action(user, "delete"),
        &[("email", "client2@example.com")],
    )
    .await;
    let page = followed(&app, &res).await;
    assert!(page.contains("The account and its vault are deleted."));

    // Nothing of the account is left in any table (its log, its kit rows and
    // the rows that hang off them neither), and nothing else changed: the
    // invitation it used is kept, with no account named as its user.
    for (table, rows) in rows_of_user(&app, user).await {
        assert!(rows.is_empty(), "{table} keeps {rows:?}");
    }
    assert_tables(&every_row(&app, admin.user_id).await, &expected);
    let used_by: Option<i64> = app
        .state
        .vault_db
        .with_conn(move |conn| {
            Ok(
                conn.query_row("SELECT used_by FROM invites WHERE id = ?1", [invite], |r| {
                    r.get(0)
                })?,
            )
        })
        .await
        .expect("the invitation is kept");
    assert_eq!(used_by, None);
    assert!(events_of(&app, user).await.is_empty());
    // It can no longer sign in, and the name answers like an unknown one.
    assert!(
        !login_start(&app, "client2@example.com", CLIENT_PASSWORD)
            .await
            .opened
    );
}

#[tokio::test]
async fn delete_never_touches_another_account() {
    let app = real_time_app().await;
    let (admin, vault) = admin_user(&app, 1).await;
    let gone = client_account(&app, 2).await.ids.user_id;
    let kept = client_account(&app, 3).await.ids.user_id;
    for (email, key) in [("client2@example.com", 2), ("client3@example.com", 3)] {
        device_of(&app, email, key).await;
    }
    let kept_device = device_of(&app, "client3@example.com", 4).await;
    let kept_browser = issue(&app, kept, Origin::Vault, SessionScope::Full, 31).await;
    give_code(&app, kept, admin.user_id).await;
    // Both accounts have a row in every kit table that holds a user's, both
    // came in through an invitation of the administrator, another invitation
    // is open, and the server has a setting.
    fill_kit_rows(&app, gone, 2).await;
    fill_kit_rows(&app, kept, 3).await;
    used_invite(&app, admin.user_id, Some(gone)).await;
    let kept_invite = used_invite(&app, admin.user_id, Some(kept)).await;
    used_invite(&app, admin.user_id, None).await;
    app.state
        .vault_db
        .with_conn(|conn| {
            conn.execute(
                "INSERT OR REPLACE INTO settings (key, value) VALUES ('test.kept', 'yes')",
                [],
            )?;
            Ok(())
        })
        .await
        .expect("a setting");
    let mut kept_events = browser_stream(&app, &kept_browser).await;
    // Disabled and backed up first: from here on only the deletion changes
    // the database.
    disable_and_back_up(&app, gone).await;
    confirm(&app, &vault).await;
    let expected = expected_after_delete(&app, admin.user_id, gone).await;

    let res = post_form(
        &app,
        &action(gone, "delete"),
        &[("email", "client2@example.com")],
    )
    .await;
    let page = followed(&app, &res).await;
    assert!(page.contains("The account and its vault are deleted."));

    // Every other row is exactly as it was, the other account's kit rows and
    // its invitation too: only the rows of the deleted account went, and the
    // invitation it used names no user any more.
    assert_tables(&every_row(&app, admin.user_id).await, &expected);
    let kept_rows = rows_of_user(&app, kept).await;
    for table in KIT_USER_TABLES {
        assert_eq!(
            kept_rows[table].len(),
            1,
            "the other account keeps its {table}"
        );
    }
    let used_by: Option<i64> = app
        .state
        .vault_db
        .with_conn(move |conn| {
            Ok(conn.query_row(
                "SELECT used_by FROM invites WHERE id = ?1",
                [kept_invite],
                |r| r.get(0),
            )?)
        })
        .await
        .expect("the invitation");
    assert_eq!(used_by, Some(kept));
    // The other account goes on: its device, its browser and its stream.
    assert_eq!(device_sync(&app, &kept_device).await.status, StatusCode::OK);
    assert!(!ended(&app, kept_browser.sid).await);
    kept_events.quiet(Duration::from_millis(300)).await;
    assert_eq!(pending_code(&app, kept).await, 1);
    assert!(row_of(&page, kept).contains("client3@example.com"));
}

/// What an action could change of an account: whether it is active, its
/// `session_version`, its events, its live sessions and devices, and its
/// pending sign-in codes.
#[derive(Debug, PartialEq, Eq)]
struct AccountState {
    active: bool,
    version: i64,
    events: Vec<(String, String, String)>,
    live: usize,
    codes: i64,
}

async fn account_state(app: &TestApp, user: i64) -> AccountState {
    let live = app
        .state
        .vault_db
        .with_conn(move |conn| {
            let live = |table: &str| {
                rows_where(
                    conn,
                    table,
                    &format!("user_id = {user} AND revoked_at IS NULL"),
                )
                .map(|rows| rows.len())
            };
            Ok(live("ferret_sessions")? + live("ferret_devices")?)
        })
        .await
        .expect("a read");
    AccountState {
        active: is_active(app, user).await,
        version: session_version(app, user).await,
        events: events_of(app, user).await,
        live,
        codes: pending_code(app, user).await,
    }
}

#[tokio::test]
async fn every_action_and_its_event_commit_together() {
    let app = real_time_app().await;
    let (admin, _vault) = admin_user(&app, 1).await;
    let user = client_account(&app, 2).await.ids.user_id;
    let device = device_of(&app, "client2@example.com", 2).await;
    issue(&app, user, Origin::Vault, SessionScope::Full, 21).await;
    give_code(&app, user, admin.user_id).await;
    let by = admin_actor(admin.user_id);
    let at = now(&app);

    // The log refuses every new event, on the connection the action runs on.
    let run = |which: &'static str| {
        let by = by.clone();
        app.state.vault_db.with_conn(move |conn| {
            conn.execute_batch(
                "CREATE TEMP TRIGGER no_events BEFORE INSERT ON ferret_account_events
                 BEGIN SELECT RAISE(ABORT, 'the log is full'); END;",
            )?;
            let result = match which {
                "disable" => actions::disable(conn, user, &by, at).map(|_| ()),
                "enable" => actions::enable(conn, user, &by, at),
                _ => actions::sign_out_everywhere(conn, user, &by, at).map(|_| ()),
            };
            conn.execute_batch("DROP TRIGGER temp.no_events")?;
            Ok(result)
        })
    };
    for (which, active) in [("disable", true), ("sign-out", true), ("enable", false)] {
        // The starting point, outside the trigger: active or disabled.
        app.state
            .vault_db
            .with_conn(move |conn| {
                conn.execute(
                    "UPDATE users SET active = ?2 WHERE id = ?1",
                    rusqlite::params![user, active],
                )?;
                Ok(())
            })
            .await
            .expect("the start");
        let before = account_state(&app, user).await;
        let result = run(which).await.expect("the database");
        assert!(
            matches!(result, Err(ActionError::Store(_))),
            "{which}: {result:?}"
        );
        assert_eq!(account_state(&app, user).await, before, "{which}");
    }
    // The device was never revoked and the code is still there.
    assert!(device_revoked_at(&app, &device).await.is_none());
    assert_eq!(pending_code(&app, user).await, 1);
    // Deletion has no event (the log goes with the account); it is refused
    // for an account that is not disabled, and nothing changes.
    let by = admin_actor(admin.user_id);
    let refused = app
        .state
        .vault_db
        .with_conn(move |conn| {
            conn.execute("UPDATE users SET active = 1 WHERE id = ?1", [user])?;
            Ok(actions::delete(
                conn,
                user,
                &by,
                "client2@example.com",
                Some(i64::MAX),
                at,
            ))
        })
        .await
        .expect("the database");
    assert!(
        matches!(refused, Err(ActionError::NotDisabled)),
        "{refused:?}"
    );
    assert!(user_exists(&app, user).await);
}

/// One action of the Users page with the server command as the actor, on
/// `target`, set up so that an administrator would succeed: disabled, with a
/// backup after the disable, for enable and delete.
async fn as_server_command(
    app: &TestApp,
    name: &'static str,
    target: i64,
    email: &'static str,
) -> Result<(), ActionError> {
    let at = now(app);
    app.state
        .vault_db
        .with_conn(move |conn| {
            if name == "enable" || name == "delete" {
                conn.execute("UPDATE users SET active = 0 WHERE id = ?1", [target])?;
                conn.execute(
                    "INSERT INTO ferret_account_events (user_id, at, kind, actor)
                     VALUES (?1, ?2, 'account_disabled', 'server_command')",
                    rusqlite::params![target, at - 10],
                )?;
            }
            let by = Actor::ServerCommand;
            Ok(match name {
                "disable" => actions::disable(conn, target, &by, at).map(|_| ()),
                "enable" => actions::enable(conn, target, &by, at),
                "sign-out" => actions::sign_out_everywhere(conn, target, &by, at).map(|_| ()),
                _ => actions::delete(conn, target, &by, email, Some(at), at),
            })
        })
        .await
        .expect("the database")
}

/// The server command is refused `name`, on an administrator (the last
/// active one besides the page's, and a disabled one) and on a user, and
/// nothing of either changes.
async fn the_server_command_is_refused(name: &'static str) {
    let app = TestApp::new_at_real_time().await;
    let (admin, _vault) = admin_user(&app, 1).await;
    let other_admin = seed(&app, 2).await.user_id;
    set_role(&app, other_admin, "admin").await;
    let user = add_account_to_app(&app, 7).await.user_id;
    for (target, email) in [
        (admin.user_id, "user1@example.com"),
        (other_admin, "user2@example.com"),
        (user, "user7@example.com"),
    ] {
        let version = session_version(&app, target).await;
        let active = is_active(&app, target).await;
        let events = events_of(&app, target).await;
        let result = as_server_command(&app, name, target, email).await;
        assert!(
            matches!(result, Err(ActionError::NotAllowed)),
            "{name} {target}: {result:?}"
        );
        assert!(user_exists(&app, target).await, "{name} {target}");
        assert_eq!(
            session_version(&app, target).await,
            version,
            "{name} {target}"
        );
        if name == "disable" || name == "sign-out" {
            assert_eq!(is_active(&app, target).await, active, "{name} {target}");
            assert_eq!(events_of(&app, target).await, events, "{name} {target}");
        } else {
            assert!(
                !is_active(&app, target).await,
                "{name} {target}: still disabled"
            );
            assert_eq!(events_of(&app, target).await.len(), events.len() + 1);
        }
    }
}

#[tokio::test]
async fn the_server_command_cannot_disable_an_account() {
    the_server_command_is_refused("disable").await;
}

#[tokio::test]
async fn the_server_command_cannot_enable_an_account() {
    the_server_command_is_refused("enable").await;
}

#[tokio::test]
async fn the_server_command_cannot_sign_an_account_out_everywhere() {
    the_server_command_is_refused("sign-out").await;
}

#[tokio::test]
async fn the_server_command_cannot_delete_an_account() {
    the_server_command_is_refused("delete").await;
}

#[tokio::test]
async fn the_prelogin_policy_follows_a_disabled_enabled_or_deleted_account_at_once() {
    let app = real_time_app().await;
    // Two accounts: the administrator's without a secret key, the user's with
    // one, so half of the accounts have one.
    let (_admin, vault) = admin_user(&app, 1).await;
    let user = add_account_to_app(&app, 7).await.user_id;
    login::refresh_once(&app.state.vault_db, &app.state.prelogin, app.clock.as_ref()).await;
    let policy = |app: &TestApp| app.state.prelogin.read().expect("the policy").clone();
    let half = PreloginPolicy::new(&[(1, 1000)], 500).expect("a policy");
    let none = PreloginPolicy::new(&[(1, 1000)], 0).expect("a policy");
    assert_eq!(policy(&app), half);

    // No background round runs here: each answer renewed the policy.
    assert_back(&post(&app, &action(user, "disable")).await);
    assert_eq!(policy(&app), none, "after the disable");
    confirm(&app, &vault).await;
    assert_back(&post(&app, &action(user, "enable")).await);
    assert_eq!(policy(&app), half, "after the enable");

    // A deletion renews it too: the account is disabled first, so its share
    // is gone already; a policy left stale is put right by the deletion.
    disable_and_back_up(&app, user).await;
    assert_eq!(policy(&app), none);
    *app.state.prelogin.write().expect("the policy") = half.clone();
    confirm(&app, &vault).await;
    let res = post_form(
        &app,
        &action(user, "delete"),
        &[("email", "user7@example.com")],
    )
    .await;
    assert_back(&res);
    assert!(!user_exists(&app, user).await);
    assert_eq!(policy(&app), none, "after the deletion");
}

// ------------------------------------------------------------- the words

/// The keys of a catalog, `section.key`.
fn keys(catalog: &str) -> Vec<String> {
    let mut section = String::new();
    let mut out = Vec::new();
    for line in catalog.lines().map(str::trim) {
        if let Some(name) = line.strip_prefix('[').and_then(|l| l.strip_suffix(']')) {
            section = name.to_string();
        } else if let Some((key, _)) = line.split_once(" = ")
            && !line.starts_with('#')
        {
            out.push(format!("{section}.{key}"));
        }
    }
    out.sort();
    out
}

#[tokio::test]
async fn the_page_has_its_words_in_every_language_of_the_admin_pages() {
    let en = keys(include_str!("../locales/en.toml"));
    let nb = keys(include_str!("../locales/nb.toml"));
    assert_eq!(en, nb, "the two catalogs have the same keys");
    assert!(en.iter().filter(|k| k.starts_with("accounts.")).count() > 30);

    let app = TestApp::new_at_real_time().await;
    admin_user(&app, 1).await;
    let page = get_in(&app, PATH, "nb").await.text();
    for word in [
        "Brukere",
        "Kontoer",
        "Åpne invitasjoner",
        "Enheter",
        "Plass",
    ] {
        assert!(page.contains(word), "nb: {word}");
    }
    for english in ["Open invitations", "Devices", "Invite someone"] {
        assert!(!page.contains(english), "nb has {english}");
    }
}
