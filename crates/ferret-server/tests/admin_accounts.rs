//! The Users page of the admin pages (`/settings/accounts`): the list of
//! accounts with Ferret's columns, the invitations, the one-time sign-in code,
//! the kit's closed user pages and who may reach any of it.
//! Spec: Fase 1 § 11 ("Several accounts", "The Users page"), § 6.3, § 4.2.

mod support;

use axum::http::StatusCode;
use base64::Engine as _;
use base64::engine::general_purpose::{STANDARD, STANDARD_NO_PAD, URL_SAFE_NO_PAD};
use ferret_server::accounts::actions::{self, ActionError};
use ferret_server::accounts::log::Actor;
use ferret_server::auth::session::Origin;
use ferret_server_auth::SessionScope;
use serde_json::json;
use support::accounts::{add_account_to_app, insert_user};
use support::handoff::{
    admin_user, begin, code_of, hand_over, mint, now, redeem, set_cookie, set_role, vault_session,
};
use support::session::{Issued, issue, seed, session_version};
use support::{ADMIN_URL, Req, Res, TestApp, VAULT_URL, Which};
use vole_kit::db::role::Role;

const PATH: &str = "/settings/accounts";
const INVITES: &str = "/settings/accounts/invites";
const SID_COOKIE: &str = "__Host-ferret_sid";

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
    let res = post(&app, INVITES).await;
    assert_eq!(res.status, StatusCode::OK, "{}", res.text());
    assert_eq!(res.header("cache-control"), "no-store");
    let page = res.text();
    let tokens = invite_tokens(&page);
    assert_eq!(tokens.len(), 1, "one link on the page");
    let token = &tokens[0];
    assert_eq!(token.len(), 43);
    assert!(page.contains(&format!("{VAULT_URL}/vault/setup#invite={token}")));
    // Never in a cookie (the message is a flash cookie) or a header.
    for (name, value) in &res.headers {
        let value = value.to_str().unwrap_or_default();
        assert!(!value.contains(token.as_str()), "{name}: {value}");
    }
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
    let first = invite_tokens(&post(&app, INVITES).await.text()).remove(0);
    let id: i64 = count(&app, "SELECT MAX(id) FROM invites").await;
    let res = post(&app, &format!("{INVITES}/{id}/resend")).await;
    assert_eq!(res.status, StatusCode::OK, "{}", res.text());
    assert_eq!(res.header("cache-control"), "no-store");
    let tokens = invite_tokens(&res.text());
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
    assert_eq!(res.status, StatusCode::OK, "the 50th: {}", res.text());
    assert_eq!(pending_invites(&app).await, 50);
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
    assert_eq!(res.status, StatusCode::OK, "{}", res.text());
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
    // The page offers no action on those rows either.
    let page = get(&app, PATH).await.text();
    for target in [admin, other_admin] {
        assert!(!row_of(&page, target).contains("sign-in-code"), "{target}");
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
        ] {
            let res = post(&app, &path).await;
            assert_eq!(res.status, StatusCode::FORBIDDEN, "{role} {path}");
        }
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
    let res = post(&app, INVITES).await;
    assert_eq!(res.status, StatusCode::OK, "{}", res.text());
    assert_eq!(pending_invites(&app).await, 2);
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
