//! `ferret sign-in-code issue --email <e> --yes`: a one-time sign-in code made
//! on the server while it runs, printed once, and good for one recovery
//! session. Spec: Fase 1 § 6.3 step 1.

mod support;

use std::ffi::OsString;

use axum::http::StatusCode;
use ferret_server::backup::RESTORE_MARKER;
use ferret_server::cli::{self, Command};
use ferret_server::http::proxy_guard::ProxyList;
use serde_json::json;
use support::handoff::set_role;
use support::session::{seed, session_version};
use support::{PEER, Req, TestApp, Which};

fn proxies() -> ProxyList {
    ProxyList::parse(&[PEER.split(':').next().expect("an address").to_string()])
        .expect("a proxy list")
}

async fn app() -> TestApp {
    TestApp::builder().proxies(proxies()).build().await
}

/// The codes in `text`: eight groups of four characters of the kit's alphabet,
/// joined by dashes.
fn codes_in(text: &str) -> Vec<String> {
    const ALPHABET: &str = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";
    let mut found = Vec::new();
    for word in text.split(|c: char| c.is_whitespace() || c == ':' || c == ',') {
        let groups: Vec<&str> = word.split('-').collect();
        if groups.len() == 8
            && groups
                .iter()
                .all(|g| g.len() == 4 && g.chars().all(|c| ALPHABET.contains(c)))
        {
            found.push(word.to_string());
        }
    }
    found
}

/// The codes of `user`: `(created_by, used, revoked, hours of life)`.
async fn code_rows(app: &TestApp, user: i64) -> Vec<(Option<i64>, bool, bool, f64)> {
    app.state
        .vault_db
        .with_conn(move |conn| {
            let mut stmt = conn.prepare(
                "SELECT created_by, used_at IS NOT NULL, revoked_at IS NOT NULL,
                        (julianday(expires_at) - julianday(created_at)) * 24
                 FROM sign_in_codes WHERE user_id = ?1 ORDER BY id",
            )?;
            let rows = stmt
                .query_map([user], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)))?
                .collect::<Result<Vec<_>, _>>()?;
            Ok(rows)
        })
        .await
        .expect("the codes")
}

fn issue(app: &TestApp, email: &str, confirmed: bool) -> Result<String, String> {
    cli::run(Command::SignInCodeIssue {
        data_dir: app.dir.clone(),
        email: email.to_string(),
        confirmed,
    })
    .map_err(|e| e.to_string())
}

async fn redeem(app: &TestApp, email: &str, code: &str) -> StatusCode {
    app.call_raw(
        Which::Vault,
        Req::post("/api/auth/redeem")
            .page_fetch(Which::Vault)
            .header("x-forwarded-proto", "https")
            .json(&json!({ "email": email, "code": code }))
            .build(),
    )
    .await
    .status
}

#[tokio::test]
async fn cli_issues_a_code_while_the_server_runs_and_prints_it_once() {
    let app = app().await;
    let admin = seed(&app, 1).await;
    set_role(&app, admin.user_id, "admin").await;
    let user = seed(&app, 2).await;
    let version = session_version(&app, user.user_id).await;

    // The server's pool is open on the same database the whole time; the
    // e-mail address may be typed in any case.
    let out = issue(&app, "User2@Example.com", true).expect("a code");
    let codes = codes_in(&out);
    assert_eq!(codes.len(), 1, "the code is printed once: {out}");
    let code = codes[0].clone();
    assert_eq!(out.matches(code.as_str()).count(), 1, "{out}");
    assert!(out.contains("UTC"), "{out}");

    // Stored by its hash only, made by the administrator, for the kit's 24
    // hours; nobody was signed out by making it.
    let rows = code_rows(&app, user.user_id).await;
    assert_eq!(rows.len(), 1);
    let (created_by, used, revoked, hours) = rows[0];
    assert_eq!(
        (created_by, used, revoked),
        (Some(admin.user_id), false, false)
    );
    assert!((hours - 24.0).abs() < 0.01, "{hours}");
    let stored: Vec<u8> = app
        .state
        .vault_db
        .with_conn(|conn| {
            Ok(conn.query_row("SELECT code_hash FROM sign_in_codes", [], |r| r.get(0))?)
        })
        .await
        .expect("the hash");
    assert_eq!(stored, vole_kit::auth::sign_in_codes::hash(&code).to_vec());
    assert_eq!(session_version(&app, user.user_id).await, version);

    // A second code replaces the first.
    let second = codes_in(&issue(&app, "user2@example.com", true).expect("a code"))[0].clone();
    assert_ne!(second, code);
    assert_eq!(
        redeem(&app, "user2@example.com", &code).await,
        StatusCode::UNAUTHORIZED
    );
    // The new one opens a recovery session, once.
    assert_eq!(
        redeem(&app, "user2@example.com", &second).await,
        StatusCode::OK
    );
    assert_eq!(
        redeem(&app, "user2@example.com", &second).await,
        StatusCode::UNAUTHORIZED
    );
}

#[tokio::test]
async fn cli_refuses_without_yes() {
    let app = app().await;
    let admin = seed(&app, 1).await;
    set_role(&app, admin.user_id, "admin").await;
    let user = seed(&app, 2).await;

    let error = issue(&app, "user2@example.com", false).expect_err("no --yes");
    assert!(error.contains("--yes"), "{error}");
    assert!(codes_in(&error).is_empty());
    assert!(code_rows(&app, user.user_id).await.is_empty());

    // The parser takes --yes as the confirmation, and nothing else.
    let parse = |args: &[&str]| cli::parse(args.iter().map(OsString::from)).expect("a command");
    let parsed = parse(&[
        "ferret",
        "sign-in-code",
        "issue",
        "--email",
        "user2@example.com",
        "--data-dir",
        "/data",
    ])
    .expect("parses");
    assert!(matches!(
        parsed,
        Command::SignInCodeIssue {
            confirmed: false,
            ..
        }
    ));
    let parsed = parse(&[
        "ferret",
        "sign-in-code",
        "issue",
        "--email",
        "user2@example.com",
        "--yes",
    ])
    .expect("parses");
    assert!(matches!(
        parsed,
        Command::SignInCodeIssue {
            confirmed: true,
            ..
        }
    ));
}

#[tokio::test]
async fn cli_refuses_a_code_that_could_never_open_a_session() {
    let app = app().await;
    let admin = seed(&app, 1).await;
    let user = seed(&app, 2).await;

    // No administrator yet.
    let error = issue(&app, "user2@example.com", true).expect_err("no admin");
    assert!(error.contains("administrator"), "{error}");
    set_role(&app, admin.user_id, "admin").await;

    for (email, why) in [
        ("nobody@example.com", "no user"),
        ("a\u{0}b", "not a login name"),
    ] {
        let error = issue(&app, email, true).expect_err(why);
        assert!(codes_in(&error).is_empty(), "{why}: {error}");
    }
    // A kit user without a vault, a disabled user, a user with the kit's
    // second factor on.
    let bare = app
        .state
        .vault_db
        .with_conn(|conn| {
            conn.execute(
                "INSERT INTO users (username, password_hash, role) VALUES ('bare@example.com', 'x', 'editor')",
                [],
            )?;
            Ok(conn.last_insert_rowid())
        })
        .await
        .expect("a bare user");
    let error = issue(&app, "bare@example.com", true).expect_err("no vault");
    assert!(error.contains("vault"), "{error}");
    for (statement, why) in [
        ("UPDATE users SET active = 0 WHERE id = ?1", "disabled"),
        (
            "UPDATE users SET active = 1, totp_enabled = 1 WHERE id = ?1",
            "two-factor",
        ),
    ] {
        let id = user.user_id;
        app.state
            .vault_db
            .with_conn(move |conn| {
                conn.execute(statement, [id])?;
                Ok(())
            })
            .await
            .expect("the change");
        let error = issue(&app, "user2@example.com", true).expect_err(why);
        assert!(error.contains(why), "{why}: {error}");
    }
    assert!(code_rows(&app, user.user_id).await.is_empty());
    assert!(code_rows(&app, bare).await.is_empty());

    // Nothing while a restore is in progress.
    std::fs::write(app.dir.join(RESTORE_MARKER), b"{}").expect("the marker");
    let error = issue(&app, "user1@example.com", true).expect_err("restore");
    assert!(!error.is_empty());
    assert!(code_rows(&app, admin.user_id).await.is_empty());
}
