//! The hand-over as a browser does it, for tests: `begin` on the admin origin,
//! a signed-in vault session, `mint` on the vault origin, `redeem` on the admin
//! origin. Each step goes through the real routers and the jar of the listener
//! it is sent to.

use axum::http::header;
use axum::response::IntoResponse as _;
use axum_extra::extract::cookie::SignedCookieJar;
use ferret_server::auth::session::Origin;
use ferret_server_auth::{Clock as _, SessionScope};
use serde_json::json;
use vole_kit::auth::reauth;

use super::session::{Issued, Seeded, issue, seed};
use super::{Jar, Req, Res, TestApp, Which};

/// What `begin` answered with.
pub struct Begun {
    pub res: Res,
    /// The challenge in the `Location` header.
    pub challenge: String,
}

/// `GET {admin}/auth/handoff/begin?{query}`, with the jar of the admin listener.
pub async fn begin(app: &TestApp, query: &str) -> Begun {
    let res = app
        .call(
            Which::Admin,
            Req::get(&format!("/auth/handoff/begin?{query}")).build(),
        )
        .await;
    let challenge = res
        .headers
        .get(header::LOCATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|loc| url::Url::parse(loc).ok())
        .and_then(|url| {
            url.query_pairs()
                .find(|(k, _)| k == "challenge")
                .map(|(_, v)| v.into_owned())
        })
        .unwrap_or_default();
    Begun { res, challenge }
}

/// `POST {vault}/api/auth/handoff`, as the vault page does it.
pub async fn mint(app: &TestApp, purpose: &str, next: &str, challenge: &str) -> Res {
    app.call(
        Which::Vault,
        Req::post("/api/auth/handoff")
            .page_fetch(Which::Vault)
            .json(&json!({ "purpose": purpose, "next": next, "challenge": challenge }))
            .build(),
    )
    .await
}

/// `POST {admin}/api/auth/handoff/redeem`, as the admin page does it.
pub async fn redeem(app: &TestApp, code: &str) -> Res {
    app.call(
        Which::Admin,
        Req::post("/api/auth/handoff/redeem")
            .page_fetch(Which::Admin)
            .json(&json!({ "code": code }))
            .build(),
    )
    .await
}

/// The code of a successful mint.
pub fn code_of(res: &Res) -> String {
    assert_eq!(res.status, 200, "mint: {}", res.text());
    res.json()["code"].as_str().expect("a code").to_string()
}

/// Signs `user_id` in on the vault origin: a session row and the vault jar.
pub async fn vault_session(app: &TestApp, user_id: i64, device_n: u8) -> Issued {
    let issued = issue(app, user_id, Origin::Vault, SessionScope::Full, device_n).await;
    app.set_jar(Which::Vault, issued.jar.clone());
    issued
}

/// The whole hand-over for the vault session in the vault jar: begin, mint,
/// redeem. Returns the answer of the redeem.
pub async fn hand_over(app: &TestApp, next: &str, purpose: &str) -> Res {
    let query = url::form_urlencoded::Serializer::new(String::new())
        .append_pair("next", next)
        .append_pair("purpose", purpose)
        .finish();
    let begun = begin(app, &query).await;
    assert_eq!(begun.res.status, 302, "begin: {}", begun.res.text());
    let code = code_of(&mint(app, purpose, next, &begun.challenge).await);
    redeem(app, &code).await
}

/// A kit user who is an administrator, with an account, signed in on the vault
/// origin and handed over to the admin origin. The jars of the two listeners
/// hold the sessions.
pub async fn admin_user(app: &TestApp, n: u8) -> (Seeded, Issued) {
    let user = seed(app, n).await;
    set_role(app, user.user_id, "admin").await;
    let vault = vault_session(app, user.user_id, n).await;
    let res = hand_over(app, "/settings", "login").await;
    assert_eq!(res.status, 200, "redeem: {}", res.text());
    (user, vault)
}

/// Sets the kit role of a user.
pub async fn set_role(app: &TestApp, user_id: i64, role: &'static str) {
    app.state
        .vault_db
        .with_conn(move |conn| {
            conn.execute(
                "UPDATE users SET role = ?2 WHERE id = ?1",
                rusqlite::params![user_id, role],
            )?;
            Ok(())
        })
        .await
        .expect("set the role");
}

/// Gives the vault jar a re-auth grant for the vault session `issued`, made
/// `age_secs` seconds ago by the kit's own clock.
pub fn grant_reauth(app: &TestApp, issued: &Issued, age_secs: i64) {
    let key = app.state.core.session_key.clone();
    let granted_at = vole_kit::auth::session::now_unix() - age_secs;
    let jar = reauth::grant_at(
        SignedCookieJar::new(key.clone()),
        &key,
        &issued.claims,
        granted_at,
        true,
    );
    let mut vault = app.jar(Which::Vault);
    vault.absorb(jar.into_response().headers());
    app.set_jar(Which::Vault, vault);
}

/// Everything a query returns, as JSON arrays of text (blobs in hex), for
/// tests that look for a value anywhere in a table.
pub async fn dump(app: &TestApp, table: &'static str) -> Vec<Vec<String>> {
    app.state
        .vault_db
        .with_conn(move |conn| {
            let mut statement = conn.prepare(&format!("SELECT * FROM {table}"))?;
            let columns = statement.column_count();
            let rows = statement
                .query_map([], |row| {
                    (0..columns)
                        .map(|i| {
                            Ok(match row.get_ref(i)? {
                                rusqlite::types::ValueRef::Null => String::new(),
                                rusqlite::types::ValueRef::Integer(n) => n.to_string(),
                                rusqlite::types::ValueRef::Real(x) => x.to_string(),
                                rusqlite::types::ValueRef::Text(t) => {
                                    String::from_utf8_lossy(t).into_owned()
                                }
                                rusqlite::types::ValueRef::Blob(b) => super::session::hex(b),
                            })
                        })
                        .collect()
                })?
                .collect::<Result<Vec<Vec<String>>, _>>()?;
            Ok(rows)
        })
        .await
        .expect("dump a table")
}

/// The clock of the app as a number.
pub fn now(app: &TestApp) -> i64 {
    i64::try_from(app.clock.now_unix()).expect("a time")
}

/// The first `Set-Cookie` of a response that sets `name`.
pub fn set_cookie(res: &Res, name: &str) -> Option<String> {
    res.set_cookies()
        .into_iter()
        .find(|c| c.starts_with(&format!("{name}=")))
}

/// A jar with only the cookies of `names` from `jar`.
pub fn only(jar: &Jar, names: &[&str]) -> Jar {
    let mut out = Jar::default();
    for name in names {
        if let Some(value) = jar.get(name) {
            out.set(name, value);
        }
    }
    out
}
