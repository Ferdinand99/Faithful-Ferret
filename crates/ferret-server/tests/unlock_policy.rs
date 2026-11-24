//! The server's rule for quick unlock: `GET /api/vault/policy` (who may read it
//! and what it says), the stored rule's defaults and, with the cargo feature
//! `quick-unlock`, the Unlock page of the admin pages (who may open and change
//! it, what it refuses, what it says in words and what it announces before a
//! stricter rule is saved). Spec: Fase 1 § 11.

mod support;

use axum::http::{Method, StatusCode};
use ferret_server::vault::policy::{self, UnlockPolicy};
use ferret_server_auth::SessionScope;
use serde_json::{Value, json};
use support::accounts::{CLIENT_PASSWORD, Client, client_account, client_session};
use support::device::{DeviceClient, device_app};
use support::session::Issued;
use support::{Req, Res, TestApp, Which};

const PATH: &str = "/api/vault/policy";

/// An app that believes the test peer as a proxy (so `https` counts) and whose
/// clock is the machine's, for the kit's pages.
async fn real_time_app() -> TestApp {
    let now = u64::try_from(vole_kit::auth::session::now_unix()).expect("a time");
    support::device::device_app_builder()
        .start(now)
        .build()
        .await
}

// ------------------------------------------------------------------ helpers

fn email(n: u8) -> String {
    format!("client{n}@example.com")
}

/// A request of the web vault with the cookies of `jar`.
fn cookie_req(jar: &Issued, method: Method, path: &str) -> Req {
    Req::new(method, path)
        .page_fetch(Which::Vault)
        .header("x-forwarded-proto", "https")
        .header("cookie", &jar.jar.header().expect("a cookie"))
}

async fn get_by_session(app: &TestApp, session: &Issued) -> Res {
    app.call_raw(Which::Vault, cookie_req(session, Method::GET, PATH).build())
        .await
}

async fn signed_in(app: &TestApp, n: u8, key: u8) -> (Client, DeviceClient) {
    let client = client_account(app, n).await;
    let mut device = DeviceClient::new(key);
    let res = device.sign_in(app, &email(n), CLIENT_PASSWORD).await;
    assert_eq!(res.status, StatusCode::OK, "{}", res.text());
    (client, device)
}

async fn stored(app: &TestApp) -> UnlockPolicy {
    app.state
        .vault_db
        .with_conn(|conn| policy::read(conn))
        .await
        .expect("the stored rule")
}

async fn store(app: &TestApp, rule: UnlockPolicy) {
    app.state
        .vault_db
        .with_conn(move |conn| policy::write(conn, &rule, 1))
        .await
        .expect("store the rule");
}

/// What a build says when the stored rule is `rule`.
fn expected(rule: &UnlockPolicy) -> Value {
    let built = cfg!(feature = "quick-unlock");
    json!({
        "pin": {
            "allowed": built && rule.pin_allowed,
            "after_restart": rule.pin_after_restart,
            "min_length": rule.pin_min_length,
        },
        "prf": { "enabled": built && policy::PRF_ROUTES_MOUNTED },
    })
}

// ------------------------------------------------------------------ the route

#[tokio::test]
async fn the_policy_defaults_to_allowed_after_restart_and_six() {
    let app = device_app().await;
    // A server that was never set up: the seeded row is the default rule.
    assert_eq!(
        stored(&app).await,
        UnlockPolicy {
            pin_allowed: true,
            pin_after_restart: true,
            pin_min_length: 6,
        }
    );
    let client = client_account(&app, 1).await;
    let session = client_session(&app, &client, SessionScope::Full, 1).await;
    let res = get_by_session(&app, &session).await;
    assert_eq!(res.status, StatusCode::OK, "{}", res.text());
    assert_eq!(res.json(), expected(&UnlockPolicy::default()));
    assert_eq!(res.json()["pin"]["after_restart"], json!(true));
    assert_eq!(res.json()["pin"]["min_length"], json!(6));

    // A database whose row is gone (edited by hand) answers with the defaults,
    // not with an error.
    app.state
        .vault_db
        .with_conn(|conn| {
            conn.execute("DELETE FROM ferret_unlock_policy", [])?;
            Ok(())
        })
        .await
        .expect("delete the row");
    assert_eq!(stored(&app).await, UnlockPolicy::default());
    let res = get_by_session(&app, &session).await;
    assert_eq!(res.json(), expected(&UnlockPolicy::default()));
}

#[tokio::test]
async fn the_policy_route_answers_a_session_and_a_device_token_and_nothing_else() {
    let app = device_app().await;
    let (client, device) = signed_in(&app, 1, 1).await;
    store(
        &app,
        UnlockPolicy {
            pin_allowed: true,
            pin_after_restart: false,
            pin_min_length: 9,
        },
    )
    .await;
    let rule = stored(&app).await;

    // A full session and a device token with the proof of its key get the same
    // answer.
    let session = client_session(&app, &client, SessionScope::Full, 1).await;
    let by_cookie = get_by_session(&app, &session).await;
    assert_eq!(by_cookie.status, StatusCode::OK, "{}", by_cookie.text());
    assert_eq!(by_cookie.json(), expected(&rule));
    let by_token = device
        .send(&app, device.token_req(&app, Method::GET, PATH))
        .await;
    assert_eq!(by_token.status, StatusCode::OK, "{}", by_token.text());
    assert_eq!(by_token.json(), by_cookie.json());

    // Nobody else: no credential at all, a session that is not a full one, the
    // `Basic` of a proxy, and a token without its proof.
    let nobody = app
        .call_raw(
            Which::Vault,
            Req::get(PATH)
                .header("ferret-protocol", "1")
                .header("x-forwarded-proto", "https")
                .build(),
        )
        .await;
    assert_eq!(nobody.status, StatusCode::UNAUTHORIZED);
    for scope in [
        SessionScope::Pending2fa,
        SessionScope::AccountReset,
        SessionScope::Unverified,
    ] {
        let other = client_session(&app, &client, scope, 2).await;
        let res = get_by_session(&app, &other).await;
        assert!(res.status.is_client_error(), "{scope:?}: {}", res.status);
        assert_ne!(res.status, StatusCode::OK, "{scope:?}");
        assert!(!res.text().contains("min_length"), "{scope:?}");
    }
    let basic = app
        .call_raw(
            Which::Vault,
            Req::get(PATH)
                .header("authorization", "Basic dXNlcjpwYXNzd29yZA==")
                .header("ferret-protocol", "1")
                .header("x-forwarded-proto", "https")
                .build(),
        )
        .await;
    assert_eq!(basic.status, StatusCode::UNAUTHORIZED);
    let token = device.access.as_ref().expect("signed in").to_wire();
    let no_proof = app
        .call_raw(
            Which::Vault,
            Req::get(PATH)
                .header("authorization", &format!("DPoP {token}"))
                .header("ferret-protocol", "1")
                .header("x-forwarded-proto", "https")
                .build(),
        )
        .await;
    assert_eq!(no_proof.status, StatusCode::UNAUTHORIZED);
    for res in [&nobody, &basic, &no_proof] {
        assert!(!res.text().contains("min_length"));
    }

    // The route only reads: no other method is served.
    for method in [Method::POST, Method::PUT, Method::PATCH, Method::DELETE] {
        let res = app
            .call_raw(
                Which::Vault,
                cookie_req(&session, method.clone(), PATH)
                    .json(&json!({ "pin": { "allowed": false } }))
                    .build(),
            )
            .await;
        assert_eq!(res.status, StatusCode::METHOD_NOT_ALLOWED, "{method}");
    }
    assert_eq!(stored(&app).await, rule, "nothing was changed");

    // A revoked device is refused like on every other route of a token.
    let device_id = device.device_id.expect("signed in");
    app.state
        .vault_db
        .with_conn(move |conn| {
            conn.execute(
                "UPDATE ferret_devices SET revoked_at = 1 WHERE device_id = ?1",
                [device_id.as_slice()],
            )?;
            Ok(())
        })
        .await
        .expect("a revocation");
    let revoked = device
        .send(&app, device.token_req(&app, Method::GET, PATH))
        .await;
    assert_eq!(revoked.status, StatusCode::UNAUTHORIZED);
    assert!(!revoked.text().contains("min_length"));
}

#[tokio::test]
async fn the_policy_route_has_no_store_and_no_account_in_the_path() {
    let app = device_app().await;
    let first = client_account(&app, 1).await;
    let second = client_account(&app, 2).await;
    let one = client_session(&app, &first, SessionScope::Full, 1).await;
    let two = client_session(&app, &second, SessionScope::Full, 2).await;
    let res_one = get_by_session(&app, &one).await;
    let res_two = get_by_session(&app, &two).await;
    for res in [&res_one, &res_two] {
        assert_eq!(res.status, StatusCode::OK, "{}", res.text());
        assert_eq!(res.header("cache-control"), "no-store");
        assert!(
            res.header("content-type").starts_with("application/json"),
            "{}",
            res.header("content-type")
        );
    }
    // The rule is the server's, not an account's: both accounts get the same
    // bytes, and the answer holds nothing but the four values and the switch.
    assert_eq!(res_one.body, res_two.body);
    let body = res_one.json();
    let pin = body["pin"].as_object().expect("the PIN rule");
    let mut keys: Vec<&str> = pin.keys().map(String::as_str).collect();
    keys.sort_unstable();
    assert_eq!(keys, ["after_restart", "allowed", "min_length"]);
    let prf = body["prf"].as_object().expect("the passkey switch");
    assert_eq!(prf.keys().collect::<Vec<_>>(), ["enabled"]);
    let mut top: Vec<&str> = body
        .as_object()
        .expect("an object")
        .keys()
        .map(String::as_str)
        .collect();
    top.sort_unstable();
    assert_eq!(top, ["pin", "prf"]);
    // No identifier of the caller is in the answer or in its headers.
    let hex = |bytes: &[u8]| -> String { bytes.iter().map(|b| format!("{b:02x}")).collect() };
    let seen = format!("{}\n{:?}", res_one.text(), res_one.headers);
    for secret in [
        hex(first.ids.account_id.as_bytes()),
        hex(first.ids.vault_id.as_bytes()),
        first.ids.user_id.to_string(),
        email(1),
    ] {
        assert!(!seen.contains(&secret), "the answer holds {secret}");
    }

    // The path has no place for an account, and no other path serves the rule.
    let account = hex(first.ids.account_id.as_bytes());
    for path in [
        format!("{PATH}/{account}"),
        format!("/api/vault/{account}/policy"),
        "/api/vault/policy/".to_string(),
        "/api/vault/policies".to_string(),
        "/api/policy".to_string(),
    ] {
        let res = app
            .call_raw(Which::Vault, cookie_req(&one, Method::GET, &path).build())
            .await;
        assert_eq!(res.status, StatusCode::NOT_FOUND, "{path}");
        assert!(!res.text().contains("min_length"), "{path}");
    }

    // The admin listener does not serve it.
    let res = app
        .call(
            Which::Admin,
            Req::get(PATH).page_fetch(Which::Admin).build(),
        )
        .await;
    assert_eq!(res.status, StatusCode::NOT_FOUND);
}

/// Without the feature the route is there and says that nothing is allowed,
/// whatever the table holds; the page and its tab are not mounted.
#[cfg(not(feature = "quick-unlock"))]
#[tokio::test]
async fn the_policy_says_off_without_quick_unlock() {
    use support::handoff::admin_user;

    let app = real_time_app().await;
    let (_user, vault) = admin_user(&app, 1).await;
    assert!(stored(&app).await.pin_allowed, "the table says yes");
    let res = app
        .call_raw(
            Which::Vault,
            Req::get(PATH)
                .page_fetch(Which::Vault)
                .header("cookie", &vault.jar.header().expect("a cookie"))
                .build(),
        )
        .await;
    assert_eq!(res.status, StatusCode::OK, "{}", res.text());
    let body = res.json();
    assert_eq!(body["pin"]["allowed"], json!(false));
    assert_eq!(body["prf"]["enabled"], json!(false));

    // No page, no tab and no post.
    let page = app
        .call(Which::Admin, Req::get("/settings/unlock").build())
        .await;
    assert_eq!(page.status, StatusCode::NOT_FOUND);
    let post = app
        .call(
            Which::Admin,
            Req::post("/settings/unlock")
                .page_fetch(Which::Admin)
                .form(&[("min_length", "8")])
                .build(),
        )
        .await;
    assert_eq!(post.status, StatusCode::NOT_FOUND);
    assert_eq!(stored(&app).await, UnlockPolicy::default());
    let backup = app
        .call(Which::Admin, Req::get("/settings/backup").build())
        .await;
    assert_eq!(backup.status, StatusCode::OK);
    assert!(!backup.text().contains("/settings/unlock"), "no tab");
}

#[cfg(feature = "quick-unlock")]
#[tokio::test]
async fn the_policy_follows_the_stored_rule_with_quick_unlock() {
    let app = device_app().await;
    let client = client_account(&app, 1).await;
    let session = client_session(&app, &client, SessionScope::Full, 1).await;
    for rule in [
        UnlockPolicy::default(),
        UnlockPolicy {
            pin_allowed: false,
            pin_after_restart: true,
            pin_min_length: 4,
        },
        UnlockPolicy {
            pin_allowed: true,
            pin_after_restart: false,
            pin_min_length: 64,
        },
    ] {
        store(&app, rule).await;
        let res = get_by_session(&app, &session).await;
        assert_eq!(res.json(), expected(&rule), "{rule:?}");
    }
    let body = get_by_session(&app, &session).await.json();
    assert_eq!(
        body["prf"]["enabled"],
        json!(policy::PRF_ROUTES_MOUNTED),
        "the passkey switch follows the routes, not the feature"
    );
}

// ------------------------------------------------------------------ the page

#[cfg(feature = "quick-unlock")]
mod page {
    use super::*;
    use ferret_server::admin::unlock::{
        MANY_COMPUTERS, OFFLINE_GUESSES_PER_SECOND, duration_text, seconds_to_try_all,
    };
    use support::Jar;
    use support::handoff::{admin_user, set_role};

    const PAGE: &str = "/settings/unlock";

    async fn get(app: &TestApp, path: &str) -> Res {
        app.call(Which::Admin, Req::get(path).build()).await
    }

    /// What the page's form sends when a person presses Save.
    async fn post(app: &TestApp, fields: &[(&str, &str)]) -> Res {
        app.call(
            Which::Admin,
            Req::post(PAGE)
                .page_fetch(Which::Admin)
                .form(fields)
                .build(),
        )
        .await
    }

    /// The page's text with the markup taken out.
    fn visible(page: &str) -> String {
        let mut out = String::new();
        let mut in_tag = false;
        for c in page.chars() {
            match c {
                '<' => in_tag = true,
                '>' => {
                    in_tag = false;
                    out.push(' ');
                }
                _ if !in_tag => out.push(c),
                _ => {}
            }
        }
        out.split_whitespace().collect::<Vec<_>>().join(" ")
    }

    #[tokio::test]
    async fn the_unlock_tab_is_for_administrators_only() {
        let app = real_time_app().await;
        let (user, vault) = admin_user(&app, 1).await;
        let admin = app.jar(Which::Admin);
        let before = stored(&app).await;

        // No session, the kit's cookie alone and a vault session id with it:
        // the sign-in redirect for the page and 401 for the post.
        let kit = admin
            .get("__Host-ferret_session")
            .expect("the kit's cookie")
            .to_string();
        let mut alone = Jar::default();
        alone.set("__Host-ferret_session", &kit);
        let mut with_vault_sid = alone.clone();
        with_vault_sid.set(
            "__Host-ferret_sid",
            vault.jar.get("__Host-ferret_sid").expect("the vault sid"),
        );
        for (jar, why) in [
            (Jar::default(), "no cookie"),
            (alone, "kit cookie alone"),
            (with_vault_sid, "kit cookie and a vault session id"),
        ] {
            app.set_jar(Which::Admin, jar);
            let res = get(&app, PAGE).await;
            assert!(res.status.is_redirection(), "{why}: {}", res.status);
            assert!(!res.text().contains("Allow PIN"), "{why}");
            let res = post(&app, &[("min_length", "12")]).await;
            assert_eq!(res.status, StatusCode::UNAUTHORIZED, "{why}");
        }

        // An editor and a viewer are refused, page and post; nothing changes.
        app.set_jar(Which::Admin, admin.clone());
        for role in ["editor", "viewer"] {
            set_role(&app, user.user_id, role).await;
            let res = get(&app, PAGE).await;
            assert_eq!(res.status, StatusCode::FORBIDDEN, "{role}");
            assert!(!res.text().contains("Allow PIN"), "{role}");
            let res = post(&app, &[("min_length", "12"), ("pin_allowed", "true")]).await;
            assert_eq!(res.status, StatusCode::FORBIDDEN, "{role}");
            assert_eq!(stored(&app).await, before, "{role}");
            // The tab is not shown to them on a page they may see.
            let general = get(&app, "/settings/general").await;
            assert!(!general.text().contains(PAGE), "{role}");
        }

        // An administrator sees the tab and the page.
        set_role(&app, user.user_id, "admin").await;
        let res = get(&app, PAGE).await;
        assert_eq!(res.status, StatusCode::OK, "{}", res.text());
        assert!(res.text().contains("Allow PIN"));
        assert!(
            res.text().contains(&format!("href=\"{PAGE}\"")),
            "the settings tabs link the page"
        );
        let backup = get(&app, "/settings/backup").await;
        assert!(backup.text().contains(&format!("href=\"{PAGE}\"")));

        // The vault listener has no such page, with a full vault session too.
        for path in [PAGE, "/settings/unlock/save", "/unlock"] {
            for method in [Method::GET, Method::POST] {
                let res = app
                    .call_raw(
                        Which::Vault,
                        Req::new(method.clone(), path)
                            .page_fetch(Which::Vault)
                            .header("cookie", &vault.jar.header().expect("a cookie"))
                            .build(),
                    )
                    .await;
                assert_eq!(res.status, StatusCode::NOT_FOUND, "{method} {path}");
            }
        }
        assert_eq!(stored(&app).await, before);
    }

    #[tokio::test]
    async fn the_unlock_tab_refuses_lengths_outside_4_to_64_and_needs_the_csrf_token() {
        let app = real_time_app().await;
        admin_user(&app, 1).await;
        let before = stored(&app).await;

        // A length outside 4 to 64, or none that is a whole number: the page
        // again with the reason, 422, and the stored rule as it was.
        for typed in [
            "3",
            "65",
            "0",
            "-1",
            "",
            "  ",
            "six",
            "6.5",
            "1e1",
            "99999999999999999999",
            "٦",
        ] {
            let res = post(
                &app,
                &[
                    ("pin_allowed", "true"),
                    ("pin_after_restart", "true"),
                    ("min_length", typed),
                ],
            )
            .await;
            assert_eq!(
                res.status,
                StatusCode::UNPROCESSABLE_ENTITY,
                "{typed:?}: {}",
                res.status
            );
            let text = visible(&res.text());
            assert!(
                text.contains("Enter a whole number from 4 to 64."),
                "{typed:?}"
            );
            assert_eq!(stored(&app).await, before, "{typed:?}");
        }
        // A missing field is the same as none.
        let res = post(&app, &[("pin_allowed", "true")]).await;
        assert_eq!(res.status, StatusCode::UNPROCESSABLE_ENTITY);
        assert_eq!(stored(&app).await, before);

        // The ends are fine, a longer minimum needs the confirmation (below),
        // and a shorter one saves at once.
        let res = post(
            &app,
            &[
                ("pin_allowed", "true"),
                ("pin_after_restart", "true"),
                ("min_length", "4"),
            ],
        )
        .await;
        assert_eq!(res.status, StatusCode::SEE_OTHER, "{}", res.text());
        assert_eq!(res.header("location"), PAGE);
        assert_eq!(stored(&app).await.pin_min_length, 4);
        let res = post(
            &app,
            &[
                ("pin_allowed", "true"),
                ("pin_after_restart", "true"),
                ("min_length", "64"),
                ("confirm", "1:1:64"),
            ],
        )
        .await;
        assert_eq!(res.status, StatusCode::SEE_OTHER, "{}", res.text());
        assert_eq!(stored(&app).await.pin_min_length, 64);

        // A post that does not come from the page is refused before the
        // handler: no origin, an origin of another site, the vault's origin,
        // and the script header alone.
        let fields = [
            ("pin_allowed", "true"),
            ("pin_after_restart", "true"),
            ("min_length", "5"),
        ];
        let before = stored(&app).await;
        for (why, req) in [
            ("no origin", Req::post(PAGE)),
            (
                "the kit's script header and no origin",
                Req::post(PAGE).header("hx-request", "true"),
            ),
            (
                "another site",
                Req::post(PAGE).header("origin", "https://evil.example"),
            ),
            (
                "the vault origin",
                Req::post(PAGE).header("origin", Which::Vault.url()),
            ),
        ] {
            let res = app.call(Which::Admin, req.form(&fields).build()).await;
            assert_eq!(res.status, StatusCode::FORBIDDEN, "{why}: {}", res.text());
            assert_eq!(stored(&app).await, before, "{why}");
        }
    }

    #[tokio::test]
    async fn the_unlock_tab_explains_disk_by_default_one_machine_and_more_machines() {
        let app = real_time_app().await;
        admin_user(&app, 1).await;

        // The default rule: six digits.
        let res = get(&app, PAGE).await;
        assert_eq!(res.status, StatusCode::OK, "{}", res.text());
        let text = visible(&res.text());
        for said in [
            // On disk by default, so it works after a restart and offline.
            "By default the extension keeps a PIN encrypted on the user’s own computer",
            "works after a restart of the browser and without a network",
            // One machine and many machines.
            "A PIN of at least 6 digits has 1,000,000 combinations",
            "in under 3 hours with one powerful computer",
            "in under 2 minutes with 100 computers",
            // A chosen PIN falls sooner, and the limit is not on a copy.
            "PINs that people choose themselves (dates, 123456, patterns) fall much sooner",
            "The limit of 5 attempts applies only inside the extension, not to a copy of the profile",
            // What the switches do.
            "If you turn off Allow PIN after restart, a PIN is kept in memory only",
            "If you turn off Allow PIN, every PIN is deleted at the next contact",
        ] {
            assert!(text.contains(said), "no {said:?} in: {text}");
        }
        assert!(text.contains("Allow PIN after restart"));
        assert!(text.contains("Shortest PIN"));

        // The text follows the shortest length that is saved.
        for (length, combos, one, many) in [
            ("4", "10,000", "under 2 minutes", "under 2 seconds"),
            ("8", "100,000,000", "under 12 days", "under 3 hours"),
            ("9", "1,000,000,000", "under 4 months", "under 2 days"),
        ] {
            let res = post(
                &app,
                &[
                    ("pin_allowed", "true"),
                    ("pin_after_restart", "true"),
                    ("min_length", length),
                    ("confirm", &format!("1:1:{length}")),
                ],
            )
            .await;
            assert_eq!(
                res.status,
                StatusCode::SEE_OTHER,
                "{length}: {}",
                res.text()
            );
            let text = visible(&get(&app, PAGE).await.text());
            assert!(
                text.contains(&format!(
                    "A PIN of at least {length} digits has {combos} combinations"
                )),
                "{length}: {text}"
            );
            assert!(
                text.contains(&format!("in {one} with one powerful computer")),
                "{length}: {text}"
            );
            assert!(
                text.contains(&format!("in {many} with 100 computers")),
                "{length}: {text}"
            );
        }

        // The page is also in Norwegian for a user who reads it so.
        app.state
            .vault_db
            .with_conn(|conn| {
                conn.execute("UPDATE users SET language = 'nb'", [])?;
                Ok(())
            })
            .await
            .expect("a language");
        let text = visible(&get(&app, PAGE).await.text());
        for said in [
            "Tillat PIN etter omstart",
            "med én kraftig datamaskin",
            "med 100 datamaskiner",
            "PIN-er folk velger selv",
            "bare i minnet",
        ] {
            assert!(text.contains(said), "no {said:?} in: {text}");
        }
        assert!(!text.contains("Allow PIN"), "{text}");
    }

    #[tokio::test]
    async fn the_admin_text_uses_the_cores_offline_constant() {
        // The one number sits in one place and the page's times are computed
        // from it: the time for a hundred computers is a hundredth of the time
        // for one.
        let per = f64::from(OFFLINE_GUESSES_PER_SECOND);
        for length in [4u8, 6, 8, 10] {
            let one = seconds_to_try_all(length, per);
            let many = seconds_to_try_all(length, per * f64::from(MANY_COMPUTERS));
            assert!(
                (one / many - f64::from(MANY_COMPUTERS)).abs() < 1e-6,
                "{length}"
            );
        }
        let app = real_time_app().await;
        admin_user(&app, 1).await;
        let text = visible(&get(&app, PAGE).await.text());
        let one = duration_text(10f64.powi(6) / f64::from(OFFLINE_GUESSES_PER_SECOND));
        assert!(
            text.contains(&format!("in {one} with one powerful computer")),
            "{text}"
        );

        // It is the number of the core's PIN profile, where the core has it.
        let core = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../ferret-core/src/pin_profile.rs");
        if let Ok(source) = std::fs::read_to_string(&core) {
            let line = source
                .lines()
                .find(|l| l.contains("pub const PIN_OFFLINE_GUESSES_PER_SECOND"))
                .expect("the core's constant");
            let value: u32 = line
                .split('=')
                .nth(1)
                .and_then(|v| v.trim().trim_end_matches(';').trim().parse().ok())
                .expect("a number");
            assert_eq!(value, OFFLINE_GUESSES_PER_SECOND);
        }
    }

    #[tokio::test]
    async fn a_stricter_rule_or_a_switch_off_is_announced_before_it_is_saved() {
        let app = real_time_app().await;
        admin_user(&app, 1).await;
        let before = stored(&app).await;

        // Each harder change alone: the page says what it deletes, nothing is
        // saved, and the form that comes back carries the confirmation.
        let cases: [(&[(&str, &str)], &str, &str); 4] = [
            (
                &[
                    ("pin_allowed", "true"),
                    ("pin_after_restart", "true"),
                    ("min_length", "8"),
                ],
                "Raising the shortest PIN to 8 characters deletes every PIN that is shorter.",
                "1:1:8",
            ),
            (
                &[("pin_after_restart", "true"), ("min_length", "6")],
                "Turning off Allow PIN deletes every PIN.",
                "0:1:6",
            ),
            (
                &[("pin_allowed", "true"), ("min_length", "6")],
                "Turning off Allow PIN after restart deletes every PIN that is kept on disk.",
                "1:0:6",
            ),
            (
                &[("min_length", "10")],
                "Turning off Allow PIN deletes every PIN.",
                "0:0:10",
            ),
        ];
        for (fields, said, token) in cases {
            let res = post(&app, fields).await;
            assert_eq!(res.status, StatusCode::OK, "{fields:?}: {}", res.text());
            let text = visible(&res.text());
            assert!(text.contains("This rule is stricter"), "{fields:?}: {text}");
            assert!(text.contains(said), "{fields:?}: {text}");
            assert!(text.contains("Select Save again to confirm."), "{text}");
            assert!(
                res.text().contains(&format!(
                    "<input type=\"hidden\" name=\"confirm\" value=\"{token}\">"
                )),
                "{fields:?}"
            );
            assert_eq!(stored(&app).await, before, "{fields:?} was saved too early");
        }
        // The confirmation belongs to the rule that was announced: the same
        // token with another rule (a switch turned off too, a longer minimum,
        // a confirmation of a plain "true") announces that rule and saves
        // nothing.
        for (fields, why) in [
            (
                [
                    ("pin_allowed", ""),
                    ("pin_after_restart", "true"),
                    ("min_length", "8"),
                    ("confirm", "1:1:8"),
                ],
                "a switch turned off after the announcement",
            ),
            (
                [
                    ("pin_allowed", "true"),
                    ("pin_after_restart", "true"),
                    ("min_length", "12"),
                    ("confirm", "1:1:8"),
                ],
                "a longer minimum after the announcement",
            ),
            (
                [
                    ("pin_allowed", "true"),
                    ("pin_after_restart", "true"),
                    ("min_length", "8"),
                    ("confirm", "true"),
                ],
                "a bare yes",
            ),
        ] {
            let fields: Vec<(&str, &str)> = fields
                .into_iter()
                .filter(|(k, v)| !(*k == "pin_allowed" && v.is_empty()))
                .collect();
            let res = post(&app, &fields).await;
            assert_eq!(res.status, StatusCode::OK, "{why}: {}", res.text());
            assert!(
                visible(&res.text()).contains("This rule is stricter"),
                "{why}"
            );
            assert_eq!(stored(&app).await, before, "{why} was saved");
        }
        // The page as it is opened again does not announce anything.
        let text = visible(&get(&app, PAGE).await.text());
        assert!(!text.contains("This rule is stricter"));

        // The same form with the confirmation saves, and says so.
        let res = post(
            &app,
            &[
                ("pin_allowed", "true"),
                ("pin_after_restart", "true"),
                ("min_length", "8"),
                ("confirm", "1:1:8"),
            ],
        )
        .await;
        assert_eq!(res.status, StatusCode::SEE_OTHER, "{}", res.text());
        assert_eq!(
            stored(&app).await,
            UnlockPolicy {
                pin_allowed: true,
                pin_after_restart: true,
                pin_min_length: 8,
            }
        );
        let text = visible(&get(&app, PAGE).await.text());
        assert!(text.contains("The unlock rule was saved."), "{text}");

        // A rule that is not stricter saves at once, with no announcement: a
        // shorter minimum, and a switch turned on.
        let res = post(
            &app,
            &[
                ("pin_allowed", "true"),
                ("pin_after_restart", "true"),
                ("min_length", "5"),
            ],
        )
        .await;
        assert_eq!(res.status, StatusCode::SEE_OTHER, "{}", res.text());
        assert_eq!(stored(&app).await.pin_min_length, 5);
        store(
            &app,
            UnlockPolicy {
                pin_allowed: false,
                pin_after_restart: false,
                pin_min_length: 5,
            },
        )
        .await;
        let res = post(
            &app,
            &[
                ("pin_allowed", "true"),
                ("pin_after_restart", "true"),
                ("min_length", "5"),
            ],
        )
        .await;
        assert_eq!(res.status, StatusCode::SEE_OTHER, "{}", res.text());
        assert_eq!(
            stored(&app).await,
            UnlockPolicy {
                pin_allowed: true,
                pin_after_restart: true,
                pin_min_length: 5,
            }
        );

        // The same rule again changes nothing and says so.
        let res = post(
            &app,
            &[
                ("pin_allowed", "true"),
                ("pin_after_restart", "true"),
                ("min_length", "5"),
            ],
        )
        .await;
        assert_eq!(res.status, StatusCode::SEE_OTHER);
        let text = visible(&get(&app, PAGE).await.text());
        assert!(text.contains("Nothing was changed."), "{text}");

        // What a client reads follows what was saved.
        let client = client_account(&app, 5).await;
        let session = client_session(&app, &client, SessionScope::Full, 1).await;
        let res = get_by_session(&app, &session).await;
        assert_eq!(res.json()["pin"]["min_length"], json!(5));
        assert_eq!(res.json()["pin"]["allowed"], json!(true));
    }
}
