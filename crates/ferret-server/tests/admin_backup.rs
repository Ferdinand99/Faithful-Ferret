//! The Backup page of the admin pages and "Take a backup now": what the page
//! shows (and never shows), who may use the button, what a second click does
//! and that the vault listener has no such page. Spec: Fase 1 § 11.

mod support;

use std::sync::Arc;

use axum::http::StatusCode;
use ferret_server::backup::schedule::{COLLECT_FOR, FIRST_RUN_AFTER};
use ferret_server::backup::set;
use serde_json::json;
use support::backup::{Reply, StandIn, cfg_with_push, job, listed};
use support::handoff::{admin_user, set_role};
use support::{Jar, Req, Res, TestApp, Which};

const PAGE: &str = "/settings/backup";
const RUN: &str = "/settings/backup/run";
const SID_COOKIE: &str = "__Host-ferret_sid";
const SESSION_COOKIE: &str = "__Host-ferret_session";

async fn get(app: &TestApp, path: &str) -> Res {
    app.call(Which::Admin, Req::get(path).build()).await
}

/// What the "Take a backup now" button of the page sends.
async fn click(app: &TestApp) -> Res {
    app.call(
        Which::Admin,
        Req::post(RUN).page_fetch(Which::Admin).build(),
    )
    .await
}

/// A page that holds `text`, with the answer's status checked first.
fn assert_page_has(res: &Res, text: &str) {
    assert_eq!(res.status, StatusCode::OK, "{}", res.text());
    assert!(res.text().contains(text), "no {text:?} in the page");
}

/// The page's text with the markup around the visible words taken out, so a
/// test can look for what a reader would see.
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

// ------------------------------------------------------------------- the page

#[tokio::test]
async fn panel_shows_the_backup_status_and_the_last_push_and_no_secret_path_or_url() {
    let app = TestApp::new_at_real_time().await;
    admin_user(&app, 1).await;

    // Before any run: the page opens, says nothing has run and offers the button.
    let res = get(&app, PAGE).await;
    assert_page_has(&res, "Not run yet");
    assert_page_has(&res, "Take a backup now");
    assert!(
        res.text().contains(&format!("action=\"{RUN}\"")),
        "the form posts to the run route"
    );
    assert!(!res.text().contains(" disabled"), "the button is on");
    assert!(
        res.text().contains(&format!("href=\"{PAGE}\"")),
        "the settings tabs link the page"
    );

    // One real run with a monitor that has a secret address: a good set, and a
    // message that the monitor took.
    let monitor = StandIn::start(Reply::Ok).await;
    let address = format!("http://{}/api/push/tokenabc123", monitor.addr);
    let cfg = cfg_with_push(&app, &address);
    let mut job = job(&app, cfg.clone(), Arc::new(set::RealPlatform));
    app.clock.advance(FIRST_RUN_AFTER as u64);
    job.poll().await.expect("a run").expect("a set");
    assert_eq!(monitor.requests().len(), 1, "the monitor was told");
    let names = listed(&cfg);
    assert_eq!(names.len(), 1);

    let res = get(&app, PAGE).await;
    assert_page_has(&res, "Good");
    let text = visible(&res.text());
    assert!(text.contains("Sets kept 1"), "{text}");
    assert!(text.contains("Last good backup"), "{text}");
    assert!(text.contains("Last failure None"), "{text}");
    assert!(text.contains("Last message to the monitor Taken"), "{text}");
    assert!(text.contains("Next backup"), "{text}");
    let snapshot = app.backup_status().snapshot();
    let good = snapshot.last_good_at.expect("a good time");
    let next = snapshot.next_run_at.expect("a next run");
    for at in [good, next] {
        let t = time::OffsetDateTime::from_unix_timestamp(at).expect("a time");
        let stamp = format!(
            "{:04}-{:02}-{:02} {:02}:{:02}:{:02}",
            t.year(),
            u8::from(t.month()),
            t.day(),
            t.hour(),
            t.minute(),
            t.second()
        );
        assert!(res.text().contains(&stamp), "{stamp} is on the page");
    }

    // A failed run and a message the monitor did not take: the fixed codes and
    // the page's own words for them.
    let now = good + 10;
    app.backup_status().record_failure(now, "no_space");
    app.backup_status().record_push(now, Err("timeout"));
    let res = get(&app, PAGE).await;
    assert_page_has(&res, "Failed");
    let text = visible(&res.text());
    assert!(text.contains("The last backup failed"), "{text}");
    assert!(text.contains("no_space"), "{text}");
    assert!(text.contains("too little free space"), "{text}");
    assert!(text.contains("Not taken"), "{text}");
    assert!(text.contains("timeout"), "{text}");
    assert!(text.contains("did not answer in time"), "{text}");
    assert!(text.contains("Sets kept 1"), "{text}");

    // Nothing of the machine, the set or the monitor is on the page, in any
    // state: not the address or its secret path, not a path of the machine, not
    // the name of a set or of a secret file, and the headers hold none either.
    let full = format!("{}\n{:?}", res.text(), res.headers);
    let dir = app.dir.display().to_string();
    let backup_dir = cfg.dir.display().to_string();
    let mut secrets = vec![
        "tokenabc123".to_string(),
        "/api/push".to_string(),
        monitor.addr.to_string(),
        dir,
        backup_dir,
        "opaque_setup".into(),
        "prelogin_secret".into(),
        "session.key".into(),
        "ferret.sqlite".into(),
        "MANIFEST".into(),
        ".complete".into(),
        "status.json".into(),
        "backups/auto".into(),
    ];
    secrets.extend(names);
    for secret in secrets {
        assert!(!full.contains(&secret), "the page shows {secret:?}");
    }
}

#[tokio::test]
async fn a_status_file_that_was_edited_by_hand_is_not_shown_as_it_stands() {
    let app = TestApp::new_at_real_time().await;
    admin_user(&app, 1).await;
    let status = app.backup_status();
    status.record_failure(1_700_000_000, "<b>/data/backups/auto</b>");
    status.record_push(1_700_000_000, Err("https://monitor.example/api/push/tok"));
    let res = get(&app, PAGE).await;
    assert_eq!(res.status, StatusCode::OK);
    let page = res.text();
    assert!(page.contains("unknown"));
    for hidden in ["/data/backups/auto", "monitor.example"] {
        assert!(!page.contains(hidden), "{hidden}");
    }
}

// ------------------------------------------------------------------- the button

#[tokio::test]
async fn backup_now_needs_an_admin_session_and_the_csrf_token() {
    let app = TestApp::new_at_real_time().await;
    let (user, vault) = admin_user(&app, 1).await;
    let status = app.backup_status();
    let admin = app.jar(Which::Admin);

    // The kit's cookie alone, a vault session id with it, and no cookie at all:
    // the one 401, and no backup is asked for.
    let kit = admin
        .get(SESSION_COOKIE)
        .expect("the kit's cookie")
        .to_string();
    let mut alone = Jar::default();
    alone.set(SESSION_COOKIE, &kit);
    let mut with_vault_sid = alone.clone();
    with_vault_sid.set(
        SID_COOKIE,
        vault.jar.get(SID_COOKIE).expect("the vault sid"),
    );
    for (jar, why) in [
        (Jar::default(), "no cookie"),
        (alone, "kit cookie alone"),
        (with_vault_sid, "kit cookie and a vault session id"),
    ] {
        app.set_jar(Which::Admin, jar);
        let res = click(&app).await;
        assert_eq!(res.status, StatusCode::UNAUTHORIZED, "{why}");
        assert_eq!(res.json(), json!({ "error": "unauthorized" }), "{why}");
        let res = get(&app, PAGE).await;
        assert!(res.status.is_redirection(), "{why}: {}", res.status);
        assert!(!res.text().contains("Take a backup now"), "{why}");
        assert!(!status.has_request(), "{why}");
    }

    // A signed-in administrator, but a post that does not come from the page:
    // no Origin and no Referer, an Origin of another site, the vault's origin.
    app.set_jar(Which::Admin, admin.clone());
    let from_elsewhere = [
        ("no origin", Req::post(RUN)),
        (
            "the kit's script header and no origin",
            Req::post(RUN).header("hx-request", "true"),
        ),
        (
            "another site",
            Req::post(RUN).header("origin", "https://evil.example"),
        ),
        (
            "the vault origin",
            Req::post(RUN).header("origin", Which::Vault.url()),
        ),
    ];
    for (why, req) in from_elsewhere {
        let res = app.call(Which::Admin, req.build()).await;
        assert_eq!(res.status, StatusCode::FORBIDDEN, "{why}: {}", res.text());
        assert!(!status.has_request(), "{why}");
    }

    // A signed-in user who is not an administrator, from the page itself.
    set_role(&app, user.user_id, "editor").await;
    let res = click(&app).await;
    assert_eq!(res.status, StatusCode::FORBIDDEN, "{}", res.text());
    assert!(!status.has_request(), "an editor");
    assert_eq!(get(&app, PAGE).await.status, StatusCode::FORBIDDEN);
    set_role(&app, user.user_id, "admin").await;

    // The administrator's own click from the page: one request, with the one
    // fixed reason, and a redirect back to the page.
    let res = click(&app).await;
    assert_eq!(res.status, StatusCode::SEE_OTHER, "{}", res.text());
    assert_eq!(res.header("location"), PAGE);
    assert!(res.body.is_empty(), "no body");
    assert_eq!(status.take_request(), Some("manual"));
    assert_eq!(status.take_request(), None);

    // The sign-out ends it: the cookies of the ended session ask for nothing.
    app.set_jar(Which::Admin, admin.clone());
    assert_eq!(
        app.call(
            Which::Admin,
            Req::post("/api/auth/logout")
                .page_fetch(Which::Admin)
                .build()
        )
        .await
        .status,
        StatusCode::NO_CONTENT
    );
    status.take_request();
    app.set_jar(Which::Admin, admin);
    let res = click(&app).await;
    assert_eq!(res.status, StatusCode::UNAUTHORIZED);
    assert!(!status.has_request());
}

#[tokio::test]
async fn a_click_asks_for_a_run_that_the_job_makes_and_the_page_says_so() {
    let app = TestApp::new_at_real_time().await;
    admin_user(&app, 1).await;
    let cfg = support::backup::cfg(&app);
    let mut job = job(&app, cfg.clone(), Arc::new(set::RealPlatform));

    let res = click(&app).await;
    assert_eq!(res.status, StatusCode::SEE_OTHER);
    let res = get(&app, PAGE).await;
    let text = visible(&res.text());
    assert!(
        text.contains("A backup was asked for. It starts within a minute."),
        "{text}"
    );
    assert!(res.text().contains(" disabled"), "the button is off");
    // The flash is shown once.
    assert!(
        !visible(&get(&app, PAGE).await.text()).contains("A backup was asked for."),
        "shown twice"
    );

    // The job collects the request for a minute, then makes the set.
    assert!(job.poll().await.is_none(), "the window is collecting");
    app.clock.advance(COLLECT_FOR as u64);
    job.poll().await.expect("a run").expect("a set");
    assert_eq!(listed(&cfg).len(), 1);
    let res = get(&app, PAGE).await;
    assert_page_has(&res, "Good");
    assert!(!res.text().contains(" disabled"), "the button is on again");
}

#[tokio::test]
async fn a_second_backup_now_while_one_runs_is_refused() {
    let app = TestApp::new_at_real_time().await;
    admin_user(&app, 1).await;
    let status = app.backup_status();

    // A run is going on: the click is refused, says so and asks for nothing.
    status.set_running(true);
    let res = click(&app).await;
    assert_eq!(res.status, StatusCode::SEE_OTHER, "{}", res.text());
    assert!(!status.has_request(), "nothing was asked for");
    let res = get(&app, PAGE).await;
    let text = visible(&res.text());
    assert!(
        text.contains("A backup is already running or about to start."),
        "{text}"
    );
    assert!(text.contains("Running"), "{text}");
    assert!(res.text().contains(" disabled"), "the button is off");
    // Not even a click that bypasses the page's disabled button.
    let res = click(&app).await;
    assert_eq!(res.status, StatusCode::SEE_OTHER);
    assert!(!status.has_request());

    // The run ends: the next click goes through, and the one after it, before
    // the job has picked the request up, is refused.
    status.set_running(false);
    assert_eq!(click(&app).await.status, StatusCode::SEE_OTHER);
    assert!(status.has_request());
    assert_eq!(click(&app).await.status, StatusCode::SEE_OTHER);
    let text = visible(&get(&app, PAGE).await.text());
    assert!(
        text.contains("A backup is already running or about to start."),
        "{text}"
    );

    // The job has taken the request and is collecting for a minute: still
    // refused, and still one request in all.
    assert_eq!(status.take_request(), Some("manual"));
    assert_eq!(status.take_request(), None);
    assert_eq!(click(&app).await.status, StatusCode::SEE_OTHER);
    assert!(
        !status.has_request(),
        "the collecting window is not stacked"
    );

    // The run starts and ends: a click goes through again.
    status.set_running(true);
    status.set_running(false);
    assert_eq!(click(&app).await.status, StatusCode::SEE_OTHER);
    assert_eq!(status.take_request(), Some("manual"));
}

// ------------------------------------------------------------------- the vault listener

#[tokio::test]
async fn the_vault_listener_has_no_backup_page() {
    let app = TestApp::new_at_real_time().await;
    admin_user(&app, 1).await;
    let status = app.backup_status();

    // Even with a full vault session (the vault jar holds one), the vault
    // listener answers 404 for the page, the action and every neighbouring name
    // a backup page or a health path could have.
    for path in [
        PAGE,
        RUN,
        "/settings",
        "/backup",
        "/backup/run",
        "/vault/backup",
        "/api/backup",
        "/api/v1/backup",
        "/admin/backup",
        "/healthz/backup",
    ] {
        let res = app.call(Which::Vault, Req::get(path).build()).await;
        assert_eq!(res.status, StatusCode::NOT_FOUND, "GET {path}");
        assert!(!res.text().contains("backup"), "GET {path}");
        let res = app
            .call(
                Which::Vault,
                Req::post(path).page_fetch(Which::Vault).build(),
            )
            .await;
        assert!(
            res.status == StatusCode::NOT_FOUND || res.status == StatusCode::METHOD_NOT_ALLOWED,
            "POST {path}: {}",
            res.status
        );
    }
    assert!(!status.has_request());
    assert!(!status.snapshot().waiting);

    // And the admin listener, with no session, does not give the page away.
    app.clear_jar(Which::Admin);
    let res = get(&app, PAGE).await;
    assert!(res.status.is_redirection());
    assert!(!res.text().contains("Take a backup now"));
}
