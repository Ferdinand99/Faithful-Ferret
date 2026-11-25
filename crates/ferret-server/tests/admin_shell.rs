//! The admin pages' side menu (vole-kit's `Shell::Sidebar`): the frame around
//! every signed-in admin page, with the switch to the web vault, the three
//! sections of pages and the account menu. The menu hides what a user may not
//! see; each page still refuses by itself (the page tests do that).

mod support;

use axum::http::StatusCode;
use support::handoff::{admin_user, set_role};
use support::{Req, Res, TestApp, VAULT_URL, Which};

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

/// The side menu's `<nav>` of a page: what the menu lists and nothing else.
fn side_nav(page: &str) -> &str {
    let start = page
        .find("<nav class=\"side-nav\"")
        .unwrap_or_else(|| panic!("no side menu on the page: {page}"));
    let rest = &page[start..];
    let end = rest.find("</nav>").expect("the menu closes");
    &rest[..end]
}

/// Every address the page's side menu links to.
fn menu_links(page: &str) -> Vec<String> {
    let nav = side_nav(page);
    nav.split("href=\"")
        .skip(1)
        .map(|rest| rest[..rest.find('"').expect("a closed attribute")].to_string())
        .collect()
}

/// The pages of the admin area that exist in this build, in the menu's order.
fn pages() -> Vec<&'static str> {
    let mut pages = vec!["/settings/backup", "/settings/users", "/settings/general"];
    if cfg!(feature = "quick-unlock") {
        pages.push("/settings/unlock");
    }
    pages.push("/settings/security");
    pages
}

#[tokio::test]
async fn every_admin_page_has_the_side_menu_and_no_tab_column() {
    let app = TestApp::new_at_real_time().await;
    admin_user(&app, 1).await;
    for path in pages() {
        let res = get(&app, path).await;
        assert_eq!(res.status, StatusCode::OK, "{path}: {}", res.text());
        let page = res.text();
        assert!(page.contains("class=\"has-side\""), "{path}");
        // The kit's files for the side menu, from the admin origin itself.
        assert!(page.contains("href=\"/static/shell.css\""), "{path}");
        assert!(page.contains("src=\"/static/shell.js\""), "{path}");
        // The top bar, the phone tab bar and the tab column are gone.
        for gone in ["class=\"topbar\"", "class=\"tabbar\"", "settings-side"] {
            assert!(!page.contains(gone), "{path}: {gone}");
        }
        // Every page of the admin area is one entry of the menu, and this
        // page's own entry is the current one.
        let links = menu_links(&page);
        for target in pages() {
            assert!(links.iter().any(|l| l == target), "{path}: no {target}");
        }
        let nav = side_nav(&page);
        let current: Vec<&str> = nav.matches("aria-current=\"page\"").collect();
        assert_eq!(current.len(), 1, "{path}: one current entry");
        let here = format!("href=\"{path}\"");
        let entry = nav.find(&here).expect("the page's own entry");
        assert!(
            nav[entry..]
                .split('>')
                .next()
                .unwrap()
                .contains("aria-current=\"page\""),
            "{path}: the current entry is the page's own"
        );
        // Nothing the kit has turned off is linked.
        for off in ["/settings/tokens", "/api-docs", "/settings/notifications"] {
            assert!(!links.iter().any(|l| l == off), "{path}: {off}");
        }
    }
}

#[tokio::test]
async fn the_logo_stays_in_the_admin_pages_and_the_switch_leads_to_the_vault() {
    let app = TestApp::new_at_real_time().await;
    admin_user(&app, 1).await;
    let page = get(&app, "/settings/security").await.text();
    // The mark and name, in the menu and in the phone bar, lead to the admin
    // start page and nowhere else.
    assert_eq!(
        page.matches("class=\"brand\" href=\"/settings/general\"")
            .count(),
        2
    );
    assert!(!page.contains("class=\"brand\" href=\"/\""));
    // The switch: Admin on the left, Vault on the right, to the path that
    // sends on to the vault origin.
    let switch = page
        .split("<a class=\"side-switch\"")
        .nth(1)
        .expect("the switch")
        .split("</a>")
        .next()
        .unwrap();
    assert!(switch.contains("href=\"/vault\""), "{switch}");
    assert!(switch.contains("Admin"), "{switch}");
    assert!(switch.contains("Vault"), "{switch}");
    assert!(switch.contains("Switch to Vault"), "{switch}");
    // It is not inside the navigation, so the kit's boosted links never take it.
    assert!(!side_nav(&page).contains("/vault"));
    // The account menu at the foot has the kit's entries and the sign-out.
    assert!(page.contains("class=\"side-foot\""));
    assert!(page.contains("popovertarget=\"user-menu\""));
    assert!(page.contains("action=\"/logout\""));
}

#[tokio::test]
async fn the_menu_has_its_words_in_english_and_norwegian() {
    let app = TestApp::new_at_real_time().await;
    admin_user(&app, 1).await;
    let en = get_in(&app, "/settings/security", "en").await.text();
    for word in [
        "Operations",
        "Access",
        "Settings",
        "Backup",
        "Users",
        "General",
        "Vault",
    ] {
        assert!(en.contains(word), "en: {word}");
    }
    let nb = get_in(&app, "/settings/security", "nb").await.text();
    for word in [
        "Drift",
        "Tilgang",
        "Innstillinger",
        "Hvelv",
        "Brukere",
        "Generelt",
    ] {
        assert!(nb.contains(word), "nb: {word}");
    }
    assert!(!nb.contains("Operations"), "nb has no English heading");
    assert!(
        nb.contains("Bytt til Hvelv") || nb.contains("Hvelv"),
        "the switch's tooltip"
    );
}

#[tokio::test]
async fn a_user_who_is_not_an_administrator_sees_no_admin_entry() {
    let app = TestApp::new_at_real_time().await;
    let (user, _) = admin_user(&app, 1).await;
    let admin_only = {
        let mut only = vec!["/settings/backup", "/settings/users", "/settings/general"];
        if cfg!(feature = "quick-unlock") {
            only.push("/settings/unlock");
        }
        only
    };
    // Positive control: the administrator sees every one of them.
    let links = menu_links(&get(&app, "/settings/security").await.text());
    for target in &admin_only {
        assert!(links.iter().any(|l| l == target), "admin: {target}");
    }
    for role in ["editor", "viewer"] {
        set_role(&app, user.user_id, role).await;
        let res = get(&app, "/settings/security").await;
        assert_eq!(res.status, StatusCode::OK, "{role}: {}", res.text());
        let page = res.text();
        let links = menu_links(&page);
        for target in &admin_only {
            assert!(!links.iter().any(|l| l == target), "{role}: {target}");
            assert!(!side_nav(&page).contains(target), "{role}: {target}");
        }
        // What every signed-in user has is still there, and a section with no
        // entry left is gone with its heading.
        assert!(links.iter().any(|l| l == "/settings/security"), "{role}");
        assert!(!page.contains("Operations"), "{role}");
        assert!(!page.contains(">Access<"), "{role}");
        // The pages themselves still refuse: the menu is not the protection.
        for target in &admin_only {
            let res = get(&app, target).await;
            assert_eq!(res.status, StatusCode::FORBIDDEN, "{role}: {target}");
        }
    }
}

#[tokio::test]
async fn the_switch_path_sends_the_browser_to_the_vault_origin_and_nothing_else() {
    let app = TestApp::new().await;
    // Open to a browser with no session: it starts nothing and carries nothing.
    for path in ["/vault", "/vault?next=https%3A%2F%2Fevil.test&code=1"] {
        let res = get(&app, path).await;
        assert_eq!(res.status, StatusCode::SEE_OTHER, "{path}");
        assert_eq!(
            res.header("location"),
            format!("{VAULT_URL}/vault/"),
            "{path}"
        );
        assert!(res.body.is_empty(), "{path}");
        assert!(res.headers.get("set-cookie").is_none(), "{path}");
    }
    // The response keeps the admin origin's strict referrer policy, so the
    // link leaks no address to the vault origin.
    let res = get(&app, "/vault").await;
    assert_eq!(res.header("referrer-policy"), "no-referrer");
    // Only a read is answered.
    let res = app
        .call(
            Which::Admin,
            Req::post("/vault").page_fetch(Which::Admin).build(),
        )
        .await;
    assert_ne!(res.header("location"), format!("{VAULT_URL}/vault/"));
    // The vault listener has no such redirect: its own `/vault` is the app.
    let res = app.call(Which::Vault, Req::get("/vault").build()).await;
    assert_ne!(res.header("location"), format!("{VAULT_URL}/vault/"));
}
