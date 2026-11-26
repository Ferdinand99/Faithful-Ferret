//! The admin pages carry Ferret's brand colour: the kit's design-system sheets,
//! followed by `brand/admin-brand.css`, whose tokens are those of the web vault.
//! Nothing else the kit serves is touched.

mod support;

use axum::http::StatusCode;
use support::{Req, Res, TestApp, Which};

const BRAND_CSS: &str = include_str!("../brand/admin-brand.css");
const WEB_BASE_CSS: &str = include_str!("../../../web/src/styles/base.css");

async fn get(app: &TestApp, path: &str, etag: Option<&str>) -> Res {
    let mut req = Req::get(path);
    if let Some(etag) = etag {
        req = req.header("if-none-match", etag);
    }
    app.call(Which::Admin, req.build()).await
}

/// The last value a sheet gives a token: the one that counts.
fn last_value<'a>(css: &'a str, token: &str) -> &'a str {
    let at = css
        .rfind(&format!("{token}:"))
        .unwrap_or_else(|| panic!("{token} is set"));
    let rest = &css[at + token.len() + 1..];
    rest[..rest.find(';').expect("a closed declaration")].trim()
}

#[tokio::test]
async fn the_admin_sheets_end_with_the_ferret_brand_tokens() {
    let app = TestApp::new_at_real_time().await;
    for (path, tokens) in [
        (
            "/static/style.css",
            &["--brand", "--brand-fill", "--brand-ring"][..],
        ),
        ("/static/shell.css", &["--brand-text"][..]),
    ] {
        let res = get(&app, path, None).await;
        assert_eq!(res.status, StatusCode::OK, "{path}");
        assert_eq!(res.header("content-type"), "text/css; charset=utf-8");
        let css = res.text();
        assert!(css.ends_with(BRAND_CSS), "{path} ends with the brand sheet");
        for token in tokens {
            let value = last_value(&css, token);
            // The dark half of each is the logo's turquoise or a lighter shade of it.
            assert!(
                ["#59d9c7", "89, 217, 199", "#7ae3d3"]
                    .iter()
                    .any(|turquoise| value.contains(turquoise)),
                "{path}: {token} is {value}, not the logo's turquoise"
            );
            for purple in [
                "#6656e8",
                "#8b7dff",
                "#a99fff",
                "102, 86, 232",
                "139, 125, 255",
            ] {
                assert!(!value.contains(purple), "{path}: {token} is still purple");
            }
        }
    }
    // The kit's own rules are all still there.
    assert!(
        get(&app, "/static/style.css", None)
            .await
            .text()
            .contains(".btn-plain")
    );
}

#[tokio::test]
async fn the_admin_tokens_are_the_web_vaults() {
    // The same four values in base.css, so both surfaces show one colour.
    for token in ["--brand", "--brand-fill", "--brand-ring", "--brand-text"] {
        let value = last_value(WEB_BASE_CSS, token);
        assert_eq!(
            last_value(BRAND_CSS, token),
            value,
            "{token} differs between the web vault and the admin pages"
        );
    }
}

#[tokio::test]
async fn the_branded_sheets_are_revalidated_and_other_files_are_the_kits() {
    let app = TestApp::new_at_real_time().await;
    let first = get(&app, "/static/style.css", None).await;
    let etag = first.header("etag").to_string();
    assert!(etag.starts_with('"') && etag.len() > 10, "{etag}");
    assert_eq!(first.header("cache-control"), "no-cache");
    let again = get(&app, "/static/style.css", Some(&etag)).await;
    assert_eq!(again.status, StatusCode::NOT_MODIFIED);
    // Another sheet has another tag.
    let shell = get(&app, "/static/shell.css", None).await;
    assert_ne!(shell.header("etag"), etag);
    // Everything else is the kit's file, byte for byte.
    let script = get(&app, "/static/app.js", None).await;
    let kit = vole_kit::http::assets::kit_file("app.js").expect("the kit has app.js");
    assert_eq!(script.body, kit.data.as_ref());
    assert_eq!(
        get(&app, "/static/nothing.css", None).await.status,
        StatusCode::NOT_FOUND
    );
}
