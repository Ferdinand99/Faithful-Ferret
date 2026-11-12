//! The product's configuration as vole-kit reads it.

mod support;

use axum::http::StatusCode;
use ferret_server::product::{self, KIT};
use support::handoff::admin_user;
use support::{Req, TestApp, Which};
use vole_kit::config::{CredentialMode, KitConfig};
use vole_kit::db::migrate::{CORE, MigrationSet, SIGN_IN_CODES};

#[test]
fn kit_config_is_valid() {
    // `install` also checks the translations; `check` is the rest.
    product::install();
    assert_eq!(vole_kit::config::check(&KIT), Ok(()));
}

#[test]
fn session_cookie_is_host_prefixed() {
    // `__Host-` needs Secure, Path=/ and no Domain, and the browser then keeps
    // the cookie to the exact host: the vault and the admin origin cannot see
    // each other's. The kit's second-factor cookie is held to the same rule.
    assert_eq!(KIT.session_cookie, "__Host-ferret_session");
    assert_eq!(KIT.pending_2fa_cookie, "__Host-ferret_2fa");
    assert_eq!(product::SID_COOKIE, "__Host-ferret_sid");
    for name in [
        KIT.session_cookie,
        KIT.pending_2fa_cookie,
        product::SID_COOKIE,
    ] {
        assert!(name.starts_with("__Host-"), "{name}");
    }
}

#[test]
fn env_prefix_is_ferret() {
    assert_eq!(KIT.env_prefix, "FERRET");
    assert_eq!(KIT.slug, "faithful-ferret");
    assert_eq!(KIT.token_prefix, "ff_");
    assert_eq!(KIT.backup_prefix, "ferret-before-");
    assert_eq!(KIT.product, "Faithful Ferret");
}

#[test]
fn the_kit_takes_no_password_and_the_optional_parts_are_off_except_sign_in_codes() {
    assert!(matches!(
        KIT.features.credentials,
        CredentialMode::External(_)
    ));
    assert!(!KIT.features.api_tokens);
    assert!(!KIT.features.api_docs);
    assert!(!KIT.features.invites);
    assert!(KIT.features.sign_in_codes);
    assert_eq!(product::EXTERNAL.login_path, "/vault/login");
    assert_eq!(product::EXTERNAL.setup_path, "/vault/setup");
    assert_eq!(product::EXTERNAL.password_path, "/vault/password");
    assert_eq!(product::EXTERNAL.reauth_path, "/vault/reauth");
}

#[test]
fn kit_config_accepts_sign_in_codes_with_its_migration() {
    product::install();
    // The feature is on, and the kit's migration for its tables is in the core
    // set that this server runs, after everything that the kit's own core set
    // holds.
    assert!(KIT.features.sign_in_codes);
    let core = KIT.migrations.core;
    assert!(core.iter().any(|(name, _)| *name == SIGN_IN_CODES.0));
    assert_eq!(core.last().map(|(name, _)| *name), Some(SIGN_IN_CODES.0));
    assert_eq!(&core[..CORE.len()], CORE, "the kit's core set is all there");
    assert_eq!(vole_kit::config::check(&KIT), Ok(()));

    // The kit refuses the same configuration without that migration.
    fn no_migrations() -> Vec<(String, String)> {
        Vec::new()
    }
    fn no_fixups(
        _: &mut rusqlite::Connection,
    ) -> Result<(), vole_kit::db::migrate::MigrationError> {
        Ok(())
    }
    static WITHOUT: MigrationSet = MigrationSet {
        core: CORE,
        adopt_core: None,
        migrations: no_migrations,
        fk_off_marker: "-- ff:foreign_keys=off",
        baseline: None,
        after: no_fixups,
    };
    let without = KitConfig {
        migrations: &WITHOUT,
        ..KIT
    };
    let refused = vole_kit::config::check(&without).expect_err("the tables are missing");
    assert!(refused.contains("sign-in codes need"), "{refused}");
}

#[tokio::test]
async fn the_general_page_shows_no_smtp_form_or_says_no_mail_is_sent() {
    let app = TestApp::new_at_real_time().await;
    admin_user(&app, 1).await;
    let res = app
        .call(Which::Admin, Req::get("/settings/general").build())
        .await;
    assert_eq!(res.status, StatusCode::OK, "{}", res.text());
    let page = res.text();
    // The kit cannot hide its mail form, so the page has to say that no mail is
    // sent when the form is there.
    let has_smtp_form = page.contains("name=\"smtp_host\"");
    let says_no_mail = page.contains("sends no email in this version");
    assert!(!has_smtp_form || says_no_mail, "{page}");
    assert!(says_no_mail, "the page says that no mail is sent");
    assert!(page.contains("Not sent"), "the one value of the field");
}
