//! The product's configuration as vole-kit reads it.

use ferret_server::product::{self, KIT};
use vole_kit::config::CredentialMode;

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
fn the_kit_takes_no_password_and_the_optional_parts_are_off() {
    assert!(matches!(
        KIT.features.credentials,
        CredentialMode::External(_)
    ));
    assert!(!KIT.features.api_tokens);
    assert!(!KIT.features.api_docs);
    assert!(!KIT.features.invites);
    assert!(!KIT.features.sign_in_codes);
    assert_eq!(product::EXTERNAL.login_path, "/vault/login");
    assert_eq!(product::EXTERNAL.setup_path, "/vault/setup");
    assert_eq!(product::EXTERNAL.password_path, "/vault/password");
    assert_eq!(product::EXTERNAL.reauth_path, "/vault/reauth");
}
