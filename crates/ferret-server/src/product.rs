//! What makes this build Faithful Ferret as far as vole-kit is concerned:
//! names, cookies, token prefix, migrations, translations, the admin
//! navigation and which parts of the kit are on.
//!
//! The kit runs with `CredentialMode::External`: it never asks for a password.
//! Its sign-in, setup, password and re-auth pages lead to [`EXTERNAL`], the
//! paths of the vault origin. On the admin listener those paths are redirects
//! to the vault origin that start the hand-over of a session (`admin::redirects`).

use rust_embed::Embed;
use vole_kit::config::{CredentialMode, ExternalCredentials, KitConfig, KitFeatures};
use vole_kit::docs::{DocsSpec, RouteDoc};
use vole_kit::http::assets::StaticFile;
use vole_kit::notify::webhook::Wording;
use vole_kit::page::{NavItem, SettingsTab, Ui};
use vole_kit::settings::GeneralSettings;

/// The product's version (`CARGO_PKG_VERSION`), reported by the OpenAPI
/// document and the MCP server.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
/// The product's name.
pub const NAME: &str = "Faithful Ferret";
/// `User-Agent` of outgoing requests.
pub const USER_AGENT: &str = concat!("FaithfulFerret/", env!("CARGO_PKG_VERSION"));
/// Name of the signed session cookie of the kit.
pub const SESSION_COOKIE: &str = "__Host-ferret_session";
/// Name of the kit's cookie between password and second factor.
pub const PENDING_2FA_COOKIE: &str = "__Host-ferret_2fa";
/// Name of the cookie that holds the random session id of Ferret's own session
/// (`ferret_sessions`), next to the kit's signed cookie.
pub const SID_COOKIE: &str = "__Host-ferret_sid";
/// The database file in the data directory.
pub const DB_FILE: &str = "ferret.sqlite";

/// Where the kit sends people for the passwords it does not take. Paths of the
/// vault origin; the admin listener redirects them there.
pub static EXTERNAL: ExternalCredentials = ExternalCredentials {
    login_path: "/vault/login",
    setup_path: "/vault/setup",
    password_path: "/vault/password",
    reauth_path: "/vault/reauth",
};

/// The kit's optional parts. The milestones that need invitations and sign-in
/// codes switch them on.
pub static FEATURES: KitFeatures = KitFeatures {
    api_tokens: false,
    api_docs: false,
    credentials: CredentialMode::External(&EXTERNAL),
    invites: false,
    sign_in_codes: false,
};

/// Ferret's own static files for the admin pages: icons and the web app
/// manifest. The design system (stylesheet, scripts, icon sprite, fonts) is
/// the kit's. The web vault's files are not these: they come from `web/dist`.
#[derive(Embed)]
#[folder = "static/"]
struct StaticAssets;

/// Looks up one of Ferret's static files (for the kit's `/static/` handler).
pub fn static_file(path: &str) -> Option<StaticFile> {
    let file = StaticAssets::get(path)?;
    Some(StaticFile {
        sha256: file.metadata.sha256_hash(),
        data: file.data,
    })
}

fn no_markdown(_: &mut String) {}
fn no_intro(_: &mut String, _: &str) {}
fn no_param(_: &RouteDoc, _: &str) -> Option<String> {
    None
}

/// The API reference is off (`FEATURES.api_docs`); the kit still wants one.
pub static DOCS: DocsSpec = DocsSpec {
    routes: &[],
    openapi_title: "Faithful Ferret API",
    openapi_description: "The Faithful Ferret API is not documented here.",
    bearer_description: "API token (ff_…)",
    credentials: &[],
    error_example: r#"{"error": "unauthorized"}"#,
    error_codes: &[],
    config_document: None,
    curl_path_param: no_param,
    markdown_intro: no_intro,
    markdown_middle: no_markdown,
    markdown_outro: no_markdown,
    page_subtitle: "api.docs_subtitle",
    openapi_path: "/api/v1/openapi.json",
    api_base: "/api/v1",
    example_path: "/api/v1/status",
    metrics_path: None,
    fallback_host: Some("localhost:3040"),
    param_types: &[],
    strict_access: false,
};

pub static KIT: KitConfig = KitConfig {
    product: NAME,
    slug: "faithful-ferret",
    short_name: "Ferret",
    session_cookie: SESSION_COOKIE,
    pending_2fa_cookie: PENDING_2FA_COOKIE,
    token_prefix: "ff_",
    other_token_prefixes: &[],
    version: VERSION,
    user_agent: USER_AGENT,
    backup_prefix: "ferret-before-",
    flash_cookie: "ferret_flash",
    env_prefix: "FERRET",
    // The vault API takes no tokens before the device tokens of a later
    // milestone, and the origin check of `http::origin_guard` replaces the
    // kit's CSRF guard there; the admin pages keep the kit's guard.
    csrf_exempt_prefixes: &[],
    csrf_exempt_path: no_exempt_path,
    extra_common_passwords: &["faithfulferret", "ferret1234"],
    migrations: &crate::db::MIGRATIONS,
    embeddable_prefixes: &[],
    static_file,
    machine_path_prefixes: &["/static/", "/api/"],
    machine_paths: &["/healthz"],
    browser_language_prefixes: &[],
    docs: &DOCS,
    locales: &[
        ("en", include_str!("../locales/en.toml")),
        ("nb", include_str!("../locales/nb.toml")),
    ],
    ui: &Ui {
        logo: "/static/favicon.svg",
        favicon: "/static/favicon.svg",
        apple_touch_icon: "/static/apple-touch-icon.png",
        manifest: "/static/site.webmanifest",
        nav: &[NavItem {
            id: "settings",
            href: "/settings",
            label: "nav.settings",
            short_label: "nav.settings",
            icon: "gear",
        }],
        settings_tabs: &[
            SettingsTab::GENERAL,
            SettingsTab::USERS,
            SettingsTab::SECURITY,
        ],
        home_url: "https://hedgerow.tools/Faithful-Ferret/",
    },
    // Set on the General page.
    public_url_setting: Some("Settings → General"),
    webhook: Wording {
        subject: "subject",
        duration: "duration",
        url_example: "https://example.com/hooks/ferret…",
    },
    token_scopes: &[],
    // Site name, public URL, time zone and language.
    general: Some(&GeneralSettings::CORE_ONLY),
    // The signed-in footer links the running version to its release notes.
    releases_url: Some("https://github.com/Ferdinand99/Faithful-Ferret/releases/tag/v{version}"),
    features: &FEATURES,
};

/// Every exempt path is a prefix above (there are none).
fn no_exempt_path(_: &str) -> bool {
    false
}

/// Installs [`KIT`]. Call it first thing at start-up, and in test set-up.
pub fn install() {
    vole_kit::config::install(&KIT);
}
