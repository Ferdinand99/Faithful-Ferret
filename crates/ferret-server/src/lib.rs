//! The Faithful Ferret server.
//!
//! A vole-kit app, like Keen Kestrel and Wise Wren, in the kit's mode for
//! products that check credentials themselves (`CredentialMode::External`).
//! The kit owns users, sessions, two-factor sign-in, invitations and the admin
//! pages. This crate owns the OPAQUE sign-in, the vault API and the web vault.
//!
//! # Two listeners, two origins
//!
//! The vault listener serves the web vault, the sign-in, setup, re-auth and
//! password pages, the WASM package and the vault API, all on one origin. The
//! master password is typed there and nowhere else. The admin listener serves
//! the kit's admin pages and nothing else; it never has a password field and
//! never loads WASM. A session is handed from the vault origin to the admin
//! origin with a one-time code (`auth::handoff`). Routing is by listener, not
//! by `Host` header: see [`server`].
//!
//! # What is where
//!
//! * [`product`]: what makes this build Faithful Ferret as far as the kit goes.
//! * [`state`]: the shared state and its narrow handles; [`server`]: the two
//!   routers and `run`.
//! * [`vault`]: the vault modules. They see only a [`state::VaultDb`] (and
//!   other narrow handles) through `FromRef`, never the kit's cookie key or its
//!   core state. `tests/arch.rs` checks this by name.
//! * [`auth`]: registration, sign-in, sessions, the hand-over to the admin
//!   origin. [`http`]: the layers (proxy trust, `Origin` check, headers),
//!   static files and extractors. [`admin`]: the admin listener's own routes.
//! * [`wire`]: the JSON shapes shared with the web vault.
//!
//! Many modules are still stubs: each has its documentation and, where it has
//! routes, a `routes()` that serves nothing yet.

#![forbid(unsafe_code)]

pub mod admin;
pub mod auth;
pub mod backup;
pub mod config;
pub mod db;
pub mod error;
pub mod http;
pub mod ids;
pub mod product;
pub mod secret;
pub mod server;
pub mod state;
pub mod vault;
pub mod wire;

use std::sync::Arc;

use ferret_server_auth::Clock;
use vole_kit::db::settings;
use vole_kit::state::Core;

pub use error::StartError;
pub use product::{VERSION, install};
pub use state::{FerretState, VaultDb, build_state, spawn_background};

use config::Config;

/// Installs the kit configuration, opens and migrates the database in
/// `config.data_dir` and returns the state of a server that is ready to serve.
///
/// The kit's own setting for the public URL (its same-origin checks, the
/// `Secure` flag of its cookies) is the admin origin: the kit's pages are the
/// ones on that listener.
pub async fn start(config: &Config, clock: Arc<dyn Clock>) -> Result<FerretState, StartError> {
    install();
    std::fs::create_dir_all(&config.data_dir).map_err(|e| {
        format!(
            "can't create the data directory {}: {e}",
            config.data_dir.display()
        )
    })?;
    let pool = vole_kit::db::build_pool(&config.data_dir.join(product::DB_FILE));
    let report = vole_kit::db::migrate(&pool, &config.data_dir.join("backups")).await?;
    if !report.applied.is_empty() {
        tracing::info!(applied = ?report.applied, "database migrated");
    }
    let http = reqwest::Client::builder()
        .user_agent(product::USER_AGENT)
        .build()?;
    let core = Core::new(
        pool,
        vole_kit::auth::load_or_create_key(&config.data_dir),
        http,
        &product::KIT,
    );
    let admin_url = config::Origins::parse(&config.vault_url, &config.admin_url)?
        .admin()
        .to_string();
    core.with_conn(move |c| settings::set(c, settings::BASE_URL, &admin_url))
        .await?;
    build_state(core, config, clock).await
}
