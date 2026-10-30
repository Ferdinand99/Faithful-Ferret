//! The state both listeners share, and the narrow handles that parts of it are
//! handed out as.
//!
//! One [`FerretState`] is built at start-up ([`build_state`]) and cloned into
//! both routers, so the two listeners share the pool, the clock, the login
//! states and the throttles. Code that needs only a part of it takes that part
//! through `FromRef`: the vault modules see a [`VaultDb`] and never the kit's
//! `Core` or its cookie key (the session extractors of `http::extract` are the
//! one place that holds the key).

use std::sync::{Arc, RwLock};

use axum::extract::FromRef;
use axum_extra::extract::cookie::Key;
use deadpool_sqlite::Pool;
use ferret_server_auth::{Clock, PreloginPolicy, Throttle};
use rusqlite::Connection;
use vole_kit::state::Core;

use crate::auth::secrets::{Secrets, load_secrets};
use crate::auth::state_store::SqliteLoginStateStore;
use crate::auth::throttle::KitThrottle;
use crate::auth::{handoff, login, state_store};
use crate::config::{Config, Origins};
use crate::error::{StartError, StoreError};
use crate::http::extract::SessionAuth;
use crate::http::proxy_guard::ProxyList;
use crate::product;

/// The database, as the vault modules see it: a pool and one way to use it.
#[derive(Clone)]
pub struct VaultDb {
    pool: Pool,
}

impl VaultDb {
    /// Wraps the pool.
    pub fn new(pool: Pool) -> Self {
        Self { pool }
    }

    /// Runs `f` on a pooled connection on a blocking thread. Every failure to
    /// get or use the connection is a [`StoreError`].
    pub async fn with_conn<T, F>(&self, f: F) -> Result<T, StoreError>
    where
        F: FnOnce(&mut Connection) -> Result<T, StoreError> + Send + 'static,
        T: Send + 'static,
    {
        let conn = self.pool.get().await?;
        conn.interact(f).await?
    }
}

/// Everything the two routers share.
#[derive(Clone)]
pub struct FerretState {
    /// The kit's state: pool, cookie key, throttles of the kit's own pages.
    pub core: Core,
    /// The database, for the vault modules.
    pub vault_db: VaultDb,
    /// The configured public origins of the two listeners.
    pub origins: Origins,
    /// The only source of time: a test moves it by hand.
    pub clock: Arc<dyn Clock>,
    /// The proxies whose forwarding headers are believed.
    pub proxies: Arc<ProxyList>,
    /// The OPAQUE set-up, the pre-login secret and the key that seals login
    /// states.
    pub secrets: Arc<Secrets>,
    /// The rate limits the OPAQUE library asks.
    pub throttle: Arc<dyn Throttle>,
    /// Where sealed login states wait between the two sign-in steps.
    pub login_states: Arc<SqliteLoginStateStore>,
    /// How the made-up answers for unknown names are spread; renewed in the
    /// background from the real accounts.
    pub prelogin: Arc<RwLock<PreloginPolicy>>,
}

impl FromRef<FerretState> for Core {
    fn from_ref(state: &FerretState) -> Core {
        state.core.clone()
    }
}

impl FromRef<FerretState> for Key {
    fn from_ref(state: &FerretState) -> Key {
        state.core.session_key.clone()
    }
}

impl FromRef<FerretState> for VaultDb {
    fn from_ref(state: &FerretState) -> VaultDb {
        state.vault_db.clone()
    }
}

impl FromRef<FerretState> for Origins {
    fn from_ref(state: &FerretState) -> Origins {
        state.origins.clone()
    }
}

impl FromRef<FerretState> for Arc<ProxyList> {
    fn from_ref(state: &FerretState) -> Arc<ProxyList> {
        state.proxies.clone()
    }
}

impl FromRef<FerretState> for Arc<dyn Clock> {
    fn from_ref(state: &FerretState) -> Arc<dyn Clock> {
        state.clock.clone()
    }
}

impl FromRef<FerretState> for SessionAuth {
    fn from_ref(state: &FerretState) -> SessionAuth {
        SessionAuth {
            key: state.core.session_key.clone(),
            db: state.vault_db.clone(),
            clock: state.clock.clone(),
        }
    }
}

/// Starts the background jobs: purging login states, renewing the pre-login
/// policy and purging hand-over codes. Call it once, inside the runtime.
pub fn spawn_background(state: &FerretState) {
    state_store::spawn_purge(state.login_states.clone(), state.clock.clone());
    login::spawn_prelogin_refresh(
        state.vault_db.clone(),
        state.prelogin.clone(),
        state.clock.clone(),
    );
    handoff::spawn_purge(state.vault_db.clone(), state.clock.clone());
}

/// Builds the state from the kit's `Core` (whose database is migrated) and the
/// configuration: the origins and the proxy list are checked, the secrets are
/// loaded and checked against the database, and the login state store is
/// opened.
///
/// Fails, and so refuses to serve, when any of that is wrong.
pub async fn build_state(
    core: Core,
    cfg: &Config,
    clock: Arc<dyn Clock>,
) -> Result<FerretState, StartError> {
    let origins = Origins::parse(&cfg.vault_url, &cfg.admin_url)?;
    let proxies = Arc::new(ProxyList::parse(&cfg.trusted_proxies)?);
    let vault_db = VaultDb::new(core.db.clone());

    let data_dir = cfg.data_dir.clone();
    let conn = core.db.get().await?;
    let loaded = conn
        .interact(move |conn| load_secrets(&data_dir, conn))
        .await
        .map_err(|e| e.to_string())?;
    let secrets = Arc::new(loaded?);
    drop(conn);

    let login_states = Arc::new(SqliteLoginStateStore::open(
        &cfg.data_dir.join(product::DB_FILE),
    )?);
    let prelogin = vault_db
        .with_conn(|conn| Ok(login::load_prelogin_policy(conn)))
        .await?;
    let throttle: Arc<dyn Throttle> = Arc::new(KitThrottle::new(clock.clone()));

    Ok(FerretState {
        core,
        vault_db,
        origins,
        clock,
        proxies,
        secrets,
        throttle,
        login_states,
        prelogin: Arc::new(RwLock::new(prelogin)),
    })
}
