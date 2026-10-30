//! The two routers and the process that serves them.
//!
//! The vault listener and the admin listener share one [`FerretState`] but
//! serve different routes, chosen by which listener (port) a request came in on
//! and never by its `Host` header:
//!
//! * the vault router: the vault API, the OPAQUE routes and the files of the
//!   web vault; nothing of the kit's pages;
//! * the admin router: the kit's pages behind the admin session guard, Ferret's
//!   own open routes (redirects, hand-over, sign-out); nothing of the vault.

use std::net::SocketAddr;
use std::sync::Arc;

use axum::Router;
use axum::extract::State;
use axum::middleware::{from_fn, from_fn_with_state};
use axum::routing::get;
use ferret_server_auth::{Clock, SystemClock};
use vole_kit::auth::{guard, pages as kit_pages};

use crate::config::Config;
use crate::error::{ApiError, StartError, StoreError};
use crate::state::{FerretState, VaultDb, spawn_background};
use crate::{admin, auth, http, vault};

/// `GET /healthz` on both listeners: `ok` when the database answers.
async fn healthz(State(db): State<VaultDb>) -> Result<&'static str, ApiError> {
    db.with_conn(|conn| {
        conn.query_row("SELECT 1", [], |row| row.get::<_, i64>(0))
            .map_err(StoreError::from)
    })
    .await?;
    Ok("ok")
}

/// The answer of the vault listener to a path it does not serve.
async fn not_found() -> ApiError {
    ApiError::not_found()
}

/// The vault listener: `vault::routes()`, `auth::routes_vault()` and the files
/// of the web vault, with the vault layers around them.
pub fn vault_router(state: FerretState) -> Router {
    let routes: Router<FerretState> = Router::new()
        .route("/healthz", get(healthz))
        .merge(vault::routes())
        .merge(auth::routes_vault())
        .merge(http::static_files::vault_routes(
            http::static_files::default_source(),
        ))
        .fallback(not_found);
    http::vault_layers(routes.with_state(state.clone()), &state)
}

/// The admin listener: the kit's pages behind [`admin::guard::admin_session_guard`]
/// (and the kit's own `require_auth`), and Ferret's open routes beside them.
///
/// Only the kit's protected router has the guard. These stay open: `/healthz`,
/// `/static/`, the redirects, `/auth/handoff*`, `/api/auth/handoff/redeem`
/// and `/api/auth/{logout,session}`, and the kit's sign-in pages (which lead on
/// to the redirects).
pub fn admin_router(state: FerretState) -> Router {
    let core = state.core.clone();
    let kit_protected: Router<FerretState> = Router::new()
        .merge(kit_pages::router())
        .route_layer(from_fn_with_state(core.clone(), guard::require_auth))
        .route_layer(from_fn_with_state(
            state.clone(),
            admin::guard::admin_session_guard,
        ));
    let open: Router<FerretState> = Router::new()
        .route("/healthz", get(healthz))
        .route("/static/{*path}", get(vole_kit::http::assets::static_asset))
        .merge(admin::routes())
        .merge(auth::routes_admin())
        .merge(kit_pages::public_router());
    let app = kit_protected
        .merge(open)
        .fallback(vole_kit::http::error::not_found)
        .with_state(state.clone())
        .layer(from_fn_with_state(core.clone(), guard::csrf_guard))
        .layer(from_fn_with_state(core, vole_kit::i18n::layer))
        .layer(from_fn(vole_kit::http::error::negotiate))
        .layer(from_fn(vole_kit::http::headers::security_headers));
    http::admin_layers(app, &state)
}

/// Sets the core dump size to 0, soft and hard limit: a crash must not write
/// the memory of the process (keys, session secrets) to disk. A no-op where
/// there is no such limit.
pub fn disable_core_dumps() -> Result<(), StartError> {
    #[cfg(unix)]
    {
        use rustix::process::{Resource, Rlimit, setrlimit};
        setrlimit(
            Resource::Core,
            Rlimit {
                current: Some(0),
                maximum: Some(0),
            },
        )
        .map_err(|e| format!("can't turn core dumps off: {e}"))?;
    }
    Ok(())
}

/// The clock the server runs on: the system clock, or in the end-to-end image
/// (cargo feature `e2e-clock`) the system clock plus the offset in the file
/// named by `FERRET_E2E_CLOCK_FILE`.
fn process_clock() -> Arc<dyn Clock> {
    #[cfg(feature = "e2e-clock")]
    if let Some(clock) = crate::e2e_clock::from_env() {
        tracing::warn!(
            file = %clock.path().display(),
            "TEST BUILD: the clock is moved by the offset in a file"
        );
        return Arc::new(clock);
    }
    Arc::new(SystemClock)
}

/// Starts the server with `config` and serves both listeners until Ctrl-C or
/// SIGTERM, then lets the requests in flight finish.
pub async fn run(config: Config) -> Result<(), StartError> {
    disable_core_dumps()?;
    // Every TLS stack in the binary uses rustls; pin its crypto provider so a
    // dependency enabling a second one can't make rustls panic at runtime.
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    if config.vault_port == config.admin_port {
        return Err("the vault port and the admin port must differ".into());
    }
    let clock = process_clock();
    let state = crate::start(&config, clock).await?;
    // Notifications and other work outside a request use the site language.
    vole_kit::i18n::site_language(&state.core).await;
    spawn_background(&state);

    let vault_listener = bind(config.vault_addr()).await?;
    let admin_listener = bind(config.admin_addr()).await?;
    tracing::info!(
        version = crate::VERSION,
        data_dir = %config.data_dir.display(),
        "Faithful Ferret: vault on http://{}, admin on http://{}",
        config.vault_addr(),
        config.admin_addr()
    );

    let (stop_tx, stop_rx) = tokio::sync::watch::channel(false);
    let stopped = move || {
        let mut rx = stop_rx.clone();
        async move {
            let _ = rx.wait_for(|stop| *stop).await;
        }
    };
    // Connect info lets the proxy guard and the throttles see the peer address.
    let vault = axum::serve(
        vault_listener,
        vault_router(state.clone()).into_make_service_with_connect_info::<SocketAddr>(),
    )
    .with_graceful_shutdown(stopped());
    let admin = axum::serve(
        admin_listener,
        admin_router(state).into_make_service_with_connect_info::<SocketAddr>(),
    )
    .with_graceful_shutdown(stopped());
    tokio::spawn(async move {
        shutdown_signal().await;
        let _ = stop_tx.send(true);
    });
    let (a, b) = tokio::join!(vault, admin);
    a?;
    b?;
    tracing::info!("stopped");
    Ok(())
}

async fn bind(addr: SocketAddr) -> Result<tokio::net::TcpListener, StartError> {
    Ok(tokio::net::TcpListener::bind(addr)
        .await
        .map_err(|e| format!("can't listen on {addr}: {e}"))?)
}

async fn shutdown_signal() {
    let ctrl_c = async {
        if let Err(err) = tokio::signal::ctrl_c().await {
            tracing::warn!(%err, "can't listen for Ctrl-C");
            std::future::pending::<()>().await;
        }
    };
    #[cfg(unix)]
    let terminate = async {
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(mut sig) => {
                sig.recv().await;
            }
            Err(err) => {
                tracing::warn!(%err, "can't listen for SIGTERM");
                std::future::pending::<()>().await;
            }
        }
    };
    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        () = ctrl_c => {},
        () = terminate => {},
    }
    tracing::info!("shutting down");
}
