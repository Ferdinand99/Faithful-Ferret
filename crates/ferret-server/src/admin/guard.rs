//! The guard around the kit's pages on the admin listener: a request needs the
//! kit's signed cookie and Ferret's own session row, and both must agree. The
//! kit's cookie alone opens nothing.
//!
//! `server::admin_router` wraps only the kit's protected router in it. These
//! stay open: `/healthz`, `/static/`, the redirects of `admin::redirects`,
//! `/auth/handoff*`, `/api/auth/handoff/redeem` and `/api/auth/{logout,session}`.

use axum::extract::{Request, State};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};

use crate::error::ApiError;
use crate::state::FerretState;

/// Lets a request through when it has a full session on the admin origin. For
/// now it lets nothing through: a guard that is not built yet fails closed.
pub async fn admin_session_guard(
    State(_state): State<FerretState>,
    _request: Request,
    _next: Next,
) -> Response {
    ApiError::unauthorized().into_response()
}
