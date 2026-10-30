//! The server's errors.
//!
//! * [`StartError`]: why the server could not start.
//! * [`ConfigError`]: a setting that is wrong.
//! * [`StoreError`]: a database call that failed (the vault modules see only
//!   this, never `rusqlite::Error` or a pool error).
//! * [`NotImplemented`]: what a stub returns. A stub never panics: with
//!   `panic = "abort"` a panic would end both listeners.
//! * [`ApiError`]: an answer to the client, `{"error":"<code>"}` with a stable
//!   code (`wire::ERROR_CODES`). It never carries a cause, a path or a value
//!   from the request.

use std::fmt;

use axum::Json;
use axum::http::{HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use ferret_server_auth::{AuthError, ErrorClass};

/// Why the server could not start.
pub type StartError = Box<dyn std::error::Error + Send + Sync>;

/// A part that a later step of the milestone builds: its stub returns this
/// instead of panicking.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NotImplemented(pub &'static str);

impl fmt::Display for NotImplemented {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} is not implemented yet", self.0)
    }
}

impl std::error::Error for NotImplemented {}

/// A setting that is wrong. The text names the setting and says what to fix.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfigError(pub String);

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for ConfigError {}

/// A database call that failed.
#[derive(Debug)]
pub enum StoreError {
    /// SQLite said no.
    Sql(rusqlite::Error),
    /// No connection could be had, or the task that held it failed.
    Pool(String),
    /// A stub was called.
    NotImplemented(NotImplemented),
}

impl fmt::Display for StoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            StoreError::Sql(e) => write!(f, "database error: {e}"),
            StoreError::Pool(e) => write!(f, "database pool error: {e}"),
            StoreError::NotImplemented(e) => e.fmt(f),
        }
    }
}

impl std::error::Error for StoreError {}

impl From<rusqlite::Error> for StoreError {
    fn from(e: rusqlite::Error) -> Self {
        StoreError::Sql(e)
    }
}

impl From<deadpool_sqlite::PoolError> for StoreError {
    fn from(e: deadpool_sqlite::PoolError) -> Self {
        StoreError::Pool(e.to_string())
    }
}

impl From<deadpool_sqlite::InteractError> for StoreError {
    fn from(e: deadpool_sqlite::InteractError) -> Self {
        StoreError::Pool(e.to_string())
    }
}

impl From<NotImplemented> for StoreError {
    fn from(e: NotImplemented) -> Self {
        StoreError::NotImplemented(e)
    }
}

/// An answer to the client: a status and a stable code.
///
/// The body is `{"error":"<code>"}` and nothing else. Causes go to the log, by
/// the code that has them, and never into the answer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApiError {
    /// The HTTP status.
    pub status: StatusCode,
    /// The stable code of the body.
    pub code: &'static str,
    /// Seconds for the `Retry-After` header, for a throttle.
    pub retry_after: Option<u32>,
}

impl ApiError {
    /// An error with this status and code.
    pub const fn new(status: StatusCode, code: &'static str) -> Self {
        Self {
            status,
            code,
            retry_after: None,
        }
    }

    /// 401 `unauthorized`: the one answer for every reason a session does not
    /// count (no cookie, one cookie, a revoked row, the wrong origin, …).
    pub const fn unauthorized() -> Self {
        Self::new(StatusCode::UNAUTHORIZED, "unauthorized")
    }

    /// 403 `forbidden_origin`.
    pub const fn forbidden_origin() -> Self {
        Self::new(StatusCode::FORBIDDEN, "forbidden_origin")
    }

    /// 404 `not_found`.
    pub const fn not_found() -> Self {
        Self::new(StatusCode::NOT_FOUND, "not_found")
    }

    /// 400 with the given code.
    pub const fn bad_request(code: &'static str) -> Self {
        Self::new(StatusCode::BAD_REQUEST, code)
    }

    /// 500 `internal`.
    pub const fn internal() -> Self {
        Self::new(StatusCode::INTERNAL_SERVER_ERROR, "internal")
    }

    /// 429 `throttled` with a wait.
    pub const fn throttled(retry_after_secs: u32) -> Self {
        Self {
            status: StatusCode::TOO_MANY_REQUESTS,
            code: "throttled",
            retry_after: Some(retry_after_secs),
        }
    }
}

impl fmt::Display for ApiError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.code)
    }
}

impl std::error::Error for ApiError {}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let mut response =
            (self.status, Json(serde_json::json!({ "error": self.code }))).into_response();
        let headers = response.headers_mut();
        headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
        if let Some(secs) = self.retry_after
            && let Ok(value) = HeaderValue::from_str(&secs.to_string())
        {
            headers.insert(header::RETRY_AFTER, value);
        }
        response
    }
}

impl From<StoreError> for ApiError {
    fn from(e: StoreError) -> Self {
        tracing::error!(error = %e, "store call failed");
        Self::internal()
    }
}

impl From<NotImplemented> for ApiError {
    fn from(e: NotImplemented) -> Self {
        tracing::error!(error = %e, "stub called");
        Self::internal()
    }
}

impl From<AuthError> for ApiError {
    /// The answer of `ferret-server-auth` for an error: status from the class,
    /// code from the library, and the wait of a throttle.
    fn from(e: AuthError) -> Self {
        let status = match e.http_class() {
            ErrorClass::BadRequest => StatusCode::BAD_REQUEST,
            ErrorClass::Denied => StatusCode::UNAUTHORIZED,
            ErrorClass::Forbidden => StatusCode::FORBIDDEN,
            ErrorClass::TooManyRequests => StatusCode::TOO_MANY_REQUESTS,
            _ => StatusCode::INTERNAL_SERVER_ERROR,
        };
        let retry_after = match e {
            AuthError::Throttled { retry_after_secs } => Some(retry_after_secs),
            _ => None,
        };
        Self {
            status,
            code: e.public_code(),
            retry_after,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_body_is_the_code_and_nothing_else() {
        let response = ApiError::unauthorized().into_response();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
    }

    #[test]
    fn a_throttle_carries_its_wait() {
        let response = ApiError::from(AuthError::Throttled {
            retry_after_secs: 7,
        })
        .into_response();
        assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(response.headers()[header::RETRY_AFTER], "7");
    }
}
