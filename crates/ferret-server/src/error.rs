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
use ferret_server_auth::AuthError;

/// Why the server could not start.
pub type StartError = Box<dyn std::error::Error + Send + Sync>;

/// A part that is not built yet: its stub returns this instead of panicking.
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
    /// The vault or account asked for is not there.
    NotFound,
    /// The caller passed values the store refuses (a bug in the caller, not
    /// something a client can cause).
    Invalid(&'static str),
    /// A stub was called.
    NotImplemented(NotImplemented),
}

impl fmt::Display for StoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            StoreError::Sql(e) => write!(f, "database error: {e}"),
            StoreError::Pool(e) => write!(f, "database pool error: {e}"),
            StoreError::NotFound => f.write_str("not found"),
            StoreError::Invalid(why) => write!(f, "invalid input: {why}"),
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

    /// The error for one of [`crate::wire::ERROR_CODES`], with the status that
    /// code always has ([`status_of`]).
    pub fn coded(code: &'static str) -> Self {
        Self::new(status_of(code), code)
    }
}

/// The status of every code in [`crate::wire::ERROR_CODES`]: the status is a
/// function of the code, so a code never travels with two statuses.
///
/// 400 is a request that is wrong in itself; 401, 403 and 429 are the answers
/// of the sign-in and the guards; 409 is a state that does not allow the call;
/// 410 is a feed cursor that is too old; 413 is a size or a quota; 422 is
/// content the server will not store.
pub const CODE_STATUS: &[(&str, StatusCode)] = &[
    ("unauthorized", StatusCode::UNAUTHORIZED),
    ("denied", StatusCode::UNAUTHORIZED),
    ("forbidden", StatusCode::FORBIDDEN),
    ("insecure_transport", StatusCode::BAD_REQUEST),
    ("handoff_invalid", StatusCode::BAD_REQUEST),
    ("manifest_not_writable", StatusCode::FORBIDDEN),
    ("malformed_registration_request", StatusCode::BAD_REQUEST),
    ("malformed_registration_record", StatusCode::BAD_REQUEST),
    ("malformed_ke1", StatusCode::BAD_REQUEST),
    ("malformed_ke3", StatusCode::BAD_REQUEST),
    ("malformed_login_id", StatusCode::BAD_REQUEST),
    ("malformed_nonce", StatusCode::BAD_REQUEST),
    ("malformed_proof", StatusCode::BAD_REQUEST),
    ("malformed_login_name", StatusCode::BAD_REQUEST),
    ("malformed_recovery_key", StatusCode::BAD_REQUEST),
    ("registration_closed", StatusCode::CONFLICT),
    ("throttled", StatusCode::TOO_MANY_REQUESTS),
    ("profile_rejected", StatusCode::UNPROCESSABLE_ENTITY),
    ("unsupported_envelope", StatusCode::UNPROCESSABLE_ENTITY),
    ("tombstone_invalid", StatusCode::UNPROCESSABLE_ENTITY),
    ("too_large", StatusCode::PAYLOAD_TOO_LARGE),
    ("quota_exceeded", StatusCode::PAYLOAD_TOO_LARGE),
    ("idem_reuse", StatusCode::UNPROCESSABLE_ENTITY),
    ("conflict", StatusCode::CONFLICT),
    ("protocol_header_missing", StatusCode::BAD_REQUEST),
    ("forbidden_origin", StatusCode::FORBIDDEN),
    ("not_found", StatusCode::NOT_FOUND),
    ("bad_request", StatusCode::BAD_REQUEST),
    ("internal", StatusCode::INTERNAL_SERVER_ERROR),
    ("gone", StatusCode::GONE),
];

/// The status of `code`. A code that is not in the table is a bug of the
/// caller and reads as 500.
pub fn status_of(code: &str) -> StatusCode {
    CODE_STATUS
        .iter()
        .find(|(listed, _)| *listed == code)
        .map_or(StatusCode::INTERNAL_SERVER_ERROR, |(_, status)| *status)
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
    /// A vault or account that is not there is 404 `not_found`; every other
    /// failure is 500 `internal`, and the cause goes to the log only.
    fn from(e: StoreError) -> Self {
        if matches!(e, StoreError::NotFound) {
            return Self::not_found();
        }
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
    /// The answer of `ferret-server-auth` for an error: code from the library,
    /// status from the code ([`status_of`]), and the wait of a throttle.
    fn from(e: AuthError) -> Self {
        let status = status_of(e.public_code());
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
    fn a_missing_vault_is_404_not_found_and_other_store_errors_are_500() {
        let missing = ApiError::from(StoreError::NotFound);
        assert_eq!(missing, ApiError::not_found());
        assert_eq!(missing.status, StatusCode::NOT_FOUND);
        assert_eq!(missing.code, "not_found");
        for other in [
            StoreError::Invalid("x"),
            StoreError::Pool("p".into()),
            StoreError::Sql(rusqlite::Error::QueryReturnedNoRows),
        ] {
            let api = ApiError::from(other);
            assert_eq!(api.status, StatusCode::INTERNAL_SERVER_ERROR);
            assert_eq!(api.code, "internal");
        }
    }

    #[test]
    fn every_code_has_exactly_one_status() {
        use crate::wire::ERROR_CODES;
        let mut listed: Vec<&str> = CODE_STATUS.iter().map(|(code, _)| *code).collect();
        let rows = listed.len();
        listed.sort_unstable();
        listed.dedup();
        assert_eq!(listed.len(), rows, "a code is in the table twice");
        let mut expected: Vec<&str> = ERROR_CODES.to_vec();
        expected.sort_unstable();
        assert_eq!(
            listed, expected,
            "the table and ERROR_CODES list the same codes"
        );
        for code in ERROR_CODES {
            let status = status_of(code);
            assert!(
                status.is_client_error() || *code == "internal",
                "{code} has status {status}"
            );
            assert_eq!(ApiError::coded(code).status, status, "{code}");
        }
        assert_eq!(
            status_of("tombstone_invalid"),
            StatusCode::UNPROCESSABLE_ENTITY
        );
        assert_eq!(status_of("gone"), StatusCode::GONE);
        // A code that is not listed is a bug of the caller, and reads as 500.
        assert_eq!(status_of("nope"), StatusCode::INTERNAL_SERVER_ERROR);
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
