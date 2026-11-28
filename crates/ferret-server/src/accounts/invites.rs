//! Invitations: how a person who was given a link makes an account.
//!
//! An administrator makes an invitation on the Users page; the kit stores the
//! SHA-256 of its token (`invites`, `kit/0007_invites.sql`) and the page shows
//! the link [`link`] once. The token travels in the fragment of the link, so it
//! never reaches a server log or a `Referer`. The web vault reads it from the
//! fragment and hands it to two routes:
//!
//! * `POST /api/auth/invite/check {invite}` ([`routes`]): `200 {expires_at,
//!   invited_by}` for a pending invitation, else `403 invite_invalid`, the same
//!   answer for a token that is unknown, used, revoked, run out or of another
//!   role than [`INVITED_ROLE`]. At most [`CHECKS_PER_ADDRESS`] per address per
//!   minute (`auth::throttle::InviteCheckLimit`). It changes nothing.
//! * `register/start {.., invite}` and `register/finish` (`auth::register`),
//!   which make the account and spend the invitation in one transaction.
//!
//! A start with an invitation that [`pending`] found is counted against that
//! invitation ([`InviteStarts`], [`STARTS_PER_INVITE`] per
//! [`STARTS_WINDOW_SECS`]): only such a start can be told that its e-mail
//! has an account (`409 email_taken`, the deliberate deviation of § 4.2), so
//! the count caps that answer. A made-up token never enters the count.
//!
//! The token itself is never kept, logged or compared as text: it is hashed
//! (`vole_kit::auth::invites::hash`) and the hash is looked up.
//!
//! Spec: Fase 1 § 4.2 ("Registration with an invitation"), § 11 (invitations
//! and the limits).

use std::fmt;
use std::net::SocketAddr;

use axum::Json;
use axum::Router;
use axum::extract::{ConnectInfo, FromRef, FromRequest as _, Request, State};
use axum::http::HeaderValue;
use axum::http::header::CACHE_CONTROL;
use axum::response::{IntoResponse as _, Response};
use axum::routing::post;
use ferret_server_auth::RetryAfter;
use rusqlite::Connection;
use time::{Date, Month, PrimitiveDateTime, Time};
use vole_kit::db::role::Role;

use crate::auth::register::ApiJson;
use crate::auth::throttle::{WindowLimit, caller_from};
use crate::config::Origins;
use crate::error::ApiError;
use crate::state::FerretState;
use crate::wire::{InviteCheckReq, InviteCheckRes};

/// The role every invited account gets. The Users page offers no other, and
/// an invitation of another role (one the kit's own page made) is refused.
pub const INVITED_ROLE: Role = Role::Viewer;

/// The starts one invitation may make per [`STARTS_WINDOW_SECS`].
pub const STARTS_PER_INVITE: usize = 10;

/// The window of [`STARTS_PER_INVITE`]: an hour.
pub const STARTS_WINDOW_SECS: u64 = 3_600;

/// The checks of an invitation one address may make per minute.
pub const CHECKS_PER_ADDRESS: usize = 10;

/// The path of the check.
pub const CHECK_PATH: &str = "/api/auth/invite/check";

/// The count of the starts of each invitation, in memory (a restart starts it
/// again): [`STARTS_PER_INVITE`] per invitation in a sliding
/// [`STARTS_WINDOW_SECS`], keyed by the hash of the token. Only an invitation
/// that [`pending`] found is counted, so only an administrator can add a key;
/// a full table still never refuses: it drops the key that was added first.
pub struct InviteStarts(WindowLimit<[u8; 32]>);

impl InviteStarts {
    /// A count with room for `max_keys` invitations.
    pub fn new(max_keys: usize) -> Self {
        Self(WindowLimit::new(
            STARTS_PER_INVITE,
            STARTS_WINDOW_SECS,
            max_keys,
        ))
    }

    /// Counts a start of the invitation with the token hash `hash` at `now`
    /// (Unix seconds): `false` when it has made [`STARTS_PER_INVITE`] in the
    /// window already (that one is not counted).
    pub fn allow(&self, hash: &[u8; 32], now: u64) -> bool {
        self.admit(hash, now).is_ok()
    }

    /// [`InviteStarts::allow`], with how long the invitation must wait.
    pub fn admit(&self, hash: &[u8; 32], now: u64) -> Result<(), RetryAfter> {
        self.0.admit(*hash, now)
    }

    /// How many invitations are counted.
    pub fn tracked_keys(&self) -> usize {
        self.0.tracked_keys()
    }
}

impl fmt::Debug for InviteStarts {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("InviteStarts([redacted])")
    }
}

/// A pending invitation of [`INVITED_ROLE`].
#[derive(Clone, PartialEq, Eq)]
pub struct PendingInvite {
    /// The kit's id of the invitation.
    pub id: i64,
    /// The e-mail of the administrator who made it, `""` when that account
    /// is gone.
    pub invited_by: String,
    /// The account of that administrator, `None` when it is gone.
    pub invited_by_id: Option<i64>,
    /// When it runs out (Unix seconds).
    pub expires_at: i64,
}

impl fmt::Debug for PendingInvite {
    // No hash and no token is held; the e-mail stays out of debug output too.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PendingInvite")
            .field("id", &self.id)
            .field("expires_at", &self.expires_at)
            .finish_non_exhaustive()
    }
}

/// The pending invitation with the token hash `hash`, by the kit's
/// `find_pending` (not used, not revoked, not run out). `None` as well for an
/// invitation of another role than [`INVITED_ROLE`] and for one whose expiry
/// cannot be read, so every invitation that does not count looks alike.
pub fn pending(conn: &Connection, hash: &[u8; 32]) -> rusqlite::Result<Option<PendingInvite>> {
    let Some(invite) = vole_kit::db::invites::find_pending(conn, hash)? else {
        return Ok(None);
    };
    if invite.role != INVITED_ROLE {
        return Ok(None);
    }
    let Some(expires_at) = unix_of(&invite.expires_at) else {
        tracing::warn!(
            invite_id = invite.id,
            "an invitation has an expiry that is not a time: it is refused"
        );
        return Ok(None);
    };
    Ok(Some(PendingInvite {
        id: invite.id,
        invited_by: invite.created_by_name.unwrap_or_default(),
        invited_by_id: invite.created_by,
        expires_at,
    }))
}

/// The link of an invitation: `{vault}/vault/setup#invite={token}`. The token
/// is in the fragment, which a browser never sends.
pub fn link(origins: &Origins, token: &str) -> String {
    format!("{}/vault/setup#invite={token}", origins.vault())
}

/// A time of the kit (UTC, `YYYY-MM-DD HH:MM:SS`, as SQLite's `datetime`
/// writes it) in Unix seconds, or `None` when it is not one.
fn unix_of(text: &str) -> Option<i64> {
    let bytes = text.as_bytes();
    let shape = bytes.len() == 19
        && bytes.iter().enumerate().all(|(i, b)| match i {
            4 | 7 => *b == b'-',
            10 => *b == b' ',
            13 | 16 => *b == b':',
            _ => b.is_ascii_digit(),
        });
    if !shape {
        return None;
    }
    let number = |range: std::ops::Range<usize>| text.get(range)?.parse::<u16>().ok();
    let year = i32::from(number(0..4)?);
    let month = Month::try_from(u8::try_from(number(5..7)?).ok()?).ok()?;
    let day = u8::try_from(number(8..10)?).ok()?;
    let hour = u8::try_from(number(11..13)?).ok()?;
    let minute = u8::try_from(number(14..16)?).ok()?;
    let second = u8::try_from(number(17..19)?).ok()?;
    let date = Date::from_calendar_date(year, month, day).ok()?;
    let time = Time::from_hms(hour, minute, second).ok()?;
    Some(
        PrimitiveDateTime::new(date, time)
            .assume_utc()
            .unix_timestamp(),
    )
}

/// `POST /api/auth/invite/check` (vault listener, no credential).
pub fn routes<S>() -> Router<S>
where
    S: Clone + Send + Sync + 'static,
    FerretState: FromRef<S>,
{
    Router::new().route(CHECK_PATH, post(check_route))
}

/// The check of an invitation link: the body, the limit per address, the
/// lookup. Every token that is not pending is the same `403 invite_invalid`.
async fn check_route(
    State(state): State<FerretState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    request: Request,
) -> Result<Response, ApiError> {
    let caller = caller_from(request.headers(), Some(peer));
    let ApiJson(req) = ApiJson::<InviteCheckReq>::from_request(request, &state).await?;
    state
        .invite_checks
        .admit(&caller, state.clock.now_unix())
        .map_err(|wait| ApiError::throttled(wait.secs()))?;
    let hash = vole_kit::auth::invites::hash(req.invite.as_str());
    drop(req);
    let found = state
        .vault_db
        .with_conn(move |conn| Ok(pending(conn, &hash)?))
        .await?;
    let Some(invite) = found else {
        return Err(ApiError::coded("invite_invalid"));
    };
    let expires_at =
        u64::try_from(invite.expires_at).map_err(|_| ApiError::coded("invite_invalid"))?;
    let mut response = Json(InviteCheckRes {
        expires_at,
        invited_by: invite.invited_by,
    })
    .into_response();
    response
        .headers_mut()
        .insert(CACHE_CONTROL, HeaderValue::from_static("no-store"));
    Ok(response)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_kit_time_reads_as_unix_seconds() {
        assert_eq!(unix_of("1970-01-01 00:00:00"), Some(0));
        assert_eq!(unix_of("2026-11-01 00:00:00"), Some(1_793_491_200));
        assert_eq!(unix_of("2024-02-29 23:59:59"), Some(1_709_251_199));
        for bad in [
            "",
            "2026-11-01",
            "2026-11-01T00:00:00",
            "2026-11-01 00:00:00Z",
            "2026-13-01 00:00:00",
            "2026-02-30 00:00:00",
            "2026-11-01 24:00:00",
            "2026-11-01 00:60:00",
            "2026-1a-01 00:00:00",
            "+026-11-01 00:00:00",
        ] {
            assert_eq!(unix_of(bad), None, "{bad:?}");
        }
    }

    #[test]
    fn the_link_carries_the_token_in_the_fragment() {
        let origins =
            Origins::parse("https://vault.example.com", "https://admin.example.com").unwrap();
        assert_eq!(
            link(&origins, "abc"),
            "https://vault.example.com/vault/setup#invite=abc"
        );
    }

    #[test]
    fn a_pending_invitation_debugs_without_its_maker() {
        let invite = PendingInvite {
            id: 7,
            invited_by: "admin@example.com".into(),
            invited_by_id: Some(1),
            expires_at: 9,
        };
        let text = format!("{invite:?}");
        assert!(!text.contains("admin@example.com"), "{text}");
        assert!(text.contains("id: 7"), "{text}");
    }

    #[test]
    fn starts_are_ten_per_hour_per_invitation() {
        let starts = InviteStarts::new(8);
        for _ in 0..STARTS_PER_INVITE {
            assert!(starts.allow(&[1; 32], 10));
        }
        assert!(!starts.allow(&[1; 32], 10));
        assert_eq!(starts.admit(&[1; 32], 10).map_err(|w| w.secs()), Err(3_600));
        assert!(starts.allow(&[2; 32], 10), "another invitation");
        assert_eq!(starts.tracked_keys(), 2);
        assert!(starts.allow(&[1; 32], 10 + 3_600));
    }
}
