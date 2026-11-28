//! The account log: what was done to an account, when, and by whom.
//!
//! One row of `ferret_account_events` (migration `0010_accounts.sql`) per
//! event: the account (its kit user), the time, the kind, the actor and, for
//! an administrator, that administrator's e-mail. The account reads its own
//! log with `GET /api/account/events` ([`routes`]), which takes a full vault
//! session only: not a reset session, not a device token, and it is not on
//! the admin listener.
//!
//! * An event is written in the transaction of the change it records
//!   ([`record`]); the two exceptions (a sign-in code, which the kit stores in
//!   a transaction of its own, and a deletion, whose log goes with the
//!   account) are in `accounts::actions`.
//! * An account keeps its newest [`MAX_EVENTS_PER_USER`] events: each write
//!   drops the oldest beyond that.
//! * Nothing here changes or deletes an event in any other way, and no route
//!   does. An event holds no code and no token: only its kind, its time and
//!   who caused it.
//!
//! Spec: Fase 1 § 11 (the account log), § 6.3 and § 8.8.

use axum::Json;
use axum::Router;
use axum::extract::{FromRef, FromRequestParts as _, Query, State};
use axum::http::request::Parts;
use axum::response::{IntoResponse as _, Response};
use axum::routing::get;
use rusqlite::{Connection, params};
use serde::Deserialize;

use crate::auth::login::no_store;
use crate::error::{ApiError, StoreError};
use crate::http::extract::VaultSession;
use crate::state::FerretState;
use crate::wire::{AccountEventJson, AccountEventsRes, ActorJson, MAX_EVENTS_PAGE, MAX_JSON_INT};

/// The most events an account keeps; the oldest go first.
pub const MAX_EVENTS_PER_USER: i64 = 1_000;

/// The events of a page when the request names no `limit`.
pub const DEFAULT_EVENTS_PAGE: usize = 50;

/// The path of the account's own log.
pub const EVENTS_PATH: &str = "/api/account/events";

/// What happened to an account. Stored as its snake_case name (`kind`); the
/// column is free text, so later kinds need no new table.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EventKind {
    /// The account was made from an invitation.
    AccountCreated,
    /// A one-time sign-in code was made for the account.
    SignInCodeIssued,
    /// A sign-in code of the account was redeemed for a reset session.
    SignInCodeRedeemed,
    /// The account was disabled.
    AccountDisabled,
    /// The account was enabled again.
    AccountEnabled,
    /// Every session and device of the account was signed out.
    SignedOutEverywhere,
    /// The server was restored from a backup (or its restore epoch raised).
    ServerRestored,
}

impl EventKind {
    /// The stored name.
    pub fn as_str(self) -> &'static str {
        match self {
            EventKind::AccountCreated => "account_created",
            EventKind::SignInCodeIssued => "sign_in_code_issued",
            EventKind::SignInCodeRedeemed => "sign_in_code_redeemed",
            EventKind::AccountDisabled => "account_disabled",
            EventKind::AccountEnabled => "account_enabled",
            EventKind::SignedOutEverywhere => "signed_out_everywhere",
            EventKind::ServerRestored => "server_restored",
        }
    }
}

/// Who caused an event.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Actor {
    /// An administrator on the admin pages. `user_id` is the administrator's
    /// account (`None` once it is gone; the log stores no id, only the
    /// e-mail), `name` the e-mail, `""` when that account is gone.
    Admin { user_id: Option<i64>, name: String },
    /// A command on the server (`ferret sign-in-code issue`).
    ServerCommand,
    /// The server itself (a restore).
    Server,
    /// The account itself (a redeemed sign-in code).
    Account,
}

impl Actor {
    /// The stored name of the actor.
    pub fn as_str(&self) -> &'static str {
        match self {
            Actor::Admin { .. } => "admin",
            Actor::ServerCommand => "server_command",
            Actor::Server => "server",
            Actor::Account => "account",
        }
    }

    /// The stored `actor_name`: an administrator's e-mail, else `""`.
    fn name(&self) -> &str {
        match self {
            Actor::Admin { name, .. } => name,
            _ => "",
        }
    }
}

/// Writes one event for `user_id` in the caller's connection or transaction,
/// and drops the account's oldest events beyond [`MAX_EVENTS_PER_USER`].
pub fn record(
    conn: &Connection,
    user_id: i64,
    kind: EventKind,
    actor: &Actor,
    now: i64,
) -> rusqlite::Result<()> {
    conn.execute(
        "INSERT INTO ferret_account_events (user_id, at, kind, actor, actor_name)
         VALUES (?1, ?2, ?3, ?4, ?5)",
        params![user_id, now, kind.as_str(), actor.as_str(), actor.name()],
    )?;
    // The id of the newest event that is one too many; with fewer events the
    // subquery is NULL and nothing is deleted.
    conn.execute(
        "DELETE FROM ferret_account_events
         WHERE user_id = ?1 AND id <= (
           SELECT id FROM ferret_account_events WHERE user_id = ?1
           ORDER BY id DESC LIMIT 1 OFFSET ?2)",
        params![user_id, MAX_EVENTS_PER_USER],
    )?;
    Ok(())
}

/// Writes `server_restored` (actor `server`) for every account, in the
/// caller's transaction (the sweep of a restore), and keeps each account to
/// [`MAX_EVENTS_PER_USER`]. Returns how many events were written.
pub fn record_restored_for_all(conn: &Connection, now: i64) -> rusqlite::Result<usize> {
    let logged = conn.execute(
        "INSERT INTO ferret_account_events (user_id, at, kind, actor, actor_name)
         SELECT id, ?1, ?2, ?3, '' FROM users ORDER BY id",
        params![
            now,
            EventKind::ServerRestored.as_str(),
            Actor::Server.as_str()
        ],
    )?;
    conn.execute(
        "DELETE FROM ferret_account_events WHERE id IN (
           SELECT id FROM (
             SELECT id, ROW_NUMBER() OVER (PARTITION BY user_id ORDER BY id DESC) AS n
             FROM ferret_account_events)
           WHERE n > ?1)",
        params![MAX_EVENTS_PER_USER],
    )?;
    Ok(logged)
}

/// One stored event, as [`page`] reads it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EventRow {
    pub id: i64,
    pub at: i64,
    pub kind: String,
    pub actor: String,
    pub actor_name: String,
}

/// The newest `limit` events of `user_id` with an id below `before` (all, when
/// `None`), newest first, and whether older ones follow.
pub fn page(
    conn: &Connection,
    user_id: i64,
    before: Option<i64>,
    limit: usize,
) -> rusqlite::Result<(Vec<EventRow>, bool)> {
    let before = before.unwrap_or(i64::MAX);
    // One more than the page, to know whether more follow.
    let wanted = i64::try_from(limit).unwrap_or(i64::MAX).saturating_add(1);
    let mut stmt = conn.prepare(
        "SELECT id, at, kind, actor, actor_name FROM ferret_account_events
         WHERE user_id = ?1 AND id < ?2
         ORDER BY id DESC LIMIT ?3",
    )?;
    let mut rows = stmt
        .query_map(params![user_id, before, wanted], |r| {
            Ok(EventRow {
                id: r.get(0)?,
                at: r.get(1)?,
                kind: r.get(2)?,
                actor: r.get(3)?,
                actor_name: r.get(4)?,
            })
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    let more = rows.len() > limit;
    rows.truncate(limit);
    Ok((rows, more))
}

/// `GET /api/account/events`.
pub fn routes<S>() -> Router<S>
where
    S: Clone + Send + Sync + 'static,
    FerretState: FromRef<S>,
{
    Router::new().route(EVENTS_PATH, get(events_route))
}

/// The query of the log: `before=<id>` and `limit=<1-100>`, both optional.
#[derive(Clone, Copy, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct EventsQuery {
    before: Option<u64>,
    limit: Option<u64>,
}

fn bad_request() -> ApiError {
    ApiError::coded("bad_request")
}

/// The page the query asks for: `(before, limit)`, or `400 bad_request`.
fn read_query(query: EventsQuery) -> Result<(Option<i64>, usize), ApiError> {
    let before = match query.before {
        None => None,
        Some(id) if id <= MAX_JSON_INT => Some(i64::try_from(id).map_err(|_| bad_request())?),
        Some(_) => return Err(bad_request()),
    };
    let limit = match query.limit {
        None => DEFAULT_EVENTS_PAGE,
        Some(n) => match usize::try_from(n) {
            Ok(n) if (1..=MAX_EVENTS_PAGE).contains(&n) => n,
            _ => return Err(bad_request()),
        },
    };
    Ok((before, limit))
}

/// The account's own events, from the session, never from the request.
async fn events_route(
    State(state): State<FerretState>,
    mut parts: Parts,
) -> Result<Response, ApiError> {
    // The session first: without one, nothing about the query is answered.
    let session = VaultSession::from_request_parts(&mut parts, &state).await?;
    let Query(query) = Query::<EventsQuery>::from_request_parts(&mut parts, &state)
        .await
        .map_err(|_| bad_request())?;
    let (before, limit) = read_query(query)?;
    let user_id = session.user_id;
    let (rows, more) = state
        .vault_db
        .with_conn(move |conn| Ok(page(conn, user_id, before, limit)?))
        .await?;
    let events = rows
        .into_iter()
        .map(event_json)
        .collect::<Result<Vec<_>, _>>()?;
    Ok(no_store(
        Json(AccountEventsRes { events, more }).into_response(),
    ))
}

/// The wire form of a stored event. The table's checks keep the actor to the
/// four names and the times to what the clock gave; a row that is none of
/// them is a store failure, not an answer.
fn event_json(row: EventRow) -> Result<AccountEventJson, StoreError> {
    const BAD: StoreError = StoreError::Invalid("an event of the account log is not one");
    let actor = match row.actor.as_str() {
        "admin" => ActorJson::Admin,
        "server_command" => ActorJson::ServerCommand,
        "server" => ActorJson::Server,
        "account" => ActorJson::Account,
        _ => return Err(BAD),
    };
    Ok(AccountEventJson {
        id: u64::try_from(row.id).map_err(|_| BAD)?,
        at: u64::try_from(row.at).map_err(|_| BAD)?,
        kind: row.kind,
        actor,
        actor_name: row.actor_name,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_kinds_are_the_snake_case_names_of_the_design() {
        let all = [
            (EventKind::AccountCreated, "account_created"),
            (EventKind::SignInCodeIssued, "sign_in_code_issued"),
            (EventKind::SignInCodeRedeemed, "sign_in_code_redeemed"),
            (EventKind::AccountDisabled, "account_disabled"),
            (EventKind::AccountEnabled, "account_enabled"),
            (EventKind::SignedOutEverywhere, "signed_out_everywhere"),
            (EventKind::ServerRestored, "server_restored"),
        ];
        for (kind, name) in all {
            assert_eq!(kind.as_str(), name);
        }
    }

    #[test]
    fn only_an_admin_carries_a_name() {
        let admin = Actor::Admin {
            user_id: Some(1),
            name: "admin@example.com".into(),
        };
        assert_eq!(
            (admin.as_str(), admin.name()),
            ("admin", "admin@example.com")
        );
        for (actor, name) in [
            (Actor::ServerCommand, "server_command"),
            (Actor::Server, "server"),
            (Actor::Account, "account"),
        ] {
            assert_eq!((actor.as_str(), actor.name()), (name, ""));
        }
    }

    #[test]
    fn the_query_takes_1_to_100_and_a_json_integer() {
        let q = |before, limit| read_query(EventsQuery { before, limit });
        assert_eq!(q(None, None), Ok((None, DEFAULT_EVENTS_PAGE)));
        assert_eq!(q(Some(7), Some(1)), Ok((Some(7), 1)));
        assert_eq!(
            q(Some(MAX_JSON_INT), Some(100)),
            Ok((Some(9_007_199_254_740_991), 100))
        );
        for (before, limit) in [
            (None, Some(0)),
            (None, Some(101)),
            (None, Some(u64::MAX)),
            (Some(MAX_JSON_INT + 1), None),
        ] {
            assert_eq!(q(before, limit), Err(bad_request()));
        }
    }
}
