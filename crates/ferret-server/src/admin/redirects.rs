//! The paths the kit sends people to for a password (`product::EXTERNAL`) are
//! redirects on the admin listener. They start the hand-over of a session from
//! the vault origin (`/auth/handoff/begin`), where the password is typed.
//!
//! * `/vault/login` and `/vault/password`: a new admin session (`login`).
//! * `/vault/reauth`: a fresh check of the password for the open admin session
//!   (`reauth`).
//! * `/vault/setup`: the first administrator is made on the vault origin, so
//!   this goes straight there and keeps the query (the setup token a start-up
//!   message links with). Nothing is signed in by it.
//!
//! `next`, where the browser should end up on the admin origin, is cleaned
//! with `auth::handoff::sanitize_next` here and again by `begin`.

use axum::Router;
use axum::extract::{FromRef, RawQuery, State};
use axum::response::Redirect;
use axum::routing::get;

use crate::auth::handoff::sanitize_next;
use crate::config::Origins;

/// The first value of a query parameter, decoded.
pub fn query_param(raw: Option<&str>, name: &str) -> Option<String> {
    url::form_urlencoded::parse(raw?.as_bytes())
        .find(|(key, _)| key == name)
        .map(|(_, value)| value.into_owned())
}

/// Where a redirect stub sends the browser: `begin`, with the cleaned `next`
/// and, for a re-authentication, the purpose.
pub fn begin_location(raw_query: Option<&str>, reauth: bool) -> String {
    let next = sanitize_next(query_param(raw_query, "next").as_deref());
    let mut query = url::form_urlencoded::Serializer::new(String::new());
    query.append_pair("next", &next);
    if reauth {
        query.append_pair("purpose", "reauth");
    }
    format!("/auth/handoff/begin?{}", query.finish())
}

async fn login(RawQuery(query): RawQuery) -> Redirect {
    Redirect::to(&begin_location(query.as_deref(), false))
}

async fn reauth(RawQuery(query): RawQuery) -> Redirect {
    Redirect::to(&begin_location(query.as_deref(), true))
}

async fn setup(State(origins): State<Origins>, RawQuery(query): RawQuery) -> Redirect {
    let target = match query.filter(|q| !q.is_empty()) {
        Some(q) => format!("{}/vault/setup?{q}", origins.vault()),
        None => format!("{}/vault/setup", origins.vault()),
    };
    Redirect::to(&target)
}

/// `/vault/{login,setup,password,reauth}`.
pub fn routes<S>() -> Router<S>
where
    S: Clone + Send + Sync + 'static,
    Origins: FromRef<S>,
{
    Router::new()
        .route("/vault/login", get(login))
        .route("/vault/password", get(login))
        .route("/vault/reauth", get(reauth))
        .route("/vault/setup", get(setup))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_stub_hands_a_cleaned_next_to_begin() {
        assert_eq!(
            begin_location(Some("next=%2Fsettings%2Fusers"), false),
            "/auth/handoff/begin?next=%2Fsettings%2Fusers"
        );
        assert_eq!(
            begin_location(Some("next=%2Fsettings"), true),
            "/auth/handoff/begin?next=%2Fsettings&purpose=reauth"
        );
        for raw in [
            "next=%2F%2Fevil.test",
            "next=https%3A%2F%2Fevil.test",
            "next=%2Fvault%2Flogin",
            "other=1",
        ] {
            assert_eq!(
                begin_location(Some(raw), false),
                "/auth/handoff/begin?next=%2F",
                "{raw}"
            );
        }
        assert_eq!(begin_location(None, false), "/auth/handoff/begin?next=%2F");
    }

    #[test]
    fn the_first_value_of_a_parameter_wins() {
        assert_eq!(
            query_param(Some("next=%2Fa&next=%2Fb"), "next").as_deref(),
            Some("/a")
        );
        assert_eq!(query_param(None, "next"), None);
    }
}
