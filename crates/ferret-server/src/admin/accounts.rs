//! The Users page of the admin pages (`/settings/accounts`, administrators):
//! every account with what an administrator may see of it, the pending
//! invitations, and the actions of this page: make an invitation, send one
//! again, revoke one, make a one-time sign-in code for a user, disable an
//! account, enable it again, sign it out everywhere and delete it.
//!
//! It replaces the kit's own Users page (`/settings/users*`, closed by
//! `admin::guard::close_kit_users_pages`): the kit's page has no account log,
//! cannot show Ferret's columns and makes its changes in transactions of its
//! own.
//!
//! * The list ([`crate::accounts::list`]) shows counts and bytes, never vault
//!   content, and no PIN column.
//! * An invitation link (`{vault}/vault/setup#invite=<token>`, the token in
//!   the fragment) and a sign-in code are shown once, with
//!   `Cache-Control: no-store`. Neither goes into a cookie, a redirect, a log
//!   line or the page that is read after that. The post that makes a link
//!   answers `303` to the page with a slot id ([`super::shown_once`]): the
//!   first read of that page shows the link, so a reload never makes a second
//!   invitation. A code is shown in the answer to its post (the post uses the
//!   confirmation up, so a repeated post makes no second code).
//! * Making or sending an invitation again, making a sign-in code, enabling
//!   an account and deleting one need a fresh confirmation of the master
//!   password: the kit's re-auth grant, given by a `reauth` hand-over from the
//!   vault origin ("Confirm it's you" leads to
//!   `/vault/reauth?next=/settings/accounts`). Revoking an invitation,
//!   disabling an account and signing it out everywhere take access away and
//!   need none. A sign-in code is a way into an account and a deletion cannot
//!   be undone on the page, so each uses the grant up (as the kit's own page
//!   does for a code): the next one needs a new confirmation. Enabling gives
//!   the administrator no way in, so it keeps the grant, as an invitation does.
//! * A deletion takes two steps: the account is disabled first, and "Delete
//!   for good" is offered only once a good backup run started after that
//!   disable, with the account's e-mail typed in. The page says that the
//!   account stays in the backup sets until they run out.
//! * What a disable or a sign-out ended is announced right after the commit,
//!   on the database thread, so the streams close even when the request went
//!   away. The pre-login policy is renewed after the database is let go
//!   (`login::refresh_policy_now` takes a lock of its own, then the database).
//! * No action works on the administrator's own account or on another
//!   administrator (`403`); the rules are `accounts::actions::target`, asked
//!   again inside the write.
//! * Every post sits behind the admin session guard and the kit's CSRF guard,
//!   and needs the administrator role.
//!
//! Spec: Fase 1 § 11 ("The Users page"), § 6.3 (the sign-in code) and § 4.2
//! (invitations).

use askama::Template;
use axum::extract::{Path, Query, State};
use axum::http::HeaderValue;
use axum::http::header::CACHE_CONTROL;
use axum::response::{IntoResponse, Redirect, Response};
use axum::routing::{get, post};
use axum::{Form, Router};
use axum_extra::extract::cookie::SignedCookieJar;
use serde::Deserialize;
use vole_kit::auth::CurrentUser;
use vole_kit::auth::reauth;
use vole_kit::auth::session::SessionClaims;
use vole_kit::db::invites::Invite;
use vole_kit::http::{ApiError, ApiResult, HtmlTemplate};
use vole_kit::i18n::{self, Tr as _};
use vole_kit::page::{PageCtx, flash};
use zeroize::Zeroizing;

use crate::accounts::actions::{self, ActionError};
use crate::accounts::invites::link;
use crate::accounts::list::{self, AccountRow};
use crate::accounts::log::Actor;
use crate::admin::codes::IssuedCode;
use crate::admin::redirects::recover_location;
use crate::auth::login;
use crate::error::StoreError;
use crate::product;
use crate::state::FerretState;

/// Where the page is.
pub const PATH: &str = "/settings/accounts";
/// Where "Invite someone" posts.
pub const INVITES_PATH: &str = "/settings/accounts/invites";

/// The routes of the page. They go behind the admin session guard.
pub fn routes() -> Router<FerretState> {
    Router::new()
        .route(PATH, get(page))
        .route(INVITES_PATH, post(create_invite))
        .route(
            "/settings/accounts/invites/{id}/revoke",
            post(revoke_invite),
        )
        .route(
            "/settings/accounts/invites/{id}/resend",
            post(resend_invite),
        )
        .route("/settings/accounts/{user}/sign-in-code", post(sign_in_code))
        .route("/settings/accounts/{user}/disable", post(disable))
        .route("/settings/accounts/{user}/enable", post(enable))
        .route("/settings/accounts/{user}/sign-out", post(sign_out))
        .route("/settings/accounts/{user}/delete", post(delete))
}

/// One account, as the page prints it.
struct Row {
    id: i64,
    email: String,
    created_at: String,
    last_login_at: Option<String>,
    devices: u32,
    totp: bool,
    active: bool,
    is_admin: bool,
    is_self: bool,
    items: u32,
    /// The bytes, as the page writes a size.
    size: String,
    code_until: Option<String>,
    /// The page offers the actions on this account: not the administrator's
    /// own, not an administrator.
    actionable: bool,
    /// The account is disabled and a good backup run started after the
    /// disable: "Delete for good" may be offered.
    delete_ready: bool,
}

impl Row {
    fn of(row: AccountRow, delete_ready: bool) -> Self {
        Self {
            actionable: !row.is_self && !row.is_admin,
            delete_ready,
            size: size_text(row.bytes),
            id: row.user_id,
            email: row.email,
            created_at: row.created_at,
            last_login_at: row.last_login_at,
            devices: row.devices,
            totp: row.totp,
            active: row.active,
            is_admin: row.is_admin,
            is_self: row.is_self,
            items: row.items,
            code_until: row.code_until,
        }
    }
}

/// A sign-in code just made, shown once.
struct CodeView {
    /// The account it is for.
    email: String,
    code: IssuedCode,
    /// Where it is typed: the vault origin's recovery page.
    recover: String,
}

/// What the post that made it shows once: a link or a code.
enum Shown {
    /// The link of an invitation just made.
    Invite(Zeroizing<String>),
    /// A sign-in code just made.
    Code(CodeView),
}

#[derive(Template)]
#[template(path = "settings_accounts.html")]
struct Page {
    ctx: PageCtx,
    accounts: Vec<Row>,
    pending: Vec<Invite>,
    /// The administrator holds a fresh re-auth grant.
    fresh: bool,
    /// Where "Confirm it's you" leads.
    reauth_url: String,
    /// The link of an invitation this post made (shown once).
    shown_invite: Option<Zeroizing<String>>,
    /// The sign-in code this post made (shown once).
    shown_code: Option<CodeView>,
    invites_path: &'static str,
    /// Where a backup is made, for an account that waits for one before it
    /// can be deleted.
    backup_path: &'static str,
}

/// A size in bytes as the page writes it: whole bytes below a KB, then one
/// decimal in KB, MB, GB or TB (1024-based, rounded down), with the
/// language's decimal mark.
fn size_text(bytes: u64) -> String {
    size_with_mark(bytes, i18n::t("accounts.decimal_mark"))
}

/// [`size_text`] with the decimal mark `mark`.
fn size_with_mark(bytes: u64, mark: &str) -> String {
    const UNITS: [&str; 4] = ["KB", "MB", "GB", "TB"];
    if bytes < 1024 {
        return format!("{bytes} B");
    }
    let bytes = u128::from(bytes);
    let mut unit = 0;
    let mut divisor: u128 = 1024;
    while unit + 1 < UNITS.len() && bytes >= divisor * 1024 {
        divisor *= 1024;
        unit += 1;
    }
    // Tenths of the unit, in whole numbers: no floating point.
    let tenths = bytes * 10 / divisor;
    format!("{}{mark}{} {}", tenths / 10, tenths % 10, UNITS[unit])
}

/// Whether the request's jar holds a fresh re-auth grant for the session of
/// `user` (the kit's `is_fresh`, and the session cookie is that user's).
fn is_fresh(state: &FerretState, jar: &SignedCookieJar, user: &CurrentUser) -> bool {
    let own = jar
        .get(product::SESSION_COOKIE)
        .and_then(|c| SessionClaims::decode(c.value()))
        .is_some_and(|claims| claims.user_id == user.id);
    own && reauth::is_fresh(jar, &state.core.session_key)
}

/// "Confirm it's you": the re-auth stub of the admin listener, coming back to
/// this page.
fn reauth_url() -> String {
    let next: String = url::form_urlencoded::byte_serialize(PATH.as_bytes()).collect();
    format!("{}?next={next}", product::EXTERNAL.reauth_path)
}

/// The administrator as the actor of an action: their account and e-mail.
fn actor(user: &CurrentUser) -> Actor {
    Actor::Admin {
        user_id: Some(user.id),
        name: user.username.clone(),
    }
}

/// A failure of the store is an internal error of the page; it is logged and
/// never shown.
fn internal(error: impl std::fmt::Display) -> ApiError {
    ApiError::internal(error)
}

/// Back to the page with a message.
fn back(jar: SignedCookieJar, kind: &str, key: &'static str) -> Response {
    (flash(jar, kind, i18n::t(key)), Redirect::to(PATH)).into_response()
}

/// What an action that was not taken answers: `403` for an account no action
/// may touch (the page never offers one), `404` for one that is not there,
/// the page with a message for the rest.
fn refused(jar: SignedCookieJar, error: ActionError) -> ApiResult<Response> {
    match error {
        ActionError::NotAllowed => Err(ApiError::Forbidden),
        ActionError::NotFound => Err(ApiError::NotFound),
        ActionError::Disabled => Ok(back(jar, "error", "accounts.err_disabled")),
        ActionError::SecondFactor => Ok(back(jar, "error", "accounts.err_second_factor")),
        ActionError::Full => Ok(back(jar, "error", "accounts.err_full")),
        ActionError::Store(error) => Err(internal(error)),
        other => Err(internal(other)),
    }
}

/// Runs an action on the database; a failure to reach it is internal.
async fn act<T, F>(state: &FerretState, f: F) -> ApiResult<Result<T, ActionError>>
where
    F: FnOnce(&mut rusqlite::Connection) -> Result<T, ActionError> + Send + 'static,
    T: Send + 'static,
{
    state
        .vault_db
        .with_conn(move |conn| Ok(f(conn)))
        .await
        .map_err(internal)
}

/// The time of the server's clock.
fn now(state: &FerretState) -> ApiResult<i64> {
    i64::try_from(state.clock.now_unix()).map_err(internal)
}

/// The page, with what a post shows once (then `no-store`).
async fn render(
    state: &FerretState,
    user: &CurrentUser,
    jar: SignedCookieJar,
    shown: Option<Shown>,
) -> ApiResult<Response> {
    let me = user.id;
    let at = now(state)?;
    let last_good = state.backup.snapshot().last_good_at;
    let (accounts, pending) = state
        .vault_db
        .with_conn(move |conn| {
            let mut accounts = Vec::new();
            for row in list::list(conn, me, at)? {
                let ready = !row.active
                    && actions::backed_up_after(
                        actions::disabled_at(conn, row.user_id)?,
                        last_good,
                    );
                accounts.push((row, ready));
            }
            Ok::<_, StoreError>((accounts, vole_kit::db::invites::list_pending(conn)?))
        })
        .await
        .map_err(internal)?;
    // The words of a row are the request's language: made here, not on the
    // database thread.
    let accounts: Vec<Row> = accounts
        .into_iter()
        .map(|(row, ready)| Row::of(row, ready))
        .collect();
    let fresh = is_fresh(state, &jar, user);
    let (ctx, jar) = PageCtx::build(
        state,
        Some(user),
        &jar,
        i18n::t("accounts.title"),
        "settings",
        "accounts",
    )
    .await;
    let secret = shown.is_some();
    let (shown_invite, shown_code) = match shown {
        Some(Shown::Invite(link)) => (Some(link), None),
        Some(Shown::Code(code)) => (None, Some(code)),
        None => (None, None),
    };
    let page = Page {
        ctx,
        accounts,
        pending,
        fresh,
        reauth_url: reauth_url(),
        shown_invite,
        shown_code,
        invites_path: INVITES_PATH,
        backup_path: crate::admin::panel::PATH,
    };
    let mut response = (jar, HtmlTemplate(page)).into_response();
    if secret {
        // The page holds a link or a code that works once: keep it out of
        // every cache.
        response
            .headers_mut()
            .insert(CACHE_CONTROL, HeaderValue::from_static("no-store"));
    }
    Ok(response)
}

/// What the page's address may carry: the slot of a link to show once.
#[derive(Deserialize)]
struct PageQuery {
    shown: Option<String>,
}

/// `GET /settings/accounts`, and `?shown=<slot>` after a new invitation: the
/// link of the slot, once, for the administrator who made it.
async fn page(
    State(state): State<FerretState>,
    user: CurrentUser,
    jar: SignedCookieJar,
    Query(query): Query<PageQuery>,
) -> ApiResult<Response> {
    user.require_admin()?;
    let shown = match query.shown {
        Some(slot) => state
            .shown_once
            .take(&slot, user.id, now(&state)?)
            .map(Shown::Invite),
        None => None,
    };
    render(&state, &user, jar, shown).await
}

/// After a new link: the flash, and `303` to the page that shows the link
/// once (the link waits in [`FerretState::shown_once`], never in the address).
fn show_link(
    state: &FerretState,
    user: &CurrentUser,
    jar: SignedCookieJar,
    token: &str,
    message: &'static str,
) -> ApiResult<Response> {
    let link = Zeroizing::new(link(&state.origins, token));
    let slot = state.shown_once.put(user.id, now(state)?, link);
    let jar = flash(jar, "success", i18n::t(message));
    Ok((jar, Redirect::to(&format!("{PATH}?shown={slot}"))).into_response())
}

/// `POST /settings/accounts/invites`: a new invitation, its link shown once
/// on the page the answer leads to.
async fn create_invite(
    State(state): State<FerretState>,
    user: CurrentUser,
    jar: SignedCookieJar,
) -> ApiResult<Response> {
    user.require_admin()?;
    if !is_fresh(&state, &jar, &user) {
        return Ok(back(jar, "error", "sec.confirm_its_you_help"));
    }
    let by = actor(&user);
    let token = match act(&state, move |conn| actions::create_invite(conn, &by)).await? {
        Ok(token) => token,
        Err(error) => return refused(jar, error),
    };
    show_link(&state, &user, jar, &token, "accounts.invite_made")
}

/// `POST /settings/accounts/invites/{id}/resend`: the old link revoked and a
/// new one made, in one transaction; the new link shown once on the page the
/// answer leads to.
async fn resend_invite(
    State(state): State<FerretState>,
    user: CurrentUser,
    jar: SignedCookieJar,
    Path(id): Path<i64>,
) -> ApiResult<Response> {
    user.require_admin()?;
    if !is_fresh(&state, &jar, &user) {
        return Ok(back(jar, "error", "sec.confirm_its_you_help"));
    }
    let by = actor(&user);
    let token = match act(&state, move |conn| actions::resend_invite(conn, id, &by)).await? {
        Ok(token) => token,
        // The old one is gone already (used, revoked or run out).
        Err(ActionError::NotFound) => return Ok(back(jar, "error", "accounts.invite_gone")),
        Err(error) => return refused(jar, error),
    };
    show_link(&state, &user, jar, &token, "accounts.invite_resent")
}

/// `POST /settings/accounts/invites/{id}/revoke`: no confirmation needed.
async fn revoke_invite(
    State(state): State<FerretState>,
    user: CurrentUser,
    jar: SignedCookieJar,
    Path(id): Path<i64>,
) -> ApiResult<Response> {
    user.require_admin()?;
    let by = actor(&user);
    match act(&state, move |conn| actions::revoke_invite(conn, id, &by)).await? {
        Ok(true) => Ok(back(jar, "success", "accounts.invite_revoked")),
        Ok(false) => Ok(back(jar, "error", "accounts.invite_gone")),
        Err(error) => refused(jar, error),
    }
}

/// `POST /settings/accounts/{user}/sign-in-code`: a one-time sign-in code for
/// the account, logged in its account log, shown once.
async fn sign_in_code(
    State(state): State<FerretState>,
    user: CurrentUser,
    jar: SignedCookieJar,
    Path(target): Path<i64>,
) -> ApiResult<Response> {
    user.require_admin()?;
    if !is_fresh(&state, &jar, &user) {
        return Ok(back(jar, "error", "sec.confirm_its_you_help"));
    }
    let by = actor(&user);
    let at = now(&state)?;
    let issued = act(&state, move |conn| {
        actions::issue_sign_in_code_for(conn, target, &by, at)
    })
    .await?;
    let (code, email) = match issued {
        Ok(made) => made,
        Err(error) => return refused(jar, error),
    };
    tracing::info!(
        admin = user.id,
        user_id = target,
        "a sign-in code was made on the Users page"
    );
    let shown = Shown::Code(CodeView {
        email,
        code,
        recover: recover_location(&state.origins),
    });
    // A way into an account: the confirmation is used up, as on the kit's own
    // page, so the next code needs a new one.
    let jar = flash(reauth::clear(jar), "success", i18n::t("accounts.code_made"));
    render(&state, &user, jar, Some(shown)).await
}

/// `POST /settings/accounts/{user}/disable`: the account can no longer sign
/// in, and every session, device and code of it ends at once. Protective: no
/// confirmation needed.
async fn disable(
    State(state): State<FerretState>,
    user: CurrentUser,
    jar: SignedCookieJar,
    Path(target): Path<i64>,
) -> ApiResult<Response> {
    user.require_admin()?;
    let by = actor(&user);
    let at = now(&state)?;
    let events = state.events.clone();
    let result = act(&state, move |conn| {
        let ended = actions::disable(conn, target, &by, at)?;
        events.announce_ended(&ended);
        Ok(ended.len())
    })
    .await?;
    match result {
        Ok(ended) => {
            tracing::info!(
                admin = user.id,
                user_id = target,
                ended,
                "an account was disabled on the Users page"
            );
            login::refresh_policy_now(&state).await;
            Ok(back(jar, "success", "accounts.disabled_done"))
        }
        Err(ActionError::Disabled) => Ok(back(jar, "error", "accounts.err_already_disabled")),
        Err(error) => refused(jar, error),
    }
}

/// `POST /settings/accounts/{user}/enable`: the account may sign in again.
/// It gives access back, so it needs a fresh confirmation; the confirmation
/// is kept, since enabling gives the administrator no way into the account.
async fn enable(
    State(state): State<FerretState>,
    user: CurrentUser,
    jar: SignedCookieJar,
    Path(target): Path<i64>,
) -> ApiResult<Response> {
    user.require_admin()?;
    if !is_fresh(&state, &jar, &user) {
        return Ok(back(jar, "error", "sec.confirm_its_you_help"));
    }
    let by = actor(&user);
    let at = now(&state)?;
    match act(&state, move |conn| actions::enable(conn, target, &by, at)).await? {
        Ok(()) => {
            tracing::info!(
                admin = user.id,
                user_id = target,
                "an account was enabled on the Users page"
            );
            login::refresh_policy_now(&state).await;
            Ok(back(jar, "success", "accounts.enabled_done"))
        }
        Err(ActionError::NotDisabled) => Ok(back(jar, "error", "accounts.err_already_active")),
        Err(error) => refused(jar, error),
    }
}

/// `POST /settings/accounts/{user}/sign-out`: every session, device and code
/// of the account ends at once, and the account may sign in again.
/// Protective: no confirmation needed.
async fn sign_out(
    State(state): State<FerretState>,
    user: CurrentUser,
    jar: SignedCookieJar,
    Path(target): Path<i64>,
) -> ApiResult<Response> {
    user.require_admin()?;
    let by = actor(&user);
    let at = now(&state)?;
    let events = state.events.clone();
    let result = act(&state, move |conn| {
        let ended = actions::sign_out_everywhere(conn, target, &by, at)?;
        events.announce_ended(&ended);
        Ok(ended.len())
    })
    .await?;
    match result {
        Ok(ended) => {
            tracing::info!(
                admin = user.id,
                user_id = target,
                ended,
                "an account was signed out everywhere on the Users page"
            );
            // The accounts that count did not change, but the policy is
            // renewed after each of these actions all the same (§ 11).
            login::refresh_policy_now(&state).await;
            Ok(back(jar, "success", "accounts.signed_out_done"))
        }
        Err(error) => refused(jar, error),
    }
}

/// What "Delete for good" posts: the account's e-mail, typed in.
#[derive(Deserialize)]
struct DeleteForm {
    #[serde(default)]
    email: String,
}

/// `POST /settings/accounts/{user}/delete`: the second step of a deletion,
/// for a disabled account with a good backup run started after the disable,
/// with a fresh confirmation and the account's e-mail typed in. It cannot be
/// undone on the page, so it uses the confirmation up; a refused one keeps it.
async fn delete(
    State(state): State<FerretState>,
    user: CurrentUser,
    jar: SignedCookieJar,
    Path(target): Path<i64>,
    Form(form): Form<DeleteForm>,
) -> ApiResult<Response> {
    user.require_admin()?;
    if !is_fresh(&state, &jar, &user) {
        return Ok(back(jar, "error", "sec.confirm_its_you_help"));
    }
    let by = actor(&user);
    let at = now(&state)?;
    let last_good = state.backup.snapshot().last_good_at;
    let typed = form.email;
    let result = act(&state, move |conn| {
        actions::delete(conn, target, &by, &typed, last_good, at)
    })
    .await?;
    match result {
        Ok(()) => {
            login::refresh_policy_now(&state).await;
            Ok(back(reauth::clear(jar), "success", "accounts.deleted_done"))
        }
        Err(ActionError::NotDisabled) => Ok(back(jar, "error", "accounts.err_not_disabled")),
        Err(ActionError::NeedsBackup) => Ok(back(jar, "error", "accounts.err_needs_backup")),
        Err(ActionError::EmailMismatch) => Ok(back(jar, "error", "accounts.err_email_mismatch")),
        Err(error) => refused(jar, error),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_size_is_bytes_then_one_decimal_of_a_unit() {
        let size = |bytes| size_with_mark(bytes, ".");
        assert_eq!(size(0), "0 B");
        assert_eq!(size(1023), "1023 B");
        assert_eq!(size(1024), "1.0 KB");
        assert_eq!(size(123_456), "120.5 KB");
        assert_eq!(size(5 * 1024 * 1024 + 512 * 1024), "5.5 MB");
        assert_eq!(size(3 * 1024 * 1024 * 1024), "3.0 GB");
        assert_eq!(size(u64::MAX), "16777215.9 TB");
        assert_eq!(size_with_mark(1536, ","), "1,5 KB");
    }

    #[test]
    fn confirm_it_is_you_comes_back_to_this_page() {
        assert_eq!(reauth_url(), "/vault/reauth?next=%2Fsettings%2Faccounts");
    }
}
