//! The Unlock page of the admin pages (`/settings/unlock`, administrators): the
//! server's rule for quick unlock. Only with the cargo feature `quick-unlock`;
//! without it the page is not mounted (404) and no tab links it.
//!
//! The page has three settings: *Allow PIN* (the emergency switch), *Allow PIN
//! after restart* (whether a PIN may be kept on disk) and the shortest PIN
//! (4 to 64 characters). The rule is stored in `ferret_unlock_policy` and
//! served to clients by `GET /api/vault/policy` ([`crate::vault::policy`]).
//!
//! Beside the form the page says in plain words what the rule means: that a
//! PIN is kept on disk by default, how long one powerful computer needs to try
//! every PIN of the shortest allowed length, and how long a hundred need. The
//! numbers are computed from the shortest length and from
//! [`OFFLINE_GUESSES_PER_SECOND`], one constant that sits in one place.
//!
//! A rule that is stricter than the saved one (a switch turned off, a longer
//! minimum) deletes PINs on the devices, so the first post only announces it
//! and saves nothing; the same form, posted again with the confirmation, saves.
//!
//! The page sits behind the admin session guard and the kit's origin check like
//! every other page, and needs the administrator role. Every change is logged
//! with the user who made it. The vault listener has no such page.

use askama::Template;
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Redirect, Response};
use axum::routing::get;
use axum::{Form, Router};
use axum_extra::extract::cookie::SignedCookieJar;
use serde::Deserialize;
use vole_kit::auth::CurrentUser;
use vole_kit::http::{ApiError, ApiResult, HtmlTemplate};
use vole_kit::i18n::{self, Tr as _};
use vole_kit::page::{PageCtx, flash};

use crate::error::StoreError;
use crate::state::FerretState;
use crate::vault::policy::{self, UnlockPolicy};

/// Where the page is, and where the form posts.
pub const PATH: &str = "/settings/unlock";

/// How many PIN guesses per second one powerful computer makes against a PIN
/// that is kept on disk (the cost of one Argon2id run at the strong PIN
/// profile). The one number that the page's times are computed from, and the
/// number the extension's own text uses.
pub const OFFLINE_GUESSES_PER_SECOND: u32 = 100;

/// How many computers the second figure on the page assumes.
pub const MANY_COMPUTERS: u32 = 100;

/// The routes of the page. They go behind the admin session guard.
pub fn routes() -> Router<FerretState> {
    Router::new().route(PATH, get(page).post(save))
}

/// The number of combinations of `length` digits as a number of seconds of
/// guessing at `per_second` guesses a second: the whole space, not half of it.
pub fn seconds_to_try_all(length: u8, per_second: f64) -> f64 {
    10f64.powi(i32::from(length)) / per_second
}

/// `seconds` as the page says it ("under 3 hours"): the next whole unit up, in
/// the largest unit that holds at least two of it. The text of each unit is a
/// translation with `{n}`.
pub fn duration_text(seconds: f64) -> String {
    const MINUTE: f64 = 60.0;
    const HOUR: f64 = 3_600.0;
    const DAY: f64 = 86_400.0;
    const MONTH: f64 = 30.0 * DAY;
    const YEAR: f64 = 365.0 * DAY;
    let (key, unit) = if seconds < 1.0 {
        return i18n::t("unlock.time_less").to_string();
    } else if seconds < MINUTE {
        ("unlock.time_seconds", 1.0)
    } else if seconds < HOUR {
        ("unlock.time_minutes", MINUTE)
    } else if seconds < DAY {
        ("unlock.time_hours", HOUR)
    } else if seconds < 60.0 * DAY {
        ("unlock.time_days", DAY)
    } else if seconds < 2.0 * YEAR {
        ("unlock.time_months", MONTH)
    } else if seconds < 1_000.0 * YEAR {
        ("unlock.time_years", YEAR)
    } else {
        return i18n::t("unlock.time_forever").to_string();
    };
    // `seconds` is at least 1 here and below 1000 years: the quotient is a
    // small positive number, and truncating it is the point.
    #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
    let n = (seconds / unit).floor() as u64 + 1;
    i18n::tf(key, &[("n", &n.to_string())])
}

/// `10^length` written out with the language's thousands separator, or as a
/// power of ten when it is too long to read.
pub fn combinations_text(length: u8) -> String {
    if length > 15 {
        return format!("10^{length}");
    }
    let digits = format!("1{}", "0".repeat(usize::from(length)));
    let separator = i18n::t("unlock.group_separator");
    let mut out = String::new();
    for (i, ch) in digits.chars().enumerate() {
        if i > 0 && digits.len().saturating_sub(i) % 3 == 0 {
            out.push_str(separator);
        }
        out.push(ch);
    }
    out
}

/// The three paragraphs that say what the rule means, for the shortest length
/// `length`.
fn explanation(length: u8) -> Explanation {
    let one = duration_text(seconds_to_try_all(
        length,
        f64::from(OFFLINE_GUESSES_PER_SECOND),
    ));
    let many = duration_text(seconds_to_try_all(
        length,
        f64::from(OFFLINE_GUESSES_PER_SECOND) * f64::from(MANY_COMPUTERS),
    ));
    Explanation {
        disk: i18n::t("unlock.explain_disk").to_string(),
        cost: i18n::tf(
            "unlock.explain_cost",
            &[
                ("length", &length.to_string()),
                ("combos", &combinations_text(length)),
                ("one", &one),
                ("many", &many),
            ],
        ),
        off: i18n::t("unlock.explain_off").to_string(),
    }
}

struct Explanation {
    disk: String,
    cost: String,
    off: String,
}

/// What the form shows.
struct View {
    pin_allowed: bool,
    pin_after_restart: bool,
    /// What is in the number field: the saved length, or what was typed.
    min_length: String,
    /// The error under the number field; empty when there is none.
    min_error: String,
    /// The sentences that announce what a stricter rule deletes; empty when the
    /// rule is not stricter or has been confirmed.
    announce: Vec<String>,
    /// The form carries the confirmation: the next post saves.
    confirm: bool,
    explain: Explanation,
}

impl View {
    fn of(policy: &UnlockPolicy) -> Self {
        Self {
            pin_allowed: policy.pin_allowed,
            pin_after_restart: policy.pin_after_restart,
            min_length: policy.pin_min_length.to_string(),
            min_error: String::new(),
            announce: Vec::new(),
            confirm: false,
            explain: explanation(policy.pin_min_length),
        }
    }
}

#[derive(Template)]
#[template(path = "settings_unlock.html")]
struct Page {
    ctx: PageCtx,
    view: View,
    /// Where the form posts.
    action: &'static str,
}

/// What the form posts. An unchecked switch sends nothing.
#[derive(Deserialize)]
pub struct UnlockForm {
    #[serde(default)]
    pin_allowed: bool,
    #[serde(default)]
    pin_after_restart: bool,
    #[serde(default)]
    min_length: String,
    #[serde(default)]
    confirm: bool,
}

/// A failure of the store is an internal error of the page; it is logged and
/// never shown.
fn internal(error: StoreError) -> ApiError {
    ApiError::internal(error)
}

async fn read_policy(state: &FerretState) -> ApiResult<UnlockPolicy> {
    state
        .vault_db
        .with_conn(|conn| policy::read(conn))
        .await
        .map_err(internal)
}

/// `GET /settings/unlock`.
async fn page(
    State(state): State<FerretState>,
    user: CurrentUser,
    jar: SignedCookieJar,
) -> ApiResult<impl IntoResponse> {
    user.require_admin()?;
    let saved = read_policy(&state).await?;
    render(&state, &user, jar, View::of(&saved), StatusCode::OK).await
}

async fn render(
    state: &FerretState,
    user: &CurrentUser,
    jar: SignedCookieJar,
    view: View,
    status: StatusCode,
) -> ApiResult<Response> {
    let (ctx, jar) = PageCtx::build(
        state,
        Some(user),
        &jar,
        i18n::t("unlock.title"),
        "settings",
        "unlock",
    )
    .await;
    let page = Page {
        ctx,
        view,
        action: PATH,
    };
    Ok((status, jar, HtmlTemplate(page)).into_response())
}

/// The sentences that say what `next` deletes, compared with `saved`.
fn announcement(saved: &UnlockPolicy, next: &UnlockPolicy) -> Vec<String> {
    let mut out = Vec::new();
    if saved.pin_allowed && !next.pin_allowed {
        out.push(i18n::t("unlock.confirm_off").to_string());
    }
    if saved.pin_after_restart && !next.pin_after_restart {
        out.push(i18n::t("unlock.confirm_restart").to_string());
    }
    if next.pin_min_length > saved.pin_min_length {
        out.push(i18n::tf(
            "unlock.confirm_min",
            &[("n", &next.pin_min_length.to_string())],
        ));
    }
    out
}

/// `POST /settings/unlock`: validates and saves. A length outside 4 to 64 is
/// refused with the page and 422. A stricter rule without the confirmation is
/// announced and not saved. A saved rule answers with a redirect to the page.
async fn save(
    State(state): State<FerretState>,
    user: CurrentUser,
    jar: SignedCookieJar,
    Form(form): Form<UnlockForm>,
) -> ApiResult<Response> {
    user.require_admin()?;
    let saved = read_policy(&state).await?;
    let typed = form.min_length.trim().to_string();
    let length = typed
        .parse::<i64>()
        .ok()
        .filter(|n| UnlockPolicy::length_ok(*n))
        .and_then(|n| u8::try_from(n).ok());
    let Some(pin_min_length) = length else {
        let mut view = View::of(&saved);
        view.pin_allowed = form.pin_allowed;
        view.pin_after_restart = form.pin_after_restart;
        view.min_length = typed;
        view.min_error = i18n::t("unlock.min_error").to_string();
        return render(&state, &user, jar, view, StatusCode::UNPROCESSABLE_ENTITY).await;
    };
    let next = UnlockPolicy {
        pin_allowed: form.pin_allowed,
        pin_after_restart: form.pin_after_restart,
        pin_min_length,
    };
    if next == saved {
        let jar = flash(jar, "success", i18n::t("unlock.unchanged"));
        return Ok((jar, Redirect::to(PATH)).into_response());
    }
    if next.is_stricter_than(&saved) && !form.confirm {
        // Announce what saving does, save nothing, and give the form back with
        // what was typed and the confirmation in it.
        let mut view = View::of(&next);
        view.announce = announcement(&saved, &next);
        view.confirm = true;
        return render(&state, &user, jar, view, StatusCode::OK).await;
    }
    let now = i64::try_from(state.clock.now_unix()).unwrap_or(i64::MAX);
    state
        .vault_db
        .with_conn(move |conn| policy::write(conn, &next, now))
        .await
        .map_err(internal)?;
    tracing::info!(
        user = %user.username,
        pin_allowed = next.pin_allowed,
        pin_after_restart = next.pin_after_restart,
        pin_min_length = next.pin_min_length,
        stricter = next.is_stricter_than(&saved),
        "the unlock rule was changed on the admin pages"
    );
    let jar = flash(jar, "success", i18n::t("unlock.saved"));
    Ok((jar, Redirect::to(PATH)).into_response())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_combinations_of_digits_are_the_table_of_the_design() {
        // 10^4, 10^6 and 10^8 digits at 100 guesses a second and at 100
        // computers: under 2 minutes / 1 second; under 3 hours / 100 seconds;
        // about 12 days / under 3 hours.
        let per = f64::from(OFFLINE_GUESSES_PER_SECOND);
        let many = per * f64::from(MANY_COMPUTERS);
        assert!((seconds_to_try_all(4, per) - 100.0).abs() < 1e-9);
        assert!((seconds_to_try_all(4, many) - 1.0).abs() < 1e-9);
        assert!((seconds_to_try_all(6, per) - 10_000.0).abs() < 1e-6);
        assert!((seconds_to_try_all(6, many) - 100.0).abs() < 1e-9);
        assert!((seconds_to_try_all(8, per) - 1_000_000.0).abs() < 1e-3);
        assert!((seconds_to_try_all(8, many) - 10_000.0).abs() < 1e-6);
    }

    #[test]
    fn a_time_is_said_in_the_next_whole_unit_up() {
        crate::product::install();
        let said = |s: f64| duration_text(s);
        assert_eq!(said(0.5), "less than a second");
        assert_eq!(said(1.0), "under 2 seconds");
        assert_eq!(said(100.0), "under 2 minutes");
        assert_eq!(said(10_000.0), "under 3 hours");
        assert_eq!(said(1_000_000.0), "under 12 days");
        assert_eq!(said(10_000_000.0), "under 4 months");
        assert_eq!(said(100_000_000.0), "under 4 years");
        assert_eq!(said(10_000_000_000.0), "under 318 years");
        assert_eq!(said(1e30), "more than 1,000 years");
    }

    #[test]
    fn combinations_are_written_with_a_separator_and_long_ones_as_a_power() {
        crate::product::install();
        assert_eq!(combinations_text(4), "10,000");
        assert_eq!(combinations_text(6), "1,000,000");
        assert_eq!(combinations_text(15), "1,000,000,000,000,000");
        assert_eq!(combinations_text(16), "10^16");
        assert_eq!(combinations_text(64), "10^64");
    }

    #[test]
    fn a_stricter_rule_is_announced_in_words() {
        let saved = UnlockPolicy::default();
        let next = UnlockPolicy {
            pin_allowed: false,
            pin_after_restart: false,
            pin_min_length: 8,
        };
        assert_eq!(announcement(&saved, &next).len(), 3);
        assert!(announcement(&saved, &saved).is_empty());
    }
}
