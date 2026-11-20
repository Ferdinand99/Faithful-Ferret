//! The Backup page of the admin pages (`/settings/backup`, administrators) and
//! its one action, "Take a backup now". Spec: Fase 1 § 11, "Backup".
//!
//! The page shows what the backup job reports: the state, when the last good
//! set was made, the fixed code of the last failure, how many sets the folder
//! holds, what the last message to the monitor came to and when the next run
//! is due. That is all. It never shows a path, a file name of a secret file, a
//! set's name, the monitor's address or anything that is in a set: the status
//! it reads ([`crate::backup::status::BackupSnapshot`]) holds times, counts and
//! fixed codes only, and the texts the page prints for a code are its own.
//!
//! "Take a backup now" is a form post on the admin listener. It sits behind the
//! admin session guard (a full admin session on the admin origin, the kit's
//! cookie agreeing) and the kit's origin check, and needs the administrator
//! role. It asks the job for a run
//! ([`crate::backup::BackupStatus::request_manual_run`]) and does nothing but
//! say so when one is going on or already on its way. The vault listener has no
//! such page and no such route.

use askama::Template;
use axum::Router;
use axum::extract::State;
use axum::response::{IntoResponse, Redirect, Response};
use axum::routing::{get, post};
use axum_extra::extract::cookie::SignedCookieJar;
use vole_kit::auth::CurrentUser;
use vole_kit::http::{ApiResult, HtmlTemplate};
use vole_kit::i18n::{self, Tr as _};
use vole_kit::page::{PageCtx, flash};

use crate::backup::status::{BackupSnapshot, State as RunState};
use crate::state::FerretState;

/// Where the page is.
pub const PATH: &str = "/settings/backup";
/// Where the form posts.
pub const RUN_PATH: &str = "/settings/backup/run";

/// The routes of the page. They go behind the admin session guard.
pub fn routes() -> Router<FerretState> {
    Router::new()
        .route(PATH, get(page))
        .route(RUN_PATH, post(run_now))
}

/// The last failure of a run, as the page shows it.
struct FailureView {
    /// When it failed; none when the time cannot be shown.
    when: Option<String>,
    /// The fixed code (only lowercase letters and underscores).
    code: String,
    /// The translation key of what the code means.
    why: &'static str,
}

/// The last message to the monitor, as the page shows it.
struct PushView {
    when: Option<String>,
    ok: bool,
    /// The fixed code of a failure.
    code: String,
    /// The translation key of what the code means (when it failed).
    why: &'static str,
}

/// Everything the page prints.
struct View {
    /// `up`, `down` or `pending`: the colour of the state tile.
    status: &'static str,
    /// The translation key of the state's name.
    state: &'static str,
    last_good: Option<String>,
    failure: Option<FailureView>,
    sets: u32,
    push: Option<PushView>,
    next_run: Option<String>,
    /// A run is going on or on its way: the button is off.
    busy: bool,
}

#[derive(Template)]
#[template(path = "settings_backup.html")]
struct Page {
    ctx: PageCtx,
    view: View,
    /// Where the form posts.
    run_path: &'static str,
}

/// The time of a Unix second as the kit writes times (UTC,
/// `YYYY-MM-DD HH:MM:SS`), so the kit's relative-time script can read it.
/// Seconds that are out of range give none (a status file edited by hand).
fn utc_text(at: i64) -> Option<String> {
    let t = time::OffsetDateTime::from_unix_timestamp(at).ok()?;
    Some(format!(
        "{:04}-{:02}-{:02} {:02}:{:02}:{:02}",
        t.year(),
        u8::from(t.month()),
        t.day(),
        t.hour(),
        t.minute(),
        t.second()
    ))
}

/// A code from the status file, as far as it is a fixed word: lowercase
/// letters and underscores, up to 32 of them. Anything else (a status file
/// that was edited by hand) is shown as `unknown`, never as it stands.
fn plain_code(code: &str) -> String {
    let fixed = !code.is_empty()
        && code.len() <= 32
        && code.bytes().all(|b| b.is_ascii_lowercase() || b == b'_');
    if fixed { code } else { "unknown" }.to_string()
}

/// What a run's failure code means, as a translation key.
fn failure_why(code: &str) -> &'static str {
    match code {
        "no_space" => "backup.why_no_space",
        "io" => "backup.why_io",
        "verify" => "backup.why_verify",
        "refused" => "backup.why_refused",
        "restore_in_progress" => "backup.why_restore",
        _ => "backup.why_unknown",
    }
}

/// What a failed message to the monitor means, as a translation key.
fn push_why(code: &str) -> &'static str {
    match code {
        "address" => "backup.push_address",
        "timeout" => "backup.push_timeout",
        "connect" => "backup.push_connect",
        "status" => "backup.push_status",
        "request" => "backup.push_request",
        _ => "backup.push_unknown",
    }
}

impl View {
    fn of(snapshot: &BackupSnapshot) -> Self {
        let (status, state) = match snapshot.state() {
            RunState::Unknown => ("pending", "backup.state_unknown"),
            RunState::Running => ("pending", "backup.state_running"),
            RunState::Ok => ("up", "backup.state_ok"),
            RunState::Failed => ("down", "backup.state_failed"),
        };
        Self {
            status,
            state,
            last_good: snapshot.last_good_at.and_then(utc_text),
            failure: snapshot.last_failure.as_ref().map(|f| {
                let code = plain_code(&f.code);
                FailureView {
                    when: utc_text(f.at),
                    why: failure_why(&code),
                    code,
                }
            }),
            sets: snapshot.sets,
            push: snapshot.last_push.as_ref().map(|p| {
                let code = p.code.as_deref().map(plain_code).unwrap_or_default();
                PushView {
                    when: utc_text(p.at),
                    ok: p.ok,
                    why: push_why(&code),
                    code,
                }
            }),
            next_run: snapshot.next_run_at.and_then(utc_text),
            busy: snapshot.running || snapshot.waiting,
        }
    }
}

/// `GET /settings/backup`.
async fn page(
    State(state): State<FerretState>,
    user: CurrentUser,
    jar: SignedCookieJar,
) -> ApiResult<impl IntoResponse> {
    user.require_admin()?;
    let view = View::of(&state.backup.snapshot());
    let (ctx, jar) = PageCtx::build(
        &state,
        Some(&user),
        &jar,
        i18n::t("backup.title"),
        "settings",
        "backup",
    )
    .await;
    let run_path = RUN_PATH;
    Ok((
        jar,
        HtmlTemplate(Page {
            ctx,
            view,
            run_path,
        }),
    ))
}

/// `POST /settings/backup/run`: asks the job for a backup, once. Answers with a
/// redirect to the page and a flash message; no body.
async fn run_now(
    State(state): State<FerretState>,
    user: CurrentUser,
    jar: SignedCookieJar,
) -> ApiResult<Response> {
    user.require_admin()?;
    let jar = match state.backup.request_manual_run() {
        Ok(()) => {
            tracing::info!(user = %user.username, "a backup was asked for on the admin pages");
            flash(jar, "success", i18n::t("backup.requested"))
        }
        Err(_) => flash(jar, "error", i18n::t("backup.already")),
    };
    Ok((jar, Redirect::to(PATH)).into_response())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_time_is_written_the_way_the_kit_reads_it() {
        assert_eq!(utc_text(0).as_deref(), Some("1970-01-01 00:00:00"));
        assert_eq!(
            utc_text(1_800_000_000).as_deref(),
            Some("2027-01-15 08:00:00")
        );
        assert_eq!(utc_text(i64::MAX), None);
    }

    #[test]
    fn only_a_fixed_word_is_shown_as_a_code() {
        assert_eq!(plain_code("no_space"), "no_space");
        for odd in [
            "",
            "No_Space",
            "/data/backups/x",
            "<b>io</b>",
            &"a".repeat(33),
        ] {
            assert_eq!(plain_code(odd), "unknown", "{odd}");
        }
    }

    #[test]
    fn every_code_the_job_writes_has_a_text() {
        for code in ["no_space", "io", "verify", "refused", "restore_in_progress"] {
            assert_ne!(failure_why(code), "backup.why_unknown", "{code}");
        }
        for code in ["address", "timeout", "connect", "status", "request"] {
            assert_ne!(push_why(code), "backup.push_unknown", "{code}");
        }
    }
}
