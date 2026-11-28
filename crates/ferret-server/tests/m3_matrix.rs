//! The matrix of the sensitive operations: a change of the master password, a
//! new recovery key, a recovery with the recovery key and the redeeming of a
//! one-time sign-in code, against the real routes, the real stores and the
//! real client of `ferret-core`. Spec: Fase 1 § 4.6 (the sensitive
//! operations), § 6.3 (the recovery) and § 11 (a backup after every change of
//! the unlock methods).
//!
//! The first test makes seeded runs. Each run is one account with several
//! sessions (two full ones, an admin one and, after a code is redeemed, a reset
//! one) and a stream of steps: changes are *prepared* from what the client
//! holds at that moment, and *sent* later, one at a time or several at once,
//! after others have won, after a session ended, after the re-authentication
//! ran out. A model of what the server must hold says what each step must
//! come to, and every step is checked against the database and against the
//! sessions: exactly one change wins per snapshot, generations only go up,
//! a nonce is used once, every session that ended is dead and every other is
//! not, the OPAQUE record is the last password's, the newest recovery key opens
//! the recovery wrap, and every change asked for a backup.
//!
//! The matrix fails when a row of its list is never reached (`ROWS`), and a new
//! route that writes the unlock methods or ends sessions fails the list of
//! routes until it has a row. Time is the manual clock of the app.
//!
//! `FERRET_M3_MATRIX_RUNS` sets the number of runs (2 000 by default) and
//! `FERRET_M3_MATRIX_SEED` the base seed; a failure names the seed of its run,
//! and `FERRET_M3_MATRIX_ONLY=<seed>` runs that one alone (on a fresh server, as
//! account 1, with the clock at its start; nothing in a run depends on either).
//! Which of several changes that are sent at once commits first is up to the
//! database, so a run with a batch may not repeat step for step; the trace names
//! the winner of each batch.
//!
//! A nonce is also tried when it has grown old (fetched when the change was
//! made, used later), and the admin sessions are checked by their rows: the
//! guard of the admin listener is the subject of `admin_listener.rs`.

mod support;

use std::collections::BTreeSet;
use std::path::Path;
use std::sync::atomic::{AtomicU32, Ordering};

use axum::http::{Method, StatusCode};
use ferret_core::{PasswordChange, Recovered, RenewedRecovery, encode_recovery_key};
use ferret_server::auth::session::{Origin, lookup};
use ferret_server::ids::SidHash;
use ferret_server::wire::b64url;
use ferret_server_auth::{Clock as _, SessionScope};
use futures_util::future::join_all;
use serde_json::json;
use support::accounts::{
    CLIENT_PASSWORD, Client, PASSWORD_PATH, RECOVER_PATH, RECOVERY_PATH, Snapshot, body_bytes,
    client_account, client_session, password_change, password_put_req, put_password, put_recovery,
    recover_req, recovered, recovery_put_req, renewed_recovery, send_signed, snapshot,
    stored_wraps,
};
use support::m3::{
    HalfWay, Ledger, Rng, env_number, finish_sign_in, pk_r_of, recovery_key_opens, run_in_parallel,
    seed_of, signs_in, start_sign_in, took_recovered, took_recovery, vault_get, vault_post,
};
use support::session::{Issued, challenge_with, issue, make_fresh, nonce_for};
use support::{PEER, TestApp, Which};

/// The base seed of the runs.
const BASE_SEED: u64 = 0x4D33_4D41_5452_4958;
/// How many runs there are by default.
const RUNS: u64 = 2_000;
/// How many accounts one server holds (one per run of its share of the seeds).
const ACCOUNTS_PER_APP: u64 = 100;
/// The number of the account that no step touches.
const BYSTANDER: u8 = 250;
/// The threads the runs are spread over.
const THREADS: u64 = 4;
/// Seconds a reset session lives.
const RESET_LIFETIME: i64 = 1_800;
/// Seconds a re-authentication is fresh.
const REAUTH: i64 = 300;
/// Seconds the server keeps a nonce.
const NONCE_LIFETIME: i64 = 300;
/// Seconds a sign-in that is half-way is kept.
const HALF_WAY_LIFETIME: i64 = 60;
/// The most time one run lets pass.
const TIME_BUDGET: i64 = 3_000;
/// From this many runs on (with the base seed of the file), every row must have
/// been reached.
const RUNS_FOR_ALL_ROWS: u64 = 400;

// The bystander's session is a vault session, good for seven days. One server
// holds the runs of one thread one after another on one clock, and every run may
// let `TIME_BUDGET` seconds pass; the clock must stay far from that limit, or the
// bystander check would fail for a reason that has nothing to do with the server.
const _: () = assert!((ACCOUNTS_PER_APP as i64) * TIME_BUDGET < 7 * 24 * 3600 / 2);

/// Every row of the matrix: what must have been exercised at least once.
const ROWS: &[&str] = &[
    "backup.not_requested_on_refusal",
    "backup.requested",
    "bystander.untouched",
    "codes.refused_after_newer_code",
    "codes.refused_after_password_change",
    "codes.refused_after_recover",
    "codes.refused_after_redeem",
    "codes.refused_after_sign_in",
    "codes.refused_unknown",
    "final.newest_recovery_key_opens",
    "final.old_password_refused",
    "final.old_recovery_key_refused",
    "final.server_matches_client",
    "final.sign_in_with_the_last_password",
    "generation.only_up",
    "halfway.finishes_without_a_change",
    "halfway.refused_after_a_new_record",
    "halfway.refused_when_it_expired",
    "halfway.survives_a_new_recovery_key",
    "nonce.expired_refused",
    "nonce.replay_refused",
    "password.dead_session",
    "password.ok",
    "password.reauth_required",
    "password.second_factor_required",
    "password.stale_refused",
    "race.loser_refused",
    "race.two_viable_one_winner",
    "recover.dead_session",
    "recover.ok_full_session",
    "recover.ok_reset_session",
    "recover.stale_refused",
    "redeem.ok",
    "renew.dead_session",
    "renew.ok",
    "renew.reauth_required",
    "renew.second_factor_required",
    "renew.stale_refused",
    "sessions.admin_ended",
    "sessions.dead_after_an_end",
    "sessions.ended_by_a_password_change",
    "sessions.ended_by_a_recovery",
    "sessions.ended_by_a_redeem",
    "sessions.kept_by_a_new_recovery_key",
    "sessions.reset_ended_by_its_recovery",
    "sessions.reset_expired",
];

// ------------------------------------------------------------------ the model

/// A session of the run, as the model knows it.
struct Sess {
    origin: Origin,
    scope: SessionScope,
    sid: SidHash,
    jar: support::Jar,
    issued_at: i64,
    /// `false` once a change or a redeem ended it.
    alive: bool,
    /// When it proved the master password again.
    fresh_at: Option<i64>,
}

impl Sess {
    fn new(origin: Origin, scope: SessionScope, issued: Issued, now: i64, fresh: bool) -> Sess {
        Sess {
            origin,
            scope,
            sid: issued.sid,
            jar: issued.jar,
            issued_at: now,
            alive: true,
            fresh_at: fresh.then_some(now),
        }
    }

    /// Whether the server must take the session at `now`: not ended, and
    /// within its limits.
    fn live(&self, now: i64) -> bool {
        let age = now - self.issued_at;
        self.alive
            && match (self.origin, self.scope) {
                (_, SessionScope::AccountReset) => age <= RESET_LIFETIME,
                _ => true,
            }
    }

    fn fresh(&self, now: i64) -> bool {
        self.fresh_at
            .is_some_and(|at| (0..=REAUTH).contains(&(now - at)))
    }

    fn is_full_vault(&self) -> bool {
        self.origin == Origin::Vault && self.scope == SessionScope::Full
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Kind {
    Password,
    Renew,
    Recover,
}

impl Kind {
    fn name(self) -> &'static str {
        match self {
            Kind::Password => "password",
            Kind::Renew => "renew",
            Kind::Recover => "recover",
        }
    }
}

/// What a prepared change holds.
enum Change {
    Password(PasswordChange, String),
    Renew(RenewedRecovery),
    Recover(Box<Recovered>, String),
}

/// A change made from what the client held at version `base`, to be sent
/// through session `via`.
struct Prepared {
    kind: Kind,
    base: u64,
    /// How often the recovery key had changed when it was made.
    rk_base: u64,
    via: usize,
    change: Change,
    /// A nonce fetched when it was made, and the time it was fetched.
    early: Option<([u8; 32], i64)>,
}

/// What it takes to send a prepared change.
struct Wire {
    method: Method,
    path: &'static str,
    proof: [u8; 64],
    body: Vec<u8>,
    jar: support::Jar,
}

struct Job {
    prepared: Prepared,
    reached: bool,
    /// The nonce it carries is older than the server keeps a nonce.
    stale_nonce: bool,
    viable: bool,
    nonce: [u8; 32],
    wire: Option<Wire>,
}

/// A one-time code of the run.
struct Code {
    value: String,
    /// Why it is dead, as a row name (empty while it is live).
    why: &'static str,
}

/// A sign-in that is half-way.
struct Half {
    half: HalfWay,
    record_epoch: u64,
    renewals: u64,
    started_at: i64,
}

/// An account that no step touches, with a session of it.
struct Bystander {
    client: Client,
    jar: support::Jar,
    before: Snapshot,
}

static ADDRESS: AtomicU32 = AtomicU32::new(0);

/// An address no redeem came from before.
fn fresh_address() -> String {
    let n = ADDRESS.fetch_add(1, Ordering::Relaxed);
    format!(
        "198.{}.{}.{}",
        18 + (n / 64_516) % 2,
        (n / 254) % 254 + 1,
        n % 254 + 1
    )
}

struct Run<'a> {
    app: &'a TestApp,
    ledger: &'a Ledger,
    bystander: &'a Bystander,
    seed: u64,
    rng: Rng,
    n: u8,
    client: Client,
    email: String,
    sessions: Vec<Sess>,
    version: u64,
    record_epoch: u64,
    renewals: u64,
    /// How often the recovery key has changed (a renewal or a recovery).
    pk_changes: u64,
    password: String,
    old_passwords: Vec<String>,
    old_recovery_keys: Vec<String>,
    gens: (u32, u32),
    pending: Vec<Prepared>,
    code: Option<Code>,
    dead_codes: Vec<Code>,
    halves: Vec<Half>,
    counter: u32,
    time_used: i64,
    trace: Vec<String>,
}

impl<'a> Run<'a> {
    async fn new(
        app: &'a TestApp,
        ledger: &'a Ledger,
        bystander: &'a Bystander,
        n: u8,
        seed: u64,
    ) -> Run<'a> {
        let client = client_account(app, n).await;
        let now = i64::try_from(app.clock.now_unix()).expect("a time");
        let user = client.ids.user_id;
        let a = client_session(app, &client, SessionScope::Full, 1).await;
        let b = client_session(app, &client, SessionScope::Full, 2).await;
        let admin = issue(app, user, Origin::Admin, SessionScope::Full, 3).await;
        let sessions = vec![
            Sess::new(Origin::Vault, SessionScope::Full, a, now, true),
            Sess::new(Origin::Vault, SessionScope::Full, b, now, true),
            Sess::new(Origin::Admin, SessionScope::Full, admin, now, false),
        ];
        Run {
            app,
            ledger,
            bystander,
            seed,
            rng: Rng::new(seed),
            n,
            email: format!("client{n}@example.com"),
            client,
            sessions,
            version: 0,
            record_epoch: 0,
            renewals: 0,
            pk_changes: 0,
            password: CLIENT_PASSWORD.to_string(),
            old_passwords: Vec::new(),
            old_recovery_keys: Vec::new(),
            gens: (1, 1),
            pending: Vec::new(),
            code: None,
            dead_codes: Vec::new(),
            halves: Vec::new(),
            counter: 0,
            time_used: 0,
            trace: Vec::new(),
        }
    }

    fn now(&self) -> i64 {
        i64::try_from(self.app.clock.now_unix()).expect("a time")
    }

    fn note(&mut self, text: String) {
        self.trace.push(text);
    }

    fn fail(&self, what: &str) -> ! {
        panic!(
            "run with seed {} (account {}, version {}): {what}\nsteps so far:\n  {}\nreplay with FERRET_M3_MATRIX_ONLY={}",
            self.seed,
            self.n,
            self.version,
            self.trace.join("\n  "),
            self.seed
        )
    }

    fn ensure(&self, ok: bool, what: impl FnOnce() -> String) {
        if !ok {
            self.fail(&what());
        }
    }

    fn hit(&self, row: &str) {
        self.ledger.hit(row);
    }

    fn new_password(&mut self) -> String {
        self.counter += 1;
        format!(
            "matrix {} {} horse battery staple",
            self.seed % 1_000_000,
            self.counter
        )
    }

    /// The indexes of the sessions that are full vault sessions the server must
    /// take now.
    fn live_full(&self) -> Vec<usize> {
        let now = self.now();
        (0..self.sessions.len())
            .filter(|i| self.sessions[*i].is_full_vault() && self.sessions[*i].live(now))
            .collect()
    }

    /// The indexes of the vault sessions (full or reset) the server must take.
    fn live_vault(&self) -> Vec<usize> {
        let now = self.now();
        (0..self.sessions.len())
            .filter(|i| self.sessions[*i].origin == Origin::Vault && self.sessions[*i].live(now))
            .collect()
    }

    /// The indexes of every full vault session, live or not.
    fn all_full(&self) -> Vec<usize> {
        (0..self.sessions.len())
            .filter(|i| self.sessions[*i].is_full_vault())
            .collect()
    }

    // ----------------------------------------------------------- the steps

    /// One step, chosen by the seed.
    async fn step(&mut self) {
        let roll = self.rng.below(100);
        match roll {
            0..14 => self.prepare(Kind::Password).await,
            14..24 => self.prepare(Kind::Renew).await,
            24..34 => self.prepare(Kind::Recover).await,
            34..58 => {
                if self.pending.is_empty() {
                    self.prepare(Kind::Password).await;
                } else {
                    let pick = self.rng.below(self.pending.len());
                    self.send(vec![pick]).await;
                }
            }
            58..65 => {
                if self.pending.len() < 2 {
                    self.prepare(Kind::Renew).await;
                } else {
                    let mut picks: Vec<usize> = (0..self.pending.len()).collect();
                    // Two or three, in any order.
                    while picks.len() > 3 || (picks.len() > 2 && self.rng.chance(1, 2)) {
                        let drop = self.rng.below(picks.len());
                        picks.remove(drop);
                    }
                    self.send(picks).await;
                }
            }
            65..71 => self.redeem().await,
            71..76 => self.issue_code().await,
            76..83 => self.pass_time().await,
            83..87 => self.reauthenticate().await,
            87..90 => self.sign_in_again().await,
            90..94 => self.start_half_way().await,
            94..98 => self.finish_half_way().await,
            _ => self.second_factor().await,
        }
    }

    async fn prepare(&mut self, kind: Kind) {
        if self.pending.len() >= 4 {
            self.note("prepare: too many waiting".to_string());
            return;
        }
        let candidates = match kind {
            Kind::Password => self.live_full(),
            Kind::Renew => self.all_full(),
            Kind::Recover => self.live_vault(),
        };
        if candidates.is_empty() {
            self.note(format!("prepare {}: no session to use", kind.name()));
            return;
        }
        let via = *self.rng.pick(&candidates);
        let jar = self.sessions[via].jar.clone();
        let change = match kind {
            Kind::Password => {
                let pw = self.new_password();
                let change = password_change(self.app, &jar, &mut self.client, &pw).await;
                Change::Password(change, pw)
            }
            Kind::Renew => Change::Renew(renewed_recovery(&mut self.client)),
            Kind::Recover => {
                let pw = self.new_password();
                let made = recovered(self.app, &jar, &mut self.client, &pw, true).await;
                Change::Recover(Box::new(made), pw)
            }
        };
        self.note(format!(
            "prepare {} at version {} for session {via}",
            kind.name(),
            self.version
        ));
        // Now and then the nonce is fetched at once and used later, so that a
        // nonce that has grown old is tried too.
        let mut early = None;
        if self.rng.chance(1, 4) {
            let challenge = challenge_with(self.app, &jar).await;
            if challenge.status == StatusCode::OK {
                let nonce: [u8; 32] =
                    b64url::decode(challenge.json()["nonce"].as_str().expect("a nonce"))
                        .expect("base64url")
                        .try_into()
                        .expect("32 bytes");
                early = Some((nonce, self.now()));
            }
        }
        self.pending.push(Prepared {
            kind,
            base: self.version,
            rk_base: self.pk_changes,
            via,
            change,
            early,
        });
    }

    /// Sends the prepared changes at `picks` (all at once when there are
    /// several) and checks what came of it against the model.
    async fn send(&mut self, mut picks: Vec<usize>) {
        picks.sort_unstable();
        picks.dedup();
        let mut batch = Vec::new();
        for index in picks.into_iter().rev() {
            batch.push(self.pending.remove(index));
        }
        batch.reverse();
        let now = self.now();
        let before = snapshot(self.app, &self.client).await;
        self.app.backup_status().take_request();

        // The nonces and proofs, one request after another.
        let mut jobs: Vec<Job> = Vec::new();
        for prepared in batch {
            let session = &self.sessions[prepared.via];
            let live = session.live(now);
            let challenge = challenge_with(self.app, &session.jar).await;
            self.ensure((challenge.status == StatusCode::OK) == live, || {
                format!(
                    "a nonce for session {} was {} (the model says live: {live}): {}",
                    prepared.via,
                    challenge.status,
                    challenge.text()
                )
            });
            let reached = live && (prepared.kind == Kind::Recover || session.fresh(now));
            let stale_nonce_possible = prepared
                .early
                .is_some_and(|(_, fetched)| now - fetched >= NONCE_LIFETIME);
            let viable = reached && !stale_nonce_possible && prepared.base == self.version;
            if !live {
                jobs.push(Job {
                    prepared,
                    reached,
                    stale_nonce: false,
                    viable,
                    nonce: [0; 32],
                    wire: None,
                });
                continue;
            }
            let fresh: [u8; 32] =
                b64url::decode(challenge.json()["nonce"].as_str().expect("a nonce"))
                    .expect("base64url")
                    .try_into()
                    .expect("32 bytes");
            // A nonce is kept for 300 seconds: it is good while it is younger.
            let (nonce, stale_nonce) = match prepared.early {
                Some((early, fetched)) => (early, now - fetched >= NONCE_LIFETIME),
                None => (fresh, false),
            };
            let (method, path, body, proof) = match &prepared.change {
                Change::Password(change, _) => {
                    let body = body_bytes(&password_put_req(change));
                    let proof = change
                        .sign(&self.client.vault, &nonce, &body)
                        .expect("a proof");
                    (Method::PUT, PASSWORD_PATH, body, proof)
                }
                Change::Renew(renewed) => {
                    let body = body_bytes(&recovery_put_req(renewed));
                    let proof = renewed
                        .sign(&self.client.vault, &nonce, &body)
                        .expect("a proof");
                    (Method::PUT, RECOVERY_PATH, body, proof)
                }
                Change::Recover(made, _) => {
                    let body = body_bytes(&recover_req(made));
                    let proof = made.sign(&nonce, &body).expect("a proof");
                    (Method::POST, RECOVER_PATH, body, proof)
                }
            };
            let jar = session.jar.clone();
            jobs.push(Job {
                prepared,
                reached,
                stale_nonce,
                viable,
                nonce,
                wire: Some(Wire {
                    method,
                    path,
                    proof,
                    body,
                    jar,
                }),
            });
        }
        self.note(format!(
            "send [{}] at version {}",
            jobs.iter()
                .map(|j| format!(
                    "{}@{}/s{}",
                    j.prepared.kind.name(),
                    j.prepared.base,
                    j.prepared.via
                ))
                .collect::<Vec<_>>()
                .join(", "),
            self.version
        ));

        // All at once.
        let app = self.app;
        let results = join_all(jobs.iter().map(|job| async move {
            match &job.wire {
                Some(w) => Some(
                    send_signed(
                        app,
                        &w.jar,
                        w.method.clone(),
                        w.path,
                        &job.nonce,
                        &w.proof,
                        w.body.clone(),
                    )
                    .await,
                ),
                None => None,
            }
        }))
        .await;

        // What each came to.
        let viable_count = jobs.iter().filter(|j| j.viable).count();
        // Who won: the one change the server answered with 200.
        let mut winner: Option<usize> = None;
        for (index, (job, result)) in jobs.iter().zip(&results).enumerate() {
            if result
                .as_ref()
                .is_some_and(|res| res.status == StatusCode::OK)
            {
                self.ensure(job.viable && winner.is_none(), || {
                    format!(
                        "{} at base {} via session {} answered 200 (viable: {}, an earlier winner: {:?})",
                        job.prepared.kind.name(),
                        job.prepared.base,
                        job.prepared.via,
                        job.viable,
                        winner
                    )
                });
                winner = Some(index);
            }
        }
        self.ensure(winner.is_some() == (viable_count > 0), || {
            format!("{viable_count} viable changes in a batch and the winner is {winner:?}")
        });
        if viable_count >= 2 {
            self.hit("race.two_viable_one_winner");
        }
        // Which of two changes that raced committed first is not fixed, so the
        // trace says which did.
        self.note(format!("winner: {winner:?}"));

        // What each of the others was refused with, exactly.
        let winner_moves_pk = winner.is_some_and(|w| jobs[w].prepared.kind != Kind::Password);
        let in_batch = jobs.len() > 1;
        for (index, (job, result)) in jobs.iter().zip(&results).enumerate() {
            let kind = job.prepared.kind;
            let name = kind.name();
            let Some(res) = result else {
                self.hit(&format!("{name}.dead_session"));
                continue;
            };
            if Some(index) == winner {
                continue;
            }
            let status = res.status;
            let error = serde_json::from_slice::<serde_json::Value>(&res.body)
                .ok()
                .and_then(|v| v["error"].as_str().map(str::to_string))
                .unwrap_or_default();
            let denied = status == StatusCode::UNAUTHORIZED && error == "denied";
            let conflict = status == StatusCode::CONFLICT && error == "write_conflict";
            // In a batch the winner may end this session before the proof is read.
            let ended = in_batch && status == StatusCode::UNAUTHORIZED && error == "unauthorized";
            let what = || {
                format!(
                    "{name} (base {}, session {}) answered {status}: {}",
                    job.prepared.base,
                    job.prepared.via,
                    res.text()
                )
            };
            if !job.reached {
                self.ensure(
                    (status == StatusCode::FORBIDDEN && error == "reauth_required") || ended,
                    || format!("without a fresh re-authentication: {}", what()),
                );
                if status == StatusCode::FORBIDDEN {
                    self.hit(&format!("{name}.reauth_required"));
                }
            } else if job.stale_nonce {
                self.ensure(denied || ended, || {
                    format!("with a nonce older than 300 seconds: {}", what())
                });
                if denied {
                    self.hit("nonce.expired_refused");
                }
            } else {
                // A recovery is signed with the recovery key the server held when
                // it was made: once that key changed, the proof is refused before
                // the manifest is looked at. Everything else loses on the
                // manifest revision.
                let key_changed_before =
                    kind == Kind::Recover && job.prepared.rk_base != self.pk_changes;
                let ok = if key_changed_before {
                    denied
                } else if kind == Kind::Recover && winner_moves_pk {
                    if job.viable {
                        denied
                    } else if in_batch {
                        conflict || denied
                    } else {
                        conflict
                    }
                } else {
                    conflict
                };
                self.ensure(ok || ended, || format!("a refused change: {}", what()));
                if job.viable {
                    self.hit("race.loser_refused");
                } else {
                    self.hit(&format!("{name}.stale_refused"));
                }
            }
        }

        let mut won: Option<(Kind, usize, [u8; 32])> = None;
        if let Some(index) = winner {
            let job = jobs.swap_remove(index);
            won = Some((job.prepared.kind, job.prepared.via, job.nonce));
            self.apply(job.prepared);
        }
        self.verify(&before, won.map(|w| w.0)).await;
        self.check_sessions().await;
        if let Some((_, via, nonce)) = won
            && self.rng.chance(1, 2)
            && self.sessions[via].is_full_vault()
            && self.sessions[via].live(self.now())
        {
            self.replay(via, nonce).await;
        }
    }

    /// The model after a change the server took.
    fn apply(&mut self, prepared: Prepared) {
        let via = prepared.via;
        let via_scope = self.sessions[via].scope;
        match prepared.change {
            Change::Password(change, pw) => {
                self.client.took_password(&change, &pw);
                self.old_passwords
                    .push(std::mem::replace(&mut self.password, pw));
                self.record_epoch += 1;
                self.end_others(via, false);
                self.kill_code("password_change");
                self.hit("password.ok");
                self.hit("sessions.ended_by_a_password_change");
            }
            Change::Renew(renewed) => {
                self.old_recovery_keys
                    .push(encode_recovery_key(&self.client.recovery_key).to_string());
                took_recovery(&mut self.client, renewed);
                self.renewals += 1;
                self.pk_changes += 1;
                self.hit("renew.ok");
                self.hit("sessions.kept_by_a_new_recovery_key");
            }
            Change::Recover(made, pw) => {
                self.old_recovery_keys
                    .push(encode_recovery_key(&self.client.recovery_key).to_string());
                took_recovered(&mut self.client, *made, &pw);
                self.pk_changes += 1;
                self.old_passwords
                    .push(std::mem::replace(&mut self.password, pw));
                self.record_epoch += 1;
                let ends_itself = via_scope == SessionScope::AccountReset;
                self.end_others(via, ends_itself);
                self.kill_code("recover");
                if ends_itself {
                    self.hit("recover.ok_reset_session");
                    self.hit("sessions.reset_ended_by_its_recovery");
                } else {
                    self.hit("recover.ok_full_session");
                }
                self.hit("sessions.ended_by_a_recovery");
            }
        }
        self.version += 1;
    }

    /// Ends every session but `via` (and `via` too when `include_via`).
    fn end_others(&mut self, via: usize, include_via: bool) {
        for (index, session) in self.sessions.iter_mut().enumerate() {
            if index == via && !include_via {
                continue;
            }
            if session.alive && session.origin == Origin::Admin {
                self.ledger.hit("sessions.admin_ended");
            }
            session.alive = false;
        }
    }

    fn kill_code(&mut self, why: &'static str) {
        if let Some(mut code) = self.code.take() {
            code.why = why;
            self.dead_codes.push(code);
        }
    }

    /// After a step: the server holds what the model says, nothing more.
    async fn verify(&mut self, before: &Snapshot, won: Option<Kind>) {
        let after = snapshot(self.app, &self.client).await;
        let requested = self.app.backup_status().take_request();
        let gens = generations(&after);
        let (old_pw, old_rk) = self.gens;
        match won {
            None => {
                self.ensure(&after == before, || {
                    format!("a refused change changed the account:\n  before {before:?}\n  after  {after:?}")
                });
                self.ensure(requested.is_none(), || {
                    format!("a refused change asked for a backup: {requested:?}")
                });
                self.ensure(gens == (old_pw, old_rk), || {
                    format!(
                        "generations moved without a change: {gens:?} from {:?}",
                        self.gens
                    )
                });
                self.hit("backup.not_requested_on_refusal");
            }
            Some(kind) => {
                self.ensure(requested == Some("unlock_methods"), || {
                    format!("a committed change asked for {requested:?}")
                });
                self.hit("backup.requested");
                let (new_pw, new_rk) = gens;
                let ok = match kind {
                    Kind::Password => new_pw > old_pw && new_rk == old_rk,
                    Kind::Renew => new_rk > old_rk && new_pw == old_pw,
                    Kind::Recover => new_pw > old_pw && new_rk > old_rk,
                };
                self.ensure(ok, || {
                    format!(
                        "generations after a {kind:?}: {gens:?} from {:?}",
                        self.gens
                    )
                });
                self.hit("generation.only_up");
                self.ensure(after.manifest_rev == before.manifest_rev + 1, || {
                    format!(
                        "the manifest went from {} to {}",
                        before.manifest_rev, after.manifest_rev
                    )
                });
                self.ensure(after.vault_seq == before.vault_seq + 1, || {
                    format!(
                        "the vault seq went from {} to {}",
                        before.vault_seq, after.vault_seq
                    )
                });
                self.ensure(
                    after.pk_a == before.pk_a && after.vk_epoch == before.vk_epoch,
                    || "pk_a or the epoch moved".to_string(),
                );
                let record_moves = kind != Kind::Renew;
                self.ensure((after.record != before.record) == record_moves, || {
                    format!(
                        "the OPAQUE record after a {kind:?}: changed {}",
                        after.record != before.record
                    )
                });
                self.gens = gens;
            }
        }
        self.matches_client(&after);
    }

    /// The server holds the wraps, the manifest and the `pk_r` the client
    /// holds.
    fn matches_client(&self, after: &Snapshot) {
        let password = &self.client.password_wrap;
        let recovery = &self.client.recovery_wrap;
        let wrap = |kind: u8, record: &ferret_core::WrapRecord| {
            (
                kind,
                *record.method_id.as_bytes(),
                u32::try_from(record.kek_generation).expect("a generation"),
                record.wrap.clone(),
            )
        };
        self.ensure(
            after.wraps == vec![wrap(1, password), wrap(2, recovery)],
            || "the stored wraps are not the client's".to_string(),
        );
        self.ensure(
            u64::try_from(after.manifest_rev).ok() == Some(self.client.manifest.rev)
                && after.manifest_envelope == self.client.manifest.envelope
                && after.manifest_tag == self.client.manifest.tag,
            || "the stored manifest is not the client's".to_string(),
        );
        self.ensure(after.pk_r == pk_r_of(&self.client), || {
            "the stored pk_r is not the client's recovery key's".to_string()
        });
    }

    /// Every session the model says is live is, and every other is dead; the
    /// bystander is untouched.
    async fn check_sessions(&mut self) {
        let now = self.now();
        for index in 0..self.sessions.len() {
            let (origin, scope, sid, jar, alive, live) = {
                let s = &self.sessions[index];
                (
                    s.origin,
                    s.scope,
                    s.sid,
                    s.jar.clone(),
                    s.alive,
                    s.live(now),
                )
            };
            match origin {
                Origin::Vault => {
                    let res = vault_get(self.app, &jar, "/api/vault/recovery").await;
                    self.ensure((res.status == StatusCode::OK) == live, || {
                        format!(
                            "session {index} ({scope:?}) answered {} (the model says live: {live}, ended by an event: {})",
                            res.status, !alive
                        )
                    });
                    if !live {
                        self.ensure(res.status == StatusCode::UNAUTHORIZED, || {
                            format!("a dead session answered {}", res.status)
                        });
                        if !alive {
                            self.hit("sessions.dead_after_an_end");
                        } else if scope == SessionScope::AccountReset {
                            self.hit("sessions.reset_expired");
                        }
                    }
                }
                Origin::Admin => {
                    let row = self
                        .app
                        .state
                        .vault_db
                        .with_conn(move |conn| Ok(lookup(conn, &sid)?))
                        .await
                        .expect("a lookup")
                        .expect("the session row");
                    self.ensure(row.revoked_at.is_some() == !alive, || {
                        format!(
                            "the admin session is ended in its row: {} (the model says ended: {})",
                            row.revoked_at.is_some(),
                            !alive
                        )
                    });
                }
            }
        }
        let res = vault_get(self.app, &self.bystander.jar, "/api/vault/recovery").await;
        self.ensure(res.status == StatusCode::OK, || {
            format!("the bystander's session answered {}", res.status)
        });
        let kept = snapshot(self.app, &self.bystander.client).await;
        self.ensure(kept == self.bystander.before, || {
            "the bystander's account changed".to_string()
        });
        self.hit("bystander.untouched");
    }

    /// A nonce that was used is refused, also with a request that is good in
    /// every other way.
    async fn replay(&mut self, via: usize, nonce: [u8; 32]) {
        let now = self.now();
        let (sid, jar) = {
            let s = &mut self.sessions[via];
            s.fresh_at = Some(now);
            (s.sid, s.jar.clone())
        };
        make_fresh(self.app, sid).await;
        let before = snapshot(self.app, &self.client).await;
        self.app.backup_status().take_request();
        let renewed = renewed_recovery(&mut self.client);
        let body = body_bytes(&recovery_put_req(&renewed));
        let proof = renewed
            .sign(&self.client.vault, &nonce, &body)
            .expect("a proof");
        let res = send_signed(
            self.app,
            &jar,
            Method::PUT,
            RECOVERY_PATH,
            &nonce,
            &proof,
            body,
        )
        .await;
        self.note("replay of a used nonce".to_string());
        self.ensure(res.status == StatusCode::UNAUTHORIZED, || {
            format!("a used nonce answered {}: {}", res.status, res.text())
        });
        let after = snapshot(self.app, &self.client).await;
        self.ensure(after == before, || {
            "a replay changed the account".to_string()
        });
        self.ensure(!self.app.backup_status().has_request(), || {
            "a replay asked for a backup".to_string()
        });
        self.hit("nonce.replay_refused");
    }

    /// A one-time code made for the user (the kit's, as the Users page makes
    /// it). A newer code ends the older one.
    async fn issue_code(&mut self) {
        let code = vole_kit::auth::sign_in_codes::generate();
        let hash = vole_kit::auth::sign_in_codes::hash(&code);
        let user = self.client.ids.user_id;
        self.app
            .state
            .vault_db
            .with_conn(move |conn| {
                vole_kit::db::sign_in_codes::insert(conn, user, &hash, user)?;
                Ok(())
            })
            .await
            .expect("a code");
        self.kill_code("newer_code");
        self.code = Some(Code {
            value: code,
            why: "",
        });
        self.note("issue a code".to_string());
    }

    /// Redeems a code: the live one if there is one, else one that is dead or
    /// one that was never made.
    async fn redeem(&mut self) {
        let use_live = self.code.is_some() && self.rng.chance(3, 4);
        let (value, live, why) = if use_live {
            (self.code.as_ref().expect("a code").value.clone(), true, "")
        } else if !self.dead_codes.is_empty() && self.rng.chance(2, 3) {
            let index = self.rng.below(self.dead_codes.len());
            let dead = &self.dead_codes[index];
            (dead.value.clone(), false, dead.why)
        } else {
            (vole_kit::auth::sign_in_codes::generate(), false, "unknown")
        };
        let before = snapshot(self.app, &self.client).await;
        let res = self
            .app
            .call_raw(
                Which::Vault,
                vault_post(
                    "/api/auth/redeem",
                    &json!({ "email": self.email, "code": value }),
                )
                .header("x-forwarded-for", &fresh_address())
                .build(),
            )
            .await;
        self.note(format!(
            "redeem (a live code: {live}, why not: {why:?}) answered {}",
            res.status
        ));
        if !live {
            self.ensure(res.status == StatusCode::UNAUTHORIZED, || {
                format!(
                    "a code that is not live answered {}: {}",
                    res.status,
                    res.text()
                )
            });
            self.ensure(res.body == br#"{"error":"denied"}"#, || {
                format!(
                    "the refusal of a code is not the common one: {}",
                    res.text()
                )
            });
            if why == "unknown" {
                self.hit("codes.refused_unknown");
            } else {
                self.hit(&format!("codes.refused_after_{why}"));
            }
        } else {
            self.ensure(res.status == StatusCode::OK, || {
                format!("a live code answered {}: {}", res.status, res.text())
            });
            let mut jar = support::Jar::default();
            jar.absorb(&res.headers);
            let user = self.client.ids.user_id;
            let rows: Vec<(Vec<u8>, String)> = self
                .app
                .state
                .vault_db
                .with_conn(move |conn| {
                    let mut stmt = conn.prepare(
                        "SELECT sid_hash, scope FROM ferret_sessions
                         WHERE user_id = ?1 AND revoked_at IS NULL",
                    )?;
                    let rows = stmt
                        .query_map([user], |r| Ok((r.get(0)?, r.get(1)?)))?
                        .collect::<Result<Vec<_>, _>>()?;
                    Ok(rows)
                })
                .await
                .expect("the live sessions");
            self.ensure(rows.len() == 1 && rows[0].1 == "account_reset", || {
                format!(
                    "after a redeem the user has {} live sessions: {:?}",
                    rows.len(),
                    rows.iter().map(|r| r.1.clone()).collect::<Vec<_>>()
                )
            });
            let sid = SidHash(rows[0].0.clone().try_into().expect("32 bytes"));
            for session in &mut self.sessions {
                if session.alive && session.origin == Origin::Admin {
                    self.ledger.hit("sessions.admin_ended");
                }
                session.alive = false;
            }
            let now = self.now();
            self.sessions.push(Sess {
                origin: Origin::Vault,
                scope: SessionScope::AccountReset,
                sid,
                jar,
                issued_at: now,
                alive: true,
                fresh_at: None,
            });
            self.kill_code("redeem");
            self.hit("redeem.ok");
            self.hit("sessions.ended_by_a_redeem");
        }
        let after = snapshot(self.app, &self.client).await;
        self.ensure(after == before, || {
            "a redeem changed the account".to_string()
        });
        self.check_sessions().await;
    }

    async fn pass_time(&mut self) {
        let step = *self.rng.pick(&[1_i64, 30, 61, 299, 301, 650, 1_801]);
        if self.time_used + step > TIME_BUDGET {
            return;
        }
        self.time_used += step;
        self.app.clock.advance(u64::try_from(step).expect("a step"));
        self.note(format!("{step} seconds pass"));
        self.check_sessions().await;
    }

    /// The user proves the master password again in one of the full sessions.
    async fn reauthenticate(&mut self) {
        let live = self.live_full();
        if live.is_empty() {
            return;
        }
        let via = *self.rng.pick(&live);
        let now = self.now();
        let sid = self.sessions[via].sid;
        make_fresh(self.app, sid).await;
        self.sessions[via].fresh_at = Some(now);
        self.note(format!("session {via} re-authenticates"));
    }

    /// A new full session, as a sign-in leaves it (not fresh).
    async fn sign_in_again(&mut self) {
        let user = self.client.ids.user_id;
        let device = u8::try_from(4 + self.sessions.len() % 200).expect("a device");
        let issued = issue(self.app, user, Origin::Vault, SessionScope::Full, device).await;
        let now = self.now();
        self.sessions.push(Sess::new(
            Origin::Vault,
            SessionScope::Full,
            issued,
            now,
            false,
        ));
        self.note("a new full session".to_string());
    }

    async fn start_half_way(&mut self) {
        if self.halves.len() >= 3 {
            return;
        }
        let half = start_sign_in(self.app, &self.email, &self.password)
            .await
            .expect("the last password opens the record");
        self.halves.push(Half {
            half,
            record_epoch: self.record_epoch,
            renewals: self.renewals,
            started_at: self.now(),
        });
        self.note("a sign-in starts".to_string());
    }

    async fn finish_half_way(&mut self) {
        if self.halves.is_empty() {
            return;
        }
        let index = self.rng.below(self.halves.len());
        // A sign-in that is half-way is kept for 60 seconds. Around that
        // moment the answer depends on the exact second, so the step waits.
        let age = self.now() - self.halves[index].started_at;
        if (HALF_WAY_LIFETIME - 5..=HALF_WAY_LIFETIME + 5).contains(&age) {
            return;
        }
        let Half {
            half,
            record_epoch,
            renewals,
            ..
        } = self.halves.remove(index);
        let (res, jar) = finish_sign_in(self.app, half).await;
        let unchanged = record_epoch == self.record_epoch;
        let expired = age > HALF_WAY_LIFETIME;
        self.note(format!(
            "a sign-in finishes (the record is unchanged: {unchanged}, it is {age} seconds old) with {}",
            res.status
        ));
        if expired {
            self.ensure(
                res.status == StatusCode::UNAUTHORIZED && res.body == br#"{"error":"denied"}"#,
                || {
                    format!(
                        "a sign-in that waited {age} seconds answered {}: {}",
                        res.status,
                        res.text()
                    )
                },
            );
            self.hit("halfway.refused_when_it_expired");
        } else if unchanged {
            self.ensure(res.status == StatusCode::OK, || {
                format!(
                    "a sign-in started on the current record answered {}: {}",
                    res.status,
                    res.text()
                )
            });
            self.hit("halfway.finishes_without_a_change");
            if renewals != self.renewals {
                self.hit("halfway.survives_a_new_recovery_key");
            }
            // The new session, and the codes it ends.
            let user = self.client.ids.user_id;
            let known: BTreeSet<[u8; 32]> = self.sessions.iter().map(|s| s.sid.0).collect();
            let rows: Vec<Vec<u8>> = self
                .app
                .state
                .vault_db
                .with_conn(move |conn| {
                    let mut stmt = conn.prepare(
                        "SELECT sid_hash FROM ferret_sessions
                         WHERE user_id = ?1 AND revoked_at IS NULL AND scope = 'full' AND origin = 'vault'",
                    )?;
                    let rows = stmt
                        .query_map([user], |r| r.get(0))?
                        .collect::<Result<Vec<_>, _>>()?;
                    Ok(rows)
                })
                .await
                .expect("the sessions");
            let fresh: Vec<SidHash> = rows
                .into_iter()
                .map(|r| SidHash(r.try_into().expect("32 bytes")))
                .filter(|sid| !known.contains(&sid.0))
                .collect();
            self.ensure(fresh.len() == 1, || {
                format!("a sign-in left {} new sessions", fresh.len())
            });
            let now = self.now();
            self.sessions.push(Sess {
                origin: Origin::Vault,
                scope: SessionScope::Full,
                sid: fresh[0],
                jar,
                issued_at: now,
                alive: true,
                fresh_at: None,
            });
            self.kill_code("sign_in");
        } else {
            self.ensure(res.status == StatusCode::UNAUTHORIZED, || {
                format!(
                    "a sign-in started before a new record answered {}: {}",
                    res.status,
                    res.text()
                )
            });
            self.ensure(res.body == br#"{"error":"denied"}"#, || {
                "the refusal is not the common one".to_string()
            });
            self.hit("halfway.refused_after_a_new_record");
        }
        self.check_sessions().await;
    }

    /// With the kit's second factor on, a change of the password and a new
    /// recovery key are refused, whatever the freshness.
    async fn second_factor(&mut self) {
        let now = self.now();
        let candidates: Vec<usize> = self
            .live_full()
            .into_iter()
            .filter(|i| self.sessions[*i].fresh(now))
            .collect();
        if candidates.is_empty() {
            return;
        }
        let via = *self.rng.pick(&candidates);
        let jar = self.sessions[via].jar.clone();
        let pw = self.new_password();
        let change = password_change(self.app, &jar, &mut self.client, &pw).await;
        let renewed = renewed_recovery(&mut self.client);
        let before = snapshot(self.app, &self.client).await;
        self.app.backup_status().take_request();
        let user = self.client.ids.user_id;
        set_second_factor(self.app, user, true).await;
        let password = put_password(self.app, &jar, &self.client, &change).await;
        let renewal = put_recovery(self.app, &jar, &self.client, &renewed).await;
        set_second_factor(self.app, user, false).await;
        self.note("both changes with the second factor on".to_string());
        for (res, row) in [(&password, "password"), (&renewal, "renew")] {
            self.ensure(
                res.status == StatusCode::FORBIDDEN
                    && res.json()["error"] == "second_factor_required",
                || {
                    format!(
                        "{row} with the second factor on answered {}: {}",
                        res.status,
                        res.text()
                    )
                },
            );
            self.hit(&format!("{row}.second_factor_required"));
        }
        let after = snapshot(self.app, &self.client).await;
        self.ensure(after == before, || {
            "a refused change changed the account".to_string()
        });
        self.ensure(!self.app.backup_status().has_request(), || {
            "a change that the second factor refused asked for a backup".to_string()
        });
    }

    // ----------------------------------------------------------- the end

    /// What must hold when the run is over.
    async fn finish(&mut self) {
        self.note("the end".to_string());
        // The server holds what the client holds, and the client's account is
        // the one the model says.
        let after = snapshot(self.app, &self.client).await;
        self.matches_client(&after);
        self.hit("final.server_matches_client");

        // OPAQUE: the last password signs in, the older ones do not.
        let latest = self.password.clone();
        self.ensure(signs_in(self.app, &self.email, &latest).await, || {
            "the last password does not sign in".to_string()
        });
        self.hit("final.sign_in_with_the_last_password");
        let olds: Vec<String> = self.old_passwords.iter().rev().take(3).cloned().collect();
        for old in olds {
            let accepted = signs_in(self.app, &self.email, &old).await;
            self.ensure(!accepted, || "an older password signs in".to_string());
            self.hit("final.old_password_refused");
        }

        // The newest recovery key opens the recovery wrap; older ones do not.
        let ctx = *self.client.vault.context();
        let stored = stored_wraps(self.app, self.client.ids.account_id).await;
        let recovery_wrap = stored
            .iter()
            .find(|w| w.0 == 2)
            .map(|w| w.3.clone())
            .expect("a recovery wrap");
        let newest = encode_recovery_key(&self.client.recovery_key).to_string();
        self.ensure(
            recovery_key_opens(&ctx, &newest, &self.client.recovery_wrap, &recovery_wrap),
            || "the newest recovery key does not open the recovery wrap".to_string(),
        );
        self.hit("final.newest_recovery_key_opens");
        let olds: Vec<String> = self
            .old_recovery_keys
            .iter()
            .filter(|code| **code != newest)
            .rev()
            .take(3)
            .cloned()
            .collect();
        for old in olds {
            self.ensure(
                !recovery_key_opens(&ctx, &old, &self.client.recovery_wrap, &recovery_wrap),
                || "an older recovery key opens the recovery wrap".to_string(),
            );
            self.hit("final.old_recovery_key_refused");
        }
    }
}

/// The generations of the two stored wraps: password, recovery.
fn generations(snapshot: &Snapshot) -> (u32, u32) {
    let pick = |kind: u8| {
        snapshot
            .wraps
            .iter()
            .find(|w| w.0 == kind)
            .map(|w| w.2)
            .expect("a wrap of the type")
    };
    (pick(1), pick(2))
}

/// Turns the kit's second factor on or off for a user.
async fn set_second_factor(app: &TestApp, user: i64, on: bool) {
    app.state
        .vault_db
        .with_conn(move |conn| {
            conn.execute(
                "UPDATE users SET totp_enabled = ?2, totp_secret = CASE WHEN ?2 = 1 THEN 'x' ELSE totp_secret END WHERE id = ?1",
                rusqlite::params![user, i64::from(on)],
            )?;
            Ok(())
        })
        .await
        .expect("the second factor");
}

// ------------------------------------------------------------------ the runs

/// The app of a share of the runs, with the proxy list that makes `https`
/// count, and the bystander.
async fn app_with_bystander() -> (TestApp, Bystander) {
    let proxies = ferret_server::http::proxy_guard::ProxyList::parse(&[PEER
        .split(':')
        .next()
        .expect("an address")
        .to_string()])
    .expect("a proxy list");
    let app = TestApp::builder().proxies(proxies).build().await;
    let client = client_account(&app, BYSTANDER).await;
    let issued = client_session(&app, &client, SessionScope::Full, 1).await;
    let before = snapshot(&app, &client).await;
    (
        app,
        Bystander {
            client,
            jar: issued.jar,
            before,
        },
    )
}

/// One run: a seed on an account of the app.
async fn one_run(app: &TestApp, bystander: &Bystander, ledger: &Ledger, n: u8, seed: u64) {
    let mut run = Run::new(app, ledger, bystander, n, seed).await;
    let steps = 8 + run.rng.below(8);
    for _ in 0..steps {
        run.step().await;
    }
    // Whatever is waiting is sent before the end, one by one, so every kind
    // of leftover is exercised too.
    while !run.pending.is_empty() {
        let index = run.rng.below(run.pending.len());
        run.send(vec![index]).await;
    }
    run.finish().await;
}

#[test]
fn random_interleavings_of_password_change_recover_renewal_and_redeem_keep_one_consistent_account()
{
    let runs = env_number("FERRET_M3_MATRIX_RUNS", RUNS);
    let base = env_number("FERRET_M3_MATRIX_SEED", BASE_SEED);
    let only = std::env::var("FERRET_M3_MATRIX_ONLY")
        .ok()
        .and_then(|v| v.trim().parse::<u64>().ok());
    let ledger = Ledger::new();
    let started = std::time::Instant::now();
    if let Some(seed) = only {
        let ledger = ledger.clone();
        run_in_parallel(1, 1, |_| {
            let ledger = ledger.clone();
            async move {
                let (app, bystander) = app_with_bystander().await;
                one_run(&app, &bystander, &ledger, 1, seed).await;
            }
        });
        return;
    }
    run_in_parallel(runs, THREADS, |range| {
        let ledger = ledger.clone();
        async move {
            let mut shared: Option<(TestApp, Bystander)> = None;
            for (position, index) in range.enumerate() {
                let slot = u64::try_from(position).expect("a position") % ACCOUNTS_PER_APP;
                if slot == 0 {
                    shared = Some(app_with_bystander().await);
                }
                let (app, bystander) = shared.as_ref().expect("an app");
                let n = u8::try_from(slot + 1).expect("an account number");
                one_run(app, bystander, &ledger, n, seed_of(base, index)).await;
            }
        }
    });
    println!("{runs} runs in {:?}", started.elapsed());
    if runs >= RUNS_FOR_ALL_ROWS && base == BASE_SEED {
        ledger.assert_covers(ROWS);
    }
}

// ------------------------------------------------------------ the nonce store

/// `PUT /api/vault/unlock-methods/recovery` for `renewed`, signed over `nonce`
/// (a nonce that may be any a session of `jar` holds).
async fn put_recovery_with(
    app: &TestApp,
    jar: &support::Jar,
    client: &Client,
    renewed: &RenewedRecovery,
    nonce: &[u8; 32],
) -> support::Res {
    let body = body_bytes(&recovery_put_req(renewed));
    let proof = renewed.sign(&client.vault, nonce, &body).expect("a proof");
    send_signed(app, jar, Method::PUT, RECOVERY_PATH, nonce, &proof, body).await
}

#[tokio::test]
async fn the_nonce_store_at_capacity_refuses_the_dropped_nonce_without_dropping_other_live_nonces()
{
    // The store holds 20 000 nonces, and a new one removes the oldest (a flood
    // is held back by the limit per session, not by refusing the next real
    // request). The matrix says what that comes to: the nonce that was dropped
    // is refused, and no other live nonce is dropped with it.
    const CAPACITY: usize = 20_000;
    let app = TestApp::new().await;
    let mut client = client_account(&app, 1).await;
    let user = client.ids.user_id;
    let a = client_session(&app, &client, SessionScope::Full, 1).await;

    let first = nonce_for(&app, &a.jar).await;
    let second = nonce_for(&app, &a.jar).await;
    let mut total = 2;
    let mut middle: Option<(Issued, [u8; 32])> = None;
    let mut sessions = 0_usize;
    while total < CAPACITY {
        let device = u8::try_from(2 + sessions % 200).expect("a device");
        let filler = issue(&app, user, Origin::Vault, SessionScope::Full, device).await;
        sessions += 1;
        let mut kept = None;
        for _ in 0..30.min(CAPACITY - total) {
            let nonce = nonce_for(&app, &filler.jar).await;
            kept.get_or_insert(nonce);
            total += 1;
        }
        if sessions == 300 {
            middle = Some((filler, kept.expect("a nonce")));
        }
    }
    let (middle_session, middle_nonce) = middle.expect("a session in the middle");
    assert_eq!(
        app.challenges().store().len(),
        CAPACITY,
        "the store is full"
    );

    // One more: the oldest goes, the store stays at its limit.
    let third = nonce_for(&app, &a.jar).await;
    assert_eq!(app.challenges().store().len(), CAPACITY, "bounded");

    let before = snapshot(&app, &client).await;
    app.backup_status().take_request();
    let renewed = renewed_recovery(&mut client);
    let res = put_recovery_with(&app, &a.jar, &client, &renewed, &first).await;
    assert_eq!(
        res.status,
        StatusCode::UNAUTHORIZED,
        "the dropped nonce: {}",
        res.text()
    );
    assert_eq!(snapshot(&app, &client).await, before, "nothing changed");
    assert!(
        !app.backup_status().has_request(),
        "no backup was asked for"
    );

    // The second-oldest, one from the middle and the newest all work, each once.
    make_fresh(&app, middle_session.sid).await;
    let cases = [
        (&a.jar, second, "the second-oldest nonce"),
        (&middle_session.jar, middle_nonce, "a nonce from the middle"),
        (&a.jar, third, "the newest nonce"),
    ];
    for (jar, nonce, what) in cases {
        let renewed = renewed_recovery(&mut client);
        let res = put_recovery_with(&app, jar, &client, &renewed, &nonce).await;
        assert_eq!(res.status, StatusCode::OK, "{what}: {}", res.text());
        took_recovery(&mut client, renewed);
        let again = renewed_recovery(&mut client);
        let res = put_recovery_with(&app, jar, &client, &again, &nonce).await;
        assert_eq!(
            res.status,
            StatusCode::UNAUTHORIZED,
            "{what} is used once: {}",
            res.text()
        );
    }
    // The three that were used left the store; the dropped one was not there.
    assert_eq!(app.challenges().store().len(), CAPACITY - 3);
}

// ------------------------------------------------------------ the list of routes

/// The files under `dir` whose text holds `needle`, relative to `src`.
fn files_holding(src: &Path, needle: &str) -> BTreeSet<String> {
    fn walk(dir: &Path, out: &mut Vec<std::path::PathBuf>) {
        for entry in std::fs::read_dir(dir).expect("a folder") {
            let path = entry.expect("an entry").path();
            if path.is_dir() {
                walk(&path, out);
            } else if path.extension().is_some_and(|e| e == "rs") {
                out.push(path);
            }
        }
    }
    let mut files = Vec::new();
    walk(src, &mut files);
    files
        .into_iter()
        .filter(|f| {
            std::fs::read_to_string(f)
                .expect("a source")
                .contains(needle)
        })
        .map(|f| {
            f.strip_prefix(src)
                .expect("under src")
                .to_string_lossy()
                .replace('\\', "/")
        })
        .collect()
}

#[test]
fn every_route_that_writes_the_unlock_methods_or_ends_sessions_has_a_row_in_the_matrix() {
    let src = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    // The routes that write the unlock methods: each is a kind of change, and
    // each kind has rows (`password`, `renew`, `recover`).
    let writers = files_holding(&src, "unlock_write::apply(");
    // `vault/prf_routes.rs` adds and removes a passkey method: it changes no
    // generation, record or key that the matrix keeps a ledger of, and has its
    // own rows in `tests/prf_routes.rs` (a stale re-authentication, a dead
    // session, a spent nonce, two writers at once).
    let expected: BTreeSet<String> = [
        "vault/password.rs",
        "vault/recovery.rs",
        "vault/recover.rs",
        "vault/prf_routes.rs",
    ]
    .into_iter()
    .map(str::to_string)
    .collect();
    assert_eq!(
        writers, expected,
        "a route writes the unlock methods and the matrix has no row for it: add one to m3_matrix"
    );
    let unlock_write =
        std::fs::read_to_string(src.join("vault/unlock_write.rs")).expect("a source");
    let enum_text = unlock_write
        .split("pub enum ChangeKind {")
        .nth(1)
        .and_then(|rest| rest.split('}').next())
        .expect("the kinds of change");
    let kinds: BTreeSet<String> = enum_text
        .lines()
        .map(str::trim)
        .filter(|l| l.ends_with(',') && l.chars().next().is_some_and(char::is_uppercase))
        .map(|l| l.trim_end_matches(',').to_string())
        .collect();
    let known: BTreeSet<String> = [
        "Password",
        "Recovery",
        "Recover",
        "AddMethod",
        "RemoveMethod",
    ]
    .into_iter()
    .map(str::to_string)
    .collect();
    assert_eq!(
        kinds, known,
        "a new kind of change needs rows in the matrix"
    );

    // The code that ends every session of a user. "Revoke all" on the page of
    // devices (`auth/devices.rs`) has its rows in `tests/devices.rs`; a
    // disable and "sign out everywhere" of the Users page
    // (`accounts/actions.rs`) have theirs in `tests/admin_accounts.rs`.
    let enders = files_holding(&src, "end_all_credentials(");
    let expected: BTreeSet<String> = [
        "accounts/actions.rs",
        "auth/devices.rs",
        "auth/redeem.rs",
        "auth/session.rs",
        "vault/unlock_write.rs",
    ]
    .into_iter()
    .map(str::to_string)
    .collect();
    assert_eq!(
        enders, expected,
        "something new ends the sessions of a user and the matrix has no row for it"
    );

    // Every kind has its rows in the list.
    for kind in ["password", "renew", "recover"] {
        for suffix in ["dead_session", "stale_refused"] {
            assert!(
                ROWS.contains(&format!("{kind}.{suffix}").as_str()),
                "{kind}.{suffix}"
            );
        }
    }
}
