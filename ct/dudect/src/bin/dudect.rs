//! The native timing tests: `dudect` (Reparaz, Balasch, Verbauwhede) through
//! `dudect-bencher`. One bench per [`ferret_ct::Target`].
//!
//! Each bench takes `FERRET_CT_N` measurements (default 1 000 000, the number
//! the design asks for; the CI smoke job sets fewer) and prints
//! `max t`. `scripts/lanbox-ct.sh` fails a gating bench when `|max t|` is 4.5
//! or more.
//!
//!     cargo run --release -p ferret-ct --features bench --bin dudect
//!     cargo run --release -p ferret-ct --features bench --bin dudect -- --filter commit_check

use dudect_bencher::rand::Rng;
use dudect_bencher::{BenchRng, Class, CtRunner, ctbench_main};
use ferret_ct::{Class as Side, Target, targets};
use std::sync::atomic::{Ordering, fence};

/// The number of measurements per bench.
fn measurements() -> usize {
    std::env::var("FERRET_CT_N")
        .ok()
        .and_then(|v| v.parse::<usize>().ok())
        .filter(|n| *n >= 1_000)
        .unwrap_or(1_000_000)
}

/// `prepare` may branch on the class; the global history of the branch
/// predictor would carry that into the first branches of the timed code. A
/// fixed run of taken back-edges leaves the same history for both classes.
/// It runs outside the timer.
#[inline(never)]
fn level_branch_history() {
    for k in 0..1024u32 {
        std::hint::black_box(k);
    }
}

fn bench(runner: &mut CtRunner, rng: &mut BenchRng, name: &str) {
    let mut target: Box<dyn Target + Send> = targets(rng.next_u64())
        .into_iter()
        .find(|t| t.name() == name)
        .expect("a target of this name");
    let reps = target.reps();
    let n = measurements();

    // The class and the input of every measurement are drawn first, so that
    // the generator does not run between the timings.
    let mut plan = Vec::with_capacity(n);
    for _ in 0..n {
        let word = rng.next_u64();
        plan.push((word & 1 == 0, (word >> 1) as usize));
    }
    // The input is copied into the target's working cell before the timer
    // starts, and one call site serves both classes: the timed code, and the
    // memory it reads, are the same for Left and Right.
    for (left, i) in plan {
        target.prepare(Side::from_bit(u32::from(!left)), i);
        // Let the stores of the copy drain before the timer starts, so that
        // the timed code does not start in the shadow of a class-dependent
        // copy.
        fence(Ordering::SeqCst);
        level_branch_history();
        let class = if left { Class::Left } else { Class::Right };
        runner.run_one(class, || target.run(reps));
    }
}

fn commit_check(r: &mut CtRunner, rng: &mut BenchRng) {
    bench(r, rng, "commit_check");
}
fn mac_verify(r: &mut CtRunner, rng: &mut BenchRng) {
    bench(r, rng, "mac_verify");
}
fn key_eq(r: &mut CtRunner, rng: &mut BenchRng) {
    bench(r, rng, "key_eq");
}
fn crockford_decode(r: &mut CtRunner, rng: &mut BenchRng) {
    bench(r, rng, "crockford_decode");
}
fn unpad_ct(r: &mut CtRunner, rng: &mut BenchRng) {
    bench(r, rng, "unpad_ct");
}
fn base32_decode(r: &mut CtRunner, rng: &mut BenchRng) {
    bench(r, rng, "base32_decode");
}
fn kek_pw_commit_path(r: &mut CtRunner, rng: &mut BenchRng) {
    bench(r, rng, "kek_pw_commit_path");
}
fn info_unwrap_valid_vs_bad_commit(r: &mut CtRunner, rng: &mut BenchRng) {
    bench(r, rng, "info_unwrap_valid_vs_bad_commit");
}

fn info_unpad_position_zeros(r: &mut CtRunner, rng: &mut BenchRng) {
    bench(r, rng, "info_unpad_position_zeros");
}
fn info_unpad_content(r: &mut CtRunner, rng: &mut BenchRng) {
    bench(r, rng, "info_unpad_content");
}
fn control_unpad_leaky(r: &mut CtRunner, rng: &mut BenchRng) {
    bench(r, rng, "control_unpad_leaky");
}
fn info_base32_a_vs_z(r: &mut CtRunner, rng: &mut BenchRng) {
    bench(r, rng, "info_base32_a_vs_z");
}
fn info_base32_upper_vs_lower(r: &mut CtRunner, rng: &mut BenchRng) {
    bench(r, rng, "info_base32_upper_vs_lower");
}
fn info_base32_random_pair(r: &mut CtRunner, rng: &mut BenchRng) {
    bench(r, rng, "info_base32_random_pair");
}
fn info_unpad_random_pair(r: &mut CtRunner, rng: &mut BenchRng) {
    bench(r, rng, "info_unpad_random_pair");
}
fn info_unpad_same(r: &mut CtRunner, rng: &mut BenchRng) {
    bench(r, rng, "info_unpad_same");
}
fn control_null(r: &mut CtRunner, rng: &mut BenchRng) {
    bench(r, rng, "control_null");
}
fn control_leaky(r: &mut CtRunner, rng: &mut BenchRng) {
    bench(r, rng, "control_leaky");
}

fn server_login_start_known_vs_unknown(r: &mut CtRunner, rng: &mut BenchRng) {
    bench(r, rng, "server_login_start_known_vs_unknown");
}
fn server_login_start_known_vs_disabled(r: &mut CtRunner, rng: &mut BenchRng) {
    bench(r, rng, "server_login_start_known_vs_disabled");
}
fn server_prelogin_known_vs_unknown(r: &mut CtRunner, rng: &mut BenchRng) {
    bench(r, rng, "server_prelogin_known_vs_unknown");
}
fn info_server_prelogin_resolve_credential(r: &mut CtRunner, rng: &mut BenchRng) {
    bench(r, rng, "info_server_prelogin_resolve_credential");
}
fn server_state_binding(r: &mut CtRunner, rng: &mut BenchRng) {
    bench(r, rng, "server_state_binding");
}
fn server_finish_credential_vs_account(r: &mut CtRunner, rng: &mut BenchRng) {
    bench(r, rng, "server_finish_credential_vs_account");
}
fn info_server_finish_state_vs_missing(r: &mut CtRunner, rng: &mut BenchRng) {
    bench(r, rng, "info_server_finish_state_vs_missing");
}

fn control_server_login_start_null(r: &mut CtRunner, rng: &mut BenchRng) {
    bench(r, rng, "control_server_login_start_null");
}
fn info_server_login_start_lookup_only(r: &mut CtRunner, rng: &mut BenchRng) {
    bench(r, rng, "info_server_login_start_lookup_only");
}
fn info_server_login_start_real_vs_made_up(r: &mut CtRunner, rng: &mut BenchRng) {
    bench(r, rng, "info_server_login_start_real_vs_made_up");
}

fn control_server_prelogin_null(r: &mut CtRunner, rng: &mut BenchRng) {
    bench(r, rng, "control_server_prelogin_null");
}
fn control_server_finish_null(r: &mut CtRunner, rng: &mut BenchRng) {
    bench(r, rng, "control_server_finish_null");
}
fn info_server_login_start_fixed_vs_pool(r: &mut CtRunner, rng: &mut BenchRng) {
    bench(r, rng, "info_server_login_start_fixed_vs_pool");
}

ctbench_main!(
    commit_check,
    mac_verify,
    key_eq,
    crockford_decode,
    unpad_ct,
    base32_decode,
    kek_pw_commit_path,
    info_unwrap_valid_vs_bad_commit,
    info_unpad_position_zeros,
    info_unpad_content,
    info_unpad_random_pair,
    info_unpad_same,
    info_base32_a_vs_z,
    info_base32_upper_vs_lower,
    info_base32_random_pair,
    control_null,
    control_leaky,
    control_unpad_leaky,
    server_login_start_known_vs_unknown,
    server_login_start_known_vs_disabled,
    server_prelogin_known_vs_unknown,
    info_server_prelogin_resolve_credential,
    control_server_login_start_null,
    info_server_login_start_lookup_only,
    info_server_login_start_real_vs_made_up,
    control_server_prelogin_null,
    control_server_finish_null,
    info_server_login_start_fixed_vs_pool,
    server_state_binding,
    server_finish_credential_vs_account,
    info_server_finish_state_vs_missing
);
