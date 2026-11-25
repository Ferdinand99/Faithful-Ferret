//! Native throughput of one PIN guess: Argon2id of PIN profile 1 (256 MiB,
//! t = 3, p = 1) through the same function the extension's KEK uses
//! (`pin_extension_key`).
//!
//! This is the measurement behind `PIN_OFFLINE_GUESSES_PER_SECOND`
//! (design § 7.2). Run it in release mode on a quiet machine:
//!
//! ```text
//! cargo run --release -p ferret-core --example pin_guess_rate -- 1 6 20
//! ```
//!
//! The arguments are the thread counts to try (one run each) and, as the last
//! argument when it is preceded by at least one count, the seconds each run
//! lasts. Every thread derives keys for its own PIN guesses back to back, so
//! `N` threads are `N` parallel guesses with `N` times 256 MiB of memory. Each
//! thread reports the hashes it finished and the time of its last one; the
//! rate of a run is the sum of those per-thread rates.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::print_stdout)]

use std::sync::{Arc, Barrier};
use std::time::{Duration, Instant};

use ferret_core::{Pin, PinProfile, pin_extension_key};

fn run(threads: usize, seconds: u64) -> (u64, f64) {
    let start = Arc::new(Barrier::new(threads + 1));
    let handles: Vec<_> = (0..threads)
        .map(|t| {
            let start = Arc::clone(&start);
            std::thread::spawn(move || {
                let mut salt = [0u8; 16];
                salt[0] = u8::try_from(t % 256).unwrap();
                // One hash first, so that the memory is mapped and warm.
                let pin = Pin::new(b"000000").unwrap();
                let _ = pin_extension_key(&pin, &salt, PinProfile::P1).unwrap();
                start.wait();
                let began = Instant::now();
                let mut count = 0u64;
                let mut last = Duration::ZERO;
                let mut n = 0u32;
                while began.elapsed() < Duration::from_secs(seconds) {
                    let guess = format!("{:06}", n % 1_000_000);
                    n += 1;
                    let pin = Pin::new(guess.as_bytes()).unwrap();
                    let key = pin_extension_key(&pin, &salt, PinProfile::P1).unwrap();
                    std::hint::black_box(&*key);
                    count += 1;
                    last = began.elapsed();
                }
                (count, last.as_secs_f64())
            })
        })
        .collect();
    start.wait();
    let mut total = 0u64;
    let mut rate = 0.0;
    for h in handles {
        let (count, last) = h.join().unwrap();
        total += count;
        rate += count as f64 / last;
    }
    (total, rate)
}

fn main() {
    let mut args: Vec<u64> = std::env::args()
        .skip(1)
        .map(|a| a.parse().expect("numbers only"))
        .collect();
    let seconds = if args.len() > 1 {
        args.pop().unwrap()
    } else {
        20
    };
    if args.is_empty() {
        args.push(1);
    }
    for threads in args {
        let (total, rate) = run(usize::try_from(threads).unwrap(), seconds);
        println!(
            "threads={threads} seconds={seconds} hashes={total} guesses_per_second={rate:.3} per_thread={:.3} ms_per_hash_per_thread={:.1}",
            rate / threads as f64,
            1000.0 * threads as f64 / rate
        );
    }
}
