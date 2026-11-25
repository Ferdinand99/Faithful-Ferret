# Native cost of one PIN guess (offline guesses per second)

Measured 2026-11-25 for the gate release. This is the measurement that sets
`PIN_OFFLINE_GUESSES_PER_SECOND` in `crates/ferret-core/src/pin_profile.rs`
(design § 7.2, "The cost of a guess"; § 2.2 A7). It replaces the provisional value.

## What is measured

One PIN guess is one Argon2id of PIN profile 1: 256 MiB, t = 3, p = 1, 32-byte
output, through `pin_extension_key` (the function that makes `KEK_pin`). The
harness is `crates/ferret-core/examples/pin_guess_rate.rs`, built in release mode
with the workspace profile (Argon2 at opt-level 3, LTO, no `target-cpu`). `N`
threads derive keys for different PINs back to back, each with its own 256 MiB;
a thread reports the hashes it finished and the time of its last one, and the
rate of a run is the sum of the per-thread rates.

```text
cargo run --release -p ferret-core --example pin_guess_rate -- 1 1 1 6 6 6 30
```

## Machine

- CPU: Intel Core i7-9700K, 3.6 GHz, 6 cores, no SMT, AVX2, 16 MiB L3
- Seen by the test: a KVM guest with all 6 cores and 32 GiB of RAM (31 GiB usable), run in a container limited to 6 CPUs
- Toolchain: rustc 1.99 (the project's builder image), Linux x86_64
- Quiet: 1-minute load average 0.12 before the record run, no other build or
  test container running (only idle long-lived services). The 4.90 after the run is the run itself.

## Raw numbers

Record run (30 seconds per line):

```text
threads=1 seconds=30 hashes=55  guesses_per_second=1.825 ms_per_hash_per_thread=547.9
threads=1 seconds=30 hashes=55  guesses_per_second=1.832 ms_per_hash_per_thread=545.7
threads=1 seconds=30 hashes=55  guesses_per_second=1.826 ms_per_hash_per_thread=547.6
threads=6 seconds=30 hashes=227 guesses_per_second=7.472 per_thread=1.245 ms_per_hash_per_thread=803.0
threads=6 seconds=30 hashes=226 guesses_per_second=7.474 per_thread=1.246 ms_per_hash_per_thread=802.8
threads=6 seconds=30 hashes=228 guesses_per_second=7.496 per_thread=1.249 ms_per_hash_per_thread=800.4
```

Scaling run (20 seconds per line, load average 1.26 at the start, from the build
of the same session):

```text
threads=1 guesses_per_second=1.832    threads=4 guesses_per_second=5.906
threads=2 guesses_per_second=3.472    threads=5 guesses_per_second=6.788
threads=3 guesses_per_second=4.870    threads=6 guesses_per_second=7.409 and 7.518
```

The same scaling run with `RUSTFLAGS="-C target-cpu=native"`: 1.866, 3.395,
4.907, 6.060, 6.938, 7.510 and 7.517 (no gain: the crate's code is scalar).

Reference C implementation, to see what an attacker's optimised code gains over
ours: the `argon2` command of the Debian 12 package (0~20171227-0.3+deb12u1),
`-id -t 3 -m 18 -p 1 -l 32`, one process per thread, 20 seconds, same container
and host. It includes the process start of each hash, so it is a slight underestimate.

```text
C threads=1 hashes=41  guesses_per_second=2.032
C threads=6 hashes=174 guesses_per_second=8.722
```

## Reading

- One core: 1.83 guesses per second (0.55 s a guess) in Rust, 2.03 in the C
  reference (+11 %). The C reference is the better number for an attacker.
- Six cores in parallel: 7.48 in Rust (68 % of 6 x 1.83), 8.72 in C (72 % of
  6 x 2.03). The loss is memory: each guess walks 256 MiB three times in a
  pattern that does not fit any cache.
- So this desktop machine reaches about 7.5 to 9 guesses per second. The
  constant does not describe this host; it describes "one powerful computer".

## Derivation of the constant

Design § 7.2 says "about 100 guesses per second on one powerful machine ... possibly
two to three times more on a large server", and "32 guesses at once need 8 GiB". The
host above is a six-core desktop, so the measurement is scaled to a reference
machine, and the scaling is explicit:

| Step | Value | Why |
|---|---|---|
| Reference machine | one server with 64 cores and memory for 64 parallel guesses (16 GiB) | the review's upper range (32 to 64 cores); the largest single machine an attacker can rent |
| Per-core rate | 2.03 per second | the best single-thread rate measured (the C reference) |
| Parallel efficiency | 0.72 | measured on this host with all cores busy (8.72 / (6 x 2.03)); assumed to hold for 64 cores |
| Result | 64 x 2.03 x 0.72 = 93.5 guesses per second | |
| Constant | 100, rounded up to the next ten | so the text never understates the attack |

Cross-check by memory traffic (an estimate, not a measurement): one guess moves
about 2 GiB (first pass writes 256 MiB and reads about 256 MiB; the two later
passes each read the old block, read the reference block and write the new
one). At 100 guesses per second that is about 200 GiB per second, which is
the sustained bandwidth of one socket with eight channels of DDR4-3200 (peak
205 GB/s) or of one large DDR5 socket. So 100 per second is about what one
large server can feed, and a much higher number needs more memory channels than
one machine has. The efficiency of 0.72 holds on this desktop with two memory
channels and 6 cores; on a 64-core server it is an assumption, and it is the
weakest step. Without any memory loss (efficiency 1.0) the figure would be 130.

The result: the earlier value of 100 stands. It is 7 % above the derived 93.5
and 23 % below the no-loss bound of 130. The earlier review expected the native
rate to be two to three times higher than 100; the measurement does not
support that (one core takes 0.55 s here, against 0.37 s for the WebAssembly
probe on a faster desktop core, and parallel guesses are limited by memory).

## Not covered

- GPUs and other special hardware, and many machines: the "100 machines" column
  of the table in § 7.2 is the 100x scaling of this figure, not a measurement.
  A GPU with high-bandwidth memory is bounded by the same memory-traffic
  arithmetic (about 2 GiB per guess) and by its memory size (256 MiB per guess).
- A real 64-core server was not available. If one becomes available, run the
  harness with `-- 64 30` and replace the efficiency above with the measured one.
