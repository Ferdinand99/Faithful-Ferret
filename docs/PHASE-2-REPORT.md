# Phase 2: results

Phase 2 is the server half of the OPAQUE sign-in, as a library: `crates/ferret-server-auth`.
It holds the registration and sign-in steps, the sealed login state, the answers for names
without an account, the rules for what a session may start, the single-use challenges and
signed requests, the rate limit hooks, and the loading of the server's secret files. It has
no HTTP, no database and no logging. This page records what was measured, which decisions
were taken, and which limits remain. It describes the repository at the end of the phase;
numbers were measured on the build host named in each section and will move as the code
changes. It is written in the same form as [`PHASE-4A-REPORT.md`](PHASE-4A-REPORT.md).

No external audit has been done and none is planned (see [`REVIEW-PACKAGE.md`](REVIEW-PACKAGE.md)).

## Summary

| Question | Answer |
|---|---|
| Does the library cover what phase 2 set out to do? | Yes: registration, sign-in and re-authentication, made-up answers for unknown and disabled names, sealed single-use login state, session scopes, challenges and signed requests, rate limit hooks, secret files and the start-up decision |
| Tests | 948 tests pass in the workspace (core, server library, vector generator, WebAssembly binding), with and without `test-support` |
| Vectors | `vectors/VERSION` 24; two new server files (`server-opaque.json`, 76 cases, and `server-secrets.json`, 105 cases); `vectors/VERSION` is 24 after the generator change; RFC 9807 appendix C.1.1 and C.1.2 server messages reproduced byte for byte |
| Fuzzing | 18 targets, 6 of them for the server library; the seed and regression replay is clean; one full nightly run (20 minutes per target) was clean on an earlier commit; the run on the final code is the gate for the release, see "Fuzzing" |
| Coverage | Server library 96.14 % lines and 93.63 % branches (thresholds 95 and 90); core total 96.52 % lines |
| Constant time | Every gated server bench is under 4.5 at 10^7 measurements, three repeats, at the optimisation level that is shipped, with controls; see the limits below |
| Dependencies | `cargo deny` and `cargo vet --locked` pass with no new exception; the library adds no new duplicate version to the tree |
| Release | The library follows the version of the repository (one component); the lock files that name it are in the release configuration, and the checks that read the version no longer fail when it changes |

## Test run for this report

Run in the builder image on a Docker host from the state of the repository at the time of
writing: formatting (including `ct/harness`), clippy for native (`--workspace
--all-targets`) and `wasm32-unknown-unknown`, `cargo test --workspace` with and without
`--features test-support` (948 passed each time, none failed), the vector check, the
test-support script and its self-test, `cargo deny --all-features check`, `cargo vet
--locked`, the MSRV (1.88) check of the core and of the server library, the lock check of
`ct/dudect`, and the rustdoc build of the core and the server library with warnings denied.
The WebAssembly job, the Node tests and the browser runners do not build any server code and
are unchanged; they run in CI.

## Size

About 9 200 lines of Rust in `crates/ferret-server-auth/src/` outside the test-support code,
which is another 1 900 lines and never part of a release. The integration tests under
`tests/` (with their shared support module) are about 10 300 lines. Counted with `wc -l`, comments and blank lines included, and
the unit tests inside the modules included.

The library is not in the WebAssembly package (`the_server_library_is_not_in_the_webassembly_build`
fails if the binding starts to depend on it), so the size of the package does not change.

## Vectors

`vectors/VERSION` went from 22 to 23 with the server files, and to 24 when the generator stopped writing the crate version into every file (see "Release"). The two server files hold the operations `server.*`:
registration and sign-in messages, the sealed state, the secret file format, the proofs of
signed requests and the answers for made-up names. The server messages of RFC 9807 appendix
C.1.1 and C.1.2 are reproduced byte for byte by the library. Seven proof vectors were also
recomputed independently during review. The independent JavaScript reference in
`tools/xcheck` does not cover the server operations (it does not implement OPAQUE either, see
the risks of phase 4A), so `server.replace_authorize` and the OPAQUE operations are marked as
not covered there.

## Fuzzing

Eighteen targets run in CI: the twelve of the core and six for the server library
(`fuzz_server_messages`, `fuzz_server_secret_file`, `fuzz_server_sealed_state`,
`fuzz_server_login_name`, `fuzz_server_wire_fields`, `fuzz_server_replace_body`). A check
(`scripts/check-fuzz-targets.mjs`) lists every function of the library that reads bytes from
a client or a file and fails when one has no target and no stated reason; it covers 44
functions: 16 with a target of their own and 28 exempt (14 are reached through another entry
point, 9 handle files and paths, 5 have a reason of their own).

- Replay of the seed corpus and the regression inputs for all 18 targets: clean (run for this
  report).
- Pull-request smoke, 60 seconds per target: clean on every run.
- Nightly run of 31 October 2026, 20 minutes per target, all 18 jobs clean, on commit b787078.
  That commit is before the last change to `login_start`, `prelogin_answer` and the throttle
  keys, so this run did not fuzz the code as shipped.
- Nightly run of 1 November 2026 on commit baf8aee (the last change to the library code), 20
  minutes per target, all 18 jobs clean.
- Longer runs while the targets were written: 10 minutes on three of them, no crash in the
  library. Three crashes in the first runs were mistakes in the fuzz harnesses and were fixed
  before the clean runs.

The gate for the release is one full nightly run on the final code, that is the first nightly
run after the release-path changes are on `main`. It has to pass before the release pull
request is merged. Only tests, CI and documentation (and the vector generator, which the
fuzz targets do not use) differ from baf8aee in the library after that commit.

## Coverage

Measured with `cargo llvm-cov --branch` on the pinned nightly (`scripts/lanbox-coverage.sh`):

| Module | Files | Lines | Needed | Branches | Needed |
|---|---|---|---|---|---|
| integrity | 4 | 98.39 | 95 | 92.71 | 90 |
| wrap | 1 | 98.54 | 95 | 93.75 | 90 |
| envelope | 1 | 98.82 | 95 | 93.75 | 90 |
| codes | 2 | 99.21 | 95 | 92.86 | 90 |
| text | 3 | 99.32 | 95 | 90.63 | 90 |
| export | 2 | 97.86 | 95 | 94.12 | 90 |
| server_auth | 16 | 96.14 | 95 | 93.63 | 90 |
| all measured files (core and server library) | 68 | 96.52 | 90 | 91.88 | none |

The unit tests inside the modules are counted, as for the core.

## Constant-time checks

The library compares and selects with the code of the core's constant-time harness
(`ct/harness`), so the analysis of the core covers its `ct_eq` and `ct_select_*`. What the
phase added is the review of every place the library compares or chooses (`ct/TRIAGE.md`,
"Server library"), tests that keep the list of places from growing unnoticed, and timing tests
of the library's public functions.

The first timing run at 10^7 on a quiet host found a real difference: the library branched on
whether an account had been found, in the unpacking of the lookup and in the choice of the
pre-login answer (t of -12.3, +6.3 and +18.3). It was fixed by choosing between the real record
and a stand-in record of the same shape without a branch, copying the chosen record into a
buffer of the call, and checking the compiled code for conditional jumps. The first fix
(commit 6f8743b) improved the pre-login bench to -4.20 and `known_vs_disabled` to +4.27, but
`server_login_start_known_vs_unknown` was +17.41 and `server_finish_credential_vs_account`
+25.92. The analysis found two causes: a small real asymmetry in the library (the stand-in record
was read late and cold, on the no-account path only), amplified by the bench, and, for the finish
bench, a fault in the bench. The record is now copied into a buffer of the call on every path.
Two later failures of the finish bench at the shipped optimisation level
(-13.95, and -19.66 with its own null control at -24.57, which compares equal bytes) were faults
in the bench, not in the library: a class test in the preparation of the inputs, which the
compiler turned into a jump. The benches were rebuilt without that test, and the setup is shown
to see a leak by the leaky controls.

Final run at the shipped profile (opt-level 3, LTO), `CT_ONLY=server`, 10^7 measurements, three
repeats, quiet host (load 0.81 at the start, 1.07 at the end):

| Bench | \|t\|, three repeats |
|---|---|
| `server_login_start_known_vs_unknown` | 2.63, 2.28, 2.23 |
| `server_login_start_known_vs_disabled` | 2.37, 1.25, 1.47 |
| `server_prelogin_known_vs_unknown` | 1.48, 1.43, 1.25 |
| `server_state_binding` (smoke test) | 1.88, 1.96, 1.48 |
| `server_finish_credential_vs_account` (smoke test) | 2.00, 0.95, 2.31 |
| null controls (four) | all under 3.9 |
| leaky controls | \|t\| of 8e4 to 3e5 |
| `info_server_prelogin_resolve_credential` (not gated, test-support only; cause not known) | 7.09, 7.18, 11.20 |

The results file is `ct/results/dudect-lanbox-server.md`; the runs on e4e6334, 6f8743b and
29fbc6b and two diagnosis runs are kept next to it. The runs behind -13.95 and -19.66/-24.57 are
recorded in `ct/TRIAGE.md` only. The limit is |t| < 4.5.

## Dependencies

`cargo deny` and `cargo vet --locked` pass with no new exception. The library takes the same
pinned versions as the core, so it brings no new version of any crate into the lock. The duplicate versions in its tree are the ones of the core (the previous generation of
RustCrypto under `opaque-ke`), each listed in `deny.toml` with its reason.

## Release

Two checks broke on the first version bump after the library was added, and both are fixed.
The vector generator wrote the crate version into the header of every file in
`vectors/internal/`, so any release made `vectorgen check` and the tests that run it fail; the
header now carries a fixed marker, as the `commit` field already did, and `vectors/VERSION`
went to 24 with the regenerated files. A test of the server's workspace
(`release_please_extra_files_name_three_server_lock_paths_and_the_manifest_version`) had the old
version written into it; it reads it from the manifest now. To show that a release goes through,
the release updaters were applied to a copy of the repository at version 0.2.0, and on that
copy all of these pass: the vector check, the 948 tests of the workspace, the 391 tests of the
server (395 with the test clock of the end-to-end image), the two lock checks, the
test-support check, a locked `cargo metadata` of the fuzz and timing workspaces, and the
coverage run (library 96.14 % lines, 93.63 % branches). The release pull request is
refreshed by release-please only when its text changes, so the commit that lands this work is a
visible `fix:`, and the configuration sets `always-update`.

## Decisions

- **No component of its own.** `ferret-server-auth` is a workspace member with
  `version.workspace = true` and `publish = false`. It carries the version of the one
  component (tags `vX.Y.Z`), because its only consumer is the server, which takes it by a path
  dependency from the same repository (so its own lock lists the library, and the library's
  version is the repository's), and the client and server must run the same OPAQUE suite; two lines of versions would
  describe one contract twice. The release configuration lists the lock files that name the
  library (`Cargo.lock`, `fuzz/Cargo.lock`, `ct/dudect/Cargo.lock` and the server's own lock);
  a preview of the release showed that without the last two entries a locked build of the
  fuzz and timing workspaces fails after a release. Phase 2 therefore ships in 0.2.0, since the
  core gained the `server-suite` feature.
- **Test tooling stays out of releases.** `scripts/check-no-test-support.sh` checks that the
  release graph of the core and the binding has neither `test-support` nor `server-suite`, that
  no release crate depends on the server library or the vector generator, and that the server
  library and the server binary do not enable `test-support` in their normal graph, including
  through feature chains.
- **The library counts nothing and asks first.** Every entry point asks a `Throttle` before it
  does effectful work and reports the outcome; the library groups the address itself.
- **A full state store drops the oldest state**, instead of refusing: a refusal would let a flood
  stop every sign-in; an eviction costs one in-flight sign-in its retry.
- **The stored profile decides**, never the request. A recovery may set any profile the rules
  accept, including a lower one, as the way out of a wrongly claimed profile; a password change
  or upgrade cannot lower it.
- **Re-authentication is bound to the session's account** inside the library, compared in
  constant time, with one public answer for every mismatch.

## Risks that remain

- **Timing evidence is for the library only.** The tests do not see the database lookup that
  builds the account lookup, the HTTP layer, TLS or the network. The server has a gross check
  of the answers to a known and an unknown name (`response_length_and_median_delay_known_vs_unknown`:
  length and median delay, with a slack of 50 % plus 2 ms; it catches a large difference only).
  A test of the distribution of the delay and of the bytes is not written, and the pre-login
  route does not exist yet. Statistical tests on one
  CPU cannot prove the absence of a leak; the compares in the finish step are shown to be
  `ct_eq` by the call-site test and by reading, not by timing alone. `info_server_prelogin_resolve_credential`
  stays above the limit (7.09 to 11.20) and its cause is not known: it is not gated because no
  request path calls the function and the function is behind `test-support`.
- **Wiping is best effort.** The sealed state's content and the `ServerLogin` value of `opaque-ke`
  are checked to wipe on drop (`tests/zeroize.rs`). Copies made while a value is moved, on the
  stack, in the allocator or in swap are out of reach.
- **Parsers of `opaque-ke` accept trailing bytes.** The library checks exact lengths before
  parsing; a test locks the upstream behaviour so a change is noticed.
- **Made-up answers are a weak disguise on a small server.** An unknown or disabled name is
  answered with a profile and a secret-key hint (`sk_hint`, whether the account uses a secret
  key) drawn from the shares of the real accounts. The two values are drawn separately, so
  their pairing does not follow the joint spread; the shares are rounded, so a name can
  change its made-up answer when a share crosses a bucket; and with a handful of accounts a
  minority answer is weak evidence that the account is real. For a self-hosted server with few
  accounts this is the main enumeration path left after timing. Nothing in the library can
  change it; the pre-login policy loader of the server documents the same limit.
- **Secret files.** The loader refuses a file that is not owned by the effective user or root. On
  a file system that remaps owners (root-squashed NFS, some bind mounts and CIFS shares) this
  refuses a valid file; the cause is named in the error. A failed start may still have written
  the set-up file, a short file after a crash costs a two second wait, and `O_NOFOLLOW` is not
  used because it needs an architecture-specific constant without a new dependency. Only the
  set-up file has a fingerprint: a pre-login secret restored from the wrong backup is not
  detected, and every made-up answer changes without a message.
- **Left to the endpoint code.** A signed proof is the third of three things that Fase 1 § 4.6
  asks of a sensitive request. The library checks only the proof. The endpoint must also require
  (a) the password again within five minutes (a re-authentication login) and (b) a fresh second
  factor when the account has one, before it calls `authorize_replacement` or
  `authorize_signed`. Also the endpoint's: the check that an account is not disabled after
  `login_finish` (the library returns the verified credential and documents it), the promotion
  from the partial session to the full one after the second factor, the rule that only
  `Outcome::Failure` may charge the key of an account (counting successes would turn a user's own
  sign-ins into 429 and would reveal that the account exists), the numbers of the rate limits
  (today the server limits `LoginStart` and `RegisterStart` only, so the per-account back-off of
  § 11 is not in force), the wire encoding of the nonce and the proof, status codes, the
  tables, the transaction around a password change, the revocation of other sessions and device
  tokens after a change, the check that the method named in a remove body is the one in the URL,
  that a recovery updates the stored `sk_hint`, and the log lines. The library gives the checks;
  it cannot make a caller use them, and the endpoint does a database read and one record parse
  before the library asks the throttle, so "first" holds inside the library only.
- **Third-party code is not re-verified:** `opaque-ke`, `voprf`, the RustCrypto crates and Argon2id
  (see the risks of phase 4A).
- **The vectors were made by the project that wrote the library.** The RFC 9807 server messages
  are independent of it; the other cases are not.

## What is next

The server (`crates/ferret-server`, which takes the library by a path dependency) has the
registration, sign-in, session scope, rate limit and start-up wiring on top of the library. What
has no caller yet is the signed-request side: nothing calls `issue_challenge`,
`authorize_replacement` or `authorize_signed`, because the routes for a password change, a
recovery, a recovery key change and a rekey are stubs. Those routes, with the re-authentication
and second factor they require, the revocation after a change, and the test of the delay and
byte distribution of the running server, come next.
