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
| Vectors | `vectors/VERSION` 23; two new server files (`server-opaque.json`, 76 cases, and `server-secrets.json`, 105 cases); RFC 9807 appendix C.1.1 and C.1.2 server messages reproduced byte for byte |
| Fuzzing | 18 targets, 6 of them for the server library; the seed and regression replay is clean; the first night of 20 minutes per target was clean; see "Fuzzing" for the second night |
| Coverage | Server library 96.14 % lines and 93.63 % branches (thresholds 95 and 90); core total 96.52 % lines |
| Constant time | Every gated server bench is under 4.5 at 10^7 measurements, three repeats, at the optimisation level that is shipped, with controls; see the limits below |
| Dependencies | `cargo deny` and `cargo vet --locked` pass with no new exception; the library adds no new duplicate version to the tree |
| Release | The library follows the version of the repository (one component); the lock files that name it are in the release configuration |

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
`tests/` are about 9 500 lines. Counted with `wc -l`, comments and blank lines included, and
the unit tests inside the modules included.

The library is not in the WebAssembly package (`the_server_library_is_not_in_the_webassembly_build`
fails if the binding starts to depend on it), so the size of the package does not change.

## Vectors

`vectors/VERSION` went from 22 to 23. The two server files hold the operations `server.*`:
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
a client or a file and fails when one has no target and no stated reason; it covers 43
functions, 5 of them exempt with a reason.

- Replay of the seed corpus and the regression inputs for all 18 targets: clean (run for this
  report).
- Pull-request smoke, 60 seconds per target: clean on every run.
- First nightly run with the server targets, 20 minutes per target (31 October 2026): all 18
  jobs clean.
- Second nightly run: see the note at the end of this section.
- Longer runs while the targets were written: 10 minutes on three of them, no crash in the
  library. Three crashes in the first runs were mistakes in the
  fuzz harnesses and were fixed before the clean runs.

The two nights the release asks for are the nightly runs of 31 October and 1 November 2026
on the code of the library as merged. The status of the second night is recorded in the pull
request that carries this page.

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
| core total | 68 | 96.52 | 90 | 91.88 | none |

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
buffer of the call, and checking the compiled code for conditional jumps. Two later failures
(`server_finish_credential_vs_account` at -13.95 and -19.66, and its own null control at -24.57,
which compares equal bytes) were faults in the bench, not in the library: a class test in the
preparation of the inputs, which the compiler turned into a jump at the optimisation level that
ships. The benches were rebuilt without that test and the setup is shown to see a leak by the
leaky controls.

Final run at the shipped profile (opt-level 3, LTO), `CT_ONLY=server`, 10^7 measurements, three
repeats, quiet host (load 0.81 at the start, 1.07 at the end):

| Bench | t, three repeats |
|---|---|
| `server_login_start_known_vs_unknown` | 2.63, 2.28, 2.23 |
| `server_login_start_known_vs_disabled` | 2.37, 1.25, 1.47 |
| `server_prelogin_known_vs_unknown` | 1.48, 1.43, 1.25 |
| `server_state_binding` (smoke test) | 1.88, 1.96, 1.48 |
| `server_finish_credential_vs_account` (smoke test) | 2.00, 0.95, 2.31 |
| null controls (four) | all under 3.9 |
| leaky controls | \|t\| of 8e4 to 3e5 |
| `info_server_prelogin_resolve_credential` (not gated, test-support only) | 7.09, 7.18, 11.20 |

The results file is `ct/results/dudect-lanbox-server.md`; the earlier runs of the fix are kept
next to it. The limit is |t| < 4.5.

## Dependencies

`cargo deny` and `cargo vet --locked` pass with no new exception. The library takes the same
pinned versions as the core, so it brings no new version of any crate into the lock. The duplicate versions in its tree are the ones of the core (the previous generation of
RustCrypto under `opaque-ke`), each listed in `deny.toml` with its reason.

## Decisions

- **No component of its own.** `ferret-server-auth` is a workspace member with
  `version.workspace = true` and `publish = false`. It carries the version of the one
  component (tags `vX.Y.Z`), because its only consumer is the server, which pins it to a tag,
  and the client and server must run the same OPAQUE suite; two lines of versions would
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
  builds the account lookup, the HTTP layer, TLS or the network. The test of the running
  server (same bytes and delay distribution for known and unknown names) is still to be written,
  and so is the one for the pre-login route, which does not exist yet. Statistical tests on one
  CPU cannot prove the absence of a leak; the compares in the finish step are shown to be
  `ct_eq` by the call-site test and by reading, not by timing alone. `info_server_prelogin_resolve_credential`
  stays above the limit because it is not a shipped path.
- **Wiping is best effort.** The sealed state's content and the `ServerLogin` value of `opaque-ke`
  are checked to wipe on drop (`tests/zeroize.rs`). Copies made while a value is moved, on the
  stack, in the allocator or in swap are out of reach.
- **Parsers of `opaque-ke` accept trailing bytes.** The library checks exact lengths before
  parsing; a test locks the upstream behaviour so a change is noticed.
- **Secret files.** The loader refuses a file that is not owned by the effective user or root. On
  a file system that remaps owners (root-squashed NFS, some bind mounts and CIFS shares) this
  refuses a valid file; the cause is named in the error. A failed start may still have written
  the set-up file, a short file after a crash costs a two second wait, and `O_NOFOLLOW` is not
  used because it needs an architecture-specific constant without a new dependency.
- **Left to the endpoint code.** The wire encoding of the nonce and the proof, status codes, the
  numbers of the rate limits, the tables, the transaction around a password change, the
  revocation of other sessions and device tokens after a change, the check that the method
  named in a remove body is the one in the URL, and the log lines. The library gives the checks;
  it cannot make a caller use them.
- **Third-party code is not re-verified:** `opaque-ke`, `voprf`, the RustCrypto crates and Argon2id
  (see the risks of phase 4A).
- **The vectors were made by the project that wrote the library.** The RFC 9807 server messages
  are independent of it; the other cases are not.

## What is next

The server endpoints that call the library, with the database tables for login states,
challenges and session scopes, the rate limit adapters, the start-up wiring and the test of
the running server for sameness of answers. The server binary lives in `crates/ferret-server`
and pins the library to a release tag.
