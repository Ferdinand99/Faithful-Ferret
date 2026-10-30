# Phase 4A: results

Phase 4A is the Rust cryptographic core and its WebAssembly binding, with the test
vectors, the checks and the release pipeline around them. This page records what was
measured, which decisions were taken, and which risks remain. It is written at the end of
the phase and describes the code in this repository at that point. Numbers were measured on
the build host named in each section; they will move as the code changes.

No external audit has been done and none is planned (see [`REVIEW-PACKAGE.md`](REVIEW-PACKAGE.md)).

## Summary

| Question | Answer |
|---|---|
| Does the core cover what phase 4A set out to do? | Yes: key hierarchy and wraps, envelope and items, tombstones, checkpoints, mutation proofs and re-key, encrypted and plain export, OPAQUE sign-in and the account flows, passkeys, TOTP, the WebAssembly binding and the worker client |
| Test vectors | 1 143 internal cases and 1 634 external ones; they run in Rust, in Node through WebAssembly and in Chromium, Firefox and WebKit, and an independent JavaScript reference opens all of the internal ones except 22 OPAQUE cases |
| Property tests and fuzzing | 20 000 cases per property pass; all twelve fuzz targets run clean |
| Constant-time checks | Everything the analysis found is triaged; timing tests pass natively and in Node; the WebAssembly scan has no finding outside its allow list |
| Dependencies | `cargo deny` and `cargo vet` pass; the duplicate versions are the approved ones |
| Size | The WebAssembly module is 1 220 038 bytes (1.16 MiB), under the 2 MiB budget, and has no test support |

## Test run for this report

Run in the builder image on a Docker host from the state of the repository at the time of
writing: formatting, clippy for native and `wasm32-unknown-unknown`, `cargo test
--workspace` (509 tests passed, none failed), the vector check, the passkey API and
test-support scripts, `cargo deny`, `cargo vet --locked`, the MSRV (1.88) check and the Node tests
of the binding (48 passed, none failed).

## Size

The release module `ferret_core_wasm_bg.wasm` is **1 220 038 bytes** (1.16 MiB) after `wasm-opt
-Oz`, against a budget of 2 MiB; it is 1 801 852 bytes before `wasm-opt`. The build with `test-support`
is larger and is never released. The linear memory maximum is 1 GiB.

Heap use (a fresh instance, after the operation; WebAssembly memory never shrinks):

| Operation | Memory |
|---|---|
| Slow step of an export at 256 MiB | 2 MiB to 258 MiB, in a worker that is ended afterwards |
| Slow step of an import at the 512 MiB ceiling | 2 MiB to 514 MiB, in a worker that is ended afterwards |
| Sign-in at the 64 MiB profile | about 66 MiB in the vault worker |

An Argon2id request for 3 GiB is refused as `kdf_out_of_memory` and does not trap.

## Argon2id speed in the browsers

Export with the default parameters (256 MiB, 3 passes, 1 lane), one Argon2id step in the job
worker. Opening a file with the same parameters takes the same time.

| Browser | Writing | Opening |
|---|---|---|
| Chromium | 0.62 to 0.63 s | 0.62 s |
| WebKit | 0.73 to 0.75 s | 0.74 s |
| Firefox | 5.04 to 5.07 s | 5.04 s |

Firefox is about eight times slower than Chromium for Argon2id in WebAssembly. The 36
cases of `kdf.json` (13 of them Argon2id, eight at 64 MiB) take 1.1 s in Chromium, 1.1 s in WebKit and
8.8 s in Firefox. The browser tests also run all vectors and a search for secrets in every worker
message (112 messages, 34 secrets, no leak) in all three browsers. The 256 MiB export test runs in
CI only with the `browsers` label, nightly and on manual runs, because of its length.

## Vectors and the independent reference

- Internal vectors: 1 143 cases, of which 29 are marked `native-only` (Argon2id with parameters below the floor, which only a test build accepts);
  the Node and browser runners run the other 1 114. External vectors (RFC 9106, 5869, 8032, 6238, 4226, 9807,
  the XChaCha20 draft, Wycheproof, the Public Suffix List test file): 1 634 cases.
- `tools/xcheck` is a second implementation in JavaScript, written from the design and the vector
  files only. It matches 1 121 of the 1 143 internal cases and does not cover the 22 OPAQUE cases
  (see the risks below). It also runs a self-test in which every damaged expectation must be detected.
- Rules the vectors now pin down: the order in which a body or a manifest is written (known keys in
  schema order, then unknown keys as read, at every level), the error codes of a damaged envelope,
  and the write-back of a body with a newer schema.

## Property tests and fuzzing

- Property tests: 20 000 cases per property pass (about four minutes for all of them).
- Twelve fuzz targets with AddressSanitizer: CBOR, item bodies and manifests, envelopes (including
  a keyed half that gets past the HMAC and the AEAD), the export file, checkpoints, the OPAQUE
  messages, the Public Suffix List and origins, otpauth addresses, the emergency sheet, recovery
  and secret key codes, master password input, and WebAuthn options. A 60 second pass of every target
  is clean on a pull request. One input crashed the harness in the first pass; it showed that a body
  with a newer schema was not written back as it was read, and the core was changed (below). In the
  long runs the envelope target reached 1.5 million executions and the CBOR target 9.8 million.

## Coverage

`cargo llvm-cov --branch` on the pinned nightly toolchain, against the thresholds of the plan
(95 % of lines and 90 % of branches per module for the security-critical modules, 90 % of lines
for the whole core):

| Module | Lines | Branches |
|---|---|---|
| integrity | 98.4 % | 92.6 % |
| wrap | 98.4 % | 92.9 % |
| envelope | 98.8 % | 93.8 % |
| codes (with the Crockford coder) | 99.2 % | 92.9 % |
| text | 99.3 % | 90.6 % |
| export | 97.8 % | 93.6 % |
| whole core | 97.0 % | 91.6 % |

The remaining uncovered code is defensive code that cannot be reached through the public API. A workflow on pull requests and a weekly run keep the thresholds enforced.

## Constant-time checks

- The core's own constant-time code (equality of commitments and tags, selection, the padding scan,
  Crockford and base32 decoding) is in small single-file modules under `ct/harness/`. A static analyzer
  reads their assembly for x86-64 and arm64 at four optimisation levels (40 reports, 220 findings). Every
  finding is triaged in `ct/TRIAGE.md` and the counts are pinned, so a change in either direction fails the
  check. One real finding was fixed: a masked select that the compiler turned into a pointer select at `-O2`;
  a check of the assembly (`select-asm`) now fails on that shape, and a deliberately bad copy of the old code
  must be flagged.
- A scan of the shipped WebAssembly module lists every division, remainder, square root, table jump
  and computed load in the core's functions; each must be in an allow list (140 entries) with a reason and an
  exact count, and a regeneration must give the committed file. A new entry or a higher count in a function
  that handles keys needs a reason that is marked as approved. The scanned module is byte-identical to the
  shipped one. The scan does not see an address that went through a local variable, and it does not look at
  stores; `ct/TRIAGE.md` says why and what would close the gap.
- Timing tests (dudect) run natively and in Node against the WebAssembly build, for the commitment
  check, the MAC check, key equality, Crockford decoding, the padding scan, base32 decoding and the path of
  the password-wrap commitment. The decisive run is on a pinned core of the build host, with one million
  measurements per bench and a limit of |t| < 4.5 (a bench over the limit is measured again with ten million).
  It is committed in `ct/results/dudect-lanbox.md` for the commit it was made on. Natively every gated bench
  stayed at or under 2.3 and in Node at or under 2.6. The controls work: the null control stayed at 2.2 and
  3.3, and the controls with a deliberate early exit were seen at 3e4 to 7e4. One information bench (base32
  upper case against lower case) showed -5.8 once; five repeats with ten million measurements gave values
  between -1.9 and +2.2. On GitHub-hosted runners the timing job is a smoke run: it checks that the setup runs
  and sees the controls, and fails only on a gross difference (over 500 after a rerun), because a shared
  runner is too noisy for the real limit.
- The limits are listed under the risks below.

## Dependencies

- `cargo deny` passes: no advisory except the one below, licenses limited to the ones in use, crates.io
  only, and duplicate versions only as listed in `deny.toml` with a reason. The duplicates come from
  `opaque-ke` 4.0.1, which is built on the previous generation of RustCrypto, and from the test-only
  cross-check of Argon2.
- One advisory is ignored with a reason (RUSTSEC-2026-0387, a timing issue in `crypto-bigint` 0.5).
  The affected code is reached through `elliptic-curve` 0.13, which `opaque-ke` and `voprf` use only for
  hash-to-curve helpers that do not touch `crypto-bigint`. `scripts/check-advisory-reach.sh` keeps that
  dependency path narrow. The entry goes when `opaque-ke` moves to `elliptic-curve` 0.14.
- `cargo vet` passes with the audits of Mozilla, Google and the Bytecode Alliance imported. Of the
  dependency versions, 9 are fully audited and 3 partly; 139 are exemptions, each with a date. These are
  not audited for this project. `cargo vet suggest` estimates the backlog at more than a million lines.

## Decisions

These are the points where the design left a choice, with what was decided.

- Decision: OPAQUE (RFC 9807) is the sign-in method, with the Argon2id profile as its key-stretching
  function. The password never leaves the device.
- Decision: `opaque-ke` is used with the `ristretto255` feature only and pinned exactly. The key-stretching
  function is the core's own wrapper over `argon2` 0.6 with zeroisation, and randomness comes from the core's
  own adapter over `getrandom`, so the old random number generator of `rand` 0.8 is never used.
- Decision: Argon2id runs in the same long-lived crypto worker as the rest of the core, so neither the
  vault key nor a key-encryption key crosses into JavaScript. The heap of about 64 MiB stays until the worker
  is restarted at lock. Only the slow step of an export or an import runs in a short-lived worker.
- Decision: constant-time checking uses a static analyzer on single-file modules, a scan of the WebAssembly
  module with an allow list, and statistical timing tests; third-party crates are covered by the timing
  tests only.
- Decision: the item body schema, the manifest and the export file follow the schemas of the design
  appendix: `schema` 1, CBOR with text keys, times as unix milliseconds, an unknown item type is kept.
  The manifest is sealed like an item with an item id of 16 zero bytes and an ordinary revision.
- Decision: the whole envelope is at most 65 536 bytes, so the largest padded body is 61 440 bytes and
  the largest plaintext is 61 439 bytes.
- Decision: the item key is made when an item is created and when the vault is re-keyed. An edit keeps the
  old wrapped item key and seals only the body again.
- Decision: the mutation operations are a closed list (`unlock-method.add`, `unlock-method.remove`,
  `unlock-method.password.put`, `unlock-method.recovery.put`, `recover`, `rekey`). The epoch in a proof is the
  epoch of the signing key.
- Decision: the minimum length of a master password is measured in NFC scalars and the maximum after NFKD
  (1 024 scalars, 4 096 bytes). Export passwords follow the same rules and need 12 characters. A PIN is digits
  only. The JavaScript glue rejects lone surrogates before encoding.
- Decision: the CBOR decoder is the core's own strict reader over the low-level `minicbor` decoder. No tags are
  allowed in version 1, map keys are text, and floats of 16, 32 and 64 bits are read and kept as they were in unknown fields. A float in a known field is refused.
- Decision: the Public Suffix List is an embedded snapshot in the core, with private domains, and its age is
  checked (warning at 75 days, failure at 90).
- Decision: the local `device` wrap uses the generic wrap AAD without a method-specific field and without a key
  commitment; only `password` and `pin` wraps have a commitment (see [`WRAP-AAD.md`](WRAP-AAD.md)).
- Decision: a passkey credential id is 32 random bytes; the `hmac-secret` extension is signalled when PRF is
  requested; the signature counter is always 0; the transports list is left empty.
- Decision: a TOTP secret is at most 128 bytes, and the only `otpauth` parameters allowed are `secret`, `issuer`,
  `algorithm`, `digits` and `period`.
- Decision: the key-stretching parameters belong to the suite and are not sent over the network; the server
  states only a profile number. Profile 1 is 64 MiB, 3 passes, 1 lane. An imported export file may use at most
  512 MiB; the WebAssembly memory maximum is 1 GiB; an export is written with 256 MiB.
- Decision: the OPAQUE server public key is pinned with the server address, the account id and the secret-key
  flag, and it is also in the setup QR code. A change needs the emergency sheet.
- Decision: the setup QR text is `ferret-setup:v1?u=<url>&a=<account>&k=<profile>&s=<0|1>&o=<server key>`.
- Decision: the export file header is one CBOR item, the wrapped content key is 72 bytes, the body is limited
  to 128 MiB and is not padded. The plain JSON export has the structure of the encrypted body, and passkey
  secrets are in it only when asked for.
- Decision: a password strength meter and a blocklist are not part of the core; the core enforces length and
  character rules only.
- Decision: a body with a newer schema is read-only. It is shown and exported, never sealed, and it is written
  back from the value that was read, never rebuilt from the typed fields. Bodies and manifests are otherwise
  written with the known keys in schema order, then the unknown keys as read.
- Decision: the independent reference does not cover OPAQUE in phase 4A (see the risks).
- Decision: the project is licensed under AGPL-3.0, and there will be no paid external audit.

## Risks that remain

- **OPAQUE has no second implementation.** The Ferret parameters (the context string, the zero salt of the
  key-stretching function, the 64-byte output, and the input `password | 0x00 | secret key`) are checked
  only against vectors made by the Rust code. The RFC test vectors run in Rust. Writing a second implementation
  (with its own ristretto255 and OPRF) is planned before 1.0; until then a shared misreading in the glue
  would go unnoticed.
- **Timing.**
  - The analysis does not re-verify the RustCrypto crates, and Argon2id has data-dependent memory access
    by design.
  - The Unicode normalisation of the master password and the tables that decide which characters are
    assigned are indexed by the characters of the password and are not constant time. An ASCII fast path is
    possible and is deferred.
  - The TOTP code is computed with a remainder of the HMAC output (the one-time code, not the key), and
    the text handling of `otpauth` addresses is not constant time.
  - The masked selects can be compiled to `cmov` or `csel`, which are constant time on current processors.
  - The timing tests are statistical, on one CPU. The WebAssembly ones depend on Node and V8, are quiet only
    because each measurement repeats the call eight times, and may need that adjusted on another machine. The
    measured module is not the binding's own.
  - Comparing a right with a wrong commitment in `unwrap_vk` is expected to differ (the right one goes on to
    the AEAD) and is reported, not gated. A change from the constant-time comparison of the commitment to a
    plain `==` in `wrap.rs` is therefore caught by the decisive timing run on the build host and the
    source check of the test suite, not by the smoke run in CI.
  - The shipped WebAssembly module has more flagged instructions than the unoptimised one, because inlining
    duplicates code; the allow list gates the shipped level. One unnamed function holds a floating-point
    division, counted but not named.
- **Wiping.** The registry that checks zeroisation on drop covers the secret key types made by one macro. The
  unlocked vault, the master password and export password types, the authentication key pair, the TOTP secret
  and the item body types are not in it. JavaScript strings cannot be wiped: recovery key and secret key
  codes, notes and revealed fields become strings, and a TOTP secret passes through one on its way in.
- **Dependencies.** Most versions are `cargo vet` exemptions. The tree holds two generations of several
  RustCrypto crates. One advisory is ignored with a reason.
- **Contracts that the core cannot enforce.**
  - The first checkpoint must have sequence number 1.
  - The check of the server address in the setup QR code is syntactic, and the client must show the host to the
    user.
  - A key-stretching upgrade is untested until a second profile exists. Until then the unlock paths that do
    not sign in ignore the profile of a scanned sheet, and an upgrade with an unchanged password would be
    refused if the creation floor ever rises.
  - Recovery on a new device must be given the scanned QR text on first use, and the client must show the
    sheet before the re-entry step.
  - Sealing a passkey item is for new items only until the client decides how an existing item is rewritten
    without losing its other fields.
  - Server-side address parsing differs from the browser's in the spelling of IPv6 addresses.
  - The PRF output reaches the vault worker as an argument, because the browser produces it on the page.
- **Plain CSV export of a body with a newer schema** is refused (`unsupported`), so no secret is dropped from the file
  without a word. The JSON export holds such a body whole.
- **Tests that are not run on every change.** The 256 MiB export test in the three browsers needs a label on a
  pull request. The twelve fuzz targets run for 60 seconds on a pull request and for 20 minutes each night. The
  timing tests that are decisive are run by hand on a quiet host.
- **The checks show that code was exercised, not that it is right.** Coverage and fuzzing do not prove
  correctness, and the vectors were made by the people who wrote the core.

## What is next

The second OPAQUE implementation is planned for phase 4B or before 1.0. The remaining items above are to be
closed before 1.0, together with whatever other reviewers find.
