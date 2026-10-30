# Review package: the Ferret cryptographic core

Faithful Ferret has **not been audited by anyone outside the project**, and no external
audit is planned or funded. This page is a scoped package for anyone who wants to read the
core critically: community reviewers, researchers, students, or a future auditor. It says
what the core does, where each construction lives, what is already checked and how to
re-run the checks, and which risks are known and accepted. It is meant to make a review
quick to start, not to replace one.

Please report findings as described in [`SECURITY.md`](../SECURITY.md).

## Scope

In scope:

- `crates/ferret-core/`: the cryptographic core, safe Rust, no I/O. About 12 200 lines
  of Rust outside `src/testing/` (the test-support code, 1 900 lines, which is never part of a
  release); counted with `wc -l` over the `.rs` files under `crates/ferret-core/src/`, without comments or
  blank lines taken out.
- `bindings/wasm/`: the WebAssembly binding and the worker client in `bindings/wasm/js/`,
  which keep key material inside WebAssembly memory.
- `vectors/`, `tools/vectorgen/`, `tools/xcheck/`: the test vectors, their generator and an
  independent JavaScript reference that opens them.
- The code that checks timing behaviour, fuzzing, coverage and the release build.

Out of scope here: the server, the web vault, the browser extension and the mobile apps.
They are not written yet; this package covers phase 4A only.

The code cites the design document with references such as "Spec: Fase 1 § 4.3" ("Fase 1"
is Norwegian for phase 1). That document is
[`docs/design/phase-1-security-design.md`](design/phase-1-security-design.md); the section
numbers in the code match its headings.

## What the core does

**Suite 1.** OPAQUE (RFC 9807) for sign-in, Argon2id for key stretching, HKDF-SHA-256,
XChaCha20-Poly1305, HMAC-SHA-256 and Ed25519. Nothing is home-made: every construction
below is a composition of these.

**Key hierarchy** (`keys.rs`, `wrap.rs`, `account.rs`):

- A random **vault key** (VK, 32 bytes) per vault and `vk_epoch`. All item data is under it.
- Each **unlock method** has a key-encryption key (KEK) that wraps VK:
  - master password: the OPAQUE `export_key` goes through HKDF to `KEK_pw`, so the server never
    sees anything that can open the vault;
  - recovery key: HKDF of the 32-byte recovery key (`KEK_rk`);
  - passkey: HKDF of the WebAuthn PRF output (`KEK_prf`);
  - local PIN and device key: Argon2id of the PIN on the device (`KEK_pin`), or a random key.
- From VK, HKDF with an account, vault and epoch salt gives `K_head` (row tags), `K_del`
  (tombstones), `K_meta` (the manifest) and a signing seed for `sk_a`. A separate recovery
  seed gives `sk_r`. The server stores only `pk_a` and `pk_r`.
- The wrap is `nonce | VK | tag`, 72 bytes, plus a 32-byte key commitment for `password` and
  `pin`. The AAD of every method is in [`WRAP-AAD.md`](WRAP-AAD.md).

**Envelope** (`envelope.rs`, `item/`): `version | suite | kind | ik_wrap | body`.

- Each item has its own random item key (IK), wrapped under VK with an AAD of
  `vault_id`, `item_id` and `vk_epoch`.
- The body is CBOR (a strict reader, `cbor/`: definite lengths, text keys, no duplicate keys, no tags; the writer
  uses the shortest forms, and the reader accepts longer heads), padded to a size class, and sealed
  under IK with an AAD of `version`, `suite`, `kind`, `vault_id`, `item_id` and `rev`.
- The server-visible row tag is HMAC-SHA-256 under `K_head` over the SHA-256 of the whole envelope.
- The whole envelope is at most 65 536 bytes. Opening checks the structure, then the tag,
  then the AEADs, and only then the padding and the CBOR. Every failure from the tag on is
  the single `decrypt` error.
- Unknown keys at every level of the body are kept and written back after the known keys.
  A body with a newer `schema` is read-only and is written back as the value that was read (same keys, same order, shortest-form encoding).

**Integrity** (`integrity/`): tombstones, signed checkpoints over the list of rows
(sequence number, digest, MAC), mutation proofs (signatures over operation, request body
and epoch), and a full re-key that re-wraps every item and re-signs the state. The client
refuses a state older than what it has seen (rollback floors for each method type, and
pinned values for the account).

**OPAQUE** (`opaque/`, `account.rs`, `pinning.rs`): the client side only, on `opaque-ke`
4.0.1. The configuration is ristretto255, 3DH, SHA-512, the internal envelope, the context
`ferret/v1/opaque`, no identities, and Argon2id v1.3 as the key-stretching function with a
zero salt and a 64-byte output (the profile is 64 MiB, 3 passes, 1 lane). The core pins the
server's OPAQUE public key together with the server address, the account id and the profile,
and compares it again on every re-registration.

**Other parts:** the encrypted export file (`export.rs`: Argon2id with a floor and a 512 MiB
ceiling on import, an inner key, 128 MiB body limit), the plaintext JSON and CSV exports
(`export/plain.rs`), passkeys (`passkey/`: ES256, COSE, authenticator data, PRF seeds, origin
canonicalisation with an embedded Public Suffix List), TOTP (`totp.rs`), the emergency sheet
and its setup QR text (`sheet.rs`), and password and code input rules (`text/`, `codes.rs`).

## Where to look

| Area | Files | Lines | What to check |
|---|---|---|---|
| Wrapping and the key hierarchy | `keys.rs`, `wrap.rs`, `secret.rs` | 337, 283, 229 | The derivations and labels; the AAD of each wrap; that the commitment is compared before the AEAD is opened; that no secret is `Clone` or `Debug` by accident |
| Envelope and items | `envelope.rs`, `item/body.rs`, `item/manifest.rs`, `item/pad.rs`, `cbor/` | 608, 587, 188, 97, 608 | AADs; order of checks on open; padding; the strict CBOR rules and limits; unknown-key preservation |
| Integrity | `integrity/checkpoint.rs`, `proof.rs`, `rekey.rs`, `tomb.rs`, `pinning.rs` | 445, 273, 474, 99, 558 | What a checkpoint covers; replay and rollback; proofs bound to operation, body and epoch; re-key atomicity |
| Accounts and OPAQUE | `account.rs`, `opaque/` | 907, 761 | Account creation, password change, recovery; the order in which pins are checked; the KSF wrapper |
| Export and import | `export.rs`, `export/plain.rs` | 617, 350 | Parameter floor and ceiling before any Argon2 work; limits; neutralised CSV |
| Passkeys | `passkey/` | about 1 600 | Origin and RP ID rules; that no private key or PRF seed leaves except as allowed (`scripts/check-passkey-api.sh`) |
| Text and codes | `text/`, `codes.rs`, `ct/harness/crockford.rs` | 417, 341, 154 | Normalisation and length rules; checksum and look-alike handling |
| WebAssembly binding | `bindings/wasm/src/`, `bindings/wasm/js/` | about 5 500 and 900 (a quarter of the Rust is `vector_ops.rs`, test support) | That secrets are returned only where `reveal-allowlist.txt` says; worker lifecycle; wiping |

## What is already checked, and how to run it

Everything builds with the pinned toolchain in `rust-toolchain.toml`. The scripts under
`scripts/` run the heavy checks in the builder image of `docker/builder.Dockerfile` on a
Docker host (`scripts/lanbox.sh` and the `scripts/lanbox-*.sh` wrappers; set
`FERRET_DOCKER_ARGS` for your host). The same checks run in GitHub Actions.

| Check | How | Where it is described |
|---|---|---|
| Unit and integration tests | `cargo test --workspace` | `crates/ferret-core/tests/` |
| Test vectors, internal (about 1 100 cases) and external (RFCs and Wycheproof, about 1 600) | `cargo run -p ferret-vectorgen --bin vectorgen -- check`, then the Rust, Node and browser runners | `vectors/OPS.md`, `vectors/ERRORS.md` |
| Independent re-implementation of the vectors | `cd tools/xcheck && npm ci && node src/run.mjs` | `tools/xcheck/AMBIGUITIES.md` |
| Three browsers, no secret in worker messages | `tests/browser` (Playwright) | `scripts/lanbox-browsers.sh` |
| Property tests (20 000 cases per property in the nightly run) | `PROPTEST_CASES=20000 cargo test -p ferret-core --test 'props_*'` | `.github/workflows/props.yml` |
| Twelve fuzz targets with AddressSanitizer | `scripts/lanbox-fuzz.sh <target\|all> <seconds>` | `fuzz/`, `.github/workflows/fuzz.yml` |
| Line and branch coverage thresholds | `scripts/lanbox-coverage.sh` | `scripts/coverage-thresholds.json` |
| Constant-time analysis and timing tests | `ct/run.sh` (analyzer, WebAssembly scan, timing tests) and `scripts/lanbox-ct.sh` | `ct/TRIAGE.md`, `ct/results/` |
| Dependencies | `cargo deny check`, `cargo vet` | `deny.toml`, `supply-chain/` |
| No test code in a release | `scripts/check-no-test-support.sh`, `tests/node/release.test.mjs` | [`RELEASING.md`](RELEASING.md) |

The measured results of the phase are in [`PHASE-4A-REPORT.md`](PHASE-4A-REPORT.md).

## Known risks that are accepted

These are the places where the core is weaker than a reader might assume. None is hidden;
each has a reason.

- **Timing.** The analysis covers the core's own constant-time code (comparisons, selection,
  padding scan, Crockford and base32 decoding). It does not re-verify the RustCrypto
  crates, and Argon2id has data-dependent memory access by design. The Unicode
  normalisation of the master password and the tables that decide "assigned" characters are
  indexed by the characters of the password and are not constant time; this runs once per
  unlock and has no cheap alternative. Timing tests are statistical, on one CPU, and the
  WebAssembly timing tests depend on Node and V8.
- **JavaScript strings cannot be wiped.** A recovery key code, a secret key code, notes and a
  revealed field are plain strings on the JavaScript side after they are shown. The TOTP
  secret passes through a string on its way in. Passwords, PINs, PRF outputs and the export
  wrap key are handled as byte arrays that are wiped.
- **Wiping is best effort.** Zeroisation is checked for the registered secret types and for the
  Argon2 memory. `UnlockedVault`, the password types, the TOTP secret and the item body types
  are not in that registry. Copies made by the host (garbage collection, swap) are out of
  reach. Inside the core, a key that is moved by value (`UnlockedVault::from_vault_key`,
  `open_vault_key`, the derivation helpers, the AEAD key schedule) can leave a copy in a
  stack frame that the wipe helpers cannot reach; the finish results of `opaque-ke` are the
  exception and are wiped in place.
- **OPAQUE is checked only against the Rust implementation.** RFC 9807 and RFC 9497 vectors run
  in Rust, but the independent JavaScript reference does not implement OPAQUE, so the Ferret
  parameters (context, zero salt, 64-byte output, the input `password | 0x00 | secret key`)
  are not confirmed by a second implementation. This is the first thing to add before 1.0.
- **Dependencies.** `opaque-ke` 4.0.1 sits on the previous generation of RustCrypto, so the tree
  holds two generations of several crates; each duplicate is listed in `deny.toml` with its
  reason. One advisory (RUSTSEC-2026-0387, a timing issue in `crypto-bigint` 0.5) is
  ignored with a reason: the affected code is not reached with secret data, and
  `scripts/check-advisory-reach.sh` keeps the dependency path that way. Most of the
  dependency versions are `cargo vet` exemptions, which means nobody has audited them for this
  project; the backlog is in `supply-chain/`.
- **Contracts with the server and the client that this package cannot enforce.** The first
  checkpoint must have sequence number 1. The check of the server address in the setup QR code
  is syntactic only, so a client has to show the host to the user. A key-stretching upgrade
  path exists but is untested until a second profile exists.
- **Passkeys.** The PRF result goes from the page to the vault worker as an argument; this is
  by design because it comes from the browser.
- **Limits of the checks.** Coverage and fuzzing show that code was exercised, not that it is
  right. The vectors were made by the same project that wrote the core; the independent
  JavaScript reference reduces that risk but was written by the same team.

## Suggested reading order

1. [`WRAP-AAD.md`](WRAP-AAD.md), then `wrap.rs` and `keys.rs`.
2. `envelope.rs`, then `item/body.rs`.
3. `integrity/checkpoint.rs` and `integrity/rekey.rs`.
4. `account.rs` and `pinning.rs` for the order of the pin checks.
5. `export.rs`.
6. `bindings/wasm/src/vault.rs` and `bindings/wasm/reveal-allowlist.txt`.
