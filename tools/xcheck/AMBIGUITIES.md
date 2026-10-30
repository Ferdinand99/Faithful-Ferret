# Ambiguities, gaps and the readings xcheck chose

xcheck was written from three sources only: the design document (`design-fase1.md`, "Fase 1"), the
vector files with `OPS.md`, `ERRORS.md` and `SOURCE.md`, and the schemas of the body, the manifest and the export file. Nothing under `crates/`, `bindings/` or `tools/vectorgen/` was read.

Where the design is silent or two places disagree, this file records the reading xcheck used. Two kinds of rule
did not come from the design text alone:

* **Taken from the vectors.** Three rules cannot be derived from the design at all, so xcheck took them from the
  vector files while reading them: the limit on pinned generations (G1), the AAGUID value (G2) and the 138-byte
  PKCS#8 layout of the stored passkey (G6). No run refused these first; they were written from the vectors.
* **Added because a vector refused a case.** Three rules were added because of a refusal that xcheck did not make: the manifest epoch on seal (G7), the reserved item id in `tomb.verify` (G8) and the floor of 15 without a
  secret key in the account flows (item 8). The design is silent on the first two; the third follows from section 4.1.

None of these changed an expected value of a vector. Everything else matched without a rule of its own.

## Rules the design does not state (xcheck needed the vectors)

| # | Where | What is missing | What xcheck does |
|---|---|---|---|
| G1 | Fase 1 section 4.7, 8.6; `rekey.run`, `account.*` | A limit on `kek_generation` and the pinned floors. `ERRORS.md` has `malformed_pinned_record` ("out of range, or the record would grow without bound") and the vector `rekey/refused/generation_too_high` uses a floor of 4 294 967 295. | The next generation must fit in 32 bits (floor below 2^32 - 1), otherwise `malformed_pinned_record`. The wrap vectors accept generations above 2^32, so this limit is for the pinned record only. The number 2^32 - 1 is an inference from that one vector. |
| G2 | Section 9.3 | The value of the fixed AAGUID. The design says one fixed UUIDv4 and that it is public. | The value is copied from the vectors (`dc704a44-b994-410c-a689-ed8d71a84ac3`) and xcheck checks only that it is a UUIDv4. The 16 bytes are therefore not independently checked. |
| G3 | Section 9 | The byte layouts of the WebAuthn objects: authenticator data, attestation object (`fmt: none`), COSE key, `clientDataJSON`, the PKCS#8 of the stored key (138 bytes, with the public key, no curve parameters in `ECPrivateKey`) and the SPKI. | WebAuthn L3 and the usual encodings, with the field order of the browsers (`type`, `challenge`, `origin`, `crossOrigin`). All of it matched, but the design does not pin it. |
| G4 | Section 9.3 | The signature nonce. The design says ES256; `OPS.md` says RFC 6979. | RFC 6979 with SHA-256 (own P-256 code, `src/p256.mjs`), no low-S step. The vector signatures are byte-identical and also verify under WebCrypto. |
| G5 | `item.open`, `OPS.md` | `OPS.md` says "a bad header is `unsupported` or `malformed_envelope`". Section 5.3 (clarified 29.10) and all the vectors say a changed `version`, `suite` or `kind` byte is `decrypt`. | The vectors and section 5.3 win: the header bytes go into the AAD as read, and only the length can give `malformed_envelope`. `OPS.md` now says so. |
| G6 | Section 9.1 | The PKCS#8 DER of the stored passkey key: "P-256 (PKCS#8 DER)" does not say which of the valid encodings. | The 138-byte form with the public key inside `ECPrivateKey` and no curve parameters there (taken from the vectors; Node's own export is a different, shorter form). The scalar is read from a fixed offset of it, and the embedded public key is checked against the scalar. |
| G7 | Section 4.3, appendix B | Whether the epoch written inside the manifest has to equal the epoch of the key. | Yes: `decrypt` on open, `malformed_item_body` on seal (item 13). Added because a vector refused it. |
| G8 | Section 8.4, appendix B | Whether the reserved all-zero `item_id` of the manifest can carry a tombstone. | No: `tombstone_invalid` in `tomb.verify`, `malformed_envelope` in `tomb.seal` (item 14). Added because a vector refused it. |

## Findings about the design text itself

* **Export header, four keys or five.** Section 6.4 gives the header as `{v, suite, kdf, created_at}` and the
  file as `header || ek_wrap || body`. The note "Presisert 29.10" says the header has "exactly five keys (`v`,
  `suite`, `kdf`, `created_at`, `ek_wrap`)". Both cannot be true: with `ek_wrap` in the header it could not follow
  it. xcheck uses four keys (section 6.4, `OPS.md`, the vectors agree). The note should be fixed.
* **Unicode 16.0 against the platform.** Section 3.1 locks suite 1 to Unicode 16.0. Node 24 ships Unicode 17.0.
  xcheck takes `\p{Assigned}` from the platform and subtracts the 4 803 code points first assigned in 17.0
  (`src/unicode17.mjs`, generated from `DerivedAge-17.0.0.txt`). A Node with an older or newer ICU needs that
  table checked. NFKD and NFC come from the platform; normalization is stable for assigned code points.

## Readings chosen (the design allows more than one)

### Primitives

1. **Argon2id.** The brief asks for libsodium. `libsodium-wrappers` (the non-sumo package) has no
   `crypto_pwhash`, and libsodium fixes the lane count at 1, but profiles allow `p` up to 4. xcheck therefore uses
   `crypto.argon2Sync` from Node (OpenSSL). It still has no dependency beyond `libsodium-wrappers` 0.8.4, which is
   used for XChaCha20-Poly1305 and Ed25519. The Argon2id vectors (RFC 9106 values through `kdf.json`) match.
2. **Salt length.** `kdf.argon2id` with a 7-byte salt is `input_too_short`. RFC 9106 asks for at least 8 bytes;
   the design is silent.
3. **No salt in HKDF.** The commitment `HKDF(salt = none, ...)` uses the RFC 5869 default: 32 zero bytes.
4. **PIN KEK.** The extension PIN KEK (section 7.2) is the Argon2id output itself (m = 64 MiB, t = 3, p = 1); the
   mobile one (section 7.4) is the HKDF over `KEK_dev_pin || Argon2id(...)`. A PIN is 6 or more ASCII digits.

### Text and codes

5. **Order of the text checks.** UTF-8 first, then forbidden characters, then "more than 1 024 scalars" before NFKD,
   then 1 024 after NFKD, then the minimum. The design lists the rules but not their order; the vectors say
   "forbidden character wins" over both length rules.
6. **Minimum length on NFC of the raw text** (not NFC of the NFKD output). Eleven ligatures are 11 characters, not 22.
7. **Forbidden characters** are category Cc and everything not assigned in Unicode 16.0 (noncharacters and code
   points past U+10FFFF included). Format characters (such as U+200D and the soft hyphen) and private use are allowed.
8. **Floor of 15 without a secret key** is applied by the account flows whenever there is no secret key in the
   OPAQUE input, whatever policy the text was first read under (section 4.1).
9. **Codes.** Letters are read upper case with `O` as `0` and `I`, `L` as `1`, also in the prefix. Order of the
   refusals: prefix (`malformed_code`), length (`input_too_short`, `input_too_long`), alphabet (`malformed_code`),
   checksum (`checksum`), spare bits (`non_canonical`). The check is over the decoded key bits only; the design says
   the checksum precedes any use but not that it precedes the canonical test; the vectors do.

### Item bodies, manifest, padding

10. **Body shape (appendix B).** Required for schema 1: `schema`, `type`, `name`, `fields` (each with `id`,
    `label`, `kind`, `value`), `urls` (each with `url`; `match` is optional), `created`, `modified`, `favorite`.
    Optional: `totp.uri`, the `passkey` map (the seeds optional), `notes`, `device`. A body with `schema` above 1 is
    only checked to be a map with an integer `schema` and is written back unchanged. A reference that follows the
    typed structure would rewrite such a body in schema order with defaults for missing keys; xcheck does not. The core
    does not either: both write the value that was read, with the same keys in the same order, and nothing added or
    typed (vector `item/open/schema_2_mistyped`, which has mistyped known keys and an unknown key in front). The
    plain JSON export does the same (`export/plain/json-006` to `json-008`); the CSV export and the encrypted export
    refuse such a body (`unsupported` and `read_only_schema`).
11. **Order of unknown keys.** Written back with the known keys in schema order (appendix B), then the unknown keys in
    the order they were read, at the top level and in `fields[]`, `urls[]`, `totp` and `passkey`. This is what
    `OPS.md` says for `export.plain.json` ("schema order, then unknown keys as read") and what "typed structure plus
    `extra`" in section 5.2 means. The vectors `item/seal/key_order` and `item/open/key_order` pin it, with an unknown key in front of a known one at
    the top level and in a field, a url, `totp` and `passkey`; `src/selftest.mjs` covers it as well.
    Manifests follow the same rule (known keys first in schema order, at the top level and in each method entry,
    then unknown keys as read), as `OPS.md` says ("Key order and newer schemas"); the vectors `item/manifest_seal/key_order`
    and `item/manifest_open/key_order` pin it.
12. **Floats** are kept at the width they were read (half, single, double) because `OPS.md` says "read and written
    back as it was". The JSON export prints finite floats with the shortest round-trip form and NaN or infinity as
    `null`; the design does not say, and no vector has a finite float in the plain export.
13. **Manifest.** The `v` field is judged first (`unsupported`), then the rest of the shape. The `vk_epoch` inside
    the manifest must equal the epoch of the key: on open a mismatch is `decrypt`, on seal `malformed_item_body`.
    The design says the manifest carries the epoch; the consequence is not spelled out.
14. **Reserved `item_id` (all zero).** Refused by `tomb.seal` and `item.seal` (`malformed_envelope`), by `item.open`,
    and treated as an invalid tombstone by `tomb.verify`. It is allowed under `item.tag` for the manifest.
15. **Padding.** A plaintext of 61 440 bytes or more is `too_large`; the class of a received body is checked
    against the allowed sizes (`malformed_envelope`).

### Checkpoint, rekey, flows

16. **Checkpoint verification order.** MAC, then digest, then the shape of the entries (`malformed_entries`),
    then `seq` against the top, then the shape of the rows, then each entry against its row, then, at the top, the
    exact comparison. Section 8.6 lists the checks but not their order or which code wins; the order was chosen
    so that the cases in `checkpoint.json` and `rekey.json` (which name the winning code) are all reachable.
17. **Rekey.** The new manifest lists only the password and recovery wraps (section 4.7: PRF wraps are dropped),
    in that order, with the new generations; keys of the old manifest that are unknown are not carried over. The
    new generation is the larger of the pinned floor and the manifest's, plus one. A revision of `2^64 - 1` cannot be
    raised and is `malformed_entries`. Order of the refusals: checkpoint `seq`, item ids, revisions, tags,
    checkpoint, manifest and floors.
18. **Account flows.** The pinned record is judged as: floors missing or too large (`malformed_pinned_record`), then
    the epoch (`pinned_vk_epoch`), then `pk_a` within the same epoch (`pinned_auth_key`), then the server key, the
    secret-key bit, the profile, the creation floor. In `recover` the typed code comes before everything and the
    recovery wrap is opened before the pinned record is compared. The new manifest is a copy of the old one with the
    changed entries rewritten, so unknown keys are kept.
19. **Proofs.** The five operations signed by `sk_a` are the four `unlock-method.*` names and `rekey`; `recover`
    is signed by `sk_r` only. `sk_a` signing `recover` is `unsupported`; verifying an unlisted `op` is `decrypt`.

### Vectors defined in `OPS.md` only

20. **TOTP, setup QR, plain exports** follow `OPS.md` word for word; the design only says "allow-list". Choices:
    one space after the colon of a label is dropped, the CSV "leading spaces" are U+0020 only, the formula
    prefix is applied to every cell, `localhost` is compared case-insensitively.
21. **Origins and RP IDs.** The design gives the rules for canonical origins in prose; IDNA comes from Node's
    `url.domainToASCII` (UTS 46) and the Public Suffix List is a vendored copy
    (`data/public_suffix_list.dat`, commit `9dfbe819...`, the one `SOURCE.md` names). xcheck's lookup also passes
    the 78 upstream cases of `vectors/external/publicsuffix-test_psl.txt`. `localhost` is allowed as an RP ID only
    from `localhost`.

## Not covered

* `opaque.register`, `opaque.login` (22 cases): the design names RFC 9807 with ristretto255 but gives no byte-level
  construction, and the RFC is not one of xcheck's sources. The account flows take a finished registration as
  input, so they are covered.
  The residual risk is that the Ferret OPAQUE configuration (context `ferret/v1/opaque`, the Argon2id KSF with a
  16-zero-byte salt and 64 bytes out, the input `mp || 0x00 || SK`, `credential_identifier = account_id`, default
  identities, `export_key` feeding `KEK_pw`) is checked by no independent implementation. The RFC 9807 vectors in
  the Rust suite use the identity KSF and the context `OPAQUE-POC`, so they do not exercise these choices.

## Guards

* xcheck refuses to start on a Node whose Unicode version is not 16.0 or 17.0, and on a Node without
  `crypto.argon2Sync` (Node 24.7 or newer; `engines` and `.npmrc` `engine-strict` say the same).
* An op in the vectors that has no handler and is not in `NOT_COVERED` (only the two OPAQUE ops) fails the run.

