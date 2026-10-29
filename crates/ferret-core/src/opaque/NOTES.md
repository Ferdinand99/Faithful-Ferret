# What was checked in `opaque-ke` 4.0.1 before the client was written

Plan Task 8, step 0. Sources: the published crate `opaque-ke 4.0.1`
(crates.io, 2025-11-03), `voprf 0.5.0` and RFC 9807 (retrieved 2026-10-29).
Nothing here is a guess about the library: each point names the file that was
read.

## (a) The KSF instance is passed in the finish parameters

* `ClientRegistrationFinishParameters::new(identifiers, Some(&ksf))` and
  `ClientLoginFinishParameters::new(context, identifiers, Some(&ksf))`
  (`src/opaque.rs`, "Convenience Structs"). `ksf` is `Option<&CS::Ksf>`.
* `get_password_derived_key` (`src/opaque.rs`) calls `ksf.hash(oprf_output)`
  when an instance is given, and `CS::Ksf::default().hash(...)` when it is
  not. The trait is `Ksf: Default` with
  `fn hash<L: ArrayLength<u8>>(&self, GenericArray<u8, L>) -> Result<GenericArray<u8, L>, InternalError>`
  (`src/ksf.rs`), so parameters cannot live in the type, only in the instance.
  `FerretKsf` carries them; `Default` is profile 1 and is never used by the
  client. Test `ksf_uses_supplied_instance_not_default`.
* `opaque-ke`'s own `Argon2` implementation is
  `hash_password_into(&input, &[0; RECOMMENDED_SALT_LEN], &mut output)`:
  a salt of 16 zero bytes, output as long as the input (64). That is what
  Fase 1 § 4.2 says, and `FerretKsf` does the same over `argon2 0.6`. Test
  `ksf_matches_opaque_ke_builtin_argon2`.
* The library copies the OPRF output before the call
  (`ksf.hash(oprf_output.clone())`), so the wipe of the input inside
  `FerretKsf::hash` clears only the copy it was given. The library's own
  buffers (`oprf_output`, the HKDF state) are outside our reach; this is a
  limit of the dependency, not of the client.

## (b) The draws, in order and length

All randomness goes through one `RngCore + CryptoRng` that the client
supplies (`Rng06`, an adapter from `SecureRng`; the operating system's
generator of `rand 0.8` is never reached, because `opaque-ke` has `std` and
`getrandom` off).

| Step | Draws |
|---|---|
| `register_start` | blind: 64 bytes. `voprf::OprfClient::blind` takes `Scalar::random`, which fills 64 bytes and reduces them modulo the group order (`src/opaque.rs` `blind`, `voprf-0.5.0/src/oprf.rs`, `src/group/ristretto.rs`). |
| `register_finish` | envelope nonce: 32 bytes (`src/envelope.rs` `seal`). |
| `login_start` | blind (64), seed of the ephemeral key pair (32, `KeyPair::derive_random`), client nonce (32) (`src/key_exchange/shared.rs` `generate_ke1`). |
| `login_finish` | none (`tripledh.rs` `generate_ke3` ignores its `rng`). |

The test `draws_are_blind_then_nonce_and_blind_seed_nonce` records them, and
every vector lists them.

The blind in RFC 9807 is a 32-byte scalar. A 64-byte draw whose second half is
zero reduces to the same scalar (it is below the group order), so the RFC's
blinds are replayed as `scalar ‖ 32 zero bytes`. No change to the library is
needed. (`opaque-ke`'s own test build uses a deterministic blind that reads 32
bytes; that is only in `cfg(test)` and is not what runs here.)

## (c) How the RFC 9807 vectors are fed in

`opaque-ke`'s own tests that read the RFC vectors are in `src/tests/`, which the
published crate leaves out (`exclude = ["/src/tests/"]` in its `Cargo.toml`),
and they use `cfg(test)` hooks. The fall-back of the plan (run the library's
own tests on pinned source) is therefore not needed and not possible from the
crate alone.

What was done instead, and works: the client code is instantiated twice by a
macro (`protocol!` in `client.rs`): for `FerretSuite`, and, behind
`test-support`, for `RfcSuite`, which is the same cipher suite with the
identity function as the KSF. The RFC's vectors 1 and 2 (ristretto255, with
and without identities) are run through `RfcSuite` with `ReplayRng`, and they
give the exact `registration_request`, `registration_upload`, `KE1`, `KE3`,
`export_key` and `session_key`. The code under test is the production code;
only the KSF type and the context differ, and both are inputs.

The macro is needed because `CipherSuite` has a long `where` clause with
`opaque-ke`-private traits (`Serialize`, `Deserialize`), so a function generic
over `CS` cannot be written outside the library.

## Other things read

* Server side: `ServerSetup`, `ServerRegistration::start`,
  `ServerLogin::start` and `finish` are public and take a `rand 0.8` RNG; the
  test server in `testing::opaque` uses them. `ServerLogin::start` with no
  record builds a fake record (RFC 9807 section 10.9), used by the test of
  the unknown-account case.
* Parsing: `RegistrationResponse::deserialize` and
  `CredentialResponse::deserialize` slice the input at fixed offsets after
  the first element (`&input[EvaluationElementLen::USIZE..]`). The client
  checks the exact length (64 and 320 bytes) first, so no hostile length can
  reach those slices; the tests and the fuzz target try other lengths.
* Errors: `finish` returns `InvalidLoginError` for a wrong password
  (envelope MAC) and a bad server MAC, `ReflectedValueError` for a reflected
  OPRF value and `SerializationError` for a masked response that does not
  parse. The client maps every error after the message has parsed to
  `Error::Decrypt`, except the KSF's own failure (`kdf_out_of_memory`).
* Dependencies (`Cargo.toml` of the crate): `digest 0.10`, `hkdf 0.12`,
  `hmac 0.12`, `rand 0.8` without default features, `curve25519-dalek 4`,
  `voprf 0.5` (feature `danger`), `elliptic-curve 0.13`, `generic-array 0.14`.
  `getrandom 0.2` is only an optional dependency of the `std` feature on
  `wasm32` and is not pulled in. The duplicates are listed in `deny.toml`.
* `elliptic-curve 0.13` brings `crypto-bigint 0.5.5`, which has an advisory
  (RUSTSEC-2026-0387, fixed in 0.7.6 only). The ristretto255 path uses
  nothing of `crypto-bigint` but `ExpandMsgXmd` (hash-based); see the report.
