# What was checked in `opaque-ke` 4.0.1 about the server side

Written before any server code was built on the feature. Sources: the published crate `opaque-ke
4.0.1` and `voprf 0.5.0` from crates.io (files named in each point), read on
2026-10-30. Each point is locked by a test in `tests/server_suite.rs`, named in
brackets. The client side is in `NOTES.md` next to this file.

## How the server suite is exported

Behind the feature `server-suite` (off by default), `opaque::server_suite`
exports `opaque_ke`, `FerretSuite`, `OPAQUE_CONTEXT`, the `Rng06` adapter and the
message lengths. The WASM package does not enable the feature, and
`scripts/check-no-test-support.sh` fails if the dependency graph of a release
crate shows it, directly or through a feature chain. Without the feature none of
these items can be named from outside the crate. `FerretKsf`, the key stretching
function of the suite, is `pub` in a private module: it has to be, because it is
the associated type of the public suite. Its name cannot be written outside the
crate, but with the feature it can be reached as
`<FerretSuite as CipherSuite>::Ksf`. The only instance that can be made from
outside is `Default`, the checked profile 1 function; the constructors with
other parameters are crate-private, so the floor and the ceiling hold.

## Set-up (`src/opaque.rs`, `src/keypair.rs`)

* `ServerSetup<CS>` serializes to the OPRF seed (64), the private key (32) and
  the public "dummy" key (32): **128 bytes**. `ServerSetup::new(rng)` draws three
  times 64 bytes: the key pair, then the OPRF seed, then a second key pair of
  which only the public half is kept as the dummy key.
  [`server_setup_draws_key_pair_seed_dummy_in_order`] `deserialize` checks that the private key is a
  canonical non-zero scalar and that the dummy key is a ristretto255 point that
  is not the identity. [`server_setup_is_128_bytes_seed_key_dummy`]
* **Zeroizing.** `ServerSetup` has no `Drop` and does not implement
  `ZeroizeOnDrop` itself. Its two secret fields do: `OprfSeed` and
  `PrivateKey` are `ZeroizeOnDrop`, so they are wiped when the setup is
  dropped. The derived `Clone` copies them (each copy wipes itself). The
  public key and the dummy key are not secret. [`server_setup_zeroize_on_drop`]
* **`Debug` prints keys.** `ServerSetup`, `KeyPair`, `PrivateKey`, `ServerLogin`
  and its state derive `Debug` over the secret fields. A server built on
  this feature must never put one of them in a type that derives `Debug`; the
  setup belongs in a guard with a hand-written `Debug`.

## Registration

* `ServerRegistration::start(&setup, request, credential_identifier)` draws
  nothing. The OPRF key is `HKDF-expand(PRK = seed, info = credential_identifier ‖ "OprfKey")` (then the OPRF `DeriveKeyPair`),
  so the same identifier gives the same key on every registration, and a new
  registration of the same account keeps its OPRF key. The response is the
  evaluated element (32) and the server public key (32): **64 bytes**, the same
  constant the client checks. [`lengths_match_the_wire_format`,
  `exported_suite_serves_the_client`]
* `ServerRegistration::finish(upload)` is a plain wrapper. The record is
  **192 bytes**: client public key (32), masking key (64), envelope (nonce 32,
  MAC 64). The server cannot look inside the envelope.
* A request is **32 bytes**. `RegistrationRequest::deserialize` accepts the
  32 bytes it needs and ignores anything after them. The same holds for every
  parser (`KE1`, the record, `KE3`, the login state and `ServerSetup`): they read
  a prefix. **A server built on this feature must check each length itself.**
  [`library_parsers_ignore_trailing_bytes`]
* Inputs that are shorter than the message are an error (`SizeError` or a
  deserialization error), never a panic, at every length from 0.
  [`malformed_points_are_errors`]

## Login

* `ServerLogin::start` always builds a fake record first (64 bytes drawn for its
  masking key, public key `dummy_pk`, a zero envelope) and replaces it with the
  real record when one is given, by a constant-time choice. The draws, in this
  order: **fake masking key (64), masking nonce (32), seed of the server's
  ephemeral key (32), server nonce (32).** `finish` draws nothing.
  [`server_login_draws_in_documented_order`]
* `ServerRegistration::dummy` is `pub(crate)`, so the server cannot call it
  (doctest of the module, `compile_fail`). `start(.., None, ..)` is the only way
  to get a fake answer, and it draws a fresh masking key each time, so the answer
  for an unknown name changes between calls. A server that needs the same answer every time builds its own
  deterministic fake record and passes it in as a record. [`dummy_record_is_not_reachable`]
* `KE1` is **96 bytes** (blinded element 32, client nonce 32, client ephemeral
  key 32). `KE2` is **320 bytes**. `KE3` is **64 bytes** (the client's MAC).
* **The login state is 128 bytes, not 192.** `ServerLogin::serialize` gives the
  3DH session key (64) and the MAC the server expects in `KE3` (64), nothing
  else (`Ke2State` in `src/key_exchange/tripledh.rs`). There is no transcript
  hash in it. The state round-trips and finishes to the same session key.
  [`server_login_state_roundtrips_128_bytes`]
* `KE3` is checked by `ConstantTimeEq` on the MAC (`finish_ke`). A wrong MAC is
  `InvalidLoginError`; a changed bit at any of the 64 positions is an error and
  `finish` takes the state by value, so a state is used once. [`ke3_mac_mismatch_is_an_error_not_a_panic`]
* `finish` returns the session key. Ferret does not use it (Fase 1 § 4.2 step 4);
  a server wipes it at once.

## Malformed input

* Points that are not a ristretto255 element (`0xff…ff`, a negative encoding,
  a value above the field modulus) and the identity element are refused by
  `deserialize`, in the registration request, in `KE1` (both the blinded element
  and the ephemeral key) and in a record. Different places give different
  variants of `ProtocolError` (`SerializationError`, or a library error from
  `voprf`); a server should map all of them to one error without reading
  the variant. [`malformed_points_are_errors`]

## Not checked here

* The state and the record are not authenticated by `opaque-ke`. A server has
  to seal the state and take the record only from the client's signed upload
  itself.
* Memory the library copies internally (`oprf_seed.clone()` in
  `key_material_info`, HKDF state) is outside reach, as on the client side.
