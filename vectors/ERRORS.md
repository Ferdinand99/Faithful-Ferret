# Error code register

`Error::code()` returns one of these stable codes. Test vectors refer to them
in `expect_error`, and the WASM binding exposes them as the only error
information. A code never carries data about secrets. A test checks that this
list and `Error::code()` agree exactly.

All authentication failures (wrong key, AAD, tag, commit, signature, padding)
share the single code `decrypt`, with no cause.

| Code | Meaning |
|---|---|
| `decrypt` | Any authentication failure, without a cause. |
| `kdf_out_of_range` | Argon2id parameters outside the floor and ceiling. |
| `kdf_profile_unknown` | Unknown KSF profile. |
| `kdf_profile_downgrade` | KSF profile below the pinned one. |
| `kdf_out_of_memory` | Argon2id could not allocate its memory. |
| `input_too_short` | Input shorter than the minimum. |
| `input_too_long` | Input longer than the maximum. |
| `input_not_utf8` | Input is not valid UTF-8. |
| `input_forbidden_character` | Input contains a forbidden or unassigned character. |
| `input_same_as_master_password` | The export password is equal to the master password. |
| `input_secret_key_mismatch` | The secret key given to an account flow is not the one in the OPAQUE input, or only one of them has a secret key. |
| `input_all_zero` | A PRF output, a `KEK_dev_pin` or a `K_exp` that was handed to the core is all zero bytes: a broken or wiped buffer, not a key. |
| `input_last_method` | A request would remove the last `password` or the last `recovery` method of the vault. |
| `malformed_envelope` | Item or manifest envelope is malformed. |
| `malformed_cbor` | CBOR is malformed: syntax error, truncated input, bad UTF-8 or a reserved byte. |
| `malformed_cbor_duplicate_key` | A CBOR map has the same key twice. |
| `malformed_cbor_indefinite` | CBOR with an indefinite length. |
| `malformed_cbor_tag` | CBOR with a tag (the allow-list is empty in v1). |
| `malformed_cbor_depth` | CBOR nested deeper than 16 levels. |
| `malformed_cbor_count` | A CBOR array or map with more than 10 000 entries, or more nodes in all than the caller allows (1 000 000 for an export body). |
| `malformed_cbor_size` | CBOR text or bytes longer than 64 KiB. |
| `malformed_cbor_key_type` | A CBOR map key that is not text. |
| `malformed_cbor_simple` | CBOR `undefined` or a simple value other than `true`, `false`, `null`. |
| `malformed_cbor_int` | A CBOR integer outside the range of `i64` and `u64`. |
| `malformed_cbor_trailing` | Bytes after the first CBOR data item. |
| `malformed_item_body` | An item body or manifest that does not have the shape of the schema. |
| `malformed_export_header` | Export file header is malformed, or the file is too short for its header, wrapped key and body. |
| `malformed_tlv` | TLV encoding is malformed. |
| `malformed_entries` | Checkpoint entries are malformed, or a rekey does not start from the checkpoint it names (wrong `seq`). Also returned when two methods would get the same id: account creation with one id for both wraps, and a recovery that gives the new recovery method an id equal to the password wrap's id or to the id of any manifest entry other than the old recovery entry (the colliding recovery id). Also: two methods of one type in a manifest, a wrap whose id the manifest does not list, a rekey with other than two wraps, and a repeated row id. |
| `malformed_pinned_record` | A value in the pinned record is out of range, or the record would grow without bound. |
| `malformed_sync_memory` | A stored rollback memory that is not in the form `SyncMemory::to_bytes` writes: another version, a length that does not fit the count, a count above 50 000, entries out of order or repeated, or `checkpoint_seq` above `max_seq`. |
| `malformed_opaque_message` | An OPAQUE message from the server with the wrong length, or one that holds something that is not a group element or key. A message that parses but does not authenticate is `decrypt`. |
| `malformed_setup_qr` | The setup QR payload of the emergency sheet is not in the exact format, or a field that goes into it (server address, e-mail) is not allowed. |
| `malformed_otpauth` | An `otpauth://` address or TOTP setting that is not allowed: wrong scheme or type, an unknown or repeated parameter, bad base32, or digits or period out of range. |
| `malformed_origin` | The origin is not one a passkey may be used from: not `https` (or `http://localhost`), an IP host, `null`, `about:blank`, `data:`, `file:`, an opaque origin, or not a valid host. |
| `malformed_rp_id` | The RP ID is not the host of the origin or a dot-delimited suffix of it, is a public suffix, carries a port, or is not a valid domain. |
| `malformed_webauthn_options` | A WebAuthn request that is wrong in itself: a user handle of 0 or more than 64 bytes, or `evalByCredential` naming a credential that is not in `allowCredentials`. |
| `malformed_code` | Recovery or secret key code with a wrong prefix or a letter outside the alphabet. |
| `too_large` | Larger than the allowed size. |
| `read_only_schema` | The item has a newer schema and is read-only. |
| `tombstone_invalid` | A tombstone failed verification. |
| `checkpoint_bad_mac` | The checkpoint MAC is wrong. |
| `checkpoint_bad_digest` | The digest does not match the entries. |
| `checkpoint_hidden_or_rolled_back` | A checkpoint entry is missing from the server's rows. |
| `checkpoint_lower_rev` | A row has a lower revision than the checkpoint records. |
| `checkpoint_same_rev_different_hash` | A row has the same revision but a different hash. |
| `checkpoint_live_behind_tombstone` | A live row is older than a tombstone. |
| `checkpoint_seq_above_top` | The checkpoint sequence is above the server's top sequence. |
| `checkpoint_top_digest_mismatch` | At the top sequence the recomputed digest differs. |
| `checkpoint_top_seq_below_remembered` | The server's highest sequence is below the highest this device has seen. |
| `checkpoint_seq_below_remembered` | The checkpoint's sequence is below the highest verified checkpoint this device remembers. |
| `checkpoint_rev_below_remembered` | A row has a lower revision than the highest this device has seen for that item. |
| `method_list_unknown` | The server lists an unlock method that the manifest does not list, or lists one id twice. |
| `method_list_changed` | The server lists an unlock method of the manifest with another type or another generation. |
| `method_list_missing` | The manifest lists an unlock method that the server does not list. |
| `checksum` | Recovery or secret key checksum error. |
| `non_canonical` | Recovery or secret key is valid but not in canonical form. |
| `not_allowed` | Passkey: user verification missing, cancelled or no match (one value). |
| `invalid_state` | Passkey `create`: a credential in `excludeCredentials` is already stored for this RP ID (WebAuthn `InvalidStateError`). Given only after the user has consented. |
| `unsupported` | Not supported by this build or version. |
| `pinned_server_url` | The server address differs from the one pinned on this device. |
| `pinned_vault_id` | The vault differs from the one pinned on this device. |
| `pinned_account_id` | The account differs from the one pinned on this device. |
| `pinned_kek_generation` | A wrap has a lower `kek_generation` than the highest seen on this device. |
| `pinned_vk_epoch` | The vault has a lower `vk_epoch` than the highest seen on this device. |
| `pinned_sk_bit` | The secret key (SK) bit differs from the one pinned on this device. |
| `pinned_server_key` | The OPAQUE server public key differs from the pinned one, or is missing. |
| `pinned_auth_key` | The vault's `pk_a` differs from the pinned one within the same `vk_epoch`. |

## Server codes

The server library (`ferret-server-auth`) answers with the codes below, and the server vector files (`server-opaque.json`, `server-secrets.json`) use them in `expect_error`. They are listed as bullets, not in the table above, because they are not codes of `Error::code()` of the core. `AuthError::public_code()` gives the first group, and a test checks that this list and the library agree and that every code has an invalid case. `denied` is the one code of every failed authentication, whatever the cause: a client cannot tell a missing login state from a wrong password.

* `malformed_registration_request` — The first registration message is not exactly 32 bytes, or is not a ristretto255 element.
* `malformed_registration_record` — The uploaded record is not exactly 192 bytes, or its client public key is not a valid element.
* `malformed_ke1` — `KE1` is not exactly 96 bytes, or holds something that is not a group element.
* `malformed_ke3` — `KE3` is not exactly 64 bytes.
* `malformed_login_id` — The login id is not 32 characters from `0-9a-f`.
* `malformed_nonce` — The nonce of a signed request is not exactly 32 bytes.
* `malformed_proof` — The proof of a signed request is not exactly 64 bytes.
* `malformed_login_name` — The login name is empty, has a control or invisible character, or is longer than 254 bytes after normalization.
* `malformed_recovery_key` — A recovery has no new recovery key or keeps the stored one, or a change of the password brings one.
* `denied` — Any failed authentication or authorization, without a cause: no login state, an expired or changed one, one made for another purpose, session or account, a `KE3` that does not verify, a nonce that was never issued, is used or has expired, a proof that does not verify.
* `forbidden` — The scope of a session that is already signed in does not allow the call.
* `profile_rejected` — A signed call names a key stretching profile that is unknown or lower than the stored one.
* `throttled` — The caller made too many attempts.
* `internal` — The server failed (a setting out of range, a clock that cannot be read). Never carries a cause.

The codes of a secret file that does not decode (`server.secret_file.*`) belong to the vectors only; the library reports them as an internal failure.

* `bad_magic` — The file does not start with `FSEC`.
* `unsupported_version` — A format version other than 1.
* `wrong_kind` — The file is of another kind than the one asked for, or of an unknown kind.
* `unsupported_suite` — A suite other than 1.
* `bad_length` — The file is shorter than its header, its length field is not the one of the kind, or the file is cut short; also a payload of the wrong length to encode.
* `trailing_bytes` — Bytes after the checksum.
* `bad_checksum` — The checksum does not match.
