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
| `malformed_entries` | Checkpoint entries are malformed. |
| `malformed_pinned_record` | A value in the pinned record is out of range, or the record would grow without bound. |
| `malformed_opaque_message` | An OPAQUE message from the server with the wrong length, or one that holds something that is not a group element or key. A message that parses but does not authenticate is `decrypt`. |
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
