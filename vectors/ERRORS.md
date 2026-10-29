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
| `malformed_cbor` | CBOR body is malformed. |
| `malformed_export_header` | Export file header is malformed. |
| `malformed_tlv` | TLV encoding is malformed. |
| `malformed_entries` | Checkpoint entries are malformed. |
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
| `unsupported` | Not supported by this build or version. |
