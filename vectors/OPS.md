# Operations register

Every vector case names an `op`. This register maps each `op` to the Rust
function that runs it, the WASM method that exposes it, and the shape of the
case's `input`. The Rust, Node and browser runners are table-driven from this
list. A case may only use an `op` that is listed here.

Rows are added by the task that introduces the operation. The first column
holds the op name in backticks.

| Op | Rust function | WASM method | `input` shape |
|---|---|---|---|
| `tlv.build` | `Tlv` builder, then `Tlv::finish` | `tlv_build` | `{ "fields": [ ... ] }`, each field one of `{ "type": "label", "value": ascii }`, `{ "type": "label_hex", "value": hex }`, `{ "type": "u8", "tag": hex1, "value": number }`, `{ "type": "u64", "tag": hex1, "value": decimal string }`, `{ "type": "bytes", "tag": hex1, "value": hex }` or `{ "type": "bytes", "tag": hex1, "fill": { "byte": hex1, "len": number } }`. `expect` is `{ "tlv": hex }`. |
| `kdf.argon2id` | `prim::argon2::argon2id` (checked) | `kdf_argon2id` | `{ "password": hex, "salt": hex, "m_kib": number, "t": number, "p": number, "out_len": number }`. `expect` is `{ "hash": hex }`. |
| `text.nfkd` | `text::unicode::nfkd` | `text_nfkd` | Text input. `expect` is `{ "nfkd": hex }` (UTF-8 bytes). |
| `text.mp` | `MasterPassword::new` | `master_password_check` | Text input and `"policy"`: `"with_secret_key"` (minimum 12) or `"without_secret_key"` (minimum 15). `expect` is `{ "mp": hex }`, the NFKD bytes. |
| `text.opaque_input` | `MasterPassword::new`, then `MasterPassword::opaque_input` | `opaque_input_build` | Text input, `"policy"` and `"secret_key"` (hex, 16 bytes, or `null`). `expect` is `{ "opaque_input": hex }`: `mp`, or `mp`, `0x00`, `SK`. |
| `text.export_password` | `ExportPassword::new` | `export_password_check` | Text input and `"master_password"`: a text input (checked with the policy `with_secret_key`) or `null`. `expect` is `{ "export_password": hex }`, the NFKD bytes. |
| `code.rk.encode` | `encode_recovery_key` | `recovery_key_encode` | `{ "key": hex }` (32 bytes). `expect` is `{ "code": "FFR1-..." }`. |
| `code.rk.decode` | `decode_recovery_key` | `recovery_key_decode` | `{ "code": string }`; separators are dropped before reading: `-`, ASCII whitespace, U+00A0, U+2013, U+2014. `expect` is `{ "key": hex }`. |
| `code.sk.encode` | `encode_secret_key` | `secret_key_encode` | `{ "key": hex }` (16 bytes). `expect` is `{ "code": "FFS1-..." }`. |
| `code.sk.decode` | `decode_secret_key` | `secret_key_decode` | `{ "code": string }`. `expect` is `{ "key": hex }`. |
| `kdf.kek.password` | `Kek::from_export_key` | `kek_from_export_key` | `{ "account_id": hex16, "export_key": hex64 }`. `expect` is `{ "kek": hex32 }`. |
| `kdf.kek.recovery` | `Kek::from_recovery_key`, `recovery_public_key` | `kek_from_recovery_key` | `{ "account_id": hex16, "rk": hex32 }`. `expect` is `{ "kek", "seed_r", "pk_r" }` (hex32 each). |
| `kdf.vk_derive` | `UnlockedVault::from_vault_key` | `vault_derive_keys` | `{ "account_id": hex16, "vault_id": hex16, "vk_epoch": decimal string, "vk": hex32 }`. `expect` is `{ "k_head", "k_del", "k_meta", "seed_a", "pk_a" }` (hex32 each). |
| `kdf.kek.prf` | `Kek::from_prf` | `kek_from_prf` | `{ "credential_id": hex (may be empty), "prf_output": hex32 }`. `expect` is `{ "kek": hex32 }`. The salt has no `account_id`. |
| `kdf.kek.pin_extension` | `Pin::new`, then `Kek::from_pin_extension` | `kek_from_pin_extension` | `{ "pin": string of digits, "device_salt": hex16 }`; profile 1. `expect` is `{ "kek": hex32 }`. |
| `kdf.kek.pin_mobile` | `Pin::new`, then `Kek::from_pin_mobile` | `kek_from_pin_mobile` | As `kdf.kek.pin_extension` plus `"kek_dev_pin": hex32`. `expect` is `{ "kek": hex32 }`. |
| `wrap.seal.password` | `Kek::from_export_key`, then `wrap_vk` with `Method::Password` | `wrap_password` | `{ "account_id", "vault_id", "method_id": hex16, "vk_epoch", "kek_generation": decimal strings, "ksf_profile": 1, "export_key": hex64, "vk": hex32 }`. `rng` is the 24-byte nonce. `expect` is `{ "wrap": hex }` (104 bytes); `intermediate` is `{ "kek", "aad", "commit" }`. |
| `wrap.seal.recovery` | `Kek::from_recovery_key`, then `wrap_vk` with `Method::Recovery` | `wrap_recovery` | The common fields above with `"rk": hex32` instead of the password fields. `expect` is a 72-byte wrap; `intermediate` is `{ "kek", "aad" }`. |
| `wrap.seal.prf` | `Kek::from_prf`, then `wrap_vk` with `Method::Prf` | `wrap_prf` | The common fields with `"credential_id": hex`, `"prf_salt": hex32`, `"prf_output": hex32`. 72-byte wrap. |
| `wrap.seal.pin` | `Pin::new`, `Kek::from_pin_extension`, then `wrap_vk` with `Method::Pin` | `wrap_pin` | The common fields with `"pin"` and `"device_salt": hex16`. 104-byte wrap; the AAD is the PIN AAD of Fase 1 § 7.2 (it has `vault_id` and `method_id`, but no `kek_generation`). |
| `wrap.seal.pin_mobile` | `Pin::new`, `Kek::from_pin_mobile`, then `wrap_vk` with `Method::Pin` | `wrap_pin_mobile` | As `wrap.seal.pin` plus `"kek_dev_pin": hex32`. |
| `wrap.seal.device` | `Kek::generate`, then `wrap_vk` with `Method::Device` | `wrap_device` | The common fields. `rng` is two draws: the 32-byte KEK, then the 24-byte nonce. 72-byte wrap; no commitment. |
| `wrap.open` | `unwrap_vk` | `wrap_open` | The common fields plus `"kek": hex32`, `"wrap": hex` and `"method"`: `{ "type": "password", "ksf_profile": 1 }`, `{ "type": "recovery" }`, `{ "type": "prf", "credential_id", "prf_salt" }`, `{ "type": "pin", "device_salt" }` or `{ "type": "device" }`. `expect` is `{ "vk": hex32, "pk_a": hex32 }`; every failure is `decrypt`. |
| `cbor.decode` | `cbor::decode`, then `cbor::encode` | `cbor_check` | `{ "segments": [...] }` (byte segments, below). `expect` is `{ "len": number, "sha256": hex }` of the bytes written back by the encoder (shortest form, map order kept); every refusal has its own `malformed_cbor_*` code. |
| `pad.apply` | `item::pad::pad` | `pad_apply` | `{ "plain": { "segments": [...] } }`. `expect` is `{ "padded_len": number, "padded_sha256": hex }`; 61 440 bytes or more of plaintext is `too_large`. |
| `pad.remove` | `item::pad::unpad` | `pad_remove` | `{ "padded": { "segments": [...] } }`. `expect` is `{ "plain_len": number, "plain_sha256": hex }`; a buffer that does not end in `0x80` and zeros is `decrypt`. |
| `item.seal` | `ItemBody::from_cbor`, then `encrypt_item` | `item_seal` | `{ "account_id", "vault_id": hex16, "vk_epoch": decimal string, "vk": hex32, "item_id": hex16, "rev": decimal string, "body": { "segments": [...] }, "existing": hex }` (`existing` only for an edit). `rng` is `[IK (32), nonce of ik_wrap (24), nonce of the body (24)]` for a new item and `[nonce of the body (24)]` for an edit. `expect` is `{ "envelope": hex, "tag": hex }`; `intermediate` is `{ "ik": hex32, "ik_aad": hex, "body_aad": hex, "padded_len": number }`. A body with `schema` above 1 is `read_only_schema`. |
| `item.seal.digest` | as `item.seal` | `item_seal` | As `item.seal`, for envelopes too large to list. `expect` is `{ "envelope_len": number, "envelope_sha256": hex, "tag": hex }`. |
| `item.open` | `decrypt_item`, then `ItemBody::to_cbor` | `item_open` | `{ "account_id", "vault_id", "vk_epoch", "vk", "item_id", "rev", "envelope": hex, "tag": hex32 }`. `expect` is `{ "read_only": bool, "body": hex }`, the body written back as CBOR. A wrong tag, key, id, revision or any changed byte is `decrypt`; a bad header is `unsupported` or `malformed_envelope`. |
| `item.manifest.seal` | `Manifest::from_cbor`, then `encrypt_manifest` | `manifest_seal` | The vault fields, `"rev"` and `"manifest": hex` (the CBOR). `rng` is the 24-byte nonce. `expect` is `{ "envelope": hex, "tag": hex }`. |
| `item.manifest.open` | `decrypt_manifest`, then `Manifest::to_cbor` | `manifest_open` | The vault fields, `"rev"`, `"envelope": hex` and `"tag": hex32`. `expect` is `{ "manifest": hex }`. A `v` other than 1 is `unsupported`. |

Text input is either `{ "utf8": hex }` (bytes, used for input that is not UTF-8) or `{ "segments": [ { "escapes": "U+0061 U+030A", "repeat": 12 } ] }`: the text is the concatenation of the segments, each segment being its code points repeated `repeat` times. A short text may also carry `"text"` for reading; it must equal the segments.

Byte segments are `{ "segments": [ { "hex": hex, "repeat": number } ] }`: the bytes are the concatenation of each `hex` repeated `repeat` times, so a body of 61 439 bytes is a few lines.
