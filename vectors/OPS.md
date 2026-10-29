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
| `code.rk.decode` | `decode_recovery_key` | `recovery_key_decode` | `{ "code": string }`. `expect` is `{ "key": hex }`. |
| `code.sk.encode` | `encode_secret_key` | `secret_key_encode` | `{ "key": hex }` (16 bytes). `expect` is `{ "code": "FFS1-..." }`. |
| `code.sk.decode` | `decode_secret_key` | `secret_key_decode` | `{ "code": string }`. `expect` is `{ "key": hex }`. |

Text input is either `{ "utf8": hex }` (bytes, used for input that is not UTF-8) or `{ "segments": [ { "escapes": "U+0061 U+030A", "repeat": 12 } ] }`: the text is the concatenation of the segments, each segment being its code points repeated `repeat` times. A short text may also carry `"text"` for reading; it must equal the segments.
