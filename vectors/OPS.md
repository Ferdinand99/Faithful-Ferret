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
