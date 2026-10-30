# Associated data of the vault-key wraps

A wrap is the vault key (VK) sealed under the key-encryption key (KEK) of one
unlock method with XChaCha20-Poly1305. The associated data (AAD) binds the wrap
to the account, the vault, the method and its generation, so a wrap cannot be
moved to another place or replayed at another generation. This page states the
AAD of every method, as the code builds it in
[`crates/ferret-core/src/wrap.rs`](../crates/ferret-core/src/wrap.rs)
(`wrap_aad`). The byte-level test vectors are in `vectors/internal/wrap.json`.

## Encoding

The AAD is a list of TLV fields written one after the other, with no other
separator: `tag (1 byte) | length (u16, big endian) | value`. Numbers are big
endian. The tags are defined in `crates/ferret-core/src/tlv.rs` (`tag`), and the
order below is the order in the AAD.

| Field | Tag | Value |
|---|---|---|
| label | `0x01` | ASCII text, always starting with `ferret/v1/` |
| suite | `0x03` | 1 byte, `0x01` |
| account_id | `0x10` | 16 bytes |
| vault_id | `0x11` | 16 bytes |
| method_id | `0x13` | 16 bytes |
| method_type | `0x14` | 1 byte |
| vk_epoch | `0x20` | u64 |
| kek_generation | `0x21` | u64 |
| kdf | `0x30` | 12 bytes: `m_kib`, `t`, `p`, each a u32 |
| credential_id | `0x31` | the passkey credential id |
| prf_salt | `0x32` | 32 bytes |
| device_salt | `0x37` | 16 bytes |

## The generic wrap AAD

For `password`, `recovery`, `prf` and `device`:

```
label            0x01  "ferret/v1/wrap"
suite            0x03  0x01
account_id       0x10
vault_id         0x11
method_type      0x14
method_id        0x13
vk_epoch         0x20
kek_generation   0x21
<method-specific fields>
```

There is no `version` field in this AAD, unlike the AADs of the item and the
item key. Note that `method_type` comes before `method_id`.

| Method | `method_type` | Method-specific fields | Commitment |
|---|---|---|---|
| `password` | 1 | `kdf` (`0x30`), the Argon2id parameters of the profile the export key was made with | yes |
| `recovery` | 2 | none | no |
| `prf` (passkey) | 3 | `credential_id` (`0x31`), then `prf_salt` (`0x32`) | no |
| `device` | 5 | none | no |

## The device wrap

A `device` wrap (method type 5) is a local device key that is never uploaded. Its
AAD is the generic wrap AAD with no method-specific field:

```
0x01 | len 14 | "ferret/v1/wrap"
0x03 | len 1  | 0x01
0x10 | len 16 | account_id
0x11 | len 16 | vault_id
0x14 | len 1  | 0x05
0x13 | len 16 | method_id
0x20 | len 8  | vk_epoch
0x21 | len 8  | kek_generation
```

That is 104 bytes. There is no `kdf`, `credential_id`, `prf_salt` or
`device_salt` field. The wrap itself is 72 bytes, `nonce (24) | VK (32) | tag
(16)`, and has **no key commitment**: only `password` and `pin` wraps carry one.
The `kek_generation` is part of the AAD, so a device wrap is replaced under a new
generation rather than rewritten in place.

## The PIN wrap

A local `pin` wrap (method type 4) has an AAD of its own. It uses a different
label, the same field order, no `kek_generation`, and the 16-byte salt of the PIN
stretching:

```
label            0x01  "ferret/v1/pin"
suite            0x03  0x01
account_id       0x10
vault_id         0x11
method_type      0x14  0x04
method_id        0x13
vk_epoch         0x20
device_salt      0x37
```

The wrap exists only on one device and is replaced, never rolled forward, so it has
no generation. It carries a key commitment, like the password wrap.

## The key commitment

`password` and `pin` wraps end with a 32-byte commitment,
`HKDF-SHA256(salt = none, ikm = KEK, info = "ferret/v1/commit")`. On opening,
the commitment is compared in constant time before the AEAD is opened, and every
failure is the single `decrypt` error. The commitment is what makes the wrap
key-committing: a ciphertext cannot be made to open under two different keys.
