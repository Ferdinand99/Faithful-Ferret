# Project Wycheproof test vectors

Unmodified copies of files from the Wycheproof project, used to check the
crates that the core builds on (and the ECDSA P-256 verifier that the passkey
code will use).

- Repository: https://github.com/C2SP/wycheproof
- Commit: `d17cc89fa5c8f4f4d378b5385ebf75da5d0926c9` (committed 2026-10-23)
- Directory in the repository: `testvectors_v1/`
- Retrieved: 2026-10-29
- Licence: Apache License 2.0, see https://github.com/C2SP/wycheproof/blob/d17cc89fa5c8f4f4d378b5385ebf75da5d0926c9/LICENSE

| File | Source URL (raw, at the commit above) | SHA-256 |
|---|---|---|
| `xchacha20_poly1305_test.json` | https://raw.githubusercontent.com/C2SP/wycheproof/d17cc89fa5c8f4f4d378b5385ebf75da5d0926c9/testvectors_v1/xchacha20_poly1305_test.json | `a79de072571b90eb40c3a63ce0c7f75dcb4b62323c8870228e1f61dcc61d63a9` |
| `chacha20_poly1305_test.json` | https://raw.githubusercontent.com/C2SP/wycheproof/d17cc89fa5c8f4f4d378b5385ebf75da5d0926c9/testvectors_v1/chacha20_poly1305_test.json | `fe61d25f90e1bde4461d00eafe61049e5f29bd999f36b766df9cda90906ad53d` |
| `ecdsa_secp256r1_sha256_test.json` | https://raw.githubusercontent.com/C2SP/wycheproof/d17cc89fa5c8f4f4d378b5385ebf75da5d0926c9/testvectors_v1/ecdsa_secp256r1_sha256_test.json | `182db4f3e230f6f9fa9f800d2a614dede30284b8e8438bbfe1171905402e9332` |
| `ed25519_test.json` | https://raw.githubusercontent.com/C2SP/wycheproof/d17cc89fa5c8f4f4d378b5385ebf75da5d0926c9/testvectors_v1/ed25519_test.json | `ea80ffebac085e21cb9d3e903e7fa2b448d96702da5b31f061d0b83b430b74b3` |
| `hkdf_sha256_test.json` | https://raw.githubusercontent.com/C2SP/wycheproof/d17cc89fa5c8f4f4d378b5385ebf75da5d0926c9/testvectors_v1/hkdf_sha256_test.json | `bb2b462a38b251cb52a2aede706d6d4b62b26864f4e80c95497507ddb07c5f1e` |
| `hmac_sha256_test.json` | https://raw.githubusercontent.com/C2SP/wycheproof/d17cc89fa5c8f4f4d378b5385ebf75da5d0926c9/testvectors_v1/hmac_sha256_test.json | `2d201cfa61d1bf95e6f5d07d96634b4a348b31e8eaa277ad7c8d09677b7a743f` |

The files are kept in their original format. How a test treats each result:

- `valid`: the operation must succeed with the expected output.
- `invalid`: the operation must fail (decryption and verification: with the
  single `decrypt` error).
- `acceptable`: either outcome is accepted, and the outcome is printed by the
  test (these are, for Ed25519, public keys of small or mixed order, which the
  strict verifier rejects).
