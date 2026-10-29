# Sources of the specification vectors

These four files hold the published test vectors of the standards that the
core builds on. They contain only the numbers printed in the documents, in a
small JSON layout of our own (lowercase hex, no prefix). They were extracted
from the document text by a script and then checked byte for byte by the test
suite, which runs every case against the implementation.

| File | Document | Section | Licence of the source |
|---|---|---|---|
| `rfc9106-argon2id.json` | RFC 9106, Argon2 | 5.3, Argon2id test vector | IETF Trust (RFC text, test data) |
| `rfc5869-hkdf.json` | RFC 5869, HKDF | Appendix A.1 to A.3 (SHA-256) | IETF Trust (RFC text, test data) |
| `rfc8032-ed25519.json` | RFC 8032, EdDSA | 7.1, tests 1, 2, 3, 1024 and SHA(abc) for Ed25519 | IETF Trust (RFC text, test data) |
| `xchacha-draft-03.json` | draft-irtf-cfrg-xchacha-03 | Appendix A.3.1, AEAD_XCHACHA20_POLY1305 | IETF Trust (draft text, test data) |

## Where the text came from

| Document | URL | SHA-256 of the text file |
|---|---|---|
| RFC 9106 | https://www.rfc-editor.org/rfc/rfc9106.txt | `855c06f060379e34285e83a217e9069b5c72e161a1e54df9af5cd88dbb231f31` |
| RFC 5869 | https://www.rfc-editor.org/rfc/rfc5869.txt | `7a40eb3835b35fc947eb12a2ed614db079d43b26e50dbc537c31fba16397089c` |
| RFC 8032 | https://www.rfc-editor.org/rfc/rfc8032.txt | `ed63657ff389301282b169b0abde9b5dd2c7e4d524fdfa5da6ff3094fc93c4c3` |
| draft-irtf-cfrg-xchacha-03 | https://www.ietf.org/archive/id/draft-irtf-cfrg-xchacha-03.txt | `fa796b50265eeee383d40e82fed880267c7835e1b3d64c50c4f06162adaa1cfd` |

Retrieved 2026-10-29.

## SHA-256 of the files in this directory

| File | SHA-256 |
|---|---|
| `rfc9106-argon2id.json` | `e2d6d0b9641c99593b92193be462d0444d23db70d0568a3d1a15a84e28210268` |
| `rfc5869-hkdf.json` | `4b631df5e9a80dd3c72dcd0cca75cb8a9f85120bbc4ee3c486b890c8c2544250` |
| `rfc8032-ed25519.json` | `35ce42facfcf313e9c7ec3e29463249c657d7d31a8be9f3ad68154ec2e3d6476` |
| `xchacha-draft-03.json` | `e8ec9a4feafa2aaf227f18b72fccc78a3346a83b84c02f51054dd35755768933` |

The message of RFC 8032 test "1024" is 1023 bytes long, as printed in the RFC.

The Wycheproof vectors are in `wycheproof/`, with their own `SOURCE.md`.
