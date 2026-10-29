# Sources of the specification vectors

These files hold the published test vectors of the standards that the
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
| `rfc9807-opaque-ristretto255.json` | RFC 9807, OPAQUE | Appendix C.1.1 and C.1.2 (real test vectors 1 and 2) | IETF Trust (RFC text, test data) |
| `rfc9497-oprf-ristretto255.json` | RFC 9497, OPRF | Appendix A.1.1 (ristretto255-SHA512, OPRF mode, test vectors 1 and 2) | IETF Trust (RFC text, test data) |
| `rfc6238-totp.json` | RFC 6238, TOTP | Appendix B, the 18 test values (SHA-1, SHA-256, SHA-512 at six times, eight digits) | IETF Trust (RFC text, test data) |
| `rfc4226-hotp.json` | RFC 4226, HOTP | Appendix D, the ten test values (counter 0 to 9) with the HMAC-SHA-1 digests | IETF Trust (RFC text, test data) |

## Where the text came from

| Document | URL | SHA-256 of the text file |
|---|---|---|
| RFC 9106 | https://www.rfc-editor.org/rfc/rfc9106.txt | `855c06f060379e34285e83a217e9069b5c72e161a1e54df9af5cd88dbb231f31` |
| RFC 5869 | https://www.rfc-editor.org/rfc/rfc5869.txt | `7a40eb3835b35fc947eb12a2ed614db079d43b26e50dbc537c31fba16397089c` |
| RFC 8032 | https://www.rfc-editor.org/rfc/rfc8032.txt | `ed63657ff389301282b169b0abde9b5dd2c7e4d524fdfa5da6ff3094fc93c4c3` |
| draft-irtf-cfrg-xchacha-03 | https://www.ietf.org/archive/id/draft-irtf-cfrg-xchacha-03.txt | `fa796b50265eeee383d40e82fed880267c7835e1b3d64c50c4f06162adaa1cfd` |
| RFC 9807 | https://www.rfc-editor.org/rfc/rfc9807.txt | `424103278391d8955713ea8b3a85509e5178fab536be42144b99d298458acc03` |
| RFC 9497 | https://www.rfc-editor.org/rfc/rfc9497.txt | `95160517617374655fe23af2c6cec311eae326deb7689239f97641fd5a560432` |

Retrieved 2026-10-29.

## SHA-256 of the files in this directory

| File | SHA-256 |
|---|---|
| `rfc9106-argon2id.json` | `e2d6d0b9641c99593b92193be462d0444d23db70d0568a3d1a15a84e28210268` |
| `rfc5869-hkdf.json` | `4b631df5e9a80dd3c72dcd0cca75cb8a9f85120bbc4ee3c486b890c8c2544250` |
| `rfc8032-ed25519.json` | `35ce42facfcf313e9c7ec3e29463249c657d7d31a8be9f3ad68154ec2e3d6476` |
| `xchacha-draft-03.json` | `e8ec9a4feafa2aaf227f18b72fccc78a3346a83b84c02f51054dd35755768933` |
| `rfc9807-opaque-ristretto255.json` | `0e711c486e101c05ed5c3a685a24eb61e46224d4d4febf1df9534145aac6c2ec` |
| `rfc9497-oprf-ristretto255.json` | `2dd137ce56560149b25b547b7cc8070aa918f843026310f01700b1e7c009211b` |
| `rfc6238-totp.json` | `315bf51a41feecc1febb6be3245f16d8f84529f141a73d5290b6733afd691499` |
| `rfc4226-hotp.json` | `11e6b75510b0eb55164447cb5db1c59f2ab6ccd8f135c2b35399ad054fde3198` |

The two OTP files (RFC 4226 and RFC 6238, URLs `https://www.rfc-editor.org/rfc/rfc4226.txt` and `https://www.rfc-editor.org/rfc/rfc6238.txt`) were entered from the printed tables and then recomputed with an independent HMAC implementation (Python `hmac`, `hashlib`) on 2026-10-29; every value agreed. RFC 6238 uses a seed per algorithm: `12345678901234567890` (20 bytes) for SHA-1, the same digits extended to 32 bytes for SHA-256 and to 64 bytes for SHA-512.

The message of RFC 8032 test "1024" is 1023 bytes long, as printed in the RFC.

The Wycheproof vectors are in `wycheproof/`, with their own `SOURCE.md`.

## OPAQUE (RFC 9807) and OPRF (RFC 9497)

`rfc9807-opaque-ristretto255.json` has the two real test vectors of RFC 9807
Appendix C.1 whose group is ristretto255 (the OPRF is `ristretto255-SHA512`,
Hash SHA-512, KDF HKDF-SHA-512, MAC HMAC-SHA-512): vector 1 without
identities and vector 2 with `client_identity` and `server_identity`. They
are the vectors that fit Ferret's suite 1. The others in the RFC use the
group `curve25519` (vectors 3 and 4), P-256 (5 and 6) or are fake vectors
for an unknown user (C.2, a server-side case); none of them is run.

The RFC's KSF is the identity function and its context is `OPAQUE-POC`, so
the test (`tests/opaque_rfc9807.rs`) runs the production client code
instantiated for a suite that differs from Ferret's in only these two parts.
The numbers in the file are exactly those printed in the RFC (inputs,
intermediate values and outputs); the extraction script only joined the hex
lines that the RFC text wraps at 69 columns.

`rfc9497-oprf-ristretto255.json` has the two test vectors of RFC 9497
Appendix A.1.1 (OPRF mode, batch size 1) for `ristretto255-SHA512`. They
check the OPRF that OPAQUE builds on, in the `voprf` crate that `opaque-ke`
uses: `DeriveKeyPair` from the seed and key info, the blinded element, the
evaluated element and the output. The VOPRF and POPRF modes of the RFC are
not used by OPAQUE and are not included.
