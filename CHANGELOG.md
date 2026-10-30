# Changelog

## 0.1.0 (2026-10-30)


### Features

* **core:** account creation, password change, recovery flow and setup QR payload ([#12](https://github.com/Ferdinand99/Faithful-Ferret/issues/12)) ([fc78650](https://github.com/Ferdinand99/Faithful-Ferret/commit/fc78650105f80716b210e37062bfbb04666c91eb))
* **core:** encrypted export format with import validation and neutralized plain export ([#8](https://github.com/Ferdinand99/Faithful-Ferret/issues/8)) ([b9c0fff](https://github.com/Ferdinand99/Faithful-Ferret/commit/b9c0fff2322e39a80297df01ebc6f0ac904982ea))
* **core:** key hierarchy, unlock-method wraps with key commitment and pinning checks ([#5](https://github.com/Ferdinand99/Faithful-Ferret/issues/5)) ([a29d6ce](https://github.com/Ferdinand99/Faithful-Ferret/commit/a29d6ce39c6b512f47fd940e947da517cc7b90c6))
* **core:** master password normalization and recovery/secret key codes ([#4](https://github.com/Ferdinand99/Faithful-Ferret/issues/4)) ([cf34dca](https://github.com/Ferdinand99/Faithful-Ferret/commit/cf34dcafa86888416f24112786d2cb208a6001bb))
* **core:** OPAQUE client over opaque-ke with pinned Argon2id KSF profile ([#9](https://github.com/Ferdinand99/Faithful-Ferret/issues/9)) ([e7a4c89](https://github.com/Ferdinand99/Faithful-Ferret/commit/e7a4c89707d809459ede8e187296d011f2192d45))
* **core:** passkey authenticator core with PRF seeds, WebAuthn builders and origin rules ([#11](https://github.com/Ferdinand99/Faithful-Ferret/issues/11)) ([c82097f](https://github.com/Ferdinand99/Faithful-Ferret/commit/c82097ff3273456938646860996ca1fa46ea4412))
* **core:** primitives, TLV builder, KDF bounds and external known-answer vectors ([#3](https://github.com/Ferdinand99/Faithful-Ferret/issues/3)) ([e8113ea](https://github.com/Ferdinand99/Faithful-Ferret/commit/e8113ea8da4b2245462148a91f3d3ca0851162bb))
* **core:** server-suite feature exports the OPAQUE suite for the server library ([#28](https://github.com/Ferdinand99/Faithful-Ferret/issues/28)) ([3a96757](https://github.com/Ferdinand99/Faithful-Ferret/commit/3a96757d5bd610574b9a162800003a3829a59665))
* **core:** strict CBOR, padding, unknown-field preservation and item envelope ([#6](https://github.com/Ferdinand99/Faithful-Ferret/issues/6)) ([9a9cf10](https://github.com/Ferdinand99/Faithful-Ferret/commit/9a9cf10ffe51aa3e6fbdc0ff090bb3e4a9a2f7a2))
* **core:** tombstones, signed checkpoints, mutation proofs and full rekey ([#7](https://github.com/Ferdinand99/Faithful-Ferret/issues/7)) ([93c3a43](https://github.com/Ferdinand99/Faithful-Ferret/commit/93c3a43bbcde287227144d267bbbead095243088))
* **core:** TOTP with strict otpauth parsing ([#10](https://github.com/Ferdinand99/Faithful-Ferret/issues/10)) ([54de629](https://github.com/Ferdinand99/Faithful-Ferret/commit/54de629488b90e07c449eb7ba9c2d2a822c83acc))
* **wasm:** worker-friendly binding where key material stays in WASM memory ([#13](https://github.com/Ferdinand99/Faithful-Ferret/issues/13)) ([9a8958a](https://github.com/Ferdinand99/Faithful-Ferret/commit/9a8958afdadd452999e46128e657c6fc1a54fe54))


### Bug Fixes

* **core:** rollback memory, unlock-method changes and the other findings of the final review ([#27](https://github.com/Ferdinand99/Faithful-Ferret/issues/27)) ([68b3a15](https://github.com/Ferdinand99/Faithful-Ferret/commit/68b3a15bdd29e167077f30f551d1419d97d99446))
* **wasm:** harden key arguments, lock, passkey create and plain export ([#25](https://github.com/Ferdinand99/Faithful-Ferret/issues/25)) ([ba51695](https://github.com/Ferdinand99/Faithful-Ferret/commit/ba51695698171633ecbb1d008107c5af255ec2cb))
