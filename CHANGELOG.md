# Changelog

## [0.3.0](https://github.com/Ferdinand99/Faithful-Ferret/compare/v0.2.0...v0.3.0) (2026-11-12)


### Features

* **core:** match saved addresses against a page, and read its origin, site and host ([#112](https://github.com/Ferdinand99/Faithful-Ferret/issues/112)) ([5861ef3](https://github.com/Ferdinand99/Faithful-Ferret/commit/5861ef3117b6f2e051ed9445a052fc162e881cfd))
* safe sync (M2) ([#120](https://github.com/Ferdinand99/Faithful-Ferret/issues/120)) ([4eb49ba](https://github.com/Ferdinand99/Faithful-Ferret/commit/4eb49ba8cade6ef3403fcaf4a2a068499d25ad2e))
* **server:** batch writes, rate limits and a bounded write queue ([#86](https://github.com/Ferdinand99/Faithful-Ferret/issues/86)) ([7aeb14a](https://github.com/Ferdinand99/Faithful-Ferret/commit/7aeb14ab2dc6065987f949fc523a7cf1a4102335))
* **server:** event stream GET /api/sync/events ([#87](https://github.com/Ferdinand99/Faithful-Ferret/issues/87)) ([9f9d42f](https://github.com/Ferdinand99/Faithful-Ferret/commit/9f9d42fd098e7c96b2750e742bb7e17decc5b744))
* **server:** full listing, tombstone retention and restore epoch bump ([#88](https://github.com/Ferdinand99/Faithful-Ferret/issues/88)) ([3f7e086](https://github.com/Ferdinand99/Faithful-Ferret/commit/3f7e086edae8c9c7a793899b4c019f60fef315f9))
* **server:** restore_seq, frozen restore rows and the restore_epoch condition ([#101](https://github.com/Ferdinand99/Faithful-Ferret/issues/101)) ([a52bf68](https://github.com/Ferdinand99/Faithful-Ferret/commit/a52bf680b6f08dd61ba73766000a7db1836145fe))
* **server:** resurrect, checkpoint endpoints and the checkpoint head ([#85](https://github.com/Ferdinand99/Faithful-Ferret/issues/85)) ([0250aee](https://github.com/Ferdinand99/Faithful-Ferret/commit/0250aee4df236f87ea43f08d61f8700f57695e67))
* **server:** sync foundation: narrow handles, stubs, wiring and migration 0005 ([#84](https://github.com/Ferdinand99/Faithful-Ferret/issues/84)) ([45192e5](https://github.com/Ferdinand99/Faithful-Ferret/commit/45192e5423d14d7f38b65734b54224785f28c310))
* **server:** wire contract for batch, checkpoints, listing and sync events ([#82](https://github.com/Ferdinand99/Faithful-Ferret/issues/82)) ([de315aa](https://github.com/Ferdinand99/Faithful-Ferret/commit/de315aa44d1924781c917dd5c28987c7fd75b6de))
* **wasm:** copy_item for keeping both versions of a conflicted item ([#92](https://github.com/Ferdinand99/Faithful-Ferret/issues/92)) ([ab75920](https://github.com/Ferdinand99/Faithful-Ferret/commit/ab75920aa087728b71e8b87cf2d18459ea3ac81e))
* **web:** accept an older server state, preview it and try again after a stop ([#94](https://github.com/Ferdinand99/Faithful-Ferret/issues/94)) ([0695639](https://github.com/Ferdinand99/Faithful-Ferret/commit/0695639a16a9d7b2d623d469030448abfad6ef78))
* **web:** conflict view and local trash ([#97](https://github.com/Ferdinand99/Faithful-Ferret/issues/97)) ([4cd493a](https://github.com/Ferdinand99/Faithful-Ferret/commit/4cd493a0497c6452c5095f0f3e38fa00706483c2))
* **web:** conflicts, a local trash and resurrection in the sync engine ([#96](https://github.com/Ferdinand99/Faithful-Ferret/issues/96)) ([5ad7012](https://github.com/Ferdinand99/Faithful-Ferret/commit/5ad7012d35fc1eea479d58ab59495f51a2a55157))
* **web:** decide an older state with restore_seq and send the restore epoch with every write ([#102](https://github.com/Ferdinand99/Faithful-Ferret/issues/102)) ([a8c705e](https://github.com/Ferdinand99/Faithful-Ferret/commit/a8c705e3b8a5f615ef53590a05f24de126b76f1c))
* **web:** full listing after a 410, checkpoint verification and upload ([#93](https://github.com/Ferdinand99/Faithful-Ferret/issues/93)) ([04b5f23](https://github.com/Ferdinand99/Faithful-Ferret/commit/04b5f23993aa7fccbeffc998f9c86bc762f6bf5e))
* **web:** live updates over the event stream with a status field ([#89](https://github.com/Ferdinand99/Faithful-Ferret/issues/89)) ([610d893](https://github.com/Ferdinand99/Faithful-Ferret/commit/610d893a98ca17bdf16e2f4c19ad6d3c07ee3364))
* **web:** restore text for an older unlock method after an accepted restore ([#100](https://github.com/Ferdinand99/Faithful-Ferret/issues/100)) ([389dc99](https://github.com/Ferdinand99/Faithful-Ferret/commit/389dc995e31ac0e1c8eb79a7f617cd7828f83d0d))
* **web:** run the sync engine in one tab per account and browser ([#108](https://github.com/Ferdinand99/Faithful-Ferret/issues/108)) ([2f56d04](https://github.com/Ferdinand99/Faithful-Ferret/commit/2f56d044b6963141044d3c7fd86ca73d30592ee1))
* **web:** sync memory under a lock, halts, device name and a five-minute poll ([#90](https://github.com/Ferdinand99/Faithful-Ferret/issues/90)) ([f3db138](https://github.com/Ferdinand99/Faithful-Ferret/commit/f3db13865a6d4ea77e4705f0b1dc300f1425e494))
* **web:** sync state, trash and forget stores, engine seam, env passing for lanbox-web.sh ([#81](https://github.com/Ferdinand99/Faithful-Ferret/issues/81)) ([5a99ab9](https://github.com/Ferdinand99/Faithful-Ferret/commit/5a99ab97340c911a77723d19b7bb30e81efde8c4))
* **web:** sync warning banners, restored-server page and forgetting a server ([#95](https://github.com/Ferdinand99/Faithful-Ferret/issues/95)) ([2ceb928](https://github.com/Ferdinand99/Faithful-Ferret/commit/2ceb9288acb480d157e0086c94d25d40c1c8e31a))
* **web:** texts for restore_epoch_refused and trash_copy_skipped ([#103](https://github.com/Ferdinand99/Faithful-Ferret/issues/103)) ([e69bb2b](https://github.com/Ferdinand99/Faithful-Ferret/commit/e69bb2bce370e140e7a2286e1d04d261b95b7fbb))


### Bug Fixes

* **scripts:** accept a tunnel client outside Docker in the ferret-test deploy ([#104](https://github.com/Ferdinand99/Faithful-Ferret/issues/104)) ([f1977f7](https://github.com/Ferdinand99/Faithful-Ferret/commit/f1977f72410ad5fa9445c58d9c5fe20b7fef10f2))
* **server:** clear htmx's history cache after an admin sign-out ([#80](https://github.com/Ferdinand99/Faithful-Ferret/issues/80)) ([8b58c8c](https://github.com/Ferdinand99/Faithful-Ferret/commit/8b58c8c10e97900c755df48f29090c57d438cc48))
* **web:** sync engine fixes found by the sync matrix ([#107](https://github.com/Ferdinand99/Faithful-Ferret/issues/107)) ([d157c5f](https://github.com/Ferdinand99/Faithful-Ferret/commit/d157c5f9e4f67b2705f5e73c21835f4bbdd52151))

## [0.2.0](https://github.com/Ferdinand99/Faithful-Ferret/compare/v0.1.0...v0.2.0) (2026-11-01)


### Features

* **server-auth:** add challenges, signed proofs and record replacement ([#40](https://github.com/Ferdinand99/Faithful-Ferret/issues/40)) ([382ae91](https://github.com/Ferdinand99/Faithful-Ferret/commit/382ae91feef3aba654c1438dcc24f940c735baca))
* **server-auth:** add login_start and login_finish ([#39](https://github.com/Ferdinand99/Faithful-Ferret/issues/39)) ([49cd589](https://github.com/Ferdinand99/Faithful-Ferret/commit/49cd5894f5c4716b87d4d1ab8415368dc2090ecb))
* **server-auth:** add registration on the server ([#34](https://github.com/Ferdinand99/Faithful-Ferret/issues/34)) ([1f1d054](https://github.com/Ferdinand99/Faithful-Ferret/commit/1f1d05427c5888c60ebbebb0daffdaee1011e2ff))
* **server-auth:** add session scopes and the rules for a reset account ([#37](https://github.com/Ferdinand99/Faithful-Ferret/issues/37)) ([bb5629a](https://github.com/Ferdinand99/Faithful-Ferret/commit/bb5629ad192312e42d235913b40f4983ebac870e))
* **server-auth:** add the rate limit hooks ([#32](https://github.com/Ferdinand99/Faithful-Ferret/issues/32)) ([ade8d3e](https://github.com/Ferdinand99/Faithful-Ferret/commit/ade8d3e530b2e36a45d611e050044721fafc0fe2))
* **server-auth:** add the sealed login state and its store ([#36](https://github.com/Ferdinand99/Faithful-Ferret/issues/36)) ([e0ac3fa](https://github.com/Ferdinand99/Faithful-Ferret/commit/e0ac3fa6bc0115e9d667b68edd41102be72cba40))
* **server-auth:** add the secret files, server keys and the startup decision ([#33](https://github.com/Ferdinand99/Faithful-Ferret/issues/33)) ([b26b532](https://github.com/Ferdinand99/Faithful-Ferret/commit/b26b532e68b101012d2b0e7e4bd0c11f39944b21))
* **server-auth:** add the server library crate with shared types and errors ([#29](https://github.com/Ferdinand99/Faithful-Ferret/issues/29)) ([6dda678](https://github.com/Ferdinand99/Faithful-Ferret/commit/6dda678b38b8346a1268ca3ecacb1f6defc63f60))
* **server-auth:** login name normalisation and made-up pre-login answers ([#35](https://github.com/Ferdinand99/Faithful-Ferret/issues/35)) ([ea12ed7](https://github.com/Ferdinand99/Faithful-Ferret/commit/ea12ed7601626503890c61dec1919b017c6bccbd))
* **server:** add sessions, session extractors, rate limits, proxy trust and the architecture test ([#52](https://github.com/Ferdinand99/Faithful-Ferret/issues/52)) ([d3ff581](https://github.com/Ferdinand99/Faithful-Ferret/commit/d3ff581a2a930cf17406c35f0189c8899dad3d03))
* **server:** add the Docker image, compose file and LANBox test deploy ([#57](https://github.com/Ferdinand99/Faithful-Ferret/issues/57)) ([7aa567f](https://github.com/Ferdinand99/Faithful-Ferret/commit/7aa567fc356231299173d2779217d6fe8504a812))
* **server:** add the end-to-end test stack with a test clock ([#61](https://github.com/Ferdinand99/Faithful-Ferret/issues/61)) ([4e6fc7c](https://github.com/Ferdinand99/Faithful-Ferret/commit/4e6fc7ce1f9c22e09a9cf840c7419ba554ac1fd8))
* **server:** add the registration endpoints of the first administrator ([#56](https://github.com/Ferdinand99/Faithful-Ferret/issues/56)) ([cd31fe7](https://github.com/Ferdinand99/Faithful-Ferret/commit/cd31fe7d3eea6dbdd8205028ee492b2983f70ec1))
* **server:** add the server skeleton, migrations and test harness ([#44](https://github.com/Ferdinand99/Faithful-Ferret/issues/44)) ([11eaccb](https://github.com/Ferdinand99/Faithful-Ferret/commit/11eaccb6edf97ab158bd43ea99791f78cc639654))
* **server:** add the sign-in, sign-out and session info endpoints ([#54](https://github.com/Ferdinand99/Faithful-Ferret/issues/54)) ([0d3b054](https://github.com/Ferdinand99/Faithful-Ferret/commit/0d3b054caa41cedff219af7071c67a4c7882815e))
* **server:** add the vault API (unlock methods, changes feed, item writes) ([#55](https://github.com/Ferdinand99/Faithful-Ferret/issues/55)) ([d326e38](https://github.com/Ferdinand99/Faithful-Ferret/commit/d326e3860fb990905d13e574693812df8ca5bce6))
* **server:** add the vault store ([#50](https://github.com/Ferdinand99/Faithful-Ferret/issues/50)) ([3acc88f](https://github.com/Ferdinand99/Faithful-Ferret/commit/3acc88f8c511b7a199bf355e1940c4d8b5c0a95b))
* **server:** add the wire contract and shared fixtures ([#48](https://github.com/Ferdinand99/Faithful-Ferret/issues/48)) ([a439c4b](https://github.com/Ferdinand99/Faithful-Ferret/commit/a439c4b269ec0a6bf11a68efee3af9777b944bc5))
* **server:** hand a session over from the vault origin to the admin origin ([#60](https://github.com/Ferdinand99/Faithful-Ferret/issues/60)) ([185c438](https://github.com/Ferdinand99/Faithful-Ferret/commit/185c4382fe4f562a1cb6d1ec08d4543b24276c1b))
* **server:** load the secret files at start-up and keep login states in SQLite ([#49](https://github.com/Ferdinand99/Faithful-Ferret/issues/49)) ([ca5b1d1](https://github.com/Ferdinand99/Faithful-Ferret/commit/ca5b1d1868da4490aaa577bacf284d2da3376348))
* **server:** serve the web vault and guard origins and cookies ([#51](https://github.com/Ferdinand99/Faithful-Ferret/issues/51)) ([3b81150](https://github.com/Ferdinand99/Faithful-Ferret/commit/3b81150f82fc7abf5f58c6ef3555586c368783c3))
* **wasm:** export verify_tombstone and accept_rows ([#42](https://github.com/Ferdinand99/Faithful-Ferret/issues/42)) ([765d96d](https://github.com/Ferdinand99/Faithful-Ferret/commit/765d96d93d55d57bfd94ee8aa01964f45a71ce46))
* **web:** add the account flows of the web vault (setup, sign-in, unlock, sign-out) ([#63](https://github.com/Ferdinand99/Faithful-Ferret/issues/63)) ([36b32e0](https://github.com/Ferdinand99/Faithful-Ferret/commit/36b32e005388d1ddf7e4af9a090ac4f525296021))
* **web:** add the API client, the strict wire codec and the local stores ([#58](https://github.com/Ferdinand99/Faithful-Ferret/issues/58)) ([c2be456](https://github.com/Ferdinand99/Faithful-Ferret/commit/c2be4567e6082aa1f69430193d4e867807de2241))
* **web:** add the sync engine, the outbox sender and the sync service ([#59](https://github.com/Ferdinand99/Faithful-Ferret/issues/59)) ([a06b9d4](https://github.com/Ferdinand99/Faithful-Ferret/commit/a06b9d468591d37bbc14331b77746d64d05cea20))
* **web:** add the vault screens, the idle lock and the unlock screen ([#64](https://github.com/Ferdinand99/Faithful-Ferret/issues/64)) ([25fe39a](https://github.com/Ferdinand99/Faithful-Ferret/commit/25fe39abbad1b9a6d0d8dfe34f4770e936bcc0d0))
* **web:** add the web vault scaffold ([#41](https://github.com/Ferdinand99/Faithful-Ferret/issues/41)) ([ff5ab63](https://github.com/Ferdinand99/Faithful-Ferret/commit/ff5ab63a4177e879836c2c3f123c99ff8b0c4a8c))
* **web:** give the web vault the Hedgerow look ([c900771](https://github.com/Ferdinand99/Faithful-Ferret/commit/c9007710b8cc703ab45598bb46d5e3813b96ee4f))


### Bug Fixes

* **auth:** choose the account without a branch, and test the timing of the server library ([baf8aee](https://github.com/Ferdinand99/Faithful-Ferret/commit/baf8aee0876bd0eccabcef3a6caee6f35f224a22))
* **release:** make the version bump pass the vector and server checks, and prepare the server library for 0.2.0 ([cbc3185](https://github.com/Ferdinand99/Faithful-Ferret/commit/cbc318566e996c984780786ce01e55784da33f20))
* **server:** equal work for every kind of account at sign-in, and register follow-ups ([#66](https://github.com/Ferdinand99/Faithful-Ferret/issues/66)) ([b787078](https://github.com/Ferdinand99/Faithful-Ferret/commit/b7870787c3534803cef518e496cb1e84485637a8))

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
