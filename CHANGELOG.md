# Changelog

## [0.12.1](https://github.com/Ferdinand99/Faithful-Ferret/compare/v0.12.0...v0.12.1) (2026-11-27)


### Bug Fixes

* **ext:** answer passkey registrations that carry appidExclude ([#338](https://github.com/Ferdinand99/Faithful-Ferret/issues/338)) ([c158588](https://github.com/Ferdinand99/Faithful-Ferret/commit/c158588b75e87d623b702dcf7a81bf43d972bc62))

## [0.12.0](https://github.com/Ferdinand99/Faithful-Ferret/compare/v0.11.0...v0.12.0) (2026-11-26)


### Features

* **admin:** side-menu shell from vole-kit 0.10 ([#310](https://github.com/Ferdinand99/Faithful-Ferret/issues/310)) ([2753ef5](https://github.com/Ferdinand99/Faithful-Ferret/commit/2753ef52404a820c5f740b15acb5100e0bb9619a))
* **core:** import a passkey from another password manager ([#319](https://github.com/Ferdinand99/Faithful-Ferret/issues/319)) ([dc35a53](https://github.com/Ferdinand99/Faithful-Ferret/commit/dc35a533ff629a5ffc68d5295d226c5aa813f44e))
* **core:** passkey candidates, site check, response fields and optional site names ([#309](https://github.com/Ferdinand99/Faithful-Ferret/issues/309)) ([baad603](https://github.com/Ferdinand99/Faithful-Ferret/commit/baad603447e48f0f5b1e71df6cf1008bd8f37b37))
* **ext:** answer objects and static methods of the passkey page script ([#320](https://github.com/Ferdinand99/Faithful-Ferret/issues/320)) ([e607fc6](https://github.com/Ferdinand99/Faithful-Ferret/commit/e607fc688dfcc1910b9fb59dbf790452fef8a58b))
* **ext:** chooser window for passkey requests ([#322](https://github.com/Ferdinand99/Faithful-Ferret/issues/322)) ([7049d9f](https://github.com/Ferdinand99/Faithful-Ferret/commit/7049d9f37bb04c307c21ad45f39074c6d9044922))
* **ext:** conditional passkey requests in the popup, and a card for a request without activation ([#328](https://github.com/Ferdinand99/Faithful-Ferret/issues/328)) ([8973e72](https://github.com/Ferdinand99/Faithful-Ferret/commit/8973e7211e48c7f8c2bcccfe55c59aa01026a474))
* **ext:** create a passkey in Ferret's chooser window ([#326](https://github.com/Ferdinand99/Faithful-Ferret/issues/326)) ([5292f57](https://github.com/Ferdinand99/Faithful-Ferret/commit/5292f57d0a9edaa6a3a81164b0801da308b6f021))
* **ext:** grouped settings with clear switches ([#311](https://github.com/Ferdinand99/Faithful-Ferret/issues/311)) ([1186ae5](https://github.com/Ferdinand99/Faithful-Ferret/commit/1186ae54327a887052f057edebd7bb2ee7927a8a))
* **ext:** hand passkey requests over to the browser, never-list settings and a shared https permission ([#325](https://github.com/Ferdinand99/Faithful-Ferret/issues/325)) ([384bdc2](https://github.com/Ferdinand99/Faithful-Ferret/commit/384bdc21bdb4864aaef54abddb1d81cd416bdc2e))
* **ext:** page script, bridge and registration for the passkey provider ([#316](https://github.com/Ferdinand99/Faithful-Ferret/issues/316)) ([05425a4](https://github.com/Ferdinand99/Faithful-Ferret/commit/05425a44ab8a4d593a0ffb7cf47884d0a4a102eb))
* **ext:** request broker for passkey requests ([#321](https://github.com/Ferdinand99/Faithful-Ferret/issues/321)) ([a0f7353](https://github.com/Ferdinand99/Faithful-Ferret/commit/a0f7353321f338a8469ec8cfecc6c71d6e8f34cf))
* **ext:** sign in with a passkey of Ferret and verify the person ([#327](https://github.com/Ferdinand99/Faithful-Ferret/issues/327)) ([5fb686c](https://github.com/Ferdinand99/Faithful-Ferret/commit/5fb686c77805ba23ff0c848cae0bbc482dc05731))
* spec and dark build flags for the passkey provider ([#313](https://github.com/Ferdinand99/Faithful-Ferret/issues/313)) ([c1ddb9a](https://github.com/Ferdinand99/Faithful-Ferret/commit/c1ddb9aea77014906bd28e53965970a103e39d09))
* turn on the passkey provider in release builds ([#335](https://github.com/Ferdinand99/Faithful-Ferret/issues/335)) ([943196b](https://github.com/Ferdinand99/Faithful-Ferret/commit/943196b535de1df446d086dba3a58e4604fef37d))
* **wasm:** passkey candidates, site check and the new response fields ([#314](https://github.com/Ferdinand99/Faithful-Ferret/issues/314)) ([a825b9d](https://github.com/Ferdinand99/Faithful-Ferret/commit/a825b9dce2d0be75c24908a438b2cabc0f0e706c))
* **web:** import passkeys from Bitwarden and AliasVault ([#324](https://github.com/Ferdinand99/Faithful-Ferret/issues/324)) ([393ce2e](https://github.com/Ferdinand99/Faithful-Ferret/commit/393ce2e8d1df5f48b6445d3ecd4b4bd6aed265ec))
* **web:** show passkeys in the item page, the list and the trash ([#318](https://github.com/Ferdinand99/Faithful-Ferret/issues/318)) ([971b35b](https://github.com/Ferdinand99/Faithful-Ferret/commit/971b35be2c27ceb10e87d639e33a91e4a057f6f3))


### Bug Fixes

* **ext:** end waiting passkey requests when the setting goes off, and the passkey architecture test ([#334](https://github.com/Ferdinand99/Faithful-Ferret/issues/334)) ([a600664](https://github.com/Ferdinand99/Faithful-Ferret/commit/a60066478ba8f7e1287da61d28ba28338d894073))
* **ext:** offer the one-time code in a row's copy menu ([#306](https://github.com/Ferdinand99/Faithful-Ferret/issues/306)) ([7de1971](https://github.com/Ferdinand99/Faithful-Ferret/commit/7de19718c6f263adf9d0d7836375feaf03c57383))
* **ext:** refuse passkey requests as Firefox does before any window ([#333](https://github.com/Ferdinand99/Faithful-Ferret/issues/333)) ([d1fcf06](https://github.com/Ferdinand99/Faithful-Ferret/commit/d1fcf0633faa60f0e87db6f18e190cfb82a84b9b))
* **release:** give the extension the server's version number ([#315](https://github.com/Ferdinand99/Faithful-Ferret/issues/315)) ([8847bff](https://github.com/Ferdinand99/Faithful-Ferret/commit/8847bffd1a60dbcdc88ee0d016ec43124f29ea38))

## [0.11.0](https://github.com/Ferdinand99/Faithful-Ferret/compare/v0.10.0...v0.11.0) (2026-11-25)


### Features

* **build:** test builds can compile the WASM from the commit's tree ([#283](https://github.com/Ferdinand99/Faithful-Ferret/issues/283)) ([fb9879e](https://github.com/Ferdinand99/Faithful-Ferret/commit/fb9879e15f45bb500cb7da0f34a2b00c5572e3e0))
* **core:** passkey method name, synced flag and AAGUID in the add request ([#289](https://github.com/Ferdinand99/Faithful-Ferret/issues/289)) ([8a9ec1f](https://github.com/Ferdinand99/Faithful-Ferret/commit/8a9ec1fde480d63c6ef3ed1aa4c0ea1a5b6f0631))
* **core:** text PINs, a strong PIN profile and the kdf in the PIN wrap AAD ([#281](https://github.com/Ferdinand99/Faithful-Ferret/issues/281)) ([804d16d](https://github.com/Ferdinand99/Faithful-Ferret/commit/804d16d42504fbc91f1b52001079f46775948a24))
* dark build flags and design text for PIN and passkey unlock ([#285](https://github.com/Ferdinand99/Faithful-Ferret/issues/285)) ([92fdcaf](https://github.com/Ferdinand99/Faithful-Ferret/commit/92fdcafc7f46986bd40fd845ae4f189252cb161c))
* **ext:** local PIN store with attempt counter and offline window ([#282](https://github.com/Ferdinand99/Faithful-Ferret/issues/282)) ([fe8a442](https://github.com/Ferdinand99/Faithful-Ferret/commit/fe8a442c8176ea38395671e704f3d2202b44fce4))
* **ext:** one-time codes in the popup ([#296](https://github.com/Ferdinand99/Faithful-Ferret/issues/296)) ([ae7a122](https://github.com/Ferdinand99/Faithful-Ferret/commit/ae7a122125b581891b3fb3fb5a0b71e07d6bdc53))
* **ext:** PIN field on the locked popup with the refusal texts ([#291](https://github.com/Ferdinand99/Faithful-Ferret/issues/291)) ([d9264c3](https://github.com/Ferdinand99/Faithful-Ferret/commit/d9264c37dad858e3fb12b3e9a30a491961a355ab))
* **ext:** PIN set, used and wiped in the background ([#290](https://github.com/Ferdinand99/Faithful-Ferret/issues/290)) ([f68a767](https://github.com/Ferdinand99/Faithful-Ferret/commit/f68a767eecb7065509acb6b09149099bf61aaca2))
* **ext:** settings view inside the popup ([#278](https://github.com/Ferdinand99/Faithful-Ferret/issues/278)) ([6805e82](https://github.com/Ferdinand99/Faithful-Ferret/commit/6805e821202004ce078334f06a392899ba373f43))
* **ext:** Unlock section in the settings view with the PIN dialog and warning ([#288](https://github.com/Ferdinand99/Faithful-Ferret/issues/288)) ([5abc479](https://github.com/Ferdinand99/Faithful-Ferret/commit/5abc479ec8354fac22829e323bcdd6609bdd4528))
* **ext:** unlock the vault with a passkey in the extension ([#298](https://github.com/Ferdinand99/Faithful-Ferret/issues/298)) ([7a993dc](https://github.com/Ferdinand99/Faithful-Ferret/commit/7a993dc1e19fa31830d841005ccaf176a4a3b920))
* **server:** add and remove passkey unlock methods ([#292](https://github.com/Ferdinand99/Faithful-Ferret/issues/292)) ([4ee6d27](https://github.com/Ferdinand99/Faithful-Ferret/commit/4ee6d276585b59d54a0e515c9c84f72e2b155924))
* **server:** PIN rule, Unlock admin tab and GET /api/vault/policy ([#284](https://github.com/Ferdinand99/Faithful-Ferret/issues/284)) ([223349e](https://github.com/Ferdinand99/Faithful-Ferret/commit/223349ee7490e20315d87c6ab281eaf5282f0874))
* turn on quick unlock in release builds ([#302](https://github.com/Ferdinand99/Faithful-Ferret/issues/302)) ([374cae3](https://github.com/Ferdinand99/Faithful-Ferret/commit/374cae305dcba851776df9675cab51895ca12b0d))
* **wasm:** PIN functions with the rule, timing and a pinned record ([#287](https://github.com/Ferdinand99/Faithful-Ferret/issues/287)) ([ef8d0fe](https://github.com/Ferdinand99/Faithful-Ferret/commit/ef8d0fe5b65f8ce3051e5ae3db7cc73329845372))
* **web:** list, add and remove passkey unlock methods ([#294](https://github.com/Ferdinand99/Faithful-Ferret/issues/294)) ([d71e861](https://github.com/Ferdinand99/Faithful-Ferret/commit/d71e861c4c627e7e658580fecc8cadd7d0207350))
* **web:** one-time passwords for websites in the web vault ([#297](https://github.com/Ferdinand99/Faithful-Ferret/issues/297)) ([14773a2](https://github.com/Ferdinand99/Faithful-Ferret/commit/14773a22d73191f9c39f31e0f6156139acf9169b))
* **web:** password generator page ([#279](https://github.com/Ferdinand99/Faithful-Ferret/issues/279)) ([e8dcc41](https://github.com/Ferdinand99/Faithful-Ferret/commit/e8dcc41b6f5355b728fb0a93a07f0783c9067cbb))
* **web:** unlock the vault with a passkey while the session lives ([#295](https://github.com/Ferdinand99/Faithful-Ferret/issues/295)) ([496c612](https://github.com/Ferdinand99/Faithful-Ferret/commit/496c612d76a8ed77057f52245a68114878fbc65a))


### Bug Fixes

* **core:** refuse a higher vault key epoch at a recovery with the recovery key ([#299](https://github.com/Ferdinand99/Faithful-Ferret/issues/299)) ([9e657ea](https://github.com/Ferdinand99/Faithful-Ferret/commit/9e657ea2ae9063b0ddc816430e4c4250ff54f656))
* **core:** refuse a vault key epoch ahead of the pinned one ([#293](https://github.com/Ferdinand99/Faithful-Ferret/issues/293)) ([8dfda6a](https://github.com/Ferdinand99/Faithful-Ferret/commit/8dfda6a5fe02b05d3b20df25d96b6eaca503216f))
* **ext:** count a PIN as the core does and keep pin out of the unlock_policy reply ([#303](https://github.com/Ferdinand99/Faithful-Ferret/issues/303)) ([c38ba2a](https://github.com/Ferdinand99/Faithful-Ferret/commit/c38ba2ac26d3ed0e2e7510fcacca6746ccb3a6f3))
* **ext:** keep opening the popup for offers after one refused attempt ([#286](https://github.com/Ferdinand99/Faithful-Ferret/issues/286)) ([b830d7d](https://github.com/Ferdinand99/Faithful-Ferret/commit/b830d7d3200d45adb37103aae1324b4dc04e8280))
* **web,ext:** one name for the show-password toggle, popup bar texts and Health focus ([#277](https://github.com/Ferdinand99/Faithful-Ferret/issues/277)) ([cab2020](https://github.com/Ferdinand99/Faithful-Ferret/commit/cab202094167f20e3fa56fd244772658bea13492))

## [0.10.0](https://github.com/Ferdinand99/Faithful-Ferret/compare/v0.9.0...v0.10.0) (2026-11-24)


### Features

* **ext:** capture script for submitted sign-in, sign-up and change forms ([#262](https://github.com/Ferdinand99/Faithful-Ferret/issues/262)) ([fbae345](https://github.com/Ferdinand99/Faithful-Ferret/commit/fbae345d0b2127024d5fce3d3fd5376590813abc))
* **ext:** generator tab in the popup and fill of a generated password ([#260](https://github.com/Ferdinand99/Faithful-Ferret/issues/260)) ([be01baf](https://github.com/Ferdinand99/Faithful-Ferret/commit/be01baf9668bfa361afe146e3068707263a2938c))
* **ext:** hold submitted forms as offers and register the capture script ([#261](https://github.com/Ferdinand99/Faithful-Ferret/issues/261)) ([7955fc3](https://github.com/Ferdinand99/Faithful-Ferret/commit/7955fc394f7aef3a4116258c029ee9fa608d1856))
* **ext:** refuse a fill under a cover that hit testing cannot see ([#270](https://github.com/Ferdinand99/Faithful-Ferret/issues/270)) ([93ab37d](https://github.com/Ferdinand99/Faithful-Ferret/commit/93ab37d4aadfc31fb98c9da3d396ac3273c44bf2))
* **ext:** the offer to save or update a password in the popup ([#269](https://github.com/Ferdinand99/Faithful-Ferret/issues/269)) ([6fe6279](https://github.com/Ferdinand99/Faithful-Ferret/commit/6fe627927b35c534503be5c11f76bcc04a76ca07))
* **ext:** turn on saving and the generator in release builds ([#272](https://github.com/Ferdinand99/Faithful-Ferret/issues/272)) ([54ee3cd](https://github.com/Ferdinand99/Faithful-Ferret/commit/54ee3cdf2a572396093386f656437eb792463a01))
* **web:** show or hide the password while editing an item ([#266](https://github.com/Ferdinand99/Faithful-Ferret/issues/266)) ([dd17ed0](https://github.com/Ferdinand99/Faithful-Ferret/commit/dd17ed0f6ef33911f2a12f08d812819fe83084be))


### Bug Fixes

* **deps:** update cookie to 0.18.3 for RUSTSEC-2026-0594 ([#265](https://github.com/Ferdinand99/Faithful-Ferret/issues/265)) ([85ce191](https://github.com/Ferdinand99/Faithful-Ferret/commit/85ce191f2452364281c08a7ce04b967be0176f35))
* **ext:** autofill-parity fixes and the parity set in the gate ([#274](https://github.com/Ferdinand99/Faithful-Ferret/issues/274)) ([af865f3](https://github.com/Ferdinand99/Faithful-Ferret/commit/af865f334ff3f39df789b2db0005f4e86aa563ea))
* **ext:** capture forms the page hides or replaces in its own submit or click handler ([#267](https://github.com/Ferdinand99/Faithful-Ferret/issues/267)) ([37649ba](https://github.com/Ferdinand99/Faithful-Ferret/commit/37649ba822791b460d969c74a0beafb210a29928))
* **ext:** credit the EFF word list on the settings page ([#263](https://github.com/Ferdinand99/Faithful-Ferret/issues/263)) ([2953c58](https://github.com/Ferdinand99/Faithful-Ferret/commit/2953c58b3088fc43fd86cc0f1ee50d7e8f354dac))

## [0.9.0](https://github.com/Ferdinand99/Faithful-Ferret/compare/v0.8.0...v0.9.0) (2026-11-23)


### Features

* **ext:** accept an older server state, resolve conflicts and name unsent writes in the popup ([#250](https://github.com/Ferdinand99/Faithful-Ferret/issues/250)) ([ba804eb](https://github.com/Ferdinand99/Faithful-Ferret/commit/ba804eb39999eabfb559fc1089c2af85287f4fb3))
* **ext:** classify, save and update a captured password through the sync engine ([#256](https://github.com/Ferdinand99/Faithful-Ferret/issues/256)) ([55a6a65](https://github.com/Ferdinand99/Faithful-Ferret/commit/55a6a655a54b343be881dac4bfc9f8081fa59a4c))
* **ext:** detect form purpose before filling ([#257](https://github.com/Ferdinand99/Faithful-Ferret/issues/257)) ([823cbbd](https://github.com/Ferdinand99/Faithful-Ferret/commit/823cbbd3e84f0b9ca543aab2f48643be72a2b999))
* **web:** show previous passwords and keep them on password edits ([#254](https://github.com/Ferdinand99/Faithful-Ferret/issues/254)) ([f3cd688](https://github.com/Ferdinand99/Faithful-Ferret/commit/f3cd688972a316d3faec46dd89dee4a1823ce6e6))


### Bug Fixes

* **web:** reach both import and export from the side menu, style the file picker ([#253](https://github.com/Ferdinand99/Faithful-Ferret/issues/253)) ([693aac2](https://github.com/Ferdinand99/Faithful-Ferret/commit/693aac2a11bca0657c02e5f2e6f1ca5c9999f420))

## [0.8.0](https://github.com/Ferdinand99/Faithful-Ferret/compare/v0.7.0...v0.8.0) (2026-11-22)


### Features

* **core:** password generator, field comparison and password history ([#249](https://github.com/Ferdinand99/Faithful-Ferret/issues/249)) ([3c511e7](https://github.com/Ferdinand99/Faithful-Ferret/commit/3c511e77ca92c8ca568bd6f34638ac3bf413205b))
* **ext:** automatic updates for the signed release build ([#244](https://github.com/Ferdinand99/Faithful-Ferret/issues/244)) ([926dd01](https://github.com/Ferdinand99/Faithful-Ferret/commit/926dd01609c35a98b4afde9e5dccbbbc3ec2d912))
* **ext:** save build flag, capture rules in the design, and copy and sign-out follow-ups ([#247](https://github.com/Ferdinand99/Faithful-Ferret/issues/247)) ([52ec8a4](https://github.com/Ferdinand99/Faithful-Ferret/commit/52ec8a45c6aea816304bdbd959c4b01601c6fd85))

## [0.7.0](https://github.com/Ferdinand99/Faithful-Ferret/compare/v0.6.1...v0.7.0) (2026-11-22)


### Features

* Firefox extension and new web vault layout ([1afe199](https://github.com/Ferdinand99/Faithful-Ferret/commit/1afe199d63880e38aee077ab34a1563801ac06d4))
* **web:** folders as encrypted labels inside each item ([#219](https://github.com/Ferdinand99/Faithful-Ferret/issues/219)) ([a215f5c](https://github.com/Ferdinand99/Faithful-Ferret/commit/a215f5c08744f9c8cbc3fef51c61c3f16b78fd82))
* **web:** unlock with the master password after the session has ended ([#225](https://github.com/Ferdinand99/Faithful-Ferret/issues/225)) ([6f23b90](https://github.com/Ferdinand99/Faithful-Ferret/commit/6f23b901dbacd2479105b6a1ddb9ea17d04722bd))


### Bug Fixes

* **extension:** keep the popup's foot visible and add a copy menu to its rows ([#235](https://github.com/Ferdinand99/Faithful-Ferret/issues/235)) ([552484c](https://github.com/Ferdinand99/Faithful-Ferret/commit/552484c75a073845cd5dae5fe3256d02eeec5e91))
* **ext:** final review fixes before the extension hand test ([#232](https://github.com/Ferdinand99/Faithful-Ferret/issues/232)) ([ff3c514](https://github.com/Ferdinand99/Faithful-Ferret/commit/ff3c51405410653f7619e0404392a61d2d15c9a4))
* **ext:** refuse a fill into a frame that its page hides or covers ([#226](https://github.com/Ferdinand99/Faithful-Ferret/issues/226)) ([8ad33c6](https://github.com/Ferdinand99/Faithful-Ferret/commit/8ad33c6cc612f8c9ef80f115e6cce3a44a3906d1))

## [0.6.1](https://github.com/Ferdinand99/Faithful-Ferret/compare/v0.6.0...v0.6.1) (2026-11-22)


### Bug Fixes

* **deps:** update url to 2.5.9 (RUSTSEC-2026-0592) ([#221](https://github.com/Ferdinand99/Faithful-Ferret/issues/221)) ([03532ab](https://github.com/Ferdinand99/Faithful-Ferret/commit/03532ab72497be2ac5d1c12273845f6f11cc948b))
* **web:** ignore white space in the pasted setup text ([#217](https://github.com/Ferdinand99/Faithful-Ferret/issues/217)) ([3e3a079](https://github.com/Ferdinand99/Faithful-Ferret/commit/3e3a0795f7d55d3718ee8373753fb5d71d9a69b9))

## [0.6.0](https://github.com/Ferdinand99/Faithful-Ferret/compare/v0.5.0...v0.6.0) (2026-11-22)


### Features

* **core:** folder labels inside the item body, through the WASM binding ([#213](https://github.com/Ferdinand99/Faithful-Ferret/issues/213)) ([d62bbf5](https://github.com/Ferdinand99/Faithful-Ferret/commit/d62bbf5ab70190eae638e9e4b0c5ca304799bf33))
* devices and DPoP-bound tokens ([c6daf9a](https://github.com/Ferdinand99/Faithful-Ferret/commit/c6daf9a2698d88d4b8d05dea3d421fe36e27d045))


### Bug Fixes

* **server:** close the findings of the final review of device tokens ([#200](https://github.com/Ferdinand99/Faithful-Ferret/issues/200)) ([027db45](https://github.com/Ferdinand99/Faithful-Ferret/commit/027db45838fca19f45a63a35755f393eb249bcf2))

## [0.5.0](https://github.com/Ferdinand99/Faithful-Ferret/compare/v0.4.0...v0.5.0) (2026-11-21)


### Features

* **deploy:** stack for real data, encrypted off-machine copy and drill stack ([#187](https://github.com/Ferdinand99/Faithful-Ferret/issues/187)) ([400c9c9](https://github.com/Ferdinand99/Faithful-Ferret/commit/400c9c9e3418388b8c87299e5917b99a976c3338))
* milestone M3 — recovery, export, import and backup ([1797311](https://github.com/Ferdinand99/Faithful-Ferret/commit/179731143b3ebb3cbf4af85f0048de3dd3f43e22))
* **server:** backup page and "Take a backup now" on the admin pages ([#184](https://github.com/Ferdinand99/Faithful-Ferret/issues/184)) ([84a42b8](https://github.com/Ferdinand99/Faithful-Ferret/commit/84a42b8be161604ab13cb17f9213781b554e515e))
* **server:** restore a backup set safely, and raise the restore epoch above the time ([#186](https://github.com/Ferdinand99/Faithful-Ferret/issues/186)) ([b734bec](https://github.com/Ferdinand99/Faithful-Ferret/commit/b734bec7f5f403ecc609cdfd5f3805091f499a38))
* **web:** keep unsaved edits and hand the vault over between tabs ([#185](https://github.com/Ferdinand99/Faithful-Ferret/issues/185)) ([f7c7101](https://github.com/Ferdinand99/Faithful-Ferret/commit/f7c71015e7269cf278ef2b394cfcc4e7b4e90d24))


### Bug Fixes

* end sessions and codes on restore-epoch bump, isolate the copy container ([#195](https://github.com/Ferdinand99/Faithful-Ferret/issues/195)) ([2bce2d0](https://github.com/Ferdinand99/Faithful-Ferret/commit/2bce2d0a83eb5a20d3a8ba714bf538252f983c15))
* take the bare admin address to the admin pages ([#198](https://github.com/Ferdinand99/Faithful-Ferret/issues/198)) ([43f6b35](https://github.com/Ferdinand99/Faithful-Ferret/commit/43f6b35d7b76035fc19cf72c8b6a33571e07b6e1))

## [0.4.0](https://github.com/Ferdinand99/Faithful-Ferret/compare/v0.3.0...v0.4.0) (2026-11-20)


### ⚠ BREAKING CHANGES

* **wasm:** require the re-authentication grant to start an encrypted export ([#177](https://github.com/Ferdinand99/Faithful-Ferret/issues/177))

### Features

* **core:** renew the recovery key and add an import port to the vault worker ([#138](https://github.com/Ferdinand99/Faithful-Ferret/issues/138)) ([ef28d36](https://github.com/Ferdinand99/Faithful-Ferret/commit/ef28d36bdbfdb275168bb29d4fb65be4f9a197c0))


### Bug Fixes

* **core:** keep the stored recovery method id when recovering ([#163](https://github.com/Ferdinand99/Faithful-Ferret/issues/163)) ([4341ce7](https://github.com/Ferdinand99/Faithful-Ferret/commit/4341ce7c91a27c0d999b1c9d9cbe4ba1e6716bec))
* **wasm:** require the re-authentication grant to start an encrypted export ([#177](https://github.com/Ferdinand99/Faithful-Ferret/issues/177)) ([7f82c05](https://github.com/Ferdinand99/Faithful-Ferret/commit/7f82c05cb2cf8de625cae16cef5bfa515c0c8a47))

## [0.3.0](https://github.com/Ferdinand99/Faithful-Ferret/compare/v0.2.0...v0.3.0) (2026-11-19)


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
* **wasm:** match open items against a page, and read a page's origin, site and host ([#125](https://github.com/Ferdinand99/Faithful-Ferret/issues/125)) ([a163b23](https://github.com/Ferdinand99/Faithful-Ferret/commit/a163b2359052d50f8abdd6e5cd91df4e2d79bd21))
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
* **server:** move to vole-kit 0.8.2 for the SQLite fix and lettre 0.11.24 ([#132](https://github.com/Ferdinand99/Faithful-Ferret/issues/132)) ([969d0cf](https://github.com/Ferdinand99/Faithful-Ferret/commit/969d0cfaf815b0b9123778a9f5d0154b0e416fb2))
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
* **server:** add the Docker image, compose file and build host test deploy ([#57](https://github.com/Ferdinand99/Faithful-Ferret/issues/57)) ([7aa567f](https://github.com/Ferdinand99/Faithful-Ferret/commit/7aa567fc356231299173d2779217d6fe8504a812))
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
