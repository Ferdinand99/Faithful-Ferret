# Firefox extension: what was measured and what follows from it

This page records what the Firefox extension relies on, measured in real Firefox, and the decisions that follow. It is the reference for the manifest, for the minimum Firefox version and for the places where an API is missing and the code has to do without it.

## How it was measured

- Firefox builds: the unbranded Release build 159.0.1 and Firefox ESR 153.6.0, the builds of the runner image (`docker/ext-runner.Dockerfile`), pinned by version and SHA-256. The current versions were checked in Mozilla's `product-details` on 2026-11-08: ESR 153.6.0esr, Release 159.0.1.
- Both manifest versions of the test build, MV3 and MV2, with the default preferences of Firefox plus the test profile (`extension/test/firefox/profile.mjs`): unsigned add-ons allowed, a fixed extension UUID, no prompt for optional permissions.
- Headless, in a container on the build host, with the content sandboxes of Firefox switched off (the container's seccomp profile blocks the user namespaces they need). The numbers are headless numbers; the same measurement is done by hand in an ordinary Firefox (see the end of this page).
- Real keyboard shortcuts, real context menu clicks and the browser's own "Terminate" for the background are made from the chrome context (`-remote-allow-system-access`), so Firefox grants `activeTab` as it does for a person.
- The probes are `extension/test/firefox/03-api-probe.spec.mjs` (one row per API, in every Firefox run) and `02-lifetime.measure.spec.mjs` (the lifetime matrix, `scripts/lanbox-ext.sh measure`).

## The lifetime of the background page

### The decision: MV2 with a persistent background page is the default for Firefox

The question is whether the background page of an MV3 build, which holds the vault worker and so the keys, survives until the auto-lock (15 minutes) while the vault is open. It does not. In every scenario, in both Firefox builds, the browser ends the MV3 background page 30 seconds after the last event, and the keys go with it (the next page starts locked). The MV2 page with `persistent: true` lived the whole window in every scenario. The rule was that MV2 becomes the default if an MV3 page is ended before the auto-lock in a normal scenario (no page of the extension open, `about:debugging` closed, the event stream open); that is the case, so **the Firefox build uses the MV2 manifest with `persistent: true`**. The MV3 build stays buildable (the manifest overlay and the tests keep both), so a later Firefox that keeps an MV3 page alive can be measured again. No keep-alive trick was used or is allowed: no port held open, no timer or alarm that is there to keep the page alive. (The heartbeat alarm belongs to the measurement and exists in the test build only; in MV3 it does wake a page that has been ended, which is why the log shows new starts.)

### How it was measured

The background page of the test build writes three kinds of entry to `storage.local` (`background/test-only/measureLog.mjs`): `startup` when it is loaded, `suspend` when the browser says it is about to end it (`runtime.onSuspend`; the listener first leaves a marker in `localStorage` and the next start turns it into the entry, because the page can be gone before a storage write finishes), and `heartbeat` from an alarm every minute. A scenario is started from the measure page with a click, and then **the page is closed**; nothing touches the extension for the length of the window (17 minutes, two more than the auto-lock). Afterwards the measure page is opened again and reads the log straight from `storage.local` (reading does not wake the background). The second witness is the browser's own `backgroundState`, read every 5 seconds from the chrome context, which does not wake or touch the page.

Scenarios, all with the vault open (the vault worker holds a WASM instance and the lock's deadline is set):

- `idle`: nothing else; no page of the extension open, no network.
- `sse`: and an open `fetch` stream of server-sent events (an event every 10 seconds) read by the background page.
- `popup`: and the popup page open as a tab.
- `argon`: and an Argon2id job (256 MiB, 8 passes, about 2 seconds) that runs again and again in the job worker.
- `terminate`: the browser's Terminate for the background, then the next message.

### The lifetime matrix

Window 17 minutes for each cell; the numbers are the same in Release 159.0.1 and ESR 153.6.0 to within a second or two.

| Scenario | MV3 | MV2 (`persistent: true`) |
|---|---|---|
| `idle` | The browser ended the page 30.0 s after the start (`onSuspend` at 30.0 s, state `stopped` at 30.1 to 30.3 s). The next page started at 54 to 61 s (the heartbeat). 18 starts of the page in the 17 minutes. | Lived the whole 17 minutes: one start, no `suspend`, 16 to 17 heartbeats. |
| `sse` | Ended at 30.0 s with the stream open. | Lived the whole window. |
| `popup` | Ended at 30.0 s with the popup page open as a tab. | Lived the whole window. |
| `argon` | Ended at 30.0 s while the job loop ran (14 jobs of about 2.1 s were done by then); the loop and the vault worker are gone in the next page. | Lived the whole window; 435 (Release) and 437 (ESR) jobs of 2.0 to 2.2 s. |
| `terminate` | After Terminate the page is `stopped`; the next message starts a new page that is **locked** and has **no `lockAt`**. | Same: Terminate works on the persistent page, and the next message starts a locked page with no `lockAt`. |

The MV2 deadline also fired on time in every MV2 cell: the first log entry that says "locked" is at 900 to 967 seconds (the first heartbeat after the 15-minute deadline), and in the `argon` cell the running job loop failed with `vault_locked` at 900.0 seconds, which is why it stopped at 435 and 437 jobs.

The rest of the MV3 log: after the first 30 seconds a page lives about 60 seconds. The browser ends every page 30 seconds after the last event (the heartbeat, which comes each minute). After every page that the heartbeat had woken (not after the first page, which waits for the next heartbeat) a new page started 23 to 115 milliseconds later, with no event of ours in between, also with an `onSuspend` listener that writes nothing. That points at Firefox starting the page again for the alarm it holds for the extension; the cause was not found. It does not matter for the vault, because every new page is locked. The heartbeat reached the page 16 or 17 times in 17 minutes in every cell.

The reports of the run (every entry of every cell, the browser's state timeline, the Argon2id times) are `lifetime-release.json` and `lifetime-esr.json` in `test-results/out/ext-measure/`; they are not committed.

## The Firefox APIs the extension relies on

Result in Firefox Release 159.0.1 and ESR 153.6.0. Where the two builds or the two manifest versions differ, the row says so; otherwise the result is the same in all four. The probes ran only in these two versions, so no row says in which earlier version an API appeared; the oldest version that every row holds in is ESR 153.6.0. The API probe fails when a row has another status than this table gives it (`documentedStatus` in `03-api-probe.spec.mjs`), so a change in Firefox has to change this table.

| API | Result | What the code does |
|---|---|---|
| `storage.session` | Works in both. Content scripts do not see it (`browser.storage.session` is undefined there). | Holds the non-secret state (`lockAt`, the clipboard mark, UI marks). |
| `storage.session.setAccessLevel` | Absent in both. | Nothing to set: the area is for the extension's own pages only. |
| `sender.origin` | Present. An extension page gets `moz-extension://<uuid>`; a content script gets the page's origin (`https://host:port`). `frameId`, `url`, `tab` and `documentId` come with it. | The origin is taken from `sender`, never from the message. |
| `documentId` in `webNavigation.getAllFrames` | Present and different for every frame. `documentLifecycle` is not given. | A frame is bound by `(tabId, frameId, documentId)`. |
| `documentId` in `webNavigation.getFrame` | Present (the end-to-end menu fill depends on it). | The context menu aims at the clicked field in the document `getFrame` names, and the fill flow fills only that document; a frame without one opens the popup instead. |
| Frame ids | The top frame is 0; the frames below it are numbered from 17179869185 (more than 2^32) up, and `parentFrameId` is the top frame's 0. They are safe integers, not 32-bit ones. | Message schemas accept a `frame_id` up to the largest safe integer (a 32-bit bound would turn real frames away). |
| `runtime.getFrameId(element)` in a content script | Works in Release and ESR, MV2: for an `iframe` it gives the same frame id as `webNavigation` (ids above 2^32); an element that holds no frame throws. The end-to-end frame checks depend on it. | The fill engine finds the element that holds a frame through it, to check that a field of the frame is shown in the page above it. |
| `documentId` in `tabs.sendMessage` | Works: `sendMessage(tabId, message, { documentId })` reaches that document. | A fill message goes to one document, not to whatever the frame has become. |
| `optional_host_permissions` in MV3 | Works. The manifest key is accepted, nothing is granted at install, `permissions.request` grants it. MV2 has the origins in `optional_permissions` (the build folds them). | Server and frame origins are asked for in a tab. |
| `permissions.request` from a tab | Works from a click on a page of the extension. In the test profile no prompt appears. | All requests happen in a tab (the popup closes when the prompt opens). |
| The preference for permissions without a prompt | `extensions.webextOptionalPermissionPrompts` set to `false` makes `permissions.request` answer without a prompt. It is the preference `profile.mjs` already sets. | Test profile only; a person's Firefox shows the prompt. |
| `menus.getTargetElement` | Works in a content script, with the `targetElementId` of `menus.onClicked`. It returns the element that was clicked. | The context menu finds the field through it. |
| `action.openPopup` from `commands.onCommand` | Works (MV3 `action`, MV2 `browserAction`), also from `menus.onClicked`, and also after the handler awaited the page matching (Release and ESR). | A shortcut or menu click with no single match opens the popup. |
| `idle.onStateChanged` with `locked` | The API is there (`queryState` answers `active`), but Firefox has no `locked` state: the source of the API does not mention it. | No lock on screen lock in Firefox. The vault locks on the deadline (15 minutes by default), at lock, at sign-out and when the browser closes. The text of the lock settings must not promise a lock on screen lock. |
| Module workers and `WebAssembly` under the extension CSP | Works in MV3 and MV2 with `'wasm-unsafe-eval'`. The core answers in the vault worker, the Argon2id job runs in the job worker (64 MiB, 3 passes: about 200 ms headless), and `eval` is refused in the same page (the CSP is in force). | `script-src 'self' 'wasm-unsafe-eval'` as it is. |
| Trusted Types | `trustedTypes` exists in the background page and in extension pages, and `createPolicy` works. | The WASM client's policy works. |
| `navigator.locks` | Works in the background page and in extension pages. | `memoryStore` of the sync engine can use it. |
| `navigator.clipboard.writeText` from the background | Works with `clipboardWrite`, and what was written can be read from the system clipboard. | Copy from the popup goes through the background. |
| `scripting.executeScript` in opaque frames | MV3: the frame with a sandbox and no `allow-same-origin` is refused by Firefox ("Missing host permission for the tab or frames"). MV2: it is injected, and `self.origin` is `"null"`. In both, `srcdoc` and `about:blank` frames are injected and report their parent's origin. | The fill engine refuses these frames itself, by the frame's URL (`about:srcdoc`, `about:blank`), by `self.origin` being `"null"` and by the origin from `webNavigation`, in MV3 and in MV2. |
| `options_ui` opened in `about:addons` | The page is a top-level extension page: its port has `frameId` 0 and no tab, and `isUiPort` accepts it. | The settings page may use the UI port in either way of opening. |
| `options_ui` with `open_in_tab: true` | Opens the page in a tab of the browser; `isUiPort` accepts it. | As above. |
| Chrome context | A shortcut and a context menu click give the extension `activeTab` on that tab, and the Terminate of the background works, in MV3 and in MV2 (also with a persistent MV2 page, which starts again on the next message). | The browser tests use all three. |
| Permanent installation | In the unbranded Release and in ESR an unsigned package is installed for good (not temporary) and stays after a restart, with the same UUID. | The browser tests restart the profile. |
| `data_collection_permissions` | Firefox accepts the manifest with `required: ["authenticationInfo"]`, and `permissions.getAll()` has a `data_collection` part. | See below. |
| `import()` of an extension module from an injected content script | Fails in both builds and both manifest versions ("error loading dynamically imported module"), even for a file with no imports, because the extension's files are not web-accessible. | The build joins the content modules into one classic script. See "The content script" below. |
| Passkey provider through a MAIN-world override of `navigator.credentials` | Works in Release 159.0.1 and ESR 153.6.0, MV3 and MV2, with a gap for srcdoc and `blob:` frames. Part of it is only simulated in the measurement. | See "The passkey provider" below. |

### The value of `data_collection_permissions`

`required: ["authenticationInfo"]`. The extension sends sign-in proofs and device credentials to a server outside the browser (the user's own), which Mozilla's definition of data transmission counts, so `none` would be wrong. Nothing goes to the developer or to a third party. Both Firefox builds accept it.

### The minimum Firefox version

`strict_min_version` is `153.0`, the current ESR. Everything the extension needs exists in ESR 153.6.0, apart from the screen-lock state and `storage.session.setAccessLevel`, which neither build has and the extension can do without. No row needed a newer Release.

### The content script

The fill engine runs in the isolated world of a page and is injected with `scripting.executeScript`. An injected file is a classic script, so it cannot use `import`, and `import()` of an extension file does not work either (see the table): Firefox does not let a content script load a module that is not web-accessible. Making the files web-accessible is not an option, because a page must not be able to load extension files, and the build refuses `web_accessible_resources`. So the build joins `content/entry.mjs` and the modules it imports into one file, `content/fill.inject.js` (`extension/scripts/lib/classic.mjs`). The joiner refuses imports outside the content modules and the two shared files they need, cycles, aliases, default and namespace imports, `import()` and duplicate top-level names. The source files keep `import` and `export`; only the packaged file is classic.

The capture script (`content/capture.inject.js`, built from `content/capture.entry.mjs`) is a second classic script made the same way. It belongs to the `save` feature (below) and exists only in a package that has the feature on. It runs in every `https` page and frame once the user has switched on "Offer to save passwords", watches for the submission of a sign-in, sign-up, change or reset form and reports what the person typed. It is held to a stricter footprint than the fill engine: at most 40 KiB, no dependency beyond the detection module (`content/forms.mjs`, shared with the fill engine, so one module decides what a field and a form are), no change to the page (no element, attribute or marker), no request, no `postMessage`, no storage, listeners in the capture phase only, and no message at all until a password field the person can see exists (an identifier step, a page that asks for the user name only, is the one other thing it reports). The build joins it "slim" (comment lines, indentation and blank lines of the sources are left out, nothing else) to keep it inside that budget. A password counts only when its last change was an `input` event the browser made for the person (`isTrusted`), read inside that listener and unchanged when the form is read after the page's own handlers have run; a key press never counts. Which groups and fields the person could see is decided in the trigger itself (a trusted submit, click or Enter, in the window in the capture phase, before the page's own handlers), so a form that the page hides, replaces or covers in its own submit or click handler is still captured; the values are still read after those handlers and must be the person's own. It has no `MutationObserver`: after a submission it looks at the form again at four fixed moments within five seconds, which also bounds its cost on a page that changes all the time. It sends the one message type that carries a secret upward (`form_capture`, with the password and, in a change form, the one in use), limited to 4 KiB, and is sent nothing back. A sign-up, change or reset form whose new password was filled by the extension (so its `input` event is not the person's) is sent with no password at all, as a request to join it to the generated password; and the "gone" check after a submission counts a form as gone only when it is removed, not displayed, not visible or too small at two checks in a row (a cover, an `aria-hidden` page behind an error modal or a dialog backdrop does not), and reports a form that comes back (also inside a shadow root) as `page_ready`.

Stated limits: a page's own listener on the window in the capture phase runs before the script's (it is registered earlier) and can rewrite a value inside the trusted event before it is read, or stop the event; the page can then only influence what is offered for its own origin, which the browser names, and nothing is stored without the user's click. An input inside a closed shadow root is retargeted to its host and is not seen, so a form there gives no capture. At rest only password fields in the page's own tree are looked for.

### The `save` feature

Saving and updating passwords from the extension is a build feature, `save` (`build.mjs --features`, the generated module `shared/features.mjs`). It is off in the release variant and on in the test variant, and the release check refuses a release with it on, until the feature is finished. "Off" means that no path of the feature exists in the package: no capture script (nor its sources), no handler that serves one of its message types, no control of it in a page. The rule for the code of the feature is the one `extension/test/unit/features.test.mjs` holds it to. A handler checks `FEATURES.save` before anything else and, with the feature off, throws an error with the code `not_available` for every message type it serves, so it behaves like a handler that is not there. Every control of the feature carries `data-feature="save"`, and a page module that builds one imports `shared/features.mjs`. Every file, message type and core operation of the feature is added to `SAVE_PATHS` in that test in the change that adds it. A unit test of a module that imports the flag loads it from a built package, because the flag module is generated and does not exist in `src/`.

The hit test of the fill engine has a stated limit. A field counts as "not covered" when `elementsFromPoint` at the centre and four more points returns the field first. That reports what a click would reach. It does not see a cover that a click passes through (`pointer-events: none`) or one that paints outside its own box (a large `box-shadow` spread, an `outline` with an offset, `filter: drop-shadow()`, `border-image-outset`). Such a cover can hide a field without failing the check. The header of `extension/src/content/fill.mjs` and the design document state the same limit, and a unit test pins it, so a change is deliberate. A stricter check that still accepts floating labels is not part of the first version.

#### The offers the background holds

The background holds what a person submitted only in memory (`background/offers.mjs`), for five minutes (fifteen for a password Ferret generated), checks the end on every access, and clears everything at every lock. A login is offered only after it worked: the page must leave the form, finish loading, and show no password form again for three and a half seconds (the capture script looks for one last time three seconds after the page is idle). One capture per frame document in two seconds is taken, not one per frame, so that the password step of a two-page sign-in is not dropped; a step that asks for the user name only has a two-second gap of its own, so that the password step that follows it on the same page is not dropped (it never makes an offer, and the twenty per tab count both); twenty per tab in a minute still bound a frame that reloads itself. The load of the capturing document itself is never an outcome (its document id when the event has one, else its address), and a navigation reported more than half a second before the capture arrived does not count for it. Turning "Offer to save passwords" off removes the access to `https` pages that was asked for with it.

### The passkey provider

Firefox has no extension API for passkey providers (Chrome's `webAuthenticationProxy` does not exist there), so the only route is to replace `navigator.credentials.create` and `get` in the page's own world. A test add-on (`extension/test/spikes/passkey`, probes in `90-passkey-spike.spec.mjs`) did that, and a local relying party verified what it produced.

- **Works** in Release 159.0.1 and ESR 153.6.0, in MV3 and MV2. The script runs in the MAIN world before the first script of the page and talks to the background over a private `MessageChannel` (not `window.postMessage`). The relying party verified registrations and sign-ins (client data, RP ID hash, flags, COSE key, signature, user handle). The page-side objects pass `instanceof PublicKeyCredential` and the response type checks. A page that is hostile from its first script did not see the channel. `PublicKeyCredential.isConditionalMediationAvailable` can be answered by the extension, and a conditional `get` can be held, answered later, aborted by the page and dropped when the document goes away.
- **How to register it:** with `scripting.registerContentScripts`, after the user grants the optional `https://*/*` permission once, with `allFrames: true`, `matchOriginAsFallback: true` and `persistAcrossSessions: true`. Before the grant the registration succeeds and injects nothing; after it, the same registration injects with no second call. `persistAcrossSessions` kept the registration over a restart. A static `content_scripts` entry behaves the same, but the build refuses that key. Firefox has no `matchAboutBlank` option for registered scripts (it throws); `matchOriginAsFallback` is the one that works.
- **Without `matchOriginAsFallback`** the override is missing in `about:blank`, srcdoc and `blob:` frames, and a page gets the browser's own functions from such a frame.
- **A gap that stays:** for srcdoc and `blob:` frames, a page that reads the frame straight after adding it still holds the frame's initial realm, and the override is not in it, so the page can fetch the native functions there. The extension cannot close this. The approval UI therefore must not rely on the override being unavoidable. The probe asserts the gap, so a change in Firefox shows up. `about:blank` frames and `window.open("")` windows have the override at once.
- **Not proven:** user presence and user verification are simulated (the background sets them without a person). Whether Firefox lets an extension show an approval surface for a request that comes from a page with no extension gesture was not tested; it is the main open question. The conditional pick went through a control page of the test add-on, not an autofill surface for the page's input (an in-page picker would be page DOM, which the design forbids). Firefox's own answers (`isConditionalMediationAvailable` true, `isUserVerifyingPlatformAuthenticatorAvailable` false) were logged for the headless Linux builds only. Every result comes from a silent install that grants all permissions, with the content sandboxes off. Still open: a signed install through `about:addons`, a real authenticator or Windows Hello, a page with a strict CSP, other extensions that override the same functions, and a check against a public relying party such as webauthn.io.
- **Detectable:** the override replaces `Function.prototype.toString` so that it looks native, and a page can still detect it. The design already assumes that.

### When an API is missing

- Without `documentId` (an older or another browser): the binding is `(tabId, frameId, url)`, and the URL is checked again in the content script just before the field is filled.
- Without a `locked` state: the deadline, lock, sign-out and browser restart lock the vault (see above).
- A frame the browser does not refuse (MV2, `about:` frames): the fill engine refuses it by what it can see itself.

## Code shared with the web vault

`extension/shared.json` lists the modules of `web/src` that the build copies, byte for byte, into `dist/shared/`. The list is closed under import (every file on it imports only files on it, `import()` included), it never names a view, route or service file, and the build refuses anything else. The copies are never edited: change the file in `web/src`. The build writes `shared/MANIFEST.json` with the SHA-256 of every copy, and the release check (`scripts/check-ext-release.sh`) compares each copy with its source in `web/src` as well as with that file.

A page of the extension imports a shared file as `../shared/<name>.mjs`. That file exists only in the package, so the type check needs a stub for it: `extension/types/shared/<name>.d.mts`, which re-exports the real source (see `dom.d.mts`; `rootDirs` in `jsconfig.json` makes the two folders one). A page that imports a shared file without a stub fails `tsc` with "cannot find module"; the unit test `a_shared_file_that_a_page_imports_has_a_type_stub` names the missing stub.

## How to run it

```
scripts/lanbox-ext.sh firefox [--channel release|esr] [--manifest mv3|mv2]     the short probes, the API rows included
scripts/lanbox-ext.sh measure [--channel release|esr] [--manifest mv3|mv2]
                              [--scenario idle,sse,popup,argon,terminate] [--window-minutes N]
```

`measure` writes `lifetime-<channel>.json` into `test-results/out/ext-measure/`. The API probe prints one `probe-row {json}` line per row and per run.

## Signing the measurement build

The workflow `.github/workflows/extension-sign-measure.yml` ("Extension sign measurement build") builds the test variant and signs it with Mozilla, unlisted, so that it can be installed for good in an ordinary Firefox. It runs only when started by hand (`workflow_dispatch`), signs one build for each run (the manifest version is an input: `mv3` or `mv2`), and gives every attempt of every run a version of its own. It refuses to sign anything that is not the test variant (the add-on id must be `ferret-test@hedgerow.tools`).

The two AMO API values are secrets of a GitHub **environment** named `amo-signing`, not repository secrets. That is what makes every signing wait for a click and keeps the values away from every other branch and workflow. Set it up once:

1. In the repository on GitHub: Settings, Environments, "New environment", name it `amo-signing`.
2. On the environment, under "Required reviewers", tick it and add yourself. Leave "Prevent self-review" off (you start the run and you approve it). Save.
3. Under "Deployment branches and tags" choose "Selected branches and tags" and add the rule `main`. A run started on any other branch is then refused the secrets.
4. Under "Environment secrets" add `AMO_JWT_ISSUER` and `AMO_JWT_SECRET` (the values from your AMO developer hub API credentials). Then delete the repository secrets of the same names (Settings, Secrets and variables, Actions), so no other workflow can read them.
5. Start a run on the `main` branch: `gh workflow run extension-sign-measure.yml --ref main -f manifest=mv2` (and again with `mv3`). The run stops at "Waiting for review"; open it in the Actions tab, click "Review deployments", tick `amo-signing` and approve. Only then does the signing job start.
6. Download the artifact `ferret-measure-<manifest>-signed` (the repository is public, so the artifact is kept for one day only) and install it as below.

## Signing a release build

The workflow `.github/workflows/extension-sign-release.yml` ("Extension sign release build") signs the release variant: the MV2 package with the add-on id `ferret@hedgerow.tools`, without the test hooks, the test pages or the test host names. It is the build to install for daily use. It runs only when started by hand and uses the same `amo-signing` environment as above, so every signing waits for your approval and only runs started on `main` get the secrets.

```
gh workflow run extension-sign-release.yml --ref main -f ref=<commit SHA on main>
```

The input `ref` is the code to sign: a full 40-character commit SHA that is reachable from `main`, or the branch name `main`. Run it on `main` (`--ref main`) with the commit on `main` as the input. Anything else is refused. The run prints the commit it resolved.

Who approves: the required reviewer of `amo-signing` (you), in the Actions tab under "Review deployments", after the build job has passed. Look at the build job's summary first: commit, version and SHA-256.

What is checked before the approval is asked for (the build job, which has no secrets):

- the release package is built twice and both builds must have the same SHA-256;
- `web-ext lint --warnings-as-errors --self-hosted` (the release carries an `update_url`, which the linter allows only for an add-on that is not hosted on AMO; `--self-hosted` drops only AMO's hosting rules);
- the release check (`scripts/check-ext-release.sh`): no test file, test page, test id, fixed UUID, internal host name or test-only permission, only the release manifest keys, and the shared web files unchanged;
- the add-on id is the release id, the manifest version is 2, the name is not the test name;
- the package is at most 8 MiB.

What is checked after the approval (the sign job): the downloaded package has the SHA-256 the build job reported; it is signed unlisted with the locked web-ext; the signed package holds exactly the files of the unsigned one apart from Mozilla's `META-INF/` signature and `manifest.json`, which Mozilla rewrites when it signs (it drops the trailing newline) and which is therefore compared as parsed JSON; every other file must be byte for byte the same. The signed `.xpi` and its SHA-256 are kept as the artifact `ferret-release-mv2-signed` for seven days, and the SHA-256 is in the job summary.

After the sign job the same run publishes the signed package for the automatic updates (next section). Approving the signing therefore also hands the new version to every installed release build.

AMO refuses a version it has already seen, and this workflow never changes the version of what it signs. Before signing a new release build, raise `version` in `extension/package.json`. The same holds after a failed run: once the package has been uploaded to AMO its version is used up, so a run that fails after the upload (while waiting for Mozilla, or in the checks of the signed file) needs a new version before the next try.

## Automatic updates

The signed release build updates itself. The extension is unlisted, so AMO does not offer the updates; instead every release build carries the address of an update manifest in `browser_specific_settings.gecko.update_url`, and Firefox reads that file now and then (about once a day, or at once with "Check for Updates" in `about:addons`) and installs a newer version it lists.

The update URL is

```
https://github.com/Ferdinand99/Faithful-Ferret/releases/download/extension-updates/updates.json
```

It is the asset `updates.json` of the GitHub release with the fixed tag `extension-updates`. An installed build keeps asking the URL it was built with, so this URL must never change: do not delete or rename the release `extension-updates` or its tag, do not rename the repository, and do not turn on immutable releases for the repository (the file is replaced on every publication; a release that is immutable cannot have its asset replaced). The URL is a constant in `extension/scripts/lib/updates.mjs`; the build adds it to the release variant only (no manifest file may set it), the test variant has none, and the release check (`scripts/check-ext-release.sh`) refuses a release package with any other value or with none.

Why a release asset and not the project site: it needs only `contents: write` for one job of the signing workflow, with no new secret, no pull request and no Pages deployment, and its address depends on the repository name alone (the project site's address follows the custom domain of another repository's Pages settings). The file does not have to be trusted for the updates to be safe: Firefox installs only a package that Mozilla has signed for this add-on id (which needs the AMO key in the `amo-signing` environment), only a version newer than the installed one, and only when the downloaded file has the SHA-256 that `update_hash` names.

Each version's package is the asset `ferret-firefox-mv2-release-<version>-signed.xpi` of the release `extension-v<version>`. These tags never start with `v`, which belongs to the core releases that release-please makes, and none of these releases is marked as the latest release.

The update manifest has Mozilla's format, one entry per published version, oldest first:

```json
{
  "addons": {
    "ferret@hedgerow.tools": {
      "updates": [
        {
          "version": "0.7.1",
          "update_link": "https://github.com/Ferdinand99/Faithful-Ferret/releases/download/extension-v0.7.1/ferret-firefox-mv2-release-0.7.1-signed.xpi",
          "update_hash": "sha256:<SHA-256 of that signed file>"
        }
      ]
    }
  }
}
```

### How a version is published

1. Raise `version` in `extension/package.json` (and the lock file) in a pull request to `main`, and merge it.
2. Start the signing workflow on `main` as above and approve `amo-signing`. Only a run started on `main` for a commit on `main` publishes.
3. The workflow then runs two more jobs:
   - `manifest` (read access only) checks the signed file against the SHA-256 the sign job reported, fetches the current `updates.json` and adds the new version with `extension/scripts/updates-json.mjs`. The writer hashes the file itself and refuses to go on when the hash differs, when the file has no Mozilla signature, another add-on id, another version or another `update_url`, when the version is not newer than every listed one, or when the current file is not exactly in the shape it writes (a link that is not this repository's HTTPS link for that version, a hash that is not SHA-256, an extra key). Every older entry is kept. Only when the release `extension-updates` does not exist at all (the first publication) does it start a new file; any other failure to read the current file stops the run.
   - `publish` (`contents: write`, and no code from the repository) checks both files again, makes the release `extension-v<version>` with the signed file and its `SHA256SUMS`, reads the live `updates.json` again and refuses unless the new file is the live one plus one entry at the end (or the same file, on a re-run), replaces `updates.json` in the release `extension-updates` (it makes that release the first time), and then downloads both over HTTPS as Firefox will and compares them with what was signed and written.
4. If `publish` fails, "Re-run failed jobs" is safe: a release `extension-v<version>` that already holds the same file is kept, one that holds another file stops the run, and the writer leaves the file unchanged when the same entry is already listed.

### Installing 0.7.1 once

Version 0.7.1 is the first release build that carries the update URL. Builds up to 0.7.0 have none and never update themselves. Install 0.7.1 by hand once: download `ferret-firefox-mv2-release-0.7.1-signed.xpi` from the release `extension-v0.7.1` and open it in Firefox (or use "Install Add-on From File" in `about:addons`). It replaces 0.7.0 in place (same add-on id, so the settings and the device stay). Every later version arrives by itself. To see it happen at once, choose "Check for Updates" in the menu of `about:addons`.

## The measurement by hand

The numbers above are headless, in a container. The same measurement is made by hand in an ordinary Firefox, with the signed, unlisted build of the test variant. About ten minutes of work and twenty minutes of waiting. Start with the MV2 build, which is the default now, and repeat with MV3 to confirm the 30 seconds.

1. Install the `.xpi` (the menu of `about:addons`, "Install Add-on From File").
2. Open the settings of "Faithful Ferret (test)" in `about:addons` and follow the link "Open the lifetime measurement page". **Bookmark that page** (Ctrl+D) so you can open it again without the settings view.
3. Choose "Vault open, no page, no network" and click Start. When the page says that the scenario started, **close the measurement page, `about:addons` (the settings view is a page of the extension too) and `about:debugging`**, and do not open any page of the extension.
4. Wait twenty minutes.
5. Open the page from the bookmark. The line at the top says when the browser first announced the end of the page and when the page started again. Copy the grey box below it (the whole log) for the record.

Opening the measurement page does not start the background page; if the log ends with a start of the page after the last heartbeat, it was caused by reopening (for example through the settings view, which does start it) and not by the measurement.

What to expect: with the MV3 build the browser ends the page after about 30 seconds and the line says so. With the MV2 build it says "never".

The "stream" scenario needs the address of a server-sent events stream over https and the permission for its server (the button "Allow the stream's server" asks for it).
