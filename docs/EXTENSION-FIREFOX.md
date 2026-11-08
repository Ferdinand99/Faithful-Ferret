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
| Frame ids | The top frame is 0; the frames below it are numbered from 17179869185 (more than 2^32) up, and `parentFrameId` is the top frame's 0. They are safe integers, not 32-bit ones. | Message schemas accept a `frame_id` up to the largest safe integer (a 32-bit bound would turn real frames away). |
| `documentId` in `tabs.sendMessage` | Works: `sendMessage(tabId, message, { documentId })` reaches that document. | A fill message goes to one document, not to whatever the frame has become. |
| `optional_host_permissions` in MV3 | Works. The manifest key is accepted, nothing is granted at install, `permissions.request` grants it. MV2 has the origins in `optional_permissions` (the build folds them). | Server and frame origins are asked for in a tab. |
| `permissions.request` from a tab | Works from a click on a page of the extension. In the test profile no prompt appears. | All requests happen in a tab (the popup closes when the prompt opens). |
| The preference for permissions without a prompt | `extensions.webextOptionalPermissionPrompts` set to `false` makes `permissions.request` answer without a prompt. It is the preference `profile.mjs` already sets. | Test profile only; a person's Firefox shows the prompt. |
| `menus.getTargetElement` | Works in a content script, with the `targetElementId` of `menus.onClicked`. It returns the element that was clicked. | The context menu finds the field through it. |
| `action.openPopup` from `commands.onCommand` | Works (MV3 `action`, MV2 `browserAction`). | A shortcut with no single match opens the popup. |
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

### The value of `data_collection_permissions`

`required: ["authenticationInfo"]`. The extension sends sign-in proofs and device credentials to a server outside the browser (the user's own), which Mozilla's definition of data transmission counts, so `none` would be wrong. Nothing goes to the developer or to a third party. Both Firefox builds accept it.

### The minimum Firefox version

`strict_min_version` is `153.0`, the current ESR. Everything the extension needs exists in ESR 153.6.0, apart from the screen-lock state and `storage.session.setAccessLevel`, which neither build has and the extension can do without. No row needed a newer Release.

### When an API is missing

- Without `documentId` (an older or another browser): the binding is `(tabId, frameId, url)`, and the URL is checked again in the content script just before the field is filled.
- Without a `locked` state: the deadline, lock, sign-out and browser restart lock the vault (see above).
- A frame the browser does not refuse (MV2, `about:` frames): the fill engine refuses it by what it can see itself.

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
3. Under "Deployment branches and tags" choose "Selected branches and tags" and add the rule `ext`. A run started on any other branch is then refused the secrets.
4. Under "Environment secrets" add `AMO_JWT_ISSUER` and `AMO_JWT_SECRET` (the values from your AMO developer hub API credentials). Then delete the repository secrets of the same names (Settings, Secrets and variables, Actions), so no other workflow can read them.
5. The file must also be on `main` before GitHub lists the workflow (a copy of it on `main` is enough; it cannot do anything there, because `main` has no `extension/` folder). Start a run on the `ext` branch: `gh workflow run extension-sign-measure.yml --ref ext -f manifest=mv2` (and again with `mv3`). The run stops at "Waiting for review"; open it in the Actions tab, click "Review deployments", tick `amo-signing` and approve. Only then does the signing job start.
6. Download the artifact `ferret-measure-<manifest>-signed` (the repository is public, so the artifact is kept for one day only) and install it as below.

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
