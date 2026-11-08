# Firefox extension: what was measured and what follows from it

This page records what the Firefox extension relies on, measured in real Firefox, and the decisions that follow. It is the reference for the manifest, for the minimum Firefox version and for the places where an API is missing and the code has to do without it.

## How it was measured

- Firefox builds: the unbranded Release build 159.0.1 and Firefox ESR 153.6.0, the builds of the runner image (`docker/ext-runner.Dockerfile`), pinned by version and SHA-256. The current versions were checked in Mozilla's `product-details` on 2026-11-08: ESR 153.6.0esr, Release 159.0.1.
- Both manifest versions of the test build, MV3 and MV2, with the default preferences of Firefox plus the test profile (`extension/test/firefox/profile.mjs`): unsigned add-ons allowed, a fixed extension UUID, no prompt for optional permissions.
- Headless, in a container on the build host, with the content sandboxes of Firefox switched off (the container's seccomp profile blocks the user namespaces they need). The numbers are headless numbers; the same measurement is done by hand in an ordinary Firefox (see the end of this page).
- Real keyboard shortcuts, real context menu clicks and the browser's own "Terminate" for the background are made from the chrome context (`-remote-allow-system-access`), so Firefox grants `activeTab` as it does for a person.
- The probes are `extension/test/firefox/03-api-probe.spec.mjs` (one row per API, in every Firefox run) and `02-lifetime.measure.spec.mjs` (the lifetime matrix, `scripts/lanbox-ext.sh measure`).

## The lifetime of the background page

LIFETIME_PLACEHOLDER

## The Firefox APIs the plan relies on

Result in Firefox Release 159.0.1 and ESR 153.6.0. Where the two builds or the two manifest versions differ, the row says so; otherwise the result is the same in all four. "Since" is the oldest version that was measured; the probes ran only in 153.6.0 and 159.0.1, so no row claims an earlier one.

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

`strict_min_version` is `153.0`, the current ESR. Everything the plan needs exists in ESR 153.6.0, apart from the screen-lock state and `storage.session.setAccessLevel`, which neither build has and the plan can do without. No row needed a newer Release.

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

## The measurement by hand

HAND_PLACEHOLDER
