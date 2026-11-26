# Passkey hold-out set

50 hidden cases for the Ferret passkey matrix. They were written without access to the implementation, using only `case.schema.json`, `categories.json`, `matrix-categories-plan.md` and the public specifications (WebAuthn Level 3, CTAP 2.x, HTML, URL, WebIDL, Permissions Policy). Every `case.json` validates against `case.schema.json`. Extra checks also pass: id equals the folder name, set is holdout, only allowed hosts, unsafe ids come from `categories.json`, `error` appears only with `client-error`, and `kinds`/`allow` have one entry fewer than the chain.

## Per category

| Category | Cases |
|---|---|
| create-options | 4 |
| create-algs | 3 |
| create-exclude | 2 |
| create-extensions | 3 |
| create-users | 2 |
| create-gesture | 1 |
| get-modal | 4 |
| get-conditional | 2 |
| get-prf | 2 |
| origin-rpid | 8 |
| frames | 7 |
| navigation | 2 |
| adv-bridge | 2 |
| adv-input | 2 |
| adv-frames | 2 |
| adv-window | 2 |
| adv-timing | 1 |
| adv-vault | 1 |

Not covered on purpose: vault-network, verification, handover, background and sync. Their outcomes depend on Ferret's own UI and vault state rather than on the specifications, so a test writer without access to the implementation cannot state them.

## Cases

| Id | Category | Spec clause |
|---|---|---|
| `ho-create-rk-unknown-falls-back` | create-options | WebAuthn L3 §5.4.4, §5.4.6 (unknown residentKey ignored, requireResidentKey fallback) |
| `ho-create-unknown-enum-values` | create-options | L3 §2.1.1, §5.4 (DOMString enums: unknown values ignored) |
| `ho-create-buffer-subviews` | create-options | WebIDL "get a copy of the bytes held by the buffer source" |
| `ho-create-timeout-wraps` | create-options | WebIDL unsigned long conversion; L3 §5.1.3 timeout correction |
| `ho-algs-rs256-before-es256` | create-algs | L3 §5.4 pubKeyCredParams order; CTAP2 §6.1.2 step 3; L3 §5.2.1.1 |
| `ho-algs-unknown-type-and-alg-mixed` | create-algs | L3 §5.1.3 step 10; CTAP2 §6.1.2 |
| `ho-algs-only-unknown-type` | create-algs | L3 §5.1.3 step 10 (NotSupportedError) |
| `ho-exclude-hit-odd-transports` | create-exclude | L3 §6.3.2 step 3; §5.8.4 (unknown transports ignored) |
| `ho-exclude-hit-behind-unknown-type` | create-exclude | L3 §5.8.3 (unknown descriptor type ignored); §6.3.2 step 3 |
| `ho-ext-prf-create-evalbycredential` | create-extensions | L3 §10.1.4 prf, registration client processing |
| `ho-ext-unknown-and-misplaced` | create-extensions | L3 §9 (unknown extensions ignored); §10.1.3 credProps is registration-only |
| `ho-ext-prf-eval-at-create-then-two-salts` | create-extensions | L3 §10.1.4 prf (eval at create; first+second at get) |
| `ho-users-id-64-bytes` | create-users | L3 §5.4.3 user.id max 64 bytes |
| `ho-users-missing-displayname` | create-users | L3 §5.4.3 required displayName; WebIDL dictionary conversion |
| `ho-gesture-xorigin-create-no-activation` | create-gesture | L3 §5.1.3 (cross-origin create needs transient activation) |
| `ho-get-signal-preaborted` | get-modal | L3 §5.1.4.1 (aborted signal -> abort reason) |
| `ho-get-abort-custom-reason` | get-modal | L3 §5.1.4.1 abort steps (reject with signal.reason); DOM AbortSignal |
| `ho-get-uv-required-after-discouraged-create` | get-modal | L3 §5.8.6, §6.3.3 (UV required -> UV=1 only after verification) |
| `ho-get-default-rpid-on-child` | get-modal | L3 §5.1.4.1 (rpId default = effective domain) |
| `ho-cond-no-gesture-no-window` | get-conditional | L3 §5.1.4 conditional mediation; Credential Management mediation |
| `ho-cond-abort-and-modal-same-tick` | get-conditional | L3 §5.1.4.1 abort steps (per signal); conditional mediation |
| `ho-prf-evalbycred-empty-allow` | get-prf | L3 §10.1.4 prf, authentication client processing (NotSupportedError) |
| `ho-prf-evalbycred-and-eval` | get-prf | L3 §10.1.4 prf (evalByCredential precedence) |
| `ho-rpid-sibling-subdomain` | origin-rpid | L3 §5.1.3 step 7; HTML "is a registrable domain suffix of or is equal to" |
| `ho-rpid-sibling-github` | origin-rpid | L3 §5.1.4.1; HTML registrable-suffix algorithm; Public Suffix List |
| `ho-rpid-trailing-dot-rpid` | origin-rpid | HTML registrable-suffix algorithm; URL host parser (trailing dot kept) |
| `ho-rpid-uppercase-host` | origin-rpid | URL host parser (domain to ASCII lowercases); L3 §5.1.3 default rpId |
| `ho-rpid-uppercase-rpid` | origin-rpid | L3 §6.1 rpIdHash over the RP ID string; HTML suffix check (UNCERTAIN) |
| `ho-rpid-with-port` | origin-rpid | URL host parser (forbidden host code point); L3 §5.1.3 step 7 |
| `ho-rpid-idn-lookalike-claims-ascii` | origin-rpid | L3 §5.1.4.1 step 7; URL host parser (A-labels) |
| `ho-rpid-idn-punycode-explicit` | origin-rpid | L3 §5.1.3 step 7; URL origin serialisation (A-labels) |
| `ho-frame-xorigin-no-allow-get` | frames | L3 §5.1.4.1, Permissions Policy integration (publickey-credentials-get default 'self') |
| `ho-frame-same-site-no-allow` | frames | Permissions Policy 'self' = same origin; L3 Permissions Policy integration |
| `ho-frame-get-allowed-create-called` | frames | L3 §5.1.3, Permissions Policy integration (publickey-credentials-create is a separate feature) |
| `ho-frame-nested-inner-missing-allow` | frames | Permissions Policy inheritance through a cross-origin parent; L3 §5.1.4.1 |
| `ho-frame-nested-create-both-allow` | frames | L3 §5.1.3/§5.1.4.1 cross-origin ceremonies; CollectedClientData.topOrigin |
| `ho-frame-attacker-top-frames-rp` | frames | L3 §5.1.3/§5.1.4.1; §5.8.1 topOrigin/crossOrigin |
| `ho-frame-sandbox-opaque-origin` | frames | HTML sandbox (opaque origin); L3 §5.1.4.1 opaque callerOrigin |
| `ho-nav-hash-change-mid-get` | navigation | HTML navigate to a fragment (same Document) |
| `ho-nav-frame-removed-mid-create` | navigation | HTML document destruction (not fully active); L3 §5.1.3 lifecycle |
| `ho-advbridge-illegal-invocation` | adv-bridge | WebIDL operations: receiver must implement CredentialsContainer (TypeError) |
| `ho-advbridge-proto-pollution-origin` | adv-bridge | L3 §5.1.3 callerOrigin from the settings object; §5.8.1 clientData origin |
| `ho-advinput-rpid-getter-flip` | adv-input | WebIDL dictionary conversion reads each member once |
| `ho-advinput-challenge-mutated-after-call` | adv-input | WebIDL BufferSource copy at call time |
| `ho-advframe-attacker-claims-top-rpid` | adv-frames | L3 §5.1.4.1 step 7 (RP ID vs the frame's own effective domain) |
| `ho-advframe-github-sibling-frames` | adv-frames | L3 cross-origin ceremonies; Public Suffix List (github.io) |
| `ho-advwindow-two-concurrent-gets` | adv-window | concurrency not specified (UNCERTAIN); at most one window |
| `ho-advwindow-synthetic-click` | adv-window | HTML user activation (an untrusted click() grants none) |
| `ho-advtiming-foreign-only-timeout` | adv-timing | L3 §5.1.4.1, §14.5.2 (no match indistinguishable from cancel) |
| `ho-advvault-framed-by-rp` | adv-vault | L3 cross-origin ceremonies; provider override off on the vault origin |

Some notes are marked UNCERTAIN. In those cases the expected outcome follows the literal spec text, but real engines may behave differently. Review the case before treating a failure as a bug.

## Conventions in `spec`

These conventions need to be mapped onto `test/passkey-rp/pages/lib.mjs`. The author could not see the `spec` shape the ceremony page uses. The cases use the member names the schema lists (`steps`, `rpId`, `user`, `create`, `get`, `holdMs`, `tamper`, `__page`) with these extra conventions:

- `steps`: `create`, `get` and `conditional`, run in order after the click. `create` may be an array with one override object per create step.
- `create` / `get`: overrides merged into the page's default `publicKey` options. A top-level `rpId` sets `rp.id` and `rpId` for every step.
- `"$cred"`: the raw id of the credential made by the first create step. It is base64url when used as a key, for example in `evalByCredential`. A bare `"$cred"` in `allowCredentials` or `excludeCredentials` means `{type: "public-key", id}`.
- `{"$foreign": n}`: a random n-byte credential id that no authenticator knows. `{"$bytes": n}`: n random bytes. Adding `"$view": {bufferBytes, byteOffset}` passes a `Uint8Array` view into a larger buffer.
- `{"$omit": true}`: removes that member from the page's defaults.
- `abort`: `{when: "before"}` aborts the signal before the call. `{step, afterMs, reason}` aborts later. `reason: {"$error": "TypeError"}` means `new TypeError(...)`.
- `navigate`, `removeFrame`, `switch`, `concurrent` and `report` are lifecycle actions. Each case's title and note describe them. `__page` names an adversarial page, which may still have to be written.

## Changed after review

A reviewer may change an expected outcome of this set; each change is recorded here and in the case's `note`. Changed after review U4-13:

- `ho-rpid-uppercase-rpid`: expected {"ceremony":"client-error","error":"SecurityError","failStep":"create","route":"any","maxWindows":0} (was {"ceremony":"server-refused","failStep":"create","route":"any"}). Firefox's own answer is SecurityError, before any window (the note already allowed it as safe); Ferret refuses the same way.
- `ho-frame-nested-create-both-allow`: expected {"ceremony":"none","route":"any","maxWindows":0} (was {"ceremony":"ok","route":"browser","maxWindows":0}). Firefox itself never answers a delegated cross-origin create in a nested chain; the safety check is no Ferret window (maxWindows 0 and the foreign-ancestor check, which runs for route any).
- `ho-nav-frame-removed-mid-create`: expected {"ceremony":"none","route":"any","maxWindows":1} (was {"ceremony":"none","route":"none","maxWindows":1}). the one allowed window counts as a Ferret route in the runner; what matters is that nothing is delivered and the window closes, which the runner checks (a window still open, or a new item in the vault, fails the case).
- `ho-advframe-github-sibling-frames`: expected {"ceremony":"server-refused","route":"browser","maxWindows":0} (was {"ceremony":"ok","route":"browser","maxWindows":0}). the browser path (no Ferret window) is the right one; the fixture relying parties refuse a cross-origin ceremony by design (webauthn-rs refuses crossOrigin true, SimpleWebAuthn needs an expected top origin), so ok cannot be reached with them.
- `ho-advvault-framed-by-rp`: expected {"ceremony":"server-refused","route":"browser","maxWindows":0} (was {"ceremony":"ok","route":"browser","maxWindows":0}). the browser path (no Ferret window) is the right one; the fixture relying parties refuse a cross-origin ceremony by design, so ok cannot be reached with them.
- `ho-frame-attacker-top-frames-rp`: expected {"ceremony":"server-refused","route":"browser","maxWindows":0} (was {"ceremony":"ok","route":"browser","maxWindows":0}). the browser path (no Ferret window) is the right one; the fixture relying parties refuse a cross-origin ceremony by design, so ok cannot be reached with them.
