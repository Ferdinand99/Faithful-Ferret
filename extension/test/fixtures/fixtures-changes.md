# Changes to the passkey matrix's expected outcomes

The fixture set of the passkey matrix (`passkey/`, written from `passkey/generate.mjs`) and the hold-out set (`passkey-holdout/`) are
frozen once merged: an expected outcome changes only with a reviewer's yes, and every change is logged here and in the case's `note`.

## Review U4-13 (2026-11-26)

Twelve changes, approved in review U4-13. The rule behind them: where Firefox's own WebAuthn refuses, Ferret refuses the same way; a
property of the test relying parties is not a property of Ferret.

| Case | Before | After | Why |
| --- | --- | --- | --- |
| `ho-rpid-uppercase-rpid` (hold-out) | server-refused, failStep create, route any | client-error SecurityError, failStep create, route any, maxWindows 0 | Firefox's own answer is SecurityError before any window; the case's note already allowed it as safe |
| `ho-frame-nested-create-both-allow` (hold-out) | ok, route browser, maxWindows 0 | none, route any, maxWindows 0 | Firefox itself never answers a delegated cross-origin create in a nested chain; the check is "no Ferret window" (maxWindows 0 and the foreign-ancestor check) |
| `ho-nav-frame-removed-mid-create` (hold-out) | none, route none, maxWindows 1 | none, route any, maxWindows 1 | the one allowed window counts as a Ferret route in the runner; the runner now checks that the window closes and that nothing reaches the vault |
| `ho-advframe-github-sibling-frames` (hold-out) | ok, route browser, maxWindows 0 | server-refused, route browser, maxWindows 0 | the browser path is right; the fixture relying parties refuse a cross-origin ceremony by design |
| `ho-advvault-framed-by-rp` (hold-out) | ok, route browser, maxWindows 0 | server-refused, route browser, maxWindows 0 | as above |
| `ho-frame-attacker-top-frames-rp` (hold-out) | ok, route browser, maxWindows 0 | server-refused, route browser, maxWindows 0 | as above |
| `background-unloaded-under-request` (MV3) | none, route ferret | client-error NotAllowedError, route ferret, waitMs 40000 | an unloaded event page loses its requests and the bridge's next ping ends them with NotAllowedError: it fails closed |
| `background-unloaded-under-request` (MV2) | run (not run) | not applicable (`manifests: ["mv3"]`) | the MV2 background page is persistent; ending it by force leaves the add-on without one, a state no person reaches; the dead-bridge path is covered by `77-passkey-bridge` |
| `get-uv-preferred-no-verification` | webauthn-rs; age-unlock, start-get, choose-in-window | SimpleWebAuthn; create-online, go-offline, age-offline 8 days, start-get, choose-in-window; expected unchanged (ok, UV false) | webauthn-rs refuses UV = 0 for a passkey registered with UV (the strict-RP note of UK107); the steps now say what "no possible verification" is instead of the runner deciding it |
| `nav-lock-mid-request` | ok, route ferret; start-waiting-create, lock, unlock-in-window, choose-in-window | client-error NotAllowedError, failStep create, route ferret, maxWindows 1; start-waiting-create, lock | a lock ends a waiting request (plan section 6, UK112 b); the unlock in the window is for a request that starts while the vault is locked (`vault-locked-unlock-in-window`) |
| `adv-signals` | the page checks eight statics | the page checks the five that stay the browser's own (signal and parse methods); the case is unchanged | three statics are answered by Ferret by design (UK119) |
| `demo-passkeys-io` | an automated case | a hand check (`hand`) | the sign-up needs an e-mailed code that no run can read; checked by hand at the gate (`docs/TESTING-U4.md`) |
