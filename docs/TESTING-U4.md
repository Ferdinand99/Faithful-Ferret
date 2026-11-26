# Testing passkeys in the extension

This milestone makes Ferret a passkey provider in Firefox. When a website asks for a passkey, Ferret opens a small window of its own
(never anything inside the page) with Ferret first: make a new passkey and keep it in the vault, or sign in with one the vault holds.
Beside that, "Use the browser instead" hands the call to Firefox's own dialog (Windows Hello, Touch ID, a phone, a security key), and
"Never on this site" leaves a site to the browser for good. A site that offers passkey autofill (conditional mediation) gets a
section in the popup and a mark on the toolbar button. Passkeys sync like every other item, the web vault shows them, and an export
from Bitwarden or AliasVault can bring them in. Signing happens only in the core: no key ever reaches JavaScript.

This file lists what is tested automatically (and which test covers which cell of the matrix), what is not tested, and how a person
checks the rest by hand at the gate (about two and a half hours). `docs/TESTING-U3.md` describes the PIN and passkey unlock that
the verification step reuses; `docs/design/phase-1-security-design.md` (sections 9.2 to 9.6 and 10.8) says what the feature promises.

All data on the test instance is throwaway test data. Use made-up names and passwords only. The real websites in checks 6 and 7 are
used only by you, by hand, with an account you can always reach another way.

## Automated tests

| What | What it checks | Command |
| --- | --- | --- |
| Core (XC4) | The authenticator (create, get, PRF, the RP ID rules and the Public Suffix List), the candidate lookup, the import of passkeys from another manager, the property tests, the vectors natively and through WASM, the fuzz targets | `scripts/lanbox.sh test -p ferret-core --locked --test passkey --test props_passkey --test origin --test passkey_import`, `scripts/lanbox-vectors.sh`, `scripts/lanbox-props.sh`, `scripts/lanbox-fuzz.sh fuzz_webauthn_options` |
| Extension unit tests and type check | The broker, the chooser window, create and get, the verification marks, the hand-over and the one-time pass, the "never" list, the popup section, the bridge's schemas, the architecture rules (signing only in the core, user presence only from Ferret's window) | `scripts/lanbox-ext.sh unit` |
| The Firefox suite (XP), Release and ESR | The page script and the bridge in real Firefox, the answer objects, the window | `scripts/lanbox-ext.sh firefox --grep passkey --wasm tree` |
| The passkey matrix (XPM), Release and ESR, MV2 and MV3 | Every case of the fixtures, the adversarial pages and the hold-out set, with Ferret answering (below) | `scripts/lanbox-passkey-rp.sh up`, then `scripts/lanbox-ext.sh passkey-matrix --provider ferret --wasm tree --channel <c> --manifest <m> --set <s>`, then `scripts/lanbox-passkey-rp.sh down` |
| The demo smoke, one run per channel | A sign-up and a sign-in with a Ferret passkey at the public demo sites; one that needs an e-mail code is checked by hand (check 3) | `scripts/lanbox-ext.sh passkey-matrix --provider ferret --wasm tree --set demo --channel <c>` |
| The end-to-end suite (XE), Release and ESR | Specs 75, 79, 97 and 98 below, against a stack of their own and the fixture container | `scripts/lanbox-ext.sh e2e --passkey-rp --wasm tree` |
| The web vault | The passkey card, the mark and the filter in the list, rename, remove, delete and restore, the import of passkeys | `scripts/lanbox-web.sh` |

Until the gate pins a published WASM package with the passkey functions, the extension's runs build the package from the tree
(`--wasm tree`). A release build never does.

### The passkey matrix

The matrix runs a real Firefox on the fixture container's own network: two relying parties (webauthn-rs, the strict one, and
SimpleWebAuthn, which many sites use), the test pages, and a test certificate authority that nothing outside the run trusts. Every case
is a folder with a `case.json` (`extension/test/fixtures/passkey/` for the fixtures and the adversarial pages,
`extension/test/fixtures/passkey-holdout/` for the hold-out set). With `--provider ferret` the extension is signed in to an end-to-end
stack of the run's own and answers, and the runner does in Ferret's window what a person would: "Save in Ferret", the passkey that
was made, the master password (or the PIN, or the account's passkey) when the window asks to verify.

The gate is 100 % of the cases of the fixtures, the adversarial pages and the hold-out set, in both channels and both manifests, with
no unsafe answer. A case that did not run counts as failed; a case ruled not applicable to a manifest (it says so in `manifests`) is
listed as such, outside the total. The demo sites are a smoke test: a failure there is an issue, not a stop, when it is understood. The reports are written to `test-results/out/u4-matrix/<set>-<channel>-<manifest>.{json,md}`.

**Driver steps.** A case that needs more than one click says what happens in its `actions`, and the runner
(`extension/test/firefox/passkeyDrive.mjs`) does it:

| Step | What the runner does |
| --- | --- |
| a lock, an unlock in the window | the popup's lock over the extension's own port; the window shows the unlock, and the master password is typed there |
| an unlock in the last five minutes, or none | a real unlock with the master password; or the setting "Count a recent unlock" off for the case (what the window sees after five minutes) |
| no network, more than seven days without it | the browser's requests to the server go to a proxy that nothing listens on (the test pages stay reachable), and the extension's sync is asked until it agrees; the PIN record's last contact is moved back |
| a navigation, `pushState`, a closed tab, an ended background | done in the page's tab; the window must close when the request ends |
| "Use the browser" | the page's call ends (as the browser ends a call the person walked away from), the page's button is clicked once more, and the browser's own authenticator answers that call (the one-time pass) |
| "Never on this site" | the call ends, the button is clicked again, and every call goes to the browser without a window; the list is emptied after the case |
| a write whose answer is lost | the stack's malicious proxy lets the passkey's write reach the server and drops the answer once; Ferret sends the same write again with the same key |
| two profiles | a second Firefox signed in to the same account: the passkey made in one signs in from the other, and one deleted in one is gone in the other |
| a page on the server's origin | the fixture's vault host counts as the signed-in server for that case: the scripts are not registered there, and the background refuses it |

**The route of a call** is Ferret's when Ferret's window showed, and the browser's when the page's call ended without one (or when
the browser's own prompt started for it: an enterprise attestation waits for a consent no automated run gives).

**The hold-out set** (50 cases) was written without the implementation, from the public specifications, and is used as written. Its
conventions (`$cred`, `$foreign`, `$bytes`, `$view`, `$omit`, `abort`, `navigate`, `removeFrame`, `concurrent`, `__page` and the
others) are mapped by the test page (`test/passkey-rp/pages/lib.mjs`). A case that turns out to be wrong, or that cannot be expressed,
is decided by a reviewer, never edited to pass: a reviewer may change an expected outcome, and each change is recorded in the case's
`note` and in `extension/test/fixtures/fixtures-changes.md`. The same holds for the fixtures.

**Unsafe answers** fail a run whatever else it does (plan section 11.3): an answer to another origin or frame than the one that asked;
an answer to a frame with a foreign ancestor; user presence without a click in Ferret's window or popup; user verification set without
a verification or a recent unlock for the request; a signature for an RP ID that is not exactly the stored one; a Ferret window without
a user gesture; a difference in error type or time between "cancelled" and "no match"; a private key outside the core; and a passkey
in the vault that the website never got, outside the trash. The runner also counts more than one Ferret window at a time as unsafe.
The ones that can be seen from outside are checked in every case; the others are covered by the unit tests, the end-to-end specs
and the leak scan.

### The end-to-end specs of passkeys

| Spec | Tests | What it shows |
| --- | --- | --- |
| `75-passkey.e2e` | `full_u4_flow_end_to_end` | The extension makes a passkey and signs in with it; the web vault shows the site, the user name and the date (never a key); a rename, a delete and a restore from the trash in the web vault reach the extension, which still signs; after "Remove passkey" in the web vault the extension's window offers no passkey for the site |
| `75-passkey.e2e` | `no_sentinel_key_leaves_the_core` | A passkey with a sentinel private key (`extension/test/fixtures/passkey-sentinel.json`, a test key of the fixture's relying party) goes into the vault through the core's import and signs. None of its forms is then in a file of the browser profile; in the browser's console output; in a message the background page receives or sends on a port (the passkey bridge's, the chooser window's and the popup's) or a runtime message it receives; in the address or body of a request the browser sent; or in what the page saw. Each scan has a control it must find. Not scanned: the page's own channel between the passkey script and the bridge (what the bridge sends on is), and the bodies of responses. The run also greps the stack's logs for it |
| `79-passkey-window.e2e` | `the_chooser_window_opens_for_a_page_request_in_release_and_esr` | The window names the site the core checked; "Use the browser", the one-time pass and "Never on this site" |
| `98-passkey-conditional.e2e` | `conditional_sign_in_from_the_popup_on_both_fixtures`, `conditional_to_modal_switch_with_and_without_the_pages_abort` | A conditional get answered from Ferret's popup at both relying parties, and a modal request that replaces a conditional one, with and without the page's own abort |
| `97-passkey-get.e2e` | `get_on_both_fixtures_verifies_with_uv_and_without` | A sign-in at both relying parties with user verification (PIN, master password, a recent unlock) and without |
| `96-passkey-matrix.e2e` | `client_libraries_accept_ferret_answers_through_the_broker` | A passkey made and used through the real broker and window, with `@simplewebauthn/browser`, a hand-written conversion and the code that reads `getPublicKey()`, at both relying parties (run on MV2 and MV3) |
| `96-passkey-matrix.e2e` | `a_passkey_made_in_one_profile_signs_in_from_the_other` | The two sync cases of the matrix passed in each channel |

## Not tested, and known limits

- **Real websites are not tested automatically.** Only the fixtures and the public demo sites are. The websites in check 6 are
  checked by hand with your own accounts, never by a run.
- **Windows Hello, a phone through a QR code and Touch ID** cannot be driven by a run: the matrix uses Firefox's virtual
  authenticator. Check 5 covers them, including Windows Hello from the popup and an unlock while a passkey autofill request waits.
- **The demo sites change.** A failure there is a finding to look at, not a stop, when the fixtures pass and the failure is
  understood. A site whose sign-up needs an e-mail code cannot be driven and is checked by hand (check 4).
- **Five minutes are not waited for.** "No unlock in the last five minutes" is made by turning the setting off for the case; the
  clock rule itself is covered by the unit tests.
- **The network capture reads request bodies the browser can read again**; responses are not read. A key never travels in an answer
  to the browser by design, and the core's tests cover what the core returns.
- **Chromium** (U5) and mobile browsers are not targets of this milestone.

## Checks by hand at the gate

**You need:**

- a test instance of the server built from the gate commit, behind your reverse proxy at `https://vault.example.test` (the vault) and
  `https://admin.example.test` (the admin pages); the names are placeholders, use your own;
- an account on it, with its secret key, and a PIN set in the extension (`docs/TESTING-U3.md`, check 2);
- the extension's build from the gate, Firefox 153 or newer (Release), on Windows, and a second browser or profile signed in to the same
  account (a Mac with Touch ID if you have one);
- a Windows computer with Windows Hello set up, a phone with a screen lock, and (optionally) a Mac with Touch ID;
- every other password manager's passkey support turned off in that browser;
- for check 6: your own accounts at a few websites that accept passkeys, each with another way to sign in that you keep (a password
  and a second factor, or a passkey in Windows Hello), so a mistake never locks you out. Make test passkeys only, in items whose
  names start with `U4-test`, and delete them afterwards.

### 1. Turn it on (about 5 minutes)

1. Settings, Passkeys, "Use Ferret for passkeys".
   *Expected:* the text says what it means; Firefox asks for access to `https` pages if you did not give it for saving logins.
2. Open the extension's settings again.
   *Expected:* the Passkeys section shows the switch on, "Count an unlock in the last 5 minutes" on, and an empty "Never on these
   sites" list.

### 2. Make and use a passkey on a demo site (about 15 minutes)

1. On `https://webauthn.io` register with the default options.
   *Expected:* Ferret's window opens and shows the host from Ferret (not the page's text), the user name from the page, and Ferret
   first. If you unlocked in the last 5 minutes one click is enough; otherwise the window asks you to verify (Windows Hello, PIN or
   master password). The page says "Success".
2. Sign in ("Authenticate").
   *Expected:* the window shows the passkey; one click (and a verification when it asks) signs you in.
3. Repeat with "User Verification: Discouraged" (one click, nothing asked) and "Required" (a verification unless you unlocked in the
   last 5 minutes).

### 3. A demo site with an e-mail code, and passkey autofill (about 15 minutes)

1. On `https://www.passkeys.io` sign up with an address you can read, make a passkey there with Ferret (the window, "Save in Ferret"),
   sign out and sign in with the passkey. No automated run can do this (the sign-up sends a code by e-mail).
   *Expected:* both work, with Ferret's window.
2. On a demo site that offers passkey autofill (for example `https://www.passkeys.io` after the sign-up), sign out and go to the
   sign-in page without clicking anything.
   *Expected:* no window opens by itself; the toolbar button gets a mark.
3. Open the popup.
   *Expected:* a section "Passkeys for <site>" lists the passkey; one click (and a verification when it is more than 5 minutes since an
   unlock) signs you in.

### 4. The browser instead, and "Never on this site" (about 10 minutes)

1. On `https://webauthn.io` start a registration and choose "Use the browser instead".
   *Expected:* the window closes, the page's call ends, and the page asks nothing; click the page's button once more: Firefox's own
   dialog (Windows Hello) comes. Within 60 seconds only, and only for the same kind of call on the same page.
2. Choose "Never on this site" on a test site.
   *Expected:* the next request there goes straight to Windows, with no Ferret window. Remove the site from the list in the settings.
3. On a site where Ferret holds no passkey, start a sign-in.
   *Expected:* Ferret's window still opens, says "No Ferret passkey for this site" and offers the browser as the clear way on.

### 5. Windows Hello, a phone and Touch ID (about 40 minutes)

These are the parts of the hand-over and the verification that no automated run can reach.

1. **Windows Hello as the browser** (Windows): on `https://webauthn.io` choose "Use the browser instead" for a registration, then
   click the page's button again.
   *Expected:* Windows Hello asks, the passkey is made in Windows, and a sign-in with the browser works the same way.
2. **A phone through a QR code**: as step 1, but choose "use a phone or tablet" in the Windows dialog and scan the code.
   *Expected:* the registration and a sign-in work (the phone has to be near the computer).
3. **Windows Hello as the verification in Ferret's window**: with no unlock in the last 5 minutes (or the setting off), sign in with a
   Ferret passkey and choose Windows Hello in the window's verification step.
   *Expected:* Windows Hello asks once; the site signs you in, and it sees user verification.
4. **Windows Hello from the popup**: on a sign-in page that offers passkey autofill (check 3), open the popup and choose the passkey
   when it asks to verify with Windows Hello.
   *Expected:* the popup hands over to Ferret's window (Windows Hello works only from a window of its own, not from the popup), and
   the sign-in completes there.
5. **An unlock while a passkey autofill request waits**: lock the vault, open a sign-in page that offers passkey autofill (the button
   gets its mark), and unlock the vault with Windows Hello (the unlock window) without leaving the page.
   *Expected:* the unlock works, and the popup's passkey section then signs you in. Then the same with the browser's own passkeys:
   the page's autofill list still offers the browser's passkeys after Ferret's unlock. If Windows Hello is aborted, or the page's
   autofill call stops working, note it: the background then needs to pause its call to the browser while Windows Hello runs.
6. **Touch ID on a Mac** (if you have one): repeat steps 1 and 3 with Touch ID; then sign in on `https://webauthn.io` from the Mac
   with the passkey Ferret made on Windows (check 8).
   *Expected:* both work.

### 6. Real websites (about 30 minutes)

Use your own accounts at a few websites of these kinds, by hand: a code hosting service, a large web mail and office suite, a large
operating system vendor's account, a self-hosted code forge, and one or two more you choose. Never put the names of the accounts in
an issue or a report.

1. At each, add a passkey in the account's security settings. Save it in Ferret in a new `U4-test` item, or add it to the item you
   have when the window offers that.
   *Expected:* the site accepts it.
2. Sign out and sign in with the passkey: with the site's passkey button (the window), and from the popup when the site offers
   passkey autofill.
   *Expected:* both sign you in.
3. Remove the test passkeys at the sites and in Ferret.

### 7. The web vault (about 10 minutes)

1. Open a `U4-test` item in the web vault.
   *Expected:* it shows "Passkey" with the site, the user name and the date, never the key. The list marks it and the passkey filter
   finds it.
2. Rename it, then sign in with it from the extension.
   *Expected:* it still works.
3. Remove the passkey from the item.
   *Expected:* the warning says that the site still has the public key; the extension no longer offers it.
4. Delete a test item and restore it from the trash.
   *Expected:* the trash names the site; after the restore the passkey signs in again.

### 8. Sync (about 10 minutes)

1. Open the second browser (or the Mac) signed in to the same account.
   *Expected:* the passkeys are there; a sign-in on `https://webauthn.io` works from there.
2. Delete a test passkey item in one browser.
   *Expected:* it is gone in the other after a sync.

### 9. Import (about 10 minutes)

1. Make a test passkey in Bitwarden or AliasVault on `https://webauthn.io`, export (Bitwarden JSON, AliasVault `.avux`) and import the
   file in the web vault.
   *Expected:* the report counts the passkey, and a sign-in on `https://webauthn.io` with it works from the extension.
2. Delete the export file and the test passkey in the other manager.

### 10. Nothing happens without you, and the combined smoke test (U2, U3 and U4; about 20 minutes)

1. On a page that asks for a passkey when it loads (without a click).
   *Expected:* no window opens by itself; the button gets a mark and the popup shows a card that opens the window.
2. Ferret's own pages and the web vault use the browser's own WebAuthn: unlock the web vault with its passkey (`docs/TESTING-U3.md`,
   check 3).
   *Expected:* it works as before.
3. Run `docs/TESTING-U3.md` check 10 (fill, save, the generator, a one-time code, PIN, passkey and master password unlock) on the same
   profile.
   *Expected:* everything works with passkeys on.
4. Clean up: delete the test passkeys in Ferret and at the websites.

## Results of a gate run

Keep these lines with the release notes of the run:

| Check | Date | Who | Result |
| --- | --- | --- | --- |
| XC4 (core, vectors, props, fuzz) |  |  |  |
| XU, Release and ESR |  |  |  |
| XP, Release and ESR |  |  |  |
| XPM fixtures, adversarial and hold-out, Release and ESR, MV2 and MV3 |  |  |  |
| Demo smoke, Release and ESR |  |  |  |
| XE, specs 75, 79, 97 and 98, Release and ESR |  |  |  |
| Web vault suites |  |  |  |
| Check 5, Windows Hello and the phone |  |  |  |
| Check 5, Windows Hello from the popup and an unlock while autofill waits |  |  |  |
| Check 5, Touch ID on a Mac |  |  |  |
| Check 6, real websites |  |  |  |
| Check 8, sync |  |  |  |
| Check 9, import |  |  |  |
| Check 10, the combined smoke test |  |  |  |
