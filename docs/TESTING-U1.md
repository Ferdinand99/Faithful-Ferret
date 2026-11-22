# Testing the Firefox extension and the new web vault layout

This milestone adds the Firefox extension (sign-in, sync, a popup that fills logins on the page they belong to, copy with a
cleared clipboard, lock and auto-lock, forgetting a server, and the frame and phishing rules of design § 10) and the new
layout of the web vault (a shell with a side menu, a windowed list, item pages, folders as encrypted labels, a theme
choice, and "Unlock" after the server session has ended). This file lists what is tested automatically, how a person checks
the rest by hand on a test instance (about an hour and a half), and the limits to expect. `docs/EXTENSION-FIREFOX.md`
records what the extension relies on in Firefox and why the Firefox build uses the MV2 manifest; `docs/TESTING-M1.md` to
`docs/TESTING-M3.md` describe the end-to-end stack and the earlier milestones' checks.

All data on the test instance is throwaway test data. Use made-up names and passwords only.

## Automated tests

| What | What it checks | Command |
| --- | --- | --- |
| Unit tests and type check of the extension | Both manifest versions in both variants built; the background, core host, fill flow, frame rules, popup and sign-in flows, lock, clipboard, menus and shortcut | `scripts/lanbox-ext.sh unit` |
| Lint and the release check | `web-ext lint` with warnings as errors on the MV2 and MV3 release builds, and `scripts/check-ext-release.sh` (no test file, no test page, no fixed UUID, only the allowed manifest keys and permissions) | `scripts/lanbox-ext.sh lint` |
| The Firefox suite (XF), unbranded Release and ESR, no network | 42 specs: smoke, the core host, lifetime, the API probe row per API, fill engine, sign-in, page matching, shortcut and menu, lock (including the 15 second setting), the fixture audit | `scripts/lanbox-ext.sh firefox --manifest mv2` |
| The end-to-end suite (XE), Release and ESR, each against a stack of its own | Sign-in and sync against a real server (an item made in the web vault shows in the extension within two seconds), the evil-server modes give the same warnings as in the web vault, the popup fills on the fixture pages, every phishing and clickjacking row of the fixtures (look-alike hosts, http, frames hidden or covered by their page, overlays added after the report, navigation between pick and fill), sign-in to revoke end to end, a killed background comes back locked, a copied password leaves the clipboard after 30 seconds | `scripts/lanbox-ext.sh e2e --manifest mv2` |
| The extension's gate run | XF then XE, MV2, with the screenshots of the e2e specs kept | `scripts/lanbox-ext.sh gate --channel release` and `--channel esr` |
| The web vault | Unit tests, Playwright in three browsers, and the stack scenarios 01 to 27 (the new shell, list, folders, unlock after the session has ended) | `scripts/lanbox-web.sh`, `scripts/lanbox-ferret-e2e-gate.sh` |

The release package is reproducible: building the unsigned release `.xpi` twice from a clean tree gives the same SHA-256.
The packed size is checked against a budget of 8 MiB.

## Checks by hand on a test instance

**You need:**

- a fresh test instance of the server built from this branch, with an empty data volume and its setup token, behind your
  reverse proxy at `https://vault.example.test` (the vault) and `https://admin.example.test` (the admin pages). These names
  are placeholders: the extension refuses `.test` names for a real server, so use your own;
- the API paths of the vault origin reachable by the extension. The extension sends no cookie, so a proxy that puts a
  single sign-on page in front of the vault must let `/api/*` through to the server untouched (a rule that bypasses the
  proxy's authentication for that path). Check it with
  `curl -i https://vault.example.test/api/auth/session`: the answer must be the server's own JSON
  (`{"error":"unauthorized"}`), not a sign-in page of the proxy;
- two static test pages for the frame cases on two names of one site that are both different from the vault, for example
  `https://frames.example.test` (site A) and `https://login.example.test` (site B), served without single sign-on (see
  "The frame pages" below);
- the signed test build of the extension (an `.xpi` signed for unlisted distribution, installable in an ordinary
  Firefox), Firefox 153 or newer;
- a second browser (for example Chromium, or a private window) for the web vault;
- a text editor to paste the clipboard into;
- an unencrypted Bitwarden JSON file with about a thousand made-up logins, including one login for site A, one for site B
  and one with a one-time code (TOTP) secret.

Reload every open vault tab after a deploy: a tab loaded before it still runs the old scripts.

### 1. The account (browser 2, about 10 minutes)

1. Open the vault. Choose "Set up a new vault", enter the setup token, an e-mail address, a master password (MP) and the
   same again, leave "Use a secret key" on, and continue. Type the keys back as asked.
   *Expected:* the emergency sheet, then "Account created". Write down the secret key (SK) and keep the line of the QR code
   text (`ferret-setup:v1?…`).
2. Import the Bitwarden file (Import and export, Import).
   *Expected:* a preview with the counts, then the items in the list.

### 2. The web vault layout (browser 2, about 15 minutes)

1. Look at the shell: the side menu (All items, Favourites, Folders, Trash, Import and export; Generator and Health shown
   as "Coming soon"), the account menu, and the Vault/Admin switch.
   *Expected:* every entry that is not "Coming soon" opens its page; nothing leads to an empty or broken page.
2. Scroll the list of about a thousand items from top to bottom, and search for one item by part of its name.
   *Expected:* scrolling stays smooth, the search answers at once while typing, the count is right.
3. Open an item.
   *Expected:* the item page shows the fields; secret fields are dots until "Show"; copy works.
4. Edit an item and put it in two folders (one new name, one existing). Open Folders, pin one folder to the menu, rename
   one, delete one.
   *Expected:* the item shows its folders; the pinned folder is in the side menu; rename and delete change every item that
   had the folder and leave the items in the vault.
5. Account menu, Theme: switch between Light, Dark and System.
   *Expected:* the whole page follows at once, and the choice is kept after a reload.
6. Lock (account menu, "Lock now") and unlock with the master password.
   *Expected:* the list is gone while locked; unlock opens it again.

### 3. The extension: install and sign in (Firefox, about 10 minutes)

1. Install the signed test build (`about:addons`, "Install Add-on From File").
   *Expected:* Firefox installs it without a warning about an unsigned add-on; the Ferret button is in the toolbar.
2. Press the button.
   *Expected:* "Not signed in" with a "Sign in" button.
3. Press "Sign in". In the tab, type the vault address and continue; press "Give access to the server" and allow it in
   Firefox's prompt.
   *Expected:* Firefox asks for exactly this server; nothing is sent before the permission.
4. Enter the e-mail, MP, answer "Yes" to the secret key question and enter SK. Paste the QR code text into "Text of the
   QR code". Sign in.
   *Expected:* "The vault is open" after a few seconds.
5. Open the popup.
   *Expected:* "Items:" with the full count; search finds an item by name.
6. In browser 2, make a new login. Watch the popup (or open it again).
   *Expected:* the new item is in the popup within a few seconds, without a reload.

### 4. Filling (Firefox, about 10 minutes)

1. Open frame page F1 on site A (a login form in the page itself). Open the popup.
   *Expected:* the site A login under "Suggestions for this page", with "Fill". The site B login is not suggested.
2. Press "Fill".
   *Expected:* "Filled in."; the user name and the password are in the form.
3. Reload F1 and press the shortcut (Alt+Shift+L).
   *Expected:* exactly one item matches, so the form is filled without the popup.
4. Reload F1, right-click in the user name field and choose "Fill with Ferret".
   *Expected:* the form is filled.
5. Open a page of a site with no saved login and open the popup.
   *Expected:* no suggestion; searching finds an item, which offers copy only, no "Fill".

### 5. Copy and the 30 second clear (Firefox, about 5 minutes)

1. In the popup, copy the password of an item. Paste it into the text editor at once.
   *Expected:* the popup says the clipboard is cleared in 30 seconds; the paste shows the password.
2. Wait 30 seconds and paste again.
   *Expected:* nothing is pasted (the clipboard is empty).
3. Copy a password and press "Lock" in the popup right away. Wait 30 seconds and paste.
   *Expected:* nothing is pasted.
4. Copy the password of item 1; after about 10 seconds copy the password of item 2. Paste at 25 seconds after the first copy,
   and again at 35 seconds.
   *Expected:* both pastes give item 2's password (the first copy's clear leaves the second value alone); 30 seconds after
   the second copy nothing is pasted.
5. Copy the one-time code of the TOTP item.
   *Expected:* a six-digit code that matches an authenticator with the same secret; it is cleared after 30 seconds too.

### 6. Lock and auto-lock (Firefox, about 10 minutes)

1. Press "Lock" in the popup.
   *Expected:* "The vault is locked" with only a password field (no server, no e-mail); unlock with MP opens it.
2. Open Ferret's settings (`about:addons`, Ferret, Preferences). Set "Lock after" to 15 seconds.
   *Expected:* "Saved."; the choices go from 15 seconds to 24 hours and there is no "never".
3. Close every Ferret page and wait 30 seconds without touching Ferret. Open the popup.
   *Expected:* locked. Typing in web pages meanwhile does not keep it open.
4. Unlock. In `about:addons`, turn Ferret off and on again (this ends its background page and starts a new one). Open
   the popup.
   *Expected:* locked, asking only for the master password; unlock works. Set "Lock after" back to 15 minutes.
5. Close Firefox and start it again. Open the popup.
   *Expected:* locked.

### 7. The frame cases (Firefox, about 10 minutes)

Open each frame page on site A and open the popup there.

| Page | What it holds | Expected |
| --- | --- | --- |
| F2 | The login form in a frame of the same origin | Site A login suggested; "Fill" fills the form inside the frame, nothing outside it |
| F3 | The login form in a frame of site B (another origin of the same site) | The popup shows "Frames waiting for your permission" with "Allow". After allowing site B's host in the tab that opens, the popup offers the site B login, and "Fill" fills the frame |
| F4 | A frame with the form, made invisible by the page (opacity 0) | "The sign-in form is in a frame that is hidden or covered on this page, so Ferret did not fill it."; the frame's fields stay empty |
| F5 | A frame with the form, covered by a transparent sheet of the page | The same refusal; nothing is filled |
| F6 | The form in a `srcdoc` frame (no address of its own) | Nothing is filled into the frame ("Ferret found no sign-in field it may fill on this page.") |

### 8. Devices and revoke (both browsers, about 5 minutes)

1. In browser 2, open Account and security, Devices.
   *Expected:* this browser ("This browser"), and the extension as "App or extension" with its platform and when it was
   last seen.
2. Revoke the extension. Open the popup in Firefox.
   *Expected:* within a few seconds the popup shows "Not signed in"; its sync has stopped.
3. Sign in again in the extension.
   *Expected:* the vault is open again; the items are there.

### 9. Unlock after the session has ended (both browsers, about 5 minutes)

1. Sign in to the vault in Firefox as well (a second web vault browser). In browser 2, Devices, revoke the Firefox web vault
   row ("Browser (web vault)").
2. Reload the vault tab in Firefox.
   *Expected:* "Unlock your vault" with "Your session has ended" and only the master password field (no e-mail, no new
   sign-in). Unlock opens the vault.

### 10. Forget this server (Firefox, about 5 minutes)

1. Lock the extension. In the locked popup, press "Forget this server" and confirm.
   *Expected:* the text says what is forgotten and that nothing on the server is deleted; then "Not signed in". In browser 2,
   Devices (after "Check again") no longer lists the extension as signed in.
2. Sign in again in the extension.
   *Expected:* it counts as the first sign-in on this device: you answer the secret key question and type the key again.

### 11. The evil-server warning (Firefox, about 5 minutes)

This one ends the test account. Do it last.

1. Whoever runs the test instance stops it, empties its data volume and starts it again: a new server with a new server key
   under the same address. Make a new account there with the same e-mail address, in a fresh private window (a browser that
   has never seen the old account).
2. Open the popup in Firefox, then sign in again with the new account's master password and secret key.
   *Expected:* a warning that the server shows something other than what this device has pinned and that this can be an
   attack. Nothing is opened, and the sign-in does not go on. The other evil-server modes (an old version replayed, an item
   hidden, a rollback) are covered by the end-to-end suite and give the same warnings as in the web vault.

## The frame pages

Six static pages on site A and one on site B, with nothing but HTML (no script):

- F1: a form with a user name field (`autocomplete="username"`) and a password field (`autocomplete="current-password"`).
- F2: an `iframe` (440 by 300 pixels) of site A's own framed form page.
- F3: the same `iframe`, of site B's form page.
- F4: as F2 with `style="opacity:0"` on the `iframe`.
- F5: as F2 with an absolutely positioned `div` (almost transparent) over the `iframe`.
- F6: an `iframe` whose `srcdoc` holds the form.

The test logins: one for `https://frames.example.test/` and one for `https://login.example.test/` (exact host match, the
default), and one with a TOTP secret for a site with no page.

## Known limits

- The Firefox build uses the MV2 manifest with a persistent background page (`docs/EXTENSION-FIREFOX.md`); the MV3 build is
  built and linted but not the one shipped for Firefox.
- The shortcut and the context menu give no text when they refuse a fill; only the popup says why.
- Between the check of a frame's holder in its parent and the write in the frame there is a short window that cannot be closed
  across documents: at most one value can get through (design § 10.5).
- A middle frame of another origin needs its own host permission; without it the fill is refused.
- Two-factor sign-in is not supported in the extension or on the web vault's Unlock page yet.
- Revoking a device does not erase what it holds; a revoked web vault browser gets "Unlock" (it still needs the master password
  and the secret key it remembers).
- The CSV export does not carry folders.
