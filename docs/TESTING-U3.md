# Testing quick unlock (PIN and passkey) and one-time codes

This milestone added three things. In the Firefox extension, a **PIN** opens the locked vault (kept on disk by default, so it works
after a restart and without a network for seven days; five wrong tries delete it). In the web vault and in the extension, a
**passkey** opens the vault through the WebAuthn PRF extension (the passkey is made and removed in the web vault; the extension
asks for it in a small window of its own). And **one-time codes (TOTP)** for websites are stored in an item, shown by the web
vault and the extension, and filled or copied from the popup. The administrator has a page of rules for the PIN. This file lists
what is tested automatically (and which test covers which cell of the matrix), what the budgets are, what is not tested, and how a
person checks the rest by hand (about two hours). `docs/TESTING-U1.md` and `docs/TESTING-U2.md` describe the earlier
extension suites; `docs/design/phase-1-security-design.md` (sections 4.3, 4.7, 7.1 to 7.6 and 11) says what the features promise.

All data on the test instance is throwaway test data. Use made-up names, passwords and PINs only.

## Automated tests

| What | What it checks | Command |
| --- | --- | --- |
| Core (XC3) | The PIN wrap and its profile, the passkey wrap and the manifest entry, the epoch rules (`pinned_epoch_ahead` at a server unlock and at a recovery), the property tests, the test vectors natively and through WASM in Node, the constant-time harness | `scripts/lanbox.sh test -p ferret-core --locked --test pin --test props_pin --test wrap --test methods --test pinning --test account`, `scripts/lanbox-vectors.sh`, `scripts/lanbox-props.sh`, `scripts/lanbox-ct.sh` |
| The independent reference | The test vectors opened by a second implementation that shares no code with the core | the `xcheck` workflow (`tools/xcheck`, Node 24) |
| Server | The admin rule (`Allow PIN`, `Allow PIN after restart`, the shortest PIN), the passkey routes, the flag-off build | `scripts/lanbox.sh test -p ferret-server --locked` (with and without `--features quick-unlock`) |
| Extension unit tests and type check | The PIN store, the attempt counter and its waits, the PIN and passkey handlers, the popup, the settings section, the unlock window, the leak scans over every request and reply | `scripts/lanbox-ext.sh unit --wasm tree` |
| The Firefox suite (XF), Release and ESR | The PIN store over the real IndexedDB and session storage of the extension | `scripts/lanbox-ext.sh firefox --manifest mv2 --wasm tree --grep unlock` |
| The end-to-end suite (XE), Release and ESR | Specs 61 and 63 to 69 below, each channel against a stack of its own | `scripts/lanbox-ext.sh e2e --manifest mv2 --wasm tree --grep <test name>` |
| The web vault | The methods page, the passkey unlock and the one-time codes in Chromium (virtual authenticator), Firefox and WebKit where the browser allows | `scripts/lanbox-web.sh`, `scripts/lanbox-ferret-e2e-gate.sh` |

`--wasm tree` builds the WASM package from the tree. A release build never does: the signed extension and the server image use the
pinned package, or the package of their own release run.

### The end-to-end specs of the unlock

| Spec | Tests | What it shows |
| --- | --- | --- |
| `61-pin.e2e` | `a_killed_worker_during_pin_unlock_counts_one_attempt` | A PIN unlock cut short by a lock while its Argon2id runs is one attempt, no more and no fewer |
| `63-pin-unlock.e2e` | `pin_unlock_after_lock_in_release_and_esr` | The real popup: the rule is said before anything is sent, a wrong PIN counts and its wait is held, a right PIN gives the tries back, the master password is one click away, five wrong PINs delete the PIN |
| `64-prf-unlock.e2e` | `prf_unlock_after_lock_in_release_and_esr` | The passkey made in the web vault opens the extension's vault in its own window, twice; the popup itself cannot send the result |
| `65-unlock-matrix.e2e` | `the_unlock_matrix_passes_in_release_and_esr` | The cells in the matrix below that need a browser: six digits and eight characters with `æøå` (also decomposed), disk and session storage, an ended background, a restart of the browser, no network inside and after the seven days, a clock set back, a changed byte (and the counter set back to zero), an unknown profile, a later epoch, a record with an extra field, a revoked device, and a scan of the whole browser profile for the sentinel PINs |
| `66-unlock-adversarial.e2e` | `content_scripts_cannot_burn_pin_attempts`, `storage_session_is_not_readable_from_a_content_script` | A content script sends every message of the unlock (a flood of wrong PINs among them) on the runtime and on the extension pages' port: nothing is answered and the counter is untouched; it cannot see `storage.session` or the extension's databases; a copy of a PIN record that it writes to the local storage is no PIN |
| `67-unlock-settings.e2e` | `set_change_and_turn_off_a_pin_from_settings`, `the_default_pin_survives_a_browser_restart_and_the_memory_choice_does_not` | The real settings page over the real background: the dialog, a wrong master password, two PINs that differ, the acknowledgement, set, change to memory, turn off, and two restarts |
| `68-unlock-web.e2e` | `the_web_vault_unlock_methods_page_works_in_firefox`, `full_u3_flow_end_to_end` | The web vault's methods page and passkey unlock driven in Firefox (Playwright's Firefox has no virtual authenticator, so geckodriver's is used); then one account through PIN, passkey, removal of the passkey in the web vault, and the leak scan including what the passkey gives |
| `69-pin-timing.e2e` | `pin_unlock_p95_is_within_budget` | Twenty PIN unlocks: the 95th percentile on the runner is within 8 seconds; the numbers are printed as `pin-unlock-timing {...}` |

After an `e2e` run and after the e2e step of a `gate` run the script also reads the logs of every container of the stack and fails if a sentinel PIN (any text that starts with `ferret-sentinel-pin-`) is in one of them, or if it finds no container to read.

### The matrix, cell by cell

| Axis | Values | Covered by |
| --- | --- | --- |
| PIN | four digits (the lowest the rule allows) | The core refuses a PIN below four characters before any key stretching (`pin` tests); the extension's rule check (`pinBackground.test.mjs`); the server's rule bounds (4 to 64) |
| | six digits | `65-unlock-matrix`, `63-pin-unlock`, `67-unlock-settings` |
| | eight characters with `æøå` | `65-unlock-matrix` (also typed in the decomposed Unicode form, which the core normalizes) |
| Place | disk (the default) | `65-unlock-matrix`, `67-unlock-settings`, `61-unlock-store.spec` |
| | `storage.session` (the choice, or the administrator turned off "after restart") | `65-unlock-matrix`, `67-unlock-settings`, `pinBackground.test.mjs` (a stricter rule deletes a disk PIN at the next contact) |
| Event | right and wrong tries, the waits (0, 0, 5, 15, 30 s), the fifth wrong try | `63-pin-unlock` (real time), `pinAttempts.test.mjs` |
| | a killed worker, a cut fifth try | `61-pin`, `pinAttempts.test.mjs` |
| | out of memory | `pinBackground.test.mjs` (an out-of-memory answer counts as a try and says that the device had too little memory, not that the PIN is wrong) |
| | restart of the browser | `65-unlock-matrix`, `67-unlock-settings` |
| | restart of the background | `65-unlock-matrix` |
| | update of the extension (the memory PIN goes, as expected) | By design: the session storage ends with the extension's instance; checked by hand below |
| Network and time | on line | everywhere |
| | no network inside seven days, and after them | `65-unlock-matrix` (the server is made unreachable through a proxy that nothing listens on; the browser's own offline switch also stops workers from starting), `pinAttempts.test.mjs` |
| | the clock set back | `65-unlock-matrix`, `pinAttempts.test.mjs` |
| Revocation | switch the PIN off, sign out (also with no network), forget the server | `pinBackground.test.mjs`, `67-unlock-settings` |
| | a revoked device | `65-unlock-matrix` |
| | master password changed on another device, recovery | The tokens end and the PIN goes (`pinBackground.test.mjs`); the core test of each flow |
| | restore epoch (a restore of the server) | A restore does not end the tokens by itself. The PIN goes when the restore took unlock methods back: the floor check refuses (`pinned_kek_generation`) and any refusal after an unlock deletes the PIN. If the restore changed none, the PIN rightly stays. Core tests and `pinBackground.test.mjs` |
| | a stricter rule, "Allow PIN" off, "Allow PIN after restart" off, an unknown profile | `pinBackground.test.mjs`, `65-unlock-matrix` (unknown profile), the server's rule tests |
| | a swapped blob (another vault key) | `pinBackground.test.mjs` (`pinned_auth_key` deletes the PIN); the core refuses a vault key that does not give the pinned `pk_a` |
| Passkey | the virtual authenticator | `64-prf-unlock`, `68-unlock-web`, `30-unlock-passkey` (web vault, Chromium) |
| | Windows Hello, a phone through a QR code, Touch ID on a Mac | By hand below |
| | a YubiKey or another security key | Not tested by hand |
| Web vault | passkey with a living session | `68-unlock-web`, `30-unlock-passkey` |
| | an expired session asks for the master password | `30-unlock-passkey` (`68-unlock-web` shows only a living session, a reload and a lock) |
| | a method removed on another device | `68-unlock-web` (`full_u3_flow_end_to_end`) |
| | "synced" or "this device only" | `29-unlock-methods`; by hand below |
| Attack | a content script sends PIN or passkey messages | `66-unlock-adversarial`, `sender.test.mjs`, `router.test.mjs` |
| | a framed extension page | `70-phishing` (no extension page loads in a frame of a web page), `sender.test.mjs` |
| | a tampered record (a byte, the profile, the epoch, an extra field, the counter set to zero) | `65-unlock-matrix`, `localUnlock.test.mjs`. A changed byte counts as a wrong PIN; the profile, the epoch and an extra field delete the PIN. The counter lies in the record in the clear, so whoever can write the profile can set it to zero: that is an accepted limit (see below), and the spec shows it |
| | `storage.session` read from a content script | `66-unlock-adversarial` |
| | a flood of tries | `66-unlock-adversarial`, `pinAttempts.test.mjs` |
| Leak | a sentinel PIN or passkey output in storage, messages, `console`, the network, the browser profile, the stack's logs | The browser profile: `65-unlock-matrix` (PINs) and `68-unlock-web` (the PIN and the passkey's output). The stack's logs: the `e2e` and `gate` runs of `scripts/lanbox-ext.sh` (the PIN prefix only, and a scan that reads no container fails). Messages, `console`, requests and storage: the leak scans of `pinBackground.test.mjs`, `pinUnlockPopup.test.mjs`, `prfUnlock.test.mjs` and `web/test/unit` |
| Time and memory | the PIN unlock within 3 seconds on a developer machine and 8 on the weak reference | `69-pin-timing` (the reference); by hand below (the developer machine) |
| | the worker ends when the vault locks | `pinBackground.test.mjs`, `61-pin` |

## Budgets and what they rest on

- **PIN unlock time.** 8 seconds at the 95th percentile on the test runner (two CPUs, a few GiB; Firefox with its sandboxes off),
  checked by `69-pin-timing`; 3 seconds at the 95th percentile on a current developer machine, measured by hand (check 8 below).
  The PIN profile (256 MiB, three passes, one lane) was chosen as the strongest that fits both.
- **Memory.** The PIN's Argon2id grows the vault's worker by the size of its memory, and WebAssembly memory is never given back.
  After a try that did not open the vault the extension ends that worker; a lock ends it too.
- **What a stolen profile allows.** The PIN on disk is a record in the profile. A copy of the profile lets a person try PINs on
  their own computer, where the limit of five tries does not apply. The administrator's page of rules says how long one powerful
  computer needs for every PIN of the shortest allowed length. A passkey that can be synced is as safe as the cloud account it
  lives in.

## Not tested, and known limits

- **A YubiKey or another security key** was not tested by hand. The extension and the web vault ask for the PRF extension
  and say so when a key does not give it.
- **Chromium** is not a target of the extension; the web vault's passkey specs run in Chromium only because that is where
  Playwright has a virtual authenticator.
- **Secure delete.** Firefox's IndexedDB does not securely delete: a deleted PIN record can stay in free pages of the database file
  for a while. The extension overwrites the record before it deletes it, which one Firefox keeps and one does not. Do not read a
  wipe as proof that the bytes are gone from the disk.
- **The clock.** The seven days and the guard against a clock set back use the device's own clock. Whoever controls it can keep an
  offline PIN usable for as long as they hold it still.
- **Another password manager** that takes over the browser's passkeys can answer the passkey call instead of the browser. The unlock
  window says what to check when the browser refuses at once (check 6 below).
- **The network and `console` are not captured in the browser.** geckodriver has no HAR. The PIN and the passkey's output are never sent to the server by design, and the unit leak scans read every request, reply, `console` call and storage write. The stack-log scan looks for the sentinel PIN, not for the passkey's output.
- **Memory growth of the vault's worker** was measured once, in the PIN probe, not in every run. That the worker ends when the vault locks is shown by the unit tests, and the end-to-end specs read that the vault is locked.
- **The try counter** is in the PIN record in the clear and outside what the wrap is bound to. Anyone who can write the browser profile can set it back to zero; the limit of five tries holds against everyone who cannot, and a copy of the profile is attacked offline anyway.
- **The end-to-end specs run on the MV2 build** (the Firefox build). A Chrome build on MV3 needs `65` and `66` run again, because the access level of `storage.session` and the sender rules differ there.
- **Playwright's Firefox** cannot drive a virtual authenticator, so the web vault's own specs cover passkeys in Chromium. The
  Firefox side of the same page is driven through geckodriver by `68-unlock-web`.
- **The unbranded Release build of Firefox that the runner uses expires** (`extension/test/firefox/README.md`).

## Checks by hand on a test instance

**You need:**

- a test instance of the server built from the commit under test, with `quick-unlock` on, behind your reverse proxy at
  `https://vault.example.test` (the vault) and `https://admin.example.test` (the admin pages). The names are placeholders; use
  your own, and give the extension access to `/api/*` as in `docs/TESTING-U1.md`;
- an account made on it, with its secret key, and an item with a made-up login for a test page and a made-up one-time code
  secret (an `otpauth://totp/...` address or a Base32 secret);
- the signed release build of the extension (or the test build from the gate), Firefox 153 or newer;
- a Windows computer with Windows Hello set up (Settings, Accounts, Sign-in options), a Mac with Touch ID and a passkey provider
  turned on (System Settings, General, AutoFill & Passwords, for example the Passwords app), and a phone with a screen lock;
- a second Firefox profile or computer, for the "other device" checks;
- a stopwatch.

Reload every open vault tab after a deploy.

### 1. The administrator's rules (about 10 minutes)

1. In the admin pages open Settings, Unlock.
   *Expected:* three settings (Allow PIN, Allow PIN after restart, the shortest PIN: 6 by default, 4 to 64) and a text that says
   in plain words how long one powerful computer needs for every PIN of the shortest length, and that a PIN is kept on disk
   by default.
2. Set the shortest PIN to 8 and save.
   *Expected:* the page says that this deletes shorter PINs on the devices at their next contact, and saves nothing yet; the same
   form sent again with the confirmation saves. Set it back to 6.

### 2. A PIN in the extension (Firefox, about 25 minutes)

1. Open the extension's settings (the popup's Settings, or about:addons, Ferret, Preferences). In the Unlock part press "Turn on PIN".
   *Expected:* a dialog with the master password, the PIN twice, "Require master password after browser restart" **off**, and
   a warning about the PIN being kept on this computer with "I understand" **not ticked**.
2. Type a wrong master password and a PIN of six digits.
   *Expected:* a refusal that names the master password; nothing was set.
3. Without ticking "I understand", enter the right master password and the PIN.
   *Expected:* the dialog asks you to tick it. Tick it and continue: "PIN is on." and a line that says it works after a restart.
4. Lock the extension. Open the popup.
   *Expected:* the PIN field has the focus; "Use master password instead" is one click away. A PIN shorter than the rule is not
   sent and costs nothing.
5. Type a wrong PIN.
   *Expected:* "That PIN is not right. 4 tries left before the PIN is deleted." Wrong again: a wait of 5 seconds is shown; Enter
   does nothing during it.
6. Type the right PIN.
   *Expected:* the vault opens, and the next lock shows 5 tries again.
7. Lock. Close Firefox completely and start it again. Open the popup.
   *Expected:* the vault is locked, and the PIN still opens it (it is on disk).
8. Settings, "Change PIN", choose "Require master password after browser restart", enter a PIN made of letters with `æøå`
   and confirm with the master password. Lock, and unlock with the new PIN. Close Firefox, start it again.
   *Expected:* the PIN works before the restart; after it the popup offers only the master password, and the settings say
   no PIN is set.
9. Set a PIN again. Lock. Type five wrong PINs, waiting out the waits.
   *Expected:* the fifth leaves the master password's form with the reason in it, and the popup offers no PIN.
10. Set a PIN again. Switch the computer's network off (not the extension's server alone). Lock and unlock with the PIN.
    *Expected:* it opens the vault. Switch the network on again.
11. In the web vault, Devices, revoke the extension. In the extension, unlock with the PIN.
    *Expected:* the PIN is deleted and the popup says the device is signed out.
12. Update the extension to a newer build if you have one (or, with the test build loaded as a temporary add-on, reload it in about:debugging) with a memory-only PIN set.
    *Expected:* the memory PIN is gone after the update (by design); a disk PIN stays.
13. With a PIN set on a device, turn "Allow PIN" off in the admin pages (check 1), and let the device sync.
    *Expected:* the device deletes its PIN at its next contact and the settings say the administrator turned PIN off.

### 3. A passkey in the web vault (about 15 minutes)

1. Account menu, Unlock methods, "Add a passkey". Enter a name, the master password, and follow the browser's prompts; use the
   passkey once more when asked.
   *Expected:* "“name” can now unlock your vault" with "Synced passkey" or "This device only", and a date.
2. Reload the vault tab.
   *Expected:* "Unlock your vault" with "Unlock with a passkey" and the master password. The passkey opens the vault with no
   password sign-in. Lock again from the account menu: the same.
3. Remove the passkey, asking for the master password again.
   *Expected:* "was removed", with a line that says to delete the passkey from the provider too; the unlock page offers none.

### 4. A passkey in the extension (about 10 minutes)

1. With a passkey made as in check 3, lock the extension and open the popup.
   *Expected:* "Unlock with a passkey" beside the PIN and the master password.
2. Press it.
   *Expected:* a small window of its own (never the popup itself, which closes when the system dialog takes the focus); one press
   makes the one browser prompt; the vault opens and the window closes.
3. Remove the passkey in the web vault and lock the extension.
   *Expected:* the popup no longer offers it, and the PIN and the master password still work.

### 5. Windows Hello, a phone through a QR code, Touch ID (about 30 minutes)

Do check 3 and check 4 once with each of these as the passkey, on the matching computer:

1. **Windows Hello** (Windows computer): make the passkey with Windows Hello, then unlock in the web vault and in the extension.
   *Expected:* both work; the list says "This device only".
2. **A phone through a QR code**: choose "use a phone or tablet", scan the code, confirm on the phone; then unlock.
   *Expected:* both work (the phone has to be near the computer for each use).
3. **Touch ID on a Mac**: make the passkey with Touch ID (through the passkey provider you turned on), then unlock in the web vault
   and in the extension.
   *Expected:* both work; the list says "Synced passkey" if the provider syncs it. After Firefox is restarted the same passkey
   still opens the vault.

If the browser refuses at once, before it has asked anything, the unlock window lists the usual causes: another password manager that took
the passkeys over, no passkey provider on the Mac, and Windows Hello not set up. Fix one and try again.

### 6. Another password manager in the way (about 10 minutes)

1. Turn on the passkey support of another password manager's browser extension, then try check 3, step 1.
   *Expected:* the other manager may offer to take the passkey, or answer the browser's call itself. Choose this browser or the
   system when it asks where to save the passkey. A passkey kept by a manager that does not give the PRF output is not added: the
   page says that nothing was added to the vault and that the passkey that was made is still in the provider, to be deleted there.
2. Turn the other manager's support off for this site and repeat.

### 7. Two passkeys, one on another device (about 10 minutes)

1. Make a passkey on this computer, and make another on the other device (a second computer, or the phone).
2. In the extension, press "Unlock with a passkey".
   *Expected:* the browser's prompt lists both or asks for the right one. Choose the one on this computer: it opens the vault. When the
   key that answers is the one on the other device, the unlock may fail at once with a refusal ("not allowed"): that is the
   browser's answer when it cannot reach a key, and the master password and the PIN still work.
3. Remove one of the passkeys in the web vault, then unlock with the other.
   *Expected:* the removed one stops working at the next unlock; the other opens the vault.

### 8. How long a PIN takes on your computer (about 5 minutes)

1. With a PIN set, lock and unlock with it ten times, timing from the press to the open vault. Do not count the first press after
   starting Firefox.
   *Expected:* the slowest of ten is within 3 seconds on a current developer computer (it is the 95th percentile that counts; ten
   tries are enough to see a problem).

### 9. Firefox and the one-time code's secret (about 5 minutes)

1. In the web vault open an item with a one-time code and press Edit. Look at the one-time password field and its "Show" button.
   *Expected:* the field does not show the stored secret (it says to leave it empty to keep it).
2. Type a new made-up secret in that field and press Save.
   *Expected:* Firefox does **not** offer to save a password for the site, and does not fill that field with a saved password at the
   next edit. If Firefox offers it, note which field it took and the Firefox version.

### 10. The combined smoke test of the extension (U2, U3 and the codes; about 25 minutes)

1. Sign in to the extension on a fresh profile (check 3 of `docs/TESTING-U1.md`). Set a PIN on disk (check 2, steps 1 to 3) and a
   passkey (check 3).
2. Open a made-up login page of a test site that has a form and a one-time code field. Open the popup, fill the login (U1), and
   fill the one-time code ("Fill the code") or copy it ("Copy one-time code").
   *Expected:* the code has six digits and matches an authenticator that holds the same secret; the clipboard is cleared after
   30 seconds; a code is not filled into a page that is not encrypted.
3. On the same site submit a login that is not in the vault, with a made-up user name and password.
   *Expected:* the extension offers to save it ("Save"); saving it makes an item that the web vault shows within seconds.
4. Open the popup's Generator tab. Make a password, and on a registration page use "Fill in the page".
   *Expected:* the page's new-password fields get a password that is not in the vault and fits the page's stated rules.
5. Lock the extension and unlock it with the PIN, then lock and unlock it with the passkey (the window), then lock and unlock with the
   master password.
   *Expected:* each one opens the vault, and the items, the saved login and the code are all there.
6. Press "Lock" and close Firefox; start it again and unlock with the PIN.
   *Expected:* the vault opens; the saved login, the generated password and the code are still there after a sync.
7. In the web vault, change the master password, then look at the extension.
   *Expected:* the extension is signed out (every device ends), the PIN is gone, and a new sign-in is needed.

## Results of a gate run

Keep these lines with the release notes of the run:

| Check | Date | Who | Result |
| --- | --- | --- | --- |
| XC3 (core, vectors, props, constant-time) |  |  |  |
| XU, Release and ESR |  |  |  |
| XE, specs 61 and 63 to 69, Release and ESR |  |  |  |
| `pin-unlock-timing` p95 on the runner (Release, ESR) |  |  |  |
| Web vault suites |  |  |  |
| Check 5, Windows Hello |  |  |  |
| Check 5, a phone through a QR code |  |  |  |
| Check 5, Touch ID on a Mac |  |  |  |
| Check 7, two passkeys |  |  |  |
| Check 8, the PIN time on a developer computer |  |  |  |
| Check 9, no offer to save the code's secret |  |  |  |
| Check 10, the combined smoke test |  |  |  |
