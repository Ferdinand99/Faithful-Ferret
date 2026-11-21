# Testing recovery, export and backup (the third milestone)

The third milestone makes the vault survivable: an emergency sheet with a recovery key, recovery when the master password
is forgotten, a new recovery key, a changed master password that ends other sessions, an encrypted export and an import
of other products' files, a backup the server makes by itself with an encrypted copy off the machine, and a restore that
is safe to cut off. This file lists what is tested automatically, how a person checks the rest by hand on the test
instance (about an hour and a half), and the checklist to finish before real data goes in. `docs/TESTING-M1.md` and
`docs/TESTING-M2.md` still describe the end-to-end stack and the earlier milestones' checks, and `docs/OPERATIONS.md`
describes the commands used below.

All data on the test instance is throwaway test data. Nothing here is done on a stack for real data.

## Automated tests

| What | What it checks |
| --- | --- |
| The server's Rust suite, with the matrices for the sensitive operations and the backup, and the sync matrix | Recovery and re-authentication rules, signed requests, the one-time code (including timing and throttling), sets written and checked, the restore killed after every step and run again or undone, the epoch rule, the import window, purged tombstones |
| The 10 000-item import through the real server (ignored by default, run in release mode) | Ten thousand items inside five minutes |
| The web vault's unit tests, its model-based sync matrix (5 000 strict runs at the gate) and the stored-format freeze tests | The sheet and PDF writers, recovery, password change, export and import, the tab hand-over, texts; no stored form changes without a migration |
| The end-to-end gate on a private stack, in Chromium, Firefox and WebKit: scenarios 18 to 26 for this milestone | 18 the sheet and its PDF, 19 a new browser with the sheet text, 20 a password change, 21 recovery with a one-time code, 22 a new recovery key and the backup push, 23 export and import into a wiped server, 24 foreign imports, 25 backup, wipe and restore, 26 two tabs and a restore over purged tombstones. At the end the data, the backup sets and the log are searched for the secrets of the run, with a planted control that must turn it red |
| The rehearsal on the throwaway stack (`scripts/ferret-home.sh drill`) | An account and items, a backup, the encrypted copy to a test target, decryption with a test key, an emptied volume, a restore, a sign-in again |

How the automatic tests are run is in the headers of the scripts under `scripts/` and in the two earlier testing files.
The matrix tolerates no known shape (`KNOWN_GAPS` is empty).

## Checks by hand on the test instance

**You need:** the test instance at `https://vault.example.org` (the vault) and `https://admin.example.org` (the admin
pages), running the build under test with an **empty data volume** (no account yet) and its setup token; two browsers
that have never been used with it (A and B, for example Firefox and Chromium), a third fresh profile for C; a PDF
viewer; a folder on your own disk that is **not** synced to a cloud; shell access to the host of the test stack (for
`backup list` and `sign-in-code`); and the repository checked out for the import files
(`web/test/fixtures/import/`). Use made-up names and passwords you do not mind losing, and write each one down as you
make it, because the test changes them on purpose:

* MP1 (first master password), MP2, MP3, MP4 (later ones), at least 15 characters if you turn the secret key off, 12 with it;
* the export password (EP), at least 12 characters and not equal to any master password;
* RK1 (the recovery key on the first sheet), later RK2, RK3.

`<compose>` and `<service>` are as in `docs/OPERATIONS.md`. Reload every open vault tab after a deploy: a tab loaded
before it still runs the old scripts.

### 1. The account and the emergency sheet (browser A, about 10 minutes)

1. Open the vault in A. Choose "Set up a new vault", enter the setup token, an e-mail address (`test@example.org`),
   MP1 and the same again, and leave "Use a secret key (recommended)" on. Press "Continue".
   *Expected:* after a few seconds "Your emergency sheet". Page 1 has the server address, e-mail, account id, the stretching
   profile, the secret key (`FFS1-…`), a QR code and the text under it (`ferret-setup:v1?u=…`). Page 2 has only the recovery key
   (`FFR1-…`). The page says that it is shown once, and that a new browser needs **both** pages. A short password or a
   mismatch is refused before anything happens.
2. Press "Print" (the print preview is enough).
   *Expected:* only the sheet is printed, nothing of the page around it, and page 2 is on a page of its own.
3. Press "Download PDF".
   *Expected:* a warning about synced folders first, and no file yet. "Cancel" gives no file. Press "Download PDF" again and "Save the
   file": one PDF with two pages. Page 1 holds the address, e-mail, account id, secret key, the QR code and its text and **not** the
   recovery key; page 2 holds the recovery key and **nothing** of page 1. Save it in the folder that is not synced. If you
   have a phone, read the QR code: the text it gives is the line under the QR code on page 1.
4. Under "Type the keys back", type the recovery key with one character wrong, then the secret key.
   *Expected:* refused, and nothing is created. Type both correctly: "Account created". Write RK1 and the secret key (SK) on
   a paper; they are what the next parts use.
5. Make three items: a login with a password, a note, and another login. Wait until the status says "Live".

### 2. The admin pages, the backup and "Take a backup now" (A, about 10 minutes)

1. Press "Go to the admin pages" and confirm MP1. Open Settings, Backup.
   *Expected:* the page shows the state, the last good backup, the last failure, the number of sets, the last message to
   the monitor and the next backup, and a button "Take a backup now". It shows **no** folder path, no set name and no monitor
   address.
2. Press "Take a backup now", then press it again at once.
   *Expected:* "A backup was asked for. It starts in about a minute." The second press says a backup is already running
   or about to start. After a minute or two the state is "Good", "Last good backup" has the time, "Sets kept" is at least 1, and the
   last message to the monitor is "Taken" (or "None sent yet" if no monitor is set on the test instance).
3. On the host: `<compose> run --rm --no-deps <service> backup list`.
   *Expected:* the set is listed under a time-stamped name, and `… backup verify <that set>` says it passes.
4. Open the Users page of the admin pages and look at the sign-in code feature (used in part 4). Do not make a code yet.

### 3. Master password change ends the other sessions (A and B, about 10 minutes)

1. In B, open the vault, sign in as `test@example.org` with MP1 and the secret key from page 1. Check that the three items are
   there. Also open a private window of A's browser and sign in there (a separate session).
2. In A open Account, "Master password". Type MP1 as the current password, MP2 as the new one with a mistake in the repeat.
   *Expected:* refused, nothing changed. Try the new password equal to the old one: refused. Now do it right.
   *Expected:* "Master password changed". It says that every other device and browser was signed out, that the server was asked
   for a new backup, that old exports and backups still open with the old password, and that the emergency sheet is still valid.
3. Look at B and the private window.
   *Expected:* within a few seconds both stop being live and ask you to sign in again; the status says the session ended.
   Edit an item in B before you sign in: the change is kept as unsent. Sign in in B with MP1: refused. Sign in with MP2: works, and the kept
   change is sent once.
4. On the admin Backup page, "Last good backup" is newer than before (the change asked for a backup).

### 4. Forgot the master password: a one-time code and a new browser (C, about 20 minutes)

1. Make a code for yourself: on the host `docker compose exec -u 1000:1000 <service> ferret sign-in-code issue --email
   test@example.org --yes`, or on the Users page of the admin pages.
   *Expected:* a code and the time it is good until (24 hours from now).
2. In C (a browser that has never seen the account) open the vault. Open the kit's own page for a sign-in code
   (`https://admin.example.org/sign-in-code`) once to see where it leads.
   *Expected:* it ends on the vault's recovery page (`#/recover`), and the code was **not** spent there.
3. On the recovery page, the heading is "Forgot your master password?". Fill in the e-mail address, the code, the text under the QR
   code (page 1), the secret key (page 1), RK1 (page 2) and a new master password MP3 twice. First type RK1 with one wrong character.
   *Expected:* a typing error is caught and **nothing is sent**; the code is still good. The page does not ask for the
   old master password anywhere.
4. Type RK1 correctly and press "Recover the account".
   *Expected:* the **new** recovery key (RK2) is shown alone; type it back (a wrong one is refused). Then "Account recovered":
   you are signed in with MP3, every other device and browser was signed out, the page says that your old recovery key no longer
   works, that page 1 did not change, and that the server was asked for a backup. The three items are all there.
5. In A and B: sign in with MP2: refused. With MP3: works.
6. Try the same code again in a fresh private window of C.
   *Expected:* "The code was not accepted" and nothing changed. (Every try, a good code too, counts toward five an hour from one
   network address; do not spend more tries than this on it.)
7. Make a second code on the host and then a third one for the same address.
   *Expected:* the second code is refused when you try it (a newer code replaces the older), and only the third is valid (leave it unused; step 5 makes its own).

### 5. A new recovery key, and the old one refused (C, about 10 minutes)

1. In C open Account, "Recovery key", "Make a new recovery key". Confirm MP3.
   *Expected:* a new key (RK3) is shown alone with the text that nothing changes before you type it back. Press "Do not use the new key".
   *Expected:* nothing changed; RK2 still works.
2. Do it again, type RK3 back (one wrong character is refused), and finish.
   *Expected:* "The new recovery key is in force", with the lines that the old key no longer opens the vault on this server, that your
   devices stay signed in, and that if the server is restored from a backup from before this change the old key works again and the new
   one does not, so keep the old sheet until a newer backup exists. The admin Backup page gets a newer "Last good backup" within
   a few minutes. **Write down which page 2 is the newest.**
3. Make a new code on the host. In a private window of C, recover with the **old** recovery key (RK2), a new password MP4 and the rest as before.
   *Expected:* "That recovery key does not open this account. Check it against page 2 of your newest emergency sheet. Nothing was
   changed." The page now says that a recovery session is still open (it lasts 30 minutes), so the code you already used is
   not needed again **for the same e-mail address**.
4. In the same window, recover with RK3 and MP4 (no code asked).
   *Expected:* RK4 is shown alone and typed back, "Account recovered", you are signed in with MP4. Everyone else is signed out again.

### 6. Encrypted export (fresh sign-in) (A, about 10 minutes)

1. Sign in in A with MP4 (from the new sign-in screen). Open Account, "Export".
   *Expected:* it says when your last encrypted export was (never), and an "Encrypted export" form asks for the master password again,
   although you are signed in, plus the export password twice.
2. Try an export password of 11 characters, then one equal to MP4, then two that differ.
   *Expected:* each is refused with its own message, and no file is made.
3. Use EP twice and MP4. Press "Make the encrypted file".
   *Expected:* the page says it is checking, reading, making the key (some seconds, 256 MiB of memory), sealing and handing over; then
   "The file was made" with the number of items (3), a file named `ferret-export-….ferretexport`, and that the file does not open with your master password.
   Open the file in a text editor: it is not readable text, and none of your item names is in it.
4. **See the warning for unsent changes:** turn the network off in the browser's developer tools, change an item in A, and open Export before
   it syncs. *Expected:* a warning that the file may not hold your newest changes ("1 item(s) have changes that the server has not accepted yet"), with "Export anyway" and "Check again". Turn the network on again.

### 7. Import the export into another browser, and the foreign files (C or D, about 15 minutes)

1. Sign in with MP4 in a fresh profile D. Open Account, "Import", choose the `.ferretexport`.
   *Expected:* a preview that says it is a Ferret export made on today's date and that the number of items is known once the export
   password has opened it, and a notice that your vault already holds 3 items and that Ferret does not remove duplicates.
2. Type a wrong export password.
   *Expected:* "The export password is wrong, or the file has been changed. Nothing was imported." Then the right one (EP): the import
   finishes ("The import has finished", "Items sent to the server: 3"); the list now shows each item twice with the same fields. Sync
   status "Live" in A shows them there too.
3. Import `web/test/fixtures/import/bitwarden/small.json`.
   *Expected:* the preview says "A Bitwarden export (JSON)", items 2 (1 login, 1 note), and that the file is not encrypted.
   Import it. Then `small.csv` (3 items: 2 logins, 1 note) and `aliasvault/synthetic.avux` (8 items: 6 logins, 1 note, 1 card).
   *Expected:* each shows its counts first; after each the page tells you to delete the plain file for good; the list grows by 2, 3 and 8.
4. Try `bitwarden/encrypted.json` and `aliasvault/encrypted.avex`.
   *Expected:* refused with the text that the export is encrypted and how to export it again without encryption. Nothing is
   imported. A `.zip` file is refused too.
5. Delete the plain files and the export from your disk. They hold secrets.

### 8. Two tabs with an unsaved edit (A, about 10 minutes)

1. In A, tab 1: open an item and press Edit, type something in a field, and **do not save**.
2. Open the vault in a second tab of A.
   *Expected:* "The vault is open in another tab" with "Use here" and nothing from the vault shown.
3. Press "Use here".
   *Expected:* a warning "The other tab has changes that are not saved …" with "Use here anyway". (With nothing unsaved in tab 1 there
   would be no warning.) Press "Use here anyway": tab 2 shows the vault.
4. Look at tab 1.
   *Expected:* the form you typed in is still on screen, read-only, under "The vault was moved to another tab", with "Take back".
   Nothing was saved from it.
5. Press "Take back" in tab 1.
   *Expected:* the vault is back in tab 1 and the form still has **what you typed** (it is not replaced by an empty one). Press save:
   the change is sent once, and tab 2 now shows the standby notice.

### 9. Optional, outside the hour and a half: a restore on the test instance

1. Make a set ("Take a backup now"), add one more item in A, and note its name.
2. On the host: stop the server, `<compose> run --rm --no-deps <service> backup restore --from <set path> --yes`, start the server.
   *Expected:* the command prints the new restore epoch (a large number, about the time in seconds), how many sessions it ended and the folder
   `pre-restore-…` where the old files went. A second command run while the marker `RESTORE_IN_PROGRESS` is there (cut it off on purpose
   with a kill, or start the server) refuses; `backup restore --abort --yes` puts the old files back.
3. In A: signed out. Sign in; the page says that the server was restored from an older backup and offers to accept the older state.
   *Expected:* the extra item is not on the server; accepting the older state uploads it again, as a conflict only where another device wrote
   after the restore. A one-time code made before the restore no longer works.

## Before real data goes in

The recorded decision is that real data is not stored until all of these hold. Tick each on the test instance first:

- [ ] The recovery key and an encrypted export work on a **new browser** (parts 4 to 7), and you have both pages of the sheet in different places.
- [ ] The automatic backup runs by itself (not only "Take a backup now"), a copy is **outside the machine, encrypted**, you opened it once with your
  age key, and the alert goes to the uptime monitor when the pushes stop (switch the push off once and wait for the alert).
- [ ] The proxy trust of the stack for real data is checked: no raw TCP resource and no client access to the app ports, the private resource reaches only the
  SFTP host and port, the host key was read on the target, and a forged `X-Forwarded-For` through the public address is recorded as the real address
  (`docs/OPERATIONS.md`, "The stack for real data").
- [ ] A restore was rehearsed from the encrypted copy on the throwaway stack, and the freeze tests (SQL schema and browser stored formats) are green on the release.
- [ ] The first start of the stack for real data is with an explicit yes, from a released image, by digest.

## Known limits

The limits are in `docs/design/phase-1-security-design.md` § 8.8 ("Recovery, export and backup") and § 11. The ones to expect while testing:

- Recovery on a new browser needs **both** pages of the sheet; the secret key cannot be changed. After a new recovery key the old one works only if the server is
  restored from a backup from before the renewal; keep the old sheet until a newer backup exists.
- No e-mail is sent (no notices), no account can have 2FA, and there is no full rekey. An old export or backup still opens with the old master password.
- The one-time code lives 24 hours, works once, and every try counts toward five an hour; someone who knows only the e-mail address can keep the real code waiting for an hour.
- The export password is checked for length and against the master password only. There is no recovery sheet encrypted with a passphrase.
- The PDF and plain files are plaintext on your disk; the browser's copy of the PDF cannot be cleared.
- Import removes no duplicates and leaves out passkeys, folders, tags, attachments and linked fields; Bitwarden's encrypted JSON, `.zip` exports and AliasVault's encrypted export are refused.
- An import window outlives its session: another device that tries to import may be told that an import is open for up to 30 minutes.
- Backup sets and their copies can still be deleted by the server and the copy container (no protection against ransomware here), and a restore needs the command and a stopped server.
- When the test clock is moved, a set made by `backup create` is stamped with real time and can look older than the server's own sets, so retention can treat it as the older one.
  This only matters for tests that move the clock.
- Standby tabs hold the unlocked keys like any open tab; there is no leader and follower model yet.

## Operating the test instance

The restore, bump, one-time code and backup steps are in `docs/OPERATIONS.md`. The data on the test instance is disposable and never becomes real data. Delete every file
this test made on your disk (the PDFs, the export, the foreign files you imported) when you are done.
