<p align="center">
  <img src="assets/brand/ferret-icon.png" alt="Faithful Ferret" width="160">
</p>

<h1 align="center">Faithful Ferret</h1>

<p align="center"><strong>A self-hosted, zero-knowledge password manager. Your vault is encrypted on your own devices, and your server only stores ciphertext.</strong></p>

<p align="center">
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-AGPL--3.0-blue.svg" alt="License: AGPL-3.0"></a>
  <img src="https://img.shields.io/badge/status-in%20development-59d9c7.svg" alt="Status: in development">
  <a href="https://hedgerow.tools/Faithful-Ferret/"><img src="https://img.shields.io/badge/website-hedgerow.tools%2FFaithful--Ferret-black.svg" alt="Website"></a>
</p>

> **Status: in development, pre-1.0 (v0.9.0).** The cryptographic core, the OPAQUE server library, the server and the
> web vault work end to end in testing. Safe sync between devices and browser tabs came in v0.3.0, and v0.5.0 added
> recovery with a printed emergency sheet, an encrypted export, import from other password managers, and automatic
> backups with an encrypted copy off the machine. v0.6.0 added devices: clients other than the web vault sign in with
> tokens that are bound to a key on the device, and there is a device list with revoke in the web vault. v0.7.0 brought
> the first Firefox extension, a new web vault layout with folders, and unlock with the master password after the
> session has ended (see [What works today](#what-works-today)). v0.8.0 added a password generator, a comparison of a
> stored field with a given value, and password history to the core. v0.9.0 shows the previous passwords of an item in
> the web vault, makes the side menu's "Import and export" reach both pages, and teaches the Firefox extension to
> work out what a form is for before it fills. No screen uses the generator or the field comparison yet. The extension
> fills logins from its popup but cannot save new passwords yet (that is coming), and it is not on the Firefox add-ons
> store. Saving passwords and the password generator in the extension are in progress, then a health check. Ferret is a
> single-author project and is **not for real passwords yet**. There is no external audit, and none is planned.

Faithful Ferret ("Ferret") is a password manager you host yourself, planned as part of
[Hedgerow](https://hedgerow.tools/), a family of small self-hosted apps. It is built around one rule: the server
must not be able to read your vault. Everything is encrypted and decrypted on your own devices, and the server,
its admin panel and its API only ever see ciphertext.

## What works today

These are in v0.9.0 and are tested on a test instance. All of it is pre-1.0, and none of it has had an external review.

- **Web vault and sync.** Set up an account, sign in, unlock, and view and edit items in the browser. Changes sync
  between devices and browser tabs. If two devices change the same item, both versions are kept side by side and
  nothing is overwritten silently.
- **Emergency sheet and recovery.** Setup produces a printable sheet in two pages: page 1 has the server address,
  account details, the secret key and a QR code, and page 2 has only the recovery key. If the master password is
  forgotten, a new browser can recover the account with the recovery key and both pages of the sheet. Recovery makes
  a new recovery key, and the old one stops working on that server. A new recovery key can also be made at any time.
- **Master password change.** One write path changes the master password and ends every other session.
- **One-time sign-in code.** An administrator can issue a code that is good once, for 24 hours. It resets a sign-in
  only. It never opens a vault, and recovery still needs the recovery key and the sheet.
- **Encrypted export.** Signing in again is required, and the file is encrypted with a separate export password, so
  it does not open with the master password. For moving to another service, the web vault can also export plain
  CSV or JSON. That file is not encrypted, and it needs the master password again and two separate confirmations.
- **Import.** From Ferret exports, from Bitwarden (unencrypted JSON and CSV) and from AliasVault (unencrypted `.avux`
  and CSV). Duplicates are not removed. Folders and collections become folders, and passkeys, tags and attachments are not imported.
  The file is chosen with a button or dropped on the import page, and it is read on the device and not uploaded.
- **Tabs.** The vault runs in one tab per browser and account. Moving it to another tab keeps unsaved edits in the
  first tab instead of dropping them.
- **Backups.** The server writes a checked backup set every 24 hours and after every change to the unlock methods.
  The admin pages show the state and have "Take a backup now". An optional second container encrypts each set with
  `age` to a public key you own and copies it to an SFTP target, then reads it back to check it. A set is restored
  with `ferret backup restore`, which is safe to cut off and run again. A restore ends every session and raises
  the restore epoch so that devices notice an older state.
- **Devices and bound tokens.** A client that is not the web vault, such as the Firefox extension, signs in
  as a device: it makes its own key, signs in with the master password, and gets an access token and a refresh token
  that only that key can use. Every request carries a proof of that key (DPoP, RFC 9449, ES256). An access token
  lives 15 minutes, a refresh token is used once and replaced at every renewal, and using an old one after a short grace
  period revokes the device. An account can have 20 devices with tokens. The web vault is not a device and keeps its cookie session.
  The Firefox extension is the first client that signs in this way.
- **Device list and revoke.** The Devices page of the web vault lists the devices with tokens and the browsers that
  are signed in, with name, platform and last seen. You can revoke one device, revoke every device and every other
  session (this asks for the master password again), or forget the devices not seen for 7 days. Revoking makes the
  tokens invalid at once and closes the device's live event stream. A change of master password, a recovery, a
  redeemed sign-in code and a restore sign every device out. The database holds only token hashes, never a token.
- **New web vault layout.** The web vault has a side menu (all items, favourites, folders, trash, import and export,
  and pinned folders), an account menu with a light, dark or system theme, and a drawer on a phone. The item list has
  search, filter chips, sortable columns, bulk actions (favourite, move to the trash), a row menu with Move to folder, and an item
  opens in its own view with an edit form. The generator and the health check are in the menu as "Coming soon". The
  menu entry "Import and export" opens a page that leads to both the import page and the export page.
- **Previous passwords.** When the password of an item is changed in the web vault, the old one is kept in the item
  (encrypted with it) and listed under "Previous passwords" on the item page, newest first, with the date each one was
  replaced. An item keeps up to five. Each value is hidden until you ask for that one, and only one secret on the page
  is shown at a time. An item that has no earlier password has no such list, and passwords changed before v0.9.0 were
  not kept.
- **Credits.** The account page has a Credits section that names the EFF large word list, used under CC BY 3.0 US, for
  the passphrase generator in the core.
- **Folders.** A folder is a label inside each item, encrypted with it, so the server never sees a name. An item can be
  in up to 20 folders (names of 1 to 64 characters). The web vault can put items in folders, and rename, merge, delete
  and pin folders to the menu. Import from Bitwarden and AliasVault turns folders and collections into folders.
- **Unlock after the session has ended.** When the server session has ended but the browser still remembers the
  account, the web vault shows the remembered e-mail and asks only for the master password instead of a full sign-in form.
  If the account has a secret key that this device does not keep, the full sign-in page is shown. The same checks of
  the server run as at any sign-in.
- **Firefox extension.** See [below](#firefox-extension).
- **Generator, field comparison and password history, in the core.** v0.8.0 added these to the shared Rust core and
  its WebAssembly package. They are tested with unit tests and the shared test vectors. The web vault shows the
  password history (see above) since v0.9.0, but **no screen of the web vault or the extension uses the generator or
  the field comparison yet**, so you cannot generate a password there.
  - *Generator.* A password of 4 to 128 characters from the lower-case letters, upper-case letters, digits and the
    symbols `!#$%&*+-.:=?@^_~` that you choose, with 0 to 8 characters required from each chosen class and an option
    to leave out the look-alike characters `Il1|O0o`. Or a passphrase of 3 to 20 words from the
    [EFF large word list](https://www.eff.org/dice) (7,776 words, CC BY 3.0 US, noted in
    [THIRD-PARTY-NOTICES](THIRD-PARTY-NOTICES)) with `-`, `.`, `_` or a space between them, optional capital first letters
    and an optional digit added to one random word. Every choice is a uniform draw from the operating system's random source, and the result
    comes with an entropy estimate for display.
  - *Field comparison.* The core can tell whether a field of an open item holds exactly a given text, such as the
    password a page sent. The values are compared with a constant-time comparison inside the WebAssembly module (the length is not
    hidden), and the answer is only yes or no; the field is not sent back.
  - *Password history.* An item can keep up to five earlier passwords, newest first with the time each one stopped
    being the password, inside its encrypted body. They are kept only when an edit asks for it, which the web vault's
    edit form does when a new password is typed. The interface gets the dates only, and a value is returned only when
    the user asks for that one.
- **Deployment.** The stack for real data publishes its two ports on the loopback address only and trusts exactly one
  proxy. Server images are built for amd64 and arm64 and signed with cosign, and the deploy script verifies the
  signature before it runs an image. The admin address is the entry point to the admin pages.

### Firefox extension

The first version of the Firefox extension came in v0.7.0. It needs Firefox 153 or newer and is early: it fills logins
from its popup, but it cannot save new passwords, make passwords or handle passkeys yet. It is **not on the Firefox
add-ons store**. A build that Mozilla has signed as an unlisted add-on is made by a manually started workflow, and the
release downloads of v0.9.0 do not include it; the signed builds are on their own releases, named `extension-v` and the
version. [`docs/EXTENSION-FIREFOX.md`](docs/EXTENSION-FIREFOX.md) describes how that build is made, and
[`docs/TESTING-U1.md`](docs/TESTING-U1.md) lists the checks.

- **Sign-in and unlock.** You sign in once, in a tab, with the address of your server (https only), your e-mail, the
  master password and, if the account has one, the secret key. Pasting the text of the emergency sheet's QR code lets
  the extension check your server before it signs in. After that the vault is unlocked with the master password
  alone; only a secret key that you chose not to keep on the device is asked for again. An account with two-factor
  sign-in cannot sign in yet.
- **Live sync.** The extension is a device with tokens bound to a key. It keeps the vault in step with the server, and
  an item changed in the web vault shows up in the popup.
- **Suggestions and fill.** The popup lists the items that match the current page first, and has search and a type
  filter for the whole vault. "Fill" puts the login into the page, and a value goes straight from the vault to the
  frame, never through the popup. The shortcut Alt+Shift+L (Firefox lets you change it) and the context menu entry
  "Fill with Ferret" do the same.
- **Copy.** Copy the user name, e-mail or password from a row, and a one-time code from the item's view. Ferret clears
  the clipboard 30 seconds after its last copy.
- **Auto-lock.** The vault locks after 15 seconds to 24 hours without use of Ferret's own pages (15 minutes by
  default). Activity in a web page does not count, and the vault also locks when the browser closes.
- **Frame and phishing rules.** The extension fills only a frame that matches the item's saved address and that is
  shown on the page. A frame that its page hides or covers is refused, and so is a field that is covered. On a page that
  only looks like a saved site, nothing is suggested or filled; an item found by search there can be copied but never
  filled. A form in a frame inside another frame that the extension has no access to cannot be checked, so it is not
  filled either.
- **Form detection.** Before it fills, the extension works out what the form is for, from the `autocomplete` hints of
  the fields and from their names, labels and placeholders in English, Norwegian, German, French and Dutch. A sign-in
  form gets the user name, the password and, if the item has a one-time code, the code. A form for changing a password
  gets the user name and the password in use, never the new one. A user name step gets the user name, and a page that
  asks only for a one-time code gets the code. A sign-up or password reset form, a card form and a PIN field get
  nothing: a stored password never goes into a field that sets a new password, a card's security code, a PIN or a
  one-time code, even when the page makes that field a password field.
- **Automatic updates.** A signed release build from version 0.7.1 on carries the address of an update list, and
  Firefox installs a newer signed version that the list names, without the add-ons store. Builds before 0.7.1 never
  update themselves; version 0.7.1 is installed by hand once.
- **Forget this server.** The extension can forget a server: it revokes its device and removes what it keeps locally.
- **A lying server.** The extension pins the server's identity, your account and the unlock methods. If a server later
  shows something else, the sign-in stops with a warning, as in the web vault. The first sign-in without the sheet's QR
  text trusts the server on first use.

How to run and operate a server is in [`docs/OPERATIONS.md`](docs/OPERATIONS.md), and the hand test for recovery, export and
backup, which has to pass before real data goes in, is in [`docs/TESTING-M3.md`](docs/TESTING-M3.md).

## Why

Ferret aims to be a password manager that is light to run and gets the everyday details right:

- **Autofill that notices.** Reliable detection of new and changed passwords, tested against a matrix of real
  sites before release.
- **Unlock the way you want.** Biometric unlock and an optional local PIN, including in the desktop browser
  extension. Ferret never collects or stores biometric data; the operating system confirms it is you.
- **Small to run.** One container with SQLite and a Rust core, like the other Hedgerow apps, and an extension that
  stays light on memory. Resource budgets will be measured, not promised.

## Planned for 1.0

Version 1.0 will not be released until all of this works and the security checks are done.

| Vault | Everywhere you use it |
|---|---|
| Generate, save and autofill passwords, with reliable detection of new and changed ones | Full web vault: unlock, view and edit in the browser |
| Passkeys as a full provider: create them, use them to sign in to websites, and sync them between devices | Browser extension for Firefox and Chromium (Chrome, Edge, Brave) on Windows and macOS |
| One-time codes (TOTP), stored encrypted next to the login | iOS app with AutoFill, passkeys and Face ID or Touch ID |
| Master password with an optional secret key; biometric or PIN unlock on a device you have set up | Android app, installed as an APK from the GitHub releases and updated from inside the app (not on Google Play) |
| Sync between devices with explicit conflict handling, never a silent overwrite | Import from AliasVault and from Bitwarden or Vaultwarden |
| Recovery key and an encrypted export that you keep | Self-hosting in one container with SQLite, for Docker and Unraid (planned) |

**Later, after 1.0:** secure notes and payment cards as their own item types, files and attachments, an SSH agent,
Wi-Fi and custom item types, sharing, and e-mail aliases as an optional add-on. The core never depends on e-mail.

## Security approach

Security is the top priority of the project, and this is how the design handles it:

- **Zero-knowledge.** The vault is encrypted and decrypted only on your devices. A valid server session does not
  unlock the vault, and nothing on the server, including administration, can decrypt it. The web vault is the
  exception to trust: it trusts the server that delivers its code, so a malicious operator could serve a tampered
  page. The browser extension (Firefox, first version) and, later, the apps are the real protection against that (see
  [Honest limits](#honest-limits)).
- **Master password and an optional secret key.** The master password unlocks the vault on a new device. A
  separate secret key can be added to protect against offline guessing if someone copies the server's database.
- **Recovery you control.** Recovery uses a recovery key on an emergency sheet and an encrypted export that you keep.
  There is **no admin recovery** of vaults: if the master password, the recovery key and every export are lost,
  nobody can open the vault. Administrators can reset a login with a one-time code, which never opens the vault.
- **Open design.** The threat model and the cryptographic design are published in
  [`docs/design/phase-1-security-design.md`](docs/design/phase-1-security-design.md).
  [`docs/REVIEW-PACKAGE.md`](docs/REVIEW-PACKAGE.md) is a guide to the code that implements it.
- **Established cryptography only.** Well-known algorithms and reviewed libraries; no home-made cryptography.
- **Internal review and testing.** A review and testing programme, including test vectors and fuzzing for the
  cryptographic core.

### Honest limits

- **There is no external audit, and none is planned or funded.** Ferret is a small open source project and has
  not been independently audited by anyone. Making the design and code public is how others can check it, and
  [`docs/REVIEW-PACKAGE.md`](docs/REVIEW-PACKAGE.md) is a scoped starting point for anyone who wants to review the
  cryptographic core.
- **The web vault trusts the server that serves it.** A compromised server could serve a tampered web page. The
  server always serves the web vault, and there is no switch to turn it off. If you do not want to trust the server
  that delivers the code, use the browser extension (Firefox, first version) and, later, the apps.
- **A compromised device is out of reach.** Malware on a device that has the vault unlocked can read what you can
  read.
- **Zero-knowledge has a price.** If every unlock and recovery method is lost, the data cannot be recovered.
- **The extension is early.** It is a first version for Firefox only, outside the add-ons store, and it cannot save new
  passwords yet. It has had no external review either.
- **Recovery has limits in this version.** A new browser needs both pages of the sheet, and the secret key cannot be
  changed. After a new recovery key, the old one works again only if the server is restored from a backup made before
  the renewal. An export or backup made before a master password change still opens with the old password. The
  server sends no e-mail, accounts have no second factor yet, and there is no full rekey.
- **Backups need care from the operator.** A backup set together with its secret files lets whoever takes the
  machine guess master passwords, one Argon2id per try (the secret key stops that), so copies off the machine are
  always encrypted. The server and the copy container can still delete their own sets and copies, so snapshots on the
  target are for the operator to add. A restore needs the command and a stopped server.
- **Real data is not ready.** The operations guide lists checks, such as a rehearsed restore and a verified proxy
  setup, that are to be done on a test instance before real data goes in.

## Repository layout

The Rust cryptographic core lives at the repository root as a Cargo workspace:

- `crates/ferret-core/`: the cryptographic core (safe Rust, no I/O).
- `crates/ferret-server-auth/`, `crates/ferret-server/`: the OPAQUE server library and the server.
- `bindings/wasm/`: the WebAssembly binding for the web vault and the browser extension.
- `web/`: the web vault.
- `tools/vectorgen/`: generates and checks the test vectors.
- `vectors/`: the cross-platform test vectors that every client must pass.
- `ct/`: the small single-file constant-time code (Crockford coding) that the core includes and the constant-time analyzer reads.
- `docker/`, `scripts/`: the images, compose files and scripts for building, testing and running the server.
- `fuzz/`: the fuzz targets, their seed corpus and the inputs of fixed crashes.
- `supply-chain/`, `deny.toml`: the dependency audits and policy (`cargo vet`, `cargo deny`).
- `docs/`: the [review package](docs/REVIEW-PACKAGE.md), the [results of phase 4A](docs/PHASE-4A-REPORT.md), the
  [wrap formats](docs/WRAP-AAD.md), [how a release is made](docs/RELEASING.md), [how to operate a server](docs/OPERATIONS.md)
  and the hand tests ([sync](docs/TESTING-M2.md) and [recovery, export and backup](docs/TESTING-M3.md)).
- `site/`, `assets/`: the website and brand assets.

This project has had no external security audit, and none is planned.

## Roadmap

The steps are the order of work, not cuts in scope, and there are no dates:

1. Design, throwaway prototypes and the security design (done).
2. The server and the shared Rust cryptographic core (first version done).
3. The web vault (first version done, work continues).
4. Safe sync, recovery and daily use. Safe sync is done (v0.3.0). Recovery with the emergency sheet, master password
   change, encrypted export, import and backups are done (v0.5.0). Devices with tokens bound to a device key, and a
   device list with revoke, are done (v0.6.0). The new web vault layout with folders, and unlock after the session has
   ended, are done (v0.7.0). The core has a password generator, a field comparison and password history (v0.8.0); the
   web vault lists the previous passwords of an item and keeps them when a password is changed (v0.9.0), and does not
   use the generator or the field comparison yet.
5. The browser extension and the iOS and Android apps. The first Firefox extension is done (v0.7.0): sign-in, sync,
   suggestions and fill from the popup, copy, and auto-lock; since v0.9.0 it also checks what a form is for before it
   fills. Saving new and changed passwords and the password generator in the extension are in progress, then a health
   check and the rest of the 1.0 list. The apps are later.
6. Hardening and 1.0 (later).

The same overview, with more detail, is on the [website](https://hedgerow.tools/Faithful-Ferret/).

## Contributing

Ferret is not open for contributions yet. When it is, a contributor licence agreement will be required for code
contributions. Until then, issues and ideas are welcome on the [issue tracker](https://github.com/Ferdinand99/Faithful-Ferret/issues).
Please report security problems privately, as described in [`SECURITY.md`](SECURITY.md).

Faithful Ferret is part of [Hedgerow](https://hedgerow.tools/), with [Vigilant Vole](https://hedgerow.tools/Vigilant-Vole/),
[Nimble Newt](https://hedgerow.tools/Nimble-Newt/), [Keen Kestrel](https://hedgerow.tools/Keen-Kestrel/) and
[Wise Wren](https://hedgerow.tools/Wise-Wren/).

## Support

Hedgerow is built in spare time and is free to use. If you find it useful, you can support it through [GitHub Sponsors](https://github.com/sponsors/Ferdinand99) or [Ko-fi](https://ko-fi.com/ferdinand99). Thank you.

## License

[GNU AGPL-3.0-only](LICENSE)

The Inter font files in `web/fonts` and `site/fonts` are under the [SIL Open Font License 1.1](web/fonts/Inter-LICENSE.txt).

The licence texts of the Rust crates inside the server binary and the WebAssembly module, and of the font, are in [THIRD-PARTY-NOTICES](THIRD-PARTY-NOTICES). The Docker image carries the file as `/usr/share/doc/ferret/THIRD-PARTY-NOTICES` (next to `LICENSE`), and every release archive holds it next to the package. The file is made by `scripts/notices.sh` (cargo-about, pinned) and CI fails when it is out of date or when a dependency has a licence that is not on the allowlist in `about.toml`. After changing a dependency, run `scripts/notices.sh` (on a Docker host, like every cargo build) and commit the result.
