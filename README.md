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

> **Status: in development, pre-1.0 (v0.12.0).** The cryptographic core, the OPAQUE server library, the server and the
> web vault work end to end in testing. Safe sync between devices and browser tabs came in v0.3.0, and v0.5.0 added
> recovery with a printed emergency sheet, an encrypted export, import from other password managers, and automatic
> backups with an encrypted copy off the machine. v0.6.0 added devices: clients other than the web vault sign in with
> tokens that are bound to a key on the device, and there is a device list with revoke in the web vault. v0.7.0 brought
> the first Firefox extension, a new web vault layout with folders, and unlock with the master password after the
> session has ended (see [What works today](#what-works-today)). v0.8.0 added a password generator, a comparison of a
> stored field with a given value, and password history to the core. v0.9.0 shows the previous passwords of an item in
> the web vault, makes the side menu's "Import and export" reach both pages, and teaches the Firefox extension to
> work out what a form is for before it fills. v0.10.0 lets you show or hide the password while you edit an item in the
> web vault, and the Firefox extension 0.8.0, built from v0.10.0, is the first signed build that offers to save a new password or update a
> changed one and has a password generator in its popup. v0.11.0 adds quick unlock and one-time codes: a PIN and a passkey (Windows Hello or Touch ID) open
> the locked vault in the Firefox extension 0.9.0, a passkey also opens it in the web vault, the web vault has a generator page,
> and one-time codes (TOTP) are stored in an item and shown by the web vault and the extension. v0.12.0 makes Ferret a
> passkey provider in the Firefox extension 0.12.0: a website that asks for a passkey gets a small Ferret window to make
> one or sign in with one, passkeys show in the web vault, passkeys can be imported from Bitwarden and AliasVault, and
> the extension's settings are grouped with clear switches. The extension is
> not on the Firefox add-ons store. A health check is next. Ferret is a single-author project and is **not for real
> passwords yet**. There is no external audit, and none is planned.

Faithful Ferret ("Ferret") is a password manager you host yourself, planned as part of
[Hedgerow](https://hedgerow.tools/), a family of small self-hosted apps. It is built around one rule: the server
must not be able to read your vault. Everything is encrypted and decrypted on your own devices, and the server,
its admin panel and its API only ever see ciphertext.

## What works today

These are in v0.12.0 and are tested on a test instance. All of it is pre-1.0, and none of it has had an external review.

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
  and CSV). Duplicates are not removed. Folders and collections become folders, and tags and attachments are not imported. The passkeys of
  Bitwarden (JSON) and AliasVault (`.avux`) files come along as passkeys of the logins they belong to, when the file holds the
  key and the server offers it (the release has it); the next item says what an imported passkey can and cannot do.
  A one-time password secret in these files comes along (one per item; the others, and Steam Guard secrets, are kept as hidden fields).
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
  opens in its own view with an edit form. The health check is in the menu as "Coming soon". The
  menu entry "Import and export" opens a page that leads to both the import page and the export page.
- **Show or hide the password while editing.** The password field of the form for adding or editing an item has a button
  that shows what you typed or hides it again (v0.10.0). The password is hidden again when you save, cancel or the vault
  locks, and whether it is shown is held in the field only: never in an address, a store or a message.
- **Generator page.** The Generator in the menu's Tools section makes a password (length, the character classes, an option to
  leave out look-alike characters) or a passphrase (number of words, separator, capital letters, an optional number) with
  the random numbers of the device, shows an estimate of the strength in bits, and can copy the value or start a new item
  with it. The value exists only on that page and is wiped when you leave it, lock the vault or sign out.
- **One-time codes (TOTP).** An item can hold a time-based one-time password: paste the `otpauth://` address or type the
  Base32 secret that the website shows. The item page shows the current code and the seconds left, and the edit form
  shows a preview. The secret is stored encrypted inside the item like any other field. Counter-based (HOTP) and Steam
  codes are not supported.
- **Passkey unlock in the web vault.** Under Unlock methods in the account menu you can add a passkey (a fingerprint, a face,
  a device PIN or a phone, through the WebAuthn PRF extension; at most 10 per account) and remove it again. In the web
  vault, the passkey opens the vault in place of the master password while the session lives; once the session has ended the
  master password is asked for. The list says whether a passkey can be synced between devices (it is then as safe as the
  cloud account it lives in) or stays on this device. The page is there only when the server offers passkeys.
- **Passkeys in the web vault.** A login that holds a passkey (made by the Firefox extension, or imported) shows it in the item
  page with the site, the user name and the date, never the key. The list marks such items and has a passkey filter, and the
  trash names the site of a deleted passkey. You can rename an item and remove the passkey from it; removing it warns that the
  site still has the public key. The web vault never signs with a passkey of the vault: only the extension does. An imported
  passkey keeps its key but starts with the counter at 0, so a site that compares counters may need the passkey registered again.
- **Unlock rules for the administrator.** Settings, Unlock (administrators only) has three switches: allow PIN, allow PIN
  after a restart of the browser, and the shortest PIN (4 to 64, 6 by default). The page says in words how long every PIN of
  the shortest length takes to try offline. The rule is read by every client and enforced when a PIN is set, at every PIN unlock, when the vault is opened,
  when the popup is opened and at least once an hour.
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
  password history (see above) since v0.9.0. The Firefox extension uses all three (see [below](#firefox-extension)):
  its generator tab makes passwords with the generator, and its offers to save or update a password use the field
  comparison and the history. **The web vault has no generator screen yet**, so you cannot generate a password there.
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

The first version of the Firefox extension came in v0.7.0. Version 0.8.0 of the extension, from v0.10.0 of the
repository, was the first signed build with saving and the password generator, and version 0.9.0, from v0.11.0, adds unlock
with a PIN or a passkey and one-time codes. From v0.12.0 the extension has the same version number as the server (server 0.12.0 comes with extension 0.12.0); the versions above are history. It needs Firefox 153 or newer and is early: it fills logins from its popup,
offers to save and update passwords, makes passwords and fills one-time codes, and since 0.12.0 it can keep and use
passkeys (see Passkey provider below). It is **not on the Firefox add-ons store**. A build that Mozilla has
signed as an unlisted add-on is made by a manually started workflow, and the release downloads of v0.10.0 do not
include it; the signed builds are on their own releases, named `extension-v` and the version (`extension-v0.8.0` for
this one). [`docs/EXTENSION-FIREFOX.md`](docs/EXTENSION-FIREFOX.md) describes how that build is made, and
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
- **Copy.** Copy the user name, e-mail or password from a row, and a one-time code from the row or the item's view. Ferret clears
  the clipboard 30 seconds after its last copy.
- **PIN unlock.** Version 0.9.0 of the extension, from v0.11.0, lets a PIN open the locked vault. The PIN is set on the
  settings page (this asks for the master password again and needs the network) and has the length the administrator's rule
  asks for. By default the PIN is kept on the computer, encrypted, so it works after a restart of the browser and, for seven
  days after the last contact with the server, without a network; "Require master password after restart" keeps it in memory
  only. Five wrong tries delete it, with a short wait before the third and later tries (5, 15 and 30 seconds). It is weaker
  than the master password: someone who gets a copy of the browser profile can try PINs on their own computer, where the limit
  of five does not apply, so use a long PIN, ideally with letters, and only on a computer you trust that has an encrypted
  disk. Settings shows this warning every time a PIN is set or changed, and the PIN is deleted when you sign out, when the
  device is revoked, when the master password changes and when the administrator turns PIN off. Ferret never stores the
  PIN itself or its length.
- **Passkey unlock.** A passkey made in the web vault (see above) also opens the extension's vault, in a small window of
  its own: Windows Hello, or Touch ID with a passkey provider. A phone through a QR code should work too, but it has not been
  tested by hand yet. It needs the network and a signed-in device (living tokens), and it works whether or not a web vault
  session is open. Ferret never sees biometric data; the operating system confirms that it is you. A security key (YubiKey) is not tested.
- **Passkey provider (0.12.0).** Ferret can answer a website's request for a passkey, in Firefox, for sites on `https`. It is off
  until you turn on "Use Ferret for passkeys" in the settings, which asks Firefox for access to `https` pages (the access that
  saving passwords asks for too) and needs the extension to be signed in. When a site asks to make a passkey or to sign in, Ferret
  opens a small window of its own, never anything inside the page. It names the site (as Ferret has checked it, not as the page
  words it), puts Ferret first, and offers "Use the browser instead" (Firefox's own dialog: Windows Hello, Touch ID, a phone or a
  security key) and "Never on this site". A new passkey is saved in the vault as a login item and syncs like every other item; it
  can only be made while you are online. A sign-in asks you to verify when it must: a recent unlock counts for 5 minutes (a setting
  that you can turn off), otherwise Windows Hello or another passkey of your account, the PIN or the master password, in the window.
  The private key stays in the core of the extension and never reaches the page or the JavaScript of the extension. A page that
  asks for a passkey as it loads gets no window by itself: the toolbar button gets a mark and the popup a card that opens it. A
  site that offers passkey autofill (conditional mediation) gets a section in the popup that lists the passkeys for it.
  Ferret does not detect a cloned passkey and signs with counter 0, as other synced passkeys do, so a site cannot tell a copy
  from the original; someone at your unlocked computer can sign in with one click in the 5 minutes after an unlock. Not supported:
  replacing a passkey, related origins, frames of another origin, `largeBlob`, and Ferret as the phone for another device. Another
  password manager that also takes passkeys may answer first. It was tested against our own test pages and two relying-party
  libraries in Firefox Release and ESR (both manifest versions), and on a few public demo sites; Windows Hello, a phone through a
  QR code and Touch ID cannot be driven by an automated run, and they have not been checked by hand yet: the checks are listed in [`docs/TESTING-U4.md`](docs/TESTING-U4.md).
- **Settings.** The settings page is grouped, with clear switches: the passkey group has the switch for Ferret as a passkey
  provider, "Count an unlock in the last 5 minutes" (on by default) and the list "Never on these sites", where you can take a site
  back.
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
- **How well detection works, as tested.** The detection of forms was measured against test forms that we wrote ourselves
  (no real sites, no copied markup), in Firefox Release and in Firefox ESR, each on a test server of its own, with the
  extension signed in to it. Three sets were run, each in three parts: filling a sign-in, noticing a submitted form, and
  filling a generated password.
  - *The main collection* (130 forms, fixed before the detection was tuned on it): filling 53 of 55 (96.4 %), noticing
    a submitted form 75 of 75, filling a generated password 25 of 26 (96.2 %). The three misses (two in filling, one in
    generating) are forms in a modal window that the page moves with a CSS transform, which Ferret refuses on purpose
    because a transformed ancestor can hide a field from the person.
  - *A second collection of 39 forms*, written by someone who had not seen the detection code or the first collection,
    and run before any change was made for it: filling 13 of 14 and noticing 10 of 20 on that first run. After fixes the
    counts are filling 14 of 14, noticing 15 of 20 and a generated password 8 of 8. The five that are not
    noticed send a request and leave the sign-in form on the screen, or have a submit that nothing follows, and a
    failed sign-in looks exactly the same, so Ferret offers nothing there by design. Leaving those five out, the counts
    are 10 of 10 filled and 15 of 15 noticed. A sixth form posts to another site, where the script cannot run; it gives
    no login offer either and is not in these counts.
  - *68 forms modelled on the patterns of a public autofill test site* (written by us, not copied): filling 32 of 32,
    noticing 41 of 41, filling a generated password 12 of 12.
  - In the final runs in both Firefox channels there were **no unsafe fills** (a value in a field that must stay empty, or a
    fill under a rule that does not match) and **no unsafe offers**, and no form that does not belong to a sign-in made
    an offer. These are results on test forms that cover the patterns we know; they say nothing about a site that does
    something new.
- **Offers to save and update passwords.** This is off until you turn on "Offer to save and update passwords" on the
  extension's settings page. Turning it on asks Firefox for access to `https` pages, because a small script has to run
  in them to notice a form that is submitted; turning it off gives that access back. Pages that were already open
  notice passwords only after a reload. The script changes nothing in the page and sends nothing until a form with a
  password field is submitted. It reads only what you typed or pasted yourself (or what Firefox filled in on your
  behalf), only in fields you can see, and never on `http` pages or in frames that do not belong to the same site as
  the page. A sign-in is offered only after it seems to have worked: the page moved on and shows no sign-in form again.
  A sign-up, change or reset form is offered a few seconds after you stop typing.
  - *Where it is shown.* Only in Ferret's popup and as a number on its toolbar button, never in the web page. By
    default the popup opens by itself on the page you are looking at when there is an offer, if Firefox lets an
    extension do that; a setting turns this off, and the number on the button stays. A click on the card is ignored for
    a moment after it appears, so a click meant for the page cannot answer it.
  - *Save or update.* Ferret's core decides, by comparing the typed password with your saved logins without
    revealing them. A new login is saved with the site's address (the host, no path), and you can change its name, user
    name and folder on the card. A changed password is offered as an update only for a saved login that matches the
    host or the exact address; the update changes the password, keeps everything else and keeps the old password under
    "Previous passwords" (up to five). A login that matches only by the site's main domain is listed apart and updated
    only if you pick it. If more than one login could be the one, you pick from a list. The card also names up
    to three logins of other sites that use the same password. The password is hidden on the card until you press "Show
    password".
  - *Nothing without your click.* A save or an update happens only when you press the button on the card, and each
    offer can be used once. "Not now" drops the offer, and "Never for this site" adds the site to a list on the
    settings page that you can edit (from a private window the choice lasts only until the browser closes). Private
    windows work like other windows, if you have allowed the extension in them.
  - *What is kept.* What you typed is kept only in the memory of the extension's background page, for at most five
    minutes, and is dropped when the tab closes and whenever the vault locks (a lock by hand, by the timer, when the
    system is idle or on a restart). It is never written to the browser's storage or a log. Copies that Firefox's
    JavaScript engine makes cannot be wiped; the copy in the core is.
  - *A change in two places.* If a login was changed on this device and somewhere else, the popup tells you what
    differs (passwords are not shown) and you keep one of the two versions; nothing is merged.
- **Password generator.** The popup has a "Generator" part, next to "Vault" and "Settings" in the bar at the bottom of
  the popup (a "Health" item is there too, marked "Coming soon"). It makes a password (4 to 128 characters from the
  classes you choose, 20 with all four by default, with an option to leave out look-alike characters) or a passphrase
  from the [EFF large word list](https://www.eff.org/dice) (3 to 20 words, 5 by default, with a separator, capital
  first letters and an optional number). The strength is shown as an estimate in bits. "Copy" puts the value on the
  clipboard, which Ferret clears after 30 seconds. "Fill in the page" puts it into the new-password fields of a sign-up,
  change or reset form on the page you are on, and into nothing else: never into a field for a password you already
  have and never into a sign-in form. It fills only when the password has at least 8 characters and fits the field.
  When the field states which characters it refuses (a `passwordrules` or `pattern` attribute), the password is made again
  by the core without those kinds of characters. When
  it has filled a form, the card to save the new login appears at once. A value you made but did not save stays only in
  the memory of the background page until the vault locks or 15 minutes pass. The options you choose are remembered;
  the value never is. The credit for the word list is on the settings page.
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

- **Autofill that notices.** Reliable detection of new and changed passwords, tested before release
  against our own test forms, modelled on common sign-in, sign-up and change-password patterns, in Firefox Release and
  ESR.
- **Passkeys, kept and used.** Ferret keeps your passkeys in the vault and answers a website's request for one in Firefox
  (since v0.12.0), and brings in the passkeys of Bitwarden and AliasVault. The phone apps and Chromium browsers come later.
- **Unlock the way you want.** A passkey (Windows Hello, Touch ID) and an optional local PIN, in the Firefox
  extension (since v0.11.0) and for the passkey in the web vault too, and on the phone apps later. Ferret never collects or stores
  biometric data; the operating system confirms it is you.
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
- **The extension is early.** It is a first version for Firefox only, outside the add-ons store. Its detection of new
  and changed passwords is a set of rules that was tested against collections of test forms (numbers above), not against
  every site: some forms are not noticed, and you can always save a login in the web vault. It has had no external
  review either.
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
   web vault lists the previous passwords of an item and keeps them when a password is changed (v0.9.0) and can show or
   hide the password while an item is edited (v0.10.0), and it has a generator page (v0.11.0) and does not use the field comparison yet.
5. The browser extension and the iOS and Android apps. The first Firefox extension is done (v0.7.0): sign-in, sync,
   suggestions and fill from the popup, copy, and auto-lock; since v0.9.0 it also checks what a form is for before it
   fills. Version 0.8.0 of the extension (v0.10.0) also offers to save new and changed passwords and has a password
   generator in its popup, version 0.9.0 (v0.11.0) unlocks with a PIN or a passkey and fills one-time codes, and version 0.12.0
   (v0.12.0) is a passkey provider in Firefox; the web vault shows one-time codes and passkeys and unlocks with a passkey too. A health check and the rest of the 1.0 list are next. The apps are later.
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
