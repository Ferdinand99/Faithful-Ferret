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

> **Status: in development, pre-1.0 (v0.6.1).** The cryptographic core, the OPAQUE server library, the server and the
> web vault work end to end in testing. Safe sync between devices and browser tabs came in v0.3.0, and v0.5.0 added
> recovery with a printed emergency sheet, an encrypted export, import from other password managers, and automatic
> backups with an encrypted copy off the machine. v0.6.0 adds devices: clients other than the web vault sign in with
> tokens that are bound to a key on the device, there is a device list with revoke in the web vault, and the core and
> the WebAssembly binding can keep folder labels inside an encrypted item (see [What works today](#what-works-today)).
> The Firefox extension with autofill and a new web vault layout, which will also bring folders to the interface, are
> in progress and not released. After them come a password generator and a health check. Ferret is a single-author
> project and is **not for real passwords yet**. There is no external audit, and none is planned.

Faithful Ferret ("Ferret") is a password manager you host yourself, planned as part of
[Hedgerow](https://hedgerow.tools/), a family of small self-hosted apps. It is built around one rule: the server
must not be able to read your vault. Everything is encrypted and decrypted on your own devices, and the server,
its admin panel and its API only ever see ciphertext.

## What works today

These are in v0.6.1 and are tested on a test instance. All of it is pre-1.0, and none of it has had an external review.

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
  and CSV). Duplicates are not removed, and passkeys, folders, tags and attachments are not imported.
- **Tabs.** The vault runs in one tab per browser and account. Moving it to another tab keeps unsaved edits in the
  first tab instead of dropping them.
- **Backups.** The server writes a checked backup set every 24 hours and after every change to the unlock methods.
  The admin pages show the state and have "Take a backup now". An optional second container encrypts each set with
  `age` to a public key you own and copies it to an SFTP target, then reads it back to check it. A set is restored
  with `ferret backup restore`, which is safe to cut off and run again. A restore ends every session and raises
  the restore epoch so that devices notice an older state.
- **Devices and bound tokens.** A client that is not the web vault, such as the browser extension will be, signs in
  as a device: it makes its own key, signs in with the master password, and gets an access token and a refresh token
  that only that key can use. Every request carries a proof of that key (DPoP, RFC 9449, ES256). An access token
  lives 15 minutes, a refresh token is used once and replaced at every renewal, and using an old one after a short grace
  period revokes the device. An account can have 20 devices with tokens. The web vault is not a device and keeps its cookie session.
  No released client uses device sign-in yet; the Firefox extension will be the first.
- **Device list and revoke.** The Devices page of the web vault lists the devices with tokens and the browsers that
  are signed in, with name, platform and last seen. You can revoke one device, revoke every device and every other
  session (this asks for the master password again), or forget the devices not seen for 7 days. Revoking makes the
  tokens invalid at once and closes the device's live event stream. A change of master password, a recovery, a
  redeemed sign-in code and a restore sign every device out. The database holds only token hashes, never a token.
- **Folder labels in the core.** An item can carry folder names (up to 20, each 1 to 64 characters) inside its
  encrypted body, through `ferret-core` and the WebAssembly binding, so the server never sees a name. There is no
  folder interface in the web vault yet, and import still leaves folders out.
- **Deployment.** The stack for real data publishes its two ports on the loopback address only and trusts exactly one
  proxy. Server images are built for amd64 and arm64 and signed with cosign, and the deploy script verifies the
  signature before it runs an image. The admin address is the entry point to the admin pages.

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
  page. The browser extension and the apps are the real protection against that (see
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
- **The web vault trusts the server that serves it.** A compromised server could serve a tampered web page. The server always serves
  the web vault, and there is no switch to turn it off. If you do not want to trust the server that delivers the
  code, use the browser extension and the apps.
- **A compromised device is out of reach.** Malware on a device that has the vault unlocked can read what you can
  read.
- **Zero-knowledge has a price.** If every unlock and recovery method is lost, the data cannot be recovered.
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
   device list with revoke, are done (v0.6.0). Folder labels are in the core; the folder interface comes with the new
   web vault layout, which is in progress.
5. The browser extension and the iOS and Android apps. The extension has started, Firefox first, and is not usable
   yet; autofill is in progress. After that come the password generator and a health check, then the rest of
   the 1.0 list. The apps are later.
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
