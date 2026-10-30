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

> **Status: in development. The cryptographic core is being written and is not for real passwords yet. There is no
> release and no release date.** The design is approved, and the Rust core and its test vectors are now being built
> in this repository. There is nothing to install or run. Please do not store real passwords in anything built from
> this repository until a release says it is ready.

Faithful Ferret ("Ferret") is a password manager you host yourself, planned as part of
[Hedgerow](https://hedgerow.tools/), a family of small self-hosted apps. It is built around one rule: the server
must not be able to read your vault. Everything is encrypted and decrypted on your own devices, and the server,
its admin panel and its API only ever see ciphertext.

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
  unlock the vault, and nothing on the server, including administration, can decrypt it.
- **Master password and an optional secret key.** The master password unlocks the vault on a new device. A
  separate secret key can be added to protect against offline guessing if someone copies the server's database.
- **Recovery you control.** Recovery uses a recovery key and an encrypted export that you keep. There is **no
  admin recovery** of vaults: if the master password, the recovery key and every export are lost, nobody can open
  the vault. Administrators can reset a login, which never opens the vault.
- **Open design.** The threat model and the cryptographic design are published in
  [`docs/design/fase-1-sikkerhetsdesign.md`](docs/design/fase-1-sikkerhetsdesign.md) (in Norwegian).
  [`docs/REVIEW-PACKAGE.md`](docs/REVIEW-PACKAGE.md) is an English guide to the constructions the code implements.
- **Established cryptography only.** Well-known algorithms and reviewed libraries; no home-made cryptography.
- **Internal review and testing.** A review and testing programme, including test vectors and fuzzing for the
  cryptographic core.

### Honest limits

- **There is no external audit, and none is planned or funded.** Ferret is a small open source project and has
  not been independently audited by anyone. Making the design and code public is how others can check it, and
  [`docs/REVIEW-PACKAGE.md`](docs/REVIEW-PACKAGE.md) is a scoped starting point for anyone who wants to review the
  cryptographic core.
- **The web vault trusts the server that serves it.** A compromised server could serve a tampered web page. This
  limitation will be documented, and administrators will be able to turn the web vault off and use the extension
  and apps only.
- **A compromised device is out of reach.** Malware on a device that has the vault unlocked can read what you can
  read.
- **Zero-knowledge has a price.** If every unlock and recovery method is lost, the data cannot be recovered.

## Repository layout

The Rust cryptographic core lives at the repository root as a Cargo workspace:

- `crates/ferret-core/`: the cryptographic core (safe Rust, no I/O).
- `bindings/wasm/`: the WebAssembly binding for the web vault and the browser extension (added later).
- `tools/vectorgen/`: generates and checks the test vectors.
- `vectors/`: the cross-platform test vectors that every client must pass.
- `ct/`: the small single-file constant-time code (Crockford coding) that the core includes and the constant-time analyzer reads.
- `docker/`, `scripts/`: the build image and scripts for building and testing on a Docker host.
- `fuzz/`: the fuzz targets, their seed corpus and the inputs of fixed crashes.
- `supply-chain/`, `deny.toml`: the dependency audits and policy (`cargo vet`, `cargo deny`).
- `docs/`: the [review package](docs/REVIEW-PACKAGE.md), the [results of phase 4A](docs/PHASE-4A-REPORT.md), the
  [wrap formats](docs/WRAP-AAD.md) and [how a release is made](docs/RELEASING.md).
- `site/`, `assets/`: the website and brand assets.

This project has had no external security audit, and none is planned.

## Roadmap

The phases are the order of work, not cuts in scope, and there are no dates:

1. Design (done).
2. Throwaway prototypes of the risky parts: biometric unlock from a browser extension, acting as a passkey
   provider, key derivation speed on every platform, and the sync protocol.
3. Security design: the threat model, cryptographic design and sync protocol, published and reviewed.
4. The server and a shared Rust cryptographic core.
5. The web vault.
6. The browser extension, then the iOS and Android apps.
7. Hardening and 1.0.

The same overview, with more detail, is on the [website](https://hedgerow.tools/Faithful-Ferret/).

## Contributing

Ferret is not open for contributions yet. When it is, a contributor licence agreement will be required for code
contributions. Until then, issues and ideas are welcome on the [issue tracker](https://github.com/Ferdinand99/Faithful-Ferret/issues).
Please report security problems privately, as described in [`SECURITY.md`](SECURITY.md).

Faithful Ferret is part of [Hedgerow](https://hedgerow.tools/), with [Vigilant Vole](https://hedgerow.tools/Vigilant-Vole/),
[Nimble Newt](https://hedgerow.tools/Nimble-Newt/), [Keen Kestrel](https://hedgerow.tools/Keen-Kestrel/) and
[Wise Wren](https://hedgerow.tools/Wise-Wren/).

## License

[GNU AGPL-3.0-only](LICENSE)
