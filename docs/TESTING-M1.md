# Testing the first milestone (server and web vault)

Two things are tested here: an automated gate that drives the real server and the
web vault in three browsers, and a short list of things a person checks by hand
on the test deployment behind the Pangolin proxy.

Everything runs on the LANBox through the Docker context `unraid`; nothing here
starts Docker on a workstation. All data on both stacks is throwaway test data.

## The automated gate

`scripts/lanbox-ferret-e2e-gate.sh` uses the separate end-to-end stack
(compose project `ferret-e2e`, started by `scripts/lanbox-ferret-test.sh e2e-up`).
That stack has its own network, its own data volume, a TLS terminator with
the host names `vault-e2e.test` and `admin-e2e.test`, and a server built with the
`e2e-clock` feature, which lets a test move the server clock forward. It never
touches the stack of the test deployment (`ferret-test`).

```
scripts/lanbox-ferret-e2e-gate.sh            # everything
scripts/lanbox-ferret-e2e-gate.sh browsers   # the scenarios in Chromium, Firefox and WebKit
scripts/lanbox-ferret-e2e-gate.sh restart    # restart the container, lost opaque_setup
scripts/lanbox-ferret-e2e-gate.sh limits     # session limits with the moved clock
scripts/lanbox-ferret-test.sh e2e-down       # remove the stack afterwards
```

`FERRET_E2E_BROWSERS` narrows the browsers (default `chromium firefox webkit`).

What it covers, in the order it runs:

| Scenario | Where |
| --- | --- |
| First account: setup link, emergency sheet, recovery key and secret key typed back before anything is uploaded; a second setup is refused | `01-setup` |
| Sign out and sign in on a fresh browser context: secret key question, pinned server identity, sealed secret key on the device | `02-signin` |
| Make, view, change and delete an item; a deleted item does not return | `03-vault` |
| Two browsers (also two different browser engines) see each other's changes within 10 seconds; signing out in one leaves the other signed in | `04-sync` |
| Lock and unlock: no secret in the page, no item index in memory, the key worker is ended, the password alone unlocks; a changed pinned server key is a loud warning, not "wrong password" | `05-lock` |
| Hand-over of a session to the admin origin: no password field, no WASM, separate cookies, a code made for another browser changes nothing | `06-admin` |
| Sign-out of the admin pages ends on a page of the admin origin that empties htmx's history cache; Back then shows no admin page | `06-admin-signout` |
| Plain http fails closed, a forged forwarding header from an untrusted peer is ignored; sign-out ends the session at the server | `07-transport` |
| The traffic of the whole run, and then the data files and the log of the server, hold none of the passwords, keys, titles or user names | `08-plaintext` and the gate script |
| No content security policy or Trusted Types violation, and no page error, in the whole run | `09-csp` |
| Restart keeps the data; a missing `opaque_setup` makes the server refuse to start | `phase-restart` and the gate script |
| Session limits: vault 12 hours idle and 7 days in all, admin 1 hour idle and 12 hours in all, asked at the server's guard while the clock moves forward only | `phase-limits`, `probe.mjs` and the gate script |

The scenarios share one account, so they run in the order of their numbers, in
one worker. Setup can only happen once on a server, so each browser gets a fresh
stack.

## The WebAssembly package

The web vault is built against the published WebAssembly package named in
`web/wasm.lock.json`: its release file, version and SHA-256. The build fetches
the file and stops if the checksum differs. There is no way to build a test stack
against any other package. When the vault needs a function that the pinned package
lacks, cut a release first, then move the pin: take the SHA-256 from the release's
`SHA256SUMS`, verify that file and the package with `cosign verify-blob` (see
`docs/RELEASING.md`), and change version, url and sha256 in the lock together.

## Checks by hand on the test deployment

The deployment is `https://vault-test.opland.net` (web vault) and
`https://ferret-test.opland.net` (admin pages), both behind Pangolin single
sign-on. Deploy or update it with `scripts/lanbox-ferret-test.sh up`; print the
first-administrator link with `scripts/lanbox-ferret-test.sh token`.

1. Open the setup link, make the account, print or copy the emergency sheet, type
   the recovery key and the secret key back, and open the vault.
2. Make, change and delete an item; reload the page and unlock with the password.
3. Open the same vault in a second browser and watch an item appear (within about
   5 seconds).
4. Lock the vault, check the lock screen shows nothing, unlock again.
5. Open the admin pages from the vault (the button on the sign-in page when you
   are signed in) and check you land on the admin settings page without typing a
   password there. The admin site has no page at `/`; that address is a 404.
6. Sign out in one browser and check the other is still signed in.
7. `scripts/lanbox-ferret-test.sh peers` shows the Pangolin traffic as
   `trusted=true` from the tunnel client's address.

## Known gaps in this milestone

The full list, with the security ones, is in the test script for the owner (outside
the repository). The code-level ones:

- There are two unlock forms (the one on the sign-in page and the one on the
  vault screens). One of them will be chosen later.
- Copied values are not cleared from the clipboard, and revealed values are not
  hidden again after a time. They are hidden by locking.
- The idle lock timer is not moved by activity on the setup-done page and on the
  sign-in page: the vault locks 15 minutes after it was opened there.
- While the setup sheet is shown, before the account is created, there is no idle
  lock.
- An account with two-step sign-in turned on in the admin pages cannot sign in to
  the vault yet.
- The setup sheet has 10 minutes: the server forgets a half-made account after
  that. If the keys are confirmed later, the upload is refused with a 401 `denied`
  answer (the same answer as for an unknown id, on purpose), and the page shows
  the general "could not be opened, check the e-mail, password and secret key"
  text instead of saying that the setup has to be started again. Open the setup
  link again.
- The admin origin answers `/` with a 404 (the kit has no page there). The vault's
  buttons go to `/settings/general`; a Pangolin health check for the admin target
  must use `/healthz`.
- No device tokens or DPoP yet: a stolen session cookie works for up to 12 hours
  idle (vault) until it is revoked. Pangolin's sign-in is not part of Ferret's
  security. There is no backup of the server's data yet.
