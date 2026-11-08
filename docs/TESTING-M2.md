# Testing safe sync (the second milestone)

The second milestone adds sync that a malicious or restored server cannot turn into silent data loss: live updates,
conflicts the user settles, a trash, rollback protection with signed checkpoints, and a way to accept a server that was
restored from an older backup. This file lists what is tested automatically, how to run it, what a person checks by
hand on the test deployment, and what is known not to be done. `docs/TESTING-M1.md` still describes the end-to-end
stack and the first milestone's checks.

Everything runs on the LANBox through the Docker context `unraid`; nothing here starts Docker on a workstation. All data
on the test stacks is throwaway test data.

## Automated tests

| What | Where | Command |
| --- | --- | --- |
| The web vault: build, type check, unit tests (the sync engine, outbox, restore, conflict, trash, forget, which tab runs the sync, texts) and Playwright in three browsers | `web/` | `scripts/lanbox-web.sh` |
| The model-based sync matrix: random runs of two to three engines against a model server (offline, retries, deletions, purges, restores, tab handovers), checking that no write is lost and every device converges | `web/test/unit/syncMatrix.test.mjs` | `FERRET_PASS_ENV="FERRET_MATRIX_RUNS FERRET_MATRIX_STRICT FERRET_MATRIX_TOLERATE" FERRET_MATRIX_RUNS=5000 FERRET_MATRIX_STRICT=1 FERRET_MATRIX_TOLERATE=purge scripts/lanbox-web.sh unit` |
| The same scenarios against the real server: seven prototype scenarios, batches, swapped blobs, checkpoints, restore epoch, tombstones, and the routes | `crates/ferret-server/tests/sync_matrix.rs`, `sync_routes.rs`, `listing.rs`, `retention.rs`, `restore_seq.rs`, `restore_epoch.rs` | `scripts/lanbox.sh test --manifest-path crates/ferret-server/Cargo.toml` |
| 10 000 items through the real server (listing, pages, checkpoint size); it is ignored by default | `sync_matrix.rs`, `ten_thousand_items` | `scripts/lanbox.sh test --release --manifest-path crates/ferret-server/Cargo.toml --test sync_matrix ten_thousand_items -- --ignored --nocapture` |
| The WebAssembly binding at scale: the rollback memory and checkpoints at the size of a large vault, `copy_item`, error codes | `tests/node/scale.test.mjs` and the other files there | `scripts/lanbox.sh --exec sh -c 'scripts/build-wasm.sh && scripts/build-wasm.sh --test && node --test tests/node/*.test.mjs'` |
| The end-to-end gate on a private stack, in Chromium, Firefox and WebKit (scenarios 01 to 17) | `web/test/e2e-stack/` | `scripts/lanbox-ferret-e2e-gate.sh` (the sync scenarios alone: `scripts/lanbox-ferret-e2e-gate.sh m2`) |

`FERRET_MATRIX_STRICT=1` makes the matrix fail on every shape it knows about. `FERRET_MATRIX_TOLERATE=purge`
lifts that for the one shape that is known not to be handled (a tombstone that the server purged after 400 days, see
the known limits below). `FERRET_MATRIX_RUNS` sets the number of seeded runs: 500 by default, 5 000 at the gate. A failing run names its seed, and `FERRET_MATRIX_SEED=<seed>` repeats it.

### The sync scenarios of the end-to-end gate

| Scenario | What it checks |
| --- | --- |
| 10, conflict | Two browsers edit one item. Both versions are shown field by field; "Keep mine" and "Keep theirs" each settle it after a confirmation; nothing resolves by itself |
| 11, live updates | A change arrives in the other browser through the event stream without a reload, and the status says so |
| 12, offline | A change made offline waits, is sent once when the network is back, and does not duplicate |
| 13, trash | A deletion moves the item to the trash of the other device; it can be restored; a conflict against a deleted item offers "restore mine" or "accept the deletion" |
| 14, malicious server | The malicious-server rig, in every mode (below) |
| 15, restored server | The server is snapshotted, changed, and the snapshot is put back with a restore bump while two browsers stay open; both show the restored notice; accepting the older state brings the missing writes back and leaves conflicts only where another device wrote after the restore |
| 16, forget this server | "Forget this server" lists unsent writes first and removes the local store |
| 17, one tab | The sync runs in one tab per browser and account; a second tab shows the notice; "Use here" moves the vault and a queued write is still sent once |

### The malicious-server rig

Scenario 14 puts a proxy between the browser and the real server. The proxy rewrites answers in these modes, and
the scenario checks that the vault never shows forged content as real and never deletes a local copy because the server
said so:

- swapped envelopes between items (the item tags no longer match);
- an old, valid row presented as current;
- a hidden item (the vault keeps it, marks it as only on this device, and uploads it again);
- a forged checkpoint (a warning, and the next honest checkpoint is still uploaded);
- a forged deletion (quarantine: "the server says deleted, but it could not be checked");
- a `410 Gone` that forces a full listing of the vault (the vault lists it again and keeps what the server left out);
- a lie about `seq`, and a rollback (the sync stops with a clear warning and offers no "accept" without a real restore);
- a fork, which is not detected (a known limit); the scenario only checks that nothing is lost.

The rig's recorder also searches everything that crossed the proxy for the secrets of the run. Screenshots of each phase
are saved in `test-results/out/m2-shots/`. The rig's modes are covered without a browser by
`web/test/unit/evilModes.test.mjs`.

## Checks by hand on the test deployment

The test deployment is `https://vault-test.opland.net` behind Pangolin. Use two different browsers, a made-up account
and no real passwords. Reload every open vault tab after a deploy: a tab loaded before it still runs the old scripts.

1. **Live updates.** The status field shows "Live" in both browsers. A new item appears in the other browser within one
   or two seconds, and ten minutes of idle time keep the status at "Live". If it says "Fetching every 5 minutes", the
   proxy buffers the stream. The vault still syncs, only more slowly.
2. **Conflict.** Edit the same item in both browsers. The second one shows a conflict with both versions side by side
   and the time and device name. "Keep mine" and "Keep theirs" each settle it. "Keep both" is not there yet.
3. **Network gone in the middle of a write.** Go offline, edit, go online. The item waits, then is saved once and shows
   up once in the other browser.
4. **Deletion and trash.** A deleted item leaves the other browser's list and is in its trash, from where it can be
   restored. A conflict against a deleted item offers "Restore mine" and "Accept the deletion".
5. **One tab per browser.** Open the vault in a second tab of the same browser: it shows "The vault is open in another
   tab" with "Use here" and nothing from the vault. Press "Use here": the vault moves, the first tab shows the notice,
   and a change that was waiting in the first tab is sent. An edit that is open and unsaved in the old tab is lost
   (a known limit). Locking in the new tab and unlocking again works.
6. **A restored server.** The administrator stops the server, restores a snapshot, bumps the restore epoch and starts it
   again (`docs/OPERATIONS.md`). Both browsers show "The server was restored" and stop syncing. "See what happened"
   shows how many local changes would be uploaded again. Accepting the older state uploads them, and creates conflicts
   only for items another device wrote after the restore. Items that were created or changed after the backup give one
   conflict each on the second device that accepts, which is a known limit.
7. **Forget this server.** On the sign-in page, "Forget this server on this device" warns about unsent changes and
   then removes the local store, so the next sign-in asks for the secret key.
8. **Sign-out closes the stream.** In the browser's network tools the `events` request is open; signing out closes it at
   once, and the other browser stays signed in and live.
9. **No stale code and no secrets.** `docker logs ferret-test-app` shows no content from the vault, and
   `scripts/lanbox-ferret-test.sh peers` shows the Pangolin traffic as `trusted=true`.

A failed checkpoint upload (the server was busy or answered with an error) shows one calm notice that it is tried again
later. It is not an error and nothing is lost.

## Known limits

The limits that this milestone leaves are listed in `docs/design/phase-1-security-design.md` § 8.8, with what stops
each of them. The ones to expect while testing:

- "Keep both" and uploading a hidden item again under a new id are not there yet, and checkpoint checks stay paused
  while a hidden item that was uploaded again has not been edited.
- Restoring a backup that is older than the last restore bump repeats an epoch that browsers have stored. They stop with
  the "looks like a rollback" notice; the operator bumps again, and nobody should press "Forget this server" for it, because
  that drops changes that were not sent yet. A backup from before the `restore_seq` migration needs a start, a stop
  and then the bump.
- Two devices that accept the same restore get a conflict for every item that was created or changed after the backup.
- A tombstone purged after 400 days, or a device's own deletion purged before it was read back, can look like a rollback.
- One tab per browser: no fence for an old tab that is alive but not answering, a standby tab unlocks the account keys,
  an unsaved edit is lost on "Use here", and locking or signing out during "Use here" can leave no syncing tab until a reload.
- A rolled-back newest write, a fork and withheld writes are not detected (§ 8.6), `top_seq` is not signed, and clearing
  site data resets the sync memory.
- The same account id pinned under two server addresses in one browser shares one local cache, and "Forget this server" leaves the shared rows in place.
- An unknown unlock method after a restore always shows the text that says it can be an attack.
- The data on a test server is disposable until backup exists.

## Operating the test server

The restore, bump and snapshot steps are in `docs/OPERATIONS.md`. The scripts are `scripts/lanbox-ferret-test.sh snapshot`
and `restore-snapshot` (both ask for `--yes-ferret-test` and are never run by a test), and `up` to deploy. A deploy
from a branch other than the one the stack runs needs the same trusted proxy address check as before.
