// The unlock matrix, in real Firefox against the end-to-end stack (run by `scripts/lanbox-ext.sh e2e`): a real server, the real
// background with its handlers and the real core with its Argon2id. One signed-in browser per channel goes through the cells
// that can only be shown in a browser:
//
//   the PIN       six digits, and a text of eight characters with letters of the Norwegian alphabet (also typed in the other
//                 Unicode form, which the core normalizes), kept on disk (the default) and in the session storage only;
//   the place     the disk database or the session storage, and nothing in the local storage;
//   the events    a right and a wrong PIN, the end of the background, a restart of the browser (the disk PIN stays, the memory
//                 PIN goes), the network gone inside the seven days and after them, a clock that was set back, a revoked device;
//   the record    a changed byte of the wrap, an unknown profile, a later vault key epoch and a record with one field too many,
//                 each of which never opens the vault and (but for a changed byte, which counts as a wrong PIN) ends the PIN;
//   the leak      a sentinel PIN is in no file of the browser's profile, in any of its common forms.
//
// The attempts and their waits, the killed worker and the PIN in the popup are shown by 61 and 63; the passkey by 64.
//
// The stack must be fresh (`e2e-up`), as for the other end-to-end specs; the account is the one the first channel made.
import assert from "node:assert/strict";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { after, test } from "node:test";
import { revokeLeftDevices } from "./adversary.mjs";
import { SLOW, VAULT_URL, extensionSignIn, pace, start, webVaultAccount } from "./e2e.mjs";
import { TEST_ADDON_ID, channels, stopFixtures } from "./harness.mjs";
import { SENTINEL_PREFIX, afterStart, ask, editDiskRecord, onBridge, pinPlaces, pinPolicy, scanFolder, setOffline, setPin } from "./unlock.mjs";

after(() => stopFixtures());

const DIGITS = "739415";
/** Eight characters, three of them letters of the Norwegian alphabet; the second is the same text in the decomposed form. */
const TEXT = "blåbærØ8";
const SENTINEL_DISK = `${SENTINEL_PREFIX}æøå-disk`;
const SENTINEL_MEMORY = `${SENTINEL_PREFIX}æøå-memory`;

test("the_unlock_matrix_passes_in_release_and_esr", async () => {
  for (const channel of channels()) {
    const session = await start(channel);
    try {
      const account = await webVaultAccount(session, channel);
      const signedIn = await extensionSignIn(session, account);
      assert.equal(signedIn.ok, true, `${channel}: ${signedIn.text}`);
      await onBridge(session);

      const state = async () => (await ask(session, "state", {})).state;
      const lock = async () => {
        await ask(session, "lock", {});
        assert.equal(await state(), "locked", `${channel}: locked`);
      };
      const unlockPin = (/** @type {string} */ pin) => ask(session, "pin_unlock", { pin });
      /** Opens the vault with the master password (the PIN is set only from an open vault). */
      const unlockMaster = async () => {
        await pace();
        const reply = await ask(session, "unlock", { mp: account.password });
        assert.equal(reply.ok, true, `${channel}: the master password unlock: ${JSON.stringify(reply)}`);
      };
      /** A PIN unlock that must open the vault. @param {string} pin @param {string} what */
      const opens = async (pin, what) => {
        const reply = await unlockPin(pin);
        assert.equal(reply.ok, true, `${channel}: ${what}: ${JSON.stringify(reply)}`);
        assert.equal(reply.account_email, account.email, `${channel}: ${what}`);
        assert.equal(await state(), "unlocked", `${channel}: ${what}`);
      };
      /** A PIN unlock that must be refused with `reason`, and leave the vault locked (or the device signed out). @param {string} pin @param {string} reason @param {string} what @param {string} [after] */
      const refuses = async (pin, reason, what, after = "locked") => {
        const reply = await unlockPin(pin);
        assert.equal(reply.ok, false, `${channel}: ${what}: ${JSON.stringify(reply)}`);
        assert.equal(reply.reason, reason, `${channel}: ${what}: ${JSON.stringify(reply)}`);
        assert.equal(await state(), after, `${channel}: ${what}`);
        return reply;
      };

      // ------------------------------------------------------------ six digits on disk
      await setPin(session, account, DIGITS, "disk");
      let places = await pinPlaces(session);
      assert.deepEqual(places, { disk: true, sessionKeys: [], localKeys: [] }, `${channel}: the PIN is on disk and nowhere else`);
      let policy = await pinPolicy(session);
      assert.deepEqual([policy.set, policy.location, policy.failures_left], [true, "disk", 5], channel);
      await lock();
      const wrong = await refuses("111111", "wrong_pin", "a wrong PIN");
      assert.equal(wrong.left, 4, `${channel}: the wrong PIN is counted`);
      await opens(DIGITS, "six digits");
      assert.equal((await pinPolicy(session)).failures_left, 5, `${channel}: a right PIN gives the attempts back`);

      // ------------------------------------------------------------ eight characters, in the session storage
      await setPin(session, account, TEXT, "session");
      places = await pinPlaces(session);
      assert.equal(places.disk, false, `${channel}: the disk PIN moved away`);
      assert.equal(places.sessionKeys.length, 1, `${channel}: the memory PIN is in the session storage`);
      assert.deepEqual(places.localKeys, [], `${channel}: nothing in the local storage`);
      policy = await pinPolicy(session);
      assert.deepEqual([policy.set, policy.location], [true, "session"], channel);
      await lock();
      await opens(TEXT, "eight characters with æøå");
      await lock();
      await opens(TEXT.normalize("NFD"), "the same text in the decomposed Unicode form");

      // ------------------------------------------------------------ the end of the background
      await lock();
      await session.terminateBackground(TEST_ADDON_ID);
      await opens(TEXT, "after the background was ended");
      assert.equal((await pinPlaces(session)).sessionKeys.length, 1, `${channel}: the memory PIN is still in the session storage`);

      // ------------------------------------------------------------ a restart of the browser: the memory PIN goes
      await session.restart();
      await afterStart(session);
      assert.equal(await state(), "locked", `${channel}: the vault is locked after a restart`);
      policy = await pinPolicy(session);
      assert.equal(policy.set, false, `${channel}: the PIN in memory is gone after a restart`);
      assert.deepEqual(await pinPlaces(session), { disk: false, sessionKeys: [], localKeys: [] }, channel);
      await refuses(TEXT, "pin_unavailable", "no PIN is left to try");
      await unlockMaster();

      // ------------------------------------------------------------ on disk: the PIN stays through a restart
      await setPin(session, account, SENTINEL_DISK, "disk");
      await session.restart();
      await afterStart(session);
      assert.equal(await state(), "locked", channel);
      policy = await pinPolicy(session);
      assert.deepEqual([policy.set, policy.location, policy.failures_left], [true, "disk", 5], `${channel}: the disk PIN is there after a restart`);
      await opens(SENTINEL_DISK, "the disk PIN after a restart");

      // ------------------------------------------------------------ no network, inside the seven days
      await lock();
      await setOffline(session, true);
      try {
        await opens(SENTINEL_DISK, "no network, inside the seven days");
        await lock();
        // Seven days and a day since the last contact: the PIN waits for the server, and is not used up.
        await editDiskRecord(session, { kind: "contact_days_ago", days: 8 });
        await refuses(SENTINEL_DISK, "pin_offline_expired", "no network, after the seven days");
        policy = await pinPolicy(session);
        assert.deepEqual([policy.set, policy.failures_left, policy.offline_ok], [true, 5, false], `${channel}: the PIN stays and nothing was counted`);
        // The clock was set back below the highest time that was seen: the same.
        await editDiskRecord(session, { kind: "contact_days_ago", days: 0 });
        await editDiskRecord(session, { kind: "clock_behind_by", days: 3 });
        await refuses(SENTINEL_DISK, "pin_offline_expired", "no network, the clock set back");
        assert.equal((await pinPolicy(session)).set, true, channel);
      } finally {
        await setOffline(session, false);
      }
      // With the network back the extension shows the server first (a renewal of the tokens), and then the PIN works.
      await editDiskRecord(session, { kind: "contact_days_ago", days: 8 });
      await opens(SENTINEL_DISK, "the network back after the seven days");
      assert.equal((await pinPolicy(session)).offline_ok, true, `${channel}: the renewal was the contact`);
      await lock();
      await editDiskRecord(session, { kind: "clock_behind_by", days: 3 });
      await opens(SENTINEL_DISK, "the network back, the clock was set back");

      // ------------------------------------------------------------ a record that was changed
      // A changed byte of the wrap does not open it, and counts as a wrong PIN.
      await lock();
      await editDiskRecord(session, { kind: "flip_wrap_byte", at: 20 });
      const flipped = await refuses(SENTINEL_DISK, "wrong_pin", "a changed byte of the wrap");
      assert.equal(flipped.left, 4, `${channel}: and it counted`);
      // An unknown profile, a later vault key epoch and a record with one field too many end the PIN, at once and for good.
      /** @type {Array<[Parameters<typeof editDiskRecord>[1], string, string]>} */
      const ended = [
        [{ kind: "profile", value: 99 }, "pin_wiped", "an unknown PIN profile"],
        [{ kind: "epoch_up", value: 1 }, "pin_stale", "a vault key epoch the record has not seen"],
        [{ kind: "extra_field" }, "pin_unavailable", "a record with one field too many"],
      ];
      for (const [change, reason, what] of ended) {
        await unlockMaster();
        await setPin(session, account, SENTINEL_DISK, "disk");
        await lock();
        await editDiskRecord(session, change);
        await refuses(SENTINEL_DISK, reason, what);
        policy = await pinPolicy(session);
        assert.equal(policy.set, false, `${channel}: ${what}: the PIN is gone`);
        assert.deepEqual((await pinPlaces(session)).disk, false, `${channel}: ${what}: nothing is left on disk`);
      }

      // ------------------------------------------------------------ a revoked device
      await unlockMaster();
      await setPin(session, account, SENTINEL_MEMORY, "session");
      await lock();
      // The web vault revokes the extension's device (from a tab of its own).
      const bridgeTab = await session.windowHandle();
      const webTab = await session.newTab();
      await session.switchTo(webTab);
      // The session of the web vault may have lived through the restarts; if it did not, it signs in again.
      await session.navigate(`${VAULT_URL}/vault/login`);
      const signedInAgain = await session.content(async () => (await fetch("/api/auth/devices", { headers: { "Ferret-Protocol": "1" }, cache: "no-store" })).ok);
      if (!signedInAgain) await webVaultAccount(session, channel);
      await revokeLeftDevices(session);
      await session.closeTab();
      await session.switchTo(bridgeTab);
      await refuses(SENTINEL_MEMORY, "pin_wiped", "a revoked device", "signed_out");
      assert.equal((await pinPolicy(session)).set, false, `${channel}: the revoked device's PIN is deleted at the first contact`);
      assert.deepEqual(await pinPlaces(session), { disk: false, sessionKeys: [], localKeys: [] }, channel);

      // ------------------------------------------------------------ no sentinel PIN is in any file of the profile
      const control = mkdtempSync(join(tmpdir(), "ferret-scan-control-"));
      try {
        writeFileSync(join(control, "utf16.bin"), Buffer.from(`xx${SENTINEL_DISK}yy`, "utf16le"));
        writeFileSync(join(control, "b64.txt"), `"${Buffer.from(SENTINEL_MEMORY).toString("base64")}"`);
        const seen = scanFolder(control, [SENTINEL_DISK, SENTINEL_MEMORY]);
        // (base64 and base64url are the same text when the value has no character that differs, so both may report)
        assert.deepEqual([...new Set(seen.map((hit) => `${hit.file}:${hit.needle}`))].sort(), ["b64.txt:1", "utf16.bin:0"], "the scan finds a value in the forms it looks for");
        assert.ok(seen.some((hit) => hit.form === "utf16") && seen.some((hit) => hit.form === "base64"), "and names the form");
      } finally {
        rmSync(control, { recursive: true, force: true });
      }
      const leaked = scanFolder(session.profileDir, [SENTINEL_DISK, SENTINEL_MEMORY, SENTINEL_DISK.normalize("NFKD"), SENTINEL_MEMORY.normalize("NFKD"), TEXT, TEXT.normalize("NFKD")]);
      assert.deepEqual(leaked, [], `${channel}: a PIN is in a file of the profile`);
    } finally {
      await setOffline(session, false).catch(() => {});
      await session.quit();
    }
  }
}, { timeout: SLOW * 12 });
