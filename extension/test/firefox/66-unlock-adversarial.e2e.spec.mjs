// A content script against the unlock, in real Firefox against the end-to-end stack (run by `scripts/lanbox-ext.sh e2e`): the
// real background, the real core and a page of the test sites. A content script is code that runs in a web page's tab with the
// extension's permissions for that page; it is what a page's own script could become if the fill engine were taken over, so it is
// treated as hostile. Two things must hold:
//
//  - It cannot burn the PIN's attempts, cannot try a PIN, set, change or turn off a PIN, and cannot open the vault: the
//    messages of the PIN and the passkey are for the extension's own top-level pages only, and a flood of them changes nothing.
//  - It cannot read `storage.session` (where a PIN kept in memory lies; the area is not there for a content script), cannot see the
//    extension's own database, and a copy of a PIN record that it writes to the local storage is no PIN: the extension reads the
//    PIN only where it put it.
//
// The page that frames an extension page is the subject of 70-phishing (no extension page loads in a frame of a web page).
import assert from "node:assert/strict";
import { after, test } from "node:test";
import { ENTRIES, world } from "./adversary.mjs";
import { pace } from "./e2e.mjs";
import { channels, stopFixtures } from "./harness.mjs";
import { SENTINEL_PREFIX } from "./unlock.mjs";

after(() => stopFixtures());

const PIN = `${SENTINEL_PREFIX}content-script`;

/**
 * One of the bridge's content-script probes, run in the top frame of a tab (see test/bridge.mjs).
 * @param {Awaited<ReturnType<typeof world>>} w
 * @param {string} probe
 * @param {Record<string, unknown>} argument
 */
async function asContentScript(w, probe, argument) {
  return w.fromBridge(() => w.bridge.invoke(probe, argument));
}

test("content_scripts_cannot_burn_pin_attempts", async () => {
  for (const channel of channels()) {
    const w = await world(channel, { entries: { host: ENTRIES.host } });
    try {
      await w.ui.open();
      await pace();
      assert.deepEqual(await w.ui.body("pin_set", { mp: w.account.password, pin: PIN, location: "disk", acknowledged: true }), { ok: true }, channel);
      await w.ui.body("lock", {});
      const before = (await w.ui.body("unlock_policy", {})).pin;
      assert.deepEqual([before.set, before.failures_left, before.location], [true, 5, "disk"], channel);

      const tabId = await w.visit(w.server.siteUrl("login"));
      /** Every message of the unlock, with a body that is right for it, a wrong PIN among them many times. */
      const bodies = [
        ...Array.from({ length: 24 }, (_, i) => ({ type: "pin_unlock", body: { pin: `${PIN}-wrong-${i}` } })),
        { type: "pin_unlock", body: { pin: PIN } },
        { type: "pin_set", body: { mp: "a content script does not know this", pin: "another-pin-123", location: "disk", acknowledged: true } },
        { type: "pin_off", body: {} },
        { type: "unlock_policy", body: {} },
        { type: "prf_options", body: {} },
        { type: "prf_unlock", body: { credential_id: "AQID", prf_output: "a".repeat(43) } },
        { type: "prf_window", body: {} },
        { type: "unlock", body: { mp: "nope" } },
        { type: "state", body: {} },
      ];
      const seen = await asContentScript(w, "content.unlock_flood", { tab_id: tabId, messages: bodies });
      // Nothing a content script sent got an answer of the unlock: no reply has a body of a PIN, a policy or a state.
      const text = JSON.stringify(seen.replies);
      assert.ok(!/wrong_pin|pin_wait|pin_wiped|"ok":true|"state":|"pin":\{/.test(text), `${channel}: a message of the unlock was answered to a content script: ${text.slice(0, 300)}`);
      assert.deepEqual(seen.port.got, [], `${channel}: the extension pages' port answered a content script: ${JSON.stringify(seen.port.got).slice(0, 300)}`);

      // What the PIN looks like now, from the extension's own page: untouched, and the vault is still locked.
      const after = (await w.ui.body("unlock_policy", {})).pin;
      assert.deepEqual([after.set, after.failures_left, after.wait_ms, after.location], [true, 5, 0, "disk"], `${channel}: the attempts and the PIN are as they were`);
      assert.equal((await w.ui.body("state", {})).state, "locked", channel);
      // And the PIN still opens the vault, which a flood that had counted would have taken away.
      const opened = await w.ui.body("pin_unlock", { pin: PIN });
      assert.equal(opened.ok, true, `${channel}: ${JSON.stringify(opened)}`);
    } finally {
      await w.ui.close().catch(() => {});
      await w.quit();
    }
  }
}, { timeout: 900_000 });

test("storage_session_is_not_readable_from_a_content_script", async () => {
  for (const channel of channels()) {
    const w = await world(channel, { entries: { host: ENTRIES.host } });
    try {
      await w.ui.open();
      await pace();
      // The PIN is kept in memory only: its record is in the session storage of the extension.
      assert.deepEqual(await w.ui.body("pin_set", { mp: w.account.password, pin: PIN, location: "session", acknowledged: false }), { ok: true }, channel);
      const kept = await w.fromBridge(() =>
        w.session.content(async () => {
          const all = await browser.storage.session.get(null);
          return JSON.stringify(Object.fromEntries(Object.entries(all).filter(([key]) => key.startsWith("ferretPin"))));
        }),
      );
      const [[key, value]] = Object.entries(JSON.parse(kept));
      assert.ok(key.startsWith("ferretPin|"), `${channel}: the PIN's record is in the session storage`);

      const tabId = await w.visit(w.server.siteUrl("login"));
      const seen = await asContentScript(w, "content.unlock_storage", { tab_id: tabId, record: { key, value } });
      assert.equal(seen.sessionArea, "undefined", `${channel}: \`browser.storage.session\` is not there for a content script (${JSON.stringify(seen)})`);
      assert.match(String(seen.sessionRead), /^threw/, `${channel}: a read of the session storage fails (${seen.sessionRead})`);
      assert.match(String(seen.sessionWrite), /^threw/, `${channel}: a write to the session storage fails (${seen.sessionWrite})`);
      assert.ok(!JSON.stringify(seen.sessionRead).includes(PIN) && !String(seen.sessionRead).includes("wrap"), channel);
      assert.ok(Array.isArray(seen.databases) && !seen.databases.some((name) => /ferret/i.test(String(name))), `${channel}: the extension's databases are not in a content script's reach (${JSON.stringify(seen.databases)})`);

      // The forged copy is in the local storage, where a content script can write; the extension reads the PIN where it put it. With the
      // real record gone, a copy of it is not a PIN.
      assert.deepEqual(seen.local, [key], `${channel}: the copy is in the local storage`);
      assert.deepEqual(await w.ui.body("pin_off", {}), { ok: true }, channel);
      const policy = (await w.ui.body("unlock_policy", {})).pin;
      assert.equal(policy.set, false, `${channel}: a copy of the record in the local storage is no PIN`);
      await w.ui.body("lock", {});
      const tried = await w.ui.body("pin_unlock", { pin: PIN });
      assert.deepEqual([tried.ok, tried.reason], [false, "pin_unavailable"], `${channel}: ${JSON.stringify(tried)}`);
      // Clean up what the content script left.
      await w.fromBridge(() => w.session.content(async (/** @type {string} */ forged) => browser.storage.local.remove(forged), key));
    } finally {
      await w.ui.close().catch(() => {});
      await w.quit();
    }
  }
}, { timeout: 900_000 });
