// Firefox probes for the local PIN store: the module runs over the real IndexedDB
// and the real session storage of the extension's own origin, with no fake. What
// they check that the unit tests cannot: the database opens and upgrades, a
// transaction with `durability: "strict"` is accepted (no TypeError), the counter
// is written before the unlock runs and is still there after the page has
// reloaded (the browser keeps it, not the page's memory), and a wipe leaves
// nothing readable through the API.
//
// What they cannot check, and say so: whether a deleted record is gone from the
// database file (an earlier probe found that it is not, and no script can
// look), and whether the commit of a strict transaction has reached the disk.
//
// Run by the Firefox runner with the test build (see 01-corehost.spec.mjs).
import assert from "node:assert/strict";
import { test } from "node:test";

const xpi = process.env.FERRET_EXT_XPI;
const uuid = process.env.FERRET_EXT_UUID;
const channel = process.env.FERRET_EXT_CHANNEL === "esr" ? "esr" : "release";
const skip = xpi && uuid ? false : "needs the Firefox runner (FERRET_EXT_XPI, FERRET_EXT_UUID)";

/** @param {(session: any) => Promise<void>} body */
async function withBridge(body) {
  const { startFirefox } = await import("./driver.mjs");
  const session = await startFirefox({ channel, addon: xpi, headless: true });
  try {
    await session.navigate(`moz-extension://${uuid}/test/bridge.html`);
    await body(session);
  } finally {
    await session.quit();
  }
}

/** Runs the scenario in the extension's page: a fresh store over the real `indexedDB` and `browser.storage.session`. */
const scenario = (/** @type {any} */ session, /** @type {string} */ name) =>
  session.execute(async (/** @type {string} */ which) => {
    const mod = await import("/background/localUnlock.mjs");
    const server = "https://vault.example.com";
    const account = "a1".repeat(16);
    const blob = (/** @type {number} */ fill) => ({
      methodId: new Uint8Array(16).fill(fill),
      wrap: new Uint8Array(104).fill(fill + 1),
      deviceSalt: new Uint8Array(16).fill(fill + 2),
      pinProfile: 1,
      vkEpoch: 3,
      rule: { minLength: 6 },
    });
    const make = () => mod.createLocalUnlock({ idb: indexedDB, session: browser.storage.session });
    // Which transactions asked for what, and whether the engine refused an option.
    const seen = { options: /** @type {unknown[]} */ ([]), refused: 0 };
    const original = IDBDatabase.prototype.transaction;
    IDBDatabase.prototype.transaction = function (/** @type {any} */ ...args) {
      try {
        const tx = original.apply(this, /** @type {any} */ (args));
        if (args[1] === "readwrite") seen.options.push({ asked: args[2] ?? null, durability: tx.durability });
        return tx;
      } catch (error) {
        seen.refused += 1;
        throw error;
      }
    };
    try {
      await mod.createLocalUnlock({ idb: indexedDB, session: browser.storage.session }).wipeAll("pin_off");
      if (which === "disk") {
        const store = make();
        await store.save(server, account, blob(7), { location: "disk", acknowledged: true });
        let atUnlock = -1;
        const first = await store.attempt(server, account, { online: true }, async () => {
          // The unlock runs: the record in the database already holds the raised counter.
          try {
            atUnlock = (await make().status(server, account)).failuresLeft;
          } catch (error) {
            atUnlock = -2;
            seen.options.push(String(error));
          }
          return { ok: false, reason: "wrong" };
        });
        // A new store over the same database (the background after a restart) sees the same counter.
        const again = await make().status(server, account);
        await make().resetFailures(server, account);
        const reset = await make().status(server, account);
        await make().wipe(server, account, "pin_off");
        const gone = await make().status(server, account);
        const sessionKeys = Object.keys(await browser.storage.session.get(null)).filter((k) => k.startsWith(mod.SESSION_KEY_PREFIX));
        const localKeys = Object.keys(await browser.storage.local.get(null)).filter((k) => /pin/i.test(k));
        return { first, atUnlock, again, reset, gone, sessionKeys, localKeys, seen };
      }
      const store = make();
      await store.save(server, account, blob(9), { location: "session" });
      const status = await make().status(server, account);
      const keys = Object.keys(await browser.storage.session.get(null)).filter((k) => k.startsWith(mod.SESSION_KEY_PREFIX));
      const first = await store.attempt(server, account, { online: false }, async () => ({ ok: true }));
      await make().wipeServer(server, "forgot_server");
      const gone = await make().status(server, account);
      const left = Object.keys(await browser.storage.session.get(null)).filter((k) => k.startsWith(mod.SESSION_KEY_PREFIX));
      return { status, keys, first, gone, left, seen };
    } finally {
      IDBDatabase.prototype.transaction = original;
    }
  }, name);

test("unlock_store_disk_record_counts_before_the_unlock_and_survives_a_new_store_in_real_firefox", { skip }, async () => {
  await withBridge(async (session) => {
    const r = await scenario(session, "disk");
    assert.equal(r.atUnlock, 4, `the counter was written before the unlock ran ${JSON.stringify(r)}`);
    assert.deepEqual(r.first, { result: "wrong", failuresLeft: 4, waitMs: 0 });
    assert.equal(r.again.failuresLeft, 4);
    assert.equal(r.again.location, "disk");
    assert.equal(r.reset.failuresLeft, 5);
    assert.equal(r.gone.set, false);
    assert.deepEqual(r.sessionKeys, [], "a disk record leaves nothing in the session storage");
    assert.deepEqual(r.localKeys, [], "nothing in the local storage");
    assert.equal(r.seen.refused, 0, "the engine accepts a transaction with durability strict");
    assert.ok(r.seen.options.length >= 3);
    // The default durability of a write in this engine, shown, since the option is accepted: strict, or the default.
    for (const entry of r.seen.options) assert.ok(entry.durability === "strict" || entry.durability === "default", JSON.stringify(entry));
  });
});

test("unlock_store_session_record_lives_only_in_the_session_storage_in_real_firefox", { skip }, async () => {
  await withBridge(async (session) => {
    const r = await scenario(session, "session");
    assert.equal(r.status.location, "session");
    assert.equal(r.keys.length, 1);
    assert.equal(r.first.result, "ok");
    assert.equal(r.gone.set, false);
    assert.deepEqual(r.left, []);
    assert.equal(r.seen.refused, 0);
  });
});
