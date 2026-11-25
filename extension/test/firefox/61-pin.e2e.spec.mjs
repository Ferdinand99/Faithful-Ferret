// The PIN in the background, against the end-to-end stack (run by `scripts/lanbox-ext.sh e2e`): a real server, the real
// core with its real Argon2id, and a real Firefox. The PIN is set over the UI port of an extension page, the vault is
// locked, and a PIN unlock is cut short by a lock while its Argon2id runs: the worker that held the key is ended in the
// middle of the call. That is one attempt (the counter is written before the Argon2id starts), no more and no fewer.
//
// The stack must be fresh (`e2e-up`), as for the other end-to-end specs; the account is the one the first channel made.
import assert from "node:assert/strict";
import { after, test } from "node:test";
import { SLOW, extensionSignIn, start, webVaultAccount } from "./e2e.mjs";
import { channels, stopFixtures } from "./harness.mjs";

after(() => stopFixtures());

const PIN = "739415-e2e-pin";

/**
 * One request over the UI port of the extension page the current tab shows. `after` sends a second request this many
 * milliseconds later on the same port (a lock, say) and its reply is returned as `second`.
 * @param {import("./driver.mjs").Session} session
 * @param {string} type @param {unknown} body
 * @param {{ after?: { delay: number, type: string, body: unknown } }} [options]
 * @returns {Promise<{ first: any, second?: any }>}
 */
function ask(session, type, body, options = {}) {
  return session.content(
    (/** @type {string} */ kind, /** @type {unknown} */ payload, /** @type {any} */ extra) =>
      new Promise((resolve, reject) => {
        const port = browser.runtime.connect({ name: "ferret-ui" });
        const timer = setTimeout(() => reject(new Error("the UI port did not answer")), 170_000);
        /** @type {Record<string, any>} */
        const replies = {};
        port.onMessage.addListener((raw) => {
          const message = JSON.parse(typeof raw === "string" ? raw : JSON.stringify(raw));
          replies[message.id] = message;
          if (replies.a1 && (extra === null || replies.a2)) {
            clearTimeout(timer);
            port.disconnect();
            resolve({ first: replies.a1, ...(extra === null ? {} : { second: replies.a2 }) });
          }
        });
        port.onDisconnect.addListener(() => reject(new Error("the UI port hung up")));
        port.postMessage(JSON.stringify({ v: 1, id: "a1", type: kind, body: payload }));
        if (extra !== null) {
          setTimeout(() => port.postMessage(JSON.stringify({ v: 1, id: "a2", type: extra.type, body: extra.body })), extra.delay);
        }
      }),
    type,
    body,
    options.after ?? null,
  );
}

test("a_killed_worker_during_pin_unlock_counts_one_attempt", async () => {
  for (const channel of channels()) {
    const session = await start(channel);
    try {
      const account = await webVaultAccount(session, channel);
      const signedIn = await extensionSignIn(session, account);
      assert.equal(signedIn.ok, true, `${channel}: ${signedIn.text}`);

      // The PIN is set with the master password again, from the page that is open (the device keeps the secret key).
      const set = await ask(session, "pin_set", { mp: account.password, pin: PIN, location: "disk", acknowledged: true });
      assert.deepEqual([set.first.type, set.first.body], ["pin_set", { ok: true }], `${channel}: ${JSON.stringify(set.first.body)}`);
      const policy = await ask(session, "unlock_policy", {});
      assert.equal(policy.first.body.pin_state.set, true, channel);
      assert.equal(policy.first.body.pin_state.location, "disk", channel);
      assert.equal(policy.first.body.pin_state.failures_left, 5, channel);
      await ask(session, "lock", {});

      // A PIN unlock, cut short by a lock while its Argon2id runs: the call is rejected as the worker goes.
      const killed = await ask(session, "pin_unlock", { pin: PIN }, { after: { delay: 500, type: "lock", body: {} } });
      assert.deepEqual([killed.first.type, killed.first.body], ["pin_unlock", { ok: false, reason: "wrong_pin", left: 4, wait_ms: 0 }], `${channel}: ${JSON.stringify(killed.first.body)}`);
      const counted = await ask(session, "unlock_policy", {});
      assert.equal(counted.first.body.pin_state.failures_left, 4, `${channel}: one attempt, no more and no fewer`);
      const state = await ask(session, "state", {});
      assert.equal(state.first.body.state, "locked", channel);

      // The next try is a normal one: it opens the vault and gives the attempts back.
      const opened = await ask(session, "pin_unlock", { pin: PIN });
      assert.equal(opened.first.body.ok, true, `${channel}: ${JSON.stringify(opened.first.body)}`);
      assert.equal(opened.first.body.account_email, account.email, channel);
      const after = await ask(session, "unlock_policy", {});
      assert.equal(after.first.body.pin_state.failures_left, 5, channel);
      assert.equal((await ask(session, "state", {})).first.body.state, "unlocked", channel);
    } finally {
      await session.quit();
    }
  }
}, { timeout: SLOW * 3 });
