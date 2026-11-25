// How long a PIN takes to open the vault in real Firefox, on the runner (run by `scripts/lanbox-ext.sh e2e`): the real background,
// the real core and its 256 MiB Argon2id in WASM, the real server. A PIN is set, and the vault is locked and opened with it
// twenty times; each time is the whole request over the UI port, from "pin_unlock" to the answer (the Argon2id, the opening of
// the wrap and the checks against the server that follow it). The runner is a small machine on purpose (two CPUs and a few GiB):
// the budget here is the one for a weak reference, 8 seconds at the 95th percentile. The budget for a developer machine
// (3 seconds) is measured by hand, with the same steps (docs/TESTING-U3.md).
//
// The numbers are reported as one line (`pin-unlock-timing {json}`), the run's evidence. The spec locks the vault before each run and
// reads that it is locked (a lock ends the vault's worker, which is shown by the unit tests, not here).
import assert from "node:assert/strict";
import { after, test } from "node:test";
import { SLOW, extensionSignIn, start, webVaultAccount } from "./e2e.mjs";
import { channels, stopFixtures, timingSlack } from "./harness.mjs";
import { SENTINEL_PREFIX, ask, onBridge, setPin } from "./unlock.mjs";

after(() => stopFixtures());

const PIN = `${SENTINEL_PREFIX}timing`;
const RUNS = 20;
/** The budget for the 95th percentile on the runner, in milliseconds. */
const BUDGET_MS = 8000;

/** @param {number[]} sorted ascending @param {number} p between 0 and 1 */
const percentile = (sorted, p) => sorted[Math.min(sorted.length - 1, Math.ceil(p * sorted.length) - 1)];

test("pin_unlock_p95_is_within_budget", async () => {
  for (const channel of channels()) {
    const session = await start(channel);
    try {
      const account = await webVaultAccount(session, channel);
      const signedIn = await extensionSignIn(session, account);
      assert.equal(signedIn.ok, true, `${channel}: ${signedIn.text}`);
      await onBridge(session);
      await setPin(session, account, PIN, "disk");

      /** @type {number[]} */
      const times = [];
      for (let i = 0; i < RUNS; i += 1) {
        await ask(session, "lock", {});
        assert.equal((await ask(session, "state", {})).state, "locked", `${channel}: locked before run ${i + 1}`);
        const started = Date.now();
        const reply = await ask(session, "pin_unlock", { pin: PIN });
        times.push(Date.now() - started);
        assert.equal(reply.ok, true, `${channel}: run ${i + 1}: ${JSON.stringify(reply)}`);
      }
      const sorted = [...times].sort((a, b) => a - b);
      const report = { channel, runs: RUNS, p50: percentile(sorted, 0.5), p95: percentile(sorted, 0.95), max: sorted.at(-1), min: sorted[0], budgetMs: BUDGET_MS };
      console.error(`pin-unlock-timing ${JSON.stringify(report)}`);
      assert.ok(report.p95 <= BUDGET_MS * timingSlack(), `${channel}: the 95th percentile of a PIN unlock is ${report.p95} ms, over the budget of ${BUDGET_MS} ms`);
    } finally {
      await session.quit();
    }
  }
}, { timeout: SLOW * 6 });
