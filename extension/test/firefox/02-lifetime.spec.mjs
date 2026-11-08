// How the background page of the test build lives in real Firefox: the short
// checks that run with every Firefox run. The full matrix, with a window of
// 17 minutes for each cell, is 02-lifetime.measure.spec.mjs (`scripts/lanbox-ext.sh measure`).
//
//   * the lifetime log records the start, the scenario and a heartbeat;
//   * a background that the browser ends (as the Terminate button of about:debugging
//     does) comes back locked, with no deadline left.
import assert from "node:assert/strict";
import { after, test } from "node:test";
import { channels, stopFixtures } from "./harness.mjs";
import { AUTO_LOCK_MS, runLifetimeCell, runTerminateCell } from "./measure.mjs";

process.env.FERRET_SSE_INTERVAL_MS ??= "300";

after(() => stopFixtures());

const MANIFESTS = /** @type {const} */ (["mv3", "mv2"]);

test("a_killed_background_comes_back_locked", async () => {
  for (const channel of channels()) {
    for (const manifest of MANIFESTS) {
      const cell = await runTerminateCell({ channel, manifest });
      const where = `${channel} ${manifest}`;
      assert.equal(cell.outcome.was_open_with_deadline, true, `${where}: the vault was open and had a deadline before: ${JSON.stringify(cell.before)}`);
      assert.equal(cell.outcome.terminated, true, `${where}: the browser ended the background: ${JSON.stringify({ terminate: cell.terminate, after: cell.stateAfter })}`);
      assert.equal(cell.outcome.came_back_locked, true, `${where}: the next start is locked: ${JSON.stringify(cell.after)}`);
      assert.equal(cell.outcome.lock_at_gone, true, `${where}: no deadline is left: ${JSON.stringify(cell.after)}`);
    }
  }
});

test("the_lifetime_log_records_the_start_the_scenario_and_a_heartbeat", async () => {
  for (const channel of channels()) {
    // 80 s: one full minute for the alarm, and a margin. Only the log is checked here; what it shows
    // about the lifetime is the measurement's business.
    const cell = await runLifetimeCell({ channel, manifest: "mv3", scenario: "idle", windowMs: 80_000, pollMs: 2000 });
    const kinds = cell.entries.map((/** @type {{ kind: string }} */ e) => e.kind);
    assert.ok(kinds.includes("startup"), `${channel}: startup in ${kinds}`);
    assert.ok(kinds.includes("scenario_start"), `${channel}: scenario_start in ${kinds}`);
    assert.ok(kinds.includes("heartbeat"), `${channel}: a heartbeat in ${kinds}`);
    assert.equal(cell.entries.find((/** @type {{ kind: string }} */ e) => e.kind === "scenario_start").core, "unlocked", `${channel}: the vault is open when the scenario starts`);
    assert.ok(cell.timeline.length >= 1 && cell.timeline.every((/** @type {{ state: unknown }} */ t) => typeof t.state === "string"), `${channel}: the browser's state was read`);
    assert.equal(cell.stored?.name, "idle");
    assert.equal(cell.outcome.window_covers_auto_lock, false);
    assert.ok(AUTO_LOCK_MS > cell.windowMs);
  }
});
