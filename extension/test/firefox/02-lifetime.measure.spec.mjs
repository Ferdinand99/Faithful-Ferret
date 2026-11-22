// The lifetime measurement: how long the background page of the test build lives
// in real Firefox, in every scenario, for both manifest versions. About three
// hours for both channels; run it with `scripts/lanbox-ext.sh measure`, never as
// part of the short probes (the file name keeps it out of them).
//
// One cell is one channel, one manifest version and one scenario, with a window
// long enough to pass the auto-lock (17 minutes by default). Every cell is written
// to a JSON report as soon as it is done; the report of the run is
// lifetime-<channel>.json in FERRET_MEASURE_OUT.
//
//   FERRET_MEASURE_MINUTES     the window of a cell (default 17; the auto-lock is 15)
//   FERRET_MEASURE_MANIFESTS   "mv3,mv2" (default)
//   FERRET_MEASURE_SCENARIOS   "idle,sse,popup,argon,terminate" (default)
//   FERRET_MEASURE_OUT         where the reports go (default /work/test-results/out/ext-measure)
import assert from "node:assert/strict";
import { mkdirSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { after, test } from "node:test";
import { channels, stopFixtures } from "./harness.mjs";
import { runLifetimeCell, runTerminateCell, SCENARIOS } from "./measure.mjs";

after(() => stopFixtures());

/** @param {string} name @param {string} fallback @param {readonly string[]} allowed */
function listFrom(name, fallback, allowed) {
  const values = (process.env[name] || fallback).split(",").map((v) => v.trim()).filter(Boolean);
  for (const value of values) if (!allowed.includes(value)) throw new Error(`${name}: ${value} is not one of ${allowed.join(", ")}`);
  if (values.length === 0) throw new Error(`${name} names nothing (a run with no cell would pass without measuring)`);
  return values;
}

const minutes = Number(process.env.FERRET_MEASURE_MINUTES || 17);
if (!Number.isFinite(minutes) || minutes < 2) throw new Error("FERRET_MEASURE_MINUTES must be a number of at least 2");
const WINDOW_MS = Math.round(minutes * 60_000);
const OUT = process.env.FERRET_MEASURE_OUT || "/work/test-results/out/ext-measure";
const manifests = /** @type {("mv3" | "mv2")[]} */ (listFrom("FERRET_MEASURE_MANIFESTS", "mv3,mv2", ["mv3", "mv2"]));
const scenarios = listFrom("FERRET_MEASURE_SCENARIOS", SCENARIOS.join(","), SCENARIOS);

test("background_lifetime_is_recorded_for_every_scenario_and_channel", async () => {
  mkdirSync(OUT, { recursive: true });
  for (const channel of channels()) {
    /** @type {any[]} */
    const cells = [];
    const file = join(OUT, `lifetime-${channel}.json`);
    const save = () => writeFileSync(file, `${JSON.stringify({ channel, windowMinutes: minutes, madeAt: new Date().toISOString(), cells }, null, 2)}\n`);
    for (const manifest of manifests) {
      for (const scenario of scenarios) {
        console.error(`measure: ${channel} ${manifest} ${scenario} (${scenario === "terminate" ? "quick" : `${minutes} min`}) ...`);
        const cell = scenario === "terminate"
          ? await runTerminateCell({ channel, manifest })
          : await runLifetimeCell({ channel, manifest, scenario: /** @type {any} */ (scenario), windowMs: WINDOW_MS });
        cells.push(cell);
        save();
        // One line per cell in the log of the run, so a run that is cut short still has its results.
        console.error(`measure-cell ${JSON.stringify({ channel, firefox: cell.firefox, manifest, scenario, outcome: cell.outcome })}`);
      }
    }
    // No empty cell: every cell of the matrix has its evidence.
    assert.equal(cells.length, manifests.length * scenarios.length, `${channel}: a cell is missing`);
    for (const cell of cells) {
      const where = `${cell.channel} ${cell.manifest} ${cell.scenario}`;
      assert.ok(cell.summary && cell.summary.boots >= 1, `${where}: the log has no start of the page`);
      if (cell.scenario === "terminate") {
        assert.ok(cell.before && cell.after && typeof cell.outcome.terminated === "boolean", `${where}: the cell is empty`);
        continue;
      }
      assert.ok(cell.entries.some((/** @type {{ kind: string }} */ e) => e.kind === "scenario_start"), `${where}: no scenario_start in the log`);
      assert.ok(cell.timeline.length >= 1, `${where}: the browser's state was never read`);
      assert.ok(cell.summary.heartbeats >= Math.floor(minutes) - 2, `${where}: ${cell.summary.heartbeats} heartbeats in ${minutes} min`);
    }
    save();
  }
});
