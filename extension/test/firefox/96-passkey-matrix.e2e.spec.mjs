// The passkey matrix in real Firefox, against the fixture container (run by `scripts/lanbox-ext.sh passkey-matrix`, on the
// container's test network; the plain `e2e` and `firefox` runs leave it out):
//
// - virtual_authenticator_and_fixture_tls_work_in_both_channels: the self-test. In each channel, Firefox trusts the fixture's
//   test CA (and has no way out of the test network), a virtual authenticator answers, and both relying parties (webauthn-rs
//   and SimpleWebAuthn) accept a create and a sign-in from the three client codes, on rp-a.test and on localhost (http and
//   https). If this fails nothing else means anything, and the matrix test is skipped.
// - passkey_matrix_runs_every_selected_case_and_writes_the_report: every case of FERRET_PASSKEY_SET (fixtures, adversarial,
//   holdout or demo) whose id contains FERRET_PASSKEY_GREP, with the provider FERRET_PASSKEY_PROVIDER (stub by default), in each
//   channel. It writes <set>-<channel>-<manifest>.json and .md to FERRET_PASSKEY_OUT and asserts: there are cases, every one has
//   a result or a reason, and no answer was unsafe.
// - passkey_matrix_meets_the_gate: 100 % of the cases of the whole set passed, none not run, no unsafe answer (§ 11.3), answered by
//   Ferret. The stub provider never meets it (it cannot run the cases that need Ferret and cannot see the route); it then asserts that
//   every case it could run passed, and says how many it could not run. With the provider ferret the gate is asserted as it is, and a
//   run with --grep fails it.
import assert from "node:assert/strict";
import { mkdirSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { channels, defaultManifest } from "./harness.mjs";
import { caseAddress, specOf } from "./passkeyCases.mjs";
import { fetchReports, launchMatrixBrowser, runSet } from "./passkeyMatrix.mjs";

const SET = /** @type {"fixtures" | "adversarial" | "holdout" | "demo"} */ (["adversarial", "holdout", "demo"].includes(process.env.FERRET_PASSKEY_SET ?? "") ? process.env.FERRET_PASSKEY_SET : "fixtures");
const PROVIDER = /** @type {"stub" | "ferret"} */ (process.env.FERRET_PASSKEY_PROVIDER === "ferret" ? "ferret" : "stub");
const GREP = process.env.FERRET_PASSKEY_GREP ?? "";
const OUT = process.env.FERRET_PASSKEY_OUT ?? join(tmpdir(), "ferret-u4-matrix");
/** @type {Map<string, Awaited<ReturnType<typeof runSet>>>} */
const runs = new Map();
let selfTestPassed = false;

/** One create and sign-in on a page of the fixture, with a real click; returns what the page reported. @param {import("./driver.mjs").Session} session @param {any} c */
async function ceremony(session, c) {
  const run = `selftest-${Math.random().toString(16).slice(2, 10)}`;
  const address = caseAddress(c, { spec: specOf(c, run), auto: false });
  await session.navigate(address.url);
  await session.waitFor(() => session.content(() => document.documentElement.dataset.ready === "1"), 20_000, `the page ${address.url}`);
  const [go] = await session.findAll("#go");
  assert.ok(go, `#go on ${address.url}`);
  await session.click(go);
  const done = await session.waitFor(async () => (await fetchReports(run)).find((r) => r.kind === "done"), 30_000, `the report of ${address.url}`);
  return { done, reports: await fetchReports(run) };
}

test("virtual_authenticator_and_fixture_tls_work_in_both_channels", async () => {
  selfTestPassed = false;
  for (const channel of channels()) {
    const session = await launchMatrixBrowser({ channel });
    try {
      /** @type {{ lib: "rs" | "swa", client: "swa" | "manual" | "pubkey", host: string, scheme?: "http" | "https" }[]} */
      const combos = [
        { lib: "rs", client: "manual", host: "rp-a.test" },
        { lib: "rs", client: "swa", host: "rp-a.test" },
        { lib: "rs", client: "pubkey", host: "rp-a.test" },
        { lib: "swa", client: "swa", host: "rp-a.test" },
        { lib: "swa", client: "manual", host: "rp-a.test" },
        { lib: "swa", client: "pubkey", host: "rp-a.test" },
        { lib: "rs", client: "manual", host: "localhost", scheme: "https" },
        { lib: "swa", client: "manual", host: "localhost", scheme: "http" },
      ];
      for (const combo of combos) {
        const c = { rp: { lib: combo.lib, client: combo.client }, page: { chain: [combo.host], ...(combo.scheme ? { scheme: combo.scheme } : {}) }, spec: { steps: ["create", "get"], user: { name: "alice", displayName: "Alice" } } };
        const { done } = await ceremony(session, c);
        assert.equal(done.ok, true, `${channel}: ${combo.lib} with ${combo.client} on ${combo.scheme ?? "https"}://${combo.host}: ${JSON.stringify(done.steps?.map((/** @type {any} */ s) => ({ step: s.step, error: s.error })))}`);
        assert.equal(done.steps.length, 2, `${channel}: ${combo.host}: create and sign-in both ran`);
      }
      // The browser must not be able to reach anything outside the test network: a public name does not resolve.
      let reached = true;
      try {
        await session.navigate("https://example.com/");
        reached = !(await session.currentUrl()).startsWith("about:");
      } catch {
        // geckodriver reports the error page as a failed navigation: the name did not resolve, as it must not.
        reached = false;
      }
      assert.equal(reached, false, `${channel}: the browser reached a public name from the test network`);
    } finally {
      await session.quit();
    }
  }
  selfTestPassed = true;
});

test("passkey_matrix_runs_every_selected_case_and_writes_the_report", async (t) => {
  if (!selfTestPassed) {
    t.skip("the self-test did not pass, so the matrix is not run");
    return;
  }
  mkdirSync(OUT, { recursive: true });
  const manifest = defaultManifest();
  for (const channel of channels()) {
    const lines = /** @type {string[]} */ ([]);
    const run = await runSet({ channel, manifest, set: SET, grep: GREP, provider: PROVIDER, outDir: OUT, log: (line) => lines.push(line) });
    console.error(lines.join("\n"));
    runs.set(channel, run);
    assert.ok(run.cases.length > 0, `${channel}: no case in ${SET} matches ${JSON.stringify(GREP)}`);
    for (const c of run.cases) assert.ok(run.results.has(c.id), `${channel}: ${c.id} has no result`);
    assert.equal(run.matrix.unsafe, 0, `${channel}: unsafe answers: ${JSON.stringify(run.matrix.rows.filter((r) => r.unsafe.length))}`);
    console.error(`${channel}: ${run.matrix.passed} of ${run.matrix.total} passed, ${run.matrix.notRun} not run (${run.matrix.needsProvider} need the Ferret provider), route not checked for ${run.matrix.routeUnchecked}`);
    if (run.throughBridge !== null) {
      // The passkey scripts were on: a run in which no request went through the bridge proves nothing about it.
      console.error(`${channel}: ${run.throughBridge} requests went through the passkey bridge`);
      if (run.matrix.rows.some((r) => r.status !== "not-run")) assert.ok(run.throughBridge > 0, `${channel}: the passkey scripts were on, and no request went through the bridge`);
    }
  }
});

test("passkey_matrix_meets_the_gate", async (t) => {
  if (runs.size === 0) {
    t.skip("the matrix was not run");
    return;
  }
  for (const [channel, run] of runs) {
    const m = run.matrix;
    if (PROVIDER === "ferret") {
      assert.equal(GREP, "", `${channel}: the gate is for the whole set: a run with --grep never meets it`);
      assert.equal(m.gate, true, `${channel}: the gate (100 % passed, nothing not run, no unsafe answer) is not met: ${JSON.stringify(m.rows.filter((r) => r.status !== "passed").map((r) => ({ id: r.id, problems: r.problems })))}`);
    } else {
      // The stub runs what it can. Whatever it ran must pass; what only Ferret can answer is counted, not hidden.
      const ranAndFailed = m.rows.filter((r) => r.status === "failed");
      assert.deepEqual(ranAndFailed.map((r) => ({ id: r.id, problems: r.problems })), [], `${channel}: cases that ran and did not pass`);
      const notRunOther = m.rows.filter((r) => r.status === "not-run" && !run.cases.find((c) => c.id === r.id)?.needs && run.cases.find((c) => c.id === r.id)?.set !== "demo");
      assert.deepEqual(notRunOther.map((r) => ({ id: r.id, problems: r.problems })), [], `${channel}: cases that could have run and did not`);
      console.error(`${channel}: stub gate: ${m.passed} passed; ${m.needsProvider} need the Ferret provider (the gate is met only with it)`);
    }
  }
});
