// The passkey matrix in real Firefox, against the fixture container (run by `scripts/lanbox-ext.sh passkey-matrix`, on the
// container's test network; the plain `e2e` and `firefox` runs leave it out):
//
// - virtual_authenticator_and_fixture_tls_work_in_both_channels: the self-test. In each channel, Firefox trusts the fixture's
//   test CA (and has no way out of the test network), a virtual authenticator answers, and both relying parties (webauthn-rs
//   and SimpleWebAuthn) accept a create and a sign-in from the three client codes, on rp-a.test and on localhost (http and
//   https). If this fails nothing else means anything, and the matrix test is skipped.
// - simplewebauthn_browser_and_manual_conversion_both_accept_the_answer: the answer objects of the passkey script
//   (src/content/passkeyResponse.mjs), built from what the virtual authenticator made, are what the three client codes get from
//   create and get, and both relying parties (webauthn-rs, strict, and SimpleWebAuthn) accept the registration and the sign-in:
//   @simplewebauthn/browser (the toJSON-free path of that library), the hand-written conversion of the sites, and the one
//   that reads getPublicKey() and the other methods of the response. Run after the self-test, in both channels.
// - passkey_matrix_runs_every_selected_case_and_writes_the_report: every case of FERRET_PASSKEY_SET (fixtures, adversarial,
//   holdout or demo) whose id contains FERRET_PASSKEY_GREP, with the provider FERRET_PASSKEY_PROVIDER (stub by default), in each
//   channel. It writes <set>-<channel>-<manifest>.json and .md to FERRET_PASSKEY_OUT and asserts: there are cases, every one has
//   a result or a reason, and no answer was unsafe.
// - client_libraries_accept_ferret_answers_through_the_broker (the Ferret provider): a passkey made and used through the real broker,
//   Ferret's window and the core, with the three client codes against both relying parties, without the answer shim (review U4-4b
//   M2; the run's manifest, so a run per manifest covers MV2 and MV3).
// - passkey_matrix_meets_the_gate (named for the set: the_passkey_matrix_passes_in_release_and_esr_mv2_and_mv3 for the fixtures,
//   the_holdout_set_passes for the hold-out set, the_adversarial_pages_pass, the_demo_sites_pass): 100 % of the cases of the whole
//   set passed, none not run, no unsafe answer (§ 11.3), answered by Ferret. The stub provider never meets it (it cannot run the cases that need Ferret and cannot see the route); it then asserts that
//   every case it could run passed, and says how many it could not run. With the provider ferret the gate is asserted as it is, and a
//   run with --grep fails it.
// - no_unsafe_answer_in_any_run: no case of any channel had an unsafe answer (asserted per run as well).
// - a_passkey_made_in_one_profile_signs_in_from_the_other (the Ferret provider, the fixtures): the two sync cases passed in each
//   channel (two Firefox profiles signed in to one account: made in A, used in B; deleted in A, gone in B).
//
// The demo set has no fixture container (the public sites, on a network that reaches them): its run has no self-test and no answer
// test, only the matrix and its gate.
import assert from "node:assert/strict";
import { mkdirSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { channels, defaultManifest } from "./harness.mjs";
import { builderScript, SHIM_SCRIPT } from "./passkeyAnswer.mjs";
import { caseAddress, specOf } from "./passkeyCases.mjs";
import { fetchReports, launchMatrixBrowser, pressInChooser, runSet, turnOnFerret } from "./passkeyMatrix.mjs";

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

if (SET !== "demo") test("virtual_authenticator_and_fixture_tls_work_in_both_channels", async () => {
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

// With the Ferret provider only (a stub run registers no such test, so it is never skipped there): a new passkey made by Ferret,
// with the person's "Save in Ferret" in Ferret's own window, is accepted by both relying parties: webauthn-rs (strict) and
// SimpleWebAuthn verify the registration on their servers. The page got the answer only after Ferret's server had the item.

// With the Ferret provider only (a stub run registers no such test, so it is never skipped there): a passkey made by Ferret, with the
// person's "Save in Ferret" in Ferret's own window, and used with a click on it, through the real broker and the MAIN script's own
// answer objects (no shim), with the three client codes: both relying parties verify the registration and the sign-in on their
// servers (webauthn-rs, strict, and SimpleWebAuthn). The page got the new passkey only after Ferret's server had the item.
if (PROVIDER === "ferret" && SET !== "demo") {
  test("client_libraries_accept_ferret_answers_through_the_broker", async (t) => {
    if (!selfTestPassed) {
      t.skip("the self-test did not pass");
      return;
    }
    for (const channel of channels()) {
      const session = await launchMatrixBrowser({ channel });
      try {
        await turnOnFerret(session, channel);
        for (const lib of /** @type {const} */ (["rs", "swa"])) {
          for (const client of /** @type {const} */ (["swa", "manual", "pubkey"])) {
            const c = { rp: { lib, client }, page: { chain: ["rp-a.test"] }, spec: { steps: ["create", "get"], user: { name: `ferret-${lib}-${client}`, displayName: "Ferret" }, get: { allow: "all" } } };
            const run = `ferret-libs-${Math.random().toString(16).slice(2, 10)}`;
            const address = caseAddress(c, { spec: specOf(c, run), auto: false });
            const main = await session.windowHandle();
            const baseline = new Set(await session.windowHandles());
            await session.navigate(address.url);
            await session.waitFor(() => session.content(() => document.documentElement.dataset.ready === "1"), 20_000, `the page ${address.url}`);
            // No shim: the answers are the passkey script's own objects.
            assert.equal(await session.content(() => typeof (/** @type {any} */ (window).__answered)), "undefined");
            const [go] = await session.findAll("#go");
            assert.ok(go, `#go on ${address.url}`);
            await session.click(go);
            /** @type {Set<string>} */
            const pressed = new Set();
            /** @type {Array<{ kind: string, role: string }>} */
            const presses = [];
            const done = await session.waitFor(async () => {
              presses.push(...(await pressInChooser(session, baseline, pressed, main)));
              return (await fetchReports(run)).find((r) => r.kind === "done");
            }, 90_000, `the report of ${address.url}`);
            const label = `${channel}: ${lib} with ${client}`;
            const reports = await fetchReports(run);
            assert.deepEqual(presses, [{ kind: "create", role: "passkey-create-new" }, { kind: "get", role: "passkey-candidate" }], `${label}: Ferret's window made the passkey and signed in with it`);
            assert.equal(done.ok, true, `${label}: ${JSON.stringify(reports.filter((r) => r.kind === "step").map((r) => ({ step: r.step, stage: r.stage, error: r.error })))}`);
            assert.equal(done.steps.length, 2, `${label}: create and sign-in both ran`);
            for (const s of done.steps) assert.equal(s.server?.ok, true, `${label}: the relying party verified the ${s.step}`);
            if (client === "pubkey") {
              const extras = done.steps[0].extras;
              assert.ok(extras.getPublicKey, `${label}: getPublicKey()`);
              assert.equal(extras.getPublicKeyAlgorithm, -7, `${label}: getPublicKeyAlgorithm()`);
              assert.ok(extras.getAuthenticatorData, `${label}: getAuthenticatorData()`);
              assert.ok(Array.isArray(extras.getTransports), `${label}: getTransports()`);
              assert.equal(extras.toJSON, true, `${label}: toJSON()`);
            }
            await session.waitFor(async () => (await session.windowHandles()).every((h) => baseline.has(h)), 20_000, `${label}: the window closed`);
          }
        }
      } finally {
        await session.quit();
      }
    }
  });
}

if (SET !== "demo") test("simplewebauthn_browser_and_manual_conversion_both_accept_the_answer", async (t) => {
  if (!selfTestPassed) {
    t.skip("the self-test did not pass, so the answer objects are not run");
    return;
  }
  const script = builderScript();
  for (const channel of channels()) {
    const session = await launchMatrixBrowser({ channel });
    try {
      for (const lib of /** @type {const} */ (["rs", "swa"])) {
        for (const client of /** @type {const} */ (["swa", "manual", "pubkey"])) {
          const c = { rp: { lib, client }, page: { chain: ["rp-a.test"] }, spec: { steps: ["create", "get"], user: { name: "alice", displayName: "Alice" } } };
          const run = `answers-${Math.random().toString(16).slice(2, 10)}`;
          const address = caseAddress(c, { spec: specOf(c, run), auto: false });
          await session.navigate(address.url);
          await session.waitFor(() => session.content(() => document.documentElement.dataset.ready === "1"), 20_000, `the page ${address.url}`);
          // The answer is built from what the virtual authenticator made, by the script's own builder, before the page's code runs.
          await session.content((/** @type {string} */ builder, /** @type {string} */ shim) => {
            for (const text of [builder, shim]) {
              const element = document.createElement("script");
              element.textContent = text;
              document.head.append(element);
            }
          }, script, SHIM_SCRIPT);
          const [go] = await session.findAll("#go");
          assert.ok(go, `#go on ${address.url}`);
          await session.click(go);
          const done = await session.waitFor(async () => (await fetchReports(run)).find((r) => r.kind === "done"), 30_000, `the report of ${address.url}`);
          const label = `${channel}: ${lib} with ${client}`;
          assert.equal(done.ok, true, `${label}: ${JSON.stringify(done.steps?.map((/** @type {any} */ s) => ({ step: s.step, stage: s.stage, error: s.error })))}`);
          assert.equal(done.steps.length, 2, `${label}: create and sign-in both ran`);
          assert.equal(await session.content(() => /** @type {any} */ (window).__answered), 2, `${label}: both answers were the script's objects`);
          if (client === "pubkey") {
            const extras = done.steps[0].extras;
            assert.ok(extras.getPublicKey, `${label}: getPublicKey()`);
            assert.equal(extras.getPublicKeyAlgorithm, -7, `${label}: getPublicKeyAlgorithm()`);
            assert.ok(extras.getAuthenticatorData, `${label}: getAuthenticatorData()`);
            assert.ok(Array.isArray(extras.getTransports), `${label}: getTransports()`);
            assert.equal(extras.toJSON, true, `${label}: toJSON()`);
          }
        }
      }
    } finally {
      await session.quit();
    }
  }
});

test("passkey_matrix_runs_every_selected_case_and_writes_the_report", async (t) => {
  if (!selfTestPassed && SET !== "demo") {
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


/** The name of the gate test for the set (the names of the plan's task U4-13). */
const GATE_NAME = /** @type {Record<string, string>} */ ({
  fixtures: "the_passkey_matrix_passes_in_release_and_esr_mv2_and_mv3",
  holdout: "the_holdout_set_passes",
  adversarial: "the_adversarial_pages_pass",
  demo: "the_demo_sites_pass",
})[SET];

test(`passkey_matrix_meets_the_gate: ${GATE_NAME}`, async (t) => {
  if (runs.size === 0) {
    t.skip("the matrix was not run");
    return;
  }
  for (const [channel, run] of runs) {
    const m = run.matrix;
    if (PROVIDER === "ferret" && SET === "demo") {
      // The demo sites are a smoke test (plan section 11.3): no unsafe answer, webauthn.io passes, and every other site either passes
      // or has a stated reason (a hand check, or a failure that is understood and has its issue); they are listed in the report.
      assert.equal(m.unsafe, 0, `${channel}: unsafe answers at a demo site`);
      assert.equal(m.rows.find((r) => r.id === "demo-webauthn-io")?.status, "passed", `${channel}: webauthn.io: ${JSON.stringify(m.rows.find((r) => r.id === "demo-webauthn-io")?.problems)}`);
      for (const r of m.rows.filter((x) => x.status !== "passed")) {
        assert.ok(r.problems.length > 0 && r.problems.every((x) => x.trim() !== ""), `${channel}: ${r.id} did not pass and says no reason`);
        console.error(`${channel}: demo ${r.id}: ${r.status}: ${r.problems.join("; ")}`);
      }
    } else if (PROVIDER === "ferret") {
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

test("no_unsafe_answer_in_any_run", (t) => {
  if (runs.size === 0) {
    t.skip("the matrix was not run");
    return;
  }
  const unsafe = [...runs].flatMap(([channel, run]) => run.matrix.rows.filter((r) => r.unsafe.length > 0).map((r) => ({ channel, id: r.id, unsafe: r.unsafe })));
  assert.deepEqual(unsafe, [], "unsafe answers");
});

// The sync cases of the fixtures, with the Ferret provider: two Firefox profiles signed in to one account.
if (PROVIDER === "ferret" && SET === "fixtures" && (GREP === "" || "sync-".includes(GREP) || GREP.startsWith("sync"))) {
  test("a_passkey_made_in_one_profile_signs_in_from_the_other", (t) => {
    if (runs.size === 0) {
      t.skip("the matrix was not run");
      return;
    }
    for (const [channel, run] of runs) {
      const rows = run.matrix.rows.filter((r) => r.category === "sync");
      assert.equal(rows.length, 2, `${channel}: the two sync cases ran`);
      assert.deepEqual(rows.filter((r) => r.status !== "passed").map((r) => ({ id: r.id, status: r.status, problems: r.problems })), [], `${channel}: the sync cases`);
    }
  });
}
