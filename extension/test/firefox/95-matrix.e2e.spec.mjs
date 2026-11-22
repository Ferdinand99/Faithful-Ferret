// The detection matrix in real Firefox, on the end-to-end stack (run by `scripts/lanbox-ext.sh matrix`; the plain
// `e2e` run leaves it out): the corpus of test/fixtures/forms against the extension, with the numbers of
// matrixReport.mjs written to FERRET_MATRIX_OUT as <channel>-<manifest>.json and matrix.md.
//
// - webdriver_key_actions_are_trusted_in_both_channels: the capture phase types with WebDriver, and the extension
//   counts only trusted input, so the run proves first that WebDriver's key events are trusted in both channels.
//   If they are not, this fails and the matrix test is skipped: there is no way round it in the test build.
// - matrix_fill_phase_runs_every_case_and_writes_the_baseline: every case, in the phases FERRET_MATRIX_PART names
//   (fill, capture or all; the capture phase needs the extension's offers and counts as not run until it has them),
//   over FERRET_MATRIX_SET (corpus or holdout), the cases whose id contains FERRET_MATRIX_GREP. The report is
//   what this test produces; it does not demand that the gate is met (the extension has to learn the cases first).
import assert from "node:assert/strict";
import { existsSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { after, test } from "node:test";
import { world } from "./adversary.mjs";
import { channels, defaultManifest, fixtures, launch, stopFixtures } from "./harness.mjs";
import { ENTRIES, caseUrl, casesOf, grantUrls, leave, locate, mergePhases, runCapturePhase, runFillPhase, runGeneratorPhase } from "./matrix.mjs";
import { computeMatrix, writeReport } from "./matrixReport.mjs";

after(() => stopFixtures());

const SET = process.env.FERRET_MATRIX_SET === "holdout" ? "holdout" : "corpus";
const PART = /** @type {"fill" | "capture" | "all"} */ (["fill", "capture", "all"].includes(process.env.FERRET_MATRIX_PART ?? "") ? process.env.FERRET_MATRIX_PART : "all");
const GREP = process.env.FERRET_MATRIX_GREP ?? "";
const OUT = process.env.FERRET_MATRIX_OUT ?? join(tmpdir(), "ferret-u2-matrix");
/** Set by the self-test when WebDriver's key events are trusted in every channel; the matrix test needs it. */
let trustedKeys = false;

test("webdriver_key_actions_are_trusted_in_both_channels", async () => {
  trustedKeys = false;
  for (const channel of channels()) {
    const session = await launch({ channel });
    try {
      const server = await fixtures();
      await session.navigate(server.url("forms.example.net", "/_selftest/"));
      await session.waitFor(() => session.content(() => document.readyState === "complete"), 15_000, "the self-test page");
      // A field in the page, one in a shadow root and one in a frame, typed into with real key actions; and a click.
      for (const id of ["#plain", "#deep", "#framed"]) {
        const el = await locate(session, id);
        assert.ok(el, `${channel}: ${id} is on the self-test page`);
        await session.type(el, "abc");
        await leave(session);
      }
      const button = await locate(session, "#btn");
      await session.click(button);
      await leave(session);
      /** @param {boolean} inFrame */
      const seen = async (inFrame) => {
        await leave(session);
        if (inFrame) {
          const [frame] = await session.findAll("#inner");
          await session.switchToFrame(frame);
        }
        try {
          return /** @type {Array<{ where: string, type: string, trusted: boolean }>} */ (JSON.parse(await session.content(() => document.documentElement.getAttribute("data-seen") ?? "[]")));
        } finally {
          await leave(session);
        }
      };
      const events = [...(await seen(false)), ...(await seen(true))];
      for (const where of ["plain", "deep", "framed"]) {
        for (const type of ["keydown", "input"]) {
          const these = events.filter((e) => e.where === where && e.type === type);
          assert.equal(these.length, 3, `${channel}: ${where}: three ${type} events for three keys (${JSON.stringify(these)})`);
        }
      }
      assert.ok(events.some((e) => e.type === "click" && e.where === "btn"), `${channel}: the click on the button was seen`);
      const untrusted = events.filter((e) => !e.trusted);
      assert.deepEqual(untrusted, [], `${channel}: WebDriver events that are not trusted, so the capture phase cannot be measured here (stop and ask)`);
    } finally {
      await session.quit();
    }
  }
  trustedKeys = true;
});

test("matrix_fill_phase_runs_every_case_and_writes_the_baseline", async (t) => {
  if (!trustedKeys) {
    // The numbers mean nothing without trusted key events (the extension counts only trusted input).
    t.skip("WebDriver key events are not shown to be trusted, so the matrix is not run");
    return;
  }
  const cases = casesOf(SET, GREP);
  assert.ok(cases.length > 0, `no case in ${SET} matches ${JSON.stringify(GREP)}`);
  const manifest = defaultManifest();
  for (const channel of channels()) {
    const server = await fixtures();
    const w = await world(channel, { grant: grantUrls(cases, server), entries: ENTRIES });
    try {
      // The entries are in the engine once a page they are for lists them.
      for (const [key, url] of /** @type {const} */ ([
        ["forms", caseUrl({ host: "forms.example.net", path: "/static/login.html" }, server)],
        ["wwwB", caseUrl({ host: "www.forms.example.net", path: "/static/login.html" }, server)],
        ["login", caseUrl({ host: "login.example.net", path: "/static/login.html" }, server)],
        ["domain", caseUrl({ host: "www.forms.example.org", path: "/static/login.html" }, server)],
      ])) {
        const tabId = await w.visit(url);
        await w.ui.open();
        try {
          await w.session.waitFor(async () => (await w.ui.body("candidates", { tab_id: tabId })).handles.some((/** @type {any} */ h) => h.name === w.named[key]), 60_000, `the entry ${key}`);
        } finally {
          await w.ui.close();
        }
      }
      // The vault check of the capture phase needs the item list of the sync engine: it has the matrix's entries.
      const vault = await w.vaultState();
      assert.equal(vault.running, true, `${channel}: the sync engine runs`);
      assert.ok(vault.rows.length >= Object.keys(ENTRIES).length, `${channel}: the vault lists its items (${vault.rows.length})`);
      assert.deepEqual(await w.vaultState(), vault, `${channel}: the item list stands still`);
      const log = (/** @type {string} */ line) => console.log(`# ${channel} ${line}`);
      const fill = PART === "capture" ? null : await runFillPhase(w, cases, log);
      const capture = PART === "fill" ? null : await runCapturePhase(w, cases, log);
      const generator = PART === "fill" ? null : await runGeneratorPhase(w, cases, log);
      const results = mergePhases(fill, capture, generator);
      assert.equal(results.length, cases.length, `${channel}: a result for every case`);
      for (const r of results) assert.ok(r.ran.fill || r.ran.capture || typeof r.error === "string", `${channel}: ${r.case.id} either ran or says why not`);

      const matrix = computeMatrix(results, { set: SET, part: PART, manifest, grep: GREP });
      writeReport(OUT, channel, matrix);
      assert.ok(existsSync(join(OUT, `${channel}-${manifest}.json`)), `${channel}: the report is written`);
      const text = readFileSync(join(OUT, "matrix.md"), "utf8");
      assert.ok(text.includes(`## ${channel} (${manifest})`), `${channel}: matrix.md has the run`);
      const pct = (/** @type {{ passed: number, total: number }} */ p) => `${p.passed}/${p.total}`;
      console.log(`# ${channel} ${manifest} ${SET}/${PART}: fill ${pct(matrix.fill)}, capture ${pct(matrix.capture)}, generator ${pct(matrix.generated)}, unsafe fills ${matrix.unsafeFills.length}, unsafe offers ${matrix.unsafeOffers.length}, not run ${matrix.notRun.length}, ${matrix.gate ? "GATE MET" : matrix.meta.part === "all" && !GREP ? "GATE NOT MET" : `partial run, no gate (the part is ${matrix.met ? "met" : "not met"})`}`);
    } finally {
      await w.quit();
    }
  }
});
