// The detection matrix in real Firefox, on the end-to-end stack (run by `scripts/lanbox-ext.sh matrix`; the plain
// `e2e` run leaves it out): the corpus of test/fixtures/forms against the extension, with the numbers of
// matrixReport.mjs written to FERRET_MATRIX_OUT as <channel>-<manifest>.json and matrix.md.
//
// - webdriver_key_actions_are_trusted_in_both_channels: the capture phase types with WebDriver, and the extension
//   counts only trusted input, so the run proves first that WebDriver's key events are trusted in both channels.
//   If they are not, this fails and the matrix test is skipped: there is no way round it in the test build.
// - matrix_fill_phase_runs_every_case_and_writes_the_baseline: every case, in the phases FERRET_MATRIX_PART names
//   (fill, capture or all; the capture phase needs the extension's offers and counts as not run until it has them),
//   over FERRET_MATRIX_SET (corpus, holdout or parity, the own-written autofill-parity suite), the cases whose id contains FERRET_MATRIX_GREP. The report is
//   what this test produces; it does not demand that the gate is met (the extension has to learn the cases first).
// - matrix_fill_rate_is_at_least_the_baseline: on a run of the whole corpus with the fill phase, in each channel, the
//   fill phase ran every positive case with a fill (the one-time-code cases too), filled at least as many of them as
//   the extension did before the detection module (FILL_BASELINE), and made no unsafe fill. It compares rates and the
//   unsafe fills, never the gate: a fill-only run has no gate.
// - The gate's own tests, each about the numbers of the run it follows, in every channel of the run. A run of a part
//   (FERRET_MATRIX_PART) asserts the part it measured; a run of some cases (FERRET_MATRIX_GREP) has no gate, so the rate tests
//   pass with a note saying so, and the gate script (lanbox-ext.sh gate) runs the whole sets. A test about the other set passes
//   with a note too (a skipped test would fail the run):
//     matrix_detection_is_at_least_95_percent_for_fill_and_capture_in_release_and_esr   (corpus)
//     no_positive_category_is_below_80_percent                                           (corpus)
//     holdout_detection_is_at_least_90_percent                                           (hold-out)
//     matrix_has_zero_unsafe_fills_and_zero_unsafe_offers                                (every run)
//     false_offers_on_benign_negatives_are_reported                                      (every run with a capture part)
import assert from "node:assert/strict";
import { existsSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { after, test } from "node:test";
import { world } from "./adversary.mjs";
import { EXTENSION_ORIGIN, channels, defaultManifest, fixtures, launch, stopFixtures } from "./harness.mjs";
import { ENTRIES, caseUrl, casesOf, grantUrls, leave, locate, mergePhases, runCapturePhase, runFillPhase, runGeneratorPhase } from "./matrix.mjs";
import { computeMatrix, writeReport } from "./matrixReport.mjs";

after(() => stopFixtures());

const SET = /** @type {"corpus" | "holdout" | "parity"} */ (["holdout", "parity"].includes(process.env.FERRET_MATRIX_SET ?? "") ? process.env.FERRET_MATRIX_SET : "corpus");
const PART = /** @type {"fill" | "capture" | "all"} */ (["fill", "capture", "all"].includes(process.env.FERRET_MATRIX_PART ?? "") ? process.env.FERRET_MATRIX_PART : "all");
const GREP = process.env.FERRET_MATRIX_GREP ?? "";
const OUT = process.env.FERRET_MATRIX_OUT ?? join(tmpdir(), SET === "parity" ? "ferret-u2-matrix-parity" : "ferret-u2-matrix");
/** Set by the self-test when WebDriver's key events are trusted in every channel; the matrix test needs it. */
let trustedKeys = false;
/**
 * The fill phase of the corpus as the extension did it before the detection module: 48 of the 55 positive cases with a
 * fill (the five one-time-code cases did not run then), with 18 unsafe fills.
 */
const FILL_BASELINE = Object.freeze({ passed: 48, total: 55 });
/** The numbers of each channel's run, for the baseline test. @type {Map<string, ReturnType<typeof computeMatrix>>} */
const runs = new Map();

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
      // Every lock clears the offers the extension holds, and a run of the whole corpus lasts longer than the default
      // "Lock after": the vault stays open for the day.
      await w.ui.open();
      try {
        await w.ui.body("settings", { lock_seconds: 86_400 });
      } finally {
        await w.ui.close();
      }
      // The capture phase needs "Offer to save passwords" on: the person turns it on in the settings tab with a real
      // click, which asks for access to https pages (the test profile accepts the request) and registers the script.
      if (PART !== "fill") {
        await w.session.navigate(`${EXTENSION_ORIGIN}/pages/settings.html`);
        await w.session.waitFor(() => w.session.content(() => document.body.dataset.ready === "1"), 15_000, "the settings page");
        const [toggle] = await w.session.findAll('[data-role="capture-switch"]');
        assert.ok(toggle, `${channel}: the settings page has the switch`);
        await w.session.click(toggle);
        await w.session.waitFor(() => w.session.content(() => document.querySelector('[data-role="capture-switch"]')?.getAttribute("aria-checked") === "true"), 15_000, "capture on");
        await w.session.switchTo(w.pageTab);
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

      // Nothing wrote to the vault between the cases or in the fill and generator passes either: the item list is what it
      // was before the phases (each case of the capture phase also compares its own before and after).
      assert.deepEqual(await w.vaultState(), vault, `${channel}: the vault changed during the run`);
      const matrix = computeMatrix(results, { set: SET, part: PART, manifest, grep: GREP });
      runs.set(channel, matrix);
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

test("matrix_fill_rate_is_at_least_the_baseline", (t) => {
  if (SET !== "corpus" || GREP !== "" || PART === "capture") {
    t.diagnostic("the baseline is about a fill phase over the whole corpus: nothing to compare in this run");
    return;
  }
  assert.ok(runs.size > 0, "the matrix ran (see the test before)");
  for (const channel of channels()) {
    const matrix = runs.get(channel);
    assert.ok(matrix, `${channel}: the matrix ran`);
    // Every positive case with a fill ran and counts, the one-time-code cases included.
    assert.equal(matrix.fill.total, FILL_BASELINE.total, `${channel}: positive cases with a fill`);
    const fillNotRun = matrix.misses.filter((m) => m.part === "fill" && m.reason.startsWith("did not run"));
    assert.deepEqual(fillNotRun, [], `${channel}: fill cases that did not run`);
    assert.ok(matrix.fill.passed / matrix.fill.total >= FILL_BASELINE.passed / FILL_BASELINE.total, `${channel}: fill ${matrix.fill.passed}/${matrix.fill.total} is below the baseline ${FILL_BASELINE.passed}/${FILL_BASELINE.total}`);
    assert.deepEqual(matrix.unsafeFills, [], `${channel}: unsafe fills`);
  }
});

// ------------------------------------------------------------------------ the gate's tests

/**
 * The numbers of the run, per channel, or null (with a note) when the test is not about this run: another set, or some cases
 * only (a run of some cases has no gate).
 * @param {import("node:test").TestContext} t @param {"corpus" | "holdout" | "parity"} set
 * @returns {Array<[string, ReturnType<typeof computeMatrix>]> | null}
 */
function numbersOf(t, set) {
  if (SET !== set) {
    t.diagnostic(`this test is about the ${set} set; this run is ${SET}`);
    return null;
  }
  if (GREP !== "") {
    t.diagnostic(`a run of the cases matching ${JSON.stringify(GREP)} has no gate`);
    return null;
  }
  assert.ok(runs.size > 0, "the matrix ran (see the test before)");
  return channels().map((channel) => {
    const matrix = runs.get(channel);
    assert.ok(matrix, `${channel}: the matrix ran`);
    return [channel, matrix];
  });
}

/** @param {{ passed: number, total: number }} p */
const share = (p) => `${p.passed}/${p.total}`;

test("matrix_detection_is_at_least_95_percent_for_fill_and_capture_in_release_and_esr", (t) => {
  const numbers = numbersOf(t, "corpus");
  if (numbers === null) return;
  for (const [channel, m] of numbers) {
    if (PART !== "capture") assert.ok(m.fill.rate !== null && m.fill.rate >= 0.95, `${channel}: fill ${share(m.fill)} is below 95 % (${m.misses.filter((x) => x.part === "fill").map((x) => x.id).join(", ")})`);
    if (PART !== "fill") {
      assert.ok(m.capture.rate !== null && m.capture.rate >= 0.95, `${channel}: capture ${share(m.capture)} is below 95 % (${m.misses.filter((x) => x.part === "capture").map((x) => x.id).join(", ")})`);
      // The generator pass is a measure of its own at the same level.
      assert.ok(m.generated.rate !== null && m.generated.rate >= 0.95, `${channel}: generator ${share(m.generated)} is below 95 %`);
    }
  }
});

test("no_positive_category_is_below_80_percent", (t) => {
  const numbers = numbersOf(t, "corpus");
  if (numbers === null) return;
  for (const [channel, m] of numbers) {
    const categories = Object.entries(m.perCategory);
    assert.ok(categories.length > 0, `${channel}: the report has categories`);
    const low = categories.filter(([, v]) => v.rate === null || v.rate < 0.8).map(([name, v]) => `${name} ${v.passed}/${v.total}`);
    assert.deepEqual(low, [], `${channel}: categories below 80 %`);
  }
});

/**
 * The hold-out cases whose written outcome a stated rule of the product forbids, each with the rule: the closed list of explained
 * misses. A sign-in that sends a request and leaves the form on screen, or whose submit nothing follows, has no outcome signal, and a
 * login is offered only after the page navigated or the form went away (a failed sign-in looks exactly like it); a post that lands on
 * another site is a landing page the script cannot run in, which counts as unknown and gives no login offer. The list changes only by
 * a logged ruling. Each of these cases must miss exactly the rule's way (the capture part, "no offer") and make nothing unsafe; one
 * that starts to pass fails the test, so that the list cannot go stale.
 * @type {Readonly<Record<string, "login-outcome-signal" | "cross-site-landing">>}
 */
const EXPLAINED_HOLDOUT = Object.freeze({
  "ho-controlled-react-en": "login-outcome-signal",
  "ho-login-noform-nb-fetch": "login-outcome-signal",
  "ho-login-noform-es-roleform": "login-outcome-signal",
  "ho-shadow-custom-slot-de": "login-outcome-signal",
  "ho-identifier-first-samepage-en": "login-outcome-signal",
  "ho-cross-action-de": "cross-site-landing",
});

test("holdout_detection_is_at_least_90_percent", (t) => {
  const numbers = numbersOf(t, "holdout");
  if (numbers === null) return;
  /** @param {{ passed: number, total: number }} p */
  const rate = (p) => (p.total === 0 ? "n/a" : `${((p.passed / p.total) * 100).toFixed(1)} %`);
  for (const [channel, m] of numbers) {
    // The explained misses: each is in the run, misses only by the rule's outcome, and makes nothing unsafe.
    for (const [id, rule] of Object.entries(EXPLAINED_HOLDOUT)) {
      assert.ok(m.cases.some((c) => c.id === id), `${channel}: the explained case ${id} is in the run`);
      if (PART === "fill") continue;
      const own = m.misses.filter((x) => x.id === id).map((x) => `${x.part}: ${x.reason}`);
      assert.deepEqual(own, ["capture: no offer"], `${channel}: ${id} must miss only as the rule says (${rule}); if it passes now, remove it from the list`);
      assert.deepEqual([...m.unsafeFills, ...m.unsafeOffers].filter((x) => x.id === id), [], `${channel}: ${id}: nothing unsafe`);
    }
    // Raw (every positive case) and adjusted (the explained ones taken out of the denominator), side by side.
    /** @param {"fill" | "capture"} part */
    const adjusted = (part) => {
      const counted = m.cases.filter((c) => c.class === "positive" && !(c.id in EXPLAINED_HOLDOUT) && (c[part] === "pass" || c[part] === "fail"));
      return { passed: counted.filter((c) => c[part] === "pass").length, total: counted.length };
    };
    const line = `${channel}: hold-out raw fill ${share(m.fill)} (${rate(m.fill)}), capture ${share(m.capture)} (${rate(m.capture)}); adjusted fill ${share(adjusted("fill"))} (${rate(adjusted("fill"))}), capture ${share(adjusted("capture"))} (${rate(adjusted("capture"))})`;
    console.log(`# ${line}`);
    t.diagnostic(line);
    if (PART !== "capture") assert.ok(adjusted("fill").total > 0 && adjusted("fill").passed / adjusted("fill").total >= 0.9, `${channel}: hold-out adjusted fill is below 90 % (${m.misses.filter((x) => x.part === "fill").map((x) => x.id).join(", ")})`);
    if (PART !== "fill") assert.ok(adjusted("capture").total > 0 && adjusted("capture").passed / adjusted("capture").total >= 0.9, `${channel}: hold-out adjusted capture is below 90 % (${m.misses.filter((x) => x.part === "capture" && !(x.id in EXPLAINED_HOLDOUT)).map((x) => x.id).join(", ")})`);
  }
});

test("parity_detection_is_at_least_90_percent_for_fill_capture_and_generator", (t) => {
  const numbers = numbersOf(t, "parity");
  if (numbers === null) return;
  for (const [channel, m] of numbers) {
    const missesOf = (/** @type {string} */ part) => m.misses.filter((x) => x.part === part).map((x) => x.id).join(", ");
    if (PART !== "capture") assert.ok(m.fill.rate !== null && m.fill.rate >= 0.9, `${channel}: parity fill ${share(m.fill)} is below 90 % (${missesOf("fill")})`);
    if (PART !== "fill") {
      assert.ok(m.capture.rate !== null && m.capture.rate >= 0.9, `${channel}: parity capture ${share(m.capture)} is below 90 % (${missesOf("capture")})`);
      assert.ok(m.generated.rate !== null && m.generated.rate >= 0.9, `${channel}: parity generator ${share(m.generated)} is below 90 % (${missesOf("generator")})`);
    }
    assert.deepEqual(m.notRun, [], `${channel}: parity cases that did not run`);
  }
});

test("matrix_has_zero_unsafe_fills_and_zero_unsafe_offers", () => {
  // Also for a run of some cases: safety does not wait for a gate. A case that did not run counts as failed.
  assert.ok(runs.size > 0, "the matrix ran (see the test before)");
  for (const channel of channels()) {
    const m = runs.get(channel);
    assert.ok(m, `${channel}: the matrix ran`);
    assert.deepEqual(m.unsafeFills.map((x) => `${x.id}: ${x.reason}${x.field ? ` in ${x.field}` : ""}`), [], `${channel}: unsafe fills`);
    assert.deepEqual(m.unsafeOffers.map((x) => `${x.id}: ${x.reason}`), [], `${channel}: unsafe offers`);
    assert.deepEqual(m.notRun, [], `${channel}: cases that did not run`);
  }
});

test("false_offers_on_benign_negatives_are_reported", (t) => {
  assert.ok(runs.size > 0, "the matrix ran (see the test before)");
  if (PART === "fill") {
    t.diagnostic("a fill-only run reads no offers");
    return;
  }
  const text = readFileSync(join(OUT, "matrix.md"), "utf8");
  assert.ok(text.includes("false offers (harmless negatives)"), "matrix.md has the line");
  for (const channel of channels()) {
    const m = runs.get(channel);
    assert.ok(m, `${channel}: the matrix ran`);
    if (m.falseOffers.rate !== null) assert.ok(Array.isArray(m.falseOffers.cases), `${channel}: the report lists them`);
    // The frozen corpus and the parity set have none; the hold-out set only reports them (its pages were written without sight of the detection).
    if ((SET === "corpus" || SET === "parity") && GREP === "") {
      assert.ok(m.falseOffers.rate !== null, `${channel}: the ${SET} set has harmless negative cases that ran`);
      assert.deepEqual(m.falseOffers.cases, [], `${channel}: false offers on harmless pages`);
    } else if (m.falseOffers.cases.length > 0) {
      t.diagnostic(`${channel}: false offers on ${m.falseOffers.cases.join(", ")}`);
    }
  }
});
