// The passkey matrix runner (U4): drives a real Firefox through the cases of test/fixtures/passkey (and the hold-out and
// demo sets) against the fixture container (test/passkey-rp), and hands what it saw to passkeyCases.mjs. Not a spec
// (run.sh picks up *.spec.mjs only); 96-passkey-matrix.e2e.spec.mjs uses it.
//
// The browser trusts the fixture's test CA (FERRET_PASSKEY_CA_PEM, written to a file for the profile's policies) and nothing
// else; the host names are the ones of the container's network (Docker DNS), never localDomains. A WebDriver virtual
// authenticator plays the platform authenticator. The PROVIDER says who answers a call that Ferret takes:
//
//   stub    nobody: the call goes the browser's way and the virtual authenticator answers. The route (Ferret or browser)
//           cannot be seen, so a case that expects Ferret is judged on what the page and the relying party saw, and
//           cases that need Ferret to answer (a window, a verification, a navigation while a request waits) are not run.
//           This is what U4-3 can do, and it proves the fixtures, the pages, the runner and the report.
//   ferret  the extension answers (U4-8 and later). Not wired yet: every case is reported as not run.
//
// A case that did not run counts as failed (UK125); nothing here ever turns "no result" into "passed".
import { writeFileSync } from "node:fs";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { startFirefox } from "./driver.mjs";
import { caseAddress, computeMatrix, loadCases, observe, specOf, writeReport } from "./passkeyCases.mjs";
import { defaultManifest, xpiPath } from "./harness.mjs";

const here = dirname(fileURLToPath(import.meta.url));

/** The directories of the sets. The hold-out set is written by another agent and copied in later (U4-13). */
export const SET_DIRS = Object.freeze({
  fixtures: resolve(here, "..", "fixtures", "passkey"),
  adversarial: resolve(here, "..", "fixtures", "passkey"),
  holdout: process.env.FERRET_PASSKEY_HOLDOUT_DIR ?? resolve(here, "..", "fixtures", "passkey-holdout"),
  demo: resolve(here, "..", "fixtures", "passkey", "demo"),
});

/** The preferences of the matrix's profile: the soft token answers (the virtual authenticator), the USB token does not. */
export const MATRIX_PREFS = Object.freeze({
  "security.webauth.webauthn_enable_softtoken": true,
  "security.webauth.webauthn_enable_usbtoken": false,
  // The names are the network's (Docker DNS), not a local override.
  "network.dns.localDomains": "",
});

/** @type {string | undefined} */
let caFile;
/** The file of the fixture's CA, written once from FERRET_PASSKEY_CA_PEM. */
export function fixtureCaFile() {
  const pem = process.env.FERRET_PASSKEY_CA_PEM;
  if (!pem) throw new Error("FERRET_PASSKEY_CA_PEM is not set (run through scripts/lanbox-ext.sh passkey-matrix, with the fixtures up)");
  if (!caFile) {
    caFile = join(mkdtempSync(join(tmpdir(), "ferret-passkey-ca-")), "passkey-rp-ca.pem");
    writeFileSync(caFile, `${pem.trim()}\n`);
  }
  return caFile;
}

/** The fixture container's base address, for the runner's own requests (reports). */
export const FIXTURE_BASE = process.env.FERRET_PASSKEY_BASE ?? "https://rp-a.test";

/** @param {number} ms */
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

/**
 * The cases of a set (those of the fixtures and adversarial sets share a folder and are told apart by `set`).
 * @param {"fixtures" | "adversarial" | "holdout" | "demo"} set @param {string} [grep] a text that the id contains
 * @returns {{ cases: any[], problems: string[] }}
 */
export function selectCases(set, grep = "") {
  const { cases, problems } = loadCases([SET_DIRS[set]]);
  return { cases: cases.filter((c) => c.set === set && c.id.includes(grep)), problems };
}

/**
 * Starts Firefox for the matrix: the fixture CA trusted, the soft token on, a virtual authenticator, the test build installed.
 * @param {{ channel: "release" | "esr", manifest?: "mv3" | "mv2", headless?: boolean }} o
 */
export async function launchMatrixBrowser({ channel, manifest = defaultManifest(), headless = process.env.FERRET_HEADLESS !== "0" }) {
  const session = await startFirefox({ channel, headless, addon: xpiPath(manifest), hosts: [], certificateFiles: [fixtureCaFile()], prefs: { ...MATRIX_PREFS } });
  await session.addVirtualAuthenticator();
  return session;
}

/** The reports of a run from the fixture server. @param {string} run */
export async function fetchReports(run) {
  const res = await fetch(`${FIXTURE_BASE}/api/report?run=${encodeURIComponent(run)}`);
  const body = /** @type {any} */ (await res.json());
  return /** @type {any[]} */ (body.reports ?? []);
}

/**
 * Enters the frames of a case's chain and returns when the ceremony page in the last one is ready.
 * @param {import("./driver.mjs").Session} session @param {{ id: string }[]} frames
 */
async function enterFrames(session, frames) {
  await session.switchToTopFrame();
  for (const frame of frames) {
    const el = await session.waitFor(async () => (await session.findAll(`#${frame.id}`))[0], 15_000, `the frame #${frame.id}`);
    await session.switchToFrame(el);
  }
  await session.waitFor(() => session.content(() => document.documentElement.dataset.ready === "1"), 20_000, "the ceremony page");
}

/**
 * Runs one case in the session's selected tab.
 * @param {import("./driver.mjs").Session} session @param {any} c @param {{ channel: string, provider: "stub" | "ferret" }} o
 * @returns {Promise<import("./passkeyCases.mjs").CaseResult>}
 */
export async function runCase(session, c, { channel, provider }) {
  if (c.set === "demo") return { status: "not-run", reason: "the demo pages have no driver yet (the end-to-end spec of U4-13 brings it)" };
  if (provider === "ferret") return { status: "not-run", reason: "the Ferret provider is not wired into the runner yet (U4-8 and later)" };
  if (c.needs === "provider") return { status: "not-run", reason: "the case needs Ferret to answer (a window, a verification or a navigation while a request waits); the stub provider cannot run it" };
  const run = `${Math.random().toString(16).slice(2, 10)}-${c.id}`.slice(0, 80);
  const spec = specOf(c, run);
  const address = caseAddress(c, { spec, auto: c.gesture === "none" });
  const main = await session.windowHandle();
  const baseline = new Set(await session.windowHandles());
  let windowsOpened = 0;
  try {
    await session.navigate(address.url);
    if (c.gesture === "click") {
      await enterFrames(session, address.frames);
      const [go] = await session.findAll("#go");
      if (!go) return { status: "not-run", reason: "the page has no #go button" };
      await session.click(go);
    }
    // Wait for the page's "done" report, counting the windows that appear meanwhile.
    const deadline = Date.now() + (c.waitMs ?? 20_000);
    /** @type {any[]} */
    let reports = [];
    for (;;) {
      await sleep(250);
      const handles = await session.windowHandles().catch(() => /** @type {string[]} */ ([]));
      windowsOpened = Math.max(windowsOpened, handles.filter((h) => !baseline.has(h)).length);
      reports = await fetchReports(run);
      if (reports.some((r) => r.kind === "done") || Date.now() > deadline) break;
    }
    // An adversarial page reports what it saw itself after the ceremony's "done": give it a moment (a page that threw, or that
    // went away, has none, and the checks of its case then say so).
    if (c.page.path?.startsWith("/adversarial/") && reports.some((r) => r.kind === "done")) {
      for (let i = 0; i < 20 && !reports.some((r) => r.kind === "adv"); i++) {
        await sleep(250);
        reports = await fetchReports(run);
      }
    }
    // A page that left (nav-before-click) or never answered has no "done": that is an outcome (ceremony none), not an error.
    const observed = observe(reports, { windowShown: windowsOpened > 0, windowsOpened });
    return { status: "ran", observed, unsafe: detectUnsafe(c, observed, provider), provider };
  } catch (e) {
    return { status: "not-run", reason: `the run threw: ${e instanceof Error ? e.message : String(e)}` };
  } finally {
    // Close what the case opened (a Ferret window, a popup the page made) and go back to the first tab.
    try {
      for (const h of await session.windowHandles()) {
        if (!baseline.has(h)) {
          await session.switchTo(h);
          await session.closeTab();
        }
      }
      await session.switchTo(main);
      await session.switchToTopFrame();
      await session.navigate("about:blank");
    } catch {
      // The next case starts with a fresh navigation anyway.
    }
  }
}

/**
 * The unsafe answers that can be seen from outside, whatever the provider. (What only Ferret's internals know, such as a
 * verification token, is measured by the specs of U4-6 to U4-8 and the end-to-end spec.)
 * @param {any} c @param {NonNullable<import("./passkeyCases.mjs").CaseResult["observed"]>} o @param {"stub" | "ferret"} provider
 * @returns {string[]}
 */
export function detectUnsafe(c, o, provider) {
  /** @type {string[]} */
  const out = [];
  const ids = new Set(c.unsafe.map((/** @type {any} */ u) => u.id));
  // A window although the page had no user activation.
  if (c.gesture === "none" && o.windowShown && ids.has("window-without-gesture")) out.push("window-without-gesture");
  // More windows than one at a time.
  if ((o.windowsOpened ?? 0) > (c.expected.maxWindows ?? 1)) out.push("response-to-other-frame");
  // A passkey made or used where the browser had to refuse the RP ID: the answer must be an error.
  if (c.expected.ceremony === "client-error" && c.expected.error === "SecurityError" && o.ceremony === "ok" && ids.has("signature-for-other-rp-id")) out.push("signature-for-other-rp-id");
  // A frame with a foreign ancestor or another origin than the top: Ferret must not answer.
  if (provider === "ferret" && c.expected.route === "browser" && o.windowShown && (ids.has("response-to-foreign-ancestor") || ids.has("response-to-other-frame"))) out.push("response-to-foreign-ancestor");
  return out;
}

/**
 * Runs a set in one Firefox of one channel and writes the report.
 * @param {{ channel: "release" | "esr", manifest: "mv3" | "mv2", set: "fixtures" | "adversarial" | "holdout" | "demo", grep?: string, provider?: "stub" | "ferret", outDir: string, log?: (line: string) => void }} o
 */
export async function runSet({ channel, manifest, set, grep = "", provider = "stub", outDir, log = () => {} }) {
  const { cases, problems } = selectCases(set, grep);
  if (problems.length) throw new Error(`the cases of ${set} have problems: ${problems.join("; ")}`);
  /** @type {Map<string, import("./passkeyCases.mjs").CaseResult>} */
  const results = new Map();
  /** @type {import("./driver.mjs").Session | undefined} */
  let session;
  try {
    const runnable = cases.some((c) => c.set !== "demo" && c.needs !== "provider" && provider === "stub");
    if (runnable) session = await launchMatrixBrowser({ channel, manifest });
    for (const c of cases) {
      const r = session ? await runCase(session, c, { channel, provider }) : await runCase(/** @type {any} */ (undefined), c, { channel, provider });
      results.set(c.id, r);
      const failing = r.observed?.reports?.find((/** @type {any} */ x) => x.kind === "step" && !x.ok);
      log(`${set} ${c.id}: ${r.status === "ran" ? JSON.stringify({ ceremony: r.observed?.ceremony, error: r.observed?.error, route: r.observed?.route, ...(failing ? { step: failing.step, message: failing.error?.message } : {}) }) : `not run (${r.reason})`}`);
    }
  } finally {
    if (session) await session.quit();
  }
  const matrix = computeMatrix(cases, results, provider);
  writeReport(outDir, matrix, { channel, manifest, set });
  return { cases, results, matrix };
}
