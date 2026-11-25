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
//   ferret  the extension answers: the runner also joins this run's end-to-end stack (the vault), signs the extension in there,
//           turns the passkey scripts on, and answers Ferret's window as a person would: it clicks the passkey the window lists
//           and, when the window asks for verification, gives the master password there. A case whose ceremony starts with a
//           create and then signs in gets its passkey from the vault's import instead (a test key that the page registers at
//           the relying party, put into a new item by the test build's `item_import_probe`), so a get does not depend on making
//           a passkey in Ferret. Cases that need what this runner cannot do yet (a passkey made by Ferret, a server cut off for
//           the extension, the popup of a conditional request) are reported as not run, with the reason.
//
// FERRET_PASSKEY_BRIDGE=1 (scripts/lanbox-ext.sh passkey-matrix --bridge) turns the test build's passkey scripts on before the
// first case (the permission for https pages with a click in the extension's own page, the setting, and the fixture's vault as
// the signed-in server). While the background hands every request back to the browser, the stub judgement then also shows that
// the bridge leaves each ceremony as the browser alone would end it; the runner counts the requests that went through the
// bridge, and a run in which none did proves nothing about it.
//
// A case that did not run counts as failed (UK125); nothing here ever turns "no result" into "passed".
import { writeFileSync } from "node:fs";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { startFirefox } from "./driver.mjs";
import { caseAddress, computeMatrix, loadCases, observe, specOf, writeReport } from "./passkeyCases.mjs";
import { BRIDGE_URL, defaultManifest, e2eCertificateFile, openBridge, xpiPath } from "./harness.mjs";
import { KEEP_BACKGROUND, extensionSignIn, webVaultAccount } from "./e2e.mjs";
import { revokeLeftDevices } from "./adversary.mjs";
import { core, grantHttps, pressInWindow, readWindow, registerTestKey, WINDOW_PAGE } from "./passkeyFerret.mjs";

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

/** Whether the test build's passkey scripts are turned on before the first case (see the head of the file). */
export const BRIDGE_ON = process.env.FERRET_PASSKEY_BRIDGE === "1";
/** The server the extension counts as signed in to when the scripts are on: the fixture's vault origin (left out by them). */
export const BRIDGE_SERVER = "https://vault-fixture.test";

/**
 * Turns the passkey scripts on in a tab of the extension's test bridge that stays open and counts the bridge's requests, and
 * comes back to the tab the session was in.
 * @param {import("./driver.mjs").Session} session
 * @returns {Promise<string>} the handle of the bridge tab
 */
export async function turnOnPasskeyScripts(session) {
  const back = await session.windowHandle();
  const tab = await session.newTab();
  await session.switchTo(tab);
  await session.navigate(BRIDGE_URL);
  await session.waitFor(() => session.content(() => document.documentElement.dataset.ready === "1"), 20_000, "the bridge page");
  await session.content(() => {
    const w = /** @type {any} */ (window);
    w.passkeyRequests = 0;
    browser.runtime.onMessage.addListener((/** @type {unknown} */ raw) => {
      try {
        if (JSON.parse(String(raw)).type === "passkey_request") w.passkeyRequests += 1;
      } catch {
        // Not a message of the bridge.
      }
      return undefined;
    });
    const button = document.createElement("button");
    button.id = "pk-grant";
    button.textContent = "grant";
    button.addEventListener("click", () => {
      browser.permissions.request({ origins: ["https://*/*"] }).then((ok) => { document.documentElement.dataset.pkGranted = String(ok); });
    });
    document.body.append(button);
  });
  const [button] = await session.findAll("#pk-grant");
  await session.click(button);
  const granted = await session.waitFor(() => session.content(() => document.documentElement.dataset.pkGranted), 15_000, "the permission for https pages");
  if (granted !== "true") throw new Error("the permission for https pages was not granted");
  await session.content((/** @type {string} */ server) => browser.storage.local.set({ use_passkeys: true, server }), BRIDGE_SERVER);
  // The background has no storage listener: the test build's `passkey_reconcile` makes the registration agree now.
  await session.content(() => new Promise((resolve, reject) => {
    const port = browser.runtime.connect({ name: "ferret-test-core" });
    const timer = setTimeout(() => reject(new Error("passkey_reconcile did not answer")), 15_000);
    port.onMessage.addListener((/** @type {any} */ reply) => {
      clearTimeout(timer);
      port.disconnect();
      if (reply?.ok) resolve(true);
      else reject(new Error(`passkey_reconcile: ${reply?.code}`));
    });
    port.postMessage({ id: "r1", op: "passkey_reconcile" });
  }));
  await session.waitFor(
    () => session.content(async () => (await browser.scripting.getRegisteredContentScripts({ ids: ["ferret-passkey-main", "ferret-passkey-bridge"] })).length === 2),
    15_000,
    "both passkey scripts registered",
  );
  await session.switchTo(back);
  return tab;
}

/** How many requests went through the bridge so far. @param {import("./driver.mjs").Session} session @param {string} tab */
export async function bridgeRequests(session, tab) {
  const back = await session.windowHandle();
  await session.switchTo(tab);
  try {
    return Number(await session.content(() => /** @type {any} */ (window).passkeyRequests ?? 0));
  } finally {
    await session.switchTo(back);
  }
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
export async function launchMatrixBrowser({ channel, manifest = defaultManifest(), headless = process.env.FERRET_HEADLESS !== "0", provider = "stub" }) {
  // With Ferret answering, the browser also trusts the stack's CA (the vault) and keeps the event page alive under a request.
  const e2e = provider === "ferret" ? e2eCertificateFile() : undefined;
  const certificateFiles = e2e ? [fixtureCaFile(), e2e] : [fixtureCaFile()];
  const prefs = provider === "ferret" ? { ...MATRIX_PREFS, ...KEEP_BACKGROUND } : { ...MATRIX_PREFS };
  const session = await startFirefox({ channel, headless, addon: xpiPath(manifest), hosts: [], certificateFiles, prefs });
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
 * Signs the extension in at this run's end-to-end stack and turns the passkey scripts on, in a tab of the extension's test bridge
 * that stays open; comes back to the tab the session was in.
 * @param {import("./driver.mjs").Session} session @param {string} channel
 * @returns {Promise<{ bridgeTab: string, password: string }>}
 */
export async function signInForFerret(session, channel) {
  const back = await session.windowHandle();
  if (!process.env.FERRET_E2E_CA_PEM) throw new Error("the Ferret provider needs the end-to-end stack (scripts/lanbox-ext.sh passkey-matrix --provider ferret)");
  const account = await webVaultAccount(session, channel);
  await revokeLeftDevices(session);
  const bridgeTab = await session.newTab();
  await session.switchTo(bridgeTab);
  const signed = await extensionSignIn(session, account);
  if (!signed.ok) throw new Error(`the sign-in of the extension failed: ${signed.text}`);
  const bridge = await openBridge(session);
  await grantHttps(session);
  await bridge.invoke("storage.local.set", { use_passkeys: true });
  await core(session, "passkey_reconcile");
  await session.waitFor(
    () => session.content(async () => (await browser.scripting.getRegisteredContentScripts({ ids: ["ferret-passkey-main", "ferret-passkey-bridge"] })).length === 2),
    15_000,
    "both passkey scripts registered",
  );
  await session.switchTo(back);
  return { bridgeTab, password: account.password };
}

/**
 * Why the Ferret provider cannot run a case yet, or null.
 * @param {any} c
 */
export function ferretCannot(c) {
  const steps = /** @type {string[]} */ (c.spec?.steps ?? ["create", "get"]);
  const seeded = steps.length === 2 && steps[0] === "create" && steps[1] === "get";
  if (steps.includes("create") && !seeded) return "the case needs a passkey made by Ferret (the create side is another task)";
  if (c.id.startsWith("vault-offline-") || c.id === "get-uv-preferred-no-verification") return "the case needs the server cut off for the extension (a switch the runner does not have yet)";
  if (c.id.startsWith("sync-")) return "the case needs a second browser profile";
  if (steps.includes("conditional") || (c.spec?.get?.mediation === "conditional" && c.expected.ceremony === "ok")) return "the case needs the popup's passkey part (another task)";
  return null;
}

/**
 * Answers Ferret's window as a person would: the first passkey the window lists, then (when the window asks for it) the master
 * password in the verification step. Leaves the session in the window's handle or a closed one; the caller switches back.
 * @param {import("./driver.mjs").Session} session @param {string} handle @param {string} password
 */
async function answerInWindow(session, handle, password) {
  await session.switchTo(handle);
  if (!(await session.currentUrl()).startsWith(`${WINDOW_PAGE}?r=`)) return;
  const shown = await readWindow(session);
  if (shown.candidates.length === 0) return;
  // The newest passkey is the one this case put into the vault (the window lists them oldest first); a page that lists no
  // credentials gets every passkey of the vault for its RP ID, the ones of earlier cases too.
  await new Promise((resolve) => setTimeout(resolve, 900));
  const rows = await session.findAll('[data-role="passkey-candidate"]');
  await session.click(rows[rows.length - 1]);
  const step = await session
    .waitFor(async () => {
      if (!(await session.windowHandles()).includes(handle)) return "closed";
      return (await session.findAll('[data-role="passkey-verify-password"]')).length > 0 ? "verify" : null;
    }, 15_000, "the window's answer or its verification step")
    .catch(() => "closed");
  if (step !== "verify") return;
  const [field] = await session.findAll('[data-role="passkey-verify-password"]');
  await session.type(field, password);
  await pressInWindow(session, "passkey-verify-password-submit");
}

/**
 * Runs one case in the session's selected tab.
 * @param {import("./driver.mjs").Session} session @param {any} c
 * @param {{ channel: string, provider: "stub" | "ferret", ferret?: { bridgeTab: string, password: string } | null }} o
 * @returns {Promise<import("./passkeyCases.mjs").CaseResult>}
 */
export async function runCase(session, c, { channel, provider, ferret = null }) {
  if (c.set === "demo") return { status: "not-run", reason: "the demo pages have no driver yet (the end-to-end spec of U4-13 brings it)" };
  if (provider === "ferret") {
    const cannot = ferretCannot(c);
    if (cannot !== null) return { status: "not-run", reason: cannot };
    if (ferret === null) return { status: "not-run", reason: "the extension is not signed in for the Ferret provider" };
  }
  if (provider === "stub" && c.needs === "provider") return { status: "not-run", reason: "the case needs Ferret to answer (a window, a verification or a navigation while a request waits); the stub provider cannot run it" };
  const run = `${Math.random().toString(16).slice(2, 10)}-${c.id}`.slice(0, 80);
  let spec = specOf(c, run);
  const main = await session.windowHandle();
  const baseline = new Set(await session.windowHandles());
  let windowsOpened = 0;
  /** Ferret's window was answered (once per case). */
  let answered = false;
  const answersInWindow = provider === "ferret" && c.expected.route === "ferret" && c.expected.ceremony === "ok";
  try {
    if (provider === "ferret" && ferret !== null && spec.steps[0] === "create") {
      // The passkey of the case comes from the vault's import: the page registers a test key at the relying party, and the key
      // goes into a new item; the case's ceremony then starts with its get.
      const host = /** @type {string} */ (c.page.chain[c.page.chain.length - 1]);
      await session.navigate(`https://${host}/ceremony.html`);
      await session.waitFor(() => session.content(() => document.documentElement.dataset.ready === "1"), 20_000, "the page of the relying party");
      const userName = spec.user?.name ?? "alice";
      const key = /** @type {any} */ (await registerTestKey(session, c.rp.lib, spec.rpId ?? host, userName));
      if (!key?.ok) return { status: "not-run", reason: `the test key could not be registered: ${JSON.stringify(key)}` };
      await session.switchTo(ferret.bridgeTab);
      try {
        await core(session, "item_import_probe", { name: `Matrix ${c.id}`.slice(0, 200), rp_id: spec.rpId ?? host, user_name: userName, cred_id: key.cred_id, user_handle: key.user_handle, key_pkcs8: key.key_pkcs8 });
      } finally {
        await session.switchTo(main);
      }
      spec = { ...spec, steps: spec.steps.slice(1), sid: key.sid };
    }
    const address = caseAddress(c, { spec, auto: c.gesture === "none" });
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
      const fresh = handles.filter((h) => !baseline.has(h));
      windowsOpened = Math.max(windowsOpened, fresh.length);
      if (answersInWindow && ferret !== null && !answered && fresh.length > 0) {
        answered = true;
        await answerInWindow(session, fresh[0], ferret.password).catch(() => {});
        await session.switchTo(main);
      }
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
    // A page that never started (a 404, a TLS error, a script error) is not a page that did nothing: it proves nothing, and the cases
    // that expect "nothing happened" must not pass on it.
    if (!reports.some((r) => r.kind === "started")) return { status: "not-run", reason: "the page never started (no report from it at all)" };
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
  if ((o.windowsOpened ?? 0) > (c.expected.maxWindows ?? 1)) out.push("too-many-windows");
  // A passkey made or used where the browser had to refuse the RP ID: the answer must be an error.
  if (c.expected.ceremony === "client-error" && c.expected.error === "SecurityError" && o.ceremony === "ok" && ids.has("signature-for-other-rp-id")) out.push("signature-for-other-rp-id");
  // A frame with a foreign ancestor or another origin than the top: Ferret must not answer.
  if (provider === "ferret" && c.expected.route === "browser" && o.windowShown && (ids.has("response-to-foreign-ancestor") || ids.has("response-to-other-frame"))) out.push("response-to-foreign-ancestor");
  return out;
}

/**
 * Runs a set in one Firefox of one channel and writes the report.
 * @param {{ channel: "release" | "esr", manifest: "mv3" | "mv2", set: "fixtures" | "adversarial" | "holdout" | "demo", grep?: string, provider?: "stub" | "ferret", outDir: string, log?: (line: string) => void }} o
 *   With BRIDGE_ON, `throughBridge` in the answer is the number of requests that went through the passkey bridge.
 */
export async function runSet({ channel, manifest, set, grep = "", provider = "stub", outDir, log = () => {} }) {
  /** The requests that went through the bridge (BRIDGE_ON), or null. @type {number | null} */
  let throughBridge = null;
  const { cases, problems } = selectCases(set, grep);
  if (problems.length) throw new Error(`the cases of ${set} have problems: ${problems.join("; ")}`);
  /** @type {Map<string, import("./passkeyCases.mjs").CaseResult>} */
  const results = new Map();
  /** @type {import("./driver.mjs").Session | undefined} */
  let session;
  try {
    const runnable = cases.some((c) => c.set !== "demo" && (provider === "ferret" ? ferretCannot(c) === null : c.needs !== "provider"));
    if (runnable) session = await launchMatrixBrowser({ channel, manifest, provider });
    const bridgeTab = session && BRIDGE_ON && provider === "stub" ? await turnOnPasskeyScripts(session) : null;
    const ferret = session && provider === "ferret" ? await signInForFerret(session, channel) : null;
    for (const c of cases) {
      const r = session ? await runCase(session, c, { channel, provider, ferret }) : await runCase(/** @type {any} */ (undefined), c, { channel, provider, ferret });
      results.set(c.id, r);
      const failing = r.observed?.reports?.find((/** @type {any} */ x) => x.kind === "step" && !x.ok);
      log(`${set} ${c.id}: ${r.status === "ran" ? JSON.stringify({ ceremony: r.observed?.ceremony, error: r.observed?.error, route: r.observed?.route, ...(failing ? { step: failing.step, message: failing.error?.message } : {}) }) : `not run (${r.reason})`}`);
    }
    if (session && bridgeTab !== null) throughBridge = await bridgeRequests(session, bridgeTab);
  } finally {
    if (session) await session.quit();
  }
  // A run of some cases (--grep) is not a run of the set: its gate is never met.
  const matrix = computeMatrix(cases, results, provider, grep === "");
  writeReport(outDir, matrix, { channel, manifest, set });
  return { cases, results, matrix, throughBridge };
}
