// What a Firefox spec needs: the pinned versions the runner image holds, the
// fixture server, the test build's package and a way to start Firefox with them.
//
//   import { channels, launch, fixtures } from "./harness.mjs";
//
// Environment (set by scripts/lanbox-ext.sh and the workflow):
//   FERRET_CHANNELS     "release", "esr" or "release,esr" (default: both)
//   FERRET_MANIFEST     "mv3" (default) or "mv2": the build the default launch installs
//   FERRET_HEADLESS     "0" runs with a window (under Xvfb); default headless
//   FERRET_E2E_CA_PEM   the certificate authority of the end-to-end stack, to trust as well
//   FERRET_E2E_SETUP_TOKEN  the setup token of a fresh end-to-end stack (its first account is made with it)
//   FERRET_FIXTURE_PORT, FERRET_FIXTURE_ALT_PORT, FERRET_FIXTURE_HTTP_PORT
//                       the fixture server's https, second https and http ports
//                       (defaults 443, 8443 and 80, so the test sites have ordinary origins)
//   FERRET_FIREFOX_RELEASE, FERRET_FIREFOX_ESR, FERRET_GECKODRIVER, FERRET_NODE
//                       the pinned versions (the runner image sets them)
//
// `node harness.mjs hosts` prints the /etc/hosts lines for the fixture hosts.
import { existsSync, mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { startFirefox } from "./driver.mjs";
import { startFixtures, readHosts } from "./fixtures-server.mjs";
import { TEST_COMMAND_ID } from "../../scripts/lib/testIds.mjs";
import { FIXED_UUID, TEST_ADDON_ID } from "./profile.mjs";

export { FIXED_UUID, TEST_ADDON_ID, readHosts };

const here = dirname(fileURLToPath(import.meta.url));
const extensionRoot = resolve(here, "..", "..");

/** The origin of the test build's pages. */
export const EXTENSION_ORIGIN = `moz-extension://${FIXED_UUID}`;
/** The test bridge page (extension/test/bridge.html, shipped by the test variant only). */
export const BRIDGE_URL = `${EXTENSION_ORIGIN}/test/bridge.html`;
/** An ordinary page of the extension. */
export const ABOUT_URL = `${EXTENSION_ORIGIN}/pages/about.html`;
/** The shortcut and the menu item that the test variant registers (manifest/test-parts). */
export const TEST_SHORTCUT = "Alt+Shift+F9";
export const TEST_COMMAND = TEST_COMMAND_ID;

/** The versions that the runner image was made with. @returns {Record<"release" | "esr" | "geckodriver" | "node", string>} */
export function pinnedVersions() {
  const read = (/** @type {string} */ name) => {
    const value = process.env[name];
    if (!value) throw new Error(`harness: ${name} is not set (the runner image sets the pinned versions)`);
    return value;
  };
  return {
    release: read("FERRET_FIREFOX_RELEASE"),
    esr: read("FERRET_FIREFOX_ESR"),
    geckodriver: read("FERRET_GECKODRIVER"),
    node: read("FERRET_NODE"),
  };
}

/** The channels of this run. @returns {("release" | "esr")[]} */
export function channels() {
  const wanted = (process.env.FERRET_CHANNELS ?? "release,esr").split(",").map((c) => c.trim()).filter(Boolean);
  if (wanted.length === 0) throw new Error("harness: FERRET_CHANNELS names no channel (a run with none would pass without testing anything)");
  for (const channel of wanted) {
    if (channel !== "release" && channel !== "esr") throw new Error(`harness: channel ${channel} is not release or esr`);
  }
  return /** @type {("release" | "esr")[]} */ (wanted);
}

/**
 * The factor the timing bounds of the footprint specs are loosened by: 1 on a quiet machine (the build host, the gate), at most 2 on
 * the shared CI runners. Anything else (a word, `Infinity`, `1e9`, a negative number) is refused, because a large factor would
 * switch the bounds off without a word.
 * @param {string | undefined} [raw]
 * @returns {number}
 */
export function timingSlack(raw = process.env.FERRET_TIMING_SLACK) {
  if (raw === undefined || raw === "") return 1;
  const value = Number(raw);
  if (!Number.isFinite(value) || value < 1 || value > 2) throw new Error(`harness: FERRET_TIMING_SLACK is a number from 1 to 2, not ${JSON.stringify(raw)}`);
  return value;
}

/**
 * Presses the test shortcut and returns the command event once it reached the page's tab. Now and then the browser sends the
 * command to the extension's own tab first (the focus is not on the page yet): that event names a moz-extension address, and the
 * press is made again, up to three times. Any other event is returned as it is for the caller to judge; no event in ten
 * seconds is an error.
 * @param {{ clear: () => Promise<unknown>, press: () => Promise<unknown>, events: () => Promise<Array<Record<string, any>>> }} io
 * @returns {Promise<Record<string, any>>}
 */
export async function commandOnPage({ clear, press, events }) {
  for (let attempt = 1; ; attempt += 1) {
    await clear();
    await press();
    const until = Date.now() + 10_000;
    /** @type {Record<string, any> | undefined} */
    let command;
    while (command === undefined && Date.now() < until) {
      command = (await events()).find((e) => e.kind === "command");
      if (command === undefined) await new Promise((resolve) => setTimeout(resolve, 200));
    }
    if (command === undefined) throw new Error("harness: the shortcut gave no command event in ten seconds");
    if (attempt < 3 && typeof command.tabUrl === "string" && command.tabUrl.startsWith("moz-extension:")) {
      await new Promise((resolve) => setTimeout(resolve, 1000));
      continue;
    }
    return command;
  }
}

/** @returns {"mv3" | "mv2"} */
export function defaultManifest() {
  const value = process.env.FERRET_MANIFEST ?? "mv3";
  if (value !== "mv3" && value !== "mv2") throw new Error(`harness: manifest ${value} is not mv3 or mv2`);
  return value;
}

/** The unsigned test build, made by `node scripts/build.mjs --variant test`. @param {"mv3" | "mv2"} manifest */
export function xpiPath(manifest) {
  const file = join(extensionRoot, "dist", `ferret-firefox-${manifest}-test.xpi`);
  if (!existsSync(file)) throw new Error(`harness: ${file} is missing (build the test variant first)`);
  return file;
}

/** @type {Promise<import("./fixtures-server.mjs").Fixtures> | undefined} */
let shared;
/** The fixture server of this process, started on first use. */
export function fixtures() {
  shared ??= startFixtures({
    port: Number(process.env.FERRET_FIXTURE_PORT ?? 443),
    altPort: Number(process.env.FERRET_FIXTURE_ALT_PORT ?? 8443),
    httpPort: Number(process.env.FERRET_FIXTURE_HTTP_PORT ?? 80),
    sseIntervalMs: Number(process.env.FERRET_SSE_INTERVAL_MS ?? 10_000),
  });
  return shared;
}

/** Stops the fixture server, if one was started. */
export async function stopFixtures() {
  if (!shared) return;
  const server = await shared;
  shared = undefined;
  await server.close();
}

/** @type {string | undefined} */
let e2eCaFile;
/** The file of the end-to-end stack's CA, written once from FERRET_E2E_CA_PEM; undefined outside that run. */
export function e2eCertificateFile() {
  const pem = process.env.FERRET_E2E_CA_PEM;
  if (!pem) return undefined;
  if (!e2eCaFile) {
    e2eCaFile = join(mkdtempSync(join(tmpdir(), "ferret-e2e-ca-")), "e2e-ca.pem");
    writeFileSync(e2eCaFile, `${pem.trim()}\n`);
  }
  return e2eCaFile;
}

/**
 * Starts Firefox with the test build installed and the CAs of the fixture server
 * (and, in the end-to-end run, of that stack) trusted.
 * @param {{ channel: "release" | "esr", manifest?: "mv3" | "mv2", prefs?: Record<string, string | number | boolean>, headless?: boolean, profileDir?: string, addon?: string }} options
 *   addon: another package than the build of `manifest` (a test that changes the manifest on purpose)
 */
export async function launch({ channel, manifest = defaultManifest(), prefs, headless = process.env.FERRET_HEADLESS !== "0", profileDir, addon }) {
  const server = await fixtures();
  const certificateFiles = [server.caFile];
  const e2e = e2eCertificateFile();
  if (e2e) certificateFiles.push(e2e);
  return startFirefox({
    channel,
    prefs,
    headless,
    addon: addon ?? xpiPath(manifest),
    hosts: server.hosts,
    certificateFiles,
    profileDir,
  });
}

/**
 * Opens the test bridge in the selected tab and returns a caller for its API.
 * @param {import("./driver.mjs").Session} session
 */
export async function openBridge(session) {
  await session.navigate(BRIDGE_URL);
  await session.waitFor(() => session.content(() => document.documentElement.dataset.ready === "1"), 20_000, "the bridge page");
  const bridge = {
    /** @param {string} api @param {...unknown} args */
    async invoke(api, ...args) {
      const json = await session.content(
        (/** @type {string} */ name, /** @type {string} */ list) => window.ferretBridge.invoke(name, list),
        api,
        JSON.stringify(args),
      );
      return JSON.parse(json);
    },
    /** @returns {Promise<Record<string, any>[]>} */
    async events() {
      return JSON.parse(await session.content(() => window.ferretBridge.events()));
    },
    async clearEvents() {
      await session.content(() => window.ferretBridge.clearEvents());
    },
  };
  return bridge;
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  if (process.argv[2] === "hosts") {
    for (const host of readHosts().fixture) console.log(`127.0.0.1 ${host}`);
  } else {
    console.error("usage: node harness.mjs hosts");
    process.exit(2);
  }
}

/**
 * Opens one page of the settings view by pressing its row on the main screen (in the settings tab, or in the settings part of the
 * popup), and waits until the page is shown. The ids are the ones of the rows: capture, never, pin, passkeys, lock, credits.
 * @param {import("./driver.mjs").Session} session
 * @param {string} id
 */
export async function openSettingsPage(session, id) {
  const shown = (/** @type {string} */ css) =>
    session.content((/** @type {string} */ selector) => {
      const node = document.querySelector(selector);
      return node !== null && node.closest("[hidden]") === null && node.getClientRects().length > 0;
    }, css);
  const row = `[data-role="settings-row-${id}"]`;
  await session.waitFor(() => shown(row), 30_000, `the settings row ${id}`);
  const [button] = await session.findAll(row);
  if (!button) throw new Error(`no settings row ${id}`);
  await session.click(button);
  await session.waitFor(() => shown(`[data-role="settings-page"][data-page="${id}"]`), 15_000, `the settings page ${id}`);
}
