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
//   FERRET_FIXTURE_PORT port of the fixture server (default 8443)
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
export const TEST_COMMAND = "ferret-test-command";

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
  for (const channel of wanted) {
    if (channel !== "release" && channel !== "esr") throw new Error(`harness: channel ${channel} is not release or esr`);
  }
  return /** @type {("release" | "esr")[]} */ (wanted);
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
  shared ??= startFixtures({ sseIntervalMs: Number(process.env.FERRET_SSE_INTERVAL_MS ?? 10_000) });
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
 * @param {{ channel: "release" | "esr", manifest?: "mv3" | "mv2", prefs?: Record<string, string | number | boolean>, headless?: boolean, profileDir?: string }} options
 */
export async function launch({ channel, manifest = defaultManifest(), prefs, headless = process.env.FERRET_HEADLESS !== "0", profileDir }) {
  const server = await fixtures();
  const certificateFiles = [server.caFile];
  const e2e = e2eCertificateFile();
  if (e2e) certificateFiles.push(e2e);
  return startFirefox({
    channel,
    prefs,
    headless,
    addon: xpiPath(manifest),
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
