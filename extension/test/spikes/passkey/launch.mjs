// Starts Firefox with the Ferret test build and the passkey spike add-on side by
// side, and gives the spec the local relying parties and a control for the spike.
// Test-only.
import { copyFileSync, mkdirSync, mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { defaultManifest, fixtures, FIXED_UUID, launch, TEST_ADDON_ID } from "../../firefox/harness.mjs";
import { buildSpikeXpi, CONTROL_URL, SPIKE_ID, SPIKE_UUID } from "./build.mjs";
import { startRp } from "./rp.mjs";

export { CONTROL_URL, SPIKE_ID, SPIKE_UUID };

/** @type {Map<string, string>} */
const built = new Map();

/** The spike add-on for a manifest version, built once per process. @param {"mv3" | "mv2"} manifest @param {"granted" | "optional"} hosts */
function spikeXpi(manifest, hosts) {
  const key = `${manifest}/${hosts}`;
  let xpi = built.get(key);
  if (!xpi) {
    xpi = buildSpikeXpi({ manifest, hosts }).xpi;
    built.set(key, xpi);
  }
  return xpi;
}

/**
 * @param {{ channel: "release" | "esr", manifest?: "mv3" | "mv2", hosts?: "granted" | "optional", extraPrefs?: Record<string, string | number | boolean> }} options
 * @returns {Promise<import("../../firefox/driver.mjs").Session & { spikeProfile: string }>}
 */
export async function launchWithSpike({ channel, manifest = defaultManifest(), hosts = "granted", extraPrefs }) {
  const profileDir = mkdtempSync(join(tmpdir(), "ferret-passkey-profile-"));
  mkdirSync(join(profileDir, "extensions"), { recursive: true });
  copyFileSync(spikeXpi(manifest, hosts), join(profileDir, "extensions", `${SPIKE_ID}.xpi`));
  const session = await launch({
    channel,
    manifest,
    profileDir,
    prefs: {
      "extensions.webextensions.uuids": JSON.stringify({ [TEST_ADDON_ID]: FIXED_UUID, [SPIKE_ID]: SPIKE_UUID }),
      ...extraPrefs,
    },
  });
  return Object.assign(session, { spikeProfile: profileDir });
}

/** Ends the session and removes the profile. @param {{ quit: () => Promise<void>, spikeProfile: string }} session */
export async function endSession(session) {
  await session.quit();
  rmSync(session.spikeProfile, { recursive: true, force: true });
}

/**
 * Opens the control page of the spike in the selected tab and returns a caller.
 * @param {import("../../firefox/driver.mjs").Session} session
 */
export async function openControl(session) {
  await session.waitFor(() => session.addonInfo(SPIKE_ID), 30_000, "the spike add-on");
  // A tab of its own, so the page tab under test is never navigated away.
  const pageTab = await session.windowHandle();
  const controlTab = await session.newTab();
  await session.switchTo(controlTab);
  try {
    await session.navigate(CONTROL_URL);
    await session.waitFor(() => session.content(() => document.documentElement.dataset.ready === "1"), 20_000, "the control page");
  } finally {
    await session.switchTo(pageTab);
  }
  return {
    /** A real click on a button of the control page. @param {string} id */
    async press(id) {
      const back = await session.windowHandle();
      await session.switchTo(controlTab);
      try {
        const found = await session.findAll(`#${id}`);
        if (found.length !== 1) throw new Error(`control: no button ${id}`);
        await session.click(found[0]);
      } finally {
        await session.switchTo(back);
      }
    },
    /** What the control page published under data-<name>. @param {string} name */
    async published(name) {
      const back = await session.windowHandle();
      await session.switchTo(controlTab);
      try {
        return await session.content((/** @type {string} */ n) => document.body.getAttribute(`data-${n}`), name);
      } finally {
        await session.switchTo(back);
      }
    },
    /** @param {string} name @param {unknown} [args] */
    async call(name, args = null) {
      const back = await session.windowHandle();
      await session.switchTo(controlTab);
      try {
        const json = await session.content((/** @type {string} */ ctl, /** @type {string} */ list) => window.spikeControl.call(ctl, list), name, JSON.stringify(args));
        return JSON.parse(json);
      } finally {
        await session.switchTo(back);
      }
    },
  };
}

/**
 * The two local relying parties: http://localhost (matched by the static content
 * scripts) and https://fixture.test (matched only after the spec registers
 * scripts at run time), plus the control host that no script matches.
 */
export async function startRelyingParties() {
  const server = await fixtures();
  const tls = { key: readFileSync(join(server.dir, "server.key"), "utf8"), cert: readFileSync(join(server.dir, "server.pem"), "utf8") };
  const local = await startRp({ originFor: (port) => `http://localhost:${port}`, rpId: "localhost" });
  const dynamic = await startRp({ originFor: (port) => `https://fixture.test:${port}`, rpId: "fixture.test", tls });
  const unmatched = await startRp({ originFor: (port) => `https://second.fixture.test:${port}`, rpId: "second.fixture.test", tls });
  return {
    local, dynamic, unmatched,
    urlOf: (/** @type {Awaited<ReturnType<typeof startRp>>} */ one, path = "/") => `${one.rp.origin}${path}`,
    async close() {
      await Promise.all([local.close(), dynamic.close(), unmatched.close()]);
    },
  };
}
