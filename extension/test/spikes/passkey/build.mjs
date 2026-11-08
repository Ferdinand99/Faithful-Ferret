// Builds the passkey spike add-on (test-only; nothing here is part of the Ferret
// build, and the release check refuses anything under test/). The spec installs it
// beside the Ferret test build in a profile of its own.
//
//   buildSpikeXpi({ manifest: "mv3" | "mv2", hosts?: "granted" | "optional" }) -> { xpi, id, uuid }
//
// The same files make both manifest versions. They differ only in the keys that
// MV3 and MV2 spell differently: the manifest version,
// host permissions and the background page.
import { mkdirSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { packZip } from "../../../scripts/lib/archive.mjs";

const here = dirname(fileURLToPath(import.meta.url));
const addonDir = join(here, "addon");

export const SPIKE_ID = "ferret-passkey-spike@hedgerow.tools";
export const SPIKE_UUID = "7d0a3b52-91c4-4e6f-8a1d-2b5c6e9f0a38";
export const SPIKE_ORIGIN = `moz-extension://${SPIKE_UUID}`;
export const CONTROL_URL = `${SPIKE_ORIGIN}/control.html`;

/** Files of the add-on, from addon/. */
const FILES = ["authenticator.mjs", "background.mjs", "control.html", "control.mjs", "main-world.js", "relay.js"];

/** Pages that the static content scripts match: the local relying party on localhost. */
export const STATIC_MATCHES = ["http://localhost/*"];
/** Pages that the spec registers at run time (scripting.registerContentScripts). */
export const DYNAMIC_MATCHES = ["https://fixture.test/*"];
/** A page that no script matches: the control for "the override is not there". */
export const UNMATCHED_HOST = "second.fixture.test";

/**
 * @param {{ manifest: "mv3" | "mv2", hosts?: "granted" | "optional" }} options
 *   hosts: "granted" lists the hosts as host permissions; "optional" lists them as optional host permissions only
 * @returns {Record<string, any>}
 */
export function spikeManifest({ manifest, hosts: how = "granted" }) {
  const hosts = [...STATIC_MATCHES, ...DYNAMIC_MATCHES, `https://${UNMATCHED_HOST}/*`];
  const scripts = [
    { matches: STATIC_MATCHES, js: ["main-world.js"], run_at: "document_start", world: "MAIN", all_frames: true, match_about_blank: true },
    { matches: STATIC_MATCHES, js: ["relay.js"], run_at: "document_start", all_frames: true, match_about_blank: true },
  ];
  const base = {
    name: "Ferret passkey spike (test only)",
    version: "0.0.1",
    description: "Spike: can a Firefox extension act as a passkey provider? Never part of a release.",
    browser_specific_settings: { gecko: { id: SPIKE_ID, strict_min_version: "128.0", data_collection_permissions: { required: ["none"] } } },
    content_scripts: scripts,
  };
  const optional = how === "optional";
  if (manifest === "mv3") {
    return {
      manifest_version: 3, ...base, background: { scripts: ["background.mjs"], type: "module" }, permissions: ["scripting", "storage", "webNavigation"],
      ...(optional ? { optional_host_permissions: ["https://*/*", "http://localhost/*"] } : { host_permissions: hosts }),
    };
  }
  return {
    manifest_version: 2, ...base, background: { page: "background.html" },
    permissions: ["scripting", "storage", "webNavigation", ...(optional ? [] : hosts)],
    ...(optional ? { optional_permissions: ["https://*/*", "http://localhost/*"] } : {}),
  };
}

/** The MV2 background page: MV2 has no `type: "module"` for background scripts. */
const MV2_BACKGROUND = "<!doctype html>\n<html><head><meta charset=\"utf-8\"><script type=\"module\" src=\"background.mjs\"></script></head><body></body></html>\n";

/**
 * @param {{ manifest: "mv3" | "mv2", hosts?: "granted" | "optional", dir?: string }} options
 * @returns {{ xpi: string, id: string, uuid: string }}
 */
export function buildSpikeXpi({ manifest, hosts, dir }) {
  const out = dir ?? mkdtempSync(join(tmpdir(), "ferret-passkey-spike-"));
  mkdirSync(out, { recursive: true });
  /** @type {Map<string, Uint8Array>} */
  const files = new Map(FILES.map((name) => [name, readFileSync(join(addonDir, name))]));
  files.set("manifest.json", Buffer.from(`${JSON.stringify(spikeManifest({ manifest, hosts }), null, 2)}\n`));
  if (manifest === "mv2") files.set("background.html", Buffer.from(MV2_BACKGROUND));
  const xpi = join(out, `passkey-spike-${manifest}-${hosts ?? "granted"}.xpi`);
  writeFileSync(xpi, packZip(files));
  return { xpi, id: SPIKE_ID, uuid: SPIKE_UUID };
}
