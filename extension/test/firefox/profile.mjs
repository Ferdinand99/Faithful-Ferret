// The test profile of the Firefox runs: preferences, the permanently installed
// test build, and the policies file that adds the certificate authorities of the
// fixture server and of the end-to-end stack.
//
// Only the test variant is installed here. It has its own add-on id and, through
// extensions.webextensions.uuids, a fixed moz-extension UUID, so a test can name
// the origin of the extension. Both are test-profile settings: a release package
// never holds them (scripts/check-ext-release.sh).
import { copyFileSync, existsSync, mkdirSync, mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

/** The add-on id of the test variant (extension/scripts/build.mjs, TEST_ID). */
export const TEST_ADDON_ID = "ferret-test@hedgerow.tools";

/** The UUID of the extension in the test profile, so its origin is moz-extension://<this>/. */
export const FIXED_UUID = "5c1d6b3e-2f8a-4d0c-9a57-3e7b1c9a4f10";

/** The Firefox builds in the runner image. */
export const FIREFOX_DIRS = Object.freeze({
  release: "/opt/firefox-release",
  esr: "/opt/firefox-esr",
});

/**
 * The preferences of the test profile.
 * @param {{ hosts?: string[], extra?: Record<string, string | number | boolean> }} [options]
 *   hosts: names that resolve to this machine without DNS; extra: more preferences
 * @returns {Record<string, string | number | boolean>}
 */
export function profilePrefs({ hosts = [], extra = {} } = {}) {
  return {
    // Unsigned test builds. Only the unbranded Release and ESR builds allow this.
    "xpinstall.signatures.required": false,
    // The extension is found at once in the profile folder and enabled, without a prompt.
    "extensions.autoDisableScopes": 0,
    "extensions.enabledScopes": 15,
    // The fixed UUID of the test build.
    "extensions.webextensions.uuids": JSON.stringify({ [TEST_ADDON_ID]: FIXED_UUID }),
    // The test profile accepts requests for optional permissions without a prompt.
    "extensions.webextOptionalPermissionPrompts": false,
    // Names of the fixture server: local, as in /etc/hosts of the runner.
    "network.dns.localDomains": hosts.join(","),
    // The container has no network and its user namespaces are limited.
    "security.sandbox.content.level": 0,
    // Nothing that phones home, and nothing that opens a page of its own.
    "app.update.auto": false,
    "app.update.enabled": false,
    "app.normandy.enabled": false,
    "browser.shell.checkDefaultBrowser": false,
    "browser.startup.page": 0,
    "browser.startup.homepage": "about:blank",
    "browser.aboutwelcome.enabled": false,
    "browser.newtabpage.enabled": false,
    "browser.tabs.warnOnClose": false,
    "browser.urlbar.quicksuggest.enabled": false,
    "browser.safebrowsing.malware.enabled": false,
    "browser.safebrowsing.phishing.enabled": false,
    "browser.region.network.url": "",
    "browser.search.update": false,
    "datareporting.policy.dataSubmissionEnabled": false,
    "datareporting.healthreport.uploadEnabled": false,
    "toolkit.telemetry.enabled": false,
    "toolkit.telemetry.reportingpolicy.firstRun": false,
    "extensions.update.enabled": false,
    "extensions.getAddons.cache.enabled": false,
    "extensions.systemAddon.update.enabled": false,
    "network.captive-portal-service.enabled": false,
    "network.connectivity-service.enabled": false,
    "network.http.speculative-parallel-limit": 0,
    "network.prefetch-next": false,
    "services.settings.server": "http://127.0.0.1:9/v1",
    "signon.rememberSignons": false,
    "startup.homepage_welcome_url": "",
    "startup.homepage_welcome_url.additional": "",
    ...extra,
  };
}

/** @param {unknown} value */
function prefValue(value) {
  if (typeof value === "string") return JSON.stringify(value);
  if (typeof value === "boolean" || typeof value === "number") return String(value);
  throw new Error(`profile: preference value ${String(value)} is not a string, number or boolean`);
}

/**
 * The text of a user.js file.
 * @param {Record<string, string | number | boolean>} prefs
 * @returns {string}
 */
export function userJs(prefs) {
  return `${Object.entries(prefs).map(([name, value]) => `user_pref(${JSON.stringify(name)}, ${prefValue(value)});`).join("\n")}\n`;
}

/**
 * Makes a profile folder: user.js and the add-on package, installed permanently by
 * placing it in the profile's extensions folder under its id (Firefox picks it up
 * on the first start and keeps it, as for any add-on installed into a profile).
 * @param {{ dir?: string, xpi: string, prefs: Record<string, string | number | boolean> }} options
 * @returns {string} the profile folder
 */
export function createProfile({ dir, xpi, prefs }) {
  const profile = dir ?? mkdtempSync(join(tmpdir(), "ferret-profile-"));
  mkdirSync(join(profile, "extensions"), { recursive: true });
  writeFileSync(join(profile, "user.js"), userJs(prefs));
  // Only the first time: a file that is already there is the installed add-on, and a restart leaves it alone.
  const target = join(profile, "extensions", `${TEST_ADDON_ID}.xpi`);
  if (!existsSync(target)) copyFileSync(xpi, target);
  return profile;
}

/**
 * The text of policies.json: no updates, no studies, no first-run pages and the
 * certificate authorities to trust (absolute file paths).
 * @param {string[]} certificateFiles
 * @returns {string}
 */
export function policiesJson(certificateFiles) {
  for (const file of certificateFiles) {
    if (!file.startsWith("/")) throw new Error(`profile: certificate path must be absolute: ${file}`);
  }
  const policies = {
    DisableAppUpdate: true,
    DisableTelemetry: true,
    DisableFirefoxStudies: true,
    DisablePocket: true,
    DisableSystemAddonUpdate: true,
    DontCheckDefaultBrowser: true,
    NoDefaultBookmarks: true,
    OverrideFirstRunPage: "",
    OverridePostUpdatePage: "",
    Certificates: { Install: certificateFiles },
  };
  return `${JSON.stringify({ policies }, null, 2)}\n`;
}

/**
 * Writes policies.json into the distribution folder of a Firefox build. Done each
 * time the browser starts (the file is read at startup), from the files that exist
 * then: the CA of the fixture server, which is made at start, and, in the run
 * against the end-to-end stack, that stack's CA.
 * @param {string} firefoxDir the install folder of the build
 * @param {string[]} certificateFiles
 */
export function writePolicies(firefoxDir, certificateFiles) {
  mkdirSync(join(firefoxDir, "distribution"), { recursive: true });
  writeFileSync(join(firefoxDir, "distribution", "policies.json"), policiesJson(certificateFiles));
}
