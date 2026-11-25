#!/usr/bin/env node
// Builds the Firefox extension: an unpacked folder and a deterministic .xpi.
//
//   node scripts/build.mjs --browser firefox --manifest mv3|mv2 --variant release|test
//                          [--features <list>] [--wasm lock|tree] [--wasm-tar <path>]
//                          [--wasm-commit <commit>] [--out <dir>]
//   node scripts/build.mjs --check-release [--web-root <web folder>] <.xpi or folder>...
//
// --features names the features that are on, separated by commas ("none" for
// none); without it a variant has its own default (DEFAULT_FEATURES). The
// features are `save` (saving and updating passwords from the extension and the
// password generator) and `unlock` (PIN and passkey unlock), both on in a release
// and in the test variant, and `passkeys` (Ferret as a passkey provider on web pages), on in the test variant only
// until it is released. The
// build writes shared/features.mjs with the result, and the release check
// refuses a release package with a feature on that a release does not have
// (RELEASE_FEATURES), with a feature off that it must have, without that file, or
// without the files of a feature that is on. A package for a test can still be
// built with `--features none`.
//
// 1. The WebAssembly package (only the files in WASM_FILES are used), from one of two sources
//    (--wasm, or FERRET_WASM_SOURCE; the default is lock):
//      lock  reads ../web/wasm.lock.json ({version, url, sha256}), fetches the published
//            ferret-core-wasm-web-<version>.tar.gz (or takes --wasm-tar) and checks its
//            SHA-256 against the lock. To move the pin, change web/wasm.lock.json.
//      tree  a test build only: a package built from the commit under test
//            (scripts/wasm-tree.sh). --wasm-tar and --wasm-commit are needed. The release
//            variant refuses it: a release package is built from the locked package only.
//    Next to the .xpi the build writes <name>.wasm.json, the record of the source:
//    {source, version, sha256} for lock and {source, commit, sha256} for tree.
// 2. Copies the files listed in shared.json from ../web/src to dist/shared/ and
//    writes dist/shared/MANIFEST.json (path -> SHA-256). An empty list writes
//    nothing, and not even the folder. The list is closed under import: a listed
//    file imports only listed files (a dynamic import() included), and no view,
//    route or service file is on it. The release check compares every listed
//    file in the package with its hash in MANIFEST.json.
// 3. Merges manifest/base.json, the overlay of the chosen manifest version and
//    manifest/parts/*.json (and, for the test variant only, manifest/test-parts/*.json). A part writes
//    the action as `action` (MV3); the MV2 build moves it into `browser_action`. A permission outside permissions.allow.json (its `release` section for the release variant) is a
//    build error, and so is a key that is never allowed (content_scripts,
//    web_accessible_resources, externally_connectable). The manifest declares
//    data_collection_permissions required: ["authenticationInfo"]: the extension
//    sends sign-in credentials and proofs to a server outside the browser (the
//    user's own), which Mozilla's definition of data transmission counts, so
//    "none" would be wrong. The test variant has its own add-on id. A release
//    carries gecko.update_url (lib/updates.mjs), the test variant none.
// 4. Merges src/locales/<lang>/<feature>.json and src/styles/<feature>.css. A
//    feature adds its own files and edits no shared file.
//    Writes background/handlers.gen.mjs (the register of background/handlers/*.handler.mjs),
//    background/variant.gen.mjs (what differs between release and test) and
//    shared/features.mjs (which features are on). The content
//    script and the modules it imports are joined into content/fill.inject.js, and, with `save` on, the capture script into
//    content/capture.inject.js (scripts/lib/classic.mjs). Anything
//    below a folder named test-only is left out of a release.
// 5. Refuses a relative import or page script whose file is not in the package, inline
//    script and style in HTML, source maps, files over 4 MiB that
//    are not .wasm, and, for the release variant, anything under test/.
// 6. Writes <out>/ferret-firefox-<mv>-<variant>/ and the .xpi next to it: sorted
//    names, a fixed time, fixed permissions, entries stored.
import {
  existsSync, mkdirSync, readdirSync, readFileSync, rmSync, statSync, writeFileSync,
} from "node:fs";
import { dirname, join, posix, relative, resolve, sep } from "node:path";
import { fileURLToPath } from "node:url";
import { packZip, readTarGz, readZip, sha256 } from "./lib/archive.mjs";
import {
  CAPTURE_BUNDLE, CAPTURE_ENTRY, CAPTURE_MAX_BYTES, CONTENT_BUNDLE, CONTENT_ENTRY, PASSKEY_BRIDGE_BUNDLE, PASSKEY_BRIDGE_ENTRY, PASSKEY_BRIDGE_MAX_BYTES,
  PASSKEY_MAIN_BUNDLE, PASSKEY_MAIN_ENTRY, PASSKEY_MAIN_MAX_BYTES, classicScript, contentMayInclude, passkeyBridgeMayInclude,
  passkeyMainMayInclude,
} from "./lib/classic.mjs";
import { danglingImports, importsOf } from "./lib/imports.mjs";
import { FIXED_UUID, TEST_COMMAND_ID, TEST_MENU_ITEM_ID } from "./lib/testIds.mjs";
import { RELEASE_ID, UPDATE_URL } from "./lib/updates.mjs";

export { sha256, RELEASE_ID, UPDATE_URL };

export const MAX_FILE_BYTES = 4 * 1024 * 1024;

/** The CSP of every extension page (design document, section 10.7). */
export const EXTENSION_CSP = "script-src 'self' 'wasm-unsafe-eval'; object-src 'self'; base-uri 'none'; frame-ancestors 'none'";

/** Added to the name of the test variant, so it cannot be mistaken for a release. */
export const TEST_NAME_SUFFIX = " (test)";

/**
 * The add-on id of every release is RELEASE_ID (lib/updates.mjs), and the test
 * variant has an id of its own, so a test build never shares storage with an
 * installed release. A release also carries the update manifest URL UPDATE_URL
 * (lib/updates.mjs) as gecko.update_url, which the build sets and no manifest file
 * may set; the test variant carries none.
 */
export const TEST_ID = "ferret-test@hedgerow.tools";

/**
 * The features a build turns on or off. `save`: saving and updating passwords from
 * the extension (the capture script, the offer in Ferret's UI, the generator).
 * A release has it on, and so has the test variant; a test build can turn it off (`--features none`) to prove that
 * "off" leaves no path of the feature in the package.
 * `unlock`: unlocking with a PIN or a passkey (the handlers, the unlock window, the controls, the PIN store). A release
 * has it on, and so has the test variant; a test build can turn it off (`--features save`) to prove that "off" leaves no
 * path of the feature in the package (the only trace is the deletion of the unlock database at start, so that a blob left
 * by an older build is removed).
 * `passkeys`: Ferret as a passkey provider on web pages (the MAIN-world script and its bridge, the chooser window, the
 * handlers, the popup's passkey section). It is on in the test variant only, until it is released; a release has it off,
 * and a package with it off holds no path of the feature. The only traces are the removal of a script registration that
 * an older build may have left (background/passkeyCleanup.mjs, which names the script ids for that and nothing else).
 */
export const FEATURES = Object.freeze(["save", "unlock", "passkeys"]);
/** The features each variant has on when --features does not say. */
export const DEFAULT_FEATURES = Object.freeze({
  release: Object.freeze(["save", "unlock"]),
  test: Object.freeze(["save", "unlock", "passkeys"]),
});
/** The features a release package has on, no more and no fewer: the release check refuses any other set. */
export const RELEASE_FEATURES = Object.freeze(["save", "unlock"]);
/** The generated module that tells the code of a package which features are on. */
export const FEATURES_FILE = "shared/features.mjs";
/**
 * The package files of the `save` feature (the capture script, joined, and the sources it is joined from). A package
 * with `save` off never holds one (the build leaves them out), and a release always does (the release check).
 */
export const SAVE_FILES = Object.freeze([CAPTURE_BUNDLE, "content/capture.mjs", CAPTURE_ENTRY]);
/**
 * The package files of the `unlock` feature: the window for a passkey unlock (its page, its script and the steps the script
 * runs, the one place with a WebAuthn call) and the one module that owns the PIN
 * store (the only code that opens the unlock database). A package with `unlock` off never holds one, and a release
 * that has the feature on always does (the release check). No file may import one of them by name: the build leaves
 * them out of a package with the feature off and refuses a package with a dangling import, and an import() with a
 * string literal counts as an import. Code reaches the PIN store and the window page only through the module that the
 * build generates, `background/unlockStore.gen.mjs` (unlockStoreModule): it re-exports the store when the feature is
 * on and says `null` when it is off. The handlers of the feature stay in the package and refuse when it is off.
 */
export const UNLOCK_FILES = Object.freeze(["pages/unlockWindow.html", "pages/unlockWindow.mjs", "pages/unlockWindowFlow.mjs", "background/localUnlock.mjs"]);
/**
 * The package files of the `passkeys` feature: the MAIN-world script and the bridge of the isolated world (each as a
 * joined classic script and as the module it is joined from), the answer objects, the chooser window, and the modules of
 * the background and the pages that only the feature uses. A package with `passkeys` off never holds one (the build leaves
 * them out), and a release never has them until the feature is released (the release check refuses any of them while
 * RELEASE_FEATURES lacks `passkeys`). No file that stays in a package may import one of them by name: the build refuses a
 * package with a dangling import. The handlers of the feature stay in the package and refuse when it is off. A change that
 * adds a file of the feature adds it here (test/unit/features.test.mjs reads this list, and its guard finds a file of the
 * feature that is missing from it). Code that stays in every package reaches the feature's modules only through the
 * generated `background/passkeys.gen.mjs` (passkeysModule).
 */
export const PASSKEY_FILES = Object.freeze([
  "content/passkey.main.inject.js",
  "content/passkey.bridge.inject.js",
  "content/passkey.main.entry.mjs",
  "content/passkey.bridge.entry.mjs",
  "content/passkeyResponse.mjs",
  "background/passkeyRegistry.mjs",
  "background/passkeyRequests.mjs",
  "background/passkeyFlow.mjs",
  "background/passkeyWrite.mjs",
  "background/passkeyVerify.mjs",
  "background/passkeyHandover.mjs",
  "pages/passkey.html",
  "pages/passkey.mjs",
  "pages/passkeyFlow.mjs",
  "pages/passkeyVerify.mjs",
  "pages/popupPasskeys.mjs",
  "shared/webauthnWire.mjs",
]);
/**
 * What a script registered in the page's own world looks like in code, in every spelling: `world: "MAIN"`, a quoted key as
 * JSON has it, and the enum `ExecutionWorld.MAIN`. A release without `passkeys` holds none of them.
 */
export const PAGE_WORLD_PATTERN = /["'`]?world["'`]?\s*:\s*(?:["'`]MAIN["'`]|[\w.]*\bMAIN\b)|ExecutionWorld\s*\.\s*MAIN/;
/** The ids under which the background registers the scripts of the `passkeys` feature. */
export const PASSKEY_SCRIPT_ID_PREFIX = "ferret-passkey-";
/** The one module that may name them in a package without the feature: it removes a registration an older build left. */
export const PASSKEY_CLEANUP_FILE = "background/passkeyCleanup.mjs";
/** The package files of each feature that has files of its own. */
export const FEATURE_FILES = Object.freeze({ save: SAVE_FILES, unlock: UNLOCK_FILES, passkeys: PASSKEY_FILES });

export const CONTENT_TYPES = Object.freeze({
  ".html": "text/html; charset=utf-8",
  ".mjs": "text/javascript; charset=utf-8",
  ".js": "text/javascript; charset=utf-8",
  ".json": "application/json; charset=utf-8",
  ".css": "text/css; charset=utf-8",
  ".svg": "image/svg+xml",
  ".wasm": "application/wasm",
});

/** Files of the published WASM package that the extension ships. */
export const WASM_FILES = [
  "js/client.mjs", "js/protocol.mjs", "js/vault.worker.mjs", "js/job.worker.mjs",
  "pkg-web/ferret_core_wasm.js", "pkg-web/ferret_core_wasm_bg.wasm",
];

/**
 * What the code of the `unlock` feature calls in the WASM package, by file: a release that has the feature on is built only
 * from a package that has all of it (a package from before the feature has none, and every PIN or passkey unlock in a
 * build made with it would fail at run time). Each entry is the name of an export that the glue file has as a function
 * or a method.
 */
export const UNLOCK_WASM_EXPORTS = Object.freeze({
  "pkg-web/ferret_core_wasm.js": Object.freeze(["argon2_pin_key", "confirm_password", "pin_unlock", "prf_methods", "prf_salt_new", "unlock_prf", "wrap_pin", "wrap_pin_key", "wrap_prf"]),
  "js/client.mjs": Object.freeze(["pinWrap"]),
});

/** The build refused the WASM package: it lacks what the feature needs. Exit status 3, so that a caller can tell it from any other failure. */
export class WasmLacksUnlockError extends Error {
  /** @param {string} message */
  constructor(message) {
    super(message);
    this.name = "WasmLacksUnlockError";
    this.exitCode = 3;
  }
}

/**
 * The names of UNLOCK_WASM_EXPORTS that a WASM package does not have.
 * @param {Map<string, Uint8Array>} tar the files of the package
 * @returns {string[]} `<file>: <name>` for each missing one
 */
export function wasmUnlockProblems(tar) {
  /** @type {string[]} */
  const missing = [];
  for (const [file, names] of Object.entries(UNLOCK_WASM_EXPORTS)) {
    const text = tar.has(file) ? Buffer.from(/** @type {Uint8Array} */ (tar.get(file))).toString("utf8") : "";
    for (const name of names) {
      // A function declaration, a method (a name at the start of a line, then its parameters) or a constant.
      if (!new RegExp(String.raw`function\s+${name}\s*\(|^[ \t]*(?:async\s+)?${name}\s*\(|\b${name}\s*=`, "m").test(text)) missing.push(`${file}: ${name}`);
    }
  }
  return missing;
}

/** Where the WASM package can come from (see the top of this file). */
export const WASM_SOURCES = Object.freeze(["lock", "tree"]);

/** @typedef {{ source: string, sha256: string, version?: string, commit?: string }} WasmRecord */

/** Single sources that only the test variant ships, by path below src/. Prefer a folder named test-only (below). */
export const TEST_ONLY_SRC = /** @type {string[]} */ ([]);

/**
 * The folder name that marks test-only code anywhere below src/ (and below
 * background/handlers/): a release build leaves such a file out, and the
 * release check refuses it. New test-only code goes in a folder of this name,
 * not on the list above.
 */
export const TEST_ONLY_DIR = "test-only";

/** @param {string} path a package path (posix) */
export const isTestOnlyPath = (path) => path.split("/").includes(TEST_ONLY_DIR);
/** Files below test/ that the test variant ships, to dist/test/. */
export const TEST_ONLY_FILES = ["test/bridge.html", "test/bridge.mjs", "test/capture-meter-start.js", "test/capture-meter-end.js"];
/** The host names of the fixture server and of the end-to-end stack: internal, never in a release. */
export const HOSTS_FILE = "test/fixtures/hosts.json";

/** Manifest keys that no part may carry. */
const FORBIDDEN_KEYS = ["content_scripts", "web_accessible_resources", "externally_connectable"];
const PERMISSION_KEYS = ["permissions", "optional_permissions", "host_permissions", "optional_host_permissions"];
const SORTED_ARRAYS = new Set(PERMISSION_KEYS);

/**
 * The top-level manifest keys a release package may carry, by manifest version.
 * This is the key set of the release manifests the build writes (the permission
 * lists are checked entry by entry against the release list of permissions.allow.json). A key outside
 * this list, such as a new content script declaration, is refused by the release
 * check even when it was added after the build.
 */
const COMMON_RELEASE_KEYS = [
  "background", "browser_specific_settings", "commands", "content_security_policy", "description", "icons",
  "manifest_version", "name", "optional_permissions", "options_ui", "permissions", "version",
];
/** The folder of the extension's icon artwork, copied to icons/ in the package (any .svg file in it). */
export const ICONS_DIR = "icons";
/** The sizes the manifest declares an icon for (the add-on list, and the toolbar button). */
export const ICON_SIZES = Object.freeze([16, 32, 48, 96, 128]);
/** The one options page: the settings, opened in a tab. */
const RELEASE_OPTIONS_PAGE = "pages/settings.html";

/** @param {unknown} value */
function isReleaseOptionsUi(value) {
  return isPlainObject(value) && Object.keys(value).length === 2 && value.page === RELEASE_OPTIONS_PAGE && value.open_in_tab === true;
}

/** The commands a release may declare: the fill shortcut (manifest/parts/commands.json), nothing else. */
export const RELEASE_COMMANDS = Object.freeze(["fill-login"]);
export const RELEASE_MANIFEST_KEYS = Object.freeze({
  2: Object.freeze([...COMMON_RELEASE_KEYS, "browser_action"].sort()),
  3: Object.freeze([...COMMON_RELEASE_KEYS, "action", "host_permissions", "optional_host_permissions"].sort()),
});

const here = dirname(fileURLToPath(import.meta.url));
const defaultRoot = resolve(here, "..");

// ----------------------------------------------------------------- helpers

/** @param {string} dir @returns {string[]} sorted names, [] when the folder is missing */
function listDir(dir) {
  return existsSync(dir) ? readdirSync(dir).sort() : [];
}

/** All files below `dir` as sorted posix paths relative to `dir`. @param {string} dir @returns {string[]} */
function walk(dir) {
  /** @type {string[]} */
  const out = [];
  /** @param {string} current */
  const visit = (current) => {
    for (const name of listDir(current)) {
      const full = join(current, name);
      if (statSync(full).isDirectory()) visit(full);
      else out.push(relative(dir, full).split(sep).join("/"));
    }
  };
  visit(dir);
  return out;
}

/** @param {string} file @returns {any} */
function readJson(file) {
  return JSON.parse(readFileSync(file, "utf8"));
}

/** @param {unknown} value @returns {value is Record<string, any>} */
function isPlainObject(value) {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

/** @param {string} a @param {string} b */
const compareText = (a, b) => (a < b ? -1 : a > b ? 1 : 0);

/**
 * Copies `value` with object keys in code unit order (arrays keep their order).
 * @param {any} value
 * @returns {any}
 */
function sortKeys(value) {
  if (Array.isArray(value)) return value.map(sortKeys);
  if (isPlainObject(value)) {
    return Object.fromEntries(Object.keys(value).sort(compareText).map((k) => [k, sortKeys(value[k])]));
  }
  return value;
}

/**
 * Merges `part` into `target`. Objects merge, arrays join without duplicates,
 * anything else that two files both set is an error.
 * @param {Record<string, any>} target
 * @param {Record<string, any>} part
 * @param {string} label
 * @param {string} [path]
 */
function mergeInto(target, part, label, path = "") {
  for (const [key, value] of Object.entries(part)) {
    const where = `${path}${key}`;
    if (!(key in target)) {
      target[key] = structuredClone(value);
    } else if (Array.isArray(target[key]) && Array.isArray(value)) {
      for (const item of value) {
        if (!target[key].some((/** @type {unknown} */ x) => JSON.stringify(x) === JSON.stringify(item))) target[key].push(structuredClone(item));
      }
    } else if (isPlainObject(target[key]) && isPlainObject(value)) {
      mergeInto(target[key], value, label, `${where}.`);
    } else {
      throw new Error(`${label}: ${where} is set in two manifest files`);
    }
  }
}

/** @param {string} entry a host permission or match pattern */
function isOrigin(entry) {
  return entry === "<all_urls>" || /^(?:\*|https?|wss?|ftp|file):\/\//.test(entry);
}

// ---------------------------------------------------------------- manifest

/**
 * The merged manifest, as an object. MV2 differs from MV3 in exactly these keys:
 * manifest_version; action / browser_action; content_security_policy (object /
 * string); background (scripts + type / page + persistent); host permissions
 * (host_permissions and optional_host_permissions / folded into permissions and
 * optional_permissions).
 * @param {{ browser: string, manifest: string, variant: string, root?: string }} options
 * @returns {Record<string, any>}
 */
export function buildManifest({ browser, manifest, variant, root = defaultRoot }) {
  if (browser !== "firefox") throw new Error(`browser "${browser}" is not supported (firefox)`);
  if (manifest !== "mv3" && manifest !== "mv2") throw new Error(`manifest "${manifest}" is not mv3 or mv2`);
  if (variant !== "release" && variant !== "test") throw new Error(`variant "${variant}" is not release or test`);
  const dir = join(root, "manifest");
  const allow = readPermissionAllow(root, variant);

  /** @type {Record<string, any>} */
  const merged = {};
  mergeInto(merged, readJson(join(dir, "base.json")), "manifest/base.json");
  mergeInto(merged, readJson(join(dir, `firefox-${manifest}.json`)), `manifest/firefox-${manifest}.json`);
  /** @type {string[]} */
  const partFiles = listDir(join(dir, "parts")).filter((n) => n.endsWith(".json"));
  for (const name of partFiles) {
    const part = readJson(join(dir, "parts", name));
    const label = `manifest/parts/${name}`;
    if (!isPlainObject(part)) throw new Error(`${label}: expected an object`);
    for (const key of FORBIDDEN_KEYS) {
      if (key in part) throw new Error(`${label}: ${key} is not allowed`);
    }
    mergeInto(merged, part, label);
  }
  if (variant === "test") {
    // Only the test variant: a test command and menu item, an options page and the permissions the browser probes need.
    for (const name of listDir(join(dir, "test-parts")).filter((n) => n.endsWith(".json"))) {
      const part = readJson(join(dir, "test-parts", name));
      const label = `manifest/test-parts/${name}`;
      if (!isPlainObject(part)) throw new Error(`${label}: expected an object`);
      for (const key of FORBIDDEN_KEYS) {
        if (key in part) throw new Error(`${label}: ${key} is not allowed`);
      }
      mergeInto(merged, part, label);
    }
  }
  for (const key of FORBIDDEN_KEYS) {
    if (key in merged) throw new Error(`manifest: ${key} is not allowed`);
  }

  // Permissions are written for MV3 (API names apart from origins) in every
  // file, and the MV2 build folds the origins into the plain lists below.
  for (const key of PERMISSION_KEYS) {
    const list = merged[key] ?? [];
    if (!Array.isArray(list) || !list.every((x) => typeof x === "string")) throw new Error(`manifest: ${key} must be a list of strings`);
    const wantOrigins = key.includes("host");
    for (const entry of list) {
      if (isOrigin(entry) !== wantOrigins) {
        throw new Error(`manifest: "${entry}" does not belong in ${key}`);
      }
      if (!allow[key].includes(entry)) {
        throw new Error(`manifest: permission "${entry}" (${key}) is not in manifest/permissions.allow.json`);
      }
    }
    if (key in merged) merged[key] = [...list].sort(compareText);
  }
  if (manifest === "mv2") {
    // A part names the action as MV3 does (`action`); MV2 calls it `browser_action`.
    if ("action" in merged) {
      merged.browser_action ??= {};
      mergeInto(merged.browser_action, merged.action, "manifest/parts (action)", "browser_action.");
      delete merged.action;
    }
    for (const [from, to] of [["host_permissions", "permissions"], ["optional_host_permissions", "optional_permissions"]]) {
      if (!(from in merged)) continue;
      merged[to] = [...(merged[to] ?? []), ...merged[from]].sort(compareText);
      delete merged[from];
    }
  }

  // The CSP is one constant; a file that spells it differently fails the build.
  const csp = manifest === "mv3" ? merged.content_security_policy?.extension_pages : merged.content_security_policy;
  if (csp !== EXTENSION_CSP) throw new Error("manifest: content_security_policy is not the extension CSP");
  if (manifest === "mv3" && Object.keys(merged.content_security_policy).length !== 1) {
    throw new Error("manifest: content_security_policy has a key other than extension_pages");
  }

  const pkg = readJson(join(root, "package.json"));
  merged.version = pkg.version;
  // The update URL comes from the build alone: a release gets UPDATE_URL, the test variant none.
  if (merged.browser_specific_settings?.gecko?.update_url !== undefined) {
    throw new Error("manifest: update_url is set by the build (a release gets UPDATE_URL), not by a manifest file");
  }
  if (variant === "test") {
    merged.name = `${merged.name}${TEST_NAME_SUFFIX}`;
    merged.browser_specific_settings.gecko.id = TEST_ID;
  } else {
    merged.browser_specific_settings.gecko.update_url = UPDATE_URL;
  }
  return sortKeys(merged);
}

// ------------------------------------------------------------------ checks

/** @param {string} label @param {string} html */
function checkHtml(label, html) {
  const scripts = [...html.matchAll(/<script\b([^>]*)>([\s\S]*?)<\/script\s*>/gi)];
  if ((html.match(/<script\b/gi) ?? []).length !== scripts.length) {
    throw new Error(`${label}: unclosed <script>`);
  }
  for (const [, attrs, body] of scripts) {
    if (!/\ssrc\s*=/i.test(` ${attrs}`) || body.trim() !== "") {
      throw new Error(`${label}: inline script is not allowed`);
    }
  }
  if (/<style\b/i.test(html)) throw new Error(`${label}: <style> is not allowed`);
  if (/[\s/]style\s*=/i.test(html)) throw new Error(`${label}: a style attribute is not allowed`);
  if (/[\s/]on[a-z]+\s*=/i.test(html))throw new Error(`${label}: an event handler attribute is not allowed`);
  if (/javascript:/i.test(html)) throw new Error(`${label}: javascript: is not allowed`);
  if (/(?:src|href)\s*=\s*["']?\s*(?:[a-z][a-z0-9+.-]*:)?\/\//i.test(html)) {
    throw new Error(`${label}: no remote resource is allowed`);
  }
}

/**
 * An icon is a picture and nothing else: no script, no event handler, no embedded
 * document, no reference to another file or a remote resource.
 * @param {string} label @param {string} svg
 */
function checkSvg(label, svg) {
  if (!/^\s*<svg\b/.test(svg)) throw new Error(`${label}: not an SVG document`);
  if (/<\s*(?:script|foreignObject|iframe|object|embed|image|use|a|style|animate|set)\b/i.test(svg)) throw new Error(`${label}: only shapes are allowed in an icon`);
  if (/<!(?:DOCTYPE|ENTITY)|<\?xml-stylesheet/i.test(svg)) throw new Error(`${label}: no DOCTYPE or ENTITY in an icon`);
  if (/[\s/]on[a-z]+\s*=|javascript:|(?:href|src)\s*=|url\(\s*["']?(?!#)/i.test(svg)) throw new Error(`${label}: an icon may not run code or name another resource`);
}

/** @param {string} path @param {Buffer} bytes */
function checkFile(path, bytes) {
  if (path.endsWith(".map")) throw new Error(`${path}: source maps are not allowed`);
  const ext = path.slice(path.lastIndexOf("."));
  if (!Object.hasOwn(CONTENT_TYPES, ext)) throw new Error(`${path}: file type is not allowed`);
  if (bytes.length > MAX_FILE_BYTES && ext !== ".wasm") throw new Error(`${path}: over 4 MiB`);
  if (ext === ".html") checkHtml(path, bytes.toString("utf8"));
  if (ext === ".svg") checkSvg(path, bytes.toString("utf8"));
  if ((ext === ".mjs" || ext === ".js" || ext === ".css") && /sourceMappingURL=/.test(bytes.toString("utf8"))) {
    throw new Error(`${path}: source map reference is not allowed`);
  }
}

/** Page and script files named in the manifest. @param {Record<string, any>} manifest @returns {string[]} */
function manifestFiles(manifest) {
  const action = manifest.action ?? manifest.browser_action;
  const bg = manifest.background ?? {};
  const icons = [manifest.icons, action?.default_icon].flatMap((map) => (isPlainObject(map) ? Object.values(map) : []));
  return [action?.default_popup, bg.page, ...(bg.scripts ?? []), manifest.options_ui?.page, ...icons].filter((p) => typeof p === "string");
}

/**
 * The internal host names (fixture server and end-to-end stack) from
 * test/fixtures/hosts.json. A missing or malformed file is an error, so a check
 * never passes for want of the list.
 * @param {string} [root] the extension folder
 * @returns {string[]} lower case host names
 */
export function readInternalHosts(root = defaultRoot) {
  const file = join(root, ...HOSTS_FILE.split("/"));
  if (!existsSync(file)) throw new Error(`${HOSTS_FILE} is missing (the release check needs the internal host names)`);
  const data = readJson(file);
  /** @type {string[]} */
  const hosts = [];
  for (const list of Object.values(data)) {
    if (!Array.isArray(list)) throw new Error(`${HOSTS_FILE}: every value must be a list of host names`);
    for (const host of list) {
      if (typeof host !== "string" || !/^[a-z0-9]([a-z0-9.-]*[a-z0-9])?$/.test(host)) throw new Error(`${HOSTS_FILE}: not a host name: ${JSON.stringify(host)}`);
      hosts.push(host);
    }
  }
  if (hosts.length === 0) throw new Error(`${HOSTS_FILE}: no host names`);
  return hosts;
}

/**
 * Whether a lower-case text names a host: the host at a label boundary, so
 * `a.github.io` is found in `https://a.github.io/` and `x.a.github.io` but not in
 * `mozilla.github.io`.
 * @param {string} lowerText
 * @param {string} host lower case
 * @returns {boolean}
 */
export function namesHost(lowerText, host) {
  let from = 0;
  for (;;) {
    const at = lowerText.indexOf(host, from);
    if (at < 0) return false;
    const before = at === 0 ? "" : lowerText[at - 1];
    const after = lowerText[at + host.length] ?? "";
    if (!/[a-z0-9-]/.test(before) && !/[a-z0-9-]/.test(after)) return true;
    from = at + 1;
  }
}

/**
 * The permission allow-list of a variant, from manifest/permissions.allow.json. The
 * file has the four lists of the test variant at its top level and a `release`
 * section with the lists a release may carry, which must be a subset of the first.
 * A missing or malformed file is an error, so a check never passes for want of it.
 * @param {string} [root] the extension folder
 * @param {string} [variant] "release" (the default) or "test"
 * @returns {Record<string, string[]>}
 */
export function readPermissionAllow(root = defaultRoot, variant = "release") {
  const file = join(root, "manifest", "permissions.allow.json");
  if (!existsSync(file)) throw new Error("manifest/permissions.allow.json is missing (the release check needs it)");
  const all = readJson(file);
  /** @param {unknown} lists @param {string} where @returns {Record<string, string[]>} */
  const shaped = (lists, where) => {
    if (!isPlainObject(lists)) throw new Error(`permissions.allow.json: ${where || "the file"} must be an object`);
    for (const key of PERMISSION_KEYS) {
      if (!Array.isArray(lists[key]) || !lists[key].every((x) => typeof x === "string")) {
        throw new Error(`permissions.allow.json: ${where}${key} must be a list of strings`);
      }
    }
    return /** @type {Record<string, string[]>} */ (lists);
  };
  const full = shaped(all, "");
  const release = shaped(all.release, "release.");
  for (const key of PERMISSION_KEYS) {
    for (const entry of release[key]) {
      if (!full[key].includes(entry)) throw new Error(`permissions.allow.json: release.${key} holds "${entry}", which the lists of the test variant do not`);
    }
  }
  return variant === "release" ? release : full;
}

/**
 * The problems in the manifest of a release package: a key outside the release key
 * list, one of the keys that are never allowed, a permission or host permission
 * outside the allow-list, and the test build's name and add-on id.
 * @param {string} text the content of manifest.json
 * @param {Record<string, string[]>} allow permissions.allow.json
 * @returns {string[]}
 */
function manifestProblems(text, allow) {
  /** @type {any} */
  let manifest;
  try {
    manifest = JSON.parse(text);
  } catch {
    return ["manifest.json is not valid JSON"];
  }
  if (!isPlainObject(manifest)) return ["manifest.json is not an object"];
  /** @type {string[]} */
  const problems = [];
  if (typeof manifest.name === "string" && manifest.name.endsWith(TEST_NAME_SUFFIX)) problems.push("manifest.json: the name is the test build's");
  const id = manifest.browser_specific_settings?.gecko?.id;
  if (id !== RELEASE_ID) problems.push(`manifest.json: the add-on id is ${JSON.stringify(id)}, a release has ${RELEASE_ID}`);
  // Firefox asks this URL for newer versions: exactly the one update manifest of the project, nothing else.
  const updateUrl = manifest.browser_specific_settings?.gecko?.update_url;
  if (updateUrl !== UPDATE_URL) problems.push(`manifest.json: the update_url is ${JSON.stringify(updateUrl)}, a release has ${UPDATE_URL}`);

  for (const key of FORBIDDEN_KEYS) {
    if (key in manifest) problems.push(`manifest.json: ${key} is not allowed in a release`);
  }
  const version = manifest.manifest_version;
  const keys = version === 2 || version === 3 ? RELEASE_MANIFEST_KEYS[version] : undefined;
  if (keys === undefined) problems.push(`manifest.json: manifest_version ${JSON.stringify(version)} is not 2 or 3`);
  for (const key of Object.keys(manifest)) {
    if (FORBIDDEN_KEYS.includes(key)) continue;
    if (keys !== undefined && !keys.includes(key)) problems.push(`manifest.json: the key ${key} is not in the release key list`);
  }

  if ("commands" in manifest) {
    if (!isPlainObject(manifest.commands)) problems.push("manifest.json: commands is not an object");
    else {
      for (const name of Object.keys(manifest.commands)) {
        if (!RELEASE_COMMANDS.includes(name)) problems.push(`manifest.json: the command ${name} is not a release command`);
      }
    }
  }

  // The settings page opens in a tab of its own, so it is an ordinary top-level page of the extension.
  if ("options_ui" in manifest && !isReleaseOptionsUi(manifest.options_ui)) {
    problems.push("manifest.json: options_ui is not the settings page opened in a tab");
  }

  // The CSP is one constant, in the shape of the manifest version.
  if (version === 3 || version === 2) {
    const expected = version === 3 ? { extension_pages: EXTENSION_CSP } : EXTENSION_CSP;
    if (JSON.stringify(manifest.content_security_policy) !== JSON.stringify(expected)) {
      problems.push(`manifest.json: content_security_policy is not the extension CSP${version === 3 ? " (an object with extension_pages only)" : " (a string)"}`);
    }
  }

  for (const key of PERMISSION_KEYS) {
    if (!(key in manifest)) continue;
    const list = manifest[key];
    if (!Array.isArray(list) || !list.every((x) => typeof x === "string")) {
      problems.push(`manifest.json: ${key} is not a list of strings`);
      continue;
    }
    // MV2 has no host permission keys: origins sit in permissions and optional_permissions.
    const allowed = new Set(allow[key]);
    if (version === 2 && !key.includes("host")) {
      for (const entry of allow[key.replace("permissions", "host_permissions")]) allowed.add(entry);
    }
    for (const entry of list) {
      if (!allowed.has(entry)) problems.push(`manifest.json: ${key} holds "${entry}", which is not in the release list of permissions.allow.json`);
    }
  }
  return problems;
}

/**
 * What a release package must not hold: test files, a fixed extension UUID, the
 * test name, an internal host name, anything under test/, a feature a release may
 * not have yet (featureProblems), and a manifest with a key or permission the
 * release does not have. Returns the problems, empty when clean.
 * @param {Map<string, Buffer>} files path -> bytes
 * @param {string[]} internalHosts host names of the fixture server and the end-to-end stack
 * @param {Record<string, string[]>} [permissionAllow] permissions.allow.json (the repository's own by default)
 * @param {string} [webRoot] the web vault folder: the shared copies are compared with its sources
 * @returns {string[]}
 */
export function releaseProblems(files, internalHosts, permissionAllow = readPermissionAllow(), webRoot = undefined) {
  if (!Array.isArray(internalHosts)) throw new Error("releaseProblems needs the list of internal host names");
  /** @type {string[]} */
  const problems = [];
  const testNames = new Set(TEST_ONLY_FILES.map((p) => p.slice(p.lastIndexOf("/") + 1)).concat(TEST_ONLY_SRC.map((p) => p.slice(p.lastIndexOf("/") + 1))));
  for (const [path, bytes] of files) {
    if (path.split("/").includes("test") || isTestOnlyPath(path)) problems.push(`${path}: test files are not allowed in a release`);
    else if (testNames.has(path.slice(path.lastIndexOf("/") + 1))) problems.push(`${path}: test-only file in a release`);
    if (/\.(?:html|mjs|js|json|css)$/.test(path)) {
      const text = bytes.toString("utf8");
      if (/moz-extension:\/\/[0-9a-f]{8}-[0-9a-f]{4}-/i.test(text)) problems.push(`${path}: a fixed extension UUID`);
      for (const id of [FIXED_UUID, TEST_COMMAND_ID, TEST_MENU_ITEM_ID]) {
        if (text.includes(id)) problems.push(`${path}: names the test-only id ${id}`);
      }
      if (text.includes("extensions.webextensions.uuids")) problems.push(`${path}: names the UUID preference of the test profile`);
      const lower = text.toLowerCase();
      for (const host of internalHosts) {
        if (namesHost(lower, host)) problems.push(`${path}: names the internal host ${host}`);
      }
    }
  }
  problems.push(...sharedProblems(files, webRoot));
  problems.push(...featureProblems(files));
  const raw = files.get("manifest.json");
  if (raw === undefined) problems.push("manifest.json is missing");
  else {
    problems.push(...manifestProblems(raw.toString("utf8"), permissionAllow));
    // Every icon the manifest names is in the package.
    try {
      for (const path of manifestFiles(JSON.parse(raw.toString("utf8")))) {
        if (!files.has(path)) problems.push(`manifest.json: ${path} is not in the package`);
      }
    } catch {
      // not valid JSON: manifestProblems said so
    }
  }
  return problems;
}

/**
 * What the record beside a built package (<name>.wasm.json, written by every build) says about its
 * WASM package: a release package comes from the locked package and nothing else. A package
 * without a record, a record of another source, and a record whose digest or version is not the
 * lock's are problems.
 * @param {string} target a .xpi or a folder
 * @param {string} webRoot the web folder that holds wasm.lock.json
 * @returns {string[]}
 */
export function wasmRecordProblems(target, webRoot) {
  const file = target.replace(/[\\/]+$/, "").replace(/\.xpi$/, "") + ".wasm.json";
  if (!existsSync(file)) return [`${file}: there is no record of where the WASM package came from (every build writes one)`];
  /** @type {WasmRecord} */
  let record;
  try {
    record = readJson(file);
  } catch {
    return [`${file}: not readable`];
  }
  if (record.source !== "lock") return [`${file}: the WASM package is from ${String(record.source)}, a release package uses the locked one`];
  const lock = readJson(join(webRoot, "wasm.lock.json"));
  /** @type {string[]} */
  const problems = [];
  if (record.sha256 !== lock.sha256) problems.push(`${file}: the WASM package is not the one in web/wasm.lock.json (digest)`);
  if (record.version !== lock.version) problems.push(`${file}: the WASM package is not the one in web/wasm.lock.json (version)`);
  return problems;
}

/**
 * Reads a built folder or .xpi into path -> bytes.
 * @param {string} target
 * @returns {Map<string, Buffer>}
 */
export function readPackage(target) {
  if (statSync(target).isDirectory()) {
    return new Map(walk(target).map((p) => [p, readFileSync(join(target, ...p.split("/")))]));
  }
  return readZip(readFileSync(target));
}

// ------------------------------------------------------------------- build

/** A view, route or service file of the web vault: never shared (they build that vault's screens). */
const NOT_SHARED = /(?:^|\/)(?:views|routes|services)\/|\.(?:route|service)\.mjs$/;

/**
 * @param {string} dir the extension folder
 * @param {{ webRoot: string, existing: Set<string> }} context
 * @returns {Map<string, Buffer>} path in dist -> bytes, and the list for MANIFEST.json
 */
function sharedFiles(dir, { webRoot, existing }) {
  const list = readJson(join(dir, "shared.json"));
  if (!Array.isArray(list) || !list.every((x) => typeof x === "string")) throw new Error("shared.json: expected a list of paths");
  /** @type {Map<string, Buffer>} */
  const out = new Map();
  if (list.length === 0) return out;
  const listed = new Set(list);
  if (listed.size !== list.length) throw new Error("shared.json: a path is listed twice");
  /** @type {Record<string, string>} */
  const hashes = {};
  for (const path of [...list].sort(compareText)) {
    if (!/^[A-Za-z0-9][A-Za-z0-9._/-]*\.mjs$/.test(path) || path.split("/").includes("..") || path.includes("//")) {
      throw new Error(`shared.json: path not allowed: ${path}`);
    }
    if (NOT_SHARED.test(path)) throw new Error(`shared.json: ${path} is a view, route or service file`);
    const source = join(webRoot, "src", ...path.split("/"));
    if (!existsSync(source)) throw new Error(`shared.json: ${path} is not in web/src`);
    const target = `shared/${path}`;
    if (existing.has(target)) throw new Error(`shared.json: ${target} is also a source file of the extension`);
    const bytes = readFileSync(source);
    // Closed under import: what a shared file imports is on the list too.
    const { specifiers, hidden } = importsOf(bytes.toString("utf8"));
    if (hidden > 0) throw new Error(`shared.json: ${path} has an import() that names no string literal`);
    for (const specifier of specifiers) {
      if (!/^\.\.?\//.test(specifier)) throw new Error(`shared.json: ${path} imports "${specifier}", which is not a relative path`);
      const imported = posix.normalize(posix.join(posix.dirname(path), specifier));
      if (!listed.has(imported)) throw new Error(`shared.json: ${path} imports ${imported}, which is not in the list`);
    }
    out.set(target, bytes);
    hashes[path] = sha256(bytes);
  }
  out.set("shared/MANIFEST.json", Buffer.from(`${JSON.stringify(hashes, null, 2)}\n`));
  return out;
}

/**
 * The files of dist/shared/ that no longer match shared/MANIFEST.json, the file
 * the build wrote with the SHA-256 of every shared file it copied. A package
 * without MANIFEST.json has no shared files to check.
 * With `webRoot` (and a `src` folder in it) every copy and every hash in
 * MANIFEST.json is also compared with the source in web/src, so an edited copy
 * together with an edited MANIFEST.json is named too.
 * @param {Map<string, Buffer>} files path -> bytes
 * @param {string} [webRoot] the web vault folder to compare with
 * @returns {string[]}
 */
export function sharedProblems(files, webRoot) {
  const raw = files.get("shared/MANIFEST.json");
  if (raw === undefined) return [];
  /** @type {unknown} */
  let hashes;
  try {
    hashes = JSON.parse(raw.toString("utf8"));
  } catch {
    return ["shared/MANIFEST.json: not valid JSON"];
  }
  if (!isPlainObject(hashes)) return ["shared/MANIFEST.json: expected an object of path -> SHA-256"];
  /** @type {string[]} */
  const problems = [];
  for (const [path, hash] of Object.entries(hashes)) {
    const bytes = files.get(`shared/${path}`);
    if (bytes === undefined) problems.push(`shared/${path}: is in shared/MANIFEST.json but not in the package`);
    else if (sha256(bytes) !== hash) problems.push(`shared/${path}: differs from its hash in shared/MANIFEST.json (a shared file is never edited here; change web/src)`);
  }
  if (webRoot !== undefined && existsSync(join(webRoot, "src"))) {
    for (const [path, hash] of Object.entries(hashes)) {
      if (typeof path !== "string" || !/^[A-Za-z0-9][A-Za-z0-9._/-]*\.mjs$/.test(path) || path.split("/").includes("..") || path.includes("//")) {
        problems.push(`shared/MANIFEST.json: path not allowed: ${path}`);
        continue;
      }
      const source = join(webRoot, "src", ...path.split("/"));
      if (!existsSync(source)) problems.push(`shared/${path}: is not in web/src`);
      else if (sha256(readFileSync(source)) !== hash || sha256(files.get(`shared/${path}`) ?? Buffer.alloc(0)) !== hash) {
        problems.push(`shared/${path}: differs from its source in web/src`);
      }
    }
  }
  return problems;
}

/**
 * The register of the message handlers: `background/handlers.gen.mjs`, which
 * imports every `background/handlers/<feature>.handler.mjs` that is in the
 * package (so a release has no test-only handler) and exports them as
 * `HANDLERS`. A feature adds its file and edits nothing else.
 * @param {Map<string, Buffer>} dist path -> bytes
 * @returns {string} the source of the register
 */
export function handlerRegister(dist) {
  const prefix = "background/handlers/";
  if (dist.has("background/handlers.gen.mjs")) {
    throw new Error("src/background/handlers.gen.mjs is generated by the build and must not exist");
  }
  const names = [...dist.keys()]
    .filter((p) => p.startsWith(prefix))
    .map((p) => p.slice(prefix.length))
    .sort(compareText)
    .filter((name) => name !== "README.mjs");
  for (const name of names) {
    // A handler for the test build only lives in handlers/test-only/.
    if (!/^(?:test-only\/)?[a-z][A-Za-z0-9]*\.handler\.mjs$/.test(name)) {
      throw new Error(`src/background/handlers/${name}: expected <feature>.handler.mjs`);
    }
  }
  const imports = names.map((name, i) => `import handler${i} from "./handlers/${name}";`);
  const list = names.map((_, i) => `handler${i}`).join(", ");
  return [
    "// Generated by scripts/build.mjs from background/handlers/*.handler.mjs. Do not edit.",
    ...imports,
    `export const HANDLERS = Object.freeze([${list}]);`,
    "",
  ].join("\n");
}

/**
 * `background/variant.gen.mjs`: what differs between the variants, decided
 * here and not at run time. The release one holds no name of the test build.
 * The test build's `variantHooks` is the hooks module of `background/test-only/`,
 * imported statically so the page sets it up in its first turn.
 * @param {string} variant
 * @param {Map<string, Buffer>} dist
 * @returns {string}
 */
export function variantModule(variant, dist) {
  if (dist.has("background/variant.gen.mjs")) {
    throw new Error("src/background/variant.gen.mjs is generated by the build and must not exist");
  }
  const lines = ["// Generated by scripts/build.mjs. Do not edit."];
  if (variant === "test") {
    lines.push('import * as hooks from "./test-only/testHooks.mjs";');
    lines.push("export const variantHooks = hooks;");
  } else {
    lines.push("export const variantHooks = null;");
  }
  return `${lines.join("\n")}\n`;
}

/** The generated module through which code reaches the files of the `unlock` feature. */
export const UNLOCK_STORE_FILE = "background/unlockStore.gen.mjs";

/**
 * `background/unlockStore.gen.mjs`: the one way to the PIN store and the window page, decided here and not at run time.
 * With `unlock` on it re-exports `createLocalUnlock` from the PIN store and names the window page; with it off it holds
 * `null` for both and imports nothing, so a package without the feature has no import edge to the files that the build
 * leaves out. A user of it checks for `null` (or `FEATURES.unlock`) before it uses either.
 * @param {readonly string[]} on the features that are on
 * @param {Map<string, Buffer>} dist
 * @returns {string}
 */
export function unlockStoreModule(on, dist) {
  if (dist.has(UNLOCK_STORE_FILE)) {
    throw new Error(`src/${UNLOCK_STORE_FILE} is generated by the build and must not exist`);
  }
  const lines = ["// Generated by scripts/build.mjs. Do not edit."];
  if (on.includes("unlock")) {
    lines.push('export { createLocalUnlock } from "./localUnlock.mjs";');
    lines.push('export const UNLOCK_WINDOW_PAGE = "pages/unlockWindow.html";');
  } else {
    lines.push("export const createLocalUnlock = null;");
    lines.push("export const UNLOCK_WINDOW_PAGE = null;");
  }
  return `${lines.join("\n")}\n`;
}

/** The generated module through which code outside the feature reaches the files of the `passkeys` feature. */
export const PASSKEY_GEN_FILE = "background/passkeys.gen.mjs";

/**
 * `background/passkeys.gen.mjs`: the one way from code that stays in every package (the entry of the background) to the
 * modules of the `passkeys` feature, decided here and not at run time. With `passkeys` on it re-exports them; with it off it
 * holds `null` for each and imports nothing, so a package without the feature has no import edge to the files the build
 * leaves out. No other file outside PASSKEY_FILES imports a file of the feature by name.
 * @param {readonly string[]} on the features that are on
 * @param {Map<string, Buffer>} dist
 * @returns {string}
 */
export function passkeysModule(on, dist) {
  if (dist.has(PASSKEY_GEN_FILE)) {
    throw new Error(`src/${PASSKEY_GEN_FILE} is generated by the build and must not exist`);
  }
  const lines = ["// Generated by scripts/build.mjs. Do not edit."];
  if (on.includes("passkeys")) {
    lines.push('export { createPasskeyRegistry } from "./passkeyRegistry.mjs";');
    lines.push('export { createPasskeyRequests } from "./passkeyRequests.mjs";');
  } else {
    lines.push("export const createPasskeyRegistry = null;");
    lines.push("export const createPasskeyRequests = null;");
  }
  return `${lines.join("\n")}\n`;
}

/**
 * The features that are on, from the value of --features: names of FEATURES separated
 * by commas, or "none".
 * @param {string} text
 * @returns {string[]}
 */
export function parseFeatures(text) {
  if (typeof text !== "string" || text.trim() === "") throw new Error('--features needs a list of features or "none"');
  if (text.trim() === "none") return [];
  const names = text.split(",").map((name) => name.trim());
  return checkFeatures(names);
}

/**
 * Checks a list of features: every name is one of FEATURES, and none is named twice.
 * @param {readonly string[]} names
 * @returns {string[]} the names, sorted
 */
function checkFeatures(names) {
  if (!Array.isArray(names)) throw new Error("features: expected a list of feature names");
  for (const name of names) {
    if (!FEATURES.includes(name)) throw new Error(`features: unknown feature ${JSON.stringify(name)} (known: ${FEATURES.join(", ")})`);
  }
  if (new Set(names).size !== names.length) throw new Error("features: a feature is named twice");
  return [...names].sort(compareText);
}

/**
 * `shared/features.mjs`: which features are on, decided here and not at run time.
 * The code of a feature asks `FEATURES.<name>` before it registers a handler, a
 * script or a control.
 * @param {readonly string[]} on the features that are on
 * @param {Map<string, Buffer>} dist
 * @returns {string}
 */
export function featuresModule(on, dist) {
  if (dist.has(FEATURES_FILE)) {
    throw new Error(`src/${FEATURES_FILE} is generated by the build and must not exist`);
  }
  const flags = Object.fromEntries(FEATURES.map((name) => [name, on.includes(name)]));
  return [
    "// Generated by scripts/build.mjs (--features). Do not edit.",
    `export const FEATURES = Object.freeze(${JSON.stringify(flags)});`,
    "",
  ].join("\n");
}

/**
 * What a release package must hold of the features: the features module that the build writes for a release (every
 * feature of RELEASE_FEATURES on, no other feature on), every file of each feature a release has on, and no file of a
 * feature it has not.
 * @param {Map<string, Buffer>} files path -> bytes
 * @returns {string[]}
 */
export function featureProblems(files) {
  /** @type {string[]} */
  const problems = [];
  const raw = files.get(FEATURES_FILE);
  if (raw === undefined) {
    problems.push(`${FEATURES_FILE} is missing (a release names the features that are on)`);
  } else {
    const text = raw.toString("utf8");
    if (text !== featuresModule(RELEASE_FEATURES, new Map())) {
      for (const name of FEATURES) {
        const flag = new RegExp(String.raw`["']?\b${name}\b["']?\s*:\s*(?!false\b)`).test(text);
        if (!RELEASE_FEATURES.includes(name) && flag) {
          problems.push(`${FEATURES_FILE}: the feature ${name} is on, which a release may not have`);
        }
        if (RELEASE_FEATURES.includes(name) && !new RegExp(String.raw`["']?\b${name}\b["']?\s*:\s*true\b`).test(text)) {
          problems.push(`${FEATURES_FILE}: the feature ${name} is off, which a release must have on`);
        }
      }
      if (problems.length === 0) problems.push(`${FEATURES_FILE}: not the module the build writes for a release`);
    }
  }
  // The unlock database is named only to delete it (the one trace of the feature in a package with it off), except by
  // the one module that owns the PIN store, which a release has when it has the feature on.
  const owner = RELEASE_FEATURES.includes("unlock") ? "background/localUnlock.mjs" : undefined;
  for (const [path, bytes] of files) {
    if (!/\.(?:mjs|js|html)$/.test(path) || WASM_FILES.includes(path) || path === owner) continue;
    const text = bytes.toString("utf8");
    if (text.split("ferret-unlock").length !== text.split('deleteDatabase("ferret-unlock")').length) {
      problems.push(`${path}: names the unlock database other than to delete it, which only the PIN store may do`);
    }
  }
  // A release without `passkeys` holds no way to act as a passkey provider: no script registered in the page's own world, no
  // override of the browser's credential functions, and the ids of the feature's scripts only in the module that removes
  // a registration an older build left.
  if (!RELEASE_FEATURES.includes("passkeys")) {
    for (const [path, bytes] of files) {
      if (!/\.(?:mjs|js|html)$/.test(path) || WASM_FILES.includes(path)) continue;
      const text = bytes.toString("utf8");
      if (PAGE_WORLD_PATTERN.test(text)) {
        problems.push(`${path}: registers a script in the page's own world, which a release without the passkeys feature may not do`);
      }
      if (/CredentialsContainer/.test(text)) {
        problems.push(`${path}: names the browser's credentials container, which a release without the passkeys feature may not do`);
      }
      if (path !== PASSKEY_CLEANUP_FILE && text.includes(PASSKEY_SCRIPT_ID_PREFIX)) {
        problems.push(`${path}: names the ids of the passkeys scripts, which a release without the feature may do only in ${PASSKEY_CLEANUP_FILE}`);
      }
    }
  }
  for (const [name, paths] of Object.entries(FEATURE_FILES)) {
    if (RELEASE_FEATURES.includes(name)) {
      for (const path of paths) {
        if (!files.has(path)) problems.push(`${path}: belongs to the ${name} feature, which a release has on, and is missing`);
      }
    } else {
      for (const path of paths) {
        if (files.has(path)) problems.push(`${path}: belongs to the ${name} feature, which a release may not have`);
      }
    }
  }
  return problems;
}

/** @param {string} root @returns {Map<string, string>} language -> catalog JSON */
function generateLocales(root) {
  const base = join(root, "src", "locales");
  /** @type {Map<string, string>} */
  const out = new Map();
  for (const lang of listDir(base)) {
    if (!/^[a-z]{2}(?:-[A-Z]{2})?$/.test(lang)) throw new Error(`locales/${lang}: not a language code`);
    /** @type {Record<string, string>} */
    const catalog = {};
    /** @type {Map<string, string>} */
    const source = new Map();
    for (const name of listDir(join(base, lang))) {
      const match = /^([a-z][a-z0-9-]*)\.json$/.exec(name);
      if (!match) throw new Error(`locales/${lang}/${name}: expected <feature>.json`);
      const feature = match[1];
      const entries = readJson(join(base, lang, name));
      if (!isPlainObject(entries)) throw new Error(`locales/${lang}/${name}: expected a flat JSON object`);
      for (const [key, text] of Object.entries(entries)) {
        if (!key.startsWith(`${feature}.`)) throw new Error(`locales/${lang}/${name}: key ${key} must start with ${feature}.`);
        if (typeof text !== "string") throw new Error(`locales/${lang}/${name}: ${key} is not a string`);
        if (source.has(key)) throw new Error(`locales/${lang}: key ${key} is in ${source.get(key)} and ${name}`);
        source.set(key, name);
        catalog[key] = text;
      }
    }
    const sorted = Object.fromEntries(Object.entries(catalog).sort(([a], [b]) => compareText(a, b)));
    out.set(lang, `${JSON.stringify(sorted, null, 2)}\n`);
  }
  return out;
}

/** @param {string} root */
function generateCss(root) {
  const base = join(root, "src", "styles");
  const names = listDir(base).filter((n) => n.endsWith(".css"));
  // base.css first, the rest by name.
  names.sort((a, b) => (a === "base.css" ? -1 : b === "base.css" ? 1 : compareText(a, b)));
  const parts = [];
  for (const name of names) {
    const text = readFileSync(join(base, name), "utf8");
    // A CSS escape can spell `url(`, so a backslash is refused too.
    if (text.includes("\\") || /@import/i.test(text) || /url\(\s*['"]?(?!data:)/i.test(text) || /expression\(/i.test(text)) {
      throw new Error(`styles/${name}: no @import, no backslash and no url() other than data: URLs`);
    }
    parts.push(`/* ${name} */\n${text.trimEnd()}\n`);
  }
  return parts.join("\n");
}

/**
 * @param {{
 *   browser?: string, manifest?: string, variant?: string, features?: readonly string[], root?: string,
 *   webRoot?: string, out?: string, wasmTar?: string, wasmSource?: string, wasmCommit?: string, fetchImpl?: typeof fetch,
 * }} [options] `features`: the features that are on (the variant's DEFAULT_FEATURES when left out)
 * @returns {Promise<{ dir: string, xpi: string, sha256: string, bytes: number, files: Map<string, Buffer>, features: string[], wasm: WasmRecord, wasmRecord: string }>}
 */
export async function build({
  browser = "firefox", manifest = "mv3", variant = "release", features,
  root = defaultRoot, webRoot, out, wasmTar, wasmSource, wasmCommit, fetchImpl = fetch,
} = {}) {
  root = resolve(root);
  webRoot = resolve(webRoot ?? join(root, "..", "web"));
  out = resolve(out ?? join(root, "dist"));
  const mv = manifest === "mv2" ? "mv2" : "mv3";
  const name = `ferret-${browser}-${mv}-${variant}`;
  const manifestJson = buildManifest({ browser, manifest, variant, root });
  const on = checkFeatures(features ?? DEFAULT_FEATURES[/** @type {"release" | "test"} */ (variant)]);

  // 1. The WASM package: the published one named in the lock, or (test variant only) one built
  // from the tree. See the top of this file.
  const source = wasmSource ?? process.env.FERRET_WASM_SOURCE ?? "lock";
  if (!WASM_SOURCES.includes(source)) throw new Error(`wasm source: ${source} is not one of ${WASM_SOURCES.join(", ")}`);
  if (variant === "release" && source !== "lock") {
    throw new Error(`a release build uses the locked WASM package only (web/wasm.lock.json), not ${source}`);
  }
  /** @type {Uint8Array} */
  let archive;
  /** @type {WasmRecord} */
  let record;
  if (source === "lock") {
    const lock = readJson(join(webRoot, "wasm.lock.json"));
    if (!/^[0-9a-f]{64}$/.test(lock.sha256) || typeof lock.version !== "string" || typeof lock.url !== "string") {
      throw new Error("wasm.lock.json: expected { version, url, sha256 }");
    }
    if (wasmTar) {
      archive = readFileSync(wasmTar);
    } else {
      const response = await fetchImpl(lock.url);
      if (!response.ok) throw new Error(`wasm package: ${lock.url} answered ${response.status}`);
      archive = new Uint8Array(await response.arrayBuffer());
    }
    if (sha256(archive) !== lock.sha256) {
      throw new Error(`wasm package: checksum mismatch (expected ${lock.sha256}, got ${sha256(archive)})`);
    }
    record = { source, version: lock.version, sha256: lock.sha256 };
  } else {
    // tree: the package was built from the commit named here; there is nothing to check it against but itself.
    if (!wasmTar) throw new Error("wasm source tree: --wasm-tar is needed (scripts/wasm-tree.sh builds it)");
    const commit = wasmCommit ?? process.env.FERRET_WASM_COMMIT ?? "";
    if (!/^[0-9a-f]{40}(?:-dirty)?$/.test(commit)) {
      throw new Error("wasm source tree: --wasm-commit is the 40-digit commit the package was built from (with -dirty after it when the tree had changes)");
    }
    archive = readFileSync(wasmTar);
    record = { source, commit, sha256: sha256(archive) };
  }
  const tar = readTarGz(archive);
  for (const file of WASM_FILES) {
    if (!tar.has(file)) throw new Error(`wasm package: ${file} is missing`);
  }
  // A release with `unlock` on is signed and shipped to every installed copy: it must not be built against a package
  // that lacks the functions the feature calls (the lock is moved to a release that has them before a release is built).
  if (variant === "release" && on.includes("unlock")) {
    const lacking = wasmUnlockProblems(tar);
    if (lacking.length > 0) {
      throw new WasmLacksUnlockError(`wasm package: a release with the unlock feature on needs a package that has what it calls, and this one (${record.source} ${record.version ?? record.commit}) lacks ${lacking.join(", ")}; move web/wasm.lock.json to a release that has them`);
    }
  }

  // 2. The sources: src/, the generated catalogs and style sheet, the test files.
  /** @type {Map<string, Buffer>} */
  const dist = new Map();
  const src = join(root, "src");
  for (const path of walk(src)) {
    if (path.startsWith("locales/") || path.startsWith("styles/")) continue;
    if (manifest === "mv3" && path === "background/background.html") continue;
    // js/ and pkg-web/ belong to the WASM package: the import check skips the
    // package's own files, so a file of ours there would escape it. Refused in
    // every variant and whatever the file type.
    if (path.startsWith("js/") || path.startsWith("pkg-web/")) throw new Error(`src/${path}: js/ and pkg-web/ are the WASM package's folders`);
    if (variant === "release" && (TEST_ONLY_SRC.includes(path) || isTestOnlyPath(path))) continue;
    if (!/\.(?:mjs|html)$/.test(path)) throw new Error(`src/${path}: only .mjs and .html files live in src`);
    dist.set(path, readFileSync(join(src, path)));
  }
  dist.set("background/handlers.gen.mjs", Buffer.from(handlerRegister(dist)));
  dist.set("background/variant.gen.mjs", Buffer.from(variantModule(variant, dist)));
  dist.set(FEATURES_FILE, Buffer.from(featuresModule(on, dist)));
  dist.set(UNLOCK_STORE_FILE, Buffer.from(unlockStoreModule(on, dist)));
  dist.set(PASSKEY_GEN_FILE, Buffer.from(passkeysModule(on, dist)));
  // The content script, joined into one classic script (an injected file cannot be a module).
  if (dist.has(CONTENT_ENTRY)) dist.set(CONTENT_BUNDLE, Buffer.from(classicScript(CONTENT_ENTRY, dist)));
  // The capture script of the `save` feature: its own classic script, joined slim (it runs in every https page).
  if (on.includes("save") && dist.has(CAPTURE_ENTRY)) {
    const script = classicScript(CAPTURE_ENTRY, dist, contentMayInclude, { slim: true, name: CAPTURE_BUNDLE });
    if (Buffer.byteLength(script) > CAPTURE_MAX_BYTES) throw new Error(`${CAPTURE_BUNDLE}: ${Buffer.byteLength(script)} bytes, over the ${CAPTURE_MAX_BYTES} of its size budget`);
    dist.set(CAPTURE_BUNDLE, Buffer.from(script));
  }
  // The passkey scripts of the `passkeys` feature: the one in the page's own world (slim, with its size budget, built from
  // its own folder only) and the bridge of the isolated world (slim, with its own budget: it runs in every https frame).
  if (on.includes("passkeys") && dist.has(PASSKEY_MAIN_ENTRY) && dist.has(PASSKEY_BRIDGE_ENTRY)) {
    const main = classicScript(PASSKEY_MAIN_ENTRY, dist, passkeyMainMayInclude, { slim: true, name: PASSKEY_MAIN_BUNDLE });
    if (Buffer.byteLength(main) > PASSKEY_MAIN_MAX_BYTES) throw new Error(`${PASSKEY_MAIN_BUNDLE}: ${Buffer.byteLength(main)} bytes, over the ${PASSKEY_MAIN_MAX_BYTES} of its size budget`);
    dist.set(PASSKEY_MAIN_BUNDLE, Buffer.from(main));
    const bridge = classicScript(PASSKEY_BRIDGE_ENTRY, dist, passkeyBridgeMayInclude, { slim: true, name: PASSKEY_BRIDGE_BUNDLE });
    if (Buffer.byteLength(bridge) > PASSKEY_BRIDGE_MAX_BYTES) throw new Error(`${PASSKEY_BRIDGE_BUNDLE}: ${Buffer.byteLength(bridge)} bytes, over the ${PASSKEY_BRIDGE_MAX_BYTES} of its size budget`);
    dist.set(PASSKEY_BRIDGE_BUNDLE, Buffer.from(bridge));
  }
  for (const [lang, text] of generateLocales(root)) dist.set(`locales.${lang}.json`, Buffer.from(text));
  const css = generateCss(root);
  if (css !== "") dist.set("assets/app.css", Buffer.from(css));
  if (variant === "test") {
    for (const path of TEST_ONLY_FILES) {
      if (existsSync(join(root, path))) dist.set(path, readFileSync(join(root, path)));
    }
  }

  // The icon artwork: extension/icons/*.svg, shipped as icons/*.svg.
  for (const name of listDir(join(root, ICONS_DIR))) {
    if (!/^[a-z0-9-]+\.svg$/.test(name)) throw new Error(`${ICONS_DIR}/${name}: only <name>.svg files live in ${ICONS_DIR}`);
    dist.set(`icons/${name}`, readFileSync(join(root, ICONS_DIR, name)));
  }

  // 3. Shared files from the web vault (an empty list adds nothing).
  for (const [path, bytes] of sharedFiles(root, { webRoot, existing: new Set(dist.keys()) })) dist.set(path, bytes);

  // 4. The WASM package and the manifest.
  for (const [path, bytes] of tar) {
    if (path.endsWith(".map")) throw new Error(`wasm package: ${path}: source maps are not allowed`);
    if (WASM_FILES.includes(path)) dist.set(path, bytes);
  }
  dist.set("manifest.json", Buffer.from(`${JSON.stringify(manifestJson, null, 2)}\n`));

  // A package with a feature off holds no file of that feature (this runs after every step that adds files).
  for (const [name, paths] of Object.entries(FEATURE_FILES)) {
    if (!on.includes(name)) for (const path of paths) dist.delete(path);
  }

  // 5. Checks.
  for (const [path, bytes] of dist) checkFile(path, bytes);
  // Every relative import and page script must find its file in the package: a
  // release that leaves out test-only code must not import it. (The WASM
  // package is checked by its SHA-256.)
  const dangling = danglingImports(dist, (path) => WASM_FILES.includes(path));
  if (dangling.length > 0) throw new Error(`package: ${dangling.join("; ")}`);
  const edited = sharedProblems(dist, webRoot);
  if (edited.length > 0) throw new Error(`package: ${edited.join("; ")}`);
  for (const path of manifestFiles(manifestJson)) {
    if (!dist.has(path)) throw new Error(`manifest.json: ${path} is not in the package`);
  }
  if (variant === "release") {
    const problems = releaseProblems(dist, readInternalHosts(root), readPermissionAllow(root), webRoot);
    if (problems.length > 0) throw new Error(`release: ${problems.join("; ")}`);
  }

  // 6. The folder and the .xpi.
  const dir = join(out, name);
  const xpi = join(out, `${name}.xpi`);
  rmSync(dir, { recursive: true, force: true });
  rmSync(xpi, { force: true });
  for (const [path, bytes] of dist) {
    const target = join(dir, ...path.split("/"));
    mkdirSync(dirname(target), { recursive: true });
    writeFileSync(target, bytes);
  }
  const packed = packXpi(dir, xpi);
  // Beside the package, not inside it: the package is the same bytes whatever the record says.
  const wasmRecord = join(out, `${name}.wasm.json`);
  writeFileSync(wasmRecord, `${JSON.stringify(record, null, 2)}\n`);
  return { dir, xpi, sha256: packed.sha256, bytes: packed.bytes, files: dist, features: on, wasm: record, wasmRecord };
}

/**
 * Packs a folder into a deterministic .xpi (sorted names, fixed time, fixed
 * permissions, entries stored).
 * @param {string} dir
 * @param {string} outFile
 * @returns {{ sha256: string, bytes: number }}
 */
export function packXpi(dir, outFile) {
  const files = new Map(walk(dir).map((p) => [p, readFileSync(join(dir, ...p.split("/")))]));
  const zip = packZip(files);
  mkdirSync(dirname(outFile), { recursive: true });
  writeFileSync(outFile, zip);
  return { sha256: sha256(zip), bytes: zip.length };
}

// --------------------------------------------------------------------- CLI

/** @param {string[]} args */
async function main(args) {
  if (args[0] === "--check-release") {
    let rest = args.slice(1);
    // --web-root <dir>: the web folder whose wasm.lock.json the packages are checked against (default: the repository's).
    let checkWebRoot = resolve(defaultRoot, "..", "web");
    if (rest[0] === "--web-root") {
      if (rest[1] === undefined) throw new Error("--web-root needs a folder");
      checkWebRoot = resolve(rest[1]);
      rest = rest.slice(2);
    }
    const targets = rest;
    if (targets.length === 0) throw new Error("--check-release needs a .xpi file or a folder");
    const internalHosts = readInternalHosts();
    const permissionAllow = readPermissionAllow();
    let failed = false;
    for (const target of targets) {
      const problems = [
        ...releaseProblems(readPackage(target), internalHosts, permissionAllow, checkWebRoot),
        ...wasmRecordProblems(target, checkWebRoot),
      ];
      for (const problem of problems) console.error(`check-release: ${target}: ${problem}`);
      if (problems.length > 0) failed = true;
      else console.log(`check-release: ${target}: clean`);
    }
    if (failed) process.exitCode = 1;
    return;
  }
  /** @type {Record<string, string>} */
  const values = {};
  for (let i = 0; i < args.length; i += 2) {
    const flag = args[i];
    const value = args[i + 1];
    if (!["--browser", "--manifest", "--variant", "--features", "--wasm", "--wasm-tar", "--wasm-commit", "--out"].includes(flag)) throw new Error(`unknown option ${flag}`);
    if (value === undefined) throw new Error(`${flag} needs a value`);
    values[flag.slice(2)] = value;
  }
  for (const required of ["browser", "manifest", "variant"]) {
    if (!values[required]) throw new Error(`--${required} is required`);
  }
  const result = await build({
    browser: values.browser,
    manifest: values.manifest,
    variant: values.variant,
    ...(values.features !== undefined ? { features: parseFeatures(values.features) } : {}),
    wasmTar: values["wasm-tar"],
    wasmSource: values.wasm,
    wasmCommit: values["wasm-commit"],
    out: values.out,
  });
  console.log(`build: ${result.files.size} files, features: ${result.features.join(", ") || "none"}, ${result.xpi} (${result.bytes} bytes, sha256 ${result.sha256}, wasm ${result.wasm.source} ${result.wasm.sha256})`);
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  main(process.argv.slice(2)).catch((error) => {
    console.error(`build: ${error.message}`);
    process.exit(error.exitCode ?? 1);
  });
}
