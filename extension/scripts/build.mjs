#!/usr/bin/env node
// Builds the Firefox extension: an unpacked folder and a deterministic .xpi.
//
//   node scripts/build.mjs --browser firefox --manifest mv3|mv2 --variant release|test
//                          [--wasm-tar <path>] [--out <dir>]
//   node scripts/build.mjs --check-release <.xpi or folder>...
//
// 1. Reads ../web/wasm.lock.json ({version, url, sha256}), fetches the published
//    ferret-core-wasm-web-<version>.tar.gz (or takes --wasm-tar), checks its
//    SHA-256 against the lock and unpacks pkg-web/ and js/ (only the files in
//    WASM_FILES). To move the pin, change web/wasm.lock.json.
// 2. Copies the files listed in shared.json from ../web/src to dist/shared/ and
//    writes dist/shared/MANIFEST.json (path -> SHA-256). An empty list writes
//    nothing, and not even the folder.
// 3. Merges manifest/base.json, the overlay of the chosen manifest version and
//    manifest/parts/*.json (and, for the test variant only, manifest/test-parts/*.json). A permission outside permissions.allow.json (its `release` section for the release variant) is a
//    build error, and so is a key that is never allowed (content_scripts,
//    web_accessible_resources, externally_connectable). The manifest declares
//    data_collection_permissions required: ["authenticationInfo"]: the extension
//    sends sign-in credentials and proofs to a server outside the browser (the
//    user's own), which Mozilla's definition of data transmission counts, so
//    "none" would be wrong. The test variant has its own add-on id.
// 4. Merges src/locales/<lang>/<feature>.json and src/styles/<feature>.css. A
//    feature adds its own files and edits no shared file.
//    Writes background/handlers.gen.mjs (the register of background/handlers/*.handler.mjs)
//    and background/variant.gen.mjs (what differs between release and test). The content
//    script and the modules it imports are joined into content/fill.inject.js (scripts/lib/classic.mjs). Anything
//    below a folder named test-only is left out of a release.
// 5. Refuses a relative import or page script whose file is not in the package, inline
//    script and style in HTML, source maps, files over 4 MiB that
//    are not .wasm, and, for the release variant, anything under test/.
// 6. Writes <out>/ferret-firefox-<mv>-<variant>/ and the .xpi next to it: sorted
//    names, a fixed time, fixed permissions, entries stored.
import {
  existsSync, mkdirSync, readdirSync, readFileSync, rmSync, statSync, writeFileSync,
} from "node:fs";
import { dirname, join, relative, resolve, sep } from "node:path";
import { fileURLToPath } from "node:url";
import { packZip, readTarGz, readZip, sha256 } from "./lib/archive.mjs";
import { CONTENT_BUNDLE, CONTENT_ENTRY, classicScript } from "./lib/classic.mjs";
import { danglingImports } from "./lib/imports.mjs";
import { FIXED_UUID, TEST_COMMAND_ID, TEST_MENU_ITEM_ID } from "./lib/testIds.mjs";

export { sha256 };

export const MAX_FILE_BYTES = 4 * 1024 * 1024;

/** The CSP of every extension page (design document, section 10.7). */
export const EXTENSION_CSP = "script-src 'self' 'wasm-unsafe-eval'; object-src 'self'; base-uri 'none'; frame-ancestors 'none'";

/** Added to the name of the test variant, so it cannot be mistaken for a release. */
export const TEST_NAME_SUFFIX = " (test)";

/** The add-on id of every release, and of the test variant (a separate id, so a test build never shares storage with an installed release). */
export const RELEASE_ID = "ferret@hedgerow.tools";
export const TEST_ID = "ferret-test@hedgerow.tools";

export const CONTENT_TYPES = Object.freeze({
  ".html": "text/html; charset=utf-8",
  ".mjs": "text/javascript; charset=utf-8",
  ".js": "text/javascript; charset=utf-8",
  ".json": "application/json; charset=utf-8",
  ".css": "text/css; charset=utf-8",
  ".wasm": "application/wasm",
});

/** Files of the published WASM package that the extension ships. */
export const WASM_FILES = [
  "js/client.mjs", "js/protocol.mjs", "js/vault.worker.mjs", "js/job.worker.mjs",
  "pkg-web/ferret_core_wasm.js", "pkg-web/ferret_core_wasm_bg.wasm",
];

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
export const TEST_ONLY_FILES = ["test/bridge.html", "test/bridge.mjs"];
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
  "background", "browser_specific_settings", "content_security_policy", "description",
  "manifest_version", "name", "optional_permissions", "permissions", "version",
];
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
  if (variant === "test") {
    merged.name = `${merged.name}${TEST_NAME_SUFFIX}`;
    merged.browser_specific_settings.gecko.id = TEST_ID;
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

/** @param {string} path @param {Buffer} bytes */
function checkFile(path, bytes) {
  if (path.endsWith(".map")) throw new Error(`${path}: source maps are not allowed`);
  const ext = path.slice(path.lastIndexOf("."));
  if (!Object.hasOwn(CONTENT_TYPES, ext)) throw new Error(`${path}: file type is not allowed`);
  if (bytes.length > MAX_FILE_BYTES && ext !== ".wasm") throw new Error(`${path}: over 4 MiB`);
  if (ext === ".html") checkHtml(path, bytes.toString("utf8"));
  if ((ext === ".mjs" || ext === ".js" || ext === ".css") && /sourceMappingURL=/.test(bytes.toString("utf8"))) {
    throw new Error(`${path}: source map reference is not allowed`);
  }
}

/** Page and script files named in the manifest. @param {Record<string, any>} manifest @returns {string[]} */
function manifestFiles(manifest) {
  const action = manifest.action ?? manifest.browser_action;
  const bg = manifest.background ?? {};
  return [action?.default_popup, bg.page, ...(bg.scripts ?? []), manifest.options_ui?.page].filter((p) => typeof p === "string");
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
 * test name, an internal host name, anything under test/, and a manifest with a
 * key or permission the release does not have. Returns the problems, empty when
 * clean.
 * @param {Map<string, Buffer>} files path -> bytes
 * @param {string[]} internalHosts host names of the fixture server and the end-to-end stack
 * @param {Record<string, string[]>} [permissionAllow] permissions.allow.json (the repository's own by default)
 * @returns {string[]}
 */
export function releaseProblems(files, internalHosts, permissionAllow = readPermissionAllow()) {
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
  const raw = files.get("manifest.json");
  if (raw === undefined) problems.push("manifest.json is missing");
  else problems.push(...manifestProblems(raw.toString("utf8"), permissionAllow));
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
  /** @type {Record<string, string>} */
  const hashes = {};
  for (const path of [...list].sort(compareText)) {
    if (!/^[A-Za-z0-9][A-Za-z0-9._/-]*\.mjs$/.test(path) || path.split("/").includes("..") || path.includes("//")) {
      throw new Error(`shared.json: path not allowed: ${path}`);
    }
    const source = join(webRoot, "src", ...path.split("/"));
    if (!existsSync(source)) throw new Error(`shared.json: ${path} is not in web/src`);
    const target = `shared/${path}`;
    if (existing.has(target)) throw new Error(`shared.json: ${target} is also a source file of the extension`);
    const bytes = readFileSync(source);
    out.set(target, bytes);
    hashes[path] = sha256(bytes);
  }
  out.set("shared/MANIFEST.json", Buffer.from(`${JSON.stringify(hashes, null, 2)}\n`));
  return out;
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
 *   browser?: string, manifest?: string, variant?: string, root?: string, webRoot?: string,
 *   out?: string, wasmTar?: string, fetchImpl?: typeof fetch,
 * }} [options]
 * @returns {Promise<{ dir: string, xpi: string, sha256: string, bytes: number, files: Map<string, Buffer> }>}
 */
export async function build({
  browser = "firefox", manifest = "mv3", variant = "release",
  root = defaultRoot, webRoot, out, wasmTar, fetchImpl = fetch,
} = {}) {
  root = resolve(root);
  webRoot = resolve(webRoot ?? join(root, "..", "web"));
  out = resolve(out ?? join(root, "dist"));
  const mv = manifest === "mv2" ? "mv2" : "mv3";
  const name = `ferret-${browser}-${mv}-${variant}`;
  const manifestJson = buildManifest({ browser, manifest, variant, root });

  // 1. The published WASM package, checked against the lock.
  const lock = readJson(join(webRoot, "wasm.lock.json"));
  if (!/^[0-9a-f]{64}$/.test(lock.sha256) || typeof lock.version !== "string" || typeof lock.url !== "string") {
    throw new Error("wasm.lock.json: expected { version, url, sha256 }");
  }
  /** @type {Uint8Array} */
  let archive;
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
  const tar = readTarGz(archive);
  for (const file of WASM_FILES) {
    if (!tar.has(file)) throw new Error(`wasm package: ${file} is missing`);
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
  // The content script, joined into one classic script (an injected file cannot be a module).
  if (dist.has(CONTENT_ENTRY)) dist.set(CONTENT_BUNDLE, Buffer.from(classicScript(CONTENT_ENTRY, dist)));
  for (const [lang, text] of generateLocales(root)) dist.set(`locales.${lang}.json`, Buffer.from(text));
  const css = generateCss(root);
  if (css !== "") dist.set("assets/app.css", Buffer.from(css));
  if (variant === "test") {
    for (const path of TEST_ONLY_FILES) {
      if (existsSync(join(root, path))) dist.set(path, readFileSync(join(root, path)));
    }
  }

  // 3. Shared files from the web vault (an empty list adds nothing).
  for (const [path, bytes] of sharedFiles(root, { webRoot, existing: new Set(dist.keys()) })) dist.set(path, bytes);

  // 4. The WASM package and the manifest.
  for (const [path, bytes] of tar) {
    if (path.endsWith(".map")) throw new Error(`wasm package: ${path}: source maps are not allowed`);
    if (WASM_FILES.includes(path)) dist.set(path, bytes);
  }
  dist.set("manifest.json", Buffer.from(`${JSON.stringify(manifestJson, null, 2)}\n`));

  // 5. Checks.
  for (const [path, bytes] of dist) checkFile(path, bytes);
  // Every relative import and page script must find its file in the package: a
  // release that leaves out test-only code must not import it. (The WASM
  // package is checked by its SHA-256.)
  const dangling = danglingImports(dist, (path) => WASM_FILES.includes(path));
  if (dangling.length > 0) throw new Error(`package: ${dangling.join("; ")}`);
  for (const path of manifestFiles(manifestJson)) {
    if (!dist.has(path)) throw new Error(`manifest.json: ${path} is not in the package`);
  }
  if (variant === "release") {
    const problems = releaseProblems(dist, readInternalHosts(root), readPermissionAllow(root));
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
  return { dir, xpi, sha256: packed.sha256, bytes: packed.bytes, files: dist };
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
    const targets = args.slice(1);
    if (targets.length === 0) throw new Error("--check-release needs a .xpi file or a folder");
    const internalHosts = readInternalHosts();
    const permissionAllow = readPermissionAllow();
    let failed = false;
    for (const target of targets) {
      const problems = releaseProblems(readPackage(target), internalHosts, permissionAllow);
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
    if (!["--browser", "--manifest", "--variant", "--wasm-tar", "--out"].includes(flag)) throw new Error(`unknown option ${flag}`);
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
    wasmTar: values["wasm-tar"],
    out: values.out,
  });
  console.log(`build: ${result.files.size} files, ${result.xpi} (${result.bytes} bytes, sha256 ${result.sha256})`);
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  main(process.argv.slice(2)).catch((error) => {
    console.error(`build: ${error.message}`);
    process.exit(1);
  });
}
