// The build flags. `save` (saving and updating passwords from the extension, and the
// generator), `unlock` (PIN and passkey unlock) and `passkeys` (Ferret as a passkey provider): all on in a release and in the test variant. A test build can turn
// any of them off (`--features none`), and "off" means that no path of the feature is there. A package built with `save` off holds no capture script,
// serves none of the feature's messages (a handler for one only refuses), and
// shows none of its controls.
//
// The rule for the code of the feature, which this test holds it to:
//
// - a handler of the feature checks `FEATURES.save` before anything else and, when the feature is off, throws an error
//   whose `code` is `not_available`, for every message type it serves (not only the first), as a handler that is not
//   there would answer;
// - every control of the feature, in a page or built by a page module, carries `data-feature="save"`, and a page
//   module that builds one imports `shared/features.mjs`;
// - every file, message type and core operation of the feature is added to SAVE_PATHS below, in the change that adds it.
//
// The lists in SAVE_PATHS, UNLOCK_PATHS and PASSKEY_PATHS name what belongs to each feature. Each change that adds
// a file, a message type or a control of the feature adds it there. The `unlock` feature follows the same rules, with
// `data-feature="unlock"` and its own lists; the one trace it leaves with the flag off is the deletion of its database
// at start (`deleteDatabase("ferret-unlock")`, in background/unlockCleanup.mjs).
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { existsSync, mkdirSync, readdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { pathToFileURL } from "node:url";
import { test } from "node:test";
import { PASSKEY_SCRIPT_IDS, removePasskeyScripts } from "../../src/background/passkeyCleanup.mjs";
import { CONTENT_TYPES, UI_TYPES } from "../../src/shared/protocol.mjs";
import { readGraph } from "./importGraph.mjs";
import {
  build, DEFAULT_FEATURES, FEATURE_FILES, FEATURES, FEATURES_FILE, featuresModule, featureProblems, isTestOnlyPath, PAGE_WORLD_PATTERN, PASSKEY_CLEANUP_FILE, PASSKEY_FILES,
  PASSKEY_SCRIPT_ID_PREFIX, PASSKEY_WASM_EXPORTS, parseFeatures, RELEASE_FEATURES, releaseProblems, readInternalHosts, SAVE_FILES, sha256, UNLOCK_FILES, UNLOCK_STORE_FILE, UNLOCK_WASM_EXPORTS, unlockStoreModule, WASM_FILES,
  WasmLacksPasskeysError, WasmLacksUnlockError, wasmPasskeyProblems, wasmUnlockProblems,
} from "../../scripts/build.mjs";
import { boot } from "./bootBackground.mjs";
import { extensionRoot, makeRoot, makeTar, wasmFiles } from "./buildHelpers.mjs";

/** What belongs to the `save` feature. */
const SAVE_PATHS = Object.freeze({
  /** Package files of the feature. */
  files: Object.freeze(["content/capture.inject.js", "content/capture.mjs", "content/capture.entry.mjs"]),
  /** Message types of the feature, from a content script and from Ferret's pages. */
  types: Object.freeze([
    "form_capture", "form_gone", "page_ready", "capture_settings",
    "offer_list", "offer_classify", "folder_names", "offer_save", "offer_update", "offer_dismiss", "offer_never", "offer_reveal",
    "generate", "generate_copy", "fill_generated",
    "sync_items", "item_conflict", "item_resolve", "item_discard",
  ]),
  /**
   * Core operations of the feature (the sync's offer ops): with the feature off each one only refuses. The generator's
   * operations (`generate`, `generate_copy`, `fill_generated`) are not read from the sync host this list is checked
   * against; generator.test.mjs checks that they refuse in a build without the feature.
   */
  coreOps: Object.freeze(["offer_classify", "offer_save", "offer_update", "folder_names"]),
  /** Core operations of the capture host: the same. */
  captureOps: Object.freeze(["capture_event", "capture_settings", "offer_list", "offer_dismiss", "offer_reveal"]),
  /** Modules that register the capture script: only code that the feature's own modules import may hold them. */
  registers: /registerContentScripts|capture\.inject\.js/,
  /** The attribute every control of the feature carries, so a page module that builds one is found. */
  control: 'data-feature="save"',
  controlInCode: /["']data-feature["']\s*:\s*["']save["']|data-feature=\\?["']save/,
});

/** What belongs to the `unlock` feature (PIN and passkey unlock). */
const UNLOCK_PATHS = Object.freeze({
  /** Package files of the feature that no other file imports. */
  files: Object.freeze(["pages/unlockWindow.html", "pages/unlockWindow.mjs", "pages/unlockWindowFlow.mjs", "background/localUnlock.mjs"]),
  /** Message types of the feature (sent by the extension's own pages only). */
  types: Object.freeze(["pin_set", "pin_unlock", "pin_off", "unlock_policy", "prf_options", "prf_unlock", "prf_window"]),
  /** The attribute every control of the feature carries. */
  control: 'data-feature="unlock"',
  controlInCode: /["']data-feature["']\s*:\s*["']unlock["']|data-feature=\\?["']unlock/,
  /** The database of the feature: a package with the feature off names it only to delete it. */
  database: "ferret-unlock",
  /** The one module that deletes it, at start, when the feature is off. */
  cleanup: "background/unlockCleanup.mjs",
});

/**
 * What belongs to the `passkeys` feature (Ferret as a passkey provider on web pages). The `passkeys` follow the rules of the
 * other features, with `data-feature="passkeys"`. The traces a package with the feature off may hold are the ids of the
 * scripts the feature registers, in background/passkeyCleanup.mjs, which removes a registration an older build left.
 */
const PASSKEY_PATHS = Object.freeze({
  /** Package files of the feature: the one list, `PASSKEY_FILES` of the build (the guard test below finds a file that is missing from it). */
  files: PASSKEY_FILES,
  /** Message types of the feature: each change that adds a type adds it here. */
  types: /** @type {readonly string[]} */ (Object.freeze(["passkey_request", "passkey_abort", "passkey_foreign", "passkey_ping", "passkey_pending", "passkey_site", "passkey_cancel", "passkey_browser", "passkey_never", "passkey_settings", "passkey_create_options", "passkey_candidates", "passkey_choose", "passkey_verify", "passkey_tab", "passkey_tab_list", "passkey_tab_open"])),
  /** The attribute every control of the feature carries (the popup's section included). */
  control: 'data-feature="passkeys"',
  controlInCode: /["']data-feature["']\s*:\s*["']passkeys["']|data-feature=\\?["']passkeys/,
  /** The prefix of the ids of the scripts it registers, and the one module that may name them with the feature off. */
  scriptIds: PASSKEY_SCRIPT_ID_PREFIX,
  cleanup: PASSKEY_CLEANUP_FILE,
});

/** The refusal of a handler whose feature is off (the router's own `not_available`): for each of the types it serves. */
const refuses = async (/** @type {any} */ handler, /** @type {string[]} */ types = handler.types) => {
  for (const type of types) {
    try {
      await handler.handle({}, { channel: handler.channel, type, state: () => "unlocked" });
      return false;
    } catch (error) {
      if (/** @type {any} */ (error)?.code !== "not_available") return false;
    }
  }
  return types.length > 0;
};

/**
 * What the core operations of the feature answer in a package, by name: `refused` when the op refuses because the
 * feature is off (`not_available`), otherwise the code it failed with (or `served`).
 * @param {string} dir
 * @returns {Promise<Record<string, string>>}
 */
async function coreOpsIn(dir) {
  const { createSyncHost } = await import(pathToFileURL(join(dir, "background", "sync.mjs")).href);
  const host = createSyncHost({
    sessionHost: { store: {}, onOpen() {}, storedServer: async () => null, sessionFor: async () => null, deviceName: async () => "", forget: async () => {}, exclusive: (/** @type {any} */ fn) => fn() },
    locks: null,
  });
  /** @type {Record<string, string>} */
  const out = {};
  for (const name of SAVE_PATHS.coreOps) {
    const op = host.ops[name];
    if (!op) {
      out[name] = "absent";
      continue;
    }
    out[name] = await op.run({}, { session: "0".repeat(32), offer_id: "0".repeat(32), name: "x", username: null, folder: null, id: "0".repeat(32), rev: 1 }, {}).then(
      () => "served",
      (/** @type {any} */ error) => (error?.code === "not_available" ? "refused" : String(error?.code)),
    );
  }
  return out;
}

/**
 * What the capture host's core operations answer in a package, by name (as `coreOpsIn`).
 * @param {string} dir
 * @returns {Promise<Record<string, string>>}
 */
async function captureOpsIn(dir) {
  const { createCaptureHost } = await import(pathToFileURL(join(dir, "background", "captureHost.mjs")).href);
  const none = { addListener() {} };
  const host = createCaptureHost({
    now: () => 1_000_000,
    random: (/** @type {Uint8Array} */ bytes) => bytes,
    webNavigation: { onCommitted: none, onCompleted: none, onHistoryStateUpdated: none, getAllFrames: async () => [] },
    tabs: { onRemoved: none, get: async () => ({}) },
    scripting: { registerContentScripts: async () => {}, unregisterContentScripts: async () => {}, getRegisteredContentScripts: async () => [] },
    permissions: { contains: async () => false, onRemoved: none },
    storageLocal: { get: async () => ({}), set: async () => {} },
  });
  /** @type {Record<string, string>} */
  const out = {};
  for (const name of SAVE_PATHS.captureOps) {
    const op = host.ops[name];
    if (!op) {
      out[name] = "absent";
      continue;
    }
    const args = { type: "form_gone", sender: { tabId: 1, frameId: 0, url: "https://a.example/" }, body: { capture_id: "c" }, tab_id: 1, session: "0".repeat(32), offer_id: "0".repeat(32) };
    out[name] = await op.run({}, args, {}).then(
      () => "served",
      (/** @type {any} */ error) => (error?.code === "not_available" ? "refused" : String(error?.code)),
    );
  }
  return out;
}

/**
 * Every path of the `save` feature that a package still has: a file of the feature, a handler of the register that
 * serves one of its message types and does not refuse it, a core operation of the feature that does not refuse, a page
 * with one of its controls, and a page module that builds such a control without asking FEATURES first.
 * @param {string} dir the unpacked package
 * @param {Map<string, Buffer>} files
 * @returns {Promise<string[]>}
 */
async function savePathsIn(dir, files) {
  /** @type {string[]} */
  const found = [];
  for (const path of SAVE_PATHS.files) if (files.has(path)) found.push(`file ${path}`);
  const register = files.get("background/handlers.gen.mjs")?.toString("utf8") ?? "";
  const handlers = [...register.matchAll(/from "\.\/(handlers\/[^"]+)"/g)].map((m) => `background/${m[1]}`);
  assert.ok(handlers.length > 0, "the register names the handlers");
  for (const path of handlers) {
    const handler = (await import(pathToFileURL(join(dir, ...path.split("/"))).href)).default;
    const served = (handler?.types ?? []).filter((/** @type {string} */ type) => SAVE_PATHS.types.includes(type));
    if (served.length > 0 && !(await refuses(handler, served))) found.push(`handler ${path} serves ${served.join(", ")}`);
  }
  for (const [name, answer] of Object.entries(await coreOpsIn(dir))) {
    if (answer !== "refused" && answer !== "absent") found.push(`core op ${name} answers ${answer}`);
  }
  for (const [name, answer] of Object.entries(await captureOpsIn(dir))) {
    if (answer !== "refused" && answer !== "absent") found.push(`core op ${name} answers ${answer}`);
  }
  // The registration of the capture script is code of the feature: a module that holds it must ask FEATURES itself or
  // be imported only by modules that do (the capture host), and one nothing imports is a way in of its own.
  const graph = readGraph(files, { skip: (path) => WASM_FILES.includes(path) });
  /** @param {string} path */
  const asksFeatures = (/** @type {string} */ path) => /shared\/features\.mjs["']/.test(files.get(path)?.toString("utf8") ?? "");
  for (const [path, bytes] of files) {
    // Test-only code (a probe that registers a script for a test) is not in a release, so it is not a path of the feature.
    if (!path.endsWith(".mjs") || path === "shared/captureConfig.mjs" || path === FEATURES_FILE || isTestOnlyPath(path)) continue;
    if (!SAVE_PATHS.registers.test(bytes.toString("utf8"))) continue;
    const importers = [...graph.edges].filter(([, edges]) => edges.some((e) => e.target === path)).map(([importer]) => importer);
    if (!asksFeatures(path) && (importers.length === 0 || !importers.every(asksFeatures))) found.push(`registration in ${path} without a gated importer`);
  }
  for (const [path, bytes] of files) {
    const text = bytes.toString("utf8");
    if (path.endsWith(".html") && text.includes(SAVE_PATHS.control)) found.push(`control in ${path}`);
    if (path.startsWith("pages/") && path.endsWith(".mjs") && SAVE_PATHS.controlInCode.test(text) && !/from\s+["']\.\.\/shared\/features\.mjs["']/.test(text)) {
      found.push(`control in ${path} without FEATURES`);
    }
  }
  return found;
}

/** @param {string} dir @returns {Promise<{ save: boolean, unlock: boolean, passkeys: boolean }>} */
const featuresOf = async (dir) => (await import(pathToFileURL(join(dir, ...FEATURES_FILE.split("/"))).href)).FEATURES;

test("the_save_feature_is_on_in_release_and_in_test", async () => {
  assert.deepEqual([...FEATURES], ["save", "unlock", "passkeys"]);
  assert.deepEqual([...DEFAULT_FEATURES.release], ["save", "unlock", "passkeys"]);
  assert.deepEqual([...DEFAULT_FEATURES.test], ["save", "unlock", "passkeys"]);
  assert.deepEqual([...RELEASE_FEATURES], ["save", "unlock", "passkeys"], "a release has save on");
  assert.deepEqual([...SAVE_FILES], [...SAVE_PATHS.files]);

  const env = makeRoot();
  try {
    const options = { root: env.root, webRoot: env.webRoot, wasmTar: env.tarPath };
    for (const manifest of ["mv2", "mv3"]) {
      const release = await build({ ...options, out: join(env.out, `r-${manifest}`), manifest, variant: "release" });
      const testBuild = await build({ ...options, out: join(env.out, `t-${manifest}`), manifest, variant: "test" });
      assert.deepEqual(release.features, ["passkeys", "save", "unlock"]);
      assert.deepEqual(testBuild.features, ["passkeys", "save", "unlock"]);
      // The generated module says so, in each package, and cannot be changed at run time.
      const releaseOn = await featuresOf(release.dir);
      const testOn = await featuresOf(testBuild.dir);
      assert.deepEqual({ ...releaseOn }, { save: true, unlock: true, passkeys: true }, manifest);
      assert.deepEqual({ ...testOn }, { save: true, unlock: true, passkeys: true }, manifest);
      assert.equal(Object.isFrozen(releaseOn), true);
      assert.equal(release.files.get(FEATURES_FILE)?.toString("utf8"), featuresModule(["save", "unlock", "passkeys"], new Map()));
      // The capture script and its sources are in the release, and no test-only code is.
      for (const path of SAVE_FILES) assert.ok(release.files.has(path), `${manifest}: ${path} is in a release`);
      assert.deepEqual([...release.files.keys()].filter((path) => isTestOnlyPath(path) || path.startsWith("test/")), [], manifest);
    }

    // --features overrides the variant's default: a test build with the feature off.
    const testOff = await build({ ...options, out: join(env.out, "t-off"), manifest: "mv2", variant: "test", features: [] });
    assert.deepEqual({ ...(await featuresOf(testOff.dir)) }, { save: false, unlock: false, passkeys: false });
    // A release with it off is refused by the build's own release check.
    await assert.rejects(build({ ...options, out: join(env.out, "r-off"), manifest: "mv2", variant: "release", features: [] }), /the feature save is off, which a release must have on/);
    await assert.rejects(build({ ...options, out: join(env.out, "x"), variant: "test", features: ["autosave"] }), /unknown feature "autosave"/);
  } finally {
    env.cleanup();
  }

  // The value of --features.
  assert.deepEqual(parseFeatures("save"), ["save"]);
  assert.deepEqual(parseFeatures(" save "), ["save"]);
  assert.deepEqual(parseFeatures("save,unlock"), ["save", "unlock"]);
  assert.deepEqual(parseFeatures("unlock"), ["unlock"]);
  assert.deepEqual(parseFeatures("save,unlock,passkeys"), ["passkeys", "save", "unlock"]);
  assert.deepEqual(parseFeatures("passkeys"), ["passkeys"]);
  assert.deepEqual(parseFeatures("none"), []);
  for (const bad of ["", " ", "save,save", "save,", "Save", "all"]) assert.throws(() => parseFeatures(bad), /features/, JSON.stringify(bad));

  // The module is the build's: a source file of that name fails the build.
  const planted = makeRoot({ "src/shared/features.mjs": "export const FEATURES = Object.freeze({ save: true, unlock: false });\n" });
  try {
    await assert.rejects(
      build({ root: planted.root, webRoot: planted.webRoot, out: planted.out, wasmTar: planted.tarPath, variant: "release" }),
      /src\/shared\/features\.mjs is generated by the build/,
    );
  } finally {
    planted.cleanup();
  }
});

test("a_package_with_save_off_has_no_capture_offer_or_generator_path", async () => {
  // The repository's own sources: nothing of the feature in a package built with it off, in either manifest version.
  const env = makeRoot();
  try {
    const options = { root: env.root, webRoot: env.webRoot, wasmTar: env.tarPath };
    for (const manifest of ["mv2", "mv3"]) {
      const off = await build({ ...options, out: join(env.out, manifest), manifest, variant: "test", features: [] });
      assert.deepEqual({ ...(await featuresOf(off.dir)) }, { save: false, unlock: false, passkeys: false });
      assert.deepEqual(await savePathsIn(off.dir, off.files), [], manifest);
    }
  } finally {
    env.cleanup();
  }

  // The check finds each kind of path (so an empty answer above means something): a handler that serves a type of the
  // feature, a page with a control of it, a page module that builds one without asking FEATURES, and the capture script.
  const probe = makeRoot({
    "src/background/handlers/offerProbe.handler.mjs": 'export default { types: ["offer_save"], channel: "ui", handle: async () => ({ ok: true }) };\n',
    "src/background/handlers/generatorProbe.handler.mjs": [
      'import { FEATURES } from "../../shared/features.mjs";',
      "export default {",
      '  types: ["generate"],',
      '  channel: "ui",',
      "  handle: async () => {",
      '    if (!FEATURES.save) throw Object.assign(new Error("not_available"), { code: "not_available" });',
      "    return { ok: true };",
      "  },",
      "};",
      "",
    ].join("\n"),
    "src/background/probeRegister.mjs": "export const register = (scripting) => scripting.registerContentScripts([]);\n",
    "src/background/handlers/mixedProbe.handler.mjs": [
      'import { FEATURES } from "../../shared/features.mjs";',
      "export default {",
      '  types: ["offer_update", "offer_dismiss"],',
      '  channel: "ui",',
      "  handle: async (_body, ctx) => {",
      '    if (!FEATURES.save && ctx.type === "offer_update") throw Object.assign(new Error("not_available"), { code: "not_available" });',
      "    return { ok: true };",
      "  },",
      "};",
      "",
    ].join("\n"),
    "src/pages/probe.html": '<!doctype html><button data-feature="save" data-role="probe">x</button>\n',
    "src/pages/probeView.mjs": 'export const control = { "data-feature": "save" };\n',
    "src/pages/probeGated.mjs": 'import { FEATURES } from "../shared/features.mjs";\nexport const control = FEATURES.save ? { "data-feature": "save" } : null;\n',
  });
  try {
    const options = { root: probe.root, webRoot: probe.webRoot, wasmTar: probe.tarPath, manifest: "mv2" };
    const release = await build({ ...options, out: join(probe.out, "r"), variant: "test", features: [] });
    release.files.set("content/capture.inject.js", Buffer.from("void 0;\n"));
    assert.deepEqual((await savePathsIn(release.dir, release.files)).sort(), [
      "control in pages/probe.html",
      "control in pages/probeView.mjs without FEATURES",
      "file content/capture.inject.js",
      "handler background/handlers/mixedProbe.handler.mjs serves offer_update, offer_dismiss",
      "handler background/handlers/offerProbe.handler.mjs serves offer_save",
      "registration in background/probeRegister.mjs without a gated importer",
    ]);
    // With the feature on, the gated handler serves its type: it refuses only because the feature is off.
    const on = await build({ ...options, out: join(probe.out, "t"), variant: "test" });
    const gated = (await import(pathToFileURL(join(on.dir, "background", "handlers", "generatorProbe.handler.mjs")).href)).default;
    assert.deepEqual(await gated.handle({}, {}), { ok: true });
    // The offer ops of the sync, the same: past the flag they go on (here to "no sync runs"), so `refused` above is the
    // flag's doing.
    assert.deepEqual(await coreOpsIn(on.dir), Object.fromEntries(SAVE_PATHS.coreOps.map((name) => [name, "sync_not_running"])));
    assert.deepEqual(await coreOpsIn(release.dir), Object.fromEntries(SAVE_PATHS.coreOps.map((name) => [name, "refused"])));
    // The capture host's operations, the same: served in the test build, refused in the release.
    assert.deepEqual(await captureOpsIn(on.dir), Object.fromEntries(SAVE_PATHS.captureOps.map((name) => [name, "served"])));
    assert.deepEqual(await captureOpsIn(release.dir), Object.fromEntries(SAVE_PATHS.captureOps.map((name) => [name, "refused"])));
  } finally {
    probe.cleanup();
  }
});

test("every_message_type_is_a_u1_type_or_listed_as_a_type_of_the_save_feature", () => {
  // Fail closed: a message type that someone adds must either be listed under the feature (and so be checked to refuse
  // with the feature off) or be added here on purpose as a type of the first release.
  const FIRST_RELEASE_TYPES = Object.freeze([
    "candidates", "copy", "fill", "forget_preview", "forget_server", "frame_report", "fill_result", "grant_check", "item", "item_code", "lock",
    "open_site", "search", "server_check", "settings", "sign_in", "state", "sync_accept_older", "sync_older_preview", "sync_retry",
    "sync_state", "unlock",
  ]);
  const all = [...Object.keys(UI_TYPES), ...Object.keys(CONTENT_TYPES)];
  const unaccounted = all.filter((type) => !FIRST_RELEASE_TYPES.includes(type) && !SAVE_PATHS.types.includes(type) && !UNLOCK_PATHS.types.includes(type) && !PASSKEY_PATHS.types.includes(type));
  assert.deepEqual(unaccounted, [], "a type that is in no list");
  // And everything listed as the feature's that exists is a type of a table (a stale name is found).
  for (const type of ["form_capture", "form_gone", "page_ready", "capture_settings", "sync_items", "item_conflict", "item_resolve", "item_discard"]) {
    assert.ok(all.includes(type), type);
  }
});

// ------------------------------------------------------------------------------------------------ the `unlock` feature

/**
 * Every path of the `unlock` feature that a package still has: a file of the feature, a handler of the register that
 * serves one of its message types and does not refuse it, a page with one of its controls, a page module that builds
 * such a control without asking FEATURES first, a WebAuthn call, and any file that names the unlock database other than
 * to delete it (the one permitted trace of a package with the feature off).
 * @param {string} dir the unpacked package
 * @param {Map<string, Buffer>} files
 * @returns {Promise<string[]>}
 */
async function unlockPathsIn(dir, files) {
  /** @type {string[]} */
  const found = [];
  for (const path of UNLOCK_PATHS.files) if (files.has(path)) found.push(`file ${path}`);
  const register = files.get("background/handlers.gen.mjs")?.toString("utf8") ?? "";
  const handlers = [...register.matchAll(/from "\.\/(handlers\/[^"]+)"/g)].map((m) => `background/${m[1]}`);
  assert.ok(handlers.length > 0, "the register names the handlers");
  for (const path of handlers) {
    const handler = (await import(pathToFileURL(join(dir, ...path.split("/"))).href)).default;
    const served = (handler?.types ?? []).filter((/** @type {string} */ type) => UNLOCK_PATHS.types.includes(type));
    if (served.length > 0 && !(await refuses(handler, served))) found.push(`handler ${path} serves ${served.join(", ")}`);
  }
  for (const [path, bytes] of files) {
    if (WASM_FILES.includes(path) || isTestOnlyPath(path)) continue;
    const text = bytes.toString("utf8");
    if (path.endsWith(".html") && text.includes(UNLOCK_PATHS.control)) found.push(`control in ${path}`);
    if (path.startsWith("pages/") && path.endsWith(".mjs") && UNLOCK_PATHS.controlInCode.test(text) && !/from\s+["']\.\.\/shared\/features\.mjs["']/.test(text)) {
      found.push(`control in ${path} without FEATURES`);
    }
    if (/\.(?:mjs|js|html)$/.test(path)) {
      if (/credentials\s*\.\s*(?:get|create)\b/.test(text)) found.push(`WebAuthn call in ${path}`);
      const named = text.split(UNLOCK_PATHS.database).length - 1;
      const deleted = text.split(`deleteDatabase("${UNLOCK_PATHS.database}")`).length - 1;
      if (named !== deleted) found.push(`database name in ${path}`);
    }
  }
  return found;
}

test("the_unlock_feature_is_on_in_release_and_in_test", async () => {
  assert.deepEqual([...FEATURES], ["save", "unlock", "passkeys"]);
  assert.deepEqual([...DEFAULT_FEATURES.release], ["save", "unlock", "passkeys"], "a release has unlock on");
  assert.deepEqual([...DEFAULT_FEATURES.test], ["save", "unlock", "passkeys"], "the test variant has it on");
  assert.deepEqual([...RELEASE_FEATURES], ["save", "unlock", "passkeys"]);
  assert.deepEqual([...UNLOCK_FILES], [...UNLOCK_PATHS.files]);
  assert.deepEqual(Object.keys(FEATURE_FILES).sort(), ["passkeys", "save", "unlock"]);

  const env = makeRoot({
    // A window page of the feature: in the package with the feature on, and left out with it off.
    "src/pages/unlockWindow.html": "<!doctype html><title>x</title>\n",
    "src/pages/unlockWindow.mjs": "export {};\n",
    "src/pages/unlockWindowFlow.mjs": "export {};\n",
    // The PIN store: the one module that opens the unlock database.
    "src/background/localUnlock.mjs": 'export const UNLOCK_DB_NAME = "ferret-unlock";\n',
  });
  try {
    const options = { root: env.root, webRoot: env.webRoot, wasmTar: env.tarPath };
    for (const manifest of ["mv2", "mv3"]) {
      const release = await build({ ...options, out: join(env.out, `r-${manifest}`), manifest, variant: "release" });
      const testBuild = await build({ ...options, out: join(env.out, `t-${manifest}`), manifest, variant: "test" });
      assert.deepEqual(release.features, ["passkeys", "save", "unlock"], manifest);
      assert.deepEqual({ ...(await featuresOf(release.dir)) }, { save: true, unlock: true, passkeys: true }, manifest);
      assert.deepEqual({ ...(await featuresOf(testBuild.dir)) }, { save: true, unlock: true, passkeys: true }, manifest);
      assert.equal(release.files.get(FEATURES_FILE)?.toString("utf8"), featuresModule(["save", "unlock", "passkeys"], new Map()));
      for (const path of UNLOCK_PATHS.files) {
        assert.equal(release.files.has(path), true, `${manifest}: ${path} is in a release`);
        assert.equal(testBuild.files.has(path), true, `${manifest}: ${path} is in the test variant`);
      }
      assert.deepEqual([...release.files.keys()].filter((path) => isTestOnlyPath(path) || path.startsWith("test/")), [], manifest);
    }
    // Each flag on its own: unlock alone leaves out the files of save, and save alone those of unlock.
    const unlockOnly = await build({ ...options, out: join(env.out, "u-only"), manifest: "mv2", variant: "test", features: ["unlock"] });
    assert.deepEqual({ ...(await featuresOf(unlockOnly.dir)) }, { save: false, unlock: true, passkeys: false });
    for (const path of SAVE_FILES) assert.equal(unlockOnly.files.has(path), false, path);
    for (const path of UNLOCK_PATHS.files) assert.equal(unlockOnly.files.has(path), true, path);
    const saveOnly = await build({ ...options, out: join(env.out, "s-only"), manifest: "mv2", variant: "test", features: ["save"] });
    assert.deepEqual({ ...(await featuresOf(saveOnly.dir)) }, { save: true, unlock: false, passkeys: false });
    for (const path of UNLOCK_PATHS.files) assert.equal(saveOnly.files.has(path), false, path);
    for (const path of SAVE_FILES) assert.equal(saveOnly.files.has(path), true, path);
  } finally {
    env.cleanup();
  }
});

test("the_release_check_requires_a_release_build_with_unlock_on", async () => {
  const env = makeRoot();
  try {
    const options = { root: env.root, webRoot: env.webRoot, wasmTar: env.tarPath, manifest: "mv2" };
    // The build's own release check refuses a release with the feature off.
    await assert.rejects(
      build({ ...options, out: join(env.out, "r-off"), variant: "release", features: ["save"] }),
      /the feature unlock is off, which a release must have on/,
    );
    const release = await build({ ...options, out: join(env.out, "r"), variant: "release" });
    const hosts = readInternalHosts(env.root);
    assert.deepEqual(releaseProblems(release.files, hosts), []);

    // The check on a finished package: the features module with unlock off, in every way it can be written.
    for (const text of [
      featuresModule(["save"], new Map()),
      'export const FEATURES = Object.freeze({"save":true,"unlock":false});\n',
      "export const FEATURES = Object.freeze({ save: true, unlock: false });\n",
      "export const FEATURES = Object.freeze({ save: true, 'unlock': 0 });\n",
      "export const FEATURES = Object.freeze({ save: true, unlock: !1 });\n",
      "export const FEATURES = Object.freeze({ save: true });\n",
    ]) {
      const files = new Map(release.files);
      files.set(FEATURES_FILE, Buffer.from(text));
      const problems = featureProblems(files);
      assert.ok(problems.some((p) => /the feature unlock is off, which a release must have on/.test(p)), text);
    }
    // A file of the feature missing from a release package is refused, and so is a package without the features module.
    for (const path of UNLOCK_PATHS.files) {
      const files = new Map(release.files);
      files.delete(path);
      assert.ok(featureProblems(files).includes(`${path}: belongs to the unlock feature, which a release has on, and is missing`), path);
    }
    const noModule = new Map(release.files);
    noModule.delete(FEATURES_FILE);
    assert.match(featureProblems(noModule).join("\n"), /shared\/features\.mjs is missing/);

    // The command the script runs (`scripts/check-ext-release.sh`) says no, with a non-zero status, to the same package.
    const bad = join(env.out, "bad");
    for (const [path, bytes] of release.files) {
      const target = join(bad, ...path.split("/"));
      mkdirSync(dirname(target), { recursive: true });
      writeFileSync(target, path === FEATURES_FILE ? featuresModule(["save"], new Map()) : bytes);
    }
    const ran = spawnSync(process.execPath, [join(extensionRoot, "scripts", "build.mjs"), "--check-release", bad], { encoding: "utf8" });
    assert.equal(ran.status, 1, ran.stdout + ran.stderr);
    assert.match(ran.stderr, /the feature unlock is off, which a release must have on/);
    const good = spawnSync(process.execPath, [join(extensionRoot, "scripts", "build.mjs"), "--check-release", "--web-root", env.webRoot, release.dir], { encoding: "utf8" });
    assert.equal(good.status, 0, good.stdout + good.stderr);
  } finally {
    env.cleanup();
  }
  // The script names the unlock feature in its header, so a reader of it sees the rule.
  assert.match(readFileSync(join(extensionRoot, "..", "scripts", "check-ext-release.sh"), "utf8"), /unlock/);
});

test("a_package_with_unlock_off_has_no_pin_or_prf_path", async () => {
  // The repository's own sources: nothing of the feature in a package built with it off, in either manifest version.
  // The only trace is the deletion of the database at start. A release has the feature on, so it is not built with it off.
  const env = makeRoot();
  try {
    const options = { root: env.root, webRoot: env.webRoot, wasmTar: env.tarPath };
    for (const manifest of ["mv2", "mv3"]) {
      const off = await build({ ...options, out: join(env.out, `t-${manifest}`), manifest, variant: "test", features: ["save"] });
      assert.deepEqual(await unlockPathsIn(off.dir, off.files), [], `test ${manifest}`);
      // The permitted trace is there, and it is the only one: the one module that holds the name, in the one form.
      const holders = [...off.files].filter(([path, bytes]) => !WASM_FILES.includes(path) && bytes.toString("utf8").includes(UNLOCK_PATHS.database)).map(([path]) => path);
      assert.deepEqual(holders, [UNLOCK_PATHS.cleanup], manifest);
      assert.equal(off.files.get(UNLOCK_PATHS.cleanup)?.toString("utf8").includes(`deleteDatabase("${UNLOCK_PATHS.database}")`), true);
    }
  } finally {
    env.cleanup();
  }

  // The check finds each kind of path (so an empty answer above means something): a handler that serves a type of the
  // feature, a page with a control of it, a page module that builds one without asking FEATURES, a WebAuthn call, a
  // use of the database other than the deletion, and a file of the feature.
  const probe = makeRoot({
    "src/background/handlers/pinProbe.handler.mjs": 'export default { types: ["pin_unlock"], channel: "ui", handle: async () => ({ ok: true }) };\n',
    "src/background/handlers/prfProbe.handler.mjs": [
      'import { FEATURES } from "../../shared/features.mjs";',
      "export default {",
      '  types: ["prf_unlock", "pin_off"],',
      '  channel: "ui",',
      "  handle: async () => {",
      '    if (!FEATURES.unlock) throw Object.assign(new Error("not_available"), { code: "not_available" });',
      "    return { ok: true };",
      "  },",
      "};",
      "",
    ].join("\n"),
    "src/pages/unlockProbe.html": '<!doctype html><button data-feature="unlock" data-role="probe">x</button>\n',
    "src/pages/unlockView.mjs": 'export const control = { "data-feature": "unlock" };\n',
    "src/pages/unlockGated.mjs": 'import { FEATURES } from "../shared/features.mjs";\nexport const control = FEATURES.unlock ? { "data-feature": "unlock" } : null;\n',
    "src/background/webauthnProbe.mjs": "export const get = () => navigator.credentials.get({});\n",
    "src/background/storeProbe.mjs": 'export const open = (idb) => idb.open("ferret-unlock", 1);\n',
    "src/background/deleteProbe.mjs": 'export const drop = (idb) => idb.deleteDatabase("ferret-unlock");\n',
  });
  try {
    const options = { root: probe.root, webRoot: probe.webRoot, wasmTar: probe.tarPath, manifest: "mv2" };
    const off = await build({ ...options, out: join(probe.out, "off"), variant: "test", features: ["save"] });
    off.files.set("pages/unlockWindow.html", Buffer.from("<!doctype html>\n"));
    off.files.set("background/localUnlock.mjs", Buffer.from("export {};\n"));
    assert.deepEqual((await unlockPathsIn(off.dir, off.files)).sort(), [
      "WebAuthn call in background/webauthnProbe.mjs",
      "control in pages/unlockProbe.html",
      "control in pages/unlockView.mjs without FEATURES",
      "database name in background/storeProbe.mjs",
      "file background/localUnlock.mjs",
      "file pages/unlockWindow.html",
      "handler background/handlers/pinProbe.handler.mjs serves pin_unlock",
    ]);
    // With the feature on, the gated handler serves its type: it refuses only because the feature is off.
    const on = await build({ ...options, out: join(probe.out, "on"), variant: "test" });
    const gated = (await import(pathToFileURL(join(on.dir, "background", "handlers", "prfProbe.handler.mjs")).href)).default;
    assert.deepEqual(await gated.handle({}, {}), { ok: true });
  } finally {
    probe.cleanup();
  }
});

test("a_build_with_unlock_off_deletes_the_unlock_database_at_start", async () => {
  const env = makeRoot();
  /** @type {string[]} */
  const deleted = [];
  /** @type {any} */ (globalThis).indexedDB = {
    deleteDatabase: (/** @type {string} */ name) => {
      deleted.push(name);
      /** @type {any} */
      const request = {};
      setTimeout(() => request.onsuccess?.({}), 0);
      return request;
    },
    open: () => {
      throw new Error("a package must not open a database at start");
    },
  };
  try {
    const options = { root: env.root, webRoot: env.webRoot, wasmTar: env.tarPath, manifest: "mv3" };
    // Off (a test build with the flag off): the deletion of the one database, once, and nothing else.
    for (const [name, variant, features] of /** @type {const} */ ([["test, off", "test", ["save"]]])) {
      const result = await build({ ...options, out: join(env.out, name.replace(/\W/g, "")), variant, ...(features ? { features: [...features] } : {}) });
      deleted.length = 0;
      try {
        await boot(result.dir);
      } finally {
        delete (/** @type {any} */ (globalThis)).browser;
      }
      assert.deepEqual(deleted, ["ferret-unlock"], name);
    }
    // On (a release and the test variant): the feature owns the database, and the cleanup does not run.
    for (const variant of /** @type {const} */ (["release", "test"])) {
      const on = await build({ ...options, out: join(env.out, `on-${variant}`), variant });
      deleted.length = 0;
      try {
        await boot(on.dir);
      } finally {
        delete (/** @type {any} */ (globalThis)).browser;
      }
      assert.deepEqual(deleted, [], `with unlock on the cleanup does not run (${variant})`);
    }
  } finally {
    delete (/** @type {any} */ (globalThis)).indexedDB;
    env.cleanup();
  }

  // The module itself: it never throws and never rejects, whatever the browser does.
  const { deleteUnlockDatabase } = await import(pathToFileURL(join(extensionRoot, "src", "background", "unlockCleanup.mjs")).href);
  assert.equal(await deleteUnlockDatabase(undefined), false);
  assert.equal(await deleteUnlockDatabase(null), false);
  assert.equal(await deleteUnlockDatabase({ deleteDatabase: () => { throw new Error("no"); } }), false);
  assert.equal(await deleteUnlockDatabase({ deleteDatabase: () => undefined }), false);
  assert.equal(await deleteUnlockDatabase({ deleteDatabase: () => { const r = /** @type {any} */ ({}); setTimeout(() => r.onerror?.({}), 0); return r; } }), false);
  assert.equal(await deleteUnlockDatabase({ deleteDatabase: () => { const r = /** @type {any} */ ({}); setTimeout(() => r.onsuccess?.({}), 0); return r; } }), true);
});

test("only_the_pin_store_names_the_unlock_database_in_a_package", async () => {
  // The architecture test over the built packages: in a package with `unlock` on, the one module that names the unlock
  // database or the session key of the PIN is the PIN store; in a package with it off, there is no PIN store, and the
  // only thing that names the database is the deletion at start.
  const env = makeRoot();
  try {
    const options = { root: env.root, webRoot: env.webRoot, wasmTar: env.tarPath };
    /** @param {Map<string, Buffer>} files @returns {string[]} */
    const holders = (files) =>
      [...files]
        .filter(([path]) => /\.(?:mjs|js|html)$/.test(path) && !WASM_FILES.includes(path) && !isTestOnlyPath(path))
        .filter(([, bytes]) => {
          const text = bytes.toString("utf8").replace(/indexedDB\s*\.\s*deleteDatabase\(\s*["']ferret-unlock["']\s*\)/g, "");
          return text.includes("ferret-unlock") || /["'`]ferretPin\b/.test(text);
        })
        .map(([path]) => path)
        .sort();
    for (const manifest of ["mv2", "mv3"]) {
      for (const variant of /** @type {const} */ (["release", "test"])) {
        const on = await build({ ...options, out: join(env.out, `on-${variant}-${manifest}`), manifest, variant });
        assert.deepEqual(holders(on.files), ["background/localUnlock.mjs"], `${manifest} ${variant}: unlock on`);
      }
      for (const [name, variant, features] of /** @type {const} */ ([["test-off", "test", ["save"]]])) {
        const off = await build({ ...options, out: join(env.out, `${name}-${manifest}`), manifest, variant, ...(features ? { features: [...features] } : {}) });
        assert.equal(off.files.has("background/localUnlock.mjs"), false, `${manifest} ${name}: no PIN store`);
        assert.deepEqual(holders(off.files), [], `${manifest} ${name}: unlock off`);
        // Nothing in the package imports the PIN store (a dangling import would have failed the build).
        for (const [path, bytes] of off.files) {
          if (/\.(?:mjs|js)$/.test(path) && !WASM_FILES.includes(path)) assert.equal(bytes.toString("utf8").includes("localUnlock"), false, `${manifest} ${name}: ${path}`);
        }
      }
    }
  } finally {
    env.cleanup();
  }
});

test("the_pin_store_is_reached_only_through_the_generated_module", async () => {
  const env = makeRoot();
  try {
    const options = { root: env.root, webRoot: env.webRoot, wasmTar: env.tarPath, manifest: "mv2" };
    const on = await build({ ...options, out: join(env.out, "on"), variant: "release" });
    const off = await build({ ...options, out: join(env.out, "off"), variant: "test", features: ["save"] });
    const gen = UNLOCK_STORE_FILE;
    assert.equal(on.files.get(gen)?.toString("utf8"), unlockStoreModule(["save", "unlock"], new Map()));
    assert.equal(off.files.get(gen)?.toString("utf8"), unlockStoreModule(["save"], new Map()));
    // With the feature on it re-exports the store and names the window page; with it off it holds null and imports nothing,
    // so a package without the feature has no import edge to the files the build leaves out.
    assert.match(/** @type {Buffer} */ (on.files.get(gen)).toString("utf8"), /export \{ createLocalUnlock \} from "\.\/localUnlock\.mjs";/);
    const offText = /** @type {Buffer} */ (off.files.get(gen)).toString("utf8");
    assert.equal(/\bimport\b|\bfrom\b/.test(offText.replace(/^\/\/.*$/gm, "")), false, offText);
    assert.match(offText, /export const createLocalUnlock = null;/);
    assert.match(offText, /export const UNLOCK_WINDOW_PAGE = null;/);
    // What the generated module gives, as the code that uses it sees it.
    const onModule = await import(pathToFileURL(join(on.dir, ...gen.split("/"))).href);
    assert.equal(typeof onModule.createLocalUnlock, "function");
    assert.equal(onModule.UNLOCK_WINDOW_PAGE, "pages/unlockWindow.html");
    const offModule = await import(pathToFileURL(join(off.dir, ...gen.split("/"))).href);
    assert.equal(offModule.createLocalUnlock, null);
    assert.equal(offModule.UNLOCK_WINDOW_PAGE, null);
  } finally {
    env.cleanup();
  }
  // The module is the build's: a source file of that name fails the build.
  const planted = makeRoot({ "src/background/unlockStore.gen.mjs": "export {};\n" });
  try {
    await assert.rejects(
      build({ root: planted.root, webRoot: planted.webRoot, out: planted.out, wasmTar: planted.tarPath, variant: "release" }),
      /unlockStore\.gen\.mjs is generated by the build/,
    );
  } finally {
    planted.cleanup();
  }
});

test("the_release_check_refuses_a_use_of_the_unlock_database_other_than_the_deletion", async () => {
  const env = makeRoot();
  try {
    const release = await build({ root: env.root, webRoot: env.webRoot, wasmTar: env.tarPath, manifest: "mv2", out: env.out, variant: "release" });
    const hosts = readInternalHosts(env.root);
    assert.deepEqual(releaseProblems(release.files, hosts), []);
    for (const text of ['export const open = (idb) => idb.open("ferret-unlock", 1);\n', 'export const name = "ferret-unlock";\n']) {
      const files = new Map(release.files);
      files.set("background/storeProbe.mjs", Buffer.from(text));
      assert.ok(releaseProblems(files, hosts).some((p) => /background\/storeProbe\.mjs: names the unlock database other than to delete it/.test(p)), text);
    }
    // The deletion itself is the permitted form.
    const files = new Map(release.files);
    files.set("background/deleteProbe.mjs", Buffer.from('export const drop = (idb) => idb.deleteDatabase("ferret-unlock");\n'));
    assert.deepEqual(releaseProblems(files, hosts), []);
  } finally {
    env.cleanup();
  }
});

test("a_release_with_unlock_on_is_not_built_against_a_package_that_lacks_what_unlock_calls", async () => {
  // A package from before the feature (the lock names one until the lock is moved to a release that has the feature): the
  // stand-in has the files, but none of the functions that the PIN and passkey unlock call.
  const old = makeTar(wasmFiles({ unlock: false }));
  const current = makeTar(wasmFiles());
  const env = makeRoot();
  try {
    const lockFile = join(env.webRoot, "wasm.lock.json");
    /** @param {Buffer} tar */
    const pin = (tar) => {
      writeFileSync(join(env.dir, "wasm.tar.gz"), tar);
      writeFileSync(lockFile, `${JSON.stringify({ version: "0.8.0", url: "https://example.invalid/wasm.tar.gz", sha256: sha256(tar) })}\n`);
    };
    const options = { root: env.root, webRoot: env.webRoot, wasmTar: join(env.dir, "wasm.tar.gz") };

    // The old package: a release is refused, naming every missing function, with the status that tells a caller why.
    pin(old);
    for (const manifest of ["mv2", "mv3"]) {
      await assert.rejects(
        build({ ...options, out: join(env.out, `old-${manifest}`), manifest, variant: "release" }),
        (error) => {
          assert.ok(error instanceof WasmLacksUnlockError);
          assert.equal(error.exitCode, 3);
          for (const [file, names] of Object.entries(UNLOCK_WASM_EXPORTS)) {
            for (const name of names) assert.ok(error.message.includes(`${file}: ${name}`), `${manifest}: ${file}: ${name}`);
          }
          assert.match(error.message, /argon2_pin_key/);
          assert.match(error.message, /move web\/wasm\.lock\.json/);
          return true;
        },
      );
    }
    assert.deepEqual(wasmUnlockProblems(new Map(Object.entries(wasmFiles({ unlock: false })).map(([path, text]) => [path, Buffer.from(text)]))).length,
      Object.values(UNLOCK_WASM_EXPORTS).reduce((sum, names) => sum + names.length, 0));

    // The same package is fine where the unlock feature is off, and in the test variant (which takes a package of the tree).
    const off = await build({ ...options, out: join(env.out, "old-test"), manifest: "mv2", variant: "test", features: ["save"] });
    assert.deepEqual({ ...(await featuresOf(off.dir)) }, { save: true, unlock: false, passkeys: false });

    // A package that has them: the release is built.
    pin(current);
    const release = await build({ ...options, out: join(env.out, "current"), manifest: "mv2", variant: "release" });
    assert.deepEqual(release.features, ["passkeys", "save", "unlock"]);
    assert.deepEqual(wasmUnlockProblems(new Map(Object.entries(wasmFiles()).map(([path, text]) => [path, Buffer.from(text)]))), []);

    // One function missing is enough.
    const withoutOne = Object.fromEntries(Object.entries(wasmFiles()).map(([path, text]) => [path, text.replace("export function confirm_password() {}\n", "")]));
    pin(makeTar(withoutOne));
    await assert.rejects(
      build({ ...options, out: join(env.out, "one"), manifest: "mv2", variant: "release" }),
      /lacks pkg-web\/ferret_core_wasm\.js: confirm_password; move/,
    );
  } finally {
    env.cleanup();
  }
});

// -------------------------------------------------------------------------------------------- the `passkeys` feature

/**
 * Every path of the `passkeys` feature that a package still has: a file of the feature, a handler of the register that
 * serves one of its message types and does not refuse it, a page with one of its controls (the popup's section too), a
 * page module that builds such a control without asking FEATURES first, a script registered in the page's own world, a
 * use of the browser's credentials container, and any file other than the cleanup that names the ids of its scripts.
 * @param {string} dir the unpacked package
 * @param {Map<string, Buffer>} files
 * @param {readonly string[]} [extraTypes] message types that a test adds to the feature's own
 * @returns {Promise<string[]>}
 */
async function passkeyPathsIn(dir, files, extraTypes = []) {
  /** @type {string[]} */
  const found = [];
  const types = [...PASSKEY_PATHS.types, ...extraTypes];
  for (const path of PASSKEY_PATHS.files) if (files.has(path)) found.push(`file ${path}`);
  const register = files.get("background/handlers.gen.mjs")?.toString("utf8") ?? "";
  const handlers = [...register.matchAll(/from "\.\/(handlers\/[^"]+)"/g)].map((m) => `background/${m[1]}`);
  assert.ok(handlers.length > 0, "the register names the handlers");
  for (const path of handlers) {
    const handler = (await import(pathToFileURL(join(dir, ...path.split("/"))).href)).default;
    const served = (handler?.types ?? []).filter((/** @type {string} */ type) => types.includes(type));
    if (served.length > 0 && !(await refuses(handler, served))) found.push(`handler ${path} serves ${served.join(", ")}`);
  }
  for (const [path, bytes] of files) {
    if (WASM_FILES.includes(path) || isTestOnlyPath(path)) continue;
    const text = bytes.toString("utf8");
    if (path.endsWith(".html") && text.includes(PASSKEY_PATHS.control)) found.push(`control in ${path}`);
    if (path.startsWith("pages/") && path.endsWith(".mjs") && PASSKEY_PATHS.controlInCode.test(text) && !/from\s+["']\.\.\/shared\/features\.mjs["']/.test(text)) {
      found.push(`control in ${path} without FEATURES`);
    }
    if (/\.(?:mjs|js|html)$/.test(path)) {
      if (PAGE_WORLD_PATTERN.test(text)) found.push(`script in the page's own world in ${path}`);
      if (/CredentialsContainer/.test(text)) found.push(`credentials container in ${path}`);
      if (path !== PASSKEY_PATHS.cleanup && text.includes(PASSKEY_PATHS.scriptIds)) found.push(`script id in ${path}`);
    }
  }
  return found;
}

test("the_passkeys_feature_is_on_in_release_and_in_test", async () => {
  assert.deepEqual([...FEATURES], ["save", "unlock", "passkeys"]);
  assert.deepEqual([...DEFAULT_FEATURES.release], ["save", "unlock", "passkeys"], "a release has passkeys on");
  assert.deepEqual([...DEFAULT_FEATURES.test], ["save", "unlock", "passkeys"], "the test variant has it on");
  assert.deepEqual([...RELEASE_FEATURES], ["save", "unlock", "passkeys"]);
  assert.deepEqual(Object.keys(FEATURE_FILES).sort(), ["passkeys", "save", "unlock"]);
  assert.equal(PASSKEY_CLEANUP_FILE, "background/passkeyCleanup.mjs");
  assert.deepEqual([...PASSKEY_SCRIPT_IDS], ["ferret-passkey-main", "ferret-passkey-bridge"]);
  for (const id of PASSKEY_SCRIPT_IDS) assert.ok(id.startsWith(PASSKEY_SCRIPT_ID_PREFIX), id);

  // A file of the feature for every path that a build does not write itself (the joined scripts are the build's) and that
  // the tree does not have yet (the real one is used where it exists).
  /** @type {Record<string, string>} */
  const stubs = {};
  for (const path of PASSKEY_PATHS.files) {
    if (path.endsWith(".inject.js") || existsSync(join(extensionRoot, "src", ...path.split("/")))) continue;
    stubs[`src/${path}`] = path.endsWith(".html") ? "<!doctype html><title>x</title>\n" : "export {};\n";
  }
  const env = makeRoot(stubs);
  try {
    const options = { root: env.root, webRoot: env.webRoot, wasmTar: env.tarPath };
    for (const manifest of ["mv2", "mv3"]) {
      const release = await build({ ...options, out: join(env.out, `r-${manifest}`), manifest, variant: "release" });
      const testBuild = await build({ ...options, out: join(env.out, `t-${manifest}`), manifest, variant: "test" });
      assert.deepEqual([...release.features].sort(), ["passkeys", "save", "unlock"], manifest);
      assert.deepEqual({ ...(await featuresOf(release.dir)) }, { save: true, unlock: true, passkeys: true }, manifest);
      assert.deepEqual({ ...(await featuresOf(testBuild.dir)) }, { save: true, unlock: true, passkeys: true }, manifest);
      assert.equal(release.files.get(FEATURES_FILE)?.toString("utf8"), featuresModule(["save", "unlock", "passkeys"], new Map()));
      assert.equal(testBuild.files.get(FEATURES_FILE)?.toString("utf8"), featuresModule(["save", "unlock", "passkeys"], new Map()));
      for (const path of PASSKEY_PATHS.files) {
        // The test stand-in of the chooser page is test-only: a release leaves it out like any test-only file.
        assert.equal(release.files.has(path), !isTestOnlyPath(path), `${manifest}: ${path} in a release`);
        if (!path.endsWith(".inject.js")) assert.equal(testBuild.files.has(path), true, `${manifest}: ${path} is in the test variant`);
      }
      // The page, the scripts of a page, the handlers and the popup part are in a release.
      for (const here of ["pages/passkey.html", "pages/passkey.mjs", "pages/popupPasskeys.mjs", "content/passkey.main.inject.js", "content/passkey.bridge.inject.js"]) assert.equal(release.files.has(here), true, here);
      assert.equal(release.files.get("background/passkeys.gen.mjs")?.toString("utf8").includes("./passkeyRequests.mjs"), true, manifest);
      assert.deepEqual(releaseProblems(release.files, readInternalHosts(env.root)), [], manifest);
    }
    // Each flag on its own: passkeys alone leaves out the files of the others, and the others leave out those of passkeys.
    const passkeysOnly = await build({ ...options, out: join(env.out, "p-only"), manifest: "mv2", variant: "test", features: ["passkeys"] });
    assert.deepEqual({ ...(await featuresOf(passkeysOnly.dir)) }, { save: false, unlock: false, passkeys: true });
    for (const path of [...SAVE_FILES, ...UNLOCK_FILES]) assert.equal(passkeysOnly.files.has(path), false, path);
    assert.equal(passkeysOnly.files.has("pages/passkey.html"), true);
    const others = await build({ ...options, out: join(env.out, "o-only"), manifest: "mv2", variant: "test", features: ["save", "unlock"] });
    assert.deepEqual({ ...(await featuresOf(others.dir)) }, { save: true, unlock: true, passkeys: false });
    assert.deepEqual(await passkeyPathsIn(others.dir, others.files), []);
    // A package with nothing on holds nothing of the feature either.
    const none = await build({ ...options, out: join(env.out, "none"), manifest: "mv2", variant: "test", features: [] });
    assert.deepEqual(await passkeyPathsIn(none.dir, none.files), []);
  } finally {
    env.cleanup();
  }

  // A file that stays in a package may not import a file of the feature by name: with the feature off the build refuses it.
  const dangling = makeRoot({ ...stubs, "src/background/probeImport.mjs": 'import "./passkeyRequests.mjs";\nexport {};\n' });
  try {
    const options = { root: dangling.root, webRoot: dangling.webRoot, wasmTar: dangling.tarPath, manifest: "mv2" };
    await build({ ...options, out: join(dangling.out, "on"), variant: "test" });
    await assert.rejects(build({ ...options, out: join(dangling.out, "off"), variant: "test", features: ["save", "unlock"] }), /passkeyRequests\.mjs/);
  } finally {
    dangling.cleanup();
  }
});

test("the_release_check_requires_passkeys_in_a_release", async () => {
  const env = makeRoot();
  try {
    const options = { root: env.root, webRoot: env.webRoot, wasmTar: env.tarPath, manifest: "mv2" };
    // The build's own release check refuses a release with the feature off (the flag-off variants are test builds).
    await assert.rejects(
      build({ ...options, out: join(env.out, "r-off"), variant: "release", features: ["save", "unlock"] }),
      /the feature passkeys is off, which a release must have on/,
    );
    const release = await build({ ...options, out: join(env.out, "r"), variant: "release" });
    const hosts = readInternalHosts(env.root);
    assert.deepEqual(releaseProblems(release.files, hosts), []);

    // The check on a finished package: the features module with passkeys off, in every way it can be written.
    for (const text of [
      featuresModule(["save", "unlock"], new Map()),
      'export const FEATURES = Object.freeze({"save":true,"unlock":true,"passkeys":false});\n',
      "export const FEATURES = Object.freeze({ save: true, unlock: true, passkeys: false });\n",
      "export const FEATURES = Object.freeze({ save: true, unlock: true, 'passkeys': 0 });\n",
      "export const FEATURES = Object.freeze({ save: true, unlock: true });\n",
    ]) {
      const files = new Map(release.files);
      files.set(FEATURES_FILE, Buffer.from(text));
      const problems = featureProblems(files);
      assert.ok(problems.some((p) => /the feature passkeys is off, which a release must have on/.test(p)), text);
    }
    // A file of the feature missing from a release package is refused, and so is a package without the features module.
    // The test-only stand-in of the chooser page is not one of them: a release leaves it out and may not hold it.
    for (const path of PASSKEY_PATHS.files) {
      const files = new Map(release.files);
      if (isTestOnlyPath(path)) {
        files.set(path, Buffer.from("x\n"));
        assert.ok(releaseProblems(files, hosts).some((p) => p.startsWith(`${path}: `)), path);
      } else {
        files.delete(path);
        assert.ok(featureProblems(files).includes(`${path}: belongs to the passkeys feature, which a release has on, and is missing`), path);
      }
    }
    const noModule = new Map(release.files);
    noModule.delete(FEATURES_FILE);
    assert.match(featureProblems(noModule).join("\n"), /shared\/features\.mjs is missing/);

    // A finished package whose WASM files are those of 0.11.0 (no candidate lookup, site check or import) is refused by the
    // release check too, whatever way it was made; the command says no to it as well.
    const old = wasmFiles({ passkeys: false });
    const stale = new Map(release.files);
    for (const path of WASM_FILES) stale.set(path, Buffer.from(old[path]));
    assert.ok(featureProblems(stale).some((p) => /the package lacks what the passkeys feature calls \(.*passkey_candidates.*passkey_import.*passkey_site/.test(p)));
    assert.deepEqual(featureProblems(stale).filter((p) => /unlock feature calls/.test(p)), []);
    const staleDir = join(env.out, "stale");
    for (const [path, bytes] of stale) {
      const target = join(staleDir, ...path.split("/"));
      mkdirSync(dirname(target), { recursive: true });
      writeFileSync(target, bytes);
    }
    const staleRan = spawnSync(process.execPath, [join(extensionRoot, "scripts", "build.mjs"), "--check-release", staleDir], { encoding: "utf8" });
    assert.equal(staleRan.status, 1, staleRan.stdout + staleRan.stderr);
    assert.match(staleRan.stderr, /the package lacks what the passkeys feature calls/);

    // The cleanup module is in the release too (it names the ids of the scripts, and only removes).
    assert.equal(release.files.has(PASSKEY_CLEANUP_FILE), true);
    assert.equal(release.files.get(PASSKEY_CLEANUP_FILE)?.toString("utf8").includes('"ferret-passkey-main"'), true);
    assert.doesNotMatch(release.files.get(PASSKEY_CLEANUP_FILE)?.toString("utf8") ?? "", /\bregisterContentScripts\(|world\s*:/);

    // The command the script runs (`scripts/check-ext-release.sh`) says no, with a non-zero status, to a package whose features
    // module has the feature off, and yes to the real one.
    const bad = join(env.out, "bad");
    for (const [path, bytes] of release.files) {
      const target = join(bad, ...path.split("/"));
      mkdirSync(dirname(target), { recursive: true });
      writeFileSync(target, path === FEATURES_FILE ? featuresModule(["save", "unlock"], new Map()) : bytes);
    }
    const ran = spawnSync(process.execPath, [join(extensionRoot, "scripts", "build.mjs"), "--check-release", bad], { encoding: "utf8" });
    assert.equal(ran.status, 1, ran.stdout + ran.stderr);
    assert.match(ran.stderr, /the feature passkeys is off, which a release must have on/);
    const good = spawnSync(process.execPath, [join(extensionRoot, "scripts", "build.mjs"), "--check-release", "--web-root", env.webRoot, release.dir], { encoding: "utf8" });
    assert.equal(good.status, 0, good.stdout + good.stderr);
  } finally {
    env.cleanup();
  }
  // The script names the passkeys feature in its header, so a reader of it sees the rule.
  assert.match(readFileSync(join(extensionRoot, "..", "scripts", "check-ext-release.sh"), "utf8"), /passkeys/);
});

test("a_release_with_passkeys_on_is_not_built_against_a_package_that_lacks_what_passkeys_calls", async () => {
  // The package of 0.11.0: it has the unlock functions and none of the passkey provider's (no candidate lookup, no site
  // check, no import). The lock names it until the pin change moves it to 0.12.0; a release built with it would sign
  // every passkey request wrongly or not at all, and is refused instead.
  const old = makeTar(wasmFiles({ passkeys: false }));
  const current = makeTar(wasmFiles());
  const env = makeRoot();
  try {
    const lockFile = join(env.webRoot, "wasm.lock.json");
    /** @param {Buffer} tar @param {string} [version] */
    const pin = (tar, version = "0.11.0") => {
      writeFileSync(join(env.dir, "wasm.tar.gz"), tar);
      writeFileSync(lockFile, `${JSON.stringify({ version, url: "https://example.invalid/wasm.tar.gz", sha256: sha256(tar) })}\n`);
    };
    const options = { root: env.root, webRoot: env.webRoot, wasmTar: join(env.dir, "wasm.tar.gz") };

    // The old package: a release is refused, naming the missing functions, with the status that tells a caller why (the
    // status of a build that a signing run or a CI job fails on).
    pin(old);
    for (const manifest of ["mv2", "mv3"]) {
      await assert.rejects(
        build({ ...options, out: join(env.out, `old-${manifest}`), manifest, variant: "release" }),
        (error) => {
          assert.ok(error instanceof WasmLacksPasskeysError);
          assert.ok(error instanceof WasmLacksUnlockError);
          assert.equal(error.exitCode, 3);
          for (const [file, names] of Object.entries(PASSKEY_WASM_EXPORTS)) {
            for (const name of names) assert.ok(error.message.includes(`${file}: ${name}`), `${manifest}: ${file}: ${name}`);
          }
          assert.match(error.message, /passkey_candidates/);
          assert.match(error.message, /passkey_site/);
          assert.match(error.message, /passkey_import/);
          assert.match(error.message, /move web\/wasm\.lock\.json/);
          return true;
        },
      );
    }
    assert.equal(wasmPasskeyProblems(new Map(Object.entries(wasmFiles({ passkeys: false })).map(([path, text]) => [path, Buffer.from(text)]))).length,
      Object.values(PASSKEY_WASM_EXPORTS).reduce((sum, names) => sum + names.length, 0));
    // That package still has what unlock calls, so only the passkeys check is what refuses it.
    assert.deepEqual(wasmUnlockProblems(new Map(Object.entries(wasmFiles({ passkeys: false })).map(([path, text]) => [path, Buffer.from(text)]))), []);

    // The same package is fine where the feature is off, and in the test variant (which takes the package of the tree).
    const off = await build({ ...options, out: join(env.out, "old-off"), manifest: "mv2", variant: "test", features: ["save", "unlock"] });
    assert.deepEqual({ ...(await featuresOf(off.dir)) }, { save: true, unlock: true, passkeys: false });
    const oldTest = await build({ ...options, out: join(env.out, "old-test"), manifest: "mv2", variant: "test" });
    assert.deepEqual({ ...(await featuresOf(oldTest.dir)) }, { save: true, unlock: true, passkeys: true });

    // A package that has them: the release is built.
    pin(current, "0.12.0");
    const release = await build({ ...options, out: join(env.out, "current"), manifest: "mv2", variant: "release" });
    assert.deepEqual([...release.features].sort(), ["passkeys", "save", "unlock"]);
    assert.deepEqual(wasmPasskeyProblems(new Map(Object.entries(wasmFiles()).map(([path, text]) => [path, Buffer.from(text)]))), []);

    // One function missing is enough, in the glue and in the worker protocol alike.
    const withoutOne = Object.fromEntries(Object.entries(wasmFiles()).map(([path, text]) => [path, text.replace("export function passkey_import() {}\n", "")]));
    pin(makeTar(withoutOne));
    await assert.rejects(
      build({ ...options, out: join(env.out, "one"), manifest: "mv2", variant: "release" }),
      /lacks pkg-web\/ferret_core_wasm\.js: passkey_import, js\/protocol\.mjs: passkey_import; move/,
    );
    // The protocol names a method as a key of its tables, which counts; a package that has it nowhere does not.
    const keyed = new Map(Object.entries(wasmFiles({ passkeys: false })).map(([path, text]) => [path, Buffer.from(text)]));
    keyed.set("js/protocol.mjs", Buffer.from("const WELL_FORMED_ARGS = {\n  passkey_site: [[1, true]],\n  \"passkey_import\": [[1, \"u64\"]],\n};\n"));
    assert.deepEqual(wasmPasskeyProblems(keyed).filter((m) => m.startsWith("js/protocol.mjs")), []);
    keyed.set("js/protocol.mjs", Buffer.from("// passkey_site and passkey_import are said in a comment only\n"));
    assert.equal(wasmPasskeyProblems(keyed).filter((m) => m.startsWith("js/protocol.mjs")).length, 2);
  } finally {
    env.cleanup();
  }
});

test("a_package_with_passkeys_off_has_no_passkey_path", async () => {
  // The repository's own sources: nothing of the feature in a package built with it off (a test build; a release always has
  // it on), in either manifest version. The only trace is the module that removes a registration a build with it on left.
  const env = makeRoot();
  try {
    const options = { root: env.root, webRoot: env.webRoot, wasmTar: env.tarPath };
    for (const manifest of ["mv2", "mv3"]) {
      const off = await build({ ...options, out: join(env.out, `t-${manifest}`), manifest, variant: "test", features: ["save", "unlock"] });
      assert.deepEqual(await passkeyPathsIn(off.dir, off.files), [], `test ${manifest}`);
      // No `content/passkey.*`, no `pages/passkey.html`, no popup part.
      assert.deepEqual([...off.files.keys()].filter((path) => /^content\/passkey/.test(path) || /^pages\/(?:passkey|popupPasskeys)/.test(path)), [], manifest);
      // The permitted trace is there, and it is the only one: the ids are in the one module, and nothing registers a script.
      const holders = [...off.files].filter(([path, bytes]) => !WASM_FILES.includes(path) && bytes.toString("utf8").includes(PASSKEY_PATHS.scriptIds)).map(([path]) => path);
      assert.deepEqual(holders, [PASSKEY_PATHS.cleanup], manifest);
      // The manifest asks for no content script of the feature, on or off: the script is registered at run time.
      const release = await build({ ...options, out: join(env.out, `r-${manifest}`), manifest, variant: "release" });
      const manifestText = /** @type {Buffer} */ (release.files.get("manifest.json")).toString("utf8");
      assert.doesNotMatch(manifestText, /passkey|content_scripts/i, manifest);
    }
  } finally {
    env.cleanup();
  }

  // The check finds each kind of path (so an empty answer above means something): a handler that serves a type of the
  // feature, a page with a control of it, a page module that builds one without asking FEATURES, a script in the page's
  // own world, the credentials container, a script id, and a file of the feature.
  const probe = makeRoot({
    "src/background/handlers/keyProbe.handler.mjs": 'export default { types: ["passkey_probe"], channel: "ui", handle: async () => ({ ok: true }) };\n',
    "src/background/handlers/gatedProbe.handler.mjs": [
      'import { FEATURES } from "../../shared/features.mjs";',
      "export default {",
      '  types: ["passkey_probe_gated"],',
      '  channel: "ui",',
      "  handle: async () => {",
      '    if (!FEATURES.passkeys) throw Object.assign(new Error("not_available"), { code: "not_available" });',
      "    return { ok: true };",
      "  },",
      "};",
      "",
    ].join("\n"),
    "src/pages/passkeyProbe.html": '<!doctype html><section data-feature="passkeys" data-role="probe">x</section>\n',
    "src/pages/passkeyView.mjs": 'export const section = { "data-feature": "passkeys" };\n',
    "src/pages/passkeyGated.mjs": 'import { FEATURES } from "../shared/features.mjs";\nexport const section = FEATURES.passkeys ? { "data-feature": "passkeys" } : null;\n',
    "src/background/worldProbe.mjs": 'export const register = (s) => s.registerContentScripts([{ id: "x", world: "MAIN" }]);\n',
    "src/content/overrideProbe.mjs": "export const keep = CredentialsContainer.prototype.get;\n",
    "src/background/idProbe.mjs": 'export const id = "ferret-passkey-main";\n',
  });
  try {
    const options = { root: probe.root, webRoot: probe.webRoot, wasmTar: probe.tarPath, manifest: "mv2" };
    const off = await build({ ...options, out: join(probe.out, "off"), variant: "test", features: ["save", "unlock"] });
    off.files.set("pages/passkey.html", Buffer.from("<!doctype html>\n"));
    off.files.set("content/passkey.main.inject.js", Buffer.from("void 0;\n"));
    assert.deepEqual((await passkeyPathsIn(off.dir, off.files, ["passkey_probe", "passkey_probe_gated"])).sort(), [
      "control in pages/passkeyProbe.html",
      "control in pages/passkeyView.mjs without FEATURES",
      "credentials container in content/overrideProbe.mjs",
      "file content/passkey.main.inject.js",
      "file pages/passkey.html",
      "handler background/handlers/keyProbe.handler.mjs serves passkey_probe",
      "script id in background/idProbe.mjs",
      "script in the page's own world in background/worldProbe.mjs",
    ]);
    // With the feature on, the gated handler serves its type: it refuses only because the feature is off.
    const on = await build({ ...options, out: join(probe.out, "on"), variant: "test" });
    const gated = (await import(pathToFileURL(join(on.dir, "background", "handlers", "gatedProbe.handler.mjs")).href)).default;
    assert.deepEqual(await gated.handle({}, {}), { ok: true });
  } finally {
    probe.cleanup();
  }
});

test("a_build_with_passkeys_off_unregisters_a_left_over_main_world_script", async () => {
  const env = makeRoot();
  /** @param {string[]} registered the ids the fake browser holds @param {{ failUnregister?: boolean }} [flags] */
  const scriptingFor = (registered, flags = {}) => {
    /** @type {{ queried: string[][], removed: string[][] }} */
    const calls = { queried: [], removed: [] };
    const scripting = {
      executeScript: async () => [],
      registerContentScripts: async () => {},
      getRegisteredContentScripts: async (/** @type {{ ids?: string[] }} */ filter) => {
        calls.queried.push([...(filter?.ids ?? [])]);
        return registered.filter((id) => !filter?.ids || filter.ids.includes(id)).map((id) => ({ id, world: "MAIN", persistAcrossSessions: true }));
      },
      unregisterContentScripts: async (/** @type {{ ids: string[] }} */ filter) => {
        calls.removed.push([...filter.ids]);
        if (flags.failUnregister) throw new Error("no");
        for (const id of filter.ids) {
          if (!registered.includes(id)) throw new Error(`Nonexistent script ID '${id}'`);
          registered.splice(registered.indexOf(id), 1);
        }
      },
    };
    return { scripting, calls, registered };
  };
  /** The removals that name the feature's scripts (the capture host removes its own script, with ids of its own, and no call mixes them). @param {string[][]} calls */
  const ours = (calls) => {
    for (const ids of calls) assert.ok(ids.every((id) => id.startsWith("ferret-passkey-")) || ids.every((id) => !id.startsWith("ferret-passkey-")), `a call mixes ids: ${ids}`);
    return calls.filter((ids) => ids.some((id) => id.startsWith("ferret-passkey-")));
  };
  try {
    const options = { root: env.root, webRoot: env.webRoot, wasmTar: env.tarPath, manifest: "mv3" };
    // Off (a test build with the flag off; a release always has it on): the scripts of the feature are removed, once, and
    // nothing else is.
    for (const [name, variant, features] of /** @type {const} */ ([["test, off", "test", ["save", "unlock"]]])) {
      const result = await build({ ...options, out: join(env.out, name.replace(/\W/g, "")), variant, ...(features ? { features: [...features] } : {}) });
      const world = scriptingFor(["ferret-passkey-main", "ferret-passkey-bridge", "ferret-capture"]);
      try {
        await boot(result.dir, { scripting: world.scripting });
      } finally {
        delete (/** @type {any} */ (globalThis)).browser;
      }
      assert.deepEqual(ours(world.calls.removed), [["ferret-passkey-main", "ferret-passkey-bridge"]], name);
      assert.deepEqual(world.registered.filter((id) => id.startsWith("ferret-passkey-")), [], `${name}: none of the feature's scripts is left`);
      for (const ids of ours(world.calls.queried)) assert.ok(ids.every((id) => PASSKEY_SCRIPT_IDS.includes(id)), `${name}: only its own ids are asked for`);
    }
    // Only the one that is there is named (an id that is not registered makes the browser refuse the call), and none at all
    // is no call. Each start gets a build of its own, because a module that was loaded once is not run again.
    let n = 0;
    /** @param {string[]} registered @param {{ failUnregister?: boolean }} [flags] */
    const startOne = async (registered, flags) => {
      const fresh = await build({ ...options, out: join(env.out, `fresh-${n++}`), variant: "test", features: ["save", "unlock"] });
      const world = scriptingFor([...registered], flags);
      try {
        const started = await boot(fresh.dir, { scripting: world.scripting });
        return { world, started };
      } finally {
        delete (/** @type {any} */ (globalThis)).browser;
      }
    };
    assert.deepEqual(ours((await startOne(["ferret-passkey-bridge"])).world.calls.removed), [["ferret-passkey-bridge"]]);
    assert.deepEqual(ours((await startOne([])).world.calls.removed), []);
    // A browser that refuses the removal does not stop the background from starting.
    const failing = await startOne(["ferret-passkey-main"], { failUnregister: true });
    assert.ok(failing.started.onMessage.length > 0, "the background started");
    assert.deepEqual(ours(failing.world.calls.removed), [["ferret-passkey-main"]]);
    // On (a release, and the test variant): the feature owns its registrations, and the cleanup does not run.
    const on = await build({ ...options, out: join(env.out, "on"), variant: "release" });
    const owned = scriptingFor(["ferret-passkey-main", "ferret-passkey-bridge"]);
    try {
      await boot(on.dir, { scripting: owned.scripting });
    } finally {
      delete (/** @type {any} */ (globalThis)).browser;
    }
    // With passkeys on the cleanup does not run: the feature's own registry makes the registration agree with the setting,
    // the permission and the sign-in, and this fake browser has none of them, so both scripts go, in one call.
    assert.deepEqual(ours(owned.calls.removed), [["ferret-passkey-main", "ferret-passkey-bridge"]]);
    assert.deepEqual(owned.registered, []);
  } finally {
    env.cleanup();
  }

  // The module itself: it never throws and never rejects, whatever the browser does.
  assert.equal(await removePasskeyScripts(undefined), false);
  assert.equal(await removePasskeyScripts(null), false);
  assert.equal(await removePasskeyScripts(/** @type {any} */ ({ getRegisteredContentScripts: () => { throw new Error("no"); }, unregisterContentScripts: async () => {} })), false);
  assert.equal(await removePasskeyScripts(/** @type {any} */ ({ getRegisteredContentScripts: async () => undefined, unregisterContentScripts: async () => {} })), true);
  assert.equal(await removePasskeyScripts(/** @type {any} */ ({ getRegisteredContentScripts: async () => [{ id: "ferret-passkey-main" }], unregisterContentScripts: async () => { throw new Error("no"); } })), false);
  // It names no id that is not its own, even if the browser answers with more.
  /** @type {string[][]} */
  const removed = [];
  const noisy = /** @type {any} */ ({
    getRegisteredContentScripts: async () => [{ id: "ferret-capture" }, { id: "ferret-passkey-bridge" }, { id: "other" }],
    unregisterContentScripts: async (/** @type {{ ids: string[] }} */ filter) => { removed.push(filter.ids); },
  });
  assert.equal(await removePasskeyScripts(noisy), true);
  assert.deepEqual(removed, [["ferret-passkey-bridge"]]);
});

test("every_file_of_the_passkey_feature_in_the_tree_is_listed", () => {
  // The guard over the real sources: a file whose name says passkey or webauthn belongs to the feature and must be in
  // PASSKEY_FILES (so a release leaves it out and the release check refuses it), apart from the cleanup module, which a
  // package without the feature keeps, and the feature's message handler, which every package keeps and which refuses while
  // the feature is off. Only code and pages are scanned (`.mjs` and `.html`): the strings and the styles
  // (locales/<lang>/*.json, styles/*.css) are merged into one catalog and one stylesheet and are not package files of their own.
  // A file that a joined script is built from is a build input and is listed too.
  const src = join(extensionRoot, "src");
  /** @param {string} dir @returns {string[]} */
  const walk = (dir) =>
    readdirSync(dir, { withFileTypes: true }).flatMap((entry) => (entry.isDirectory() ? walk(join(dir, entry.name)) : [join(dir, entry.name)]));
  const named = walk(src)
    .map((file) => file.slice(src.length + 1).replace(/\\/g, "/"))
    .filter((path) => /\.(?:mjs|html)$/.test(path) && /passkey|webauthn/i.test(path))
    .filter((path) => path !== PASSKEY_CLEANUP_FILE)
    // A handler stays in every package and refuses while the feature is off (passkeyPathsIn checks that it does).
    .filter((path) => !/^background\/handlers\/[A-Za-z]+\.handler\.mjs$/.test(path));
  const missing = named.filter((path) => !PASSKEY_FILES.includes(path));
  assert.deepEqual(missing, [], "a file named for the passkey feature that PASSKEY_FILES does not list");
  // The list holds each file once, and the joined scripts come as a pair with their sources.
  assert.equal(new Set(PASSKEY_FILES).size, PASSKEY_FILES.length);
  assert.ok(PASSKEY_FILES.includes("shared/webauthnWire.mjs"));
});
