// The build flags. `save` (saving and updating passwords from the extension, and the
// generator): on in a release and in the test variant. `unlock` (PIN and passkey unlock): on in the test variant and
// off in a release until it is released. A test build can turn either off (`--features none`), and "off" means that no
// path of the feature is there. A package built with `save` off holds no capture script,
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
// The lists in SAVE_PATHS and UNLOCK_PATHS name what belongs to each feature. Each change that adds
// a file, a message type or a control of the feature adds it there. The `unlock` feature follows the same rules, with
// `data-feature="unlock"` and its own lists; the one trace it leaves with the flag off is the deletion of its database
// at start (`deleteDatabase("ferret-unlock")`, in background/unlockCleanup.mjs).
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { pathToFileURL } from "node:url";
import { test } from "node:test";
import { CONTENT_TYPES, UI_TYPES } from "../../src/shared/protocol.mjs";
import { readGraph } from "./importGraph.mjs";
import {
  build, DEFAULT_FEATURES, FEATURE_FILES, FEATURES, FEATURES_FILE, featuresModule, featureProblems, isTestOnlyPath, parseFeatures, RELEASE_FEATURES,
  releaseProblems, readInternalHosts, SAVE_FILES, UNLOCK_FILES, UNLOCK_STORE_FILE, unlockStoreModule, WASM_FILES,
} from "../../scripts/build.mjs";
import { boot } from "./bootBackground.mjs";
import { extensionRoot, makeRoot } from "./buildHelpers.mjs";

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
  files: Object.freeze(["pages/unlockWindow.html", "pages/unlockWindow.mjs", "background/localUnlock.mjs"]),
  /** Message types of the feature (sent by the extension's own pages only). */
  types: Object.freeze(["pin_set", "pin_unlock", "pin_off", "unlock_policy", "prf_options", "prf_unlock"]),
  /** The attribute every control of the feature carries. */
  control: 'data-feature="unlock"',
  controlInCode: /["']data-feature["']\s*:\s*["']unlock["']|data-feature=\\?["']unlock/,
  /** The database of the feature: a package with the feature off names it only to delete it. */
  database: "ferret-unlock",
  /** The one module that deletes it, at start, when the feature is off. */
  cleanup: "background/unlockCleanup.mjs",
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

/** @param {string} dir @returns {Promise<{ save: boolean, unlock: boolean }>} */
const featuresOf = async (dir) => (await import(pathToFileURL(join(dir, ...FEATURES_FILE.split("/"))).href)).FEATURES;

test("the_save_feature_is_on_in_release_and_in_test", async () => {
  assert.deepEqual([...FEATURES], ["save", "unlock"]);
  assert.deepEqual([...DEFAULT_FEATURES.release], ["save"]);
  assert.deepEqual([...DEFAULT_FEATURES.test], ["save", "unlock"]);
  assert.deepEqual([...RELEASE_FEATURES], ["save"], "a release has save on");
  assert.deepEqual([...SAVE_FILES], [...SAVE_PATHS.files]);

  const env = makeRoot();
  try {
    const options = { root: env.root, webRoot: env.webRoot, wasmTar: env.tarPath };
    for (const manifest of ["mv2", "mv3"]) {
      const release = await build({ ...options, out: join(env.out, `r-${manifest}`), manifest, variant: "release" });
      const testBuild = await build({ ...options, out: join(env.out, `t-${manifest}`), manifest, variant: "test" });
      assert.deepEqual(release.features, ["save"]);
      assert.deepEqual(testBuild.features, ["save", "unlock"]);
      // The generated module says so, in each package, and cannot be changed at run time.
      const releaseOn = await featuresOf(release.dir);
      const testOn = await featuresOf(testBuild.dir);
      assert.deepEqual({ ...releaseOn }, { save: true, unlock: false }, manifest);
      assert.deepEqual({ ...testOn }, { save: true, unlock: true }, manifest);
      assert.equal(Object.isFrozen(releaseOn), true);
      assert.equal(release.files.get(FEATURES_FILE)?.toString("utf8"), featuresModule(["save"], new Map()));
      // The capture script and its sources are in the release, and no test-only code is.
      for (const path of SAVE_FILES) assert.ok(release.files.has(path), `${manifest}: ${path} is in a release`);
      assert.deepEqual([...release.files.keys()].filter((path) => isTestOnlyPath(path) || path.startsWith("test/")), [], manifest);
    }

    // --features overrides the variant's default: a test build with the feature off.
    const testOff = await build({ ...options, out: join(env.out, "t-off"), manifest: "mv2", variant: "test", features: [] });
    assert.deepEqual({ ...(await featuresOf(testOff.dir)) }, { save: false, unlock: false });
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
      assert.deepEqual({ ...(await featuresOf(off.dir)) }, { save: false, unlock: false });
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
  const unaccounted = all.filter((type) => !FIRST_RELEASE_TYPES.includes(type) && !SAVE_PATHS.types.includes(type) && !UNLOCK_PATHS.types.includes(type));
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

test("the_unlock_feature_is_off_in_release_and_on_in_test", async () => {
  assert.deepEqual([...FEATURES], ["save", "unlock"]);
  assert.deepEqual([...DEFAULT_FEATURES.release], ["save"], "a release has unlock off until it is released");
  assert.deepEqual([...DEFAULT_FEATURES.test], ["save", "unlock"], "the test variant has it on");
  assert.deepEqual([...RELEASE_FEATURES], ["save"]);
  assert.deepEqual([...UNLOCK_FILES], [...UNLOCK_PATHS.files]);
  assert.deepEqual(Object.keys(FEATURE_FILES).sort(), ["save", "unlock"]);

  const env = makeRoot({
    // A window page of the feature: in the package with the feature on, and left out with it off.
    "src/pages/unlockWindow.html": "<!doctype html><title>x</title>\n",
    "src/pages/unlockWindow.mjs": "export {};\n",
    // The PIN store: the one module that opens the unlock database.
    "src/background/localUnlock.mjs": 'export const UNLOCK_DB_NAME = "ferret-unlock";\n',
  });
  try {
    const options = { root: env.root, webRoot: env.webRoot, wasmTar: env.tarPath };
    for (const manifest of ["mv2", "mv3"]) {
      const release = await build({ ...options, out: join(env.out, `r-${manifest}`), manifest, variant: "release" });
      const testBuild = await build({ ...options, out: join(env.out, `t-${manifest}`), manifest, variant: "test" });
      assert.deepEqual({ ...(await featuresOf(release.dir)) }, { save: true, unlock: false }, manifest);
      assert.deepEqual({ ...(await featuresOf(testBuild.dir)) }, { save: true, unlock: true }, manifest);
      assert.equal(release.files.get(FEATURES_FILE)?.toString("utf8"), featuresModule(["save"], new Map()));
      for (const path of UNLOCK_PATHS.files) {
        assert.equal(release.files.has(path), false, `${manifest}: ${path} is not in a release`);
        assert.equal(testBuild.files.has(path), true, `${manifest}: ${path} is in the test variant`);
      }
      assert.deepEqual(await unlockPathsIn(release.dir, release.files), [], manifest);
    }
    // Each flag on its own: unlock alone leaves out the files of save, and save alone those of unlock.
    const unlockOnly = await build({ ...options, out: join(env.out, "u-only"), manifest: "mv2", variant: "test", features: ["unlock"] });
    assert.deepEqual({ ...(await featuresOf(unlockOnly.dir)) }, { save: false, unlock: true });
    for (const path of SAVE_FILES) assert.equal(unlockOnly.files.has(path), false, path);
    for (const path of UNLOCK_PATHS.files) assert.equal(unlockOnly.files.has(path), true, path);
    const saveOnly = await build({ ...options, out: join(env.out, "s-only"), manifest: "mv2", variant: "test", features: ["save"] });
    assert.deepEqual({ ...(await featuresOf(saveOnly.dir)) }, { save: true, unlock: false });
    for (const path of UNLOCK_PATHS.files) assert.equal(saveOnly.files.has(path), false, path);
    for (const path of SAVE_FILES) assert.equal(saveOnly.files.has(path), true, path);
  } finally {
    env.cleanup();
  }
});

test("the_release_check_refuses_a_release_build_with_unlock_on", async () => {
  const env = makeRoot();
  try {
    const options = { root: env.root, webRoot: env.webRoot, wasmTar: env.tarPath, manifest: "mv2" };
    // The build's own release check refuses it.
    await assert.rejects(
      build({ ...options, out: join(env.out, "r-on"), variant: "release", features: ["save", "unlock"] }),
      /the feature unlock is on, which a release may not have/,
    );
    const release = await build({ ...options, out: join(env.out, "r"), variant: "release" });
    const hosts = readInternalHosts(env.root);
    assert.deepEqual(releaseProblems(release.files, hosts), []);

    // The check on a finished package: the features module with unlock on, in every way it can be written.
    for (const text of [
      featuresModule(["save", "unlock"], new Map()),
      'export const FEATURES = Object.freeze({"save":true,"unlock":true});\n',
      "export const FEATURES = Object.freeze({ save: true, unlock: true });\n",
      "export const FEATURES = Object.freeze({ save: true, 'unlock': 1 });\n",
    ]) {
      const files = new Map(release.files);
      files.set(FEATURES_FILE, Buffer.from(text));
      const problems = featureProblems(files);
      assert.ok(problems.some((p) => /the feature unlock is on, which a release may not have/.test(p)), text);
    }
    // A file of the feature in a release package is refused, and so is a package without the features module.
    for (const path of UNLOCK_PATHS.files) {
      const files = new Map(release.files);
      files.set(path, Buffer.from("x\n"));
      assert.ok(featureProblems(files).includes(`${path}: belongs to the unlock feature, which a release may not have`), path);
    }
    const noModule = new Map(release.files);
    noModule.delete(FEATURES_FILE);
    assert.match(featureProblems(noModule).join("\n"), /shared\/features\.mjs is missing/);

    // The command the script runs (`scripts/check-ext-release.sh`) says no, with a non-zero status, to the same package.
    const bad = join(env.out, "bad");
    for (const [path, bytes] of release.files) {
      const target = join(bad, ...path.split("/"));
      mkdirSync(dirname(target), { recursive: true });
      writeFileSync(target, path === FEATURES_FILE ? featuresModule(["save", "unlock"], new Map()) : bytes);
    }
    const ran = spawnSync(process.execPath, [join(extensionRoot, "scripts", "build.mjs"), "--check-release", bad], { encoding: "utf8" });
    assert.equal(ran.status, 1, ran.stdout + ran.stderr);
    assert.match(ran.stderr, /the feature unlock is on, which a release may not have/);
    const good = spawnSync(process.execPath, [join(extensionRoot, "scripts", "build.mjs"), "--check-release", "--web-root", env.webRoot, release.dir], { encoding: "utf8" });
    assert.equal(good.status, 0, good.stdout + good.stderr);
  } finally {
    env.cleanup();
  }
  // The script names the unlock feature in its header, so a reader of it sees the rule.
  assert.match(readFileSync(join(extensionRoot, "..", "scripts", "check-ext-release.sh"), "utf8"), /unlock/);
});

test("a_release_package_with_unlock_off_has_no_pin_or_prf_path", async () => {
  // The repository's own sources: nothing of the feature in a package built with it off, in either manifest version
  // and in either variant. The only trace is the deletion of the database at start.
  const env = makeRoot();
  try {
    const options = { root: env.root, webRoot: env.webRoot, wasmTar: env.tarPath };
    for (const manifest of ["mv2", "mv3"]) {
      const release = await build({ ...options, out: join(env.out, `r-${manifest}`), manifest, variant: "release" });
      assert.deepEqual(await unlockPathsIn(release.dir, release.files), [], `release ${manifest}`);
      const off = await build({ ...options, out: join(env.out, `t-${manifest}`), manifest, variant: "test", features: ["save"] });
      assert.deepEqual(await unlockPathsIn(off.dir, off.files), [], `test ${manifest}`);
      // The permitted trace is there, and it is the only one: the one module that holds the name, in the one form.
      const holders = [...release.files].filter(([path, bytes]) => !WASM_FILES.includes(path) && bytes.toString("utf8").includes(UNLOCK_PATHS.database)).map(([path]) => path);
      assert.deepEqual(holders, [UNLOCK_PATHS.cleanup], manifest);
      assert.equal(release.files.get(UNLOCK_PATHS.cleanup)?.toString("utf8").includes(`deleteDatabase("${UNLOCK_PATHS.database}")`), true);
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
    // Off (a release; a test build with the flag off): the deletion of the one database, once, and nothing else.
    for (const [name, variant, features] of /** @type {const} */ ([["release", "release", undefined], ["test, off", "test", ["save"]]])) {
      const result = await build({ ...options, out: join(env.out, name.replace(/\W/g, "")), variant, ...(features ? { features: [...features] } : {}) });
      deleted.length = 0;
      try {
        await boot(result.dir);
      } finally {
        delete (/** @type {any} */ (globalThis)).browser;
      }
      assert.deepEqual(deleted, ["ferret-unlock"], name);
    }
    // On (the test variant): the feature owns the database, and the cleanup does not run.
    const on = await build({ ...options, out: join(env.out, "on"), variant: "test" });
    deleted.length = 0;
    try {
      await boot(on.dir);
    } finally {
      delete (/** @type {any} */ (globalThis)).browser;
    }
    assert.deepEqual(deleted, [], "with unlock on the cleanup does not run");
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
      const on = await build({ ...options, out: join(env.out, `on-${manifest}`), manifest, variant: "test" });
      assert.deepEqual(holders(on.files), ["background/localUnlock.mjs"], `${manifest}: unlock on`);
      for (const [name, variant, features] of /** @type {const} */ ([["release", "release", undefined], ["test-off", "test", ["save"]]])) {
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
    const on = await build({ ...options, out: join(env.out, "on"), variant: "test" });
    const off = await build({ ...options, out: join(env.out, "off"), variant: "release" });
    const gen = UNLOCK_STORE_FILE;
    assert.equal(on.files.get(gen)?.toString("utf8"), unlockStoreModule(["save", "unlock"], new Map()));
    assert.equal(off.files.get(gen)?.toString("utf8"), unlockStoreModule(["save"], new Map()));
    // With the feature on it re-exports the store and names the window page; with it off it holds null and imports nothing,
    // so the release has no import edge to the files the build leaves out.
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
