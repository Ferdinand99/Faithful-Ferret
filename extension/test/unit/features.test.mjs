// The build flag `save` (saving and updating passwords from the extension, and the
// generator): on in a release and in the test variant. A test build can turn it
// off (`--features none`), and "off" means that no path of the
// feature is there. A package built with `save` off holds no capture script,
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
// The lists in SAVE_PATHS name what belongs to the feature. Each change that adds
// a file, a message type or a control of the feature adds it there.
import assert from "node:assert/strict";
import { join } from "node:path";
import { pathToFileURL } from "node:url";
import { test } from "node:test";
import { CONTENT_TYPES, UI_TYPES } from "../../src/shared/protocol.mjs";
import { readGraph } from "./importGraph.mjs";
import {
  build, DEFAULT_FEATURES, FEATURES, FEATURES_FILE, featuresModule, isTestOnlyPath, parseFeatures, RELEASE_FEATURES, SAVE_FILES, WASM_FILES,
} from "../../scripts/build.mjs";
import { makeRoot } from "./buildHelpers.mjs";

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

/** @param {string} dir @returns {Promise<{ save: boolean }>} */
const featuresOf = async (dir) => (await import(pathToFileURL(join(dir, ...FEATURES_FILE.split("/"))).href)).FEATURES;

test("the_save_feature_is_on_in_release_and_in_test", async () => {
  assert.deepEqual([...FEATURES], ["save"]);
  assert.deepEqual([...DEFAULT_FEATURES.release], ["save"]);
  assert.deepEqual([...DEFAULT_FEATURES.test], ["save"]);
  assert.deepEqual([...RELEASE_FEATURES], ["save"], "a release has save on");
  assert.deepEqual([...SAVE_FILES], [...SAVE_PATHS.files]);

  const env = makeRoot();
  try {
    const options = { root: env.root, webRoot: env.webRoot, wasmTar: env.tarPath };
    for (const manifest of ["mv2", "mv3"]) {
      const release = await build({ ...options, out: join(env.out, `r-${manifest}`), manifest, variant: "release" });
      const testBuild = await build({ ...options, out: join(env.out, `t-${manifest}`), manifest, variant: "test" });
      assert.deepEqual(release.features, ["save"]);
      assert.deepEqual(testBuild.features, ["save"]);
      // The generated module says so, in each package, and cannot be changed at run time.
      const releaseOn = await featuresOf(release.dir);
      const testOn = await featuresOf(testBuild.dir);
      assert.deepEqual({ ...releaseOn }, { save: true }, manifest);
      assert.deepEqual({ ...testOn }, { save: true }, manifest);
      assert.equal(Object.isFrozen(releaseOn), true);
      assert.equal(release.files.get(FEATURES_FILE)?.toString("utf8"), featuresModule(["save"], new Map()));
      // The capture script and its sources are in the release, and no test-only code is.
      for (const path of SAVE_FILES) assert.ok(release.files.has(path), `${manifest}: ${path} is in a release`);
      assert.deepEqual([...release.files.keys()].filter((path) => isTestOnlyPath(path) || path.startsWith("test/")), [], manifest);
    }

    // --features overrides the variant's default: a test build with the feature off.
    const testOff = await build({ ...options, out: join(env.out, "t-off"), manifest: "mv2", variant: "test", features: [] });
    assert.deepEqual({ ...(await featuresOf(testOff.dir)) }, { save: false });
    // A release with it off is refused by the build's own release check.
    await assert.rejects(build({ ...options, out: join(env.out, "r-off"), manifest: "mv2", variant: "release", features: [] }), /the feature save is off, which a release must have on/);
    await assert.rejects(build({ ...options, out: join(env.out, "x"), variant: "test", features: ["autosave"] }), /unknown feature "autosave"/);
  } finally {
    env.cleanup();
  }

  // The value of --features.
  assert.deepEqual(parseFeatures("save"), ["save"]);
  assert.deepEqual(parseFeatures(" save "), ["save"]);
  assert.deepEqual(parseFeatures("none"), []);
  for (const bad of ["", " ", "save,save", "save,", "Save", "all"]) assert.throws(() => parseFeatures(bad), /features/, JSON.stringify(bad));

  // The module is the build's: a source file of that name fails the build.
  const planted = makeRoot({ "src/shared/features.mjs": "export const FEATURES = Object.freeze({ save: true });\n" });
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
      assert.deepEqual({ ...(await featuresOf(off.dir)) }, { save: false });
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
    "candidates", "copy", "fill", "forget_preview", "forget_server", "frame_report", "fill_result", "grant_check", "item", "lock",
    "open_site", "search", "server_check", "settings", "sign_in", "state", "sync_accept_older", "sync_older_preview", "sync_retry",
    "sync_state", "unlock",
  ]);
  const all = [...Object.keys(UI_TYPES), ...Object.keys(CONTENT_TYPES)];
  const unaccounted = all.filter((type) => !FIRST_RELEASE_TYPES.includes(type) && !SAVE_PATHS.types.includes(type));
  assert.deepEqual(unaccounted, [], "a type that is in neither list");
  // And everything listed as the feature's that exists is a type of a table (a stale name is found).
  for (const type of ["form_capture", "form_gone", "page_ready", "capture_settings", "sync_items", "item_conflict", "item_resolve", "item_discard"]) {
    assert.ok(all.includes(type), type);
  }
});
