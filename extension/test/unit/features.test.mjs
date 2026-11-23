// The build flag `save` (saving and updating passwords from the extension): off
// in a release, on in the test variant, and "off" means that no path of the
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
import {
  build, DEFAULT_FEATURES, FEATURES, FEATURES_FILE, featuresModule, parseFeatures, RELEASE_FEATURES, SAVE_FILES,
} from "../../scripts/build.mjs";
import { makeRoot } from "./buildHelpers.mjs";

/** What belongs to the `save` feature. */
const SAVE_PATHS = Object.freeze({
  /** Package files of the feature. */
  files: Object.freeze(["content/capture.inject.js", "content/capture.mjs", "content/capture.entry.mjs"]),
  /** Message types of the feature, from a content script and from Ferret's pages. */
  types: Object.freeze([
    "form_capture", "form_gone", "page_ready",
    "offer_list", "offer_save", "offer_update", "offer_dismiss", "offer_never",
    "generate", "fill_generated",
    "sync_items", "item_conflict", "item_resolve", "item_discard",
  ]),
  /** Core operations of the feature (the sync's offer ops): with the feature off each one only refuses. */
  coreOps: Object.freeze(["offer_classify", "offer_save", "offer_update", "folder_names"]),
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

test("the_save_feature_is_off_in_release_and_on_in_test", async () => {
  assert.deepEqual([...FEATURES], ["save"]);
  assert.deepEqual([...DEFAULT_FEATURES.release], []);
  assert.deepEqual([...DEFAULT_FEATURES.test], ["save"]);
  assert.deepEqual([...RELEASE_FEATURES], [], "a release may not have save on yet");
  assert.deepEqual([...SAVE_FILES], [...SAVE_PATHS.files]);

  const env = makeRoot();
  try {
    const options = { root: env.root, webRoot: env.webRoot, wasmTar: env.tarPath };
    for (const manifest of ["mv2", "mv3"]) {
      const release = await build({ ...options, out: join(env.out, `r-${manifest}`), manifest, variant: "release" });
      const testBuild = await build({ ...options, out: join(env.out, `t-${manifest}`), manifest, variant: "test" });
      assert.deepEqual(release.features, []);
      assert.deepEqual(testBuild.features, ["save"]);
      // The generated module says so, in each package, and cannot be changed at run time.
      const off = await featuresOf(release.dir);
      const on = await featuresOf(testBuild.dir);
      assert.deepEqual({ ...off }, { save: false }, manifest);
      assert.deepEqual({ ...on }, { save: true }, manifest);
      assert.equal(Object.isFrozen(off), true);
      assert.equal(release.files.get(FEATURES_FILE)?.toString("utf8"), featuresModule([], new Map()));
    }

    // --features overrides the variant's default: a test build with the feature off.
    const testOff = await build({ ...options, out: join(env.out, "t-off"), manifest: "mv2", variant: "test", features: [] });
    assert.deepEqual({ ...(await featuresOf(testOff.dir)) }, { save: false });
    // A release with it on is refused by the build's own release check.
    await assert.rejects(build({ ...options, out: join(env.out, "r-on"), manifest: "mv2", variant: "release", features: ["save"] }), /the feature save is on/);
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

test("a_release_package_with_save_off_has_no_capture_offer_or_generator_path", async () => {
  // The repository's own sources: nothing of the feature in a release, in either manifest version.
  const env = makeRoot();
  try {
    const options = { root: env.root, webRoot: env.webRoot, wasmTar: env.tarPath };
    for (const manifest of ["mv2", "mv3"]) {
      const release = await build({ ...options, out: join(env.out, manifest), manifest, variant: "release" });
      assert.deepEqual({ ...(await featuresOf(release.dir)) }, { save: false });
      assert.deepEqual(await savePathsIn(release.dir, release.files), [], manifest);
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
    const release = await build({ ...options, out: join(probe.out, "r"), variant: "release" });
    release.files.set("content/capture.inject.js", Buffer.from("void 0;\n"));
    assert.deepEqual((await savePathsIn(release.dir, release.files)).sort(), [
      "control in pages/probe.html",
      "control in pages/probeView.mjs without FEATURES",
      "file content/capture.inject.js",
      "handler background/handlers/mixedProbe.handler.mjs serves offer_update, offer_dismiss",
      "handler background/handlers/offerProbe.handler.mjs serves offer_save",
    ]);
    // With the feature on, the gated handler serves its type: it refuses only because the feature is off.
    const on = await build({ ...options, out: join(probe.out, "t"), variant: "test" });
    const gated = (await import(pathToFileURL(join(on.dir, "background", "handlers", "generatorProbe.handler.mjs")).href)).default;
    assert.deepEqual(await gated.handle({}, {}), { ok: true });
    // The offer ops of the sync, the same: past the flag they go on (here to "no sync runs"), so `refused` above is the
    // flag's doing.
    assert.deepEqual(await coreOpsIn(on.dir), Object.fromEntries(SAVE_PATHS.coreOps.map((name) => [name, "sync_not_running"])));
    assert.deepEqual(await coreOpsIn(release.dir), Object.fromEntries(SAVE_PATHS.coreOps.map((name) => [name, "refused"])));
  } finally {
    probe.cleanup();
  }
});
