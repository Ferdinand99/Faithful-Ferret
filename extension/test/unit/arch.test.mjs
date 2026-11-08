import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { test } from "node:test";
import { pathToFileURL } from "node:url";
import { build, handlerRegister, isTestOnlyPath, readInternalHosts, releaseProblems, WASM_FILES } from "../../scripts/build.mjs";
import { makeRoot } from "./buildHelpers.mjs";
import { createFakeBrowser, extensionPageSender } from "./fakeBrowser.mjs";
import { createPort } from "./backgroundHelpers.mjs";
import { importsOf, reach, readGraph } from "./importGraph.mjs";

const CORE_HOST = "background/coreHost.mjs";
const MANIFESTS = ["mv3", "mv2"];
const VARIANTS = ["release", "test"];

/**
 * Builds a package from a throwaway copy of the extension with a fake WASM
 * package, so no test needs the network.
 *
 * @param {{ manifest?: string, variant?: string, extra?: Record<string, string | null> }} [options]
 */
async function built({ manifest = "mv3", variant = "release", extra = {} } = {}) {
  const env = makeRoot(extra);
  try {
    const result = await build({ root: env.root, webRoot: env.webRoot, out: env.out, wasmTar: env.tarPath, manifest, variant });
    return { env, result, files: result.files };
  } catch (error) {
    env.cleanup();
    throw error;
  }
}

/** Only the exact files of the WASM package: a look-alike path (our own file under js/) is not part of it. @param {string} path */
const insideWasmPackage = (path) => WASM_FILES.includes(path);

/**
 * What breaks "only the core host imports the WASM client": an import of the
 * package from any file but the core host, a page that loads it, an import that
 * hides its target, and any other way to name it.
 *
 * @param {Map<string, Buffer>} files
 * @returns {string[]}
 */
function wasmViolations(files) {
  const graph = readGraph(files, { skip: insideWasmPackage });
  /** @type {string[]} */
  const out = [];
  for (const [path, edges] of graph.edges) {
    for (const { specifier, target } of edges) {
      if (target === null) out.push(`${path}: imports ${specifier} (only relative imports are allowed)`);
      else if (insideWasmPackage(target) && path !== CORE_HOST) out.push(`${path}: imports ${target}`);
    }
  }
  for (const path of graph.hidden) out.push(`${path}: an import() with no string literal`);
  for (const [page, scripts] of graph.scripts) {
    for (const script of scripts) if (insideWasmPackage(script)) out.push(`${page}: loads ${script}`);
  }
  for (const [path, bytes] of files) {
    if (insideWasmPackage(path) || path === CORE_HOST || !/\.(?:mjs|js|html)$/.test(path)) continue;
    if (/client\.mjs|pkg-web|\.worker\.mjs|ferret_core_wasm|WebAssembly/.test(bytes.toString("utf8"))) out.push(`${path}: names the WASM package`);
  }
  return out;
}

/**
 * What a page or a content script must not reach: the WASM package and
 * anything in the background (the core host, the lock, the router, handlers).
 *
 * @param {Map<string, Buffer>} files
 * @returns {{ roots: string[], violations: string[] }}
 */
function cryptoReach(files) {
  const graph = readGraph(files, { skip: insideWasmPackage });
  const roots = [
    ...[...files.keys()].filter((p) => p.startsWith("content/") && /\.(?:mjs|js)$/.test(p)),
    ...[...graph.scripts].filter(([page]) => page !== "background/background.html").flatMap(([, scripts]) => scripts),
  ];
  const reached = reach(graph.edges, roots);
  const violations = [...reached].filter((p) => insideWasmPackage(p) || p.startsWith("background/"));
  for (const path of graph.hidden) if (reached.has(path)) violations.push(`${path}: an import() with no string literal`);
  // A second line of defence for what the reader cannot follow: no page or
  // content file may even name a path in the background.
  for (const path of reached) {
    if (insideWasmPackage(path) || path.startsWith("background/")) continue;
    if (/background\//.test(files.get(path)?.toString("utf8") ?? "")) violations.push(`${path}: names background/`);
  }
  return { roots, violations };
}

test("only_core_host_imports_the_wasm_client", async () => {
  for (const manifest of MANIFESTS) {
    for (const variant of VARIANTS) {
      const { env, files } = await built({ manifest, variant });
      try {
        assert.deepEqual(wasmViolations(files), [], `${manifest} ${variant}`);
        // Not vacuous: the core host does import it, and the package is in the build.
        const graph = readGraph(files, { skip: insideWasmPackage });
        assert.ok(graph.edges.get(CORE_HOST)?.some((e) => e.target === "js/client.mjs"));
        assert.ok(files.has("js/client.mjs") && files.has("pkg-web/ferret_core_wasm.js"));
      } finally {
        env.cleanup();
      }
    }
  }
});

test("a_second_importer_of_the_wasm_client_is_found", async () => {
  const plants = {
    "a page imports it": { "src/pages/spy.mjs": 'import { createClient } from "../js/client.mjs";\nexport const c = createClient;\n' },
    "a background module imports it": { "src/background/lock2.mjs": 'export { createClient } from "../js/client.mjs";\n' },
    "a dynamic import of it": { "src/pages/spy.mjs": 'export const load = () => import("../js/client.mjs");\n' },
    "an import that hides its target": { "src/pages/spy.mjs": 'export const load = (p) => import("../js/" + p);\n' },
    "a worker that names it": { "src/pages/spy.mjs": 'export const w = new Worker(new URL("../js/vault.worker.mjs", import.meta.url));\n' },
    "a bare specifier": { "src/pages/spy.mjs": 'import x from "some-package";\nexport default x;\n' },
  };
  for (const [label, extra] of Object.entries(plants)) {
    const { env, files } = await built({ extra });
    try {
      assert.notDeepEqual(wasmViolations(files), [], label);
    } finally {
      env.cleanup();
    }
  }
  const { env, files } = await built({
    extra: { "src/pages/spy.html": '<!doctype html><html><head><script type="module" src="../js/client.mjs"></script></head></html>\n' },
  });
  try {
    assert.notDeepEqual(wasmViolations(files), []);
  } finally {
    env.cleanup();
  }
});

test("content_and_page_bundles_reach_no_crypto_module", async () => {
  for (const manifest of MANIFESTS) {
    for (const variant of VARIANTS) {
      const { env, files, result } = await built({ manifest, variant });
      try {
        const { roots, violations } = cryptoReach(files);
        assert.deepEqual(violations, [], `${manifest} ${variant}`);
        assert.ok(roots.includes("pages/about.mjs"), "the pages are checked");
        const manifestJson = JSON.parse(readFileSync(join(result.dir, "manifest.json"), "utf8"));
        assert.equal("content_scripts" in manifestJson, false);
      } finally {
        env.cleanup();
      }
    }
  }
});

test("a_page_or_content_script_that_reaches_a_crypto_module_is_found", async () => {
  const plants = {
    "a content script imports the core host": { "src/content/fill.mjs": 'import "../background/coreHost.mjs";\n' },
    "a content script imports the lock": { "src/content/fill.mjs": 'import "../background/lock.mjs";\n' },
    // A content file that the joined script does not include is still a root of the graph check.
    "a content module outside the joined script imports the core host": { "src/content/extra.mjs": 'import "../background/coreHost.mjs";\n' },
    "a content module outside the joined script imports the client": { "src/content/extra.mjs": 'import "../js/client.mjs";\n' },
    "a page reaches the client through a shared module": {
      "src/pages/spy.mjs": 'import "../shared/viaShared.mjs";\n',
      "src/shared/viaShared.mjs": 'import "../js/client.mjs";\n',
    },
    "a page reaches the router": { "src/pages/spy.mjs": 'export const load = () => import("../background/router.mjs");\n' },
    "a page that hides an import": { "src/pages/spy.mjs": "export const load = (p) => import(p);\n" },
    "a page that hides an import in a template literal": {
      "src/pages/spy.mjs": 'export const text = `${await import("../background/coreHost.mjs")}`;\n',
    },
    "a page that names a path in the background": { "src/pages/spy.mjs": 'export const where = "../background/lock.mjs";\n' },
  };
  for (const [label, extra] of Object.entries(plants)) {
    if ("src/content/fill.mjs" in extra) {
      // The build joins the content script into one file and refuses a module it may not include.
      await assert.rejects(built({ extra }), /not allowed in a content script/, label);
      continue;
    }
    const { env, files } = await built({
      extra: {
        ...extra,
        // A page whose script is the planted one, when the plant is a page.
        ...("src/pages/spy.mjs" in extra ? { "src/pages/spy.html": '<!doctype html><html><head><script type="module" src="spy.mjs"></script></head></html>\n' } : {}),
      },
    });
    try {
      assert.notDeepEqual(cryptoReach(files).violations, [], label);
    } finally {
      env.cleanup();
    }
  }
});

test("the_router_the_lock_and_the_handlers_cannot_reach_the_core_host", async () => {
  const { env, files } = await built({
    extra: { "src/background/handlers/session.handler.mjs": 'export default { types: ["state"], channel: "ui", handle: async () => ({}) };\n' },
  });
  try {
    const graph = readGraph(files, { skip: insideWasmPackage });
    const handlers = [...files.keys()].filter((p) => p.startsWith("background/handlers/") && p.endsWith(".handler.mjs"));
    assert.equal(handlers.length, 1);
    const reached = reach(graph.edges, ["background/router.mjs", "background/lock.mjs", ...handlers]);
    assert.equal(reached.has(CORE_HOST), false);
    assert.equal([...reached].some(insideWasmPackage), false);
    // Only the entry imports the core host.
    const importers = [...graph.edges].filter(([, edges]) => edges.some((e) => e.target === CORE_HOST)).map(([path]) => path);
    assert.deepEqual(importers, ["background/main.mjs"]);
  } finally {
    env.cleanup();
  }
});

test("the_background_entry_is_main_in_both_manifest_versions_and_has_the_lock_permissions", async () => {
  for (const manifest of MANIFESTS) {
    const { env, result } = await built({ manifest });
    try {
      const json = JSON.parse(readFileSync(join(result.dir, "manifest.json"), "utf8"));
      for (const name of ["alarms", "idle", "storage"]) assert.ok(json.permissions.includes(name), `${manifest}: ${name}`);
      if (manifest === "mv3") {
        assert.deepEqual(json.background.scripts, ["background/main.mjs"]);
      } else {
        assert.equal(json.background.page, "background/background.html");
        const html = readFileSync(join(result.dir, "background", "background.html"), "utf8");
        assert.deepEqual([...html.matchAll(/<script\b[^>]*\bsrc="([^"]+)"/g)].map((m) => m[1]), ["main.mjs"]);
      }
    } finally {
      env.cleanup();
    }
  }
});

test("the_test_hooks_are_in_the_test_variant_only", async () => {
  for (const manifest of MANIFESTS) {
    const release = await built({ manifest, variant: "release" });
    const test_ = await built({ manifest, variant: "test" });
    try {
      assert.equal(release.files.has("background/test-only/testHooks.mjs"), false);
      assert.equal(test_.files.has("background/test-only/testHooks.mjs"), true);
    } finally {
      release.env.cleanup();
      test_.env.cleanup();
    }
  }
});

test("the_handler_register_lists_every_handler_file_in_order_and_refuses_strays", async () => {
  const handler = (/** @type {string} */ type) => `export default { types: ["${type}"], channel: "ui", handle: async () => ({}) };\n`;
  const { env, files } = await built({
    extra: {
      "src/background/handlers/zeta.handler.mjs": handler("state"),
      "src/background/handlers/alpha.handler.mjs": handler("lock"),
    },
  });
  try {
    const text = /** @type {Buffer} */ (files.get("background/handlers.gen.mjs")).toString("utf8");
    assert.deepEqual(importsOf(text).specifiers, ["./handlers/alpha.handler.mjs", "./handlers/zeta.handler.mjs"]);
    assert.match(text, /export const HANDLERS = Object\.freeze\(\[handler0, handler1\]\);/);
  } finally {
    env.cleanup();
  }
  const none = await built();
  try {
    assert.match(/** @type {Buffer} */ (none.files.get("background/handlers.gen.mjs")).toString("utf8"), /export const HANDLERS = Object\.freeze\(\[\]\);/);
  } finally {
    none.env.cleanup();
  }
  await assert.rejects(built({ extra: { "src/background/handlers/Bad.mjs": "export {};\n" } }), /expected <feature>\.handler\.mjs/);
  await assert.rejects(built({ extra: { "src/background/handlers.gen.mjs": "export {};\n" } }), /generated by the build/);
  assert.throws(() => handlerRegister(new Map([["background/handlers.gen.mjs", Buffer.from("")]])), /generated by the build/);
});

/**
 * Loads the built `main.mjs` of a package against a fake `browser` and returns
 * what it registered.
 *
 * @param {string} dir the unpacked package
 */
async function boot(dir) {
  const fake = createFakeBrowser();
  /** @type {Array<(port: any) => void>} */
  const onConnect = [];
  /** @type {Array<(message: unknown, sender: unknown) => unknown>} */
  const onMessage = [];
  const counts = { alarm: 0, idle: 0 };
  /** @type {Map<string, unknown>} */
  const session = new Map([["lock_at", Date.now() + 600_000]]);
  /** @type {any} */ (globalThis).browser = {
    runtime: {
      ...fake.runtime,
      getManifest: () => ({ manifest_version: 3, browser_specific_settings: { gecko: { id: fake.runtime.id } } }),
      onConnect: { addListener: (/** @type {any} */ fn) => onConnect.push(fn) },
      onMessage: { addListener: (/** @type {any} */ fn) => onMessage.push(fn) },
      onSuspend: { addListener() {} },
      onSuspendCanceled: { addListener() {} },
    },
    alarms: { create() {}, clear() {}, get: async () => undefined, onAlarm: { addListener: () => { counts.alarm += 1; } } },
    idle: { onStateChanged: { addListener: () => { counts.idle += 1; } } },
    storage: {
      local: new Proxy({}, { get: () => async () => ({}) }),
      session: {
        get: async (/** @type {string} */ key) => (session.has(key) ? { [key]: session.get(key) } : {}),
        set: async (/** @type {Record<string, unknown>} */ items) => { for (const [k, v] of Object.entries(items)) session.set(k, v); },
        remove: async (/** @type {string} */ key) => { session.delete(key); },
      },
    },
  };
  const before = Reflect.ownKeys(globalThis);
  await import(pathToFileURL(join(dir, "background", "main.mjs")).href);
  await new Promise((resolve) => setTimeout(resolve, 10));
  return { fake, onConnect, onMessage, counts, session, before };
}

test("background_exposes_nothing_on_globalThis", async () => {
  for (const variant of VARIANTS) {
    const { env, result } = await built({ variant });
    try {
      const { fake, onConnect, onMessage, counts, session, before } = await boot(result.dir);
      assert.deepEqual(Reflect.ownKeys(globalThis), before, `${variant}: the background added a name to globalThis`);

      // It is wired: every listener is registered, and the start locked the vault.
      assert.equal(onConnect.length, variant === "test" ? 2 : 1);
      // The test build also listens for the content script's reports (the fill probe) and for its own
      // content-script probe, and the lifetime log listens for the heartbeat.
      assert.equal(onMessage.length, variant === "test" ? 3 : 1);
      assert.deepEqual(counts, { alarm: variant === "test" ? 2 : 1, idle: 1 });
      assert.equal(session.has("lock_at"), false, "a new page starts locked");

      // And it routes: the UI port is accepted from an extension page, with no handler yet.
      const port = createPort("ferret-ui", extensionPageSender(fake));
      onConnect[0](port);
      assert.equal(port.listenerCount(), 1);
      const framed = createPort("ferret-ui", extensionPageSender(fake, "pages/signin.html", { frameId: 1 }));
      onConnect[0](framed);
      assert.equal(framed.disconnected, true);

      if (variant === "test") {
        // The test build has a port for the core operations, with the same sender rules.
        const test = createPort("ferret-test-core", extensionPageSender(fake));
        for (const connect of onConnect) connect(test);
        await new Promise((resolve) => setTimeout(resolve, 10));
        assert.equal(test.listenerCount(), 1);
        await test.send({ id: "1", op: "item_list" });
        assert.deepEqual(test.sent, [{ id: "1", ok: false, code: "unknown_core_op" }]);
        const framedTest = createPort("ferret-test-core", extensionPageSender(fake, "pages/signin.html", { frameId: 2 }));
        for (const connect of onConnect) connect(framedTest);
        await new Promise((resolve) => setTimeout(resolve, 10));
        assert.equal(framedTest.disconnected, true);
      }
    } finally {
      delete (/** @type {any} */ (globalThis)).browser;
      env.cleanup();
    }
  }
});

test("a_release_has_no_trace_of_the_test_build", async () => {
  for (const manifest of MANIFESTS) {
    const { env, files } = await built({ manifest, variant: "release" });
    try {
      for (const [path, bytes] of files) {
        if (!/\.(?:mjs|js|html|json)$/.test(path) || insideWasmPackage(path)) continue;
        const text = bytes.toString("utf8");
        for (const name of ["TEST_ID", "testHooks", "test-only", "ferret-test"]) {
          assert.equal(text.includes(name), false, `${manifest}: ${path} names ${name}`);
        }
      }
      assert.equal([...files.keys()].some((p) => p.includes("test-only")), false);
      const variantText = /** @type {Buffer} */ (files.get("background/variant.gen.mjs")).toString("utf8");
      assert.match(variantText, /export const variantHooks = null;/);
      const main = /** @type {Buffer} */ (files.get("background/main.mjs")).toString("utf8");
      assert.deepEqual(importsOf(main).specifiers.filter((s) => s.includes("variant")), ["./variant.gen.mjs"]);
    } finally {
      env.cleanup();
    }
  }
  // The test build imports its hooks through the same switch, statically, so the page sets them up in its first turn.
  const { env, files } = await built({ variant: "test" });
  try {
    const text = /** @type {Buffer} */ (files.get("background/variant.gen.mjs")).toString("utf8");
    assert.deepEqual(importsOf(text).specifiers, ["./test-only/testHooks.mjs"]);
  } finally {
    env.cleanup();
  }
});

test("anything_in_a_test_only_folder_is_left_out_of_a_release_and_refused_by_the_release_check", async () => {
  const extra = {
    "src/pages/test-only/probe.mjs": "export {};\n",
    "src/background/test-only/more.mjs": "export {};\n",
    "src/background/handlers/test-only/probe.handler.mjs": 'export default { types: ["state"], channel: "ui", handle: async () => ({}) };\n',
  };
  const release = await built({ variant: "release", extra });
  const test_ = await built({ variant: "test", extra });
  try {
    assert.equal([...release.files.keys()].some((p) => p.includes("test-only")), false);
    for (const path of Object.keys(extra)) assert.equal(test_.files.has(path.slice("src/".length)), true, path);
    // A test-only handler is registered in the test build and not in the release.
    const registerOf = (/** @type {Map<string, Buffer>} */ files) => /** @type {Buffer} */ (files.get("background/handlers.gen.mjs")).toString("utf8");
    assert.deepEqual(importsOf(registerOf(test_.files)).specifiers, ["./handlers/test-only/probe.handler.mjs"]);
    assert.deepEqual(importsOf(registerOf(release.files)).specifiers, []);
    // The release check refuses such a path even if the build were bypassed.
    for (const path of ["background/test-only/x.mjs", "pages/test-only/x.html", "background/handlers/test-only/x.handler.mjs"]) {
      const problems = releaseProblems(new Map([...release.files, [path, Buffer.from("export {};\n")]]), readInternalHosts());
      assert.ok(problems.some((p) => p.startsWith(`${path}:`)), path);
    }
    assert.equal(isTestOnlyPath("background/test-only/testHooks.mjs"), true);
    assert.equal(isTestOnlyPath("background/testonly/x.mjs"), false);
  } finally {
    release.env.cleanup();
    test_.env.cleanup();
  }
});

test("a_release_build_fails_on_an_import_or_script_that_points_outside_the_package", async () => {
  const hooks = '// a real module that reaches into test-only code\nimport "../background/test-only/testHooks.mjs";\nexport {};\n';
  const cases = {
    "a page module imports test-only code": { "src/pages/uses.mjs": hooks },
    "a shared module imports a test-only module": {
      "src/shared/uses.mjs": 'export { x } from "./test-only/x.mjs";\n',
      "src/shared/test-only/x.mjs": "export const x = 1;\n",
    },
    "a dynamic import of a test-only module": {
      "src/pages/uses.mjs": 'export const load = () => import("../shared/test-only/x.mjs");\n',
      "src/shared/test-only/x.mjs": "export const x = 1;\n",
    },
    "a page script that is not there": {
      "src/pages/uses.html": '<!doctype html><html><head><script type="module" src="gone.mjs"></script></head></html>\n',
    },
    "an import of a file that does not exist": { "src/pages/uses.mjs": 'import "./nothing.mjs";\n' },
  };
  for (const [label, extra] of Object.entries(cases)) {
    await assert.rejects(built({ variant: "release", extra }), /not in the package/, `release: ${label}`);
  }
  // The test build holds the test-only files, so the first three build there.
  for (const label of Object.keys(cases).slice(0, 3)) {
    const { env } = await built({ variant: "test", extra: /** @type {any} */ (cases)[label] });
    env.cleanup();
  }
  // And a package that is whole builds, in both variants.
  for (const variant of VARIANTS) (await built({ variant })).env.cleanup();
});

test("the_wasm_exemption_covers_only_the_files_of_the_package", async () => {
  // The build refuses a source file of ours under the package's folders, whatever its name.
  for (const path of ["src/js/spy.mjs", "src/pkg-web/spy.mjs", "src/js/client.mjs", "src/pkg-web/ferret_core_wasm.js"]) {
    for (const variant of VARIANTS) {
      await assert.rejects(built({ variant, extra: { [path]: "export {};\n" } }), /js\/ and pkg-web\/ are the WASM package's folders/, `${variant}: ${path}`);
    }
  }
  // A package file that is not one of the shipped files is not exempt: it is read like any other file.
  assert.equal(insideWasmPackage("js/client.mjs"), true);
  assert.equal(insideWasmPackage("js/other.mjs"), false);
  assert.equal(insideWasmPackage("pkg-web/other.js"), false);
});
