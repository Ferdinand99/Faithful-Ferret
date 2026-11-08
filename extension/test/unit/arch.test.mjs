import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { test } from "node:test";
import { pathToFileURL } from "node:url";
import { build, handlerRegister } from "../../scripts/build.mjs";
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

/** @param {string} path */
const insideWasmPackage = (path) => path.startsWith("js/") || path.startsWith("pkg-web/");

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
    "a page reaches the client through a shared module": {
      "src/pages/spy.mjs": 'import "../shared/viaShared.mjs";\n',
      "src/shared/viaShared.mjs": 'import "../js/client.mjs";\n',
    },
    "a page reaches the router": { "src/pages/spy.mjs": 'export const load = () => import("../background/router.mjs");\n' },
    "a page that hides an import": { "src/pages/spy.mjs": "export const load = (p) => import(p);\n" },
  };
  for (const [label, extra] of Object.entries(plants)) {
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
      assert.equal(release.files.has("background/testHooks.mjs"), false);
      assert.equal(test_.files.has("background/testHooks.mjs"), true);
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

test("background_exposes_nothing_on_globalThis", async () => {
  const { env, result } = await built();
  const fake = createFakeBrowser();
  /** @type {Array<(port: any) => void>} */
  const onConnect = [];
  /** @type {Array<(message: unknown, sender: unknown) => unknown>} */
  const onMessage = [];
  let alarmListeners = 0;
  let idleListeners = 0;
  /** @type {Map<string, unknown>} */
  const session = new Map([["lock_at", Date.now() + 600_000]]);
  const fakeBrowserObject = {
    runtime: {
      ...fake.runtime,
      getManifest: () => ({ manifest_version: 3, browser_specific_settings: { gecko: { id: fake.runtime.id } } }),
      onConnect: { addListener: (/** @type {any} */ fn) => onConnect.push(fn) },
      onMessage: { addListener: (/** @type {any} */ fn) => onMessage.push(fn) },
    },
    alarms: { create() {}, clear() {}, onAlarm: { addListener: () => { alarmListeners += 1; } } },
    idle: { onStateChanged: { addListener: () => { idleListeners += 1; } } },
    storage: {
      session: {
        get: async (/** @type {string} */ key) => (session.has(key) ? { [key]: session.get(key) } : {}),
        set: async (/** @type {Record<string, unknown>} */ items) => { for (const [k, v] of Object.entries(items)) session.set(k, v); },
        remove: async (/** @type {string} */ key) => { session.delete(key); },
      },
    },
  };
  /** @type {any} */ (globalThis).browser = fakeBrowserObject;
  const before = Reflect.ownKeys(globalThis);
  try {
    await import(pathToFileURL(join(result.dir, "background", "main.mjs")).href);
    await new Promise((resolve) => setTimeout(resolve, 10));
    assert.deepEqual(Reflect.ownKeys(globalThis), before, "the background added a name to globalThis");

    // It is wired: every listener is registered, and the start locked the vault.
    assert.equal(onConnect.length, 1);
    assert.equal(onMessage.length, 1);
    assert.equal(alarmListeners, 1);
    assert.equal(idleListeners, 1);
    assert.equal(session.has("lock_at"), false, "a new page starts locked");

    // And it routes: the UI port is accepted from an extension page, with no handler yet.
    const port = createPort("ferret-ui", extensionPageSender(fake));
    onConnect[0](port);
    assert.equal(port.listenerCount(), 1);
    const framed = createPort("ferret-ui", extensionPageSender(fake, "pages/signin.html", { frameId: 1 }));
    onConnect[0](framed);
    assert.equal(framed.disconnected, true);
  } finally {
    delete (/** @type {any} */ (globalThis)).browser;
    env.cleanup();
  }
});
