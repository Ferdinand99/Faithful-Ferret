// The joiner that turns the content script and its imports into one classic
// script (scripts/lib/classic.mjs), and the real content script run as that
// script, the way the browser runs an injected file.
import assert from "node:assert/strict";
import { readFileSync, readdirSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { test } from "node:test";
import { fileURLToPath } from "node:url";
import vm from "node:vm";
import { classicScript, CONTENT_ENTRY } from "../../scripts/lib/classic.mjs";
import {
  addLoginForm, BACKGROUND_SENDER, createPage, decodeSent, EXTENSION_BASE, fillMessage, RUNTIME_ID,
} from "./fakeDom.mjs";

/** @param {Record<string, string>} files @returns {Map<string, Buffer>} */
const pack = (files) => new Map(Object.entries(files).map(([path, text]) => [path, Buffer.from(text)]));

const src = resolve(dirname(fileURLToPath(import.meta.url)), "..", "..", "src");
/** The real sources, by package path. @returns {Map<string, Buffer>} */
function readSources() {
  /** @type {Map<string, Buffer>} */
  const out = new Map();
  const walk = (/** @type {string} */ dir) => {
    for (const entry of readdirSync(dir, { withFileTypes: true })) {
      const path = join(dir, entry.name);
      if (entry.isDirectory()) walk(path);
      else out.set(path.slice(src.length + 1).split("\\").join("/"), readFileSync(path));
    }
  };
  walk(src);
  return out;
}

const SMALL = {
  "content/entry.mjs": 'import { run } from "./b.mjs";\n\nglobalThis.answer = run();\n',
  "content/b.mjs": 'import {\n  one,\n  two,\n} from "../shared/protocol.mjs";\nimport { c } from "./c.mjs";\nexport function run() { return one + two + c; }\nexport { run };\n',
  "content/c.mjs": "export const c = 3;\n",
  "shared/protocol.mjs": "export const one = 1;\nexport const two = 2;\n",
};

test("joins_the_closure_in_dependency_order_without_import_or_export", () => {
  const out = classicScript("content/entry.mjs", pack(SMALL));
  assert.doesNotMatch(out, /^\s*(?:import|export)\b/m);
  const order = [...out.matchAll(/^\/\/ ---- (.+)$/gm)].map((m) => m[1]);
  assert.deepEqual(order, ["shared/protocol.mjs", "content/c.mjs", "content/b.mjs", "content/entry.mjs"]);
  assert.match(out, /^\/\/ Files: shared\/protocol\.mjs, content\/c\.mjs, content\/b\.mjs, content\/entry\.mjs$/m);
  // It runs in order: the entry calls what the others export.
  const context = vm.createContext({});
  vm.runInContext(out, context);
  assert.equal(context.answer, 6);
  // Same input, same output.
  assert.equal(classicScript("content/entry.mjs", pack(SMALL)), out);
});

test("refuses_what_it_cannot_join_instead_of_guessing", () => {
  /** @type {Array<[string, Record<string, string>, RegExp]>} */
  const cases = [
    ["an alias", { "content/entry.mjs": 'import { a as b } from "./x.mjs";\n', "content/x.mjs": "export const a = 1;\n" }, /plain names/],
    ["a default import", { "content/entry.mjs": 'import a from "./x.mjs";\n', "content/x.mjs": "export default 1;\n" }, /not supported/],
    ["a namespace import", { "content/entry.mjs": 'import * as a from "./x.mjs";\n', "content/x.mjs": "export const a = 1;\n" }, /not supported/],
    ["a re-export", { "content/entry.mjs": 'export { a } from "./x.mjs";\n', "content/x.mjs": "export const a = 1;\n" }, /not supported/],
    ["an export default", { "content/entry.mjs": 'import "./x.mjs";\n', "content/x.mjs": "export default 1;\n" }, /not supported/],
    ["a dynamic import with a literal", { "content/entry.mjs": 'import("./x.mjs");\n', "content/x.mjs": "export const a = 1;\n" }, /not supported/],
    ["a dynamic import that hides its target", { "content/entry.mjs": "export const f = (p) => import(p);\n" }, /no string literal/],
    ["import.meta", { "content/entry.mjs": "export const u = import.meta.url;\n" }, /import\.meta/],
    ["a bare specifier", { "content/entry.mjs": 'import "lodash";\n' }, /only relative/],
    ["a background module", { "content/entry.mjs": 'import "../background/coreHost.mjs";\n', "background/coreHost.mjs": "export const x = 1;\n" }, /not allowed in a content script/],
    ["another shared module", { "content/entry.mjs": 'import "../shared/origin.mjs";\n', "shared/origin.mjs": "export const x = 1;\n" }, /not allowed in a content script/],
    ["a page of the extension", { "content/entry.mjs": 'import "../pages/el.mjs";\n', "pages/el.mjs": "export const x = 1;\n" }, /not allowed in a content script/],
    ["a missing file", { "content/entry.mjs": 'import "./gone.mjs";\n' }, /is not in the package/],
    ["a cycle", { "content/entry.mjs": 'import "./a.mjs";\n', "content/a.mjs": 'import "./b.mjs";\n', "content/b.mjs": 'import "./a.mjs";\n' }, /cycle/],
    ["a name that is not exported", { "content/entry.mjs": 'import { missing } from "./x.mjs";\n', "content/x.mjs": "export const a = 1;\n" }, /does not export/],
    ["export let", { "content/entry.mjs": 'import "./x.mjs";\n', "content/x.mjs": "export let a = 1;\n" }, /export let/],
    ["an import after code on the same line", { "content/entry.mjs": 'globalThis.x = 1; import "./x.mjs";\n', "content/x.mjs": "export const a = 1;\n" }, /not supported/],
    ["an import form inside a block comment, with the real one missing", { "content/entry.mjs": '/*\nimport "./x.mjs";\n*/\nimport "./y.mjs";\n', "content/x.mjs": "export const a = 1;\n", "content/y.mjs": "export const b = 1;\n" }, /not supported/],
    ["an export with an alias", { "content/entry.mjs": 'import "./x.mjs";\n', "content/x.mjs": "const a = 1;\nexport { a as b };\n" }, /plain names/],
    ["a script that does not parse", { "content/entry.mjs": "const = ;\n" }, /does not parse/],
  ];
  for (const [label, files, message] of cases) {
    assert.throws(() => classicScript("content/entry.mjs", pack(files)), message, label);
  }
});

test("only_the_content_folder_and_the_protocol_files_may_be_joined", () => {
  const files = readSources();
  // The real closure is exactly the entry, the engine, the protocol and the schema checker.
  const joined = [...classicScript(CONTENT_ENTRY, files).matchAll(/^\/\/ ---- (.+)$/gm)].map((m) => m[1]);
  assert.deepEqual(joined, ["shared/schema.mjs", "shared/protocol.mjs", "content/fill.mjs", "content/entry.mjs"]);
  for (const text of [
    'import "../shared/origin.mjs";\n',
    'import "../background/lock.mjs";\n',
    'import "../js/client.mjs";\n',
    'import "../pages/el.mjs";\n',
  ]) {
    const planted = new Map(files);
    planted.set(CONTENT_ENTRY, Buffer.from(text));
    assert.throws(() => classicScript(CONTENT_ENTRY, planted), /not allowed in a content script/, text);
  }
});

test("the_real_content_script_runs_as_one_classic_script_and_starts_once", () => {
  const script = classicScript(CONTENT_ENTRY, readSources());
  assert.doesNotMatch(script, /^\s*(?:import|export)\b/m);
  assert.doesNotMatch(script, /background\/|\bsubtle\b|WebAssembly|indexedDB|localStorage|\.storage\b/);
  new vm.Script(script); // parses as a classic script

  const { window, document } = createPage();
  addLoginForm(document);
  /** @type {string[]} */
  const sent = [];
  /** @type {Array<(raw: unknown, sender: unknown) => void>} */
  const listeners = [];
  Object.assign(window, {
    TextEncoder,
    browser: {
      runtime: {
        id: RUNTIME_ID,
        getURL: (/** @type {string} */ path) => `${EXTENSION_BASE}${path}`,
        sendMessage: async (/** @type {string} */ raw) => { sent.push(raw); },
        onMessage: { addListener: (/** @type {any} */ fn) => { listeners.push(fn); } },
      },
    },
  });
  const context = vm.createContext(window);
  vm.runInContext(script, context);
  assert.equal(listeners.length, 1);
  const descriptor = Object.getOwnPropertyDescriptor(window, "__ferretFill");
  assert.ok(descriptor, "the engine is offered to the extension");
  assert.equal(descriptor.enumerable, false);
  assert.equal(descriptor.writable, false);
  assert.equal(descriptor.configurable, false);
  assert.equal(Object.keys(window).includes("__ferretFill"), false);

  // A second injection into the same page changes nothing.
  vm.runInContext(script, context);
  assert.equal(listeners.length, 1);
  assert.equal(Object.getOwnPropertyDescriptor(window, "__ferretFill")?.value, descriptor.value);

  // It reports on request and fills on message, as the engine does in the unit tests.
  assert.equal(descriptor.value.begin("req-1"), true);
  const [report] = decodeSent(sent);
  assert.equal(report.type, "frame_report");
  assert.deepEqual(report.body.fields.map((/** @type {{ kind: string }} */ f) => f.kind), ["username", "password"]);
  sent.length = 0;
  listeners[0](fillMessage({ field: "password", value: "pw" }), BACKGROUND_SENDER);
  assert.deepEqual(decodeSent(sent).map((m) => m.body), [{ request_id: "req-1", ok: true }]);
  // A message from a page-like sender is ignored.
  sent.length = 0;
  listeners[0](fillMessage({ field: "username", value: "u" }), { id: RUNTIME_ID, url: "https://example.com/" });
  assert.deepEqual(sent, []);
});

test("each_module_keeps_its_own_scope_and_a_name_in_two_files_is_fine", () => {
  const out = classicScript("content/entry.mjs", pack({
    "content/entry.mjs": 'import { one } from "./a.mjs";\nimport { two } from "./b.mjs";\nglobalThis.result = [one(), two(), typeof origin];\n',
    "content/a.mjs": 'const same = 1;\nconst origin = { not: "the global" };\nexport function one() { return same; }\n',
    "content/b.mjs": 'const same = 2;\nexport function two() { return same; }\n',
  }));
  // The context has a global origin; the entry does not see the one declared in a.mjs.
  const context = vm.createContext({ origin: "https://example.com" });
  vm.runInContext(out, context);
  assert.deepEqual([...context.result], [1, 2, "string"]);
  // Nothing of a module leaks to the global scope.
  assert.equal(vm.runInContext("typeof same + typeof one + typeof __m0", context), "undefinedundefinedundefined");
});

test("an_imported_name_is_read_from_the_module_that_exports_it", () => {
  const out = classicScript("content/entry.mjs", pack({
    "content/entry.mjs": 'import { b } from "./a.mjs";\nglobalThis.result = b;\n',
    "content/a.mjs": 'import { a } from "./c.mjs";\nexport const b = a + 1;\n',
    "content/c.mjs": "export const a = 41;\n",
  }));
  const context = vm.createContext({});
  vm.runInContext(out, context);
  assert.equal(context.result, 42);
});
