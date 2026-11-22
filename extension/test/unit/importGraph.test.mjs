import assert from "node:assert/strict";
import { test } from "node:test";
import { importsOf, readGraph, reach } from "./importGraph.mjs";

test("import_graph_reads_static_dynamic_side_effect_and_re_export_specifiers", () => {
  const source = [
    'import a from "./a.mjs";',
    "import { b, c as d } from '../b.mjs';",
    'import * as e from "./e.mjs";',
    'import "./side.mjs";',
    'export { f } from "./f.mjs";',
    'export * from "./g.mjs";',
    'export * as h from "./h.mjs";',
    'const x = await import("./dyn.mjs");',
    "import(\n  './dyn2.mjs',\n  { with: { type: 'json' } });",
    "const url = import.meta.url;",
    '// import nope from "./comment.mjs";',
    '/* import("./block.mjs") */',
    'const text = "import q from \\"./string.mjs\\"";',
  ].join("\n");
  assert.deepEqual(importsOf(source), {
    specifiers: ["./a.mjs", "../b.mjs", "./e.mjs", "./side.mjs", "./f.mjs", "./g.mjs", "./h.mjs", "./dyn.mjs", "./dyn2.mjs"],
    hidden: 0,
  });
});

test("an_import_the_reader_cannot_resolve_is_hidden_and_fails_closed", () => {
  const cases = {
    "a computed argument": "export const load = (p) => import(p);",
    "a concatenation": 'export const load = (p) => import("../js/" + p);',
    "a template argument": "export const load = (p) => import(`../js/${p}.mjs`);",
    "an import inside a template literal": 'export const text = `${await import("../background/coreHost.mjs")}`;',
    "an import inside a string": 'export const text = "import(\\"../x.mjs\\")";',
    "an import after a regular expression with a quote": "const quote = /[\"']/;\nexport const load = () => import('../y.mjs');\nconst more = `${import('../z.mjs')}`;",
  };
  for (const [label, source] of Object.entries(cases)) {
    assert.ok(importsOf(source).hidden > 0, label);
  }
  // Comments and an ordinary literal do not trip it.
  assert.equal(importsOf('// import(x)\n/* import(y) */\nexport const a = () => import("./ok.mjs");').hidden, 0);
});

test("the_graph_resolves_paths_and_marks_bare_specifiers_and_pages", () => {
  const files = new Map([
    ["pages/a.mjs", Buffer.from('import "../shared/s.mjs";\nimport x from "pkg";\n')],
    ["shared/s.mjs", Buffer.from('export * from "./t.mjs";\n')],
    ["shared/t.mjs", Buffer.from("export const t = 1;\n")],
    ["pages/a.html", Buffer.from('<script type="module" src="a.mjs"></script>')],
  ]);
  const graph = readGraph(files);
  assert.deepEqual(graph.edges.get("pages/a.mjs"), [
    { specifier: "../shared/s.mjs", target: "shared/s.mjs" },
    { specifier: "pkg", target: null },
  ]);
  assert.deepEqual(graph.scripts.get("pages/a.html"), ["pages/a.mjs"]);
  assert.deepEqual([...reach(graph.edges, ["pages/a.mjs"])].sort(), ["pages/a.mjs", "shared/s.mjs", "shared/t.mjs"]);
});
