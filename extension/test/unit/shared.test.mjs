// The code that the extension shares with the web vault: the list in
// shared.json, the copy the build makes and the checks around it.
import assert from "node:assert/strict";
import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { spawnSync } from "node:child_process";
import { test } from "node:test";
import { build, packXpi, sha256, sharedProblems } from "../../scripts/build.mjs";
import { extensionRoot, makeRoot, repoRoot } from "./buildHelpers.mjs";
import { readGraph } from "./importGraph.mjs";

const WEB_SRC = join(repoRoot, "web", "src");
const CHECK = join(repoRoot, "scripts", "check-ext-release.sh");

/** The real list. @returns {string[]} */
const realList = () => JSON.parse(readFileSync(join(extensionRoot, "shared.json"), "utf8"));

/**
 * A throwaway build root with the real list and the real web/src.
 * @param {Record<string, string | null>} [extra]
 */
function realRoot(extra = {}) {
  return makeRoot({ "shared.json": readFileSync(join(extensionRoot, "shared.json"), "utf8"), ...extra });
}

/** @param {ReturnType<typeof makeRoot>} env @param {Record<string, unknown>} [options] */
const buildRealIn = (env, options = {}) => build({ root: env.root, webRoot: env.webRoot, out: env.out, wasmTar: env.tarPath, ...options });

/** @param {string} target @returns {{ status: number | null, output: string }} */
function runCheck(target) {
  const result = spawnSync("bash", [CHECK, target], { encoding: "utf8" });
  return { status: result.status, output: `${result.stdout}${result.stderr}` };
}

test("every_shared_file_is_byte_equal_to_its_source_in_web", async () => {
  const list = realList();
  assert.ok(list.length > 0, "the list is not empty");
  assert.deepEqual(list, [...list].sort(), "the list is sorted");
  const env = realRoot();
  try {
    for (const variant of ["release", "test"]) {
      const result = await buildRealIn(env, { variant });
      /** @type {Record<string, string>} */
      const expected = {};
      for (const path of list) {
        const source = readFileSync(join(WEB_SRC, ...path.split("/")));
        // The package holds the very bytes of web/src, in the folder and in the map the build keeps.
        assert.deepEqual(readFileSync(join(result.dir, "shared", ...path.split("/"))), source, `${variant}: ${path}`);
        assert.deepEqual(result.files.get(`shared/${path}`), source, `${variant}: ${path} (map)`);
        expected[path] = sha256(source);
      }
      assert.deepEqual(JSON.parse(readFileSync(join(result.dir, "shared", "MANIFEST.json"), "utf8")), expected);
      assert.deepEqual(sharedProblems(result.files), []);
    }
  } finally {
    env.cleanup();
  }
});

test("a_shared_file_edited_in_dist_fails_the_build", async () => {
  const env = realRoot();
  try {
    const release = await buildRealIn(env, { variant: "release" });
    assert.equal(runCheck(release.dir).status, 0, "the unedited release is clean");

    // An edit of a copy in the package (folder or .xpi) is named by the release check.
    for (const path of ["dom.mjs", "crypto/convert.mjs", "sync/engine.mjs"]) {
      const file = join(release.dir, "shared", ...path.split("/"));
      const original = readFileSync(file);
      writeFileSync(file, `${original.toString("utf8")}\n// edited\n`);
      const folder = runCheck(release.dir);
      assert.notEqual(folder.status, 0, path);
      assert.match(folder.output, new RegExp(`shared/${path.replace(/[./]/g, "\\$&")}: differs from its hash`), path);
      const xpi = join(env.dir, "edited.xpi");
      packXpi(release.dir, xpi);
      const packed = runCheck(xpi);
      assert.notEqual(packed.status, 0, `${path} (.xpi)`);
      assert.match(packed.output, /differs from its hash/, `${path} (.xpi)`);
      writeFileSync(file, original);
    }
    assert.equal(runCheck(release.dir).status, 0, "restored, the release is clean again");

    // A copy that is missing is named too, and a build from the map refuses an edited copy.
    const files = new Map(release.files);
    files.delete("shared/b64.mjs");
    assert.deepEqual(sharedProblems(files), ["shared/b64.mjs: is in shared/MANIFEST.json but not in the package"]);
    files.set("shared/b64.mjs", Buffer.from("export {};\n"));
    assert.match(sharedProblems(files)[0], /^shared\/b64\.mjs: differs from its hash/);
    files.set("shared/MANIFEST.json", Buffer.from("[1]"));
    assert.deepEqual(sharedProblems(files), ["shared/MANIFEST.json: expected an object of path -> SHA-256"]);
    files.set("shared/MANIFEST.json", Buffer.from("{"));
    assert.deepEqual(sharedProblems(files), ["shared/MANIFEST.json: not valid JSON"]);
  } finally {
    env.cleanup();
  }
});

test("shared_imports_resolve_inside_the_list", async () => {
  // The real import graph of the real sources, with their dynamic import() too.
  const list = new Set(realList());
  const files = new Map([...list].map((path) => [path, readFileSync(join(WEB_SRC, ...path.split("/")))]));
  const graph = readGraph(files);
  assert.deepEqual(graph.hidden, [], "no import() that names no literal");
  /** @type {string[]} */
  const problems = [];
  for (const [path, edges] of graph.edges) {
    for (const { specifier, target } of edges) {
      if (target === null) problems.push(`${path} imports "${specifier}", which is not a relative path`);
      else if (!list.has(target)) problems.push(`${path} imports ${target}, which is not in the list`);
    }
  }
  assert.deepEqual(problems, []);

  // A file that the list lacks fails the build with the name of both files: a static
  // import, a re-export and a dynamic import(), in a folder and above it.
  /** @type {Array<[string, string, string]>} */
  const cases = [
    ["a static import", 'import { x } from "./b.mjs";\nexport const a = x;\n', "a.mjs imports b.mjs, which is not in the list"],
    ["a re-export", 'export * from "./b.mjs";\n', "a.mjs imports b.mjs, which is not in the list"],
    ["a dynamic import", 'export const load = () => import("./b.mjs");\n', "a.mjs imports b.mjs, which is not in the list"],
    ["a file above the folder", 'import "../b.mjs";\n', "d/a.mjs imports b.mjs, which is not in the list"],
    ["a computed import()", "export const load = (p) => import(p);\n", "has an import() that names no string literal"],
    ["a bare specifier", 'import "left-pad";\n', 'imports "left-pad", which is not a relative path'],
  ];
  for (const [label, source, message] of cases) {
    const name = label === "a file above the folder" ? "d/a.mjs" : "a.mjs";
    const env = makeRoot({ "shared.json": `["${name}"]\n`, "src/pages/about.mjs": "export {};\n" });
    try {
      mkdirSync(join(env.webRoot, "src", dirname(name)), { recursive: true });
      writeFileSync(join(env.webRoot, "src", ...name.split("/")), source);
      writeFileSync(join(env.webRoot, "src", "b.mjs"), "export const x = 1;\n");
      await assert.rejects(buildRealIn(env), (error) => {
        assert.ok(error instanceof Error);
        assert.ok(error.message.includes(message), `${label}: ${error.message}`);
        return true;
      }, label);
      // With the target on the list the same build succeeds.
      writeFileSync(join(env.root, "shared.json"), `["${name}", "b.mjs"]\n`);
      if (label !== "a computed import()" && label !== "a bare specifier") {
        const result = await buildRealIn(env);
        assert.ok(result.files.has("shared/b.mjs"), label);
      }
    } finally {
      env.cleanup();
    }
  }
});

test("the_shared_list_names_no_view_route_or_service_file", async () => {
  for (const path of realList()) {
    assert.doesNotMatch(path, /^(?:views|routes|services)\//, path);
    assert.doesNotMatch(path, /\.(?:route|service)\.mjs$/, path);
  }
  // Nothing on the list may reach a view, route or service file either: the closure above
  // is inside the list, so it holds none. The build refuses such a name outright.
  for (const bad of ["views/shell.mjs", "routes/home.route.mjs", "services/sync.service.mjs", "sync/x.service.mjs", "a/b.route.mjs"]) {
    const env = makeRoot({ "shared.json": `["${bad}"]\n` });
    try {
      await assert.rejects(buildRealIn(env), /is a view, route or service file/, bad);
    } finally {
      env.cleanup();
    }
  }
  // A list that names a file twice is refused too.
  const env = makeRoot({ "shared.json": '["a.mjs", "a.mjs"]\n' });
  try {
    await assert.rejects(buildRealIn(env), /listed twice/);
  } finally {
    env.cleanup();
  }
});
