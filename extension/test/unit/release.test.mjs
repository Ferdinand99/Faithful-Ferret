import assert from "node:assert/strict";
import { mkdirSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { spawnSync } from "node:child_process";
import { test } from "node:test";
import { build, releaseProblems } from "../../scripts/build.mjs";
import { makeRoot, repoRoot } from "./buildHelpers.mjs";

const CHECK = join(repoRoot, "scripts", "check-ext-release.sh");

const MEASURE_HTML = '<!doctype html><html><head><script type="module" src="measure.mjs"></script></head></html>\n';

/** Test-only files in the places the build looks at. */
const PLANTED = {
  "test/bridge.html": '<!doctype html><script type="module" src="bridge.mjs"></script>\n',
  "test/bridge.mjs": "export {};\n",
  "src/pages/measure.html": MEASURE_HTML,
  "src/pages/measure.mjs": "export {};\n",
};

/** @param {string} target @returns {{ status: number | null, output: string }} */
function runCheck(target) {
  const result = spawnSync("bash", [CHECK, target], { encoding: "utf8" });
  return { status: result.status, output: `${result.stdout}${result.stderr}` };
}

test("release_variant_contains_no_test_files_and_no_fixed_uuid", async () => {
  const env = makeRoot(PLANTED);
  try {
    const options = { root: env.root, webRoot: env.webRoot, out: env.out, wasmTar: env.tarPath };
    const release = await build({ ...options, variant: "release" });
    const test = await build({ ...options, variant: "test" });

    // The release leaves the planted test files out; the test variant has them.
    assert.deepEqual([...release.files.keys()].filter((p) => /(?:^|\/)(?:test|bridge|measure)/.test(p)), []);
    for (const path of ["test/bridge.html", "test/bridge.mjs", "pages/measure.html", "pages/measure.mjs"]) {
      assert.ok(test.files.has(path), path);
    }
    assert.deepEqual(releaseProblems(release.files), []);

    // The check passes for the release (folder and .xpi) and fails for the test build.
    for (const target of [release.dir, release.xpi]) {
      const clean = runCheck(target);
      assert.equal(clean.status, 0, clean.output);
    }
    const bad = runCheck(test.xpi);
    assert.notEqual(bad.status, 0);
    assert.match(bad.output, /test files are not allowed in a release/);
    assert.match(bad.output, /the name is the test build's/);

    // A test file planted into a release folder, in several places, fails the check.
    for (const path of ["test/bridge.html", "test/anything.mjs", "pages/bridge.html", "pages/measure.mjs"]) {
      const file = join(release.dir, ...path.split("/"));
      mkdirSync(dirname(file), { recursive: true });
      writeFileSync(file, "export {};\n");
      const result = runCheck(release.dir);
      assert.notEqual(result.status, 0, path);
      assert.match(result.output, new RegExp(path.replace(".", "\\.")), path);
    }
  } finally {
    env.cleanup();
  }
});

test("release_variant_refuses_a_fixed_extension_uuid_and_the_test_profile_preference", async () => {
  const uuid = "5d0f3b6e-6c1a-4e0e-9a55-0f2f0b6f6f10";
  for (const text of [
    `export const url = "moz-extension://${uuid}/pages/about.html";\n`,
    'export const pref = "extensions.webextensions.uuids";\n',
  ]) {
    const env = makeRoot({ "src/pages/leak.mjs": text });
    try {
      const options = { root: env.root, webRoot: env.webRoot, out: env.out, wasmTar: env.tarPath };
      await assert.rejects(build({ ...options, variant: "release" }), /release: .*pages\/leak\.mjs/);
      // The same source is no problem for the test variant: the check is about releases.
      await build({ ...options, variant: "test" });
    } finally {
      env.cleanup();
    }
  }
  assert.deepEqual(releaseProblems(new Map([["manifest.json", Buffer.from('{ "name": "x" }')]])), []);
  assert.deepEqual(releaseProblems(new Map()), ["manifest.json is missing"]);
});

test("check_ext_release_needs_a_package", () => {
  const result = spawnSync("bash", [CHECK, join(repoRoot, "extension", "does-not-exist.xpi")], { encoding: "utf8" });
  assert.notEqual(result.status, 0);
});
