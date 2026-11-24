// Where the WebAssembly package of a build comes from: test builds may use one built from the tree
// (scripts/wasm-tree.sh, scripts/wasm-source.mjs, .github/workflows/wasm-tree.yml), release builds
// use the locked package or the package of their own release run and nothing else. These tests read
// the scripts and the workflows (no WASM build needed).
// Run: node --test tests/node/wasm-source.test.mjs
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { execFileSync, spawnSync } from "node:child_process";
import { existsSync, mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { test } from "node:test";
import { chooseSource, sourceFor, workspaceVersion } from "../../scripts/wasm-source.mjs";
import { root } from "./paths.mjs";

const read = (/** @type {string} */ path) => readFileSync(join(root, ...path.split("/")), "utf8");
/** A workflow without its comment lines. @param {string} name */
const workflow = (name) => read(`.github/workflows/${name}`).split(/\r?\n/).filter((line) => !line.trim().startsWith("#")).join("\n");
/** The text of one job of a workflow (up to the next job). @param {string} text @param {string} job */
function job(text, job) {
  const start = text.search(new RegExp(`^  ${job}:$`, "m"));
  assert.ok(start >= 0, `job ${job}`);
  const rest = text.slice(start + 1);
  const next = rest.search(/^  [a-z][a-z0-9-]*:$/m);
  return next < 0 ? rest : rest.slice(0, next);
}

test("ci_uses_the_tree_wasm_while_the_lock_is_behind_the_tree", () => {
  // The decision: the package of the tree while the lock names an older version than the core in the tree.
  assert.equal(chooseSource("0.8.0", "0.10.0"), "tree", "a number is not a text: 8 is less than 10");
  assert.equal(chooseSource("0.9.9", "0.10.0"), "tree");
  assert.equal(chooseSource("0.10.0", "0.10.1"), "tree");
  assert.equal(chooseSource("0.10.0", "1.0.0"), "tree");
  assert.equal(chooseSource("0.10.0", "0.10.0"), "lock", "the pin pull request has moved the lock to the tree's version");
  assert.equal(chooseSource("0.11.0", "0.10.9"), "lock");
  for (const bad of ["", "main", "1.2", "1.2.3-rc.1", "v1.2.3"]) {
    assert.throws(() => chooseSource(bad, "0.10.0"), /not a version/, bad);
    assert.throws(() => chooseSource("0.8.0", bad), /not a version/, bad);
  }
  assert.equal(workspaceVersion('[workspace]\nmembers = []\n\n[workspace.package]\nversion = "0.10.0"\nedition = "2024"\n\n[workspace.dependencies]\nversion = "9.9.9"\n'), "0.10.0");
  assert.throws(() => workspaceVersion("[package]\nversion = \"1.0.0\"\n"), /no \[workspace\.package\] version/);
  // On this very tree it is the rule applied to the two files.
  const lock = JSON.parse(read("web/wasm.lock.json"));
  assert.equal(sourceFor(root), chooseSource(lock.version, workspaceVersion(read("Cargo.toml"))));
  assert.equal(execFileSync("node", [join(root, "scripts", "wasm-source.mjs")], { encoding: "utf8" }).trim(), sourceFor(root));

  // The workflows that test the web vault and the extension ask for it, and take the package it built.
  const called = workflow("wasm-tree.yml");
  assert.match(called, /workflow_call:/);
  assert.match(called, /node scripts\/wasm-source\.mjs/);
  assert.match(job(called, "build"), /if: needs\.decide\.outputs\.source == 'tree'/);
  assert.match(called, /scripts\/wasm-tree\.sh/);
  assert.match(called, /actions\/cache\/restore@/, "the packages are cached by the hash of what the build reads");
  assert.match(called, /name: wasm-tree/);
  for (const [name, jobs] of [["web.yml", ["unit", "e2e"]], ["extension.yml", ["unit"]], ["extension-firefox.yml", ["firefox"]]]) {
    const text = workflow(name);
    assert.match(job(text, "wasm"), /uses: \.\/\.github\/workflows\/wasm-tree\.yml/, name);
    for (const one of jobs) {
      const body = job(text, one);
      assert.match(body, /needs: wasm/, `${name} ${one}`);
      assert.match(body, /if: needs\.wasm\.outputs\.source == 'tree'\n\s+uses: actions\/download-artifact@[0-9a-f]{40}[^\n]*\n\s+with:\n\s+name: wasm-tree/, `${name} ${one} takes the package`);
    }
  }
  for (const [name, jobs] of [["web.yml", ["unit", "e2e"]], ["extension.yml", ["unit"]]]) {
    for (const one of jobs) assert.match(job(workflow(name), one), /--wasm tree[\s\S]*--wasm-commit/, `${name} ${one} builds against it`);
  }
  assert.match(job(workflow("extension-firefox.yml"), "firefox"), /FERRET_WASM_SOURCE=\$\{\{ needs\.wasm\.outputs\.source \}\}/);
  // The extension's release variant never takes it, in CI as anywhere.
  assert.match(job(workflow("extension.yml"), "unit"), /--variant release --wasm lock/);
  assert.doesNotMatch(job(workflow("extension.yml"), "lint"), /wasm-tree|--wasm tree/);
  // The pins of the recipe are the release's own.
  const pins = (/** @type {string} */ text) => ["WASM_PACK_VERSION", "WASM_BINDGEN_CLI_VERSION", "BINARYEN_VERSION", "BINARYEN_SHA256", "NODE_VERSION", "NODE_SHA256"].map((k) => new RegExp(`^  ${k}: (\\S+)$`, "m").exec(text)?.[1]);
  assert.deepEqual(pins(called), pins(workflow("release.yml")));
  assert.ok(pins(called).every(Boolean));
});

test("the_release_image_web_vault_uses_this_releases_wasm", () => {
  const release = workflow("release.yml");
  const image = job(release, "image");
  // The image waits for the build job and takes the files that job made, not the package the lock names.
  assert.match(image, /needs: build/);
  assert.match(image, /actions\/download-artifact@[0-9a-f]{40}[^\n]*\n\s+with:\n\s+name: release-files\n\s+path: wasm-package/);
  assert.match(image, /WASM_SOURCE=release/);
  assert.match(image, /WASM_SHA256=\$\{\{ steps\.wasm\.outputs\.sha256 \}\}/);
  assert.match(job(release, "build"), /name: release-files/);
  // No path in the release run builds a package from the tree.
  assert.doesNotMatch(release, /wasm-tree|WASM_SOURCE=(?:tree|lock)|--wasm tree/);
  // The Dockerfile's release source takes that archive with that digest, and the tree source is refused when there is a revision.
  const dockerfile = read("docker/server.Dockerfile");
  assert.match(dockerfile, /node scripts\/build\.mjs --wasm release --wasm-tar "\$1" --wasm-sha256 "\$WASM_SHA256"/);
  assert.match(dockerfile, /COPY web\/wasm\.lock\.json wasm-package\* \/wasm-in\//);
  assert.match(dockerfile, /a release image \(REVISION is set\) cannot carry a WebAssembly package built from the tree/);
  assert.match(dockerfile, /FERRET_RELEASE_BUILD=\$\{REVISION:\+1\}/);
  assert.match(dockerfile, /^ARG WASM_SOURCE=lock$/m, "the default is the lock");
  // The build script of the server checks the record and the release image refuses a tree package.
  assert.match(read("crates/ferret-server/build.rs"), /wasm_source::decide\(/);
  assert.match(dockerfile, /WASM_SOURCE=release is for a release image: it needs a REVISION/);
  assert.match(workflow("release.yml"), /image-publish:[\s\S]*?needs: \[image, publish\]/);
  assert.doesNotMatch(read("docker/compose.ferret-home.yml"), /WASM_SOURCE|FERRET_WASM/);
});

test("the_release_image_records_the_wasm_sha256", (t) => {
  const image = job(workflow("release.yml"), "image");
  // The digest comes from the SHA256SUMS of the run (the file the publish job signs), after the archive was checked against it.
  const find = /id: wasm[\s\S]*?run: \|\n([\s\S]*?)\n      - uses:/.exec(image);
  assert.ok(find, "a step that reads the entry");
  const script = find[1].replace(/^ {10}/gm, "");
  assert.match(script, /sha256sum -c SHA256SUMS/);
  assert.match(script, /awk -v n="\$name" '\$2 == n \{ print \$1 \}' SHA256SUMS/);
  // That step, run on a SHA256SUMS like the release's, finds the entry of the web archive and nothing else.
  const scratch = join(root, "target", `wasm-source-test-${process.pid}`);
  rmSync(scratch, { recursive: true, force: true });
  mkdirSync(scratch, { recursive: true });
  t.after(() => rmSync(scratch, { recursive: true, force: true }));
  const files = { "ferret-core-wasm-web-9.9.9.tar.gz": "web", "ferret-core-wasm-node-9.9.9.tar.gz": "node" };
  const sums = [];
  for (const [name, text] of Object.entries(files)) {
    writeFileSync(join(scratch, name), text);
    sums.push(`${createHash("sha256").update(text).digest("hex")}  ${name}`);
  }
  writeFileSync(join(scratch, "SHA256SUMS"), `${sums.sort((a, b) => (a.split("  ")[1] < b.split("  ")[1] ? -1 : 1)).join("\n")}\n`);
  const output = join(scratch, "github-output");
  const run = spawnSync("bash", ["-c", script], {
    cwd: scratch,
    encoding: "utf8",
    env: { ...process.env, VERSION: "9.9.9", GITHUB_OUTPUT: output },
  });
  assert.equal(run.status, 0, run.stderr);
  assert.equal(readFileSync(output, "utf8"), `sha256=${createHash("sha256").update("web").digest("hex")}\n`);
  // A changed archive is not accepted.
  writeFileSync(join(scratch, "ferret-core-wasm-web-9.9.9.tar.gz"), "changed");
  assert.notEqual(spawnSync("bash", ["-c", script], { cwd: scratch, encoding: "utf8", env: { ...process.env, VERSION: "9.9.9", GITHUB_OUTPUT: output } }).status, 0);

  // The image says it, and the job compares it with that entry before anything is published.
  assert.match(image, /grep -qx "wasm: release \$WASM_SHA256"/);
  assert.match(image, /WASM_SHA256: \$\{\{ steps\.wasm\.outputs\.sha256 \}\}/);
  assert.ok(image.indexOf("The image carries this release's WebAssembly package") < image.indexOf("Note the digest"), "checked before the digest is handed on");
  // The server prints it: the line of --build-info, from the record the web build wrote.
  assert.match(read("crates/ferret-server/src/build_info.rs"), /wasm: \{wasm\}/);
  assert.match(read("web/scripts/build.mjs"), /WASM_SOURCE_FILE = "wasm-source\.json"/);
  // The deploy script refuses an image that does not say lock or release.
  assert.match(read("scripts/ferret-home.sh"), /wasm: \(lock\|release\) \[0-9a-f\]\{64\}/);
});

test("a_tree_package_is_recorded_with_the_commit_it_was_built_from", (t) => {
  const scratch = join(root, "target", `wasm-tree-test-${process.pid}`);
  const rel = `target/wasm-tree-test-${process.pid}`;
  rmSync(scratch, { recursive: true, force: true });
  mkdirSync(scratch, { recursive: true });
  t.after(() => rmSync(scratch, { recursive: true, force: true }));
  const version = workspaceVersion(read("Cargo.toml"));
  const web = join(scratch, `ferret-core-wasm-web-${version}.tar.gz`);
  writeFileSync(web, "a package");
  const sha = createHash("sha256").update("a package").digest("hex");
  const commit = "0123456789abcdef0123456789abcdef01234567";
  const run = (/** @type {string[]} */ args, /** @type {Record<string, string>} */ env = {}) =>
    spawnSync("bash", [join(root, "scripts", "wasm-tree.sh"), ...args], { cwd: root, encoding: "utf8", env: { ...process.env, FERRET_TREE_COMMIT: commit, ...env } });
  const done = run(["--record", rel]);
  assert.equal(done.status, 0, done.stderr);
  assert.deepEqual(JSON.parse(readFileSync(join(scratch, "wasm-tree.json"), "utf8")), { source: "tree", commit, sha256: sha });
  assert.equal(run(["--record", rel], { FERRET_TREE_COMMIT: `${commit}-dirty` }).status, 0);
  assert.equal(JSON.parse(readFileSync(join(scratch, "wasm-tree.json"), "utf8")).commit, `${commit}-dirty`);
  // Not a commit, and not a folder outside the repository.
  for (const bad of ["main", commit.slice(1), `${commit}-clean`, "0123456789ABCDEF0123456789ABCDEF01234567"]) {
    const refused = run(["--record", rel], { FERRET_TREE_COMMIT: bad });
    assert.equal(refused.status, 2, bad);
    assert.match(refused.stderr, /not a 40-digit commit/);
  }
  for (const out of ["/tmp/x", "../x", "a/../../x"]) assert.equal(run(["--record", out]).status, 2, out);
  // No package, no record.
  rmSync(web);
  rmSync(join(scratch, "wasm-tree.json"));
  assert.equal(run(["--record", rel]).status, 1);
  assert.ok(!existsSync(join(scratch, "wasm-tree.json")));
});
