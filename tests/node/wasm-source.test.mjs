// Where the WebAssembly package of a build comes from: CI and release builds use the locked package
// (web/wasm.lock.json) or, for the server image, the package of their own release run; a test build
// run by hand may use one built from the tree (scripts/wasm-tree.sh). These tests read the scripts
// and the workflows (no WASM build needed).
// Run: node --test tests/node/wasm-source.test.mjs
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { execFileSync, spawnSync } from "node:child_process";
import { existsSync, mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { test } from "node:test";
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

test("ci_takes_the_locked_wasm_package", () => {
  // The rule that built the package of the commit while the lock was behind the core is gone: no workflow has the job,
  // the reusable workflow or the script that decided it.
  assert.ok(!existsSync(join(root, ".github", "workflows", "wasm-tree.yml")));
  assert.ok(!existsSync(join(root, "scripts", "wasm-source.mjs")));
  for (const name of ["web.yml", "extension.yml", "extension-firefox.yml", "release.yml"]) {
    const text = workflow(name);
    assert.doesNotMatch(text, /wasm-tree|wasm-source|--wasm tree|--wasm-commit|WASM_SOURCE=tree|needs\.wasm\./, name);
  }
  // The lock is a published release (its URL and version agree), and the web vault and the extension build against it.
  const lock = JSON.parse(read("web/wasm.lock.json"));
  assert.match(lock.sha256, /^[0-9a-f]{64}$/);
  assert.equal(lock.url, `https://github.com/Ferdinand99/Faithful-Ferret/releases/download/v${lock.version}/ferret-core-wasm-web-${lock.version}.tar.gz`);
  assert.match(job(workflow("web.yml"), "unit"), /run: node scripts\/build\.mjs\n/);
  assert.match(job(workflow("web.yml"), "e2e"), /run: node scripts\/build\.mjs\n/);
  assert.match(job(workflow("extension-firefox.yml"), "firefox"), /jq -r \.url web\/wasm\.lock\.json/);
  // The release variant of the extension is refused, on purpose, while the lock names a package from before the release that has
  // the passkey functions (GATE_LOCK_VERSION in extension/scripts/release-build.sh): the CI jobs and scripts/lanbox-ext.sh say
  // so with a warning and skip what needs a release package, and the signing workflow builds the release itself and so fails.
  // Once the lock is at that release or a later one, the pin change has removed the rule, and the release variant is built and
  // linted in full, with no way to skip it.
  const unit = job(workflow("extension.yml"), "unit");
  const lint = job(workflow("extension.yml"), "lint");
  const gateFile = join(root, "extension", "scripts", "release-build.sh");
  const gate = existsSync(gateFile) ? /^GATE_LOCK_VERSION=(\d+)\.(\d+)\.(\d+)$/m.exec(read("extension/scripts/release-build.sh")) : null;
  assert.equal(existsSync(gateFile), gate !== null, "release-build.sh names its GATE_LOCK_VERSION");
  const locked = lock.version.split(".").map(Number);
  const behind = gate !== null && (() => {
    const wanted = gate.slice(1).map(Number);
    for (let i = 0; i < 3; i += 1) if (locked[i] !== wanted[i]) return locked[i] < wanted[i];
    return false;
  })();
  if (behind) {
    assert.match(unit, /--variant test --wasm lock/);
    assert.match(unit, /bash scripts\/release-build\.sh "\$mv" \|\| \[ \$\? -eq 10 \]/);
    assert.match(lint, /run: bash scripts\/lint-release\.sh/);
    assert.match(read("extension/scripts/release-build.sh"), /--variant release --wasm lock/);
    assert.ok(existsSync(join(root, "extension", "scripts", "lint-release.sh")));
    assert.match(read("scripts/lanbox-ext.sh"), /release-build\.sh/);
    // Signing never takes the old lock: its build job runs the build itself, which refuses.
    assert.match(read(".github/workflows/extension-sign-release.yml"), /node scripts\/build\.mjs --browser firefox --manifest mv2 --variant release/);
  } else {
    assert.equal(gate, null, "the lock is at the release with the passkey functions: the pin change removes release-build.sh and lint-release.sh");
    assert.match(unit, /--variant "\$variant" --wasm lock/);
    assert.match(lint, /--variant release\n\s+npm exec --no -- web-ext lint[^\n]*--warnings-as-errors/);
    assert.match(lint, /run: bash scripts\/check-ext-release\.sh/);
    assert.doesNotMatch(lint, /release-skipped|\|\| \[ \$\? -eq 10 \]/);
    assert.ok(!existsSync(join(root, "extension", "scripts", "lint-release.sh")));
    for (const file of ["scripts/lanbox-ext.sh", "extension/scripts/build.mjs"]) assert.doesNotMatch(read(file), /GATE_LOCK_VERSION|release-skipped|-eq 10/, file);
  }
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
  const version = /^\[workspace\.package\]\s*$[\s\S]*?^version\s*=\s*"([^"]+)"/m.exec(read("Cargo.toml"))?.[1] ?? "";
  assert.match(version, /^\d+\.\d+\.\d+$/);
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
