// The release packages: what scripts/package-release.sh puts in the archives
// must be exactly the release build, free of test support, and the checksums
// must match. Needs the packages of scripts/build-wasm.sh (pkg-web, pkg-node)
// and GNU tar and bash, as the build environments have.
// Run: node --test tests/node/release.test.mjs
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { execFileSync } from "node:child_process";
import { mkdirSync, mkdtempSync, readdirSync, readFileSync, rmSync, statSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, relative } from "node:path";
import { after, test } from "node:test";
import { root } from "./paths.mjs";

const VERSION = "0.0.0-test";
const WASM_LIMIT = 2 * 1024 * 1024;
const script = join(root, "scripts", "package-release.sh");
const scratch = mkdtempSync(join(tmpdir(), "ferret-release-"));
after(() => rmSync(scratch, { recursive: true, force: true }));

const sha256 = (bytes) => createHash("sha256").update(bytes).digest("hex");
const run = (...args) => execFileSync("bash", [script, ...args], { cwd: root, encoding: "utf8" });

function filesUnder(dir) {
  const out = [];
  for (const entry of readdirSync(dir, { withFileTypes: true, recursive: true })) {
    if (entry.isFile()) out.push(relative(dir, join(entry.parentPath, entry.name)).split("\\").join("/"));
  }
  return out.sort();
}

function extract(archive, into) {
  mkdirSync(into, { recursive: true });
  execFileSync("tar", ["-xzf", archive, "-C", into]);
  return into;
}

const one = join(scratch, "one");
const two = join(scratch, "two");
run("package", VERSION, one);
run("package", VERSION, two);

test("release_artifact_has_no_test_support_and_matches_sha256", () => {
  const sums = readFileSync(join(one, "SHA256SUMS"), "utf8").trim().split("\n");
  const names = sums.map((line) => line.split("  ")[1]).sort();
  assert.deepEqual(names, [
    `ferret-core-wasm-node-${VERSION}.tar.gz`,
    `ferret-core-wasm-web-${VERSION}.tar.gz`,
  ]);
  for (const line of sums) {
    const [sum, name] = line.split("  ");
    assert.match(sum, /^[0-9a-f]{64}$/);
    assert.equal(sha256(readFileSync(join(one, name))), sum, `${name} matches SHA256SUMS`);
  }

  for (const flavor of ["web", "node"]) {
    const dir = extract(join(one, `ferret-core-wasm-${flavor}-${VERSION}.tar.gz`), join(scratch, `x-${flavor}`));
    const top = join(dir, `ferret-core-wasm-${flavor}-${VERSION}`);
    const files = filesUnder(top);
    // Only the package, the license and (web) the worker client.
    const allowed = new RegExp(`^(pkg-${flavor}/[^/]+|LICENSE${flavor === "web" ? "|js/[^/]+" : ""})$`);
    for (const f of files) assert.match(f, allowed, `${f} belongs in the ${flavor} archive`);
    assert.ok(!files.some((f) => /-test\b|test-support/.test(f)), "no test build in the archive");
    assert.ok(files.includes("LICENSE"));

    // The module is the release build, byte for byte, and has no test exports.
    const wasmPath = `pkg-${flavor}/ferret_core_wasm_bg.wasm`;
    const packed = readFileSync(join(top, wasmPath));
    const built = readFileSync(join(root, "bindings", "wasm", wasmPath));
    assert.ok(packed.equals(built), `${flavor}: the archive holds the release module`);
    assert.ok(packed.length <= WASM_LIMIT, `${flavor}: ${packed.length} bytes is over the 2 MiB budget`);
    const names = WebAssembly.Module.exports(new WebAssembly.Module(packed)).map((e) => e.name);
    assert.ok(names.length > 60);
    assert.deepEqual(
      names.filter((n) => /(^|_)test_|replay/.test(n)),
      [],
      `${flavor}: the module exports test support`,
    );
    const dts = readFileSync(join(top, `pkg-${flavor}/ferret_core_wasm.d.ts`), "utf8");
    assert.ok(!/test_|replay|TestServer/.test(dts), `${flavor}: the .d.ts names test support`);
  }
});

test("the archives are reproducible", () => {
  for (const name of readdirSync(one)) {
    assert.ok(statSync(join(two, name)).isFile());
    assert.equal(sha256(readFileSync(join(one, name))), sha256(readFileSync(join(two, name))), `${name} is the same twice`);
  }
});

test("the checksums command covers the files that are added later", () => {
  const dir = join(scratch, "three");
  run("package", VERSION, dir);
  execFileSync("bash", ["-c", `echo '{}' > ferret-core-wasm-${VERSION}.cdx.json`], { cwd: dir });
  run("checksums", dir);
  const lines = readFileSync(join(dir, "SHA256SUMS"), "utf8").trim().split("\n");
  assert.equal(lines.length, 3);
  assert.ok(lines.some((l) => l.endsWith(`ferret-core-wasm-${VERSION}.cdx.json`)));
});

test("a version that is not a version is refused", () => {
  assert.throws(() => execFileSync("bash", [script, "package", "../x", join(scratch, "bad")], { cwd: root, stdio: "pipe" }));
});
