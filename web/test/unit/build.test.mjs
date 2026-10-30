import assert from "node:assert/strict";
import { existsSync, readFileSync, readdirSync, statSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { test } from "node:test";
import { build, readTarGz } from "../../scripts/build.mjs";
import { makeRoot, makeTar, sha256, wasmFiles } from "./helpers.mjs";

/** Every file below `dir` with its bytes' hash. */
function snapshot(dir, base = dir, out = {}) {
  for (const name of readdirSync(dir).sort()) {
    const full = join(dir, name);
    if (statSync(full).isDirectory()) snapshot(full, base, out);
    else out[full.slice(base.length)] = sha256(readFileSync(full));
  }
  return out;
}

/** Hashes of the shared files, which a feature must not change. */
const SHARED = ["src/boot.mjs", "src/app.mjs", "src/router.mjs", "src/i18n.mjs", "src/dom.mjs", "src/tt.mjs", "src/index.html", "src/locales/en/app.json", "src/styles/base.css"];

const FEATURE_FILES = {
  "src/routes/vault.route.mjs": 'export default { path: "/vault/items/:id", title: "vaultx.title", load: () => null };\n',
  "src/services/alpha.service.mjs": 'export default { name: "alpha", deps: ["client", "beta"], create: (deps) => ({ beta: deps.beta }) };\n',
  "src/services/beta.service.mjs": 'export default { name: "beta", deps: ["i18n"], create: () => ({}) };\n',
  "src/locales/en/vaultx.json": '{ "vaultx.title": "Items", "vaultx.empty": "Nothing here" }\n',
  "src/locales/nb/vaultx.json": '{ "vaultx.title": "Elementer", "vaultx.empty": "Ingenting her" }\n',
  "src/styles/vaultx.css": ".vaultx { color: red; }\n",
};

test("build_generates_routes_services_locales_and_css_from_feature_files", async () => {
  const plain = makeRoot();
  await build({ root: plain.root, out: plain.out, wasmTar: plain.tarPath });
  const shared = Object.fromEntries(SHARED.map((p) => [p, sha256(readFileSync(join(plain.root, p)))]));

  const { root, out, tarPath } = makeRoot(FEATURE_FILES);
  const result = await build({ root, out, wasmTar: tarPath });

  // The generated lists name the new files, services after their dependencies.
  const routes = readFileSync(join(root, "src", "routes.gen.mjs"), "utf8");
  assert.match(routes, /from "\.\/routes\/home\.route\.mjs"/);
  assert.match(routes, /from "\.\/routes\/vault\.route\.mjs"/);
  const services = readFileSync(join(root, "src", "services.gen.mjs"), "utf8");
  assert.match(services, /alpha\.service\.mjs/);
  assert.match(services, /beta\.service\.mjs/);
  assert.equal(readFileSync(join(out, "app", "routes.gen.mjs"), "utf8"), routes);
  assert.ok(existsSync(join(out, "app", "routes", "vault.route.mjs")));
  assert.ok(existsSync(join(out, "app", "services", "alpha.service.mjs")));

  // The catalogs are merged per language, sorted, from every feature file.
  const en = JSON.parse(readFileSync(join(out, "app", "locales.en.json"), "utf8"));
  const nb = JSON.parse(readFileSync(join(out, "app", "locales.nb.json"), "utf8"));
  assert.equal(en["vaultx.title"], "Items");
  assert.equal(nb["vaultx.title"], "Elementer");
  assert.equal(en["app.name"], "Faithful Ferret");
  assert.equal(en["home.title"], "Start");
  assert.deepEqual(Object.keys(en), Object.keys(en).sort());

  // The styles are one file, base first.
  const css = readFileSync(join(out, "assets", "app.css"), "utf8");
  assert.ok(css.indexOf("/* base.css */") < css.indexOf("/* vaultx.css */"));
  assert.match(css, /\.vaultx \{ color: red; \}/);

  // The WASM package and the worker client are in place; test-only files are not.
  for (const path of ["js/client.mjs", "js/vault.worker.mjs", "js/job.worker.mjs", "js/protocol.mjs", "pkg-web/ferret_core_wasm.js", "pkg-web/ferret_core_wasm_bg.wasm", "index.html", "assets/app.css", "manifest.json"]) {
    assert.ok(existsSync(join(out, path)), path);
  }
  for (const path of ["js/vector-runner.mjs", "pkg-web/ferret_core_wasm.d.ts", "pkg-web/package.json", "LICENSE"]) {
    assert.ok(!existsSync(join(out, path)), path);
  }

  // The manifest has the hash and type of every file but itself.
  const manifest = JSON.parse(readFileSync(join(out, "manifest.json"), "utf8"));
  assert.deepEqual(manifest, result.manifest);
  assert.equal(manifest["pkg-web/ferret_core_wasm_bg.wasm"].type, "application/wasm");
  assert.equal(manifest["app/boot.mjs"].type, "text/javascript; charset=utf-8");
  assert.equal(manifest["app/boot.mjs"].sha256, sha256(readFileSync(join(out, "app", "boot.mjs"))));
  assert.equal(manifest["manifest.json"], undefined);

  // No shared file was changed by adding the feature.
  for (const [path, hash] of Object.entries(shared)) {
    assert.equal(sha256(readFileSync(join(root, path))), hash, path);
  }
});

test("locale_key_outside_its_feature_prefix_fails_the_build", async () => {
  const bad = makeRoot({ "src/locales/en/vaultx.json": '{ "other.title": "x" }\n' });
  await assert.rejects(build({ root: bad.root, out: bad.out, wasmTar: bad.tarPath }), /must start with vaultx\./);
  // A feature name has no dot, so two files can never both own a key prefix.
  const dotted = makeRoot({ "src/locales/en/vault.x.json": '{ "vault.x.y": "b" }\n' });
  await assert.rejects(build({ root: dotted.root, out: dotted.out, wasmTar: dotted.tarPath }), /expected <feature>\.json/);
  const notString = makeRoot({ "src/locales/en/vaultx.json": '{ "vaultx.n": 3 }\n' });
  await assert.rejects(build({ root: notString.root, out: notString.out, wasmTar: notString.tarPath }), /not a string/);
});

test("service_cycle_fails_the_build", async () => {
  const cycle = makeRoot({
    "src/services/a.service.mjs": 'export default { name: "a", deps: ["b"], create: () => ({}) };\n',
    "src/services/b.service.mjs": 'export default { name: "b", deps: ["a"], create: () => ({}) };\n',
  });
  await assert.rejects(build({ root: cycle.root, out: cycle.out, wasmTar: cycle.tarPath }), /service dependency cycle: a -> b -> a/);
  const unknown = makeRoot({ "src/services/a.service.mjs": 'export default { name: "a", deps: ["nope"], create: () => ({}) };\n' });
  await assert.rejects(build({ root: unknown.root, out: unknown.out, wasmTar: unknown.tarPath }), /unknown service nope/);
  const twice = makeRoot({ "src/services/i18n.service.mjs": 'export default { name: "i18n", deps: [], create: () => ({}) };\n' });
  await assert.rejects(build({ root: twice.root, out: twice.out, wasmTar: twice.tarPath }), /used twice/);
  const shape = makeRoot({ "src/services/a.service.mjs": 'export default { name: "a" };\n' });
  await assert.rejects(build({ root: shape.root, out: shape.out, wasmTar: shape.tarPath }), /exports \{ name, deps, create \}/);
  const route = makeRoot({ "src/routes/x.route.mjs": 'export default { path: "/", title: "x.t", load: () => null };\n' });
  await assert.rejects(build({ root: route.root, out: route.out, wasmTar: route.tarPath }), /route path used twice/);
});

test("build_fails_on_checksum_mismatch", async () => {
  const { root, out, tarPath } = makeRoot();
  const lock = JSON.parse(readFileSync(join(root, "wasm.lock.json"), "utf8"));
  writeFileSync(join(root, "wasm.lock.json"), JSON.stringify({ ...lock, sha256: "0".repeat(64) }));
  await assert.rejects(build({ root, out, wasmTar: tarPath }), /checksum mismatch/);
  assert.ok(!existsSync(out), "nothing is written");
  // The same check applies to a download.
  const tar = makeTar(wasmFiles());
  writeFileSync(join(root, "wasm.lock.json"), JSON.stringify({ ...lock, sha256: sha256(tar) }));
  const tampered = Buffer.from(tar);
  tampered[tampered.length - 5] ^= 1;
  const fetchImpl = async () => new Response(tampered);
  await assert.rejects(build({ root, out, fetchImpl }), /checksum mismatch/);
  const good = await build({ root, out, fetchImpl: async () => new Response(tar) });
  assert.ok(good.manifest["index.html"]);
  await assert.rejects(build({ root, out, fetchImpl: async () => new Response("no", { status: 404 }) }), /answered 404/);
});

test("build_is_reproducible", async () => {
  const { root, out, tarPath } = makeRoot(FEATURE_FILES);
  await build({ root, out, wasmTar: tarPath });
  const first = snapshot(out);
  await new Promise((resolve) => setTimeout(resolve, 20));
  await build({ root, out, wasmTar: tarPath });
  assert.deepEqual(snapshot(out), first);
  // A second root with the same files gives the same output.
  const again = makeRoot(FEATURE_FILES);
  await build({ root: again.root, out: again.out, wasmTar: again.tarPath });
  assert.deepEqual(snapshot(again.out), first);
});

test("build_rejects_sourcemaps_inline_script_style_and_large_files", async () => {
  const cases = [
    [{ "src/app.map": "{}" }, /only \.mjs files/],
    [{ "src/boot.mjs.map": "{}" }, /only \.mjs files/],
    [{ "src/extra.mjs": "export const x = 1;\n//# sourceMappingURL=extra.mjs.map\n" }, /source map reference/],
    [{ "src/index.html": '<!doctype html><script>alert(1)</script>' }, /inline script/],
    [{ "src/index.html": '<!doctype html><script type="module" src="/app/boot.mjs">x</script>' }, /inline script/],
    [{ "src/index.html": '<!doctype html><p style="color:red">x</p>' }, /style attribute/],
    [{ "src/index.html": "<!doctype html><style>p{}</style>" }, /<style>/],
    [{ "src/index.html": '<!doctype html><a onclick="x()">x</a>' }, /event handler/],
    [{ "src/index.html": '<!doctype html><script src="https://cdn.example/x.js"></script>' }, /third-party/],
    [{ "src/index.html": '<!doctype html><script src="//cdn.example/x.js"></script>' }, /third-party/],
    [{ "src/styles/x.css": '@import "https://x/y.css";' }, /@import/],
    [{ "src/styles/x.css": "a { background: url(https://x/y.png); }" }, /url\(\)/],
    [{ "admin/handoff.html": "<script>1</script>" }, /inline script/],
    [{ "src/big.mjs": `export const x = "${"a".repeat(4 * 1024 * 1024)}";\n` }, /over 4 MiB/],
  ];
  for (const [files, pattern] of cases) {
    const r = makeRoot(files);
    await assert.rejects(build({ root: r.root, out: r.out, wasmTar: r.tarPath }), pattern, Object.keys(files)[0]);
  }
  // A source map or a link in the WASM package is refused too.
  for (const [files, extra, pattern] of [
    [{ ...wasmFiles(), "pkg-web/ferret_core_wasm.js.map": "{}" }, [], /source maps/],
    [wasmFiles(), [["ferret-core-wasm-web-9.9.9/js/link.mjs", "", "2"]], /entry type 2/],
    [wasmFiles(), [["ferret-core-wasm-web-9.9.9/../evil.mjs", "x", "0"]], /path not allowed/],
    [wasmFiles(), [["/abs.mjs", "x", "0"]], /path not allowed/],
  ]) {
    const r = makeRoot();
    const tar = makeTar(files, { extra });
    const path = join(r.root, "other.tar.gz");
    writeFileSync(path, tar);
    writeFileSync(join(r.root, "wasm.lock.json"), JSON.stringify({ version: "9.9.9", url: "https://example.invalid/x", sha256: sha256(tar) }));
    await assert.rejects(build({ root: r.root, out: r.out, wasmTar: path }), pattern);
  }
  // A package without the workers is refused.
  const { "js/vault.worker.mjs": _gone, ...rest } = wasmFiles();
  const r = makeRoot();
  const tar = makeTar(rest);
  writeFileSync(join(r.root, "t.tar.gz"), tar);
  writeFileSync(join(r.root, "wasm.lock.json"), JSON.stringify({ version: "9.9.9", url: "https://example.invalid/x", sha256: sha256(tar) }));
  await assert.rejects(build({ root: r.root, out: r.out, wasmTar: join(r.root, "t.tar.gz") }), /js\/vault\.worker\.mjs is missing/);
});

test("tar_reader_strips_the_top_folder_and_rejects_a_bad_header", () => {
  const files = readTarGz(makeTar({ "a/b.txt": "x" }));
  assert.deepEqual([...files.keys()], ["a/b.txt"]);
  assert.throws(() => readTarGz(Buffer.from("not a tar")), /./);
});
