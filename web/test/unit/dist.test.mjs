// Checks on the real web/dist (run `npm run build` first) and on the sources.
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { existsSync, readFileSync, readdirSync, statSync } from "node:fs";
import { join } from "node:path";
import { test } from "node:test";
import { loadHeaders, SERVER_HEADERS_JSON, STUB_HEADERS_JSON } from "../serve.mjs";
import { web } from "./helpers.mjs";

const dist = join(web, "dist");

function manifest() {
  assert.ok(existsSync(join(dist, "manifest.json")), "web/dist is missing: run `npm run build` first");
  return JSON.parse(readFileSync(join(dist, "manifest.json"), "utf8"));
}

function allFiles(dir) {
  return readdirSync(dir).flatMap((n) => {
    const full = join(dir, n);
    return statSync(full).isDirectory() ? allFiles(full) : [full];
  });
}

test("dist_html_has_no_inline_script_or_style", () => {
  const htmlFiles = Object.keys(manifest()).filter((p) => p.endsWith(".html"));
  assert.ok(htmlFiles.includes("index.html"));
  for (const path of htmlFiles) {
    const html = readFileSync(join(dist, path), "utf8");
    for (const [, attrs, body] of html.matchAll(/<script\b([^>]*)>([\s\S]*?)<\/script\s*>/gi)) {
      assert.match(attrs, /\ssrc="/, path);
      assert.equal(body.trim(), "", path);
    }
    assert.doesNotMatch(html, /<style\b/i, path);
    assert.doesNotMatch(html, /\sstyle\s*=/i, path);
    assert.doesNotMatch(html, /\son[a-z]+\s*=/i, path);
    assert.doesNotMatch(html, /javascript:/i, path);
  }
  // The css is a file of its own and loads nothing from another origin.
  const css = readFileSync(join(dist, "assets", "app.css"), "utf8");
  assert.doesNotMatch(css, /@import|url\(\s*["']?(?!data:)|https?:\/\//i);
});

test("dist_has_no_sourcemaps", () => {
  const files = allFiles(dist);
  assert.ok(files.length > 10);
  for (const file of files) {
    assert.doesNotMatch(file, /\.map$/);
    if (/\.(mjs|js|css)$/.test(file)) assert.doesNotMatch(readFileSync(file, "utf8"), /sourceMappingURL=/, file);
    if (!file.endsWith(".wasm")) assert.ok(statSync(file).size <= 4 * 1024 * 1024, file);
  }
  const listed = Object.keys(manifest()).sort();
  assert.deepEqual(files.map((f) => f.slice(dist.length + 1).split("\\").join("/")).filter((p) => p !== "manifest.json").sort(), listed);
});

test("dist_serves_the_files_the_page_and_the_workers_load", () => {
  const files = manifest();
  for (const path of [
    "index.html", "app/boot.mjs", "app/app.mjs", "app/routes.gen.mjs", "app/services.gen.mjs", "app/locales.en.json", "app/locales.nb.json",
    "assets/app.css", "js/client.mjs", "js/vault.worker.mjs", "js/job.worker.mjs", "pkg-web/ferret_core_wasm.js", "pkg-web/ferret_core_wasm_bg.wasm",
  ]) {
    assert.ok(files[path], path);
  }
  // The index loads one module and one stylesheet, both from this origin.
  const html = readFileSync(join(dist, "index.html"), "utf8");
  assert.match(html, /<script type="module" src="\/app\/boot\.mjs"><\/script>/);
  assert.match(html, /href="\/assets\/app\.css"/);
});

test("src_has_no_html_sinks_or_dynamic_code", () => {
  const sinks = [/\.innerHTML\b/, /\.outerHTML\b/, /insertAdjacentHTML/, /document\.write/, /\beval\s*\(/, /new\s+Function\b/, /createContextualFragment/, /DOMParser/, /javascript:/];
  const src = join(web, "src");
  for (const file of allFiles(src).filter((f) => f.endsWith(".mjs"))) {
    const text = readFileSync(file, "utf8");
    for (const sink of sinks) assert.doesNotMatch(text, sink, file);
  }
});

test("wasm_lock_names_a_published_version", async (t) => {
  const lock = JSON.parse(readFileSync(join(web, "wasm.lock.json"), "utf8"));
  assert.deepEqual(Object.keys(lock).sort(), ["sha256", "url", "version"]);
  assert.match(lock.version, /^\d+\.\d+\.\d+$/);
  assert.match(lock.sha256, /^[0-9a-f]{64}$/);
  assert.equal(
    lock.url,
    `https://github.com/Ferdinand99/Faithful-Ferret/releases/download/v${lock.version}/ferret-core-wasm-web-${lock.version}.tar.gz`,
  );
  if (process.env.FERRET_OFFLINE) return t.skip("FERRET_OFFLINE is set");
  const response = await fetch(lock.url, { method: "HEAD" });
  assert.equal(response.status, 200, `${lock.url} is not a published release file`);
});

test("types_check", () => {
  assert.ok(existsSync(join(web, "src", "routes.gen.mjs")), "run `npm run build` first");
  const tsc = join(web, "node_modules", "typescript", "bin", "tsc");
  const run = spawnSync(process.execPath, [tsc, "-p", "jsconfig.json", "--noEmit"], { cwd: web, encoding: "utf8" });
  assert.equal(run.status, 0, `${run.stdout}${run.stderr}`);
});

test("header_list_is_section_12_verbatim", () => {
  const stub = loadHeaders(STUB_HEADERS_JSON);
  assert.deepEqual(Object.keys(stub), [
    "Content-Security-Policy", "Cross-Origin-Opener-Policy", "Cross-Origin-Resource-Policy", "Referrer-Policy", "Strict-Transport-Security",
  ]);
  assert.equal(
    stub["Content-Security-Policy"],
    "default-src 'none'; script-src 'self' 'wasm-unsafe-eval'; style-src 'self'; connect-src 'self'; img-src 'self' data:; frame-ancestors 'none'; base-uri 'none'; form-action 'self'; require-trusted-types-for 'script'; trusted-types ferret",
  );
  assert.equal(stub["Cross-Origin-Opener-Policy"], "same-origin");
  assert.equal(stub["Cross-Origin-Resource-Policy"], "same-origin");
  assert.equal(stub["Referrer-Policy"], "no-referrer");
  assert.equal(stub["Strict-Transport-Security"], "max-age=63072000; includeSubDomains; preload");
  // When the server's fixture exists, the stub must say the same.
  if (existsSync(SERVER_HEADERS_JSON)) {
    const real = loadHeaders(SERVER_HEADERS_JSON);
    for (const [name, value] of Object.entries(stub)) assert.equal(real[name], value, name);
  }
});
