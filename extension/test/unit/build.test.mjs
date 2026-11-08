import assert from "node:assert/strict";
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { test } from "node:test";
import { readZip } from "../../scripts/lib/archive.mjs";
import { build, MAX_FILE_BYTES, sha256, WASM_FILES } from "../../scripts/build.mjs";
import { extensionRoot, makeRoot, makeTar, wasmFiles } from "./buildHelpers.mjs";

/** @param {Record<string, string | null>} [extra] @param {Record<string, unknown>} [options] */
async function buildIn(extra, options = {}) {
  const env = makeRoot(extra);
  try {
    const result = await build({ root: env.root, webRoot: env.webRoot, out: env.out, wasmTar: env.tarPath, ...options });
    return { env, result };
  } catch (error) {
    env.cleanup();
    throw error;
  }
}

test("build_is_reproducible", async () => {
  for (const manifest of ["mv3", "mv2"]) {
    for (const variant of ["release", "test"]) {
      const a = await buildIn({}, { manifest, variant });
      const b = await buildIn({}, { manifest, variant });
      try {
        const first = readFileSync(a.result.xpi);
        assert.equal(sha256(first), a.result.sha256);
        assert.equal(a.result.sha256, b.result.sha256, `${manifest} ${variant}`);
        assert.deepEqual(first, readFileSync(b.result.xpi));
        assert.equal(a.result.bytes, first.length);

        // Sorted names, a fixed time (1980-01-01 00:00:00) and fixed permissions.
        const names = [...readZip(first).keys()];
        assert.deepEqual(names, [...names].sort());
        let offset = 0;
        let entries = 0;
        while (first.readUInt32LE(offset) === 0x04034b50) {
          assert.equal(first.readUInt16LE(offset + 10), 0, "DOS time");
          assert.equal(first.readUInt16LE(offset + 12), 0x21, "DOS date");
          offset += 30 + first.readUInt32LE(offset + 18) + first.readUInt16LE(offset + 26) + first.readUInt16LE(offset + 28);
          entries += 1;
        }
        assert.equal(entries, names.length);
        const directory = first.readUInt32LE(first.length - 22 + 16);
        assert.equal(first.readUInt32LE(directory + 38) >>> 16, 0o100644, "file mode");

        // The folder holds the same files as the archive.
        for (const [path, bytes] of readZip(first)) {
          assert.deepEqual(readFileSync(join(a.result.dir, ...path.split("/"))), bytes, path);
        }
        assert.match(a.result.xpi, new RegExp(`ferret-firefox-${manifest}-${variant}\\.xpi$`));
      } finally {
        a.env.cleanup();
        b.env.cleanup();
      }
    }
  }
});

test("build_differs_between_variants_and_manifest_versions", async () => {
  const hashes = new Set();
  for (const manifest of ["mv3", "mv2"]) {
    for (const variant of ["release", "test"]) {
      const { env, result } = await buildIn({}, { manifest, variant });
      hashes.add(result.sha256);
      env.cleanup();
    }
  }
  assert.equal(hashes.size, 4);
});

test("wasm_tar_with_a_wrong_sha256_is_refused", async () => {
  const env = makeRoot();
  try {
    // A different archive than the one the lock names.
    const other = join(env.dir, "other.tar.gz");
    writeFileSync(other, makeTar({ ...wasmFiles(), "js/client.mjs": "// changed\n" }));
    await assert.rejects(
      build({ root: env.root, webRoot: env.webRoot, out: env.out, wasmTar: other }),
      /checksum mismatch/,
    );
    assert.equal(existsSync(env.out), false, "nothing is written");

    // A lock with another hash refuses the right archive too.
    writeFileSync(
      join(env.webRoot, "wasm.lock.json"),
      `${JSON.stringify({ version: "0.0.0", url: "https://example.invalid/x.tar.gz", sha256: "0".repeat(64) })}\n`,
    );
    await assert.rejects(build({ root: env.root, webRoot: env.webRoot, out: env.out, wasmTar: env.tarPath }), /checksum mismatch/);

    // An archive without one of the files is refused, even with the right hash.
    const partial = makeTar(Object.fromEntries(Object.entries(wasmFiles()).filter(([p]) => p !== WASM_FILES[0])));
    writeFileSync(env.tarPath, partial);
    writeFileSync(
      join(env.webRoot, "wasm.lock.json"),
      `${JSON.stringify({ version: "0.0.0", url: "https://example.invalid/x.tar.gz", sha256: sha256(partial) })}\n`,
    );
    await assert.rejects(build({ root: env.root, webRoot: env.webRoot, out: env.out, wasmTar: env.tarPath }), /js\/client\.mjs is missing/);
  } finally {
    env.cleanup();
  }
});

test("wasm_package_is_fetched_from_the_lock_when_no_tar_is_given", async () => {
  const env = makeRoot();
  try {
    /** @type {string[]} */
    const asked = [];
    const archive = readFileSync(env.tarPath);
    const fetchImpl = /** @type {typeof fetch} */ (async (url) => {
      asked.push(String(url));
      return new Response(archive);
    });
    await build({ root: env.root, webRoot: env.webRoot, out: env.out, fetchImpl });
    assert.deepEqual(asked, ["https://example.invalid/wasm.tar.gz"]);
    const failing = /** @type {typeof fetch} */ (async () => new Response("no", { status: 404 }));
    await assert.rejects(build({ root: env.root, webRoot: env.webRoot, out: env.out, fetchImpl: failing }), /answered 404/);
  } finally {
    env.cleanup();
  }
});

const BAD_HTML = {
  "inline script": '<!doctype html><script>alert(1)</script>',
  "inline script with an src and a body": '<!doctype html><script src="a.mjs">alert(1)</script>',
  "unclosed script": '<!doctype html><script src="a.mjs">',
  "style element": "<!doctype html><style>p { color: red }</style>",
  "style attribute": '<!doctype html><p style="color:red">x</p>',
  "event handler": '<!doctype html><p onclick="x()">x</p>',
  "javascript url": '<!doctype html><a href="javascript:x()">x</a>',
  "remote script": '<!doctype html><script type="module" src="https://example.com/a.mjs"></script>',
  "protocol-relative script": '<!doctype html><script type="module" src="//example.com/a.mjs"></script>',
};

test("html_with_inline_script_or_style_attribute_is_refused", async () => {
  for (const [name, html] of Object.entries(BAD_HTML)) {
    await assert.rejects(buildIn({ "src/pages/bad.html": html }), /pages\/bad\.html/, name);
  }
  // The pages of the extension itself are clean.
  const { env } = await buildIn({});
  env.cleanup();
});

test("build_refuses_source_maps_big_files_and_unknown_file_types", async () => {
  await assert.rejects(buildIn({ "src/pages/a.mjs": "export {};\n//# sourceMappingURL=a.mjs.map\n" }), /source map/);
  await assert.rejects(buildIn({ "src/pages/a.mjs.map": "{}" }), /only \.mjs and \.html/);
  await assert.rejects(buildIn({ "src/pages/big.mjs": `export const x = "${"a".repeat(MAX_FILE_BYTES)}";\n` }), /over 4 MiB/);
  await assert.rejects(buildIn({ "src/pages/a.png": "x" }), /only \.mjs and \.html/);

  // A big .wasm is fine.
  const env = makeRoot();
  try {
    const big = makeTar({ ...wasmFiles(), "pkg-web/ferret_core_wasm_bg.wasm": Buffer.alloc(MAX_FILE_BYTES + 1, 1) });
    writeFileSync(env.tarPath, big);
    writeFileSync(
      join(env.webRoot, "wasm.lock.json"),
      `${JSON.stringify({ version: "0.0.0", url: "https://example.invalid/x.tar.gz", sha256: sha256(big) })}\n`,
    );
    const result = await build({ root: env.root, webRoot: env.webRoot, out: env.out, wasmTar: env.tarPath });
    assert.ok(result.files.get("pkg-web/ferret_core_wasm_bg.wasm")?.length === MAX_FILE_BYTES + 1);
  } finally {
    env.cleanup();
  }
});

test("build_refuses_a_manifest_that_names_a_missing_file", async () => {
  await assert.rejects(
    buildIn({ "src/pages/about.html": null }),
    /pages\/about\.html is not in the package/,
  );
});

test("build_merges_locales_and_styles_from_feature_files", async () => {
  const { env, result } = await buildIn({
    "src/locales/en/extra.json": '{ "extra.title": "Extra" }\n',
    "src/locales/nb/extra.json": '{ "extra.title": "Ekstra" }\n',
    "src/styles/extra.css": ".extra { color: red; }\n",
  });
  try {
    const en = JSON.parse(/** @type {Buffer} */ (result.files.get("locales.en.json")).toString("utf8"));
    const nb = JSON.parse(/** @type {Buffer} */ (result.files.get("locales.nb.json")).toString("utf8"));
    assert.equal(en["extra.title"], "Extra");
    assert.equal(nb["extra.title"], "Ekstra");
    assert.equal(en["about.title"], "Faithful Ferret");
    assert.deepEqual(Object.keys(en), Object.keys(en).sort());
    const css = /** @type {Buffer} */ (result.files.get("assets/app.css")).toString("utf8");
    assert.ok(css.indexOf("/* base.css */") < css.indexOf("/* extra.css */"));
  } finally {
    env.cleanup();
  }
  // A key outside the file's own feature, a duplicate and a url() are refused.
  await assert.rejects(buildIn({ "src/locales/en/extra.json": '{ "other.title": "x" }\n' }), /must start with extra\./);
  await assert.rejects(buildIn({ "src/locales/en/extra.json": '{ "about.title": "x" }\n' }), /must start with extra\./);
  await assert.rejects(buildIn({ "src/styles/extra.css": "a { background: url(https://example.com/x.png) }\n" }), /no @import/);
});

test("mv3_build_has_no_background_page_and_mv2_build_has_it", async () => {
  const mv3 = await buildIn({}, { manifest: "mv3" });
  const mv2 = await buildIn({}, { manifest: "mv2" });
  try {
    assert.equal(mv3.result.files.has("background/background.html"), false);
    assert.equal(mv2.result.files.has("background/background.html"), true);
    assert.equal(mv3.result.files.has("background/compat.mjs"), true);
  } finally {
    mv3.env.cleanup();
    mv2.env.cleanup();
  }
});

test("shared_manifest_is_empty_in_u0", async () => {
  assert.deepEqual(JSON.parse(readFileSync(join(extensionRoot, "shared.json"), "utf8")), []);
  const { env, result } = await buildIn({});
  try {
    assert.equal(result.files.has("shared/MANIFEST.json"), false);
    assert.equal(existsSync(join(result.dir, "shared", "MANIFEST.json")), false);
    assert.equal(existsSync(join(result.dir, "shared")), existsSync(join(env.root, "src", "shared")), "dist/shared exists only if src/shared does");
  } finally {
    env.cleanup();
  }
});

test("shared_files_are_copied_from_web_with_their_hashes_and_never_over_a_source_file", async () => {
  const env = makeRoot({ "shared.json": '["b.mjs", "dir/a.mjs"]\n' });
  try {
    mkdirSync(join(env.webRoot, "src", "dir"), { recursive: true });
    writeFileSync(join(env.webRoot, "src", "b.mjs"), "export const b = 1;\n");
    writeFileSync(join(env.webRoot, "src", "dir", "a.mjs"), "export const a = 1;\n");
    const result = await build({ root: env.root, webRoot: env.webRoot, out: env.out, wasmTar: env.tarPath });
    assert.equal(readFileSync(join(result.dir, "shared", "b.mjs"), "utf8"), "export const b = 1;\n");
    assert.deepEqual(JSON.parse(readFileSync(join(result.dir, "shared", "MANIFEST.json"), "utf8")), {
      "b.mjs": sha256("export const b = 1;\n"),
      "dir/a.mjs": sha256("export const a = 1;\n"),
    });

    for (const bad of ['["../x.mjs"]', '["/etc/passwd"]', '["a.js"]', '["missing.mjs"]', '{"a": 1}']) {
      writeFileSync(join(env.root, "shared.json"), `${bad}\n`);
      await assert.rejects(build({ root: env.root, webRoot: env.webRoot, out: env.out, wasmTar: env.tarPath }), /shared\.json/, bad);
    }

    // A listed file may not land on a source file of the extension.
    mkdirSync(join(env.root, "src", "shared"), { recursive: true });
    writeFileSync(join(env.root, "src", "shared", "b.mjs"), "export {};\n");
    writeFileSync(join(env.root, "shared.json"), '["b.mjs"]\n');
    await assert.rejects(build({ root: env.root, webRoot: env.webRoot, out: env.out, wasmTar: env.tarPath }), /also a source file/);
  } finally {
    env.cleanup();
  }
});

