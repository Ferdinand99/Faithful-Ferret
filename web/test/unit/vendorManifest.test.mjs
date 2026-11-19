// The vendored third-party files: the manifest matches the files and their licence, the notices list
// them, the build refuses a file that is not as listed, and nothing that is only for development (the QR
// decoder of the tests, the test tools) is in dist/.
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { existsSync, readdirSync, readFileSync, statSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { test } from "node:test";
import { build } from "../../scripts/build.mjs";
import { makeRoot, web } from "./helpers.mjs";

/** The vendored file, pinned here as well as in the manifest, so that an edit of both together shows in review. */
const QRCODEGEN_SHA256 = "431935a3148eeffc57534e859ee2d3826c89c89228e92b7827d8d3c736d3c8b1";
const sha256 = (bytes) => createHash("sha256").update(bytes).digest("hex");
const repo = join(web, "..");
const manifest = () => JSON.parse(readFileSync(join(web, "vendor", "MANIFEST.json"), "utf8"));

function allFiles(dir) {
  return readdirSync(dir).flatMap((n) => {
    const full = join(dir, n);
    return statSync(full).isDirectory() ? allFiles(full) : [full];
  });
}

test("vendor_manifest_matches_the_file_hash_and_the_license", () => {
  const m = manifest();
  assert.equal(m.format, "ferret-vendor/1");
  assert.ok(m.files.length >= 1);
  const listed = new Set(["MANIFEST.json"]);
  for (const entry of m.files) {
    const file = readFileSync(join(web, "vendor", entry.file));
    assert.equal(sha256(file), entry.sha256, `${entry.file} is not the file in the manifest`);
    if (entry.name === "qrcodegen") assert.equal(sha256(file), QRCODEGEN_SHA256, "the vendored file is not the one pinned in this test");
    const licence = readFileSync(join(web, "vendor", entry.licenseFile), "utf8");
    assert.equal(sha256(licence), entry.licenseSha256, `${entry.licenseFile} is not the file in the manifest`);
    listed.add(entry.file);
    listed.add(entry.licenseFile);

    // The licence the manifest names is the one the file carries, with the copyright of its authors.
    assert.equal(entry.license, "MIT");
    assert.ok(licence.includes(entry.copyright), "the licence file holds the copyright line");
    assert.match(licence, /Permission is hereby granted, free of charge/);
    const text = file.toString("utf8");
    assert.match(text, /^\/\/ SPDX-License-Identifier: MIT\n\/\/ Modified by Faithful Ferret: /, "SPDX line and the note on what was changed");
    assert.ok(text.includes(entry.copyright), "the file keeps the copyright line of its authors");
    assert.ok(text.includes("Permission is hereby granted, free of charge"), "the file keeps the licence header of its authors");
    assert.ok(text.includes(entry.commit), "the note names the commit the file comes from");
    assert.match(entry.commit, /^[0-9a-f]{40}$/);
    assert.match(entry.sourceSha256, /^[0-9a-f]{64}$/);
    assert.match(entry.ships, /^js\/vendor\/.*\.mjs$/);

    // The vendored code only computes: no network, no storage, no dynamic code, no page access.
    for (const word of ["fetch(", "XMLHttpRequest", "WebSocket", "localStorage", "sessionStorage", "indexedDB", "eval(", "new Function", "document.", "window.", "importScripts", "import(", "Math.random", "crypto."]) {
      assert.ok(!text.includes(word), `${entry.file} must not use ${word}`);
    }
  }
  // Nothing else is in the vendor folder.
  const files = allFiles(join(web, "vendor")).map((f) => f.slice(join(web, "vendor").length + 1).split("\\").join("/"));
  assert.deepEqual(files.sort(), [...listed].sort());
});

test("vendor_build_refuses_a_file_that_is_not_the_listed_one_and_a_file_that_is_not_listed", async () => {
  const entry = manifest().files[0];
  // As it is: the build puts the file in dist/js/vendor/ and next to the worker client, with the same bytes.
  const ok = makeRoot();
  const built = await build({ root: ok.root, out: ok.out, wasmTar: ok.tarPath });
  const shipped = readFileSync(join(ok.out, ...entry.ships.split("/")));
  assert.equal(sha256(shipped), entry.sha256);
  assert.equal(built.manifest[entry.ships].sha256, entry.sha256);
  assert.ok(existsSync(join(ok.root, ...entry.ships.split("/"))), "the sources import it from js/vendor/");
  assert.ok(existsSync(join(ok.root, ...entry.ships.replace(/\.mjs$/, ".d.mts").split("/"))), "with its type declarations");
  assert.ok(!existsSync(join(ok.out, ...entry.ships.replace(/\.mjs$/, ".d.mts").split("/"))), "which are not in dist");
  assert.ok(!existsSync(join(ok.out, "vendor")), "no licence file or manifest in dist");

  // One changed byte.
  const changed = makeRoot();
  const target = join(changed.root, "vendor", entry.file);
  writeFileSync(target, `${readFileSync(target, "utf8")}\n// changed\n`);
  await assert.rejects(build({ root: changed.root, out: changed.out, wasmTar: changed.tarPath }), /SHA-256 is not the one/);

  // A changed licence file.
  const licence = makeRoot();
  const licenceTarget = join(licence.root, "vendor", entry.licenseFile);
  writeFileSync(licenceTarget, `${readFileSync(licenceTarget, "utf8")} `);
  await assert.rejects(build({ root: licence.root, out: licence.out, wasmTar: licence.tarPath }), /SHA-256 is not the one/);

  // A file that is not listed.
  const extra = makeRoot({ "vendor/other/other.mjs": "export default 1;\n" });
  await assert.rejects(build({ root: extra.root, out: extra.out, wasmTar: extra.tarPath }), /not listed in vendor\/MANIFEST\.json/);

  // A file that is listed but not there.
  const missing = makeRoot();
  const list = manifest();
  list.files[0].file = "qrcodegen/missing.mjs";
  writeFileSync(join(missing.root, "vendor", "MANIFEST.json"), JSON.stringify(list));
  await assert.rejects(build({ root: missing.root, out: missing.out, wasmTar: missing.tarPath }), /missing or has no SHA-256/);

  // A header that lost its SPDX line or its authors' copyright cannot be shipped, even with the new hash.
  const stripped = makeRoot();
  const text = readFileSync(join(stripped.root, "vendor", entry.file), "utf8").replace("// SPDX-License-Identifier: MIT\n", "");
  writeFileSync(join(stripped.root, "vendor", entry.file), text);
  const edited = manifest();
  edited.files[0].sha256 = sha256(text);
  writeFileSync(join(stripped.root, "vendor", "MANIFEST.json"), JSON.stringify(edited));
  await assert.rejects(build({ root: stripped.root, out: stripped.out, wasmTar: stripped.tarPath }), /SPDX line/);
});

test("third_party_notices_list_qrcodegen", () => {
  const notices = readFileSync(join(repo, "THIRD-PARTY-NOTICES"), "utf8");
  const extra = JSON.parse(readFileSync(join(repo, "notices-extra.json"), "utf8"));
  for (const entry of manifest().files) {
    const listed = extra.vendored.find((v) => v.name === entry.name);
    assert.ok(listed, `${entry.name} has an entry in notices-extra.json`);
    assert.equal(listed.version, entry.version);
    assert.equal(listed.license, entry.license);
    assert.equal(listed.copyright, entry.copyright);
    assert.equal(listed.file, `web/vendor/${entry.file}`);
    assert.equal(listed.licenseFile, `web/vendor/${entry.licenseFile}`);
    assert.ok(listed.note.includes("Modified by Faithful Ferret"));
    // The file the notices are made from is the licence file in the repository.
    assert.ok(notices.includes(readFileSync(join(web, "vendor", entry.licenseFile), "utf8").trim().replace(/\r\n/g, "\n")), "the licence text is in THIRD-PARTY-NOTICES");
    assert.ok(notices.includes(`${entry.name} ${entry.version} (${entry.origin})`), "the notices name the file, its version and where it comes from");
    assert.ok(notices.includes(`file: web/vendor/${entry.file}`));
    assert.ok(notices.includes(entry.copyright));
  }
  assert.equal(extra.vendored.length, manifest().files.length, "no entry for a file that is not vendored");
  assert.ok(notices.includes("qrcodegen 1.8.0"));
  assert.ok(notices.includes("Copyright (c) Project Nayuki"));
});

test("dist_holds_no_dev_dependency", () => {
  const dist = join(web, "dist");
  assert.ok(existsSync(join(dist, "manifest.json")), "web/dist is missing: run `npm run build` first");
  const pkg = JSON.parse(readFileSync(join(web, "package.json"), "utf8"));
  const lock = JSON.parse(readFileSync(join(web, "package-lock.json"), "utf8"));
  // The web vault has no runtime dependency at all, and each package in the lock is a development one.
  assert.equal(pkg.dependencies, undefined);
  assert.ok(pkg.devDependencies.jsqr, "jsqr is a development dependency");
  assert.match(pkg.devDependencies.jsqr, /^\d+\.\d+\.\d+$/, "pinned to one version");
  for (const [path, info] of Object.entries(lock.packages)) {
    if (path === "") continue;
    assert.ok(info.dev === true || info.devOptional === true, `${path} is not a development dependency`);
  }
  assert.equal(lock.packages["node_modules/jsqr"].dev, true);

  // Nothing of them is in dist: not their names, not an import of them, not a path into node_modules.
  const names = Object.keys(pkg.devDependencies);
  const files = allFiles(dist).filter((f) => /\.(mjs|js|json|html|css)$/.test(f));
  assert.ok(files.length > 10);
  for (const file of files) {
    const text = readFileSync(file, "utf8");
    // (A word, not a substring: the font in app/inter.mjs is base64 text, which holds any four letters somewhere.)
    assert.ok(!/\bjsqr\b/i.test(text), `${file} mentions jsqr`);
    assert.ok(!text.includes("node_modules"), `${file} points into node_modules`);
    for (const name of names) {
      assert.ok(!new RegExp(`(?:from|import\\(|require\\()\\s*["']${name.replace(/[/@-]/g, "\\$&")}["'/]`).test(text), `${file} imports ${name}`);
    }
    assert.ok(!/fake-indexeddb|@playwright/.test(text), `${file} mentions a test tool`);
  }
  // The vendored file is the only third-party code in dist, and it is the listed one.
  const entry = manifest().files[0];
  assert.equal(sha256(readFileSync(join(dist, ...entry.ships.split("/")))), entry.sha256);
  const outside = JSON.parse(readFileSync(join(dist, "manifest.json"), "utf8"));
  const vendored = Object.keys(outside).filter((p) => p.includes("vendor"));
  assert.deepEqual(vendored, [entry.ships]);
});
