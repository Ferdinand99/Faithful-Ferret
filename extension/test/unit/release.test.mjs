import assert from "node:assert/strict";
import { copyFileSync, mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { spawnSync } from "node:child_process";
import { test } from "node:test";
import {
  build, buildManifest, EXTENSION_CSP, FEATURES_FILE, featuresModule, packXpi, readInternalHosts, readPermissionAllow, RELEASE_MANIFEST_KEYS, releaseProblems, SAVE_FILES, UPDATE_URL,
} from "../../scripts/build.mjs";
import { extensionRoot, makeRoot, repoRoot } from "./buildHelpers.mjs";

const CHECK = join(repoRoot, "scripts", "check-ext-release.sh");
/** The internal host names of the repository's own test/fixtures/hosts.json. */
const HOSTS = readInternalHosts();

/**
 * The features module of a release (save on) and the files of that feature, for a package made by hand.
 * @type {[string, Buffer][]}
 */
const RELEASE_BASE = [
  [FEATURES_FILE, Buffer.from(featuresModule(["save"], new Map()))],
  ...SAVE_FILES.map((path) => /** @type {[string, Buffer]} */ ([path, Buffer.from("void 0;\n")])),
];

const MEASURE_HTML = '<!doctype html><html><head><script type="module" src="measure.mjs"></script></head></html>\n';

/** Test-only files in the places the build looks at. */
const PLANTED = {
  "test/bridge.html": '<!doctype html><script type="module" src="bridge.mjs"></script>\n',
  "test/bridge.mjs": "export {};\n",
  "src/pages/test-only/measure.html": MEASURE_HTML,
  "src/pages/test-only/measure.mjs": "export {};\n",
};

/** @param {string} target @returns {{ status: number | null, output: string }} */
function runCheck(target) {
  // The fixture builds sit in <dir>/out next to their web folder <dir>/web, the lock the packages are checked against.
  const result = spawnSync("bash", [CHECK, "--web-root", join(dirname(target), "..", "web"), target], { encoding: "utf8" });
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
    for (const path of ["test/bridge.html", "test/bridge.mjs", "pages/test-only/measure.html", "pages/test-only/measure.mjs"]) {
      assert.ok(test.files.has(path), path);
    }
    assert.deepEqual(releaseProblems(release.files, HOSTS), []);

    // The check passes for the release (folder and .xpi) and fails for the test build.
    for (const target of [release.dir, release.xpi]) {
      const clean = runCheck(target);
      assert.equal(clean.status, 0, clean.output);
    }
    const bad = runCheck(test.xpi);
    assert.notEqual(bad.status, 0);
    assert.match(bad.output, /test files are not allowed in a release/);
    assert.match(bad.output, /the name is the test build's/);
    assert.match(bad.output, /the add-on id is "ferret-test@hedgerow\.tools"/);

    // A test file planted into a release folder, in several places, fails the check.
    for (const path of ["test/bridge.html", "test/anything.mjs", "pages/bridge.html", "pages/test-only/measure.mjs"]) {
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
  assert.deepEqual(releaseProblems(new Map(RELEASE_BASE), HOSTS), ["manifest.json is missing"]);
});

test("release_package_must_carry_exactly_the_release_add_on_id", () => {
  /** @param {unknown} id */
  const manifestWith = (id) => new Map([...RELEASE_BASE, [
    "manifest.json",
    Buffer.from(JSON.stringify({ name: "Faithful Ferret", manifest_version: 3, content_security_policy: { extension_pages: EXTENSION_CSP }, browser_specific_settings: { gecko: { id, update_url: UPDATE_URL } } })),
  ]]);
  assert.deepEqual(releaseProblems(manifestWith("ferret@hedgerow.tools"), HOSTS), []);
  for (const id of ["ferret-test@hedgerow.tools", "other@example.com", "Ferret@hedgerow.tools", "ferret@hedgerow.tools ", undefined]) {
    const problems = releaseProblems(manifestWith(id), HOSTS);
    assert.equal(problems.length, 1, String(id));
    assert.match(problems[0], /the add-on id is/);
  }
  // No gecko section at all.
  assert.match(releaseProblems(new Map([...RELEASE_BASE, ["manifest.json", Buffer.from('{ "name": "x" }')]]), HOSTS)[0], /the add-on id is undefined/);
});

test("release_package_must_carry_exactly_the_update_url", () => {
  assert.equal(UPDATE_URL, "https://github.com/Ferdinand99/Faithful-Ferret/releases/download/extension-updates/updates.json");
  /** @param {unknown} url @param {boolean} [present] */
  const manifestWith = (url, present = true) => new Map([...RELEASE_BASE, [
    "manifest.json",
    Buffer.from(JSON.stringify({
      name: "Faithful Ferret", manifest_version: 3, content_security_policy: { extension_pages: EXTENSION_CSP },
      browser_specific_settings: { gecko: present ? { id: "ferret@hedgerow.tools", update_url: url } : { id: "ferret@hedgerow.tools" } },
    })),
  ]]);
  assert.deepEqual(releaseProblems(manifestWith(UPDATE_URL), HOSTS), []);
  for (const url of [
    UPDATE_URL.replace("https:", "http:"),
    `${UPDATE_URL}?x=1`,
    `${UPDATE_URL}/`,
    UPDATE_URL.toUpperCase(),
    UPDATE_URL.replace("Ferdinand99/Faithful-Ferret", "someone/Faithful-Ferret"),
    UPDATE_URL.replace("extension-updates", "v0.7.1"),
    "https://example.com/updates.json",
    "",
    null,
    42,
  ]) {
    const problems = releaseProblems(manifestWith(url), HOSTS);
    assert.equal(problems.length, 1, String(url));
    assert.match(problems[0], /the update_url is .*, a release has https:\/\/github\.com\//, String(url));
  }
  // A release without an update_url would stop updating: refused too.
  assert.match(releaseProblems(manifestWith(undefined, false), HOSTS).join("\n"), /the update_url is undefined/);
});

test("release_build_carries_the_release_id_and_the_test_build_its_own", async () => {
  const env = makeRoot();
  try {
    const options = { root: env.root, webRoot: env.webRoot, out: env.out, wasmTar: env.tarPath };
    for (const manifest of ["mv3", "mv2"]) {
      const release = await build({ ...options, manifest, variant: "release" });
      const test = await build({ ...options, manifest, variant: "test" });
      const gecko = (/** @type {{ files: Map<string, Buffer> }} */ r) => JSON.parse(/** @type {Buffer} */ (r.files.get("manifest.json")).toString("utf8")).browser_specific_settings.gecko;
      assert.equal(gecko(release).id, "ferret@hedgerow.tools");
      assert.equal(gecko(test).id, "ferret-test@hedgerow.tools");
      // The release asks the project's update manifest for new versions; the test variant never updates itself.
      assert.equal(gecko(release).update_url, UPDATE_URL, manifest);
      assert.equal("update_url" in gecko(test), false, manifest);
    }
  } finally {
    env.cleanup();
  }
});

test("no_manifest_file_may_set_the_update_url", async () => {
  const base = JSON.parse(readFileSync(join(extensionRoot, "manifest", "base.json"), "utf8"));
  base.browser_specific_settings.gecko.update_url = UPDATE_URL;
  const part = { browser_specific_settings: { gecko: { update_url: "https://example.com/updates.json" } } };
  /** @type {[string, unknown, string[]][]} */
  const cases = [
    ["manifest/base.json", base, ["release", "test"]],
    ["manifest/parts/extra.json", part, ["release", "test"]],
    // A test part is read for the test variant only.
    ["manifest/test-parts/extra.json", part, ["test"]],
  ];
  for (const [path, json, variants] of cases) {
    const env = makeRoot({ [path]: `${JSON.stringify(json, null, 2)}\n` });
    try {
      const options = { root: env.root, webRoot: env.webRoot, out: env.out, wasmTar: env.tarPath };
      for (const variant of variants) {
        await assert.rejects(build({ ...options, variant }), /update_url is set by the build/, `${path} ${variant}`);
      }
    } finally {
      env.cleanup();
    }
  }
});

test("check_ext_release_needs_a_package", () => {
  const result = spawnSync("bash", [CHECK, join(repoRoot, "extension", "does-not-exist.xpi")], { encoding: "utf8" });
  assert.notEqual(result.status, 0);
});

test("release_check_refuses_an_internal_host_name", async () => {
  assert.ok(HOSTS.includes("fixture.test") && HOSTS.includes("vault-e2e.test"), "the fixture and e2e hosts are in hosts.json");
  for (const host of HOSTS) {
    const env = makeRoot({ "src/pages/leak.mjs": `export const url = "https://${host.toUpperCase()}/login";
` });
    try {
      const options = { root: env.root, webRoot: env.webRoot, out: env.out, wasmTar: env.tarPath };
      await assert.rejects(build({ ...options, variant: "release" }), new RegExp(`pages/leak\\.mjs: names the internal host ${host.replaceAll(".", "\\.")}`));
      // The test variant may name them.
      await build({ ...options, variant: "test" });
    } finally {
      env.cleanup();
    }
  }
  // A package folder that holds one fails the standalone check.
  const env = makeRoot();
  try {
    const options = { root: env.root, webRoot: env.webRoot, out: env.out, wasmTar: env.tarPath };
    const release = await build({ ...options, variant: "release" });
    writeFileSync(join(release.dir, "pages", "about.mjs"), `${release.files.get("pages/about.mjs")}
// https://${HOSTS[0]}/
`);
    const result = runCheck(release.dir);
    assert.notEqual(result.status, 0);
    assert.match(result.output, /names the internal host/);
  } finally {
    env.cleanup();
  }
});

test("release_check_fails_closed_without_the_host_list", async () => {
  const env = makeRoot({ "test/fixtures/hosts.json": null });
  try {
    await assert.rejects(build({ root: env.root, webRoot: env.webRoot, out: env.out, wasmTar: env.tarPath, variant: "release" }), /hosts.json is missing/);
  } finally {
    env.cleanup();
  }
  assert.throws(() => releaseProblems(new Map(), /** @type {any} */ (undefined)));
});

// ------------------------------------------------- the manifest of a release

/** @typedef {{ status: number | null, output: string }} CheckResult */

/**
 * Plants a change into the manifest.json of a built release and runs the release
 * check on a folder and on a .xpi packed from it.
 * @param {{ dir: string, files: Map<string, Buffer>, wasmRecord: string }} release
 * @param {(manifest: Record<string, any>) => void} change
 * @param {string} label a file name part, one per case
 * @returns {{ folder: CheckResult, xpi: CheckResult }}
 */
function checkChanged(release, change, label) {
  const manifest = JSON.parse(/** @type {Buffer} */ (release.files.get("manifest.json")).toString("utf8"));
  change(manifest);
  const folder = join(release.dir, "..", `planted-${label}`);
  const files = new Map(release.files);
  files.set("manifest.json", Buffer.from(`${JSON.stringify(manifest, null, 2)}\n`));
  for (const [path, bytes] of files) {
    const file = join(folder, ...path.split("/"));
    mkdirSync(dirname(file), { recursive: true });
    writeFileSync(file, bytes);
  }
  const xpi = join(release.dir, "..", `planted-${label}.xpi`);
  packXpi(folder, xpi);
  // The record of the WASM package that the build wrote beside the release stays beside the planted copies.
  copyFileSync(release.wasmRecord, `${folder}.wasm.json`);
  return { folder: runCheck(folder), xpi: runCheck(xpi) };
}

test("release_check_refuses_manifest_keys_and_permissions_outside_the_release", async () => {
  const env = makeRoot();
  try {
    const options = { root: env.root, webRoot: env.webRoot, out: env.out, wasmTar: env.tarPath };
    /** @type {Record<string, [(m: Record<string, any>) => void, RegExp][]>} */
    const cases = {
      mv3: [
        [(m) => { m.content_scripts = [{ matches: ["https://*/*"], js: ["content/fill.inject.js"] }]; }, /content_scripts is not allowed in a release/],
        [(m) => { m.web_accessible_resources = ["content/fill.inject.js"]; }, /web_accessible_resources is not allowed in a release/],
        [(m) => { m.externally_connectable = { matches: ["https://*/*"] }; }, /externally_connectable is not allowed in a release/],
        [(m) => { m.commands = { run: { suggested_key: { default: "Alt+Shift+F9" } } }; }, /the command run is not a release command/],
        [(m) => { m.commands["ferret-test-command"] = { suggested_key: { default: "Alt+Shift+F9" } }; }, /the command ferret-test-command is not a release command/],
        [(m) => { m.commands = ["fill-login"]; }, /commands is not an object/],
        [(m) => { m.options_ui = { page: "pages/about.html", open_in_tab: true }; }, /options_ui is not the settings page opened in a tab/],
        [(m) => { m.options_ui = { page: "pages/settings.html", open_in_tab: false }; }, /options_ui is not the settings page opened in a tab/],
        [(m) => { m.options_ui = { page: "pages/settings.html", open_in_tab: true, browser_style: true }; }, /options_ui is not the settings page opened in a tab/],
        [(m) => { m.browser_action = { default_title: "x" }; }, /the key browser_action is not in the release key list/],
        [(m) => { m.chrome_url_overrides = { newtab: "pages/about.html" }; }, /the key chrome_url_overrides is not in the release key list/],
        [(m) => { m.permissions.push("tabs"); }, /permissions holds "tabs"/],
        // Allowed for the test variant, not for a release.
        [(m) => { m.optional_permissions = ["menus"]; }, /optional_permissions holds "menus"/],
        [(m) => { m.content_security_policy = undefined; }, /content_security_policy is not the extension CSP \(an object/],
        [(m) => { m.content_security_policy = EXTENSION_CSP; }, /content_security_policy is not the extension CSP \(an object/],
        [(m) => { m.content_security_policy = { extension_pages: `${EXTENSION_CSP}; script-src-elem 'unsafe-inline'` }; }, /content_security_policy is not the extension CSP/],
        [(m) => { m.content_security_policy = { extension_pages: "script-src 'self' 'unsafe-eval'; object-src 'self'" }; }, /content_security_policy is not the extension CSP/],
        [(m) => { m.content_security_policy.sandbox = "sandbox allow-scripts"; }, /content_security_policy is not the extension CSP/],
        [(m) => { m.permissions.push("<all_urls>"); }, /permissions holds "<all_urls>"/],
        [(m) => { m.permissions.push("https://*/*"); }, /permissions holds "https:\/\/\*\/\*"/],
        [(m) => { m.optional_permissions = ["history"]; }, /optional_permissions holds "history"/],
        [(m) => { m.host_permissions = ["https://*/*"]; }, /host_permissions holds "https:\/\/\*\/\*"/],
        [(m) => { m.optional_host_permissions = ["<all_urls>"]; }, /optional_host_permissions holds "<all_urls>"/],
        [(m) => { m.optional_host_permissions = ["http://*/*"]; }, /optional_host_permissions holds "http:\/\/\*\/\*"/],
        [(m) => { m.permissions = "storage"; }, /permissions is not a list of strings/],
        [(m) => { m.manifest_version = 4; }, /manifest_version 4 is not 2 or 3/],
        [(m) => { m.name = `${m.name} (test)`; }, /the name is the test build's/],
        [(m) => { m.browser_specific_settings.gecko.id = "ferret-test@hedgerow.tools"; }, /the add-on id is "ferret-test@hedgerow\.tools"/],
        [(m) => { delete m.browser_specific_settings.gecko.update_url; }, /the update_url is undefined/],
        [(m) => { m.browser_specific_settings.gecko.update_url = "https://example.com/updates.json"; }, /the update_url is "https:\/\/example\.com\/updates\.json"/],
      ],
      mv2: [
        [(m) => { m.content_scripts = []; }, /content_scripts is not allowed in a release/],
        [(m) => { m.web_accessible_resources = []; }, /web_accessible_resources is not allowed in a release/],
        [(m) => { m.externally_connectable = {}; }, /externally_connectable is not allowed in a release/],
        [(m) => { m.action = { default_title: "x" }; }, /the key action is not in the release key list/],
        [(m) => { m.host_permissions = ["https://*/*"]; }, /the key host_permissions is not in the release key list/],
        [(m) => { m.optional_host_permissions = ["https://*/*"]; }, /the key optional_host_permissions is not in the release key list/],
        [(m) => { m.permissions.push("tabs"); }, /permissions holds "tabs"/],
        [(m) => { m.content_security_policy = undefined; }, /content_security_policy is not the extension CSP \(a string\)/],
        [(m) => { m.content_security_policy = { extension_pages: EXTENSION_CSP }; }, /content_security_policy is not the extension CSP \(a string\)/],
        [(m) => { m.content_security_policy = `${EXTENSION_CSP}; script-src-elem 'unsafe-inline'`; }, /content_security_policy is not the extension CSP/],
        [(m) => { m.content_security_policy = "script-src 'self' 'unsafe-eval'; object-src 'self'"; }, /content_security_policy is not the extension CSP/],
        [(m) => { m.permissions.push("<all_urls>"); }, /permissions holds "<all_urls>"/],
        [(m) => { m.optional_permissions = ["http://*/*"]; }, /optional_permissions holds "http:\/\/\*\/\*"/],
        [(m) => { m.name = `${m.name} (test)`; }, /the name is the test build's/],
        [(m) => { m.browser_specific_settings.gecko.id = "ferret-test@hedgerow.tools"; }, /the add-on id is "ferret-test@hedgerow\.tools"/],
        [(m) => { delete m.browser_specific_settings.gecko.update_url; }, /the update_url is undefined/],
        [(m) => { m.browser_specific_settings.gecko.update_url = UPDATE_URL.replace("https:", "http:"); }, /the update_url is "http:\/\//],
      ],
    };
    for (const manifest of ["mv3", "mv2"]) {
      const release = await build({ ...options, manifest, variant: "release" });
      assert.deepEqual(releaseProblems(release.files, HOSTS), [], manifest);
      let n = 0;
      for (const [change, expected] of cases[manifest]) {
        n += 1;
        const result = checkChanged(release, change, `${manifest}-${n}`);
        for (const [kind, run] of Object.entries(result)) {
          assert.notEqual(run.status, 0, `${manifest} case ${n} ${kind}: ${expected}`);
          assert.match(run.output, expected, `${manifest} case ${n} ${kind}`);
        }
      }
    }
  } finally {
    env.cleanup();
  }
});

test("release_check_accepts_the_optional_origin_the_release_list_names", async () => {
  const env = makeRoot();
  try {
    const options = { root: env.root, webRoot: env.webRoot, out: env.out, wasmTar: env.tarPath };
    const v3 = await build({ ...options, manifest: "mv3", variant: "release" });
    const okV3 = checkChanged(v3, (m) => { m.optional_host_permissions = ["https://*/*"]; }, "ok-mv3");
    const v2 = await build({ ...options, manifest: "mv2", variant: "release" });
    const okV2 = checkChanged(v2, (m) => { m.optional_permissions = ["https://*/*"]; }, "ok-mv2");
    for (const run of [okV3.folder, okV3.xpi, okV2.folder, okV2.xpi]) assert.equal(run.status, 0, run.output);
  } finally {
    env.cleanup();
  }
});

test("release_key_list_covers_the_keys_of_both_release_manifests_and_nothing_else", async () => {
  const env = makeRoot();
  try {
    for (const manifest of ["mv3", "mv2"]) {
      const built = Object.keys(buildManifest({ browser: "firefox", manifest, variant: "release", root: env.root }));
      const listed = RELEASE_MANIFEST_KEYS[manifest === "mv3" ? 3 : 2];
      for (const key of built) assert.ok(listed.includes(key), `${manifest}: ${key} is built but not listed`);
      // What is listed and not built is only a permission list, which the allow-list governs entry by entry.
      for (const key of listed) {
        assert.ok(built.includes(key) || /permissions$/.test(key), `${manifest}: ${key} is listed but not built`);
      }
      for (const key of ["content_scripts", "web_accessible_resources", "externally_connectable"]) assert.ok(!listed.includes(key));
    }
  } finally {
    env.cleanup();
  }
});

test("a_release_may_carry_only_the_release_permissions_and_the_test_variant_the_wider_list", async () => {
  // Every permission of the real test list is a release one now, so a list with one more test-only entry stands in.
  const real = readPermissionAllow(undefined, "test");
  for (const permission of ["history"]) {
    const env = makeRoot({
      "manifest/permissions.allow.json": `${JSON.stringify({ ...real, permissions: [...real.permissions, permission].sort() })}\n`,
      "manifest/parts/extra.json": `${JSON.stringify({ permissions: [permission] })}\n`,
    });
    try {
      const options = { root: env.root, webRoot: env.webRoot, out: env.out, wasmTar: env.tarPath };
      for (const manifest of ["mv3", "mv2"]) {
        await assert.rejects(build({ ...options, manifest, variant: "release" }), new RegExp(`permission "${permission}" \\(permissions\\) is not in manifest/permissions\\.allow\\.json`), `${manifest} ${permission}`);
        // The test variant has them in its list.
        await build({ ...options, manifest, variant: "test" });
      }
    } finally {
      env.cleanup();
    }
  }
  // The release list is a subset of the test variant's: a release entry the wider list lacks is a broken file.
  const env = makeRoot({ "manifest/permissions.allow.json": `${JSON.stringify({
    permissions: ["storage"], optional_permissions: [], host_permissions: [], optional_host_permissions: [],
    release: { permissions: ["storage", "tabs"], optional_permissions: [], host_permissions: [], optional_host_permissions: [] },
  })}\n` });
  try {
    assert.throws(() => readPermissionAllow(env.root, "release"), /release\.permissions holds "tabs"/);
    assert.throws(() => readPermissionAllow(env.root, "test"), /release\.permissions holds "tabs"/);
  } finally {
    env.cleanup();
  }
  // The real file: release lists inside the wider ones; every permission of the test variant is a release one now.
  const release = readPermissionAllow(undefined, "release");
  const wider = readPermissionAllow(undefined, "test");
  assert.deepEqual(wider.permissions.filter((p) => !release.permissions.includes(p)), []);
});

test("release_check_fails_closed_without_the_permission_allow_list", async () => {
  const env = makeRoot({ "manifest/permissions.allow.json": null });
  try {
    await assert.rejects(build({ root: env.root, webRoot: env.webRoot, out: env.out, wasmTar: env.tarPath, variant: "release" }), /permissions\.allow\.json/);
  } finally {
    env.cleanup();
  }
});

test("the_release_check_requires_a_release_build_with_save_on", async () => {
  const env = makeRoot();
  try {
    const options = { root: env.root, webRoot: env.webRoot, out: env.out, wasmTar: env.tarPath, manifest: "mv2" };
    // The build refuses a release with the feature off.
    await assert.rejects(build({ ...options, variant: "release", features: [] }), /release: .*shared\/features\.mjs: the feature save is off, which a release must have on/);
    const release = await build({ ...options, variant: "release" });
    assert.equal(runCheck(release.dir).status, 0);
    const file = join(release.dir, ...FEATURES_FILE.split("/"));
    const xpi = join(env.out, "edited.xpi");

    // The module of a build with the feature off, put into a release (the folder and its .xpi): refused.
    writeFileSync(file, featuresModule([], new Map()));
    packXpi(release.dir, xpi);
    for (const target of [release.dir, xpi]) {
      const result = runCheck(target);
      assert.notEqual(result.status, 0, target);
      assert.match(result.output, /shared\/features\.mjs: the feature save is off, which a release must have on/, target);
    }
    // Any other spelling of it off, or a module the build did not write, is refused too.
    for (const text of [
      "export const FEATURES = Object.freeze({ save: false });\n",
      "export const FEATURES = Object.freeze({ 'save': 0 });\n",
      "export const FEATURES = Object.freeze({ save: !1 });\n",
      "export const FEATURES = globalThis.features;\n",
      "",
    ]) {
      writeFileSync(file, text);
      const result = runCheck(release.dir);
      assert.notEqual(result.status, 0, JSON.stringify(text));
      assert.match(result.output, /shared\/features\.mjs: (?:the feature save is off|not the module the build writes for a release)/, JSON.stringify(text));
    }
    // No module at all: refused (a release names the features that are on).
    rmSync(file);
    const missing = runCheck(release.dir);
    assert.notEqual(missing.status, 0);
    assert.match(missing.output, /shared\/features\.mjs is missing/);
    // The module put back as the build writes it: clean again.
    writeFileSync(file, featuresModule(["save"], new Map()));
    assert.equal(runCheck(release.dir).status, 0);

    // The capture script (or one of its sources) missing from a release: refused, whatever the module says.
    for (const path of SAVE_FILES) {
      const target = join(release.dir, ...path.split("/"));
      const bytes = readFileSync(target);
      rmSync(target);
      const without = runCheck(release.dir);
      assert.notEqual(without.status, 0, path);
      assert.match(without.output, new RegExp(`${path.replaceAll(".", "\\.")}: belongs to the save feature, which a release has on, and is missing`), path);
      writeFileSync(target, bytes);
      assert.equal(runCheck(release.dir).status, 0, path);
    }
  } finally {
    env.cleanup();
  }
});

test("a_release_with_save_on_holds_no_test_only_path_of_the_feature", async () => {
  // The test-only offer probes (plant, bench, peek), the write probe and the bridge stay out of a release with the
  // feature on, and no package file imports one (the build's own import check).
  const env = makeRoot();
  try {
    const options = { root: env.root, webRoot: env.webRoot, out: env.out, wasmTar: env.tarPath };
    for (const manifest of ["mv2", "mv3"]) {
      const release = await build({ ...options, out: join(env.out, `r-${manifest}`), manifest, variant: "release" });
      const paths = [...release.files.keys()];
      assert.deepEqual(paths.filter((path) => /(?:^|\/)test-only\/|^test\//.test(path)), [], manifest);
    }
  } finally {
    env.cleanup();
  }
});
