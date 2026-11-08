import assert from "node:assert/strict";
import { readFileSync, readdirSync } from "node:fs";
import { join } from "node:path";
import { test } from "node:test";
import { pathToFileURL } from "node:url";
import { buildManifest, EXTENSION_CSP } from "../../scripts/build.mjs";
import { extensionRoot, makeRoot, repoRoot } from "./buildHelpers.mjs";

const VARIANTS = ["release", "test"];
const MANIFESTS = ["mv3", "mv2"];

/** @param {string} manifest @param {string} variant @param {string} [root] */
const manifestOf = (manifest, variant, root) => buildManifest({ browser: "firefox", manifest, variant, root });

/** @param {string} file @returns {any} */
const readJson = (file) => JSON.parse(readFileSync(file, "utf8"));

/** @param {string[]} a @param {string[]} b */
const sortedUnion = (a = [], b = []) => [...a, ...b].sort();

/**
 * The five differences between the MV3 and the MV2 manifest, checked one by one
 * and then removed. Everything left must be equal.
 * @param {Record<string, any>} m3
 * @param {Record<string, any>} m2
 */
function assertOnlyTheKnownDifferences(m3, m2) {
  const a = structuredClone(m3);
  const b = structuredClone(m2);
  // 1. manifest_version
  assert.equal(a.manifest_version, 3);
  assert.equal(b.manifest_version, 2);
  delete a.manifest_version;
  delete b.manifest_version;
  // 2. action / browser_action, same content
  assert.deepEqual(a.action, b.browser_action);
  assert.equal(a.browser_action, undefined);
  assert.equal(b.action, undefined);
  delete a.action;
  delete b.browser_action;
  // 3. content_security_policy: an object with extension_pages / the same string
  assert.deepEqual(Object.keys(a.content_security_policy), ["extension_pages"]);
  assert.equal(typeof b.content_security_policy, "string");
  assert.equal(a.content_security_policy.extension_pages, b.content_security_policy);
  delete a.content_security_policy;
  delete b.content_security_policy;
  // 4. background: scripts + type / page + persistent
  assert.deepEqual(Object.keys(a.background).sort(), ["scripts", "type"]);
  assert.equal(a.background.type, "module");
  assert.deepEqual(Object.keys(b.background).sort(), ["page", "persistent"]);
  assert.equal(b.background.persistent, true);
  delete a.background;
  delete b.background;
  // 5. host permissions: separate lists / folded into the plain lists
  assert.deepEqual(b.permissions ?? [], sortedUnion(a.permissions, a.host_permissions));
  assert.deepEqual(b.optional_permissions ?? [], sortedUnion(a.optional_permissions, a.optional_host_permissions));
  assert.equal(b.host_permissions, undefined);
  assert.equal(b.optional_host_permissions, undefined);
  for (const key of ["permissions", "optional_permissions", "host_permissions", "optional_host_permissions"]) {
    delete a[key];
    delete b[key];
  }
  assert.deepEqual(a, b);
}

test("manifest_mv3_and_mv2_differ_only_in_the_allowed_keys", () => {
  for (const variant of VARIANTS) {
    assertOnlyTheKnownDifferences(manifestOf("mv3", variant), manifestOf("mv2", variant));
  }

  // The same with host permissions in play: they move into the plain lists in MV2.
  const env = makeRoot({ "manifest/parts/hosts.json": '{ "optional_host_permissions": ["https://*/*"] }\n' });
  try {
    const m3 = manifestOf("mv3", "release", env.root);
    const m2 = manifestOf("mv2", "release", env.root);
    assert.deepEqual(m3.optional_host_permissions, ["https://*/*"]);
    assert.deepEqual(m2.optional_permissions, ["https://*/*"]);
    assertOnlyTheKnownDifferences(m3, m2);
  } finally {
    env.cleanup();
  }

  // The MV2 page loads the same script as the MV3 background.
  const page = readFileSync(join(extensionRoot, "src", "background", "background.html"), "utf8");
  const sources = [...page.matchAll(/<script\b[^>]*\ssrc="([^"]+)"/g)].map((m) => `background/${m[1]}`);
  assert.deepEqual(sources, manifestOf("mv3", "release").background.scripts);
});

test("manifest_permissions_are_a_subset_of_the_allow_list_and_every_part_permission_is_listed", () => {
  const allow = readJson(join(extensionRoot, "manifest", "permissions.allow.json"));
  const m3 = manifestOf("mv3", "release");
  for (const key of Object.keys(allow)) {
    for (const entry of m3[key] ?? []) assert.ok(allow[key].includes(entry), `mv3 ${key}: ${entry}`);
  }
  const m2 = manifestOf("mv2", "release");
  for (const entry of m2.permissions ?? []) assert.ok([...allow.permissions, ...allow.host_permissions].includes(entry), `mv2 permissions: ${entry}`);
  for (const entry of m2.optional_permissions ?? []) assert.ok([...allow.optional_permissions, ...allow.optional_host_permissions].includes(entry), `mv2 optional_permissions: ${entry}`);
  const partsDir = join(extensionRoot, "manifest", "parts");
  for (const name of readdirSync(partsDir)) {
    const part = readJson(join(partsDir, name));
    for (const key of Object.keys(allow)) {
      for (const entry of part[key] ?? []) assert.ok(allow[key].includes(entry), `${name} ${key}: ${entry}`);
    }
  }
  // storage is declared by the core part.
  assert.deepEqual(readJson(join(partsDir, "core.json")).permissions, ["storage"]);

  // An extra permission in a part file stops the build and names the permission.
  /** @param {Record<string, unknown>} part */
  const withPart = (part) => makeRoot({ "manifest/parts/extra.json": `${JSON.stringify(part)}\n` });
  for (const [part, pattern] of /** @type {[Record<string, unknown>, RegExp][]} */ ([
    [{ permissions: ["tabs"] }, /permission "tabs" \(permissions\) is not in manifest\/permissions\.allow\.json/],
    [{ permissions: ["cookies", "webRequest"] }, /"cookies"/],
    [{ optional_permissions: ["history"] }, /"history"/],
    [{ host_permissions: ["https://*/*"] }, /"https:\/\/\*\/\*" \(host_permissions\)/],
    [{ optional_host_permissions: ["<all_urls>"] }, /"<all_urls>"/],
    [{ optional_host_permissions: ["http://*/*"] }, /"http:\/\/\*\/\*"/],
    [{ permissions: ["https://example.com/*"] }, /does not belong in permissions/],
    [{ host_permissions: ["storage"] }, /does not belong in host_permissions/],
  ])) {
    const env = withPart(part);
    try {
      for (const manifest of MANIFESTS) {
        assert.throws(() => manifestOf(manifest, "release", env.root), pattern, JSON.stringify(part));
      }
    } finally {
      env.cleanup();
    }
  }
});

test("manifest_has_no_content_scripts_no_web_accessible_resources_and_no_externally_connectable", () => {
  for (const manifest of MANIFESTS) {
    for (const variant of VARIANTS) {
      const m = manifestOf(manifest, variant);
      for (const key of ["content_scripts", "web_accessible_resources", "externally_connectable", "devtools_page", "chrome_url_overrides", "sidebar_action", "declarative_net_request"]) {
        assert.equal(key in m, false, `${manifest} ${variant}: ${key}`);
      }
      // No origin without a prompt either: host access is optional only.
      assert.equal(m.host_permissions, undefined);
      assert.ok(!(m.permissions ?? []).some((/** @type {string} */ p) => p.includes("://") || p === "<all_urls>"));
    }
  }
  // A part file cannot add them.
  for (const key of ["content_scripts", "web_accessible_resources", "externally_connectable"]) {
    const env = makeRoot({ "manifest/parts/extra.json": `${JSON.stringify({ [key]: key === "content_scripts" ? [] : { matches: [] } })}\n` });
    try {
      assert.throws(() => manifestOf("mv3", "release", env.root), new RegExp(`${key} is not allowed`), key);
    } finally {
      env.cleanup();
    }
  }
});

test("manifest_declares_data_collection_permissions_and_strict_min_version_153", () => {
  for (const manifest of MANIFESTS) {
    for (const variant of VARIANTS) {
      const m = manifestOf(manifest, variant);
      // The extension sends sign-in credentials and proofs to a server outside the
      // browser (the user's own), which counts as authentication information.
      assert.deepEqual(m.browser_specific_settings, {
        gecko: {
          // The test variant has an id of its own, so it never shares storage with a release.
          id: variant === "test" ? "ferret-test@hedgerow.tools" : "ferret@hedgerow.tools",
          strict_min_version: "153.0",
          data_collection_permissions: { required: ["authenticationInfo"] },
        },
      });
      assert.equal(m.version, readJson(join(extensionRoot, "package.json")).version);
      assert.equal(m.name, variant === "test" ? "Faithful Ferret (test)" : "Faithful Ferret");
    }
  }
});

test("extension_csp_is_the_one_in_the_spec", () => {
  const spec = readFileSync(join(repoRoot, "docs", "design", "phase-1-security-design.md"), "utf8");
  assert.ok(spec.includes(`CSP for extension pages: \`${EXTENSION_CSP}\``), "the constant is the spec's text");
  assert.equal(EXTENSION_CSP, "script-src 'self' 'wasm-unsafe-eval'; object-src 'self'; base-uri 'none'; frame-ancestors 'none'");
  for (const variant of VARIANTS) {
    assert.deepEqual(manifestOf("mv3", variant).content_security_policy, { extension_pages: EXTENSION_CSP });
    assert.equal(manifestOf("mv2", variant).content_security_policy, EXTENSION_CSP);
  }
  // A weaker policy stops the build.
  for (const [manifest, weaker] of /** @type {[string, unknown][]} */ ([
    ["mv3", { extension_pages: `${EXTENSION_CSP.replace("script-src 'self'", "script-src 'self' 'unsafe-eval'")}` }],
    ["mv3", { extension_pages: EXTENSION_CSP, sandbox: "sandbox allow-scripts" }],
    ["mv2", EXTENSION_CSP.replace("; frame-ancestors 'none'", "")],
  ])) {
    const overlay = { ...readJson(join(extensionRoot, "manifest", `firefox-${manifest}.json`)), content_security_policy: weaker };
    const env = makeRoot({ [`manifest/firefox-${manifest}.json`]: `${JSON.stringify(overlay)}\n` });
    try {
      assert.throws(() => manifestOf(manifest, "release", env.root), /content_security_policy/, JSON.stringify(weaker));
    } finally {
      env.cleanup();
    }
  }
});

test("manifest_files_that_set_the_same_key_are_refused", () => {
  const env = makeRoot({ "manifest/parts/extra.json": '{ "name": "Other" }\n' });
  try {
    assert.throws(() => manifestOf("mv3", "release", env.root), /name is set in two manifest files/);
  } finally {
    env.cleanup();
  }
  assert.throws(() => buildManifest({ browser: "chrome", manifest: "mv3", variant: "release" }), /not supported/);
  assert.throws(() => buildManifest({ browser: "firefox", manifest: "mv4", variant: "release" }), /not mv3 or mv2/);
  assert.throws(() => buildManifest({ browser: "firefox", manifest: "mv3", variant: "beta" }), /not release or test/);
});

/**
 * Loads background/compat.mjs against a fake `browser`. The module runs once per
 * URL, so each load gets its own query string.
 * @param {object} fake
 * @param {string} tag
 */
async function loadCompat(fake, tag) {
  const globals = /** @type {any} */ (globalThis);
  globals.browser = fake;
  try {
    const file = join(extensionRoot, "src", "background", "compat.mjs");
    return await import(`${pathToFileURL(file).href}?${tag}`);
  } finally {
    delete globals.browser;
  }
}

/** @returns {Record<string, () => void>} */
function makeAction() {
  return { setPopup() {}, getPopup() {}, openPopup() {}, setTitle() {}, setBadgeText() {}, onClicked: /** @type {any} */ ({}) };
}

test("compat_action_is_the_same_object_shape_in_both_variants", async () => {
  const mv3Action = makeAction();
  const mv2Action = makeAction();
  const mv3 = await loadCompat({
    runtime: { getManifest: () => ({ manifest_version: 3 }) },
    action: mv3Action,
    browserAction: { decoy: true },
  }, "mv3");
  const mv2 = await loadCompat({
    runtime: { getManifest: () => ({ manifest_version: 2 }) },
    browserAction: mv2Action,
    action: { decoy: true },
  }, "mv2");
  assert.equal(mv3.action, mv3Action);
  assert.equal(mv2.action, mv2Action);
  assert.deepEqual(Object.keys(mv3.action).sort(), Object.keys(mv2.action).sort());
  for (const name of ["setPopup", "openPopup"]) {
    assert.equal(typeof mv3.action[name], "function");
    assert.equal(typeof mv2.action[name], "function");
  }
  // No action API for the manifest version: the module refuses to load.
  await assert.rejects(loadCompat({ runtime: { getManifest: () => ({ manifest_version: 3 }) } }, "none"), /no action API for manifest version 3/);
  await assert.rejects(loadCompat({ runtime: { getManifest: () => ({ manifest_version: 2 }) }, action: makeAction() }, "none2"), /no action API for manifest version 2/);
});
