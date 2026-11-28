// The code that the extension shares with the web vault: the list in
// shared.json, the copy the build makes and the checks around it.
import assert from "node:assert/strict";
import { existsSync, mkdirSync, readdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { spawnSync } from "node:child_process";
import { test } from "node:test";
import { build, packXpi, sha256, sharedProblems } from "../../scripts/build.mjs";
import { extensionRoot, makeRoot, repoRoot, WITHOUT_SHARED_IMPORTS } from "./buildHelpers.mjs";
import { reach, readGraph } from "./importGraph.mjs";

const WEB_SRC = join(repoRoot, "web", "src");
const CHECK = join(repoRoot, "scripts", "check-ext-release.sh");

/** The real list. @returns {string[]} */
const realList = () => JSON.parse(readFileSync(join(extensionRoot, "shared.json"), "utf8"));

/**
 * A throwaway build root with the real list and the real web/src.
 * @param {Record<string, string | null>} [extra]
 */
function realRoot(extra = {}) {
  return makeRoot({ "shared.json": readFileSync(join(extensionRoot, "shared.json"), "utf8"), ...extra });
}

/** @param {ReturnType<typeof makeRoot>} env @param {Record<string, unknown>} [options] */
const buildRealIn = (env, options = {}) => build({ root: env.root, webRoot: env.webRoot, out: env.out, wasmTar: env.tarPath, ...options });

/** @param {string} target @returns {{ status: number | null, output: string }} */
function runCheck(target) {
  // The fixture builds sit in <dir>/out next to their web folder <dir>/web, the lock the packages are checked against.
  const result = spawnSync("bash", [CHECK, "--web-root", join(dirname(target), "..", "web"), target], { encoding: "utf8" });
  return { status: result.status, output: `${result.stdout}${result.stderr}` };
}

/** The list as it stands. A change to it is made on purpose, here and in shared.json together. */
const EXPECTED_LIST = [
  "api.mjs",
  "auth/deviceKey.mjs",
  "auth/dpop.mjs",
  "auth/tokens.mjs",
  "b64.mjs",
  "crypto/convert.mjs",
  "crypto/env.mjs",
  "crypto/errors.mjs",
  "crypto/session.mjs",
  "dom.mjs",
  "flows/deviceSecret.mjs",
  "flows/forgetServer.mjs",
  "flows/passkeyAnswer.mjs",
  "flows/prfUnlock.mjs",
  "flows/setupQr.mjs",
  "flows/signin.mjs",
  "i18n.mjs",
  "store/activitySeen.mjs",
  "store/cache.mjs",
  "store/exportReminder.mjs",
  "store/forget.mjs",
  "store/idb.mjs",
  "store/outbox.mjs",
  "store/pinned.mjs",
  "store/restoreNote.mjs",
  "store/settings.mjs",
  "store/syncState.mjs",
  "store/trash.mjs",
  "sync/checkpoint.mjs",
  "sync/conflict.mjs",
  "sync/deviceName.mjs",
  "sync/engine.mjs",
  "sync/errors.mjs",
  "sync/events.mjs",
  "sync/memory.mjs",
  "sync/outbox.mjs",
  "sync/owner.mjs",
  "sync/passkeyKey.mjs",
  "sync/restore.mjs",
  "tabId.mjs",
  "tt.mjs",
  "wire.mjs",
];

test("the_shared_list_is_exactly_the_agreed_one", () => {
  const list = realList();
  assert.deepEqual(list, EXPECTED_LIST);
});

/**
 * The web vault's own account operations, and the PDF, QR and download code under
 * them: the extension never carries them (they stay behind `crypto/vaultSession.mjs`).
 */
const WEB_VAULT_ONLY = [
  "crypto/vaultSession.mjs",
  "download.mjs",
  "flows/changePassword.mjs",
  "flows/emergencySheet.mjs",
  "flows/export.mjs",
  "flows/import.mjs",
  "flows/reauth.mjs",
  "flows/reapplyMethods.mjs",
  "flows/register.mjs",
  "flows/renewRecovery.mjs",
  "flows/showSecretKey.mjs",
  "flows/signedCall.mjs",
  "pdf.mjs",
  "qr.mjs",
];

test("the_shared_list_stays_closed_under_imports", () => {
  // The real import graph of web/src, read from the sign-in modules the extension takes: everything they
  // reach is on the list, and nothing they reach is a web-vault-only module.
  const list = new Set(realList());
  /** @param {string} dir @param {string} prefix @returns {string[]} */
  const walk = (dir, prefix = "") =>
    readdirSync(dir, { withFileTypes: true }).flatMap((entry) =>
      entry.isDirectory() ? walk(join(dir, entry.name), `${prefix}${entry.name}/`) : entry.name.endsWith(".mjs") ? [`${prefix}${entry.name}`] : []);
  const all = new Map(walk(WEB_SRC).map((path) => [path, readFileSync(join(WEB_SRC, ...path.split("/")))]));
  const graph = readGraph(all);
  const roots = ["crypto/session.mjs", "flows/signin.mjs", "auth/deviceKey.mjs", "auth/dpop.mjs", "auth/tokens.mjs"];
  for (const root of roots) assert.ok(list.has(root), `${root} is shared`);
  const reached = reach(graph.edges, roots);
  assert.deepEqual([...reached].filter((path) => !list.has(path)).sort(), [], "every module the sign-in reaches is on the list");
  assert.deepEqual(WEB_VAULT_ONLY.filter((path) => reached.has(path) || list.has(path)), [], "no web-vault-only module");
  // The same holds for the whole list, from every file on it.
  assert.deepEqual([...reach(graph.edges, list)].filter((path) => !list.has(path)).sort(), []);
  // The web vault still reaches the shared session and sign-in, and its own operations, through its own session.
  const vault = reach(graph.edges, ["crypto/vaultSession.mjs"]);
  for (const path of ["crypto/session.mjs", "flows/signin.mjs", ...WEB_VAULT_ONLY]) {
    assert.ok(vault.has(path), `the web vault's session reaches ${path}`);
  }
});

test("every_shared_file_is_byte_equal_to_its_source_in_web", async () => {
  const list = realList();
  assert.ok(list.length > 0, "the list is not empty");
  assert.deepEqual(list, [...list].sort(), "the list is sorted");
  const env = realRoot();
  try {
    for (const variant of ["release", "test"]) {
      const result = await buildRealIn(env, { variant });
      /** @type {Record<string, string>} */
      const expected = {};
      for (const path of list) {
        const source = readFileSync(join(WEB_SRC, ...path.split("/")));
        // The package holds the very bytes of web/src, in the folder and in the map the build keeps.
        assert.deepEqual(readFileSync(join(result.dir, "shared", ...path.split("/"))), source, `${variant}: ${path}`);
        assert.deepEqual(result.files.get(`shared/${path}`), source, `${variant}: ${path} (map)`);
        expected[path] = sha256(source);
      }
      assert.deepEqual(JSON.parse(readFileSync(join(result.dir, "shared", "MANIFEST.json"), "utf8")), expected);
      assert.deepEqual(sharedProblems(result.files), []);
    }
  } finally {
    env.cleanup();
  }
});

test("the_shared_flow_is_the_same_file_in_the_extension", async () => {
  // The passkey unlock flow is written once, in web/src, and the extension carries that very file (and the answer checks
  // it uses): any edit of a copy is caught by the hashes, as for every shared file.
  const flow = ["flows/prfUnlock.mjs", "flows/passkeyAnswer.mjs"];
  const env = realRoot();
  try {
    for (const variant of ["release", "test"]) {
      const result = await buildRealIn(env, { variant });
      const manifest = JSON.parse(readFileSync(join(result.dir, "shared", "MANIFEST.json"), "utf8"));
      for (const path of flow) {
        const source = readFileSync(join(WEB_SRC, ...path.split("/")));
        assert.deepEqual(readFileSync(join(result.dir, "shared", ...path.split("/"))), source, `${variant}: ${path} is the web vault's file`);
        assert.equal(manifest[path], sha256(source), `${variant}: ${path} has its hash in the manifest`);
      }
    }
  } finally {
    env.cleanup();
  }
  // It is on the list, and it reaches nothing that is not.
  const list = new Set(realList());
  for (const path of flow) assert.ok(list.has(path), path);
  const files = new Map([...list].map((path) => [path, readFileSync(join(WEB_SRC, ...path.split("/")))]));
  const edges = readGraph(files).edges.get("flows/prfUnlock.mjs") ?? [];
  assert.ok(edges.length > 0);
  for (const { specifier, target } of edges) assert.ok(target !== null && list.has(target), `${specifier} is shared`);
});

test("a_shared_file_edited_in_dist_fails_the_build", async () => {
  const env = realRoot();
  try {
    const release = await buildRealIn(env, { variant: "release" });
    assert.equal(runCheck(release.dir).status, 0, "the unedited release is clean");

    // An edit of a copy in the package (folder or .xpi) is named by the release check.
    for (const path of ["dom.mjs", "crypto/convert.mjs", "sync/engine.mjs"]) {
      const file = join(release.dir, "shared", ...path.split("/"));
      const original = readFileSync(file);
      writeFileSync(file, `${original.toString("utf8")}\n// edited\n`);
      const folder = runCheck(release.dir);
      assert.notEqual(folder.status, 0, path);
      assert.match(folder.output, new RegExp(`shared/${path.replace(/[./]/g, "\\$&")}: differs from its hash`), path);
      const xpi = join(env.dir, "edited.xpi");
      packXpi(release.dir, xpi);
      const packed = runCheck(xpi);
      assert.notEqual(packed.status, 0, `${path} (.xpi)`);
      assert.match(packed.output, /differs from its hash/, `${path} (.xpi)`);
      writeFileSync(file, original);
    }
    assert.equal(runCheck(release.dir).status, 0, "restored, the release is clean again");

    // A copy edited together with its entry in MANIFEST.json passes the check against the MANIFEST
    // alone, but not the check against the sources in web/src (what the release check runs).
    {
      const path = "b64.mjs";
      const file = join(release.dir, "shared", path);
      const manifestFile = join(release.dir, "shared", "MANIFEST.json");
      const originalFile = readFileSync(file);
      const originalManifest = readFileSync(manifestFile);
      const edited = Buffer.from(`${originalFile.toString("utf8")}
// edited
`);
      /** @type {Record<string, string>} */
      const hashes = JSON.parse(originalManifest.toString("utf8"));
      hashes[path] = sha256(edited);
      writeFileSync(file, edited);
      writeFileSync(manifestFile, `${JSON.stringify(hashes, null, 2)}
`);
      const files = new Map(release.files);
      files.set(`shared/${path}`, edited);
      files.set("shared/MANIFEST.json", Buffer.from(`${JSON.stringify(hashes, null, 2)}
`));
      assert.deepEqual(sharedProblems(files), [], "the MANIFEST alone cannot see it");
      assert.deepEqual(sharedProblems(files, join(repoRoot, "web")), [`shared/${path}: differs from its source in web/src`]);
      const checked = runCheck(release.dir);
      assert.notEqual(checked.status, 0, "the release check compares with web/src");
      assert.match(checked.output, /shared\/b64\.mjs: differs from its source in web\/src/);
      const xpi = join(env.dir, "edited-both.xpi");
      packXpi(release.dir, xpi);
      assert.notEqual(runCheck(xpi).status, 0, "the .xpi too");
      writeFileSync(file, originalFile);
      writeFileSync(manifestFile, originalManifest);
    }
    assert.equal(runCheck(release.dir).status, 0, "restored again, the release is clean");

    // A copy that is missing is named too, and a build from the map refuses an edited copy.
    const files = new Map(release.files);
    files.delete("shared/b64.mjs");
    assert.deepEqual(sharedProblems(files), ["shared/b64.mjs: is in shared/MANIFEST.json but not in the package"]);
    files.set("shared/b64.mjs", Buffer.from("export {};\n"));
    assert.match(sharedProblems(files)[0], /^shared\/b64\.mjs: differs from its hash/);
    files.set("shared/MANIFEST.json", Buffer.from("[1]"));
    assert.deepEqual(sharedProblems(files), ["shared/MANIFEST.json: expected an object of path -> SHA-256"]);
    files.set("shared/MANIFEST.json", Buffer.from("{"));
    assert.deepEqual(sharedProblems(files), ["shared/MANIFEST.json: not valid JSON"]);
  } finally {
    env.cleanup();
  }
});

test("shared_imports_resolve_inside_the_list", async () => {
  // The real import graph of the real sources, with their dynamic import() too.
  const list = new Set(realList());
  const files = new Map([...list].map((path) => [path, readFileSync(join(WEB_SRC, ...path.split("/")))]));
  const graph = readGraph(files);
  assert.deepEqual(graph.hidden, [], "no import() that names no literal");
  /** @type {string[]} */
  const problems = [];
  for (const [path, edges] of graph.edges) {
    for (const { specifier, target } of edges) {
      if (target === null) problems.push(`${path} imports "${specifier}", which is not a relative path`);
      else if (!list.has(target)) problems.push(`${path} imports ${target}, which is not in the list`);
    }
  }
  assert.deepEqual(problems, []);

  // A file that the list lacks fails the build with the name of both files: a static
  // import, a re-export and a dynamic import(), in a folder and above it.
  /** @type {Array<[string, string, string]>} */
  const cases = [
    ["a static import", 'import { x } from "./b.mjs";\nexport const a = x;\n', "a.mjs imports b.mjs, which is not in the list"],
    ["a re-export", 'export * from "./b.mjs";\n', "a.mjs imports b.mjs, which is not in the list"],
    ["a dynamic import", 'export const load = () => import("./b.mjs");\n', "a.mjs imports b.mjs, which is not in the list"],
    ["a file above the folder", 'import "../b.mjs";\n', "d/a.mjs imports b.mjs, which is not in the list"],
    ["a computed import()", "export const load = (p) => import(p);\n", "has an import() that names no string literal"],
    ["a bare specifier", 'import "left-pad";\n', 'imports "left-pad", which is not a relative path'],
  ];
  for (const [label, source, message] of cases) {
    const name = label === "a file above the folder" ? "d/a.mjs" : "a.mjs";
    const env = makeRoot({ "shared.json": `["${name}"]\n`, ...WITHOUT_SHARED_IMPORTS });
    try {
      mkdirSync(join(env.webRoot, "src", dirname(name)), { recursive: true });
      writeFileSync(join(env.webRoot, "src", ...name.split("/")), source);
      writeFileSync(join(env.webRoot, "src", "b.mjs"), "export const x = 1;\n");
      await assert.rejects(buildRealIn(env), (error) => {
        assert.ok(error instanceof Error);
        assert.ok(error.message.includes(message), `${label}: ${error.message}`);
        return true;
      }, label);
      // With the target on the list the same build succeeds.
      writeFileSync(join(env.root, "shared.json"), `["${name}", "b.mjs"]\n`);
      if (label !== "a computed import()" && label !== "a bare specifier") {
        const result = await buildRealIn(env);
        assert.ok(result.files.has("shared/b.mjs"), label);
      }
    } finally {
      env.cleanup();
    }
  }
});

test("a_shared_file_that_a_page_imports_has_a_type_stub", () => {
  // The type check finds "../shared/<name>.mjs" (a file that exists only in the package)
  // through extension/types/shared/<name>.d.mts, so each shared file that the sources import needs one.
  const list = new Set(realList());
  /** @param {string} dir @returns {string[]} */
  const walkSources = (dir) =>
    readdirSync(dir, { withFileTypes: true }).flatMap((entry) => (entry.isDirectory() ? walkSources(join(dir, entry.name)) : entry.name.endsWith(".mjs") ? [join(dir, entry.name)] : []));
  const missing = [];
  for (const file of walkSources(join(extensionRoot, "src"))) {
    for (const match of readFileSync(file, "utf8").matchAll(/(?:from|import\()\s*["'](?:\.\.?\/)+shared\/([^"']+\.mjs)["']/g)) {
      const shared = match[1];
      if (list.has(shared) && !existsSync(join(extensionRoot, "types", "shared", `${shared.slice(0, -4)}.d.mts`))) missing.push(`${file}: types/shared/${shared.slice(0, -4)}.d.mts`);
    }
  }
  assert.deepEqual(missing, []);
});

test("the_shared_list_names_no_view_route_or_service_file", async () => {
  for (const path of realList()) {
    assert.doesNotMatch(path, /(?:^|\/)(?:views|routes|services)\//, path);
    assert.doesNotMatch(path, /\.(?:route|service)\.mjs$/, path);
  }
  // Nothing on the list may reach a view, route or service file either: the closure above
  // is inside the list, so it holds none. The build refuses such a name outright.
  for (const bad of ["views/shell.mjs", "routes/home.route.mjs", "services/sync.service.mjs", "sync/x.service.mjs", "a/b.route.mjs", "sync/views/x.mjs", "a/routes/b.mjs", "store/services/c.mjs"]) {
    const env = makeRoot({ "shared.json": `["${bad}"]\n` });
    try {
      await assert.rejects(buildRealIn(env), /is a view, route or service file/, bad);
    } finally {
      env.cleanup();
    }
  }
  // A list that names a file twice is refused too.
  const env = makeRoot({ "shared.json": '["a.mjs", "a.mjs"]\n' });
  try {
    await assert.rejects(buildRealIn(env), /listed twice/);
  } finally {
    env.cleanup();
  }
});
