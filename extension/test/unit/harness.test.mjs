// The pieces of the Firefox harness that need no Firefox: the profile text, the
// fixture server, and what the test variant adds to the build (and a release
// must not have).
import assert from "node:assert/strict";
import { get } from "node:https";
import { test } from "node:test";
import { build, buildManifest, readInternalHosts, releaseProblems, TEST_ID } from "../../scripts/build.mjs";
import { startFixtures } from "../firefox/fixtures-server.mjs";
import { FIXED_UUID, policiesJson, profilePrefs, TEST_ADDON_ID, userJs } from "../firefox/profile.mjs";
import { extensionRoot, makeRoot } from "./buildHelpers.mjs";

test("test_profile_prefs_and_policies_are_what_the_harness_needs", () => {
  assert.equal(TEST_ADDON_ID, TEST_ID);
  const prefs = profilePrefs({ hosts: ["a.test", "b.test"] });
  assert.equal(prefs["xpinstall.signatures.required"], false);
  assert.deepEqual(JSON.parse(String(prefs["extensions.webextensions.uuids"])), { [TEST_ID]: FIXED_UUID });
  assert.equal(prefs["extensions.webextOptionalPermissionPrompts"], false);
  assert.equal(prefs["network.dns.localDomains"], "a.test,b.test");
  assert.equal(profilePrefs({ extra: { "x.y": 3 } })["x.y"], 3);

  const text = userJs({ a: true, "b.c": 'x"y', d: 4 });
  assert.equal(text, 'user_pref("a", true);\nuser_pref("b.c", "x\\"y");\nuser_pref("d", 4);\n');
  assert.throws(() => userJs({ a: /** @type {any} */ ({}) }), /not a string, number or boolean/);

  const policies = JSON.parse(policiesJson(["/tmp/a.pem", "/tmp/b.pem"]));
  assert.deepEqual(policies.policies.Certificates.Install, ["/tmp/a.pem", "/tmp/b.pem"]);
  assert.equal(policies.policies.DisableAppUpdate, true);
  assert.throws(() => policiesJson(["relative.pem"]), /absolute/);
});

test("the_test_variant_has_the_bridge_and_a_test_command_and_a_release_has_neither", async () => {
  const env = makeRoot();
  try {
    const options = { root: extensionRoot, webRoot: env.webRoot, out: env.out, wasmTar: env.tarPath };
    for (const manifest of ["mv3", "mv2"]) {
      const test = await build({ ...options, manifest, variant: "test" });
      const release = await build({ ...options, manifest, variant: "release" });
      for (const path of ["test/bridge.html", "test/bridge.mjs"]) {
        assert.ok(test.files.has(path), `${manifest}: ${path} in the test build`);
        assert.equal(release.files.has(path), false, `${manifest}: ${path} not in the release`);
      }
      assert.deepEqual(releaseProblems(release.files, readInternalHosts(extensionRoot)), []);
      const tm = buildManifest({ browser: "firefox", manifest, variant: "test" });
      const rm = buildManifest({ browser: "firefox", manifest, variant: "release" });
      assert.deepEqual(tm.commands["ferret-test-command"].suggested_key, { default: "Alt+Shift+F9" });
      assert.ok(tm.permissions.includes("activeTab") && tm.permissions.includes("menus"));
      assert.equal("commands" in rm, false);
      assert.equal(rm.permissions.includes("menus"), false);
      assert.equal(rm.permissions.includes("activeTab"), false);
      // No host permission of any kind in the test variant either.
      assert.deepEqual((tm.permissions ?? []).filter((/** @type {string} */ p) => p.includes("://") || p === "<all_urls>"), []);
      assert.equal("host_permissions" in tm, false);
    }
  } finally {
    env.cleanup();
  }
});

test("fixture_server_serves_https_with_its_own_ca_for_the_listed_hosts", async () => {
  const server = await startFixtures({ hosts: ["one.test", "two.test"], port: 0, sseIntervalMs: 50 });
  /**
   * @param {string} host
   * @param {string} path
   * @param {{ ca?: string, servername?: string }} [tls]
   * @returns {Promise<{ status: number | undefined, type: string | undefined, body: string }>}
   */
  const fetchText = (host, path, tls = {}) => new Promise((resolve, reject) => {
    let body = "";
    let settled = false;
    const finish = (/** @type {{ status: number | undefined, type: string | undefined, body: string }} */ value) => {
      if (!settled) {
        settled = true;
        resolve(value);
      }
    };
    const request = get({
      host: "127.0.0.1", port: server.port, path, headers: { host: `${host}:${server.port}` },
      servername: tls.servername ?? host, ca: tls.ca ?? server.caPem,
    }, (response) => {
      response.setEncoding("utf8");
      response.on("data", (chunk) => {
        body += chunk;
        if (path === "/sse" && body.includes("event: tick")) {
          finish({ status: response.statusCode, type: response.headers["content-type"], body });
          request.destroy();
        }
      });
      response.on("close", () => finish({ status: response.statusCode, type: response.headers["content-type"], body }));
    });
    request.on("error", (error) => {
      if (settled) return;
      settled = true;
      reject(error);
    });
  });
  try {
    assert.equal(server.url("one.test", "/x"), `https://one.test:${server.port}/x`);
    const login = await fetchText("one.test", "/static/login.html");
    assert.equal(login.status, 200);
    assert.match(login.body, /<input id="password" name="password" type="password"/);
    assert.equal((await fetchText("two.test", "/healthz")).body, "ok\n");
    assert.equal((await fetchText("one.test", "/nope")).status, 404);
    assert.equal((await fetchText("other.test", "/healthz", { servername: "one.test" })).status, 421, "a host that is not listed");
    const events = await fetchText("one.test", "/sse");
    assert.equal(events.type, "text/event-stream");
    assert.match(events.body, /event: tick\ndata: 1\n/);
    // The CA is the only thing that vouches for the certificate.
    await assert.rejects(fetchText("one.test", "/healthz", { ca: "" }), /self-signed|unable to verify|certificate/i);
  } finally {
    await server.close();
  }
});
