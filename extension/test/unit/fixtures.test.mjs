// The adversarial test sites (test/fixtures/sites) without a browser: the host
// list, the page table, what each page renders, and the fixture server's three
// listeners. The Firefox spec (test/firefox/fixtures.spec.mjs) proves the same
// sites in a real browser.
import assert from "node:assert/strict";
import { request as httpRequest } from "node:http";
import { request as httpsRequest } from "node:https";
import { test } from "node:test";
import { domainToASCII } from "node:url";
import { build, readInternalHosts, releaseProblems } from "../../scripts/build.mjs";
import { readHosts, startFixtures } from "../firefox/fixtures-server.mjs";
import {
  HOMOGRAPH_A_LABEL_HOST, HOMOGRAPH_UNICODE_HOST, ORIGIN_HOSTS, ORIGINS, originText, SITES, siteById,
} from "../fixtures/sites/index.mjs";
import { extensionRoot, makeRoot } from "./buildHelpers.mjs";

const PORTS = { https: 443, alt: 8443, http: 80 };
const context = { url: (/** @type {string} */ origin, path = "/") => `${originText(origin, PORTS)}${path}` };

test("every_site_host_is_in_hosts_json_and_nothing_else_is", () => {
  const listed = readHosts().fixture;
  for (const host of ORIGIN_HOSTS) assert.ok(listed.includes(host), `${host} is in hosts.json`);
  const extra = listed.filter((host) => !ORIGIN_HOSTS.includes(host));
  assert.deepEqual(extra, ["fixture.test", "second.fixture.test"], "hosts.json holds only the harness hosts besides the sites'");
  for (const host of listed) assert.equal(host, host.toLowerCase());
});

test("the_homograph_host_is_a_cyrillic_o_and_its_a_label_is_the_standard_one", () => {
  assert.equal(HOMOGRAPH_UNICODE_HOST.codePointAt(1), 0x043e, "the second character is a Cyrillic small o");
  assert.notEqual(HOMOGRAPH_UNICODE_HOST, "login.example.test");
  assert.equal(domainToASCII(HOMOGRAPH_UNICODE_HOST), HOMOGRAPH_A_LABEL_HOST);
  assert.equal(ORIGINS.homograph.host, HOMOGRAPH_A_LABEL_HOST);
});

test("the_site_table_covers_every_case_and_is_well_formed", () => {
  const ids = SITES.map((s) => s.id);
  assert.equal(new Set(ids).size, ids.length, "ids are unique");
  const routes = SITES.map((s) => `${ORIGINS[s.origin].listener} ${ORIGINS[s.origin].host} ${s.path}`);
  assert.equal(new Set(routes).size, routes.length, "no two sites share a route");

  const required = [
    "login", "framed-same-site", "framed-foreign", "http-downgrade", "other-port",
    "lookalike-dash", "lookalike-suffix", "lookalike-homograph", "github-a", "github-b",
    "frames-opaque", "overlay", "opacity-html", "offscreen", "hidden-fields", "css-shadow",
    "navigate-frame", "ferret-lookalike",
    ...["opacity", "filter", "transform", "clip-path", "mask", "mix-blend-mode"].flatMap((p) => [`css-${p}`, `css-${p}-subtle`]),
  ];
  for (const id of required) assert.ok(ids.includes(id), `a site named ${id}`);

  for (const site of SITES) {
    assert.ok(ORIGINS[site.origin], `${site.id}: a known origin`);
    assert.ok(site.path.startsWith("/"), `${site.id}: path`);
    assert.ok(site.summary.length > 20, `${site.id}: summary`);
    assert.ok(site.expect.outcome, `${site.id}: outcome`);
    const html = site.render(context);
    assert.ok(html.startsWith("<!doctype html>"), `${site.id}: a whole page`);
    assert.ok(html.includes(`data-fixture-site="${site.id}"`), `${site.id}: marked with its id`);
    assert.ok(!html.includes("undefined"), `${site.id}: nothing left undefined`);
    // A test-site page never needs the network beyond its own listed hosts.
    for (const [, host] of html.matchAll(/https?:\/\/([a-z0-9.-]+)/g)) {
      assert.ok(ORIGIN_HOSTS.includes(host), `${site.id}: ${host} is a fixture host`);
    }
    for (const [, value] of html.matchAll(/data-fixture-expect="([^"]*)"/g)) assert.ok(value === "fill" || value === "reject", `${site.id}: expectation ${value}`);
  }
});

test("the_sites_say_what_the_brief_says_about_origins", () => {
  assert.equal(ORIGINS.login.scheme, "https");
  assert.equal(ORIGINS.loginHttp.scheme, "http");
  assert.equal(ORIGINS.loginHttp.host, ORIGINS.login.host);
  assert.equal(ORIGINS.loginAlt.host, ORIGINS.login.host);
  assert.notEqual(ORIGINS.loginAlt.listener, ORIGINS.login.listener);
  assert.equal(originText("login", PORTS), "https://login.example.test");
  assert.equal(originText("loginAlt", PORTS), "https://login.example.test:8443");
  assert.equal(originText("loginHttp", PORTS), "http://login.example.test");
  assert.equal(ORIGINS.dash.host, "login-example.test");
  assert.equal(ORIGINS.suffix.host, "login.example.test.evil.test");
  assert.equal(ORIGINS.ghA.host, "a.github.io");
  assert.equal(ORIGINS.ghB.host, "b.github.io");
  assert.equal(ORIGINS.www.host.split(".").slice(1).join("."), ORIGINS.login.host.split(".").slice(1).join("."), "www and login share a registrable domain");
  assert.ok(!ORIGINS.evil.host.endsWith("example.test"), "evil is a foreign site");

  assert.ok(siteById("framed-same-site").render(context).includes('src="https://login.example.test/"'));
  assert.ok(siteById("framed-foreign").render(context).includes('src="https://evil.test/login"'));
  const frames = siteById("frames-opaque").render(context);
  assert.match(frames, /<iframe id="frame-blank"/);
  assert.match(frames, /<iframe id="frame-srcdoc"[^>]* srcdoc="/);
  assert.match(frames, /<iframe id="frame-sandbox-srcdoc" [^>]*sandbox="allow-scripts allow-forms"[^>]* srcdoc="/);
  assert.match(frames, /<iframe id="frame-sandbox-https" [^>]*sandbox="allow-scripts allow-forms"[^>]* src="https:\/\/login\.example\.test\/t\/sandboxed-login\.html"/);
  assert.ok(!/sandbox="[^"]*allow-same-origin/.test(frames), "a sandbox frame never gets its origin back");
  assert.ok(siteById("opacity-html").render(context).includes('<html lang="en" data-fixture-site="opacity-html" style="opacity: 0">'));
  const mimic = siteById("ferret-lookalike").render(context);
  assert.match(mimic, /<title>Faithful Ferret/);
  assert.match(mimic, /<link rel="icon" href="data:image\/svg\+xml,/);
  assert.equal(siteById("ferret-lookalike").origin, "evil");
  for (const id of ["lookalike-dash", "lookalike-suffix", "lookalike-homograph"]) assert.equal(siteById(id).expect.search, "copy_only");
});

test("each_hostile_page_has_a_hostile_field_and_a_clear_control", () => {
  for (const id of ["overlay", "offscreen", "hidden-fields", "css-shadow", ...["opacity", "filter", "transform", "clip-path", "mask", "mix-blend-mode"].flatMap((p) => [`css-${p}`, `css-${p}-subtle`])]) {
    const html = siteById(id).render(context);
    // (css-shadow writes its forms from a script, so its quotes are escaped)
    assert.match(html, /data-fixture-expect=\\?"reject/, `${id}: a hostile field`);
    assert.match(html, /data-fixture-expect=\\?"fill/, `${id}: a control field`);
  }
  assert.doesNotMatch(siteById("opacity-html").render(context), /data-fixture-expect="fill"/, "a page that is invisible as a whole has no control");
  assert.match(siteById("css-filter").render(context), /filter: opacity\(0\.02\)/);
  assert.match(siteById("css-filter-subtle").render(context), /filter: blur\(0px\)/);
  assert.match(siteById("css-mask").render(context), /mask-image/);
  assert.match(siteById("css-mix-blend-mode").render(context), /mix-blend-mode: screen/);
  assert.match(siteById("css-clip-path").render(context), /clip-path: inset\(100%\)/);
  assert.match(siteById("css-transform-subtle").render(context), /transform: translateX\(1px\)/);
  assert.match(siteById("overlay").render(context), /class="cover"/);
  for (const reason of ["display: none", "visibility: hidden", "opacity: 0", "hidden data", "aria-hidden", "disabled", "readonly"]) {
    assert.ok(siteById("hidden-fields").render(context).includes(reason), `hidden-fields: ${reason}`);
  }
});

/**
 * @param {import("../firefox/fixtures-server.mjs").Fixtures} server
 * @param {"https" | "alt" | "http"} listener
 * @param {string} host
 * @param {string} path
 * @param {string} [method]
 * @returns {Promise<{ status: number | undefined, body: string, type: string | undefined }>}
 */
function request(server, listener, host, path, method = "GET") {
  const port = server.ports[listener];
  return new Promise((resolve, reject) => {
    const options = { host: "127.0.0.1", port, path, method, headers: { host: `${host}:${port}` }, servername: host, ca: server.caPem };
    const done = (/** @type {import("node:http").IncomingMessage} */ response) => {
      let body = "";
      response.setEncoding("utf8");
      response.on("data", (chunk) => { body += chunk; });
      response.on("end", () => resolve({ status: response.statusCode, body, type: response.headers["content-type"] }));
    };
    const req = listener === "http" ? httpRequest(options, done) : httpsRequest(options, done);
    req.on("error", reject);
    req.end();
  });
}

test("the_server_serves_each_site_on_its_own_listener_and_no_other", async () => {
  const server = await startFixtures({ port: 0, altPort: 0, httpPort: 0 });
  try {
    assert.equal(new Set([server.port, server.altPort, server.httpPort]).size, 3, "three listeners");
    for (const site of SITES) {
      const origin = ORIGINS[site.origin];
      const answer = await request(server, origin.listener, origin.host, site.path);
      assert.equal(answer.status, 200, `${site.id}: 200`);
      assert.match(answer.type ?? "", /^text\/html/, `${site.id}: html`);
      assert.ok(answer.body.includes(`data-fixture-site="${site.id}"`), `${site.id}: the page of the site`);
      assert.equal(server.siteUrl(site.id), `${server.origin(site.origin)}${site.path}`);
      // The same path on the other listeners is not this site.
      for (const other of /** @type {const} */ (["https", "alt", "http"])) {
        if (other === origin.listener) continue;
        const wrong = await request(server, other, origin.host, site.path);
        assert.ok(!wrong.body.includes(`data-fixture-site="${site.id}"`), `${site.id}: not served on ${other}`);
      }
    }
    // Frames and links name the real ports of this run.
    const framed = await request(server, "https", ORIGINS.www.host, "/");
    assert.ok(framed.body.includes(`src="${server.origin("login")}/"`));
    assert.equal(server.origin("loginAlt"), `https://login.example.test:${server.altPort}`);
    assert.equal(server.origin("loginHttp"), `http://login.example.test:${server.httpPort}`);
    // HEAD has no body; an unlisted host is refused; the harness paths still work on every listener.
    assert.equal((await request(server, "https", ORIGINS.login.host, "/", "HEAD")).body, "");
    assert.equal((await request(server, "http", "unlisted.test", "/healthz")).status, 421);
    assert.equal((await request(server, "alt", ORIGINS.login.host, "/healthz")).body, "ok\n");
    assert.equal((await request(server, "http", ORIGINS.login.host, "/static/login.html")).status, 200);
    assert.equal((await request(server, "https", ORIGINS.login.host, "/t/nothing.html")).status, 404);
    assert.ok(server.requests.some((r) => r.listener === "http" && r.host === "unlisted.test"));
  } finally {
    await server.close();
  }
});

test("two_listeners_cannot_share_a_port", async () => {
  await assert.rejects(startFixtures({ port: 18443, altPort: 18443 }), /same port/);
});

test("the_sites_never_reach_a_package", async () => {
  const env = makeRoot();
  try {
    const options = { root: extensionRoot, webRoot: env.webRoot, out: env.out, wasmTar: env.tarPath };
    for (const variant of ["release", "test"]) {
      const built = await build({ ...options, manifest: "mv3", variant });
      for (const path of built.files.keys()) assert.ok(!/fixtures|sites\//.test(path), `${variant}: ${path} is no fixture page`);
      for (const [path, bytes] of built.files) {
        if (/\.(html|mjs|json)$/.test(path)) assert.ok(!bytes.toString("utf8").includes("data-fixture-site"), `${variant}: ${path} holds no fixture page`);
      }
    }
    // The hosts the sites use are internal hosts: a release that names one is refused.
    const hosts = readInternalHosts(extensionRoot);
    for (const host of ORIGIN_HOSTS) assert.ok(hosts.includes(host), `${host} is an internal host`);
    const leak = new Map([["pages/x.mjs", Buffer.from(`export const x = "https://${ORIGINS.ghA.host}/";\n`)]]);
    assert.ok(releaseProblems(leak, hosts).some((p) => p.includes(`names the internal host ${ORIGINS.ghA.host}`)));
  } finally {
    env.cleanup();
  }
});
