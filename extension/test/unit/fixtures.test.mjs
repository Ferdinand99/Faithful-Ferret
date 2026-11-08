// The adversarial test sites (test/fixtures/sites) without a browser: the host
// list, the page table, what each page renders, and the fixture server's three
// listeners. The Firefox spec (test/firefox/fixtures.spec.mjs) proves the same
// sites in a real browser.
import assert from "node:assert/strict";
import { request as httpRequest } from "node:http";
import { request as httpsRequest } from "node:https";
import { isIP } from "node:net";
import { test } from "node:test";
import { domainToASCII, domainToUnicode } from "node:url";
import { build, namesHost, readInternalHosts, releaseProblems } from "../../scripts/build.mjs";
import { readHosts, startFixtures } from "../firefox/fixtures-server.mjs";
import { profilePrefs } from "../firefox/profile.mjs";
import {
  CONFUSABLE_A_LABEL_HOST, CONFUSABLE_UNICODE_HOST, DIGIT_A_LABEL_HOST, DIGIT_UNICODE_HOST,
  HOMOGRAPH_A_LABEL_HOST, HOMOGRAPH_UNICODE_HOST, ORIGIN_HOSTS, ORIGINS, originText, SITES, siteById,
} from "../fixtures/sites/index.mjs";
import { extensionRoot, makeRoot } from "./buildHelpers.mjs";

const PORTS = { https: 443, alt: 8443, http: 80 };
const context = { url: (/** @type {string} */ origin, path = "/") => `${originText(origin, PORTS)}${path}` };

/** The sites whose fields decide (see expect.outcome). */
const FIELD_SITES = SITES.filter((s) => s.expect.outcome === "fields");

test("every_site_host_is_in_hosts_json_and_nothing_else_is", () => {
  const listed = readHosts().fixture;
  for (const host of ORIGIN_HOSTS) assert.ok(listed.includes(host), `${host} is in hosts.json`);
  const extra = listed.filter((host) => !ORIGIN_HOSTS.includes(host));
  assert.deepEqual(extra, ["fixture.test", "second.fixture.test"], "hosts.json holds only the harness hosts besides the sites'");
  for (const host of listed) assert.equal(host, host.toLowerCase());
  assert.ok(!ORIGIN_HOSTS.includes("127.0.0.1"), "an IP address needs no entry in hosts.json");
});

test("the_example_family_is_under_names_the_public_suffix_list_knows", () => {
  // example.net and example.org are registrable domains in the core's list, so
  // same-site and domain matches work between them; .test is not in the list.
  // The core decides same-site; this only keeps the family where it can.
  for (const name of ["login", "www", "shop", "loginHttp", "loginAlt", "wwwHttp", "dash"]) {
    assert.match(ORIGINS[name].host, /(^|\.)example\.net$|^login-example\.net$/, `${name} is under example.net`);
  }
  assert.equal(ORIGINS.tld.host, "login.example.org");
  assert.equal(ORIGINS.www.host.split(".").slice(1).join("."), ORIGINS.login.host.split(".").slice(1).join("."), "www and login share a registrable domain");
  assert.ok(!ORIGINS.evil.host.endsWith("example.net"), "evil is a foreign site");
  for (const name of ["login", "www", "shop", "dash", "tld"]) assert.ok(!ORIGINS[name].host.endsWith(".test"), `${name} is not under .test`);
});

test("the_homograph_hosts_have_the_a_labels_the_standard_gives", () => {
  assert.equal(HOMOGRAPH_UNICODE_HOST.codePointAt(8), 0x0430, "the third letter of example is a Cyrillic small a");
  assert.equal(DIGIT_UNICODE_HOST.codePointAt(8), 0x0966, "the o of example is a Devanagari digit zero");
  assert.equal(domainToASCII(HOMOGRAPH_UNICODE_HOST), HOMOGRAPH_A_LABEL_HOST);
  assert.equal(domainToASCII(CONFUSABLE_UNICODE_HOST), CONFUSABLE_A_LABEL_HOST);
  assert.equal(domainToASCII(DIGIT_UNICODE_HOST), DIGIT_A_LABEL_HOST);
  assert.equal(domainToUnicode(CONFUSABLE_A_LABEL_HOST), CONFUSABLE_UNICODE_HOST);
  assert.equal(domainToUnicode(DIGIT_A_LABEL_HOST), DIGIT_UNICODE_HOST);
  // The deceptive character is in the registrable label: each is another
  // registrable domain than example.net, so a domain entry cannot match it.
  for (const host of [HOMOGRAPH_A_LABEL_HOST, CONFUSABLE_A_LABEL_HOST, DIGIT_A_LABEL_HOST]) {
    assert.notEqual(host.split(".").slice(-2).join("."), "example.net", host);
    assert.ok(host.split(".").slice(-2)[0].startsWith("xn--"), `${host}: the registrable label is the A-label`);
  }
  assert.equal(ORIGINS.homograph.host, HOMOGRAPH_A_LABEL_HOST);
  assert.equal(ORIGINS.confusable.host, CONFUSABLE_A_LABEL_HOST);
  assert.equal(ORIGINS.digit.host, DIGIT_A_LABEL_HOST);
  // A label that mixes scripts (Latin letters with a Cyrillic letter, or with a
  // digit of another script, which counts as a letter of its script) is shown as
  // the A-label only; the all-Cyrillic label is shown in Unicode with the
  // A-label beside it.
  for (const id of ["lookalike-homograph", "lookalike-digit"]) {
    const { display } = /** @type {any} */ (siteById(id).expect);
    assert.equal(display.unicode, display.a_label, id);
  }
  const shown = /** @type {any} */ (siteById("lookalike-confusable").expect).display;
  assert.notEqual(shown.unicode, shown.a_label);
  assert.ok(shown.a_label.includes("xn--"));
});

test("the_site_table_covers_every_case_and_is_well_formed", () => {
  const ids = SITES.map((s) => s.id);
  assert.equal(new Set(ids).size, ids.length, "ids are unique");
  const routes = SITES.map((s) => `${ORIGINS[s.origin].listener} ${ORIGINS[s.origin].host} ${s.path}`);
  assert.equal(new Set(routes).size, routes.length, "no two sites share a route");

  const required = [
    "login", "sibling", "framed-same-site", "framed-cross-site", "framed-foreign", "http-downgrade", "http-sibling",
    "http-framed-same-site", "http-top-https-frame", "loopback", "loopback-framed", "other-port",
    "lookalike-dash", "lookalike-suffix", "lookalike-tld", "lookalike-homograph", "lookalike-confusable", "lookalike-digit",
    "github-a", "github-b", "frames-opaque", "frames-special", "nested-login", "framed-nested",
    "overlay", "overlay-popover", "overlay-dialog", "opacity-html", "offscreen", "below-fold", "hidden-fields", "tiny-fields",
    "css-shadow", "css-visibility", "css-visibility-collapse",
    "blur-opacity", "blur-overlay", "blur-swap", "blur-navigate", "forged-events", "navigate-frame", "ferret-lookalike",
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
    // A test-site page names no host beyond the fixture hosts (and the loopback address).
    for (const [, host] of html.matchAll(/https?:\/\/([a-z0-9.-]+)/g)) {
      assert.ok(ORIGIN_HOSTS.includes(host) || host === "127.0.0.1", `${site.id}: ${host} is a fixture host`);
    }
    for (const [, value] of html.matchAll(/data-fixture-expect=\\?"([^"\\]*)/g)) assert.ok(value === "fill" || value === "reject", `${site.id}: expectation ${value}`);
  }
});

test("the_sites_have_the_origins_they_name", () => {
  assert.equal(ORIGINS.login.scheme, "https");
  assert.equal(ORIGINS.loginHttp.scheme, "http");
  assert.equal(ORIGINS.loginHttp.host, ORIGINS.login.host);
  assert.equal(ORIGINS.loginAlt.host, ORIGINS.login.host);
  assert.notEqual(ORIGINS.loginAlt.listener, ORIGINS.login.listener);
  assert.equal(originText("login", PORTS), "https://login.example.net");
  assert.equal(originText("loginAlt", PORTS), "https://login.example.net:8443");
  assert.equal(originText("loginHttp", PORTS), "http://login.example.net");
  assert.equal(originText("loopback", PORTS), "http://127.0.0.1");
  assert.equal(ORIGINS.dash.host, "login-example.net");
  assert.equal(ORIGINS.suffix.host, "login.example.net.evil.test");
  assert.equal(ORIGINS.ghA.host, "a.github.io");
  assert.equal(ORIGINS.ghB.host, "b.github.io");

  assert.ok(siteById("framed-same-site").render(context).includes('src="https://login.example.net/"'));
  assert.equal(siteById("framed-same-site").origin, "www");
  assert.ok(siteById("framed-cross-site").render(context).includes('src="https://login.example.net/"'));
  assert.equal(siteById("framed-cross-site").origin, "evil");
  assert.ok(siteById("framed-foreign").render(context).includes('src="https://evil.test/login"'));
  assert.ok(siteById("http-framed-same-site").render(context).includes('src="http://login.example.net/"'));
  assert.ok(siteById("http-top-https-frame").render(context).includes('src="https://login.example.net/"'));
  assert.equal(siteById("http-top-https-frame").origin, "wwwHttp");
  assert.ok(siteById("loopback-framed").render(context).includes('src="http://127.0.0.1/"'));

  const frames = siteById("frames-opaque").render(context);
  assert.match(frames, /<iframe id="frame-blank"/);
  assert.match(frames, /<iframe id="frame-srcdoc"[^>]* srcdoc="/);
  assert.match(frames, /<iframe id="frame-sandbox-srcdoc" [^>]*sandbox="allow-scripts allow-forms"[^>]* srcdoc="/);
  assert.match(frames, /<iframe id="frame-sandbox-https" [^>]*sandbox="allow-scripts allow-forms"[^>]* src="https:\/\/login\.example\.net\/t\/sandboxed-login\.html"/);
  assert.ok(!/sandbox="[^"]*allow-same-origin/.test(frames), "a sandbox frame never gets its origin back");
  // The page the sandbox loads is a plain sign-in page: filled when it is the top page.
  assert.equal(siteById("sandboxed-login").expect.outcome, "fill");
  assert.ok(!siteById("sandboxed-login").render(context).includes("data-fixture-expect"), "no field verdict that depends on being framed");
  const special = siteById("frames-special").render(context);
  assert.match(special, /<iframe id="frame-data"[^>]* src="data:text\/html/);
  assert.match(special, /<iframe id="frame-javascript"[^>]* src="javascript:/);
  assert.match(special, /URL\.createObjectURL\(new Blob/);
  assert.match(siteById("nested-login").render(context), /<iframe id="nested-blank"/);
  assert.match(siteById("navigate-frame").render(context), /navigateFrame\("data"\)/);

  assert.ok(siteById("opacity-html").render(context).includes('<html lang="en" data-fixture-site="opacity-html" style="opacity: 0">'));
  const mimic = siteById("ferret-lookalike").render(context);
  assert.match(mimic, /<title>Faithful Ferret/);
  assert.match(mimic, /<link rel="icon" href="data:image\/svg\+xml,/);
  assert.equal(siteById("ferret-lookalike").origin, "evil");
  for (const id of ["lookalike-dash", "lookalike-suffix", "lookalike-tld", "lookalike-homograph", "lookalike-confusable", "lookalike-digit"]) {
    assert.equal(siteById(id).expect.search, "copy_only", id);
    assert.equal(siteById(id).expect.domain_entry, "no_offer", `${id}: a domain entry does not match either`);
  }
  assert.equal(siteById("http-downgrade").expect.http_entry, "offer_with_warning");
  assert.equal(siteById("http-sibling").expect.http_entry, "no_offer");
  assert.equal(siteById("sibling").expect.domain_entry, "fill");
  assert.equal(siteById("sibling").expect.outcome, "no_offer");
});

test("each_hostile_page_has_hostile_fields_with_their_reasons_and_a_clear_control", () => {
  assert.ok(FIELD_SITES.length >= 20);
  for (const site of FIELD_SITES) {
    const html = site.render(context);
    // (css-shadow writes its forms from a script, so its quotes are escaped)
    const rejects = [...html.matchAll(/data-fixture-expect=\\?"reject/g)].length;
    const reasons = [...html.matchAll(/data-fixture-reason=\\?"/g)].length;
    assert.ok(rejects >= 1, `${site.id}: a hostile field`);
    assert.equal(reasons, rejects, `${site.id}: every hostile field names its reason`);
    if (site.id !== "opacity-html") assert.match(html, /data-fixture-expect=\\?"fill/, `${site.id}: a control field`);
  }
  assert.doesNotMatch(siteById("opacity-html").render(context), /data-fixture-expect="fill"/, "a page that is invisible as a whole has no control");
  assert.match(siteById("css-filter").render(context), /filter: opacity\(0\.02\)/);
  assert.match(siteById("css-filter-subtle").render(context), /filter: blur\(0px\)/);
  assert.match(siteById("css-mask").render(context), /mask-image/);
  assert.match(siteById("css-mix-blend-mode").render(context), /mix-blend-mode: screen/);
  assert.match(siteById("css-clip-path").render(context), /clip-path: inset\(100%\)/);
  assert.match(siteById("css-transform-subtle").render(context), /transform: translateX\(1px\)/);
  assert.match(siteById("overlay").render(context), /class="cover"/);
  assert.match(siteById("overlay-popover").render(context), /popover="manual"[\s\S]*showPopover\(\)/);
  assert.match(siteById("overlay-dialog").render(context), /<dialog id="cover">[\s\S]*showModal\(\)/);
  assert.match(siteById("css-visibility").render(context), /<div id="hostile-parent" style="visibility: hidden"><form [^>]*style="visibility: visible"/);
  assert.match(siteById("css-visibility-collapse").render(context), /visibility: collapse/);
  for (const id of ["css-visibility", "css-visibility-collapse", "css-shadow"]) assert.equal(siteById(id).expect.exact, true, id);
  for (const property of ["opacity", "filter", "transform", "clip-path", "mask", "mix-blend-mode"]) {
    assert.equal(siteById(`css-${property}-subtle`).expect.exact, true, `${property}: the subtle value is the only reason`);
  }
});

test("the_hidden_decoys_come_before_the_visible_fields", () => {
  const html = siteById("hidden-fields").render(context);
  const at = (/** @type {string} */ id) => html.indexOf(`id="${id}"`);
  assert.ok(at("hide-user") > 0 && at("hide-user") < at("ok-user"), "a hidden user name field before the visible one");
  assert.ok(at("hide-email") < at("ok-user"));
  for (const id of ["hide-display", "hide-visibility", "hide-opacity", "hide-size", "hide-attribute", "hide-aria", "hide-disabled", "hide-readonly"]) {
    assert.ok(at(id) > 0 && at(id) < at("ok-pass"), `${id} before the visible password field`);
  }
  for (const reason of ["display: none", "visibility: hidden", "opacity: 0", "hidden data", "aria-hidden", "disabled", "readonly"]) {
    assert.ok(html.includes(reason), `hidden-fields: ${reason}`);
  }
  const tiny = siteById("tiny-fields").render(context);
  assert.ok(tiny.indexOf('id="tiny-1"') < tiny.indexOf('id="ok-pass"'));
  assert.match(tiny, /width: 1px; height: 1px/);
});

test("the_pages_that_change_after_the_choice_turn_hostile_on_request_and_on_blur", () => {
  for (const id of ["blur-opacity", "blur-overlay", "blur-swap", "blur-navigate"]) {
    const html = siteById(id).render(context);
    assert.match(html, /window\.turnHostile = turnHostile;/, id);
    assert.match(html, /addEventListener\("blur", turnHostile\)/, id);
    assert.ok(!html.includes("data-fixture-expect"), `${id}: the fields are clear until the page turns`);
  }
  assert.equal(siteById("blur-navigate").expect.outcome, "origin_changed");
  assert.match(siteById("blur-navigate").render(context), /var evilLogin = "https:\/\/evil\.test\/login"/);
  const forged = siteById("forged-events").render(context);
  assert.match(forged, /new CustomEvent\("ferret-fill"/);
  assert.match(forged, /type: "fill_field"/);
  assert.match(forged, /window\.fixtureState/);
});

test("the_release_check_matches_host_names_at_label_boundaries", () => {
  assert.equal(namesHost('see "https://a.github.io/x"', "a.github.io"), true);
  assert.equal(namesHost("x.a.github.io", "a.github.io"), true);
  assert.equal(namesHost("a.github.io.", "a.github.io"), true);
  assert.equal(namesHost("https://mozilla.github.io/docs", "a.github.io"), false);
  assert.equal(namesHost("devil.test", "evil.test"), false);
  assert.equal(namesHost("evil.test-two", "evil.test"), false);
  assert.equal(namesHost("mozilla.github.io then a.github.io", "a.github.io"), true);
  const hosts = readInternalHosts(extensionRoot);
  const clean = new Map([["pages/x.mjs", Buffer.from("export const docs = 'https://mozilla.github.io/';\n")]]);
  assert.ok(!releaseProblems(clean, hosts).some((p) => p.includes("a.github.io")));
  const leak = new Map([["pages/x.mjs", Buffer.from("export const x = 'https://A.GitHub.io/';\n")]]);
  assert.ok(releaseProblems(leak, hosts).some((p) => p.includes("names the internal host a.github.io")));
});

test("the_test_profile_pins_https_first_off", () => {
  const prefs = profilePrefs();
  assert.equal(prefs["dom.security.https_first"], false);
  assert.equal(prefs["dom.security.https_only_mode"], false);
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
    const options = { host: "127.0.0.1", port, path, method, headers: { host: `${host}:${port}` }, servername: isIP(host) ? "fixture.test" : host, ca: server.caPem };
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
    assert.equal(server.origin("loginAlt"), `https://login.example.net:${server.altPort}`);
    assert.equal(server.origin("loginHttp"), `http://login.example.net:${server.httpPort}`);
    assert.equal(server.origin("loopback"), `http://127.0.0.1:${server.httpPort}`);
    // HEAD has no body; an unlisted host is refused; the loopback address is
    // served over http only; the harness paths still work on every listener.
    assert.equal((await request(server, "https", ORIGINS.login.host, "/", "HEAD")).body, "");
    assert.equal((await request(server, "http", "unlisted.test", "/healthz")).status, 421);
    assert.equal((await request(server, "https", "127.0.0.1", "/")).status, 421);
    assert.equal((await request(server, "http", "127.0.0.1", "/healthz")).body, "ok\n");
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
    for (const host of ORIGIN_HOSTS) {
      const leak = new Map([["pages/x.mjs", Buffer.from(`export const x = "https://${host}/";\n`)]]);
      assert.ok(releaseProblems(leak, hosts).some((p) => p.includes(`names the internal host ${host}`)), `${host} is refused`);
    }
  } finally {
    env.cleanup();
  }
});
