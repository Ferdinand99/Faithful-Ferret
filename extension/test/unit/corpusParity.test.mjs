// The autofill-parity suite (test/fixtures/forms-parity) without a browser: every case is well formed, the pages
// stay inside the suite (no remote resource, no brand), the fixture server serves them, and the runner's rules
// for generated passwords work. The Firefox matrix measures the extension against it (`--set parity`).
import assert from "node:assert/strict";
import { existsSync, readdirSync, readFileSync, statSync } from "node:fs";
import { request } from "node:http";
import { join } from "node:path";
import { test } from "node:test";
import { PARITY_FORMS_DIR, readHosts, startFixtures } from "../firefox/fixtures-server.mjs";
import { PARITY_DIR, casesOf, idPrefixFor } from "../firefox/matrix.mjs";
import { CATEGORIES, caseProblems, computeMatrix, followsRules, loadCorpus } from "../firefox/matrixReport.mjs";
import { IP_HOSTS, ORIGINS } from "../fixtures/sites/index.mjs";

const OPTIONS = { prefix: "ap-" };
const caseFolders = () => readdirSync(PARITY_DIR).filter((n) => !n.startsWith("_") && statSync(join(PARITY_DIR, n)).isDirectory()).sort();
/** @param {string} dir */
const filesOf = (dir) => readdirSync(dir).filter((n) => /\.(html|js|css)$/.test(n)).map((n) => ({ name: n, text: readFileSync(join(dir, n), "utf8") }));

/** @param {Record<string, any>} c @returns {string[]} the `#id`s a case names */
function referencedIds(c) {
  /** @type {string[]} */
  const out = [];
  const e = c.expect;
  if (e.fill) out.push(...Object.keys(e.fill.fields));
  out.push(...(e.allow ?? []), ...c.must_stay_empty, ...Object.keys(c.fields));
  if (e.generated) out.push(e.generated.new, ...(e.generated.confirm ? [e.generated.confirm] : []));
  if (e.capture) out.push(e.capture.password_from);
  if (c.frame) out.push(c.frame.id);
  for (const s of [...(c.prepare ?? []), ...c.steps]) {
    const id = s.type ?? s.click;
    if (typeof id === "string" && id.startsWith("#")) out.push(id);
  }
  return out;
}

test("the_parity_suite_is_there_and_every_case_is_well_formed", () => {
  assert.equal(PARITY_DIR, PARITY_FORMS_DIR);
  assert.equal(idPrefixFor("parity"), "ap-");
  const names = caseFolders();
  assert.ok(names.length >= 55, `${names.length} cases`);
  const hosts = readHosts().fixture;
  for (const name of names) {
    const dir = join(PARITY_DIR, name);
    const c = JSON.parse(readFileSync(join(dir, "case.json"), "utf8"));
    assert.deepEqual(caseProblems(c, name, OPTIONS), [], `${name}/case.json`);
    assert.equal(c.source, "own", `${name}: own work`);
    assert.ok(existsSync(join(dir, "index.html")), `${name}/index.html`);
    for (const host of [c.host, c.frame?.host].filter(Boolean)) assert.ok(hosts.includes(host) || IP_HOSTS.includes(host), `${name}: ${host} is in hosts.json`);
    const ids = new Set(filesOf(dir).flatMap(({ text }) => [...text.matchAll(/\bid=\\?["']([A-Za-z][A-Za-z0-9_-]*)\\?["']/g)].map((m) => m[1])));
    for (const ref of referencedIds(c)) assert.ok(ids.has(ref.slice(1)), `${name}: ${ref} is in a page of the case`);
    for (const { name: file, text } of filesOf(dir)) {
      const markup = text.replace(/<script[\s\S]*?<\/script>/g, "");
      const staticIds = [...markup.matchAll(/\bid=["']([A-Za-z][A-Za-z0-9_-]*)["']/g)].map((m) => m[1]);
      assert.equal(new Set(staticIds).size, staticIds.length, `${name}/${file}: an id is used twice`);
      for (const m of text.matchAll(/\b(?:action|href|src)=["']([a-z0-9][a-z0-9._-]*\.html)(?:\?[^"']*)?["']/g)) assert.ok(existsSync(join(dir, m[1])), `${name}/${file}: ${m[1]} exists`);
      for (const m of text.matchAll(/\{\{origin:([A-Za-z]+)\}\}/g)) assert.ok(Object.hasOwn(ORIGINS, m[1]), `${name}/${file}: origin ${m[1]}`);
    }
    if (c.frame) assert.ok(existsSync(join(dir, c.frame.path.split("/").pop() ?? "")), `${name}: the frame's page exists`);
  }
  assert.equal(loadCorpus(PARITY_DIR, OPTIONS).length, names.length);
  assert.equal(casesOf("parity").length, names.length, "the runner loads the same cases");
  // Without the suite's prefix the ids are refused (positive control).
  assert.ok(caseProblems(JSON.parse(readFileSync(join(PARITY_DIR, names[0], "case.json"), "utf8")), names[0]).length > 0);
});

test("the_parity_suite_covers_the_patterns_it_stands_for", () => {
  const cases = loadCorpus(PARITY_DIR, OPTIONS);
  const ids = cases.map((c) => c.id);
  assert.equal(new Set(ids).size, ids.length, "ids are unique");
  for (const c of cases) {
    assert.ok(Object.hasOwn(CATEGORIES, c.category), `${c.id}: a known category`);
    assert.equal(c.path.split("/")[1], c.id);
    assert.ok(c.class === "negative" || c.expect.fill !== null || c.expect.capture !== null || c.expect.generated, `${c.id}: measures something`);
  }
  for (const part of ["reveal-display-none", "reveal-zero-size", "reveal-added-hidden", "reveal-scroll", "dialog-modal", "dialog-positioned", "frame-iframe", "frameset", "nested-iframe", "dialog-iframe", "nested-dialogs-iframe", "iframe-positioned-dialog", "shadow", "multi-step-totp", "hidden-totp", "duplicate-username", "rules-length", "spa-registration", "passkeys", "device-trust", "heavy-nodes", "heavy-mutations", "card-simple", "identity", "search", "other-inputs", "save-"]) {
    assert.ok(ids.some((id) => id.includes(part)), `a case for ${part}`);
  }
  const markup = cases.flatMap((c) => filesOf(c.dir).map((f) => f.text)).join("\n");
  assert.ok(/data-1p-ignore/.test(markup), "a page with data-1p-ignore");
  assert.ok(/<frameset/.test(markup) && /<dialog/.test(markup) && /attachShadow/.test(markup) && /passwordrules/.test(markup) && /webauthn/.test(markup), "frameset, dialog, shadow root, password rules and passkey fields");
});

/** The names a page of the suite must not use (real services and products). Lower case, whole words. */
const BRANDS = Object.freeze([
  "google", "gmail", "facebook", "instagram", "whatsapp", "microsoft", "outlook", "apple", "icloud", "amazon", "paypal", "netflix", "github",
  "gitlab", "twitter", "linkedin", "dropbox", "spotify", "ebay", "adobe", "slack", "zoom", "stripe", "visa", "mastercard", "amex", "vipps",
  "bankid", "wikipedia", "reddit", "yahoo", "steam", "discord", "tiktok", "youtube", "samsung", "bitwarden", "vaultwarden", "keepass",
  "lastpass", "dashlane", "1password", "okta", "auth0", "autofill",
]);

test("no_page_of_the_suite_loads_a_remote_resource_or_names_a_brand", () => {
  let checked = 0;
  for (const name of caseFolders()) {
    for (const { name: file, text } of filesOf(join(PARITY_DIR, name))) {
      const where = `${name}/${file}`;
      assert.equal(/:\/\//.test(text), false, `${where}: a literal address`);
      assert.equal(/(?:src|href|action|poster|srcset|formaction|data)\s*=\s*["']?\s*\/\//i.test(text), false, `${where}: a protocol-relative address`);
      assert.equal(/url\(\s*["']?\s*(?:https?:)?\/\//i.test(text) || /@import/i.test(text) || /<link\b/i.test(text), false, `${where}: css or a link that reaches out`);
      assert.equal(/<script\b[^>]*\bsrc=/i.test(text), false, `${where}: an external script`);
      assert.equal(/<(?:img|video|audio|source|embed|object)\b/i.test(text), false, `${where}: an element that loads a resource`);
      assert.equal(/\bimport\s*\(|\bnavigator\.sendBeacon\b|\bWebSocket\b|\bEventSource\b|\bfetch\s*\(|XMLHttpRequest/.test(text), false, `${where}: a script that reaches out`);
      for (const m of text.matchAll(/\b(?:src|href|action)=["']([^"']*)["']/g)) {
        assert.match(m[1], /^(?:#[a-z0-9-]*|\{\{origin:[A-Za-z]+\}\}\/|\/static\/[a-z0-9._-]+$|[a-z0-9][a-z0-9._-]*\.html(?:\?[^"']*)?$|)$/, `${where}: an address that is not the suite's own: ${m[1]}`);
      }
      const lower = text.toLowerCase();
      for (const brand of BRANDS) assert.equal(new RegExp(`(?<![a-z0-9])${brand}(?![a-z0-9])`).test(lower), false, `${where}: the name ${brand}`);
      checked += 1;
    }
  }
  assert.ok(checked >= 70, `${checked} files checked`);
});

test("the_fixture_server_serves_every_page_of_the_suite", async () => {
  const server = await startFixtures({ port: 0, altPort: 0, httpPort: 0 });
  try {
    /** @param {string} host @param {string} path @returns {Promise<{ status: number, type: string, body: string }>} */
    const get = (host, path) => new Promise((resolveGet, rejectGet) => {
      const req = request({ host: "127.0.0.1", port: server.httpPort, path, method: "GET", headers: { host } }, (res) => {
        let body = "";
        res.setEncoding("utf8");
        res.on("data", (chunk) => { body += chunk; });
        res.on("end", () => resolveGet({ status: res.statusCode ?? 0, type: String(res.headers["content-type"]), body }));
      });
      req.on("error", rejectGet);
      req.end();
    });
    let pages = 0;
    for (const c of loadCorpus(PARITY_DIR, OPTIONS)) {
      for (const file of readdirSync(c.dir).filter((n) => n.endsWith(".html"))) {
        const reply = await get(c.host, file === "index.html" ? c.path : `/${c.id}/${file}`);
        assert.equal(reply.status, 200, `${c.id}/${file}`);
        assert.match(reply.type, /^text\/html/);
        assert.ok(reply.body.includes("<html"), `${c.id}/${file}: a page`);
        pages += 1;
      }
    }
    assert.ok(pages >= 70, `${pages} pages served`);
    assert.equal((await get("forms.example.net", "/ap-login-simple/case.json")).status, 404, "case.json is not served");
  } finally {
    await server.close();
  }
});

test("password_rules_are_checked_where_the_value_is_and_a_miss_is_reported", () => {
  const rules = { minlength: 8, maxlength: 12, require: ["lower", "digit"], forbid: ["symbol"] };
  assert.equal(followsRules("abcd1234", rules), true);
  assert.equal(followsRules("abcd123", rules), false, "too short");
  assert.equal(followsRules("abcd1234efgh9", rules), false, "too long");
  assert.equal(followsRules("ABCD1234", rules), false, "no lower case");
  assert.equal(followsRules("abcd1234!", rules), false, "a symbol");
  assert.equal(followsRules("Zq7!-anything-Vm4$", {}), true, "no rules, no refusal");
  // A case that states rules passes only when the runner saw the value follow them.
  const c = loadCorpus(PARITY_DIR, OPTIONS).find((x) => x.id === "ap-signup-rules-length");
  assert.ok(c, "the rules case is in the suite");
  /** @param {boolean | undefined} ok */
  const run = (ok) => computeMatrix([{ case: c, ran: { fill: false, capture: false, generated: true }, observed: { fills: [], tried: [], entries: {}, offers: [], generated: { filled: ["#pw", "#pw2"], stray: [], ...(ok === undefined ? {} : { rules_ok: ok }) } } }], { set: "parity", part: "capture" });
  assert.equal(run(true).generated.passed, 1);
  assert.equal(run(false).generated.passed, 0);
  assert.equal(run(false).misses.some((m) => m.part === "generated" && /password rules/.test(m.reason)), true);
  assert.equal(run(undefined).generated.passed, 0, "no verdict is a miss");
  assert.equal(caseProblems({ ...c, expect: { ...c.expect, generated: { ...c.expect.generated, rules: { minlength: "six" } } } }, c.id, OPTIONS).length > 0, true, "a malformed rule is refused");
});
