// The detection corpus (test/fixtures/forms) without a browser: every case is well formed, the corpus
// has the cases each category needs, nothing in it loads a remote resource or names a brand, and the
// fixture server serves every page. The Firefox spec (test/firefox/95-matrix.e2e.spec.mjs) measures
// the extension against it.
import assert from "node:assert/strict";
import { existsSync, readdirSync, readFileSync, statSync } from "node:fs";
import { request } from "node:http";
import { dirname, join, resolve } from "node:path";
import { test } from "node:test";
import { fileURLToPath } from "node:url";
import { FORMS_DIR, readHosts, startFixtures } from "../firefox/fixtures-server.mjs";
import { CATEGORIES, LANGUAGES, caseProblems, loadCorpus } from "../firefox/matrixReport.mjs";
import { IP_HOSTS, ORIGINS } from "../fixtures/sites/index.mjs";

const here = dirname(fileURLToPath(import.meta.url));
const repoRoot = resolve(here, "..", "..", "..");

/** Every folder of the corpus, the self-test page included. @returns {string[]} */
const folders = () => readdirSync(FORMS_DIR).filter((n) => statSync(join(FORMS_DIR, n)).isDirectory()).sort();
/** The folders that are cases. */
const caseFolders = () => folders().filter((n) => !n.startsWith("_"));
/** The text files of a case folder. @param {string} dir */
const filesOf = (dir) => readdirSync(dir).filter((n) => /\.(html|js|css)$/.test(n)).map((n) => ({ name: n, text: readFileSync(join(dir, n), "utf8") }));

// An id in markup, also in markup a script writes (a quoted string, where the quote has a backslash) and in a custom element's attribute.
const ID_ATTRIBUTE = /\b(?:input-)?id=(?:\\?["']|&quot;)([A-Za-z][A-Za-z0-9_-]*)(?:\\?["']|&quot;)/g;

/**
 * The ids an `#id` reference may point to: every id attribute of the case's pages.
 * @param {string} dir
 */
function idsOf(dir) {
  /** @type {Set<string>} */
  const ids = new Set();
  for (const { text } of filesOf(dir)) for (const m of text.matchAll(ID_ATTRIBUTE)) ids.add(m[1]);
  return ids;
}

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

test("every_case_has_a_valid_case_json_and_a_page", () => {
  const names = caseFolders();
  assert.ok(names.length >= 130, `${names.length} cases`);
  const hosts = readHosts().fixture;
  for (const name of names) {
    const dir = join(FORMS_DIR, name);
    const c = JSON.parse(readFileSync(join(dir, "case.json"), "utf8"));
    assert.deepEqual(caseProblems(c, name), [], `${name}/case.json`);
    assert.ok(existsSync(join(dir, "index.html")), `${name}/index.html`);
    // The host the case opens, and the host of its frame, are names the runner maps (an IP address needs no entry).
    for (const host of [c.host, c.frame?.host].filter(Boolean)) assert.ok(hosts.includes(host) || IP_HOSTS.includes(host), `${name}: ${host} is in hosts.json`);
    // Every field the case names is in its pages, and no page has one id twice.
    const ids = idsOf(dir);
    for (const ref of referencedIds(c)) assert.ok(ids.has(ref.slice(1)), `${name}: ${ref} is in a page of the case`);
    for (const { name: file, text } of filesOf(dir)) {
      const all = [...text.matchAll(/\bid=["']([A-Za-z][A-Za-z0-9_-]*)["']/g)].map((m) => m[1]);
      // A page that writes more markup with a script (a late render, a custom element) names its ids once in the
      // script text and once in the markup it creates, so the check is on the static markup only.
      const markup = text.replace(/<script[\s\S]*?<\/script>/g, "");
      const staticIds = [...markup.matchAll(/\bid=["']([A-Za-z][A-Za-z0-9_-]*)["']/g)].map((m) => m[1]);
      assert.equal(new Set(staticIds).size, staticIds.length, `${name}/${file}: an id is used twice`);
      assert.ok(all.length >= 0);
      // A link or a form to a page of the case, and a frame of the case, name a file that exists.
      for (const m of text.matchAll(/\b(?:action|href|src)=["']([a-z0-9][a-z0-9._-]*\.html)(?:\?[^"']*)?["']/g)) assert.ok(existsSync(join(dir, m[1])), `${name}/${file}: ${m[1]} exists`);
      for (const m of text.matchAll(/\{\{origin:([A-Za-z]+)\}\}\/([a-z0-9-]+)\/([a-z0-9._-]+)/g)) {
        assert.ok(Object.hasOwn(ORIGINS, m[1]), `${name}/${file}: origin ${m[1]}`);
        assert.equal(m[2], name, `${name}/${file}: a case points only at its own pages`);
        assert.ok(existsSync(join(dir, m[3])), `${name}/${file}: ${m[3]} exists`);
      }
      for (const m of text.matchAll(/\{\{origin:([A-Za-z]+)\}\}/g)) assert.ok(Object.hasOwn(ORIGINS, m[1]), `${name}/${file}: origin ${m[1]}`);
    }
    if (c.frame && c.frame.path.startsWith("/")) assert.ok(existsSync(join(dir, c.frame.path.split("/").pop() ?? "")), `${name}: the frame's page exists`);
  }
  // The loader reads the same cases and refuses a broken one.
  assert.equal(loadCorpus(FORMS_DIR).length, names.length);
  assert.ok(caseProblems({ id: "x" }, "y").length > 0, "a broken case is refused (positive control)");
});

test("the_corpus_has_the_minimum_per_category", () => {
  const cases = loadCorpus(FORMS_DIR);
  /** @type {Record<string, number>} */
  const count = {};
  /** @type {Record<string, number>} */
  const byClass = { positive: 0, negative: 0, special: 0 };
  for (const c of cases) {
    count[c.category] = (count[c.category] ?? 0) + 1;
    byClass[c.class] += 1;
  }
  for (const [name, spec] of Object.entries(CATEGORIES)) assert.ok((count[name] ?? 0) >= spec.min, `${name}: ${count[name] ?? 0} cases, at least ${spec.min}`);
  assert.deepEqual(Object.keys(count).filter((n) => !Object.hasOwn(CATEGORIES, n)), [], "no category outside the table");
  assert.ok(byClass.positive >= 80 && byClass.negative >= 45 && byClass.special >= 5 && cases.length >= 130, JSON.stringify(byClass));
  // The five languages are in the sign-in cases.
  for (const lang of LANGUAGES) assert.ok(cases.some((c) => c.category === "login" && c.lang === lang), `a sign-in case in ${lang}`);
  // The cases that name no fill and no capture would measure nothing.
  for (const c of cases) assert.ok(c.class === "negative" || c.expect.fill !== null || c.expect.capture !== null, c.id);
});

test("case_ids_are_unique_and_start_with_their_category", () => {
  const cases = loadCorpus(FORMS_DIR);
  const ids = cases.map((c) => c.id);
  assert.equal(new Set(ids).size, ids.length, "ids are unique");
  for (const c of cases) {
    assert.ok(c.id.startsWith(`${c.category}-`), `${c.id} starts with ${c.category}-`);
    assert.equal(c.class, CATEGORIES[c.category].class, `${c.id}: the class of its category`);
    assert.equal(c.path.split("/")[1], c.id, `${c.id}: its path`);
  }
  assert.deepEqual(caseFolders(), ids.slice().sort(), "a case for every folder and a folder for every case");
});

/** The names a fixture must not use (real services and products). Lower case, matched as whole words. */
const BRANDS = Object.freeze([
  "google", "gmail", "facebook", "instagram", "whatsapp", "microsoft", "outlook", "office365", "apple", "icloud", "amazon", "paypal",
  "netflix", "github", "gitlab", "twitter", "linkedin", "dropbox", "spotify", "ebay", "adobe", "slack", "zoom", "stripe", "visa",
  "mastercard", "amex", "vipps", "bankid", "altinn", "nordea", "dnb", "sparebank", "wikipedia", "reddit", "yahoo", "steam", "discord",
  "tiktok", "youtube", "samsung", "bitwarden", "vaultwarden", "keepass", "lastpass", "dashlane", "onepassword", "1password", "okta", "auth0",
]);

/**
 * What a corpus file loads from outside or names that it should not.
 * @param {string} text
 * @returns {string[]}
 */
function fixtureProblems(text) {
  /** @type {string[]} */
  const out = [];
  if (/:\/\//.test(text)) out.push("a literal address (use {{origin:name}} for another origin of the corpus)");
  if (/(?:src|href|action|poster|srcset|formaction|data)\s*=\s*["']?\s*\/\//i.test(text)) out.push("a protocol-relative address");
  if (/url\(\s*["']?\s*(?:https?:)?\/\//i.test(text)) out.push("a remote url()");
  if (/@import/i.test(text)) out.push("@import");
  if (/<link\b/i.test(text)) out.push("a <link>");
  if (/<script\b[^>]*\bsrc=/i.test(text)) out.push("an external script");
  if (/<(?:img|video|audio|source|embed|object)\b/i.test(text)) out.push("an element that loads a resource");
  if (/\bimport\s*\(|\bnavigator\.sendBeacon\b|\bWebSocket\b|\bEventSource\b/.test(text)) out.push("a script that reaches out");
  for (const m of text.matchAll(/\b(?:src|href|action)=["']([^"']*)["']/g)) {
    const v = m[1];
    if (/^(?:#|\{\{origin:[A-Za-z]+\}\}\/|\/static\/|[a-z0-9][a-z0-9._-]*\.html(?:\?[^"']*)?$)/.test(v) || v === "") continue;
    out.push(`an address that is not the case's own: ${v}`);
  }
  const lower = text.toLowerCase();
  for (const brand of BRANDS) if (new RegExp(`(?<![a-z0-9])${brand}(?![a-z0-9])`).test(lower)) out.push(`the name ${brand}`);
  return out;
}

test("no_fixture_loads_a_remote_resource_or_names_a_brand", () => {
  assert.ok(BRANDS.length >= 20, "the list of names is not empty");
  let checked = 0;
  for (const name of folders()) {
    for (const { name: file, text } of filesOf(join(FORMS_DIR, name))) {
      assert.deepEqual(fixtureProblems(text), [], `${name}/${file}`);
      checked += 1;
    }
  }
  assert.ok(checked >= 130, `${checked} files checked`);
  // Positive controls: the checker sees what it is there to see.
  assert.ok(fixtureProblems('<img src="https://cdn.example.org/a.png">').length > 0, "a remote image");
  assert.ok(fixtureProblems('<script src="//cdn.example.org/a.js"></script>').length > 0, "a protocol-relative script");
  assert.ok(fixtureProblems("<style>@import 'a.css'; b { background: url(https://x.example/a.png) }</style>").length > 0, "css that reaches out");
  assert.ok(fixtureProblems("<title>Sign in to Github</title>").some((p) => p.includes("github")), "a brand");
  assert.deepEqual(fixtureProblems('<form action="/static/login-done.html"><iframe src="{{origin:formsEvil}}/x/inner.html"></iframe></form>'), [], "own addresses pass");
});

/**
 * What is missing from a case that says it is adapted from someone else's file: the licence header and the
 * change note in every file, and a notice in notices-extra.json.
 * @param {{ id: string, source: string }} c
 * @param {Array<{ name: string, text: string }>} files
 * @param {string} notices the text of notices-extra.json
 * @returns {string[]}
 */
function adaptedProblems(c, files, notices) {
  if (c.source === "own") return [];
  /** @type {string[]} */
  const out = [];
  if (c.source !== "adapted") return [`source ${c.source}`];
  for (const f of files) {
    if (!/SPDX-License-Identifier:\s*\S+/.test(f.text)) out.push(`${f.name}: no SPDX header`);
    if (!/Modified by Faithful Ferret/.test(f.text)) out.push(`${f.name}: no change note`);
  }
  if (!notices.includes(c.id)) out.push("no entry in notices-extra.json");
  return out;
}

test("adapted_files_carry_their_header_and_notice", () => {
  const cases = loadCorpus(FORMS_DIR);
  const adapted = cases.filter((c) => c.source !== "own");
  const noticesFile = join(repoRoot, "notices-extra.json");
  const notices = existsSync(noticesFile) ? readFileSync(noticesFile, "utf8") : "";
  if (adapted.length > 0) assert.ok(notices !== "", "notices-extra.json is there to be checked");
  for (const c of adapted) assert.deepEqual(adaptedProblems(c, filesOf(c.dir), notices), [], c.id);
  // Positive controls: a file without its header, and an entry that was never made, are caught.
  const bare = [{ name: "index.html", text: "<!doctype html>" }];
  assert.deepEqual(adaptedProblems({ id: "x", source: "adapted" }, bare, ""), ["index.html: no SPDX header", "index.html: no change note", "no entry in notices-extra.json"]);
  const dressed = [{ name: "index.html", text: "<!-- SPDX-License-Identifier: AGPL-3.0-only\n Modified by Faithful Ferret -->" }];
  assert.deepEqual(adaptedProblems({ id: "x", source: "adapted" }, dressed, '"x"'), []);
  assert.deepEqual(adaptedProblems({ id: "x", source: "own" }, bare, ""), []);
});

test("the_fixture_server_serves_every_case_and_its_other_pages", async () => {
  const server = await startFixtures({ port: 0, altPort: 0, httpPort: 0 });
  try {
    /** @param {string} host @param {string} path @param {string} [method] */
    const get = (host, path, method = "GET") => new Promise((resolveGet, rejectGet) => {
      const req = request({ host: "127.0.0.1", port: server.httpPort, path, method, headers: { host } }, (res) => {
        let body = "";
        res.setEncoding("utf8");
        res.on("data", (chunk) => { body += chunk; });
        res.on("end", () => resolveGet({ status: res.statusCode, type: String(res.headers["content-type"]), body }));
      });
      req.on("error", rejectGet);
      req.end();
    });
    let pages = 0;
    for (const c of loadCorpus(FORMS_DIR)) {
      for (const file of readdirSync(c.dir).filter((n) => n.endsWith(".html"))) {
        const path = file === "index.html" ? c.path.split("?")[0] : `/${c.id}/${file}`;
        const reply = await get(c.host, path);
        assert.equal(reply.status, 200, `${c.id}${path}`);
        assert.match(reply.type, /^text\/html/);
        assert.ok(reply.body.includes("<html"), `${c.id}${path}: a page`);
        assert.equal(reply.body.includes("{{origin:"), false, `${c.id}${path}: the origins are filled in`);
        pages += 1;
      }
    }
    assert.ok(pages >= 140, `${pages} pages served`);
    // A form may post to a page of the case; a file that is not a page of a case is not served.
    assert.equal((await get("forms.example.net", "/login-basic-en/index.html", "POST")).status, 200);
    assert.equal((await get("forms.example.net", "/login-basic-en/case.json")).status, 404, "case.json is not served");
    assert.equal((await get("forms.example.net", "/login-basic-en/../x.html")).status, 404);
    assert.equal((await get("forms.example.net", "/no-such-case/")).status, 404);
    // The origins the pages name come out with the run's ports.
    const framed = await get("www.forms.example.net", "/frame-same-site-en/");
    assert.ok(framed.body.includes(`src="${server.origin("forms")}/frame-same-site-en/inner.html"`), "the frame's address");
  } finally {
    await server.close();
  }
});
