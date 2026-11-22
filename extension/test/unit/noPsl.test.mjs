// The extension has no Public Suffix List and no rule of its own that finds a
// suffix or a registrable domain (design document, section 10.4): every site
// rule is the core's, and the core's list lives in the WASM package. A second
// list here could disagree with the core's and offer an item on a site the core
// would refuse.
import assert from "node:assert/strict";
import { readdirSync, readFileSync, statSync } from "node:fs";
import { join, relative } from "node:path";
import { test } from "node:test";
import { extensionRoot, repoRoot } from "./buildHelpers.mjs";

/** Entries of the real list (ICANN and private parts) that a copy of it, or a hand-made piece of it, would hold. */
const KNOWN_LINES = Object.freeze([
  "co.uk", "org.uk", "ac.uk", "gov.uk", "com.au", "net.au", "co.jp", "co.nz", "com.br", "com.cn",
  "github.io", "gitlab.io", "herokuapp.com", "blogspot.com", "appspot.com", "pages.dev", "vercel.app", "netlify.app",
  "s3.amazonaws.com", "cloudfront.net", "azurewebsites.net", "firebaseapp.com", "web.app", "workers.dev",
]);

/** File names that a copy of the list has. */
const LIST_FILE = /public[_-]?suffix|effective_tld_names|\.dat$/i;

/** Names in code that a suffix rule has. */
const SUFFIX_LOGIC = /\b(?:public_?suffix(?:es)?|registrable_?domain|registrableDomain|etld(?:\+1|plus_?one)?|effective_?tld|getDomain|psl)\b/i;

/**
 * Cutting a host (or any text) at its dots: the first step of every suffix rule written by hand, whether by
 * `split` or by looking for a dot with `indexOf` or `lastIndexOf`.
 */
const SPLIT_ON_DOTS = /\.(?:split|lastIndexOf|indexOf)\(\s*(?:"\."|'\.'|`\.`|\/\\\.\/[a-z]*)\s*[,)]/g;

/**
 * The places in shippable code that look for a dot and are no site rule, each with its line and its reason.
 * Nothing else may cut a text at its dots.
 */
const DOT_EXEMPT = Object.freeze([
  {
    path: "src/background/session.mjs",
    line: 'const last = name.slice(name.lastIndexOf(".") + 1);',
    why: "RESERVED_SUFFIXES: the special-use names of RFC 2606 and RFC 6761 that a release refuses as a server; not the Public Suffix List and no site rule",
  },
  {
    path: "scripts/build.mjs",
    line: 'const ext = path.slice(path.lastIndexOf("."));',
    why: "the extension of a file name in the package (for its media type), not a host",
  },
]);

/**
 * What is not checked, and why: the test sites hold real names of the list on purpose (they test the core's
 * list), and so do the test that checks them, their README and this file. The passkey spike's authenticator is a
 * throwaway test add-on with its own stand-in suffix set (never built into a package), and its test names entries
 * of it. TODO(passkey): the passkey provider uses the core's `validate_rp_id`; these two skips go when it lands.
 */
const SKIPPED = Object.freeze([
  "node_modules/",
  "dist/",
  "test/fixtures/",
  "test/unit/fixtures.test.mjs",
  "test/unit/noPsl.test.mjs",
  "test/unit/passkeySpike.test.mjs",
  "test/spikes/passkey/addon/authenticator.mjs",
  "test/firefox/README.md",
]);

/** Every file under `dir` (paths relative to the extension folder). @param {string} dir @returns {string[]} */
function walk(dir) {
  /** @type {string[]} */
  const out = [];
  for (const name of readdirSync(dir)) {
    const full = join(dir, name);
    const path = relative(extensionRoot, full).split("\\").join("/");
    if (SKIPPED.some((skip) => (skip.endsWith("/") ? `${path}/`.startsWith(skip) : path === skip))) continue;
    if (statSync(full).isDirectory()) out.push(...walk(full));
    else out.push(path);
  }
  return out;
}

/** The code of a file without its comments (a comment may name a rule; code may not have one). @param {string} text */
const codeOf = (text) => text.replace(/\/\*[\s\S]*?\*\//g, "").replace(/(^|[^:\\])\/\/.*$/gm, "$1");

/** Whether `text` names the list entry `line` at label boundaries. @param {string} text @param {string} line */
function names(text, line) {
  const at = new RegExp(`(^|[^a-z0-9-])${line.replace(/\./g, "\\.")}($|[^a-z0-9-])`, "i");
  return at.test(text);
}

/**
 * The problems of one file.
 * @param {string} path @param {string} text
 */
function problemsOf(path, text) {
  /** @type {string[]} */
  const out = [];
  if (LIST_FILE.test(path)) out.push(`${path}: a file named like the Public Suffix List`);
  const script = /\.(?:mjs|js)$/.test(path);
  // In a script, data is code (a comment that names an entry as an example holds no list); elsewhere all of it.
  const data = script ? codeOf(text) : text;
  for (const line of KNOWN_LINES) if (names(data, line)) out.push(`${path}: names the list entry ${line}`);
  // A rule is looked for in what can run in the extension: its sources, its build and the web vault's files it
  // copies. A test may split a token on its dots (a JWS) without being a suffix rule.
  if (script && /^(?:src|scripts|web\/src)\//.test(path)) {
    const code = data;
    const logic = SUFFIX_LOGIC.exec(code);
    if (logic) out.push(`${path}: ${logic[0]} (a suffix rule)`);
    for (const found of code.matchAll(SPLIT_ON_DOTS)) {
      const start = code.lastIndexOf("\n", found.index) + 1;
      const end = code.indexOf("\n", found.index);
      const line = code.slice(start, end < 0 ? undefined : end).trim();
      if (DOT_EXEMPT.some((e) => e.path === path && e.line === line)) continue;
      out.push(`${path}: cuts a text at its dots (${line.slice(0, 80)})`);
    }
  }
  return out;
}

test("there_is_no_psl_data_or_logic_under_extension", () => {
  const files = walk(extensionRoot).filter((p) => /\.(?:mjs|js|json|html|css|sh|md|txt)$/.test(p) || LIST_FILE.test(p));
  assert.ok(files.includes("src/background/frames.mjs") && files.includes("scripts/build.mjs"), "the walk reaches the sources");
  /** @type {string[]} */
  const problems = [];
  for (const path of files) problems.push(...problemsOf(path, readFileSync(join(extensionRoot, path), "utf8")));
  // The files the build copies from the web vault into the package (extension/shared.json) are checked too.
  const shared = /** @type {string[]} */ (JSON.parse(readFileSync(join(extensionRoot, "shared.json"), "utf8")));
  assert.ok(shared.length > 0);
  for (const file of shared) problems.push(...problemsOf(`web/src/${file}`, readFileSync(join(repoRoot, "web", "src", file), "utf8")));
  assert.deepEqual(problems, []);

  // The checks find what they are for.
  assert.notDeepEqual(problemsOf("src/x.mjs", 'const SUFFIXES = new Set(["co.uk", "github.io"]);'), []);
  assert.notDeepEqual(problemsOf("src/x.mjs", "export function registrableDomain(host) { return host; }"), []);
  assert.notDeepEqual(problemsOf("src/x.mjs", 'const labels = host.split(".");'), []);
  assert.notDeepEqual(problemsOf("src/x.mjs", "const labels = host.split(/\\./);"), []);
  assert.notDeepEqual(problemsOf("src/x.mjs", 'const tld = host.slice(host.lastIndexOf(".") + 1);'), []);
  assert.notDeepEqual(problemsOf("src/x.mjs", 'const rest = host.slice(host.indexOf(".", 1));'), []);
  // An exemption holds for its own line in its own file only, and the exempt lines are still there.
  assert.notDeepEqual(problemsOf("src/background/session.mjs", 'const tld = host.slice(host.lastIndexOf(".") + 1);'), []);
  assert.notDeepEqual(problemsOf("src/x.mjs", 'const last = name.slice(name.lastIndexOf(".") + 1);'), []);
  assert.deepEqual(problemsOf("src/background/session.mjs", 'const last = name.slice(name.lastIndexOf(".") + 1);'), []);
  for (const e of DOT_EXEMPT) assert.ok(readFileSync(join(extensionRoot, e.path), "utf8").includes(e.line), `${e.path}: the exempt line is still there`);
  assert.notDeepEqual(problemsOf("src/public_suffix_list.dat", "com\n"), []);
  assert.notDeepEqual(problemsOf("src/data/effective_tld_names.json", "[]"), []);
  // And leave alone what is not a list: a name that only contains an entry, a comment, an e-mail split.
  assert.deepEqual(problemsOf("src/x.mjs", '// the core decides that a.github.io and b.github.io are other sites\nconst host = "mygithub.iox";'), []);
  assert.deepEqual(problemsOf("src/x.mjs", 'const [name, domain] = email.split("@");'), []);
});
