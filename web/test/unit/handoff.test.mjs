import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { test } from "node:test";
import { codeFromHash, run, safeTarget } from "../../admin/handoff.mjs";
import { completeHandoff, goToAdmin } from "../../src/flows/handoff.mjs";
import { web } from "./helpers.mjs";

const CODE = "A".repeat(43);
const CHALLENGE = "B".repeat(43);
const ADMIN = "https://admin.ferret.test";
const ORIGIN = ADMIN;

/** A fake browser for the admin page: the address, its history and a fetch that answers. */
function browser({ hash = `#code=${CODE}`, answer = { ok: true, json: async () => ({ next: "/settings" }) } } = {}) {
  const log = { replaced: [], navigated: [], requests: [] };
  const location = {
    hash,
    pathname: "/auth/handoff",
    search: "",
    origin: ORIGIN,
    replace: (url) => log.navigated.push(url),
  };
  const history = { replaceState: (_state, _title, url) => log.replaced.push(url) };
  const fetch = async (url, init) => {
    log.requests.push({ url, init });
    if (answer instanceof Error) throw answer;
    return answer;
  };
  return { env: { location, history, fetch }, log };
}

test("fragment_carries_only_the_code", async () => {
  assert.equal(codeFromHash(`#code=${CODE}`), CODE);
  assert.equal(codeFromHash(`code=${CODE}`), CODE);
  // Anything else in the fragment, or a code of the wrong shape, is no code.
  for (const hash of ["", "#", "#code=", `#code=${CODE}&next=/evil`, `#next=/x&code=${CODE}`, `#token=${CODE}`, `#code=${CODE}x`, `#code=${CODE.slice(1)}`, "#code=%3Cscript%3E", `#code=${CODE}&code=${CODE}`]) {
    assert.equal(codeFromHash(hash), null, hash);
  }

  const { env, log } = browser();
  assert.equal(await run(env), true);
  // The fragment is gone from the address before anything else happens.
  assert.deepEqual(log.replaced, ["/auth/handoff"]);
  assert.equal(log.requests.length, 1);
  const [{ url, init }] = log.requests;
  // The code is in the body only: not in the URL, not in a header.
  assert.equal(url, "/api/auth/handoff/redeem");
  assert.deepEqual(JSON.parse(init.body), { code: CODE });
  assert.ok(!url.includes(CODE));
  assert.ok(!JSON.stringify(init.headers).includes(CODE));
  assert.equal(init.method, "POST");
  assert.equal(init.credentials, "same-origin");
  assert.equal(init.referrerPolicy, "no-referrer");
  assert.equal(init.headers["ferret-protocol"], "1");
  assert.deepEqual(log.navigated, [`${ORIGIN}/settings`]);
});

test("a_fragment_that_is_not_a_code_is_removed_and_nothing_is_sent", async () => {
  const { env, log } = browser({ hash: "#code=short" });
  assert.equal(await run(env), false);
  assert.deepEqual(log.replaced, ["/auth/handoff"]);
  assert.equal(log.requests.length, 0);
  assert.equal(log.navigated.length, 0);
});

test("client_checks_next_with_the_url_parser_not_a_prefix", async () => {
  // Same origin: followed.
  for (const next of ["/", "/settings/users?tab=a", "/a/b#c", `${ORIGIN}/settings`]) {
    assert.ok(safeTarget(next, ORIGIN)?.startsWith(ORIGIN), next);
  }
  // Another origin, or a value the parser turns into one: refused. A tab or a
  // line feed inside "/<tab>/evil.test" is dropped by the parser, leaving
  // "//evil.test", which a prefix check on "/" would let through.
  for (const next of ["//evil.test", "/\t/evil.test", "/\n/evil.test", "/\\evil.test", "\\\\evil.test", "https://evil.test/", "http://admin.ferret.test", "javascript:alert(1)", "data:text/html,x", `${ORIGIN}.evil.test/`, "https://admin.ferret.test@evil.test/", null, 5, undefined]) {
    assert.equal(safeTarget(next, ORIGIN), null, String(next));
  }
  // And the run does not navigate to one.
  for (const next of ["//evil.test", "/\t/evil.test", "https://evil.test/"]) {
    const { env, log } = browser({ answer: { ok: true, json: async () => ({ next }) } });
    assert.equal(await run(env), false, next);
    assert.deepEqual(log.navigated, [], next);
  }
});

test("a_failed_redeem_goes_nowhere", async () => {
  for (const answer of [
    { ok: false, json: async () => ({ error: "handoff_invalid" }) },
    { ok: true, json: async () => { throw new Error("not json"); } },
    { ok: true, json: async () => ({}) },
    new Error("offline"),
  ]) {
    const { env, log } = browser({ answer });
    assert.equal(await run(env), false);
    assert.deepEqual(log.navigated, []);
  }
});

test("go_to_admin_starts_the_flow_on_the_admin_origin", async () => {
  /** @type {string[]} */
  const seen = [];
  await goToAdmin({ adminUrl: ADMIN, next: "/settings/users", navigate: (u) => seen.push(u) });
  await goToAdmin({ adminUrl: `${ADMIN}/`, next: "/settings", purpose: "reauth", navigate: (u) => seen.push(u) });
  await goToAdmin({ adminUrl: ADMIN, navigate: (u) => seen.push(u) });
  // A next that is not a plain path is replaced by "/".
  await goToAdmin({ adminUrl: ADMIN, next: "//evil.test", navigate: (u) => seen.push(u) });
  await goToAdmin({ adminUrl: ADMIN, next: "/a\tb", navigate: (u) => seen.push(u) });
  assert.deepEqual(seen, [
    `${ADMIN}/auth/handoff/begin?next=%2Fsettings%2Fusers`,
    `${ADMIN}/auth/handoff/begin?next=%2Fsettings&purpose=reauth`,
    `${ADMIN}/auth/handoff/begin?next=%2F`,
    `${ADMIN}/auth/handoff/begin?next=%2F`,
    `${ADMIN}/auth/handoff/begin?next=%2F`,
  ]);
  await assert.rejects(goToAdmin({ adminUrl: ADMIN, purpose: "other", navigate: () => {} }));
  await assert.rejects(goToAdmin({ adminUrl: "ftp://admin.ferret.test", navigate: () => {} }));
  await assert.rejects(goToAdmin({ adminUrl: "https://user:pw@admin.ferret.test", navigate: () => {} }));
});

test("complete_handoff_mints_a_code_and_puts_only_the_code_in_the_fragment", async () => {
  const calls = [];
  const api = {
    post: async (path, body) => {
      calls.push({ path, body });
      return { code: CODE, expires_in: 60 };
    },
  };
  /** @type {string[]} */
  const seen = [];
  await completeHandoff({ api, challenge: CHALLENGE, next: "/settings", purpose: "login", adminUrl: ADMIN, navigate: (u) => seen.push(u) });
  assert.deepEqual(calls, [{ path: "/api/auth/handoff", body: { purpose: "login", next: "/settings", challenge: CHALLENGE } }]);
  assert.deepEqual(seen, [`${ADMIN}/auth/handoff#code=${CODE}`]);
  // The fragment holds the code and nothing else: no challenge, no next.
  assert.ok(!seen[0].includes(CHALLENGE));
  assert.ok(!seen[0].includes("settings"));

  await completeHandoff({ api, challenge: CHALLENGE, next: "//evil.test", purpose: "reauth", adminUrl: ADMIN, navigate: (u) => seen.push(u) });
  assert.deepEqual(calls[1].body, { purpose: "reauth", next: "/", challenge: CHALLENGE });
});

test("complete_handoff_refuses_what_it_cannot_trust", async () => {
  const api = { post: async () => ({ code: CODE }) };
  const base = { api, challenge: CHALLENGE, adminUrl: ADMIN, navigate: () => assert.fail("navigated") };
  await assert.rejects(completeHandoff({ ...base, challenge: "short" }));
  await assert.rejects(completeHandoff({ ...base, purpose: "other" }));
  await assert.rejects(completeHandoff({ ...base, adminUrl: "javascript:alert(1)" }));
  // A code of the wrong shape from the server is not put in a URL.
  for (const code of ["", "short", `${CODE}#x`, `${CODE.slice(1)}/`, 5, undefined]) {
    await assert.rejects(completeHandoff({ ...base, api: { post: async () => ({ code }) } }), String(code));
  }
  // A failed call is the caller's to show.
  await assert.rejects(completeHandoff({ ...base, api: { post: async () => { throw new Error("401"); } } }));
});

test("the_admin_page_has_one_script_no_password_field_and_no_wasm", () => {
  const html = readFileSync(join(web, "admin", "handoff.html"), "utf8");
  const scripts = [...html.matchAll(/<script\b[^>]*>/gi)].map((m) => m[0]);
  assert.equal(scripts.length, 1);
  assert.match(scripts[0], /\ssrc="\/auth\/handoff\.mjs"/);
  assert.doesNotMatch(html, /type\s*=\s*["']?password/i);
  assert.doesNotMatch(html, /wasm|pkg-web|vault\.worker/i);
  assert.doesNotMatch(html, /<script[^>]*>[^<]+<\/script>/i);
  // The script is plain: no WASM, no framework, no dynamic code.
  const script = readFileSync(join(web, "admin", "handoff.mjs"), "utf8");
  assert.doesNotMatch(script, /\bimport\b\s*[("'{*\w]|WebAssembly|\beval\s*\(|new\s+Function|innerHTML|document\.write/);
});
