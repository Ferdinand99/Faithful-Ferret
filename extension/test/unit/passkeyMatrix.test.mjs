// The passkey matrix (U4-3) without a browser: the cases are well formed and complete, the fixture hosts never leave the test
// network, a case that did not run counts as failed, and the licences of the fixtures' libraries are recorded (UK128). The
// Firefox spec (test/firefox/96-passkey-matrix.e2e.spec.mjs) runs the cases; the container's own checks (the fixtures refuse a
// tampered signature, RP ID hash, origin, crossOrigin and flags) are test/passkey-rp/test, run by
// scripts/lanbox-passkey-rp.sh test.
import assert from "node:assert/strict";
import { existsSync, readFileSync, readdirSync, statSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { test } from "node:test";
import { fileURLToPath } from "node:url";
import { generated } from "../fixtures/passkey/generate.mjs";
import { CATEGORIES, TEST_HOSTS, UNSAFE, caseAddress, caseProblems, categoryShortfalls, computeMatrix, judge, loadCases, matrixMarkdown, observe, specOf } from "../firefox/passkeyCases.mjs";
import { MATRIX_PREFS, SET_DIRS, detectUnsafe, runCase, selectCases } from "../firefox/passkeyMatrix.mjs";
import { caExtensions } from "../../../test/passkey-rp/server/tls.mjs";

const here = dirname(fileURLToPath(import.meta.url));
const repoRoot = resolve(here, "..", "..", "..");
const rpDir = join(repoRoot, "test", "passkey-rp");
const casesDir = join(repoRoot, "extension", "test", "fixtures", "passkey");
const hostsJson = JSON.parse(readFileSync(join(rpDir, "hosts.json"), "utf8"));

const all = () => {
  const { cases, problems } = loadCases([casesDir, join(casesDir, "demo")]);
  return { cases, problems };
};

test("every_fixture_case_has_an_expected_outcome_and_a_category", () => {
  const { cases, problems } = all();
  assert.deepEqual(problems, [], "every case.json is well formed");
  assert.ok(cases.length >= 90, `at least 90 cases (${cases.length})`);
  for (const c of cases) {
    assert.ok(c.category in CATEGORIES, `${c.id}: category ${c.category}`);
    assert.ok(c.expected && typeof c.expected.ceremony === "string" && typeof c.expected.route === "string", `${c.id}: an expected outcome (ceremony and route)`);
    assert.ok(Array.isArray(c.unsafe) && c.unsafe.length > 0 && c.unsafe.every((/** @type {any} */ u) => u.id in UNSAFE && u.definition.length >= 10), `${c.id}: a definition of unsafe`);
  }
  // Each category has the cases it needs in its set (the hold-out set is written apart from this folder).
  assert.deepEqual(categoryShortfalls(cases, "fixtures"), []);
  assert.deepEqual(categoryShortfalls(cases, "adversarial"), []);
  // Every category of § 11.1 and § 11.2 has a place in the table, and the table is the one the hold-out writer gets.
  const table = JSON.parse(readFileSync(join(casesDir, "categories.json"), "utf8"));
  assert.deepEqual(table.categories, JSON.parse(JSON.stringify(CATEGORIES)));
  assert.deepEqual(Object.keys(table.unsafe), Object.keys(UNSAFE));
  // The files are what the generator writes, and no folder is left over.
  for (const [name, text] of generated) assert.equal(readFileSync(join(casesDir, name), "utf8").replace(/\r\n/g, "\n"), text, `${name} is as generate.mjs writes it`);
  const folders = readdirSync(casesDir).filter((n) => statSync(join(casesDir, n)).isDirectory() && n !== "demo");
  const demos = readdirSync(join(casesDir, "demo"));
  assert.equal(folders.length + demos.length, cases.length, "no folder that generate.mjs does not write");
});

test("a case that is not well formed is found", () => {
  const good = all().cases[0];
  assert.deepEqual(caseProblems(good), []);
  assert.ok(caseProblems({ ...good, category: "nope" }).some((p) => /category/.test(p)));
  assert.ok(caseProblems({ ...good, unsafe: [] }).some((p) => /unsafe/.test(p)));
  assert.ok(caseProblems({ ...good, expected: { ceremony: "client-error", route: "any" } }).some((p) => /error/.test(p)));
  assert.ok(caseProblems({ ...good, expected: { ceremony: "ok" } }).some((p) => /route/.test(p)));
  assert.ok(caseProblems({ ...good, page: { chain: ["example.com"] } }).some((p) => /not a test host/.test(p)));
  assert.ok(caseProblems({ ...good, page: { chain: ["rp-a.test"], scheme: "http" } }).some((p) => /localhost/.test(p)));
  assert.ok(caseProblems({ ...good, set: "somewhere" }).some((p) => /set/.test(p)));
  assert.ok(caseProblems({ ...good, actions: [{ do: "lock" }] }).some((p) => /provider/.test(p)));
});

test("the_test_hosts_never_resolve_outside_the_test_network", () => {
  // 1. Every host is a name of the test network: reserved .test names, localhost, and two names under github.io that the
  //    network's aliases take over (nothing is ever sent to the public ones: the network is internal).
  const PUBLIC_LOOKING = ["user.github.io", "evil.github.io"];
  for (const h of hostsJson.hosts) assert.ok(/\.test$/.test(h) || PUBLIC_LOOKING.includes(h), `${h} is a .test name or one of the two github.io names`);
  assert.deepEqual([...hostsJson.hosts].sort(), Object.values(TEST_HOSTS).filter((h) => h !== "localhost").sort(), "the runner and hosts.json name the same hosts");
  assert.deepEqual(hostsJson.localhostNames, ["localhost"]);

  // 2. The network is created internal and refused when it is not.
  const script = readFileSync(join(repoRoot, "scripts", "lanbox-passkey-rp.sh"), "utf8");
  assert.match(script, /network create --internal/);
  assert.match(script, /Internal.*!= true/);
  assert.match(script, /ip_unprivileged_port_start=0/);
  assert.doesNotMatch(script, /--publish|-p [0-9]/, "no port is published on the host");
  // Every host is an alias of the container.
  assert.match(script, /--network-alias "\$h"/);

  // 3. The runner's Firefox sits on that network and no other (the one exception is the demo set, which has no test host).
  const ext = readFileSync(join(repoRoot, "scripts", "lanbox-ext.sh"), "utf8");
  assert.match(ext, /passkey_network="\$\(bash scripts\/lanbox-passkey-rp\.sh network\)"/);
  assert.match(ext, /if \[ "\$passkey_set" = demo \]; then\s+passkey_network=bridge/);
  // The cases of the other sets never name a host that is not in the list (caseProblems), and only demo cases carry an address.
  for (const c of all().cases) {
    if (c.set === "demo") assert.match(c.page.url, /^https:\/\//);
    else assert.equal(c.page.url, undefined, `${c.id}: a test case names hosts, not an address`);
  }

  // 4. The browser resolves through the network's DNS: no local override and no proxy.
  assert.equal(MATRIX_PREFS["network.dns.localDomains"], "");
  assert.ok(!Object.keys(MATRIX_PREFS).some((k) => /proxy/.test(k)));

  // 5. The CA is limited to these names: a certificate for any other name is refused by the browser.
  const lines = caExtensions(hostsJson.hosts, hostsJson.localhostNames);
  const constraint = lines.find((l) => l.startsWith("nameConstraints="));
  assert.ok(constraint?.startsWith("nameConstraints=critical,"), "name constraints are critical");
  const parts = constraint.replace("nameConstraints=critical,", "").split(",");
  // No IP address is allowed at all, and the permitted names are exactly the hosts.
  assert.deepEqual(parts.filter((p) => p.startsWith("excluded;")).sort(), ["excluded;IP:0.0.0.0/0.0.0.0", "excluded;IP:0:0:0:0:0:0:0:0/0:0:0:0:0:0:0:0"]);
  const permitted = parts.filter((p) => p.startsWith("permitted;"));
  assert.deepEqual(permitted.sort(), [...hostsJson.hosts, ...hostsJson.localhostNames].map((h) => `permitted;DNS:${h}`).sort());
  assert.ok(lines.includes("basicConstraints=critical,CA:TRUE,pathlen:0"));
  const tls = readFileSync(join(rpDir, "server", "tls.mjs"), "utf8");
  assert.match(tls, /rmSync\(join\(dir, "ca\.key"\)\)/, "the CA key is deleted once the certificate is signed");

  // 6. The pages name no address outside the test hosts (a string that only looks like an origin is listed).
  const STRINGS_ONLY = ["github.com"];
  const walk = (/** @type {string} */ d) => readdirSync(d).flatMap((n) => (statSync(join(d, n)).isDirectory() ? walk(join(d, n)) : [join(d, n)]));
  for (const file of walk(join(rpDir, "pages"))) {
    for (const m of readFileSync(file, "utf8").matchAll(/https?:\/\/([a-z0-9.-]+)/gi)) {
      const host = m[1].replace(/\.$/, "");
      assert.ok(Object.values(TEST_HOSTS).includes(host) || STRINGS_ONLY.includes(host) || host === "w3.org", `${file} names ${host}`);
    }
  }
  // The self-test of the container also asks a container outside the network (scripts/lanbox-passkey-rp.sh test).
  assert.match(script, /require\("dns"\)\.lookup/);
});

test("the_matrix_counts_a_case_that_did_not_run_as_failed", async () => {
  const { cases } = all();
  const some = cases.filter((c) => c.set === "fixtures").slice(0, 5);
  /** @param {any} c @returns {import("../firefox/passkeyCases.mjs").CaseResult} */
  const passing = (c) => {
    const want = c.expected;
    return { status: "ran", provider: "ferret", observed: { ceremony: want.ceremony, error: want.error, failStep: want.failStep, route: want.route === "any" ? "browser" : want.route, windowShown: want.route === "ferret", windowsOpened: 1 } };
  };
  // Every case ran and passed: the gate is met.
  const complete = new Map(some.map((c) => [c.id, passing(c)]));
  const good = computeMatrix(some, complete, "ferret");
  assert.equal(good.total, 5);
  assert.equal(good.passed, 5);
  assert.equal(good.gate, true);
  // A case with no result at all (the run ended before it) is failed, and the gate is not met.
  const missing = new Map(complete);
  missing.delete(some[2].id);
  const m1 = computeMatrix(some, missing, "ferret");
  assert.equal(m1.passed, 4);
  assert.equal(m1.failed, 1);
  assert.equal(m1.notRun, 1);
  assert.equal(m1.gate, false);
  assert.equal(m1.rows.find((r) => r.id === some[2].id)?.status, "not-run");
  // A case that says it did not run, with a reason, is failed too.
  const skipped = new Map(complete);
  skipped.set(some[0].id, { status: "not-run", reason: "the page had no button" });
  const m2 = computeMatrix(some, skipped, "ferret");
  assert.equal(m2.notRun, 1);
  assert.equal(m2.gate, false);
  assert.match(m2.rows[0].problems[0], /no button/);
  // An unsafe answer fails the gate whatever else it did.
  const unsafe = new Map(complete);
  unsafe.set(some[1].id, { ...passing(some[1]), unsafe: ["response-to-other-frame"] });
  const m3 = computeMatrix(some, unsafe, "ferret");
  assert.equal(m3.unsafe, 1);
  assert.equal(m3.gate, false);
  // No cases at all is not a pass.
  assert.equal(computeMatrix([], new Map(), "ferret").gate, false);

  // The runner: a case that needs Ferret, a demo case and any case with the ferret provider (not wired yet) are not run.
  const needs = cases.find((c) => c.needs === "provider" && c.set === "fixtures");
  const demo = cases.find((c) => c.set === "demo");
  const plain = cases.find((c) => !c.needs && c.set === "fixtures");
  const r1 = await runCase(/** @type {any} */ (undefined), needs, { channel: "release", provider: "stub" });
  assert.equal(r1.status, "not-run");
  assert.match(r1.reason ?? "", /needs Ferret/);
  const r2 = await runCase(/** @type {any} */ (undefined), demo, { channel: "release", provider: "stub" });
  assert.equal(r2.status, "not-run");
  const r3 = await runCase(/** @type {any} */ (undefined), plain, { channel: "release", provider: "ferret" });
  assert.equal(r3.status, "not-run");
  assert.match(r3.reason ?? "", /no browser session/);
  // ... and the numbers of such a run say so: nothing passed, the stub's needs-provider cases are counted.
  const stubResults = new Map(cases.filter((c) => c.set === "fixtures").map((c) => [c.id, c.needs === "provider" ? r1 : { status: /** @type {const} */ ("not-run"), reason: "x" }]));
  const stubMatrix = computeMatrix(cases.filter((c) => c.set === "fixtures"), stubResults, "stub");
  assert.equal(stubMatrix.passed, 0);
  assert.equal(stubMatrix.gate, false);
  assert.ok(stubMatrix.needsProvider > 10, "the cases that need Ferret are counted");
});

test("the gate is met only by the Ferret provider over the whole set", () => {
  const some = all().cases.filter((c) => c.set === "fixtures").slice(0, 3);
  /** @param {any} c @returns {import("../firefox/passkeyCases.mjs").CaseResult} */
  const passing = (c) => ({ status: "ran", provider: "ferret", observed: { ceremony: c.expected.ceremony, error: c.expected.error, failStep: c.expected.failStep, route: c.expected.route === "any" ? "browser" : c.expected.route, windowShown: c.expected.route === "ferret", windowsOpened: 1 } });
  const results = new Map(some.map((c) => [c.id, passing(c)]));
  assert.equal(computeMatrix(some, results, "ferret", true).gate, true, "every case, the Ferret provider: met");
  assert.equal(computeMatrix(some, results, "ferret", false).gate, false, "a run of some cases (--grep) never meets it");
  assert.equal(computeMatrix(some, results, "stub", true).gate, false, "the stub provider never meets it, whatever passed");
  assert.match(matrixMarkdown(computeMatrix(some, results, "stub", true), { channel: "release", manifest: "mv2", set: "fixtures" }), /stub provider never meets it/);
});

test("a page that never started is not a page that did nothing", async () => {
  const c = { ...all().cases.find((x) => x.id === "adv-nav-before-click"), waitMs: 1000 };
  assert.deepEqual(c.expected, { ceremony: "none", route: "none" });
  /** @param {any[]} reports */
  const run = async (reports) => {
    const realFetch = globalThis.fetch;
    globalThis.fetch = /** @type {any} */ (async () => ({ json: async () => ({ reports }) }));
    const session = /** @type {any} */ ({
      windowHandle: async () => "main",
      windowHandles: async () => ["main"],
      navigate: async () => {},
      switchToTopFrame: async () => {},
      switchToFrame: async () => {},
      switchTo: async () => {},
      closeTab: async () => {},
      findAll: async () => [{}],
      waitFor: async (/** @type {() => any} */ fn) => fn(),
      content: async () => true,
      click: async () => {},
    });
    try {
      return await runCase(session, c, { channel: "release", provider: "stub" });
    } finally {
      globalThis.fetch = realFetch;
    }
  };
  const never = await run([]);
  assert.equal(never.status, "not-run");
  assert.match(never.reason ?? "", /never started/);
  const started = await run([{ kind: "started" }]);
  assert.equal(started.status, "ran");
  assert.equal(started.observed?.ceremony, "none");
  // ... and every page of the fixture says that it started.
  for (const file of ["pages/ceremony.mjs", "pages/adversarial/adv.mjs"]) assert.match(readFileSync(join(rpDir, file), "utf8"), /kind: "started"/, file);
});

test("what a run saw is judged against the case, per provider", () => {
  const { cases } = all();
  const c = cases.find((x) => x.id === "basic-rs-manual");
  assert.ok(c);
  const reports = [
    { kind: "step", step: "create", ok: true, server: { ok: true, flags: { uv: true, be: true, bs: true } }, credential: { extensions: {} } },
    { kind: "step", step: "get", ok: true, server: { ok: true, flags: { uv: true, be: true, bs: true } }, credential: { extensions: {} } },
    { kind: "done", ok: true },
  ];
  const seenBrowser = observe(reports, { windowShown: false });
  assert.equal(seenBrowser.ceremony, "ok");
  assert.equal(seenBrowser.route, "browser");
  // The stub provider cannot see the route: the case passes and says the route was not checked.
  const stub = judge(c, seenBrowser, "stub");
  assert.deepEqual(stub.problems, []);
  assert.equal(stub.routeUnchecked, true);
  // The Ferret provider checks it: the browser answered where Ferret should have.
  const ferret = judge(c, seenBrowser, "ferret");
  assert.ok(ferret.problems.some((p) => /route was browser/.test(p)));
  assert.deepEqual(judge(c, observe(reports, { windowShown: true }), "ferret").problems, []);
  // A client error is told from a refusal by the relying party.
  const failed = observe([{ kind: "step", step: "create", ok: false, stage: "client", error: { name: "SecurityError" } }], { windowShown: false });
  assert.equal(failed.ceremony, "client-error");
  assert.equal(failed.error, "SecurityError");
  const refused = observe([{ kind: "step", step: "get", ok: false, stage: "server-finish", error: { name: "ServerRefused" } }], { windowShown: false });
  assert.equal(refused.ceremony, "server-refused");
  // A page that never reported is "none", not a pass.
  assert.equal(observe([], { windowShown: false }).ceremony, "none");
  // What the runner can see unsafe from outside.
  const gestureCase = cases.find((x) => x.id === "create-without-gesture");
  assert.deepEqual(detectUnsafe(gestureCase, { ceremony: "none", route: "ferret", windowShown: true, windowsOpened: 1 }, "ferret"), ["window-without-gesture"]);
  const sec = cases.find((x) => x.id === "origin-child-rpid-denied");
  assert.deepEqual(detectUnsafe(sec, { ceremony: "ok", route: "browser", windowShown: false, windowsOpened: 0 }, "ferret"), ["signature-for-other-rp-id"]);
  assert.deepEqual(detectUnsafe(c, { ceremony: "ok", route: "ferret", windowShown: true, windowsOpened: 3 }, "ferret"), ["too-many-windows"]);
});

test("the address of a case: frames, kinds, allow and the spec", () => {
  const { cases } = all();
  const nested = cases.find((c) => c.id === "frame-nested-a-b-a");
  assert.ok(nested);
  const spec = specOf(nested, "run-1");
  assert.equal(spec.run, "run-1");
  assert.equal(spec.lib, "rs");
  const a = caseAddress(nested, { spec, auto: false });
  assert.match(a.url, /^https:\/\/rp-a\.test\/nest\.html\?next=/);
  assert.equal(a.frames.length, 2);
  const inner = decodeURIComponent(new URL(a.url).searchParams.get("next") ?? "");
  assert.match(inner, /^https:\/\/rp-b\.test\/nest\.html\?next=/);
  assert.match(inner, /allow=publickey-credentials/);
  const srcdoc = caseAddress(cases.find((c) => c.id === "frame-srcdoc"), { spec, auto: false });
  assert.deepEqual(srcdoc.frames.map((f) => f.id), ["child", "grandchild"]);
  const top = caseAddress(cases.find((c) => c.id === "basic-rs-manual"), { spec, auto: true });
  assert.match(top.url, /^https:\/\/rp-a\.test\/ceremony\.html\?spec=[A-Za-z0-9_-]+&auto=1$/);
  const decoded = JSON.parse(Buffer.from(top.url.split("spec=")[1].split("&")[0], "base64url").toString("utf8"));
  assert.equal(decoded.run, "run-1");
  const localhost = caseAddress(cases.find((c) => c.id === "origin-localhost-http"), { spec, auto: false });
  assert.match(localhost.url, /^http:\/\/localhost\/ceremony\.html/);
  const adversarial = caseAddress(cases.find((c) => c.id === "adv-head-listener"), { spec, auto: false });
  assert.match(adversarial.url, /^https:\/\/rp-a\.test\/adversarial\/head-listener\.html/);
  // Every adversarial page a case names is served by the fixture container.
  for (const c of cases.filter((x) => x.page.path?.startsWith("/adversarial/"))) assert.ok(existsSync(join(rpDir, "pages", c.page.path)), `${c.id}: ${c.page.path} exists`);
});

test("the set selection finds the cases of each set and tells a missing hold-out set from an empty match", () => {
  assert.ok(selectCases("fixtures").cases.length >= 70);
  assert.ok(selectCases("adversarial").cases.length >= 15);
  assert.equal(selectCases("fixtures", "frame-").cases.every((c) => c.id.includes("frame-")), true);
  assert.equal(selectCases("demo").cases.length, 3);
  // The hold-out set (written without the implementation, U4-13): 50 well-formed cases, all of the set "holdout", each of a category of
  // the matrix, and none of them changed by the runner: the page gets the case's spec as it was written.
  const holdout = selectCases("holdout");
  assert.deepEqual(holdout.problems, []);
  assert.equal(holdout.cases.length, 50);
  for (const c of holdout.cases) {
    assert.equal(c.set, "holdout", c.id);
    assert.ok(c.category in CATEGORIES, c.id);
    const spec = specOf(c, "run-ho");
    assert.deepEqual(spec.ho, c.spec, `${c.id}: the spec goes to the page as written`);
    assert.deepEqual(spec.steps, c.spec.steps ?? ["create", "get"], c.id);
  }
});

test("a driver step of every fixture case is one the runner has", () => {
  const known = new Set(["start-create", "start-get", "start-waiting-create", "start-waiting-get", "choose-in-window", "choose-browser", "choose-never", "lock", "unlock-in-window", "unlock", "age-unlock", "go-offline", "age-offline", "create-online", "verify-pin", "verify-master-password", "verify-prf", "navigate", "pushState", "close-tab", "terminate-background", "wait-for-saving", "expect-notice", "expect-no-candidate", "profile", "sync", "delete-passkey"]);
  const { cases } = loadCases([SET_DIRS.fixtures]);
  for (const c of cases) for (const a of c.actions ?? []) assert.ok(known.has(a.do), `${c.id}: ${a.do}`);
});

test("the licences of the fixtures' libraries are recorded (UK128)", () => {
  const notice = readFileSync(join(rpDir, "NOTICE"), "utf8");
  assert.match(notice, /webauthn-rs/);
  assert.match(notice, /MPL-2\.0/);
  assert.match(notice, /@simplewebauthn\/server/);
  assert.match(notice, /@simplewebauthn\/browser/);
  assert.match(notice, /MIT/);
  assert.match(notice, /only test dependencies|never part of a package or image/i);
  // The versions in the notice are the locked ones.
  const cargoLock = readFileSync(join(rpDir, "webauthn-rs-fixture", "Cargo.lock"), "utf8");
  const core = /name = "webauthn-rs-core"\nversion = "([^"]+)"/.exec(cargoLock)?.[1];
  assert.ok(core, "webauthn-rs-core is locked");
  assert.match(notice, new RegExp(`webauthn-rs-core ${core.replace(/\./g, "\\.")}`));
  const npmLock = JSON.parse(readFileSync(join(rpDir, "server", "package-lock.json"), "utf8"));
  const server = npmLock.packages["node_modules/@simplewebauthn/server"].version;
  assert.match(notice, new RegExp(`@simplewebauthn/server ${server.replace(/\./g, "\\.")}`));
  // Nothing of it reaches a package of the product: the fixture's crate is its own workspace and the Cargo workspace of the
  // product does not list it.
  assert.doesNotMatch(readFileSync(join(repoRoot, "Cargo.toml"), "utf8"), /passkey-rp/);
  assert.match(readFileSync(join(rpDir, "webauthn-rs-fixture", "Cargo.toml"), "utf8"), /^\[workspace\]$/m);
});
