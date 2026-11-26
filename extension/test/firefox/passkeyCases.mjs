// The passkey matrix (U4): what a case may say (case.json), which cases each category must have, and how the
// results of a run turn into the numbers of the gate. No browser in here: the runner (passkeyMatrix.mjs) drives
// Firefox and hands what it saw to `computeMatrix`; the unit tests (test/unit/passkeyMatrix.test.mjs) use the same
// functions on made-up results.
//
// A case is a folder `<set>/<id>/case.json` (fixtures: test/fixtures/passkey, hold-out: test/fixtures/passkey-holdout).
// The pages it uses are served by the fixture container (test/passkey-rp). The schema is test/fixtures/passkey/case.schema.json,
// the categories test/fixtures/passkey/categories.json; the pieces of a case in short:
//
//   id, set (fixtures | adversarial | holdout | demo), category, title
//   rp        { lib: "rs" | "swa", client: "swa" | "manual" | "pubkey" }  which relying party and which client code
//   page      { chain: [host, ...], kinds?: [...], allow?: [...], scheme?, path? }   the top page is chain[0], the ceremony runs on
//             the last host; kinds[i] is how chain[i] frames chain[i+1] (iframe | srcdoc | blank | sandbox | sandbox-same)
//   spec      what the ceremony page does (see test/passkey-rp/pages/lib.mjs): steps, rpId, user, create, get ...
//   gesture   "click" (a real click on #go) or "none" (the page starts at once, with no user activation)
//   expected  { ceremony, error?, failStep?, route, flags? }  and, where the stub provider (the browser path) must give
//             another answer than Ferret would, `stub` with the same members
//   unsafe    [{ id, definition }]  what an unsafe answer is for this case (at least one)
//   needs     "provider" when the case can only be judged with Ferret answering (a window, a verification, a navigation
//             while a request waits); the stub provider cannot run it and it counts as not run
import { existsSync, readdirSync, readFileSync, statSync, writeFileSync } from "node:fs";
import { join } from "node:path";

/** The sets of cases. */
export const SETS = Object.freeze(["fixtures", "adversarial", "holdout", "demo"]);

/** The test hosts (test/passkey-rp/hosts.json): every one of them lives inside the test network only. */
export const TEST_HOSTS = Object.freeze({
  A: "rp-a.test",
  LOGIN: "login.rp-a.test",
  B: "rp-b.test",
  ATTACKER: "attacker.test",
  VAULT: "vault-fixture.test",
  USER_GITHUB: "user.github.io",
  EVIL_GITHUB: "evil.github.io",
  IDN: "xn--rp--8cd.test",
  LOCALHOST: "localhost",
});

export const CEREMONIES = Object.freeze(["ok", "client-error", "server-refused", "none"]);
export const ROUTES = Object.freeze(["ferret", "browser", "none", "any"]);
export const FRAME_KINDS = Object.freeze(["iframe", "srcdoc", "blank", "sandbox", "sandbox-same"]);
export const CLIENT_ERRORS = Object.freeze(["NotAllowedError", "SecurityError", "InvalidStateError", "AbortError", "TypeError", "NotSupportedError", "ConstraintError", "UnknownError"]);

/**
 * The unsafe answers of § 11.3: a run with one of them fails whatever else it does.
 * @type {Readonly<Record<string, string>>}
 */
export const UNSAFE = Object.freeze({
  "response-to-other-frame": "an answer to another origin or frame than the one that asked",
  "response-to-foreign-ancestor": "an answer to a frame that has a foreign ancestor",
  "up-without-click": "user presence without a click in Ferret's own window or popup",
  "uv-without-verification": "user verification set without a verification (or a recent unlock) for the request",
  "signature-for-other-rp-id": "a signature for an RP ID that is not exactly the stored one",
  "window-without-gesture": "a Ferret window without a user gesture",
  "error-differs": "a difference in error type or time between \"cancelled\" and \"no match\"",
  "key-outside-core": "a private key outside the core",
  "passkey-not-delivered": "a passkey in the vault that the site never got, outside the trash",
  // Not in § 11.3's list but seen from outside by the runner: the plan allows one Ferret window at a time (UK129).
  "too-many-windows": "more Ferret windows at a time than the request limit allows (one)",
});

/**
 * The categories of the matrix and how many cases each must have in its set (the hold-out set uses the same
 * categories and has at least 10 cases in all). The table is also in test/fixtures/passkey/categories.json.
 * @type {Readonly<Record<string, { set: "fixtures" | "adversarial", min: number, summary: string }>>}
 */
export const CATEGORIES = Object.freeze({
  "create-basic": { set: "fixtures", min: 6, summary: "create and sign in with every relying party and client code" },
  "create-options": { set: "fixtures", min: 8, summary: "residentKey, userVerification, attestation and authenticatorAttachment" },
  "create-algs": { set: "fixtures", min: 4, summary: "pubKeyCredParams: empty, ES256 and RS256, RS256 only, EdDSA only" },
  "create-exclude": { set: "fixtures", min: 2, summary: "excludeCredentials with and without a Ferret match" },
  "create-extensions": { set: "fixtures", min: 4, summary: "credProps, prf with and without eval, appid" },
  "create-users": { set: "fixtures", min: 4, summary: "two users on one relying party, the same user.id again, user.id of 0 and 65 bytes" },
  "create-gesture": { set: "fixtures", min: 1, summary: "create without user activation" },
  "get-modal": { set: "fixtures", min: 8, summary: "modal get: allowCredentials, userVerification, timeout and the page's AbortSignal" },
  "get-conditional": { set: "fixtures", min: 3, summary: "conditional mediation, and switching from conditional to modal" },
  "get-prf": { set: "fixtures", min: 3, summary: "prf eval and evalByCredential, and prf on a passkey made without it" },
  "origin-rpid": { set: "fixtures", min: 10, summary: "origin and RP ID: parent domain, child, sibling, public suffix, IDN, case, trailing dot, localhost" },
  frames: { set: "fixtures", min: 7, summary: "top, same-origin frame, cross-origin frame, nested a-b-a, sandbox, srcdoc, about:blank" },
  navigation: { set: "fixtures", min: 3, summary: "a new document mid-request, pushState, a closed tab, a lock mid-request" },
  "vault-network": { set: "fixtures", min: 4, summary: "open, locked, offline, unknown outcome and a late-accepted write" },
  verification: { set: "fixtures", min: 3, summary: "recent unlock, PRF in the window, PIN, master password" },
  handover: { set: "fixtures", min: 3, summary: "the browser chosen, Never on this site, automatic hand-over" },
  background: { set: "fixtures", min: 1, summary: "the background page unloaded under a waiting request" },
  sync: { set: "fixtures", min: 2, summary: "create in one profile and use in another; delete in one and gone in the other" },
  "adv-bridge": { set: "adversarial", min: 4, summary: "a page that talks to the bridge, tampers with the built-ins or overwrites navigator.credentials" },
  "adv-input": { set: "adversarial", min: 4, summary: "forged origins, huge options, a thousand requests, control characters and look-alike names" },
  "adv-timing": { set: "adversarial", min: 1, summary: "no match against cancelled, timed" },
  "adv-frames": { set: "adversarial", min: 3, summary: "a cross-origin frame that names the top's RP ID, a nested frame, a navigation just before the click" },
  "adv-window": { set: "adversarial", min: 3, summary: "a request without a gesture, a storm of windows, a page that reaches for the Ferret window" },
  "adv-vault": { set: "adversarial", min: 1, summary: "a page on the vault's origin (the override must be off)" },
  "adv-signals": { set: "adversarial", min: 1, summary: "the signal methods go to the browser untouched" },
});

const STEP_NAMES = Object.freeze(["create", "get", "conditional"]);
const CLIENTS = Object.freeze(["swa", "manual", "pubkey"]);
const LIBS = Object.freeze(["rs", "swa"]);
const ID_RE = /^[a-z0-9][a-z0-9-]{0,78}$/;

/** @param {unknown} v */
const isObject = (v) => typeof v === "object" && v !== null && !Array.isArray(v);

/**
 * What is wrong with a case, as a list of sentences (empty: the case is well formed).
 * @param {any} c
 * @returns {string[]}
 */
export function caseProblems(c) {
  /** @type {string[]} */
  const p = [];
  if (!isObject(c)) return ["the case is not an object"];
  if (typeof c.id !== "string" || !ID_RE.test(c.id)) p.push(`id ${JSON.stringify(c.id)} is not lower-case letters, digits and dashes`);
  if (!SETS.includes(c.set)) p.push(`set ${JSON.stringify(c.set)} is not one of ${SETS.join(", ")}`);
  if (typeof c.category !== "string" || !(c.category in CATEGORIES)) p.push(`category ${JSON.stringify(c.category)} is not in the category table`);
  if (typeof c.title !== "string" || c.title.trim() === "") p.push("title is missing");
  // The relying party.
  if (c.set === "demo") {
    if (!isObject(c.page) || typeof c.page.url !== "string" || !/^https:\/\//.test(c.page.url)) p.push("a demo case needs page.url (https)");
  } else {
    if (!isObject(c.rp) || !LIBS.includes(c.rp.lib) || !CLIENTS.includes(c.rp.client)) p.push("rp needs lib (rs | swa) and client (swa | manual | pubkey)");
    if (!isObject(c.page) || !Array.isArray(c.page.chain) || c.page.chain.length < 1 || c.page.chain.length > 4) {
      p.push("page.chain needs 1 to 4 hosts");
    } else {
      const hosts = Object.values(TEST_HOSTS);
      for (const h of c.page.chain) if (!hosts.includes(String(h).toLowerCase().replace(/\.$/, ""))) p.push(`page.chain names ${JSON.stringify(h)}, which is not a test host`);
      const kinds = c.page.kinds ?? [];
      if (!Array.isArray(kinds) || kinds.length > c.page.chain.length - 1) p.push("page.kinds has more entries than there are frames");
      for (const k of kinds) if (!FRAME_KINDS.includes(k)) p.push(`page.kinds names ${JSON.stringify(k)}`);
      if (c.page.scheme !== undefined && c.page.scheme !== "https" && c.page.scheme !== "http") p.push("page.scheme is https or http");
      if (c.page.scheme === "http" && c.page.chain[0] !== "localhost") p.push("only localhost is served over http");
    }
    if (!isObject(c.spec)) {
      p.push("spec is missing");
    } else {
      const steps = c.spec.steps ?? ["create", "get"];
      if (!Array.isArray(steps) || steps.length === 0 || steps.some((/** @type {string} */ s) => !STEP_NAMES.includes(s))) p.push(`spec.steps must be a list of ${STEP_NAMES.join(", ")}`);
    }
  }
  if (c.gesture !== "click" && c.gesture !== "none") p.push("gesture is click or none");
  // The expected outcome.
  const e = c.expected;
  const outcomeProblems = (/** @type {any} */ o, /** @type {string} */ where) => {
    if (!isObject(o)) return [`${where} is missing`];
    /** @type {string[]} */
    const q = [];
    if (!CEREMONIES.includes(o.ceremony)) q.push(`${where}.ceremony is one of ${CEREMONIES.join(", ")}`);
    if (o.ceremony === "client-error" && !CLIENT_ERRORS.includes(o.error)) q.push(`${where}.error is one of ${CLIENT_ERRORS.join(", ")} for a client error`);
    if (o.ceremony !== "client-error" && o.error !== undefined) q.push(`${where}.error only goes with a client error`);
    if (o.failStep !== undefined && !STEP_NAMES.includes(o.failStep)) q.push(`${where}.failStep is a step name`);
    if (o.prf !== undefined && o.prf !== "results" && o.prf !== "none") q.push(`${where}.prf is results or none`);
    if (o.maxWindows !== undefined && !Number.isInteger(o.maxWindows)) q.push(`${where}.maxWindows is an integer`);
    if (o.adv !== undefined && (!Array.isArray(o.adv) || o.adv.some((/** @type {any} */ a) => !isObject(a) || typeof a.key !== "string" || !("equals" in a || "noValue" in a)))) q.push(`${where}.adv is a list of { key, equals | noValue }`);
    if (where === "expected" && !ROUTES.includes(o.route)) q.push(`expected.route is one of ${ROUTES.join(", ")}`);
    return q;
  };
  p.push(...outcomeProblems(e, "expected"));
  if (c.expected?.stub !== undefined) p.push(...outcomeProblems(c.expected.stub, "expected.stub"));
  // What is unsafe.
  if (!Array.isArray(c.unsafe) || c.unsafe.length === 0) {
    p.push("unsafe needs at least one entry (the definition of an unsafe answer for this case)");
  } else {
    for (const u of c.unsafe) {
      if (!isObject(u) || !(u.id in UNSAFE)) p.push(`unsafe id ${JSON.stringify(u?.id)} is not one of ${Object.keys(UNSAFE).join(", ")}`);
      else if (typeof u.definition !== "string" || u.definition.trim().length < 10) p.push(`unsafe ${u.id} needs a definition of at least ten characters`);
    }
  }
  if (c.waitMs !== undefined && !(Number.isInteger(c.waitMs) && c.waitMs >= 1000 && c.waitMs <= 120000)) p.push("waitMs is 1000 to 120000");
  if (c.actions !== undefined && (!Array.isArray(c.actions) || c.actions.some((/** @type {any} */ a) => !isObject(a) || typeof a.do !== "string"))) p.push("actions is a list of { do: ... }");
  if (c.actions !== undefined && c.needs !== "provider") p.push("a case with actions needs the provider");
  if (c.needs !== undefined && c.needs !== "provider") p.push('needs is "provider" or absent');
  if (c.manifests !== undefined && (!Array.isArray(c.manifests) || c.manifests.length === 0 || c.manifests.some((/** @type {unknown} */ m) => m !== "mv2" && m !== "mv3"))) p.push("manifests is a list of mv2 and mv3");
  if (c.hand !== undefined && (c.set !== "demo" || typeof c.hand !== "string" || c.hand.trim().length < 10)) p.push("hand is a reason of ten characters or more, for a demo case only");
  return p;
}

/**
 * Whether a case applies to a manifest (`manifests` absent: to every one).
 * @param {any} c @param {string} manifest
 */
export function appliesTo(c, manifest) {
  return !Array.isArray(c.manifests) || c.manifests.includes(manifest);
}

/**
 * The cases in the folders `<dir>/<id>/case.json` (a missing folder has none), by id.
 * @param {string[]} dirs
 * @returns {{ cases: any[], problems: string[] }}
 */
export function loadCases(dirs) {
  /** @type {any[]} */
  const cases = [];
  /** @type {string[]} */
  const problems = [];
  /** @type {Set<string>} */
  const seen = new Set();
  for (const dir of dirs) {
    if (!existsSync(dir)) continue;
    for (const name of readdirSync(dir).sort()) {
      const file = join(dir, name, "case.json");
      if (!statSyncIsDir(join(dir, name)) || !existsSync(file)) continue;
      let c;
      try {
        c = JSON.parse(readFileSync(file, "utf8"));
      } catch (e) {
        problems.push(`${name}: case.json is not JSON (${e instanceof Error ? e.message : e})`);
        continue;
      }
      if (c.id !== name) problems.push(`${name}: id is ${JSON.stringify(c.id)} but the folder is ${name}`);
      for (const q of caseProblems(c)) problems.push(`${name}: ${q}`);
      if (seen.has(c.id)) problems.push(`${name}: id is used twice`);
      seen.add(c.id);
      cases.push(c);
    }
  }
  return { cases, problems };
}

/** @param {string} dir */
function statSyncIsDir(dir) {
  try {
    return statSync(dir).isDirectory();
  } catch {
    return false;
  }
}

/** What the categories need of a list of cases of one set: the missing numbers, as sentences. @param {any[]} cases @param {"fixtures" | "adversarial"} set */
export function categoryShortfalls(cases, set) {
  /** @type {string[]} */
  const out = [];
  for (const [name, def] of Object.entries(CATEGORIES)) {
    if (def.set !== set) continue;
    const n = cases.filter((c) => c.set === set && c.category === name).length;
    if (n < def.min) out.push(`${name}: ${n} of at least ${def.min}`);
  }
  return out;
}

// ------------------------------------------------------------------------------------- the address of a case

/**
 * The address the runner opens for a case, and the frame path to enter to reach the ceremony page.
 * @param {any} c  a well-formed case
 * @param {{ spec: any, auto: boolean, base?: Record<string, string> }} opts
 * @returns {{ url: string, frames: { id: string }[] }}
 */
export function caseAddress(c, { spec, auto }) {
  const scheme = c.page.scheme ?? "https";
  const chain = /** @type {string[]} */ (c.page.chain);
  const kinds = /** @type {string[]} */ (c.page.kinds ?? []);
  const allows = /** @type {string[]} */ (c.page.allow ?? []);
  const encoded = Buffer.from(JSON.stringify(spec), "utf8").toString("base64url");
  // The last page is the ceremony; every page before it is a nest.html that frames the next.
  let next = `${scheme}://${chain[chain.length - 1]}${c.page.path ?? "/ceremony.html"}?spec=${encoded}${auto ? "&auto=1" : ""}`;
  /** @type {{ id: string }[]} */
  const frames = [];
  for (let i = chain.length - 2; i >= 0; i--) {
    const kind = kinds[i] ?? "iframe";
    const allow = allows[i] ?? "";
    next = `${scheme}://${chain[i]}/nest.html?next=${encodeURIComponent(next)}&kind=${kind}${allow ? `&allow=${encodeURIComponent(allow)}` : ""}`;
  }
  for (let i = 0; i < chain.length - 1; i++) {
    frames.push({ id: "child" });
    if (kinds[i] === "srcdoc" || kinds[i] === "blank") frames.push({ id: "grandchild" });
  }
  return { url: next, frames };
}

/**
 * The spec the ceremony page gets: the case's, with the run, the relying party and the client code. A case of the hold-out set
 * keeps its spec as it was written, under `ho`: the page maps its conventions (test/passkey-rp/pages/lib.mjs, "the hold-out set's
 * words"), and nothing of what it expects is changed.
 * @param {any} c @param {string} run
 */
export function specOf(c, run) {
  if (c.set === "holdout") return { steps: c.spec.steps ?? ["create", "get"], run, lib: c.rp.lib, client: c.rp.client, ho: c.spec };
  return { steps: ["create", "get"], ...c.spec, run, lib: c.rp.lib, client: c.rp.client };
}

// ---------------------------------------------------------------------------------------- judging a result

/**
 * @typedef {{
 *   status: "ran" | "not-run" | "not-applicable",
 *   reason?: string,
 *   observed?: { ceremony: string, error?: string, failStep?: string, route: string, windowShown: boolean, windowsOpened?: number, prf?: string, adv?: Record<string, any>, flags?: { uv?: boolean, be?: boolean, bs?: boolean }, reports?: any[], problems?: string[] },
 *   unsafe?: string[],
 *   provider?: "stub" | "ferret",
 * }} CaseResult
 */

/**
 * What the run saw, from the ceremony page's reports and the browser's windows.
 * @param {any[]} reports  the reports of the run (kind "step" and "done")
 * @param {{ windowShown: boolean, windowsOpened?: number }} seen
 * @returns {NonNullable<CaseResult["observed"]>}
 */
export function observe(reports, { windowShown, windowsOpened = windowShown ? 1 : 0 }) {
  const steps = reports.filter((r) => r.kind === "step");
  const done = reports.find((r) => r.kind === "done");
  /** @type {NonNullable<CaseResult["observed"]>} */
  const o = { ceremony: "none", route: windowShown ? "ferret" : "none", windowShown, reports };
  const failed = steps.find((s) => !s.ok);
  if (failed) {
    o.ceremony = failed.error?.name === "ServerRefused" || failed.stage === "server-finish" ? "server-refused" : "client-error";
    if (o.ceremony === "client-error") o.error = failed.error?.name;
    o.failStep = failed.step;
  } else if (done?.ok) {
    o.ceremony = "ok";
  }
  // No window of Ferret's and the page's call ended: the browser answered it (a call Ferret took ends only from its window, or
  // waits with a mark when no window may open).
  if (!windowShown && steps.length > 0) o.route = "browser";
  const last = [...steps].reverse().find((s) => s.ok && s.server?.flags);
  if (last) o.flags = last.server.flags;
  // The extension results are what the page's browser (or Ferret) returned, whether or not the relying party then accepted the response.
  const lastStep = [...steps].reverse().find((s) => s.credential);
  if (lastStep) o.prf = lastStep.credential.extensions?.prf?.results ? "results" : "none";
  const adv = [...reports].reverse().find((r) => r.kind === "adv");
  if (adv) o.adv = adv;
  o.windowsOpened = windowsOpened;
  return o;
}

/**
 * Does what was seen match what the case expects? `provider` "stub" is the browser path with a virtual authenticator:
 * Ferret does not answer, so the route cannot be checked and `expected.stub` (if there is one) replaces the ceremony.
 * @param {any} c @param {NonNullable<CaseResult["observed"]>} o @param {"stub" | "ferret"} provider
 * @returns {{ ok: boolean, problems: string[], routeUnchecked: boolean }}
 */
export function judge(c, o, provider) {
  const want = provider === "stub" && c.expected.stub ? { ...c.expected, ...c.expected.stub } : c.expected;
  /** @type {string[]} */
  const problems = [];
  if (o.ceremony !== want.ceremony) problems.push(`ceremony was ${o.ceremony}, expected ${want.ceremony}`);
  if (want.ceremony === "client-error" && o.error !== want.error) problems.push(`error was ${o.error}, expected ${want.error}`);
  if (want.failStep && o.failStep !== want.failStep) problems.push(`the failing step was ${o.failStep}, expected ${want.failStep}`);
  for (const [k, v] of Object.entries(want.flags ?? {})) {
    if (/** @type {any} */ (o.flags)?.[k] !== v) problems.push(`flag ${k} was ${/** @type {any} */ (o.flags)?.[k]}, expected ${v}`);
  }
  if (want.prf && o.prf !== want.prf) problems.push(`prf was ${o.prf}, expected ${want.prf}`);
  if (want.maxWindows !== undefined && (o.windowsOpened ?? 0) > want.maxWindows) problems.push(`${o.windowsOpened} Ferret windows were shown, at most ${want.maxWindows} allowed`);
  for (const check of want.adv ?? []) {
    const value = o.adv?.[check.key];
    if ("equals" in check && JSON.stringify(value) !== JSON.stringify(check.equals)) problems.push(`the page saw ${check.key} = ${JSON.stringify(value)}, expected ${JSON.stringify(check.equals)}`);
    if ("noValue" in check && value && typeof value === "object" && Object.values(value).includes(check.noValue)) problems.push(`the page saw ${check.key} with a value ${JSON.stringify(check.noValue)}`);
    if (value === undefined) problems.push(`the page did not report ${check.key}`);
  }
  // What the runner's driver steps found wrong themselves (a window that did not say what it must, or stayed open).
  for (const p of o.problems ?? []) problems.push(p);
  let routeUnchecked = false;
  if (want.route !== "any") {
    if (provider === "stub") routeUnchecked = want.route === "ferret";
    else if (o.route !== want.route) problems.push(`route was ${o.route}, expected ${want.route}`);
  }
  return { ok: problems.length === 0, problems, routeUnchecked };
}

/**
 * The numbers of a run over `cases`. A case with no result, or whose result says it did not run, counts as failed: the
 * run proved nothing about it (UK125).
 * The gate is met only by the Ferret provider over the whole set (`complete`: no case was left out by a filter): the stub provider cannot see
 * the route and cannot run the cases that need Ferret, and a run of some cases proves nothing about the rest.
 * @param {any[]} cases
 * @param {Map<string, CaseResult>} results
 * @param {"stub" | "ferret"} provider
 * @param {boolean} [complete] the run was of every case of the set (no --grep)
 */
export function computeMatrix(cases, results, provider, complete = true) {
  /** @type {{ id: string, set: string, category: string, status: "passed" | "failed" | "not-run", problems: string[], routeUnchecked: boolean, unsafe: string[] }[]} */
  const rows = [];
  /** The cases ruled not applicable to this run's manifest: listed on their own, outside the total. @type {{ id: string, reason: string }[]} */
  const notApplicable = [];
  for (const c of cases) {
    const r = results.get(c.id);
    if (r?.status === "not-applicable") {
      notApplicable.push({ id: c.id, reason: r.reason ?? "" });
      continue;
    }
    if (!r || r.status !== "ran" || !r.observed) {
      rows.push({ id: c.id, set: c.set, category: c.category, status: "not-run", problems: [r?.reason ?? "no result: the run ended before this case"], routeUnchecked: false, unsafe: [] });
      continue;
    }
    const j = judge(c, r.observed, provider);
    const unsafe = r.unsafe ?? [];
    rows.push({ id: c.id, set: c.set, category: c.category, status: j.ok && unsafe.length === 0 ? "passed" : "failed", problems: [...j.problems, ...unsafe.map((u) => `UNSAFE: ${u}`)], routeUnchecked: j.routeUnchecked, unsafe });
  }
  const total = rows.length;
  const passed = rows.filter((r) => r.status === "passed").length;
  const notRun = rows.filter((r) => r.status === "not-run").length;
  const unsafe = rows.reduce((n, r) => n + r.unsafe.length, 0);
  // The cases that only a Ferret answer can settle are not run by the stub provider: they count as not run, and the
  // gate counts them as failed.
  const needsProvider = rows.filter((r) => r.status === "not-run" && cases.find((c) => c.id === r.id)?.needs === "provider").length;
  return {
    provider,
    total,
    passed,
    failed: total - passed,
    notRun,
    needsProvider,
    unsafe,
    routeUnchecked: rows.filter((r) => r.routeUnchecked).length,
    complete,
    // 100 % of the cases of the whole set, none not run, no unsafe answer, answered by Ferret (§ 11.3).
    gate: provider === "ferret" && complete && total > 0 && passed === total && unsafe === 0,
    notApplicable,
    rows,
  };
}

/** @param {ReturnType<typeof computeMatrix>} m @param {{ channel: string, manifest: string, set: string }} meta */
export function matrixMarkdown(m, { channel, manifest, set }) {
  const lines = [
    `# Passkey matrix: ${set}, ${channel}, ${manifest}, provider ${m.provider}`,
    "",
    `cases ${m.total}, passed ${m.passed}, failed ${m.failed} (of which not run ${m.notRun}, of which need the Ferret provider ${m.needsProvider}), unsafe answers ${m.unsafe}, route not checked ${m.routeUnchecked}`,
    `unsafe answers seen from outside (gesture, window count, an RP ID the browser refused, a frame route; what only Ferret's internals know is measured by the specs of U4-6 to U4-8): ${m.unsafe}`,
    `gate (the Ferret provider, the whole set, 100 % passed, nothing not run, no unsafe answer): ${m.gate ? "met" : "NOT met"}${m.provider === "stub" ? " (the stub provider never meets it)" : m.complete ? "" : " (a filtered run never meets it)"}`,
    ...(m.notApplicable.length ? [`not applicable to ${manifest} (outside the total): ${m.notApplicable.map((x) => `${x.id} (${x.reason})`).join("; ")}`] : []),
    "",
  ];
  const bad = m.rows.filter((r) => r.status !== "passed");
  if (bad.length) {
    lines.push("| case | status | why |", "|---|---|---|");
    for (const r of bad) lines.push(`| ${r.id} | ${r.status} | ${r.problems.join("; ").replace(/\|/g, "/")} |`);
  }
  return `${lines.join("\n")}\n`;
}

/** Writes <channel>-<manifest>.json and matrix.md for the set. @param {string} outDir @param {ReturnType<typeof computeMatrix>} m @param {{ channel: string, manifest: string, set: string }} meta */
export function writeReport(outDir, m, meta) {
  const { channel, manifest, set } = meta;
  writeFileSync(join(outDir, `${set}-${channel}-${manifest}.json`), `${JSON.stringify({ meta, ...m }, null, 1)}\n`);
  writeFileSync(join(outDir, `${set}-${channel}-${manifest}.md`), matrixMarkdown(m, meta));
}
