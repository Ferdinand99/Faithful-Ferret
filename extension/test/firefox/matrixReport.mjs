// The detection corpus and the matrix: what a case may say (case.json), which cases each
// category must have, and how the results of a run turn into the numbers of the gate.
// No browser in here: the runner (matrix.mjs) drives Firefox and hands the results to
// `computeMatrix`; the unit tests (test/unit/corpus.test.mjs, matrixReport.test.mjs) use
// the same functions on made-up results.
//
// A case is a folder `<set>/<id>/` with `index.html` (and the other pages of the case) and
// `case.json`. The pieces of case.json, in short (see fixtures/forms/README.md for more):
//
//   id, class (positive | negative | special), category, lang, host, scheme?, path, frame
//   prepare   steps before the fill of the fill phase (a click that shows the next step)
//   steps     what a person does for the capture phase (type, click, key, wait, generate_fill, ferret_fill)
//   expect    fill: { entry, fields: { "#id": "username" | "password" | "totp" | "totp:<n>" } } | null
//             allow: ["#id"]       fields in which a fill is acceptable (a negative case with a real field beside the trap)
//             generated: { new, confirm, rules? } | null   (rules: { minlength?, maxlength?, require?: [lower|upper|digit|symbol], forbid?: [...] }
//                        the password rules the generated value must follow; the runner reads them, the page's own attributes state them)
//             capture: { offer, username, password_from, origin, reuse?, info? } | null
//             no_offer, max_offers
//   must_stay_empty  fields a fill must never reach
//   fields    { "#id": <field kind> } for the fields the case marks (CVC, PIN, one-time code ...)
//   source    "own" (written for this corpus) or "adapted" (carries a licence header and a notice)
import { existsSync, mkdirSync, readdirSync, readFileSync, statSync, writeFileSync } from "node:fs";
import { join } from "node:path";

/** The user name of every entry of the matrix's vault (the adversary helpers make them all alike). */
export const VAULT_USERNAME = "ola";

/** The languages a case may be written in. */
export const LANGUAGES = Object.freeze(["en", "nb", "de", "fr", "nl"]);

/** The field kinds a case may name in `fields`. */
export const FIELD_KINDS = Object.freeze([
  "username", "email", "current_password", "new_password", "confirm_password",
  "otp", "otp_digit", "search", "card_number", "card_cvc", "pin", "other",
]);

/** Kinds that no password or user name may ever be put into or taken from. */
const SECRET_KINDS = new Set(["card_cvc", "card_number", "pin", "otp", "otp_digit", "search"]);
/** Kinds a stored password must never be put into. */
const NEW_PASSWORD_KINDS = new Set(["new_password", "confirm_password"]);

/**
 * The categories of the corpus: their class, how many cases each must have at least, and whether
 * an offer in them is always unsafe (the page has no login the user could mean).
 * @type {Readonly<Record<string, { class: "positive" | "negative" | "special", min: number, never?: boolean }>>}
 */
export const CATEGORIES = Object.freeze({
  login: { class: "positive", min: 15 },
  "login-noform": { class: "positive", min: 8 },
  identifier: { class: "positive", min: 6 },
  signup: { class: "positive", min: 14 },
  change: { class: "positive", min: 8 },
  reset: { class: "positive", min: 4 },
  shadow: { class: "positive", min: 6 },
  frame: { class: "positive", min: 3 },
  spa: { class: "positive", min: 6 },
  controlled: { class: "positive", min: 5 },
  otp: { class: "positive", min: 5 },
  harmless: { class: "negative", min: 10 },
  card: { class: "negative", min: 4, never: true },
  "otp-masked": { class: "negative", min: 3, never: true },
  hidden: { class: "negative", min: 7, never: true },
  tamper: { class: "negative", min: 5, never: true },
  "foreign-frame": { class: "negative", min: 5, never: true },
  insecure: { class: "negative", min: 3, never: true },
  reauth: { class: "negative", min: 5 },
  flood: { class: "negative", min: 3 },
  lookalike: { class: "special", min: 3 },
  "domain-entry": { class: "special", min: 1 },
  "cross-post": { class: "special", min: 1 },
});

/** The kinds of frame a case may embed. */
export const FRAME_KINDS = Object.freeze(["same-site", "foreign", "srcdoc", "sandbox", "blank", "hidden"]);

const OFFERS = Object.freeze(["save", "update", "choose"]);
const STEP_KEYS = Object.freeze(["type", "click", "key", "wait", "generate_fill", "ferret_fill"]);

/** @param {unknown} v @returns {v is Record<string, any>} */
const isObject = (v) => typeof v === "object" && v !== null && !Array.isArray(v);
/** @param {unknown} v */
const isId = (v) => typeof v === "string" && /^#[A-Za-z][A-Za-z0-9_-]*$/.test(v);

/** The classes of characters a password rule can name. */
export const CHARACTER_CLASSES = Object.freeze(["lower", "upper", "digit", "symbol"]);

/** @param {unknown} r */
function rulesAreWellFormed(r) {
  if (!isObject(r)) return false;
  for (const key of Object.keys(r)) if (!["minlength", "maxlength", "require", "forbid"].includes(key)) return false;
  for (const key of ["minlength", "maxlength"]) if (r[key] !== undefined && !(Number.isInteger(r[key]) && r[key] > 0)) return false;
  for (const key of ["require", "forbid"]) if (r[key] !== undefined && !(Array.isArray(r[key]) && r[key].every((/** @type {unknown} */ x) => CHARACTER_CLASSES.includes(/** @type {string} */ (x))))) return false;
  return true;
}

/**
 * Whether a password follows the rules of a case (the runner calls this where it can see the value; a report never holds it).
 * @param {string} value
 * @param {{ minlength?: number, maxlength?: number, require?: string[], forbid?: string[] }} rules
 */
export function followsRules(value, rules) {
  const has = {
    lower: /[a-z]/.test(value),
    upper: /[A-Z]/.test(value),
    digit: /[0-9]/.test(value),
    symbol: /[^A-Za-z0-9]/.test(value),
  };
  if (rules.minlength !== undefined && value.length < rules.minlength) return false;
  if (rules.maxlength !== undefined && value.length > rules.maxlength) return false;
  if ((rules.require ?? []).some((k) => !has[/** @type {keyof typeof has} */ (k)])) return false;
  if ((rules.forbid ?? []).some((k) => has[/** @type {keyof typeof has} */ (k)])) return false;
  return true;
}

/**
 * What is wrong with a case.json (an empty list for a good one). `folder` is the case's folder name. `prefix` is what
 * every id of the set starts with before its category (the autofill-parity suite uses "ap-").
 * @param {unknown} c
 * @param {string} folder
 * @param {{ prefix?: string }} [options]
 * @returns {string[]}
 */
export function caseProblems(c, folder, { prefix = "" } = {}) {
  /** @type {string[]} */
  const p = [];
  if (!isObject(c)) return ["case.json is not an object"];
  const known = ["id", "class", "category", "lang", "host", "scheme", "path", "frame", "prepare", "steps", "expect", "must_stay_empty", "fields", "source"];
  for (const key of Object.keys(c)) if (!known.includes(key)) p.push(`unknown key ${key}`);
  if (c.id !== folder) p.push(`id ${JSON.stringify(c.id)} is not the folder name ${folder}`);
  const cat = typeof c.category === "string" ? CATEGORIES[c.category] : undefined;
  if (!cat) p.push(`unknown category ${JSON.stringify(c.category)}`);
  else {
    if (c.class !== cat.class) p.push(`class ${JSON.stringify(c.class)} but the category ${c.category} is ${cat.class}`);
    if (typeof c.id === "string" && !c.id.startsWith(`${prefix}${c.category}-`)) p.push(`the id does not start with ${prefix}${c.category}-`);
  }
  if (!LANGUAGES.includes(c.lang)) p.push(`lang ${JSON.stringify(c.lang)}`);
  if (typeof c.host !== "string" || !/^[a-z0-9.-]+$/.test(c.host)) p.push("host");
  if (c.scheme !== undefined && c.scheme !== "https" && c.scheme !== "http") p.push("scheme");
  if (typeof c.path !== "string" || !c.path.startsWith(`/${folder}/`)) p.push(`path must start with /${folder}/`);
  if (c.frame !== null && c.frame !== undefined) {
    const f = c.frame;
    if (!isObject(f) || !isId(f.id) || typeof f.host !== "string" || typeof f.path !== "string" || !FRAME_KINDS.includes(f.kind)) p.push("frame needs id, host, path and a known kind");
  } else if (c.frame === undefined) p.push("frame (null when there is none)");
  for (const list of ["prepare", "steps"]) {
    const steps = c[list];
    if (steps === undefined && list === "prepare") continue;
    if (!Array.isArray(steps)) {
      p.push(`${list} is not a list`);
      continue;
    }
    steps.forEach((s, i) => {
      const keys = isObject(s) ? Object.keys(s).filter((k) => STEP_KEYS.includes(k)) : [];
      if (keys.length !== 1) p.push(`${list}[${i}] needs exactly one of ${STEP_KEYS.join(", ")}`);
      else if (keys[0] === "type" && (!isId(s.type) || typeof s.text !== "string" || !(s.repeat === undefined || (Number.isInteger(s.repeat) && s.repeat >= 1 && s.repeat <= 5000)))) p.push(`${list}[${i}]: type needs an #id, a text and maybe a repeat`);
      else if (keys[0] === "click" && !isId(s.click)) p.push(`${list}[${i}]: click needs an #id`);
      else if (keys[0] === "wait" && !(Number.isInteger(s.wait) && s.wait > 0 && s.wait <= 10_000)) p.push(`${list}[${i}]: wait is a number of milliseconds`);
      else if (keys[0] === "key" && typeof s.key !== "string") p.push(`${list}[${i}]: key needs a name`);
    });
  }
  if (!isObject(c.expect)) p.push("expect");
  else {
    const e = c.expect;
    for (const key of Object.keys(e)) if (!["fill", "allow", "generated", "capture", "no_offer", "max_offers"].includes(key)) p.push(`unknown expect.${key}`);
    if (e.fill !== null) {
      if (!isObject(e.fill) || typeof e.fill.entry !== "string" || !isObject(e.fill.fields) || Object.keys(e.fill.fields).length === 0) p.push("expect.fill is null or { entry, fields }");
      else {
        for (const [id, kind] of Object.entries(e.fill.fields)) {
          if (!isId(id) || !(kind === "username" || kind === "password" || (typeof kind === "string" && /^totp(:[0-9])?$/.test(kind)))) p.push(`expect.fill.fields ${id}: ${kind}`);
        }
      }
    }
    if (e.allow !== undefined && !(Array.isArray(e.allow) && e.allow.every(isId))) p.push("expect.allow is a list of #ids");
    if (e.generated !== null && e.generated !== undefined) {
      if (!isObject(e.generated) || !isId(e.generated.new) || !(e.generated.confirm === null || isId(e.generated.confirm))) p.push("expect.generated is { new, confirm }");
      else if (e.generated.rules !== undefined && !rulesAreWellFormed(e.generated.rules)) p.push("expect.generated.rules is { minlength?, maxlength?, require?, forbid? }");
    } else if (e.generated === undefined) p.push("expect.generated (null when there is none)");
    if (e.capture !== null) {
      const k = e.capture;
      if (!isObject(k) || !OFFERS.includes(k.offer) || !(k.username === null || typeof k.username === "string") || !isId(k.password_from) || !/^https?:\/\/[a-z0-9.-]+$/.test(String(k.origin))) {
        p.push("expect.capture is null or { offer, username, password_from, origin }");
      } else if (k.offer === "update" && typeof k.target !== "string") p.push("expect.capture.target names the entry an update is for");
    }
    if (c.class === "negative") {
      if (e.fill !== null) p.push("a negative case fills nothing (use expect.allow)");
      if (e.capture !== null) p.push("a negative case has no expected capture");
      if (typeof e.no_offer !== "boolean") p.push("expect.no_offer (true or false) on a negative case");
      else if (!e.no_offer && !(Number.isInteger(e.max_offers) && e.max_offers >= 1)) p.push("expect.max_offers when a negative case may offer");
    } else {
      if (e.fill === null && e.capture === null && !e.generated) p.push("a positive or special case expects a fill or a capture");
      if (c.class === "special" && e.capture === null) p.push("a special case expects a capture");
    }
  }
  if (!Array.isArray(c.must_stay_empty) || !c.must_stay_empty.every(isId)) p.push("must_stay_empty is a list of #ids");
  if (!isObject(c.fields)) p.push("fields");
  else for (const [id, kind] of Object.entries(c.fields)) if (!isId(id) || !FIELD_KINDS.includes(/** @type {any} */ (kind))) p.push(`fields ${id}: ${kind}`);
  if (c.source !== "own" && c.source !== "adapted") p.push("source is own or adapted");
  return p;
}

/**
 * Every case of a corpus directory, with the folder (`dir`) it came from.
 * A folder whose name starts with an underscore is not a case (the self-test page).
 * @param {string} dir
 * @param {{ prefix?: string }} [options] see caseProblems
 * @returns {Array<Record<string, any> & { dir: string }>}
 */
export function loadCorpus(dir, options = {}) {
  /** @type {Array<Record<string, any> & { dir: string }>} */
  const cases = [];
  if (!existsSync(dir)) return cases;
  for (const name of readdirSync(dir).sort()) {
    const folder = join(dir, name);
    if (name.startsWith("_") || !statSync(folder).isDirectory()) continue;
    const problems = caseProblems(JSON.parse(readFileSync(join(folder, "case.json"), "utf8")), name, options);
    if (problems.length > 0) throw new Error(`corpus: ${name}/case.json: ${problems.join("; ")}`);
    cases.push({ ...JSON.parse(readFileSync(join(folder, "case.json"), "utf8")), dir: folder });
  }
  return cases;
}

/** @param {Record<string, any>} c @returns {string} the origin of the page the case opens */
export function pageOrigin(c) {
  return `${c.scheme ?? "https"}://${c.host}`;
}

/**
 * Whether an entry's rule matches a document, as the fill rules say (https only for an https entry; `host` is
 * the same host, `domain` the same registrable domain, which the rule carries, `exact` the same address).
 * @param {{ url: string, matching: "host" | "domain" | "exact", domain?: string }} rule
 * @param {string} docUrl
 */
export function ruleMatches(rule, docUrl) {
  let doc;
  let entry;
  try {
    doc = new URL(docUrl);
    entry = new URL(rule.url);
  } catch {
    return false;
  }
  if (doc.protocol !== entry.protocol) return false;
  if (rule.matching === "exact") return doc.href.split("#")[0] === entry.href.split("#")[0];
  if (rule.matching === "host") return doc.host === entry.host;
  if (rule.matching === "domain") return typeof rule.domain === "string" && (doc.hostname === rule.domain || doc.hostname.endsWith(`.${rule.domain}`));
  return false;
}

// ----------------------------------------------------------------- one result

/**
 * What the runner saw for one case.
 * @typedef {{
 *   fills: Array<{ entry: string, kind: "username" | "password" | "totp", index?: number, id: string, docUrl: string }>,
 *   tried: Array<{ entry: string, ok: boolean, reason?: string }>,
 *   entries: Record<string, { url: string, matching: "host" | "domain" | "exact", domain?: string }>,
 *   vault_changed?: boolean,
 *   retries?: number,
 *   offers: Array<{ type: string, origin: string, username: string | null, password_field: string | null, reuse?: boolean, generated?: boolean, info?: string,
 *                   target_entry?: string, target_host?: string, target_match?: string, picked?: boolean, written_without_click?: boolean }>,
 *   generated: { filled: string[], stray?: string[], rules_ok?: boolean } | null,
 * }} Observed
 * @typedef {{ case: Record<string, any>, ran: { fill: boolean, capture: boolean, generated?: boolean }, observed?: Partial<Observed>, error?: string }} Result
 * @typedef {{ id: string, category: string, kind: "fill" | "offer", reason: string, field?: string }} Miss
 */

/** @param {Record<string, any>} c */
const expectsFill = (c) => c.class !== "negative" && c.expect.fill !== null;
/** @param {Record<string, any>} c */
const expectsCapture = (c) => c.class !== "negative" && c.expect.capture !== null;
/** The generator's check is a measure of its own (see computeMatrix), not part of the capture check. @param {Record<string, any>} c */
const expectsGenerated = (c) => c.class !== "negative" && (c.expect.generated ?? null) !== null;

/**
 * The fills of a result that are unsafe, each with its reason.
 * @param {Result} r
 * @returns {Miss[]}
 */
export function unsafeFillsOf(r) {
  const c = r.case;
  /** @type {Miss[]} */
  const out = [];
  const entries = r.observed?.entries ?? {};
  const wanted = c.expect.fill?.fields ?? {};
  const allow = c.expect.allow ?? [];
  for (const f of r.observed?.fills ?? []) {
    const miss = (/** @type {string} */ reason) => out.push({ id: c.id, category: c.category, kind: "fill", reason, field: f.id });
    const rule = entries[f.entry];
    const kindOfField = c.fields?.[f.id];
    const want = wanted[f.id];
    if (!rule || !ruleMatches(rule, f.docUrl)) miss("rule_mismatch");
    else if (c.must_stay_empty.includes(f.id)) miss("must_stay_empty");
    else if (want !== undefined) {
      // A field the case expects a fill in: the right kind of value only (a code into a code field is the point of the case).
      if (!(f.kind === "totp" ? String(want).startsWith("totp") : want === f.kind)) miss("wrong_kind");
    } else if (SECRET_KINDS.has(kindOfField)) miss("wrong_kind");
    else if (f.kind === "password" && NEW_PASSWORD_KINDS.has(kindOfField)) miss("stored_password_in_new_password");
    else if (!allow.includes(f.id)) miss("unexpected_field");
  }
  return out;
}

/**
 * The offers of a result that are unsafe, each with its reason (one miss per reason and offer).
 * @param {Result} r
 * @returns {Miss[]}
 */
export function unsafeOffersOf(r) {
  const c = r.case;
  /** @type {Miss[]} */
  const out = [];
  const offers = r.observed?.offers ?? [];
  const category = CATEGORIES[c.category];
  const origin = c.expect.capture?.origin ?? pageOrigin(c);
  if (category?.never && offers.length > 0) out.push({ id: c.id, category: c.category, kind: "offer", reason: "offer_in_a_case_with_no_login" });
  if (c.class === "negative" && !c.expect.no_offer && offers.length > c.expect.max_offers) out.push({ id: c.id, category: c.category, kind: "offer", reason: "more_offers_than_allowed" });
  for (const o of offers) {
    const miss = (/** @type {string} */ reason) => out.push({ id: c.id, category: c.category, kind: "offer", reason, ...(o.password_field ? { field: o.password_field } : {}) });
    if (o.origin !== origin) miss("wrong_origin");
    if (o.password_field !== null && o.password_field !== undefined && SECRET_KINDS.has(c.fields?.[o.password_field])) miss("value_from_cvc_pin_or_code_field");
    // A current password is never the new one: in a sign-up, a change or a reset form it is not a value to offer.
    if (o.password_field !== null && o.password_field !== undefined && c.fields?.[o.password_field] === "current_password" && ["signup", "change", "reset"].includes(c.category)) miss("current_password_offered_as_a_new_one");
    // A field the fill must leave empty is also one a value must not be taken from, unless it is the field the case expects
    // the offer to come from (the new password the person typed there): only a value from another such field is unsafe,
    // and in a negative case every one is.
    const expectedFrom = c.class !== "negative" ? (c.expect.capture?.password_from ?? null) : null;
    if (o.password_field !== null && o.password_field !== undefined && c.must_stay_empty.includes(o.password_field) && o.password_field !== expectedFrom) miss("value_from_a_field_that_must_stay_empty");
    if (o.type === "update") {
      let host = "";
      try {
        host = new URL(o.origin).host;
      } catch {
        // the origin is wrong anyway
      }
      if (o.target_host !== host) miss("update_on_another_host");
      if (o.target_match === "domain" && o.picked !== true) miss("domain_update_without_an_explicit_pick");
    }
    if (o.written_without_click === true) miss("write_without_a_click");
  }
  // The runner never clicks a save control in the capture phase, so any change of the vault during a case is a write
  // nobody asked for, whatever the extension says about itself.
  if (r.observed?.vault_changed === true) out.push({ id: c.id, category: c.category, kind: "offer", reason: "write_without_a_click" });
  return out;
}

/**
 * The generator check of a case: the new-password field (and the confirm field) hold the same generated value.
 * @param {Result} r
 * @returns {{ status: "pass" | "fail", reason?: string }}
 */
function generatedCheck(r) {
  const want = r.case.expect.generated;
  const filled = r.observed?.generated?.filled ?? [];
  for (const id of [want.new, want.confirm].filter(Boolean)) if (!filled.includes(id)) return { status: "fail", reason: `the generated password did not go into ${id}` };
  // No other field may hold it: not the password in use of a change form, not the e-mail box.
  const stray = r.observed?.generated?.stray ?? [];
  if (stray.length > 0) return { status: "fail", reason: `the generated password also went into ${stray.join(", ")}` };
  // A page that states password rules: the value must follow them (the runner checked; the report never holds the value).
  if (want.rules && r.observed?.generated?.rules_ok !== true) return { status: "fail", reason: "the generated password does not follow the page's password rules" };
  return { status: "pass" };
}

/**
 * The fill check of a case: "pass" or "fail" with the reason.
 * @param {Result} r
 * @returns {{ status: "pass" | "fail", reason?: string }}
 */
function fillCheck(r) {
  const want = r.case.expect.fill;
  const tried = r.observed?.tried?.find((t) => t.entry === want.entry);
  if (!tried) return { status: "fail", reason: `the entry ${want.entry} was not offered` };
  if (!tried.ok) return { status: "fail", reason: `fill refused: ${tried.reason ?? "unknown"}` };
  const fills = r.observed?.fills ?? [];
  for (const [id, kind] of Object.entries(want.fields)) {
    const got = fills.find((f) => f.id === id && f.entry === want.entry);
    if (!got) return { status: "fail", reason: `${id} did not get its ${String(kind).split(":")[0]}` };
    const ok = String(kind).startsWith("totp") ? got.kind === "totp" && got.index === (kind === "totp" ? undefined : Number(String(kind).slice(5))) : got.kind === kind;
    if (!ok) return { status: "fail", reason: `${id} got a ${got.kind}, not the ${String(kind).split(":")[0]}` };
  }
  return { status: "pass" };
}

/**
 * The capture check of a case: "pass" or "fail" with the reason.
 * @param {Result} r
 * @returns {{ status: "pass" | "fail", reason?: string }}
 */
function captureCheck(r) {
  const c = r.case;
  const offers = r.observed?.offers ?? [];
  const want = c.expect.capture;
  if (want === null) return { status: "pass" };
  if (offers.length === 0) return { status: "fail", reason: "no offer" };
  if (offers.length > 1) return { status: "fail", reason: `${offers.length} offers for one submission` };
  const [o] = offers;
  if (o.type !== want.offer) return { status: "fail", reason: `offer is ${o.type}, not ${want.offer}` };
  if (o.username !== want.username) return { status: "fail", reason: "the user name of the offer is wrong" };
  if (o.password_field !== want.password_from) return { status: "fail", reason: `the password came from ${o.password_field}, not ${want.password_from}` };
  if (o.origin !== want.origin) return { status: "fail", reason: `the origin of the offer is ${o.origin}` };
  if (want.reuse === true && o.reuse !== true) return { status: "fail", reason: "no reuse warning" };
  if (typeof want.info === "string" && o.info !== want.info) return { status: "fail", reason: `no ${want.info} info line` };
  if (want.offer === "update" && o.target_entry !== want.target) return { status: "fail", reason: `the update is for ${o.target_entry}, not ${want.target}` };
  return { status: "pass" };
}

/**
 * What the numbers need from the cases of a set.
 * @param {"corpus" | "holdout" | "parity"} set
 */
function thresholds(set) {
  return set === "holdout" ? { overall: 0.9, floor: 0 } : { overall: 0.95, floor: 0.8 }; // the corpus and the parity suite
}

/** @param {number} passed @param {number} total */
const rateOf = (passed, total) => (total === 0 ? null : passed / total);

/**
 * The numbers of a run.
 *
 * - `fill` and `capture`: the share of the positive cases with that check that passed (negative and special
 *   cases never count here). A check on a case that did not run is a miss.
 * - `perCategory`: for every positive and special category, the share of its cases whose checks all passed.
 * - `unsafeFills` and `unsafeOffers`: every one found in any case of any class.
 * - `falseOffers`: offers in harmless negative cases (the ones with no `never` mark) that expect none.
 * - `generated`: the generator's own measure, over the cases with `expect.generated` (a generator pass in the capture
 *   phase). It is part of the gate at the set's overall level when the capture part is selected; a case whose
 *   generator pass did not run, or got no answer, is a miss.
 * - `notRun`: the cases a selected part did not run for.
 * - `met`: both rates and the generator's at the set's level, no positive or special category under the floor,
 *   nothing unsafe, nothing unrun. A part that was not selected does not count. The hold-out set has no category floor.
 * - `gate`: `met` for a complete run (every part, no case filter); a partial run has no gate.
 * @param {Result[]} results
 * @param {{ set?: "corpus" | "holdout" | "parity", part?: "fill" | "capture" | "all", manifest?: string, grep?: string }} [options]
 */
export function computeMatrix(results, { set = "corpus", part = "all", manifest = "mv2", grep = "" } = {}) {
  const level = thresholds(set);
  const useFill = part === "fill" || part === "all";
  const useCapture = part === "capture" || part === "all";
  /** @type {Record<"fill" | "capture", { passed: number, total: number }>} */
  const count = { fill: { passed: 0, total: 0 }, capture: { passed: 0, total: 0 } };
  /** @type {Record<string, { passed: number, total: number }>} */
  const cat = {};
  /** @type {Record<string, { cases: number, unsafe: number, falseOffers: number }>} */
  const negative = {};
  /** @type {Miss[]} */
  const unsafeFills = [];
  /** @type {Miss[]} */
  const unsafeOffers = [];
  /** @type {Array<{ id: string, category: string, part: "fill" | "capture" | "generated", reason: string }>} */
  const misses = [];
  /** @type {string[]} */
  const notRun = [];
  /** @type {string[]} */
  const falseCases = [];
  let negativeRan = 0;
  const generatedCount = { passed: 0, total: 0 };
  /** The cases whose page had to be opened again because the shortcut went to the bridge tab. @type {Array<{ id: string, retries: number }>} */
  const retried = [];
  /** @type {string[]} */
  const generatedNotRun = [];
  /** @type {Array<{ id: string, category: string, class: string, fill: string, capture: string }>} */
  const cases = [];

  for (const r of results) {
    const c = r.case;
    const mustRun = { fill: useFill, capture: useCapture };
    const status = { fill: "skipped", capture: "skipped" };
    for (const which of /** @type {const} */ (["fill", "capture"])) {
      if (!mustRun[which]) continue;
      if (!r.ran[which]) {
        status[which] = "notrun";
        if (!notRun.includes(c.id)) notRun.push(c.id);
        if ((which === "fill" ? expectsFill(c) : expectsCapture(c))) misses.push({ id: c.id, category: c.category, part: which, reason: r.error ? `did not run: ${r.error}` : "did not run" });
        continue;
      }
      const applies = which === "fill" ? expectsFill(c) : expectsCapture(c);
      if (!applies) {
        status[which] = "ok";
        continue;
      }
      const check = which === "fill" ? fillCheck(r) : captureCheck(r);
      status[which] = check.status;
      if (check.status === "fail") misses.push({ id: c.id, category: c.category, part: which, reason: check.reason ?? "failed" });
    }
    // Safety, in every class, for the parts that ran.
    if (mustRun.fill && r.ran.fill) unsafeFills.push(...unsafeFillsOf(r));
    const offerMisses = mustRun.capture && r.ran.capture ? unsafeOffersOf(r) : [];
    unsafeOffers.push(...offerMisses);

    if (c.class === "negative") {
      const n = (negative[c.category] ??= { cases: 0, unsafe: 0, falseOffers: 0 });
      n.cases += 1;
      n.unsafe += unsafeFillsOf(r).length * Number(mustRun.fill && r.ran.fill) + offerMisses.length;
      if (mustRun.capture && r.ran.capture && !CATEGORIES[c.category]?.never) {
        negativeRan += 1;
        if (c.expect.no_offer && (r.observed?.offers?.length ?? 0) > 0) {
          falseCases.push(c.id);
          n.falseOffers += 1;
        }
      }
    } else {
      // The overall rate counts the positive cases only; the category numbers also the special ones.
      let all = true;
      let any = false;
      for (const which of /** @type {const} */ (["fill", "capture"])) {
        if (!mustRun[which] || !(which === "fill" ? expectsFill(c) : expectsCapture(c))) continue;
        any = true;
        const ok = status[which] === "pass";
        if (c.class === "positive") {
          count[which].total += 1;
          if (ok) count[which].passed += 1;
        }
        if (!ok) all = false;
      }
      if (any) {
        const entry = (cat[c.category] ??= { passed: 0, total: 0 });
        entry.total += 1;
        if (all) entry.passed += 1;
      }
    }
    if (useCapture && expectsGenerated(c)) {
      generatedCount.total += 1;
      if (!r.ran.generated) {
        generatedNotRun.push(c.id);
        misses.push({ id: c.id, category: c.category, part: "generated", reason: r.error ? `did not run: ${r.error}` : "did not run" });
      } else if (generatedCheck(r).status === "pass") generatedCount.passed += 1;
      else misses.push({ id: c.id, category: c.category, part: "generated", reason: generatedCheck(r).reason ?? "failed" });
    }
    if ((r.observed?.retries ?? 0) > 0) retried.push({ id: c.id, retries: r.observed?.retries ?? 0 });
    cases.push({ id: c.id, category: c.category, class: c.class, fill: status.fill, capture: status.capture });
  }

  const part2 = (/** @type {"fill" | "capture"} */ which) => ({ ...count[which], rate: rateOf(count[which].passed, count[which].total), selected: which === "fill" ? useFill : useCapture });
  const fill = part2("fill");
  const capture = part2("capture");
  /** @type {Record<string, { rate: number | null, passed: number, total: number }>} */
  const perCategory = {};
  for (const [name, v] of Object.entries(cat)) perCategory[name] = { rate: rateOf(v.passed, v.total), passed: v.passed, total: v.total };

  const partOk = (/** @type {{ selected: boolean, rate: number | null }} */ p) => !p.selected || (p.rate !== null && p.rate >= level.overall);
  const floorsOk = Object.values(perCategory).every((v) => v.rate !== null && v.rate >= level.floor);
  const generatedOk = !useCapture || generatedCount.total === 0 || generatedCount.passed / generatedCount.total >= level.overall;
  const met = partOk(fill) && partOk(capture) && generatedOk && floorsOk && unsafeFills.length === 0 && unsafeOffers.length === 0 && notRun.length === 0;
  const complete = part === "all" && grep === "";
  const generated = { ...generatedCount, rate: rateOf(generatedCount.passed, generatedCount.total), selected: useCapture, notRun: generatedNotRun };
  const falseOffers = { rate: rateOf(falseCases.length, negativeRan), cases: falseCases };

  return {
    meta: { set, part, manifest, grep },
    fill,
    capture,
    generated,
    perCategory,
    negative,
    unsafeFills,
    unsafeOffers,
    falseOffers,
    notRun,
    misses,
    retries: { total: retried.reduce((sum, x) => sum + x.retries, 0), cases: retried },
    cases,
    met,
    gate: met && complete,
  };
}

/** @typedef {ReturnType<typeof computeMatrix>} Matrix */

/** @param {number | null} rate */
const percent = (rate) => (rate === null ? "n/a" : `${(rate * 100).toFixed(1)} %`);

/**
 * The text report of one run.
 * @param {string} channel
 * @param {Matrix} m
 * @returns {string}
 */
function markdownOf(channel, m) {
  const lines = [];
  // A run of one part or of some cases has no gate: it says whether the part it measured is met.
  const verdict = m.gate ? "GATE MET" : m.meta.part === "all" && !m.meta.grep ? "GATE NOT MET" : `PARTIAL RUN (${m.meta.part === "all" ? "some cases" : `${m.meta.part} part`}${m.meta.grep ? `, cases matching ${m.meta.grep}` : ""}): no gate; the part is ${m.met ? "met" : "not met"}`;
  lines.push(`## ${channel} (${m.meta.manifest}), set ${m.meta.set}, part ${m.meta.part}: ${verdict}`, "");
  lines.push("| Measure | Passed | Total | Rate |", "|---|---|---|---|");
  for (const which of /** @type {const} */ (["fill", "capture"])) {
    const p = m[which];
    lines.push(`| ${which} (positive cases) | ${p.passed} | ${p.total} | ${p.selected ? percent(p.rate) : "not selected"} |`);
  }
  if (m.generated) lines.push(`| generator | ${m.generated.passed} | ${m.generated.total} | ${m.generated.selected ? percent(m.generated.rate) : "not selected"} |`);
  lines.push(`| unsafe fills | | ${m.unsafeFills.length} | |`, `| unsafe offers | | ${m.unsafeOffers.length} | |`);
  lines.push(`| false offers (harmless negatives) | | ${m.falseOffers.cases.length} | ${percent(m.falseOffers.rate)} |`);
  lines.push(`| cases that did not run | | ${m.notRun.length} | |`);
  // The shortcut now and then goes to the bridge tab and the page is opened again; a channel that needs it more is visible here.
  lines.push(`| shortcut retries (the command went to the bridge tab) | | ${m.retries?.total ?? 0} | ${(m.retries?.cases ?? []).map((x) => `${x.id} x${x.retries}`).join(", ")} |`, "");
  lines.push("| Category | Passed | Total | Rate |", "|---|---|---|---|");
  for (const [name, v] of Object.entries(m.perCategory).sort()) lines.push(`| ${name} | ${v.passed} | ${v.total} | ${percent(v.rate)} |`);
  lines.push("");
  const list = (/** @type {string} */ title, /** @type {string[]} */ items) => {
    lines.push(`### ${title} (${items.length})`, "");
    lines.push(...(items.length === 0 ? ["none"] : items.map((i) => `- ${i}`)), "");
  };
  // Security reasons first; `unexpected_field` (a value in a field the case did not expect) is a matter of precision.
  const fillLine = (/** @type {Miss} */ x) => `${x.id} (${x.category}): ${x.reason}${x.field ? ` in ${x.field}` : ""}`;
  list("Unsafe fills, security", m.unsafeFills.filter((x) => x.reason !== "unexpected_field").map(fillLine));
  list("Unsafe fills, precision", m.unsafeFills.filter((x) => x.reason === "unexpected_field").map(fillLine));
  list("Unsafe offers", m.unsafeOffers.map((x) => `${x.id} (${x.category}): ${x.reason}${x.field ? ` from ${x.field}` : ""}`));
  list("Cases that did not run", m.notRun);
  list("Misses", m.misses.map((x) => `${x.id} (${x.category}, ${x.part}): ${x.reason}`));
  return lines.join("\n");
}

/**
 * Writes `<channel>-<manifest>.json` (the numbers and the cases, never a value) and a `matrix.md` with a section for
 * every such file of the directory.
 * @param {string} dir
 * @param {string} channel
 * @param {Matrix} matrix
 */
export function writeReport(dir, channel, matrix) {
  mkdirSync(dir, { recursive: true });
  writeFileSync(join(dir, `${channel}-${matrix.meta.manifest}.json`), `${JSON.stringify({ channel, ...matrix }, null, 2)}\n`);
  const sections = readdirSync(dir)
    .filter((f) => /^(release|esr)-mv[23]\.json$/.test(f))
    .sort()
    .map((f) => {
      const data = JSON.parse(readFileSync(join(dir, f), "utf8"));
      return markdownOf(data.channel, data);
    });
  writeFileSync(join(dir, "matrix.md"), `# Detection matrix\n\n${sections.join("\n")}\n`);
}
