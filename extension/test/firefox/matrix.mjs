// The matrix runner: drives the extension in a real Firefox, signed in to the end-to-end stack, over the
// cases of the corpus (test/fixtures/forms, or the hold-out set), and hands what it saw to
// matrixReport.mjs. Not a spec (run.sh picks up *.spec.mjs only); 95-matrix.e2e.spec.mjs uses it.
//
// Two phases, each over every case:
//   fill     opens the page the way a person does (the real shortcut gives activeTab), asks the extension
//            for the page's entries and fills each one it offers (for a positive case, the entry the case
//            names; for any other, every entry offered), then reads every input of every document, frames
//            and shadow roots included. A value of the vault found in an input is a fill.
//   capture  does what the case's `steps` say with real key events and clicks and reads the offers the
//            extension holds for the tab through the test bridge's `offers_peek` (the offer's metadata and
//            the SHA-256 of its password, never the password). Until the extension keeps offers, the bridge
//            says it has none to show and every case of this phase counts as not run.
//
// The vault of a run has a few entries (ENTRIES), all with the user name VAULT_USERNAME and a password the
// run makes up. Nothing of a password goes into a report: a fill is recorded as "this entry's password went
// into #id" and an offer by the SHA-256 of its password.
import { createHash } from "node:crypto";
import { resolve } from "node:path";
import { FORMS_DIR } from "./fixtures-server.mjs";
import { VAULT_USERNAME, loadCorpus } from "./matrixReport.mjs";

/** Where the hold-out set is added to the repository when the time comes. */
export const HOLDOUT_DIR = resolve(FORMS_DIR, "..", "forms-holdout");

/** @param {"corpus" | "holdout"} set */
export const formsDirFor = (set) => (set === "holdout" ? HOLDOUT_DIR : FORMS_DIR);

/**
 * The entries of the matrix's vault: what the extension should offer where. `rule` is what a fill is judged by
 * (`domain` is the registrable domain of a `domain` entry).
 * @type {Readonly<Record<string, { name: string, url: string, matching: "host" | "domain" | "exact", domain?: string }>>}
 */
export const ENTRIES = Object.freeze({
  forms: { name: "Forms entry", url: "https://forms.example.net/", matching: "host" },
  login: { name: "Login entry", url: "https://login.example.net/", matching: "host" },
  domain: { name: "Domain entry", url: "https://app.forms.example.org/", matching: "domain", domain: "example.org" },
  wwwA: { name: "Www entry A", url: "https://www.forms.example.net/", matching: "host" },
  wwwB: { name: "Www entry B", url: "https://www.forms.example.net/", matching: "host" },
});

/** What a fill is judged by. */
export const RULES = Object.freeze(Object.fromEntries(Object.entries(ENTRIES).map(([key, e]) => [key, { url: e.url, matching: e.matching, ...(e.domain ? { domain: e.domain } : {}) }])));

const NO_OFFERS = "the extension keeps no offers to read yet";

/** @param {string} text */
export const sha256 = (text) => createHash("sha256").update(text, "utf8").digest("hex");
/** @param {number} ms */
const sleep = (ms) => new Promise((done) => setTimeout(done, ms));

/**
 * The address of a case's page on the running fixture server.
 * @param {Record<string, any>} c
 * @param {import("./fixtures-server.mjs").Fixtures} server
 */
export function caseUrl(c, server) {
  const scheme = c.scheme ?? "https";
  const port = scheme === "https" ? server.ports.https : server.ports.http;
  const standard = scheme === "https" ? 443 : 80;
  return `${scheme}://${c.host}${port === standard ? "" : `:${port}`}${c.path}`;
}

/** Loads the cases of a set, keeping the ones whose id contains `grep`. @param {"corpus" | "holdout"} set @param {string} [grep] */
export function casesOf(set, grep = "") {
  const all = loadCorpus(formsDirFor(set));
  return grep === "" ? all : all.filter((c) => c.id.includes(grep));
}

/** The pages with a frame on another origin of the same site, to give the extension its host permission for them. @param {Record<string, any>[]} cases @param {import("./fixtures-server.mjs").Fixtures} server */
export function grantUrls(cases, server) {
  return cases.filter((c) => c.frame && c.frame.host !== c.host && (c.scheme ?? "https") === "https").map((c) => caseUrl(c, server));
}

// ----------------------------------------------------------------------- finding and driving elements

/**
 * The element with this id in the selected tab, in the top document, a shadow root or a frame (nested frames
 * too). The session stays inside the frame that holds it, so the caller's next call acts on it; `leave` goes back.
 * @param {import("./driver.mjs").Session} session
 * @param {string} selector "#id"
 * @returns {Promise<any>} the element, or null
 */
export async function locate(session, selector) {
  const name = selector.replace(/^#/, "");
  await session.switchToTopFrame();
  /** @param {number} depth @returns {Promise<any>} */
  const search = async (depth) => {
    const hit = await session.content((/** @type {string} */ id) => {
      /** @param {Document | ShadowRoot} root @returns {Element | null} */
      const walk = (root) => {
        const direct = root.getElementById(id);
        if (direct) return direct;
        for (const el of root.querySelectorAll("*")) {
          if (el.shadowRoot) {
            const inner = walk(el.shadowRoot);
            if (inner) return inner;
          }
        }
        return null;
      };
      return walk(document);
    }, name);
    if (hit) return hit;
    if (depth >= 3) return null;
    const count = /** @type {number} */ (await session.content(() => document.querySelectorAll("iframe, frame").length));
    for (let i = 0; i < count; i += 1) {
      const frames = await session.findAll("iframe, frame");
      if (!frames[i]) continue;
      try {
        await session.switchToFrame(frames[i]);
      } catch {
        continue;
      }
      const inner = await search(depth + 1);
      if (inner) return inner;
      await session.switchToParentFrame();
    }
    return null;
  };
  return search(0);
}

/** Back to the top document. @param {import("./driver.mjs").Session} session */
export const leave = (session) => session.switchToTopFrame();

/**
 * The text of a step with the vault's passwords filled in: `{{password:<entry>}}`.
 * @param {string} text @param {Record<string, string>} passwords
 */
export function expandText(text, passwords) {
  return text.replace(/\{\{password:([A-Za-z]+)\}\}/g, (_, key) => {
    if (!Object.hasOwn(passwords, key)) throw new Error(`a step names the entry ${key}, which the vault does not have`);
    return passwords[key];
  });
}

/**
 * Does the steps of a case with real key events and clicks. `typed` collects the SHA-256 of what was typed into
 * each field (by id), so an offer can be matched to the field its password came from.
 * @param {import("./driver.mjs").Session} session
 * @param {Array<Record<string, any>>} steps
 * @param {{ passwords: Record<string, string>, typed: Record<string, string>, ferretFill?: () => Promise<void> }} ctx
 */
export async function runSteps(session, steps, ctx) {
  for (const step of steps) {
    if (typeof step.type === "string") {
      const el = await locate(session, step.type);
      if (!el) throw new Error(`step: ${step.type} is not on the page`);
      const text = expandText(step.text, ctx.passwords).repeat(step.repeat ?? 1);
      await session.type(el, text);
      ctx.typed[step.type] = sha256(text);
    } else if (typeof step.click === "string") {
      const el = await locate(session, step.click);
      if (!el) throw new Error(`step: ${step.click} is not on the page`);
      await session.click(el);
    } else if (typeof step.key === "string") {
      const keys = /** @type {Record<string, string>} */ ({ Enter: "", Tab: "" });
      if (!keys[step.key]) throw new Error(`step: the key ${step.key} is not known`);
      const active = await session.content(() => {
        /** @type {Element | null} */
        let el = document.activeElement;
        while (el?.shadowRoot?.activeElement) el = el.shadowRoot.activeElement;
        return el;
      });
      if (!active) throw new Error("step: nothing has the focus");
      await session.type(active, keys[step.key]);
    } else if (typeof step.wait === "number") {
      await sleep(step.wait);
    } else if (step.ferret_fill === true) {
      if (!ctx.ferretFill) throw new Error("step: this phase cannot ask the extension to fill");
      await ctx.ferretFill();
    } else {
      throw new Error(`step: ${JSON.stringify(Object.keys(step))} is not supported by this runner yet`);
    }
  }
  await leave(session);
}

// ----------------------------------------------------------------------- reading the page

/**
 * Every input of the selected tab, in every document (frames of any origin, nested up to three deep) and shadow
 * root, with the address of the document that holds it.
 * @param {import("./driver.mjs").Session} session
 * @returns {Promise<Array<{ id: string, type: string, value: string, docUrl: string }>>}
 */
export async function scanDocs(session) {
  /** @type {Array<{ id: string, type: string, value: string, docUrl: string }>} */
  const out = [];
  /** @param {number} depth */
  const walk = async (depth) => {
    let read;
    try {
      read = await session.content(() => {
        /** @type {Array<{ id: string, type: string, value: string }>} */
        const inputs = [];
        /** @param {Document | ShadowRoot} root */
        const visit = (root) => {
          for (const el of root.querySelectorAll("*")) {
            // A hidden input is the page's own data, not a field a fill could reach.
            if ((el instanceof HTMLInputElement && el.type !== "hidden") || el instanceof HTMLTextAreaElement) inputs.push({ id: el.id, type: el.type, value: el.value });
            if (el.shadowRoot) visit(el.shadowRoot);
          }
        };
        visit(document);
        return { url: location.href, inputs };
      });
    } catch {
      out.push({ id: "", type: "unreadable", value: "", docUrl: `unreadable:${depth}` });
      return;
    }
    for (const i of read.inputs) out.push({ ...i, docUrl: read.url });
    if (depth >= 3) return;
    const count = /** @type {number} */ (await session.content(() => document.querySelectorAll("iframe, frame").length));
    for (let i = 0; i < count; i += 1) {
      const frames = await session.findAll("iframe, frame");
      if (!frames[i]) continue;
      try {
        await session.switchToFrame(frames[i]);
      } catch {
        continue;
      }
      try {
        await walk(depth + 1);
      } finally {
        await session.switchToParentFrame();
      }
    }
  };
  await session.switchToTopFrame();
  await walk(0);
  return out;
}

// ----------------------------------------------------------------------- the fill phase

/**
 * @typedef {Awaited<ReturnType<typeof import("./adversary.mjs").world>>} World
 */

/**
 * Opens a case's page and does its `prepare` steps. Returns the tab's id.
 * @param {World} w @param {Record<string, any>} c
 */
async function openCase(w, c) {
  const tabId = await w.visit(caseUrl(c, w.server));
  // A frame may load after the page does.
  if (c.frame) await sleep(1200);
  await runSteps(w.session, c.prepare ?? [], { passwords: w.passwords, typed: {} });
  return tabId;
}

/**
 * The extension's list for a tab and "Fill" on the row of one entry, on one popup session.
 * @param {World} w @param {number} tabId @param {string} key
 * @returns {Promise<{ offered: string[], ok: boolean, reason?: string }>}
 */
async function fillEntry(w, tabId, key) {
  await w.ui.open();
  try {
    const list = await w.ui.body("candidates", { tab_id: tabId });
    const handles = /** @type {Array<{ name: string, ref: string }>} */ (list.handles ?? []);
    const offered = handles.map((h) => w.keyOf(h.name)).filter((k) => typeof k === "string");
    const row = handles.find((h) => h.name === w.named[key]);
    if (!row) return { offered, ok: false, reason: "not_offered" };
    const reply = await w.ui.ask("fill", { ref: row.ref, tab_id: tabId });
    if (reply.type !== "fill") return { offered, ok: false, reason: `the extension answered ${reply.type}` };
    return { offered, ok: reply.body?.ok === true, ...(reply.body?.ok === true ? {} : { reason: String(reply.body?.reason ?? "not_filled") }) };
  } finally {
    await w.ui.close();
  }
}

/** The entries the extension offers on the open page. @param {World} w @param {number} tabId @returns {Promise<string[]>} */
async function offeredEntries(w, tabId) {
  await w.ui.open();
  try {
    const list = await w.ui.body("candidates", { tab_id: tabId });
    return /** @type {Array<{ name: string }>} */ (list.handles ?? []).map((h) => w.keyOf(h.name)).filter((k) => typeof k === "string");
  } finally {
    await w.ui.close();
  }
}

/**
 * The fill phase of one case.
 * @param {World} w @param {Record<string, any>} c
 * @returns {Promise<import("./matrixReport.mjs").Result>}
 */
export async function fillCase(w, c) {
  /** @type {import("./matrixReport.mjs").Result} */
  const result = { case: c, ran: { fill: false, capture: false }, observed: { fills: [], tried: [], entries: RULES, offers: [], generated: null } };
  const want = c.expect.fill;
  if (want && Object.values(want.fields).some((kind) => String(kind).startsWith("totp"))) {
    // The vault of the matrix cannot hold a one-time-code secret yet, so there is no code to look for.
    result.error = "the matrix vault has no one-time-code entry yet";
    return result;
  }
  try {
    let tabId = await openCase(w, c);
    // A positive case fills the entry it names; any other case fills every entry the page is offered (what a
    // person who clicks Fill on each would get).
    const keys = want ? [want.entry] : await offeredEntries(w, tabId);
    const unique = [...new Set(keys)];
    for (let i = 0; i < unique.length; i += 1) {
      const key = unique[i];
      if (i > 0) tabId = await openCase(w, c);
      const reply = await fillEntry(w, tabId, key);
      result.observed?.tried?.push({ entry: key, ok: reply.ok, ...(reply.reason ? { reason: reply.reason } : {}) });
      // The page may put the state back (a controlled field) or move on; look after a moment.
      await sleep(700);
      const password = w.passwords[key];
      for (const input of await scanDocs(w.session)) {
        if (input.value === "") continue;
        if (input.value === password) result.observed?.fills?.push({ entry: key, kind: "password", id: `#${input.id}`, docUrl: input.docUrl });
        else if (input.value === VAULT_USERNAME) result.observed?.fills?.push({ entry: key, kind: "username", id: `#${input.id}`, docUrl: input.docUrl });
      }
      await leave(w.session);
    }
    result.ran.fill = true;
  } catch (error) {
    result.error = String(error instanceof Error ? error.message : error).slice(0, 300);
  }
  return result;
}

/**
 * The fill phase over every case.
 * @param {World} w @param {Record<string, any>[]} cases @param {(line: string) => void} [log]
 * @returns {Promise<import("./matrixReport.mjs").Result[]>}
 */
export async function runFillPhase(w, cases, log = () => {}) {
  /** @type {import("./matrixReport.mjs").Result[]} */
  const results = [];
  for (const c of cases) {
    const r = await fillCase(w, c);
    log(`fill ${c.id}: ${r.ran.fill ? `${r.observed?.fills?.length ?? 0} values` : `not run (${r.error})`}`);
    results.push(r);
  }
  return results;
}

// ----------------------------------------------------------------------- the capture phase

/**
 * What the extension holds as offers for a tab, through the test bridge. Until the extension keeps offers,
 * the bridge answers `{ available: false }`.
 * @param {World} w @param {number} tabId
 * @returns {Promise<{ available: boolean, offers: Array<Record<string, any>> }>}
 */
export async function offersPeek(w, tabId) {
  const reply = await w.fromBridge(() => w.bridge.invoke("offers_peek", { tab_id: tabId }));
  if (!reply || typeof reply !== "object" || reply.available !== true) return { available: false, offers: [] };
  return { available: true, offers: Array.isArray(reply.offers) ? reply.offers : [] };
}

/**
 * The capture phase of one case: the steps, then the offers.
 * @param {World} w @param {Record<string, any>} c
 * @returns {Promise<import("./matrixReport.mjs").Result>}
 */
export async function captureCase(w, c) {
  /** @type {import("./matrixReport.mjs").Result} */
  const result = { case: c, ran: { fill: false, capture: false }, observed: { fills: [], tried: [], entries: RULES, offers: [], generated: null } };
  try {
    const tabId = await openCase(w, c);
    const first = await offersPeek(w, tabId);
    if (!first.available) {
      result.error = NO_OFFERS;
      return result;
    }
    /** @type {Record<string, string>} */
    const typed = {};
    await runSteps(w.session, c.steps, { passwords: w.passwords, typed, ferretFill: async () => { await fillEntry(w, tabId, "forms"); } });
    const wantsOffer = c.class !== "negative" && c.expect.capture !== null;
    // An offer follows a submit by up to 15 seconds; a case that expects none is watched as long.
    let peek = first;
    const until = Date.now() + (wantsOffer ? 20_000 : 8_000);
    while (Date.now() < until) {
      await sleep(1000);
      peek = await offersPeek(w, tabId);
      if (wantsOffer && peek.offers.length > 0) break;
    }
    result.observed = {
      ...result.observed,
      offers: peek.offers.map((o) => ({
        type: String(o.type),
        origin: String(o.origin),
        username: typeof o.username === "string" ? o.username : null,
        password_field: Object.entries(typed).find(([, hash]) => hash === o.password_sha256)?.[0] ?? null,
        ...(o.reuse === true ? { reuse: true } : {}),
        ...(typeof o.info === "string" ? { info: o.info } : {}),
        ...(typeof o.target_name === "string" ? { target_entry: w.keyOf(o.target_name) } : {}),
        ...(typeof o.target_host === "string" ? { target_host: o.target_host } : {}),
        ...(typeof o.target_match === "string" ? { target_match: o.target_match } : {}),
        ...(o.picked === true ? { picked: true } : {}),
        ...(o.written_without_click === true ? { written_without_click: true } : {}),
      })),
    };
    result.ran.capture = true;
  } catch (error) {
    result.error = String(error instanceof Error ? error.message : error).slice(0, 300);
  }
  return result;
}

/**
 * The capture phase over every case.
 * @param {World} w @param {Record<string, any>[]} cases @param {(line: string) => void} [log]
 */
export async function runCapturePhase(w, cases, log = () => {}) {
  /** @type {import("./matrixReport.mjs").Result[]} */
  const results = [];
  // Without offers to read there is nothing to measure: no page is opened, every case is not run.
  if (!(await offersPeek(w, 0)).available) {
    for (const c of cases) results.push({ case: c, ran: { fill: false, capture: false }, observed: { fills: [], tried: [], entries: RULES, offers: [], generated: null }, error: NO_OFFERS });
    log(`capture: ${NO_OFFERS}; ${cases.length} cases not run`);
    return results;
  }
  for (const c of cases) {
    const r = await captureCase(w, c);
    log(`capture ${c.id}: ${r.ran.capture ? `${r.observed?.offers?.length ?? 0} offers` : `not run (${r.error})`}`);
    results.push(r);
  }
  return results;
}

/** Merges the results of the two phases of each case. @param {import("./matrixReport.mjs").Result[]} fill @param {import("./matrixReport.mjs").Result[]} capture */
export function mergePhases(fill, capture) {
  return fill.map((f) => {
    const c = capture.find((r) => r.case.id === f.case.id);
    if (!c) return f;
    return {
      case: f.case,
      ran: { fill: f.ran.fill, capture: c.ran.capture },
      observed: { ...f.observed, offers: c.observed?.offers ?? [], generated: c.observed?.generated ?? null },
      ...(f.error || c.error ? { error: [f.error, c.error].filter(Boolean).join("; ") } : {}),
    };
  });
}
