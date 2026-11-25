// The popup's passkey part (pages/popupPasskeys.mjs; the `passkeys` feature): the card of a page's request that waits for Ferret's
// window, the list of a conditional request with its verification step, the list for information without a request, the line
// "click the page again", and the guard of every click (only the person's, 400 ms after each change). It runs on the DOM stand-in
// against a fake background; the package is the test variant, built once. The background's side is in passkeyGet.test.mjs.
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { pathToFileURL } from "node:url";
import { test } from "node:test";
import { byRole, one, settle, textsOf, useDocument } from "./pageDom.mjs";
import { pkg } from "./sessionHelpers.mjs";
import { PASSKEY_PAGES_GEN_FILE, passkeyPagesModule } from "../../scripts/build.mjs";

const ID = (/** @type {number} */ n) => n.toString(16).padStart(32, "0");
const RLO = String.fromCharCode(0x202e);
const CANDIDATES = [
  { item_id: ID(1), name: "Example", user_name: "anna", created: 1_800_000_000_000 },
  { item_id: ID(3), name: `Example ${RLO}(work)`, user_name: "anna@example.com", created: 1_700_000_000_000 },
];

async function setup() {
  useDocument();
  const { dir } = await pkg();
  const load = (/** @type {string} */ path) => import(pathToFileURL(join(dir, ...path.split("/"))).href);
  const catalog = JSON.parse(readFileSync(join(dir, "locales.en.json"), "utf8"));
  return { part: await load("pages/popupPasskeys.mjs"), gen: await load("pages/provider.gen.mjs"), texts: textsOf(catalog, "en"), dir };
}

/** A clock and timers the test moves. */
function clockWorld() {
  const clock = { t: 100_000 };
  /** @type {Array<{ fn: () => void, at: number }>} */
  let timers = [];
  return {
    now: () => clock.t,
    schedule: (/** @type {() => void} */ fn, /** @type {number} */ ms) => {
      const handle = { fn, at: clock.t + ms };
      timers.push(handle);
      return handle;
    },
    cancel: (/** @type {any} */ handle) => {
      timers = timers.filter((t) => t !== handle);
    },
    /** @param {number} ms */
    async tick(ms) {
      clock.t += ms;
      for (const due of timers.filter((t) => t.at <= clock.t)) {
        timers = timers.filter((t) => t !== due);
        due.fn();
      }
      await settle();
    },
    pending: () => timers.length,
  };
}

/**
 * A fake background for one tab: `state.tab` is what `passkey_tab` says, `state.list` what `passkey_tab_list` says, `state.choose`
 * and `state.verify` the answers of a choice and of a verification. Every call is recorded.
 * @param {Record<string, any>} [over]
 */
function background(over = {}) {
  const state = {
    tab: { ok: true, waiting: null, conditional: false, again: null, foreign: false },
    list: { ok: true, mode: "none" },
    choose: /** @type {any[]} */ ([{ ok: true }]),
    verify: { ok: true },
    open: { ok: true },
    ...over,
  };
  /** @type {Array<{ type: string, body: any }>} */
  const calls = [];
  const request = async (/** @type {string} */ type, /** @type {any} */ body) => {
    calls.push({ type, body });
    if (type === "passkey_tab") return state.tab;
    if (type === "passkey_tab_list") return state.list;
    if (type === "passkey_choose") return state.choose.length > 1 ? state.choose.shift() : state.choose[0];
    if (type === "passkey_verify") return state.verify;
    if (type === "passkey_tab_open") return state.open;
    throw Object.assign(new Error("not_available"), { code: "not_available" });
  };
  return { state, calls, request };
}

/** A click, as the browser makes it for the person (`isTrusted`) or for a script. @param {any} target @param {boolean} [trusted] */
async function tap(target, trusted = true) {
  assert.ok(target, "there is something to click");
  const event = { type: "click", isTrusted: trusted, target, defaultPrevented: false, preventDefault() {} };
  for (const [type, fn] of target.listeners) if (type === "click") fn(event);
  await settle();
}

/** @param {any} node @returns {string} */
const text = (node) => (node === null ? "" : node.textContent);

test("the_popup_part_shows_the_card_the_line_and_the_list_and_counts_only_guarded_clicks", async () => {
  const { part, texts } = await setup();
  const clock = clockWorld();
  const bg = background({ tab: { ok: true, waiting: { origin: "https://xn--bcher-kva.example", kind: "get" }, conditional: false, again: null, foreign: true } });
  const answered = { n: 0 };
  const view = part.createPopupPasskeys({ texts, request: bg.request, tabId: 7, unlocked: false, onAnswered: () => void (answered.n += 1), ...clock });
  await view.start();
  // Locked: the card only (the window unlocks), never the list.
  assert.equal(view.root.hidden, false);
  assert.equal(bg.calls.some((c) => c.type === "passkey_tab_list"), false, "a locked popup asks for no list");
  assert.equal(text(one(view.root, "passkey-popup-card-host")), "xn--bcher-kva.example", "the host the browser gave, as an A-label");
  assert.match(text(one(view.root, "passkey-popup-card")), /asks for a passkey/);
  assert.match(text(one(view.root, "passkey-popup-foreign")), /another password manager or the site itself/i);
  // A click too soon, or one a script made, counts for nothing.
  const open = one(view.root, "passkey-popup-open");
  await tap(open);
  await tap(open, false);
  assert.equal(bg.calls.filter((c) => c.type === "passkey_tab_open").length, 0);
  await clock.tick(400);
  await tap(open, false);
  assert.equal(bg.calls.filter((c) => c.type === "passkey_tab_open").length, 0);
  await tap(open);
  assert.deepEqual(bg.calls.filter((c) => c.type === "passkey_tab_open").map((c) => c.body), [{ tab_id: 7, which: "waiting" }]);
  // The window took it: the card goes at the next look, and the part hides when nothing is left.
  bg.state.tab = { ok: true, waiting: null, conditional: false, again: "get", foreign: false };
  await clock.tick(1000);
  assert.equal(one(view.root, "passkey-popup-card"), null);
  assert.match(text(one(view.root, "passkey-popup-again")), /click the passkey button on the page again/i);
  bg.state.tab = { ok: true, waiting: null, conditional: false, again: null, foreign: false };
  await clock.tick(1000);
  assert.equal(view.root.hidden, true);
  view.stop();
  assert.equal(clock.pending(), 0, "a stopped part asks nothing more");
  assert.equal(answered.n, 0);
});

test("the_popup_part_picks_a_passkey_of_a_conditional_request_and_verifies_in_the_popup", async () => {
  const { part, texts } = await setup();
  const clock = clockWorld();
  const bg = background({
    tab: { ok: true, waiting: null, conditional: true, again: null, foreign: false },
    list: { ok: true, mode: "pick", host: "example.com", candidates: CANDIDATES, recent: false, methods: ["prf", "pin", "password"], online: true },
    choose: [{ ok: false, reason: "verification_needed" }, { ok: true }],
  });
  let answered = 0;
  const view = part.createPopupPasskeys({ texts, request: bg.request, tabId: 7, unlocked: true, onAnswered: () => void (answered += 1), ...clock });
  await view.start();
  assert.equal(text(one(view.root, "passkey-popup-title")), "Passkeys for example.com");
  // Oldest first; a name's direction characters are gone, and every name of the vault is isolated.
  const rows = byRole(view.root, "passkey-popup-pick");
  assert.deepEqual(rows.map((r) => r.getAttribute("data-item")), [ID(3), ID(1)]);
  assert.equal(text(rows[0]).includes(RLO), false);
  assert.equal(one(view.root, "passkey-popup-not-asked"), null);
  await clock.tick(400);
  await tap(rows[0]);
  assert.deepEqual(bg.calls.filter((c) => c.type === "passkey_choose").map((c) => c.body), [{ tab_id: 7, kind: "get", item_id: ID(3) }]);
  // Verification: the PIN and the master password here; Windows Hello opens Ferret's window (the popup cannot ask for it).
  // One way, to keep the popup short: the PIN when there is one (else the master password).
  assert.ok(one(view.root, "passkey-verify-pin-form"));
  assert.equal(one(view.root, "passkey-verify-password-form"), null);
  assert.equal(one(view.root, "passkey-verify-prf"), null, "no WebAuthn call from the popup");
  const prf = one(view.root, "passkey-popup-prf");
  assert.ok(prf);
  await clock.tick(400);
  await tap(prf);
  assert.deepEqual(bg.calls.filter((c) => c.type === "passkey_tab_open").map((c) => c.body), [{ tab_id: 7, which: "conditional" }]);
  // The PIN: sent once, the field emptied before it goes, and the same choice is sent again after the background's mark.
  const pin = /** @type {any} */ (one(view.root, "passkey-verify-pin"));
  pin.value = "123456";
  const form = /** @type {any} */ (one(view.root, "passkey-verify-pin-form"));
  for (const [type, fn] of form.listeners) if (type === "submit") fn({ type, target: form, preventDefault() {} });
  assert.equal(pin.value, "", "emptied at once");
  await settle();
  assert.deepEqual(bg.calls.filter((c) => c.type === "passkey_verify").map((c) => c.body), [{ tab_id: 7, method: "pin", pin: "123456" }]);
  assert.deepEqual(bg.calls.filter((c) => c.type === "passkey_choose").map((c) => c.body.item_id), [ID(3), ID(3)]);
  assert.equal(answered, 1);
  view.stop();
});

test("the_popup_part_follows_the_tab_and_lists_for_information_without_a_request", async () => {
  const { part, texts, gen } = await setup();
  // The generated module hands the popup its part in a build with the feature.
  assert.equal(gen.createPopupPasskeys, part.createPopupPasskeys);
  const clock = clockWorld();
  const bg = background({ list: { ok: true, mode: "info", host: "example.com", candidates: CANDIDATES } });
  const view = part.createPopupPasskeys({ texts, request: bg.request, tabId: 7, unlocked: true, ...clock });
  await view.start();
  // No request: the passkeys for information, no button.
  assert.deepEqual(byRole(view.root, "passkey-popup-pick"), []);
  assert.equal(byRole(view.root, "passkey-popup-info").length, 2);
  assert.match(text(one(view.root, "passkey-popup-not-asked")), /has not asked/);
  // The page starts its conditional request: the list is read again and gets its buttons.
  bg.state.tab = { ok: true, waiting: null, conditional: true, again: null, foreign: false };
  bg.state.list = { ok: true, mode: "pick", host: "example.com", candidates: CANDIDATES, recent: true, methods: ["recent"], online: true };
  await clock.tick(1000);
  assert.equal(byRole(view.root, "passkey-popup-pick").length, 2);
  // The page aborts (or navigates): the buttons go at the next look.
  bg.state.tab = { ok: true, waiting: null, conditional: false, again: null, foreign: false };
  bg.state.list = { ok: true, mode: "none" };
  await clock.tick(1000);
  assert.deepEqual(byRole(view.root, "passkey-popup-pick"), []);
  assert.equal(view.root.hidden, true);
  // The list is read only when the popup opens and when the request comes or goes, never on every look (it needs the open vault,
  // and reading it must not keep the vault from locking).
  const lists = bg.calls.filter((c) => c.type === "passkey_tab_list").length;
  await clock.tick(1000);
  await clock.tick(1000);
  assert.equal(bg.calls.filter((c) => c.type === "passkey_tab_list").length, lists);
  view.stop();
});

test("the_popup_reaches_its_passkey_part_only_through_the_generated_module", () => {
  assert.equal(PASSKEY_PAGES_GEN_FILE, "pages/provider.gen.mjs");
  assert.match(passkeyPagesModule(["passkeys", "save"], new Map()), /^export \{ createPopupPasskeys \} from "\.\/popupPasskeys\.mjs";$/m);
  // Without the feature it imports nothing: a package without the part has no edge to it.
  const off = passkeyPagesModule(["save", "unlock"], new Map());
  assert.match(off, /^export const createPopupPasskeys = null;$/m);
  assert.doesNotMatch(off, /import|from/);
  assert.throws(() => passkeyPagesModule([], new Map([[PASSKEY_PAGES_GEN_FILE, Buffer.from("")]])), /generated by the build/);
});
