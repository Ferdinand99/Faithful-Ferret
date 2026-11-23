// What the specs about offers share (72-capture-adversarial, 81-u2-end-to-end): a signed-in Firefox with the vault kept open and
// "Offer to save passwords" turned on with the settings tab's real click, the id of the page's tab, the real popup in a
// window of its own showing an offer's card, and a sign-up of the corpus made unique to a run (the account is shared by the
// channels, and a login the vault holds already would be an update, not a save). Not a spec (run.sh picks up *.spec.mjs only).
import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";
import { world } from "./adversary.mjs";
import { POPUP_URL, SLOW } from "./e2e.mjs";
import { EXTENSION_ORIGIN } from "./harness.mjs";
import { ENTRIES, casesOf, offersPeek } from "./matrix.mjs";

export const sleep = (/** @type {number} */ ms) => new Promise((resolve) => setTimeout(resolve, ms));

/** @typedef {Awaited<ReturnType<typeof world>>} World */

/**
 * A world with the vault kept open and "Offer to save passwords" on.
 * @param {"release" | "esr"} channel
 * @returns {Promise<World>}
 */
export async function readyWorld(channel) {
  const w = await world(channel, { grant: [], entries: ENTRIES });
  await w.ui.open();
  try {
    await w.ui.body("settings", { lock_seconds: 86_400 });
  } finally {
    await w.ui.close();
  }
  await w.session.navigate(`${EXTENSION_ORIGIN}/pages/settings.html`);
  await w.session.waitFor(() => w.session.content(() => document.body.dataset.ready === "1"), 15_000, "the settings page");
  const [toggle] = await w.session.findAll('[data-role="capture-switch"]');
  assert.ok(toggle, `${channel}: the settings page has the switch`);
  await w.session.click(toggle);
  await w.session.waitFor(() => w.session.content(() => document.querySelector('[data-role="capture-switch"]')?.getAttribute("aria-checked") === "true"), 15_000, "capture on");
  await w.session.switchTo(w.pageTab);
  return w;
}

/** The id of the newest tab (the page of the case). @param {World} w */
export async function newestTab(w) {
  const tabs = await w.fromBridge(() => w.bridge.invoke("tabs.query", {}));
  return tabs.reduce((/** @type {{ id: number }} */ a, /** @type {{ id: number }} */ b) => (b.id > a.id ? b : a)).id;
}

/**
 * The real popup about a tab, in a window of its own, with the card of kind `kind` shown and its 400 ms guard passed.
 * @param {World} w @param {number} tabId @param {string} kind the card's `data-kind`
 */
export async function popupWithCard(w, tabId, kind) {
  const handle = await w.session.newWindow();
  await w.session.switchTo(handle);
  await w.session.navigate(`${POPUP_URL}?tab=${tabId}`);
  await w.page.ready();
  try {
    await w.page.waitVisible('[data-role="offer-card"]', 30_000);
  } catch (error) {
    const body = await w.session.content(() => (document.body.textContent ?? "").replace(/\s+/g, " ").slice(0, 600));
    const listed = await offersPeek(w, tabId);
    throw new Error(`no offer card in the popup about tab ${tabId}: ${String(error)}; the popup shows: ${body}; the store holds ${JSON.stringify(listed.offers.map((o) => [o.type, o.origin]))}`);
  }
  await w.session.waitFor(() => w.session.content(() => document.querySelector('[data-role="offer-card"] [data-role="offer-actions"], [data-role="offer-gone"]') !== null), SLOW, "the card");
  const shown = await w.session.content(() => document.querySelector('[data-role="offer-card"]')?.getAttribute("data-kind") ?? "");
  assert.equal(shown, kind, `the card is a ${kind} card: ${await w.session.content(() => (document.querySelector('[data-role="offer-card"]')?.textContent ?? "").slice(0, 300))}`);
  await sleep(700);
  return handle;
}

/**
 * A copy of a corpus sign-up case whose user name and password are this run's own.
 * @param {string} id the case (a typed sign-up: a user name field, #pw and #pw2)
 * @param {string} [tag]
 */
export function uniqueSignup(id, tag = randomBytes(3).toString("hex")) {
  const [base] = casesOf("corpus", id);
  assert.equal(base?.id, id);
  const c = structuredClone(base);
  const user = `anna-${tag}@example.net`;
  const password = `Zq7!su-${tag}-Vm4$`;
  c.steps = c.steps.map((/** @type {any} */ s) => (s.type === "#pw" || s.type === "#pw2" ? { ...s, text: password } : typeof s.type === "string" ? { ...s, text: user } : s));
  c.expect.capture.username = user;
  return { c, user, password, tag };
}

/**
 * Shows the web vault's item list and waits for an item whose row holds `name`; returns the item page's href.
 * @param {World} w @param {string} name
 */
export async function vaultItemHref(w, name) {
  await w.session.switchTo(w.vaultTab);
  const base = (await w.session.currentUrl()).split("#")[0];
  await w.session.navigate(`${base}#/items`);
  await w.page.waitVisible('[data-role="list"]', SLOW);
  return w.session.waitFor(
    () => w.session.content((/** @type {string} */ wanted) => [...document.querySelectorAll('[data-role="list"] a[href^="#/items/"]')].find((a) => (a.textContent ?? "").includes(wanted))?.getAttribute("href") ?? null, name),
    60_000,
    `the item ${name} in the web vault's list`,
  );
}

/**
 * The text of every node under `css` in the web vault's current page.
 * @param {World} w @param {string} css
 */
export const allText = (w, css) => w.session.content((/** @type {string} */ selector) => [...document.querySelectorAll(selector)].map((n) => (n.textContent ?? "").trim()), css);
