// The offer cards of the popup (offerCards.mjs), on a small stand-in for the DOM with the texts of the built package: what a
// card shows (the host from the core, never a password), when its buttons count (not in the first 400 ms, never on Enter,
// never with the focus on them), which login an update goes to, and the texts in both languages. The background is a fake
// that records every request.
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { pathToFileURL } from "node:url";
import { test } from "node:test";
import { byRole, click, one, settle, textsOf, useDocument, withAttribute } from "./pageDom.mjs";
import { pkg } from "./sessionHelpers.mjs";

const SECRET = "Sentinel-PASSWORD-never-on-the-card-3k";
const OFFER = "a1".repeat(16);
const HOST = { a_label: "xn--bcher-kva.example", unicode: "bücher.example" };

/** @param {string} dir */
function packageOf(dir) {
  return {
    load: (/** @type {string} */ path) => import(pathToFileURL(join(dir, ...path.split("/"))).href),
    catalog: (/** @type {string} */ lang) => JSON.parse(readFileSync(join(dir, `locales.${lang}.json`), "utf8")),
    texts: (/** @type {string} */ lang) => textsOf(JSON.parse(readFileSync(join(dir, `locales.${lang}.json`), "utf8")), lang),
  };
}

/** A classification as the flow gives it. @param {Record<string, unknown>} [over] */
const classification = (over = {}) => ({ ok: true, action: "save", targets: [], domainOnly: [], reused: [], usernameFrom: "typed", ...over });

/**
 * A fake background that records every request of the flow.
 * @param {{ classify?: any, folders?: string[], save?: any, update?: any, reveal?: any }} [answers]
 */
function fakeFlow({ classify = classification(), folders = ["Work", "Private"], save = { ok: true, pending: true }, update = { ok: true, pending: false }, reveal = { ok: true, value: SECRET } } = {}) {
  /** @type {Array<{ call: string, args: any[] }>} */
  const calls = [];
  const record = (/** @type {string} */ call, /** @type {any} */ answer) => async (/** @type {any[]} */ ...args) => {
    calls.push({ call, args });
    return typeof answer === "function" ? answer(...args) : answer;
  };
  return {
    calls,
    flow: {
      list: record("list", { ok: true, offers: [], notice: null }),
      classify: record("classify", classify),
      folders: record("folders", folders),
      save: record("save", save),
      updatePassword: record("updatePassword", update),
      dismiss: record("dismiss", { ok: true }),
      never: record("never", { ok: true }),
      reveal: record("reveal", reveal),
    },
  };
}

/** @param {Record<string, unknown>} [over] */
const offerOf = (over = {}) => ({ offerId: OFFER, kind: "signup", host: HOST, username: "anna@example.net", generated: false, incognito: false, ...over });

/** The test variant's module, the English texts and a clock the test moves. */
async function setup() {
  useDocument();
  const pack = packageOf((await pkg()).dir);
  const mod = await pack.load("pages/offerCards.mjs");
  const clock = { t: 10_000 };
  return { pack, mod, clock, now: () => clock.t, texts: pack.texts("en") };
}

/** A key on an element, to the element's own listeners and the card's. @param {any} target @param {string} key */
function press(target, key) {
  const event = { type: "keydown", key, target, defaultPrevented: false, preventDefault() { event.defaultPrevented = true; } };
  for (const [type, fn] of target.listeners) if (type === "keydown") fn(event);
  // The event bubbles to the card, as in the browser.
  let up = target.parentNode;
  while (up) {
    for (const [type, fn] of up.listeners ?? []) if (type === "keydown") fn(event);
    up = up.parentNode;
  }
  return event;
}

test("the_offer_card_shows_the_host_from_the_core_and_never_a_password", async () => {
  const { mod, now, texts } = await setup();
  const fake = fakeFlow();
  const card = mod.createOfferCard({ texts, flow: fake.flow, offer: offerOf(), now });
  await card.loaded;
  const text = card.root.textContent;
  // The host as the core shows it: the Unicode form and the A-label beside it, each left to right.
  assert.equal(one(card.root, "offer-host")?.getAttribute("dir"), "ltr");
  assert.equal(one(card.root, "offer-host")?.getAttribute("data-a-label"), HOST.a_label);
  assert.ok(text.includes(HOST.unicode) && text.includes(HOST.a_label), "both forms of the host");
  assert.equal(one(card.root, "offer-title")?.textContent, "Save in Ferret?");
  assert.equal(card.root.getAttribute("data-kind"), "save");
  // The name and the user name are editable, the name starts as the host without `www.`, the folders are the vault's.
  assert.equal(one(card.root, "offer-name")?.value, HOST.unicode);
  assert.equal(one(card.root, "offer-username")?.value, "anna@example.net");
  assert.deepEqual(byRole(card.root, "offer-folder")[0].childNodes.map((o) => o.textContent), ["No folder", "Work", "Private"]);
  // The password is hidden: an empty password field, the hint, and nowhere in the page.
  const password = one(card.root, "offer-password");
  assert.equal(password?.getAttribute("type"), "password");
  assert.equal(password?.value, "");
  assert.equal(password?.hasAttribute("readonly"), true);
  assert.ok(text.includes("Hidden."), "it says the password is hidden");
  assert.equal(text.includes(SECRET), false);
  assert.ok(text.includes("never asks for your master password inside a web page"), "the master password line");
  assert.equal(fake.calls.some((c) => c.call === "reveal"), false, "nothing asked for the password before a click on Show");
  // Every control of the card carries the mark of the feature.
  for (const button of byRole(card.root, "offer-save")) assert.equal(button.getAttribute("data-feature"), "save");
  assert.equal(card.root.getAttribute("data-feature"), "save");
  await settle();
  assert.deepEqual(
    fake.calls.map((c) => c.call),
    ["classify", "folders"],
  );
});

test("the_password_can_be_shown_on_a_click_and_is_wiped_when_hidden_or_when_the_card_goes", async () => {
  const { mod, clock, now, texts } = await setup();
  const fake = fakeFlow();
  const card = mod.createOfferCard({ texts, flow: fake.flow, offer: offerOf(), now });
  await card.loaded;
  clock.t += 1000;
  const toggle = one(card.root, "offer-password-toggle");
  const input = one(card.root, "offer-password");
  assert.equal(toggle?.getAttribute("aria-label"), "Show password");
  assert.equal(toggle?.getAttribute("aria-pressed"), "false");
  await click(toggle);
  assert.equal(input?.value, SECRET);
  assert.equal(input?.getAttribute("type"), "text");
  assert.equal(toggle?.getAttribute("aria-pressed"), "true");
  assert.equal(toggle?.getAttribute("aria-label"), "Show password", "one state for a screen reader: a fixed name and aria-pressed");
  assert.ok(one(card.root, "offer-password-hint")?.textContent.startsWith("Shown until"), "the hint says it is shown");
  await click(toggle);
  assert.equal(input?.value, "");
  assert.equal(input?.getAttribute("type"), "password");
  assert.ok(one(card.root, "offer-password-hint")?.textContent.startsWith("Hidden."));
  assert.equal(card.root.textContent.includes(SECRET), false);
  // Shown again and then the card is closed (a lock, a rebuild): the field is emptied.
  await click(toggle);
  assert.equal(input?.value, SECRET);
  card.hide();
  assert.equal(input?.value, "");
  assert.equal(input?.getAttribute("type"), "password");
  // A refused reveal says so and shows nothing.
  const gone = fakeFlow({ reveal: { ok: false, reason: "not_offered" } });
  const other = mod.createOfferCard({ texts, flow: gone.flow, offer: offerOf(), now });
  await other.loaded;
  clock.t += 1000;
  await click(one(other.root, "offer-password-toggle"));
  assert.equal(one(other.root, "offer-password")?.value, "");
  assert.equal(one(other.root, "offer-error")?.hidden, false);
});

test("an_auto_opened_popup_does_not_save_on_enter_or_an_early_click", async () => {
  const { mod, clock, now, texts } = await setup();
  const doc = /** @type {any} */ (globalThis).document;
  const fake = fakeFlow();
  const card = mod.createOfferCard({ texts, flow: fake.flow, offer: offerOf(), now });
  await card.loaded;
  card.focus();
  // No default button and no form: nothing in the card submits; the focus is on the heading, not on a button that writes.
  assert.deepEqual(withAttribute(card.root, "type").filter((n) => n.getAttribute("type") === "submit"), []);
  assert.equal(card.root.tagName, "SECTION");
  assert.equal(byRole(card.root, "offer-title")[0], doc.activeElement, "the focus starts on the heading");
  for (const role of ["offer-save", "offer-not-now", "offer-never"]) assert.notEqual(one(card.root, role), doc.activeElement, role);
  const writes = () => fake.calls.filter((c) => ["save", "updatePassword", "dismiss", "never"].includes(c.call));
  // Enter does nothing, in a field and on the card.
  for (const target of [one(card.root, "offer-name"), one(card.root, "offer-username"), card.root]) {
    const event = press(target, "Enter");
    assert.equal(event.defaultPrevented, true);
  }
  await settle();
  assert.deepEqual(writes(), [], "Enter writes nothing");
  // A click in the first 400 ms is ignored, for every control of the card.
  for (const role of ["offer-save", "offer-not-now", "offer-never", "offer-password-toggle"]) {
    clock.t += 399 - (clock.t - 10_000);
    await click(one(card.root, role));
  }
  assert.equal(clock.t - 10_000, 399);
  assert.deepEqual(writes(), [], "a click before 400 ms counts for nothing");
  assert.equal(fake.calls.some((c) => c.call === "reveal"), false);
  // After that it counts, once.
  clock.t += 1;
  const saveButton = one(card.root, "offer-save");
  await click(saveButton);
  assert.equal(writes().length, 1);
  assert.deepEqual(writes()[0].args, [OFFER, { name: HOST.unicode, username: "anna@example.net", folder: null }]);
  assert.equal(JSON.stringify(writes()[0].args).includes(SECRET), false, "the message carries no password");
  assert.equal(one(card.root, "offer-result")?.textContent, "Saved. Waiting for sync.");
  // The card is answered: another click does nothing.
  await click(saveButton);
  assert.equal(writes().length, 1);
});

test("reuse_warning_is_shown_above_the_save_button", async () => {
  const { mod, clock, now, texts } = await setup();
  const fake = fakeFlow({ classify: classification({ reused: [{ name: "Other shop", host: { a_label: "other.example.org", unicode: "other.example.org" } }, { name: "Mail", host: null }] }) });
  const card = mod.createOfferCard({ texts, flow: fake.flow, offer: offerOf(), now });
  await card.loaded;
  const children = card.root.childNodes.map((n) => /** @type {any} */ (n).getAttribute?.("data-role"));
  const warning = children.indexOf("offer-reuse");
  const actions = children.indexOf("offer-actions");
  assert.ok(warning >= 0 && actions >= 0 && warning < actions, "the warning comes before the buttons");
  const text = one(card.root, "offer-reuse")?.textContent ?? "";
  assert.ok(text.includes("also used for") && text.includes("Other shop") && text.includes("other.example.org") && text.includes("Mail"));
  assert.equal(byRole(card.root, "offer-reuse-item").length, 2);
  clock.t += 500;
});

test("the_update_card_names_the_login_and_updates_or_saves_as_new_on_a_click", async () => {
  const { mod, clock, now, texts } = await setup();
  const target = { id: "b2".repeat(16), rev: 3, name: "Shop", username: "anna@example.net", how: "host" };
  const fake = fakeFlow({ classify: classification({ action: "update", targets: [target] }), update: { ok: true, pending: true } });
  const card = mod.createOfferCard({ texts, flow: fake.flow, offer: offerOf({ kind: "change" }), now });
  await card.loaded;
  assert.equal(card.root.getAttribute("data-kind"), "update");
  assert.equal(one(card.root, "offer-title")?.textContent, "Update the password?");
  assert.equal(one(card.root, "offer-target-name")?.textContent, "Shop");
  assert.equal(one(card.root, "offer-target-username")?.textContent, "anna@example.net");
  assert.deepEqual(["offer-update", "offer-save-new", "offer-not-now"].map((r) => one(card.root, r)?.textContent), ["Update", "Save as new", "Not now"]);
  assert.equal(one(card.root, "offer-never"), null, "the update card has no \"Never\"");
  clock.t += 500;
  await click(one(card.root, "offer-update"));
  assert.deepEqual(fake.calls.find((c) => c.call === "updatePassword")?.args, [OFFER, { id: target.id, rev: 3 }]);
  assert.equal(one(card.root, "offer-result")?.textContent, "Updated. Waiting for sync.");

  // "Save as new" saves a new login with the page's host as its name.
  const other = fakeFlow({ classify: classification({ action: "update", targets: [target] }) });
  const second = mod.createOfferCard({ texts, flow: other.flow, offer: offerOf(), now });
  await second.loaded;
  clock.t += 500;
  await click(one(second.root, "offer-save-new"));
  assert.deepEqual(other.calls.find((c) => c.call === "save")?.args, [OFFER, { name: HOST.unicode, username: "anna@example.net", folder: null }]);
});

test("a_domain_only_item_is_listed_with_its_host_and_updated_only_on_its_own_click", async () => {
  const { mod, clock, now, texts } = await setup();
  const shared = { id: "c3".repeat(16), rev: 2, name: "Shared login", host: { a_label: "shop.example.net", unicode: "shop.example.net" } };
  const fake = fakeFlow({ classify: classification({ action: "save", domainOnly: [shared] }) });
  const card = mod.createOfferCard({ texts, flow: fake.flow, offer: offerOf(), now });
  await card.loaded;
  // The card is a save card; the other login is listed apart, with its host and the line that says why it is not the target.
  assert.equal(card.root.getAttribute("data-kind"), "save");
  assert.ok(one(card.root, "offer-domain-info")?.textContent.includes("another address of the same site"));
  assert.ok(one(card.root, "offer-domain")?.textContent.includes("shop.example.net"));
  assert.equal(one(card.root, "offer-update"), null, "no update button of its own: only the pick below");
  clock.t += 500;
  await click(one(card.root, "offer-save"));
  assert.equal(fake.calls.some((c) => c.call === "updatePassword"), false, "saving never updates the other login");
  // A fresh card: the pick sends `picked`.
  const again = fakeFlow({ classify: classification({ action: "save", domainOnly: [shared] }) });
  const second = mod.createOfferCard({ texts, flow: again.flow, offer: offerOf(), now });
  await second.loaded;
  clock.t += 500;
  const pick = one(second.root, "offer-domain-update");
  assert.equal(pick?.getAttribute("aria-label"), "Update Shared login");
  await click(pick);
  assert.deepEqual(again.calls.find((c) => c.call === "updatePassword")?.args, [OFFER, { id: shared.id, rev: 2, picked: true }]);
});

test("several_candidates_are_a_list_to_pick_from_and_a_changed_item_shows_the_new_card", async () => {
  const { mod, clock, now, texts } = await setup();
  const a = { id: "b2".repeat(16), rev: 1, name: "Shop A", username: "anna", how: "host" };
  const b = { id: "b3".repeat(16), rev: 4, name: "Shop B", username: "anna", how: "host" };
  const fake = fakeFlow({ classify: classification({ action: "choose", targets: [a, b] }) });
  const card = mod.createOfferCard({ texts, flow: fake.flow, offer: offerOf({ kind: "change" }), now });
  await card.loaded;
  assert.equal(card.root.getAttribute("data-kind"), "choose");
  assert.equal(byRole(card.root, "offer-choice").length, 2);
  assert.equal(one(card.root, "offer-update"), null, "no automatic choice");
  clock.t += 500;
  // The item changed meanwhile: the answer carries the new classification, the card shows it and says why.
  fake.flow.updatePassword = async () => ({ ok: false, reason: "item_changed", classification: classification({ action: "update", targets: [{ ...b, rev: 5 }] }) });
  await click(byRole(card.root, "offer-choice-update")[1]);
  assert.equal(card.root.getAttribute("data-kind"), "update");
  assert.equal(one(card.root, "offer-target-name")?.textContent, "Shop B");
  assert.ok(one(card.root, "offer-error")?.textContent.includes("changed in the meantime"));
  // An offer that is gone says so and leaves nothing to answer (the rebuilt card ignores a click for its first 400 ms).
  fake.flow.updatePassword = async () => ({ ok: false, reason: "not_offered" });
  clock.t += 500;
  await click(one(card.root, "offer-update"));
  assert.ok(one(card.root, "offer-gone")?.textContent.includes("This offer is gone"));
  assert.equal(one(card.root, "offer-update"), null);
});

test("not_now_and_never_answer_and_a_private_window_says_how_long_never_lasts", async () => {
  const { mod, clock, now, texts } = await setup();
  const fake = fakeFlow();
  const card = mod.createOfferCard({ texts, flow: fake.flow, offer: offerOf({ incognito: true }), now });
  await card.loaded;
  assert.ok(one(card.root, "offer-private")?.textContent.includes("until the browser closes"));
  clock.t += 500;
  await click(one(card.root, "offer-never"));
  assert.deepEqual(fake.calls.map((c) => c.call).slice(2), ["never"]);
  assert.ok(one(card.root, "offer-result")?.textContent.includes("until the browser closes"));
  const second = fakeFlow();
  const card2 = mod.createOfferCard({ texts, flow: second.flow, offer: offerOf(), now });
  await card2.loaded;
  clock.t += 500;
  await click(one(card2.root, "offer-not-now"));
  assert.deepEqual(second.calls.map((c) => c.call).slice(2), ["dismiss"]);
  assert.equal(one(card2.root, "offer-result")?.textContent, "Not saved.");
  // A write that is refused for a reason leaves the card, with the reason, for another click.
  const refusing = fakeFlow({ save: { ok: false, reason: "origin_changed" } });
  const card3 = mod.createOfferCard({ texts, flow: refusing.flow, offer: offerOf(), now });
  await card3.loaded;
  clock.t += 500;
  await click(one(card3.root, "offer-save"));
  assert.ok(one(card3.root, "offer-error")?.textContent.includes("The page changed"));
  assert.notEqual(one(card3.root, "offer-save"), null);
});

test("the_section_shows_the_refusal_reason_and_the_cards_of_the_tab", async () => {
  const { mod, now, texts } = await setup();
  const fake = fakeFlow();
  fake.flow.list = async () => ({ ok: true, offers: [offerOf()], notice: "frame_hidden" });
  const section = mod.createOfferSection({ texts, flow: fake.flow, tabId: 7, now });
  assert.equal(await section.loaded, 1);
  assert.equal(section.root.hidden, false);
  assert.equal(one(section.root, "refusal-notice")?.getAttribute("data-reason"), "frame_hidden");
  assert.ok(one(section.root, "refusal-reason")?.textContent.includes("hidden or covered"));
  assert.equal(byRole(section.root, "offer-card").length, 1);
  // A popup about no page has no offers, and shows nothing.
  const none = mod.createOfferSection({ texts, flow: fake.flow, tabId: null, now });
  assert.equal(await none.loaded, 0);
  assert.equal(none.root.hidden, true);
  // The reason stays for as long as the popup is open, also when the next list has none.
  fake.flow.list = async () => ({ ok: true, offers: [], notice: null });
  assert.equal(await section.reload(), 0);
  assert.equal(one(section.root, "refusal-notice")?.getAttribute("data-reason"), "frame_hidden");
});

test("the_flow_sends_only_ids_and_choices_and_every_text_exists_in_both_languages", async () => {
  const { pack, mod } = await setup();
  /** @type {Array<{ type: string, body: any }>} */
  const sent = [];
  const flow = mod.createOfferFlow(async (/** @type {string} */ type, /** @type {any} */ body) => {
    sent.push({ type, body });
    return { ok: true, pending: true, offers: [], folders: [] };
  });
  await flow.save(OFFER, { name: "Shop", username: " ", folder: "" });
  await flow.save(OFFER, { name: "Shop", username: "anna", folder: "Work" });
  await flow.updatePassword(OFFER, { id: "b2".repeat(16), rev: 2, picked: true });
  await flow.dismiss(OFFER);
  await flow.never(OFFER);
  assert.deepEqual(sent.map((s) => s.type), ["offer_save", "offer_save", "offer_update", "offer_dismiss", "offer_never"]);
  assert.deepEqual(sent[0].body, { offer_id: OFFER, name: "Shop" }, "an empty user name and no folder are left out");
  assert.deepEqual(sent[1].body, { offer_id: OFFER, name: "Shop", username: "anna", folder: "Work" });
  for (const s of sent) assert.equal(/password|value|session/.test(Object.keys(s.body).join(",")), false);
  // Every text the card and its errors use exists in English and Norwegian, with the same placeholders.
  const source = readFileSync(join((await pkg()).dir, "pages", "offerCards.mjs"), "utf8");
  const keys = new Set([...source.matchAll(/["'`](offer\.[a-z_.]+)["'`]/g)].map((m) => m[1]));
  for (const reason of mod.OFFER_ERRORS) keys.add(`offer.error.${reason}`);
  keys.add("offer.error.unknown");
  assert.ok(keys.size > 30);
  const en = pack.catalog("en");
  const nb = pack.catalog("nb");
  for (const key of keys) {
    if (key.endsWith(".") || key === "offer.error." ) continue;
    assert.equal(typeof en[key], "string", `en ${key}`);
    assert.equal(typeof nb[key], "string", `nb ${key}`);
    assert.deepEqual((en[key].match(/\{\w+\}/g) ?? []).sort(), (nb[key].match(/\{\w+\}/g) ?? []).sort(), `placeholders of ${key}`);
  }
  assert.equal(nb["offer.title.save"], "Lagre i Ferret?");
  assert.equal(nb["offer.master"], "Ferret ber aldri om hovedpassordet ditt inne i en nettside.");
});

test("the_click_guard_counts_from_when_the_buttons_appear_also_after_a_classification_that_took_long", async () => {
  const { mod, clock, now, texts } = await setup();
  const a = { id: "b2".repeat(16), rev: 1, name: "Shop A", username: "anna", how: "host" };
  const fake = fakeFlow({ classify: classification() });
  // The classification takes 500 ms: the card was made then, but its buttons appear only now.
  fake.flow.classify = async () => {
    clock.t += 500;
    return classification();
  };
  const card = mod.createOfferCard({ texts, flow: fake.flow, offer: offerOf(), now });
  await card.loaded;
  const writes = () => fake.calls.filter((c) => ["save", "updatePassword", "dismiss", "never"].includes(c.call));
  clock.t += 399;
  await click(one(card.root, "offer-save"));
  assert.deepEqual(writes(), [], "399 ms after the buttons appeared nothing counts");
  clock.t += 1;
  await click(one(card.root, "offer-save"));
  assert.equal(writes().length, 1, "at 400 ms it counts");

  // A rebuild after a changed item puts new buttons under the cursor: the guard starts again.
  const second = fakeFlow({ classify: classification({ action: "choose", targets: [a, { ...a, id: "b3".repeat(16), name: "Shop B" }] }) });
  const card2 = mod.createOfferCard({ texts, flow: second.flow, offer: offerOf({ kind: "change" }), now });
  await card2.loaded;
  clock.t += 500;
  let attempts = 0;
  second.flow.updatePassword = async () => {
    attempts += 1;
    return { ok: false, reason: "item_changed", classification: classification({ action: "update", targets: [a] }) };
  };
  await click(byRole(card2.root, "offer-choice-update")[0]);
  assert.equal(card2.root.getAttribute("data-kind"), "update");
  const count = () => attempts;
  assert.equal(count(), 1);
  clock.t += 399;
  await click(one(card2.root, "offer-update"));
  assert.equal(count(), 1, "the rebuilt card ignores a click for 400 ms");
  clock.t += 1;
  await click(one(card2.root, "offer-update"));
  assert.equal(count(), 2);
});

test("a_card_for_a_password_ferret_generated_has_no_never_button", async () => {
  const { mod, now, texts } = await setup();
  const made = mod.createOfferCard({ texts, flow: fakeFlow().flow, offer: offerOf({ generated: true }), now });
  await made.loaded;
  assert.equal(one(made.root, "offer-never"), null);
  assert.ok(one(made.root, "offer-generated")?.textContent.includes("generator"));
  assert.notEqual(one(made.root, "offer-not-now"), null);
  const typed = mod.createOfferCard({ texts, flow: fakeFlow().flow, offer: offerOf(), now });
  await typed.loaded;
  assert.notEqual(one(typed.root, "offer-never"), null);
});

test("a_reveal_that_answers_after_a_rebuild_is_dropped_and_a_hidden_section_empties_the_field", async () => {
  const { mod, clock, now, texts } = await setup();
  const a = { id: "b2".repeat(16), rev: 1, name: "Shop A", username: "anna", how: "host" };
  const fake = fakeFlow({ classify: classification({ action: "update", targets: [a] }) });
  /** @type {(v: any) => void} */
  let answer = () => {};
  fake.flow.reveal = () => new Promise((resolve) => { answer = resolve; });
  const card = mod.createOfferCard({ texts, flow: fake.flow, offer: offerOf(), now });
  await card.loaded;
  clock.t += 500;
  const oldInput = one(card.root, "offer-password");
  await click(one(card.root, "offer-password-toggle"));
  // While the answer is on its way, a refused write rebuilds the card.
  fake.flow.updatePassword = async () => ({ ok: false, reason: "item_changed", classification: classification({ action: "update", targets: [{ ...a, rev: 2 }] }) });
  await click(one(card.root, "offer-update"));
  const newInput = one(card.root, "offer-password");
  assert.notEqual(newInput, oldInput);
  answer({ ok: true, value: SECRET });
  await settle();
  assert.equal(oldInput?.value, "", "the answer did not land in the old field");
  assert.equal(newInput?.value, "");

  // The section's hide (a lock, a rebuild, the popup closing) empties a shown password at once.
  const shownFlow = fakeFlow();
  shownFlow.flow.list = async () => ({ ok: true, offers: [offerOf()], notice: null });
  const section = mod.createOfferSection({ texts, flow: shownFlow.flow, tabId: 7, now });
  await section.loaded;
  clock.t += 500;
  const field = one(section.root, "offer-password");
  await click(one(section.root, "offer-password-toggle"));
  assert.equal(field?.value, SECRET);
  section.hide();
  assert.equal(field?.value, "");
  assert.equal(field?.getAttribute("type"), "password");
});

test("the_popup_empties_what_a_card_shows_before_it_builds_its_view_again_and_when_it_closes", async () => {
  const { readFileSync } = await import("node:fs");
  const { join } = await import("node:path");
  const source = readFileSync(join((await pkg()).dir, "pages", "popup.mjs"), "utf8");
  // `show` empties first (a lock rebuilds the view through it), the offers section hides on the way, and a closing page does too.
  assert.match(source, /function show\(view, note = null\) \{[\s\S]{0,400}teardown\?\.\(\);\s*teardown = null;/);
  assert.match(source, /teardown = \(\) => offers\?\.hide\(\);/);
  assert.match(source, /addEventListener\("pagehide", \(\) => teardown\?\.\(\)\)/);
});
