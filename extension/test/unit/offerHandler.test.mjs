// The offer in Ferret's popup, from the background's side (offer.handler.mjs, the capture host's offer operations and the
// sync's write operations): who may ask, which session may answer which offer, and that nothing is written without the
// click of the popup. The router, lock, core host, handlers, store of offers and sync host are the built package's own,
// over a fake core and engine (offerUiWorld.mjs).
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { test } from "node:test";
import { CONTENT_TYPES, UI_TYPES, encode } from "../../src/shared/protocol.mjs";
import { contentScriptSender, extensionPageSender } from "./fakeBrowser.mjs";
import { idOf, item, NEW, OLD } from "./offerWriteWorld.mjs";
import { ORIGIN, PAGE, TAB, TYPED, USER, uiWorld } from "./offerUiWorld.mjs";
import { pkg } from "./sessionHelpers.mjs";

/** The offer types and the body each one needs (for an offer id and an item). @param {string} id */
const bodies = (id) => ({
  offer_list: { tab_id: TAB },
  offer_classify: { offer_id: id },
  folder_names: {},
  offer_save: { offer_id: id, name: "Shop", username: USER },
  offer_update: { offer_id: id, id: idOf(1), rev: 1 },
  offer_dismiss: { offer_id: id },
  offer_never: { offer_id: id },
  offer_reveal: { offer_id: id },
});

test("save_needs_a_click_in_the_popup_and_an_offer_id_from_this_popup_session", async () => {
  const w = await uiWorld([]);
  await w.offerReady();
  // The offer is held, and nothing was written: a capture, a badge and a list are not a click.
  assert.equal(w.offers.size(), 1);
  assert.deepEqual(w.writes, []);

  const popup = w.connectPopup();
  const listed = await popup.ask("offer_list", { tab_id: TAB });
  assert.equal(listed.ok, true);
  assert.equal(listed.offers.length, 1);
  const [offer] = listed.offers;
  assert.match(offer.offer_id, /^[0-9a-f]{32}$/);
  assert.deepEqual(
    { ...offer, offer_id: undefined },
    { offer_id: undefined, kind: "signup", host: { a_label: "login.example.net", unicode: "login.example.net" }, username: USER, generated: false, incognito: false },
  );
  assert.equal(JSON.stringify(listed).includes(TYPED), false, "the list holds no password");
  const classified = await popup.ask("offer_classify", { offer_id: offer.offer_id });
  assert.equal(classified.action, "save");
  assert.equal(JSON.stringify(classified).includes(TYPED), false, "the classification holds no password");
  assert.deepEqual(w.writes, [], "listing and classifying write nothing");

  // Another popup page (another session), a made-up id and the id of nothing: refused, and nothing is written or lost.
  const other = w.connectPopup();
  const guesses = ["ab".repeat(16), offer.offer_id.replace(/.$/, "0"), "00".repeat(16)].filter((id) => id !== offer.offer_id);
  for (const id of [offer.offer_id, ...guesses]) {
    for (const [type, body] of /** @type {Array<[string, any]>} */ ([
      ["offer_save", { offer_id: id, name: "Shop", username: USER }],
      ["offer_update", { offer_id: id, id: idOf(1), rev: 1 }],
      ["offer_classify", { offer_id: id }],
      ["offer_dismiss", { offer_id: id }],
      ["offer_never", { offer_id: id }],
      ["offer_reveal", { offer_id: id }],
    ])) {
      const answer = await other.ask(type, body);
      assert.equal(answer.ok, false, `${type} ${id === offer.offer_id ? "of another session" : "of an unknown offer"}`);
      assert.equal(answer.reason, "not_offered", type);
    }
  }
  assert.deepEqual(w.writes, [], "no write without this popup's click");
  assert.equal(w.offers.size(), 1, "a refused answer does not drop the offer");

  // A message cannot name the session: a key the schema does not list ends the connection.
  const sly = w.connectPopup();
  await sly.port.send(JSON.stringify({ v: 1, id: "s1", type: "offer_save", body: { offer_id: offer.offer_id, name: "Shop", session: "x" } }));
  assert.equal(sly.port.disconnected, true);
  assert.throws(() => encode("offer_save", { offer_id: offer.offer_id, name: "Shop", session: "x" }), "the popup cannot even build such a message");
  assert.deepEqual(w.writes, []);
  const handlerSource = readFileSync(join(w.dir ?? (await pkg()).dir, "background", "handlers", "offer.handler.mjs"), "utf8");
  assert.equal(/body\??\.session/.test(handlerSource), false, "the handler never reads a session from a message");
  assert.match(handlerSource, /ctx\.session/);

  // The click of this popup: the item is written once, with the typed password, and the offer is gone.
  const saved = await popup.ask("offer_save", { offer_id: offer.offer_id, name: "Shop", username: USER });
  assert.deepEqual(saved, { ok: true, pending: true });
  assert.equal(w.writes.length, 1);
  assert.equal(w.writes[0].op, "create");
  assert.equal(w.writes[0].draft.fields.find((/** @type {any} */ f) => f.id === "password").value, TYPED);
  assert.deepEqual(w.writes[0].draft.urls, [{ url: ORIGIN, matching: "host" }]);
  assert.equal(w.offers.size(), 0, "an offer is used once");
  assert.deepEqual(await popup.ask("offer_save", { offer_id: offer.offer_id, name: "Shop", username: USER }), { ok: false, reason: "not_offered" });
  assert.equal(w.writes.length, 1);
  assert.equal(w.badgeText.get(TAB), "", "the badge went with the offer");
});

test("a_content_script_cannot_send_offer_save_or_offer_update_while_the_popup_can", async () => {
  const w = await uiWorld([item(1, { name: "Shop", username: USER, password: OLD, urls: [[`${ORIGIN}/`, "host"]] })]);
  await w.offerReady();
  const popup = w.connectPopup();
  const [offer] = (await popup.ask("offer_list", { tab_id: TAB })).offers;
  const id = offer.offer_id;
  const calls = Object.entries(bodies(id));

  // A content script has no way in: the content table does not hold the types, so its message is not even answered.
  const script = contentScriptSender(w.fake, PAGE, { tab: { id: TAB }, frameId: 0, documentId: `doc-${TAB}-0` });
  for (const [type, body] of calls) {
    assert.equal(await w.router.onMessage(JSON.stringify({ v: 1, id: "a", type, body }), script), undefined, `${type} from a content script`);
    assert.equal(Object.hasOwn(CONTENT_TYPES, type), false, `${type} is not a content type`);
  }
  // It cannot open the popup's port either, and neither can a page of the extension that a web page frames.
  const framed = extensionPageSender(w.fake, "pages/popup.html", { frameId: 4, tab: { id: 9 } });
  const foreign = { ...extensionPageSender(w.fake, "pages/popup.html"), id: "other-extension@example.net" };
  const webPage = { ...script, id: undefined };
  for (const [name, sender] of /** @type {Array<[string, any]>} */ ([["a content script", script], ["a framed extension page", framed], ["another extension", foreign], ["a web page", webPage]])) {
    const port = w.connectPopup(sender);
    assert.equal(port.port.disconnected, true, `${name}: the port is refused`);
    assert.equal(port.port.listenerCount(), 0, `${name}: nothing listens`);
    assert.deepEqual(await port.ask("offer_save", { offer_id: id, name: "x" }), { disconnected: true });
  }
  assert.deepEqual(w.writes, [], "nothing was written by any of them");
  assert.equal(w.offers.size(), 1);

  // The handler checks the sender again, first, whatever the router did: with a context whose sender is not a top-level
  // page of this extension nothing is called.
  const { load } = await pkg();
  const handler = (await load("background/handlers/offer.handler.mjs")).default;
  /** @type {string[]} */
  const reached = [];
  const base = {
    channel: "ui",
    session: "ab".repeat(16),
    runtime: w.fake.runtime,
    state: () => "unlocked",
    call: async (/** @type {string} */ op) => void reached.push(op),
  };
  for (const [name, ctx] of /** @type {Array<[string, any]>} */ ([
    ["a content script", { ...base, sender: script }],
    ["a framed extension page", { ...base, sender: framed }],
    ["another extension", { ...base, sender: foreign }],
    ["no sender", { ...base, sender: undefined }],
    ["no runtime", { ...base, sender: extensionPageSender(w.fake, "pages/popup.html"), runtime: undefined }],
    ["the content channel", { ...base, channel: "content", sender: extensionPageSender(w.fake, "pages/popup.html") }],
    ["no session", { ...base, sender: extensionPageSender(w.fake, "pages/popup.html"), session: undefined }],
    ["a session that is not one of the router's", { ...base, sender: extensionPageSender(w.fake, "pages/popup.html"), session: "../x" }],
  ])) {
    for (const [type, body] of calls) {
      await assert.rejects(handler.handle(body, { ...ctx, type }), (/** @type {any} */ error) => error?.code === "not_available", `${name}: ${type}`);
    }
  }
  assert.deepEqual(reached, [], "no operation was called for any of them");

  // The popup can: its click on "Update" writes the new password into the item it was offered for.
  const classified = await popup.ask("offer_classify", { offer_id: id });
  assert.equal(classified.action, "update");
  const updated = await popup.ask("offer_update", { offer_id: id, id: classified.targets[0].id, rev: classified.targets[0].rev });
  assert.deepEqual(updated, { ok: true, pending: true });
  assert.equal(w.writes.length, 1);
  assert.equal(w.writes[0].op, "update");
  assert.equal(w.writes[0].draft.keep_password_history, true);
});

test("a_page_that_mimics_the_offer_gets_no_message_through", async () => {
  const w = await uiWorld();
  await w.offerReady();
  const sentBefore = w.badgeCalls.length;
  const popup = w.connectPopup();
  const [offer] = (await popup.ask("offer_list", { tab_id: TAB })).offers;
  // Everything a page can reach is a content script's message, or a window message that no listener of the extension
  // hears. The router answers neither a page's own message (it has no extension id) nor one of another extension.
  const message = (/** @type {string} */ type, /** @type {any} */ body) => JSON.stringify({ v: 1, id: "m1", type, body });
  const mimics = [
    contentScriptSender(w.fake, PAGE, { tab: { id: TAB }, frameId: 0 }),
    { ...contentScriptSender(w.fake, PAGE, { tab: { id: TAB }, frameId: 0 }), id: "other-extension@example.net" },
    { url: PAGE, origin: ORIGIN, frameId: 0, tab: { id: TAB } },
    { id: w.fake.runtime.id, url: w.fake.base + "pages/popup.html", origin: "null", frameId: 0 },
  ];
  for (const sender of mimics) {
    for (const [type, body] of Object.entries(bodies(offer.offer_id))) {
      assert.equal(await w.router.onMessage(message(type, body), sender), undefined, type);
    }
    // And the form types of the page's own script do not reach the popup's types.
    assert.equal(await w.router.onMessage(message("offer_save", { offer_id: offer.offer_id, name: "x", password: "p" }), sender), undefined);
  }
  assert.deepEqual(w.writes, []);
  assert.equal(w.offers.size(), 1, "the offer is still there");
  assert.equal(w.badgeCalls.length, sentBefore, "nothing changed on the button");
  // Every offer type is a UI type of the popup's table and nothing else.
  for (const type of Object.keys(bodies("x"))) {
    assert.equal(Object.hasOwn(UI_TYPES, type), true, type);
    assert.equal(Object.hasOwn(CONTENT_TYPES, type), false, type);
  }
  // A body that carries a password key is refused at the door: the popup never sends the password.
  assert.deepEqual(await popup.ask("offer_dismiss", { offer_id: offer.offer_id }), { ok: true });
  assert.throws(() => encode("offer_save", { offer_id: offer.offer_id, name: "x", password: "p" }));
});

test("not_now_drops_the_values_and_never_adds_the_host_to_the_list", async () => {
  const w = await uiWorld();
  await w.offerReady();
  const popup = w.connectPopup();
  const [first] = (await popup.ask("offer_list", { tab_id: TAB })).offers;
  assert.deepEqual(await popup.ask("offer_dismiss", { offer_id: first.offer_id }), { ok: true });
  assert.equal(w.offers.size(), 0, "the captured values are gone");
  assert.equal(w.offers.peek(first.offer_id, "00".repeat(16)), null);
  assert.deepEqual(await w.captureHost.never.list(), [], "\"Not now\" never adds the host to the list");
  assert.equal("capture_never" in w.local, false, "nothing was written to the disk");
  assert.deepEqual(w.writes, []);

  // "Never": this offer and every other offer of the host go, and the host joins the list on the disk. A later form of
  // that host gives no offer.
  await w.offerReady({ capture_id: "cap2" });
  await w.offerReady({ capture_id: "cap3", kind: "change", password: "Typed-another-password-7" });
  const listed = (await popup.ask("offer_list", { tab_id: TAB })).offers;
  assert.equal(listed.length, 2);
  assert.deepEqual(await popup.ask("offer_never", { offer_id: listed[0].offer_id }), { ok: true });
  assert.equal(w.offers.size(), 0, "all the offers of that host are gone");
  await w.flush();
  assert.deepEqual(w.local.capture_never, ["login.example.net"]);
  assert.deepEqual(await w.captureHost.never.list(), ["login.example.net"]);
  await w.offerReady({ capture_id: "cap4" });
  assert.equal(w.offers.size(), 0, "a form of a host on the list is not offered");
  assert.equal(w.badgeText.get(TAB), "");
  // The generated password of a site the user said never to is still offered: it was made on the user's own click.
  await w.offers.onGenerated({ tabId: TAB, frameId: 0, frameUrl: PAGE, kind: "signup", password: "Generated-by-Ferret-9x" });
  assert.equal(w.offers.size(), 1);

  // A private window: the choice is kept in memory only, never in storage.
  const priv = await uiWorld([], { incognito: true });
  await priv.offerReady();
  const page = priv.connectPopup();
  const [offer] = (await page.ask("offer_list", { tab_id: TAB })).offers;
  assert.equal(offer.incognito, true, "the card can say that the choice is kept until the browser closes");
  assert.deepEqual(await page.ask("offer_never", { offer_id: offer.offer_id }), { ok: true });
  await priv.flush();
  assert.equal("capture_never" in priv.local, false, "a private window's choice is not written to the disk");
  assert.equal(await priv.captureHost.never.has("login.example.net"), true);
  await priv.offerReady({ capture_id: "cap2" });
  assert.equal(priv.offers.size(), 0);
});

test("the_never_list_is_shown_and_editable_in_settings", async () => {
  const w = await uiWorld([], { stored: { capture_never: ["shop.example.net", "login.example.net"] } });
  // The settings page's own messages, also on a locked vault: the list, one host off it, then all of them.
  await w.coreHost.lock("manual");
  const page = w.connectPopup(extensionPageSender(w.fake, "pages/settings.html"));
  const shown = await page.ask("capture_settings", {});
  assert.deepEqual(shown.never, ["login.example.net", "shop.example.net"]);
  assert.equal(typeof shown.auto_open, "boolean");
  assert.deepEqual((await page.ask("capture_settings", { never_remove: "shop.example.net" })).never, ["login.example.net"]);
  await w.flush();
  assert.deepEqual(w.local.capture_never, ["login.example.net"]);
  assert.deepEqual((await page.ask("capture_settings", { never_clear: true })).never, []);
  // A host that was taken off the list gets offers again.
  await w.reopen();
  await w.offerReady();
  assert.equal(w.offers.size(), 1);
  // The page never sends a host to add: the request has no such key.
  const schema = UI_TYPES.capture_settings.request;
  assert.deepEqual(Object.keys(/** @type {any} */ (schema).shape).sort(), ["auto_open", "enable", "never_clear", "never_remove"]);
});

test("a_locked_vault_asks_for_the_password_in_the_popup_and_then_shows_the_offer", async () => {
  const w = await uiWorld();
  // The vault is locked when the form is submitted: the offer is taken and the button shows it.
  await w.coreHost.lock("manual");
  await w.offerReady();
  assert.equal(w.offers.size(), 1, "a capture is accepted while the vault is locked");
  assert.equal(w.badgeText.get(TAB), "1", "the badge shows that something waits");
  assert.equal(w.popup.attempts, 0, "the popup does not open by itself to ask for the master password");
  // The popup asks for the master password first: the offer's own answers need the vault.
  const popup = w.connectPopup();
  assert.deepEqual(await popup.ask("offer_list", { tab_id: TAB }), { refused: "vault_locked" });
  assert.deepEqual(await popup.ask("offer_classify", { offer_id: "ab".repeat(16) }), { refused: "vault_locked" });
  assert.deepEqual(await popup.ask("offer_save", { offer_id: "ab".repeat(16), name: "x" }), { refused: "vault_locked" });
  assert.deepEqual(await popup.ask("offer_reveal", { offer_id: "ab".repeat(16) }), { refused: "vault_locked" });
  assert.deepEqual(w.writes, []);
  assert.equal(w.offers.size(), 1, "the unlock has not happened and the offer is still held");

  // The vault is unlocked (the sign-in tab or the popup's own form does that): the same offer shows.
  await w.reopen();
  const again = w.connectPopup();
  const listed = await again.ask("offer_list", { tab_id: TAB });
  assert.equal(listed.offers.length, 1);
  assert.equal((await again.ask("offer_classify", { offer_id: listed.offers[0].offer_id })).action, "save");

  // But a lock after the form was submitted clears it (the vault locks, the offer is gone).
  await w.coreHost.lock("manual");
  assert.equal(w.offers.size(), 0);
  assert.equal(w.badgeText.get(TAB), "");
});

test("a_domain_only_item_is_updated_only_after_an_explicit_pick", async () => {
  const shared = item(1, { name: "Shared login", username: USER, password: OLD, urls: [["https://shop.example.net/", "domain"]] });
  const w = await uiWorld([shared]);
  await w.offerReady({ password: NEW });
  const popup = w.connectPopup();
  const [offer] = (await popup.ask("offer_list", { tab_id: TAB })).offers;
  const classified = await popup.ask("offer_classify", { offer_id: offer.offer_id });
  // A match by the main domain alone is never the target: the offer is a new login, and the other login is listed with its host.
  assert.equal(classified.action, "save");
  assert.deepEqual(classified.targets, []);
  assert.equal(classified.domain_only.length, 1);
  assert.equal(classified.domain_only[0].name, "Shared login");
  assert.deepEqual(classified.domain_only[0].host, { a_label: "shop.example.net", unicode: "shop.example.net" });
  const { id, rev } = classified.domain_only[0];
  // Without the pick the handler's update is refused and nothing changes.
  const refused = await popup.ask("offer_update", { offer_id: offer.offer_id, id, rev });
  assert.deepEqual({ ok: refused.ok, reason: refused.reason }, { ok: false, reason: "not_a_target" });
  assert.deepEqual(w.writes, []);
  assert.equal(w.offers.size(), 1, "the refused update left the offer for another answer");
  // With the user's pick from the list that names the host: the password of that item changes, and nothing else.
  const picked = await popup.ask("offer_update", { offer_id: offer.offer_id, id, rev, picked: true });
  assert.deepEqual(picked, { ok: true, pending: true });
  assert.equal(w.writes.length, 1);
  assert.equal(w.writes[0].id, id);
  assert.deepEqual(Object.keys(w.writes[0].draft).sort(), ["fields", "keep_password_history"]);
});

test("a_changed_item_is_classified_again_and_the_offer_stays_for_another_click", async () => {
  const w = await uiWorld([item(1, { name: "Shop", username: USER, password: OLD, urls: [[`${ORIGIN}/`, "host"]] })]);
  await w.offerReady({ password: NEW });
  const popup = w.connectPopup();
  const [offer] = (await popup.ask("offer_list", { tab_id: TAB })).offers;
  const classified = await popup.ask("offer_classify", { offer_id: offer.offer_id });
  assert.equal(classified.action, "update");
  // The item changed on another device after the card was shown.
  const stored = w.byId.get(idOf(1));
  stored.rev += 1;
  const stale = await popup.ask("offer_update", { offer_id: offer.offer_id, id: classified.targets[0].id, rev: classified.targets[0].rev });
  assert.equal(stale.ok, false);
  assert.equal(stale.reason, "item_changed");
  assert.equal(stale.classification.action, "update", "the card is told what the offer means now");
  assert.equal(stale.classification.targets[0].rev, stored.rev);
  assert.equal(w.offers.size(), 1, "the offer stays for another click");
  assert.deepEqual(w.writes, []);
});

test("the_popup_can_read_the_offered_password_only_on_its_own_click_and_never_in_a_list", async () => {
  const w = await uiWorld();
  await w.offerReady();
  const popup = w.connectPopup();
  const listed = await popup.ask("offer_list", { tab_id: TAB });
  const id = listed.offers[0].offer_id;
  const classified = await popup.ask("offer_classify", { offer_id: id });
  for (const reply of [listed, classified, await popup.ask("folder_names", {})]) assert.equal(JSON.stringify(reply).includes(TYPED), false);
  // "Show": the value, to the session that was told of the offer, and nothing else changes.
  assert.deepEqual(await popup.ask("offer_reveal", { offer_id: id }), { ok: true, value: TYPED });
  assert.equal(w.offers.size(), 1, "showing the password does not use the offer up");
  assert.deepEqual(w.writes, []);
  // Another session cannot.
  assert.deepEqual(await w.connectPopup().ask("offer_reveal", { offer_id: id }), { ok: false, reason: "not_offered" });
  // Once the offer is answered, there is nothing to show.
  await popup.ask("offer_dismiss", { offer_id: id });
  assert.deepEqual(await popup.ask("offer_reveal", { offer_id: id }), { ok: false, reason: "not_offered" });
  // The value is not in the badge or in anything the button was told.
  assert.equal(JSON.stringify(w.badgeCalls).includes(TYPED), false);
  assert.equal(JSON.stringify(w.local).includes(TYPED), false);
});
