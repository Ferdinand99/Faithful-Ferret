// The context menu (src/background/menus.mjs) and the aim of the fill engine at
// the clicked field (src/content/fill.mjs `aim`, src/background/inject.mjs
// `aimFill`): one fixed item that names nothing, a click fills only in its own
// frame and only the clicked field's group, and a password goes only into a
// password input.
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { test } from "node:test";
import { createQuickFill } from "../../src/background/commands.mjs";
import { aimFill } from "../../src/background/inject.mjs";
import { FALLBACK_TITLE, MENU_ID, TITLE_KEY, listenForMenus, menuTitle, titleLanguage } from "../../src/background/menus.mjs";
import { AIM_MS } from "../../src/content/fill.mjs";
import { extensionRoot } from "./buildHelpers.mjs";
import { addInput, addLoginForm } from "./fakeDom.mjs";
import { ITEM, createWorld, valueOf } from "./quickFillWorld.mjs";

const PAGE = "https://example.com/login";

/** A fake `menus` that records every call. */
function fakeMenus() {
  /** @type {Array<[string, any]>} */
  const calls = [];
  /** @type {Array<(info: any, tab?: any) => void>} */
  const listeners = [];
  return {
    calls,
    listeners,
    create: (/** @type {any} */ properties) => { calls.push(["create", properties]); },
    remove: async (/** @type {string} */ id) => { calls.push(["remove", id]); },
    update: (/** @type {any} */ ...args) => { calls.push(["update", args]); },
    removeAll: async () => { calls.push(["removeAll", null]); },
    onClicked: { addListener: (/** @type {any} */ fn) => listeners.push(fn) },
  };
}

/**
 * The menu on a world: returns a way to click the item on an element of the page.
 * @param {ReturnType<typeof createWorld>} world
 */
async function menuOn(world) {
  const menus = fakeMenus();
  const quickFill = createQuickFill({
    coreHost: world.coreHost,
    lock: world.lock,
    sessions: world.sessions,
    openPopup: world.openPopup,
    scripting: world.scripting,
    webNavigation: world.webNavigation,
  });
  /** @type {Promise<unknown>[]} */
  const runs = [];
  const spy = {
    open: () => quickFill.open(),
    fillOrOpen: (/** @type {unknown} */ tabId, /** @type {any} */ click) => {
      const run = quickFill.fillOrOpen(tabId, click);
      runs.push(run);
      return run;
    },
  };
  await listenForMenus({ menus, quickFill: spy, title: "Fill with Ferret" });
  let nextId = 100;
  return {
    menus,
    /**
     * Clicks the item on `element` (in frame `frameId`, whose address the menu saw as `frameUrl`).
     * @param {any} element @param {{ frameId?: number, frameUrl?: string, menuItemId?: string, tabId?: number }} [where]
     */
    async click(element, { frameId = 0, frameUrl = PAGE, menuItemId = MENU_ID, tabId = 7 } = {}) {
      nextId += 1;
      world.targets.set(nextId, element);
      runs.length = 0;
      const info = { menuItemId, frameId, targetElementId: nextId, editable: true, pageUrl: frameId === 0 ? frameUrl : PAGE, ...(frameId === 0 ? {} : { frameUrl }) };
      for (const listener of menus.listeners) listener(info, { id: tabId });
      const outcomes = await Promise.all(runs);
      return outcomes[0];
    },
  };
}

/** Two sign-in forms, one under the other, and a search box with no form. */
function twoForms(/** @type {any} */ document) {
  const first = addLoginForm(document);
  const form = document.body.append(document.createElement("form", { id: "second" }));
  const user2 = addInput(document, form, { type: "email", name: "email", id: "user2" }, { top: 260 });
  const pass2 = addInput(document, form, { type: "password", name: "pw", id: "pass2" }, { top: 320 });
  user2.form = pass2.form = form;
  const search = addInput(document, document.body, { type: "search", name: "q", id: "q" }, { top: 400 });
  const note = addInput(document, document.body, { type: "text", name: "comment", id: "comment" }, { top: 460 });
  return { user: first.user, pass: first.pass, user2, pass2, search, note };
}

test("the_menu_has_one_static_item_and_lists_no_item_names", async () => {
  const world = createWorld({ build: twoForms, offer: [{ frameId: 0 }] });
  const menu = await menuOn(world);
  // One item, made once, on editable fields, with a fixed title.
  assert.deepEqual(menu.menus.calls, [["remove", MENU_ID], ["create", { id: MENU_ID, title: "Fill with Ferret", contexts: ["editable"] }]]);
  assert.equal(menu.menus.listeners.length, 1);

  // Clicks with one match, several, none, while locked: the menu never changes, whatever the vault holds.
  await menu.click(world.pass);
  world.offer = [{ frameId: 0, items: 3 }];
  await menu.click(world.pass);
  world.offer = [];
  await menu.click(world.pass);
  world.state = "locked";
  await menu.click(world.pass);
  assert.equal(menu.menus.calls.length, 2, "no create, update or remove after the start");

  // The item's title is a catalog text, never an item: English and Norwegian, and the English text as the fallback.
  const en = JSON.parse(readFileSync(join(extensionRoot, "src", "locales", "en", "menus.json"), "utf8"));
  const nb = JSON.parse(readFileSync(join(extensionRoot, "src", "locales", "nb", "menus.json"), "utf8"));
  assert.deepEqual(Object.keys(en), [TITLE_KEY]);
  assert.deepEqual(Object.keys(nb), [TITLE_KEY]);
  assert.equal(en[TITLE_KEY], FALLBACK_TITLE);
  assert.equal(nb[TITLE_KEY], "Fyll inn med Ferret");
  const catalogs = /** @type {Record<string, any>} */ ({ "locales.en.json": en, "locales.nb.json": nb });
  const fetch = async (/** @type {string} */ url) => {
    const body = catalogs[url];
    return { ok: body !== undefined, json: async () => body };
  };
  const getURL = (/** @type {string} */ path) => path;
  assert.equal(await menuTitle({ fetch, getURL, languages: ["nb-NO", "en"] }), "Fyll inn med Ferret");
  assert.equal(await menuTitle({ fetch, getURL, languages: ["nn"] }), "Fyll inn med Ferret");
  assert.equal(await menuTitle({ fetch, getURL, languages: ["de-DE", "en-GB"] }), "Fill with Ferret");
  assert.equal(await menuTitle({ fetch: async () => { throw new Error("gone"); }, getURL, languages: ["nb"] }), FALLBACK_TITLE);
  assert.equal(await menuTitle({ fetch: async () => ({ ok: true, json: async () => ({ [TITLE_KEY]: "" }) }), getURL, languages: ["nb"] }), FALLBACK_TITLE);
  assert.equal(titleLanguage([]), "en");

  // The module never makes or changes an item from what a click brings or what the vault holds.
  const code = readFileSync(join(extensionRoot, "src", "background", "menus.mjs"), "utf8").replace(/^\s*(?:\/\/|\*|\/\*\*).*$/gm, "");
  assert.equal([...code.matchAll(/menus\.create\(/g)].length, 1);
  assert.doesNotMatch(code, /menus\.update|\.name\b|\.username\b|visible/);
});

test("the_menu_click_fills_the_clicked_field_when_exactly_one_candidate_matches", async () => {
  // The click on the second form's password: that form is filled, the first one stays empty.
  let world = createWorld({ build: twoForms, offer: [{ frameId: 0 }] });
  let menu = await menuOn(world);
  assert.equal(await menu.click(world.pass2), "filled");
  assert.equal(valueOf(world.user2), ITEM.username);
  assert.equal(valueOf(world.pass2), ITEM.password);
  assert.equal(valueOf(world.user), "");
  assert.equal(valueOf(world.pass), "");
  assert.equal(world.popups.count, 0);
  // The script was aimed at the clicked field in the clicked frame's document before the fill began.
  const aims = world.injections.filter((i) => "func" in i && /\.aim\(/.test(String(i.func)));
  assert.equal(aims.length, 1);
  assert.deepEqual(aims[0].target, { tabId: 7, documentIds: ["doc-0"] });
  assert.deepEqual(world.ops(), ["fill_offer", "fill"]);

  // The click on the first form's user name: the user name goes into it and the password into its form's password.
  world = createWorld({ build: twoForms, offer: [{ frameId: 0 }] });
  menu = await menuOn(world);
  assert.equal(await menu.click(world.user), "filled");
  assert.equal(valueOf(world.user), ITEM.username);
  assert.equal(valueOf(world.pass), ITEM.password);
  assert.equal(valueOf(world.pass2), "");

  // Several matches, or none: the popup, and nothing put into the page.
  for (const offer of [[{ frameId: 0, items: 2 }], []]) {
    world = createWorld({ build: twoForms, offer });
    menu = await menuOn(world);
    assert.equal(await menu.click(world.pass2), "popup");
    assert.equal(world.injections.length, 0);
    assert.equal(valueOf(world.pass2), "");
  }

  // Locked: the popup at once, in the turn of the click.
  world = createWorld({ build: twoForms, offer: [{ frameId: 0 }], state: "locked" });
  menu = await menuOn(world);
  assert.equal(await menu.click(world.pass2), "popup");
  assert.deepEqual(world.ops(), []);

  // A click on another menu item does nothing; a click without the element or the frame address opens the popup.
  world = createWorld({ build: twoForms, offer: [{ frameId: 0 }] });
  menu = await menuOn(world);
  assert.equal(await menu.click(world.pass2, { menuItemId: "something-else" }), undefined);
  assert.equal(world.popups.count, 0);
  for (const listener of menu.menus.listeners) listener({ menuItemId: MENU_ID, frameId: 0, pageUrl: PAGE }, { id: 7 });
  for (const listener of menu.menus.listeners) listener({ menuItemId: MENU_ID, frameId: 0, targetElementId: 5 }, { id: 7 });
  assert.equal(world.popups.count, 2);
  assert.deepEqual(world.ops(), []);
});

test("the_menu_applies_the_frame_rules_to_its_frame", async () => {
  // The only match is in the top frame; the click is in a cross-site frame, which the page matching does not offer.
  // Nothing is filled, not in that frame and not in the top one.
  let world = createWorld({
    build: twoForms,
    offer: [{ frameId: 0 }],
    frames: { 0: { url: PAGE, documentId: "doc-0" }, 3: { url: "https://evil.example.net/frame", documentId: "doc-3" } },
  });
  let menu = await menuOn(world);
  assert.equal(await menu.click(world.pass, { frameId: 3, frameUrl: "https://evil.example.net/frame" }), "popup");
  assert.deepEqual(world.ops(), ["fill_offer"]);
  assert.equal(world.injections.length, 0);
  assert.equal(valueOf(world.pass), "");

  // A match in the clicked same-site frame fills there, and only there.
  world = createWorld({
    build: twoForms,
    offer: [{ frameId: 0 }, { frameId: 5 }],
    frames: { 5: { url: "https://login.example.com/frame", documentId: "doc-5" } },
  });
  menu = await menuOn(world);
  assert.equal(await menu.click(world.pass, { frameId: 5, frameUrl: "https://login.example.com/frame" }), "filled");
  const fill = world.log.find((l) => l.op === "fill");
  assert.equal(fill?.args.frame_id, 5);
  for (const injection of world.injections) assert.deepEqual(injection.target.documentIds ?? injection.target.frameIds, injection.target.documentIds ? ["doc-5"] : [5]);

  // A reference tied to several frames (top first): the menu fills in the clicked one of them only, the shortcut in
  // the first; a click in a frame the reference is not tied to fills nothing.
  const tied = { offer: [{ frameId: 0, frameIds: [0, 5] }], frames: { 0: { url: PAGE, documentId: "doc-0" }, 5: { url: "https://login.example.com/frame", documentId: "doc-5" }, 8: { url: "https://example.com/other", documentId: "doc-8" } } };
  world = createWorld({ build: twoForms, ...tied });
  menu = await menuOn(world);
  assert.equal(await menu.click(world.pass, { frameId: 5, frameUrl: "https://login.example.com/frame" }), "filled");
  assert.equal(world.log.find((l) => l.op === "fill")?.args.frame_id, 5);
  world = createWorld({ build: twoForms, ...tied });
  menu = await menuOn(world);
  assert.equal(await menu.click(world.pass, { frameId: 8, frameUrl: "https://example.com/other" }), "popup");
  assert.deepEqual(world.ops(), ["fill_offer"]);
  world = createWorld({ build: twoForms, ...tied });
  const shortcut = createQuickFill({ coreHost: world.coreHost, lock: world.lock, openPopup: world.openPopup, scripting: world.scripting, webNavigation: world.webNavigation });
  assert.equal(await shortcut.fillOrOpen(7), "filled");
  assert.equal(world.log.find((l) => l.op === "fill")?.args.frame_id, 0);

  // `info.frameId` and `info.frameUrl` disagree with the frame the browser resolves (the id names a document at
  // another address now): no fill.
  world = createWorld({ build: twoForms, offer: [{ frameId: 5 }], frames: { 5: { url: "https://login.example.com/next", documentId: "doc-6" } } });
  menu = await menuOn(world);
  assert.equal(await menu.click(world.pass, { frameId: 5, frameUrl: "https://login.example.com/frame" }), "popup");
  assert.equal(world.injections.length, 0);

  // The frame moved on after the click (it shows another address now): no fill.
  world = createWorld({ build: twoForms, offer: [{ frameId: 0 }], frames: { 0: { url: "https://example.com/elsewhere", documentId: "doc-9" } } });
  menu = await menuOn(world);
  assert.equal(await menu.click(world.pass), "popup");
  assert.equal(world.injections.length, 0);
  assert.deepEqual(world.ops(), ["fill_offer"]);

  // The frame is gone: no fill.
  world = createWorld({ build: twoForms, offer: [{ frameId: 6 }], frames: { 6: null } });
  menu = await menuOn(world);
  assert.equal(await menu.click(world.pass, { frameId: 6, frameUrl: "https://example.com/a" }), "popup");
  assert.equal(world.injections.length, 0);

  // An http match in the clicked frame: the popup (warning and one more click), no fill.
  world = createWorld({ build: twoForms, offer: [{ frameId: 0, insecure: true }] });
  menu = await menuOn(world);
  assert.equal(await menu.click(world.pass), "popup");
  assert.equal(world.injections.length, 0);
});

test("a_password_is_never_filled_into_a_non_password_field_from_the_menu", async () => {
  // A search box and a plain text box with no form, on a page with sign-in forms: the clicked box gets the user
  // name at most, and no password anywhere, even from a background that sends every value it has.
  for (const field of ["search", "note"]) {
    const world = createWorld({ build: twoForms, offer: [{ frameId: 0 }] });
    world.pushEveryKind = true;
    const menu = await menuOn(world);
    await menu.click(/** @type {any} */ (world)[field]);
    const box = /** @type {any} */ (world)[field];
    assert.notEqual(valueOf(box), ITEM.password, field);
    for (const input of [world.user, world.pass, world.user2, world.pass2]) assert.equal(valueOf(input), "", `${field}: no other field`);
    assert.deepEqual(world.fills.find((f) => f.field === "password"), { field: "password", ok: false }, `${field}: the engine refused the password`);
  }

  // The clicked field is a password field: the password goes into it, and the user name never does.
  let world = createWorld({ build: twoForms, offer: [{ frameId: 0 }] });
  let menu = await menuOn(world);
  await menu.click(world.pass2);
  assert.equal(valueOf(world.pass2), ITEM.password);
  assert.notEqual(valueOf(world.pass2), ITEM.username);

  // Fields the engine never fills: one that sets a new password, a hidden one, a checkbox. The report is empty, so
  // nothing at all is filled (an aimed request never falls back to the page's first form).
  for (const attributes of [{ type: "password", autocomplete: "new-password" }, { type: "text", "aria-hidden": "true" }, { type: "checkbox" }]) {
    world = createWorld({
      build: (document) => ({ ...addLoginForm(document), odd: addInput(document, document.body, attributes, { top: 300 }) }),
      offer: [{ frameId: 0 }],
    });
    world.pushEveryKind = true;
    menu = await menuOn(world);
    assert.equal(await menu.click(world.odd), "not_filled", JSON.stringify(attributes));
    assert.equal(valueOf(world.odd), "");
    assert.equal(valueOf(world.user), "");
    assert.equal(valueOf(world.pass), "");
  }
});

test("an_aim_is_for_the_next_request_of_its_document_only", async () => {
  const world = createWorld({ build: twoForms });
  // The engine is driven through the world's scripting, as the background reaches it.
  const run = async (/** @type {any} */ func, /** @type {any[]} */ args) => (await world.scripting.executeScript({ target: { tabId: 7, frameIds: [0] }, func, args }))[0].result;
  const begin = (/** @type {string} */ id) => run((/** @type {string} */ r) => /** @type {any} */ (globalThis).__ferretFill.begin(r), [id]);
  const aim = (/** @type {unknown} */ id) => run((/** @type {unknown} */ t) => /** @type {any} */ (globalThis).__ferretFill.aim(t), [id]);
  world.targets.set(1, world.pass2);

  // A bad id, an unknown id and an element of another document aim at nothing.
  assert.equal(await aim("1"), false);
  assert.equal(await aim(1.5), false);
  assert.equal(await aim(99), false);
  const other = createWorld({ build: twoForms });
  world.targets.set(2, other.pass2);
  assert.equal(await aim(2), false);

  // An aim holds for one request: the next begin fills the clicked group, the one after it the page's first form.
  assert.equal(await aim(1), true);
  assert.equal(await begin("req-a"), true);
  world.offer = [{ frameId: 0 }];
  const quick = createQuickFill({ coreHost: world.coreHost, lock: world.lock, openPopup: world.openPopup, scripting: world.scripting, webNavigation: world.webNavigation });
  assert.equal(await quick.fillOrOpen(7), "filled");
  assert.equal(valueOf(world.pass), ITEM.password, "not aimed: the page's first form");
  assert.equal(valueOf(world.pass2), "");

  // An aim that waited longer than AIM_MS is gone.
  const late = createWorld({ build: twoForms, offer: [{ frameId: 0 }] });
  late.targets.set(1, late.pass2);
  await late.scripting.executeScript({ target: { tabId: 7, frameIds: [0] }, func: (/** @type {number} */ t) => /** @type {any} */ (globalThis).__ferretFill.aim(t), args: [1] });
  late.advance(AIM_MS + 1);
  const lateQuick = createQuickFill({ coreHost: late.coreHost, lock: late.lock, openPopup: late.openPopup, scripting: late.scripting, webNavigation: late.webNavigation });
  assert.equal(await lateQuick.fillOrOpen(7), "filled");
  assert.equal(valueOf(late.pass), ITEM.password);
  assert.equal(valueOf(late.pass2), "");
});

test("aim_fill_injects_the_entry_and_hands_the_engine_the_element_id", async () => {
  /** @type {any[]} */
  const calls = [];
  let answer = true;
  const scripting = {
    executeScript: async (/** @type {any} */ injection) => {
      calls.push(injection);
      return "func" in injection ? [{ result: answer }] : [{ result: null }];
    },
  };
  await aimFill({ scripting, tabId: 7, frameId: 3, targetElementId: 42 });
  assert.deepEqual(calls[0], { target: { tabId: 7, frameIds: [3] }, files: ["/content/fill.inject.js"] });
  assert.deepEqual(calls[1].args, [42]);
  const text = String(calls[1].func);
  const run = new Function("globalThis", `return (${text})(42);`);
  /** @type {unknown[]} */
  const seen = [];
  assert.equal(run({ __ferretFill: { aim: (/** @type {unknown} */ id) => { seen.push(id); return true; } } }), true);
  assert.deepEqual(seen, [42]);
  assert.equal(run({ __ferretFill: { begin: () => true } }), false, "an engine without aim");
  assert.equal(run({}), false);

  calls.length = 0;
  await aimFill({ scripting, tabId: 7, frameId: 3, documentId: "doc-3", targetElementId: 42 });
  for (const call of calls) assert.deepEqual(call.target, { tabId: 7, documentIds: ["doc-3"] });

  answer = false;
  await assert.rejects(aimFill({ scripting, tabId: 7, frameId: 3, targetElementId: 42 }), /found no clicked field/);
  calls.length = 0;
  for (const bad of [{ tabId: -1, frameId: 0, targetElementId: 1 }, { tabId: 1, frameId: 0.5, targetElementId: 1 }, { tabId: 1, frameId: 0, targetElementId: "1" }, { tabId: 1, frameId: 0, targetElementId: 1.5 }]) {
    await assert.rejects(aimFill({ scripting, .../** @type {any} */ (bad) }), TypeError);
  }
  assert.equal(calls.length, 0, "a bad request injects nothing");
});
