// The context menu (src/background/menus.mjs) over the real page matching,
// frame rules and fill flow, and the aim of the fill engine at the clicked field
// (src/content/fill.mjs `aim`, src/background/inject.mjs `aimFill`): one fixed
// item that names nothing, a click fills only in its own frame and only the
// clicked field's group, and a password goes only into a password input.
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { test } from "node:test";
import { createQuickFill } from "../../src/background/commands.mjs";
import { aimFill } from "../../src/background/inject.mjs";
import { FALLBACK_TITLE, MENU_ID, TITLE_KEY, listenForMenus, menuTitle, titleLanguage } from "../../src/background/menus.mjs";
import { AIM_MS } from "../../src/content/fill.mjs";
import { extensionRoot } from "./buildHelpers.mjs";
import { encode } from "../../src/shared/protocol.mjs";
import { BACKGROUND_SENDER, addInput, addLoginForm } from "./fakeDom.mjs";
import { ITEM, PAGE, TAB, createWorld, valueOf } from "./quickFillWorld.mjs";

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

/** @param {Awaited<ReturnType<typeof createWorld>>} world */
const quickFillOf = (world) => createQuickFill({
  coreHost: world.coreHost,
  lock: world.lock,
  sessions: world.sessions,
  openPopup: world.openPopup,
  scripting: world.scripting,
  webNavigation: world.webNavigation,
});

/**
 * The menu on a world: returns a way to click the item on an element of a frame.
 * @param {Awaited<ReturnType<typeof createWorld>>} world
 */
async function menuOn(world) {
  const menus = fakeMenus();
  const quickFill = quickFillOf(world);
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
     * @param {any} element @param {{ frameId?: number, frameUrl?: string, menuItemId?: string }} [where]
     */
    async click(element, { frameId = 0, frameUrl = PAGE, menuItemId = MENU_ID } = {}) {
      nextId += 1;
      world.targets.set(nextId, element);
      runs.length = 0;
      const info = { menuItemId, frameId, targetElementId: nextId, editable: true, pageUrl: frameId === 0 ? frameUrl : PAGE, ...(frameId === 0 ? {} : { frameUrl }) };
      for (const listener of menus.listeners) listener(info, { id: TAB });
      const outcomes = await Promise.all(runs);
      return outcomes[0];
    },
  };
}

/** Two sign-in forms, one under the other, a search box and a free text box with no form. */
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

const TOP = { frameId: 0, url: PAGE, build: twoForms };
const LOGIN_FRAME = "https://login.example.com/frame";
const EVIL_FRAME = "https://evil.example.net/frame";

test("the_menu_has_one_static_item_and_lists_no_item_names", async () => {
  const world = await createWorld({ frames: [TOP], items: [{ name: "My bank", urls: ["https://example.com/"] }] });
  const menu = await menuOn(world);
  // One item, made once, on editable fields, with a fixed title.
  assert.deepEqual(menu.menus.calls, [["remove", MENU_ID], ["create", { id: MENU_ID, title: "Fill with Ferret", contexts: ["editable"] }]]);
  assert.equal(menu.menus.listeners.length, 1);

  // Clicks that fill, that find nothing and that come while locked: the menu never changes, whatever the vault holds.
  assert.equal(await menu.click(world.pass), "filled");
  await menu.click(world.pass, { frameId: 0, frameUrl: "https://example.com/other" });
  await world.coreHost.call("fill_offer", { session: "0".repeat(32), tab_id: TAB }).catch(() => {});
  assert.equal(menu.menus.calls.length, 2, "no create, update or remove after the start");
  assert.equal(JSON.stringify(menu.menus.calls).includes("My bank"), false);

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
  let world = await createWorld({ frames: [TOP] });
  let menu = await menuOn(world);
  assert.equal(await menu.click(world.pass2), "filled");
  assert.equal(valueOf(world.user2), ITEM.username);
  assert.equal(valueOf(world.pass2), ITEM.password);
  assert.equal(valueOf(world.user), "");
  assert.equal(valueOf(world.pass), "");
  assert.equal(world.popups.count, 0);
  // The page matching and the fill were both for the clicked frame only.
  assert.deepEqual(world.ops(), ["fill_offer", "fill"]);
  assert.equal(world.log[0].args.frame_id, 0);
  assert.equal(world.log[1].args.frame_id, 0);
  // The script was aimed at the clicked field in the clicked frame's document before the fill began there.
  const funcs = world.injections.filter((i) => "func" in i);
  assert.match(String(funcs[0].func), /\.aim\(/);
  assert.deepEqual(funcs[0].target, { tabId: TAB, documentIds: ["doc-0"] });
  assert.match(String(funcs[1].func), /\.begin\(/);
  assert.deepEqual(funcs[1].target, { tabId: TAB, documentIds: ["doc-0"] });
  assert.equal(world.refSessions(), 0);
  assert.equal(world.openHandles(), 0);

  // The click on the first form's user name: the user name goes into it and the password into its form's password.
  world = await createWorld({ frames: [TOP] });
  menu = await menuOn(world);
  assert.equal(await menu.click(world.user), "filled");
  assert.equal(valueOf(world.user), ITEM.username);
  assert.equal(valueOf(world.pass), ITEM.password);
  assert.equal(valueOf(world.pass2), "");

  // Several matches, or none: the popup, and nothing put into the page.
  for (const items of [[{ urls: ["https://example.com/"] }, { urls: ["https://example.com/x"] }], []]) {
    world = await createWorld({ frames: [TOP], items });
    menu = await menuOn(world);
    assert.equal(await menu.click(world.pass2), "popup");
    assert.equal(world.injections.length, 0);
    assert.equal(valueOf(world.pass2), "");
  }

  // Locked: the popup at once, in the turn of the click.
  world = await createWorld({ frames: [TOP], state: "locked" });
  menu = await menuOn(world);
  assert.equal(await menu.click(world.pass2), "popup");
  assert.deepEqual(world.ops(), []);

  // A click on another menu item does nothing; a click without the element or the frame address opens the popup.
  world = await createWorld({ frames: [TOP] });
  menu = await menuOn(world);
  assert.equal(await menu.click(world.pass2, { menuItemId: "something-else" }), undefined);
  assert.equal(world.popups.count, 0);
  for (const listener of menu.menus.listeners) listener({ menuItemId: MENU_ID, frameId: 0, pageUrl: PAGE }, { id: TAB });
  for (const listener of menu.menus.listeners) listener({ menuItemId: MENU_ID, frameId: 0, targetElementId: 5 }, { id: TAB });
  assert.equal(world.popups.count, 2);
  assert.deepEqual(world.ops(), []);
});

test("the_menu_applies_the_frame_rules_to_its_frame", async () => {
  // A cross-site frame whose origin matches an entry, below a top that matches too: a click in the frame fills
  // nothing, not in that frame and not in the top one.
  let world = await createWorld({
    frames: [TOP, { frameId: 3, url: EVIL_FRAME, build: addLoginForm }],
    items: [{ urls: ["https://example.com/", "https://evil.example.net/"] }],
  });
  let menu = await menuOn(world);
  assert.equal(await menu.click(world.frame(3).pass, { frameId: 3, frameUrl: EVIL_FRAME }), "popup");
  assert.deepEqual(world.ops(), ["fill_offer"]);
  assert.equal(world.log[0].args.frame_id, 3);
  assert.equal(world.injections.length, 0);
  assert.equal(valueOf(world.frame(3).pass), "");
  assert.equal(valueOf(world.pass), "");

  // A same-site frame with its own match: the click there fills there, and only there.
  world = await createWorld({
    frames: [TOP, { frameId: 5, url: LOGIN_FRAME, build: addLoginForm }],
    items: [{ urls: ["https://login.example.com/"] }],
  });
  menu = await menuOn(world);
  assert.equal(await menu.click(world.frame(5).pass, { frameId: 5, frameUrl: LOGIN_FRAME }), "filled");
  assert.equal(valueOf(world.frame(5).pass), ITEM.password);
  assert.equal(valueOf(world.pass), "");
  // Everything went to the frame's document, apart from the questions to the top whether the frame is shown there
  // (the fill script, then the question about frame 5).
  const asks = (/** @type {any} */ i) => typeof i.func === "function" && String(i.func).includes("frameShown");
  for (const injection of world.injections) {
    const toTop = injection.target.documentIds?.[0] === "doc-0";
    assert.deepEqual(injection.target, { tabId: TAB, documentIds: [toTop ? "doc-0" : "doc-5"] });
    if (toTop) assert.ok(asks(injection) ? injection.args[0] === 5 : injection.files !== undefined, "only the frame check goes to the top");
    else assert.equal(asks(injection), false);
  }
  assert.ok(world.injections.some(asks), "the top was asked");

  // One item tied to the top and a frame of the same origin: a click in the top fills the top only, even though
  // the frame has a form too.
  world = await createWorld({ frames: [TOP, { frameId: 5, url: "https://example.com/frame", build: addLoginForm }] });
  menu = await menuOn(world);
  assert.equal(await menu.click(world.pass), "filled");
  assert.equal(valueOf(world.pass), ITEM.password);
  assert.equal(valueOf(world.frame(5).pass), "");
  for (const injection of world.injections) assert.deepEqual(injection.target, { tabId: TAB, documentIds: ["doc-0"] });

  // An opaque frame (about:blank) gets nothing, also when the click names it.
  world = await createWorld({ frames: [TOP, { frameId: 6, url: "about:blank", build: addLoginForm }] });
  menu = await menuOn(world);
  assert.equal(await menu.click(world.frame(6).pass, { frameId: 6, frameUrl: "about:blank" }), "popup");
  assert.equal(world.injections.length, 0);

  // `info.frameId` and `info.frameUrl` disagree with the frame the browser resolves (the id names a document at
  // another address now, of the same origin, which still matches): nothing is filled.
  world = await createWorld({ frames: [TOP] });
  world.nav.set(0, { frameId: 0, parentFrameId: -1, url: "https://example.com/elsewhere", documentId: "doc-9" });
  menu = await menuOn(world);
  assert.equal(await menu.click(world.pass), "popup");
  assert.equal(world.injections.length, 0);
  assert.equal(valueOf(world.pass), "");

  // The frame the browser resolves names no document: the aim and the fill could not be tied to one, so nothing is
  // filled.
  world = await createWorld({ frames: [TOP] });
  world.nav.set(0, { frameId: 0, parentFrameId: -1, url: PAGE, documentId: /** @type {any} */ (undefined) });
  menu = await menuOn(world);
  assert.equal(await menu.click(world.pass), "popup");
  assert.equal(world.injections.length, 0);

  // The frame is gone: nothing is filled.
  world = await createWorld({ frames: [TOP, { frameId: 5, url: LOGIN_FRAME, build: addLoginForm }], items: [{ urls: ["https://login.example.com/"] }] });
  world.nav.delete(5);
  menu = await menuOn(world);
  assert.equal(await menu.click(world.frame(5).pass, { frameId: 5, frameUrl: LOGIN_FRAME }), "popup");
  assert.equal(world.injections.length, 0);

  // A plain http page: the popup (warning and one more click), no fill.
  world = await createWorld({ frames: [{ frameId: 0, url: "http://example.com/login", build: twoForms }], items: [{ urls: ["http://example.com/"] }] });
  menu = await menuOn(world);
  assert.equal(await menu.click(world.pass, { frameUrl: "http://example.com/login" }), "popup");
  assert.equal(world.injections.length, 0);
});

test("the_menu_fills_nothing_into_a_frame_that_its_parent_hides_or_covers", async () => {
  // A click on the password field of a same-site frame whose iframe the top makes invisible, or covers.
  for (const [label, trick] of /** @type {Array<[string, (iframe: any) => void]>} */ ([
    ["opacity 0 on the iframe", (iframe) => { iframe.style.opacity = "0"; }],
    ["a cover over the iframe", (iframe) => {
      const cover = iframe.ownerDocument.body.append(iframe.ownerDocument.createElement("div", { id: "cover" }));
      cover.rect = { ...iframe.rect };
      cover.z = 10;
    }],
  ])) {
    const world = await createWorld({
      frames: [TOP, { frameId: 5, url: LOGIN_FRAME, build: addLoginForm, holder: trick }],
      items: [{ urls: ["https://login.example.com/"] }],
    });
    const menu = await menuOn(world);
    assert.equal(await menu.click(world.frame(5).pass, { frameId: 5, frameUrl: LOGIN_FRAME }), "not_filled", label);
    assert.equal(valueOf(world.frame(5).pass), "", `${label}: no password`);
    assert.equal(valueOf(world.frame(5).user), "", `${label}: no user name`);
    // The aim that no value used is taken back.
    assert.deepEqual(world.injections.at(-1).target, { tabId: TAB, documentIds: ["doc-5"] }, `${label}: disarmed`);
  }
});

test("a_password_is_never_filled_into_a_non_password_field_from_the_menu", async () => {
  // A search box and a free text box with no form, on a page with sign-in forms: the clicked box gets the user
  // name at most, no password goes anywhere, and no other field is touched.
  for (const field of ["search", "note"]) {
    const world = await createWorld({ frames: [TOP] });
    const menu = await menuOn(world);
    await menu.click(/** @type {any} */ (world)[field]);
    const box = /** @type {any} */ (world)[field];
    assert.notEqual(valueOf(box), ITEM.password, field);
    for (const input of [world.user, world.pass, world.user2, world.pass2]) assert.equal(valueOf(input), "", `${field}: no other field`);
    assert.equal(world.fills.some((f) => f.field === "password"), false, `${field}: no password was sent`);
  }

  // The engine itself refuses a password for a field that is not a password input, whatever the background sends.
  const world = await createWorld({ frames: [TOP] });
  world.targets.set(1, world.note);
  const run = async (/** @type {any} */ func, /** @type {any[]} */ args) => (await world.scripting.executeScript({ target: { tabId: TAB, frameIds: [0] }, func, args }))[0].result;
  assert.equal(await run((/** @type {number} */ t) => /** @type {any} */ (globalThis).__ferretFill.aim(t), [1]), true);
  assert.equal(await run((/** @type {string} */ r) => /** @type {any} */ (globalThis).__ferretFill.begin(r), ["req-x"]), true);
  const engine = world.engineOf(0);
  for (const field of ["password", "username"]) {
    engine.onMessage(encode("fill_field", { request_id: "req-x", field, value: field === "password" ? ITEM.password : ITEM.username, expect: { origin: "https://example.com", frameUrl: PAGE } }), BACKGROUND_SENDER);
  }
  assert.equal(valueOf(world.note), ITEM.username, "the user name may go into the clicked text box");
  for (const input of [world.note, world.pass, world.pass2, world.search]) assert.notEqual(valueOf(input), ITEM.password);

  // The clicked field is a password field: the password goes into it, and the user name never does.
  let other = await createWorld({ frames: [TOP] });
  let menu = await menuOn(other);
  await menu.click(other.pass2);
  assert.equal(valueOf(other.pass2), ITEM.password);
  assert.equal(valueOf(other.user2), ITEM.username);

  // Inputs the engine never fills: one that sets a new password, a hidden one. The report is empty, so nothing at
  // all is filled (an aimed request never falls back to the page's first form).
  for (const attributes of [{ type: "password", autocomplete: "new-password" }, { type: "text", "aria-hidden": "true" }]) {
    other = await createWorld({
      frames: [{ frameId: 0, url: PAGE, build: (document) => ({ ...addLoginForm(document), odd: addInput(document, document.body, attributes, { top: 300 }) }) }],
    });
    menu = await menuOn(other);
    assert.equal(await menu.click(other.odd), "not_filled", JSON.stringify(attributes));
    assert.equal(valueOf(other.odd), "");
    assert.equal(valueOf(other.user), "");
    assert.equal(valueOf(other.pass), "");
  }
  // Editable elements that are no text or password input (a checkbox, a text area): the aim refuses them, so the
  // popup opens, and nothing is filled.
  for (const build of [
    (/** @type {any} */ document) => ({ ...addLoginForm(document), odd: addInput(document, document.body, { type: "checkbox" }, { top: 300 }) }),
    (/** @type {any} */ document) => {
      const area = document.body.append(document.createElement("textarea", { name: "comment" }));
      area.rect = { left: 100, top: 300, width: 240, height: 64 };
      return { ...addLoginForm(document), odd: area };
    },
  ]) {
    other = await createWorld({ frames: [{ frameId: 0, url: PAGE, build }] });
    menu = await menuOn(other);
    assert.equal(await menu.click(other.odd), "popup");
    assert.equal(other.popups.count, 1);
    assert.equal(valueOf(other.user), "");
    assert.equal(valueOf(other.pass), "");
    assert.equal(other.ops().includes("fill"), false, "no fill was asked for");
  }
});

test("an_aim_is_for_the_next_request_of_its_document_only", async () => {
  const world = await createWorld({ frames: [TOP] });
  // The engine is driven through the world's scripting, as the background reaches it.
  const run = async (/** @type {any} */ func, /** @type {any[]} */ args) => (await world.scripting.executeScript({ target: { tabId: TAB, frameIds: [0] }, func, args }))[0].result;
  const begin = (/** @type {string} */ id) => run((/** @type {string} */ r) => /** @type {any} */ (globalThis).__ferretFill.begin(r), [id]);
  const aim = (/** @type {unknown} */ id) => run((/** @type {unknown} */ t) => /** @type {any} */ (globalThis).__ferretFill.aim(t), [id]);
  world.targets.set(1, world.pass2);

  // A bad id, an unknown id and an element of another document aim at nothing.
  assert.equal(await aim("1"), false);
  assert.equal(await aim(1.5), false);
  assert.equal(await aim(99), false);
  const other = await createWorld({ frames: [TOP] });
  world.targets.set(2, other.pass2);
  assert.equal(await aim(2), false);

  // An aim holds for one request: the next begin uses it up, and the shortcut after it fills the page's first form.
  assert.equal(await aim(1), true);
  assert.equal(await begin("req-a"), true);
  assert.equal(await quickFillOf(world).fillOrOpen(TAB), "filled");
  assert.equal(valueOf(world.pass), ITEM.password, "not aimed: the page's first form");
  assert.equal(valueOf(world.pass2), "");

  // A menu fill that ended before its request began (here: the fill flow was busy) takes its aim back, so the
  // shortcut right after it fills the page's first form, not the clicked one.
  const busy = await createWorld({ frames: [TOP] });
  const plainCall = busy.coreHost.call;
  busy.coreHost.call = async (op, args) => (op === "fill" ? { ok: false, reason: "busy" } : plainCall(op, args));
  const busyMenu = await menuOn(busy);
  assert.equal(await busyMenu.click(busy.pass2), "not_filled");
  const disarm = busy.injections.at(-1);
  assert.deepEqual(disarm.target, { tabId: TAB, documentIds: ["doc-0"] });
  assert.match(String(disarm.func), /\.aim\(null\)/);
  busy.coreHost.call = plainCall;
  assert.equal(await quickFillOf(busy).fillOrOpen(TAB), "filled");
  assert.equal(valueOf(busy.pass), ITEM.password, "the aim was taken back");
  assert.equal(valueOf(busy.pass2), "");

  // An aim that waited longer than AIM_MS is gone.
  const late = await createWorld({ frames: [TOP] });
  late.targets.set(1, late.pass2);
  await late.scripting.executeScript({ target: { tabId: TAB, frameIds: [0] }, func: (/** @type {number} */ t) => /** @type {any} */ (globalThis).__ferretFill.aim(t), args: [1] });
  late.advance(AIM_MS + 1);
  assert.equal(await quickFillOf(late).fillOrOpen(TAB), "filled");
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
