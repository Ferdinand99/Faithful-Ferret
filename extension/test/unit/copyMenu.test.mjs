// The copy menu of a row in the popup's list: which entries it shows and
// which value each one asks the background for, the keyboard (Enter or Space,
// the arrows, Home, End, Escape and Tab), the focus going back to the button,
// and the 30-second clear of the clipboard after a copy of the user name as
// after one of the password. The menu runs on a small stand-in for the DOM.
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { test } from "node:test";
import { ALARM_PREFIX, CLEAR_AFTER_MS, MARK_KEY } from "../../src/background/clipboard.mjs";
import { PASSWORD, itemWorld } from "./itemHelpers.mjs";
import { pkg } from "./sessionHelpers.mjs";

// The menu imports the shared DOM helpers, which exist only in a build: it is loaded from the built package.
/** @type {typeof import("../../src/pages/copyMenu.mjs")} */
const { copyEntries, copyLabel, createCopyMenu, isEmailAddress, menuKey } = await (await pkg()).load("pages/copyMenu.mjs");

const here = dirname(fileURLToPath(import.meta.url));
const src = join(here, "..", "..", "src");
/** @param {string} lang */
const catalog = (lang) => JSON.parse(readFileSync(join(src, "locales", lang, "popup.json"), "utf8"));

// ------------------------------------------------------------------ a small DOM

class FakeNode {
  /** @param {number} nodeType */
  constructor(nodeType) {
    this.nodeType = nodeType;
    /** @type {FakeElement | null} */
    this.parentNode = null;
    /** @type {FakeNode[]} */
    this.childNodes = [];
  }

  get firstChild() {
    return this.childNodes[0] ?? null;
  }

  /** @param {FakeNode} child */
  appendChild(child) {
    child.parentNode?.removeChild(child);
    child.parentNode = /** @type {any} */ (this);
    this.childNodes.push(child);
    return child;
  }

  /** @param {FakeNode} child */
  removeChild(child) {
    this.childNodes = this.childNodes.filter((c) => c !== child);
    child.parentNode = null;
    return child;
  }

  /** @returns {string} */
  get textContent() {
    return this.childNodes.map((c) => c.textContent).join("");
  }
}

class FakeText extends FakeNode {
  /** @param {string} data */
  constructor(data) {
    super(3);
    this.data = data;
  }

  get textContent() {
    return this.data;
  }
}

class FakeElement extends FakeNode {
  /** @param {any} doc @param {string} tagName */
  constructor(doc, tagName) {
    super(1);
    this.doc = doc;
    this.tagName = tagName.toUpperCase();
    /** @type {Map<string, string>} */
    this.attributes = new Map();
    /** @type {Array<[string, (event: any) => void]>} */
    this.listeners = [];
  }

  /** @param {string} name @param {string} value */
  setAttribute(name, value) {
    this.attributes.set(name, String(value));
  }

  /** @param {string} name */
  getAttribute(name) {
    return this.attributes.get(name) ?? null;
  }

  /** @param {string} name */
  removeAttribute(name) {
    this.attributes.delete(name);
  }

  get hidden() {
    return this.attributes.has("hidden");
  }

  set hidden(value) {
    if (value) this.attributes.set("hidden", "");
    else this.attributes.delete("hidden");
  }

  /** @param {string} type @param {(event: any) => void} fn */
  addEventListener(type, fn) {
    this.listeners.push([type, fn]);
  }

  focus() {
    this.doc.activeElement = this;
  }

  /** @param {FakeNode} node */
  contains(node) {
    for (let n = /** @type {FakeNode | null} */ (node); n !== null; n = n.parentNode) if (n === this) return true;
    return false;
  }

  /** @param {string} role @returns {FakeElement[]} */
  byRole(role) {
    /** @type {FakeElement[]} */
    const out = [];
    const walk = (/** @type {FakeNode} */ n) => {
      if (n instanceof FakeElement && n.getAttribute("data-role") === role) out.push(n);
      for (const c of n.childNodes) walk(c);
    };
    walk(this);
    return out;
  }
}

/** A document with an `activeElement`, set as the global one. */
function useDocument() {
  const doc = {
    /** @type {FakeElement | null} */
    activeElement: null,
    /** @param {string} tag */
    createElement: (tag) => new FakeElement(doc, tag),
    /** @param {string} data */
    createTextNode: (data) => new FakeText(data),
  };
  /** @type {any} */ (globalThis).document = doc;
  return doc;
}

/**
 * An event on `target` that bubbles up to the root, as the browser's would.
 * @param {FakeElement} target @param {string} type @param {Record<string, unknown>} [init]
 */
function fire(target, type, init = {}) {
  const event = {
    type,
    target,
    defaultPrevented: false,
    preventDefault() {
      event.defaultPrevented = true;
    },
    ...init,
  };
  for (let n = /** @type {FakeElement | null} */ (target); n !== null; n = n.parentNode) {
    for (const [t, fn] of n.listeners) if (t === type) fn(event);
  }
  return event;
}

/** A key on the element that has the focus. @param {any} doc @param {string} key */
const press = (doc, key) => fire(doc.activeElement, "keydown", { key });

/**
 * The text of a key in a language, with its `{name}` parts filled in.
 * @param {string} lang @returns {(key: string, vars?: Record<string, string | number>) => string}
 */
const textsOf = (lang) => (key, vars = {}) => (catalog(lang)[key] ?? `?${key}`).replace(/\{(\w+)\}/g, (/** @type {string} */ all, /** @type {string} */ name) => (name in vars ? String(vars[name]) : all));

/** The menu of a row, with what it asked for. @param {{ username: string, name?: string, hasTotp?: boolean }} row */
function menuOf(row) {
  const doc = useDocument();
  /** @type {Array<[string, string]>} */
  const copied = [];
  let opened = 0;
  let closed = 0;
  const t = textsOf("en");
  const menu = createCopyMenu({
    row: { ref: "r1", ...row },
    t,
    copy: (field, done) => copied.push([field, done]),
    onOpen: () => {
      opened += 1;
    },
    onClose: () => {
      closed += 1;
    },
  });
  const root = /** @type {FakeElement} */ (/** @type {unknown} */ (menu.root));
  const button = /** @type {FakeElement} */ (/** @type {unknown} */ (menu.button));
  const list = root.byRole("copy-menu")[0];
  const items = () => list.childNodes.filter((n) => n instanceof FakeElement);
  return { doc, menu, root, button, list, items, copied, counts: () => ({ opened, closed }) };
}

test("the_copy_menu_offers_the_user_name_or_the_e_mail_and_the_password_and_the_one_time_code_of_an_item_that_holds_one", () => {
  assert.deepEqual(copyEntries({ username: "ola" }), [
    { field: "username", label: "popup.row.copy_username", done: "popup.copied.username" },
    { field: "password", label: "popup.row.copy_password", done: "popup.copied.password" },
  ]);
  assert.deepEqual(copyEntries({ username: "ola@example.net" }).map((e) => [e.field, e.label, e.done]), [
    ["username", "popup.row.copy_email", "popup.copied.email"],
    ["password", "popup.row.copy_password", "popup.copied.password"],
  ]);
  // No user name: the password only.
  assert.deepEqual(copyEntries({ username: "" }).map((e) => e.field), ["password"]);
  // The one-time code is offered for a row that is marked as holding one, and only for that row.
  assert.deepEqual(copyEntries({ username: "ola", hasTotp: true }).map((e) => [e.field, e.label]), [
    ["username", "popup.row.copy_username"],
    ["password", "popup.row.copy_password"],
    ["totp", "popup.row.copy_totp"],
  ]);
  assert.deepEqual(copyEntries({ username: "", hasTotp: true }).map((e) => e.field), ["password", "totp"]);
  for (const hasTotp of [false, undefined]) assert.deepEqual(copyEntries({ username: "ola", hasTotp }).map((e) => e.field), ["username", "password"], `hasTotp ${hasTotp}`);
  assert.deepEqual(menuOf({ username: "ola" }).items().map((i) => i.getAttribute("data-field")), ["username", "password"], "no one-time code in the menu of an unmarked row");
  const marked = menuOf({ username: "ola", hasTotp: true });
  assert.deepEqual(marked.items().map((i) => i.getAttribute("data-field")), ["username", "password", "totp"], "the one-time code in the menu of a marked row");
  fire(marked.items()[2], "click");
  assert.deepEqual(marked.copied, [["totp", "popup.copied.totp"]]);
  for (const name of ["ola@example.net", "o.la+x@mail.example.org", " ola@example.net "]) assert.equal(isEmailAddress(name), true, name);
  for (const name of ["ola", "ola@localhost", "@example.net", "ola@", "o la@example.net", "ola@exa mple.net", ""]) assert.equal(isEmailAddress(name), false, name);
  // Every label and note is in both languages.
  const en = catalog("en");
  const nb = catalog("nb");
  const keys = ["popup.row.copy", ...copyEntries({ username: "a@b.c", hasTotp: true }).flatMap((e) => [e.label, e.done]), ...copyEntries({ username: "a" }).flatMap((e) => [e.label, e.done])];
  for (const key of keys) {
    assert.ok(Object.hasOwn(en, key), key);
    assert.ok(Object.hasOwn(nb, key), key);
  }
  // Every note after a copy says that the clipboard is cleared.
  for (const key of keys.filter((k) => k.startsWith("popup.copied."))) {
    assert.match(en[key], /30 seconds/, key);
    assert.match(nb[key], /30 sekunder/, key);
  }
  // The menu writes no markup and no styles.
  const code = readFileSync(join(src, "pages", "copyMenu.mjs"), "utf8");
  for (const sink of ["innerHTML", "outerHTML", "insertAdjacentHTML", "document.write", "eval(", "new Function", "style="]) assert.equal(code.includes(sink), false, sink);
});

test("each_entry_asks_the_background_for_its_own_value_and_the_focus_goes_back_to_the_button", () => {
  const { doc, button, list, items, copied, counts } = menuOf({ username: "ola@example.net" });
  // The button names the menu it opens.
  assert.equal(button.getAttribute("aria-haspopup"), "menu");
  assert.equal(button.getAttribute("aria-expanded"), "false");
  assert.equal(button.getAttribute("aria-label"), "Copy from (no name)");
  assert.equal(button.getAttribute("title"), "Copy");
  assert.equal(list.getAttribute("role"), "menu");
  assert.equal(list.hidden, true);
  assert.deepEqual(items().map((i) => [i.getAttribute("role"), i.getAttribute("tabindex"), i.textContent]), [
    ["menuitem", "-1", "Copy e-mail"],
    ["menuitem", "-1", "Copy password"],
  ]);
  // A click opens it at its first entry; a click on an entry closes it, asks for that value and gives the focus back.
  fire(button, "click");
  assert.equal(list.hidden, false);
  assert.equal(button.getAttribute("aria-expanded"), "true");
  assert.equal(doc.activeElement, items()[0]);
  fire(items()[0], "click");
  assert.deepEqual(copied, [["username", "popup.copied.email"]]);
  assert.equal(list.hidden, true);
  assert.equal(button.getAttribute("aria-expanded"), "false");
  assert.equal(doc.activeElement, button);
  fire(button, "click");
  fire(items()[1], "click");
  assert.deepEqual(copied, [["username", "popup.copied.email"], ["password", "popup.copied.password"]]);
  // A second click on the button closes it without a copy.
  fire(button, "click");
  fire(button, "click");
  assert.equal(list.hidden, true);
  assert.equal(copied.length, 2);
  assert.deepEqual(counts(), { opened: 3, closed: 3 });
  // A user name that is no e-mail address says so.
  const plain = menuOf({ username: "ola" });
  fire(plain.button, "click");
  assert.equal(plain.items()[0].textContent, "Copy user name");
  fire(plain.items()[0], "click");
  assert.deepEqual(plain.copied, [["username", "popup.copied.username"]]);
});

test("the_copy_menu_works_with_the_keyboard", () => {
  const { doc, button, list, items, copied, menu } = menuOf({ username: "ola" });
  button.focus();
  // Enter and Space are the button's click (the browser makes them one): the menu opens at its first entry.
  assert.equal(press(doc, "Enter").defaultPrevented, false, "Enter is left to the button");
  fire(button, "click");
  assert.equal(doc.activeElement, items()[0]);
  // The arrows move round, Home and End go to the ends.
  assert.equal(press(doc, "ArrowDown").defaultPrevented, true);
  assert.equal(doc.activeElement, items()[1]);
  press(doc, "ArrowDown");
  assert.equal(doc.activeElement, items()[0], "round to the first");
  press(doc, "ArrowUp");
  assert.equal(doc.activeElement, items()[1], "round to the last");
  press(doc, "Home");
  assert.equal(doc.activeElement, items()[0]);
  press(doc, "End");
  assert.equal(doc.activeElement, items()[1]);
  // Escape closes it and gives the focus back to the button; nothing was copied.
  assert.equal(press(doc, "Escape").defaultPrevented, true);
  assert.equal(list.hidden, true);
  assert.equal(menu.open, false);
  assert.equal(button.getAttribute("aria-expanded"), "false");
  assert.equal(doc.activeElement, button);
  // Arrow Down on the button opens it at the first entry, Arrow Up at the last.
  press(doc, "ArrowDown");
  assert.equal(list.hidden, false);
  assert.equal(doc.activeElement, items()[0]);
  press(doc, "Escape");
  press(doc, "ArrowUp");
  assert.equal(doc.activeElement, items()[1]);
  // Enter on an entry is its click: the password is asked for and the focus is back on the button.
  fire(/** @type {any} */ (doc.activeElement), "click");
  assert.deepEqual(copied, [["password", "popup.copied.password"]]);
  assert.equal(doc.activeElement, button);
  // Tab closes it and moves on as usual (not held back).
  press(doc, "ArrowDown");
  assert.equal(press(doc, "Tab").defaultPrevented, false);
  assert.equal(list.hidden, true);
  // Other keys, and Escape on a closed menu, are not the menu's.
  button.focus();
  assert.equal(press(doc, "Escape").defaultPrevented, false);
  assert.equal(press(doc, "a").defaultPrevented, false);
  assert.equal(list.hidden, true);
  // The steps themselves.
  assert.deepEqual(menuKey("ArrowDown", { open: false, at: -1, count: 2 }), { open: true, focus: 0 });
  assert.deepEqual(menuKey("ArrowUp", { open: false, at: -1, count: 2 }), { open: true, focus: 1 });
  assert.equal(menuKey("Enter", { open: false, at: -1, count: 2 }), null);
  assert.deepEqual(menuKey("ArrowDown", { open: true, at: -1, count: 3 }), { open: true, focus: 0 });
  assert.deepEqual(menuKey("ArrowUp", { open: true, at: 0, count: 3 }), { open: true, focus: 2 });
  assert.deepEqual(menuKey("Escape", { open: true, at: 1, count: 3 }), { open: false, focus: "button" });
  assert.deepEqual(menuKey("Tab", { open: true, at: 1, count: 3 }), { open: false, focus: null });
  assert.equal(menuKey("ArrowDown", { open: false, at: -1, count: 0 }), null);
});

test("a_copied_user_name_is_cleared_after_30_seconds_as_a_copied_password_is", async () => {
  const world = await itemWorld();
  await world.open();
  const popup = world.popup();
  const [row] = (await popup.list.search({ query: "Example" })).rows;
  // The menu's entries, wired to the background as the list wires them.
  /** @type {Promise<unknown>[]} */
  const pending = [];
  useDocument();
  const menu = createCopyMenu({
    row,
    t: (key) => key,
    copy: (field) => pending.push(popup.list.copy(row.ref, field)),
    onOpen: () => {},
    onClose: () => {},
  });
  const button = /** @type {FakeElement} */ (/** @type {unknown} */ (menu.button));
  const entry = (/** @type {string} */ field) => /** @type {FakeElement} */ ((/** @type {FakeElement} */ (/** @type {unknown} */ (menu.root))).byRole(`copy-${field}`)[0]);
  /** The clipboard alarm that is armed, and when it fires. */
  const armed = () => [...world.events.alarmList.entries()].filter(([name]) => name.startsWith(ALARM_PREFIX));
  /** Fires an alarm; a one-shot alarm is gone once it fired, as in the browser. @param {string} name */
  const fire1 = async (name) => {
    world.events.alarmList.delete(name);
    await world.events.fireAlarm(name);
  };

  for (const [field, value] of /** @type {Array<[string, string]>} */ ([["username", "ola@example.net"], ["password", PASSWORD]])) {
    world.written.length = 0;
    fire(button, "click");
    fire(entry(field), "click");
    assert.deepEqual(await Promise.all(pending.splice(0)), [{ ok: true }], field);
    assert.deepEqual(world.written, [value], `${field}: the background wrote the item's own value`);
    const alarms = armed();
    assert.equal(alarms.length, 1, field);
    assert.equal(alarms[0][1].when, world.clock.now() + CLEAR_AFTER_MS, `${field}: cleared 30 seconds later`);
    assert.equal(alarms[0][0], `${ALARM_PREFIX}${world.sessionStorage.data.get(MARK_KEY)}`);
    world.clock.advance(CLEAR_AFTER_MS);
    await fire1(alarms[0][0]);
    assert.deepEqual(world.written, [value, ""], `${field}: the clipboard is empty again`);
  }

  // A user name and then a password 10 seconds later: the user name's alarm leaves the password, the password's clears it.
  world.written.length = 0;
  fire(button, "click");
  fire(entry("username"), "click");
  await Promise.all(pending.splice(0));
  const first = armed()[0][0];
  world.clock.advance(10_000);
  fire(button, "click");
  fire(entry("password"), "click");
  await Promise.all(pending.splice(0));
  world.clock.advance(20_000);
  await fire1(first);
  assert.deepEqual(world.written, ["ola@example.net", PASSWORD]);
  const [[second]] = armed();
  world.clock.advance(10_000);
  await fire1(second);
  assert.deepEqual(world.written, ["ola@example.net", PASSWORD, ""]);
  // The popup never got a value.
  assert.equal(popup.received().join("\n").includes(PASSWORD), false);
});

test("each_copy_button_names_its_row_for_screen_readers", () => {
  // The button and its menu are named after the row, so the buttons of the list can be told apart; the tooltip says "Copy".
  const one = menuOf({ username: "ola", name: "Example Bank" });
  const two = menuOf({ username: "ola", name: "Mail" });
  assert.equal(one.button.getAttribute("aria-label"), "Copy from Example Bank");
  assert.equal(one.list.getAttribute("aria-label"), "Copy from Example Bank");
  assert.equal(two.button.getAttribute("aria-label"), "Copy from Mail");
  assert.equal(one.button.getAttribute("title"), "Copy");
  // A row without a name is named as the list shows it.
  assert.equal(menuOf({ username: "ola", name: "" }).button.getAttribute("aria-label"), "Copy from (no name)");
  // In Norwegian too, and a name is put in as it is (a text, never markup).
  assert.equal(copyLabel({ name: "Banken <b>" }, textsOf("nb")), "Kopier fra Banken <b>");
  assert.equal(copyLabel({}, textsOf("nb")), "Kopier fra (uten navn)");
  for (const lang of ["en", "nb"]) assert.match(catalog(lang)["popup.row.copy_from"], /\{name\}/, lang);

  // The list passes each row to its copy button: every copy button in the popup's list names its own row.
  const list = readFileSync(join(src, "pages", "popupList.mjs"), "utf8");
  assert.match(list, /createCopyMenu\(\{\s*row,/);
});

test("the_copy_note_says_the_clipboard_is_cleared_after_30_seconds_even_if_you_copied_something_else", () => {
  const en = catalog("en");
  const nb = catalog("nb");
  const notes = [...new Set([...copyEntries({ username: "a@b.c", hasTotp: true }), ...copyEntries({ username: "a" })].map((e) => e.done))];
  assert.deepEqual(notes.sort(), ["popup.copied.email", "popup.copied.password", "popup.copied.totp", "popup.copied.username"]);
  for (const key of notes) {
    assert.match(en[key], /clears the clipboard after 30 seconds, even if you have copied something else in the meantime\.$/, key);
    assert.match(nb[key], /tømmer utklippstavlen etter 30 sekunder, også om du har kopiert noe annet i mellomtiden\.$/, key);
  }
});
