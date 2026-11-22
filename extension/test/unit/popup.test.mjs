// The popup's list of the vault: what the background answers to it (names,
// user names, marks and references, never a value), the popup's own flow over
// those answers, and the texts of the list in both languages.
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { test } from "node:test";
import { ACTION_ERRORS, FILTER_TYPES, actionErrorKey, createListFlow, followStep, rowsOf } from "../../src/pages/popupFlow.mjs";
import { REASONS as COPY_REASONS } from "../../src/background/handlers/copy.handler.mjs";
import { REASONS as FILL_REASONS } from "../../src/background/handlers/fill.handler.mjs";
import { ITEMS, OTHER_PASSWORD, PASSWORD, TAB, TOTP_CODE, idOf, itemWorld } from "./itemHelpers.mjs";

const here = dirname(fileURLToPath(import.meta.url));
const src = join(here, "..", "..", "src");
/** @param {string} lang */
const catalog = (lang) => JSON.parse(readFileSync(join(src, "locales", lang, "popup.json"), "utf8"));

test("the_popup_never_shows_a_password", async () => {
  const world = await itemWorld();
  await world.open();
  const popup = world.popup();
  // Everything the popup can ask for: the page's candidates, the lists, an item's view, a copy of each value, a fill
  // and opening a site.
  const page = await popup.list.page(TAB);
  const listed = await popup.list.list({});
  const searched = await popup.list.list({ query: "o", type: "login" });
  const [row] = listed.all.rows;
  const view = await popup.list.item(row.ref);
  for (const field of ["username", "password", "totp"]) assert.deepEqual(await popup.list.copy(row.ref, field), { ok: true }, field);
  assert.deepEqual(await popup.list.fill(/** @type {any} */ (page).rows[0], TAB), { ok: true });
  assert.deepEqual(await popup.list.openSite(row.ref), { ok: true });
  // The values went to the clipboard and into the page, written by the background.
  assert.deepEqual(world.written, ["ola@example.net", PASSWORD, TOTP_CODE]);
  assert.deepEqual(world.page.filled, { username: "ola@example.net", password: PASSWORD });
  // Not one of the texts the background sent the popup holds a password or a code.
  const received = popup.received();
  assert.ok(received.length >= 8);
  for (const text of received) {
    for (const secret of [PASSWORD, OTHER_PASSWORD, TOTP_CODE]) assert.equal(text.includes(secret), false, `${secret} in ${text.slice(0, 80)}`);
  }
  // The item view says what can be copied, and shows the user name only.
  assert.deepEqual(view, {
    ok: true,
    name: "Example",
    username: "ola@example.net",
    type: "login",
    favorite: true,
    urls: ["https://login.example.net/"],
    copyable: ["username", "password", "totp"],
  });
  assert.ok(searched.all.rows.every((r) => r.type === "login"));
  // The page code has no way to show one: no input of type password in the list, the item view shows dots.
  const code = readFileSync(join(src, "pages", "popupList.mjs"), "utf8");
  assert.equal(/type:\s*"password"/.test(code), false);
  assert.match(code, /valueRow\("password", "••••••••"\)/);
  for (const sink of ["innerHTML", "outerHTML", "insertAdjacentHTML", "document.write", "eval(", "new Function", "style="]) {
    assert.equal(code.includes(sink), false, sink);
    assert.equal(readFileSync(join(src, "pages", "popup.mjs"), "utf8").includes(sink), false, sink);
  }
});

test("search_lists_names_and_usernames_only_with_copy_actions", async () => {
  const many = Array.from({ length: 45 }, (_, i) => ({
    id: idOf(10 + i), name: `Site ${String(i).padStart(2, "0")}`, username: `user${i}`, password: `pw-${i}-secret`, favorite: i % 10 === 0, type: "login", urls: [`https://s${i}.example.com/`], totp: false,
  }));
  const world = await itemWorld({ items: [...ITEMS, ...many] });
  await world.open();
  const popup = world.popup();
  const reply = await popup.request("search", { query: "" });
  assert.equal(reply.total, 48);
  assert.equal(reply.handles.length, 40, "one page");
  for (const handle of reply.handles) {
    assert.deepEqual(Object.keys(handle).filter((k) => !["ref", "name", "username", "favorite", "type", "site"].includes(k)), [], JSON.stringify(handle));
    assert.match(handle.ref, /^[0-9a-f]{32}$/);
  }
  const next = await popup.request("search", { query: "", offset: 40 });
  assert.equal(next.handles.length, 8);
  // By name, by user name, by address, by several words; favourites; a type.
  assert.deepEqual((await popup.list.search({ query: "bank" })).rows.map((r) => r.name), ["Bank"]);
  assert.deepEqual((await popup.list.search({ query: "user4" })).rows.map((r) => r.name), ["Site 04", "Site 40", "Site 41", "Site 42", "Site 43", "Site 44"]);
  assert.deepEqual((await popup.list.search({ query: "s7.example" })).rows.map((r) => r.name), ["Site 07"]);
  assert.deepEqual((await popup.list.search({ query: "site 3" })).rows.length, 14);
  assert.deepEqual((await popup.list.search({ favorites: true })).rows.map((r) => r.name).sort(), ["Example", "Site 00", "Site 10", "Site 20", "Site 30", "Site 40"]);
  assert.deepEqual((await popup.list.search({ type: "note" })).rows.map((r) => r.name), ["Recipe"]);
  // A search's reference copies, shows and opens; it never fills.
  const [bank] = (await popup.list.search({ query: "bank" })).rows;
  assert.deepEqual(await popup.list.copy(bank.ref, "password"), { ok: true });
  assert.deepEqual(world.written, [OTHER_PASSWORD]);
  assert.equal((await popup.list.item(bank.ref)).ok, true);
  assert.deepEqual(await popup.list.openSite(bank.ref), { ok: true });
  assert.deepEqual(world.opened, ["https://bank.example.org/"]);
  assert.deepEqual(await popup.request("fill", { ref: bank.ref, tab_id: TAB, frame_id: 0 }), { ok: false, reason: "not_offered" });
  // An item without an address has no site, and opening it is refused.
  const [note] = (await popup.list.search({ query: "recipe" })).rows;
  assert.equal(note.site, false);
  assert.deepEqual(await popup.list.openSite(note.ref), { ok: false, reason: "no_site" });
  // The answer names nothing secret.
  for (const text of popup.received()) assert.equal(/pw-\d+-secret|S3cret/.test(text), false, text.slice(0, 80));
  // A locked vault answers no search.
  await world.coreHost.lock("manual");
  await assert.rejects(popup.request("search", { query: "" }), { code: "vault_locked" });
});

test("the_list_shows_suggestions_favourites_and_all_items_and_a_search_hides_the_suggestions", async () => {
  /** @type {Array<[string, any]>} */
  const asked = [];
  /** @type {Record<string, any>} */
  const answers = {
    candidates: {
      handles: [{ ref: "c1", name: "Example", username: "ola", frame_id: 0, insecure: true }, { ref: "c2", name: "Stray" }],
      host: { unicode: "løgin.example.net", a_label: "xn--lgin-ura.example.net" },
      insecure: true,
      grant: [{ origin: "https://www.example.net", host: { unicode: "www.example.net", a_label: "www.example.net" } }],
    },
  };
  const request = async (/** @type {string} */ type, /** @type {any} */ body) => {
    asked.push([type, body]);
    if (type === "search") return { handles: body.favorites ? [{ ref: "f1", name: "Fav", favorite: true }] : [{ ref: "a1", name: "A" }], total: body.query === "" && body.type === undefined ? 3 : 1 };
    return answers[type];
  };
  const list = createListFlow(request);
  const page = await list.page(TAB);
  // Only candidates with a frame can be filled; the host is the core's, with the A-label next to it.
  assert.deepEqual(page, {
    host: "løgin.example.net (xn--lgin-ura.example.net)",
    insecure: true,
    rows: [{ ref: "c1", name: "Example", username: "ola", favorite: false, type: "other", site: false, insecure: true, frameId: 0 }],
    grant: [{ origin: "https://www.example.net", host: "www.example.net" }],
  });
  // The request names no frame (all of the tab's), and a tab that shows no web page has no host.
  assert.deepEqual(asked[0], ["candidates", { tab_id: TAB }]);
  answers.candidates = { handles: [], insecure: false, grant: [] };
  assert.deepEqual(await list.page(TAB), { host: "", insecure: false, rows: [], grant: [] });
  assert.equal(await list.page(null), null, "no page: nothing to ask");
  answers.candidates = undefined;
  const refused = createListFlow(async (type) => {
    if (type === "candidates") throw Object.assign(new Error("not_available"), { code: "not_available" });
    return { handles: [], total: 0 };
  });
  assert.equal(await refused.page(TAB), null, "no page matching: no suggestions");

  asked.length = 0;
  const plain = await list.list({});
  assert.deepEqual(plain.favorites?.rows.map((r) => r.ref), ["f1"]);
  assert.deepEqual(plain.all.rows.map((r) => r.ref), ["a1"]);
  assert.equal(plain.count, 3);
  assert.deepEqual(asked, [["search", { query: "", favorites: true }], ["search", { query: "" }]]);
  asked.length = 0;
  const searching = await list.list({ query: "ex", type: "login" });
  assert.equal(searching.favorites, null, "a search shows its results only");
  assert.equal(searching.count, 3, "the count is the vault's");
  assert.deepEqual(asked, [["search", { query: "ex", type: "login" }], ["search", { query: "" }]]);
  // "Fill" on a row without a frame is not even asked.
  asked.length = 0;
  assert.deepEqual(await list.fill(rowsOf({ handles: [{ ref: "x", name: "x" }] })[0], TAB), { ok: false, reason: "not_offered" });
  assert.deepEqual(asked, []);
  await list.fill(/** @type {any} */ (page).rows[0], TAB);
  // "Fill" names no frame: the background fills the first of the item's frames that has a sign-in form.
  assert.deepEqual(asked, [["fill", { ref: "c1", tab_id: TAB }]]);
});

test("rows_keep_only_what_the_popup_shows", () => {
  const rows = rowsOf({ handles: [{ ref: "r1", name: "N", username: "u", favorite: true, type: "card", site: true, frame_id: 3, extra: "x" }, { name: "no ref" }, null] });
  assert.deepEqual(rows, [{ ref: "r1", name: "N", username: "u", favorite: true, type: "card", site: true, insecure: false, frameId: 3 }]);
  assert.deepEqual(rowsOf(null), []);
  assert.equal(actionErrorKey("origin_changed"), "popup.error.origin_changed");
  assert.equal(actionErrorKey("<b>"), "popup.error.unknown");
  assert.equal(actionErrorKey(undefined), "popup.error.unknown");
});

test("every_text_of_the_list_is_there_in_both_languages", () => {
  const en = catalog("en");
  const nb = catalog("nb");
  assert.deepEqual(Object.keys(nb).sort(), Object.keys(en).sort());
  for (const [key, text] of Object.entries(nb)) assert.ok(typeof text === "string" && text.trim() !== "", key);
  // Every reason the background can give has a text.
  for (const reason of [...ACTION_ERRORS, "unknown"]) assert.ok(Object.hasOwn(en, `popup.error.${reason}`), reason);
  for (const reason of [...FILL_REASONS, ...COPY_REASONS]) assert.ok(ACTION_ERRORS.includes(reason) || reason === "unknown", reason);
  for (const type of [...FILTER_TYPES, "all", "other"]) assert.ok(Object.hasOwn(en, `popup.type.${type}`), type);
  // Every literal key of the list and the popup is in the catalog.
  for (const file of ["popupList.mjs", "popup.mjs"]) {
    const code = readFileSync(join(src, "pages", file), "utf8");
    for (const [, key] of code.matchAll(/t\("(popup\.[a-z_.]+)"/g)) assert.ok(Object.hasOwn(en, key), `${file}: ${key}`);
  }
  // The texts with a value to put in name it the same way in both.
  for (const [key, text] of Object.entries(en)) {
    const vars = (/** @type {string} */ s) => [...s.matchAll(/\{([a-z_]+)\}/g)].map((m) => m[1]).sort();
    assert.deepEqual(vars(nb[key]), vars(text), key);
  }
});

test("the_list_has_only_working_controls", () => {
  const code = readFileSync(join(src, "pages", "popupList.mjs"), "utf8");
  // Every button of the list has a click handler; the layout's controls that do not work in this version are absent.
  for (const absent of ["popup.row.edit", "popup.row.clone", "popup.row.move", "popup.row.delete", "popup.tab.generator", "popup.tab.health", "popup.new_item"]) {
    assert.equal(code.includes(absent), false, absent);
  }
  const html = readFileSync(join(src, "pages", "popup.html"), "utf8");
  assert.equal(/<nav\b/.test(html), false, "no tab bar");
  assert.equal(/style=/.test(html), false, "no inline style");
  assert.equal(/<script\b(?![^>]*\bsrc=)/.test(html), false, "no inline script");
});

test("an_automatic_list_reload_does_not_move_the_lock_deadline", async () => {
  // A popped-out popup reloads its list whenever the sync changes something. With nobody at it, it locks at the deadline.
  const world = await itemWorld();
  await world.open();
  const popup = world.popup();
  const deadline = world.sessionStorage.data.get("lock_at");
  assert.equal(typeof deadline, "number");
  let lockedAt = null;
  for (let minute = 1; minute <= 20 && lockedAt === null; minute += 1) {
    world.clock.advance(60_000);
    await popup.list.page(TAB, { automatic: true });
    await popup.list.list({ automatic: true }).catch(() => null);
    await world.tick();
    if (world.coreHost.state() === "locked") lockedAt = minute;
    else assert.equal(world.sessionStorage.data.get("lock_at"), deadline, `minute ${minute}: the deadline stayed`);
  }
  assert.equal(lockedAt, 15, "locked at the deadline (15 minutes)");

  // The same reads made by the user move it.
  const busy = await itemWorld();
  await busy.open();
  const user = busy.popup();
  for (let minute = 1; minute <= 20; minute += 1) {
    busy.clock.advance(60_000);
    await user.list.page(TAB);
    await user.list.list({});
    await busy.tick();
  }
  assert.equal(busy.coreHost.state(), "unlocked");
  assert.equal(busy.sessionStorage.data.get("lock_at"), busy.clock.now() + 15 * 60_000);
});

test("open_site_opens_only_the_items_own_web_address", async () => {
  const bad = ["javascript:alert(1)", "data:text/html,x", "file:///etc/passwd", "ftp://x.example.net/", "about:blank"];
  const items = [
    { id: idOf(7), name: "Mixed", username: "m", password: "pw-7-secret", favorite: false, type: "login", urls: [...bad, "https://example.net/"], totp: false },
    { id: idOf(8), name: "Only bad", username: "b", password: "pw-8-secret", favorite: false, type: "login", urls: bad, totp: false },
  ];
  const world = await itemWorld({ items });
  await world.open();
  const popup = world.popup();
  const [mixed] = (await popup.list.search({ query: "mixed" })).rows;
  const [onlyBad] = (await popup.list.search({ query: "only bad" })).rows;
  assert.equal(mixed.site, true);
  assert.equal(onlyBad.site, false);
  assert.deepEqual(await popup.list.openSite(mixed.ref), { ok: true });
  assert.deepEqual(world.opened, ["https://example.net/"]);
  assert.deepEqual(await popup.list.openSite(onlyBad.ref), { ok: false, reason: "no_site" });
  assert.deepEqual(world.opened, ["https://example.net/"], "nothing else was opened");
  // The page names a reference, never an address: an unknown reference opens nothing.
  assert.deepEqual(await popup.request("open_site", { ref: "f".repeat(32) }), { ok: false, reason: "not_offered" });
  assert.deepEqual(world.opened, ["https://example.net/"]);
});

test("the_field_border_has_at_least_3_to_1_contrast_in_the_popup_and_the_tabs", () => {
  // WCAG 1.4.11: the border of a field against the field and against the page, in both themes.
  // The token lives in session.css, the styles of every page: the popup and the sign-in,
  // settings and grant tabs (where the master password and the Secret Key are typed).
  const popup = readFileSync(join(src, "styles", "popup.css"), "utf8");
  const session = readFileSync(join(src, "styles", "session.css"), "utf8");
  /** @param {string} css @param {string} name @returns {[string, string]} the light and the dark value */
  const token = (css, name) => {
    const m = new RegExp(String.raw`${name}:\s*light-dark\((#[0-9a-f]{6}),\s*(#[0-9a-f]{6})\)`, "i").exec(css);
    assert.ok(m, name);
    return [m[1], m[2]];
  };
  /** @param {string} hex */
  const luminance = (hex) => {
    const [r, g, b] = [1, 3, 5].map((i) => parseInt(hex.slice(i, i + 2), 16) / 255).map((c) => (c <= 0.04045 ? c / 12.92 : ((c + 0.055) / 1.055) ** 2.4));
    return 0.2126 * r + 0.7152 * g + 0.0722 * b;
  };
  /** @param {string} a @param {string} b */
  const contrast = (a, b) => {
    const [x, y] = [luminance(a), luminance(b)].sort((p, q) => q - p);
    return (x + 0.05) / (y + 0.05);
  };
  const border = token(session, "--field-border");
  for (const behind of ["--field", "--bg", "--card", "--card-raised"]) {
    const ground = token(session, behind);
    for (const theme of [0, 1]) assert.ok(contrast(border[theme], ground[theme]) >= 3, `${behind} ${theme ? "dark" : "light"}: ${contrast(border[theme], ground[theme]).toFixed(2)}`);
  }
  // Every field of every page uses it (.ff-input is the class of the tabs' inputs, the
  // settings select and the sign-in text area), and so does the popup's search field.
  assert.match(session, /\.ff-input \{[^}]*border: 1px solid var\(--field-border\)/);
  assert.match(popup, /\.ff-search \{[^}]*border: 1px solid var\(--field-border\)/);
  // No other rule gives a field a weaker border.
  const sync = readFileSync(join(src, "styles", "sync.css"), "utf8");
  const base = readFileSync(join(src, "styles", "base.css"), "utf8");
  for (const [name, css] of [["session", session], ["popup", popup], ["sync", sync], ["base", base]]) {
    assert.doesNotMatch(css, /--control-border/, name);
    for (const rule of css.matchAll(/([^{}]*\.ff-(?:input|search)[^{}]*)\{([^}]*)\}/g)) {
      const body = rule[2];
      if (/border(?:-color)?\s*:/.test(body)) assert.match(body, /var\(--field-border\)|transparent|none|border:\s*0\b/, `${name}: ${rule[1].trim()}`);
    }
  }
  for (const page of ["signin", "settings", "grant", "popup"]) {
    const html = readFileSync(join(src, "pages", `${page}.html`), "utf8");
    assert.match(html, /href="\.\.\/assets\/app\.css"/, `${page} loads the shared styles`);
  }
});

test("an_open_forget_question_still_follows_a_lock", () => {
  const sync = { running: true, status: "idle", live: "live", halted: "rollback_suspected", actions: ["try_again", "forget"], warnings: [] };
  /** @type {import("../../src/pages/popupFlow.mjs").PopupView} */
  const shown = { view: "unlocked", host: "vault.example.com", account: "ola@example.com", server: "https://vault.example.com", sync };
  const changed = { ...shown, sync: { ...sync, status: "syncing" } };
  // While the user answers "Forget this server", the sync's part (where the question is) stays as it is.
  assert.equal(followStep(shown, changed, true), "same");
  assert.equal(followStep(shown, changed, false), "sync");
  assert.equal(followStep(shown, shown, false), "same");
  assert.equal(followStep(shown, null, true), "same");
  // A lock, a sign-out or another account ends the question, and the list with it.
  for (const asking of [true, false]) {
    assert.equal(followStep(shown, { ...shown, view: "locked", sync: null }, asking), "rebuild", `locked, asking ${asking}`);
    assert.equal(followStep(shown, { view: "signed_out", host: "", account: "", server: "", sync: null }, asking), "rebuild", `signed out, asking ${asking}`);
    assert.equal(followStep(shown, { ...shown, account: "kari@example.com" }, asking), "rebuild", `another account, asking ${asking}`);
    assert.equal(followStep(shown, { ...shown, server: "https://other.example.com" }, asking), "rebuild", `another server, asking ${asking}`);
  }

  // The popup reads the state on every round, with the question open or not.
  const code = readFileSync(join(src, "pages", "popup.mjs"), "utf8");
  assert.match(code, /\n\s*next = await flow\.load\(\);\n/);
  assert.match(code, /followStep\(view, next, root\.querySelector\('\[data-role="forget-confirm"\]'\) !== null\)/);

  // Those reads (`state`, `sync_state`) never move the deadline, and `state` after the deadline says "locked": see
  // a_message_that_needs_no_key_does_not_move_the_deadline and state_after_the_deadline_reports_locked (router tests).
});
