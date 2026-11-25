// Passkeys in the web vault: the item page shows the site, the user name the site gave and the date, never the key; a new name is
// the ordinary edit and keeps the passkey; "Remove passkey" and "Move to trash" ask first and name the site; the trash keeps the
// passkey and says which site it belongs to; the list has a Passkeys filter. The sync engine here is the real one over the fake
// server and the fake core (the fake core keeps the body, with its private key, inside, as the real one does).
import assert from "node:assert/strict";
import { readFileSync, readdirSync } from "node:fs";
import { join } from "node:path";
import { test } from "node:test";
import { createListPrefs } from "../../src/listPrefs.mjs";
import { createWipeScope, formatMoment } from "../../src/views/common.mjs";
import { editView } from "../../src/views/edit.mjs";
import { itemView } from "../../src/views/item.mjs";
import { listView } from "../../src/views/list.mjs";
import { applyFilters, defaultState, formatListQuery, parseListQuery } from "../../src/views/listModel.mjs";
import { passkeyOf, passkeySites } from "../../src/views/itemModel.mjs";
import { trashView } from "../../src/views/trash.mjs";
import { fakeConflictEngine } from "./conflictHelpers.mjs";
import { createFakeClient, currentRev, Model, settle as settleEngine, syncDevice, until } from "./syncHelpers.mjs";
import { web } from "./helpers.mjs";
import { all, click, fakeClient, fakeEngine, find, fire, settle, submit, t, textOf, walk, withDom } from "./vaultHelpers.mjs";

const ID = "11".repeat(16);
const ID_B = "22".repeat(16);
const CREATED = Date.UTC(2026, 10, 20, 12, 0);
const SECRET_KEY = "PRIVATE-KEY-SENTINEL";
const SECRET_SEED = "PRF-SEED-SENTINEL";
const CRED_ID = "CREDENTIAL-ID-SENTINEL";

/** The view the core gives for an item with a passkey: public facts and credential ids, no key and no seed. */
const passkeyView = (extra = {}) => ({
  rp_id: "github.com", user_name: "ada@example.com", created: CREATED, has_prf: true,
  cred_id: new Uint8Array([1, 2, 3, 4]), user_handle: new Uint8Array([9, 8, 7]), rp_name: "GitHub", user_display_name: "Ada L.", ...extra,
});

const VIEW = Object.freeze({
  item_type: "login", name: "GitHub passkey", fields: [], urls: [{ url: "https://github.com", matching: "host" }],
  has_totp: false, has_notes: false, favorite: false, read_only: false, passkey: passkeyView(),
});
const ENTRY = Object.freeze({
  id: ID, name: "GitHub passkey", type: "login", favorite: false, urls: ["https://github.com"], username: "", rev: 2,
  passkeySite: "github.com", hasPasskey: true,
  pending: false, damaged: false, quarantined: false, missingOnServer: false, blocked: false, blockedReason: null, readOnly: false,
});

async function openItem({ entry = {}, view = {} } = {}) {
  const engine = fakeEngine({ items: [{ ...ENTRY, ...entry }], views: { [ID]: { ...VIEW, ...view } }, secrets: { [ID]: [] } });
  const client = fakeClient(engine);
  const moves = [];
  const root = await itemView({ engine, sync: engine, client, id: ID, t, go: (path) => moves.push(path), locale: "en" });
  return { engine, client, root, moves };
}

const row = (root, key) => find(root, "passkey-value", key);
const dialogText = (root) => textOf(find(root, "dialog"));

test("the_item_shows_site_user_and_date_never_the_key", async () => {
  await withDom(async () => {
    // Even a view that wrongly carried the key or a seed would not reach the page: the page reads only the public facts.
    const view = { passkey: { ...passkeyView(), priv: SECRET_KEY, prf_seed_uv: SECRET_SEED, cred_id_text: CRED_ID } };
    const { root, engine, client } = await openItem({ view });
    const card = all(root, "item-card").find((c) => c.getAttribute("data-card") === "passkey");
    assert.ok(card, "the passkey has a card of its own");
    assert.equal(textOf(card).includes("passkey.heading"), true);
    // The site is the relying party id, the identity; the user name and the date are the facts the page shows.
    assert.equal(textOf(row(card, "site")).trim(), "github.com");
    assert.equal(textOf(row(card, "user")).trim(), "ada@example.com");
    assert.equal(textOf(row(card, "created")).trim(), formatMoment(CREATED, "en"));
    assert.ok(textOf(card).includes("passkey.kind"), "it says what kind of passkey it is");
    const text = textOf(root);
    for (const hidden of [SECRET_KEY, SECRET_SEED, CRED_ID, "AQIDBA", "01020304"]) assert.ok(!text.includes(hidden), `${hidden} is not on the page`);
    // The page asks the worker for nothing about the passkey, and no item is left open.
    assert.deepEqual(client.calls, []);
    assert.equal(engine.handles.size, 0);
    assert.equal(all(root, "reveal").length, 0, "no field of the card has a Show button");
    assert.equal(all(card, "copy").length, 0, "and none a Copy button");
  });
});

test("the_texts_a_site_chose_are_isolated_labelled_and_never_the_identity_of_the_site", async () => {
  await withDom(async () => {
    const hostile = "github.com (official, verified)";
    const { root } = await openItem({ view: { passkey: passkeyView({ rp_name: hostile, user_display_name: "Ada ‮L." }) } });
    const card = all(root, "item-card").find((c) => c.getAttribute("data-card") === "passkey");
    // The site row is the relying party id and nothing else; what the site calls itself is a row of its own, with its own label.
    assert.equal(textOf(row(card, "site")).trim(), "github.com");
    assert.equal(textOf(row(card, "site_name")).trim(), hostile);
    assert.ok(textOf(find(card, "passkey-row", "site_name")).includes("passkey.site_name"));
    assert.ok(textOf(find(card, "passkey-row", "display_name")).includes("passkey.display_name"));
    // Every value is in a <bdi>, so a text of the site cannot reorder the text around it.
    for (const value of all(card, "passkey-value")) assert.equal(value.tagName.toLowerCase(), "bdi");
    // The header names the item, not the site's own words.
    assert.ok(!textOf(find(root, "item-head")).includes(hostile));
    // A text that only repeats the id or the user name is not shown twice.
    const same = await openItem({ view: { passkey: passkeyView({ rp_name: "GitHub.com", user_display_name: "ada@example.com" }) } });
    assert.equal(all(same.root, "passkey-value").map((n) => n.getAttribute("data-key")).join(), "site,user,created");
  });
});

test("an_item_without_a_passkey_has_no_passkey_card", async () => {
  await withDom(async () => {
    const { root } = await openItem({ entry: { passkeySite: null, hasPasskey: false }, view: { passkey: null } });
    assert.equal(all(root, "item-card").some((c) => c.getAttribute("data-card") === "passkey"), false);
    assert.equal(find(root, "remove-passkey"), null);
    assert.equal(passkeyOf({ passkey: { rp_id: "" } }), null);
    assert.equal(passkeyOf({}), null);
  });
});

test("rename_keeps_the_passkey_and_it_still_signs", async () => {
  // The edit form sends nothing about the passkey: a new name is the ordinary edit.
  await withDom(async () => {
    const engine = fakeEngine({ items: [ENTRY], views: { [ID]: VIEW }, secrets: { [ID]: [] } });
    const root = await editView({ engine, client: fakeClient(engine), id: ID, t, go() {}, hosts: [] });
    assert.ok(textOf(find(root, "passkey-note")).includes("github.com"), "the form says the passkey is kept");
    find(root, "name").value = "Work GitHub";
    await fire(find(root, "name"), "input");
    await submit(find(root, "edit-form"));
    await settle();
    const [update] = engine.calls.filter((c) => c[0] === "update");
    assert.equal(update[2].name, "Work GitHub");
    assert.ok(!("passkey" in update[2]) && !("remove_passkey" in update[2]), "the draft says nothing about the passkey");
  });
  // In the engine over the core, the passkey is the same one afterwards: the key stays inside, the ids are as they were.
  const model = new Model();
  const client = createFakeClient();
  const content = { item_type: "login", name: "GitHub passkey", fields: [], passkey: { rp_id: "github.com", user_name: "ada", cred_id: "c1", user_handle: "u1", priv: SECRET_KEY, created: CREATED, prf_seed_uv: SECRET_SEED } };
  model.set(ID, { rev: 1, ...client.wireRow(ID, 1, content) });
  const d = await syncDevice({ model, client });
  await d.engine.start();
  assert.equal(d.engine.list()[0].passkeySite, "github.com");
  await d.engine.update(ID, { name: "Work GitHub" }, currentRev(d.engine, ID));
  const opened = await d.engine.open(ID);
  assert.equal(opened.view.name, "Work GitHub");
  assert.equal(opened.view.passkey.rp_id, "github.com");
  assert.equal(opened.view.passkey.cred_id, "c1");
  assert.equal(JSON.stringify(opened.view).includes(SECRET_KEY), false, "the view never has the key");
  const handle = [...d.client.vault.handles.values()][0];
  assert.equal(handle.body.passkey.priv, SECRET_KEY, "the key is still in the core, unchanged, so it still signs");
  assert.equal(handle.body.passkey.prf_seed_uv, SECRET_SEED);
  await opened.close();
  assert.equal(d.engine.list()[0].passkeySite, "github.com", "the list still knows the passkey");
  d.engine.stop();
});

test("remove_passkey_keeps_the_item_and_warns_about_the_site", async () => {
  await withDom(async () => {
    const { root, engine } = await openItem();
    const first = click(find(root, "remove-passkey"));
    await settle();
    // The question names the site and says the site still has the public key; nothing is written before the yes.
    const text = dialogText(root);
    assert.ok(text.includes("passkey.remove_title") && text.includes("passkey.remove_body"));
    assert.ok(text.includes("github.com"));
    assert.deepEqual(engine.calls.filter((c) => c[0] === "update"), []);
    await click(find(root, "dialog-cancel"));
    await first;
    assert.equal(find(root, "dialog"), null);
    assert.deepEqual(engine.calls.filter((c) => c[0] === "update"), [], "cancel changes nothing");

    const second = click(find(root, "remove-passkey"));
    await settle();
    await click(find(root, "dialog-confirm"));
    await second;
    assert.deepEqual(engine.calls.filter((c) => c[0] === "update"), [["update", ID, { remove_passkey: true }]], "only the passkey goes, nothing else is touched");
    assert.deepEqual(engine.expectedRevs, [2], "on the newest revision");
    assert.ok(textOf(find(root, "message")).includes("passkey.removed"));
    assert.ok(engine.calls.every((c) => c[0] !== "remove"), "the item is not deleted");
  });
  // In the engine over the core the item stays, with its name, and only the passkey is gone.
  const model = new Model();
  const client = createFakeClient();
  model.set(ID, { rev: 1, ...client.wireRow(ID, 1, { item_type: "login", name: "Keep me", fields: [], passkey: { rp_id: "github.com", user_name: "ada", cred_id: "c1", user_handle: "u1", priv: SECRET_KEY, created: CREATED } }) });
  const d = await syncDevice({ model, client });
  await d.engine.start();
  await d.engine.update(ID, { remove_passkey: true }, currentRev(d.engine, ID));
  const [entry] = d.engine.list();
  assert.deepEqual([entry.name, entry.passkeySite, entry.hasPasskey], ["Keep me", null, false]);
  const opened = await d.engine.open(ID);
  assert.equal(opened.view.passkey, null);
  await opened.close();
  d.engine.stop();
});

test("an_item_that_cannot_be_changed_has_no_remove_button", async () => {
  await withDom(async () => {
    const { root } = await openItem({ entry: { blocked: true } });
    assert.equal(find(root, "remove-passkey"), null);
    assert.ok(all(root, "item-card").some((c) => c.getAttribute("data-card") === "passkey"), "the passkey is still shown");
  });
});

test("delete_and_restore_from_the_trash_keep_the_passkey_working", async () => {
  // The question before the deletion names the site and says what happens to the passkey here.
  await withDom(async () => {
    const { root, engine } = await openItem();
    const deleting = click(find(root, "delete"));
    await settle();
    const text = dialogText(root);
    assert.ok(text.includes("passkey.delete_body"), "the question for an item with a passkey");
    assert.ok(text.includes("github.com"), "it names the site");
    await click(find(root, "dialog-confirm"));
    await deleting;
    assert.deepEqual(engine.calls.filter((c) => c[0] === "remove"), [["remove", ID]]);
    // An item without a passkey gets the ordinary question.
    const plain = await openItem({ entry: { passkeySite: null, hasPasskey: false }, view: { passkey: null } });
    const asking = click(find(plain.root, "delete"));
    await settle();
    assert.ok(dialogText(plain.root).includes("list.trash_body"));
    assert.ok(!dialogText(plain.root).includes("passkey.delete_body"));
    await click(find(plain.root, "dialog-cancel"));
    await asking;
  });
  // In the engine: deleted, in the trash with its site, restored: the same passkey, key unchanged, and the list knows it again.
  const model = new Model();
  const client = createFakeClient();
  model.set(ID, { rev: 1, ...client.wireRow(ID, 1, { item_type: "login", name: "GitHub passkey", fields: [], passkey: { rp_id: "github.com", user_name: "ada", cred_id: "c1", user_handle: "u1", priv: SECRET_KEY, created: CREATED } }) });
  const d = await syncDevice({ model, client });
  await d.engine.start();
  await d.engine.update(ID, { name: "GitHub passkey" }, currentRev(d.engine, ID)); // revision 2, so a deletion has a version below it
  await d.engine.remove(ID);
  await until(() => d.model.items.get(ID).deleted === true, "the deletion is on the server");
  await until(async () => (await d.engine.trash()).length === 1, "and in the trash");
  const [trashed] = await d.engine.trash();
  assert.equal(trashed.passkeySite, "github.com", "the trash knows which site the passkey is for");
  assert.equal(d.engine.list().length, 0);
  await d.engine.restoreFromTrash(ID);
  await until(() => model.items.get(ID).deleted === false, "the item is back on the server");
  await settleEngine();
  const [entry] = d.engine.list();
  assert.deepEqual([entry.name, entry.passkeySite], ["GitHub passkey", "github.com"]);
  const opened = await d.engine.open(ID);
  assert.equal(opened.view.passkey.rp_id, "github.com");
  const handle = [...d.client.vault.handles.values()][0];
  assert.equal(handle.body.passkey.priv, SECRET_KEY, "the same key, so it works as before");
  assert.equal(handle.body.passkey.cred_id, "c1");
  await opened.close();
  d.engine.stop();
});

test("the_not_registered_note_is_shown_in_the_trash", async () => {
  await withDom(async () => {
    const entries = [
      { id: ID, name: "GitHub passkey", deletedAt: 1_700_000_000_000, passkeySite: "github.com" },
      { id: ID_B, name: "Plain login", deletedAt: 1_699_000_000_000 },
    ];
    const root = await trashView({ engine: fakeConflictEngine({ trash: entries }), t, locale: "en", scope: createWipeScope() });
    const items = all(root, "trash-item");
    const withKey = items.find((n) => n.getAttribute("data-id") === ID);
    const without = items.find((n) => n.getAttribute("data-id") === ID_B);
    const note = find(withKey, "trash-passkey");
    assert.ok(note, "an item with a passkey has the note");
    assert.ok(textOf(note).includes("passkey.trash_note") && textOf(note).includes("github.com"), "it names the site");
    assert.equal(note.getAttribute("role"), "note");
    assert.equal(find(without, "trash-passkey"), null, "an item without one has none");
    // The English text says it plainly.
    const en = JSON.parse(readFileSync(join(web, "src", "locales", "en", "passkey.json"), "utf8"));
    assert.ok(/not registered at \{site\}/.test(en["passkey.trash_note"]));
  });
});

// ------------------------------------------------------------------- the list

const listItem = (n, extra = {}) => ({
  id: String(n).padStart(32, "0"), name: `Item ${n}`, favorite: false, urls: [], username: "", rev: 1, pending: false, damaged: false, quarantined: false,
  missingOnServer: false, blocked: false, blockedReason: null, readOnly: false, type: "login", modified: 1_700_000_000_000, passkeySite: null, hasPasskey: false, ...extra,
});
const mixed = () => [
  listItem(1, { name: "Bank" }),
  listItem(2, { name: "GitHub", passkeySite: "github.com", hasPasskey: true }),
  listItem(3, { name: "Google", passkeySite: "google.com", hasPasskey: true, favorite: true }),
  listItem(4, { name: "Wifi", type: "note" }),
];
const names = (root) => all(root, "item-link").map((link) => textOf(link).replace(/\s+/g, " ").replace("★", "").trim());
const nav = () => ({ query: "", sets: [], set(next) { this.sets.push(next); this.query = next; }, watch: () => () => {} });
const prefs = () => createListPrefs({ getItem: () => null, setItem() {}, removeItem() {} });

test("the_passkeys_filter_lists_items_with_a_passkey", async () => {
  await withDom(async () => {
    const address = nav();
    const root = listView({ engine: fakeEngine({ items: mixed() }), router: { go() {} }, t, nav: address, prefs: prefs() });
    assert.deepEqual(names(root), ["Bank", "GitHub", "Google", "Wifi"]);
    const chip = find(root, "passkeys-chip");
    assert.equal(chip.getAttribute("aria-pressed"), "false");
    assert.equal(find(root, "passkeys-remove").hidden, true);
    // The rows with a passkey have the mark, with the site in its title, in words.
    const marked = all(root, "item").filter((r) => [...walk(r)].some((n) => n.getAttribute?.("data-mark") === "passkey"));
    assert.deepEqual(marked.map((r) => textOf(find(r, "item-link")).replace("★", "").trim()), ["GitHub", "Google"]);
    assert.ok([...walk(marked[0])].some((n) => n.getAttribute?.("data-mark") === "passkey" && n.getAttribute("title").includes("github.com")));

    await click(chip);
    assert.deepEqual(names(root), ["GitHub", "Google"]);
    assert.equal(chip.getAttribute("aria-pressed"), "true");
    assert.equal(find(root, "passkeys-remove").hidden, false);
    assert.deepEqual(address.sets, ["pk=1"], "the filter is in the address");
    // With the favourites as well, only the item that is both.
    await click(find(root, "favorites-chip"));
    assert.deepEqual(names(root), ["Google"]);
    assert.deepEqual(address.sets, ["pk=1", "fav=1&pk=1"]);
    await click(find(root, "passkeys-remove"));
    assert.deepEqual(names(root), ["Google"], "taking the passkeys filter off leaves the favourites");
    assert.equal(chip.getAttribute("aria-pressed"), "false");
  });
});

test("the_passkeys_filter_is_only_there_when_an_item_has_a_passkey", async () => {
  await withDom(async () => {
    const without = listView({ engine: fakeEngine({ items: [listItem(1), listItem(2)] }), router: { go() {} }, t, nav: nav(), prefs: prefs() });
    assert.equal(find(without, "chip-passkeys").hidden, true);
    const withOne = listView({ engine: fakeEngine({ items: mixed() }), router: { go() {} }, t, nav: nav(), prefs: prefs() });
    assert.equal(find(withOne, "chip-passkeys").hidden, false);
    // An address with the filter on and no item with a passkey: the list is empty, and the filter can be taken off.
    const address = nav();
    address.query = "pk=1";
    const empty = listView({ engine: fakeEngine({ items: [listItem(1)] }), router: { go() {} }, t, nav: address, prefs: prefs() });
    assert.deepEqual(names(empty), []);
    assert.equal(find(empty, "chip-passkeys").hidden, false, "it stays while it is on");
    await click(find(empty, "empty-clear-filters"));
    assert.deepEqual(names(empty), ["Item 1"]);
  });
});

test("the_filter_model_reads_and_writes_the_passkey_filter", () => {
  const state = parseListQuery("pk=1&fav=1");
  assert.deepEqual([state.passkey, state.favorite], [true, true]);
  assert.equal(formatListQuery(state), "fav=1&pk=1");
  assert.deepEqual(parseListQuery(formatListQuery(state)), state);
  assert.equal(parseListQuery("pk=2").passkey, false, "only 1 turns it on");
  assert.equal(parseListQuery("").passkey, false);
  assert.equal(defaultState().passkey, false);
  const items = [{ type: "login", passkeySite: "a.example" }, { type: "login", passkeySite: null }, { type: "login" }];
  assert.equal(applyFilters(items, { ...defaultState(), passkey: true }).length, 1);
  assert.equal(applyFilters(items, defaultState()).length, 3);
});

test("deleting_items_with_passkeys_names_their_sites", async () => {
  await withDom(async () => {
    const engine = fakeEngine({ items: mixed() });
    const root = listView({ engine, router: { go() {} }, t, nav: nav(), prefs: prefs() });
    const selectAll = find(root, "select-all");
    selectAll.checked = true;
    await fire(selectAll, "change");
    await click(find(root, "bulk-trash"));
    await settle();
    const text = textOf(find(root, "dialog"));
    assert.ok(text.includes("passkey.delete_many_body"));
    assert.ok(text.includes("github.com") && text.includes("google.com"), "the sites that hold the public keys");
    assert.ok(text.includes('"passkeys":2'));
    await click(find(root, "dialog-cancel"));
    await settle();
    assert.deepEqual(engine.calls.filter((c) => c[0] === "remove"), []);
    // Items without a passkey get the ordinary question.
    const plain = fakeEngine({ items: [listItem(1), listItem(2)] });
    const other = listView({ engine: plain, router: { go() {} }, t, nav: nav(), prefs: prefs() });
    const all2 = find(other, "select-all");
    all2.checked = true;
    await fire(all2, "change");
    await click(find(other, "bulk-trash"));
    await settle();
    assert.ok(textOf(find(other, "dialog")).includes("list.trash_body"));
  });
  const sites = passkeySites([{ passkeySite: "a.example" }, { passkeySite: "a.example" }, { passkeySite: null }, {}, ...["b", "c", "d", "e", "f"].map((s) => ({ passkeySite: `${s}.example` }))]);
  assert.equal(sites.passkeys, 7);
  assert.equal(sites.sites, "a.example, b.example, c.example, d.example, e.example, …");
});

test("texts_exist_in_en_and_nb", () => {
  const dir = (lang) => JSON.parse(readFileSync(join(web, "src", "locales", lang, "passkey.json"), "utf8"));
  const en = dir("en");
  const nb = dir("nb");
  assert.deepEqual(Object.keys(nb).sort(), Object.keys(en).sort());
  const placeholders = (text) => [...text.matchAll(/\{([A-Za-z0-9_]+)\}/g)].map((m) => m[1]).sort();
  for (const key of Object.keys(en)) {
    assert.ok(key.startsWith("passkey."), key);
    assert.deepEqual(placeholders(nb[key]), placeholders(en[key]), key);
    assert.ok(en[key].trim() !== "" && nb[key].trim() !== "", key);
    assert.ok(!/passnøkkel/i.test(nb[key]), `${key}: the word is passkey in Norwegian too`);
  }
  // Every text the views ask for exists, and none is left unused.
  const used = new Set();
  const root = join(web, "src");
  const walkDir = (d) => readdirSync(d, { withFileTypes: true }).flatMap((e) => (e.isDirectory() ? walkDir(join(d, e.name)) : e.name.endsWith(".mjs") ? [join(d, e.name)] : []));
  for (const file of walkDir(root)) for (const m of readFileSync(file, "utf8").matchAll(/["'`](passkey\.[a-z_]+)["'`]/g)) used.add(m[1]);
  for (const key of used) assert.ok(key in en, `${key} is used but has no text`);
  for (const key of Object.keys(en)) assert.ok(used.has(key), `${key} is not used`);
});
