// The item list: local search, order, the marks that show how an item stands
// with the server, and that the unlock-method manifest is never an item.
import assert from "node:assert/strict";
import { test } from "node:test";
import { createSyncEngine, MANIFEST_ID } from "../../src/sync/engine.mjs";
import { listView, matches } from "../../src/views/list.mjs";
import { freshStore, scope } from "./idbHelpers.mjs";
import { createFakeApi, createFakeClient, createFakeStore, counterRand, FakeTimers, Model, until } from "./syncHelpers.mjs";
import { all, click, fakeEngine, find, fire, settle, t, textOf, withDom } from "./vaultHelpers.mjs";

const base = {
  favorite: false, urls: [], username: "", rev: 1, pending: false, damaged: false, quarantined: false,
  missingOnServer: false, blocked: false, blockedReason: null, readOnly: false, type: "login",
};
const item = (n, extra = {}) => ({ ...base, id: String(n).repeat(32).slice(0, 32), name: `Item ${n}`, ...extra });

/** The names shown, in order. */
const shownNames = (root) => all(root, "item-link").map((link) => textOf(link).replace(/\s+/g, " ").trim());

test("search_is_local_and_case_insensitive_and_never_sends_the_query", async () => {
  await withDom(async () => {
    const sent = [];
    const saved = { fetch: globalThis.fetch, beacon: globalThis.navigator?.sendBeacon };
    globalThis.fetch = (...args) => {
      sent.push(args);
      throw new Error("the search must not make a request");
    };
    try {
      const engine = fakeEngine({
        items: [
          item(1, { name: "Bank of Norway", urls: ["https://bank.example"], username: "ada" }),
          item(2, { name: "Mail", urls: ["https://MAIL.example/login"], username: "Grace.Hopper" }),
          item(3, { name: "Wiki", urls: [], username: "" }),
        ],
      });
      const moves = [];
      const root = listView({ engine, router: { go: (p) => moves.push(p) }, t });
      const search = find(root, "search");
      assert.deepEqual(shownNames(root), ["Bank of Norway", "Mail", "Wiki"]);

      const query = async (text) => {
        search.value = text;
        await fire(search, "input");
        return shownNames(root);
      };
      assert.deepEqual(await query("BANK"), ["Bank of Norway"], "name, any case");
      assert.deepEqual(await query("mail.EXAMPLE"), ["Mail"], "address, any case");
      assert.deepEqual(await query("GRACE hopper"), ["Mail"], "user name, every word");
      assert.deepEqual(await query("ada norway"), ["Bank of Norway"], "words from two fields");
      assert.deepEqual(await query("nothing like it"), []);
      assert.ok(textOf(find(root, "count")).includes("vault.list.no_match"));
      assert.deepEqual(await query(""), ["Bank of Norway", "Mail", "Wiki"]);

      assert.deepEqual(sent, [], "no request was made");
      assert.deepEqual(moves, [], "the query did not go into the address");
      const hrefs = all(root, "item-link").map((a) => a.getAttribute("href"));
      assert.ok(hrefs.every((href) => /^#\/items\/[0-9a-f]{32}$/.test(href)));
    } finally {
      globalThis.fetch = saved.fetch;
    }
  });
});

test("matching_folds_case_and_compatibility_forms", () => {
  assert.equal(matches({ name: "ÅPNE", urls: [] }, "åpne"), true);
  assert.equal(matches({ name: "ＢＡＮＫ", urls: [] }, "bank"), true);
  assert.equal(matches({ name: "x", urls: ["https://A.test"] }, "a.TEST"), true);
  assert.equal(matches({ name: "x", urls: [] }, "   "), true, "a blank query shows everything");
});

test("favorites_come_first_and_the_engines_order_holds_inside_each_group", async () => {
  await withDom(async () => {
    const engine = fakeEngine({
      items: [item(1, { name: "A" }), item(2, { name: "B", favorite: true }), item(3, { name: "C" }), item(4, { name: "D", favorite: true })],
    });
    const root = listView({ engine, router: { go() {} }, t });
    assert.deepEqual(shownNames(root).map((n) => n.replace("★", "").trim()), ["B", "D", "A", "C"]);
  });
});

test("list_never_shows_the_manifest_row", async () => {
  await withDom(async () => {
    // The second guard: a list that does contain the manifest id still does not show it.
    const engine = fakeEngine({ items: [item(1), { ...item(2), id: MANIFEST_ID, name: "manifest" }] });
    const root = listView({ engine, router: { go() {} }, t });
    assert.deepEqual(shownNames(root), ["Item 1"]);
    assert.ok(!textOf(root).includes("manifest"));
  });

  // And the engine itself, fed a real feed that has the manifest row in it.
  await withDom(async () => {
    const model = new Model();
    const client = createFakeClient();
    const store = await createFakeStore({ db: await freshStore() });
    const api = createFakeApi(model);
    const engine = createSyncEngine({
      api, client: { vault: client.vault }, store, scope: scope(), timers: new FakeTimers(), rand: counterRand(1),
    });
    await engine.start();
    const id = await engine.create({ item_type: "login", name: "Real item" });
    await until(() => model.items.get(id)?.rev === 1, "the item is on the server");
    model.set(MANIFEST_ID, { rev: 1, ...client.wireRow(MANIFEST_ID, 1, { item_type: "login", name: "unlock methods" }) });
    await engine.syncNow();
    const root = listView({ engine, router: { go() {} }, t });
    assert.deepEqual(shownNames(root), ["Real item"]);
    assert.ok(!textOf(root).includes("unlock methods"));
    engine.stop();
  });
});

test("the_index_carries_the_plain_user_name_and_never_a_hidden_value", async () => {
  const model = new Model();
  const client = createFakeClient();
  const store = await createFakeStore({ db: await freshStore() });
  const engine = createSyncEngine({
    api: createFakeApi(model), client: { vault: client.vault }, store, scope: scope(), timers: new FakeTimers(), rand: counterRand(2),
  });
  await engine.start();
  await engine.create({
    item_type: "login",
    name: "Bank",
    fields: [{ id: "username", kind: "text", value: "ada" }, { id: "password", kind: "password", value: "pw-SECRET-1" }],
  });
  const [summary] = engine.list();
  assert.equal(summary.username, "ada");
  assert.ok(!JSON.stringify(summary).includes("pw-SECRET-1"));
  engine.stop();
});

test("every_sync_mark_is_shown_as_words", async () => {
  await withDom(async () => {
    const engine = fakeEngine({
      items: [
        item(1, { pending: true }),
        item(2, { damaged: true }),
        item(3, { quarantined: true }),
        item(4, { missingOnServer: true }),
        item(5, { blocked: true, blockedReason: "conflict" }),
        item(6, { readOnly: true }),
        item(7),
      ],
    });
    const root = listView({ engine, router: { go() {} }, t });
    const rows = all(root, "item");
    const marksOf = (row) => [...row.childNodes.flatMap((c) => [c, ...c.childNodes])].filter((n) => n.getAttribute?.("data-mark")).map((n) => [n.getAttribute("data-mark"), textOf(n).trim()]);
    assert.deepEqual(marksOf(rows[0]), [["pending", "vault.mark.pending"]]);
    assert.deepEqual(marksOf(rows[1]), [["damaged", "vault.mark.damaged"]]);
    assert.deepEqual(marksOf(rows[2]), [["quarantined", "vault.mark.quarantined"]]);
    assert.deepEqual(marksOf(rows[3]), [["missing", "vault.mark.missing"]]);
    assert.deepEqual(marksOf(rows[4]), [["blocked", "vault.mark.blocked"]], "a blocked item is not also shown as waiting");
    assert.deepEqual(marksOf(rows[5]), [["read_only", "vault.mark.read_only"]]);
    assert.deepEqual(marksOf(rows[6]), []);
  });
});

test("the_list_follows_the_engine_and_says_when_it_is_empty", async () => {
  await withDom(async () => {
    const engine = fakeEngine({ items: [] });
    const root = listView({ engine, router: { go() {} }, t });
    assert.ok(textOf(find(root, "count")).includes("vault.list.empty"));
    engine.items = [item(1, { name: "Late" })];
    engine.emit("changed", { ids: [engine.items[0].id] });
    await settle();
    assert.deepEqual(shownNames(root), ["Late"]);
    assert.ok(textOf(find(root, "count")).includes("vault.list.count"));
  });
});

test("the_new_item_button_goes_to_the_new_item_screen", async () => {
  await withDom(async () => {
    const moves = [];
    const root = listView({ engine: fakeEngine({ items: [] }), router: { go: (p) => moves.push(p) }, t });
    await click(find(root, "new-item"));
    assert.deepEqual(moves, ["/items/new"]);
  });
});
