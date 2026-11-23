// "Previous passwords" on the item screen: the dates come from the view, every value is hidden until its own Show, is
// fetched on that click only, shows one at a time with every other secret of the page, and goes with the same wipes.
import assert from "node:assert/strict";
import { test } from "node:test";
import { createWipeScope } from "../../src/views/common.mjs";
import { itemView } from "../../src/views/item.mjs";
import { MAX_PASSWORD_HISTORY, historyEntries } from "../../src/views/itemModel.mjs";
import { all, click, coded, fakeClient, fakeEngine, find, settle, t, textOf, withDom } from "./vaultHelpers.mjs";

const ID = "11".repeat(16);
const PASSWORD = "pw-SECRET-1";
const OLD_1 = "old-pw-SECRET-4";
const OLD_2 = "old-pw-SECRET-5";
const T1 = Date.UTC(2026, 10, 20, 12, 0);
const T2 = Date.UTC(2026, 9, 2, 8, 30);
const DAY = 86_400_000;

const VIEW = Object.freeze({
  item_type: "login",
  name: "Bank",
  fields: [
    { id: "username", label: "User name", kind: "text", value: "ada" },
    { id: "password", label: "Password", kind: "password", value: null },
  ],
  urls: [{ url: "https://bank.example", matching: "host" }],
  has_totp: false,
  has_notes: false,
  favorite: false,
  read_only: false,
  password_history: [{ until: T1 }, { until: T2 }],
});

const ENTRY = Object.freeze({
  id: ID, name: "Bank", type: "login", favorite: false, urls: ["https://bank.example"], username: "ada", rev: 2,
  pending: false, damaged: false, quarantined: false, missingOnServer: false, blocked: false, blockedReason: null, readOnly: false,
});

/** An item screen over fakes; `view` replaces parts of the view, `history` holds the old values by place. */
async function open({ entry = {}, view = {}, history = [OLD_1, OLD_2], touch, scope, locale = "en" } = {}) {
  const engine = fakeEngine({ items: [{ ...ENTRY, ...entry }], views: { [ID]: { ...VIEW, ...view } }, secrets: { [ID]: ["ada", PASSWORD] } });
  const client = fakeClient(engine, { history: { [ID]: history } });
  const written = [];
  const root = await itemView({
    engine, sync: engine, client, id: ID, t, touch, scope, locale,
    clipboard: { writeText: async (text) => void written.push(text) },
  });
  return { engine, client, root, written };
}

const cardsOf = (root) => all(root, "item-card").map((card) => card.getAttribute("data-card"));
const historyCard = (root) => all(root, "item-card").find((card) => card.getAttribute("data-card") === "history");
const when = (ms) => new Intl.DateTimeFormat("en", { dateStyle: "medium", timeStyle: "short" }).format(new Date(ms));

test("previous_passwords_show_dates_and_reveal_one_value_at_a_time", async () => {
  await withDom(async () => {
    const { root, engine, client, written } = await open();
    assert.deepEqual(cardsOf(root), ["login", "history"], "the card follows the sign-in card");
    const card = historyCard(root);
    assert.ok(textOf(card).includes('vault.item.history_heading {"count":2}'), "the heading has the count");
    assert.deepEqual(all(card, "field").map((f) => f.getAttribute("data-key")), ["h0", "h1"], "newest first");
    // The dates are the ones of the view, in the page's language and the local time zone.
    assert.ok(textOf(find(card, "field", "h0")).includes(when(T1)));
    assert.ok(textOf(find(card, "field", "h1")).includes(when(T2)));
    // No old value is on the page, and the worker was not asked for any to draw it.
    for (const secret of [OLD_1, OLD_2]) assert.ok(!textOf(root).includes(secret), "hidden until Show");
    assert.deepEqual(client.calls, []);
    assert.equal(find(root, "value", "h0").childNodes[0].data, "••••••••");

    await click(find(root, "reveal", "h0"));
    assert.ok(textOf(root).includes(OLD_1));
    assert.ok(!textOf(root).includes(OLD_2), "only the one that was asked for");
    assert.deepEqual(client.calls.map((c) => c[0]), ["reveal_password_history"]);
    assert.equal(client.calls[0][2], 0, "the worker is asked for that entry's place");
    assert.equal(engine.handles.size, 0, "the handle lived for the one call");

    // One at a time, together with every other secret of the page.
    await click(find(root, "reveal", "h1"));
    assert.ok(textOf(root).includes(OLD_2));
    assert.ok(!textOf(root).includes(OLD_1), "showing the next hides the first");
    await click(find(root, "reveal", "f1"));
    assert.ok(textOf(root).includes(PASSWORD));
    assert.ok(!textOf(root).includes(OLD_2), "showing the current password hides it");
    await click(find(root, "reveal", "h0"));
    assert.ok(!textOf(root).includes(PASSWORD), "and the other way round");
    await click(find(root, "reveal", "h0"));
    assert.ok(!textOf(root).includes(OLD_1), "the same button hides it again");

    // Copying hands the value to the clipboard without putting it on the page.
    await click(find(root, "copy", "h1"));
    assert.deepEqual(written, [OLD_2]);
    assert.ok(!textOf(root).includes(OLD_2));
    assert.ok(textOf(root).includes("vault.item.copied"));
  });
});

test("every_previous_password_button_names_the_entry_it_acts_on", async () => {
  await withDom(async () => {
    const { root } = await open();
    const name = (role, key) => find(root, role, key).getAttribute("aria-label");
    const speak = (ms) => JSON.stringify(t("vault.item.history_speak", { date: when(ms) }));
    assert.equal(name("reveal", "h0"), `vault.item.show_label {"label":${speak(T1)}}`);
    assert.equal(name("copy", "h1"), `vault.item.copy_label {"label":${speak(T2)}}`);
    await click(find(root, "reveal", "h0"));
    assert.equal(name("reveal", "h0"), `vault.item.hide_label {"label":${speak(T1)}}`);
    await click(find(root, "reveal", "h1"));
    assert.equal(name("reveal", "h0"), `vault.item.show_label {"label":${speak(T1)}}`, "the one that was shown goes back");
    // Real buttons, so the keyboard reaches them.
    for (const key of ["h0", "h1"]) for (const role of ["reveal", "copy"]) assert.equal(find(root, role, key).tagName, "button");
  });
});

test("previous_passwords_list_at_most_five", async () => {
  await withDom(async () => {
    const six = Array.from({ length: 6 }, (_, i) => ({ until: T1 - i * DAY }));
    const values = six.map((_, i) => `old-pw-SECRET-${i}`);
    const { root, client } = await open({ view: { password_history: six }, history: values });
    assert.equal(MAX_PASSWORD_HISTORY, 5);
    const card = historyCard(root);
    assert.deepEqual(all(card, "field").map((f) => f.getAttribute("data-key")), ["h0", "h1", "h2", "h3", "h4"], "a sixth is never listed");
    assert.ok(textOf(card).includes('vault.item.history_heading {"count":5}'));
    assert.equal(find(root, "reveal", "h5"), null);
    assert.deepEqual(client.calls, []);
    assert.equal(historyEntries({ password_history: six }).length, 5);
  });
});

test("an_item_without_history_shows_no_previous_passwords", async () => {
  for (const password_history of [undefined, [], null, "x", {}]) {
    await withDom(async () => {
      const { root } = await open({ view: { password_history } });
      assert.deepEqual(cardsOf(root), ["login"]);
      assert.ok(!textOf(root).includes("vault.item.history"));
      assert.equal(find(root, "reveal", "h0"), null);
    });
  }
});

test("the_entries_come_from_the_dates_of_the_view_and_a_missing_date_is_unknown_not_dropped", async () => {
  assert.deepEqual(historyEntries({ password_history: [{ until: 5 }, {}, { until: "x" }, null] }), [
    { index: 0, until: 5 }, { index: 1, until: null }, { index: 2, until: null }, { index: 3, until: null },
  ]);
  assert.deepEqual(historyEntries(null), []);
  assert.deepEqual(historyEntries({}), []);
  await withDom(async () => {
    const { root } = await open({ view: { password_history: [{ until: T1 }, {}] } });
    assert.ok(textOf(find(historyCard(root), "field", "h1")).includes("vault.item.history_unknown"));
    await click(find(root, "reveal", "h1"));
    assert.ok(textOf(root).includes(OLD_2), "a password with no date can still be shown");
  });
});

test("a_previous_password_reveal_stops_when_the_item_changed_since_the_page_was_drawn", async () => {
  await withDom(async () => {
    const { root, engine, client } = await open();
    // Another device updated the password again: the entry at place 0 is now another one.
    const original = engine.open;
    engine.open = (id) => original.call(engine, id).then((o) => ({ ...o, view: { ...o.view, password_history: [{ until: T1 + 60_000 }, { until: T1 }] } }));
    await click(find(root, "reveal", "h0"));
    assert.ok(!textOf(root).includes(OLD_1) && !textOf(root).includes(OLD_2));
    assert.ok(textOf(root).includes("vault.error.item_changed"));
    assert.deepEqual(client.calls, [], "the worker is not asked for a value that may be another one");
    assert.equal(engine.handles.size, 0);
    // A history that is gone altogether is the same.
    engine.open = (id) => original.call(engine, id).then((o) => ({ ...o, view: { ...o.view, password_history: [] } }));
    await click(find(root, "reveal", "h1"));
    assert.ok(textOf(root).includes("vault.error.item_changed"));
    assert.deepEqual(client.calls, []);
  });
});

test("an_old_password_goes_with_a_rebuild_a_failed_reveal_and_the_lock", async () => {
  await withDom(async () => {
    const scope = createWipeScope();
    const { root, engine, client } = await open({ scope });
    // A change to the item draws the page again: what was shown is hidden.
    await click(find(root, "reveal", "h0"));
    assert.ok(textOf(root).includes(OLD_1));
    engine.emit("changed", { ids: [ID] });
    await settle();
    assert.ok(!textOf(root).includes(OLD_1), "a rebuild hides it");
    // A refused reveal hides what was shown before it.
    await click(find(root, "reveal", "h1"));
    assert.ok(textOf(root).includes(OLD_2));
    const working = client.vault.reveal_password_history;
    client.vault.reveal_password_history = async () => {
      throw coded("invalid_input");
    };
    await click(find(root, "reveal", "h0"));
    assert.ok(!textOf(root).includes(OLD_2), "a failed reveal leaves nothing on the page");
    // The lock empties the page, the old passwords with it.
    client.vault.reveal_password_history = working;
    await click(find(root, "reveal", "h0"));
    assert.ok(textOf(root).includes(OLD_1));
    scope.run();
    assert.ok(!textOf(root).includes("old-pw"), "nothing decrypted is left in the page");
    assert.equal(root.childNodes.length, 0);
  });
});

test("a_reveal_or_copy_of_a_previous_password_after_the_lock_time_is_not_carried_out", async () => {
  await withDom(async () => {
    const { root, client, written } = await open({ touch: () => false });
    await click(find(root, "reveal", "h0"));
    await click(find(root, "copy", "h0"));
    assert.deepEqual(client.calls, []);
    assert.deepEqual(written, []);
  });
});

test("a_read_only_item_still_shows_its_previous_passwords", async () => {
  await withDom(async () => {
    const { root } = await open({ entry: { readOnly: true }, view: { read_only: true } });
    assert.ok(find(root, "reveal", "h0"), "reading an old password changes nothing");
    assert.equal(find(root, "edit"), null);
  });
});
