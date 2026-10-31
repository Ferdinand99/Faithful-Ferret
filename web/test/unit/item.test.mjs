// The item screen: secrets stay out of the page until the user asks, one at a
// time, and an item that the sync engine marks is shown with the mark and
// without the actions it cannot take.
import assert from "node:assert/strict";
import { test } from "node:test";
import { editView } from "../../src/views/edit.mjs";
import { itemView } from "../../src/views/item.mjs";
import { all, click, coded, fakeClient, fakeEngine, find, settle, t, textOf, withDom } from "./vaultHelpers.mjs";

const ID = "11".repeat(16);
const PASSWORD = "pw-SECRET-1";
const PIN = "pin-SECRET-2";
const NOTES = "notes-SECRET-3";

const VIEW = Object.freeze({
  item_type: "login",
  name: "Bank",
  fields: [
    { id: "username", label: "User name", kind: "text", value: "ada" },
    { id: "password", label: "Password", kind: "password", value: null },
    { id: "pin", label: "PIN", kind: "hidden", value: null },
  ],
  urls: [{ url: "https://bank.example", matching: "host" }],
  has_totp: false,
  has_notes: true,
  favorite: false,
  read_only: false,
});

const ENTRY = Object.freeze({
  id: ID, name: "Bank", type: "login", favorite: false, urls: ["https://bank.example"], username: "ada", rev: 2,
  pending: false, damaged: false, quarantined: false, missingOnServer: false, blocked: false, blockedReason: null, readOnly: false,
});

/** An item screen over fakes. `entry` and `view` replace parts of the defaults. */
async function open({ entry = {}, view = {}, touch, clipboard, go } = {}) {
  const engine = fakeEngine({
    items: [{ ...ENTRY, ...entry }],
    views: { [ID]: { ...VIEW, ...view } },
    secrets: { [ID]: ["ada", PASSWORD, PIN] },
  });
  const client = fakeClient(engine, { notes: { [ID]: NOTES } });
  const written = [];
  const moves = [];
  const root = await itemView({
    engine,
    sync: engine,
    client,
    id: ID,
    t,
    go: go ?? ((path) => moves.push(path)),
    touch,
    clipboard: clipboard === undefined ? { writeText: async (text) => void written.push(text) } : clipboard,
  });
  return { engine, client, root, written, moves };
}

test("secrets_are_not_in_the_dom_until_revealed", async () => {
  await withDom(async () => {
    const { root, engine } = await open();
    const text = textOf(root);
    for (const secret of [PASSWORD, PIN, NOTES]) assert.ok(!text.includes(secret), "no secret before a reveal");
    assert.ok(text.includes("ada"), "a plain field shows as it is");
    assert.equal(find(root, "value", "f1").childNodes[0].data, "••••••••");
    assert.equal(engine.handles.size, 0, "no item is left open by the screen");

    await click(find(root, "reveal", "f1"));
    assert.ok(textOf(root).includes(PASSWORD));
    assert.ok(!textOf(root).includes(PIN));
    assert.equal(engine.handles.size, 0, "the handle lived for the one call");
  });
});

test("reveal_shows_one_secret_at_a_time", async () => {
  await withDom(async () => {
    const { root, client } = await open();
    await click(find(root, "reveal", "f1"));
    assert.ok(textOf(root).includes(PASSWORD));
    assert.equal(find(root, "reveal", "f1").childNodes[0].data, "vault.item.hide");

    await click(find(root, "reveal", "f2"));
    assert.ok(textOf(root).includes(PIN), "field B shows");
    assert.ok(!textOf(root).includes(PASSWORD), "showing B hides A");
    assert.equal(find(root, "reveal", "f1").childNodes[0].data, "vault.item.show");

    await click(find(root, "reveal", "notes"));
    assert.ok(textOf(root).includes(NOTES));
    assert.ok(!textOf(root).includes(PIN));

    await click(find(root, "reveal", "notes"));
    assert.ok(!textOf(root).includes(NOTES), "the same button hides it again");
    assert.deepEqual(client.calls.map((c) => c[0]), ["reveal_item_field", "reveal_item_field", "reveal_item_notes"]);
  });
});

test("reveal_checks_that_the_field_is_still_the_one_that_was_shown", async () => {
  await withDom(async () => {
    const { root, engine } = await open();
    // The item changed after the screen was built: field 1 is now another field.
    engine.handles.clear();
    const changed = { ...VIEW, fields: [VIEW.fields[0], { id: "other", label: "Other", kind: "password", value: null }, VIEW.fields[2]] };
    const original = engine.open;
    engine.open = (id) => original.call(engine, id).then((o) => ({ ...o, view: changed }));
    await click(find(root, "reveal", "f1"));
    assert.ok(!textOf(root).includes(PASSWORD));
    assert.ok(textOf(root).includes("vault.error.item_changed"));
  });
});

test("an_action_after_the_lock_time_is_not_carried_out", async () => {
  await withDom(async () => {
    const { root, client, written } = await open({ touch: () => false });
    await click(find(root, "reveal", "f1"));
    await click(find(root, "copy", "f1"));
    assert.deepEqual(client.calls, []);
    assert.deepEqual(written, []);
  });
});

test("copy_uses_the_clipboard_api_and_reports_failure", async () => {
  await withDom(async () => {
    const { root, written } = await open();
    await click(find(root, "copy", "f1"));
    assert.deepEqual(written, [PASSWORD]);
    assert.ok(textOf(root).includes("vault.item.copied"));
    assert.ok(!textOf(root).includes(PASSWORD), "copying does not put the value on the page");
    await click(find(root, "copy", "f0"));
    assert.deepEqual(written, [PASSWORD, "ada"], "a plain value is copied as it is");
  });
  await withDom(async () => {
    const { root } = await open({ clipboard: { writeText: async () => { throw new Error("denied"); } } });
    await click(find(root, "copy", "f1"));
    assert.ok(textOf(root).includes("vault.error.clipboard"));
    assert.ok(!textOf(root).includes("vault.item.copied"));
    assert.ok(!textOf(root).includes(PASSWORD));
  });
  await withDom(async () => {
    const { root } = await open({ clipboard: null });
    await click(find(root, "copy", "f1"));
    assert.ok(textOf(root).includes("vault.error.clipboard"), "no clipboard API is a reported failure");
  });
});

test("unsupported_newer_schema_item_is_read_only_with_a_notice", async () => {
  await withDom(async () => {
    const { root, engine } = await open({ entry: { readOnly: true }, view: { read_only: true } });
    assert.ok(find(root, "notice")?.getAttribute("data-notice") === "read_only");
    assert.equal(find(root, "edit"), null);
    assert.equal(find(root, "delete"), null);
    assert.ok(textOf(root).includes("Bank"), "it can still be read");
    // The edit screen refuses as well.
    const edit = await editView({ engine, client: fakeClient(engine), id: ID, t });
    assert.ok(find(edit, "not-editable"));
    assert.equal(find(edit, "save"), null);
  });
});

test("damaged_item_shows_a_notice_and_keeps_the_last_good_version", async () => {
  await withDom(async () => {
    const { root, engine } = await open({ entry: { damaged: true } });
    assert.equal(find(root, "notice").getAttribute("data-notice"), "damaged");
    assert.ok(textOf(root).includes("vault.notice.damaged"));
    assert.ok(textOf(root).includes("Bank") && textOf(root).includes("ada"), "the last good version is shown");
    assert.equal(find(root, "edit"), null);
    assert.equal(find(root, "delete"), null);
    assert.ok(find(root, "reveal", "f1"), "it can still be read");
    const edit = await editView({ engine, client: fakeClient(engine), id: ID, t });
    assert.ok(find(edit, "not-editable"));
  });
});

test("quarantined_item_cannot_be_edited_or_deleted", async () => {
  await withDom(async () => {
    const { root } = await open({ entry: { quarantined: true } });
    assert.equal(find(root, "notice").getAttribute("data-notice"), "quarantined");
    assert.equal(find(root, "edit"), null);
    assert.equal(find(root, "delete"), null);
  });
});

test("a_blocked_item_offers_discard_my_change_through_sync_discard", async () => {
  await withDom(async () => {
    const { root, engine } = await open({ entry: { blocked: true, blockedReason: "conflict" } });
    const notice = find(root, "notice");
    assert.equal(notice.getAttribute("data-notice"), "blocked");
    assert.ok(textOf(notice).includes("sync.error.blocked") && textOf(notice).includes("sync.error.conflict"));
    assert.equal(find(root, "edit"), null, "a blocked item cannot be edited");
    assert.equal(find(root, "delete"), null);
    assert.equal(textOf(find(root, "discard-change")).trim(), "vault.notice.discard_change");

    // The engine shows the server's version after the discard; the screen reads it again.
    engine.items[0] = { ...ENTRY, blocked: false };
    await click(find(root, "discard-change"));
    await settle();
    assert.deepEqual(engine.calls.filter((c) => c[0] === "discard"), [["discard", ID]]);
    assert.equal(find(root, "discard-change"), null);
    assert.ok(find(root, "edit"), "the item can be edited again");
  });
});

test("a_missing_item_is_discarded_only_after_an_explicit_confirmation", async () => {
  await withDom(async () => {
    const { root, engine, moves } = await open({ entry: { missingOnServer: true } });
    assert.equal(find(root, "notice").getAttribute("data-notice"), "missing");
    assert.equal(find(root, "edit"), null);
    assert.equal(find(root, "delete"), null);

    const first = click(find(root, "discard-missing")); // waits for the answer
    await settle();
    const dialog = find(root, "dialog");
    assert.ok(dialog, "a dialog asks first");
    assert.equal(dialog.getAttribute("role"), "alertdialog");
    assert.deepEqual(engine.calls.filter((c) => c[0] === "discardMissing"), [], "nothing is discarded by the first click");

    await click(find(dialog, "dialog-cancel"));
    await first;
    assert.equal(find(root, "dialog"), null);
    assert.deepEqual(engine.calls.filter((c) => c[0] === "discardMissing"), []);

    const second = click(find(root, "discard-missing"));
    await settle();
    await click(find(find(root, "dialog"), "dialog-confirm"));
    await second;
    await settle();
    assert.deepEqual(engine.calls.filter((c) => c[0] === "discardMissing"), [["discardMissing", ID]]);
    assert.deepEqual(moves, ["/items"]);
  });
});

test("delete_asks_first_and_removes_through_the_engine", async () => {
  await withDom(async () => {
    const { root, engine, moves } = await open();
    const first = click(find(root, "delete"));
    await settle();
    assert.ok(find(root, "dialog"));
    await click(find(find(root, "dialog"), "dialog-cancel"));
    await first;
    assert.deepEqual(engine.calls.filter((c) => c[0] === "remove"), []);

    const second = click(find(root, "delete"));
    await settle();
    await click(find(find(root, "dialog"), "dialog-confirm"));
    await second;
    await settle();
    assert.deepEqual(engine.calls.filter((c) => c[0] === "remove"), [["remove", ID]]);
    assert.deepEqual(moves, ["/items"]);
  });
});

test("a_refused_delete_shows_the_reason_and_stays_on_the_item", async () => {
  await withDom(async () => {
    const { root, engine, moves } = await open();
    engine.failWith = coded("blocked", { reason: "conflict" });
    const pending = click(find(root, "delete"));
    await settle();
    await click(find(find(root, "dialog"), "dialog-confirm"));
    await pending;
    await settle();
    assert.ok(textOf(root).includes("sync.error.blocked"));
    assert.deepEqual(moves, []);
  });
});

test("an_item_that_does_not_exist_says_so", async () => {
  await withDom(async () => {
    const engine = fakeEngine({ items: [], views: {} });
    const root = await itemView({ engine, sync: engine, client: fakeClient(engine), id: ID, t });
    assert.ok(find(root, "unavailable"));
    assert.ok(textOf(root).includes("vault.item.not_found"));
    assert.equal(all(root, "reveal").length, 0);
  });
});

test("the_item_is_read_again_when_the_engine_says_it_changed_and_secrets_go_back_to_dots", async () => {
  await withDom(async () => {
    const { root, engine } = await open();
    await click(find(root, "reveal", "f1"));
    assert.ok(textOf(root).includes(PASSWORD));
    engine.emit("changed", { ids: ["22".repeat(16)] });
    await settle();
    assert.ok(textOf(root).includes(PASSWORD), "another item changing does not hide it");
    engine.emit("changed", { ids: [ID] });
    await settle();
    assert.ok(!textOf(root).includes(PASSWORD), "a change to this item hides what was shown");
  });
});
