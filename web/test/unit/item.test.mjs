// The item screen: secrets stay out of the page until the user asks, one at a
// time, and an item that the sync engine marks is shown with the mark and
// without the actions it cannot take.
import assert from "node:assert/strict";
import { test } from "node:test";
import { editView } from "../../src/views/edit.mjs";
import { itemView } from "../../src/views/item.mjs";
import { FakeElement, all, click, coded, fakeClient, fakeEngine, find, fire, settle, t, textOf, walk, withDom } from "./vaultHelpers.mjs";

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

// ------------------------------------------------------------------ the new look

/** The cards of the page, by their kind. */
const cardsOf = (root) => all(root, "item-card").concat(all(root, "urls")).map((card) => card.getAttribute("data-card"));

test("the_page_has_a_header_with_a_tile_the_name_the_type_and_the_actions_and_then_the_cards", async () => {
  await withDom(async () => {
    const { root } = await open();
    const head = find(root, "item-head");
    assert.ok(head, "a header");
    const tile = [...head.childNodes].find((n) => n.getAttribute?.("class")?.includes("tile"));
    assert.equal(textOf(tile).trim(), "B", "the tile shows the first letter of the name");
    assert.equal(tile.getAttribute("data-type"), "login");
    assert.equal(tile.getAttribute("aria-hidden"), "true", "the letter is decoration: the name is the heading");
    assert.ok(textOf(find(head, "type")).includes("vault.type.login"));
    assert.ok(find(head, "edit") && find(head, "delete") && find(head, "more"), "Edit, move to trash and the menu are in the header");
    assert.deepEqual(cardsOf(root), ["login", "fields", "notes", "urls"], "sign-in, other fields, notes, addresses");
    assert.ok(textOf(find(root, "back")).includes("vault.item.back"));
  });
});

test("the_sign_in_fields_are_one_card_and_the_other_fields_another", async () => {
  await withDom(async () => {
    const { root } = await open();
    const login = all(root, "item-card").find((c) => c.getAttribute("data-card") === "login");
    const fields = all(root, "item-card").find((c) => c.getAttribute("data-card") === "fields");
    assert.deepEqual(all(login, "field").map((f) => f.getAttribute("data-key")), ["f0", "f1"]);
    assert.deepEqual(all(fields, "field").map((f) => f.getAttribute("data-key")), ["f2"]);
    assert.ok(textOf(login).includes("vault.item.card_login"));
    assert.ok(textOf(fields).includes("vault.item.card_fields"));
  });
  await withDom(async () => {
    // A note with fields and no sign-in: its fields are "Details", not "Custom fields".
    const { root } = await open({ view: { item_type: "note", fields: [{ id: "x", label: "Code", kind: "text", value: "42" }], urls: [], has_notes: false } });
    assert.deepEqual(cardsOf(root), ["fields"]);
    assert.ok(textOf(root).includes("vault.item.card_details"));
    assert.ok(!textOf(root).includes("vault.item.card_login"));
  });
});

test("an_item_with_nothing_but_a_name_has_no_empty_cards", async () => {
  await withDom(async () => {
    const { root } = await open({ view: { fields: [], urls: [], has_notes: false } });
    assert.deepEqual(cardsOf(root), []);
    assert.ok(find(root, "item-head"));
  });
});

test("every_copy_and_reveal_button_names_the_field_it_acts_on", async () => {
  await withDom(async () => {
    const { root } = await open();
    const name = (role, key) => find(root, role, key).getAttribute("aria-label");
    assert.equal(name("copy", "f0"), 'vault.item.copy_label {"label":"User name"}');
    assert.equal(name("copy", "f1"), 'vault.item.copy_label {"label":"Password"}');
    assert.equal(name("reveal", "f1"), 'vault.item.show_label {"label":"Password"}');
    assert.equal(name("reveal", "f2"), 'vault.item.show_label {"label":"PIN"}');
    assert.equal(name("reveal", "notes"), 'vault.item.show_label {"label":"vault.item.notes"}');
    assert.equal(find(root, "reveal", "f0"), null, "a plain value has no reveal button");
    // The name follows the state: showing makes it "Hide Password", hiding makes it "Show Password" again.
    await click(find(root, "reveal", "f1"));
    assert.equal(name("reveal", "f1"), 'vault.item.hide_label {"label":"Password"}');
    await click(find(root, "reveal", "f2"));
    assert.equal(name("reveal", "f1"), 'vault.item.show_label {"label":"Password"}', "the one that was shown goes back");
    assert.equal(name("reveal", "f2"), 'vault.item.hide_label {"label":"PIN"}');
    // Every one of them is a real button, so the keyboard reaches it and Enter or Space works.
    for (const button of [...all(root, "copy"), ...all(root, "reveal")]) assert.equal(button.tagName, "button");
  });
});

test("an_address_has_a_copy_button_and_copying_it_does_not_ask_the_worker", async () => {
  await withDom(async () => {
    const { root, written, client } = await open();
    assert.equal(textOf(find(root, "url")).trim(), "https://bank.example");
    const button = find(root, "copy-url");
    assert.equal(button.getAttribute("aria-label"), 'vault.item.copy_label {"label":"vault.item.address"}');
    await click(button);
    assert.deepEqual(written, ["https://bank.example"]);
    assert.deepEqual(client.calls, [], "an address is not a secret: the worker is not asked");
    assert.ok(textOf(root).includes("vault.item.copied"));
  });
});

test("the_header_shows_a_star_after_the_name_only_for_a_favourite", async () => {
  await withDom(async () => {
    const plain = await open();
    assert.ok(!textOf(find(plain.root, "item-head")).includes("★"));
    const fav = await open({ view: { favorite: true } });
    const h1 = [...walk(find(fav.root, "item-head"))].find((n) => n.tagName === "h1");
    const star = [...walk(h1)].find((n) => n.getAttribute?.("role") === "img");
    assert.equal(star.getAttribute("aria-label"), "vault.item.favorite", "the star has a name for a screen reader");
    assert.ok(textOf(h1).trim().startsWith("Bank"), "the name comes first");
  });
});

test("the_folder_labels_are_hidden_until_the_item_has_some", async () => {
  await withDom(async () => {
    const none = await open();
    assert.equal(find(none.root, "folder-chips").hidden, true, "the hook is there and hidden");
    assert.equal(all(none.root, "folder-chip").length, 0);

    const some = await open({ view: { folders: ["Home", "Finance", "bad\nlabel"] } });
    assert.equal(find(some.root, "folder-chips").hidden, false);
    assert.deepEqual(all(some.root, "folder-chip").map((c) => textOf(c).trim()), ["Finance", "Home"], "sorted, and a label that breaks the rules is dropped");
    assert.equal(find(some.root, "folder-chip-more"), null, "no +N chip for a short list");

    // Past the first twelve, the rest are one "+N" chip that names them.
    const many = Array.from({ length: 15 }, (_, i) => `F${String(i).padStart(2, "0")}`);
    const lots = await open({ view: { folders: many } });
    assert.equal(all(lots.root, "folder-chip").length, 12);
    const more = find(lots.root, "folder-chip-more");
    assert.equal(textOf(more).trim(), "+3");
    assert.equal(more.getAttribute("title"), "F12, F13, F14");
  });
});

test("the_folder_task_can_make_the_chips_and_add_move_to_folder_to_the_menu", async () => {
  await withDom(async () => {
    const moved = [];
    const engine = fakeEngine({ items: [{ ...ENTRY }], views: { [ID]: { ...VIEW, folders: ["Home"] } }, secrets: { [ID]: ["ada", PASSWORD, PIN] } });
    const root = await itemView({
      engine, sync: engine, client: fakeClient(engine), id: ID, t, moveToFolder: (id) => moved.push(id),
      folderChip: (label) => globalThis.document.createTextNode(`[${label}]`),
    });
    assert.ok(textOf(find(root, "folder-chip")).includes("[Home]"), "the folder task's chip is used");
    await click(find(root, "more"));
    await click(find(root, "move"));
    assert.deepEqual(moved, [ID]);
  });
  await withDom(async () => {
    const { root } = await open();
    assert.equal(find(root, "move"), null, "without the hook there is no such entry");
  });
});

test("delete_is_move_to_trash_and_says_what_the_trash_does", async () => {
  await withDom(async () => {
    const { root, engine, moves } = await open();
    assert.ok(textOf(find(root, "delete")).includes("vault.item.trash"));
    const pending = click(find(root, "delete"));
    await settle();
    const dialog = find(root, "dialog");
    const words = textOf(dialog);
    assert.ok(words.includes("list.trash_title_one") && words.includes("list.trash_body") && words.includes("list.trash_confirm"), "the same words as the list's trash question");
    await click(find(dialog, "dialog-confirm"));
    await pending;
    await settle();
    assert.deepEqual(engine.calls.filter((c) => c[0] === "remove"), [["remove", ID]]);
    assert.deepEqual(moves, ["/items"]);
  });
});

test("the_menu_switches_the_favourite_with_a_patch_of_that_key_against_the_newest_revision", async () => {
  await withDom(async () => {
    const { root, engine } = await open();
    const more = find(root, "more");
    assert.equal(more.getAttribute("aria-haspopup"), "menu");
    assert.equal(more.getAttribute("aria-expanded"), "false");
    assert.equal(more.getAttribute("aria-label"), 'vault.item.more {"name":"Bank"}');
    assert.equal(find(root, "more-menu").hidden, true);
    await click(more);
    assert.equal(more.getAttribute("aria-expanded"), "true");
    assert.equal(find(root, "more-menu").hidden, false);
    assert.ok(textOf(find(root, "favorite")).includes("vault.item.favorite_add"));

    // A newer revision came in since the page was drawn: the patch carries that one, so the engine can refuse a stale write.
    engine.items[0] = { ...ENTRY, rev: 5 };
    await click(find(root, "favorite"));
    await settle();
    assert.deepEqual(engine.calls.filter((c) => c[0] === "update"), [["update", ID, { favorite: true }]]);
    assert.deepEqual(engine.expectedRevs, [5]);
    assert.ok(textOf(root).includes("vault.item.favorited"));
    assert.equal(find(root, "more-menu").hidden, true, "the menu closed");
  });
});

test("a_favourite_is_switched_off_with_the_same_patch_and_a_refusal_is_shown", async () => {
  await withDom(async () => {
    const { root, engine } = await open({ view: { favorite: true } });
    await click(find(root, "more"));
    assert.ok(textOf(find(root, "favorite")).includes("vault.item.favorite_remove"));
    engine.failWith = coded("item_changed");
    await click(find(root, "favorite"));
    await settle();
    assert.deepEqual(engine.calls.filter((c) => c[0] === "update"), [["update", ID, { favorite: false }]]);
    assert.ok(textOf(root).includes("vault.error.item_changed"), "the reason is shown and nothing was changed");
  });
});

test("an_item_that_cannot_be_changed_has_no_menu_and_no_edit_or_trash", async () => {
  await withDom(async () => {
    for (const entry of [{ readOnly: true }, { damaged: true }, { blocked: true, blockedReason: "conflict" }, { quarantined: true }, { missingOnServer: true }]) {
      const { root } = await open({ entry, view: entry.readOnly ? { read_only: true } : {} });
      assert.equal(find(root, "more"), null, JSON.stringify(entry));
      assert.equal(find(root, "edit"), null);
      assert.equal(find(root, "delete"), null);
      assert.ok(find(root, "item-head"), "it can still be read");
    }
  });
});

test("the_menu_closes_on_a_press_outside_it_and_the_listener_goes_with_a_lock", async () => {
  await withDom(async () => {
    const listeners = new Set();
    globalThis.document.addEventListener = (type, fn) => type === "pointerdown" && listeners.add(fn);
    globalThis.document.removeEventListener = (type, fn) => type === "pointerdown" && listeners.delete(fn);
    const { createWipeScope } = await import("../../src/views/common.mjs");
    const scope = createWipeScope();
    const engine = fakeEngine({ items: [{ ...ENTRY }], views: { [ID]: { ...VIEW } }, secrets: { [ID]: ["ada", PASSWORD, PIN] } });
    const root = await itemView({ engine, sync: engine, client: fakeClient(engine), id: ID, t, scope });
    assert.equal(listeners.size, 1);
    await click(find(root, "more"));
    assert.equal(find(root, "more-menu").hidden, false);
    // A press on the menu itself leaves it open; a press somewhere else closes it.
    for (const fn of listeners) fn({ target: find(root, "favorite") });
    assert.equal(find(root, "more-menu").hidden, false);
    for (const fn of listeners) fn({ target: { parentNode: null } });
    assert.equal(find(root, "more-menu").hidden, true);

    // A secret that is on the page goes with the lock, and so does the listener.
    await click(find(root, "reveal", "f1"));
    assert.ok(textOf(root).includes(PASSWORD));
    scope.run();
    assert.equal(listeners.size, 0, "nothing of the page is held by the document after a lock");
    assert.ok(!textOf(root).includes(PASSWORD) && !textOf(root).includes("Bank"), "nothing decrypted is left in the page");
    assert.equal(root.childNodes.length, 0);
  });
});

test("the_menu_is_driven_from_the_keyboard", async () => {
  await withDom(async () => {
    const { root } = await open();
    const menu = find(root, "more-menu");
    const focused = [];
    for (const node of walk(root)) if (node.getAttribute) node.focus = () => focused.push(node.getAttribute("data-role"));
    // Down on the button opens the menu and moves into it; Escape in the menu closes it and the focus goes back to the button.
    await fire(find(root, "more"), "keydown", { key: "ArrowDown" });
    assert.equal(menu.hidden, false);
    assert.equal(focused.at(-1), "favorite");
    await fire(menu, "keydown", { key: "Escape", target: find(root, "favorite") });
    assert.equal(menu.hidden, true);
    assert.equal(focused.at(-1), "more");
  });
});

test("after_the_favourite_switch_the_focus_is_on_the_new_menu_button_and_the_page_is_built_once", async () => {
  await withDom(async () => {
    const focused = [];
    const saved = FakeElement.prototype.focus;
    FakeElement.prototype.focus = function focus() {
      focused.push(this.getAttribute("data-role"));
    };
    try {
      const { root, engine } = await open();
      const opens = () => engine.calls.filter((c) => c[0] === "open").length;
      await click(find(root, "more"));
      const oldMore = find(root, "more");
      const before = opens();
      focused.length = 0;
      await click(find(root, "favorite"));
      await settle();
      assert.equal(opens(), before, "nothing is built until the engine says the item changed");
      // The engine says so: the header is built again, and its menu button has the focus.
      engine.items[0] = { ...ENTRY, favorite: true, rev: 3 };
      engine.emit("changed", { ids: [ID] });
      await settle();
      assert.equal(opens(), before + 1, "one rebuild");
      assert.notEqual(find(root, "more"), oldMore, "the header is a new one");
      assert.equal(focused.at(-1), "more");
      // A later rebuild (another device's change) does not take the focus.
      focused.length = 0;
      engine.emit("changed", { ids: [ID] });
      await settle();
      assert.deepEqual(focused, []);
    } finally {
      if (saved === undefined) delete FakeElement.prototype.focus;
      else FakeElement.prototype.focus = saved;
    }
  });
});

test("a_refused_favourite_switch_leaves_the_focus_alone_for_the_next_rebuild", async () => {
  await withDom(async () => {
    const focused = [];
    const saved = FakeElement.prototype.focus;
    FakeElement.prototype.focus = function focus() {
      focused.push(this.getAttribute("data-role"));
    };
    try {
      const { root, engine } = await open();
      await click(find(root, "more"));
      engine.failWith = coded("item_changed");
      await click(find(root, "favorite"));
      await settle();
      focused.length = 0;
      engine.emit("changed", { ids: [ID] });
      await settle();
      assert.deepEqual(focused, []);
    } finally {
      if (saved === undefined) delete FakeElement.prototype.focus;
      else FakeElement.prototype.focus = saved;
    }
  });
});
