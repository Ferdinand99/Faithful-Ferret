// The edit screen: what a draft holds, that a secret is never read back into
// the form, and that saving empties the form.
import assert from "node:assert/strict";
import { test } from "node:test";
import { createWipeScope } from "../../src/views/common.mjs";
import { editView } from "../../src/views/edit.mjs";
import { all, click, coded, fakeClient, fakeEngine, fire, find, settle, submit, t, textOf, walk, withDom } from "./vaultHelpers.mjs";

const ID = "11".repeat(16);
const NEW_ID = "ab".repeat(16);
const PASSWORD = "pw-SECRET-1";
const NOTES = "notes-SECRET-3";

const VIEW = Object.freeze({
  item_type: "login",
  name: "Bank",
  fields: [
    { id: "username", label: "User name", kind: "text", value: "ada" },
    { id: "password", label: "Password", kind: "password", value: null },
    { id: "pin", label: "PIN", kind: "hidden", value: null },
  ],
  urls: [{ url: "https://bank.example", matching: "domain" }, { url: "https://second.example", matching: "host" }],
  has_totp: false,
  has_notes: true,
  favorite: false,
  read_only: false,
});

const ENTRY = Object.freeze({
  id: ID, name: "Bank", type: "login", favorite: false, urls: [], username: "ada", rev: 1,
  pending: false, damaged: false, quarantined: false, missingOnServer: false, blocked: false, blockedReason: null, readOnly: false,
});

const FORM_ROLES = ["name", "username", "password", "url", "notes"];

async function edit({ id = ID, view = {}, entry = {}, touch, scope } = {}) {
  const engine = fakeEngine({ items: [{ ...ENTRY, ...entry }], views: { [ID]: { ...VIEW, ...view } }, secrets: { [ID]: ["ada", PASSWORD, "4242"] } });
  const client = fakeClient(engine, { notes: { [ID]: NOTES } });
  const moves = [];
  const root = await editView({ engine, client, id, t, go: (path) => moves.push(path), touch, scope });
  return { engine, client, root, moves };
}

const type = (root, role, value) => {
  find(root, role).value = value;
};

test("a_new_login_is_a_draft_in_the_cores_own_key_names", async () => {
  await withDom(async () => {
    const { root, engine, moves } = await edit({ id: null });
    type(root, "name", " Bank ");
    type(root, "username", "ada");
    type(root, "password", PASSWORD);
    type(root, "url", "https://bank.example");
    find(root, "favorite").checked = true;
    await submit(find(root, "edit-form"));
    assert.deepEqual(engine.calls, [["create", {
      item_type: "login",
      name: "Bank",
      favorite: true,
      fields: [
        { id: "username", label: "vault.edit.username", kind: "text", value: "ada" },
        { id: "password", label: "vault.edit.password", kind: "password", value: PASSWORD },
      ],
      urls: [{ url: "https://bank.example", matching: "host" }],
    }]]);
    assert.deepEqual(moves, [`/items/${NEW_ID}`]);
  });
});

test("a_new_note_has_no_login_fields", async () => {
  await withDom(async () => {
    const { root, engine } = await edit({ id: null });
    find(root, "type").value = "note";
    await fire(find(root, "type"), "change");
    assert.equal(find(root, "login-fields").hidden, true);
    type(root, "name", "Wifi");
    type(root, "username", "left over");
    type(root, "notes", "the code");
    await submit(find(root, "edit-form"));
    assert.deepEqual(engine.calls[0][1], { item_type: "note", name: "Wifi", favorite: false, notes: "the code" });
  });
});

test("edit_save_wipes_form_state", async () => {
  await withDom(async () => {
    const { root, engine, moves } = await edit({ id: null });
    type(root, "name", "Bank");
    type(root, "username", "ada");
    type(root, "password", PASSWORD);
    type(root, "url", "https://bank.example");
    type(root, "notes", NOTES);
    find(root, "favorite").checked = true;
    await submit(find(root, "edit-form"));
    assert.equal(engine.calls.length, 1);
    assert.deepEqual(moves, [`/items/${NEW_ID}`]);
    for (const role of FORM_ROLES) assert.equal(find(root, role).value, "", `${role} is empty after the save`);
    assert.equal(find(root, "favorite").checked, false);
    assert.ok(!textOf(root).includes(PASSWORD));
  });
});

test("an_edit_that_leaves_the_password_empty_names_the_field_by_id_only", async () => {
  await withDom(async () => {
    const { root, engine, client } = await edit();
    assert.equal(find(root, "name").value, "Bank");
    assert.equal(find(root, "username").value, "ada");
    assert.equal(find(root, "password").value, "", "the password is never read back into the form");
    assert.equal(find(root, "url").value, "https://bank.example");
    assert.deepEqual(client.calls, [], "no secret is revealed to open the form");
    assert.equal(find(root, "notes"), null, "the notes are not in the form until asked for");

    type(root, "name", "Bank 2");
    await submit(find(root, "edit-form"));
    assert.deepEqual(engine.calls.at(-1), ["update", ID, {
      name: "Bank 2",
      favorite: false,
      fields: [{ id: "username" }, { id: "password" }, { id: "pin" }],
      urls: [{ url: "https://bank.example", matching: "domain" }, { url: "https://second.example", matching: "host" }],
    }]);
  });
});

test("a_typed_password_or_user_name_replaces_only_that_field", async () => {
  await withDom(async () => {
    const { root, engine } = await edit();
    type(root, "password", "pw-NEW-9");
    type(root, "username", "grace");
    type(root, "url", "");
    await submit(find(root, "edit-form"));
    const [, , draft] = engine.calls.at(-1);
    assert.deepEqual(draft.fields, [{ id: "username", value: "grace" }, { id: "password", value: "pw-NEW-9" }, { id: "pin" }]);
    assert.deepEqual(draft.urls, [{ url: "https://second.example", matching: "host" }], "the first address is gone, the rest stay");
  });
});

test("notes_are_read_into_the_form_only_when_asked_for", async () => {
  await withDom(async () => {
    const { root, engine, client } = await edit();
    assert.ok(!textOf(root).includes(NOTES));
    // Saved without opening the notes: the draft does not mention them.
    await submit(find(root, "edit-form"));
    assert.ok(!("notes" in engine.calls.at(-1)[2]) && !("remove_notes" in engine.calls.at(-1)[2]));
    assert.deepEqual(client.calls, []);
  });
  await withDom(async () => {
    const { root, engine, client } = await edit();
    await click(find(root, "load-notes"));
    assert.deepEqual(client.calls.map((c) => c[0]), ["reveal_item_notes"]);
    assert.equal(engine.handles.size, 0, "the handle was closed");
    assert.equal(find(root, "notes").value, NOTES);
    type(root, "notes", "changed notes");
    await submit(find(root, "edit-form"));
    assert.equal(engine.calls.at(-1)[2].notes, "changed notes");
  });
  await withDom(async () => {
    const { root, engine } = await edit();
    await click(find(root, "load-notes"));
    type(root, "notes", "");
    await submit(find(root, "edit-form"));
    assert.equal(engine.calls.at(-1)[2].remove_notes, true, "emptying the notes removes them");
    assert.ok(!("notes" in engine.calls.at(-1)[2]));
  });
});

test("a_name_is_required_and_nothing_is_sent_without_one", async () => {
  await withDom(async () => {
    const { root, engine } = await edit({ id: null });
    await submit(find(root, "edit-form"));
    assert.deepEqual(engine.calls, []);
    assert.equal(find(root, "error").hidden, false);
    assert.ok(textOf(root).includes("vault.error.name_required"));
  });
});

test("a_refused_save_keeps_the_form_for_another_try_and_says_why", async () => {
  await withDom(async () => {
    const { root, engine, moves } = await edit({ id: null });
    engine.failWith = coded("quota_exceeded");
    type(root, "name", "Bank");
    type(root, "password", PASSWORD);
    await submit(find(root, "edit-form"));
    assert.ok(textOf(find(root, "error")).includes("sync.error.quota_exceeded"));
    assert.equal(find(root, "password").value, PASSWORD, "what was typed stays so the user can retry");
    assert.equal(find(root, "save").disabled, false);
    assert.deepEqual(moves, []);
  });
});

test("the_lock_empties_the_form", async () => {
  await withDom(async () => {
    const scope = createWipeScope();
    const { root } = await edit({ id: null, scope });
    type(root, "name", "Bank");
    type(root, "password", PASSWORD);
    scope.run();
    assert.equal(find(root, "password"), null, "the form is gone");
    assert.ok(!textOf(root).includes(PASSWORD));
  });
});

test("an_action_after_the_lock_time_does_not_save", async () => {
  await withDom(async () => {
    const { root, engine } = await edit({ id: null, touch: () => false });
    type(root, "name", "Bank");
    await submit(find(root, "edit-form"));
    assert.deepEqual(engine.calls, []);
    assert.equal(all(root, "save").length, 1);
    await settle();
  });
});

test("a_save_after_another_devices_change_arrived_is_refused_and_nothing_is_written", async () => {
  await withDom(async () => {
    const { root, engine, moves } = await edit();
    type(root, "name", "My edit");
    // The feed delivers a newer version of the item while the form is open.
    engine.items[0] = { ...engine.items[0], rev: 2, name: "Changed elsewhere" };
    await submit(find(root, "edit-form"));
    assert.deepEqual(engine.calls.filter((c) => c[0] !== "open"), [], "nothing was sent to the engine");
    assert.equal(find(root, "error").hidden, false);
    assert.ok(textOf(find(root, "error")).includes("vault.error.item_changed"));
    assert.equal(find(root, "name").value, "My edit", "what was typed stays");
    assert.ok(!find(root, "save").disabled, "the form can be used again");
    assert.deepEqual(moves, []);
  });
});

test("a_save_names_the_revision_the_form_was_built_from", async () => {
  await withDom(async () => {
    const { root, engine } = await edit();
    await submit(find(root, "edit-form"));
    assert.deepEqual(engine.expectedRevs, [1], "the engine is told the base revision as well");
  });
});

test("an_item_that_vanished_while_the_form_was_open_is_not_saved", async () => {
  await withDom(async () => {
    const { root, engine } = await edit();
    engine.items.length = 0;
    await submit(find(root, "edit-form"));
    assert.deepEqual(engine.calls.filter((c) => c[0] !== "open"), []);
    assert.ok(textOf(find(root, "error")).includes("vault.error.item_changed"));
  });
});

test("an_item_without_a_summary_when_the_form_opened_is_not_saved_later", async () => {
  await withDom(async () => {
    // The engine had no summary of the item when the form opened (so there is no base revision).
    const engine = fakeEngine({ items: [], views: { [ID]: { ...VIEW } } });
    const root = await editView({ engine, client: fakeClient(engine), id: ID, t });
    engine.items.push({ ...ENTRY, rev: 5 }); // the item shows up before Save
    type(root, "name", "x");
    await submit(find(root, "edit-form"));
    assert.deepEqual(engine.calls.filter((c) => c[0] !== "open"), [], "nothing is sent without a base revision");
    assert.ok(textOf(find(root, "error")).includes("vault.error.item_changed"));
  });
});

test("the_form_tells_whether_it_holds_edits_that_are_not_saved", async () => {
  await withDom(async () => {
    const forms = [];
    const tracker = { trackUnsaved: (form) => (forms.push(form), () => void forms.splice(forms.indexOf(form), 1)) };
    const engine = fakeEngine({ items: [{ ...ENTRY }], views: { [ID]: { ...VIEW } }, secrets: { [ID]: ["ada", PASSWORD, "4242"] } });
    const client = fakeClient(engine, { notes: { [ID]: NOTES } });
    const root = await editView({ engine, client, id: ID, t, go() {}, tracker });
    const [form] = forms;
    assert.equal(form.key, `edit:${ID}`);
    assert.equal(form.dirty(), false, "nothing typed");
    type(root, "name", "Bank 2");
    assert.equal(form.dirty(), true);
    type(root, "name", "Bank");
    assert.equal(form.dirty(), false, "back to what it started with");
    type(root, "password", PASSWORD);
    assert.equal(form.dirty(), true, "a typed password is an edit");
    type(root, "password", "");
    find(root, "favorite").checked = true;
    assert.equal(form.dirty(), true);
    find(root, "favorite").checked = false;
    // Notes of an item that has some count once they were typed into.
    await click(find(root, "load-notes"));
    assert.equal(form.dirty(), false, "notes that were only read in are no edit");
    for (const [kind, fn] of find(root, "notes").listeners) if (kind === "input") fn({});
    assert.equal(form.dirty(), true);
    // A frozen form is read-only and sends nothing.
    form.freeze();
    assert.equal(find(root, "name").readOnly, true);
    await submit(find(root, "edit-form"));
    assert.deepEqual(engine.calls.filter(([kind]) => kind === "update"), []);
    // A lock wipes it, and then it holds nothing to lose.
    const wiped = [];
    form.thaw({ engine, scope: { add: (fn) => (wiped.push(fn), () => {}) } });
    assert.equal(find(root, "name").readOnly, false);
    wiped[0]();
    assert.equal(form.dirty(), false);
    assert.equal(forms.length, 0, "it left the list");
    assert.equal(find(root, "name"), null);
  });
});

test("a_restore_that_became_a_copy_moves_the_open_form_to_the_new_id", async () => {
  await withDom(async () => {
    const COPY = "cd".repeat(16);
    const engine = fakeEngine({ items: [{ ...ENTRY }], views: { [ID]: { ...VIEW } }, secrets: { [ID]: ["ada", PASSWORD, "4242"] } });
    const client = fakeClient(engine, { notes: { [ID]: NOTES } });
    const moves = [];
    const root = await editView({ engine, client, id: ID, t, go: (path) => moves.push(path) });
    type(root, "name", "Typed after the restore");
    engine.items = [{ ...ENTRY, id: COPY, rev: 1 }];
    engine.emit("copied", { from: "ee".repeat(16), to: COPY }); // another item: ignored
    assert.equal(find(root, "cancel").getAttribute("href"), `#/items/${ID}`);
    engine.emit("copied", { from: ID, to: COPY });
    assert.equal(find(root, "name").value, "Typed after the restore", "what was typed stays");
    assert.equal(find(root, "cancel").getAttribute("href"), `#/items/${COPY}`);
    await submit(find(root, "edit-form"));
    assert.deepEqual(engine.calls.filter(([kind]) => kind === "update").map(([, id]) => id), [COPY], "it is saved to the copy");
    assert.deepEqual(engine.expectedRevs, [1]);
  });
});

test("a_form_that_moved_to_a_copy_still_answers_to_the_key_of_the_old_item", async () => {
  await withDom(async () => {
    const COPY = "cd".repeat(16);
    const forms = [];
    const tracker = { trackUnsaved: (form) => (forms.push(form), () => {}) };
    const engine = fakeEngine({ items: [{ ...ENTRY }], views: { [ID]: { ...VIEW } }, secrets: { [ID]: ["ada", PASSWORD, "4242"] } });
    const client = fakeClient(engine, { notes: { [ID]: NOTES } });
    await editView({ engine, client, id: ID, t, go() {}, tracker });
    engine.items = [{ ...ENTRY, id: COPY, rev: 1 }];
    engine.emit("copied", { from: ID, to: COPY });
    assert.equal(forms[0].key, `edit:${COPY}`);
    assert.deepEqual(forms[0].keys, [`edit:${ID}`, `edit:${COPY}`]);
  });
});

// ------------------------------------------------------------------ the new look

test("the_form_is_three_cards_details_sign_in_and_notes_with_the_actions_below", async () => {
  await withDom(async () => {
    const { root } = await edit();
    const form = find(root, "edit-form");
    const cards = [...form.childNodes].filter((n) => n.getAttribute?.("class")?.includes("item-section")).map((n) => n.getAttribute("data-role"));
    assert.deepEqual(cards, ["details-card", "login-fields", "notes-slot"]);
    assert.ok(textOf(find(root, "details-card")).includes("vault.edit.card_details"));
    assert.ok(textOf(find(root, "login-fields")).includes("vault.item.card_login"));
    // The name and the favourite are in the first card, the sign-in fields in the second.
    assert.ok(find(find(root, "details-card"), "name") && find(find(root, "details-card"), "favorite"));
    assert.ok(["username", "password", "url"].every((role) => find(find(root, "login-fields"), role)));
    // The save and cancel buttons come after the cards.
    const order = [...form.childNodes].map((n) => n.getAttribute?.("data-role") ?? n.getAttribute?.("class") ?? "");
    assert.ok(order.indexOf("notes-slot") < order.findIndex((c) => c.includes("actions")));
    assert.ok(find(root, "save") && find(root, "cancel"));
  });
});

/** An edit form over an engine whose vault has other items in folders too. */
async function editWithFolders({ id = ID, folders = ["Work", "Bank"], others = [["22".repeat(16), ["Home", "work"]]] } = {}) {
  const items = [{ ...ENTRY, folders }, ...others.map(([otherId, list]) => ({ ...ENTRY, id: otherId, name: "Other", folders: list }))];
  const engine = fakeEngine({ items, views: { [ID]: { ...VIEW, folders } }, secrets: { [ID]: ["ada", PASSWORD, "4242"] } });
  const client = fakeClient(engine, { notes: { [ID]: NOTES } });
  const moves = [];
  const root = await editView({ engine, client, id, t, go: (path) => moves.push(path) });
  return { engine, root, moves };
}

const chips = (root) => all(root, "folder-picked-chip").map((chip) => textOf(chip).trim());
const offers = (root) => all(root, "folder-offer").map((offer) => textOf(offer).trim());

test("the_folder_picker_is_in_the_first_card_with_the_folders_of_the_item_and_of_the_vault", async () => {
  await withDom(async () => {
    const { root } = await editWithFolders();
    const slot = find(find(root, "details-card"), "folder-slot");
    assert.ok(slot && slot.hidden !== true, "the picker is shown: a folder is made by putting an item in it");
    assert.deepEqual(chips(root), ["Bank", "Work"], "the item's folders, in display order");
    // The other folders of the vault are offered; one that differs only in case from a chosen one is not.
    assert.deepEqual(offers(root), ["Home"]);
  });
  await withDom(async () => {
    const { root } = await edit({ id: null });
    assert.ok(find(find(root, "details-card"), "folder-picker"), "a new item has the picker too");
    assert.deepEqual(chips(find(root, "details-card")), []);
    assert.ok(find(find(root, "details-card"), "type"), "a new item chooses its type in the first card");
  });
});

test("a_save_that_did_not_touch_the_folders_sends_no_folders_so_the_item_keeps_them", async () => {
  await withDom(async () => {
    const { root, engine } = await editWithFolders();
    type(root, "name", "Bank 2");
    await submit(find(root, "edit-form"));
    const [[kind, , draft]] = engine.calls.filter((call) => call[0] === "update");
    assert.equal(kind, "update");
    assert.equal("folders" in draft, false, "a draft without folders keeps every folder of the item, also any this screen does not show");
  });
});

test("a_folder_is_added_by_typing_or_picking_and_removed_by_its_cross_and_the_draft_holds_the_whole_list", async () => {
  await withDom(async () => {
    const { root, engine } = await editWithFolders();
    // Remove "Work", pick "Home", type a new one and press Enter (which never sends the form).
    await click(all(root, "folder-remove").find((b) => b.getAttribute("data-folder") === "Work"));
    await click(all(root, "folder-offer").find((b) => b.getAttribute("data-folder") === "Home"));
    find(root, "folder-input").value = "  Taxes 2026 ";
    const enter = await fire(find(root, "folder-input"), "keydown", { key: "Enter" });
    assert.equal(enter.prevented, true);
    assert.deepEqual(engine.calls.filter((call) => call[0] === "update"), [], "Enter adds the name and saves nothing");
    assert.deepEqual(chips(root), ["Bank", "Home", "Taxes 2026"]);
    await submit(find(root, "edit-form"));
    const [[, , draft]] = engine.calls.filter((call) => call[0] === "update");
    assert.deepEqual(draft.folders, ["Bank", "Home", "Taxes 2026"], "kept names first in the item's order, then the new ones, trimmed");
  });
});

test("a_folder_that_exists_in_another_case_is_taken_in_the_spelling_the_vault_shows", async () => {
  await withDom(async () => {
    const { root, engine } = await editWithFolders({ folders: [], others: [["22".repeat(16), ["Home"]], ["33".repeat(16), ["Home"]]] });
    find(root, "folder-input").value = "HOME";
    await click(find(root, "folder-add"));
    assert.deepEqual(chips(root), ["Home"]);
    await submit(find(root, "edit-form"));
    assert.deepEqual(engine.calls.find((call) => call[0] === "update")[2].folders, ["Home"]);
  });
});

test("a_name_that_breaks_a_rule_is_refused_with_the_text_of_its_code_and_nothing_is_saved", async () => {
  await withDom(async () => {
    const { root, engine } = await editWithFolders({ folders: ["Bank"] });
    const tryName = async (name) => {
      find(root, "folder-input").value = name;
      await click(find(root, "folder-add"));
      const box = find(root, "folder-error");
      return box.hidden ? null : textOf(box).trim();
    };
    assert.equal(await tryName("x".repeat(65)), "folders.error.folder_too_long");
    assert.equal(await tryName(`a${String.fromCharCode(0x202e)}b`), "folders.error.folder_bad_character");
    assert.equal(await tryName(`zero${String.fromCharCode(0x200b)}width`), "folders.error.folder_bad_character");
    assert.equal(await tryName("   "), "folders.error.folder_empty");
    assert.equal(await tryName("BANK"), "folders.error.folder_duplicate");
    assert.equal(await tryName("x".repeat(64)), null, "64 characters is the limit");
    assert.equal(await tryName(`fam${String.fromCharCode(0x200d)}ily`), null, "a zero width joiner is allowed");
    // A name typed and not added is added when the form is saved; one the rules refuse stops the save.
    find(root, "folder-input").value = "a".repeat(70);
    await submit(find(root, "edit-form"));
    assert.deepEqual(engine.calls.filter((call) => call[0] === "update"), []);
    assert.equal(textOf(find(root, "folder-error")).trim(), "folders.error.folder_too_long");
  });
});

test("the_twenty_first_folder_is_refused_and_the_cores_own_refusal_is_shown_by_its_code", async () => {
  await withDom(async () => {
    const twenty = Array.from({ length: 20 }, (_, i) => `F${i}`);
    const { root, engine } = await editWithFolders({ folders: twenty, others: [] });
    find(root, "folder-input").value = "One more";
    await click(find(root, "folder-add"));
    assert.ok(textOf(find(root, "folder-error")).trim().startsWith("folders.error.folder_too_many"));
    // The core has the last word: its code is shown under the picker.
    await click(all(root, "folder-remove")[0]);
    engine.failWith = coded("folder_duplicate");
    await submit(find(root, "edit-form"));
    assert.equal(textOf(find(root, "folder-error")).trim(), "folders.error.folder_duplicate");
    assert.equal(find(root, "error").hidden, false);
  });
});

test("the_picker_counts_as_an_edit_and_a_lock_wipes_it", async () => {
  await withDom(async () => {
    const scope = createWipeScope();
    const engine = fakeEngine({ items: [{ ...ENTRY, folders: ["Bank"] }], views: { [ID]: { ...VIEW, folders: ["Bank"] } } });
    const forms = [];
    const root = await editView({ engine, client: fakeClient(engine), id: ID, t, scope, tracker: { trackUnsaved: (form) => (forms.push(form), () => {}) } });
    const [form] = forms;
    assert.equal(form.dirty(), false);
    await click(find(root, "folder-remove"));
    assert.equal(form.dirty(), true, "taking the item out of a folder is an edit that is not saved");
    scope.run();
    assert.equal(textOf(root).includes("Bank"), false, "no folder name stays on the page after a lock");
  });
});

test("every_input_still_has_its_label_and_the_save_still_sends_the_same_draft", async () => {
  await withDom(async () => {
    const { root, engine } = await edit();
    // Each input is named by a label that points at it.
    const inputs = [...walk(root)].filter((n) => ["input", "textarea", "select"].includes(n.tagName) && n.getAttribute("type") !== "checkbox");
    const labelled = new Set([...walk(root)].filter((n) => n.tagName === "label").map((n) => n.getAttribute("for")));
    for (const input of inputs) assert.ok(labelled.has(input.getAttribute("id")), `label for ${input.getAttribute("data-role")}`);
    type(root, "name", "Bank 2");
    await submit(find(root, "edit-form"));
    const [kind, , draft] = engine.calls.find((c) => c[0] === "update");
    assert.equal(kind, "update");
    assert.equal(draft.name, "Bank 2");
    assert.equal(draft.favorite, false);
  });
});

test("editing_the_password_in_the_web_vault_keeps_the_old_one", async () => {
  // A new password on an existing item asks the core to move the old one into the item's previous passwords; the form
  // never holds, reads or sends an old value (the draft has no key for one).
  await withDom(async () => {
    const { root, engine, client } = await edit();
    type(root, "password", "pw-NEW-9");
    await submit(find(root, "edit-form"));
    const [kind, id, draft] = engine.calls.at(-1);
    assert.equal(kind, "update");
    assert.equal(id, ID);
    assert.equal(draft.keep_password_history, true);
    assert.deepEqual(draft.fields, [{ id: "username" }, { id: "password", value: "pw-NEW-9" }, { id: "pin" }]);
    assert.deepEqual(client.calls, [], "no old value was revealed to the form");
    assert.ok(!JSON.stringify(draft).includes(PASSWORD), "the draft carries no old value");
  });
  // An edit that leaves the password alone asks for nothing; a new item has no history to keep.
  await withDom(async () => {
    const { root, engine } = await edit();
    type(root, "name", "Bank 2");
    await submit(find(root, "edit-form"));
    assert.ok(!("keep_password_history" in engine.calls.at(-1)[2]));
  });
  await withDom(async () => {
    const { root, engine } = await edit({ id: null });
    type(root, "name", "Bank");
    type(root, "password", "pw-NEW-9");
    await submit(find(root, "edit-form"));
    assert.ok(!("keep_password_history" in engine.calls.at(-1)[1]));
  });
  // The form says what happens to the old password.
  await withDom(async () => {
    const { root } = await edit();
    assert.ok(textOf(find(root, "password").parentNode ?? root).includes("vault.edit.password_history"));
  });
});
