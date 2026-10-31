// The edit screen: what a draft holds, that a secret is never read back into
// the form, and that saving empties the form.
import assert from "node:assert/strict";
import { test } from "node:test";
import { createWipeScope } from "../../src/views/common.mjs";
import { editView } from "../../src/views/edit.mjs";
import { all, click, coded, fakeClient, fakeEngine, fire, find, settle, submit, t, textOf, withDom } from "./vaultHelpers.mjs";

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
