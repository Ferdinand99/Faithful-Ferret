// No silent loss of folders: every path in the web vault that writes an item starts from the item's own body and sends
// `folders` only when the user changed them, so the labels (and every key a client does not know) stay. These run the
// real sync engine over a fake server and a fake core that keeps a body as the core does (a draft is applied to the open
// body; `folders` left out keeps them, a list replaces them). The core's own tests prove the same of the real binding.
import assert from "node:assert/strict";
import { test } from "node:test";
import { b64u, hex16 } from "../../src/b64.mjs";
import { deleteFolder, renameFolder } from "../../src/views/folderActions.mjs";
import { editView } from "../../src/views/edit.mjs";
import { favouriteDraft } from "../../src/views/itemModel.mjs";
import { createFakeClient, currentRev, Model, settle, syncDevice, until } from "./syncHelpers.mjs";
import { find, submit, t, withDom } from "./vaultHelpers.mjs";

const ID_A = "11".repeat(16);
const ID_B = "22".repeat(16);
const ID_C = "33".repeat(16);

/** A key no version of the web vault knows: it stands for what a newer client may write. */
const FUTURE = { zz_future: { kept: true } };

const body = (name, folders, extra = {}) => ({
  item_type: "login", name, fields: [{ id: "username", label: "User", kind: "text", value: `${name}-user` }], ...(folders ? { folders } : {}), ...FUTURE, ...extra,
});

const setRow = (model, client, id, rev, content) => model.set(id, { rev, ...client.wireRow(id, rev, content) });

/** The whole body of the server's row of an item, read with the fake core (what the next device would get). */
async function serverBody(d, id) {
  const row = d.model.items.get(id);
  const handle = await d.client.vault.open_item(hex16.decode(id), row.rev, b64u.decode(row.blob), b64u.decode(row.tag));
  try {
    return structuredClone(d.client.vault.handles.get(handle).body);
  } finally {
    await d.client.vault.close_item(handle);
  }
}

/** A device over a server with three items: A in Work and Bank, B in work (another case), C in no folder. */
async function world() {
  const model = new Model();
  const client = createFakeClient();
  setRow(model, client, ID_A, 1, body("Alpha", ["Work", "Bank"]));
  setRow(model, client, ID_B, 1, body("Beta", ["work"]));
  setRow(model, client, ID_C, 1, body("Gamma", null));
  const d = await syncDevice({ model, client });
  await d.engine.start();
  await until(() => d.engine.list().length === 3, "the three items");
  return d;
}

const sentRevs = (d) => [ID_A, ID_B, ID_C].map((id) => d.model.items.get(id).rev);

test("the_summary_of_an_item_carries_its_folders_as_the_core_shows_them", async () => {
  const d = await world();
  const byId = Object.fromEntries(d.engine.list().map((item) => [item.id, item.folders]));
  assert.deepEqual(byId, { [ID_A]: ["Work", "Bank"], [ID_B]: ["work"], [ID_C]: [] });
  // A copy: changing the list a screen got does not change the engine's.
  d.engine.list().find((item) => item.id === ID_A).folders.push("x");
  assert.deepEqual(d.engine.list().find((item) => item.id === ID_A).folders, ["Work", "Bank"]);
  d.engine.stop();
});

test("an_edit_in_the_form_that_does_not_touch_the_folders_keeps_them_and_every_unknown_key", async () => {
  const d = await world();
  await withDom(async () => {
    const root = await editView({ engine: d.engine, client: { vault: d.client.vault }, id: ID_A, t });
    find(root, "name").value = "Alpha renamed";
    await submit(find(root, "edit-form"));
  });
  await until(() => d.model.items.get(ID_A).rev === 2, "the edit is on the server");
  const after = await serverBody(d, ID_A);
  assert.equal(after.name, "Alpha renamed");
  assert.deepEqual(after.folders, ["Work", "Bank"]);
  assert.deepEqual(after.zz_future, { kept: true });
  d.engine.stop();
});

test("a_favourite_switch_is_a_patch_that_keeps_the_folders_and_every_unknown_key", async () => {
  const d = await world();
  await d.engine.update(ID_A, favouriteDraft({ favorite: false }), currentRev(d.engine, ID_A));
  await until(() => d.model.items.get(ID_A).rev === 2, "the patch is on the server");
  const after = await serverBody(d, ID_A);
  assert.equal(after.favorite, true);
  assert.deepEqual(after.folders, ["Work", "Bank"]);
  assert.deepEqual(after.zz_future, { kept: true });
  d.engine.stop();
});

test("a_rename_writes_every_item_in_the_folder_whatever_its_case_and_no_other_item", async () => {
  const d = await world();
  const result = await renameFolder({ engine: d.engine, from: "Work", to: "Jobb" });
  assert.deepEqual([result.done, result.failed, result.skipped, result.total], [2, 0, 0, 2]);
  await until(() => d.model.items.get(ID_A).rev === 2 && d.model.items.get(ID_B).rev === 2, "both writes are on the server");
  await settle();
  assert.deepEqual(sentRevs(d), [2, 2, 1], "the item in no folder is not written");
  const a = await serverBody(d, ID_A);
  const b = await serverBody(d, ID_B);
  assert.deepEqual(a.folders, ["Jobb", "Bank"], "the new name stands where the old one stood");
  assert.deepEqual(b.folders, ["Jobb"]);
  for (const item of [a, b]) {
    assert.deepEqual(item.zz_future, { kept: true }, "an unknown key is kept");
    assert.equal(item.fields[0].value, `${item.name}-user`, "and so is everything else");
  }
  d.engine.stop();
});

test("a_rename_onto_a_folder_the_item_has_already_makes_one_label", async () => {
  const d = await world();
  await renameFolder({ engine: d.engine, from: "Bank", to: "work" });
  await until(() => d.model.items.get(ID_A).rev === 2, "the write");
  assert.deepEqual((await serverBody(d, ID_A)).folders, ["Work"], "the item is in the folder once");
  assert.deepEqual(sentRevs(d), [2, 1, 1]);
  d.engine.stop();
});

test("a_delete_takes_the_label_off_every_item_in_the_folder_and_the_items_stay", async () => {
  const d = await world();
  const result = await deleteFolder({ engine: d.engine, name: "WORK" });
  assert.equal(result.done, 2);
  await until(() => d.model.items.get(ID_A).rev === 2 && d.model.items.get(ID_B).rev === 2, "both writes");
  await settle();
  assert.deepEqual(sentRevs(d), [2, 2, 1]);
  assert.equal(d.model.items.get(ID_A).deleted ?? false, false, "the items stay");
  const a = await serverBody(d, ID_A);
  const b = await serverBody(d, ID_B);
  assert.deepEqual(a.folders, ["Bank"]);
  assert.equal("folders" in b, false, "an item left in no folder has no key at all");
  assert.deepEqual(b.zz_future, { kept: true });
  assert.equal(d.engine.list().length, 3);
  d.engine.stop();
});

test("a_rename_never_overwrites_a_change_that_came_in_meanwhile", async () => {
  const d = await world();
  // Another device changed A after this one listed it: the write of A is refused as a conflict by the server and A keeps
  // the other device's version; B is renamed.
  setRow(d.model, d.client, ID_A, 2, body("Alpha elsewhere", ["Work", "Bank", "Other"]));
  const result = await renameFolder({ engine: d.engine, from: "Work", to: "Jobb" });
  assert.equal(result.done + result.failed, 2);
  await until(() => d.model.items.get(ID_B).rev === 2, "B is renamed");
  await until(() => d.events.error.some((e) => e.code === "conflict" && e.id === ID_A) || d.model.items.get(ID_A).rev === 2, "A is not overwritten");
  const a = await serverBody(d, ID_A);
  assert.equal(a.name, "Alpha elsewhere", "the other device's change is on the server as it was");
  assert.deepEqual(a.folders, ["Work", "Bank", "Other"]);
  d.engine.stop();
});

test("keeping_either_side_of_a_conflict_keeps_that_sides_folders_and_unknown_keys", async () => {
  for (const choice of ["mine", "theirs"]) {
    const model = new Model();
    const client = createFakeClient();
    setRow(model, client, ID_A, 1, body("Original", ["Work"]));
    const d = await syncDevice({ model, client });
    await d.engine.start();
    await until(() => d.engine.list().length === 1, "the item");
    setRow(model, client, ID_A, 2, body("Theirs", ["Home"]));
    await d.engine.update(ID_A, { name: "Mine" }, currentRev(d.engine, ID_A));
    await until(() => d.events.error.some((e) => e.code === "conflict"), "the conflict");
    await until(() => d.engine.list()[0]?.rev === 2, "the server's version");
    await settle(10);
    await d.engine.resolve(ID_A, choice);
    if (choice === "mine") await until(() => model.items.get(ID_A).rev === 3, "mine is written");
    await settle(10);
    const after = await serverBody(d, ID_A);
    assert.equal(after.name, choice === "mine" ? "Mine" : "Theirs");
    assert.deepEqual(after.folders, choice === "mine" ? ["Work"] : ["Home"], choice);
    assert.deepEqual(after.zz_future, { kept: true }, choice);
    d.engine.stop();
  }
});

test("an_item_restored_from_the_trash_comes_back_with_its_folders_and_unknown_keys", async () => {
  const d = await world();
  await d.engine.remove(ID_A);
  await until(() => d.model.items.get(ID_A).deleted === true, "the deletion is on the server");
  await until(async () => (await d.engine.trash()).length === 1, "in the trash");
  await d.engine.restoreFromTrash(ID_A);
  await until(() => d.model.items.get(ID_A).deleted === false, "the item is back");
  const after = await serverBody(d, ID_A);
  assert.deepEqual(after.folders, ["Work", "Bank"]);
  assert.deepEqual(after.zz_future, { kept: true });
  d.engine.stop();
});

test("a_second_device_sees_a_rename_after_it_syncs", async () => {
  const d = await world();
  const other = await syncDevice({ model: d.model, client: d.client, seed: 2 });
  await other.engine.start();
  await until(() => other.engine.list().length === 3, "the second device has the items");
  await renameFolder({ engine: d.engine, from: "Work", to: "Jobb" });
  await until(() => d.model.items.get(ID_A).rev === 2 && d.model.items.get(ID_B).rev === 2, "on the server");
  await other.engine.syncNow?.();
  other.timers.advance(10_000);
  await until(() => other.engine.list().find((item) => item.id === ID_B)?.folders?.[0] === "Jobb", "the second device has the new name");
  assert.deepEqual(other.engine.list().find((item) => item.id === ID_A).folders, ["Jobb", "Bank"]);
  d.engine.stop();
  other.engine.stop();
});
