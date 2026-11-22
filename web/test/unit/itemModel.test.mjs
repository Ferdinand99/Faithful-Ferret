// The item screen's view model: which fields go in which card, the tile, the folder labels and the favourite patch.
// Pure functions; no DOM and no secret.
import assert from "node:assert/strict";
import { test } from "node:test";
import { MAX_FOLDER_CHIPS, favouriteDraft, folderLabels, groupFields, tileLetter, tileType } from "../../src/views/itemModel.mjs";

test("the_tile_has_a_colour_for_a_known_type_and_the_neutral_one_for_any_other", () => {
  for (const type of ["login", "note", "card", "identity"]) assert.equal(tileType(type), type);
  for (const odd of ["passkey", "", null, undefined, 7, "LOGIN", "login\"><script>"]) assert.equal(tileType(odd), "other");
});

test("the_tile_letter_is_the_first_character_in_upper_case_and_a_question_mark_for_no_name", () => {
  assert.equal(tileLetter("bank"), "B");
  assert.equal(tileLetter("  github"), "G");
  assert.equal(tileLetter("ølbryggeri"), "Ø");
  assert.equal(tileLetter("😀 party"), "😀", "a character outside the basic plane is one letter, not half of one");
  for (const none of ["", "   ", null, undefined]) assert.equal(tileLetter(none), "?");
});

test("the_sign_in_fields_come_first_and_the_rest_keep_the_order_the_item_has", () => {
  const { login, custom } = groupFields([
    { id: "pin", label: "PIN", value: null },
    { id: "password", label: "Password", value: null },
    { id: "recovery", label: "Recovery code", value: "abc" },
    { id: "username", label: "User name", value: "ada" },
  ]);
  assert.deepEqual(login.map((f) => f.id), ["username", "password"], "user name, then password, whatever their place in the item");
  assert.deepEqual(custom.map((f) => f.id), ["pin", "recovery"]);
  // The key and the index are the field's place in the item: that is what the worker is asked for.
  assert.deepEqual(login.map((f) => [f.key, f.index]), [["f3", 3], ["f1", 1]]);
  assert.deepEqual(custom.map((f) => [f.key, f.index]), [["f0", 0], ["f2", 2]]);
});

test("a_value_is_plain_only_when_the_core_showed_it", () => {
  const { login, custom } = groupFields([
    { id: "username", label: "User name", value: "ada" },
    { id: "password", label: "Password", value: null },
    { id: "pin", label: "PIN" },
    { id: "odd", label: "Odd", value: 12 },
  ]);
  assert.equal(login[0].plain, "ada");
  assert.equal(login[1].plain, null, "a secret is never plain");
  assert.deepEqual(custom.map((f) => f.plain), [null, null], "a missing or odd value is treated as secret, never shown");
});

test("fields_that_are_not_objects_are_skipped_and_a_missing_label_is_empty", () => {
  assert.deepEqual(groupFields(undefined), { login: [], custom: [] });
  assert.deepEqual(groupFields("nope"), { login: [], custom: [] });
  const { custom } = groupFields([null, 4, { id: "x" }]);
  assert.deepEqual(custom.map((f) => [f.key, f.id, f.label]), [["f2", "x", ""]], "the index counts the skipped ones, so it still names the field in the item");
});

test("the_folder_labels_of_a_view_without_folders_are_none", () => {
  assert.deepEqual(folderLabels({}), []);
  assert.deepEqual(folderLabels(null), []);
  assert.deepEqual(folderLabels({ folders: "Home" }), []);
});

test("a_folder_label_follows_the_rules_of_a_name_and_the_labels_are_sorted_once_each", () => {
  // Display order (ignoring case, numbers in order); a repeat in another case is shown once; what breaks a rule is dropped.
  assert.deepEqual(folderLabels({ folders: ["Home", "Finance", "home", "", "two\nlines", 5, null, "x".repeat(65), "ok"] }), ["Finance", "Home", "ok"]);
  const many = Array.from({ length: 20 }, (_, i) => `Folder ${i}`);
  const labels = folderLabels({ folders: many });
  assert.equal(labels.length, 20, "every label is handed on; the page draws the first ones and a +N chip");
  assert.deepEqual(labels.slice(0, 3), ["Folder 0", "Folder 1", "Folder 2"]);
  assert.equal(labels[19], "Folder 19");
  assert.ok(MAX_FOLDER_CHIPS < 20);
});

test("the_favourite_draft_is_a_patch_of_the_one_key_that_switches_it", () => {
  assert.deepEqual(favouriteDraft({ favorite: false }), { favorite: true });
  assert.deepEqual(favouriteDraft({ favorite: true }), { favorite: false });
  assert.deepEqual(favouriteDraft({}), { favorite: true });
  assert.deepEqual(favouriteDraft(null), { favorite: true });
  assert.deepEqual(Object.keys(favouriteDraft({ favorite: true, name: "x" })), ["favorite"], "nothing else of the item is in the draft");
});
