// Folders as labels: the rules of a name (the core's, checked first in the page), when two names are one folder, the
// folders of a vault, the list of an item after a rename or a delete, the addresses of folder pages (a token, never the
// name), and the pinned folders, which are kept sealed under the vault key and never in clear.
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { test } from "node:test";
import { hex16 } from "../../src/b64.mjs";
import {
  MAX_FOLDERS, checkFolderList, checkFolderName, folderChips, folderIndex, foldKey, normalizeFolder, renamedList, sameFolder,
  sortFolders, withShownNames, withoutFolder,
} from "../../src/folders.mjs";
import { createPinStore, pinsKey } from "../../src/pinStore.mjs";
import { forgetServer } from "../../src/store/forget.mjs";
import { getSetting, setSetting, deleteSetting } from "../../src/store/settings.mjs";
import { createUiPrefs, MAX_PINNED, watchPins } from "../../src/uiPrefs.mjs";
import { clearFolderLinks, folderHref, keyOfToken, tokenFor } from "../../src/views/folderLinks.mjs";
import { web } from "./helpers.mjs";
import { ACCOUNT, SERVER, VAULT, freshStore } from "./idbHelpers.mjs";
import { createFakeClient } from "./syncHelpers.mjs";

const ch = (code) => String.fromCodePoint(code);

// ---------------------------------------------------------------- the rules of a name

test("a_name_is_put_in_nfc_and_trimmed_and_must_have_1_to_64_characters", () => {
  assert.equal(normalizeFolder("  Bank  "), "Bank");
  assert.equal(normalizeFolder(`${ch(0x3000)}Bank${ch(0xa0)}`), "Bank", "every Unicode white space at the ends goes");
  // A decomposed e with an acute accent is stored composed.
  assert.equal(normalizeFolder(`Cafe${ch(0x301)}`), `Caf${ch(0xe9)}`);
  assert.equal(checkFolderName(""), "folder_empty");
  assert.equal(checkFolderName("   "), "folder_empty");
  assert.equal(checkFolderName(`${ch(0x2028)}`), "folder_empty", "a name that is only a separator trims to nothing");
  assert.equal(checkFolderName(5), "folder_empty");
  assert.equal(checkFolderName("x".repeat(64)), null);
  assert.equal(checkFolderName("x".repeat(65)), "folder_too_long");
  // Characters, not UTF-16 units: 64 emoji (two units each) is a good name.
  assert.equal(checkFolderName(ch(0x1f512).repeat(64)), null);
  assert.equal(checkFolderName(ch(0x1f512).repeat(65)), "folder_too_long");
  // The length is counted on the NFC form: 64 decomposed letters with accents are 64 characters once composed.
  assert.equal(checkFolderName(`e${ch(0x301)}`.repeat(64)), null);
});

test("a_name_may_not_hold_a_control_a_separator_a_direction_control_a_zero_width_space_or_a_byte_order_mark", () => {
  for (const code of [0x0, 0x7, 0x1b, 0x7f, 0x85, 0x9f, 0x2028, 0x2029, 0x061c, 0x200e, 0x200f, 0x202a, 0x202b, 0x202c, 0x202d, 0x202e, 0x2066, 0x2067, 0x2068, 0x2069, 0x200b, 0xfeff]) {
    assert.equal(checkFolderName(`a${ch(code)}b`), "folder_bad_character", code.toString(16));
  }
  // A line break inside a name is a control character.
  assert.equal(checkFolderName(`two${ch(10)}lines`), "folder_bad_character");
  // Joiners are allowed: scripts and emoji need them.
  assert.equal(checkFolderName(`a${ch(0x200d)}b`), null);
  assert.equal(checkFolderName(`a${ch(0x200c)}b`), null);
  assert.equal(checkFolderName("Økonomi / 2026 (ny)"), null);
});

test("two_names_are_one_folder_when_they_differ_only_in_case_or_in_composition", () => {
  assert.equal(sameFolder("Work", "WORK"), true);
  assert.equal(sameFolder(" work ", "Work"), true);
  assert.equal(sameFolder(`Caf${ch(0xe9)}`, `CAFE${ch(0x301)}`), true);
  assert.equal(sameFolder("Æble", "æble"), true);
  // Simple lower-case mapping, as the core: these stay apart.
  assert.equal(sameFolder("Straße".normalize(), "STRASSE"), false);
  assert.equal(foldKey("ABC"), "abc");
});

test("a_list_of_an_item_has_at_most_20_names_and_no_two_the_same", () => {
  assert.equal(checkFolderList([]), null);
  assert.equal(checkFolderList(Array.from({ length: MAX_FOLDERS }, (_, i) => `F${i}`)), null);
  assert.equal(checkFolderList(Array.from({ length: MAX_FOLDERS + 1 }, (_, i) => `F${i}`)), "folder_too_many");
  assert.equal(checkFolderList(["Work", "work"]), "folder_duplicate");
  assert.equal(checkFolderList(["Work", ""]), "folder_empty");
  assert.equal(MAX_FOLDERS, 20);
});

test("the_codes_and_rules_are_the_cores", () => {
  // The texts the page has are for exactly the codes the core gives.
  const en = JSON.parse(readFileSync(join(web, "src", "locales", "en", "folders.json"), "utf8"));
  const nb = JSON.parse(readFileSync(join(web, "src", "locales", "nb", "folders.json"), "utf8"));
  for (const code of ["folder_empty", "folder_too_long", "folder_bad_character", "folder_too_many", "folder_duplicate"]) {
    assert.ok(en[`folders.error.${code}`], code);
    assert.ok(nb[`folders.error.${code}`], code);
  }
});

// ---------------------------------------------------------------- the folders of a vault

test("the_folders_of_a_vault_are_the_names_its_items_carry_in_display_order", () => {
  const items = [
    { id: "a", folders: ["Work", "Bank"] },
    { id: "b", folders: ["work"] },
    { id: "c", folders: ["Work", "Home"] },
    { id: "d", folders: [] },
    { id: "e" },
  ];
  const index = folderIndex(items);
  assert.deepEqual(index.map((f) => [f.name, f.ids]), [["Bank", ["a"]], ["Home", ["c"]], ["Work", ["a", "b", "c"]]]);
  // The spelling most items use is the one shown.
  assert.equal(index.find((f) => f.key === "work").name, "Work");
  // A folder with no item does not exist.
  assert.deepEqual(folderIndex([{ id: "x", folders: [] }]), []);
  // The items with the names as shown: "work" on b is "Work".
  const shown = withShownNames(items, index);
  assert.deepEqual(shown.map((i) => i.folders), [["Work", "Bank"], ["Work"], ["Work", "Home"], [], undefined]);
  assert.equal(shown[3], items[3], "an item without folders is handed on as it is");
});

test("labels_are_sorted_for_display_only_and_the_rest_are_a_count", () => {
  assert.deepEqual(sortFolders(["b", "A", "a", "C10", "C9"]), ["A", "b", "C9", "C10"]);
  assert.deepEqual(folderChips(["Zeta", "alpha", "Beta"], 1), { shown: ["alpha"], more: 2 });
  assert.deepEqual(folderChips(undefined, 3), { shown: [], more: 0 });
});

test("the_list_of_an_item_after_a_rename_or_a_delete", () => {
  assert.deepEqual(renamedList(["Work", "Bank"], "work", " Jobb "), ["Jobb", "Bank"], "where the old name stood, trimmed");
  assert.deepEqual(renamedList(["Work", "Bank"], "Bank", "WORK"), ["Work"], "into a folder it has already: once");
  assert.deepEqual(renamedList(["work"], "Work", "Work"), ["Work"], "a change of case is a rename too");
  assert.equal(renamedList(["Home"], "Work", "Jobb"), null, "an item not in the folder is not written");
  assert.deepEqual(withoutFolder(["Work", "Bank"], "WORK"), ["Bank"]);
  assert.deepEqual(withoutFolder(["Work"], "Work"), []);
  assert.equal(withoutFolder(["Home"], "Work"), null);
});

// ---------------------------------------------------------------- the address of a folder

test("the_address_of_a_folder_holds_a_random_token_and_never_its_name", () => {
  clearFolderLinks();
  const token = tokenFor("Secret project");
  assert.match(token, /^[0-9a-f]{16}$/);
  assert.equal(tokenFor("SECRET PROJECT"), token, "one folder, one token");
  assert.notEqual(tokenFor("Other"), token);
  assert.equal(folderHref("Secret project"), `#/folders/${token}`);
  assert.ok(!folderHref("Secret project").toLowerCase().includes("secret"));
  assert.equal(keyOfToken(token), "secret project");
  assert.equal(keyOfToken("not a token"), null);
  assert.equal(keyOfToken("0".repeat(16)), null, "a token this page never made");
  // A lock forgets them: an old address leads nowhere, and the folder gets a new token.
  clearFolderLinks();
  assert.equal(keyOfToken(token), null);
  assert.notEqual(tokenFor("Secret project"), token);
  clearFolderLinks();
});

// ---------------------------------------------------------------- the pins

/** Settings over the real browser store (a fake IndexedDB). */
async function settingsOver() {
  const { store } = await freshStore();
  return {
    store,
    settings: {
      get: (key) => getSetting(store, key),
      set: (key, value) => setSetting(store, key, value),
      remove: (key) => deleteSetting(store, key),
    },
  };
}

test("the_pins_are_kept_sealed_under_the_vault_key_and_come_back_after_an_unlock", async () => {
  const { store, settings } = await settingsOver();
  const client = createFakeClient();
  const pins = createPinStore({ vault: client.vault, settings, accountId: ACCOUNT, vaultId: VAULT, vkEpoch: 1 });
  assert.deepEqual(await pins.load(), [], "nothing kept yet");
  await pins.save(["Secret project", "Bank"]);
  const record = await getSetting(store, pinsKey(ACCOUNT, VAULT));
  assert.deepEqual(Object.keys(record).sort(), ["envelope", "epoch", "id", "tag", "v"]);
  assert.ok(hex16.is(record.id));
  // No name in clear anywhere in what is stored.
  const stored = Buffer.concat([Buffer.from(JSON.stringify({ ...record, envelope: null, tag: null })), Buffer.from(record.envelope), Buffer.from(record.tag)]).toString("latin1");
  for (const name of ["Secret project", "Bank"]) assert.ok(!stored.includes(name), name);
  // The core sealed it as a body that holds the names and nothing of an item.
  const sealed = client.vault.calls.find((call) => call[0] === "encrypt_item");
  assert.equal(sealed[2], 1);
  assert.equal(sealed[3], null, "a new body, never an item of the vault");
  // Another page of the same vault reads them back.
  const again = createPinStore({ vault: client.vault, settings, accountId: ACCOUNT, vaultId: VAULT, vkEpoch: 1 });
  assert.deepEqual(await again.load(), ["Secret project", "Bank"]);
  assert.equal(client.vault.handles.size, 0, "the handle is closed after the read");
  // Another epoch, or a value that does not open: no pins (it is a preference, not data).
  assert.deepEqual(await createPinStore({ vault: client.vault, settings, accountId: ACCOUNT, vaultId: VAULT, vkEpoch: 2 }).load(), []);
  await setSetting(store, pinsKey(ACCOUNT, VAULT), { ...record, tag: new Uint8Array(32) });
  assert.deepEqual(await again.load(), []);
  await setSetting(store, pinsKey(ACCOUNT, VAULT), "Secret project");
  assert.deepEqual(await again.load(), []);
  // No pins: the record goes.
  await again.save(["Bank"]);
  await again.save([]);
  assert.equal(await getSetting(store, pinsKey(ACCOUNT, VAULT)), undefined);
});

test("forget_this_server_removes_the_sealed_pins_with_the_sync_flags", async () => {
  const { store, settings } = await settingsOver();
  const client = createFakeClient();
  await createPinStore({ vault: client.vault, settings, accountId: ACCOUNT, vaultId: VAULT, vkEpoch: 1 }).save(["Bank"]);
  assert.ok(pinsKey(ACCOUNT, VAULT).startsWith(`sync.flags.${ACCOUNT}.`));
  await forgetServer(store, SERVER, ACCOUNT);
  assert.equal(await getSetting(store, pinsKey(ACCOUNT, VAULT)), undefined);
});

test("pins_are_held_by_name_in_memory_ignoring_case_and_every_change_is_handed_to_the_saver", async () => {
  const saved = [];
  const pins = [];
  const saver = { save: null };
  const prefs = createUiPrefs(null, pins, saver);
  assert.equal(prefs.pin("Work"), true, "with no saver the pin is held in memory only");
  prefs.restorePins(["Bank", "bank", "x".repeat(65), "Work"], async (names) => void saved.push(names));
  assert.deepEqual(prefs.pinned(), ["Bank", "Work"], "what comes back is checked: a repeat and a bad name are dropped");
  assert.equal(prefs.isPinned("BANK"), true);
  assert.equal(prefs.pin(" work "), true, "pinned already, ignoring case");
  assert.equal(prefs.pin("Home"), true);
  prefs.renamePin("home", "House");
  prefs.unpin("WORK");
  await new Promise((resolve) => setImmediate(resolve));
  assert.deepEqual(prefs.pinned(), ["Bank", "House"]);
  assert.deepEqual(saved.at(-1), ["Bank", "House"], "the saver has the newest list");
  // A rename onto another pin makes one pin.
  prefs.renamePin("House", "bank");
  assert.deepEqual(prefs.pinned(), ["Bank"]);
  // A lock forgets the pins and the saver.
  prefs.clearPins();
  assert.deepEqual(prefs.pinned(), []);
  prefs.pin("After");
  await new Promise((resolve) => setImmediate(resolve));
  assert.notDeepEqual(saved.at(-1), ["After"], "nothing is kept after a lock");
  assert.equal(MAX_PINNED, 20);
  for (const bad of ["", `two${ch(10)}lines`, "x".repeat(65), 5, null]) assert.equal(prefs.pin(/** @type {any} */ (bad)), false, String(bad));
});

test("the_menu_is_told_when_the_pins_change", () => {
  let told = 0;
  const off = watchPins(() => {
    told += 1;
  });
  const prefs = createUiPrefs(null, [], { save: null });
  prefs.pin("A");
  prefs.unpin("A");
  prefs.unpin("A");
  off();
  prefs.pin("B");
  assert.equal(told, 2, "a pin and an unpin; an unpin of nothing and a change after `off` are not told");
});

test("no_folder_name_is_written_in_clear_by_the_preferences", () => {
  const source = readFileSync(join(web, "src", "uiPrefs.mjs"), "utf8");
  assert.ok(!/indexedDB|sessionStorage|document\.cookie|setItem\([^)]*pins/.test(source));
  const store = readFileSync(join(web, "src", "pinStore.mjs"), "utf8");
  assert.ok(/encrypt_item/.test(store), "the pins are sealed by the core");
  assert.ok(!/localStorage/.test(store));
});

test("a_record_of_an_older_vault_key_epoch_is_removed_when_it_is_read", async () => {
  const { store, settings } = await settingsOver();
  const client = createFakeClient();
  await createPinStore({ vault: client.vault, settings, accountId: ACCOUNT, vaultId: VAULT, vkEpoch: 1 }).save(["Secret project"]);
  assert.ok(await getSetting(store, pinsKey(ACCOUNT, VAULT)));
  // After a rekey the old key may be exposed: the ciphertext under it does not stay.
  assert.deepEqual(await createPinStore({ vault: client.vault, settings, accountId: ACCOUNT, vaultId: VAULT, vkEpoch: 2 }).load(), []);
  assert.equal(await getSetting(store, pinsKey(ACCOUNT, VAULT)), undefined);
  assert.equal(client.vault.calls.filter((call) => call[0] === "open_item").length, 0, "it is not opened");
  // A store that cannot remove it still gives no pins.
  const failing = { ...settings, get: async () => ({ v: 1, epoch: 1, id: "ab".repeat(16), envelope: new Uint8Array(8), tag: new Uint8Array(32) }), remove: async () => { throw new Error("store"); } };
  assert.deepEqual(await createPinStore({ vault: client.vault, settings: failing, accountId: ACCOUNT, vaultId: VAULT, vkEpoch: 2 }).load(), []);
});

test("two_quick_pin_changes_are_kept_in_the_order_they_were_made", async () => {
  const started = [];
  const finished = [];
  /** The first save is slow; the second must wait for it. */
  let releaseFirst = () => {};
  const firstHeld = new Promise((resolve) => {
    releaseFirst = resolve;
  });
  const saver = {
    save: async (names) => {
      started.push([...names]);
      if (started.length === 1) await firstHeld;
      finished.push([...names]);
    },
  };
  const prefs = createUiPrefs(null, [], saver);
  prefs.pin("A");
  prefs.pin("B");
  await new Promise((resolve) => setImmediate(resolve));
  assert.deepEqual(started, [["A"]], "the second save waits for the first");
  releaseFirst();
  await new Promise((resolve) => setImmediate(resolve));
  await new Promise((resolve) => setImmediate(resolve));
  assert.deepEqual(finished, [["A"], ["A", "B"]], "the newest list is the last one kept");
  // A failed save does not stop the next.
  const failing = { save: async (names) => {
    if (names.length === 1) throw new Error("store");
    finished.push([...names]);
  } };
  const other = createUiPrefs(null, [], failing);
  other.pin("X");
  other.pin("Y");
  await new Promise((resolve) => setImmediate(resolve));
  await new Promise((resolve) => setImmediate(resolve));
  assert.deepEqual(finished.at(-1), ["X", "Y"]);
});
