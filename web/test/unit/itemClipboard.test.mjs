// What the item page and the generator copy: a secret is written through the clipboard helper (cleared after 30 seconds and by a
// lock, and the text says so), a user name or an address is written as it is and left alone.
import assert from "node:assert/strict";
import { test } from "node:test";
import { secretClipboardFor } from "../../src/secretClipboard.mjs";
import { createWipeScope } from "../../src/views/common.mjs";
import { generatorView } from "../../src/views/generator.mjs";
import { createOptionsStore } from "../../src/generatorPrefs.mjs";
import { itemView } from "../../src/views/item.mjs";
import { click, fakeClient, fakeEngine, find, settle, t, textOf, withDom } from "./vaultHelpers.mjs";

const ID = "11".repeat(16);
const PASSWORD = "pw-SECRET-1";
const PIN = "pin-SECRET-2";

const VIEW = Object.freeze({
  item_type: "login", name: "Bank",
  fields: [
    { id: "username", label: "User name", kind: "text", value: "ada" },
    { id: "password", label: "Password", kind: "password", value: null },
    { id: "pin", label: "PIN", kind: "hidden", value: null },
  ],
  urls: [{ url: "https://bank.example", matching: "host" }],
  has_totp: false, has_notes: true, favorite: false, read_only: false,
});
const ENTRY = Object.freeze({
  id: ID, name: "Bank", type: "login", favorite: false, urls: ["https://bank.example"], username: "ada", rev: 2,
  pending: false, damaged: false, quarantined: false, missingOnServer: false, blocked: false, blockedReason: null, readOnly: false,
});

function fakeClipboard() {
  const clipboard = { writes: [], async writeText(text) { clipboard.writes.push(text); } };
  return clipboard;
}

async function open() {
  const engine = fakeEngine({ items: [ENTRY], views: { [ID]: VIEW }, secrets: { [ID]: ["ada", PASSWORD, PIN] } });
  const client = fakeClient(engine, { notes: { [ID]: "notes" } });
  const clipboard = fakeClipboard();
  const scope = createWipeScope();
  const root = await itemView({ engine, sync: engine, client, id: ID, t, scope, clipboard });
  return { root, clipboard, scope, helper: secretClipboardFor(clipboard) };
}

test("a_secret_field_is_copied_through_the_helper_and_the_text_says_it_is_cleared", async () => {
  await withDom(async () => {
    const { root, clipboard, helper } = await open();
    await click(find(root, "copy", "f1"));
    assert.deepEqual(clipboard.writes, [PASSWORD]);
    assert.equal(helper.pending(), true);
    assert.ok(textOf(root).includes("vault.item.copied_secret"));
    await click(find(root, "copy", "f2"));
    assert.deepEqual(clipboard.writes, [PASSWORD, PIN], "any other hidden field is a secret too");
    assert.equal(helper.pending(), true);
    await helper.clearNow();
  });
});

test("a_user_name_and_an_address_are_copied_as_they_are_and_nothing_is_scheduled", async () => {
  await withDom(async () => {
    const { root, clipboard, helper } = await open();
    await click(find(root, "copy", "f0"));
    await click(find(root, "copy-url"));
    await settle();
    assert.deepEqual(clipboard.writes, ["ada", "https://bank.example"]);
    assert.equal(helper.pending(), false);
    assert.ok(!textOf(root).includes("vault.item.copied_secret"));
    assert.ok(textOf(root).includes("vault.item.copied"));
  });
});

test("a_lock_clears_the_secret_at_once", async () => {
  await withDom(async () => {
    const { root, clipboard, scope, helper } = await open();
    await click(find(root, "copy", "f1"));
    assert.equal(helper.pending(), true);
    scope.run(); // a lock
    await settle();
    assert.deepEqual(clipboard.writes, [PASSWORD, ""]);
    assert.equal(helper.pending(), false);
  });
});

test("the_generators_copy_is_cleared_too_and_a_lock_clears_it_at_once", async () => {
  await withDom(async () => {
    const clipboard = fakeClipboard();
    const scope = createWipeScope();
    const client = { vault: { generate_password: async () => ({ value: "GEN-1", bits: 100 }), generate_passphrase: async () => ({ value: "a-b", bits: 50 }) } };
    const root = generatorView({
      t, client, store: createOptionsStore({ getItem: () => null, setItem() {}, removeItem() {} }), scope, clipboard,
      win: { location: { hash: "#/generator" }, addEventListener() {}, removeEventListener() {} },
    });
    await settle();
    await click(find(root, "copy"));
    assert.deepEqual(clipboard.writes, ["GEN-1"]);
    assert.equal(secretClipboardFor(clipboard).pending(), true);
    assert.ok(textOf(find(root, "generator-status")).includes("vault.item.copied_secret"));
    scope.run();
    await settle();
    assert.deepEqual(clipboard.writes, ["GEN-1", ""]);
  });
});
