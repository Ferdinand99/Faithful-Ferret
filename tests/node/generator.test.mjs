// The generator, the comparison of a field with a candidate and the earlier
// passwords of an item, through the binding: `generate_password`,
// `generate_passphrase`, `Vault.item_field_equals`,
// `Vault.items_with_field_value`, `Vault.reveal_password_history`, the
// `password_history` of `item_view` and `keep_password_history` of a draft.
// Run against the build with `test-support`, which has the same exports as the
// release plus the vector operations and the memory probes.
// Run: node --test tests/node/generator.test.mjs
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { test } from "node:test";
import { createDispatcher } from "../../bindings/wasm/js/protocol.mjs";
import { parseOps, runVectorFile } from "../../bindings/wasm/js/vector-runner.mjs";
import { NOW, codeOf, fill, newAccount, reauthToken, root, row, wasm } from "./helpers.mjs";

const vectors = JSON.parse(readFileSync(join(root, "vectors", "internal", "generator.json"), "utf8"));
const ops = parseOps(readFileSync(join(root, "vectors", "OPS.md"), "utf8"));
const WORDS = new Set(
  readFileSync(join(root, "crates", "ferret-core", "src", "generator", "eff_large_words.txt"), "utf8")
    .split("\n")
    .filter(Boolean),
);
const LOWER = "abcdefghijklmnopqrstuvwxyz";
const UPPER = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
const DIGITS = "0123456789";
const SYMBOLS = "!#$%&*+-.:=?@^_~";

function code(fn) {
  const e = codeOf(fn);
  assert.equal(e.name, "FerretError");
  assert.equal(e.message, e.code, "the message is the code and nothing else");
  return e.code;
}

const PASSWORD = { length: 20, lower: true, upper: true, digits: true, symbols: true, min_each: 1, avoid_ambiguous: false };
const PASSPHRASE = { words: 5, separator: "-", capitalize: true, number: false };

let nextId = 1;
function newId() {
  const id = fill(16, 0x60);
  id[0] = nextId & 0xff;
  id[1] = (nextId >> 8) & 0xff;
  nextId++;
  return id;
}

/** A login with the web vault's field ids, sealed and opened: `{ id, handle, sealed }`. */
function login(vault, password, extra = {}) {
  const id = newId();
  const draft = {
    item_type: "login",
    name: "Example",
    fields: [
      { id: "username", label: "Username", kind: "text", value: "anna@example.net" },
      { id: "password", label: "Password", kind: "password", value: password },
    ],
    urls: [{ url: "https://example.com", matching: "host" }],
    ...extra,
  };
  const sealed = vault.encrypt_item(id, 1, draft, undefined, NOW);
  return { id, sealed, handle: vault.open_item(id, sealed.rev, sealed.envelope, sealed.tag) };
}

/** Seals an edit of the open item and opens the result in its place. */
function edit(vault, item, draft, now) {
  const rev = item.sealed.rev + 1;
  item.sealed = vault.encrypt_item(item.id, rev, draft, item.handle, now);
  vault.close_item(item.handle);
  item.handle = vault.open_item(item.id, item.sealed.rev, item.sealed.envelope, item.sealed.tag);
  return item;
}

/** Every field id with no value, and the new password: the update draft of a save offer. */
const passwordUpdate = (value) => ({
  fields: [{ id: "username" }, { id: "password", value }],
  keep_password_history: true,
});

// ------------------------------------------------------------- generator

test("binding_generator_agrees_with_the_core_vectors", () => {
  // The vectors through the WASM build: the same core functions that the two
  // exports call, with the recorded draws.
  const r = runVectorFile(wasm, vectors, ops);
  assert.deepEqual(r.failures, []);
  assert.equal(r.passed, vectors.cases.length);
  assert.ok(r.passed >= 40, `${r.passed} rows`);
  // And the exports, with real randomness, follow the rules of each valid
  // case and give the same estimate; the refused options give the same code.
  for (const c of vectors.cases) {
    if (c.op === "generator.uniform_index") continue;
    const fn = c.op === "generator.password" ? wasm.generate_password : wasm.generate_passphrase;
    if (c.status === "invalid") {
      assert.equal(code(() => fn(c.input)), c.expect_error, c.id);
      continue;
    }
    const got = fn(c.input);
    assert.deepEqual(Object.keys(got).sort(), ["bits", "value"], c.id);
    assert.equal(got.bits, c.expect.bits, c.id);
    assert.equal(typeof got.value, "string");
    if (c.op === "generator.password") {
      assert.equal(got.value.length, c.input.length, c.id);
      const alphabet = [
        c.input.lower ? LOWER : "",
        c.input.upper ? UPPER : "",
        c.input.digits ? DIGITS : "",
        c.input.symbols ? SYMBOLS : "",
      ].join("");
      for (const ch of got.value) {
        assert.ok(alphabet.includes(ch), `${c.id}: ${ch}`);
        if (c.input.avoid_ambiguous) assert.ok(!"Il1|O0o".includes(ch), c.id);
      }
    } else {
      const parts = got.value.split(c.input.separator);
      assert.ok(parts.length >= c.input.words, c.id);
      if (c.input.separator !== "-") {
        assert.equal(parts.length, c.input.words, c.id);
        for (const p of parts) assert.ok(WORDS.has(p.replace(/\d+$/, "").toLowerCase()), `${c.id}: ${p}`);
      }
    }
  }
});

test("generate_functions_are_exported_and_typed", () => {
  // They need no vault, and the dispatcher of the vault worker answers them
  // without one.
  assert.equal(typeof wasm.generate_password, "function");
  assert.equal(typeof wasm.generate_passphrase, "function");
  const dispatch = createDispatcher(wasm);
  const pw = dispatch({ id: 1, target: "vault", method: "generate_password", args: [PASSWORD] }).reply;
  assert.equal(pw.ok, true);
  assert.equal(pw.value.value.length, 20);
  assert.ok(Math.abs(pw.value.bits - 20 * Math.log2(78)) < 1e-9);
  const pp = dispatch({ id: 2, target: "vault", method: "generate_passphrase", args: [PASSPHRASE] }).reply;
  assert.equal(pp.ok, true);
  assert.ok(Math.abs(pp.value.bits - 5 * Math.log2(7776)) < 1e-9);
  // Two calls give two values.
  assert.notEqual(wasm.generate_password(PASSWORD).value, wasm.generate_password(PASSWORD).value);
  // Options: every key is required, no other key is taken, and the types are checked.
  const { length: _, ...noLength } = PASSWORD;
  assert.equal(code(() => wasm.generate_password(noLength)), "invalid_input");
  assert.equal(code(() => wasm.generate_password({ ...PASSWORD, extra: 1 })), "invalid_input");
  assert.equal(code(() => wasm.generate_password({ ...PASSWORD, length: "20" })), "invalid_input");
  assert.equal(code(() => wasm.generate_password({ ...PASSWORD, length: 20.5 })), "invalid_input");
  assert.equal(code(() => wasm.generate_password({ ...PASSWORD, lower: 1 })), "invalid_input");
  assert.equal(code(() => wasm.generate_password(null)), "invalid_input");
  assert.equal(code(() => wasm.generate_password({ ...PASSWORD, length: 129 })), "generator_options");
  assert.equal(code(() => wasm.generate_password({ ...PASSWORD, length: 70000 })), "invalid_input");
  assert.equal(code(() => wasm.generate_passphrase({ ...PASSPHRASE, separator: "--" })), "invalid_input");
  assert.equal(code(() => wasm.generate_passphrase({ ...PASSPHRASE, separator: "" })), "invalid_input");
  assert.equal(code(() => wasm.generate_passphrase({ ...PASSPHRASE, separator: "," })), "generator_options");
  assert.equal(code(() => wasm.generate_passphrase({ ...PASSPHRASE, words: 2 })), "generator_options");
  const bad = dispatch({ id: 3, target: "vault", method: "generate_password", args: [{ ...PASSWORD, min_each: 9 }] }).reply;
  assert.deepEqual(bad, { id: 3, ok: false, code: "generator_options" });
});

// ------------------------------------------------------- field comparison

test("item_field_equals_uses_ct_eq_and_reads_only_that_field", () => {
  // The source: the binding asks the core, and the core compares with ct_eq.
  const vaultRs = readFileSync(join(root, "bindings", "wasm", "src", "vault.rs"), "utf8");
  const body = vaultRs.slice(vaultRs.indexOf("pub fn item_field_equals"), vaultRs.indexOf("pub fn items_with_field_value"));
  assert.match(body, /Zeroizing::new\(candidate\)/);
  assert.match(body, /\.field_value_equals\(field_id, candidate\.as_bytes\(\)\)/);
  assert.ok(!/notes|totp|passkey|password_history|reveal/.test(body.replace(/\/\/\/.*\n/g, "")), "nothing else of the item is read");
  const historyRs = readFileSync(join(root, "crates", "ferret-core", "src", "item", "history.rs"), "utf8");
  const compare = historyRs.slice(historyRs.indexOf("pub fn field_value_equals"));
  assert.match(compare, /crate::prim::ct::ct_eq\(f\.value\.as_bytes\(\), candidate\)/);
  assert.ok(!/==\s*candidate|candidate\s*==/.test(compare), "no plain comparison");
  // The behaviour: only the field with that id counts.
  const { vault } = newAccount("field-equals");
  const item = login(vault, "hunter2-secret", {
    fields: [
      { id: "username", label: "Username", kind: "text", value: "anna@example.net" },
      { id: "password", label: "Password", kind: "password", value: "hunter2-secret" },
      { id: "password-2", label: "Old", kind: "password", value: "second-secret" },
      { id: "pin", label: "PIN", kind: "hidden", value: "1234" },
    ],
    notes: "hunter2-secret in the notes",
  });
  const eq = (field, candidate) => vault.item_field_equals(item.handle, field, candidate);
  assert.equal(eq("password", "hunter2-secret"), true);
  assert.equal(eq("password", "hunter2-secreT"), false);
  assert.equal(eq("password", "hunter2-secre"), false);
  assert.equal(eq("password", "hunter2-secret "), false);
  assert.equal(eq("password", ""), false);
  assert.equal(eq("password", "second-secret"), false, "password-2 is another field");
  assert.equal(eq("password", "anna@example.net"), false);
  assert.equal(eq("password-2", "second-secret"), true);
  assert.equal(eq("pin", "1234"), true);
  assert.equal(eq("missing", ""), false, "no such field: false");
  // UTF-8 bytes, no normalisation.
  const nfc = login(vault, "café");
  assert.equal(vault.item_field_equals(nfc.handle, "password", "café"), true);
  assert.equal(vault.item_field_equals(nfc.handle, "password", "café"), false);
  // A handle that is not open, a locked vault.
  assert.equal(code(() => vault.item_field_equals(item.handle + 7777, "password", "x")), "invalid_handle");
  vault.lock();
  assert.equal(code(() => eq("password", "hunter2-secret")), "vault_locked");
});

/**
 * Every place of `needle` in the linear memory of the instance, read in
 * overlapping pieces of 1 MiB with `test_read_memory` (from address 8 up).
 */
function findInMemory(needle) {
  const size = wasm.test_memory_bytes();
  const piece = 1024 * 1024;
  const found = new Set();
  for (let start = 8; start < size; start += piece) {
    const len = Math.min(piece + needle.length, size - start);
    const memory = Buffer.from(wasm.test_read_memory(start, len));
    for (let at = memory.indexOf(needle); at >= 0; at = memory.indexOf(needle, at + 1)) found.add(start + at);
  }
  return [...found];
}

test("item_field_equals_zeroizes_its_copy_of_the_candidate", () => {
  const { vault } = newAccount("field-equals-wipe");
  const item = login(vault, "the-stored-password");
  // Candidates that are nowhere else: random letters, ASCII.
  const sentinel = (tag) => `${tag}-${[...crypto.getRandomValues(new Uint8Array(24))].map((b) => LOWER[b % 26]).join("")}`;
  const enc = (s) => new TextEncoder().encode(s);
  // Positive control: a page address handed to `page_origin` is copied into
  // WASM memory and freed without a wipe, and the scan finds it.
  const control = sentinel("control");
  wasm.page_origin(`https://${control}.example/`);
  assert.ok(findInMemory(enc(control)).length > 0, "the scan sees a string that was not wiped");
  // The candidate of a comparison is gone after the call, whatever the answer.
  const miss = sentinel("candidate");
  assert.equal(vault.item_field_equals(item.handle, "password", miss), false);
  assert.deepEqual(findInMemory(enc(miss)), [], "the candidate is wiped");
  const other = sentinel("listed");
  assert.deepEqual([...vault.items_with_field_value([item.handle], "password", other)], []);
  assert.deepEqual(findInMemory(enc(other)), [], "the candidate of the list call is wiped");
  // A refused candidate (too long) is wiped too.
  const long = sentinel("long") + "x".repeat(5000);
  assert.equal(code(() => vault.item_field_equals(item.handle, "password", long)), "too_large");
  assert.deepEqual(findInMemory(enc(long.slice(0, 40))), [], "a refused candidate is wiped");
  // The stored value is in the open item, as it must be (the scan works on it).
  assert.ok(findInMemory(enc("the-stored-password")).length > 0);
});

test("items_with_field_value_agrees_with_item_field_equals", () => {
  const { vault } = newAccount("items-with-value");
  const a = login(vault, "shared-secret");
  const b = login(vault, "other-secret");
  const c = login(vault, "shared-secret");
  const note = vault.open_item(
    ...(() => {
      const id = newId();
      const s = vault.encrypt_item(id, 1, { item_type: "note", name: "Note", notes: "shared-secret" }, undefined, NOW);
      return [id, s.rev, s.envelope, s.tag];
    })(),
  );
  const handles = [a.handle, b.handle, c.handle, note, a.handle];
  for (const candidate of ["shared-secret", "other-secret", "nope", ""]) {
    const want = handles.filter((h) => vault.item_field_equals(h, "password", candidate));
    assert.deepEqual([...vault.items_with_field_value(handles, "password", candidate)], want, candidate);
  }
  assert.deepEqual([...vault.items_with_field_value(handles, "password", "shared-secret")], [a.handle, c.handle, a.handle]);
  assert.deepEqual([...vault.items_with_field_value([], "password", "x")], []);
  // One handle that is not open fails the whole call; more than the open limit is refused.
  assert.equal(code(() => vault.items_with_field_value([a.handle, 123456789], "password", "x")), "invalid_handle");
  assert.equal(code(() => vault.items_with_field_value(new Array(4097).fill(a.handle), "password", "x")), "invalid_input");
  // Through the dispatcher the arguments are typed.
  const dispatch = createDispatcher(wasm);
  for (const args of [
    [["1"], "password", "x"],
    [[a.handle], 5, "x"],
    [[a.handle], "password", 5],
    [[a.handle], "password", "lone \ud800 surrogate"],
  ]) {
    const r = dispatch({ id: 9, target: "vault", method: "items_with_field_value", args }).reply;
    assert.deepEqual(r, { id: 9, ok: false, code: "invalid_input" }, JSON.stringify(args));
  }
});

test("item_field_equals_refuses_candidates_over_4_kib", () => {
  const { vault } = newAccount("field-equals-size");
  const exact = "a".repeat(4096);
  const item = login(vault, exact);
  assert.equal(vault.item_field_equals(item.handle, "password", exact), true, "4 KiB is allowed");
  assert.equal(code(() => vault.item_field_equals(item.handle, "password", `${exact}a`)), "too_large");
  // Bytes of UTF-8 count, not characters: 1366 three-byte characters are 4098 bytes.
  assert.equal(code(() => vault.item_field_equals(item.handle, "password", "€".repeat(1366))), "too_large");
  assert.equal(vault.item_field_equals(item.handle, "password", "€".repeat(1365)), false);
  assert.equal(code(() => vault.items_with_field_value([item.handle], "password", `${exact}a`)), "too_large");
});

test("item_field_equals_is_not_a_reveal", () => {
  const { vault } = newAccount("field-equals-not-reveal");
  const item = login(vault, "never-shown");
  // The answer is one boolean: nothing of the value, not its length.
  const yes = vault.item_field_equals(item.handle, "password", "never-shown");
  const no = vault.item_field_equals(item.handle, "password", "never-show");
  assert.equal(yes, true);
  assert.equal(no, false);
  assert.equal(typeof no, "boolean");
  assert.equal(JSON.stringify({ yes, no }), '{"yes":true,"no":false}');
  const dispatch = createDispatcher(wasm);
  // It is not a reveal method: not named so, not on the allow list.
  const allowlist = readFileSync(join(root, "bindings", "wasm", "reveal-allowlist.txt"), "utf8");
  for (const name of ["item_field_equals", "items_with_field_value"]) {
    assert.ok(!name.startsWith("reveal_"));
    assert.ok(!allowlist.includes(name), name);
  }
  // A lone surrogate is refused by the dispatcher (it would be compared as U+FFFD).
  const bad = dispatch({ id: 5, target: "vault", method: "item_field_equals", args: [item.handle, "password", "\udc00"] }).reply;
  assert.deepEqual(bad, { id: 5, ok: false, code: "invalid_input" });
});

// --------------------------------------------------------------- history

test("update_with_keep_history_moves_the_old_password_inside_the_core", () => {
  const { vault } = newAccount("history-move");
  const item = login(vault, "old-secret");
  edit(vault, item, passwordUpdate("new-secret"), NOW + 1000);
  const view = vault.item_view(item.handle);
  assert.deepEqual(view.password_history, [{ until: NOW + 1000 }]);
  assert.equal(vault.reveal_password_history(item.handle, 0), "old-secret");
  assert.equal(vault.item_field_equals(item.handle, "password", "new-secret"), true);
  // Every other field, the addresses and the folders are kept.
  assert.deepEqual(view.fields.find((f) => f.id === "username").value, "anna@example.net");
  assert.deepEqual(view.urls, [{ url: "https://example.com", matching: "host" }]);
  // The old value never came back to this side: the draft held only the new one.
  assert.ok(!JSON.stringify(passwordUpdate("new-secret")).includes("old-secret"));
  // Without the flag no history is kept.
  const plain = login(vault, "first");
  edit(vault, plain, { fields: [{ id: "username" }, { id: "password", value: "second" }] }, NOW + 5);
  assert.deepEqual(vault.item_view(plain.handle).password_history, []);
  // On a new item the flag does nothing.
  const fresh = login(vault, "brand-new", { keep_password_history: true });
  assert.deepEqual(vault.item_view(fresh.handle).password_history, []);
});

test("history_keeps_at_most_five_newest_first", () => {
  const { vault } = newAccount("history-five");
  const item = login(vault, "p0");
  for (let i = 1; i <= 7; i++) edit(vault, item, passwordUpdate(`p${i}`), NOW + i);
  assert.deepEqual(
    vault.item_view(item.handle).password_history,
    [7, 6, 5, 4, 3].map((i) => ({ until: NOW + i })),
  );
  assert.deepEqual(
    [0, 1, 2, 3, 4].map((i) => vault.reveal_password_history(item.handle, i)),
    ["p6", "p5", "p4", "p3", "p2"],
  );
});

test("an_unchanged_password_adds_no_history", () => {
  const { vault } = newAccount("history-unchanged");
  const item = login(vault, "same");
  edit(vault, item, passwordUpdate("same"), NOW + 1);
  edit(vault, item, { name: "Renamed", keep_password_history: true }, NOW + 2);
  edit(vault, item, { fields: [{ id: "username", value: "bob" }, { id: "password" }], keep_password_history: true }, NOW + 3);
  const view = vault.item_view(item.handle);
  assert.deepEqual(view.password_history, []);
  assert.equal(view.name, "Renamed");
});

test("history_is_kept_by_a_reader_that_does_not_know_it", () => {
  // An edit that does not ask for history (an older client's draft) keeps the
  // list that is there, and a copy keeps it too.
  const { vault } = newAccount("history-kept");
  const item = login(vault, "one");
  edit(vault, item, passwordUpdate("two"), NOW + 1);
  edit(vault, item, { name: "Renamed", favorite: true, folders: ["Work"] }, NOW + 2);
  assert.deepEqual(vault.item_view(item.handle).password_history, [{ until: NOW + 1 }]);
  const copyId = newId();
  const copy = vault.copy_item(item.handle, copyId, NOW + 3);
  const h = vault.open_item(copyId, copy.rev, copy.envelope, copy.tag);
  assert.equal(vault.reveal_password_history(h, 0), "one");
  // The earlier password is inside the encrypted body only.
  assert.ok(!Buffer.from(item.sealed.envelope).toString("latin1").includes("password_history"));
});

test("the_draft_has_no_key_for_an_old_password", () => {
  const { vault } = newAccount("history-draft");
  const item = login(vault, "secret");
  // The history cannot be written from JavaScript, under any name.
  for (const key of ["password_history", "history", "old_password", "previous_password"]) {
    const draft = { ...passwordUpdate("x"), [key]: [{ value: "planted", until: 1 }] };
    assert.equal(code(() => vault.encrypt_item(item.id, 2, draft, item.handle, NOW)), "invalid_input", key);
  }
  assert.equal(code(() => vault.encrypt_item(item.id, 2, { keep_password_history: "yes" }, item.handle, NOW)), "invalid_input");
  assert.deepEqual(vault.item_view(item.handle).password_history, [], "nothing was sealed");
  // The draft type has the flag and no field for a value.
  const d = readFileSync(join(root, "bindings", "wasm", "src", "item.rs"), "utf8");
  assert.match(d, /keep_password_history: bool,/);
  assert.ok(!/password_history: Option|history: Option|old_password/.test(d.slice(d.indexOf("pub(crate) struct DraftDto"), d.indexOf("impl DraftDto"))));
});

test("item_view_shows_history_dates_and_never_values", () => {
  const { vault } = newAccount("history-view");
  const item = login(vault, "first-secret-value");
  edit(vault, item, passwordUpdate("second-secret-value"), NOW + 10);
  edit(vault, item, passwordUpdate("third-secret-value"), NOW + 20);
  const view = vault.item_view(item.handle);
  assert.deepEqual(view.password_history, [{ until: NOW + 20 }, { until: NOW + 10 }]);
  const text = JSON.stringify(view);
  for (const s of ["first-secret-value", "second-secret-value", "third-secret-value"]) {
    assert.ok(!text.includes(s), `${s} is in the view`);
  }
  // An item without history has an empty list.
  assert.deepEqual(vault.item_view(login(vault, "x").handle).password_history, []);
});

test("reveal_password_history_returns_one_entry_and_refuses_an_index_out_of_range", () => {
  const { vault } = newAccount("history-reveal");
  const item = login(vault, "a1");
  edit(vault, item, passwordUpdate("a2"), NOW + 1);
  edit(vault, item, passwordUpdate("a3"), NOW + 2);
  assert.equal(vault.reveal_password_history(item.handle, 0), "a2");
  assert.equal(vault.reveal_password_history(item.handle, 1), "a1");
  assert.equal(code(() => vault.reveal_password_history(item.handle, 2)), "invalid_input");
  assert.equal(code(() => vault.reveal_password_history(item.handle, 4294967295)), "invalid_input");
  assert.equal(code(() => vault.reveal_password_history(item.handle + 99999, 0)), "invalid_handle");
  const none = login(vault, "b");
  assert.equal(code(() => vault.reveal_password_history(none.handle, 0)), "invalid_input");
  // The dispatcher types the index.
  const dispatch = createDispatcher(wasm);
  for (const index of [-1, 1.5, "0", 2 ** 32]) {
    const r = dispatch({ id: 6, target: "vault", method: "reveal_password_history", args: [item.handle, index] }).reply;
    assert.deepEqual(r, { id: 6, ok: false, code: "invalid_input" }, String(index));
  }
  vault.lock();
  assert.equal(code(() => vault.reveal_password_history(item.handle, 0)), "vault_locked");
});

test("plain_export_includes_the_history", () => {
  const account = newAccount("history-export");
  const { vault } = account;
  const item = login(vault, "exported-old");
  edit(vault, item, passwordUpdate("exported-new"), NOW + 7);
  const json = JSON.parse(vault.reveal_plain_export([row(item.id, item.sealed)], "json", false, reauthToken(account), NOW));
  assert.deepEqual(json.items[0].body.password_history, [{ value: "exported-old", until: NOW + 7 }]);
});
