// The import worker: it reads the file, makes the drafts, sends them over the vault port and answers
// with envelopes, counts and warnings only.
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { test } from "node:test";
import { createHandler, KINDS, NO_EXISTING, runImport } from "../../src/workers/import.worker.mjs";
import { ImportError } from "../../src/import/limits.mjs";
import { allStrings, bitwardenDir, fixture, fixtureFile, sealedValue, textFile, vaultPort } from "./importHelpers.mjs";

const NOW = 1_700_000_000_000;
let counter = 0;
/** Ids that are unique and never zero. */
const random = (bytes) => {
  bytes.fill(0);
  new DataView(bytes.buffer).setUint32(0, ++counter);
  bytes[15] = 1;
  return bytes;
};
const handler = (extra = {}) => createHandler({ now: () => NOW, random, ...extra });
const request = (file, port, extra = {}) => ({ id: 7, kind: "bitwarden_json", file, port, ...extra });

/** Words from the fixtures that must never be in what the page gets. */
const SECRET_WORDS = ["synthetic-password", "alice@example.test", "GEZDGNBV", "example.test", "Synthetic notes", "Every login field", "0000000000000000", "Alice Example", "hidden value", "A secure note"];

test("the_worker_sends_drafts_only_over_the_vault_port_and_answers_with_envelopes_counts_and_warnings", async () => {
  const port = vaultPort();
  const reply = await handler()(request(fixtureFile("every-type.json"), port));

  assert.deepEqual(Object.keys(reply).sort(), ["id", "kind", "ok", "report", "sealed"]);
  assert.equal(reply.kind, "bitwarden_json");
  assert.equal(reply.id, 7);
  assert.equal(reply.ok, true);

  // Eight drafts went over the port, each the one message the vault's import port takes.
  assert.equal(port.sent.length, 8);
  const ids = new Set();
  for (const message of port.sent) {
    assert.deepEqual(Object.keys(message).sort(), ["args", "id", "method"]);
    assert.equal(message.method, "encrypt_item");
    assert.equal(message.args.length, 5);
    const [itemId, rev, draft, existing, now] = message.args;
    assert.ok(itemId instanceof Uint8Array && itemId.length === 16 && !itemId.every((b) => b === 0));
    assert.equal(rev, 1);
    assert.equal(existing, NO_EXISTING);
    assert.equal(existing, "no_existing");
    assert.equal(now, NOW);
    assert.ok(draft && typeof draft === "object" && !Array.isArray(draft));
    assert.equal("passkey" in draft, false);
    for (const key of Object.keys(draft)) assert.ok(["item_type", "name", "favorite", "fields", "urls", "totp", "notes", "folders"].includes(key), key);
    if ("folders" in draft) assert.ok(Array.isArray(draft.folders) && draft.folders.every((name) => typeof name === "string"), "folders is a list of names");
    ids.add(Buffer.from(itemId).toString("hex"));
  }
  assert.equal(ids.size, 8, "every item has its own id");
  assert.deepEqual(new Set(port.sent.map((m) => m.id)).size, 8);

  // What the page gets: ids and envelopes, in the order of the file, and a report.
  assert.equal(reply.sealed.length, 8);
  reply.sealed.forEach((sealed, i) => {
    assert.deepEqual(Object.keys(sealed).sort(), ["envelope", "id", "rev", "tag"]);
    assert.equal(sealed.rev, 1);
    assert.ok(sealed.envelope instanceof Uint8Array);
    assert.ok(sealed.tag instanceof Uint8Array && sealed.tag.length === 32);
    assert.deepEqual([...sealed.id], [...port.sent[i].args[0]]);
  });
  assert.equal(reply.report.counts.items, 8);
  assert.equal(reply.report.counts.sealed, 8);
  assert.ok(reply.report.warnings.length > 5);
  for (const w of reply.report.warnings) assert.deepEqual(Object.keys(w).sort(), ["code", "index"]);
  // The port is closed and let go of when the import is over.
  assert.equal(port.closed, true);
  assert.equal(port.onmessage, null);
});

test("no_draft_and_no_file_byte_ever_reaches_the_main_thread", async () => {
  // What the page can see is the reply and nothing else: look at all of it.
  for (const [kind, name] of [["bitwarden_json", "every-type.json"], ["bitwarden_csv", "small.csv"]]) {
    const port = vaultPort();
    const reply = await handler()({ id: 1, kind, file: fixtureFile(name), port });
    assert.equal(reply.ok, true, name);
    const seen = JSON.stringify(reply, (_, v) => (v instanceof Uint8Array ? `<${v.length} bytes>` : v));
    for (const word of SECRET_WORDS) assert.ok(!seen.includes(word), `${name}: ${word}`);
    // Not the file, not a draft, not the port: numbers, codes and byte arrays only.
    assert.equal("file" in reply, false);
    assert.equal("port" in reply, false);
    assert.equal("drafts" in reply, false);
    for (const text of allStrings({ ...reply, sealed: [] })) {
      assert.ok(/^[a-z0-9_]+$/i.test(text), `a reply holds only codes and keys: ${text}`);
    }
  }
  // A refusal has no text of the file either.
  for (const [kind, text] of [["bitwarden_json", '{"__proto__": 1, "secret-key": "secret-value"}'], ["bitwarden_csv", 'name,x\n"secret-value"y,1\n'], ["bitwarden_json", '{"encrypted": true, "data": "secret-value"}']]) {
    const reply = await handler()({ id: 2, kind, file: textFile(text), port: vaultPort() });
    assert.equal(reply.ok, false);
    assert.ok(!JSON.stringify(reply).includes("secret"), JSON.stringify(reply));
  }

  // The same, in a process that looks like a worker: every message the worker posts to the page is
  // collected and none holds a draft or a byte of the file.
  const script = `
    import { readFileSync } from "node:fs";
    class WorkerGlobalScope {}
    Object.setPrototypeOf(globalThis, WorkerGlobalScope.prototype);
    globalThis.WorkerGlobalScope = WorkerGlobalScope;
    const toPage = [];
    globalThis.postMessage = (m) => toPage.push(m);
    await import(process.argv[1]);
    const file = new File([readFileSync(process.argv[2])], "every-type.json");
    const toVault = [];
    const port = {
      onmessage: null,
      postMessage(m) {
        toVault.push(m);
        setImmediate(() => port.onmessage?.({ data: { id: m.id, ok: true, value: { rev: 1, envelope: new Uint8Array([1]), tag: new Uint8Array(32) } } }));
      },
      close() {},
    };
    await globalThis.onmessage({ data: { id: 5, kind: "bitwarden_json", file, port } });
    await globalThis.onmessage({ data: { id: 6, kind: "bitwarden_json", file, port } });
    console.log(JSON.stringify({ toPage: toPage.map((m) => JSON.stringify(m)), vault: toVault.length }));
  `;
  const url = new URL("../../src/workers/import.worker.mjs", import.meta.url).href;
  const run = spawnSync(process.execPath, ["--input-type=module", "-e", script, url, `${bitwardenDir}/every-type.json`], { encoding: "utf8" });
  assert.equal(run.status, 0, run.stderr);
  const out = JSON.parse(run.stdout);
  assert.equal(out.vault, 8);
  assert.equal(out.toPage.length, 2, "one answer per message");
  const [first, second] = out.toPage.map((m) => JSON.parse(m));
  assert.equal(first.id, 5);
  assert.equal(first.ok, true);
  assert.equal(first.sealed.length, 8);
  // The second request is refused: a worker does one import.
  assert.deepEqual(second, { id: 6, ok: false, error: "unsupported" });
  for (const word of SECRET_WORDS) assert.ok(!out.toPage.join("").includes(word), word);
});

test("an_item_id_is_never_the_all_zero_id", async () => {
  let calls = 0;
  const port = vaultPort();
  // The first two draws are zeros (the id of the manifest); they are drawn again.
  const reply = await handler({ random: (bytes) => (++calls <= 2 ? bytes.fill(0) : bytes.fill(9)) })(request(textFile(JSON.stringify({ items: [{ type: 2, name: "a" }] })), port));
  assert.equal(reply.ok, true);
  assert.equal(calls, 3);
  assert.deepEqual([...port.sent[0].args[0]], new Array(16).fill(9));
});

test("the_worker_works_over_a_real_message_channel", async () => {
  const { port1, port2 } = new MessageChannel();
  const seen = [];
  port2.onmessage = (event) => {
    seen.push(event.data);
    port2.postMessage({ id: event.data.id, ok: true, value: sealedValue(event.data.id) });
  };
  try {
    const reply = await handler()(request(fixtureFile("small.json"), port1));
    assert.equal(reply.ok, true);
    assert.equal(reply.sealed.length, 2);
    assert.equal(seen.length, 2);
    assert.deepEqual(seen[0].args[2].item_type, "login");
    assert.ok(seen[0].args[0] instanceof Uint8Array);
    assert.equal(seen[0].args[3], "no_existing");
  } finally {
    port2.close();
    port1.close();
  }
});

test("at_most_16_drafts_are_in_flight_and_a_big_file_goes_through", async () => {
  const items = Array.from({ length: 200 }, (_, i) => ({ type: 2, name: `Note ${i}`, notes: `body ${i}` }));
  let outstanding = 0;
  let most = 0;
  const port = vaultPort({
    reply: (message) => {
      outstanding--;
      return { id: message.id, ok: true, value: sealedValue(message.id) };
    },
  });
  const post = port.postMessage;
  port.postMessage = (message) => {
    outstanding++;
    most = Math.max(most, outstanding);
    post(message);
  };
  const reply = await handler()(request(textFile(JSON.stringify({ encrypted: false, items })), port));
  assert.equal(reply.ok, true);
  assert.equal(reply.sealed.length, 200);
  assert.ok(most <= 16 && most > 1, `most in flight: ${most}`);
  // In the order of the file.
  assert.deepEqual(port.sent.map((m) => m.args[2].name), items.map((i) => i.name));
});

test("an_otpauth_address_the_core_refuses_is_sent_again_as_a_hidden_field_with_a_warning", async () => {
  const text = JSON.stringify({ encrypted: false, items: [{ type: 1, name: "A", login: { username: "u", totp: "otpauth://totp/x?secret=ABC&algorithm=MD5" } }, { type: 1, name: "B", login: { totp: "GEZDGNBVGY3TQOJQ" } }] });
  const port = vaultPort({
    reply: (message) => (message.args[2].totp?.uri.includes("MD5") ? { id: message.id, ok: false, code: "malformed_otpauth" } : { id: message.id, ok: true, value: sealedValue(message.id) }),
  });
  const reply = await handler()(request(textFile(text), port));
  assert.equal(reply.ok, true);
  assert.equal(reply.sealed.length, 2);
  // A was sent twice: with the address, then without it and with a hidden field.
  const a = port.sent.filter((m) => m.args[2].name === "A");
  assert.equal(a.length, 2);
  assert.ok(a[0].args[2].totp);
  assert.equal(a[1].args[2].totp, undefined);
  assert.deepEqual(a[1].args[2].fields.at(-1), { id: "totp", label: "One-time password", kind: "hidden", value: "otpauth://totp/x?secret=ABC&algorithm=MD5" });
  // The same id: it is the same item.
  assert.deepEqual([...a[0].args[0]], [...a[1].args[0]]);
  assert.deepEqual(reply.report.warnings, [{ code: "totp_invalid", index: 0 }]);
  assert.equal(reply.report.counts.totp, 1);
  assert.equal(reply.report.counts.sealed, 2);
});

test("an_otpauth_address_the_core_cannot_normalise_is_kept_as_a_hidden_field_and_does_not_stop_the_import", async () => {
  // A bad percent escape in the issuer: the vault answers invalid_input, not malformed_otpauth.
  const address = "otpauth://totp/Example:alice?secret=GEZDGNBVGY3TQOJQ&issuer=50%off";
  const text = JSON.stringify({ encrypted: false, items: [{ type: 1, name: "A", login: { totp: address } }, { type: 1, name: "B", login: { totp: "GEZDGNBVGY3TQOJQ" } }] });
  const port = vaultPort({
    reply: (message) => (message.args[2].totp?.uri.includes("%off") ? { id: message.id, ok: false, code: "invalid_input" } : { id: message.id, ok: true, value: sealedValue(message.id) }),
  });
  const reply = await handler()(request(textFile(text), port));
  assert.equal(reply.ok, true);
  assert.equal(reply.sealed.length, 2);
  const a = port.sent.filter((m) => m.args[2].name === "A");
  assert.equal(a.length, 2);
  assert.equal(a[1].args[2].totp, undefined);
  assert.deepEqual(a[1].args[2].fields.at(-1), { id: "totp", label: "One-time password", kind: "hidden", value: address });
  // The same item id, so no item twice.
  assert.deepEqual([...a[0].args[0]], [...a[1].args[0]]);
  assert.deepEqual(reply.report.warnings, [{ code: "totp_invalid", index: 0 }]);
  assert.equal(reply.report.counts.totp, 1);
  assert.equal(reply.report.counts.sealed, 2);
  // Only once: when the second try is refused too, the import stops as for any other refusal.
  const stubborn = vaultPort({ reply: (message) => (message.args[2].name === "A" ? { id: message.id, ok: false, code: "invalid_input" } : { id: message.id, ok: true, value: sealedValue(message.id) }) });
  assert.deepEqual(await handler()(request(textFile(text), stubborn)), { id: 7, ok: false, error: "import_seal_failed" });
  assert.equal(stubborn.sent.filter((m) => m.args[2].name === "A").length, 2);
});

test("an_item_that_is_too_large_is_left_out_with_a_warning_and_the_rest_is_stored", async () => {
  const text = JSON.stringify({ encrypted: false, items: [{ type: 2, name: "small" }, { type: 2, name: "huge" }, { type: 2, name: "small 2" }] });
  const port = vaultPort({ reply: (message) => (message.args[2].name === "huge" ? { id: message.id, ok: false, code: "too_large" } : { id: message.id, ok: true, value: sealedValue(message.id) }) });
  const reply = await handler()(request(textFile(text), port));
  assert.equal(reply.ok, true);
  assert.equal(reply.sealed.length, 2);
  assert.deepEqual(reply.report.warnings, [{ code: "item_too_large", index: 1 }]);
  assert.equal(reply.report.skipped.tooLarge, 1);
  assert.equal(reply.report.counts.sealed, 2);
});

test("any_other_refusal_of_the_vault_stops_the_import_and_a_closed_port_does_too", async () => {
  const text = JSON.stringify({ encrypted: false, items: Array.from({ length: 5 }, (_, i) => ({ type: 2, name: `n${i}` })) });
  for (const code of ["vault_locked", "invalid_input", "internal"]) {
    const port = vaultPort({ reply: (message) => ({ id: message.id, ok: false, code }) });
    const reply = await handler()(request(textFile(text), port));
    assert.deepEqual(reply, { id: 7, ok: false, error: "import_seal_failed" });
    assert.equal(port.closed, true);
    assert.equal(port.onmessage, null);
  }
  // A reply that is not a sealed item is a refusal too.
  const bad = vaultPort({ reply: (message) => ({ id: message.id, ok: true, value: { rev: 1 } }) });
  assert.deepEqual(await handler()(request(textFile(text), bad)), { id: 7, ok: false, error: "import_seal_failed" });
  // The vault was locked: the port says so and closes.
  const closed = vaultPort({ reply: () => ({ closed: true }) });
  assert.deepEqual(await handler()(request(textFile(text), closed)), { id: 7, ok: false, error: "import_port_closed" });
  assert.equal(closed.closed, true);
  // The reason is a code of the vault, kept on the error and never a text.
  await assert.rejects(runImport(request(textFile(text), vaultPort({ reply: (m) => ({ id: m.id, ok: false, code: "vault_locked" }) }))), (error) => error instanceof ImportError && error.reason === "vault_locked");
});

test("a_refused_file_is_answered_with_a_code_and_the_port_is_never_used", async () => {
  const cases = [
    [fixtureFile("encrypted.json"), "bitwarden_json", "import_encrypted_export"],
    [fixtureFile("password-protected.json"), "bitwarden_json", "import_encrypted_export"],
    [fixtureFile("hostile.json"), "bitwarden_json", "import_bad_key"],
    [fixtureFile("huge-depth.json"), "bitwarden_json", "import_too_deep"],
    [textFile("not json"), "bitwarden_json", "import_bad_json"],
    [textFile('{"items":[]}'), "bitwarden_json", "import_empty"],
    [textFile("name,type\n"), "bitwarden_csv", "import_empty"],
    [textFile("a,b\n1,2\n"), "bitwarden_csv", "import_bad_format"],
  ];
  for (const [file, kind, error] of cases) {
    const port = vaultPort();
    const reply = await handler()({ id: 3, kind, file, port });
    assert.deepEqual(reply, { id: 3, ok: false, error }, `${kind} ${error}`);
    assert.equal(port.sent.length, 0);
    assert.equal(port.closed, true);
  }
  // A CSV error carries its line.
  const reply = await handler()({ id: 4, kind: "bitwarden_csv", file: textFile('name,notes\nA,b\nB,x"y\n'), port: vaultPort() });
  assert.deepEqual(reply, { id: 4, ok: false, error: "import_bad_csv", line: 3 });
});

test("a_zip_file_is_refused_before_it_is_read_as_text", async () => {
  const zip = new File([new Uint8Array([0x50, 0x4b, 0x03, 0x04, 0x14, 0x00, 0x00, 0x00, 0x08, 0x00]), "x".repeat(100)], "export.zip");
  let read = 0;
  zip.text = async () => {
    read++;
    return "";
  };
  for (const kind of KINDS.filter((k) => k !== "aliasvault_avux")) {
    const reply = await handler()({ id: 9, kind, file: zip, port: vaultPort() });
    assert.deepEqual(reply, { id: 9, ok: false, error: "import_zip" }, kind);
  }
  // An .avux file is a ZIP file: its bytes are read, but only by the ZIP reader, which refuses this one.
  const avux = await handler()({ id: 9, kind: "aliasvault_avux", file: zip, port: vaultPort() });
  assert.deepEqual(avux, { id: 9, ok: false, error: "import_bad_zip" });
  assert.equal(read, 0);
});

test("anything_that_is_not_an_import_request_is_unsupported_and_a_worker_does_one_import", async () => {
  const good = () => request(fixtureFile("small.json"), vaultPort());
  /** @type {[string, any][]} */
  const bad = [
    ["no message", undefined],
    ["null", null],
    ["a number", 5],
    ["no id", { ...good(), id: undefined }],
    ["an object id", { ...good(), id: {} }],
    ["no kind", { ...good(), kind: undefined }],
    ["a kind that does not exist", { ...good(), kind: "bitwarden_zip" }],
    ["a kind of the prototype", { ...good(), kind: "constructor" }],
    ["a file that is text", { ...good(), file: "text" }],
    ["no file", { ...good(), file: undefined }],
    ["no port", { ...good(), port: undefined }],
    ["a port without close", { ...good(), port: { postMessage() {} } }],
    ["a port that is a string", { ...good(), port: "port" }],
  ];
  for (const [what, message] of bad) {
    const one = handler();
    const reply = await one(message);
    assert.deepEqual(Object.keys(reply).sort(), ["error", "id", "ok"], what);
    assert.equal(reply.ok, false, what);
    assert.equal(reply.error, "unsupported", what);
    // A refused message does not use up the worker's one import.
    assert.equal((await one(good())).ok, true, what);
  }
  const one = handler();
  assert.equal((await one(good())).ok, true);
  assert.deepEqual(await one(good()), { id: 7, ok: false, error: "unsupported" });
  assert.deepEqual([...KINDS], ["bitwarden_json", "bitwarden_csv", "aliasvault_csv", "aliasvault_avux", "csv"]);
  assert.ok(Object.isFrozen(KINDS));
  assert.equal(fixture("small.json").length > 0, true);
});
