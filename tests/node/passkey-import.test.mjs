// The import of a passkey from another program, through the binding
// (`Vault.passkey_import`): the vectors of `passkey_import.json` run through
// the method of the vault, what the item shows afterwards, the arguments, and
// that the key leaves nothing in WASM memory.
// Run: node --test tests/node/passkey-import.test.mjs
import assert from "node:assert/strict";
import { createECDH, createHash, createPublicKey, randomBytes, verify } from "node:crypto";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { test } from "node:test";
import { LOGIN_DRAFT, NOW, codeOf, fill, newAccount, root, wasm } from "./helpers.mjs";

const file = JSON.parse(readFileSync(join(root, "vectors", "internal", "passkey_import.json"), "utf8"));
const hex = (s) => new Uint8Array(Buffer.from(s, "hex"));
const toHex = (b) => Buffer.from(b).toString("hex");

function code(fn) {
  const e = codeOf(fn);
  assert.equal(e.name, "FerretError");
  assert.equal(e.message, e.code, "the message is the code and nothing else");
  return e.code;
}

/** The `passkey` argument of the binding for the input of a vector case. */
function argument(i) {
  const a = {
    cred_id: hex(i.cred_id),
    rp_id: i.rp_id,
    user_handle: hex(i.user_handle),
    user_name: i.user_name,
    created: Number(i.created),
    counter: i.counter,
  };
  if (i.rp_name !== null) a.rp_name = i.rp_name;
  if (i.user_display_name !== null) a.user_display_name = i.user_display_name;
  if (i.key.format === "pkcs8") a.key_pkcs8 = hex(i.key.hex);
  else a.key_jwk = i.key.text;
  if (i.prf) {
    a.prf_seed_uv = hex(i.prf.uv);
    a.prf_seed_nouv = hex(i.prf.nouv);
  }
  return a;
}

const DRAFT = { item_type: "login", name: "Imported" };
const GET = { challenge: fill(32, 3), rp_id: null, allow: [], user_verification: "discouraged" };

function open(vault, id, out) {
  return vault.open_item(id, out.item.rev, out.item.envelope, out.item.tag);
}

function assertSignature(spkiHex, got) {
  const key = createPublicKey({ key: Buffer.from(spkiHex, "hex"), format: "der", type: "spki" });
  const signed = Buffer.concat([
    Buffer.from(got.authenticator_data),
    createHash("sha256").update(Buffer.from(got.client_data_json)).digest(),
  ]);
  assert.ok(verify("sha256", signed, { key, dsaEncoding: "der" }, Buffer.from(got.signature)));
}

test("binding_passkey_import_agrees_with_the_core_vectors", () => {
  const { vault } = newAccount("import-vectors");
  let valid = 0;
  let invalid = 0;
  for (const [n, c] of file.cases.entries()) {
    const id = fill(16, 0x80 + (n % 100));
    const i = c.input;
    if (c.status === "invalid") {
      assert.equal(code(() => vault.passkey_import(id, 1, DRAFT, argument(i), NOW)), c.expect_error, c.id);
      invalid++;
      continue;
    }
    const want = c.expect;
    const out = vault.passkey_import(id, 1, DRAFT, argument(i), NOW);
    assert.deepEqual(out.notes, want.notes, c.id);
    assert.equal(out.rp_id, want.record.rp_id, c.id);
    // The item is sealed and not open; open it and see what it holds.
    const handle = open(vault, id, out);
    const view = vault.item_view(handle);
    assert.equal(view.passkey.rp_id, want.record.rp_id, c.id);
    assert.equal(toHex(view.passkey.cred_id), want.record.cred_id, c.id);
    assert.equal(toHex(view.passkey.user_handle), want.record.user_handle, c.id);
    assert.equal(view.passkey.user_name, want.record.user_name, c.id);
    assert.equal(view.passkey.rp_name, want.record.rp_name, c.id);
    assert.equal(view.passkey.user_display_name, want.record.user_display_name, c.id);
    assert.equal(view.passkey.has_prf, want.record.prf_seed_uv !== null, c.id);
    assert.equal(toHex(vault.test_passkey_secret(handle, "pkcs8")), want.record.priv_pkcs8, c.id);
    for (const [which, key] of [["seed_uv", "prf_seed_uv"], ["seed_nouv", "prf_seed_nouv"]]) {
      const got = vault.test_passkey_secret(handle, which);
      assert.equal(got === undefined || got === null ? null : toHex(got), want.record[key], c.id);
    }
    // The passkey signs for the site, with and without user verification.
    const origin = `https://${want.record.rp_id}`;
    const caller = { origin, top_origin_is_same: true };
    for (const verified of [true, false]) {
      const got = vault.passkey_get(handle, GET, caller, { user_present: true, user_verified: verified });
      assert.equal(toHex(got.id), want.record.cred_id, c.id);
      assertSignature(want.record.public_key_spki, got);
    }
    vault.close_item(handle);
    valid++;
  }
  assert.ok(valid >= 25 && invalid >= 30, `${valid} valid, ${invalid} invalid cases`);
});

test("import_seals_a_new_login_with_the_site_as_its_address", () => {
  const { vault } = newAccount("import-login");
  const base = file.cases.find((c) => c.id === "passkey_import/valid/001");
  const arg = (n) => ({ ...argument(base.input), cred_id: fill(32, 0x20 + n) });
  const id = fill(16, 0x41);
  // No addresses in the draft: the site of the passkey.
  const plain = vault.passkey_import(id, 1, DRAFT, arg(0), NOW);
  assert.equal(plain.item.rev, 1);
  assert.deepEqual(vault.item_view(open(vault, id, plain)).urls.map((u) => u.url), ["https://rp-a.test"]);
  // The rest of the login is the importer's: fields, notes, addresses.
  const full = vault.passkey_import(fill(16, 0x42), 1, { ...LOGIN_DRAFT, name: "Kept" }, arg(1), NOW);
  const view = vault.item_view(open(vault, fill(16, 0x42), full));
  assert.deepEqual(view.urls.map((u) => u.url), ["https://example.com"]);
  assert.equal(view.name, "Kept");
  assert.equal(view.fields.length, 2);
  assert.ok(view.passkey);
  // Nothing is stored or opened by the call itself.
  assert.equal(code(() => vault.item_view(1234)), "invalid_handle");
});

test("item_view_hides_priv_and_seeds_after_import", () => {
  const { vault } = newAccount("import-view");
  const withPrf = file.cases.find((c) => c.id === "passkey_import/valid/006");
  const id = fill(16, 0x43);
  const out = vault.passkey_import(id, 1, DRAFT, argument(withPrf.input), NOW);
  // The reply is the sealed item, the site and the notes: nothing else.
  assert.deepEqual(Object.keys(out).sort(), ["item", "notes", "rp_id"]);
  assert.deepEqual(Object.keys(out.notes).sort(), ["counter", "prf", "register_again"]);
  const handle = open(vault, id, out);
  const view = vault.item_view(handle);
  assert.deepEqual(Object.keys(view.passkey).sort(), [
    "created", "cred_id", "has_prf", "rp_id", "rp_name", "user_display_name", "user_handle", "user_name",
  ]);
  const secrets = ["scalar", "pkcs8", "seed_uv", "seed_nouv"].map((w) => vault.test_passkey_secret(handle, w));
  assert.ok(secrets.every((s) => s && s.length >= 32));
  const hexes = secrets.map(toHex);
  const walk = (v) => (v instanceof Uint8Array ? [toHex(v)] : v && typeof v === "object" ? Object.values(v).flatMap(walk) : []);
  const shown = [view, out].flatMap(walk).join(" ") + JSON.stringify(view) + JSON.stringify(out.notes) + out.rp_id;
  for (const h of hexes) assert.ok(!shown.includes(h), "a secret of the passkey is in what JavaScript gets");
  // The sealed envelope is ciphertext: the key is not in it either.
  const envelope = toHex(out.item.envelope);
  for (const h of hexes) assert.ok(!envelope.includes(h));
});

test("import_checks_its_arguments", () => {
  const { vault } = newAccount("import-args");
  const good = file.cases.find((c) => c.id === "passkey_import/valid/006").input;
  const id = fill(16, 0x44);
  const call = (arg, draft = DRAFT, item = id, rev = 1, now = NOW) => code(() => vault.passkey_import(item, rev, draft, arg, now));
  const a = () => argument(good);
  assert.ok(vault.passkey_import(id, 1, DRAFT, a(), NOW));

  // A key in both forms, or in none; one seed alone; a key that is not bytes or text.
  assert.equal(call({ ...a(), key_pkcs8: fill(138, 1) }), "invalid_input");
  const noKey = a();
  delete noKey.key_jwk;
  assert.equal(call(noKey), "invalid_input");
  const oneSeed = a();
  delete oneSeed.prf_seed_nouv;
  assert.equal(call(oneSeed), "invalid_input");
  assert.equal(call({ ...a(), key_jwk: 7 }), "invalid_input");
  assert.equal(call({ ...a(), cred_id: "abc" }), "invalid_input");
  assert.equal(call({ ...a(), user_handle: [1, 2, 3] }), "invalid_input");
  // Fields that do not exist, and numbers that are not whole.
  assert.equal(call({ ...a(), private_key: fill(32, 1) }), "invalid_input");
  assert.equal(call({ ...a(), counter: 1.5 }), "invalid_input");
  assert.equal(call({ ...a(), counter: -1 }), "invalid_input");
  assert.equal(call({ ...a(), counter: 2 ** 32 }), "invalid_input");
  assert.equal(call({ ...a(), created: -1 }), "invalid_input");
  assert.equal(call({ ...a(), created: "1" }), "invalid_input");
  const noCreated = a();
  delete noCreated.created;
  assert.equal(call(noCreated), "invalid_input");
  assert.equal(call(null), "invalid_input");
  // The draft is the draft of a new item and has no passkey of its own.
  assert.equal(call(a(), { name: "No type" }), "invalid_input");
  assert.equal(call(a(), { ...DRAFT, remove_passkey: true }), "invalid_input");
  assert.equal(call(a(), { ...DRAFT, passkey: { user_name: "x" } }), "invalid_input");
  assert.equal(call(a(), { ...DRAFT, private_key: "x" }), "invalid_input");
  // A passkey is kept in a login only.
  for (const item_type of ["note", "card", "Login", "", "something"]) {
    assert.equal(call(a(), { ...DRAFT, item_type }), "invalid_input", item_type);
  }
  // The item id: 16 bytes, and not the manifest.
  assert.equal(call(a(), DRAFT, fill(15, 1)), "invalid_input");
  assert.equal(call(a(), DRAFT, fill(16, 0)), "invalid_input");
  assert.equal(call(a(), DRAFT, id, 1.5), "invalid_input");
  assert.equal(call(a(), DRAFT, id, 1, -1), "invalid_input");
  // A passkey that is already in an open item is not made twice.
  const first = vault.passkey_import(fill(16, 0x45), 1, DRAFT, a(), NOW);
  open(vault, fill(16, 0x45), first);
  assert.equal(call(a(), DRAFT, fill(16, 0x46)), "invalid_state");
  // A locked vault answers nothing.
  vault.lock();
  assert.equal(call(a()), "vault_locked");
});

// ----------------------------------------------------------- the memory

/** Every place of `needle` in the linear memory, in overlapping pieces of 1 MiB. */
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

/** A key nobody has seen: the scalar, the PKCS#8 in the form Bitwarden writes, and the JWK of AliasVault. */
function freshKey() {
  const ecdh = createECDH("prime256v1");
  ecdh.generateKeys();
  // Node drops leading zero bytes of the scalar (about 1 run in 256): pad it to the 32 bytes PKCS#8 and JWK need.
  const raw = ecdh.getPrivateKey();
  const d = Buffer.concat([Buffer.alloc(32 - raw.length), raw]);
  const point = ecdh.getPublicKey(); // 04 || x || y
  const pkcs8 = Buffer.concat([
    Buffer.from("308187020100301306072a8648ce3d020106082a8648ce3d030107046d306b020101" + "0420", "hex"),
    d,
    Buffer.from("a144034200", "hex"),
    point,
  ]);
  const b64 = (b) => Buffer.from(b).toString("base64url");
  const jwk = `{"kty":"EC","crv":"P-256","x":"${b64(point.subarray(1, 33))}","y":"${b64(point.subarray(33))}","d":"${b64(d)}"}`;
  return { d, pkcs8, jwk, dText: b64(d) };
}

const input = (key, form) => ({
  cred_id: randomBytes(32),
  rp_id: "memory.example",
  user_handle: randomBytes(16),
  user_name: "u",
  created: 1,
  ...(form === "pkcs8" ? { key_pkcs8: new Uint8Array(key.pkcs8) } : { key_jwk: key.jwk }),
});

test("import_takes_the_key_as_owned_bytes_and_zeroizes", () => {
  const { vault } = newAccount("import-wipe");
  // Control: an open item holds its key in memory, and the scan sees it.
  const seen = freshKey();
  const out = vault.passkey_import(fill(16, 0x51), 1, DRAFT, input(seen, "pkcs8"), NOW);
  const handle = open(vault, fill(16, 0x51), out);
  assert.ok(findInMemory(seen.d).length > 0, "the scan sees the scalar of an open passkey");
  vault.close_item(handle);

  // The key given as bytes, and as text: nothing of it stays after the call.
  for (const form of ["pkcs8", "jwk"]) {
    const key = freshKey();
    const argument = input(key, form);
    // `pkcs8` is the argument the caller still holds; the copy the call made
    // is what must be gone. The caller wipes its own array.
    vault.passkey_import(fill(16, 0x52), 1, DRAFT, argument, NOW);
    if (argument.key_pkcs8) argument.key_pkcs8.fill(0);
    assert.deepEqual(findInMemory(key.d), [], `${form}: the scalar is not left`);
    assert.deepEqual(findInMemory(key.pkcs8), [], `${form}: the PKCS#8 is not left`);
    assert.deepEqual(findInMemory(Buffer.from(key.dText)), [], `${form}: the text of d is not left`);
    assert.deepEqual(findInMemory(Buffer.from(key.jwk)), [], `${form}: the JWK text is not left`);
  }

  // A refused import wipes what it read as well: a key whose public part is
  // not its own, a site that is a public suffix, a duplicate.
  const key = freshKey();
  const other = freshKey();
  const bad = `{"kty":"EC","crv":"P-256","x":"${other.dText}","y":"${other.dText}","d":"${key.dText}"}`;
  assert.equal(code(() => vault.passkey_import(fill(16, 0x53), 1, DRAFT, { ...input(key, "jwk"), key_jwk: bad }, NOW)), "malformed_item_body");
  assert.equal(code(() => vault.passkey_import(fill(16, 0x53), 1, DRAFT, { ...input(key, "pkcs8"), rp_id: "co.uk" }, NOW)), "malformed_rp_id");
  const seeds = { prf_seed_uv: randomBytes(32), prf_seed_nouv: randomBytes(31) };
  assert.equal(code(() => vault.passkey_import(fill(16, 0x53), 1, DRAFT, { ...input(key, "pkcs8"), ...seeds }, NOW)), "malformed_item_body");
  // A value of the wrong type after the key and the seeds are read: the
  // pieces that were read are wiped when they are thrown away.
  const late = freshKey();
  const lateSeeds = { prf_seed_uv: randomBytes(32), prf_seed_nouv: randomBytes(32) };
  for (const [form, wrong] of [["pkcs8", { counter: "7" }], ["jwk", { counter: "7" }], ["pkcs8", { created: "1" }]]) {
    const argument = { ...input(late, form), ...lateSeeds, ...wrong };
    assert.equal(code(() => vault.passkey_import(fill(16, 0x54), 1, DRAFT, argument, NOW)), "invalid_input", form);
    if (argument.key_pkcs8) argument.key_pkcs8.fill(0);
  }
  assert.deepEqual(findInMemory(late.d), [], "a refused argument leaves no scalar");
  assert.deepEqual(findInMemory(late.pkcs8), [], "a refused argument leaves no PKCS#8");
  assert.deepEqual(findInMemory(Buffer.from(late.dText)), [], "a refused argument leaves no text of d");
  assert.deepEqual(findInMemory(Buffer.from(late.jwk)), [], "a refused argument leaves no JWK text");
  assert.deepEqual(findInMemory(Buffer.from(lateSeeds.prf_seed_uv)), [], "a refused argument leaves no seed");
  assert.deepEqual(findInMemory(Buffer.from(lateSeeds.prf_seed_nouv)), [], "a refused argument leaves no second seed");
  assert.deepEqual(findInMemory(key.d), [], "a refused import leaves no scalar");
  assert.deepEqual(findInMemory(key.pkcs8), [], "a refused import leaves no PKCS#8");
  assert.deepEqual(findInMemory(Buffer.from(key.dText)), [], "a refused import leaves no text of d");
  assert.deepEqual(findInMemory(Buffer.from(seeds.prf_seed_uv)), [], "a refused import leaves no seed");
});
