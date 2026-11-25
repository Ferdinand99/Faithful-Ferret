// The import of passkeys from another password manager's file, end to end in Node: the web vault's import worker reads the file and
// sends each passkey over a real import port to the real vault worker (the dispatcher) and the real WASM core, which seals it; the item
// is then opened and the passkey signs for its site. Plus the rules of the port for `passkey_import`.
// The files are throwaway test data (web/test/fixtures/import): keys for rp-a.test, made for these tests and registered nowhere.
// Run: node --test tests/node/import-passkeys.test.mjs
import assert from "node:assert/strict";
import { createECDH, createHash, createHmac, createPrivateKey, createPublicKey, verify } from "node:crypto";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { test } from "node:test";
import { createClient } from "../../bindings/wasm/js/client.mjs";
import { IMPORT_PORT, createDispatcher, createJobDispatcher, importCall, NO_EXISTING } from "../../bindings/wasm/js/protocol.mjs";
import { runImport } from "../../web/src/workers/import.worker.mjs";
import { passkeyKey } from "../../web/src/import/passkeys.mjs";
import { zip } from "../../web/test/unit/zipHelper.mjs";
import { IDS, NOW, PASSWORD, URL_, enc, fill, root, wasm } from "./helpers.mjs";

const fixtures = join(root, "web", "test", "fixtures", "import");
const read = (...parts) => readFileSync(join(fixtures, ...parts), "utf8");
const expected = JSON.parse(read("passkeys-expected.json")).passkeys;
const bitwardenText = read("bitwarden", "passkeys.json");
const manifestText = read("aliasvault", "passkeys-manifest.json");
const nss = readFileSync(join(root, "crates", "ferret-core", "tests", "data", "import", "firefox-pkcs8.txt"), "utf8")
  .split("\n").filter(Boolean).map((line) => line.split(" ")[1]);

class FakeWorker {
  constructor(dispatch) {
    this.dispatch = dispatch;
    this.terminated = false;
    this.ports = [];
  }

  postMessage(message, transfer = []) {
    const ports = transfer.filter((t) => t instanceof MessagePort);
    const copy = structuredClone(message, { transfer: transfer.filter((t) => !(t instanceof MessagePort)) });
    this.ports.push(...ports);
    queueMicrotask(() => {
      if (this.terminated) return;
      const { reply, transfer: out } = this.dispatch(copy, ports);
      this.onmessage?.({ data: structuredClone(reply, { transfer: out }) });
    });
  }

  terminate() {
    this.terminated = true;
    for (const port of this.ports) port.close();
  }
}

/** A client over the real dispatcher and the real core, with a new account open. */
async function clientWithVault(seed) {
  const client = createClient({
    createVaultWorker: () => new FakeWorker(createDispatcher(wasm)),
    createJobWorker: () => new FakeWorker(createJobDispatcher(wasm)),
  });
  const server = new wasm.TestServer(enc.encode(seed));
  const request = await client.vault.register_start(enc.encode(PASSWORD), { kind: "generate" });
  await client.vault.register_finish(server.register_response(IDS.account_id, request), 1);
  await client.vault.create_account(URL_, IDS);
  return client;
}

let counter = 0;
const random = (bytes) => {
  bytes.fill(0);
  new DataView(bytes.buffer).setUint32(0, ++counter);
  bytes[15] = 7;
  return bytes;
};

/** Runs the worker on `file` over a real port of `client`; the passkeys of the vault are `known`. */
const importFile = (client, file, kind, known = []) =>
  runImport({ id: 1, kind, file, port: client.importPort(), passkeys: { known } }, { now: () => NOW, random });

const GET = { challenge: fill(32, 3), rp_id: null, allow: [], user_verification: "discouraged" };
const b64u = (bytes) => Buffer.from(bytes).toString("base64url");

/** Opens a sealed item, and signs for its site; returns what the vault shows of the item and the answer. */
async function openAndSign(client, sealed, { uv = true, prf = undefined } = {}) {
  const handle = await client.vault.open_item(sealed.id, sealed.rev, sealed.envelope, sealed.tag);
  const view = await client.vault.item_view(handle);
  let got = null;
  if (view.passkey) {
    const caller = { origin: `https://${view.passkey.rp_id}`, top_origin_is_same: true };
    got = await client.vault.passkey_get(handle, { ...GET, ...(prf ? { prf } : {}) }, caller, { user_present: true, user_verified: uv });
  }
  await client.vault.close_item(handle);
  return { view, got };
}

function assertSigns(spki, got) {
  const key = typeof spki === "string" ? createPublicKey({ key: Buffer.from(spki, "base64"), format: "der", type: "spki" }) : spki;
  const signed = Buffer.concat([Buffer.from(got.authenticator_data), createHash("sha256").update(Buffer.from(got.client_data_json)).digest()]);
  assert.ok(verify("sha256", signed, { key, dsaEncoding: "der" }, Buffer.from(got.signature)), "the signature verifies against the public key of the file");
}

test("bitwarden_fido2_credentials_import_and_sign_on_the_fixture", async () => {
  const client = await clientWithVault("web-import-bitwarden");
  const done = await importFile(client, new File([bitwardenText], "export.json"), "bitwarden_json");
  assert.equal(done.sealed.length, 3);
  assert.equal(done.report.counts.passkeys, 2);
  assert.equal(done.report.passkeys.skipped.not_discoverable, 1);
  assert.equal(done.report.passkeys.registerAgain, 1);
  assert.deepEqual(done.report.passkeys.sites, ["rp-a.test"]);

  // The two passkeys sign for the site, with and without user verification, and the item is the login they came with.
  for (const [n, want] of [[0, expected[0]], [1, expected[1]]]) {
    for (const uv of [true, false]) {
      const { view, got } = await openAndSign(client, done.sealed[n], { uv });
      assert.equal(view.item_type, "login");
      assert.equal(view.name, `Import test Bitwarden ${n + 1}`);
      assert.equal(view.passkey.rp_id, "rp-a.test");
      assert.equal(view.passkey.user_name, `import-test-${n + 1}@rp-a.test`);
      assert.equal(view.passkey.rp_name, "RP A (test)");
      assert.equal(view.passkey.has_prf, false);
      assert.equal(view.fields.find((f) => f.id === "username").value, `import-test-${n + 1}@rp-a.test`);
      assert.deepEqual(view.urls.map((u) => u.url), ["https://rp-a.test/"]);
      assert.equal(b64u(got.id), want.credentialIdRawB64u, "the credential id of the file, as bytes");
      assert.equal(b64u(view.passkey.user_handle), want.userHandleB64u);
      assertSigns(want.publicKeySpkiB64, got);
    }
  }
  // The passkey that is not discoverable is not imported; its login is.
  const third = await openAndSign(client, done.sealed[2]);
  assert.equal(third.view.passkey, null);
  assert.equal(third.view.name, "Import test Bitwarden 3");
  await client.lock();
});

test("a_passkey_is_not_imported_twice_and_a_second_run_leaves_the_first_alone", async () => {
  const client = await clientWithVault("web-import-twice");
  const first = await importFile(client, new File([bitwardenText], "export.json"), "bitwarden_json");
  assert.equal(first.report.counts.passkeys, 2);
  // The page names the passkeys the vault holds; the same file again brings none of them in, and the logins come in again without them.
  const known = expected.slice(0, 2).map((e) => passkeyKey("rp-a.test", Buffer.from(e.credentialIdRawB64u, "base64url")));
  const second = await importFile(client, new File([bitwardenText], "export.json"), "bitwarden_json", known);
  assert.equal(second.report.counts.passkeys, 0);
  assert.equal(second.report.passkeys.skipped.duplicate, 2);
  assert.equal(second.sealed.length, 3);
  for (const sealed of second.sealed) assert.equal((await openAndSign(client, sealed)).view.passkey, null);
  await client.lock();
});

test("firefox_exported_keys_import_and_sign", async () => {
  const client = await clientWithVault("web-import-nss");
  const credentials = nss.map((keyValue, n) => {
    return {
      credentialId: `b64.${b64u(Buffer.alloc(20, n + 1))}`, keyType: "public-key", keyAlgorithm: "ECDSA", keyCurve: "P-256", keyValue,
      rpId: "rp-a.test", userHandle: b64u(Buffer.alloc(8, n + 9)), userName: `nss-${n}`, counter: "0", rpName: "RP A", userDisplayName: "NSS", discoverable: "true",
      creationDate: "2026-11-25T11:00:00.000Z",
    };
  });
  const file = new File([JSON.stringify({ encrypted: false, folders: [], items: credentials.map((c, n) => ({ type: 1, name: `NSS ${n}`, login: { username: `u${n}`, fido2Credentials: [c] } })) })], "export.json");
  const done = await importFile(client, file, "bitwarden_json");
  assert.equal(done.report.counts.passkeys, nss.length);
  for (const [n, keyValue] of nss.entries()) {
    const { got } = await openAndSign(client, done.sealed[n]);
    const priv = createPrivateKey({ key: Buffer.from(keyValue, "base64url"), format: "der", type: "pkcs8" });
    assertSigns(createPublicKey(priv), got);
  }
  await client.lock();
});

/** The `.avux` file of the fixture: a ZIP file with the manifest in it. */
const avux = (text = manifestText) => new File([zip([{ name: "manifest.json", data: Buffer.from(text) }])], "export.avux");

test("aliasvault_passkeys_import_and_sign_on_the_fixture", async () => {
  const client = await clientWithVault("web-import-aliasvault");
  const done = await importFile(client, avux(), "aliasvault_avux");
  assert.equal(done.sealed.length, 2);
  assert.equal(done.report.counts.passkeys, 2);
  assert.equal(done.report.passkeys.registerAgain, 0, "AliasVault has no counter");
  for (const [n, want] of [[0, expected[3]], [1, expected[4]]]) {
    for (const uv of [true, false]) {
      const { view, got } = await openAndSign(client, done.sealed[n], { uv });
      assert.equal(view.name, `Import test AliasVault ${n + 1}`);
      assert.equal(view.passkey.rp_id, "rp-a.test");
      assert.equal(b64u(got.id), want.credentialIdRawB64u);
      assert.equal(b64u(view.passkey.user_handle), want.userHandleB64u);
      assert.equal(view.passkey.has_prf, n === 1);
      assertSigns(want.publicKeySpkiB64, got);
    }
  }
  // The PRF of the second passkey is AliasVault's own: HMAC-SHA256(prfKey, SHA-256("WebAuthn PRF" || 0 || salt)), with and without UV.
  const prfKey = Buffer.from(expected[4].prfKeyB64, "base64");
  const salt = Buffer.alloc(32, 0x42);
  const want = createHmac("sha256", prfKey).update(createHash("sha256").update(Buffer.concat([Buffer.from("WebAuthn PRF"), Buffer.from([0]), salt])).digest()).digest();
  for (const uv of [true, false]) {
    const { got } = await openAndSign(client, done.sealed[1], { uv, prf: { eval: { first: new Uint8Array(salt) } } });
    assert.equal(Buffer.from(got.prf.first).toString("hex"), want.toString("hex"), `the PRF output, uv ${uv}`);
  }
  await client.lock();
});

test("a_prf_key_of_another_length_imports_the_passkey_without_prf", async () => {
  const client = await clientWithVault("web-import-prf-drop");
  const manifest = JSON.parse(manifestText);
  manifest.items[1].passkeys[0].prfKey = Buffer.alloc(16, 9).toString("base64");
  const done = await importFile(client, avux(JSON.stringify(manifest)), "aliasvault_avux");
  assert.equal(done.report.counts.passkeys, 2);
  assert.equal(done.report.passkeys.prfDropped, 1);
  const { view, got } = await openAndSign(client, done.sealed[1]);
  assert.equal(view.passkey.has_prf, false);
  assertSigns(expected[4].publicKeySpkiB64, got);
  await client.lock();
});

test("what_the_core_refuses_is_counted_and_the_login_is_imported_without_the_passkey", async () => {
  const client = await clientWithVault("web-import-refusals");
  const ecdh = createECDH("secp384r1");
  ecdh.generateKeys();
  const base = JSON.parse(bitwardenText).items[0].login.fido2Credentials[0];
  const credential = (change, n) => ({ ...base, credentialId: `b64.${b64u(Buffer.alloc(16, n))}`, ...change });
  const items = [
    // A site that is a public suffix, and one that is no host: bad_site.
    credential({ rpId: "co.uk" }, 1), credential({ rpId: "not a host" }, 2),
    // A key that is not a key: unreadable; PKCS#8 of a P-384 key: another kind of key.
    credential({ keyValue: b64u(Buffer.alloc(138, 1)) }, 3),
    credential({ keyValue: b64u(Buffer.concat([Buffer.from("3081b6020100301006072a8648ce3d020106052b81040022046f306d02010104", "hex"), Buffer.alloc(100, 1)])) }, 4),
  ].map((c, n) => ({ type: 1, name: `Refused ${n}`, login: { username: "x", fido2Credentials: [c] } }));
  const file = new File([JSON.stringify({ encrypted: false, folders: [], items })], "export.json");
  const done = await importFile(client, file, "bitwarden_json");
  assert.equal(done.sealed.length, 4, "every login is imported");
  assert.equal(done.report.counts.passkeys, 0);
  assert.equal(done.report.skipped.passkeys, 4);
  assert.equal(done.report.passkeys.skipped.bad_site, 2);
  assert.equal(done.report.passkeys.skipped.unreadable + done.report.passkeys.skipped.other_key, 2);
  await client.lock();
});

// ----------------------------------------------------------------------- the import port

const IMPORTED = { item_type: "login", name: "Imported" };
const PASSKEY = {
  cred_id: new Uint8Array(16).fill(1), rp_id: "example.com", user_handle: new Uint8Array(8).fill(2), user_name: "u", created: 1, counter: 0,
  key_pkcs8: new Uint8Array(138).fill(3),
};
const request = (passkey, extra = {}) => ({ id: 1, method: "passkey_import", args: [new Uint8Array(16).fill(5), 1, IMPORTED, passkey, NOW], ...extra });
const refusal = (req) => {
  try {
    importCall(req);
  } catch (e) {
    return e.code;
  }
  return null;
};

test("the_import_port_takes_a_passkey_import_with_the_fields_of_the_binding_and_nothing_else", () => {
  assert.equal(refusal(request({ ...PASSKEY })), null);
  assert.equal(importCall(request({ ...PASSKEY })).method, "passkey_import");
  assert.equal(refusal(request({ ...PASSKEY, key_pkcs8: undefined, key_jwk: "{}" })), null);
  assert.equal(refusal(request({ ...PASSKEY, prf_seed_uv: new Uint8Array(32), prf_seed_nouv: new Uint8Array(32), rp_name: "n", user_display_name: "d" })), null);
  const bad = [
    null, "x", [], new Uint8Array(3), { ...PASSKEY, key_pkcs8: undefined },
    { ...PASSKEY, key_jwk: "{}" }, { ...PASSKEY, extra: 1 }, { ...PASSKEY, cred_id: [1, 2] }, { ...PASSKEY, rp_id: 5 }, { ...PASSKEY, rp_id: "x\ud800" },
    { ...PASSKEY, created: "1" }, { ...PASSKEY, created: NaN }, { ...PASSKEY, counter: Infinity }, { ...PASSKEY, prf_seed_uv: new Uint8Array(32) },
    { ...PASSKEY, prf_seed_nouv: new Uint8Array(32) }, { ...PASSKEY, key_pkcs8: "text" }, { ...PASSKEY, user_name: undefined }, { ...PASSKEY, created: undefined },
  ];
  for (const passkey of bad) assert.equal(refusal(request(passkey)), "invalid_input", JSON.stringify(passkey));
  // The rest of the request is as strict as for a plain item.
  for (const change of [
    { args: [new Uint8Array(15), 1, IMPORTED, { ...PASSKEY }, NOW] },
    { args: [new Uint8Array(16), 1, IMPORTED, { ...PASSKEY }, NOW] },
    { args: [new Uint8Array(16).fill(5), 2, IMPORTED, { ...PASSKEY }, NOW] },
    { args: [new Uint8Array(16).fill(5), 1, { ...IMPORTED, passkey: { rp_id: "example.com" } }, { ...PASSKEY }, NOW] },
    { args: [new Uint8Array(16).fill(5), 1, [IMPORTED], { ...PASSKEY }, NOW] },
    { args: [new Uint8Array(16).fill(5), 1, IMPORTED, { ...PASSKEY }, -1] },
    { args: [new Uint8Array(16).fill(5), 1, IMPORTED, { ...PASSKEY }, NOW, "extra"] },
    { args: [new Uint8Array(16).fill(5), 1, IMPORTED, NO_EXISTING, NOW] },
    { method: "passkey_create" },
    { method: "passkey_get" },
    { method: "open_item" },
  ]) assert.equal(refusal(request({ ...PASSKEY }, change)), "invalid_input", JSON.stringify(Object.keys(change)));
  // `encrypt_item` with a passkey argument is still refused.
  assert.equal(refusal({ id: 1, method: "encrypt_item", args: [new Uint8Array(16).fill(5), 1, IMPORTED, { ...PASSKEY }, NOW] }), "invalid_input");
});

test("the_vault_worker_wipes_the_key_and_the_seeds_that_came_over_the_port", async () => {
  // A vault that records the arguments it is given (the same objects the port gave it).
  const calls = [];
  class FakeVault {
    passkey_import(...args) {
      calls.push(args);
      if (args[3].rp_id === "refused.example") throw Object.assign(new Error("x"), { code: "unsupported" });
      return { item: { rev: 1, envelope: new Uint8Array(4), tag: new Uint8Array(32) }, rp_id: args[3].rp_id, notes: { register_again: false, counter: 0, prf: true } };
    }

    lock() {}
    free() {}
  }
  class FakeJob {
    create_account() {
      return { vault: new FakeVault() };
    }

    clear() {}
  }
  const dispatch = createDispatcher({ UnlockJob: FakeJob, Vault: FakeVault });
  assert.equal(dispatch({ id: 1, target: "vault", method: "create_account", args: [] }).reply.ok, true);
  const { port1, port2 } = new MessageChannel();
  assert.equal(dispatch({ id: 2, target: "vault", method: IMPORT_PORT, args: [] }, [port2]).reply.ok, true);
  const ask = (message) => new Promise((resolve) => {
    port1.onmessage = (event) => resolve(event.data);
    port1.postMessage(message);
  });
  const seeds = { prf_seed_uv: new Uint8Array(32).fill(7), prf_seed_nouv: new Uint8Array(32).fill(7) };
  const ok = await ask(request({ ...PASSKEY, ...seeds }, { id: 11 }));
  assert.equal(ok.ok, true);
  assert.deepEqual(Object.keys(ok.value).sort(), ["item", "notes", "rp_id"]);
  // The vault was given the arrays, and they are wiped now (the vault copied what it needs).
  assert.equal(calls.length, 1);
  const given = calls[0][3];
  assert.ok(given.key_pkcs8.every((b) => b === 0), "the key is wiped");
  assert.ok(given.prf_seed_uv.every((b) => b === 0) && given.prf_seed_nouv.every((b) => b === 0), "the seeds are wiped");
  // A passkey the vault refuses is wiped too, and a request the port refuses is never given to the vault.
  const refused = await ask(request({ ...PASSKEY, rp_id: "refused.example" }, { id: 12 }));
  assert.deepEqual(refused, { id: 12, ok: false, code: "unsupported" });
  assert.ok(calls[1][3].key_pkcs8.every((b) => b === 0), "wiped after a refusal");
  const invalid = await ask(request({ ...PASSKEY, extra: 1 }, { id: 13 }));
  assert.deepEqual(invalid, { id: 13, ok: false, code: "invalid_input" });
  assert.equal(calls.length, 2);
  port1.close();
});
