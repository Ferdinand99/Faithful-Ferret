// The passkeys of an import file: the Bitwarden and AliasVault readers, the worker that sends each passkey to the vault over the import
// port, what is counted and left out, and that no key is ever in a draft, a message other than the one that carries it, an answer or a log.
// The vault is a fake that answers as `passkey_import` of the binding does (the real one, with the real keys, is in tests/node).
// Every key here is a throwaway test key for the site rp-a.test.
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { test } from "node:test";
import { fromAvuxManifest } from "../../src/import/aliasvault.mjs";
import { fromBitwardenJson } from "../../src/import/bitwarden.mjs";
import { decodeBase64, guidBytes, passkeyKey } from "../../src/import/passkeys.mjs";
import { safeJsonParse } from "../../src/import/prescan.mjs";
import { createHandler } from "../../src/workers/import.worker.mjs";
import { allStrings, avText, fixture, sealedValue, textFile, vaultPort } from "./importHelpers.mjs";
import { web } from "./helpers.mjs";
import { answer, fakeImportEngine, importWorld } from "./importFlowHelpers.mjs";
import { Model, createFakeClient, syncDevice } from "./syncHelpers.mjs";
import { zip } from "./zipHelper.mjs";

const NOW = 1_700_000_000_000;
let counter = 0;
const random = (bytes) => {
  bytes.fill(0);
  new DataView(bytes.buffer).setUint32(0, ++counter);
  bytes[15] = 1;
  return bytes;
};
const handler = () => createHandler({ now: () => NOW, random });
const expected = JSON.parse(readFileSync(join(web, "test", "fixtures", "import", "passkeys-expected.json"), "utf8")).passkeys;
const b64u = (bytes) => Buffer.from(bytes).toString("base64url");
const bitwarden = () => fixture("passkeys.json");
const manifestText = () => avText("passkeys-manifest.json");
/** The `.avux` file of the AliasVault passkey fixture: a ZIP file with the manifest in it. */
const avux = (text = manifestText()) => new File([zip([{ name: "manifest.json", data: Buffer.from(text) }])], "passkeys.avux");

/**
 * A port that plays the vault worker for an import: `passkey_import` is answered as the binding answers it (the site in its canonical
 * spelling, the notes), `encrypt_item` as it always was. `refuse` makes a code for a message.
 */
function passkeyPort({ refuse = () => undefined } = {}) {
  const port = vaultPort({
    reply: (message, index) => {
      const code = refuse(message);
      if (code !== undefined) return { id: message.id, ok: false, code };
      if (message.method === "passkey_import") {
        const p = message.args[3];
        return {
          id: message.id,
          ok: true,
          value: {
            item: sealedValue(index),
            rp_id: p.rp_id.toLowerCase().replace(/\.$/, ""),
            notes: { register_again: p.counter > 0, counter: p.counter, prf: p.prf_seed_uv !== undefined },
          },
        };
      }
      return { id: message.id, ok: true, value: sealedValue(index) };
    },
  });
  // The messages as they were when they were sent: the worker wipes the key bytes of the object when the item is sealed.
  const snapshots = [];
  const post = port.postMessage;
  port.postMessage = (message) => {
    snapshots.push(structuredClone(message));
    post(message);
  };
  port.snapshots = snapshots;
  return port;
}

const request = (file, port, { kind = "bitwarden_json", passkeys = { known: [] }, labels } = {}) => ({
  id: 3, kind, file, port, ...(passkeys === false ? {} : { passkeys }), ...(labels === undefined ? {} : { labels }),
});

/** A Bitwarden export with one login with the credentials given. */
function bitwardenFile(credentials, login = {}) {
  return textFile(JSON.stringify({
    encrypted: false,
    folders: [],
    items: [{ type: 1, name: "Site", login: { username: "me", password: "pw-1", uris: [{ uri: "https://rp-a.test/", match: null }], fido2Credentials: credentials, ...login } }],
  }));
}

/** The first credential of the fixture, changed. */
const credential = (change = {}, n = 0) => ({ ...safeJsonParse(bitwarden()).items[n].login.fido2Credentials[0], ...change });
const methods = (port) => port.snapshots.map((m) => m.method);

// ------------------------------------------------------------------------------------------------ the ids

test("bitwarden_guid_and_b64_credential_ids_both_parse", async () => {
  const port = passkeyPort();
  const reply = await handler()(request(textFile(bitwarden()), port));
  assert.equal(reply.ok, true);
  const sent = port.snapshots.filter((m) => m.method === "passkey_import").map((m) => m.args[3]);
  assert.equal(sent.length, 2);
  // The GUID, in the order the text is written; the `b64.` text, as base64url.
  assert.equal(b64u(sent[0].cred_id), expected[0].credentialIdRawB64u);
  assert.equal(b64u(sent[1].cred_id), expected[1].credentialIdRawB64u);
  assert.equal(b64u(sent[0].user_handle), expected[0].userHandleB64u);
  assert.equal(b64u(sent[1].user_handle), expected[1].userHandleB64u);
  assert.equal(sent[0].cred_id.length, 16);
  assert.equal(sent[1].cred_id.length, 32);
});

test("a_guid_is_read_in_the_order_it_is_written_and_a_base64_text_in_its_own_alphabet", () => {
  assert.deepEqual([...guidBytes("00112233-4455-6677-8899-aabbccddeeff")], [0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]);
  assert.deepEqual([...guidBytes("A1BC3321-A9E5-434A-8C23-6600066CC911")], [...guidBytes("a1bc3321-a9e5-434a-8c23-6600066cc911")]);
  for (const bad of ["", "a1bc3321a9e5434a8c236600066cc911", "a1bc3321-a9e5-434a-8c23-6600066cc91", "a1bc3321-a9e5-434a-8c23-6600066cc91g", null, 5]) assert.equal(guidBytes(bad), null);
  // Standard base64 has `+` and `/` and padding; base64url has `-` and `_` and none. They are not mixed.
  assert.deepEqual([...decodeBase64("+/8=", false)], [0xfb, 0xff]);
  assert.equal(decodeBase64("+/8=", true), null);
  assert.deepEqual([...decodeBase64("-_8", true)], [0xfb, 0xff]);
  assert.deepEqual([...decodeBase64("-_8=", true)], [0xfb, 0xff]);
  assert.equal(decodeBase64("-_8", false), null);
  assert.deepEqual([...decodeBase64("AQID", false)], [1, 2, 3]);
  for (const bad of ["", "A", "AQIDB", "AQ=D", "AQ===", "AQID\n", "AQ ID", null, 7]) assert.equal(decodeBase64(bad, false), null, String(bad));
  // The padding, when there is some, is whole.
  assert.equal(decodeBase64("AQI", false)?.length, 2);
  assert.equal(decodeBase64("AQ=", false), null);
});

// -------------------------------------------------------------------------------------- joining a login

test("a_passkey_joins_its_login_item", async () => {
  const port = passkeyPort();
  const reply = await handler()(request(textFile(bitwarden()), port));
  assert.equal(reply.ok, true);
  // Three logins, three items: two with a passkey inside, one (not discoverable) without.
  assert.deepEqual(methods(port), ["passkey_import", "passkey_import", "encrypt_item"]);
  assert.equal(reply.sealed.length, 3);
  assert.equal(reply.report.counts.sealed, 3);
  assert.equal(reply.report.counts.passkeys, 2);
  const [first, second] = port.snapshots;
  for (const [message, n] of [[first, 1], [second, 2]]) {
    const [itemId, rev, draft, passkey, now] = message.args;
    assert.equal(itemId.length, 16);
    assert.equal(rev, 1);
    assert.equal(now, NOW);
    // The draft is the login: its name, user name and address are the item of the passkey.
    assert.equal(draft.item_type, "login");
    assert.equal(draft.name, `Import test Bitwarden ${n}`);
    assert.equal(draft.fields.find((f) => f.id === "username").value, `import-test-${n}@rp-a.test`);
    assert.deepEqual(draft.urls, [{ url: "https://rp-a.test/", matching: "host" }]);
    assert.equal("passkey" in draft, false);
    assert.equal(passkey.rp_id, "rp-a.test");
    assert.equal(passkey.user_name, `import-test-${n}@rp-a.test`);
    assert.equal(passkey.rp_name, "RP A (test)");
    assert.equal(passkey.user_display_name, `Import Test ${n}`);
    assert.equal(passkey.created, Date.parse("2026-11-25T09:34:34.485Z"));
    assert.equal(Object.hasOwn(passkey, "prf_seed_uv"), false);
    assert.equal(passkey.key_pkcs8.length, 138);
  }
  // The same ids go back, in the order of the file.
  assert.deepEqual(reply.sealed.map((s) => Buffer.from(s.id).toString("hex")), port.snapshots.map((m) => Buffer.from(m.args[0]).toString("hex")));
});

test("a_second_passkey_of_a_login_gets_an_item_of_its_own_with_the_same_name", async () => {
  const port = passkeyPort();
  const second = credential({ credentialId: "b64.rG7-pY6CMa0iNyxgdA9ixAV-17h-xnnPsSU8Jcg6PEs", counter: "0" });
  const reply = await handler()(request(bitwardenFile([credential(), second]), port));
  assert.equal(reply.ok, true);
  assert.deepEqual(methods(port), ["passkey_import", "passkey_import"]);
  const [joined, own] = port.snapshots.map((m) => m.args[2]);
  assert.equal(joined.fields.find((f) => f.id === "password").value, "pw-1");
  assert.equal(own.name, "Site");
  assert.equal(own.item_type, "login");
  assert.match(own.notes, /belonged to a login with another passkey/);
  // The item of its own holds the user name and the passkey, and nothing of the password.
  assert.deepEqual(own.fields.map((f) => f.id), ["username"]);
  assert.equal(allStrings(own).includes("pw-1"), false);
  assert.equal(reply.report.counts.passkeys, 2);
  assert.equal(reply.report.counts.items, 2);
  assert.equal(reply.report.counts.login, 2);
  assert.equal(reply.report.passkeys.extra, 1);
  assert.ok(reply.report.warnings.some((w) => w.code === "passkey_extra_item"));
  assert.equal(reply.sealed.length, 2);
});

test("aliasvault_passkeys_join_their_login_and_use_the_item_s_user_name", async () => {
  const port = passkeyPort();
  const reply = await handler()(request(avux(), port, { kind: "aliasvault_avux" }));
  assert.equal(reply.ok, true);
  assert.deepEqual(methods(port), ["passkey_import", "passkey_import"]);
  const [a, b] = port.snapshots.map((m) => m.args);
  assert.equal(a[2].name, "Import test AliasVault 1");
  assert.equal(a[2].fields.find((f) => f.id === "username").value, "import-test-av1@rp-a.test");
  // Id from the GUID of the passkey (no credentialId), the user handle as standard base64 with padding.
  assert.equal(b64u(a[3].cred_id), expected[3].credentialIdRawB64u);
  assert.equal(b64u(a[3].user_handle), expected[3].userHandleB64u);
  assert.equal(b64u(b[3].cred_id), expected[4].credentialIdRawB64u);
  assert.equal(b64u(b[3].user_handle), expected[4].userHandleB64u);
  assert.equal(a[3].user_name, "import-test-av1@rp-a.test");
  assert.equal(a[3].rp_id, "rp-a.test");
  assert.equal(a[3].counter, 0);
  assert.equal(typeof a[3].key_jwk, "string");
  assert.equal(Object.hasOwn(a[3], "key_pkcs8"), false);
  assert.equal(reply.report.counts.passkeys, 2);
});

// ------------------------------------------------------------------------------------------ leaving out

test("non_discoverable_or_handle_less_passkeys_are_skipped_and_counted", async () => {
  // The fixture: the third passkey has no user handle (and says it is not discoverable).
  {
    const port = passkeyPort();
    const reply = await handler()(request(textFile(bitwarden()), port));
    assert.equal(reply.report.passkeys.skipped.not_discoverable, 1);
    assert.equal(reply.report.skipped.passkeys, 1);
    assert.equal(reply.report.counts.passkeys, 2);
    // Its login is still imported, without the passkey.
    assert.equal(port.snapshots[2].method, "encrypt_item");
    assert.equal(port.snapshots[2].args[2].name, "Import test Bitwarden 3");
  }
  // `discoverable: "false"` leaves it out even when a user handle is there; so does an empty handle or none at all.
  const cases = [
    credential({ discoverable: "false" }),
    credential({ discoverable: "FALSE" }),
    credential({ userHandle: "" }),
    credential({ userHandle: undefined }),
    credential({ userHandle: null }),
  ];
  for (const one of cases) {
    const port = passkeyPort();
    const reply = await handler()(request(bitwardenFile([one]), port));
    assert.equal(reply.ok, true);
    assert.deepEqual(methods(port), ["encrypt_item"], JSON.stringify(one.discoverable));
    assert.equal(reply.report.passkeys.skipped.not_discoverable, 1);
    assert.equal(reply.report.skipped.passkeys, 1);
    assert.equal(reply.report.counts.passkeys, 0);
  }
  // Discoverable `"true"` with a handle is read.
  const port = passkeyPort();
  await handler()(request(bitwardenFile([credential({ discoverable: "true" })]), port));
  assert.deepEqual(methods(port), ["passkey_import"]);
});

test("other_curves_and_algorithms_are_skipped_and_counted", async () => {
  const others = [
    credential({ keyCurve: "P-384" }),
    credential({ keyCurve: "Ed25519" }),
    credential({ keyAlgorithm: "RSA" }),
    credential({ keyType: "other" }),
    credential({ keyAlgorithm: undefined }),
  ];
  for (const one of others) {
    const port = passkeyPort();
    const reply = await handler()(request(bitwardenFile([one]), port));
    assert.deepEqual(methods(port), ["encrypt_item"]);
    assert.equal(reply.report.passkeys.skipped.other_key, 1);
    assert.equal(reply.report.skipped.passkeys, 1);
  }
  // AliasVault: an RSA key (`kty`), another curve, an OKP key.
  for (const [kty, crv] of [["RSA", undefined], ["EC", "P-384"], ["OKP", "Ed25519"], ["EC", "secp256k1"]]) {
    const manifest = safeJsonParse(manifestText());
    manifest.items.length = 1;
    const key = JSON.parse(manifest.items[0].passkeys[0].privateKey);
    manifest.items[0].passkeys[0].privateKey = JSON.stringify({ ...key, kty, crv });
    const port = passkeyPort();
    const reply = await handler()(request(avux(JSON.stringify(manifest)), port, { kind: "aliasvault_avux" }));
    assert.deepEqual(methods(port), ["encrypt_item"], `${kty} ${crv}`);
    assert.equal(reply.report.passkeys.skipped.other_key, 1, `${kty} ${crv}`);
  }
  // A key with no `kty` is read as EC (AliasVault leaves it out in some versions).
  {
    const manifest = safeJsonParse(manifestText());
    manifest.items.length = 1;
    const { kty, ...rest } = JSON.parse(manifest.items[0].passkeys[0].privateKey);
    manifest.items[0].passkeys[0].privateKey = JSON.stringify(rest);
    const port = passkeyPort();
    await handler()(request(avux(JSON.stringify(manifest)), port, { kind: "aliasvault_avux" }));
    assert.deepEqual(methods(port), ["passkey_import"]);
  }
  // What the vault itself refuses, by its code: the key it does not take, a site that is no site, a passkey it has open.
  const refusals = [["unsupported", "other_key"], ["malformed_rp_id", "bad_site"], ["malformed_item_body", "unreadable"], ["too_large", "unreadable"], ["malformed_webauthn_options", "unreadable"], ["invalid_state", "duplicate"]];
  for (const [code, reason] of refusals) {
    const port = passkeyPort({ refuse: (m) => (m.method === "passkey_import" ? code : undefined) });
    const reply = await handler()(request(bitwardenFile([credential()]), port));
    assert.equal(reply.ok, true, code);
    assert.equal(reply.report.passkeys.skipped[reason], 1, code);
    // The login is imported without the passkey: a second message, `encrypt_item`, with the plain draft (no note).
    assert.deepEqual(methods(port), ["passkey_import", "encrypt_item"], code);
    assert.equal(port.snapshots[1].args[2].notes, undefined);
    assert.equal(reply.sealed.length, 1);
    assert.equal(reply.report.counts.passkeys, 0);
  }
  // A code that is not about the passkey stops the import.
  const port = passkeyPort({ refuse: () => "vault_locked" });
  const stopped = await handler()(request(bitwardenFile([credential()]), port));
  assert.deepEqual(stopped, { id: 3, ok: false, error: "import_seal_failed" });
});

test("unreadable_passkeys_are_counted_and_the_rest_of_the_file_goes_on", async () => {
  const bad = [
    credential({ credentialId: "not-a-guid" }),
    credential({ credentialId: "b64." }),
    credential({ credentialId: `b64.${"A".repeat(1400)}` }),
    credential({ keyValue: "***" }),
    credential({ keyValue: b64u(new Uint8Array(2000)) }),
    credential({ userHandle: b64u(new Uint8Array(65)) }),
    credential({ counter: "seven" }),
    credential({ counter: "4294967296" }),
    credential({ counter: "-1" }),
    credential({ rpId: "" }),
    "a string",
    null,
  ];
  for (const one of bad) {
    const port = passkeyPort();
    const reply = await handler()(request(bitwardenFile([one]), port));
    assert.equal(reply.ok, true);
    assert.deepEqual(methods(port), ["encrypt_item"]);
    assert.equal(reply.report.skipped.passkeys, 1);
    assert.equal(Object.values(reply.report.passkeys.skipped).reduce((a, b) => a + b, 0), 1);
  }
});

test("a_passkey_the_vault_has_already_is_left_out_and_so_is_one_that_is_in_the_file_twice", async () => {
  const known = passkeyKey("rp-a.test", Buffer.from(expected[0].credentialIdRawB64u, "base64url"));
  assert.match(known, /^rp-a\.test\n[0-9a-f]{32}$/);
  // The first is held (in an item, or in the trash: the page names both), the second is new.
  {
    const port = passkeyPort();
    const reply = await handler()(request(textFile(bitwarden()), port, { passkeys: { known: [known] } }));
    assert.equal(reply.report.passkeys.skipped.duplicate, 1);
    assert.equal(reply.report.counts.passkeys, 1);
    assert.equal(reply.report.skipped.passkeys, 2, "the duplicate and the one that is not discoverable");
    // Its login is imported without the passkey.
    assert.deepEqual(methods(port), ["passkey_import", "passkey_import", "encrypt_item", "encrypt_item"]);
    assert.equal(reply.sealed.length, 3);
  }
  // The same passkey twice in the file, in two logins, and the same site spelled in capitals: once.
  {
    const again = credential({ rpId: "RP-A.test" });
    const file = textFile(JSON.stringify({
      encrypted: false,
      folders: [],
      items: [
        { type: 1, name: "One", login: { username: "a", fido2Credentials: [credential()] } },
        { type: 1, name: "Two", login: { username: "b", fido2Credentials: [again] } },
      ],
    }));
    const port = passkeyPort();
    const reply = await handler()(request(file, port));
    assert.equal(reply.report.counts.passkeys, 1);
    assert.equal(reply.report.passkeys.skipped.duplicate, 1);
    assert.equal(reply.sealed.length, 2);
  }
  // A vault that says it has the passkey open (`invalid_state`) is the same.
  {
    const port = passkeyPort({ refuse: (m) => (m.method === "passkey_import" ? "invalid_state" : undefined) });
    const reply = await handler()(request(bitwardenFile([credential()]), port));
    assert.equal(reply.report.passkeys.skipped.duplicate, 1);
  }
  // Without a list of the vault's passkeys nothing is imported twice from this file, either.
  const port = passkeyPort();
  const reply = await handler()(request(textFile(bitwarden()), port, { passkeys: { known: [] } }));
  assert.equal(reply.report.passkeys.skipped.duplicate, 0);
});

// -------------------------------------------------------------------------------- counter and PRF

test("a_counter_above_zero_says_register_again", async () => {
  const port = passkeyPort();
  const reply = await handler()(request(textFile(bitwarden()), port));
  // The second passkey of the fixture had been used seven times.
  assert.equal(port.snapshots[1].args[3].counter, 7);
  assert.equal(port.snapshots[0].args[3].counter, 0);
  assert.equal(reply.report.passkeys.registerAgain, 1);
  assert.deepEqual(reply.report.passkeys.sites, ["rp-a.test"]);
  assert.deepEqual(reply.report.warnings.filter((w) => w.code === "passkey_register_again"), [{ code: "passkey_register_again", index: 1 }]);
  // The item says so too, in the words of the page; the one with counter 0 does not.
  assert.match(port.snapshots[1].args[2].notes, /had been used before/);
  assert.equal(port.snapshots[0].args[2].notes, undefined);
  // The words of the page are used when it gives them.
  const own = passkeyPort();
  await handler()(request(textFile(bitwarden()), own, { labels: { passkey_register_again: "Registrer på nytt." } }));
  assert.equal(own.snapshots[1].args[2].notes, "Registrer på nytt.");
  // The sites are those the vault answers, a few of them, each once.
  const many = Array.from({ length: 30 }, (_, n) => credential({ counter: "3", rpId: `site-${n}.test`, credentialId: `b64.${b64u(new Uint8Array(16).fill(n + 1))}` }));
  const port3 = passkeyPort();
  const big = await handler()(request(bitwardenFile(many), port3));
  assert.equal(big.report.passkeys.registerAgain, 30);
  assert.equal(big.report.passkeys.sites.length, 20);
  assert.equal(new Set(big.report.passkeys.sites).size, 20);
  assert.equal(big.report.passkeys.siteCount, 30, "the sites are counted past the 20 that are named");
  // Two used passkeys of one site are one site.
  const same = [credential({ counter: "3" }), credential({ counter: "4", credentialId: `b64.${b64u(new Uint8Array(16).fill(9))}` })];
  const oneSite = await handler()(request(bitwardenFile(same), passkeyPort()));
  assert.equal(oneSite.report.passkeys.registerAgain, 2);
  assert.equal(oneSite.report.passkeys.siteCount, 1);
  assert.deepEqual(oneSite.report.passkeys.sites, ["rp-a.test"]);
});

test("prf_is_dropped_with_a_warning_when_the_formula_differs", async () => {
  const withKey = (prfKey) => {
    const manifest = safeJsonParse(manifestText());
    manifest.items.length = 2;
    manifest.items[1].passkeys[0].prfKey = prfKey;
    return avux(JSON.stringify(manifest));
  };
  // Thirty-two bytes: AliasVault's one secret answers for both ways of using it, so it is both seeds.
  {
    const port = passkeyPort();
    const reply = await handler()(request(avux(), port, { kind: "aliasvault_avux" }));
    const withPrf = port.snapshots[1].args[3];
    const key = Buffer.from(expected[4].prfKeyB64, "base64");
    assert.equal(key.length, 32);
    assert.deepEqual([...withPrf.prf_seed_uv], [...key]);
    assert.deepEqual([...withPrf.prf_seed_nouv], [...key]);
    assert.notEqual(withPrf.prf_seed_uv, withPrf.prf_seed_nouv);
    assert.equal(Object.hasOwn(port.snapshots[0].args[3], "prf_seed_uv"), false);
    assert.equal(reply.report.passkeys.prfDropped, 0);
  }
  // Any other length (or text that is no base64) drops the PRF, keeps the passkey, and says so.
  for (const odd of [Buffer.alloc(16, 5).toString("base64"), Buffer.alloc(64, 5).toString("base64"), Buffer.alloc(31, 5).toString("base64"), "not base64!", "O6TQuM7OZTXrItJEbxV4Ru94sC6ORiH92gBtODOousc"]) {
    const port = passkeyPort();
    const reply = await handler()(request(withKey(odd), port, { kind: "aliasvault_avux" }));
    const sent = port.snapshots[1].args[3];
    // The last one is the right key without its padding: no padding is still base64 of 32 bytes.
    const dropped = odd !== "O6TQuM7OZTXrItJEbxV4Ru94sC6ORiH92gBtODOousc";
    assert.equal(Object.hasOwn(sent, "prf_seed_uv"), !dropped, odd);
    assert.equal(Object.hasOwn(sent, "prf_seed_nouv"), !dropped, odd);
    assert.equal(reply.report.passkeys.prfDropped, dropped ? 1 : 0, odd);
    assert.equal(reply.report.warnings.some((w) => w.code === "passkey_prf_dropped"), dropped, odd);
    assert.equal(reply.report.counts.passkeys, 2, "the passkey itself is imported");
  }
  // A key that is not text, or an empty one, is no PRF (and no warning for none).
  for (const none of [null, ""]) {
    const port = passkeyPort();
    const reply = await handler()(request(withKey(none), port, { kind: "aliasvault_avux" }));
    assert.equal(Object.hasOwn(port.snapshots[1].args[3], "prf_seed_uv"), false);
    assert.equal(reply.report.passkeys.prfDropped, 0);
  }
});

// ------------------------------------------------------------------------------------ no key leaks

test("the_key_is_never_in_a_draft_message_or_log", async () => {
  const keys = [];
  for (const item of safeJsonParse(bitwarden()).items) for (const c of item.login.fido2Credentials) keys.push(c.keyValue, Buffer.from(c.keyValue, "base64url").toString("hex"));
  const manifest = safeJsonParse(manifestText());
  for (const item of manifest.items) for (const p of item.passkeys) keys.push(p.privateKey, JSON.parse(p.privateKey).d, p.prfKey ?? "PRF-NONE-XYZ");
  const words = keys.filter(Boolean);
  const logged = [];
  const real = { log: console.log, info: console.info, warn: console.warn, error: console.error, debug: console.debug, trace: console.trace };
  for (const name of Object.keys(real)) console[name] = (...args) => logged.push(args);
  /** @type {any} */ let bw;
  /** @type {any} */ let av;
  /** @type {any} */ let bwPort;
  /** @type {any} */ let avPort;
  try {
    bwPort = passkeyPort();
    bw = await handler()(request(textFile(bitwarden()), bwPort));
    avPort = passkeyPort();
    av = await handler()(request(avux(), avPort, { kind: "aliasvault_avux" }));
  } finally {
    Object.assign(console, real);
  }
  assert.deepEqual(logged, [], "nothing is logged");
  for (const [reply, port] of [[bw, bwPort], [av, avPort]]) {
    assert.equal(reply.ok, true);
    // What the page gets: ids, envelopes, a report. No key, no seed, no id of a credential.
    const answer = JSON.stringify({ ...reply, sealed: reply.sealed.map((s) => ({ ...s, envelope: [...s.envelope], tag: [...s.tag] })) });
    for (const word of words) assert.equal(answer.includes(word), false, "the answer");
    assert.equal(answer.includes(expected[0].credentialIdRawB64u), false);
    for (const m of port.snapshots) {
      if (m.method === "encrypt_item") {
        // A draft is text of the login and nothing else.
        for (const s of allStrings(m.args[2])) for (const word of words) assert.equal(s.includes(word), false, "a draft");
        assert.equal(m.args[2].passkey, undefined);
      } else {
        // The key is in the one argument made for it, and nowhere in the draft.
        assert.equal(m.method, "passkey_import");
        for (const s of allStrings(m.args[2])) for (const word of words) assert.equal(s.includes(word), false, "the draft of a passkey");
        assert.deepEqual(Object.keys(m).sort(), ["args", "id", "method"]);
      }
    }
  }
  // The bytes of the key and the seeds that stayed in the worker are wiped when the item is sealed.
  for (const m of bwPort.sent) {
    if (m.method !== "passkey_import") continue;
    assert.ok(m.args[3].key_pkcs8.every((b) => b === 0), "the PKCS#8 bytes are wiped");
  }
  for (const m of avPort.sent) {
    if (m.method !== "passkey_import" || m.args[3].prf_seed_uv === undefined) continue;
    assert.ok(m.args[3].prf_seed_uv.every((b) => b === 0) && m.args[3].prf_seed_nouv.every((b) => b === 0), "the seeds are wiped");
  }
  // A refusal says its code and nothing of the key.
  const refused = passkeyPort({ refuse: () => "vault_locked" });
  const stopped = await handler()(request(textFile(bitwarden()), refused));
  assert.deepEqual(stopped, { id: 3, ok: false, error: "import_seal_failed" });
  for (const word of words) assert.equal(JSON.stringify(stopped).includes(word), false);
  for (const m of refused.sent) if (m.method === "passkey_import") assert.ok(m.args[3].key_pkcs8.every((b) => b === 0), "wiped when the import stops");
});

test("without_passkey_import_passkeys_are_skipped_as_before", async () => {
  // No `passkeys` in the request: counted, one warning for each login, and nothing about a passkey goes to the vault.
  for (const [file, kind, count] of [[textFile(bitwarden()), "bitwarden_json", 3], [avux(), "aliasvault_avux", 2]]) {
    const port = passkeyPort();
    const reply = await handler()(request(file, port, { kind, passkeys: false }));
    assert.equal(reply.ok, true);
    assert.ok(port.snapshots.every((m) => m.method === "encrypt_item"));
    assert.equal(reply.report.skipped.passkeys, count);
    assert.equal(reply.report.counts.passkeys, 0);
    assert.equal(reply.report.warnings.filter((w) => w.code === "passkey_skipped").length, count);
    assert.deepEqual(reply.report.passkeys, { skipped: { not_discoverable: 0, other_key: 0, bad_site: 0, unreadable: 0, duplicate: 0 }, registerAgain: 0, prfDropped: 0, extra: 0, sites: [], siteCount: 0 });
    assert.equal(reply.sealed.length, count);
    const text = JSON.stringify(port.snapshots);
    assert.equal(text.includes("keyValue"), false);
    assert.equal(text.includes("key_pkcs8"), false);
  }
  // The readers say the same when asked not to read them.
  const read = fromBitwardenJson(safeJsonParse(bitwarden()));
  assert.deepEqual(read.passkeys, []);
  assert.equal(read.report.skipped.passkeys, 3);
  const av = fromAvuxManifest(safeJsonParse(manifestText()));
  assert.deepEqual(av.passkeys, []);
  assert.equal(av.report.skipped.passkeys, 2);
});

test("a_request_that_names_passkeys_wrongly_is_not_one_the_worker_takes", async () => {
  for (const passkeys of [null, 5, "x", {}, { known: "x" }, { known: [1] }, { known: [null] }, { known: ["x".repeat(5000)] }, { known: new Array(20_001).fill("a") }]) {
    const reply = await handler()({ id: 9, kind: "bitwarden_json", file: textFile(bitwarden()), port: passkeyPort(), passkeys });
    assert.deepEqual(reply, { id: 9, ok: false, error: "unsupported" }, JSON.stringify(passkeys)?.slice(0, 30));
  }
});

// ------------------------------------------------------------------------------ other refusals

test("a_login_with_a_code_the_vault_refuses_keeps_its_passkey", async () => {
  // The core refuses the one-time password: it is kept as a hidden field, and the passkey is sent again with the login.
  let refusedOnce = false;
  const port = passkeyPort({
    refuse: (m) => {
      if (m.method === "passkey_import" && m.args[2].totp && !refusedOnce) {
        refusedOnce = true;
        return "malformed_otpauth";
      }
      return undefined;
    },
  });
  const reply = await handler()(request(bitwardenFile([credential()], { totp: "GEZDGNBVGY3TQOJQ" }), port));
  assert.equal(reply.ok, true);
  assert.deepEqual(methods(port), ["passkey_import", "passkey_import"]);
  assert.equal(port.snapshots[1].args[2].totp, undefined);
  assert.ok(port.snapshots[1].args[2].fields.some((f) => f.id === "totp" && f.kind === "hidden"));
  // The key is still the key (sent again), and it was not lost when the first answer came.
  assert.equal(port.snapshots[1].args[3].key_pkcs8.length, 138);
  assert.equal(reply.report.counts.passkeys, 1);
  assert.ok(reply.report.warnings.some((w) => w.code === "totp_invalid"));
});

test("an_item_that_is_no_login_gets_the_passkey_in_a_login_of_its_own", async () => {
  const manifest = safeJsonParse(manifestText());
  manifest.items.length = 1;
  manifest.items[0].itemType = "Note";
  const port = passkeyPort();
  const reply = await handler()(request(avux(JSON.stringify(manifest)), port, { kind: "aliasvault_avux" }));
  assert.equal(reply.ok, true);
  // The note, and a login for the passkey, with the same name.
  assert.deepEqual(methods(port), ["encrypt_item", "passkey_import"]);
  assert.equal(port.snapshots[0].args[2].item_type, "note");
  assert.equal(port.snapshots[1].args[2].item_type, "login");
  assert.equal(port.snapshots[1].args[2].name, port.snapshots[0].args[2].name);
  assert.equal(reply.report.passkeys.extra, 1);
});

// ------------------------------------------------------------------------------- the flow and the engine

const POLICY = (offered) => ({ pin: { allowed: true, after_restart: true, min_length: 6 }, prf: { enabled: true }, passkeys: { import: offered } });
const worldWith = (offered, port = () => passkeyPort()) =>
  importWorld({ port, overrides: { "GET /api/vault/policy": () => answer(200, offered === null ? { pin: { allowed: false } } : POLICY(offered)) } });
const engineWith = (known) => ({ ...fakeImportEngine(), passkeyKeys: async () => known });

test("the_preview_reads_passkeys_only_when_the_server_offers_it_and_the_engine_knows_the_vault_s_passkeys", async () => {
  const known = [passkeyKey("rp-a.test", Buffer.from(expected[0].credentialIdRawB64u, "base64url"))];
  // On: the worker is told which passkeys the vault has, and the preview says what became of the passkeys.
  {
    const w = await worldWith(true);
    const preview = await w.session.importPreview(textFile(bitwarden(), "export.json"), { engine: engineWith(known) });
    assert.deepEqual(w.workers.made[0].posted[0].message.passkeys, { known });
    assert.equal(preview.counts.passkeys, 1);
    assert.equal(preview.counts.sealed, 3);
    assert.equal(preview.skipped.passkeys, 2);
    assert.deepEqual(preview.passkeys.skipped, { not_discoverable: 1, other_key: 0, bad_site: 0, unreadable: 0, duplicate: 1 });
    assert.equal(preview.passkeys.registerAgain, 1);
    assert.deepEqual(preview.passkeys.sites, ["rp-a.test"]);
    assert.ok(Object.isFrozen(preview.passkeys) && Object.isFrozen(preview.passkeys.sites));
    // Nothing of a key, an id or a handle is in what the page has.
    const text = JSON.stringify(preview);
    for (const word of [safeJsonParse(bitwarden()).items[0].login.fido2Credentials[0].keyValue, expected[0].credentialIdRawB64u, expected[0].userHandleB64u]) assert.equal(text.includes(word), false);
  }
  // The `.avux` is read the same way.
  {
    const w = await worldWith(true);
    const preview = await w.session.importPreview(avux(), { engine: engineWith([]) });
    assert.equal(preview.kind, "aliasvault_avux");
    assert.equal(preview.counts.passkeys, 2);
    assert.deepEqual(w.workers.made[0].posted[0].message.passkeys, { known: [] });
  }
  // Off (the server says no, or does not say, or cannot be asked), or an engine that cannot say which passkeys the vault has: as before.
  for (const [offered, engine] of [[false, engineWith([])], [null, engineWith([])], [true, fakeImportEngine()]]) {
    const w = await worldWith(offered);
    const preview = await w.session.importPreview(textFile(bitwarden(), "export.json"), { engine });
    assert.equal("passkeys" in w.workers.made[0].posted[0].message, false, String(offered));
    assert.equal(preview.passkeys, null);
    assert.equal(preview.counts.passkeys, 0);
    assert.equal(preview.skipped.passkeys, 3);
    assert.ok(w.ports[0].sent.every((m) => m.method === "encrypt_item"));
  }
  // A CSV file has no passkeys, so the vault is not asked.
  {
    const w = await worldWith(true);
    let asked = 0;
    const engine = { ...engineWith([]), passkeyKeys: async () => (asked++, []) };
    await w.session.importPreview(new File(["name,login_username\nA,b\n"], "export.csv"), { engine });
    assert.equal(asked, 0);
  }
  // A list that is not a list of texts is no list: the passkeys are left out.
  {
    const w = await worldWith(true);
    const preview = await w.session.importPreview(textFile(bitwarden(), "export.json"), { engine: { ...fakeImportEngine(), passkeyKeys: async () => [1, 2] } });
    assert.equal(preview.passkeys, null);
  }
});

test("a_site_the_page_gets_back_is_one_that_looks_like_a_site", async () => {
  const odd = (message, index) => ({
    id: message.id,
    ok: true,
    value: message.method === "passkey_import"
      ? { item: sealedValue(index), rp_id: ["rp-a.test", "<script>x</script>", "a b", "UPPER.test", ""][index % 5], notes: { register_again: true, counter: 1, prf: false } }
      : sealedValue(index),
  });
  const w = await worldWith(true, () => vaultPort({ reply: odd }));
  const many = Array.from({ length: 5 }, (_, n) => credential({ counter: "2", credentialId: `b64.${b64u(new Uint8Array(16).fill(n + 1))}` }));
  const preview = await w.session.importPreview(bitwardenFile(many, {}), { engine: engineWith([]) });
  assert.deepEqual(preview.passkeys.sites, ["rp-a.test"]);
});

test("the_engine_names_the_passkeys_of_the_vault_and_of_the_trash", async () => {
  const idA = "11".repeat(16);
  const idB = "22".repeat(16);
  const idC = "33".repeat(16);
  const model = new Model();
  const client = createFakeClient();
  // The real core's view gives the credential id as bytes; the fake keeps hex text in the body.
  const view = client.vault.item_view;
  client.vault.item_view = async (handle) => {
    const v = await view(handle);
    return v.passkey ? { ...v, passkey: { ...v.passkey, cred_id: Buffer.from(v.passkey.cred_id, "hex") } } : v;
  };
  const withPasskey = (name, rp, cred) => ({ item_type: "login", name, fields: [], passkey: { rp_id: rp, user_name: "me", cred_id: cred, user_handle: "aa", priv: "KEY-SENTINEL", created: 1 } });
  model.set(idA, { rev: 1, ...client.wireRow(idA, 1, withPasskey("A", "github.com", "0a0b0c")) });
  model.set(idB, { rev: 1, ...client.wireRow(idB, 1, withPasskey("B", "example.com", "0d0e0f")) });
  model.set(idC, { rev: 1, ...client.wireRow(idC, 1, { item_type: "login", name: "C", fields: [] }) });
  const d = await syncDevice({ model, client });
  await d.engine.start();
  const key = (rp, hex) => passkeyKey(rp, Buffer.from(hex, "hex"));
  assert.deepEqual((await d.engine.passkeyKeys()).sort(), [key("example.com", "0d0e0f"), key("github.com", "0a0b0c")].sort());
  // B is deleted elsewhere: it is in the trash, and its passkey is still the vault's (it comes back with the item).
  model.set(idB, { rev: 2, deleted: true, tomb: client.wireTomb(idB, 2) });
  await d.engine.syncNow();
  assert.equal(d.engine.list().some((entry) => entry.id === idB), false);
  assert.equal((await d.engine.trash()).length, 1);
  assert.deepEqual((await d.engine.passkeyKeys()).sort(), [key("example.com", "0d0e0f"), key("github.com", "0a0b0c")].sort());
  // Nothing in the list the page sees, or in the keys, is the key of a passkey.
  assert.equal(JSON.stringify(d.engine.list()).includes("0a0b0c"), false);
  assert.equal(JSON.stringify(await d.engine.passkeyKeys()).includes("KEY-SENTINEL"), false);
  d.engine.stop();
  await assert.rejects(() => d.engine.passkeyKeys(), (e) => e.code === "stopped");
});

test("a_passkey_the_vault_refuses_as_invalid_input_stops_the_import_instead_of_counting_it", async () => {
  // The readers make everything the vault checks that way, so this is a worker that does not know the call (an older package) or a bug.
  for (const login of [{}, { totp: "GEZDGNBVGY3TQOJQ" }]) {
    const port = passkeyPort({ refuse: (m) => (m.method === "passkey_import" ? "invalid_input" : undefined) });
    const reply = await handler()(request(bitwardenFile([credential()], login), port));
    assert.deepEqual(reply, { id: 3, ok: false, error: "import_seal_failed" }, JSON.stringify(login));
    for (const m of port.sent) if (m.method === "passkey_import") assert.ok(m.args[3].key_pkcs8.every((b) => b === 0), "wiped when the import stops");
  }
});

test("keys_decoded_before_a_reader_throws_are_wiped", () => {
  const wiped = [];
  const fill = Uint8Array.prototype.fill;
  Uint8Array.prototype.fill = function (value, ...rest) {
    if (value === 0) wiped.push(this.length);
    return fill.call(this, value, ...rest);
  };
  try {
    // A passkey, then an item that is no object: the reader refuses the file.
    const text = JSON.stringify({ encrypted: false, folders: [], items: [{ type: 1, name: "Site", login: { fido2Credentials: [credential()] } }, 7] });
    assert.throws(() => fromBitwardenJson(safeJsonParse(text), { passkeys: true, now: NOW }), (e) => e.code === "import_bad_format");
    assert.ok(wiped.includes(138), "the PKCS#8 bytes of the first passkey are wiped");
    wiped.length = 0;
    const manifest = safeJsonParse(manifestText());
    manifest.items.push(7);
    assert.throws(() => fromAvuxManifest(safeJsonParse(JSON.stringify(manifest)), { passkeys: true, now: NOW }), (e) => e.code === "import_bad_format");
    assert.ok(wiped.includes(32), "the PRF seeds of the AliasVault passkey are wiped");
  } finally {
    Uint8Array.prototype.fill = fill;
  }
});
