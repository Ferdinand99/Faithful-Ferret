// The key of a device client: made non-extractable, stored in `device_keys`
// only after a successful sign-in, one record per server, and never written
// anywhere else. Spec: Fase 1 § 7.6; RFC 7638 § 3 for the thumbprint.
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { test } from "node:test";
import {
  DEVICE_KEY_FIELDS, deleteDeviceKey, generateDeviceKey, loadDeviceKey, saveDeviceKey, saveRefreshToken, thumbprint,
} from "../../src/auth/deviceKey.mjs";
import { createClock, createProof } from "../../src/auth/dpop.mjs";
import { run, req } from "../../src/store/idb.mjs";
import { web } from "./helpers.mjs";
import { ACCOUNT, freshStore, SERVER } from "./idbHelpers.mjs";

const WIRE = join(web, "..", "crates", "ferret-server", "tests", "fixtures", "wire");
const DEVICE = "7e3a9c1f5b2d48a6b0c4d8e2f6a1b3c5";
const OTHER_DEVICE = "c5b3a1f6e2d8c4b0a6482d5b1f9c3a7e";
const token = (fill) => Buffer.alloc(32, fill).toString("base64url");
const signedIn = (fill = 1, deviceId = DEVICE) => ({ deviceId, accountId: ACCOUNT, refreshToken: token(fill) });

/** Every record of `device_keys`, read straight from the database. */
const rawRecords = (store) => run(store, ["device_keys"], "readonly", ([table]) => req(table.getAll()));

/** Signs `data` with the private key and checks it with the public JWK, through WebCrypto. */
async function signsFor(key) {
  const data = new TextEncoder().encode("ferret device key test");
  const signature = await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, key.privateKey, data);
  const verifier = await crypto.subtle.importKey("jwk", key.publicJwk, { name: "ECDSA", namedCurve: "P-256" }, false, ["verify"]);
  return crypto.subtle.verify({ name: "ECDSA", hash: "SHA-256" }, verifier, signature, data);
}

/** A WebCrypto that records what each call to exportKey returned. */
function recordingSubtle() {
  const exports = [];
  return {
    exports,
    subtle: {
      generateKey: (...args) => crypto.subtle.generateKey(...args),
      async exportKey(format, key) {
        const out = await crypto.subtle.exportKey(format, key);
        exports.push({ format, type: key.type, out });
        return out;
      },
    },
  };
}

test("device_key_is_not_extractable_and_survives_reopening_the_db", async () => {
  const db = await freshStore();
  const key = await generateDeviceKey(`${SERVER}/some/path?x=1`);
  assert.equal(key.serverUrl, SERVER, "a server is known by its origin");
  assert.equal(key.privateKey.extractable, false);
  assert.equal(key.privateKey.type, "private");
  assert.deepEqual(key.privateKey.usages, ["sign"]);
  assert.equal(key.privateKey.algorithm.name, "ECDSA");
  assert.equal(key.privateKey.algorithm.namedCurve, "P-256");
  assert.deepEqual([key.deviceId, key.accountId, key.refreshToken], [null, null, null]);

  await saveDeviceKey(db.store, key, signedIn());
  const store = await db.reopen();
  const loaded = await loadDeviceKey(store, `${SERVER}/`);
  assert.ok(loaded);
  assert.deepEqual(Object.keys(loaded).sort(), [...DEVICE_KEY_FIELDS].sort());
  assert.equal(loaded.serverUrl, SERVER);
  assert.equal(loaded.privateKey.extractable, false);
  assert.equal(loaded.privateKey.type, "private");
  assert.deepEqual(loaded.publicJwk, key.publicJwk);
  assert.deepEqual([loaded.deviceId, loaded.accountId, loaded.refreshToken], [DEVICE, ACCOUNT, token(1)]);
  assert.equal(await signsFor(loaded), true, "the stored key still signs, and the public JWK is its own");
  await assert.rejects(crypto.subtle.exportKey("jwk", loaded.privateKey));
  await assert.rejects(crypto.subtle.exportKey("pkcs8", loaded.privateKey));

  // A proof made with the stored key is one the public JWK verifies.
  const proof = await createProof(loaded, { method: "GET", url: `${SERVER}/api/sync/changes`, clock: createClock() });
  assert.equal(proof.split(".").length, 3);
  assert.equal(await loadDeviceKey(store, "https://other.example"), null);
});

test("a_new_login_key_replaces_the_old_one", async () => {
  const db = await freshStore();
  const first = await generateDeviceKey(SERVER);
  await saveDeviceKey(db.store, first, signedIn(1));
  const second = await generateDeviceKey(SERVER);
  assert.notDeepEqual(second.publicJwk, first.publicJwk, "every sign-in makes a new key");
  await saveDeviceKey(db.store, second, signedIn(2, OTHER_DEVICE));

  const records = await rawRecords(db.store);
  assert.equal(records.length, 1, "one record per server");
  const loaded = await loadDeviceKey(db.store, SERVER);
  assert.deepEqual(loaded?.publicJwk, second.publicJwk);
  assert.equal(loaded?.deviceId, OTHER_DEVICE);
  assert.equal(loaded?.refreshToken, token(2));
  assert.notEqual(await thumbprint(loaded.publicJwk), await thumbprint(first.publicJwk));

  // A key for another server is a record of its own.
  const elsewhere = await generateDeviceKey("https://other.example");
  await saveDeviceKey(db.store, elsewhere, signedIn(3));
  assert.equal((await rawRecords(db.store)).length, 2);
  await deleteDeviceKey(db.store, SERVER);
  assert.equal(await loadDeviceKey(db.store, SERVER), null);
  assert.deepEqual((await loadDeviceKey(db.store, "https://other.example"))?.publicJwk, elsewhere.publicJwk);
  await deleteDeviceKey(db.store, SERVER); // not there: no error
});

test("a_key_is_stored_only_after_a_successful_login", async () => {
  const db = await freshStore();
  // Making a key writes nothing.
  const key = await generateDeviceKey(SERVER);
  assert.deepEqual(await rawRecords(db.store), []);

  // Without what a successful sign-in answers, nothing is stored.
  for (const partial of [
    {},
    { deviceId: DEVICE, accountId: ACCOUNT },
    { deviceId: DEVICE, refreshToken: token(1) },
    { accountId: ACCOUNT, refreshToken: token(1) },
    { deviceId: null, accountId: ACCOUNT, refreshToken: token(1) },
    { deviceId: DEVICE.toUpperCase(), accountId: ACCOUNT, refreshToken: token(1) },
    { deviceId: DEVICE, accountId: ACCOUNT, refreshToken: `${token(1)}=` },
    { deviceId: DEVICE, accountId: ACCOUNT, refreshToken: token(1).slice(1) },
    { deviceId: DEVICE, accountId: ACCOUNT, refreshToken: Buffer.alloc(33, 1).toString("base64url") },
  ]) {
    await assert.rejects(saveDeviceKey(db.store, key, partial), (e) => e.code === "device_key_malformed", JSON.stringify(partial));
  }
  // An old record stays when a new sign-in does not finish.
  await saveDeviceKey(db.store, key, signedIn(1));
  const next = await generateDeviceKey(SERVER);
  await assert.rejects(saveDeviceKey(db.store, next, { deviceId: DEVICE, accountId: ACCOUNT, refreshToken: null }));
  assert.deepEqual((await loadDeviceKey(db.store, SERVER))?.publicJwk, key.publicJwk);

  // A key that is not the non-extractable signing key of a device is never stored.
  const extractable = await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"]);
  const p384 = await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-384" }, false, ["sign", "verify"]);
  for (const privateKey of [extractable.privateKey, p384.privateKey, extractable.publicKey, null]) {
    await assert.rejects(saveDeviceKey(db.store, { ...next, privateKey }, signedIn(2)), (e) => e.code === "device_key_malformed");
  }
  await assert.rejects(saveDeviceKey(db.store, { ...next, publicJwk: { ...next.publicJwk, ext: true } }, signedIn(2)));
  assert.deepEqual((await loadDeviceKey(db.store, SERVER))?.publicJwk, key.publicJwk);
});

test("a_private_key_and_a_public_jwk_of_two_pairs_are_never_stored", async () => {
  const db = await freshStore();
  const first = await generateDeviceKey(SERVER);
  const second = await generateDeviceKey(SERVER);
  // The key of one sign-in with the JWK of another (a retried sign-in mixed up) is refused, and nothing is stored.
  await assert.rejects(
    saveDeviceKey(db.store, { ...first, publicJwk: second.publicJwk }, signedIn(1)),
    (e) => e.code === "device_key_malformed" && /one key pair/.test(e.message),
  );
  // A JWK that is a valid point of P-256 but of no key the record holds: the RFC 9449 example key.
  const { jwk } = JSON.parse(readFileSync(join(WIRE, "dpop_jwk.json"), "utf8"));
  await assert.rejects(saveDeviceKey(db.store, { ...first, publicJwk: jwk }, signedIn(1)), (e) => e.code === "device_key_malformed");
  assert.deepEqual(await rawRecords(db.store), []);
  // An older record stays when the new one is refused.
  await saveDeviceKey(db.store, first, signedIn(1));
  await assert.rejects(saveDeviceKey(db.store, { ...second, publicJwk: first.publicJwk }, signedIn(2)), (e) => e.code === "device_key_malformed");
  const loaded = await loadDeviceKey(db.store, SERVER);
  assert.deepEqual(loaded?.publicJwk, first.publicJwk);
  assert.equal(loaded?.refreshToken, token(1));
  assert.equal(await signsFor(loaded), true);
});

test("the_refresh_token_is_replaced_in_the_stored_record_only", async () => {
  const db = await freshStore();
  await assert.rejects(saveRefreshToken(db.store, SERVER, token(5)), (e) => e.code === "device_key_missing");
  const key = await generateDeviceKey(SERVER);
  await saveDeviceKey(db.store, key, signedIn(1));
  await saveRefreshToken(db.store, `${SERVER}/`, token(6));
  const loaded = await loadDeviceKey(db.store, SERVER);
  assert.equal(loaded?.refreshToken, token(6));
  assert.equal(loaded?.deviceId, DEVICE);
  assert.deepEqual(loaded?.publicJwk, key.publicJwk);
  assert.equal(await signsFor(loaded), true);
  for (const bad of [null, "", token(7).slice(2), `${token(7)}x`, 7]) {
    await assert.rejects(saveRefreshToken(db.store, SERVER, bad), (e) => e.code === "device_key_malformed");
  }
  assert.equal((await loadDeviceKey(db.store, SERVER))?.refreshToken, token(6));
});

test("a_stored_record_of_another_shape_is_refused", async () => {
  const db = await freshStore();
  const key = await generateDeviceKey(SERVER);
  await saveDeviceKey(db.store, key, signedIn(1));
  const [good] = await rawRecords(db.store);
  const putRaw = (value) => run(db.store, ["device_keys"], "readwrite", async ([table]) => { await req(table.put(value)); });
  for (const damaged of [
    { ...good, extra: 1 },
    { ...good, refreshToken: null },
    { ...good, deviceId: "not-an-id" },
    { ...good, publicJwk: { ...good.publicJwk, d: good.publicJwk.x } },
    { ...good, publicJwk: { ...good.publicJwk, crv: "P-384" } },
    { ...good, privateKey: "a key" },
    (({ accountId, ...rest }) => rest)(good),
  ]) {
    await putRaw(damaged);
    await assert.rejects(loadDeviceKey(db.store, SERVER), (e) => e.code === "device_key_malformed");
  }
  await putRaw(good);
  assert.deepEqual((await loadDeviceKey(db.store, SERVER))?.publicJwk, key.publicJwk);
});

test("the_public_jwk_has_exactly_four_members_from_a_real_export", async () => {
  const { subtle, exports } = recordingSubtle();
  const key = await generateDeviceKey(SERVER, { subtle });
  // The real export of the public key has more than the four members (WebCrypto adds `ext` and
  // `key_ops`), and the key copies exactly `kty`, `crv`, `x` and `y` out of it.
  assert.equal(exports.length, 1);
  assert.equal(exports[0].format, "jwk");
  assert.equal(exports[0].type, "public");
  assert.deepEqual(Object.keys(exports[0].out).sort(), ["crv", "ext", "key_ops", "kty", "x", "y"]);
  assert.deepEqual(Object.keys(key.publicJwk), ["kty", "crv", "x", "y"]);
  assert.deepEqual(key.publicJwk, { kty: "EC", crv: "P-256", x: exports[0].out.x, y: exports[0].out.y });
  for (const coordinate of [key.publicJwk.x, key.publicJwk.y]) {
    assert.match(coordinate, /^[A-Za-z0-9_-]{43}$/);
    assert.equal(Buffer.from(coordinate, "base64url").length, 32);
  }
  assert.equal(await signsFor(key), true);
});

test("jkt_matches_the_wire_fixture", async () => {
  // The key of RFC 9449 § 4.1 and its thumbprint (§ 6.1), as the server's wire fixture has them.
  const { jwk, jkt } = JSON.parse(readFileSync(join(WIRE, "dpop_jwk.json"), "utf8"));
  assert.equal(await thumbprint(jwk), jkt);
  assert.equal(jkt, "0ZcOCORZNYy-DWpqq30jZyJGHTN0d2HglBV3uiguA4I");
  // The order of the members does not change it; anything but the four public members is refused.
  assert.equal(await thumbprint({ y: jwk.y, x: jwk.x, crv: jwk.crv, kty: jwk.kty }), jkt);
  for (const bad of [{ ...jwk, d: jwk.x }, { ...jwk, ext: true }, { ...jwk, crv: "P-384" }, { ...jwk, kty: "RSA" }, { ...jwk, x: `${jwk.x}A` }, { ...jwk, y: jwk.y.slice(1) }, null]) {
    await assert.rejects(thumbprint(bad));
  }
  // A thumbprint is 32 bytes as base64url, and two keys have two.
  const key = await generateDeviceKey(SERVER);
  assert.match(await thumbprint(key.publicJwk), /^[A-Za-z0-9_-]{43}$/);
  assert.notEqual(await thumbprint(key.publicJwk), jkt);
});

test("no_private_key_material_is_ever_exported", async () => {
  const { subtle, exports } = recordingSubtle();
  const db = await freshStore();
  const key = await generateDeviceKey(SERVER, { subtle });
  // Only the public key is exported, and only once.
  assert.deepEqual(exports.map((e) => e.type), ["public"]);
  for (const format of ["jwk", "pkcs8", "raw", "spki"]) {
    await assert.rejects(crypto.subtle.exportKey(format, key.privateKey), undefined, format);
  }
  const wrapping = await crypto.subtle.generateKey({ name: "AES-KW", length: 256 }, false, ["wrapKey"]);
  await assert.rejects(crypto.subtle.wrapKey("jwk", key.privateKey, wrapping, "AES-KW"));

  await saveDeviceKey(db.store, key, signedIn(1));
  const [record] = await rawRecords(db.store);
  assert.equal(record.privateKey.extractable, false);
  assert.deepEqual(Object.keys(record.publicJwk).sort(), ["crv", "kty", "x", "y"]);
  // Nothing in the record but the CryptoKey is key material, and it has no readable bytes.
  const json = JSON.stringify(record);
  assert.equal(json.includes('"d"'), false);
  assert.deepEqual(JSON.parse(json).privateKey, {});
  const proof = await createProof(record, { method: "POST", url: `${SERVER}/api/auth/token/refresh`, clock: createClock() });
  const [header, claims] = proof.split(".").slice(0, 2).map((s) => JSON.parse(Buffer.from(s, "base64url").toString("utf8")));
  assert.deepEqual(Object.keys(header.jwk), ["kty", "crv", "x", "y"]);
  assert.equal(JSON.stringify({ header, claims }).includes('"d"'), false);
});

test("nothing_reaches_local_storage_session_storage_or_console", async (t) => {
  // Storage that records every call, and a console that records every call.
  const calls = [];
  const storage = (name) =>
    new Proxy({}, {
      get: (_, prop) => {
        calls.push(`${name}.${String(prop)}`);
        return () => undefined;
      },
      set: (_, prop) => {
        calls.push(`${name}.${String(prop)}=`);
        return true;
      },
    });
  for (const name of ["localStorage", "sessionStorage"]) {
    const had = Object.getOwnPropertyDescriptor(globalThis, name);
    Object.defineProperty(globalThis, name, { value: storage(name), configurable: true, writable: true });
    t.after(() => {
      if (had) Object.defineProperty(globalThis, name, had);
      else delete globalThis[name];
    });
  }
  for (const method of ["log", "info", "warn", "error", "debug", "trace", "dir", "table"]) {
    t.mock.method(console, method, (...args) => calls.push(`console.${method}: ${args.length}`));
  }

  const db = await freshStore();
  const clock = createClock({ now: () => 1_793_491_200_000 });
  clock.observe(new Date(1_793_491_200_000).toUTCString());
  const key = await generateDeviceKey(SERVER);
  await createProof(key, { method: "POST", url: `${SERVER}/api/auth/opaque/login/finish`, clock });
  await saveDeviceKey(db.store, key, signedIn(1));
  await saveRefreshToken(db.store, SERVER, token(2));
  const loaded = await loadDeviceKey(db.store, SERVER);
  await createProof(loaded, { method: "GET", url: `${SERVER}/api/sync/changes?x=1`, accessToken: token(3), clock });
  await assert.rejects(saveDeviceKey(db.store, key, {}));
  await assert.rejects(createProof(loaded, { method: "get", url: SERVER, clock }));
  await thumbprint(key.publicJwk);
  await deleteDeviceKey(db.store, SERVER);
  assert.deepEqual(calls, []);
});
