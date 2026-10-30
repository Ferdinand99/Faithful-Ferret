// The settings store: the device id, and the device secrets.
import assert from "node:assert/strict";
import { test } from "node:test";
import { cache } from "../../src/store/cache.mjs";
import { deleteSetting, deviceId, deviceSecrets, getSetting, setSetting } from "../../src/store/settings.mjs";
import { ACCOUNT, SERVER, freshStore, scope } from "./idbHelpers.mjs";

test("device_id_is_stable_across_reopen", async () => {
  const db = await freshStore();
  const first = await deviceId(db.store);
  assert.match(first, /^[0-9a-f]{32}$/);
  assert.equal(await deviceId(db.store), first);
  const store = await db.reopen();
  assert.equal(await deviceId(store), first);
  assert.equal(await getSetting(store, "device_id"), first);
  // A new browser (a new database) gets its own.
  const other = await freshStore();
  assert.notEqual(await deviceId(other.store), first);
});

test("device_id_is_made_once_from_16_random_bytes", async () => {
  const db = await freshStore();
  let calls = 0;
  const rand = (bytes) => {
    calls += 1;
    return bytes.fill(0xab);
  };
  assert.equal(await deviceId(db.store, rand), "ab".repeat(16));
  assert.equal(await deviceId(db.store, rand), "ab".repeat(16));
  assert.equal(calls, 1);
});

test("two_tabs_asking_for_the_device_id_at_once_agree", async () => {
  const db = await freshStore();
  const ids = await Promise.all(Array.from({ length: 8 }, () => deviceId(db.store)));
  assert.equal(new Set(ids).size, 1);
});

test("settings_store_and_delete_values", async () => {
  const db = await freshStore();
  assert.equal(await getSetting(db.store, "language"), undefined);
  await setSetting(db.store, "language", "nb");
  assert.equal(await getSetting(db.store, "language"), "nb");
  await deleteSetting(db.store, "language");
  assert.equal(await getSetting(db.store, "language"), undefined);
  await assert.rejects(setSetting(db.store, "", 1), TypeError);
});

test("device_secrets_store_holds_the_sealing_key_and_the_sealed_sk_and_clearing_the_cache_leaves_it_alone", async () => {
  const db = await freshStore();
  const key = await crypto.subtle.generateKey({ name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]);
  const aad = new TextEncoder().encode(`${SERVER}\n${ACCOUNT}`);
  const iv = new Uint8Array(12).fill(1);
  const secret = new TextEncoder().encode("the secret key code");
  const sealed = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv, additionalData: aad }, key, secret));

  assert.equal(await deviceSecrets.get(db.store, SERVER, ACCOUNT), null);
  await deviceSecrets.put(db.store, SERVER, ACCOUNT, { key, iv, sealed });

  // Clearing the row cache leaves the secrets alone.
  await cache.putRows(db.store, scope(), []);
  await cache.clear(db.store, scope());
  await cache.clearAccount(db.store, ACCOUNT);

  const store = await db.reopen();
  const back = await deviceSecrets.get(store, SERVER, ACCOUNT);
  assert.ok(back.key.extractable === false, "the sealing key is still not extractable");
  assert.deepEqual(back.sealed, sealed);
  // The key that came back out of the database still opens the seal ...
  const opened = await crypto.subtle.decrypt({ name: "AES-GCM", iv: back.iv, additionalData: aad }, back.key, back.sealed);
  assert.deepEqual(new Uint8Array(opened), secret);
  // ... and nothing readable about the secret is stored next to it.
  assert.ok(!JSON.stringify(Array.from(back.sealed)).includes(String(Array.from(secret))));

  // The secrets are per server and account.
  assert.equal(await deviceSecrets.get(store, "https://other.example", ACCOUNT), null);
  assert.equal(await deviceSecrets.get(store, SERVER, "11112222333344445555666677778888"), null);

  await deviceSecrets.delete(store, SERVER, ACCOUNT);
  assert.equal(await deviceSecrets.get(store, SERVER, ACCOUNT), null);
  await assert.rejects(deviceSecrets.put(store, SERVER, ACCOUNT, "text"), TypeError);
  await assert.rejects(deviceSecrets.get(store, SERVER, "nope"), TypeError);
});
