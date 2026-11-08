// Opening the database.
import assert from "node:assert/strict";
import { test } from "node:test";
import { DB_VERSION, serverKey, STORES } from "../../src/store/idb.mjs";
import { freshStore } from "./idbHelpers.mjs";

test("the_store_tells_its_owner_when_another_tab_upgrades_the_database", async () => {
  let closed = 0;
  const db = await freshStore(() => {
    closed += 1;
  });
  // Another tab opens a newer version: this connection is asked to let go.
  const upgrade = db.factory.open("ferret", DB_VERSION + 1);
  await new Promise((resolve, reject) => {
    upgrade.onsuccess = () => {
      upgrade.result.close();
      resolve(undefined);
    };
    upgrade.onerror = () => reject(upgrade.error);
  });
  assert.equal(closed, 1);
});

test("the_database_has_the_seven_stores_of_version_2", async () => {
  const db = await freshStore();
  assert.equal(DB_VERSION, 2);
  assert.equal(STORES.length, 7);
  assert.deepEqual([...db.store.db.objectStoreNames].sort(), [...STORES].sort());
});

test("a_server_is_known_by_its_origin", () => {
  assert.equal(serverKey("https://vault.example"), "https://vault.example");
  assert.equal(serverKey("https://vault.example/"), "https://vault.example");
  assert.equal(serverKey("https://vault.example/app/?x=1#y"), "https://vault.example");
  assert.equal(serverKey("HTTPS://Vault.Example:443/"), "https://vault.example");
  assert.equal(serverKey("http://127.0.0.1:3041"), "http://127.0.0.1:3041");
  for (const bad of ["", "vault.example", "javascript:alert(1)", "file:///etc/passwd", null, 5]) {
    assert.throws(() => serverKey(bad), TypeError, String(bad));
  }
});

test("the_store_service_offers_one_sign_in_lookup", async () => {
  const { default: service } = await import("../../src/services/store.service.mjs");
  const store = service.create({});
  assert.equal(typeof store.pinnedForSignIn, "function");
  assert.equal("loadPinned" in store, false);
  assert.equal("loadPinnedByAccount" in store, false);
});

test("the_store_service_offers_sync_state_trash_and_forget", async () => {
  const { default: service } = await import("../../src/services/store.service.mjs");
  const store = service.create({});
  for (const name of ["loadSyncState", "saveSyncState", "forgetServer", "pendingWrites"]) {
    assert.equal(typeof store[name], "function", name);
  }
  for (const name of ["put", "all", "get", "remove", "purgeBefore", "clear"]) {
    assert.equal(typeof store.trash[name], "function", `trash.${name}`);
  }
});
