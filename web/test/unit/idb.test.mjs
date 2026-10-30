// Opening the database.
import assert from "node:assert/strict";
import { test } from "node:test";
import { serverKey } from "../../src/store/idb.mjs";
import { freshStore } from "./idbHelpers.mjs";

test("the_store_tells_its_owner_when_another_tab_upgrades_the_database", async () => {
  let closed = 0;
  const db = await freshStore(() => {
    closed += 1;
  });
  // Another tab opens a newer version: this connection is asked to let go.
  const upgrade = db.factory.open("ferret", 2);
  await new Promise((resolve, reject) => {
    upgrade.onsuccess = () => {
      upgrade.result.close();
      resolve(undefined);
    };
    upgrade.onerror = () => reject(upgrade.error);
  });
  assert.equal(closed, 1);
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
