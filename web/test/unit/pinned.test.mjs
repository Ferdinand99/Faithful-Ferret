// The pinned record.
import assert from "node:assert/strict";
import { test } from "node:test";
import { StoreError } from "../../src/store/idb.mjs";
import { forgetPinned, loadPinned, loadPinnedByAccount, savePinned } from "../../src/store/pinned.mjs";
import { ACCOUNT, SERVER, freshStore, pinnedRecord } from "./idbHelpers.mjs";

const OTHER = "11112222333344445555666677778888";
const EMAIL = "ada@example.org";

const refusedWith = async (code, promise) => {
  await assert.rejects(promise, (error) => error instanceof StoreError && error.code === code);
};

test("pinned_is_null_on_a_new_device", async () => {
  const db = await freshStore();
  assert.equal(await loadPinned(db.store, SERVER, EMAIL), null);
  assert.equal(await loadPinnedByAccount(db.store, SERVER, ACCOUNT), null);
});

test("pinned_survives_reopen", async () => {
  const db = await freshStore();
  const record = pinnedRecord({ vk: 3, floors: [["password", 2], ["recovery", 1], ["prf", 4, [1, 2, 3]]] });
  await savePinned(db.store, SERVER, ACCOUNT, EMAIL, record);
  const store = await db.reopen();
  const loaded = await loadPinned(store, SERVER, EMAIL);
  assert.deepEqual(loaded, record);
  assert.ok(loaded.pk_a instanceof Uint8Array);
  assert.deepEqual(await loadPinnedByAccount(store, SERVER, ACCOUNT), record);
  // Another server, or another e-mail, finds nothing.
  assert.equal(await loadPinned(store, "https://other.example", EMAIL), null);
  assert.equal(await loadPinned(store, SERVER, "bob@example.org"), null);
});

test("pinned_finds_the_account_by_the_form_of_the_email_the_server_uses", async () => {
  const db = await freshStore();
  await savePinned(db.store, SERVER, ACCOUNT, "Ada@Example.org", pinnedRecord());
  assert.ok(await loadPinned(db.store, SERVER, "  ada@example.ORG "));
});

test("pinned_refuses_epoch_downgrade", async () => {
  const db = await freshStore();
  await savePinned(db.store, SERVER, ACCOUNT, EMAIL, pinnedRecord({ vk: 5 }));
  await refusedWith("pinned_epoch_downgrade", savePinned(db.store, SERVER, ACCOUNT, EMAIL, pinnedRecord({ vk: 4 })));
  // The refused save left the record as it was.
  assert.equal((await loadPinned(db.store, SERVER, EMAIL)).vk_epoch_max, 5);
  // The same epoch, or a higher one, is saved.
  await savePinned(db.store, SERVER, ACCOUNT, EMAIL, pinnedRecord({ vk: 5 }));
  await savePinned(db.store, SERVER, ACCOUNT, EMAIL, pinnedRecord({ vk: 6 }));
  assert.equal((await loadPinned(db.store, SERVER, EMAIL)).vk_epoch_max, 6);
});

test("pinned_refuses_a_lower_floor_or_kdf_profile", async () => {
  const db = await freshStore();
  const floors = [["password", 3], ["recovery", 2], ["prf", 5, [9]]];
  await savePinned(db.store, SERVER, ACCOUNT, EMAIL, pinnedRecord({ ksf: 2, floors }));
  await refusedWith(
    "pinned_floor_downgrade",
    savePinned(db.store, SERVER, ACCOUNT, EMAIL, pinnedRecord({ ksf: 2, floors: [["password", 2], ["recovery", 2], ["prf", 5, [9]]] })),
  );
  await refusedWith(
    "pinned_floor_downgrade",
    savePinned(db.store, SERVER, ACCOUNT, EMAIL, pinnedRecord({ ksf: 2, floors: [["password", 3], ["recovery", 2], ["prf", 4, [9]]] })),
  );
  await refusedWith("pinned_profile_downgrade", savePinned(db.store, SERVER, ACCOUNT, EMAIL, pinnedRecord({ ksf: 1, floors })));
  // A passkey with another credential is another floor: it starts fresh.
  await savePinned(db.store, SERVER, ACCOUNT, EMAIL, pinnedRecord({ ksf: 2, floors: [["password", 3], ["recovery", 2], ["prf", 1, [8]]] }));
  assert.equal((await loadPinned(db.store, SERVER, EMAIL)).kek_generation_max.length, 3);
});

test("pinned_refuses_something_that_is_not_a_record", async () => {
  const db = await freshStore();
  const bad = [
    null,
    {},
    { ...pinnedRecord(), vk_epoch_max: -1 },
    { ...pinnedRecord(), kek_generation_max: "x" },
    { ...pinnedRecord(), ksf_profile: 1.5 },
  ];
  for (const record of bad) {
    await refusedWith("pinned_malformed", savePinned(db.store, SERVER, ACCOUNT, EMAIL, record));
  }
  await assert.rejects(savePinned(db.store, SERVER, "not-an-id", EMAIL, pinnedRecord()), TypeError);
  await assert.rejects(savePinned(db.store, "", ACCOUNT, EMAIL, pinnedRecord()), TypeError);
  await assert.rejects(savePinned(db.store, SERVER, ACCOUNT, "  ", pinnedRecord()), TypeError);
});

test("pinned_is_keyed_on_account_id_and_the_email_index_survives_an_email_change", async () => {
  const db = await freshStore();
  await savePinned(db.store, SERVER, ACCOUNT, EMAIL, pinnedRecord({ vk: 2 }));
  await savePinned(db.store, SERVER, OTHER, "bob@example.org", pinnedRecord({ vk: 1, accountId: OTHER }));
  assert.equal((await loadPinned(db.store, SERVER, EMAIL)).account_id, ACCOUNT);
  assert.equal((await loadPinned(db.store, SERVER, "bob@example.org")).account_id, OTHER);

  // The owner changes the e-mail: the same record is found under the new one,
  // and the old address no longer leads to it.
  await savePinned(db.store, SERVER, ACCOUNT, "ada@new.example", pinnedRecord({ vk: 2 }));
  const store = await db.reopen();
  assert.equal((await loadPinned(store, SERVER, "ada@new.example")).account_id, ACCOUNT);
  assert.equal(await loadPinned(store, SERVER, EMAIL), null);
  assert.equal((await loadPinned(store, SERVER, "bob@example.org")).account_id, OTHER);

  // Someone else takes the new address: it leads to them and no longer to the
  // first account, whose record is still there under its account id.
  await savePinned(store, SERVER, OTHER, "ada@new.example", pinnedRecord({ vk: 1, accountId: OTHER }));
  assert.equal((await loadPinned(store, SERVER, "ada@new.example")).account_id, OTHER);
  assert.ok(await loadPinnedByAccount(store, SERVER, ACCOUNT));
});

test("pinned_does_not_let_a_sign_in_under_a_new_email_lower_the_floors_of_a_known_account", async () => {
  const db = await freshStore();
  await savePinned(db.store, SERVER, ACCOUNT, EMAIL, pinnedRecord({ vk: 4 }));
  // The device does not know the new e-mail, so a sign-in starts from nothing,
  assert.equal(await loadPinned(db.store, SERVER, "ada@new.example"), null);
  // but the account id is the same and a first-use record cannot replace the floors.
  await refusedWith("pinned_epoch_downgrade", savePinned(db.store, SERVER, ACCOUNT, "ada@new.example", pinnedRecord({ vk: 1 })));
});

test("forgetting_a_server_removes_the_record_and_its_index", async () => {
  const db = await freshStore();
  await savePinned(db.store, SERVER, ACCOUNT, EMAIL, pinnedRecord());
  await forgetPinned(db.store, SERVER, ACCOUNT);
  assert.equal(await loadPinned(db.store, SERVER, EMAIL), null);
  assert.equal(await loadPinnedByAccount(db.store, SERVER, ACCOUNT), null);
  // A lower record may be saved afresh once the server is forgotten.
  await savePinned(db.store, SERVER, ACCOUNT, EMAIL, pinnedRecord({ vk: 1 }));
});
