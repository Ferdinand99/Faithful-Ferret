// The pinned record.
import assert from "node:assert/strict";
import { test } from "node:test";
import { hex16 } from "../../src/b64.mjs";
import { StoreError } from "../../src/store/idb.mjs";
import { forgetPinned, loadPinned, loadPinnedByAccount, pinnedForSignIn, savePinned } from "../../src/store/pinned.mjs";
import { ACCOUNT, SERVER, freshStore, pinnedRecord } from "./idbHelpers.mjs";

const OTHER = "11112222333344445555666677778888";
const EMAIL = "ada@example.org";
const NEW_VAULT = "00ff00ff00ff00ff00ff00ff00ff00ff";
const idOf = (record) => hex16.encode(record.account_id);

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
  // A passkey with another credential is another floor: the old one is still
  // missing, and a new one next to it is fine.
  await refusedWith(
    "pinned_floor_missing",
    savePinned(db.store, SERVER, ACCOUNT, EMAIL, pinnedRecord({ ksf: 2, floors: [["password", 3], ["recovery", 2], ["prf", 1, [8]]] })),
  );
  await savePinned(db.store, SERVER, ACCOUNT, EMAIL, pinnedRecord({ ksf: 2, floors: [...floors, ["prf", 1, [8]]] }));
  assert.equal((await loadPinned(db.store, SERVER, EMAIL)).kek_generation_max.length, 4);
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
  assert.equal(idOf(await loadPinned(db.store, SERVER, EMAIL)), ACCOUNT);
  assert.equal(idOf(await loadPinned(db.store, SERVER, "bob@example.org")), OTHER);

  // The owner changes the e-mail: the same record is found under the new one,
  // and the old address no longer leads to it.
  await savePinned(db.store, SERVER, ACCOUNT, "ada@new.example", pinnedRecord({ vk: 2 }));
  const store = await db.reopen();
  assert.equal(idOf(await loadPinned(store, SERVER, "ada@new.example")), ACCOUNT);
  assert.equal(await loadPinned(store, SERVER, EMAIL), null);
  assert.equal(idOf(await loadPinned(store, SERVER, "bob@example.org")), OTHER);

  // Someone else takes the new address: it leads to them and no longer to the
  // first account, whose record is still there under its account id.
  await savePinned(store, SERVER, OTHER, "ada@new.example", pinnedRecord({ vk: 1, accountId: OTHER }));
  assert.equal(idOf(await loadPinned(store, SERVER, "ada@new.example")), OTHER);
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

test("pinned_refuses_a_record_that_drops_a_floor_and_then_adds_it_back_lower", async () => {
  const db = await freshStore();
  const full = [["password", 3], ["recovery", 4], ["prf", 5, [1, 2]]];
  await savePinned(db.store, SERVER, ACCOUNT, EMAIL, pinnedRecord({ vk: 2, floors: full }));
  // A first-use style record: fewer floors, same epoch.
  await refusedWith("pinned_floor_missing", savePinned(db.store, SERVER, ACCOUNT, EMAIL, pinnedRecord({ vk: 2, floors: [["password", 3]] })));
  await refusedWith("pinned_floor_missing", savePinned(db.store, SERVER, ACCOUNT, EMAIL, pinnedRecord({ vk: 2, floors: [] })));
  // The record is as it was, so a floor cannot be re-added lower in a second step.
  await refusedWith(
    "pinned_floor_downgrade",
    savePinned(db.store, SERVER, ACCOUNT, EMAIL, pinnedRecord({ vk: 2, floors: [["password", 3], ["recovery", 1], ["prf", 5, [1, 2]]] })),
  );
  assert.equal((await loadPinned(db.store, SERVER, EMAIL)).kek_generation_max.length, 3);
  // Floors may rise, and a new method may be added.
  await savePinned(
    db.store,
    SERVER,
    ACCOUNT,
    EMAIL,
    pinnedRecord({ vk: 2, floors: [["password", 4], ["recovery", 4], ["prf", 5, [1, 2]], ["prf", 1, [7]]] }),
  );
});

test("pinned_refuses_a_change_of_server_account_vault_or_sk_bit", async () => {
  const db = await freshStore();
  await savePinned(db.store, SERVER, ACCOUNT, EMAIL, pinnedRecord({ vk: 2 }));
  await refusedWith("pinned_key_mismatch", savePinned(db.store, SERVER, ACCOUNT, EMAIL, pinnedRecord({ vk: 2, server: "https://evil.example" })));
  await refusedWith("pinned_identity_changed", savePinned(db.store, SERVER, ACCOUNT, EMAIL, pinnedRecord({ vk: 2, vaultId: NEW_VAULT })));
  await refusedWith("pinned_identity_changed", savePinned(db.store, SERVER, ACCOUNT, EMAIL, pinnedRecord({ vk: 2, skBit: false })));
  await refusedWith("pinned_identity_changed", savePinned(db.store, SERVER, ACCOUNT, EMAIL, pinnedRecord({ vk: 9, skBit: false })));
  assert.equal((await loadPinned(db.store, SERVER, EMAIL)).vk_epoch_max, 2);
});

test("pinned_refuses_a_change_of_the_server_address_inside_the_record", async () => {
  const db = await freshStore();
  // The same pin (same origin) with the address spelled another way is another record.
  await savePinned(db.store, "https://vault.example", ACCOUNT, EMAIL, pinnedRecord({ server: "https://vault.example" }));
  await refusedWith(
    "pinned_identity_changed",
    savePinned(db.store, "https://vault.example/", ACCOUNT, EMAIL, pinnedRecord({ server: "https://vault.example/" })),
  );
});

test("pinned_refuses_a_change_of_the_server_key_once_it_is_set", async () => {
  const db = await freshStore();
  // Unset to set is the first pin of the key.
  await savePinned(db.store, SERVER, ACCOUNT, EMAIL, pinnedRecord({ serverKey: null }));
  await savePinned(db.store, SERVER, ACCOUNT, EMAIL, pinnedRecord({ serverKey: 7 }));
  await refusedWith("pinned_server_key_changed", savePinned(db.store, SERVER, ACCOUNT, EMAIL, pinnedRecord({ serverKey: 8 })));
  await refusedWith("pinned_server_key_changed", savePinned(db.store, SERVER, ACCOUNT, EMAIL, pinnedRecord({ serverKey: null })));
  await savePinned(db.store, SERVER, ACCOUNT, EMAIL, pinnedRecord({ serverKey: 7, vk: 2 }));
});

test("pinned_refuses_a_new_account_key_at_the_same_epoch", async () => {
  const db = await freshStore();
  await savePinned(db.store, SERVER, ACCOUNT, EMAIL, pinnedRecord({ vk: 2, pkA: 3 }));
  await refusedWith("pinned_pk_a_changed", savePinned(db.store, SERVER, ACCOUNT, EMAIL, pinnedRecord({ vk: 2, pkA: 4 })));
  // A new epoch has a new account key.
  await savePinned(db.store, SERVER, ACCOUNT, EMAIL, pinnedRecord({ vk: 3, pkA: 4 }));
  await refusedWith("pinned_pk_a_changed", savePinned(db.store, SERVER, ACCOUNT, EMAIL, pinnedRecord({ vk: 3, pkA: 5 })));
});

test("pinned_refuses_a_record_for_another_account_or_server_than_its_key", async () => {
  const db = await freshStore();
  await refusedWith("pinned_key_mismatch", savePinned(db.store, SERVER, ACCOUNT, EMAIL, pinnedRecord({ accountId: OTHER })));
  await refusedWith("pinned_key_mismatch", savePinned(db.store, "https://other.example", ACCOUNT, EMAIL, pinnedRecord()));
  assert.equal(await loadPinnedByAccount(db.store, SERVER, ACCOUNT), null);
  assert.equal(await loadPinnedByAccount(db.store, SERVER, OTHER), null);
  // Ids and keys are bytes, as the core hands them over.
  await refusedWith("pinned_malformed", savePinned(db.store, SERVER, ACCOUNT, EMAIL, { ...pinnedRecord(), account_id: ACCOUNT }));
  await refusedWith("pinned_malformed", savePinned(db.store, SERVER, ACCOUNT, EMAIL, { ...pinnedRecord(), pk_a: new Uint8Array(31) }));
  await refusedWith("pinned_malformed", savePinned(db.store, SERVER, ACCOUNT, EMAIL, { ...pinnedRecord(), sk_bit: "yes" }));
});

test("the_same_server_with_or_without_a_trailing_slash_is_one_pin", async () => {
  const db = await freshStore();
  await savePinned(db.store, "https://vault.example/", ACCOUNT, EMAIL, pinnedRecord({ server: "https://vault.example/" }));
  assert.ok(await loadPinned(db.store, "https://vault.example", EMAIL));
  assert.ok(await loadPinnedByAccount(db.store, "https://vault.example/", ACCOUNT));
  assert.equal(await loadPinned(db.store, "https://vault.example:8443", EMAIL), null);
  await assert.rejects(loadPinned(db.store, "not a url", EMAIL), TypeError);
  await assert.rejects(loadPinned(db.store, "javascript:alert(1)", EMAIL), TypeError);
});

test("pinned_for_sign_in_takes_the_record_the_email_maps_to", async () => {
  const db = await freshStore();
  const record = pinnedRecord({ vk: 2 });
  await savePinned(db.store, SERVER, ACCOUNT, EMAIL, record);
  assert.deepEqual(await pinnedForSignIn(db.store, SERVER, EMAIL, ACCOUNT), record);
});

test("pinned_for_sign_in_refuses_a_server_that_names_another_account", async () => {
  const db = await freshStore();
  await savePinned(db.store, SERVER, ACCOUNT, EMAIL, pinnedRecord());
  // The other account is pinned too, but the e-mail maps to the first one.
  await savePinned(db.store, SERVER, OTHER, "bob@example.org", pinnedRecord({ accountId: OTHER }));
  await refusedWith("pinned_account_mismatch", pinnedForSignIn(db.store, SERVER, EMAIL, OTHER));
  await refusedWith("pinned_account_mismatch", pinnedForSignIn(db.store, SERVER, EMAIL, "99998888777766665555444433332222"));
});

test("pinned_for_sign_in_falls_back_to_the_account_when_the_email_changed_elsewhere", async () => {
  const db = await freshStore();
  const record = pinnedRecord({ vk: 4 });
  await savePinned(db.store, SERVER, ACCOUNT, EMAIL, record);
  // The e-mail was changed on another device: nothing maps from the new one.
  assert.equal(await loadPinned(db.store, SERVER, "ada@new.example"), null);
  assert.deepEqual(await pinnedForSignIn(db.store, SERVER, "ada@new.example", ACCOUNT), record);
});

test("pinned_for_sign_in_is_null_only_for_a_first_use", async () => {
  const db = await freshStore();
  assert.equal(await pinnedForSignIn(db.store, SERVER, EMAIL, ACCOUNT), null);
  await savePinned(db.store, SERVER, OTHER, "bob@example.org", pinnedRecord({ accountId: OTHER }));
  assert.equal(await pinnedForSignIn(db.store, SERVER, EMAIL, ACCOUNT), null);
  assert.equal(await pinnedForSignIn(db.store, "https://other.example", "bob@example.org", OTHER), null);
  await assert.rejects(pinnedForSignIn(db.store, SERVER, EMAIL, "nope"), TypeError);
});

test("pinned_accepts_only_the_form_of_the_core_record", async () => {
  const db = await freshStore();
  const base = pinnedRecord();
  const floor = { type: "password", credential_id: null, generation: 1 };
  const bad = {
    "an extra field": { ...base, extra: 1 },
    "a missing field": (({ pk_a, ...rest }) => rest)(base),
    "a duplicate floor": { ...base, kek_generation_max: [floor, floor] },
    "a duplicate passkey": {
      ...base,
      kek_generation_max: [
        { type: "prf", credential_id: new Uint8Array([1]), generation: 1 },
        { type: "prf", credential_id: new Uint8Array([1]), generation: 2 },
      ],
    },
    "an unknown floor type": { ...base, kek_generation_max: [{ ...floor, type: "pin" }] },
    "a passkey without a credential": { ...base, kek_generation_max: [{ type: "prf", credential_id: null, generation: 1 }] },
    "a passkey with an empty credential": { ...base, kek_generation_max: [{ type: "prf", credential_id: new Uint8Array(0), generation: 1 }] },
    "a credential as text": { ...base, kek_generation_max: [{ type: "prf", credential_id: "abcd", generation: 1 }] },
    "a credential on a password floor": { ...base, kek_generation_max: [{ ...floor, credential_id: new Uint8Array([1]) }] },
    "a floor with an extra field": { ...base, kek_generation_max: [{ ...floor, note: "x" }] },
    "a negative bigint generation": { ...base, kek_generation_max: [{ ...floor, generation: -1n }] },
    "a negative bigint epoch": { ...base, vk_epoch_max: -1n },
    "a profile above a byte": { ...base, ksf_profile: 256 },
    "a fractional generation": { ...base, kek_generation_max: [{ ...floor, generation: 1.5 }] },
  };
  for (const [why, record] of Object.entries(bad)) {
    await refusedWith("pinned_malformed", savePinned(db.store, SERVER, ACCOUNT, EMAIL, record), why);
  }
  assert.equal(await loadPinnedByAccount(db.store, SERVER, ACCOUNT), null, "nothing was stored");
  // Bigints from the core are fine, as are passkey floors with byte credentials.
  await savePinned(
    db.store,
    SERVER,
    ACCOUNT,
    EMAIL,
    pinnedRecord({ vk: 2, floors: [["password", 1], ["recovery", 1], ["prf", 3, [1, 2]]] }),
  );
  await savePinned(
    db.store,
    SERVER,
    ACCOUNT,
    EMAIL,
    { ...pinnedRecord({ vk: 2, floors: [["password", 1], ["recovery", 1], ["prf", 3, [1, 2]]] }), vk_epoch_max: 2n },
  );
});
