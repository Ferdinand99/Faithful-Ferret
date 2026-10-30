// The outbox: order and exact bytes.
import assert from "node:assert/strict";
import { test } from "node:test";
import { b64u } from "../../src/b64.mjs";
import { StoreError } from "../../src/store/idb.mjs";
import { outbox } from "../../src/store/outbox.mjs";
import { freshStore, scope } from "./idbHelpers.mjs";

const hex = (n) => n.toString(16).padStart(32, "0");
const bytes = (n, fill) => new Uint8Array(n).fill(fill);
const encode = (text) => new TextEncoder().encode(text);

/** A live write whose body is written the way `layout` says: that is what is kept. */
function liveEntry(n, { baseRev = 0, layout = "compact" } = {}) {
  const blob = bytes(48, n);
  const tag = bytes(32, n + 100);
  const fields = { base_rev: baseRev, blob: b64u.encode(blob), tag: b64u.encode(tag), idem: hex(n + 1000) };
  const text =
    layout === "compact"
      ? JSON.stringify(fields)
      : // another key order, spaces and a trailing newline: not what JSON.stringify makes
        `{ "idem" : "${fields.idem}",\n  "tag":"${fields.tag}", "blob": "${fields.blob}",\n  "base_rev":${baseRev} }\n`;
  return { idem: hex(n + 1000), itemId: hex(n), baseRev, body: { blob, tag }, bytes: encode(text) };
}

function tombEntry(n, baseRev = 3) {
  const tomb = bytes(40, n);
  const text = JSON.stringify({ base_rev: baseRev, deleted: true, tomb: b64u.encode(tomb), idem: hex(n + 1000) });
  return { idem: hex(n + 1000), itemId: hex(n), baseRev, body: { tomb }, bytes: encode(text) };
}

const refusedWith = (code, promise) =>
  assert.rejects(promise, (error) => error instanceof StoreError && error.code === code);

test("outbox_keeps_order_and_exact_bytes", async () => {
  const db = await freshStore();
  const entries = [liveEntry(5, { layout: "spaced" }), tombEntry(2), liveEntry(9), liveEntry(1, { baseRev: 4, layout: "spaced" })];
  for (const entry of entries) await outbox.enqueue(db.store, scope(), entry);

  for (const reopen of [false, true]) {
    const store = reopen ? await db.reopen() : db.store;
    const back = await outbox.all(store, scope());
    assert.deepEqual(back.map((e) => e.idem), entries.map((e) => e.idem), "enqueue order, not id order");
    back.forEach((entry, i) => {
      assert.ok(entry.bytes instanceof Uint8Array);
      assert.deepEqual(Array.from(entry.bytes), Array.from(entries[i].bytes), "the very same bytes");
      assert.deepEqual(entry, entries[i]);
    });
  }
  // The kept bytes are not a re-serialization: the first entry is still spaced.
  const [first] = await outbox.all(db.store, scope());
  assert.match(new TextDecoder().decode(first.bytes), /^\{ "idem" : /);
});

test("outbox_removes_one_entry_by_key_and_only_in_its_scope", async () => {
  const db = await freshStore();
  const a = liveEntry(1);
  const b = liveEntry(2);
  await outbox.enqueue(db.store, scope(1), a);
  await outbox.enqueue(db.store, scope(1), b);
  await outbox.enqueue(db.store, scope(2), liveEntry(3));

  await outbox.remove(db.store, scope(2), a.idem); // another scope: nothing happens
  assert.equal((await outbox.all(db.store, scope(1))).length, 2);
  await outbox.remove(db.store, scope(1), a.idem);
  assert.deepEqual((await outbox.all(db.store, scope(1))).map((e) => e.idem), [b.idem]);
  await outbox.remove(db.store, scope(1), a.idem); // already gone
  assert.equal((await outbox.all(db.store, scope(2))).length, 1);

  // A removed key may be queued again, and goes to the end.
  await outbox.enqueue(db.store, scope(1), a);
  assert.deepEqual((await outbox.all(db.store, scope(1))).map((e) => e.idem), [b.idem, a.idem]);
});

test("outbox_refuses_the_same_key_twice", async () => {
  const db = await freshStore();
  await outbox.enqueue(db.store, scope(), liveEntry(1));
  await refusedWith("outbox_duplicate", outbox.enqueue(db.store, scope(), liveEntry(1)));
  assert.equal((await outbox.all(db.store, scope())).length, 1);
  // The same key in another scope is another write.
  await outbox.enqueue(db.store, scope(2), liveEntry(1));
});

test("outbox_refuses_an_entry_whose_bytes_do_not_match_it", async () => {
  const db = await freshStore();
  const good = liveEntry(1);
  const other = liveEntry(2);
  const bad = [
    { ...good, idem: other.idem },
    { ...good, baseRev: 9 },
    { ...good, body: other.body },
    { ...good, body: { tomb: bytes(40, 1) } },
    { ...good, body: { ...good.body, extra: bytes(1, 1) } },
    { ...good, bytes: encode("not json") },
    { ...good, bytes: encode('{"base_rev":0,"idem":"' + good.idem + '"}') },
    { ...good, bytes: new TextDecoder().decode(good.bytes) },
    { ...good, itemId: "00000000000000000000000000000000" },
    { ...good, itemId: "XYZ" },
    { ...tombEntry(3), body: { blob: bytes(48, 3), tag: bytes(32, 3) } },
    { ...tombEntry(3), body: { tomb: bytes(40, 4) } },
  ];
  for (const entry of bad) await refusedWith("outbox_entry", outbox.enqueue(db.store, scope(), entry));
  assert.deepEqual(await outbox.all(db.store, scope()), []);
});
