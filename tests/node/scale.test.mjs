// The rollback memory and the checkpoints at the size of a large vault, through
// the real WASM build: how long they take and how big the memory gets. The
// budgets are for a CI runner or the LANBox, not for a phone; the browser has
// its own gate.
// Run: node --test tests/node/scale.test.mjs
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { test } from "node:test";
import { LOGIN_DRAFT, NOW, newAccount, wasm } from "./helpers.mjs";

const sha256 = (b) => new Uint8Array(createHash("sha256").update(Buffer.from(b)).digest());

/** The id of item `n` (from 1; 0 is the manifest): big endian in the last four bytes, so ids ascend. */
function idOf(n) {
  const id = new Uint8Array(16);
  new DataView(id.buffer).setUint32(12, n);
  return id;
}

const { vault, created } = newAccount("scale");

/** `count` live items as the rows of the server: `{ item_id, rev, state, envelope, tag }`. */
function items(count) {
  const rows = [];
  for (let n = 1; n <= count; n++) {
    const sealed = vault.encrypt_item(idOf(n), 1, { ...LOGIN_DRAFT, name: `Item ${n}` }, undefined, NOW);
    rows.push({ item_id: idOf(n), rev: sealed.rev, state: "live", envelope: sealed.envelope, tag: sealed.tag });
  }
  return rows;
}

const manifestRow = {
  item_id: new Uint8Array(16),
  rev: created.manifest.rev,
  state: "live",
  envelope: created.manifest.envelope,
  tag: created.manifest.tag,
};

/** The entries of a checkpoint for rows that are all live. */
const entriesOf = (rows) => rows.map((r) => ({ item_id: r.item_id, rev: r.rev, hash: sha256(r.envelope) }));

let ten;
const tenThousand = () => (ten ??= items(10_000));

function timed(label, fn) {
  const start = process.hrtime.bigint();
  const value = fn();
  const ms = Number(process.hrtime.bigint() - start) / 1e6;
  console.log(`# ${label}: ${ms.toFixed(1)} ms`);
  return { value, ms };
}

test("accept_rows_of_500_rows_within_200_ms", () => {
  const rows = items(500);
  const { value: memory, ms } = timed("accept_rows, 500 rows", () => vault.accept_rows(rows, 500, wasm.sync_memory_new()));
  assert.ok(ms < 200, `${ms.toFixed(1)} ms is over 200 ms`);
  assert.equal(memory.length, 21 + 24 * 500);
});

test("verify_checkpoint_of_10000_rows_within_3_s", () => {
  const rows = [manifestRow, ...tenThousand()];
  const checkpoint = vault.make_checkpoint(10_001, entriesOf(rows));
  const { value: memory, ms } = timed("verify_checkpoint, 10 001 rows", () =>
    vault.verify_checkpoint(checkpoint, rows, 10_001, wasm.sync_memory_new()),
  );
  assert.ok(ms < 3000, `${ms.toFixed(1)} ms is over 3 s`);
  assert.equal(memory.length, 21 + 24 * rows.length);
  // A row that is not what the checkpoint says is still found among that many:
  // the row at 5 000 carries the envelope and tag of its neighbour, and the tag
  // does not fit the id, which is the one code `decrypt`.
  const swapped = rows.slice();
  swapped[5_000] = { ...swapped[5_000], envelope: swapped[5_001].envelope, tag: swapped[5_001].tag };
  assert.throws(() => vault.verify_checkpoint(checkpoint, swapped, 10_001, wasm.sync_memory_new()), { code: "decrypt" });
});

test("make_checkpoint_of_10000_entries", () => {
  const entries = entriesOf(tenThousand());
  const { value: checkpoint, ms } = timed("make_checkpoint, 10 000 entries", () => vault.make_checkpoint(10_000, entries));
  assert.ok(ms < 3000, `${ms.toFixed(1)} ms is over 3 s`);
  assert.equal(checkpoint.seq, 10_000);
  assert.equal(checkpoint.entries.length, 56 * 10_000, "one 56-byte entry per item");
  assert.equal(checkpoint.digest.length, 32);
  assert.equal(checkpoint.mac.length, 32);
  assert.deepEqual(checkpoint.digest, sha256(checkpoint.entries), "the digest is the SHA-256 of the entries");
  // Two entries for the same id are not a checkpoint.
  assert.throws(() => vault.make_checkpoint(1, [entries[0], entries[0]]), { code: "malformed_entries" });
});

test("sync_memory_with_10000_items_is_21_plus_24_bytes_per_item", () => {
  const rows = tenThousand();
  let memory = wasm.sync_memory_new();
  assert.equal(memory.length, 21, "an empty memory is the 21-byte header");
  for (let from = 0; from < rows.length; from += 500) {
    memory = vault.accept_rows(rows.slice(from, from + 500), from + 500, memory);
  }
  assert.equal(memory.length, 21 + 24 * 10_000);
  assert.equal(memory.length, 240_021);
});
