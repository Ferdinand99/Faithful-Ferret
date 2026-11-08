// The pieces of checkpoint.mjs that need no engine: the entries of a checkpoint, the table of warnings, the checks
// of a page of the listing.
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { test } from "node:test";
import { b64u, hex16 } from "../../src/b64.mjs";
import { HALT_CODES, SyncError } from "../../src/sync/engine.mjs";
import {
  escalate, warningRank, MAX_PAGE,
  checkListingPage, checkpointBody, entriesOf, failingIds, hardWarningOf, STOP_CODES, suspendsUpload, UPLOAD_EVERY_MS, VERIFY_AFTER_MS,
  WARNING_TABLE,
} from "../../src/sync/checkpoint.mjs";

const id = (n) => n.toString(16).padStart(2, "0").repeat(16);
const sha = (bytes) => new Uint8Array(createHash("sha256").update(bytes).digest());
const live = (n, rev, envelope = new Uint8Array([n, rev, 9])) => ({
  itemId: id(n), rev, seq: rev, deleted: false, envelope, tag: new Uint8Array(32), tomb: null,
});
const gone = (n, rev) => ({ itemId: id(n), rev, seq: rev, deleted: true, envelope: null, tag: null, tomb: new Uint8Array(40) });

test("entries_are_sorted_by_item_id_bytes_and_use_null_for_tombstones", async () => {
  // Handed over out of order, in a Map's iteration order too.
  const rows = new Map([[id(0xf0), live(0xf0, 2)], [id(0x01), gone(0x01, 5)], [id(0x80), live(0x80, 1)], [id(0x0a), live(0x0a, 3)]]);
  const entries = await entriesOf(rows.values());
  assert.deepEqual(entries.map((e) => hex16.encode(e.item_id)), [id(0x01), id(0x0a), id(0x80), id(0xf0)], "the order of the id bytes");
  assert.deepEqual(entries.map((e) => e.rev), [5, 3, 1, 2]);
  assert.equal(entries[0].hash, null, "a tombstone has no hash");
  assert.deepEqual(entries[1].hash, sha(live(0x0a, 3).envelope), "a live row has the SHA-256 of its envelope");
  for (const e of entries) assert.ok(e.item_id instanceof Uint8Array && e.item_id.length === 16);
  assert.deepEqual(await entriesOf([]), []);
});

test("a_list_that_cannot_be_right_is_not_signed", async () => {
  await assert.rejects(entriesOf([live(1, 1), live(1, 2)]), TypeError, "one item twice");
  await assert.rejects(entriesOf([live(1, 0)]), TypeError, "a revision starts at 1");
  await assert.rejects(entriesOf([{ ...live(1, 1), envelope: null }]), TypeError, "a live row without its envelope");
  await assert.rejects(entriesOf([{ ...gone(1, 1), envelope: new Uint8Array(1) }]), TypeError, "a tombstone with an envelope");
});

test("the_constants_are_a_day_and_ten_minutes", () => {
  assert.equal(VERIFY_AFTER_MS, 86_400_000);
  assert.equal(UPLOAD_EVERY_MS, 600_000);
});

test("the_upload_body_is_the_wire_shape_with_base64url_bytes", () => {
  const body = JSON.parse(checkpointBody({ seq: 4, digest: new Uint8Array(32).fill(1), mac: new Uint8Array(32).fill(2), entries: new Uint8Array(56) }));
  assert.deepEqual(Object.keys(body), ["seq", "digest", "mac", "entries"]);
  assert.equal(body.seq, 4);
  assert.deepEqual(b64u.decode(body.digest), new Uint8Array(32).fill(1));
  assert.equal(b64u.decode(body.entries).length, 56);
});

// ------------------------------------------------------------------ the table of warnings

test("the_table_names_every_core_code_and_closes_on_the_unknown", () => {
  const older = ["checkpoint_hidden_or_rolled_back", "checkpoint_lower_rev", "checkpoint_same_rev_different_hash", "checkpoint_live_behind_tombstone", "checkpoint_top_digest_mismatch"];
  for (const code of older) assert.equal(hardWarningOf(code), "server_shows_older_state", code);
  for (const code of ["checkpoint_seq_below_remembered", "checkpoint_rev_below_remembered"]) assert.equal(hardWarningOf(code), "checkpoint_rolled_back", code);
  for (const code of ["checkpoint_bad_mac", "checkpoint_bad_digest", "malformed_entries"]) assert.equal(hardWarningOf(code), "checkpoint_forged", code);
  assert.equal(hardWarningOf("checkpoint_seq_above_top"), "bad_feed");
  assert.equal(hardWarningOf("checkpoint_top_seq_below_remembered"), "rollback_suspected");
  assert.equal(hardWarningOf("too_large"), "sync_memory_full");
  // Closed: a code nobody named, or something that is no code at all, is the worst reading.
  for (const code of ["something_new", "", "__proto__", "constructor", "toString", "hasOwnProperty"]) {
    assert.equal(hardWarningOf(code), "server_shows_older_state", `[${code}]`);
  }
});

test("only_marked_failures_are_deferred", () => {
  for (const code of ["checkpoint_lower_rev", "checkpoint_hidden_or_rolled_back", "checkpoint_top_digest_mismatch", "checkpoint_rev_below_remembered", "checkpoint_same_rev_different_hash"]) {
    assert.equal(hardWarningOf(code, { deferred: true }), "verify_deferred", code);
    assert.notEqual(hardWarningOf(code, { deferred: false }), "verify_deferred", code);
  }
  // A forged checkpoint, a bad feed and a rollback of the top are never explained by a mark.
  for (const code of ["checkpoint_bad_mac", "checkpoint_bad_digest", "malformed_entries", "checkpoint_seq_above_top", "checkpoint_top_seq_below_remembered", "checkpoint_live_behind_tombstone", "unknown"]) {
    assert.notEqual(hardWarningOf(code, { deferred: true }), "verify_deferred", code);
  }
});

test("the_table_says_what_stops_and_what_suspends_uploads", () => {
  assert.deepEqual(
    Object.entries(WARNING_TABLE).filter(([, row]) => !row.suspendsUpload).map(([code]) => code).sort(),
    ["bad_feed", "checkpoint_forged", "server_hid_item"],
    "only these three leave uploads alone",
  );
  assert.deepEqual([...STOP_CODES], ["rollback_suspected", "server_restored", "restore_epoch_lowered", "sync_memory_full", "unsupported"]);
  assert.deepEqual([...HALT_CODES], [...STOP_CODES], "the engine halts for exactly the stops of the table");
  assert.equal(suspendsUpload("verify_deferred"), true);
  assert.equal(suspendsUpload("server_shows_older_state"), true);
  assert.equal(suspendsUpload("checkpoint_forged"), false);
  assert.equal(suspendsUpload("nothing_known"), false);
  assert.equal(WARNING_TABLE.verify_deferred.kind, "warning");
  assert.equal(WARNING_TABLE.server_shows_older_state.kind, "state");
});

// ------------------------------------------------------------------ the ids a checkpoint disagrees with

/** The bytes of a checkpoint's entries. */
async function entryBytes(rows) {
  const entries = await entriesOf(rows);
  const out = new Uint8Array(entries.length * 56);
  entries.forEach((e, i) => {
    out.set(e.item_id, i * 56);
    new DataView(out.buffer).setBigUint64(i * 56 + 16, BigInt(e.rev));
    out.set(e.hash ?? new Uint8Array(32), i * 56 + 24);
  });
  return out;
}

test("failing_ids_are_the_entries_the_rows_do_not_agree_with", async () => {
  const held = [live(1, 3), live(2, 1), gone(3, 4), live(4, 2)];
  const rows = new Map(held.map((r) => [r.itemId, r]));
  assert.deepEqual([...(await failingIds(await entryBytes(held), rows, true))], [], "the same rows agree");
  // Entry of 1 at revision 5 (the rows are behind), of 2 with another hash at the same revision, of 3 live (the row is deleted),
  // of 5 live with no row, of 6 a tombstone with no row (fine), and 4 is above its entry (fine).
  const entries = await entryBytes([live(1, 5), live(2, 1, new Uint8Array([7])), live(3, 4), live(4, 1), live(5, 1), gone(6, 2)]);
  assert.deepEqual([...(await failingIds(entries, rows, false))].sort(), [id(1), id(2), id(3), id(5)]);
  // At the top every row must be an entry too: 4 is listed (at a lower revision) and passes only when it is not at the top.
  assert.deepEqual([...(await failingIds(entries, rows, true))].sort(), [id(1), id(2), id(3), id(4), id(5)]);
  assert.equal(await failingIds(new Uint8Array(55), rows, false), null, "entries that cannot be read name nothing");
});

// ------------------------------------------------------------------ pages of the listing

const item = (n, seq = 1) => ({ id: id(n), seq });
const page = (items, extra = {}) => {
  const more = extra.has_more ?? false;
  return {
    items, as_of_seq: Math.max(0, ...items.map((i) => i.seq)), vk_epoch: 1, restore_epoch: 0, has_more: more,
    ...(more ? { next_after: items.at(-1)?.id } : {}), ...extra,
  };
};
const bad = (fn) => assert.throws(fn, (e) => e instanceof SyncError && e.code === "bad_feed");

test("a_listing_that_follows_the_rules_is_accepted", () => {
  const first = page([item(1), item(2)], { has_more: true, as_of_seq: 5 });
  checkListingPage(first, null);
  const second = page([item(3, 7), item(4)], { has_more: true, as_of_seq: 7 });
  checkListingPage(second, first);
  const third = page([item(5)], { has_more: false, as_of_seq: 9 });
  checkListingPage(third, second);
  // An empty vault, and an empty last page.
  checkListingPage(page([], { as_of_seq: 3 }), null);
});

test("ids_that_do_not_rise_are_a_bad_feed_inside_a_page_and_across_pages", () => {
  bad(() => checkListingPage(page([item(2), item(1)]), null));
  bad(() => checkListingPage(page([item(2), item(2)]), null));
  const first = page([item(1), item(5)], { has_more: true });
  bad(() => checkListingPage(page([item(5)]), first)); // the last id again
  bad(() => checkListingPage(page([item(3)]), first)); // an id below the last one
  checkListingPage(page([item(6)]), first);
});

test("a_next_after_that_does_not_move_forward_or_does_not_match_is_a_bad_feed", () => {
  const first = page([item(1), item(2)], { has_more: true });
  bad(() => checkListingPage({ ...first, next_after: id(1) }, null)); // not the last row of the page
  bad(() => checkListingPage({ ...first, next_after: id(9) }, null)); // skips ahead
  bad(() => checkListingPage({ ...first, items: [] }, null)); // more rows, and none shown
  bad(() => checkListingPage(page([item(3)], { has_more: true, next_after: id(2) }), first)); // stuck: the position of the page before
  bad(() => checkListingPage({ ...page([item(3)]), next_after: id(3) }, first)); // a position on the last page
  bad(() => checkListingPage(page([item(3)]), page([item(1)]))); // a page after the last one
});

test("the_epochs_must_not_change_between_pages", () => {
  const first = page([item(1)], { has_more: true });
  bad(() => checkListingPage({ ...page([item(2)]), vk_epoch: 2 }, first));
  bad(() => checkListingPage({ ...page([item(2)]), restore_epoch: 1 }, first));
  checkListingPage(page([item(2)]), first);
});

test("as_of_seq_holds_per_page_and_never_falls_from_one_page_to_the_next", () => {
  bad(() => checkListingPage(page([item(1, 9)], { as_of_seq: 8 }), null)); // below a seq on its own page
  const first = page([item(1, 4)], { has_more: true, as_of_seq: 6 });
  bad(() => checkListingPage(page([item(2, 3)], { as_of_seq: 5 }), first)); // fell
  checkListingPage(page([item(2, 3)], { as_of_seq: 6 }), first);
  // An honest server takes writes while it lists: a later page may hold a row above the first page's as_of_seq.
  checkListingPage(page([item(2, 12)], { as_of_seq: 12 }), first);
});

test("a_page_may_hold_no_more_rows_than_were_asked_for", () => {
  const rows = (n) => Array.from({ length: n }, (_, i) => ({ id: (i + 1).toString(16).padStart(32, "0"), seq: 1 }));
  checkListingPage(page(rows(MAX_PAGE)), null, MAX_PAGE);
  bad(() => checkListingPage(page(rows(MAX_PAGE + 1)), null, MAX_PAGE));
  bad(() => checkListingPage(page(rows(3)), null, 2));
});

test("a_failure_can_raise_a_warning_but_never_lower_it", () => {
  assert.equal(escalate(null, "checkpoint_forged"), "checkpoint_forged");
  assert.equal(escalate(null, "verify_deferred"), "verify_deferred");
  assert.equal(escalate("checkpoint_forged", "bad_feed"), "bad_feed", "information is replaced by information");
  assert.equal(escalate("checkpoint_forged", "verify_deferred"), "verify_deferred");
  assert.equal(escalate("verify_deferred", "checkpoint_forged"), "verify_deferred");
  assert.equal(escalate("verify_deferred", "server_shows_older_state"), "server_shows_older_state");
  assert.equal(escalate("server_shows_older_state", "checkpoint_forged"), "server_shows_older_state");
  assert.equal(escalate("server_shows_older_state", "bad_feed"), "server_shows_older_state");
  assert.equal(escalate("server_shows_older_state", "verify_deferred"), "server_shows_older_state");
  assert.equal(escalate("checkpoint_rolled_back", "verify_deferred"), "checkpoint_rolled_back");
  assert.equal(escalate("verify_deferred", "a_code_nobody_named"), "a_code_nobody_named", "an unknown code ranks as a state warning");
  assert.equal(escalate("a_code_nobody_named", "checkpoint_forged"), "a_code_nobody_named");
  assert.deepEqual(["checkpoint_forged", "verify_deferred", "server_shows_older_state", null].map(warningRank), [1, 2, 3, 0]);
});
