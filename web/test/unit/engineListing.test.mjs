// The full listing after a 410: it goes through GET /api/sync/items, every page is checked, the feed goes on from the
// as_of_seq of the first page, and a verification follows.
import assert from "node:assert/strict";
import { test } from "node:test";
import { ApiError } from "../../src/api.mjs";
import { b64u } from "../../src/b64.mjs";
import { cache } from "../../src/store/cache.mjs";
import { scope } from "./idbHelpers.mjs";
import { createFakeClient, Model, settle, syncDevice, until } from "./syncHelpers.mjs";

const IDS = ["11", "22", "33", "44", "55"].map((n) => n.repeat(16));
const [ID_A, ID_B, ID_C, ID_D, ID_E] = IDS;
const ID_LATE = "ff".repeat(16);

const setRow = (model, client, id, rev, name, extra = {}) => model.set(id, { rev, ...client.wireRow(id, rev, { item_type: "login", name }), ...extra });
const names = (d) => Object.fromEntries(d.engine.list().map((i) => [i.id, i.name]));
const feedPaths = (d) => d.api.gets.map((p) => p.replace("/api/sync/", ""));

/**
 * Five items on the server and a started device. Then the floor of the feed moves above the cursor of the device, and another
 * device changes A: the next pass is a 410 and a listing of three pages of two rows.
 */
async function aMovedFloor() {
  const model = new Model();
  const client = createFakeClient();
  IDS.forEach((id, i) => setRow(model, client, id, 1, `Item ${i + 1}`));
  const d = await syncDevice({ model, client });
  await d.engine.start();
  model.seq += 3;
  model.minValidSince = model.seq;
  setRow(model, client, ID_A, 2, "Item 1 changed");
  model.pageSize = 2;
  d.api.gets.length = 0;
  return { d, model, client };
}

test("410_lists_through_the_items_endpoint_and_continues_from_the_first_as_of_seq", async () => {
  const { d, model } = await aMovedFloor();
  await d.engine.syncNow();
  assert.deepEqual(feedPaths(d), [
    "changes?since=5&limit=500",
    "items?limit=500",
    `items?limit=500&after=${ID_B}`,
    `items?limit=500&after=${ID_D}`,
    `changes?since=${model.seq}&limit=500`,
  ], "the 410, three pages of the listing, then the feed from the as_of_seq of the first page");
  assert.equal(names(d)[ID_A], "Item 1 changed");
  assert.equal(d.engine.list().length, 5);
  assert.equal(d.events.error.length, 0);
  assert.ok(d.engine.list().every((item) => !item.missingOnServer), "everything was shown");
  d.engine.stop();
});

test("a_write_during_the_listing_is_not_lost", async () => {
  const { d, model, client } = await aMovedFloor();
  const real = d.api.get;
  let listed = 0;
  d.api.get = async (path) => {
    const answer = await real(path);
    if (path.startsWith("/api/sync/items") && (listed += 1) === 1) {
      // After the first page: A (already listed, at the revision before) is changed, and a new item is made with an id on a later page.
      setRow(model, client, ID_A, 3, "Item 1 changed again");
      setRow(model, client, ID_LATE, 1, "Made during the listing");
    }
    return answer;
  };
  await d.engine.syncNow();
  assert.equal(d.events.error.length, 0, "an honest server that takes writes while it lists is not a bad feed");
  assert.equal(names(d)[ID_A], "Item 1 changed again", "A is above the as_of_seq of the first page: the feed brings it");
  assert.equal(names(d)[ID_LATE], "Made during the listing", "an item on a later page, with a seq above the first page's as_of_seq");
  const paths = feedPaths(d);
  assert.match(paths.at(-1), /^changes\?since=9&/, "the feed starts at the as_of_seq of the first page, not at a later page's");
  assert.ok(d.engine.list().every((item) => !item.missingOnServer));
  d.engine.stop();
});

test("a_listing_is_followed_by_a_verify", async () => {
  const { d, model } = await aMovedFloor();
  assert.equal(d.api.checkpointGets.length, 1, "the first start verified");
  d.client.vault.calls.length = 0;
  await d.engine.syncNow();
  assert.equal(d.api.checkpointGets.length, 2, "the listing was followed by a verification, though the last one was minutes ago");
  const [verify] = d.client.vault.calls.filter((c) => c[0] === "verify_checkpoint");
  assert.equal(verify[2], model.seq, "at the top the pass read");
  assert.deepEqual(d.engine.health(), { halted: null, warnings: [] });
  d.engine.stop();
});

test("a_second_410_in_one_pass_ends_with_gone", async () => {
  const { d } = await aMovedFloor();
  const real = d.api.get;
  let gone = 0;
  d.api.get = async (path) => {
    if (path.includes("/changes")) {
      gone += 1;
      throw new ApiError(410, "gone", null, { error: "gone", min_valid_since: 99 });
    }
    return real(path);
  };
  await d.engine.syncNow();
  assert.equal(feedPaths(d).filter((p) => p.startsWith("items")).length, 3, "one listing and no more");
  assert.equal(gone, 2, "the 410, and the 410 after the listing");
  assert.deepEqual(d.events.error, [{ code: "gone" }]);
  assert.ok(d.events.state.some((s) => s.kind === "failed" && s.code === "gone"));
  // The listing was read and kept: the next pass goes on from where it began.
  d.api.get = real;
  d.events.error.length = 0;
  await d.engine.syncNow();
  assert.equal(d.events.error.length, 0);
  assert.equal(d.engine.list().length, 5);
  d.engine.stop();
});

// ------------------------------------------------------------------ a listing that cannot be right

/** Runs the listing with `mutate(page, number of the page)` applied to what the server answers, and returns the device. */
async function listingWith(mutate) {
  const { d } = await aMovedFloor();
  const real = d.api.get;
  let pages = 0;
  d.api.get = async (path) => {
    const answer = await real(path);
    if (!path.startsWith("/api/sync/items")) return answer;
    pages += 1;
    return mutate(structuredClone(answer), pages) ?? answer;
  };
  await d.engine.syncNow();
  return { d, real };
}

const isBadFeed = (d) => d.events.error.length === 1 && d.events.error[0].code === "bad_feed";

test("a_listing_with_descending_ids_a_stuck_next_after_or_a_changed_epoch_is_bad_feed", async () => {
  const cases = {
    "descending ids in a page": (page, n) => (n === 1 ? { ...page, items: [...page.items].reverse() } : null),
    "the same id on two pages": (page, n) => (n === 2 ? { ...page, items: page.items.slice(0, 1).map((i) => ({ ...i, id: ID_B })) } : null),
    "ids that went back": (page, n) => (n === 2 ? { ...page, items: page.items.map((i) => ({ ...i, id: ID_A })) } : null),
    "a next_after that does not move": (page, n) => (n === 2 ? { ...page, next_after: ID_B } : null),
    "more rows and none shown": (page, n) => (n === 2 ? { ...page, items: [] } : null),
    "a next_after that skips rows": (page, n) => (n === 1 ? { ...page, next_after: ID_C } : null),
    "a restore epoch that changes": (page, n) => (n === 2 ? { ...page, restore_epoch: page.restore_epoch + 1 } : null),
    "a key epoch that changes": (page, n) => (n === 3 ? { ...page, vk_epoch: page.vk_epoch + 1 } : null),
  };
  for (const [what, mutate] of Object.entries(cases)) {
    const { d, real } = await listingWith(mutate);
    assert.ok(isBadFeed(d), `${what}: ${JSON.stringify(d.events.error)}`);
    assert.ok(d.engine.list().every((item) => !item.missingOnServer), `${what}: nothing is marked missing from half a listing`);
    assert.equal(d.engine.health().halted, null, what);
    // Nothing was deleted, and an honest answer next time lists again and recovers.
    d.api.get = real;
    d.events.error.length = 0;
    await d.engine.syncNow();
    assert.equal(d.events.error.length, 0, `${what}: the next pass`);
    assert.equal(names(d)[ID_A], "Item 1 changed", what);
    d.engine.stop();
  }
});

test("as_of_seq_below_a_listed_seq_is_bad_feed", async () => {
  const { d } = await listingWith((page, n) => (n === 1 ? { ...page, as_of_seq: Math.max(...page.items.map((i) => i.seq)) - 1 } : null));
  assert.ok(isBadFeed(d), JSON.stringify(d.events.error));
  d.engine.stop();
  // A later page whose as_of_seq falls below the first page's.
  const second = await listingWith((page, n) => (n === 2 ? { ...page, as_of_seq: 1 } : null));
  assert.ok(isBadFeed(second.d), JSON.stringify(second.d.events.error));
  second.d.engine.stop();
});

test("as_of_seq_is_checked_per_page_and_not_against_rows_on_other_pages", async () => {
  // The first page says 9; a later page has a row at seq 12 and says 12 (a write during the listing). Honest.
  const { d, model, client } = await aMovedFloor();
  const real = d.api.get;
  let listed = 0;
  d.api.get = async (path) => {
    if (path.startsWith("/api/sync/items") && (listed += 1) === 2) setRow(model, client, ID_C, 2, "Item 3 changed", { seq: model.seq + 3 });
    return real(path);
  };
  await d.engine.syncNow();
  await settle();
  assert.equal(d.events.error.length, 0);
  assert.equal(names(d)[ID_C], "Item 3 changed");
  d.engine.stop();
});

test("a_listing_that_lowers_the_top_below_what_the_device_has_seen_halts_it", async () => {
  // The memory is checked for every page of the listing as it is for the feed: a top below the remembered one is a rollback.
  const { d } = await listingWith((page) => ({ ...page, as_of_seq: 2, items: page.items.map((i) => ({ ...i, seq: 1 })) }));
  assert.equal(d.engine.health().halted, "rollback_suspected");
  d.engine.stop();
});

test("a_listing_never_deletes_what_it_does_not_show", async () => {
  const { d, model } = await aMovedFloor();
  model.hidden.add(ID_C); // the listing leaves C out; the server still has it
  await d.engine.syncNow();
  const c = d.engine.list().find((i) => i.id === ID_C);
  assert.ok(c, "still there, with its name");
  assert.equal(c.name, "Item 3");
  d.engine.stop();
});

test("a_tombstone_in_the_listing_is_verified_and_the_item_leaves_the_list", async () => {
  const { d, model, client } = await aMovedFloor();
  model.set(ID_C, { rev: 2, deleted: true, tomb: client.wireTomb(ID_C, 2) }); // another device deleted C
  model.set(ID_LATE, { rev: 4, deleted: true, tomb: client.wireTomb(ID_LATE, 4) }); // and a deletion of an item this device never had
  await d.engine.syncNow();
  assert.ok(feedPaths(d).some((p) => p.startsWith("items")), "through the listing");
  assert.equal(d.events.error.length, 0);
  assert.deepEqual(d.engine.list().map((i) => i.id).sort(), [ID_A, ID_B, ID_D, ID_E]);
  const rows = await cache.getRows(d.store.database.store, scope());
  assert.deepEqual(rows.filter((r) => r.deleted).map((r) => [r.itemId, r.rev]).sort(), [[ID_C, 2], [ID_LATE, 4]], "kept as rows");
  assert.deepEqual(d.engine.health(), { halted: null, warnings: [] }, "the checkpoint lists them as tombstones and agrees");
  d.engine.stop();

  // A tombstone that does not verify: quarantine, and the local copy stays.
  const second = await aMovedFloor();
  second.model.set(ID_D, { rev: 2, deleted: true, tomb: b64u.encode(new Uint8Array(40)) });
  await second.d.engine.syncNow();
  const item = second.d.engine.list().find((i) => i.id === ID_D);
  assert.equal(item?.quarantined, true);
  assert.ok(second.d.events.state.some((s) => s.kind === "warning" && s.code === "tombstone_unverified"));
  second.d.engine.stop();
});

test("a_page_with_more_rows_than_were_asked_for_is_refused", async () => {
  // The listing: 501 rows on one page.
  const { d, real } = await listingWith((page, n) => {
    if (n !== 1) return null;
    const items = Array.from({ length: 501 }, (_, i) => ({ ...page.items[0], id: (i + 1).toString(16).padStart(32, "0") }));
    return { ...page, items, has_more: false, next_after: undefined, as_of_seq: 99 };
  });
  assert.ok(isBadFeed(d), JSON.stringify(d.events.error));
  assert.ok(d.engine.list().every((item) => !item.missingOnServer));
  d.api.get = real;
  d.events.error.length = 0;
  await d.engine.syncNow();
  assert.equal(d.events.error.length, 0, "an honest answer next time");
  d.engine.stop();

  // The feed: 501 changes on one page.
  const { d: e } = await aMovedFloor();
  const feed = e.api.get;
  e.api.get = async (path) => {
    const answer = await feed(path);
    if (!path.includes("/changes")) return answer;
    const change = answer.changes[0] ?? { id: ID_A, rev: 1, seq: 1, deleted: false };
    return { ...answer, changes: Array.from({ length: 501 }, (_, i) => ({ ...change, seq: i + 1 })) };
  };
  await e.engine.syncNow();
  assert.ok(isBadFeed(e), JSON.stringify(e.events.error));
  e.engine.stop();
});
