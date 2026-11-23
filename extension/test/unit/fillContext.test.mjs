// What Ferret filled where (fillContext.mjs): the fill flow notes each value it
// put into a document, the write path reads it for a change form there, and it
// lasts five minutes of wall clock and no lock.
import assert from "node:assert/strict";
import { test } from "node:test";
import { createFillContext, FILL_CONTEXT_TTL_MS, MAX_FILL_CONTEXT } from "../../src/background/fillContext.mjs";
import { LOGIN_URL, PASSWORD, TAB, idOf, itemWorld } from "./itemHelpers.mjs";
import { pkg } from "./sessionHelpers.mjs";

const ITEM = idOf(1);
const OTHER = idOf(2);
const PLACE = { tabId: 7, frameId: 0, documentId: "doc-1", url: "https://login.example.net/change", fieldKind: "password" };

/** A clock the test moves. */
function clock(start = 1_763_800_000_000) {
  let t = start;
  return { now: () => t, move: (/** @type {number} */ ms) => { t += ms; } };
}

test("the_fill_context_is_cleared_on_lock_and_after_five_minutes", async () => {
  // Five minutes of wall clock, checked on every access (no timer).
  const c = clock();
  const context = createFillContext({ now: c.now });
  context.record({ ...PLACE, itemId: ITEM });
  assert.equal(context.lookup(PLACE), ITEM);
  c.move(FILL_CONTEXT_TTL_MS - 1);
  assert.equal(context.lookup(PLACE), ITEM, "just under five minutes");
  c.move(1);
  assert.equal(context.lookup(PLACE), null, "five minutes later it is gone");
  assert.equal(context.size(), 0);
  // A clock that went back drops it too (it cannot be trusted to be young).
  context.record({ ...PLACE, itemId: ITEM });
  c.move(-1000);
  assert.equal(context.lookup(PLACE), null);

  // Every lock: the fill flow clears it when the core host locks, whatever the reason.
  const { load } = await pkg();
  const [{ createFillHost }, { createFillContext: packaged }] = await Promise.all([load("background/fillFlow.mjs"), load("background/fillContext.mjs")]);
  for (const reason of ["manual", "timeout", "idle", "sign_out", "restart", "worker_failed"]) {
    const fill = packaged({ now: c.now });
    /** @type {Array<(reason: string) => void>} */
    const listeners = [];
    const host = createFillHost({ syncHost: { engine: () => null }, clipboard: { copy: async () => {} }, scripting: /** @type {any} */ ({}), tabs: /** @type {any} */ ({}), fillContext: fill });
    host.attach({ state: () => "unlocked", liveClient: () => ({}), onLocked: (/** @type {any} */ fn) => listeners.push(fn) });
    fill.record({ ...PLACE, itemId: ITEM });
    assert.equal(fill.size(), 1);
    for (const listener of listeners) listener(reason);
    assert.equal(fill.size(), 0, `a ${reason} lock clears it`);
    assert.equal(fill.lookup(PLACE), null);
  }
});

test("the_fill_context_matches_the_document_then_the_address_and_keeps_only_ids", () => {
  const c = clock();
  const context = createFillContext({ now: c.now });
  context.record({ ...PLACE, itemId: ITEM });
  // Another document, frame, tab or kind of field is another place.
  assert.equal(context.lookup({ ...PLACE, documentId: "doc-2" }), null);
  assert.equal(context.lookup({ ...PLACE, frameId: 1 }), null);
  assert.equal(context.lookup({ ...PLACE, tabId: 8 }), null);
  assert.equal(context.lookup({ ...PLACE, fieldKind: "username" }), null);
  // Without a document id the address counts, without its fragment.
  const { documentId: _drop, ...noDocument } = PLACE;
  context.record({ ...noDocument, url: "https://login.example.net/change#step-1", itemId: OTHER });
  assert.equal(context.lookup({ ...noDocument, url: "https://login.example.net/change#step-2" }), OTHER);
  assert.equal(context.lookup({ ...noDocument, url: "https://login.example.net/other" }), null);
  // The newest fill of a place counts.
  context.record({ ...PLACE, itemId: OTHER });
  assert.equal(context.lookup(PLACE), OTHER);
  // A malformed record is ignored; a value can never be stored as an id.
  context.record(/** @type {any} */ ({ ...PLACE, itemId: PASSWORD }));
  context.record(/** @type {any} */ ({ ...PLACE, fieldKind: "card_number", itemId: ITEM }));
  assert.equal(context.lookup(PLACE), OTHER);
  // A bounded memory: the oldest goes first.
  context.clear();
  for (let i = 0; i < MAX_FILL_CONTEXT + 5; i += 1) context.record({ ...PLACE, documentId: `doc-${i}`, itemId: ITEM });
  assert.equal(context.size(), MAX_FILL_CONTEXT);
  assert.equal(context.lookup({ ...PLACE, documentId: "doc-0" }), null);
  assert.equal(context.lookup({ ...PLACE, documentId: `doc-${MAX_FILL_CONTEXT + 4}` }), ITEM);
});

test("a_fill_notes_each_value_it_put_into_the_document", async () => {
  const { load } = await pkg();
  const { createFillContext: packaged } = await load("background/fillContext.mjs");
  const context = packaged();
  const world = await itemWorld({ fillContext: context });
  await world.open();
  const popup = world.popup();
  const page = await popup.list.page(TAB);
  assert.ok(page);
  const [row] = page.rows;
  assert.deepEqual(await popup.list.fill(row, TAB), { ok: true });
  const where = { tabId: TAB, frameId: 0, documentId: "doc-1", url: LOGIN_URL };
  assert.equal(context.lookup({ ...where, fieldKind: "password" }), ITEM);
  assert.equal(context.lookup({ ...where, fieldKind: "username" }), ITEM);
  // A lock clears it.
  await world.coreHost.lock("manual");
  assert.equal(context.lookup({ ...where, fieldKind: "password" }), null);
});
