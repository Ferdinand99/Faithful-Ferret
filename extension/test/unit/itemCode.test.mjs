// The one-time code in the popup: the live code of an item (`item_code`) made in the core from the device's clock, the
// copy that the clipboard clears after 30 seconds, "Fill the code" into a one-time code field of the same site only, and
// the offer of the code on the page that follows a sign-in. Through the real background (core host, lock, router and the
// handlers of the built package) with a fake core whose codes are the RFC 6238 ones.
import assert from "node:assert/strict";
import { test } from "node:test";
import { ALARM_PREFIX, CLEAR_AFTER_MS, MARK_KEY } from "../../src/background/clipboard.mjs";
import { FILL_CONTEXT_TTL_MS } from "../../src/background/fillContext.mjs";
import { actionErrorKey } from "../../src/pages/popupFlow.mjs";
import { PASSWORD, TAB, LOGIN_ORIGIN, LOGIN_URL, TOTP_CODE, idOf, itemWorld } from "./itemHelpers.mjs";
import { pkg } from "./sessionHelpers.mjs";

/** The secret of the RFC 6238 test vectors, in base32. */
const SECRET = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";
/** A second of the RFC's table (T = 1111111109): the SHA-1 code of the secret is 07081804 (8 digits), so 081804 with 6. */
const NOW_S = 1_111_111_109;
const REFERENCE = "081804";
const LEFT = 30 - (NOW_S % 30);

/** The page's frames: the top (a sign-in form) and one frame below it that is part of the same site. */
const SUB_URL = "https://login.example.net/code-frame";

/** @param {any} popup */
async function suggestion(popup) {
  const page = await popup.list.page(TAB);
  assert.ok(page, "the page has candidates");
  return page.rows[0];
}

/** A world whose clock stands at a second of the RFC's table and whose core makes the RFC's codes. @param {Parameters<typeof itemWorld>[0]} [options] */
async function codeWorld(options = {}) {
  const world = await itemWorld({ totpSecret: SECRET, ...options });
  world.clock.set(NOW_S * 1000);
  await world.open();
  return world;
}

test("the_popup_shows_a_code_that_matches_the_reference_at_a_fixed_clock", async () => {
  const world = await codeWorld();
  const popup = world.popup();
  const row = await suggestion(popup);
  const found = (await popup.list.search({ query: "example" })).rows[0];
  // A reference of the page's candidates and one of a search both show the code: the core's code for the device's second.
  for (const ref of [row.ref, found.ref]) {
    assert.deepEqual(await popup.list.itemCode(ref), { ok: true, code: REFERENCE, seconds_left: LEFT });
  }
  // The second of the next period gives the next code, and the seconds count down from the full period.
  world.clock.advance(LEFT * 1000);
  const next = await popup.list.itemCode(row.ref);
  assert.equal(next.ok, true);
  assert.notEqual(next.code, REFERENCE);
  assert.equal(next.seconds_left, 30);
  // The core was asked for the device's clock, in whole seconds, and the item was closed again.
  const asked = world.client.calls.filter((/** @type {any} */ c) => c.method === "totp_code").map((/** @type {any} */ c) => c.args[1]);
  assert.deepEqual(asked, [NOW_S, NOW_S, NOW_S + LEFT]);
  assert.equal(world.handles.size, 0);
});

test("the_code_is_in_no_message_but_the_reply_of_item_code_and_the_secret_is_in_none", async () => {
  const world = await codeWorld();
  const popup = world.popup();
  const row = await suggestion(popup);
  await popup.list.list({});
  await popup.list.item(row.ref);
  await popup.list.itemCode(row.ref);
  assert.deepEqual(await popup.list.copy(row.ref, "totp"), { ok: true });
  assert.deepEqual(world.written, [REFERENCE]);
  const received = popup.received();
  const withCode = received.filter((text) => text.includes(REFERENCE));
  assert.equal(withCode.length, 1, "one message holds the code");
  assert.equal(JSON.parse(withCode[0]).type, "item_code");
  for (const text of received) {
    assert.equal(text.includes(SECRET), false, "the secret never reaches the popup");
    assert.equal(text.includes(PASSWORD), false);
  }
  // The item view only says that a code can be copied.
  const view = await popup.list.item(row.ref);
  assert.deepEqual(view.copyable, ["username", "password", "totp"]);
});

test("a_locked_vault_gives_no_code_and_an_item_without_one_gives_none", async () => {
  const world = await codeWorld();
  const popup = world.popup();
  const row = await suggestion(popup);
  const bank = (await popup.list.search({ query: "bank" })).rows[0];
  assert.deepEqual(await popup.list.itemCode(bank.ref), { ok: false, reason: "no_value" });
  // A reference this session never got.
  assert.deepEqual(await popup.list.itemCode("f".repeat(32)), { ok: false, reason: "not_offered" });
  // A reference of another popup session.
  const other = world.popup();
  assert.deepEqual(await other.list.itemCode(row.ref), { ok: false, reason: "not_offered" });
  // After a lock the background refuses before it looks at anything: no code, no reason beyond "locked".
  await world.coreHost.lock("manual");
  await assert.rejects(popup.list.itemCode(row.ref), (/** @type {any} */ error) => error?.code === "vault_locked");
  const calls = world.client.calls.filter((/** @type {any} */ c) => c.method === "totp_code").length;
  await world.open();
  // The old reference is gone with the lock.
  assert.deepEqual(await popup.list.itemCode(row.ref), { ok: false, reason: "not_offered" });
  assert.equal(world.client.calls.filter((/** @type {any} */ c) => c.method === "totp_code").length, calls, "the core made no code for it");
});

test("copy_of_the_code_is_cleared_from_the_clipboard_after_30_seconds", async () => {
  const world = await codeWorld();
  const popup = world.popup();
  const row = await suggestion(popup);
  assert.deepEqual(await popup.list.copy(row.ref, "totp"), { ok: true });
  assert.deepEqual(world.written, [REFERENCE]);
  // The same helper as for a password: an alarm is armed for 30 seconds after the copy, and it empties the clipboard.
  const armed = [...world.events.alarmList.entries()].filter(([name]) => name.startsWith(ALARM_PREFIX));
  assert.equal(armed.length, 1);
  assert.equal(armed[0][1].when, world.clock.now() + CLEAR_AFTER_MS);
  assert.equal(armed[0][0], `${ALARM_PREFIX}${world.sessionStorage.data.get(MARK_KEY)}`);
  world.clock.advance(CLEAR_AFTER_MS);
  world.events.alarmList.delete(armed[0][0]);
  await world.events.fireAlarm(armed[0][0]);
  assert.deepEqual(world.written, [REFERENCE, ""], "the clipboard is empty again");
});

/** The frames of a page with a sign-in form in the top and a code field in a frame of the same site. */
const sameSite = () => [
  { frameId: 0, documentId: "doc-1", url: LOGIN_URL, origin: LOGIN_ORIGIN, itemIds: [idOf(1)] },
  { frameId: 5, documentId: "doc-5", url: SUB_URL, origin: LOGIN_ORIGIN, itemIds: [idOf(1)] },
];

test("fill_the_code_puts_in_the_code_field_of_a_frame_of_the_same_site_and_nothing_else", async () => {
  const world = await codeWorld({ frames: sameSite() });
  const sub = world.addFrame({ url: SUB_URL, frameId: 5, documentId: "doc-5", selfOrigin: LOGIN_ORIGIN }, ["totp"]);
  // A frame of another site that also has a code field: the page matching does not offer it, so it is never asked.
  const alien = world.addFrame({ url: "https://evil.example.test/code", frameId: 6, documentId: "doc-6", selfOrigin: "https://evil.example.test" }, ["totp"]);
  world.page.fields = ["username", "password", "totp"];
  const popup = world.popup();
  const row = await suggestion(popup);
  assert.deepEqual(await popup.list.fill(row, TAB, { only: "totp" }), { ok: true });
  // The top has a code field too, and is the first frame with one: it takes the code, and only the code.
  assert.deepEqual(world.page.filled, { totp: REFERENCE });
  assert.deepEqual(sub.filled, {});
  assert.deepEqual(alien.filled, {});
  assert.deepEqual(world.pushed.map((p) => p.message.body.field), ["totp"]);
  assert.equal(world.injections.some((i) => i.target?.documentIds?.[0] === "doc-6"), false, "the other site's frame was never asked");

  // Without a code field in the top, the frame of the same site below it gets the code.
  const below = await codeWorld({ frames: sameSite() });
  below.page.fields = ["username", "password"];
  const frame = below.addFrame({ url: SUB_URL, frameId: 5, documentId: "doc-5", selfOrigin: LOGIN_ORIGIN }, ["totp"]);
  const other = below.addFrame({ url: "https://evil.example.test/code", frameId: 6, documentId: "doc-6", selfOrigin: "https://evil.example.test" }, ["totp"]);
  const p2 = below.popup();
  assert.deepEqual(await p2.list.fill(await suggestion(p2), TAB, { only: "totp" }), { ok: true });
  assert.deepEqual(frame.filled, { totp: REFERENCE });
  assert.deepEqual(below.page.filled, {});
  assert.deepEqual(other.filled, {});
});

test("fill_the_code_on_a_page_without_a_code_field_fills_nothing", async () => {
  const world = await codeWorld();
  world.page.fields = ["username", "password"];
  const popup = world.popup();
  const row = await suggestion(popup);
  assert.deepEqual(await popup.list.fill(row, TAB, { only: "totp" }), { ok: false, reason: "no_fields" });
  assert.deepEqual(world.page.filled, {});
  assert.deepEqual(world.pushed, []);
  // An item without a code has nothing to put there.
  const bankWorld = await codeWorld({ frames: [{ frameId: 0, documentId: "doc-1", url: LOGIN_URL, origin: LOGIN_ORIGIN, itemIds: [idOf(2)] }] });
  bankWorld.page.fields = ["totp"];
  const bankPopup = bankWorld.popup();
  assert.deepEqual(await bankPopup.list.fill(await suggestion(bankPopup), TAB, { only: "totp" }), { ok: false, reason: "no_value" });
  assert.deepEqual(bankWorld.pushed, []);
  // Any other `only` is refused by the schema before the background looks at it.
  assert.throws(() => popup.request("fill", { ref: row.ref, tab_id: TAB, only: "password" }));
});

test("a_search_reference_cannot_fill_the_code", async () => {
  const world = await codeWorld();
  world.page.fields = ["totp"];
  const popup = world.popup();
  const found = (await popup.list.search({ query: "example" })).rows[0];
  assert.deepEqual(await popup.request("fill", { ref: found.ref, tab_id: TAB, frame_id: 0, only: "totp" }), { ok: false, reason: "not_offered" });
  assert.deepEqual(world.pushed, []);
  assert.deepEqual(world.injections, []);
});

test("the_page_after_a_sign_in_is_offered_the_code_of_that_item_only", async () => {
  const { load } = await pkg();
  const { createFillContext } = await load("background/fillContext.mjs");
  /** @type {any} */
  let world = null;
  const context = createFillContext({ now: () => world.clock.now() });
  world = await codeWorld({ fillContext: context });
  const popup = world.popup();
  // Before any sign-in nothing is marked.
  assert.equal((await suggestion(popup)).next, undefined);

  // The sign-in is filled; the page that follows (the same tab) may ask for the code.
  const row = await suggestion(popup);
  assert.deepEqual(await popup.list.fill(row, TAB), { ok: true });
  const after = await suggestion(popup);
  assert.equal(after.next, true);
  // Only the filled item is marked, and only in that tab.
  assert.deepEqual(context.filledIn(TAB).map((f) => f.itemId), [idOf(1)]);
  assert.deepEqual(context.filledIn(TAB + 1), []);

  // The code goes in: the offer ends.
  world.page.fields = ["totp"];
  assert.deepEqual(await popup.list.fill(after, TAB, { only: "totp" }), { ok: true });
  assert.equal((await suggestion(popup)).next, undefined);

  // Five minutes later a sign-in is not "just filled" any more.
  world.page.fields = ["username", "password"];
  assert.deepEqual(await popup.list.fill(await suggestion(popup), TAB), { ok: true });
  assert.equal((await suggestion(popup)).next, true);
  world.clock.advance(FILL_CONTEXT_TTL_MS);
  assert.equal((await suggestion(popup)).next, undefined);

  // A lock forgets it: after the next unlock nothing is marked.
  assert.deepEqual(await popup.list.fill(await suggestion(popup), TAB), { ok: true });
  await world.coreHost.lock("manual");
  await world.open();
  const again = world.popup();
  assert.equal((await suggestion(again)).next, undefined);
});

test("an_item_without_a_code_is_never_offered_one_after_its_sign_in", async () => {
  const { load } = await pkg();
  const { createFillContext } = await load("background/fillContext.mjs");
  /** @type {any} */
  let world = null;
  const context = createFillContext({ now: () => world.clock.now() });
  world = await codeWorld({ fillContext: context, frames: [{ frameId: 0, documentId: "doc-1", url: LOGIN_URL, origin: LOGIN_ORIGIN, itemIds: [idOf(2)] }] });
  const popup = world.popup();
  assert.deepEqual(await popup.list.fill(await suggestion(popup), TAB), { ok: true });
  assert.equal((await suggestion(popup)).next, undefined);
});

test("a_reference_code_is_not_the_constant_of_the_other_tests", () => {
  // The helper's constant is for the tests that only need some code; the reference above is the RFC's.
  assert.notEqual(TOTP_CODE, REFERENCE);
});

test("the_offer_of_the_code_does_not_depend_on_saving_passwords", async () => {
  // Without the flag `save` the fill context of the write path is not made; the fill flow then keeps a memory of its own,
  // so the popup offers the code after a sign-in in a build with the flag off too. Everything else here needs no memory.
  const { readFileSync } = await import("node:fs");
  const { join, dirname } = await import("node:path");
  const { fileURLToPath } = await import("node:url");
  const main = readFileSync(join(dirname(fileURLToPath(import.meta.url)), "..", "..", "src", "background", "main.mjs"), "utf8");
  assert.match(main, /const fillContext = FEATURES\.save \? createFillContext\(\{ now \}\) : null;/);
  assert.match(main, /const codeOfferContext = fillContext \?\? createFillContext\(\{ now \}\);/);
  assert.match(main, /fillContext: codeOfferContext,/);
  // A fill flow without any memory still serves the code itself and fills it.
  const world = await codeWorld();
  world.page.fields = ["totp"];
  const popup = world.popup();
  const row = await suggestion(popup);
  assert.equal(row.next, undefined);
  assert.deepEqual(await popup.list.itemCode(row.ref), { ok: true, code: REFERENCE, seconds_left: LEFT });
  assert.deepEqual(await popup.list.fill(row, TAB, { only: "totp" }), { ok: true });
  assert.deepEqual(world.page.filled, { totp: REFERENCE });
});

test("a_code_alone_is_never_filled_into_an_unencrypted_page_whatever_the_popup_asks", async () => {
  const world = await codeWorld({ frames: [{ frameId: 0, documentId: "doc-1", url: LOGIN_URL, origin: LOGIN_ORIGIN, insecure: true, itemIds: [idOf(1)] }] });
  world.page.fields = ["username", "password", "totp"];
  const popup = world.popup();
  const row = await suggestion(popup);
  assert.equal(row.insecure, true);
  // The background refuses before it asks the page anything, with its own text in both languages.
  assert.deepEqual(await popup.list.fill(row, TAB, { only: "totp" }), { ok: false, reason: "insecure_page" });
  assert.deepEqual(world.injections, []);
  assert.deepEqual(world.pushed, []);
  assert.equal(world.client.calls.some((/** @type {any} */ c) => c.method === "totp_code"), false, "no code was made for it");
  assert.equal(actionErrorKey("insecure_page"), "popup.error.insecure_page");
  // "Fill anyway" is the sign-in's own confirmation: it fills the sign-in as it always did, and the code is no part of the refusal above.
  assert.deepEqual(await popup.list.fill(row, TAB), { ok: true });
  assert.deepEqual(world.page.filled, { username: "ola@example.net", password: PASSWORD, totp: REFERENCE });
  // Copy is still there.
  assert.deepEqual(await popup.list.copy(row.ref, "totp"), { ok: true });
});

test("a_code_fill_checks_that_the_code_field_is_shown_not_the_sign_in_field_of_the_frame", async () => {
  const world = await codeWorld({ frames: sameSite() });
  world.page.fields = [];
  const sub = world.addFrame({ url: SUB_URL, frameId: 5, documentId: "doc-5", selfOrigin: LOGIN_ORIGIN }, ["username", "totp"]);
  const popup = world.popup();
  assert.deepEqual(await popup.list.fill(await suggestion(popup), TAB, { only: "totp" }), { ok: true });
  assert.deepEqual(sub.filled, { totp: REFERENCE });
  assert.ok(world.frameShown.kinds.length > 0);
  assert.deepEqual([...new Set(world.frameShown.kinds)], ["totp"], "only the code field was asked about");
});
