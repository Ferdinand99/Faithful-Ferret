// "Fill" from the popup, through the real background (core host, lock, router
// and the handlers of the built package) with a fake core, a fake page
// matching and a page whose fill script answers through the router:
//
// - the value goes from the background to the one frame, never through the
//   popup;
// - only a candidate of the page can fill, in the popup session and the frame
//   it was offered for; a search's reference is for copying only;
// - the frame is fetched again before the fill and its origin must still match,
//   and the frame's report must come from that frame and document with the
//   same origin;
// - a report or a result that names no pending request does nothing.
import assert from "node:assert/strict";
import { test } from "node:test";
import { createRefs } from "../../src/background/fillFlow.mjs";
import { ITEMS, LOGIN_ORIGIN, LOGIN_URL, OTHER_PASSWORD, PASSWORD, TAB, TOTP_CODE, idOf, itemWorld } from "./itemHelpers.mjs";

/** The calls of the fake core that read a value. @param {any} world */
const reveals = (world) => world.client.calls.filter((/** @type {any} */ c) => ["reveal_item_field", "totp_code"].includes(c.method));

/** The suggestion rows of the page in `TAB`. @param {any} popup */
async function suggestions(popup) {
  const page = await popup.list.page(TAB);
  assert.ok(page, "the page has candidates");
  return page.rows;
}

test("fill_never_passes_a_value_through_the_popup", async () => {
  const world = await itemWorld();
  await world.open();
  const popup = world.popup();
  const [row, ...more] = await suggestions(popup);
  assert.equal(more.length, 0);
  assert.deepEqual(Object.keys(row).sort(), ["favorite", "frameId", "insecure", "name", "ref", "site", "type", "username"]);
  assert.equal(row.name, "Example");
  assert.equal(row.frameId, 0);

  assert.deepEqual(await popup.list.fill(row, TAB), { ok: true });
  // The page got both values, one message each, to its own document only.
  assert.deepEqual(world.page.filled, { username: "ola@example.net", password: PASSWORD });
  assert.deepEqual(world.pushed.map((p) => [p.tabId, p.message.body.field, p.options]), [
    [TAB, "username", { documentId: "doc-1" }],
    [TAB, "password", { documentId: "doc-1" }],
  ]);
  for (const { message } of world.pushed) assert.deepEqual(message.body.expect, { origin: LOGIN_ORIGIN, frameUrl: LOGIN_URL });
  // The script went into the frame the reference was made for, pinned to its document.
  assert.deepEqual(world.injections.map((i) => i.target), [
    { tabId: TAB, documentIds: ["doc-1"] },
    { tabId: TAB, documentIds: ["doc-1"] },
  ]);
  // Nothing the popup received carries a value, and the item was closed again.
  const received = popup.received().join("\n");
  for (const secret of [PASSWORD, OTHER_PASSWORD, TOTP_CODE]) assert.equal(received.includes(secret), false, secret);
  assert.deepEqual(world.opens, [`open ${idOf(1)}`, `close ${idOf(1)}`]);
  assert.equal(world.handles.size, 0);
  // The frame was fetched again before the fill (once for the offer, once for the fill).
  assert.deepEqual(world.matching.asked, [TAB, TAB]);
});

test("a_search_result_ref_cannot_be_filled_on_a_non_matching_page", async () => {
  // A look-alike page: the page matching (the core's rule) finds no item for it.
  const world = await itemWorld({ frames: [{ frameId: 0, documentId: "doc-1", url: "https://login.example.net.evil.test/", origin: "https://login.example.net.evil.test", itemIds: [] }] });
  await world.open();
  const popup = world.popup();
  assert.deepEqual(await suggestions(popup), [], "nothing is offered to fill");
  // A search finds the real item anywhere in the vault…
  const found = await popup.list.search({ query: "example" });
  const [row] = found.rows;
  assert.equal(row.name, "Example");
  assert.equal(row.frameId, null, "a search result names no frame");
  // …and its reference cannot fill, whatever tab and frame the page names.
  for (const frameId of [0, 1]) {
    assert.deepEqual(await popup.request("fill", { ref: row.ref, tab_id: TAB, frame_id: frameId }), { ok: false, reason: "not_offered" });
  }
  assert.deepEqual(world.injections, []);
  assert.deepEqual(world.pushed, []);
  assert.deepEqual(reveals(world), []);
  // It can be copied.
  assert.deepEqual(await popup.list.copy(row.ref, "password"), { ok: true });
  assert.deepEqual(world.written, [PASSWORD]);

  // On the real page too, a search's reference stays a copy reference.
  const real = await itemWorld();
  await real.open();
  const other = real.popup();
  const [hit] = (await other.list.search({ query: "example" })).rows;
  assert.deepEqual(await other.request("fill", { ref: hit.ref, tab_id: TAB, frame_id: 0 }), { ok: false, reason: "not_offered" });
  assert.deepEqual(real.injections, []);
});

test("a_ref_from_another_popup_session_or_frame_is_refused", async () => {
  const world = await itemWorld({
    frames: [
      { frameId: 0, documentId: "doc-1", url: LOGIN_URL, origin: LOGIN_ORIGIN, itemIds: [idOf(1)] },
      { frameId: 5, documentId: "doc-5", url: "https://www.example.net/login", origin: "https://www.example.net", itemIds: [] },
    ],
  });
  await world.open();
  const first = world.popup();
  const second = world.popup();
  const [row] = await suggestions(first);
  // Another popup session does not know the reference.
  assert.deepEqual(await second.request("fill", { ref: row.ref, tab_id: TAB, frame_id: 0 }), { ok: false, reason: "not_offered" });
  for (const type of ["copy", "item", "open_site"]) {
    const body = type === "copy" ? { ref: row.ref, field: "password" } : { ref: row.ref };
    assert.equal((await second.request(type, body)).ok, false, type);
  }
  // Another frame or another tab: refused, also in the session that got it.
  assert.deepEqual(await first.request("fill", { ref: row.ref, tab_id: TAB, frame_id: 5 }), { ok: false, reason: "not_offered" });
  assert.deepEqual(await first.request("fill", { ref: row.ref, tab_id: TAB + 1, frame_id: 0 }), { ok: false, reason: "not_offered" });
  assert.deepEqual(world.injections, []);
  assert.deepEqual(reveals(world), []);
  // The references of each session differ.
  const [again] = await suggestions(second);
  assert.notEqual(again.ref, row.ref);

  // A closed popup takes its references with it.
  assert.equal(world.fillHost.refs.size(), 2);
  first.close();
  await world.until(() => world.fillHost.refs.size() === 1, "the closed session's references are gone");

  // A lock drops every reference: after an unlock, an old one is refused.
  await world.coreHost.lock("manual");
  await world.open();
  assert.deepEqual(await second.request("fill", { ref: again.ref, tab_id: TAB, frame_id: 0 }), { ok: false, reason: "not_offered" });
  assert.deepEqual(world.injections, []);
});

test("an_unsolicited_frame_report_or_fill_result_does_nothing", async () => {
  const world = await itemWorld();
  await world.open();
  // With no fill running: a report and a result for made-up requests.
  await world.fromPage("frame_report", { request_id: "f".repeat(32), self_origin: LOGIN_ORIGIN, fields: [{ kind: "password", id: "a" }] });
  await world.fromPage("fill_result", { request_id: "f".repeat(32), ok: true });
  await world.tick();
  assert.deepEqual(world.pushed, []);
  assert.deepEqual(reveals(world), []);
  assert.deepEqual(world.opens, []);

  // While a fill runs, a report with its id from another frame or another document is ignored, and so is a result
  // that comes before any value was sent: the fill goes on with the real report only.
  const popup = world.popup();
  const [row] = await suggestions(popup);
  world.page.reports = false;
  const filling = popup.list.fill(row, TAB);
  await world.until(() => world.injections.length === 2, "the script was put in");
  const requestId = world.injections[1].args[0];
  const sender = { ...world.page.sender };
  for (const change of [{ frameId: 3 }, { documentId: "doc-2" }]) {
    Object.assign(world.page.sender, change);
    await world.fromPage("frame_report", { request_id: requestId, self_origin: LOGIN_ORIGIN, fields: [{ kind: "password", id: "a" }] });
    Object.assign(world.page.sender, sender);
  }
  await world.fromPage("fill_result", { request_id: requestId, ok: true });
  await world.tick();
  assert.deepEqual(world.pushed, [], "nothing was sent for a report from elsewhere");
  assert.deepEqual(reveals(world), []);
  await world.fromPage("frame_report", { request_id: requestId, self_origin: LOGIN_ORIGIN, fields: [{ kind: "password", id: "a" }] });
  assert.deepEqual(await filling, { ok: true });
  assert.deepEqual(world.page.filled, { password: PASSWORD });

  // A fill whose frame never reports ends, and sends nothing.
  const quiet = await itemWorld();
  await quiet.open();
  quiet.page.reports = false;
  const [r] = await suggestions(quiet.popup());
  const ended = await quiet.popup().request("fill", { ref: r.ref, tab_id: TAB, frame_id: 0 });
  assert.deepEqual(ended, { ok: false, reason: "not_offered" }, "another popup's reference");
  const own = quiet.popup();
  const [mine] = await suggestions(own);
  assert.deepEqual(await own.list.fill(mine, TAB), { ok: false, reason: "no_report" });
  assert.deepEqual(quiet.pushed, []);
  assert.deepEqual(reveals(quiet), []);
  // A report after the end changes nothing.
  await quiet.fromPage("frame_report", { request_id: quiet.injections[1].args[0], self_origin: LOGIN_ORIGIN, fields: [{ kind: "password", id: "a" }] });
  await quiet.tick();
  assert.deepEqual(quiet.pushed, []);
});

test("fill_rechecks_the_frame_and_aborts_when_the_origin_changed", async () => {
  // Between the offer and the click, the frame moved to another origin: nothing is put into it.
  const moved = await itemWorld();
  await moved.open();
  const popup = moved.popup();
  const [row] = await suggestions(popup);
  moved.matching.frames = [{ frameId: 0, documentId: "doc-2", url: "https://evil.test/login", origin: "https://evil.test", itemIds: [] }];
  assert.deepEqual(await popup.list.fill(row, TAB), { ok: false, reason: "origin_changed" });
  assert.deepEqual(moved.injections, []);
  assert.deepEqual(reveals(moved), []);

  // A new document in the frame (same origin) is not the frame that was offered either.
  const reloaded = await itemWorld();
  await reloaded.open();
  const p2 = reloaded.popup();
  const [r2] = await suggestions(p2);
  reloaded.matching.frames = [{ ...reloaded.matching.frames[0], documentId: "doc-9" }];
  assert.deepEqual(await p2.list.fill(r2, TAB), { ok: false, reason: "origin_changed" });
  assert.deepEqual(reloaded.injections, []);

  // The item no longer matches the frame.
  const unmatched = await itemWorld();
  await unmatched.open();
  const p3 = unmatched.popup();
  const [r3] = await suggestions(p3);
  unmatched.matching.frames = [{ ...unmatched.matching.frames[0], itemIds: [] }];
  assert.deepEqual(await p3.list.fill(r3, TAB), { ok: false, reason: "origin_changed" });
  assert.deepEqual(unmatched.injections, []);

  // The frame navigated after the check, before it reported: its report comes from another origin.
  const late = await itemWorld();
  await late.open();
  const p4 = late.popup();
  const [r4] = await suggestions(p4);
  late.page.sender.url = "https://evil.test/login";
  late.page.sender.selfOrigin = "https://evil.test";
  assert.deepEqual(await p4.list.fill(r4, TAB), { ok: false, reason: "origin_changed" });
  assert.equal(late.injections.length, 2);
  assert.deepEqual(late.pushed, []);
  assert.deepEqual(reveals(late), []);

  // A sandboxed frame: the browser says the right origin, the script's own origin is opaque. It can only narrow.
  for (const selfOrigin of ["null", "https://other.example.net"]) {
    const sandboxed = await itemWorld();
    await sandboxed.open();
    const p5 = sandboxed.popup();
    const [r5] = await suggestions(p5);
    sandboxed.page.sender.selfOrigin = selfOrigin;
    assert.deepEqual(await p5.list.fill(r5, TAB), { ok: false, reason: "origin_changed" }, selfOrigin);
    assert.deepEqual(sandboxed.pushed, [], selfOrigin);
    assert.deepEqual(reveals(sandboxed), [], selfOrigin);
  }

  // The frame refuses the first value (its address changed under it): the rest is not sent.
  const refused = await itemWorld();
  await refused.open();
  const p6 = refused.popup();
  const [r6] = await suggestions(p6);
  refused.page.answer = () => ({ ok: false, reason: "origin_changed" });
  assert.deepEqual(await p6.list.fill(r6, TAB), { ok: false, reason: "origin_changed" });
  assert.deepEqual(refused.pushed.map((p) => p.message.body.field), ["username"]);
  assert.equal(refused.handles.size, 0, "the item is closed again");
});

test("a_lock_during_a_fill_ends_it_before_a_value_is_read", async () => {
  const world = await itemWorld();
  await world.open();
  const popup = world.popup();
  const [row] = await suggestions(popup);
  world.page.reports = false;
  const filling = popup.list.fill(row, TAB);
  await world.until(() => world.injections.length === 2, "the script was put in");
  const requestId = world.injections[1].args[0];
  await world.coreHost.lock("manual");
  await world.fromPage("frame_report", { request_id: requestId, self_origin: LOGIN_ORIGIN, fields: [{ kind: "password", id: "a" }] });
  const result = await filling;
  assert.equal(result.ok, false);
  assert.deepEqual(world.pushed, []);
  assert.deepEqual(reveals(world), []);
});

test("an_insecure_candidate_and_the_one_time_code_fill_through_the_same_path", async () => {
  const world = await itemWorld({
    frames: [{ frameId: 0, documentId: "doc-1", url: LOGIN_URL, origin: LOGIN_ORIGIN, insecure: true, itemIds: [idOf(1)] }],
  });
  await world.open();
  world.page.fields = ["username", "password", "totp"];
  const popup = world.popup();
  const [row] = await suggestions(popup);
  assert.equal(row.insecure, true);
  assert.deepEqual(await popup.list.fill(row, TAB), { ok: true });
  assert.deepEqual(world.page.filled, { username: "ola@example.net", password: PASSWORD, totp: TOTP_CODE });
  const totp = world.client.calls.find((/** @type {any} */ c) => c.method === "totp_code");
  assert.deepEqual(totp?.args.slice(1), [Math.floor(world.clock.now() / 1000)]);
  // The list never named the item's other values.
  assert.equal(JSON.stringify(row).includes(PASSWORD), false);
  assert.equal(ITEMS.length, 3);
});

test("a_lock_and_an_unlock_while_the_frame_is_fetched_again_drop_the_reference_of_the_fill", async () => {
  const world = await itemWorld();
  await world.open();
  const popup = world.popup();
  const [row] = await suggestions(popup);
  // The second question to the page matching (the fill's check of the frame): the vault locks and opens again meanwhile.
  world.matching.before = async (n) => {
    if (n !== 2) return;
    await world.coreHost.lock("manual");
    await world.open();
  };
  assert.deepEqual(await popup.list.fill(row, TAB), { ok: false, reason: "not_offered" });
  assert.deepEqual(world.injections, []);
  assert.deepEqual(reveals(world), []);
});

test("an_open_vault_without_a_running_sync_refuses_item_actions_without_locking", async () => {
  const world = await itemWorld();
  await world.open();
  const popup = world.popup();
  const [row] = await suggestions(popup);
  world.matching.syncRunning = false;
  assert.deepEqual(await popup.list.copy(row.ref, "password"), { ok: false, reason: "sync_not_running" });
  assert.deepEqual(await popup.list.fill(row, TAB), { ok: false, reason: "sync_not_running" });
  assert.equal((await popup.list.item(row.ref)).reason, "sync_not_running");
  await assert.rejects(popup.request("search", { query: "" }));
  // None of it is a failed worker: the vault stays open, and nothing was read.
  assert.equal(world.coreHost.state(), "unlocked");
  assert.equal(world.client.locks, 0);
  assert.deepEqual(world.written, []);
  assert.deepEqual(reveals(world), []);
});

test("a_full_session_drops_its_oldest_copy_reference_and_never_a_fill_reference", () => {
  let n = 0;
  const refs = createRefs({ random: (bytes) => bytes.fill((n += 1)), max: 3 });
  const session = "a".repeat(32);
  const fill = refs.issue(session, "fill", { purpose: "fill", itemId: idOf(1), tabId: TAB, frames: [{ frameId: 0, origin: LOGIN_ORIGIN }] });
  const copies = [2, 3].map((i) => refs.issue(session, "copy", { purpose: "copy", itemId: idOf(i) }));
  // A new copy reference: the oldest copy one goes, the fill one stays.
  const fourth = refs.issue(session, "copy", { purpose: "copy", itemId: idOf(4) });
  assert.equal(refs.get(session, copies[0]), null);
  assert.equal(refs.get(session, fill)?.purpose, "fill");
  assert.equal(refs.get(session, copies[1])?.itemId, idOf(3));
  assert.equal(refs.get(session, fourth)?.itemId, idOf(4));
  // The dropped item gets a new reference when it is asked for again.
  const again = refs.issue(session, "copy", { purpose: "copy", itemId: idOf(2) });
  assert.notEqual(again, copies[0]);
  // A session full of fill references refuses a new one rather than drop one.
  const full = createRefs({ random: (bytes) => bytes.fill((n += 1)), max: 2 });
  for (const frameId of [0, 1]) full.issue(session, "fill", { purpose: "fill", itemId: idOf(1), tabId: TAB, frames: [{ frameId, origin: LOGIN_ORIGIN }] });
  assert.throws(() => full.issue(session, "copy", { purpose: "copy", itemId: idOf(2) }), { code: "busy" });
});

// ------------------------------------------------------------ frames that tie on an item

const FRAME_URL = "https://login.example.net/frame/login";

/** The top and a frame of the top's origin that both match the login item (they tie). */
const tied = () => [
  { frameId: 0, documentId: "doc-1", url: LOGIN_URL, origin: LOGIN_ORIGIN, itemIds: [idOf(1)] },
  { frameId: 3, documentId: "doc-3", url: FRAME_URL, origin: LOGIN_ORIGIN, itemIds: [idOf(1)] },
];

test("an_item_that_ties_in_two_frames_is_listed_once_and_fills_the_first_frame_with_a_form", async () => {
  const world = await itemWorld({ frames: tied() });
  await world.open();
  // The top has no sign-in form, the frame has one.
  world.page.fields = [];
  const frame = world.addFrame({ url: FRAME_URL, frameId: 3, documentId: "doc-3", selfOrigin: LOGIN_ORIGIN });
  const popup = world.popup();
  const rows = await suggestions(popup);
  assert.equal(rows.length, 1, "the item is listed once");
  assert.equal(rows[0].frameId, 0, "the top first");
  assert.deepEqual(await popup.list.fill(rows[0], TAB), { ok: true });
  // The script went into both frames; only the frame with the form got the values.
  assert.deepEqual(world.injections.filter((i) => i.func).map((i) => i.target), [{ tabId: TAB, documentIds: ["doc-1"] }, { tabId: TAB, documentIds: ["doc-3"] }]);
  assert.deepEqual(world.page.filled, {});
  assert.deepEqual(frame.filled, { username: "ola@example.net", password: PASSWORD });
  assert.deepEqual(world.pushed.map((p) => p.options), [{ documentId: "doc-3" }, { documentId: "doc-3" }]);

  // When both have a form, the top is filled, and only the top: one fill fills one group.
  const both = await itemWorld({ frames: tied() });
  await both.open();
  const other = both.addFrame({ url: FRAME_URL, frameId: 3, documentId: "doc-3", selfOrigin: LOGIN_ORIGIN });
  const p2 = both.popup();
  assert.deepEqual(await p2.list.fill((await suggestions(p2))[0], TAB), { ok: true });
  assert.deepEqual(both.page.filled, { username: "ola@example.net", password: PASSWORD });
  assert.deepEqual(other.filled, {});
  // The frame's late report of a request that ended does nothing.
  assert.deepEqual(both.pushed.map((p) => p.options.documentId), ["doc-1", "doc-1"]);
});

test("a_frame_whose_report_narrows_to_nothing_is_dropped_and_no_form_gives_no_fields", async () => {
  // A sandboxed frame of the top's origin (its own origin is opaque) ties with a top that has no form.
  const world = await itemWorld({ frames: tied() });
  await world.open();
  world.page.fields = [];
  const sandbox = world.addFrame({ url: FRAME_URL, frameId: 3, documentId: "doc-3", selfOrigin: "null" });
  const popup = world.popup();
  assert.deepEqual(await popup.list.fill((await suggestions(popup))[0], TAB), { ok: false, reason: "no_fields" });
  assert.deepEqual(world.pushed, [], "nothing went into the sandboxed frame");
  assert.deepEqual(sandbox.filled, {});
  assert.deepEqual(reveals(world), []);

  // The sandbox has the form and the top has one too: the sandbox is dropped, the top is filled.
  const second = await itemWorld({ frames: tied() });
  await second.open();
  second.addFrame({ url: FRAME_URL, frameId: 3, documentId: "doc-3", selfOrigin: "null" });
  const p2 = second.popup();
  assert.deepEqual(await p2.list.fill((await suggestions(p2))[0], TAB), { ok: true });
  assert.deepEqual(second.pushed.map((p) => p.options.documentId), ["doc-1", "doc-1"]);
});

test("a_fill_that_names_a_frame_fills_only_that_frame", async () => {
  // The menu's path: the request names the frame that was clicked.
  const world = await itemWorld({ frames: tied() });
  await world.open();
  const frame = world.addFrame({ url: FRAME_URL, frameId: 3, documentId: "doc-3", selfOrigin: LOGIN_ORIGIN });
  const popup = world.popup();
  const [row] = await suggestions(popup);
  assert.deepEqual(await popup.request("fill", { ref: row.ref, tab_id: TAB, frame_id: 3 }), { ok: true });
  assert.deepEqual(world.injections.filter((i) => i.func).map((i) => i.target), [{ tabId: TAB, documentIds: ["doc-3"] }]);
  assert.deepEqual(world.page.filled, {});
  assert.deepEqual(frame.filled, { username: "ola@example.net", password: PASSWORD });
  // The frame was checked again on its own.
  assert.equal(world.matching.askedFrames.at(-1), 3);
  // A frame that is not one of the reference's is refused.
  assert.deepEqual(await popup.request("fill", { ref: row.ref, tab_id: TAB, frame_id: 9 }), { ok: false, reason: "not_offered" });
});

test("a_tied_frame_that_changed_is_left_out_and_the_others_are_still_tried", async () => {
  const world = await itemWorld({ frames: tied() });
  await world.open();
  world.addFrame({ url: FRAME_URL, frameId: 3, documentId: "doc-3", selfOrigin: LOGIN_ORIGIN });
  const popup = world.popup();
  const [row] = await suggestions(popup);
  // The frame got a new document after the list: it is not the frame that was offered.
  world.matching.frames = [tied()[0], { ...tied()[1], documentId: "doc-7" }];
  assert.deepEqual(await popup.list.fill(row, TAB), { ok: true });
  assert.deepEqual(world.injections.filter((i) => i.func).map((i) => i.target), [{ tabId: TAB, documentIds: ["doc-1"] }]);
});

test("the_candidates_reply_carries_the_host_the_insecure_mark_and_the_grant_list", async () => {
  const world = await itemWorld({ frames: [{ frameId: 0, documentId: "doc-1", url: LOGIN_URL, origin: LOGIN_ORIGIN, insecure: true, itemIds: [idOf(1)] }] });
  world.matching.grant = [{ origin: "https://www.example.net", host: { a_label: "www.example.net", unicode: "www.example.net" } }];
  await world.open();
  const popup = world.popup();
  const reply = await popup.request("candidates", { tab_id: TAB });
  assert.deepEqual(reply.host, { a_label: "login.example.net", unicode: "login.example.net" });
  assert.equal(reply.insecure, true);
  assert.deepEqual(reply.grant, world.matching.grant);
  assert.equal(reply.handles.length, 1);
  assert.equal(reply.handles[0].insecure, true);
  // A tab that shows no web page: no host, nothing offered.
  const none = await popup.request("candidates", { tab_id: TAB + 1 });
  assert.deepEqual(none, { handles: [], insecure: false, grant: [] });
});
