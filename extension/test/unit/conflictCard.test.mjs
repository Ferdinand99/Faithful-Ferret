// The items whose change waits, was refused or is in conflict, in the popup of
// a build with saving from the extension on (design document, section 8.5):
// the conflict card shows the two versions (name, user name, when and on which
// device each was changed) and never a password; "Keep mine" and "Keep the
// server's" each take a second click, which a double click is not, and the
// choice is made against the versions the card showed; "Discard the draft"
// asks first. The background is the real one with the sync wired in, over a
// fake engine that records what is asked of it; the popup's parts run on a
// small stand-in for the DOM, with the texts of the built package.
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { join } from "node:path";
import { test } from "node:test";
import { byRole, click, one, settle, textsOf, useDocument, withAttribute } from "./pageDom.mjs";
import { fakeEngines, pkg } from "./sessionHelpers.mjs";
import { MP, syncWorld } from "./syncWorld.mjs";

const PASSWORD = "Sentinel-pa55word-never-shown";
const OLD_PASSWORD = "Older-sentinel-pa55";
const CONFLICTED = "c0".repeat(16);
const REFUSED = "d0".repeat(16);
const WAITING = "e0".repeat(16);
const MODIFIED_MINE = Date.UTC(2026, 10, 20, 9, 30);
const MODIFIED_THEIRS = Date.UTC(2026, 10, 21, 18, 5);

/** The view of one version, as the core gives it: the password field is there; its value never is, but this one has it. */
const viewOf = (/** @type {string} */ name, /** @type {string} */ password, /** @type {number} */ modified, /** @type {string} */ device) => ({
  item_type: "login",
  name,
  modified,
  device,
  fields: [
    { id: "username", label: "Username", kind: "text", value: "anna@example.net" },
    // A view never carries a secret; this one does, to show that nothing of it reaches the popup.
    { id: "password", label: "Password", kind: "password", value: password },
  ],
  urls: [{ url: "https://login.example.net", matching: "host" }],
  has_notes: true,
});

/** An engine with one item in conflict, one refused change and one change that waits. */
function engineWithItems() {
  const engines = fakeEngines();
  /** @param {any} engine */
  const fill = (engine) => {
    engine.items = [
      { id: WAITING, name: "Waiting", username: "w", pending: true, blocked: false, blockedReason: null, conflict: false },
      { id: REFUSED, name: "Refused", username: "r", pending: true, blocked: true, blockedReason: "quota_exceeded", conflict: false },
      { id: CONFLICTED, name: "Mail (this device)", username: "anna@example.net", pending: true, blocked: true, blockedReason: "conflict", conflict: true },
      { id: "f0".repeat(16), name: "Calm", username: "", pending: false, blocked: false, blockedReason: null, conflict: false },
    ];
    engine.conflicts.set(CONFLICTED, {
      local: { rev: 3, deleted: false, view: viewOf("Mail (this device)", PASSWORD, MODIFIED_MINE, "Ferret for Firefox (Windows)"), handle: 7 },
      server: { rev: 3, deleted: false, view: viewOf("Mail (web vault)", OLD_PASSWORD, MODIFIED_THEIRS, "Web vault (Linux)"), handle: 8 },
      fields: [],
      seen: { rev: 3, deleted: false },
    });
  };
  return { engines, fill };
}

/** The background with those items, the popup's flows and builders, and a clock for the clicks. */
async function itemsWorld() {
  const { engines, fill } = engineWithItems();
  const sync = await syncWorld({ engines });
  await sync.signIn();
  const [engine] = engines.made;
  fill(engine);
  const { load, dir } = await pkg();
  const [cards, flowModule] = await Promise.all([load("pages/conflictCard.mjs"), load("pages/popupFlow.mjs")]);
  const request = sync.world.page("pages/popup.html").request;
  const flow = flowModule.createSyncItemsFlow(request);
  const texts = textsOf(JSON.parse(await readFile(join(dir, "locales.en.json"), "utf8")), "en");
  const clock = { now: 1_000_000 };
  return { ...sync, engine, fill, cards, flowModule, request, flow, texts, clock };
}

test("the_conflict_card_shows_no_password", async () => {
  const { engine, cards, request, flow, texts, popup, clock } = await itemsWorld();

  // The sync's part counts the items: one change waits, two items need the user.
  const view = await popup.load();
  assert.equal(view.sync?.pending, 1);
  assert.equal(view.sync?.blocked, 1);
  assert.equal(view.sync?.conflicts, 1);
  useDocument();
  let reviewed = 0;
  const attention = cards.createSyncAttention({ texts, sync: view.sync, onReview: () => (reviewed += 1) });
  assert.equal(one(attention, "sync-pending")?.textContent, texts.t("sync.items.pending", { count: 1 }));
  assert.equal(one(attention, "sync-needs")?.textContent, texts.t("sync.items.needs", { count: 2 }));
  await click(one(attention, "sync-review"));
  assert.equal(reviewed, 1);
  // Every control of the feature says so.
  for (const control of byRole(attention, "sync-review")) assert.equal(control.getAttribute("data-feature"), "save");

  // The list: the conflict first, then the refused change, then the one that waits; names and states only.
  const listed = await request("sync_items", {});
  assert.deepEqual(listed.items.map((/** @type {any} */ i) => [i.name, i.state, i.reason ?? null]), [
    ["Mail (this device)", "conflict", null],
    ["Refused", "blocked", "quota_exceeded"],
    ["Waiting", "pending", null],
  ]);
  assert.equal(listed.total, 3);
  const ref = listed.items[0].ref;
  assert.match(ref, /^[0-9a-f]{32}$/);
  assert.equal(JSON.stringify(listed).includes(CONFLICTED), false, "no item id reaches the popup");

  // The background's answer: both versions, with what the card shows, and no value of the item.
  const answer = await request("item_conflict", { ref });
  assert.deepEqual(answer, {
    ok: true,
    mine: { deleted: false, name: "Mail (this device)", username: "anna@example.net", modified: MODIFIED_MINE, device: "Ferret for Firefox (Windows)" },
    theirs: { deleted: false, name: "Mail (web vault)", username: "anna@example.net", modified: MODIFIED_THEIRS, device: "Web vault (Linux)" },
    differs: [{ what: "name" }],
  });
  for (const secret of [PASSWORD, OLD_PASSWORD]) assert.equal(JSON.stringify(answer).includes(secret), false);
  assert.equal(engine.closed, 1, "the handles of the two versions are closed before the answer goes");

  // The card: both versions, side by side, and no password, nor a place for one.
  useDocument();
  const card = cards.createConflictCard({ texts, flow, ref, onDone: () => {}, onBack: () => {}, now: () => clock.now });
  await card.loaded;
  const sides = byRole(card.root, "conflict-side");
  assert.deepEqual(sides.map((s) => s.getAttribute("data-side")), ["mine", "theirs"]);
  assert.deepEqual(byRole(card.root, "conflict-name").map((n) => n.textContent), ["Mail (this device)", "Mail (web vault)"]);
  assert.deepEqual(byRole(card.root, "conflict-username").map((n) => n.textContent), ["anna@example.net", "anna@example.net"]);
  assert.deepEqual(byRole(card.root, "conflict-device").map((n) => n.textContent), ["Ferret for Firefox (Windows)", "Web vault (Linux)"]);
  assert.equal(byRole(card.root, "conflict-modified").every((n) => n.textContent !== texts.t("sync.conflict.unknown")), true);
  const shown = card.root.textContent;
  for (const secret of [PASSWORD, OLD_PASSWORD]) assert.equal(shown.includes(secret), false);
  assert.equal(shown.includes(texts.t("sync.conflict.no_password")), true);
  for (const tag of ["INPUT", "TEXTAREA"]) assert.equal(withAttribute(card.root, "type").some((n) => n.tagName === tag), false);
  for (const control of withAttribute(card.root, "type")) assert.equal(control.getAttribute("data-feature"), "save", control.getAttribute("data-role") ?? "");

  // A deleted version says so, and has no user name line.
  const conflicts = engine.conflicts.get(CONFLICTED);
  conflicts.server = { rev: 4, deleted: true, view: null, handle: null };
  conflicts.seen = { rev: 4, deleted: true };
  const deleted = await request("item_conflict", { ref });
  assert.deepEqual(deleted.theirs, { deleted: true });
  useDocument();
  const again = cards.createConflictCard({ texts, flow, ref, onDone: () => {}, onBack: () => {} });
  await again.loaded;
  assert.equal(one(again.root, "conflict-deleted")?.textContent, texts.t("sync.conflict.deleted_theirs"));
  assert.equal(byRole(again.root, "conflict-username").length, 1);
});

test("the_conflict_card_names_what_differs_and_never_a_value_or_a_password", async () => {
  const { engine, cards, request, flow, texts, clock } = await itemsWorld();
  const listed = await request("sync_items", {});
  const ref = listed.items[0].ref;
  // The two versions differ in the user name, an own field, the addresses, the favourite mark and (by the number of earlier
  // passwords) the password; the notes and the one-time code are the same.
  const conflicts = engine.conflicts.get(CONFLICTED);
  const mine = viewOf("Mail", PASSWORD, MODIFIED_MINE, "Ferret for Firefox (Windows)");
  const theirs = viewOf("Mail", OLD_PASSWORD, MODIFIED_THEIRS, "Web vault (Linux)");
  mine.fields[0].value = "anna@example.net";
  theirs.fields[0].value = "anna.new@example.net";
  mine.fields.push({ id: "recovery", label: "Recovery e-mail", kind: "email", value: "one@example.net" });
  theirs.fields.push({ id: "recovery", label: "Recovery e-mail", kind: "email", value: "two@example.net" });
  mine.fields.push({ id: "pin", label: "PIN", kind: "hidden", value: "1234-secret-pin" });
  theirs.fields.push({ id: "pin", label: "PIN", kind: "hidden", value: "9999-secret-pin" });
  theirs.urls = [{ url: "https://login.example.org", matching: "host" }];
  theirs.favorite = true;
  /** @type {any} */ (mine).password_history = [{ until: 1 }];
  /** @type {any} */ (theirs).password_history = [];
  conflicts.local.view = mine;
  conflicts.server.view = theirs;
  const answer = await request("item_conflict", { ref });
  assert.deepEqual(answer.differs, [{ what: "username" }, { what: "field", label: "Recovery e-mail" }, { what: "urls" }, { what: "favorite" }, { what: "hidden" }]);
  // Names only: no value of a field, no password, not even the hidden ones the test planted.
  for (const secret of [PASSWORD, OLD_PASSWORD, "1234-secret-pin", "9999-secret-pin", "one@example.net", "two@example.net"]) {
    assert.equal(JSON.stringify(answer.differs).includes(secret), false, secret);
  }
  useDocument();
  const card = cards.createConflictCard({ texts, flow, ref, onDone: () => {}, onBack: () => {}, now: () => clock.now });
  await card.loaded;
  assert.deepEqual(
    byRole(card.root, "conflict-differs-item").map((n) => n.getAttribute("data-what")),
    ["username", "field", "urls", "favorite", "hidden"],
  );
  const text = one(card.root, "conflict-differs")?.textContent ?? "";
  assert.ok(text.includes("Recovery e-mail") && text.includes("hidden field"));
  for (const secret of [PASSWORD, OLD_PASSWORD, "1234-secret-pin", "one@example.net"]) assert.equal(text.includes(secret), false, secret);
  assert.equal(one(card.root, "conflict-differs")?.getAttribute("data-feature"), "save");
  // Identical versions name nothing.
  conflicts.server.view = structuredClone(mine);
  assert.deepEqual((await request("item_conflict", { ref })).differs, []);
});

test("keep_theirs_needs_a_second_click_and_keep_mine_writes_on_top", async () => {
  const { engine, cards, request, flow, texts, clock } = await itemsWorld();
  const ref = (await request("sync_items", {})).items[0].ref;

  // A choice against versions this page was never shown is refused, and nothing is done.
  assert.deepEqual(await request("item_resolve", { ref, choice: "mine" }), { ok: false, reason: "not_shown" });
  assert.deepEqual(engine.resolved, []);

  useDocument();
  let done = 0;
  const card = cards.createConflictCard({ texts, flow, ref, onDone: () => (done += 1), onBack: () => {}, now: () => clock.now });
  await card.loaded;
  const theirs = one(card.root, "keep-theirs");
  const mine = one(card.root, "keep-mine");

  // "Keep the server's": the first click asks again and says what is dropped for good.
  await click(theirs);
  assert.deepEqual(engine.resolved, []);
  assert.equal(theirs?.textContent, texts.t("sync.conflict.confirm_theirs"));
  assert.equal(one(card.root, "conflict-note")?.textContent, texts.t("sync.conflict.drops_theirs"));
  // A second click right away is a double click: still nothing.
  clock.now += 50;
  await click(theirs);
  assert.deepEqual(engine.resolved, []);
  // The other choice takes the question back: its own first click only asks.
  clock.now += 1000;
  await click(mine);
  assert.deepEqual(engine.resolved, []);
  assert.equal(theirs?.textContent, texts.t("sync.conflict.keep_theirs"), "the first choice is asked again from the start");
  assert.equal(mine?.textContent, texts.t("sync.conflict.confirm_mine"));
  assert.equal(one(card.root, "conflict-note")?.textContent, texts.t("sync.conflict.drops_mine"));
  // The second click on "Keep mine", after a moment: this device's version is written on top of the server's version
  // the card showed (the engine's "mine": a write with the server's revision as its base).
  clock.now += 1000;
  await click(mine);
  assert.deepEqual(engine.resolved, [{ id: CONFLICTED, choice: "mine", seen: { rev: 3, deleted: false } }]);
  assert.equal(done, 1);
  // The choice was made against what was shown: it cannot be sent again without reading the versions again.
  assert.deepEqual(await request("item_resolve", { ref, choice: "theirs" }), { ok: false, reason: "not_shown" });

  // "Keep the server's" on a new card: one click is not enough, the second is.
  useDocument();
  const next = cards.createConflictCard({ texts, flow, ref, onDone: () => (done += 1), onBack: () => {}, now: () => clock.now });
  await next.loaded;
  await click(one(next.root, "keep-theirs"));
  assert.equal(engine.resolved.length, 1);
  clock.now += 400;
  await click(one(next.root, "keep-theirs"));
  assert.deepEqual(engine.resolved.at(-1), { id: CONFLICTED, choice: "theirs", seen: { rev: 3, deleted: false } });
  assert.equal(done, 2);
});

test("a_conflict_whose_server_version_changed_is_shown_again_before_a_choice", async () => {
  const { engine, cards, request, flow, texts, clock } = await itemsWorld();
  const ref = (await request("sync_items", {})).items[0].ref;
  useDocument();
  let done = 0;
  const card = cards.createConflictCard({ texts, flow, ref, onDone: () => (done += 1), onBack: () => {}, now: () => clock.now });
  await card.loaded;
  // The engine refuses: the server's version is another one than the card showed. Nothing is done, the card reads both
  // versions again and says why.
  const realResolve = engine.resolve;
  engine.resolve = async (/** @type {string} */ id, /** @type {string} */ choice, /** @type {any} */ seen) => {
    engine.resolved.push({ id, choice, seen });
    throw Object.assign(new Error("changed"), { code: "conflict_changed" });
  };
  await click(one(card.root, "keep-mine"));
  clock.now += 500;
  const reads = engine.closed;
  await click(one(card.root, "keep-mine"));
  await settle();
  assert.equal(done, 0);
  assert.equal(engine.closed, reads + 1, "the versions were read again");
  assert.equal(one(card.root, "conflict-error")?.textContent, texts.t("sync.item.error.conflict_changed"));
  assert.equal(one(card.root, "keep-mine")?.textContent, texts.t("sync.conflict.keep_mine"), "the choice starts over");
  engine.resolve = realResolve;
});

test("discard_needs_a_confirmation", async () => {
  const { engine, cards, request, flow, texts } = await itemsWorld();
  useDocument();
  let closed = 0;
  const list = cards.createSyncItems({ texts, flow, onClose: () => (closed += 1) });
  await list.loaded;
  const rows = byRole(list.root, "sync-item");
  assert.deepEqual(rows.map((r) => r.getAttribute("data-state")), ["conflict", "blocked", "pending"]);
  const refused = rows[1];
  assert.equal(one(refused, "sync-item-reason")?.textContent, texts.t("sync.blocked.quota_exceeded"));
  assert.equal(one(rows[2], "discard-start"), null, "a change that only waits cannot be discarded here");
  assert.equal(one(rows[0], "discard-start"), null, "a conflict has its own two choices");

  // The first click asks; "Keep it" takes the question back, and nothing is discarded.
  await click(one(refused, "discard-start"));
  assert.deepEqual(engine.discarded, []);
  assert.equal(one(refused, "discard-question")?.textContent, texts.t("sync.items.discard_question"));
  await click(one(refused, "discard-cancel"));
  assert.deepEqual(engine.discarded, []);
  assert.equal(one(refused, "discard-question"), null);
  // Asked again and confirmed: the draft goes, and the list is read again.
  await click(one(refused, "discard-start"));
  await click(one(refused, "discard-confirm"));
  assert.deepEqual(engine.discarded, [REFUSED]);
  assert.equal(closed, 0);

  // The background discards only a refused change, never a conflict (which has its own choices) or a change that waits.
  const listed = (await request("sync_items", {})).items;
  const refOf = (/** @type {string} */ state) => listed.find((/** @type {any} */ i) => i.state === state).ref;
  assert.deepEqual(await request("item_discard", { ref: refOf("conflict") }), { ok: false, reason: "in_conflict" });
  assert.deepEqual(await request("item_discard", { ref: refOf("pending") }), { ok: false, reason: "not_found" });
  assert.deepEqual(await request("item_discard", { ref: "ab".repeat(16) }), { ok: false, reason: "not_offered" });
  assert.deepEqual(engine.discarded, [REFUSED]);
});

test("the_references_of_the_items_end_with_the_lock_and_the_page", async () => {
  const { world, engines, fill, request, popup } = await itemsWorld();
  const ref = (await request("sync_items", {})).items[0].ref;
  assert.equal((await request("item_conflict", { ref })).ok, true);
  // Another page's session does not know this page's reference.
  const other = world.page("pages/popup.html").request;
  assert.deepEqual(await other("item_conflict", { ref }), { ok: false, reason: "not_offered" });
  // While locked the types need an open vault.
  await popup.lock();
  await assert.rejects(request("item_conflict", { ref }), { code: "vault_locked" });
  await assert.rejects(request("sync_items", {}), { code: "vault_locked" });
  // After the next unlock (a new engine with the same items) the old reference is gone: the lock ended it.
  assert.deepEqual((await popup.unlock({ password: MP })).result, { ok: true });
  fill(engines.made.at(-1));
  assert.deepEqual(await request("item_conflict", { ref }), { ok: false, reason: "not_offered" });
  assert.deepEqual(await request("item_resolve", { ref, choice: "theirs" }), { ok: false, reason: "not_offered" });

  // A page that goes away takes its references with it: its session is ended in the background.
  /** @type {string[]} */
  const ended = [];
  const endSession = world.syncHost.endSession;
  world.syncHost.endSession = (/** @type {string} */ session) => {
    ended.push(session);
    endSession(session);
  };
  const before = world.ports.length;
  const leaving = world.page("pages/popup.html").request;
  const fresh = (await leaving("sync_items", {})).items[0].ref;
  assert.equal((await leaving("item_conflict", { ref: fresh })).ok, true);
  const port = world.ports[before];
  port.page.disconnect();
  await settle();
  assert.equal(ended.length, 1, "the background heard that the page left");
  assert.match(ended[0], /^[0-9a-f]{32}$/);
  // The same reference was this page's only: the page that is still open never had it.
  assert.deepEqual(await request("item_conflict", { ref: fresh }), { ok: false, reason: "not_offered" });
});
