// A form with edits that are not saved when the vault moves to another tab: the new tab warns before it takes the vault, the old
// tab keeps the form on screen read-only with "Take back", and nothing of the form is ever written anywhere but the page.
import assert from "node:assert/strict";
import { test } from "node:test";
import { autoLockFor } from "../../src/lock.mjs";
import listRoute from "../../src/routes/list.route.mjs";
import newRoute from "../../src/routes/new.route.mjs";
import { dumpDatabase } from "./accountHelpers.mjs";
import { ACCOUNT, VAULT } from "./idbHelpers.mjs";
import { settle, until } from "./syncHelpers.mjs";
import { browser, NAME } from "./tabHelpers.mjs";
import { click, fakeSession, find, submit, t, textOf, withDom } from "./vaultHelpers.mjs";

const NAME_TEXT = "Draft-Name-ZZ41";
const SECRET = "typed-secret-NOT-SAVED-9f3";

/** The page of a tab: the account session, and a route context that records where the page goes. */
function pageOf(tab) {
  const session = fakeSession({ info: { accountId: ACCOUNT, email: "ada@example.test" } });
  session.current = () => (session.isOpen ? { accountId: ACCOUNT, vaultId: VAULT, vkEpoch: 1, email: "ada@example.test" } : null);
  const moves = [];
  const ctx = (path) => ({
    params: {}, path, i18n: { t, lang: "en", missing: [] }, client: { vault: {} }, services: { crypto: session, sync: tab.sync }, go: (p) => moves.push(p), routes: [],
  });
  return { session, moves, ctx, done: () => autoLockFor(session, tab.sync).stop() };
}

/** Two tabs; the first has the vault open on the form for a new item, with edits typed in. */
async function rig() {
  const b = await browser();
  const one = await b.tab();
  const two = await b.tab();
  const p1 = pageOf(one);
  const p2 = pageOf(two);
  const frame1 = await newRoute.load(p1.ctx("/items/new"));
  const card2 = await listRoute.load(p2.ctx("/items"));
  assert.ok(find(card2, "standby"), "the second tab is on standby");
  find(frame1, "name").value = NAME_TEXT;
  find(frame1, "password").value = SECRET;
  return { b, one, two, p1, p2, frame1, card2, done: () => { p1.done(); p2.done(); b.stopAll(); } };
}

test("use_here_asks_the_owner_about_unsaved_edits_and_warns", async () => {
  await withDom(async () => {
    const r = await rig();
    try {
      await click(find(r.card2, "use-here"));
      await settle(5);
      const warning = find(r.card2, "warning");
      assert.equal(warning.hidden, false, "the owner has edits that are not saved: a warning");
      assert.ok(textOf(warning).includes("standby.warn_unsaved"));
      assert.ok(find(r.card2, "use-here-anyway") && find(r.card2, "warning-cancel"));
      assert.equal(r.two.sync.standby(), true, "nothing moved yet");
      assert.ok(r.one.sync.current(), "the owner still runs the engine");
      // "Cancel" goes back to the notice and changes nothing.
      await click(find(r.card2, "warning-cancel"));
      assert.equal(warning.hidden, true);
      assert.equal(r.two.sync.standby(), true);
      // A form that holds nothing (the owner cleared it) is no warning: the vault moves at once.
      find(r.frame1, "name").value = "";
      find(r.frame1, "password").value = "";
      await click(find(r.card2, "use-here"));
      await until(() => r.two.sync.current() !== null, "the vault moved without a warning");
      assert.equal(warning.hidden, true);
    } finally {
      r.done();
    }
  });
});

test("no_answer_within_a_second_also_warns", async () => {
  await withDom(async () => {
    const r = await rig();
    try {
      for (const channel of r.b.channels.all) if (channel.name === NAME && channel.listeners.size > 0) channel.muted = true; // a frozen owner tab
      const pressed = click(find(r.card2, "use-here"));
      await settle(10);
      r.b.clock.advance(999);
      await settle(10);
      assert.equal(find(r.card2, "warning").hidden, true, "the owner is given a second");
      r.b.clock.advance(1);
      await pressed;
      assert.equal(find(r.card2, "warning").hidden, false);
      assert.ok(textOf(find(r.card2, "warning")).includes("standby.warn_no_answer"));
      assert.equal(r.two.sync.standby(), true, "nothing moved");
    } finally {
      r.done();
    }
  });
});

test("the_old_tab_keeps_the_unsaved_form_visible_and_read_only_with_take_back", async () => {
  await withDom(async () => {
    const r = await rig();
    try {
      // The user goes on after the warning: the vault moves to the second tab.
      await click(find(r.card2, "use-here"));
      await settle(5);
      await click(find(r.card2, "use-here-anyway"));
      await until(() => r.two.sync.current() !== null, "the engine runs in the second tab");
      await until(() => r.one.sync.standby(), "the first tab is on standby");
      assert.deepEqual(r.p2.moves, ["/items"], "the second tab shows its screen again");

      // The first tab keeps the form, with what was typed, and says so; it is read-only and nothing is saved from it.
      const edit = find(r.frame1, "edit");
      assert.ok(edit && find(r.frame1, "edit-form"), "the form is still on screen");
      assert.equal(find(r.frame1, "name").value, NAME_TEXT);
      assert.equal(find(r.frame1, "password").value, SECRET);
      for (const role of ["name", "username", "password", "url", "notes"]) {
        assert.equal(find(r.frame1, role).readOnly, true, `${role} is read-only`);
      }
      assert.equal(find(r.frame1, "save").disabled, true);
      assert.equal(edit.getAttribute("data-state"), "frozen");
      assert.ok(find(r.frame1, "take-back"), "with a button to take the vault back");
      assert.equal(find(r.frame1, "use-here"), null);
      assert.ok(textOf(find(r.frame1, "standby")).includes("standby.unsaved_title"));
      await submit(find(r.frame1, "edit-form"));
      assert.equal(r.one.api.puts.length, 0, "nothing is sent from the old tab");
      assert.equal(r.p1.moves.length, 0);

      // "Take back": the second tab holds nothing unsaved, so no warning; the vault moves back and the same form goes on.
      await click(find(r.frame1, "take-back"));
      await until(() => r.one.sync.current() !== null, "the first tab has the engine again");
      assert.deepEqual(r.p1.moves, ["/items/new"], "the screen is built again");
      const again = await newRoute.load(r.p1.ctx("/items/new"));
      assert.equal(find(again, "edit"), edit, "it is the same form, not a new one");
      assert.equal(find(again, "name").value, NAME_TEXT, "with what was typed");
      assert.equal(find(again, "name").readOnly, false);
      assert.equal(find(again, "save").disabled, false);
      assert.equal(edit.getAttribute("data-state"), "open");
      assert.equal(r.one.sync.hasUnsaved(), true, "and the owner knows it has edits again");

      // Saved from here, the form is done: nothing unsaved is left.
      find(again, "password").value = "";
      await submit(find(again, "edit-form"));
      assert.match(r.p1.moves.at(-1), /^\/items\/[0-9a-f]{32}$/);
      assert.equal(r.one.sync.hasUnsaved(), false);
    } finally {
      r.done();
    }
  });
});

test("a_tab_without_unsaved_edits_shows_the_plain_notice_when_the_vault_moves", async () => {
  await withDom(async () => {
    const r = await rig();
    try {
      find(r.frame1, "name").value = "";
      find(r.frame1, "password").value = "";
      await r.two.sync.takeOver();
      await until(() => r.one.sync.standby(), "the first tab is on standby");
      assert.equal(find(r.frame1, "edit-form"), null, "no form is kept");
      assert.ok(find(r.frame1, "use-here"), "the plain notice");
      assert.equal(find(r.frame1, "take-back"), null);
    } finally {
      r.done();
    }
  });
});

test("a_kept_form_goes_on_when_the_vault_comes_back_by_itself_and_a_lock_wipes_it", async () => {
  await withDom(async () => {
    const r = await rig();
    try {
      await r.two.sync.takeOver();
      await until(() => r.one.sync.standby(), "the first tab is on standby");
      assert.ok(find(r.frame1, "take-back"));
      assert.equal(find(r.frame1, "name").value, NAME_TEXT);

      // The second tab signs out: the first one, which waits and is in view, gets the vault and its screen is built again.
      r.two.sync.stop();
      await until(() => r.one.sync.current() !== null, "the waiting tab gets the vault");
      await until(() => r.p1.moves.length > 0, "the screen is built again");
      const again = await newRoute.load(r.p1.ctx("/items/new"));
      assert.equal(find(again, "name").value, NAME_TEXT);
      assert.equal(find(again, "name").readOnly, false);

      // The vault moves away once more, and then the user locks: the form is emptied, and nothing of it is kept.
      await r.two.sync.start({ accountId: ACCOUNT, vaultId: VAULT, vkEpoch: 1 });
      await r.two.sync.takeOver();
      await until(() => r.one.sync.standby(), "the first tab is on standby again");
      assert.ok(find(r.frame1, "take-back") || find(again, "take-back"));
      await autoLockFor(r.p1.session, r.one.sync).lock(); // the one way to lock: the service stops, then the session ends
      await settle(10);
      assert.equal(find(r.frame1, "name"), null, "the form is gone");
      assert.equal(find(again, "name"), null);
      assert.equal(r.one.sync.takeFrozen("new"), null, "and nothing of it is kept");
    } finally {
      r.done();
    }
  });
});

test("the_draft_never_goes_to_indexeddb", async () => {
  // Everything the page prints is captured, and the capture is proved to work before the flow starts.
  const printed = [];
  const methods = ["log", "info", "warn", "error", "debug", "trace", "dir"];
  const saved = Object.fromEntries(methods.map((method) => [method, console[method]]));
  for (const method of methods) console[method] = (...args) => void printed.push(args.map((a) => (typeof a === "string" ? a : JSON.stringify(a, (_k, v) => (v instanceof Error ? v.stack : v)))).join(" "));
  try {
    console.warn("capture-probe");
    assert.deepEqual(printed, ["capture-probe"], "the capture works");
    printed.length = 0;
    await draftNeverLeaves(printed);
  } finally {
    for (const method of methods) console[method] = saved[method];
  }
});

async function draftNeverLeaves(printed) {
  await withDom(async () => {
    const r = await rig();
    try {
      await click(find(r.card2, "use-here"));
      await settle(5);
      await click(find(r.card2, "use-here-anyway"));
      await until(() => r.one.sync.standby(), "the vault moved");
      await click(find(r.frame1, "take-back"));
      await until(() => r.one.sync.current() !== null, "and came back");
      const frame2 = await newRoute.load(r.p1.ctx("/items/new"));
      await r.two.sync.takeOver();
      await until(() => r.one.sync.standby(), "and moved again");
      await settle(20);

      assert.equal(find(frame2, "password").value, SECRET, "the draft is in the form");
      const dump = await dumpDatabase(r.b.db.store);
      for (const piece of [SECRET, NAME_TEXT]) {
        assert.ok(!dump.includes(piece), "no part of the draft is in IndexedDB");
        assert.ok(!JSON.stringify(r.b.channels.posted).includes(piece), "nor in a message between the tabs");
        assert.ok(!JSON.stringify([r.one.api.puts, r.two.api.puts, r.one.api.gets, r.two.api.gets]).includes(piece), "nor in a request");
        assert.ok(!JSON.stringify([r.one.store.spy, r.two.store.spy]).includes(piece), "nor in what the stores were asked to write");
      }
      for (const storage of [globalThis.localStorage, globalThis.sessionStorage]) assert.equal(storage?.length ?? 0, 0, "nor in web storage");
      for (const piece of [SECRET, NAME_TEXT]) assert.ok(!printed.join(" ").includes(piece), "nor in the console");
    } finally {
      r.done();
    }
  });
}
