// A copied secret is taken off the clipboard again after 30 seconds, but only while it is still ours, and at once by a lock.
import assert from "node:assert/strict";
import { test } from "node:test";
import { CLEAR_AFTER_MS, RETRY_WINDOW_MS, clearOnLock, createSecretClipboard, secretClipboardFor } from "../../src/secretClipboard.mjs";
import { fakeClock, settle } from "./vaultHelpers.mjs";

/** A clipboard that records what is written and holds the last text; `refuse` makes the next writes fail. */
function fakeClipboard({ readable = true } = {}) {
  const clipboard = {
    text: "",
    writes: [],
    refuse: 0,
    reads: 0,
    async writeText(text) {
      if (clipboard.refuse > 0) {
        clipboard.refuse -= 1;
        throw new Error("not focused");
      }
      clipboard.writes.push(text);
      clipboard.text = text;
    },
  };
  if (readable) {
    clipboard.readText = async () => {
      clipboard.reads += 1;
      return clipboard.text;
    };
  }
  return clipboard;
}

/** A window that has focus events, and a document that says whether the tab has focus. */
function fakeFocus(focused = true) {
  const listeners = new Set();
  return {
    focused,
    doc: { hasFocus: () => state.focused },
    win: {
      addEventListener: (type, fn) => type === "focus" && listeners.add(fn),
      removeEventListener: (type, fn) => type === "focus" && listeners.delete(fn),
    },
    get listening() {
      return listeners.size;
    },
    /** The tab gets focus back. */
    focus() {
      state.focused = true;
      for (const fn of [...listeners]) {
        listeners.delete(fn);
        fn();
      }
    },
  };
}
let state;

function rig({ clipboard = fakeClipboard(), granted = null, focused = true } = {}) {
  const clock = fakeClock();
  state = fakeFocus(focused);
  const permissions = granted === null ? null : { query: async () => ({ state: granted }) };
  const helper = createSecretClipboard({
    clipboard, doc: state.doc, win: state.win, permissions, setTimer: clock.setTimeout, clearTimer: clock.clearTimeout,
  });
  return { clipboard, clock, helper, focus: state };
}

test("the_clear_comes_after_30_seconds_and_not_before", async () => {
  const { clipboard, clock, helper } = rig({ clipboard: fakeClipboard({ readable: false }) });
  assert.equal(CLEAR_AFTER_MS, 30_000);
  await helper.copy("S3CRET");
  assert.deepEqual(clipboard.writes, ["S3CRET"]);
  assert.equal(helper.pending(), true);
  clock.advance(29_999);
  await settle();
  assert.deepEqual(clipboard.writes, ["S3CRET"]);
  clock.advance(1);
  await settle();
  assert.deepEqual(clipboard.writes, ["S3CRET", ""]);
  assert.equal(helper.pending(), false);
  assert.equal(clock.pending, 0);
});

test("a_newer_secret_replaces_the_older_one_and_gets_its_own_30_seconds", async () => {
  const { clipboard, clock, helper } = rig({ clipboard: fakeClipboard({ readable: false }) });
  await helper.copy("A");
  clock.advance(20_000);
  await helper.copy("B");
  clock.advance(10_000); // 30 seconds after A: A's timer is gone
  await settle();
  assert.deepEqual(clipboard.writes, ["A", "B"]);
  clock.advance(20_000);
  await settle();
  assert.deepEqual(clipboard.writes, ["A", "B", ""]);
});

test("where_the_clipboard_can_be_read_it_is_cleared_only_when_it_still_holds_our_value", async () => {
  const mine = rig({ granted: "granted" });
  await mine.helper.copy("S3CRET");
  mine.clock.advance(30_000);
  await settle();
  assert.equal(mine.clipboard.reads, 1);
  assert.deepEqual(mine.clipboard.writes, ["S3CRET", ""]);

  const other = rig({ granted: "granted" });
  await other.helper.copy("S3CRET");
  other.clipboard.text = "something the user copied elsewhere";
  other.clock.advance(30_000);
  await settle();
  assert.deepEqual(other.clipboard.writes, ["S3CRET"], "someone else's text is left alone");
  assert.equal(other.helper.pending(), false);
});

test("the_page_never_asks_to_read_the_clipboard", async () => {
  for (const granted of ["prompt", "denied", null]) {
    const { clipboard, clock, helper } = rig({ granted });
    await helper.copy("S3CRET");
    clock.advance(30_000);
    await settle();
    assert.equal(clipboard.reads, 0, `permission ${granted}`);
    assert.deepEqual(clipboard.writes, ["S3CRET", ""], "cleared by our own bookkeeping");
  }
  // A browser that does not know the permission name is the same as no permission.
  const clipboard = fakeClipboard();
  const clock = fakeClock();
  state = fakeFocus();
  const helper = createSecretClipboard({
    clipboard, doc: state.doc, win: state.win, setTimer: clock.setTimeout, clearTimer: clock.clearTimeout,
    permissions: { query: async () => { throw new TypeError("unknown permission"); } },
  });
  await helper.copy("S3CRET");
  clock.advance(30_000);
  await settle();
  assert.equal(clipboard.reads, 0);
  assert.deepEqual(clipboard.writes, ["S3CRET", ""]);
});

test("a_tab_without_focus_is_cleared_when_it_gets_focus_back", async () => {
  const { clipboard, clock, helper, focus } = rig({ focused: true });
  await helper.copy("S3CRET");
  focus.focused = false;
  clock.advance(30_000);
  await settle();
  assert.deepEqual(clipboard.writes, ["S3CRET"], "no attempt while the tab has no focus");
  assert.equal(helper.pending(), true);
  assert.equal(focus.listening, 1);
  focus.focus();
  await settle();
  assert.deepEqual(clipboard.writes, ["S3CRET", ""]);
  assert.equal(helper.pending(), false);
  assert.equal(focus.listening, 0);
});

test("a_write_the_browser_refuses_is_tried_once_more_when_the_tab_has_focus_and_then_given_up", async () => {
  const first = rig();
  await first.helper.copy("S3CRET");
  first.clipboard.refuse = 1;
  first.clock.advance(30_000);
  await settle();
  assert.deepEqual(first.clipboard.writes, ["S3CRET"]);
  assert.equal(first.focus.listening, 1, "it waits for the focus");
  first.focus.focus();
  await settle();
  assert.deepEqual(first.clipboard.writes, ["S3CRET", ""]);

  const second = rig();
  await second.helper.copy("S3CRET");
  second.clipboard.refuse = 5;
  second.clock.advance(30_000);
  await settle();
  second.focus.focus(); // the one retry, refused again
  await settle();
  assert.equal(second.helper.pending(), false, "it gave up");
  assert.equal(second.focus.listening, 0);
  assert.deepEqual(second.clipboard.writes, ["S3CRET"]);
  assert.equal(second.clipboard.refuse, 3, "two tries in all: at the time, then once when the tab had focus");
});

test("a_clear_that_waits_for_the_focus_is_dropped_after_5_minutes", async () => {
  assert.equal(RETRY_WINDOW_MS, 300_000);
  const { clipboard, clock, helper, focus } = rig();
  await helper.copy("S3CRET");
  focus.focused = false;
  clock.advance(30_000);
  await settle();
  assert.equal(focus.listening, 1);
  clock.advance(RETRY_WINDOW_MS - 1);
  await settle();
  assert.equal(helper.pending(), true, "still waiting just before the end");
  clock.advance(1);
  await settle();
  assert.equal(helper.pending(), false);
  assert.equal(focus.listening, 0);
  focus.focus(); // the tab comes back much later: nothing is cleared
  await settle();
  assert.deepEqual(clipboard.writes, ["S3CRET"]);
  assert.equal(clock.pending, 0);
});

test("the_wait_for_the_focus_leaves_no_timer_behind_when_it_ends_by_a_clear", async () => {
  const { clock, helper, focus } = rig();
  await helper.copy("S3CRET");
  focus.focused = false;
  clock.advance(30_000);
  await settle();
  assert.equal(clock.pending, 1, "the end of the wait");
  focus.focus();
  await settle();
  assert.equal(clock.pending, 0);
  assert.equal(helper.pending(), false);
});

test("a_lock_clears_at_once_and_stops_the_timer", async () => {
  const { clipboard, clock, helper } = rig();
  await helper.copy("S3CRET");
  await helper.clearNow();
  assert.deepEqual(clipboard.writes, ["S3CRET", ""]);
  assert.equal(helper.pending(), false);
  assert.equal(clock.pending, 0);
  clock.advance(60_000);
  await settle();
  assert.deepEqual(clipboard.writes, ["S3CRET", ""], "nothing more later");
  await helper.clearNow();
  assert.deepEqual(clipboard.writes, ["S3CRET", ""], "nothing waiting, nothing written");
});

test("a_lock_leaves_alone_text_that_is_no_longer_ours_where_it_can_tell", async () => {
  const { clipboard, helper } = rig({ granted: "granted" });
  await helper.copy("S3CRET");
  clipboard.text = "other";
  await helper.clearNow();
  assert.deepEqual(clipboard.writes, ["S3CRET"]);
});

test("a_lock_does_not_wait_for_the_focus", async () => {
  const { clipboard, helper, focus } = rig({ focused: false });
  await helper.copy("S3CRET");
  await helper.clearNow();
  assert.equal(focus.listening, 0);
  assert.equal(helper.pending(), false);
  assert.ok(clipboard.writes.length >= 1);
});

test("the_session_lock_and_sign_out_clear_the_clipboard_once_per_session", async () => {
  const clipboard = fakeClipboard();
  const helper = secretClipboardFor(clipboard);
  const listeners = [];
  const session = { onLock: (fn) => void listeners.push(fn) };
  clearOnLock(session, clipboard);
  clearOnLock(session, clipboard);
  assert.equal(listeners.length, 1);
  await helper.copy("S3CRET");
  listeners[0]();
  await settle();
  assert.deepEqual(clipboard.writes, ["S3CRET", ""]);
  clearOnLock({}, clipboard); // a stand-in without a lock event is no error
});

test("a_refused_copy_is_the_clipboard_error_and_the_older_secret_keeps_its_timer", async () => {
  const { clipboard, clock, helper } = rig({ clipboard: fakeClipboard({ readable: false }) });
  await helper.copy("A");
  clipboard.refuse = 1;
  await assert.rejects(helper.copy("B"), (error) => error.code === "clipboard");
  assert.equal(helper.pending(), true);
  clock.advance(30_000);
  await settle();
  assert.deepEqual(clipboard.writes, ["A", ""]);
  await assert.rejects(createSecretClipboard({ clipboard: null }).copy("x"), (error) => error.code === "clipboard");
  await assert.rejects(secretClipboardFor(null).copy("x"), (error) => error.code === "clipboard");
});

test("one_clipboard_has_one_helper_so_a_secret_from_another_page_is_replaced_not_duplicated", () => {
  const clipboard = fakeClipboard();
  assert.equal(secretClipboardFor(clipboard), secretClipboardFor(clipboard));
  assert.notEqual(secretClipboardFor(clipboard), secretClipboardFor(fakeClipboard()));
});
