// A screen's listener for an engine event: it answers while the screen is on the page, drops out once a screen that was shown is
// gone, never answers a node that is known to be off the page, and is not lost by a screen that is built but not yet on the page.
import assert from "node:assert/strict";
import { test } from "node:test";
import { listenWhileShown } from "../../src/views/common.mjs";

/** An engine with one event and a count of its listeners. */
function engine() {
  const listeners = new Set();
  return {
    listeners,
    on: (_event, fn) => {
      listeners.add(fn);
      return () => void listeners.delete(fn);
    },
    emit: (payload) => {
      for (const fn of [...listeners]) fn(payload);
    },
  };
}

test("a_screen_that_is_built_but_not_yet_on_the_page_answers_once_it_is", () => {
  const e = engine();
  const root = { isConnected: false };
  const heard = [];
  listenWhileShown(root, e, "state", (payload) => heard.push(payload));
  // An event in the steps between the end of `load` and the mount: not answered by a detached node, but the listener is kept.
  e.emit("early");
  assert.deepEqual(heard, []);
  assert.equal(e.listeners.size, 1, "the listener of a screen that was never shown is kept");
  root.isConnected = true;
  e.emit("on the page");
  assert.deepEqual(heard, ["on the page"]);
});

test("a_screen_that_was_shown_and_is_gone_is_dropped_at_the_next_event", () => {
  const e = engine();
  const root = { isConnected: true };
  const heard = [];
  listenWhileShown(root, e, "state", (payload) => heard.push(payload));
  e.emit(1);
  root.isConnected = false;
  e.emit(2);
  assert.deepEqual(heard, [1]);
  assert.equal(e.listeners.size, 0);
});

test("a_screen_that_was_never_on_the_page_never_answers", () => {
  const e = engine();
  const root = { isConnected: false };
  const heard = [];
  listenWhileShown(root, e, "state", (payload) => heard.push(payload));
  for (let i = 0; i < 3; i += 1) e.emit(i);
  assert.deepEqual(heard, [], "a replaced screen does not build a second notice");
});

test("a_node_that_reports_nothing_about_the_page_is_answered", () => {
  const e = engine();
  const heard = [];
  listenWhileShown({}, e, "state", (payload) => heard.push(payload));
  e.emit("x");
  assert.deepEqual(heard, ["x"]);
});
