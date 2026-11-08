// The live field in the top bar, and the texts it shows.
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { test } from "node:test";
import { createWipeScope } from "../../src/views/common.mjs";
import { shellView } from "../../src/views/shell.mjs";
import { web } from "./helpers.mjs";
import { fakeEngine, find, textOf, withDom } from "./vaultHelpers.mjs";

const catalog = (lang) => JSON.parse(readFileSync(join(web, "src", "locales", lang, "live.json"), "utf8"));
const en = catalog("en");
/** The text of a key as the English catalog has it; a key it lacks shows as itself. */
const fromCatalog = (key) => en[key] ?? key;

/** A live source the test moves by hand. */
function fakeLive(state = "connecting") {
  const listeners = new Set();
  const live = {
    current: state,
    state: () => live.current,
    on(event, fn) {
      assert.equal(event, "state");
      listeners.add(fn);
      return () => void listeners.delete(fn);
    },
    set(next) {
      live.current = next;
      for (const fn of [...listeners]) fn(next);
    },
    get listening() {
      return listeners.size;
    },
  };
  return live;
}

function frame(live, t = fromCatalog) {
  const engine = fakeEngine();
  const root = shellView({
    t: (key, vars) => (key.startsWith("live.") ? t(key, vars) : key),
    engine,
    session: { onLock() {} },
    content: globalThis.document.createElement("div"),
    lock: async () => {},
    touch: () => true,
    scope: createWipeScope(),
    onLocked: () => globalThis.document.createElement("div"),
    win: undefined,
    live,
  });
  return { root, engine, field: () => find(root, "live-status") };
}

test("status_field_shows_live_fallback_and_offline_from_the_catalog", async () => {
  await withDom(async () => {
    const live = fakeLive("connecting");
    const { root, field } = frame(live);
    assert.equal(textOf(field()).trim(), en["live.state.connecting"], "the state at the start");
    assert.equal(field().getAttribute("data-state"), "connecting");
    assert.equal(field().getAttribute("role"), "status", "a screen reader hears the change");

    live.set("live");
    assert.equal(textOf(field()).trim(), "Live");
    assert.equal(field().getAttribute("data-state"), "live");

    live.set("fallback");
    assert.equal(textOf(field()).trim(), "Checking every 5 minutes");
    assert.equal(field().getAttribute("data-state"), "fallback");

    live.set("offline");
    assert.equal(textOf(field()).trim(), en["live.state.offline"]);
    assert.equal(field().getAttribute("data-state"), "offline");

    live.set("unauthorized");
    assert.equal(textOf(field()).trim(), en["live.state.unauthorized"]);

    // A state the frame has no text for is shown as off, never as a bare key or as markup.
    live.set("<b>live</b>");
    assert.equal(textOf(field()).trim(), en["live.state.offline"]);
    assert.equal(field().getAttribute("data-state"), "offline");

    // The sync state beside it is its own field and is not touched.
    assert.ok(find(root, "sync-status"));
    assert.notEqual(find(root, "sync-status"), field());
  });
});

test("the_frame_starts_from_the_state_the_channel_is_in", async () => {
  await withDom(async () => {
    const { field } = frame(fakeLive("fallback"));
    assert.equal(textOf(field()).trim(), en["live.state.fallback"]);
    assert.equal(field().getAttribute("data-state"), "fallback");
  });
});

test("a_frame_without_the_channel_has_no_live_field", async () => {
  await withDom(async () => {
    const { field } = frame(undefined);
    assert.equal(field(), null);
  });
});

test("a_frame_that_has_left_the_page_stops_listening", async () => {
  await withDom(async () => {
    const live = fakeLive("live");
    const { root } = frame(live);
    assert.equal(live.listening, 1);
    root.isConnected = true;
    live.set("fallback");
    root.isConnected = false;
    live.set("offline");
    assert.equal(live.listening, 0, "the next event after it left removes the listener");
  });
});

test("live_texts_exist_in_both_languages", () => {
  const nb = catalog("nb");
  assert.deepEqual(Object.keys(en), Object.keys(nb));
  const states = ["connecting", "live", "fallback", "offline", "unauthorized"];
  assert.deepEqual(Object.keys(en).sort(), states.map((state) => `live.state.${state}`).sort());
  const names = (s) => [...s.matchAll(/\{([A-Za-z0-9_]+)\}/g)].map((m) => m[1]).sort();
  for (const [key, value] of Object.entries(en)) {
    assert.ok(key.startsWith("live."), key);
    assert.ok(typeof value === "string" && value.length > 0, key);
    assert.ok(typeof nb[key] === "string" && nb[key].length > 0, key);
    assert.deepEqual(names(nb[key]), names(value), key);
  }
  assert.equal(nb["live.state.live"], "Direkte");
  assert.equal(nb["live.state.fallback"], "Henter hvert 5. minutt");

  // The frame knows exactly these states.
  const source = readFileSync(join(web, "src", "views", "shell.mjs"), "utf8");
  const listed = /const LIVE_STATES = Object\.freeze\(\[([^\]]*)\]\)/.exec(source)?.[1] ?? "";
  assert.deepEqual([...listed.matchAll(/"([a-z]+)"/g)].map((m) => m[1]), states);
});
