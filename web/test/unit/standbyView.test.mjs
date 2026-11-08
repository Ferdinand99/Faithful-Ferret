// The notice of a tab that is not the one that holds the vault, and how the vault routes and the frame
// use it: a tab that starts on standby, a tab that is put on standby while it shows the vault.
import assert from "node:assert/strict";
import { test } from "node:test";
import { autoLockFor } from "../../src/lock.mjs";
import listRoute from "../../src/routes/list.route.mjs";
import { standbyView } from "../../src/views/standby.mjs";
import { enterVault } from "../../src/views/shell.mjs";
import { EN, NB, textFor, translator, withFocus } from "./syncWarningsHelpers.mjs";
import { click, fakeClient, fakeEngine, fakeSession, find, settle, t, textOf, walk, withDom } from "./vaultHelpers.mjs";

const ID = "11".repeat(16);
const ENTRY = {
  id: ID, name: "Bank", type: "login", favorite: false, urls: [], username: "ada", rev: 1, pending: false, damaged: false,
  quarantined: false, missingOnServer: false, blocked: false, blockedReason: null, readOnly: false,
};

/**
 * A page over fakes whose sync service can be on standby. `takeOver` is what the button calls; the tests make it wait or fail.
 * @param {{ standby?: boolean, engineNow?: boolean }} [options]
 */
function rig({ standby = false, engineNow = !standby } = {}) {
  const engine = fakeEngine({ items: [ENTRY], views: { [ID]: { item_type: "login", name: "Bank", fields: [], urls: [], has_notes: false, favorite: false, read_only: false } } });
  const client = fakeClient(engine);
  const session = fakeSession({ client });
  const listeners = new Set();
  const sync = {
    engine,
    isStandby: standby,
    running: engineNow,
    started: [],
    takeOvers: 0,
    takeOverResult: null, // a promise to wait for, or an error to throw
    current: () => (sync.running ? engine : null),
    standby: () => sync.isStandby,
    onStandby(fn) {
      listeners.add(fn);
      return () => void listeners.delete(fn);
    },
    tell(on) {
      sync.isStandby = on;
      if (on) sync.running = false;
      for (const fn of [...listeners]) fn(on);
    },
    get listening() {
      return listeners.size;
    },
    async start(scope) {
      sync.started.push(scope);
      if (sync.isStandby) return null;
      sync.running = true;
      return engine;
    },
    async takeOver() {
      sync.takeOvers += 1;
      if (sync.takeOverResult instanceof Error) throw sync.takeOverResult;
      await sync.takeOverResult;
      sync.isStandby = false;
      sync.running = true;
      return engine;
    },
    stop: () => engine.stop(),
    discard: engine.discard,
    discardMissing: engine.discardMissing,
  };
  const moves = [];
  const ctx = (path, lang = "en") => ({
    params: {}, path, i18n: { t: lang === "en" ? t : translator(lang), lang, missing: [] }, client, services: { crypto: session, sync }, go: (p) => moves.push(p),
  });
  const done = () => autoLockFor(session, sync).stop();
  return { engine, client, session, sync, moves, ctx, done };
}

test("a_second_tab_does_not_start_an_engine_and_shows_the_notice", async () => {
  await withDom(async () => {
    const r = rig({ standby: true });
    try {
      const node = await listRoute.load(r.ctx("/items"));
      assert.ok(find(node, "standby"), "the notice takes the whole page");
      assert.equal(find(node, "shell"), null, "no vault frame");
      assert.equal(find(node, "list"), null, "no list");
      assert.equal(find(node, "unlock"), null);
      assert.equal(r.sync.started.length, 0, "the engine is not asked to start on a tab that is on standby");
      assert.ok(!textOf(node).includes("Bank"), "no vault data is shown in the tab");
      assert.ok(find(node, "use-here"), "with a button to use the vault here");
      assert.ok(textOf(node).includes("standby.title"));
    } finally {
      r.done();
    }
  });
});

test("a_start_that_ends_on_standby_shows_the_notice_too", async () => {
  await withDom(async () => {
    const r = rig({ standby: false, engineNow: false });
    r.sync.isStandby = false;
    const start = r.sync.start;
    r.sync.start = async (scope) => {
      r.sync.isStandby = true; // another tab turned out to hold the lock
      return start(scope);
    };
    try {
      const node = await listRoute.load(r.ctx("/items"));
      assert.deepEqual(r.sync.started.length, 1, "a start was tried");
      assert.ok(find(node, "standby"));
      assert.equal(find(node, "shell"), null);
    } finally {
      r.done();
    }
  });
});

test("the_notice_says_the_vault_is_open_in_another_tab_with_a_use_here_button_in_both_languages", async () => {
  await withDom(async () => {
    for (const [lang, catalog, title, button] of [
      ["en", EN, "The vault is open in another tab", "Use here"],
      ["nb", NB, "Hvelvet er åpent i en annen fane", "Bruk her"],
    ]) {
      const view = standbyView({ t: translator(lang), sync: { takeOver: async () => {}, standby: () => true }, onTaken() {}, lock: async () => {} });
      assert.equal(textFor(catalog, "standby.title"), title);
      assert.ok([...walk(view.root)].some((n) => String(n.tagName).toLowerCase() === "h1"), "a heading");
      assert.ok(textOf(view.root).includes(title), lang);
      assert.ok(textOf(find(view.root, "use-here")).includes(button), lang);
      assert.equal(find(view.root, "use-here").getAttribute("type"), "button");
      assert.equal(view.root.getAttribute("aria-labelledby"), "standby-title", "named by its heading for a screen reader");
    }
  });
});

test("use_here_asks_for_the_vault_once_shows_progress_and_then_shows_the_screen_again", async () => {
  await withDom(async () => {
    const r = rig({ standby: true });
    try {
      let release;
      r.sync.takeOverResult = new Promise((resolve) => { release = resolve; });
      const node = await listRoute.load(r.ctx("/items"));
      const button = find(node, "use-here");
      const first = click(button);
      await settle(2);
      assert.equal(r.sync.takeOvers, 1);
      assert.equal(button.getAttribute("aria-busy"), "true");
      assert.equal(button.getAttribute("aria-disabled"), "true");
      assert.ok(textOf(find(node, "status")).includes("standby.working"), "the wait is told");
      await click(button);
      assert.equal(r.sync.takeOvers, 1, "a second press while it works does nothing");
      release();
      await first;
      assert.equal(button.getAttribute("aria-busy"), "false");
      assert.deepEqual(r.moves, ["/items"], "the screen is built again, now with the engine");
    } finally {
      r.done();
    }
  });
});

test("when_use_here_fails_the_notice_says_so_and_the_button_keeps_focus", async () => {
  await withDom(async () => {
    await withFocus(async () => {
      const r = rig({ standby: true });
      try {
        r.sync.takeOverResult = Object.assign(new Error("the lock could not be taken"), { code: "owner_unavailable" });
        const node = await listRoute.load(r.ctx("/items"));
        await click(find(node, "use-here"));
        assert.ok(textOf(find(node, "error")).includes("standby.error"));
        assert.equal(find(node, "error").getAttribute("role"), "alert");
        assert.equal(globalThis.document.activeElement, find(node, "use-here"), "focus is on the button, for another try");
        assert.deepEqual(r.moves, []);
        assert.equal(find(node, "use-here").getAttribute("aria-busy"), "false");
        // The next press asks again, and clears the old error.
        r.sync.takeOverResult = null;
        await click(find(node, "use-here"));
        assert.equal(textOf(find(node, "error")).trim(), "");
        assert.deepEqual(r.moves, ["/items"]);
      } finally {
        r.done();
      }
    });
  });
});

test("a_use_here_that_leaves_the_tab_off_standby_builds_the_screen_again_to_say_what_is_wrong", async () => {
  await withDom(async () => {
    const r = rig({ standby: true });
    try {
      r.sync.takeOver = async () => {
        r.sync.isStandby = false; // the lock was taken, but the engine could not start
        throw new Error("storage");
      };
      const node = await listRoute.load(r.ctx("/items"));
      await click(find(node, "use-here"));
      assert.deepEqual(r.moves, ["/items"]);
    } finally {
      r.done();
    }
  });
});

test("the_notice_can_lock_the_vault_and_the_lock_wipes_it", async () => {
  await withDom(async () => {
    const r = rig({ standby: true });
    try {
      const node = await listRoute.load(r.ctx("/items"));
      await click(find(node, "lock"));
      await settle();
      assert.equal(r.session.locked, 1);
      assert.ok(find(node, "unlock"), "the lock puts the unlock screen where the notice was");
      assert.equal(find(node, "use-here"), null);
    } finally {
      r.done();
    }
  });
});

test("a_tab_that_shows_the_vault_shows_the_notice_when_another_tab_takes_it", async () => {
  await withDom(async () => {
    await withFocus(async () => {
      const r = rig();
      try {
        const node = await listRoute.load(r.ctx("/items"));
        assert.ok(find(node, "list"));
        assert.ok(textOf(node).includes("Bank"));
        assert.equal(r.sync.listening, 1, "the frame listens for standby");
        r.sync.tell(true);
        assert.ok(find(node, "standby"), "the notice takes the frame");
        assert.equal(find(node, "list"), null, "the list is gone from the page");
        assert.ok(!textOf(node).includes("Bank"), "and what it showed with it");
        assert.equal(globalThis.document.activeElement, find(node, "use-here"), "focus is where the next step is");
        // And the lock still reaches this tab: it puts the unlock screen there.
        await r.session.lock();
        await settle();
        assert.ok(find(node, "unlock"));
      } finally {
        r.done();
      }
    });
  });
});

test("a_frame_that_has_left_the_page_stops_listening_for_standby", async () => {
  await withDom(async () => {
    const r = rig();
    try {
      const node = await listRoute.load(r.ctx("/items"));
      const shell = find(node, "shell");
      shell.isConnected = true;
      r.sync.tell(false); // an event while the frame is on the page
      shell.isConnected = false;
      r.sync.tell(false);
      assert.equal(r.sync.listening, 0, "the listener is removed by the first event after the frame has left");
      assert.ok(find(node, "list"), "and the old frame is left alone");
    } finally {
      r.done();
    }
  });
});

test("a_notice_press_counts_as_activity_and_a_locked_vault_does_not_ask", async () => {
  await withDom(async () => {
    const calls = [];
    const view = standbyView({ t, sync: { takeOver: async () => void calls.push("takeOver"), standby: () => true }, onTaken() {}, lock: async () => {}, touch: () => false });
    await click(find(view.root, "use-here"));
    assert.deepEqual(calls, [], "the vault locked just now: nothing is asked");
  });
});

test("enter_vault_does_not_use_a_standby_notice_of_a_sync_that_has_none", async () => {
  await withDom(async () => {
    const r = rig();
    delete r.sync.standby;
    delete r.sync.onStandby;
    try {
      const out = await enterVault(r.ctx("/items"));
      assert.ok(out.engine, "an old-style sync is used as before");
      assert.equal(out.locked, undefined);
    } finally {
      r.done();
    }
  });
});
