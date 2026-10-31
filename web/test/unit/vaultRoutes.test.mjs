// The vault routes and the frame: open or locked, the sync status and the
// banners, and that the routes only use the container's services.
import assert from "node:assert/strict";
import { test } from "node:test";
import { autoLockFor } from "../../src/lock.mjs";
import editRoute from "../../src/routes/edit.route.mjs";
import homeRoute from "../../src/routes/home.route.mjs";
import itemRoute from "../../src/routes/item.route.mjs";
import listRoute from "../../src/routes/list.route.mjs";
import newRoute from "../../src/routes/new.route.mjs";
import unlockRoute from "../../src/routes/unlock.route.mjs";
import { enterVault } from "../../src/views/shell.mjs";
import { all, click, fakeClient, fakeClock, fakeEngine, fakePage, fakeSession, find, settle, t, textOf, withDom } from "./vaultHelpers.mjs";

const ID = "11".repeat(16);
const ENTRY = {
  id: ID, name: "Bank", type: "login", favorite: false, urls: [], username: "ada", rev: 1, pending: false, damaged: false,
  quarantined: false, missingOnServer: false, blocked: false, blockedReason: null, readOnly: false,
};
const VIEW = { item_type: "login", name: "Bank", fields: [], urls: [], has_notes: false, favorite: false, read_only: false };

const enterVaultFor = (r) => enterVault(r.ctx("/items"));

/** A page context over fakes. `engineNow` is what `sync.current()` answers. */
function rig({ open = true, engineNow = "engine", startFails = false, info } = {}) {
  const engine = fakeEngine({ items: [ENTRY], views: { [ID]: VIEW } });
  const client = fakeClient(engine);
  const session = fakeSession({ client, open, ...(info === undefined ? {} : { info }) });
  const sync = {
    engine,
    started: [],
    current: () => (engineNow === "engine" ? engine : null),
    start: async (scope) => {
      sync.started.push(scope);
      if (startFails) throw new Error("no sync");
      engineNow = "engine";
      return engine;
    },
    stop: () => engine.stop(),
    discard: engine.discard,
    discardMissing: engine.discardMissing,
  };
  const moves = [];
  const ctx = (path, params = {}) => ({
    params, path, i18n: { t, lang: "en", missing: [] }, client, services: { crypto: session, sync }, go: (p) => moves.push(p),
  });
  const done = () => autoLockFor(session, sync).stop(); // the idle timer must not outlive the test
  return { engine, client, session, sync, moves, ctx, done };
}

test("a_locked_vault_shows_the_unlock_screen_for_every_vault_route", async () => {
  await withDom(async () => {
    for (const [route, params] of [[listRoute, {}], [itemRoute, { id: ID }], [editRoute, { id: ID }], [newRoute, {}]]) {
      const r = rig({ open: false });
      try {
        const node = await route.load(r.ctx(route.path, params));
        await settle();
        assert.ok(find(node, "unlock"), route.path);
        assert.equal(find(node, "shell"), null, "no vault frame around a locked vault");
        assert.equal(find(node, "list"), null);
        assert.equal(r.session.attached, null, "the routes do not replace the seam the lock service put on the session");
      } finally {
        r.done();
      }
    }
  });
});

test("an_open_vault_shows_the_list_in_the_frame", async () => {
  await withDom(async () => {
    const r = rig();
    try {
      const node = await listRoute.load(r.ctx("/items"));
      assert.ok(find(node, "shell"));
      assert.ok(find(node, "list"));
      assert.ok(find(node, "lock"));
      assert.ok(textOf(node).includes("Bank"));
      assert.equal(autoLockFor(r.session, r.sync).running(), true, "the idle lock runs while the vault is open");
    } finally {
      r.done();
    }
  });
});

test("the_sync_engine_is_started_when_the_session_is_open_and_none_runs", async () => {
  await withDom(async () => {
    const r = rig({ engineNow: "none" });
    try {
      const node = await listRoute.load(r.ctx("/items"));
      assert.deepEqual(r.sync.started, [{ accountId: "aa".repeat(16), vaultId: "bb".repeat(16), vkEpoch: 1 }]);
      assert.ok(find(node, "shell"));
    } finally {
      r.done();
    }
  });
  await withDom(async () => {
    const r = rig({ engineNow: "none", startFails: true });
    try {
      const node = await listRoute.load(r.ctx("/items"));
      assert.ok(find(node, "sync-unavailable"), "an open vault that cannot sync says so and can be locked");
      assert.equal(find(node, "shell"), null);
      await click(find(node, "lock"));
      assert.equal(r.session.locked, 1);
    } finally {
      r.done();
    }
  });
});

test("item_edit_and_new_routes_build_their_screens_inside_the_frame", async () => {
  await withDom(async () => {
    const r = rig();
    try {
      const item = await itemRoute.load(r.ctx("/items/x", { id: ID }));
      assert.ok(find(item, "shell") && find(item, "item"));
      const edit = await editRoute.load(r.ctx("/items/x/edit", { id: ID }));
      assert.ok(find(edit, "shell") && find(edit, "edit-form"));
      assert.equal(find(edit, "name").value, "Bank");
      const fresh = await newRoute.load(r.ctx("/items/new"));
      assert.ok(find(fresh, "shell") && find(fresh, "edit-form"));
      assert.ok(find(fresh, "type"), "a new item picks its type");
      const bad = await itemRoute.load(r.ctx("/items/x", { id: "not-an-id" }));
      assert.ok(find(bad, "message"));
      assert.equal(find(bad, "item"), null);
    } finally {
      r.done();
    }
  });
});

test("the_unlock_route_opens_the_items_when_the_vault_is_already_open", async () => {
  await withDom(async () => {
    const open = rig();
    try {
      await unlockRoute.load(open.ctx("/unlock"));
      assert.deepEqual(open.moves, ["/items"]);
    } finally {
      open.done();
    }
    const closed = rig({ open: false });
    try {
      const node = await unlockRoute.load(closed.ctx("/unlock"));
      await settle();
      assert.deepEqual(closed.moves, []);
      assert.ok(find(node, "unlock-form"));
    } finally {
      closed.done();
    }
  });
});

test("the_start_page_goes_to_the_items_for_an_open_vault_and_offers_a_link_otherwise", async () => {
  await withDom(async () => {
    const open = rig();
    const node = homeRoute.load(open.ctx("/"));
    assert.deepEqual(open.moves, ["/items"]);
    assert.ok(node);
    const closed = rig({ open: false });
    homeRoute.load(closed.ctx("/"));
    assert.deepEqual(closed.moves, []);
    // Before the account services exist at all (nothing signed in), the page still shows.
    const bare = homeRoute.load({ i18n: { t }, services: {}, go() {} });
    assert.ok(textOf(bare).includes("home.open"));
  });
});

test("the_frame_shows_the_sync_state_and_banners_for_warnings_and_refused_changes", async () => {
  await withDom(async () => {
    const r = rig();
    try {
      const node = await listRoute.load(r.ctx("/items"));
      const status = find(node, "sync-status");
      assert.ok(textOf(status).includes("sync.state.syncing"));
      r.engine.emit("state", { kind: "offline" });
      assert.ok(textOf(status).includes("sync.state.offline"));
      r.engine.emit("state", { kind: "idle", at: 1 });
      assert.ok(textOf(status).includes("sync.state.idle"));
      r.engine.emit("state", { kind: "unauthorized" });
      assert.ok(textOf(find(node, "banners")).includes("vault.banner.sign_in_again"));

      r.engine.emit("state", { kind: "warning", code: "server_behind" });
      r.engine.emit("state", { kind: "warning", code: "server_behind" });
      const warnings = all(node, "banner").filter((b) => b.getAttribute("data-banner") === "warning:server_behind");
      assert.equal(warnings.length, 1, "the same warning is shown once");
      assert.ok(textOf(warnings[0]).includes("sync.warning.server_behind"));

      r.engine.emit("error", { code: "conflict", id: ID });
      const errors = all(node, "banner").filter((b) => b.getAttribute("data-banner").startsWith("error:"));
      assert.equal(errors.length, 1);
      assert.equal(errors[0].getAttribute("role"), "alert");
      assert.ok(textOf(errors[0]).includes("Bank") && textOf(errors[0]).includes("sync.error.conflict"));

      await click(find(warnings[0], "banner-dismiss"));
      assert.equal(all(node, "banner").filter((b) => b.getAttribute("data-banner") === "warning:server_behind").length, 0);

      // Text that is not a known state or a plain code is not shown as a key.
      r.engine.emit("state", { kind: "warning", code: "../../x" });
      r.engine.emit("state", { kind: "weird" });
      assert.ok(!textOf(node).includes("weird"));
    } finally {
      r.done();
    }
  });
});

test("clicks_and_keys_in_the_frame_move_the_idle_time_on", async () => {
  await withDom(async () => {
    const r = rig();
    try {
      const node = await listRoute.load(r.ctx("/items"));
      const lock = autoLockFor(r.session, r.sync);
      const before = lock.lockAt();
      await new Promise((resolve) => setTimeout(resolve, 5));
      const [, press] = node.listeners.find(([kind]) => kind === "keydown");
      press({});
      assert.ok(lock.lockAt() > before);
    } finally {
      r.done();
    }
  });
});

test("an_error_with_a_code_the_screens_do_not_know_shows_the_general_message", async () => {
  await withDom(async () => {
    const r = rig();
    try {
      const node = await listRoute.load(r.ctx("/items"));
      r.engine.emit("error", { code: "something_new" });
      assert.ok(textOf(find(node, "banners")).includes("vault.error.unknown"));
    } finally {
      r.done();
    }
  });
});

test("the_idle_lock_runs_even_when_the_sync_engine_cannot_start", async () => {
  await withDom(async () => {
    const r = rig({ engineNow: "none", startFails: true });
    const clock = fakeClock();
    // The idle lock of the session, with a clock the test moves.
    const lock = autoLockFor(r.session, r.sync, { now: clock.now, timers: clock, doc: fakePage(), idleMs: 60_000 });
    try {
      const node = await listRoute.load(r.ctx("/items"));
      assert.ok(find(node, "sync-unavailable"), "the page says syncing is down");
      assert.equal(lock.running(), true, "the vault is open, so the idle lock is armed");
      clock.advance(59_999);
      assert.equal(r.session.locked, 0);
      clock.advance(1);
      await settle();
      assert.equal(r.session.locked, 1, "the idle time ended the session");
      assert.equal(find(node, "lock"), null, "the notice is replaced");
      assert.ok(find(node, "unlock-host"), "by the unlock screen");
    } finally {
      lock.stop();
    }
  });
});

test("a_frame_built_after_the_vault_locked_is_the_unlock_screen", async () => {
  await withDom(async () => {
    const r = rig();
    try {
      // The route is loading when the lock lands; its page is built after the session has locked.
      const vault = await enterVaultFor(r);
      r.session.isOpen = false;
      const node = vault.page(document.createElement("section"));
      assert.equal(find(node, "shell"), null, "no frame with a Lock button");
      assert.ok(find(node, "unlock-host"));
      await settle(); // the unlock screen fills itself in
    } finally {
      r.done();
    }
  });
});
