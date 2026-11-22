// The keyboard shortcut (src/background/commands.mjs): one match fills, none or
// several open the popup, a locked vault opens the popup at once, and the
// action reaches the vault only through the fill flow's two operations.
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { test } from "node:test";
import { FILL_COMMAND, createQuickFill, listenForCommands } from "../../src/background/commands.mjs";
import { extensionRoot } from "./buildHelpers.mjs";
import { addLoginForm } from "./fakeDom.mjs";
import { ITEM, createWorld, valueOf } from "./quickFillWorld.mjs";

/** @param {ReturnType<typeof createWorld>} world */
const quickFillOf = (world) => createQuickFill({
  coreHost: world.coreHost,
  lock: world.lock,
  sessions: world.sessions,
  openPopup: world.openPopup,
  scripting: world.scripting,
  webNavigation: world.webNavigation,
});

/** Registers the shortcut on a fake `commands` and returns a way to press it. @param {ReturnType<typeof createQuickFill>} quickFill */
function pressable(quickFill) {
  /** @type {Array<(name: string, tab?: { id?: number }) => void>} */
  const listeners = [];
  /** @type {Promise<unknown>[]} */
  const runs = [];
  const spy = { ...quickFill, fillOrOpen: (/** @type {unknown} */ tabId) => { const run = quickFill.fillOrOpen(tabId); runs.push(run); return run; } };
  listenForCommands({ commands: { onCommand: { addListener: (fn) => listeners.push(fn) } }, quickFill: spy });
  assert.equal(listeners.length, 1, "one listener, registered at once");
  return {
    /** @param {string} name @param {{ id?: number } | undefined} tab */
    press: async (name, tab) => {
      runs.length = 0;
      listeners[0](name, tab);
      await Promise.all(runs);
      return runs.length;
    },
  };
}

test("the_command_fills_one_candidate_and_opens_the_popup_for_zero_or_several", async () => {
  // One match in the top frame: it is filled, and no popup opens.
  let world = createWorld({ build: addLoginForm, offer: [{ frameId: 0 }] });
  let shortcut = pressable(quickFillOf(world));
  assert.equal(await shortcut.press(FILL_COMMAND, { id: 7 }), 1);
  assert.equal(valueOf(world.user), ITEM.username);
  assert.equal(valueOf(world.pass), ITEM.password);
  assert.equal(world.popups.count, 0);
  assert.deepEqual(world.ops(), ["fill_offer", "fill"]);
  const [offer, fill] = world.log;
  assert.equal(offer.args.tab_id, 7);
  assert.match(offer.args.session, /^[0-9a-f]{32}$/);
  assert.equal(fill.args.session, offer.args.session, "the fill uses the reference of the same action");
  assert.equal(fill.args.frame_id, 0);
  assert.deepEqual(world.sessionsEnded, [offer.args.session], "the action's references end with it");
  assert.deepEqual(world.lockCalls, { checks: ["fill"], touches: 1 }, "checked as an action in Ferret's UI, and the deadline moves");
  // A second press is a new action with a new session.
  await shortcut.press(FILL_COMMAND, { id: 7 });
  assert.notEqual(world.log[2].args.session, offer.args.session);

  // A match in a same-site frame counts as well: the fill goes to that frame.
  world = createWorld({ build: addLoginForm, offer: [{ frameId: 4 }] });
  await pressable(quickFillOf(world)).press(FILL_COMMAND, { id: 7 });
  assert.equal(world.log[1].args.frame_id, 4);
  assert.equal(world.popups.count, 0);

  // No match: the popup, and nothing put into the page.
  world = createWorld({ build: addLoginForm, offer: [] });
  await pressable(quickFillOf(world)).press(FILL_COMMAND, { id: 7 });
  assert.equal(world.popups.count, 1);
  assert.deepEqual(world.ops(), ["fill_offer"]);
  assert.equal(world.injections.length, 0);
  assert.equal(world.sessionsEnded.length, 1);

  // Several matches, in one frame or in two: the popup lets the user choose.
  for (const offer of [[{ frameId: 0, items: 2 }], [{ frameId: 0 }, { frameId: 4 }]]) {
    world = createWorld({ build: addLoginForm, offer });
    await pressable(quickFillOf(world)).press(FILL_COMMAND, { id: 7 });
    assert.equal(world.popups.count, 1, JSON.stringify(offer));
    assert.deepEqual(world.ops(), ["fill_offer"]);
    assert.equal(valueOf(world.pass), "");
  }

  // One match for an http item: that needs the warning and one more click, so the popup opens.
  world = createWorld({ build: addLoginForm, offer: [{ frameId: 0, insecure: true }] });
  await pressable(quickFillOf(world)).press(FILL_COMMAND, { id: 7 });
  assert.equal(world.popups.count, 1);
  assert.deepEqual(world.ops(), ["fill_offer"]);
  assert.equal(valueOf(world.pass), "");

  // A locked vault: the popup opens in the turn of the shortcut (the user's action still counts), and the vault is
  // not asked.
  world = createWorld({ build: addLoginForm, offer: [{ frameId: 0 }], state: "locked" });
  const quick = quickFillOf(world);
  const pending = quick.fillOrOpen(7);
  assert.equal(world.popups.count, 1, "opened before anything was awaited");
  assert.equal(await pending, "popup");
  assert.deepEqual(world.ops(), []);
  assert.deepEqual(world.lockCalls, { checks: [], touches: 0 });

  // A deadline that has passed (the lock check locks and says no): the popup, no page matching.
  world = createWorld({ build: addLoginForm, offer: [{ frameId: 0 }], allowed: false });
  await pressable(quickFillOf(world)).press(FILL_COMMAND, { id: 7 });
  assert.equal(world.popups.count, 1);
  assert.deepEqual(world.ops(), []);
  assert.equal(world.lockCalls.touches, 0);

  // The page matching fails (no running sync, a lock on the way): the popup says why.
  world = createWorld({ build: addLoginForm, offer: [{ frameId: 0 }] });
  world.coreHost.call = async (op) => {
    world.log.push({ op, args: null });
    throw Object.assign(new Error("sync_not_running"), { code: "sync_not_running" });
  };
  await pressable(quickFillOf(world)).press(FILL_COMMAND, { id: 7 });
  assert.equal(world.popups.count, 1);
  assert.equal(world.sessionsEnded.length, 1);
});

test("the_shortcut_ignores_other_commands_bad_tabs_and_a_second_press_while_the_first_runs", async () => {
  const world = createWorld({ build: addLoginForm, offer: [{ frameId: 0 }] });
  const quick = quickFillOf(world);
  const shortcut = pressable(quick);
  assert.equal(await shortcut.press("ferret-test-command", { id: 7 }), 0, "another command is not this one");
  for (const tab of [undefined, {}, { id: -1 }, { id: 1.5 }, { id: "7" }]) {
    assert.equal(await quick.fillOrOpen(/** @type {any} */ (tab)?.id), "refused");
  }
  assert.deepEqual(world.ops(), []);
  assert.equal(world.popups.count, 0);

  const first = quick.fillOrOpen(7);
  assert.equal(await quick.fillOrOpen(7), "busy");
  assert.equal(await first, "filled");
  assert.deepEqual(world.ops(), ["fill_offer", "fill"]);
  // Once it is done, the next press runs.
  assert.equal(await quick.fillOrOpen(7), "filled");
});

test("a_popup_that_cannot_open_is_no_error_of_the_shortcut", async () => {
  const world = createWorld({ build: addLoginForm, offer: [] });
  const quick = createQuickFill({
    coreHost: world.coreHost,
    lock: world.lock,
    openPopup: () => Promise.reject(new Error("openPopup requires a user gesture")),
    scripting: world.scripting,
    webNavigation: world.webNavigation,
  });
  assert.equal(await quick.fillOrOpen(7), "popup");
  const throwing = createQuickFill({
    coreHost: world.coreHost,
    lock: world.lock,
    openPopup: () => {
      throw new Error("no action");
    },
    scripting: world.scripting,
    webNavigation: world.webNavigation,
  });
  assert.equal(await throwing.fillOrOpen(7), "popup");
});

test("the_shortcut_module_reaches_the_vault_only_through_the_fill_operations_and_reads_no_name", () => {
  const source = readFileSync(join(extensionRoot, "src", "background", "commands.mjs"), "utf8");
  const code = source.replace(/^\s*(?:\/\/|\*|\/\*\*).*$/gm, "");
  // The only core operations it calls.
  assert.deepEqual([...code.matchAll(/\.call\("([a-z_]+)"/g)].map((m) => m[1]).sort(), ["fill", "fill_offer"]);
  // It imports only the injection of the fill script: no core host, no client, no shared crypto.
  assert.deepEqual([...code.matchAll(/from "([^"]+)"/g)].map((m) => m[1]), ["./inject.mjs"]);
  // A handle's name and user name are never read.
  assert.doesNotMatch(code, /\.name\b|\.username\b/);
});
