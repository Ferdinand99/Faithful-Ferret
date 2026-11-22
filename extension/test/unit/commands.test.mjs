// The keyboard shortcut (src/background/commands.mjs) over the real page
// matching, frame rules and fill flow: one match fills, none or several open the
// popup, a locked vault opens the popup at once, and the action reaches the
// vault only through the fill flow's two operations.
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { test } from "node:test";
import { FILL_COMMAND, createQuickFill, listenForCommands } from "../../src/background/commands.mjs";
import { extensionRoot } from "./buildHelpers.mjs";
import { addLoginForm } from "./fakeDom.mjs";
import { ITEM, PAGE, TAB, createWorld, valueOf } from "./quickFillWorld.mjs";

/** @param {Awaited<ReturnType<typeof createWorld>>} world */
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
      const outcomes = await Promise.all(runs);
      return outcomes[0];
    },
  };
}

const LOGIN_FRAME = "https://login.example.com/frame";

test("the_command_fills_one_candidate_and_opens_the_popup_for_zero_or_several", async () => {
  // One match in the top frame: it is filled, and no popup opens.
  let world = await createWorld({ frames: [{ frameId: 0, url: PAGE, build: addLoginForm }] });
  const shortcut = pressable(quickFillOf(world));
  assert.equal(await shortcut.press(FILL_COMMAND, { id: TAB }), "filled");
  assert.equal(valueOf(world.user), ITEM.username);
  assert.equal(valueOf(world.pass), ITEM.password);
  assert.equal(world.popups.count, 0);
  assert.deepEqual(world.ops(), ["fill_offer", "fill"]);
  const [offer, fill] = world.log;
  assert.deepEqual(Object.keys(offer.args).sort(), ["session", "tab_id"], "the shortcut asks for every frame");
  assert.equal(offer.args.tab_id, TAB);
  assert.match(offer.args.session, /^[0-9a-f]{32}$/);
  assert.equal(fill.args.session, offer.args.session, "the fill uses the reference of the same action");
  assert.equal("frame_id" in fill.args, false, "the fill flow picks the frame");
  assert.deepEqual(world.sessionsEnded, [offer.args.session], "the action's references end with it");
  assert.equal(world.refSessions(), 0);
  assert.equal(world.openHandles(), 0, "every item handle is closed");
  assert.deepEqual(world.lockCalls, { checks: ["fill"], touches: 1 }, "checked as an action in Ferret's UI, and the deadline moves");
  // A second press is a new action with a new session.
  await shortcut.press(FILL_COMMAND, { id: TAB });
  assert.notEqual(world.log[2].args.session, offer.args.session);

  // A match in a same-site frame only: the fill goes to that frame.
  world = await createWorld({
    frames: [{ frameId: 0, url: PAGE }, { frameId: 5, url: LOGIN_FRAME, build: addLoginForm }],
    items: [{ urls: ["https://login.example.com/"] }],
  });
  assert.equal(await pressable(quickFillOf(world)).press(FILL_COMMAND, { id: TAB }), "filled");
  assert.equal(valueOf(world.frame(5).pass), ITEM.password);
  assert.equal(world.popups.count, 0);

  // One item that matches the top and a frame of the same origin: the first frame (top first) whose script reports
  // sign-in fields gets it. Here the top has no form, so the frame does.
  world = await createWorld({ frames: [{ frameId: 0, url: PAGE }, { frameId: 5, url: "https://example.com/frame", build: addLoginForm }] });
  assert.equal(await pressable(quickFillOf(world)).press(FILL_COMMAND, { id: TAB }), "filled");
  assert.equal(valueOf(world.frame(5).pass), ITEM.password);

  // No match: the popup, and nothing put into the page.
  world = await createWorld({ frames: [{ frameId: 0, url: PAGE, build: addLoginForm }], items: [{ urls: ["https://bank.example.org/"] }] });
  assert.equal(await pressable(quickFillOf(world)).press(FILL_COMMAND, { id: TAB }), "popup");
  assert.deepEqual(world.ops(), ["fill_offer"]);
  assert.equal(world.injections.length, 0);
  assert.equal(world.sessionsEnded.length, 1);
  assert.equal(world.refSessions(), 0);

  // Several matches: the popup lets the user choose.
  world = await createWorld({ frames: [{ frameId: 0, url: PAGE, build: addLoginForm }], items: [{ urls: ["https://example.com/"] }, { urls: ["https://example.com/a"] }] });
  assert.equal(await pressable(quickFillOf(world)).press(FILL_COMMAND, { id: TAB }), "popup");
  assert.deepEqual(world.ops(), ["fill_offer"]);
  assert.equal(valueOf(world.pass), "");

  // One match on a plain http page: that needs the warning and one more click, so the popup opens.
  world = await createWorld({ frames: [{ frameId: 0, url: "http://example.com/login", build: addLoginForm }], items: [{ urls: ["http://example.com/"] }] });
  assert.equal(await pressable(quickFillOf(world)).press(FILL_COMMAND, { id: TAB }), "popup");
  assert.deepEqual(world.ops(), ["fill_offer"]);
  assert.equal(valueOf(world.pass), "");

  // A locked vault: the popup opens in the turn of the shortcut (the user's action still counts), and the vault is
  // not asked.
  world = await createWorld({ frames: [{ frameId: 0, url: PAGE, build: addLoginForm }], state: "locked" });
  const pending = quickFillOf(world).fillOrOpen(TAB);
  assert.equal(world.popups.count, 1, "opened before anything was awaited");
  assert.equal(await pending, "popup");
  assert.deepEqual(world.ops(), []);
  assert.deepEqual(world.lockCalls, { checks: [], touches: 0 });

  // The page matching fails (here the fill flow's offer rejects): the popup, nothing put into the page, and the
  // action's session ends.
  world = await createWorld({ frames: [{ frameId: 0, url: PAGE, build: addLoginForm }] });
  const realCall = world.coreHost.call;
  world.coreHost.call = async (op, args) => {
    if (op === "fill_offer") {
      world.log.push({ op, args });
      throw Object.assign(new Error("sync_not_running"), { code: "sync_not_running" });
    }
    return realCall(op, args);
  };
  assert.equal(await pressable(quickFillOf(world)).press(FILL_COMMAND, { id: TAB }), "popup");
  assert.deepEqual(world.ops(), ["fill_offer"]);
  assert.equal(world.injections.length, 0);
  assert.equal(world.sessionsEnded.length, 1);
  assert.equal(valueOf(world.pass), "");

  // A deadline that has passed (the lock check locks and says no): the popup, no page matching.
  world = await createWorld({ frames: [{ frameId: 0, url: PAGE, build: addLoginForm }], allowed: false });
  assert.equal(await pressable(quickFillOf(world)).press(FILL_COMMAND, { id: TAB }), "popup");
  assert.deepEqual(world.ops(), []);
  assert.equal(world.lockCalls.touches, 0);
});

test("the_shortcut_ignores_other_commands_bad_tabs_and_a_second_press_while_the_first_runs", async () => {
  const world = await createWorld({ frames: [{ frameId: 0, url: PAGE, build: addLoginForm }] });
  const quick = quickFillOf(world);
  const shortcut = pressable(quick);
  assert.equal(await shortcut.press("ferret-test-command", { id: TAB }), undefined, "another command is not this one");
  for (const tab of [undefined, {}, { id: -1 }, { id: 1.5 }, { id: "7" }]) {
    assert.equal(await quick.fillOrOpen(/** @type {any} */ (tab)?.id), "refused");
  }
  assert.deepEqual(world.ops(), []);
  assert.equal(world.popups.count, 0);

  const first = quick.fillOrOpen(TAB);
  assert.equal(await quick.fillOrOpen(TAB), "busy");
  assert.equal(await first, "filled");
  assert.deepEqual(world.ops(), ["fill_offer", "fill"]);
  // Once it is done, the next press runs.
  assert.equal(await quick.fillOrOpen(TAB), "filled");
});

test("a_popup_that_cannot_open_is_no_error_of_the_shortcut", async () => {
  const world = await createWorld({ frames: [{ frameId: 0, url: PAGE, build: addLoginForm }], items: [] });
  for (const openPopup of [() => Promise.reject(new Error("openPopup requires a user gesture")), () => { throw new Error("no action"); }]) {
    const quick = createQuickFill({ coreHost: world.coreHost, lock: world.lock, openPopup, scripting: world.scripting, webNavigation: world.webNavigation });
    assert.equal(await quick.fillOrOpen(TAB), "popup");
  }
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
