// A tab that forgets the server tells the others; a tab that has that server and account
// open locks and stops its engine, and a tab that does not is left alone.
import assert from "node:assert/strict";
import { test } from "node:test";
import { forgetServer } from "../../src/flows/forgetServer.mjs";
import forgetWatch from "../../src/services/forgetWatch.service.mjs";
import { settle } from "./vaultHelpers.mjs";

const SERVER = "https://vault.example";
const ACCOUNT = "0a1b2c3d4e5f60718293a4b5c6d7e8f9";
const OTHER_ACCOUNT = "ffeeddccbbaa99887766554433221100";

/** A BroadcastChannel by name: what one end posts, every other end receives. */
function bus() {
  const ends = new Set();
  return {
    make() {
      const listeners = new Set();
      const end = {
        closed: false,
        postMessage(data) {
          if (end.closed) throw new Error("closed");
          for (const other of ends) if (other !== end && !other.closed) for (const fn of [...other.listeners]) fn({ data: structuredClone(data) });
        },
        addEventListener: (type, fn) => type === "message" && listeners.add(fn),
        close: () => {
          end.closed = true;
        },
        listeners,
      };
      ends.add(end);
      return end;
    },
  };
}

/** A tab: a session that is open for an account (or not), an engine that can be stopped, and the watch. */
let tabs = 0;
function tab(channels, { accountId = ACCOUNT, serverUrl = SERVER, open = true, tabId = `tab-${(tabs += 1)}` } = {}) {
  const log = [];
  const session = {
    isOpen: open,
    current: () => (session.isOpen ? { accountId } : null),
    async lock() {
      log.push("lock");
      session.isOpen = false;
    },
  };
  const sync = { stop: () => log.push("stop") };
  const service = forgetWatch.create({ crypto: session, sync, serverUrl, makeChannel: () => channels.make(), navigate: (hash) => log.push(["navigate", hash]), tabId });
  return { session, sync, service, log };
}

test("forget_tells_other_tabs_and_they_lock", async () => {
  const channels = bus();
  const same = tab(channels);
  const sameAgain = tab(channels);
  const otherAccount = tab(channels, { accountId: OTHER_ACCOUNT });
  const otherServer = tab(channels, { serverUrl: "https://elsewhere.example" });
  const closedTab = tab(channels, { open: false });
  // The tab that forgets: its own flow, with its own end of the channel.
  const here = channels.make();
  const result = await forgetServer({
    api: { post: async () => ({}) },
    session: { lock: async () => {}, forgetSecretKey: async () => {} },
    store: { open: async () => ({}), pendingWrites: async () => 0, sharedAccount: async () => false, forgetServer: async () => ({ removed: {} }) },
    serverUrl: SERVER, accountId: ACCOUNT, confirm: async () => true, navigate() {}, channel: here, locks: null, tabId: "the-tab-that-forgets",
  });
  assert.equal(result, "forgotten");
  await settle();
  // Both tabs of this server and account lock and stop the engine, and go to the sign-in page.
  for (const t of [same, sameAgain]) assert.deepEqual(t.log, ["lock", "stop", ["navigate", "#/login"]]);
  // A tab for another account, another server, or one that is locked already, is left alone.
  for (const t of [otherAccount, otherServer, closedTab]) assert.deepEqual(t.log, []);
  assert.equal(otherAccount.session.isOpen, true);
});

test("the_tab_that_forgets_ignores_its_own_forget_message", async () => {
  const channels = bus();
  // The tab that forgets has a watch of its own, made apart from the flow's channel: it hears the flow's messages.
  const forgetting = tab(channels, { tabId: "the-tab-that-forgets" });
  const other = tab(channels);
  const result = await forgetServer({
    api: { post: async () => ({}) },
    session: { lock: async () => {}, forgetSecretKey: async () => {} },
    store: { open: async () => ({}), pendingWrites: async () => 0, sharedAccount: async () => false, forgetServer: async () => ({ removed: {} }) },
    serverUrl: SERVER, accountId: ACCOUNT, confirm: async () => true, navigate() {}, channel: channels.make(), locks: null, tabId: "the-tab-that-forgets",
  });
  assert.equal(result, "forgotten");
  await settle();
  assert.deepEqual(forgetting.log, [], "no lock, no stop, and the page that says what was forgotten stays");
  assert.deepEqual(other.log, ["lock", "stop", ["navigate", "#/login"]], "another tab of the account does lock");
});

test("a_message_that_names_another_tab_or_none_is_heard", async () => {
  const channels = bus();
  const t = tab(channels, { tabId: "mine" });
  const sender = channels.make();
  sender.postMessage({ type: "forgetting", serverKey: SERVER, accountId: ACCOUNT, from: "mine" });
  await settle();
  assert.deepEqual(t.log, []);
  sender.postMessage({ type: "forgetting", serverKey: SERVER, accountId: ACCOUNT, from: "someone-else" });
  await settle();
  assert.deepEqual(t.log, ["lock", "stop", ["navigate", "#/login"]]);
});

test("a_message_that_is_not_a_forget_message_for_this_tab_is_ignored", async () => {
  const channels = bus();
  const t = tab(channels);
  const sender = channels.make();
  for (const message of [
    null, "forgotten", 7, {}, { type: "other", serverKey: SERVER, accountId: ACCOUNT },
    { type: "forgotten", serverKey: "https://elsewhere.example", accountId: ACCOUNT },
    { type: "forgotten", serverKey: SERVER, accountId: OTHER_ACCOUNT },
    { type: "forgotten", serverKey: SERVER, accountId: "not hex" },
    { type: "forgotten", serverKey: SERVER },
    { type: "forgotten", accountId: ACCOUNT },
  ]) {
    sender.postMessage(message);
    await settle(2);
  }
  assert.deepEqual(t.log, []);
  assert.equal(t.session.isOpen, true);
  sender.postMessage({ type: "forgotten", serverKey: SERVER, accountId: ACCOUNT });
  await settle();
  assert.deepEqual(t.log, ["lock", "stop", ["navigate", "#/login"]]);
});

test("a_tab_that_cannot_lock_still_stops_its_engine_and_goes_to_sign_in", async () => {
  const channels = bus();
  const t = tab(channels);
  t.session.lock = async () => {
    t.log.push("lock");
    throw new Error("worker gone");
  };
  channels.make().postMessage({ type: "forgotten", serverKey: SERVER, accountId: ACCOUNT });
  await settle();
  assert.deepEqual(t.log, ["lock", "stop", ["navigate", "#/login"]]);
});

test("the_watch_ends_with_close_and_needs_no_channel_support", async () => {
  const channels = bus();
  const t = tab(channels);
  t.service.close();
  channels.make().postMessage({ type: "forgotten", serverKey: SERVER, accountId: ACCOUNT });
  await settle();
  assert.deepEqual(t.log, [], "a closed watch hears nothing");
  // A page without BroadcastChannel makes no channel, and nothing breaks.
  const saved = globalThis.BroadcastChannel;
  delete globalThis.BroadcastChannel;
  try {
    const service = forgetWatch.create({ crypto: {}, sync: {}, serverUrl: SERVER, navigate() {} });
    service.close();
    // An address that is not a server address makes none either.
    forgetWatch.create({ crypto: {}, sync: {}, serverUrl: "not a url", makeChannel: () => assert.fail("no channel"), navigate() {} }).close();
  } finally {
    if (saved !== undefined) globalThis.BroadcastChannel = saved;
  }
});

test("the_tabs_stop_when_the_forgetting_starts_and_the_second_message_does_nothing_more", async () => {
  const channels = bus();
  const t = tab(channels);
  const sender = channels.make();
  sender.postMessage({ type: "forgetting", serverKey: SERVER, accountId: ACCOUNT });
  await settle();
  // The tab is locked and stopped before anything is removed.
  assert.deepEqual(t.log, ["lock", "stop", ["navigate", "#/login"]]);
  sender.postMessage({ type: "forgotten", serverKey: SERVER, accountId: ACCOUNT });
  await settle();
  assert.deepEqual(t.log, ["lock", "stop", ["navigate", "#/login"]], "locked already: nothing happens again");
  // A tab that missed the first message stops on the second.
  const late = tab(channels);
  sender.postMessage({ type: "forgotten", serverKey: SERVER, accountId: ACCOUNT });
  await settle();
  assert.deepEqual(late.log, ["lock", "stop", ["navigate", "#/login"]]);
});
