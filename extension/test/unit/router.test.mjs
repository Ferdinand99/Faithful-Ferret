import assert from "node:assert/strict";
import { test } from "node:test";
import { CORE_OPS, createCoreHost } from "../../src/background/coreHost.mjs";
import { LOCK_AT_KEY, LOCK_EXEMPT, createLock } from "../../src/background/lock.mjs";
import { createRouter } from "../../src/background/router.mjs";
import { CONTENT_TYPES, REFUSAL_REASONS, UI_PORT, UI_TYPES, decode, encode, encodeRefusal } from "../../src/shared/protocol.mjs";
import { contentScriptSender, createFakeBrowser, extensionPageSender } from "./fakeBrowser.mjs";
import { createAlarmsAndIdle, createClock, createFakeClient, createPort, createSessionStorage } from "./backgroundHelpers.mjs";

const MINUTE = 60_000;

const probes = Object.freeze({
  unlock_probe: {
    vault: false,
    worker: /** @type {"none"} */ ("none"),
    run: async (/** @type {any} */ _client, /** @type {any} */ _args, /** @type {any} */ ctx) => {
      ctx.setUnlocked();
      return { ok: true };
    },
  },
});

/**
 * @param {{ unlocked?: boolean, handlers?: (log: Array<{ type: string, body: any, ctx: any }>) => any[] }} [options]
 */
async function setup({ unlocked = false, handlers } = {}) {
  const fake = createFakeBrowser();
  const clock = createClock();
  const client = createFakeClient({ vault: { ferret_aaguid: () => new Uint8Array(16) } });
  const coreHost = createCoreHost({ createClient: () => client, now: clock.now, ops: probes, names: [...CORE_OPS, "unlock_probe"] });
  const storage = createSessionStorage();
  const events = createAlarmsAndIdle();
  const lock = createLock({ alarms: events.alarms, idle: events.idle, storageSession: storage, now: clock.now, coreHost });
  if (unlocked) {
    await coreHost.call("unlock_probe");
    lock.touch();
    await new Promise((resolve) => setTimeout(resolve, 0));
  }
  /** @type {Array<{ type: string, body: any, ctx: any, stateAtCall: string }>} */
  const log = [];
  const record = (/** @type {string} */ type, /** @type {any} */ reply, /** @type {(ctx: any) => unknown} */ after = () => {}) => ({
    types: [type],
    channel: /** @type {"ui" | "content"} */ (type in UI_TYPES ? "ui" : "content"),
    async handle(/** @type {any} */ body, /** @type {any} */ ctx) {
      log.push({ type, body, ctx, stateAtCall: ctx.state() });
      await after(ctx);
      return reply;
    },
  });
  const defaults = [
    record("state", { state: "locked" }),
    record("lock", { ok: true }),
    record("sign_in", { ok: true }),
    record("unlock", { ok: true }, async (ctx) => {
      await ctx.call("unlock_probe");
      ctx.touch();
    }),
    record("settings", { lock_minutes: 15 }),
    record("candidates", { handles: [] }),
    record("search", { handles: [] }),
    record("frame_report", undefined),
    record("fill_result", undefined),
  ];
  const router = createRouter({ runtime: fake.runtime, lock, coreHost, handlers: handlers ? handlers(log) : defaults });
  return { fake, clock, client, coreHost, storage, events, lock, router, log };
}

/** Connects a UI port from `sender` and returns it. */
function connect(/** @type {any} */ router, /** @type {unknown} */ sender, name = UI_PORT) {
  const port = createPort(name, sender);
  router.onConnect(port);
  return port;
}

const requests = {
  state: () => encode("state", {}),
  lock: () => encode("lock", {}),
  sign_in: () => encode("sign_in", { server: "https://vault.example", email: "a@b.c", mp: "typed" }),
  unlock: () => encode("unlock", { mp: "typed" }),
  settings: () => encode("settings", {}),
  candidates: () => encode("candidates", { tab_id: 1, frame_id: 0 }),
  search: () => encode("search", { query: "x" }),
};

/** The refusal as the page decodes it: a typed reply of the UI channel. @param {string} text */
const refusal = (text) => {
  const message = decode(text, UI_TYPES, { reply: true });
  assert.equal(message.type, "refused");
  return message;
};

test("unlock_is_allowed_while_locked_and_sets_lock_at", async () => {
  const { fake, clock, coreHost, storage, router, log } = await setup();
  const port = connect(router, extensionPageSender(fake));
  assert.equal(coreHost.state(), "locked");

  // Every name in LOCK_EXEMPT reaches its handler while the vault is locked.
  for (const type of LOCK_EXEMPT) {
    log.length = 0;
    port.sent.length = 0;
    await port.send(/** @type {Record<string, () => string>} */ (requests)[type]());
    assert.deepEqual(log.map((entry) => entry.type), [type], type);
    assert.equal(decode(port.sent[0], UI_TYPES, { reply: true }).type, type);
  }
  assert.equal(coreHost.state(), "unlocked", "the unlock handler opened it");
  assert.equal((await storage.get(LOCK_AT_KEY))[LOCK_AT_KEY], clock.now() + 15 * MINUTE);
});

test("a_type_that_needs_the_vault_is_refused_while_locked_and_never_reaches_its_handler", async () => {
  const { fake, router, log } = await setup();
  const port = connect(router, extensionPageSender(fake));
  await port.send(requests.candidates());
  await port.send(requests.search());
  assert.deepEqual(log, []);
  assert.equal(port.sent.length, 2);
  for (const text of port.sent) assert.deepEqual(refusal(text).body, { reason: "vault_locked" });
  assert.equal(refusal(port.sent[0]).type, "refused");
});

test("an_expired_deadline_locks_before_the_handler_runs", async () => {
  const { fake, clock, client, coreHost, router, log } = await setup({ unlocked: true });
  const port = connect(router, extensionPageSender(fake));
  clock.advance(15 * MINUTE);
  await port.send(requests.candidates());
  assert.deepEqual(log, []);
  assert.equal(coreHost.state(), "locked");
  assert.equal(client.locks, 1);
  assert.deepEqual(refusal(port.sent[0]).body, { reason: "vault_locked" });
});

test("a_call_with_an_open_vault_reaches_the_handler_and_moves_the_deadline", async () => {
  const { fake, clock, storage, router, log } = await setup({ unlocked: true });
  const port = connect(router, extensionPageSender(fake));
  clock.advance(5 * MINUTE);
  await port.send(requests.candidates());
  assert.deepEqual(log.map((e) => e.type), ["candidates"]);
  assert.deepEqual(decode(port.sent[0], UI_TYPES, { reply: true }).body, { handles: [] });
  assert.equal((await storage.get(LOCK_AT_KEY))[LOCK_AT_KEY], clock.now() + 15 * MINUTE);
});

test("a_message_that_needs_no_key_does_not_move_the_deadline", async () => {
  const { fake, clock, storage, router } = await setup({ unlocked: true });
  const port = connect(router, extensionPageSender(fake));
  await new Promise((resolve) => setTimeout(resolve, 0));
  const before = (await storage.get(LOCK_AT_KEY))[LOCK_AT_KEY];
  clock.advance(5 * MINUTE);
  await port.send(requests.state());
  await port.send(requests.settings());
  assert.equal((await storage.get(LOCK_AT_KEY))[LOCK_AT_KEY], before);
});

test("the_ui_port_is_accepted_only_through_isUiPort", async () => {
  const { fake, router } = await setup();
  const good = connect(router, extensionPageSender(fake));
  assert.equal(good.disconnected, false);
  assert.equal(good.listenerCount(), 1);

  const refused = {
    "a framed extension page (frameId 3)": extensionPageSender(fake, "pages/signin.html", { frameId: 3 }),
    "an extension page in a tab with no frame id": extensionPageSender(fake, "pages/signin.html", { frameId: undefined, tab: { id: 4 } }),
    "a content script": contentScriptSender(fake),
    "a data: page": { id: fake.runtime.id, url: "data:text/html,<p>x</p>", origin: "null", frameId: 0 },
    "about:blank": { id: fake.runtime.id, url: "about:blank", origin: "null", frameId: 0 },
    "another extension": { ...extensionPageSender(fake), id: "other@example.org" },
    "another extension's page": { ...extensionPageSender(fake), url: "moz-extension://11111111-2222-4333-8444-555555555555/pages/x.html" },
    "no sender": undefined,
  };
  for (const [label, sender] of Object.entries(refused)) {
    const port = connect(router, sender);
    assert.equal(port.disconnected, true, label);
    assert.equal(port.listenerCount(), 0, `${label}: no listener, so nothing is read from it`);
  }
});

test("a_framed_extension_page_cannot_use_the_ui_port", async () => {
  const { fake, router, log } = await setup({ unlocked: true });
  const port = connect(router, extensionPageSender(fake, "pages/signin.html", { frameId: 2 }));
  await port.send(requests.unlock());
  await port.send(requests.state());
  assert.deepEqual(log, []);
  assert.deepEqual(port.sent, []);
});

test("a_port_with_another_name_is_not_ours_and_is_left_alone", async () => {
  const { fake, router } = await setup();
  const port = connect(router, extensionPageSender(fake), "someone-else");
  assert.equal(port.disconnected, false);
  assert.equal(port.listenerCount(), 0);
});

test("a_bad_message_on_the_ui_port_ends_the_connection", async () => {
  const { fake, router, log } = await setup({ unlocked: true });
  const content = encode("fill_result", { request_id: "r1", ok: true });
  const bad = ["not json", 7, null, content, JSON.stringify({ v: 1, id: "a", type: "state", body: { extra: 1 } }), JSON.stringify({ v: 2, id: "a", type: "state", body: {} }), "x".repeat(70_000)];
  for (const raw of bad) {
    const port = connect(router, extensionPageSender(fake));
    await port.send(raw);
    assert.equal(port.disconnected, true, String(raw).slice(0, 30));
    assert.deepEqual(port.sent, []);
  }
  assert.deepEqual(log, []);
});

test("a_type_without_a_handler_is_not_available", async () => {
  const { fake, router } = await setup({ handlers: () => [] });
  const port = connect(router, extensionPageSender(fake));
  await port.send(requests.state());
  assert.deepEqual(refusal(port.sent[0]).body, { reason: "not_available" });
});

test("a_refusal_carries_a_reason_and_never_text_from_the_handler_or_the_request", async () => {
  const handlers = () => [
    { types: ["unlock"], channel: "ui", handle: async () => { throw new Error("master password hunter2"); } },
    { types: ["sign_in"], channel: "ui", handle: async () => { throw Object.assign(new Error("hunter2"), { code: "bad_credentials" }); } },
    { types: ["lock"], channel: "ui", handle: async () => { throw Object.assign(new Error("hunter2"), { code: "invalid_input" }); } },
    { types: ["settings"], channel: "ui", handle: async () => ({ lock_minutes: 9999 }) },
    { types: ["state"], channel: "ui", handle: async () => { throw Object.assign(new Error("x"), { code: "Has Spaces: hunter2" }); } },
  ];
  const { fake, router } = await setup({ handlers });
  const port = connect(router, extensionPageSender(fake));
  await port.send(requests.unlock());
  await port.send(requests.sign_in());
  await port.send(requests.settings());
  await port.send(requests.state());
  await port.send(requests.lock());
  // A code outside the fixed list is internal_error; one in it is passed on.
  assert.deepEqual(port.sent.map((t) => refusal(t).body.reason), ["internal_error", "internal_error", "internal_error", "internal_error", "invalid_input"]);
  assert.equal(port.sent.join("").includes("hunter2"), false);
  for (const sent of port.sent) assert.ok(REFUSAL_REASONS.includes(refusal(sent).body.reason));
  assert.equal(JSON.parse(encodeRefusal("abc", "Not A Reason")).body.reason, "internal_error");
});

test("the_handler_context_has_the_call_and_no_key_or_client", async () => {
  const { fake, router, log } = await setup({ unlocked: true });
  const port = connect(router, extensionPageSender(fake));
  await port.send(requests.candidates());
  const { ctx } = log[0];
  assert.deepEqual(Object.keys(ctx).sort(), ["call", "channel", "lock", "sender", "setMinutes", "state", "touch"]);
  assert.equal(Object.isFrozen(ctx), true);
  assert.equal(ctx.channel, "ui");
  // The host's list decides what it can call.
  await assert.rejects(ctx.call("vault.item_view", [1]), { code: "unknown_core_op" });
  assert.equal(JSON.stringify(Object.keys(ctx)).includes("client"), false);
});

test("a_content_script_reaches_only_the_content_types_and_never_while_locked", async () => {
  const { fake, router, log } = await setup({ unlocked: true });
  const sender = contentScriptSender(fake, "https://example.com/login", { tab: { id: 7 }, frameId: 2 });
  const report = encode("frame_report", { request_id: "r1", self_origin: "https://example.com", fields: [] });
  assert.equal(await router.onMessage(report, sender), undefined);
  assert.deepEqual(log.map((e) => [e.type, e.ctx.channel, e.ctx.sender.tabId, e.ctx.sender.frameId]), [["frame_report", "content", 7, 2]]);
  // A report handler reads the state and nothing else: no call, no lock, no touch.
  assert.deepEqual(Object.keys(log[0].ctx).sort(), ["channel", "sender", "state"]);

  // A UI type from a content script is ignored, as is a message that is not ours.
  log.length = 0;
  for (const raw of [requests.unlock(), requests.state(), requests.candidates(), "junk", 5, undefined]) {
    assert.equal(await router.onMessage(raw, sender), undefined);
  }
  assert.deepEqual(log, []);
});

test("a_content_message_from_an_extension_page_or_a_stranger_is_ignored", async () => {
  const { fake, router, log } = await setup({ unlocked: true });
  const report = encode("fill_result", { request_id: "r1", ok: true });
  assert.equal(router.onMessage(report, extensionPageSender(fake)), undefined);
  assert.equal(router.onMessage(report, { ...contentScriptSender(fake), id: "other@example.org" }), undefined);
  assert.equal(router.onMessage(report, { ...contentScriptSender(fake), url: "about:blank" }), undefined);
  assert.equal(router.onMessage(report, undefined), undefined);
  assert.deepEqual(log, []);
});

test("a_content_report_while_the_vault_is_locked_is_dropped", async () => {
  const { fake, router, log } = await setup();
  const report = encode("fill_result", { request_id: "r1", ok: true });
  assert.equal(await router.onMessage(report, contentScriptSender(fake)), undefined);
  assert.deepEqual(log, []);
});

test("a_ui_message_is_not_taken_from_runtime_send_message_of_an_extension_page", async () => {
  const { fake, router, log } = await setup({ unlocked: true });
  assert.equal(router.onMessage(requests.unlock(), extensionPageSender(fake)), undefined);
  assert.deepEqual(log, []);
});

test("the_handlers_are_checked_at_start_up", async () => {
  const make = (/** @type {any[]} */ handlers) => async () => (await setup({ handlers: () => handlers }));
  const ok = { types: ["state"], channel: "ui", handle: async () => ({}) };
  await assert.rejects(make([ok, { ...ok }])(), /two handlers/);
  await assert.rejects(make([{ ...ok, types: ["frame_report"] }])(), /no type/);
  await assert.rejects(make([{ ...ok, channel: "content" }])(), /no type/);
  await assert.rejects(make([{ ...ok, types: ["nope"] }])(), /no type/);
  await assert.rejects(make([{ ...ok, types: [] }])(), /needs channel/);
  await assert.rejects(make([{ ...ok, channel: "other" }])(), /needs channel/);
  await assert.rejects(make([{ ...ok, handle: null }])(), /needs channel/);
  await assert.rejects(make([null])(), /needs channel/);
  assert.ok(Object.hasOwn(UI_TYPES, "state") && Object.hasOwn(CONTENT_TYPES, "frame_report"));
});

test("state_after_the_deadline_reports_locked", async () => {
  const { fake, clock, coreHost, router, log } = await setup({ unlocked: true });
  const port = connect(router, extensionPageSender(fake));
  clock.advance(15 * MINUTE);
  await port.send(requests.state());
  assert.equal(log.at(-1)?.type, "state");
  assert.equal(log.at(-1)?.stateAtCall, "locked", "the vault was locked before the handler answered");
  assert.equal(coreHost.state(), "locked");
});

test("a_poll_in_the_turn_after_an_unlock_does_not_lock_the_new_vault", async () => {
  const { fake, coreHost, router } = await setup();
  const port = connect(router, extensionPageSender(fake));
  // The unlock handler of the stub opens the host and touches afterwards; a state
  // poll that arrives in between must find a deadline already.
  const poll = connect(router, extensionPageSender(fake, "pages/popup.html"));
  await Promise.all([port.send(requests.unlock()), poll.send(requests.state())]);
  assert.equal(coreHost.state(), "unlocked");
});

test("lock_is_never_refused_and_a_throw_during_lock_still_ends_locked", async () => {
  // A lock check that throws refuses every other type, and never `lock`.
  {
    const { fake, coreHost } = await setup({ unlocked: true });
    /** @type {string[]} */
    const ran = [];
    const handler = (/** @type {string} */ type, /** @type {any} */ reply) => ({
      types: [type],
      channel: /** @type {"ui"} */ ("ui"),
      async handle(/** @type {any} */ _body, /** @type {any} */ ctx) {
        ran.push(type);
        if (type === "lock") await ctx.lock("manual");
        return reply;
      },
    });
    const router = createRouter({
      runtime: fake.runtime,
      lock: { checkOrLock: async () => { throw new Error("storage failed"); }, touch() {}, setMinutes() {} },
      coreHost,
      handlers: [handler("lock", { ok: true }), handler("candidates", { handles: [] })],
    });
    const port = connect(router, extensionPageSender(fake));
    await port.send(requests.candidates());
    await port.send(requests.lock());
    assert.deepEqual(ran, ["lock"], "only lock ran");
    assert.deepEqual(refusal(port.sent[0]).body, { reason: "vault_locked" });
    assert.deepEqual(decode(port.sent[1], UI_TYPES, { reply: true }).body, { ok: true });
    assert.equal(coreHost.state(), "locked");
  }
  // A client that cannot end its worker, and a deadline that cannot be read: the host ends locked all the same.
  {
    const { fake, client, coreHost, storage, router, log } = await setup({
      unlocked: true,
      handlers: () => [{
        types: ["lock"],
        channel: "ui",
        async handle(/** @type {any} */ _body, /** @type {any} */ ctx) {
          await ctx.lock("manual");
          return { ok: true };
        },
      }],
    });
    client.lock = async () => {
      throw new Error("the worker would not end");
    };
    storage.broken = true;
    const port = connect(router, extensionPageSender(fake));
    await port.send(requests.lock());
    assert.equal(coreHost.state(), "locked");
    assert.equal(log.length, 0);
    assert.equal(port.sent.length, 1, "the page got an answer");
    assert.equal(refusal(port.sent[0]).body.reason, "internal_error");
  }
});
