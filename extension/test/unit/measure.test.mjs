import assert from "node:assert/strict";
import { test } from "node:test";
import { CORE_OPS, createCoreHost } from "../../src/background/coreHost.mjs";
import { createLock, LOCK_AT_KEY } from "../../src/background/lock.mjs";
import { HEARTBEAT_ALARM, MAX_ENTRIES, createMeasureLog, startMeasureLog } from "../../src/background/test-only/measureLog.mjs";
import { createScenarios } from "../../src/background/test-only/measureScenario.mjs";
import { install, ops, TEST_MEASURE_PORT, TEST_WHOAMI_PORT } from "../../src/background/test-only/testHooks.mjs";
import { summarize } from "../../src/shared/test-only/measureSummary.mjs";
import { createAlarmsAndIdle, createClock, createFakeClient, createPort, createSessionStorage } from "./backgroundHelpers.mjs";
import { createFakeBrowser, extensionPageSender } from "./fakeBrowser.mjs";

const SECOND = 1000;
const MINUTE = 60 * SECOND;

/** The settle that the log's write queue needs. */
const settle = () => new Promise((resolve) => setTimeout(resolve, 0));

/** The browser objects that the log listens to. */
function logEnvironment() {
  /** @type {Array<() => void>} */
  const suspendListeners = [];
  /** @type {Array<() => void>} */
  const canceledListeners = [];
  /** @type {Array<(alarm: { name: string }) => unknown>} */
  const alarmListeners = [];
  /** @type {Map<string, unknown>} */
  const alarms = new Map();
  return {
    suspendListeners,
    alarms,
    runtime: {
      onSuspend: { addListener: (/** @type {any} */ fn) => suspendListeners.push(fn) },
      onSuspendCanceled: { addListener: (/** @type {any} */ fn) => canceledListeners.push(fn) },
    },
    alarmsApi: {
      get: async (/** @type {string} */ name) => alarms.get(name),
      create: (/** @type {string} */ name, /** @type {unknown} */ info) => { alarms.set(name, info); },
      onAlarm: { addListener: (/** @type {any} */ fn) => alarmListeners.push(fn) },
    },
    fireAlarm: (/** @type {string} */ name) => Promise.all(alarmListeners.map((fn) => fn({ name }))),
    fireSuspend: () => { for (const fn of suspendListeners) fn(); },
    fireCanceled: () => { for (const fn of canceledListeners) fn(); },
  };
}

test("the_log_writes_every_entry_in_order_and_keeps_only_the_newest", async () => {
  const storage = createSessionStorage();
  const clock = createClock(5000);
  const log = createMeasureLog({ storageLocal: storage, now: clock.now, boot: "b1", core: () => "locked" });
  // Three entries made in the same turn keep their order and none is lost.
  log.append("startup");
  clock.advance(10);
  log.append("heartbeat", { n: 1 });
  clock.advance(10);
  log.append("suspend");
  const entries = await log.read();
  assert.deepEqual(entries.map((e) => e.kind), ["startup", "heartbeat", "suspend"]);
  assert.deepEqual(entries.map((e) => e.at), [5000, 5010, 5020]);
  assert.equal(entries[1].n, 1);
  assert.equal(entries[0].core, "locked");
  assert.equal(entries[0].boot, "b1");

  // A ring: the oldest go first.
  for (let i = 0; i < MAX_ENTRIES + 10; i += 1) log.append("heartbeat", { i });
  const full = await log.read();
  assert.equal(full.length, MAX_ENTRIES);
  assert.equal(full[full.length - 1].i, MAX_ENTRIES + 9);

  await log.clear();
  assert.deepEqual(await log.read(), []);
});

test("a_storage_that_fails_does_not_stop_the_log_or_throw", async () => {
  const storage = createSessionStorage();
  const log = createMeasureLog({ storageLocal: storage, now: () => 1, boot: "b", core: () => "locked" });
  storage.broken = true;
  await log.append("startup");
  storage.broken = false;
  await log.append("heartbeat");
  assert.deepEqual((await log.read()).map((e) => e.kind), ["heartbeat"]);
});

test("the_log_registers_its_listeners_at_once_and_makes_the_alarm_only_when_it_is_missing", async () => {
  const env = logEnvironment();
  const storage = createSessionStorage();
  const clock = createClock(1000);
  const { log } = startMeasureLog({ runtime: /** @type {any} */ (env.runtime), alarms: /** @type {any} */ (env.alarmsApi), storageLocal: storage, now: clock.now, core: () => "locked", boot: "first" });
  // The listeners are there before the first await: an alarm that woke the page reaches them.
  assert.equal(env.suspendListeners.length, 1);
  await settle();
  assert.deepEqual(env.alarms.get(HEARTBEAT_ALARM), { delayInMinutes: 1, periodInMinutes: 1 });
  clock.advance(MINUTE);
  await env.fireAlarm(HEARTBEAT_ALARM);
  await env.fireAlarm("ferret-lock");
  clock.advance(30 * SECOND);
  env.fireSuspend();
  env.fireCanceled();
  assert.deepEqual((await log.read()).map((e) => e.kind), ["startup", "heartbeat", "suspend", "suspend_canceled"]);

  // A later start of the page: the alarm is there already, so it is not made again (that would move the beat).
  env.alarms.set(HEARTBEAT_ALARM, { kept: true });
  startMeasureLog({ runtime: /** @type {any} */ (env.runtime), alarms: /** @type {any} */ (env.alarmsApi), storageLocal: storage, now: clock.now, core: () => "locked", boot: "second" });
  await settle();
  assert.deepEqual(env.alarms.get(HEARTBEAT_ALARM), { kept: true });
});

test("summarize_counts_from_the_scenario_start_and_finds_the_suspend_and_the_restart", () => {
  const e = (/** @type {string} */ kind, /** @type {number} */ at, /** @type {string} */ boot) => ({ kind, at, boot });
  const summary = summarize([
    e("startup", 1000, "a"),
    e("scenario_start", 4000, "a"),
    e("heartbeat", 64_000, "a"),
    e("suspend", 94_000, "a"),
    e("startup", 124_000, "b"),
    e("heartbeat", 124_100, "b"),
    e("suspend", 154_000, "b"),
  ]);
  assert.equal(summary.boots, 2);
  assert.equal(summary.heartbeats, 2);
  assert.equal(summary.suspends, 2);
  assert.equal(summary.firstSuspendAfterMs, 90_000);
  assert.equal(summary.restartAfterMs, 120_000);
  assert.equal(summary.lastEntryAfterMs, 150_000);
  assert.deepEqual(summary.lifetimes.map((l) => [l.boot, l.aliveMs, l.ended]), [["a", 93_000, "suspend"], ["b", 30_000, "suspend"]]);
});

test("summarize_of_a_page_that_never_ended_has_no_suspend_and_no_restart", () => {
  const summary = summarize([
    { kind: "startup", at: 0, boot: "a" },
    { kind: "scenario_start", at: 10, boot: "a" },
    { kind: "heartbeat", at: 60_010, boot: "a" },
    { kind: "heartbeat", at: 120_010, boot: "a" },
  ]);
  assert.equal(summary.firstSuspendAfterMs, null);
  assert.equal(summary.restartAfterMs, null);
  assert.equal(summary.boots, 1);
  assert.deepEqual(summary.lifetimes.map((l) => [l.ended, l.aliveMs]), [["last_seen", 120_010]]);
  // Nothing at all, and entries that are not entries: no throw, no number out of nothing.
  assert.equal(summarize([]).boots, 0);
  assert.equal(summarize([/** @type {any} */ (null), /** @type {any} */ ({ kind: 1 })]).boots, 0);
});

/** A core host and a lock over fakes, with the test build's operations in. */
function coreSetup() {
  const clock = createClock(1_000_000);
  const client = createFakeClient({ vault: { ferret_aaguid: () => new Uint8Array(16) } });
  const coreHost = createCoreHost({ createClient: () => client, now: clock.now, ops, names: [...CORE_OPS] });
  const storage = createSessionStorage();
  const events = createAlarmsAndIdle();
  const lock = createLock({ alarms: events.alarms, idle: events.idle, storageSession: storage, now: clock.now, coreHost });
  return { clock, client, coreHost, storage, events, lock };
}

test("measure_open_starts_the_vault_worker_opens_the_host_and_starts_the_deadline", async () => {
  const { clock, client, coreHost, storage, events } = coreSetup();
  assert.equal(coreHost.state(), "locked");
  assert.deepEqual(await coreHost.call("measure_open"), { ok: true });
  assert.equal(coreHost.state(), "unlocked");
  assert.deepEqual(client.calls.map((c) => c.method), ["ferret_aaguid"], "the worker did a stateless call, nothing else");
  await settle();
  assert.equal((await storage.get(LOCK_AT_KEY))[LOCK_AT_KEY], clock.now() + 15 * MINUTE);
  assert.ok(events.alarmList.has("ferret-lock"));
  // A lock still ends it: the worker is ended and the deadline is gone.
  await coreHost.lock("manual");
  assert.equal(coreHost.state(), "locked");
  assert.equal(client.locks, 1);
});

test("measure_open_fails_closed_when_the_worker_does_not_answer_with_sixteen_bytes", async () => {
  const clock = createClock();
  const client = createFakeClient({ vault: { ferret_aaguid: () => new Uint8Array(3) } });
  const coreHost = createCoreHost({ createClient: () => client, now: clock.now, ops });
  await assert.rejects(coreHost.call("measure_open"), { code: "internal" });
  assert.equal(coreHost.state(), "locked");
});

/** The log, the host and the scenarios over fakes. */
function scenarioSetup(fetchImpl = /** @type {typeof fetch} */ (async () => { throw new Error("no network in this test"); })) {
  const { clock, client, coreHost, storage, events } = coreSetup();
  const area = createSessionStorage();
  const log = createMeasureLog({ storageLocal: area, now: clock.now, boot: "b", core: () => coreHost.state() });
  const scenarios = createScenarios({ coreHost, log, storageLocal: area, scenarioKey: "measure_scenario", fetchImpl, now: clock.now });
  return { clock, client, coreHost, storage, events, area, log, scenarios };
}

test("a_scenario_starts_with_a_clean_log_the_vault_open_and_the_scenario_written_down", async () => {
  const { coreHost, area, log, scenarios } = scenarioSetup();
  await log.append("startup");
  await log.append("heartbeat");
  const reply = await scenarios.start({ scenario: "idle" });
  assert.deepEqual(reply, { ok: true, core: "unlocked" });
  assert.equal(coreHost.state(), "unlocked");
  const entries = await log.read();
  assert.deepEqual(entries.map((e) => e.kind), ["scenario_start"], "the log was emptied first");
  assert.equal(entries[0].core, "unlocked", "the entry is written after the vault opened");
  assert.deepEqual((await area.get("measure_scenario")).measure_scenario, { name: "idle", startedAt: 1_000_000 });
  assert.deepEqual(scenarios.current(), { name: "idle", stopped: false });
  await scenarios.stop();
  assert.equal(scenarios.current(), null);
  assert.deepEqual(await area.get("measure_scenario"), {});
});

test("a_scenario_refuses_what_it_does_not_know_and_a_stream_that_is_not_https", async () => {
  const { coreHost, scenarios } = scenarioSetup();
  for (const args of [undefined, {}, { scenario: 1 }, { scenario: "nope" }, { scenario: "sse" }, { scenario: "sse", url: "http://example.org/sse" }, { scenario: "sse", url: "javascript:alert(1)" }, { scenario: "sse", url: `https://example.org/${"a".repeat(400)}` }, { scenario: "argon", m_kib: 0 }, { scenario: "argon", t: 17 }, { scenario: "argon", m_kib: 1.5 }]) {
    await assert.rejects(scenarios.start(/** @type {any} */ (args)), (/** @type {any} */ error) => ["bad_scenario", "bad_url", "bad_params"].includes(error.code), JSON.stringify(args));
  }
  assert.equal(coreHost.state(), "locked", "a refused scenario opens nothing");
});

test("the_stream_scenario_logs_when_the_stream_opens_and_when_it_ends", async () => {
  /** @type {string[]} */
  const seen = [];
  const body = new ReadableStream({
    start(controller) {
      controller.enqueue(new TextEncoder().encode(": open\n\n"));
      controller.enqueue(new TextEncoder().encode("data: 1\n\n"));
      setTimeout(() => controller.close(), 5);
    },
  });
  const fetchImpl = /** @type {typeof fetch} */ (async (url, init) => {
    seen.push(`${url} ${init?.credentials} ${init?.cache}`);
    return new Response(body, { status: 200 });
  });
  const { log, scenarios } = scenarioSetup(fetchImpl);
  await scenarios.start({ scenario: "sse", url: "https://example.org/sse" });
  await new Promise((resolve) => setTimeout(resolve, 40));
  await settle();
  assert.deepEqual(seen, ["https://example.org/sse omit no-store"]);
  const entries = await log.read();
  assert.deepEqual(entries.map((e) => e.kind), ["scenario_start", "stream_open", "stream_end"]);
  assert.equal(entries[2].chunks, 2);
});

test("a_stream_that_fails_is_logged_with_a_code_and_never_a_message", async () => {
  const fetchImpl = /** @type {typeof fetch} */ (async () => { throw new Error("secret detail of the network error"); });
  const { log, scenarios } = scenarioSetup(fetchImpl);
  await scenarios.start({ scenario: "sse", url: "https://example.org/sse" });
  await new Promise((resolve) => setTimeout(resolve, 20));
  const entries = await log.read();
  assert.deepEqual(entries.map((e) => e.kind), ["scenario_start", "stream_error"]);
  assert.equal(entries[1].code, "failed");
  assert.equal(JSON.stringify(entries).includes("secret"), false);
});

test("the_argon_scenario_runs_jobs_until_it_is_stopped", async () => {
  let calls = 0;
  const clock = createClock();
  const client = createFakeClient({
    vault: { ferret_aaguid: () => new Uint8Array(16) },
    job: { argon2_export_key: async () => { calls += 1; clock.advance(1000); await new Promise((resolve) => setTimeout(resolve, 2)); return new Uint8Array(32); } },
  });
  const coreHost = createCoreHost({ createClient: () => client, now: clock.now, ops });
  const area = createSessionStorage();
  const log = createMeasureLog({ storageLocal: area, now: clock.now, boot: "b", core: () => coreHost.state() });
  const scenarios = createScenarios({ coreHost, log, storageLocal: area, scenarioKey: "measure_scenario", now: clock.now });
  await scenarios.start({ scenario: "argon", m_kib: 64, t: 1 });
  await new Promise((resolve) => setTimeout(resolve, 30));
  await scenarios.stop();
  const before = calls;
  await new Promise((resolve) => setTimeout(resolve, 20));
  assert.ok(before >= 2, `${before} jobs ran`);
  assert.ok(calls <= before + 1, "no new job starts after stop");
  const done = (await log.read()).filter((e) => e.kind === "job_done");
  assert.ok(done.length >= 1);
  assert.deepEqual([done[0].m_kib, done[0].t, done[0].p, done[0].ms], [64, 1, 1, 1000]);
});

/** The test hooks over fake browser objects, in the page's first turn. */
function hooksSetup() {
  const fake = createFakeBrowser();
  const events = createAlarmsAndIdle();
  const env = logEnvironment();
  /** @type {Array<(port: any) => void>} */
  const connectListeners = [];
  /** @type {Array<(message: any, sender: any) => unknown>} */
  const messageListeners = [];
  const clock = createClock();
  const client = createFakeClient({ vault: { ferret_aaguid: () => new Uint8Array(16) } });
  const coreHost = createCoreHost({ createClient: () => client, now: clock.now });
  const sessionStorage = createSessionStorage();
  const local = createSessionStorage();
  const browser = {
    runtime: { ...fake.runtime, ...env.runtime, onConnect: { addListener: (/** @type {any} */ fn) => connectListeners.push(fn) }, onMessage: { addListener: (/** @type {any} */ fn) => messageListeners.push(fn) } },
    alarms: env.alarmsApi,
    storage: { local, session: sessionStorage },
  };
  install({ browser, runtime: fake.runtime, coreHost, now: clock.now });
  return { fake, events, env, connectListeners, messageListeners, coreHost, local, sessionStorage, client };
}

test("the_hooks_put_the_log_and_the_ports_in_place_in_the_first_turn", async () => {
  const { env, connectListeners, messageListeners, local } = hooksSetup();
  assert.equal(connectListeners.length, 1);
  assert.equal(messageListeners.length, 1);
  assert.equal(env.suspendListeners.length, 1);
  await settle();
  assert.deepEqual((await local.get("measure_log")).measure_log.map((/** @type {{ kind: string }} */ e) => e.kind), ["startup"]);
});

test("the_measure_port_takes_top_level_extension_pages_only_and_answers_known_commands_only", async () => {
  const { fake, connectListeners, coreHost } = hooksSetup();
  const [onConnect] = connectListeners;

  for (const sender of [
    extensionPageSender(fake, "pages/test-only/measure.html", { frameId: 3 }),
    { ...extensionPageSender(fake), url: "https://example.org/", origin: "https://example.org" },
    { id: "other@example" },
    undefined,
  ]) {
    const port = createPort(TEST_MEASURE_PORT, sender);
    onConnect(port);
    assert.equal(port.disconnected, true, JSON.stringify(sender));
    assert.equal(port.listenerCount(), 0);
  }

  const port = createPort(TEST_MEASURE_PORT, extensionPageSender(fake, "pages/test-only/measure.html"));
  onConnect(port);
  assert.equal(port.disconnected, false);
  await port.send({ id: "1", cmd: "state" });
  await port.send({ id: "2", cmd: "constructor" });
  await port.send({ id: "3", cmd: "start", scenario: "nope" });
  await port.send({ id: "4", cmd: "start", scenario: "idle" });
  /** @type {any[]} */
  const replies = /** @type {any} */ (port.sent);
  assert.deepEqual(replies[0], { id: "1", ok: true, value: { core: "locked", scenario: null, lockAt: null } });
  assert.deepEqual(replies[1], { id: "2", ok: false, code: "unknown_command" });
  assert.deepEqual(replies[2], { id: "3", ok: false, code: "bad_scenario" });
  assert.equal(replies[3].ok, true);
  assert.equal(coreHost.state(), "unlocked");
});

test("the_whoami_port_says_what_the_router_would_see_and_grants_nothing", () => {
  const { fake, connectListeners } = hooksSetup();
  const [onConnect] = connectListeners;
  const ask = (/** @type {any} */ sender) => {
    const port = createPort(TEST_WHOAMI_PORT, sender);
    onConnect(port);
    return /** @type {any} */ (port.sent[0]);
  };
  const top = ask(extensionPageSender(fake, "pages/test-only/options.html"));
  assert.equal(top.isUiPort, true);
  assert.equal(top.isTopLevel, true);
  assert.equal(top.sender.frameId, 0);
  const framed = ask(extensionPageSender(fake, "pages/test-only/options.html", { frameId: 2, tab: { id: 4 } }));
  assert.equal(framed.isUiPort, false);
  assert.equal(framed.sender.tabId, 4);
  const foreign = ask({ id: "other@example", url: "moz-extension://other/x.html", frameId: 0 });
  assert.equal(foreign.isUiPort, false);
  // The answer has facts and verdicts only: no function, no way to ask for more.
  assert.deepEqual(Object.keys(top).sort(), ["isTopLevel", "isUiPort", "sender"]);
});

test("a_content_script_probe_gets_the_browsers_facts_and_other_messages_are_left_alone", async () => {
  const { fake, messageListeners } = hooksSetup();
  const [onMessage] = messageListeners;
  const sender = { id: fake.runtime.id, url: "https://example.com/login", origin: "https://example.com", tab: { id: 7 }, frameId: 0, documentId: "d1" };
  const answer = /** @type {any} */ (await onMessage({ ferretProbe: "sender" }, sender));
  assert.equal(answer.sender.origin, "https://example.com");
  assert.equal(answer.sender.documentId, "d1");
  assert.deepEqual(answer.contentSender, { tabId: 7, frameId: 0, documentId: "d1", url: "https://example.com/login" });
  assert.equal(onMessage({ ferretProbe: "other" }, sender), undefined);
  assert.equal(onMessage({ v: 1, id: "x", type: "frame_report", body: {} }, sender), undefined);
  assert.equal(onMessage(undefined, sender), undefined);
});

test("a_page_that_ends_without_a_logged_suspend_still_shows_as_a_restart", () => {
  const summary = summarize([
    { kind: "startup", at: 0, boot: "a" },
    { kind: "scenario_start", at: 10, boot: "a" },
    { kind: "startup", at: 58_000, boot: "b" },
    { kind: "heartbeat", at: 59_000, boot: "b" },
  ]);
  assert.equal(summary.firstSuspendAfterMs, null, "the browser's announcement was not logged");
  assert.equal(summary.restartAfterMs, 57_990, "but a new page started");
  assert.equal(summary.boots, 2);
});

test("the_suspend_marker_is_written_at_once_and_becomes_an_entry_at_the_next_start", async () => {
  const env = logEnvironment();
  const storage = createSessionStorage();
  /** @type {Map<string, string>} */
  const kept = new Map();
  const marker = { getItem: (/** @type {string} */ k) => kept.get(k) ?? null, setItem: (/** @type {string} */ k, /** @type {string} */ v) => { kept.set(k, v); }, removeItem: (/** @type {string} */ k) => { kept.delete(k); } };
  const clock = createClock(7000);
  startMeasureLog({ runtime: /** @type {any} */ (env.runtime), alarms: /** @type {any} */ (env.alarmsApi), storageLocal: storage, now: clock.now, core: () => "unlocked", boot: "old", marker });
  env.fireSuspend();
  // Before any write has finished: the marker is there, synchronously.
  assert.deepEqual(JSON.parse(/** @type {string} */ (kept.get("measure_suspend"))), { at: 7000, boot: "old" });

  // The page is gone before its own entry was written (a storage that never answers).
  const lost = createSessionStorage();
  clock.advance(30_000);
  const env2 = logEnvironment();
  const { log } = startMeasureLog({ runtime: /** @type {any} */ (env2.runtime), alarms: /** @type {any} */ (env2.alarmsApi), storageLocal: lost, now: clock.now, core: () => "locked", boot: "new", marker });
  await settle();
  await settle();
  const entries = await log.read();
  assert.deepEqual(entries.map((e) => [e.kind, e.boot, e.at, e.late ?? false]), [["startup", "new", 37_000, false], ["suspend", "old", 7000, true]]);
  assert.equal(kept.has("measure_suspend"), false, "the marker is used once");

  // When the old page did log its own entry, the marker adds nothing.
  kept.set("measure_suspend", JSON.stringify({ at: 7000, boot: "old" }));
  await lost.set({ measure_log: [{ kind: "suspend", at: 7000, boot: "old" }] });
  const env3 = logEnvironment();
  const { log: log3 } = startMeasureLog({ runtime: /** @type {any} */ (env3.runtime), alarms: /** @type {any} */ (env3.alarmsApi), storageLocal: lost, now: clock.now, core: () => "locked", boot: "third", marker });
  await settle();
  await settle();
  assert.deepEqual((await log3.read()).filter((e) => e.kind === "suspend").length, 1);

  // And a browser without localStorage, or a marker that is garbage, is not an error.
  startMeasureLog({ runtime: /** @type {any} */ (logEnvironment().runtime), alarms: /** @type {any} */ (logEnvironment().alarmsApi), storageLocal: createSessionStorage(), now: clock.now, core: () => "locked", boot: "x", marker: null });
  kept.set("measure_suspend", "{not json");
  startMeasureLog({ runtime: /** @type {any} */ (logEnvironment().runtime), alarms: /** @type {any} */ (logEnvironment().alarmsApi), storageLocal: createSessionStorage(), now: clock.now, core: () => "locked", boot: "y", marker });
  await settle();
});
