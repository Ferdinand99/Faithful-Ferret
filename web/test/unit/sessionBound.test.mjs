// The web vault's sync bound to the unlocked account (`flows/sessionBound.mjs`, spec Fase 1 § 8.8 "Two accounts in one
// browser"): another tab of the browser profile that signs in as another account changes the session under a tab that is
// open, and that tab must then neither write into the other account's vault nor read its feed as its own.
import assert from "node:assert/strict";
import { test } from "node:test";
import { ApiError } from "../../src/api.mjs";
import { SESSION_OTHER_ACCOUNT, SESSION_PATH, sessionBoundApi } from "../../src/flows/sessionBound.mjs";
import syncService from "../../src/services/sync.service.mjs";
import { createLiveChannel } from "../../src/sync/events.mjs";
import { outbox } from "../../src/store/outbox.mjs";
import { ACCOUNT, SERVER, VAULT } from "./idbHelpers.mjs";
import { createFakeApi, createFakeClient, createFakeStore, FakeLocks, Model, settle, until } from "./syncHelpers.mjs";

const OTHER = "ff".repeat(16);
const scope = { accountId: ACCOUNT, vaultId: VAULT, vkEpoch: 1 };

/** A stand-in API that logs every request and answers the session as `session.account`. */
function loggingApi() {
  const session = { account: ACCOUNT };
  /** @type {string[]} */
  const log = [];
  const api = {
    async get(/** @type {string} */ path) {
      log.push(`GET ${path}`);
      if (path === SESSION_PATH) {
        if (session.account === null) throw new ApiError(401, "unauthorized");
        return { account_id: session.account };
      }
      return { path };
    },
    async put(/** @type {string} */ path) {
      log.push(`PUT ${path}`);
      return { rev: 1 };
    },
    async post(/** @type {string} */ path) {
      log.push(`POST ${path}`);
      return { results: [] };
    },
  };
  return { api, session, log };
}

test("every_request_is_made_between_two_checks_of_the_session", async () => {
  const { api, log } = loggingApi();
  const bound = sessionBoundApi(api, ACCOUNT, () => assert.fail("the session is the account's"));
  assert.deepEqual(await bound.api.get("/api/sync/changes?since=0"), { path: "/api/sync/changes?since=0" });
  await bound.api.put("/api/sync/items/x");
  await bound.api.post("/api/sync/batch");
  assert.deepEqual(log, [
    `GET ${SESSION_PATH}`, "GET /api/sync/changes?since=0", `GET ${SESSION_PATH}`,
    `GET ${SESSION_PATH}`, "PUT /api/sync/items/x", `GET ${SESSION_PATH}`,
    `GET ${SESSION_PATH}`, "POST /api/sync/batch", `GET ${SESSION_PATH}`,
  ]);
  assert.equal(bound.other(), false);
});

test("a_session_of_another_account_sends_nothing_and_says_so_once", async () => {
  const { api, session, log } = loggingApi();
  let told = 0;
  const bound = sessionBoundApi(api, ACCOUNT, () => {
    told += 1;
  });
  session.account = OTHER;
  await assert.rejects(bound.api.put("/api/sync/items/x"), (error) => error instanceof ApiError && error.status === 401 && error.code === SESSION_OTHER_ACCOUNT);
  assert.deepEqual(log, [`GET ${SESSION_PATH}`], "the write never went out");
  assert.equal(told, 1);
  assert.equal(bound.other(), true);

  // From now on nothing reaches the server, not even the session check, and the page is not told again.
  session.account = ACCOUNT;
  await assert.rejects(bound.api.get("/api/sync/changes?since=0"), { code: SESSION_OTHER_ACCOUNT });
  await assert.rejects(bound.confirm(), { code: SESSION_OTHER_ACCOUNT });
  assert.deepEqual(log, [`GET ${SESSION_PATH}`]);
  assert.equal(told, 1);
});

test("an_answer_read_while_the_session_changed_is_not_used", async () => {
  const { api, session, log } = loggingApi();
  let told = 0;
  const bound = sessionBoundApi(api, ACCOUNT, () => {
    told += 1;
  });
  // The other tab signs in while the page of the feed is on its way: the page is dropped.
  const get = api.get;
  api.get = async (path) => {
    const answer = await get(path);
    if (path !== SESSION_PATH) session.account = OTHER;
    return answer;
  };
  await assert.rejects(bound.api.get("/api/sync/changes?since=0"), { code: SESSION_OTHER_ACCOUNT });
  assert.deepEqual(log, [`GET ${SESSION_PATH}`, "GET /api/sync/changes?since=0", `GET ${SESSION_PATH}`]);
  assert.equal(told, 1);
});

test("an_ended_session_or_a_network_failure_is_the_request_s_own_failure", async () => {
  const { api, session } = loggingApi();
  let told = 0;
  const bound = sessionBoundApi(api, ACCOUNT, () => {
    told += 1;
  });
  session.account = null;
  await assert.rejects(bound.api.get("/api/sync/changes?since=0"), { status: 401, code: "unauthorized" });
  api.get = async () => {
    throw new ApiError(0, "network");
  };
  await assert.rejects(bound.api.put("/api/sync/items/x"), { status: 0, code: "network" });
  assert.equal(told, 0, "neither is another account");
  assert.equal(bound.other(), false);
  assert.throws(() => sessionBoundApi(api, "", () => {}), TypeError);
});

/** The real sync service over a fake server and a fake store. */
async function service() {
  const store = await createFakeStore();
  const client = createFakeClient();
  const model = new Model();
  const api = createFakeApi(model);
  const sync = syncService.create({ api, store, client: { vault: client.vault }, serverUrl: SERVER, locks: new FakeLocks(), nav: { userAgent: "" } });
  return { sync, store, model, api };
}

test("the_engine_stops_and_keeps_its_outbox_when_the_session_becomes_another_account_s", async (t) => {
  const { sync, store, model, api } = await service();
  t.after(() => sync.stop());
  let told = 0;
  sync.onSessionOther(() => {
    told += 1;
  });
  /** @type {any[]} */
  const engines = [];
  sync.onEngine((engine) => engines.push(engine));
  let engine = await sync.start(scope);
  assert.ok(engine);
  const first = await engine.create({ item_type: "login", name: "Before" });
  await until(async () => model.items.has(first), "the first item on the server");
  await until(async () => (await outbox.all(await store.open(), scope)).length === 0, "the outbox empty");
  assert.ok(api.sessionGets > 0, "the session was checked");

  // Another tab signs in as another account: the profile's cookie is that account's now.
  api.sessionAccount = OTHER;
  const putsBefore = api.puts.length;
  const second = await engine.create({ item_type: "login", name: "After" });
  await until(async () => told === 1, "the page told");
  await settle();
  assert.equal(api.puts.length, putsBefore, "no write went out under the other account's session");
  assert.equal(model.items.has(second), false);
  assert.equal(sync.current(), null, "the engine is stopped");
  assert.equal(engines.at(-1), null, "and its end is announced");
  const kept = await outbox.all(await store.open(), scope);
  assert.deepEqual(kept.map((entry) => entry.itemId), [second], "the write waits in the outbox");
  await assert.rejects(sync.confirmSession(engine), { code: SESSION_OTHER_ACCOUNT });

  // The account signs in again: a new engine sends what waited, to its own vault.
  api.sessionAccount = ACCOUNT;
  engine = await sync.start(scope);
  assert.ok(engine);
  await until(async () => model.items.has(second), "the kept write on the server");
  await until(async () => (await outbox.all(await store.open(), scope)).length === 0, "the outbox empty again");
  assert.equal(told, 1);
  sync.stop();
});

test("no_checkpoint_or_feed_page_is_read_or_sent_under_another_account_s_session", async (t) => {
  const { sync, api } = await service();
  t.after(() => sync.stop());
  sync.onSessionOther(() => {});
  const engine = await sync.start(scope);
  assert.ok(engine);
  await engine.syncNow();
  api.sessionAccount = OTHER;
  const gets = api.gets.length;
  const checkpointGets = api.checkpointGets.length;
  const checkpointPuts = api.checkpointPuts.length;
  await engine.syncNow();
  await settle();
  assert.equal(api.gets.length, gets, "no page of the other account's feed");
  assert.equal(api.checkpointGets.length, checkpointGets);
  assert.equal(api.checkpointPuts.length, checkpointPuts);
  assert.equal(sync.current(), null);
  sync.stop();
});

/** A fake stream: `hello(seq)` sends a hello on the open stream. */
function oneStream() {
  /** @type {Array<{ push(text: string): void }>} */
  const opened = [];
  return {
    opened,
    stream: async () => {
      /** @type {((value: { done: boolean, value?: Uint8Array }) => void)[]} */
      const waiting = [];
      /** @type {Uint8Array[]} */
      const queued = [];
      opened.push({
        push(text) {
          const bytes = new TextEncoder().encode(text);
          const next = waiting.shift();
          if (next) next({ done: false, value: bytes });
          else queued.push(bytes);
        },
      });
      return /** @type {any} */ ({
        read: () => (queued.length > 0 ? Promise.resolve({ done: false, value: queued.shift() }) : new Promise((resolve) => waiting.push(resolve))),
        cancel: async () => {},
      });
    },
  };
}

test("the_live_channel_acts_on_a_connection_only_after_the_session_check", async (t) => {
  const streams = oneStream();
  /** @type {(number | null)[]} */
  const hints = [];
  /** @type {string[]} */
  const states = [];
  let answer = /** @type {null | (() => void)} */ (null);
  const channel = createLiveChannel({
    api: { stream: streams.stream },
    onHint: (seq) => void hints.push(seq),
    onState: (state) => void states.push(state),
    confirm: () => new Promise((resolve) => {
      answer = () => resolve(undefined);
    }),
    win: null,
  });
  t.after(() => channel.stop());
  channel.start();
  await settle();
  streams.opened[0].push("event: hello\ndata: {\"seq\":4}\n\n");
  await settle();
  assert.deepEqual(hints, [], "nothing is acted on before the check");
  assert.notEqual(channel.state(), "live");
  /** @type {() => void} */ (answer)();
  await settle();
  assert.deepEqual(hints, [4]);
  assert.equal(channel.state(), "live");
  channel.stop();
});

test("the_live_channel_stops_when_the_session_is_another_account_s", async (t) => {
  const streams = oneStream();
  /** @type {(number | null)[]} */
  const hints = [];
  const channel = createLiveChannel({
    api: { stream: streams.stream },
    onHint: (seq) => void hints.push(seq),
    confirm: async () => {
      throw new ApiError(401, SESSION_OTHER_ACCOUNT);
    },
    win: null,
  });
  t.after(() => channel.stop());
  channel.start();
  await settle();
  streams.opened[0].push("event: hello\ndata: {\"seq\":4}\n\n");
  await settle();
  assert.deepEqual(hints, [], "the hello of another account's stream is not acted on");
  assert.equal(channel.state(), "unauthorized");
  await settle();
  assert.equal(streams.opened.length, 1, "no new try");
  channel.stop();
});
