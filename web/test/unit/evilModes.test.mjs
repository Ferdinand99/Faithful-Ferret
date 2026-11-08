// The malicious server of the end-to-end stack (web/test/e2e-stack/evil): one
// test for every mode against a fake vault, and the promises that make the rig
// honest about itself: the honest mode changes nothing, no mode touches
// anything but the sync answers of the vault host, the event stream is not
// buffered, and the control port is a port of its own.
import assert from "node:assert/strict";
import { existsSync, readdirSync } from "node:fs";
import http from "node:http";
import { dirname, join } from "node:path";
import { after, describe, it } from "node:test";
import { fileURLToPath } from "node:url";
import { createRecorder } from "../e2e-stack/evil/recorder.mjs";
import { ModeError, MODE_NAMES, flipByte, parseMode } from "../e2e-stack/evil/modes.mjs";
import { createProxy } from "../e2e-stack/evil/proxy.mjs";

// ---------------------------------------------------------------- fixtures

/** A 32 digit item id. @param {number} n */
const id = (n) => n.toString(16).padStart(32, "0");
/** A base64url text of `len` bytes that all have the value `fill`. @param {number} len @param {number} fill */
const b64 = (len, fill) => Buffer.alloc(len, fill).toString("base64url");
const A = id(0xa);
const B = id(0xb);
const C = id(0xc);
const SID_A = "session-a-0123456789";
const SID_B = "session-b-0123456789";
const cookie = (/** @type {string} */ sid) => ({ cookie: `other=1; __Host-ferret_sid=${sid}; more=2` });

/** What a client sends for a live item. @param {number} base @param {number} fill */
const live = (base, fill) => ({ base_rev: base, blob: b64(64, fill), tag: b64(32, fill + 100), idem: b64(16, fill) });

/** A vault that answers like the real server for the routes the proxy reads. */
function fakeVault() {
  const state = {
    seq: 0,
    /** @type {Map<string, any>} */
    rows: new Map(),
    /** @type {any} */
    full: null,
    restoreEpoch: 3,
    restoreSeq: 7,
    /** @type {{ method: string, url: string, headers: http.IncomingHttpHeaders, body: Buffer }[]} */
    calls: [],
  };
  const sorted = (/** @type {(a: any, b: any) => number} */ cmp) => [...state.rows.values()].sort(cmp);
  /** @param {any} body @param {string} item */
  function put(item, body) {
    const cur = state.rows.get(item);
    if (body.base_rev !== (cur?.rev ?? 0)) {
      return { status: 409, json: { error: "conflict", current_rev: cur?.rev ?? 0, deleted: cur?.deleted ?? false, ...(cur && !cur.deleted ? { blob: cur.blob, tag: cur.tag } : {}) } };
    }
    const rev = body.base_rev + 1;
    state.seq += 1;
    state.rows.set(
      item,
      body.deleted ? { id: item, rev, seq: state.seq, deleted: true, tomb: body.tomb } : { id: item, rev, seq: state.seq, deleted: false, blob: body.blob, tag: body.tag },
    );
    return { status: 200, json: { rev, seq: state.seq, replayed: false } };
  }
  const head = () => (state.full ? { seq: state.full.seq, digest: state.full.digest, mac: state.full.mac } : null);
  /** @param {http.IncomingMessage} req @param {http.ServerResponse} res */
  function handler(req, res) {
    /** @type {Buffer[]} */
    const chunks = [];
    req.on("data", (c) => chunks.push(c));
    req.on("end", () => {
      const body = Buffer.concat(chunks);
      state.calls.push({ method: req.method ?? "", url: req.url ?? "", headers: req.headers, body });
      const url = new URL(req.url ?? "/", "http://fake.invalid");
      const q = url.searchParams;
      /** @type {{ status: number, json: any }} */
      let out = { status: 404, json: { error: "not_found" } };
      if (req.method === "GET" && url.pathname === "/api/sync/changes") {
        const since = Number(q.get("since") ?? 0);
        const limit = Number(q.get("limit") ?? 100);
        const newer = sorted((a, b) => a.seq - b.seq).filter((r) => r.seq > since);
        out = {
          status: 200,
          json: { changes: newer.slice(0, limit), latest_seq: state.seq, vk_epoch: 1, restore_epoch: state.restoreEpoch, restore_seq: state.restoreSeq, ...(head() ? { checkpoint: head() } : {}), has_more: newer.length > limit },
        };
      } else if (req.method === "GET" && url.pathname === "/api/sync/items") {
        const after = q.get("after") ?? "";
        const limit = Number(q.get("limit") ?? 100);
        const rest = sorted((a, b) => (a.id < b.id ? -1 : 1)).filter((r) => r.id > after);
        const page = rest.slice(0, limit);
        out = {
          status: 200,
          json: { items: page, as_of_seq: state.seq, vk_epoch: 1, restore_epoch: state.restoreEpoch, restore_seq: state.restoreSeq, ...(rest.length > limit ? { next_after: page[page.length - 1].id } : {}), has_more: rest.length > limit },
        };
      } else if (req.method === "GET" && url.pathname === "/api/sync/checkpoint") {
        out = state.full ? { status: 200, json: state.full } : { status: 404, json: { error: "not_found" } };
      } else if (req.method === "PUT" && url.pathname === "/api/sync/checkpoint") {
        state.full = JSON.parse(body.toString("utf8"));
        out = { status: 200, json: { seq: state.full.seq } };
      } else if (req.method === "PUT" && url.pathname.startsWith("/api/sync/items/")) {
        out = put(url.pathname.slice("/api/sync/items/".length), JSON.parse(body.toString("utf8")));
      } else if (req.method === "POST" && url.pathname === "/api/sync/batch") {
        const { ops } = JSON.parse(body.toString("utf8"));
        out = { status: 200, json: { results: ops.map((/** @type {any} */ op) => { const r = put(op.id, op); return r.status === 200 ? { status: 200, ...r.json } : { status: 409, ...r.json }; }) } };
      }
      const text = Buffer.from(JSON.stringify(out.json));
      res.writeHead(out.status, { "content-type": "application/json", "content-length": text.length });
      res.end(text);
    });
  }
  return { state, handler };
}

/** @param {(req: http.IncomingMessage, res: http.ServerResponse) => void} handler */
async function listen(handler) {
  const server = http.createServer(handler);
  await new Promise((resolve) => server.listen(0, "127.0.0.1", () => resolve(undefined)));
  return { server, port: /** @type {import("node:net").AddressInfo} */ (server.address()).port };
}

/**
 * An HTTP call without a connection pool.
 * @param {number} port @param {string} method @param {string} path
 * @param {{ headers?: Record<string, string>, body?: string | Buffer }} [options]
 * @returns {Promise<{ status: number, headers: http.IncomingHttpHeaders, raw: string[], body: Buffer }>}
 */
function call(port, method, path, { headers = {}, body } = {}) {
  return new Promise((resolve, reject) => {
    const req = http.request({ host: "127.0.0.1", port, method, path, headers, agent: false }, (res) => {
      /** @type {Buffer[]} */
      const chunks = [];
      res.on("data", (c) => chunks.push(c));
      res.on("end", () => resolve({ status: res.statusCode ?? 0, headers: res.headers, raw: res.rawHeaders, body: Buffer.concat(chunks) }));
      res.on("error", reject);
    });
    req.on("error", reject);
    req.end(body);
  });
}

/** Both fake servers, the proxy in front of them, and the clock the proxy uses. */
async function rig() {
  const vault = fakeVault();
  const adminFake = fakeVault();
  const upVault = await listen(vault.handler);
  const upAdmin = await listen(adminFake.handler);
  const clock = { t: 1_000_000 };
  const proxy = createProxy({
    upstreamVault: `http://127.0.0.1:${upVault.port}`,
    upstreamAdmin: `http://127.0.0.1:${upAdmin.port}`,
    now: () => clock.t,
    random: (n) => new Uint8Array(n).fill(7),
  });
  const ports = await proxy.listen({ host: "127.0.0.1", vaultPort: 0, adminPort: 0, controlPort: 0 });
  const json = async (/** @type {Promise<{ body: Buffer }>} */ p) => JSON.parse((await p).body.toString("utf8"));
  return {
    vault,
    upVaultPort: upVault.port,
    upAdminPort: upAdmin.port,
    clock,
    proxy,
    ports,
    /** Switches a mode on through the control port. @param {string} mode @param {object} [params] */
    async mode(mode, params = {}) {
      const r = await call(ports.control, "POST", "/mode", { headers: { "content-type": "application/json" }, body: JSON.stringify({ mode, ...params }) });
      assert.equal(r.status, 200, r.body.toString());
    },
    /** A write through the proxy, as a session. @param {string} item @param {object} body @param {string} [sid] */
    async put(item, body, sid = SID_A) {
      const r = await call(ports.vault, "PUT", `/api/sync/items/${item}`, { headers: { "content-type": "application/json", ...cookie(sid) }, body: JSON.stringify(body) });
      assert.equal(r.status, 200, r.body.toString());
      return JSON.parse(r.body.toString("utf8"));
    },
    /** @param {string} path @param {string} [sid] */
    get: (path, sid = SID_A) => json(call(ports.vault, "GET", path, { headers: cookie(sid) })),
    async close() {
      await proxy.close();
      upVault.server.closeAllConnections();
      upAdmin.server.closeAllConnections();
      await Promise.all([upVault, upAdmin].map((u) => new Promise((resolve) => u.server.close(() => resolve(undefined)))));
    },
  };
}

/** @param {any[]} rows @param {string} item */
const rowOf = (rows, item) => rows.find((r) => r.id === item);

// -------------------------------------------------------------------- tests

describe("evil modes", () => {
  it("swap_blobs_swaps_blob_and_tag_and_nothing_else", async () => {
    const r = await rig();
    after(() => r.close());
    await r.put(A, live(0, 1));
    await r.put(B, live(0, 2));
    await r.put(C, live(0, 3));
    const honest = await r.get("/api/sync/changes?since=0");
    await r.mode("swap_blobs", { a: A, b: B });
    const lie = await r.get("/api/sync/changes?since=0");
    assert.equal(rowOf(lie.changes, A).blob, rowOf(honest.changes, B).blob);
    assert.equal(rowOf(lie.changes, A).tag, rowOf(honest.changes, B).tag);
    assert.equal(rowOf(lie.changes, B).blob, rowOf(honest.changes, A).blob);
    assert.equal(rowOf(lie.changes, B).tag, rowOf(honest.changes, A).tag);
    // Nothing else changed: the ids, revisions and sequence numbers, the third item, the envelope.
    const strip = (/** @type {any} */ x) => ({ ...x, changes: x.changes.map((/** @type {any} */ c) => ({ ...c, blob: undefined, tag: undefined })) });
    assert.deepEqual(strip(lie), strip(honest));
    assert.deepEqual(rowOf(lie.changes, C), rowOf(honest.changes, C));
    // The listing is lied to in the same way.
    const items = await r.get("/api/sync/items");
    assert.equal(rowOf(items.items, A).blob, rowOf(honest.changes, B).blob);
    // A page that has only one of the two gets the other's newest body from what was seen.
    const one = await r.get("/api/sync/changes?since=1");
    assert.equal(one.changes.length, 2);
    await r.put(A, live(1, 9));
    const only = await r.get("/api/sync/changes?since=3");
    assert.deepEqual(only.changes.map((/** @type {any} */ c) => c.id), [A]);
    assert.equal(only.changes[0].blob, rowOf(honest.changes, B).blob);
  });

  it("replay_old_shows_the_first_version_that_was_seen_at_the_place_of_the_real_row", async () => {
    const r = await rig();
    after(() => r.close());
    await r.put(A, live(0, 1));
    await r.put(B, live(0, 2));
    await r.put(A, live(1, 5));
    await r.put(A, live(2, 6));
    const honest = await r.get("/api/sync/changes?since=0");
    assert.equal(rowOf(honest.changes, A).rev, 3);
    await r.mode("replay_old", { id: A });
    const lie = await r.get("/api/sync/changes?since=0");
    const old = rowOf(lie.changes, A);
    assert.equal(old.rev, 1);
    assert.equal(old.blob, b64(64, 1));
    assert.equal(old.tag, b64(32, 101));
    assert.equal(old.seq, rowOf(honest.changes, A).seq, "the old row sits where the real one is");
    assert.deepEqual(rowOf(lie.changes, B), rowOf(honest.changes, B));
    assert.equal((await r.get("/api/sync/items")).items.find((/** @type {any} */ i) => i.id === A).rev, 1);
    // An item that has had one version only is not changed.
    await r.mode("replay_old", { id: B });
    assert.deepEqual(rowOf((await r.get("/api/sync/changes?since=0")).changes, B), rowOf(honest.changes, B));
  });

  it("hide_removes_the_rows_of_one_item_and_leaves_the_conflict_answer_honest", async () => {
    const r = await rig();
    after(() => r.close());
    await r.put(A, live(0, 1));
    await r.put(B, live(0, 2));
    const honest = await r.get("/api/sync/changes?since=0");
    await r.mode("hide", { id: A });
    const lie = await r.get("/api/sync/changes?since=0");
    assert.deepEqual(lie.changes.map((/** @type {any} */ c) => c.id), [B]);
    assert.equal(lie.latest_seq, honest.latest_seq, "the cursor still moves on");
    assert.deepEqual((await r.get("/api/sync/items")).items.map((/** @type {any} */ i) => i.id), [B]);
    // The real server still has the row, and says so when it is written again.
    const conflict = await call(r.ports.vault, "PUT", `/api/sync/items/${A}`, { headers: { "content-type": "application/json", ...cookie(SID_A) }, body: JSON.stringify(live(0, 8)) });
    assert.equal(conflict.status, 409);
    const body = JSON.parse(conflict.body.toString("utf8"));
    assert.equal(body.blob, b64(64, 1));
    assert.equal(body.tag, b64(32, 101));
  });

  it("gone_answers_410_only_for_since_above_0", async () => {
    const r = await rig();
    after(() => r.close());
    await r.put(A, live(0, 1));
    await r.put(B, live(0, 2));
    // A floor that is asked for: 410 for 0 < since < floor, as the real server does.
    await r.mode("gone", { min_valid_since: 5 });
    const before = r.vault.state.calls.length;
    const ask = (/** @type {string} */ path) => call(r.ports.vault, "GET", path, { headers: cookie(SID_A) });
    assert.equal((await ask("/api/sync/changes?since=0")).status, 200);
    assert.equal((await ask("/api/sync/changes")).status, 200);
    const gone = await ask("/api/sync/changes?since=1&limit=50");
    assert.equal(gone.status, 410);
    assert.deepEqual(JSON.parse(gone.body.toString("utf8")), { error: "gone", min_valid_since: 5 });
    assert.equal((await ask("/api/sync/changes?since=4")).status, 410);
    assert.equal((await ask("/api/sync/changes?since=5")).status, 200, "at the floor is not below it");
    assert.equal(r.vault.state.calls.length, before + 3, "the real server is not asked for the two 410s");
    // The full listing is never 410.
    assert.equal((await ask("/api/sync/items")).status, 200);
    // Other modes never answer 410.
    await r.mode("honest");
    assert.equal((await ask("/api/sync/changes?since=1")).status, 200);
  });

  it("gone_floor_is_the_top_seen_so_a_client_resuming_from_as_of_seq_settles", async () => {
    const r = await rig();
    after(() => r.close());
    await r.put(A, live(0, 1));
    await r.put(B, live(0, 2));
    await r.get("/api/sync/changes?since=0");
    // The floor was fixed when the mode was switched on: the highest seq seen (2).
    await r.mode("gone");
    const ask = (/** @type {string} */ path) => call(r.ports.vault, "GET", path, { headers: cookie(SID_A) });
    const early = await ask("/api/sync/changes?since=1");
    assert.equal(early.status, 410);
    assert.equal(JSON.parse(early.body.toString("utf8")).min_valid_since, 2);
    const listing = await r.get("/api/sync/items");
    assert.equal(listing.as_of_seq, 2);
    // The client goes on from the as_of_seq of its listing: that is not below the floor.
    assert.equal((await ask(`/api/sync/changes?since=${listing.as_of_seq}`)).status, 200);
    // And a later write moves nothing: the floor stays where it was.
    await r.put(C, live(0, 3));
    assert.equal((await ask("/api/sync/changes?since=2")).status, 200);
    assert.equal((await ask("/api/sync/changes?since=1")).status, 410);
    // A floor above the as_of_seq of the listing: the second 410 ends the pass in gone.
    await r.mode("gone", { min_valid_since: 500 });
    const listed = await r.get("/api/sync/items");
    assert.equal((await ask(`/api/sync/changes?since=${listed.as_of_seq}`)).status, 410);
    assert.equal((await ask(`/api/sync/changes?since=${listed.as_of_seq}`)).status, 410, "again: the pass ends in gone");
  });

  it("gone_with_hide_gives_the_order_410_then_a_listing_without_the_item_then_a_409_with_an_equal_blob", async () => {
    const r = await rig();
    after(() => r.close());
    await r.put(A, live(0, 1));
    await r.put(B, live(0, 2));
    const honestItems = await r.get("/api/sync/items");
    await r.mode("gone", { min_valid_since: 500, hide: A });
    const ask = (/** @type {string} */ path) => call(r.ports.vault, "GET", path, { headers: cookie(SID_A) });
    // 1. the 410 for a client that is caught up
    assert.equal((await ask("/api/sync/changes?since=2")).status, 410);
    // 2. the listing leaves the item out (and the rest is untouched)
    const items = await r.get("/api/sync/items");
    assert.deepEqual(items.items.map((/** @type {any} */ i) => i.id), [B]);
    assert.deepEqual(items.items[0], rowOf(honestItems.items, B));
    assert.equal(items.as_of_seq, honestItems.as_of_seq);
    const changes = await r.get("/api/sync/changes?since=0");
    assert.deepEqual(changes.changes.map((/** @type {any} */ c) => c.id), [B]);
    // 3. the upload of the item that the client then keeps meets the real row: 409 with the very same blob and tag
    const conflict = await call(r.ports.vault, "PUT", `/api/sync/items/${A}`, { headers: { "content-type": "application/json", ...cookie(SID_A) }, body: JSON.stringify(live(0, 1)) });
    assert.equal(conflict.status, 409);
    const body = JSON.parse(conflict.body.toString("utf8"));
    assert.equal(body.blob, rowOf(honestItems.items, A).blob);
    assert.equal(body.tag, rowOf(honestItems.items, A).tag);
    // The parameters are checked: the hidden item is an item id.
    const refused = await call(r.ports.control, "POST", "/mode", { headers: { "content-type": "application/json" }, body: JSON.stringify({ mode: "gone", hide: "x" }) });
    assert.equal(refused.status, 400);
  });

  it("rollback_and_fork_answer_404_for_a_checkpoint_that_their_state_does_not_hold", async () => {
    const r = await rig();
    after(() => r.close());
    await r.put(A, live(0, 1));
    r.clock.t += 1000;
    const early = r.clock.t;
    r.clock.t += 1000;
    await call(r.ports.vault, "PUT", "/api/sync/checkpoint", { headers: { "content-type": "application/json", ...cookie(SID_B) }, body: JSON.stringify({ seq: 1, digest: b64(32, 1), mac: b64(32, 2), entries: b64(56, 3) }) });
    // Before the checkpoint existed: no checkpoint, in the head and in the body, while the real server has one.
    await r.mode("rollback", { at: early });
    assert.equal((await call(r.ports.vault, "GET", "/api/sync/checkpoint", { headers: cookie(SID_A) })).status, 404);
    assert.ok(!("checkpoint" in (await r.get("/api/sync/changes?since=0"))));
    // A fork frozen before the checkpoint was uploaded by another session: the same.
    await r.mode("fork", { sid: SID_A });
    // (the fork is frozen now, after the checkpoint; so the session sees it)
    assert.equal((await call(r.ports.vault, "GET", "/api/sync/checkpoint", { headers: cookie(SID_A) })).status, 200);
    // A second fork on a vault that has none: it is frozen before any checkpoint.
    const r2 = await rig();
    after(() => r2.close());
    await r2.put(A, live(0, 1));
    await r2.mode("fork", { sid: SID_A });
    r2.clock.t += 1000;
    await call(r2.ports.vault, "PUT", "/api/sync/checkpoint", { headers: { "content-type": "application/json", ...cookie(SID_B) }, body: JSON.stringify({ seq: 1, digest: b64(32, 1), mac: b64(32, 2), entries: b64(56, 3) }) });
    assert.equal((await call(r2.ports.vault, "GET", "/api/sync/checkpoint", { headers: cookie(SID_A) })).status, 404);
    assert.equal((await call(r2.ports.vault, "GET", "/api/sync/checkpoint", { headers: cookie(SID_B) })).status, 200);
  });

  it("a_forked_session_keeps_its_checkpoint_in_its_own_branch_and_the_real_server_never_gets_it", async () => {
    const r = await rig();
    after(() => r.close());
    await r.put(A, live(0, 1));
    await r.mode("fork", { sid: SID_A });
    const upload = (/** @type {number} */ seq, /** @type {string} */ sid, /** @type {number} */ fill) =>
      call(r.ports.vault, "PUT", "/api/sync/checkpoint", { headers: { "content-type": "application/json", ...cookie(sid) }, body: JSON.stringify({ seq, digest: b64(32, fill), mac: b64(32, fill + 1), entries: b64(56, fill + 2) }) });
    const forked = await upload(1, SID_A, 10);
    assert.equal(forked.status, 200);
    assert.deepEqual(JSON.parse(forked.body.toString("utf8")), { seq: 1 });
    assert.equal(r.vault.state.full, null, "not sent on");
    assert.equal(r.vault.state.calls.some((c) => c.method === "PUT" && c.url === "/api/sync/checkpoint"), false);
    // The session reads it back, in the body and in the head of the feed.
    const mine = await r.get("/api/sync/checkpoint", SID_A);
    assert.equal(mine.mac, b64(32, 11));
    assert.deepEqual((await r.get("/api/sync/changes?since=0", SID_A)).checkpoint, { seq: 1, digest: b64(32, 10), mac: b64(32, 11) });
    // A lower seq than its own branch holds is stale, as at the real server.
    r.clock.t += 1000;
    assert.equal((await upload(3, SID_A, 20)).status, 200);
    const stale = await upload(2, SID_A, 30);
    assert.equal(stale.status, 409);
    assert.deepEqual(JSON.parse(stale.body.toString("utf8")), { error: "checkpoint_stale", stored_seq: 3 });
    // Another session's upload goes to the real server as usual, and the real head never reaches the fork.
    assert.equal((await upload(1, SID_B, 40)).status, 200);
    assert.equal(r.vault.state.full.seq, 1);
    assert.equal((await r.get("/api/sync/checkpoint", SID_A)).seq, 3);
    assert.equal((await r.get("/api/sync/checkpoint", SID_B)).mac, b64(32, 41));
  });

  it("fake_tombstone_turns_a_live_row_into_a_tombstone_with_a_higher_rev_and_40_random_bytes", async () => {
    const r = await rig();
    after(() => r.close());
    await r.put(A, live(0, 1));
    await r.put(B, live(0, 2));
    const honest = await r.get("/api/sync/changes?since=0");
    await r.mode("fake_tombstone", { id: A });
    const lie = await r.get("/api/sync/changes?since=0");
    const fake = rowOf(lie.changes, A);
    assert.deepEqual(Object.keys(fake), ["id", "rev", "seq", "deleted", "tomb"]);
    assert.equal(fake.deleted, true);
    assert.equal(fake.rev, rowOf(honest.changes, A).rev + 1);
    assert.equal(fake.seq, rowOf(honest.changes, A).seq);
    assert.equal(Buffer.from(fake.tomb, "base64url").length, 40);
    assert.deepEqual(rowOf(lie.changes, B), rowOf(honest.changes, B));
    // The same lie every time; and the listing has it too.
    assert.deepEqual(rowOf((await r.get("/api/sync/changes?since=0")).changes, A), fake);
    assert.deepEqual(rowOf((await r.get("/api/sync/items")).items, A), fake);
    // A row that already is a tombstone is left alone.
    await r.put(B, { base_rev: 1, deleted: true, tomb: b64(40, 4), idem: b64(16, 4) });
    await r.mode("fake_tombstone", { id: B });
    assert.equal(rowOf((await r.get("/api/sync/changes?since=0")).changes, B).tomb, b64(40, 4));
  });

  it("seq_lie_rewrites_latest_seq_only", async () => {
    const r = await rig();
    after(() => r.close());
    await r.put(A, live(0, 1));
    await r.put(B, live(0, 2));
    const honest = await r.get("/api/sync/changes?since=0");
    for (const latest of [0, 1, 7, 9_000_000]) {
      await r.mode("seq_lie", { latest_seq: latest });
      const lie = await r.get("/api/sync/changes?since=0");
      assert.equal(lie.latest_seq, latest);
      assert.deepEqual({ ...lie, latest_seq: honest.latest_seq }, honest);
    }
    assert.equal((await r.get("/api/sync/items")).as_of_seq, honest.latest_seq, "the listing is not touched");
  });

  it("rollback_shows_the_state_that_was_seen_at_the_time_and_keeps_restore_epoch", async () => {
    const r = await rig();
    after(() => r.close());
    await r.put(A, live(0, 1));
    await r.put(B, live(0, 2));
    await call(r.ports.vault, "PUT", "/api/sync/checkpoint", { headers: { "content-type": "application/json", ...cookie(SID_A) }, body: JSON.stringify({ seq: 2, digest: b64(32, 1), mac: b64(32, 2), entries: b64(56, 3) }) });
    r.clock.t += 10_000;
    const at = r.clock.t;
    r.clock.t += 10_000;
    await r.put(A, live(1, 5));
    await r.put(C, live(0, 3));
    await r.put(B, { base_rev: 1, deleted: true, tomb: b64(40, 4), idem: b64(16, 4) });
    await call(r.ports.vault, "PUT", "/api/sync/checkpoint", { headers: { "content-type": "application/json", ...cookie(SID_A) }, body: JSON.stringify({ seq: 5, digest: b64(32, 6), mac: b64(32, 7), entries: b64(56, 8) }) });
    const honest = await r.get("/api/sync/changes?since=0");
    assert.equal(honest.latest_seq, 5);
    await r.mode("rollback", { at });
    const lie = await r.get("/api/sync/changes?since=0");
    assert.equal(lie.latest_seq, 2);
    assert.equal(lie.restore_epoch, 3, "a rollback is not a restore");
    assert.equal(lie.vk_epoch, honest.vk_epoch);
    assert.deepEqual(lie.changes.map((/** @type {any} */ c) => [c.id, c.rev, c.deleted]), [[A, 1, false], [B, 1, false]]);
    assert.equal(rowOf(lie.changes, A).blob, b64(64, 1));
    assert.deepEqual(lie.checkpoint, { seq: 2, digest: b64(32, 1), mac: b64(32, 2) });
    assert.equal(lie.has_more, false);
    // A client that is further on asks for what is newer and hears nothing, and a lower top.
    const ahead = await r.get("/api/sync/changes?since=5");
    assert.deepEqual(ahead.changes, []);
    assert.equal(ahead.latest_seq, 2);
    const items = await r.get("/api/sync/items");
    assert.deepEqual(items.items.map((/** @type {any} */ i) => i.id), [A, B]);
    assert.equal(items.as_of_seq, 2);
    assert.equal(items.restore_epoch, 3);
    const checkpoint = await r.get("/api/sync/checkpoint");
    assert.equal(checkpoint.seq, 2);
    // Pages follow the limit.
    const page = await r.get("/api/sync/changes?since=0&limit=1");
    assert.equal(page.changes.length, 1);
    assert.equal(page.has_more, true);
  });

  it("fork_freezes_the_state_for_one_session_and_gives_the_others_the_live_one", async () => {
    const r = await rig();
    after(() => r.close());
    await r.put(A, live(0, 1));
    r.clock.t += 1000;
    await r.mode("fork", { sid: SID_A.slice(0, 12) });
    r.clock.t += 1000;
    await r.put(B, live(0, 2), SID_B);
    await r.put(A, live(1, 5), SID_B);
    const seenByA = await r.get("/api/sync/changes?since=0", SID_A);
    assert.deepEqual(seenByA.changes.map((/** @type {any} */ c) => [c.id, c.rev]), [[A, 1]]);
    assert.equal(seenByA.latest_seq, 1);
    const seenByB = await r.get("/api/sync/changes?since=0", SID_B);
    assert.deepEqual(seenByB.changes.map((/** @type {any} */ c) => [c.id, c.rev]), [[B, 1], [A, 2]]);
    assert.equal(seenByB.latest_seq, 3);
    // What the forked session writes itself stays in its own view (a fork that is not noticed).
    await r.put(C, live(0, 3), SID_A);
    const again = await r.get("/api/sync/changes?since=0", SID_A);
    assert.deepEqual(again.changes.map((/** @type {any} */ c) => c.id).sort(), [A, C]);
    assert.ok(!again.changes.some((/** @type {any} */ c) => c.id === B), "what the others wrote is not in it");
    // A session that has no cookie or another one is not forked.
    assert.equal((await call(r.ports.vault, "GET", "/api/sync/changes?since=0")).body.toString().includes(B), true);
  });

  it("forge_checkpoint_flips_one_byte_of_mac_or_entries", async () => {
    const r = await rig();
    after(() => r.close());
    await r.put(A, live(0, 1));
    const sent = { seq: 1, digest: b64(32, 1), mac: b64(32, 2), entries: b64(56, 3) };
    await call(r.ports.vault, "PUT", "/api/sync/checkpoint", { headers: { "content-type": "application/json", ...cookie(SID_A) }, body: JSON.stringify(sent) });
    const differing = (/** @type {string} */ x, /** @type {string} */ y) => {
      const p = Buffer.from(x, "base64url");
      const q = Buffer.from(y, "base64url");
      assert.equal(p.length, q.length);
      return p.filter((byte, i) => byte !== q[i]).length;
    };
    await r.mode("forge_checkpoint");
    const forged = await r.get("/api/sync/checkpoint");
    assert.equal(differing(forged.mac, sent.mac), 1);
    assert.equal(forged.entries, sent.entries);
    assert.equal(forged.digest, sent.digest);
    assert.equal(forged.seq, 1);
    const head = (await r.get("/api/sync/changes?since=0")).checkpoint;
    assert.equal(differing(head.mac, sent.mac), 1);
    assert.equal(head.digest, sent.digest);
    await r.mode("forge_checkpoint", { field: "entries" });
    const entries = await r.get("/api/sync/checkpoint");
    assert.equal(differing(entries.entries, sent.entries), 1);
    assert.equal(entries.mac, sent.mac);
    assert.equal((await r.get("/api/sync/changes?since=0")).checkpoint.mac, sent.mac, "the head has no entries to forge");
    assert.equal(flipByte(flipByte(sent.mac)), sent.mac);
  });

  it("drop_checkpoint_head_removes_the_head_from_changes_only", async () => {
    const r = await rig();
    after(() => r.close());
    await r.put(A, live(0, 1));
    await call(r.ports.vault, "PUT", "/api/sync/checkpoint", { headers: { "content-type": "application/json", ...cookie(SID_A) }, body: JSON.stringify({ seq: 1, digest: b64(32, 1), mac: b64(32, 2), entries: b64(56, 3) }) });
    const honest = await r.get("/api/sync/changes?since=0");
    assert.ok(honest.checkpoint);
    await r.mode("drop_checkpoint_head");
    const lie = await r.get("/api/sync/changes?since=0");
    assert.ok(!("checkpoint" in lie));
    const { checkpoint, ...rest } = honest;
    assert.ok(checkpoint);
    assert.deepEqual(lie, rest);
    assert.equal((await r.get("/api/sync/checkpoint")).seq, 1, "the checkpoint itself is still served");
  });

  it("every_mode_passes_restore_seq_through_on_changes_and_items", async () => {
    const r = await rig();
    after(() => r.close());
    await r.put(A, live(0, 1));
    await r.put(B, live(0, 2));
    await call(r.ports.vault, "PUT", "/api/sync/checkpoint", { headers: { "content-type": "application/json", ...cookie(SID_A) }, body: JSON.stringify({ seq: 2, digest: b64(32, 1), mac: b64(32, 2), entries: b64(56, 3) }) });
    r.vault.state.restoreSeq = 41; // what the real server froze at the last restore bump: no mode invents or drops it
    const modes = [
      ["honest", {}],
      ["swap_blobs", { a: A, b: B }],
      ["replay_old", { id: A }],
      ["hide", { id: A }],
      ["gone", { hide: A }],
      ["fake_tombstone", { id: A }],
      ["seq_lie", { latest_seq: 9 }],
      ["rollback", { at: r.clock.t + 1 }],
      ["fork", { sid: SID_A }],
      ["forge_checkpoint", {}],
      ["drop_checkpoint_head", {}],
    ];
    for (const [mode, params] of modes) {
      await r.mode(/** @type {string} */ (mode), /** @type {object} */ (params));
      const changes = await r.get("/api/sync/changes?since=0");
      const items = await r.get("/api/sync/items");
      assert.equal(changes.restore_seq, 41, `${mode}: /changes carries restore_seq`);
      assert.equal(items.restore_seq, 41, `${mode}: /items carries restore_seq`);
    }
  });

  it("honest_mode_is_byte_identical", async () => {
    // An upstream with answers that no JSON writer would produce: odd spacing and key order, other statuses.
    const answers = new Map([
      ["/api/sync/changes?since=0", [200, ' { "has_more" : false,\n "changes":[ ] , "latest_seq":0,"vk_epoch":1,"restore_epoch":0 }\n']],
      ["/api/sync/items?limit=5", [200, '{"as_of_seq":0,"items":[],"has_more":false,"vk_epoch":1,"restore_epoch":0}   ']],
      ["/api/sync/checkpoint", [404, '{ "error" : "not_found" }']],
      ["/api/sync/changes?since=zzz", [400, '{"error":"bad_request"}']],
      ["/api/sync/other", [500, "not json at all \u0000ÿ"]],
      ["/plain", [200, "plain text"]],
    ]);
    const seen = /** @type {{ headers: http.IncomingHttpHeaders, body: Buffer }[]} */ ([]);
    const up = await listen((req, res) => {
      /** @type {Buffer[]} */
      const chunks = [];
      req.on("data", (c) => chunks.push(c));
      req.on("end", () => {
        seen.push({ headers: req.headers, body: Buffer.concat(chunks) });
        const [status, text] = answers.get(req.url ?? "") ?? [200, "echo"];
        res.writeHead(/** @type {number} */ (status), { "content-type": "application/json", "x-extra": "kept", date: "Sun, 01 Jan 2034 00:00:00 GMT", "set-cookie": ["a=1; Path=/", "b=2; Path=/"] });
        res.end(Buffer.from(/** @type {string} */ (text), "latin1"));
      });
    });
    const proxy = createProxy({ upstreamVault: `http://127.0.0.1:${up.port}`, upstreamAdmin: `http://127.0.0.1:${up.port}` });
    const ports = await proxy.listen({ host: "127.0.0.1", vaultPort: 0, adminPort: 0, controlPort: 0 });
    after(async () => {
      await proxy.close();
      up.server.closeAllConnections();
      up.server.close();
    });
    const hop = new Set(["connection", "keep-alive", "transfer-encoding", "content-length"]);
    const names = (/** @type {string[]} */ raw) => raw.filter((_, i) => i % 2 === 0).map((n) => n.toLowerCase()).filter((n) => !hop.has(n)).sort();
    for (const [path] of answers) {
      const direct = await call(up.port, "GET", path);
      const proxied = await call(ports.vault, "GET", path);
      assert.equal(proxied.status, direct.status, path);
      assert.deepEqual(proxied.body, direct.body, path);
      assert.deepEqual(names(proxied.raw), names(direct.raw), path);
      for (const name of ["content-type", "x-extra", "date", "set-cookie"]) assert.deepEqual(proxied.headers[name], direct.headers[name], `${path} ${name}`);
    }
    // The request goes on as it was: the bytes of the body and the headers (the cookie, the forwarding headers of the terminator).
    const odd = Buffer.from('{ "base_rev" :0,\n"blob":"AA" , "tag":"BB","idem":"CC" }');
    const headers = { "content-type": "application/json", "x-forwarded-for": "10.9.8.7", "x-forwarded-proto": "https", origin: "https://vault-e2e.test", ...cookie(SID_A) };
    seen.length = 0;
    await call(up.port, "PUT", `/api/sync/items/${A}`, { headers, body: odd });
    await call(ports.vault, "PUT", `/api/sync/items/${A}`, { headers, body: odd });
    assert.equal(seen.length, 2);
    assert.deepEqual(seen[1].body, seen[0].body);
    for (const name of ["content-type", "x-forwarded-for", "x-forwarded-proto", "origin", "cookie", "content-length"]) {
      assert.equal(seen[1].headers[name], seen[0].headers[name], name);
    }
    // The host header is the one the client wrote (the name the terminator was asked for), not the proxy's own.
    assert.equal(seen[1].headers.host, `127.0.0.1:${ports.vault}`);
  });

  it("modes_never_touch_non_sync_paths_or_the_admin_host", async () => {
    const r = await rig();
    after(() => r.close());
    await r.put(A, live(0, 1));
    await r.put(B, live(0, 2));
    // The admin listener holds the same rows, so that a reshaped answer would differ from the real one.
    for (const [item, fill] of [[A, 1], [B, 2]]) {
      const sent = await call(r.upAdminPort, "PUT", `/api/sync/items/${item}`, { headers: { "content-type": "application/json" }, body: JSON.stringify(live(0, /** @type {number} */ (fill))) });
      assert.equal(sent.status, 200);
    }
    // The sync paths on the admin host, and paths that only look like the sync API, on both hosts.
    const paths = ["/api/sync/changes?since=1", "/api/sync/changes?since=0", "/api/sync/items", "/api/sync/checkpoint", "/api/syncing/changes?since=1", "/api/auth/session", "/healthz", "/sync/changes?since=1"];
    const modes = /** @type {[string, object][]} */ ([
      ["swap_blobs", { a: A, b: B }],
      ["replay_old", { id: A }],
      ["hide", { id: A }],
      ["gone", {}],
      ["fake_tombstone", { id: A }],
      ["seq_lie", { latest_seq: 99 }],
      ["rollback", { at: 0 }],
      ["fork", { sid: SID_A }],
      ["forge_checkpoint", {}],
      ["drop_checkpoint_head", {}],
    ]);
    const same = (/** @type {any} */ x, /** @type {any} */ y, /** @type {string} */ label) => {
      assert.equal(x.status, y.status, label);
      assert.deepEqual(x.body, y.body, label);
    };
    for (const [mode, params] of modes) {
      await r.mode(mode, params);
      for (const path of paths) {
        same(await call(r.ports.admin, "GET", path, { headers: cookie(SID_A) }), await call(r.upAdminPort, "GET", path, { headers: cookie(SID_A) }), `${mode} ${path} on the admin host`);
        if (path.startsWith("/api/sync/")) continue;
        same(await call(r.ports.vault, "GET", path, { headers: cookie(SID_A) }), await call(r.upVaultPort, "GET", path, { headers: cookie(SID_A) }), `${mode} ${path} on the vault host`);
      }
    }
    // The sync paths of the vault host are the ones that are reshaped.
    await r.mode("hide", { id: A });
    assert.equal((await r.get("/api/sync/changes?since=0")).changes.some((/** @type {any} */ c) => c.id === A), false);
    // The admin host was not recorded: the record holds the two items of the vault host.
    assert.equal(r.proxy.recorder.summary().items, 2);
  });

  it("proxy_passes_sse_unbuffered", async () => {
    /** @type {() => void} */
    let release = () => {};
    const gate = new Promise((resolve) => { release = () => resolve(undefined); });
    const up = await listen((req, res) => {
      res.writeHead(200, { "content-type": "text/event-stream", "cache-control": "no-store, no-transform", "x-accel-buffering": "no" });
      res.write('event: hello\ndata: {"seq":1}\n\n');
      // The second event is only sent when the client has the first one.
      void gate.then(() => {
        res.write('event: sync\ndata: {"seq":2}\n\n');
        res.end();
      });
    });
    const proxy = createProxy({ upstreamVault: `http://127.0.0.1:${up.port}`, upstreamAdmin: `http://127.0.0.1:${up.port}` });
    const ports = await proxy.listen({ host: "127.0.0.1", vaultPort: 0, adminPort: 0, controlPort: 0 });
    after(async () => {
      release();
      await proxy.close();
      up.server.closeAllConnections();
      up.server.close();
    });
    // A lying mode does not change that.
    const hid = await call(ports.control, "POST", "/mode", { headers: { "content-type": "application/json" }, body: JSON.stringify({ mode: "hide", id: A }) });
    assert.equal(hid.status, 200);
    const received = await new Promise((resolve, reject) => {
      const timer = setTimeout(() => reject(new Error("the first event did not arrive while the stream was open: the proxy buffers")), 3000);
      const req = http.request({ host: "127.0.0.1", port: ports.vault, path: "/api/sync/events", headers: { accept: "text/event-stream" }, agent: false }, (res) => {
        assert.equal(res.statusCode, 200);
        assert.equal(res.headers["content-type"], "text/event-stream");
        assert.equal(res.headers["cache-control"], "no-store, no-transform");
        assert.equal(res.headers["x-accel-buffering"], "no");
        let text = "";
        res.on("data", (c) => {
          text += c;
          if (text.includes("event: hello") && !text.includes("event: sync")) {
            // The first event is here and the stream is still open: let the second one go.
            release();
          }
          if (text.includes("event: sync")) {
            clearTimeout(timer);
            resolve(text);
          }
        });
        res.on("error", reject);
      });
      req.on("error", reject);
      req.end();
    });
    assert.equal(received, 'event: hello\ndata: {"seq":1}\n\nevent: sync\ndata: {"seq":2}\n\n');
  });

  it("mode_control_listens_only_on_the_internal_port", async () => {
    const r = await rig();
    after(() => r.close());
    assert.equal(new Set([r.ports.vault, r.ports.admin, r.ports.control]).size, 3);
    const body = JSON.stringify({ mode: "hide", id: A });
    const headers = { "content-type": "application/json" };
    // On the vault and admin ports the control paths are ordinary paths of the real server.
    for (const port of [r.ports.vault, r.ports.admin]) {
      for (const [method, path] of [["POST", "/mode"], ["GET", "/mode"], ["POST", "/reset"], ["GET", "/recorded"], ["GET", "/health"]]) {
        const answer = await call(port, method, path, { headers, body: method === "POST" ? body : undefined });
        assert.equal(answer.status, 404, `${method} ${path} on port ${port}`);
        assert.deepEqual(JSON.parse(answer.body.toString("utf8")), { error: "not_found" });
      }
    }
    assert.deepEqual(r.proxy.mode(), { mode: "honest", params: {} }, "no control request on the other ports switched a mode on");
    // On the control port there is nothing of the sync API.
    assert.equal((await call(r.ports.control, "GET", "/api/sync/changes?since=0")).status, 404);
    assert.equal((await call(r.ports.control, "PUT", `/api/sync/items/${A}`, { headers, body: JSON.stringify(live(0, 1)) })).status, 404);
    // The control port switches, shows and resets.
    assert.equal((await call(r.ports.control, "GET", "/health")).status, 200);
    await r.mode("hide", { id: A });
    assert.deepEqual(JSON.parse((await call(r.ports.control, "GET", "/mode")).body.toString("utf8")).mode, "hide");
    assert.equal((await call(r.ports.control, "POST", "/reset", { headers, body: "{}" })).status, 200);
    assert.deepEqual(r.proxy.mode(), { mode: "honest", params: {} });
    // A page in a browser cannot switch a lie on.
    for (const extra of [{ origin: "https://vault-e2e.test" }, { "sec-fetch-site": "cross-site" }]) {
      const refused = await call(r.ports.control, "POST", "/mode", { headers: { ...headers, ...extra }, body });
      assert.equal(refused.status, 403);
    }
    assert.deepEqual(r.proxy.mode(), { mode: "honest", params: {} });
    // The summary is counts, never content.
    await r.put(A, live(0, 1));
    const summary = JSON.parse((await call(r.ports.control, "GET", "/recorded")).body.toString("utf8"));
    assert.deepEqual(Object.keys(summary).sort(), ["checkpoints", "items", "now", "top_seq", "versions"]);
    assert.equal(summary.items, 1);
  });

  it("unknown_modes_and_bad_parameters_are_refused", async () => {
    for (const bad of [
      null,
      [],
      {},
      { mode: "nope" },
      { mode: "swap_blobs", a: A },
      { mode: "swap_blobs", a: A, b: A },
      { mode: "swap_blobs", a: A, b: "xyz" },
      { mode: "hide", id: A.toUpperCase() },
      { mode: "hide", id: A, extra: 1 },
      { mode: "honest", id: A },
      { mode: "seq_lie", latest_seq: -1 },
      { mode: "seq_lie", latest_seq: 1.5 },
      { mode: "seq_lie", latest_seq: "7" },
      { mode: "rollback" },
      { mode: "gone", min_valid_since: 0 },
      { mode: "gone", hide: "nope" },
      { mode: "gone", other: 1 },
      { mode: "fork", sid: "short" },
      { mode: "forge_checkpoint", field: "digest" },
    ]) {
      assert.throws(() => parseMode(bad), ModeError, JSON.stringify(bad));
    }
    for (const name of MODE_NAMES) {
      const params = { swap_blobs: { a: A, b: B }, replay_old: { id: A }, hide: { id: A }, fake_tombstone: { id: A }, seq_lie: { latest_seq: 3 }, rollback: { at: 5 }, fork: { sid: SID_A } }[/** @type {"hide"} */ (name)] ?? {};
      assert.equal(parseMode({ mode: name, ...params }).mode, name);
    }
    const r = await rig();
    after(() => r.close());
    const refused = await call(r.ports.control, "POST", "/mode", { headers: { "content-type": "application/json" }, body: JSON.stringify({ mode: "swap_blobs", a: A }) });
    assert.equal(refused.status, 400);
    assert.deepEqual(r.proxy.mode(), { mode: "honest", params: {} });
  });

  it("the_recorder_keeps_the_first_and_the_newest_version_and_only_valid_rows", () => {
    let t = 1;
    const rec = createRecorder({ now: () => t });
    rec.observeChanges({ changes: [{ id: A, rev: 1, seq: 1, deleted: false, blob: "x", tag: "y" }, { id: "nope", rev: 1, seq: 2, deleted: false, blob: "x", tag: "y" }, { id: B, rev: 0, seq: 3, deleted: false, blob: "x", tag: "y" }], latest_seq: 3 }, null);
    t = 2;
    rec.observeChanges({ changes: [{ id: A, rev: 2, seq: 4, deleted: false, blob: "x2", tag: "y2" }, { id: A, rev: 1, seq: 1, deleted: false, blob: "x", tag: "y" }], latest_seq: 4 }, null);
    assert.equal(rec.first(A)?.rev, 1);
    assert.equal(rec.latest(A)?.rev, 2);
    assert.equal(rec.first("nope"), null);
    assert.equal(rec.first(B), null);
    assert.equal(rec.summary().versions, 2);
    assert.equal(rec.top(), 4);
    assert.deepEqual(rec.viewAt(1).rows.map((v) => v.rev), [1]);
    assert.deepEqual(rec.viewAt(2).rows.map((v) => v.rev), [2]);
    assert.equal(rec.viewAt(1).top, 3);
  });

  it("the_rig_is_not_in_the_web_dist", (t) => {
    const dist = join(dirname(fileURLToPath(import.meta.url)), "..", "..", "dist");
    if (!existsSync(dist)) return t.skip("web/dist is not built");
    /** @param {string} dir @returns {string[]} */
    const walk = (dir) => readdirSync(dir, { withFileTypes: true }).flatMap((e) => (e.isDirectory() ? walk(join(dir, e.name)).map((f) => `${e.name}/${f}`) : [e.name]));
    for (const file of walk(dist)) assert.ok(!/evil|e2e-stack/i.test(file), `${file} is in the web build`);
  });
});
