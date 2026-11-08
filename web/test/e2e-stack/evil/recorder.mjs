// What the malicious server in the end-to-end stack remembers. It watches the
// honest answers of the real server (never the ones it makes up itself) and
// keeps every version of every item that it has seen, the heads and bodies of
// the checkpoints, and the highest sequence number, each with the time it was
// seen and the session that was talking. The modes of modes.mjs replay old
// versions, roll the vault back to a moment, or freeze it for one session from
// this memory.
//
// Test rig only: it lives in the end-to-end stack and in no production image.

const ID = /^[0-9a-f]{32}$/;
const isU53 = (n) => Number.isSafeInteger(n) && n >= 0;
const isText = (s) => typeof s === "string" && s.length > 0;

/**
 * @typedef {{ t: number, sid: string | null, own: boolean, id: string, rev: number, seq: number, deleted: boolean, blob?: string, tag?: string, tomb?: string }} Version
 * @typedef {{ t: number, sid: string | null, own: boolean, seq: number, digest: string, mac: string, entries: string | null }} Head
 */

/** Whether `row` is a row of the wire format (a live row or a tombstone). @param {any} row */
export function validRow(row) {
  if (row === null || typeof row !== "object") return false;
  if (typeof row.id !== "string" || !ID.test(row.id)) return false;
  if (!isU53(row.rev) || row.rev < 1 || !isU53(row.seq)) return false;
  if (row.deleted === true) return isText(row.tomb);
  return row.deleted === false && isText(row.blob) && isText(row.tag);
}

/** The row of the wire format for a version, with the keys in the order of the server. @param {Version} v */
export function rowOf(v) {
  return v.deleted
    ? { id: v.id, rev: v.rev, seq: v.seq, deleted: true, tomb: v.tomb }
    : { id: v.id, rev: v.rev, seq: v.seq, deleted: false, blob: v.blob, tag: v.tag };
}

/**
 * @param {{ now?: () => number, maxIds?: number, maxVersionsPerId?: number }} [options]
 */
export function createRecorder({ now = Date.now, maxIds = 100_000, maxVersionsPerId = 256 } = {}) {
  /** @type {Map<string, Version[]>} */
  const versions = new Map();
  /** @type {{ t: number, seq: number, sid: string | null, own: boolean }[]} */
  const tops = [];
  /** @type {Head[]} */
  const heads = [];

  /** @param {any} row @param {string | null} sid @param {boolean} own whether this session wrote it */
  function addRow(row, sid, own) {
    if (!validRow(row)) return;
    let list = versions.get(row.id);
    if (!list) {
      if (versions.size >= maxIds) return;
      list = [];
      versions.set(row.id, list);
    }
    const known = list.find((v) => v.rev === row.rev && v.seq === row.seq);
    if (known) {
      if (own) Object.assign(known, { sid, own });
      return;
    }
    /** @type {Version} */
    const v = row.deleted
      ? { t: now(), sid, own, id: row.id, rev: row.rev, seq: row.seq, deleted: true, tomb: row.tomb }
      : { t: now(), sid, own, id: row.id, rev: row.rev, seq: row.seq, deleted: false, blob: row.blob, tag: row.tag };
    list.push(v);
    // The first version is what `replay_old` needs; the oldest of the rest go first.
    if (list.length > maxVersionsPerId) list.splice(1, 1);
  }

  /** @param {number} seq @param {string | null} sid @param {boolean} own */
  function addTop(seq, sid, own) {
    if (!isU53(seq)) return;
    tops.push({ t: now(), seq, sid, own });
    if (tops.length > 100_000) tops.splice(0, tops.length - 50_000);
  }

  /** @param {any} head @param {string | null} sid @param {string | null} entries @param {boolean} own */
  function addHead(head, sid, entries, own) {
    if (head === null || typeof head !== "object") return;
    if (!isU53(head.seq) || !isText(head.digest) || !isText(head.mac)) return;
    const same = heads.find((h) => h.seq === head.seq && h.digest === head.digest && h.mac === head.mac);
    if (same) {
      if (entries && !same.entries) same.entries = entries;
      if (own) Object.assign(same, { sid, own });
      return;
    }
    heads.push({ t: now(), sid, own, seq: head.seq, digest: head.digest, mac: head.mac, entries });
    if (heads.length > 1000) heads.splice(0, heads.length - 500);
  }

  /** @param {{ t: number, seq: number, sid: string | null, own: boolean }[]} list @param {number} t @param {string | null} sid */
  const topOf = (list, t, sid) =>
    list.filter((x) => x.t <= t || (sid !== null && x.own && x.sid === sid)).reduce((m, x) => Math.max(m, x.seq), 0);

  return {
    now,

    /** A `GET /api/sync/changes` answer of the real server. @param {any} json @param {string | null} sid */
    observeChanges(json, sid) {
      if (!json || !Array.isArray(json.changes)) return;
      for (const row of json.changes) addRow(row, sid, false);
      addTop(json.latest_seq, sid, false);
      if (json.checkpoint) addHead(json.checkpoint, sid, null, false);
    },

    /** A `GET /api/sync/items` answer. @param {any} json @param {string | null} sid */
    observeItems(json, sid) {
      if (!json || !Array.isArray(json.items)) return;
      for (const row of json.items) addRow(row, sid, false);
      addTop(json.as_of_seq, sid, false);
    },

    /** A `GET /api/sync/checkpoint` answer. @param {any} json @param {string | null} sid */
    observeCheckpoint(json, sid) {
      if (!json || !isText(json.entries)) return;
      addHead(json, sid, json.entries, false);
    },

    /**
     * A write that the server stored: `PUT /api/sync/items/{id}`.
     * @param {string} id @param {any} body the request @param {any} result the 200 answer @param {string | null} sid
     */
    observePut(id, body, result, sid) {
      if (!body || !result || !isU53(result.rev) || !isU53(result.seq)) return;
      addRow({ id, rev: result.rev, seq: result.seq, deleted: body.deleted === true, blob: body.blob, tag: body.tag, tomb: body.tomb }, sid, true);
      addTop(result.seq, sid, true);
    },

    /** `POST /api/sync/batch`: the operations that were stored. @param {any} body @param {any} result @param {string | null} sid */
    observeBatch(body, result, sid) {
      if (!body || !Array.isArray(body.ops) || !result || !Array.isArray(result.results)) return;
      body.ops.forEach((/** @type {any} */ op, /** @type {number} */ i) => {
        const r = result.results[i];
        if (op && r && r.status === 200) this.observePut(op.id, op, r, sid);
      });
    },

    /** A checkpoint that the server stored: `PUT /api/sync/checkpoint`. @param {any} body @param {string | null} sid */
    observePutCheckpoint(body, sid) {
      if (!body || !isText(body.entries)) return;
      addHead(body, sid, body.entries, true);
    },

    /** The first version of the item that was seen. @param {string} id @returns {Version | null} */
    first(id) {
      return versions.get(id)?.[0] ?? null;
    },

    /** The newest version of the item that was seen (the highest `seq`). @param {string} id @returns {Version | null} */
    latest(id) {
      const list = versions.get(id);
      if (!list || list.length === 0) return null;
      return list.reduce((a, b) => (b.seq > a.seq || (b.seq === a.seq && b.rev > a.rev) ? b : a));
    },

    /** The highest sequence number seen. */
    top() {
      return tops.reduce((m, x) => Math.max(m, x.seq), 0);
    },

    /**
     * The vault as it was at the time `t`: for every item the newest version
     * seen at or before `t`; the same for the checkpoint. With `sid`, what that
     * session itself wrote after `t` is in as well (a fork that keeps its own
     * writes).
     * @param {number} t
     * @param {string | null} [sid]
     */
    viewAt(t, sid = null) {
      const seen = (/** @type {{ t: number, sid: string | null, own: boolean }} */ x) => x.t <= t || (sid !== null && x.own && x.sid === sid);
      /** @type {Version[]} */
      const rows = [];
      for (const list of versions.values()) {
        /** @type {Version | null} */
        let best = null;
        for (const v of list) {
          if (seen(v) && (best === null || v.seq > best.seq || (v.seq === best.seq && v.rev > best.rev))) best = v;
        }
        if (best) rows.push(best);
      }
      rows.sort((a, b) => (a.id < b.id ? -1 : a.id > b.id ? 1 : 0));
      const top = Math.max(topOf(tops, t, sid), rows.reduce((m, v) => Math.max(m, v.seq), 0));
      const candidates = heads.filter(seen);
      const newest = (/** @type {Head[]} */ list) => list.reduce((a, h) => (a === null || h.seq > a.seq ? h : a), /** @type {Head | null} */ (null));
      return { rows, top, head: newest(candidates), checkpoint: newest(candidates.filter((h) => h.entries !== null)) };
    },

    /** Counts only (no content), for the control port. */
    summary() {
      let count = 0;
      for (const list of versions.values()) count += list.length;
      return { now: now(), items: versions.size, versions: count, top_seq: this.top(), checkpoints: heads.length };
    },

    clear() {
      versions.clear();
      tops.length = 0;
      heads.length = 0;
    },
  };
}
