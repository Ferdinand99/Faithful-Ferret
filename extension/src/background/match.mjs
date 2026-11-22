// The core host's side of the matching (design document, sections 10.4 and
// 10.5). Only the entry (main.mjs) imports this module, and it hands the core
// host its operations:
//
//   page_origin       the origin the core gives an address (`page_origin`)
//   same_site         whether two addresses are on the same site (`same_site`)
//   display_host      how the core shows the host of an address (`display_host`)
//   candidates_match  the items whose saved addresses match the chosen frames,
//                     and which of the frames that wait for their host
//                     permission some item matches
//   grant_listed      whether a list named an origin for a grant (the grant
//                     tab asks for no other)
//
// The first three are stateless functions of the core and need no key. The
// last one needs the open vault: it takes the items from the sync engine's list
// (names and user names, which the engine has already decrypted for its index),
// opens them in batches, asks the core which of them match each frame
// (`match_page`; the rule is the core's alone) and closes every handle before
// it answers, whatever happened. A handle never leaves this module.
//
// What leaves is, per item, its id and the frames it may be filled in: no
// handle and no reference. The references the popup gets are the fill flow's
// (fillFlow.mjs), made per popup session from this answer.
//
// A frame of the top's site with another origin waits for its host permission.
// Matching needs no permission (the core compares the address the browser gave
// with the saved ones), so such a frame is matched too, but it is offered no item:
// it is only named, so that the popup can ask for the permission, and
// only when some item matches it. The origins named this way are kept for 10
// minutes (at most 32, emptied at every lock), and the grant tab asks only for
// one of them.

/** An item id: 16 bytes in lower-case hex (the sync engine's form). */
const ITEM_ID = /^[0-9a-f]{32}$/;

/** 16 bytes as lower-case hex. @param {Uint8Array} bytes */
export function hex(bytes) {
  return Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
}

/** How many items are opened at once for a match. */
export const MATCH_BATCH = 64;
/** The most frames one match looks at (frames.mjs gives at most as many). */
const MAX_FRAMES = 32;
/** The most items one answer names (frames.mjs keeps the best 100 of a list). */
const MAX_ITEMS = 256;
/** The most frames one item is offered in (the frames that tie on its closest match, the top first). */
export const MAX_ITEM_FRAMES = 4;
const MAX_URL = 8192;
const HOW = Object.freeze(["exact", "host", "domain"]);
/** How long a listed grant origin may be asked for, and how many are kept. */
const GRANT_TTL_MS = 10 * 60_000;
const MAX_GRANTS = 32;

/** The error of this module: a short code. */
export class MatchError extends Error {
  /** @param {string} code */
  constructor(code) {
    super(code);
    this.name = "MatchError";
    this.code = code;
  }
}

/**
 * @typedef {{ id: string, name: string, username: string, urls: string[], damaged?: boolean, quarantined?: boolean }} Summary
 * @typedef {{
 *   list(): Summary[],
 *   open(id: string): Promise<{ handle: number, close(): Promise<void> }>,
 * }} ItemSource the part of the sync engine a match uses
 */

/** The longest name and user name a list carries (the protocol's bound). */
const MAX_TEXT = 256;

/**
 * A text cut to at most `max` UTF-16 units, never inside a surrogate pair.
 * @param {string} text @param {number} max
 */
export function clip(text, max) {
  if (text.length <= max) return text;
  const code = text.charCodeAt(max - 1);
  return text.slice(0, code >= 0xd800 && code <= 0xdbff ? max - 1 : max);
}

/** @param {unknown} n @returns {n is number} */
const isIndex = (n) => typeof n === "number" && Number.isSafeInteger(n) && n >= 0;
/** @param {unknown} s @param {number} max @returns {s is string} */
const isText = (s, max) => typeof s === "string" && s !== "" && s.length <= max;

/**
 * Checks the frames a match is asked for. They come from frames.mjs, which took
 * them from the browser; a wrong shape is a bug and refuses the whole call.
 * @param {unknown} frames
 */
function checkFrames(frames) {
  if (!Array.isArray(frames) || frames.length === 0 || frames.length > MAX_FRAMES) throw new MatchError("invalid_input");
  return frames.map((/** @type {any} */ f) => {
    if (typeof f !== "object" || f === null || !isIndex(f.frame_id) || !isText(f.url, MAX_URL) || !isText(f.origin, 300)) {
      throw new MatchError("invalid_input");
    }
    if (f.document_id !== undefined && !isText(f.document_id, 64)) throw new MatchError("invalid_input");
    if (f.waiting !== undefined && typeof f.waiting !== "boolean") throw new MatchError("invalid_input");
    return { frameId: f.frame_id, documentId: f.document_id, url: f.url, origin: f.origin, waiting: f.waiting === true };
  });
}

/**
 * The items of `source` whose saved addresses match the frames, each once, with
 * the frames where the core's answer is closest (exact, then the host, then the
 * registrable domain): every frame that ties on that answer, in the order of
 * `frames` (the top first), at most `MAX_ITEM_FRAMES`. A `domain` entry for the
 * host of a frame is therefore offered for that frame, where its form is, and
 * not for the top it also matches by domain; a frame of the top's origin that
 * holds the form ties with the top and is offered too. A frame marked
 * `waiting` (its host permission is missing) is matched, but no item is offered
 * for it: it only shows up in `waiting`, the indexes of such frames that some
 * item matches. Every handle that is opened is closed before this returns or
 * throws.
 *
 * @param {{ vault: { match_page(url: string, handles: number[]): Promise<unknown> } }} client the op's client
 * @param {ItemSource} source
 * @param {Array<{ frameId: number, documentId?: string, url: string, origin: string, waiting?: boolean }>} frames
 * @returns {Promise<{ items: Array<{ id: string, name: string, username: string, how: string, frames: number[] }>, waiting: number[] }>}
 *   `frames` and `waiting` are indexes in `frames`
 */
export async function matchItems(client, source, frames) {
  // Only items with a saved address can match; which address matches is the core's to say.
  const items = source.list().filter((s) => typeof s.id === "string" && ITEM_ID.test(s.id) && s.damaged !== true && s.quarantined !== true && Array.isArray(s.urls) && s.urls.length > 0);
  /** @type {Map<string, { how: string, frames: Set<number> }>} */
  const best = new Map();
  /** @type {Set<number>} */
  const waiting = new Set();
  for (let at = 0; at < items.length; at += MATCH_BATCH) {
    const batch = items.slice(at, at + MATCH_BATCH);
    /** @type {Array<{ handle: number, close(): Promise<void> }>} */
    const opened = [];
    /** @type {Map<number, string>} */
    const idOf = new Map();
    try {
      const results = await Promise.allSettled(batch.map((s) => source.open(s.id)));
      results.forEach((result, i) => {
        if (result.status !== "fulfilled") return;
        opened.push(result.value);
        idOf.set(result.value.handle, batch[i].id);
      });
      // An item that does not open (damaged, deleted since the list) is not offered. A lock refuses the whole match.
      const locked = results.find((r) => r.status === "rejected" && ["vault_locked", "worker_failed", "stopped"].includes(/** @type {any} */ (r).reason?.code));
      if (locked) throw new MatchError("vault_locked");
      if (opened.length === 0) continue;
      const handles = opened.map((o) => o.handle);
      for (let frame = 0; frame < frames.length; frame += 1) {
        const answer = await client.vault.match_page(frames[frame].url, handles);
        if (!Array.isArray(answer)) throw new MatchError("internal");
        for (const hit of answer) {
          const id = idOf.get(/** @type {any} */ (hit)?.handle);
          const how = /** @type {any} */ (hit)?.how;
          if (id === undefined || !HOW.includes(how)) continue;
          if (frames[frame].waiting === true) {
            waiting.add(frame);
            continue;
          }
          const known = best.get(id);
          if (known !== undefined && HOW.indexOf(known.how) < HOW.indexOf(how)) continue;
          if (known !== undefined && known.how === how) known.frames.add(frame);
          else best.set(id, { how, frames: new Set([frame]) });
        }
      }
    } finally {
      await Promise.all(opened.map((o) => Promise.resolve().then(() => o.close()).catch(() => {})));
    }
  }
  /** @type {Array<{ id: string, name: string, username: string, how: string, frames: number[] }>} */
  const out = [];
  for (const s of items) {
    const hit = best.get(s.id);
    if (!hit) continue;
    const tied = [...hit.frames].sort((a, b) => a - b).slice(0, MAX_ITEM_FRAMES);
    out.push({ id: s.id, name: String(s.name ?? ""), username: String(s.username ?? ""), how: hit.how, frames: tied });
  }
  // The closest match first (exact, then the host, then the registrable domain), then by name.
  out.sort((a, b) => HOW.indexOf(a.how) - HOW.indexOf(b.how) || a.name.toLowerCase().localeCompare(b.name.toLowerCase()) || (a.id < b.id ? -1 : 1));
  return { items: out, waiting: [...waiting].sort((a, b) => a - b) };
}

/**
 * The origins a list named for a grant, for a while (`GRANT_TTL_MS`, at most `MAX_GRANTS`).
 * @param {{ now: () => number }} clock
 */
export function createGrantList({ now }) {
  /** @type {Map<string, number>} origin -> when a list named it */
  const named = new Map();
  const drop = () => {
    const t = now();
    for (const [origin, at] of named) if (t - at > GRANT_TTL_MS || t < at) named.delete(origin);
  };
  return {
    /** @param {string} origin */
    add(origin) {
      drop();
      named.delete(origin);
      named.set(origin, now());
      while (named.size > MAX_GRANTS) named.delete(/** @type {string} */ (named.keys().next().value));
    },
    /** @param {unknown} origin */
    has(origin) {
      drop();
      return typeof origin === "string" && named.has(origin);
    },
    clear() {
      named.clear();
    },
  };
}

/**
 * The matching of the extension and its core-host operations. Call `attach`
 * once the core host exists.
 * @param {{ engine: () => ItemSource | null, now?: () => number }} options
 *   `engine`: the sync engine of the open vault, or null
 */
export function createMatchHost({ engine, now = Date.now }) {
  const grants = createGrantList({ now });
  /** @param {unknown} url */
  const checkUrl = (url) => {
    if (!isText(url, MAX_URL)) throw new MatchError("invalid_input");
    return url;
  };

  const ops = Object.freeze({
    page_origin: {
      vault: false,
      worker: /** @type {const} */ ("vault"),
      run: async (/** @type {any} */ client, /** @type {any} */ args) => {
        const origin = await client.vault.page_origin(checkUrl(args?.url));
        if (!isText(origin, 300)) throw new MatchError("malformed_origin");
        return { origin };
      },
    },
    same_site: {
      vault: false,
      worker: /** @type {const} */ ("vault"),
      run: async (/** @type {any} */ client, /** @type {any} */ args) => ({
        same: (await client.vault.same_site(checkUrl(args?.a), checkUrl(args?.b))) === true,
      }),
    },
    display_host: {
      vault: false,
      worker: /** @type {const} */ ("vault"),
      run: async (/** @type {any} */ client, /** @type {any} */ args) => {
        const shown = await client.vault.display_host(checkUrl(args?.url));
        if (!isText(shown?.a_label, 300) || !isText(shown?.unicode, 300)) throw new MatchError("malformed_origin");
        return { a_label: shown.a_label, unicode: shown.unicode };
      },
    },
    candidates_match: {
      vault: true,
      worker: /** @type {const} */ ("vault"),
      run: async (/** @type {any} */ client, /** @type {any} */ args) => {
        const frames = checkFrames(args?.frames);
        const source = engine();
        if (source === null) return { items: [], grant_frames: [] };
        const matched = await matchItems(client, source, frames);
        const grantFrames = matched.waiting.map((i) => frames[i]);
        for (const frame of grantFrames) grants.add(frame.origin);
        const items = matched.items.slice(0, MAX_ITEMS).map((m) => ({
          item_id: m.id,
          name: clip(m.name, MAX_TEXT),
          username: m.username === "" ? null : clip(m.username, MAX_TEXT),
          how: m.how,
          frame_ids: m.frames.map((i) => frames[i].frameId),
        }));
        return { items, grant_frames: grantFrames.map((f) => f.frameId) };
      },
    },
    grant_listed: {
      vault: false,
      worker: /** @type {const} */ ("none"),
      run: async (/** @type {any} */ _client, /** @type {any} */ args) => ({ listed: grants.has(args?.origin) }),
    },
  });

  return {
    ops,

    /**
     * Joins the core host: every lock forgets the listed grant origins.
     * @param {{ onLocked(listener: () => void): unknown }} coreHost
     */
    attach(coreHost) {
      coreHost.onLocked(() => {
        grants.clear();
      });
    },
  };
}
