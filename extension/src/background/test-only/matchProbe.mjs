// What the Firefox tests of the matching need from the background, in the test
// build only (a folder named test-only: a release leaves it out). Core
// operations, called over the test build's core port:
//
//   frames_probe  the frames of a tab that `fillableFrames` chooses, with the
//                 real `webNavigation` and the real core, and how many frames the
//                 browser lists in all
//   item_probe    makes one item with the sync engine (the extension writes no
//                 items in this release; the tests need entries to match), with
//                 an optional user name and password the test made up
//   match_bench   seals `n` items in the open vault (kept in memory here, never
//                 stored or sent), then times the real `matchItems` over them for
//                 one page: the items are opened and viewed as the sync engine
//                 opens them, matched and closed. It answers the time, the counts
//                 and whether a closed handle is refused by the core.
//
// None of them answers with a key, a value or a handle.

import { fillableFrames } from "../frames.mjs";
import { hex, matchItems } from "../match.mjs";

/** The most items `match_bench` seals. */
const MAX_BENCH = 2000;

/** @param {string} code */
const fail = (code) => Object.assign(new Error(code), { code });

/** @param {unknown} n @param {number} min @param {number} max */
const whole = (n, min, max) => typeof n === "number" && Number.isInteger(n) && n >= min && n <= max;
/** @param {unknown} s @param {number} max @returns {s is string} */
const text = (s, max) => typeof s === "string" && s !== "" && s.length <= max;

/** @param {number} n */
function randomBytes(n) {
  const bytes = new Uint8Array(n);
  globalThis.crypto.getRandomValues(bytes);
  return bytes;
}

/**
 * @param {{ engine: () => any, webNavigation?: any, now?: () => number }} deps
 */
export function createMatchProbe({ engine, webNavigation = /** @type {any} */ (globalThis).browser?.webNavigation, now = () => performance.now() }) {
  /** @type {Readonly<Record<string, import("../coreHost.mjs").CoreOp>>} */
  const ops = Object.freeze({
    frames_probe: {
      vault: false,
      worker: "vault",
      async run(client, args) {
        if (!whole(args?.tab_id, 0, 2_147_483_647)) throw fail("invalid_input");
        const core = {
          page_origin: (/** @type {string} */ url) => client.vault.page_origin(url),
          same_site: async (/** @type {string} */ a, /** @type {string} */ b) => (await client.vault.same_site(a, b)) === true,
        };
        const listed = await webNavigation.getAllFrames({ tabId: args.tab_id }).catch(() => null);
        return { frames: await fillableFrames(args.tab_id, { webNavigation, core }), listed: Array.isArray(listed) ? listed.length : 0 };
      },
    },

    item_probe: {
      vault: true,
      worker: "vault",
      async run(_client, args) {
        const running = engine();
        if (running === null) throw fail("sync_not_running");
        if (!text(args?.name, 256) || !text(args?.url, 2048) || !["host", "domain", "exact"].includes(args?.matching)) throw fail("invalid_input");
        /** @type {Record<string, unknown>} */
        const draft = { item_type: "login", name: args.name, favorite: false, urls: [{ url: args.url, matching: args.matching }] };
        /** @type {Array<Record<string, string>>} */
        const fields = [];
        if (text(args.username, 256)) fields.push({ id: "username", label: "Username", kind: "text", value: args.username });
        // A password of the test's own making, so the adversarial specs can see where a fill puts it.
        if (text(args.password, 256)) fields.push({ id: "password", label: "Password", kind: "password", value: args.password });
        if (fields.length > 0) draft.fields = fields;
        return { id: await running.create(draft) };
      },
    },

    match_bench: {
      vault: true,
      worker: "vault",
      async run(client, args) {
        if (!whole(args?.n, 1, MAX_BENCH) || !text(args?.url, 2048) || !text(args?.other, 2048)) throw fail("invalid_input");
        /** @type {Map<string, { idBytes: Uint8Array, envelope: Uint8Array, tag: Uint8Array }>} */
        const rows = new Map();
        /** @type {Array<{ id: string, name: string, username: string, urls: string[] }>} */
        const list = [];
        for (let at = 0; at < args.n; at += 100) {
          const batch = Array.from({ length: Math.min(100, args.n - at) }, (_, i) => at + i);
          await Promise.all(batch.map(async (i) => {
            const idBytes = randomBytes(16);
            const id = hex(idBytes);
            // Every tenth item is for the page; the rest for another host.
            const url = i % 10 === 0 ? args.url : args.other;
            const sealed = await client.vault.encrypt_item(idBytes.slice(), 1, { item_type: "login", name: `Bench ${i}`, favorite: false, urls: [{ url, matching: "host" }] }, undefined, Date.now());
            rows.set(id, { idBytes, envelope: sealed.envelope, tag: sealed.tag });
            list.push({ id, name: `Bench ${i}`, username: "", urls: [url] });
          }));
        }
        let opened = 0;
        let closed = 0;
        /** @type {Set<number>} */
        const live = new Set();
        /** @type {number | null} */
        let lastClosed = null;
        const source = {
          list: () => list,
          async open(/** @type {string} */ id) {
            const row = /** @type {{ idBytes: Uint8Array, envelope: Uint8Array, tag: Uint8Array }} */ (rows.get(id));
            const handle = await client.vault.open_item(row.idBytes.slice(), 1, row.envelope, row.tag);
            opened += 1;
            live.add(handle);
            try {
              // As the sync engine's `open` does.
              await client.vault.item_view(handle);
            } catch (error) {
              live.delete(handle);
              await client.vault.close_item(handle).catch(() => {});
              throw error;
            }
            return {
              handle,
              close: async () => {
                if (!live.delete(handle)) return;
                await client.vault.close_item(handle);
                closed += 1;
                lastClosed = handle;
              },
            };
          },
        };
        const origin = await client.vault.page_origin(args.url);
        const started = now();
        const { items: matched } = await matchItems(client, source, [{ frameId: 0, url: args.url, origin }]);
        const ms = now() - started;
        let closedIsRefused = false;
        if (lastClosed !== null) {
          try {
            await client.vault.item_view(lastClosed);
          } catch (error) {
            closedIsRefused = /** @type {{ code?: unknown }} */ (error)?.code === "invalid_handle";
          }
        }
        return { ms, items: list.length, matched: matched.length, opened, closed, still_open: live.size, closed_is_refused: closedIsRefused };
      },
    },
  });
  return { ops };
}
