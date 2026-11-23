// What the Firefox tests of the write path need from the background, in the
// test build only (a folder named test-only: a release leaves it out). Until
// the background has its store of offers, the test build has this small one:
//
//   captures      the offers of the test build: what a test planted, under a
//                 random offer id, for one popup session, cleared at every lock
//                 (the sync reads them through its `captures`, as it will read
//                 the real store)
//
// Core operations, called over the test build's core port:
//
//   offer_plant   plants a captured form the test made up (an address of a test
//                 site, a user name and a password of the test's own making),
//                 as the capture of a submitted form would be held; it answers
//                 the offer id and nothing else
//   offer_bench   seals `n` items in the open vault (kept in memory here, never
//                 stored or sent), every other one with the password of the
//                 capture for another host, then times the real classification
//                 (offerWrite.mjs) of a capture for the page over them. It
//                 answers the time, the counts and the outcome: never a value.

import { createOfferWriter } from "../offerWrite.mjs";
import { hex } from "../match.mjs";

/** The most items `offer_bench` seals. */
const MAX_BENCH = 2000;

const HEX16 = /^[0-9a-f]{32}$/;

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

/** @type {Map<string, { session: string, capture: any }>} */
const planted = new Map();

/** The offers of the test build (the sync's `captures`). */
export const captures = Object.freeze({
  /** @param {string} offerId @param {string} session */
  peek(offerId, session) {
    const offer = planted.get(offerId);
    return offer !== undefined && offer.session === session ? { ...offer.capture } : null;
  },
  /** @param {string} offerId @param {string} session */
  take(offerId, session) {
    const offer = planted.get(offerId);
    if (offer === undefined || offer.session !== session) return null;
    planted.delete(offerId);
    return { ...offer.capture };
  },
  clear() {
    planted.clear();
  },
  size: () => planted.size,
});

/**
 * A capture from the test's arguments, with its origin read by the core.
 * @param {any} client @param {any} args
 */
async function captureOf(client, args) {
  if (!text(args?.frame_url, 2048) || !text(args?.password, 1024) || !["login", "signup", "change", "reset"].includes(args?.kind)) {
    throw fail("invalid_input");
  }
  const origin = await client.vault.page_origin(args.frame_url);
  return {
    tabId: whole(args.tab_id, 0, 2_147_483_647) ? args.tab_id : 1,
    frameId: whole(args.frame_id, 0, 2_147_483_647) ? args.frame_id : 0,
    frameUrl: args.frame_url,
    origin,
    kind: args.kind,
    username: text(args.username, 512) ? args.username : null,
    usernameFrom: text(args.username, 512) ? (["typed", "page", "identifier", "fill"].includes(args.username_from) ? args.username_from : "typed") : null,
    password: args.password,
    currentPassword: text(args.current_password, 1024) ? args.current_password : null,
    generated: false,
  };
}

/**
 * @param {{ now?: () => number }} [deps]
 */
export function createOfferProbe({ now = () => performance.now() } = {}) {
  /** @type {Readonly<Record<string, import("../coreHost.mjs").CoreOp>>} */
  const ops = Object.freeze({
    offer_plant: {
      vault: true,
      worker: "vault",
      async run(client, args) {
        if (typeof args?.session !== "string" || !HEX16.test(args.session)) throw fail("invalid_input");
        const capture = await captureOf(client, args);
        const offerId = hex(randomBytes(16));
        planted.set(offerId, { session: args.session, capture });
        return { offer_id: offerId };
      },
    },

    offer_bench: {
      vault: true,
      worker: "vault",
      async run(client, args) {
        if (!whole(args?.n, 1, MAX_BENCH) || !text(args?.other, 2048)) throw fail("invalid_input");
        const capture = await captureOf(client, args);
        /** @type {Map<string, { idBytes: Uint8Array, envelope: Uint8Array, tag: Uint8Array }>} */
        const rows = new Map();
        /** @type {Array<{ id: string, rev: number, name: string, username: string, urls: string[] }>} */
        const list = [];
        for (let at = 0; at < args.n; at += 100) {
          const batch = Array.from({ length: Math.min(100, args.n - at) }, (_, i) => at + i);
          await Promise.all(batch.map(async (i) => {
            const idBytes = randomBytes(16);
            const id = hex(idBytes);
            // Every other item holds the capture's password, for another host; the rest a password of their own.
            const value = i % 2 === 0 ? capture.password : `${capture.password}-${i}`;
            const fields = [
              { id: "username", label: "User name", kind: "text", value: `bench-${i}` },
              { id: "password", label: "Password", kind: "password", value },
            ];
            const sealed = await client.vault.encrypt_item(idBytes.slice(), 1, { item_type: "login", name: `Bench ${i}`, fields, urls: [{ url: args.other, matching: "host" }] }, undefined, Date.now());
            rows.set(id, { idBytes, envelope: sealed.envelope, tag: sealed.tag });
            list.push({ id, rev: 1, name: `Bench ${i}`, username: `bench-${i}`, urls: [args.other] });
          }));
        }
        let opened = 0;
        let closed = 0;
        /** @type {Set<number>} */
        const live = new Set();
        const engine = {
          list: () => list,
          async open(/** @type {string} */ id) {
            const row = /** @type {{ idBytes: Uint8Array, envelope: Uint8Array, tag: Uint8Array }} */ (rows.get(id));
            const handle = await client.vault.open_item(row.idBytes.slice(), 1, row.envelope, row.tag);
            opened += 1;
            live.add(handle);
            try {
              const view = await client.vault.item_view(handle);
              return {
                handle,
                view,
                close: async () => {
                  if (!live.delete(handle)) return;
                  await client.vault.close_item(handle);
                  closed += 1;
                },
              };
            } catch (error) {
              live.delete(handle);
              await client.vault.close_item(handle).catch(() => {});
              throw error;
            }
          },
          create: () => Promise.reject(fail("not_available")),
          update: () => Promise.reject(fail("not_available")),
        };
        const writer = createOfferWriter({ engine, liveClient: client });
        const started = now();
        const outcome = await writer.classify(capture);
        const ms = now() - started;
        return { ms, items: list.length, opened, closed, still_open: live.size, action: outcome.action, reused: outcome.reused.length };
      },
    },
  });
  return { ops };
}
