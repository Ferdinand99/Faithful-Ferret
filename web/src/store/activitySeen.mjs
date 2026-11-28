// What this browser last showed of the account log ("Activity"): the id and the time of the
// newest event on the page. The notice at an unlock (`flows/accountEvents.mjs`) tells the events
// that an administrator, a command on the server or the server caused after it. It is not a
// secret: two numbers the server sent, and no key, item or name. It lives in the settings under
// `activity.seen.<server>.<account>`, so two accounts in one browser, or one account on two
// servers, never share it; "forget this server" removes it (see `forget.mjs`).
import { hex16 } from "../b64.mjs";
import { serverKey } from "./idb.mjs";
import { deleteSetting, getSetting, setSetting } from "./settings.mjs";

/** @typedef {{ id: number, at: number }} SeenMark the id and the time (seconds) of the newest event shown; 0 and 0 for an empty log */

/**
 * The settings key of the mark.
 * @param {string} serverUrl
 * @param {string} accountId
 * @returns {string}
 */
export function activitySeenKey(serverUrl, accountId) {
  if (!hex16.is(accountId)) throw new TypeError("an account id is 32 lower-case hex characters");
  return `activity.seen.${serverKey(serverUrl)}.${accountId}`;
}

/** @param {unknown} value @returns {value is number} */
const whole = (value) => typeof value === "number" && Number.isSafeInteger(value) && value >= 0;

/**
 * The mark as it is stored, or null when it is not one: exactly the two fields, whole numbers.
 * @param {unknown} value
 * @returns {SeenMark | null}
 */
function clean(value) {
  if (value === null || typeof value !== "object" || Array.isArray(value)) return null;
  if (Object.keys(value).sort().join() !== "at,id") return null;
  const { id, at } = /** @type {Record<string, unknown>} */ (value);
  return whole(id) && whole(at) ? { id, at } : null;
}

/**
 * The mark of an account on a server, or null when this browser has none (or holds something that is not one).
 * @param {import("./idb.mjs").Store} store
 * @param {string} serverUrl
 * @param {string} accountId
 * @returns {Promise<SeenMark | null>}
 */
export async function loadSeen(store, serverUrl, accountId) {
  return clean(await getSetting(store, activitySeenKey(serverUrl, accountId)));
}

/**
 * Keeps the mark of an account on a server.
 * @param {import("./idb.mjs").Store} store
 * @param {string} serverUrl
 * @param {string} accountId
 * @param {SeenMark} mark
 * @returns {Promise<void>}
 */
export async function saveSeen(store, serverUrl, accountId, mark) {
  const key = activitySeenKey(serverUrl, accountId);
  const kept = clean(mark);
  if (kept === null) throw new TypeError("a mark is an id and a time, both whole numbers of at least 0");
  await setSetting(store, key, kept);
}

/**
 * Removes the mark of an account on a server, if there is one.
 * @param {import("./idb.mjs").Store} store
 * @param {string} serverUrl
 * @param {string} accountId
 * @returns {Promise<void>}
 */
export async function deleteSeen(store, serverUrl, accountId) {
  await deleteSetting(store, activitySeenKey(serverUrl, accountId));
}

/** The three calls as the store service hands them out. */
export const activitySeen = Object.freeze({ load: loadSeen, save: saveSeen, delete: deleteSeen });
