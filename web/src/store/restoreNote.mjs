// A small local note: an older state of the server was accepted on this device, and the
// server's unlock methods went back with it (`manifestOlder`). At the next unlock the core
// refuses the older method, because the pinned floors are never lowered; the note lets the
// sign-in and unlock screens say that the cause is the restore and not only an attack.
//
// The note is not a secret and carries no key, item or name. It decides which text the screen
// shows and nothing else: it lowers no floor and changes no check. It lives in the settings
// under `restore.note.<server>.<account>`, expires after 30 days, and "forget this server"
// removes it (see `forget.mjs`).
import { hex16 } from "../b64.mjs";
import { serverKey } from "./idb.mjs";
import { deleteSetting, getSetting, setSetting } from "./settings.mjs";

/** How long the note is kept: 30 days, in milliseconds. */
export const RESTORE_NOTE_TTL_MS = 30 * 24 * 60 * 60 * 1000;

/** A note dated further ahead than this is a clock that went wrong, and is not trusted. */
const CLOCK_SLACK_MS = 24 * 60 * 60 * 1000;

/** @typedef {{ acceptedAt: number, restoreEpoch: number, manifestOlder: boolean }} RestoreNote */

/**
 * The settings key of a note.
 * @param {string} serverUrl
 * @param {string} accountId
 * @returns {string}
 */
export function restoreNoteKey(serverUrl, accountId) {
  if (!hex16.is(accountId)) throw new TypeError("an account id is 32 lower-case hex characters");
  return `restore.note.${serverKey(serverUrl)}.${accountId}`;
}

/** @param {unknown} value @returns {value is number} */
const whole = (value) => typeof value === "number" && Number.isSafeInteger(value) && value >= 0;

/**
 * The note as it is stored, or null when it is not a note: exactly the three fields, of the right types.
 * @param {unknown} value
 * @returns {RestoreNote | null}
 */
function clean(value) {
  if (value === null || typeof value !== "object" || Array.isArray(value)) return null;
  if (Object.keys(value).sort().join() !== "acceptedAt,manifestOlder,restoreEpoch") return null;
  const { acceptedAt, restoreEpoch, manifestOlder } = /** @type {Record<string, unknown>} */ (value);
  if (!whole(acceptedAt) || acceptedAt === 0 || !whole(restoreEpoch) || typeof manifestOlder !== "boolean") return null;
  return { acceptedAt, restoreEpoch, manifestOlder };
}

/**
 * Keeps the note for an account on a server, replacing an earlier one. A value that is not a note is refused.
 * @param {import("./idb.mjs").Store} store
 * @param {string} serverUrl
 * @param {string} accountId
 * @param {RestoreNote} note
 * @returns {Promise<void>}
 */
export async function saveRestoreNote(store, serverUrl, accountId, note) {
  const key = restoreNoteKey(serverUrl, accountId);
  const kept = clean(note);
  if (kept === null) throw new TypeError("a restore note is { acceptedAt, restoreEpoch, manifestOlder }");
  await setSetting(store, key, kept);
}

/**
 * Removes the note of an account on a server, if there is one.
 * @param {import("./idb.mjs").Store} store
 * @param {string} serverUrl
 * @param {string} accountId
 * @returns {Promise<void>}
 */
export async function deleteRestoreNote(store, serverUrl, accountId) {
  await deleteSetting(store, restoreNoteKey(serverUrl, accountId));
}

/**
 * The note for an account on a server, or null when there is none, it is older than 30 days,
 * or what is stored is not a note. A note that has expired is removed when it is read.
 * @param {import("./idb.mjs").Store} store
 * @param {string} serverUrl
 * @param {string} accountId
 * @param {number} now ms since the epoch
 * @returns {Promise<RestoreNote | null>}
 */
export async function loadRestoreNote(store, serverUrl, accountId, now) {
  const key = restoreNoteKey(serverUrl, accountId);
  if (!whole(now)) throw new TypeError("now is ms since the epoch");
  const note = clean(await getSetting(store, key));
  if (note === null) return null;
  if (note.acceptedAt > now + CLOCK_SLACK_MS) return null;
  if (now - note.acceptedAt > RESTORE_NOTE_TTL_MS) {
    try {
      await deleteSetting(store, key);
    } catch {
      // An expired note that cannot be removed now is still no note, and is tried again at the next read.
    }
    return null;
  }
  return note;
}
