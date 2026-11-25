// What the unlock specs (65 to 69) share: requests over the UI port from the test bridge (a top-level page of the extension), the
// PIN record as it lies in the extension's own database (read and changed from a page of the extension, as only the extension
// and the test can), the browser's own network switch, and a scan of a profile folder for values that must never be in it.
// Not a spec (run.sh picks up *.spec.mjs only).
import assert from "node:assert/strict";
import { readFileSync, readdirSync, statSync } from "node:fs";
import { join } from "node:path";
import { SLOW, helpers, pace } from "./e2e.mjs";
import { BRIDGE_URL, TEST_ADDON_ID } from "./harness.mjs";

/** The start of every sentinel PIN: the end-to-end run looks for it in the stack's logs too (scripts/lanbox-ext.sh). */
export const SENTINEL_PREFIX = "ferret-sentinel-pin-";

/** @typedef {import("./driver.mjs").Session} Session */

/**
 * Opens the test bridge in the current tab: a page of the extension that is not the popup and does nothing by itself.
 * @param {Session} session
 */
export async function onBridge(session) {
  await session.navigate(BRIDGE_URL);
  await session.waitFor(() => session.content(() => document.documentElement.dataset.ready === "1"), 20_000, "the bridge page");
}

/**
 * One request over the UI port of the extension page the current tab shows. `after` sends a second request this many
 * milliseconds later on the same port and returns its reply as `second`.
 * @param {Session} session
 * @param {string} type @param {unknown} body
 * @param {{ after?: { delay: number, type: string, body: unknown } }} [options]
 * @returns {Promise<{ type: string, body: any, second?: { type: string, body: any } }>}
 */
export async function askFull(session, type, body, options = {}) {
  const raw = await session.content(
    (/** @type {string} */ kind, /** @type {string} */ payload, /** @type {string | null} */ extra) =>
      new Promise((resolve, reject) => {
        const port = browser.runtime.connect({ name: "ferret-ui" });
        const timer = setTimeout(() => reject(new Error("the UI port did not answer")), 170_000);
        /** @type {Record<string, any>} */
        const replies = {};
        const second = extra === null ? null : JSON.parse(extra);
        port.onMessage.addListener((message) => {
          const parsed = JSON.parse(typeof message === "string" ? message : JSON.stringify(message));
          replies[parsed.id] = parsed;
          if (replies.a1 && (second === null || replies.a2)) {
            clearTimeout(timer);
            port.disconnect();
            resolve(JSON.stringify({ ...replies.a1, ...(second === null ? {} : { second: replies.a2 }) }));
          }
        });
        port.onDisconnect.addListener(() => reject(new Error("the UI port hung up")));
        port.postMessage(JSON.stringify({ v: 1, id: "a1", type: kind, body: JSON.parse(payload) }));
        if (second !== null) setTimeout(() => port.postMessage(JSON.stringify({ v: 1, id: "a2", type: second.type, body: second.body })), second.delay);
      }),
    type,
    JSON.stringify(body),
    options.after === undefined ? null : JSON.stringify(options.after),
  );
  return JSON.parse(raw);
}

/** The body of the reply to one request. @param {Session} session @param {string} type @param {unknown} body */
export async function ask(session, type, body) {
  return (await askFull(session, type, body)).body;
}

/** What the extension says of the PIN now. @param {Session} session */
export async function pinPolicy(session) {
  return (await ask(session, "unlock_policy", {})).pin_state;
}

/**
 * Sets a PIN from the master password (the device keeps the secret key), the way the settings page does.
 * @param {Session} session
 * @param {{ password: string }} account
 * @param {string} pin
 * @param {"disk" | "session"} [location]
 */
export async function setPin(session, account, pin, location = "disk") {
  await pace();
  const reply = await ask(session, "pin_set", { mp: account.password, pin, location, acknowledged: location === "disk" });
  assert.deepEqual(reply, { ok: true }, `pin_set: ${JSON.stringify(reply)}`);
}

/**
 * The PIN record on disk, changed in the extension's own database (the page that runs this is a page of the extension, as only
 * the extension and the test can be). `change` says what to do to the stored record; the answer is what was stored before
 * (byte arrays as lists of numbers), or null when there is no record on disk. Nothing is evaluated: the changes are a fixed list.
 * @param {Session} session
 * @param {{ kind: "contact_days_ago" | "clock_behind_by", days: number } | { kind: "flip_wrap_byte", at: number } | { kind: "profile" | "epoch_up" | "failures", value: number } | { kind: "extra_field" | "delete" | "none" }} change
 * @returns {Promise<Record<string, any> | null>}
 */
export function editDiskRecord(session, change) {
  return session.content(
    (/** @type {any} */ op) =>
      new Promise((resolve, reject) => {
        const day = 24 * 3600 * 1000;
        const open = indexedDB.open("ferret-unlock");
        open.onerror = () => reject(new Error("the unlock database did not open"));
        open.onsuccess = () => {
          const db = open.result;
          if (!db.objectStoreNames.contains("pin")) {
            db.close();
            resolve(null);
            return;
          }
          const tx = db.transaction("pin", "readwrite");
          const store = tx.objectStore("pin");
          const cursor = store.openCursor();
          /** @type {any} */
          let before = null;
          cursor.onsuccess = () => {
            const at = cursor.result;
            if (!at) return;
            const record = at.value;
            before = JSON.parse(JSON.stringify({ ...record, methodId: Array.from(record.methodId), wrap: Array.from(record.wrap), deviceSalt: Array.from(record.deviceSalt) }));
            const now = Date.now();
            /** @type {any} */
            let next = { ...record };
            switch (op.kind) {
              case "contact_days_ago":
                next.lastContactAt = now - op.days * day;
                break;
              case "clock_behind_by":
                next.highestSeenAt = now + op.days * day;
                break;
              case "flip_wrap_byte": {
                const wrap = record.wrap.slice();
                wrap[op.at] ^= 1;
                next.wrap = wrap;
                break;
              }
              case "profile":
                next.pinProfile = op.value;
                break;
              case "epoch_up":
                next.vkEpoch = record.vkEpoch + op.value;
                break;
              case "failures":
                next.failures = op.value;
                next.lastFailureAt = op.value === 0 ? null : now - 600_000;
                break;
              case "extra_field":
                next.pinLength = 6;
                break;
              case "delete":
                next = null;
                break;
              default:
                break;
            }
            if (next === null) at.delete();
            else if (op.kind !== "none") at.update(next);
          };
          tx.oncomplete = () => {
            db.close();
            resolve(before);
          };
          tx.onerror = () => reject(new Error("the unlock database refused the change"));
        };
      }),
    change,
  );
}

/**
 * Where the extension's PIN data is, from a page of the extension: whether the disk database holds a record, how many keys of
 * the session storage are the PIN's, and which keys of the local storage mention a PIN (none, ever).
 * @param {Session} session
 * @returns {Promise<{ disk: boolean, sessionKeys: string[], localKeys: string[] }>}
 */
export function pinPlaces(session) {
  return session.content(async () => {
    const disk = await new Promise((resolve) => {
      const open = indexedDB.open("ferret-unlock");
      open.onerror = () => resolve(false);
      open.onsuccess = () => {
        const db = open.result;
        if (!db.objectStoreNames.contains("pin")) {
          db.close();
          resolve(false);
          return;
        }
        const count = db.transaction("pin").objectStore("pin").count();
        count.onsuccess = () => {
          db.close();
          resolve(count.result > 0);
        };
        count.onerror = () => {
          db.close();
          resolve(false);
        };
      };
    });
    const sessionKeys = Object.keys(await browser.storage.session.get(null)).filter((key) => key.startsWith("ferretPin"));
    const localKeys = Object.keys(await browser.storage.local.get(null)).filter((key) => /pin/i.test(key));
    return { disk: disk === true, sessionKeys, localKeys };
  });
}

/**
 * Takes the server away from the browser (or gives it back): web requests go to a proxy that nothing listens on, so every request
 * to the server fails at once, as with no connection. Pages and workers of the extension still load (the browser's own offline
 * switch is not used: it also stops them from starting a worker).
 * @param {Session} session @param {boolean} offline
 */
export async function setOffline(session, offline) {
  await session.chrome((/** @type {boolean} */ value) => {
    const prefs = /** @type {any} */ (globalThis).Services.prefs;
    if (value) {
      prefs.setStringPref("network.proxy.http", "127.0.0.1");
      prefs.setIntPref("network.proxy.http_port", 9);
      prefs.setStringPref("network.proxy.ssl", "127.0.0.1");
      prefs.setIntPref("network.proxy.ssl_port", 9);
      prefs.setStringPref("network.proxy.no_proxies_on", "");
      prefs.setBoolPref("network.proxy.allow_hijacking_localhost", true);
      prefs.setIntPref("network.proxy.type", 1);
    } else {
      prefs.setIntPref("network.proxy.type", 0);
    }
  }, offline);
}

/**
 * Every file under `dir` that holds one of `needles`: a text as UTF-8, as UTF-16, or as base64, base64url or hex of its UTF-8; a
 * list of bytes raw, or as base64, base64url or hex. Result: the relative path, the needle's index and the form that was found. A
 * needle that is found is a value that left where it was allowed to be.
 * @param {string} dir
 * @param {Array<string | Uint8Array>} needles
 * @returns {Array<{ file: string, needle: number, form: string }>}
 */
export function scanFolder(dir, needles) {
  /** @type {Array<{ file: string, needle: number, form: string }>} */
  const found = [];
  const forms = needles.map((needle) => {
    const raw = typeof needle === "string" ? Buffer.from(needle, "utf8") : Buffer.from(needle);
    return [
      [typeof needle === "string" ? "utf8" : "raw", raw],
      ...(typeof needle === "string" ? [["utf16", Buffer.from(needle, "utf16le")]] : []),
      ["base64", Buffer.from(raw.toString("base64"))],
      ["base64url", Buffer.from(raw.toString("base64url"))],
      ["hex", Buffer.from(raw.toString("hex"))],
    ];
  });
  /** @param {string} path */
  const walk = (path) => {
    let entries;
    try {
      entries = readdirSync(path, { withFileTypes: true });
    } catch {
      return;
    }
    for (const entry of entries) {
      const full = join(path, entry.name);
      if (entry.isDirectory()) walk(full);
      else if (entry.isFile()) {
        let bytes;
        try {
          if (statSync(full).size > 512 * 1024 * 1024) continue;
          bytes = readFileSync(full);
        } catch {
          continue;
        }
        forms.forEach((candidates, needle) => {
          for (const [form, buffer] of /** @type {Array<[string, Buffer]>} */ (candidates)) {
            if (bytes.includes(buffer)) found.push({ file: full.slice(dir.length + 1), needle, form });
          }
        });
      }
    }
  };
  walk(dir);
  return found;
}

/**
 * Makes the account's passkey in the web vault (the account is signed in there), and returns to a blank page.
 * @param {import("./driver.mjs").Session} session
 * @param {{ password: string }} account
 * @param {string} name the name of the new passkey (each channel makes its own: the account keeps the one an earlier channel made, whose key is in a browser that is gone)
 */
export async function addPasskey(session, account, name) {
  const page = helpers(session);
  await session.content(() => {
    location.hash = "#/unlock-methods";
  });
  await page.waitVisible('[data-role="methods-page"]', SLOW);
  await page.waitAny(['[data-role="methods-empty"]', '[data-role="methods-row"]'], SLOW);
  // The account keeps the passkey an earlier channel made, whose key is in a browser that is gone: it is removed first, so the
  // call below has only the credential that this browser has.
  const count = async () => (await session.findAll('[data-role="methods-row"]')).length;
  for (let left = await count(); left > 0; left = await count()) {
    await page.click('[data-role="methods-remove"]');
    await page.waitVisible('[data-role="dialog-confirm"]', SLOW);
    await page.click('[data-role="dialog-confirm"]');
    const next = await page.waitAny(['[data-role="reauth-dialog"]', '[data-role="methods-done"]'], SLOW);
    if (next === '[data-role="reauth-dialog"]') {
      await page.type('[data-role="reauth-password"]', account.password);
      await pace();
      await page.click('[data-role="reauth-confirm"]');
    }
    await session.waitFor(async () => (await count()) < left, SLOW, "the removal of the old passkey");
  }
  await pace();
  await page.click('[data-role="methods-add"]');
  // The page asks for the master password again when the last check is older than a minute.
  const asked = await page.waitAny(['[data-role="reauth-dialog"]', '[data-role="methods-name-form"]'], SLOW);
  if (asked === '[data-role="reauth-dialog"]') {
    await page.type('[data-role="reauth-password"]', account.password);
    await pace();
    await page.click('[data-role="reauth-confirm"]');
  }
  await page.waitVisible('[data-role="methods-name-form"]', SLOW);
  await page.type('[data-role="methods-name-input"]', name);
  await page.click('[data-role="methods-create"]');
  await page.waitVisible('[data-role="methods-confirm"]', SLOW);
  await page.click('[data-role="methods-confirm"]');
  await page.waitVisible('[data-role="methods-done"]', SLOW);
}

/** Waits for the extension to be there after a start of the browser, and opens the test bridge. @param {Session} session */
export async function afterStart(session) {
  await session.waitFor(async () => (await session.addonInfo(TEST_ADDON_ID))?.active, 30_000, "the add-on after the start");
  await onBridge(session);
}

export { SLOW };
