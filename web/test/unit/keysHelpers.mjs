// Helpers for the tests of the key pages: a signed-in account whose fake core keeps the new recovery key
// of a renewal the way the worker does (until it is typed back, discarded or the renewal ends), a fake
// server that also answers the recovery write, and the catalogs. Every value here is a test value.
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { b64u } from "../../src/b64.mjs";
import { createI18n } from "../../src/i18n.mjs";
import { loadPinned } from "../../src/store/pinned.mjs";
import { ACCOUNT, EMAIL, RK_CODE, SERVER, accountDocument, coded, filled, pinnedRecord } from "./accountHelpers.mjs";
import { web } from "./helpers.mjs";
import { answer, signedInWorld } from "./securityHelpers.mjs";

export { ACCOUNT, EMAIL, RK_CODE, SERVER, filled, pinnedRecord };

/** Another valid-looking key, as a user would type the old one. */
export const OLD_RK_CODE = "FFR1-OLDK-OLDK-OLDK-OLDK-OLDK-OLDK-OLDK-OLDK-OLDK-OLDK-OLDK-OLDK-OLDK-OLDK";

const read = (lang, name) => JSON.parse(readFileSync(join(web, "src", "locales", lang, `${name}.json`), "utf8"));

/** The catalog of a language as the app merges it (the files the key pages use). */
export const catalog = (lang) => ({ ...read(lang, "account"), ...read(lang, "security"), ...read(lang, "sheet"), ...read(lang, "keys") });

/** A translator over the real catalogs. */
export const i18n = (lang = "en") => createI18n({ en: catalog("en"), nb: catalog("nb") }, lang);

/** Runs an async body with a fake document whose inputs start empty, as real ones do. */
export async function withDom(body) {
  const saved = globalThis.document;
  globalThis.document = accountDocument();
  try {
    return await body();
  } finally {
    if (saved === undefined) delete globalThis.document;
    else globalThis.document = saved;
  }
}

/** @param {Record<string, any>} record @param {string} type */
export const floorIn = (record, type) => record.kek_generation_max.find((f) => f.type === type)?.generation ?? null;

/** The floor of a method in the record this device keeps for the account. */
export async function storedFloor(world, type) {
  return floorIn(await loadPinned(world.db.store, SERVER, EMAIL), type);
}

/** The server's list of unlock methods at the given generations. */
export function methodsAnswer({ password = 1, recovery = 1 } = {}) {
  return answer(200, {
    methods: [
      { method_id: "11".repeat(16), method_type: 1, kek_generation: password, wrap: b64u.encode(filled(104, 5)) },
      { method_id: "22".repeat(16), method_type: 2, kek_generation: recovery, wrap: b64u.encode(filled(72, 6)) },
    ],
    pk_a: b64u.encode(filled(32, 3)),
    vk_epoch: 1,
    manifest: { rev: 1, envelope: b64u.encode(filled(80, 4)), tag: b64u.encode(filled(32, 5)) },
  });
}

/**
 * A signed-in account for the key flows.
 * - `core.held` is the new recovery key the fake worker holds (null when none). `renew_recovery` refuses a server
 *   wrap below the pinned recovery floor (`pinned_kek_generation`), as the core does; the after-restore entry does not.
 *   Both give generation max(floor, server) + 1 and a record whose recovery floor is that generation.
 * - `world.recoveryPuts` are the signed recovery writes the fake server received.
 * @param {object} [options]
 */
export async function keysWorld({ skBit = true, server = { password: 1, recovery: 1 }, puts = [{ status: 200 }], handlers = {}, forgetKey = false } = {}) {
  const core = { held: null };
  const recoveryPuts = [];
  const renew = (refuse) => (pinned, current) => {
    const floor = floorIn(pinned, "recovery") ?? 0;
    if (refuse && current.kek_generation < floor) throw coded("pinned_kek_generation");
    const generation = Math.max(floor, current.kek_generation) + 1;
    core.held = RK_CODE;
    return {
      wrap: { method_id: current.method_id, kek_generation: generation, method: { type: "recovery" }, wrap: filled(72, 12) },
      pk_r: filled(32, 13),
      manifest: { rev: 2, envelope: filled(80, 14), tag: filled(32, 15) },
      pinned: { ...pinned, kek_generation_max: pinned.kek_generation_max.map((f) => (f.type === "recovery" ? { ...f, generation } : f)) },
    };
  };
  const world = await signedInWorld({
    skBit,
    forgetKey,
    handlers: {
      renew_recovery: renew(true),
      renew_recovery_after_restore: renew(false),
      reveal_recovery_code: () => {
        if (core.held === null) throw coded("invalid_input");
        return core.held;
      },
      verify_recovery_setup: (typed) => {
        if (typed !== core.held) throw coded(/^FFR1-/.test(typed) ? "decrypt" : "checksum");
        core.held = null;
      },
      clear_setup_secrets: () => {
        core.held = null;
      },
      check_code: () => undefined,
      setup_qr_build: (url, accountId, profile, bit) => `ferret-setup:v1?u=${encodeURIComponent(url)}&a=${Buffer.from(accountId).toString("hex")}&k=${profile}&s=${bit ? 1 : 0}&o=x`,
      ...handlers,
    },
    overrides: {
      "GET /api/vault/unlock-methods": () => methodsAnswer(server),
      "PUT /api/vault/unlock-methods/recovery": (body, state) => {
        recoveryPuts.push({ headers: state.requests.at(-1).headers, body });
        const next = puts[Math.min(recoveryPuts.length, puts.length) - 1];
        if (next.status === 200) return answer(200, next.body ?? { kek_generation: body.kek_generation, seq: 13 });
        return answer(next.status, next.body ?? { error: "write_conflict" });
      },
    },
  });
  world.core = core;
  world.recoveryPuts = recoveryPuts;
  return world;
}

/** A password check that answers `answer` and leaves a mark in the world's log. */
export const reauthWith = (world, answer = "ok") => async () => {
  world.log.push("reauth");
  return answer;
};

/** A `confirmNewRk` that types `typed` (each in turn) and answers what the check left. */
export function typing(world, ...typed) {
  const shown = [];
  const confirm = async ({ sheet, verify }) => {
    world.log.push("sheet");
    shown.push(sheet);
    for (const key of typed) {
      try {
        await verify(key);
        return true;
      } catch (error) {
        shown.push(error.code);
      }
    }
    return false;
  };
  confirm.shown = shown;
  return confirm;
}
