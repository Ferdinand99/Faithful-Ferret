// Helpers for the tests of the warning banner, the restored page and the forget page:
// the catalogs as the build merges them, a translate function for each language, and a
// stand-in for the part of the sync engine those screens use.
import { readFileSync, readdirSync } from "node:fs";
import { join } from "node:path";
import { createI18n } from "../../src/i18n.mjs";
import { web } from "./helpers.mjs";

/** The merged catalog of one language, as the build makes it. @param {string} lang */
export function catalogOf(lang) {
  const dir = join(web, "src", "locales", lang);
  const out = {};
  for (const name of readdirSync(dir)) Object.assign(out, JSON.parse(readFileSync(join(dir, name), "utf8")));
  return out;
}

export const EN = catalogOf("en");
export const NB = catalogOf("nb");

/** A translate function for a language, from the real catalogs. @param {"en" | "nb"} [lang] */
export const translator = (lang = "en") => createI18n({ en: EN, nb: NB }, lang).t;

/** A text of the catalog with its variables filled in. @param {Record<string, string>} catalog @param {string} key @param {Record<string, any>} [vars] */
export const textFor = (catalog, key, vars = {}) => catalog[key].replace(/{([a-z]+)}/g, (whole, name) => String(vars[name] ?? whole));

/**
 * The engine as the warning screens use it. `halted` and `warnings` are what `health()` says;
 * `raise`, `clear` and `halt` change them and tell the listeners, as the engine does.
 * @param {{ halted?: string | null, warnings?: string[] }} [start]
 */
export function fakeWarningsEngine({ halted = null, warnings = [] } = {}) {
  const listeners = { state: new Set(), error: new Set() };
  const engine = {
    halted,
    warnings: [...warnings],
    calls: /** @type {string[]} */ ([]),
    verifyResult: "ok",
    previewResult: { reupload: 2, conflicts: 1 },
    acceptResult: { reuploaded: 2, conflicts: 1 },
    previewError: /** @type {any} */ (null),
    acceptError: /** @type {any} */ (null),
    resumeError: /** @type {any} */ (null),
    /** What a call of `resumeAfterHalt` does to the engine before it answers. */
    onResume: /** @type {null | (() => void)} */ (null),
    gate: /** @type {null | Promise<void>} */ (null),
    health: () => ({ halted: engine.halted, warnings: [...engine.warnings] }),
    async verifyNow() {
      engine.calls.push("verifyNow");
      if (engine.gate) await engine.gate;
      return engine.verifyResult;
    },
    async resumeAfterHalt() {
      engine.calls.push("resumeAfterHalt");
      if (engine.gate) await engine.gate;
      if (engine.resumeError) throw engine.resumeError;
      engine.onResume?.();
    },
    async restorePreview() {
      engine.calls.push("restorePreview");
      if (engine.previewError) throw engine.previewError;
      return engine.previewResult;
    },
    async acceptOlderState() {
      engine.calls.push("acceptOlderState");
      if (engine.gate) await engine.gate;
      if (engine.acceptError) throw engine.acceptError;
      return engine.acceptResult;
    },
    /** @param {"state" | "error"} event @param {(payload: any) => void} fn */
    on(event, fn) {
      listeners[event].add(fn);
      return () => void listeners[event].delete(fn);
    },
    /** @param {"state" | "error"} event @param {any} payload */
    emit(event, payload) {
      for (const fn of [...listeners[event]]) fn(payload);
    },
    /** @param {string} code @param {Record<string, any>} [extra] */
    raise(code, extra = {}) {
      engine.warnings.push(code);
      engine.emit("state", { kind: "warning", code, ...extra });
    },
    /** @param {string} code */
    clear(code) {
      engine.warnings = engine.warnings.filter((c) => c !== code);
      engine.emit("state", { kind: "warning_cleared", code });
    },
    /** @param {string} code */
    halt(code) {
      engine.halted = code;
      engine.emit("state", { kind: "halted", code });
    },
    get listening() {
      return listeners.state.size + listeners.error.size;
    },
  };
  return engine;
}
