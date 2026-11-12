// Helpers for the tests of the warning banner, the restored page and the forget page:
// the catalogs as the build merges them, a translate function for each language, and a
// stand-in for the part of the sync engine those screens use.
import { readFileSync, readdirSync } from "node:fs";
import { join } from "node:path";
import { createI18n } from "../../src/i18n.mjs";
import { FakeElement, FakeNode, web } from "./helpers.mjs";

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
    /** Whether the cause of the stop is still there when `resumeAfterHalt` has looked (the engine halts again, with the same code). */
    stillStopped: false,
    gate: /** @type {null | Promise<void>} */ (null),
    health: () => ({ halted: engine.halted, warnings: [...engine.warnings] }),
    async verifyNow() {
      engine.calls.push("verifyNow");
      if (engine.gate) await engine.gate;
      return engine.verifyResult;
    },
    /** As the real engine does it: the stop is lifted and `syncing` is said at once, then the pass runs, and the engine halts again if the cause remains. */
    async resumeAfterHalt() {
      engine.calls.push("resumeAfterHalt");
      if (engine.resumeError) throw engine.resumeError;
      const code = engine.halted;
      engine.halted = null;
      engine.emit("state", { kind: "syncing" });
      if (engine.gate) await engine.gate;
      await Promise.resolve();
      if (engine.stillStopped && code !== null) {
        engine.halted = code;
        engine.emit("state", { kind: "halted", code });
      }
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

/** Whether `node` is `root` or below it. @param {any} root @param {any} node */
function within(root, node) {
  for (let at = node; at; at = at.parentNode) if (at === root) return true;
  return false;
}

/**
 * Gives the fake DOM a focus, as a browser has it: `focus()` makes an element the active one, and the
 * active element is lost when it is removed from the page or becomes disabled. Runs `body`
 * with it and puts everything back. `document.activeElement` is what a test reads.
 * @template T
 * @param {() => Promise<T>} body
 * @returns {Promise<T>}
 */
export async function withFocus(body) {
  const doc = /** @type {any} */ (globalThis.document);
  doc.activeElement = null;
  const nodeProto = /** @type {any} */ (FakeNode.prototype);
  const elementProto = /** @type {any} */ (FakeElement.prototype);
  const removeChild = nodeProto.removeChild;
  const hadFocus = Object.getOwnPropertyDescriptor(elementProto, "focus");
  const hadDisabled = Object.getOwnPropertyDescriptor(elementProto, "disabled");
  nodeProto.removeChild = function (/** @type {any} */ child) {
    if (within(child, doc.activeElement)) doc.activeElement = null;
    return removeChild.call(this, child);
  };
  elementProto.focus = function () {
    if (!this.disabled) doc.activeElement = this;
  };
  Object.defineProperty(elementProto, "disabled", {
    configurable: true,
    get() {
      return this._disabled === true;
    },
    set(value) {
      this._disabled = value === true;
      if (this._disabled && doc.activeElement === this) doc.activeElement = null;
    },
  });
  try {
    return await body();
  } finally {
    nodeProto.removeChild = removeChild;
    if (hadFocus) Object.defineProperty(elementProto, "focus", hadFocus);
    else delete elementProto.focus;
    if (hadDisabled) Object.defineProperty(elementProto, "disabled", hadDisabled);
    else delete elementProto.disabled;
  }
}
