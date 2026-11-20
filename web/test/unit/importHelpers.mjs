// Shared helpers of the import tests: the synthetic fixtures, a file, and a port that stands in for
// the vault worker.
import { readFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));

/** The folder of the synthetic Bitwarden fixtures. */
export const bitwardenDir = resolve(here, "..", "fixtures", "import", "bitwarden");

/** The folder of the synthetic AliasVault fixtures. */
export const aliasvaultDir = resolve(here, "..", "fixtures", "import", "aliasvault");

/** The text of an AliasVault fixture. @param {string} name */
export const avText = (name) => readFileSync(join(aliasvaultDir, name), "utf8");

/** The bytes of an AliasVault fixture. @param {string} name */
export const avBytes = (name) => readFileSync(join(aliasvaultDir, name));

/** An AliasVault fixture as a file. @param {string} name @param {string} [as] */
export const avFile = (name, as = name) => new File([avBytes(name)], as);

/** The text of a fixture. @param {string} name */
export const fixture = (name) => readFileSync(join(bitwardenDir, name), "utf8");

/** The parsed JSON of a fixture (plain objects, for tests that only look). @param {string} name */
export const fixtureJson = (name) => JSON.parse(fixture(name));

/** A file made of a fixture. @param {string} name @param {string} [as] */
export const fixtureFile = (name, as = name) => new File([fixture(name)], as);

/** A file of text. @param {string} text @param {string} [name] */
export const textFile = (text, name = "export.json") => new File([text], name);

/** One sealed answer of the fake vault. */
export const sealedValue = (n = 0) => ({ rev: 1, envelope: new Uint8Array([0xe0, n & 0xff, 1, 2, 3]), tag: new Uint8Array(32).fill(n & 0xff) });

/**
 * A port with the surface the worker uses (`postMessage`, `onmessage`, `close`) that plays the vault
 * worker: every message the worker sends is kept in `sent` and answered by `reply`.
 * @param {{ reply?: (message: any, index: number) => any, immediate?: boolean }} [options]
 */
export function vaultPort({ reply = (message) => ({ id: message.id, ok: true, value: sealedValue(message.id) }), immediate = false } = {}) {
  /** @type {any[]} */
  const sent = [];
  const port = {
    /** @type {((event: { data: unknown }) => void) | null} */
    onmessage: null,
    closed: false,
    sent,
    /** @param {any} message */
    postMessage(message) {
      sent.push(message);
      const index = sent.length - 1;
      const answer = () => {
        const data = reply(message, index);
        if (data !== undefined && port.onmessage) port.onmessage({ data });
      };
      if (immediate) answer();
      else setImmediate(answer);
    },
    close() {
      port.closed = true;
    },
  };
  return port;
}

/** Every string anywhere in a value (keys included). @param {unknown} value @param {string[]} [out] */
export function allStrings(value, out = []) {
  if (typeof value === "string") out.push(value);
  else if (value instanceof Uint8Array) return out;
  else if (Array.isArray(value)) for (const v of value) allStrings(v, out);
  else if (value !== null && typeof value === "object") {
    for (const [k, v] of Object.entries(value)) {
      out.push(k);
      allStrings(v, out);
    }
  }
  return out;
}
