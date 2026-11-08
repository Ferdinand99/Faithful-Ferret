// The error type of the sync engine and the codes that several of its files
// read the same way.

/** An error of the engine. `code` is a word for the caller to switch on. */
export class SyncError extends Error {
  /** @param {string} code @param {string} [message] @param {string | null} [reason] why (for `blocked`: the code that blocked the item) */
  constructor(code, message = code, reason = null) {
    super(message);
    this.name = "SyncError";
    /** @type {string} */
    this.code = code;
    /** @type {string | null} */
    this.reason = reason;
  }
}

/** Codes of the core and the client that mean "the vault is not usable now", not "this row is bad". */
export const FATAL_CODES = new Set(["locked", "vault_locked", "worker_failed", "internal"]);

/** @param {unknown} error */
export const codeOf = (error) => {
  const code = /** @type {any} */ (error)?.code;
  return typeof code === "string" ? code : "internal";
};

/** @param {unknown} error */
export const isFatal = (error) => FATAL_CODES.has(codeOf(error));
