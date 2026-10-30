// The error of the account flows. Its `code` is a short stable word the pages
// translate; it never carries text typed by the user.

export class AccountError extends Error {
  /**
   * @param {string} code
   * @param {Record<string, any> | null} [details] non-secret facts (a retry time, an account id)
   */
  constructor(code, details = null) {
    super(code);
    this.name = "AccountError";
    /** @type {string} */
    this.code = code;
    /** @type {Record<string, any> | null} */
    this.details = details;
  }
}

/**
 * The code of any error the flows can meet: the core's (`decrypt`,
 * `pinned_sk_bit`), the server's (`denied`, `throttled`), the store's, or our
 * own. Anything else is `unknown`.
 * @param {unknown} error
 * @returns {string}
 */
export function codeOf(error) {
  const code = /** @type {any} */ (error)?.code;
  if (typeof code === "string" && /^[a-z0-9_]{1,64}$/.test(code)) return code;
  return error instanceof TypeError ? "invalid_input" : "unknown";
}

/**
 * Adds the server's secret-key hint to an error, so the page can preselect the
 * answer on the next try. The hint changes nothing that was sent.
 * @param {unknown} error
 * @param {boolean} hint
 * @returns {unknown}
 */
export function withSkHint(error, hint) {
  if (error !== null && typeof error === "object") /** @type {any} */ (error).skHint = hint;
  return error;
}
