// The client of the vault's JSON API. Every call is same-origin, never cached,
// never follows a redirect, and answers with JSON or an `ApiError`. The error
// carries the server's code (`{"error": code}`): callers switch on the code,
// not on the status, because two codes can share a status (both 413s).
//
// Writes: pass the body of a retried write as the same string (or bytes) you
// sent the first time, under the same `idem`. The server hashes the raw body,
// so a re-serialized retry is 422 `idem_reuse` instead of a replay.
import { checkStep, readJson, readWire, SHAPES } from "./wire.mjs";

/** Statuses the server answers for a request that retrying cannot fix. */
const TERMINAL_STATUSES = Object.freeze([400, 403, 413, 422]);

/** The code of an error answer is a lower-case word list, nothing else. */
const CODE = /^[a-z0-9_]{1,64}$/;

export class ApiError extends Error {
  /**
   * @param {number} status the HTTP status, or 0 when no answer came
   * @param {string} code the server's code, or `network` / `bad_response` from the client
   * @param {number | null} [retryAfter] seconds to wait, from the Retry-After header
   * @param {Record<string, any> | null} [body] the parsed error body (`conflict`: the current row; `gone`: `min_valid_since`)
   */
  constructor(status, code, retryAfter = null, body = null) {
    super(`${status} ${code}`);
    this.name = "ApiError";
    /** @type {number} */
    this.status = status;
    /** @type {string} */
    this.code = code;
    /** @type {number | null} */
    this.retryAfter = retryAfter;
    /** @type {Record<string, any> | null} */
    this.body = body;
  }

  /** The request is wrong or refused and must not be sent again as it is (400, 403, 413, 422): show the code and keep the draft. */
  get terminal() {
    return TERMINAL_STATUSES.includes(this.status);
  }

  /** For `gone` (410): the floor of the feed. The client lists the vault again from 0. */
  get minValidSince() {
    const n = this.body?.min_valid_since;
    return this.code === "gone" && Number.isSafeInteger(n) && n >= 0 ? n : null;
  }
}

/**
 * Whether a URL parser would keep `path` on the page's own origin: it starts
 * with one `/` and holds no backslash, control character or space (browsers
 * read `/\evil.example` and `/<tab>/evil.example` as another host).
 * @param {unknown} path
 */
function isLocalPath(path) {
  if (typeof path !== "string" || !path.startsWith("/") || path.startsWith("//")) return false;
  for (const ch of path) {
    const code = ch.codePointAt(0) ?? 0;
    if (ch === String.fromCharCode(92) || code <= 0x20 || (code >= 0x7f && code <= 0x9f)) return false;
  }
  try {
    return new URL(path, "https://origin.invalid").origin === "https://origin.invalid";
  } catch {
    return false;
  }
}

/**
 * Seconds from a Retry-After header, or null for anything but whole seconds.
 * @param {string | null} value
 */
function secondsOf(value) {
  if (value === null || !/^[0-9]{1,15}$/.test(value.trim())) return null;
  return Number(value.trim());
}

/**
 * @typedef {object} CallOptions
 * @property {string} [shape] a key of the wire shapes (`wire.mjs`): the answer is checked against it
 *
 * @typedef {object} Api
 * @property {(path: string, options?: CallOptions) => Promise<any>} get
 * @property {(path: string, body?: unknown, options?: CallOptions) => Promise<any>} post
 * @property {(path: string, body?: unknown, options?: CallOptions) => Promise<any>} put
 */

/**
 * @param {{ base?: string, fetchImpl?: typeof fetch, timeoutMs?: number }} [options]
 * @returns {Api}
 */
export function createApi({ base = "", fetchImpl = fetch, timeoutMs = 60_000 } = {}) {
  /**
   * @param {"GET" | "POST" | "PUT"} method
   * @param {string} path
   * @param {unknown} body a string or bytes are sent as they are; anything else as JSON
   * @param {CallOptions} options
   */
  async function call(method, path, body, options) {
    if (!isLocalPath(path)) throw new TypeError("an API path starts with a single / and has no backslash or control character");
    const kind = options.shape;
    if (kind !== undefined && !(kind in SHAPES)) throw new TypeError(`no wire shape named ${kind}`);
    /** @type {Record<string, string>} */
    const headers = { Accept: "application/json" };
    /** @type {RequestInit} */
    const init = { method, credentials: "same-origin", cache: "no-store", redirect: "error", headers };
    if (method !== "GET") {
      headers["Ferret-Protocol"] = "1";
      headers["Content-Type"] = "application/json";
      if (typeof body === "string" || body instanceof Uint8Array) {
        init.body = /** @type {BodyInit} */ (body);
      } else if (body !== undefined) {
        init.body = JSON.stringify(body);
      }
    }
    if (typeof AbortSignal !== "undefined" && typeof AbortSignal.timeout === "function") {
      init.signal = AbortSignal.timeout(timeoutMs);
    }

    /** @type {Response} */
    let response;
    try {
      response = await fetchImpl(base + path, init);
    } catch {
      // A refused redirect, a dropped connection and a timeout all end here.
      throw new ApiError(0, "network");
    }

    const status = response.status;
    const retryAfter = secondsOf(response.headers.get("retry-after"));
    if (response.redirected || response.type === "opaqueredirect" || (status >= 300 && status < 400)) {
      throw new ApiError(status, "bad_response", retryAfter);
    }
    const ok = status >= 200 && status < 300;
    if (ok && status === 204) return null;

    const media = (response.headers.get("content-type") ?? "").split(";")[0].trim().toLowerCase();
    /** @type {string} */
    let text;
    try {
      text = media === "application/json" ? await response.text() : "";
    } catch {
      throw new ApiError(status, "bad_response", retryAfter);
    }
    if (media !== "application/json") throw new ApiError(status, "bad_response", retryAfter);

    if (ok) {
      try {
        return kind ? readWire(kind, text) : readJson(text);
      } catch {
        throw new ApiError(status, "bad_response", retryAfter);
      }
    }
    throw errorOf(status, text, retryAfter);
  }

  return {
    get: (path, options = {}) => call("GET", path, undefined, options),
    post: (path, body, options = {}) => call("POST", path, body, options),
    put: (path, body, options = {}) => call("PUT", path, body, options),
  };
}

/**
 * The error for an answer that is not a success. `{"error": code}` gives the
 * code; a 409 from an item write has the current row instead (code `conflict`).
 * Anything else is `bad_response`: a proxy page or a server we do not know.
 * @param {number} status
 * @param {string} text
 * @param {number | null} retryAfter
 */
function errorOf(status, text, retryAfter) {
  /** @type {any} */
  let body;
  try {
    body = readJson(text);
  } catch {
    return new ApiError(status, "bad_response", retryAfter);
  }
  if (body !== null && typeof body === "object" && typeof body.error === "string" && CODE.test(body.error)) {
    return new ApiError(status, body.error, retryAfter, body);
  }
  if (status === 409 && body !== null && typeof body === "object" && "current_rev" in body) {
    try {
      const row = readWire("conflict_res", text);
      checkStep("conflict_res", row);
      return new ApiError(status, "conflict", retryAfter, row);
    } catch {
      return new ApiError(status, "bad_response", retryAfter);
    }
  }
  return new ApiError(status, "bad_response", retryAfter);
}
