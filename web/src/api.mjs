// The client of the vault's JSON API. Every call is same-origin, never cached,
// never follows a redirect, and answers with JSON or an `ApiError`. The error
// carries the server's code (`{"error": code}`): callers switch on the code,
// not on the status, because two codes can share a status (both 413s).
//
// Writes: pass the body of a retried write as the same string (or bytes) you
// sent the first time, under the same `idem`. The server hashes the raw body,
// so a re-serialized retry is 422 `idem_reuse` instead of a replay.
//
// A device client passes `auth` (the `TokenAuth` of `auth/tokens.mjs`). Then
// no request carries a cookie (`credentials: "omit"`), every request carries
// `Ferret-Protocol: 1` (also GET and the event stream), and each attempt has
// `Authorization: DPoP <access token>` and a new DPoP proof (spec Fase 1 § 7.6;
// RFC 9449 § 7.1). A device client also reads its answers with
// `unknown: "ignore"` (`wire.mjs`): a field the shape does not name is dropped,
// so an extension keeps working against a newer server. Without `auth` nothing
// changes for the web vault: an unknown field is refused.
import { b64u } from "./b64.mjs";
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
 * @property {(path: string, options?: CallOptions) => Promise<any>} del a `DELETE` without a body (a write: `Ferret-Protocol: 1`)
 * @property {(path: string, options?: { signal?: AbortSignal }) => Promise<ReadableStreamDefaultReader<Uint8Array>>} stream
 * @property {(method: "PUT" | "POST", path: string, bodyBytes: Uint8Array, proof: { nonce: Uint8Array, proof: Uint8Array }, options?: CallOptions) => Promise<any>} sendSigned
 *   a write that carries a proof (spec Fase 1 § 4.6): the exact bytes of `bodyBytes` are the body, the nonce and the proof go in
 *   `Ferret-Nonce` (32 bytes) and `Ferret-Proof` (64 bytes) as base64url without padding, and a redirect is never followed
 */

/**
 * What a device client gives the API client so that its requests carry tokens:
 * the `TokenAuth` of `auth/tokens.mjs`.
 * @typedef {object} RequestAuth
 * @property {(method: string, url: string) => Promise<Record<string, string>>} prepare
 *   the `Authorization` and `DPoP` headers of one attempt, with a new proof each time
 * @property {(response: Response) => void} observe takes the server's clock from a `dpop_invalid` answer
 * @property {(used?: Record<string, string> | null) => Promise<void>} refresh
 *   renews the access token once the attempt that sent the headers `used` met `token_expired`
 * @property {(code: string) => Promise<void>} refused tells the tokens the code a token request was refused with
 */

/** The calls a {@link RequestAuth} has. */
const AUTH_CALLS = Object.freeze(["prepare", "observe", "refresh", "refused"]);

/**
 * @param {{ base?: string, fetchImpl?: typeof fetch, timeoutMs?: number, auth?: RequestAuth | null }} [options]
 *   `auth`: the tokens of a device client; without it the client is the web vault's and sends its cookie
 * @returns {Api}
 */
export function createApi({ base = "", fetchImpl = fetch, timeoutMs = 60_000, auth = null } = {}) {
  if (auth !== null && (typeof auth !== "object" || !AUTH_CALLS.every((name) => typeof Reflect.get(auth, name) === "function"))) {
    throw new TypeError("auth is the TokenAuth of a device client");
  }
  /** Cookies go with the web vault's requests only; a device's requests carry its token instead. */
  const credentials = auth === null ? "same-origin" : "omit";
  /** The web vault comes from its own server and refuses an unknown answer field; a device client ignores it. */
  const unknown = auth === null ? "refuse" : "ignore";

  /**
   * Sends a request and reads its answer with `read`. Without `auth` this is one
   * `fetch` of `init` as it is. With `auth`, every attempt is a copy of `init`
   * with the token headers of `auth.prepare` (a new proof each time), and a
   * refusal of the token may send it once more: `token_expired` after one
   * renewal, `dpop_invalid` after taking the server's clock from that answer
   * once. Any other refusal is told to `auth.refused` (`device_revoked` and
   * `token_reused` end the tokens) and thrown.
   * @template T
   * @param {string} url
   * @param {RequestInit & { method: string, headers: Record<string, string> }} init
   * @param {() => AbortSignal | undefined} signalOf the signal of one attempt
   * @param {() => string} failure the code of an attempt that got no answer
   * @param {(response: Response) => Promise<T>} read gives the value of the answer, or throws its `ApiError`
   * @returns {Promise<T>}
   */
  async function exchange(url, init, signalOf, failure, read) {
    /** @param {RequestInit} attempt */
    const send = async (attempt) => {
      const signal = signalOf();
      if (signal) attempt.signal = signal;
      try {
        return await fetchImpl(url, attempt);
      } catch {
        // A refused redirect, a dropped connection and a timeout all end here.
        throw new ApiError(0, failure());
      }
    };
    if (auth === null) return read(await send(init));

    let refreshed = false;
    let resynced = false;
    for (;;) {
      const headers = { ...init.headers, ...(await auth.prepare(init.method, url)) };
      const response = await send({ ...init, headers });
      try {
        return await read(response);
      } catch (error) {
        if (!(error instanceof ApiError) || error.status !== 401) throw error;
        // Only an access token is renewed; a request with a proof alone (a renewal, a sign-out) has nothing to renew.
        if (error.code === "token_expired" && !refreshed && Object.hasOwn(headers, "Authorization")) {
          refreshed = true;
          await auth.refresh(headers);
          continue;
        }
        if (error.code === "dpop_invalid" && !resynced) {
          resynced = true;
          auth.observe(response);
          continue;
        }
        await auth.refused(error.code);
        throw error;
      }
    }
  }

  /** A time limit for one attempt of a call, where the platform has one. */
  const timeout = () =>
    typeof AbortSignal !== "undefined" && typeof AbortSignal.timeout === "function" ? AbortSignal.timeout(timeoutMs) : undefined;

  /**
   * @param {"GET" | "POST" | "PUT" | "DELETE"} method
   * @param {string} path
   * @param {unknown} body a string or bytes are sent as they are; anything else as JSON
   * @param {CallOptions} options
   * @param {{ "Ferret-Nonce": string, "Ferret-Proof": string } | null} [proof] the two headers of a signed write
   */
  async function call(method, path, body, options, proof = null) {
    if (!isLocalPath(path)) throw new TypeError("an API path starts with a single / and has no backslash or control character");
    const kind = options.shape;
    if (kind !== undefined && !(kind in SHAPES)) throw new TypeError(`no wire shape named ${kind}`);
    /** @type {Record<string, string>} */
    const headers = { Accept: "application/json" };
    /** @type {RequestInit & { method: string, headers: Record<string, string> }} */
    const init = { method, credentials, cache: "no-store", redirect: "error", headers };
    if (method !== "GET") {
      headers["Ferret-Protocol"] = "1";
      headers["Content-Type"] = "application/json";
      if (proof !== null) {
        headers["Ferret-Nonce"] = proof["Ferret-Nonce"];
        headers["Ferret-Proof"] = proof["Ferret-Proof"];
      }
      if (typeof body === "string" || body instanceof Uint8Array) {
        init.body = /** @type {BodyInit} */ (body);
      } else if (body !== undefined) {
        init.body = JSON.stringify(body);
      }
    } else if (auth !== null) {
      // A token request carries the protocol header on every method, GET too.
      headers["Ferret-Protocol"] = "1";
    }

    return exchange(base + path, init, timeout, () => "network", async (response) => {
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
          return kind ? readWire(kind, text, { unknown }) : readJson(text);
        } catch {
          throw new ApiError(status, "bad_response", retryAfter);
        }
      }
      throw errorOf(status, text, retryAfter, unknown);
    });
  }

  /**
   * Opens an event stream (`text/event-stream`) and gives its reader. The
   * answer must be a 200 with that media type and a body; anything else is an
   * `ApiError` (the server's code for an error answer, `bad_response` for a
   * proxy page, a redirect or a wrong media type) and the body is dropped. The
   * stream has no time limit of its own: the caller ends it with `signal`.
   * @param {string} path
   * @param {{ signal?: AbortSignal }} [options]
   */
  async function stream(path, { signal } = {}) {
    if (!isLocalPath(path)) throw new TypeError("an API path starts with a single / and has no backslash or control character");
    /** @type {RequestInit & { method: string, headers: Record<string, string> }} */
    const init = {
      method: "GET",
      credentials,
      cache: "no-store",
      redirect: "error",
      headers: { Accept: "text/event-stream", "Ferret-Protocol": "1" },
    };

    return exchange(base + path, init, () => signal, () => (signal?.aborted ? "aborted" : "network"), async (response) => {
      /** Drops what is left of the body without waiting for it. */
      const drop = () => {
        try {
          void response.body?.cancel().catch(() => {});
        } catch {
          // Nothing to drop.
        }
      };
      const status = response.status;
      const retryAfter = secondsOf(response.headers.get("retry-after"));
      if (response.redirected || response.type === "opaqueredirect" || (status >= 300 && status < 400)) {
        drop();
        throw new ApiError(status, "bad_response", retryAfter);
      }
      const media = (response.headers.get("content-type") ?? "").split(";")[0].trim().toLowerCase();
      if (status === 200) {
        const reader = media === "text/event-stream" ? response.body?.getReader() : undefined;
        if (!reader) {
          drop();
          throw new ApiError(status, "bad_response", retryAfter);
        }
        return reader;
      }
      if ((status >= 200 && status < 300) || media !== "application/json") {
        drop();
        throw new ApiError(status, "bad_response", retryAfter);
      }
      /** @type {string} */
      let text;
      try {
        text = await response.text();
      } catch {
        throw new ApiError(status, "bad_response", retryAfter);
      }
      throw errorOf(status, text, retryAfter, unknown);
    });
  }

  /**
   * A write with a proof. The body is sent as the bytes it is: the proof is over those bytes, so the call never builds the
   * body from a value, and a retry sends the same array. A wrong length of the nonce or the proof is refused before anything
   * is sent (the server answers 400 and burns no nonce for it, but a request that cannot be right is not worth a trip).
   * A device client makes no signed call (sensitive operations take the web vault's session only), so with `auth` it is
   * refused before anything is sent.
   * @param {"PUT" | "POST"} method
   * @param {string} path
   * @param {Uint8Array} bodyBytes
   * @param {{ nonce: Uint8Array, proof: Uint8Array }} proof
   * @param {CallOptions} [options]
   */
  async function sendSigned(method, path, bodyBytes, proof, options = {}) {
    if (auth !== null) throw new TypeError("a device client makes no signed call");
    if (method !== "PUT" && method !== "POST") throw new TypeError("a signed call is a PUT or a POST");
    if (!(bodyBytes instanceof Uint8Array)) throw new TypeError("a signed call sends bytes");
    if (proof === null || typeof proof !== "object") throw new TypeError("a signed call has a nonce and a proof");
    const { nonce, proof: signature } = proof;
    if (!(nonce instanceof Uint8Array) || nonce.length !== 32) throw new TypeError("the nonce is 32 bytes");
    if (!(signature instanceof Uint8Array) || signature.length !== 64) throw new TypeError("the proof is 64 bytes");
    return call(method, path, bodyBytes, options, { "Ferret-Nonce": b64u.encode(nonce), "Ferret-Proof": b64u.encode(signature) });
  }

  return {
    stream,
    sendSigned,
    get: (path, options = {}) => call("GET", path, undefined, options),
    post: (path, body, options = {}) => call("POST", path, body, options),
    put: (path, body, options = {}) => call("PUT", path, body, options),
    del: (path, options = {}) => call("DELETE", path, undefined, options),
  };
}

/**
 * The error for an answer that is not a success. `{"error": code}` gives the
 * code; a 409 from an item write has the current row instead (code `conflict`).
 * Anything else is `bad_response`: a proxy page or a server we do not know.
 * @param {number} status
 * @param {string} text
 * @param {number | null} retryAfter
 * @param {"refuse" | "ignore"} unknown what the current row of a conflict does with a field its shape does not name
 */
function errorOf(status, text, retryAfter, unknown) {
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
      const row = readWire("conflict_res", text, { unknown });
      checkStep("conflict_res", row);
      return new ApiError(status, "conflict", retryAfter, row);
    } catch {
      return new ApiError(status, "bad_response", retryAfter);
    }
  }
  return new ApiError(status, "bad_response", retryAfter);
}
