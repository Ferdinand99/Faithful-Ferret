// DPoP proofs (RFC 9449 § 4) for a device client: a compact JWS, signed with
// the device's non-extractable P-256 key through WebCrypto (ES256, RFC 7518
// § 3.4: the signature is r ‖ s, 64 bytes, which is the form WebCrypto's ECDSA
// gives). No JWT library and no signature code of our own: the header and the
// claims are fixed JSON, and WebCrypto does the signing.
//
//   header  {"typ":"dpop+jwt","alg":"ES256","jwk":{"kty":"EC","crv":"P-256","x":…,"y":…}}
//   claims  {"jti":…,"htm":…,"htu":…,"iat":…,"ath"?:…}
//
// `jti` is 16 random bytes as base64url. `htu` is the request URL without its
// query and fragment. `iat` is the server's time: the client keeps the offset
// between its own clock and the server's `Date` header, so a device whose
// clock is wrong still makes proofs within the server's ±60 seconds. `ath` is
// there exactly when an access token goes with the request: base64url of
// SHA-256 of the token's ASCII text (§ 4.2).
//
// A proof is a secret for as long as it can be used: it is sent in the `DPoP`
// header and never stored or logged.
import { b64u } from "../b64.mjs";

/** The `typ` of a DPoP proof. */
export const DPOP_TYP = "dpop+jwt";
/** The one signing algorithm. */
export const DPOP_ALG = "ES256";
/** The random bytes of a `jti`. */
export const JTI_BYTES = 16;
/** The length of a token on the wire: 32 bytes as base64url without padding. */
const TOKEN_CHARS = 43;

/**
 * The server's clock as the client sees it.
 * @typedef {object} Clock
 * @property {(dateHeader: string | null) => void} observe takes the server's time from the first answer that has a `Date` header
 * @property {() => number} nowSeconds the server's time now, in whole seconds since the Unix epoch
 * @property {(dateHeader: string | null) => void} resync takes the server's time from this answer, replacing what was taken before
 */

/**
 * Parses an HTTP `Date` header (RFC 9110 § 5.6.7) to milliseconds, or null.
 * @param {unknown} dateHeader
 * @returns {number | null}
 */
function dateOf(dateHeader) {
  if (typeof dateHeader !== "string" || dateHeader === "") return null;
  const at = Date.parse(dateHeader);
  return Number.isFinite(at) ? at : null;
}

/**
 * A clock that follows the server's time. Until an answer with a `Date` header
 * has been seen, it is the local clock. `observe` takes the offset from the
 * first such answer and leaves it after that; `resync` replaces it (once after
 * a `dpop_invalid`, before the one retry). A missing or unreadable header
 * changes nothing.
 * @param {{ now?: () => number }} [options] `now` is the local time in milliseconds
 * @returns {Clock}
 */
export function createClock({ now = () => Date.now() } = {}) {
  /** @type {number | null} */
  let offset = null;
  /** @param {string | null} dateHeader */
  const take = (dateHeader) => {
    const at = dateOf(dateHeader);
    if (at !== null) offset = at - now();
  };
  return Object.freeze({
    observe(/** @type {string | null} */ dateHeader) {
      if (offset === null) take(dateHeader);
    },
    nowSeconds() {
      return Math.floor((now() + (offset ?? 0)) / 1000);
    },
    resync(/** @type {string | null} */ dateHeader) {
      take(dateHeader);
    },
  });
}

/**
 * The `htu` of a request URL: its origin and path, without query and fragment.
 * @param {string | URL} url
 * @returns {string}
 */
export function htuOf(url) {
  const parsed = new URL(url);
  if (parsed.protocol !== "https:" && parsed.protocol !== "http:") throw new TypeError("a request URL is an http(s) URL");
  return `${parsed.origin}${parsed.pathname}`;
}

/**
 * The `ath` of an access token: base64url of SHA-256 of its ASCII text.
 * @param {string} accessToken
 * @returns {Promise<string>}
 */
export async function accessTokenHash(accessToken) {
  if (typeof accessToken !== "string" || !/^[\x21-\x7e]+$/.test(accessToken)) {
    throw new TypeError("an access token is visible ASCII");
  }
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(accessToken));
  return b64u.encode(new Uint8Array(digest));
}

/** @param {unknown} token */
function isToken(token) {
  if (typeof token !== "string" || token.length !== TOKEN_CHARS) return false;
  try {
    return b64u.decode(token).length === 32;
  } catch {
    return false;
  }
}

/** @param {object} value */
const segment = (value) => b64u.encode(new TextEncoder().encode(JSON.stringify(value)));

/**
 * Makes a DPoP proof for one request.
 * @param {{ privateKey: CryptoKey, publicJwk: import("./deviceKey.mjs").PublicJwk }} key the device key
 * @param {object} request
 * @param {string} request.method the HTTP method, as sent (`GET`, `POST`, …)
 * @param {string | URL} request.url the full request URL; query and fragment are left out of `htu`
 * @param {string | null} [request.accessToken] the access token that goes with the request, or null for a sign-in or a renewal
 * @param {Clock} request.clock the server's clock
 * @param {Pick<Crypto, "getRandomValues">} [request.rand] the source of the `jti`
 * @returns {Promise<string>} the compact JWS for the `DPoP` header
 */
export async function createProof(key, { method, url, accessToken = null, clock, rand = crypto }) {
  if (typeof method !== "string" || !/^[A-Z]{1,16}$/.test(method)) throw new TypeError("a method is an upper-case HTTP method");
  if (!clock || typeof clock.nowSeconds !== "function") throw new TypeError("a proof needs the server's clock");
  if (accessToken !== null && !isToken(accessToken)) throw new TypeError("an access token is 43 characters of base64url");
  const { kty, crv, x, y } = key.publicJwk;
  if (kty !== "EC" || crv !== "P-256" || typeof x !== "string" || typeof y !== "string") {
    throw new TypeError("a device key is a P-256 key");
  }
  const iat = clock.nowSeconds();
  if (!Number.isSafeInteger(iat) || iat < 0) throw new TypeError("the clock gives whole seconds");

  const header = { typ: DPOP_TYP, alg: DPOP_ALG, jwk: { kty, crv, x, y } };
  /** @type {{ jti: string, htm: string, htu: string, iat: number, ath?: string }} */
  const claims = {
    jti: b64u.encode(rand.getRandomValues(new Uint8Array(JTI_BYTES))),
    htm: method,
    htu: htuOf(url),
    iat,
  };
  if (accessToken !== null) claims.ath = await accessTokenHash(accessToken);

  const input = `${segment(header)}.${segment(claims)}`;
  const signature = new Uint8Array(
    await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, key.privateKey, new TextEncoder().encode(input)),
  );
  if (signature.length !== 64) throw new TypeError("an ES256 signature is 64 bytes");
  return `${input}.${b64u.encode(signature)}`;
}
