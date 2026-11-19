// The text of the emergency sheet's QR code, read on a new device (spec Fase 1
// § 4.2, "Pinning and the SK bit", F-01 point 6, and § 6.1). The sign-in page
// reads it, shows the host and the port to the user, and checks it against what
// the server says before the password is used:
//
//   readSetupQr          the core reads the text (`setup_qr_parse`); the answer is checked for form
//   checkQrBeforeKe3     the address, the server's OPAQUE key and the profile; before KE3 is posted
//   checkQrAfterLogin    the account id the server names after `login/finish`
//
// A difference is a hard error and nothing is pinned. The text is public in the
// sense that it holds no key, but it names the account and the server, so it is
// treated like the other sheet texts: never in a URL, in storage, in the log or
// in an error message, and this module never keeps it.
//
// This file is pure: it imports no DOM, no store and no network code.
import { hex16 } from "../b64.mjs";

/**
 * A refusal of the sheet's text. `code` is a short stable word the pages translate; it never carries the text.
 * `qr_server_url`, `qr_server_key`, `qr_profile`, `qr_account` and `qr_sk_bit` are the hard errors of a mismatch;
 * `malformed_setup_qr`, `qr_unsupported`, `qr_too_large` and `kdf_profile_unknown` are the reader's.
 */
export class SetupQrError extends Error {
  /** @param {string} code */
  constructor(code) {
    super(code);
    this.name = "SetupQrError";
    /** @type {string} */
    this.code = code;
  }
}

/** The longest text the reader looks at (the core's own limit). */
export const MAX_QR_TEXT = 1700;

/**
 * What the core says about a text of its own, as the codes the pages translate.
 * @type {Readonly<Record<string, string>>}
 */
const CORE_CODES = Object.freeze({
  malformed_setup_qr: "malformed_setup_qr",
  unsupported: "qr_unsupported",
  too_large: "qr_too_large",
  kdf_profile_unknown: "kdf_profile_unknown",
});

/**
 * @typedef {object} SetupQr what the sheet states
 * @property {string} serverUrl the address exactly as the sheet wrote it
 * @property {"https" | "http"} scheme
 * @property {string} host in lower case; an IPv6 literal keeps its brackets
 * @property {number | null} port
 * @property {string} accountId 32 lower-case hex characters
 * @property {number} ksfProfile
 * @property {boolean} skBit whether the account has a secret key
 * @property {Uint8Array} serverPublicKey the OPAQUE server key (32 bytes)
 */

/**
 * @param {unknown} a
 * @param {unknown} b
 */
function sameBytes(a, b) {
  return a instanceof Uint8Array && b instanceof Uint8Array && a.length === b.length && a.every((n, i) => n === b[i]);
}

/**
 * Whether `value` is a value this module made (all the checks run on a form that
 * the reader made, so a caller cannot pass a half-made one).
 * @param {unknown} qr
 * @returns {asserts qr is SetupQr}
 */
function assertQr(qr) {
  const q = /** @type {any} */ (qr);
  const ok =
    q !== null &&
    typeof q === "object" &&
    typeof q.serverUrl === "string" &&
    hex16.is(q.accountId) &&
    Number.isInteger(q.ksfProfile) &&
    typeof q.skBit === "boolean" &&
    q.serverPublicKey instanceof Uint8Array &&
    q.serverPublicKey.length === 32;
  if (!ok) throw new TypeError("not a read sheet text");
}

/**
 * The origin of an address (scheme, lower-case host, port), or null when it is not an http(s) address.
 * @param {unknown} address
 * @returns {string | null}
 */
function originOf(address) {
  if (typeof address !== "string") return null;
  try {
    const url = new URL(address);
    return url.protocol === "https:" || url.protocol === "http:" ? url.origin : null;
  } catch {
    return null;
  }
}

/**
 * Reads the text of the sheet's QR code with the core and checks the form of
 * the answer. Nothing is sent anywhere. Show `host` and `port` to the user and
 * have them confirm before the sign-in goes on.
 * @param {{ vault: { setup_qr_parse(text: string): Promise<unknown> | unknown } }} client the crypto client
 * @param {unknown} text the text the user pasted
 * @returns {Promise<Readonly<SetupQr>>}
 * @throws {SetupQrError}
 */
export async function readSetupQr(client, text) {
  if (typeof text !== "string") throw new SetupQrError("malformed_setup_qr");
  const clean = text.trim();
  if (clean === "") throw new SetupQrError("malformed_setup_qr");
  if (clean.length > MAX_QR_TEXT) throw new SetupQrError("qr_too_large");
  /** @type {any} */
  let raw;
  try {
    raw = await client.vault.setup_qr_parse(clean);
  } catch (error) {
    const code = /** @type {any} */ (error)?.code;
    const mapped = typeof code === "string" && Object.hasOwn(CORE_CODES, code) ? CORE_CODES[code] : null;
    // A code of the core's that is not about the text itself (a worker that stopped) goes on as it is.
    if (mapped === null) throw error;
    throw new SetupQrError(mapped);
  }
  const port = raw?.port ?? null;
  const ok =
    raw !== null &&
    typeof raw === "object" &&
    typeof raw.server_url === "string" &&
    (raw.scheme === "https" || raw.scheme === "http") &&
    typeof raw.host === "string" &&
    raw.host !== "" &&
    (port === null || (Number.isInteger(port) && port >= 1 && port <= 65_535)) &&
    raw.account_id instanceof Uint8Array &&
    raw.account_id.length === 16 &&
    Number.isInteger(raw.ksf_profile) &&
    raw.ksf_profile >= 0 &&
    raw.ksf_profile <= 255 &&
    typeof raw.sk_bit === "boolean" &&
    raw.server_public_key instanceof Uint8Array &&
    raw.server_public_key.length === 32;
  if (!ok) throw new SetupQrError("malformed_setup_qr");
  return Object.freeze({
    serverUrl: raw.server_url,
    scheme: raw.scheme,
    host: raw.host,
    port,
    accountId: hex16.encode(raw.account_id),
    ksfProfile: raw.ksf_profile,
    skBit: raw.sk_bit,
    serverPublicKey: raw.server_public_key.slice(),
  });
}

/**
 * The checks that run before KE3 is posted (and, the first two of them, before
 * the password is stretched):
 *
 *   - the address on the sheet is the address of this page's server (`serverUrl`):
 *     the two are compared as origins (scheme, host in lower case, port), so a
 *     valid address with a path or capital letters is the same server, and a
 *     sheet for another server is no reason to talk to this one;
 *   - the KSF profile the server states is not lower than the sheet's
 *     (`serverProfile`): a lower one would make the password cheaper to guess;
 *   - the OPAQUE key the server proved (`serverPublicKey`) is the sheet's.
 *
 * A value that is left out is not checked; the sign-in calls this again as the
 * values become known, and the last call has all three.
 * @param {SetupQr} qr what `readSetupQr` returned
 * @param {{ serverUrl: string, serverPublicKey?: Uint8Array, serverProfile?: number }} seen
 * @returns {void}
 * @throws {SetupQrError} `qr_server_url`, `qr_profile` or `qr_server_key`
 */
export function checkQrBeforeKe3(qr, { serverUrl, serverPublicKey, serverProfile }) {
  assertQr(qr);
  if (originOf(qr.serverUrl) === null || originOf(qr.serverUrl) !== originOf(serverUrl)) throw new SetupQrError("qr_server_url");
  if (serverProfile !== undefined && (!Number.isInteger(serverProfile) || serverProfile < qr.ksfProfile)) {
    throw new SetupQrError("qr_profile");
  }
  if (serverPublicKey !== undefined && !sameBytes(serverPublicKey, qr.serverPublicKey)) {
    throw new SetupQrError("qr_server_key");
  }
}

/**
 * The check that runs once the server has named the account (`login/finish`):
 * it is the account on the sheet.
 * @param {SetupQr} qr
 * @param {{ accountId: string }} seen the account id the server named, 32 hex characters
 * @returns {void}
 * @throws {SetupQrError} `qr_account`
 */
export function checkQrAfterLogin(qr, { accountId }) {
  assertQr(qr);
  if (!hex16.is(accountId) || accountId !== qr.accountId) throw new SetupQrError("qr_account");
}
