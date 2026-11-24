// What is read out of the answer of a passkey, shared by the web vault and the browser extension (extension/shared.json):
// the checks of an assertion and the evaluation that opens a closed vault (spec Fase 1 § 4.3, § 9.4, § 7.3). This file
// makes no WebAuthn call of its own: the page hands the call in (`getAssertion`), so a package that has the passkey
// unlock switched off holds no call to the browser. The calls that register a passkey, and the evaluation of one
// credential, are in `passkeyCeremony.mjs`, which only the web vault carries.
//
// Every answer is checked against what was asked: the type and the challenge in the client data, the origin, the hash of
// the relying party id in the authenticator data (so the id really is the host), the credential id, the flags. A refusal
// is an `AccountError` with a code of its own and nothing is kept.
//
// The PRF output is a lasting secret of the vault (a key that opens it for anyone who holds the passkey). It is returned
// as a fresh `Uint8Array` that the caller hands to the core, which wipes it; it is never logged, stored or put in an
// address, and this module keeps no copy of it. Copies made here are wiped before they are dropped.
import { b64u } from "../b64.mjs";
import { AccountError } from "../crypto/errors.mjs";

/** The length of a PRF result in bytes. */
export const PRF_OUTPUT_LENGTH = 32;
/** A failure sooner than this after the call is the browser or the system refusing it, not a user who said no. */
export const FAST_FAILURE_MS = 2_000;
/** The bits of the flags byte of the authenticator data. */
export const UP = 0x01;
export const UV = 0x04;
export const BE = 0x08;
export const BS = 0x10;
export const AT = 0x40;
/** How long the browser may wait for the user, in milliseconds. */
export const TIMEOUT_MS = 120_000;

/**
 * @typedef {object} Credentials
 * @property {(options: any) => Promise<any>} create
 * @property {(options: any) => Promise<any>} get
 */

/**
 * @typedef {object} CeremonyDeps
 * @property {Credentials | undefined} [credentials] `navigator.credentials`
 * @property {(bytes: Uint8Array) => Uint8Array} rand fills a byte array with random values and gives it back
 * @property {() => number} now milliseconds
 * @property {(data: Uint8Array) => Promise<Uint8Array>} sha256
 * @property {string} origin the page's origin, as the browser writes it into the client data
 */

/** @param {unknown} value @returns {Uint8Array | null} a copy of the bytes of a buffer or a view, or null */
export function bytesOf(value) {
  if (value instanceof ArrayBuffer) return new Uint8Array(value.slice(0));
  if (ArrayBuffer.isView(value)) return new Uint8Array(value.buffer.slice(value.byteOffset, value.byteOffset + value.byteLength));
  return null;
}

/** @param {Uint8Array} a @param {Uint8Array} b */
export function sameBytes(a, b) {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i += 1) diff |= a[i] ^ b[i];
  return diff === 0;
}

/**
 * The name of a failed call, as the error of the flow. A call that is refused at once (before the user could have
 * seen anything) says so: the usual cause is another password manager that has taken over the passkeys of the browser,
 * or a system with no passkey provider set up.
 * @param {unknown} error
 * @param {number} elapsed
 */
export function refused(error, elapsed) {
  const name = /** @type {any} */ (error)?.name;
  switch (name) {
    case "NotAllowedError":
    case "AbortError":
      return new AccountError(elapsed < FAST_FAILURE_MS ? "passkey_blocked" : "passkey_cancelled");
    case "InvalidStateError":
      return new AccountError("passkey_exists");
    case "NotSupportedError":
      return new AccountError("passkey_unsupported");
    case "SecurityError":
      return new AccountError("passkey_security");
    default:
      return new AccountError("passkey_failed");
  }
}

/**
 * Reads the client data of an answer and checks what the browser says it was asked.
 * @param {unknown} raw
 * @param {{ type: string, challenge: Uint8Array, origin: string }} expected
 */
export function checkClientData(raw, { type, challenge, origin }) {
  const bytes = bytesOf(raw);
  if (bytes === null) throw new AccountError("passkey_bad_answer");
  /** @type {any} */
  let data;
  try {
    data = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes));
  } catch {
    throw new AccountError("passkey_bad_answer");
  }
  if (data === null || typeof data !== "object" || data.type !== type || data.origin !== origin || data.challenge !== b64u.encode(challenge)) {
    throw new AccountError("passkey_bad_answer");
  }
  // A cross-origin frame has no business making this call.
  if (data.crossOrigin === true) throw new AccountError("passkey_bad_answer");
}

/**
 * The part of the authenticator data every answer has: the relying party hash must be the hash of `rpId`, the user
 * must be present and verified.
 * @param {unknown} raw
 * @param {string} rpId
 * @param {CeremonyDeps} deps
 * @returns {Promise<Uint8Array>}
 */
export async function checkedAuthData(raw, rpId, deps) {
  const data = bytesOf(raw);
  if (data === null || data.length < 37) throw new AccountError("passkey_bad_answer");
  const expected = await deps.sha256(new TextEncoder().encode(rpId));
  if (!sameBytes(data.subarray(0, 32), expected)) throw new AccountError("passkey_bad_answer");
  if ((data[32] & UP) === 0) throw new AccountError("passkey_bad_answer");
  // The user was verified (a PIN, a fingerprint, a face), not only present: without it the result would be a weaker secret.
  if ((data[32] & UV) === 0) throw new AccountError("passkey_not_verified");
  return data;
}

/**
 * Wipes the browser's own buffer of a PRF result, as far as script can (best effort: the engine may have copied it). Safe to call
 * again and on anything: a value that is not a buffer is left alone.
 * @param {any} results `extensions.prf.results`
 */
export function wipeBrowserResult(results) {
  const first = results?.first;
  if (first instanceof ArrayBuffer) new Uint8Array(first).fill(0);
  else if (ArrayBuffer.isView(first)) new Uint8Array(first.buffer, first.byteOffset, first.byteLength).fill(0);
}

/**
 * The 32 bytes of a PRF result, or null when there is none. A result of another length is refused.
 * @param {any} results `extensions.prf.results`
 * @returns {Uint8Array | null}
 */
export function firstResultOf(results) {
  if (results === undefined || results === null) return null;
  const first = bytesOf(results.first);
  // The browser's own buffer is wiped as far as script can: the copy is the one that goes on.
  wipeBrowserResult(results);
  if (first === null) throw new AccountError("passkey_bad_output");
  if (first.length !== PRF_OUTPUT_LENGTH) {
    first.fill(0);
    throw new AccountError("passkey_bad_output");
  }
  return first;
}

/**
 * The evaluation that opens a closed vault: any one of the passkeys that are unlock methods, each with the salt of its
 * own method. The browser is asked with `allowCredentials` (the methods' credential ids) and `evalByCredential` (the
 * salt of each), and the answer says which passkey the user used. The call is the first thing this function does and
 * nothing is awaited before it, so a page can make it directly from a click (a browser lets a page make one WebAuthn
 * call for each click). `getAssertion(publicKey)` is the page's own WebAuthn call.
 *
 * The answer is checked as in `evaluatePasskey`: the credential is one that was asked for, the client data says
 * `webauthn.get` for this challenge and origin, the relying party hash is the hash of `rpId` and the user was present and
 * verified (UV), and the PRF result is exactly 32 bytes.
 * @param {{
 *   rpId: string,
 *   credentials: ReadonlyArray<{ id: Uint8Array, salt: Uint8Array }>,
 *   getAssertion: (publicKey: any) => Promise<any>,
 * }} request `rpId` is the exact host of the vault (never a parent domain)
 * @param {Omit<CeremonyDeps, "credentials">} deps
 * @returns {Promise<{ credentialId: Uint8Array, output: Uint8Array }>} the passkey that answered and the 32 bytes of its
 * result; the caller hands the result on and wipes it
 */
export async function evaluateOneOf({ rpId, credentials, getAssertion }, deps) {
  if (typeof getAssertion !== "function") throw new AccountError("passkey_unsupported");
  if (typeof rpId !== "string" || rpId === "" || credentials.length === 0) throw new TypeError("a passkey needs the host and a credential");
  // A salt of another size cannot make the key: the plain error of an unlock that did not work, not a fault of the page.
  if (credentials.some((c) => c.salt.length !== PRF_OUTPUT_LENGTH)) throw new AccountError("passkey_unlock_failed");
  const challenge = deps.rand(new Uint8Array(32));
  /** @type {Record<string, { first: Uint8Array }>} */
  const evalByCredential = {};
  for (const { id, salt } of credentials) evalByCredential[b64u.encode(id)] = { first: salt.slice() };
  const options = {
    rpId,
    challenge,
    allowCredentials: credentials.map(({ id }) => ({ type: "public-key", id: id.slice() })),
    userVerification: "required",
    timeout: TIMEOUT_MS,
    extensions: { prf: { evalByCredential } },
  };
  const started = deps.now();
  /** @type {any} */
  let assertion;
  try {
    assertion = await getAssertion(options);
  } catch (error) {
    throw refused(error, deps.now() - started);
  }
  if (assertion === null || assertion === undefined || assertion.type !== "public-key") throw new AccountError("passkey_unsupported");
  const extensions = typeof assertion.getClientExtensionResults === "function" ? assertion.getClientExtensionResults() : {};
  /** @type {Uint8Array | null} */
  let output = null;
  try {
    const answered = bytesOf(assertion.rawId);
    const used = answered === null ? undefined : credentials.find(({ id }) => sameBytes(answered, id));
    if (used === undefined) throw new AccountError("passkey_other_credential");
    checkClientData(assertion.response?.clientDataJSON, { type: "webauthn.get", challenge, origin: deps.origin });
    await checkedAuthData(assertion.response?.authenticatorData, rpId, deps);
    output = firstResultOf(extensions?.prf?.results);
    if (output === null) throw new AccountError("passkey_no_output");
    const out = output;
    output = null;
    return { credentialId: used.id.slice(), output: out };
  } finally {
    // Only an output that was not handed on is wiped here (every path that throws), and the browser's own buffer is wiped
    // even when the answer was refused before the result was read.
    output?.fill(0);
    wipeBrowserResult(extensions?.prf?.results);
  }
}
