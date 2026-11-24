// The two WebAuthn calls that turn a passkey into an unlock method (spec Fase 1 § 4.3, § 9.3, § 9.4), and what is
// read out of their answers. Nothing here talks to the server or to the vault.
//
//   create    a new credential on this site's exact host (`rp.id` is the host, never a parent domain), user
//             verification required, no discoverable credential, the PRF extension asked for with the new
//             salt. The answer's authenticator data gives the AAGUID and the BE and BS flags; the extension
//             result says whether the authenticator can evaluate the PRF and may hold a first result already.
//   get       the one evaluation that is used: the same credential, the same salt, user verification required.
//             The authenticator data must say that the user was verified, and the result must be exactly 32 bytes.
//
// Every answer is checked against what was asked: the type and the challenge in the client data, the origin, the
// hash of the relying party id in the authenticator data (so the id really is the host), the credential id, the
// flags. A refusal is an `AccountError` with a code of its own and nothing is kept.
//
// The PRF output is a lasting secret of the vault (a key that opens it for anyone who holds the passkey). It is
// returned as a fresh `Uint8Array` that the caller hands to the core, which wipes it; it is never logged, stored or
// put in an address, and this module keeps no copy of it. Copies made here are wiped before they are dropped.
//
// A browser lets a page make one WebAuthn call for each click, so the page calls `createPasskey` from one click and
// `evaluatePasskey` from the next. This module does not wait or ask; it only makes the call it is told to.
import { b64u } from "../b64.mjs";
import { AccountError } from "../crypto/errors.mjs";

/** The length of a PRF result in bytes. */
export const PRF_OUTPUT_LENGTH = 32;
/** A failure sooner than this after the call is the browser or the system refusing it, not a user who said no. */
export const FAST_FAILURE_MS = 2_000;
/** The bits of the flags byte of the authenticator data. */
const UP = 0x01;
const UV = 0x04;
const BE = 0x08;
const BS = 0x10;
const AT = 0x40;
/** Where the AAGUID sits in the authenticator data of a registration: 32 (rpIdHash) + 1 (flags) + 4 (counter). */
const AAGUID_AT = 37;
/** The shortest authenticator data of a registration: the fixed part, the AAGUID, and the length of the credential id. */
const MIN_REGISTRATION_DATA = AAGUID_AT + 16 + 2;
/** The longest credential id the server stores (`credential_id`). */
const MAX_CREDENTIAL_ID = 1024;
/** The two signature algorithms asked for: ES256 and RS256. */
const ALGORITHMS = Object.freeze([-7, -257]);
/** How long the browser may wait for the user, in milliseconds. */
const TIMEOUT_MS = 120_000;

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

/**
 * What a registration said about the credential. The PRF result, when the authenticator gave one at registration,
 * is `firstResult` (32 bytes the caller wipes); nothing else here is secret.
 * @typedef {object} Registration
 * @property {Uint8Array} credentialId
 * @property {Uint8Array} aaguid 16 bytes; all zero when the authenticator does not say
 * @property {boolean} be "backup eligible": the credential can be synced (fixed for its life)
 * @property {boolean} bs "backup state" at registration (information only)
 * @property {Uint8Array | null} firstResult the PRF result of the registration, or null when there was none
 */

/** @param {unknown} value @returns {Uint8Array | null} a copy of the bytes of a buffer or a view, or null */
function bytesOf(value) {
  if (value instanceof ArrayBuffer) return new Uint8Array(value.slice(0));
  if (ArrayBuffer.isView(value)) return new Uint8Array(value.buffer.slice(value.byteOffset, value.byteOffset + value.byteLength));
  return null;
}

/** @param {Uint8Array} a @param {Uint8Array} b */
function sameBytes(a, b) {
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
function refused(error, elapsed) {
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
function checkClientData(raw, { type, challenge, origin }) {
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
async function checkedAuthData(raw, rpId, deps) {
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
 * The 32 bytes of a PRF result, or null when there is none. A result of another length is refused.
 * @param {any} results `extensions.prf.results`
 * @returns {Uint8Array | null}
 */
function firstResultOf(results) {
  if (results === undefined || results === null) return null;
  const first = bytesOf(results.first);
  if (first === null) throw new AccountError("passkey_bad_output");
  if (first.length !== PRF_OUTPUT_LENGTH) {
    first.fill(0);
    throw new AccountError("passkey_bad_output");
  }
  return first;
}

/**
 * Registers a new credential for this site with the PRF extension asked for.
 * @param {{
 *   rpId: string, rpName: string, userName: string, salt: Uint8Array, exclude: ReadonlyArray<Uint8Array>,
 * }} request `rpId` is the page's exact host. `userName` is what the authenticator shows (the name the user gave).
 * `salt` is the new PRF salt (32 bytes). `exclude` are the credentials already registered as unlock methods.
 * @param {CeremonyDeps} deps
 * @returns {Promise<Registration>}
 */
export async function createPasskey({ rpId, rpName, userName, salt, exclude }, deps) {
  const credentials = deps.credentials;
  if (!credentials || typeof credentials.create !== "function") throw new AccountError("passkey_unsupported");
  if (typeof rpId !== "string" || rpId === "" || salt.length !== PRF_OUTPUT_LENGTH) throw new TypeError("a passkey needs the host and a 32-byte salt");
  const challenge = deps.rand(new Uint8Array(32));
  // A handle of the user that the authenticator keeps; it names nobody (new random bytes for every credential).
  const userId = deps.rand(new Uint8Array(32));
  const options = {
    publicKey: {
      rp: { id: rpId, name: rpName },
      user: { id: userId, name: userName, displayName: userName },
      challenge,
      pubKeyCredParams: ALGORITHMS.map((alg) => ({ type: "public-key", alg })),
      authenticatorSelection: { userVerification: "required", residentKey: "discouraged", requireResidentKey: false },
      attestation: "none",
      excludeCredentials: exclude.map((id) => ({ type: "public-key", id: id.slice() })),
      timeout: TIMEOUT_MS,
      extensions: { prf: { eval: { first: salt.slice() } } },
    },
  };
  const started = deps.now();
  /** @type {any} */
  let credential;
  try {
    credential = await credentials.create(options);
  } catch (error) {
    throw refused(error, deps.now() - started);
  }
  /** @type {Uint8Array | null} */
  let first = null;
  try {
    if (credential === null || credential === undefined || credential.type !== "public-key" || typeof credential.response?.getAuthenticatorData !== "function") {
      throw new AccountError("passkey_unsupported");
    }
    const extensions = typeof credential.getClientExtensionResults === "function" ? credential.getClientExtensionResults() : {};
    // The authenticator cannot evaluate the PRF (a security key without hmac-secret, a provider without it): no unlock method.
    if (extensions?.prf?.enabled !== true) throw new AccountError("passkey_no_prf");
    checkClientData(credential.response.clientDataJSON, { type: "webauthn.create", challenge, origin: deps.origin });
    const data = await checkedAuthData(credential.response.getAuthenticatorData(), rpId, deps);
    if ((data[32] & AT) === 0 || data.length < MIN_REGISTRATION_DATA) throw new AccountError("passkey_bad_answer");
    const credentialId = bytesOf(credential.rawId);
    if (credentialId === null || credentialId.length === 0 || credentialId.length > MAX_CREDENTIAL_ID) throw new AccountError("passkey_bad_answer");
    // The id inside the authenticator data is the one the browser gave; a mismatch is not a credential this page asked for.
    const idLength = (data[AAGUID_AT + 16] << 8) | data[AAGUID_AT + 17];
    const inside = data.subarray(MIN_REGISTRATION_DATA, MIN_REGISTRATION_DATA + idLength);
    if (idLength !== credentialId.length || !sameBytes(inside, credentialId)) throw new AccountError("passkey_bad_answer");
    first = firstResultOf(extensions.prf.results);
    return {
      credentialId,
      aaguid: data.slice(AAGUID_AT, AAGUID_AT + 16),
      be: (data[32] & BE) !== 0,
      bs: (data[32] & BS) !== 0,
      firstResult: first,
    };
  } catch (error) {
    first?.fill(0);
    throw error;
  }
}

/**
 * Evaluates the PRF of a credential for a salt: the one call whose result becomes the key of the unlock method.
 * @param {{ rpId: string, credentialId: Uint8Array, salt: Uint8Array }} request
 * @param {CeremonyDeps} deps
 * @returns {Promise<Uint8Array>} the 32 bytes of the result; the caller hands them on and wipes them
 */
export async function evaluatePasskey({ rpId, credentialId, salt }, deps) {
  const credentials = deps.credentials;
  if (!credentials || typeof credentials.get !== "function") throw new AccountError("passkey_unsupported");
  if (typeof rpId !== "string" || rpId === "" || salt.length !== PRF_OUTPUT_LENGTH) throw new TypeError("a passkey needs the host and a 32-byte salt");
  const challenge = deps.rand(new Uint8Array(32));
  const options = {
    publicKey: {
      rpId,
      challenge,
      allowCredentials: [{ type: "public-key", id: credentialId.slice() }],
      userVerification: "required",
      timeout: TIMEOUT_MS,
      extensions: { prf: { eval: { first: salt.slice() } } },
    },
  };
  const started = deps.now();
  /** @type {any} */
  let assertion;
  try {
    assertion = await credentials.get(options);
  } catch (error) {
    throw refused(error, deps.now() - started);
  }
  if (assertion === null || assertion === undefined || assertion.type !== "public-key") throw new AccountError("passkey_unsupported");
  const extensions = typeof assertion.getClientExtensionResults === "function" ? assertion.getClientExtensionResults() : {};
  /** @type {Uint8Array | null} */
  let output = null;
  try {
    const answered = bytesOf(assertion.rawId);
    if (answered === null || !sameBytes(answered, credentialId)) throw new AccountError("passkey_other_credential");
    checkClientData(assertion.response?.clientDataJSON, { type: "webauthn.get", challenge, origin: deps.origin });
    await checkedAuthData(assertion.response?.authenticatorData, rpId, deps);
    output = firstResultOf(extensions?.prf?.results);
    if (output === null) throw new AccountError("passkey_no_output");
    const out = output;
    output = null;
    return out;
  } finally {
    // Only an output that was not handed on is wiped here (every path that throws).
    output?.fill(0);
  }
}

/**
 * Whether the output of the registration (when there was one) is the output of the evaluation. A passkey whose
 * two answers differ does not give a stable key, and a method made from it would lock the user out.
 * @param {Uint8Array | null} atRegistration
 * @param {Uint8Array} atEvaluation
 */
export function sameOutput(atRegistration, atEvaluation) {
  return atRegistration === null || sameBytes(atRegistration, atEvaluation);
}

/**
 * The dependencies of the browser.
 * @returns {CeremonyDeps}
 */
export function browserDeps() {
  const g = /** @type {any} */ (globalThis);
  return {
    credentials: g.navigator?.credentials,
    rand: (bytes) => g.crypto.getRandomValues(bytes),
    now: () => Date.now(),
    sha256: async (data) => new Uint8Array(await g.crypto.subtle.digest("SHA-256", data)),
    origin: g.location?.origin ?? "",
  };
}
