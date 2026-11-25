// A software authenticator for the checks of the fixtures themselves (it is test code: no file of
// extension/ or web/ uses it). It makes the responses a browser would send, with ES256 and attestation
// "none", and lets a test change one thing at a time (a flag, the RP ID hash, the origin, crossOrigin, the
// signature, the counter) so that a fixture can be shown to refuse what it must refuse.
import { createHash, generateKeyPairSync, randomBytes, sign } from "node:crypto";

const sha256 = (/** @type {Buffer | string} */ data) => createHash("sha256").update(data).digest();

// ------------------------------------------------------------------ CBOR (what a response needs)

/** @param {number} major @param {number} n */
function head(major, n) {
  if (n < 24) return Buffer.from([(major << 5) | n]);
  if (n < 256) return Buffer.from([(major << 5) | 24, n]);
  if (n < 65536) return Buffer.from([(major << 5) | 25, n >> 8, n & 255]);
  throw new Error("cbor: too long");
}
/** @param {unknown} v @returns {Buffer} */
export function cbor(v) {
  if (typeof v === "number") return v >= 0 ? head(0, v) : head(1, -1 - v);
  if (typeof v === "string") return Buffer.concat([head(3, Buffer.byteLength(v)), Buffer.from(v)]);
  if (Buffer.isBuffer(v)) return Buffer.concat([head(2, v.length), v]);
  if (v instanceof Map) return Buffer.concat([head(5, v.size), ...[...v].flatMap(([k, x]) => [cbor(k), cbor(x)])]);
  throw new Error(`cbor: cannot encode ${typeof v}`);
}

// ------------------------------------------------------------------------------ the authenticator

export const FLAG = { UP: 0x01, UV: 0x04, BE: 0x08, BS: 0x10, AT: 0x40 };
const b64u = (/** @type {Buffer} */ b) => b.toString("base64url");

/**
 * @typedef {{
 *   flags?: number,            the flag byte as it is sent (default UP | UV | BE | BS, plus AT on a create)
 *   rpId?: string,             what the RP ID hash is made of (default: the RP ID of the options)
 *   origin?: string,           what clientDataJSON says (default: the origin of the page)
 *   crossOrigin?: boolean,     clientDataJSON's crossOrigin (default: absent)
 *   counter?: number,          the signature counter (default 0)
 *   tamperSignature?: boolean, flip a bit of the signature
 *   challenge?: string,        a challenge other than the one asked for
 *   omitUserHandle?: boolean,  no userHandle in the assertion
 * }} Tamper
 */

export class SoftAuthenticator {
  constructor() {
    const { privateKey, publicKey } = generateKeyPairSync("ec", { namedCurve: "P-256" });
    this.privateKey = privateKey;
    const jwk = publicKey.export({ format: "jwk" });
    this.x = Buffer.from(/** @type {string} */ (jwk.x), "base64url");
    this.y = Buffer.from(/** @type {string} */ (jwk.y), "base64url");
    this.credentialId = randomBytes(32);
    /** @type {Buffer | undefined} */
    this.userHandle = undefined;
  }

  /** @param {any} options @param {string} origin @param {Tamper} [t] */
  create(options, origin, t = {}) {
    const rpId = t.rpId ?? options.rp.id;
    this.userHandle = Buffer.from(options.user.id, "base64url");
    const flags = t.flags ?? FLAG.UP | FLAG.UV | FLAG.BE | FLAG.BS;
    const cose = cbor(
      new Map(/** @type {[number, unknown][]} */ ([[1, 2], [3, -7], [-1, 1], [-2, this.x], [-3, this.y]])),
    );
    const idLen = Buffer.alloc(2);
    idLen.writeUInt16BE(this.credentialId.length);
    const counter = Buffer.alloc(4);
    counter.writeUInt32BE(t.counter ?? 0);
    const authData = Buffer.concat([sha256(rpId), Buffer.from([flags | FLAG.AT]), counter, Buffer.alloc(16), idLen, this.credentialId, cose]);
    const attestationObject = cbor(new Map(/** @type {[string, unknown][]} */ ([["fmt", "none"], ["attStmt", new Map()], ["authData", authData]])));
    const clientData = this.#clientData("webauthn.create", t.challenge ?? options.challenge, origin, t);
    return {
      id: b64u(this.credentialId),
      rawId: b64u(this.credentialId),
      type: "public-key",
      response: { clientDataJSON: b64u(clientData), attestationObject: b64u(attestationObject), transports: ["internal"] },
      clientExtensionResults: {},
    };
  }

  /** @param {any} options @param {string} origin @param {Tamper} [t] */
  get(options, origin, t = {}) {
    const rpId = t.rpId ?? options.rpId;
    const flags = t.flags ?? FLAG.UP | FLAG.UV | FLAG.BE | FLAG.BS;
    const counter = Buffer.alloc(4);
    counter.writeUInt32BE(t.counter ?? 0);
    const authData = Buffer.concat([sha256(rpId), Buffer.from([flags]), counter]);
    const clientData = this.#clientData("webauthn.get", t.challenge ?? options.challenge, origin, t);
    const signature = sign("sha256", Buffer.concat([authData, sha256(clientData)]), this.privateKey);
    if (t.tamperSignature) signature[signature.length - 1] ^= 1;
    return {
      id: b64u(this.credentialId),
      rawId: b64u(this.credentialId),
      type: "public-key",
      response: { clientDataJSON: b64u(clientData), authenticatorData: b64u(authData), signature: b64u(signature), userHandle: this.userHandle && !t.omitUserHandle ? b64u(this.userHandle) : undefined },
      clientExtensionResults: {},
    };
  }

  /** @param {string} type @param {string} challenge @param {string} origin @param {Tamper} t */
  #clientData(type, challenge, origin, t) {
    const data = { type, challenge, origin: t.origin ?? origin, ...(t.crossOrigin === undefined ? {} : { crossOrigin: t.crossOrigin }) };
    return Buffer.from(JSON.stringify(data));
  }
}
