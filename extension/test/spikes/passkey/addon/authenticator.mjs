// Test-only software authenticator for the passkey-provider spike. It exists so
// that a local relying party can check, in Node, that what an override hands back
// to a page is valid WebAuthn. It is NOT the provider: the real one keeps its keys
// in the Rust core (design document, section 9.1), never in a script like this.
//
// Everything here is WebCrypto (ECDSA P-256 / SHA-256) plus the byte layouts that
// the WebAuthn specification fixes (authenticator data, COSE key, attestation
// object "none"). The private key is a non-extractable CryptoKey.

/** The fixed AAGUID of Ferret (design document, section 9.3). */
export const AAGUID = "dc704a44-b994-410c-a689-ed8d71a84ac3";

/** Authenticator data flags (WebAuthn level 3, section 6.1). */
export const FLAGS = Object.freeze({ UP: 0x01, UV: 0x04, BE: 0x08, BS: 0x10, AT: 0x40 });

export class DomError extends Error {
  /** @param {string} name @param {string} message */
  constructor(name, message) {
    super(message);
    this.name = name;
  }
}

/** @param {Uint8Array} bytes */
export function b64u(bytes) {
  let s = "";
  for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

/** @param {string} s @returns {Uint8Array} */
export function fromB64u(s) {
  if (typeof s !== "string" || !/^[A-Za-z0-9_-]*$/.test(s)) throw new DomError("TypeError", "bad base64url");
  const bin = atob(s.replace(/-/g, "+").replace(/_/g, "/"));
  const out = Uint8Array.from(bin, (c) => c.charCodeAt(0));
  if (b64u(out) !== s) throw new DomError("TypeError", "non-canonical base64url");
  return out;
}

/** @param {...Uint8Array} parts */
const concat = (...parts) => {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let o = 0;
  for (const p of parts) {
    out.set(p, o);
    o += p.length;
  }
  return out;
};
const utf8 = (/** @type {string} */ s) => new TextEncoder().encode(s);
const sha256 = async (/** @type {Uint8Array} */ bytes) => new Uint8Array(await crypto.subtle.digest("SHA-256", bytes));

/** @param {number} major @param {number} n */
function cborHead(major, n) {
  if (n < 24) return Uint8Array.of((major << 5) | n);
  if (n < 256) return Uint8Array.of((major << 5) | 24, n);
  if (n < 65536) return Uint8Array.of((major << 5) | 25, n >> 8, n & 255);
  return Uint8Array.of((major << 5) | 26, (n >>> 24) & 255, (n >>> 16) & 255, (n >>> 8) & 255, n & 255);
}

/**
 * The few CBOR types an attestation object needs: integers, byte strings, text,
 * arrays and maps (in insertion order).
 * @param {unknown} v
 * @returns {Uint8Array}
 */
export function cbor(v) {
  if (typeof v === "number") return v >= 0 ? cborHead(0, v) : cborHead(1, -1 - v);
  if (v instanceof Uint8Array) return concat(cborHead(2, v.length), v);
  if (typeof v === "string") {
    const b = utf8(v);
    return concat(cborHead(3, b.length), b);
  }
  if (Array.isArray(v)) return concat(cborHead(4, v.length), ...v.map(cbor));
  if (v instanceof Map) return concat(cborHead(5, v.size), ...[...v].flatMap(([k, val]) => [cbor(k), cbor(val)]));
  throw new Error("cbor: unsupported type");
}

/** WebCrypto gives r||s (64 bytes); WebAuthn wants an ASN.1 DER SEQUENCE of two INTEGERs. @param {Uint8Array} sig */
export function derFromRaw(sig) {
  const int = (/** @type {Uint8Array} */ x) => {
    let i = 0;
    while (i < x.length - 1 && x[i] === 0) i++;
    x = x.slice(i);
    if (x[0] & 0x80) x = concat(Uint8Array.of(0), x);
    return concat(Uint8Array.of(0x02, x.length), x);
  };
  const body = concat(int(sig.slice(0, 32)), int(sig.slice(32, 64)));
  return concat(Uint8Array.of(0x30, body.length), body);
}

// SPKI DER for P-256: a fixed 26-byte prefix and the 65-byte uncompressed point.
const SPKI_P256_PREFIX = Uint8Array.from([
  0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce,
  0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00,
]);

/** @param {string} uuid */
const uuidBytes = (uuid) => Uint8Array.from(uuid.replaceAll("-", "").match(/../g) ?? [], (h) => parseInt(h, 16));

// A tiny stand-in for the Public Suffix List. The real provider uses the core's.
const PUBLIC_SUFFIXES = new Set(["co.uk", "com.au", "github.io", "herokuapp.com"]);

/**
 * The RP ID rule of the design document (section 9.2): it equals the host or is a
 * dot-bounded suffix of it, never a public suffix, never an IP host, and the origin
 * must be https (or http on localhost).
 * @param {string} origin an origin string that comes from the browser
 * @param {string | null | undefined} requested
 * @returns {string}
 */
export function resolveRpId(origin, requested) {
  /** @type {URL} */
  let u;
  try {
    u = new URL(origin);
  } catch {
    throw new DomError("SecurityError", "bad origin");
  }
  const secure = u.protocol === "https:" || (u.protocol === "http:" && u.hostname === "localhost");
  if (!secure) throw new DomError("SecurityError", "insecure origin");
  const host = u.hostname.toLowerCase();
  if (/^\d+\.\d+\.\d+\.\d+$/.test(host) || host.includes(":")) throw new DomError("SecurityError", "an IP host has no RP ID");
  const rpId = (requested == null ? host : String(requested)).toLowerCase();
  if (rpId === host) return rpId;
  if (!host.endsWith(`.${rpId}`)) throw new DomError("SecurityError", "rp.id is not a suffix of the origin");
  if (!rpId.includes(".") || PUBLIC_SUFFIXES.has(rpId)) throw new DomError("SecurityError", "rp.id is a public suffix");
  return rpId;
}

/**
 * @typedef {{ rpId: string, userHandle: string, userName: string, privateKey: CryptoKey, publicRaw: Uint8Array, createdAt: number }} Stored
 */

/** A software authenticator that keeps its credentials in memory. */
export class Authenticator {
  constructor() {
    /** @type {Map<string, Stored>} credential id (base64url) -> credential */
    this.creds = new Map();
  }

  count() {
    return this.creds.size;
  }

  /** What anything outside the authenticator can learn about the keys: only these flags. */
  keyFlags() {
    return [...this.creds.values()].map((c) => ({ type: c.privateKey.type, extractable: c.privateKey.extractable }));
  }

  async tryExportPrivate() {
    const c = [...this.creds.values()][0];
    try {
      await crypto.subtle.exportKey("pkcs8", c.privateKey);
      return "exported";
    } catch (error) {
      return `refused: ${/** @type {Error} */ (error).name}`;
    }
  }

  /**
   * @param {{ origin: string, uv: boolean, rpId?: string | null, challenge: string, user: { id: string, name: string }, pubKeyCredParams?: { alg: number }[], excludeCredentials?: string[], userVerification?: string }} request
   */
  async create(request) {
    const rpId = resolveRpId(request.origin, request.rpId);
    fromB64u(request.challenge);
    fromB64u(request.user.id);
    if (request.userVerification === "required" && !request.uv) throw new DomError("NotAllowedError", "user verification is not available");
    const algs = request.pubKeyCredParams ?? [];
    if (algs.length > 0 && !algs.some((a) => a.alg === -7)) return { use: "native", reason: "no ES256 requested" };
    for (const ex of request.excludeCredentials ?? []) {
      const c = this.creds.get(ex);
      if (c && c.rpId === rpId) throw new DomError("InvalidStateError", "credential already registered");
    }
    const pair = await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, false, ["sign", "verify"]);
    const publicRaw = new Uint8Array(await crypto.subtle.exportKey("raw", pair.publicKey)); // 0x04 || x || y
    const credId = crypto.getRandomValues(new Uint8Array(32));
    const id = b64u(credId);
    const cose = new Map(/** @type {[number, unknown][]} */ ([[1, 2], [3, -7], [-1, 1], [-2, publicRaw.slice(1, 33)], [-3, publicRaw.slice(33, 65)]]));
    const attested = concat(uuidBytes(AAGUID), Uint8Array.of(credId.length >> 8, credId.length & 255), credId, cbor(cose));
    const flags = FLAGS.UP | (request.uv ? FLAGS.UV : 0) | FLAGS.BE | FLAGS.BS | FLAGS.AT;
    const authData = concat(await sha256(utf8(rpId)), Uint8Array.of(flags), new Uint8Array(4), attested);
    const attestationObject = cbor(new Map(/** @type {[string, unknown][]} */ ([["fmt", "none"], ["attStmt", new Map()], ["authData", authData]])));
    const clientDataJSON = JSON.stringify({ type: "webauthn.create", challenge: request.challenge, origin: request.origin, crossOrigin: false });
    this.creds.set(id, { rpId, userHandle: request.user.id, userName: request.user.name, privateKey: pair.privateKey, publicRaw, createdAt: Date.now() });
    return {
      result: {
        id,
        attestationObject: b64u(attestationObject),
        authenticatorData: b64u(authData),
        clientDataJSON: b64u(utf8(clientDataJSON)),
        publicKey: b64u(concat(SPKI_P256_PREFIX, publicRaw)),
        publicKeyAlgorithm: -7,
        transports: ["internal"],
      },
    };
  }

  /**
   * The credentials that could answer a request, newest first. The stored RP ID
   * must equal the requested one exactly (design document, section 9.2).
   * @param {{ origin: string, rpId?: string | null, allowCredentials?: string[] }} request
   * @returns {[string, Stored][]}
   */
  candidates(request) {
    const rpId = resolveRpId(request.origin, request.rpId);
    const allow = request.allowCredentials ?? [];
    return [...this.creds].filter(([id, c]) => c.rpId === rpId && (allow.length === 0 || allow.includes(id))).sort((a, b) => b[1].createdAt - a[1].createdAt);
  }

  /**
   * @param {{ origin: string, uv: boolean, rpId?: string | null, challenge: string, allowCredentials?: string[], userVerification?: string }} request
   * @param {string} [credentialId] which credential; the newest match when omitted
   */
  async get(request, credentialId) {
    const rpId = resolveRpId(request.origin, request.rpId);
    fromB64u(request.challenge);
    if (request.userVerification === "required" && !request.uv) throw new DomError("NotAllowedError", "user verification is not available");
    const found = this.candidates(request);
    const match = credentialId === undefined ? found[0] : found.find(([id]) => id === credentialId);
    if (!match) return { use: "native", reason: "no credential" };
    const [id, c] = match;
    const flags = FLAGS.UP | (request.uv ? FLAGS.UV : 0) | FLAGS.BE | FLAGS.BS;
    const authData = concat(await sha256(utf8(rpId)), Uint8Array.of(flags), new Uint8Array(4));
    const clientDataJSON = utf8(JSON.stringify({ type: "webauthn.get", challenge: request.challenge, origin: request.origin, crossOrigin: false }));
    const signed = concat(authData, await sha256(clientDataJSON));
    const raw = new Uint8Array(await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, c.privateKey, signed));
    return {
      result: {
        id,
        authenticatorData: b64u(authData),
        clientDataJSON: b64u(clientDataJSON),
        signature: b64u(derFromRaw(raw)),
        userHandle: c.userHandle,
      },
    };
  }
}
