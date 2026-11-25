// The answer objects of the passkey script in the page's own world (the `passkeys` feature, design document § 9.5 and
// § 10.8): the PublicKeyCredential with its AuthenticatorAttestationResponse (a `create`) or AuthenticatorAssertionResponse
// (a `get`), built from the bytes the core made. The build joins this file into content/passkey.main.inject.js, with
// content/passkey.main.entry.mjs.
//
// The page must not be able to tell them from the browser's own, except where a script can never be a platform object:
//
// - `instanceof PublicKeyCredential`, `Credential`, `AuthenticatorAttestationResponse`, `AuthenticatorAssertionResponse`
//   and `AuthenticatorResponse` hold, and `Object.prototype.toString` gives the browser's own tag. The browser's prototypes
//   are reached through one prototype of the object's own, which carries the members (as accessors and methods of the
//   prototype, the way the browser has them): the object has no own property, so `Object.keys` is empty and `for...in`
//   lists what the browser's lists, in the browser's order. Each member checks that `this` is the object it was made for,
//   as a platform object does (`TypeError`).
// - The members are those of the browser: `id`, `rawId`, `type`, `authenticatorAttachment`, `response`,
//   `getClientExtensionResults()`, `toJSON()` (Web Authentication level 3: RegistrationResponseJSON and
//   AuthenticationResponseJSON, bytes in unpadded base64url) and, for the responses, `clientDataJSON`, `attestationObject`,
//   `authenticatorData`, `signature`, `userHandle`, `getTransports()`, `getAuthenticatorData()`, `getPublicKey()` and
//   `getPublicKeyAlgorithm()`. Bytes the page can change (`getPublicKey()` and the like) are copies; what an attribute
//   holds is the same ArrayBuffer at each read, as it is in the browser.
// - What the page can not have: the browser's own brand (`PublicKeyCredential.prototype.toJSON.call(ours)` throws, as it
//   does for any object that is not the browser's), `structuredClone` (an empty object here, an error there), and the
//   source of a member (`toString()` shows it).
//
// This script is untrusted and holds nothing secret (the answer is what the core made for this page). It keeps what it
// uses from the page's world at install, calls it with `Reflect.apply`, makes records by literals or `defineProperty`
// (never an assignment that a setter of the page's `Object.prototype` or `Array.prototype` could see) and never makes an
// object with `Object.create`. The credential has a `then` of its own (not enumerable, `undefined`), so a page that defines
// `Object.prototype.then` cannot step into the promise that is resolved with it.

const W = window;
const R = Reflect.apply;
const ODP = Object.defineProperty;
const OGOPD = Object.getOwnPropertyDescriptor;
const hasOwn = Object.hasOwn;
const isArray = Array.isArray;
const TypeErr = TypeError;
const AB = ArrayBuffer;
const U8 = Uint8Array;
const TA = Object.getPrototypeOf(U8.prototype);
const abLength = /** @type {Function} */ (/** @type {PropertyDescriptor} */ (OGOPD(AB.prototype, "byteLength")).get);
const taLength = /** @type {Function} */ (/** @type {PropertyDescriptor} */ (OGOPD(TA, "length")).get);
const taSet = TA.set;
/** The browser's prototypes of the three objects, kept now (the page has not run yet); null where the browser has none. */
const protoOf = (/** @type {string} */ name) => {
  const ctor = /** @type {any} */ (W)[name];
  return typeof ctor === "function" && typeof ctor.prototype === "object" && ctor.prototype !== null ? ctor.prototype : null;
};
const CREDENTIAL = protoOf("PublicKeyCredential");
const ATTESTATION = protoOf("AuthenticatorAttestationResponse");
const ASSERTION = protoOf("AuthenticatorAssertionResponse");
const ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

/** A record that was never an object of the page's world to write to: no prototype, so no setter. @returns {any} */
const rec = () => ({ __proto__: null });
/** An own data property, defined with a descriptor that has no prototype. @param {object} o @param {PropertyKey} key @param {unknown} value */
const put = (o, key, value) => {
  const d = rec();
  d.value = value;
  d.writable = true;
  d.enumerable = true;
  d.configurable = true;
  ODP(o, key, d);
};
/** An own property of something that came over the port, or undefined. @param {any} o @param {string} key */
const own = (o, key) => (typeof o === "object" && o !== null && R(hasOwn, null, [o, key]) ? o[key] : undefined);
const bad = () => {
  throw new TypeErr("passkey answer");
};
/** An ArrayBuffer (and no SharedArrayBuffer), or the answer is refused. @param {unknown} x @returns {ArrayBuffer} */
const buffer = (x) => {
  R(abLength, x, []);
  return /** @type {ArrayBuffer} */ (x);
};
/** A fresh copy of an ArrayBuffer. @param {ArrayBuffer} x @returns {ArrayBuffer} */
const copy = (x) => {
  const out = new AB(R(abLength, x, []));
  R(taSet, new U8(out), [new U8(x)]);
  return out;
};
/** Unpadded base64url. @param {ArrayBuffer} x @returns {string} */
const b64u = (x) => {
  const u = new U8(x);
  const n = R(taLength, u, []);
  let out = "";
  for (let i = 0; i < n; i += 3) {
    const a = u[i];
    const b = i + 1 < n ? u[i + 1] : 0;
    const c = i + 2 < n ? u[i + 2] : 0;
    const t = (a << 16) | (b << 8) | c;
    out += ALPHABET[t >> 18] + ALPHABET[(t >> 12) & 63];
    if (i + 1 < n) out += ALPHABET[(t >> 6) & 63];
    if (i + 2 < n) out += ALPHABET[t & 63];
  }
  return out;
};
/** @param {unknown} x @returns {boolean} */
const flag = (x) => (typeof x === "boolean" ? x : bad());
/** The attachment: a word, or null. @param {unknown} x @returns {string | null} */
const attachment = (x) => (x === null ? null : typeof x === "string" && x.length > 0 && x.length < 32 ? x : bad());
/** @param {object} self @param {object} expected */
const brand = (self, expected) => {
  if (self !== expected) throw new TypeErr("Illegal invocation");
};
/** A hidden `then` of undefined on a prototype, so that a `then` of the page's Object.prototype is never reached. @param {object} proto */
const hideThen = (proto) => {
  const d = rec();
  d.value = undefined;
  d.writable = false;
  d.enumerable = false;
  d.configurable = true;
  ODP(proto, "then", d);
};

/**
 * The extension results the core made, checked and copied: what `getClientExtensionResults()` and `toJSON()` give out.
 * @param {unknown} x
 */
const extensionResults = (x) => {
  const given = typeof x === "object" && x !== null ? x : bad();
  const credProps = own(given, "credProps");
  const rk = credProps === undefined ? undefined : flag(own(credProps, "rk"));
  const prf = own(given, "prf");
  /** @type {boolean | undefined} */
  let enabled;
  /** @type {ArrayBuffer | undefined} */
  let first;
  /** @type {ArrayBuffer | undefined} */
  let second;
  if (prf !== undefined) {
    const e = own(prf, "enabled");
    if (e !== undefined) enabled = flag(e);
    const results = own(prf, "results");
    if (results !== undefined) {
      first = copy(buffer(own(results, "first")));
      const s = own(results, "second");
      if (s !== undefined) second = copy(buffer(s));
    }
  }
  return {
    /** The object `getClientExtensionResults()` returns: a fresh one at each call, with its own copies of the bytes. */
    object() {
      const out = {};
      if (rk !== undefined) put(out, "credProps", { rk });
      if (prf !== undefined) {
        const p = {};
        if (enabled !== undefined) put(p, "enabled", enabled);
        if (first !== undefined) {
          const results = {};
          put(results, "first", copy(first));
          if (second !== undefined) put(results, "second", copy(second));
          put(p, "results", results);
        }
        put(out, "prf", p);
      }
      return out;
    },
    /** The same, for `toJSON()`: the bytes in base64url. */
    json() {
      const out = {};
      if (rk !== undefined) put(out, "credProps", { rk });
      if (prf !== undefined) {
        const p = {};
        if (enabled !== undefined) put(p, "enabled", enabled);
        if (first !== undefined) {
          const results = {};
          put(results, "first", b64u(first));
          if (second !== undefined) put(results, "second", b64u(second));
          put(p, "results", results);
        }
        put(out, "prf", p);
      }
      return out;
    },
  };
};

/**
 * The credential for the page, from the answer of the core (`responseFromWire` of the bridge: WebAuthn names, ArrayBuffers).
 * Null where it cannot be made (the browser has no WebAuthn objects, or the answer is not one of `kind`): the page then
 * gets the error of a request that was not allowed, never half an object.
 * @param {"create" | "get"} kind @param {unknown} response
 * @returns {object | null}
 */
export function credentialFrom(kind, response) {
  try {
    if (CREDENTIAL === null) return null;
    if (kind === "create" && ATTESTATION !== null) return make(kind, response, ATTESTATION);
    if (kind === "get" && ASSERTION !== null) return make(kind, response, ASSERTION);
  } catch {
    // An answer that is not what it should be.
  }
  return null;
}

/**
 * @param {"create" | "get"} kind @param {unknown} r @param {object} responseBase the browser's prototype of the response
 * @returns {object}
 */
function make(kind, r, responseBase) {
  const create = kind === "create";
  const rawId = copy(buffer(own(r, "id")));
  const clientDataJSON = copy(buffer(own(r, "clientDataJSON")));
  const authenticatorData = copy(buffer(own(r, "authenticatorData")));
  const attached = attachment(own(r, "authenticatorAttachment"));
  const extensions = extensionResults(own(r, "clientExtensionResults"));
  const id = b64u(rawId);
  // The fields of one kind, which the other has not.
  /** @type {ArrayBuffer | undefined} */
  let attestationObject;
  /** @type {ArrayBuffer | null} */
  let publicKey = null;
  /** @type {number} */
  let publicKeyAlgorithm = 0;
  /** @type {string[]} */
  const transports = [];
  /** @type {ArrayBuffer | undefined} */
  let signature;
  /** @type {ArrayBuffer | null} */
  let userHandle = null;
  if (create) {
    attestationObject = copy(buffer(own(r, "attestationObject")));
    const key = own(r, "publicKey");
    publicKey = key === null ? null : copy(buffer(key));
    const alg = own(r, "publicKeyAlgorithm");
    publicKeyAlgorithm = typeof alg === "number" && alg === alg && alg !== Infinity && alg !== -Infinity ? alg : bad();
    const list = own(r, "transports");
    if (!isArray(list) || list.length > 8) bad();
    for (let i = 0; i < list.length; i += 1) {
      const t = list[i];
      if (typeof t !== "string" || t.length === 0 || t.length > 32) bad();
      put(transports, i, t);
    }
  } else {
    signature = copy(buffer(own(r, "signature")));
    const handle = own(r, "userHandle");
    userHandle = handle === null ? null : copy(buffer(handle));
  }

  /** @type {object} */
  let resp;
  /** @type {object} */
  let cred;
  /** A fresh array of the transports, the way `getTransports()` gives one. */
  const transportList = () => {
    /** @type {string[]} */
    const out = [];
    for (let i = 0; i < transports.length; i += 1) put(out, i, transports[i]);
    return out;
  };
  const responseProto = create
    ? {
        __proto__: responseBase,
        getTransports() {
          brand(this, resp);
          return transportList();
        },
        getAuthenticatorData() {
          brand(this, resp);
          return copy(authenticatorData);
        },
        getPublicKey() {
          brand(this, resp);
          return publicKey === null ? null : copy(publicKey);
        },
        getPublicKeyAlgorithm() {
          brand(this, resp);
          return publicKeyAlgorithm;
        },
        get attestationObject() {
          brand(this, resp);
          return attestationObject;
        },
        get clientDataJSON() {
          brand(this, resp);
          return clientDataJSON;
        },
      }
    : {
        __proto__: responseBase,
        get authenticatorData() {
          brand(this, resp);
          return authenticatorData;
        },
        get signature() {
          brand(this, resp);
          return signature;
        },
        get userHandle() {
          brand(this, resp);
          return userHandle;
        },
        get clientDataJSON() {
          brand(this, resp);
          return clientDataJSON;
        },
      };
  resp = { __proto__: responseProto };

  /** The response as `toJSON()` gives it. */
  const responseJSON = () => {
    // The members in lexicographic order, which is the order of a dictionary turned into an object (and the browser's).
    const out = {};
    if (create) put(out, "attestationObject", b64u(/** @type {ArrayBuffer} */ (attestationObject)));
    put(out, "authenticatorData", b64u(authenticatorData));
    put(out, "clientDataJSON", b64u(clientDataJSON));
    if (create) {
      if (publicKey !== null) put(out, "publicKey", b64u(publicKey));
      put(out, "publicKeyAlgorithm", publicKeyAlgorithm);
      put(out, "transports", transportList());
    } else {
      put(out, "signature", b64u(/** @type {ArrayBuffer} */ (signature)));
      if (userHandle !== null) put(out, "userHandle", b64u(userHandle));
    }
    return out;
  };
  const credentialProto = {
    __proto__: CREDENTIAL,
    getClientExtensionResults() {
      brand(this, cred);
      return extensions.object();
    },
    toJSON() {
      brand(this, cred);
      const out = {};
      if (attached !== null) put(out, "authenticatorAttachment", attached);
      put(out, "clientExtensionResults", extensions.json());
      put(out, "id", id);
      put(out, "rawId", id);
      put(out, "response", responseJSON());
      put(out, "type", "public-key");
      return out;
    },
    get rawId() {
      brand(this, cred);
      return rawId;
    },
    get response() {
      brand(this, cred);
      return resp;
    },
    get authenticatorAttachment() {
      brand(this, cred);
      return attached;
    },
    get id() {
      brand(this, cred);
      return id;
    },
    get type() {
      brand(this, cred);
      return "public-key";
    },
  };
  hideThen(credentialProto);
  cred = { __proto__: credentialProto };
  return cred;
}
